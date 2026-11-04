#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — snmp_probe (telecom protocol module)
# SNMP (Simple Network Management Protocol) probe — v1, v2c, v3.
#
# SNMP is used in ALL sectors for network/device management. UDP 161 query,
# 162 trap. Default community strings ("public", "private") are still
# deployed on millions of devices (routers, switches, APs, printers, UPS).
#
# Tests:
#   1. SNMPv1 GET sysDescr (1.3.6.1.2.1.1.1.0)        → snmp_accessible
#   2. SNMPv2c GET with communities public, private,
#      cisco, admin                                  → community_strings_worked
#   3. SNMPv3 discovery (authPriv support)             → snmpv3_available
#   4. Read sysContact, sysLocation, sysName           → sysDescr / sysName etc
#   5. Check for writable communities (SetRequest test)
#                                                    → writable_community
#   6. List common OIDs: interfaces, routing, ARP      → oids_read
#
# SNMP frame (BER encoded, RFC 1157 / RFC 3416):
#   SEQUENCE { version INTEGER, community OCTET STRING, PDU {
#     request-id INTEGER, error-status INTEGER, error-index INTEGER,
#     varbindlist SEQUENCE OF SEQUENCE { name OID, value ANY }
#   }}
#
# PDU types (context-specific tag 0xA0+):
#   GetRequest(0xA0) GetNextRequest(0xA1) Response(0xA2)
#   SetRequest(0xA3) GetBulkRequest(0xA5) Inform(0xA6)
#   SNMPv2-Trap(0xA7) Report(0xA8)
#
# BER encoding (X.690):
#   Tag (1 byte) + Length (short <0x80 or long form 0x80|n + n bytes) + Value
#   Tags: INTEGER=0x02, OCTET STRING=0x04, NULL=0x05, OID=0x06,
#         SEQUENCE=0x30, IpAddress=0x40, TimeTicks=0x43, Counter32=0x41,
#         Gauge32=0x42
#   OID encoding: first byte = 40*X + Y (X=first, Y=second component),
#                 subsequent values base-128 with continuation bit (0x80).
#
# SNMPv3 discovery (RFC 3414 §4): send a GetRequest with empty USM
# parameters + Report PDU → server replies with snmpEngineID and
# usmStatsUnknownEngineIDs, proving v3 is supported.
#
# CLI:
#   python3 snmp_probe.py [host] [port]
#       host default = 127.0.0.1
#       port default = 161
#
# Output: single JSON object on stdout.
#
# Legal: Default-community scanning is legal (read-only). Writing via SNMP
# SetRequest without authorization is illegal (FR Art. 323-1 /
# US 18 USC §1030). SAFE_MODE=read_only: never emits SetRequest.
import json
import os
import random
import socket
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple

# ─── Make sector_base importable from ../../sector_base.py ────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULES_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _MODULES_ROOT not in sys.path:
    sys.path.insert(0, _MODULES_ROOT)

try:
    from sector_base import get_sector_config  # noqa: E402
    _SECTOR_BASE_OK = True
except Exception:  # noqa: BLE001
    _SECTOR_BASE_OK = False

    def get_sector_config() -> Dict:  # type: ignore[no-redef]
        return {"sector": "telecom", "safe_mode": "read_only"}

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "snmp_probe"
TIMEOUT_S = 5  # 5 s hard cap on every socket op

# ─── CLI args ─────────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 161
except ValueError:
    PORT = 161

# SAFE_MODE: read_only (default) = no SetRequest tests.
SAFE_MODE = os.environ.get("SAFE_MODE", "read_only")

# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))
_rng = random.Random(SEED)

# ─── LAB guard ────────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ═══════════════════════════════════════════════════════════════════════════
#  Constants — OIDs (RFC 3418 / RFC 1213 / RFC 2863)
# ═══════════════════════════════════════════════════════════════════════════
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
OID_SYS_SERVICES = "1.3.6.1.2.1.1.7.0"
OID_IF_NUMBER = "1.3.6.1.2.1.2.1.0"
OID_IF_TABLE = "1.3.6.1.2.1.2.2"
OID_IP_ROUTE_TABLE = "1.3.6.1.2.1.4.21"
OID_AT_TABLE = "1.3.6.1.2.1.3.1"  # ARP table (deprecated; replaced by ipNetToMediaTable)
OID_IP_NET_TO_MEDIA = "1.3.6.1.2.1.4.22"  # modern ARP equivalent
OID_SNMP_ENGINE_ID = "1.3.6.1.6.3.10.2.1.1.0"  # SNMPv3
OID_USM_STATS_UNKNOWN_ENGINE = "1.3.6.1.6.3.15.1.1.4.0"  # SNMPv3

# Standard community strings to probe
COMMON_COMMUNITIES = ["public", "private", "cisco", "admin", "monitoring",
                      "read", "readwrite", "secret", "default"]

# SNMP versions
SNMP_V1 = 0
SNMP_V2C = 1
SNMP_V3 = 3

# PDU types (BER tags)
PDU_GET_REQUEST = 0xA0
PDU_GET_NEXT_REQUEST = 0xA1
PDU_RESPONSE = 0xA2
PDU_SET_REQUEST = 0xA3
PDU_GET_BULK = 0xA5
PDU_INFORM = 0xA6
PDU_V2_TRAP = 0xA7
PDU_REPORT = 0xA8

# Error statuses (RFC 3416 §4.1.1)
ERR_NO_ERROR = 0
ERR_TOO_BIG = 1
ERR_NO_SUCH_NAME = 2
ERR_BAD_VALUE = 3
ERR_READ_ONLY = 4
ERR_GEN_ERROR = 5
ERR_NO_ACCESS = 6
ERR_WRONG_TYPE = 7
ERR_WRONG_LENGTH = 8
ERR_WRONG_ENCODING = 9
ERR_WRONG_VALUE = 10
ERR_NO_CREATION = 11
ERR_INCONSISTENT_VALUE = 12
ERR_RESOURCE_UNAVAILABLE = 13
ERR_COMMIT_FAILED = 14
ERR_UNDO_FAILED = 15
ERR_AUTHORIZATION_ERROR = 16
ERR_NOT_WRITABLE = 17
ERR_INCONSISTENT_NAME = 18

ERR_NAMES = {
    ERR_NO_ERROR: "noError",
    ERR_TOO_BIG: "tooBig",
    ERR_NO_SUCH_NAME: "noSuchName",
    ERR_BAD_VALUE: "badValue",
    ERR_READ_ONLY: "readOnly",
    ERR_GEN_ERROR: "genErr",
    ERR_NO_ACCESS: "noAccess",
    ERR_WRONG_TYPE: "wrongType",
    ERR_WRONG_LENGTH: "wrongLength",
    ERR_WRONG_ENCODING: "wrongEncoding",
    ERR_WRONG_VALUE: "wrongValue",
    ERR_NO_CREATION: "noCreation",
    ERR_INCONSISTENT_VALUE: "inconsistentValue",
    ERR_RESOURCE_UNAVAILABLE: "resourceUnavailable",
    ERR_COMMIT_FAILED: "commitFailed",
    ERR_UNDO_FAILED: "undoFailed",
    ERR_AUTHORIZATION_ERROR: "authorizationError",
    ERR_NOT_WRITABLE: "notWritable",
    ERR_INCONSISTENT_NAME: "inconsistentName",
}


# ═══════════════════════════════════════════════════════════════════════════
#  Socket helpers
# ═══════════════════════════════════════════════════════════════════════════
def _set_sock_timeout(sock: socket.socket, seconds: float = TIMEOUT_S) -> None:
    try:
        if hasattr(socket, "SO_RCVTIMEO"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO,
                            struct.pack("ll", int(seconds),
                                        int((seconds % 1) * 1_000_000)))
        if hasattr(socket, "SO_SNDTIMEO"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                            struct.pack("ll", int(seconds),
                                        int((seconds % 1) * 1_000_000)))
    except OSError:
        pass
    sock.settimeout(seconds)


# ═══════════════════════════════════════════════════════════════════════════
#  BER encoding (X.690)
# ═══════════════════════════════════════════════════════════════════════════
def encode_ber_length(length: int) -> bytes:
    """BER length: short form if < 0x80, long form otherwise."""
    if length < 0x80:
        return bytes([length])
    body = bytearray()
    while length > 0:
        body.insert(0, length & 0xFF)
        length >>= 8
    if len(body) > 0x7F:
        raise ValueError("BER length too large")
    return bytes([0x80 | len(body)]) + bytes(body)


def encode_tlv(tag: int, value: bytes) -> bytes:
    """Build a Tag-Length-Value triple."""
    return bytes([tag & 0xFF]) + encode_ber_length(len(value)) + value


def encode_integer(value: int) -> bytes:
    """Encode a signed INTEGER as BER (minimal length)."""
    if -128 <= value <= 127:
        body = struct.pack(">b", value)
    elif -32768 <= value <= 32767:
        body = struct.pack(">h", value)
    elif -(1 << 23) <= value <= (1 << 23) - 1:
        body = struct.pack(">i", value & 0xFFFFFFFF)[1:]
    elif -(1 << 31) <= value <= (1 << 31) - 1:
        body = struct.pack(">i", value)
    else:
        # Large integers — use 8-byte
        body = struct.pack(">q", value)
    # Strip redundant leading 0x00 (positive) or 0xFF (negative)
    while len(body) > 1 and (
        (body[0] == 0xFF and (body[1] & 0x80)) or
        (body[0] == 0x00 and not (body[1] & 0x80))
    ):
        body = body[1:]
    return encode_tlv(0x02, body)


def encode_unsigned(value: int, tag: int = 0x02) -> bytes:
    """Encode an unsigned INTEGER (or Counter/Gauge with custom tag)."""
    if value < 0:
        raise ValueError("unsigned cannot be negative")
    if value == 0:
        body = b"\x00"
    else:
        body = bytearray()
        v = value
        while v > 0:
            body.insert(0, v & 0xFF)
            v >>= 8
        if body[0] & 0x80:
            body.insert(0, 0x00)
        body = bytes(body)
    return encode_tlv(tag, body)


def encode_octet_string(data: bytes) -> bytes:
    return encode_tlv(0x04, data)


def encode_null() -> bytes:
    return bytes([0x05, 0x00])


def encode_sequence(contents: bytes) -> bytes:
    return encode_tlv(0x30, contents)


def encode_oid(oid_str: str) -> bytes:
    """Encode an OID as BER. First byte = 40*X + Y, then base-128 with
    continuation bits for subsequent values."""
    parts = [int(p) for p in oid_str.split(".")]
    if len(parts) < 2:
        raise ValueError("OID must have ≥ 2 components")
    body = bytearray()
    body.append(40 * parts[0] + parts[1])
    for p in parts[2:]:
        body.extend(_encode_oid_subid(p))
    return encode_tlv(0x06, bytes(body))


def _encode_oid_subid(value: int) -> bytes:
    """Encode a single OID sub-identifier as base-128 with continuation."""
    if value < 0:
        raise ValueError("OID subid must be non-negative")
    if value < 0x80:
        return bytes([value])
    out = bytearray()
    out.append(value & 0x7F)
    value >>= 7
    while value > 0:
        out.insert(0, 0x80 | (value & 0x7F))
        value >>= 7
    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════
#  BER decoding (minimal — enough to parse SNMP responses)
# ═══════════════════════════════════════════════════════════════════════════
def decode_ber_length(data: bytes, pos: int) -> Tuple[int, int]:
    """Decode a BER length field. Returns (length, new_pos)."""
    if pos >= len(data):
        return (0, pos)
    b = data[pos]
    pos += 1
    if b < 0x80:
        return (b, pos)
    num_bytes = b & 0x7F
    if num_bytes == 0 or pos + num_bytes > len(data):
        return (0, pos + num_bytes)
    length = int.from_bytes(data[pos:pos + num_bytes], "big")
    return (length, pos + num_bytes)


def decode_ber_tlv(data: bytes, pos: int) -> Tuple[int, bytes, int]:
    """Decode one TLV. Returns (tag, value_bytes, new_pos)."""
    if pos >= len(data):
        return (0, b"", pos)
    tag = data[pos]
    pos += 1
    length, pos = decode_ber_length(data, pos)
    end = min(pos + length, len(data))
    value = data[pos:end]
    return (tag, value, end)


def decode_integer(value: bytes) -> int:
    """Decode a BER INTEGER value (signed two's complement)."""
    if not value:
        return 0
    n = int.from_bytes(value, "big", signed=True)
    return n


def decode_oid(value: bytes) -> str:
    """Decode a BER OID value into dotted-decimal string."""
    if not value:
        return ""
    parts: List[str] = []
    first = value[0]
    parts.append(str(first // 40))
    parts.append(str(first % 40))
    i = 1
    while i < len(value):
        n = 0
        while i < len(value):
            b = value[i]
            i += 1
            n = (n << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        parts.append(str(n))
    return ".".join(parts)


def decode_octet_string(value: bytes) -> str:
    """Decode an OCTET STRING as ASCII (with replacement for non-printable)."""
    try:
        return value.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return value.hex()


def decode_snmp_response(data: bytes) -> Optional[Dict]:
    """Parse an SNMP response packet. Returns dict with version, community,
    pdu_type, request_id, error_status, error_index, varbinds (list of
    (oid, value, value_type))."""
    pos = 0
    tag, value, pos = decode_ber_tlv(data, pos)
    if tag != 0x30:  # SEQUENCE
        return None
    # version INTEGER
    v_tag, v_val, pos = decode_ber_tlv(value, 0)
    if v_tag != 0x02:
        return None
    version = decode_integer(v_val)
    # community OCTET STRING (v1/v2c) — for v3 this is msgGlobalData SEQUENCE
    if version == SNMP_V3:
        return _decode_snmp_v3_response(value, version)
    c_tag, c_val, pos = decode_ber_tlv(value, pos)
    if c_tag != 0x04:
        return None
    community = c_val.decode("ascii", errors="replace")
    # PDU
    p_tag, p_val, pos = decode_ber_tlv(value, pos)
    if (p_tag & 0xE0) != 0xA0:
        return None
    pdu_type = p_tag & 0x1F
    # request-id INTEGER
    rid_tag, rid_val, p_pos = decode_ber_tlv(p_val, 0)
    if rid_tag != 0x02:
        return None
    request_id = decode_integer(rid_val)
    # error-status INTEGER
    es_tag, es_val, p_pos = decode_ber_tlv(p_val, p_pos)
    if es_tag != 0x02:
        return None
    error_status = decode_integer(es_val)
    # error-index INTEGER
    ei_tag, ei_val, p_pos = decode_ber_tlv(p_val, p_pos)
    if ei_tag != 0x02:
        return None
    error_index = decode_integer(ei_val)
    # varbindlist SEQUENCE OF SEQUENCE { name OID, value ANY }
    vbl_tag, vbl_val, p_pos = decode_ber_tlv(p_val, p_pos)
    if vbl_tag != 0x30:
        return None
    varbinds: List[Tuple[str, str, int]] = []
    vb_pos = 0
    while vb_pos < len(vbl_val):
        vb_tag, vb_val, vb_pos = decode_ber_tlv(vbl_val, vb_pos)
        if vb_tag != 0x30:
            break
        # name OID
        n_tag, n_val, vb_inner_pos = decode_ber_tlv(vb_val, 0)
        oid = decode_oid(n_val) if n_tag == 0x06 else ""
        # value (any type)
        val_tag, val_val, _ = decode_ber_tlv(vb_val, vb_inner_pos)
        val_str = _decode_varbind_value(val_tag, val_val)
        varbinds.append((oid, val_str, val_tag))
    return {
        "version": version,
        "community": community,
        "pdu_type": pdu_type,
        "request_id": request_id,
        "error_status": error_status,
        "error_index": error_index,
        "varbinds": varbinds,
    }


def _decode_varbind_value(tag: int, value: bytes) -> str:
    """Decode a varbind value based on its tag."""
    if tag == 0x05:  # NULL
        return ""
    if tag == 0x02:  # INTEGER
        return str(decode_integer(value))
    if tag == 0x04:  # OCTET STRING
        return decode_octet_string(value)
    if tag == 0x06:  # OBJECT IDENTIFIER
        return decode_oid(value)
    if tag == 0x40:  # IpAddress
        if len(value) == 4:
            return ".".join(str(b) for b in value)
        return value.hex()
    if tag in (0x41, 0x42):  # Counter32, Gauge32, Unsigned32
        return str(int.from_bytes(value, "big", signed=False))
    if tag == 0x43:  # TimeTicks
        return f"{int.from_bytes(value, 'big', signed=False)} (centiseconds)"
    if tag == 0x44:  # Opaque
        return f"<opaque {len(value)} bytes>"
    if tag == 0x46:  # Counter64
        return str(int.from_bytes(value, "big", signed=False))
    if tag in (0x30,):  # SEQUENCE (for tables)
        return f"<sequence {len(value)} bytes>"
    # Unknown — hex dump
    return value.hex()[:64]


def _decode_snmp_v3_response(value: bytes, version: int) -> Optional[Dict]:
    """Parse a SNMPv3 response. We only extract the report varbinds."""
    # version is at offset 0 of value
    pos = 0
    v_tag, v_val, pos = decode_ber_tlv(value, pos)
    if v_tag != 0x02:
        return None
    # msgGlobalData SEQUENCE
    gd_tag, gd_val, pos = decode_ber_tlv(value, pos)
    if gd_tag != 0x30:
        return None
    # msgSecurityParameters OCTET STRING
    sp_tag, sp_val, pos = decode_ber_tlv(value, pos)
    # msgData — could be encrypted (0x08) or plaintext scopedPDU (0x30)
    md_tag, md_val, pos = decode_ber_tlv(value, pos)
    varbinds: List[Tuple[str, str, int]] = []
    pdu_type = None
    request_id = 0
    error_status = 0
    error_index = 0
    if md_tag == 0x30:
        # scopedPDU: SEQUENCE { contextEngineId OCTET STRING,
        #                       contextName OCTET STRING, data PDU }
        ce_tag, ce_val, md_pos = decode_ber_tlv(md_val, 0)
        cn_tag, cn_val, md_pos = decode_ber_tlv(md_val, md_pos)
        pdu_tag, pdu_val, md_pos = decode_ber_tlv(md_val, md_pos)
        pdu_type = pdu_tag & 0x1F
        # Parse request-id, error-status, error-index, varbindlist
        rid_tag, rid_val, p_pos = decode_ber_tlv(pdu_val, 0)
        if rid_tag == 0x02:
            request_id = decode_integer(rid_val)
        es_tag, es_val, p_pos = decode_ber_tlv(pdu_val, p_pos)
        if es_tag == 0x02:
            error_status = decode_integer(es_val)
        ei_tag, ei_val, p_pos = decode_ber_tlv(pdu_val, p_pos)
        if ei_tag == 0x02:
            error_index = decode_integer(ei_val)
        vbl_tag, vbl_val, p_pos = decode_ber_tlv(pdu_val, p_pos)
        if vbl_tag == 0x30:
            vb_pos = 0
            while vb_pos < len(vbl_val):
                vb_tag, vb_val, vb_pos = decode_ber_tlv(vbl_val, vb_pos)
                if vb_tag != 0x30:
                    break
                n_tag, n_val, vb_inner = decode_ber_tlv(vb_val, 0)
                oid = decode_oid(n_val) if n_tag == 0x06 else ""
                val_tag, val_val, _ = decode_ber_tlv(vb_val, vb_inner)
                val_str = _decode_varbind_value(val_tag, val_val)
                varbinds.append((oid, val_str, val_tag))
    return {
        "version": version,
        "community": "",
        "pdu_type": pdu_type or PDU_REPORT,
        "request_id": request_id,
        "error_status": error_status,
        "error_index": error_index,
        "varbinds": varbinds,
    }


# ═══════════════════════════════════════════════════════════════════════════
#  SNMP packet building
# ═══════════════════════════════════════════════════════════════════════════
def build_varbind(oid: str, value_bytes: bytes = b"") -> bytes:
    """Build a single varbind SEQUENCE { name OID, value }.
    If value_bytes is empty, value is NULL (used in GetRequest)."""
    if not value_bytes:
        value_bytes = encode_null()
    return encode_sequence(encode_oid(oid) + value_bytes)


def build_varbind_list(varbinds: List[bytes]) -> bytes:
    """Build varbindlist SEQUENCE OF varbind."""
    return encode_sequence(b"".join(varbinds))


def build_pdu(pdu_type: int, request_id: int,
              varbinds: List[bytes],
              error_status: int = 0,
              error_index: int = 0,
              non_repeaters: Optional[int] = None,
              max_repetitions: Optional[int] = None) -> bytes:
    """Build a PDU (context-specific). For GetBulkRequest, error_status and
    error_index fields are repurposed as non-repeaters and max-repetitions."""
    body = encode_integer(request_id)
    if pdu_type == (PDU_GET_BULK & 0x1F):
        # non_repeaters + max_repetitions instead of error-status + error-index
        body += encode_integer(non_repeaters if non_repeaters is not None else 0)
        body += encode_integer(max_repetitions if max_repetitions is not None
                               else 10)
    else:
        body += encode_integer(error_status)
        body += encode_integer(error_index)
    body += build_varbind_list(varbinds)
    tag = 0xA0 | (pdu_type & 0x1F)
    return encode_tlv(tag, body)


def build_snmp_v1_v2c_packet(version: int, community: str,
                             pdu_type: int, request_id: int,
                             oids: List[str],
                             non_repeaters: Optional[int] = None,
                             max_repetitions: Optional[int] = None) -> bytes:
    """Build a full SNMPv1 (version=0) or v2c (version=1) packet."""
    ver_enc = encode_integer(version)
    comm_enc = encode_octet_string(community.encode("ascii"))
    varbinds = [build_varbind(oid) for oid in oids]
    pdu_enc = build_pdu(pdu_type, request_id, varbinds,
                        non_repeaters=non_repeaters,
                        max_repetitions=max_repetitions)
    return encode_sequence(ver_enc + comm_enc + pdu_enc)


def build_snmp_v3_discovery_packet(request_id: int) -> bytes:
    """Build an SNMPv3 discovery packet (RFC 3414 §4).
    Sends a GetRequest with empty USM parameters + reportable flag, which
    triggers the server to send a Report PDU with snmpEngineID."""
    # msgGlobalData SEQUENCE: msgID, msgMaxSize, msgFlags, msgSecurityModel
    msg_id = encode_integer(request_id)
    msg_max_size = encode_integer(65507)
    # msgFlags: 0x04 = reportable, no auth, no priv
    msg_flags = encode_octet_string(bytes([0x04]))
    msg_sec_model = encode_integer(3)  # USM
    global_data = encode_sequence(msg_id + msg_max_size + msg_flags +
                                  msg_sec_model)
    # msgSecurityParameters: empty OctetString (USM params empty)
    # Actually USM params: SEQUENCE { engineID OCTET STRING,
    #   engineBoots INTEGER, engineTime INTEGER, userName OCTET STRING,
    #   authParams OCTET STRING, privParams OCTET STRING }
    usm_engine_id = encode_octet_string(b"")
    usm_engine_boots = encode_integer(0)
    usm_engine_time = encode_integer(0)
    usm_username = encode_octet_string(b"")
    usm_auth_params = encode_octet_string(b"")
    usm_priv_params = encode_octet_string(b"")
    usm_params = encode_sequence(usm_engine_id + usm_engine_boots +
                                 usm_engine_time + usm_username +
                                 usm_auth_params + usm_priv_params)
    msg_sec_params = encode_octet_string(usm_params)
    # scopedPDU: SEQUENCE { contextEngineId, contextName, PDU }
    ctx_engine_id = encode_octet_string(b"")
    ctx_name = encode_octet_string(b"")
    # PDU is GetRequest (0xA0) with empty varbind list (some servers want
    # at least one varbind — use 1.3.6.1 = snmpEngineID's parent)
    pdu = build_pdu(PDU_GET_REQUEST & 0x1F, request_id,
                    [build_varbind("1.3.6.1")])
    scoped_pdu = encode_sequence(ctx_engine_id + ctx_name + pdu)
    # msgData: scopedPDU as plaintext (tag 0x30) — or as encryptedPDU (0x08)
    msg_data = scoped_pdu
    # Top-level SEQUENCE
    ver_enc = encode_integer(SNMP_V3)
    return encode_sequence(ver_enc + global_data + msg_sec_params + msg_data)


# ═══════════════════════════════════════════════════════════════════════════
#  UDP send/recv
# ═══════════════════════════════════════════════════════════════════════════
def send_recv_snmp(host: str, port: int, message: bytes,
                   timeout: float = TIMEOUT_S) -> Tuple[Optional[bytes], str]:
    """Send an SNMP packet over UDP and read the response."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _set_sock_timeout(sock, timeout)
        sock.sendto(message, (host, port))
        try:
            data, _ = sock.recvfrom(65535)
        except (socket.timeout, TimeoutError):
            return None, "timeout"
        except OSError as e:
            return None, f"recv_error:{type(e).__name__}"
        return data, ""
    except (ConnectionRefusedError, OSError) as e:
        return None, f"send_error:{type(e).__name__}"
    except Exception as e:  # noqa: BLE001
        return None, f"error:{type(e).__name__}:{e}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass


# ═══════════════════════════════════════════════════════════════════════════
#  Test 1+4: SNMPv1 GET sysDescr + read sysContact/sysName/sysLocation
# ═══════════════════════════════════════════════════════════════════════════
def test_snmpv1_get_sysdescr(host: str, port: int,
                             results: List[Dict]) -> Tuple[bool, str]:
    """SNMPv1 GET sysDescr with community 'public'. Returns
    (accessible, sysDescr_value)."""
    rid = _rng.randint(1, 0x7FFFFFFF)
    pkt = build_snmp_v1_v2c_packet(SNMP_V1, "public",
                                   PDU_GET_REQUEST, rid, [OID_SYS_DESCR])
    data, err = send_recv_snmp(host, port, pkt)
    if data is None:
        results.append({"test": "snmpv1_get_sysdescr",
                        "verdict": "no_response",
                        "error": err})
        return False, ""
    parsed = decode_snmp_response(data)
    if parsed is None:
        results.append({"test": "snmpv1_get_sysdescr",
                        "verdict": "invalid_response",
                        "raw_len": len(data)})
        return False, ""
    if parsed["pdu_type"] != (PDU_RESPONSE & 0x1F):
        results.append({"test": "snmpv1_get_sysdescr",
                        "verdict": "wrong_pdu_type",
                        "pdu_type": parsed["pdu_type"]})
        return False, ""
    sysdescr = ""
    if parsed["varbinds"]:
        sysdescr = parsed["varbinds"][0][1]
    accessible = parsed["error_status"] == ERR_NO_ERROR
    results.append({
        "test": "snmpv1_get_sysdescr",
        "verdict": "accessible" if accessible else
                   ERR_NAMES.get(parsed["error_status"], "error"),
        "community_used": "public",
        "sysDescr": sysdescr,
        "error_status": parsed["error_status"],
    })
    return accessible, sysdescr


def test_read_system_info(host: str, port: int, community: str,
                          results: List[Dict]) -> Dict[str, str]:
    """Read sysContact, sysName, sysLocation, sysObjectID, sysServices in a
    single GetRequest."""
    oids = [OID_SYS_CONTACT, OID_SYS_NAME, OID_SYS_LOCATION,
            OID_SYS_OBJECT_ID, OID_SYS_SERVICES]
    rid = _rng.randint(1, 0x7FFFFFFF)
    pkt = build_snmp_v1_v2c_packet(SNMP_V1, community,
                                   PDU_GET_REQUEST, rid, oids)
    data, err = send_recv_snmp(host, port, pkt)
    if data is None:
        results.append({"test": "read_system_info",
                        "verdict": "no_response",
                        "error": err})
        return {}
    parsed = decode_snmp_response(data)
    if parsed is None:
        results.append({"test": "read_system_info",
                        "verdict": "invalid_response"})
        return {}
    info = {}
    oid_names = {
        OID_SYS_CONTACT: "sysContact",
        OID_SYS_NAME: "sysName",
        OID_SYS_LOCATION: "sysLocation",
        OID_SYS_OBJECT_ID: "sysObjectID",
        OID_SYS_SERVICES: "sysServices",
    }
    for oid, val, _tag in parsed["varbinds"]:
        name = oid_names.get(oid, oid)
        info[name] = val
    results.append({
        "test": "read_system_info",
        "verdict": "ok" if info else "no_data",
        "community": community,
        "info": info,
        "error_status": parsed["error_status"],
    })
    return info


# ═══════════════════════════════════════════════════════════════════════════
#  Test 2: SNMPv2c community strings
# ═══════════════════════════════════════════════════════════════════════════
def test_community_strings(host: str, port: int,
                           results: List[Dict]) -> List[str]:
    """Probe common community strings via SNMPv2c GET sysDescr. Returns list
    of communities that worked (returned a Response with noError)."""
    worked: List[str] = []
    for community in COMMON_COMMUNITIES:
        rid = _rng.randint(1, 0x7FFFFFFF)
        pkt = build_snmp_v1_v2c_packet(SNMP_V2C, community,
                                       PDU_GET_REQUEST, rid,
                                       [OID_SYS_DESCR])
        data, err = send_recv_snmp(host, port, pkt, timeout=2.0)
        if data is None:
            continue
        parsed = decode_snmp_response(data)
        if parsed is None:
            continue
        if parsed["pdu_type"] == (PDU_RESPONSE & 0x1F) and \
                parsed["error_status"] == ERR_NO_ERROR:
            worked.append(community)
            sysdescr = parsed["varbinds"][0][1] if parsed["varbinds"] else ""
            results.append({
                "test": "community_string",
                "verdict": "worked",
                "community": community,
                "version": "v2c",
                "sysDescr": sysdescr,
            })
        else:
            results.append({
                "test": "community_string",
                "verdict": ERR_NAMES.get(parsed["error_status"], "error")
                           if parsed else "invalid",
                "community": community,
            })
    return worked


# ═══════════════════════════════════════════════════════════════════════════
#  Test 3: SNMPv3 discovery
# ═══════════════════════════════════════════════════════════════════════════
def test_snmpv3_discovery(host: str, port: int,
                          results: List[Dict]) -> bool:
    """Send a SNMPv3 discovery packet (no auth). A server that supports v3
    responds with a Report PDU containing snmpEngineID."""
    rid = _rng.randint(1, 0x7FFFFFFF)
    pkt = build_snmp_v3_discovery_packet(rid)
    data, err = send_recv_snmp(host, port, pkt)
    if data is None:
        results.append({"test": "snmpv3_discovery",
                        "verdict": "no_response",
                        "error": err})
        return False
    parsed = decode_snmp_response(data)
    if parsed is None:
        results.append({"test": "snmpv3_discovery",
                        "verdict": "invalid_response",
                        "raw_len": len(data)})
        return False
    # A Report PDU (0xA8 & 0x1F = 8) confirms v3 support
    is_report = parsed["pdu_type"] == (PDU_REPORT & 0x1F)
    engine_id = ""
    for oid, val, _tag in parsed["varbinds"]:
        if oid == OID_SNMP_ENGINE_ID:
            engine_id = val
    results.append({
        "test": "snmpv3_discovery",
        "verdict": "v3_available" if is_report else "not_v3",
        "pdu_type": parsed["pdu_type"],
        "engine_id": engine_id,
        "varbind_count": len(parsed["varbinds"]),
    })
    return is_report


# ═══════════════════════════════════════════════════════════════════════════
#  Test 5: Writable community check (SetRequest — SAFE_MODE=full only)
# ═══════════════════════════════════════════════════════════════════════════
def test_writable_community(host: str, port: int,
                            communities: List[str],
                            results: List[Dict]) -> bool:
    """For each community that worked, send a SetRequest on a harmless OID
    (sysContact) with a benign probe value. If the response has error_status
    = 0 (noError), the community has WRITE access — CRITICAL.

    SAFE_MODE=read_only: SKIPPED (we never write on production devices).
    SAFE_MODE=full: only on communities that already responded to GET.

    Returns True if any community is writable."""
    if SAFE_MODE != "full":
        results.append({
            "test": "writable_community",
            "verdict": "skipped",
            "reason": ("SAFE_MODE != full — SetRequest on production devices "
                       "is destructive (changes device configuration)"),
        })
        return False
    if not communities:
        results.append({"test": "writable_community",
                        "verdict": "skipped",
                        "reason": "no working communities to test"})
        return False
    writable = False
    # Probe marker value (sysContact, harmless)
    marker_value = f"harness-probe-{SEED}".encode("utf-8")
    for community in communities:
        rid = _rng.randint(1, 0x7FFFFFFF)
        # SetRequest: varbind value is OCTET STRING (sysContact is DisplayString)
        vb = build_varbind(OID_SYS_CONTACT, encode_octet_string(marker_value))
        pdu = build_pdu(PDU_SET_REQUEST & 0x1F, rid, [vb])
        pkt = encode_sequence(
            encode_integer(SNMP_V2C) +
            encode_octet_string(community.encode("ascii")) +
            pdu
        )
        data, err = send_recv_snmp(host, port, pkt)
        if data is None:
            continue
        parsed = decode_snmp_response(data)
        if parsed is None:
            continue
        if parsed["pdu_type"] == (PDU_RESPONSE & 0x1F):
            err_status = parsed["error_status"]
            if err_status == ERR_NO_ERROR:
                writable = True
                results.append({
                    "test": "writable_community",
                    "verdict": "vulnerable_writable",
                    "community": community,
                    "detail": ("SetRequest accepted with no error — community "
                               "has WRITE access (CRITICAL)"),
                })
            else:
                results.append({
                    "test": "writable_community",
                    "verdict": "read_only",
                    "community": community,
                    "error_status": err_status,
                    "error_name": ERR_NAMES.get(err_status, "unknown"),
                })
    return writable


# ═══════════════════════════════════════════════════════════════════════════
#  Test 6: List common OIDs (interfaces, routing, ARP)
# ═══════════════════════════════════════════════════════════════════════════
def test_common_oids(host: str, port: int, community: str,
                     results: List[Dict]) -> List[str]:
    """Use GetNextRequest to walk ifNumber (interfaces count), then probe
    ipRouteTable (routing) and atTable (ARP). Returns list of OIDs that
    returned data."""
    read_oids: List[str] = []
    probes = [
        ("ifNumber", OID_IF_NUMBER),
        ("ipRouteTable", OID_IP_ROUTE_TABLE),
        ("atTable", OID_AT_TABLE),
        ("ipNetToMediaTable", OID_IP_NET_TO_MEDIA),
    ]
    for label, oid in probes:
        rid = _rng.randint(1, 0x7FFFFFFF)
        # GetNextRequest returns the next OID in the MIB after the requested
        # one. Useful for table enumeration.
        pkt = build_snmp_v1_v2c_packet(SNMP_V2C, community,
                                       PDU_GET_NEXT_REQUEST, rid, [oid])
        data, err = send_recv_snmp(host, port, pkt, timeout=2.0)
        if data is None:
            continue
        parsed = decode_snmp_response(data)
        if parsed is None:
            continue
        if parsed["pdu_type"] == (PDU_RESPONSE & 0x1F) and \
                parsed["error_status"] == ERR_NO_ERROR and parsed["varbinds"]:
            next_oid = parsed["varbinds"][0][0]
            value = parsed["varbinds"][0][1]
            read_oids.append(next_oid)
            results.append({
                "test": "common_oid",
                "label": label,
                "verdict": "read_ok",
                "requested_oid": oid,
                "next_oid": next_oid,
                "value": value[:80],  # truncate long values
            })
        else:
            results.append({
                "test": "common_oid",
                "label": label,
                "verdict": ERR_NAMES.get(parsed["error_status"], "error")
                           if parsed else "invalid",
                "requested_oid": oid,
            })
    return read_oids


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("Default-community scanning is read-only. SetRequest "
                           "without authorization is illegal (FR Art. 323-1 / "
                           "US 18 USC §1030). Lab only."),
        }))
        sys.exit(1)

    t0 = time.time()
    results: List[Dict] = []
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "snmp_port": PORT,
        "transport": "UDP",
        "sector": get_sector_config().get("sector", "telecom"),
        "safe_mode": SAFE_MODE,
        "read_only": SAFE_MODE != "full",
        "seed": SEED,
        # Spec-required output fields:
        "snmp_accessible": False,
        "community_strings_worked": [],
        "sysDescr": "",
        "writable_community": False,
        "snmpv3_available": False,
        "oids_read": [],
        "results": results,
        "errors": [],
    }

    # ─── 1. SNMPv1 GET sysDescr ──────────────────────────────────────────
    sysdescr = ""
    try:
        accessible, sysdescr = test_snmpv1_get_sysdescr(HOST, PORT, results)
        summary["snmp_accessible"] = accessible
        summary["sysDescr"] = sysdescr
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"snmpv1_get:{type(e).__name__}:{e}")

    # ─── 2. SNMPv2c community strings ────────────────────────────────────
    communities_worked: List[str] = []
    try:
        communities_worked = test_community_strings(HOST, PORT, results)
        summary["community_strings_worked"] = communities_worked
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"communities:{type(e).__name__}:{e}")

    # ─── 3. SNMPv3 discovery ─────────────────────────────────────────────
    try:
        summary["snmpv3_available"] = test_snmpv3_discovery(HOST, PORT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"snmpv3:{type(e).__name__}:{e}")

    # ─── 4. Read system info (sysContact, sysName, sysLocation) ──────────
    # Use 'public' first; if it didn't work, use any community that worked.
    read_community = "public"
    if communities_worked:
        read_community = communities_worked[0]
    if summary["snmp_accessible"]:
        try:
            test_read_system_info(HOST, PORT, read_community, results)
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"system_info:{type(e).__name__}:{e}")

    # ─── 5. Writable community (SAFE_MODE=full only) ────────────────────
    try:
        summary["writable_community"] = test_writable_community(
            HOST, PORT, communities_worked, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"writable:{type(e).__name__}:{e}")

    # ─── 6. Common OIDs (interfaces, routing, ARP) ──────────────────────
    try:
        summary["oids_read"] = test_common_oids(
            HOST, PORT, read_community, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"common_oids:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
