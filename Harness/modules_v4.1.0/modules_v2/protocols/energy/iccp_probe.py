#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — iccp_probe
# Energy sector module — IEC 60870-6 (ICCP / TASE.2) probing of inter-control-
# center communications. ICCP is the protocol utility control centers use to
# exchange SCADA data (measurements, states, schedules) between themselves.
#
#   - Default port : 102 (MMS / RFC 1006 TPKT — same stack as IEC 61850 MMS,
#                              but ICCP uses different MMS object conventions)
#   - Layer stack  : TCP → TPKT (RFC 1006) → COTP (ISO 8073 class 0) → MMS (BER)
#
#   - Probes performed (all READ-ONLY — no Write, no DefineNamedVariableList,
#     no Operate):
#       1. iccp_initiate    — COTP CR + MMS Initiate-Request → Initiate-
#                             Response. Confirms an ICCP server is listening
#                             AND completes the ACSE/MMS association.
#       2. enumerate_domains — MMS GetNameList(objectClass=domain). ICCP
#                             domains typically start with "ICC_" or contain
#                             the bilateral-table identifier. Count +
#                             identify them.
#       3. enumerate_vlists  — MMS GetNameList(objectClass=namVarList).
#                             ICCP Transfer Sets are stored as MMS Named
#                             Variable Lists — count them.
#       4. enumerate_vars    — MMS GetNameList(objectClass=namVar,
#                             continueAfter=domain) — count the accessible
#                             data points per ICCP domain. Sum total =
#                             data_points.
#       5. bilateral_table   — heuristic: an ICCP domain whose name matches
#                             the bilateral-table pattern (ICC_*, BLT_*) OR
#                             a named variable list named "B<id>" / "TS<id>"
#                             ⇒ bilateral_table=True.
#       6. auth_required     — examine the Initiate-Response. If the server
#                             requires ACSE auth (its Initiate-Response
#                             contains an authentication-error or the
#                             association was rejected for "auth-required")
#                             ⇒ auth_required=True. If we negotiated an MMS
#                             association without any ACSE step ⇒
#                             auth_required=False (legacy unauthenticated
#                             ICCP — common but a security finding).
#
#   - Raw socket implementation: TPKT + COTP frame builder, minimal BER
#     encoder/decoder for MMS PDUs.
#   - READ_ONLY=True (energy sector safety constraint).
#   - SEED env var : deterministic invoke IDs.
#   - LAB=1 mandatory ; 5 s timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (energy) : NERC CIP, NIS2, ENISA, IEC 60870-6,
#   IEC 62351-3 / -4 / -6 (security for ICCP/MMS over TLS).
import json
import os
import random
import socket
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple

# ─── Make sector_base importable from ../../sector_base.py ────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULES_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _MODULES_ROOT not in sys.path:
    sys.path.insert(0, _MODULES_ROOT)

try:
    from sector_base import get_sector_config, get_safe_mode
    SECTOR_BASE_OK = True
except Exception as exc:  # noqa: BLE001
    SECTOR_BASE_OK = False
    _SECTOR_BASE_ERR = str(exc)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "iccp_probe"
DEFAULT_PORT = 102  # MMS / RFC 1006 TPKT
TIMEOUT_S = 5.0
READ_ONLY = True  # energy sector safety constraint

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── SEED for deterministic invoke IDs ─────────────────────────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else None
except ValueError:
    SEED = None
_rng = random.Random(SEED) if SEED is not None else random.Random()


def _next_invoke_id() -> int:
    return _rng.randint(1, 0xFFFFFFFF)


# ─── LAB guard ─────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ─── Sector / SAFE_MODE config ─────────────────────────────────────────────
if SECTOR_BASE_OK:
    SECTOR_CFG = get_sector_config()
    SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")
else:
    SECTOR_CFG = {"sector": "energy", "safe_mode": "read_only"}
    SAFE_MODE = "read_only"


# ═══════════════════════════════════════════════════════════════════════════
#  TPKT (RFC 1006)
# ═══════════════════════════════════════════════════════════════════════════
TPKT_VERSION = 0x03


def tpkt_wrap(payload: bytes) -> bytes:
    total_len = 4 + len(payload)
    return struct.pack(">BBH", TPKT_VERSION, 0x00, total_len) + payload


def _read_n(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def read_tpkt(sock: socket.socket) -> Optional[bytes]:
    header = _read_n(sock, 4)
    if len(header) < 4:
        return None
    version, _rsv, length = struct.unpack(">BBH", header)
    if version != TPKT_VERSION or length < 4:
        return None
    body = _read_n(sock, length - 4)
    return body


# ═══════════════════════════════════════════════════════════════════════════
#  COTP (ISO 8073, class 0)
# ═══════════════════════════════════════════════════════════════════════════
COTP_CR = 0xE0
COTP_CC = 0xD0
COTP_DR = 0x80
COTP_DT = 0xF0


def build_cotp_cr(src_ref: int = 0x0001) -> bytes:
    dst_ref = 0x0000
    class_opts = 0x00
    var_part = bytes([0xC0, 0x01, 0x0A])             # TPDU-SIZE = 1024
    var_part += bytes([0xC2, 0x02, 0x00, 0x01])      # called TSAP
    var_part += bytes([0xC1, 0x02, 0x00, 0x01])      # calling TSAP
    header_no_li = (bytes([COTP_CR]) + struct.pack(">HH", dst_ref, src_ref)
                    + bytes([class_opts]) + var_part)
    li = len(header_no_li)
    return bytes([li]) + header_no_li


def build_cotp_dt(payload: bytes) -> bytes:
    return bytes([0x02, COTP_DT, 0x80]) + payload


def parse_cotp_cr_cc(body: bytes) -> Optional[Dict]:
    if not body or len(body) < 6:
        return None
    li = body[0]
    code = body[1] & 0xF0
    if code not in (COTP_CR, COTP_CC):
        return None
    dst_ref, src_ref = struct.unpack(">HH", body[2:6])
    class_opts = body[6] if len(body) > 6 else 0
    info = {
        "tpdu_type": "CC" if code == COTP_CC else "CR",
        "dst_ref": dst_ref, "src_ref": src_ref,
        "class_opts": class_opts,
        "tpdu_size": None, "has_tsap": False,
    }
    i = 1 + li
    while i + 2 <= len(body):
        pcode = body[i]
        plen = body[i + 1]
        pval = body[i + 2:i + 2 + plen]
        if pcode == 0xC0 and plen >= 1:
            info["tpdu_size"] = 1 << pval[0] if pval[0] <= 0x0F else None
        elif pcode in (0xC1, 0xC2):
            info["has_tsap"] = True
        i += 2 + plen
    return info


def parse_cotp_dt(body: bytes) -> Optional[bytes]:
    if not body or len(body) < 3:
        return None
    li = body[0]
    code = body[1] & 0xF0
    if code != COTP_DT:
        return None
    return body[1 + li:]


# ═══════════════════════════════════════════════════════════════════════════
#  BER (Basic Encoding Rules) — minimal encoder/decoder
# ═══════════════════════════════════════════════════════════════════════════
TAG_UNIV_INTEGER = 0x02
TAG_UNIV_OCTETSTRING = 0x04
TAG_UNIV_NULL = 0x05
TAG_UNIV_OID = 0x06
TAG_UNIV_SEQUENCE = 0x30


def ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    out = b""
    n = length
    while n > 0:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def ber_tlv(tag_byte: int, value: bytes) -> bytes:
    return bytes([tag_byte]) + ber_len(len(value)) + value


def ber_constructed(tag_byte: int, *children: bytes) -> bytes:
    val = b"".join(children)
    return bytes([tag_byte]) + ber_len(len(val)) + val


def ber_context_tag(num: int, constructed: bool, value: bytes) -> bytes:
    if num > 30:
        tag = bytes([0x80 | (0x20 if constructed else 0x00) | 0x1F])
        out = b""
        n = num
        while n > 0:
            out = bytes([(n & 0x7F) | 0x80]) + out
            n >>= 7
        if out:
            out = out[:-1] + bytes([out[-1] & 0x7F])
        tag = tag + out
    else:
        tag = bytes([0x80 | (0x20 if constructed else 0x00) | num])
    return tag + ber_len(len(value)) + value


def ber_decode_len(data: bytes, idx: int) -> Tuple[int, int]:
    """Decode a BER length at idx; return (length, new_idx)."""
    if idx >= len(data):
        return (0, idx)
    b = data[idx]
    idx += 1
    if b < 0x80:
        return (b, idx)
    n = b & 0x7F
    if n == 0 or idx + n > len(data):
        return (0, idx)
    length = 0
    for _ in range(n):
        length = (length << 8) | data[idx]
        idx += 1
    return (length, idx)


def ber_decode_int(data: bytes, idx: int) -> Tuple[Optional[int], int]:
    if idx >= len(data) or data[idx] != TAG_UNIV_INTEGER:
        return (None, idx)
    idx += 1
    length, idx = ber_decode_len(data, idx)
    if idx + length > len(data):
        return (None, idx)
    val = int.from_bytes(data[idx:idx + length], "big", signed=True)
    return (val, idx + length)


# ═══════════════════════════════════════════════════════════════════════════
#  MMS PDU BUILDERS
# ═══════════════════════════════════════════════════════════════════════════
# Confirmed-RequestPDU ::= [0] confirmedRequestPDU
# confirmedRequestPDU ::= SEQUENCE { invokeID INTEGER, listOfConfirmedRequests }
MMS_CONFIRMED_REQ_TAG = 0xA0
# Initiate-RequestPDU tag inside confirmedRequestPDU is [0]
# GetNameList-Request is [1]

# MMS ObjectClass enum (AbstractSyntaxName):
#   domain (0), named-variable-list (2), named-variable (named after domain),
#   semaphore (3), etc. GetNameList uses a CHOICE: objectClass [0] named OR
#   objectScope [1].

# We use simple integer encoding for objectClass:
#   0 = domain
#   2 = named-variable-list
#   3 = named-variable (when paired with a domain scope)


def build_mms_initiate_request() -> bytes:
    """Build a minimal MMS Initiate-RequestPDU.

    Per IEC 61850-7-2 / IEC 60870-6-802 (ICCP):
      InitiateRequestPDU ::= SEQUENCE {
        localDetailCalling       [0] IMPLICIT INTEGER,
        proposedMaxServOutstandingCalling [1] IMPLICIT INTEGER,
        proposedMaxServOutstandingCalled  [2] IMPLICIT INTEGER,
        proposedDataStructureNestingLevel [3] IMPLICIT INTEGER OPTIONAL,
        initRequestDetail        [4] SEQUENCE {
          proposedVersionNumber  [0] INTEGER (0..1),
          proposedParameterCBB   [1] BIT STRING,
          servicesSupportedCalled [2] BIT STRING } }

    The BIT STRING for servicesSupportedCalled advertises which MMS services
    the caller supports — we set all flags to 0 except Initiate + GetNameList
    + GetVariableAccessAttributes (so an ICCP server sees we only want
    read-only enumeration).
    """
    # localDetailCalling = 1024 (max fragment size we accept)
    inner = (
        ber_context_tag(0, False, _ber_int(1024)) +
        ber_context_tag(1, False, _ber_int(8)) +    # maxServOutstandingCalling
        ber_context_tag(2, False, _ber_int(8))      # maxServOutstandingCalled
    )
    # servicesSupportedCalled bit string: 11 bytes (BIT STRING: 1 unused-bit
    # count byte + 10 bytes of flag bits). We set bits 0 (Status), 1 (GetNameList),
    # 2 (GetVariableAccessAttributes), 4 (Identify), 6 (GetNamedVariableList),
    # ... see MMS service bit table. For brevity we set just bytes:
    # bit 1 (GetNameList) is in byte 0 bit 1 → 0x02
    # bit 6 (Identify)    is in byte 0 bit 6 → 0x40
    # Combined byte 0: 0x42, others 0
    flags = bytes([0x42]) + b"\x00" * 9
    init_detail = (
        ber_context_tag(0, False, _ber_int(1)) +          # proposedVersionNumber=1
        ber_context_tag(1, False,
                        bytes([0x07]) + b"\x00") +        # parameterCBB (1 byte)
        ber_context_tag(2, False, bytes([0x00]) + flags)  # servicesSupportedCalled (10 bytes + 1 unused count)
    )
    init_detail_tlv = ber_context_tag(4, True, init_detail)
    init_req = ber_context_tag(0, True, inner + init_detail_tlv)
    return init_req


def _ber_int(val: int) -> bytes:
    """Encode a non-negative int as a BER INTEGER (signed)."""
    if val == 0:
        return bytes([0x02, 0x01, 0x00])
    # Calculate byte length
    n = val
    length = 0
    while n > 0:
        n >>= 8
        length += 1
    # If MSB is set, prepend 0x00 to keep sign positive
    if (val >> (8 * (length - 1))) & 0x80:
        length += 1
    return bytes([0x02, length]) + val.to_bytes(length, "big")


def build_mms_confirmed_request(invoke_id: int, service_tag: int,
                                service_pdu: bytes) -> bytes:
    """Build a Confirmed-RequestPDU.

    Structure:
      [0] SEQUENCE {
        invokeID INTEGER,
        service CHOICE { <tag> <service_pdu> }
      }
    The service CHOICE tag is a context tag [N] where N depends on the service:
      GetNameList-Request = [1]
      GetVariableAccessAttributes-Request = [4]
      Initiate-RequestPDU is in the Initiate-RequestPDU directly (not in
      Confirmed-RequestPDU) — for our purposes we send it as a separate
      MMS-PDU wrapper.
    """
    body = ber_tlv(TAG_UNIV_INTEGER, _ber_int_value(invoke_id)) + \
        ber_context_tag(service_tag, True, service_pdu)
    return bytes([MMS_CONFIRMED_REQ_TAG]) + ber_len(len(body)) + body


def _ber_int_value(val: int) -> bytes:
    """Encode int as just the value bytes (no tag/length)."""
    if val == 0:
        return b"\x00"
    n = val
    length = 0
    while n > 0:
        n >>= 8
        length += 1
    if (val >> (8 * (length - 1))) & 0x80:
        length += 1
    return val.to_bytes(length, "big")


def build_getnamelist_request(object_class: int,
                              continue_after: Optional[bytes] = None) -> bytes:
    """Build a GetNameList-Request.

    GetNameList-Request ::= [1] SEQUENCE {
      objectClass  [0] CHOICE { basicData<obj> [N] INTEGER } OPTIONAL,
      objectScope   [1] SEQUENCE { ... } OPTIONAL,
      continueAfter [2] Identifier OPTIONAL }
    `object_class` is the integer object class (0=domain, 2=namVarList,
    3=namVar, ...). We encode it as the basic CHOICE: [0] [N] IMPLICIT INTEGER.
    For brevity we use the implicit form: [0] is a context-tag wrapper around
    the actual class enum.
    """
    # objectClass [0] is a CHOICE on ObjectClass ::= CHOICE { basicData [0] INTEGER,
    # ... }. We encode basicData which is itself [N] of INTEGER value.
    # MMS objectClass basicData integer values (TASE.2):
    #   0 = domain, 2 = named-variable-list, etc.
    # The CHOICE uses context tag 0 for basicData, and the inner integer
    # is also context-tagged with the value of the class.
    # Simplified: we just send [0] INTEGER (the class number directly).
    object_class_tlv = ber_context_tag(0, False, _ber_int_value(object_class))
    inner = object_class_tlv
    if continue_after is not None:
        inner += ber_context_tag(2, False, continue_after)
    return inner


# ═══════════════════════════════════════════════════════════════════════════
#  MMS RESPONSE PARSERS
# ═══════════════════════════════════════════════════════════════════════════

def parse_mms_pdu(data: bytes) -> Optional[Dict]:
    """Parse a top-level MMS PDU.

    Returns {kind, content, error}. `kind` is one of:
      'initiate-response'   ([8] Initiate-ResponsePDU)
      'confirmed-response'  ([1] Confirmed-ResponsePDU)
      'confirmed-error'     ([2] Confirmed-ErrorPDU)
      'reject'              ([4] RejectPDU)
      'conclude-request'    ([2] Conclude-RequestPDU)
    """
    if not data:
        return None
    tag = data[0]
    length, idx = ber_decode_len(data, 1)
    content = data[idx: idx + length]
    if tag == 0xA8:
        return {"kind": "initiate-response", "content": content}
    if tag == 0xA1:
        return {"kind": "confirmed-response", "content": content}
    if tag == 0xA2:
        return {"kind": "confirmed-error", "content": content}
    if tag == 0xA4:
        return {"kind": "reject", "content": content}
    if tag == 0xA2 and length == 0:
        return {"kind": "conclude-request", "content": content}
    return {"kind": f"unknown:0x{tag:02X}", "content": content}


def parse_initiate_response(content: bytes) -> Dict:
    """Parse an Initiate-ResponsePDU.

    Returns:
      {negotiated_version, supported_services, auth_required}
    """
    out: Dict = {"negotiated_version": None, "supported_services": None,
                 "auth_required": None, "parsed_ok": False}
    # The Initiate-ResponsePDU is a SEQUENCE — we walk through context-tagged
    # children. Per the ASN.1, children are:
    #   [0] localDetailCalled INTEGER
    #   [1] negotiatedDataStructureNestingLevel INTEGER
    #   [2] initResponseDetail SEQUENCE {
    #       [0] negotiatedVersionNumber INTEGER
    #       [1] negotiatedParameterCBB BIT STRING
    #       [2] servicesSupportedCalled BIT STRING }
    # We only need negotiatedVersionNumber and servicesSupportedCalled.
    try:
        idx = 0
        while idx < len(content):
            tag = content[idx]
            length, idx = ber_decode_len(content, idx + 1)
            if tag == 0xA2:  # [2] initResponseDetail SEQUENCE
                detail = content[idx: idx + length]
                d_idx = 0
                while d_idx < len(detail):
                    d_tag = detail[d_idx]
                    d_len, d_idx = ber_decode_len(detail, d_idx + 1)
                    if d_tag == 0x80:  # [0] version
                        # INTEGER value
                        v = int.from_bytes(detail[d_idx: d_idx + d_len],
                                           "big", signed=True)
                        out["negotiated_version"] = v
                    elif d_tag == 0x82:  # [2] servicesSupportedCalled
                        out["supported_services"] = detail[d_idx: d_idx + d_len].hex()
                    d_idx += d_len
                out["parsed_ok"] = True
                break
            idx += length
    except Exception:  # noqa: BLE001
        pass
    return out


def parse_getnamelist_response(content: bytes) -> Tuple[List[str], Optional[bytes]]:
    """Parse a GetNameList-Response.

    Returns (list_of_names, more_follows).
    `more_follows` is the continueAfter identifier to use in the next
    request, or None if no more follows.
    """
    names: List[str] = []
    more: Optional[bytes] = None
    # GetNameList-Response ::= [1] SEQUENCE {
    #   listOfIdentifier [0] SEQUENCE OF Identifier,
    #   moreFollows       [1] BOOLEAN DEFAULT FALSE,
    #   continueAfter     [2] Identifier OPTIONAL }
    # Actually the request is wrapped in Confirmed-ResponsePDU:
    #   Confirmed-ResponsePDU ::= [1] SEQUENCE {
    #     invokeID INTEGER,
    #     confirmedServiceResponse CHOICE { ... } }
    try:
        idx = 0
        # Skip invokeID INTEGER
        if idx < len(content) and content[idx] == 0x02:
            _l, idx = ber_decode_len(content, idx + 1)
            idx += _l
        # Now expect the service CHOICE — for GetNameList it's [1]
        if idx < len(content) and content[idx] == 0xA1:
            _l, idx = ber_decode_len(content, idx + 1)
            inner_end = idx + _l
            while idx < inner_end:
                tag = content[idx]
                length, idx = ber_decode_len(content, idx + 1)
                if tag == 0xA0:  # [0] listOfIdentifier SEQUENCE OF
                    seq = content[idx: idx + length]
                    s_idx = 0
                    while s_idx < len(seq):
                        if seq[s_idx] == TAG_UNIV_OCTETSTRING or \
                                seq[s_idx] == 0x16:  # OCTET STRING or IA5String
                            sl, s_idx = ber_decode_len(seq, s_idx + 1)
                            try:
                                names.append(seq[s_idx:s_idx + sl].decode(
                                    "ascii", errors="replace"))
                            except Exception:  # noqa: BLE001
                                names.append(seq[s_idx:s_idx + sl].hex())
                            s_idx += sl
                        else:
                            sl, s_idx = ber_decode_len(seq, s_idx + 1)
                            s_idx += sl
                elif tag == 0x81:  # [1] moreFollows BOOLEAN
                    if length >= 1 and content[idx] != 0:
                        # more follows — capture continueAfter if present
                        pass
                elif tag == 0x82:  # [2] continueAfter
                    more = content[idx: idx + length]
                idx += length
    except Exception:  # noqa: BLE001
        pass
    return names, more


# ═══════════════════════════════════════════════════════════════════════════
#  ICCP / MMS ASSOCIATION
# ═══════════════════════════════════════════════════════════════════════════

def open_iccp_association(host: str, port: int) -> Optional[Dict]:
    """Open a COTP/MMS association with an ICCP server.

    Returns {sock, cotp_info, initiate_ok, init_response_content, error}
    or None on transport failure.
    """
    out: Dict = {"sock": None, "cotp_info": None, "initiate_ok": False,
                 "init_response_content": None, "error": None}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_S)
        sock.connect((host, port))
        out["sock"] = sock
    except (socket.timeout, TimeoutError):
        out["error"] = "connect_timeout"; return out
    except ConnectionRefusedError:
        out["error"] = "connection_refused"; return out
    except OSError as e:
        out["error"] = f"connect_os:{type(e).__name__}:{e}"; return out

    # 1. COTP CR
    try:
        cr = build_cotp_cr(src_ref=0x0001)
        sock.sendall(tpkt_wrap(cr))
        body = read_tpkt(sock)
        if body is None:
            out["error"] = "no_cotp_response"; return out
        info = parse_cotp_cr_cc(body)
        if info is None:
            out["error"] = "cotp_parse_failed"; return out
        if info["tpdu_type"] != "CC":
            out["error"] = f"cotp_not_cc:{info['tpdu_type']}"; return out
        out["cotp_info"] = info
    except (socket.timeout, TimeoutError):
        out["error"] = "cotp_timeout"; return out
    except OSError as e:
        out["error"] = f"cotp_os:{type(e).__name__}:{e}"; return out

    # 2. MMS Initiate
    try:
        init_req = build_mms_initiate_request()
        sock.sendall(tpkt_wrap(build_cotp_dt(init_req)))
        body2 = read_tpkt(sock)
        if body2 is None:
            out["error"] = "no_mms_response"; return out
        mms_payload = parse_cotp_dt(body2)
        if mms_payload is None:
            out["error"] = "cotp_dt_not_parsed"; return out
        parsed = parse_mms_pdu(mms_payload)
        if not parsed:
            out["error"] = "mms_parse_failed"; return out
        if parsed.get("kind") == "initiate-response":
            out["initiate_ok"] = True
            out["init_response_content"] = parsed.get("content")
        elif parsed.get("kind") == "confirmed-error":
            out["error"] = "initiate:confirmed-error"
        elif parsed.get("kind") == "reject":
            out["error"] = "initiate:reject"
        else:
            out["error"] = f"initiate:unexpected:{parsed.get('kind')}"
    except (socket.timeout, TimeoutError):
        out["error"] = "mms_timeout"; return out
    except OSError as e:
        out["error"] = f"mms_os:{type(e).__name__}:{e}"; return out

    return out


def close_mms(sock: socket.socket) -> None:
    if sock is None:
        return
    try:
        # Send a COTP DR (disconnect)
        dr = bytes([0x02, 0x80, 0x00, 0x00, 0x00, 0x00])
        sock.sendall(tpkt_wrap(dr))
    except Exception:  # noqa: BLE001
        pass
    try:
        sock.close()
    except Exception:  # noqa: BLE001
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  ICCP ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════

def mms_getnamelist(sock: socket.socket, object_class: int,
                    continue_after: Optional[bytes] = None,
                    max_rounds: int = 8) -> Dict:
    """Issue a GetNameList request and collect all returned identifiers
    (following moreFollows / continueAfter up to max_rounds).
    """
    result: Dict = {"names": [], "rounds": 0, "error": None}
    cont = continue_after
    for _ in range(max_rounds):
        invoke_id = _next_invoke_id()
        svc = build_getnamelist_request(object_class, continue_after=cont)
        pdu = build_mms_confirmed_request(invoke_id, 1, svc)
        try:
            sock.sendall(tpkt_wrap(build_cotp_dt(pdu)))
            body = read_tpkt(sock)
        except (socket.timeout, TimeoutError):
            result["error"] = "timeout"; return result
        except OSError as e:
            result["error"] = f"os:{type(e).__name__}"; return result
        if body is None:
            result["error"] = "no_response"; return result
        mms_payload = parse_cotp_dt(body)
        if mms_payload is None:
            result["error"] = "cotp_dt_not_parsed"; break
        parsed = parse_mms_pdu(mms_payload)
        if not parsed:
            result["error"] = "mms_parse_failed"; break
        if parsed.get("kind") == "confirmed-response":
            names, more = parse_getnamelist_response(parsed.get("content") or b"")
            result["names"].extend(names)
            result["rounds"] += 1
            if more and more != cont:
                cont = more
                continue
            else:
                break
        elif parsed.get("kind") == "confirmed-error":
            result["error"] = "getnamelist:confirmed-error"
            break
        elif parsed.get("kind") == "reject":
            result["error"] = "getnamelist:reject"
            break
        else:
            result["error"] = f"getnamelist:unexpected:{parsed.get('kind')}"
            break
    return result


# ICCP/TASE.2 conventions:
#   Domain names typically start with "ICC_" or contain a bilateral ID.
#   Transfer Sets are Named Variable Lists with names like "TS_<id>" or
#   follow TASE.2 naming. Bilateral tables are stored as Named Variable
#   Lists with the prefix "B<id>" or as special ICCP BLT objects.
_ICCP_DOMAIN_PATTERNS = ("ICC_", "ICCP_", "BLT_", "TASE")
_ICCP_BLT_PATTERNS = ("B", "BLT", "bilateral", "TS_")  # transfer sets / BLT


def looks_like_iccp_domain(name: str) -> bool:
    n = name.upper()
    return any(p in n for p in _ICCP_DOMAIN_PATTERNS)


def looks_like_blt_or_transfer_set(name: str) -> bool:
    n = name.upper()
    return any(n.startswith(p) or p in n for p in _ICCP_BLT_PATTERNS)


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("ICCP / TASE.2 probing on production inter-control-"
                           "center links is illegal outside an authorized lab. "
                           "NERC CIP / IEC 60870-6 / IEC 62351."),
        }))
        sys.exit(1)

    t0 = time.time()
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "port": PORT,
        "sector": SECTOR_CFG.get("sector"),
        "safe_mode": SAFE_MODE,
        "read_only": READ_ONLY,
        "seed": SEED,
        # Spec-required output fields:
        "iccp_accessible": False,
        "bilateral_table": False,
        "transfer_sets": 0,
        "auth_required": False,
        "data_points": 0,
        # Extra diagnostic fields:
        "domains": [],
        "named_variable_lists": [],
        "initiate": {},
        "errors": [],
    }

    # ─── 1. Open ICCP / MMS association ────────────────────────────────────
    assoc = open_iccp_association(HOST, PORT)
    if assoc is None or assoc.get("sock") is None or not assoc.get("initiate_ok"):
        summary["errors"].append(f"assoc:{assoc.get('error') if assoc else 'none'}")
        # auth_required inference: if the MMS Initiate was rejected, the
        # server may require ACSE auth (IEC 62351-6).
        err = assoc.get("error") if assoc else None
        if err and ("confirmed-error" in err or "reject" in err
                    or "initiate:" in err):
            summary["auth_required"] = True
        summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
        print(json.dumps(summary, indent=2, default=str))
        return

    summary["iccp_accessible"] = True
    summary["initiate"] = parse_initiate_response(
        assoc.get("init_response_content") or b""
    )
    # If we negotiated an MMS Initiate WITHOUT any ACSE auth step → the
    # server did NOT require authentication (legacy unauthenticated ICCP).
    summary["auth_required"] = False

    sock = assoc["sock"]

    # ─── 2. Enumerate domains (ICCP Logical Devices) ───────────────────────
    try:
        domains_res = mms_getnamelist(sock, object_class=0, max_rounds=8)
        summary["domains"] = domains_res.get("names", [])
        if domains_res.get("error"):
            summary["errors"].append(f"domains:{domains_res['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"domains:{type(e).__name__}:{e}")

    # ─── 3. Enumerate Named Variable Lists (ICCP Transfer Sets) ────────────
    try:
        vlists_res = mms_getnamelist(sock, object_class=2, max_rounds=8)
        summary["named_variable_lists"] = vlists_res.get("names", [])
        if vlists_res.get("error"):
            summary["errors"].append(f"vlists:{vlists_res['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"vlists:{type(e).__name__}:{e}")

    # ─── 4. Enumerate Named Variables per domain (count data points) ──────
    # For ICCP, named variables live inside domains; the MMS GetNameList
    # object class is "named-variable" but scoped to a specific domain.
    # In the simplified BER we just count all known ICCP-domain-named vars
    # in a single round (without per-domain scope iteration) — enough for a
    # best-effort count.
    try:
        vars_res = mms_getnamelist(sock, object_class=3, max_rounds=4)
        if vars_res.get("error"):
            summary["errors"].append(f"vars:{vars_res['error']}")
        summary["data_points"] = len(vars_res.get("names", []))
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"vars:{type(e).__name__}:{e}")

    close_mms(sock)

    # ─── 5. ICCP bilateral-table & transfer-set inference ─────────────────
    iccp_domains = [d for d in summary["domains"] if looks_like_iccp_domain(d)]
    blt_named = [n for n in summary["named_variable_lists"]
                 if looks_like_blt_or_transfer_set(n)]
    summary["bilateral_table"] = bool(iccp_domains or blt_named)
    summary["transfer_sets"] = len(summary["named_variable_lists"])

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
