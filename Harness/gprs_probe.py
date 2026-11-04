#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — gprs_probe (telecom protocol module)
# GPRS (2G/3G packet data) probe — GGSN/SGSN GTP-C / GTP-U interfaces.
#
# GPRS Tunnelling Protocol (GTP, 3GPP TS 29.060 for GTPv1, TS 29.274 for
# GTPv2) carries control-plane (GTP-C, port 2123) and user-plane (GTP-U,
# port 2152) traffic between SGSN/GGSN (2G/3G) and between MME/SGW/PGW
# (4G LTE, GTPv2). GTP' (port 3386) carries charging data to the CGF.
#
# Tests:
#   1. Port scan GGSN mgmt ports (2123 GTP-C, 2152 GTP-U, 3386 GTP')
#   2. GTP-C Echo Request on port 2123 → echo_response
#   3. GTP-U port 2152 open check      → gtp_u_accessible
#   4. GTP-C Create PDP Context w/o auth → create_pdp_without_auth (CRIT)
#   5. APN list discovery (common APN probe) → apns_found
#
# GTPv1 frame format (3GPP TS 29.060 §6):
#   Byte 0: bits[7:5]=Version(001), bit 4=PT(1), bit 3=R(0),
#           bit 2=E(ext), bit 1=S(seq), bit 0=PN(npdu)
#   Byte 1: Message Type
#   Bytes 2-3: Length (BE) — covers everything after the length field
#   Bytes 4-7: TEID (BE) — Tunnel Endpoint Identifier
#   Optional (if S/E/PN): 2-byte seq + 1-byte npdu + 1-byte next-ext
#   Payload: Information Elements (IEs)
#
# GTP-C message types:
#   1 = Echo Request, 2 = Echo Response
#   16 = Create PDP Context Request, 17 = Create PDP Context Response
#   20 = Delete PDP Context Request, 21 = Delete PDP Context Response
#   26 = Error Indication
#
# GTP-C Echo Request: no payload (or Private Extension IE).
# GTP-C Echo Response: Recovery IE (type 14, TV format: 0x0E + 1 byte).
#
# GTPv1 Create PDP Context Request IEs (3GPP TS 29.060 §7.3.1):
#   - IMSI (type 2, TV: 0x02 + 8 bytes IMSI BCD)
#   - Recovery (type 14, TV: 0x0E + 1 byte)
#   - TEID Data I (type 16, TLV: 0x10 + 2-byte len + 4-byte TEID)
#   - TEID Control Plane (type 17, TLV: 0x11 + 2-byte len + 4-byte TEID)
#   - NSAPI (type 20, TV: 0x14 + 1 byte)
#   - PDP Type Org + PDP Type Number (TLV)
#   - PDP Address (TLV)
#   - APN (TLV)
#   - SGSN Address for signaling (TLV)
#   - SGSN Address for user traffic (TLV)
#   - QoS Profile (TLV)
#
# Cause codes in Create PDP Context Response (TS 29.060 §7.3.5):
#   128 = Request accepted (CRITICAL if without auth!)
#   192 = Non-existent
#   193 = Invalid message format
#   194 = IMSI not known
#   195 = System failure
#   200 = Unknown APN
#   203 = User authentication failed
#
# CLI:
#   python3 gprs_probe.py [host] [port]
#       host default = 127.0.0.1
#       port default = 2123  (GTP-C)
#
# Output: single JSON object on stdout.
#
# Legal: Sending Create PDP Context to a production GGSN can bill subscribers
# or trigger alerts. LAB only (FR Art. 323-1 / US 18 USC §1030).
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
MODULE_NAME = "gprs_probe"
TIMEOUT_S = 5  # 5 s hard cap on every socket op

# ─── CLI args ─────────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 2123
except ValueError:
    PORT = 2123

# SAFE_MODE can be overridden via env. telecom sector default = read_only.
# In read_only mode we DO NOT send Create PDP Context (we use Echo only).
SAFE_MODE = os.environ.get("SAFE_MODE", "read_only")

# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))
_rng = random.Random(SEED)

# ─── LAB guard ────────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ═══════════════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════════════
GTP_C_PORT = 2123   # GTP-C control plane (IANA)
GTP_U_PORT = 2152   # GTP-U user plane (IANA)
GTP_PRIME_PORT = 3386  # GTP' charging (IANA)

# GTPv1 message types (3GPP TS 29.060 §7.1)
MSG_ECHO_REQUEST = 1
MSG_ECHO_RESPONSE = 2
MSG_VERSION_NOT_SUPPORTED = 3
MSG_CREATE_PDP_CTX_REQ = 16
MSG_CREATE_PDP_CTX_RSP = 17
MSG_DELETE_PDP_CTX_REQ = 20
MSG_DELETE_PDP_CTX_RSP = 21
MSG_ERROR_INDICATION = 26

# GTPv1 IE types (3GPP TS 29.060 §7.7)
IE_CAUSE = 1          # TV: 1 byte cause (in Create PDP Response)
IE_IMSI = 2           # TV: 8 bytes BCD
IE_RECOVERY = 14      # TV: 1 byte restart counter
IE_TEID_DATA_I = 16   # TLV: 4 byte TEID
IE_TEID_CTRL = 17     # TLV: 4 byte TEID
IE_TEID_DATA_II = 18  # TLV: 1 byte NSAPI + 4 byte TEID
IE_NSAPI = 20         # TV: 1 byte (NSAPI in lower nibble)
IE_PDP_TYPE = 23      # TLV
IE_PDP_ADDRESS = 24   # TLV
IE_APN = 28           # TLV
IE_SGSN_ADDR_SIG = 29 # TLV
IE_SGSN_ADDR_USR = 30 # TLV
IE_QOS_PROFILE = 31   # TLV

# Cause values (3GPP TS 29.060 §7.3.5)
CAUSE_REQUEST_ACCEPTED = 128
CAUSE_NON_EXISTENT = 192
CAUSE_INVALID_MSG = 193
CAUSE_IMSI_UNKNOWN = 194
CAUSE_SYSTEM_FAILURE = 195
CAUSE_UNKNOWN_APN = 200
CAUSE_USER_AUTH_FAILED = 203


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
#  GTPv1 frame building
# ═══════════════════════════════════════════════════════════════════════════
def build_gtp_v1(msg_type: int, teid: int, seq_no: int,
                 payload: bytes, has_seq: bool = True) -> bytes:
    """Build a GTPv1 frame (3GPP TS 29.060 §6):
       flags(1) + msg_type(1) + length(2 BE) + TEID(4 BE) +
       optional(seq(2) + npdu(1) + next_ext(1)) + payload

    flags bits: V(3)=001, PT=1, R=0, E=0, S=1 (if has_seq), PN=0
    => flags = 0x30 (no seq) | 0x02 (S bit) → wait, S bit is bit 1 = 0x02?
    Actually:
      bit 7 (MSB)  = V[2]
      bit 6        = V[1]
      bit 5        = V[0]
      bit 4        = PT
      bit 3        = R (reserved)
      bit 2        = E (extension)
      bit 1        = S (sequence number)
      bit 0 (LSB)  = PN (N-PDU number)
    So V=001 = bits 7:5 = 001 → 0x20
       PT=1 → bit 4 → 0x10
       S=1 → bit 1 → 0x02
    => 0x30 (V+PT) | 0x02 (S) = 0x32
    """
    flags = 0x30  # version=1, PT=1
    optional = b""
    if has_seq:
        flags |= 0x02  # S bit
        # Sequence (2) + N-PDU (1) + Next-Ext-Header (1)
        optional = struct.pack(">HBB", seq_no & 0xFFFF, 0, 0)
    # Length field: everything after the length field itself
    # = 4 (TEID) + len(optional) + len(payload)
    length = 4 + len(optional) + len(payload)
    header = bytes([flags, msg_type & 0xFF]) + struct.pack(">H", length) + \
             struct.pack(">I", teid & 0xFFFFFFFF)
    return header + optional + payload


def parse_gtp_v1(data: bytes) -> Optional[Dict]:
    """Parse a GTPv1 frame. Returns dict with version, msg_type, length,
    teid, seq, npdu, next_ext, payload, or None if too short / not GTP."""
    if len(data) < 8:
        return None
    flags = data[0]
    version = (flags >> 5) & 0x07
    if version != 1:
        return None  # not GTPv1
    pt = (flags >> 4) & 0x01
    has_ext = (flags >> 3) & 0x01
    has_seq = (flags >> 2) & 0x01  # wait that's E... let me recheck
    # Per spec: bit 3=E, bit 2=S, bit 1=PN? But spec also says bit 2 is S.
    # Looking again at 3GPP TS 29.060 §6: bit numbering uses bit 8 = MSB,
    # bit 1 = LSB. So:
    #   bit 8 7 6 = Version
    #   bit 5 = PT
    #   bit 4 = Reserved
    #   bit 3 = E (Extension Header flag)
    #   bit 2 = S (Sequence Number flag)
    #   bit 1 = PN (N-PDU Number flag)
    # In Python with bit positions 7..0:
    #   bit 7 6 5 = version  (V >> 5)
    #   bit 4     = PT       (V >> 4) & 1
    #   bit 3     = Reserved
    #   bit 2     = E        (V >> 2) & 1
    #   bit 1     = S        (V >> 1) & 1
    #   bit 0     = PN       (V) & 1
    has_ext = (flags >> 2) & 0x01
    has_seq = (flags >> 1) & 0x01
    has_npdu = flags & 0x01
    msg_type = data[1]
    length = struct.unpack(">H", data[2:4])[0]
    teid = struct.unpack(">I", data[4:8])[0]
    pos = 8
    seq_no = 0
    npdu = 0
    next_ext = 0
    if has_seq or has_npdu or has_ext:
        if pos + 4 > len(data):
            return None
        seq_no = struct.unpack(">H", data[pos:pos + 2])[0]
        npdu = data[pos + 2]
        next_ext = data[pos + 3]
        pos += 4
    payload = data[pos:pos + length - (pos - 8)]
    # The length field counts everything after the 4-byte mandatory header
    # (so optional + payload). Recompute correctly:
    optional_len = 4 if (has_seq or has_npdu or has_ext) else 0
    payload = data[8 + optional_len:8 + optional_len + (length - optional_len)]
    return {
        "version": version,
        "pt": pt,
        "msg_type": msg_type,
        "length": length,
        "teid": teid,
        "seq": seq_no,
        "npdu": npdu,
        "next_ext": next_ext,
        "has_seq": bool(has_seq),
        "has_ext": bool(has_ext),
        "has_npdu": bool(has_npdu),
        "payload": payload,
    }


# ═══════════════════════════════════════════════════════════════════════════
#  GTP-C Echo Request (3GPP TS 29.060 §7.2)
# ═══════════════════════════════════════════════════════════════════════════
def build_echo_request(seq_no: int) -> bytes:
    """Echo Request has no payload (optionally a Private Extension IE).
    TEID=0 (signaling)."""
    return build_gtp_v1(MSG_ECHO_REQUEST, teid=0, seq_no=seq_no,
                        payload=b"", has_seq=True)


# ═══════════════════════════════════════════════════════════════════════════
#  GTP-C Create PDP Context Request (3GPP TS 29.060 §7.3.1)
# ═══════════════════════════════════════════════════════════════════════════
def encode_imsi_bcd(imsi_str: str) -> bytes:
    """Encode an IMSI as 8 bytes BCD (TS 23.003 §2.2 + TS 29.060 §7.7.2).
    IMSI is up to 15 digits. BCD-encoded with swapped nibbles, padded
    with 0xF if odd length. Total = 8 bytes."""
    digits = "".join(c for c in imsi_str if c.isdigit())
    if len(digits) > 15:
        digits = digits[:15]
    if len(digits) % 2 == 1:
        digits += "F"  # pad with F
    out = bytearray()
    for i in range(0, len(digits), 2):
        n1 = int(digits[i], 16) if digits[i] != "F" else 0xF
        n2 = int(digits[i + 1], 16) if digits[i + 1] != "F" else 0xF
        out.append((n2 << 4) | n1)  # swap nibbles
    # Pad to 8 bytes total
    while len(out) < 8:
        out.append(0xFF)
    return bytes(out[:8])


def build_create_pdp_context_request(seq_no: int, imsi: str, apn: str) -> bytes:
    """Build a minimal Create PDP Context Request. This is sent only if
    SAFE_MODE=full. The fields are minimally populated to be parseable
    by a GGSN; the GGSN should reject this as 'IMSI not known' (cause 194)
    if it does auth, or 'Request accepted' (128) if it doesn't (CRITICAL)."""
    # IE: IMSI (TV: 0x02 + 8 bytes BCD)
    ies = bytes([IE_IMSI]) + encode_imsi_bcd(imsi)
    # IE: Recovery (TV: 0x0E + 1 byte restart counter)
    ies += bytes([IE_RECOVERY, _rng.randint(0, 255)])
    # IE: TEID Data I (TLV: 0x10 + len(2) + 4 bytes TEID)
    teid_data = _rng.randint(1, 0xFFFFFFFF)
    ies += bytes([IE_TEID_DATA_I]) + struct.pack(">H", 4) + \
           struct.pack(">I", teid_data)
    # IE: TEID Control Plane (TLV: 0x11 + len(2) + 4 bytes TEID)
    teid_ctrl = _rng.randint(1, 0xFFFFFFFF)
    ies += bytes([IE_TEID_CTRL]) + struct.pack(">H", 4) + \
           struct.pack(">I", teid_ctrl)
    # IE: NSAPI (TV: 0x14 + 1 byte; NSAPI in lower nibble, value 5..15)
    nsapi_val = 5
    ies += bytes([IE_NSAPI, nsapi_val & 0x0F])
    # IE: PDP Type Organization + PDP Type Number (TLV)
    # Org: 0 = IETF, PDP Type: 1 = IPv4, 2 = IPv6, 3 = IPv4v6
    ies += bytes([IE_PDP_TYPE]) + struct.pack(">H", 2) + bytes([0, 1])
    # IE: PDP Address (TLV) — empty (request dynamic allocation)
    ies += bytes([IE_PDP_ADDRESS]) + struct.pack(">H", 2) + bytes([0, 1])
    # IE: APN (TLV: 0x1C + len(2) + APN labels)
    apn_bytes = _encode_apn(apn)
    ies += bytes([IE_APN]) + struct.pack(">H", len(apn_bytes)) + apn_bytes
    # IE: SGSN Address for signaling (TLV) — use HOST IP
    try:
        sgsn_ip = socket.inet_aton(HOST)
    except OSError:
        sgsn_ip = b"\x7f\x00\x00\x01"
    ies += bytes([IE_SGSN_ADDR_SIG]) + struct.pack(">H", 4) + sgsn_ip
    # IE: SGSN Address for user traffic (TLV)
    ies += bytes([IE_SGSN_ADDR_USR]) + struct.pack(">H", 4) + sgsn_ip
    # IE: QoS Profile (TLV) — minimal: 3 bytes (rate 0, delay 0, ...)
    # QoS Profile TLV: 0x10 + len(2) + 3 bytes (prior, delay, relclass)
    ies += bytes([IE_QOS_PROFILE]) + struct.pack(">H", 3) + bytes([0, 0, 0])
    return build_gtp_v1(MSG_CREATE_PDP_CTX_REQ, teid=0, seq_no=seq_no,
                        payload=ies, has_seq=True)


def _encode_apn(apn_str: str) -> bytes:
    """Encode an APN as label-length-prefixed bytes (TS 23.003 §9.1.1).
    "internet.mnc012.mcc345.gprs" → \x08internet\x03mnc\x03mcc\x04gprs"""
    out = bytearray()
    for label in apn_str.split("."):
        b = label.encode("ascii", errors="replace")
        if len(b) > 63:
            b = b[:63]
        out.append(len(b))
        out.extend(b)
    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════
#  Cause IE extraction (in Create PDP Context Response)
# ═══════════════════════════════════════════════════════════════════════════
def extract_cause(payload: bytes) -> Optional[int]:
    """In Create PDP Context Response, the first IE is Cause (type 1, TV
    format: byte 0 = 0x01, byte 1 = cause value). Return the cause value."""
    if len(payload) < 2:
        return None
    if payload[0] != IE_CAUSE:
        # Sometimes the cause IE is not first; scan for it
        for i in range(0, len(payload) - 1):
            if payload[i] == IE_CAUSE:
                return payload[i + 1]
        return None
    return payload[1]


# ═══════════════════════════════════════════════════════════════════════════
#  UDP send/recv
# ═══════════════════════════════════════════════════════════════════════════
def send_recv_gtp(host: str, port: int, message: bytes,
                  timeout: float = TIMEOUT_S) -> Tuple[Optional[bytes], str]:
    """Send a GTP message over UDP and read the response."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _set_sock_timeout(sock, timeout)
        sock.sendto(message, (host, port))
        try:
            data, _ = sock.recvfrom(8192)
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


def port_udp_open(host: str, port: int,
                  timeout: float = 2.0) -> Tuple[bool, str]:
    """Probe whether a UDP port is open by sending an empty datagram.
    Returns (open, verdict_str). For UDP this is unreliable: an ICMP
    port-unreachable means closed, silence means open or filtered."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _set_sock_timeout(sock, timeout)
        sock.sendto(b"\x00", (host, port))
        try:
            data, _ = sock.recvfrom(128)
            # Got a response → port definitely open
            return True, f"responded:{len(data)}b"
        except (socket.timeout, TimeoutError):
            return True, "silent_open_or_filtered"
        except ConnectionRefusedError:
            return False, "icmp_port_unreachable"
        except OSError as e:
            # errno 111 (ECONNREFUSED) → closed
            import errno
            if getattr(e, "errno", None) == errno.ECONNREFUSED:
                return False, "icmp_port_unreachable"
            return False, f"oserror:{type(e).__name__}"
    except Exception as e:  # noqa: BLE001
        return False, f"error:{type(e).__name__}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass


# ═══════════════════════════════════════════════════════════════════════════
#  Test 1: Port scan GGSN management interfaces
# ═══════════════════════════════════════════════════════════════════════════
def test_port_scan(host: str, port: int,
                   results: List[Dict]) -> Dict[int, bool]:
    """Scan GGSN management ports: 2123 (GTP-C), 2152 (GTP-U), 3386 (GTP')."""
    ports_to_scan = [GTP_C_PORT, GTP_U_PORT, GTP_PRIME_PORT]
    out: Dict[int, bool] = {}
    for p in ports_to_scan:
        open_, verdict = port_udp_open(host, p)
        out[p] = open_
        results.append({
            "test": "port_scan",
            "port": p,
            "verdict": "open" if open_ else "closed",
            "detail": verdict,
        })
    return out


# ═══════════════════════════════════════════════════════════════════════════
#  Test 2: GTP-C Echo Request
# ═══════════════════════════════════════════════════════════════════════════
def test_echo_request(host: str, port: int,
                      results: List[Dict]) -> Tuple[bool, Optional[Dict]]:
    """Send a GTP-C Echo Request. A GGSN should respond with an Echo
    Response (msg_type=2) containing a Recovery IE. Returns (echo_ok,
    parsed_response)."""
    seq = _rng.randint(1, 0xFFFF)
    msg = build_echo_request(seq)
    data, err = send_recv_gtp(host, port, msg)
    if data is None:
        results.append({"test": "echo_request",
                        "verdict": "no_response",
                        "error": err})
        return False, None
    parsed = parse_gtp_v1(data)
    if parsed is None:
        results.append({"test": "echo_request",
                        "verdict": "invalid_gtp",
                        "raw_len": len(data)})
        return False, None
    echo_ok = parsed["msg_type"] == MSG_ECHO_RESPONSE
    results.append({
        "test": "echo_request",
        "verdict": "echo_ok" if echo_ok else "wrong_msg_type",
        "msg_type": parsed["msg_type"],
        "seq": parsed["seq"],
        "expected_seq": seq,
        "payload_len": len(parsed["payload"]),
    })
    return echo_ok, parsed


# ═══════════════════════════════════════════════════════════════════════════
#  Test 3: GTP-U port 2152 accessibility
# ═══════════════════════════════════════════════════════════════════════════
def test_gtp_u_accessible(host: str, port: int,
                          port_scan: Dict[int, bool],
                          results: List[Dict]) -> bool:
    """GTP-U (port 2152) is the user-plane. We send a no-op GTP-U Echo
    Request (msg_type=1, version=1, PT=1) and check for an Echo Response.
    If no response but port is open, we mark as 'port_open_no_response'."""
    accessible = port_scan.get(GTP_U_PORT, False)
    if not accessible:
        results.append({"test": "gtp_u_accessible",
                        "verdict": "port_closed"})
        return False
    # Try a GTP-U echo
    seq = _rng.randint(1, 0xFFFF)
    msg = build_gtp_v1(MSG_ECHO_REQUEST, teid=0, seq_no=seq,
                       payload=b"", has_seq=True)
    data, err = send_recv_gtp(host, GTP_U_PORT, msg, timeout=3.0)
    if data is None:
        results.append({"test": "gtp_u_accessible",
                        "verdict": "port_open_no_response",
                        "detail": "GTP-U port is open but did not respond to Echo"})
        return True  # port itself is accessible
    parsed = parse_gtp_v1(data)
    if parsed and parsed["msg_type"] == MSG_ECHO_RESPONSE:
        results.append({"test": "gtp_u_accessible",
                        "verdict": "echo_ok",
                        "seq": parsed["seq"]})
        return True
    results.append({"test": "gtp_u_accessible",
                    "verdict": "port_open_invalid_response"})
    return True


# ═══════════════════════════════════════════════════════════════════════════
#  Test 4: Create PDP Context without auth (CRITICAL)
# ═══════════════════════════════════════════════════════════════════════════
def test_create_pdp_without_auth(host: str, port: int,
                                 results: List[Dict]) -> bool:
    """Send a Create PDP Context Request with a fictitious IMSI. If the
    GGSN responds with cause=128 (Request accepted), it accepted a PDP
    context without authentication — CRITICAL vulnerability.

    SAFE_MODE=read_only: SKIPPED (creating PDP contexts can bill subscribers).
    SAFE_MODE=full: sends the request.

    Returns True if PDP context accepted without auth."""
    if SAFE_MODE != "full":
        results.append({
            "test": "create_pdp_without_auth",
            "verdict": "skipped",
            "reason": ("SAFE_MODE != full — Create PDP Context can bill "
                       "subscribers on a production GGSN"),
        })
        return False
    # Fictitious IMSI: MCC=001 (test), MNC=01, MSIN=random
    imsi = "00101" + f"{_rng.randint(0, 999999999):09d}"
    apn = "internet"
    seq = _rng.randint(1, 0xFFFF)
    msg = build_create_pdp_context_request(seq, imsi, apn)
    data, err = send_recv_gtp(host, port, msg)
    if data is None:
        results.append({"test": "create_pdp_without_auth",
                        "verdict": "no_response",
                        "error": err})
        return False
    parsed = parse_gtp_v1(data)
    if parsed is None:
        results.append({"test": "create_pdp_without_auth",
                        "verdict": "invalid_gtp_response"})
        return False
    if parsed["msg_type"] != MSG_CREATE_PDP_CTX_RSP:
        results.append({"test": "create_pdp_without_auth",
                        "verdict": "wrong_msg_type",
                        "msg_type": parsed["msg_type"]})
        return False
    cause = extract_cause(parsed["payload"])
    accepted = (cause == CAUSE_REQUEST_ACCEPTED)
    results.append({
        "test": "create_pdp_without_auth",
        "verdict": "vulnerable_accepted" if accepted else "rejected",
        "cause": cause,
        "imsi_used": imsi,
        "apn_used": apn,
        "detail": ("GGSN accepted Create PDP Context without auth — "
                   "anyone can establish tunnels and route traffic!")
                   if accepted else
                  (f"GGSN rejected (cause={cause}) — auth working"),
    })
    return accepted


# ═══════════════════════════════════════════════════════════════════════════
#  Test 5: APN list (probe common APN names)
# ═══════════════════════════════════════════════════════════════════════════
COMMON_APNS = [
    "internet", "mms", "wap", "web", "broadband", "voip", "ims",
    "internet.mnc001.mcc001.gprs",  # test network APN FQDN form
]


def test_apn_list(host: str, port: int,
                  results: List[Dict]) -> List[str]:
    """Probe common APN names via Create PDP Context Request. For each APN,
    if the GGSN responds with cause=128 (Request accepted) or 200 (Unknown
    APN — proves it parsed our APN field), record the APN as 'seen'.

    SAFE_MODE=read_only: SKIPPED.
    SAFE_MODE=full: probes each APN once."""
    if SAFE_MODE != "full":
        results.append({
            "test": "apn_list",
            "verdict": "skipped",
            "reason": ("SAFE_MODE != full — APN probing sends Create PDP "
                       "Context requests (can trigger billing alerts)"),
        })
        return []
    found_apns: List[str] = []
    imsi = "00101" + f"{_rng.randint(0, 999999999):09d}"
    for apn in COMMON_APNS:
        seq = _rng.randint(1, 0xFFFF)
        msg = build_create_pdp_context_request(seq, imsi, apn)
        data, err = send_recv_gtp(host, port, msg, timeout=3.0)
        if data is None:
            continue
        parsed = parse_gtp_v1(data)
        if parsed is None or parsed["msg_type"] != MSG_CREATE_PDP_CTX_RSP:
            continue
        cause = extract_cause(parsed["payload"])
        # Any response that mentions cause 200 (Unknown APN) or 128 (Accepted)
        # or 203 (User auth failed) proves the GGSN parsed our APN
        if cause in (CAUSE_REQUEST_ACCEPTED, CAUSE_UNKNOWN_APN,
                     CAUSE_USER_AUTH_FAILED, CAUSE_IMSI_UNKNOWN,
                     CAUSE_NON_EXISTENT, CAUSE_SYSTEM_FAILURE):
            found_apns.append(apn)
        # 200 = Unknown APN → APN doesn't exist but was processed
        # 128 = Accepted → APN exists and tunnel created (CRITICAL)
    results.append({
        "test": "apn_list",
        "verdict": "probed",
        "apns_tested": len(COMMON_APNS),
        "apns_responded": len(found_apns),
        "apns": found_apns,
    })
    return found_apns


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
            "legal_note": ("GPRS GTP probing on production GGSN can bill "
                           "subscribers (FR Art. 323-1 / US 18 USC §1030). "
                           "Lab only."),
        }))
        sys.exit(1)

    t0 = time.time()
    results: List[Dict] = []
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "gtp_c_port": PORT,
        "sector": get_sector_config().get("sector", "telecom"),
        "safe_mode": SAFE_MODE,
        "read_only": SAFE_MODE != "full",
        "seed": SEED,
        # Spec-required output fields:
        "gtp_c_accessible": False,
        "gtp_u_accessible": False,
        "echo_response": False,
        "create_pdp_without_auth": False,
        "apns_found": [],
        "results": results,
        "errors": [],
    }

    # ─── 1. Port scan GGSN management ports ───────────────────────────────
    port_scan: Dict[int, bool] = {}
    try:
        port_scan = test_port_scan(HOST, PORT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"port_scan:{type(e).__name__}:{e}")

    # ─── 2. GTP-C Echo Request ────────────────────────────────────────────
    try:
        echo_ok, _parsed = test_echo_request(HOST, PORT, results)
        summary["echo_response"] = echo_ok
        summary["gtp_c_accessible"] = echo_ok or port_scan.get(GTP_C_PORT, False)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"echo_request:{type(e).__name__}:{e}")

    # ─── 3. GTP-U port accessibility ──────────────────────────────────────
    try:
        summary["gtp_u_accessible"] = test_gtp_u_accessible(
            HOST, PORT, port_scan, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"gtp_u:{type(e).__name__}:{e}")

    # ─── 4. Create PDP Context without auth (SAFE_MODE=full only) ────────
    try:
        summary["create_pdp_without_auth"] = test_create_pdp_without_auth(
            HOST, PORT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"create_pdp:{type(e).__name__}:{e}")

    # ─── 5. APN list ──────────────────────────────────────────────────────
    try:
        summary["apns_found"] = test_apn_list(HOST, PORT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"apn_list:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
