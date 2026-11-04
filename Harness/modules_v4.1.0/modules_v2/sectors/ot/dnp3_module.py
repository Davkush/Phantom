#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — dnp3_probe
# OT/ICS validation module — DNP3 (IEEE 1815) link + application probing.
#
#   - Default port : 20000 (DNP3 over TCP/IP, IEEE 1815-2012 §9)
#   - Functions    : send_link_status  (link FC=9 Request Link Status, ctrl=0xC9),
#                    read_class_0      (app FC=0x01 READ, obj 60 var 1, qual 0x06),
#                    check_auth_v5     (app FC=0x21 Authenticate Request SAv5),
#                    try_operate       (app FC=0x02 OPERATE — SAFE_MODE=full only)
#   - Raw socket implementation: full DNP3 link frame builder
#       start bytes (0x05 0x64), length, control, dest(2 LE), src(2 LE),
#       header CRC, then ≤16-byte data blocks each followed by a per-block CRC.
#   - CRC-16 (polynomial 0x3D65, init 0x0000) computed exactly as specified.
#   - Respects SAFE_MODE : if read_only, OPERATE is skipped and reported as
#     "write_skipped_safe_mode" (no packet emitted — an OPERATE can drive a
#     physical relay, breaker, or valve).
#   - LAB=1 mandatory. 5 s timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (OT) : NERC CIP, NIS2, IEC 62443, IEEE 1815.
#
# Output JSON (top-level fields required by the spec):
#   link_established, data_read, auth_v5_active, operate_tested,
#   dnp3_src, dnp3_dst
import json
import os
import socket
import struct
import sys
import time
from typing import Optional

# ─── Make sector_base importable from ../../sector_base.py ────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULES_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _MODULES_ROOT not in sys.path:
    sys.path.insert(0, _MODULES_ROOT)

from sector_base import (  # noqa: E402
    get_sector_config,
    check_write_allowed,
    is_write_allowed,
)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "dnp3_probe"
DEFAULT_PORT = 20000
TIMEOUT_S = 5.0

# ─── DNP3 link / application constants ─────────────────────────────────────
DNP3_START = b"\x05\x64"           # link-layer start bytes (sync)

# Link-layer control bytes (DIR=1 from primary, PRM=1 primary frame)
LINK_CTRL_LINK_STATUS = 0xC9       # FCB=0, FCV=0, FC=9 (Request Link Status)
LINK_CTRL_SEND_DATA_NOACK = 0xC3   # FCB=0, FCV=0, FC=3 (Send user data, no ACK)

# Application-layer function codes
APP_FC_READ            = 0x01
APP_FC_OPERATE         = 0x02
APP_FC_AUTHENTICATE_REQ = 0x21
APP_FC_RESPONSE        = 0x81
APP_FC_UNSOLICITED_RSP = 0x82

# Application control byte (FIR=1, FIN=1, CON=1, UNS=0, seq=0)
APP_AC_REQUEST = 0xC0

# Object groups / variations
OBJ_GROUP_CLASS_0   = 0x3C   # group 60 = event class data
OBJ_VAR_CLASS_0     = 0x01   # var 1   = class 0 (static)
OBJ_GROUP_AUTH      = 0x5C   # group 92 = authentication (SAv5)
OBJ_VAR_AUTH        = 0x01   # var 1   = challenge info
OBJ_GROUP_BIN_CMD   = 0x0C   # group 12 = binary output command block
OBJ_VAR_BIN_CMD     = 0x01   # var 1   = binary output command

# Qualifier field codes
QUAL_8BIT_STOP  = 0x06        # 8-bit stop index, no prefix
QUAL_16BIT_STOP = 0x07        # 16-bit stop index, no prefix

# IIN (Internal Indications) bits
IIN1_NO_FUNC_AUTH = 0x20      # IIN1.5 = NO_FUNC_CODE_AUTHORIZATION
IIN2_NO_FUNC_SUPPORT = 0x02   # IIN2.1 = function not supported

# Lab default source/destination DNP3 addresses
DNP3_SRC = 1
DNP3_DST = 1

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT


# ─── LAB guard ─────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    """Refuse to run unless LAB=1 is set (isolated lab authorization)."""
    return os.environ.get("LAB") == "1"


# ─── Sector / SAFE_MODE config ─────────────────────────────────────────────
SECTOR_CFG = get_sector_config()
SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")


# ═══════════════════════════════════════════════════════════════════════════
#  CRC-16 (exact function from the spec — polynomial 0x3D65, init 0x0000)
# ═══════════════════════════════════════════════════════════════════════════
def dnp3_crc(data):
    """CRC-16 with polynomial 0x3D65 and init 0x0000 (bit-by-bit reflected)."""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x3D65
            else:
                crc >>= 1
    return crc


def crc16_le(data: bytes) -> bytes:
    """Return the 2-byte little-endian CRC for `data`."""
    return struct.pack("<H", dnp3_crc(data) & 0xFFFF)


# ═══════════════════════════════════════════════════════════════════════════
#  DNP3 LINK FRAME BUILDER
# ═══════════════════════════════════════════════════════════════════════════
def build_link_header(ctrl: int, dest: int = DNP3_DST,
                      src: int = DNP3_SRC, user_data_len: int = 0) -> bytes:
    """Build the 10-byte link header (start, length, ctrl, dest, src, CRC).

    Length field counts octets after the start bytes and length byte and
    excluding the header CRC: 1 (control) + 2 (dest) + 2 (src) + user_data.
    Minimum length is 5 (no user data).
    """
    length = 5 + user_data_len
    if length > 255:
        raise ValueError(f"user_data too long ({user_data_len} bytes, max 250)")
    header = (DNP3_START
              + bytes([length & 0xFF, ctrl & 0xFF])
              + struct.pack("<H", dest & 0xFFFF)
              + struct.pack("<H", src & 0xFFFF))
    return header + crc16_le(header)


def build_data_blocks(user_data: bytes) -> bytes:
    """Split user data into ≤16-byte blocks each followed by a 2-byte CRC."""
    if not user_data:
        return b""
    out = bytearray()
    offset = 0
    while offset < len(user_data):
        block = user_data[offset:offset + 16]
        out.extend(block)
        out.extend(crc16_le(block))
        offset += 16
    return bytes(out)


def build_frame(ctrl: int, user_data: bytes = b"",
                dest: int = DNP3_DST, src: int = DNP3_SRC) -> bytes:
    """Build a full DNP3 link frame (header + data blocks)."""
    header = build_link_header(ctrl, dest=dest, src=src,
                               user_data_len=len(user_data))
    return header + build_data_blocks(user_data)


# ═══════════════════════════════════════════════════════════════════════════
#  APPLICATION-LAYER REQUEST BUILDERS
# ═══════════════════════════════════════════════════════════════════════════
def build_read_class_0_request() -> bytes:
    """READ Class 0 (app FC=0x01, obj 60 var 1, qual 0x06, range 0..0).

    Reads all static (class-0) data points the outstation holds.
    This is the classic unauthenticated enumeration vector for DNP3.
    """
    app_header = bytes([APP_AC_REQUEST, APP_FC_READ])
    obj_header = bytes([OBJ_GROUP_CLASS_0, OBJ_VAR_CLASS_0,
                        QUAL_8BIT_STOP, 0x00, 0x00])   # start=0, stop=0
    return app_header + obj_header


def build_auth_v5_request() -> bytes:
    """Authenticate Request SAv5 (app FC=0x21, obj 92 var 1, qual 0x07).

    A minimal AuthenticateReq carrying an empty challenge block. If SAv5 is
    active, the outstation responds with an auth challenge object (group 92)
    or sets IIN1.5 (NO_FUNC_CODE_AUTHORIZATION) on a non-authenticated READ.
    """
    app_header = bytes([APP_AC_REQUEST, APP_FC_AUTHENTICATE_REQ])
    # 16-bit stop qualifier → range is 2 LE start + 2 LE stop = 4 bytes
    obj_header = bytes([OBJ_GROUP_AUTH, OBJ_VAR_AUTH,
                        QUAL_16BIT_STOP]) + struct.pack("<HH", 0, 0)
    # Minimal auth challenge block:
    #   User Number (2 LE) + Role (1) + Reason (1) + Challenge Length (1)
    auth_block = struct.pack("<HBBB", 1, 0, 0, 0)
    return app_header + obj_header + auth_block


def build_operate_request() -> bytes:
    """OPERATE Binary Output Command (app FC=0x02, obj 12 var 1, qual 0x06).

    Control byte = 0x00 → NUL state (no-op, no relay transition). Used to
    test whether the outstation accepts OPERATE requests at all.
    """
    app_header = bytes([APP_AC_REQUEST, APP_FC_OPERATE])
    obj_header = bytes([OBJ_GROUP_BIN_CMD, OBJ_VAR_BIN_CMD,
                        QUAL_8BIT_STOP, 0x00, 0x00])   # start=0, stop=0
    # Binary Output Command Block:
    #   Control Status (1) + Count (4 LE) + ON time (4 LE) + OFF time (4 LE)
    # Control 0x00 → NUL/no-op. All-zero times → no timing constraint.
    control_block = struct.pack("<BIII", 0x00, 0, 0, 0)
    return app_header + obj_header + control_block


# ═══════════════════════════════════════════════════════════════════════════
#  DNP3 RAW TRANSPORT (TCP)
# ═══════════════════════════════════════════════════════════════════════════
class Dnp3RawClient:
    """Minimal DNP3-over-TCP client using raw sockets (no external deps)."""

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self) -> "Dnp3RawClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── raw IO helpers ───────────────────────────────────────────────────
    def _recvn(self, n: int) -> bytes:
        if self.sock is None:
            raise RuntimeError("socket not connected")
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _recv_until_quiet(self, timeout: float = 2.0,
                          max_bytes: int = 4096) -> bytes:
        """Read whatever arrives within `timeout` (handles partial reads)."""
        if self.sock is None:
            raise RuntimeError("socket not connected")
        old_to = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        chunks = []
        try:
            while True:
                try:
                    chunk = self.sock.recv(max_bytes)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except (socket.timeout, TimeoutError):
                    break
        finally:
            self.sock.settimeout(old_to)
        return b"".join(chunks)

    # ── frame senders ────────────────────────────────────────────────────
    def send_frame(self, ctrl: int, user_data: bytes = b"",
                   dest: int = DNP3_DST, src: int = DNP3_SRC) -> None:
        if self.sock is None:
            raise RuntimeError("socket not connected")
        self.sock.sendall(build_frame(ctrl, user_data, dest=dest, src=src))


# ═══════════════════════════════════════════════════════════════════════════
#  DNP3 RESPONSE PARSER
# ═══════════════════════════════════════════════════════════════════════════
def parse_frames(raw: bytes) -> list:
    """Parse one or more DNP3 link frames from `raw`.

    Returns a list of dicts:
      {"link_ctrl": int, "dest": int, "src": int, "user_data": bytes, "valid": bool}
    Frames with a wrong header CRC or truncated data are returned with
    valid=False so the caller can still see *some* response came back.
    """
    frames = []
    offset = 0
    while offset + 10 <= len(raw):
        if raw[offset:offset + 2] != DNP3_START:
            # Skip 1 byte and resync — some outstations prefix ACK frames
            # differently or pad with stray bytes.
            offset += 1
            continue
        header = raw[offset:offset + 10]
        length = header[2]
        ctrl = header[3]
        dest = struct.unpack("<H", header[4:6])[0]
        src = struct.unpack("<H", header[6:8])[0]
        crc_recv = struct.unpack("<H", header[8:10])[0]
        crc_calc = dnp3_crc(header[:8])
        header_ok = (crc_recv == crc_calc)

        user_data_len = length - 5 if length >= 5 else 0
        user_data = b""
        cursor = offset + 10
        remaining = user_data_len
        block_crc_ok = True
        while remaining > 0 and cursor + 2 <= len(raw):
            block_size = min(remaining, 16)
            if cursor + block_size + 2 > len(raw):
                block_crc_ok = False
                break
            block = raw[cursor:cursor + block_size]
            b_crc_recv = struct.unpack("<H",
                                       raw[cursor + block_size:cursor + block_size + 2])[0]
            if dnp3_crc(block) != b_crc_recv:
                block_crc_ok = False
            user_data += block
            cursor += block_size + 2
            remaining -= block_size

        frames.append({
            "link_ctrl": ctrl,
            "dest": dest,
            "src": src,
            "user_data": user_data,
            "valid": bool(header_ok and block_crc_ok),
            "length": length,
        })
        offset = cursor
    return frames


def _parse_app_response(user_data: bytes) -> dict:
    """Parse the first 4 bytes of an app response (AC, FC, IIN1, IIN2)."""
    out = {"ac": None, "fc": None, "iin1": None, "iin2": None, "iin": None}
    if len(user_data) < 2:
        return out
    out["ac"] = user_data[0]
    out["fc"] = user_data[1]
    if len(user_data) >= 4:
        out["iin1"] = user_data[2]
        out["iin2"] = user_data[3]
        out["iin"] = (user_data[2] << 8) | user_data[3]
    return out


# ═══════════════════════════════════════════════════════════════════════════
#  PROBE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
def send_link_status(client: Dnp3RawClient) -> dict:
    """Send Request Link Status (link FC=9, control byte 0xC9, no user data).

    Per IEEE 1815 §9.4.3, the outstation responds with a Link Status frame
    (secondary, FC=11) or an ACK (secondary, FC=0). Either response confirms
    the link layer is alive.
    """
    result = {"link_established": False, "response_fc": None, "error": None}
    try:
        client.send_frame(LINK_CTRL_LINK_STATUS, user_data=b"")
        raw = client._recv_until_quiet(timeout=2.0)
        frames = parse_frames(raw)
        if frames:
            # Secondary responses: DIR=0, PRM=0; function code in low nibble.
            # FC=0 (ACK), FC=1 (NACK), FC=2 (User Data Not Ready...),
            # FC=9 (Link Status) — all indicate the link responded.
            ctrl = frames[0]["link_ctrl"]
            fc = ctrl & 0x0F
            result["response_fc"] = fc
            result["link_established"] = True
        else:
            result["error"] = "timeout" if not raw else "no_frame_parsed"
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def _send_app_request_and_recv(client: Dnp3RawClient,
                               user_data: bytes,
                               wait_s: float = 3.0) -> list:
    """Send an app-layer request as Send-User-Data-NoAck and return frames."""
    client.send_frame(LINK_CTRL_SEND_DATA_NOACK, user_data=user_data)
    raw = client._recv_until_quiet(timeout=wait_s)
    return parse_frames(raw)


def read_class_0(client: Dnp3RawClient) -> dict:
    """READ Class 0 (app FC=0x01, obj 60 var 1, qual 0x06)."""
    result = {"data_read": False, "bytes_returned": 0,
              "app_fc": None, "iin": None, "error": None}
    try:
        req = build_read_class_0_request()
        frames = _send_app_request_and_recv(client, req, wait_s=3.0)
        app_frame = next((f for f in frames if f["user_data"]), None)
        if app_frame is None:
            result["error"] = "timeout" if not frames else "no_app_response"
            return result
        app = _parse_app_response(app_frame["user_data"])
        result["app_fc"] = app["fc"]
        result["iin"] = app["iin"]
        if app["fc"] in (APP_FC_RESPONSE, APP_FC_UNSOLICITED_RSP):
            result["data_read"] = True
            result["bytes_returned"] = max(0, len(app_frame["user_data"]) - 4)
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def check_auth_v5(client: Dnp3RawClient) -> dict:
    """Authenticate Request SAv5 (app FC=0x21).

    Detects whether Secure Authentication v5 is enforced by the outstation:
      - response contains a Group-92 auth challenge object → SAv5 active
      - IIN1.5 (NO_FUNC_CODE_AUTHORIZATION) set → SAv5 required
      - IIN2.1 (NO_FUNCTION_CODE_SUPPORT) set → SAv5 not supported
    """
    result = {"auth_v5_active": False, "app_fc": None, "iin": None,
              "has_auth_object": False, "error": None}
    try:
        req = build_auth_v5_request()
        frames = _send_app_request_and_recv(client, req, wait_s=2.0)
        app_frame = next((f for f in frames if f["user_data"]), None)
        if app_frame is None:
            result["error"] = "timeout" if not frames else "no_app_response"
            return result
        ud = app_frame["user_data"]
        app = _parse_app_response(ud)
        result["app_fc"] = app["fc"]
        result["iin"] = app["iin"]
        # Look for an auth object (Group 92 / 0x5C) in the response body
        # after the 4-byte response header (AC + FC + IIN1 + IIN2).
        body = ud[4:]
        for i in range(len(body) - 1):
            if body[i] == OBJ_GROUP_AUTH and body[i + 1] in (0x01, 0x02):
                result["has_auth_object"] = True
                break
        iin1 = app["iin1"] or 0
        iin2 = app["iin2"] or 0
        if result["has_auth_object"]:
            result["auth_v5_active"] = True
        elif iin1 & IIN1_NO_FUNC_AUTH:
            # Outstation rejected our (unauthenticated) request because auth
            # is mandatory → SAv5 is enforced.
            result["auth_v5_active"] = True
        elif iin2 & IIN2_NO_FUNC_SUPPORT:
            result["auth_v5_active"] = False
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def try_operate(client: Dnp3RawClient) -> dict:
    """OPERATE (app FC=0x02, Binary Output Command). SAFE_MODE=full only.

    Sends a NUL-state Binary Output Command (control byte 0x00 → no relay
    transition) to test whether the outstation accepts OPERATE requests at
    all. Respects SAFE_MODE: if read_only, returns "write_skipped_safe_mode"
    and emits NO packet.
    """
    result = {"operate_tested": False, "app_fc": None, "iin": None,
              "status": None, "error": None}

    # SAFE_MODE gate — primary guard (do not exit, just skip).
    if not is_write_allowed():
        result["status"] = "write_skipped_safe_mode"
        return result

    # Defense-in-depth: sector_base guard (would exit(3) if bypassed).
    check_write_allowed(MODULE_NAME)

    try:
        req = build_operate_request()
        frames = _send_app_request_and_recv(client, req, wait_s=2.0)
        result["operate_tested"] = True
        app_frame = next((f for f in frames if f["user_data"]), None)
        if app_frame is None:
            result["status"] = "timeout" if not frames else "no_app_response"
            return result
        app = _parse_app_response(app_frame["user_data"])
        result["app_fc"] = app["fc"]
        result["iin"] = app["iin"]
        iin1 = app["iin1"] or 0
        if app["fc"] == APP_FC_RESPONSE:
            if iin1 & IIN1_NO_FUNC_AUTH:
                result["status"] = "operate_rejected_no_auth"
            elif iin1 == 0 and (app["iin2"] or 0) == 0:
                result["status"] = "operate_accepted"
            else:
                result["status"] = "operate_iin_error"
        else:
            result["status"] = "unexpected_response"
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        result["status"] = "timeout"
        result["operate_tested"] = True
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        result["status"] = "conn_error"
        result["operate_tested"] = True
    except SystemExit:
        # check_write_allowed may sys.exit(3) — propagate cleanly.
        raise
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
        result["status"] = "error"
        result["operate_tested"] = True
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("DNP3 probing on production SCADA/RTUs is illegal "
                           "outside an authorized lab. NERC CIP / IEC 62443 / "
                           "IEEE 1815."),
        }))
        sys.exit(1)

    t0 = time.time()
    summary: dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "port": PORT,
        "sector": SECTOR_CFG.get("sector"),
        "safe_mode": SAFE_MODE,
        "transport": "raw_socket",
        # Spec-required top-level output fields:
        "link_established": False,
        "data_read": False,
        "auth_v5_active": False,
        "operate_tested": False,
        "dnp3_src": DNP3_SRC,
        "dnp3_dst": DNP3_DST,
        # Detail / error reporting:
        "details": {},
        "errors": [],
    }

    try:
        with Dnp3RawClient(HOST, PORT, timeout=TIMEOUT_S) as client:
            # 1. Link status (link-level)
            ls = send_link_status(client)
            summary["link_established"] = bool(ls.get("link_established"))
            summary["details"]["link_status"] = ls
            if ls.get("error"):
                summary["errors"].append(f"send_link_status:{ls['error']}")

            # 2. READ Class 0 (app-level enumeration)
            rc = read_class_0(client)
            summary["data_read"] = bool(rc.get("data_read"))
            summary["details"]["read_class_0"] = rc
            if rc.get("error"):
                summary["errors"].append(f"read_class_0:{rc['error']}")

            # 3. SAv5 authentication probe
            av = check_auth_v5(client)
            summary["auth_v5_active"] = bool(av.get("auth_v5_active"))
            summary["details"]["check_auth_v5"] = av
            if av.get("error"):
                summary["errors"].append(f"check_auth_v5:{av['error']}")

            # 4. OPERATE — SAFE_MODE=full only
            op = try_operate(client)
            summary["operate_tested"] = bool(op.get("operate_tested"))
            summary["details"]["try_operate"] = op
            if op.get("error"):
                summary["errors"].append(f"try_operate:{op['error']}")
            if op.get("status") == "write_skipped_safe_mode":
                summary["details"]["try_operate"]["note"] = (
                    "SAFE_MODE is read_only for this sector — OPERATE not "
                    "attempted (would drive a physical relay/breaker). "
                    "Set SECTOR=it/crypto to enable SAFE_MODE=full in lab."
                )
    except (socket.timeout, TimeoutError):
        summary["errors"].append("connection:timeout")
    except (ConnectionRefusedError, OSError) as e:
        summary["errors"].append(f"connection:{type(e).__name__}:{e}")
    except SystemExit:
        raise
    except Exception as e:
        summary["errors"].append(f"unhandled:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
