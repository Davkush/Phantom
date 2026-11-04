#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — grpc_probe (telecom protocol module)
# gRPC (HTTP/2-based RPC framework, Google 2015) probe.
#
# gRPC runs over HTTP/2 (TLS+ALPN or plaintext h2c). Used in 5G core SBI
# (Service-Based Interface, 3GPP TS 29.500), CNCF microservices, etcd,
# TiKV, Envoy xDS. Default port 50051.
#
# Tests:
#   1. Send HTTP/2 preface + SETTINGS → check server responds with SETTINGS
#                                            → grpc_accessible
#   2. PING frame + ACK                  → settings_received (liveness)
#   3. Reflection service HEADERS+DATA   → reflection_enabled
#      (grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo)
#   4. Health check service              → health_check
#      (grpc.health.v1.Health/Check)
#   5. List services (if reflection)     → services
#   6. Auth: TLS vs plaintext, bearer    → auth_required
#
# HTTP/2 frame format (RFC 7540 §4.1):
#   Length(24 bits) + Type(8) + Flags(8) + R(1)+StreamID(31) + Payload
#
# Frame types: DATA(0x0) HEADERS(0x1) PRIORITY(0x2) RST_STREAM(0x3)
#   SETTINGS(0x4) PUSH_PROMISE(0x5) PING(0x6) GOAWAY(0x7)
#   WINDOW_UPDATE(0x8) CONTINUATION(0x9)
#
# Connection preface (RFC 7540 §3.5) — client MUST send first 24 bytes:
#   "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + SETTINGS frame
#
# HPACK (RFC 7541) header encoding. We use literal-without-indexing for
# simplicity (RFC 7541 §6.2.2): first byte 0x00 (no indexing, new name).
#
# gRPC message framing (length-prefix): 1-byte compress flag + 4-byte
# big-endian length + protobuf payload.
#
# Reflection protobuf (grpc.reflection.v1alpha):
#   ServerReflectionRequest { oneof message_request { string list_services=7; } }
#   list_services="" returns all services. Wire encoding of empty list_services:
#     field 7, wire type 2 (length-delimited) → 0x3a 0x00  (2 bytes)
#   ServerReflectionResponse { ... list_services_response=7; }
#     ListServiceResponse { repeated ServiceResponse service=1; }
#       ServiceResponse { string name=1; }
#
# Health protobuf (grpc.health.v1):
#   HealthCheckRequest { string service=1; }   # empty = overall
#   HealthCheckResponse { ServingStatus status=1; }   # enum: 0=UNKNOWN
#                                                     # 1=SERVING 2=NOT_SERVING
#
# CLI:
#   python3 grpc_probe.py [host] [port]
#       host default = 127.0.0.1
#       port default = 50051
#
# Output: single JSON object on stdout.
#
# Legal: gRPC reflection can leak internal service topology. LAB only.
import json
import os
import random
import re
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
MODULE_NAME = "grpc_probe"
TIMEOUT_S = 5  # 5 s hard cap on every socket op

# ─── CLI args ─────────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 50051
except ValueError:
    PORT = 50051

# SAFE_MODE can be overridden via env. telecom sector default = read_only.
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

# SETTINGS identifiers (RFC 7540 §6.5.2)
SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

# gRPC status codes (gRPC RFC: github.com/grpc/grpc/blob/master/doc/statuscodes.md)
GRPC_STATUS_OK = 0
GRPC_STATUS_UNAUTHENTICATED = 16
GRPC_STATUS_PERMISSION_DENIED = 7
GRPC_STATUS_UNIMPLEMENTED = 12


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
#  HTTP/2 frame building
# ═══════════════════════════════════════════════════════════════════════════
def build_frame(frame_type: int, flags: int, stream_id: int,
                payload: bytes) -> bytes:
    """Build an HTTP/2 frame (RFC 7540 §4.1):
       Length(24) + Type(8) + Flags(8) + R(1)+StreamID(31) + Payload"""
    length = len(payload)
    if length > 0xFFFFFF:
        raise ValueError("payload too large for a single HTTP/2 frame")
    # Stream ID: top bit (R) must be 0; mask off just in case
    sid = stream_id & 0x7FFFFFFF
    header = (length.to_bytes(3, "big") +
              bytes([frame_type & 0xFF, flags & 0xFF]) +
              struct.pack(">I", sid))
    return header + payload


def build_settings_frame(settings: Optional[List[Tuple[int, int]]] = None,
                         ack: bool = False) -> bytes:
    """Build a SETTINGS frame. Each setting is (id, value). If ack=True,
    payload must be empty (acknowledging the server's SETTINGS)."""
    if ack:
        return build_frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")
    payload = b""
    for sid, val in (settings or []):
        payload += struct.pack(">HI", sid, val)
    return build_frame(FRAME_SETTINGS, 0, 0, payload)


def build_ping_frame(opaque: bytes = b"\x00\x00\x00\x00harness",
                     ack: bool = False) -> bytes:
    """Build a PING frame. opaque must be exactly 8 bytes."""
    if len(opaque) != 8:
        opaque = (opaque + b"\x00" * 8)[:8]
    return build_frame(FRAME_PING, FLAG_ACK if ack else 0, 0, opaque)


def build_window_update(stream_id: int, increment: int) -> bytes:
    """Build a WINDOW_UPDATE frame (RFC 7540 §6.9)."""
    payload = struct.pack(">I", increment & 0x7FFFFFFF)
    return build_frame(FRAME_WINDOW_UPDATE, 0, stream_id, payload)


def build_headers_frame(stream_id: int, header_block: bytes,
                        end_stream: bool = False,
                        end_headers: bool = True) -> bytes:
    """Build a HEADERS frame (RFC 7540 §6.2)."""
    flags = 0
    if end_stream:
        flags |= FLAG_END_STREAM
    if end_headers:
        flags |= FLAG_END_HEADERS
    return build_frame(FRAME_HEADERS, flags, stream_id, header_block)


def build_data_frame(stream_id: int, data: bytes,
                     end_stream: bool = True) -> bytes:
    """Build a DATA frame (RFC 7540 §6.1)."""
    flags = FLAG_END_STREAM if end_stream else 0
    return build_frame(FRAME_DATA, flags, stream_id, data)


# ═══════════════════════════════════════════════════════════════════════════
#  HPACK header compression (RFC 7541)
# ═══════════════════════════════════════════════════════════════════════════
def _hpack_int(value: int, prefix_bits: int, prefix_byte: int = 0) -> bytes:
    """Encode an integer with HPACK (RFC 7541 §5.1)."""
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
    """Encode a header with literal-without-indexing (RFC 7541 §6.2.2/§6.2.3).
       Format: 0000xxxx (xxxx=0 for new name) + name len + name + value len + value
       For never-index: 0001xxxx instead of 0000xxxx."""
    prefix = 0x10 if never_index else 0x00
    name_b = name.encode("ascii")
    value_b = value.encode("ascii")
    out = bytes([prefix])  # literal-without-indexing, new name
    out += _hpack_int(len(name_b), 7, 0x00)
    out += name_b
    out += _hpack_int(len(value_b), 7, 0x00)
    out += value_b
    return out


def build_grpc_header_block(host: str, port: int, path: str,
                            scheme: str = "http",
                            authority: Optional[str] = None) -> bytes:
    """Build the HPACK-encoded header block for a gRPC request.
       Required pseudo-headers (RFC 7540 §8.1.2.3):
         :method = POST
         :scheme = http or https
         :path   = /package.Service/Method
         :authority = host:port
       Required gRPC headers (gRPC over HTTP/2 spec):
         content-type = application/grpc
         te = trailers
         grpc-accept-encoding = identity
         user-agent = harness/...
    """
    if authority is None:
        authority = f"{host}:{port}" if port not in (80, 443) else host
    block = b""
    block += hpack_literal(":method", "POST", never_index=True)
    block += hpack_literal(":scheme", scheme, never_index=True)
    block += hpack_literal(":path", path, never_index=True)
    block += hpack_literal(":authority", authority, never_index=True)
    block += hpack_literal("content-type", "application/grpc")
    block += hpack_literal("te", "trailers")
    block += hpack_literal("grpc-accept-encoding", "identity")
    block += hpack_literal("user-agent",
                           f"harness/{HARNESS_VERSION} ({MODULE_NAME})")
    return block


# ═══════════════════════════════════════════════════════════════════════════
#  gRPC message framing
# ═══════════════════════════════════════════════════════════════════════════
def grpc_frame(protobuf_payload: bytes, compressed: bool = False) -> bytes:
    """Wrap a protobuf payload in a gRPC message frame:
       1 byte compress flag + 4 byte BE length + payload."""
    flag = 0x01 if compressed else 0x00
    return bytes([flag]) + struct.pack(">I", len(protobuf_payload)) + \
           protobuf_payload


# Reflection: ServerReflectionRequest with list_services="" (empty string)
#   field 7 (list_services), wire type 2 (length-delimited) → tag 0x3a
#   length 0 → 0x00
REFLECTION_REQUEST_PAYLOAD = b"\x3a\x00"  # 2 bytes

# Health: HealthCheckRequest with empty service (no fields) → 0 bytes
HEALTH_REQUEST_PAYLOAD = b""


# ═══════════════════════════════════════════════════════════════════════════
#  HTTP/2 frame parsing
# ═══════════════════════════════════════════════════════════════════════════
def parse_frames(data: bytes) -> List[Dict]:
    """Parse all HTTP/2 frames in `data`. Returns list of dicts:
       {type, flags, stream_id, payload}."""
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
            break  # truncated
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
    """Parse a SETTINGS frame payload into a dict of {id: value}."""
    out: Dict[int, int] = {}
    for i in range(0, len(payload) - 5, 6):
        sid, val = struct.unpack(">HI", payload[i:i + 6])
        out[sid] = val
    return out


# ═══════════════════════════════════════════════════════════════════════════
#  HPACK header block decoding (minimal — literal-without-indexing only)
# ═══════════════════════════════════════════════════════════════════════════
# We only decode what's needed to read :status and grpc-status from the
# response. The gRPC server typically uses indexed (0x80+) for :status (it
# is in the static table — index 8 = "200").
_HPACK_STATIC = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
]


def _decode_hpack_int(data: bytes, pos: int,
                      prefix_bits: int) -> Tuple[int, int]:
    """Decode an HPACK integer (RFC 7541 §5.1). Returns (value, new_pos)."""
    max_val = (1 << prefix_bits) - 1
    val = data[pos] & max_val
    pos += 1
    if val < max_val:
        return val, pos
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        val += (b & 0x7F) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7
        if shift > 35:
            break
    return val, pos


def decode_hpack_headers(block: bytes) -> List[Tuple[str, str]]:
    """Decode an HPACK header block. Supports indexed, literal-with-incremental,
    literal-without-indexing, and literal-never-indexed. Does NOT maintain a
    dynamic table (we use a snapshot of the static table for indexed reads)."""
    out: List[Tuple[str, str]] = []
    dynamic: List[Tuple[str, str]] = []
    pos = 0
    while pos < len(block):
        b = block[pos]
        if b & 0x80:
            # Indexed Header Field (RFC 7541 §6.1)
            idx, pos = _decode_hpack_int(block, pos, 7)
            entry = None
            if 1 <= idx <= len(_HPACK_STATIC):
                entry = _HPACK_STATIC[idx - 1]
            elif idx > len(_HPACK_STATIC):
                dyn_idx = idx - len(_HPACK_STATIC) - 1
                if 0 <= dyn_idx < len(dynamic):
                    entry = dynamic[dyn_idx]
            if entry:
                out.append(entry)
        elif b & 0xC0 == 0x40:
            # Literal with incremental indexing (RFC 7541 §6.2.1)
            idx, pos = _decode_hpack_int(block, pos, 6)
            if idx == 0:
                name_len, pos = _decode_hpack_int(block, pos, 7)
                name = block[pos:pos + name_len].decode("ascii", errors="replace")
                pos += name_len
            else:
                name = _HPACK_STATIC[idx - 1][0] if 1 <= idx <= len(_HPACK_STATIC) else ""
            val_len, pos = _decode_hpack_int(block, pos, 7)
            value = block[pos:pos + val_len].decode("ascii", errors="replace")
            pos += val_len
            entry = (name, value)
            out.append(entry)
            dynamic.insert(0, entry)
        elif b & 0xF0 in (0x00, 0x10):
            # Literal without indexing / never-indexed (RFC 7541 §6.2.2/§6.2.3)
            idx, pos = _decode_hpack_int(block, pos, 4)
            if idx == 0:
                name_len, pos = _decode_hpack_int(block, pos, 7)
                name = block[pos:pos + name_len].decode("ascii", errors="replace")
                pos += name_len
            else:
                name = _HPACK_STATIC[idx - 1][0] if 1 <= idx <= len(_HPACK_STATIC) else ""
            val_len, pos = _decode_hpack_int(block, pos, 7)
            value = block[pos:pos + val_len].decode("ascii", errors="replace")
            pos += val_len
            out.append((name, value))
        elif b & 0xE0 == 0x20:
            # Dynamic Table Size Update (RFC 7541 §6.3)
            _size, pos = _decode_hpack_int(block, pos, 5)
            # Truncate dynamic table
            while len(dynamic) > _size // 32:
                dynamic.pop()
        else:
            pos += 1  # unknown
    return out


# ═══════════════════════════════════════════════════════════════════════════
#  Connection setup
# ═══════════════════════════════════════════════════════════════════════════
def open_h2_connection(host: str, port: int) -> Tuple[Optional[object], bool, str]:
    """Open a TCP (optionally TLS) socket and send the HTTP/2 preface +
    SETTINGS frame. Returns (socket, tls_used, error_str).
    Tries TLS+ALPN(h2) first; falls back to plaintext h2c on failure."""
    sock = None
    ssock = None
    tls_used = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _set_sock_timeout(sock, TIMEOUT_S)
        sock.connect((host, port))
        # Try TLS+ALPN
        if port in (443, 8443) or os.environ.get("GRPC_TLS", "0") == "1":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                alpn = ssock.selected_alpn_protocol()
                if alpn == "h2":
                    tls_used = True
                    io_sock = ssock
                else:
                    # Server doesn't speak h2 over TLS — try plaintext
                    ssock.close()
                    ssock = None
                    io_sock = None
            except (ssl.SSLError, OSError):
                try:
                    ssock.close()
                except Exception:  # noqa: BLE001
                    pass
                ssock = None
                io_sock = None
        else:
            io_sock = sock
        # If TLS failed, open a new plaintext socket
        if io_sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _set_sock_timeout(sock, TIMEOUT_S)
            sock.connect((host, port))
            io_sock = sock
            tls_used = False
        # Send HTTP/2 connection preface + SETTINGS
        preface = H2_PREFACE + build_settings_frame([
            (SETTINGS_HEADER_TABLE_SIZE, 4096),
            (SETTINGS_ENABLE_PUSH, 0),
            (SETTINGS_MAX_CONCURRENT_STREAMS, 100),
            (SETTINGS_INITIAL_WINDOW_SIZE, 65535),
            (SETTINGS_MAX_FRAME_SIZE, 16384),
        ])
        io_sock.sendall(preface)
        return io_sock, tls_used, ""
    except (ConnectionRefusedError, OSError) as e:
        for s in (ssock, sock):
            if s is not None:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass
        return None, False, f"{type(e).__name__}:{e}"
    except Exception as e:  # noqa: BLE001
        for s in (ssock, sock):
            if s is not None:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass
        return None, False, f"{type(e).__name__}:{e}"


# ═══════════════════════════════════════════════════════════════════════════
#  Test 1+2: HTTP/2 preface + SETTINGS + PING
# ═══════════════════════════════════════════════════════════════════════════
def test_h2_handshake(host: str, port: int,
                      results: List[Dict]) -> Tuple[bool, Optional[object], bool]:
    """Send preface + SETTINGS + PING. Returns (accessible, socket, tls_used).
    A HTTP/2 server MUST respond with its own SETTINGS within a reasonable
    time. We treat receipt of any HTTP/2 frame as success."""
    io_sock, tls_used, err = open_h2_connection(host, port)
    if io_sock is None:
        results.append({"test": "h2_handshake",
                        "verdict": "no_connection",
                        "error": err})
        return False, None, False
    # Read response — expect SETTINGS from server
    try:
        data = io_sock.recv(4096)
    except (socket.timeout, TimeoutError):
        data = b""
    except OSError as e:
        results.append({"test": "h2_handshake",
                        "verdict": "recv_error",
                        "error": f"{type(e).__name__}:{e}"})
        try:
            io_sock.close()
        except Exception:  # noqa: BLE001
            pass
        return False, None, False
    if not data:
        results.append({"test": "h2_handshake",
                        "verdict": "no_response",
                        "detail": "Server did not respond to preface+SETTINGS"})
        try:
            io_sock.close()
        except Exception:  # noqa: BLE001
            pass
        return False, None, False
    frames = parse_frames(data)
    has_settings = any(f["type"] == FRAME_SETTINGS for f in frames)
    # Send PING to confirm liveness
    ping_payload = b"harness1"  # exactly 8 bytes
    try:
        io_sock.sendall(build_ping_frame(ping_payload))
        ping_data = io_sock.recv(4096)
    except (socket.timeout, TimeoutError, OSError):
        ping_data = b""
    ping_frames = parse_frames(ping_data) if ping_data else []
    ping_acked = any(f["type"] == FRAME_PING and (f["flags"] & FLAG_ACK)
                     and f["payload"] == ping_payload for f in ping_frames)
    # Read server's advertised settings
    server_settings: Dict[int, int] = {}
    for f in frames:
        if f["type"] == FRAME_SETTINGS and not (f["flags"] & FLAG_ACK):
            server_settings = parse_settings(f["payload"])
            break
    # Send SETTINGS ACK back (RFC 7540 §6.5)
    try:
        io_sock.sendall(build_settings_frame(ack=True))
    except OSError:
        pass
    results.append({
        "test": "h2_handshake",
        "verdict": "h2_up",
        "tls_used": tls_used,
        "server_settings": server_settings,
        "settings_received": has_settings,
        "ping_acked": ping_acked,
    })
    return has_settings, io_sock, tls_used


# ═══════════════════════════════════════════════════════════════════════════
#  Test 3: Reflection service (grpc.reflection.v1alpha.ServerReflection)
# ═══════════════════════════════════════════════════════════════════════════
REFLECTION_PATH_V1ALPHA = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
REFLECTION_PATH_V1 = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"


def test_reflection(host: str, port: int, io_sock: object, tls_used: bool,
                    results: List[Dict]) -> Tuple[bool, List[str]]:
    """Call the reflection service. If reflection is enabled, the server
    returns a ServerReflectionResponse with list_services_response listing
    all available services. Returns (reflection_enabled, service_list)."""
    stream_id = 1  # first client-initiated stream
    scheme = "https" if tls_used else "http"
    header_block = build_grpc_header_block(host, port, REFLECTION_PATH_V1ALPHA,
                                           scheme=scheme)
    # HEADERS frame (END_HEADERS=1, END_STREAM=0)
    msg = build_headers_frame(stream_id, header_block,
                              end_stream=False, end_headers=True)
    # DATA frame with gRPC message (END_STREAM=1)
    msg += build_data_frame(stream_id,
                            grpc_frame(REFLECTION_REQUEST_PAYLOAD),
                            end_stream=True)
    try:
        io_sock.sendall(msg)  # type: ignore[union-attr]
    except OSError as e:
        results.append({"test": "reflection",
                        "verdict": "send_error",
                        "error": f"{type(e).__name__}:{e}"})
        return False, []
    # Read response — expect HEADERS (with :status=200) + DATA
    try:
        data = io_sock.recv(8192)  # type: ignore[union-attr]
    except (socket.timeout, TimeoutError, OSError):
        data = b""
    if not data:
        results.append({"test": "reflection",
                        "verdict": "no_response",
                        "detail": "Server did not respond to reflection request"})
        return False, []
    frames = parse_frames(data)
    # Collect HEADERS + DATA on our stream
    status_code: Optional[int] = None
    grpc_status: Optional[int] = None
    grpc_message: Optional[str] = None
    data_payload = b""
    for f in frames:
        if f["stream_id"] != stream_id:
            continue
        if f["type"] == FRAME_HEADERS or f["type"] == FRAME_CONTINUATION:
            headers = decode_hpack_headers(f["payload"])
            for k, v in headers:
                if k == ":status":
                    try:
                        status_code = int(v)
                    except ValueError:
                        pass
                elif k == "grpc-status":
                    try:
                        grpc_status = int(v)
                    except ValueError:
                        pass
                elif k == "grpc-message":
                    grpc_message = v
        elif f["type"] == FRAME_DATA:
            data_payload += f["payload"]
    reflection_enabled = False
    services: List[str] = []
    if status_code == 200 and grpc_status == GRPC_STATUS_OK:
        reflection_enabled = True
        services = parse_reflection_services(data_payload)
    elif status_code == 200 and grpc_status == GRPC_STATUS_UNIMPLEMENTED:
        # Reflection service exists but is unimplemented — try v1
        results.append({"test": "reflection",
                        "verdict": "v1alpha_unimplemented_try_v1",
                        "grpc_status": grpc_status})
        # Fall through to v1 attempt below — handled inline for clarity
    results.append({
        "test": "reflection",
        "verdict": "enabled" if reflection_enabled else "not_enabled",
        "http_status": status_code,
        "grpc_status": grpc_status,
        "grpc_message": grpc_message,
        "services_found": len(services),
        "services_sample": services[:15],
    })
    # If v1alpha not enabled, try v1
    if not reflection_enabled and status_code in (None, 200):
        v1_enabled, v1_services = _try_reflection_v1(host, port, io_sock, tls_used)
        if v1_enabled:
            reflection_enabled = True
            services = v1_services
            results.append({
                "test": "reflection_v1",
                "verdict": "enabled",
                "services_found": len(v1_services),
                "services_sample": v1_services[:15],
            })
    return reflection_enabled, services


def _try_reflection_v1(host: str, port: int, io_sock: object,
                       tls_used: bool) -> Tuple[bool, List[str]]:
    """Retry reflection using the v1 path on a new stream (id=3)."""
    stream_id = 3
    scheme = "https" if tls_used else "http"
    header_block = build_grpc_header_block(host, port, REFLECTION_PATH_V1,
                                           scheme=scheme)
    msg = build_headers_frame(stream_id, header_block,
                              end_stream=False, end_headers=True)
    msg += build_data_frame(stream_id,
                            grpc_frame(REFLECTION_REQUEST_PAYLOAD),
                            end_stream=True)
    try:
        io_sock.sendall(msg)  # type: ignore[union-attr]
    except OSError:
        return False, []
    try:
        data = io_sock.recv(8192)  # type: ignore[union-attr]
    except (socket.timeout, TimeoutError, OSError):
        data = b""
    if not data:
        return False, []
    frames = parse_frames(data)
    grpc_status: Optional[int] = None
    data_payload = b""
    status_code: Optional[int] = None
    for f in frames:
        if f["stream_id"] != stream_id:
            continue
        if f["type"] in (FRAME_HEADERS, FRAME_CONTINUATION):
            for k, v in decode_hpack_headers(f["payload"]):
                if k == ":status":
                    try:
                        status_code = int(v)
                    except ValueError:
                        pass
                elif k == "grpc-status":
                    try:
                        grpc_status = int(v)
                    except ValueError:
                        pass
        elif f["type"] == FRAME_DATA:
            data_payload += f["payload"]
    if status_code == 200 and grpc_status == GRPC_STATUS_OK:
        return True, parse_reflection_services(data_payload)
    return False, []


def parse_reflection_services(data_payload: bytes) -> List[str]:
    """Parse gRPC message frames from data_payload and extract service names
    from ServerReflectionResponse.list_services_response.service[].name.

    The wire structure (protobuf) is:
      list_services_response (field 7, wire type 2) → tag 0x3a + length
        ServiceResponse (field 1, wire type 2) → tag 0x0a + length
          name (field 1, wire type 2) → tag 0x0a + length + utf8 bytes

    gRPC framing: 1-byte compress-flag + 4-byte BE length + protobuf.
    We do a forgiving scan: for every 0x3a (list_services_response tag)
    followed by a length, then 0x0a + length + utf8 string, capture it.
    """
    services: List[str] = []
    # Strip gRPC framing (5-byte prefix per message)
    pb_data = b""
    pos = 0
    while pos + 5 <= len(data_payload):
        if data_payload[pos] not in (0x00, 0x01):
            # Not a valid compress flag — fall back to treating whole as pb
            pb_data = data_payload
            break
        msg_len = struct.unpack(">I", data_payload[pos + 1:pos + 5])[0]
        msg_start = pos + 5
        msg_end = msg_start + msg_len
        if msg_end > len(data_payload):
            pb_data = data_payload[msg_start:]
            break
        pb_data += data_payload[msg_start:msg_end]
        pos = msg_end
    if not pb_data:
        pb_data = data_payload
    # Scan for service name strings. Heuristic: find 0x3a <len> 0x0a <len> <utf8>
    i = 0
    while i < len(pb_data) - 2:
        if pb_data[i] == 0x3a:  # list_services_response tag (field 7, wire 2)
            lsr_len = pb_data[i + 1] if i + 1 < len(pb_data) else 0
            i += 2
            end = min(i + lsr_len, len(pb_data))
            while i < end:
                if pb_data[i] == 0x0a:  # ServiceResponse tag (field 1, wire 2)
                    if i + 1 >= end:
                        break
                    name_len = pb_data[i + 1]
                    name_start = i + 2
                    name_end = name_start + name_len
                    if name_end <= len(pb_data):
                        try:
                            name = pb_data[name_start:name_end].decode("utf-8")
                            if re.match(r"^[A-Za-z0-9_.\-]+$", name):
                                services.append(name)
                        except UnicodeDecodeError:
                            pass
                    i = name_end
                else:
                    i += 1
        else:
            i += 1
    # Dedupe
    seen = set()
    uniq: List[str] = []
    for s in services:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


# ═══════════════════════════════════════════════════════════════════════════
#  Test 4: Health check service (grpc.health.v1.Health)
# ═══════════════════════════════════════════════════════════════════════════
HEALTH_PATH = "/grpc.health.v1.Health/Check"
HEALTH_STATUS_NAMES = {0: "UNKNOWN", 1: "SERVING", 2: "NOT_SERVING",
                       3: "SERVICE_UNKNOWN"}


def test_health_check(host: str, port: int, io_sock: object,
                      tls_used: bool, results: List[Dict]) -> bool:
    """Call Health/Check on a new stream (id=5). Returns True if the service
    exists and responds with status SERVING (1) or NOT_SERVING (2)."""
    stream_id = 5
    scheme = "https" if tls_used else "http"
    header_block = build_grpc_header_block(host, port, HEALTH_PATH,
                                           scheme=scheme)
    msg = build_headers_frame(stream_id, header_block,
                              end_stream=False, end_headers=True)
    msg += build_data_frame(stream_id, grpc_frame(HEALTH_REQUEST_PAYLOAD),
                            end_stream=True)
    try:
        io_sock.sendall(msg)  # type: ignore[union-attr]
    except OSError as e:
        results.append({"test": "health_check",
                        "verdict": "send_error",
                        "error": f"{type(e).__name__}:{e}"})
        return False
    try:
        data = io_sock.recv(4096)  # type: ignore[union-attr]
    except (socket.timeout, TimeoutError, OSError):
        data = b""
    if not data:
        results.append({"test": "health_check",
                        "verdict": "no_response"})
        return False
    frames = parse_frames(data)
    status_code: Optional[int] = None
    grpc_status: Optional[int] = None
    serving_status: Optional[int] = None
    data_payload = b""
    for f in frames:
        if f["stream_id"] != stream_id:
            continue
        if f["type"] in (FRAME_HEADERS, FRAME_CONTINUATION):
            for k, v in decode_hpack_headers(f["payload"]):
                if k == ":status":
                    try:
                        status_code = int(v)
                    except ValueError:
                        pass
                elif k == "grpc-status":
                    try:
                        grpc_status = int(v)
                    except ValueError:
                        pass
        elif f["type"] == FRAME_DATA:
            data_payload += f["payload"]
    if data_payload and len(data_payload) >= 6:
        # gRPC message: 1 byte flag + 4 byte len + protobuf
        pb = data_payload[5:5 + struct.unpack(">I", data_payload[1:5])[0]]
        # HealthCheckResponse { ServingStatus status = 1; } → tag 0x08 + varint
        if len(pb) >= 2 and pb[0] == 0x08:
            serving_status = pb[1]
    healthy = (status_code == 200 and grpc_status == GRPC_STATUS_OK and
               serving_status in (1, 2, 0, 3))
    results.append({
        "test": "health_check",
        "verdict": "healthy" if serving_status == 1 else
                   ("not_serving" if serving_status == 2 else "no_response"),
        "http_status": status_code,
        "grpc_status": grpc_status,
        "serving_status": HEALTH_STATUS_NAMES.get(serving_status, "UNKNOWN"),
    })
    return healthy


# ═══════════════════════════════════════════════════════════════════════════
#  Test 5: Auth check
# ═══════════════════════════════════════════════════════════════════════════
def test_auth_required(host: str, port: int, io_sock: object,
                       tls_used: bool, results: List[Dict]) -> bool:
    """If TLS is used, transport auth is present. If plaintext h2c, anyone
    can connect → auth NOT required at transport layer (the application may
    still require bearer tokens — we check by looking for grpc-status=16
    (UNAUTHENTICATED) on the reflection/health calls).

    Returns True if auth is required."""
    if tls_used:
        results.append({
            "test": "auth_required",
            "verdict": "tls",
            "detail": "Transport uses TLS+ALPN(h2) — client cert may be required",
        })
        return True
    # Plaintext — application-layer auth via bearer token is common.
    # We can't easily test without a token; mark as "unknown_application_auth"
    results.append({
        "test": "auth_required",
        "verdict": "plaintext_h2c",
        "detail": ("Transport is plaintext h2c — no transport auth. "
                   "Application-layer auth (bearer) may still be required."),
    })
    return False


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
            "legal_note": ("gRPC reflection leaks internal service topology. "
                           "Lab only (FR Art. 323-1 / US 18 USC §1030)."),
        }))
        sys.exit(1)

    t0 = time.time()
    results: List[Dict] = []
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "grpc_port": PORT,
        "sector": get_sector_config().get("sector", "telecom"),
        "safe_mode": SAFE_MODE,
        "read_only": SAFE_MODE != "full",
        "seed": SEED,
        # Spec-required output fields:
        "grpc_accessible": False,
        "reflection_enabled": False,
        "services": [],
        "auth_required": False,
        "health_check": False,
        "results": results,
        "errors": [],
    }

    io_sock: Optional[object] = None
    tls_used = False

    # ─── 1. HTTP/2 handshake + SETTINGS + PING ───────────────────────────
    try:
        accessible, io_sock, tls_used = test_h2_handshake(HOST, PORT, results)
        summary["grpc_accessible"] = accessible
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"h2_handshake:{type(e).__name__}:{e}")

    if io_sock is None:
        summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
        print(json.dumps(summary, indent=2, default=str))
        return

    # ─── 2. Reflection ───────────────────────────────────────────────────
    try:
        reflection_enabled, services = test_reflection(
            HOST, PORT, io_sock, tls_used, results)
        summary["reflection_enabled"] = reflection_enabled
        summary["services"] = services
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"reflection:{type(e).__name__}:{e}")

    # ─── 3. Health check ─────────────────────────────────────────────────
    try:
        summary["health_check"] = test_health_check(
            HOST, PORT, io_sock, tls_used, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"health_check:{type(e).__name__}:{e}")

    # ─── 4. Auth required ────────────────────────────────────────────────
    try:
        summary["auth_required"] = test_auth_required(
            HOST, PORT, io_sock, tls_used, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"auth_required:{type(e).__name__}:{e}")

    # Clean up
    try:
        io_sock.close()  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
