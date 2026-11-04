#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — websocket_probe (cross-sector protocol module)
# WebSocket injection probe — applies to trading feeds, real-time APIs,
# telecom signaling gateways, OT telemetry, IT chat, banking market data.
#
# RFC 6455 — The WebSocket Protocol. The handshake is an HTTP Upgrade:
#   GET /ws HTTP/1.1
#   Host: ...
#   Upgrade: websocket
#   Connection: Upgrade
#   Sec-WebSocket-Key: <base64(16 random bytes)>
#   Sec-WebSocket-Version: 13
#   Origin: <origin>   ← CSWSH attack vector
#
# Server replies:
#   HTTP/1.1 101 Switching Protocols
#   Upgrade: websocket
#   Connection: Upgrade
#   Sec-WebSocket-Accept: <base64(SHA1(key + magic GUID))>
#
# Tests:
#   1. WebSocket upgrade handshake       (HTTP 101 Switching Protocols)
#   2. Origin header validation          (CSWSH — Cross-Site WebSocket Hijacking)
#   3. Message injection                 (send crafted JSON, check for reflection)
#   4. Authentication check             (can connect without token?)
#   5. Sensitive data in initial handshake response
#
# CLI:
#   python3 websocket_probe.py [ws_url]
#       default = ws://127.0.0.1:8080/ws
#
# Output: single JSON object on stdout.
#
# Uses `websocket-client` library if available (pip install websocket-client),
# else falls back to a stdlib raw-socket HTTP Upgrade + minimal WS frame codec.
#
# Legal: lab isolated only (LAB=1 guard). 5 s timeout on every socket op.
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# ─── Optional `websocket-client` library ─────────────────────────────────────
try:
    import websocket  # type: ignore  # pip install websocket-client
    _HAS_WSLIB = True
except Exception:  # noqa: BLE001
    websocket = None  # type: ignore
    _HAS_WSLIB = False

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
        return {"sector": "cross", "safe_mode": "read_only"}

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "websocket_probe"
TIMEOUT_S = 5  # 5 s hard cap

# ─── CLI args ─────────────────────────────────────────────────────────────────
TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8080/ws"

# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))

# RFC 6455 magic GUID used to compute Sec-WebSocket-Accept
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Evil Origin used to test CSWSH — a properly-configured server rejects it,
# a vulnerable server accepts the connection.
EVIL_ORIGIN = "https://evil.example.com"

# Injection payloads — JSON-shaped, preserve structure so the server-side
# parser is the target (not the WS layer).
INJECTION_PAYLOADS = (
    {"action": "';--"},                              # SQLi
    {"$gt": ""},                                     # NoSQLi operator injection
    {"action": "__proto__"},                         # Prototype pollution
    {"action": "'; DROP TABLE users; --"},           # Classic SQLi
    {"action": "{{7*7}}"},                           # SSTI (Jinja2)
    {"action": "../../../etc/passwd"},               # Path traversal
    {"action": {"$ne": None}},                       # NoSQLi operator
)

# Sensitive data patterns to look for in the initial handshake response
SENSITIVE_PATTERNS = (
    "secret", "token", "api_key", "apikey", "password",
    "private_key", "session_id", "csrf", "ssn",
    "credit_card", "pan", "cvv", "auth_token",
)


# ─── LAB guard ────────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ═══════════════════════════════════════════════════════════════════════════
#  URL parsing
# ═══════════════════════════════════════════════════════════════════════════
def parse_ws_url(url: str) -> Dict:
    """Parse a ws:// or wss:// URL into host, port, path, use_tls, resource.
    Falls back to defaults on parse failure."""
    import urllib.parse
    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("ws", "wss"):
            scheme = "ws"
        use_tls = (scheme == "wss")
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if use_tls else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return {
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
            "use_tls": use_tls,
            "resource": path,
        }
    except Exception:  # noqa: BLE001
        return {
            "scheme": "ws",
            "host": "127.0.0.1",
            "port": 8080,
            "path": "/ws",
            "use_tls": False,
            "resource": "/ws",
        }


# ═══════════════════════════════════════════════════════════════════════════
#  Raw socket handshake (stdlib fallback when websocket-client missing)
# ═══════════════════════════════════════════════════════════════════════════
def gen_ws_key() -> str:
    """Generate a random Sec-WebSocket-Key (16 bytes, base64-encoded)."""
    import random as _r
    rng = _r.Random(SEED)
    return base64.b64encode(bytes(rng.randint(0, 255) for _ in range(16))).decode("ascii")


def compute_ws_accept(key: str) -> str:
    """Compute the expected Sec-WebSocket-Accept value (RFC 6455 §4.2.2)."""
    digest = hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def build_handshake_request(host: str, port: int, path: str,
                            ws_key: str,
                            origin: Optional[str] = None,
                            extra_headers: Optional[Dict[str, str]] = None,
                            auth_token: Optional[str] = None) -> bytes:
    """Build an HTTP Upgrade request for the WebSocket handshake."""
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {ws_key}",
        "Sec-WebSocket-Version: 13",
        f"User-Agent: harness/{HARNESS_VERSION} ({MODULE_NAME}) seed={SEED}",
    ]
    if origin:
        lines.append(f"Origin: {origin}")
    if auth_token:
        lines.append(f"Authorization: Bearer {auth_token}")
    if extra_headers:
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("")
    return ("\r\n".join(lines)).encode("ascii")


def parse_http_response(data: bytes) -> Dict:
    """Parse an HTTP response. Returns dict with status_code, reason,
    headers (lowercased), body. Tolerant of partial reads."""
    try:
        text = data.decode("iso-8859-1", errors="replace")
    except Exception:  # noqa: BLE001
        return {"status_code": 0, "reason": "", "headers": {}, "body": "",
                "raw_hex": data.hex()[:128]}
    # Split headers/body on first \r\n\r\n
    if "\r\n\r\n" in text:
        header_blob, body = text.split("\r\n\r\n", 1)
    else:
        header_blob, body = text, ""
    lines = header_blob.split("\r\n")
    if not lines:
        return {"status_code": 0, "reason": "", "headers": {}, "body": body}
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    status_code = 0
    reason = ""
    if len(parts) >= 2 and parts[0].startswith("HTTP"):
        try:
            status_code = int(parts[1])
        except ValueError:
            status_code = 0
        reason = parts[2] if len(parts) > 2 else ""
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return {
        "status_code": status_code,
        "reason": reason,
        "headers": headers,
        "body": body,
    }


def raw_socket_handshake(host: str, port: int, path: str, use_tls: bool,
                         origin: Optional[str] = None,
                         auth_token: Optional[str] = None,
                         timeout: float = TIMEOUT_S) -> Tuple[Optional[Dict],
                                                                Optional[socket.socket],
                                                               str]:
    """Open a TCP (or TLS) socket, send the WS handshake, read the response.
    Returns (parsed_response, socket_or_None, error_str). The socket is left
    open for subsequent message injection tests when the handshake succeeds
    with HTTP 101."""
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
    except (socket.timeout, TimeoutError):
        if sock:
            sock.close()
        return None, None, "timeout"
    except (ConnectionRefusedError, OSError) as e:
        if sock:
            sock.close()
        return None, None, f"conn_error:{type(e).__name__}"
    except Exception as e:  # noqa: BLE001
        if sock:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass
        return None, None, f"socket_error:{type(e).__name__}:{e}"

    ws_key = gen_ws_key()
    req = build_handshake_request(host, port, path, ws_key,
                                  origin=origin, auth_token=auth_token)
    try:
        sock.sendall(req)
        # Read up to first \r\n\r\n (handshake response). Read in chunks.
        buf = b""
        sock.settimeout(timeout)
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            try:
                chunk = sock.recv(2048)
            except (socket.timeout, TimeoutError):
                break
            except OSError as e:
                sock.close()
                return None, None, f"recv_error:{type(e).__name__}"
            if not chunk:
                break
            buf += chunk
    except OSError as e:
        sock.close()
        return None, None, f"io_error:{type(e).__name__}"

    if not buf:
        sock.close()
        return None, None, "empty_response"
    parsed = parse_http_response(buf)
    # If 101 Switching Protocols, keep socket open for WS messages.
    # If not, close it.
    if parsed["status_code"] != 101:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
        return parsed, None, ""
    return parsed, sock, ""


# ═══════════════════════════════════════════════════════════════════════════
#  Minimal WS frame codec (RFC 6455 §5) — stdlib fallback
# ═══════════════════════════════════════════════════════════════════════════
def ws_send_text(sock: socket.socket, message: str) -> bool:
    """Send a WS text frame (opcode 0x1, FIN=1, client mask required)."""
    payload = message.encode("utf-8")
    mask_bit = 0x80
    # Frame header
    if len(payload) <= 125:
        header = struct.pack("!BB", 0x81, mask_bit | len(payload))
    elif len(payload) <= 65535:
        header = struct.pack("!BBH", 0x81, mask_bit | 126, len(payload))
    else:
        header = struct.pack("!BBQ", 0x81, mask_bit | 127, len(payload))
    # Masking key (4 random bytes — seeded for reproducibility)
    import random as _r
    rng = _r.Random(SEED + len(payload))
    mask = bytes(rng.randint(0, 255) for _ in range(4))
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    try:
        sock.sendall(header + mask + masked)
        return True
    except OSError:
        return False


def ws_recv_frame(sock: socket.socket,
                  timeout: float = TIMEOUT_S) -> Optional[Dict]:
    """Read one WS frame from the server. Returns dict with fin, opcode,
    payload_text (if text frame), payload_hex (always), or None on error.
    Server frames are NOT masked (RFC 6455 §5.1)."""
    try:
        sock.settimeout(timeout)
        header = sock.recv(2)
        if len(header) < 2:
            return None
        b1, b2 = header[0], header[1]
        fin = bool(b1 & 0x80)
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F
        if length == 126:
            ext = sock.recv(2)
            if len(ext) < 2:
                return None
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = sock.recv(8)
            if len(ext) < 8:
                return None
            length = struct.unpack("!Q", ext)[0]
        if masked:
            mask = sock.recv(4)
            if len(mask) < 4:
                return None
        # Read payload (may need multiple recvs)
        payload = b""
        while len(payload) < length:
            chunk = sock.recv(min(2048, length - len(payload)))
            if not chunk:
                break
            payload += chunk
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return {
            "fin": fin,
            "opcode": opcode,
            "payload_text": payload.decode("utf-8", errors="replace"),
            "payload_hex": payload.hex(),
        }
    except (socket.timeout, TimeoutError):
        return None
    except OSError:
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  Test 1: WebSocket upgrade handshake
# ═══════════════════════════════════════════════════════════════════════════
def test_handshake(host: str, port: int, path: str, use_tls: bool,
                   results: List[Dict]) -> Tuple[bool, Optional[Dict]]:
    """Perform a WS handshake with no Origin header (default policy).
    Returns (accessible, response_dict)."""
    if _HAS_WSLIB:
        try:
            url = f"{'wss' if use_tls else 'ws'}://{host}:{port}{path}"
            ws = websocket.create_connection(
                url, timeout=TIMEOUT_S,
                header={"User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME})"},
                suppress_origin=False,
            )
            # If create_connection returned, the handshake succeeded (101).
            ws.close()
            results.append({
                "test": "handshake",
                "verdict": "accessible",
                "library": "websocket-client",
                "status_code": 101,
            })
            # We still do a raw handshake to capture the response headers
            # for the data_in_handshake test.
            resp, sock, err = raw_socket_handshake(host, port, path, use_tls)
            if sock:
                sock.close()
            return True, resp
        except Exception as e:  # noqa: BLE001
            results.append({
                "test": "handshake",
                "verdict": "failed",
                "library": "websocket-client",
                "error": f"{type(e).__name__}:{e}",
            })
            return False, None
    else:
        resp, sock, err = raw_socket_handshake(host, port, path, use_tls)
        if resp and resp["status_code"] == 101:
            results.append({
                "test": "handshake",
                "verdict": "accessible",
                "library": "raw_socket",
                "status_code": 101,
                "sec_websocket_accept": resp["headers"].get("sec-websocket-accept"),
            })
            if sock:
                sock.close()
            return True, resp
        else:
            results.append({
                "test": "handshake",
                "verdict": "failed",
                "library": "raw_socket",
                "status_code": resp["status_code"] if resp else 0,
                "error": err,
            })
            return False, resp


# ═══════════════════════════════════════════════════════════════════════════
#  Test 2: Origin validation / CSWSH
# ═══════════════════════════════════════════════════════════════════════════
def test_origin_validation(host: str, port: int, path: str, use_tls: bool,
                           results: List[Dict]) -> Tuple[bool, bool]:
    """Send a WS handshake with an evil Origin (https://evil.example.com).
    A properly-configured server rejects it (403 / 400). A vulnerable server
    accepts it (101) — Cross-Site WebSocket Hijacking (CSWSH).
    Returns (origin_validated, cswsh_vulnerable)."""
    if _HAS_WSLIB:
        try:
            url = f"{'wss' if use_tls else 'ws'}://{host}:{port}{path}"
            ws = websocket.create_connection(
                url, timeout=TIMEOUT_S,
                header={"Origin": EVIL_ORIGIN,
                        "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME})"},
                suppress_origin=False,
            )
            ws.close()
            results.append({
                "test": "origin_validation",
                "verdict": "vulnerable_cswsh",
                "origin_used": EVIL_ORIGIN,
                "detail": "Server accepted connection with evil Origin (CSWSH)",
            })
            return False, True
        except Exception as e:  # noqa: BLE001
            err_msg = str(e).lower()
            # websocket-client raises WebSocketBadStatusException for 4xx
            if "403" in err_msg or "400" in err_msg or "handshake" in err_msg:
                results.append({
                    "test": "origin_validation",
                    "verdict": "origin_validated",
                    "origin_used": EVIL_ORIGIN,
                    "detail": "Server rejected evil Origin",
                })
                return True, False
            results.append({
                "test": "origin_validation",
                "verdict": "unknown",
                "origin_used": EVIL_ORIGIN,
                "error": f"{type(e).__name__}:{e}",
            })
            return False, False
    else:
        resp, sock, err = raw_socket_handshake(
            host, port, path, use_tls, origin=EVIL_ORIGIN)
        if resp and resp["status_code"] == 101:
            if sock:
                sock.close()
            results.append({
                "test": "origin_validation",
                "verdict": "vulnerable_cswsh",
                "origin_used": EVIL_ORIGIN,
                "detail": "Server accepted connection with evil Origin (CSWSH)",
            })
            return False, True
        elif resp and resp["status_code"] in (400, 403):
            results.append({
                "test": "origin_validation",
                "verdict": "origin_validated",
                "origin_used": EVIL_ORIGIN,
                "status_code": resp["status_code"],
                "detail": "Server rejected evil Origin",
            })
            return True, False
        else:
            results.append({
                "test": "origin_validation",
                "verdict": "unknown",
                "origin_used": EVIL_ORIGIN,
                "status_code": resp["status_code"] if resp else 0,
                "error": err,
            })
            return False, False


# ═══════════════════════════════════════════════════════════════════════════
#  Test 3: Message injection
# ═══════════════════════════════════════════════════════════════════════════
def test_message_injection(host: str, port: int, path: str, use_tls: bool,
                           results: List[Dict]) -> bool:
    """Open a WS connection, send crafted JSON payloads, look for reflection
    or server-side error indicators in the response. Returns True if any
    payload was reflected or triggered an error."""
    if _HAS_WSLIB:
        try:
            url = f"{'wss' if use_tls else 'ws'}://{host}:{port}{path}"
            ws = websocket.create_connection(url, timeout=TIMEOUT_S)
        except Exception as e:  # noqa: BLE001
            results.append({"test": "message_injection",
                            "verdict": "skipped",
                            "reason": f"could_not_connect:{type(e).__name__}"})
            return False
        try:
            ws.settimeout(TIMEOUT_S)
            reflected = False
            for payload in INJECTION_PAYLOADS:
                try:
                    ws.send(json.dumps(payload))
                except Exception:  # noqa: BLE001
                    continue
                try:
                    reply = ws.recv()
                except Exception:  # noqa: BLE001
                    continue
                reply_lower = str(reply).lower()
                # Check for reflection of the payload
                payload_str = json.dumps(payload)
                if payload_str in str(reply):
                    reflected = True
                    results.append({
                        "test": "message_injection",
                        "verdict": "vulnerable_reflection",
                        "payload": payload_str[:80],
                        "detail": "Payload reflected verbatim in server response",
                    })
                    break
                # Check for SQL/NoSQL error signatures
                if any(s in reply_lower for s in ("sql syntax", "uncaught",
                                                  "syntax error", "mongo error",
                                                  "exception", "stack trace",
                                                  "drop table", "or 1=1")):
                    reflected = True
                    results.append({
                        "test": "message_injection",
                        "verdict": "vulnerable_error_leak",
                        "payload": payload_str[:80],
                        "detail": "Server leaked an error indicating injection worked",
                    })
                    break
            if not reflected:
                results.append({"test": "message_injection",
                                "verdict": "no_reflection",
                                "payloads_tried": len(INJECTION_PAYLOADS)})
            return reflected
        finally:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
    else:
        # Raw socket path
        resp, sock, err = raw_socket_handshake(host, port, path, use_tls)
        if not sock:
            results.append({"test": "message_injection",
                            "verdict": "skipped",
                            "reason": "handshake_failed"})
            return False
        try:
            reflected = False
            for payload in INJECTION_PAYLOADS:
                ok = ws_send_text(sock, json.dumps(payload))
                if not ok:
                    continue
                frame = ws_recv_frame(sock, timeout=2.0)
                if not frame:
                    continue
                reply = frame.get("payload_text", "")
                reply_lower = reply.lower()
                payload_str = json.dumps(payload)
                if payload_str in reply:
                    reflected = True
                    results.append({
                        "test": "message_injection",
                        "verdict": "vulnerable_reflection",
                        "payload": payload_str[:80],
                    })
                    break
                if any(s in reply_lower for s in ("sql syntax", "uncaught",
                                                  "syntax error", "mongo error",
                                                  "exception", "drop table")):
                    reflected = True
                    results.append({
                        "test": "message_injection",
                        "verdict": "vulnerable_error_leak",
                        "payload": payload_str[:80],
                    })
                    break
            if not reflected:
                results.append({"test": "message_injection",
                                "verdict": "no_reflection",
                                "payloads_tried": len(INJECTION_PAYLOADS)})
            return reflected
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass


# ═══════════════════════════════════════════════════════════════════════════
#  Test 4: Authentication check
# ═══════════════════════════════════════════════════════════════════════════
def test_auth_check(host: str, port: int, path: str, use_tls: bool,
                    results: List[Dict]) -> bool:
    """Attempt a WS handshake WITHOUT any Authorization header or token.
    Returns True if auth IS required (handshake rejected without token),
    False if anonymous access is allowed."""
    resp, sock, err = raw_socket_handshake(host, port, path, use_tls)
    if resp and resp["status_code"] == 101:
        if sock:
            sock.close()
        results.append({
            "test": "auth_check",
            "verdict": "no_auth_required",
            "detail": "WebSocket endpoint accessible without auth token",
        })
        return False
    elif resp and resp["status_code"] in (401, 403):
        results.append({
            "test": "auth_check",
            "verdict": "auth_required",
            "status_code": resp["status_code"],
        })
        return True
    elif resp:
        results.append({
            "test": "auth_check",
            "verdict": "other",
            "status_code": resp["status_code"],
        })
        return False
    else:
        results.append({
            "test": "auth_check",
            "verdict": "no_response",
            "error": err,
        })
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  Test 5: Sensitive data in handshake response
# ═══════════════════════════════════════════════════════════════════════════
def test_data_in_handshake(handshake_response: Optional[Dict],
                           results: List[Dict]) -> bool:
    """Inspect the handshake response headers and body for sensitive data
    leakage (tokens, secrets, PII). Returns True if any sensitive pattern
    was found."""
    if not handshake_response:
        results.append({"test": "data_in_handshake",
                        "verdict": "skipped", "reason": "no_handshake_response"})
        return False
    headers = handshake_response.get("headers", {})
    body = handshake_response.get("body", "")
    found_in: List[str] = []
    # Check header values
    for hname, hval in headers.items():
        for pattern in SENSITIVE_PATTERNS:
            if pattern in hname.lower() or pattern in hval.lower():
                found_in.append(f"header:{hname}")
                break
    # Check body
    body_lower = body.lower()
    for pattern in SENSITIVE_PATTERNS:
        if pattern in body_lower:
            found_in.append(f"body:{pattern}")
    leaked = bool(found_in)
    results.append({
        "test": "data_in_handshake",
        "verdict": "leaked" if leaked else "no_sensitive_data",
        "found_in": found_in[:10] if leaked else [],
        "header_count": len(headers),
        "body_length": len(body),
    })
    return leaked


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
            "legal_note": ("WebSocket probing on production APIs is illegal "
                           "outside an authorized lab."),
        }))
        sys.exit(1)

    t0 = time.time()
    results: List[Dict] = []
    url_parts = parse_ws_url(TARGET_URL)
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": TARGET_URL,
        "host": url_parts["host"],
        "port": url_parts["port"],
        "path": url_parts["path"],
        "use_tls": url_parts["use_tls"],
        "sector": get_sector_config().get("sector", "cross"),
        "safe_mode": "read_only",
        "read_only": True,
        "seed": SEED,
        "websocket_client_available": _HAS_WSLIB,
        # Spec-required output fields:
        "ws_accessible": False,
        "origin_validated": False,
        "cswsh_vulnerable": False,
        "auth_required": False,
        "message_injection": False,
        "data_in_handshake": False,
        "results": results,
        "errors": [],
    }

    # ─── 1. Handshake ─────────────────────────────────────────────────────
    handshake_response: Optional[Dict] = None
    try:
        accessible, handshake_response = test_handshake(
            url_parts["host"], url_parts["port"], url_parts["path"],
            url_parts["use_tls"], results)
        summary["ws_accessible"] = accessible
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"handshake:{type(e).__name__}:{e}")

    # ─── 2. Origin validation / CSWSH ─────────────────────────────────────
    try:
        origin_validated, cswsh_vulnerable = test_origin_validation(
            url_parts["host"], url_parts["port"], url_parts["path"],
            url_parts["use_tls"], results)
        summary["origin_validated"] = origin_validated
        summary["cswsh_vulnerable"] = cswsh_vulnerable
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"origin_validation:{type(e).__name__}:{e}")

    # ─── 3. Message injection ─────────────────────────────────────────────
    try:
        summary["message_injection"] = test_message_injection(
            url_parts["host"], url_parts["port"], url_parts["path"],
            url_parts["use_tls"], results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"message_injection:{type(e).__name__}:{e}")

    # ─── 4. Auth check ────────────────────────────────────────────────────
    try:
        summary["auth_required"] = test_auth_check(
            url_parts["host"], url_parts["port"], url_parts["path"],
            url_parts["use_tls"], results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"auth_check:{type(e).__name__}:{e}")

    # ─── 5. Sensitive data in handshake response ──────────────────────────
    try:
        summary["data_in_handshake"] = test_data_in_handshake(
            handshake_response, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"data_in_handshake:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
