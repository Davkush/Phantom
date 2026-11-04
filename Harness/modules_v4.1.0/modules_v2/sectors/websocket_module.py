#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — Cross-sector: WebSocket security probe.
# Applies to every sector exposing real-time APIs (crypto trading feeds,
# banking market data, telecom signaling gateways, OT telemetry, IT chat).
#
# Tests the most common WebSocket misconfigurations observed in real
# engagements:
#   - Handshake correctness          (RFC 6455 Upgrade / Sec-WebSocket-Key)
#   - Origin validation             (CSWSH — Cross-Site WebSocket Hijacking)
#   - Auth enforcement              (anonymous access to private channels)
#   - Input injection               (SQLi / NoSQLi / prototype pollution)
#   - Cross-user data leakage       (subscribe to foreign channels)
#
# Lab scope only (LAB=1 guard). Timeouts hard-capped at 5s per socket op.
# Graceful degradation: uses the `websockets` library when available,
# otherwise falls back to a stdlib raw-socket handshake.
#
# Usage:
#   LAB=1 python3 websocket_module.py ws://127.0.0.1:8080/ws
#   LAB=1 python3 websocket_module.py wss://api.example.com/feed
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
import warnings
from typing import Any, Dict, List, Optional, Tuple

# Suppress noisy deprecation warnings from the `websockets` library
# (e.g. "There is no current event loop") — they pollute stderr and would
# break the JSON-only stdout contract.
warnings.filterwarnings("ignore")

# ─── Optional deps ───────────────────────────────────────────────────
try:
    import websockets                                  # type: ignore
    from websockets.exceptions import InvalidHandshake  # type: ignore
    _HAS_WSLIB = True
except ImportError:                                     # pragma: no cover
    websockets = None                                  # type: ignore
    _HAS_WSLIB = False

# ─── Constants ───────────────────────────────────────────────────────
HARNESS_VERSION = "3.0.0"
MODULE_NAME = "websocket_probe"
HANDSHAKE_TIMEOUT = 5        # seconds
READ_TIMEOUT = 5             # seconds per message read
EVIL_ORIGIN = "https://evil.com"
SUBSCRIBE_CHANNEL = "private"   # candidate channel for cross-user leak test

# Injection payloads (JSON shape preserved — server-side parser is the target).
INJECTION_PAYLOADS = (
    {"action": "';--"},            # SQLi
    {"$gt": ""},                   # NoSQLi operator injection (MongoDB)
    {"action": "__proto__"},       # Prototype pollution
    {"action": "'; DROP TABLE users; --"},   # classic SQLi
    {"action": {"$where": "sleep(2000)"}},   # NoSQLi time-based
)


# ─── LAB guard ──────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ─── CLI args ────────────────────────────────────────────────────────
TARGET_WS = sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8080/ws"


# ─── URL parsing ─────────────────────────────────────────────────────
def parse_ws_url(url: str) -> Tuple[str, str, int, str, bool]:
    """Return (scheme, host, port, path, use_tls)."""
    if url.startswith("wss://"):
        scheme = "wss"; use_tls = True
        rest = url[6:]
    elif url.startswith("ws://"):
        scheme = "ws"; use_tls = False
        rest = url[5:]
    else:
        scheme = "ws"; use_tls = False; rest = url
    if "/" in rest:
        host_port, path = rest.split("/", 1)
        path = "/" + path
    else:
        host_port, path = rest, "/"
    if ":" in host_port:
        host, port = host_port.rsplit(":", 1)
        port = int(port)
    else:
        host = host_port
        port = 443 if use_tls else 80
    return scheme, host, port, path, use_tls


# ─── Raw-socket WebSocket client (stdlib fallback) ───────────────────
def _make_socket(host: str, port: int, use_tls: bool) -> socket.socket:
    raw = socket.create_connection((host, port), timeout=HANDSHAKE_TIMEOUT)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE            # lab only — never for prod
        raw = ctx.wrap_socket(raw, server_hostname=host)
    return raw


def _recv_until(sock: socket.socket, sentinel: bytes,
                timeout: float = HANDSHAKE_TIMEOUT) -> bytes:
    """Read until sentinel (e.g. b"\r\n\r\n") seen or timeout."""
    sock.settimeout(timeout)
    buf = b""
    deadline = time.time() + timeout
    while sentinel not in buf and time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def raw_handshake(host: str, port: int, path: str, use_tls: bool,
                  origin: Optional[str] = None,
                  auth_token: Optional[str] = None) -> Tuple[bool, str, bytes]:
    """Perform a RFC 6455 handshake with a raw socket.

    Returns (success, status_line, response_bytes).
    """
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        "User-Agent: harness/3.0.0 (websocket_probe)",
    ]
    if origin:
        lines.append(f"Origin: {origin}")
    if auth_token:
        lines.append(f"Authorization: Bearer {auth_token}")
    req = ("\r\n".join(lines) + "\r\n\r\n").encode()

    try:
        sock = _make_socket(host, port, use_tls)
    except (socket.error, OSError) as e:
        return False, "", f"{type(e).__name__}: {e}".encode()
    try:
        sock.sendall(req)
        resp = _recv_until(sock, b"\r\n\r\n")
    except socket.error as e:
        sock.close()
        return False, "", f"{type(e).__name__}: {e}".encode()

    status_line = resp.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    # Verify Sec-WebSocket-Accept matches expected SHA1/RFC6455 response.
    expected = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode("ascii")
    success = ("101" in status_line) and (expected.encode() in resp)
    # Hand off socket for further use if successful.
    if success:
        globals()["_LAST_SOCKET"] = sock
    else:
        try:
            sock.close()
        except Exception:
            pass
    return success, status_line, resp


def raw_send_text(sock: socket.socket, message: str) -> None:
    """Send a text frame (server-mask not required for client→server, but
    RFC 6455 mandates client masking; we mask properly)."""
    payload = message.encode("utf-8")
    mask_bit = 0x80
    header = bytearray([0x81])          # FIN + text opcode
    length = len(payload)
    mask_key = os.urandom(4)
    if length < 126:
        header.append(length | mask_bit)
    elif length < 65536:
        header.append(126 | mask_bit)
        header.extend(struct.pack(">H", length))
    else:
        header.append(127 | mask_bit)
        header.extend(struct.pack(">Q", length))
    header.extend(mask_key)
    masked = bytearray(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + bytes(masked))


def raw_recv_frame(sock: socket.socket, timeout: float = READ_TIMEOUT) -> Optional[str]:
    """Read one WebSocket frame; return decoded text payload or None."""
    sock.settimeout(timeout)
    try:
        hdr = _recv_exact(sock, 2)
        if hdr is None or len(hdr) < 2:
            return None
    except socket.timeout:
        return None
    opcode = hdr[0] & 0x0F
    masked = bool(hdr[1] & 0x80)
    length = hdr[1] & 0x7F
    if length == 126:
        ext = _recv_exact(sock, 2)
        length = struct.unpack(">H", ext)[0] if ext else 0
    elif length == 127:
        ext = _recv_exact(sock, 8)
        length = struct.unpack(">Q", ext)[0] if ext else 0
    mask_key = _recv_exact(sock, 4) if masked else None
    payload = _recv_exact(sock, length) or b""
    if masked and mask_key:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    if opcode == 0x8:                       # close
        return None
    if opcode in (0x1, 0x0):                # text / continuation
        try:
            return payload.decode("utf-8", errors="replace")
        except Exception:
            return None
    return None


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    if n <= 0:
        return b""
    sock.settimeout(READ_TIMEOUT)
    buf = b""
    deadline = time.time() + READ_TIMEOUT
    while len(buf) < n and time.time() < deadline:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            break
        except socket.error:
            break
        if not chunk:
            break
        buf += chunk
    return buf if len(buf) == n else (buf if buf else None)


# ─── Public API ──────────────────────────────────────────────────────
# The `websockets` library binds its connection objects to a specific
# asyncio event loop. Calling `asyncio.run()` per-operation closes the
# loop each time, breaking subsequent send/recv on the same connection.
# Solution: run ONE persistent loop in a background daemon thread and
# dispatch every coroutine via `run_coroutine_threadsafe`.
import asyncio as _asyncio
import threading as _threading


class _LoopRunner:
    """Persistent asyncio event loop running in a daemon thread."""

    def __init__(self) -> None:
        self._loop: Optional[_asyncio.AbstractEventLoop] = None
        self._thread: Optional[_threading.Thread] = None
        self._lock = _threading.Lock()

    def _ensure(self) -> _asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop is not None and not self._loop.is_closed():
                return self._loop
            self._loop = _asyncio.new_event_loop()
            self._thread = _threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            return self._loop

    def _run(self) -> None:
        assert self._loop is not None
        _asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def submit(self, coro, timeout: float) -> Any:
        loop = self._ensure()
        fut = _asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return fut.result(timeout=timeout)
        except Exception:
            return None

    def shutdown(self) -> None:
        with self._lock:
            loop = self._loop
            if loop is None or loop.is_closed():
                return
            try:
                loop.call_soon_threadsafe(loop.stop)
            except Exception:
                pass
            self._loop = None


_LOOP = _LoopRunner()


def _wslib_connect_sync(uri: str, extra_headers: Dict[str, str]) -> Any:
    """Synchronous wrapper around `websockets.connect` using a persistent
    background loop so the returned connection object stays usable."""

    async def _do_connect():
        # `websockets` >= 14 renamed `extra_headers` → `additional_headers`.
        kwargs: Dict[str, Any] = {"open_timeout": HANDSHAKE_TIMEOUT}
        try:
            co_varnames = websockets.connect.__code__.co_varnames
            if "additional_headers" in co_varnames:
                kwargs["additional_headers"] = extra_headers
            elif "extra_headers" in co_varnames:
                kwargs["extra_headers"] = extra_headers
        except Exception:
            kwargs["additional_headers"] = extra_headers
        return await websockets.connect(uri, **kwargs)

    return _LOOP.submit(_do_connect(), timeout=HANDSHAKE_TIMEOUT)


def _wslib_send_sync(conn: Any, message: str) -> None:
    _LOOP.submit(conn.send(message), timeout=READ_TIMEOUT)


def _wslib_recv_sync(conn: Any, timeout: float) -> Optional[str]:
    async def _do_recv():
        return await _asyncio.wait_for(conn.recv(), timeout=timeout)
    return _LOOP.submit(_do_recv(), timeout=timeout + 1.0)


def _wslib_close_sync(conn: Any) -> None:
    async def _do_close():
        try:
            await conn.close()
        except Exception:
            pass
    _LOOP.submit(_do_close(), timeout=READ_TIMEOUT)


def connect_websocket(origin: Optional[str] = None,
                      auth_token: Optional[str] = None) -> Tuple[bool, str, Any]:
    """Perform a WebSocket handshake.

    Uses `websockets` library if available, else a raw socket. Returns
    (connected, transport, conn_obj) where transport ∈ {"websockets","raw"}.
    """
    scheme, host, port, path, use_tls = parse_ws_url(TARGET_WS)

    if _HAS_WSLIB:
        try:
            extra_headers: Dict[str, str] = {}
            if origin:
                extra_headers["Origin"] = origin
            if auth_token:
                extra_headers["Authorization"] = f"Bearer {auth_token}"
            conn = _wslib_connect_sync(TARGET_WS, extra_headers)
            if conn is not None:
                return True, "websockets", conn
        except Exception:
            pass

    ok, status, _resp = raw_handshake(host, port, path, use_tls,
                                      origin=origin, auth_token=auth_token)
    sock = globals().get("_LAST_SOCKET")
    if ok and sock is not None:
        return True, "raw", sock
    return False, "raw", status


def _send_text(conn: Any, transport: str, message: str) -> bool:
    if transport == "raw":
        try:
            raw_send_text(conn, message)
            return True
        except Exception:
            return False
    elif transport == "websockets":
        try:
            _wslib_send_sync(conn, message)
            return True
        except Exception:
            return False
    return False


def _recv_text(conn: Any, transport: str, timeout: float = READ_TIMEOUT) -> Optional[str]:
    if transport == "raw":
        try:
            return raw_recv_frame(conn, timeout=timeout)
        except Exception:
            return None
    elif transport == "websockets":
        return _wslib_recv_sync(conn, timeout)
    return None


def send_payload(conn: Any, transport: str, payload: Any) -> Dict[str, Any]:
    """Send a JSON payload, measure response time, capture response text."""
    if isinstance(payload, (dict, list)):
        msg = json.dumps(payload)
    else:
        msg = str(payload)
    t0 = time.time()
    sent = _send_text(conn, transport, msg)
    if not sent:
        return {"sent": False, "ms": round((time.time() - t0) * 1000, 1),
                "response": None, "error": "send_failed"}
    resp = _recv_text(conn, transport, timeout=READ_TIMEOUT)
    ms = round((time.time() - t0) * 1000, 1)
    return {"sent": True, "payload": msg, "ms": ms,
            "response": resp, "error": None if resp is not None else "no_response"}


def check_origin_validation() -> Tuple[bool, Dict[str, Any]]:
    """Connect with Origin: https://evil.com → check if accepted (CSWSH).
    Returns (origin_accepted, detail).
    """
    # Close any existing raw socket first.
    _close_current_conn()
    ok, transport, conn = connect_websocket(origin=EVIL_ORIGIN)
    detail = {"evil_origin": EVIL_ORIGIN, "transport": transport,
              "accepted": ok, "status": conn if not ok else None}
    if ok:
        _close_current_conn()
    return ok, detail


def test_injection(conn: Any, transport: str) -> List[Dict[str, Any]]:
    """Send injection payloads; capture response / time / error indicators."""
    results: List[Dict[str, Any]] = []
    for payload in INJECTION_PAYLOADS:
        r = send_payload(conn, transport, payload)
        # Heuristics: detect SQL/NoSQL error strings in response or anomalous
        # response time (time-based payloads).
        body_lower = (r.get("response") or "").lower()
        error_indicator = any(s in body_lower for s in (
            "sql", "sqlite", "syntax", "mysql", "postgresql", "ora-",
            "mongo", "bson", "prototype", "$where", "unexpected token",
            "syntaxerror", "invalid input"))
        time_anomaly = r.get("ms", 0) > 1900    # matches sleep(2000) payload
        results.append({
            "payload": r.get("payload"),
            "sent": r.get("sent"),
            "response_len": len(r.get("response") or "") if r.get("response") else 0,
            "ms": r.get("ms"),
            "error_indicator": error_indicator,
            "time_anomaly": time_anomaly,
            "error": r.get("error"),
        })
    return results


def check_auth_required() -> Tuple[bool, Dict[str, Any]]:
    """Connect WITHOUT auth token → check if access granted (bad if yes).
    Returns (access_granted_anonymously, detail).
    """
    _close_current_conn()
    ok, transport, conn = connect_websocket(auth_token=None)
    detail = {"transport": transport, "connected": ok}
    access_granted = False
    if ok:
        # If we can send a payload and receive anything (or even stay open),
        # treat as anonymous access granted.
        r = send_payload(conn, transport, {"action": "ping"})
        access_granted = r.get("sent", False) or True   # connected ⇒ granted
        detail["ping_response"] = r.get("response")
        detail["access_granted"] = access_granted
    globals()["_CONN"] = (conn, transport) if ok else (None, transport)
    return access_granted, detail


def test_cross_section_leak(conn: Any, transport: str) -> Dict[str, Any]:
    """Subscribe to a candidate private channel and check for foreign data."""
    sub_msg = {"action": "subscribe", "channel": SUBSCRIBE_CHANNEL}
    sent = _send_text(conn, transport, json.dumps(sub_msg))
    if not sent:
        return {"tested": False, "error": "subscribe_failed"}
    # Listen up to 3 messages within read timeout each.
    messages: List[str] = []
    for _ in range(3):
        m = _recv_text(conn, transport, timeout=READ_TIMEOUT)
        if m is None:
            break
        messages.append(m)
    # Heuristics: cross-user leak if any message contains foreign-looking
    # identifiers (user_id, account, balance, email, token, ssn, iban...).
    leak_indicators = ("user_id", "account", "balance", "email", "token",
                       "ssn", "iban", "wallet", "apikey", "api_key",
                       "session", "phone", "address")
    leak = any(any(ind in msg.lower() for ind in leak_indicators)
               for msg in messages)
    return {
        "tested": True,
        "channel": SUBSCRIBE_CHANNEL,
        "messages_received": len(messages),
        "leak_indicator": leak,
        "sample": messages[:2],
    }


def _close_current_conn() -> None:
    conn, _ = globals().get("_CONN", (None, None))
    if conn is not None:
        try:
            if isinstance(conn, socket.socket):
                conn.close()
            else:
                # websockets conn — use the async close helper.
                _wslib_close_sync(conn)
        except Exception:
            pass
        globals()["_CONN"] = (None, None)
    sock = globals().pop("_LAST_SOCKET", None)
    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass


# ─── Main ────────────────────────────────────────────────────────────
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "lab": False,
            "error": "LAB guard not satisfied",
            "detail": ("Set LAB=1 in the environment to confirm lab authorization. "
                       "WebSocket probing forges handshakes and may access private "
                       "channels — lab isolated targets only."),
            "legal_note": "Unauthorized interception of WebSocket traffic is illegal.",
        }, indent=2))
        sys.exit(1)

    scheme, host, port, path, use_tls = parse_ws_url(TARGET_WS)
    deps = {"websockets_lib": _HAS_WSLIB}

    # ── 1. Plain handshake (no Origin, no auth) ────────────────────
    _close_current_conn()
    connected, transport, conn_obj = connect_websocket()
    connection_status = {
        "transport": transport,
        "connected": connected,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "use_tls": use_tls,
        "status_or_obj": (conn_obj if not connected else "ok"),
    }
    messages_received = 0
    injection_tested: List[Dict[str, Any]] = []
    cross_user_leak: Dict[str, Any] = {"tested": False}

    if connected:
        globals()["_CONN"] = (conn_obj, transport)
        # Pre-read any unsolicited server messages (e.g. welcome).
        try:
            welcome = _recv_text(conn_obj, transport, timeout=1.0)
            if welcome:
                messages_received += 1
        except Exception:
            pass

        # ── 2. Origin validation test (separate connection) ────────
        try:
            origin_accepted, origin_detail = check_origin_validation()
        except Exception as e:
            origin_accepted = False
            origin_detail = {"error": f"{type(e).__name__}: {e}"}

        # Re-establish main connection after origin test (closes socket).
        _close_current_conn()
        connected2, transport2, conn_obj2 = connect_websocket()
        if connected2:
            globals()["_CONN"] = (conn_obj2, transport2)
            conn_obj, transport = conn_obj2, transport2

        # ── 3. Auth required test (separate anonymous connection) ──
        try:
            access_anon, auth_detail = check_auth_required()
        except Exception as e:
            access_anon = False
            auth_detail = {"error": f"{type(e).__name__}: {e}"}
        # check_auth_required leaves its own conn open in _CONN.
        conn_obj, transport = globals().get("_CONN", (None, None))

        # ── 4. Injection tests on the live connection ──────────────
        if conn_obj is not None:
            try:
                injection_tested = test_injection(conn_obj, transport)
                messages_received += sum(1 for r in injection_tested if r.get("response_len", 0) > 0)
            except Exception as e:
                injection_tested = [{"error": f"{type(e).__name__}: {e}"}]

            # ── 5. Cross-section / cross-user leak test ────────────
            try:
                cross_user_leak = test_cross_section_leak(conn_obj, transport)
                messages_received += cross_user_leak.get("messages_received", 0)
            except Exception as e:
                cross_user_leak = {"tested": False, "error": f"{type(e).__name__}: {e}"}
    else:
        origin_accepted = False
        origin_detail = {"error": "not_connected"}
        access_anon = False
        auth_detail = {"error": "not_connected"}

    # Cleanup.
    _close_current_conn()
    # Tear down the background asyncio loop (if any) so the process can
    # exit cleanly without lingering daemon threads holding the loop open.
    try:
        _LOOP.shutdown()
    except Exception:
        pass

    # Origin validated = server REJECTED evil origin (good).
    origin_validated = (connected and not origin_accepted)
    # Auth required = server DENIED anonymous access (good).
    auth_required = (connected and not access_anon)

    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "lab": True,
        "target": TARGET_WS,
        "dependencies": deps,
        "connected": connected,
        "origin_validated": origin_validated,
        "auth_required": auth_required,
        "injection_tested": bool(injection_tested),
        "injection_results": injection_tested,
        "cross_user_leak": cross_user_leak,
        "messages_received": messages_received,
        "connection_detail": connection_status,
        "origin_detail": origin_detail,
        "auth_detail": auth_detail,
        # High-level verdicts:
        "findings": {
            "high_cswsh_origin_accepted": origin_accepted,
            "high_anonymous_access": access_anon,
            "high_injection_indicator": any(
                r.get("error_indicator") or r.get("time_anomaly")
                for r in injection_tested if isinstance(r, dict)),
            "critical_cross_user_leak": bool(cross_user_leak.get("leak_indicator")),
        },
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
