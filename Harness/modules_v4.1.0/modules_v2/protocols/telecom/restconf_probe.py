#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — restconf_probe (telecom protocol module)
# RESTCONF (RFC 8040) — RESTful NETCONF over HTTPS.
#
# RESTCONF exposes NETCONF datastores via HTTP/1.1 or HTTP/2 over TLS
# (port 443). It is the modern alternative to NETCONF-over-SSH, used by
# Cisco IOS-XE, Juniper Junos, Nokia SR OS, YumaWorks, ConfD.
#
# Tests:
#   1. GET /.well-known/host-meta        → restconf_root (discovery)
#   2. GET /restconf/data                → accessible (200 vs 401/404)
#   3. Check authentication              → auth_required (basic/bearer/cert)
#   4. Check YANG model support          → yang_models (ietf-interfaces,
#      ietf-system, ietf-yang-library)
#   5. Test ietf-interfaces + ietf-system datastores → datastores_accessible
#
# RESTCONF root discovery (RFC 8040 §3.1):
#   GET /.well-known/host-meta
#       Accept: application/xrd+xml
#   → <XRD><Link rel="restconf" href="/restconf"/></XRD>
#
# YANG library: GET /restconf/data/ietf-yang-library:modules-state
#   → list of all YANG modules the server implements.
#
# CLI:
#   python3 restconf_probe.py [host] [port]
#       host default = 127.0.0.1
#       port default = 443
#
# Output: single JSON object on stdout.
#
# Legal: Unauthorised RESTCONF writes on production routers is illegal
# (FR Art. 323-1 / US 18 USC §1030). READ_ONLY: only GET requests.
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
MODULE_NAME = "restconf_probe"
TIMEOUT_S = 5  # 5 s hard cap on every socket op

# ─── CLI args ─────────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443
except ValueError:
    PORT = 443

# SAFE_MODE can be overridden via env. telecom sector default = read_only.
SAFE_MODE = os.environ.get("SAFE_MODE", "read_only")

# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))
_rng = random.Random(SEED)

# ─── LAB guard ────────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ═══════════════════════════════════════════════════════════════════════════
#  TLS / socket helpers
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


def _wrap_tls(sock: socket.socket, host: str,
              alpn: Optional[List[str]] = None) -> Tuple[Optional[ssl.SSLSocket],
                                                          Optional[str]]:
    """Wrap a TCP socket in TLS. Returns (ssl_sock, negotiated_alpn_or_None)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Enable ALPN if requested (RESTCONF may negotiate h2 or http/1.1)
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except (NotImplementedError, AttributeError):
            pass
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=host)
    except (ssl.SSLError, OSError) as e:
        return None, f"tls_error:{type(e).__name__}"
    negotiated = None
    try:
        negotiated = ssock.selected_alpn_protocol()
    except (NotImplementedError, AttributeError, OSError):
        negotiated = None
    return ssock, negotiated


# ═══════════════════════════════════════════════════════════════════════════
#  HTTP/1.1 client (minimal)
# ═══════════════════════════════════════════════════════════════════════════
def http_request(host: str, port: int, method: str, path: str,
                 extra_headers: Optional[Dict[str, str]] = None,
                 body: bytes = b"",
                 accept: str = "application/yang-data+json, application/yang-data+xml",
                 use_tls: bool = True) -> Tuple[Optional[Dict], str]:
    """Send an HTTP/1.1 request. Returns (parsed_response_or_None, error_str).
    parsed_response has: status_code, reason, headers (dict), body (str)."""
    sock = None
    ssock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _set_sock_timeout(sock, TIMEOUT_S)
        sock.connect((host, port))
        if use_tls:
            ssock, alpn_err = _wrap_tls(sock, host, alpn=["http/1.1", "h2"])
            if ssock is None:
                return None, alpn_err or "tls_failed"
            io_sock = ssock
        else:
            io_sock = sock
        # Build request
        headers = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host}:{port}" if port not in (80, 443) else f"Host: {host}",
            f"User-Agent: harness/{HARNESS_VERSION} ({MODULE_NAME})",
            f"Accept: {accept}",
            "Connection: close",
        ]
        if extra_headers:
            for k, v in extra_headers.items():
                headers.append(f"{k}: {v}")
        if body:
            headers.append(f"Content-Length: {len(body)}")
            headers.append("Content-Type: application/yang-data+json")
        req = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body
        io_sock.sendall(req)
        # Read all response bytes
        chunks: List[bytes] = []
        total = 0
        while True:
            try:
                chunk = io_sock.recv(8192)
            except (socket.timeout, TimeoutError):
                break
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 1_000_000:  # 1 MB safety cap
                break
        raw = b"".join(chunks)
        return _parse_http_response(raw), ""
    except (ConnectionRefusedError, OSError) as e:
        return None, f"send_error:{type(e).__name__}:{e}"
    except Exception as e:  # noqa: BLE001
        return None, f"error:{type(e).__name__}:{e}"
    finally:
        for s in (ssock, sock):
            if s is not None:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass


_STATUS_RE = re.compile(rb"^HTTP/\d\.\d\s+(\d{3})\s+(.*)$")


def _parse_http_response(raw: bytes) -> Optional[Dict]:
    """Parse an HTTP/1.1 response into a dict. Splits headers/body at the
    first \r\n\r\n."""
    if not raw:
        return None
    # Find header/body boundary
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        sep = raw.find(b"\n\n")
        if sep == -1:
            return None
        head = raw[:sep]
        body = raw[sep + 2:]
    else:
        head = raw[:sep]
        body = raw[sep + 4:]
    head_text = head.decode("iso-8859-1", errors="replace")
    lines = head_text.split("\r\n") if "\r\n" in head_text else head_text.split("\n")
    if not lines:
        return None
    m = _STATUS_RE.match(lines[0].encode("ascii", errors="replace"))
    if not m:
        return None
    status_code = int(m.group(1))
    reason = m.group(2).decode("ascii", errors="replace")
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    # Handle chunked transfer encoding
    body_str = body.decode("utf-8", errors="replace")
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body_str = _dechunk(body)
    return {
        "status_code": status_code,
        "reason": reason,
        "headers": headers,
        "body": body_str,
        "raw_body_len": len(body),
    }


def _dechunk(body: bytes) -> str:
    """Decode HTTP/1.1 chunked transfer-encoding body."""
    out = bytearray()
    pos = 0
    while pos < len(body):
        # Find chunk size line
        end = body.find(b"\r\n", pos)
        if end == -1:
            break
        size_str = body[pos:end].split(b";")[0].strip()
        try:
            size = int(size_str, 16)
        except ValueError:
            break
        if size == 0:
            break
        chunk_start = end + 2
        chunk_end = chunk_start + size
        out.extend(body[chunk_start:chunk_end])
        pos = chunk_end + 2  # skip trailing \r\n
    return out.decode("utf-8", errors="replace")


# ═══════════════════════════════════════════════════════════════════════════
#  Test 1: RESTCONF root discovery via /.well-known/host-meta
# ═══════════════════════════════════════════════════════════════════════════
# RFC 8040 §3.1: client discovers the RESTCONF root by fetching
# /.well-known/host-meta. The response is an XRD document:
#   <XRD><Link rel="restconf" href="/restconf"/></XRD>
_HREF_RE = re.compile(
    r'<Link[^>]*rel=["\']restconf["\'][^>]*href=["\']([^"\']+)["\']',
    re.IGNORECASE)
_HREF_RE2 = re.compile(
    r'<Link[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\']restconf["\']',
    re.IGNORECASE)


def test_discover_root(host: str, port: int,
                       results: List[Dict]) -> Tuple[bool, str]:
    """GET /.well-known/host-meta to find the RESTCONF root. Returns
    (discovered, root_path)."""
    resp, err = http_request(host, port, "GET", "/.well-known/host-meta",
                             accept="application/xrd+xml, application/xml")
    if resp is None:
        results.append({"test": "discover_root",
                        "verdict": "no_response",
                        "error": err})
        return False, ""
    discovered = False
    root = ""
    if resp["status_code"] == 200:
        m = _HREF_RE.search(resp["body"]) or _HREF_RE2.search(resp["body"])
        if m:
            root = m.group(1)
            discovered = True
    results.append({
        "test": "discover_root",
        "verdict": "discovered" if discovered else "not_advertised",
        "status_code": resp["status_code"],
        "restconf_root": root,
    })
    # Fall back to /restconf if not discovered
    if not root:
        root = "/restconf"
    return discovered, root


# ═══════════════════════════════════════════════════════════════════════════
#  Test 2: GET /restconf/data — accessibility check
# ═══════════════════════════════════════════════════════════════════════════
def test_data_accessible(host: str, port: int, root: str,
                         results: List[Dict]) -> Tuple[bool, bool]:
    """GET <root>/data. Returns (accessible, auth_required).
       200 OK                → accessible=True, auth_required=False (critical)
       401 WWW-Authenticate  → accessible=True (RESTCONF present), auth=True
       404 Not Found         → accessible=False
       403 Forbidden         → accessible=True, auth=True (no challenge)"""
    path = root.rstrip("/") + "/data"
    resp, err = http_request(host, port, "GET", path)
    if resp is None:
        results.append({"test": "data_accessible",
                        "verdict": "no_response",
                        "error": err})
        return False, True
    accessible = False
    auth_required = True
    if resp["status_code"] == 200:
        accessible = True
        auth_required = False
    elif resp["status_code"] in (401, 407):
        accessible = True
        auth_required = True
    elif resp["status_code"] == 403:
        accessible = True
        auth_required = True
    elif resp["status_code"] == 404:
        accessible = False
        auth_required = True
    results.append({
        "test": "data_accessible",
        "verdict": "accessible" if accessible else "not_accessible",
        "status_code": resp["status_code"],
        "auth_required": auth_required,
        "www_authenticate": resp["headers"].get("www-authenticate"),
    })
    return accessible, auth_required


# ═══════════════════════════════════════════════════════════════════════════
#  Test 3: Authentication mechanisms (basic / bearer / client cert)
# ═══════════════════════════════════════════════════════════════════════════
def test_auth_mechanisms(host: str, port: int, root: str,
                         auth_required: bool,
                         results: List[Dict]) -> Dict:
    """Probe authentication: send a request with bogus Basic creds, a bogus
    Bearer token, and see which schemes the server advertises. We do NOT
    use a client cert (we don't have one)."""
    mech: Dict[str, bool] = {"basic": False, "bearer": False,
                             "client_cert": False, "none": False}
    if not auth_required:
        # No auth required at all → all "none"
        mech["none"] = True
        results.append({
            "test": "auth_mechanisms",
            "verdict": "no_auth_required",
            "detail": "RESTCONF /data returned 200 with no credentials",
        })
        return mech
    # Send Basic auth with bogus creds — server will 401 but advertise scheme
    resp, _err = http_request(host, port, "GET", root.rstrip("/") + "/data",
                              extra_headers={"Authorization":
                                             "Basic aGFybmVzczpwcm9iZQ=="})
    if resp is not None:
        www = resp["headers"].get("www-authenticate", "")
        if "basic" in www.lower():
            mech["basic"] = True
        if "bearer" in www.lower():
            mech["bearer"] = True
        if "client-cert" in www.lower() or "tls" in www.lower():
            mech["client_cert"] = True
        results.append({
            "test": "auth_mechanisms",
            "verdict": "advertised",
            "www_authenticate": www,
            "mechanisms": mech,
            "status_code": resp["status_code"],
        })
    else:
        results.append({"test": "auth_mechanisms",
                        "verdict": "no_response"})
    return mech


# ═══════════════════════════════════════════════════════════════════════════
#  Test 4: YANG model support (ietf-yang-library)
# ═══════════════════════════════════════════════════════════════════════════
# GET /restconf/data/ietf-yang-library:modules-state
# Returns a list of all YANG modules the server implements.
_YANG_MODULE_RE = re.compile(
    r'"name"\s*:\s*"([^"]+)".*?"revision"\s*:\s*"([^"]*)"',
    re.DOTALL)
_YANG_MODULE_RE_XML = re.compile(
    r'<module>\s*<name>([^<]+)</name>\s*<revision>([^<]*)</revision>',
    re.DOTALL)


def test_yang_models(host: str, port: int, root: str,
                     auth_required: bool,
                     results: List[Dict]) -> List[str]:
    """Query ietf-yang-library:modules-state to enumerate YANG models.
    Returns a list of module names."""
    path = root.rstrip("/") + "/data/ietf-yang-library:modules-state"
    resp, err = http_request(host, port, "GET", path)
    if resp is None:
        results.append({"test": "yang_models",
                        "verdict": "no_response",
                        "error": err})
        return []
    models: List[str] = []
    if resp["status_code"] == 200:
        # JSON or XML?
        body = resp["body"]
        if body.lstrip().startswith("{") or body.lstrip().startswith("["):
            for m in _YANG_MODULE_RE.finditer(body):
                models.append(f"{m.group(1)}@{m.group(2)}" if m.group(2)
                              else m.group(1))
        else:
            for m in _YANG_MODULE_RE_XML.finditer(body):
                models.append(f"{m.group(1)}@{m.group(2)}" if m.group(2)
                              else m.group(1))
        # Dedupe
        seen = set()
        uniq = []
        for m in models:
            if m not in seen:
                seen.add(m)
                uniq.append(m)
        models = uniq[:100]  # cap at 100 for the report
    results.append({
        "test": "yang_models",
        "verdict": "enumerated" if models else "not_available",
        "status_code": resp["status_code"],
        "count": len(models),
        "sample": models[:10],
    })
    return models


# ═══════════════════════════════════════════════════════════════════════════
#  Test 5: ietf-interfaces + ietf-system datastores
# ═══════════════════════════════════════════════════════════════════════════
def test_datastores_accessible(host: str, port: int, root: str,
                               results: List[Dict]) -> bool:
    """GET ietf-interfaces:interfaces and ietf-system:system — if either
    responds (200 or 401), the datastore endpoint is reachable."""
    paths = [
        (root.rstrip("/") + "/data/ietf-interfaces:interfaces", "ietf-interfaces"),
        (root.rstrip("/") + "/data/ietf-system:system", "ietf-system"),
    ]
    accessible_any = False
    for path, label in paths:
        resp, _err = http_request(host, port, "GET", path)
        ok = False
        if resp is not None and resp["status_code"] in (200, 401, 403):
            ok = True
            accessible_any = True
        results.append({
            "test": "datastore_endpoint",
            "label": label,
            "verdict": "reachable" if ok else "unreachable",
            "status_code": resp["status_code"] if resp else None,
        })
    return accessible_any


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
            "legal_note": ("Unauthorised RESTCONF on production routers is "
                           "illegal (FR Art. 323-1 / US 18 USC §1030). Lab only."),
        }))
        sys.exit(1)

    t0 = time.time()
    results: List[Dict] = []
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "restconf_port": PORT,
        "sector": get_sector_config().get("sector", "telecom"),
        "safe_mode": SAFE_MODE,
        "read_only": SAFE_MODE != "full",
        "seed": SEED,
        # Spec-required output fields:
        "restconf_root": "",
        "accessible": False,
        "auth_required": True,
        "yang_models": [],
        "datastores_accessible": False,
        "results": results,
        "errors": [],
    }

    # ─── 1. Discover RESTCONF root ────────────────────────────────────────
    root = "/restconf"
    try:
        _discovered, root = test_discover_root(HOST, PORT, results)
        summary["restconf_root"] = root
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"discover_root:{type(e).__name__}:{e}")

    # ─── 2. GET /restconf/data → accessible ───────────────────────────────
    auth_required = True
    try:
        accessible, auth_required = test_data_accessible(HOST, PORT, root, results)
        summary["accessible"] = accessible
        summary["auth_required"] = auth_required
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"data_accessible:{type(e).__name__}:{e}")

    # ─── 3. Authentication mechanisms ─────────────────────────────────────
    try:
        test_auth_mechanisms(HOST, PORT, root, auth_required, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"auth_mechs:{type(e).__name__}:{e}")

    # ─── 4. YANG model support ────────────────────────────────────────────
    try:
        summary["yang_models"] = test_yang_models(HOST, PORT, root,
                                                  auth_required, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"yang_models:{type(e).__name__}:{e}")

    # ─── 5. Datastore endpoints (ietf-interfaces / ietf-system) ──────────
    try:
        summary["datastores_accessible"] = test_datastores_accessible(
            HOST, PORT, root, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"datastores:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
