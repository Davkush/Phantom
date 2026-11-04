#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — sip_probe (telecom protocol module)
# SIP (Session Initiation Protocol, RFC 3261) VoIP signaling probe.
#
# SIP is used for VoIP call setup, registration, presence and IM. It is the
# dominant call-signaling protocol in PBX systems (Asterisk, FreeSWITCH,
# Kamailio, OpenSIPS) and in WebRTC gateways.
#
# Tests:
#   1. OPTIONS ping (SIP keepalive)         → sip_responsive
#   2. REGISTER with fake credentials       → auth_required
#   3. ENUM (E.164 Number to URI) lookup    → enum_tested
#   4. SIP digest auth replay vulnerability → digest_replay_vulnerable
#   5. SIP INVITE flooding (rate limit)     → informational only
#   6. Toll fraud risk: can we place a call without auth?
#                                            → toll_fraud_risk
#
# SIP message format (RFC 3261 §7):
#   Request line: <Method> <Request-URI> SIP/2.0\r\n
#   Status line : SIP/2.0 <code> <reason>\r\n
#   Headers     : <name>: <value>\r\n
#   Blank line  : \r\n
#   Body        : (SDP for INVITE, empty for OPTIONS/REGISTER)
#
# Mandatory headers per RFC 3261 §8.1.1:
#   Via, From, To, Call-ID, CSeq, Max-Forwards, Contact (for dialog-creating)
#
# CLI:
#   python3 sip_probe.py [host] [port]
#       host default = 127.0.0.1
#       port default = 5060
#
# Output: single JSON object on stdout.
#
# Legal: Toll fraud on production PBX is illegal and can cost tens of
# thousands of euros in hours (FR Art. 313-1 / US 18 USC §1343). LAB only.
import json
import os
import random
import re
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
MODULE_NAME = "sip_probe"
TIMEOUT_S = 5  # 5 s hard cap on every socket op

# ─── CLI args ─────────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
except ValueError:
    PORT = 5060

# SAFE_MODE can be overridden via env. telecom sector default = read_only.
SAFE_MODE = os.environ.get("SAFE_MODE", "read_only")

# ─── SEED reproducibility (deterministic Call-ID / tag / branch) ──────────────
SEED = int(os.environ.get("SEED", "1337"))
_rng = random.Random(SEED)

# Test credentials (RFC 4458 reserved username, never a real subscriber)
TEST_USER = "harness-probe"
TEST_PASS = "probe-secret-1337"
TEST_E164 = "+15550100"   # ITU-T E.430 reserved for lab/fiction

# ─── LAB guard ────────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


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


def _rand_tag() -> str:
    return f"{_rng.randint(0, 0xffffffff):x}"


def _rand_call_id() -> str:
    return f"harness-{_rng.randint(0, 0xffffffff):x}@{HOST}"


def _rand_branch() -> str:
    return f"z9hG4bKharness{_rng.randint(0, 0xffffffff):x}"


# ═══════════════════════════════════════════════════════════════════════════
#  SIP message building (RFC 3261)
# ═══════════════════════════════════════════════════════════════════════════
def build_sip_options(host: str, port: int) -> bytes:
    """Build a SIP OPTIONS request (RFC 3261 §11.2). OPTIONS is the standard
    keepalive / capability-discovery method — a SIP server MUST respond."""
    call_id = _rand_call_id()
    branch = _rand_branch()
    tag = _rand_tag()
    msg = (
        f"OPTIONS sip:{host}:{port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {HOST}:{PORT};branch={branch};rport\r\n"
        f"From: <sip:harness@{HOST}>;tag={tag}\r\n"
        f"To: <sip:{host}:{port}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: harness/{HARNESS_VERSION} ({MODULE_NAME})\r\n"
        f"Accept: application/sdp\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )
    return msg.encode("utf-8")


def build_sip_register(host: str, port: int, realm: Optional[str] = None,
                       auth_header: Optional[str] = None) -> bytes:
    """Build a SIP REGISTER request. If `auth_header` is provided (a
    computed `Authorization:` line for digest auth), it is included —
    used to test digest replay. Otherwise sends an unauthenticated REGISTER
    to detect a misconfigured PBX that accepts registration without auth."""
    call_id = _rand_call_id()
    branch = _rand_branch()
    tag = _rand_tag()
    contact = f"<sip:{TEST_USER}@{HOST}:5060>;expires=3600"
    lines = [
        f"REGISTER sip:{host}:{port} SIP/2.0",
        f"Via: SIP/2.0/UDP {HOST}:{PORT};branch={branch};rport",
        f"From: <sip:{TEST_USER}@{host}>;tag={tag}",
        f"To: <sip:{TEST_USER}@{host}>",
        f"Call-ID: {call_id}",
        f"CSeq: 1 REGISTER",
        f"Contact: {contact}",
        f"Max-Forwards: 70",
        f"User-Agent: harness/{HARNESS_VERSION} ({MODULE_NAME})",
    ]
    if auth_header:
        lines.append(auth_header)
    lines.append("Content-Length: 0")
    lines.append("")
    return ("\r\n".join(lines)).encode("utf-8")


def build_sip_invite_no_auth(host: str, port: int,
                             target_e164: str) -> bytes:
    """Build a SIP INVITE without authentication, attempting to place a call
    to `target_e164`. Toll-fraud test — only emitted when SAFE_MODE=full."""
    call_id = _rand_call_id()
    branch = _rand_branch()
    tag = _rand_tag()
    sdp_body = (
        "v=0\r\n"
        f"o=harness {SEED} {SEED} IN IP4 {HOST}\r\n"
        f"s=harness-probe\r\n"
        f"c=IN IP4 {HOST}\r\n"
        "t=0 0\r\n"
        "m=audio 8000 RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
    )
    sdp_bytes = sdp_body.encode("utf-8")
    msg = (
        f"INVITE sip:{target_e164}@{host}:{port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {HOST}:{PORT};branch={branch};rport\r\n"
        f"From: <sip:harness@{HOST}>;tag={tag}\r\n"
        f"To: <sip:{target_e164}@{host}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Max-Forwards: 70\r\n"
        f"Contact: <sip:harness@{HOST}:5060>\r\n"
        f"Content-Type: application/sdp\r\n"
        f"Content-Length: {len(sdp_bytes)}\r\n"
        f"\r\n"
    ).encode("utf-8") + sdp_bytes
    return msg


# ═══════════════════════════════════════════════════════════════════════════
#  SIP response parsing
# ═══════════════════════════════════════════════════════════════════════════
_STATUS_RE = re.compile(r"^SIP/2\.0\s+(\d{3})\s+(.*)$", re.IGNORECASE)


def parse_sip_response(data: bytes) -> Optional[Dict]:
    """Parse a SIP response. Returns dict with status_code, reason, headers,
    body, or None if data is not a SIP response."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    m = _STATUS_RE.match(lines[0])
    if not m:
        return None
    status_code = int(m.group(1))
    reason = m.group(2)
    headers: Dict[str, str] = {}
    body_start = -1
    for i, line in enumerate(lines[1:], 1):
        if line == "":
            body_start = i + 1
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    body = ""
    if body_start > 0 and body_start < len(lines):
        body = "\r\n".join(lines[body_start:])
    return {
        "status_code": status_code,
        "reason": reason,
        "headers": headers,
        "body": body,
    }


def send_recv_sip(host: str, port: int, message: bytes,
                  timeout: float = TIMEOUT_S) -> Tuple[Optional[Dict], str]:
    """Send a SIP message over UDP, read back the response.
    Returns (parsed_response_or_None, error_str)."""
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
        return parse_sip_response(data), ""
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
#  Test 1: OPTIONS ping (responsiveness)
# ═══════════════════════════════════════════════════════════════════════════
def test_options_ping(host: str, port: int, results: List[Dict]) -> bool:
    """Send OPTIONS, look for any SIP/2.0 response. The status code tells
    us the server type:
      200 OK            → Asterisk / FreeSWITCH (permissive)
      405 Method Not Allowed → OPTIONS not supported, but SIP server alive
      486 Busy Here     → Kamailio (stateful proxy)
    Any SIP response = sip_responsive=True."""
    msg = build_sip_options(host, port)
    resp, err = send_recv_sip(host, port, msg)
    responsive = False
    server_fingerprint = None
    if resp:
        responsive = True
        # Server header often reveals the implementation
        server_fingerprint = resp["headers"].get("server")
        results.append({
            "test": "options_ping",
            "verdict": "responsive",
            "status_code": resp["status_code"],
            "reason": resp["reason"],
            "server": server_fingerprint,
            "allow": resp["headers"].get("allow"),
        })
    else:
        results.append({
            "test": "options_ping",
            "verdict": "no_response",
            "error": err,
        })
    return responsive


# ═══════════════════════════════════════════════════════════════════════════
#  Test 2: REGISTER with fake credentials (auth check)
# ═══════════════════════════════════════════════════════════════════════════
def test_register_auth(host: str, port: int,
                       results: List[Dict]) -> Tuple[bool, Optional[Dict]]:
    """Send REGISTER without auth. Expected responses:
      401 Unauthorized (with WWW-Authenticate)  → auth properly required
      403 Forbidden                              → auth required (no challenge)
      200 OK                                     → CRITICAL: no auth required!
    Returns (auth_required, www_authenticate_dict_or_None)."""
    msg = build_sip_register(host, port)
    resp, err = send_recv_sip(host, port, msg)
    auth_required = True
    www_auth = None
    if resp:
        if resp["status_code"] in (401, 407):
            auth_required = True
            www_auth_raw = resp["headers"].get("www-authenticate") or \
                           resp["headers"].get("proxy-authenticate")
            if www_auth_raw:
                www_auth = parse_digest_challenge(www_auth_raw)
            results.append({
                "test": "register_no_auth",
                "verdict": "auth_required",
                "status_code": resp["status_code"],
                "www_authenticate": www_auth,
            })
        elif resp["status_code"] == 200:
            # CRITICAL: registration accepted with no auth!
            auth_required = False
            results.append({
                "test": "register_no_auth",
                "verdict": "vulnerable_no_auth",
                "status_code": resp["status_code"],
                "detail": "PBX accepted REGISTER without credentials",
            })
        else:
            results.append({
                "test": "register_no_auth",
                "verdict": "other",
                "status_code": resp["status_code"],
                "reason": resp["reason"],
            })
    else:
        results.append({
            "test": "register_no_auth",
            "verdict": "no_response",
            "error": err,
        })
    return auth_required, www_auth


# ═══════════════════════════════════════════════════════════════════════════
#  Digest auth challenge parsing + digest computation (RFC 7616 / RFC 2617)
# ═══════════════════════════════════════════════════════════════════════════
def parse_digest_challenge(header_value: str) -> Dict:
    """Parse a `WWW-Authenticate: Digest realm="...", nonce="...", ...` value.
    Returns a dict of parameters (lowercased keys)."""
    params: Dict[str, str] = {}
    # Strip the scheme prefix (Digest / Basic)
    parts = header_value.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "digest":
        body = parts[1]
    else:
        body = header_value
    # Match key=value or key="value" tokens
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([^\s,]+))', body):
        key = m.group(1).lower()
        val = m.group(2) if m.group(2) is not None else m.group(3)
        params[key] = val
    return params


def compute_digest_response(username: str, password: str, realm: str,
                            nonce: str, method: str, uri: str,
                            algorithm: str = "MD5",
                            qop: Optional[str] = None,
                            nc: Optional[str] = None,
                            cnonce: Optional[str] = None) -> str:
    """Compute a SIP digest auth `response` value per RFC 7616 / RFC 2617.
    Supports MD5 (default) and MD5-sess (qop=auth). SHA-256 is RFC 7616 but
    rarely deployed in SIP — not implemented here for stdlib simplicity."""
    import hashlib
    def h(s: str) -> str:
        return hashlib.md5(s.encode("utf-8")).hexdigest()
    ha1 = h(f"{username}:{realm}:{password}")
    if algorithm.lower() == "md5-sess":
        ha1 = h(f"{ha1}:{nonce}:{cnonce}")
    ha2 = h(f"{method}:{uri}")
    if qop:
        # qop=auth: response = H(HA1:nonce:nc:cnonce:qop:HA2)
        response = h(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    else:
        response = h(f"{ha1}:{nonce}:{ha2}")
    return response


def build_authorization_header(username: str, realm: str, nonce: str,
                               uri: str, method: str, response: str,
                               algorithm: str = "MD5",
                               qop: Optional[str] = None,
                               nc: Optional[str] = None,
                               cnonce: Optional[str] = None,
                               opaque: Optional[str] = None) -> str:
    """Build a SIP `Authorization:` header (RFC 3261 §22.2 + RFC 2617)."""
    parts = [f'Digest username="{username}"',
             f'realm="{realm}"',
             f'nonce="{nonce}"',
             f'uri="{uri}"',
             f'response="{response}"',
             f'algorithm={algorithm}']
    if qop:
        parts.append(f'qop={qop}')
        parts.append(f'nc={nc}')
        parts.append(f'cnonce="{cnonce}"')
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return "Authorization: " + ", ".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
#  Test 3: ENUM (E.164 Number to URI) lookup
# ═══════════════════════════════════════════════════════════════════════════
# ENUM (RFC 6116) maps E.164 phone numbers to DNS URIs. The number
# +1 555 0100 becomes:
#   0.0.1.0.5.5.5.5.1.e164.arpa
# and the DNS server returns NAPTR records (URI) for SIP/H323/tel: etc.
def test_enum_lookup(e164: str, results: List[Dict]) -> bool:
    """Perform a DNS NAPTR lookup for the ENUM domain of `e164`.
    Returns True if the lookup was performed (regardless of result — a
    NXDOMAIN is a valid result indicating no ENUM record)."""
    # Build the ENUM domain: strip non-digits, reverse, append e164.arpa
    digits = re.sub(r"\D", "", e164)
    if not digits:
        results.append({"test": "enum_lookup",
                        "verdict": "skipped", "reason": "invalid_e164"})
        return False
    enum_domain = ".".join(reversed(digits)) + ".e164.arpa"
    try:
        import dns.resolver  # type: ignore
        resolver = dns.resolver.Resolver()
        resolver.timeout = TIMEOUT_S
        resolver.lifetime = TIMEOUT_S
        try:
            answers = resolver.resolve(enum_domain, "NAPTR")
            naptrs = [str(r) for r in answers]
            results.append({
                "test": "enum_lookup",
                "verdict": "record_found",
                "enum_domain": enum_domain,
                "naptr_records": naptrs[:5],
            })
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            results.append({
                "test": "enum_lookup",
                "verdict": "no_record",
                "enum_domain": enum_domain,
                "detail": "No ENUM record (NXDOMAIN / NoAnswer)",
            })
            return True
        except dns.resolver.NoNameservers:
            results.append({
                "test": "enum_lookup",
                "verdict": "no_nameservers",
                "enum_domain": enum_domain,
            })
            return True
    except ImportError:
        # dnspython not available — fall back to socket.getaddrinfo() on the
        # ENUM domain (works for A records only, but proves DNS reachability).
        try:
            socket.getaddrinfo(enum_domain, None)
            results.append({
                "test": "enum_lookup",
                "verdict": "dns_resolvable",
                "enum_domain": enum_domain,
                "detail": "dnspython not installed; basic DNS resolution OK",
            })
            return True
        except (socket.gaierror, OSError):
            results.append({
                "test": "enum_lookup",
                "verdict": "no_dns_record",
                "enum_domain": enum_domain,
                "detail": "No DNS record found (basic resolver fallback)",
            })
            return True
        except Exception as e:  # noqa: BLE001
            results.append({
                "test": "enum_lookup",
                "verdict": "error",
                "error": f"{type(e).__name__}:{e}",
            })
            return False
    except Exception as e:  # noqa: BLE001
        results.append({
            "test": "enum_lookup",
            "verdict": "error",
            "error": f"{type(e).__name__}:{e}",
        })
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  Test 4: Digest auth replay vulnerability
# ═══════════════════════════════════════════════════════════════════════════
def test_digest_replay(host: str, port: int,
                       www_auth: Optional[Dict],
                       results: List[Dict]) -> bool:
    """Digest replay test: if the server returned a nonce in the 401
    challenge, we compute a digest response using FAKE credentials and
    resubmit the REGISTER. A vulnerable server that:
      (a) accepts a digest response computed with ANY password (because it
          doesn't actually verify against its user database), OR
      (b) reuses the same nonce for multiple challenges (nonce reuse),
    is replay-vulnerable. We test (b) by submitting the same nonce twice."""
    if not www_auth or "nonce" not in www_auth:
        results.append({"test": "digest_replay",
                        "verdict": "skipped",
                        "reason": "no_nonce_in_challenge"})
        return False
    realm = www_auth.get("realm", "lab")
    nonce = www_auth["nonce"]
    qop = www_auth.get("qop")
    algorithm = www_auth.get("algorithm", "MD5")
    opaque = www_auth.get("opaque")
    uri = f"sip:{host}:{port}"
    cnonce = f"{_rng.randint(0, 0xffffffff):x}"
    nc = "00000001"
    # Compute digest response with our test credentials
    response = compute_digest_response(
        TEST_USER, TEST_PASS, realm, nonce, "REGISTER", uri,
        algorithm=algorithm, qop=qop, nc=nc, cnonce=cnonce)
    auth_header = build_authorization_header(
        TEST_USER, realm, nonce, uri, "REGISTER", response,
        algorithm=algorithm, qop=qop, nc=nc, cnonce=cnonce, opaque=opaque)
    # Resubmit REGISTER with the computed auth
    msg = build_sip_register(host, port, realm=realm, auth_header=auth_header)
    resp, err = send_recv_sip(host, port, msg)
    replay_vulnerable = False
    if resp:
        # 200 OK with fake credentials = CRITICAL: server didn't validate
        # the password against its user DB.
        if resp["status_code"] == 200:
            replay_vulnerable = True
            results.append({
                "test": "digest_replay",
                "verdict": "vulnerable",
                "status_code": resp["status_code"],
                "detail": ("Server accepted digest response computed with "
                           "fake credentials — password not validated"),
            })
        elif resp["status_code"] in (401, 407):
            # Got a new challenge — check if the nonce is the same
            new_www = resp["headers"].get("www-authenticate") or \
                      resp["headers"].get("proxy-authenticate")
            new_nonce = None
            if new_www:
                new_www_dict = parse_digest_challenge(new_www)
                new_nonce = new_www_dict.get("nonce")
            # If the server returned the SAME nonce, it's replay-vulnerable
            # (RFC 2617 §3.2.1: nonce must be unique per challenge).
            if new_nonce and new_nonce == nonce:
                replay_vulnerable = True
                results.append({
                    "test": "digest_replay",
                    "verdict": "vulnerable_nonce_reuse",
                    "status_code": resp["status_code"],
                    "detail": ("Server reused the same nonce across "
                               "challenges — replay-vulnerable"),
                    "nonce": nonce[:32] + "..." if len(nonce) > 32 else nonce,
                })
            else:
                results.append({
                    "test": "digest_replay",
                    "verdict": "rejected",
                    "status_code": resp["status_code"],
                    "detail": "Fresh nonce issued, fake creds rejected",
                })
        else:
            results.append({
                "test": "digest_replay",
                "verdict": "other",
                "status_code": resp["status_code"],
                "reason": resp["reason"],
            })
    else:
        results.append({"test": "digest_replay",
                        "verdict": "no_response",
                        "error": err})
    return replay_vulnerable


# ═══════════════════════════════════════════════════════════════════════════
#  Test 5: INVITE flooding (rate limit) — informational only
# ═══════════════════════════════════════════════════════════════════════════
def test_invite_flooding(host: str, port: int,
                         results: List[Dict]) -> None:
    """Send a small burst of OPTIONS (not INVITE — we don't want to actually
    place calls) and measure whether the server rate-limits. This is
    informational: a real INVITE flood would degrade VoIP quality, but the
    detection logic is identical (look for 100 Trying + 503 Service Unavailable
    with Retry-After)."""
    burst_count = 5
    success = 0
    rate_limited = False
    retry_after = None
    for i in range(burst_count):
        msg = build_sip_options(host, port)
        resp, _ = send_recv_sip(host, port, msg, timeout=1.0)
        if resp:
            success += 1
            if resp["status_code"] == 503:
                rate_limited = True
                retry_after = resp["headers"].get("retry-after")
                break
        # No sleep between sends — we want to test rate limit
    results.append({
        "test": "invite_flooding_rate_limit",
        "verdict": "rate_limited" if rate_limited else "not_rate_limited",
        "burst_count": burst_count,
        "responses_received": success,
        "retry_after": retry_after,
        "detail": ("In read-only mode we burst OPTIONS (not INVITE) — "
                   "503 with Retry-After indicates rate-limiting is in place"),
    })


# ═══════════════════════════════════════════════════════════════════════════
#  Test 6: Toll fraud (INVITE without auth — SAFE_MODE=full only)
# ═══════════════════════════════════════════════════════════════════════════
def test_toll_fraud(host: str, port: int,
                    results: List[Dict]) -> bool:
    """Toll fraud test: send an INVITE without authentication, attempting
    to place a call to a fictitious E.164 number. A misconfigured PBX will
    accept the INVITE (100 Trying → 180 Ringing → 200 OK) without auth.

    SAFE_MODE=read_only (default): this test is SKIPPED — placing a call
    to a PSTN gateway incurs real cost on production telco infrastructure.
    SAFE_MODE=full: emits the INVITE.

    Returns True if toll fraud risk detected (200 OK without auth)."""
    if SAFE_MODE != "full":
        results.append({
            "test": "toll_fraud",
            "verdict": "skipped",
            "reason": "SAFE_MODE != full (toll fraud has real cost in production)",
            "detail": ("Set SAFE_MODE=full to emit an INVITE without auth — "
                       "only do this in an isolated lab PBX"),
        })
        return False
    msg = build_sip_invite_no_auth(host, port, TEST_E164)
    resp, err = send_recv_sip(host, port, msg)
    risk = False
    if resp:
        # 100 Trying is normal (the PBX is routing the call). 183 Session
        # Progress, 180 Ringing or 200 OK = the call is being placed!
        if resp["status_code"] in (180, 183, 200):
            risk = True
            results.append({
                "test": "toll_fraud",
                "verdict": "vulnerable",
                "status_code": resp["status_code"],
                "detail": ("PBX accepted INVITE without authentication — "
                           "toll fraud risk: any attacker can place calls"),
            })
        elif resp["status_code"] in (401, 407):
            results.append({
                "test": "toll_fraud",
                "verdict": "auth_required",
                "status_code": resp["status_code"],
                "detail": "PBX correctly challenged the INVITE",
            })
        else:
            results.append({
                "test": "toll_fraud",
                "verdict": "other",
                "status_code": resp["status_code"],
                "reason": resp["reason"],
            })
    else:
        results.append({"test": "toll_fraud",
                        "verdict": "no_response",
                        "error": err})
    return risk


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
            "legal_note": ("SIP probing / toll fraud on production PBX is "
                           "illegal (FR Art. 313-1 / US 18 USC §1343). Lab only."),
        }))
        sys.exit(1)

    t0 = time.time()
    results: List[Dict] = []
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "sip_port": PORT,
        "sector": get_sector_config().get("sector", "telecom"),
        "safe_mode": SAFE_MODE,
        "read_only": SAFE_MODE != "full",
        "seed": SEED,
        # Spec-required output fields:
        "sip_responsive": False,
        "auth_required": None,
        "toll_fraud_risk": False,
        "digest_replay_vulnerable": False,
        "enum_tested": False,
        "results": results,
        "errors": [],
    }

    # ─── 1. OPTIONS ping ───────────────────────────────────────────────────
    try:
        summary["sip_responsive"] = test_options_ping(HOST, PORT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"options_ping:{type(e).__name__}:{e}")

    # ─── 2. REGISTER with fake credentials ────────────────────────────────
    www_auth: Optional[Dict] = None
    try:
        auth_req, www_auth = test_register_auth(HOST, PORT, results)
        summary["auth_required"] = auth_req
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"register_auth:{type(e).__name__}:{e}")

    # ─── 3. ENUM lookup ───────────────────────────────────────────────────
    try:
        summary["enum_tested"] = test_enum_lookup(TEST_E164, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"enum_lookup:{type(e).__name__}:{e}")

    # ─── 4. Digest replay ─────────────────────────────────────────────────
    try:
        summary["digest_replay_vulnerable"] = test_digest_replay(
            HOST, PORT, www_auth, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"digest_replay:{type(e).__name__}:{e}")

    # ─── 5. INVITE flooding (informational rate-limit check) ──────────────
    try:
        test_invite_flooding(HOST, PORT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"invite_flooding:{type(e).__name__}:{e}")

    # ─── 6. Toll fraud (SAFE_MODE=full only) ──────────────────────────────
    try:
        summary["toll_fraud_risk"] = test_toll_fraud(HOST, PORT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"toll_fraud:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
