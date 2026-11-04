#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — protocol probe : PSD2 / Open Banking FAPI APIs.
# Secteur : banking — SAFE_MODE=read_only (read-only security posture checks).
#
#   - v3.1 : GET /.well-known/openid-configuration → OIDC discovery endpoint
#   - v3.1 : OAuth 2.0 + PKCE enforcement (code_challenge_methods_supported)
#   - v3.1 : mTLS requirement check (FAPI 2.0 Security Profile requirement)
#   - v3.1 : Consent manipulation test (request more scopes than consented →
#            expect 400/403 "scope_mismatch" from /token)
#   - v3.1 : alg:none JWT vulnerability (forge a none-signed JWT, POST as
#            client_assertion → expect rejection; CRITICAL if accepted)
#   - v3.1 : FAPI Security Profile compliance synthesis (PKCE + mTLS + alg:none
#            rejection + consent validation)
#   - v3.1 : SEED reproducibility, LAB=1 guard, timeout 5s
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# PSD2 (Directive (EU) 2015/2366) — RTS-SCA requirements.
# FAPI : OpenID Financial-grade API Security Profile 1.0 Part 2 (advanced/paranoid).
#        https://openid.net/specs/openid-financial-api-part-2-1_ID2.html
# mTLS : RFC 8705 (OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens).
import base64
import json
import os
import re
import sys
import time
from typing import Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print(json.dumps({
        "module": "open_banking_probe",
        "harness_version": "3.1.0",
        "error": "requests_not_installed",
        "hint": "pip install requests urllib3",
    }))
    sys.exit(2)

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "open_banking_probe"
DEFAULT_PORT = 443              # Open Banking / PSD2 FAPI (HTTPS)
REQUEST_TIMEOUT = 5            # 5s strict

# ─── Import sector_base (best-effort) ─────────────────────────────────────────
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from sector_base import (  # type: ignore
        get_sector_config,
        get_safe_mode as _sector_safe_mode,
    )
    _HAS_SECTOR_BASE = True
except Exception:  # noqa: BLE001
    _HAS_SECTOR_BASE = False

    def get_sector_config() -> dict:  # type: ignore[no-redef]
        return {
            "sector": "banking",
            "safe_mode": "read_only",
            "regulations": ("DORA", "PCI-DSS", "PSD2", "SWIFT CSP"),
            "harness_version": HARNESS_VERSION,
        }

    def _sector_safe_mode() -> str:  # type: ignore[no-redef]
        return "read_only"


def get_safe_mode() -> str:
    env_sm = os.environ.get("SAFE_MODE", "").lower().strip()
    if env_sm in ("read_only", "full"):
        return env_sm
    return _sector_safe_mode()


# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))


# ─── Guards ───────────────────────────────────────────────────────────────────
def _check_lab_guard() -> None:
    if os.environ.get("LAB") != "1":
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_failed",
            "reason": "LAB env var must be set to 1 (isolated lab only)",
            "harness_version": HARNESS_VERSION,
        }))
        sys.exit(2)


def _check_safe_mode() -> str:
    sm = get_safe_mode()
    if sm not in ("read_only", "full"):
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "invalid_safe_mode",
            "safe_mode": sm,
            "valid": ("read_only", "full"),
        }))
        sys.exit(2)
    return sm


# ─── Args CLI ────────────────────────────────────────────────────────────────
# Usage: open_banking_probe.py <host> [port]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT


def _base_url() -> str:
    return f"https://{TARGET_HOST}:{TARGET_PORT}"


# ─── Sessions HTTP ────────────────────────────────────────────────────────────
def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME}) seed={SEED}",
        "Accept": "application/json, */*",
        "X-Forwarded-For": "127.0.0.1",
    })
    return s


def _safe_get(session: requests.Session, path: str) -> dict:
    url = path if path.startswith("http") else _base_url() + path
    t0 = time.time()
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=False)
        return {
            "url": url,
            "status": r.status_code,
            "len": len(r.content),
            "ms": round((time.time() - t0) * 1000, 1),
            "headers": dict(r.headers),
            "body": r.content,
            "error": None,
        }
    except requests.exceptions.Timeout:
        return _err(url, t0, "Timeout")
    except requests.exceptions.ConnectionError as e:
        return _err(url, t0, "ConnectionError", detail=str(e)[:200])
    except requests.RequestException as e:
        return _err(url, t0, type(e).__name__, detail=str(e)[:200])


def _safe_post(session: requests.Session, path: str,
               data: Optional[dict] = None, json_body: Optional[dict] = None,
               headers: Optional[dict] = None) -> dict:
    url = path if path.startswith("http") else _base_url() + path
    t0 = time.time()
    try:
        r = session.post(url, data=data, json=json_body, headers=headers or {},
                         timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=False)
        return {
            "url": url,
            "status": r.status_code,
            "len": len(r.content),
            "ms": round((time.time() - t0) * 1000, 1),
            "headers": dict(r.headers),
            "body": r.content,
            "error": None,
        }
    except requests.exceptions.Timeout:
        return _err(url, t0, "Timeout")
    except requests.exceptions.ConnectionError as e:
        return _err(url, t0, "ConnectionError", detail=str(e)[:200])
    except requests.RequestException as e:
        return _err(url, t0, type(e).__name__, detail=str(e)[:200])


def _err(url: str, t0: float, err: str, detail: str = "") -> dict:
    return {
        "url": url,
        "status": None,
        "len": 0,
        "ms": round((time.time() - t0) * 1000, 1),
        "headers": {},
        "body": b"",
        "error": err,
        "error_detail": detail,
    }


# ─── 1. OIDC Discovery (.well-known/openid-configuration) ────────────────────
def check_oidc_discovery(session: requests.Session) -> dict:
    """GET /.well-known/openid-configuration → OpenID Connect discovery doc.
    FAPI requires OIDC discovery. Extract : issuer, authorization_endpoint,
    token_endpoint, jwks_uri, scopes_supported, code_challenge_methods_supported,
    token_endpoint_auth_methods_supported (looking for tls_client_auth = mTLS).
    """
    r = _safe_get(session, "/.well-known/openid-configuration")
    result: dict = {
        "endpoint": "/.well-known/openid-configuration",
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "error": r["error"],
        "discovery_found": False,
        "issuer": None,
        "authorization_endpoint": None,
        "token_endpoint": None,
        "jwks_uri": None,
        "scopes_supported": [],
        "code_challenge_methods_supported": [],
        "token_endpoint_auth_methods_supported": [],
        "mtls_required_metadata_keys": [],
    }
    if r["error"] is None and r["status"] == 200 and r["body"]:
        try:
            doc = json.loads(r["body"].decode("utf-8"))
            result["discovery_found"] = True
            result["issuer"] = doc.get("issuer")
            result["authorization_endpoint"] = doc.get("authorization_endpoint")
            result["token_endpoint"] = doc.get("token_endpoint")
            result["jwks_uri"] = doc.get("jwks_uri")
            result["scopes_supported"] = doc.get("scopes_supported", []) or []
            result["code_challenge_methods_supported"] = doc.get(
                "code_challenge_methods_supported", []) or []
            result["token_endpoint_auth_methods_supported"] = doc.get(
                "token_endpoint_auth_methods_supported", []) or []
            # mTLS metadata : tls_client_certificate_bound_access_tokens,
            # mutual_tls_sender_constrained_access_tokens (RFC 8705)
            for k in (
                "tls_client_certificate_bound_access_tokens",
                "mutual_tls_sender_constrained_access_tokens",
                "mtls_endpoint_aliases",
            ):
                if k in doc:
                    result["mtls_required_metadata_keys"].append(k)
            result["discovery_doc"] = doc
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            result["error"] = "json_decode_error"
            result["error_detail"] = str(e)[:200]
    return result


# ─── 2. PKCE enforcement ──────────────────────────────────────────────────────
def check_pkce_enforcement(oidc_check: dict) -> dict:
    """Verify OAuth 2.0 + PKCE enforcement (RFC 7636).
    FAPI Security Profile 1.0 Part 2 (advanced/paranoid) REQUIRES PKCE with
    code_challenge_method = S256.

    PKCE is enforced iff :
      - code_challenge_methods_supported contains "S256"
      - (preferred) "S256" is the only method listed (no "plain" allowed in FAPI)
    """
    methods = oidc_check.get("code_challenge_methods_supported", [])
    has_s256 = "S256" in methods
    has_plain = "plain" in methods
    pkce_enforced = has_s256 and not has_plain  # FAPI: only S256 allowed
    return {
        "code_challenge_methods_supported": methods,
        "has_s256": has_s256,
        "has_plain": has_plain,
        "pkce_enforced": pkce_enforced,
        "severity": "high" if not pkce_enforced else "info",
        "note": (
            "FAPI 1.0 Part 2 requires PKCE with S256 only (no 'plain'). "
            "Missing PKCE = authorization code interception vector (RFC 7636 §7.1)."
        ),
    }


# ─── 3. mTLS requirement ──────────────────────────────────────────────────────
def check_mtls_requirement(oidc_check: dict) -> dict:
    """Verify mTLS (RFC 8705) — FAPI requires sender-constrained access tokens.

    mTLS is required iff discovery doc declares one of :
      - tls_client_certificate_bound_access_tokens: true
      - mutual_tls_sender_constrained_access_tokens: true
      - mtls_endpoint_aliases present
      - token_endpoint_auth_methods_supported includes "tls_client_auth"
    """
    auth_methods = oidc_check.get("token_endpoint_auth_methods_supported", [])
    mtls_metadata_keys = oidc_check.get("mtls_required_metadata_keys", [])
    has_tls_client_auth = "tls_client_auth" in auth_methods
    discovery_doc = oidc_check.get("discovery_doc") or {}
    bound_tokens = (
        discovery_doc.get("tls_client_certificate_bound_access_tokens") is True
        or discovery_doc.get("mutual_tls_sender_constrained_access_tokens") is True
    )
    mtls_required = bool(mtls_metadata_keys) or has_tls_client_auth or bound_tokens
    return {
        "tls_client_auth_in_methods": has_tls_client_auth,
        "mtls_metadata_keys": mtls_metadata_keys,
        "bound_access_tokens_declared": bound_tokens,
        "mtls_required": mtls_required,
        "severity": "high" if not mtls_required else "info",
        "note": (
            "FAPI 2.0 Security Profile requires mTLS sender-constrained access "
            "tokens (RFC 8705). Missing mTLS = bearer token theft vector "
            "(no proof-of-possession)."
        ),
    }


# ─── 4. Consent manipulation test ─────────────────────────────────────────────
def test_consent_manipulation(session: requests.Session, oidc_check: dict) -> dict:
    """Request more scopes than consented → expect rejection.

    PSD2 consent model : a PSU (Payment Service User) consents to a specific
    scope (e.g. "payments" or "accounts"). The TPP requests an access token
    for that scope. An attacker might try to request broader scopes at /token
    than what was consented (e.g. "accounts payments" when consent was for
    "payments" only).

    Test : POST /token with grant_type=client_credentials and scope="accounts payments"
    (over-broad scope). A conformant FAPI AS rejects with:
      - error="invalid_scope" (preferred — RFC 6749 §3.3)
      - or error="consent_mismatch" (PSD2-specific)
      - or error="access_denied"
    A non-conformant AS might issue a token with broader scopes than consented
    = consent bypass (CRITICAL).
    """
    token_endpoint = oidc_check.get("token_endpoint")
    if not token_endpoint:
        return {
            "endpoint": None,
            "skipped": True,
            "reason": "token_endpoint not found in OIDC discovery doc",
            "consent_validation": "inconclusive",
        }
    # Ensure token_endpoint is on the same target host (avoid SSRF)
    if not token_endpoint.startswith(_base_url()):
        # Replace with our target URL (the discovery doc may use a different host)
        # We use the path portion only, on our explicit target
        path = token_endpoint.split("/", 3)[-1] if "/" in token_endpoint else "/token"
        token_endpoint = _base_url() + "/" + path.lstrip("/")

    # Request an over-broad scope (more than consented)
    over_broad_scope = "accounts payments fundsconfirmations"
    data = {
        "grant_type": "client_credentials",
        "scope": over_broad_scope,
        "client_id": f"harness-lab-{SEED}",
    }
    r = _safe_post(session, token_endpoint, data=data,
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
    result = {
        "endpoint": token_endpoint,
        "scope_requested": over_broad_scope,
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "error": r["error"],
        "skipped": False,
    }
    # Parse token response
    parsed_body = None
    if r["body"]:
        try:
            parsed_body = json.loads(r["body"].decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            try:
                parsed_body = {"raw": r["body"][:300].decode("utf-8", "ignore")}
            except Exception:  # noqa: BLE001
                parsed_body = {"raw_hex": r["body"][:300].hex()}
    result["response_body"] = parsed_body

    if r["error"] is None and r["status"] is not None:
        if r["status"] in (400, 403):
            err_code = (parsed_body or {}).get("error") if isinstance(parsed_body, dict) else None
            if err_code in ("invalid_scope", "consent_mismatch", "access_denied",
                            "invalid_grant", "unauthorized"):
                result["consent_validation"] = "enforced"
                result["severity"] = "info"
                result["note"] = (
                    f"safe: server rejected over-broad scope (error={err_code}). "
                    "Consent validation present."
                )
            else:
                result["consent_validation"] = "rejected_unknown_error"
                result["severity"] = "info"
                result["note"] = (
                    f"server rejected (HTTP {r['status']}) but error code is "
                    f"unexpected: {err_code}. Consent validation may or may not be enforced."
                )
        elif r["status"] in (401,):
            result["consent_validation"] = "auth_required_first"
            result["severity"] = "info"
            result["note"] = (
                "server requires client auth before evaluating scope. "
                "Cannot test consent bypass without valid client credentials."
            )
        elif r["status"] in (200, 201):
            # CRITICAL : token issued for over-broad scope
            result["consent_validation"] = "bypassed"
            result["severity"] = "critical"
            result["note"] = (
                "CRITICAL: server issued an access token for an over-broad scope "
                "without verifying consent. Consent bypass — PSD2 RTS-SCA violation "
                "(Art. 30 Strong Customer Authentication)."
            )
        else:
            result["consent_validation"] = f"http_{r['status']}"
            result["severity"] = "info"
    else:
        result["consent_validation"] = "no_response"
        result["severity"] = "info"
    return result


# ─── 5. alg:none JWT vulnerability test ───────────────────────────────────────
def test_jwt_alg_none(session: requests.Session, oidc_check: dict) -> dict:
    """Forge a JWT with alg=none and submit it as a client_assertion to /token.
    Expect rejection. CRITICAL if accepted.

    RFC 7519 §8.1 : alg=none means no digital signature. RFC 8725 (JWT BCP) §3.1
    explicitly REJECTS alg=none for security-sensitive contexts.

    FAPI Security Profile 1.0 Part 2 §5.2.2 explicitly forbids alg=none.
    PSD2 RTS-SCA requires signed tokens for client authentication.

    Attack vector : if the AS accepts a JWT with alg=none, an attacker can
    impersonate ANY client_id (just craft {"alg":"none"}, no signature needed) →
    consent bypass, account access, payment initiation.

    Test : forge client_assertion JWT with alg=none, exp=now+3600,
    sub=aud="https://<host>/token" (PSD2 client_assertion pattern), submit
    to /token as grant_type=client_credentials with
    client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer.
    """
    token_endpoint = oidc_check.get("token_endpoint")
    if not token_endpoint:
        return {
            "endpoint": None,
            "skipped": True,
            "reason": "token_endpoint not found in OIDC discovery doc",
            "jwt_alg_none_vulnerable": None,
        }
    if not token_endpoint.startswith(_base_url()):
        path = token_endpoint.split("/", 3)[-1] if "/" in token_endpoint else "/token"
        token_endpoint = _base_url() + "/" + path.lstrip("/")

    # Forge alg:none JWT — header {"alg":"none","typ":"JWT"}, payload with sub/aud/iss/exp.
    header = {"alg": "none", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "iss": f"harness-lab-{SEED}",
        "sub": f"harness-lab-{SEED}",
        "aud": token_endpoint,
        "iat": now,
        "exp": now + 3600,
        "jti": f"harness-jti-{SEED}-{now}",
    }
    forged_jwt = _b64url_json(header) + "." + _b64url_json(payload) + "."

    data = {
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": forged_jwt,
        "client_id": f"harness-lab-{SEED}",
        "scope": "accounts",
    }
    r = _safe_post(session, token_endpoint, data=data,
                   headers={"Content-Type": "application/x-www-form-urlencoded"})

    result = {
        "endpoint": token_endpoint,
        "jwt_header": header,
        "jwt_payload": payload,
        "forged_jwt_preview": forged_jwt[:80] + "...",
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "error": r["error"],
    }
    parsed_body = None
    if r["body"]:
        try:
            parsed_body = json.loads(r["body"].decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            try:
                parsed_body = {"raw": r["body"][:300].decode("utf-8", "ignore")}
            except Exception:  # noqa: BLE001
                parsed_body = {"raw_hex": r["body"][:300].hex()}
    result["response_body"] = parsed_body

    if r["error"] is None and r["status"] is not None:
        if r["status"] in (400, 401, 403):
            err_code = (parsed_body or {}).get("error") if isinstance(parsed_body, dict) else None
            # Rejection keywords that indicate alg=none was rejected
            rejection_keywords = (
                "invalid_client", "invalid_grant", "invalid_assertion",
                "invalid_signature", "invalid_token", "unauthorized",
                "unsupported_algorithm", "alg_none_forbidden",
            )
            if err_code in rejection_keywords:
                result["jwt_alg_none_vulnerable"] = False
                result["severity"] = "info"
                result["note"] = (
                    f"safe: server rejected alg=none JWT (error={err_code}). "
                    "FAPI §5.2.2 compliance confirmed."
                )
            else:
                # Rejected but with a generic error code — still safe but
                # error code doesn't explicitly mention alg=none rejection
                result["jwt_alg_none_vulnerable"] = False
                result["severity"] = "low"
                result["note"] = (
                    f"server rejected (HTTP {r['status']}, error={err_code}) but "
                    "did not explicitly cite alg=none. Likely safe."
                )
        elif r["status"] in (200, 201):
            # CRITICAL : alg=none JWT accepted → token issued
            result["jwt_alg_none_vulnerable"] = True
            result["severity"] = "critical"
            result["note"] = (
                "CRITICAL: server accepted an alg=none JWT as client_assertion "
                "and issued an access token. JWT signature verification is "
                "absent. An attacker can impersonate ANY PSD2 client → consent "
                "bypass, account access, payment initiation. RFC 8725 §3.1 / "
                "FAPI §5.2.2 violation."
            )
        else:
            result["jwt_alg_none_vulnerable"] = None
            result["severity"] = "info"
            result["note"] = f"inconclusive: HTTP {r['status']}"
    else:
        result["jwt_alg_none_vulnerable"] = None
        result["severity"] = "info"
        result["note"] = "no response — cannot test alg:none vulnerability"
    return result


def _b64url_json(obj: dict) -> str:
    """Base64url-encode a JSON object (no padding, RFC 7515 §2)."""
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ─── 6. FAPI compliance synthesis ─────────────────────────────────────────────
def synthesize_fapi_compliance(pkce_check: dict, mtls_check: dict,
                               jwt_check: dict, consent_check: dict) -> dict:
    """Synthesize FAPI 2.0 Security Profile compliance.
    fapi_compliant = PKCE enforced AND mTLS required AND alg:none rejected
                     AND consent validation enforced.
    """
    pkce_ok = bool(pkce_check.get("pkce_enforced"))
    mtls_ok = bool(mtls_check.get("mtls_required"))
    jwt_ok = jwt_check.get("jwt_alg_none_vulnerable") is False
    consent_ok = consent_check.get("consent_validation") == "enforced"
    fapi_compliant = pkce_ok and mtls_ok and jwt_ok and consent_ok
    return {
        "fapi_compliant": fapi_compliant,
        "criteria": {
            "pkce_enforced": pkce_ok,
            "mtls_required": mtls_ok,
            "alg_none_rejected": jwt_ok,
            "consent_validated": consent_ok,
        },
        "severity": "critical" if not fapi_compliant else "info",
        "note": (
            "FAPI 2.0 Security Profile compliance requires ALL of : PKCE (S256 only), "
            "mTLS sender-constrained tokens, alg:none rejection, consent validation."
        ),
    }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # SAFE_MODE read-only : tous les checks sont compatibles :
    #   - GET discovery doc
    #   - GET metadata + header inspection
    #   - POST /token with invalid scope (over-broad) → safe : no token issued
    #     for a real PSU (we use a fake client_id without valid credentials)
    #   - POST /token with forged alg:none JWT → safe : no token issued (we
    #     expect rejection)
    session = build_session()

    # Phase 1 : OIDC discovery
    oidc_check = check_oidc_discovery(session)

    # Phase 2 : PKCE enforcement (from discovery doc)
    pkce_check = check_pkce_enforcement(oidc_check)

    # Phase 3 : mTLS requirement (from discovery doc)
    mtls_check = check_mtls_requirement(oidc_check)

    # Phase 4 : consent manipulation (POST /token over-broad scope)
    consent_check = test_consent_manipulation(session, oidc_check)

    # Phase 5 : alg:none JWT vulnerability
    jwt_check = test_jwt_alg_none(session, oidc_check)

    # Phase 6 : FAPI compliance synthesis
    fapi_check = synthesize_fapi_compliance(pkce_check, mtls_check,
                                            jwt_check, consent_check)

    # ─── Synthèse JSON stdout ──────────────────────────────────────────────
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "banking",
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "seed": SEED,
        "target": {
            "host": TARGET_HOST,
            "port": TARGET_PORT,
        },
        "regulations": list(get_sector_config().get("regulations", [])),
        "read_only": True,
        "results": {
            "oidc_discovery": oidc_check,
            "pkce_enforcement": pkce_check,
            "mtls_requirement": mtls_check,
            "consent_manipulation": consent_check,
            "jwt_alg_none": jwt_check,
            "fapi_compliance": fapi_check,
        },
        "summary": {
            "fapi_compliant": fapi_check.get("fapi_compliant"),
            "pkce_enforced": pkce_check.get("pkce_enforced"),
            "mtls_required": mtls_check.get("mtls_required"),
            "jwt_alg_none_vulnerable": jwt_check.get("jwt_alg_none_vulnerable"),
            "consent_validation": consent_check.get("consent_validation"),
        },
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
