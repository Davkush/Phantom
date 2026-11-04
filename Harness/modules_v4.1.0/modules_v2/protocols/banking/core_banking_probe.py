#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — protocol probe : Core Banking APIs (T24/Finastra).
# Secteur : banking — SAFE_MODE=read_only (pas d'écriture sur core banking).
#
#   - v3.1 : probe endpoints REST/SOAP caractéristiques T24 (port 9080) et
#            Finastra Fusion (port 8443) — auto-detect via vendor fingerprints
#   - v3.1 : GET /api/accounts, /api/transfers, /api/balances → check existence
#   - v3.1 : check authentication (OAuth, session, basic auth) via 401/403 detection
#   - v3.1 : test transfer endpoint existence (READ_ONLY : POST with invalid body,
#            never an actual transfer — 400/422 = endpoint exists, 404 = absent)
#   - v3.1 : race condition indicator detection (concurrent OPTIONS, idempotency
#            header check) — NEVER real double-spend in read-only
#   - v3.1 : detect vendor from HTTP headers, error messages, HTML
#   - v3.1 : SEED reproducibility, LAB=1 guard, timeout 5s
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# DORA / PCI-DSS / PSD2 — aucune écriture sur core banking en read-only.
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print(json.dumps({
        "module": "core_banking_probe",
        "harness_version": "3.1.0",
        "error": "requests_not_installed",
        "hint": "pip install requests urllib3",
    }))
    sys.exit(2)

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "core_banking_probe"
DEFAULT_PORT = 443              # Core banking REST/SOAP (HTTPS)
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
# Usage: core_banking_probe.py <host> [port] [scheme]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
TARGET_SCHEME = sys.argv[3] if len(sys.argv) > 3 else "https"


def _base_url() -> str:
    return f"{TARGET_SCHEME}://{TARGET_HOST}:{TARGET_PORT}"


# ─── Sessions HTTP ────────────────────────────────────────────────────────────
def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME}) seed={SEED}",
        "Accept": "application/json, application/xml, text/html, */*",
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


def _safe_post(session: requests.Session, path: str, body: dict,
               content_type: str = "application/json") -> dict:
    url = path if path.startswith("http") else _base_url() + path
    t0 = time.time()
    try:
        r = session.post(url, json=body, timeout=REQUEST_TIMEOUT, verify=False,
                         allow_redirects=False,
                         headers={"Content-Type": content_type})
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


def _safe_options(session: requests.Session, path: str) -> dict:
    url = path if path.startswith("http") else _base_url() + path
    t0 = time.time()
    try:
        r = session.options(url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=False)
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


# ─── Endpoint map par vendor ─────────────────────────────────────────────────
VENDOR_ENDPOINTS = [
    # Temenos T24 (port 9080 jBase)
    ("temenos_t24", "/BrowserServlet",          "T24 BrowserServlet"),
    ("temenos_t24", "/TAFJRESTServer",          "T24 TAFJ REST"),
    ("temenos_t24", "/TAFJRESTServer/rest/",    "T24 TAFJ REST root"),
    ("temenos_t24", "/t24/irns/",               "T24 IRNS"),
    # Finastra Fusion (port 8443)
    ("finastra",    "/fusionfabric",            "Finastra FusionFabric"),
    ("finastra",    "/FusionRetailBanking",     "Finastra Fusion Retail Banking"),
    ("finastra",    "/fusiondeveloperkit",      "Finastra FDK"),
    ("finastra",    "/fusionconnect",           "Finastra FusionConnect"),
    # SAP Banking
    ("sap_banking", "/sap/bc/aba/ocn/",         "SAP Banking OCN"),
    ("sap_banking", "/sap/bc/soap/wsdl/",       "SAP SOAP WSDL"),
    ("sap_banking", "/sap/opu/odata/sap/",      "SAP Gateway OData"),
    # FIServ / Signature
    ("fiserv",      "/signature/api/",          "Fiserv Signature API"),
    ("fiserv",      "/dna/",                    "Fiserv DNA"),
    # Jack Henry
    ("jack_henry",  "/jha/silverlake/",         "Jack Henry SilverLake"),
    ("jack_henry",  "/episys/",                 "Jack Henry Episys"),
    # Finacle (Infosys)
    ("finacle",     "/finacle/",                "Infosys Finacle"),
    # Oracle FLEXCUBE
    ("flexcube",    "/fc10/",                   "Oracle FLEXCUBE"),
    ("flexcube",    "/FLEXCUBE/",               "Oracle FLEXCUBE UBS"),
]

VENDOR_BODY_PATTERNS = [
    (re.compile(rb"Temenos|T24|jBASE|TAFC|TAFJ", re.I),       "temenos_t24"),
    (re.compile(rb"Finastra|Fusion(?:Fabric|Retail|Connect)", re.I), "finastra"),
    (re.compile(rb"SAP\b|NetWeaver|SAP_Banking|aba/ocn", re.I), "sap_banking"),
    (re.compile(rb"Fiserv|Signature|DNA\b", re.I),             "fiserv"),
    (re.compile(rb"Jack\s*Henry|SilverLake|Episys", re.I),     "jack_henry"),
    (re.compile(rb"Finacle|Infosys", re.I),                    "finacle"),
    (re.compile(rb"FLEXCUBE|Oracle\s*Financial", re.I),        "flexcube"),
]


# ─── 1. Detect vendor ────────────────────────────────────────────────────────
def detect_vendor(session: requests.Session) -> dict:
    """Probe endpoints caractéristiques pour identifier le vendor."""
    endpoints = []
    vendor_hits: dict[str, list[str]] = {}
    body_vendor: Optional[str] = None

    for vendor, path, label in VENDOR_ENDPOINTS:
        r = _safe_get(session, path)
        # 404 = absent ; 401/403 = existe mais auth requise ; 200 = accessible
        found = (
            r["error"] is None
            and r["status"] is not None
            and r["status"] < 500
            and r["status"] != 404
        )
        endpoints.append({
            "vendor": vendor,
            "endpoint": path,
            "label": label,
            "status": r["status"],
            "len": r["len"],
            "ms": r["ms"],
            "found": found,
            "error": r["error"],
        })
        if found:
            vendor_hits.setdefault(vendor, []).append(path)
        if body_vendor is None and r["error"] is None and r["body"]:
            scan = (r["body"] or b"") + json.dumps(r["headers"]).encode("ascii", "ignore")
            for pat, vname in VENDOR_BODY_PATTERNS:
                if pat.search(scan):
                    body_vendor = vname
                    break

    detected_vendor = body_vendor
    if detected_vendor is None and vendor_hits:
        detected_vendor = max(vendor_hits.items(), key=lambda kv: len(kv[1]))[0]

    return {
        "detected_vendor": detected_vendor,
        "vendor_hits": {v: paths for v, paths in vendor_hits.items()},
        "body_vendor": body_vendor,
        "endpoints": endpoints,
        "tested": len(VENDOR_ENDPOINTS),
        "found_count": sum(1 for e in endpoints if e["found"]),
    }


# ─── 2. Check API paths + authentication ──────────────────────────────────────
def check_api_paths(session: requests.Session) -> dict:
    """GET /api/accounts, /api/transfers, /api/balances → check existence + auth.
    Teste aussi quelques variants (/api/v1/..., /rest/...).
    Pour chaque path : verdict (open_no_auth / auth_required / not_found / error)."""
    paths = [
        "/api/accounts",
        "/api/v1/accounts",
        "/rest/accounts",
        "/api/transfers",
        "/api/v1/transfers",
        "/rest/transfers",
        "/api/balances",
        "/api/v1/balances",
        "/rest/balances",
        "/oauth/token",
        "/api/health",
        "/health",
        "/api/customers",
    ]
    results = []
    auth_required_count = 0
    open_no_auth_count = 0
    endpoints_found = []

    for path in paths:
        r = _safe_get(session, path)
        if r["error"] is not None or r["status"] is None:
            results.append({
                "endpoint": path,
                "status": r["status"],
                "error": r["error"],
                "verdict": "error",
            })
            continue
        status = r["status"]
        found = status < 500 and status != 404
        if status in (200, 204):
            verdict = "open_no_auth"
            open_no_auth_count += 1
            found = True
        elif status in (301, 302):
            verdict = "redirect"
        elif status in (401, 403, 407):
            verdict = "auth_required"
            auth_required_count += 1
            found = True
        elif status == 404:
            verdict = "not_found"
            found = False
        elif status == 405:
            verdict = "method_not_allowed"
            found = True
        else:
            verdict = f"http_{status}"
            found = status < 500
        if found:
            endpoints_found.append(path)
        results.append({
            "endpoint": path,
            "status": status,
            "len": r["len"],
            "ms": r["ms"],
            "found": found,
            "verdict": verdict,
            "error": None,
        })

    return {
        "tested": len(results),
        "auth_required_count": auth_required_count,
        "open_no_auth_count": open_no_auth_count,
        "auth_required": auth_required_count > 0,
        "any_open": open_no_auth_count > 0,
        "endpoints_found": endpoints_found,
        "results": results,
    }


# ─── 3. Test transfer endpoint (READ_ONLY : invalid POST, never real transfer) ─
def test_transfer_endpoint(session: requests.Session, safe_mode: str) -> dict:
    """Test transfer endpoint existence WITHOUT performing a transfer.

    READ_ONLY strategy : POST /api/transfers with a deliberately INVALID body
    (negative amount + missing required fields). The endpoint will respond:
      - 400 / 422 = endpoint exists, validation rejected the payload (we learn
        that transfers are accepted by the API but protected by schema validation)
      - 404 = endpoint absent
      - 401 / 403 = endpoint exists but auth required (good hygiene)
      - 200 / 201 = CRITICAL — endpoint accepted an invalid transfer (no
        validation) → would also accept a real fraudulent transfer

    NB: This is the closest we can get to "test transfer API with dummy data"
    while remaining READ-ONLY. No real money movement is initiated because the
    payload is structurally invalid (negative amount).
    """
    # Payload intentionally invalid : negative amount + dummy accounts + missing
    # required fields (currency, reference). Un nœud core banking avec validation
    # de schéma DOIT rejeter avec 400/422. Un nœud sans validation pourrait
    # accepter silencieusement (CRITICAL).
    invalid_payload = {
        "from_account": "HARNESS_INVALID_LAB_DO_NOT_PROCESS",
        "to_account":   "HARNESS_INVALID_LAB_DO_NOT_PROCESS",
        "amount":       "-0.01",          # negative → must be rejected
        "currency":     "",               # empty → must be rejected
        "reference":    "",               # empty → must be rejected
        "harness_lab":  True,             # explicit lab marker for SIEM filtering
        "harness_dry_run": True,          # explicit dry-run intent
        "harness_seed": SEED,
    }
    r = _safe_post(session, "/api/transfers", invalid_payload)
    result = {
        "endpoint": "/api/transfers",
        "method": "POST",
        "payload_strategy": "deliberately_invalid (negative amount + missing fields)",
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "error": r["error"],
        "read_only": True,
        "safe_mode": safe_mode,
        "note": (
            "READ-ONLY: payload is structurally invalid (negative amount, missing "
            "currency). No real transfer can be created even if the endpoint "
            "accepts it — but acceptance itself indicates missing validation."
        ),
    }
    if r["error"] is None and r["status"] is not None:
        if r["status"] in (400, 422):
            result["endpoint_found"] = True
            result["transfer_tested"] = True
            result["validation_present"] = True
            result["severity"] = "info"
        elif r["status"] in (401, 403, 407):
            result["endpoint_found"] = True
            result["transfer_tested"] = True
            result["validation_present"] = None  # auth wall blocks validation check
            result["severity"] = "info"
        elif r["status"] in (404, 405):
            result["endpoint_found"] = False
            result["transfer_tested"] = False
            result["validation_present"] = None
            result["severity"] = "info"
        elif r["status"] in (200, 201):
            # CRITICAL: server accepted an invalid transfer
            result["endpoint_found"] = True
            result["transfer_tested"] = True
            result["validation_present"] = False
            result["severity"] = "critical"
            result["note_critical"] = (
                "Server accepted POST with negative amount + missing required "
                "fields. Schema validation is absent — a real fraudulent transfer "
                "would also be accepted. This is the core banking equivalent of "
                "the Bangladesh Bank 2016 vector (no validation on MT103 amounts)."
            )
        else:
            result["endpoint_found"] = r["status"] < 500
            result["transfer_tested"] = r["status"] < 500
            result["validation_present"] = None
            result["severity"] = "info"
    else:
        result["endpoint_found"] = False
        result["transfer_tested"] = False
        result["validation_present"] = None
        result["severity"] = "info"
    # Body preview for context (truncated, no PII expected from an error)
    if r["body"]:
        try:
            result["body_preview"] = r["body"][:300].decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            result["body_preview"] = r["body"][:300].hex()
    else:
        result["body_preview"] = ""
    return result


# ─── 4. Race condition indicator detection ────────────────────────────────────
def check_race_condition_indicator(session: requests.Session, safe_mode: str) -> dict:
    """Detect race condition protection on /api/transfers WITHOUT sending real
    transfers. We use two complementary read-only techniques:

    1) OPTIONS /api/transfers → check for idempotency / rate-limit headers.
       Idempotency-Key header support = strong indicator of race protection
       (RFC: Idempotency-Key is the standard way to make POST safe to retry).
       Rate-limit headers (Retry-After, X-RateLimit-*) = good hygiene signal.

    2) Concurrent OPTIONS x3 to the SAME endpoint → if responses show
       X-RateLimit-Remaining decreasing, the rate-limiter is per-token and
       would also apply to POSTs (so concurrent POSTs would be serialized).
       If no rate-limiting on OPTIONS, race protection probably absent on POST too.

    We NEVER send concurrent POST /api/transfers in read-only mode (would create
    real transfers). Only OPTIONS (read-only metadata) and header inspection.
    """
    indicators: dict = {
        "idempotency_key_required": False,
        "rate_limit_headers_present": False,
        "rate_limit_remaining_decreases": False,
        "concurrent_options_serialized": False,
    }
    rate_headers_seen = set()

    # Phase A : single OPTIONS → header inspection
    r = _safe_options(session, "/api/transfers")
    if r["error"] is None and r["headers"]:
        for h in r["headers"]:
            hl = h.lower()
            if "idempotency" in hl:
                indicators["idempotency_key_required"] = True
            if "rate" in hl or "limit" in hl or "retry" in hl or "throttle" in hl:
                indicators["rate_limit_headers_present"] = True
                rate_headers_seen.add(hl)
        # If server advertises Idempotency-Key requirement in 405/Allow header
        allow = r["headers"].get("Allow", "") + " " + r["headers"].get("accept", "")
        if "Idempotency" in allow or "idempotency" in allow.lower():
            indicators["idempotency_key_required"] = True

    # Phase B : concurrent OPTIONS x3 → check X-RateLimit-Remaining decay
    remaining_values: list[int] = []
    lock = threading.Lock()
    statuses: list[int] = []

    def _do_options(idx: int) -> dict:
        rr = _safe_options(session, "/api/transfers")
        rem = None
        if rr["headers"]:
            for h, v in rr["headers"].items():
                if h.lower() in ("x-ratelimit-remaining", "ratelimit-remaining"):
                    try:
                        rem = int(str(v))
                    except ValueError:
                        pass
        return {"idx": idx, "status": rr["status"], "remaining": rem}

    # Only do concurrent burst if OPTIONS returned something (avoid noise)
    if r["error"] is None and r["status"] is not None and r["status"] < 500:
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = [ex.submit(_do_options, i) for i in range(3)]
            for fut in as_completed(futures):
                with lock:
                    res = fut.result()
                    statuses.append(res["status"])
                    if res["remaining"] is not None:
                        remaining_values.append(res["remaining"])

    if len(remaining_values) >= 2:
        # If remaining decreases between calls → rate-limiter is active per-token
        if remaining_values[0] > remaining_values[-1]:
            indicators["rate_limit_remaining_decreases"] = True
            indicators["concurrent_options_serialized"] = True

    # Verdict : race condition vulnerable = no indicator of protection
    any_protection = any(indicators.values())
    race_vulnerable = None if r["status"] in (404, None) else (not any_protection)

    return {
        "endpoint": "/api/transfers",
        "method": "OPTIONS",
        "concurrent_attempts": 3,
        "rate_headers_seen": sorted(rate_headers_seen),
        "statuses": sorted(statuses),
        "indicators": indicators,
        "race_condition_vulnerable": race_vulnerable,
        "severity": "high" if race_vulnerable is True else (
            "info" if race_vulnerable is False else "info"
        ),
        "note": (
            "READ-ONLY: only OPTIONS + header inspection. No concurrent POST "
            "in read-only mode (would create real transfers). Verdict is an "
            "INDICATOR based on hygiene signals (idempotency-key, rate-limit) — "
            "not a definitive race-condition test. For definitive test, run "
            "with SAFE_MODE=full + LAB=1 (lab isolated, dedicated test account)."
        ),
        "safe_mode": safe_mode,
    }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # SAFE_MODE read-only : tous les checks sont compatibles :
    #   - detect_vendor : GET only
    #   - check_api_paths : GET only
    #   - test_transfer_endpoint : POST with INVALID payload (negative amount)
    #     → read-only by construction (no real transfer can be created)
    #   - check_race_condition_indicator : OPTIONS only (no POST)
    session = build_session()

    # Phase 1 : detect vendor
    vendor_check = detect_vendor(session)

    # Phase 2 : check API paths + auth
    api_check = check_api_paths(session)

    # Phase 3 : test transfer endpoint (invalid payload, read-only)
    transfer_check = test_transfer_endpoint(session, safe_mode)

    # Phase 4 : race condition indicator (OPTIONS + headers)
    race_check = check_race_condition_indicator(session, safe_mode)

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
            "scheme": TARGET_SCHEME,
        },
        "regulations": list(get_sector_config().get("regulations", [])),
        "read_only": safe_mode == "read_only",
        "results": {
            "vendor_detection": vendor_check,
            "api_paths_check": api_check,
            "transfer_endpoint_test": transfer_check,
            "race_condition_indicator": race_check,
        },
        "summary": {
            "vendor_detected": vendor_check.get("detected_vendor"),
            "transfer_tested": transfer_check.get("transfer_tested", False),
            "auth_required": api_check.get("auth_required", False),
            "race_condition_vulnerable": race_check.get("race_condition_vulnerable"),
            "endpoints_found": api_check.get("endpoints_found", []),
        },
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
