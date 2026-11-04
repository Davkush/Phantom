#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — module bancaire : Core Banking API probe.
# Secteur: banking (SAFE_MODE=read_only — pas d'écriture sur core banking).
#
#   - v3.0 : détection vendor (Temenos T24, Finastra Fusion, SAP Banking, ...)
#   - v3.0 : probe endpoints REST/SOAP caractéristiques
#   - v3.0 : check_api_auth (open vs auth_required)
#   - v3.0 : check_data_enumeration (GET /api/accounts/{1..10})
#   - v3.0 : test_double_spend_race (POST concurrent) — ONLY si SAFE_MODE=full + LAB=1
#   - v3.0 : guard LAB=1 + SAFE_MODE=read_only + timeout 5s
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# DORA / PCI-DSS / PSD2 — aucune écriture sur core banking en read-only.
import json
import os
import re
import sys
import threading
import time
from typing import Optional

import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "core_banking_probe"
DEFAULT_PORT = 443              # Core banking REST/SOAP (HTTPS)
REQUEST_TIMEOUT = 5            # 5s strict (cf. spec harness)

# ─── Import sector_base (best-effort) ─────────────────────────────────────────
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from sector_base import (  # type: ignore
        get_sector_config,
        get_safe_mode as _sector_safe_mode,
        is_write_allowed,
        check_write_allowed,
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

    def is_write_allowed() -> bool:  # type: ignore[no-redef]
        return get_safe_mode() == "full"

    def check_write_allowed(module_name: str) -> None:  # type: ignore[no-redef]
        if not is_write_allowed():
            print(json.dumps({
                "module": module_name,
                "error": "write_not_allowed",
                "sector": "banking",
                "safe_mode": get_safe_mode(),
            }))
            sys.exit(3)


def get_safe_mode() -> str:
    """Effective SAFE_MODE: respect explicit env override (lab admin opt-in),
    otherwise fall back to sector_base default (read_only for banking).
    Banking default is read_only per SWIFT CSP / DORA — explicit SAFE_MODE=full
    is required to enable write tests (e.g., double_spend_race) AND only in LAB=1."""
    env_sm = os.environ.get("SAFE_MODE", "").lower().strip()
    if env_sm in ("read_only", "full"):
        return env_sm
    return _sector_safe_mode()


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
# Usage: core_banking_module.py <host> [port] [scheme]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
TARGET_SCHEME = sys.argv[3] if len(sys.argv) > 3 else "https"


def _base_url() -> str:
    return f"{TARGET_SCHEME}://{TARGET_HOST}:{TARGET_PORT}"


# ─── Sessions HTTP ────────────────────────────────────────────────────────────
def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME})",
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


def _safe_post(session: requests.Session, path: str, json_body: dict) -> dict:
    url = path if path.startswith("http") else _base_url() + path
    t0 = time.time()
    try:
        r = session.post(url, json=json_body, timeout=REQUEST_TIMEOUT, verify=False,
                         allow_redirects=False)
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
# (vendor, path, label, auth_check_hint)
VENDOR_ENDPOINTS = [
    # Temenos T24
    ("temenos_t24", "/BrowserServlet",          "T24 BrowserServlet"),
    ("temenos_t24", "/TAFJRESTServer",          "T24 TAFJ REST"),
    ("temenos_t24", "/TAFJRESTServer/rest/",    "T24 TAFJ REST root"),
    ("temenos_t24", "/t24/irns/",               "T24 IRNS"),
    ("temenos_t24", "/webservices",             "T24 Web Services"),
    # Finastra Fusion
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
    ("finacle",     "/finaclewebservice/",      "Finacle WS"),
    # Oracle FLEXCUBE
    ("flexcube",    "/fc10/",                   "Oracle FLEXCUBE"),
    ("flexcube",    "/FLEXCUBE/",               "Oracle FLEXCUBE UBS"),
]

# Patterns de fingerprint dans body/headers
VENDOR_BODY_PATTERNS = [
    (re.compile(rb"Temenos|T24|jBASE|TAFC|TAFJ", re.I),       "temenos_t24"),
    (re.compile(rb"Finastra|Fusion(?:Fabric|Retail|Connect)", re.I), "finastra"),
    (re.compile(rb"SAP\b|NetWeaver|SAP_Banking|aba/ocn", re.I), "sap_banking"),
    (re.compile(rb"Fiserv|Signature|DNA\b", re.I),             "fiserv"),
    (re.compile(rb"Jack\s*Henry|SilverLake|Episys", re.I),     "jack_henry"),
    (re.compile(rb"Finacle|Infosys", re.I),                    "finacle"),
    (re.compile(rb"FLEXCUBE|Oracle\s*Financial", re.I),        "flexcube"),
]

# Body patterns pour détection de "leak" de données client
ACCOUNT_LEAK_PATTERNS = [
    re.compile(rb"account[_-]?id", re.I),
    re.compile(rb"balance", re.I),
    re.compile(rb"iban", re.I),
    re.compile(rb"account[_-]?number", re.I),
    re.compile(rb"customer[_-]?name", re.I),
    re.compile(rb"account[_-]?type", re.I),
    re.compile(rb"currency", re.I),
    re.compile(rb"available[_-]?balance", re.I),
    re.compile(rb"routing", re.I),
    re.compile(rb"swift[_-]?bic", re.I),
]


# ─── detect_core_vendor ───────────────────────────────────────────────────────
def detect_core_vendor(session: requests.Session) -> dict:
    """Probe endpoints caractéristiques pour identifier le vendor.
    Retourne le vendor détecté + liste des endpoints trouvés."""
    endpoints = []
    vendor_hits: dict[str, list[str]] = {}
    body_vendor: Optional[str] = None

    for vendor, path, label in VENDOR_ENDPOINTS:
        r = _safe_get(session, path)
        # "found" = serveur répond avec un status < 500 (donc l'endpoint existe
        # potentiellement, même s'il renvoie 401/403/404).
        # 404 = endpoint absent ; 401/403 = endpoint existe mais auth requise
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
        # Detect vendor via body/headers
        if body_vendor is None and r["error"] is None and r["body"]:
            scan = (r["body"] or b"") + json.dumps(r["headers"]).encode("ascii", "ignore")
            for pat, vname in VENDOR_BODY_PATTERNS:
                if pat.search(scan):
                    body_vendor = vname
                    break

    # Vendor détection par priorité : body > endpoint hits count
    detected_vendor = body_vendor
    if detected_vendor is None and vendor_hits:
        # Vendor avec le plus d'endpoints trouvés
        detected_vendor = max(vendor_hits.items(), key=lambda kv: len(kv[1]))[0]

    return {
        "detected_vendor": detected_vendor,
        "vendor_hits": {v: paths for v, paths in vendor_hits.items()},
        "body_vendor": body_vendor,
        "endpoints": endpoints,
        "tested": len(VENDOR_ENDPOINTS),
        "found_count": sum(1 for e in endpoints if e["found"]),
    }


# ─── check_api_auth ───────────────────────────────────────────────────────────
def check_api_auth(session: requests.Session, vendor_findings: dict) -> dict:
    """Test if found endpoints require auth (401/403) or are open (200).
    Vendor_findings = output de detect_core_vendor()['vendor_hits']."""
    auth_required_count = 0
    open_no_auth_count = 0
    results = []

    # Test all found endpoints from vendor_hits + quelques endpoints génériques
    test_paths = set()
    for paths in vendor_findings.values():
        for p in paths:
            test_paths.add(p)
    # Add common API paths
    test_paths.update({
        "/api/v1/accounts",
        "/api/accounts",
        "/rest/accounts",
        "/oauth/token",
        "/api/health",
        "/health",
        "/api/customers",
    })

    for path in sorted(test_paths):
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
        if status in (200, 204):
            verdict = "open_no_auth"
            open_no_auth_count += 1
        elif status in (301, 302):
            verdict = "redirect"
        elif status in (401, 403, 407):
            verdict = "auth_required"
            auth_required_count += 1
        elif status == 404:
            verdict = "not_found"
        elif status == 405:
            verdict = "method_not_allowed"
        else:
            verdict = f"http_{status}"
        results.append({
            "endpoint": path,
            "status": status,
            "len": r["len"],
            "ms": r["ms"],
            "verdict": verdict,
            "error": None,
        })

    return {
        "tested": len(results),
        "auth_required_count": auth_required_count,
        "open_no_auth_count": open_no_auth_count,
        "auth_required": auth_required_count > 0,
        "any_open": open_no_auth_count > 0,
        "results": results,
    }


# ─── check_data_enumeration ───────────────────────────────────────────────────
def check_data_enumeration(session: requests.Session) -> dict:
    """GET /api/accounts/{id} with sequential IDs 1-10 → check if account data leaked.
    Vecteur classique : IDOR (Insecure Direct Object Reference) sur core banking.
    Sévérité critique : fuite données clients = violation RGPD/DORA."""
    tested_ids = list(range(1, 11))  # 1..10
    results = []
    leaked_count = 0
    leaked_fields_seen = set()

    for account_id in tested_ids:
        path = f"/api/accounts/{account_id}"
        r = _safe_get(session, path)
        leak_patterns_found = []
        if r["error"] is None and r["status"] == 200 and r["body"]:
            body = r["body"]
            for pat in ACCOUNT_LEAK_PATTERNS:
                if pat.search(body):
                    # Extract matched keyword (group 0)
                    m = pat.search(body)
                    if m:
                        leak_patterns_found.append(m.group(0).decode("ascii", "ignore").lower())
        is_leaked = bool(leak_patterns_found) and r["status"] == 200
        if is_leaked:
            leaked_count += 1
            leaked_fields_seen.update(leak_patterns_found)
        results.append({
            "id": account_id,
            "endpoint": path,
            "status": r["status"],
            "len": r["len"],
            "ms": r["ms"],
            "leaked": is_leaked,
            "leaked_fields": leak_patterns_found,
            "error": r["error"],
        })

    enumeration_possible = leaked_count >= 2  # ≥ 2 IDs leaked → enumeration confirmed
    return {
        "tested_ids": tested_ids,
        "tested_count": len(tested_ids),
        "leaked_count": leaked_count,
        "leaked_fields_seen": sorted(leaked_fields_seen),
        "enumeration_possible": enumeration_possible,
        "severity": "critical" if enumeration_possible else (
            "high" if leaked_count == 1 else "info"
        ),
        "results": results,
    }


# ─── test_double_spend_race ───────────────────────────────────────────────────
def test_double_spend_race(session: requests.Session, safe_mode: str) -> dict:
    """POST two concurrent transfer requests → check if balance check is atomic.
    Vecteur : TOCTOU (time-of-check-time-of-use) sur balance check.
    Si le core banking ne lock pas le compte atomiquement, les deux transferts
    peuvent réussir même si le solde ne couvre qu'un seul → double spend.
    
    ⚠️ SAFE_MODE=read_only → SKIP (write forbidden).
    ⚠️ SAFE_MODE=full + LAB=1 → exécuté en lab isolé uniquement."""
    if safe_mode != "full":
        return {
            "skipped": True,
            "reason": f"SAFE_MODE={safe_mode} — write forbidden in read-only banking",
            "race_condition_tested": False,
            "double_spend_possible": None,
            "note": "DORA / PCI-DSS : no concurrent POST to core banking in read-only mode",
        }
    if os.environ.get("LAB") != "1":
        return {
            "skipped": True,
            "reason": "LAB!=1 — race condition test requires isolated lab",
            "race_condition_tested": False,
            "double_spend_possible": None,
        }

    # LAB=1 + SAFE_MODE=full → on tente
    # Payload de transfert : compte source lab, montant faible, deux requêtes
    # concurrentes vers le même endpoint pour tester atomicité.
    transfer_endpoint = "/api/transfers"
    payload = {
        "from_account": "LAB000001",
        "to_account":   "LAB000002",
        "amount":       "0.01",
        "currency":     "EUR",
        "reference":    "HARNESS-RACE-TEST",
        "lab_test":     True,
    }

    # Use ThreadPoolExecutor to fire 2 concurrent POSTs
    results: list[dict] = []
    lock = threading.Lock()

    def _do_post(idx: int) -> dict:
        # Re-use session (thread-safe for requests.Session in modern versions)
        r = _safe_post(session, transfer_endpoint, payload)
        return {
            "thread_idx": idx,
            "status": r["status"],
            "len": r["len"],
            "ms": r["ms"],
            "error": r["error"],
            "body_preview": (r["body"][:200].decode("utf-8", "ignore")
                             if r["body"] else ""),
        }

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(_do_post, i) for i in range(2)]
        for fut in as_completed(futures):
            with lock:
                results.append(fut.result())

    # Sort results by thread_idx for deterministic output
    results.sort(key=lambda x: x["thread_idx"])

    # Heuristique double-spend : si les deux requêtes retournent 200/201 →
    # le core banking n'a pas détecté la race → vulnérabilité probable.
    # Si une seule (ou aucune) réussit → balance check probablement atomique.
    both_succeeded = all(r["status"] in (200, 201) for r in results if r["status"] is not None)
    one_succeeded = sum(1 for r in results if r["status"] in (200, 201)) == 1
    none_succeeded = all(r["status"] not in (200, 201) for r in results if r["status"] is not None)

    if both_succeeded:
        verdict = "double_spend_possible"
        double_spend = True
        severity = "critical"
    elif one_succeeded:
        verdict = "one_succeeded_one_rejected"
        double_spend = False
        severity = "info"
    elif none_succeeded:
        verdict = "both_rejected"
        double_spend = False
        severity = "info"
    else:
        verdict = "inconclusive"
        double_spend = None
        severity = "info"

    return {
        "skipped": False,
        "endpoint": transfer_endpoint,
        "concurrent_requests": 2,
        "results": results,
        "verdict": verdict,
        "double_spend_possible": double_spend,
        "race_condition_tested": True,
        "severity": severity,
        "note": "Tested in isolated lab with SAFE_MODE=full + LAB=1",
    }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # SAFE_MODE read-only : detect_core_vendor, check_api_auth, check_data_enumeration
    # sont des GET → compatibles read-only.
    # test_double_spend_race fait des POST (écriture) → SKIP sauf SAFE_MODE=full + LAB=1.

    session = build_session()

    # Phase 1 : detect_core_vendor (GET endpoints caractéristiques)
    vendor_check = detect_core_vendor(session)

    # Phase 2 : check_api_auth (GET — read-only)
    auth_check = check_api_auth(session, vendor_check.get("vendor_hits", {}))

    # Phase 3 : check_data_enumeration (GET /api/accounts/{1..10})
    enum_check = check_data_enumeration(session)

    # Phase 4 : test_double_spend_race (POST — only if SAFE_MODE=full + LAB=1)
    race_check = test_double_spend_race(session, safe_mode)

    # ─── Synthèse JSON stdout ──────────────────────────────────────────────
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "banking",
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "target": {
            "host": TARGET_HOST,
            "port": TARGET_PORT,
            "scheme": TARGET_SCHEME,
        },
        "regulations": list(get_sector_config().get("regulations", [])),
        "read_only": safe_mode == "read_only",
        "results": {
            "vendor_detection": vendor_check,
            "api_auth_check": auth_check,
            "data_enumeration": enum_check,
            "double_spend_race": race_check,
        },
        "summary": {
            "core_vendor": vendor_check.get("detected_vendor"),
            "api_endpoints_found": vendor_check.get("found_count", 0),
            "auth_required": auth_check.get("auth_required", False),
            "race_condition_tested": race_check.get("race_condition_tested", False),
            "enumeration_possible": enum_check.get("enumeration_possible", False),
        },
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }

    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
