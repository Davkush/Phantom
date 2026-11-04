#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — module bancaire : SWIFT Alliance Access probe.
# Secteur: banking (SAFE_MODE=read_only — aucune écriture sur Alliance/SAA).
#
#   - v3.0 : probe HTTPS Alliance Access (port 9443 default)
#   - v3.0 : détection endpoints REST /saa/rest/v1/*
#   - v3.0 : test connectivité HSM (port 1500 TCP)
#   - v3.0 : fingerprint version Alliance via headers/body
#   - v3.0 : test intégrité logs d'audit (accessible sans auth ?)
#   - v3.0 : guard LAB=1 + SAFE_MODE=read_only + timeout 5s
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# SWIFT CSP / DORA / PCI-DSS — read-only, aucune écriture sur Alliance.
import json
import os
import re
import socket
import sys
import time
from typing import Optional

import requests
import urllib3

# Désactive warnings InsecureRequestWarning (verify=False en lab)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "swift_probe"
DEFAULT_PORT = 9443          # SWIFT Alliance Access (cf. sector_base _PORT_MAP_BANKING)
HSM_PORT = 1500              # Thales / Utimaco HSM (typique)
REQUEST_TIMEOUT = 5          # 5s strict (cf. spec harness)

# ─── Import sector_base (best-effort, fallback si PYTHONPATH non configuré) ───
try:
    # Les modules vivent dans sectors/banking/, sector_base.py dans modules_v2/
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
                "reason": "Banking sector is read-only (SWIFT CSP / DORA)",
            }))
            sys.exit(3)


def get_safe_mode() -> str:
    """Effective SAFE_MODE: respect explicit env override (lab admin opt-in),
    otherwise fall back to sector_base default (read_only for banking)."""
    env_sm = os.environ.get("SAFE_MODE", "").lower().strip()
    if env_sm in ("read_only", "full"):
        return env_sm
    return _sector_safe_mode()


# ─── Guards : LAB=1 obligatoire + SAFE_MODE banking = read_only ───────────────
def _check_lab_guard() -> None:
    """Exit si LAB != 1 — exécution réservée aux laboratoires isolés."""
    if os.environ.get("LAB") != "1":
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_failed",
            "reason": "LAB env var must be set to 1 (isolated lab only)",
            "harness_version": HARNESS_VERSION,
        }))
        sys.exit(2)


def _check_banking_safe_mode() -> None:
    """Banking est en read_only par défaut — aucune écriture sur Alliance/SAA."""
    sm = get_safe_mode()
    # On n'exit pas ici (le module ne fait que des GET, donc read_only est OK).
    # On log juste le mode dans le rapport final. Si SAFE_MODE=full était demandé
    # pour une opération d'écriture future, on utiliserait check_write_allowed().
    if sm not in ("read_only", "full"):
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "invalid_safe_mode",
            "safe_mode": sm,
            "valid": ("read_only", "full"),
        }))
        sys.exit(2)


# ─── Args CLI ────────────────────────────────────────────────────────────────
# Usage: swift_module.py <host> [port] [hsm_port]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
HSM_TARGET_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else HSM_PORT

# ─── Helpers HTTP ─────────────────────────────────────────────────────────────
def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME})",
        "Accept": "*/*",
        "X-Forwarded-For": "127.0.0.1",
    })
    return s


def _base_url() -> str:
    return f"https://{TARGET_HOST}:{TARGET_PORT}"


def _safe_get(session: requests.Session, path: str) -> dict:
    """GET HTTPS avec verify=False, timeout=5s. Retourne dict métriques + contenu.
    Aucune levée d'exception — toutes les erreurs sont capturées pour le rapport."""
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


# ─── Patterns fingerprint SWIFT Alliance ──────────────────────────────────────
# Alliance Access versions historiques : 7.x, 8.x, 9.x, 10.x
# Headers typiques : Server, X-SWIFT-*, X-Alliance-*
# Body : titre HTML "Alliance Access" / "SWIFTNet Link" / "Alliance Gateway"
ALLIANCE_VERSION_PATTERNS = [
    # Headers
    re.compile(r"alliance[\s\-_]?access[\s/]*v?(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"x-swift-version[:\s]+v?(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"x-alliance-version[:\s]+v?(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"server[:\s]+swift[\s/-]+(\d+\.\d+(?:\.\d+)?)", re.I),
    # Body (HTML titles, meta tags)
    re.compile(rb"Alliance Access[^<]{0,40}?v?(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(rb"SWIFTNet[^<]{0,40}?v?(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(rb'content="[^"]*?alliance[^"]*?(\d+\.\d+(?:\.\d+)?)"', re.I),
    re.compile(rb"<title>[^<]*?Alliance[^<]*?(\d+\.\d+(?:\.\d+)?)[^<]*?</title>", re.I),
]

ALLIANCE_PRODUCT_PATTERNS = [
    (re.compile(rb"Alliance Access", re.I),          "SWIFT Alliance Access"),
    (re.compile(rb"Alliance Gateway", re.I),         "SWIFT Alliance Gateway"),
    (re.compile(rb"SWIFTNet Link", re.I),            "SWIFTNet Link (SNL)"),
    (re.compile(rb"Alliance Web Platform", re.I),    "Alliance Web Platform"),
    (re.compile(rb"saa\b", re.I),                    "Alliance Access (SAA)"),
]


# ─── Fonctions de probe ───────────────────────────────────────────────────────
def check_alliance_access(session: requests.Session) -> dict:
    """GET https://host:9443/saa/login → login page accessible ?
    Heuristique : status 200/302 + body contient 'alliance'/'saa'/'login'."""
    r = _safe_get(session, "/saa/login")
    body_lower = r["body"].lower() if r["body"] else b""
    is_accessible = (
        r["error"] is None
        and r["status"] in (200, 302, 301)
        and any(
            pat in body_lower
            for pat in (b"alliance", b"saa", b"swift", b"login", b"password")
        )
    )
    return {
        "endpoint": "/saa/login",
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "accessible": is_accessible,
        "error": r["error"],
    }


def check_api_endpoints(session: requests.Session) -> dict:
    """Probe /saa/rest/v1/messages, /saa/rest/v1/health, /saa/api/status.
    Détermine pour chacun : status code, accessible, nécessite auth (401/403)."""
    paths = (
        "/saa/rest/v1/messages",     # liste messages (auth required)
        "/saa/rest/v1/health",       # health check (often unauth)
        "/saa/api/status",           # legacy status endpoint
    )
    endpoints = []
    found_open = 0
    for path in paths:
        r = _safe_get(session, path)
        # 401/403 = endpoint existe mais auth requise (donc "found")
        # 200/204 = endpoint accessible (potentiellement sans auth → critique)
        found = r["error"] is None and r["status"] is not None and r["status"] < 500
        open_no_auth = found and r["status"] in (200, 204)
        auth_required = found and r["status"] in (401, 403, 407)
        if open_no_auth:
            found_open += 1
        endpoints.append({
            "endpoint": path,
            "status": r["status"],
            "len": r["len"],
            "ms": r["ms"],
            "found": found,
            "open_no_auth": open_no_auth,
            "auth_required": auth_required,
            "error": r["error"],
        })
    return {
        "tested": len(paths),
        "endpoints": endpoints,
        "open_without_auth": found_open,
    }


def check_hsm_connectivity(session: requests.Session) -> dict:
    """Test TCP connect sur port HSM (1500) sur le même host que Alliance.
    HSM (Thales PayShield, Utimaco, SafeNet) écoute généralement sur TCP 1500.
    Aucune donnée envoyée — simple connect() puis fermeture immédiate (read-only)."""
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(REQUEST_TIMEOUT)
    try:
        s.connect((TARGET_HOST, HSM_TARGET_PORT))
        s.close()
        return {
            "host": TARGET_HOST,
            "port": HSM_TARGET_PORT,
            "open": True,
            "ms": round((time.time() - t0) * 1000, 1),
            "error": None,
            "note": "TCP connect-only (no data sent — SAFE_MODE read_only)",
        }
    except socket.timeout:
        return _hsm_err(t0, "Timeout")
    except ConnectionRefusedError:
        return _hsm_err(t0, "ConnectionRefused")
    except OSError as e:
        return _hsm_err(t0, type(e).__name__, detail=str(e)[:200])


def _hsm_err(t0: float, err: str, detail: str = "") -> dict:
    return {
        "host": TARGET_HOST,
        "port": HSM_TARGET_PORT,
        "open": False,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": err,
        "error_detail": detail,
    }


def detect_swift_version(session: requests.Session, login_resp: Optional[dict] = None) -> dict:
    """Parse headers/body des endpoints déjà récupérés pour détecter version.
    Évite une requête supplémentaire si on a déjà un login_resp valide."""
    version: Optional[str] = None
    product: Optional[str] = None
    source = None

    # 1) Headers + body de la page de login si disponible
    if login_resp and login_resp.get("error") is None:
        # Concatène headers + body pour le scan
        headers_blob = json.dumps(login_resp.get("headers", {})).encode("utf-8", "ignore")
        body_blob = login_resp.get("body", b"") or b""
        scan_blob = headers_blob + b"\n" + body_blob
        for pat in ALLIANCE_VERSION_PATTERNS:
            m = pat.search(scan_blob)
            if m:
                version = m.group(1) if m.groups() else "unknown"
                source = "login_page"
                break
        if not product:
            for pat, label in ALLIANCE_PRODUCT_PATTERNS:
                if pat.search(scan_blob):
                    product = label
                    break

    # 2) Si rien trouvé sur login, on probe /saa/api/status (souvent leaky)
    if version is None:
        r = _safe_get(session, "/saa/api/status")
        if r["error"] is None:
            headers_blob = json.dumps(r["headers"]).encode("utf-8", "ignore")
            body_blob = r["body"] or b""
            scan_blob = headers_blob + b"\n" + body_blob
            for pat in ALLIANCE_VERSION_PATTERNS:
                m = pat.search(scan_blob)
                if m:
                    version = m.group(1) if m.groups() else "unknown"
                    source = "status_endpoint"
                    break
            if not product:
                for pat, label in ALLIANCE_PRODUCT_PATTERNS:
                    if pat.search(scan_blob):
                        product = label
                        break

    return {
        "version": version,
        "product": product,
        "source": source,
        "detected": version is not None or product is not None,
    }


def check_log_integrity(session: requests.Session) -> dict:
    """GET /saa/rest/v1/audit/logs → accessible sans auth ?
    Critique : les logs d'audit Alliance contiennent MT/MX message refs,
    utilisateurs, BIC8/BIC11 — une fuite viole SWIFT CSP Control 7.x."""
    r = _safe_get(session, "/saa/rest/v1/audit/logs")
    body_lower = (r["body"] or b"").lower()
    # Heuristique de "leak" : 200 + body contient patterns d'audit logs
    log_patterns = (
        b"audit", b"message_ref", b"session_id",
        b"user_id", b"timestamp", b"bic", b"action",
    )
    leaked_patterns = [p.decode("ascii", "ignore") for p in log_patterns if p in body_lower]
    accessible_no_auth = (
        r["error"] is None
        and r["status"] in (200, 204)
        and len(leaked_patterns) >= 2
    )
    return {
        "endpoint": "/saa/rest/v1/audit/logs",
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "accessible_without_auth": accessible_no_auth,
        "leaked_patterns": leaked_patterns if accessible_no_auth else [],
        "auth_required": r["status"] in (401, 403, 407),
        "error": r["error"],
        "severity": "critical" if accessible_no_auth else (
            "high" if r["status"] in (200, 204) else "info"
        ),
    }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    # Guards
    _check_lab_guard()
    _check_banking_safe_mode()

    # SAFE_MODE read-only : ce module ne fait QUE des GET, donc compatible.
    # On n'appelle pas check_write_allowed() car aucune opération d'écriture.
    # Si l'utilisateur tente SAFE_MODE=full explicitement, c'est son choix
    # mais le module reste read-only par construction (GET uniquement).

    session = build_session()

    # Phase 1 : Alliance Access login page
    alliance_check = check_alliance_access(session)

    # Phase 2 : API REST endpoints
    api_check = check_api_endpoints(session)

    # Phase 3 : HSM connectivity (TCP only, no data)
    hsm_check = check_hsm_connectivity(session)

    # Phase 4 : Version fingerprint
    login_resp = None
    if alliance_check["accessible"]:
        # On re-fabrique un dict compatible avec detect_swift_version()
        # à partir des données déjà collectées (évite une double requête).
        # Pour cela on refait un GET ciblé — c'est idempotent et read-only.
        login_resp = _safe_get(session, "/saa/login")
    version_check = detect_swift_version(session, login_resp)

    # Phase 5 : Log integrity check
    log_check = check_log_integrity(session)

    # ─── Synthèse JSON stdout ──────────────────────────────────────────────
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "banking",
        "safe_mode": get_safe_mode(),
        "lab": os.environ.get("LAB", "?"),
        "target": {
            "host": TARGET_HOST,
            "port": TARGET_PORT,
            "hsm_port": HSM_TARGET_PORT,
        },
        "regulations": list(get_sector_config().get("regulations", [])),
        "read_only": True,  # ce module ne fait que des GET
        "results": {
            "alliance_accessible": alliance_check["accessible"],
            "alliance_login": alliance_check,
            "api_endpoints": api_check,
            "hsm_port_open": hsm_check["open"],
            "hsm_connectivity": hsm_check,
            "swift_version": version_check,
            "log_integrity_check": log_check,
        },
        "summary": {
            "alliance_accessible": alliance_check["accessible"],
            "api_endpoints_found": api_check["open_without_auth"],
            "hsm_port_open": hsm_check["open"],
            "swift_version": version_check["version"],
            "log_integrity_check": log_check["accessible_without_auth"],
        },
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }

    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
