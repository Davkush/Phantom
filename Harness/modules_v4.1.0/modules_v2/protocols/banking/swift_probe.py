#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — protocol probe : SWIFT Alliance Access (HTTPS 9443).
# Secteur : banking — SAFE_MODE=read_only (aucune écriture sur Alliance/SAA).
#
#   - v3.1 : probe HTTPS Alliance Access (port 9443 default)
#   - v3.1 : GET /saa/login → login page found ?
#   - v3.1 : GET /saa/      → dashboard reachable ?
#   - v3.1 : TLS cert inspection → CN, issuer, validity (ssl stdlib)
#   - v3.1 : version fingerprint via headers + body
#   - v3.1 : lockout policy detection (3 quick GET /saa/login, watch 429 / lockout hint)
#   - v3.1 : SEED reproducibility, LAB=1 guard, timeout 5s
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# SWIFT CSP / DORA / PCI-DSS — read-only, aucune écriture sur Alliance.
#
# ⚠️ NOTE HISTORIQUE — Bangladesh Bank 2016 fraud vector
#   Le 5 février 2016, des attaquants ont compromis le SWIFT Alliance Access
#   de la Bangladesh Bank via malware installé sur le poste d'administration,
#   envoyant 35 instructions MT103 frauduleuses (~951 M USD demandés, 81 M USD
#   exfiltrés vers Philippines). Vecteur : credentials SAA volés + absence
#   d'authentification forte sur Alliance Access + désactivation/contournement
#   des logs d'audit (print spooler tampering).
#   Ce module documente ces risques via les checks :
#     - login_page_found       (page de login exposée = surface d'attaque)
#     - alliance_accessible    (dashboard reachable sans auth = CRITICAL)
#     - tls_cert.expiry        (cert expiré = MITM possible = vecteur SAA hijack)
#     - lockout_policy         (absence lockout = brute-force credential stuffing,
#                               vecteur initial Bangladesh Bank)
#     - version_detected       (version obsolète = CVE connues SAA < 7.5)
#   Référence : SWIFT CSP Control 1.x (subcontractor security), 7.x (audit logs),
#               2.x (segmentation). Verdict SWIFT Independent Operation Review 2016.
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Optional

# Requêtes HTTP lab-safe (verify=False accepté en lab isolé).
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print(json.dumps({
        "module": "swift_probe",
        "harness_version": "3.1.0",
        "error": "requests_not_installed",
        "hint": "pip install requests urllib3",
    }))
    sys.exit(2)

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "swift_probe"
DEFAULT_PORT = 9443              # SWIFT Alliance Access (cf. sector_base _PORT_MAP_BANKING)
REQUEST_TIMEOUT = 5             # 5s strict (cf. spec harness)

# ─── Import sector_base (best-effort) ─────────────────────────────────────────
# Les modules protocols/banking/ vivent à /modules_v2/protocols/banking/, donc
# sector_base.py est à /modules_v2/ (3 niveaux au-dessus).
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
    """Effective SAFE_MODE: respect explicit env override (lab admin opt-in),
    otherwise fall back to sector_base default (read_only for banking)."""
    env_sm = os.environ.get("SAFE_MODE", "").lower().strip()
    if env_sm in ("read_only", "full"):
        return env_sm
    return _sector_safe_mode()


# ─── SEED reproducibility ─────────────────────────────────────────────────────
# SEED fixe les sorties pseudo-aléatoires (ex : STAN, trace ID, time offsets
# dans les payloads de test) pour qu'une exécution à SEED identique produise
# un rapport identique. Ici on l'utilise pour fixer le STAN des probes GET
# (header X-Harness-STAN) afin que les logs serveur soient corrélables.
SEED = int(os.environ.get("SEED", "1337"))
_STAN_SEQ = [0]  # mutable counter for deterministic increment

def _next_stan() -> str:
    """Deterministic STAN : SEED + incrément. Permet de reproduire les logs."""
    _STAN_SEQ[0] += 1
    return f"{(SEED + _STAN_SEQ[0]) % 1000000:06d}"


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
# Usage: swift_probe.py <host> [port]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT


# ─── Helpers HTTP ─────────────────────────────────────────────────────────────
def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME}) seed={SEED}",
        "Accept": "*/*",
        "X-Forwarded-For": "127.0.0.1",
        "X-Harness-STAN": _next_stan(),
    })
    return s


def _base_url() -> str:
    return f"https://{TARGET_HOST}:{TARGET_PORT}"


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
# Alliance Access versions : 7.x (legacy, Bangladesh Bank era), 8.x, 9.x, 10.x
# Headers typiques : Server, X-SWIFT-*, X-Alliance-*
# Body : titre HTML "Alliance Access" / "SWIFTNet Link" / "Alliance Gateway"
ALLIANCE_VERSION_PATTERNS = [
    re.compile(r"alliance[\s\-_]?access[\s/]*v?(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"x-swift-version[:\s]+v?(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"x-alliance-version[:\s]+v?(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"server[:\s]+swift[\s/-]+(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(rb"Alliance Access[^<]{0,40}?v?(\d+\.\d+(?:\.\d+)?)", re.I),
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


# ─── 1. Alliance Access login page ────────────────────────────────────────────
def check_login_page(session: requests.Session) -> dict:
    """GET /saa/login → login page found ?
    Heuristique : status 200/302 + body contient 'alliance'/'saa'/'login'."""
    r = _safe_get(session, "/saa/login")
    body_lower = r["body"].lower() if r["body"] else b""
    is_found = (
        r["error"] is None
        and r["status"] in (200, 302, 301)
        and any(p in body_lower for p in (b"alliance", b"saa", b"swift", b"login", b"password"))
    )
    return {
        "endpoint": "/saa/login",
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "login_page_found": is_found,
        "error": r["error"],
    }


# ─── 2. Alliance Access dashboard reachable ───────────────────────────────────
def check_dashboard(session: requests.Session) -> dict:
    """GET /saa/ → dashboard reachable ?
    Critique : si 200 sans auth, dashboard Alliance exposé = surface d'attaque
    majeure (Bangladesh Bank 2016 : dashboard exposé a facilité la reconnaissance
    initiale des attaquants)."""
    r = _safe_get(session, "/saa/")
    body_lower = r["body"].lower() if r["body"] else b""
    is_accessible = (
        r["error"] is None
        and r["status"] == 200
        and any(p in body_lower for p in (b"alliance", b"saa", b"swift", b"dashboard"))
    )
    return {
        "endpoint": "/saa/",
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "alliance_accessible": is_accessible,
        "auth_required": r["status"] in (401, 403, 407),
        "error": r["error"],
        "severity": "critical" if is_accessible else (
            "high" if r["status"] == 200 else "info"
        ),
    }


# ─── 3. TLS certificate inspection ────────────────────────────────────────────
def check_tls_cert() -> dict:
    """Récupère le cert TLS via socket + ssl stdlib (sans requests).
    Extrait : CN subject, issuer CN, notBefore, notAfter, validity (expired/expiring).
    Pas de verify (lab) — on veut juste lire le cert présenté.
    Toutes les erreurs sont capturées (connexion refusée, timeout, SSL handshake
    failure, etc.) pour ne pas interrompre le rapport JSON."""
    t0 = time.time()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    der: Optional[bytes] = None
    sock: Optional[socket.socket] = None
    try:
        sock = socket.create_connection((TARGET_HOST, TARGET_PORT),
                                        timeout=REQUEST_TIMEOUT)
        ssock = ctx.wrap_socket(sock, server_hostname=TARGET_HOST)
        try:
            der = ssock.getpeercert(binary_form=True)
        finally:
            try:
                ssock.close()
            except OSError:
                pass
    except ssl.SSLError as e:
        return _tls_err(t0, "SSLError", detail=str(e)[:200])
    except socket.timeout:
        return _tls_err(t0, "Timeout")
    except ConnectionRefusedError:
        return _tls_err(t0, "ConnectionRefused")
    except OSError as e:
        return _tls_err(t0, type(e).__name__, detail=str(e)[:200])
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if der is None:
        return _tls_err(t0, "NoCert")
    # Parse the DER via ssl stdlib helper
    try:
        cert_dict = ssl.DER_cert_to_PEM_cert(der)
        # ssl._ssl._test_decode_cert parses a PEM string → dict with subject/issuer/notAfter
        parsed = ssl._ssl._test_decode_cert(cert_dict)  # type: ignore[attr-defined]
    except Exception as e:  # noqa: BLE001
        return _tls_err(t0, "CertParseError", detail=str(e)[:200])

    subject = parsed.get("subject", ())
    issuer = parsed.get("issuer", ())
    not_before = parsed.get("notBefore")
    not_after = parsed.get("notAfter")
    cn = _extract_cn(subject)
    issuer_cn = _extract_cn(issuer)

    now = datetime.now(timezone.utc)
    expiry_iso = _parse_asn1_time(not_after)
    valid_now = True
    expiring_within_30d = False
    if expiry_iso is not None:
        if now > expiry_iso:
            valid_now = False
        elif (expiry_iso - now).days <= 30:
            expiring_within_30d = True

    return {
        "host": TARGET_HOST,
        "port": TARGET_PORT,
        "cn": cn,
        "issuer_cn": issuer_cn,
        "not_before": not_before,
        "not_after": not_after,
        "valid_now": valid_now,
        "expiring_within_30d": expiring_within_30d,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": None,
        "severity": "high" if not valid_now else ("medium" if expiring_within_30d else "info"),
    }


def _extract_cn(name_tuple) -> Optional[str]:
    """Extract CN from a parsed subject/issuer tuple.
    Format: ((('countryName', 'US'),), (('commonName', 'foo.bar'),), ...)"""
    for rdn in name_tuple:
        for attr, val in rdn:
            if attr in ("commonName", "CN"):
                return val
    return None


def _parse_asn1_time(s: Optional[str]) -> Optional[datetime]:
    """Parse ASN1 time formats '%b %d %H:%M:%S %Y %Z' (e.g. 'Jun  1 12:00:00 2025 GMT')."""
    if not s:
        return None
    try:
        dt = datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _tls_err(t0: float, err: str, detail: str = "") -> dict:
    return {
        "host": TARGET_HOST,
        "port": TARGET_PORT,
        "cn": None,
        "issuer_cn": None,
        "not_before": None,
        "not_after": None,
        "valid_now": None,
        "expiring_within_30d": None,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": err,
        "error_detail": detail,
    }


# ─── 4. Version detection ─────────────────────────────────────────────────────
def detect_version(session: requests.Session, login_resp: Optional[dict] = None) -> dict:
    """Parse headers/body pour détecter la version Alliance Access.
    Compose un scan_blob des headers + body des réponses déjà collectées
    (évite une requête supplémentaire si login_resp est valide)."""
    version: Optional[str] = None
    product: Optional[str] = None
    source = None
    if login_resp and login_resp.get("error") is None:
        scan_blob = (
            json.dumps(login_resp.get("headers", {})).encode("utf-8", "ignore")
            + b"\n" + (login_resp.get("body", b"") or b"")
        )
        version, product, source = _scan_blob(scan_blob, source := "login_page")
    if version is None:
        # Probe un status endpoint souvent leaky
        r = _safe_get(session, "/saa/api/status")
        if r["error"] is None:
            scan_blob = (
                json.dumps(r["headers"]).encode("utf-8", "ignore")
                + b"\n" + (r["body"] or b"")
            )
            version, product, source = _scan_blob(scan_blob, "status_endpoint")
    return {
        "version": version,
        "product": product,
        "source": source,
        "version_detected": version is not None,
    }


def _scan_blob(blob: bytes, src: str):
    v = None
    p = None
    for pat in ALLIANCE_VERSION_PATTERNS:
        m = pat.search(blob)
        if m:
            v = m.group(1) if m.groups() else "unknown"
            break
    for pat, label in ALLIANCE_PRODUCT_PATTERNS:
        if pat.search(blob):
            p = label
            break
    return v, p, src if (v or p) else None


# ─── 5. Lockout policy detection ──────────────────────────────────────────────
def check_lockout_policy(session: requests.Session) -> dict:
    """Détecte la politique de lockout / rate-limiting sur /saa/login.

    Méthode (read-only) : on envoie 3 GET /saa/login rapides (sans credentials
    réels — c'est un GET, pas un POST login). Si :
      - 429 Too Many Requests apparaît → lockout_policy=True (rate-limit actif)
      - Header Retry-After présent → lockout_policy=True (backoff imposé)
      - Header X-RateLimit-* présent → lockout_policy=True (limite déclarée)
      - Status passe 200→403/423 → lockout_policy=True (verrouillage compte)

    NB: le GET /saa/login sans credentials ne déclenche normalement PAS le
    lockout (qui s'applique aux POST auth). Mais on observe les headers
    de rate-limiting déclarés par le serveur, qui indiquent si la politique
    existe. Un serveur sans AUCUN de ces signaux est probablement sans
    protection brute-force → vecteur credential stuffing (Bangladesh Bank 2016).
    """
    results = []
    statuses = []
    rate_limit_headers_seen = set()
    saw_429 = False
    saw_retry_after = False
    saw_lock_transition = False

    for i in range(3):
        # Nouveau STAN à chaque tir pour corrélation logs (SEED-deterministic)
        session.headers["X-Harness-STAN"] = _next_stan()
        r = _safe_get(session, "/saa/login")
        statuses.append(r["status"])
        # Detect rate-limit related headers
        for h in (r["headers"] or {}).keys():
            hl = h.lower()
            if "rate" in hl or "limit" in hl or "retry" in hl or "throttle" in hl:
                rate_limit_headers_seen.add(hl)
        if r["status"] == 429:
            saw_429 = True
        if "retry-after" in (r["headers"] or {}):
            saw_retry_after = True
        # Status transition from accessible (200/302) to locked (403/423/429)
        if i > 0 and r["status"] in (403, 423, 429) and statuses[0] in (200, 302):
            saw_lock_transition = True
        results.append({
            "attempt": i + 1,
            "status": r["status"],
            "ms": r["ms"],
            "error": r["error"],
        })
        # Petit délai inter-tir pour rester read-only (pas de flood)
        time.sleep(0.05)

    lockout_policy = (
        saw_429 or saw_retry_after or saw_lock_transition
        or bool(rate_limit_headers_seen)
    )
    return {
        "endpoint": "/saa/login",
        "attempts": 3,
        "statuses": statuses,
        "rate_limit_headers": sorted(rate_limit_headers_seen),
        "saw_429": saw_429,
        "saw_retry_after": saw_retry_after,
        "saw_lock_transition": saw_lock_transition,
        "lockout_policy": lockout_policy,
        "severity": "high" if not lockout_policy else "info",
        "note": (
            "No rate-limit/lockout signals detected — credential stuffing "
            "vector plausible (cf. Bangladesh Bank 2016 initial access)."
            if not lockout_policy
            else "Rate-limit/lockout signals present (good hygiene)."
        ),
        "results": results,
    }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # SAFE_MODE read-only : tous les checks sont des GET + lecture TLS cert.
    # Pas de POST login, pas de credential brute-force réel. Compatible read-only.
    session = build_session()

    # Phase 1 : login page found ?
    login_check = check_login_page(session)

    # Phase 2 : dashboard reachable ?
    dashboard_check = check_dashboard(session)

    # Phase 3 : TLS cert inspection
    tls_check = check_tls_cert()

    # Phase 4 : version detection (re-use login response if accessible)
    login_resp = None
    if login_check.get("login_page_found"):
        # On refait un GET ciblé (idempotent, read-only) pour récupérer le body
        # exploitable par detect_version (évite de trimballer le body partout).
        login_resp = _safe_get(session, "/saa/login")
    version_check = detect_version(session, login_resp)

    # Phase 5 : lockout policy detection (3 GET /saa/login rapides)
    lockout_check = check_lockout_policy(session)

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
        "read_only": True,  # GET + TLS read only
        "results": {
            "login_page": login_check,
            "dashboard": dashboard_check,
            "tls_cert": tls_check,
            "version": version_check,
            "lockout_policy": lockout_check,
        },
        "summary": {
            "alliance_accessible": dashboard_check["alliance_accessible"],
            "login_page_found": login_check["login_page_found"],
            "tls_cert": {
                "cn": tls_check.get("cn"),
                "issuer": tls_check.get("issuer_cn"),
                "expiry": tls_check.get("not_after"),
                "valid_now": tls_check.get("valid_now"),
            },
            "version_detected": version_check.get("version_detected"),
            "version": version_check.get("version"),
            "lockout_policy": lockout_check["lockout_policy"],
        },
        "risk_note": (
            "Bangladesh Bank 2016 fraud vector : compromission Alliance Access "
            "via credential stuffing + audit log tampering. Vectors mitigated "
            "by SWIFT CSP controls 1.x (subcontractor security), 2.x (segmentation), "
            "7.x (audit log integrity). This module audits for the hygiene gaps "
            "that enabled the initial access : exposed login page, absent lockout, "
            "expired TLS cert, obsolete Alliance version."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
