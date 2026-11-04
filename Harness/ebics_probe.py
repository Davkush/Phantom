#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — protocol probe : EBICS (Electronic Banking
# Internet Communication Standard). Port 443 (HTTPS), Europe-wide
# bank-to-customer file transfer protocol (RFC/ISO 20022 carrier).
# Secteur : banking — SAFE_MODE=read_only.
#
#   - v3.1 : POST / with EBICS H004 / H003 INI / HIA / HPB request XML
#   - v3.1 : TLS cert inspection (CN, issuer, expiry) via ssl stdlib
#   - v3.1 : Order-type probe (INI, HIA, HPB, C53/C54 CAMT.053, pain.001)
#   - v3.1 : Version negotiation H004 (3.0) vs H003 (2.5) via EBICS_VERSION
#   - v3.1 : SEED reproducibility (deterministic HostID/PartnerID/UserID),
#            LAB=1 guard, timeout 5s, read_only=True
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# EBICS = ISO 20022 + DFS (Deutsche Finanzinformatik), used by EBA Clearing,
# SWIFT, and most DACH/EU banks. EBICS 3.0 (H004) = TS 102 540 v3.0.
# EBICS 2.5 (H003) = TS 102 540 v2.5 (legacy, still widely deployed).
#
# Références :
#   - EBICS TS 102 540 (ETSI) — v3.0 (H004), v2.5 (H003)
#   - EBICS 3.0 spec sections 4 / 7 / 11 (INI / HIA / HPB)
#   - CAMT.053 (bank-to-customer statement) — ISO 20022 CBPR+
#   - pain.001 (customer-to-bank payment initiation) — ISO 20022 CBPR+
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Optional

# HTTP / TLS — lab-safe (verify=False accepté en lab isolé).
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print(json.dumps({
        "module": "ebics_probe",
        "harness_version": "3.1.0",
        "error": "requests_not_installed",
        "hint": "pip install requests urllib3",
    }))
    sys.exit(2)

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "ebics_probe"
DEFAULT_PORT = 443              # EBICS over HTTPS (Europe bank-to-customer)
REQUEST_TIMEOUT = 5            # 5s strict (cf. spec harness)

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
# SEED fixe les identifiants EBICS (HostID, PartnerID, UserID, Nonce) pour
# qu'une exécution à SEED identique produise un rapport identique et que les
# logs serveur soient corrélables entre runs.
SEED = int(os.environ.get("SEED", "1337"))
# Deterministic EBICS identifiers (lab-safe, no real customer data)
HOST_ID = f"HV{SEED:08d}"            # HV prefix = harness-validate
PARTNER_ID = f"HVP{SEED:08d}"
USER_ID = f"HVU{SEED:08d}"
SYSTEM_ID = f"HVS{SEED:08d}"


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
# Usage: ebics_probe.py <host> [port]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT


# ─── Helpers HTTP ─────────────────────────────────────────────────────────────
def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME}) seed={SEED}",
        "Accept": "text/xml, application/xml, */*",
        "X-Forwarded-For": "127.0.0.1",
        "X-Harness-SEED": str(SEED),
    })
    return s


def _base_url() -> str:
    return f"https://{TARGET_HOST}:{TARGET_PORT}"


def _safe_post(session: requests.Session, body_xml: bytes,
               extra_headers: Optional[dict] = None) -> dict:
    """POST EBICS request XML to / (the canonical EBICS endpoint).
    Returns a dict with status, headers, body, ms, error."""
    url = _base_url() + "/"
    t0 = time.time()
    headers = {
        "Content-Type": "text/xml; charset=ISO-8859-1",
        "EBICS_HOST": HOST_ID,
    }
    if extra_headers:
        headers.update(extra_headers)
    try:
        r = session.post(url, data=body_xml, headers=headers,
                         timeout=REQUEST_TIMEOUT, verify=False,
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


def _safe_get(session: requests.Session, path: str) -> dict:
    url = path if path.startswith("http") else _base_url() + path
    t0 = time.time()
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, verify=False,
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


# ─── EBICS request builders ───────────────────────────────────────────────────
# EBICS request XML — H004 (3.0) and H003 (2.5) variants.
# These are unsigned "no EU signature" requests for INI / HIA / HPB / FDL / 
# AZC order types. The server should respond with an EBICS error response
# (e.g. 061001 = "no valid user" or 091002 = "transaction not initialised")
# rather than HTTP 404 if it is a real EBICS endpoint.

EBICS_NS_H004 = "http://www.ebics.org/H004"
EBICS_NS_H003 = "http://www.ebics.org/H003"
EBICS_SCHEMA_LOC_H004 = "http://www.ebics.org/H004 ebics_request_H004.xsd"
EBICS_SCHEMA_LOC_H003 = "http://www.ebics.org/H003 ebics_request_H003.xsd"


def _ebics_timestamp() -> str:
    """ISO-8601 UTC timestamp with ms (EBICS 'Timestamp' element format).
    Deterministic-ish (using current UTC) but lab-safe."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


def _ebics_nonce() -> str:
    """Deterministic nonce derived from SEED (reproducible)."""
    return f"LV{SEED:016x}"[:16]


def build_ebics_request(order_type: str, version: str = "H004",
                        transaction_phase: str = "Initialisation",
                        order_id: str = "A001") -> bytes:
    """Build an unsigned EBICS request XML for the given OrderType.

    Order types of interest:
      INI  — Send user signature key (initialization step 1)
      HIA  — Send user encryption + authentication keys (initialization step 2)
      HPB  — Download bank's public keys (initialization step 3)
      FDL  — File download (e.g. C53/C54 CAMT.053 statement)
      AZC  — Bank parameter download (admin)
      VMK  — Send VMK order (key management continuation)
      CDB  — Download bank parameters
      SPR  — Subscriber parameters (admin)
      BTU  — Bank technical parameters upload
    """
    if version == "H004":
        ns = EBICS_NS_H004
        schema = EBICS_SCHEMA_LOC_H004
    else:
        ns = EBICS_NS_H003
        schema = EBICS_SCHEMA_LOC_H003

    xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<ebicsRequest xmlns="{ns}" '
        f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        f'xsi:schemaLocation="{schema}" '
        f'Version="{version}" Revision="1">'
        f'<header authenticate="true">'
        f'<static>'
        f'<HostID>{HOST_ID}</HostID>'
        f'<Nonce>{_ebics_nonce()}</Nonce>'
        f'<Timestamp>{_ebics_timestamp()}</Timestamp>'
        f'<PartnerID>{PARTNER_ID}</PartnerID>'
        f'<UserID>{USER_ID}</UserID>'
        f'<Product Language="en" Provider="harness-validate">'
        f'EBICS Probe v{HARNESS_VERSION}'
        f'</Product>'
        f'<OrderNumber>{order_id}</OrderNumber>'
        f'<OrderType>{order_type}</OrderType>'
        f'</static>'
        f'<mutable>'
        f'<TransactionPhase>{transaction_phase}</TransactionPhase>'
        f'</mutable>'
        f'</header>'
        f'<body/>'
        f'</ebicsRequest>'
    )
    return xml.encode("utf-8")


# ─── EBICS response parsing ───────────────────────────────────────────────────
# Standard EBICS return codes (TS 102 540 Annex A). Subset relevant to probes:
#   000000  EBICS_OK
#   011001  EBICS_NO_SESSION_DATA (admin order without auth)
#   061001  EBICS_UNKNOWN_USER  → server recognizes EBICS, user not registered
#   091002  EBICS_TX_INITIALISATION_MISSING
#   091011  EBICS_TX_NUMBER_NOT_OK → transaction phase issue
#   091116  EBICS_INVALID_ORDER_TYPE → server says order type unsupported
#   011301  EBICS_KEYMGMT_UNSUPPORTED_VERSION_SIGNATURE
#   091001  EBICS_DOWNLOAD_POSTPROCESSING_NO_MORE_DATA
EBICS_RETURN_CODES = {
    "000000": "EBICS_OK",
    "011001": "EBICS_NO_SESSION_DATA",
    "061001": "EBICS_UNKNOWN_USER",
    "091002": "EBICS_TX_INITIALISATION_MISSING",
    "091011": "EBICS_TX_NUMBER_NOT_OK",
    "091116": "EBICS_INVALID_ORDER_TYPE",
    "011301": "EBICS_KEYMGMT_UNSUPPORTED_VERSION_SIGNATURE",
    "091001": "EBICS_DOWNLOAD_POSTPROCESSING_NO_MORE_DATA",
}


def parse_ebics_response(body: bytes) -> dict:
    """Parse EBICS response XML. Extract: technical code, order type echoed,
    whether the response is EBICS-formatted (vs HTML error / 404 page)."""
    if not body:
        return {
            "is_ebics_response": False,
            "technical_code": None,
            "technical_meaning": None,
            "order_type_echo": None,
            "version_echo": None,
            "host_id_echo": None,
        }
    text = body.decode("utf-8", errors="ignore")
    # Detect EBICS response root
    is_ebics = (
        "<ebicsKeyManagementResponse" in text
        or "<ebicsResponse" in text
        or "<ebicsRequest" in text
        or 'xmlns="http://www.ebics.org/H00' in text
    )
    tech_code = None
    tech_meaning = None
    # EBICS TS 102 540 uses <ReturnCode> (capital R, C) in body + header.
    # Some servers use <returnCode> or <technicalCode>. Match case-insensitively.
    m = re.search(r"<(?:Technical|Return)?Code[^>]*>(\d{6})</(?:Technical|Return)?Code>", text, re.I)
    if m:
        tech_code = m.group(1)
        tech_meaning = EBICS_RETURN_CODES.get(tech_code, "unknown")
    # Order type echoed back (some responses echo the requested OrderType)
    m2 = re.search(r"<OrderType[^>]*>([A-Z0-9]+)</OrderType>", text)
    order_type_echo = m2.group(1) if m2 else None
    # Version echo (ebicsResponse/@Version)
    m3 = re.search(r'Version="(H00[34])"', text)
    version_echo = m3.group(1) if m3 else None
    # HostID echo
    m4 = re.search(r"<HostID[^>]*>([^<]+)</HostID>", text)
    host_id_echo = m4.group(1) if m4 else None
    return {
        "is_ebics_response": is_ebics,
        "technical_code": tech_code,
        "technical_meaning": tech_meaning,
        "order_type_echo": order_type_echo,
        "version_echo": version_echo,
        "host_id_echo": host_id_echo,
    }


# ─── 1. Probe HTTP root (GET /) → detect EBICS presence ──────────────────────
def check_root(session: requests.Session) -> dict:
    """GET / — most EBICS servers respond with HTTP 405 / 200 + a marker page.
    The presence of EBICS-related error string ('ebics', 'ebicsHost', 'H004')
    in the response indicates the server expects EBICS POSTs."""
    r = _safe_get(session, "/")
    body_lower = (r["body"] or b"").lower()
    is_ebics_marker = (
        r["error"] is None
        and (b"ebics" in body_lower or b"h004" in body_lower or b"h003" in body_lower
             or b"ebicshost" in body_lower)
    )
    return {
        "endpoint": "/",
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "ebics_marker_in_body": is_ebics_marker,
        "server_header": (r["headers"] or {}).get("Server"),
        "error": r["error"],
        "severity": (
            "info" if is_ebics_marker
            else "medium" if r["status"] in (404, 405)
            else "info"
        ),
    }


# ─── 2. TLS certificate inspection ────────────────────────────────────────────
def check_tls_cert() -> dict:
    """Retrieve TLS cert via socket + ssl stdlib. Extract: CN, issuer CN,
    notBefore, notAfter, validity (expired/expiring within 30d)."""
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
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        parsed = ssl._ssl._test_decode_cert(pem)  # type: ignore[attr-defined]
    except Exception as e:  # noqa: BLE001
        return _tls_err(t0, "CertParseError", detail=str(e)[:200])

    subject = parsed.get("subject", ())
    issuer = parsed.get("issuer", ())
    not_before = parsed.get("notBefore")
    not_after = parsed.get("notAfter")
    cn = _extract_cn(subject)
    issuer_cn = _extract_cn(issuer)
    san = parsed.get("subjectAltName", ())
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
        "san": [s[1] for s in san if isinstance(s, tuple) and len(s) == 2],
        "not_before": not_before,
        "not_after": not_after,
        "valid_now": valid_now,
        "expiring_within_30d": expiring_within_30d,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": None,
        "severity": "high" if not valid_now else ("medium" if expiring_within_30d else "info"),
    }


def _extract_cn(name_tuple) -> Optional[str]:
    for rdn in name_tuple:
        for attr, val in rdn:
            if attr in ("commonName", "CN"):
                return val
    return None


def _parse_asn1_time(s: Optional[str]) -> Optional[datetime]:
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
        "san": [],
        "not_before": None,
        "not_after": None,
        "valid_now": None,
        "expiring_within_30d": None,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": err,
        "error_detail": detail,
    }


# ─── 3. Send EBICS INI request (initialization) ──────────────────────────────
def send_ebics_ini(session: requests.Session, version: str = "H004") -> dict:
    """POST an EBICS INI order. INI = Send user signature key (the very first
    step of subscriber initialization). An unsigned INI request without a real
    RSA signature payload will be rejected with a technical return code, but
    if the server is a real EBICS endpoint, the response body will be a
    well-formed ebicsKeyManagementResponse XML.

    A non-EBICS server returns HTML 404/500 — that distinguishes the cases.
    """
    xml = build_ebics_request(order_type="INI", version=version,
                              order_id=f"A{(SEED % 90000) + 100:05d}")
    r = _safe_post(session, xml, extra_headers={"EBICS_VERSION": version})
    parsed = parse_ebics_response(r["body"])
    # EBICS server reachable = response is EBICS-formatted (regardless of
    # technical code) OR server returned HTTP 200/400/500 with EBICS marker
    body_lower = (r["body"] or b"").lower()
    ebics_marker = (
        parsed["is_ebics_response"]
        or b"ebics" in body_lower
        or b"h004" in body_lower
        or b"h003" in body_lower
    )
    return {
        "endpoint": "/",
        "order_type": "INI",
        "version": version,
        "method": "POST",
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "error": r["error"],
        "ini_sent": r["error"] is None and r["status"] is not None,
        "ebics_response_received": parsed["is_ebics_response"],
        "technical_code": parsed["technical_code"],
        "technical_meaning": parsed["technical_meaning"],
        "version_echo": parsed["version_echo"],
        "host_id_echo": parsed["host_id_echo"],
        "ebics_marker_in_body": ebics_marker,
        "severity": "info" if parsed["is_ebics_response"] else "medium",
    }


# ─── 4. Test additional order types (HIA, HPB, C53/C54, pain.001) ────────────
def probe_order_type(session: requests.Session, order_type: str,
                     version: str = "H004",
                     order_id: str = "A001") -> dict:
    """Send a generic EBICS order probe. Returns whether the server:
      - Returned an EBICS-formatted response
      - Echoed a technical code (and which)
      - Rejected with EBICS_INVALID_ORDER_TYPE (091116) → unsupported order type
      - Rejected with EBICS_UNKNOWN_USER (061001) → order type supported,
        user just not registered (this is what we expect for INI/HIA/HPB)
    """
    xml = build_ebics_request(order_type=order_type, version=version,
                              order_id=order_id)
    r = _safe_post(session, xml, extra_headers={"EBICS_VERSION": version})
    parsed = parse_ebics_response(r["body"])
    # 091116 = INVALID_ORDER_TYPE → order type explicitly unsupported
    # 061001 = UNKNOWN_USER → server processed XML, recognised order type,
    #          user just not registered. This means order type is supported.
    order_type_supported = (
        parsed["is_ebics_response"]
        and parsed["technical_code"] != "091116"
    )
    return {
        "order_type": order_type,
        "version": version,
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "error": r["error"],
        "ebics_response_received": parsed["is_ebics_response"],
        "technical_code": parsed["technical_code"],
        "technical_meaning": parsed["technical_meaning"],
        "order_type_supported": order_type_supported,
        "severity": (
            "info" if order_type_supported
            else "medium" if parsed["technical_code"] == "091116"
            else "info"
        ),
    }


def test_all_order_types(session: requests.Session, version: str = "H004") -> dict:
    """Probe multiple EBICS order types:
      - INI  : Initialize (signature key upload)
      - HIA  : HA initialization (auth + encryption key upload)
      - HPB  : Public key download (bank keys)
      - FDL  : File download (used for C53/C54 CAMT.053, MT940)
      - AZC  : Bank parameters download (admin)
      - C53  : Bank statement download (CAMT.053) — usually a FDL OrderType
              attribute but some banks accept direct C53/C54 order types.
      - C54  : Intra-day statement (CAMT.053)
      - pain.001 is *content* of an FUL/FTU upload order, not an OrderType.
              We test FUL/FTU to see if upload is open.
    """
    order_types = ["INI", "HIA", "HPB", "FDL", "AZC", "C53", "C54", "FUL", "FTU"]
    results = []
    for i, ot in enumerate(order_types):
        oid = f"A{(SEED % 90000) + 100 + i:05d}"
        results.append(probe_order_type(session, ot, version=version, order_id=oid))
        # Tiny inter-request delay (avoid flood, stay read-only)
        time.sleep(0.05)
    return {
        "version_tested": version,
        "order_types_tested": order_types,
        "results": results,
        "supported_count": sum(1 for r in results if r["order_type_supported"]),
    }


# ─── 5. Version negotiation (H004 vs H003) ───────────────────────────────────
def negotiate_version(session: requests.Session) -> dict:
    """Probe both H004 (3.0) and H003 (2.5) and see which one the server
    accepts / echoes back in its response."""
    h004 = send_ebics_ini(session, version="H004")
    time.sleep(0.05)
    h003 = send_ebics_ini(session, version="H003")
    # The server's preferred version is the one for which an EBICS response
    # with a non-missing version echo is returned.
    preferred = None
    if h004["ebics_response_received"] and h004["version_echo"] == "H004":
        preferred = "H004"
    elif h003["ebics_response_received"] and h003["version_echo"] == "H003":
        preferred = "H003"
    elif h004["ebics_response_received"] and not h003["ebics_response_received"]:
        preferred = "H004"
    elif h003["ebics_response_received"] and not h004["ebics_response_received"]:
        preferred = "H003"
    return {
        "preferred_version": preferred,
        "h004_probe": h004,
        "h003_probe": h003,
    }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # SAFE_MODE read-only : INI/HIA/HPB probes are unsigned (no real RSA sig
    # payload) so they cannot actually initialize a subscriber. They only
    # detect EBICS server presence via XML response structure. Compatible
    # read-only. No real customer data is sent — deterministic SEED-derived
    # PartnerID/UserID, never a real bank subscriber ID.
    session = build_session()

    # Phase 1 : HTTP root probe (GET /) — cheap pre-check
    root_check = check_root(session)

    # Phase 2 : TLS cert inspection
    tls_check = check_tls_cert()

    # Phase 3 : INI request (H004 first, then H003) — version negotiation
    version_check = negotiate_version(session)
    # Pick preferred version for the next probes (default H004)
    probe_version = version_check["preferred_version"] or "H004"

    # Phase 4 : Full order-type probe (INI, HIA, HPB, FDL, AZC, C53, C54, ...)
    order_types_check = test_all_order_types(session, version=probe_version)

    # ─── Summary flags ─────────────────────────────────────────────────────
    ini_sent = version_check["h004_probe"]["ini_sent"] or version_check["h003_probe"]["ini_sent"]
    ebics_accessible = (
        root_check["ebics_marker_in_body"]
        or version_check["h004_probe"]["ebics_response_received"]
        or version_check["h003_probe"]["ebics_response_received"]
        or any(r["ebics_response_received"] for r in order_types_check["results"])
    )

    # Build flat list of "order types tested" with boolean result for the spec
    order_types_tested = [
        {"order_type": r["order_type"],
         "supported": r["order_type_supported"],
         "technical_code": r["technical_code"]}
        for r in order_types_check["results"]
    ]

    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "banking",
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "seed": SEED,
        "read_only": True,
        "regulations": list(get_sector_config().get("regulations", [])),
        "target": {
            "host": TARGET_HOST,
            "port": TARGET_PORT,
        },
        # Spec output keys
        "ebics_accessible": ebics_accessible,
        "version": probe_version,
        "tls_cert": {
            "cn": tls_check.get("cn"),
            "issuer_cn": tls_check.get("issuer_cn"),
            "not_before": tls_check.get("not_before"),
            "not_after": tls_check.get("not_after"),
            "valid_now": tls_check.get("valid_now"),
            "expiring_within_30d": tls_check.get("expiring_within_30d"),
            "san": tls_check.get("san"),
            "error": tls_check.get("error"),
        },
        "order_types_tested": order_types_tested,
        "ini_sent": ini_sent,
        "results": {
            "root_check": root_check,
            "tls_cert": tls_check,
            "version_negotiation": version_check,
            "order_types": order_types_check,
        },
        "summary": {
            "ebics_accessible": ebics_accessible,
            "version_preferred": probe_version,
            "ini_sent": ini_sent,
            "order_types_supported_count": order_types_check["supported_count"],
            "tls_cert_valid": tls_check.get("valid_now"),
            "tls_cert_expiry": tls_check.get("not_after"),
            "tls_cert_cn": tls_check.get("cn"),
        },
        "risk_note": (
            "EBICS exposure: read-only probe. INI/HIA/HPB are unsigned so they "
            "cannot initialize a real subscriber. Server responding with EBICS "
            "XML (vs HTTP 404 HTML) confirms EBICS endpoint. Order types "
            "returning 061001 (UNKNOWN_USER) = supported but user not registered. "
            "091116 (INVALID_ORDER_TYPE) = explicitly unsupported. Banks should "
            "restrict EBICS to TLS client-cert/mTLS-authenticated TPPs (DORA, "
            "SWIFT CSP Control 2.x segmentation, EBA PSD2 RTS-SCA)."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
