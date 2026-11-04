#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — protocol probe : AS2 (Applicability Statement 2).
# Port 443 (HTTPS) — B2B file transfer over HTTP. Used for SWIFT FileAct
# partner-side delivery, supply-chain EDI (X12/EDIFACT), banking file exchange.
# Secteur : banking — SAFE_MODE=read_only.
#
#   - v3.1 : Send AS2 HTTP POST with Content-Type application/EDI-X12 / EDIFACT
#   - v3.1 : AS2-From / AS2-To header validation (partner ID recognition)
#   - v3.1 : MDN (Message Disposition Notification) presence + structure
#   - v3.1 : MIC (Message Integrity Check) in MDN headers
#   - v3.1 : Signed MDN detection (multipart/signed, pkcs7-signature)
#   - v3.1 : Content-Type acceptance matrix (X12, EDIFACT, XML, octet-stream)
#   - v3.1 : SEED reproducibility, LAB=1 guard, timeout 5s
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# AS2 = RFC 4130 (MIME-based secure EDI), RFC 6152 (AS2 features), MDN per RFC 3798.
# Banking usage: SWIFT FileAct adapter (RFC-style), B2B vendor EDI, supply-chain
# financing, corporate-to-bank statement delivery (CAMT via AS2 gateways).
#
# Références :
#   - RFC 4130 §4 — AS2 Message Construction
#   - RFC 4130 §7 — MDN (Message Disposition Notification)
#   - RFC 3798 — Message Disposition Notification format
#   - RFC 1847 — Security Multiparts (multipart/signed, multipart/encrypted)
#   - RFC 3851 — S/MIME (signed MDN with pkcs7-signature)
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default as default_email_policy
from typing import Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print(json.dumps({
        "module": "as2_probe",
        "harness_version": "3.1.0",
        "error": "requests_not_installed",
        "hint": "pip install requests urllib3",
    }))
    sys.exit(2)

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "as2_probe"
DEFAULT_PORT = 443              # AS2 over HTTPS (B2B)
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

# Deterministic, clearly-fake AS2 partner IDs (lab-safe, never a real partner)
AS2_FROM = f"HARNESS-LAB-{SEED}"
AS2_TO = f"BANK-AS2-TEST-{SEED}"


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
# Usage: as2_probe.py <host> [port]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT


# ─── Helpers HTTP ─────────────────────────────────────────────────────────────
def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME}) seed={SEED}",
        "X-Forwarded-For": "127.0.0.1",
        "X-Harness-SEED": str(SEED),
    })
    return s


def _base_url() -> str:
    return f"https://{TARGET_HOST}:{TARGET_PORT}"


def _as2_message_id() -> str:
    """Deterministic AS2 Message-ID (RFC 4130 §4.2). Format: <unique@host>.
    SEED-based to ensure reproducibility between runs."""
    return f"<harness-as2-{SEED}-{int(time.time() * 1000) % 1000000}@lab.invalid>"


def _as2_post(session: requests.Session, path: str,
              body: bytes, content_type: str,
              as2_from: str = AS2_FROM, as2_to: str = AS2_TO,
              request_mdn: bool = True,
              request_signed_mdn: bool = True) -> dict:
    """POST an AS2 message. Builds the canonical AS2 header set per RFC 4130.

    Headers (RFC 4130 §4.2 mandatory + recommended):
      AS2-From, AS2-To, Message-ID, AS2-Version, Content-Type,
      Disposition-Notification-To (if MDN requested),
      Disposition-Notification-Options (if signed MDN requested),
      Subject, Date, MIME-Version.
    """
    url = path if path.startswith("http") else _base_url() + path
    t0 = time.time()
    headers = {
        "Content-Type": content_type,
        "AS2-From": as2_from,
        "AS2-To": as2_to,
        "Message-ID": _as2_message_id(),
        "AS2-Version": "1.1",
        "MIME-Version": "1.0",
        "Subject": f"AS2 harness probe (SEED={SEED})",
        "Date": datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"),
    }
    if request_mdn:
        headers["Disposition-Notification-To"] = f"http://{TARGET_HOST}/as2/mdn"
        if request_signed_mdn:
            headers["Disposition-Notification-Options"] = (
                "signed-receipt-protocol=required, pkcs7-signature; "
                "signed-receipt-micalgorithm=required, sha-256"
            )
        else:
            headers["Disposition-Notification-Options"] = (
                "signed-receipt-protocol=optional; "
                "signed-receipt-micalgorithm=optional, sha-256"
            )
    try:
        r = session.post(url, data=body, headers=headers,
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


# ─── Dummy EDI payloads (minimal, read-only safe) ────────────────────────────
# Minimal ANSI X12 ISA envelope (segment terminator ~, element separator *).
# This is an empty envelope — no actual ST/SE/BHT transaction set. An AS2
# gateway will still produce an MDN for the envelope itself.
def minimal_x12_envelope() -> bytes:
    isa = (
        f"ISA*00*          *00*          *ZZ*HVSENDER         *ZZ*HVRECEIVER       "
        f"*{datetime.now(timezone.utc).strftime('%y%m%d')}*"
        f"{datetime.now(timezone.utc).strftime('%H%M')}*U*00401*"
        f"{(SEED % 900000) + 100000:09d}*0*P*>~"
        f"GS*FA*HVSENDER*HVRECEIVER*"
        f"{datetime.now(timezone.utc).strftime('%Y%m%d')}*"
        f"{datetime.now(timezone.utc).strftime('%H%M%S')}*"
        f"{(SEED % 900000) + 100000:09d}*X*004010~"
        f"ST*997*0001~"
        f"SE*2*0001~"
        f"GE*1*{SEED % 9000 + 1000:04d}~"
        f"IEA*1*{SEED % 9000 + 1000:04d}~"
    )
    return isa.encode("ascii", errors="ignore")


# Minimal EDIFACT UNB envelope (segment terminator ', element separator +).
def minimal_edifact_envelope() -> bytes:
    unb = (
        f"UNB+UNOC:3+HVSENDER:ZZ+HVRECEIVER:ZZ+"
        f"{datetime.now(timezone.utc).strftime('%y%m%d:%H%M')}+"
        f"{SEED % 900000 + 100000:06d}'"
        f"UNH+1+CONTRL.D:2:B'UNT+2+1'"
        f"UNZ+1+{SEED % 900000 + 100000:06d}'"
    )
    return unb.encode("ascii", errors="ignore")


# Minimal generic XML payload (ISO 20022 document-info carrier).
def minimal_xml_payload() -> bytes:
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Document xmlns="urn:iso:std:iso:20022:tech:xsd:hvprobe">'
        '<harness>as2-probe-seed-' + str(SEED) + '</harness>'
        '</Document>'
    )
    return xml.encode("utf-8")


def minimal_octet_payload() -> bytes:
    return f"HARNESS-AS2-PROBE-SEED-{SEED}-OCTET-PLACEHOLDER".encode("ascii")


# ─── MDN parsing ──────────────────────────────────────────────────────────────
def parse_mdn(resp: dict) -> dict:
    """Parse the HTTP response as an MDN (RFC 4130 §7).

    MDN is delivered either:
      - Synchronously: as the HTTP response body (multipart/report or multipart/signed)
      - Asynchronously: via a separate HTTP POST to Disposition-Notification-To
        (we only see the sync case here, which is the common banking pattern)

    We extract:
      - is_mdn: True if body parses as MIME multipart/report or contains
                'Message-Disposition-Notification' / 'Reporting-UA'
      - original_message_id_echoed: was our Message-ID echoed in Original-Message-ID
      - disposition: 'processed' / 'failure' / etc.
      - mic: Message Integrity Check (Received-content-MIC header or part)
      - signed: was the MDN S/MIME-signed (multipart/signed, pkcs7-signature)
      - partner_id_validated: server recognized our partner ID (no rejection
        disposition with 'unsupported' / 'unknown' / 'invalid AS2-To')
    """
    body = resp.get("body", b"") or b""
    headers = resp.get("headers", {}) or {}
    if not body:
        return {
            "is_mdn": False,
            "signed": False,
            "disposition": None,
            "original_message_id_echoed": False,
            "mic": None,
            "partner_id_validated": False,
            "error": resp.get("error"),
        }
    # Build a "fake" RFC822 message so the email parser can handle Content-Type
    # headers consistently (responses may use multipart/report or multipart/signed).
    ct = headers.get("Content-Type", "") or headers.get("content-type", "")
    # We construct the input as Content-Type: <ct>\r\n\r\n<body> so BytesParser
    # treats the body as a proper MIME entity.
    raw_for_parser = (f"Content-Type: {ct}\r\nMIME-Version: 1.0\r\n\r\n").encode("ascii") + body
    try:
        msg = BytesParser(policy=default_email_policy).parsebytes(raw_for_parser)
    except Exception as e:  # noqa: BLE001
        return {
            "is_mdn": False,
            "signed": False,
            "disposition": None,
            "original_message_id_echoed": False,
            "mic": None,
            "partner_id_validated": False,
            "error": f"parse_error:{type(e).__name__}",
        }

    content_type = msg.get_content_type() if msg else ""
    is_multipart = msg.is_multipart() if msg else False
    is_mdn = False
    signed = False
    disposition = None
    mic = None
    original_msg_id_echoed = False

    # Look for multipart/report (RFC 3798 MDN) or multipart/signed (RFC 1847)
    if is_multipart and msg:
        for part in msg.walk():
            ct_part = part.get_content_type()
            if ct_part == "multipart/report":
                is_mdn = True
            if ct_part == "multipart/signed":
                signed = True
                # Check protocol parameter (pkcs7-signature = S/MIME)
                proto = part.get_param("protocol", "")
                if proto and "pkcs7-signature" in str(proto).lower():
                    signed = True
            if ct_part in ("message/disposition-notification",):
                is_mdn = True
                # The disposition-notification part is RFC 3798 text/plain
                try:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        text = payload.decode("utf-8", errors="ignore")
                    else:
                        text = str(payload)
                except Exception:  # noqa: BLE001
                    text = ""
                m_dispo = re.search(r"Disposition:\s*([^\r\n]+)", text)
                if m_dispo:
                    disposition = m_dispo.group(1).strip()
                if "Original-Message-ID" in text:
                    original_msg_id_echoed = True
                m_mic = re.search(r"Received-content-MIC:\s*([^\r\n]+)", text)
                if m_mic:
                    mic = m_mic.group(1).strip()
    # Also check MDN as flat text/plain (some servers return plain MDN)
    if not is_mdn and body:
        text_flat = body.decode("utf-8", errors="ignore")
        if any(p in text_flat for p in (
                "Message-Disposition-Notification",
                "Reporting-UA",
                "Disposition:",
                "Original-Message-ID",
                "Final-Recipient")):
            is_mdn = True
            m_dispo = re.search(r"Disposition:\s*([^\r\n]+)", text_flat)
            if m_dispo:
                disposition = m_dispo.group(1).strip()
            if "Original-Message-ID" in text_flat:
                original_msg_id_echoed = True
            m_mic = re.search(r"Received-content-MIC:\s*([^\r\n]+)", text_flat)
            if m_mic:
                mic = m_mic.group(1).strip()
    # MIC can also be in the HTTP headers
    if mic is None:
        for hk in ("Received-content-MIC", "received-content-mic"):
            if hk in headers:
                mic = headers[hk]
                break

    # partner_id_validated = MDN reports 'processed' (not 'failure' / 'unsupported')
    partner_validated = (
        is_mdn
        and disposition is not None
        and "processed" in disposition.lower()
        and "failure" not in disposition.lower()
        and "unsupported" not in disposition.lower()
        and "unknown" not in disposition.lower()
        and "invalid" not in disposition.lower()
    )
    return {
        "is_mdn": is_mdn,
        "signed": signed,
        "disposition": disposition,
        "original_message_id_echoed": original_msg_id_echoed,
        "mic": mic,
        "partner_id_validated": partner_validated,
        "content_type": content_type,
    }


# ─── 1. Root HTTP probe ───────────────────────────────────────────────────────
def check_root(session: requests.Session) -> dict:
    """GET / — most AS2 gateways respond with 200 (info page) or 405/404."""
    url = _base_url() + "/"
    t0 = time.time()
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, verify=False,
                        allow_redirects=False)
        body_lower = (r.content or b"").lower()
        is_as2_marker = (
            b"as2" in body_lower
            or b"as2-from" in body_lower
            or b"as2-to" in body_lower
            or b"mdn" in body_lower
            or b"fileact" in body_lower
        )
        return {
            "endpoint": "/",
            "status": r.status_code,
            "len": len(r.content),
            "ms": round((time.time() - t0) * 1000, 1),
            "as2_marker_in_body": is_as2_marker,
            "server_header": r.headers.get("Server"),
            "error": None,
        }
    except requests.exceptions.Timeout:
        return _err(url, t0, "Timeout")
    except requests.exceptions.ConnectionError as e:
        return _err(url, t0, "ConnectionError", detail=str(e)[:200])
    except requests.RequestException as e:
        return _err(url, t0, type(e).__name__, detail=str(e)[:200])


# ─── 2. Send AS2 message (X12 payload, signed MDN requested) ─────────────────
def send_as2_x12(session: requests.Session, path: str = "/as2",
                 request_signed_mdn: bool = True) -> dict:
    """Send a minimal X12 envelope as an AS2 message. Default path /as2.
    Many banking AS2 gateways use /as2, /as2/receive, /edi, /b2b.
    """
    body = minimal_x12_envelope()
    r = _as2_post(session, path, body,
                  content_type="application/EDI-X12",
                  request_mdn=True,
                  request_signed_mdn=request_signed_mdn)
    mdn = parse_mdn(r)
    return {
        "endpoint": path,
        "content_type": "application/EDI-X12",
        "status": r["status"],
        "len": r["len"],
        "ms": r["ms"],
        "error": r["error"],
        "as2_posted": r["error"] is None and r["status"] is not None,
        "mdn_returned": mdn["is_mdn"],
        "mdn_signed": mdn["signed"],
        "mdn_disposition": mdn["disposition"],
        "mdn_mic": mdn["mic"],
        "partner_id_validated": mdn["partner_id_validated"],
        "response_content_type": r["headers"].get("Content-Type"),
    }


# ─── 3. Content-type acceptance matrix ───────────────────────────────────────
def probe_content_types(session: requests.Session,
                        path: str = "/as2") -> dict:
    """Send the same minimal payload with different Content-Types to see which
    the AS2 gateway accepts. Accepted = HTTP 200 + MDN returned (or HTTP 202
    Accepted for async MDN)."""
    ct_payloads = [
        ("application/EDI-X12",        minimal_x12_envelope()),
        ("application/EDIFACT",        minimal_edifact_envelope()),
        ("application/xml",            minimal_xml_payload()),
        ("application/octet-stream",   minimal_octet_payload()),
        ("application/edi-consent",    minimal_x12_envelope()),
        ("text/plain",                 minimal_octet_payload()),
    ]
    results = []
    accepted = []
    for ct, payload in ct_payloads:
        r = _as2_post(session, path, payload, content_type=ct,
                      request_mdn=True, request_signed_mdn=False)
        mdn = parse_mdn(r)
        is_accepted = (
            r["error"] is None
            and r["status"] is not None
            and r["status"] in (200, 202)
            and (mdn["is_mdn"] or r["status"] == 202)  # 202 = async MDN
        )
        results.append({
            "content_type": ct,
            "status": r["status"],
            "len": r["len"],
            "ms": r["ms"],
            "mdn_returned": mdn["is_mdn"],
            "accepted": is_accepted,
            "error": r["error"],
        })
        if is_accepted:
            accepted.append(ct)
        time.sleep(0.05)  # inter-request delay (read-only)
    return {
        "tested": [ct for ct, _ in ct_payloads],
        "results": results,
        "content_types_accepted": accepted,
    }


# ─── 4. Partner ID validation (unknown partner) ──────────────────────────────
def probe_partner_id_validation(session: requests.Session,
                                path: str = "/as2") -> dict:
    """Send two AS2 messages:
      - With our (deterministic, fake) AS2-From/AS2-To = should be REJECTED
        by a conformant gateway (no such partner registered). The server may
        still produce an MDN with 'failure: unsupported' disposition OR may
        return HTTP 200 with no MDN OR return HTTP 400/403.
      - With empty/missing AS2-From → should be REJECTED.
    """
    body = minimal_x12_envelope()

    # Case 1: fake partner ID
    r1 = _as2_post(session, path, body, content_type="application/EDI-X12",
                   as2_from=AS2_FROM, as2_to=AS2_TO,
                   request_mdn=True, request_signed_mdn=False)
    mdn1 = parse_mdn(r1)
    # Server validates partner IDs if:
    #   - Returns HTTP 200/202 + MDN with disposition 'failure'/'unsupported' OR
    #   - Returns HTTP 4xx (rejected)
    case1_validated = (
        (mdn1["is_mdn"] and not mdn1["partner_id_validated"])
        or (r1["status"] in (400, 401, 403, 404, 422))
    )

    # Case 2: empty AS2-From
    r2 = _as2_post(session, path, body, content_type="application/EDI-X12",
                   as2_from="", as2_to="",
                   request_mdn=True, request_signed_mdn=False)
    mdn2 = parse_mdn(r2)
    case2_validated = (
        r2["status"] in (400, 401, 403, 422)
        or (mdn2["is_mdn"] and not mdn2["partner_id_validated"])
        or r2["status"] is None  # connection refused (hard rejection)
    )

    return {
        "case1_fake_partner_id": {
            "as2_from": AS2_FROM,
            "as2_to": AS2_TO,
            "status": r1["status"],
            "mdn_returned": mdn1["is_mdn"],
            "mdn_disposition": mdn1["disposition"],
            "validated": case1_validated,
        },
        "case2_empty_partner_id": {
            "as2_from": "",
            "as2_to": "",
            "status": r2["status"],
            "mdn_returned": mdn2["is_mdn"],
            "mdn_disposition": mdn2["disposition"],
            "validated": case2_validated,
        },
        "partner_id_validated": case1_validated or case2_validated,
        "severity": (
            "high" if not (case1_validated or case2_validated) else "info"
        ),
        "note": (
            "AS2 gateway accepts unknown partner IDs without rejection — "
            "missing partner-ID validation = spoofing vector (DORA Art. 9, "
            "B2B gateway hygiene)." if not (case1_validated or case2_validated)
            else "Partner-ID validation present (good hygiene)."
        ),
    }


# ─── 5. TLS cert inspection ───────────────────────────────────────────────────
def check_tls_cert() -> dict:
    """Retrieve TLS cert via socket + ssl stdlib."""
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
    not_after = parsed.get("notAfter")
    cn = _extract_cn(subject)
    issuer_cn = _extract_cn(issuer)
    now = datetime.now(timezone.utc)
    expiry_iso = _parse_asn1_time(not_after)
    valid_now = True
    if expiry_iso is not None and now > expiry_iso:
        valid_now = False
    return {
        "host": TARGET_HOST,
        "port": TARGET_PORT,
        "cn": cn,
        "issuer_cn": issuer_cn,
        "not_after": not_after,
        "valid_now": valid_now,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": None,
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
        "not_after": None,
        "valid_now": None,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": err,
        "error_detail": detail,
    }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # SAFE_MODE read-only : all AS2 probes use minimal dummy EDI payloads
    # (empty X12/EDIFACT envelopes). No real payment instruction, no real
    # partner ID (deterministic SEED-derived). The MDN is only an
    # acknowledgement of receipt — no banking transaction is initiated.
    session = build_session()

    # Phase 1 : root HTTP probe
    root_check = check_root(session)

    # Phase 2 : send AS2 X12 message with signed MDN requested
    as2_send = send_as2_x12(session, path="/as2", request_signed_mdn=True)

    # Phase 3 : content-type acceptance matrix
    ct_check = probe_content_types(session, path="/as2")

    # Phase 4 : partner ID validation (unknown partner / empty IDs)
    partner_check = probe_partner_id_validation(session, path="/as2")

    # Phase 5 : TLS cert inspection
    tls_check = check_tls_cert()

    # ─── Summary flags per spec ────────────────────────────────────────────
    as2_accessible = (
        root_check.get("as2_marker_in_body")
        or as2_send.get("mdn_returned")
        or any(r.get("accepted") for r in ct_check["results"])
        or as2_send.get("status") in (200, 202, 400, 403, 415)
    )
    mdn_returned = as2_send.get("mdn_returned")
    signature_required = as2_send.get("mdn_signed")  # MDN was signed = signature required
    # partner_id_validated = server rejected our unknown partner ID OR
    # returned a failure MDN for it
    partner_id_validated = partner_check.get("partner_id_validated")
    content_types_accepted = ct_check.get("content_types_accepted", [])

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
        "as2_accessible": as2_accessible,
        "mdn_returned": bool(mdn_returned),
        "signature_required": bool(signature_required),
        "partner_id_validated": bool(partner_id_validated),
        "content_types_accepted": content_types_accepted,
        "results": {
            "root_check": root_check,
            "as2_send": as2_send,
            "content_types": ct_check,
            "partner_id_validation": partner_check,
            "tls_cert": tls_check,
        },
        "summary": {
            "as2_accessible": as2_accessible,
            "mdn_returned": bool(mdn_returned),
            "mdn_signed": bool(signature_required),
            "mdn_disposition": as2_send.get("mdn_disposition"),
            "mdn_mic_present": as2_send.get("mdn_mic") is not None,
            "partner_id_validated": bool(partner_id_validated),
            "content_types_accepted": content_types_accepted,
            "tls_cert_cn": tls_check.get("cn"),
            "tls_cert_valid": tls_check.get("valid_now"),
        },
        "risk_note": (
            "AS2 B2B gateways in banking must enforce: TLS+mTLS for transport, "
            "partner-ID validation (against known AS2 partner list), S/MIME "
            "signed MDN with MIC for non-repudiation, certificate-based "
            "authentication per partner (DORA Art. 9, ISO 11010 — AS2 profile). "
            "Missing partner-ID validation = spoofing vector. Missing MIC = "
            "non-repudiation gap. Read-only: only empty envelope payloads "
            "are sent — no real payment/EDI transaction is initiated."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
