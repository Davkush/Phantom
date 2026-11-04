#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — HL7 probe (health sector).
# Phase 2 reconnaissance against HL7 v2 (MLLP) and FHIR (R4 / SMART) APIs.
#
# Tests:
#   - MLLP framing (Minimal Lower Layer Protocol) over TCP 2575
#     frame = 0x0B + message + 0x1C + 0x0D
#   - ADT^A01  (admission notification)         — check if accepted w/o auth
#   - QRY^A19  (patient query)                  — check if PHI returned w/o auth
#   - FHIR /fhir/Patient, /fhir/Observation     — anonymous data access
#   - SMART on FHIR OAuth configuration         — /.well-known/smart-configuration
#   - FHIR consent filtering                    — /fhir/Patient?_count=100
#
# Safety:
#   - LAB=1 guard — refuses to run outside an explicit lab environment
#   - SAFE_MODE=read_only for health sector — no ADT injection in production
#     (we send the ADT^A01 only when SAFE_MODE=full; in read_only mode we
#     only probe the listener + send QRY^A19 read-only queries)
#   - 5s socket / HTTP timeout on every connection
#   - PHI masking: patient names / MRN / PID never echoed — only counts
#
# Cadre légal : laboratoires isolés uniquement (HIPAA / HDS / RGPD).
import json
import os
import re
import socket
import struct
import sys
import time
from typing import Optional

# Make sector_base importable when this module is run directly as a script.
_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULES_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _MODULES_ROOT not in sys.path:
    sys.path.insert(0, _MODULES_ROOT)

try:
    from sector_base import get_sector_config, get_safe_mode, is_write_allowed
    SECTOR_BASE_OK = True
except Exception as exc:  # noqa: BLE001
    SECTOR_BASE_OK = False
    _SECTOR_BASE_ERR = str(exc)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "hl7_probe"
DEFAULT_TIMEOUT = 5  # seconds — required by sector policy

# ─── MLLP framing (HL7 v2 Minimal Lower Layer Protocol) ─────────────
MLLP_START = 0x0B   # Vertical Tab
MLLP_END1 = 0x1C    # File Separator
MLLP_END2 = 0x0D    # Carriage Return

# MLLP frame = <SB> + message + <EB><CR>
# Use struct.pack to make the binary framing explicit and portable.
MLLP_FRAME_START = struct.pack("B", MLLP_START)
MLLP_FRAME_END = struct.pack("BB", MLLP_END1, MLLP_END2)


def wrap_mllp(message: str) -> bytes:
    """Wrap an HL7 v2 message string in MLLP framing."""
    return MLLP_FRAME_START + message.encode("ascii", errors="replace") \
        + MLLP_FRAME_END


def unwrap_mllp(frame: bytes) -> Optional[str]:
    """Strip MLLP framing and decode the inner message. Returns None if the
    frame is incomplete or malformed."""
    if not frame or frame[0] != MLLP_START:
        return None
    # Find terminator \x1C\x0D
    end_idx = frame.find(MLLP_FRAME_END)
    if end_idx == -1:
        return None
    inner = frame[1:end_idx]
    try:
        return inner.decode("ascii", errors="replace")
    except Exception:  # noqa: BLE001
        return None


# ─── HL7 v2 message templates ───────────────────────────────────────
# Field separator |, encoding chars ^~\& (component ^, repetition ~,
# escape \, sub-component &).
HL7_FIELD_SEP = "|"
HL7_ENCODING_CHARS = "^~\\&"
HL7_SEGMENT_SEP = "\r"  # CR — HL7 v2 uses \r as segment terminator


def _now_hl7() -> str:
    """YYYYMMDDHHMMSS — HL7 v2 TS (time stamp) format."""
    return time.strftime("%Y%m%d%H%M%S", time.gmtime())


def build_adt_a01(message_id: str = "HARNESS0001",
                  patient_mrn: str = "LAB-000-FAKE") -> str:
    """Build an ADT^A01 (admit/visit notification) HL7 v2.5 message.

    NOTE: this is an INJECTION (write) operation. It is only sent when
    SAFE_MODE=full. In read_only mode we never emit it — we only check
    whether the MLLP listener accepts the TCP connection.
    """
    ts = _now_hl7()
    segments = [
        f"MSH{HL7_FIELD_SEP}{HL7_ENCODING_CHARS}{HL7_FIELD_SEP}HARNESS"
        f"{HL7_FIELD_SEP}HARNESS_FAC{HL7_FIELD_SEP}LAB_HIS"
        f"{HL7_FIELD_SEP}LAB_HIS{HL7_FIELD_SEP}{ts}{HL7_FIELD_SEP}"
        f"{HL7_FIELD_SEP}ADT^A01{HL7_FIELD_SEP}{message_id}{HL7_FIELD_SEP}"
        f"P{HL7_FIELD_SEP}2.5",
        f"EVN{HL7_FIELD_SEP}A01{HL7_FIELD_SEP}{ts}",
        # PID segment — uses a fake MRN for the lab. Real patient data is
        # never used by this harness.
        f"PID{HL7_FIELD_SEP}1{HL7_FIELD_SEP}{HL7_FIELD_SEP}{patient_mrn}"
        f"{HL7_FIELD_SEP}{HL7_FIELD_SEP}LABDOE^JOHN"
        f"{HL7_FIELD_SEP}19700101{HL7_FIELD_SEP}M",
        f"PV1{HL7_FIELD_SEP}1{HL7_FIELD_SEP}I{HL7_FIELD_SEP}ICU^1",
    ]
    return HL7_SEGMENT_SEP.join(segments) + HL7_SEGMENT_SEP


def build_qry_a19(message_id: str = "HARNESS0002",
                  patient_mrn: str = "LAB-000-FAKE") -> str:
    """Build a QRY^A19 (patient query) HL7 v2.5 message."""
    ts = _now_hl7()
    segments = [
        f"MSH{HL7_FIELD_SEP}{HL7_ENCODING_CHARS}{HL7_FIELD_SEP}HARNESS"
        f"{HL7_FIELD_SEP}HARNESS_FAC{HL7_FIELD_SEP}LAB_HIS"
        f"{HL7_FIELD_SEP}LAB_HIS{HL7_FIELD_SEP}{ts}{HL7_FIELD_SEP}"
        f"{HL7_FIELD_SEP}QRY^A19{HL7_FIELD_SEP}{message_id}{HL7_FIELD_SEP}"
        f"P{HL7_FIELD_SEP}2.5",
        # QRD — query definition. Format:
        # QRD|ts|R|I|QRY|queryid|delimited||||filter|...
        f"QRD{HL7_FIELD_SEP}{ts}{HL7_FIELD_SEP}R{HL7_FIELD_SEP}I"
        f"{HL7_FIELD_SEP}QRY{HL7_FIELD_SEP}{message_id}"
        f"{HL7_FIELD_SEP}{HL7_FIELD_SEP}{HL7_FIELD_SEP}{HL7_FIELD_SEP}"
        f"{patient_mrn}{HL7_FIELD_SEP}DEM{HL7_FIELD_SEP}",
    ]
    return HL7_SEGMENT_SEP.join(segments) + HL7_SEGMENT_SEP


# ─── HL7 ACK parsing ────────────────────────────────────────────────
# ACK^A01 segment field MSA-1 = AA (accept), AE (error), AR (reject).
ACK_ACCEPT_RE = re.compile(r"MSA\|AA\|", re.IGNORECASE)
ACK_REJECT_RE = re.compile(r"MSA\|A[ER]\|", re.IGNORECASE)
# A QRY^A19 response contains a PID segment with patient data.
PID_RE = re.compile(r"(^|\r)PID\|")
# Count of PID segments inside a QRY^A19 response = patient records returned.
def _count_pid(msg: str) -> int:
    return len(PID_RE.findall(msg))


# ─── TCP / MLLP transport ───────────────────────────────────────────
def _port_open(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def send_mllp_message(host: str, port: int, msg_type: str,
                      message_id: str, patient_mrn: str,
                      timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Send an HL7 v2 message over MLLP and capture the ACK / response.

    msg_type : 'ADT_A01' or 'QRY_A19'
    """
    out = {"sent": False, "ack_received": False, "ack_code": "",
           "patient_records_returned": 0, "phi_in_response": False,
           "raw_response_redacted": True, "detail": ""}
    if msg_type == "ADT_A01":
        msg = build_adt_a01(message_id, patient_mrn)
    elif msg_type == "QRY_A19":
        msg = build_qry_a19(message_id, patient_mrn)
    else:
        out["detail"] = f"unknown msg_type={msg_type}"
        return out
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(wrap_mllp(msg))
            out["sent"] = True
            # Read response until we see the MLLP end-of-frame bytes.
            buf = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if MLLP_FRAME_END in buf:
                        break
            except socket.timeout:
                out["detail"] = "recv timeout (no ACK)"
            inner = unwrap_mllp(buf)
            if inner is None:
                out["detail"] = "no MLLP frame received"
                return out
            out["ack_received"] = True
            # Determine ACK code (AA / AE / AR)
            m = ACK_ACCEPT_RE.search(inner)
            if m:
                out["ack_code"] = "AA"
            elif ACK_REJECT_RE.search(inner):
                # AE = error, AR = reject
                m2 = re.search(r"MSA\|([A-Z]{2})\|", inner)
                out["ack_code"] = m2.group(1) if m2 else "A?"
            else:
                # Not an ACK at all — for QRY^A19 this is the query response
                out["ack_code"] = "RESPONSE"
            # For QRY^A19, count PID segments returned (PHI leak)
            pid_count = _count_pid(inner)
            out["patient_records_returned"] = pid_count
            out["phi_in_response"] = pid_count > 0
            # PHI masking: never echo the response body. raw_response_redacted
            # is permanently True — we only expose aggregate metrics.
            out["detail"] = (f"msg_type={msg_type} ack_code={out['ack_code']} "
                             f"pid_count={pid_count}")
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        out["detail"] = f"socket error: {exc}"
    return out


# ─── FHIR REST API probe ────────────────────────────────────────────
# Use urllib from the stdlib so this module has zero third-party deps.
# (requests would be cleaner but isn't always available in the lab image.)
import urllib.request
import urllib.error
import ssl

DEFAULT_FHIR_PORTS = (8080, 8443)

# SMART on FHIR configuration endpoint (smart-app-launch-2 §1.1).
SMART_CONFIG_PATH = "/.well-known/smart-configuration"

# Patient/Observation FHIR endpoints (relative to the FHIR base path).
FHIR_PATHS = (
    "/fhir/Patient",
    "/fhir/Observation",
    "/fhir/metadata",  # CapabilityStatement
)


def _http_get(url: str, timeout: int = DEFAULT_TIMEOUT,
              verify_tls: bool = False) -> tuple[int, bytes, dict]:
    """Perform an anonymous (no Authorization header) HTTP GET.

    Returns (status_code, body_bytes, headers_dict). On network failure,
    returns (-1, b"", {}).
    """
    req = urllib.request.Request(url, headers={
        "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME})",
        "Accept": "application/fhir+json, application/json;q=0.9, */*;q=0.1",
    })
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read()
            return (r.status, body, dict(r.headers))
    except urllib.error.HTTPError as e:
        return (e.code, e.read() or b"", dict(e.headers))
    except (urllib.error.URLError, socket.timeout, OSError, ssl.SSLError):
        return (-1, b"", {})


def check_fhir_endpoints(host: str, ports=(8080, 8443),
                         timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Probe FHIR REST API for anonymous access + SMART OAuth config.

    Returns the consolidated dict for the FHIR portion of the report.
    """
    out = {
        "fhir_accessible": False,
        "anonymous_data": False,
        "endpoints": {},
        "smart_config_found": False,
        "smart_oauth_authorize": "",
        "smart_oauth_token": "",
        "detail": "",
    }
    found_base = None  # first reachable base URL
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        for path in FHIR_PATHS:
            url = f"{scheme}://{host}:{port}{path}"
            status, body, _hdr = _http_get(url, timeout=timeout)
            entry = {"status": status, "body_size": len(body)}
            # Quick-and-dirty FHIR Bundle detection
            is_bundle = (b'"resourceType":"Bundle"' in body
                         or b'"resourceType": "Bundle"' in body)
            has_entries = (b'"entry"' in body)
            entry["is_bundle"] = is_bundle
            entry["has_entries"] = has_entries
            entry["anonymous_data"] = (status == 200 and is_bundle and has_entries)
            out["endpoints"][f"{port}{path}"] = entry
            if entry["anonymous_data"] and not out["anonymous_data"]:
                out["anonymous_data"] = True
                out["fhir_accessible"] = True
                found_base = f"{scheme}://{host}:{port}"
            elif status == 200 and not out["fhir_accessible"]:
                # CapabilityStatement / 200 OK counts as reachable
                out["fhir_accessible"] = True
                found_base = f"{scheme}://{host}:{port}"
    # SMART on FHIR configuration discovery
    if found_base:
        smart_url = f"{found_base}{SMART_CONFIG_PATH}"
        status, body, _hdr = _http_get(smart_url, timeout=timeout)
        if status == 200 and body:
            try:
                cfg = json.loads(body.decode("utf-8", errors="replace"))
                if isinstance(cfg, dict):
                    out["smart_config_found"] = True
                    out["smart_oauth_authorize"] = str(cfg.get("authorize", ""))
                    out["smart_oauth_token"] = str(cfg.get("token", ""))
                    # Note if 'launch' is required (confidential apps)
                    if cfg.get("capabilities"):
                        out["smart_capabilities"] = list(cfg.get("capabilities"))[:20]
            except Exception as exc:  # noqa: BLE001
                out["detail"] = f"smart-configuration parse error: {exc}"
    if not out["fhir_accessible"]:
        out["detail"] = "no FHIR endpoint returned 200/Bundle"
    return out


def check_fhir_consent(host: str, ports=(8080, 8443),
                       timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Check whether consent filtering is applied on /fhir/Patient.

    Strategy:
      - GET /fhir/Patient?_count=100  (request a wide page)
      - If 100 records returned with no consent filtering, we flag
        consent_filtering=False
      - If the endpoint requires auth (401/403) or returns fewer than
        expected records with consent filtering headers, we flag
        consent_filtering=True
    """
    out = {"consent_filtering": False, "detail": ""}
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/fhir/Patient?_count=100"
        status, body, hdr = _http_get(url, timeout=timeout)
        if status == -1:
            continue
        if status in (401, 403):
            # Auth required — consent is enforced at the API gateway
            out["consent_filtering"] = True
            out["detail"] = f"HTTP {status} — auth required at port {port}"
            return out
        if status == 200:
            try:
                bundle = json.loads(body.decode("utf-8", errors="replace"))
                entries = bundle.get("entry", []) if isinstance(bundle, dict) else []
                entry_count = len(entries)
                # Heuristic: if 100 records are returned with NO filtering
                # indication, consent filtering is likely NOT applied.
                # If the server explicitly returns fewer records or sets
                # X-Consent-Filtered / X-Access-Scope headers, it IS.
                consent_headers = [
                    k for k in hdr
                    if any(t in k.lower() for t in
                           ("consent", "scope", "access", "permission"))
                ]
                if entry_count >= 100 and not consent_headers:
                    out["consent_filtering"] = False
                    out["detail"] = (
                        f"100 records returned with no consent headers — "
                        f"filtering NOT applied (port {port})"
                    )
                elif entry_count < 100 and consent_headers:
                    out["consent_filtering"] = True
                    out["detail"] = (
                        f"{entry_count} records + consent headers {consent_headers} "
                        f"(port {port})"
                    )
                elif consent_headers:
                    out["consent_filtering"] = True
                    out["detail"] = (
                        f"consent headers present {consent_headers} "
                        f"(port {port}, entries={entry_count})"
                    )
                else:
                    # No explicit signal — flag as ambiguous / not-applied
                    out["consent_filtering"] = False
                    out["detail"] = (
                        f"{entry_count} entries, no consent headers "
                        f"(port {port}) — filtering NOT detected"
                    )
                return out
            except Exception as exc:  # noqa: BLE001
                out["detail"] = f"parse error port {port}: {exc}"
                continue
    return out


# ─── LAB guard ──────────────────────────────────────────────────────
def lab_guard() -> bool:
    """Refuse to run unless LAB=1 is set in the environment."""
    return os.environ.get("LAB") == "1"


# ─── CLI args ───────────────────────────────────────────────────────
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("HL7_HOST", "127.0.0.1")
MLLP_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("MLLP_PORT", "2575"))
FHIR_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else int(os.environ.get("FHIR_PORT", "8080"))


# ─── Main entrypoint ────────────────────────────────────────────────
def main() -> int:
    # 1. LAB guard
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "LAB guard not satisfied",
            "detail": "Set LAB=1 in the environment to confirm lab authorization.",
        }))
        return 1

    # 2. Sector config — record SAFE_MODE
    sector_cfg = get_sector_config() if SECTOR_BASE_OK else None
    safe_mode = (sector_cfg or {}).get("safe_mode", "read_only")

    t0 = time.time()
    mllp_open = _port_open(TARGET_HOST, MLLP_PORT)
    fhir_ports_to_test = tuple({FHIR_PORT, 8080, 8443})

    out = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "health",
        "safe_mode": safe_mode,
        "target": {
            "host": TARGET_HOST,
            "mllp_port": MLLP_PORT,
            "fhir_ports": list(fhir_ports_to_test),
        },
        "sector_base_ok": SECTOR_BASE_OK,
        # Required output fields
        "mllp_port_open": mllp_open,
        "adt_accepted": False,
        "patient_query_returned": False,
        "fhir_accessible": False,
        "anonymous_data": False,
        "consent_filtering": False,
        # PHI masking confirmation
        "phi_masking": "patient_names_and_mrns_redacted_counts_only",
        "details": {},
        "duration_ms": 0,
    }

    # 3. MLLP / HL7 v2 probe
    if mllp_open:
        # 3a. ADT^A01 — only send when SAFE_MODE=full (this is a write)
        if SECTOR_BASE_OK and not is_write_allowed():
            out["details"]["adt_a01"] = (
                f"SAFE_MODE={safe_mode} — ADT^A01 injection refused "
                "(write op blocked in health sector)"
            )
        else:
            adt_res = send_mllp_message(
                TARGET_HOST, MLLP_PORT, "ADT_A01",
                message_id="HARNESSADT01", patient_mrn="LAB-000-FAKE",
            )
            out["adt_accepted"] = (adt_res.get("ack_code") == "AA")
            out["details"]["adt_a01"] = adt_res

        # 3b. QRY^A19 — read-only patient query (always allowed)
        qry_res = send_mllp_message(
            TARGET_HOST, MLLP_PORT, "QRY_A19",
            message_id="HARNESSQRY19", patient_mrn="LAB-000-FAKE",
        )
        # patient_query_returned = server returned a PID segment (PHI)
        out["patient_query_returned"] = bool(qry_res.get("phi_in_response"))
        out["details"]["qry_a19"] = {
            "ack_code": qry_res.get("ack_code"),
            "patient_records_returned": qry_res.get("patient_records_returned", 0),
            # PHI masking: no patient names — only count
            "phi_leak_detected": qry_res.get("phi_in_response", False),
            "detail": qry_res.get("detail"),
        }
    else:
        out["details"]["mllp"] = f"port {MLLP_PORT} closed"

    # 4. FHIR REST API probe
    fhir_res = check_fhir_endpoints(TARGET_HOST, ports=fhir_ports_to_test)
    out["fhir_accessible"] = bool(fhir_res.get("fhir_accessible"))
    out["anonymous_data"] = bool(fhir_res.get("anonymous_data"))
    out["details"]["fhir"] = {
        "smart_config_found": fhir_res.get("smart_config_found"),
        "smart_oauth_authorize": fhir_res.get("smart_oauth_authorize"),
        "smart_oauth_token": fhir_res.get("smart_oauth_token"),
        "smart_capabilities": fhir_res.get("smart_capabilities", []),
        "endpoints": fhir_res.get("endpoints", {}),
        "detail": fhir_res.get("detail"),
    }

    # 5. FHIR consent filtering check
    consent_res = check_fhir_consent(TARGET_HOST, ports=fhir_ports_to_test)
    out["consent_filtering"] = bool(consent_res.get("consent_filtering"))
    out["details"]["consent"] = consent_res.get("detail", "")

    out["duration_ms"] = int((time.time() - t0) * 1000)
    print(json.dumps(out, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
