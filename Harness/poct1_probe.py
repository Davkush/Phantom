#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — poct1_probe
# Health sector validation module — POCT1-A (Point-of-Care Testing) and
# ASTM E1381/E1394 (serial/TCP framing) probing of POC diagnostic devices.
#
#   - Default port : 5000 (POCT1-A XML over HTTP) — also tries ASTM
#     framing on the same TCP port for backward-compatible devices.
#   - POCT1-A = CLSI (formerly NCCLS) connectivity standard for point-of-
#     care diagnostic devices: blood glucose analyzers, hemoglobin meters,
#     blood gas analyzers, coagulation meters, cardiac markers.
#   - Two transports probed:
#       1. ASTM E1381/E1394 (binary framing):
#            ENQ(0x05) → ACK(0x06) handshake
#            Frame: STX(0x02) + frame# + record + ETX(0x03) + CR(0x0D)
#                   + 2-byte hex checksum (mod 256)
#            Record types: H=Header, P=Patient, O=Order, R=Result,
#                          C=Comment, M=Manufacturer, L=Terminator
#       2. POCT1-A XML over HTTP:
#            POST /poct/discovery  with <POCT1DiscoveryRequest>
#            (READ-ONLY override: GET /poct/discovery — many POCT servers
#             answer a GET with device info without requiring auth)
#   - Functions:
#       astm_checksum       — 2-byte hex checksum (mod 256)
#       build_astm_frame    — STX + frame# + record + ETX + CR + checksum
#       build_header_record — H|...|^|||...|^... record (E1394 §6.2)
#       probe_astm          — ENQ → ACK → H record → response → EOT
#       probe_poct_xml      — GET /poct/discovery → XML device info
#       detect_analyzer     — keyword map for device classification
#   - READ_ONLY=True (health sector safety constraint) — only ASTM query
#     records (H + L terminator) and HTTP GET are emitted. No patient
#     order (O) records, no result (R) records, no POST/PUT — the probe
#     never creates a patient, sends an order, or uploads a result.
#   - HIPAA note: POC patient results (glucose, INR, blood gas) are PHI.
#     Result counts are reported as integers only — no patient names,
#     DOBs, or numeric values are echoed.
#   - SEED env var: deterministic ASTM frame sequence + request IDs.
#   - LAB=1 mandatory. 5 s timeout on every socket / HTTP operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (health) : HIPAA, HDS, RGPD, FDA 21 CFR Part 11,
# CLSI POCT1-A (GP02), ASTM E1381/E1394.
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

# ─── Make sector_base importable from ../../sector_base.py ────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULES_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _MODULES_ROOT not in sys.path:
    sys.path.insert(0, _MODULES_ROOT)

try:
    from sector_base import get_sector_config, get_safe_mode
    SECTOR_BASE_OK = True
except Exception as exc:  # noqa: BLE001 — standalone fallback
    SECTOR_BASE_OK = False
    _SECTOR_BASE_ERR = str(exc)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "poct1_probe"
DEFAULT_PORT = 5000
TIMEOUT_S = 5.0
READ_ONLY = True  # health sector safety constraint (H/L records + GET only)

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── SEED for deterministic frame sequence / request IDs ──────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else None
except ValueError:
    SEED = None
_rng = random.Random(SEED) if SEED is not None else random.Random()


def _next_seq() -> int:
    """Deterministic ASTM frame sequence (1–7 cycling)."""
    return _rng.randint(1, 7)


# ─── LAB guard ─────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ─── Sector / SAFE_MODE config ─────────────────────────────────────────────
if SECTOR_BASE_OK:
    SECTOR_CFG = get_sector_config()
    SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")
else:
    SECTOR_CFG = {"sector": "health", "safe_mode": "read_only"}
    SAFE_MODE = "read_only"


# ═══════════════════════════════════════════════════════════════════════════
#  ASTM E1381 control characters
# ═══════════════════════════════════════════════════════════════════════════
ASTM_ENQ = 0x05   # Enquiry — initiate transmission
ASTM_ACK = 0x06   # Positive acknowledge
ASTM_NAK = 0x15   # Negative acknowledge
ASTM_STX = 0x02   # Start of text
ASTM_ETX = 0x03   # End of text (final frame)
ASTM_ETB = 0x17   # End of block (intermediate frame)
ASTM_CR = 0x0D    # Carriage return
ASTM_LF = 0x0A    # Line feed
ASTM_EOT = 0x04   # End of transmission


def astm_checksum(frame: bytes) -> str:
    """Compute the ASTM E1381 checksum: sum of all bytes from the frame
    number byte (inclusive) through ETX or ETB (inclusive), modulo 256,
    expressed as 2 uppercase hex chars."""
    total = sum(frame) & 0xFF
    return f"{total:02X}"


def build_astm_frame(record: str, frame_no: int = 1,
                     final: bool = True) -> bytes:
    """Build one ASTM E1381 frame.

    Frame = STX + str(frame_no) + record + (ETX if final else ETB) + CR
            + checksum(2 bytes)

    The checksum is computed over [frame_no_byte ... ETX/ETB] (inclusive
    of CR? — NO: per E1381, the checksum is over bytes from frame number
    through ETX/ETB inclusive; CR is not part of the checksum).
    """
    if not 1 <= frame_no <= 7:
        frame_no = 1
    terminator = ASTM_ETX if final else ASTM_ETB
    payload = f"{frame_no}".encode("ascii") + record.encode("ascii", "replace")
    payload_with_term = payload + bytes([terminator])
    csum = astm_checksum(payload_with_term)
    return (bytes([ASTM_STX]) + payload_with_term + bytes([ASTM_CR]) +
            csum.encode("ascii"))


def build_header_record() -> str:
    """Build a minimal ASTM E1394 Header (H) record.

    H|sender_id^type|receiver_id^type|message_comment|message_id|
       password|sender_name|||version|processing_id|||character_set
    Fields per E1394 §6.2. We fill the minimum:
       sender = HVHARNESS
       receiver = *
       message_id = <seq>
       version = 1.0
    """
    ts = time.strftime("%Y%m%d%H%M%S")
    mid = f"HV{ts}{_rng.randint(100, 999)}"
    # H|sender|receiver|||...|^...|||version|P||character_set
    return (
        f"H|HVHARNESS^ANALYZER|*||||||"
        f"{mid}|P|||"
    )


def build_terminator_record() -> str:
    """Build the ASTM E1394 Terminator (L) record: L|1|N"""
    return "L|1|N"


# ═══════════════════════════════════════════════════════════════════════════
#  ASTM probe (E1381/E1394 over TCP)
# ═══════════════════════════════════════════════════════════════════════════
def probe_astm(host: str, port: int) -> Dict:
    """Run the ASTM E1381/E1394 probe.

    Sequence (per ASTM E1381 §5):
       1. Send ENQ.
       2. Wait for ACK (0x06) — server is ready to receive.
       3. Send the Header (H) record frame + ACK wait.
       4. Send the Terminator (L) record frame + ACK wait.
       5. Send EOT.
    If the server sends any record (H, P, O, R, M) back without being
    prompted with an authentication challenge, patient data is exposed
    without auth (READ-ONLY probe — we never send O or R records).

    Returns per-server diagnostics:
       astm_accessible (bool): ENQ was ACKed
       patient_data_accessible (bool): server sent P or R records
       observations_reported (int): count of R records received
       analyzer_type (str): inferred from M record or H record content
       hl7_generation (bool): H record contains HL7 generation hint
       records_received (list[str]): record types received (H/P/O/R/C/M/L)
    """
    result = {
        "astm_accessible": False,
        "patient_data_accessible": False,
        "observations_reported": 0,
        "analyzer_type": "",
        "hl7_generation": False,
        "records_received": [],
        "raw_records_text": "",   # for downstream analyzer-type detection
        "error": None,
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_S)
        sock.connect((host, port))
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        return result

    try:
        # ─── 1. ENQ ────────────────────────────────────────────────────
        sock.sendall(bytes([ASTM_ENQ]))
        try:
            resp = sock.recv(1)
        except (socket.timeout, TimeoutError):
            resp = b""
        if not resp or resp[0] != ASTM_ACK:
            result["error"] = "no_enq_ack"
            # Even a NAK is informative (device alive but rejected)
            if resp and resp[0] == ASTM_NAK:
                result["error"] = "enq_nak"
            return result
        result["astm_accessible"] = True

        # ─── 2. Header record ──────────────────────────────────────────
        h_frame = build_astm_frame(build_header_record(), frame_no=1, final=True)
        sock.sendall(h_frame)
        # Read whatever comes back — may be an ACK followed by frames
        sock.settimeout(TIMEOUT_S)
        chunks: List[bytes] = []
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if len(b"".join(chunks)) > 8192:
                    break
        except (socket.timeout, TimeoutError):
            pass
        buf = b"".join(chunks)

        # Parse ASTM frames out of the buffer
        records_text, record_types, r_count, m_text, h_text = \
            _parse_astm_records(buf)
        result["records_received"] = record_types
        result["raw_records_text"] = records_text
        result["observations_reported"] = r_count
        if record_types:
            # If we received P (patient) or R (result) records without
            # ever sending credentials, patient data is accessible.
            if "P" in record_types or "R" in record_types:
                result["patient_data_accessible"] = True
            # M (manufacturer) record carries device identification
            if m_text:
                a_type, hl7 = detect_analyzer(m_text)
                if a_type:
                    result["analyzer_type"] = a_type
                if hl7:
                    result["hl7_generation"] = True
            elif h_text:
                a_type, hl7 = detect_analyzer(h_text)
                if a_type:
                    result["analyzer_type"] = a_type
                if hl7:
                    result["hl7_generation"] = True

        # ─── 3. ACK any received frames, then send Terminator + EOT ────
        # Send ACK to acknowledge any inbound records (politeness).
        if record_types:
            try:
                sock.sendall(bytes([ASTM_ACK]))
            except Exception:  # noqa: BLE001 — best-effort
                pass
        l_frame = build_astm_frame(build_terminator_record(),
                                   frame_no=1, final=True)
        try:
            sock.sendall(l_frame)
        except Exception:  # noqa: BLE001 — best-effort
            pass
        try:
            sock.sendall(bytes([ASTM_EOT]))
        except Exception:  # noqa: BLE001 — best-effort
            pass

    except OSError as e:
        result["error"] = f"io_error:{type(e).__name__}"
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
    return result


def _parse_astm_records(buf: bytes) -> Tuple[str, List[str], int, str, str]:
    """Extract ASTM E1381 frames from a byte buffer and decode their
    record payloads. Returns (joined_records_text, record_types,
    result_count, manufacturer_record_text, header_record_text)."""
    if not buf:
        return "", [], 0, "", ""
    # Filter ACK/NAK/ENQ/EOT control bytes
    text = buf.decode("ascii", errors="replace")
    # Split on STX to find frame starts
    records: List[str] = []
    record_types: List[str] = []
    m_text = ""
    h_text = ""
    r_count = 0
    parts = text.split(chr(ASTM_STX))
    for part in parts[1:]:  # skip the part before the first STX
        # Find the terminator: ETX (0x03) or ETB (0x17)
        etx_idx = part.find(chr(ASTM_ETX))
        etb_idx = part.find(chr(ASTM_ETB))
        end_idx = -1
        if etx_idx >= 0 and (etb_idx < 0 or etx_idx < etb_idx):
            end_idx = etx_idx
        elif etb_idx >= 0:
            end_idx = etb_idx
        if end_idx < 0:
            continue
        # Frame payload starts at char index 0 (frame number) — skip it
        if end_idx <= 1:
            continue
        payload = part[1:end_idx]   # skip frame number byte
        # Strip the trailing checksum (2 chars after CR)
        cr_idx = payload.find(chr(ASTM_CR))
        if cr_idx >= 0:
            payload = payload[:cr_idx]
        records.append(payload)
        if payload:
            rtype = payload[0].upper()
            record_types.append(rtype)
            if rtype == "R":
                r_count += 1
            elif rtype == "M":
                m_text = payload
            elif rtype == "H":
                h_text = payload
    return "|".join(records), record_types, r_count, m_text, h_text


# ═══════════════════════════════════════════════════════════════════════════
#  Analyzer type detection (keyword-based)
# ═══════════════════════════════════════════════════════════════════════════
# Keywords map manufacturer / device-name strings to analyzer categories.
_ANALYZER_KEYWORDS: List[Tuple[str, str]] = [
    ("glucose",     "glucose_analyzer"),
    ("glucometer",  "glucose_analyzer"),
    ("accu-chek",   "glucose_analyzer"),
    ("one touch",   "glucose_analyzer"),
    ("freestyle",   "glucose_analyzer"),
    ("hemoglobin",  "hemoglobin_meter"),
    ("hemocue",     "hemoglobin_meter"),
    ("hgb",         "hemoglobin_meter"),
    ("blood gas",   "blood_gas_analyzer"),
    ("bloodgas",    "blood_gas_analyzer"),
    ("abi",         "blood_gas_analyzer"),
    ("gem",         "blood_gas_analyzer"),
    ("radiometer",  "blood_gas_analyzer"),
    ("coagulation", "coagulation_meter"),
    ("coag",        "coagulation_meter"),
    ("inr",         "coagulation_meter"),
    ("pt/inr",      "coagulation_meter"),
    ("cardiac",     "cardiac_marker"),
    ("troponin",    "cardiac_marker"),
    ("bnp",         "cardiac_marker"),
    ("lactate",     "lactate_analyzer"),
    ("pulse ox",    "pulse_oximeter"),
    ("spo2",        "pulse_oximeter"),
    ("urinalysis",  "urinalysis_analyzer"),
    ("urine",       "urinalysis_analyzer"),
    ("immunoassay", "immunoassay_analyzer"),
    ("elisa",       "immunoassay_analyzer"),
]

# HL7 generation keywords (in H or M record)
_HL7_KEYWORDS = ("hl7", "HL7", "ADT", "ORU", "ORM", "^HL7")


def detect_analyzer(text: str) -> Tuple[str, bool]:
    """Detect analyzer type from manufacturer/header record text. Returns
    (analyzer_type, hl7_generation_flag)."""
    t = text or ""
    a_type = "unknown"
    low = t.lower()
    for kw, label in _ANALYZER_KEYWORDS:
        if kw.lower() in low:
            a_type = label
            break
    hl7 = any(k in t for k in _HL7_KEYWORDS)
    return a_type, hl7


# ═══════════════════════════════════════════════════════════════════════════
#  POCT1-A XML Discovery probe (over HTTP)
# ═══════════════════════════════════════════════════════════════════════════
# POCT1-A XML uses namespaces like:
#   xmlns="http://www.poct1.org/POCT1/2005/08"
# Discovery endpoint candidates (in order):
_POCT_PATHS = [
    "/poct/discovery",
    "/POCT/Discovery",
    "/discovery",
    "/poct",
    "/POCT1",
]


def _http_get(url: str, timeout: float = TIMEOUT_S) -> Tuple[int, bytes, str]:
    """Stdlib GET request returning (status, body, error)."""
    try:
        req = urllib.request.Request(url, headers={
            "Accept": ("application/xml,text/xml,application/soap+xml,"
                       "application/json;q=0.9,*/*;q=0.1"),
            "User-Agent": "HVHARNESS/3.0.0 (poct1_probe; lab-only; read-only)",
        }, method="GET")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.getcode(), r.read(), ""
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:  # noqa: BLE001
            body = b""
        return e.code, body, f"http_error:{e.code}"
    except urllib.error.URLError as e:
        return 0, b"", f"url_error:{type(e.reason).__name__}"
    except (socket.timeout, TimeoutError):
        return 0, b"", "timeout"
    except Exception as e:  # noqa: BLE001
        return 0, b"", f"{type(e).__name__}:{e}"


def _parse_poct_xml(body: bytes) -> Optional[ET.Element]:
    """Best-effort XML parse (tolerant of BOM / namespace noise)."""
    if not body:
        return None
    try:
        text = body.decode("utf-8-sig", errors="replace")
        # Strip leading BOM or whitespace
        text = text.lstrip()
        if not text.startswith("<"):
            # Find first XML decl
            i = text.find("<?xml")
            if i < 0:
                i = text.find("<")
            if i < 0:
                return None
            text = text[i:]
        return ET.fromstring(text)
    except Exception:  # noqa: BLE001
        return None


def probe_poct_xml(host: str, port: int) -> Dict:
    """Send POCT1-A Discovery GET requests to candidate paths. Parse the
    XML response for device info, analyzer type, and observation count."""
    result = {
        "poct_accessible": False,
        "analyzer_type": "",
        "hl7_generation": False,
        "observations_reported": 0,
        "patient_data_accessible": False,
        "discovery_path": None,
        "device_info_text": "",
        "error": None,
    }
    scheme = "http"
    for path in _POCT_PATHS:
        url = f"{scheme}://{host}:{port}{path}"
        code, body, err = _http_get(url)
        if code == 0:
            continue
        if code in (401, 403):
            # auth required — try next path; record it as not accessible
            continue
        if code != 200:
            continue
        # Got a 200 — try to parse as XML
        root = _parse_poct_xml(body)
        if root is not None:
            result["poct_accessible"] = True
            result["discovery_path"] = path
            # Flatten the XML text content for keyword detection
            flat = _flatten_xml(root)
            result["device_info_text"] = flat[:2000]
            a_type, hl7 = detect_analyzer(flat)
            if a_type != "unknown":
                result["analyzer_type"] = a_type
            if hl7:
                result["hl7_generation"] = True
            # Count Observation / Result nodes
            obs_count = _count_observations(root)
            result["observations_reported"] = obs_count
            # If observations came back without auth → patient data accessible
            if obs_count > 0:
                result["patient_data_accessible"] = True
            return result
        else:
            # 200 but non-XML — maybe a plain-text banner with device info
            text = body.decode("utf-8", errors="replace")[:2000]
            if text and any(k in text.lower()
                            for k, _ in _ANALYZER_KEYWORDS):
                result["poct_accessible"] = True
                result["discovery_path"] = path
                result["device_info_text"] = text
                a_type, hl7 = detect_analyzer(text)
                if a_type != "unknown":
                    result["analyzer_type"] = a_type
                if hl7:
                    result["hl7_generation"] = True
                return result
    result["error"] = "no_poct_endpoint"
    return result


def _flatten_xml(root: ET.Element) -> str:
    """Flatten an XML tree into a space-separated text blob (for keyword
    detection)."""
    parts: List[str] = []
    for elem in root.iter():
        tag = _local_name(elem.tag)
        if tag:
            parts.append(tag)
        if elem.text:
            parts.append(elem.text.strip())
        if elem.attrib:
            for k, v in elem.attrib.items():
                parts.append(f"{k}={v}")
    # Also include tail text
    for elem in root.iter():
        if elem.tail:
            parts.append(elem.tail.strip())
    return " ".join(p for p in parts if p)


def _local_name(tag: str) -> str:
    """Strip the XML namespace from a tag."""
    if not tag:
        return ""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _count_observations(root: ET.Element) -> int:
    """Count observation / result XML nodes."""
    count = 0
    for elem in root.iter():
        ln = _local_name(elem.tag).lower()
        if ln in ("observation", "result", "observationreport",
                  "testresult", "patientresult"):
            count += 1
    return count


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("POCT1-A / ASTM probing on production clinical "
                           "analyzers is illegal outside an authorized lab. "
                           "HIPAA / HDS / FDA 21 CFR Part 11."),
        }))
        sys.exit(1)

    t0 = time.time()
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "port": PORT,
        "sector": SECTOR_CFG.get("sector"),
        "safe_mode": SAFE_MODE,
        "read_only": READ_ONLY,
        "seed": SEED,
        # Spec-required output fields:
        "poct_accessible": False,
        "astm_compatible": False,
        "analyzer_type": "unknown",
        "patient_data_accessible": False,
        "hl7_generation": False,
        "observations_reported": 0,
        # Extra diagnostics:
        "transport": "tcp",
        "astm_records_received": [],
        "discovery_path": None,
        "errors": [],
    }

    # ─── 1. ASTM E1381 probe (TCP framing) ──────────────────────────────
    try:
        ar = probe_astm(HOST, PORT)
        summary["astm_compatible"] = bool(ar.get("astm_accessible"))
        summary["astm_records_received"] = ar.get("records_received", [])
        # If ASTM got patient data, propagate
        if ar.get("patient_data_accessible"):
            summary["patient_data_accessible"] = True
        if ar.get("observations_reported"):
            summary["observations_reported"] += int(
                ar.get("observations_reported", 0))
        if ar.get("analyzer_type") and ar["analyzer_type"] != "unknown":
            summary["analyzer_type"] = ar["analyzer_type"]
        if ar.get("hl7_generation"):
            summary["hl7_generation"] = True
        if ar.get("error"):
            summary["errors"].append(f"astm:{ar['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"astm:{type(e).__name__}:{e}")

    # ─── 2. POCT1-A XML Discovery probe (HTTP) ──────────────────────────
    try:
        pr = probe_poct_xml(HOST, PORT)
        if pr.get("poct_accessible"):
            summary["poct_accessible"] = True
            summary["discovery_path"] = pr.get("discovery_path")
        if pr.get("patient_data_accessible"):
            summary["patient_data_accessible"] = True
        if pr.get("observations_reported"):
            summary["observations_reported"] += int(
                pr.get("observations_reported", 0))
        if pr.get("analyzer_type") and pr["analyzer_type"] != "unknown":
            # Prefer the POCT1 XML analyzer_type if ASTM didn't find one
            if summary["analyzer_type"] == "unknown":
                summary["analyzer_type"] = pr["analyzer_type"]
        if pr.get("hl7_generation"):
            summary["hl7_generation"] = True
        if pr.get("error"):
            summary["errors"].append(f"poct_xml:{pr['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"poct_xml:{type(e).__name__}:{e}")

    # poct_accessible = either ASTM or POCT1-A XML responded
    summary["poct_accessible"] = bool(summary["poct_accessible"] or
                                      summary["astm_compatible"])

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
