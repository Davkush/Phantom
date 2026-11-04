#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — hl7_probe
# Health sector validation module — HL7 v2.x (MLLP) + FHIR R4 (REST) probing.
#
#   - Default ports : 2575 (MLLP, HL7 v2.x) and 8080 (FHIR REST API)
#   - Functions    :
#       MLLP path:
#         send_mllp_echo     — \x0b + MSH echo/ack test + \x1c\x0d
#         check_mllp_tls     — detect whether port 2575 speaks TLS or plaintext
#         count_messages     — how many application ACKs (MSA) we received
#       FHIR path (port 8080):
#         fhir_metadata      — GET /fhir/metadata → CapabilityStatement
#         fhir_patient_list  — GET /fhir/Patient → count of patients exposed
#         fhir_smart         — check OAuth 2.0 SMART-on-FHIR security extension
#   - Raw socket implementation for MLLP framing; urllib for FHIR (stdlib only,
#     no `requests` dependency required).
#   - READ_ONLY=True (health sector safety constraint) — only reads (GET /
#     MLLP echo test) are emitted; no POST/PUT/DELETE, no ADT-A08 updates.
#   - HIPAA note : unauthenticated access to /Patient or MLLP without TLS =
#     direct violation. All PHI is counted, never echoed (no names, no MRN).
#   - SEED env var : deterministic message control IDs.
#   - LAB=1 mandatory. 5 s timeout on every socket / HTTP operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (health) : HIPAA, HDS, RGPD, FDA 21 CFR Part 11.
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

# ─── Make sector_base importable from ../../sector_base.py ────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULES_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _MODULES_ROOT not in sys.path:
    sys.path.insert(0, _MODULES_ROOT)

try:
    from sector_base import get_sector_config, get_safe_mode
    SECTOR_BASE_OK = True
except Exception as exc:  # noqa: BLE001
    SECTOR_BASE_OK = False
    _SECTOR_BASE_ERR = str(exc)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "hl7_probe"
DEFAULT_MLLP_PORT = 2575
DEFAULT_FHIR_PORT = 8080
TIMEOUT_S = 5.0
READ_ONLY = True  # health sector safety constraint

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_MLLP_PORT
except ValueError:
    PORT = DEFAULT_MLLP_PORT

# If the user passed the FHIR port explicitly, we probe both anyway —
# MLLP on 2575 and FHIR on 8080 by default. CLI port overrides MLLP target.
MLLP_PORT = PORT
FHIR_PORT = DEFAULT_FHIR_PORT

# ─── SEED for deterministic message control IDs ────────────────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else None
except ValueError:
    SEED = None
_rng = random.Random(SEED) if SEED is not None else random.Random()


def _next_msg_id() -> str:
    """Return a deterministic HL7 message control ID (MSH-10)."""
    return f"HV{_rng.randint(100000, 999999)}"


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
#  MLLP FRAMING (HL7 v2.x, RFC-like but de-facto standard)
# ═══════════════════════════════════════════════════════════════════════════
# MLLP framing:
#   \x0b  — start block (SB)
#   <HL7 message>
#   \x1c  — end block (EB)
#   \x0d  — carriage return (CR)
MLLP_SB = b"\x0b"
MLLP_EB = b"\x1c"
MLLP_CR = b"\x0d"


def mllp_wrap(message: str) -> bytes:
    """Wrap an HL7 message in MLLP framing."""
    return MLLP_SB + message.encode("ascii", errors="replace") + MLLP_EB + MLLP_CR


def mllp_unwrap(data: bytes) -> List[str]:
    """Extract all complete MLLP-framed messages from a byte buffer.
    Returns a list of decoded HL7 message strings (incomplete trailing
    data without an EB/CR terminator is discarded)."""
    msgs: List[str] = []
    i = 0
    while True:
        start = data.find(MLLP_SB, i)
        if start == -1:
            break
        end = data.find(MLLP_EB + MLLP_CR, start + 1)
        if end == -1:
            # also accept a lone EB (some implementations skip the CR)
            end_alt = data.find(MLLP_EB, start + 1)
            if end_alt == -1:
                break
            msg = data[start + 1:end_alt]
            msgs.append(msg.decode("ascii", errors="replace"))
            i = end_alt + 1
        else:
            msg = data[start + 1:end]
            msgs.append(msg.decode("ascii", errors="replace"))
            i = end + 2
    return msgs


# ═══════════════════════════════════════════════════════════════════════════
#  HL7 v2 MESSAGE BUILDING
# ═══════════════════════════════════════════════════════════════════════════
def build_echo_message(msg_ctrl_id: str) -> str:
    """Build a minimal HL7 echo / verification test message.

    MSH|^~\\&|SENDING_APP|SENDING_FAC|RECV_APP|RECV_FAC|YYYYMMDDHHMMSS||ACK^A01|<msgid>|P|2.5
    Then an EVN segment and a minimal PID (with no real patient data —
    just structure to validate the parser accepts the message).
    """
    ts = time.strftime("%Y%m%d%H%M%S")
    # Use ACK^A01 as the message type — many HL7 listeners will echo back
    # a generic ACK (MSA|AA|<msgid>) without requiring a real ADT.
    msh = (
        f"MSH|^~\\&|HVHARNESS|LAB|ANY|ANY|{ts}||ACK^A01|{msg_ctrl_id}|P|2.5\r"
        f"MSA|AA|{msg_ctrl_id}\r"
    )
    return msh


def parse_msa(hl7_msg: str) -> Optional[Dict]:
    """Parse the MSA (Message Acknowledgment) segment from an HL7 response.
    Returns {ack_code, msg_ctrl_id} or None if no MSA segment."""
    for seg in hl7_msg.split("\r"):
        if seg.startswith("MSA|"):
            fields = seg.split("|")
            if len(fields) >= 3:
                return {
                    "ack_code": fields[1],
                    "msg_ctrl_id": fields[2],
                }
            elif len(fields) >= 2:
                return {"ack_code": fields[1], "msg_ctrl_id": ""}
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  TLS DETECTION (for MLLP)
# ═══════════════════════════════════════════════════════════════════════════
def detect_tls(host: str, port: int) -> Optional[bool]:
    """Probe whether `port` speaks TLS.

    Returns True if the server responds with a TLS ServerHello handshake,
    False if it speaks plaintext (or returns a non-TLS banner), None if
    the connection failed entirely.

    A TLS ServerHello starts with:
      ContentType=0x16 (Handshake), Version (2 bytes), Length (2 BE),
      then HandshakeType=0x02 (ServerHello).
    """
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(TIMEOUT_S)
        raw.connect((host, port))
        # Send a TLS ClientHello-ish probe; we don't need a valid CH, just
        # any bytes — a TLS server will reply with a Handshake or Alert,
        # a plaintext server will reply with whatever its protocol expects.
        raw.sendall(b"\x16\x03\x01\x00\x01\x01")  # minimal TLS-ish bytes
        try:
            first = raw.recv(5)
        except (socket.timeout, TimeoutError):
            raw.close()
            return None
        raw.close()
        if not first:
            return None
        # TLS record: content type 0x16/0x14/0x15 = handshake / CCS / alert
        if first[0] in (0x16, 0x14, 0x15):
            return True
        return False
    except (socket.timeout, TimeoutError):
        return None
    except (ConnectionRefusedError, OSError):
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  MLLP PROBE
# ═══════════════════════════════════════════════════════════════════════════
def probe_mllp(host: str, port: int) -> Dict:
    """Probe an MLLP endpoint. Sends one echo message and reads back any
    application ACKs. Also checks whether messages are accepted without
    any preceding authentication (HL7 v2 has no native auth — if the
    listener accepts the MLLP frame and returns an MSA, it is open).

    Returns:
      mllp_accessible, messages_intercepted, auth_required, tls_detected, error
    """
    result = {
        "mllp_accessible": False,
        "messages_intercepted": 0,
        "auth_required": None,
        "tls_detected": None,
        "error": None,
    }

    # First — does the port speak TLS?
    result["tls_detected"] = detect_tls(host, port)
    # If TLS was detected, MLLP-over-TLS requires a TLS handshake first;
    # we still attempt a plaintext MLLP send to confirm the listener type.
    # (A plaintext probe against a TLS-only port will just fail to parse,
    #  which is itself informative.)

    # Open a plain TCP connection for the MLLP probe.
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
        msg_id = _next_msg_id()
        echo = build_echo_message(msg_id)
        sock.sendall(mllp_wrap(echo))
        # Read whatever comes back (one recv is usually enough for an ACK)
        try:
            data = sock.recv(4096)
        except (socket.timeout, TimeoutError):
            data = b""
        if data:
            msgs = mllp_unwrap(data)
            acks = [parse_msa(m) for m in msgs]
            acks = [a for a in acks if a is not None]
            result["messages_intercepted"] = len(acks)
            if acks:
                result["mllp_accessible"] = True
                # If we got an AA (application accept) without sending any
                # credentials, no auth was required.
                any_aa = any(a.get("ack_code", "").upper() == "AA" for a in acks)
                result["auth_required"] = not any_aa
            else:
                # Got bytes but no MSA — could be a non-HL7 listener
                result["auth_required"] = None
        else:
            result["auth_required"] = None
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except OSError as e:
        result["error"] = f"io_error:{type(e).__name__}"
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  FHIR R4 PROBE
# ═══════════════════════════════════════════════════════════════════════════
# SMART-on-FHIR security extension URIs
SMART_OAUTH_EXT = "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris"
SMART_OAUTH_AUTHORIZE = "authorize"
SMART_OAUTH_TOKEN = "token"

# Candidate FHIR base paths to try (in order) when probing /metadata
_FHIR_BASE_CANDIDATES = ["/fhir", "/fhir/r4", "", "/api/fhir", "/baseR4"]


def _http_get(url: str, timeout: float = TIMEOUT_S) -> Tuple[int, bytes, str]:
    """Perform a GET request using urllib (stdlib). Returns (status, body,
    error). Follows up to 3 redirects."""
    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/fhir+json,application/json;q=0.9,*/*;q=0.1",
            "User-Agent": "HVHARNESS/3.0.0 (HL7-FHIR-probe; lab-only)",
        })
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # lab-only; do not enforce TLS certs
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.getcode(), r.read(), ""
    except urllib.error.HTTPError as e:
        # HTTP error (4xx/5xx) — still return the body so we can inspect
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, body, f"http_error:{e.code}"
    except urllib.error.URLError as e:
        return 0, b"", f"url_error:{type(e.reason).__name__}"
    except (socket.timeout, TimeoutError):
        return 0, b"", "timeout"
    except Exception as e:
        return 0, b"", f"{type(e).__name__}:{e}"


def _safe_json(data: bytes) -> Optional[dict]:
    """Best-effort JSON decode (tolerant of BOM / trailing junk)."""
    if not data:
        return None
    try:
        text = data.decode("utf-8-sig", errors="replace")
        return json.loads(text)
    except Exception:
        return None


def fhir_discover_base(host: str, port: int) -> Optional[str]:
    """Discover a working FHIR base path by trying /metadata on each
    candidate. Returns the base path (e.g. '/fhir') or None."""
    for base in _FHIR_BASE_CANDIDATES:
        url = f"http://{host}:{port}{base}/metadata"
        code, body, _err = _http_get(url)
        if code == 200:
            j = _safe_json(body)
            if j and isinstance(j, dict) and j.get("resourceType") == "CapabilityStatement":
                return base
    return None


def fhir_metadata(host: str, port: int, base: str) -> Dict:
    """Fetch the CapabilityStatement and inspect it for:
      - SMART-on-FHIR security extension (oauth-uris → authorize/token)
      - Whether the server declares any security requirements
    """
    result = {
        "fhir_accessible": False,
        "smart_on_fhir": False,
        "fhir_version": None,
        "security_declared": False,
        "authorize_url": None,
        "token_url": None,
        "error": None,
    }
    url = f"http://{host}:{port}{base}/metadata"
    code, body, err = _http_get(url)
    if code != 200:
        result["error"] = err or f"http_{code}"
        return result
    j = _safe_json(body)
    if not j or j.get("resourceType") != "CapabilityStatement":
        result["error"] = "not_capability_statement"
        return result
    result["fhir_accessible"] = True
    result["fhir_version"] = j.get("fhirVersion")

    # Inspect rest[].security for SMART extension
    rest = j.get("rest") or []
    for r in rest:
        sec = r.get("security") if isinstance(r, dict) else None
        if sec:
            result["security_declared"] = True
            # SMART extension lives under extension[]
            for ext in sec.get("extension") or []:
                url_e = ext.get("url", "")
                if SMART_OAUTH_EXT in url_e:
                    # nested extensions hold authorize / token URIs
                    for inner in ext.get("extension") or []:
                        iu = inner.get("url", "")
                        iv = inner.get("valueUri") or ""
                        if iu == SMART_OAUTH_AUTHORIZE:
                            result["authorize_url"] = iv
                        elif iu == SMART_OAUTH_TOKEN:
                            result["token_url"] = iv
                    if result["authorize_url"] or result["token_url"]:
                        result["smart_on_fhir"] = True
    return result


def fhir_count_patients(host: str, port: int, base: str) -> Dict:
    """GET /Patient and count how many patients are exposed WITHOUT auth.

    FHIR search responses include a `total` field when the server chooses
    to report it. If `total` is absent, we count `entry[]` instead.

    Returns: {patients_exposed, status_code, auth_required, error}
    """
    result = {
        "patients_exposed": 0,
        "status_code": None,
        "auth_required": None,
        "error": None,
    }
    url = f"http://{host}:{port}{base}/Patient"
    code, body, err = _http_get(url)
    result["status_code"] = code
    if code == 0:
        result["error"] = err
        return result
    if code in (401, 403):
        result["auth_required"] = True
        result["error"] = err or f"http_{code}"
        return result
    if code != 200:
        result["error"] = err or f"http_{code}"
        return result
    j = _safe_json(body)
    if not j:
        result["error"] = "invalid_json"
        return result
    # If we got a 200 with a Bundle of patients WITHOUT sending any auth
    # header, patient data is exposed without authentication.
    total = j.get("total")
    if isinstance(total, int):
        result["patients_exposed"] = total
    else:
        entries = j.get("entry") or []
        result["patients_exposed"] = len(entries)
    result["auth_required"] = False  # got 200 without auth
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("HL7 / FHIR probing on production clinical systems "
                           "is illegal outside an authorized lab. HIPAA / HDS."),
        }))
        sys.exit(1)

    t0 = time.time()
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "mllp_port": MLLP_PORT,
        "fhir_port": FHIR_PORT,
        "sector": SECTOR_CFG.get("sector"),
        "safe_mode": SAFE_MODE,
        "read_only": READ_ONLY,
        "seed": SEED,
        # Spec-required output fields:
        "mllp_accessible": False,
        "fhir_accessible": False,
        "messages_intercepted": 0,
        "auth_required": None,
        "smart_on_fhir": False,
        "patients_exposed": 0,
        # Extra diagnostic fields:
        "mllp_tls_detected": None,
        "fhir_version": None,
        "fhir_base_path": None,
        "errors": [],
    }

    # ─── 1. MLLP probe (port 2575) ───────────────────────────────────────
    try:
        mr = probe_mllp(HOST, MLLP_PORT)
        summary["mllp_accessible"] = bool(mr.get("mllp_accessible"))
        summary["messages_intercepted"] = int(mr.get("messages_intercepted", 0))
        summary["mllp_tls_detected"] = mr.get("tls_detected")
        if mr.get("auth_required") is not None:
            summary["auth_required"] = mr["auth_required"]
        if mr.get("error"):
            summary["errors"].append(f"mllp:{mr['error']}")
    except Exception as e:
        summary["errors"].append(f"mllp:{type(e).__name__}:{e}")

    # ─── 2. FHIR R4 probe (port 8080) ────────────────────────────────────
    try:
        base = fhir_discover_base(HOST, FHIR_PORT)
        summary["fhir_base_path"] = base
        if base is not None:
            fr = fhir_metadata(HOST, FHIR_PORT, base)
            summary["fhir_accessible"] = bool(fr.get("fhir_accessible"))
            summary["fhir_version"] = fr.get("fhir_version")
            summary["smart_on_fhir"] = bool(fr.get("smart_on_fhir"))
            if fr.get("error"):
                summary["errors"].append(f"fhir_metadata:{fr['error']}")

            pr = fhir_count_patients(HOST, FHIR_PORT, base)
            summary["patients_exposed"] = int(pr.get("patients_exposed", 0))
            if pr.get("auth_required") is not None:
                # If FHIR requires auth, override auth_required to True
                if pr["auth_required"]:
                    summary["auth_required"] = True
                elif summary["auth_required"] is None:
                    summary["auth_required"] = False
            if pr.get("error"):
                summary["errors"].append(f"fhir_patient:{pr['error']}")
        else:
            # No FHIR base discovered — port may not host a FHIR API
            summary["errors"].append("fhir:no_capability_statement_found")
    except Exception as e:
        summary["errors"].append(f"fhir:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
