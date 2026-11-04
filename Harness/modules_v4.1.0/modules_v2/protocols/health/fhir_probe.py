#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — fhir_probe
# Health sector validation module — HL7 FHIR R4 (REST API) probing.
#
#   - Default URL : http://127.0.0.1:8080/fhir   (argv[1] = base URL)
#   - Distinct from hl7_probe.py, which tests MLLP v2 (port 2575) AND
#     performs a *minimal* FHIR metadata check. This module performs a
#     deep, FHIR-only audit: capability statement, patient/observation
#     exposure, SMART-on-FHIR OAuth 2.0, Bulk Data API ($export), and
#     information-leakage detection.
#
#   - Functions:
#       fhir_metadata         — GET {base}/metadata → CapabilityStatement,
#                                extract fhirVersion (DSTU2/STU3/R4/R4B/R5)
#       fhir_patient_list     — GET {base}/Patient → count PHI exposed
#       fhir_observations     — GET {base}/Observation → clinical data leak
#       smart_configuration   — GET /.well-known/smart-configuration
#                                (scopes, PKCE, client_assertion)
#       bulk_data_export      — GET {base}/$export → Bulk Data API (FHIR R4)
#       check_data_leakage    — inspect 4xx/5xx OperationOutcome bodies
#                                for patient identifiers (PHI leak)
#   - READ_ONLY=True (health sector safety constraint) — only GET requests
#     are emitted. No POST/PUT/DELETE/PATCH, no $export kick-off POST,
#     no patient create/update. The $export probe uses GET with the
#     `Prefer: respond-async` header but never POSTs a kick-off.
#   - HIPAA note: unauthenticated /Patient access = direct violation.
#     Patient counts are reported as integers only — no names, MRNs,
#     DOBs, or other PHI are echoed.
#   - SEED env var: deterministic request IDs / correlation headers.
#   - LAB=1 mandatory. 5 s timeout on every HTTP operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (health) : HIPAA, HDS, RGPD, FDA 21 CFR Part 11,
# ONC certification (45 CFR §170.315), SMART App Launch IG.
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
MODULE_NAME = "fhir_probe"
TIMEOUT_S = 5.0
READ_ONLY = True  # health sector safety constraint (GET only)

# ─── CLI args — argv[1] = base URL (full URL, not just host) ───────────────
DEFAULT_BASE_URL = "http://127.0.0.1:8080/fhir"
BASE_URL = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE_URL
# Normalize: strip trailing slash
if BASE_URL.endswith("/"):
    BASE_URL = BASE_URL[:-1]

# ─── SEED for deterministic request IDs ────────────────────────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else None
except ValueError:
    SEED = None
_rng = random.Random(SEED) if SEED is not None else random.Random()


def _next_req_id() -> str:
    """Deterministic FHIR request/correlation ID."""
    return f"fhir-{_rng.randint(100000, 999999)}"


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
#  HTTP helpers (urllib stdlib only)
# ═══════════════════════════════════════════════════════════════════════════
SMART_OAUTH_EXT = "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris"

# Known FHIR version strings (per HL7 FHIR versions)
FHIR_VERSIONS = ("1.0.2", "1.4.0", "3.0.2", "4.0.1", "4.3.0", "5.0.0")
FHIR_VERSION_NAMES = {
    "1.0.2": "DSTU2",
    "1.4.0": "STU3 (ballot)",
    "1.6.0": "STU3 (ballot)",
    "1.8.0": "STU3 (ballot)",
    "3.0.0": "STU3",
    "3.0.1": "STU3",
    "3.0.2": "STU3",
    "4.0.0": "R4",
    "4.0.1": "R4",
    "4.3.0": "R4B",
    "4.3.0-cibuild": "R4B",
    "5.0.0": "R5",
    "5.0.0-cibuild": "R5",
}
# Map a raw fhirVersion string to its spec name (handles CI-build suffixes
# and unknown versions gracefully).
def _label_for_version(v: str) -> str:
    v = str(v).strip()
    if v in FHIR_VERSION_NAMES:
        return FHIR_VERSION_NAMES[v]
    low = v.lower()
    for key, label in FHIR_VERSION_NAMES.items():
        if low.startswith(key):
            return label
    if low.startswith("1.0"):
        return "DSTU2"
    if low.startswith("3.0") or low.startswith("1."):
        return "STU3"
    if low.startswith("4.0"):
        return "R4"
    if low.startswith("4.3"):
        return "R4B"
    if low.startswith("5."):
        return "R5"
    return ""


def _http_get(url: str, headers: Optional[Dict] = None,
              timeout: float = TIMEOUT_S) -> Tuple[int, bytes, Dict, str]:
    """Perform a GET request. Returns (status, body, response_headers, error).

    Follows up to 3 redirects. Does not verify TLS certs (lab-only).
    """
    req_headers = {
        "Accept": "application/fhir+json,application/json;q=0.9,*/*;q=0.1",
        "User-Agent": "HVHARNESS/3.0.0 (fhir_probe; lab-only; read-only)",
    }
    if headers:
        req_headers.update(headers)
    try:
        req = urllib.request.Request(url, headers=req_headers, method="GET")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # lab-only
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            resp_headers = {k.lower(): v for k, v in r.headers.items()}
            return r.getcode(), r.read(), resp_headers, ""
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:  # noqa: BLE001
            body = b""
        resp_headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return e.code, body, resp_headers, f"http_error:{e.code}"
    except urllib.error.URLError as e:
        return 0, b"", {}, f"url_error:{type(e.reason).__name__}"
    except (socket.timeout, TimeoutError):
        return 0, b"", {}, "timeout"
    except Exception as e:  # noqa: BLE001
        return 0, b"", {}, f"{type(e).__name__}:{e}"


def _safe_json(data: bytes) -> Optional[dict]:
    if not data:
        return None
    try:
        return json.loads(data.decode("utf-8-sig", errors="replace"))
    except Exception:  # noqa: BLE001
        return None


def _join_url(base: str, path: str) -> str:
    """Join a base URL with a path, ensuring exactly one slash."""
    if path.startswith("/"):
        return base + path
    return base + "/" + path


# ═══════════════════════════════════════════════════════════════════════════
#  Probe 1 — CapabilityStatement (metadata)
# ═══════════════════════════════════════════════════════════════════════════
def fhir_metadata(base_url: str) -> Dict:
    """GET {base}/metadata → CapabilityStatement.

    Extracts:
      - fhir_accessible (bool): 200 + resourceType==CapabilityStatement
      - version (str): fhirVersion raw string (e.g. '4.0.1')
      - version_name (str): human label (R4 / R4B / R5 / ...)
      - smart_on_fhir (bool): security extension with oauth-uris present
      - authorize_url / token_url (str|None)
    """
    result = {
        "fhir_accessible": False,
        "version": "",
        "version_name": "",
        "smart_on_fhir": False,
        "authorize_url": None,
        "token_url": None,
        "security_declared": False,
        "error": None,
    }
    url = _join_url(base_url, "metadata")
    code, body, _hdrs, err = _http_get(url)
    if code != 200:
        result["error"] = err or f"http_{code}"
        return result
    j = _safe_json(body)
    if not j or not isinstance(j, dict):
        result["error"] = "invalid_json"
        return result
    if j.get("resourceType") not in ("CapabilityStatement", "Conformance"):
        result["error"] = "not_capability_statement"
        return result
    result["fhir_accessible"] = True
    fver = j.get("fhirVersion") or ""
    result["version"] = str(fver)
    result["version_name"] = _label_for_version(str(fver))
    # Inspect rest[].security
    rest = j.get("rest") or []
    for r in rest:
        if not isinstance(r, dict):
            continue
        sec = r.get("security")
        if sec:
            result["security_declared"] = True
            for ext in sec.get("extension") or []:
                if SMART_OAUTH_EXT in (ext.get("url") or ""):
                    for inner in ext.get("extension") or []:
                        iu = inner.get("url", "")
                        iv = inner.get("valueUri") or ""
                        if iu == "authorize":
                            result["authorize_url"] = iv
                        elif iu == "token":
                            result["token_url"] = iv
                    if result["authorize_url"] or result["token_url"]:
                        result["smart_on_fhir"] = True
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  Probe 2 — Patient list exposure (no auth)
# ═══════════════════════════════════════════════════════════════════════════
def fhir_patient_list(base_url: str) -> Dict:
    """GET {base}/Patient → count PHI exposed without authentication."""
    result = {
        "patients_exposed": 0,
        "status_code": None,
        "auth_required": None,
        "error": None,
    }
    url = _join_url(base_url, "Patient")
    code, body, _hdrs, err = _http_get(url)
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
    total = j.get("total")
    if isinstance(total, int):
        result["patients_exposed"] = total
    else:
        entries = j.get("entry") or []
        result["patients_exposed"] = len(entries)
    result["auth_required"] = False
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  Probe 3 — Observation (clinical data) exposure (no auth)
# ═══════════════════════════════════════════════════════════════════════════
def fhir_observations(base_url: str) -> Dict:
    """GET {base}/Observation → check if clinical data exposed without auth."""
    result = {
        "observations_exposed": 0,
        "clinical_data_exposed": False,
        "status_code": None,
        "error": None,
    }
    # _count=1 limits the response (read-only, polite)
    url = _join_url(base_url, "Observation?_count=1")
    code, body, _hdrs, err = _http_get(url)
    result["status_code"] = code
    if code == 0:
        result["error"] = err
        return result
    if code in (401, 403):
        result["error"] = err or f"http_{code}"
        return result
    if code != 200:
        result["error"] = err or f"http_{code}"
        return result
    j = _safe_json(body)
    if not j:
        result["error"] = "invalid_json"
        return result
    entries = j.get("entry") or []
    result["observations_exposed"] = len(entries)
    result["clinical_data_exposed"] = len(entries) > 0
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  Probe 4 — SMART-on-FHIR /.well-known/smart-configuration
# ═══════════════════════════════════════════════════════════════════════════
# The .well-known endpoint is served at the *root* of the FHIR host (not
# under /fhir), per the SMART App Launch IG. We derive the root from BASE_URL.
def _root_url(base_url: str) -> str:
    """Return scheme://host:port from base_url (drop the path)."""
    m = re.match(r"^(https?://[^/]+)", base_url, re.IGNORECASE)
    return m.group(1) if m else base_url


def smart_configuration(base_url: str) -> Dict:
    """GET /.well-known/smart-configuration → SMART capabilities.

    Checks:
      - scopes_supported contains patient/*.read, patient/*.write, launch/patient
      - capabilities includes 'client-confidential-asymmetric' (client_assertion)
      - PKCE required: 'require-pkce' in capabilities, or
        pkce_required_supported==True
    """
    result = {
        "smart_on_fhir": False,
        "pkce_required": False,
        "client_assertion": False,
        "scopes_supported": [],
        "capabilities": [],
        "error": None,
    }
    root = _root_url(base_url)
    url = root + "/.well-known/smart-configuration"
    code, body, _hdrs, err = _http_get(url)
    if code == 0:
        result["error"] = err
        return result
    if code != 200:
        result["error"] = err or f"http_{code}"
        return result
    j = _safe_json(body)
    if not j or not isinstance(j, dict):
        result["error"] = "invalid_json"
        return result
    result["smart_on_fhir"] = True
    caps = j.get("capabilities") or []
    result["capabilities"] = list(caps)
    result["scopes_supported"] = list(j.get("scopes_supported") or [])
    # PKCE: required if 'require-pkce' in capabilities (per SMART v2)
    if any("require-pkce" in str(c).lower() for c in caps):
        result["pkce_required"] = True
    elif j.get("pkce_required") is True:
        result["pkce_required"] = True
    # client_assertion support (confidential asymmetric client)
    if any("client-confidential-asymmetric" in str(c) for c in caps):
        result["client_assertion"] = True
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  Probe 5 — Bulk Data API ($export, FHIR R4)
# ═══════════════════════════════════════════════════════════════════════════
# READ-ONLY: A real $export kick-off is a POST. We only do GET to test
# whether the $export endpoint exists (the operation is advertised in
# CapabilityStatement.rest.resource.operation OR the endpoint responds
# with 405 Method Not Allowed when GET is sent — both indicate Bulk Data
# support).
def bulk_data_export(base_url: str) -> Dict:
    """GET {base}/$export → Bulk Data API support detection.

    A 202 (Accepted) would indicate async kick-off accepted; a 405 indicates
    the endpoint exists but requires POST; a 404 means no Bulk Data API.
    """
    result = {
        "bulk_data_api": False,
        "status_code": None,
        "kickoff_method": "GET",
        "error": None,
    }
    url = _join_url(base_url, "$export")
    code, body, _hdrs, err = _http_get(url, headers={
        "Prefer": "respond-async",
        "Accept": "application/fhir+json",
    })
    result["status_code"] = code
    if code == 0:
        result["error"] = err
        return result
    # 202 = async kick-off accepted (some servers accept GET)
    # 405 = endpoint exists, POST required (typical, correct behavior)
    # 404/400 = endpoint absent
    if code in (202, 405):
        result["bulk_data_api"] = True
    elif code in (404, 400):
        result["bulk_data_api"] = False
    elif code == 200:
        # 200 with a Parameters resource — also acceptable
        j = _safe_json(body)
        if j and isinstance(j, dict):
            result["bulk_data_api"] = True
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  Probe 6 — Information leakage in error responses
# ═══════════════════════════════════════════════════════════════════════════
# Patterns that indicate PHI leakage in OperationOutcome diagnostics:
#   - MRN-like tokens (e.g. "MRN12345", "patient 12345")
#   - Dates of birth (YYYY-MM-DD)
#   - 10-digit phone numbers
#   - Email addresses
#   - Patient names (hard to detect generically; we look for "Patient/<id>"
#     references in error messages)
_PHI_PATTERNS = [
    re.compile(r"\bMRN[-:]?\s?\d{4,12}\b", re.IGNORECASE),
    re.compile(r"\bpatient[/#]?\d{4,12}\b", re.IGNORECASE),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),               # SSN-like
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),               # DOB / date
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),        # email
    re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),       # phone
    re.compile(r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b"),        # First Last name
]


def check_data_leakage(base_url: str) -> Dict:
    """Trigger error responses (404 on a non-existent resource) and inspect
    the OperationOutcome diagnostics for PHI leakage."""
    result = {
        "data_leakage": False,
        "leak_indicators": [],
        "error": None,
    }
    # Request a non-existent Patient to trigger a 404 OperationOutcome
    url = _join_url(base_url, "Patient/$nonexistent-id-harness-probe-000")
    code, body, _hdrs, err = _http_get(url)
    if code == 0:
        result["error"] = err
        return result
    text = body.decode("utf-8", errors="replace") if body else ""
    if not text:
        return result
    found = []
    for pat in _PHI_PATTERNS:
        m = pat.search(text)
        if m:
            found.append(m.group(0))
    if found:
        result["data_leakage"] = True
        # Do NOT echo the leaked values verbatim — just classify them.
        result["leak_indicators"] = sorted(set(
            _classify_leak(s) for s in found
        ))
    return result


def _classify_leak(s: str) -> str:
    """Classify a leaked token without echoing it (privacy)."""
    if re.match(r"\bMRN", s, re.IGNORECASE):
        return "mrn"
    if "@" in s:
        return "email"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return "date_or_dob"
    if re.fullmatch(r"\d{3}-\d{2}-\d{4}", s):
        return "ssn"
    if re.fullmatch(r"\d{3}[-.]?\d{3}[-.]?\d{4}", s):
        return "phone"
    if "patient" in s.lower():
        return "patient_reference"
    return "name_like"


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("FHIR probing on production clinical systems is "
                           "illegal outside an authorized lab. HIPAA / HDS."),
        }))
        sys.exit(1)

    t0 = time.time()
    resources_tested: List[str] = []
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "base_url": BASE_URL,
        "sector": SECTOR_CFG.get("sector"),
        "safe_mode": SAFE_MODE,
        "read_only": READ_ONLY,
        "seed": SEED,
        # Spec-required output fields:
        "fhir_accessible": False,
        "version": "",
        "patients_exposed": 0,
        "smart_on_fhir": False,
        "pkce_required": False,
        "bulk_data_api": False,
        "data_leakage": False,
        "resources_tested": resources_tested,
        # Extra diagnostics:
        "version_name": "",
        "client_assertion": False,
        "observations_exposed": 0,
        "clinical_data_exposed": False,
        "auth_required": None,
        "errors": [],
    }

    # ─── 1. CapabilityStatement / metadata ───────────────────────────────
    try:
        md = fhir_metadata(BASE_URL)
        resources_tested.append("metadata")
        summary["fhir_accessible"] = bool(md.get("fhir_accessible"))
        summary["version"] = str(md.get("version") or "")
        summary["version_name"] = md.get("version_name") or ""
        # SMART-on-FHIR may be signalled via CapabilityStatement security ext
        # or via .well-known — we OR them below.
        summary["smart_on_fhir"] = bool(md.get("smart_on_fhir"))
        if md.get("error"):
            summary["errors"].append(f"metadata:{md['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"metadata:{type(e).__name__}:{e}")

    # If FHIR is not accessible, short-circuit remaining probes
    if not summary["fhir_accessible"]:
        summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
        print(json.dumps(summary, indent=2, default=str))
        return

    # ─── 2. Patient list exposure ────────────────────────────────────────
    try:
        pr = fhir_patient_list(BASE_URL)
        resources_tested.append("Patient")
        summary["patients_exposed"] = int(pr.get("patients_exposed", 0))
        if pr.get("auth_required") is True:
            summary["auth_required"] = True
        elif pr.get("auth_required") is False:
            summary["auth_required"] = False
        if pr.get("error"):
            summary["errors"].append(f"patient:{pr['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"patient:{type(e).__name__}:{e}")

    # ─── 3. Observation clinical data ───────────────────────────────────
    try:
        obs = fhir_observations(BASE_URL)
        resources_tested.append("Observation")
        summary["observations_exposed"] = int(obs.get("observations_exposed", 0))
        summary["clinical_data_exposed"] = bool(obs.get("clinical_data_exposed"))
        if obs.get("error"):
            summary["errors"].append(f"observation:{obs['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"observation:{type(e).__name__}:{e}")

    # ─── 4. SMART-on-FHIR /.well-known ──────────────────────────────────
    try:
        sm = smart_configuration(BASE_URL)
        resources_tested.append(".well-known/smart-configuration")
        if sm.get("smart_on_fhir"):
            summary["smart_on_fhir"] = True
        summary["pkce_required"] = bool(sm.get("pkce_required"))
        summary["client_assertion"] = bool(sm.get("client_assertion"))
        if sm.get("error"):
            summary["errors"].append(f"smart:{sm['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"smart:{type(e).__name__}:{e}")

    # ─── 5. Bulk Data API ($export) ─────────────────────────────────────
    try:
        be = bulk_data_export(BASE_URL)
        resources_tested.append("$export")
        summary["bulk_data_api"] = bool(be.get("bulk_data_api"))
        if be.get("error"):
            summary["errors"].append(f"bulk_export:{be['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"bulk_export:{type(e).__name__}:{e}")

    # ─── 6. Data leakage in error responses ─────────────────────────────
    try:
        dl = check_data_leakage(BASE_URL)
        summary["data_leakage"] = bool(dl.get("data_leakage"))
        if dl.get("error"):
            summary["errors"].append(f"leakage:{dl['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"leakage:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
