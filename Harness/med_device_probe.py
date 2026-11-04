#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — med_device_probe
# Health sector validation module — medical device reconnaissance.
#
#   - Default ports scanned : 4000-4010, 4170, 9100 (plus web ports 80/8080/4000
#     when medical-device fingerprints suggest an embedded web UI)
#   - Functions:
#       scan_ports        — TCP connect() loopback scan of common medical
#                            device ports, banner grab on each open port.
#       fingerprint_device — match banner / HTTP headers against a curated
#                            table of known medical-device fingerprints
#                            (infusion pumps, ventilators, monitors, PACS).
#       check_urgent11    — passive indicators of the Nucleus RTOS TCP/IP
#                            stack (URGENT/11 CVE-2019-12255..12264).
#                            READ-ONLY: we do NOT send any malformed packet
#                            that could crash a vulnerable device; we only
#                            inspect banners / TCP options / HTTP Server
#                            headers.
#       check_login_page  — detect a web login form (READ_ONLY: we just check
#                            that the page EXISTS and looks like a default-
#                            credential login page; we never submit any
#                            credential).
#   - READ_ONLY=True (health sector safety constraint) — no active exploit
#     attempts, no credential submission, no firmware write.
#   - HIPAA / FDA note : unauthenticated access to a medical device web UI
#     is a direct patient-safety risk (could alter therapy parameters).
#   - SEED env var : deterministic scan order.
#   - LAB=1 mandatory. 5 s timeout per connect.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (health) : HIPAA, HDS, RGPD, FDA 21 CFR Part 11,
#   IEC 80001 (network risk management for medical devices).
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
MODULE_NAME = "med_device_probe"
DEFAULT_PORT = 4000  # representative default for CLI parsing
TIMEOUT_S = 5.0
READ_ONLY = True  # health sector safety constraint

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── SEED for deterministic scan order ─────────────────────────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else None
except ValueError:
    SEED = None
_rng = random.Random(SEED) if SEED is not None else random.Random()


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
#  MEDICAL DEVICE PORT TABLE
# ═══════════════════════════════════════════════════════════════════════════
# Common ports observed on bedside medical devices and PACS modalities.
# 4000-4010 : various infusion pumps / proprietary control daemons
# 4170      : Carestream / DR workstations (DICOM-adjacent)
# 9100      : printer / some lab analyzers (raw 9100 JetDirect-style)
# 80/8080   : embedded web management UIs
MED_PORTS = list(range(4000, 4011)) + [4170, 9100, 80, 8080, 443]

# Web ports we will probe for login pages
WEB_PORTS = (80, 8080, 4000, 443)


# ═══════════════════════════════════════════════════════════════════════════
#  DEVICE FINGERPRINT TABLE
# ═══════════════════════════════════════════════════════════════════════════
# (substring_lower, device_type, vendor_hint)
DEVICE_FINGERPRINTS: List[Tuple[str, str, str]] = [
    # Infusion pumps
    ("baxter", "infusion_pump", "Baxter"),
    ("bd bodyguard", "infusion_pump", "BD BodyGuard"),
    ("bodyguard", "infusion_pump", "BD BodyGuard"),
    ("hospira", "infusion_pump", "Hospira/ICU Medical"),
    ("plum", "infusion_pump", "Hospira Plum"),
    ("symbiq", "infusion_pump", "Hospira Symbiq"),
    ("fresenius", "infusion_pump", "Fresenius"),
    ("agilia", "infusion_pump", "Fresenius Agilia"),
    ("b.braun", "infusion_pump", "B. Braun"),
    ("infusomat", "infusion_pump", "B. Braun Infusomat"),
    # Ventilators
    ("ventilator", "ventilator", "Generic"),
    ("hamilton", "ventilator", "Hamilton Medical"),
    ("drager", "ventilator", "Dräger"),
    ("draeger", "ventilator", "Dräger"),
    ("maquet", "ventilator", "Getinge/Maquet"),
    ("servo-i", "ventilator", "Maquet Servo-i"),
    ("servo", "ventilator", "Maquet Servo"),
    ("philips ventil", "ventilator", "Philips"),
    ("v60", "ventilator", "Philips Respironics V60"),
    ("puritan", "ventilator", "Puritan Bennett"),
    ("840", "ventilator", "Puritan Bennett 840"),
    # Patient monitors
    ("monitor", "patient_monitor", "Generic"),
    ("philips", "patient_monitor", "Philips"),
    ("intellivue", "patient_monitor", "Philips IntelliVue"),
    ("ge healthcare", "patient_monitor", "GE Healthcare"),
    ("dash", "patient_monitor", "GE Dash"),
    ("culow", "patient_monitor", "GE CARESCAPE"),
    ("carescape", "patient_monitor", "GE CARESCAPE"),
    ("mindray", "patient_monitor", "Mindray"),
    ("nenb", "patient_monitor", "Nihon Kohden"),
    ("nihon", "patient_monitor", "Nihon Kohden"),
    # PACS / imaging
    ("pacs", "pacs", "Generic"),
    ("dicom", "pacs", "Generic"),
    ("dcm4che", "pacs", "dcm4che"),
    ("orthanc", "pacs", "Orthanc"),
    ("ge pacs", "pacs", "GE Centricity"),
    ("centricity", "pacs", "GE Centricity"),
    ("syngo", "pacs", "Siemens syngo"),
    # Anesthesia
    ("anesthesia", "anesthesia_machine", "Generic"),
    ("aneasthesia", "anesthesia_machine", "Generic"),
    ("aisys", "anesthesia_machine", "GE Aisys"),
    ("avance", "anesthesia_machine", "GE Avance"),
    # Lab analyzers
    ("analyzer", "lab_analyzer", "Generic"),
    ("cobas", "lab_analyzer", "Roche Cobas"),
    ("architect", "lab_analyzer", "Abbott Architect"),
    ("cell-dyn", "lab_analyzer", "Abbott Cell-Dyn"),
    # Default web UIs on common medical devices
    ("pyxis", "medication_station", "BD Pyxis"),
    ("omnicell", "medication_station", "Omnicell"),
]


# ═══════════════════════════════════════════════════════════════════════════
#  URGENT/11 (Nucleus RTOS) INDICATORS
# ═══════════════════════════════════════════════════════════════════════════
# URGENT/11 (CVE-2019-12255..12264, + CVE-2020-7980 etc.) affect the Nucleus
# NET TCP/IP stack. We do NOT send any crash-triggering packet — instead we
# look for passive indicators that the device is running Nucleus NET:
#   - HTTP "Server:" header containing "Nucleus" / "Proneam" / "Allegro"
#   - TCP/IP fingerprints (small MSS, fixed window size of 0x1000 or 0x400,
#     no SACK, no window scale)
#   - banners containing "Nucleus" / "Proneam"
NUCLEUS_BANNER_TOKENS = ("nucleus", "proneam", "allegro", "interpeak", "nettrom")
NUCLEUS_HTTP_TOKENS = ("nucleus", "proneam", "allegro", "thttpd/2.25b",
                       "webs/", "goahead")


# ═══════════════════════════════════════════════════════════════════════════
#  PORT SCAN + BANNER GRAB
# ═══════════════════════════════════════════════════════════════════════════
def tcp_connect(host: str, port: int, timeout: float = TIMEOUT_S
                ) -> Optional[socket.socket]:
    """Best-effort TCP connect. Returns a connected socket or None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except (socket.timeout, TimeoutError):
        return None
    except (ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


def banner_grab(host: str, port: int, timeout: float = TIMEOUT_S
                ) -> Tuple[Optional[bytes], Optional[dict]]:
    """Connect to (host, port) and try to grab a banner.

    For text protocols, many servers send a banner immediately on connect.
    For HTTP, we send a minimal GET / if no banner arrives within 1 s.

    Returns (banner_bytes_or_None, tcp_info_or_None). tcp_info holds
    passive TCP fingerprint data (MSS, window size, options) captured from
    the underlying socket — these are NOT raw packet captures (we stay in
    user-space) but the kernel-exposed sock options that mirror them.
    """
    s = tcp_connect(host, port, timeout)
    if s is None:
        return None, None
    tcp_info: Optional[dict] = None
    banner: Optional[bytes] = None
    try:
        # Try a passive read first (1 s window)
        s.settimeout(1.0)
        try:
            banner = s.recv(1024)
        except (socket.timeout, TimeoutError):
            banner = None
        except OSError:
            banner = None

        # If nothing came, probe with HTTP for likely web ports
        if not banner and port in WEB_PORTS:
            try:
                s.settimeout(timeout)
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                chunks: List[bytes] = []
                while True:
                    try:
                        data = s.recv(4096)
                    except (socket.timeout, TimeoutError):
                        break
                    if not data:
                        break
                    chunks.append(data)
                    if sum(len(c) for c in chunks) > 64 * 1024:
                        break
                banner = b"".join(chunks) if chunks else None
            except OSError:
                banner = None

        # Capture passive TCP info from the kernel
        try:
            tcp_info = _capture_tcp_info(s)
        except Exception:
            tcp_info = None
    finally:
        try:
            s.close()
        except Exception:
            pass
    return banner, tcp_info


def _capture_tcp_info(s: socket.socket) -> Optional[dict]:
    """Capture passive TCP/IP fingerprint data exposed via socket options.

    On Linux, SO_RCVBUF / TCP_MAXSEG reflect the negotiated MSS and the
    receive buffer (a proxy for advertised window). These are read-only
    socket option queries — they do not touch the network.
    """
    info: Dict = {}
    try:
        info["rcvbuf"] = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    except OSError:
        pass
    try:
        info["sndbuf"] = s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
    except OSError:
        pass
    # TCP_MAXSEG (Linux) = negotiated MSS
    try:
        TCP_MAXSEG = getattr(socket, "TCP_MAXSEG", 2)
        info["mss"] = s.getsockopt(socket.IPPROTO_TCP, TCP_MAXSEG)
    except OSError:
        pass
    # TCP_INFO (Linux) — a struct exposing negotiated RTT / window
    try:
        TCP_INFO = getattr(socket, "TCP_INFO", 11)
        raw = s.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 256)
        # struct tcp_info layout varies by kernel — we just store the raw
        # bytes length as a sanity check
        info["tcp_info_len"] = len(raw)
    except OSError:
        pass
    return info if info else None


# ═══════════════════════════════════════════════════════════════════════════
#  FINGERPRINT MATCHING
# ═══════════════════════════════════════════════════════════════════════════
def match_fingerprints(banner: bytes) -> List[Dict]:
    """Match banner bytes against the fingerprint table.
    Returns a list of {device_type, vendor_hint, matched_token}.
    """
    text = banner.decode("ascii", errors="replace").lower()
    matches: List[Dict] = []
    seen: set = set()
    for token, dtype, vendor in DEVICE_FINGERPRINTS:
        if token.lower() in text:
            key = (dtype, vendor)
            if key in seen:
                continue
            seen.add(key)
            matches.append({
                "device_type": dtype,
                "vendor_hint": vendor,
                "matched_token": token,
            })
    return matches


def extract_http_headers(banner: bytes) -> Dict[str, str]:
    """Parse HTTP response headers from a banner. Returns {header: value}."""
    if not banner:
        return {}
    text = banner.decode("ascii", errors="replace")
    # Split status line + headers
    parts = text.split("\r\n\r\n", 1)
    head = parts[0]
    headers: Dict[str, str] = {}
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers


# ═══════════════════════════════════════════════════════════════════════════
#  URGENT/11 PASSIVE CHECK
# ═══════════════════════════════════════════════════════════════════════════
def check_urgent11_indicators(banner: bytes, tcp_info: Optional[dict]) -> Optional[bool]:
    """Return True if passive indicators strongly suggest Nucleus NET
    (URGENT/11 affected), False if indicators rule it out, None if
    inconclusive.

    READ-ONLY: we inspect only banners / HTTP headers / socket options.
    We do NOT send any crafted TCP segment that would exercise the
    vulnerable code paths (CVE-2019-12255 etc.) — that could crash a
    production ventilator.
    """
    if not banner and not tcp_info:
        return None
    text = (banner or b"").decode("ascii", errors="replace").lower()
    headers = extract_http_headers(banner or b"")
    server_hdr = headers.get("server", "").lower()

    strong_tokens = []
    # Banner-side Nucleus tokens
    for tok in NUCLEUS_BANNER_TOKENS:
        if tok in text:
            strong_tokens.append(f"banner:{tok}")
    # HTTP Server header tokens
    for tok in NUCLEUS_HTTP_TOKENS:
        if tok in server_hdr:
            strong_tokens.append(f"server:{tok}")

    # Weak indicator: very small MSS (Nucleus NET historically advertises
    # MSS 512 / 536 / 1460; small MSS alone is not conclusive)
    weak = False
    if tcp_info:
        mss = tcp_info.get("mss")
        if mss and mss <= 536:
            weak = True

    if strong_tokens:
        return True
    if weak:
        return None  # inconclusive — could be a constrained embedded stack
    # No indicators at all
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  WEB LOGIN PAGE DETECTION (READ-ONLY)
# ═══════════════════════════════════════════════════════════════════════════
def _http_get(url: str, timeout: float = TIMEOUT_S) -> Tuple[int, bytes]:
    """GET with urllib (stdlib). Returns (status, body)."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "HVHARNESS/3.0.0 (med-device-probe; lab-only)",
            "Accept": "text/html,*/*",
        })
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.getcode(), r.read()
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, body
    except Exception:
        return 0, b""


def check_login_page(host: str, port: int) -> Optional[bool]:
    """Detect whether a web login form exists on the given port.

    READ-ONLY: we ONLY fetch "/" and look for a login form (input
    type=password). We never submit any credential.

    Returns:
      True  — a login page exists (default-credential risk is present)
      False — port reachable but no login form detected
      None  — port unreachable / not HTTP
    """
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}/"
    code, body = _http_get(url)
    if code == 0 or body == b"":
        return None
    text = body.decode("ascii", errors="replace").lower()
    # Heuristic: password input field + login-related keywords
    has_password_field = ("type=\"password\"" in text or
                          "type='password'" in text or
                          "<input type=password" in text or
                          "password" in text and "input" in text)
    login_keywords = ("login", "sign in", "logon", "authenticate",
                      "username", "user name", "user id", "userid")
    has_login_kw = any(kw in text for kw in login_keywords)
    if has_password_field and has_login_kw:
        return True
    if has_password_field:
        return True
    return False


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN SCAN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("Medical-device probing on production equipment "
                           "is illegal outside an authorized lab. HIPAA / "
                           "FDA / IEC 80001."),
        }))
        sys.exit(1)

    t0 = time.time()
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "sector": SECTOR_CFG.get("sector"),
        "safe_mode": SAFE_MODE,
        "read_only": READ_ONLY,
        "seed": SEED,
        # Spec-required output fields:
        "devices_found": 0,
        "device_types": [],
        "urgent11_vulnerable": None,
        "web_interfaces": [],
        "default_credential_risk": None,
        # Extra diagnostic fields:
        "open_ports": [],
        "fingerprints": [],
        "errors": [],
    }

    # Deterministic scan order (seedable)
    scan_ports = list(MED_PORTS)
    _rng.shuffle(scan_ports)

    open_ports: List[int] = []
    web_interfaces: List[Dict] = []
    all_device_types: List[str] = set() if False else []  # placeholder
    device_types_set: set = set()
    urgent11_evidence: List[str] = []
    urgent11_positive = False
    login_pages_found = 0
    fingerprints_all: List[Dict] = []

    for port in scan_ports:
        banner, tcp_info = banner_grab(HOST, port, timeout=TIMEOUT_S)
        if banner is None and tcp_info is None:
            continue
        open_ports.append(port)
        port_entry: Dict = {"port": port, "banner_preview": None,
                            "device_type": None, "vendor": None}
        if banner:
            # Truncate preview for the report (first 80 printable chars)
            preview = banner.decode("ascii", errors="replace")[:80]
            preview = "".join(ch if ch.isprintable() else "." for ch in preview)
            port_entry["banner_preview"] = preview

            # Fingerprint matching
            matches = match_fingerprints(banner)
            for m in matches:
                device_types_set.add(m["device_type"])
                fingerprints_all.append({
                    "port": port,
                    "device_type": m["device_type"],
                    "vendor_hint": m["vendor_hint"],
                    "matched_token": m["matched_token"],
                })
                if not port_entry["device_type"]:
                    port_entry["device_type"] = m["device_type"]
                    port_entry["vendor"] = m["vendor_hint"]

            # URGENT/11 passive check
            u11 = check_urgent11_indicators(banner, tcp_info)
            if u11 is True:
                urgent11_positive = True
                urgent11_evidence.append(f"port_{port}")
                port_entry["urgent11_indicator"] = True
            elif u11 is None:
                port_entry["urgent11_indicator"] = None

        # HTTP headers extraction (for web ports)
        if port in WEB_PORTS:
            headers = extract_http_headers(banner) if banner else {}
            web_entry = {
                "port": port,
                "has_http": bool(headers) or (banner and b"HTTP/" in banner[:32]),
                "server_header": headers.get("server"),
                "title": _extract_html_title(banner) if banner else None,
            }
            if web_entry["has_http"]:
                web_interfaces.append(web_entry)
                # Check for login page
                lp = check_login_page(HOST, port)
                if lp is True:
                    login_pages_found += 1
                    web_entry["login_page"] = True
                else:
                    web_entry["login_page"] = lp

    # ─── Aggregate results ───────────────────────────────────────────────
    summary["open_ports"] = sorted(open_ports)
    summary["devices_found"] = len(fingerprints_all) if fingerprints_all else len(open_ports)
    summary["device_types"] = sorted(device_types_set) if device_types_set else (
        [_infer_type_from_ports(open_ports)] if open_ports else []
    )
    summary["fingerprints"] = fingerprints_all
    summary["web_interfaces"] = web_interfaces
    summary["urgent11_vulnerable"] = True if urgent11_positive else (
        None if open_ports else None
    )
    if urgent11_evidence:
        summary["urgent11_evidence_ports"] = urgent11_evidence
    # Default-credential risk: True if we found a login page on any web port
    # READ-ONLY — we did NOT attempt any credential submission.
    if login_pages_found > 0:
        summary["default_credential_risk"] = True
    elif web_interfaces:
        # Web interfaces found but none with a login page → no obvious risk
        summary["default_credential_risk"] = False
    else:
        summary["default_credential_risk"] = None

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


def _extract_html_title(body: bytes) -> Optional[str]:
    """Extract <title>...</title> from an HTML body."""
    if not body:
        return None
    text = body.decode("ascii", errors="replace")
    low = text.lower()
    start = low.find("<title")
    if start == -1:
        return None
    gt = text.find(">", start)
    if gt == -1:
        return None
    end = low.find("</title>", gt)
    if end == -1:
        return None
    return text[gt + 1:end].strip()[:120]


def _infer_type_from_ports(open_ports: List[int]) -> str:
    """Best-effort device-type inference when no banner matched."""
    if any(p in open_ports for p in (4000, 4001, 4002)):
        return "unknown_medical_device"
    if 4170 in open_ports:
        return "imaging_workstation"
    if 9100 in open_ports:
        return "embedded_printer_or_analyzer"
    return "unknown"


if __name__ == "__main__":
    main()
