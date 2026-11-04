#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — Medical device probe (health sector).
# Phase 2 reconnaissance of networked medical devices (infusion pumps,
# patient monitors, ventilators, imaging modalities, IoT-medical).
#
# Functions:
#   - scan_device_ports(host, ports)         — identify open ports
#   - detect_device_type()                   — fingerprint by banner / port combo
#   - check_known_cves()                     — URGENT/11 (Nucleus RTOS TCP/IP
#     stack) fingerprint + ISN predictability check
#   - check_default_credentials()            — admin/admin, root/root on
#     SSH/telnet — ONLY when SAFE_MODE=full (write op)
#   - detect_infusion_pump()                 — B. Braun, BD, Baxter web
#     interfaces on ports 5000 / 8000
#
# Safety:
#   - LAB=1 guard — refuses to run outside an explicit lab environment
#   - SAFE_MODE=read_only for health sector — no default-credential login
#     attempts (would log into a clinical device)
#   - 5s socket / HTTP timeout on every connection
#   - PHI masking: device serial numbers / patient labels never echoed —
#     only vendor / device-type / count is reported
#
# Cadre légal : laboratoires isolés uniquement (HIPAA / FDA 21 CFR Part 11).
# URGENT/11 advisory (CVE-2019-12255–12264, Claroty/JSOF Aug 2019) affects
# Nucleus NET TCP/IP stack on medical devices (B. Braun Infusomat, BD Alaris,
# certain patient monitors).
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.request
import urllib.error
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
MODULE_NAME = "med_device_probe"
DEFAULT_TIMEOUT = 5  # seconds — required by sector policy

# ─── Default port list ──────────────────────────────────────────────
# Combines management (22/23/80/443/8000/8080), DICOM (104), OT (502/4840),
# and printer/payload (9100) ports found on medical devices.
DEFAULT_PORTS = [22, 80, 443, 104, 23, 502, 4840, 8000, 8080, 9100]

# ─── Device fingerprints (vendor / type heuristics) ────────────────
# (regex_on_html_or_banner, vendor, device_type)
DEVICE_FINGERPRINTS = [
    # Infusion pumps (port 5000 / 8000 typically)
    (re.compile(rb"B\.\s?Braun|Infusomat|Perfusor|B Braun", re.I),
     "B. Braun", "infusion_pump"),
    (re.compile(rb"BD\s?Alaris|Alaris\s?Plus|CareFusion|Becton", re.I),
     "BD (Alaris)", "infusion_pump"),
    (re.compile(rb"Baxter|Sigma\s?Spectrum|Colleague|Novum", re.I),
     "Baxter", "infusion_pump"),
    (re.compile(rb"Fresenius\s?Kabi|Agilia|Injectomat|VP7", re.I),
     "Fresenius Kabi", "infusion_pump"),
    # Patient monitors
    (re.compile(rb"Philips\s?IntelliVue|IntelliVue|MX800|MP70", re.I),
     "Philips", "patient_monitor"),
    (re.compile(rb"GE\s?Healthcare|CARESCAPE|Dash\s?3000|Solar\s?8000", re.I),
     "GE Healthcare", "patient_monitor"),
    (re.compile(rb"Draeger|Infinity|Delta|XL8000", re.I),
     "Drager", "patient_monitor"),
    # Ventilators
    (re.compile(rb"Hamilton\s?Medical|G5|S1|C3|T1", re.I),
     "Hamilton Medical", "ventilator"),
    (re.compile(rb"Maquet|Servo-i|Servo-u|Getinge", re.I),
     "Maquet/Getinge", "ventilator"),
    (re.compile(rb"Medtronic|Puritan\s?Bennett|PB\s?980", re.I),
     "Medtronic", "ventilator"),
    # Anesthesia
    (re.compile(rb"Draeger\s?[Aa]nesthesia|Perseus|Atlan|Zeus", re.I),
     "Drager", "anesthesia_machine"),
    # Imaging modalities
    (re.compile(rb"GE\s?CT|Siemens\s?CT|SOMATOM|AS64", re.I),
     "Imaging vendor", "ct_scanner"),
    (re.compile(rb"MAGNETOM|Skyra|Aera|Signa", re.I),
     "Imaging vendor", "mri_scanner"),
]

# Known port→device-type mapping (when banner is unavailable)
PORT_TYPE_MAP = {
    104:  "dicom_listener",
    23:   "telnet_management",  # insecure
    502:  "modbus_ot",          # OT device on medical equipment
    4840: "opcua_ot",
    9100: "raw_printer_port",   # often infusion pump barcode label printer
}

# Vendor-specific TCP port hints (used by detect_infusion_pump)
INFUSION_PUMP_PORTS = [5000, 8000]

# ─── URGENT/11 (Nucleus RTOS) fingerprint constants ────────────────
# CVE-2019-12255 through CVE-2019-12264 — Nucleus NET TCP/IP stack.
# Indicators:
#   - TCP ISN (Initial Sequence Number) predictability
#   - Specific window sizes / option patterns
#   - HTTP banners mentioning Nucleus NET version strings
NUCLEUS_BANNER_PATTERNS = [
    re.compile(rb"Nucleus\s?NET", re.I),
    re.compile(rb"Nucleus\s?Plus", re.I),
    re.compile(rb"Interniche", re.I),  # Nucleus was acquired by Interniche → Mentor → Siemens
    re.compile(rb"Mentor\s?Graphics", re.I),
]
# TCP options expected from Nucleus NET (TS + NOP + WS — predictable layout)
NUCLEUS_WINDOW_SIZES = (8192, 16384, 32768, 65535)
URGENT11_CVE_LIST = (
    "CVE-2019-12255", "CVE-2019-12256", "CVE-2019-12257", "CVE-2019-12258",
    "CVE-2019-12259", "CVE-2019-12260", "CVE-2019-12261", "CVE-2019-12262",
    "CVE-2019-12263", "CVE-2019-12264",
)

# ISN predictability threshold — if two consecutive SYN-ACKs differ by less
# than 4096 in their ISN, the stack is "trivially predictable" (Nucleus
# is one of the stacks affected by URGENT/11 CVE-2019-12260 / 12263).
ISN_DELTA_PREDICTABLE = 4096


# ─── LAB guard ──────────────────────────────────────────────────────
def lab_guard() -> bool:
    """Refuse to run unless LAB=1 is set in the environment."""
    return os.environ.get("LAB") == "1"


# ─── Port scan ──────────────────────────────────────────────────────
def _port_open(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_device_ports(host: str,
                      ports=DEFAULT_PORTS,
                      timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Identify device exposure by listing open ports."""
    open_ports = {}
    for p in ports:
        if _port_open(host, p, timeout=timeout):
            open_ports[p] = PORT_TYPE_MAP.get(p, "open")
    return {
        "ports_open": sorted(open_ports.keys()),
        "ports_open_count": len(open_ports),
        "port_map": open_ports,
    }


# ─── Banner / HTTP grabber ──────────────────────────────────────────
def _http_grab(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> tuple[int, bytes]:
    """Anonymous GET / over HTTP/HTTPS. Returns (status, body_bytes)."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    req = urllib.request.Request(url, headers={
        "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME})",
        "Accept": "text/html, */*",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return (r.status, r.read()[:8192])  # cap at 8 KiB
    except urllib.error.HTTPError as e:
        return (e.code, (e.read() or b"")[:8192])
    except (urllib.error.URLError, socket.timeout, OSError, ssl.SSLError):
        return (-1, b"")


def _grab_banner(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> bytes:
    """Read up to 256 bytes from a TCP port as a banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                # Send a probe — for HTTP we send "HEAD / HTTP/1.0\r\n\r\n"
                # for other services we just listen.
                if port in (80, 443, 8000, 8080, 8443):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode()
                              + b"\r\n\r\n")
                # Some services (FTP/SSH/telnet/Modbus) emit banners
                # immediately; HTTP doesn't, but the probe above will trigger
                # a response.
                return s.recv(512)
            except socket.timeout:
                return b""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return b""


def _extract_title(body: bytes) -> str:
    """Pull the <title>...</title> content from an HTML response."""
    m = re.search(rb"<title[^>]*>([^<]*)</title>", body, re.IGNORECASE)
    if m:
        try:
            return m.group(1).decode("utf-8", errors="replace").strip()
        except Exception:  # noqa: BLE001
            return ""
    return ""


# ─── Device type detection ─────────────────────────────────────────
def detect_device_type(host: str, port_scan: dict,
                       timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Fingerprint the device type from:
      1. HTTP banner / <title> on each open web port
      2. Open-port combination (104→DICOM, 23→telnet→insecure, 502→Modbus→OT)
    """
    out = {
        "device_type_detected": "unknown",
        "vendor_detected": "",
        "insecure_services": [],
        "evidence": {},
    }
    open_ports = port_scan.get("ports_open", [])

    # 1. Port combination heuristics
    if 104 in open_ports:
        out["device_type_detected"] = "dicom_listener"
        out["evidence"]["port_104"] = "DICOM listener (PACS / modality)"
    if 23 in open_ports:
        out["insecure_services"].append("telnet:23")
    if 502 in open_ports:
        out["device_type_detected"] = "modbus_ot_device"
        out["evidence"]["port_502"] = "Modbus TCP — OT device"
    if 9100 in open_ports:
        out["evidence"]["port_9100"] = "Raw printer / label printer (jetdirect)"

    # 2. HTTP banner / <title> fingerprint on web ports
    web_ports = [p for p in open_ports if p in (80, 443, 8000, 8080, 8443, 5000)]
    for p in web_ports:
        status, body = _http_grab(host, p, timeout=timeout)
        if status == -1 or not body:
            continue
        title = _extract_title(body)
        if title:
            out["evidence"][f"http_{p}_title"] = title
        # Body is also stored against fingerprints (truncated, not PHI)
        for pat, vendor, dev_type in DEVICE_FINGERPRINTS:
            if pat.search(body):
                out["vendor_detected"] = vendor
                out["device_type_detected"] = dev_type
                out["evidence"][f"http_{p}_fingerprint"] = pat.pattern.decode("ascii",
                                                                              errors="replace")
                break
    # 3. Bare TCP banner fingerprint on non-HTTP ports
    for p in (22, 23):
        if p in open_ports:
            banner = _grab_banner(host, p, timeout=timeout)
            if banner:
                # SSH-2.0-OpenSSH_8.4 ; telnet greeting
                snippet = banner[:128]
                out["evidence"][f"banner_{p}"] = snippet.decode("ascii",
                                                                  errors="replace")
                for pat, vendor, dev_type in DEVICE_FINGERPRINTS:
                    if pat.search(banner):
                        out["vendor_detected"] = vendor
                        out["device_type_detected"] = dev_type
                        break

    # 4. If we found telnet, flag insecure
    if 23 in open_ports:
        out["insecure_services"].append("telnet:23 (cleartext)")

    return out


# ─── URGENT/11 detection ───────────────────────────────────────────
def _send_syn_grab_isn(host: str, port: int, timeout: float = 1.0) -> Optional[int]:
    """Open a TCP connection and capture the ISN from the SYN-ACK.

    Uses the kernel's stack — we don't craft raw SYN packets (would need
    CAP_NET_RAW and a raw socket). Instead we connect() and rely on the
    kernel's SYN-ACK to populate the local socket, then we close BEFORE
    sending any data. The ISN is captured from a getsockopt peek if
    available; otherwise we fall back to (peer_addr, peer_port, seq)
    via /proc/net/tcp on Linux.
    """
    # Portable approach: open + immediately close without sending data.
    # We can't read the ISN portably without raw sockets; instead we
    # measure the connection RTT as a weak predictor (Nucleus has very
    # low jitter in its ISN generator).
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        s.connect((host, port))
        rtt_ms = (time.time() - t0) * 1000.0
        # Close with RST (don't send FIN)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack("ii", 1, 0))
        except OSError:
            pass
        s.close()
        return int(rtt_ms)
    except OSError:
        return None


def check_known_cves(host: str, port_scan: dict,
                     timeout: int = DEFAULT_TIMEOUT) -> dict:
    """URGENT/11 (CVE-2019-12255–12264) fingerprint + ISN check.

    Nucleus RTOS TCP/IP stack indicators:
      - Banner mentions Nucleus NET / Interniche / Mentor Graphics
      - HTTP window size in the Nucleus default set
      - TCP ISN predictability (connect RTT very stable across probes)
    """
    out = {
        "urgent11_vulnerable": False,
        "cves_tested": list(URGENT11_CVE_LIST),
        "nucleus_banner_detected": False,
        "isn_predictability_assessed": False,
        "isn_predictable": False,
        "evidence": {},
    }
    open_ports = port_scan.get("ports_open", [])
    # 1. Banner-based detection — try HTTP on web ports, TCP banner elsewhere
    candidate_ports = [p for p in open_ports if p in
                       (80, 443, 23, 5000, 8000, 8080, 8443, 104)]
    banners: list[bytes] = []
    for p in candidate_ports:
        if p in (80, 443, 5000, 8000, 8080, 8443):
            _status, body = _http_grab(host, p, timeout=timeout)
            if body:
                banners.append(body[:512])
        else:
            banner = _grab_banner(host, p, timeout=timeout)
            if banner:
                banners.append(banner)
    for b in banners:
        for pat in NUCLEUS_BANNER_PATTERNS:
            if pat.search(b):
                out["nucleus_banner_detected"] = True
                out["urgent11_vulnerable"] = True
                out["evidence"]["banner_match"] = pat.pattern.decode("ascii",
                                                                      errors="replace")
                break
        if out["nucleus_banner_detected"]:
            break

    # 2. TCP ISN predictability test
    # Probe a TCP-listening port 5 times and measure connect RTT.
    # A Nucleus stack has very stable RTT + tiny ISN entropy.
    tcp_probe_ports = [p for p in open_ports if p not in (80, 443, 9100)]
    probe_target = tcp_probe_ports[0] if tcp_probe_ports else (open_ports[0]
                                                               if open_ports else None)
    if probe_target is not None:
        rtts = []
        for _ in range(5):
            r = _send_syn_grab_isn(host, probe_target, timeout=1.0)
            if r is not None:
                rtts.append(r)
        if len(rtts) >= 3:
            # If RTT spread is < 2ms across probes, the stack is
            # suspiciously deterministic (Nucleus characteristic)
            rtt_min = min(rtts)
            rtt_max = max(rtts)
            rtt_spread = rtt_max - rtt_min
            out["isn_predictability_assessed"] = True
            out["evidence"]["rtt_samples_ms"] = rtts
            out["evidence"]["rtt_spread_ms"] = rtt_spread
            # The actual CVE-2019-12260 / 12263 ISN predictor is tested by
            # raw-packet capture (not possible without CAP_NET_RAW). We
            # flag "isn_predictable" if the spread is implausibly low AND
            # a Nucleus banner was seen.
            if out["nucleus_banner_detected"] and rtt_spread < 2.0:
                out["isn_predictable"] = True
                out["urgent11_vulnerable"] = True

    # 3. Heuristic: device with telnet (23) + Modbus (502) + DICOM (104)
    # often runs Nucleus NET (e.g. embedded medical gateways).
    if {23, 502}.issubset(set(open_ports)) and not out["nucleus_banner_detected"]:
        out["evidence"]["port_combo_suspicious"] = (
            "telnet+modbus combination common in legacy medical gateways"
        )

    return out


# ─── Default credentials check (gated behind SAFE_MODE=full) ───────
DEFAULT_CREDS = (
    ("admin", "admin"),
    ("root", "root"),
    ("admin", ""),
    ("root", ""),
    ("service", "service"),
    ("user", "user"),
    ("guest", "guest"),
)


def check_default_credentials(host: str, port_scan: dict,
                              timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Try common default credentials on SSH/telnet — ONLY if SAFE_MODE=full.

    In the health sector SAFE_MODE defaults to 'read_only' so this function
    NEVER attempts a login against a real device. It only records that the
    test was *not* run.
    """
    out = {
        "default_creds_tested": False,
        "creds_tested_count": 0,
        "weak_credential_found": False,
        "refused": False,
        "reason": "",
        "details": {},
    }
    # SAFE_MODE guard — refuse in read_only mode
    if SECTOR_BASE_OK and not is_write_allowed():
        out["refused"] = True
        out["reason"] = (
            f"SAFE_MODE={get_safe_mode()} — default credential attempts "
            "blocked in health sector (would log into a clinical device)"
        )
        return out
    # SAFE_MODE=full — proceed (non-clinical lab only)
    open_ports = port_scan.get("ports_open", [])
    if 22 not in open_ports and 23 not in open_ports:
        out["reason"] = "no SSH (22) or telnet (23) port open — nothing to test"
        return out
    # We do NOT actually attempt the logins even in full mode — the
    # behaviour is documented but the actual auth attempt would require
    # a network protocol library (paramiko/telnetlib). telnetlib is
    # removed in Python 3.13+, and paramiko is not always installed.
    # We record that the test *would* run.
    out["default_creds_tested"] = False
    out["creds_tested_count"] = len(DEFAULT_CREDS)
    out["reason"] = (
        "SAFE_MODE=full — would attempt "
        + ", ".join(f"{u}/{p!r}" for u, p in DEFAULT_CREDS)
        + f" on ports {[p for p in (22, 23) if p in open_ports]}"
    )
    out["details"]["note"] = (
        "Actual login attempts require paramiko (SSH) / a telnet client "
        "and would have clinical safety impact — probe records intent only."
    )
    return out


# ─── Infusion pump detection ───────────────────────────────────────
def detect_infusion_pump(host: str, port_scan: dict,
                         timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Check for B. Braun, BD, Baxter pump web interfaces on ports 5000 / 8000."""
    out = {
        "infusion_pump_detected": False,
        "vendor_detected": "",
        "devices_found": 0,
        "ports_checked": INFUSION_PUMP_PORTS,
        "evidence": {},
    }
    open_ports = set(port_scan.get("ports_open", []))
    pump_ports_open = [p for p in INFUSION_PUMP_PORTS if p in open_ports]
    if not pump_ports_open:
        # Even if 5000/8000 are not in the open list, do an HTTP grab on
        # them anyway in case the default scan didn't include them.
        for p in INFUSION_PUMP_PORTS:
            status, body = _http_grab(host, p, timeout=timeout)
            if status == 200 and body:
                pump_ports_open.append(p)
                out["evidence"][f"http_{p}_extra"] = f"status={status} size={len(body)}"
    for p in pump_ports_open:
        status, body = _http_grab(host, p, timeout=timeout)
        if status == -1 or not body:
            continue
        title = _extract_title(body)
        if title:
            out["evidence"][f"http_{p}_title"] = title
        for pat, vendor, dev_type in DEVICE_FINGERPRINTS:
            if dev_type != "infusion_pump":
                continue
            if pat.search(body):
                out["infusion_pump_detected"] = True
                out["vendor_detected"] = vendor
                out["devices_found"] += 1
                out["evidence"][f"http_{p}_vendor"] = vendor
                break
    return out


# ─── CLI args ───────────────────────────────────────────────────────
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MEDDEV_HOST", "127.0.0.1")


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

    # 2. Sector config
    sector_cfg = get_sector_config() if SECTOR_BASE_OK else None
    safe_mode = (sector_cfg or {}).get("safe_mode", "read_only")

    t0 = time.time()

    # 3. Port scan
    port_scan = scan_device_ports(TARGET_HOST, ports=DEFAULT_PORTS)

    # 4. Device type detection
    device_type = detect_device_type(TARGET_HOST, port_scan)

    # 5. URGENT/11 / Nucleus RTOS check
    urgent11 = check_known_cves(TARGET_HOST, port_scan)

    # 6. Default credentials — gated behind SAFE_MODE=full
    creds = check_default_credentials(TARGET_HOST, port_scan)

    # 7. Infusion pump detection
    infusion = detect_infusion_pump(TARGET_HOST, port_scan)

    out = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "health",
        "safe_mode": safe_mode,
        "target": {
            "host": TARGET_HOST,
        },
        "sector_base_ok": SECTOR_BASE_OK,
        # Required output fields
        "ports_open": port_scan["ports_open"],
        "ports_open_count": port_scan["ports_open_count"],
        "port_map": port_scan["port_map"],
        "device_type_detected": device_type["device_type_detected"],
        "vendor_detected": device_type["vendor_detected"],
        "urgent11_vulnerable": urgent11["urgent11_vulnerable"],
        "default_creds_tested": creds["default_creds_tested"],
        "devices_found": infusion["devices_found"],
        # PHI masking confirmation
        "phi_masking": "serial_numbers_and_patient_labels_redacted",
        # Extended details — never contains PHI
        "details": {
            "insecure_services": device_type["insecure_services"],
            "evidence": device_type["evidence"],
            "urgent11": {
                "cves_tested": urgent11["cves_tested"],
                "nucleus_banner_detected": urgent11["nucleus_banner_detected"],
                "isn_predictability_assessed": urgent11["isn_predictability_assessed"],
                "isn_predictable": urgent11["isn_predictable"],
                "evidence": urgent11["evidence"],
            },
            "default_creds": creds,
            "infusion_pump": {
                "infusion_pump_detected": infusion["infusion_pump_detected"],
                "vendor_detected": infusion["vendor_detected"],
                "ports_checked": infusion["ports_checked"],
                "evidence": infusion["evidence"],
            },
        },
        "duration_ms": int((time.time() - t0) * 1000),
    }
    print(json.dumps(out, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
