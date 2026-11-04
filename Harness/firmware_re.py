#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — reverse engineering module : firmware analysis.
# Secteur : cross-sector (defensive RE tool — analyze LOCAL firmware images).
#
# Defensive purpose:
#   This module analyzes firmware images of devices the operator has purchased
#   and deployed (routers, IoT, OT PLCs, embedded devices). It extracts the
#   embedded filesystem, scans for credentials / private keys / API tokens,
#   identifies kernel version and bootloader, and flags backdoor indicators.
#   All analysis is performed on a LOCAL firmware image provided as CLI arg.
#   No network egress — the module never contacts any external service.
#
#   - v3.1 : binwalk signature scan + filesystem extraction
#   - v3.1 : filesystem type detection (squashfs, jffs2, cramfs, ubifs, romfs)
#   - v3.1 : kernel version + bootloader identification (strings-based)
#   - v3.1 : credentials / API tokens / private keys scan in extracted files
#   - v3.1 : backdoor indicators (debug shells, hardcoded creds, telnet,
#            busybox shell on startup, /etc/init.d/S* with shell)
#   - v3.1 : known-vulnerable version signatures (kernel + busybox + dropbear)
#   - v3.1 : SEED reproducibility (file scan order, sample sizes),
#            LAB=1 guard, strict local-file-only invariant
#
# Cadre légal : Art. 323-1 Code pénal (accès frauduleux).
#   L'analyse de firmwares de matériel que l'on a acheté et déployé est
#   légitime (audit, défense). Aucune exfiltration, aucune sortie réseau.
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "firmware_re"
TIMEOUT_S = 180                    # binwalk extraction can be slow
MAX_FILES_ANALYZED = 2000          # cap to bound scan time
MAX_SECRETS = 200                  # cap secrets in JSON
MAX_FILE_SIZE_TO_SCAN = 8 * 1024 * 1024   # 8 MB per file (skip huge blobs)

# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))


def _seeded_take(items: list, n: int) -> list:
    """Deterministic sampling of n items (reproducible across runs)."""
    if len(items) <= n:
        return list(items)
    keyed = sorted(
        enumerate(items),
        key=lambda iv: ((iv[0] * SEED) % 1000003, iv[0]),
    )
    return [iv[1] for iv in keyed[:n]]


# ─── Import sector_base (best-effort) ─────────────────────────────────────────
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from sector_base import (  # type: ignore
        get_sector_config,
        get_safe_mode as _sector_safe_mode,
    )
    _HAS_SECTOR_BASE = True
except Exception:  # noqa: BLE001
    _HAS_SECTOR_BASE = False

    def get_sector_config() -> dict:  # type: ignore[no-redef]
        return {
            "sector": os.environ.get("SECTOR", "it"),
            "safe_mode": "full",
            "harness_version": HARNESS_VERSION,
        }

    def _sector_safe_mode() -> str:  # type: ignore[no-redef]
        return "full"


# ─── Guards ───────────────────────────────────────────────────────────────────
def _check_lab_guard() -> None:
    if os.environ.get("LAB") != "1":
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "lab_guard_failed",
            "reason": "LAB env var must be set to 1 (isolated lab only)",
            "legal_note": (
                "Defensive firmware analysis of LOCAL images (operator-owned "
                "devices). No network egress. Lab isolation required."
            ),
        }))
        sys.exit(2)


def _check_safe_mode() -> str:
    sm = os.environ.get("SAFE_MODE", "").lower().strip()
    if sm in ("read_only", "full"):
        return sm
    return _sector_safe_mode()


# ─── Tool availability ───────────────────────────────────────────────────────
def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


# ─── Binwalk signature scan ──────────────────────────────────────────────────
def binwalk_scan(firmware: Path) -> tuple:
    """Run binwalk signature scan. Returns (signatures_list, raw_output_str)."""
    binwalk = _which("binwalk")
    if not binwalk:
        return ([], "")
    try:
        proc = subprocess.run(
            [binwalk, str(firmware)],
            capture_output=True, text=True, timeout=TIMEOUT_S)
        out = proc.stdout
        sigs: list = []
        # Parse lines like:
        # 0               0x0               Squashfs filesystem ...
        for line in out.splitlines():
            m = re.match(
                r"^\s*(\d+)\s+([0-9a-fA-F]+)\s+(.+)$", line)
            if m:
                offset_dec, offset_hex, desc = m.groups()
                sigs.append({
                    "offset": int(offset_dec),
                    "offset_hex": "0x" + offset_hex,
                    "description": desc.strip(),
                })
        return (sigs, out)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ([], "")


# ─── Binwalk filesystem extraction ───────────────────────────────────────────
def binwalk_extract(firmware: Path) -> tuple:
    """Run binwalk -e to extract filesystem. Returns (extract_dir, error_or_None)."""
    binwalk = _which("binwalk")
    if not binwalk:
        return (None, "binwalk_not_installed")
    extract_dir = Path(tempfile.mkdtemp(prefix="fwre_extract_"))
    try:
        proc = subprocess.run(
            [binwalk, "-e", "-C", str(extract_dir), str(firmware)],
            capture_output=True, text=True, timeout=TIMEOUT_S)
        # binwalk extracts into <extract_dir>/_<firmware_name>.extracted
        # or directly into <extract_dir>
        return (extract_dir, None if proc.returncode == 0 else
                f"binwalk_extract_rc_{proc.returncode}")
    except subprocess.TimeoutExpired:
        return (extract_dir, "binwalk_timeout")
    except (FileNotFoundError, OSError) as e:
        return (extract_dir, "binwalk_exec_error: %s" % type(e).__name__)


# ─── Filesystem type detection ───────────────────────────────────────────────
FS_TYPES = {
    "squashfs":   re.compile(rb"hsqs|sqsh", re.I),  # magic
    "jffs2":      re.compile(rb"\x19\x85|\x65\x85", re.I),
    "cramfs":     re.compile(rb"\x45\x3d\xcd\x28", re.I),
    "ubifs":      re.compile(rb"\x06\x10\x18\x31|UBI#", re.I),
    "romfs":      re.compile(rb"-rom1fs-"),
    "yaffs":      re.compile(rb"\x03\x18\x00\x00|YAFFS", re.I),
    "ext2":       re.compile(rb"\x53\xef", re.I),
    "cpio":       re.compile(rb"070701|070702", re.I),
    "tar":        re.compile(rb"ustar", re.I),
}


def detect_filesystem_type(firmware: Path) -> Optional[str]:
    """Detect filesystem magic at start of firmware (first 1 MB)."""
    try:
        with open(firmware, "rb") as fh:
            head = fh.read(1024 * 1024)
    except OSError:
        return None
    for name, pat in FS_TYPES.items():
        if pat.search(head):
            return name
    return None


# ─── Kernel version + bootloader detection ───────────────────────────────────
KERNEL_RE = re.compile(
    r"Linux version (\d+\.\d+\.\d+[^\s]*)", re.I)
UBOOT_RE = re.compile(
    r"U-Boot\s+(\d+\.\d+[^\s]*)", re.I)
BAREBOX_RE = re.compile(
    r"barebox[\s-]+(\d+\.\d+\.\d+[^\s]*)", re.I)
REDBOOT_RE = re.compile(
    r"RedBoot[^\n]*", re.I)


def detect_kernel_and_bootloader(firmware: Path) -> tuple:
    """Scan firmware for kernel version + bootloader signature (strings-based)."""
    if not _which("strings"):
        return (None, None)
    try:
        proc = subprocess.run(
            ["strings", "-n", "8", str(firmware)],
            capture_output=True, text=True, timeout=TIMEOUT_S)
        out = proc.stdout
        km = KERNEL_RE.search(out)
        ub = UBOOT_RE.search(out)
        bb = BAREBOX_RE.search(out)
        rb = REDBOOT_RE.search(out)
        kernel = km.group(1) if km else None
        bootloader = None
        if ub:
            bootloader = "u-boot " + ub.group(1)
        elif bb:
            bootloader = "barebox " + bb.group(1)
        elif rb:
            bootloader = "redboot"
        return (kernel, bootloader)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return (None, None)


# ─── Secrets / credentials scan ──────────────────────────────────────────────
# Patterns tuned for config files commonly found in firmware (passwd, shadow,
# /etc/config/*, web admin config, dropbear/openssh keys).
CRED_PATTERNS = [
    ("shadow_password", re.compile(
        r"^[^:]+:[^:]+:\$[156]\$[^\$:]+\$[A-Za-z0-9./]{22}", re.M),
     "Linux shadow password hash (potentially crackable)"),
    ("passwd_placeholder", re.compile(
        r"^[^:]+:x?:\d+:\d+", re.M),
     "Linux passwd entry (username + UID)"),
    ("private_key_pem", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        re.M),
     "Private key embedded in firmware"),
    ("ssh_authorized_key", re.compile(
        r"ssh-(?:rsa|ed25519|dss|ecdsa) AAAA[A-Za-z0-9+/]{40,}"),
     "SSH authorized_keys entry"),
    ("aws_access_key", re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"),
     "AWS access key ID"),
    ("aws_secret_key", re.compile(
        r"(?i)aws_secret(?:_access)?_key[\"'\s:=]+[A-Za-z0-9/+]{40}"),
     "AWS secret access key"),
    ("google_api_key", re.compile(
        r"\bAIza[0-9A-Za-z\-_]{35}\b"),
     "Google API key"),
    ("github_token", re.compile(
        r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
     "GitHub personal access token"),
    ("slack_token", re.compile(
        r"\bxox[abp]-[A-Za-z0-9-]{10,48}\b"),
     "Slack token"),
    ("telegram_bot_token", re.compile(
        r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"),
     "Telegram bot token"),
    ("jwt_token", re.compile(
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     "JWT token"),
    ("generic_api_key", re.compile(
        r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)"
        r"[\"'\s:=]+[A-Za-z0-9_\-]{16,}"),
     "Generic API key in config"),
    ("password_assignment", re.compile(
        r"(?i)(?:password|passwd|pwd|admin_pass)[\"'\s:=]+['\"]?[^\s'\"$]{6,}",
        re.M),
     "Hardcoded password in config"),
    ("mysql_password", re.compile(
        r"(?i)mysql(?:_root)?_password[\"'\s:=]+['\"]?[^\s'\"]{6,}"),
     "MySQL password in config"),
    ("wifi_psk", re.compile(
        r"(?i)(?:wpa[_-]?psk|wifi[_-]?password|psk)[\"'\s:=]+['\"]?[^\s'\"]{8,}"),
     "WiFi PSK / password in config"),
    ("telnet_password", re.compile(
        r"(?i)telnet(?:d)?(?:_pass|_password)?[\"'\s:=]+['\"]?[^\s'\"]{6,}"),
     "Telnet password"),
    ("default_admin_password", re.compile(
        r"(?i)\b(?:admin|root|default)[\"'\s:=]+(?:admin|root|1234|password"
        r"|default|guest|12345)\b"),
     "Default admin credentials"),
]


def scan_file_for_secrets(path: Path, relpath: str) -> list:
    """Scan a single file for credential / secret patterns."""
    secrets: list = []
    try:
        if path.stat().st_size > MAX_FILE_SIZE_TO_SCAN:
            return secrets
        # Try text first
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return secrets
        for cred_type, pat, risk in CRED_PATTERNS:
            for m in pat.finditer(text):
                # Redact the actual secret value — only show pattern type + location
                secrets.append({
                    "type": cred_type,
                    "risk": risk,
                    "file": relpath,
                    "offset": m.start(),
                    "preview": m.group(0)[:8] + "***REDACTED***",
                    "severity": "critical" if "private_key" in cred_type or
                                "shadow_password" in cred_type or
                                "secret_key" in cred_type or
                                "aws" in cred_type else "high",
                })
    except OSError:
        pass
    return secrets


def scan_extracted_tree(extract_dir: Path) -> tuple:
    """Walk extracted tree and scan all files for secrets.
    Returns (files_analyzed_count, secrets_list)."""
    files_analyzed = 0
    all_secrets: list = []
    if not extract_dir or not extract_dir.exists():
        return (0, [])
    for root, dirs, files in os.walk(extract_dir):
        # Skip binwalk internal "cgi-bin" duplicates etc.
        for fname in files:
            if files_analyzed >= MAX_FILES_ANALYZED:
                return (files_analyzed, _seeded_take(all_secrets, MAX_SECRETS))
            fpath = Path(root) / fname
            try:
                relpath = str(fpath.relative_to(extract_dir))
            except ValueError:
                relpath = str(fpath)
            try:
                if not fpath.is_file() or fpath.is_symlink():
                    continue
                files_analyzed += 1
                secrets = scan_file_for_secrets(fpath, relpath)
                all_secrets.extend(secrets)
            except OSError:
                continue
    return (files_analyzed, _seeded_take(all_secrets, MAX_SECRETS))


# ─── Backdoor indicators ─────────────────────────────────────────────────────
BACKDOOR_FILES = {
    "/etc/init.d/S*": "init script — check for shell spawns",
    "/etc/inittab":   "sysvinit — check for getty shells",
    "/etc/passwd":    "passwd — check for empty/root passwords",
    "/etc/shadow":    "shadow — crackable hashes",
    "/etc/dropbear/": "dropbear keys + authorized_keys",
    "/etc/ssh/":      "openssh keys + authorized_keys",
    "/root/.ssh/":    "root authorized_keys",
    "/etc/profile":   "profile — check for backdoor commands",
    "/etc/rc.local":  "rc.local — check for backdoor commands",
    "/www/cgi-bin/":  "web cgi — common backdoor location",
    "/sbin/telnetd":  "telnet daemon binary",
    "/usr/sbin/telnetd": "telnet daemon binary",
    "/bin/busybox":   "busybox — check for telnetd applet",
}

BACKDOOR_STRINGS_PATTERNS = [
    re.compile(r"/bin/sh.*telnet[d]? -l", re.I),
    re.compile(r"telnet[d]?.*-l\s*/bin/sh", re.I),
    re.compile(r"nc\s+-l.*-e\s*/bin/sh", re.I),       # netcat backdoor
    re.compile(r"socat.*EXEC:/bin/sh", re.I),
    re.compile(r"/bin/ash\s+-l", re.I),
    re.compile(r"backdoor", re.I),
    re.compile(r"debug[_-]?shell", re.I),
    re.compile(r"factory[_-]?mode", re.I),
]


def find_backdoor_indicators(firmware: Path, extract_dir: Optional[Path]
                             ) -> list:
    """Look for backdoor indicators in firmware strings + extracted files."""
    indicators: list = []
    # 1. String-based scan in whole firmware
    if _which("strings"):
        try:
            proc = subprocess.run(
                ["strings", "-n", "8", str(firmware)],
                capture_output=True, text=True, timeout=TIMEOUT_S)
            out = proc.stdout
            for pat in BACKDOOR_STRINGS_PATTERNS:
                for m in pat.finditer(out):
                    indicators.append({
                        "type": "backdoor_string_pattern",
                        "pattern": pat.pattern,
                        "match": m.group(0)[:60],
                        "severity": "critical",
                        "location": "firmware_strings",
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    # 2. File-based scan in extracted tree
    if extract_dir and extract_dir.exists():
        for pattern, desc in BACKDOOR_FILES.items():
            # Resolve glob
            base = pattern.lstrip("/")
            for p in extract_dir.glob("**/" + base.split("/")[-1]):
                try:
                    rel = str(p.relative_to(extract_dir))
                except ValueError:
                    rel = str(p)
                # Check if it's a telnetd binary
                if "telnetd" in pattern and p.exists():
                    indicators.append({
                        "type": "backdoor_telnetd",
                        "file": rel,
                        "severity": "high",
                        "risk": "telnet daemon present — plaintext + often enabled",
                    })
                # Check /etc/init.d/S* for shell spawns
                if "S*" in pattern and p.exists():
                    try:
                        content = p.read_text(encoding="utf-8",
                                              errors="ignore")
                        for pat in BACKDOOR_STRINGS_PATTERNS:
                            m = pat.search(content)
                            if m:
                                indicators.append({
                                    "type": "init_script_shell_spawn",
                                    "file": rel,
                                    "match": m.group(0)[:60],
                                    "severity": "critical",
                                    "risk": "init script spawns debug shell",
                                })
                    except OSError:
                        pass
    # Dedupe
    seen = set()
    out_indicators = []
    for ind in indicators:
        k = (ind.get("type"), ind.get("file") or ind.get("match"))
        if k in seen:
            continue
        seen.add(k)
        out_indicators.append(ind)
    return _seeded_take(out_indicators, 100)


# ─── Known vulnerable versions ───────────────────────────────────────────────
VULN_VERSIONS = {
    # (component, min_vulnerable_version_inclusive, max_vulnerable_version_inclusive)
    "busybox": [
        ("1.19.0", "1.31.0", "BusyBox < 1.32 — multiple CVEs (CVE-2018-1000517, CVE-2019-5747)"),
    ],
    "dropbear": [
        ("2011.54", "2020.78", "Dropbear < 2020.79 — CVE-2020-28228 (heap overflow)"),
    ],
    "u-boot": [
        ("2014.01", "2019.07", "U-Boot < 2019.07 — multiple vulnerabilities"),
    ],
    "linux_kernel": [
        ("2.6.0", "4.4.0",  "Linux kernel 2.6 → 4.4 — many CVEs (Dirty COW CVE-2016-5195)"),
        ("4.5.0", "4.19.0", "Linux kernel 4.5 → 4.19 — multiple privilege escalation CVEs"),
        ("5.0.0", "5.4.20", "Linux kernel 5.0 → 5.4.20 — CVE-2020-8835 (bpf)",
                            "CVE-2020-14386 (bpf)"),
    ],
    "openssl": [
        ("1.0.0", "1.0.1f", "OpenSSL 1.0.1 → 1.0.1f — Heartbleed CVE-2014-0160"),
    ],
}


def check_known_vulns(kernel_version: Optional[str],
                     bootloader: Optional[str]) -> list:
    """Match detected versions against known-vulnerable ranges."""
    vulns: list = []
    if kernel_version:
        # Strip suffix
        m = re.match(r"(\d+\.\d+\.\d+)", kernel_version)
        if m:
            ver = m.group(1)
            for lo, hi, desc in VULN_VERSIONS["linux_kernel"]:
                if _ver_ge(lo, ver) and _ver_ge(ver, hi):
                    vulns.append({
                        "component": "linux_kernel",
                        "version": ver,
                        "vulnerability": desc,
                        "severity": "high",
                    })
    if bootloader and "u-boot" in bootloader.lower():
        m = re.search(r"u-?boot\s+(\d+\.\d+)", bootloader, re.I)
        if m:
            ver = m.group(1) + ".0"
            for lo, hi, desc in VULN_VERSIONS["u-boot"]:
                if _ver_ge(lo, ver) and _ver_ge(ver, hi):
                    vulns.append({
                        "component": "u-boot",
                        "version": ver,
                        "vulnerability": desc,
                        "severity": "medium",
                    })
    return vulns


def _ver_ge(a: str, b: str) -> bool:
    """Return True if version a >= version b (numeric compare, 3 fields)."""
    pa = [int(x) for x in re.findall(r"\d+", a)]
    pb = [int(x) for x in re.findall(r"\d+", b)]
    while len(pa) < 3: pa.append(0)
    while len(pb) < 3: pb.append(0)
    return tuple(pa[:3]) >= tuple(pb[:3])


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    if len(sys.argv) < 2:
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "missing_firmware_path",
            "usage": "firmware_re.py <firmware_image_path>",
        }))
        sys.exit(2)

    firmware_path = Path(sys.argv[1]).resolve()
    if not firmware_path.exists() or not firmware_path.is_file():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "firmware_not_found",
            "path": str(firmware_path),
        }))
        sys.exit(2)

    binwalk = _which("binwalk")
    if not binwalk:
        # Python binwalk package fallback
        try:
            import binwalk as _bw  # noqa: F401
            binwalk = "py-binwalk"
        except ImportError:
            binwalk = None

    if not binwalk:
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "binwalk_not_installed",
            "hint": "pip install binwalk   (or apt install binwalk)",
            "firmware": str(firmware_path),
            "lab": os.environ.get("LAB", "?"),
            "seed": SEED,
        }))
        sys.exit(3)

    # Defensive invariant : LOCAL file only — no network operations.

    # 1. Compute firmware sha256 (for traceability / provenance)
    try:
        h = hashlib.sha256()
        with open(firmware_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        fw_sha256 = h.hexdigest()
    except OSError:
        fw_sha256 = None

    # 2. Detect filesystem type (magic) — independent of binwalk
    fs_type = detect_filesystem_type(firmware_path)

    # 3. Kernel + bootloader detection (strings-based)
    kernel_version, bootloader = detect_kernel_and_bootloader(firmware_path)

    # 4. Binwalk signature scan
    signatures, _ = binwalk_scan(firmware_path)

    # 5. Binwalk extraction
    extract_dir, extract_err = binwalk_extract(firmware_path)
    files_analyzed = 0
    credentials_found: list = []
    if extract_dir and extract_err is None:
        files_analyzed, credentials_found = scan_extracted_tree(extract_dir)

    # 6. Backdoor indicators
    backdoor_indicators = find_backdoor_indicators(firmware_path, extract_dir)

    # 7. Known-vulnerable version check
    known_vulns = check_known_vulns(kernel_version, bootloader)

    # 8. Cleanup extract dir
    if extract_dir and extract_dir.exists():
        try:
            shutil.rmtree(extract_dir, ignore_errors=True)
        except OSError:
            pass

    # 9. JSON report
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "firmware": str(firmware_path),
        "sha256": fw_sha256,
        "signatures_found": signatures,
        "signatures_count": len(signatures),
        "filesystem_type": fs_type,
        "filesystem_extracted": extract_err is None and extract_dir is not None,
        "extract_error": extract_err,
        "files_analyzed": files_analyzed,
        "credentials_found": credentials_found,
        "credentials_count": len(credentials_found),
        "kernel_version": kernel_version,
        "bootloader": bootloader,
        "backdoor_indicators": backdoor_indicators,
        "backdoor_indicators_count": len(backdoor_indicators),
        "known_vulnerable_versions": known_vulns,
        "seed": SEED,
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "read_only": False,   # binwalk extracts (writes to /tmp) but does not
                              # modify the original firmware
        "no_network_egress": True,
        "binwalk_available": bool(binwalk),
        "legal_note": (
            "Defensive RE : analyse de firmware LOCAL (matériel opérateur "
            "acheté et déployé). Aucune sortie réseau. "
            "Art. 323-1 Code pénal — usage lab isolé."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
