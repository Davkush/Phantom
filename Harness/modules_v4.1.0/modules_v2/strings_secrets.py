#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — reverse engineering module : strings + secrets.
# Secteur : cross-sector (defensive RE tool — extract secrets from LOCAL files).
#
# Defensive purpose:
#   This module extracts printable strings from LOCAL binaries / firmware
#   images on the operator's OWN systems (recovered during IR, from devices
#   purchased and deployed, or from build artifacts). It then runs pattern
#   matching for known secret formats (AWS keys, JWTs, PEM keys, API tokens)
#   and Shannon entropy analysis to flag high-entropy strings (potential
#   crypto keys, base64/hex-encoded secrets).
#
#   No network egress — all analysis is on the LOCAL file. Secrets found are
#   REDACTED in the JSON output (only previews shown, never full values) to
#   avoid leaking them into downstream logs / orchestrator state.
#
#   - v3.1 : strings(1) extraction with configurable min length
#   - v3.1 : raw-bytes fallback when strings(1) unavailable
#   - v3.1 : Shannon entropy per string (flag > 4.0 bits/char)
#   - v3.1 : pattern matching : AWS keys, GCP keys, GitHub tokens, Slack,
#            JWT, PEM private keys, SSH keys, Telegram, Stripe, generic
#            api_key/secret/password assignments
#   - v3.1 : URL / IP / email / bitcoin address extraction
#   - v3.1 : crypto indicators (PEM headers, ASN.1 OIDs, PKCS markers)
#   - v3.1 : SEED reproducibility (string sampling order),
#            LAB=1 guard, strict local-file-only invariant
#
# Cadre légal : Art. 323-1 Code pénal (accès frauduleux).
#   L'extraction de secrets de binaires sur ses propres systèmes est
#   légitime (audit, IR). Aucune exfiltration, aucune sortie réseau.
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "strings_secrets"
TIMEOUT_S = 120
MAX_STRINGS = 50000              # cap to bound JSON + memory
MAX_SECRETS = 200                # cap secrets in JSON
MAX_HIGH_ENTROPY = 200           # cap high-entropy strings
MAX_URLS = 100
MAX_IPS = 100
MIN_STRING_LEN = 6               # printable ASCII run threshold
ENTROPY_THRESHOLD = 4.0          # bits/char; >4.0 → potential encoded secret
MIN_LEN_FOR_ENTROPY = 16         # don't entropy-flag short strings

# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))


def _seeded_take(items: list, n: int) -> list:
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
                "Defensive secrets extraction from LOCAL binaries (operator "
                "systems). No network egress. Lab isolation required."
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


# ─── Strings extraction ──────────────────────────────────────────────────────
def extract_strings(path: Path, min_len: int = MIN_STRING_LEN) -> list:
    """Use strings(1) if available, else raw-bytes regex."""
    strings_bin = _which("strings")
    if strings_bin:
        try:
            proc = subprocess.run(
                [strings_bin, "-n", str(min_len), str(path)],
                capture_output=True, text=True, timeout=TIMEOUT_S)
            lines = proc.stdout.splitlines()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            lines = _raw_extract(path, min_len)
    else:
        lines = _raw_extract(path, min_len)
    # Cap
    if len(lines) > MAX_STRINGS:
        lines = _seeded_take(lines, MAX_STRINGS)
    return lines


def _raw_extract(path: Path, min_len: int) -> list:
    """Fallback : read bytes and regex for printable ASCII runs."""
    try:
        data = path.read_bytes()
    except OSError:
        return []
    runs = re.findall(
        rb"[\x20-\x7e]{%d,}" % min_len, data)
    return [r.decode("ascii", errors="ignore") for r in runs][:MAX_STRINGS]


# ─── Shannon entropy ─────────────────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits/char for a string.
    Range: 0 (constant) to log2(alphabet_size) ~ 4.7 for ASCII printable
    subset, ~ 6.0 for base64 alphabet, ~ 4.0 for hex alphabet."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    ent = 0.0
    for c, ct in counts.items():
        p = ct / n
        if p > 0:
            ent -= p * math.log2(p)
    return ent


# ─── Secret pattern matching ─────────────────────────────────────────────────
# Each pattern: (id, regex, severity, redact_strategy)
SECRET_PATTERNS = [
    ("aws_access_key_id",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "critical",
     "show_first_8"),
    ("aws_secret_access_key",
     re.compile(
         r"(?i)aws_secret(?:_access)?_key[\"'\s:=]+['\"]?([A-Za-z0-9/+]{40})"),
     "critical",
     "show_first_4"),
    ("google_api_key",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
     "high",
     "show_first_8"),
    ("github_pat",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
     "critical",
     "show_first_8"),
    ("github_oauth",
     re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
     "critical",
     "show_first_8"),
    ("slack_token",
     re.compile(r"\bxox[abp]-[A-Za-z0-9-]{10,48}\b"),
     "high",
     "show_first_8"),
    ("slack_webhook",
     re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9/]{10,80}"),
     "high",
     "show_first_30"),
    ("stripe_secret_key",
     re.compile(r"\bsk_live_[A-Za-z0-9]{24,99}\b"),
     "critical",
     "show_first_8"),
    ("stripe_publishable_key",
     re.compile(r"\bpk_live_[A-Za-z0-9]{24,99}\b"),
     "medium",
     "show_first_8"),
    ("twilio_api_key",
     re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
     "high",
     "show_first_4"),
    ("telegram_bot_token",
     re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"),
     "high",
     "show_first_8"),
    ("jwt_token",
     re.compile(
         r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     "high",
     "show_first_16"),
    ("private_key_pem",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
     "critical",
     "show_marker_only"),
    ("public_key_pem",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PUBLIC KEY-----"),
     "low",
     "show_marker_only"),
    ("ssh_authorized_key",
     re.compile(
         r"\b(?:ssh-(?:rsa|ed25519|dss|ecdsa)|ecdsa-sha2-nistp\d+) "
         r"AAAA[A-Za-z0-9+/]{40,}=?=?"),
     "high",
     "show_first_16"),
    ("pgp_signature",
     re.compile(r"-----BEGIN PGP SIGNATURE-----"),
     "info",
     "show_marker_only"),
    ("azure_storage_key",
     re.compile(
         r"\bDefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}"),
     "critical",
     "show_first_16"),
    ("azure_connection_string",
     re.compile(r"\bEndpoint=sb://[^\s;]+;SharedAccessKey=[A-Za-z0-9+/=]{30,}"),
     "critical",
     "show_first_16"),
    ("azure_tenant_id",
     re.compile(r"(?i)tenant[_-]?id[\"'\s:=]+([0-9a-fA-F\-]{36})"),
     "medium",
     "show_first_8"),
    ("azure_client_secret",
     re.compile(
         r"(?i)client[_-]?secret[\"'\s:=]+['\"]?([A-Za-z0-9_\-\.]{16,})"),
     "high",
     "show_first_4"),
    ("generic_api_key",
     re.compile(
         r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|"
         r"auth[_-]?token|bearer)[\"'\s:=]+['\"]?([A-Za-z0-9_\-]{16,})"),
     "high",
     "show_first_4"),
    ("password_assignment",
     re.compile(
         r"(?i)(?:password|passwd|pwd|admin_pass|user_pass|root_pass|"
         r"db_pass|mysql_pass|postgres_pass|redis_pass|mongo_pass)"
         r"[\"'\s:=]+['\"]?([^\s'\"$\n]{6,})"),
     "high",
     "show_first_4"),
    ("wifi_psk",
     re.compile(
         r"(?i)(?:wpa[_-]?psk|wpa2[_-]?psk|wifi[_-]?password|wifi[_-]?psk"
         r"|wlan[_-]?psk|psk)[\"'\s:=]+['\"]?([^\s'\"]{8,})"),
     "high",
     "show_first_4"),
    ("database_url",
     re.compile(
         r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s]+:[^\s@]+@[^\s/]+"),
     "critical",
     "show_first_16"),
    ("cookie_session",
     re.compile(
         r"(?i)(?:session[_-]?id|session[_-]?token|cookie|csrf[_-]?token)"
         r"[\"'\s:=]+['\"]?([A-Za-z0-9_\-]{16,})"),
     "medium",
     "show_first_4"),
    ("generic_secret_env",
     re.compile(
         r"(?i)(?:SECRET|TOKEN|PASSWORD|API_KEY|PASS|PWD)_[A-Z_]+"
         r"[\"'\s:=]+['\"]?([A-Za-z0-9_\-\.]{8,})"),
     "high",
     "show_first_4"),
    ("bitcoin_wif_private_key",
     re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"),
     "critical",
     "show_first_4"),
    ("ethereum_private_key",
     re.compile(r"\b0x[0-9a-fA-F]{64}\b"),
     "critical",
     "show_first_8"),
    ("monero_private_key",
     re.compile(r"\b[0-9a-fA-F]{64}\b"),
     "medium",
     "show_first_4"),
]


URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\\]{6,256}", re.I)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,}\b")
BITCOIN_ADDR_RE = re.compile(
    r"\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{20,40})\b")
ETHEREUM_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")


# Crypto infrastructure indicators (not secrets per se, but indicate crypto use)
CRYPTO_INDICATORS = [
    ("pem_marker",
     re.compile(r"-----BEGIN [A-Z ]+-----")),
    ("pkcs7_padding",
     re.compile(r"(?i)\bPKCS7?[\s_]?PADDING\b")),
    ("aes_sbox_constant",
     re.compile(r"\b(?:0x)?637c777bf2[0-9a-fA-F]{6}\b")),
    ("rsa_oid",
     re.compile(r"\b1\.2\.840\.113549\.1\.1\.\d+\b")),
    ("ec_oid",
     re.compile(r"\b1\.2\.840\.10045\.\d+(\.\d+)?\b")),
    ("ed25519_oid",
     re.compile(r"\b1\.3\.101\.112\b")),
    ("x25519_oid",
     re.compile(r"\b1\.3\.101\.110\b")),
    ("chacha_constant",
     re.compile(r"expand 32-byte k")),
    ("bcrypt_marker",
     re.compile(r"\b\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{22}")),
    ("argon2_marker",
     re.compile(r"\b\$argon2[idy]?\$v=\d+\$m=\d+,t=\d+,p=\d+")),
]


def _redact(value: str, strategy: str) -> str:
    """Redact a secret value per the given strategy. NEVER returns full value."""
    if strategy == "show_marker_only":
        return value  # marker like -----BEGIN is not secret itself
    if strategy == "show_first_4":
        return value[:4] + "***REDACTED***"
    if strategy == "show_first_8":
        return value[:8] + "***REDACTED***"
    if strategy == "show_first_16":
        return value[:16] + "***REDACTED***"
    if strategy == "show_first_30":
        return value[:30] + "***REDACTED***"
    return "***REDACTED***"


def scan_for_secrets(strings_list: list) -> list:
    """Scan all strings for secret patterns. Returns list of redacted matches."""
    secrets: list = []
    # Build a single text blob for regex scanning
    text = "\n".join(strings_list)
    seen = set()
    for name, pat, severity, strategy in SECRET_PATTERNS:
        for m in pat.finditer(text):
            # If pattern has a group, use the group (the secret value)
            value = m.group(1) if m.groups() else m.group(0)
            value = value.strip()
            if not value:
                continue
            # Find which string line it came from (for context)
            string_index = text[:m.start()].count("\n")
            ctx_string = strings_list[string_index] if string_index < len(strings_list) else value
            # Dedup key : (pattern_name, redacted_value)
            redacted = _redact(value, strategy)
            key = (name, redacted)
            if key in seen:
                continue
            seen.add(key)
            secrets.append({
                "type": name,
                "severity": severity,
                "value_redacted": redacted,
                "value_length": len(value),
                "context_string_index": string_index,
                "context_string_excerpt": ctx_string[:60] + (
                    "..." if len(ctx_string) > 60 else ""),
            })
    return _seeded_take(secrets, MAX_SECRETS)


def scan_high_entropy(strings_list: list) -> list:
    """Flag strings with Shannon entropy > threshold (potential encoded secrets)."""
    high_ent: list = []
    seen = set()
    for idx, s in enumerate(strings_list):
        if len(s) < MIN_LEN_FOR_ENTROPY:
            continue
        # Skip if it's already detected as a known secret pattern (covered above)
        ent = shannon_entropy(s)
        if ent > ENTROPY_THRESHOLD:
            # Classify potential encoding
            if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) and len(s) % 4 == 0:
                encoding = "base64"
            elif re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
                encoding = "hex"
            elif re.fullmatch(r"[A-Za-z0-9_\-]+", s):
                encoding = "base64url_or_jwt"
            else:
                encoding = "unknown"
            # Skip pure-numeric or pure-alpha (low entropy despite passing threshold)
            if re.fullmatch(r"\d+", s) or re.fullmatch(r"[a-z]+", s, re.I):
                continue
            redacted = s[:8] + "***REDACTED***"
            key = redacted
            if key in seen:
                continue
            seen.add(key)
            high_ent.append({
                "entropy_bits_per_char": round(ent, 3),
                "string_length": len(s),
                "value_redacted": redacted,
                "suspected_encoding": encoding,
                "string_index": idx,
            })
    return _seeded_take(high_ent, MAX_HIGH_ENTROPY)


def scan_indicators(strings_list: list) -> dict:
    """Extract URLs, IPs, emails, crypto addresses, and crypto infra markers."""
    text = "\n".join(strings_list)
    urls = []
    seen = set()
    for m in URL_RE.finditer(text):
        v = m.group(0).strip().rstrip(".")
        if v not in seen:
            seen.add(v)
            urls.append(v)
    ips = []
    seen_ip = set()
    for m in IPV4_RE.finditer(text):
        v = m.group(0)
        # Skip common benign IPs
        if v in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
            continue
        if v not in seen_ip:
            seen_ip.add(v)
            ips.append({"addr": v, "family": "ipv4"})
    for m in IPV6_RE.finditer(text):
        v = m.group(0)
        if v in ("::", "::1"):
            continue
        if v not in seen_ip:
            seen_ip.add(v)
            ips.append({"addr": v, "family": "ipv6"})
    emails = []
    seen_email = set()
    for m in EMAIL_RE.finditer(text):
        v = m.group(0)
        if v not in seen_email:
            seen_email.add(v)
            emails.append(v)
    btc = []
    seen_btc = set()
    for m in BITCOIN_ADDR_RE.finditer(text):
        v = m.group(0)
        if v not in seen_btc:
            seen_btc.add(v)
            btc.append(v)
    eth = []
    seen_eth = set()
    for m in ETHEREUM_ADDR_RE.finditer(text):
        v = m.group(0)
        if v not in seen_eth:
            seen_eth.add(v)
            eth.append(v)
    crypto_indicators = []
    for name, pat in CRYPTO_INDICATORS:
        matches = pat.findall(text)
        if matches:
            crypto_indicators.append({
                "indicator": name,
                "count": len(matches),
                "sample_redacted": (matches[0][:16] + "***"
                                    if isinstance(matches[0], str) and
                                    len(matches[0]) > 16 else matches[0]),
            })
    return {
        "urls": _seeded_take(urls, MAX_URLS),
        "urls_count": len(urls),
        "ips": _seeded_take(ips, MAX_IPS),
        "ips_count": len(ips),
        "emails": _seeded_take(emails, 30),
        "emails_count": len(emails),
        "bitcoin_addresses": _seeded_take(btc, 20),
        "bitcoin_count": len(btc),
        "ethereum_addresses": _seeded_take(eth, 20),
        "ethereum_count": len(eth),
        "crypto_indicators": _seeded_take(crypto_indicators, 30),
        "crypto_indicators_count": len(crypto_indicators),
    }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    if len(sys.argv) < 2:
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "missing_binary_path",
            "usage": "strings_secrets.py <binary_or_firmware_path>",
        }))
        sys.exit(2)

    target_path = Path(sys.argv[1]).resolve()
    if not target_path.exists():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "file_not_found",
            "path": str(target_path),
        }))
        sys.exit(2)

    # Defensive invariant : LOCAL file only. No network operations.
    # SEED preserved for reproducible string sampling order.

    # Compute sha256 for traceability
    try:
        with open(target_path, "rb") as fh:
            target_sha256 = hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        target_sha256 = None

    # 1. Extract strings
    strings_list = extract_strings(target_path)

    # 2. Scan for known secret patterns
    secrets_found = scan_for_secrets(strings_list)

    # 3. Entropy analysis
    high_entropy_strings = scan_high_entropy(strings_list)

    # 4. URLs / IPs / emails / crypto addresses / crypto indicators
    indicators = scan_indicators(strings_list)

    # 5. JSON report
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "binary": str(target_path),
        "sha256": target_sha256,
        "total_strings": len(strings_list),
        "strings_sample": _seeded_take(strings_list, 30),
        "secrets_found": secrets_found,
        "secrets_count": len(secrets_found),
        "high_entropy_strings": high_entropy_strings,
        "high_entropy_count": len(high_entropy_strings),
        "entropy_threshold_bits": ENTROPY_THRESHOLD,
        "min_string_length": MIN_STRING_LEN,
        "urls_found": indicators["urls"],
        "urls_count": indicators["urls_count"],
        "ips_found": indicators["ips"],
        "ips_count": indicators["ips_count"],
        "emails_found": indicators["emails"],
        "emails_count": indicators["emails_count"],
        "bitcoin_addresses": indicators["bitcoin_addresses"],
        "bitcoin_count": indicators["bitcoin_count"],
        "ethereum_addresses": indicators["ethereum_addresses"],
        "ethereum_count": indicators["ethereum_count"],
        "crypto_indicators": indicators["crypto_indicators"],
        "crypto_indicators_count": indicators["crypto_indicators_count"],
        "redaction_note": (
            "All secret values are REDACTED (only previews shown). "
            "Full values must be retrieved manually from the original file."
        ),
        "seed": SEED,
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "read_only": True,    # no modifications to target
        "no_network_egress": True,
        "strings_tool_available": bool(_which("strings")),
        "legal_note": (
            "Defensive RE : extraction de secrets de binaires LOCAUX "
            "(systèmes opérateur). Aucune sortie réseau. "
            "Art. 323-1 Code pénal — usage lab isolé."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
