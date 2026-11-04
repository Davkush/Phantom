#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — protocol probe : SFTP (SSH File Transfer Protocol).
# Port 22, batch file exchange between banks (pain.001, CAMT.053, MT940, SWIFT
# FileAct dropboxes). Secteur : banking — SAFE_MODE=read_only.
#
#   - v3.1 : SSH banner grab → SSH version + product
#   - v3.1 : Auth methods probe (password, publickey, keyboard-interactive)
#   - v3.1 : Default credentials check (banking/banking, sftp/sftp, ftp/ftp)
#   - v3.1 : Key-based auth enforcement detection
#   - v3.1 : List accessible directories after auth (READ_ONLY: list, no get)
#   - v3.1 : Banking file pattern scan (pain.001, CAMT.053, MT940, pacs.008)
#   - v3.1 : SEED reproducibility, LAB=1 guard, timeout 5s
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# SFTP = SSH File Transfer Protocol (IETF secshfilexfer, RFC 4251-4254 family).
# Paramiko est utilisé si disponible (pip install paramiko) ; sinon fallback
# raw SSH banner + kex via socket (banner + SSH_MSG_KEXINIT parsing).
#
# Références :
#   - RFC 4252 (SSH authentication) — SSH_MSG_USERAUTH_REQUEST / FAILURE / SUCCESS
#   - RFC 4253 (SSH transport) — banner + SSH_MSG_KEXINIT
#   - RFC 4251 (SSH architecture) — name-list auth methods
#   - SWIFT FileAct / InterAct — often delivered via SFTP gateways
#   - DORA Art. 9 (ICT third-party risk) — bank SFTP partners must be on
#     dedicated VLAN + key-based auth + IP allow-list (SWIFT CSP Control 2.x).
import json
import os
import re
import socket
import struct
import sys
import time
from typing import Optional

# Paramiko is preferred for full SFTP semantics (auth methods, ls) but we fall
# back to a raw socket SSH handshake if it is not installed.
try:
    import paramiko  # type: ignore
    _HAS_PARAMIKO = True
    # Suppress paramiko logging noise (otherwise dumps banners to stderr)
    import logging as _logging
    _logging.getLogger("paramiko").setLevel(_logging.CRITICAL)
except ImportError:
    _HAS_PARAMIKO = False

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "sftp_probe"
DEFAULT_PORT = 22               # SSH / SFTP
REQUEST_TIMEOUT = 5             # 5s strict (cf. spec harness)

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
# Usage: sftp_probe.py <host> [port]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT


# ─── Banking file patterns (read-only scan, never download) ───────────────────
BANKING_FILE_PATTERNS = [
    re.compile(r"pain\.001", re.I),                # ISO 20022 customer payment
    re.compile(r"pain\.002", re.I),                # ISO 20022 status report
    re.compile(r"pain\.008", re.I),                # ISO 20022 direct debit
    re.compile(r"camt\.053", re.I),                # Bank-to-customer statement
    re.compile(r"camt\.054", re.I),                # Bank-to-customer debit
    re.compile(r"camt\.052", re.I),                # Intra-day statement
    re.compile(r"pacs\.008", re.I),                # FI-to-FI customer credit
    re.compile(r"pacs\.002", re.I),                # FI-to-FI payment status
    re.compile(r"\bMT940\b"),                      # SWIFT MT940 (customer stmt)
    re.compile(r"\bMT942\b"),                      # SWIFT MT942 (intra-day)
    re.compile(r"\bMT103\b"),                      # SWIFT MT103 (customer pay)
    re.compile(r"\bMT202\b"),                      # SWIFT MT202 (cover / bank)
    re.compile(r"fileact", re.I),                  # SWIFT FileAct
    re.compile(r"interact", re.I),                 # SWIFT InterAct
    re.compile(r"\.edi\b", re.I),                  # EDI files
    re.compile(r"\.pgp\b", re.I),                  # PGP-encrypted batch
    re.compile(r"\.gpg\b", re.I),                  # GPG-encrypted batch
]


def scan_banking_patterns(filenames: list) -> list:
    """Scan a list of filenames for known banking patterns (read-only)."""
    found = []
    seen = set()
    for fn in filenames:
        for pat in BANKING_FILE_PATTERNS:
            if pat.search(fn):
                label = pat.pattern
                if label not in seen:
                    seen.add(label)
                    found.append({"pattern": label, "sample": fn[:120]})
                break
    return found


# ─── 1. SSH banner grab (raw socket) ─────────────────────────────────────────
def grab_banner() -> dict:
    """Open a raw TCP socket, read the SSH banner (first line, 'SSH-2.0-...'),
    parse SSH version + product + OS. This works WITHOUT paramiko and is the
    minimal-disruption way to fingerprint an SSH/SFTP server.

    The SSH protocol sends the banner as a UTF-8 line terminated by \\r\\n
    before any binary packet (RFC 4253 §4.2). It is <= 253 chars.
    """
    t0 = time.time()
    sock: Optional[socket.socket] = None
    try:
        sock = socket.create_connection((TARGET_HOST, TARGET_PORT),
                                        timeout=REQUEST_TIMEOUT)
        sock.settimeout(REQUEST_TIMEOUT)
        # SSH banner = first line ending in \r\n
        buf = b""
        while b"\n" not in buf and len(buf) < 256:
            chunk = sock.recv(64)
            if not chunk:
                break
            buf += chunk
        banner_raw = buf.split(b"\n", 1)[0].decode("utf-8", errors="ignore").strip()
    except socket.timeout:
        return {"banner": None, "raw": None, "ms": round((time.time() - t0) * 1000, 1),
                "error": "Timeout"}
    except ConnectionRefusedError:
        return {"banner": None, "raw": None, "ms": round((time.time() - t0) * 1000, 1),
                "error": "ConnectionRefused"}
    except OSError as e:
        return {"banner": None, "raw": None, "ms": round((time.time() - t0) * 1000, 1),
                "error": type(e).__name__, "error_detail": str(e)[:200]}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if not banner_raw:
        return {"banner": None, "raw": None, "ms": round((time.time() - t0) * 1000, 1),
                "error": "NoBanner"}
    # Parse: SSH-protoversion-softwareversion [comments]
    m = re.match(r"^SSH-(\d\.\d)-([^ \t\r\n]+)(?:[ \t]+(.*))?$", banner_raw)
    if m:
        proto_version = m.group(1)
        software_version = m.group(2)
        comments = (m.group(3) or "").strip()
    else:
        proto_version = None
        software_version = None
        comments = None
    # Extract product (OpenSSH, Bitvise, GlobalScape, WS_FTP, ...)
    product = None
    if software_version:
        mp = re.match(r"^([A-Za-z0-9_\-]+)", software_version)
        if mp:
            product = mp.group(1)
    return {
        "banner": banner_raw,
        "raw": banner_raw,
        "proto_version": proto_version,
        "software_version": software_version,
        "product": product,
        "comments": comments,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": None,
    }


# ─── 2. Auth methods probe (paramiko preferred, raw fallback) ─────────────────
def probe_auth_methods() -> dict:
    """Query the SSH server for the list of acceptable authentication methods
    for a (deterministic, fake) username.

    Method 1 (preferred): paramiko Transport + auth_none (SSH_MSG_USERAUTH_REQUEST
    with method "none") → server replies SSH_MSG_USERAUTH_FAILURE with a
    name-list of methods that can proceed.

    Method 2 (fallback, no paramiko): raw socket handshake. Send banner,
    SSH_MSG_KEXINIT, then SSH_MSG_USERAUTH_REQUEST(method=none). Parse the
    SSH_MSG_USERAUTH_FAILURE name-list. This requires a minimal SSH packet
    implementation — included here.
    """
    t0 = time.time()
    username = f"hv_labprobe_{SEED}"   # Deterministic, clearly-fake username
    if _HAS_PARAMIKO:
        return _probe_auth_methods_paramiko(username, t0)
    return _probe_auth_methods_raw(username, t0)


def _probe_auth_methods_paramiko(username: str, t0: float) -> dict:
    """Use paramiko Transport.connect with auth_none trick. We don't pass any
    real credential; the 'none' auth method returns the methods list in
    BadAuthenticationType."""
    methods: list = []
    err = None
    err_detail = None
    try:
        t = paramiko.Transport((TARGET_HOST, TARGET_PORT))
        t.set_log_channel("paramiko")
        t.use_compression(False)
        t.connect(username=username, password=None)  # type: ignore[arg-type]
        # If connect() succeeded with 'none' auth (very rare in banking) — close
        methods = ["none"]
        try:
            t.close()
        except Exception:  # noqa: BLE001
            pass
    except paramiko.BadAuthenticationType as e:
        # e.methods is the name-list of methods that can proceed
        m_list = getattr(e, "methods", None)
        if isinstance(m_list, (list, tuple)):
            methods = list(m_list)
        else:
            # Fallback: parse string repr
            methods = [m.strip() for m in str(m_list).split(",") if m.strip()] if m_list else []
    except paramiko.SSHException as e:
        err = "SSHException"
        err_detail = str(e)[:200]
    except socket.timeout:
        err = "Timeout"
    except OSError as e:
        err = type(e).__name__
        err_detail = str(e)[:200]
    return {
        "username_used": username,
        "auth_methods": methods,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": err,
        "error_detail": err_detail,
        "via": "paramiko",
    }


def _probe_auth_methods_raw(username: str, t0: float) -> dict:
    """Raw socket SSH handshake to extract auth methods. This is a minimal
    implementation: send banner, KEXINIT (with our minimal KEX algorithms),
    then a USERAUTH_REQUEST with method='none' and parse the USERAUTH_FAILURE
    name-list.

    NOTE: this is best-effort. If the server doesn't accept our minimal KEX
    algorithms, it will disconnect and we won't get auth methods. In that
    case, return empty methods list with error.
    """
    sock: Optional[socket.socket] = None
    methods: list = []
    err = None
    err_detail = None
    try:
        sock = socket.create_connection((TARGET_HOST, TARGET_PORT),
                                        timeout=REQUEST_TIMEOUT)
        sock.settimeout(REQUEST_TIMEOUT)
        # Send our banner
        sock.sendall(b"SSH-2.0-harness_sftp_probe\r\n")
        # Read server banner
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(64)
            if not chunk:
                break
            buf += chunk
        # Send a minimal SSH_MSG_KEXINIT (msg code 20)
        cookie = b"\x00" * 16
        # 10 name-lists (kex_algorithms, server_host_key_algorithms,
        # encryption_algorithms_c2s, encryption_algorithms_s2c,
        # mac_algorithms_c2s, mac_algorithms_s2c,
        # compression_algorithms_c2s, compression_algorithms_s2c,
        # languages_c2s, languages_s2c)
        # Use a single widely-supported algorithm per slot
        algos = (
            b"diffie-hellman-group14-sha256",                # kex
            b"ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256",      # hostkey
            b"aes128-ctr", b"aes128-ctr",                    # enc c2s, s2c
            b"hmac-sha2-256", b"hmac-sha2-256",              # mac c2s, s2c
            b"none", b"none",                                # comp c2s, s2c
            b"", b"",                                        # lang c2s, s2c
        )
        payload = struct.pack(">B", 20) + cookie
        for a in algos:
            payload += struct.pack(">I", len(a)) + a
        payload += struct.pack(">B", 0)  # first_kex_packet_follows = false
        payload += struct.pack(">I", 0)  # reserved
        # Send as SSH packet: [packet_len(4)][padding_len(1)][payload][padding]
        block_size = 8
        padding_len = block_size - ((5 + len(payload)) % block_size)
        if padding_len < 4:
            padding_len += block_size
        packet_len = 1 + len(payload) + padding_len
        packet = struct.pack(">IB", packet_len, padding_len) + payload + b"\x00" * padding_len
        sock.sendall(packet)
        # Read server response (KEXINIT + maybe more). We don't actually need
        # to perform DH; we just send USERAUTH_REQUEST 'none' and the server
        # will reject with USERAUTH_FAILURE listing methods (some servers
        # require service request first).
        # SSH_MSG_SERVICE_REQUEST (code 5) for ssh-userauth
        svc = b"ssh-userauth"
        svc_payload = struct.pack(">B", 5) + struct.pack(">I", len(svc)) + svc
        svc_pad = block_size - ((5 + len(svc_payload)) % block_size)
        if svc_pad < 4:
            svc_pad += block_size
        svc_pkt_len = 1 + len(svc_payload) + svc_pad
        svc_pkt = struct.pack(">IB", svc_pkt_len, svc_pad) + svc_payload + b"\x00" * svc_pad
        try:
            sock.sendall(svc_pkt)
        except OSError:
            pass
        # Now send USERAUTH_REQUEST 'none'
        u = username.encode("utf-8")
        svc2 = b"ssh-userauth"
        method = b"none"
        uauth_payload = (
            struct.pack(">B", 50)             # SSH_MSG_USERAUTH_REQUEST
            + struct.pack(">I", len(u)) + u
            + struct.pack(">I", len(svc2)) + svc2
            + struct.pack(">I", len(method)) + method
        )
        upad = block_size - ((5 + len(uauth_payload)) % block_size)
        if upad < 4:
            upad += block_size
        upkt_len = 1 + len(uauth_payload) + upad
        upkt = struct.pack(">IB", upkt_len, upad) + uauth_payload + b"\x00" * upad
        sock.sendall(upkt)
        # Read responses
        resp_buf = b""
        try:
            while len(resp_buf) < 1024:
                chunk = sock.recv(512)
                if not chunk:
                    break
                resp_buf += chunk
                # Look for USERAUTH_FAILURE (code 51) or USERAUTH_SUCCESS (52)
                # Skip 4-byte length + 1-byte padding before payload byte
                if len(resp_buf) >= 6:
                    payload_offset = 5
                    msg_code = resp_buf[payload_offset]
                    if msg_code in (51, 52):
                        break
        except socket.timeout:
            pass
        # Parse USERAUTH_FAILURE
        if len(resp_buf) >= 6 and resp_buf[5] == 51:
            # payload layout after msg code: uint32 len, name-list, bool partial_success
            pos = 6
            if pos + 4 <= len(resp_buf):
                names_len = struct.unpack(">I", resp_buf[pos:pos + 4])[0]
                pos += 4
                names_bytes = resp_buf[pos:pos + names_len]
                names_str = names_bytes.decode("utf-8", errors="ignore")
                methods = [m.strip() for m in names_str.split(",") if m.strip()]
    except socket.timeout:
        err = "Timeout"
    except ConnectionRefusedError:
        err = "ConnectionRefused"
    except OSError as e:
        err = type(e).__name__
        err_detail = str(e)[:200]
    except struct.error as e:
        err = "ProtocolParseError"
        err_detail = str(e)[:200]
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return {
        "username_used": username,
        "auth_methods": methods,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": err,
        "error_detail": err_detail if err else None,
        "via": "raw_socket",
    }


# ─── 3. Default credentials check (read-only: just attempt auth) ─────────────
DEFAULT_CREDS = [
    ("banking", "banking"),
    ("sftp", "sftp"),
    ("ftp", "ftp"),
    ("user", "password"),
    ("admin", "admin"),
    ("swift", "swift"),
]


def check_default_creds(auth_methods: list) -> dict:
    """Attempt password authentication with common default credential pairs.

    READ-ONLY : we only attempt login; we do NOT navigate the filesystem
    (that is done in a separate, controlled step). Each attempt is followed
    by an immediate disconnect. We do at most len(DEFAULT_CREDS) attempts.

    Lab-safe heuristic: in a real bank, even a single successful password
    auth via SFTP would be a critical hygiene failure (DORA Art. 9,
    SWIFT CSP Control 7.3 — unique credentials, key-based auth preferred).
    """
    if not _HAS_PARAMIKO:
        return {
            "tested": False,
            "reason": "paramiko_required_for_credential_probe",
            "hint": "pip install paramiko",
            "successful_credentials": [],
            "default_creds_detected": False,
        }
    if "password" not in auth_methods:
        return {
            "tested": True,
            "reason": "password_auth_not_advertised",
            "successful_credentials": [],
            "default_creds_detected": False,
            "note": "Server does not advertise 'password' in auth methods.",
        }
    results = []
    success = []
    for user, pw in DEFAULT_CREDS:
        t0 = time.time()
        ok = False
        err = None
        try:
            t = paramiko.Transport((TARGET_HOST, TARGET_PORT))
            t.connect(username=user, password=pw)
            ok = True
            success.append({"user": user, "password": pw})
            try:
                t.close()
            except Exception:  # noqa: BLE001
                pass
        except paramiko.AuthenticationException:
            err = "AuthenticationException"
        except paramiko.SSHException as e:
            err = "SSHException"
            err_detail = str(e)[:120]
        except socket.timeout:
            err = "Timeout"
        except OSError as e:
            err = type(e).__name__
            err_detail = str(e)[:120]
        results.append({
            "user": user,
            "ms": round((time.time() - t0) * 1000, 1),
            "authenticated": ok,
            "error": err,
        })
        if ok:
            # Don't keep trying after a success — one is enough to flag risk
            break
        time.sleep(0.1)  # inter-attempt delay (be polite, stay read-only)
    return {
        "tested": True,
        "attempts": len(results),
        "results": results,
        "successful_credentials": success,
        "default_creds_detected": bool(success),
        "severity": "critical" if success else "info",
        "note": (
            "Default credentials accepted via SFTP — critical hygiene failure "
            "(DORA Art. 9, SWIFT CSP Control 7.3)." if success
            else "No default credentials accepted."
        ),
    }


# ─── 4. List directories + scan for banking files (read-only) ────────────────
def list_and_scan(auth_methods: list, creds_check: dict) -> dict:
    """Connect (with whatever auth works — key-only servers cannot be probed
    here without a private key, which we don't have) and:
      - List top-level directories (READ_ONLY: listdir, no get/put)
      - Recurse one level deep into known banking dirs (inbox, outbox,
        archive, sent, received, statements, payments)
      - Scan filenames for known banking patterns (pain.001, CAMT.053, MT940)
    """
    if not _HAS_PARAMIKO:
        return {
            "listed": False,
            "reason": "paramiko_required_for_listing",
            "hint": "pip install paramiko",
            "directories": [],
            "banking_files_found": [],
        }
    # If only key-based auth is advertised, we cannot list without a key.
    if auth_methods and "password" not in auth_methods and "keyboard-interactive" not in auth_methods:
        return {
            "listed": False,
            "reason": "key_auth_only_no_credential_available",
            "directories": [],
            "banking_files_found": [],
            "note": "Server enforces key-based authentication only — good "
                    "hygiene. Cannot list without a private key (expected "
                    "for SWIFT CSP-compliant SFTP gateways).",
        }
    # Use a successful credential from the default-creds check if any
    creds = None
    if creds_check.get("successful_credentials"):
        c = creds_check["successful_credentials"][0]
        creds = (c["user"], c["password"])
    if creds is None:
        # Fall back to the deterministic probe username + a fake password
        creds = (f"hv_labprobe_{SEED}", "invalid_lab_password")
    user, pw = creds
    directories: list = []
    banking_files: list = []
    try:
        t = paramiko.Transport((TARGET_HOST, TARGET_PORT))
        t.connect(username=user, password=pw)
        sftp = paramiko.SFTPClient.from_transport(t)
        if sftp is None:
            return {
                "listed": False,
                "reason": "sftp_subsystem_not_available",
                "directories": [],
                "banking_files_found": [],
            }
        try:
            entries = sftp.listdir(".")
            directories = ["/" + e for e in entries]
            # Scan top-level for banking patterns
            banking_files.extend(scan_banking_patterns(entries))
            # Recurse one level into known banking dirs
            known_banking_dirs = ("inbox", "outbox", "archive", "sent",
                                  "received", "statements", "payments",
                                  "inbound", "outbound", "swift", "fileact")
            for d in entries:
                if d.lower() not in known_banking_dirs:
                    continue
                try:
                    sub = sftp.listdir(d)
                    for f in sub:
                        banking_files.extend(scan_banking_patterns([f]))
                except OSError:
                    continue
        finally:
            try:
                sftp.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                t.close()
            except Exception:  # noqa: BLE001
                pass
        return {
            "listed": True,
            "directories": directories[:50],
            "banking_files_found": banking_files[:30],
            "auth_user": user,
        }
    except paramiko.AuthenticationException:
        return {
            "listed": False,
            "reason": "auth_failed",
            "directories": [],
            "banking_files_found": [],
            "auth_user": user,
        }
    except paramiko.SSHException as e:
        return {
            "listed": False,
            "reason": "ssh_exception",
            "error_detail": str(e)[:200],
            "directories": [],
            "banking_files_found": [],
            "auth_user": user,
        }
    except socket.timeout:
        return {
            "listed": False,
            "reason": "timeout",
            "directories": [],
            "banking_files_found": [],
            "auth_user": user,
        }
    except OSError as e:
        return {
            "listed": False,
            "reason": type(e).__name__,
            "error_detail": str(e)[:200],
            "directories": [],
            "banking_files_found": [],
            "auth_user": user,
        }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # SAFE_MODE read-only : banner grab + auth-method probe + (read-only)
    # listing. No file upload/download/delete. Default creds check only
    # attempts authentication, then disconnects — no data is read or written.
    banner = grab_banner()
    auth_check = probe_auth_methods()
    auth_methods = auth_check.get("auth_methods", []) or []
    creds_check = check_default_creds(auth_methods)
    listing_check = list_and_scan(auth_methods, creds_check)

    # key_auth_required = server advertises 'publickey' AND does NOT advertise
    # 'password' (a key-only policy = SWIFT CSP-grade hygiene).
    key_auth_required = (
        "publickey" in auth_methods
        and "password" not in auth_methods
        and "keyboard-interactive" not in auth_methods
    )

    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "banking",
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "seed": SEED,
        "read_only": True,
        "regulations": list(get_sector_config().get("regulations", [])),
        "paramiko_available": _HAS_PARAMIKO,
        "target": {
            "host": TARGET_HOST,
            "port": TARGET_PORT,
        },
        # Spec output keys
        "ssh_banner": banner.get("banner"),
        "auth_methods": auth_methods,
        "default_creds": bool(creds_check.get("default_creds_detected")),
        "key_auth_required": key_auth_required,
        "directories": listing_check.get("directories", []),
        "banking_files_found": listing_check.get("banking_files_found", []),
        "results": {
            "banner": banner,
            "auth_methods": auth_check,
            "default_creds": creds_check,
            "listing": listing_check,
        },
        "summary": {
            "ssh_banner": banner.get("banner"),
            "product": banner.get("product"),
            "auth_methods": auth_methods,
            "key_auth_required": key_auth_required,
            "default_creds_detected": bool(creds_check.get("default_creds_detected")),
            "directories_count": len(listing_check.get("directories", [])),
            "banking_files_count": len(listing_check.get("banking_files_found", [])),
        },
        "risk_note": (
            "SFTP gateways in banking must enforce key-based authentication "
            "(no password), unique per-partner credentials, IP allow-listing "
            "and dedicated VLAN segmentation (DORA Art. 9, SWIFT CSP Control "
            "2.x/7.3). Default credentials = critical. Listing banking files "
            "(pain.001, CAMT.053, MT940) confirms this is an active banking "
            "channel — read-only: no download/upload performed."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
