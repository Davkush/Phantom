#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — protocol probe : FTPS (FTP over SSL/TLS).
# Port 990 (implicit TLS) or 21 with AUTH TLS (explicit). Still used in
# banking for legacy batch file exchange (pain.001, CAMT, MT940 dropboxes).
# Secteur : banking — SAFE_MODE=read_only.
#
#   - v3.1 : FTP banner grab → identify FTP daemon + TLS support
#   - v3.1 : AUTH TLS negotiation (explicit FTPS on port 21)
#   - v3.1 : Implicit FTPS (port 990) — direct TLS handshake
#   - v3.1 : TLS cert inspection (CN, issuer, expiry)
#   - v3.1 : Data channel protection PROT P vs PROT C
#   - v3.1 : Anonymous login check (must be NO in banking)
#   - v3.1 : List directories after auth (READ_ONLY: NLST/LIST only)
#   - v3.1 : SEED reproducibility, LAB=1 guard, timeout 5s
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# FTPS = RFC 4217 (Securing FTP with TLS), RFC 959 (FTP), RFC 2228 (FTP Security).
# Banking usage: legacy partner file exchange, ISO 20022 batch dropboxes.
#
# Références :
#   - RFC 4217 §7 — Implicit vs Explicit FTPS
#   - RFC 959 §5.3.1 — PROT command (P = protected, C = clear)
#   - SWIFT CSP Control 2.x (segmentation) — legacy FTPS must be decommissioned
#     or wrapped in dedicated VLAN; DORA Art. 9 (third-party risk).
#   - PCI-DSS 4.0 §4.2 — FIPS-compliant TLS for FTPS in cardholder environments.
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from ftplib import FTP, FTP_TLS, error_perm, error_temp, all_errors
from typing import Optional

# Try to import requests/urllib3 for shared session headers — not strictly
# needed for FTPS but kept for parity with sibling probes. Fall back silently.
try:
    import requests  # noqa: F401
    import urllib3  # noqa: F401
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "ftps_probe"
DEFAULT_PORT = 990             # FTPS implicit TLS (banking default)
REQUEST_TIMEOUT = 5            # 5s strict (cf. spec harness)

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

# Deterministic, clearly-fake FTP credentials (lab-safe — never a real account)
PROBE_USER = f"hv_labprobe_{SEED}"
PROBE_PASS = f"invalid_lab_password_{SEED}"


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
# Usage: ftps_probe.py <host> [port]   (default port 990 = implicit FTPS)
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT


# ─── TLS context helper ──────────────────────────────────────────────────────
def _make_tls_context() -> ssl.SSLContext:
    """Build a TLS context that accepts self-signed / lab certs. We don't
    verify (lab-safe), but we still read the cert for reporting."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Allow legacy protocols just in case the FTPS server is older (lab reality)
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    return ctx


# ─── 1. Raw banner grab (FTP banner line, plain socket) ──────────────────────
def grab_banner_raw() -> dict:
    """Open a raw TCP socket and read the FTP banner (first 220- line).
    This works for both implicit (990, requires TLS) and explicit (21, plain)
    FTPS servers — but for implicit we just record the failure and use the
    TLS-wrapped path. So we only attempt plain-banner-grab on port != 990.
    """
    t0 = time.time()
    # If port is 990 (implicit TLS), the banner is encrypted — we won't see
    # it without a TLS handshake. Skip the plain banner grab and note it.
    if TARGET_PORT == 990:
        return {
            "banner": None,
            "raw": None,
            "ms": round((time.time() - t0) * 1000, 1),
            "error": None,
            "note": "implicit_ftps_port_990_banner_encrypted",
        }
    sock: Optional[socket.socket] = None
    try:
        sock = socket.create_connection((TARGET_HOST, TARGET_PORT),
                                        timeout=REQUEST_TIMEOUT)
        sock.settimeout(REQUEST_TIMEOUT)
        buf = b""
        # FTP banner ends with \r\n
        while b"\r\n" not in buf and len(buf) < 1024:
            chunk = sock.recv(256)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        return {"banner": None, "raw": None,
                "ms": round((time.time() - t0) * 1000, 1), "error": "Timeout"}
    except ConnectionRefusedError:
        return {"banner": None, "raw": None,
                "ms": round((time.time() - t0) * 1000, 1), "error": "ConnectionRefused"}
    except OSError as e:
        return {"banner": None, "raw": None,
                "ms": round((time.time() - t0) * 1000, 1),
                "error": type(e).__name__, "error_detail": str(e)[:200]}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    banner = buf.decode("utf-8", errors="ignore").strip()
    # Extract daemon hint (vsftpd, ProFTPD, FileZilla, Pure-FTPd, GlobalScape,
    # WS_FTP, IBM z/OS FTP, etc.)
    product = None
    m = re.search(r"\(([^)]+FTP[^)]*|vsftpd[^)]*|ProFTPD[^)]*|"
                  r"Pure-FTPd[^)]*|FileZilla[^)]*|GlobalScape[^)]*|"
                  r"WS_FTP[^)]*|IBM FTP[^)]*)\)", banner, re.I)
    if m:
        product = m.group(1)
    return {
        "banner": banner[:300],
        "raw": banner,
        "product": product,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": None,
    }


# ─── 2. Implicit FTPS (port 990) — TLS handshake + banner via ftplib ─────────
def probe_implicit_ftps() -> dict:
    """Connect to implicit FTPS (port 990). The entire control channel is
    TLS-wrapped from the start. Use FTP_TLS with an explicit context.
    ftplib.FTP_TLS does implicit FTPS if we pre-wrap the socket, but the
    cleanest approach is to subclass and wrap before sending USER.
    """
    t0 = time.time()
    cert_info: dict = {}
    banner: Optional[str] = None
    accessible = False
    err = None
    err_detail = None
    # We use a custom FTP_TLS subclass that wraps the socket immediately for
    # implicit FTPS. The trick: override `connect` to wrap the socket before
    # the initial banner exchange.
    class _ImplicitFTP(FTP_TLS):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._cert_info = {}

        def connect(self, host="", port=0, timeout=-999, source_address=None):
            """Connect and immediately wrap with TLS (implicit FTPS)."""
            if host != "":
                self.host = host
            if port > 0:
                self.port = port
            if timeout != -999:
                self.timeout = timeout
            if source_address is not None:
                self.source_address = source_address
            # Open raw socket
            self.sock = socket.create_connection((self.host, self.port),
                                                  self.timeout,
                                                  self.source_address)
            # Wrap with TLS immediately (implicit FTPS)
            ctx = _make_tls_context()
            self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)
            # Read the cert and stash it for reporting
            try:
                der = self.sock.getpeercert(binary_form=True)
                if der:
                    self._cert_info = _parse_der_cert(der)
            except Exception:  # noqa: BLE001
                pass
            file = self.sock.makefile("rb")
            self.file = file
            # Read banner
            self.welcome = self.getresp()
            return self.welcome

    try:
        ftp = _ImplicitFTP()
        ftp.connect(TARGET_HOST, TARGET_PORT, timeout=REQUEST_TIMEOUT)
        banner = str(ftp.welcome or "")
        cert_info = dict(ftp._cert_info)  # noqa: SLF001
        accessible = True
        # Don't login yet — the caller will do auth checks separately
        try:
            ftp.close()
        except Exception:  # noqa: BLE001
            pass
    except socket.timeout:
        err = "Timeout"
    except ssl.SSLError as e:
        err = "SSLError"
        err_detail = str(e)[:200]
    except ConnectionRefusedError:
        err = "ConnectionRefused"
    except error_perm as e:
        # 530 = not logged in (banner was received, then server kicked us)
        accessible = True
        err = "error_perm"
        err_detail = str(e)[:200]
    except error_temp as e:
        accessible = True
        err = "error_temp"
        err_detail = str(e)[:200]
    except all_errors as e:
        err = "ftplib_error"
        err_detail = str(e)[:200]
    except OSError as e:
        err = type(e).__name__
        err_detail = str(e)[:200]
    return {
        "mode": "implicit",
        "accessible": accessible,
        "banner": banner[:300] if banner else None,
        "ms": round((time.time() - t0) * 1000, 1),
        "cert": cert_info,
        "error": err,
        "error_detail": err_detail,
    }


# ─── 3. Explicit FTPS (port 21) — AUTH TLS upgrade ──────────────────────────
def probe_explicit_ftps() -> dict:
    """Connect to plain FTP on port 21, send AUTH TLS, upgrade the control
    channel. Use ftplib.FTP_TLS.protect_data() / prot_p() to upgrade data
    channel too. Returns accessible=True iff AUTH TLS succeeded.
    """
    t0 = time.time()
    cert_info: dict = {}
    banner: Optional[str] = None
    tls_negotiated = False
    accessible = False
    err = None
    err_detail = None
    try:
        ftp = FTP_TLS(context=_make_tls_context())
        ftp.connect(TARGET_HOST, TARGET_PORT, timeout=REQUEST_TIMEOUT)
        banner = str(ftp.welcome or "")
        accessible = True
        # AUTH TLS — explicit upgrade
        ftp.auth()
        tls_negotiated = True
        # Read cert from the existing socket
        try:
            der = ftp.sock.getpeercert(binary_form=True)
            if der:
                cert_info = _parse_der_cert(der)
        except Exception:  # noqa: BLE001
            pass
        try:
            ftp.close()
        except Exception:  # noqa: BLE001
            pass
    except socket.timeout:
        err = "Timeout"
    except ssl.SSLError as e:
        err = "SSLError"
        err_detail = str(e)[:200]
    except ConnectionRefusedError:
        err = "ConnectionRefused"
    except error_perm as e:
        # AUTH TLS not permitted = plain FTP, no TLS upgrade
        accessible = True
        err = "AUTH_TLS_not_permitted"
        err_detail = str(e)[:200]
    except error_temp as e:
        accessible = True
        err = "error_temp"
        err_detail = str(e)[:200]
    except all_errors as e:
        accessible = True
        err = "ftplib_error"
        err_detail = str(e)[:200]
    except OSError as e:
        err = type(e).__name__
        err_detail = str(e)[:200]
    return {
        "mode": "explicit",
        "accessible": accessible,
        "tls_negotiated": tls_negotiated,
        "banner": banner[:300] if banner else None,
        "ms": round((time.time() - t0) * 1000, 1),
        "cert": cert_info,
        "error": err,
        "error_detail": err_detail,
    }


# ─── 4. Data channel protection (PROT P vs PROT C) ───────────────────────────
def probe_data_protection() -> dict:
    """After AUTH TLS succeeds, PROT P protects the data channel (encrypted),
    PROT C leaves it clear (only the control channel is encrypted). Banking
    FTPS must use PROT P for any data transfer.

    Test: AUTH TLS → PBSZ 0 → PROT P → check if accepted. Then PROT C → check
    if accepted (it should be — but PROT C for data = weak hygiene).
    """
    t0 = time.time()
    prot_p_accepted = False
    prot_c_accepted = False
    err = None
    err_detail = None
    try:
        ftp = FTP_TLS(context=_make_tls_context())
        ftp.connect(TARGET_HOST, TARGET_PORT, timeout=REQUEST_TIMEOUT)
        ftp.login(user=PROBE_USER, passwd=PROBE_PASS)
        ftp.auth()
        # PBSZ 0 (RFC 4217 §3 — Protection Buffer Size)
        try:
            ftp.sendcmd("PBSZ 0")
        except all_errors:
            pass
        # PROT P (protected data)
        try:
            resp = ftp.sendcmd("PROT P")
            prot_p_accepted = "200" in (resp or "") or "PROT" in (resp or "").upper()
        except all_errors as e:
            err_detail = str(e)[:120]
        # PROT C (clear data — should be accepted but indicates weaker posture)
        try:
            resp_c = ftp.sendcmd("PROT C")
            prot_c_accepted = "200" in (resp_c or "") or "PROT" in (resp_c or "").upper()
        except all_errors:
            pass
        try:
            ftp.close()
        except Exception:  # noqa: BLE001
            pass
    except socket.timeout:
        err = "Timeout"
    except ssl.SSLError as e:
        err = "SSLError"
        err_detail = str(e)[:200]
    except error_perm as e:
        err = "error_perm"
        err_detail = str(e)[:200]
    except all_errors as e:
        err = "ftplib_error"
        err_detail = str(e)[:200]
    except OSError as e:
        err = type(e).__name__
        err_detail = str(e)[:200]
    data_protected = prot_p_accepted and not prot_c_accepted
    return {
        "prot_p_accepted": prot_p_accepted,
        "prot_c_accepted": prot_c_accepted,
        "data_protected": data_protected,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": err,
        "error_detail": err_detail,
        "note": (
            "Data channel uses PROT P (encrypted) — banking-grade hygiene."
            if data_protected
            else "PROT C accepted or PROT P rejected — data channel may go "
                 "in clear (PCI-DSS §4.2 violation)."
        ),
    }


# ─── 5. Anonymous login check ────────────────────────────────────────────────
def check_anonymous_login() -> dict:
    """Try USER=anonymous / PASS=harness@lab. In banking FTPS, anonymous
    access MUST be disabled. We only test the attempt — no data transfer.
    """
    t0 = time.time()
    anonymous_ok = False
    welcome: Optional[str] = None
    err = None
    err_detail = None
    try:
        # For implicit FTPS (990), use FTP_TLS without explicit AUTH
        if TARGET_PORT == 990:
            # We use the plain FTP_TLS class which still works for implicit
            # if we pre-wrap (we won't here — anonymous check on 990 is rare)
            ftp = FTP_TLS(context=_make_tls_context())
            try:
                ftp.connect(TARGET_HOST, TARGET_PORT, timeout=REQUEST_TIMEOUT)
                ftp.login(user="anonymous", passwd=f"harness@lab-{SEED}")
                anonymous_ok = True
                welcome = str(ftp.welcome or "")
            finally:
                try:
                    ftp.close()
                except Exception:  # noqa: BLE001
                    pass
        else:
            ftp = FTP_TLS(context=_make_tls_context())
            try:
                ftp.connect(TARGET_HOST, TARGET_PORT, timeout=REQUEST_TIMEOUT)
                ftp.login(user="anonymous", passwd=f"harness@lab-{SEED}")
                anonymous_ok = True
                welcome = str(ftp.welcome or "")
            finally:
                try:
                    ftp.close()
                except Exception:  # noqa: BLE001
                    pass
    except error_perm:
        err = "AuthenticationException"
    except socket.timeout:
        err = "Timeout"
    except ssl.SSLError as e:
        err = "SSLError"
        err_detail = str(e)[:200]
    except all_errors as e:
        err = "ftplib_error"
        err_detail = str(e)[:200]
    except OSError as e:
        err = type(e).__name__
        err_detail = str(e)[:200]
    return {
        "anonymous_login": anonymous_ok,
        "welcome": welcome[:200] if welcome else None,
        "ms": round((time.time() - t0) * 1000, 1),
        "error": err,
        "error_detail": err_detail,
        "severity": "critical" if anonymous_ok else "info",
        "note": (
            "Anonymous FTP login accepted — CRITICAL hygiene failure in "
            "banking (PCI-DSS §7, DORA Art. 9, SWIFT CSP Control 2.x)."
            if anonymous_ok
            else "Anonymous login rejected (good hygiene)."
        ),
    }


# ─── 6. List directories (READ_ONLY: NLST only, no download) ─────────────────
def list_directories() -> dict:
    """After AUTH TLS + PROT P, attempt NLST on '/' (root). Use the lab-probe
    credentials (which will fail on real servers). If anonymous login worked,
    we use that for listing. We do NOT call RETR (no download)."""
    t0 = time.time()
    entries: list = []
    err = None
    err_detail = None
    user_used = PROBE_USER
    # Prefer anonymous if it worked (separate step), else probe creds
    try:
        ftp = FTP_TLS(context=_make_tls_context())
        ftp.connect(TARGET_HOST, TARGET_PORT, timeout=REQUEST_TIMEOUT)
        try:
            ftp.login(user="anonymous", passwd=f"harness@lab-{SEED}")
            user_used = "anonymous"
        except error_perm:
            # Fall back to probe creds (expected to fail on real banking servers)
            try:
                ftp.login(user=PROBE_USER, passwd=PROBE_PASS)
                user_used = PROBE_USER
            except error_perm as e:
                raise
        # AUTH TLS upgrade for control channel
        try:
            ftp.auth()
        except all_errors:
            pass
        # PROT P for data channel
        try:
            ftp.prot_p()
        except all_errors:
            pass
        # NLST — name list only (no sizes, no contents)
        try:
            entries = ftp.nlst()
        except all_errors as e:
            err_detail = str(e)[:120]
    except error_perm as e:
        err = "AuthenticationException"
        err_detail = str(e)[:200]
    except socket.timeout:
        err = "Timeout"
    except ssl.SSLError as e:
        err = "SSLError"
        err_detail = str(e)[:200]
    except all_errors as e:
        err = "ftplib_error"
        err_detail = str(e)[:200]
    except OSError as e:
        err = type(e).__name__
        err_detail = str(e)[:200]
    return {
        "user_used": user_used,
        "directories": entries[:50],
        "ms": round((time.time() - t0) * 1000, 1),
        "error": err,
        "error_detail": err_detail,
    }


# ─── Cert parsing helper ─────────────────────────────────────────────────────
def _parse_der_cert(der: bytes) -> dict:
    """Parse a DER-encoded certificate using ssl stdlib."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        parsed = ssl._ssl._test_decode_cert(pem)  # type: ignore[attr-defined]
    except Exception as e:  # noqa: BLE001
        return {"error": f"CertParseError:{type(e).__name__}",
                "error_detail": str(e)[:200]}
    subject = parsed.get("subject", ())
    issuer = parsed.get("issuer", ())
    not_before = parsed.get("notBefore")
    not_after = parsed.get("notAfter")
    cn = _extract_cn(subject)
    issuer_cn = _extract_cn(issuer)
    now = datetime.now(timezone.utc)
    expiry_iso = _parse_asn1_time(not_after)
    valid_now = True
    expiring_within_30d = False
    if expiry_iso is not None:
        if now > expiry_iso:
            valid_now = False
        elif (expiry_iso - now).days <= 30:
            expiring_within_30d = True
    return {
        "cn": cn,
        "issuer_cn": issuer_cn,
        "not_before": not_before,
        "not_after": not_after,
        "valid_now": valid_now,
        "expiring_within_30d": expiring_within_30d,
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


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # SAFE_MODE read-only : banner grab + AUTH TLS + PROT P + anonymous check
    # + NLST (name list only — no RETR, no STOR, no DELE). No file download,
    # no file upload, no modification of the FTP filesystem.
    banner_check = grab_banner_raw()

    # Determine implicit (990) vs explicit (21) and probe accordingly
    if TARGET_PORT == 990:
        access_check = probe_implicit_ftps()
        explicit_check = {"mode": "explicit", "skipped": True,
                          "reason": "port_990_is_implicit_ftps"}
    else:
        access_check = probe_explicit_ftps()
        explicit_check = access_check

    # Cert from whichever access check gathered it
    cert = access_check.get("cert") or {}

    # Data protection + anonymous + listing only if accessible
    if access_check.get("accessible"):
        prot_check = probe_data_protection()
        anon_check = check_anonymous_login()
        listing_check = list_directories()
    else:
        prot_check = {"skipped": True, "reason": "ftps_not_accessible"}
        anon_check = {"skipped": True, "reason": "ftps_not_accessible"}
        listing_check = {"skipped": True, "reason": "ftps_not_accessible"}

    # ─── Summary flags per spec ────────────────────────────────────────────
    ftps_accessible = bool(access_check.get("accessible"))
    tls_negotiated = bool(
        access_check.get("tls_negotiated")
        or (TARGET_PORT == 990 and ftps_accessible)
    )
    data_protected = bool(prot_check.get("data_protected")) if not prot_check.get("skipped") else False
    anonymous_login = bool(anon_check.get("anonymous_login")) if not anon_check.get("skipped") else False
    directories = listing_check.get("directories") or []

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
            "mode": "implicit" if TARGET_PORT == 990 else "explicit",
        },
        # Spec output keys
        "ftps_accessible": ftps_accessible,
        "tls_negotiated": tls_negotiated,
        "cert": {
            "cn": cert.get("cn"),
            "issuer_cn": cert.get("issuer_cn"),
            "not_before": cert.get("not_before"),
            "not_after": cert.get("not_after"),
            "valid_now": cert.get("valid_now"),
            "expiring_within_30d": cert.get("expiring_within_30d"),
            "error": cert.get("error"),
        },
        "data_protected": data_protected,
        "anonymous_login": anonymous_login,
        "directories": directories,
        "results": {
            "banner": banner_check,
            "access": access_check,
            "explicit_mode": explicit_check,
            "data_protection": prot_check,
            "anonymous_login": anon_check,
            "listing": listing_check,
        },
        "summary": {
            "ftps_accessible": ftps_accessible,
            "tls_negotiated": tls_negotiated,
            "ftp_daemon": banner_check.get("product"),
            "cert_cn": cert.get("cn"),
            "cert_issuer": cert.get("issuer_cn"),
            "cert_valid": cert.get("valid_now"),
            "cert_expiry": cert.get("not_after"),
            "data_protected": data_protected,
            "anonymous_login": anonymous_login,
            "directories_count": len(directories),
        },
        "risk_note": (
            "FTPS legacy in banking should be decommissioned in favor of SFTP "
            "or AS2 (DORA Art. 9, SWIFT CSP Control 2.x). If retained: must "
            "enforce PROT P (encrypted data channel), no anonymous login, "
            "unique per-partner credentials, certificate-based auth preferred. "
            "Read-only: NLST only — no RETR / STOR / DELE."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
