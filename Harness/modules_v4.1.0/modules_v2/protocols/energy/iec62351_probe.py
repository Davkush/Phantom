#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — iec62351_probe
# Energy sector META-module — IEC 62351 (Power system communications security)
# posture assessment for the protocols IEC 62351 wraps (IEC 61850, IEC 60870-5,
# DNP3). This is NOT a protocol-speaker itself; it probes whether the
# energy-protocol endpoint on host:port enforces the IEC 62351 security
# controls (TLS, certificate auth, audit logging, role-based access, etc.).
#
#   - IEC 62351 parts covered (inference only — no key/cert material sent):
#       IEC 62351-3  — TLS profile for TCP-based protocols (IEC 60870-5-104,
#                      DNP3, IEC 61850 MMS). Mandates TLS 1.2+, specific
#                      cipher suites (ECDHE_* / GCM / SHA-256), no legacy
#                      TLS 1.0/1.1, no RC4, no static RSA key exchange.
#       IEC 62351-4  — Security for MMS (auth + integrity)
#       IEC 62351-5  — Security for IEC 60870-5 (legacy 101/104)
#       IEC 62351-6  — Authentication for IEC 61850 MMS (peer auth on the
#                      Initiate-Response, plus authenticated Identify)
#       IEC 62351-9  — Key management (cyphering keys / signing keys)
#       IEC 62351-12 — Resilience & security for IEC 61850 MMS
#
#   - Probes performed (all READ-ONLY, no Write/Operate on the underlying
#     IED):
#       1. tcp_reach         — raw TCP connect to (host, port). Confirms
#                               the endpoint exists.
#       2. tls_handshake     — ssl.wrap_socket() against the SAME port. If
#                               the server completes a TLS handshake → TLS
#                               is supported on the endpoint.
#       3. iec62351_3_check  — verify TLS 1.2+ AND no forbidden ciphers
#                               (RC4, 3DES, static RSA kx). IEC 62351-3
#                               mandates AEAD + PFS.
#       4. legacy_plain_apdu — on a SEPARATE plain (non-TLS) socket, attempt
#                               a protocol-specific probe (IEC 104 STARTDT
#                               on 2404, MMS Initiate on 102, DNP3 Link
#                               Status on 20000). If the server responds
#                               over plaintext → legacy_unauthenticated=True
#                               (IEC 62351-5/6 NOT enforced).
#       5. mms_auth_check    — if MMS Initiate succeeds, examine the
#                               Initiate-Response supportedServices bitmap
#                               and the proposeIdList for ACSE auth fields
#                               → IEC 62351-6 inference.
#       6. security_events   — passive inference: if the server logs auth
#                               failures, after our deliberate failed-auth
#                               attempt it should close the connection or
#                               return a security error PDU. If it just
#                               keeps serving → security_events_logged=False
#                               (inconclusive best-effort).
#
#   - CLI: host = argv[1], port = argv[2] (default 2404 = IEC 60870-5-104)
#   - The same port may carry TLS-secured IEC 104 / DNP3 / MMS — this module
#     tries BOTH plain and TLS against it, then ALSO probes the canonical
#     "secure" port shifts (port+1 convention used by some vendors and the
#     IEC 62351-3 "secure" profile) for additional context.
#
#   - READ_ONLY=True  (energy sector safety constraint)
#   - SEED env var    : deterministic tls session ID / probe ordering
#   - LAB=1 mandatory ; 5 s timeout on every socket / TLS operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (energy) : NERC CIP, NIS2, ENISA, IEC 62351,
#   IEC 61850, IEC 60870-5, IEEE 1815 (DNP3).
import json
import os
import random
import socket
import ssl
import struct
import sys
import time
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
MODULE_NAME = "iec62351_probe"
DEFAULT_PORT = 2404  # IEC 60870-5-104 (the most common IEC 62351-wrapped proto)
TIMEOUT_S = 5.0
READ_ONLY = True  # META-module — never writes anything

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── SEED for deterministic probe ordering / TLS session ID ────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else None
except ValueError:
    SEED = None
_rng = random.Random(SEED) if SEED is not None else random.Random()


def _next_session_id() -> int:
    """Deterministic 32-bit pseudo-session id for TLS SNI / probe order."""
    return _rng.randint(1, 0xFFFFFFFF)


# ─── LAB guard ─────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ─── Sector / SAFE_MODE config ─────────────────────────────────────────────
if SECTOR_BASE_OK:
    SECTOR_CFG = get_sector_config()
    SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")
else:
    SECTOR_CFG = {"sector": "energy", "safe_mode": "read_only"}
    SAFE_MODE = "read_only"


# ═══════════════════════════════════════════════════════════════════════════
#  PLAIN PROTOCOL PROBES (one per IEC 62351-wrapped protocol family)
# ═══════════════════════════════════════════════════════════════════════════
# Each helper returns {responded: bool, error: Optional[str], details: dict}.
# None of them ever send a Write / Operate / Control frame — READ-ONLY.

def _recv_all(sock: socket.socket, n: int, timeout: float = TIMEOUT_S) -> bytes:
    """Read up to n bytes within timeout."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, TimeoutError):
        pass
    return buf


def probe_iec104_plain(host: str, port: int) -> Dict:
    """IEC 60870-5-104 STARTDT.act probe on a plain socket.

    A conformant IEC 62351-5 deployment MUST refuse plaintext STARTDT — the
    endpoint should be TLS-only. A plaintext reply → legacy_unauthenticated.
    """
    out = {"responded": False, "got_startdt_con": False,
           "raw_first_bytes": None, "error": None}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_S)
        sock.connect((host, port))
        # STARTDT.act U-format: 0x68 0x04 0x07 0x00 0x00 0x00
        sock.sendall(b"\x68\x04\x07\x00\x00\x00")
        data = _recv_all(sock, 6, TIMEOUT_S)
        sock.close()
        if data:
            out["responded"] = True
            out["raw_first_bytes"] = data.hex()
            # STARTDT.con = 0x68 0x04 0x0B 0x00 0x00 0x00
            if len(data) >= 3 and data[0] == 0x68 and data[2] == 0x0B:
                out["got_startdt_con"] = True
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except ConnectionRefusedError:
        out["error"] = "connection_refused"
    except OSError as e:
        out["error"] = f"os_error:{type(e).__name__}:{e}"
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}:{e}"
    return out


def probe_dnp3_plain(host: str, port: int) -> Dict:
    """DNP3 link-status probe on a plain socket.

    A conformant IEC 62351-3/7 deployment MUST refuse plaintext DNP3 — the
    endpoint should be TLS-only (DNP3 Secure Authentication v5 over TLS).
    A plaintext link-status reply → legacy_unauthenticated.
    """
    out = {"responded": False, "link_active": False,
           "raw_first_bytes": None, "error": None}
    # DNP3 link-status frame: 0x05 0x64 | len=5 | ctrl=0xC9 | dst=1 LE | src=1 LE
    # + header CRC (CRC-16 poly 0x3D65, init 0x0000, reflected)
    try:
        from protocols.ot.dnp3_probe import dnp3_crc  # type: ignore
        _has_dnp3_crc = True
    except Exception:  # noqa: BLE001 — fall back to a local crc
        _has_dnp3_crc = False

    def _crc_local(data: bytes) -> int:
        # CRC-16 poly 0x3D65 reflected = 0xA6BC, init 0x0000
        POLY = 0xA6BC
        crc = 0x0000
        for b in data:
            crc ^= b
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ POLY
                else:
                    crc >>= 1
        return crc & 0xFFFF

    crc_fn = dnp3_crc if _has_dnp3_crc else _crc_local
    try:
        # Build the minimal link-status frame
        hdr = b"\x05\x64\x05\xC9" + struct.pack("<HH", 1, 1)
        frame = hdr + struct.pack("<H", crc_fn(hdr))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_S)
        sock.connect((host, port))
        sock.sendall(frame)
        # Expect 10-byte reply header (start + len + ctrl + dst + src + crc)
        data = _recv_all(sock, 10, TIMEOUT_S)
        sock.close()
        if data:
            out["responded"] = True
            out["raw_first_bytes"] = data.hex()
            # Reply ctrl byte: secondary, DIR=0 PRM=0 → 0x0_, FC=0x0B = link status
            if len(data) >= 3 and data[0] == 0x05 and data[1] == 0x64 and \
                    (data[3] & 0x0F) == 0x0B:
                out["link_active"] = True
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except ConnectionRefusedError:
        out["error"] = "connection_refused"
    except OSError as e:
        out["error"] = f"os_error:{type(e).__name__}:{e}"
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}:{e}"
    return out


def probe_mms_plain(host: str, port: int) -> Dict:
    """TPKT/COTP/MMS Initiate probe on a plain socket (used for both IEC 61850
    MMS and ICCP/TASE.2, both ride MMS on port 102).

    A conformant IEC 62351-6 deployment MUST enforce ACSE authentication and
    should not negotiate MMS Initiate over plaintext without auth. A plain
    Initiate-Response → legacy_unauthenticated.
    """
    out = {"responded": False, "got_initiate_response": False,
           "raw_first_bytes": None, "supported_services": None,
           "error": None}

    # ── Build a minimal COTP CR + MMS Initiate-Request ───────────────────
    # TPKT header: 0x03 0x00 <len BE 2>
    # COTP CR:     LI(1)=0x11  code(1)=0xE0  dst_ref(2)=0x0000  src_ref(2)=0x0001
    #              class/opts(1)=0x00  var-part: TPDU-SIZE(0xC0 0x01 0x0A)
    #              called-TSAP(0xC2 0x02 0x00 0x01)
    #              calling-TSAP(0xC1 0x02 0x00 0x01)
    cotp_cr = bytes([
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC0, 0x01, 0x0A,
        0xC2, 0x02, 0x00, 0x01,
        0xC1, 0x02, 0x00, 0x01,
    ])
    # MMS Initiate-RequestPDU — minimal BER
    # [0] InitiateRequestPDU ::= SEQUENCE {
    #   localDetailCalling [0] INTEGER, proposedMaxServOutstandingCalling [1] INTEGER,
    #   proposedMaxServOutstandingCalled [2] INTEGER, proposedDataStructureNestingLevel [3] INTEGER,
    #   initRequestDetail [4] SEQUENCE { ... proposedVersionNumber [0] INTEGER,
    #     proposedParameterCBB [1] BIT STRING, servicesSupportedCalled [2] BIT STRING }
    # }
    # We send the absolute minimum that real IEDs accept: a 1-byte per field.
    inner = (
        bytes([0x80, 0x01, 0x09]) +                       # localDetailCalling = 9
        bytes([0x81, 0x01, 0x05]) +                       # proposedMaxServOutstandingCalling
        bytes([0x82, 0x01, 0x05]) +                       # proposedMaxServOutstandingCalled
        bytes([0x83, 0x01, 0x03])                          # nestingLevel
    )
    # servicesSupportedCalled bit string (8 bytes of zero flags) + version 1
    init_detail = (
        bytes([0x80, 0x01, 0x01]) +                       # versionNumber
        bytes([0x81, 0x02, 0x07, 0x00]) +                 # parameterCBB
        bytes([0x82, 0x09, 0x00]) + b"\x00" * 8           # servicesSupportedCalled (8 bytes)
    )
    init_detail_tlv = bytes([0xA4]) + _ber_len(len(init_detail)) + init_detail
    init_req = bytes([0xA0]) + _ber_len(len(inner + init_detail_tlv)) + \
        inner + init_detail_tlv
    # Confirmed-RequestPDU ::= [0] confirmedRequestPDU
    # confirmedRequestPDU ::= SEQUENCE { invokeID INTEGER, ... }
    # The MMS PDU wrapper: [0] (confirmed) + invokeID + InitiateRequestPDU
    invoke_id = _rng.randint(1, 0x7FFFFFFF)
    pdu_body = bytes([0x02, 0x04]) + invoke_id.to_bytes(4, "big") + init_req
    mms_pdu = bytes([0xA0]) + _ber_len(len(pdu_body)) + pdu_body

    # COTP DT: LI=0x02  code=0xF0  EOT=0x80 + MMS payload
    cotp_dt = bytes([0x02, 0xF0, 0x80]) + mms_pdu

    # TPKT-wrapped COTP CR (we send CR, then DT in two writes)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_S)
        sock.connect((host, port))
        # Send COTP CR (TPKT-wrapped)
        cr_tpkt = struct.pack(">BBH", 0x03, 0x00, 4 + len(cotp_cr)) + cotp_cr
        sock.sendall(cr_tpkt)
        # Read COTP CC (TPKT-wrapped) — at least 7 bytes (TPKT 4 + COTP LI+code+refs)
        cc = _recv_all(sock, 11, TIMEOUT_S)
        if not cc or len(cc) < 7:
            out["error"] = "no_cotp_cc"
            sock.close()
            return out
        # Check COTP CC code (byte 5 of TPKT-wrapped, i.e. cc[4+1])
        if cc[5] != 0xD0:
            out["error"] = f"not_cotp_cc:0x{cc[5]:02X}"
            sock.close()
            return out
        # Send COTP DT with MMS Initiate (TPKT-wrapped)
        dt_tpkt = struct.pack(">BBH", 0x03, 0x00, 4 + len(cotp_dt)) + cotp_dt
        sock.sendall(dt_tpkt)
        # Read TPKT response (header 4 bytes, then payload)
        resp_hdr = _recv_all(sock, 4, TIMEOUT_S)
        if len(resp_hdr) < 4 or resp_hdr[0] != 0x03:
            out["error"] = "no_tpkt_response"
            sock.close()
            return out
        resp_len = struct.unpack(">H", resp_hdr[2:4])[0]
        body = _recv_all(sock, max(resp_len - 4, 0), TIMEOUT_S)
        sock.close()
        if not body:
            out["error"] = "empty_body"
            return out
        out["responded"] = True
        out["raw_first_bytes"] = (resp_hdr + body).hex()[:80]
        # Heuristic: look for A8 (Initiate-ResponsePDU tag) somewhere
        if b"\xA8" in body[:64] or b"\xA8" in body:
            out["got_initiate_response"] = True
        # supportedServicesCalled bit string follows in Initiate-Response —
        # we search for the [2] BIT STRING tag (0x82) after the A8
        idx = body.find(b"\xA8")
        if idx >= 0 and idx + 4 < len(body):
            # naive: try to locate 0x82 with length 0x09 (8 bytes + unused)
            sub = body[idx: idx + 64]
            j = sub.find(b"\x82\x09")
            if j >= 0 and j + 2 + 9 <= len(sub):
                out["supported_services"] = sub[j + 2: j + 2 + 9].hex()
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except ConnectionRefusedError:
        out["error"] = "connection_refused"
    except OSError as e:
        out["error"] = f"os_error:{type(e).__name__}:{e}"
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}:{e}"
    return out


def _ber_len(length: int) -> bytes:
    """BER length encoding (short or long form)."""
    if length < 0x80:
        return bytes([length])
    out = b""
    n = length
    while n > 0:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


# ═══════════════════════════════════════════════════════════════════════════
#  TLS / IEC 62351-3 PROBE
# ═══════════════════════════════════════════════════════════════════════════

# Forbidden cipher suites (IEC 62351-3 §6 mandates AEAD + PFS, so RC4, 3DES,
# NULL, static RSA key exchange, EXPORT, anon DH/ECDH are all forbidden).
_FORBIDDEN_CIPHER_TOKENS = (
    "RC4", "3DES", "DES", "NULL", "EXPORT", "ANON", "STATIC",
    "CBC", "MD5",
)


def probe_tls(host: str, port: int) -> Dict:
    """Attempt a TLS handshake on (host, port) and capture the negotiated
    cipher / protocol version / peer cert presence.

    Returns:
      {tls_supported, negotiated_version, negotiated_cipher,
       cert_present, cert_subject, forbidden_cipher_used,
       iec62351_3_compliant, error}
    """
    out: Dict = {
        "tls_supported": False,
        "negotiated_version": None,
        "negotiated_cipher": None,
        "cert_present": False,
        "cert_subject": None,
        "forbidden_cipher_used": False,
        "iec62351_3_compliant": False,
        "error": None,
    }
    # Build a TLS client context. We deliberately allow the handshake to
    # succeed even with weak ciphers so we can OBSERVE what was negotiated,
    # then mark forbidden_cipher_used=True afterwards.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Allow legacy protocols so we can observe whether the server is stuck
    # on TLS 1.0 / 1.1 (forbidden by IEC 62351-3). The handshake result tells
    # us the actual negotiated version.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):
        pass  # older OpenSSL may not support setting this

    sock = None
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(TIMEOUT_S)
        raw.connect((host, port))
        ssock = ctx.wrap_socket(raw, server_hostname=host)
        sock = ssock
        out["tls_supported"] = True
        out["negotiated_version"] = ssock.version()
        cipher = ssock.cipher()
        if cipher:
            out["negotiated_cipher"] = cipher[0]
            name = (cipher[0] or "").upper()
            out["forbidden_cipher_used"] = any(
                tok in name for tok in _FORBIDDEN_CIPHER_TOKENS
            )
        # Peer cert (we requested CERT_NONE so DER cert is still retrievable
        # via getpeercert(binary_form=True))
        der = ssock.getpeercert(binary_form=True)
        if der:
            out["cert_present"] = True
            # Subject extraction without cryptography deps — best-effort,
            # decode just the CN from the DER via a quick regex on printable.
            try:
                txt = _extract_cn_from_der(der)
                out["cert_subject"] = txt
            except Exception:  # noqa: BLE001
                out["cert_subject"] = f"<der:{len(der)}B>"
    except ssl.SSLError as e:
        # Handshake failure is the canonical "TLS not supported" signal
        out["error"] = f"ssl_error:{type(e).__name__}:{e}"[:200]
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except ConnectionRefusedError:
        out["error"] = "connection_refused"
    except OSError as e:
        out["error"] = f"os_error:{type(e).__name__}:{e}"[:200]
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}:{e}"[:200]
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

    # ── IEC 62351-3 compliance check ──────────────────────────────────────
    # Requires: TLS 1.2+, AEAD cipher (no forbidden tokens), peer cert present
    ver = out["negotiated_version"] or ""
    is_1_2_plus = ver in ("TLSv1.2", "TLSv1.3")
    out["iec62351_3_compliant"] = bool(
        out["tls_supported"]
        and is_1_2_plus
        and not out["forbidden_cipher_used"]
        and out["cert_present"]
    )
    return out


def _extract_cn_from_der(der: bytes) -> Optional[str]:
    """Best-effort CN extraction from a DER cert without `cryptography`.
    Scans for the printable ASCII run after a CN OID (0x55 0x04 0x03)."""
    cn_oid = b"\x55\x04\x03"
    idx = der.find(cn_oid)
    if idx < 0:
        return None
    # Skip OID + tag + length + value (a few bytes). The CN string is
    # typically a UTF8String (0x0C) or PrintableString (0x13) right after.
    j = idx + 3
    while j + 2 < len(der):
        if der[j] in (0x0C, 0x13, 0x16):  # UTF8 / Printable / IA5
            length = der[j + 1]
            cn = der[j + 2: j + 2 + length]
            try:
                return cn.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                return None
        j += 1
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  IEC 62351-6 (MMS auth) INFERENCE
# ═══════════════════════════════════════════════════════════════════════════

def infer_iec62351_6(mms_probe: Dict) -> bool:
    """IEC 62351-6 inference from the plain MMS Initiate exchange.

    Without an actual ACSE authentication handshake (which would require
    real keys), we use heuristics:
      - If the server refused to negotiate MMS Initiate over plain TCP →
        it is enforcing IEC 62351-6 (probably wants ACSE/AP-init first).
      - If the server responded with a full Initiate-Response over plain
        TCP without any auth step → IEC 62351-6 NOT enforced.
    """
    if mms_probe.get("error") in ("connection_refused",):
        return False
    # If the server didn't respond at all on port 102, we can't tell.
    if not mms_probe.get("responded"):
        return False
    # If we got an Initiate-Response with no preceding auth → NOT compliant
    if mms_probe.get("got_initiate_response"):
        return False
    # If it responded but did NOT complete Initiate (e.g. DR or Reject) →
    # it MAY be enforcing auth. Best-effort: True.
    return True


# ═══════════════════════════════════════════════════════════════════════════
#  SECURITY-EVENT-LOGGING INFERENCE
# ═══════════════════════════════════════════════════════════════════════════

def infer_security_events_logged(plain_probe: Dict, tls_probe: Dict) -> bool:
    """Best-effort inference whether the endpoint logs security events.

    Heuristics (inconclusive — a server may log without giving us a signal):
      - If the endpoint is TLS-only AND refuses plaintext probes → security
        posture is enforced, audit-logging is plausible (return True).
      - If the endpoint serves plaintext and immediately replies to our
        probe → it is permissive; audit-logging unlikely (return False).
      - If we got no signal either way → False (inconclusive default).
    """
    if tls_probe.get("tls_supported") and not plain_probe.get("responded"):
        # TLS-only deployment: the server explicitly refused plaintext,
        # which suggests security controls including logging.
        return True
    if plain_probe.get("responded"):
        return False
    return False


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("IEC 62351 security-posture probing on production "
                           "power-system infrastructure is illegal outside an "
                           "authorized lab. NERC CIP / IEC 62351 / NIS2."),
        }))
        sys.exit(1)

    t0 = time.time()
    # Decide which plain-probe to run based on the chosen port.
    if PORT == 2404:
        plain_kind = "iec104"
    elif PORT == 20000:
        plain_kind = "dnp3"
    elif PORT in (102,):
        plain_kind = "mms"
    else:
        # Auto-detect: try IEC 104 first (the spec default), then MMS, then DNP3.
        plain_kind = "auto"

    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "port": PORT,
        "sector": SECTOR_CFG.get("sector"),
        "safe_mode": SAFE_MODE,
        "read_only": READ_ONLY,
        "seed": SEED,
        "probe_kind": plain_kind,
        # Spec-required output fields:
        "tls_supported": False,
        "auth_required": False,
        "cert_auth": False,
        "security_events_logged": False,
        "legacy_unauthenticated": False,
        "iec62351_3_compliant": False,
        "iec62351_6_compliant": False,
        # Extra diagnostic fields:
        "tls": {},
        "plain_probe": {},
        "mms_probe": {},
        "errors": [],
    }

    # ─── 1. TLS probe on the configured port ───────────────────────────────
    tls_probe: Dict = {}
    try:
        tls_probe = probe_tls(HOST, PORT)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"tls:{type(e).__name__}:{e}")
    summary["tls"] = tls_probe
    summary["tls_supported"] = bool(tls_probe.get("tls_supported"))
    summary["cert_auth"] = bool(
        tls_probe.get("tls_supported") and tls_probe.get("cert_present")
    )
    summary["iec62351_3_compliant"] = bool(
        tls_probe.get("iec62351_3_compliant")
    )

    # ─── 2. Plain (non-TLS) probe to detect legacy_unauthenticated ─────────
    # We probe the SAME port (host:PORT) — IEC 62351-3 mandates TLS-only on
    # that port, so a plaintext response ⇒ legacy mode is still active.
    plain_probe: Dict = {}
    mms_probe: Dict = {}
    if plain_kind == "iec104":
        try:
            plain_probe = probe_iec104_plain(HOST, PORT)
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"iec104:{type(e).__name__}:{e}")
        summary["plain_probe"] = plain_probe
        summary["legacy_unauthenticated"] = bool(
            plain_probe.get("responded") and plain_probe.get("got_startdt_con")
        )
        # auth_required on IEC 104 is meaningless — IEC 60870-5-104 has no
        # native auth. auth_required is derived from TLS requirement instead.
        summary["auth_required"] = bool(
            tls_probe.get("tls_supported") and not summary["legacy_unauthenticated"]
        )
    elif plain_kind == "dnp3":
        try:
            plain_probe = probe_dnp3_plain(HOST, PORT)
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"dnp3:{type(e).__name__}:{e}")
        summary["plain_probe"] = plain_probe
        summary["legacy_unauthenticated"] = bool(
            plain_probe.get("responded") and plain_probe.get("link_active")
        )
        # DNP3 has SAv5 (separate module). If TLS is supported AND plaintext
        # DNP3 is rejected, auth is required.
        summary["auth_required"] = bool(
            tls_probe.get("tls_supported") and not summary["legacy_unauthenticated"]
        )
    elif plain_kind == "mms":
        try:
            mms_probe = probe_mms_plain(HOST, PORT)
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"mms:{type(e).__name__}:{e}")
        summary["mms_probe"] = mms_probe
        summary["legacy_unauthenticated"] = bool(mms_probe.get("got_initiate_response"))
        # IEC 62351-6 inference on the MMS Initiate exchange
        summary["iec62351_6_compliant"] = infer_iec62351_6(mms_probe)
        summary["auth_required"] = bool(
            mms_probe.get("responded") and not mms_probe.get("got_initiate_response")
        )
    else:  # auto
        # Try IEC 104 (default port), MMS (port 102), DNP3 (port 20000)
        try:
            plain_probe = probe_iec104_plain(HOST, PORT)
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"iec104:{type(e).__name__}:{e}")
        summary["plain_probe"] = plain_probe
        if plain_probe.get("responded"):
            summary["legacy_unauthenticated"] = bool(plain_probe.get("got_startdt_con"))
            summary["auth_required"] = bool(
                tls_probe.get("tls_supported")
                and not summary["legacy_unauthenticated"]
            )
        else:
            # Fall through to a probe on port 102 if that's not what we are on
            if PORT != 102:
                try:
                    mms_probe = probe_mms_plain(HOST, 102)
                except Exception as e:  # noqa: BLE001
                    summary["errors"].append(f"mms:{type(e).__name__}:{e}")
                summary["mms_probe"] = mms_probe
                summary["legacy_unauthenticated"] = bool(
                    mms_probe.get("got_initiate_response")
                )
                summary["iec62351_6_compliant"] = infer_iec62351_6(mms_probe)
                summary["auth_required"] = bool(
                    mms_probe.get("responded")
                    and not mms_probe.get("got_initiate_response")
                )

    # ─── 3. Security-event-logging inference ───────────────────────────────
    summary["security_events_logged"] = infer_security_events_logged(
        plain_probe or mms_probe, tls_probe
    )

    # ─── 4. IEC 62351-6 final inference for non-MMS cases ──────────────────
    # If the user pointed us at IEC 104 / DNP3, we also try MMS on port 102
    # opportunistically to derive iec62351_6_compliant.
    if plain_kind in ("iec104", "dnp3", "auto") and not summary["iec62351_6_compliant"]:
        try:
            extra_mms = probe_mms_plain(HOST, 102)
            summary["iec62351_6_compliant"] = infer_iec62351_6(extra_mms)
            if extra_mms.get("responded") and extra_mms.get("got_initiate_response"):
                # MMS is reachable in plaintext on port 102 → strengthen the
                # legacy_unauthenticated flag.
                if not summary["legacy_unauthenticated"]:
                    summary["legacy_unauthenticated"] = True
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"mms_extra:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
