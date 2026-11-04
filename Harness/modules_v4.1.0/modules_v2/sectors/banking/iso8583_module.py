#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — module bancaire : ISO 8583 card switch probe.
# Secteur: banking (SAFE_MODE=read_only — seul MTI 0800 est envoyé, 0200 skipped).
#
#   - v3.0 : socket TCP brute vers host d'autorisation (port 5000 default)
#   - v3.0 : encodage ISO 8583 simplifié : MTI(4) + bitmap(8B) + champs
#   - v3.0 : send_network_management (0800) → echo test
#   - v3.0 : send_signon (0800 + field 70=001)
#   - v3.0 : try_unauthorized_transaction (0200) — SKIP si SAFE_MODE != full
#   - v3.0 : detect_switch_vendor via patterns réponse (ACI/TSYS/First Data/...)
#   - v3.0 : guard LAB=1 + SAFE_MODE=read_only + timeout 5s
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# PCI-DSS / PSD2 — aucun 0200 envoyé en SAFE_MODE=read_only (write forbidden).
import json
import os
import re
import socket
import struct
import sys
import time
from typing import Optional

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "iso8583_probe"
DEFAULT_PORT = 5000              # ISO 8583 authorization host (lab default)
SOCKET_TIMEOUT = 5              # 5s strict (cf. spec harness)
RECV_BUFFER = 4096

# ─── Import sector_base (best-effort) ─────────────────────────────────────────
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from sector_base import (  # type: ignore
        get_sector_config,
        get_safe_mode as _sector_safe_mode,
        is_write_allowed,
        check_write_allowed,
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

    def is_write_allowed() -> bool:  # type: ignore[no-redef]
        return get_safe_mode() == "full"

    def check_write_allowed(module_name: str) -> None:  # type: ignore[no-redef]
        if not is_write_allowed():
            print(json.dumps({
                "module": module_name,
                "error": "write_not_allowed",
                "sector": "banking",
                "safe_mode": get_safe_mode(),
            }))
            sys.exit(3)


def get_safe_mode() -> str:
    """Effective SAFE_MODE: respect explicit env override (lab admin opt-in),
    otherwise fall back to sector_base default (read_only for banking).
    Banking default is read_only per SWIFT CSP / DORA — explicit SAFE_MODE=full
    is required to enable write tests (e.g., 0200 unauthorized transaction)
    AND only in LAB=1."""
    env_sm = os.environ.get("SAFE_MODE", "").lower().strip()
    if env_sm in ("read_only", "full"):
        return env_sm
    return _sector_safe_mode()


# ─── Guards ───────────────────────────────────────────────────────────────────
def _check_lab_guard() -> None:
    """Exit si LAB != 1."""
    if os.environ.get("LAB") != "1":
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_failed",
            "reason": "LAB env var must be set to 1 (isolated lab only)",
            "harness_version": HARNESS_VERSION,
        }))
        sys.exit(2)


def _check_safe_mode() -> str:
    """Retourne le SAFE_MODE courant ; valide sa valeur."""
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
# Usage: iso8583_module.py <host> [port]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT


# ─── Encodage ISO 8583 simplifié ──────────────────────────────────────────────
# Format message :
#   [2 bytes length (big-endian)] [MTI 4 ASCII] [primary bitmap 8 bytes binary]
#   [secondary bitmap 8 bytes (si F1 set)] [fields...]
# Champs supportés (subset lab) :
#   F2  (LLVAR)   — Primary Account Number (PAN)
#   F4  (fixed 12)— Transaction amount (digits)
#   F7  (fixed 10)— Transmission date & time MMDDhhmmss
#   F11 (fixed 6) — System trace audit number (STAN)
#   F14 (fixed 4) — Expiration date YYMM
#   F22 (fixed 3) — POS entry mode
#   F24 (fixed 3) — Network international identifier (NII)
#   F25 (fixed 2) — POS condition code
#   F35 (LLVAR)   — Track 2 data
#   F39 (fixed 2) — Response code (réponse uniquement)
#   F41 (fixed 8) — Card acceptor terminal identification
#   F42 (fixed 15)— Card acceptor id code
#   F62 (LLVAR)   — Private reserved
#   F70 (fixed 3) — Network management information code (001=signon, 002=signoff,
#                   003=echo, 301=signon-reload-key, ...)  [REQUIRES secondary bitmap]
# Encodings : ASCII (lab), real switches may use EBCDIC/BCD.
#
# NOTE : Field 70 > 64 donc nécessite le secondary bitmap. F1 dans le primary
# bitmap signale sa présence (16 bytes total au lieu de 8).

FIELD_SPECS = {
    2:  ("llvar",   None),     # LLVAR
    4:  ("fixed",   12),
    7:  ("fixed",   10),
    11: ("fixed",   6),
    14: ("fixed",   4),
    22: ("fixed",   3),
    24: ("fixed",   3),
    25: ("fixed",   2),
    35: ("llvar",   None),
    39: ("fixed",   2),       # response code (parse only)
    41: ("fixed",   8),
    42: ("fixed",   15),
    62: ("llvar",   None),    # private reserved
    70: ("fixed",   3),       # network mgmt info code (secondary bitmap)
}


MAX_FIELD = 128               # primary (1-64) + secondary (65-128)
BITMAP_TOTAL_BYTES = 16       # 8 bytes primary + 8 bytes secondary


def _set_bit(bitmap: bytearray, field_no: int) -> None:
    """Set bit for field_no (1..128) in combined primary+secondary bitmap (16 bytes).
    Field 1 → MSB of byte 0 (primary). Field 65 → MSB of byte 8 (secondary).
    Field 1 is special : it indicates presence of secondary bitmap — but if
    the caller sets field_no=1 explicitly, that's exactly what we want."""
    if not (1 <= field_no <= MAX_FIELD):
        raise ValueError(f"field_no {field_no} out of range (1..{MAX_FIELD})")
    bit_pos = field_no - 1              # 0..127
    byte_idx = bit_pos // 8             # 0..15
    bit_in_byte = 7 - (bit_pos % 8)
    bitmap[byte_idx] |= (1 << bit_in_byte)


def encode_field(field_no: int, value: str) -> bytes:
    """Encode a single field value to bytes per FIELD_SPECS."""
    spec = FIELD_SPECS.get(field_no)
    if spec is None:
        raise ValueError(f"field {field_no} not in FIELD_SPECS")
    enc, length = spec
    if enc == "fixed":
        v = value.encode("ascii", "ignore")
        # Pad/truncate to fixed length (right-pad with '0' for numeric, space for alpha)
        if len(v) >= length:
            return v[:length]
        return v + b"0" * (length - len(v))
    elif enc == "llvar":
        data = value.encode("ascii", "ignore")
        if len(data) > 99:
            data = data[:99]
        return f"{len(data):02d}".encode("ascii") + data
    else:
        raise ValueError(f"unknown encoding {enc} for field {field_no}")


def build_iso8583(mti: str, fields: dict) -> bytes:
    """Build ISO 8583 message (no length prefix).
    mti: 4 ASCII digits (e.g., "0800", "0200")
    fields: dict {field_no: value}  (field_no must be 1..128)
    Returns: MTI(4B) + primary_bitmap(8B) [+ secondary_bitmap(8B) if needed]
             + fields (in numeric order).
    Field 1 (secondary bitmap indicator) is set automatically if any field >= 65
    is present in `fields`.
    """
    if not (len(mti) == 4 and mti.isdigit()):
        raise ValueError(f"MTI must be 4 digits, got {mti!r}")
    # Detect if secondary bitmap is required (any field >= 65)
    needs_secondary = any(fno > 64 for fno in fields)
    # Allocate full 16-byte combined bitmap (primary + secondary)
    bitmap = bytearray(BITMAP_TOTAL_BYTES)
    # If secondary needed, set field 1 (which is the secondary-bitmap indicator)
    if needs_secondary:
        _set_bit(bitmap, 1)
    # Set user-requested fields (excluding field 1 if user didn't ask for it)
    for fno in fields:
        if fno == 1 and needs_secondary:
            # Field 1 already set above as secondary bitmap indicator
            continue
        _set_bit(bitmap, fno)
    # Determine bitmap size in output: 8 bytes if no secondary, 16 if present
    bitmap_out = bytes(bitmap[:16]) if needs_secondary else bytes(bitmap[:8])
    msg = bytearray()
    msg += mti.encode("ascii")
    msg += bitmap_out
    for fno in sorted(fields):
        msg += encode_field(fno, fields[fno])
    return bytes(msg)


def frame_message(msg: bytes) -> bytes:
    """Prepend 2-byte big-endian length header (common TCP ISO 8583 framing)."""
    return struct.pack(">H", len(msg)) + msg


def parse_response(raw: bytes) -> dict:
    """Parse minimal ISO 8583 response: MTI + bitmap + check field 39 (response code).
    Field 39 = response code (2 ASCII chars: '00'=approved, '05'=do not honor,
    '12'=invalid transaction, '91'=issuer or switch inoperative, ...)."""
    if len(raw) < 12:
        return {"error": "too_short", "len": len(raw), "raw_hex": raw.hex()}
    # Strip 2-byte length header if present (heuristic: first 2 bytes are length)
    has_len_header = False
    if len(raw) >= 14:
        declared_len = struct.unpack(">H", raw[:2])[0]
        # If declared length matches remaining bytes, it's a length-prefixed frame
        if declared_len == len(raw) - 2:
            raw = raw[2:]
            has_len_header = True
        elif declared_len + 2 == len(raw):
            # Some servers include header in declared length
            raw = raw[2:]
            has_len_header = True
    try:
        mti = raw[:4].decode("ascii", "ignore")
    except Exception:  # noqa: BLE001
        mti = "????"
    primary_bitmap = raw[4:12]
    # Check if secondary bitmap is present (field 1 set in primary)
    has_secondary = bool(primary_bitmap[0] & 0x80)
    secondary_bitmap: bytes = b""
    if has_secondary and len(raw) >= 20:
        secondary_bitmap = raw[12:20]
        full_bitmap = primary_bitmap + secondary_bitmap
        bitmap_offset = 20   # after MTI(4) + primary(8) + secondary(8)
        max_field = 128
    else:
        # Either no secondary bit set, or message truncated before secondary bitmap
        has_secondary = False  # downgrade if truncated
        full_bitmap = primary_bitmap
        bitmap_offset = 12   # after MTI(4) + primary(8)
        max_field = 64
    # Parse present fields per combined bitmap (1..max_field)
    fields_present = []
    response_code = None
    for fno in range(1, max_field + 1):
        bit_pos = fno - 1
        byte_idx = bit_pos // 8
        bit_in_byte = 7 - (bit_pos % 8)
        if byte_idx < len(full_bitmap) and full_bitmap[byte_idx] & (1 << bit_in_byte):
            fields_present.append(fno)
    # Walk fields to locate field 39 (response code, 2 ASCII chars).
    # Field 39 is in the primary bitmap (1..64) so we can walk up to it.
    # Field 1 (if set as secondary bitmap indicator) is not encoded as data.
    offset = bitmap_offset
    for fno in fields_present:
        if fno == 1:
            # Field 1 is the secondary bitmap indicator itself — no data bytes.
            continue
        if fno == 39:
            if offset + 2 <= len(raw):
                response_code = raw[offset:offset + 2].decode("ascii", "ignore")
            break
        if fno > 64:
            # Past primary bitmap — response_code (F39) not found walking up
            break
        spec = FIELD_SPECS.get(fno)
        if spec is None:
            # Field not in our subset — can't walk further safely
            break
        enc, length = spec
        if enc == "fixed":
            offset += length
        elif enc == "llvar":
            if offset + 2 <= len(raw):
                ll_str = raw[offset:offset + 2].decode("ascii", "ignore")
                try:
                    ll = int(ll_str)
                except ValueError:
                    break
                offset += 2 + ll
            else:
                break
    return {
        "mti": mti,
        "bitmap_hex": primary_bitmap.hex(),
        "secondary_bitmap_hex": secondary_bitmap.hex() if has_secondary else None,
        "has_secondary_bitmap": has_secondary,
        "has_length_header": has_len_header,
        "fields_present": fields_present,
        "response_code": response_code,
        "raw_len": len(raw),
        "raw_hex_preview": raw[:64].hex(),
    }


# ─── Patterns de détection vendor ─────────────────────────────────────────────
# Switch vendors principaux : ACI (BASE24-eps), TSYS (PRIMA), First Data (Omaha),
# Equinox, BPC, S1, Euronet, HP-NonStop (Tandem), Concardis, CCAuthorize, etc.
VENDOR_PATTERNS = [
    (re.compile(rb"ACI\s*Worldwide|BASE24|base24eps|ON/2", re.I), "ACI Worldwide (BASE24)"),
    (re.compile(rb"TSYS|PRIMA|tsys_ accredia", re.I),             "TSYS / PRIMA"),
    (re.compile(rb"First\s*Data|FDR|FDMS|Omaha", re.I),           "First Data / Fiserv"),
    (re.compile(rb"BPC\s*Group|bpc_smart|smart vista", re.I),     "BPC SmartVista"),
    (re.compile(rb"Euronet|eanet", re.I),                         "Euronet Worldwide"),
    (re.compile(rb"S1\s*Corp|S1\b", re.I),                        "S1 Corporation"),
    (re.compile(rb"HP\s*NonStop|Tandem|GUARDIAN", re.I),          "HP NonStop (Tandem)"),
    (re.compile(rb"Open\s*Way|way4", re.I),                       "OpenWay WAY4"),
    (re.compile(rb"Concardis|payengine", re.I),                   "Concardis PayEngine"),
    (re.compile(rb"Corecard|CORE\s*CARD", re.I),                  "CoreCard"),
    (re.compile(rb"Marqeta|marqeta", re.I),                       "Marqeta"),
    (re.compile(rb"Thales|payShield|utimaco|safenet", re.I),     "HSM Vendor (Thales/Utimaco)"),
]


def detect_switch_vendor(raw: bytes) -> dict:
    """Detect switch vendor via patterns in raw response bytes.
    In real life, vendor is rarely leaked in clear — but some test/lab switches
    do echo vendor strings in error responses or vendor-private field 62."""
    detected = []
    for pat, label in VENDOR_PATTERNS:
        if pat.search(raw):
            detected.append(label)
    return {
        "vendor": detected[0] if detected else None,
        "all_matches": detected,
        "detected": bool(detected),
    }


# ─── Socket helper ────────────────────────────────────────────────────────────
def send_recv(payload: bytes) -> dict:
    """TCP connect → send payload → recv response → close.
    Timeout 5s strict. Captures errors sans lever."""
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKET_TIMEOUT)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        s.sendall(payload)
        # Pour les réponses longues, on boucle recv jusqu'à timeout ou EOF
        chunks: list[bytes] = []
        while True:
            try:
                chunk = s.recv(RECV_BUFFER)
                if not chunk:
                    break
                chunks.append(chunk)
                # Si on a assez de données (≥ header + MTI + bitmap), on peut sortir
                if sum(len(c) for c in chunks) >= 14:
                    break
            except socket.timeout:
                break
        raw = b"".join(chunks)
        return {
            "sent_bytes": len(payload),
            "recv_bytes": len(raw),
            "ms": round((time.time() - t0) * 1000, 1),
            "raw": raw,
            "error": None,
        }
    except socket.timeout:
        return _sock_err(t0, "Timeout", payload)
    except ConnectionRefusedError:
        return _sock_err(t0, "ConnectionRefused", payload)
    except OSError as e:
        return _sock_err(t0, type(e).__name__, payload, detail=str(e)[:200])
    finally:
        try:
            s.close()
        except OSError:
            pass


def _sock_err(t0: float, err: str, payload: bytes, detail: str = "") -> dict:
    return {
        "sent_bytes": 0,
        "recv_bytes": 0,
        "ms": round((time.time() - t0) * 1000, 1),
        "raw": b"",
        "error": err,
        "error_detail": detail,
        "payload_hex": payload.hex(),
    }


# ─── Fonctions de probe ISO 8583 ──────────────────────────────────────────────
def send_network_management() -> dict:
    """MTI 0800 (network management) → echo test.
    Fields: F7 (date/time), F11 (STAN), F70=301 (echo test).
    Expected response: MTI 0810 with same STAN."""
    fields = {
        7:  "0101120000",   # 01-01 12:00:00 (lab fixed date)
        11: "000001",       # STAN 000001
        70: "301",          # Network mgmt info code: 301 = echo test (some vendors)
    }
    msg = build_iso8583("0800", fields)
    framed = frame_message(msg)
    r = send_recv(framed)
    result = {
        "mti_sent": "0800",
        "fields_sent": list(fields.keys()),
        "info_code": "301",
        "info_meaning": "echo_test",
        "sent_bytes": r["sent_bytes"],
        "recv_bytes": r["recv_bytes"],
        "ms": r["ms"],
        "error": r["error"],
        "error_detail": r.get("error_detail"),
        "reachable": r["error"] is None and r["recv_bytes"] > 0,
    }
    if r["error"] is None and r["recv_bytes"] > 0:
        parsed = parse_response(r["raw"])
        result["response"] = parsed
        result["echo_ok"] = parsed.get("mti") == "0810"
    else:
        result["response"] = None
        result["echo_ok"] = False
    # Strip raw bytes for JSON output (too large)
    result["raw_hex_preview"] = r["raw"][:64].hex() if r["raw"] else ""
    return result


def send_signon() -> dict:
    """MTI 0800 with F70=001 (signon).
    Expected: MTI 0810 with F39='00' (approved)."""
    fields = {
        7:  "0101120000",
        11: "000002",
        70: "001",         # 001 = signon
        24: "123",         # NII
    }
    msg = build_iso8583("0800", fields)
    framed = frame_message(msg)
    r = send_recv(framed)
    result = {
        "mti_sent": "0800",
        "fields_sent": list(fields.keys()),
        "info_code": "001",
        "info_meaning": "signon",
        "sent_bytes": r["sent_bytes"],
        "recv_bytes": r["recv_bytes"],
        "ms": r["ms"],
        "error": r["error"],
        "error_detail": r.get("error_detail"),
    }
    if r["error"] is None and r["recv_bytes"] > 0:
        parsed = parse_response(r["raw"])
        result["response"] = parsed
        # Signon OK = 0810 + response code 00 (or empty for some switches)
        result["signon_ok"] = (
            parsed.get("mti") == "0810"
            and parsed.get("response_code") in (None, "00", "  ")
        )
    else:
        result["response"] = None
        result["signon_ok"] = False
    result["raw_hex_preview"] = r["raw"][:64].hex() if r["raw"] else ""
    return result


def try_unauthorized_transaction(safe_mode: str) -> dict:
    """MTI 0200 (financial transaction) with minimal fields → check if rejected.
    SAFE_MODE=read_only → SKIP (write forbidden in banking sector).
    SAFE_MODE=full → send 0200 and check response code (12/91/etc. = rejected)."""
    if safe_mode != "full":
        return {
            "mti_sent": None,
            "skipped": True,
            "reason": f"SAFE_MODE={safe_mode} — 0200 forbidden in read-only banking sector",
            "unauthorized_rejected": None,
            "note": "PCI-DSS / SWIFT CSP : no financial MTI sent in read-only mode",
        }
    # SAFE_MODE=full + LAB=1 → on peut tenter (mais avec PAN de test lab)
    # PAN de test : 4111111111111111 (Visa test) — usage lab uniquement.
    fields = {
        2:  "4111111111111111",   # Test PAN (Visa sandbox)
        4:  "000000001000",       # Amount: 10.00 (12 digits, minor units)
        7:  "0101120000",
        11: "000003",
        14: "2512",               # Exp date 12/25
        22: "012",                # POS entry mode: magstripe
        25: "00",                 # POS condition code: normal
        35: "4111111111111111=25121011200000100000",  # Track 2
        41: "TERM0001",           # Terminal ID
        42: "LAB000000000001",    # Card acceptor ID
    }
    msg = build_iso8583("0200", fields)
    framed = frame_message(msg)
    r = send_recv(framed)
    result = {
        "mti_sent": "0200",
        "skipped": False,
        "fields_sent": list(fields.keys()),
        "sent_bytes": r["sent_bytes"],
        "recv_bytes": r["recv_bytes"],
        "ms": r["ms"],
        "error": r["error"],
        "error_detail": r.get("error_detail"),
    }
    if r["error"] is None and r["recv_bytes"] > 0:
        parsed = parse_response(r["raw"])
        result["response"] = parsed
        rc = parsed.get("response_code")
        # 0210 = response to 0200 ; response_code != '00' or '05'/'12'/'91' = rejected
        result["unauthorized_rejected"] = (
            parsed.get("mti") == "0210"
            and rc not in (None, "00")
        )
        result["response_code"] = rc
    else:
        result["response"] = None
        result["unauthorized_rejected"] = None
        result["response_code"] = None
    result["raw_hex_preview"] = r["raw"][:64].hex() if r["raw"] else ""
    return result


def detect_switch_vendor_from_responses(responses: list[dict]) -> dict:
    """Concatène toutes les raw responses et cherche patterns vendor."""
    combined = b""
    for r in responses:
        if isinstance(r, dict) and r.get("raw_hex_preview"):
            try:
                combined += bytes.fromhex(r["raw_hex_preview"])
            except ValueError:
                pass
    return detect_switch_vendor(combined)


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # SAFE_MODE read-only : on autorise send_network_management() et send_signon()
    # car ce sont des MTI 0800 (network mgmt, non-financiers, echo-like).
    # On SKIP try_unauthorized_transaction() car 0200 = écriture financière.
    # Si SAFE_MODE=full explicitement, on autorise le 0200 en lab.

    mti_tested: list[str] = []
    responses_raw: list[dict] = []

    # Phase 1 : network management echo (0800) — read-only, autorisé
    nm_result = send_network_management()
    mti_tested.append("0800")
    responses_raw.append({
        "mti": "0800",
        "raw_hex_preview": nm_result.get("raw_hex_preview", ""),
    })

    # Phase 2 : signon (0800 + F70=001) — read-only, autorisé
    signon_result = send_signon()
    if not mti_tested.count("0800") >= 2:
        mti_tested.append("0800")  # on a testé deux variantes de 0800
    responses_raw.append({
        "mti": "0800",
        "raw_hex_preview": signon_result.get("raw_hex_preview", ""),
    })

    # Phase 3 : unauthorized transaction (0200) — SKIP si read-only
    tx_result = try_unauthorized_transaction(safe_mode)
    if not tx_result.get("skipped"):
        mti_tested.append("0200")
        responses_raw.append({
            "mti": "0200",
            "raw_hex_preview": tx_result.get("raw_hex_preview", ""),
        })

    # Phase 4 : vendor detection
    vendor_check = detect_switch_vendor_from_responses(responses_raw)

    # ─── Synthèse JSON stdout ──────────────────────────────────────────────
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "banking",
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "target": {
            "host": TARGET_HOST,
            "port": TARGET_PORT,
        },
        "regulations": list(get_sector_config().get("regulations", [])),
        "read_only": safe_mode == "read_only",
        "results": {
            "network_management": nm_result,
            "signon": signon_result,
            "unauthorized_transaction": tx_result,
            "vendor_detection": vendor_check,
        },
        "summary": {
            "switch_reachable": nm_result.get("reachable", False),
            "signon_ok": signon_result.get("signon_ok", False),
            "unauthorized_rejected": tx_result.get("unauthorized_rejected"),
            "switch_vendor": vendor_check.get("vendor"),
            "mti_tested": mti_tested,
        },
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }

    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
