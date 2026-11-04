#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — protocol probe : ISO 8583 card switch (raw socket).
# Secteur : banking — SAFE_MODE=read_only (uniquement MTI 0800 non-financier).
#
#   - v3.1 : socket TCP brute vers host d'autorisation (port 5000 default)
#   - v3.1 : encodage ISO 8583 manuel : MTI(4) + bitmap(8/16B) + data elements
#   - v3.1 : send network management message (MTI 0800) → expect 0810 response
#   - v3.1 : echo test (MTI 0800 + F70=301) → verify response code F39
#   - v3.1 : authorization probe (MTI 0100) — SKIP en read_only (financial MTI)
#   - v3.1 : response code forgery test (envoi F39 dans un request → rejet attendu)
#   - v3.1 : SEED reproducibility, LAB=1 guard, timeout 5s
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# PCI-DSS / PSD2 — aucun 0100/0200 envoyé en SAFE_MODE=read_only (write forbidden).
#
# Format ISO 8583-1:1993 message :
#   [2 bytes length (big-endian, optionnel selon framing)] [MTI 4 ASCII]
#   [primary bitmap 8 bytes binary] [secondary bitmap 8 bytes si F1 set]
#   [data elements in numeric order]
#
# Champs supportés (subset lab) :
#   F0  (MTI 4)    — Message Type Indicator (toujours présent, hors bitmap)
#   F2  (LLVAR)    — Primary Account Number (PAN)
#   F4  (fixed 12) — Transaction amount
#   F7  (fixed 10) — Transmission date & time MMDDhhmmss
#   F11 (fixed 6)  — System trace audit number (STAN)
#   F14 (fixed 4)  — Expiration date YYMM
#   F22 (fixed 3)  — POS entry mode
#   F24 (fixed 3)  — Network international identifier (NII)
#   F25 (fixed 2)  — POS condition code
#   F35 (LLVAR)    — Track 2 data
#   F39 (fixed 2)  — Response code (RESPONSE-ONLY field per ISO spec)
#   F41 (fixed 8)  — Card acceptor terminal identification
#   F42 (fixed 15) — Card acceptor id code
#   F62 (LLVAR)    — Private reserved
#   F70 (fixed 3)  — Network management information code
#                    (001=signon, 002=signoff, 301=echo, 301=signon-reload-key)
#                    [REQUIRES secondary bitmap car F70 > 64]
#
# Vecteur "response code forgery" :
#   F39 est un champ RÉPONSE (jamais dans un request légitime). Si on envoie
#   un MTI 0800 request AVEC F39="00" set, un switch conforme DOIT :
#     - soit rejeter le message (code 12 = invalid transaction / field not valid)
#     - soit ignorer F39 dans le parsing d'un request
#   Si le switch accepte silencieusement notre F39 forgé et l'écho dans la
#   réponse (ou ne retourne PAS d'erreur) → validation côté serveur défaillante
#   = un attaquant pourrait injecter des response codes arbitraires dans des
#   messages acquéreur → approve-to-decline swap = fraude.
import json
import os
import re
import socket
import struct
import sys
import time
from typing import Optional

# Tentative d'import de la lib iso8583 (optionnelle). Fallback sur encodage manuel.
try:
    import iso8583  # type: ignore
    _HAS_ISO8583_LIB = True
except ImportError:
    _HAS_ISO8583_LIB = False
    # Message informatif (n'interrompt pas — fallback manuel intégré)
    sys.stderr.write(
        "[iso8583_probe] lib iso8583 non installée — utilisation de l'encodage "
        "manuel intégré (subset lab). Pour fonctionnalités avancées : pip install iso8583\n"
    )

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "iso8583_probe"
DEFAULT_PORT = 5000              # ISO 8583 authorization host (lab default)
SOCKET_TIMEOUT = 5               # 5s strict (cf. spec harness)
RECV_BUFFER = 4096

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
_STAN_SEQ = [0]

def _next_stan() -> str:
    """STAN déterministe (SEED + incrément). Permet de reproduire les tirs
    ISO 8583 à l'identique pour audit (logs switch corrélables)."""
    _STAN_SEQ[0] += 1
    return f"{(SEED + _STAN_SEQ[0]) % 1000000:06d}"


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
# Usage: iso8583_probe.py <host> [port]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT


# ─── Encodage ISO 8583 manuel (subset lab) ────────────────────────────────────
FIELD_SPECS = {
    2:  ("llvar",   None),     # LLVAR (2 digits length prefix + data)
    4:  ("fixed",   12),       # Transaction amount (digits, minor units)
    7:  ("fixed",   10),       # MMDDhhmmss
    11: ("fixed",   6),        # STAN
    14: ("fixed",   4),        # YYMM
    22: ("fixed",   3),        # POS entry mode
    24: ("fixed",   3),        # NII
    25: ("fixed",   2),        # POS condition code
    35: ("llvar",   None),     # Track 2
    39: ("fixed",   2),        # Response code (RESPONSE field, pas dans un request)
    41: ("fixed",   8),        # Terminal ID
    42: ("fixed",   15),       # Card acceptor id code
    62: ("llvar",   None),     # Private reserved
    70: ("fixed",   3),        # Network mgmt info code (secondary bitmap)
}

MAX_FIELD = 128
BITMAP_TOTAL_BYTES = 16       # 8 bytes primary + 8 bytes secondary


def _set_bit(bitmap: bytearray, field_no: int) -> None:
    """Set bit for field_no (1..128) in combined primary+secondary bitmap (16 bytes).
    Field 1 → MSB of byte 0 (primary). Field 65 → MSB of byte 8 (secondary)."""
    if not (1 <= field_no <= MAX_FIELD):
        raise ValueError(f"field_no {field_no} out of range (1..{MAX_FIELD})")
    bit_pos = field_no - 1
    byte_idx = bit_pos // 8
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
        if len(v) >= length:
            return v[:length]
        # Right-pad with '0' (numeric convention) — lab subset
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
    fields: dict {field_no: value}  (field_no 1..128)
    Returns: MTI(4B) + primary_bitmap(8B) [+ secondary_bitmap(8B) if needed]
             + fields in numeric order.
    Field 1 (secondary bitmap indicator) is set automatically if any field >= 65.
    """
    if not (len(mti) == 4 and mti.isdigit()):
        raise ValueError(f"MTI must be 4 digits, got {mti!r}")
    needs_secondary = any(fno > 64 for fno in fields)
    bitmap = bytearray(BITMAP_TOTAL_BYTES)
    if needs_secondary:
        _set_bit(bitmap, 1)  # secondary bitmap indicator
    for fno in fields:
        if fno == 1 and needs_secondary:
            continue  # Field 1 already set above
        _set_bit(bitmap, fno)
    bitmap_out = bytes(bitmap[:16]) if needs_secondary else bytes(bitmap[:8])
    msg = bytearray()
    msg += mti.encode("ascii")
    msg += bitmap_out
    for fno in sorted(fields):
        msg += encode_field(fno, fields[fno])
    return bytes(msg)


def frame_message(msg: bytes) -> bytes:
    """Prepend 2-byte big-endian length header (common TCP ISO 8583 framing).
    Alternative framings : 4-byte ASCII length, 4-byte binary, ou aucun (raw).
    On garde le framing 2-byte big-endian (le plus répandu en lab + production).
    """
    return struct.pack(">H", len(msg)) + msg


def parse_response(raw: bytes) -> dict:
    """Parse minimal ISO 8583 response : MTI + bitmap + field 39 (response code).
    Field 39 = response code (2 ASCII chars : '00'=approved, '05'=do not honor,
    '12'=invalid transaction, '91'=issuer or switch inoperative, ...)."""
    if len(raw) < 12:
        return {"error": "too_short", "len": len(raw), "raw_hex": raw.hex()}
    # Strip 2-byte length header if present (heuristic: first 2 bytes are length)
    has_len_header = False
    if len(raw) >= 14:
        declared_len = struct.unpack(">H", raw[:2])[0]
        if declared_len == len(raw) - 2 or declared_len + 2 == len(raw):
            raw = raw[2:]
            has_len_header = True
    try:
        mti = raw[:4].decode("ascii", "ignore")
    except Exception:  # noqa: BLE001
        mti = "????"
    primary_bitmap = raw[4:12]
    has_secondary = bool(primary_bitmap and primary_bitmap[0] & 0x80)
    secondary_bitmap: bytes = b""
    if has_secondary and len(raw) >= 20:
        secondary_bitmap = raw[12:20]
        full_bitmap = primary_bitmap + secondary_bitmap
        bitmap_offset = 20
        max_field = 128
    else:
        has_secondary = False
        full_bitmap = primary_bitmap
        bitmap_offset = 12
        max_field = 64
    fields_present = []
    for fno in range(1, max_field + 1):
        bit_pos = fno - 1
        byte_idx = bit_pos // 8
        bit_in_byte = 7 - (bit_pos % 8)
        if byte_idx < len(full_bitmap) and full_bitmap[byte_idx] & (1 << bit_in_byte):
            fields_present.append(fno)
    # Walk fields to locate F39
    response_code = None
    offset = bitmap_offset
    for fno in fields_present:
        if fno == 1:
            continue  # secondary bitmap indicator, no data bytes
        if fno == 39:
            if offset + 2 <= len(raw):
                response_code = raw[offset:offset + 2].decode("ascii", "ignore")
            break
        if fno > 64:
            break  # past primary bitmap, F39 not found walking up
        spec = FIELD_SPECS.get(fno)
        if spec is None:
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


# ─── Socket helper ────────────────────────────────────────────────────────────
def send_recv(payload: bytes) -> dict:
    """TCP connect → send payload → recv response → close. Timeout 5s strict.
    Capture toutes les erreurs sans lever."""
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKET_TIMEOUT)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        s.sendall(payload)
        chunks: list[bytes] = []
        while True:
            try:
                chunk = s.recv(RECV_BUFFER)
                if not chunk:
                    break
                chunks.append(chunk)
                # Si on a déjà reçu assez (header + MTI + bitmap), on peut sortir
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


# ─── 1. Network management message (MTI 0800) → 0810 ─────────────────────────
def send_network_management() -> dict:
    """MTI 0800 (network management) → echo test.
    Fields: F7 (date/time), F11 (STAN), F70=301 (echo test).
    Expected response: MTI 0810 with same STAN."""
    stan = _next_stan()
    fields = {
        7:  "0101120000",   # 01-01 12:00:00 (lab fixed date)
        11: stan,           # STAN (SEED-deterministic)
        70: "301",          # Network mgmt info code: 301 = echo test (some vendors)
    }
    msg = build_iso8583("0800", fields)
    framed = frame_message(msg)
    r = send_recv(framed)
    result = {
        "mti_sent": "0800",
        "fields_sent": list(fields.keys()),
        "stan": stan,
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
        result["network_management_ok"] = (
            parsed.get("mti") == "0810"
            and r["recv_bytes"] > 0
        )
    else:
        result["response"] = None
        result["network_management_ok"] = False
    result["raw_hex_preview"] = r["raw"][:64].hex() if r["raw"] else ""
    return result


# ─── 2. Echo test (MTI 0800 + F70=301) → verify response code ────────────────
def send_echo_test() -> dict:
    """MTI 0800 + F70=301 (echo) → expected MTI 0810 with F39='00' (approved).
    Echo_ok = 0810 + response code '00' (or absent for some switches — empty accepted)."""
    stan = _next_stan()
    fields = {
        7:  "0101120000",
        11: stan,
        70: "301",          # 301 = echo test
        24: "123",          # NII
        41: "TERM0001",     # Terminal ID (lab)
    }
    msg = build_iso8583("0800", fields)
    framed = frame_message(msg)
    r = send_recv(framed)
    result = {
        "mti_sent": "0800",
        "fields_sent": list(fields.keys()),
        "stan": stan,
        "info_code": "301",
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
        # echo_ok = 0810 + (F39='00' or F39 absent — some switches omit on echo)
        result["echo_ok"] = (
            parsed.get("mti") == "0810"
            and rc in (None, "00", "  ")
        )
        result["response_code"] = rc
    else:
        result["response"] = None
        result["echo_ok"] = False
        result["response_code"] = None
    result["raw_hex_preview"] = r["raw"][:64].hex() if r["raw"] else ""
    return result


# ─── 3. Authorization MTI 0100 — READ_ONLY skip ──────────────────────────────
def probe_authorization_mti(safe_mode: str) -> dict:
    """MTI 0100 (authorization request) — SKIP si SAFE_MODE != full.

    MTI 0100 est un message financier (authorization, pas de clearing).
    En SAFE_MODE=read_only (banking sector default), on n'envoie JAMAIS de
    message financier — même en lab — pour éviter tout impact comptable.
    On documente seulement les champs qu'on aurait testés.
    """
    if safe_mode != "full":
        return {
            "mti_would_send": "0100",
            "skipped": True,
            "reason": (
                f"SAFE_MODE={safe_mode} — 0100 forbidden in read-only banking. "
                "PCI-DSS / SWIFT CSP : no financial MTI sent in read-only mode."
            ),
            "fields_would_test": [2, 4, 7, 11, 14, 22, 25, 35, 41, 42],
            "expected_response_mti": "0110",
            "expected_rejection_code": "05" or "12" or "91",
            "tested": False,
        }
    # SAFE_MODE=full + LAB=1 → on envoie 0100 avec PAN de test lab
    stan = _next_stan()
    fields = {
        2:  "4111111111111111",   # Test PAN (Visa sandbox)
        4:  "000000001000",       # Amount: 10.00 (minor units)
        7:  "0101120000",
        11: stan,
        14: "2512",               # Exp 12/25
        22: "012",                # POS entry mode: magstripe
        25: "00",                 # POS condition code: normal
        35: "4111111111111111=25121011200000100000",  # Track 2
        41: "TERM0001",
        42: "LAB000000000001",
    }
    msg = build_iso8583("0100", fields)
    framed = frame_message(msg)
    r = send_recv(framed)
    result = {
        "mti_would_send": "0100",
        "skipped": False,
        "mti_sent": "0100",
        "fields_sent": list(fields.keys()),
        "stan": stan,
        "sent_bytes": r["sent_bytes"],
        "recv_bytes": r["recv_bytes"],
        "ms": r["ms"],
        "error": r["error"],
        "error_detail": r.get("error_detail"),
        "tested": True,
    }
    if r["error"] is None and r["recv_bytes"] > 0:
        parsed = parse_response(r["raw"])
        result["response"] = parsed
        result["response_code"] = parsed.get("response_code")
        result["authorization_processed"] = parsed.get("mti") == "0110"
    else:
        result["response"] = None
        result["authorization_processed"] = False
    result["raw_hex_preview"] = r["raw"][:64].hex() if r["raw"] else ""
    return result


# ─── 4. Response code forgery test (F39 in a request) ────────────────────────
def test_response_code_forgery() -> dict:
    """Send MTI 0800 with F39='00' explicitly set in the request.
    F39 is a RESPONSE-ONLY field per ISO 8583 spec. A conformant switch MUST :
      - reject the message (F39 not valid in a request → code 12 = invalid tx)
      - or ignore F39 silently in request parsing
    If the switch echoes back our F39='00' as its own response code WITHOUT
    raising an error → server-side validation is missing → an attacker could
    forge response codes (approve-to-decline swap, decline-to-approve fraud).
    """
    stan = _next_stan()
    fields = {
        7:  "0101120000",
        11: stan,
        70: "301",          # echo test
        39: "00",           # FORGED response code in a REQUEST (should be invalid)
    }
    msg = build_iso8583("0800", fields)
    framed = frame_message(msg)
    r = send_recv(framed)
    result = {
        "mti_sent": "0800",
        "fields_sent": list(fields.keys()),
        "stan": stan,
        "forged_field": 39,
        "forged_value": "00",
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
        # response_code_forged = True if switch ACCEPTED our forged F39 (didn't reject)
        # Heuristique :
        #   - response_code '12' (invalid transaction) → switch a détecté → forgery rejected
        #   - response_code '05' (do not honor)        → switch a rejeté → forgery rejected
        #   - response_code '00' or absent + 0810      → switch n'a PAS détecté → CRITICAL
        if parsed.get("mti") == "0810":
            if rc in ("12", "05", "91"):
                result["response_code_forged"] = False
                result["note"] = (
                    f"safe: switch rejected forged F39 (response_code={rc}). "
                    "Server-side field validation present."
                )
            elif rc in (None, "00", "  "):
                result["response_code_forged"] = True
                result["note"] = (
                    "CRITICAL: switch silently accepted forged F39='00' in a "
                    "request → server-side validation missing. An attacker could "
                    "inject arbitrary response codes (approve-to-decline swap)."
                )
            else:
                result["response_code_forged"] = None
                result["note"] = (
                    f"inconclusive: unexpected response_code={rc}. "
                    "Manual analysis required."
                )
        else:
            result["response_code_forged"] = None
            result["note"] = (
                f"inconclusive: response MTI={parsed.get('mti')} (expected 0810). "
                "Switch may not implement 0800 echo."
            )
    else:
        result["response"] = None
        result["response_code_forged"] = None
        result["note"] = "no response from switch — cannot test forgery."
    result["raw_hex_preview"] = r["raw"][:64].hex() if r["raw"] else ""
    return result


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # SAFE_MODE read-only : send_network_management, send_echo_test, et
    # test_response_code_forgery sont des MTI 0800 (network mgmt, non-financier,
    # echo-like) → autorisés en read-only.
    # probe_authorization_mti (0100) → SKIP en read-only.

    fields_tested: list[int] = []

    # Phase 1 : network management (0800 → 0810)
    nm_result = send_network_management()
    fields_tested.extend(nm_result.get("fields_sent", []))

    # Phase 2 : echo test (0800 + F70=301)
    echo_result = send_echo_test()
    fields_tested.extend(echo_result.get("fields_sent", []))

    # Phase 3 : response code forgery test (0800 + F39 forged)
    forgery_result = test_response_code_forgery()
    fields_tested.extend(forgery_result.get("fields_sent", []))

    # Phase 4 : authorization MTI 0100 — SKIP en read-only
    auth_result = probe_authorization_mti(safe_mode)
    if not auth_result.get("skipped"):
        fields_tested.extend(auth_result.get("fields_sent", []))

    # Dédoublonne et trie
    fields_tested = sorted(set(fields_tested))

    # ─── Synthèse JSON stdout ──────────────────────────────────────────────
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "banking",
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "seed": SEED,
        "target": {
            "host": TARGET_HOST,
            "port": TARGET_PORT,
        },
        "regulations": list(get_sector_config().get("regulations", [])),
        "read_only": safe_mode == "read_only",
        "iso8583_lib_available": _HAS_ISO8583_LIB,
        "encoding": "manual (subset lab)" if not _HAS_ISO8583_LIB else "iso8583 lib",
        "results": {
            "network_management": nm_result,
            "echo_test": echo_result,
            "authorization_mti_0100": auth_result,
            "response_code_forgery": forgery_result,
        },
        "summary": {
            "network_management_ok": nm_result.get("network_management_ok", False),
            "echo_ok": echo_result.get("echo_ok", False),
            "response_code_forged": forgery_result.get("response_code_forged"),
            "fields_tested": fields_tested,
            "authorization_0100_tested": not auth_result.get("skipped", True),
        },
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
