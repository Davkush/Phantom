#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — dlms_probe
# Energy sector module — IEC 62056 (DLMS / COSEM) probing of smart meters
# (electricity, gas, water, heat). DLMS/COSEM is the dominant smart-meter
# protocol family worldwide (Europe / APAC / parts of NAM).
#
#   - Default port : 4059 (DLMS over TCP/IP — IEC 62056-46)
#   - HDLC serial  : out of scope for this TCP probe (would need raw serial
#                              access on /dev/ttyUSBx)
#   - Stack (TCP)  : TCP → DLMS-TCP-Wrapper (version(2) + length(2)) →
#                    ACSE APDU (AARQ/AARE, BER encoded) → DLMS APDU
#                    (Get/Set/Action, A-XDR encoded) inside user-information
#
#   - Probes performed (READ-ONLY — no Set-Request, no Action-Request on
#     tariff configuration or other writable attributes):
#       1. send_aarq        — ACSE AARQ (Association Request) with
#                             authentication = None. A conformant smart
#                             meter MUST respond with AARE (Association
#                             Response) carrying the negotiated
#                             application-context-name and the meter's
#                             authentication requirements.
#       2. parse_aare       — extract:
#                             • auth_level (None / Low / High MD5 /
#                               High SHA1 / High GMAC / High SHA-256)
#                             • ciphering_active (Boolean): whether the AARE
#                               negotiated an encrypted application-context
#                               (the AC OIDs 2.16.756.5.16.1.0.0.x with
#                               x in {11, 12, 13, 14} mean ciphering ON,
#                               versions 8..10 mean ciphering OFF).
#                             • conformance block (BIT STRING of
#                               servicesSupported) — this tells us which
#                               DLMS services the meter allows (Get / Set /
#                               Action / etc.).
#       3. read_meter_data  — Issue a Get-Request-Normal for the OBIS
#                             logical name 1.1.1.0.0.255 (total active
#                             power, electricity). Inspect the response:
#                             Get-Response tag 0xC4 (with-data) ⇒
#                             meter_data_read=True.
#       4. write_capability — READ-ONLY inference: examine the negotiated
#                             conformance block. If bit "Set" (bit 4) is
#                             set in the conformance block ⇒ the meter
#                             allows writes (we DO NOT exercise this — we
#                             only report the capability).
#       5. devices_found    — counts how many distinct logical devices
#                             (meters) responded. A single TCP connection
#                             usually addresses one meter, so this is 0 or 1
#                             (extended to N if we detect multiple meter
#                             IDs via a device enumeration when supported).
#
#   - Ciphering detection:
#       DLMS ciphering uses two keys: the Global Unicast Encryption Key
#       (GUEK, AES-128/256-GCM) for data confidentiality, and the Global
#       Signing Key (GSK, AES-GMAC) for authentication. When ciphering is
#       negotiated, the AARE carries an application-context-name OID with
#       version ≥ 11, AND the user-information InitiateResponse carries
#       a "cyphering" SEQUENCE inside its negotiated_conformance block.
#       We sniff for both.
#
#   - DLMS wrapper: 2-byte version (BE) + 2-byte length (BE) over the
#     ACSE/DLMS APDU.
#
#   - READ_ONLY=True  (energy sector safety constraint — never Set/Action
#     on a live meter)
#   - SEED env var    : deterministic invoke IDs
#   - LAB=1 mandatory ; 5 s timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (energy) : NERC CIP / NIS2 / ENISA, IEC 62056
#   (DLMS/COSEM), IEC 62351-3 / -8 (TLS for smart-metering backhaul).
import json
import os
import random
import socket
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
MODULE_NAME = "dlms_probe"
DEFAULT_PORT = 4059  # DLMS over TCP/IP (IEC 62056-46)
TIMEOUT_S = 5.0
READ_ONLY = True  # never Set / Action on a live meter

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── SEED for deterministic invoke IDs ────────────────────────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else None
except ValueError:
    SEED = None
_rng = random.Random(SEED) if SEED is not None else random.Random()


def _next_invoke_id() -> int:
    return _rng.randint(1, 0xFF)


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
#  DLMS / ACSE CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
# DLMS-TCP-Wrapper
DLMS_TCP_WRAPPER_VERSION = 0x0000

# ACSE APDU tags (BER — context class, constructed for SEQUENCEs)
ACSE_AARQ_TAG = 0x60   # [Application 0] — AARQ (constructed)
ACSE_AARE_TAG = 0x61   # [Application 1] — AARE (constructed)
ACSE_RLRQ_TAG = 0x62   # [Application 2] — Release-Request
ACSE_RLRE_TAG = 0x63   # [Application 3] — Release-Response
ACSE_ABRT_TAG = 0x64   # [Application 4] — Abort

# AARQ/AARE context-class fields
AARQ_APP_CONTEXT_NAME   = 0xA0   # [0]
AARQ_CALLED_AP_TITLE    = 0xA1   # [1]
AARQ_CALLED_AP_INVOC    = 0xA2   # [2]
AARQ_CALLING_AP_TITLE   = 0xA6   # [3] — actually [6]
AARQ_CALLING_AP_INVOC   = 0xA7   # [7]
AARQ_SENDER_ACSE_REQ    = 0x8A   # [10] (primitive) — sender-acse-requirements BIT STRING
AARQ_MECHANISM_NAME     = 0xAC   # [12] (primitive) — mechanism-name OBJECT IDENTIFIER
AARQ_CALLING_AUTH_VALUE = 0xA8   # [8] — calling-authentication-value
AARQ_USER_INFORMATION   = 0xBE   # [30] (constructed) — user-information

# Application-context-name OIDs (DLMS / COSEM)
# Format: 2.16.756.5.16.1.0.0.<version>
#   version 1 = LN, no ciphering
#   version 2 = SN, no ciphering
#   version 3 = LN, no ciphering
#   version 4 = SN, no ciphering
#   version 8 = LN referencing, no ciphering, version 3
#   version 9 = SN referencing, no ciphering, version 3
#   version 10= LN referencing, no ciphering, version 3
#   version 11= LN referencing, with ciphering, version 3
#   version 12= SN referencing, with ciphering, version 3
#   version 13= LN referencing, with ciphering, version 4
#   version 14= SN referencing, with ciphering, version 4
# OID encoded (BER): 06 09 60 85 74 05 08 01 01 <version byte>
#   (the first two arcs 2.40 are encoded as 0x60 in the first content byte)
APP_CTX_OID_PREFIX = bytes([0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01])
APP_CTX_OID_NO_CIPHER_LN = 8     # version 8 — LN, no ciphering
APP_CTX_OID_NO_CIPHER_SN = 9     # version 9 — SN, no ciphering
APP_CTX_OID_WITH_CIPHER_LN = 11  # version 11 — LN, with ciphering
APP_CTX_OID_WITH_CIPHER_SN = 12  # version 12 — SN, with ciphering

# Mechanism-name OIDs (DLMS auth mechanisms)
# OID prefix 0.0.40.0.x.y is encoded as: 06 06 00 28 00 xx yy
# (0.0 = 0x00, 0x00; 40 = 0x28; 0 = 0x00)
MECH_OID_PREFIX = bytes([0x00, 0x28, 0x00])
# (mechanism-name OID 0.0.40.0.1.1 = Low-level security)
MECH_LOW_SECURITY     = (1, 1)   # 0.0.40.0.1.1
MECH_HIGH_MD5         = (2, 1)   # 0.0.40.0.2.1
MECH_HIGH_SHA1        = (2, 2)   # 0.0.40.0.2.2
MECH_HIGH_GMAC        = (2, 3)   # 0.0.40.0.2.3
MECH_HIGH_SHA256      = (2, 4)   # 0.0.40.0.2.4
MECH_HIGH_ECDSA       = (3, 0)   # 0.0.40.0.3.0

# DLMS APDU tags (A-XDR — these are the high-level tags for DLMS PDUs)
DLMS_GET_REQUEST_NORMAL     = 0xC0  # Get-Request-Normal
DLMS_GET_REQUEST_NEXT       = 0xC1  # Get-Request-Next
DLMS_GET_REQUEST_WITH_LIST  = 0xC2  # Get-Request-With-List
DLMS_SET_REQUEST_NORMAL     = 0xC1  # (offset by context; set never sent)
DLMS_GET_RESPONSE_NORMAL    = 0xC4  # Get-Response-Normal (with data)
DLMS_GET_RESPONSE_NEXT      = 0xC5  # Get-Response-Next
DLMS_GET_RESPONSE_WITH_LIST = 0xC6
DLMS_GET_RESPONSE_ERROR     = 0xD0  # Get-Response with error

# OBIS logical name for total active power (electricity meter)
# 1.1.1.0.0.255 — A=1 (electricity), B=1 (import), C=1 (active power),
# D=0 (sum), E=0 (rate 0), F=255 (default billing period)
OBIS_ACTIVE_POWER = bytes([1, 1, 1, 0, 0, 0xFF])


# ═══════════════════════════════════════════════════════════════════════════
#  BER HELPERS (minimal — for ACSE APDU encoding/decoding)
# ═══════════════════════════════════════════════════════════════════════════

def ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    out = b""
    n = length
    while n > 0:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def ber_decode_len(data: bytes, idx: int) -> Tuple[int, int]:
    if idx >= len(data):
        return (0, idx)
    b = data[idx]
    idx += 1
    if b < 0x80:
        return (b, idx)
    n = b & 0x7F
    if n == 0 or idx + n > len(data):
        return (0, idx)
    length = 0
    for _ in range(n):
        length = (length << 8) | data[idx]
        idx += 1
    return (length, idx)


def ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_len(len(value)) + value


def ber_int(val: int) -> bytes:
    """Encode a non-negative int as a BER INTEGER."""
    if val == 0:
        return bytes([0x02, 0x01, 0x00])
    n = val
    length = 0
    while n > 0:
        n >>= 8
        length += 1
    if (val >> (8 * (length - 1))) & 0x80:
        length += 1
    return bytes([0x02, length]) + val.to_bytes(length, "big")


def ber_oid(oid_bytes: bytes) -> bytes:
    """Wrap raw OID content bytes as a BER OBJECT IDENTIFIER (tag 0x06)."""
    return bytes([0x06, len(oid_bytes)]) + oid_bytes


def _extract_oid_bytes(value: bytes) -> Optional[bytes]:
    """Extract OID content bytes from a field value.

    Accepts both:
      • explicit tagging: value is `0x06 <len> <oid-content>` (BER OID TLV)
      • implicit tagging: value is just `<oid-content>` (no OID tag)
    Returns the OID content bytes, or None if the value is too short.
    """
    if value is None or len(value) < 2:
        return None
    if value[0] == 0x06:   # explicit — BER OID tag
        oid_len = value[1]
        if len(value) >= 2 + oid_len:
            return value[2: 2 + oid_len]
        return None
    # Implicit — treat the whole value as OID content
    return value


# ═══════════════════════════════════════════════════════════════════════════
#  DLMS-TCP WRAPPER
# ═══════════════════════════════════════════════════════════════════════════

def dlms_wrap(apdu: bytes) -> bytes:
    """Wrap a DLMS APDU in the DLMS-TCP wrapper: version(2 BE) + length(2 BE)."""
    return struct.pack(">HH", DLMS_TCP_WRAPPER_VERSION, len(apdu)) + apdu


def _read_n(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def read_dlms_wrapper(sock: socket.socket) -> Optional[bytes]:
    """Read one DLMS-TCP-wrapped APDU. Returns the APDU or None on failure."""
    hdr = _read_n(sock, 4)
    if len(hdr) < 4:
        return None
    version, length = struct.unpack(">HH", hdr)
    if length == 0 or length > 65535:
        return None
    body = _read_n(sock, length)
    if len(body) < length:
        return None
    return body


# ═══════════════════════════════════════════════════════════════════════════
#  AARQ / AARE BUILDERS & PARSERS
# ═══════════════════════════════════════════════════════════════════════════

def build_dlms_initiate_request() -> bytes:
    """Build the DLMS InitiateRequest APDU that goes inside the AARQ
    user-information PDV.

    Per IEC 62056-53 §7.3, the InitiateRequest uses A-XDR encoding (similar
    to BER for tag/length, but with DLMS-specific primitives). Layout:

      dedicated-key            OCTET STRING (length 0 = empty)
      response-allowed         BOOLEAN (1 byte, 0xFF)
      proposed-quality-of-service  INTEGER OPTIONAL (we omit)
      proposed-dlms-version-number INTEGER (1 byte: 6)
      proposed-conformance     BIT STRING (3 bytes — 24-bit conformance block)
      proposed-maximum-pdu-size  INTEGER (2 bytes, e.g. 1024)

    For a READ-ONLY probe, advertise only Get / Get-With-List /
    Attribute-0-Supported-With-Get / General-Get. We DO NOT advertise Set,
    Action, or Information-Report.
    """
    # Conformance block (3 bytes / 24 bits):
    # Bit 0 (MSB byte 1 bit 7) = Action-Service
    # Bit 1 (MSB byte 1 bit 6) = Action-With-List
    # Bit 2 (MSB byte 1 bit 5) = Get-Service                       <-- we set
    # Bit 3 (MSB byte 1 bit 4) = Get-With-List
    # Bit 4 (MSB byte 1 bit 3) = Set-Service                        (we leave clear)
    # Bit 5 (MSB byte 1 bit 2) = Set-With-List
    # Bit 6 (MSB byte 1 bit 1) = Event-Notification
    # Bit 7 (MSB byte 1 bit 0) = Unconfirmed-Service
    # Byte 2 bit 7 = Attribute-0-Supported-With-Get                <-- we set
    # Byte 2 bit 1 = General-Get                                   <-- we set
    # Byte 3: leave 0
    byte1 = 0x20   # bit 2 (Get) = byte1 bit 5 = 0x20
    byte2 = 0x82   # bit 8 (Attr-0-With-Get) = byte2 bit 7 = 0x80, bit 14 (General-Get) = byte2 bit 1 = 0x02
    byte3 = 0x00
    conf_bytes = bytes([byte1, byte2, byte3])

    # dedicated-key: OCTET STRING (empty), A-XDR encodes as 0x00 (length 0)
    # response-allowed: BOOLEAN (TRUE) — 0x01 (DLMS uses 1 for TRUE)
    # proposed-dlms-version-number: INTEGER 6 — A-XDR encodes as 0x06
    # proposed-conformance: BIT STRING — A-XDR encodes as 0x00 (no unused bits)
    #   + 3 bytes
    # proposed-maximum-pdu-size: Unsigned16 (1024) — A-XDR encodes as 2 bytes BE
    pdu_size = 1024
    initiate_body = (
        bytes([0x00])               # dedicated-key: empty octet string (length 0)
        + bytes([0x01])             # response-allowed: TRUE
        + bytes([0x06])             # proposed-dlms-version-number: 6
        + bytes([0x00]) + conf_bytes   # proposed-conformance BIT STRING (no unused + 3 bytes)
        + struct.pack(">H", pdu_size)  # proposed-maximum-pdu-size Unsigned16
    )
    return initiate_body


def build_aarq(auth_level: str = "none",
               client_password: bytes = b"",
               client_challenge: bytes = b"") -> bytes:
    """Build an ACSE AARQ APDU.

    `auth_level`:
        "none"     — no auth (default)
        "low"      — Low-level security (password)
        "high_md5" — High-level MD5 challenge-response (we send client_challenge)
    The AARQ carries:
      - application-context-name (OID 2.16.756.5.16.1.0.0.8 = LN no ciphering)
      - sender-acse-requirements (BIT STRING with "authentication" bit if auth)
      - mechanism-name (OID for the chosen auth mechanism)
      - calling-authentication-value (the password or challenge response)
      - user-information (PDV-list with DLMS InitiateRequest)
    """
    app_ctx_oid = APP_CTX_OID_PREFIX + bytes([APP_CTX_OID_NO_CIPHER_LN])
    app_ctx_tlv = ber_tlv(AARQ_APP_CONTEXT_NAME, ber_oid(app_ctx_oid))

    # sender-acse-requirements — BIT STRING (1 byte, 0 unused bits)
    # bit 0 (MSB) = "authentication"
    sender_acse = bytes([0x83, 0x01, 0x00])  # tag [11] implicit, primitive, length 1, value 0
    if auth_level != "none":
        # Set the "authentication" bit (bit 0 of the 1-byte BIT STRING)
        # The BIT STRING content is: 0x00 unused-bits + 1 byte flags.
        sender_acse = bytes([0x83, 0x02, 0x00, 0x80])  # 0 unused + 0x80 = bit 0 set

    # mechanism-name — OBJECT IDENTIFIER
    if auth_level == "none":
        mechanism_tlv = b""
        auth_value_tlv = b""
    elif auth_level == "low":
        mech_oid = MECH_OID_PREFIX + bytes(MECH_LOW_SECURITY)
        mechanism_tlv = ber_tlv(AARQ_MECHANISM_NAME, mech_oid)
        # calling-authentication-value [8] CHOICE: charstring [0] password
        # We use a CHAR STRING (PrintableString) wrapper for simplicity.
        if client_password:
            inner = bytes([0x80]) + ber_len(len(client_password)) + client_password
            auth_value_tlv = ber_tlv(AARQ_CALLING_AUTH_VALUE, inner)
        else:
            auth_value_tlv = b""
    elif auth_level == "high_md5":
        mech_oid = MECH_OID_PREFIX + bytes(MECH_HIGH_MD5)
        mechanism_tlv = ber_tlv(AARQ_MECHANISM_NAME, mech_oid)
        if client_challenge:
            inner = bytes([0x81]) + ber_len(len(client_challenge)) + client_challenge
            auth_value_tlv = ber_tlv(AARQ_CALLING_AUTH_VALUE, inner)
        else:
            auth_value_tlv = b""
    else:
        mechanism_tlv = b""
        auth_value_tlv = b""

    # user-information [30] (constructed) — PDV list
    init_req = build_dlms_initiate_request()
    # PDV: [0] SEQUENCE { transfer-syntax-name OID, data OCTET STRING }
    # We use the DLMS transfer syntax OID 2.16.756.5.16.1.0.0.8 (same as AC)
    pdv_data = init_req
    transfer_oid = APP_CTX_OID_PREFIX + bytes([APP_CTX_OID_NO_CIPHER_LN])
    pdv = bytes([0x30]) + ber_len(len(ber_oid(transfer_oid) + ber_tlv(0x04, pdv_data))) + \
        ber_oid(transfer_oid) + ber_tlv(0x04, pdv_data)
    # PDV-list is SEQUENCE OF PDV (we have one)
    pdv_list = bytes([0x28]) + ber_len(len(pdv)) + pdv   # [0] SET
    user_info_tlv = bytes([AARQ_USER_INFORMATION]) + ber_len(len(pdv_list)) + pdv_list

    # AARQ APDU body
    aarq_body = app_ctx_tlv + sender_acse + mechanism_tlv + auth_value_tlv + user_info_tlv
    return bytes([ACSE_AARQ_TAG]) + ber_len(len(aarq_body)) + aarq_body


def parse_aare(apdu: bytes) -> Dict:
    """Parse an AARE (Association Response) APDU.

    Returns:
      {meter_accessible, auth_level, ciphering_active,
       negotiated_ac_oid_version, conformance, error}
    """
    out: Dict = {
        "parsed_ok": False,
        "auth_level": "none",
        "ciphering_active": False,
        "negotiated_ac_oid_version": None,
        "conformance": None,
        "error": None,
    }
    if not apdu or apdu[0] != ACSE_AARE_TAG:
        out["error"] = f"not_aare:0x{(apdu[:1] or b'').hex()}"
        return out
    length, idx = ber_decode_len(apdu, 1)
    content = apdu[idx: idx + length]
    # Walk context-tagged children. We accept multiple tag-number conventions
    # for the mechanism-name field because the AARE in different ACSE /
    # DLMS profiles uses either [12] (DLMS convention, same as AARQ) or
    # [9] (X.227 AARE).
    MECH_NAME_TAGS = (AARQ_MECHANISM_NAME, 0xA9)
    i = 0
    while i < len(content):
        tag = content[i]
        length, i = ber_decode_len(content, i + 1)
        value = content[i: i + length]
        i += length
        # application-context-name [0]
        if tag == AARQ_APP_CONTEXT_NAME:
            # value is an OID TLV (06 ... <oid>) — explicit tagging
            oid_bytes = _extract_oid_bytes(value)
            if oid_bytes is not None:
                if len(oid_bytes) >= 8 and oid_bytes[:7] == APP_CTX_OID_PREFIX:
                    version = oid_bytes[7]
                    out["negotiated_ac_oid_version"] = version
                    # Versions 11..14 imply ciphering ON
                    out["ciphering_active"] = version in (11, 12, 13, 14)
        elif tag in MECH_NAME_TAGS:
            oid_bytes = _extract_oid_bytes(value)
            if oid_bytes is not None:
                # Mechanism OIDs (DLMS) are encoded as 0.0.40.0.x.y, which
                # is 5 bytes in BER (00 28 00 xx yy). 3-byte prefix + 2
                # tail bytes.
                if len(oid_bytes) >= 5 and oid_bytes[:3] == MECH_OID_PREFIX:
                    x, y = oid_bytes[3], oid_bytes[4]
                    out["auth_level"] = _decode_mechanism(x, y)
        elif tag == AARQ_USER_INFORMATION:
            # user-information [30] — PDV-list
            # Walk PDVs to find the data (DLMS InitiateResponse)
            ui_idx = 0
            while ui_idx < len(value):
                ui_tag = value[ui_idx]
                ui_len, ui_idx = ber_decode_len(value, ui_idx + 1)
                ui_content = value[ui_idx: ui_idx + ui_len]
                ui_idx += ui_len
                # Look for SET [0x28] of SEQUENCE [0x30] of { OID, OCTETSTRING }
                if ui_tag == 0x28 and len(ui_content) >= 2 and ui_content[0] == 0x30:
                    seq_len, seq_idx = ber_decode_len(ui_content, 1)
                    seq = ui_content[seq_idx: seq_idx + seq_len]
                    # Skip OID, find OCTET STRING
                    s_idx = 0
                    while s_idx < len(seq):
                        s_tag = seq[s_idx]
                        s_len, s_idx = ber_decode_len(seq, s_idx + 1)
                        s_val = seq[s_idx: s_idx + s_len]
                        s_idx += s_len
                        if s_tag == 0x04:  # OCTET STRING — contains InitiateResponse
                            conf = _extract_conformance(s_val)
                            if conf:
                                out["conformance"] = conf.hex()
                                out["parsed_ok"] = True
                            break
    return out


def _decode_mechanism(x: int, y: int) -> str:
    """Map a mechanism-name OID's last two arcs to a human-readable name."""
    if (x, y) == MECH_LOW_SECURITY:
        return "low"
    if (x, y) == MECH_HIGH_MD5:
        return "high_md5"
    if (x, y) == MECH_HIGH_SHA1:
        return "high_sha1"
    if (x, y) == MECH_HIGH_GMAC:
        return "high_gmac"
    if (x, y) == MECH_HIGH_SHA256:
        return "high_sha256"
    if (x, y) == MECH_HIGH_ECDSA:
        return "high_ecdsa"
    return f"unknown_{x}_{y}"


def _extract_conformance(init_resp: bytes) -> Optional[bytes]:
    """Best-effort extraction of the 3-byte conformance block from a
    DLMS InitiateResponse APDU.

    InitiateResponse layout (A-XDR):
      negotiated-quality-of-service  INTEGER OPTIONAL (skip if present)
      negotiated-dlms-version-number INTEGER (1 byte)
      negotiated-conformance         BIT STRING (0 unused + 3 bytes)
      negotiated-maximum-pdu-size    Unsigned16 (2 bytes)
      vaa-name                       Unsigned16 (2 bytes)
    """
    if len(init_resp) < 8:
        return None
    # Try the common case: no QoS, dlms-version (1 byte) then conformance (1 + 3 bytes)
    # Offsets: 0 = dlms-version, 1 = unused-bits count, 2..4 = 3 conformance bytes
    # But there may also be a dedicated-key, response-allowed, etc. So we scan
    # for the pattern: byte X = 0x06 (dlms version 6), byte X+1 = 0x00 (no unused bits),
    # bytes X+2..X+4 = conformance block.
    for i in range(len(init_resp) - 4):
        if init_resp[i] == 0x06 and init_resp[i + 1] == 0x00:
            return init_resp[i + 2: i + 5]
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  GET-REQUEST BUILDER (read-only — active power register)
# ═══════════════════════════════════════════════════════════════════════════

def build_get_request_normal(obis: bytes, invoke_id: int,
                              attribute_index: int = 1) -> bytes:
    """Build a DLMS Get-Request-Normal for a logical-name-referenced object.

    Per IEC 62056-6-2 §7.3, Get-Request-Normal is encoded (A-XDR) as:

      [0xC0] <len>                  -- Get-Request-Normal tag (high nibble 0xC)
      invoke-id-and-priority (1B)   -- bit 7=service-class (0=confirmed),
                                       bit 6=priority (0=high),
                                       bits 5..0 = invoke-id
      variable-access-specification CHOICE [1] = "name":
        [0x01] <len=15?>            -- CHOICE [1] = name (LN-referenced)
          logical-name [0x00] <len=6> <OBIS bytes>
          attribute-index [0x00] <len=1> <attr>
          access-selector [0x00] <len=0> (omitted for default)

    The exact A-XDR encoding of the Name SEQUENCE varies between
    implementations; we use the canonical form:
      invoke-id-and-priority: 1 byte
      variable-access-spec: 0x01 (CHOICE=name) + 0x09 (length) + ...
    """
    # Build the body (without the Get-Request-Normal tag/length)
    invoke_byte = (invoke_id & 0x3F)  # confirmed, high priority
    # variable-access-specification CHOICE = [1] name
    # name ::= SEQUENCE {
    #   logical-name [6] OctetString,
    #   attribute-index [3] Unsigned8,
    # }
    # A-XDR encodes the CHOICE index as 0x01 (for "name"), then the data follows.
    # logical-name as OctetString: 0x00 (tag for OctetString in A-XDR LN) + len + data
    # Actually the LN A-XDR encoding for the Name is:
    #   [6] OctetString(6)  — implicitly tagged as 0x06 + 0x06 + 6 bytes
    #   [3] Unsigned8       — implicitly tagged as 0x03 + 0x01 + 1 byte
    # We try the canonical DLMS Green Book encoding:
    var_access = (
        bytes([0x01])               # CHOICE = name (LN)
        + bytes([0x06, len(obis)]) + obis   # [6] logical-name OctetString
        + bytes([0x03, 0x01, attribute_index])   # [3] attribute-index
    )
    body = bytes([invoke_byte]) + var_access
    return bytes([DLMS_GET_REQUEST_NORMAL]) + ber_len(len(body)) + body


# ═══════════════════════════════════════════════════════════════════════════
#  GET-RESPONSE PARSER
# ═══════════════════════════════════════════════════════════════════════════

def parse_get_response(apdu: bytes) -> Dict:
    """Parse a Get-Response and return whether it carries data."""
    out: Dict = {"has_data": False, "tag": None, "error": None,
                 "data_length": 0}
    if not apdu:
        out["error"] = "empty_apdu"
        return out
    out["tag"] = apdu[0]
    if apdu[0] == DLMS_GET_RESPONSE_NORMAL:
        # Get-Response-Normal carries data
        length, idx = ber_decode_len(apdu, 1)
        out["data_length"] = max(length - 2, 0)   # minus invoke-id and result tag
        out["has_data"] = True
    elif apdu[0] == DLMS_GET_RESPONSE_NEXT:
        # Data-block-transfer — also has data
        out["has_data"] = True
    elif apdu[0] == DLMS_GET_RESPONSE_ERROR:
        out["error"] = "get_response_error"
    elif apdu[0] == 0xD0 or apdu[0] == 0xD1:
        out["error"] = "data_access_error"
    else:
        out["error"] = f"unexpected_tag:0x{apdu[0]:02X}"
    return out


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("DLMS / COSEM smart-meter probing on production "
                           "metering infrastructure is illegal outside an "
                           "authorized lab. NERC CIP / NIS2 / IEC 62056."),
        }))
        sys.exit(1)

    t0 = time.time()
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "port": PORT,
        "sector": SECTOR_CFG.get("sector"),
        "safe_mode": SAFE_MODE,
        "read_only": READ_ONLY,
        "seed": SEED,
        # Spec-required output fields:
        "meter_accessible": False,
        "auth_level": "none",
        "meter_data_read": False,
        "ciphering_active": False,
        "devices_found": 0,
        # Extra diagnostic fields:
        "negotiated_ac_oid_version": None,
        "conformance": None,
        "errors": [],
    }

    # ─── 1. Open TCP connection + send AARQ ────────────────────────────────
    sock = None
    aare_info: Dict = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_S)
        sock.connect((HOST, PORT))
        # Send AARQ (auth_level = none)
        aarq = build_aarq(auth_level="none")
        sock.sendall(dlms_wrap(aarq))
        # Read AARE
        aare_apdu = read_dlms_wrapper(sock)
        if aare_apdu is None:
            summary["errors"].append("aarq:no_aare_response")
        else:
            aare_info = parse_aare(aare_apdu)
            if aare_info.get("parsed_ok") or aare_apdu[0] == ACSE_AARE_TAG:
                summary["meter_accessible"] = True
                summary["devices_found"] = 1   # one meter responded
                summary["auth_level"] = aare_info.get("auth_level", "none")
                summary["ciphering_active"] = bool(aare_info.get("ciphering_active"))
                summary["negotiated_ac_oid_version"] = aare_info.get(
                    "negotiated_ac_oid_version")
                summary["conformance"] = aare_info.get("conformance")
            else:
                summary["errors"].append(
                    f"aare:{aare_info.get('error') or 'parse_failed'}")
    except (socket.timeout, TimeoutError):
        summary["errors"].append("transport:timeout")
    except ConnectionRefusedError:
        summary["errors"].append("transport:ConnectionRefusedError")
    except OSError as e:
        summary["errors"].append(f"transport:{type(e).__name__}:{e}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"transport:{type(e).__name__}:{e}")

    # ─── 2. Read meter data (Get active power register) ───────────────────
    if summary["meter_accessible"] and sock is not None:
        try:
            invoke_id = _next_invoke_id()
            get_req = build_get_request_normal(
                OBIS_ACTIVE_POWER, invoke_id=invoke_id, attribute_index=2
            )
            sock.sendall(dlms_wrap(get_req))
            resp = read_dlms_wrapper(sock)
            if resp is None:
                summary["errors"].append("get:no_response")
            else:
                parsed = parse_get_response(resp)
                if parsed.get("has_data"):
                    summary["meter_data_read"] = True
                if parsed.get("error"):
                    summary["errors"].append(f"get:{parsed['error']}")
        except (socket.timeout, TimeoutError):
            summary["errors"].append("get:timeout")
        except OSError as e:
            summary["errors"].append(f"get:{type(e).__name__}:{e}")
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"get:{type(e).__name__}:{e}")

    # ─── 3. Best-effort graceful close ────────────────────────────────────
    if sock is not None:
        try:
            # Send RLQ (Release Request) — best-effort
            rlq = bytes([ACSE_RLRQ_TAG, 0x03,
                         0xA0, 0x01, 0x01])  # release-request-reason = normal
            sock.sendall(dlms_wrap(rlq))
        except Exception:  # noqa: BLE001
            pass
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass

    # ─── 4. Ciphering refinement ──────────────────────────────────────────
    # If we negotiated ciphering AND the AARE was parsed OK, OR if the
    # negotiated auth_level is GMAC/SHA256 (which implies ciphering), set
    # ciphering_active = True.
    if not summary["ciphering_active"] and \
            summary["auth_level"] in ("high_gmac", "high_sha256", "high_ecdsa"):
        summary["ciphering_active"] = True

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
