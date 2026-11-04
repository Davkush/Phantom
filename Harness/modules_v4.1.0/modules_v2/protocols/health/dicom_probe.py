#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — dicom_probe
# Health sector validation module — DICOM (Digital Imaging and Communications
# in Medicine) probing of PACS / modalities / DICOM routers.
#
#   - Default port : 104 (DICOM)
#   - Functions    : c_echo     (Verification SOP 1.2.840.10008.1.1 → service alive),
#                    c_find_patients (Patient Root 1.2.840.10008.5.1.4.1.2.1.1 →
#                    enumerate patients, filter on CT Image Storage
#                    1.2.840.10008.5.1.4.1.1.2; read patient names tag
#                    (0010,0010) and REDACT to initials),
#                    check_auth (no credentials in A-ASSOCIATE-RQ ⇒ anonymous
#                    binding attempts — true DICOM has no native auth so a
#                    successful C-ECHO without identity binding ⇒ auth_required=False)
#   - Raw socket implementation : full DICOM PDU builder (A-ASSOCIATE-RQ,
#     P-DATA-TF, A-RELEASE-RQ, A-ABORT) + DIMSE Command Set encoder
#     (Explicit VR Little Endian) + C-FIND identifier data set encoder.
#   - READ_ONLY=True (health sector safety constraint) — no C-STORE, no
#     C-MOVE, no image upload. Only C-ECHO (verification) and C-FIND (query)
#     are emitted, both of which are read-only DIMSE operations.
#   - HIPAA note : accessing patient data without auth = direct violation.
#     Patient names are REDACTED to initials before leaving the module.
#   - SEED env var : if set, deterministic message IDs / invoke IDs.
#   - LAB=1 mandatory. 5 s timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (health) : HIPAA, HDS, RGPD, FDA 21 CFR Part 11.
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
    from sector_base import get_sector_config, get_safe_mode, is_write_allowed
    SECTOR_BASE_OK = True
except Exception as exc:  # noqa: BLE001 — standalone fallback
    SECTOR_BASE_OK = False
    _SECTOR_BASE_ERR = str(exc)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "dicom_probe"
DEFAULT_PORT = 104
TIMEOUT_S = 5.0
READ_ONLY = True  # health sector safety constraint (no C-STORE / C-MOVE)

# ─── DICOM constants ──────────────────────────────────────────────────────
# SOP Class UIDs (PS3.4 Annex B / PS3.7 Annex C)
VERIFICATION_SOP_CLASS = "1.2.840.10008.1.1"
# Patient Root Query/Retrieve Information Model – FIND
PATIENT_ROOT_FIND = "1.2.840.10008.5.1.4.1.2.1.1"
# CT Image Storage (used as C-FIND query filter for SOP class)
CT_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.2"

# Transfer Syntax UIDs
EXPLICIT_VR_LE = "1.2.840.10008.1.2.1"
IMPLICIT_VR_LE = "1.2.840.10008.1.2"

# Application Context UID
APP_CONTEXT_UID = "1.2.840.10008.3.1.1.1"

# Implementation UIDs (synthetic, for our probe client)
IMPL_CLASS_UID = "1.2.826.0.1.3680043.9.7000.1.42"
IMPL_VERSION_NAME = "HVHARNESS_300"

# PDU types (PS3.8 §9.3)
PDU_ASSOC_RQ = 0x01
PDU_ASSOC_AC = 0x02
PDU_ASSOC_RJ = 0x03
PDU_PDATA_TF = 0x04
PDU_RELEASE_RQ = 0x05
PDU_RELEASE_RP = 0x06
PDU_ABORT = 0x07

# Item types within A-ASSOCIATE-RQ (PS3.8 §9.3.1)
ITEM_APP_CONTEXT = 0x10
ITEM_PRES_CONTEXT = 0x20          # used in A-ASSOCIATE-RQ
ITEM_PRES_CONTEXT_RESULT = 0x21   # used in A-ASSOCIATE-AC
ITEM_ABSTRACT_SYNTAX = 0x30
ITEM_TRANSFER_SYNTAX = 0x40
ITEM_USER_INFO = 0x50
UI_MAX_LENGTH = 0x51
UI_IMPL_CLASS_UID = 0x52
UI_IMPL_VERSION_NAME = 0x55

# DIMSE Command Field values (PS3.7 §9.3.1, §10.1.1)
CMD_C_ECHO_RQ = 0x0030
CMD_C_ECHO_RSP = 0x8030
CMD_C_FIND_RQ = 0x0020
CMD_C_FIND_RSP = 0x8020

# Command status (PS3.7 §9.1.1.1.9)
STATUS_SUCCESS = 0x0000
STATUS_PENDING = 0xFF00
STATUS_PENDING_WARNING = 0xFF01
STATUS_FAILURE_NO_SUCH_OBJ = 0x0112
STATUS_FAILURE_NOT_AUTHORIZED = 0x0124
STATUS_FAILURE_REFUSED = 0x0120

# DICOM Data Set element tags (group, element) — little-endian in wire form
TAG_COMMAND_GROUP_LENGTH = (0x0000, 0x0000)  # UL, 4
TAG_AFFECTED_SOP_CLASS_UID = (0x0000, 0x0002)  # UI
TAG_REQUESTED_SOP_CLASS_UID = (0x0000, 0x0003)  # UI
TAG_COMMAND_FIELD = (0x0000, 0x0100)  # US, 2
TAG_MESSAGE_ID = (0x0000, 0x0110)  # US, 2
TAG_MESSAGE_ID_RESP = (0x0000, 0x0120)  # US, 2
TAG_DATA_SET_TYPE = (0x0000, 0x0800)  # US, 2  (0x0001 = no dataset)
TAG_STATUS = (0x0000, 0x0900)  # US, 2 (response)
TAG_ERROR_COMMENT = (0x0000, 0x0907)  # LO (response)

# Patient/study identifier tags for C-FIND queries
TAG_PATIENT_NAME = (0x0010, 0x0010)  # PN
TAG_PATIENT_ID = (0x0010, 0x0020)  # LO
TAG_SOP_CLASS_UID = (0x0008, 0x0016)  # UI
TAG_MODALITY = (0x0008, 0x0060)  # CS
TAG_STUDY_DATE = (0x0008, 0x0020)  # DA

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── SEED for deterministic message IDs ────────────────────────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else None
except ValueError:
    SEED = None
_rng = random.Random(SEED) if SEED is not None else random.Random()


def _next_msg_id() -> int:
    """Return a deterministic Message ID (1-65535) for DIMSE commands."""
    return _rng.randint(1, 0xFFFF)


# ─── LAB guard ─────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    """Refuse to run unless LAB=1 is set (isolated lab authorization)."""
    return os.environ.get("LAB") == "1"


# ─── Sector / SAFE_MODE config ─────────────────────────────────────────────
if SECTOR_BASE_OK:
    SECTOR_CFG = get_sector_config()
    SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")
else:
    SECTOR_CFG = {"sector": "health", "safe_mode": "read_only"}
    SAFE_MODE = "read_only"


# ═══════════════════════════════════════════════════════════════════════════
#  DICOM DATA SET ENCODING (Explicit VR Little Endian, PS3.5 §7.1)
# ═══════════════════════════════════════════════════════════════════════════
# VR → (length_field_bytes, is_long_vr)
# Long VRs (OB, OD, OF, OL, OW, SQ, UC, UR, UT, UN): 2 reserved + 4-byte length
# Short VRs (others): 2-byte length
_LONG_VRS = {"OB", "OD", "OF", "OL", "OW", "SQ", "UC", "UR", "UT", "UN"}


def _encode_element(tag: Tuple[int, int], vr: str, value: bytes) -> bytes:
    """Encode a single DICOM element (tag + VR + length + value) in EVR-LE."""
    group, elem = tag
    tag_bytes = struct.pack("<HH", group, elem)
    vr_bytes = vr.encode("ascii", errors="replace").ljust(2)[:2]
    if vr in _LONG_VRS:
        # 2 reserved bytes + 4-byte length (little-endian)
        return tag_bytes + vr_bytes + b"\x00\x00" + struct.pack("<I", len(value)) + value
    else:
        return tag_bytes + vr_bytes + struct.pack("<H", len(value)) + value


def _encode_string_element(tag: Tuple[int, int], vr: str, text: str,
                           pad_to_even: bool = True) -> bytes:
    """Encode a string element. DICOM strings must have even length.

    Per PS3.5 §6.2, UI (Unique Identifier) values are padded with a
    trailing NUL (0x00); all other text VRs (PN, LO, SH, CS, DA, etc.)
    are padded with a trailing SPACE (0x20)."""
    raw = text.encode("ascii", errors="replace")
    if pad_to_even and len(raw) % 2 == 1:
        pad = b"\x00" if vr.upper() == "UI" else b"\x20"
        raw += pad
    return _encode_element(tag, vr, raw)


def _encode_us_element(tag: Tuple[int, int], value: int) -> bytes:
    """Encode an Unsigned Short (US) element."""
    return _encode_element(tag, "US", struct.pack("<H", value & 0xFFFF))


def _encode_ul_element(tag: Tuple[int, int], value: int) -> bytes:
    """Encode an Unsigned Long (UL) element."""
    return _encode_element(tag, "UL", struct.pack("<I", value & 0xFFFFFFFF))


# ═══════════════════════════════════════════════════════════════════════════
#  PDU CONSTRUCTION (PS3.8 §9.3)
# ═══════════════════════════════════════════════════════════════════════════
def _pdu_header(pdu_type: int, data: bytes) -> bytes:
    """Build a PDU: type(1) + reserved(1) + length(4 BE) + data."""
    return struct.pack(">BBI", pdu_type, 0x00, len(data)) + data


def _item(item_type: int, data: bytes) -> bytes:
    """Build a generic PDU item: type(1) + reserved(1) + length(2 BE) + data."""
    return struct.pack(">BBH", item_type, 0x00, len(data)) + data


def _pad_ae_title(title: str) -> bytes:
    """Pad/truncate an AE Title to exactly 16 bytes (space-padded)."""
    b = title.encode("ascii", errors="replace")[:16]
    return b.ljust(16, b"\x20")


def build_a_associate_rq(called_ae: str, calling_ae: str,
                         abstract_syntax: str,
                         transfer_syntaxes: List[str],
                         max_pdu_length: int = 65542) -> bytes:
    """Build an A-ASSOCIATE-RQ PDU (PS3.8 §9.3.1).

    Structure:
      Protocol version (2) + reserved (2) + Called AE (16) + Calling AE (16) +
      reserved (32) + variable items (App Context + Pres Context + User Info)
    """
    # Fixed header (74 bytes after PDU header)
    fixed = struct.pack("<HH", 0x0001, 0x0000)  # protocol version + reserved
    fixed += _pad_ae_title(called_ae)
    fixed += _pad_ae_title(calling_ae)
    fixed += b"\x00" * 32  # reserved

    # Application Context Item
    app_ctx = _item(ITEM_APP_CONTEXT, _encode_uid_padded(APP_CONTEXT_UID))

    # Presentation Context Item (single PC, ID=1)
    # Abstract Syntax sub-item
    abs_syntax = _item(ITEM_ABSTRACT_SYNTAX, _encode_uid_padded(abstract_syntax))
    # Transfer Syntax sub-items (one or more)
    ts_items = b"".join(
        _item(ITEM_TRANSFER_SYNTAX, _encode_uid_padded(ts))
        for ts in transfer_syntaxes
    )
    # Presentation Context Item: PC ID(1) + reserved(1) + reserved(1) + reserved(1) + sub-items
    pres_context_payload = bytes([0x01, 0x00, 0x00, 0x00]) + abs_syntax + ts_items
    pres_context = _item(ITEM_PRES_CONTEXT, pres_context_payload)

    # User Information Item
    max_len_item = struct.pack(">BBHI", UI_MAX_LENGTH, 0x00, 4, max_pdu_length)
    impl_class_item = _item(UI_IMPL_CLASS_UID, _encode_uid_padded(IMPL_CLASS_UID))
    impl_version_item = _item(UI_IMPL_VERSION_NAME, IMPL_VERSION_NAME.encode("ascii"))
    user_info = _item(ITEM_USER_INFO,
                      max_len_item + impl_class_item + impl_version_item)

    body = fixed + app_ctx + pres_context + user_info
    return _pdu_header(PDU_ASSOC_RQ, body)


def _encode_uid_padded(uid: str) -> bytes:
    """Encode a UID, padded to even length with trailing NUL (0x00)."""
    raw = uid.encode("ascii", errors="replace")
    if len(raw) % 2 == 1:
        raw += b"\x00"
    return raw


def build_p_data_tf(pdv: bytes) -> bytes:
    """Build a P-DATA-TF PDU wrapping a single PDV."""
    return _pdu_header(PDU_PDATA_TF, pdv)


def build_pdv(pc_id: int, message_control: int, payload: bytes) -> bytes:
    """Build a PDV item: length(4 BE) + PC ID(1) + msg ctrl header(1) + data."""
    inner = bytes([pc_id & 0xFF, message_control & 0xFF]) + payload
    return struct.pack(">I", len(inner)) + inner


def build_a_release_rq() -> bytes:
    """Build an A-RELEASE-RQ PDU (PS3.8 §9.3.2). Body is 4 reserved bytes."""
    return _pdu_header(PDU_RELEASE_RQ, b"\x00\x00\x00\x00")


def build_a_abort() -> bytes:
    """Build an A-ABORT PDU (PS3.8 §9.3.8). Body = reserved + source + reason."""
    return _pdu_header(PDU_ABORT, b"\x00\x00\x00\x00")


# ═══════════════════════════════════════════════════════════════════════════
#  DIMSE COMMAND SET (PS3.7 §10.1)
# ═══════════════════════════════════════════════════════════════════════════
def build_c_echo_rq(msg_id: int, sop_class_uid: str = VERIFICATION_SOP_CLASS) -> bytes:
    """Build a C-ECHO-RQ command set (EVR-LE), with Command Group Length prefix."""
    # Inner command set elements (excluding the group-length itself)
    inner = (
        _encode_string_element(TAG_AFFECTED_SOP_CLASS_UID, "UI", sop_class_uid)
        + _encode_us_element(TAG_COMMAND_FIELD, CMD_C_ECHO_RQ)
        + _encode_us_element(TAG_MESSAGE_ID, msg_id)
        + _encode_us_element(TAG_DATA_SET_TYPE, 0x0001)  # 0x0001 = no dataset
    )
    # Command Group Length = byte length of `inner`
    cmd_set = _encode_ul_element(TAG_COMMAND_GROUP_LENGTH, len(inner)) + inner
    return cmd_set


def build_c_find_rq(msg_id: int, sop_class_uid: str,
                    identifier: bytes) -> bytes:
    """Build a C-FIND-RQ command set + the identifier data set is sent as a
    SEPARATE P-DATA-TF (command set first with dataset-type=0x0000, then
    identifier data fragments)."""
    inner = (
        _encode_string_element(TAG_AFFECTED_SOP_CLASS_UID, "UI", sop_class_uid)
        + _encode_us_element(TAG_COMMAND_FIELD, CMD_C_FIND_RQ)
        + _encode_us_element(TAG_MESSAGE_ID, msg_id)
        + _encode_us_element(TAG_DATA_SET_TYPE, 0x0000)  # 0x0000 = dataset present
    )
    cmd_set = _encode_ul_element(TAG_COMMAND_GROUP_LENGTH, len(inner)) + inner
    return cmd_set


def build_c_find_identifier(wildcard_keys: List[Tuple[Tuple[int, int], str, str]]) -> bytes:
    """Build the C-FIND identifier data set (the query keys).
    Each entry: (tag, vr, value). Empty value or '*' = match all.
    """
    out = b""
    for tag, vr, value in wildcard_keys:
        out += _encode_string_element(tag, vr, value)
    return out


# ═══════════════════════════════════════════════════════════════════════════
#  PDU / DIMSE PARSING
# ═══════════════════════════════════════════════════════════════════════════
def parse_pdu_header(buf: bytes) -> Tuple[int, int, int]:
    """Parse a 6-byte PDU header → (pdu_type, reserved, length)."""
    if len(buf) < 6:
        raise ValueError("short_pdu_header")
    pdu_type, reserved, length = struct.unpack(">BBI", buf[:6])
    return pdu_type, reserved, length


def parse_command_set(data: bytes) -> Dict[Tuple[int, int], bytes]:
    """Parse a DIMSE command set (EVR-LE) → {tag: raw_value_bytes}."""
    out: Dict[Tuple[int, int], bytes] = {}
    i = 0
    while i + 4 <= len(data):
        group, elem = struct.unpack("<HH", data[i:i + 4])
        tag = (group, elem)
        i += 4
        if i + 2 > len(data):
            break
        vr = data[i:i + 2].decode("ascii", errors="replace")
        i += 2
        if vr in _LONG_VRS:
            i += 2  # reserved
            if i + 4 > len(data):
                break
            length = struct.unpack("<I", data[i:i + 4])[0]
            i += 4
        else:
            if i + 2 > len(data):
                break
            length = struct.unpack("<H", data[i:i + 2])[0]
            i += 2
        if i + length > len(data):
            length = len(data) - i
        out[tag] = data[i:i + length]
        i += length
    return out


def parse_identifier_ds(data: bytes) -> Dict[Tuple[int, int], str]:
    """Parse a C-FIND identifier data set → {tag: value_str}. Strips padding."""
    raw = parse_command_set(data)  # same EVR-LE encoding
    out: Dict[Tuple[int, int], str] = {}
    for tag, val in raw.items():
        try:
            s = val.decode("ascii", errors="replace").rstrip("\x00 ")
        except Exception:
            s = ""
        out[tag] = s
    return out


def _read_n(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from socket (handles partial reads)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _read_pdu(sock: socket.socket) -> Tuple[int, bytes]:
    """Read one complete PDU → (pdu_type, pdu_data)."""
    header = _read_n(sock, 6)
    if len(header) < 6:
        raise OSError("truncated_pdu_header")
    pdu_type, _resv, length = parse_pdu_header(header)
    if length > 16 * 1024 * 1024:  # sanity guard (16 MB)
        raise OSError(f"pdu_too_large:{length}")
    body = _read_n(sock, length) if length > 0 else b""
    return pdu_type, body


def _iter_pdv_items(pdata_body: bytes):
    """Yield (pc_id, mch, payload) for each PDV item in a P-DATA-TF body."""
    i = 0
    while i + 4 <= len(pdata_body):
        pdv_len = struct.unpack(">I", pdata_body[i:i + 4])[0]
        i += 4
        if i + pdv_len > len(pdata_body):
            pdv_len = len(pdata_body) - i
        if pdv_len < 2:
            break
        pc_id = pdata_body[i]
        mch = pdata_body[i + 1]
        payload = pdata_body[i + 2:i + pdv_len]
        yield pc_id, mch, payload
        i += pdv_len


# ═══════════════════════════════════════════════════════════════════════════
#  PHI REDACTION
# ═══════════════════════════════════════════════════════════════════════════
def redact_patient_name(name: str) -> str:
    """Reduce a DICOM patient name (PN) to initials only.

    DICOM PN format: "Lastname^Firstname^Middlename^Prefix^Suffix"
    Components separated by '^'. Within a component, parts are separated
    by '=' (for alphabetic/ideographic/phonetic representations).

    We return at most the first letter of each non-empty component,
    uppercased, joined by spaces. e.g. "DOE^JOHN^Q" → "D J Q".
    Unknown/empty components are skipped. If the whole name is a wildcard
    (e.g. '*' from our query) it is left as-is.
    """
    if not name or name in ("*", ""):
        return name
    # Split on '=' first; take the alphabetic representation (first part)
    alpha = name.split("=", 1)[0]
    parts = alpha.split("^")
    initials = []
    for part in parts:
        p = part.strip()
        if not p:
            continue
        # Take first alphabetic character only
        for ch in p:
            if ch.isalpha():
                initials.append(ch.upper())
                break
    return " ".join(initials) if initials else "[unknown]"


# ═══════════════════════════════════════════════════════════════════════════
#  PROBE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
def c_echo(sock: socket.socket, pc_id: int, msg_id: int) -> Dict:
    """Send a C-ECHO-RQ on the association and read the C-ECHO-RSP.

    Returns: {echo_ok, status, error}
    """
    result = {"echo_ok": False, "status": None, "error": None}
    cmd_set = build_c_echo_rq(msg_id, VERIFICATION_SOP_CLASS)
    # Command set is sent with mch = 0x01 (command + last fragment)
    pdv = build_pdv(pc_id, 0x01, cmd_set)
    sock.sendall(build_p_data_tf(pdv))

    # Read response PDU(s) — should be a P-DATA-TF with the C-ECHO-RSP
    try:
        pdu_type, body = _read_pdu(sock)
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        return result
    except OSError as e:
        result["error"] = f"read_error:{type(e).__name__}"
        return result

    if pdu_type != PDU_PDATA_TF:
        result["error"] = f"unexpected_pdu:0x{pdu_type:02X}"
        return result

    for _pc, mch, payload in _iter_pdv_items(body):
        if mch & 0x01:  # command fragment
            cmd = parse_command_set(payload)
            status_val = cmd.get(TAG_STATUS)
            if status_val is not None and len(status_val) >= 2:
                status = struct.unpack("<H", status_val[:2])[0]
                result["status"] = status
                if status == STATUS_SUCCESS:
                    result["echo_ok"] = True
            else:
                # Could be the response with status in different position
                result["status"] = 0xFFFF
            break
    return result


def c_find_patients(sock: socket.socket, pc_id: int, msg_id: int,
                    max_results: int = 50) -> Dict:
    """Send a C-FIND-RQ on Patient Root and collect pending responses.

    Each pending response carries an identifier data set with patient
    attributes (e.g. (0010,0010) Patient Name). We collect up to
    `max_results` patients, extract the name, and REDACT it to initials.

    Returns: {find_ok, patients_count, patient_names_redacted, status, error}
    """
    result = {
        "find_ok": False,
        "patients_count": 0,
        "patient_names_redacted": [],
        "status": None,
        "error": None,
    }

    # Build the identifier data set (query keys)
    # Wildcard '*' matches any value; empty also matches any.
    identifier = build_c_find_identifier([
        (TAG_PATIENT_NAME, "PN", ""),       # match all patients
        (TAG_PATIENT_ID, "LO", ""),
        (TAG_SOP_CLASS_UID, "UI", CT_IMAGE_STORAGE),  # filter on CT studies
    ])

    # Command set fragment (mch = 0x01, command + last)
    cmd_set = build_c_find_rq(msg_id, PATIENT_ROOT_FIND, identifier)
    pdv_cmd = build_pdv(pc_id, 0x01, cmd_set)
    # Identifier data set fragment (mch = 0x00, data + last)
    pdv_data = build_pdv(pc_id, 0x00, identifier)
    sock.sendall(build_p_data_tf(pdv_cmd))
    sock.sendall(build_p_data_tf(pdv_data))

    collected = 0
    names: List[str] = []
    deadline = time.time() + TIMEOUT_S
    while collected < max_results and time.time() < deadline:
        try:
            pdu_type, body = _read_pdu(sock)
        except (socket.timeout, TimeoutError):
            result["error"] = "timeout" if collected == 0 else None
            break
        except OSError as e:
            result["error"] = f"read_error:{type(e).__name__}"
            break
        if pdu_type != PDU_PDATA_TF:
            result["error"] = f"unexpected_pdu:0x{pdu_type:02X}"
            break

        # Accumulate command + data fragments per PC
        cmd_buf = b""
        data_buf = b""
        for _pc, mch, payload in _iter_pdv_items(body):
            if mch & 0x01:
                cmd_buf += payload
            else:
                data_buf += payload

        if cmd_buf:
            cmd = parse_command_set(cmd_buf)
            status_val = cmd.get(TAG_STATUS)
            status = None
            if status_val is not None and len(status_val) >= 2:
                status = struct.unpack("<H", status_val[:2])[0]
                result["status"] = status

            if status in (STATUS_PENDING, STATUS_PENDING_WARNING):
                # Pending response — the data_buf holds the identifier
                if data_buf:
                    ds = parse_identifier_ds(data_buf)
                    name = ds.get(TAG_PATIENT_NAME, "")
                    names.append(redact_patient_name(name))
                    collected += 1
                # Continue reading more pending responses
            elif status == STATUS_SUCCESS:
                result["find_ok"] = True
                break
            else:
                # Failure or other status
                if status in (STATUS_FAILURE_REFUSED, STATUS_FAILURE_NOT_AUTHORIZED):
                    result["error"] = f"access_denied:0x{status:04X}"
                elif status is not None:
                    result["error"] = f"find_failed:0x{status:04X}"
                break

    result["patients_count"] = collected
    result["patient_names_redacted"] = names
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  ASSOCIATION LIFECYCLE
# ═══════════════════════════════════════════════════════════════════════════
def open_association(host: str, port: int, called_ae: str = "ANYSCP",
                     calling_ae: str = "HVHARNESS",
                     abstract_syntax: str = VERIFICATION_SOP_CLASS,
                     transfer_syntaxes: Optional[List[str]] = None
                     ) -> Optional[Dict]:
    """Open a DICOM association. Returns a dict with the socket + accepted PC
    info, or None on failure."""
    if transfer_syntaxes is None:
        transfer_syntaxes = [EXPLICIT_VR_LE, IMPLICIT_VR_LE]
    result = {
        "sock": None,
        "pc_id": None,
        "accepted": False,
        "reject_reason": None,
        "error": None,
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_S)
        sock.connect((host, port))
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        return result

    result["sock"] = sock
    rq = build_a_associate_rq(called_ae, calling_ae, abstract_syntax,
                              transfer_syntaxes)
    try:
        sock.sendall(rq)
        pdu_type, body = _read_pdu(sock)
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        return result
    except OSError as e:
        result["error"] = f"read_error:{type(e).__name__}"
        return result

    if pdu_type == PDU_ASSOC_AC:
        # Parse accepted presentation contexts — find our PC ID
        # Body layout: protocol version(2) + reserved(2) + Called AE(16) +
        # Calling AE(16) + reserved(32) + variable items
        # In AC, the Presentation Context Definition Result List item is
        # type 0x21 (PS3.8 §9.3.2). Each result entry:
        #   PC ID(1) + Result(1) + Reserved(1) + Transfer Syntax sub-item
        # Result = 0 (acceptance), 1 (user-rejection), 2 (provider-rejection),
        #          3 (abstract-syntax-not-supported),
        #          4 (transfer-syntaxes-not-supported)
        idx = 2 + 2 + 16 + 16 + 32  # skip fixed header (68 bytes)
        while idx + 4 <= len(body):
            item_type = body[idx]
            item_len = struct.unpack(">H", body[idx + 2:idx + 4])[0]
            item_body = body[idx + 4:idx + 4 + item_len]
            if item_type in (ITEM_PRES_CONTEXT_RESULT, ITEM_PRES_CONTEXT) \
                    and len(item_body) >= 3:
                pc_id = item_body[0]
                # In AC result item: byte 0 = PC ID, byte 1 = result, byte 2 = reserved
                # (In RQ item 0x20: byte 0 = PC ID, bytes 1-3 = reserved)
                pres_result = item_body[1] if item_type == ITEM_PRES_CONTEXT_RESULT \
                    else item_body[2]
                if pres_result == 0:  # acceptance
                    result["pc_id"] = pc_id
                    result["accepted"] = True
                    return result
            idx += 4 + item_len
        result["error"] = "no_accepted_pc"
        return result
    elif pdu_type == PDU_ASSOC_RJ:
        # Body: result(1) + source(1) + reason(1)
        if len(body) >= 3:
            result["reject_reason"] = f"r{body[0]}_s{body[1]}_c{body[2]}"
        else:
            result["reject_reason"] = "unknown"
        return result
    elif pdu_type == PDU_ABORT:
        result["reject_reason"] = "abort"
        return result
    else:
        result["error"] = f"unexpected_pdu:0x{pdu_type:02X}"
        return result


def close_association(sock: socket.socket) -> None:
    """Send A-RELEASE-RQ and read A-RELEASE-RP, then close the socket.
    Falls back to A-ABORT if anything goes wrong (best-effort cleanup)."""
    if sock is None:
        return
    try:
        sock.sendall(build_a_release_rq())
        try:
            _read_pdu(sock)  # expect A-RELEASE-RP (0x06)
        except Exception:
            pass
    except Exception:
        try:
            sock.sendall(build_a_abort())
        except Exception:
            pass
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("DICOM probing on production PACS/modalities is "
                           "illegal outside an authorized lab. HIPAA / HDS."),
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
        "dicom_accessible": False,
        "patients_accessible": 0,
        "patient_names_redacted": [],
        "auth_required": None,
        # Extra diagnostic fields:
        "echo_ok": False,
        "echo_status": None,
        "find_status": None,
        "errors": [],
    }

    # ─── 1. Open association with Verification SOP (C-ECHO) ──────────────
    assoc = open_association(
        HOST, PORT,
        called_ae="ANYSCP",
        calling_ae="HVHARNESS",
        abstract_syntax=VERIFICATION_SOP_CLASS,
        transfer_syntaxes=[EXPLICIT_VR_LE, IMPLICIT_VR_LE],
    )
    if assoc is None or assoc.get("sock") is None:
        summary["errors"].append(f"assoc_failed:{assoc.get('error') if assoc else 'none'}")
        summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
        print(json.dumps(summary, indent=2, default=str))
        return

    sock = assoc["sock"]
    if not assoc.get("accepted"):
        # Association rejected or aborted
        reason = assoc.get("reject_reason") or assoc.get("error") or "rejected"
        summary["errors"].append(f"assoc_rejected:{reason}")
        # If rejected for security/policy reasons, auth may be required
        summary["auth_required"] = ("rejected" in reason.lower()
                                    or "refused" in reason.lower())
        close_association(sock)
        summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
        print(json.dumps(summary, indent=2, default=str))
        return

    # Association accepted ⇒ DICOM listener is accessible AND no auth was
    # required to bind (DICOM A-ASSOCIATE carries no credentials).
    summary["dicom_accessible"] = True
    summary["auth_required"] = False
    pc_id = assoc["pc_id"] or 1

    # ─── 2. C-ECHO (Verification) ────────────────────────────────────────
    try:
        echo_id = _next_msg_id()
        er = c_echo(sock, pc_id, echo_id)
        summary["echo_ok"] = bool(er.get("echo_ok"))
        summary["echo_status"] = er.get("status")
        if er.get("error"):
            summary["errors"].append(f"c_echo:{er['error']}")
    except Exception as e:
        summary["errors"].append(f"c_echo:{type(e).__name__}:{e}")

    # ─── 3. Re-open association for C-FIND with Patient Root ─────────────
    # DICOM allows a single abstract syntax per presentation context, but
    # one association can carry multiple PCs. For simplicity we close and
    # reopen with the Patient Root QR model as the abstract syntax.
    close_association(sock)

    assoc2 = open_association(
        HOST, PORT,
        called_ae="ANYSCP",
        calling_ae="HVHARNESS",
        abstract_syntax=PATIENT_ROOT_FIND,
        transfer_syntaxes=[EXPLICIT_VR_LE, IMPLICIT_VR_LE],
    )
    if assoc2 and assoc2.get("accepted") and assoc2.get("sock"):
        sock2 = assoc2["sock"]
        pc_id2 = assoc2["pc_id"] or 1
        try:
            find_id = _next_msg_id()
            fr = c_find_patients(sock2, pc_id2, find_id, max_results=50)
            summary["patients_accessible"] = int(fr.get("patients_count", 0))
            summary["patient_names_redacted"] = fr.get("patient_names_redacted", [])
            summary["find_status"] = fr.get("status")
            if fr.get("error"):
                # Access-denied ⇒ auth required for patient data
                if "access_denied" in str(fr["error"]):
                    summary["auth_required"] = True
                summary["errors"].append(f"c_find:{fr['error']}")
        except Exception as e:
            summary["errors"].append(f"c_find:{type(e).__name__}:{e}")
        finally:
            close_association(sock2)
    else:
        # Patient Root not accepted — likely the SCP only supports Verification
        reason = (assoc2.get("reject_reason") if assoc2 else None) \
                 or (assoc2.get("error") if assoc2 else None) or "rejected"
        summary["errors"].append(f"patient_root_assoc_failed:{reason}")
        if "rejected" in str(reason).lower() or "refused" in str(reason).lower():
            summary["auth_required"] = True

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
