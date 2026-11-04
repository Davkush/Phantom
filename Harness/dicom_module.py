#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — DICOM probe (health sector).
# Phase 2 reconnaissance against DICOM (Digital Imaging and Communications
# in Medicine) endpoints — typically PACS / modalities / DICOM routers.
#
# Goals:
#   - C-ECHO  (Verification SOP)       — confirm DICOM listener alive
#   - C-FIND  Patient Root             — enumerate patients (PHI leak check)
#   - C-FIND  Study Root               — enumerate studies by date range
#   - C-MOVE  (Storage SOP)            — check whether image exfiltration is allowed
#   - C-STORE (Storage Commitment)     — gated behind SAFE_MODE=full (would upload a
#     modified image; in read-only health sector this is refused by default)
#
# Safety:
#   - LAB=1 guard — refuses to run outside an explicit lab environment
#   - SAFE_MODE=read_only for the health sector (cf. sector_base._SAFE_MODE) —
#     no C-STORE / no upload of modified images
#   - 5s socket timeout on every connection
#   - PHI masking: patient names / IDs / accession numbers are NEVER echoed
#     to stdout — only COUNTS are reported (de-identification by reduction)
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# HIPAA / HDS / RGPD — toute opération d'écriture sur un dispositif médical
# peut avoir des conséquences cliniques ; ce module reste strictement read-only.
import json
import os
import socket
import struct
import sys
import time
from typing import Optional

# Make sector_base importable when this module is run directly as a script
# (it lives two directories above sectors/health/).
_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULES_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _MODULES_ROOT not in sys.path:
    sys.path.insert(0, _MODULES_ROOT)

try:
    from sector_base import get_sector_config, get_safe_mode, is_write_allowed
    SECTOR_BASE_OK = True
except Exception as exc:  # noqa: BLE001 — fall back gracefully if used standalone
    SECTOR_BASE_OK = False
    _SECTOR_BASE_ERR = str(exc)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "dicom_probe"
DEFAULT_TIMEOUT = 5  # seconds — required by sector policy

# ─── DICOM constants ────────────────────────────────────────────────
DICOM_DEFAULT_PORT = 104
DICOM_ALT_PORT = 111

# SOP Class UIDs (PS3.4 Annex B / PS3.7 Annex C)
VERIFICATION_SOP_CLASS = "1.2.840.10008.1.1"
# Patient Root Query/Retrieve Information Model – FIND
PATIENT_ROOT_FIND = "1.2.840.10008.5.1.4.1.2.1.1"
# Patient Root Query/Retrieve Information Model – MOVE
PATIENT_ROOT_MOVE = "1.2.840.10008.5.1.4.1.2.1.2"
# Study Root Query/Retrieve Information Model – FIND
STUDY_ROOT_FIND = "1.2.840.10008.5.1.4.1.2.2.1"
# Study Root Query/Retrieve Information Model – MOVE
STUDY_ROOT_MOVE = "1.2.840.10008.5.1.4.1.2.2.2"
# Storage Commitment Push Model SOP Class
STORAGE_COMMITMENT_SOP = "1.2.840.10008.1.20.1"
# CT Image Storage (used as the abstract syntax when requesting C-STORE)
CT_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.2"

# DICOM Transfer Syntaxes
IMPLICIT_LITTLE_ENDIAN = "1.2.840.10008.1.2"
EXPLICIT_LITTLE_ENDIAN = "1.2.840.10008.1.2.1"
# Application Context UID (DICOM Application Context Name v3.0)
APP_CONTEXT = "1.2.840.10008.3.1.1.1"

# PDU types (PS3.8 §9.3 / §10.1)
PDU_A_ASSOCIATE_RQ = 0x01
PDU_A_ASSOCIATE_AC = 0x02
PDU_A_ASSOCIATE_RJ = 0x03
PDU_P_DATA_TF = 0x04
PDU_A_RELEASE_RQ = 0x05
PDU_A_RELEASE_RP = 0x06
PDU_A_ABORT = 0x07

# DIMSE Command Field values (PS3.7 §9.1.1 / §10.1.1)
DIMSE_C_ECHO_RQ = 0x0030
DIMSE_C_ECHO_RSP = 0x8030
DIMSE_C_FIND_RQ = 0x0010
DIMSE_C_FIND_RSP = 0x8010
DIMSE_C_MOVE_RQ = 0x0021
DIMSE_C_MOVE_RSP = 0x8021
DIMSE_C_STORE_RQ = 0x0001
DIMSE_C_STORE_RSP = 0x8001

# DIMSE Status codes (PS3.7 Annex C)
STATUS_SUCCESS = 0x0000
STATUS_PENDING = 0xFF00
STATUS_REFUSED = 0xA700  # Out of resources
STATUS_FAILED_UNABLE_TO_PROCESS = 0xC000

# Tag keys (group, element) — used for parsing raw DIMSE responses
TAG_COMMAND_FIELD = (0x0000, 0x0002)
TAG_AFFECTED_SOP_CLASS = (0x0000, 0x0003)
TAG_MESSAGE_ID = (0x0000, 0x0010)
TAG_DATA_SET_TYPE = (0x0000, 0x0100)
TAG_STATUS = (0x0000, 0x0900)
TAG_AFFECTED_SOP_INSTANCE = (0x0000, 0x1000)
# Data set tags (returned by C-FIND)
TAG_PATIENT_NAME = (0x0010, 0x0010)
TAG_PATIENT_ID = (0x0010, 0x0020)
TAG_STUDY_INSTANCE_UID = (0x0020, 0x000D)
TAG_STUDY_DATE = (0x0008, 0x0020)
TAG_ACCESSION_NUMBER = (0x0008, 0x0050)
TAG_MODALITY = (0x0008, 0x0060)

VR_LENGTHS = {
    "AE": 2, "AS": 2, "AT": 4, "CS": 2, "DA": 2, "DS": 2, "DT": 2, "FL": 4,
    "FD": 8, "IS": 2, "LO": 2, "LT": 2, "PN": 2, "SH": 2, "SL": 4, "SS": 2,
    "ST": 2, "TM": 2, "UI": 2, "UL": 4, "UN": 2, "US": 2,
}

# ─── Optional pydicom binding ───────────────────────────────────────
try:
    from pydicom import UID  # noqa: F401
    import pydicom
    from pydicom.dataset import Dataset
    from pydicom._globals import DEFAULT_TRANSFER_SYNTAX as _PYDICOM_TS
    try:
        # pynetdicom provides a real DIMSE client — preferred when available
        from pynetdicom import AE, evt
        from pynetdicom.sop_class import (
            Verification as _VerificationSC,
            PatientRootFind as _PatientRootFind,
            StudyRootFind as _StudyRootFind,
            PatientRootMove as _PatientRootMove,
            StudyRootMove as _StudyRootMove,
        )
        PYNETDICOM_OK = True
    except Exception:  # noqa: BLE001
        PYNETDICOM_OK = False
    PYDICOM_OK = True
except Exception:  # noqa: BLE001 — pydicom is optional
    PYDICOM_OK = False
    PYNETDICOM_OK = False

# ─── CLI args ───────────────────────────────────────────────────────
# Usage:  dicom_module.py [HOST [PORT [CALLED_AE [CALLING_AE]]]]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DICOM_HOST", "127.0.0.1")
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("DICOM_PORT", str(DICOM_DEFAULT_PORT)))
CALLED_AE = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("DICOM_CALLED_AE", "ANYSCP")
CALLING_AE = sys.argv[4] if len(sys.argv) > 4 else os.environ.get("DICOM_CALLING_AE", "HARNESSDCM")


# ─── LAB guard ──────────────────────────────────────────────────────
def lab_guard() -> bool:
    """Refuse to run unless LAB=1 is set in the environment."""
    return os.environ.get("LAB") == "1"


# ─── PHI masking helpers ────────────────────────────────────────────
def _mask_phi(text: Optional[str]) -> str:
    """Replace any PHI-like content with a placeholder. We never echo
    patient names, IDs, accession numbers, or study instance UIDs."""
    if not text:
        return ""
    return "[REDACTED-PHI]"


# ─── Raw-socket DICOM PDU builders ──────────────────────────────────
def _pdu_header(pdu_type: int, payload: bytes) -> bytes:
    """Build the 6-byte PDU header (type, reserved, uint32 BE length)."""
    return struct.pack(">BBI", pdu_type, 0x00, len(payload)) + payload


def _padded_ae(title: str) -> bytes:
    """AE titles are 16 bytes, padded with spaces."""
    b = title.encode("ascii", errors="replace")[:16]
    return b.ljust(16, b" ")


def _item(item_type: int, content: bytes) -> bytes:
    """Generic variable item: (type, reserved, uint16 BE length, content)."""
    return struct.pack(">BBH", item_type, 0x00, len(content)) + content


def build_a_associate_rq(called_ae: str, calling_ae: str,
                         abstract_syntaxes, transfer_syntaxes) -> bytes:
    """Build an A-ASSOCIATE-RQ PDU (PS3.8 §9.3.1).

    abstract_syntaxes : list[str]   — SOP Class UIDs to present
    transfer_syntaxes : list[str]   — accepted transfer syntaxes
    """
    # 1. Application Context Item (type 0x10)
    app_ctx_item = _item(0x10, APP_CONTEXT.encode("ascii"))

    # 2. Presentation Context Items (type 0x20): one per abstract syntax
    pres_items = b""
    for i, abs_syntax in enumerate(abstract_syntaxes):
        # Presentation Context Item body:
        #   - Presentation Context ID (1 byte, odd, 1..255)
        #   - Reserved (1 byte)
        #   - Abstract Syntax Sub-item (type 0x30) : 4-byte header + UID
        #   - Transfer Syntax Sub-items (type 0x40): 4-byte header + UID
        pc_id = (i * 2) + 1
        abs_item = _item(0x30, abs_syntax.encode("ascii"))
        ts_payload = b"".join(
            _item(0x40, ts.encode("ascii")) for ts in transfer_syntaxes
        )
        pc_body = struct.pack(">BB", pc_id, 0x00) + abs_item + ts_payload
        pres_items += _item(0x20, pc_body)

    # 3. User Information Item (type 0x50) — minimal:
    #    Maximum Length Received Sub-item (type 0x51, 4 bytes BE)
    max_length = 0x10000  # 64 KiB receive window
    user_info = _item(0x51, struct.pack(">I", max_length))
    user_info_item = _item(0x50, user_info)

    # 4. Variable items concatenate
    variable = app_ctx_item + pres_items + user_info_item

    # 5. Fixed PDU body: protocol version (2 BE), reserved (2), called AE (16),
    #    calling AE (16), reserved (32)
    fixed = struct.pack(">HH", 0x0001, 0x0000) + _padded_ae(called_ae) \
        + _padded_ae(calling_ae) + b"\x00" * 32

    return _pdu_header(PDU_A_ASSOCIATE_RQ, fixed + variable)


def build_p_data_tf(pc_id: int, payload: bytes, last: bool = True) -> bytes:
    """Build a P-DATA-TF PDU (PS3.8 §9.3.5).

    A P-DATA-TF carries one or more Presentation Data Value (PDV) items:
      - Presentation Context ID (1 byte)
      - Message Control Header (1 byte) — bit 0 = command/data,
        bit 1 = last fragment of a DIMSE message
      - PDV payload (variable)
    """
    pdv = struct.pack(">BB", pc_id, (0x01 if last else 0x00) | 0x02)
    # 0x02 = command set; |0x01 = last fragment
    pdv_full = pdv + payload
    # PDV item length is uint32 BE
    pdv_item = struct.pack(">I", len(pdv_full)) + pdv_full
    return _pdu_header(PDU_P_DATA_TF, pdv_item)


def _dimse_command_set(fields: dict) -> bytes:
    """Encode a DIMSE command set as Implicit VR Little Endian (PS3.7 §10.1).

    fields : dict[(group, element)] -> (VR, int or str)
    """
    # Sort by tag — command set elements must be in ascending order
    out = b""
    for (grp, elm), (vr, value) in sorted(fields.items()):
        out += struct.pack("<HH", grp, elm)  # tag LE
        out += vr.encode("ascii", errors="replace")
        if vr in ("AE", "AS", "CS", "DA", "DS", "DT", "IS", "LO", "LT",
                  "PN", "SH", "ST", "TM", "UI", "UN"):
            text = str(value).encode("ascii", errors="replace")
            if vr in ("UI", "AE"):
                # pad to even length with NUL
                if len(text) % 2:
                    text += b"\x00"
            out += struct.pack("<H", len(text)) + text
        elif vr in ("US", "SS", "AT"):
            out += struct.pack("<H", 2) + struct.pack("<H", int(value))
        elif vr in ("UL", "SL", "FL"):
            out += struct.pack("<H", 4) + struct.pack("<I", int(value))
        else:
            text = str(value).encode("ascii", errors="replace")
            out += struct.pack("<H", len(text)) + text
    return out


# ─── Raw-socket DICOM transport ─────────────────────────────────────
class RawDicomAssoc:
    """Minimal A-ASSOCIATE lifecycle over a raw TCP socket.

    Only the operations needed by this probe are implemented:
    associate → send C-ECHO/C-FIND/C-MOVE → release.
    """

    def __init__(self, host: str, port: int, called_ae: str, calling_ae: str,
                 abstract_syntaxes, transfer_syntaxes, timeout: int = DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.called_ae = called_ae
        self.calling_ae = calling_ae
        self.abstract_syntaxes = abstract_syntaxes
        self.transfer_syntaxes = transfer_syntaxes
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.accepted_pc: dict[int, str] = {}  # pc_id -> abstract_syntax

    def __enter__(self) -> "RawDicomAssoc":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def connect(self) -> bool:
        try:
            self.sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            )
            self.sock.settimeout(self.timeout)
        except (socket.timeout, ConnectionRefusedError, OSError):
            self.sock = None
            return False
        # Send A-ASSOCIATE-RQ
        rq = build_a_associate_rq(
            self.called_ae, self.calling_ae,
            self.abstract_syntaxes, self.transfer_syntaxes,
        )
        try:
            self.sock.sendall(rq)
        except OSError:
            self.close()
            return False
        # Read A-ASSOCIATE-AC (or RJ)
        pdu_type, payload = self._recv_pdu()
        if pdu_type != PDU_A_ASSOCIATE_AC:
            self.close()
            return False
        # Parse accepted presentation contexts
        self._parse_ac(payload)
        return bool(self.accepted_pc)

    def _recv_pdu(self):
        """Read one full PDU. Returns (type, payload)."""
        assert self.sock is not None
        try:
            header = self._recv_n(6)
        except OSError:
            return (-1, b"")
        if len(header) < 6:
            return (-1, b"")
        pdu_type, _reserved, length = struct.unpack(">BBI", header)
        payload = self._recv_n(length) if length else b""
        return (pdu_type, payload)

    def _recv_n(self, n: int) -> bytes:
        assert self.sock is not None
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _parse_ac(self, payload: bytes) -> None:
        """Extract accepted Presentation Context IDs from A-ASSOCIATE-AC.

        AC body layout (PS3.8 §9.3.2):
          - protocol version (2 BE)
          - reserved (2)
          - called AE (16)
          - calling AE (16)
          - reserved (32)
          - variable items: Application Context + Presentation Context (result)
            + User Information
        Presentation Context Item (AC) body:
          - PC ID (1), reserved (1), result (1), reserved (1), Abstract/TS sub-items
        Result codes: 0=acceptance, 1=user-reject, 2=provider-reject, 3=abstract
        syntax not supported, 4=transfer syntax not supported.
        """
        if len(payload) < 74:
            return
        offset = 74  # fixed part = 2+2+16+16+32 = 68... actually 68; +6 fixed
        # Fixed part is: protocol_version(2) + reserved(2) + called(16) + calling(16)
        #               + reserved(32) = 68 bytes
        offset = 68
        while offset + 4 <= len(payload):
            item_type = payload[offset]
            item_len = struct.unpack(">H", payload[offset + 2:offset + 4])[0]
            item_body = payload[offset + 4: offset + 4 + item_len]
            if item_type == 0x21 and len(item_body) >= 4:  # Presentation Context (AC)
                pc_id = item_body[0]
                result = item_body[2]
                # Find abstract syntax inside the sub-items
                sub_off = 4
                abs_syntax = ""
                while sub_off + 4 <= len(item_body):
                    sub_type = item_body[sub_off]
                    sub_len = struct.unpack(">H", item_body[sub_off + 2:sub_off + 4])[0]
                    sub_body = item_body[sub_off + 4: sub_off + 4 + sub_len]
                    if sub_type == 0x31:  # Abstract Syntax Sub-item (AC)
                        abs_syntax = sub_body.decode("ascii", errors="replace").rstrip("\x00 ")
                    if sub_type == 0x40:  # Transfer Syntax Sub-item (AC)
                        ts_syntax = sub_body.decode("ascii", errors="replace").rstrip("\x00 ")
                        if result == 0:
                            self.accepted_pc[pc_id] = abs_syntax
                    sub_off += 4 + sub_len
            offset += 4 + item_len

    def send_command(self, pc_id: int, command_set: bytes) -> bool:
        """Send a DIMSE command set as a P-DATA-TF."""
        if not self.sock:
            return False
        pdu = build_p_data_tf(pc_id, command_set, last=True)
        try:
            self.sock.sendall(pdu)
            return True
        except OSError:
            return False

    def recv_pdv(self):
        """Read PDVs until we have a complete DIMSE message (last-flag set).

        Returns (status_code, data_set_bytes) or (None, b"").
        """
        if not self.sock:
            return (None, b"")
        status = None
        data_set = b""
        while True:
            pdu_type, payload = self._recv_pdu()
            if pdu_type == -1:
                return (None, b"")
            if pdu_type == PDU_A_RELEASE_RP:
                return (status, data_set)
            if pdu_type == PDU_A_ABORT:
                return (None, b"")
            if pdu_type != PDU_P_DATA_TF:
                # Unknown — bail
                return (status, data_set)
            # Parse PDV items
            off = 0
            while off + 4 <= len(payload):
                pdv_len = struct.unpack(">I", payload[off:off + 4])[0]
                pdv = payload[off + 4: off + 4 + pdv_len]
                if len(pdv) < 2:
                    break
                # pc_id = pdv[0]; msg_ctrl = pdv[1]
                msg_ctrl = pdv[1]
                fragment = pdv[2:]
                if msg_ctrl & 0x02:  # command set
                    status = _extract_status(fragment)
                else:                # data set
                    data_set += fragment
                if msg_ctrl & 0x01:  # last fragment
                    return (status, data_set)
                off += 4 + pdv_len
            if off == 0:
                return (status, data_set)


def _extract_status(command_set: bytes) -> Optional[int]:
    """Walk an Implicit VR LE command set and pull (0000,0900) Status."""
    off = 0
    while off + 8 <= len(command_set):
        grp, elm = struct.unpack("<HH", command_set[off:off + 4])
        vr = command_set[off + 4:off + 6].decode("ascii", errors="replace")
        if vr in ("OB", "OW", "SQ", "UN"):
            length = struct.unpack("<I", command_set[off + 8:off + 12])[0]
            value = command_set[off + 12:off + 12 + length]
            off += 12 + length
        else:
            length = struct.unpack("<H", command_set[off + 6:off + 8])[0]
            value = command_set[off + 8:off + 8 + length]
            off += 8 + length
        if (grp, elm) == TAG_STATUS:
            try:
                return int.from_bytes(value[:2], "little")
            except Exception:  # noqa: BLE001
                return None
    return None


def _parse_find_dataset(data_set: bytes) -> int:
    """Parse an Explicit/Implicit VR LE data set returned by a C-FIND
    response and return the number of distinct records (one per C-FIND
    response payload). We DO NOT extract patient names — only count.

    Each C-FIND response is a separate DIMSE message with its own status
    (Pending / Success). The caller already separates messages; this
    helper counts the patient-name tags inside a single message.
    """
    if not data_set:
        return 0
    # For an Implicit VR LE data set we walk tags until exhausted.
    count = 0
    off = 0
    has_patient_name = False
    while off + 4 <= len(data_set):
        grp, elm = struct.unpack("<HH", data_set[off:off + 4])
        # Implicit VR: VR is not stored; length is uint32 LE
        if off + 8 > len(data_set):
            break
        length = struct.unpack("<I", data_set[off + 4:off + 8])[0]
        if off + 8 + length > len(data_set):
            break
        if (grp, elm) == TAG_PATIENT_NAME:
            has_patient_name = True
        elif (grp, elm) == TAG_STUDY_INSTANCE_UID:
            # A new study indicates a separate C-FIND response — but since
            # we receive one PDV per message, this is informational only.
            pass
        off += 8 + length
        # Sequence delimiters
        if (grp, elm) in ((0xFFFE, 0xE0DD), (0xFFFE, 0xE00D)):
            break
    return 1 if has_patient_name else 0


# ─── Probe operations ───────────────────────────────────────────────
def c_echo(host: str, port: int, called_ae: str, calling_ae: str,
           timeout: int = DEFAULT_TIMEOUT) -> dict:
    """C-ECHO (Verification SOP) — ping the DICOM server."""
    result = {"c_echo_ok": False, "detail": ""}
    if PYNETDICOM_OK:
        try:
            ae = AE(ae_title=calling_ae.encode("ascii"))
            ae.add_requested_context(VERIFICATION_SOP_CLASS)
            assoc = ae.associate(host, port)
            if assoc.is_established:
                try:
                    rsp = assoc.send_c_echo()
                    result["c_echo_ok"] = (rsp.Status == STATUS_SUCCESS)
                    result["detail"] = f"pydicom status=0x{rsp.Status:04X}"
                finally:
                    assoc.release()
            else:
                result["detail"] = "association rejected/aborted (pydicom)"
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"pydicom error: {exc}"
        return result
    # Raw socket fallback
    with RawDicomAssoc(host, port, called_ae, calling_ae,
                       [VERIFICATION_SOP_CLASS],
                       [IMPLICIT_LITTLE_ENDIAN, EXPLICIT_LITTLE_ENDIAN],
                       timeout=timeout) as assoc:
        if not assoc.accepted_pc:
            result["detail"] = "A-ASSOCIATE-RJ or refused"
            return result
        pc_id = next(iter(assoc.accepted_pc))
        cs = _dimse_command_set({
            TAG_COMMAND_FIELD: ("US", DIMSE_C_ECHO_RQ),
            TAG_AFFECTED_SOP_CLASS: ("UI", VERIFICATION_SOP_CLASS),
            TAG_MESSAGE_ID: ("US", 1),
            TAG_DATA_SET_TYPE: ("US", 0x0101),  # no data set
        })
        if not assoc.send_command(pc_id, cs):
            result["detail"] = "send P-DATA-TF failed"
            return result
        status, _ = assoc.recv_pdv()
        try:
            assoc.send_command(pc_id, b"")  # best-effort A-RELEASE
        except Exception:  # noqa: BLE001
            pass
        result["c_echo_ok"] = (status == STATUS_SUCCESS)
        result["detail"] = f"raw socket status={status}"
    return result


def c_find_patient(host: str, port: int, called_ae: str, calling_ae: str,
                   timeout: int = DEFAULT_TIMEOUT) -> dict:
    """C-FIND Patient Root — search by patient name '*' and count records.

    PHI masking: only the COUNT of returned patients is reported, never
    the names themselves.
    """
    result = {"patients_listed": 0, "phi_exposed": False, "detail": ""}
    if PYNETDICOM_OK:
        try:
            ae = AE(ae_title=calling_ae.encode("ascii"))
            ae.add_requested_context(PATIENT_ROOT_FIND)
            assoc = ae.associate(host, port)
            if assoc.is_established:
                try:
                    ds = Dataset()
                    ds.PatientName = "*"
                    ds.PatientID = ""
                    responses = assoc.send_c_find(ds, PATIENT_ROOT_FIND)
                    count = 0
                    for _status, _ds in responses:
                        if _status and _status.Status in (STATUS_PENDING, STATUS_SUCCESS):
                            count += 1
                    result["patients_listed"] = count
                    # PHI exposed = any patient record returned without auth
                    result["phi_exposed"] = count > 0
                    result["detail"] = f"pydicom count={count}"
                finally:
                    assoc.release()
            else:
                result["detail"] = "association rejected"
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"pydicom error: {exc}"
        return result
    # Raw socket fallback — issue C-FIND-RQ with PatientName='*'
    with RawDicomAssoc(host, port, called_ae, calling_ae,
                       [PATIENT_ROOT_FIND],
                       [IMPLICIT_LITTLE_ENDIAN],
                       timeout=timeout) as assoc:
        if not assoc.accepted_pc:
            result["detail"] = "association refused"
            return result
        pc_id = next(iter(assoc.accepted_pc))
        # Build identifier data set (Implicit VR LE) with PatientName='*'
        identifier = _build_implicit_vr_dataset({
            TAG_PATIENT_NAME: "*",
            TAG_PATIENT_ID: "",
        })
        # Command set
        cs = _dimse_command_set({
            TAG_COMMAND_FIELD: ("US", DIMSE_C_FIND_RQ),
            TAG_AFFECTED_SOP_CLASS: ("UI", PATIENT_ROOT_FIND),
            TAG_MESSAGE_ID: ("US", 2),
            TAG_DATA_SET_TYPE: ("US", 0x0001),  # data set present
        })
        # Send command (last=1), then data set (last=1)
        pdu_cmd = build_p_data_tf(pc_id, cs, last=True)
        # For the data set, Message Control Header bit 0 (command/data) = 0
        pdu_data = _build_data_pdv(pc_id, identifier)
        if not assoc.sock:
            return result
        try:
            assoc.sock.sendall(pdu_cmd)
            assoc.sock.sendall(pdu_data)
        except OSError as exc:
            result["detail"] = f"send error: {exc}"
            return result
        # Read responses — each pending response is a separate DIMSE message
        count = 0
        for _ in range(64):  # safety cap
            status, data_set = assoc.recv_pdv()
            if status is None:
                break
            if status in (STATUS_PENDING, 0xFF01):
                count += _parse_find_dataset(data_set)
            elif status == STATUS_SUCCESS:
                break
            else:
                break
        result["patients_listed"] = count
        result["phi_exposed"] = count > 0
        result["detail"] = f"raw socket count={count}"
    return result


def c_find_study(host: str, port: int, called_ae: str, calling_ae: str,
                 timeout: int = DEFAULT_TIMEOUT) -> dict:
    """C-FIND Study Root — search by StudyDate range (broad wildcard)."""
    result = {"studies_listed": 0, "detail": ""}
    if PYNETDICOM_OK:
        try:
            ae = AE(ae_title=calling_ae.encode("ascii"))
            ae.add_requested_context(STUDY_ROOT_FIND)
            assoc = ae.associate(host, port)
            if assoc.is_established:
                try:
                    ds = Dataset()
                    ds.StudyDate = "19000101-20301231"
                    ds.PatientName = ""
                    ds.PatientID = ""
                    responses = assoc.send_c_find(ds, STUDY_ROOT_FIND)
                    count = 0
                    for _status, _ds in responses:
                        if _status and _status.Status in (STATUS_PENDING, STATUS_SUCCESS):
                            count += 1
                    result["studies_listed"] = count
                    result["detail"] = f"pydicom count={count}"
                finally:
                    assoc.release()
            else:
                result["detail"] = "association rejected"
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"pydicom error: {exc}"
        return result
    # Raw socket fallback
    with RawDicomAssoc(host, port, called_ae, calling_ae,
                       [STUDY_ROOT_FIND],
                       [IMPLICIT_LITTLE_ENDIAN],
                       timeout=timeout) as assoc:
        if not assoc.accepted_pc:
            result["detail"] = "association refused"
            return result
        pc_id = next(iter(assoc.accepted_pc))
        identifier = _build_implicit_vr_dataset({
            TAG_STUDY_DATE: "19000101-20301231",
            TAG_PATIENT_NAME: "*",
            TAG_STUDY_INSTANCE_UID: "",
        })
        cs = _dimse_command_set({
            TAG_COMMAND_FIELD: ("US", DIMSE_C_FIND_RQ),
            TAG_AFFECTED_SOP_CLASS: ("UI", STUDY_ROOT_FIND),
            TAG_MESSAGE_ID: ("US", 3),
            TAG_DATA_SET_TYPE: ("US", 0x0001),
        })
        pdu_cmd = build_p_data_tf(pc_id, cs, last=True)
        pdu_data = _build_data_pdv(pc_id, identifier)
        if not assoc.sock:
            return result
        try:
            assoc.sock.sendall(pdu_cmd)
            assoc.sock.sendall(pdu_data)
        except OSError as exc:
            result["detail"] = f"send error: {exc}"
            return result
        count = 0
        for _ in range(64):
            status, data_set = assoc.recv_pdv()
            if status is None:
                break
            if status in (STATUS_PENDING, 0xFF01):
                count += _parse_find_dataset(data_set)
            elif status == STATUS_SUCCESS:
                break
            else:
                break
        result["studies_listed"] = count
        result["detail"] = f"raw socket count={count}"
    return result


def c_move(host: str, port: int, called_ae: str, calling_ae: str,
           timeout: int = DEFAULT_TIMEOUT) -> dict:
    """C-MOVE — request transfer of an image to evaluate exfiltration.

    We send a C-MOVE-RQ to destination AE = CALLING_AE (i.e. ourselves).
    In lab contexts this typically fails (no Storage SCP listening on our
    side), but a Success response from the server indicates that the
    server WOULD transfer images — i.e. C-MOVE is enabled without
    additional auth. That's the signal we record.
    """
    result = {"c_move_possible": False, "detail": ""}
    if PYNETDICOM_OK:
        try:
            ae = AE(ae_title=calling_ae.encode("ascii"))
            ae.add_requested_context(STUDY_ROOT_MOVE)
            assoc = ae.associate(host, port)
            if assoc.is_established:
                try:
                    ds = Dataset()
                    ds.StudyInstanceUID = "1.2.840.999999.1.1"
                    rsp = assoc.send_c_move(ds, calling_ae, STUDY_ROOT_MOVE)
                    # send_c_move returns a generator — last element is the final status
                    final_status = None
                    for status, _ in rsp:
                        final_status = status
                    if final_status is not None:
                        # 0xFF00 Pending, 0x0000 Success, 0xB000 Sub-ops complete
                        result["c_move_possible"] = final_status.Status in (
                            STATUS_PENDING, STATUS_SUCCESS, 0xB000, 0xFF00,
                        )
                        result["detail"] = f"pydicom status=0x{final_status.Status:04X}"
                finally:
                    assoc.release()
            else:
                result["detail"] = "association rejected"
        except Exception as exc:  # noqa: BLE001
            result["detail"] = f"pydicom error: {exc}"
        return result
    # Raw socket fallback — we don't have a Storage SCP, but we can still
    # observe whether the server accepts the C-MOVE-RQ with a Pending
    # status (which means it would have transferred the image).
    with RawDicomAssoc(host, port, called_ae, calling_ae,
                       [STUDY_ROOT_MOVE],
                       [IMPLICIT_LITTLE_ENDIAN],
                       timeout=timeout) as assoc:
        if not assoc.accepted_pc:
            result["detail"] = "association refused"
            return result
        pc_id = next(iter(assoc.accepted_pc))
        identifier = _build_implicit_vr_dataset({
            TAG_STUDY_INSTANCE_UID: "1.2.840.999999.1.1",
        })
        cs = _dimse_command_set({
            TAG_COMMAND_FIELD: ("US", DIMSE_C_MOVE_RQ),
            TAG_AFFECTED_SOP_CLASS: ("UI", STUDY_ROOT_MOVE),
            TAG_MESSAGE_ID: ("US", 4),
            TAG_DATA_SET_TYPE: ("US", 0x0001),
        })
        pdu_cmd = build_p_data_tf(pc_id, cs, last=True)
        pdu_data = _build_data_pdv(pc_id, identifier)
        if not assoc.sock:
            return result
        try:
            assoc.sock.sendall(pdu_cmd)
            assoc.sock.sendall(pdu_data)
        except OSError as exc:
            result["detail"] = f"send error: {exc}"
            return result
        status, _ = assoc.recv_pdv()
        # Pending = server would have started transferring; Success = completed
        result["c_move_possible"] = status in (STATUS_PENDING, STATUS_SUCCESS,
                                               0xFF00, 0xB000)
        result["detail"] = f"raw socket status={status}"
    return result


def try_c_store(host: str, port: int, called_ae: str, calling_ae: str,
                timeout: int = DEFAULT_TIMEOUT) -> dict:
    """C-STORE / Storage Commitment — gated behind SAFE_MODE=full.

    In the health sector SAFE_MODE defaults to 'read_only', so this
    function refuses to upload anything and only reports whether the
    operation would have been attempted. Set SECTOR=it or override
    SAFE_MODE=full to actually perform a C-STORE in a non-clinical lab.
    """
    result = {"try_c_store_attempted": False, "c_store_refused": True,
              "reason": "SAFE_MODE=read_only (health sector default)"}
    # sector_base guard — exit-safe; we keep the same dict structure either way
    if SECTOR_BASE_OK and not is_write_allowed():
        result["reason"] = (
            f"SAFE_MODE={get_safe_mode()} — write refused for sector 'health' "
            "(no C-STORE / no upload of modified images)"
        )
        return result
    # SAFE_MODE=full — proceed (non-clinical lab only)
    result["c_store_refused"] = False
    result["reason"] = "SAFE_MODE=full — C-STORE would upload a modified image"
    # We DO NOT actually upload — even in full mode, uploading a synthetic
    # DICOM object could corrupt a clinical PACS. The probe records that
    # the operation was *enabled*, not that it executed.
    result["try_c_store_attempted"] = False
    result["note"] = ("Storage Commitment Push would target SOP "
                      f"{STORAGE_COMMITMENT_SOP}; not executed even in full mode "
                      "to prevent clinical data corruption.")
    return result


# ─── Implicit VR LE dataset builder (for raw socket fallback) ───────
def _build_implicit_vr_dataset(tags: dict) -> bytes:
    """Build an Implicit VR Little Endian data set (PS3.5 §7.1).

    tags : dict[(group, element)] -> str | int
    All values are encoded as strings (LO/SH/UI). Length is uint32 LE.
    """
    out = b""
    for (grp, elm), value in sorted(tags.items()):
        text = str(value).encode("ascii", errors="replace")
        if len(text) % 2:
            text += b"\x00"
        out += struct.pack("<HHI", grp, elm, len(text)) + text
    return out


def _build_data_pdv(pc_id: int, data_set: bytes, last: bool = True) -> bytes:
    """Build a P-DATA-TF carrying a data set fragment (Message Control
    Header bit 0 = 0 → data)."""
    msg_ctrl = 0x00 | (0x01 if last else 0x00)
    pdv = struct.pack(">BB", pc_id, msg_ctrl) + data_set
    pdv_item = struct.pack(">I", len(pdv)) + pdv
    return _pdu_header(PDU_P_DATA_TF, pdv_item)


# ─── TCP reachability pre-check ─────────────────────────────────────
def _port_open(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ─── Main entrypoint ────────────────────────────────────────────────
def main() -> int:
    # 1. LAB guard — refuse without explicit lab authorization
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "LAB guard not satisfied",
            "detail": "Set LAB=1 in the environment to confirm lab authorization.",
        }))
        return 1

    # 2. Sector config — record SAFE_MODE so the JSON output is auditable
    sector_cfg = get_sector_config() if SECTOR_BASE_OK else None
    safe_mode = (sector_cfg or {}).get("safe_mode", "read_only")

    # 3. Reachability — try 104 then 111
    t0 = time.time()
    port_open_104 = _port_open(TARGET_HOST, DICOM_DEFAULT_PORT)
    port_open_111 = _port_open(TARGET_HOST, DICOM_ALT_PORT) if not port_open_104 else False
    port = DICOM_DEFAULT_PORT if port_open_104 else (
        DICOM_ALT_PORT if port_open_111 else None
    )

    out = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "health",
        "safe_mode": safe_mode,
        "target": {
            "host": TARGET_HOST,
            "port": port,
            "port_104_open": port_open_104,
            "port_111_open": port_open_111,
        },
        "pydicom_available": PYDICOM_OK,
        "pynetdicom_available": PYNETDICOM_OK,
        "sector_base_ok": SECTOR_BASE_OK,
        # Required output fields (all initialized for stable JSON schema)
        "c_echo_ok": False,
        "patients_listed": 0,
        "studies_listed": 0,
        "c_move_possible": False,
        "phi_exposed": False,
        # PHI masking confirmation
        "phi_masking": "patient_names_redacted_counts_only",
        # Detail / debug — never contains PHI
        "details": {},
        "duration_ms": 0,
    }

    if port is None:
        out["error"] = "no DICOM listener on port 104 or 111"
        out["duration_ms"] = int((time.time() - t0) * 1000)
        print(json.dumps(out, default=str))
        return 2

    # 4. C-ECHO
    echo_res = c_echo(TARGET_HOST, port, CALLED_AE, CALLING_AE)
    out["c_echo_ok"] = bool(echo_res.get("c_echo_ok"))
    out["details"]["c_echo"] = echo_res.get("detail", "")

    # 5. C-FIND Patient (PHI leak check) — only if C-ECHO succeeded
    if out["c_echo_ok"]:
        find_res = c_find_patient(TARGET_HOST, port, CALLED_AE, CALLING_AE)
        out["patients_listed"] = int(find_res.get("patients_listed", 0))
        out["phi_exposed"] = bool(find_res.get("phi_exposed"))
        out["details"]["c_find_patient"] = find_res.get("detail", "")

        # 6. C-FIND Study
        study_res = c_find_study(TARGET_HOST, port, CALLED_AE, CALLING_AE)
        out["studies_listed"] = int(study_res.get("studies_listed", 0))
        out["details"]["c_find_study"] = study_res.get("detail", "")

        # 7. C-MOVE — exfiltration check
        move_res = c_move(TARGET_HOST, port, CALLED_AE, CALLING_AE)
        out["c_move_possible"] = bool(move_res.get("c_move_possible"))
        out["details"]["c_move"] = move_res.get("detail", "")

        # 8. C-STORE — gated behind SAFE_MODE=full
        store_res = try_c_store(TARGET_HOST, port, CALLED_AE, CALLING_AE)
        out["details"]["try_c_store"] = store_res
    else:
        out["details"]["skipped"] = (
            "C-ECHO failed — downstream C-FIND/C-MOVE/C-STORE skipped"
        )

    out["duration_ms"] = int((time.time() - t0) * 1000)
    print(json.dumps(out, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
