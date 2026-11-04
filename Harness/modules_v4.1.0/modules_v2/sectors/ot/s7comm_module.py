#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — s7comm_probe
# OT/ICS validation module — Siemens S7comm (ISO-on-TCP) probing.
#
#   - Default port : 102 (Siemens S7 / ISO-on-TCP, RFC 1006)
#   - Functions    : connect_plc (COTP CR/CC + Setup Communication),
#                    read_device_info (SZL 0x0011 → module/serial/firmware),
#                    read_db (S7 read data block), try_write_db (SAFE_MODE=full)
#   - Uses python-snap7 if installed, else falls back to raw socket
#     TPKT/COTP/S7 packet crafting (no external dependency).
#   - Respects SAFE_MODE : if read_only, write test is skipped and reported
#     as "write_skipped_safe_mode".
#   - LAB=1 mandatory. Timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (OT) : NERC CIP, NIS2, IEC 62443.
import json
import os
import socket
import struct
import sys
import time
from typing import Optional

# ─── Make sector_base importable from ../../sector_base.py ────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULES_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _MODULES_ROOT not in sys.path:
    sys.path.insert(0, _MODULES_ROOT)

from sector_base import (  # noqa: E402
    get_sector_config,
    check_write_allowed,
    is_write_allowed,
)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "s7comm_probe"
DEFAULT_PORT = 102
TIMEOUT_S = 5.0

# Default TSAPs used by Siemens S7 PLCs for rack 0 / slot 2.
# Called  TSAP = 0x0102  (server-side, "device")
# Calling TSAP = 0x0100  (client-side, "PG/PC")
DEFAULT_LOCAL_TSAP = 0x0100
DEFAULT_REMOTE_TSAP = 0x0102

# ─── Optional snap7 import (graceful degrade) ────────────────────────────
SNAP7_AVAILABLE = False
snap7_client = None
try:
    import snap7  # type: ignore
    SNAP7_AVAILABLE = True
except ImportError:
    SNAP7_AVAILABLE = False

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── LAB guard ─────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"

# ─── Sector / SAFE_MODE config ─────────────────────────────────────────────
SECTOR_CFG = get_sector_config()
SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")


# ═══════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET S7COMM TRANSPORT (fallback when snap7 missing)
# ═══════════════════════════════════════════════════════════════════════════
# Stack : TCP → TPKT (RFC 1006) → COTP (ISO 8073) → S7 → payload
#
# TPKT header : 0x03, 0x00, <len BE 2 bytes>
# COTP CR      : LI(1) + Code(0xE0) + DST_REF(2) + SRC_REF(2) + Class(1)
#                + variable part (TSAP parameters)
# COTP CC      : Code=0xD0
# COTP DT      : Code=0xF0 + EOT byte (0x80)
#
# S7 header    : ProtocolId(0x32) + ROSCTR(1=Job) + Redundancy(2)
#                + PduReference(2) + ParamLength(2) + DataLength(2)
# S7 param     : Function(1) + ItemHeader(0x12) + ItemDataLength(1)
#                + DBNumber(2) + Area(1) + Address(3) bytes (offset in bits)
class S7RawClient:
    """Minimal S7comm-over-ISO-on-TCP client (raw sockets, no deps)."""

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S,
                 local_tsap: int = DEFAULT_LOCAL_TSAP,
                 remote_tsap: int = DEFAULT_REMOTE_TSAP):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.local_tsap = local_tsap
        self.remote_tsap = remote_tsap
        self.sock: Optional[socket.socket] = None
        self.pdu_ref = 0
        self.negotiated_pdusize = 0  # set by setup comm response

    # ── connection lifecycle ────────────────────────────────────────────
    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        self._cotp_connect()
        self._setup_communication()

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self) -> "S7RawClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── TPKT/COTP framing helpers ───────────────────────────────────────
    def _send_tpkt(self, payload: bytes) -> None:
        if self.sock is None:
            raise RuntimeError("socket not connected")
        total = 4 + len(payload)
        frame = struct.pack(">BBH", 0x03, 0x00, total) + payload
        self.sock.sendall(frame)

    def _recv_tpkt(self) -> bytes:
        if self.sock is None:
            raise RuntimeError("socket not connected")
        header = self._recvn(4)
        if len(header) < 4 or header[0] != 0x03 or header[1] != 0x00:
            raise OSError("invalid_tpkt_header")
        total = struct.unpack(">H", header[2:4])[0]
        if total < 4:
            raise OSError("invalid_tpkt_length")
        body = self._recvn(total - 4)
        return body

    def _recvn(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    # ── COTP Connect Request / Confirm ──────────────────────────────────
    def _cotp_connect(self) -> None:
        # Variable part: TPDU size param (0xC0) + called/calling TSAP (0xC1/0xC2)
        # COTP CR body :
        #   LI(1=0x11 for our variable part length) Code(0xE0) DST_REF(0x0000)
        #   SRC_REF(0x0001) Class(0x00)
        #   0xC0 len=0x01 tpdu_size_code
        #   0xC1 len=0x02 called_tsap(2)
        #   0xC2 len=0x02 calling_tsap(2)
        called = struct.pack(">H", self.remote_tsap)
        calling = struct.pack(">H", self.local_tsap)
        varpart = (
            b"\xC0\x01\x0A"                       # TPDU size = 0x0A → 1024 bytes? (we keep default)
            + b"\xC1\x02" + called
            + b"\xC2\x02" + calling
        )
        li = len(varpart) + 6 + 1  # +6 fixed header bytes + 1 for LI itself
        # COTP fixed header is: LI(1) Code(1) DST_REF(2) SRC_REF(2) Class(1) = 6
        body = (
            struct.pack("B", li)
            + b"\xE0"
            + b"\x00\x00"                  # DST_REF
            + b"\x00\x01"                  # SRC_REF
            + b"\x00"                      # Class
            + varpart
        )
        self._send_tpkt(body)
        cc = self._recv_tpkt()
        if len(cc) < 2 or cc[1] != 0xD0:
            raise OSError(f"cotp_cc_invalid: code=0x{cc[1]:02X}" if len(cc) >= 2 else "cotp_cc_short")
        # TPDU size optional — we ignore it; PLC may use its own.

    # ── S7 Setup Communication (ROSCTR=0x01, func=0xF0) ─────────────────
    def _setup_communication(self) -> None:
        # Function 0xF0, reserved 0x00, then bytes:
        #   CallingMaxAMQ(2) CallingMaxPDU(2)
        pdu_req = bytes([
            0x32,                 # protocol id
            0x01,                 # job
            0x00, 0x00,           # redundancy
            0x00, 0x00,           # pdu reference
            0x00, 0x08,           # param length = 8
            0x00, 0x00,           # data length = 0
            0xF0,                 # function: setup communication
            0x00,                 # reserved
            0x01, 0x00,           # max AMQ calls (256)
            0x01, 0x00,           # max AMQ PDU  (256)
        ])
        self._send_tpkt(pdu_req)
        resp = self._recv_tpkt()
        if len(resp) < 12 or resp[0] != 0x32:
            raise OSError("s7_setup_invalid")
        # Negotiated PDU size is in bytes [13:15] of the response body
        # Response layout: 0x32, ROSCTR, Redundancy(2), PduRef(2),
        #                  ParamLen(2), DataLen(2), 0xF0, 0x00, AMQ(2), PDU(2)
        try:
            self.negotiated_pdusize = struct.unpack(">H", resp[13:15])[0]
        except Exception:
            self.negotiated_pdusize = 0

    # ── S7 Read (function 0x04) ─────────────────────────────────────────
    def read_var(self, area: int, db_number: int, offset: int, size: int) -> bytes:
        """S7 read. area: 0x04=DB, 0x05=Input, 0x06=Output, 0x07=Marker/Flags,
        0x1D=Clocked flags, 0x03=System data block (SZL).

        Variable spec item layout (per snap7 / S7comm spec) :
            Function(1) ItemCount(1)
            ItemHeader(0x12) ItemDataLen(0x0A)
            SyntaxID(0x10) Area(1) NumElements(2 BE)
            DBNumber(2 BE) Address(4 BE bits, top byte = 0)
        """
        self.pdu_ref = (self.pdu_ref + 1) & 0xFFFF
        bit_offset = (offset * 8) & 0xFFFFFF           # 24-bit address
        addr_bytes = struct.pack(">I", bit_offset)     # 4 bytes, top byte = 0
        param = bytes([
            0x04,                       # function: read
            0x01,                       # item count = 1
            0x12, 0x0A, 0x10, area,     # item header + syntax id + area
        ]) + struct.pack(">H", size) + struct.pack(">H", db_number) + addr_bytes
        hdr = bytearray([
            0x32, 0x01,                 # protocol id, job
            0x00, 0x00,                 # redundancy
        ])
        hdr += struct.pack(">H", self.pdu_ref)   # pdu reference
        hdr += struct.pack(">H", len(param))     # param length
        hdr += struct.pack(">H", 0)              # data length = 0 for read
        frame = bytes(hdr) + param
        self._send_tpkt(frame)
        resp = self._recv_tpkt()
        return self._parse_read_response(resp)

    def _parse_read_response(self, resp: bytes) -> bytes:
        # Response: 0x32, ROSCTR(1), Redundancy(2), PduRef(2),
        #           ParamLen(2), DataLen(2), Param[1]=0x04, ItemCount[1],
        #           then per-item: ReturnCode(1), TransportSize(1), Length(2)
        if len(resp) < 12 or resp[0] != 0x32:
            raise OSError("s7_read_invalid_header")
        param_len = struct.unpack(">H", resp[6:8])[0]
        data_len = struct.unpack(">H", resp[8:10])[0]
        param_off = 10
        if len(resp) < param_off + param_len:
            raise OSError("s7_read_param_truncated")
        param = resp[param_off:param_off + param_len]
        if len(param) < 2 or param[0] != 0x04:
            raise OSError("s7_read_unexpected_function")
        item_count = param[1]
        data_off = param_off + param_len
        if len(resp) < data_off + data_len:
            raise OSError("s7_read_data_truncated")
        data = resp[data_off:data_off + data_len]
        # Parse first item only: ReturnCode(1), TransportSize(1), Length(2), then data
        if len(data) < 4:
            return b""
        ret_code = data[0]
        _transport_size = data[1]
        _length = struct.unpack(">H", data[2:4])[0]
        item_data = data[4:]
        if ret_code != 0xFF:  # 0xFF = success; anything else is error
            raise OSError(f"s7_read_return_code:0x{ret_code:02X}")
        return item_data

    # ── S7 Write (function 0x05) ────────────────────────────────────────
    def write_var(self, area: int, db_number: int, offset: int,
                  data: bytes) -> bool:
        """S7 write. Returns True if the PLC echoed a success return code.

        area encoding matches read_var (0x04=DB, 0x06=Output, 0x07=Marker...).
        """
        self.pdu_ref = (self.pdu_ref + 1) & 0xFFFF
        size = len(data)
        bit_offset = (offset * 8) & 0xFFFFFF
        addr_bytes = struct.pack(">I", bit_offset)
        param = bytes([
            0x05,                       # function: write
            0x01,                       # item count = 1
            0x12, 0x0A, 0x10, area,
        ]) + struct.pack(">H", size) + struct.pack(">H", db_number) + addr_bytes
        # Data block: ReturnCode(0x00 placeholder) + TransportSize(0x09=byte/word)
        #             + DataLength(2) + raw bytes
        data_block = bytes([0x00, 0x09]) + struct.pack(">H", size) + data
        hdr = bytearray([
            0x32, 0x01,                 # protocol id, job
            0x00, 0x00,                 # redundancy
        ])
        hdr += struct.pack(">H", self.pdu_ref)
        hdr += struct.pack(">H", len(param))
        hdr += struct.pack(">H", len(data_block))
        frame = bytes(hdr) + param + data_block
        self._send_tpkt(frame)
        resp = self._recv_tpkt()
        return self._parse_write_response(resp)

    def _parse_write_response(self, resp: bytes) -> bool:
        if len(resp) < 12 or resp[0] != 0x32:
            return False
        param_len = struct.unpack(">H", resp[6:8])[0]
        param_off = 10
        if len(resp) < param_off + param_len:
            return False
        param = resp[param_off:param_off + param_len]
        if len(param) < 2 or param[0] != 0x05:
            return False
        data_off = param_off + param_len
        if len(resp) < data_off + 1:
            return False
        ret_code = resp[data_off]
        return ret_code == 0xFF


# ═══════════════════════════════════════════════════════════════════════════
#  PROBE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
def connect_plc() -> dict:
    """ISO-on-TCP setup: TCP connect → COTP CR → COTP CC → S7 Setup Comm.

    Returns {plc_reachable, cotp_ok, s7_setup_ok, negotiated_pdu, error}.
    """
    result = {
        "plc_reachable": False,
        "cotp_ok": False,
        "s7_setup_ok": False,
        "negotiated_pdu": 0,
        "error": None,
    }
    try:
        if SNAP7_AVAILABLE:
            client = snap7.client.Client()
            client.connect(HOST, 0, 2)  # rack 0, slot 2
            result["plc_reachable"] = True
            result["cotp_ok"] = True
            result["s7_setup_ok"] = True
            try:
                result["negotiated_pdu"] = client.get_pdu_length()
            except Exception:
                pass
            try:
                client.disconnect()
            except Exception:
                pass
        else:
            with S7RawClient(HOST, PORT, timeout=TIMEOUT_S) as c:
                result["plc_reachable"] = True
                result["cotp_ok"] = True
                result["s7_setup_ok"] = True
                result["negotiated_pdu"] = c.negotiated_pdusize
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
        return result
    return result


# SZL 0x0011 (Module identification) → module type, serial, firmware
SZL_MODULE_ID = 0x0011
SZL_MODULE_INDEX_1 = 0x0001   # 1st record → module / version
SZL_SERIAL_INDEX = 0x0007     # 7th record → serial number
SZL_FIRMWARE_INDEX = 0x0004   # 4th record → firmware version


def _parse_szl_module_id(data: bytes) -> dict:
    """Parse SZL record response (module identification).

    The SZL partial-list response contains a header (variable length) then
    one or more 0x1C-byte records. We extract module type, firmware version
    and serial number fields when present.
    """
    out = {"module_type": None, "serial": None, "firmware": None,
           "raw_hex": data.hex() if data else ""}
    if not data or len(data) < 8:
        return out
    # SZL partial list response header:
    #   ReturnCode? + ItemHeader(0x12) + ItemDataLen(0x09) + SyntaxID(0x12)
    #   + (unknown 4) + DataHeader + records...
    # Each record (for SZL 0x0011) is typically 0x1C bytes:
    #   bytes [0..1]   = index
    #   bytes [2..19]  = module name (text)
    #   bytes [20..23] = module version + revision
    # We walk the response looking for printable ASCII runs to extract info.
    text = data.decode("latin-1", errors="replace")
    import re
    ascii_runs = re.findall(r"[\x20-\x7E]{4,}", text)
    out["ascii_runs"] = ascii_runs[:8]
    # Heuristic: longest ASCII run ≥6 chars is usually the module name.
    if ascii_runs:
        longest = max(ascii_runs, key=len)
        out["module_type"] = longest.strip()
    # Firmware version: bytes that look like "V?.??.??" or a 4-byte pattern
    fw = re.search(r"V\d+\.\d+(?:\.\d+)?", text)
    if fw:
        out["firmware"] = fw.group(0)
    else:
        # Try to interpret firmware bytes (index 0x0001 record, offset 20..23)
        # as BCD-packed version: major.minor.build
        try:
            # Find a 4-byte window that looks like a version (1-digit numbers)
            for i in range(0, len(data) - 3):
                b0, b1, b2, b3 = data[i], data[i+1], data[i+2], data[i+3]
                if 1 <= b0 <= 99 and 0 <= b1 <= 99 and 0 <= b2 <= 99 and b3 in (0, 1):
                    out["firmware"] = f"V{b0}.{b1}.{b2}"
                    break
        except Exception:
            pass
    # Serial number: SZL index 0x0007 record → 24 bytes, ASCII after offset 2
    try:
        if len(data) >= 0x1C * 2:
            # Second record (offset 0x1C) often holds serial
            rec2 = data[0x1C:0x1C + 0x1C]
            serial_text = rec2[2:18].decode("latin-1", errors="replace").strip()
            if serial_text and any(c.isdigit() for c in serial_text):
                out["serial"] = serial_text
    except Exception:
        pass
    return out


def read_device_info() -> dict:
    """Read SZL (System Status List) 0x0011 → module type / serial / firmware.

    Uses snap7.get_cpu_info() when available, else raw S7comm SZL read
    (area 0x03 = system data block, SZL ID 0x0011, index 0x0001).
    """
    result = {
        "plc_identified": False,
        "module_type": None,
        "serial": None,
        "firmware": None,
        "error": None,
    }

    if SNAP7_AVAILABLE:
        try:
            client = snap7.client.Client()
            client.connect(HOST, 0, 2)
            try:
                info = client.get_cpu_info() if hasattr(client, "get_cpu_info") else None
                if info is not None:
                    result["module_type"] = (getattr(info, "moduleTypeName", None)
                                             or getattr(info, "module", None))
                    result["serial"] = getattr(info, "serialNumber", None)
                    result["firmware"] = getattr(info, "copyright", None)
                    result["plc_identified"] = any(
                        v for v in (result["module_type"], result["serial"], result["firmware"])
                    )
                else:
                    # Fallback: read SZL directly
                    szl = client.db_read(1, 0, 0x1C) if hasattr(client, "db_read") else None
                    if szl:
                        result["module_type"] = "snap7_cpu_info_unavailable"
                        result["plc_identified"] = True
            finally:
                client.disconnect()
        except Exception as e:
            result["error"] = f"snap7:{type(e).__name__}:{e}"
        return result

    # Raw socket path: read SZL via S7 read on area 0x03 (system data block)
    try:
        with S7RawClient(HOST, PORT, timeout=TIMEOUT_S) as c:
            # SZL read requires function 0x05 (user data) normally, but a plain
            # S7 read on area 0x03 with the SZL ID as DB number returns the
            # system status list on most Siemens S7-300/400 PLCs.
            try:
                data = c.read_var(area=0x03, db_number=SZL_MODULE_ID,
                                  offset=0, size=0x1C)
            except OSError as e:
                # Some PLCs reject area-0x03 reads without a SZL function call;
                # we record the error and still mark plc_identified=False.
                result["error"] = f"szl_read:{e}"
                return result
            parsed = _parse_szl_module_id(data)
            result["module_type"] = parsed.get("module_type")
            result["serial"] = parsed.get("serial")
            result["firmware"] = parsed.get("firmware")
            result["plc_identified"] = any(
                v for v in (result["module_type"], result["serial"], result["firmware"])
            )
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def read_db(db_number: int = 1, offset: int = 0, size: int = 10) -> dict:
    """Read data block (S7 read, area 0x04). Returns {read_ok, data_hex, error}."""
    result = {"read_ok": False, "data_hex": "", "size": 0, "error": None}

    if SNAP7_AVAILABLE:
        try:
            client = snap7.client.Client()
            client.connect(HOST, 0, 2)
            try:
                data = client.db_read(db_number, offset, size)
            finally:
                client.disconnect()
            result["data_hex"] = bytes(data).hex()
            result["size"] = len(data)
            result["read_ok"] = True
        except Exception as e:
            result["error"] = f"snap7:{type(e).__name__}:{e}"
        return result

    try:
        with S7RawClient(HOST, PORT, timeout=TIMEOUT_S) as c:
            data = c.read_var(area=0x04, db_number=db_number, offset=offset, size=size)
            result["data_hex"] = data.hex()
            result["size"] = len(data)
            result["read_ok"] = True
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def try_write_db(db_number: int = 1, offset: int = 0,
                 data: bytes = b"\x00\x00") -> dict:
    """Write to a data block (S7 write, area 0x04). ONLY if SAFE_MODE=full.

    Respects SAFE_MODE : if read_only → write_skipped_safe_mode (no packet sent).
    When SAFE_MODE=full, calls check_write_allowed() as defense-in-depth.
    """
    result = {
        "write_tested": False,
        "write_ok": False,
        "db": db_number,
        "offset": offset,
        "status": None,
        "error": None,
    }

    if not is_write_allowed():
        result["status"] = "write_skipped_safe_mode"
        return result

    check_write_allowed(MODULE_NAME)  # defense-in-depth guard

    if SNAP7_AVAILABLE:
        try:
            client = snap7.client.Client()
            client.connect(HOST, 0, 2)
            try:
                client.db_write(db_number, offset, bytearray(data))
            finally:
                client.disconnect()
            result["write_tested"] = True
            result["write_ok"] = True
            result["status"] = "write_ok"
        except Exception as e:
            result["write_tested"] = True
            result["error"] = f"snap7:{type(e).__name__}:{e}"
            result["status"] = "snap7_error"
        return result

    try:
        with S7RawClient(HOST, PORT, timeout=TIMEOUT_S) as c:
            ok = c.write_var(area=0x04, db_number=db_number,
                             offset=offset, data=data)
            result["write_tested"] = True
            result["write_ok"] = bool(ok)
            result["status"] = "write_ok" if ok else "write_failed"
    except (socket.timeout, TimeoutError):
        result["write_tested"] = True
        result["error"] = "timeout"
        result["status"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["write_tested"] = True
        result["error"] = f"conn_error:{type(e).__name__}"
        result["status"] = "conn_error"
    except Exception as e:
        result["write_tested"] = True
        result["error"] = f"{type(e).__name__}:{e}"
        result["status"] = "error"
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("S7comm probing on production PLCs is illegal "
                           "outside an authorized lab. NERC CIP / IEC 62443."),
        }))
        sys.exit(1)

    t0 = time.time()
    summary: dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "port": PORT,
        "sector": SECTOR_CFG.get("sector"),
        "safe_mode": SAFE_MODE,
        "library": "snap7" if SNAP7_AVAILABLE else "raw_socket",
        "plc_identified": False,
        "module_type": None,
        "serial": None,
        "firmware": None,
        "read_ok": False,
        "write_tested": False,
        "write_status": ("write_skipped_safe_mode"
                         if SAFE_MODE != "full" else None),
        "db_sample_hex": "",
        "errors": [],
    }

    # 1. Connection (COTP CR/CC + Setup Communication)
    try:
        cn = connect_plc()
        if cn.get("error"):
            summary["errors"].append(f"connect_plc:{cn['error']}")
        # If unreachable, no point continuing — bail out gracefully.
        # SAFE_MODE=read_only still reports write_status=write_skipped_safe_mode.
        if not cn.get("plc_reachable"):
            summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
            print(json.dumps(summary, indent=2, default=str))
            return
    except Exception as e:
        summary["errors"].append(f"connect_plc:{type(e).__name__}:{e}")
        summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
        print(json.dumps(summary, indent=2, default=str))
        return

    # 2. Read SZL (module / firmware / serial)
    try:
        di = read_device_info()
        summary["plc_identified"] = bool(di.get("plc_identified"))
        summary["module_type"] = di.get("module_type")
        summary["serial"] = di.get("serial")
        summary["firmware"] = di.get("firmware")
        if di.get("error"):
            summary["errors"].append(f"read_device_info:{di['error']}")
    except Exception as e:
        summary["errors"].append(f"read_device_info:{type(e).__name__}:{e}")

    # 3. Read DB (data block) — read-only probe
    try:
        db = read_db(db_number=1, offset=0, size=10)
        summary["db_sample_hex"] = db.get("data_hex", "")
        summary["read_ok"] = bool(db.get("read_ok"))
        if db.get("error"):
            summary["errors"].append(f"read_db:{db['error']}")
    except Exception as e:
        summary["errors"].append(f"read_db:{type(e).__name__}:{e}")

    # 4. Write test — only if SAFE_MODE=full
    try:
        wr = try_write_db(db_number=1, offset=0, data=b"\x00\x00")
        summary["write_tested"] = bool(wr.get("write_tested"))
        summary["write_status"] = wr.get("status")
        if wr.get("error"):
            summary["errors"].append(f"try_write_db:{wr['error']}")
    except SystemExit:
        raise
    except Exception as e:
        summary["errors"].append(f"try_write_db:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
