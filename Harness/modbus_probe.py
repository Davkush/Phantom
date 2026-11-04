#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — modbus_probe (OT protocol module)
# Read-only Modbus TCP probe for SCADA/ICS validation.
#
# Default port: 502 (Modbus TCP, IANA-assigned).
# Stack: TCP → MBAP header (7 bytes) + PDU.
# MBAP header: Transaction ID (2, BE) | Protocol ID (2, =0) | Length (2, BE)
#              | Unit ID (1)
#
# Probes performed (ALL read-only — no FC 0x05/0x06/0x0F/0x10):
#   1. Read Device Identification  (FC 0x2B, MEI 0x0E, ReadDevID=0x01)
#      → vendor (obj 0x00), product_code (obj 0x01), revision (obj 0x02)
#   2. Read Coils                 (FC 0x01, addr=0, qty=10)
#   3. Read Holding Registers     (FC 0x03, addr=0, qty=10)
#   4. Read Input Registers       (FC 0x04, addr=0, qty=10)
#
# READ_ONLY is enforced unconditionally — these are OT assets where a write
# command can drive a physical actuator (pump, valve, breaker). No FC ≥ 0x05
# is ever constructed by this module.
#
# Reproducibility: SEED env var seeds the transaction-ID sequence so repeated
# runs against the same target produce identical wire bytes.
#
# Legal: isolated lab only (NERC CIP / IEC 62443 / NIS2).
import json
import os
import random
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

from sector_base import get_sector_config  # noqa: E402

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "modbus_probe"
DEFAULT_PORT = 502
TIMEOUT_S = 5.0
DEFAULT_UNIT_ID = 1

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

SEED = int(os.environ.get("SEED", "1337"))
random.seed(SEED)

SECTOR_CFG = get_sector_config()
SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")  # OT sector → read_only

# ─── Optional pymodbus import (NOT required — used only for cross-check) ───
PYMODBUS_AVAILABLE = False
try:
    from pymodbus.client import ModbusTcpClient as _ModbusTcpClientV3  # type: ignore
    PYMODBUS_AVAILABLE = True
except ImportError:
    try:
        from pymodbus.client.sync import ModbusTcpClient as _ModbusTcpClientV2  # type: ignore
        PYMODBUS_AVAILABLE = True
    except ImportError:
        PYMODBUS_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET MODBUS TCP TRANSPORT
# ═══════════════════════════════════════════════════════════════════════════
class ModbusRawClient:
    """Minimal Modbus TCP client using raw sockets (no external deps).

    Builds MBAP + PDU frames, sends, reads back exactly the response PDU.
    """

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S, unit_id: int = DEFAULT_UNIT_ID):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.unit_id = unit_id
        self._txn = random.randint(1, 0xFFFF)  # SEED-reproducible start
        self.sock: Optional[socket.socket] = None

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self) -> "ModbusRawClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- frame helpers -----------------------------------------------------
    def _build_mbap_pdu(self, pdu: bytes) -> bytes:
        """Wrap a PDU with a fresh MBAP header (7 bytes) + PDU."""
        self._txn = (self._txn + 1) & 0xFFFF
        txn = struct.pack(">H", self._txn)
        proto = b"\x00\x00"                     # Modbus protocol = 0
        length = struct.pack(">H", len(pdu) + 1)  # +1 for Unit ID
        unit = struct.pack("B", self.unit_id)
        return txn + proto + length + unit + pdu

    def _recvn(self, n: int) -> bytes:
        """Read exactly n bytes (handles partial TCP reads)."""
        if self.sock is None:
            raise RuntimeError("socket not connected")
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _send_recv(self, pdu: bytes, expected_min: int = 2) -> bytes:
        """Send PDU wrapped in MBAP, return only the response PDU."""
        if self.sock is None:
            raise RuntimeError("socket not connected")
        frame = self._build_mbap_pdu(pdu)
        self.sock.sendall(frame)
        header = self._recvn(7)              # MBAP header = 7 bytes
        if len(header) < 7:
            raise OSError("truncated_mbap_header")
        _txn, _proto, length, _unit = struct.unpack(">HHHB", header)
        pdu_len = max(length - 1, 0)         # length includes the unit_id byte
        pdu_len = max(pdu_len, expected_min)
        return self._recvn(pdu_len)


# ═══════════════════════════════════════════════════════════════════════════
#  PROBE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
# Modbus function codes used (all read-only)
FC_READ_COILS               = 0x01
FC_READ_INPUT_DISCRETES     = 0x02
FC_READ_HOLDING_REGISTERS   = 0x03
FC_READ_INPUT_REGISTERS     = 0x04
FC_READ_DEVICE_ID           = 0x2B
MEI_READ_DEVICE_ID          = 0x0E

# Read-Device-ID object IDs (basic set, MB spec §6.21)
_ID_OBJ_VENDOR      = 0x00
_ID_OBJ_PRODUCT     = 0x01
_ID_OBJ_REVISION    = 0x02
_ID_OBJ_VENDOR_URL  = 0x03
_ID_OBJ_PRODUCT_NM  = 0x04
_ID_OBJ_MODEL       = 0x05
_ID_OBJ_APP_NAME    = 0x06


def _decode_id_objects(pdu: bytes) -> dict:
    """Parse a Read-Device-ID response PDU into {obj_id: value_str}.

    Response PDU layout (after FC + MEI):
      ReadDevID(1) ConformityLevel(1) MoreFollows(1) NextObjectID(1) NumObjects(1)
      then for each object: ObjID(1) ObjLen(1) Value(ObjLen)
    """
    out: dict = {}
    # Need at least the 7-byte fixed header (FC + MEI + 5 bytes)
    if len(pdu) < 7:
        return out
    num_obj = pdu[6]
    idx = 7
    for _ in range(num_obj):
        if idx + 2 > len(pdu):
            break
        obj_id = pdu[idx]
        obj_len = pdu[idx + 1]
        idx += 2
        if idx + obj_len > len(pdu):
            break
        try:
            val = pdu[idx:idx + obj_len].decode("utf-8", errors="replace")
        except Exception:
            val = pdu[idx:idx + obj_len].hex()
        out[obj_id] = val
        idx += obj_len
    return out


def probe_device_id(client: ModbusRawClient) -> dict:
    """FC 0x2B / MEI 0x0E — Read Device Identification (Basic)."""
    result = {
        "device_identified": False, "vendor": None, "product": None,
        "version": None, "conformity_level": None, "raw_objects": {},
        "error": None,
    }
    # PDU: FC + MEI + ReadDevID(1=Basic) + ObjectID(0x00)
    pdu_req = bytes([FC_READ_DEVICE_ID, MEI_READ_DEVICE_ID, 0x01, 0x00])
    try:
        pdu_resp = client._send_recv(pdu_req, expected_min=8)
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"; return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"; return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"; return result

    if not pdu_resp or len(pdu_resp) < 2:
        result["error"] = "empty_response"; return result
    # Validate FC echo (0x2B) and MEI (0x0E)
    if pdu_resp[0] == (FC_READ_DEVICE_ID | 0x80):
        result["error"] = f"modbus_exception:0x{pdu_resp[1]:02X}"; return result
    if pdu_resp[0] != FC_READ_DEVICE_ID or (len(pdu_resp) > 1 and pdu_resp[1] != MEI_READ_DEVICE_ID):
        result["error"] = f"unexpected_fc:0x{pdu_resp[0]:02X}"; return result
    if len(pdu_resp) >= 6:
        result["conformity_level"] = pdu_resp[3]
    objs = _decode_id_objects(pdu_resp)
    result["raw_objects"] = {str(k): v for k, v in objs.items()}
    result["vendor"]  = objs.get(_ID_OBJ_VENDOR) or objs.get(_ID_OBJ_VENDOR_URL)
    result["product"] = objs.get(_ID_OBJ_PRODUCT) or objs.get(_ID_OBJ_PRODUCT_NM) \
                        or objs.get(_ID_OBJ_MODEL)
    result["version"] = objs.get(_ID_OBJ_REVISION)
    result["device_identified"] = any(
        v is not None for v in (result["vendor"], result["product"], result["version"])
    )
    return result


def _read_bits_or_words(client: ModbusRawClient, fc: int, addr: int, count: int
                        ) -> dict:
    """Generic reader for FC 0x01/0x02/0x03/0x04.

    Returns: {read_ok, values, count, error}
    """
    result = {"read_ok": False, "values": [], "count": 0, "error": None}
    pdu_req = struct.pack(">BHH", fc, addr & 0xFFFF, count & 0xFFFF)
    try:
        pdu_resp = client._send_recv(pdu_req, expected_min=2)
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"; return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"; return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"; return result

    if not pdu_resp or len(pdu_resp) < 2:
        result["error"] = "empty_response"; return result
    if pdu_resp[0] == (fc | 0x80):
        result["error"] = f"modbus_exception:0x{pdu_resp[1]:02X}"; return result
    if pdu_resp[0] != fc:
        result["error"] = f"unexpected_fc:0x{pdu_resp[0]:02X}"; return result

    byte_count = pdu_resp[1]
    payload = pdu_resp[2:2 + byte_count]
    if fc in (FC_READ_COILS, FC_READ_INPUT_DISCRETES):
        bits = []
        for i in range(count):
            byte_i = i // 8
            bit_i = i % 8
            if byte_i < len(payload):
                bits.append((payload[byte_i] >> bit_i) & 0x01)
        result["values"] = bits
    else:  # 16-bit registers
        regs = []
        for i in range(0, len(payload) - 1, 2):
            regs.append(struct.unpack(">H", payload[i:i + 2])[0])
        result["values"] = regs
    result["count"] = len(result["values"])
    result["read_ok"] = True
    return result


def read_coils(client: ModbusRawClient, addr: int = 0, count: int = 10) -> dict:
    """FC 0x01 — Read Coils."""
    return _read_bits_or_words(client, FC_READ_COILS, addr, count)


def read_holding_registers(client: ModbusRawClient, addr: int = 0, count: int = 10) -> dict:
    """FC 0x03 — Read Holding Registers."""
    return _read_bits_or_words(client, FC_READ_HOLDING_REGISTERS, addr, count)


def read_input_registers(client: ModbusRawClient, addr: int = 0, count: int = 10) -> dict:
    """FC 0x04 — Read Input Registers."""
    return _read_bits_or_words(client, FC_READ_INPUT_REGISTERS, addr, count)


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def _safe_pymodbus_check() -> dict:
    """If pymodbus is the only path being considered, surface a structured
    'library_not_installed' error. We never raise it as a hard failure here —
    raw socket is the canonical transport — but we expose it for callers
    that depend on the optional library path."""
    return {"library": "raw_socket", "pymodbus_present": PYMODBUS_AVAILABLE}


def main() -> None:
    t0 = time.time()
    summary: dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "port": PORT,
        "sector": SECTOR_CFG.get("sector"),
        "read_only": True,                  # OT safety constraint
        "safe_mode": SAFE_MODE,
        "library": "raw_socket",
        "device_identified": False,
        "vendor": None,
        "product": None,
        "version": None,
        "registers_read": 0,
        "read_ok": False,
        "results": {},
        "errors": [],
    }
    summary.update(_safe_pymodbus_check() if PYMODBUS_AVAILABLE else {})

    # Single TCP connection reused across all probes (close on exit).
    try:
        with ModbusRawClient(HOST, PORT, timeout=TIMEOUT_S) as client:
            # 1. Device identification
            try:
                idr = probe_device_id(client)
                summary["device_identified"] = idr["device_identified"]
                summary["vendor"] = idr["vendor"]
                summary["product"] = idr["product"]
                summary["version"] = idr["version"]
                summary["results"]["device_id"] = {
                    "conformity_level": idr["conformity_level"],
                    "raw_objects": idr["raw_objects"],
                    "error": idr["error"],
                }
                if idr.get("error"):
                    summary["errors"].append(f"probe_device_id:{idr['error']}")
            except Exception as e:
                summary["errors"].append(f"probe_device_id:{type(e).__name__}:{e}")

            # 2. Read Coils (FC 0x01)
            try:
                cr = read_coils(client, addr=0, count=10)
                summary["results"]["read_coils"] = {
                    "count": cr["count"], "values": cr["values"],
                    "error": cr["error"],
                }
                if cr.get("error"):
                    summary["errors"].append(f"read_coils:{cr['error']}")
            except Exception as e:
                summary["errors"].append(f"read_coils:{type(e).__name__}:{e}")

            # 3. Read Holding Registers (FC 0x03)
            try:
                hr = read_holding_registers(client, addr=0, count=10)
                summary["results"]["read_holding_registers"] = {
                    "count": hr["count"], "values": hr["values"],
                    "error": hr["error"],
                }
                if hr.get("read_ok"):
                    summary["registers_read"] += hr["count"]
                if hr.get("error"):
                    summary["errors"].append(f"read_holding_registers:{hr['error']}")
            except Exception as e:
                summary["errors"].append(
                    f"read_holding_registers:{type(e).__name__}:{e}")

            # 4. Read Input Registers (FC 0x04)
            try:
                ir = read_input_registers(client, addr=0, count=10)
                summary["results"]["read_input_registers"] = {
                    "count": ir["count"], "values": ir["values"],
                    "error": ir["error"],
                }
                if ir.get("read_ok"):
                    summary["registers_read"] += ir["count"]
                if ir.get("error"):
                    summary["errors"].append(
                        f"read_input_registers:{ir['error']}")
            except Exception as e:
                summary["errors"].append(
                    f"read_input_registers:{type(e).__name__}:{e}")

            # read_ok = True if at least one of the 3 register/coil reads
            # succeeded without error.
            read_oks = [
                (summary["results"].get("read_coils", {}) or {}).get("count", 0) > 0,
                (summary["results"].get("read_holding_registers", {}) or {}).get(
                    "count", 0) > 0,
                (summary["results"].get("read_input_registers", {}) or {}).get(
                    "count", 0) > 0,
            ]
            summary["read_ok"] = any(read_oks)

    except (socket.timeout, TimeoutError):
        summary["errors"].append("transport:timeout")
        summary["results"]["transport_error"] = "timeout"
    except ConnectionRefusedError:
        summary["errors"].append("transport:ConnectionRefusedError")
        summary["results"]["transport_error"] = "connection_refused"
    except OSError as e:
        summary["errors"].append(f"transport:{type(e).__name__}:{e}")
        summary["results"]["transport_error"] = type(e).__name__
    except Exception as e:
        summary["errors"].append(f"transport:{type(e).__name__}:{e}")
        summary["results"]["transport_error"] = type(e).__name__

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
