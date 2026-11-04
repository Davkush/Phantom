#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — modbus_probe
# OT/ICS validation module — Modbus TCP probing (read-only safe by default).
#
#   - Default port : 502 (Modbus TCP)
#   - Functions    : probe_device_id (FC 0x2B/0x0E), read_coils (FC 0x01),
#                    read_holding_registers (FC 0x03),
#                    try_write_register (FC 0x06, SAFE_MODE=full only)
#   - Uses pymodbus if installed, else falls back to raw socket Modbus TCP
#     packet crafting (no external dependency).
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
from typing import Optional, Tuple

# ─── Make sector_base importable from ../../sector_base.py ────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULES_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _MODULES_ROOT not in sys.path:
    sys.path.insert(0, _MODULES_ROOT)

from sector_base import (  # noqa: E402
    get_sector_config,
    check_write_allowed,
    is_write_allowed,
    get_safe_mode,
)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "modbus_probe"
DEFAULT_PORT = 502
TIMEOUT_S = 5.0
DEFAULT_UNIT_ID = 1

# ─── Optional pymodbus import (graceful degrade) ─────────────────────────
PYMODBUS_AVAILABLE = False
ModbusTcpClient = None
try:  # pymodbus >= 3.x
    from pymodbus.client import ModbusTcpClient as _ModbusTcpClientV3  # type: ignore
    ModbusTcpClient = _ModbusTcpClientV3
    PYMODBUS_AVAILABLE = True
except ImportError:
    try:  # pymodbus 2.x
        from pymodbus.client.sync import ModbusTcpClient as _ModbusTcpClientV2  # type: ignore
        ModbusTcpClient = _ModbusTcpClientV2
        PYMODBUS_AVAILABLE = True
    except ImportError:
        PYMODBUS_AVAILABLE = False


# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT


# ─── LAB guard ─────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    """Refuse to run unless LAB=1 is set (isolated lab authorization)."""
    return os.environ.get("LAB") == "1"


# ─── Sector / SAFE_MODE config ─────────────────────────────────────────────
SECTOR_CFG = get_sector_config()
SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")


# ═══════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET MODBUS TCP TRANSPORT (fallback when pymodbus missing)
# ═══════════════════════════════════════════════════════════════════════════
class ModbusRawClient:
    """Minimal Modbus TCP client using raw sockets (no external deps).

    Handles MBAP header (Transaction ID / Protocol ID / Length / Unit ID)
    + PDU. Suitable for read-coils, read-holding-registers, write-single-
    register and the Encapsulated Interface Read-Device-ID transport.
    """

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S, unit_id: int = DEFAULT_UNIT_ID):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.unit_id = unit_id
        self._txn = 0
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
        """Wrap a PDU with a fresh MBAP header."""
        self._txn = (self._txn + 1) & 0xFFFF
        txn = struct.pack(">H", self._txn)
        proto = b"\x00\x00"          # Modbus protocol = 0
        length = struct.pack(">H", len(pdu) + 1)  # +1 for Unit ID
        unit = struct.pack("B", self.unit_id)
        return txn + proto + length + unit + pdu

    def _send_recv(self, pdu: bytes, expected_min: int = 2) -> bytes:
        """Send PDU wrapped in MBAP, return only the response PDU."""
        if self.sock is None:
            raise RuntimeError("socket not connected")
        frame = self._build_mbap_pdu(pdu)
        self.sock.sendall(frame)
        # MBAP header = 7 bytes; then PDU
        header = self._recvn(7)
        if len(header) < 7:
            raise OSError("truncated_mbap_header")
        _txn, _proto, length, unit = struct.unpack(">HHHB", header)
        pdu_len = max(length - 1, 0)  # length field counts the unit_id byte
        pdu_len = max(pdu_len, expected_min)
        resp_pdu = self._recvn(pdu_len)
        return resp_pdu

    def _recvn(self, n: int) -> bytes:
        """Read exactly n bytes from socket (handles partial reads)."""
        if self.sock is None:
            raise RuntimeError("socket not connected")
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf


# ═══════════════════════════════════════════════════════════════════════════
#  PROBE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
def _decode_id_objects(pdu: bytes) -> dict:
    """Parse a Read-Device-ID response PDU into {obj_id: value_str}.

    Response layout (after FC+MEI):
      Function(0x2B) MEI(0x0E) ReadDevID(1) ConformityLevel(1)
      MoreFollows(1) NextObjectID(1) NumObjects(1)
      then for each object: ObjID(1) ObjLen(1) Value(ObjLen)
    """
    out: dict = {}
    # Need at least the 7-byte fixed header (FC + MEI + ReadDevID + Conformity
    # + MoreFollows + NextObjID + NumObjects).
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


# Known basic device-id object IDs → friendly names
_ID_OBJ_NAMES = {
    0x00: "vendor",
    0x01: "product_code",
    0x02: "major_minor_revision",
    0x03: "vendor_url",
    0x04: "product_name",
    0x05: "model_name",
    0x06: "user_application_name",
}


def probe_device_id() -> dict:
    """Read Device Identification (FC 0x2B / MEI 0x0E, ReadDevID=Basic).

    Returns dict: device_identified, vendor, product, version, raw_objects.
    """
    result = {
        "device_identified": False,
        "vendor": None,
        "product": None,
        "version": None,
        "raw_objects": {},
        "error": None,
    }
    # FC=0x2B, MEI=0x0E, ReadDevID=0x01 (Basic), ObjectID=0x00
    pdu_req = bytes([0x2B, 0x0E, 0x01, 0x00])

    def _do_raw(c: ModbusRawClient) -> bytes:
        return c._send_recv(pdu_req, expected_min=8)

    def _do_pymodbus(client) -> Optional[bytes]:
        # pymodbus 3.x: client.read_device_id()
        try:
            rr = client.read_device_id(unit=DEFAULT_UNIT_ID)
        except TypeError:
            # older signatures
            rr = client.read_device_id()
        if rr is None or getattr(rr, "isError", lambda: True)():
            return b""
        # Reconstruct a pseudo-PDU so the parser works
        objs = getattr(rr, "information", {}) or {}
        pdu = bytes([0x2B, 0x0E, 0x01, 0x00, 0x00, len(objs)])
        for oid, val in objs.items():
            if isinstance(val, str):
                vb = val.encode("utf-8", errors="replace")
            else:
                vb = bytes(val)
            pdu += bytes([int(oid) & 0xFF, len(vb)]) + vb
        return pdu

    try:
        pdu_resp = _dispatch(_do_raw, _do_pymodbus)
    except (socket.timeout, TimeoutError) as e:
        result["error"] = "timeout"
        return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
        return result

    if not pdu_resp or len(pdu_resp) < 2:
        result["error"] = "empty_response"
        return result
    # Validate function code echo (0x2B) and MEI type (0x0E)
    if pdu_resp[0] != 0x2B or (len(pdu_resp) > 1 and pdu_resp[1] != 0x0E):
        # Exception response: FC = 0xAB (0x2B | 0x80)
        if pdu_resp[0] == 0xAB:
            result["error"] = f"modbus_exception:0x{pdu_resp[1]:02X}"
        else:
            result["error"] = f"unexpected_fc:0x{pdu_resp[0]:02X}"
        return result
    objs = _decode_id_objects(pdu_resp)
    named = {_ID_OBJ_NAMES.get(k, f"obj_{k:02x}"): v for k, v in objs.items()}
    result["raw_objects"] = {str(k): v for k, v in objs.items()}
    result["vendor"] = named.get("vendor")
    result["product"] = named.get("product_code") or named.get("product_name")
    result["version"] = named.get("major_minor_revision")
    result["device_identified"] = any(
        v is not None for v in (result["vendor"], result["product"], result["version"])
    )
    return result


def read_coils(addr: int = 0, count: int = 10) -> dict:
    """Read Coils (FC 0x01). Returns {read_ok, values, count, error}."""
    pdu_req = struct.pack(">BHH", 0x01, addr & 0xFFFF, count & 0xFFFF)
    result = {"read_ok": False, "values": [], "count": 0, "error": None}

    def _do_raw(c: ModbusRawClient) -> bytes:
        return c._send_recv(pdu_req, expected_min=2)

    def _do_pymodbus(client) -> Optional[bytes]:
        rr = client.read_coils(addr, count, slave=DEFAULT_UNIT_ID) \
            if "slave" in client.read_coils.__doc__ else \
            client.read_coils(addr, count, unit=DEFAULT_UNIT_ID)
        # Fallback to no unit kwarg if both fail
        return _pymodbus_to_pdu(rr, fc=0x01)

    try:
        pdu_resp = _dispatch(_do_raw, _do_pymodbus)
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
        return result

    if not pdu_resp or len(pdu_resp) < 2:
        result["error"] = "empty_response"
        return result
    if pdu_resp[0] == 0x81:  # exception
        result["error"] = f"modbus_exception:0x{pdu_resp[1]:02X}"
        return result
    if pdu_resp[0] != 0x01:
        result["error"] = f"unexpected_fc:0x{pdu_resp[0]:02X}"
        return result
    byte_count = pdu_resp[1]
    bits_data = pdu_resp[2:2 + byte_count]
    bits = []
    for i in range(count):
        byte_i = i // 8
        bit_i = i % 8
        if byte_i < len(bits_data):
            bits.append((bits_data[byte_i] >> bit_i) & 0x01)
    result["values"] = bits
    result["count"] = len(bits)
    result["read_ok"] = True
    return result


def read_holding_registers(addr: int = 0, count: int = 10) -> dict:
    """Read Holding Registers (FC 0x03). Returns {read_ok, values, error}."""
    pdu_req = struct.pack(">BHH", 0x03, addr & 0xFFFF, count & 0xFFFF)
    result = {"read_ok": False, "values": [], "count": 0, "error": None}

    def _do_raw(c: ModbusRawClient) -> bytes:
        return c._send_recv(pdu_req, expected_min=2)

    def _do_pymodbus(client) -> Optional[bytes]:
        rr = client.read_holding_registers(addr, count, slave=DEFAULT_UNIT_ID)
        return _pymodbus_to_pdu(rr, fc=0x03)

    try:
        pdu_resp = _dispatch(_do_raw, _do_pymodbus)
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
        return result

    if not pdu_resp or len(pdu_resp) < 2:
        result["error"] = "empty_response"
        return result
    if pdu_resp[0] == 0x83:
        result["error"] = f"modbus_exception:0x{pdu_resp[1]:02X}"
        return result
    if pdu_resp[0] != 0x03:
        result["error"] = f"unexpected_fc:0x{pdu_resp[0]:02X}"
        return result
    byte_count = pdu_resp[1]
    reg_data = pdu_resp[2:2 + byte_count]
    values = []
    for i in range(0, len(reg_data) - 1, 2):
        values.append(struct.unpack(">H", reg_data[i:i + 2])[0])
    result["values"] = values
    result["count"] = len(values)
    result["read_ok"] = True
    return result


def try_write_register(addr: int = 0, value: int = 0) -> dict:
    """Write Single Register (FC 0x06). ONLY attempted if SAFE_MODE=full.

    Respects SAFE_MODE : if read_only → returns write_skipped_safe_mode and
    does NOT emit any packet. When SAFE_MODE=full, calls check_write_allowed()
    as a defense-in-depth guard before sending.
    """
    result = {
        "write_tested": False,
        "write_ok": False,
        "addr": addr,
        "value": value,
        "status": None,
        "error": None,
    }

    # SAFE_MODE gate — primary guard (do not exit, just skip).
    if not is_write_allowed():
        result["status"] = "write_skipped_safe_mode"
        return result

    # Defense-in-depth: sector_base guard (would exit(3) if somehow bypassed).
    # We call it only after our own check passed — keeps semantics explicit.
    check_write_allowed(MODULE_NAME)

    pdu_req = struct.pack(">BHH", 0x06, addr & 0xFFFF, value & 0xFFFF)

    def _do_raw(c: ModbusRawClient) -> bytes:
        return c._send_recv(pdu_req, expected_min=5)

    def _do_pymodbus(client) -> Optional[bytes]:
        rr = client.write_register(addr, value, slave=DEFAULT_UNIT_ID)
        return _pymodbus_to_pdu(rr, fc=0x06)

    try:
        pdu_resp = _dispatch(_do_raw, _do_pymodbus)
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        result["status"] = "timeout"
        return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        result["status"] = "conn_error"
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
        result["status"] = "error"
        return result

    result["write_tested"] = True
    if not pdu_resp or len(pdu_resp) < 2:
        result["status"] = "empty_response"
        return result
    if pdu_resp[0] == 0x86:
        result["error"] = f"modbus_exception:0x{pdu_resp[1]:02X}"
        result["status"] = "modbus_exception"
        return result
    if pdu_resp[0] != 0x06:
        result["error"] = f"unexpected_fc:0x{pdu_resp[0]:02X}"
        result["status"] = "unexpected_fc"
        return result
    # Echo validation: server returns addr+value echoed back
    if len(pdu_resp) >= 5:
        r_addr, r_val = struct.unpack(">HH", pdu_resp[1:5])
        if r_addr == (addr & 0xFFFF) and r_val == (value & 0xFFFF):
            result["write_ok"] = True
            result["status"] = "write_ok"
        else:
            result["status"] = "echo_mismatch"
            result["error"] = f"expected {(addr, value)}, got {(r_addr, r_val)}"
    else:
        result["status"] = "short_response"
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  DISPATCH : use pymodbus if available, else raw socket
# ═══════════════════════════════════════════════════════════════════════════
def _dispatch(raw_fn, pymodbus_fn) -> bytes:
    """Execute the given function under the appropriate transport.

    raw_fn   : callable(ModbusRawClient) -> bytes (response PDU)
    pymodbus_fn : callable(client) -> bytes|None (response PDU, or None to
                 signal "use raw fallback for this call").

    A single connection is opened for the duration of the call. If pymodbus
    is unavailable, the raw socket path is used.
    """
    if PYMODBUS_AVAILABLE and ModbusTcpClient is not None:
        try:
            client = ModbusTcpClient(HOST, port=PORT, timeout=TIMEOUT_S)
            try:
                if hasattr(client, "connect"):
                    client.connect()
                pdu = pymodbus_fn(client)
                if pdu is None:
                    raise RuntimeError("pymodbus_call_returned_none")
                return pdu
            finally:
                if hasattr(client, "close"):
                    client.close()
        except Exception:
            # Fall back to raw socket on ANY pymodbus failure
            pass
    # Raw socket path
    with ModbusRawClient(HOST, PORT, timeout=TIMEOUT_S) as c:
        return raw_fn(c)


def _pymodbus_to_pdu(rr, fc: int) -> Optional[bytes]:
    """Convert a pymodbus response object into a pseudo-PDU for our parsers.

    Returns None to signal the caller to fall back to raw socket.
    """
    if rr is None:
        return None
    if getattr(rr, "isError", lambda: False)():
        # Exception response
        exc = getattr(rr, "exception_code", 1) or 1
        return bytes([fc | 0x80, int(exc) & 0xFF])
    if fc in (0x01,):
        bits = list(getattr(rr, "bits", []) or [])
        if not bits:
            return None
        byte_count = (len(bits) + 7) // 8
        out = bytearray([fc, byte_count])
        for byte_i in range(byte_count):
            b = 0
            for bit_i in range(8):
                idx = byte_i * 8 + bit_i
                if idx < len(bits) and bits[idx]:
                    b |= (1 << bit_i)
            out.append(b)
        return bytes(out)
    if fc in (0x03,):
        regs = list(getattr(rr, "registers", []) or [])
        if not regs:
            return None
        out = bytearray([fc, len(regs) * 2])
        for r in regs:
            out += struct.pack(">H", int(r) & 0xFFFF)
        return bytes(out)
    if fc in (0x06,):
        addr = int(getattr(rr, "address", 0)) & 0xFFFF
        val = int(getattr(rr, "value", 0)) & 0xFFFF
        return bytes([fc]) + struct.pack(">HH", addr, val)
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("Modbus probing on production PLCs is illegal "
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
        "library": "pymodbus" if PYMODBUS_AVAILABLE else "raw_socket",
        "device_identified": False,
        "vendor": None,
        "product": None,
        "version": None,
        "read_ok": False,
        "write_tested": False,
        "write_status": None,
        "registers_sample": [],
        "coils_sample": [],
        "errors": [],
    }

    # 1. Device identification
    try:
        idr = probe_device_id()
        summary["device_identified"] = idr["device_identified"]
        summary["vendor"] = idr["vendor"]
        summary["product"] = idr["product"]
        summary["version"] = idr["version"]
        if idr.get("error"):
            summary["errors"].append(f"probe_device_id:{idr['error']}")
    except Exception as e:
        summary["errors"].append(f"probe_device_id:{type(e).__name__}:{e}")

    # 2. Read coils (FC 0x01) — no auth
    try:
        cr = read_coils(addr=0, count=10)
        summary["coils_sample"] = cr.get("values", [])
        if cr.get("error"):
            summary["errors"].append(f"read_coils:{cr['error']}")
    except Exception as e:
        summary["errors"].append(f"read_coils:{type(e).__name__}:{e}")

    # 3. Read holding registers (FC 0x03)
    try:
        rr = read_holding_registers(addr=0, count=10)
        summary["registers_sample"] = rr.get("values", [])
        summary["read_ok"] = bool(rr.get("read_ok"))
        if rr.get("error"):
            summary["errors"].append(f"read_holding_registers:{rr['error']}")
    except Exception as e:
        summary["errors"].append(f"read_holding_registers:{type(e).__name__}:{e}")

    # 4. Write test (FC 0x06) — only if SAFE_MODE=full
    try:
        wr = try_write_register(addr=0, value=0)
        summary["write_tested"] = bool(wr.get("write_tested"))
        summary["write_status"] = wr.get("status")
        if wr.get("error"):
            summary["errors"].append(f"try_write_register:{wr['error']}")
    except SystemExit:
        # check_write_allowed may call sys.exit(3) on read_only sector —
        # already gated above, but guard against any unexpected exit.
        raise
    except Exception as e:
        summary["errors"].append(f"try_write_register:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
