#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — ethernetip_probe (OT protocol module)
# Read-only EtherNet/IP (CIP) probe for Allen-Bradley / Rockwell validation.
#
# Default port: 44818 (EtherNet/IP, IANA-assigned).
# Stack: TCP → EtherNet/IP encapsulation → CIP (Common Industrial Protocol).
#
# Probes performed (ALL read-only — no Forward_Open / Forward_Close / CIP
# WriteService / Message Router write):
#   1. NOP            (command 0x0000)             → transport test
#   2. ListIdentity   (command 0x0063)             → devices_found
#   3. ListServices   (command 0x0064)             → services_available
#   4. Forward Open   (READ_ONLY: check whether
#      the device would accept it — we DO NOT issue a real Forward Open.
#      Inference is performed by inspecting ListServices for the
#      "Connected" service flag and ListIdentity for "vendor" +
#      "device type". Result is reported as commands_would_be_accepted:
#      None / True / False.)
#
# EtherNet/IP encapsulation header (24 bytes, all LE):
#   Command(2) | Length(2) | SessionHandle(4) | Status(4) |
#   SenderContext(8) | Options(4) | [payload...]
#
# ListIdentity response payload (per item):
#   ID item length(4) | target identity:
#     ProtocolVersion(2) | FWINetAddress(4) | product name(16, fixed)
#     | VendorID(2) | DeviceType(2) | ProductCode(2) | Revision(2)
#     | Status(2) | SerialNumber(4) | ProductName len-prefixed
#
# ListServices response payload (per item):
#   Svc item length(4) | protocol version(2) | capability flags(2)
#   | service name (16 bytes ASCII)
#
# Reproducibility: SEED seeds the sender-context counter.
#
# Legal: isolated lab only (NERC CIP / ODVA EtherNet/IP Volume 2 / IEC 62443).
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
MODULE_NAME = "ethernetip_probe"
DEFAULT_PORT = 44818
TIMEOUT_S = 5.0

# EtherNet/IP commands
CMD_NOP                = 0x0000
CMD_LIST_SERVICES      = 0x0004
CMD_LIST_IDENTITY      = 0x0063
CMD_LIST_INTERFACES    = 0x0064
CMD_REGISTER_SESSION   = 0x0065
CMD_UNREGISTER_SESSION = 0x0066
CMD_SEND_RRDATA        = 0x006F          # unconnected explicit
CMD_SEND_UNITDATA      = 0x0070          # connected explicit (requires Forward Open)
CMD_FORWARD_OPEN       = 0x0054          # WRITE — never sent
CMD_FORWARD_CLOSE      = 0x004D          # WRITE — never sent

# Known CIP service codes (for inference only — we don't emit these)
CIP_READ_TAG           = 0x4C
CIP_WRITE_TAG          = 0x4D            # WRITE — never used

# Capability flags in ListServices response (ODVA Volume 2 §2-4.5)
SVC_CAPABILITY_CIP         = 0x0020
SVC_CAPABILITY_CONNECTED   = 0x0001       # supports connected messaging
SVC_CAPABILITY_UNCONNECTED = 0x0020       # supports unconnected explicit

# Vendor name lookup (subset of ODVA vendor IDs)
VENDOR_NAMES = {
    1:   "Rockwell Automation / Allen-Bradley",
    2:   "Rockwell Automation / Allen-Bradley",
    6:   "Honeywell",
    7:   "Allen-Bradley (legacy)",
    19:  "Softing",
    32:  "Hitachi",
    39:  "AsiaPower",
    43:  "Mitsubishi Electric",
    65:  "ABB",
    90:  "Bosch Rexroth",
    100: "Yaskawa Electric",
    188: "Emerson",
    234: "Schneider Electric",
    999: "B&R Industrial Automation",
}

# Device type lookup (subset of CIP device types)
DEVICE_TYPES = {
    0x0000: "General purpose",
    0x000C: "Communications adapter",
    0x0002: "AC drive",
    0x0006: "Analog I/O",
    0x0007: "Discrete I/O",
    0x0011: "Position controller",
    0x0001: "PLC",
    0x0017: "SoftLogix PLC",
    0x000D: "Safety",
}

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

SEED = int(os.environ.get("SEED", "1337"))
_CTX = random.Random(SEED).randint(0, 0xFFFFFFFFFFFFFFFF)

SECTOR_CFG = get_sector_config()
SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")


# ═══════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET EtherNet/IP CLIENT
# ═══════════════════════════════════════════════════════════════════════════
class ENIPRawClient:
    """Minimal EtherNet/IP client (raw sockets, no deps).

    Sends NOP / ListIdentity / ListServices. Never sends RegisterSession,
    Forward Open / Close, or SendUnitData (connected write path).
    """

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S):
        self.host = host
        self.port = port
        self.timeout = timeout
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

    def __enter__(self) -> "ENIPRawClient":
        self.connect(); return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── frame helpers ───────────────────────────────────────────────────
    def _build_encap(self, command: int, payload: bytes = b"",
                     session: int = 0) -> bytes:
        """Build a 24-byte EtherNet/IP encapsulation header + payload."""
        global _CTX
        _CTX = (_CTX + 1) & 0xFFFFFFFFFFFFFFFF
        # Header layout (all LE):
        #   Command(2) | Length(2) | SessionHandle(4) | Status(4)
        #   | SenderContext(8) | Options(4)
        hdr = struct.pack("<HHIIQI",
                          command & 0xFFFF,
                          len(payload) & 0xFFFF,
                          session & 0xFFFFFFFF,
                          0,                          # status (request = 0)
                          _CTX,                       # sender context
                          0)                          # options
        return hdr + payload

    def _send_recv(self, command: int, payload: bytes = b"",
                   session: int = 0) -> dict:
        """Send an encapsulated command and return the parsed response."""
        out = {"status": None, "command_recv": None, "session": None,
               "payload": b"", "error": None}
        try:
            frame = self._build_encap(command, payload, session)
            self.sock.sendall(frame)
            # Read 24-byte header
            hdr = self._recvn(24)
            if len(hdr) < 24:
                out["error"] = "truncated_encap_header"
                return out
            (cmd_recv, length, sess, status, _ctx, _opts) = struct.unpack(
                "<HHIIQI", hdr)
            out["command_recv"] = cmd_recv
            out["status"] = status
            out["session"] = sess
            # Read payload (may be empty)
            body = self._recvn(length) if length > 0 else b""
            out["payload"] = body
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"
        return out

    def _recvn(self, n: int) -> bytes:
        if self.sock is None:
            raise RuntimeError("socket not connected")
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    # ── high-level probes ───────────────────────────────────────────────
    def send_nop(self) -> dict:
        """Send NOP command (transport test)."""
        out = {"nop_ok": False, "error": None}
        r = self._send_recv(CMD_NOP)
        if r.get("error"):
            out["error"] = r["error"]
            return out
        if r.get("command_recv") == CMD_NOP:
            out["nop_ok"] = (r.get("status") == 0)
        else:
            out["error"] = (
                f"unexpected_command:0x{(r.get('command_recv') or 0):04X}")
        return out

    def send_list_identity(self) -> dict:
        """Send ListIdentity and decode devices."""
        out = {"devices_found": 0, "devices": [],
               "vendors": [], "product_names": [], "error": None}
        r = self._send_recv(CMD_LIST_IDENTITY)
        if r.get("error"):
            out["error"] = r["error"]
            return out
        if r.get("status") not in (0,):
            out["error"] = f"enip_status:0x{r.get('status', 0):08X}"
            return out
        payload = r.get("payload", b"")
        # Payload is a list of identity items:
        #   Item count(4) | items:
        #     TypeID(2) | ItemLength(2) | data(ItemLength)
        if len(payload) < 4:
            out["error"] = "short_list_identity"
            return out
        n_items = struct.unpack("<I", payload[:4])[0]
        idx = 4
        vendors = set()
        product_names = []
        device_types = []
        serials = []
        for _ in range(n_items):
            if idx + 4 > len(payload):
                break
            type_id, item_len = struct.unpack("<HH", payload[idx:idx+4])
            idx += 4
            if idx + item_len > len(payload):
                break
            item = payload[idx:idx+item_len]
            idx += item_len
            if type_id != 0x000C:       # 0x000C = CIP Identity item
                continue
            # CIP identity item layout:
            #   ProtocolVersion(2) | FWINetAddress(4) | ProductName(16, fixed)
            #   | VendorID(2) | DeviceType(2) | ProductCode(2)
            #   | RevisionMajor(1) RevisionMinor(1) | Status(2)
            #   | SerialNumber(4) | ProductNameLen(1) | ProductName(N)
            if len(item) < 1 + 2 + 4 + 16:
                continue
            # Actually first byte of item is "ProtocolVersion" indicator
            # Some implementations differ — we use the ODVA Volume 2 layout.
            try:
                # offset 0: ProtocolVersion(2) LE
                # offset 2: FWINetAddress (4) — 4-byte IPv4 BE wrapped
                proto_ver = struct.unpack("<H", item[0:2])[0]
                ip4 = ".".join(str(b) for b in item[2:6])
                # ProductName is a fixed 16-byte ASCII (older format) OR
                # short-name (LongName follows). We try to extract.
                fixed_name = item[6:22].decode("ascii", errors="replace").rstrip("\x00")
                # After fixed 16 bytes: VendorID(2) + DeviceType(2) +
                # ProductCode(2) + Revision(2) + Status(2) + Serial(4)
                if len(item) >= 22 + 14:
                    vendor_id, dev_type, prod_code = struct.unpack("<HHH", item[22:28])
                    rev_major, rev_minor = item[28], item[29]
                    dev_status = struct.unpack("<H", item[30:32])[0]
                    serial = struct.unpack("<I", item[32:36])[0]
                    # State/Status
                    # ProductName (LongName) follows: length-prefixed (1 B) + name
                    if len(item) >= 36 + 1:
                        name_len = item[36]
                        long_name = item[37:37+name_len].decode(
                            "ascii", errors="replace")
                    else:
                        long_name = fixed_name
                else:
                    vendor_id = 0
                    dev_type = 0
                    prod_code = 0
                    serial = 0
                    long_name = fixed_name
                vendor_name = VENDOR_NAMES.get(vendor_id, f"vendor_{vendor_id}")
                dev_type_name = DEVICE_TYPES.get(dev_type, f"type_0x{dev_type:04X}")
                vendors.add(vendor_name)
                product_names.append(long_name or fixed_name)
                device_types.append(dev_type_name)
                out["devices"].append({
                    "ip": ip4,
                    "protocol_version": proto_ver,
                    "vendor_id": vendor_id,
                    "vendor_name": vendor_name,
                    "device_type": dev_type_name,
                    "product_code": prod_code,
                    "revision": f"{rev_major}.{rev_minor}",
                    "status": dev_status,
                    "serial": f"0x{serial:08X}",
                    "product_name": long_name or fixed_name,
                })
            except Exception as e:
                # Skip malformed items gracefully
                continue
        out["devices_found"]   = len(out["devices"])
        out["vendors"]         = sorted(vendors)
        out["product_names"]   = product_names
        return out

    def send_list_services(self) -> dict:
        """Send ListServices and decode available services."""
        out = {"services_available": [], "supports_connected": False,
               "supports_unconnected": False, "error": None}
        r = self._send_recv(CMD_LIST_SERVICES)
        if r.get("error"):
            out["error"] = r["error"]
            return out
        if r.get("status") not in (0,):
            out["error"] = f"enip_status:0x{r.get('status', 0):08X}"
            return out
        payload = r.get("payload", b"")
        if len(payload) < 4:
            out["error"] = "short_list_services"
            return out
        n_items = struct.unpack("<I", payload[:4])[0]
        idx = 4
        for _ in range(n_items):
            if idx + 4 > len(payload):
                break
            type_id, item_len = struct.unpack("<HH", payload[idx:idx+4])
            idx += 4
            if idx + item_len > len(payload):
                break
            item = payload[idx:idx+item_len]
            idx += item_len
            if type_id != 0x0100:       # 0x0100 = CIP service item
                continue
            # Service item layout:
            #   ProtocolVersion(2) | CapabilityFlags(2) | ServiceName(16 B ASCII)
            if len(item) < 20:
                continue
            proto_ver = struct.unpack("<H", item[0:2])[0]
            cap_flags = struct.unpack("<H", item[2:4])[0]
            svc_name  = item[4:20].decode("ascii", errors="replace").rstrip("\x00")
            out["services_available"].append({
                "service": svc_name,
                "protocol_version": proto_ver,
                "capability_flags": f"0x{cap_flags:04X}",
                "supports_connected": bool(cap_flags & SVC_CAPABILITY_CONNECTED),
                "supports_unconnected": bool(cap_flags & SVC_CAPABILITY_UNCONNECTED),
            })
            if cap_flags & SVC_CAPABILITY_CONNECTED:
                out["supports_connected"] = True
            if cap_flags & SVC_CAPABILITY_UNCONNECTED:
                out["supports_unconnected"] = True
        return out

    def infer_forward_open_acceptance(self) -> dict:
        """READ_ONLY inference: would a Forward Open be accepted?

        We DO NOT issue a Forward Open. We infer from ListServices capability
        flags whether the device supports connected messaging (required for
        Forward Open to succeed at the CIP transport layer).
        Returns {commands_would_be_accepted: True/False/None, reason}.
        """
        out = {"commands_would_be_accepted": None, "reason": None}
        # The standalone ListServices call has already happened; we
        # rely on the caller to provide its output. This helper exists
        # as a clean inference surface and is used by main().
        return out


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
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
        "devices_found": 0,
        "vendors": [],
        "product_names": [],
        "services_available": [],
        "commands_would_be_accepted": None,
        "results": {},
        "errors": [],
    }

    try:
        with ENIPRawClient(HOST, PORT, timeout=TIMEOUT_S) as client:
            # 1. NOP transport test
            try:
                nop = client.send_nop()
                summary["results"]["nop"] = {
                    "nop_ok": nop.get("nop_ok"),
                    "error": nop.get("error"),
                }
                if nop.get("error"):
                    summary["errors"].append(f"nop:{nop['error']}")
            except Exception as e:
                summary["errors"].append(f"nop:{type(e).__name__}:{e}")

            # 2. ListIdentity
            try:
                li = client.send_list_identity()
                summary["devices_found"] = int(li.get("devices_found", 0))
                summary["vendors"]       = li.get("vendors", [])
                summary["product_names"] = li.get("product_names", [])
                summary["results"]["list_identity"] = {
                    "devices": li.get("devices"),
                    "error": li.get("error"),
                }
                if li.get("error"):
                    summary["errors"].append(
                        f"list_identity:{li['error']}")
            except Exception as e:
                summary["errors"].append(
                    f"list_identity:{type(e).__name__}:{e}")

            # 3. ListServices
            try:
                ls = client.send_list_services()
                summary["services_available"] = ls.get("services_available", [])
                summary["results"]["list_services"] = {
                    "supports_connected": ls.get("supports_connected"),
                    "supports_unconnected": ls.get("supports_unconnected"),
                    "services": ls.get("services_available"),
                    "error": ls.get("error"),
                }
                if ls.get("error"):
                    summary["errors"].append(
                        f"list_services:{ls['error']}")

                # 4. Infer Forward Open acceptance (READ_ONLY: no actual
                # Forward Open is sent). A device supports Forward Open iff
                # it advertises the "Connected" capability flag.
                if ls.get("supports_connected") is True:
                    summary["commands_would_be_accepted"] = True
                elif ls.get("supports_connected") is False and \
                     len(summary["services_available"]) > 0:
                    summary["commands_would_be_accepted"] = False
                else:
                    summary["commands_would_be_accepted"] = None
            except Exception as e:
                summary["errors"].append(
                    f"list_services:{type(e).__name__}:{e}")

            summary["device_identified"] = bool(
                summary["devices_found"] > 0 or summary["services_available"]
            )
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
