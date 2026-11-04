#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — bacnet_probe (OT protocol module)
# Read-only BACnet probe for building automation / HVAC validation.
#
# Default port: 47808 (0xBAC0, BACnet/IP, IANA-assigned).
# Stack: UDP → BACnet Virtual Link Layer (BVLC) → NPDU → APDU.
#
# Probes performed (ALL read-only — no WriteProperty / AtomicWriteFile):
#   1. Send Who-Is (local subnet broadcast, range 0..0xFFFF) → collect I-Am
#   2. Read Device Object Name        (obj type 8, instance 0, property 77)
#   3. Read Device Object Vendor Name (obj type 8, instance 0, property 120)
#   4. Count devices found
#
# BACnet/IP frame layout:
#   BVLC: Type(1, 0x81) | Function(1, 0x0B=original-broadcast-NPDU /
#         0x0A=original-unicast-NPDU) | Length(2, BE, total BVLC+NPDU+APDU)
#   NPDU: Version(1, 0x01) | Control(1) | (DNET/DADR/SNET/SADR if control set)
#         | HopCount(1) | MessageType(1) | VendorID(2) if network-specific
#   APDU: PDU type bits (0=confirmed-request) | service choice | args
#
# Confirmed ReadProperty APDU (service choice 0x0C):
#   PDU type(0x00 invoke-id high bits 0) | invoke-id(1) | service-choice(0x0C)
#   | obj-type(2, BE) | obj-instance(4, low 22 bits)
#   | property-id(2, BE) | (optional array-index)
#
# Who-Is / I-Am (unconfirmed, service choice 0x08 / 0x00):
#   APDU: 0x10 (unconfirmed, no segmentation) | service(0x08 Who-Is)
#   args: device-type(2) | device-instance-low(4) | device-type(2) |
#         device-instance-high(4) → range [low..high]
#
# Reproducibility: SEED seeds the invoke-ID sequence.
#
# Legal: isolated lab only (ASHRAE 135 / NIS2 / IEC 62443).
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
MODULE_NAME = "bacnet_probe"
DEFAULT_PORT = 0xBAC0              # 47808
TIMEOUT_S = 5.0

# BVLC function codes
BVLC_ORIG_UNICAST    = 0x0A
BVLC_ORIG_BROADCAST  = 0x0B
BVLC_RESULT          = 0x00
BVLC_READ_BCAST_DIST = 0x02
BVLC_FORIGN_NPDU     = 0x04

# NPDU control bits
NPDU_NET_LAYER_MSG     = 0x80
NPDU_DEST_EXPLICIT     = 0x20
NPDU_SRC_EXPLICIT      = 0x08
NPDU_DATA_EXPECTING_REPLY = 0x04
NPDU_PRIORITY_NORMAL   = 0x00

# BACnet object types
OBJ_DEVICE    = 8
OBJ_ANALOG_IN = 0
OBJ_ANALOG_OUT = 1
OBJ_ANALOG_VAL = 2

# BACnet property identifiers (subset)
PROP_OBJECT_NAME     = 77
PROP_VENDOR_NAME     = 120
PROP_VENDOR_ID       = 120   # alias for clarity
PROP_MODEL_NAME      = 70
PROP_FIRMWARE_REV    = 12
PROP_APPL_SW_VER     = 13
PROP_DESCRIPTION     = 28
PROP_LOCATION        = 58
PROP_PROTOCOL_SERVICES = 96

# BACnet APDU / service codes
PDU_TYPE_CONFIRMED_REQ   = 0x00      # top 4 bits
PDU_TYPE_UNCONFIRMED_REQ = 0x10
PDU_TYPE_SIMPLE_ACK      = 0x20
PDU_TYPE_COMPLEX_ACK     = 0x30
PDU_TYPE_ERROR           = 0x50
PDU_TYPE_REJECT          = 0x60
PDU_TYPE_ABORT           = 0x80
SEGMENTED_BOTH           = 0x00

SVC_UNCONF_WHO_IS = 0x08
SVC_UNCONF_I_AM   = 0x00
SVC_READ_PROPERTY = 0x0C
SVC_WRITE_PROPERTY = 0x0F           # WRITE — never sent
SVC_READ_PROP_MULTIPLE = 0x0E

# Tag classes
TAG_CLASS_APP = 0
TAG_CLASS_CTX = 1

# Default broadcast target
DEFAULT_BROADCAST = "255.255.255.255"

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

SEED = int(os.environ.get("SEED", "1337"))
_INVOKE_ID = random.Random(SEED).randint(0, 0xFF)

SECTOR_CFG = get_sector_config()
SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")


# ═══════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET BACNET CLIENT
# ═══════════════════════════════════════════════════════════════════════════
class BacnetRawClient:
    """Minimal BACnet/IP client (raw UDP sockets, no deps).

    Sends Who-Is broadcast + ReadProperty unicast. Parses I-Am and ReadProperty
    responses. Never emits WriteProperty / AtomicWriteFile / SubscribeCOV.
    """

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S,
                 broadcast_addr: str = DEFAULT_BROADCAST):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.broadcast_addr = broadcast_addr
        self.sock: Optional[socket.socket] = None

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(self.timeout)
        # Bind to ephemeral port for receiving
        self.sock.bind(("0.0.0.0", 0))

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self) -> "BacnetRawClient":
        self.connect(); return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── frame builders ──────────────────────────────────────────────────
    @staticmethod
    def _encode_obj_id(obj_type: int, instance: int) -> bytes:
        """Encode a BACnet object identifier (4 bytes, big-endian).

        Layout: type(10 bits) | instance(22 bits)
        """
        v = ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF)
        return struct.pack(">I", v)

    @staticmethod
    def _decode_obj_id(raw: bytes) -> tuple:
        """Decode a 4-byte object identifier → (type, instance)."""
        v = struct.unpack(">I", raw)[0]
        return ((v >> 22) & 0x3FF, v & 0x3FFFFF)

    def _build_npdu(self, control: int = 0x00) -> bytes:
        """Build a minimal NPDU (no source/dest network fields)."""
        return bytes([0x01, control])         # version 1, control

    def _build_whois(self, lo: int = 0, hi: int = 0x3FFFFF) -> bytes:
        """Build a Who-Is broadcast frame."""
        # APDU: 0x10 (unconfirmed) | 0x08 (Who-Is) | range
        apdu = bytes([PDU_TYPE_UNCONFIRMED_REQ, SVC_UNCONF_WHO_IS])
        # Range: lo instance, hi instance, each as object-identifier with
        # object type = DEVICE (8). Spec actually wants just the instance
        # numbers tagged, but the typical Who-Is uses tag 0/1 (context) for
        # low and high device instance (4 bytes each, tagged with context
        # class, tag number 0/1, length 4).
        # Context-tagged device-instance (tag 0 = low, tag 1 = high)
        # Encoding: tag(1) = (class=1)<<3 | (tag<<0) | len(4)
        # Tag byte: 0x08 (CTX, tag 0, len 4) ; 0x19 (CTX, tag 1, len 4)
        lo_bytes = struct.pack(">I", lo)
        hi_bytes = struct.pack(">I", hi)
        apdu += bytes([0x0C]) + lo_bytes        # CTX tag 0, len 4
        apdu += bytes([0x1C]) + hi_bytes        # CTX tag 1, len 4
        # BVLC: 0x81 | 0x0B (orig-broadcast) | length BE
        bvlc = bytes([0x81, BVLC_ORIG_BROADCAST])
        npdu = self._build_npdu(0x00)
        total = 4 + len(npdu) + len(apdu)
        bvlc += struct.pack(">H", total)
        return bvlc + npdu + apdu

    def _build_read_property(self, obj_type: int, instance: int,
                             property_id: int, invoke_id: int = 0) -> bytes:
        """Build a ReadProperty confirmed-request frame."""
        # APDU: type(0=confirmed) + invoke-id(1) + service-choice(0x0C)
        # Confirmed request PDU header (no segmentation):
        #   bit 7..4 = 0 (type confirmed-req)
        #   bit 3    = segmented? 0
        #   bit 2    = more follows? 0
        #   bit 1..0 = segment count bits (00 when not segmented)
        # Then: invoke-id (1 byte)
        # Then: service-choice (1 byte) = 0x0C
        # Then: service-request args:
        #   object-identifier (4 B app-tagged: tag 12, len 4)
        #   property-identifier (tag 12 context, 1 B value if 0..255)
        apdu = bytes([PDU_TYPE_CONFIRMED_REQ, invoke_id & 0xFF, SVC_READ_PROPERTY])
        # Object identifier — context tag 0, length 4
        apdu += bytes([0x0C]) + self._encode_obj_id(obj_type, instance)
        # Property identifier — context tag 1, length 1 (since < 256)
        if property_id < 256:
            apdu += bytes([0x19]) + bytes([property_id & 0xFF])
        else:
            apdu += bytes([0x1A]) + struct.pack(">H", property_id)
        # NPDU: data expecting reply
        npdu = self._build_npdu(NPDU_DATA_EXPECTING_REPLY | NPDU_PRIORITY_NORMAL)
        # BVLC: 0x81 | 0x0A (orig-unicast) | length BE
        bvlc = bytes([0x81, BVLC_ORIG_UNICAST])
        total = 4 + len(npdu) + len(apdu)
        bvlc += struct.pack(">H", total)
        return bvlc + npdu + apdu

    # ── send / receive ──────────────────────────────────────────────────
    def send_whois(self, listen_s: float = 2.0) -> dict:
        """Send Who-Is broadcast and collect I-Am responses for `listen_s`.

        We use a shorter listen window than `self.timeout` so the overall
        module budget (Who-Is + read-property probes) stays within ~5 s when
        nothing responds on an isolated lab network.
        """
        out = {"devices_found": 0, "i_am_responses": [], "error": None}
        try:
            frame = self._build_whois(lo=0, hi=0x3FFFFF)
            # Send to broadcast address and the host (if host is unicast)
            for addr in {self.broadcast_addr, self.host}:
                try:
                    self.sock.sendto(frame, (addr, self.port))
                except OSError:
                    pass
            # Collect I-Am responses for up to listen_s seconds.
            deadline = time.time() + listen_s
            seen_instances = set()
            while time.time() < deadline:
                # Short per-iteration socket timeout so we re-evaluate the
                # deadline frequently and can collect multiple I-Am frames.
                self.sock.settimeout(min(0.5, max(0.1, deadline - time.time())))
                try:
                    data, addr = self.sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                parsed = self._parse_i_am(data, addr)
                if parsed:
                    iid = parsed.get("device_instance")
                    if iid is not None and iid not in seen_instances:
                        seen_instances.add(iid)
                        out["i_am_responses"].append(parsed)
            out["devices_found"] = len(seen_instances)
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"
        return out

    def _parse_i_am(self, data: bytes, addr: tuple) -> Optional[dict]:
        """Parse an I-Am response. Returns dict or None if not I-Am."""
        if len(data) < 4:
            return None
        # BVLC (4) + NPDU (2+) + APDU
        if data[0] != 0x81:
            return None
        bvlc_func = data[1]
        if bvlc_func not in (BVLC_ORIG_UNICAST, BVLC_ORIG_BROADCAST):
            return None
        # NPDU: skip to APDU (version + control, optionally network fields)
        # For a minimal NPDU (no network fields), APDU starts at offset 6.
        # We'll detect by skipping the BVLC length + NPDU header (2).
        bvlc_len = struct.unpack(">H", data[2:4])[0]
        if bvlc_len > len(data):
            return None
        npdu_off = 4
        if len(data) < npdu_off + 2:
            return None
        npdu_ver = data[npdu_off]
        npdu_ctrl = data[npdu_off + 1]
        idx = npdu_off + 2
        # If DNET/DADR present, skip
        if npdu_ctrl & NPDU_DEST_EXPLICIT:
            if idx + 2 > len(data): return None
            dnet = struct.unpack(">H", data[idx:idx+2])[0]
            idx += 2
            if dnet != 0xFFFF:
                dlen = data[idx]; idx += 1 + dlen
        if npdu_ctrl & NPDU_SRC_EXPLICIT:
            if idx + 2 > len(data): return None
            snet = struct.unpack(">H", data[idx:idx+2])[0]
            idx += 2
            slen = data[idx]; idx += 1 + slen
        if npdu_ctrl & (NPDU_DEST_EXPLICIT | NPDU_SRC_EXPLICIT):
            idx += 1   # hop count
        # APDU: type(1) | service(1) ...
        if idx + 2 > len(data):
            return None
        apdu_type = data[idx]
        svc = data[idx + 1]
        idx += 2
        if apdu_type != PDU_TYPE_UNCONFIRMED_REQ or svc != SVC_UNCONF_I_AM:
            return None
        # I-Am args: object-identifier (app tag 12) + max-APDU (tag 2 unsigned)
        # + segmentation (tag 3) + vendor-id (tag 4)
        # Parse app-tagged values
        objs = []
        while idx < len(data) and len(objs) < 4:
            tag = data[idx]
            tag_class = (tag >> 3) & 0x01
            tag_num    = (tag >> 0) & 0x07 if (tag & 0x08) else (tag >> 4)
            length = tag & 0x07
            idx += 1
            if length == 5:
                length = data[idx]; idx += 1
            elif length == 6:
                length = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
            elif length == 7:
                length = struct.unpack(">I", data[idx:idx+4])[0]; idx += 4
            val = data[idx:idx+length]; idx += length
            objs.append((tag_class, tag_num, val))
        if len(objs) < 4:
            return None
        # objs[0] = device object-identifier (4 B), objs[1] = max-APDU (2 B),
        # objs[2] = segmentation (1 B), objs[3] = vendor-id (2 B)
        try:
            obj_type, instance = self._decode_obj_id(objs[0][2])
            vendor_id = struct.unpack(">H", objs[3][2])[0] if len(objs[3][2]) == 2 else objs[3][2][0]
            max_apdu = struct.unpack(">H", objs[1][2])[0] if len(objs[1][2]) == 2 else objs[1][2][0]
        except Exception:
            return None
        return {
            "device_instance": instance,
            "object_type": obj_type,
            "vendor_id": vendor_id,
            "max_apdu": max_apdu,
            "source_ip": addr[0] if isinstance(addr, tuple) else str(addr),
        }

    # ── read property ───────────────────────────────────────────────────
    def read_property(self, obj_type: int, instance: int, property_id: int,
                       target_ip: Optional[str] = None) -> dict:
        """Send a ReadProperty to a device and parse the response."""
        global _INVOKE_ID
        _INVOKE_ID = (_INVOKE_ID + 1) & 0xFF
        out = {"read_ok": False, "value": None, "raw_response_hex": "",
               "error": None}
        target = target_ip or self.host
        try:
            frame = self._build_read_property(obj_type, instance, property_id,
                                              invoke_id=_INVOKE_ID)
            self.sock.sendto(frame, (target, self.port))
            # Wait for the matching Complex ACK. Cap the inner wait at 1.0 s
            # per iteration so we don't burn the entire TIMEOUT_S budget on
            # a single unanswered probe.
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                self.sock.settimeout(min(1.0, max(0.2, deadline - time.time())))
                try:
                    data, addr = self.sock.recvfrom(2048)
                except socket.timeout:
                    break
                except OSError:
                    break
                parsed = self._parse_complex_ack(data, _INVOKE_ID)
                if parsed:
                    out["read_ok"] = parsed["read_ok"]
                    out["value"]   = parsed["value"]
                    out["raw_response_hex"] = parsed["raw_hex"]
                    if parsed.get("error"):
                        out["error"] = parsed["error"]
                    return out
            out["error"] = "no_response"
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"
        return out

    def _parse_complex_ack(self, data: bytes, invoke_id: int) -> Optional[dict]:
        """Parse a Complex ACK response to a ReadProperty request."""
        if len(data) < 6 or data[0] != 0x81:
            return None
        bvlc_len = struct.unpack(">H", data[2:4])[0]
        if bvlc_len > len(data):
            return None
        npdu_off = 4
        if len(data) < npdu_off + 2:
            return None
        npdu_ctrl = data[npdu_off + 1]
        idx = npdu_off + 2
        if npdu_ctrl & NPDU_DEST_EXPLICIT:
            if idx + 2 > len(data): return None
            dnet = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
            if dnet != 0xFFFF:
                dlen = data[idx]; idx += 1 + dlen
        if npdu_ctrl & NPDU_SRC_EXPLICIT:
            if idx + 2 > len(data): return None
            snet = struct.unpack(">H", data[idx:idx+2])[0]; idx += 2
            slen = data[idx]; idx += 1 + slen
        if npdu_ctrl & (NPDU_DEST_EXPLICIT | NPDU_SRC_EXPLICIT):
            idx += 1
        if idx + 2 > len(data):
            return None
        apdu_type = data[idx]
        recv_invoke = data[idx + 1]
        svc = data[idx + 2]
        idx += 3
        # Complex ACK top nibble = 0x3
        if (apdu_type & 0xF0) != PDU_TYPE_COMPLEX_ACK:
            return None
        if recv_invoke != (invoke_id & 0xFF):
            return None
        if svc != SVC_READ_PROPERTY:
            return None
        # Skip object-identifier (context tag 0, 5 bytes incl tag) and
        # property-identifier (context tag 1, 1 or 2 bytes).
        # Look for the opening-tag (0x3E) which delimits the value.
        opening = bytes([0x3E])
        closing = bytes([0x3F])
        o = data.find(opening, idx)
        if o < 0:
            return {"read_ok": False, "value": None,
                    "raw_hex": data.hex(), "error": "no_opening_tag"}
        c = data.find(closing, o + 1)
        if c < 0:
            c = len(data)
        # Inside [o+1 .. c] there's typically one or more application-tagged
        # values. We extract a best-effort string or hex.
        content = data[o + 1:c]
        value: object
        if len(content) >= 1:
            tag = content[0]
            tag_num = (tag >> 4) & 0x0F
            tag_len = tag & 0x07
            payload = content[1:1 + tag_len]
            if tag_num == 7:        # character string
                if len(payload) >= 1:
                    # First byte = encoding (0 = ANSI/UTF-8)
                    value = payload[1:].decode("utf-8", errors="replace")
                else:
                    value = payload.hex()
            else:
                value = payload.hex() if payload else None
        else:
            value = None
        return {"read_ok": True, "value": value,
                "raw_hex": data.hex(), "error": None}


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
        "device_names": [],
        "vendors": [],
        "read_ok": False,
        "results": {},
        "errors": [],
    }

    try:
        with BacnetRawClient(HOST, PORT, timeout=TIMEOUT_S) as client:
            # 1. Who-Is broadcast → collect I-Am
            try:
                wi = client.send_whois()
                summary["devices_found"] = int(wi.get("devices_found", 0))
                summary["results"]["who_is"] = {
                    "devices_found": wi.get("devices_found"),
                    "i_am_responses": wi.get("i_am_responses"),
                    "error": wi.get("error"),
                }
                if wi.get("error"):
                    summary["errors"].append(f"who_is:{wi['error']}")
            except Exception as e:
                summary["errors"].append(f"who_is:{type(e).__name__}:{e}")

            # 2 & 3. For each discovered device, read Device Object Name (prop 77)
            # and Vendor Name (prop 120). Also try the explicit host target
            # even if no I-Am was received (may be a unicast-only device).
            # Cap the number of targets probed to keep the module within the
            # harness 5 s timeout budget on large / unresponsive networks.
            targets_to_probe = []
            seen = set()
            for iam in (summary["results"].get("who_is", {}) or {}).get(
                    "i_am_responses", []) or []:
                src = iam.get("source_ip")
                if src and src not in seen:
                    seen.add(src)
                    targets_to_probe.append(src)
            if HOST not in seen:
                targets_to_probe.append(HOST)

            # Limit to at most 3 targets × 2 read-property calls each
            # (≈ 3 × 2 × 1 s = 6 s worst case, well within orchestration budget).
            MAX_TARGETS = 3
            targets_to_probe = targets_to_probe[:MAX_TARGETS]

            names = []
            vendors = []
            any_read_ok = False
            for tgt in targets_to_probe:
                # Read Object Name (property 77) of Device Object (type 8, inst 0)
                rn = client.read_property(OBJ_DEVICE, 0, PROP_OBJECT_NAME,
                                          target_ip=tgt)
                if rn.get("read_ok"):
                    any_read_ok = True
                    if isinstance(rn.get("value"), str):
                        names.append(rn["value"])
                # Read Vendor Name (property 120) — note: in BACnet, prop 120
                # is "Vendor Name" (added in rev 16+). Many devices expose only
                # the 2-byte vendor identifier; we try both.
                rv = client.read_property(OBJ_DEVICE, 0, PROP_VENDOR_NAME,
                                          target_ip=tgt)
                if rv.get("read_ok"):
                    any_read_ok = True
                    if isinstance(rv.get("value"), str):
                        vendors.append(rv["value"])
            summary["device_names"] = names
            summary["vendors"] = vendors
            summary["read_ok"] = any_read_ok

            summary["device_identified"] = bool(
                summary["devices_found"] > 0 or any_read_ok)

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
