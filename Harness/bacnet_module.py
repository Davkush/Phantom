#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — bacnet_probe
# Energy/building automation module — BACnet/IP (ASHRAE 135) probing.
#
#   - Default port : 47808 (0xBAC0, UDP — BACnet/IP)
#   - Functions    : send_whois            (BVLC Original-Broadcast-NPDU +
#                                              Unconfirmed Who-Is → collect
#                                              I-Am responses → device inventory),
#                    read_device_id        (ReadProperty Device.ObjectIdentifier,
#                                              instance 0, property 1),
#                    read_device_name      (ReadProperty Device.ObjectName,
#                                              property 77),
#                    read_analog_inputs    (ReadProperty AnalogInput.present-value,
#                                              instances 0-10, property 85),
#                    try_write_analog_output (WriteProperty AnalogOutput.
#                                              present-value — SAFE_MODE=full only)
#   - Raw UDP socket implementation: full BVLC + NPDU + APDU builder.
#       BVLC: 0x81 [function] [length BE 2]
#       NPDU: version(0x01) + control(0x08 expecting reply) + optional
#             DNET/DLEN/DADR/SNET/SLEN/SADR
#       APDU: PDU type (high nibble) + invoke ID + service choice + service
#             request. Tag encoding: class(bit 7) | tag_number(4 bits << 4) |
#             length(4 bits). Length 0x0E = opening tag, 0x0F = closing tag.
#   - Respects SAFE_MODE : if read_only, write is skipped and reported as
#     "write_skipped_safe_mode" (NO packet emitted — writing to an analog
#     output can drive a physical actuator/valve/damper).
#   - LAB=1 mandatory. 5 s timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (energy) : NERC CIP, NIS2, ENISA, ASHRAE 135.
#
# Output JSON (top-level fields required by the spec):
#   devices_found (list of {instance, vendor, name}),
#   analog_inputs_read, write_tested
import json
import os
import socket
import struct
import sys
import time
from typing import Optional, Tuple, List, Iterable

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
MODULE_NAME = "bacnet_probe"
DEFAULT_PORT = 47808
TIMEOUT_S = 5.0

# ─── BACnet/IP BVLC constants ──────────────────────────────────────────────
BVLC_TYPE                  = 0x81
BVLC_FUNC_ORIG_UNICAST_NPDU  = 0x0A
BVLC_FUNC_ORIG_BROADCAST_NPDU = 0x0B

# ─── NPDU control bits ─────────────────────────────────────────────────────
NPDU_VERSION = 0x01
NPDU_CTRL_EXPECTING_REPLY = 0x08
NPDU_CTRL_HAS_DEST        = 0x80
NPDU_CTRL_HAS_SOURCE      = 0x20

# ─── APDU PDU types (high nibble of byte 0) ────────────────────────────────
PDU_TYPE_CONFIRMED_REQ    = 0x00
PDU_TYPE_UNCONFIRMED_REQ  = 0x10
PDU_TYPE_SIMPLE_ACK       = 0x20
PDU_TYPE_COMPLEX_ACK      = 0x30
PDU_TYPE_ERROR            = 0x50

# ─── Service choices ───────────────────────────────────────────────────────
SVC_WHO_IS        = 0x08
SVC_I_AM          = 0x00
SVC_READ_PROPERTY = 0x0C
SVC_WRITE_PROPERTY = 0x0F

# ─── BACnet object types (10-bit field of ObjectIdentifier) ────────────────
OBJ_TYPE_ANALOG_INPUT  = 0
OBJ_TYPE_ANALOG_OUTPUT = 1
OBJ_TYPE_DEVICE        = 8

# ─── BACnet property identifiers ───────────────────────────────────────────
PROP_OBJECT_IDENTIFIER = 1
PROP_OBJECT_NAME       = 77
PROP_PRESENT_VALUE     = 85
PROP_VENDOR_NAME       = 121
PROP_VENDOR_ID         = 120

# ─── Analog-input instance range for read_analog_inputs ────────────────────
ANALOG_INPUT_RANGE = range(0, 11)   # 0..10 inclusive

# Default device instance to probe (used when no device responds to Who-Is).
DEFAULT_DEVICE_INSTANCE = 0

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "255.255.255.255"
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
#  OBJECT IDENTIFIER HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def encode_object_id(obj_type: int, instance: int) -> bytes:
    """4-byte big-endian encoding of a BACnet ObjectIdentifier."""
    val = ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF)
    return struct.pack(">I", val)


def parse_object_id(data: bytes) -> Tuple[int, int]:
    """Decode a 4-byte BE ObjectIdentifier → (type, instance)."""
    if len(data) < 4:
        return (0, 0)
    val = struct.unpack(">I", data[:4])[0]
    obj_type = (val >> 22) & 0x3FF
    instance = val & 0x3FFFFF
    return (obj_type, instance)


# ═══════════════════════════════════════════════════════════════════════════
#  BACNET TAG ENCODERS
# ═══════════════════════════════════════════════════════════════════════════
# Tag byte layout:
#   bit 7      : class (0=application, 1=context)
#   bits 6-4   : tag number (0..14)
#   bits 3-0   : length (0..5 = direct, 5 = ext 1-byte, 6 = ext 2-byte,
#                7 = ext 3-byte, 14 = opening tag, 15 = closing tag)
# BACnet application tag numbers per ASHRAE 135-2016 Table 20-2.
# Note: tag 11 is *reserved* and ObjectIdentifier is tag **12** (byte 0xC0
# for length-0, 0xC4 for length-4) — this is what real BACnet devices and
# Wireshark use. (Some older spec revisions swap 11/12; we follow the
# de-facto wire encoding.)
APP_TAG_NULL      = 0
APP_TAG_BOOLEAN   = 1
APP_TAG_UNSIGNED  = 2
APP_TAG_SIGNED    = 3
APP_TAG_REAL      = 4
APP_TAG_DOUBLE    = 5
APP_TAG_OCTET_STR = 6
APP_TAG_CHAR_STR  = 7
APP_TAG_BIT_STR   = 8
APP_TAG_DATE      = 9
APP_TAG_TIME      = 10
APP_TAG_OBJ_ID    = 12   # ← ObjectIdentifier (tag byte 0xC4 for len-4)
APP_TAG_RESERVED  = 11   # unused on the wire
APP_TAG_ERROR     = 13


def _encode_length_nibble(tag_byte: int, length: int) -> bytes:
    """Append the proper length-encoding bytes for a tag with given payload."""
    if length <= 5:
        return bytes([tag_byte | length])
    elif length <= 0xFF:
        return bytes([tag_byte | 0x05, length])
    elif length <= 0xFFFF:
        return bytes([tag_byte | 0x06]) + struct.pack(">H", length)
    else:
        return bytes([tag_byte | 0x07]) + struct.pack(">I", length)[1:]


def encode_app_unsigned(value: int) -> bytes:
    """BACnet application-tagged UnsignedInt (tag 2)."""
    if value < 0:
        raise ValueError("unsigned must be non-negative")
    if value <= 0xFF:
        payload = bytes([value & 0xFF])
    elif value <= 0xFFFF:
        payload = struct.pack(">H", value)
    elif value <= 0xFFFFFF:
        payload = struct.pack(">I", value)[1:]
    else:
        payload = struct.pack(">I", value)
    return _encode_length_nibble(APP_TAG_UNSIGNED << 4, len(payload)) + payload


def encode_app_object_id(obj_type: int, instance: int) -> bytes:
    """BACnet application-tagged ObjectIdentifier (tag 11)."""
    payload = encode_object_id(obj_type, instance)
    return _encode_length_nibble(APP_TAG_OBJ_ID << 4, 4) + payload


def encode_app_real(value: float) -> bytes:
    """BACnet application-tagged Real (tag 4, IEEE-754 single)."""
    payload = struct.pack(">f", value)
    return _encode_length_nibble(APP_TAG_REAL << 4, 4) + payload


def encode_app_char_string(s: str) -> bytes:
    """BACnet application-tagged CharacterString (tag 7, ANSI/UTF-8)."""
    # Encoding byte 0x00 = ANSI X3.4 / UTF-8 (treat as UTF-8 here).
    payload = bytes([0x00]) + s.encode("utf-8", errors="replace")
    return _encode_length_nibble(APP_TAG_CHAR_STR << 4, len(payload)) + payload


def encode_ctx_tag(tag_number: int, payload: bytes) -> bytes:
    """Context-specific tagged value (length is implicit in payload)."""
    tag_byte = 0x80 | ((tag_number & 0x0F) << 4)
    return _encode_length_nibble(tag_byte, len(payload)) + payload


def ctx_open_tag(tag_number: int) -> bytes:
    """Opening context tag (length nibble = 0x0E = 14)."""
    return bytes([0x80 | ((tag_number & 0x0F) << 4) | 0x0E])


def ctx_close_tag(tag_number: int) -> bytes:
    """Closing context tag (length nibble = 0x0F = 15)."""
    return bytes([0x80 | ((tag_number & 0x0F) << 4) | 0x0F])


# ═══════════════════════════════════════════════════════════════════════════
#  BVLC / NPDU / APDU BUILDERS
# ═══════════════════════════════════════════════════════════════════════════
def build_bvlc(function: int, npdu_apdu: bytes) -> bytes:
    """Wrap an NPDU+APDU in a BVLC header (type 0x81, function, length BE 2)."""
    total_len = 4 + len(npdu_apdu)
    return bytes([BVLC_TYPE, function]) + struct.pack(">H", total_len) + npdu_apdu


def build_npdu_broadcast() -> bytes:
    """NPDU for a broadcast message: version=0x01, control=0x08 (expecting reply).

    No source/destination network fields — the broadcast is handled at the
    IP/UDP layer (BVLC function 0x0B), and the receiver will respond directly
    to our UDP source address.
    """
    return bytes([NPDU_VERSION, NPDU_CTRL_EXPECTING_REPLY])


def build_npdu_unicast() -> bytes:
    """NPDU for a unicast confirmed request (expecting reply)."""
    return bytes([NPDU_VERSION, NPDU_CTRL_EXPECTING_REPLY])


def build_whois_apdu() -> bytes:
    """Who-Is (Unconfirmed-Req, service choice 0x08, no params = all devices)."""
    return bytes([PDU_TYPE_UNCONFIRMED_REQ, SVC_WHO_IS])


def build_readprop_apdu(invoke_id: int, obj_type: int, instance: int,
                        prop_id: int) -> bytes:
    """ReadProperty (Confirmed-Req, service choice 0x0C)."""
    pdu = bytes([PDU_TYPE_CONFIRMED_REQ, invoke_id & 0xFF, SVC_READ_PROPERTY])
    # Object Identifier (context tag 0, length 4)
    pdu += encode_ctx_tag(0, encode_object_id(obj_type, instance))
    # Property Identifier (context tag 1, length 1 for prop_id < 256)
    pdu += encode_ctx_tag(1, bytes([prop_id & 0xFF]))
    return pdu


def build_writeprop_real_apdu(invoke_id: int, obj_type: int, instance: int,
                              prop_id: int, value: float) -> bytes:
    """WriteProperty with a real value (Confirmed-Req, service choice 0x0F)."""
    pdu = bytes([PDU_TYPE_CONFIRMED_REQ, invoke_id & 0xFF, SVC_WRITE_PROPERTY])
    pdu += encode_ctx_tag(0, encode_object_id(obj_type, instance))
    pdu += encode_ctx_tag(1, bytes([prop_id & 0xFF]))
    # Value wrapped in opening/closing context tag 3
    pdu += ctx_open_tag(3) + encode_app_real(value) + ctx_close_tag(3)
    return pdu


# ═══════════════════════════════════════════════════════════════════════════
#  APDU PARSER
# ═══════════════════════════════════════════════════════════════════════════
# Note on BACnet tag encoding (ASHRAE 135-2016 §20.2):
#   The upper 4 bits of the tag byte combine the class bit (bit 7) and the
#   3-bit tag number (bits 6-4). In Wireshark's actual dissection code this
#   is exposed as a single 4-bit "tag number" 0..15 (the spec calls this the
#   "Tag Number"; bit 7 doubles as the class indicator).
#
#   Practical consequence: an application-tagged ObjectIdentifier has tag byte
#   0xC4 (upper nibble = 0xC = 12), which is indistinguishable on the wire
#   from a context-specific tag 4 length 4. Real BACnet devices and Wireshark
#   use position-based interpretation: in a slot expecting an application
#   ObjectIdentifier (e.g. I-Am), 0xC4 = ObjectIdentifier; in a slot expecting
#   a context tag 4 (e.g. some ReadProperty-ACK variants), 0xC4 = ctx tag 4.
#
#   To keep things unambiguous we expose TWO fields per tag:
#     * tag_id     : the raw upper nibble (0..15)
#     * tag_class  : 0 = application, 1 = context (= tag_id >> 3)
#   and we expose the 3-bit tag number for context tags as (tag_id & 0x07).
#   Parsers below use tag_id directly for application tags (e.g. 0xC for
#   ObjectIdentifier) and (tag_id & 0x07) for context tags (e.g. 0 for ctx 0).
def iter_tags(body: bytes, start: int = 0
              ) -> Iterable[Tuple[int, int, int, bytes]]:
    """Yield (tag_id, length, value) tuples from `body`.

    tag_id is the raw upper nibble of the tag byte (0..15). For opening
    context tags, length = -1 and value = b"". For closing context tags,
    length = -2 and value = b"". Stops at end of `body` or on malformed tag.
    """
    pos = start
    while pos < len(body):
        tag_byte = body[pos]
        length_nibble = tag_byte & 0x0F
        tag_id = (tag_byte >> 4) & 0x0F
        pos += 1
        if length_nibble == 0x0E:
            # Opening context tag
            yield (tag_id, -1, b"")
            continue
        if length_nibble == 0x0F:
            # Closing context tag
            yield (tag_id, -2, b"")
            continue
        if length_nibble <= 4:
            length = length_nibble
        elif length_nibble == 5:
            if pos + 1 > len(body):
                return
            length = body[pos]; pos += 1
        elif length_nibble == 6:
            if pos + 2 > len(body):
                return
            length = struct.unpack(">H", body[pos:pos + 2])[0]; pos += 2
        elif length_nibble == 7:
            if pos + 3 > len(body):
                return
            length = (body[pos] << 16) | (body[pos + 1] << 8) | body[pos + 2]
            pos += 3
        else:
            return
        if pos + length > len(body):
            return
        value = body[pos:pos + length]
        pos += length
        yield (tag_id, length, value)


def parse_i_am(apdu: bytes) -> Optional[dict]:
    """Parse an I-Am response (Unconfirmed-Req, service choice 0x00).

    Expected layout (all application-tagged, in order):
      ObjectIdentifier (tag_id 0xC, len 4)   → obj_type, instance
      UnsignedInt      (tag_id 0x2)          → max APDU
      UnsignedInt      (tag_id 0x2)          → segmentation
      UnsignedInt      (tag_id 0x2)          → vendor ID
    """
    if len(apdu) < 2:
        return None
    if apdu[0] != PDU_TYPE_UNCONFIRMED_REQ or apdu[1] != SVC_I_AM:
        return None
    body = apdu[2:]
    out = {"obj_type": None, "instance": None,
           "max_apdu": None, "segmentation": None, "vendor_id": None}
    unsigned_count = 0
    for tag_id, length, value in iter_tags(body):
        if tag_id == APP_TAG_OBJ_ID and length == 4:
            ot, inst = parse_object_id(value)
            out["obj_type"] = ot
            out["instance"] = inst
        elif tag_id == APP_TAG_UNSIGNED and length and value:
            uval = int.from_bytes(value, "big")
            if unsigned_count == 0:
                out["max_apdu"] = uval
            elif unsigned_count == 1:
                out["segmentation"] = uval
            elif unsigned_count == 2:
                out["vendor_id"] = uval
            unsigned_count += 1
    return out if out["instance"] is not None else None


def parse_readprop_ack(apdu: bytes) -> Optional[dict]:
    """Parse a ReadProperty-ACK (Complex-ACK, service choice 0x0C).

    Expected layout (after the 3-byte APDU header):
      ctx tag 0 (tag_id 0x8, len 4)         → object identifier
      ctx tag 1 (tag_id 0x9, len 1)         → property identifier
      [optional ctx tag 2 array index]
      ctx open tag 3 (tag_id 0xB, len -1)   → value start
      <application-tagged value bytes>
      ctx close tag 3 (tag_id 0xB, len -2)  → value end

    Returns dict with obj_type, instance, prop_id, value_bytes (the raw bytes
    between the opening and closing context tags of the value), or None.
    """
    if len(apdu) < 3:
        return None
    if (apdu[0] & 0xF0) != PDU_TYPE_COMPLEX_ACK:
        return None
    service_choice = apdu[2]
    if service_choice != SVC_READ_PROPERTY:
        return None
    body = apdu[3:]
    out = {"obj_type": None, "instance": None,
           "prop_id": None, "value_bytes": b""}
    in_value = False
    value_buf = bytearray()
    for tag_id, length, value in iter_tags(body):
        if length == -1:
            # Opening context tag → start collecting value bytes
            in_value = True
            value_buf = bytearray()
            continue
        if length == -2:
            # Closing context tag → end of value
            if in_value:
                out["value_bytes"] = bytes(value_buf)
                break
            continue
        if in_value:
            # Re-emit the original tag byte(s) so a downstream decoder
            # can use iter_tags again on value_bytes.
            tag_byte = (tag_id << 4)
            if length <= 4:
                value_buf.append(tag_byte | length)
            elif length <= 0xFF:
                value_buf.append(tag_byte | 0x05)
                value_buf.append(length)
            elif length <= 0xFFFF:
                value_buf.append(tag_byte | 0x06)
                value_buf += struct.pack(">H", length)
            else:
                value_buf.append(tag_byte | 0x07)
                value_buf += struct.pack(">I", length)[1:]
            value_buf += value
        else:
            # ctx tag 0 (tag_id 0x8) = object identifier
            if tag_id == 0x8 and length == 4:
                ot, inst = parse_object_id(value)
                out["obj_type"] = ot
                out["instance"] = inst
            # ctx tag 1 (tag_id 0x9) = property identifier
            elif tag_id == 0x9 and value:
                out["prop_id"] = int.from_bytes(value, "big")
    return out if out["value_bytes"] else None


def parse_simple_ack_or_error(apdu: bytes) -> dict:
    """Classify a SimpleACK or Error response."""
    if len(apdu) < 3:
        return {"type": "unknown"}
    ptype = apdu[0] & 0xF0
    if ptype == PDU_TYPE_SIMPLE_ACK:
        return {"type": "simple_ack", "invoke_id": apdu[1],
                "service": apdu[2]}
    if ptype == PDU_TYPE_ERROR:
        # Error response: invoke ID + service choice + error class + error code
        body = apdu[3:] if len(apdu) > 3 else b""
        error_class = None
        error_code = None
        unsigned_count = 0
        for tag_id, length, value in iter_tags(body):
            if tag_id == APP_TAG_UNSIGNED and value:
                uval = int.from_bytes(value, "big")
                if unsigned_count == 0:
                    error_class = uval
                elif unsigned_count == 1:
                    error_code = uval
                unsigned_count += 1
        return {"type": "error", "invoke_id": apdu[1],
                "service": apdu[2], "error_class": error_class,
                "error_code": error_code}
    return {"type": "other", "ptype": ptype}


def decode_value_bytes(value_bytes: bytes):
    """Decode application-tagged value bytes to a Python value (best effort).

    Returns: int, float, str, (obj_type, instance), or hex string.
    """
    for tag_id, length, value in iter_tags(value_bytes):
        if tag_id == APP_TAG_UNSIGNED and value:
            return int.from_bytes(value, "big")
        if tag_id == APP_TAG_SIGNED and value:
            return int.from_bytes(value, "big", signed=True)
        if tag_id == APP_TAG_REAL and length == 4:
            return struct.unpack(">f", value)[0]
        if tag_id == APP_TAG_DOUBLE and length == 8:
            return struct.unpack(">d", value)[0]
        if tag_id == APP_TAG_OBJ_ID and length == 4:
            return parse_object_id(value)
        if tag_id == APP_TAG_CHAR_STR and value:
            # First byte is the encoding (0x00 = ANSI/UTF-8)
            try:
                return value[1:].decode("utf-8", errors="replace")
            except Exception:
                return value.hex()
        if tag_id == APP_TAG_BOOLEAN:
            return bool(length)
        return value.hex()
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  BACNET UDP TRANSPORT
# ═══════════════════════════════════════════════════════════════════════════
class BacnetUdpClient:
    """Minimal BACnet/IP UDP client (raw sockets, no external deps)."""

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        self.sock.settimeout(self.timeout)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self) -> "BacnetUdpClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── senders ──────────────────────────────────────────────────────────
    def send_to(self, data: bytes, addr: Tuple[str, int]) -> None:
        if self.sock is None:
            raise RuntimeError("socket not connected")
        self.sock.sendto(data, addr)

    def send_bvlc_broadcast(self, npdu_apdu: bytes,
                            addr: Tuple[str, int]) -> None:
        pkt = build_bvlc(BVLC_FUNC_ORIG_BROADCAST_NPDU, npdu_apdu)
        self.send_to(pkt, addr)

    def send_bvlc_unicast(self, npdu_apdu: bytes,
                          addr: Tuple[str, int]) -> None:
        pkt = build_bvlc(BVLC_FUNC_ORIG_UNICAST_NPDU, npdu_apdu)
        self.send_to(pkt, addr)

    # ── receivers ────────────────────────────────────────────────────────
    def recv_one(self, timeout: float = 1.0
                 ) -> Optional[Tuple[Tuple[str, int], bytes]]:
        if self.sock is None:
            raise RuntimeError("socket not connected")
        old_to = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(4096)
            return (addr, data)
        except (socket.timeout, TimeoutError):
            return None
        finally:
            self.sock.settimeout(old_to)

    def recv_multiple(self, window_s: float = 2.0,
                      per_recv_timeout: float = 0.5
                      ) -> List[Tuple[Tuple[str, int], bytes]]:
        """Collect all responses that arrive within `window_s`."""
        results: List[Tuple[Tuple[str, int], bytes]] = []
        deadline = time.time() + window_s
        while time.time() < deadline:
            r = self.recv_one(timeout=per_recv_timeout)
            if r is None:
                continue
            results.append(r)
        return results


def _strip_bvlc_npdu(packet: bytes) -> Tuple[Optional[str], Optional[bytes]]:
    """Strip BVLC + NPDU headers and return (npdu_ctrl, apdu_bytes)."""
    if len(packet) < 4:
        return (None, None)
    if packet[0] != BVLC_TYPE:
        return (None, None)
    bvlc_func = packet[1]
    bvlc_len = struct.unpack(">H", packet[2:4])[0]
    if bvlc_len < 4 or bvlc_len > len(packet):
        return (None, None)
    npdu_start = 4
    if len(packet) < npdu_start + 2:
        return (None, None)
    npdu_version = packet[npdu_start]
    npdu_ctrl = packet[npdu_start + 1]
    pos = npdu_start + 2
    # Skip optional destination network info
    if npdu_ctrl & NPDU_CTRL_HAS_DEST:
        if pos + 3 > len(packet):
            return (None, None)
        dlen = packet[pos + 2]
        pos += 3 + dlen
    # Skip optional source network info
    if npdu_ctrl & NPDU_CTRL_HAS_SOURCE:
        if pos + 3 > len(packet):
            return (None, None)
        slen = packet[pos + 2]
        pos += 3 + slen
    # Hop count if expecting reply and dest present
    if (npdu_ctrl & NPDU_CTRL_HAS_DEST) and (npdu_ctrl & 0x80):
        pos += 1
    apdu = packet[pos:bvlc_len]
    return (f"0x{npdu_ctrl:02X}", apdu)


# ═══════════════════════════════════════════════════════════════════════════
#  PROBE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
def send_whois(client: BacnetUdpClient,
               broadcast_addr: Tuple[str, int] = (HOST, PORT),
               listen_s: float = 2.0) -> dict:
    """Broadcast Who-Is and collect I-Am responses → device inventory.

    Returns: dict with `devices` (list of {addr, instance, vendor_id, obj_type})
    and `error`.
    """
    result = {"devices": [], "bytes_sent": 0, "error": None}
    try:
        npdu = build_npdu_broadcast()
        apdu = build_whois_apdu()
        pkt = build_bvlc(BVLC_FUNC_ORIG_BROADCAST_NPDU, npdu + apdu)
        client.send_to(pkt, broadcast_addr)
        result["bytes_sent"] = len(pkt)
        # Collect I-Am responses
        responses = client.recv_multiple(window_s=listen_s,
                                          per_recv_timeout=0.5)
        for addr, data in responses:
            _ctrl, apdu_resp = _strip_bvlc_npdu(data)
            if not apdu_resp:
                continue
            iam = parse_i_am(apdu_resp)
            if iam and iam["instance"] is not None:
                result["devices"].append({
                    "addr": f"{addr[0]}:{addr[1]}",
                    "instance": iam["instance"],
                    "vendor_id": iam.get("vendor_id"),
                    "obj_type": iam.get("obj_type"),
                })
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def _send_readprop(client: BacnetUdpClient, addr: Tuple[str, int],
                   obj_type: int, instance: int, prop_id: int,
                   invoke_id: int = 1) -> Optional[dict]:
    """Send a unicast ReadProperty request and return the parsed ACK."""
    apdu = build_readprop_apdu(invoke_id, obj_type, instance, prop_id)
    pkt = build_bvlc(BVLC_FUNC_ORIG_UNICAST_NPDU,
                     build_npdu_unicast() + apdu)
    client.send_to(pkt, addr)
    r = client.recv_one(timeout=2.0)
    if r is None:
        return None
    _addr, data = r
    _ctrl, apdu_resp = _strip_bvlc_npdu(data)
    if not apdu_resp or len(apdu_resp) < 1:
        return None
    ptype = apdu_resp[0] & 0xF0
    if ptype == PDU_TYPE_COMPLEX_ACK:
        return parse_readprop_ack(apdu_resp)
    else:
        return {"error": parse_simple_ack_or_error(apdu_resp)}


def read_device_id(client: BacnetUdpClient, device_addr: Tuple[str, int],
                   instance: int = DEFAULT_DEVICE_INSTANCE) -> dict:
    """ReadProperty Device.ObjectIdentifier (instance 0, prop 1)."""
    result = {"instance_read": False, "device_instance": None,
              "obj_type": None, "error": None}
    try:
        r = _send_readprop(client, device_addr, OBJ_TYPE_DEVICE,
                           instance, PROP_OBJECT_IDENTIFIER)
        if r is None:
            result["error"] = "timeout"
            return result
        if "error" in r:
            result["error"] = str(r["error"])
            return result
        val = decode_value_bytes(r.get("value_bytes", b""))
        if isinstance(val, tuple) and len(val) == 2:
            result["obj_type"] = val[0]
            result["device_instance"] = val[1]
            result["instance_read"] = True
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def read_device_name(client: BacnetUdpClient, device_addr: Tuple[str, int],
                     instance: int = DEFAULT_DEVICE_INSTANCE) -> dict:
    """ReadProperty Device.ObjectName (property 77)."""
    result = {"name_read": False, "name": None, "error": None}
    try:
        r = _send_readprop(client, device_addr, OBJ_TYPE_DEVICE,
                           instance, PROP_OBJECT_NAME)
        if r is None:
            result["error"] = "timeout"
            return result
        if "error" in r:
            result["error"] = str(r["error"])
            return result
        val = decode_value_bytes(r.get("value_bytes", b""))
        if val is not None:
            result["name"] = val if isinstance(val, str) else str(val)
            result["name_read"] = True
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def read_analog_inputs(client: BacnetUdpClient,
                       device_addr: Tuple[str, int]) -> dict:
    """ReadProperty AnalogInput.present-value (instances 0-10, prop 85)."""
    result = {"analog_inputs_read": False, "values": [],
              "instances_read": 0, "errors": []}
    for inst in ANALOG_INPUT_RANGE:
        try:
            r = _send_readprop(client, device_addr,
                               OBJ_TYPE_ANALOG_INPUT, inst,
                               PROP_PRESENT_VALUE,
                               invoke_id=(inst + 2) & 0xFF)
            if r is None:
                result["errors"].append(f"instance_{inst}:timeout")
                continue
            if "error" in r:
                result["errors"].append(
                    f"instance_{inst}:{r['error'].get('type', 'error')}"
                )
                continue
            val = decode_value_bytes(r.get("value_bytes", b""))
            result["values"].append({"instance": inst, "value": val})
            result["instances_read"] += 1
        except Exception as e:
            result["errors"].append(f"instance_{inst}:{type(e).__name__}:{e}")
    result["analog_inputs_read"] = result["instances_read"] > 0
    return result


def try_write_analog_output(client: BacnetUdpClient,
                            device_addr: Tuple[str, int],
                            instance: int = 0,
                            value: float = 0.0) -> dict:
    """WriteProperty AnalogOutput.present-value — SAFE_MODE=full only.

    Respects SAFE_MODE: if read_only, returns "write_skipped_safe_mode" and
    emits NO packet — writing to an analog output can drive a physical
    actuator/valve/damper.
    """
    result = {"write_tested": False, "instance": instance, "value": value,
              "status": None, "error": None}

    # SAFE_MODE gate — primary guard (do not exit, just skip).
    if not is_write_allowed():
        result["status"] = "write_skipped_safe_mode"
        return result

    # Defense-in-depth: sector_base guard (would exit(3) if bypassed).
    check_write_allowed(MODULE_NAME)

    try:
        apdu = build_writeprop_real_apdu(invoke_id=42,
                                         obj_type=OBJ_TYPE_ANALOG_OUTPUT,
                                         instance=instance,
                                         prop_id=PROP_PRESENT_VALUE,
                                         value=value)
        pkt = build_bvlc(BVLC_FUNC_ORIG_UNICAST_NPDU,
                         build_npdu_unicast() + apdu)
        client.send_to(pkt, device_addr)
        result["write_tested"] = True
        r = client.recv_one(timeout=2.0)
        if r is None:
            result["status"] = "timeout"
            return result
        _addr, data = r
        _ctrl, apdu_resp = _strip_bvlc_npdu(data)
        if not apdu_resp or len(apdu_resp) < 1:
            result["status"] = "no_response"
            return result
        parsed = parse_simple_ack_or_error(apdu_resp)
        if parsed.get("type") == "simple_ack":
            result["status"] = "write_accepted"
        elif parsed.get("type") == "error":
            result["status"] = f"write_rejected:cls={parsed.get('error_class')},code={parsed.get('error_code')}"
            result["error"] = parsed
        else:
            result["status"] = f"unexpected_response:{parsed.get('type')}"
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        result["status"] = "timeout"
        result["write_tested"] = True
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        result["status"] = "conn_error"
        result["write_tested"] = True
    except SystemExit:
        # check_write_allowed may sys.exit(3) — propagate cleanly.
        raise
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
        result["status"] = "error"
        result["write_tested"] = True
    return result


def _parse_addr(addr_str: str, default_port: int = DEFAULT_PORT) -> Tuple[str, int]:
    """Parse "host:port" or "host" into (host, int)."""
    if ":" in addr_str:
        host, _, port_s = addr_str.rpartition(":")
        try:
            return (host, int(port_s))
        except ValueError:
            return (addr_str, default_port)
    return (addr_str, default_port)


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("BACnet probing on production building automation "
                           "is illegal outside an authorized lab. "
                           "NERC CIP / NIS2 / ENISA / ASHRAE 135."),
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
        "transport": "raw_udp_socket",
        # Spec-required top-level output fields:
        "devices_found": [],
        "analog_inputs_read": False,
        "write_tested": False,
        # Detail / error reporting:
        "details": {},
        "errors": [],
    }

    broadcast_addr = (HOST, PORT)

    try:
        with BacnetUdpClient(HOST, PORT, timeout=TIMEOUT_S) as client:
            # 1. Who-Is broadcast → discover devices
            wi = send_whois(client, broadcast_addr=broadcast_addr,
                            listen_s=2.0)
            summary["details"]["whois"] = {
                "bytes_sent": wi["bytes_sent"],
                "raw_devices": wi["devices"],
                "error": wi.get("error"),
            }
            if wi.get("error"):
                summary["errors"].append(f"send_whois:{wi['error']}")

            discovered = wi.get("devices", [])
            if not discovered:
                # No I-Am responses — fall back to the CLI host as a single
                # device target so the rest of the probes can still attempt
                # unicast reads.
                discovered = [{
                    "addr": f"{HOST}:{PORT}",
                    "instance": DEFAULT_DEVICE_INSTANCE,
                    "vendor_id": None,
                    "obj_type": OBJ_TYPE_DEVICE,
                    "_fallback": True,
                }]

            # 2. For each discovered device: read_device_id + read_device_name
            devices_found = []
            primary_addr = _parse_addr(discovered[0]["addr"], PORT)
            for dev in discovered:
                addr = _parse_addr(dev["addr"], PORT)
                instance = dev.get("instance", DEFAULT_DEVICE_INSTANCE)
                vendor_id = dev.get("vendor_id")
                name = None
                # Read device name (prop 77)
                rn = read_device_name(client, addr, instance=instance)
                if rn.get("name_read"):
                    name = rn.get("name")
                else:
                    if rn.get("error"):
                        summary["errors"].append(
                            f"read_device_name@{dev['addr']}:{rn['error']}")
                devices_found.append({
                    "instance": instance,
                    "vendor": vendor_id,
                    "name": name,
                    "addr": dev["addr"],
                })
            summary["devices_found"] = devices_found

            # 3. read_device_id on the first discovered device
            ri = read_device_id(client, primary_addr,
                                instance=devices_found[0]["instance"])
            summary["details"]["read_device_id"] = ri
            if ri.get("error"):
                summary["errors"].append(f"read_device_id:{ri['error']}")

            # 4. read_analog_inputs (instances 0-10) on the first device
            ai = read_analog_inputs(client, primary_addr)
            summary["analog_inputs_read"] = bool(ai.get("analog_inputs_read"))
            summary["details"]["read_analog_inputs"] = ai
            for e in ai.get("errors", []):
                summary["errors"].append(f"read_analog_inputs:{e}")

            # 5. try_write_analog_output — SAFE_MODE=full only
            wo = try_write_analog_output(client, primary_addr,
                                         instance=0, value=0.0)
            summary["write_tested"] = bool(wo.get("write_tested"))
            summary["details"]["try_write_analog_output"] = wo
            if wo.get("error"):
                summary["errors"].append(
                    f"try_write_analog_output:{wo['error']}")
            if wo.get("status") == "write_skipped_safe_mode":
                summary["details"]["try_write_analog_output"]["note"] = (
                    "SAFE_MODE is read_only for this sector — WriteProperty "
                    "NOT attempted (would drive a physical actuator/valve). "
                    "Set SECTOR=it/crypto to enable SAFE_MODE=full in lab."
                )
    except (socket.timeout, TimeoutError):
        summary["errors"].append("connection:timeout")
    except (ConnectionRefusedError, OSError) as e:
        summary["errors"].append(f"connection:{type(e).__name__}:{e}")
    except SystemExit:
        raise
    except Exception as e:
        summary["errors"].append(f"unhandled:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
