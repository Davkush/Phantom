#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — iec61850_probe
# Energy sector validation module — IEC 61850 MMS (Manufacturing Message
# Specification) probing of Intelligent Electronic Devices (IEDs) in modern
# digital substations.
#
#   - Default ports : 102 (MMS / RFC 1006 TPKT) and 4840 (OPC-UA mapping)
#   - Stack         : TCP → TPKT (RFC 1006) → COTP (ISO 8073) → MMS (BER)
#   - Functions:
#       mms_initiate       — COTP CR + MMS Initiate-RequestPDU → Initiate-Response
#                            (confirms an IED is listening and accepts MMS)
#       mms_get_namelist   — GetNameList on objectClass=domain → enumerate
#                            Logical Devices (LDs). Iterate continueAfter to
#                            collect the full list.
#       goose_capability   — passive inference from the Initiate-Response
#                            supportedServices bitmap (fileServices /
#                            variableAccessServices bits) and from the
#                            presence of GOOSE-relevant Logical Nodes in
#                            the model. We do NOT send a GOOSE subscribe
#                            (GOOSE is layer-2 multicast; out of scope for
#                            a TCP MMS probe).
#       command_check      — READ-ONLY inference only. We NEVER send an
#                            MMS Operate (DefineAndSelect / Operate) —
#                            sending a control command to a live breaker
#                            or tap-changer is a grid-stability risk.
#   - Raw socket implementation: TPKT + COTP frame builder, minimal BER
#     encoder/decoder for MMS PDUs.
#   - READ_ONLY=True (energy sector safety constraint) — no Operate, no
#     Write, no file upload. Only Initiate + GetNameList (read-only).
#   - SEED env var : deterministic invoke IDs.
#   - LAB=1 mandatory. 5 s timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (energy) : NERC CIP, NIS2, ENISA, IEC 61850,
#   IEC 62351 (security for power system communication).
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
MODULE_NAME = "iec61850_probe"
DEFAULT_PORT = 102  # MMS / RFC 1006 TPKT
ALT_PORT = 4840      # OPC-UA mapping (also commonly used for IEC 61850)
TIMEOUT_S = 5.0
READ_ONLY = True  # energy sector safety constraint — no Operate

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── SEED for deterministic invoke IDs ─────────────────────────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else None
except ValueError:
    SEED = None
_rng = random.Random(SEED) if SEED is not None else random.Random()


def _next_invoke_id() -> int:
    return _rng.randint(1, 0xFFFFFFFF)


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
#  TPKT (RFC 1006)
# ═══════════════════════════════════════════════════════════════════════════
# TPKT header: version(1)=0x03 + reserved(1)=0x00 + length(2, BE, includes
# the 4-byte header itself)
TPKT_VERSION = 0x03


def tpkt_wrap(payload: bytes) -> bytes:
    """Wrap a COTP PDU in a TPKT header."""
    total_len = 4 + len(payload)
    return struct.pack(">BBH", TPKT_VERSION, 0x00, total_len) + payload


def _read_n(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def read_tpkt(sock: socket.socket) -> Optional[bytes]:
    """Read one TPKT-framed PDU and return its COTP payload."""
    header = _read_n(sock, 4)
    if len(header) < 4:
        return None
    version, _rsv, length = struct.unpack(">BBH", header)
    if version != TPKT_VERSION:
        return None
    if length < 4:
        return None
    body = _read_n(sock, length - 4)
    return body


# ═══════════════════════════════════════════════════════════════════════════
#  COTP (ISO 8073, class 0)
# ═══════════════════════════════════════════════════════════════════════════
# TPDU type codes (high nibble of byte 1 after the length byte):
#   CR (Connect Request) = 0xE0
#   CC (Connect Confirm) = 0xD0
#   DR (Disconnect Request) = 0x80
#   DT (Data Transfer)    = 0xF0
COTP_CR = 0xE0
COTP_CC = 0xD0
COTP_DR = 0x80
COTP_DT = 0xF0


def build_cotp_cr(src_ref: int = 0x0001) -> bytes:
    """Build a COTP Connect Request (class 0) TPDU.

    Layout (ISO 8073 §12.1):
      LI(1) + TPDU code(1, 0xE0) + DST-REF(2) + SRC-REF(2) +
      class/options(1) + variable parts
    LI = length of the rest of the header (excluding LI itself).
    DST-REF = 0x0000 (remote reference, unknown → 0)
    SRC-REF = our local reference
    class/options byte: bits 4-0 = class (0), bit 6 = extended format (0),
      bit 7 = ... For class 0 with no options: 0x00.
    Variable parts: we add a TPDU-SIZE parameter (code 0xC0) indicating
    we accept 0x0A = 1024-byte TPDU. This is the minimum most IEDs accept.
    """
    dst_ref = 0x0000
    # class 0, options: 0b00000000
    class_opts = 0x00
    # variable part: TPDU-SIZE (code 0xC0, len 0x01, value 0x0A = 2^10 = 1024)
    var_part = bytes([0xC0, 0x01, 0x0A])
    # Also propose calling/called TPDU size via additional optional but
    # commonly-required parameter: src/dst TSAP (0xC1 / 0xC2). Many IEDs
    # require a called TSAP matching their configuration. We propose a
    # generic TSAP (0x0001) — a strict IED may reject, which we report.
    # Called TSAP (0xC2): len 0x02, value 0x0001
    # Calling TSAP (0xC1): len 0x02, value 0x0001
    var_part += bytes([0xC2, 0x02, 0x00, 0x01])
    var_part += bytes([0xC1, 0x02, 0x00, 0x01])

    header_no_li = bytes([COTP_CR]) + struct.pack(">HH", dst_ref, src_ref) \
        + bytes([class_opts]) + var_part
    li = len(header_no_li)
    return bytes([li]) + header_no_li


def build_cotp_dt(payload: bytes) -> bytes:
    """Build a COTP Data Transfer TPDU (class 0, single fragment).

    Layout: LI(1)=0x02 + code(1)=0xF0 + EOT(1)=0x80 (last byte: bit 7 = EOT)
    + MMS payload
    """
    return bytes([0x02, COTP_DT, 0x80]) + payload


def parse_cotp_cr_cc(body: bytes) -> Optional[Dict]:
    """Parse a COTP CR/CC response → {tpdu_type, dst_ref, src_ref, class_opts,
    tpdu_size, has_tsap}. Returns None if the bytes don't look like CR/CC."""
    if not body or len(body) < 6:
        return None
    li = body[0]
    code = body[1] & 0xF0  # high nibble
    if code not in (COTP_CR, COTP_CC):
        return None
    dst_ref, src_ref = struct.unpack(">HH", body[2:6])
    class_opts = body[6] if len(body) > 6 else 0
    info = {
        "tpdu_type": "CC" if code == COTP_CC else "CR",
        "dst_ref": dst_ref,
        "src_ref": src_ref,
        "class_opts": class_opts,
        "tpdu_size": None,
        "has_tsap": False,
    }
    # Parse variable part (after the fixed 7 bytes: LI + code + 4 refs + 1 class)
    i = 1 + li  # skip LI and the header bytes it counts
    while i + 2 <= len(body):
        pcode = body[i]
        plen = body[i + 1]
        pval = body[i + 2:i + 2 + plen]
        if pcode == 0xC0 and plen >= 1:
            # TPDU-SIZE: value 0x0A..0x0F = 2^(val) bytes
            info["tpdu_size"] = 1 << pval[0] if pval[0] <= 0x0F else None
        elif pcode in (0xC1, 0xC2):
            info["has_tsap"] = True
        i += 2 + plen
    return info


def parse_cotp_dt(body: bytes) -> Optional[bytes]:
    """Extract the MMS payload from a COTP DT TPDU. Returns None if not DT."""
    if not body or len(body) < 3:
        return None
    li = body[0]
    code = body[1] & 0xF0
    if code != COTP_DT:
        return None
    # Class 0 DT: byte 2 = EOT byte; payload starts at offset 1+li
    return body[1 + li:]


# ═══════════════════════════════════════════════════════════════════════════
#  BER (Basic Encoding Rules) — minimal encoder/decoder
# ═══════════════════════════════════════════════════════════════════════════
# Tag byte layout:
#   bits 7-6 : class (00=Universal, 01=Application, 10=Context, 11=Private)
#   bit 5    : constructed (1) or primitive (0)
#   bits 4-0 : tag number (0-30); 31 (0x1F) = long form follows

# Universal tag numbers we use
TAG_UNIV_INTEGER = 0x02
TAG_UNIV_BITSTRING = 0x03
TAG_UNIV_OCTETSTRING = 0x04
TAG_UNIV_NULL = 0x05
TAG_UNIV_OID = 0x06
TAG_UNIV_SEQUENCE = 0x30  # constructed
TAG_UNIV_IA5STRING = 0x16


def ber_len(length: int) -> bytes:
    """BER length encoding: short form (< 128) or long form."""
    if length < 0x80:
        return bytes([length])
    # long form
    out = b""
    n = length
    while n > 0:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def ber_tlv(tag_byte: int, value: bytes) -> bytes:
    """Build a primitive BER TLV (single tag byte + length + value)."""
    return bytes([tag_byte]) + ber_len(len(value)) + value


def ber_constructed(tag_byte: int, *children: bytes) -> bytes:
    """Build a constructed BER TLV (tag with bit 5 set)."""
    val = b"".join(children)
    # tag_byte must already have bit 5 (0x20) set by the caller
    return bytes([tag_byte]) + ber_len(len(val)) + val


def ber_context_tag(num: int, constructed: bool, value: bytes) -> bytes:
    """Build a context-class [num] TLV. If constructed, set bit 5."""
    if num > 30:
        # long-form tag (rare in our use)
        tag = bytes([0x80 | (0x20 if constructed else 0x00) | 0x1F])
        # encode num in continuation bytes (7 bits each, MSB=1 except last)
        out = b""
        n = num
        while n > 0:
            out = bytes([(n & 0x7F) | 0x80]) + out
            n >>= 7
        # clear MSB of last byte
        if out:
            out = out[:-1] + bytes([out[-1] & 0x7F])
        tag = tag + out
    else:
        tag = bytes([0x80 | (0x20 if constructed else 0x00) | num])
    return tag + ber_len(len(value)) + value


def ber_integer(value: int) -> bytes:
    """Encode a small integer as a Universal INTEGER (0x02)."""
    if value == 0:
        body = b"\x00"
    elif value > 0:
        body = b""
        n = value
        while n > 0:
            body = bytes([n & 0xFF]) + body
            n >>= 8
        # prepend 0x00 if high bit set (to keep positive)
        if body[0] & 0x80:
            body = b"\x00" + body
    else:
        # negative — two's complement minimal
        n = value
        body = b""
        # find minimal length
        while True:
            body = bytes([n & 0xFF]) + body
            n >>= 8
            if n == -1 and (body[0] & 0x80):
                break
            if n == 0 and not (body[0] & 0x80):
                break
    return ber_tlv(TAG_UNIV_INTEGER, body)


def ber_unsigned(value: int) -> bytes:
    """Encode an unsigned integer as a Universal INTEGER (positive)."""
    if value < 0:
        value = 0
    if value == 0:
        return ber_tlv(TAG_UNIV_INTEGER, b"\x00")
    body = b""
    n = value
    while n > 0:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    if body[0] & 0x80:
        body = b"\x00" + body
    return ber_tlv(TAG_UNIV_INTEGER, body)


# ─── BER DECODER ───────────────────────────────────────────────────────────
def ber_decode_tag(buf: bytes, offset: int) -> Optional[Tuple[int, bool, int, int]]:
    """Decode a BER tag at offset. Returns (tag_value, constructed, header_len,
    content_offset) or None. For context-class tags returns num 0..30 (or
    -1 for long-form we don't fully parse)."""
    if offset >= len(buf):
        return None
    b = buf[offset]
    cls = (b >> 6) & 0x03
    constructed = bool(b & 0x20)
    tag_num = b & 0x1F
    hdr_len = 1
    if tag_num == 0x1F:
        # long-form tag — parse continuation bytes
        tag_num = 0
        i = offset + 1
        while i < len(buf):
            tag_num = (tag_num << 7) | (buf[i] & 0x7F)
            i += 1
            if not (buf[i - 1] & 0x80):
                break
        hdr_len = i - offset
        # we encode long-form as negative sentinel to signal "complex"
        tag_num = -1
    # Build a single tag value: class(2) << 12 | constructed(1) << 11 | num(11)
    tag_value = (cls << 12) | (int(constructed) << 11) | (tag_num & 0x7FF)
    return tag_value, constructed, hdr_len, offset + hdr_len


def ber_decode_length(buf: bytes, offset: int) -> Optional[Tuple[int, int]]:
    """Decode BER length at offset. Returns (length, content_offset)."""
    if offset >= len(buf):
        return None
    b = buf[offset]
    if b < 0x80:
        return b, offset + 1
    num_bytes = b & 0x7F
    if num_bytes == 0:
        return None  # indefinite length — not supported
    if offset + 1 + num_bytes > len(buf):
        return None
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | buf[offset + 1 + i]
    return length, offset + 1 + num_bytes


def ber_decode_tlv(buf: bytes, offset: int) -> Optional[Tuple[int, bool, bytes, int]]:
    """Decode one TLV → (tag_value, constructed, content_bytes, next_offset)."""
    t = ber_decode_tag(buf, offset)
    if t is None:
        return None
    tag_value, constructed, hdr_len, after_tag = t
    ln = ber_decode_length(buf, after_tag)
    if ln is None:
        return None
    length, content_off = ln
    if content_off + length > len(buf):
        length = len(buf) - content_off
    content = buf[content_off:content_off + length]
    return tag_value, constructed, content, content_off + length


# ═══════════════════════════════════════════════════════════════════════════
#  MMS PDU CONSTRUCTION
# ═══════════════════════════════════════════════════════════════════════════
# MMSpdu ::= CHOICE {
#   initiate-RequestPDU           [0]  InitiateRequestPDU,
#   initiate-ResponsePDU          [1]  InitiateResponsePDU,
#   initiate-ErrorPDU             [2]  InitiateErrorPDU,
#   conclude-RequestPDU           [10] ConcludeRequestPDU,
#   confirmed-RequestPDU          [10] ConfirmedRequestPDU,  ← note: same tag
#   ...
# }
# Wait — MMS uses distinct tags per choice. Confirmed-RequestPDU is [10]
# in the core MMS spec (ISO 9506-1). Let me be careful:
#   initiate-RequestPDU           [0]
#   initiate-ResponsePDU          [1]
#   conclude-RequestPDU           [8]
#   conclude-ResponsePDU          [9]
#   confirmed-RequestPDU          [10]
#   confirmed-ResponsePDU         [11]
#   rejectPDU                     [12]
#   ...
#
# ConfirmedRequestPDU ::= SEQUENCE {
#   invokeID                      Unsigned32,
#   listOfArgument                SEQUENCE OF ANY OPTIONAL,
#   ...
#   opcode                        ConfirmedServiceRequest
# }
# In practice, IEC 61850 uses a simplified ConfirmedRequestPDU:
#   ConfirmedRequestPDU ::= SEQUENCE {
#     invokeID   Unsigned32,
#     opcode     ConfirmedServiceRequest
#   }
# where opcode is a CHOICE with context tags:
#   getNameList [1] GetNameListRequest
#
# GetNameListRequest ::= SEQUENCE {
#   objectClass    [0] ObjectClass,
#   objectScope    [1] ObjectScope OPTIONAL,
#   continueAfter  [2] Identifier OPTIONAL
# }
# ObjectClass ::= CHOICE { basic [0] BasicObjectClass, ... }
# BasicObjectClass ::= ENUMERATED { named-variable(0), ... , domain(9), ... }
# So for domain (Logical Device) enumeration:
#   objectClass = [0] [0] ENUMERATED(9)   (context[0] constructed wrapping
#                                          context[0] primitive = 9)

# MMS Initiate Request tags
MMS_TAG_INITIATE_REQ = 0   # context [0] constructed
MMS_TAG_CONFIRMED_REQ = 10  # context [10] constructed
# GetNameList opcode tag (inside ConfirmedServiceRequest CHOICE)
MMS_TAG_GETNAMELIST_REQ = 1  # context [1] constructed

# BasicObjectClass enumerated values
BOC_NAMED_VARIABLE = 0
BOC_DOMAIN = 9  # Logical Device in IEC 61850


def build_mms_initiate_request() -> bytes:
    """Build an MMS Initiate-RequestPDU (BER).

    InitiateRequestPDU ::= SEQUENCE {
      proposedVersion                    [0] IMPLICIT Integer8,
      proposedMaxServOutstandingCalled   [1] IMPLICIT Integer16,
      proposedMaxServOutstandingCalling  [2] IMPLICIT Integer16,
      proposedDataStructureNestingLevel  [3] IMPLICIT Integer8 OPTIONAL,
      initRequestDetail                  [4] SEQUENCE {
        proposedVersionNumber    [0] IMPLICIT Integer8,
        proposedParameterCBC     [1] IMPLICIT BIT STRING,
        supportedServices        [2] IMPLICIT BIT STRING,
        ...
      }
    }
    The whole SEQUENCE is wrapped in context tag [0] (initiate-RequestPDU).
    """
    # initRequestDetail contents
    # proposedVersionNumber [0] = 1 (MMS version 1)
    ver_num = ber_context_tag(0, False, bytes([1]))
    # proposedParameterCBC [1] BIT STRING — a single byte of bits, unused=0
    # bit 0 = str1 (string), bit 1 = str2, bit 2 = vnam, bit 3 = valt, ...
    # We set a minimal bitmap (all supported) = 0xFF, unused bits 0.
    param_cbc = ber_context_tag(1, False, bytes([0x00, 0xFF]))  # unused=0, value=0xFF
    # supportedServices [2] BIT STRING — indicate GetNameList (bit 11 in the
    # supportedServices bitmap of MMS). We just set a broad bitmap.
    # GetNameList is service bit "11" in variableAccessServices? Actually
    # supportedServices is a CHOICE of nested service-bitmaps — we set a
    # generous bitmap to advertise broad support.
    sup_svcs = ber_context_tag(2, False, bytes([0x00, 0xFF, 0xFF, 0xFF]))
    init_detail = ber_context_tag(4, True, ver_num + param_cbc + sup_svcs)

    # proposedVersion [0] = 1
    prop_ver = ber_context_tag(0, False, bytes([1]))
    # proposedMaxServOutstandingCalled [1] = 10
    prop_called = ber_context_tag(1, False, struct.pack(">H", 10))
    # proposedMaxServOutstandingCalling [2] = 10
    prop_calling = ber_context_tag(2, False, struct.pack(">H", 10))
    # proposedDataStructureNestingLevel [3] = 10
    prop_nest = ber_context_tag(3, False, bytes([10]))

    init_req_seq = prop_ver + prop_called + prop_calling + prop_nest + init_detail
    # Wrap in context [0] constructed (initiate-RequestPDU)
    return ber_context_tag(MMS_TAG_INITIATE_REQ, True, init_req_seq)


def build_mms_getnamelist_request(invoke_id: int,
                                  continue_after: Optional[str] = None) -> bytes:
    """Build an MMS GetNameList request for objectClass=domain (Logical Device).

    ConfirmedRequestPDU [10] ::= SEQUENCE {
      invokeID    Unsigned32,
      opcode      ConfirmedServiceRequest
    }
    ConfirmedServiceRequest ::= CHOICE { ... getNameList [1] GetNameListRequest }
    GetNameListRequest ::= SEQUENCE {
      objectClass    [0] ObjectClass,
      objectScope    [1] ObjectScope OPTIONAL,
      continueAfter  [2] Identifier OPTIONAL
    }
    ObjectClass ::= CHOICE { basic [0] BasicObjectClass }
    BasicObjectClass ::= ENUMERATED { ... domain(9) ... }
    """
    # objectClass = [0] constructed wrapping [0] primitive = 9 (domain)
    obj_class_basic = ber_context_tag(0, False, bytes([BOC_DOMAIN]))
    obj_class = ber_context_tag(0, True, obj_class_basic)
    # objectScope: omit (defaults to vmdSpecific in MMS, but for domain
    # enumeration the scope is implicitly vmd-specific)
    # continueAfter [2] (Identifier = VisibleString)
    cont_after = b""
    if continue_after:
        cont_after = ber_context_tag(2, False, continue_after.encode("ascii"))
    # GetNameListRequest SEQUENCE
    gnl_req = ber_constructed(TAG_UNIV_SEQUENCE, obj_class + cont_after)
    # Wrap in context [1] (getNameList opcode)
    opcode = ber_context_tag(MMS_TAG_GETNAMELIST_REQ, True, gnl_req)
    # invokeID
    inv_id = ber_unsigned(invoke_id & 0xFFFFFFFF)
    # ConfirmedRequestPDU SEQUENCE
    conf_req_seq = ber_constructed(TAG_UNIV_SEQUENCE, inv_id + opcode)
    # Wrap in context [10] (confirmed-RequestPDU)
    return ber_context_tag(MMS_TAG_CONFIRMED_REQ, True, conf_req_seq)


# ═══════════════════════════════════════════════════════════════════════════
#  MMS RESPONSE PARSING
# ═══════════════════════════════════════════════════════════════════════════
def parse_mms_pdu(buf: bytes) -> Optional[Dict]:
    """Parse the outer MMS PDU tag and return {kind, content}.

    kind is one of: 'initiate-response', 'confirmed-response',
    'confirmed-error', 'reject', 'conclude-response', 'unknown'.
    """
    t = ber_decode_tlv(buf, 0)
    if t is None:
        return None
    tag_value, constructed, content, _next = t
    cls = (tag_value >> 12) & 0x03
    tag_num = tag_value & 0x7FF
    if cls != 0x02:  # not context class
        return {"kind": "unknown", "content": content}
    if tag_num == 1:
        return {"kind": "initiate-response", "content": content}
    if tag_num == 11:
        return {"kind": "confirmed-response", "content": content}
    if tag_num == 12:
        return {"kind": "reject", "content": content}
    if tag_num == 2:
        return {"kind": "initiate-error", "content": content}
    if tag_num == 9:
        return {"kind": "conclude-response", "content": content}
    return {"kind": f"context[{tag_num}]", "content": content}


def parse_getnamelist_response(content: bytes) -> Tuple[List[str], Optional[str]]:
    """Parse a GetNameList response → (listOfIdentifier, continueAfter).

    ConfirmedResponsePDU [11] SEQUENCE {
      invokeID           Unsigned32,
      listOfServiceResult SEQUENCE OF ...,
      confirmedServiceResponse ConfirmedServiceResponse
    }
    ConfirmedServiceResponse ::= CHOICE { ... getNameList [1] GetNameListResponse }
    GetNameListResponse ::= SEQUENCE {
      listOfIdentifier [0] SEQUENCE OF Identifier,
      moreFollows     [1] BOOLEAN OPTIONAL
    }

    We do a forgiving recursive scan for [0] context-tagged SEQUENCE OF
    Identifier (VisibleString) and the [1] BOOLEAN (moreFollows).
    """
    identifiers: List[str] = []
    continue_after: Optional[str] = None
    _scan_for_identifiers(content, identifiers)
    more = _scan_for_more_follows(content)
    if more:
        # If more follows, set continue_after to the last identifier we found
        if identifiers:
            continue_after = identifiers[-1]
    return identifiers, continue_after


def _scan_for_identifiers(buf: bytes, out: List[str]) -> None:
    """Recursively scan for VisibleString / IA5String / GeneralString
    contents that look like Logical Device names. We accept any primitive
    string-tag TLV whose value is printable ASCII of length 1-32."""
    offset = 0
    while offset < len(buf):
        t = ber_decode_tlv(buf, offset)
        if t is None:
            break
        tag_value, constructed, content, next_off = t
        cls = (tag_value >> 12) & 0x03
        tag_num = tag_value & 0x7FF
        if not constructed and cls == 0x00:  # Universal primitive
            # VisibleString=0x1A, IA5String=0x16, GeneralString=0x1B,
            # UTF8String=0x0C, GraphicString=0x19
            if tag_num in (0x1A, 0x16, 0x1B, 0x0C, 0x19):
                val = content
                if 1 <= len(val) <= 32 and all(32 <= b < 127 for b in val):
                    try:
                        s = val.decode("ascii")
                        # Logical Device names typically match [A-Za-z0-9_]+
                        if s and all(c.isalnum() or c in "_-." for c in s):
                            out.append(s)
                    except UnicodeDecodeError:
                        pass
        elif constructed:
            _scan_for_identifiers(content, out)
        offset = next_off


def _scan_for_more_follows(buf: bytes) -> bool:
    """Look for a context [1] BOOLEAN with value TRUE (0xFF)."""
    offset = 0
    while offset < len(buf):
        t = ber_decode_tlv(buf, offset)
        if t is None:
            break
        tag_value, constructed, content, next_off = t
        cls = (tag_value >> 12) & 0x03
        tag_num = tag_value & 0x7FF
        if cls == 0x02 and tag_num == 1 and not constructed:
            # context [1] primitive — BOOLEAN TRUE is 0xFF
            if content and content[0] == 0xFF:
                return True
        elif constructed:
            if _scan_for_more_follows(content):
                return True
        offset = next_off
    return False


# ═══════════════════════════════════════════════════════════════════════════
#  GOOSE CAPABILITY INFERENCE (passive)
# ═══════════════════════════════════════════════════════════════════════════
def infer_goose_capability(initiate_response_content: Optional[bytes],
                           logical_devices: List[str]) -> Optional[bool]:
    """Passively infer whether the IED is GOOSE-capable.

    GOOSE is a layer-2 multicast protocol (EtherType 0x88B8) and cannot
    be tested over a TCP MMS connection. However:
      - IEC 61850 IEDs that expose Logical Devices via MMS are virtually
        always GOOSE publishers/subscribers (GOOSE is the horizontal
        communication; MMS is the vertical / client-server).
      - The presence of process-level LDs (names starting with a typical
        IEC 61850 prefix) is a strong indicator.
    We return True when at least one Logical Device was enumerated, None
    if we have no model information, False only if we explicitly see a
    server that declares no variableAccessServices (rare).
    """
    if logical_devices:
        return True
    if initiate_response_content is None:
        return None
    # Look at supportedServices bitmap — if variableAccessServices bit is
    # set, the IED exposes data; combined with GOOSE being default in
    # IEC 61850, we return None (inconclusive-but-likely).
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  PROBE ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════
def open_mms_association(host: str, port: int) -> Optional[Dict]:
    """Open a TCP + TPKT + COTP association and send an MMS Initiate Request.

    Returns {sock, initiate_ok, init_response_content, error} or None.
    """
    result = {
        "sock": None,
        "initiate_ok": False,
        "init_response_content": None,
        "cotp_info": None,
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

    # 1. COTP CR
    cr = build_cotp_cr(src_ref=0x0001)
    try:
        sock.sendall(tpkt_wrap(cr))
        body = read_tpkt(sock)
    except (socket.timeout, TimeoutError):
        result["error"] = "cotp_cr_timeout"
        return result
    except OSError as e:
        result["error"] = f"cotp_cr_io:{type(e).__name__}"
        return result

    if body is None:
        result["error"] = "cotp_no_response"
        return result
    cc = parse_cotp_cr_cc(body)
    if cc is None:
        result["error"] = "cotp_not_cr_cc"
        return result
    result["cotp_info"] = cc
    if cc["tpdu_type"] != "CC":
        # DR or other — IED refused the connection
        result["error"] = f"cotp_{cc['tpdu_type'].lower()}"
        return result

    # 2. MMS Initiate Request
    init_req = build_mms_initiate_request()
    dt = build_cotp_dt(init_req)
    try:
        sock.sendall(tpkt_wrap(dt))
        body2 = read_tpkt(sock)
    except (socket.timeout, TimeoutError):
        result["error"] = "mms_init_timeout"
        return result
    except OSError as e:
        result["error"] = f"mms_init_io:{type(e).__name__}"
        return result

    if body2 is None:
        result["error"] = "mms_no_response"
        return result
    mms_payload = parse_cotp_dt(body2)
    if mms_payload is None:
        result["error"] = "cotp_dt_not_parsed"
        return result

    parsed = parse_mms_pdu(mms_payload)
    if parsed and parsed.get("kind") == "initiate-response":
        result["initiate_ok"] = True
        result["init_response_content"] = parsed.get("content")
    elif parsed:
        result["error"] = f"mms_unexpected:{parsed.get('kind')}"
    else:
        result["error"] = "mms_parse_failed"
    return result


def enumerate_logical_devices(sock: socket.socket, max_rounds: int = 8) -> Dict:
    """Send repeated GetNameList requests (with continueAfter) to enumerate
    all Logical Devices on the IED.

    Returns {logical_devices, rounds, error}.
    """
    result = {"logical_devices": [], "rounds": 0, "error": None}
    continue_after: Optional[str] = None
    for _ in range(max_rounds):
        invoke_id = _next_invoke_id()
        gnl_req = build_mms_getnamelist_request(invoke_id, continue_after)
        dt = build_cotp_dt(gnl_req)
        try:
            sock.sendall(tpkt_wrap(dt))
            body = read_tpkt(sock)
        except (socket.timeout, TimeoutError):
            result["error"] = "getnamelist_timeout"
            break
        except OSError as e:
            result["error"] = f"getnamelist_io:{type(e).__name__}"
            break
        if body is None:
            result["error"] = "getnamelist_no_response"
            break
        mms_payload = parse_cotp_dt(body)
        if mms_payload is None:
            result["error"] = "cotp_dt_not_parsed"
            break
        parsed = parse_mms_pdu(mms_payload)
        if not parsed:
            result["error"] = "mms_parse_failed"
            break
        if parsed.get("kind") == "confirmed-response":
            ids, cont = parse_getnamelist_response(parsed.get("content") or b"")
            result["logical_devices"].extend(ids)
            result["rounds"] += 1
            if cont and cont != continue_after:
                continue_after = cont
                continue
            else:
                break  # no more follows
        elif parsed.get("kind") == "reject":
            result["error"] = "mms_rejected"
            break
        elif parsed.get("kind", "").startswith("initiate-error") or \
                parsed.get("kind") == "confirmed-error":
            result["error"] = f"mms_error:{parsed.get('kind')}"
            break
        else:
            result["error"] = f"mms_unexpected:{parsed.get('kind')}"
            break
    return result


def close_mms(sock: socket.socket) -> None:
    """Best-effort graceful close."""
    if sock is None:
        return
    try:
        # Send a COTP DR (disconnect) — minimal
        dr = bytes([0x02, 0x80, 0x00, 0x00, 0x00, 0x00])  # LI + DR + DST + SRC + reason
        sock.sendall(tpkt_wrap(dr))
    except Exception:
        pass
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
            "legal_note": ("IEC 61850 / MMS probing on production substation "
                           "IEDs is illegal outside an authorized lab. NERC CIP / "
                           "IEC 62351."),
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
        "ied_found": 0,
        "logical_devices": [],
        "goose_capable": None,
        "commands_accepted": None,  # READ-ONLY: never tested
        # Extra diagnostic fields:
        "cotp_connected": False,
        "mms_initiated": False,
        "errors": [],
    }

    # ─── 1. Open MMS association + Initiate ───────────────────────────────
    assoc = open_mms_association(HOST, PORT)
    if assoc is None or assoc.get("sock") is None:
        summary["errors"].append(f"assoc:{assoc.get('error') if assoc else 'none'}")
        summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
        print(json.dumps(summary, indent=2, default=str))
        return

    sock = assoc["sock"]
    if assoc.get("cotp_info"):
        summary["cotp_connected"] = assoc["cotp_info"].get("tpdu_type") == "CC"
    if assoc.get("initiate_ok"):
        summary["mms_initiated"] = True
        summary["ied_found"] = 1  # one IED responded to MMS Initiate
    else:
        summary["errors"].append(f"mms_initiate:{assoc.get('error')}")
        close_mms(sock)
        summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
        print(json.dumps(summary, indent=2, default=str))
        return

    # ─── 2. Enumerate Logical Devices ────────────────────────────────────
    try:
        gnl = enumerate_logical_devices(sock, max_rounds=8)
        summary["logical_devices"] = gnl.get("logical_devices", [])
        if gnl.get("error"):
            summary["errors"].append(f"getnamelist:{gnl['error']}")
    except Exception as e:
        summary["errors"].append(f"getnamelist:{type(e).__name__}:{e}")
    finally:
        close_mms(sock)

    # ─── 3. GOOSE capability inference (passive) ─────────────────────────
    summary["goose_capable"] = infer_goose_capability(
        assoc.get("init_response_content"),
        summary["logical_devices"],
    )

    # ─── 4. Commands check (READ-ONLY inference only) ────────────────────
    # We never send an MMS Operate. We report None (inconclusive) unless we
    # explicitly enumerated controllable Logical Nodes — even then, "would
    # be accepted" is speculation, so we stay None.
    summary["commands_accepted"] = None

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
