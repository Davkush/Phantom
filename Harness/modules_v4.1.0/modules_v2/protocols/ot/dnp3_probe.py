#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — dnp3_probe (OT protocol module)
# Read-only DNP3 (IEEE 1815) link + application probe for SCADA validation.
#
# Default port: 20000 (DNP3 over TCP/IP, IEEE 1815-2012 §9).
# Layer stack: TCP → DNP3 data-link (frame: 0x0564 + len + ctrl + dst + src
#              + header CRC + ≤16-byte data blocks each followed by a block CRC)
#              → DNP3 transport (pseudo, single-fragment when ≤ 248 B)
#              → DNP3 application (ASDU: AC + FC + IIN + objects).
#
# Probes performed (ALL read-only — no FC=0x02 OPERATE / 0x03 DIRECT_OPERATE):
#   1. Link Status Request  (link FC=9, ctrl=0xC9) → link_active
#   2. SAv5 Authentication probe (app FC=0x21) → authenticated (None/False)
#   3. Read Class 0 data (app FC=0x01, obj 60 var 1, qualifier 0x06)
#      → data_objects_read (count)
#
# READ_ONLY is enforced unconditionally — a DNP3 OPERATE/DIRECT_OPERATE can
# drive a relay, breaker, or valve. No command frame is ever emitted.
#
# CRC-16 implementation: polynomial 0x3D65, init 0x0000, bit-reversed
# (per IEEE 1815 §5.3.3). Header CRC is over the 10-byte header; data block
# CRCs are over each ≤16-byte data block.
#
# Reproducibility: SEED seeds the application-layer sequence number.
#
# Legal: isolated lab only (NERC CIP / IEEE 1815 / NIS2 / IEC 62443).
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
MODULE_NAME = "dnp3_probe"
DEFAULT_PORT = 20000
TIMEOUT_S = 5.0

# ─── DNP3 link / application constants ─────────────────────────────────────
DNP3_START = b"\x05\x64"                    # link-layer sync bytes

# Link-layer control bytes (DIR=1 from primary, PRM=1 primary frame)
# Format: DIR(1) PRM(1) FCB(1) FCV(1) | FC(4)
LINK_CTRL_LINK_STATUS_REQ = 0xC9            # FC=9 Request Link Status
LINK_CTRL_RESET_LINK       = 0xC0           # FC=0 Reset Remote Link
LINK_CTRL_USER_DATA_NO_ACK = 0xC3           # FC=3 Send user data no-ACK
LINK_CTRL_USER_DATA_ACK    = 0xC4           # FC=4 Send user data (ACK)

# Application-layer function codes
APP_FC_READ            = 0x01
APP_FC_OPERATE         = 0x02               # WRITE — never sent
APP_FC_AUTHENTICATE    = 0x21               # SAv5 auth challenge probe
APP_FC_RESPONSE        = 0x81
APP_FC_UNSOLICITED_RSP = 0x82

# Application control byte (FIR=1, FIN=1, CON=1, UNS=0, seq=0)
APP_AC_REQUEST_FIRST_LAST_CON = 0xC0

# Object groups / variations
OBJ_GROUP_CLASS_0   = 0x3C                  # group 60 = event class data
OBJ_VAR_CLASS_0     = 0x01                  # var 1   = class 0 (static)
OBJ_GROUP_DEVICE_ATTR = 0x00                # group 0  = device attributes
OBJ_VAR_DEVICE_AUTH  = 0x01
OBJ_GROUP_AUTH      = 0x5C                   # group 92 = SAv5 authentication

# Qualifier field codes
QUAL_8BIT_STOP  = 0x06                       # 8-bit stop index, no prefix
QUAL_16BIT_STOP = 0x07                       # 16-bit stop index, no prefix

# IIN (Internal Indications) bits
IIN1_NO_FUNC_AUTH = 0x20                     # IIN1.5 = NO_FUNC_CODE_AUTHORIZATION
IIN2_NO_FUNC_SUPPORT = 0x02                  # IIN2.1 = function not supported
IIN2_NEED_TIME     = 0x08                    # IIN2.3 = time sync needed

# Lab default source/destination DNP3 addresses (configurable via env)
DNP3_SRC = int(os.environ.get("DNP3_SRC", "1"))
DNP3_DST = int(os.environ.get("DNP3_DST", "1"))

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

SEED = int(os.environ.get("SEED", "1337"))
_APP_SEQ = random.Random(SEED).randint(0, 31)  # SEED-reproducible app seq

SECTOR_CFG = get_sector_config()
SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")


# ═══════════════════════════════════════════════════════════════════════════
#  CRC-16 (DNP3 — polynomial 0x3D65, reflected)
# ═══════════════════════════════════════════════════════════════════════════
# Per IEEE 1815 §5.3.3. Lookup table built lazily and cached.
_CRC_TABLE: Optional[list] = None


def _crc_table() -> list:
    global _CRC_TABLE
    if _CRC_TABLE is not None:
        return _CRC_TABLE
    POLY = 0xA6BC    # reflected form of 0x3D65
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ POLY
            else:
                crc >>= 1
        table.append(crc)
    _CRC_TABLE = table
    return table


def dnp3_crc(data: bytes) -> int:
    """Compute the DNP3 CRC-16 over `data` (init=0x0000)."""
    table = _crc_table()
    crc = 0x0000
    for b in data:
        crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
    return crc & 0xFFFF


# ═══════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET DNP3 TRANSPORT
# ═══════════════════════════════════════════════════════════════════════════
class Dnp3RawClient:
    """Minimal DNP3 client (raw sockets, no external deps).

    Builds:
      • Link-only frames  (Link Status, Reset Link)
      • Link + app frames (Class-0 Read, Auth probe)

    Frame layout (link layer):
      [0x05][0x64] len(1) ctrl(1) dst(2 LE) src(2 LE) | header CRC(2 LE)
      [data block ≤16 B][block CRC(2 LE)] ...
    """

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S,
                 src: int = DNP3_SRC, dst: int = DNP3_DST):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.src = src & 0xFFFF
        self.dst = dst & 0xFFFF
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

    def __enter__(self) -> "Dnp3RawClient":
        self.connect(); return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- frame builders ----------------------------------------------------
    def _build_link_frame(self, ctrl: int, data: bytes = b"") -> bytes:
        """Build a complete link-layer frame.

        Header (10 B): 0x05 0x64 | len | ctrl | dst(2 LE) | src(2 LE)
        `len` = 5 (fixed header bytes following the length byte, i.e.
                   ctrl + dst + src) + len(data)  — per IEEE 1815 §5.2.
        Then header CRC(2 LE) + ≤16-byte data blocks each with their own CRC.
        """
        # Without a data block, length = 5 (ctrl + dst + src).
        # With data, length = 5 + len(data).
        length = 5 + len(data)
        if length > 255:
            raise ValueError("DNP3 frame too long")
        header = (
            DNP3_START
            + struct.pack("<BB", length, ctrl)
            + struct.pack("<H", self.dst)
            + struct.pack("<H", self.src)
        )
        header_crc = struct.pack("<H", dnp3_crc(header))
        out = header + header_crc
        # Append data blocks (each ≤16 B + 2 B CRC)
        if data:
            off = 0
            while off < len(data):
                chunk = data[off:off + 16]
                out += chunk + struct.pack("<H", dnp3_crc(chunk))
                off += 16
        return out

    def _build_app_read_class0(self) -> bytes:
        """Build a Class-0 READ application fragment.

        ASDU: AC(1) FC(1) | IIN1(1) IIN2(1) | obj header(0x3C 0x01 0x06 0x00)
        AC = FIR|FIN|CON|UNS bits + seq(5). For a request we use
        AC = 0xC0 | (seq & 0x1F). IIN is 0x0000 in requests.
        """
        global _APP_SEQ
        _APP_SEQ = (_APP_SEQ + 1) & 0x1F
        ac = APP_AC_REQUEST_FIRST_LAST_CON | _APP_SEQ
        fc = APP_FC_READ
        iin = b"\x00\x00"
        # Object header: group(60) var(1) qualifier(0x06=8-bit stop) stop=0
        obj_hdr = bytes([OBJ_GROUP_CLASS_0, OBJ_VAR_CLASS_0,
                         QUAL_8BIT_STOP, 0x00])
        return bytes([ac, fc]) + iin + obj_hdr

    def _build_app_auth_probe(self) -> bytes:
        """Build a SAv5 AUTHENTICATE-NO-ACK request (challenge request,
        group 92 var 1). Used purely to detect whether the outstation
        requires authentication — it will either echo a challenge or set
        IIN1.5 NO_FUNC_CODE_AUTHORIZATION."""
        global _APP_SEQ
        _APP_SEQ = (_APP_SEQ + 1) & 0x1F
        ac = APP_AC_REQUEST_FIRST_LAST_CON | _APP_SEQ
        fc = APP_FC_AUTHENTICATE
        iin = b"\x00\x00"
        # Empty challenge request — outstation must reply with a challenge
        # group 92 var 1. We just need to see if it rejects (auth disabled)
        # or accepts (auth enabled).
        return bytes([ac, fc]) + iin

    # -- send / recv -------------------------------------------------------
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

    def _recv_link_frame(self) -> dict:
        """Receive one link-layer frame and decode its header + payload.

        Returns {ctrl, dst, src, data, error, valid_crc}.
        """
        out = {"ctrl": None, "dst": None, "src": None, "data": b"",
               "valid_crc": True, "error": None}
        # Read start bytes
        start = self._recvn(2)
        if start != DNP3_START:
            # Possibly a NACK / short response — bail out gracefully
            out["error"] = f"bad_start_bytes:{start.hex()}"
            return out
        length_byte = self._recvn(1)
        if not length_byte:
            out["error"] = "no_length_byte"; return out
        length = length_byte[0]
        # Header = ctrl(1) + dst(2) + src(2) — total 5 bytes follow length.
        # Plus the header CRC (2 B).
        rest_hdr = self._recvn(5 + 2)
        if len(rest_hdr) < 7:
            out["error"] = "truncated_header"; return out
        ctrl = rest_hdr[0]
        dst, src = struct.unpack("<HH", rest_hdr[1:5])
        hdr_crc = struct.unpack("<H", rest_hdr[5:7])[0]
        # Validate header CRC over the 8-byte header (start+len+ctrl+dst+src)
        full_hdr = start + length_byte + rest_hdr[:5]
        if dnp3_crc(full_hdr) != hdr_crc:
            out["valid_crc"] = False
        out["ctrl"], out["dst"], out["src"] = ctrl, dst, src
        # Data blocks: each is len_in_block bytes + 2 B CRC. Total data
        # length = length - 5.
        data_len = length - 5
        if data_len < 0:
            out["error"] = f"bad_length:{length}"; return out
        data = b""
        remaining = data_len
        while remaining > 0:
            blk_len = min(remaining, 16)
            blk = self._recvn(blk_len + 2)
            if len(blk) < blk_len + 2:
                out["error"] = "truncated_data_block"; break
            blk_data, blk_crc = blk[:blk_len], struct.unpack("<H", blk[blk_len:])[0]
            if dnp3_crc(blk_data) != blk_crc:
                out["valid_crc"] = False
            data += blk_data
            remaining -= blk_len
        out["data"] = data
        return out

    # -- high-level probes -------------------------------------------------
    def send_link_status(self) -> dict:
        """Send a Link Status request (link FC=9, ctrl=0xC9)."""
        out = {"link_active": False, "link_ctrl_recv": None,
               "valid_crc": True, "error": None}
        frame = self._build_link_frame(LINK_CTRL_LINK_STATUS_REQ)
        try:
            self.sock.sendall(frame)
            resp = self._recv_link_frame()
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"; return out
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"; return out
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"; return out
        if resp.get("error"):
            out["error"] = resp["error"]; return out
        # Link Status response: link FC=11 (0xB) Reply Link Status
        # ctrl byte from secondary, DIR=0 PRM=0 → top bits = 0x00
        ctrl_recv = resp.get("ctrl")
        out["link_ctrl_recv"] = ctrl_recv
        out["valid_crc"] = resp.get("valid_crc", True)
        # Lower 4 bits = link FC; 0x0B (11) = Link Status reply.
        if ctrl_recv is not None and (ctrl_recv & 0x0F) == 0x0B:
            out["link_active"] = True
        else:
            out["error"] = f"unexpected_link_ctrl:0x{(ctrl_recv or 0):02X}"
        return out

    def send_class0_read(self) -> dict:
        """Send a Class-0 READ request and decode the response IIN/objects."""
        out = {"data_objects_read": 0, "iin": None, "error": None,
               "response_fc": None}
        app = self._build_app_read_class0()
        frame = self._build_link_frame(LINK_CTRL_USER_DATA_NO_ACK, data=app)
        try:
            self.sock.sendall(frame)
            resp = self._recv_link_frame()
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"; return out
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"; return out
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"; return out
        if resp.get("error"):
            out["error"] = resp["error"]; return out
        data = resp.get("data", b"")
        if len(data) < 4:
            out["error"] = "short_app_response"
            return out
        # ASDU: AC(1) FC(1) IIN1(1) IIN2(1) | object headers...
        _ac, fc, iin1, iin2 = data[0], data[1], data[2], data[3]
        out["iin"] = {"iin1": iin1, "iin2": iin2,
                      "no_func_auth": bool(iin1 & IIN1_NO_FUNC_AUTH),
                      "no_func_support": bool(iin2 & IIN2_NO_FUNC_SUPPORT)}
        out["response_fc"] = fc
        if fc == APP_FC_RESPONSE:
            # Count object headers; each starts group(1) var(1) qual(1) ...
            idx = 4
            n_obj = 0
            while idx + 4 <= len(data):
                _grp, _var, qf, _ = data[idx], data[idx + 1], data[idx + 2], data[idx + 3]
                # qualifier prefix/size affects how many bytes follow — we
                # just count objects and stop (precise parsing is heavy and
                # not needed for a read-only probe summary).
                n_obj += 1
                # Best-effort: skip qualifier prefix + 1 object; conservative
                # break to avoid runaway.
                idx += 4
                if qf in (0x00, 0x01):           # all points / 8-bit start-stop
                    idx += 2
                elif qf == 0x06:                  # 8-bit stop
                    idx += 1
                elif qf == 0x07:                  # 16-bit stop
                    idx += 2
                else:
                    idx += 1
            out["data_objects_read"] = n_obj
        elif fc == (APP_FC_READ | 0x40):
            out["error"] = "negative_response"
        else:
            out["error"] = f"unexpected_app_fc:0x{fc:02X}"
        return out

    def probe_auth_v5(self) -> dict:
        """Send a SAv5 AUTHENTICATE request and observe response.

        Returns authenticated = True if the outstation returns a group-92
        challenge (auth enabled), False if it sets IIN1.5 (auth disabled
        but acknowledged), None if no response or unsupported.
        """
        out = {"authenticated": None, "auth_required": None,
               "iin": None, "error": None}
        app = self._build_app_auth_probe()
        frame = self._build_link_frame(LINK_CTRL_USER_DATA_NO_ACK, data=app)
        try:
            self.sock.sendall(frame)
            resp = self._recv_link_frame()
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"; return out
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"; return out
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"; return out
        if resp.get("error"):
            out["error"] = resp["error"]; return out
        data = resp.get("data", b"")
        if len(data) < 4:
            out["error"] = "short_app_response"; return out
        _ac, fc, iin1, iin2 = data[0], data[1], data[2], data[3]
        out["iin"] = {"iin1": iin1, "iin2": iin2}
        if iin1 & IIN1_NO_FUNC_AUTH:
            # Function not authorized without SAv5 → auth IS required.
            out["auth_required"] = True
            out["authenticated"] = False
        elif iin2 & IIN2_NO_FUNC_SUPPORT:
            # Function not supported → auth NOT implemented.
            out["auth_required"] = False
            out["authenticated"] = None
        elif len(data) > 5 and data[4] == OBJ_GROUP_AUTH:
            # Got a group-92 challenge → auth IS required (not authenticated
            # by us, but the device enforces it).
            out["auth_required"] = True
            out["authenticated"] = False
        else:
            out["auth_required"] = False
            out["authenticated"] = None
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
        "dnp3_src": DNP3_SRC,
        "dnp3_dst": DNP3_DST,
        "device_identified": False,
        "link_active": False,
        "authenticated": None,
        "data_objects_read": 0,
        "devices_found": 0,
        "results": {},
        "errors": [],
    }

    try:
        with Dnp3RawClient(HOST, PORT, timeout=TIMEOUT_S,
                           src=DNP3_SRC, dst=DNP3_DST) as client:
            # 1. Link status
            try:
                lr = client.send_link_status()
                summary["link_active"] = bool(lr.get("link_active"))
                summary["results"]["link_status"] = {
                    "link_ctrl_recv": lr.get("link_ctrl_recv"),
                    "valid_crc": lr.get("valid_crc"),
                    "error": lr.get("error"),
                }
                if lr.get("error"):
                    summary["errors"].append(f"link_status:{lr['error']}")
            except Exception as e:
                summary["errors"].append(
                    f"link_status:{type(e).__name__}:{e}")

            # Only proceed to app-layer probes if link is up
            if summary["link_active"]:
                summary["devices_found"] = 1   # we reached one outstation

                # 2. SAv5 auth probe
                try:
                    ar = client.probe_auth_v5()
                    summary["authenticated"] = ar.get("authenticated")
                    summary["results"]["auth_v5"] = {
                        "auth_required": ar.get("auth_required"),
                        "iin": ar.get("iin"),
                        "error": ar.get("error"),
                    }
                    if ar.get("error"):
                        summary["errors"].append(f"probe_auth_v5:{ar['error']}")
                except Exception as e:
                    summary["errors"].append(
                        f"probe_auth_v5:{type(e).__name__}:{e}")

                # 3. Class-0 read
                try:
                    cr = client.send_class0_read()
                    summary["data_objects_read"] = int(cr.get("data_objects_read", 0))
                    summary["results"]["class0_read"] = {
                        "iin": cr.get("iin"),
                        "response_fc": cr.get("response_fc"),
                        "error": cr.get("error"),
                    }
                    if cr.get("error"):
                        summary["errors"].append(
                            f"class0_read:{cr['error']}")
                except Exception as e:
                    summary["errors"].append(
                        f"class0_read:{type(e).__name__}:{e}")

                # device_identified = link active + (vendor info or class0 read OK)
                summary["device_identified"] = bool(
                    summary["link_active"] and (
                        summary["data_objects_read"] > 0
                        or (summary["results"].get("auth_v5") or {}).get("iin")
                    )
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
