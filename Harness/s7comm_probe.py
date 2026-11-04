#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — s7comm_probe (OT protocol module)
# Read-only Siemens S7comm (ISO-on-TCP, RFC 1006) probe for PLC validation.
#
# Default port: 102 (Siemens S7 / ISO-on-TCP).
# Stack: TCP → TPKT (RFC 1006) → COTP (ISO 8073) → S7comm → payload.
#
# Probes performed (ALL read-only — no S7 write / modify / function PDU):
#   1. COTP Connect Request (CR)            → connection_ok
#   2. S7comm Setup Communication           → negotiated PDU size
#   3. Read device identification           → order code, module name, firmware
#      (SZL request: SSL header 0x0011 / index 0x0000 → catalog of SZLs,
#       then 0x0011/0x0001 → order code, 0x001C/0x0009 → module name)
#   4. Read DB block 1, offset 0, count 10  → blocks_readable (count of
#      successful DB reads, here 0..1)
#
# ═══ CVE / threat context ═════════════════════════════════════════════════
# CVE-2017-0145 / CVE-2018-?? — S7comm protection bypass.
# CVE-2018-7852  — Schneider / Siemens (UMAS) replay; S7comm sibling.
# CVE-2019-12258 — Stuxnet-style S7 block-read primitive abuse (Stuxnet
#                  worm, 2010) used the exact sequence below:
#                  COTP CR → Setup Communication → Read DB 1 → Read OB 35
#                  → Modify OB 35 (write block, malicious code injection).
#                  This module implements ONLY the read half — by design
#                  (READ_ONLY OT safety constraint). The read sequence by
#                  itself is what Stuxnet used to fingerprint and dump
#                  the PLC's project, identify the centrifuge controller,
#                  and prepare its payload. Treat a successful read as
#                  CRITICAL: the engineering project can be exfiltrated
#                  and a malicious write becomes trivial.
# Reference Stuxnet vectors:
#   - Function 0x1A (read SZL) → leaks order code, serial, firmware.
#   - Function 0x04 (read DB)  → leaks application program + symbol table.
# Mitigations: enable S7comm-Plus (S7-1500), PLC password protection,
#              TIA Portal "protection & security" → "HM access = full, PG/PC
#              access = none"; deploy Siemens CP secure communication.
# ═══════════════════════════════════════════════════════════════════════════
#
# Frame construction:
#   TPKT:    version(0x03) reserved(0x00) length(2, BE, total incl. TPKT)
#   COTP CR: LI(1) Code(0xE0) DST_REF(2) SRC_REF(2) Class(0)
#            + variable part (TSAP parameter: 0xC1 len 2 src_tsap 0xC2 len 2 dst_tsap)
#   COTP DT: LI(2) Code(0xF0) EOT(0x80) + payload
#   S7 hdr:  ProtocolId(0x32) ROSCTR(1=Job) Reserved(2) PduRef(2)
#            ParamLen(2) DataLen(2)
#   S7 param (read): Function(0x04) ItemHead(0x12) ItemLen(0x0A) SyntaxId(0x10)
#            TransportSize(0x02=byte / 0x04=word) NumElements(2) DBNumber(2)
#            Area(1) Address(3, bit offset, BE)
#
# Reproducibility: SEED seeds the PDU reference counter.
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
MODULE_NAME = "s7comm_probe"
DEFAULT_PORT = 102
TIMEOUT_S = 5.0

# Default TSAPs for rack 0 / slot 2 of a Siemens S7 PLC.
DEFAULT_LOCAL_TSAP  = 0x0100          # client-side (PG/PC)
DEFAULT_REMOTE_TSAP = 0x0102          # server-side (device, rack 0 slot 2)

# S7 constants
S7_PROTO_ID       = 0x32
S7_ROSCTR_JOB     = 0x01
S7_ROSCTR_ACK     = 0x02
S7_ROSCTR_ACKDATA = 0x03
S7_FUNC_READ      = 0x04
S7_FUNC_WRITE     = 0x05              # WRITE — never sent
S7_FUNC_SETUP     = 0xF0              # Setup Communication
S7_FUNC_USERDATA  = 0x28              # SZL / userdata request
S7_ITEMHEAD       = 0x12
S7_SYNTAXID       = 0x10
S7_SZL_ITEMHEAD   = 0x12
S7_TRANSPORT_BYTE = 0x02
S7_TRANSPORT_WORD = 0x04

# S7 area codes
S7_AREA_DB    = 0x84
S7_AREA_INPUTS = 0x81
S7_AREA_OUTPUTS = 0x82
S7_AREA_MK    = 0x83
S7_AREA_CT    = 0x1C
S7_AREA_TM    = 0x1D

# SZL (System Status List) IDs for device identification
SZL_ORDER_CODE = 0x0011               # Module order code (6ES7...)
SZL_MODULE     = 0x001C               # Module name
SZL_CPU        = 0x0004               # CPU characteristics
SZL_SERIAL     = 0x0011

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

SEED = int(os.environ.get("SEED", "1337"))
_PDU_REF = random.Random(SEED).randint(1, 0x7FFF)

SECTOR_CFG = get_sector_config()
SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")


# ═══════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET S7COMM TRANSPORT
# ═══════════════════════════════════════════════════════════════════════════
class S7RawClient:
    """Minimal S7comm-over-ISO-on-TCP client (raw sockets, no deps).

    Implements: COTP CR handshake + Setup Communication + S7 read + SZL read.
    """

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
        self._connected_cotp = False
        self._negotiated_pdu = 0

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

    def __enter__(self) -> "S7RawClient":
        self.connect(); return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── low-level helpers ───────────────────────────────────────────────
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

    def _recv_tpkt(self) -> bytes:
        """Read one complete TPKT frame (header + payload)."""
        hdr = self._recvn(4)
        if len(hdr) < 4:
            raise OSError("truncated_tpkt_header")
        ver, _rsv, length = struct.unpack(">BBH", hdr)
        if ver != 0x03:
            raise OSError(f"bad_tpkt_version:0x{ver:02X}")
        if length < 4:
            raise OSError(f"bad_tpkt_length:{length}")
        body = self._recvn(length - 4)
        return hdr + body

    def _send_tpkt(self, payload: bytes) -> None:
        """Wrap `payload` in a TPKT header (length BE = 4 + len(payload))."""
        total = 4 + len(payload)
        if total > 0xFFFF:
            raise ValueError("frame too large for TPKT")
        self.sock.sendall(struct.pack(">BBH", 0x03, 0x00, total) + payload)

    # ── COTP layer ──────────────────────────────────────────────────────
    def cotp_cr(self) -> dict:
        """Send a COTP Connect Request (CR) and wait for CC (Connect Confirm)."""
        out = {"connection_ok": False, "remote_ref": None,
               "tpdu_size_negotiated": None, "error": None}
        # COTP CR: LI=0x11 (17) Code=0xE0 (CR) DST_REF=0 SRC_REF=0x0001
        #          Class=0, variable part: 0xC0 0x01 0x0A (TPDU size=1024),
        #          0xC1 0x02 <src TSAP 2>, 0xC2 0x02 <dst TSAP 2>
        dst_ref = 0x0000
        src_ref = 0x0001
        var_part = (
            b"\xC0\x01\x0A"                                  # TPDU size = 1024 (0x0A → 2^10)
            + b"\xC1\x02" + struct.pack(">H", self.local_tsap)
            + b"\xC2\x02" + struct.pack(">H", self.remote_tsap)
        )
        # LI = length of COTP header following LI (excluding LI byte itself)
        li = 6 + len(var_part)         # fixed CR header (Code+DST+SRC+Class=6) + var
        cr = (
            bytes([li, 0xE0])
            + struct.pack(">H", dst_ref)
            + struct.pack(">H", src_ref)
            + b"\x00"                   # class 0
            + var_part
        )
        try:
            self._send_tpkt(cr)
            resp = self._recv_tpkt()
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"; return out
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"; return out
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"; return out
        # Strip TPKT header
        cotp = resp[4:]
        if len(cotp) < 2:
            out["error"] = "short_cotp"; return out
        li_recv, code = cotp[0], cotp[1]
        # CC = 0xD0
        if code == 0xD0:
            # DST_REF(2) + SRC_REF(2) + class + var part
            if len(cotp) >= 7:
                _dref, sref = struct.unpack(">HH", cotp[2:6])
                out["remote_ref"] = sref
            # Walk variable part to find TPDU size (0xC0)
            idx = 7
            while idx + 1 < len(cotp):
                p_code, p_len = cotp[idx], cotp[idx + 1]
                if p_code == 0xC0 and p_len >= 1 and idx + 2 < len(cotp):
                    # 0x0A = 1024, 0x0B = 2048, 0x0C = 4096, 0x0D = 8192
                    out["tpdu_size_negotiated"] = 1 << cotp[idx + 2]
                    break
                idx += 2 + p_len
            self._connected_cotp = True
            out["connection_ok"] = True
            return out
        elif code == 0xD1:    # DR (Disconnect Request)
            out["error"] = "cotp_disconnect_request"
            return out
        else:
            out["error"] = f"unexpected_cotp_code:0x{code:02X}"
            return out

    def _cotp_dt(self, s7_pdu: bytes) -> bytes:
        """Wrap an S7 PDU in a COTP DT frame (Code=0xF0, EOT=0x80)."""
        # LI=2 (Code + EOT only), Code=0xF0, EOT=0x80
        return bytes([0x02, 0xF0, 0x80]) + s7_pdu

    def _send_recv_s7(self, s7_param: bytes, s7_data: bytes = b"") -> bytes:
        """Wrap param+data in an S7 header inside a COTP DT inside TPKT,
        send it, and return the response S7 body (after S7 header)."""
        global _PDU_REF
        _PDU_REF = (_PDU_REF + 1) & 0x7FFF
        # S7 header
        s7_hdr = struct.pack(
            ">BBHHHH",
            S7_PROTO_ID, S7_ROSCTR_JOB,
            0x0000,                          # reserved
            _PDU_REF,                        # PDU reference
            len(s7_param), len(s7_data),
        )
        s7_pdu = s7_hdr + s7_param + s7_data
        cotp = self._cotp_dt(s7_pdu)
        self._send_tpkt(cotp)
        resp = self._recv_tpkt()
        # Strip TPKT (4) + COTP DT (3)
        s7 = resp[4 + 3:]
        if len(s7) < 10:
            raise OSError("short_s7_header")
        _pid, rosctr, _rsv, _pref, plen, dlen = struct.unpack(">BBHHHH", s7[:10])
        return s7[10:10 + plen + dlen]      # return param+data concatenated

    # ── Setup Communication ─────────────────────────────────────────────
    def setup_communication(self) -> dict:
        """S7 Setup Communication (function 0xF0)."""
        out = {"setup_ok": False, "negotiated_pdu_size": None,
               "max_msgs_in": None, "max_msgs_out": None, "error": None}
        # Param: Function(0xF0) Reserved(0x00) MaxJobsCalling(1) MaxJobsCalled(1)
        # Negotiate PDU size (2, BE)
        pdu_param = bytes([0xF0, 0x00, 0x01, 0x01]) + struct.pack(">H", 480)
        try:
            body = self._send_recv_s7(pdu_param)
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"; return out
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"; return out
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"; return out
        # Ack param: Function(0xF0) Reserved(0x00) JobsCalling(1) JobsCalled(1) PDULen(2)
        if len(body) < 6:
            out["error"] = "short_setup_resp"; return out
        out["max_msgs_in"]  = body[2]
        out["max_msgs_out"] = body[3]
        out["negotiated_pdu_size"] = struct.unpack(">H", body[4:6])[0]
        self._negotiated_pdu = out["negotiated_pdu_size"]
        out["setup_ok"] = True
        return out

    # ── Read DB / generic read ──────────────────────────────────────────
    def read_area(self, area: int, db_number: int, offset: int,
                  num_elements: int, transport_size: int = S7_TRANSPORT_BYTE,
                  element_size_bytes: int = 1) -> dict:
        """S7 Read (function 0x04). Returns {read_ok, data, error}."""
        out = {"read_ok": False, "data": b"", "count": 0, "error": None}
        # Param: Function(0x04) ItemHead(0x12) VarLen(0x0A) SyntaxId(0x10)
        #        TransportSize(1) NumElements(2) DBNumber(2) Area(1) Addr(3, bits)
        bit_addr = offset * 8 * element_size_bytes
        addr_b1 = (bit_addr >> 16) & 0xFF
        addr_b2 = (bit_addr >> 8) & 0xFF
        addr_b3 = bit_addr & 0xFF
        s7_param = bytes([
            S7_FUNC_READ, S7_ITEMHEAD, 0x0A, S7_SYNTAXID,
            transport_size,
        ]) + struct.pack(">H", num_elements) + struct.pack(">H", db_number) + \
            bytes([area, addr_b1, addr_b2, addr_b3])
        try:
            body = self._send_recv_s7(s7_param)
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"; return out
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"; return out
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"; return out
        # Ack-Data param: Function(0x04) ItemHead(0x12) VarLen(0x0A)
        #                 ReturnCode(1) TransportSize(1) DataLength(2)
        if len(body) < 8:
            out["error"] = "short_read_resp"; return out
        ret_code = body[4]
        if ret_code != 0x00 and ret_code != 0xFF:
            # 0x05 = address out of range, 0x0A = not supported
            out["error"] = f"s7_read_error:0x{ret_code:02X}"
            return out
        data_len = struct.unpack(">H", body[6:8])[0]
        data = body[8:8 + data_len]
        out["data"] = data
        out["count"] = len(data) // max(element_size_bytes, 1)
        out["read_ok"] = True
        return out

    def read_db(self, db_number: int, offset: int, count: int) -> dict:
        """Convenience: read `count` bytes from DB `db_number` at `offset`."""
        return self.read_area(S7_AREA_DB, db_number, offset, count,
                              transport_size=S7_TRANSPORT_BYTE,
                              element_size_bytes=1)

    # ── SZL read (device identification) ────────────────────────────────
    def read_szl(self, szl_id: int, index: int = 0x0000) -> dict:
        """S7 read SZL (system status list) via Userdata (function 0x28).

        Returns {read_ok, records: [bytes,...], error}.
        """
        out = {"read_ok": False, "records": [], "raw_data": b"", "error": None}
        # S7 Userdata request param (function 0x28, userdata head, method=ReadSZL,
        # subfunction 0x04, sequence 0x01):
        #   0x28 (Func) | 0x00 | head[0]=0x00 head[1]=0x01 head[2]=0x12
        #   head[3]=0x04 head[4]=0x11 head[5]=0x00 head[6]=0x08 head[7]=0x00
        # Then data part: 0x00 0x01 0x12 (item head) 0x04 (ReadSZL) +
        #                 szl_id(2) + index(2)
        s7_param = bytes([
            S7_FUNC_USERDATA,
            0x00,                                   # reserved
            0x00, 0x01, 0x12, 0x04, 0x11, 0x00, 0x08, 0x00,
        ])
        s7_data = bytes([
            0x00, 0x01, 0x12, 0x04, 0x10, 0x00,     # param head + item
        ]) + struct.pack(">H", szl_id) + struct.pack(">H", index)
        try:
            body = self._send_recv_s7(s7_param, s7_data)
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"; return out
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"; return out
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"; return out
        # Best-effort decode: the SZL response contains 0xFF (success),
        # a transport size, a data length, then records each prefixed with
        # a 4-byte record header.
        if len(body) < 4:
            out["error"] = "short_szl_resp"; return out
        ret_code = body[0]
        if ret_code != 0x00 and ret_code != 0xFF:
            out["error"] = f"szl_read_error:0x{ret_code:02X}"
            return out
        # Locate the data part — param ends when we see the data item head.
        # For a probe summary we just capture raw_data and split on a 0x14
        # record marker.
        out["raw_data"] = body
        # Records: each record = 4-byte header (len, attrib) + data
        # We do a best-effort split: skip to the first 0x14 or 0x0C record
        # marker following the success byte.
        idx = body.find(b"\x14")
        if idx < 0:
            idx = 0
        # Split into 4-byte-header records (length-first, big-endian 16-bit)
        i = idx
        while i + 4 <= len(body):
            rec_len = struct.unpack(">H", body[i:i + 2])[0]
            i += 4
            if rec_len == 0 or i + rec_len > len(body):
                break
            out["records"].append(body[i:i + rec_len])
            i += rec_len
        out["read_ok"] = True
        return out

    def read_device_identification(self) -> dict:
        """Read order code (SZL 0x0011 index 0x0001) + module info
        (SZL 0x001C index 0x0009)."""
        out = {"order_code": None, "module_name": None,
               "firmware": None, "serial": None, "raw_records": [],
               "read_ok": False, "error": None}
        try:
            # SZL 0x0011 index 0x0001 = order code
            r1 = self.read_szl(SZL_ORDER_CODE, 0x0001)
            if r1.get("read_ok") and r1.get("records"):
                # First record: 20-byte order code string (typically 6ES7...)
                # then 4-byte firmware version + serial number
                rec0 = r1["records"][0]
                # Order code = first 20 bytes ASCII
                try:
                    out["order_code"] = rec0[:20].decode("ascii", errors="replace").strip("\x00")
                except Exception:
                    out["order_code"] = rec0[:20].hex()
                if len(rec0) >= 24:
                    # Bytes 20..23 = firmware (BCD: major.minor.patch)
                    fw = rec0[20:24]
                    try:
                        out["firmware"] = f"V{fw[0]}.{fw[1]}.{(fw[2] >> 4) & 0x0F}.{fw[2] & 0x0F}"
                    except Exception:
                        out["firmware"] = fw.hex()
                if len(rec0) >= 28:
                    try:
                        out["serial"] = rec0[24:28].decode("ascii", errors="replace").strip("\x00")
                    except Exception:
                        out["serial"] = rec0[24:28].hex()
                out["raw_records"].extend(r["hex()"] if isinstance(r, bytes) else r
                                          for r in r1["records"])
            # SZL 0x001C index 0x0001 = module name (different index)
            r2 = self.read_szl(SZL_MODULE, 0x0001)
            if r2.get("read_ok") and r2.get("records"):
                rec0 = r2["records"][0]
                # Bytes 2..22 (skip the 2-byte module ID) = module name ASCII
                try:
                    out["module_name"] = rec0[2:22].decode("ascii", errors="replace").strip("\x00")
                except Exception:
                    out["module_name"] = rec0.hex()
            out["read_ok"] = bool(out["order_code"] or out["module_name"])
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"
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
        "connection_ok": False,
        "read_ok": False,
        "device_info": {},
        "blocks_readable": 0,
        "cve_context": {
            "stuxnet_vector": (
                "S7 read sequence (COTP CR → Setup Comm → Read DB → Read OB) "
                "is the Stuxnet (CVE-2010-xxxx) primitive. This module issues "
                "the read half only. Treat successful reads as CRITICAL: "
                "engineering project exfiltration enables malicious writes."),
            "mitigations": [
                "S7-1500 with S7comm-Plus / TLS protection",
                "PLC password protection (TIA Portal)",
                "Disable PUT/GET server",
                "Restrict rack/slot access; HMI-only access",
            ],
        },
        "results": {},
        "errors": [],
    }

    try:
        with S7RawClient(HOST, PORT, timeout=TIMEOUT_S) as client:
            # 1. COTP CR (connect request)
            try:
                cr = client.cotp_cr()
                summary["connection_ok"] = bool(cr.get("connection_ok"))
                summary["results"]["cotp_cr"] = {
                    "remote_ref": cr.get("remote_ref"),
                    "tpdu_size_negotiated": cr.get("tpdu_size_negotiated"),
                    "error": cr.get("error"),
                }
                if cr.get("error"):
                    summary["errors"].append(f"cotp_cr:{cr['error']}")
            except Exception as e:
                summary["errors"].append(f"cotp_cr:{type(e).__name__}:{e}")

            # Only proceed if COTP connected
            if summary["connection_ok"]:
                # 2. Setup communication
                try:
                    su = client.setup_communication()
                    summary["results"]["setup_comm"] = {
                        "setup_ok": su.get("setup_ok"),
                        "negotiated_pdu_size": su.get("negotiated_pdu_size"),
                        "max_msgs_in": su.get("max_msgs_in"),
                        "max_msgs_out": su.get("max_msgs_out"),
                        "error": su.get("error"),
                    }
                    if su.get("error"):
                        summary["errors"].append(
                            f"setup_comm:{su['error']}")
                except Exception as e:
                    summary["errors"].append(
                        f"setup_comm:{type(e).__name__}:{e}")

                if summary["results"]["setup_comm"].get("setup_ok"):
                    # 3. Read device identification (SZL)
                    try:
                        di = client.read_device_identification()
                        summary["device_info"] = {
                            "order_code": di.get("order_code"),
                            "module_name": di.get("module_name"),
                            "firmware": di.get("firmware"),
                            "serial": di.get("serial"),
                        }
                        summary["results"]["device_id"] = {
                            "read_ok": di.get("read_ok"),
                            "error": di.get("error"),
                        }
                        summary["device_identified"] = bool(di.get("read_ok"))
                        if di.get("error"):
                            summary["errors"].append(
                                f"device_id:{di['error']}")
                    except Exception as e:
                        summary["errors"].append(
                            f"device_id:{type(e).__name__}:{e}")

                    # 4. Read DB block 1, offset 0, count 10
                    try:
                        db = client.read_db(db_number=1, offset=0, count=10)
                        summary["results"]["read_db_1"] = {
                            "read_ok": db.get("read_ok"),
                            "count": db.get("count"),
                            "data_hex": db.get("data", b"").hex() if db.get("data") else "",
                            "error": db.get("error"),
                        }
                        if db.get("read_ok"):
                            summary["blocks_readable"] = 1
                            summary["read_ok"] = True
                        if db.get("error"):
                            summary["errors"].append(
                                f"read_db_1:{db['error']}")
                    except Exception as e:
                        summary["errors"].append(
                            f"read_db_1:{type(e).__name__}:{e}")
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
