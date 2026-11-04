#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — iec104_probe
# Energy/SCADA validation module — IEC 60870-5-104 APDU probing.
#
#   - Default port : 2404 (IEC 60870-5-104 TCP)
#   - Functions    : send_uframe_startact   (U-Format STARTDT act → con),
#                    send_testfr            (U-Format TESTFR act → con),
#                    read_interrogation     (I-Format, type 100 C_IC_NA_1,
#                                            COT 6, QOI 20 → reads ALL data),
#                    try_single_command     (I-Format, type 45 C_SC_NA_1 —
#                                            SAFE_MODE=full only; controls a
#                                            physical device)
#   - Raw socket implementation: full APDU builder
#       (start byte 0x68, APDU length, 4-byte control field, ASDU).
#       Handles U-Format (link control), S-Format (ack), I-Format (sequenced
#       data). I-Format control field encodes 15-bit N(S)/N(R) with LSB=0.
#   - Respects SAFE_MODE : if read_only, single-command is skipped and
#     reported as "write_skipped_safe_mode" (NO packet emitted — a single
#     command can trip a physical relay / breaker).
#   - LAB=1 mandatory. 5 s timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (energy) : NERC CIP, NIS2, ENISA, IEC 60870.
#
# Output JSON (top-level fields required by the spec):
#   link_active, testfr_ok, interrogation_read, command_tested, asdu_common_addr
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
MODULE_NAME = "iec104_probe"
DEFAULT_PORT = 2404
TIMEOUT_S = 5.0

# ─── ASDU defaults ─────────────────────────────────────────────────────────
# Common address 1 is the most common RTU/IED address in lab setups.
# Originator address 0 = local (no specific originator).
ASDU_COMMON_ADDR = 1
ASDU_ORIGINATOR_ADDR = 0

# ─── U-Format function bytes (control field 1) ────────────────────────────
# Per IEC 60870-5-104 §4.2.1:
#   STARTDT act = 0x07, STARTDT con = 0x0B
#   STOPDT  act = 0x13, STOPDT  con = 0x17
#   TESTFR  act = 0x43, TESTFR  con = 0x83
# Bits 0-1 of byte 1 = 0b11 (U-format); bits 2-7 hold the function.
U_STARTDT_ACT = 0x07
U_STARTDT_CON = 0x0B
U_STOPDT_ACT  = 0x13
U_STOPDT_CON  = 0x17
U_TESTFR_ACT  = 0x43
U_TESTFR_CON  = 0x83

# ─── ASDU type identifiers (IEC 60870-5-101 §7.2.1) ───────────────────────
T_C_IC_NA_1 = 100   # Interrogation command
T_C_SC_NA_1 = 45    # Single command

# ─── Cause Of Transmission (COT) ───────────────────────────────────────────
COT_ACTIVATION          = 6
COT_ACTIVATION_CON      = 7
COT_DEACTIVATION        = 8
COT_INTERROGATED_BY_GEN = 20   # response COT after interrogation
COT_RETURN_INFO_REMOTE  = 9    # data returned from a remote site

# ─── QOI (Qualifier of Interrogation) ──────────────────────────────────────
QOI_INTERROGATE_ALL = 20

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
#  APDU BUILDERS
# ═══════════════════════════════════════════════════════════════════════════
def build_uframe(func_byte: int) -> bytes:
    """U-Format APDU: 0x68 0x04 [func] 0x00 0x00 0x00."""
    return bytes([0x68, 0x04, func_byte, 0x00, 0x00, 0x00])


def build_sframe(nr: int) -> bytes:
    """S-Format APDU (supervisory ACK).

    byte1 = 0x01 (bit 0 = 1 marks S-format, bit 1 = 0)
    byte2 = 0x00
    byte3/4 = N(R) shifted left 1 with LSB=0 (I-format / S-format convention)
    """
    byte1_2 = 0x0001
    byte3_4 = (nr & 0x7FFF) << 1
    return bytes([0x68, 0x04]) + struct.pack("<HH", byte1_2, byte3_4)


def build_iframe(ns: int, nr: int, asdu: bytes) -> bytes:
    """I-Format APDU carrying an ASDU.

    Control field layout (4 bytes):
      byte1 bits 1-7 + byte2 bits 0-7  → N(S) (15 bits), byte1 bit 0 = 0
      byte3 bits 1-7 + byte4 bits 0-7  → N(R) (15 bits), byte3 bit 0 = 0
    """
    byte1_2 = (ns & 0x7FFF) << 1   # LSB=0 marks I-format
    byte3_4 = (nr & 0x7FFF) << 1
    ctrl = struct.pack("<HH", byte1_2, byte3_4)
    apdu_len = len(ctrl) + len(asdu)   # always 4 + len(ASDU)
    return bytes([0x68, apdu_len & 0xFF]) + ctrl + asdu


def build_asdu(type_id: int, vsq: int, cot: int, common_addr: int,
               originator: int = ASDU_ORIGINATOR_ADDR,
               ioa: int = 0, payload: bytes = b"") -> bytes:
    """Build a generic ASDU.

    Layout per IEC 60870-5-101 §7.2:
      Type(1) + VSQ(1) + COT(1) + OA(1) + CA(2 LE) + IOA(3 LE) + payload
    VSQ bit 7 = SQ (sequence), bits 0-6 = number of objects.
    """
    head = bytes([
        type_id & 0xFF,
        vsq & 0xFF,
        cot & 0xFF,
        originator & 0xFF,
    ]) + struct.pack("<H", common_addr & 0xFFFF)
    ioa_bytes = struct.pack("<I", ioa & 0xFFFFFF)[:3]   # 24-bit LE IOA
    return head + ioa_bytes + payload


def build_interrogation_asdu(common_addr: int = ASDU_COMMON_ADDR,
                             ioa: int = 0,
                             qoi: int = QOI_INTERROGATE_ALL) -> bytes:
    """C_IC_NA_1 interrogation command (type 100, COT 6, QOI 20)."""
    return build_asdu(T_C_IC_NA_1, vsq=0x01, cot=COT_ACTIVATION,
                      common_addr=common_addr, ioa=ioa,
                      payload=bytes([qoi & 0xFF]))


def build_single_command_asdu(common_addr: int = ASDU_COMMON_ADDR,
                              ioa: int = 1,
                              state: int = 1,
                              qu: int = 0,
                              select: bool = False) -> bytes:
    """C_SC_NA_1 single command (type 45, COT 6).

    QOS (Qualifier of Single Command) byte layout per IEC 60870-5-101
    §7.2.6.39:
      bit 0     SCS  (state: 0=OFF, 1=ON)
      bits 1-2  QU   (qualifier, 0=default)
      bit 7     S/E  (0=execute, 1=select)
    """
    qos = (state & 0x01) | ((qu & 0x03) << 1) | (0x80 if select else 0x00)
    return build_asdu(T_C_SC_NA_1, vsq=0x01, cot=COT_ACTIVATION,
                      common_addr=common_addr, ioa=ioa,
                      payload=bytes([qos & 0xFF]))


# ═══════════════════════════════════════════════════════════════════════════
#  APDU PARSER
# ═══════════════════════════════════════════════════════════════════════════
def parse_apdu(data: bytes) -> Optional[dict]:
    """Parse one APDU from the start of `data`.

    Returns dict with keys: format ('U'|'S'|'I'), raw_len, and
    format-specific fields (func for U, ns/nr for S and I, asdu for I).
    Returns None if `data` is too short to contain a full APDU.
    """
    if len(data) < 6:
        return None
    if data[0] != 0x68:
        return None
    apdu_len = data[1]
    total = 2 + apdu_len
    if len(data) < total:
        return None
    ctrl1 = data[2]
    ctrl2 = data[3]
    ctrl3 = data[4]
    ctrl4 = data[5]

    # Identify format by bit pattern in control field byte 1.
    #   U-format: bits 0-1 = 0b11 (both set)
    #   S-format: bit 0 = 1, bit 1 = 0
    #   I-format: bit 0 = 0
    if (ctrl1 & 0x01) == 0x01:
        if (ctrl1 & 0x02) == 0x02:
            # U-format — function is encoded in the full byte value.
            return {"format": "U", "raw_len": total, "func": ctrl1,
                    "raw": data[:total]}
        else:
            # S-format
            nr = ((ctrl3 | (ctrl4 << 8)) >> 1) & 0x7FFF
            return {"format": "S", "raw_len": total, "nr": nr,
                    "raw": data[:total]}
    else:
        # I-format
        ns = ((ctrl1 | (ctrl2 << 8)) >> 1) & 0x7FFF
        nr = ((ctrl3 | (ctrl4 << 8)) >> 1) & 0x7FFF
        asdu = data[6:total]
        return {"format": "I", "raw_len": total, "ns": ns, "nr": nr,
                "asdu": asdu, "raw": data[:total]}


def parse_asdu(asdu: bytes) -> Optional[dict]:
    """Parse an ASDU into its component fields."""
    if len(asdu) < 6:
        return None
    type_id    = asdu[0]
    vsq        = asdu[1]
    cot        = asdu[2]
    originator = asdu[3]
    common_addr = struct.unpack("<H", asdu[4:6])[0]
    ioa = 0
    payload = b""
    if len(asdu) >= 9:
        ioa_bytes = asdu[6:9]
        ioa = ioa_bytes[0] | (ioa_bytes[1] << 8) | (ioa_bytes[2] << 16)
        payload = asdu[9:]
    return {
        "type_id": type_id,
        "vsq": vsq,
        "cot": cot,
        "originator": originator,
        "common_addr": common_addr,
        "ioa": ioa,
        "payload": payload,
    }


# ═══════════════════════════════════════════════════════════════════════════
#  IEC104 RAW TRANSPORT (TCP)
# ═══════════════════════════════════════════════════════════════════════════
class Iec104RawClient:
    """Minimal IEC 60870-5-104 TCP client (raw sockets, no external deps)."""

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        # Sequence counters (15-bit, wrapped at 32768)
        self.ns = 0   # next send sequence
        self.nr = 0   # next receive sequence

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

    def __enter__(self) -> "Iec104RawClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── raw IO ───────────────────────────────────────────────────────────
    def _send_raw(self, apdu: bytes) -> None:
        if self.sock is None:
            raise RuntimeError("socket not connected")
        self.sock.sendall(apdu)

    def _recv_raw(self, timeout: float = 2.0) -> bytes:
        """Read whatever arrives within `timeout`. May contain multiple APDUs."""
        if self.sock is None:
            raise RuntimeError("socket not connected")
        old_to = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        chunks = []
        try:
            while True:
                try:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except (socket.timeout, TimeoutError):
                    break
        finally:
            self.sock.settimeout(old_to)
        return b"".join(chunks)

    # ── frame senders ────────────────────────────────────────────────────
    def send_uframe(self, func_byte: int) -> None:
        self._send_raw(build_uframe(func_byte))

    def send_sframe(self, nr: Optional[int] = None) -> None:
        if nr is None:
            nr = self.nr
        self._send_raw(build_sframe(nr))

    def send_iframe(self, asdu: bytes) -> int:
        """Send an I-format frame, return the N(S) used."""
        ns_used = self.ns
        apdu = build_iframe(self.ns, self.nr, asdu)
        self._send_raw(apdu)
        self.ns = (self.ns + 1) & 0x7FFF
        return ns_used

    # ── frame receiver ───────────────────────────────────────────────────
    def recv_apdus(self, timeout: float = 2.0) -> list:
        """Receive all APDUs that arrive within `timeout`."""
        raw = self._recv_raw(timeout=timeout)
        apdus = []
        offset = 0
        while offset < len(raw):
            parsed = parse_apdu(raw[offset:])
            if parsed is None:
                break
            apdus.append(parsed)
            offset += parsed["raw_len"]
            # Update N(R) based on received I-frames
            if parsed["format"] == "I":
                self.nr = (self.nr + 1) & 0x7FFF
        return apdus


# ═══════════════════════════════════════════════════════════════════════════
#  PROBE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
def send_uframe_startact(client: Iec104RawClient) -> dict:
    """U-Format STARTDT act — start data transfer with the outstation.

    Per IEC 60870-5-104 §4.2.1, the controlled (server) side replies with
    STARTDT con (0x0B) when it accepts the start request.
    """
    result = {"active": False, "con_received": False,
              "response_func": None, "error": None}
    try:
        client.send_uframe(U_STARTDT_ACT)
        apdus = client.recv_apdus(timeout=2.0)
        for ap in apdus:
            if ap["format"] == "U":
                result["response_func"] = ap["func"]
                if ap["func"] == U_STARTDT_CON:
                    result["con_received"] = True
                    result["active"] = True
                    break
        if not result["con_received"] and apdus:
            result["error"] = "unexpected_response"
        elif not apdus:
            result["error"] = "timeout"
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def send_testfr(client: Iec104RawClient) -> dict:
    """U-Format TESTFR act → con. Per IEC 60870-5-104 §4.2.2.

    Used as a keepalive (t3 timer). The controlled side echoes with TESTFR
    con (0x83).
    """
    result = {"ok": False, "con_received": False,
              "response_func": None, "error": None}
    try:
        client.send_uframe(U_TESTFR_ACT)
        apdus = client.recv_apdus(timeout=2.0)
        for ap in apdus:
            if ap["format"] == "U":
                result["response_func"] = ap["func"]
                if ap["func"] == U_TESTFR_CON:
                    result["con_received"] = True
                    result["ok"] = True
                    break
        if not result["con_received"] and apdus:
            result["error"] = "unexpected_response"
        elif not apdus:
            result["error"] = "timeout"
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def read_interrogation(client: Iec104RawClient,
                       common_addr: int = ASDU_COMMON_ADDR) -> dict:
    """I-Format interrogation command (C_IC_NA_1, type 100, COT 6, QOI 20).

    Triggers the outstation to send ALL its data points (per IEC 60870-5-101
    §7.2.6.22 — QOI=20 reads everything: digital + analog + counters).
    This is the classic unauthenticated data dump vector for IEC104.
    """
    result = {"read": False, "asdu_count": 0, "bytes_returned": 0,
              "types_seen": [], "cot_seen": [], "error": None}
    asdu_req = build_interrogation_asdu(common_addr=common_addr)
    try:
        client.send_iframe(asdu_req)
        # Interrogation can produce a burst of I-frames; collect for up to 3 s.
        all_apdus = []
        deadline = time.time() + 3.0
        while time.time() < deadline:
            batch = client.recv_apdus(timeout=1.0)
            if not batch:
                break
            all_apdus.extend(batch)
            # If we see an activation-confirmation (COT=7) for type 100,
            # the interrogation cycle is complete — stop early.
            parsed = [parse_asdu(a["asdu"]) for a in batch
                      if a["format"] == "I"]
            if any(p and p.get("cot") == COT_ACTIVATION_CON
                   and p.get("type_id") == T_C_IC_NA_1
                   for p in parsed):
                break

        i_frames = [a for a in all_apdus if a["format"] == "I"]
        result["asdu_count"] = len(i_frames)
        result["bytes_returned"] = sum(len(a["asdu"]) for a in i_frames)
        types_seen = set()
        cots_seen = set()
        for a in i_frames:
            p = parse_asdu(a["asdu"])
            if p:
                types_seen.add(p["type_id"])
                cots_seen.add(p["cot"])
        result["types_seen"] = sorted(types_seen)
        result["cot_seen"] = sorted(cots_seen)
        result["read"] = (result["bytes_returned"] > 0)
        # Send an S-frame ACK so the server doesn't retransmit.
        try:
            client.send_sframe()
        except Exception:
            pass
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def try_single_command(client: Iec104RawClient,
                       common_addr: int = ASDU_COMMON_ADDR,
                       ioa: int = 1,
                       state: int = 1) -> dict:
    """I-Format single command (C_SC_NA_1, type 45, COT 6).

    ONLY attempted if SAFE_MODE=full. Respects SAFE_MODE : if read_only,
    returns "write_skipped_safe_mode" and emits NO packet — a single
    command can control a physical device (relay, breaker, valve).
    """
    result = {
        "tested": False,
        "command_ok": False,
        "ioa": ioa,
        "state": state,
        "response_cot": None,
        "status": None,
        "error": None,
    }

    # SAFE_MODE gate — primary guard (do not exit, just skip).
    if not is_write_allowed():
        result["status"] = "write_skipped_safe_mode"
        return result

    # Defense-in-depth: sector_base guard (would exit(3) if bypassed).
    check_write_allowed(MODULE_NAME)

    asdu_req = build_single_command_asdu(common_addr=common_addr, ioa=ioa,
                                         state=state, select=False)
    try:
        client.send_iframe(asdu_req)
        apdus = client.recv_apdus(timeout=2.0)
        result["tested"] = True
        i_frames = [a for a in apdus if a["format"] == "I"]
        for a in i_frames:
            p = parse_asdu(a["asdu"])
            if p and p["type_id"] == T_C_SC_NA_1:
                result["response_cot"] = p["cot"]
                # COT=7 (activation confirmation) → command accepted
                if p["cot"] == COT_ACTIVATION_CON:
                    result["command_ok"] = True
                    result["status"] = "command_accepted"
                else:
                    result["status"] = f"cot_{p['cot']}"
                break
        else:
            if i_frames:
                result["status"] = "no_command_response"
            else:
                result["status"] = "no_response"
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        result["status"] = "timeout"
        result["tested"] = True
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        result["status"] = "conn_error"
        result["tested"] = True
    except SystemExit:
        # check_write_allowed may sys.exit(3) — propagate cleanly.
        raise
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
        result["status"] = "error"
        result["tested"] = True
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
            "legal_note": ("IEC 60870-5-104 probing on production RTUs "
                           "is illegal outside an authorized lab. "
                           "NERC CIP / NIS2 / ENISA / IEC 60870."),
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
        "transport": "raw_socket",
        # Spec-required top-level output fields:
        "link_active": False,
        "testfr_ok": False,
        "interrogation_read": False,
        "command_tested": False,
        "asdu_common_addr": ASDU_COMMON_ADDR,
        # Detail / error reporting:
        "details": {},
        "errors": [],
    }

    try:
        with Iec104RawClient(HOST, PORT, timeout=TIMEOUT_S) as client:
            # 1. STARTDT act → con (establish data transfer)
            sa = send_uframe_startact(client)
            summary["link_active"] = bool(sa.get("active"))
            summary["details"]["startdt"] = sa
            if sa.get("error"):
                summary["errors"].append(f"send_uframe_startact:{sa['error']}")

            # 2. TESTFR act → con (link keepalive)
            tf = send_testfr(client)
            summary["testfr_ok"] = bool(tf.get("ok"))
            summary["details"]["testfr"] = tf
            if tf.get("error"):
                summary["errors"].append(f"send_testfr:{tf['error']}")

            # 3. Interrogation (read all data)
            iq = read_interrogation(client, common_addr=ASDU_COMMON_ADDR)
            summary["interrogation_read"] = bool(iq.get("read"))
            summary["details"]["interrogation"] = iq
            if iq.get("error"):
                summary["errors"].append(f"read_interrogation:{iq['error']}")

            # 4. Single command — SAFE_MODE=full only
            sc = try_single_command(client, common_addr=ASDU_COMMON_ADDR,
                                    ioa=1, state=1)
            summary["command_tested"] = bool(sc.get("tested"))
            summary["details"]["single_command"] = sc
            if sc.get("error"):
                summary["errors"].append(f"try_single_command:{sc['error']}")
            if sc.get("status") == "write_skipped_safe_mode":
                summary["details"]["single_command"]["note"] = (
                    "SAFE_MODE is read_only for this sector — single command "
                    "NOT attempted (would drive a physical relay/breaker). "
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
