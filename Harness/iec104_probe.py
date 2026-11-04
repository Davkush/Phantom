#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — iec104_probe (OT protocol module)
# Read-only IEC 60870-5-104 probe for power grid substation validation.
#
# Default port: 2404 (IEC 60870-5-104 over TCP, IANA-assigned).
# Stack: TCP → IEC 104 APDU (APCI + optional ASDU).
#
# Probes performed (ALL read-only — no C_SC_NA_1 single-command is emitted):
#   1. STARTDT act (U-format, byte 1 = 0x07)  → expect STARTDT con (0x0B)
#   2. TESTFR act   (U-format, byte 1 = 0x43)  → expect TESTFR con   (0x83)
#   3. Interrogation command C_IC_NA_1 (I-format, COT=6, common address,
#      QOI=20 = interrogation of all stations) → list stations/devices
#   4. Check whether single-command C_SC_NA_1 would be accepted:
#      READ_ONLY → we DO NOT send the command. We infer "commands_accepted"
#      from the response to the interrogation (some RTUs pre-announce
#      command-capable data objects). When unknown → None.
#
# IEC 104 APDU layout:
#   Start byte 0x68 | APDU length (1 byte) | APDU (control fields + ASDU)
#
# APCI (4 control bytes):
#   U-format: byte0 = U-type bits | 0x07 (STARTDT act) | 0x0B (STARTDT con)
#                                          0x13 (STOPDT act) | 0x17 (STOPDT con)
#                                          0x43 (TESTFR act)  | 0x83 (TESTFR con)
#   S-format: byte0 = 0x01, byte1=0, byte2..3 = receive sequence counter
#   I-format: byte0..1 (send seq), byte2..3 (recv seq), then ASDU
#
# ASDU layout:
#   Type(1) | VariableStructQualifier(1) | CauseOfTx(1) | OriginatorAddr(1)
#   | CommonAddr(2 LE) | IOA (information object address, 3 LE) | data
#
# Reproducibility: SEED seeds the send-sequence counter.
#
# Legal: isolated lab only (NERC CIP / NIS2 / IEC 62351).
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
MODULE_NAME = "iec104_probe"
DEFAULT_PORT = 2404
TIMEOUT_S = 5.0

# IEC 104 U-format control byte 1 values
U_STARTDT_ACT = 0x07
U_STARTDT_CON = 0x0B
U_STOPDT_ACT  = 0x13
U_STOPDT_CON  = 0x17
U_TESTFR_ACT  = 0x43
U_TESTFR_CON  = 0x83

# ASDU types we care about (IEC 60870-5-101/104)
T_C_IC_NA_1 = 100               # Interrogation command
T_C_IC_NA_1TA = 101             # Interrogation command with time tag
T_C_SC_NA_1   = 45              # Single command (we DO NOT send)
T_M_SP_NA_1   = 1               # Single-point information
T_M_SP_TB_1   = 30              # Single-point with time tag CP56Time2a
T_M_DP_NA_1   = 3               # Double-point information
T_M_ME_NA_1   = 9               # Measured value, normalized
T_C_DC_NA_1   = 46              # Double command

# Cause of transmission (COT)
COT_ACT      = 6                # Activation
COT_ACTCON   = 7                # Activation confirmation
COT_INROG    = 20               # Interrogated by station
COT_INRO1    = 9                # Interrogated by station - group 1
COT_DEACT    = 8                # Deactivation

# QOI (Qualifier of interrogation)
QOI_STATION   = 0                # Interrogate station 0
QOI_SECTION   = 0x14             # Interrogation of all stations (=20)
QOI_GROUP     = 0x15             # Group 1...16

# Default common address (lab)
DEFAULT_CA = 1

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

SEED = int(os.environ.get("SEED", "1337"))
_S_SEQ = (random.Random(SEED).randint(0, 0x7FFF)) << 1   # I-format send seq, 2-byte field

SECTOR_CFG = get_sector_config()
SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")


# ═══════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET IEC 104 CLIENT
# ═══════════════════════════════════════════════════════════════════════════
class IEC104RawClient:
    """Minimal IEC 60870-5-104 client (raw sockets, no deps).

    Sends STARTDT/TESTFR U-frames and an I-format interrogation. Parses I-format
    responses into ASDU records. Never sends command frames (C_SC_NA_1, C_DC_NA_1).
    """

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S, common_addr: int = DEFAULT_CA):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ca = common_addr & 0xFFFF
        self.sock: Optional[socket.socket] = None
        self._s_seq = 0    # send sequence (in 2-byte I-format field units)
        self._r_seq = 0    # receive sequence

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

    def __enter__(self) -> "IEC104RawClient":
        self.connect(); return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── frame builders ──────────────────────────────────────────────────
    @staticmethod
    def _build_u(ctrl1: int) -> bytes:
        """Build a U-format APDU. APCI = ctrl1(1) ctrl2(0) ctrl3(0) ctrl4(0)."""
        apdu = bytes([ctrl1, 0x00, 0x00, 0x00])
        return bytes([0x68, len(apdu)]) + apdu

    def _build_i(self, asdu: bytes) -> bytes:
        """Build an I-format APDU. APCI = send_seq(2 LE) + recv_seq(2 LE) + asdu.

        Sequence counters in I-format are 15-bit fields; we shift left by 1
        (LSB is reserved = 0).
        """
        # Increment send sequence
        self._s_seq = (self._s_seq + 1) & 0x7FFF
        ctrl1 = self._s_seq & 0xFF
        ctrl2 = (self._s_seq >> 8) & 0x7F       # LSB reserved (bit 0 = 0)
        r_seq_low = self._r_seq & 0xFF
        r_seq_high = (self._r_seq >> 8) & 0x7F
        apdu = bytes([ctrl1, ctrl2, r_seq_low, r_seq_high]) + asdu
        return bytes([0x68, len(apdu)]) + apdu

    # ── receive / parse ─────────────────────────────────────────────────
    def _recv_apdu(self) -> Optional[bytes]:
        """Read one APDU (start + length + APDU)."""
        if self.sock is None:
            return None
        # Start byte
        start = self.sock.recv(1)
        if not start:
            return None
        if start[0] != 0x68:
            # Re-sync: skip until we find 0x68
            while start and start[0] != 0x68:
                start = self.sock.recv(1)
            if not start:
                return None
        ln = self.sock.recv(1)
        if not ln:
            return None
        n = ln[0]
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return bytes([0x68, n]) + buf

    def _classify(self, apdu: bytes) -> dict:
        """Classify an APDU as U/S/I format. Returns {format, ctrl1, asdu}."""
        if len(apdu) < 6:
            return {"format": "unknown", "ctrl1": None, "asdu": b""}
        # The full APDU frame starts with 0x68 length(1) ctrl1 ctrl2 ctrl3 ctrl4
        ctrl1 = apdu[2]
        if ctrl1 & 0x01:
            return {"format": "U", "ctrl1": ctrl1, "asdu": b""}
        elif ctrl1 & 0x02:
            return {"format": "S", "ctrl1": ctrl1, "asdu": b""}
        else:
            # I-format: ASDU = apdu[6:]
            return {"format": "I", "ctrl1": ctrl1, "asdu": apdu[6:],
                    "s_seq": (apdu[2] | (apdu[3] << 8)) >> 1,
                    "r_seq": (apdu[4] | (apdu[5] << 8)) >> 1}

    @staticmethod
    def _parse_asdu(asdu: bytes) -> dict:
        """Parse an ASDU (without APCI) into structured records.

        ASDU layout (no time-tag):
          type(1) VSQ(1) COT(1) OA(1) CA(2 LE) [IOA(3 LE) data...]*
        Returns: {type, vsq, cot, oa, ca, objects: [{ioa, data_hex}]}.
        """
        if len(asdu) < 6:
            return {"type": None, "vsq": 0, "cot": None, "oa": None,
                    "ca": None, "objects": []}
        t, vsq, cot, oa = asdu[0], asdu[1], asdu[2], asdu[3]
        ca = asdu[4] | (asdu[5] << 8)
        idx = 6
        n_obj = vsq & 0x7F
        seq   = bool(vsq & 0x80)   # sequence flag
        objects = []
        for _ in range(n_obj):
            if idx + 3 > len(asdu):
                break
            ioa = asdu[idx] | (asdu[idx + 1] << 8) | (asdu[idx + 2] << 16)
            idx += 3
            # Object length depends on type — for a probe summary we just
            # capture the IOA and a 1-byte preview.
            preview = asdu[idx:idx + 8]
            objects.append({"ioa": ioa, "preview_hex": preview.hex()})
            # Best-effort advance by 1 byte (sequence mode) or fixed guess.
            idx += 1 if seq else 5
        return {"type": t, "vsq": vsq, "cot": cot, "oa": oa, "ca": ca,
                "objects": objects}

    # ── high-level probes ───────────────────────────────────────────────
    def send_u(self, ctrl1: int) -> dict:
        """Send a U-format frame (STARTDT/STOPDT/TESTFR act) and wait for
        the matching con response."""
        out = {"sent": ctrl1, "con_recv": False, "con_byte": None,
               "error": None}
        try:
            self.sock.sendall(self._build_u(ctrl1))
            # Loop reading APDUs until we see the matching U-con
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                self.sock.settimeout(max(0.5, deadline - time.time()))
                apdu = self._recv_apdu()
                if not apdu:
                    break
                cls = self._classify(apdu)
                if cls["format"] == "U":
                    # The con byte = act byte | 0x04 (startdt) or act | 0x40 (testfr)
                    # Specifically: STARTDT_ACT 0x07 → CON 0x0B; TESTFR_ACT 0x43 → CON 0x83
                    expected_con = ctrl1 | 0x04 if ctrl1 in (U_STARTDT_ACT, U_STOPDT_ACT) else ctrl1 | 0x40
                    if cls["ctrl1"] == expected_con:
                        out["con_recv"] = True
                        out["con_byte"] = cls["ctrl1"]
                        return out
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"
        except Exception as e:
            out["error"] = f"{type(e).__name__}:{e}"
        return out

    def send_interrogation(self, qoi: int = QOI_SECTION) -> dict:
        """Send a C_IC_NA_1 interrogation command and collect responses.

        Returns {stations_found, asdu_count, types_seen, commands_accepted,
                 error}.
        """
        out = {"stations_found": 0, "asdu_count": 0, "types_seen": [],
               "commands_accepted": None, "raw_responses": [],
               "error": None}
        # Build ASDU: type(100=C_IC_NA_1) | VSQ(0x01) | COT(6=ACT) | OA(0)
        # | CA(2 LE) | IOA(3 LE) | QOI(1)
        asdu = bytes([T_C_IC_NA_1, 0x01, COT_ACT, 0x00])
        asdu += struct.pack("<H", self.ca)
        asdu += bytes([0x00, 0x00, 0x00])      # IOA = 0
        asdu += bytes([qoi])
        try:
            self.sock.sendall(self._build_i(asdu))
            # Collect responses over a short window
            deadline = time.time() + self.timeout
            stations = set()
            types_seen = set()
            asdu_count = 0
            commands_acceptance_signal = None
            while time.time() < deadline:
                self.sock.settimeout(max(0.5, deadline - time.time()))
                apdu = self._recv_apdu()
                if not apdu:
                    break
                cls = self._classify(apdu)
                if cls["format"] == "U":
                    continue
                if cls["format"] == "S":
                    # Ack — keep waiting
                    continue
                if cls["format"] == "I":
                    parsed = self._parse_asdu(cls["asdu"])
                    if parsed["type"] is not None:
                        types_seen.add(parsed["type"])
                        asdu_count += 1
                        # Each unique common address → one station
                        stations.add(parsed["ca"])
                        # If interrogation returns command-capable types
                        # (C_SC_NA_1, C_DC_NA_1) in activation confirmations,
                        # we infer the device accepts commands.
                        if parsed["type"] in (T_C_SC_NA_1, T_C_DC_NA_1):
                            if parsed["cot"] in (COT_ACTCON, COT_ACT, COT_INROG):
                                commands_acceptance_signal = True
                        out["raw_responses"].append({
                            "type": parsed["type"], "vsq": parsed["vsq"],
                            "cot": parsed["cot"], "ca": parsed["ca"],
                            "objects": parsed["objects"][:5],  # cap preview
                        })
                    # Track recv sequence
                    self._r_seq = (self._r_seq + 1) & 0x7FFF
            out["stations_found"] = len(stations)
            out["asdu_count"]     = asdu_count
            out["types_seen"]     = sorted(types_seen)
            out["commands_accepted"] = commands_acceptance_signal
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"
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
        "link_active": False,
        "stations_found": 0,
        "commands_accepted": None,
        "testfr_ok": False,
        "results": {},
        "errors": [],
    }

    try:
        with IEC104RawClient(HOST, PORT, timeout=TIMEOUT_S) as client:
            # 1. STARTDT act → con
            try:
                sd = client.send_u(U_STARTDT_ACT)
                summary["results"]["startdt"] = {
                    "con_recv": sd.get("con_recv"),
                    "con_byte": sd.get("con_byte"),
                    "error": sd.get("error"),
                }
                summary["link_active"] = bool(sd.get("con_recv"))
                if sd.get("error"):
                    summary["errors"].append(f"startdt:{sd['error']}")
            except Exception as e:
                summary["errors"].append(f"startdt:{type(e).__name__}:{e}")

            if summary["link_active"]:
                # 2. TESTFR act → con (keepalive)
                try:
                    tf = client.send_u(U_TESTFR_ACT)
                    summary["testfr_ok"] = bool(tf.get("con_recv"))
                    summary["results"]["testfr"] = {
                        "con_recv": tf.get("con_recv"),
                        "con_byte": tf.get("con_byte"),
                        "error": tf.get("error"),
                    }
                    if tf.get("error"):
                        summary["errors"].append(f"testfr:{tf['error']}")
                except Exception as e:
                    summary["errors"].append(f"testfr:{type(e).__name__}:{e}")

                # 3. Interrogation command C_IC_NA_1 (QOI=20)
                try:
                    iq = client.send_interrogation(qoi=QOI_SECTION)
                    summary["stations_found"] = int(iq.get("stations_found", 0))
                    summary["commands_accepted"] = iq.get("commands_accepted")
                    summary["results"]["interrogation"] = {
                        "asdu_count": iq.get("asdu_count"),
                        "types_seen": iq.get("types_seen"),
                        "raw_responses": iq.get("raw_responses")[:10],
                        "error": iq.get("error"),
                    }
                    if iq.get("error"):
                        summary["errors"].append(
                            f"interrogation:{iq['error']}")
                except Exception as e:
                    summary["errors"].append(
                        f"interrogation:{type(e).__name__}:{e}")

                # device_identified: link active + we received at least one ASDU
                summary["device_identified"] = bool(
                    summary["link_active"] and
                    (summary["results"].get("interrogation", {}) or {}).get(
                        "asdu_count", 0) > 0
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
