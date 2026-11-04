#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — synchrophasor_probe
# Energy sector validation module — IEEE C37.118 Phasor Measurement Unit
# (PMU) / Synchrophasor protocol probing.
#
#   - Default ports : 19999 (PC37.118 default) and 4713 (openPDC / historical)
#   - Functions:
#       send_cfg_request   — Command frame with CMD=0x0005 (send CFG-1) and
#                            CMD=0x0004 (send CFG-2). Parse the returned
#                            configuration frame to extract NUMPMU, FORMAT,
#                            DATA_RATE.
#       send_data_request  — Command frame with CMD=0x0002 (turn on data
#                            transmission). Read back a data frame to
#                            confirm real-time phasor streaming.
#       check_auth         — IEEE C37.118 has NO native authentication. If a
#                            PMU responds to a command frame without any
#                            preceding auth exchange ⇒ authenticated=False
#                            (CRITICAL — manipulation could affect grid
#                            stability).
#   - Raw socket implementation: full C37.118 frame builder
#       (SYNC 0xAA + type/version byte + FRAMESIZE + IDCODE + SOC + FRACSEC
#        + FRAMEDATA + CHK = CRC-CCITT/X.25 over SYNC..end-of-FRAMEDATA).
#   - READ_ONLY=True (energy sector safety constraint) — we only send
#     read-type commands (0x0003 header, 0x0004 CFG-2, 0x0005 CFG-1,
#     0x0002 turn-on-data). We NEVER send 0x0001 (turn off data — could
#     blind a control center) and we never inject spoofed data frames.
#   - SEED env var : deterministic IDCODE selection.
#   - LAB=1 mandatory. 5 s timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (energy) : NERC CIP, NIS2, ENISA, IEEE C37.118,
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
MODULE_NAME = "synchrophasor_probe"
DEFAULT_PORT = 19999
ALT_PORT = 4713
TIMEOUT_S = 5.0
READ_ONLY = True  # energy sector safety constraint

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── SEED for deterministic IDCODE ─────────────────────────────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else None
except ValueError:
    SEED = None
_rng = random.Random(SEED) if SEED is not None else random.Random()


def _our_idcode() -> int:
    """Return a deterministic 16-bit IDCODE for our command frames
    (this is the *destination* IDCODE in our command; the PMU's own IDCODE
    appears in its responses)."""
    return _rng.randint(1, 0xFFFE) or 1


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
#  IEEE C37.118 CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
SYNC_WORD = 0xAA

# Frame type (bits 7-6 of SYNC byte 2) + version (bits 5-4)
# We use version 2 (C37.118-2011) = 0b10 in bits 5-4.
def _sync_byte(frame_type: int, version: int = 2) -> int:
    """Build the second SYNC byte: frame_type(bits 7-6) | version(bits 5-4) | 0."""
    return ((frame_type & 0x03) << 6) | ((version & 0x03) << 4)

FRAME_TYPE_DATA = 0x00
FRAME_TYPE_HEADER = 0x01
FRAME_TYPE_CONFIG = 0x02
FRAME_TYPE_COMMAND = 0x03

SYNC_DATA = bytes([SYNC_WORD, _sync_byte(FRAME_TYPE_DATA)])
SYNC_HEADER = bytes([SYNC_WORD, _sync_byte(FRAME_TYPE_HEADER)])
SYNC_CONFIG = bytes([SYNC_WORD, _sync_byte(FRAME_TYPE_CONFIG)])
SYNC_COMMAND = bytes([SYNC_WORD, _sync_byte(FRAME_TYPE_COMMAND)])

# Command codes (CMD field, 2 bytes BE)
CMD_TURN_OFF_DATA = 0x0001   # READ-ONLY GUARD: never sent
CMD_TURN_ON_DATA = 0x0002
CMD_SEND_HEADER = 0x0003
CMD_SEND_CFG2 = 0x0004
CMD_SEND_CFG1 = 0x0005       # C37.118-2005 CFG-1 / 2011 CFG-3

# Frame type names for response parsing
_FRAME_TYPE_NAMES = {
    FRAME_TYPE_DATA: "data",
    FRAME_TYPE_HEADER: "header",
    FRAME_TYPE_CONFIG: "config",
    FRAME_TYPE_COMMAND: "command",
}


# ═══════════════════════════════════════════════════════════════════════════
#  CRC-CCITT (X.25 / "FALSE" variant, init=0xFFFF, poly=0x1021)
# ═══════════════════════════════════════════════════════════════════════════
def crc_ccitt(data: bytes) -> int:
    """Compute CRC-CCITT (FALSE variant, as used by IEEE C37.118).

    Polynomial 0x1021, initial value 0xFFFF, MSB-first (non-reflected),
    NO final XOR. This matches the openPDC / IEEE C37.118-2011 §6.2.3.1
    reference implementation.

    Test vector: crc_ccitt(b"123456789") == 0x29B1.
    Returns a 16-bit value.
    """
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def crc_ccitt_verify(frame: bytes) -> bool:
    """Verify the trailing 2-byte CRC of a complete C37.118 frame."""
    if len(frame) < 4:
        return False
    payload = frame[:-2]
    expected = struct.unpack(">H", frame[-2:])[0]
    return crc_ccitt(payload) == expected


# ═══════════════════════════════════════════════════════════════════════════
#  FRAME BUILDERS
# ═══════════════════════════════════════════════════════════════════════════
def build_command_frame(idcode: int, cmd: int,
                        soc: int = 0, fracsec: int = 0) -> bytes:
    """Build a complete IEEE C37.118 command frame.

    Layout:
      SYNC (2) + FRAMESIZE (2 BE) + IDCODE (2 BE) + SOC (4 BE) +
      FRACSEC (4 BE) + CMD (2 BE) + CHK (2 BE)

    Total fixed size = 18 bytes. FRAMESIZE counts the whole frame
    including SYNC and CHK (per IEEE C37.118-2011 §6.2).
    """
    framesize = 18
    header = (
        SYNC_COMMAND
        + struct.pack(">H", framesize)
        + struct.pack(">H", idcode & 0xFFFF)
        + struct.pack(">I", soc & 0xFFFFFFFF)
        + struct.pack(">I", fracsec & 0xFFFFFFFF)
        + struct.pack(">H", cmd & 0xFFFF)
    )
    crc = crc_ccitt(header)
    return header + struct.pack(">H", crc)


# ═══════════════════════════════════════════════════════════════════════════
#  FRAME READING + PARSING
# ═══════════════════════════════════════════════════════════════════════════
def _read_n(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def read_frame(sock: socket.socket, timeout: float = TIMEOUT_S
               ) -> Optional[bytes]:
    """Read one complete C37.118 frame. Returns the raw frame bytes
    (including CRC) or None on timeout / parse error.

    Strategy: read 4 bytes (SYNC + FRAMESIZE), then read the rest of the
    frame based on FRAMESIZE.
    """
    sock.settimeout(timeout)
    head = _read_n(sock, 4)
    if len(head) < 4:
        return None
    if head[0] != SYNC_WORD:
        return None
    framesize = struct.unpack(">H", head[2:4])[0]
    if framesize < 4 or framesize > 65535:
        return None
    remaining = _read_n(sock, framesize - 4)
    if len(remaining) < framesize - 4:
        return None
    return head + remaining


def parse_frame_type(frame: bytes) -> Optional[int]:
    """Return the frame type (0..3) from a complete frame, or None."""
    if len(frame) < 2 or frame[0] != SYNC_WORD:
        return None
    return (frame[1] >> 6) & 0x03


def parse_frame_version(frame: bytes) -> Optional[int]:
    """Return the version (0..3) from a complete frame, or None."""
    if len(frame) < 2 or frame[0] != SYNC_WORD:
        return None
    return (frame[1] >> 4) & 0x03


def parse_common_header(frame: bytes) -> Optional[Dict]:
    """Parse the common C37.118 frame header (first 12 bytes).

    Returns: {sync, frame_type, version, framesize, idcode, soc, fracsec}
    """
    if len(frame) < 12:
        return None
    sync1 = frame[0]
    sync2 = frame[1]
    framesize = struct.unpack(">H", frame[2:4])[0]
    idcode = struct.unpack(">H", frame[4:6])[0]
    soc = struct.unpack(">I", frame[6:10])[0]
    fracsec = struct.unpack(">I", frame[10:14])[0] if len(frame) >= 14 else 0
    return {
        "sync": sync1,
        "frame_type": (sync2 >> 6) & 0x03,
        "version": (sync2 >> 4) & 0x03,
        "framesize": framesize,
        "idcode": idcode,
        "soc": soc,
        "fracsec": fracsec,
    }


def parse_config_frame(frame: bytes) -> Optional[Dict]:
    """Parse a C37.118 configuration frame (CFG-1 or CFG-2).

    CFG-2 layout (C37.118-2011):
      SYNC(2) + FRAMESIZE(2) + IDCODE(2) + SOC(4) + FRACSEC(4) +
      NUMPMU(2) +
      for each PMU (i = NUMPMU):
        STN(16) + IDCODE(2) + FORMAT(2) + PHNMR(2) + ANNMR(2) + DIGNMR(2) +
        CHNAM(16*(PHNMR+ANNMR+DIGNMR)) +
        PHUNIT(4*PHNMR) + ANUNIT(2*ANNMR + extra?) + DIGUNIT(4*DIGNMR) +
        FNOM(2) + CFGCOUNT(2)
      DATA_RATE(2) + CHK(2)

    We extract: NUMPMU, per-PMU station names, FORMAT, channel counts,
    FNOM, DATA_RATE.

    Returns a dict with the parsed fields, or None on parse failure.
    """
    hdr = parse_common_header(frame)
    if hdr is None:
        return None
    if hdr["frame_type"] != FRAME_TYPE_CONFIG:
        return None
    # Need at least through NUMPMU
    if len(frame) < 16:
        return None
    numpmu = struct.unpack(">H", frame[14:16])[0]
    result = {
        "numpmu": numpmu,
        "idcode": hdr["idcode"],
        "soc": hdr["soc"],
        "fracsec": hdr["fracsec"],
        "version": hdr["version"],
        "framesize": hdr["framesize"],
        "stations": [],
        "data_rate": None,
        "fnom": None,
        "format_per_pmu": [],
        "channel_counts": [],
        "crc_ok": crc_ccitt_verify(frame),
    }
    idx = 16
    try:
        for _ in range(numpmu):
            if idx + 16 + 2 + 2 + 2 + 2 + 2 > len(frame):
                break
            stn = frame[idx:idx + 16].decode("ascii", errors="replace").rstrip("\x00 ")
            idx += 16
            pmu_id = struct.unpack(">H", frame[idx:idx + 2])[0]
            idx += 2
            fmt = struct.unpack(">H", frame[idx:idx + 2])[0]
            idx += 2
            phnmr = struct.unpack(">H", frame[idx:idx + 2])[0]
            idx += 2
            annmr = struct.unpack(">H", frame[idx:idx + 2])[0]
            idx += 2
            dignmr = struct.unpack(">H", frame[idx:idx + 2])[0]
            idx += 2
            # Skip channel names (16 bytes each, total phnmr+annmr+dignmr)
            chnam_len = 16 * (phnmr + annmr + dignmr)
            idx += chnam_len
            # Skip PHUNIT (4 bytes * phnmr)
            idx += 4 * phnmr
            # ANUNIT (2 bytes * annmr, + 2 bytes * annmr for ANUNMASK in 2011)
            idx += 2 * annmr
            # Skip DIGUNIT (4 bytes * dignmr)
            idx += 4 * dignmr
            # FNOM (2) + CFGCOUNT (2)
            if idx + 4 > len(frame):
                break
            fnom = struct.unpack(">H", frame[idx:idx + 2])[0]
            idx += 2
            cfgcount = struct.unpack(">H", frame[idx:idx + 2])[0]
            idx += 2
            result["stations"].append({
                "stn": stn,
                "idcode": pmu_id,
                "format": fmt,
                "phnmr": phnmr,
                "annmr": annmr,
                "dignmr": dignmr,
                "fnom": fnom,
            })
            result["format_per_pmu"].append(fmt)
            result["channel_counts"].append({
                "phasors": phnmr, "analog": annmr, "digital": dignmr,
            })
            if result["fnom"] is None:
                result["fnom"] = fnom
        # After all PMUs: DATA_RATE (2 bytes BE) + CHK (2)
        if idx + 2 <= len(frame) - 2:
            data_rate = struct.unpack(">H", frame[idx:idx + 2])[0]
            result["data_rate"] = data_rate
    except (struct.error, IndexError):
        # Truncated frame — return what we have
        pass
    return result


def parse_data_frame(frame: bytes) -> Optional[Dict]:
    """Lightweight parse of a data frame — just confirm it's a data frame
    with a valid CRC. We do NOT extract phasor values (that requires the
    matching CFG-2 to know the channel layout)."""
    hdr = parse_common_header(frame)
    if hdr is None:
        return None
    if hdr["frame_type"] != FRAME_TYPE_DATA:
        return None
    return {
        "idcode": hdr["idcode"],
        "soc": hdr["soc"],
        "fracsec": hdr["fracsec"],
        "framesize": hdr["framesize"],
        "crc_ok": crc_ccitt_verify(frame),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  PROBE ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════
def probe_pmu(host: str, port: int) -> Dict:
    """Connect to a PMU / PDC at (host, port) and run the full probe:

      1. Send CFG-2 request (CMD 0x0004) → read config frame
      2. Send CFG-1 request (CMD 0x0005) → read config frame (basic)
      3. Send data-on request (CMD 0x0002) → read a data frame
      4. Check authentication (C37.118 has none)

    Returns the spec-required fields:
      pmu_found, data_rate, phasors_streamed, authenticated
    """
    result = {
        "pmu_found": 0,
        "data_rate": 0,
        "phasors_streamed": False,
        "authenticated": None,
        # diagnostic extras
        "cfg2_parsed": None,
        "cfg1_parsed": None,
        "data_frame": None,
        "stations": [],
        "numpmu": 0,
        "errors": [],
    }

    # Open TCP connection
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_S)
        sock.connect((host, port))
    except (socket.timeout, TimeoutError):
        result["errors"].append("conn:timeout")
        return result
    except (ConnectionRefusedError, OSError) as e:
        result["errors"].append(f"conn:{type(e).__name__}")
        return result

    target_idcode = _our_idcode()
    try:
        # ─── 1. CFG-2 request ──────────────────────────────────────────
        try:
            sock.sendall(build_command_frame(target_idcode, CMD_SEND_CFG2))
            frame = read_frame(sock, timeout=TIMEOUT_S)
        except (socket.timeout, TimeoutError):
            frame = None
        except OSError as e:
            result["errors"].append(f"cfg2_io:{type(e).__name__}")
            frame = None
        if frame is not None:
            cfg2 = parse_config_frame(frame)
            if cfg2:
                result["cfg2_parsed"] = {
                    "numpmu": cfg2["numpmu"],
                    "data_rate": cfg2["data_rate"],
                    "fnom": cfg2["fnom"],
                    "crc_ok": cfg2["crc_ok"],
                }
                result["pmu_found"] = cfg2["numpmu"]
                result["data_rate"] = cfg2["data_rate"] or 0
                result["stations"] = cfg2["stations"]
                result["numpmu"] = cfg2["numpmu"]
                # A PMU that answered CFG-2 without any auth ⇒ authenticated=False
                result["authenticated"] = False
            else:
                result["errors"].append("cfg2:parse_failed")
        else:
            result["errors"].append("cfg2:no_response")

        # ─── 2. CFG-1 request ──────────────────────────────────────────
        try:
            sock.sendall(build_command_frame(target_idcode, CMD_SEND_CFG1))
            frame1 = read_frame(sock, timeout=TIMEOUT_S)
        except (socket.timeout, TimeoutError):
            frame1 = None
        except OSError:
            frame1 = None
        if frame1 is not None:
            cfg1 = parse_config_frame(frame1)
            if cfg1:
                result["cfg1_parsed"] = {
                    "numpmu": cfg1["numpmu"],
                    "data_rate": cfg1["data_rate"],
                    "crc_ok": cfg1["crc_ok"],
                }
                # If CFG-2 failed but CFG-1 succeeded, fill in basic fields
                if result["pmu_found"] == 0:
                    result["pmu_found"] = cfg1["numpmu"]
                    result["data_rate"] = cfg1["data_rate"] or 0
                    result["authenticated"] = False
            # else: CFG-1 may use a different layout; ignore parse failure

        # ─── 3. Data-on request (CMD 0x0002) ────────────────────────────
        # READ-ONLY guard: CMD_TURN_OFF_DATA (0x0001) is NEVER sent.
        try:
            sock.sendall(build_command_frame(target_idcode, CMD_TURN_ON_DATA))
            # Read up to 2 frames looking for a data frame (some PMUs send
            # a CFG echo first)
            for _ in range(2):
                df = read_frame(sock, timeout=TIMEOUT_S)
                if df is None:
                    break
                ft = parse_frame_type(df)
                if ft == FRAME_TYPE_DATA:
                    parsed = parse_data_frame(df)
                    result["data_frame"] = parsed
                    result["phasors_streamed"] = True if parsed else False
                    break
                # otherwise keep reading
        except (socket.timeout, TimeoutError):
            result["errors"].append("data:timeout")
        except OSError as e:
            result["errors"].append(f"data_io:{type(e).__name__}")

    finally:
        try:
            # Best-effort: send turn-off-data to leave the PMU in a clean
            # state. This is a read-control command, NOT a state-modifying
            # control on the physical grid — but per our READ-ONLY policy
            # for the energy sector, we still skip it to avoid blinding a
            # real control center that may be consuming the stream.
            # We DO NOT send CMD_TURN_OFF_DATA.
            pass
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

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
            "legal_note": ("Synchrophasor / PMU probing on production grid "
                           "infrastructure is illegal outside an authorized "
                           "lab. NERC CIP / IEEE C37.118 / IEC 62351."),
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
        "pmu_found": 0,
        "data_rate": 0,
        "phasors_streamed": False,
        "authenticated": None,
        # Extra diagnostic fields:
        "numpmu": 0,
        "stations": [],
        "cfg2_parsed": None,
        "cfg1_parsed": None,
        "errors": [],
    }

    pr = probe_pmu(HOST, PORT)
    summary["pmu_found"] = int(pr.get("pmu_found", 0))
    summary["data_rate"] = int(pr.get("data_rate", 0))
    summary["phasors_streamed"] = bool(pr.get("phasors_streamed"))
    summary["authenticated"] = pr.get("authenticated")
    summary["numpmu"] = int(pr.get("numpmu", 0))
    # Strip noisy station fields from the summary (keep stn + idcode only)
    summary["stations"] = [
        {"stn": s.get("stn"), "idcode": s.get("idcode")}
        for s in (pr.get("stations") or [])
    ]
    summary["cfg2_parsed"] = pr.get("cfg2_parsed")
    summary["cfg1_parsed"] = pr.get("cfg1_parsed")
    summary["errors"] = pr.get("errors", [])

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
