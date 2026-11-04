#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — ieee11073_probe
# Health sector validation module — IEEE 11073 Personal Health Device (PHD)
# probing. IEEE 11073-20601 (Optimized Exchange Protocol) over TCP.
#
#   - Default port : 21524 (IEEE 11073-20601 agent)
#   - Transports   : BLE / USB / TCP. This module probes the TCP transport
#     (the only one reachable over the network). BLE/USB detection is
#     noted as transport: "tcp" and the module reports BLE/USB as not
#     applicable for a network probe.
#   - Functions:
#       build_assoc_rq    — IEEE 11073-20601 A-ASSOCIATE-RQ APDU
#       send_assoc        — establish association, parse A-ASSOCIATE-AC
#       mds_get           — GetRequestSimple on MDS object (handle 0),
#                           attribute 0 (all attributes)
#       detect_device_type — scan response bytes for nomenclature codes:
#                            1602=BP, 1603=Glucose, 1604=SpO2,
#                            1605=Weight, 1606=Temp, 1607=ECG
#       scan_ports        — scan common IEEE 11073 ports for an agent
#   - APDU encoding (per IEEE 11073-20601 §9.2):
#       CHOICE type (1 byte) + LENGTH + VALUE
#       A-ASSOCIATE-RQ/A-ASSOCIATE-AC: 4-byte big-endian length
#       All other APDUs: 2-byte big-endian length
#   - READ_ONLY=True (health sector safety constraint) — only Get (read)
#     operations are emitted. No Set, no Action (e.g. no PM-store Create),
#     no event-report subscription. The probe never writes data to the
#     device.
#   - HIPAA note: personal health device data (BP, glucose, SpO2) is PHI.
#     Numeric nomenclature codes are reported, but observed values are
#     NOT echoed (read-only enumeration only).
#   - SEED env var: deterministic EUI-64 system-id + invoke-ids.
#   - LAB=1 mandatory. 5 s timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (health) : HIPAA, HDS, RGPD, FDA 21 CFR Part 11,
# IEEE 11073-20601 / 104xx device specializations, IEC 62304.
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
except Exception as exc:  # noqa: BLE001 — standalone fallback
    SECTOR_BASE_OK = False
    _SECTOR_BASE_ERR = str(exc)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "ieee11073_probe"
DEFAULT_PORT = 21524
TIMEOUT_S = 5.0
READ_ONLY = True  # health sector safety constraint (Get only — no Set/Action)

# Common IEEE 11073-20601 TCP ports (21524 is the well-known assignment;
# 2400, 2500, 5050 appear in some vendor PHD gateways).
COMMON_PORTS = [21524, 2400, 2500, 5050]

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── SEED for deterministic EUI-64 / invoke-ids ────────────────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else None
except ValueError:
    SEED = None
_rng = random.Random(SEED) if SEED is not None else random.Random()


def _next_invoke_id() -> int:
    """Deterministic ROSE invoke-id (2-byte)."""
    return _rng.randint(1, 0xFFFF)


def _eui64() -> bytes:
    """Generate a deterministic 8-byte EUI-64 system-id (locally
    administered, unicast — bits L=1, U=1 per RFC 7042)."""
    b = bytearray(_rng.randbytes(8))
    b[0] |= 0b0000_0010  # U/L bit = locally administered
    b[0] &= 0b1111_1110  # I/G bit = unicast
    return bytes(b)


# ─── LAB guard ─────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ─── Sector / SAFE_MODE config ─────────────────────────────────────────────
if SECTOR_BASE_OK:
    SECTOR_CFG = get_sector_config()
    SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")
else:
    SECTOR_CFG = {"sector": "health", "safe_mode": "read_only"}
    SAFE_MODE = "read_only"


# ═══════════════════════════════════════════════════════════════════════════
#  IEEE 11073-20601 APDU constants (§9.2)
# ═══════════════════════════════════════════════════════════════════════════
# APDU CHOICE types
APDU_ASSOC_RQ = 0xE1
APDU_ASSOC_AC = 0xE2
APDU_ASSOC_RJ = 0xE3
APDU_RELEASE_RQ = 0xE4
APDU_RELEASE_RP = 0xE5
APDU_ABORT = 0xE6
APDU_PCANCEL_RQ = 0xE7
APDU_DATA = 0xE0  # presentation-data APDU (carries ROSE messages)

# Abort reasons
ABRT_REASON_CONGESTION = 0x01
ABRT_REASON_PERSISTENT = 0x02
ABRT_REASON_TRANSIENT = 0x03
ABRT_REASON_REMOTE = 0x80
ABRT_REASON_LOCAL = 0x81

# ROSE invoke-type opcodes (inside APDU_DATA value)
ROIV_CMIP_CONFIRMED_EVENT_REPORT = 0x01
ROIV_CMIP_CONFIRMED_ACTION = 0x05
ROIV_CMIP_GET = 0x06
ROIV_CMIP_SET = 0x07
ROIV_CMIP_CONFIRMED_SET = 0x0D
ROIV_CMIP_CONFIRMED_EVENT_REPORT_CONF = 0x0E
RORS_CMIP_CONFIRMED_EVENT_REPORT = 0x21
RORS_CMIP_GET = 0x26
RORS_CMIP_CONFIRMED_ACTION = 0x25
ROER = 0x30  # Error response
RORJ = 0x40  # Reject

# Operation types (11073-10201) — GET = MOC_GET, value 0xC000
OP_GET = 0xC000
# Action: MDS Create Event Report = 0x0D1C (11073-10201); not used (read-only)

# Device specialization nomenclature codes (11073-10101 / 104xx specializations)
# MDC_DEV_SPEC_PROFILE_* values per IEEE 11073-10101
DEVICE_NOMENCLATURE = {
    1602: "blood_pressure",     # MDC_DEV_SPEC_PROFILE_BP / 11073-10407
    1603: "glucose",            # MDC_DEV_SPEC_PROFILE_GLUCOSE / 11073-10417
    1604: "pulse_oximetry",     # MDC_DEV_SPEC_PROFILE_PULSE_OX / 11073-10406
    1605: "weight_scale",       # MDC_DEV_SPEC_PROFILE_SCALE / 11073-10415
    1606: "thermometer",        # MDC_DEV_SPEC_PROFILE_TEMP / 11073-10408
    1607: "ecg",                # MDC_DEV_SPEC_PROFILE_ECG / 11073-10406
}
# Byte patterns to search for in agent responses (big-endian + LE):
# Code 1602 = 0x0642. In MDER 16-bit, it is big-endian 06 42.
# Some agents send it little-endian (42 06). Search both.
_NOMENCLATURE_BE = {c: struct.pack(">H", c) for c in DEVICE_NOMENCLATURE}
_NOMENCLATURE_LE = {c: struct.pack("<H", c) for c in DEVICE_NOMENCLATURE}


# ═══════════════════════════════════════════════════════════════════════════
#  APDU builders
# ═══════════════════════════════════════════════════════════════════════════
def build_assoc_rq(system_id: bytes) -> bytes:
    """Build an A-ASSOCIATE-RQ APDU (IEEE 11073-20601 §8.3 / §9.2.2).

    Layout of the VALUE field (47 bytes total):
      offset  size  field
      0       4     protocol-version        (BIT STRING, 0x80000000 = version1)
      4       2     encoding-rules          (BIT STRING, 0x8000 = MDER)
      6       1     byte-order              (0x00 = Little Endian)
      7       1     poo-structure           (0x00 = no presence bits set)
      8       1     aa-procedure-var        (0x50 = frag + seg supported)
      9       2     irooma                  (0x8000 = unacknowledged)
      11      4     protocol-version        (0x80000000)
      15      4     nomenclature-version    (0x80000000 = version1)
      19      4     functional-profiles     (0x80000000 = version1)
      23      8     system-id               (EUI-64, caller-provided)
      31      1     test-mode-flag          (0x00 = normal)
      32      1     test-equipment-type     (0x00)
      33      1     responsiveness-capability (0x08 = responsive)
      34      1     responsiveness-mode     (0x00)
      35      2     max-msg-rt-size         (0x0300 = 768 bytes)
      37      2     max-msg-rt-wait         (0x0100 = 256)
      39      2     apdu-buffer-len         (0x0300 = 768)
      41      4     protocol-version        (0x80000000)
      45      2     vendor-attribute-list   (count = 0)
    """
    if len(system_id) != 8:
        raise ValueError("system_id must be 8 bytes (EUI-64)")
    value = (
        b"\x80\x00\x00\x00"      # protocol-version (version 1)
        b"\x80\x00"              # encoding-rules (MDER)
        b"\x00"                  # byte-order (LE)
        b"\x00"                  # poo-structure
        b"\x50"                  # aa-procedure-var (frag + seg)
        b"\x80\x00"              # irooma
        b"\x80\x00\x00\x00"      # protocol-version
        b"\x80\x00\x00\x00"      # nomenclature-version (version 1)
        b"\x80\x00\x00\x00"      # functional-profiles (version 1)
        + system_id +            # system-id (8 bytes)
        b"\x00"                  # test-mode-flag
        b"\x00"                  # test-equipment-type
        b"\x08"                  # responsiveness-capability
        b"\x00"                  # responsiveness-mode
        b"\x03\x00"              # max-msg-rt-size (768)
        b"\x01\x00"              # max-msg-rt-wait (256)
        b"\x03\x00"              # apdu-buffer-len (768)
        b"\x80\x00\x00\x00"      # protocol-version
        b"\x00\x00"              # vendor-attribute-list (count = 0)
    )
    # A-ASSOCIATE-RQ uses a 4-byte big-endian length
    header = struct.pack(">BI", APDU_ASSOC_RQ, len(value))
    return header + value


def build_abort() -> bytes:
    """Build an A-ABRT APDU (used to tear down cleanly)."""
    # value = reason-byte + invoke-id-type + invoke-id (minimal: 0x00 0x00)
    value = b"\x81\x00\x00\x00"  # local reason + zero invoke-id
    header = struct.pack(">BH", APDU_ABORT, len(value))
    return header + value


def build_mds_get(invoke_id: int) -> bytes:
    """Build a GetRequestSimple for the MDS object (handle 0), all
    attributes (attribute-id 0xFFFF). READ-ONLY: this is a Get only.

    Inner ROIV-APDU structure (11073-20601 §10.4):
      CHOICE 1 byte: ROIV_CMIP_GET (0x06)
      length 2 bytes (big-endian)
      invoke-id 2 bytes
      operation-type 2 bytes (OP_GET = 0xC000)
      obj-handle 2 bytes (0 = MDS)
      attribute-id-list: count 2 bytes (0 = empty → all attributes)
    """
    roiv_value = struct.pack(">HHHH",
                             invoke_id,
                             OP_GET,
                             0x0000,        # obj-handle: 0 = MDS
                             0x0000)        # attribute-id-list count: 0 = all
    roiv = struct.pack(">BH", ROIV_CMIP_GET, len(roiv_value)) + roiv_value
    # Wrap in APDU_DATA (presentation-data APDU) with 2-byte length
    pd_value = b"\x01" + struct.pack(">H", len(roiv)) + roiv  # octet-string with length
    header = struct.pack(">BH", APDU_DATA, len(pd_value))
    return header + pd_value


# ═══════════════════════════════════════════════════════════════════════════
#  APDU parsing
# ═══════════════════════════════════════════════════════════════════════════
def parse_apdu_header(data: bytes) -> Optional[Tuple[int, int, int]]:
    """Parse the first APDU header in `data`. Returns (choice_type,
    length, header_size) or None if too short / malformed."""
    if len(data) < 2:
        return None
    choice = data[0]
    if choice in (APDU_ASSOC_RQ, APDU_ASSOC_AC, APDU_ASSOC_RJ):
        # 4-byte length
        if len(data) < 5:
            return None
        length = struct.unpack(">I", data[1:5])[0]
        return choice, length, 5
    # all others: 2-byte length
    length = struct.unpack(">H", data[1:3])[0]
    return choice, length, 3


# ═══════════════════════════════════════════════════════════════════════════
#  Device-type detection from response bytes
# ═══════════════════════════════════════════════════════════════════════════
def detect_device_types(data: bytes) -> Tuple[List[int], List[str]]:
    """Scan a byte buffer for IEEE 11073-10101 nomenclature codes
    corresponding to PHD device specializations (1602–1607).

    Returns (codes_found, type_names_found).
    """
    codes: List[int] = []
    names: List[str] = []
    for code, name in DEVICE_NOMENCLATURE.items():
        if _NOMENCLATURE_BE[code] in data or _NOMENCLATURE_LE[code] in data:
            codes.append(code)
            names.append(name)
    return codes, names


# ═══════════════════════════════════════════════════════════════════════════
#  Port scanning (find IEEE 11073 agents on common ports)
# ═══════════════════════════════════════════════════════════════════════════
def scan_ports(host: str, ports: List[int]) -> List[int]:
    """Quick TCP connect scan of candidate ports. Returns ports that
    accept a TCP connection within TIMEOUT_S."""
    open_ports: List[int] = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT_S)
            s.connect((host, p))
            s.close()
            open_ports.append(p)
        except (socket.timeout, TimeoutError):
            continue
        except (ConnectionRefusedError, OSError):
            continue
    return open_ports


# ═══════════════════════════════════════════════════════════════════════════
#  Association + MDS Get probe
# ═══════════════════════════════════════════════════════════════════════════
def probe_agent(host: str, port: int) -> Dict:
    """Connect to an IEEE 11073-20601 agent on `host`:`port` and run the
    full probe: A-ASSOCIATE-RQ → wait for A-ASSOCIATE-AC → send MDS Get
    → parse device-type nomenclature from the response → A-ABRT.

    Returns a per-agent result dict.
    """
    result = {
        "host": host,
        "port": port,
        "tcp_open": False,
        "association_ok": False,
        "auth_required": False,
        "data_readable": False,
        "device_types": [],
        "nomenclature_codes": [],
        "bytes_received": 0,
        "abort_reason": None,
        "error": None,
    }
    # Open TCP
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_S)
        sock.connect((host, port))
        result["tcp_open"] = True
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        return result

    try:
        # ─── 1. Send A-ASSOCIATE-RQ ────────────────────────────────────
        sysid = _eui64()
        rq = build_assoc_rq(sysid)
        sock.sendall(rq)
        try:
            resp = sock.recv(4096)
        except (socket.timeout, TimeoutError):
            resp = b""
        if not resp:
            result["error"] = "no_assoc_response"
            return result
        result["bytes_received"] = len(resp)
        hdr = parse_apdu_header(resp)
        if hdr is None:
            result["error"] = "malformed_apdu_header"
            return result
        choice, length, hdr_size = hdr
        if choice == APDU_ASSOC_AC:
            result["association_ok"] = True
            # IEEE 11073-20601 has no native authentication — if the agent
            # accepts the association without any prior pairing or auth,
            # auth_required=False. If the agent rejected with A-ASSOC-RJ
            # (e.g. system-id unknown), auth_required=True.
        elif choice == APDU_ASSOC_RJ:
            # A-ASSOCIATE-RJ: agent rejected. Parse the diagnostic byte.
            result["association_ok"] = False
            result["auth_required"] = True  # likely pairing/auth required
            if len(resp) >= hdr_size + 1:
                # RJ has result (1B), source (1B), reason (1B) after length
                result["abort_reason"] = f"rej_reason:{resp[hdr_size + 2]:#04x}" \
                    if len(resp) >= hdr_size + 3 else "rejected"
            result["error"] = "association_rejected"
            return result
        elif choice == APDU_ABORT:
            result["association_ok"] = False
            result["error"] = "aborted_on_assoc"
            if len(resp) >= hdr_size:
                reason_byte = resp[hdr_size] if len(resp) > hdr_size else 0
                result["abort_reason"] = f"abrt:{reason_byte:#04x}"
            return result
        else:
            result["error"] = f"unexpected_apdu:0x{choice:02x}"
            return result

        # ─── 2. Send MDS Get (all attributes) ──────────────────────────
        invoke_id = _next_invoke_id()
        get_rq = build_mds_get(invoke_id)
        sock.sendall(get_rq)
        # Read the response (RORS_CMIP_GET or ROER/RORJ). May need multiple
        # recv() calls for fragmented responses.
        chunks: List[bytes] = []
        sock.settimeout(TIMEOUT_S)
        try:
            while len(b"".join(chunks)) < 4096:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if len(chunks) >= 3:
                    break
        except (socket.timeout, TimeoutError):
            pass
        mds_resp = b"".join(chunks)
        result["bytes_received"] += len(mds_resp)

        if mds_resp:
            # The response payload is inside an APDU_DATA wrapper. We scan
            # the entire buffer for nomenclature codes regardless of
            # framing (handles MDER, AARQ-exchange, attribute lists).
            codes, names = detect_device_types(mds_resp)
            result["nomenclature_codes"] = codes
            result["device_types"] = names
            # Check for RORS_CMIP_GET (0x26) → successful Get response
            if bytes([RORS_CMIP_GET]) in mds_resp:
                result["data_readable"] = True
            elif bytes([ROER]) in mds_resp or bytes([RORJ]) in mds_resp:
                result["data_readable"] = False
                result["error"] = "get_error_or_reject"
            elif len(mds_resp) > hdr_size:
                # Got bytes back we couldn't classify — assume partial read
                result["data_readable"] = True
            # If device codes were found, the MDS attributes are readable
            if codes:
                result["data_readable"] = True

        # ─── 3. Send A-ABRT to tear down cleanly ───────────────────────
        try:
            sock.sendall(build_abort())
        except Exception:  # noqa: BLE001 — best-effort
            pass

    except (socket.timeout, TimeoutError):
        result["error"] = result.get("error") or "timeout"
    except OSError as e:
        result["error"] = f"io_error:{type(e).__name__}"
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
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
            "legal_note": ("IEEE 11073 PHD probing on production medical "
                           "devices is illegal outside an authorized lab. "
                           "HIPAA / HDS / FDA 21 CFR Part 11."),
        }))
        sys.exit(1)

    t0 = time.time()
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "port": PORT,
        "transport": "tcp",   # BLE/USB not reachable over network probe
        "sector": SECTOR_CFG.get("sector"),
        "safe_mode": SAFE_MODE,
        "read_only": READ_ONLY,
        "seed": SEED,
        # Spec-required output fields:
        "devices_found": 0,
        "device_types": [],
        "association_ok": False,
        "auth_required": False,
        "data_readable": False,
        "nomenclature_codes": [],
        # Extra diagnostics:
        "ports_scanned": [],
        "ports_open": [],
        "per_port_results": [],
        "errors": [],
    }

    # ─── Port scan (CLI port first, then common alternatives) ───────────
    ports_to_scan = [PORT] + [p for p in COMMON_PORTS if p != PORT]
    summary["ports_scanned"] = ports_to_scan
    try:
        open_ports = scan_ports(HOST, ports_to_scan)
        summary["ports_open"] = open_ports
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"scan:{type(e).__name__}:{e}")
        open_ports = [PORT]  # fall back to CLI port directly

    # ─── Probe each open port ───────────────────────────────────────────
    all_codes: List[int] = []
    all_types: List[str] = []
    devices_found = 0
    for p in open_ports:
        try:
            r = probe_agent(HOST, p)
            summary["per_port_results"].append(r)
            if r.get("association_ok"):
                devices_found += 1
                summary["association_ok"] = True
            if r.get("auth_required"):
                summary["auth_required"] = True
            if r.get("data_readable"):
                summary["data_readable"] = True
            for code in r.get("nomenclature_codes", []):
                if code not in all_codes:
                    all_codes.append(code)
            for name in r.get("device_types", []):
                if name not in all_types:
                    all_types.append(name)
            if r.get("error"):
                summary["errors"].append(f"port{p}:{r['error']}")
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"port{p}:{type(e).__name__}:{e}")

    summary["devices_found"] = devices_found
    summary["device_types"] = all_types
    summary["nomenclature_codes"] = all_codes

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
