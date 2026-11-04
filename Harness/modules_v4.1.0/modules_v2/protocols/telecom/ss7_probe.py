#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — ss7_probe (telecom protocol module)
# SS7 / SIGTRAN / Diameter signaling exposure probe.
#
# SS7 (Signaling System No. 7) is the legacy signaling stack used by mobile
# networks for SMS routing, roaming, and call setup. It is being phased out
# in favour of Diameter (4G/LTE) and HTTP/2 signaling (5G SBI), but the
# vast majority of deployed networks still expose SS7/SIGTRAN on:
#   - SCTP port 2905 (M3UA — SIGTRAN adaptation layer for SS7 MTP3)
#   - TCP/SCTP port 3868 (Diameter — used by 4G/LTE S6a, HSS, IMS)
#
# Tests (informational / read-only, no actual SS7 traffic emitted):
#   1. SCTP port 2905 reachability             → sctp_2905_open
#   2. Diameter port 3868 reachability          → diameter_3868_open
#   3. MAP (Mobile Application Part) vulnerability indicators
#   4. SMS interception risk (if SS7 accessible)
#   5. Location tracking risk (Provide Subscriber Info)
#   6. GT (Global Title) routing exposure
#
# IMPORTANT: SS7 vulnerabilities are protocol-level (MAP/SRI-for-SM abuse,
# ProvideSubscriberInfo, AnyTimeInterrogation). They cannot be fixed at the
# network edge — the only mitigation is SS7 firewalls (e.g. Eclipse, Cellusys,
# Anam) and migrating to Diameter with IPSec. This probe ONLY documents
# exposure; it does NOT send MAP operations or attempt SMS interception.
#
# Stack:
#   SCTP  (RFC 4960) — SIGTRAN transport
#   M3UA  (RFC 4666) — SS7 MTP3 User Adaptation Layer
#   SCCP  (ITU-T Q.713) — Connection-less / Connection-oriented
#   TCAP  (ITU-T Q.773) — Transaction Capabilities Application Part
#   MAP   (3GPP TS 29.002) — Mobile Application Part
#   Diameter (RFC 6733) — AAA protocol, base protocol + S6a/S6d (HSS)
#
# CLI:
#   python3 ss7_probe.py [host] [port]
#       host default = 127.0.0.1
#       port default = 2905 (SCTP SIGTRAN)
#
# Output: single JSON object on stdout.
#
# Legal: SS7 interception on production telecom equipment is illegal (France:
# Art. 323-1 Code pénal; US: 18 USC §1029; EU: Directive 2013/40/EU Art. 3).
# Lab isolated only.
import json
import os
import socket
import struct
import sys
import time
from typing import Dict, List, Optional

# ─── Make sector_base importable from ../../sector_base.py ────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULES_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _MODULES_ROOT not in sys.path:
    sys.path.insert(0, _MODULES_ROOT)

try:
    from sector_base import get_sector_config  # noqa: E402
    _SECTOR_BASE_OK = True
except Exception:  # noqa: BLE001
    _SECTOR_BASE_OK = False

    def get_sector_config() -> Dict:  # type: ignore[no-redef]
        return {"sector": "telecom", "safe_mode": "read_only"}

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "ss7_probe"
TIMEOUT_S = 5  # 5 s hard cap on every socket op

# ─── CLI args ─────────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 2905
except ValueError:
    PORT = 2905

# Standard SS7 / SIGTRAN / Diameter ports
SCTP_SIGTRAN_PORT = 2905     # M3UA / SIGTRAN (IANA-assigned)
DIAMETER_PORT = 3868         # Diameter base protocol (RFC 6733)
SIP_PORT = 5060              # cross-sector VoIP (informational only here)

# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))

# ─── Is SCTP available on this kernel? ────────────────────────────────────────
# Linux exposes SCTP via IPPROTO_SCTP=132 only if the sctp kernel module is
# loaded. On macOS/Windows SCTP is rarely available — we fall back to TCP
# connect() probes (which still detect whether the port is open, just not
# whether the daemon speaks SCTP).
try:
    IPPROTO_SCTP = socket.IPPROTO_SCTP  # type: ignore[attr-defined]
    _SCTP_AVAILABLE = True
except AttributeError:
    IPPROTO_SCTP = 132
    _SCTP_AVAILABLE = False

# ─── LAB guard ────────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ═══════════════════════════════════════════════════════════════════════════
#  Socket helpers (timeout on both SO_*TIMEO + settimeout)
# ═══════════════════════════════════════════════════════════════════════════
def _set_sock_timeout(sock: socket.socket, seconds: float = TIMEOUT_S) -> None:
    try:
        if hasattr(socket, "SO_RCVTIMEO"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO,
                            struct.pack("ll", int(seconds),
                                        int((seconds % 1) * 1_000_000)))
        if hasattr(socket, "SO_SNDTIMEO"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                            struct.pack("ll", int(seconds),
                                        int((seconds % 1) * 1_000_000)))
    except OSError:
        pass
    sock.settimeout(seconds)


# ═══════════════════════════════════════════════════════════════════════════
#  SCTP port probe (port 2905 — SIGTRAN / M3UA)
# ═══════════════════════════════════════════════════════════════════════════
def probe_sctp_port(host: str, port: int) -> Dict:
    """Probe whether the SCTP port is open. Tries SCTP sockets if the kernel
    supports them, else falls back to a TCP connect() probe (which still
    detects a listening socket, since SIGTRAN daemons like sigtran-stack
    typically bind both SCTP and TCP)."""
    result: Dict = {
        "open": False,
        "transport": None,        # "sctp" | "tcp_fallback" | None
        "banner": None,
        "error": None,
    }
    # 1. Try SCTP first
    if _SCTP_AVAILABLE:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
            _set_sock_timeout(sock)
            sock.connect((host, port))
            result["open"] = True
            result["transport"] = "sctp"
            # Try a 1-byte SHUTDOWN-CHUNK-equivalent read to detect a banner
            # (M3UA daemons typically don't send anything until we send M3UA
            # ASPAC — so we just close cleanly.)
            try:
                sock.settimeout(0.5)
                data = sock.recv(64)
                if data:
                    result["banner"] = data.hex()
            except (socket.timeout, TimeoutError, OSError):
                pass
            sock.close()
            return result
        except (socket.timeout, TimeoutError):
            result["error"] = "timeout"
        except (ConnectionRefusedError, OSError) as e:
            result["error"] = f"sctp_conn_error:{type(e).__name__}"
        except Exception as e:  # noqa: BLE001
            result["error"] = f"sctp_error:{type(e).__name__}"
    # 2. Fall back to TCP connect()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _set_sock_timeout(sock)
        sock.connect((host, port))
        result["open"] = True
        result["transport"] = "tcp_fallback"
        # A few SIGTRAN daemons emit a banner on connect; capture it.
        try:
            sock.settimeout(0.5)
            data = sock.recv(128)
            if data:
                result["banner"] = data.hex()[:128]
        except (socket.timeout, TimeoutError, OSError):
            pass
        sock.close()
    except (socket.timeout, TimeoutError):
        if not result["error"]:
            result["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"tcp_conn_error:{type(e).__name__}"
    except Exception as e:  # noqa: BLE001
        result["error"] = f"tcp_error:{type(e).__name__}"
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  Diameter port probe (port 3868 — RFC 6733)
# ═══════════════════════════════════════════════════════════════════════════
# Diameter header (RFC 6733 §3):
#   Version(1) | Message-Length(3) | Command-Flags(1) | Command-Code(3)
#   Application-Id(3) | Hop-by-Hop-Id(4) | End-to-End-Id(4) | AVPs...
# Command-Code 257 = Capabilities-Exchange (CER)
DIAMETER_VERSION = 0x01
DIAMETER_CMD_CER = 257   # Capabilities-Exchange-Request
DIAMETER_APP_RELAY = 0xffffffff


def build_diameter_cer(hop_id: int, end_to_end_id: int) -> bytes:
    """Build a minimal Diameter Capabilities-Exchange-Request (CER).
    Includes one Origin-Host AVP and one Origin-Realm AVP — both strings.
    The CER is the standard greeting for any Diameter peer; a 4G/LTE HSS
    or DRA (Diameter Routing Agent) will respond with a CEA (Capabilities-
    Exchange-Answer)."""
    def _avp(code: int, value: bytes, vendor_specific: bool = False,
             mandatory: bool = True) -> bytes:
        flags = 0x40 if mandatory else 0x00
        if vendor_specific:
            flags |= 0x80
            hdr = struct.pack("!IBB3sI", code, flags, 0, b"\x00\x00\x00",
                              len(value) + 12)
        else:
            hdr = struct.pack("!IBB3s", code, flags, 0,
                              struct.pack("!I", len(value) + 8)[1:])
            hdr = code.to_bytes(4, "big") + bytes([flags, 0]) + \
                  struct.pack("!I", len(value) + 8)[1:].rjust(3, b"\x00")
        # padding to 4-byte boundary
        pad = (4 - (len(value) % 4)) % 4
        return hdr + value + b"\x00" * pad

    # Simpler, correct CER build (no vendor-specific AVPs — Origin-Host and
    # Origin-Realm are mandatory per RFC 6733 §6.5 / §6.6)
    def avp_utf8(code: int, value: str) -> bytes:
        val = value.encode("utf-8")
        # AVP header: code(4) | flags(1) | length(3) — total length incl hdr
        avp_len = 8 + len(val)
        pad = (4 - (avp_len % 4)) % 4
        flags = 0x40  # mandatory
        return (code.to_bytes(4, "big")
                + bytes([flags])
                + avp_len.to_bytes(3, "big")
                + val
                + b"\x00" * pad)

    origin_host = avp_utf8(264, "harness.probe.lab")
    origin_realm = avp_utf8(296, "probe.lab")
    host_ip = avp_utf8(257, "127.0.0.1")  # Host-IP-Address (string form)
    vendor_id = struct.pack("!I", 0)  # Vendor-Id = 0 (IETF)
    product_name = avp_utf8(269, "harness-ss7-probe")

    payload = origin_host + origin_realm + host_ip + vendor_id + product_name
    cmd_flags = 0x80  # request bit (R=1, P=0, E=0)
    msg_len = 20 + len(payload)
    header = (bytes([DIAMETER_VERSION])
              + msg_len.to_bytes(3, "big")
              + bytes([cmd_flags])
              + DIAMETER_CMD_CER.to_bytes(3, "big")
              + DIAMETER_APP_RELAY.to_bytes(4, "big")[-3:].rjust(3, b"\x00")
              + struct.pack("!I", hop_id)
              + struct.pack("!I", end_to_end_id))
    # Application-Id must be 3 bytes wide per RFC 6733; rebuild header cleanly:
    header = (bytes([DIAMETER_VERSION])
              + msg_len.to_bytes(3, "big")
              + bytes([cmd_flags])
              + DIAMETER_CMD_CER.to_bytes(3, "big")
              + b"\x00\x00\x00"  # Application-Id = 0 (relay)
              + struct.pack("!I", hop_id)
              + struct.pack("!I", end_to_end_id))
    return header + payload


def parse_diameter_header(data: bytes) -> Optional[Dict]:
    """Parse a Diameter message header. Returns None if data is too short
    or the version byte is not 0x01."""
    if len(data) < 20:
        return None
    version = data[0]
    if version != DIAMETER_VERSION:
        return None
    msg_len = int.from_bytes(data[1:4], "big")
    cmd_flags = data[4]
    cmd_code = int.from_bytes(data[5:8], "big")
    app_id = int.from_bytes(data[8:12], "big")
    hop_id = int.from_bytes(data[12:16], "big")
    end_to_end_id = int.from_bytes(data[16:20], "big")
    return {
        "version": version,
        "message_length": msg_len,
        "command_flags": cmd_flags,
        "command_code": cmd_code,
        "application_id": app_id,
        "hop_by_hop_id": hop_id,
        "end_to_end_id": end_to_end_id,
        "is_answer": not (cmd_flags & 0x80),
    }


def probe_diameter_port(host: str, port: int) -> Dict:
    """Probe port 3868 for Diameter. If open, send a minimal CER and look for
    a CEA reply (command-code 257, R-bit clear)."""
    result: Dict = {
        "open": False,
        "cer_sent": False,
        "cea_received": False,
        "peer_info": None,
        "error": None,
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _set_sock_timeout(sock)
        sock.connect((host, port))
        result["open"] = True
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
        return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
        return result
    except Exception as e:  # noqa: BLE001
        result["error"] = f"socket_error:{type(e).__name__}"
        return result

    # SAFE_MODE=read_only — we DO send a CER (it's the protocol greeting,
    # equivalent to a TCP SYN+ACK), but we never send an AAR/ULR/LUR/CLR
    # (which would actually query subscriber data).
    try:
        cer = build_diameter_cer(hop_id=SEED & 0xffffffff,
                                 end_to_end_id=(SEED + 1) & 0xffffffff)
        sock.sendall(cer)
        result["cer_sent"] = True
        try:
            data = sock.recv(2048)
        except (socket.timeout, TimeoutError):
            data = b""
        if data:
            parsed = parse_diameter_header(data)
            if parsed:
                result["cea_received"] = (parsed.get("command_code") == 257
                                          and parsed.get("is_answer"))
                result["peer_info"] = parsed
            else:
                result["peer_info"] = {"raw_hex": data[:64].hex()}
    except OSError as e:
        result["error"] = f"io_error:{type(e).__name__}"
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  MAP / SCCP / GT risk documentation (no traffic emitted)
# ═══════════════════════════════════════════════════════════════════════════
# MAP (Mobile Application Part, 3GPP TS 29.002) operations that are classically
# abused over an exposed SS7 link:
#   - sendRoutingInfoForSM (SRI-for-SM)     → SMS interception
#   - provideSubscriberInfo (PSI)            → location tracking
#   - anyTimeInterrogation (ATI)             → location tracking
#   - insertSubscriberData (ISD)             → subscriber fraud
#   - deleteSubscriberData (DSD)             → denial of service
#   - updateLocation (UL)                    → location fraud
#
# GT (Global Title, ITU-T Q.713 §3) is the routing address used by SCCP to
# route MAP queries. Exposed GTs that respond to global-title translation
# (GTT) can be abused to inject forged MAP messages.
MAP_RISK_INDICATORS: List[Dict] = [
    {
        "operation": "sendRoutingInfoForSM",
        "opcode": 0x2d,  # MAP v1 = 45, v2 = 0x2d
        "risk": "sms_interception",
        "detail": ("If an attacker can send SRI-for-SM to the HLR with a "
                   "target MSISDN, the HLR returns the VMSC address where "
                   "SMS should be routed. The attacker then sends the SMS "
                   "directly to that VMSC, bypassing the legitimate SMSC — "
                   "this is how 2FA interception works in production."),
        "mitigation": "SS7 firewall (allowlist of SCCP GTs / MAP opcodes)",
    },
    {
        "operation": "provideSubscriberInfo",
        "opcode": 0x47,
        "risk": "location_tracking",
        "detail": ("PSI returns the subscriber's Cell-ID / LAC / SAC — "
                   "real-time location with no authentication. Used by "
                   "lawful intercept but also by commercial SS7-location "
                   "services sold without subscriber consent."),
        "mitigation": "SS7 firewall (block inbound PSI from foreign GTs)",
    },
    {
        "operation": "anyTimeInterrogation",
        "opcode": 0x3c,
        "risk": "location_tracking",
        "detail": ("ATI allows interrogation of subscriber location / "
                   "subscriber state from any node — a classic SS7 abuse."),
        "mitigation": "SS7 firewall (block ATI from non-VLR nodes)",
    },
    {
        "operation": "insertSubscriberData",
        "opcode": 0x07,
        "risk": "call_fraud",
        "detail": ("ISD allows modification of subscriber data (call "
                   "barring, CSG subscription). An attacker with HLR access "
                   "can grant themselves premium services."),
        "mitigation": "SS7 firewall (block inbound ISD entirely)",
    },
]

GT_ROUTING_RISK = {
    "risk": "gt_routing_exposure",
    "detail": ("If the HLR or STP exposes GT (Global Title) translation to "
               "arbitrary SCCP Called-Party addresses, an attacker can craft "
               "MAP messages with arbitrary Called-GT and route them through "
               "the operator's network to any destination (often used for "
               "wholesale SMS fraud — 'grey routes')."),
    "mitigation": "E.164 GT allowlist + SCCP Calling-GT screening",
}


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("SS7/SIGTRAN probing on production telecom "
                           "equipment is illegal (FR Art. 323-1, US 18 USC "
                           "§1029, EU Directive 2013/40/EU). Lab only."),
        }))
        sys.exit(1)

    t0 = time.time()
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "sctp_port_probed": PORT,
        "diameter_port_probed": DIAMETER_PORT,
        "sector": get_sector_config().get("sector", "telecom"),
        "safe_mode": "read_only",
        "read_only": True,
        "seed": SEED,
        "sctp_kernel_available": _SCTP_AVAILABLE,
        # Spec-required output fields:
        "sctp_2905_open": False,
        "diameter_3868_open": False,
        "ss7_risks": ["sms_interception", "location_tracking", "call_fraud"],
        "note": ("SS7 vulnerabilities are protocol-level, not fixable at "
                 "network edge"),
        # Extra diagnostics:
        "map_risk_indicators": [],
        "gt_routing_exposure": True,  # documented risk (always reported)
        "errors": [],
    }

    # ─── 1. SCTP / SIGTRAN probe (port 2905) ───────────────────────────────
    try:
        sctp_r = probe_sctp_port(HOST, PORT)
        summary["sctp_2905_open"] = bool(sctp_r.get("open"))
        summary["sctp_transport"] = sctp_r.get("transport")
        summary["sctp_banner_hex"] = sctp_r.get("banner")
        if sctp_r.get("error"):
            summary["errors"].append(f"sctp_probe:{sctp_r['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"sctp_probe:{type(e).__name__}:{e}")

    # ─── 2. Diameter probe (port 3868) ────────────────────────────────────
    try:
        diam_r = probe_diameter_port(HOST, DIAMETER_PORT)
        summary["diameter_3868_open"] = bool(diam_r.get("open"))
        summary["diameter_cer_sent"] = bool(diam_r.get("cer_sent"))
        summary["diameter_cea_received"] = bool(diam_r.get("cea_received"))
        summary["diameter_peer_info"] = diam_r.get("peer_info")
        if diam_r.get("error"):
            summary["errors"].append(f"diameter_probe:{diam_r['error']}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"diameter_probe:{type(e).__name__}:{e}")

    # ─── 3. MAP vulnerability indicators (documented, no traffic) ─────────
    # If SS7 or Diameter is reachable, we surface the MAP operations an
    # attacker could invoke. This is informational — we do NOT send them.
    ss7_accessible = (summary["sctp_2905_open"] or summary["diameter_3868_open"])
    summary["ss7_accessible"] = ss7_accessible
    summary["map_risk_indicators"] = MAP_RISK_INDICATORS if ss7_accessible else []
    summary["gt_routing_risk"] = GT_ROUTING_RISK if ss7_accessible else None

    # ─── 4. Risk synthesis (informational) ────────────────────────────────
    # SMS interception: possible if SRI-for-SM is reachable on the HLR.
    # Location tracking: possible if PSI / ATI is reachable.
    # Call fraud: possible if ISD / DSD is reachable.
    # In a read-only probe we cannot determine opcode-level reachability,
    # so we report all three risks as "documented" if SS7 is accessible.
    summary["risk_assessment"] = {
        "sms_interception": {
            "documented": True,
            "applicable": ss7_accessible,
            "map_operation": "sendRoutingInfoForSM (opcode 0x2d)",
        },
        "location_tracking": {
            "documented": True,
            "applicable": ss7_accessible,
            "map_operations": ["provideSubscriberInfo (0x47)",
                               "anyTimeInterrogation (0x3c)"],
        },
        "call_fraud": {
            "documented": True,
            "applicable": ss7_accessible,
            "map_operation": "insertSubscriberData (0x07)",
        },
        "gt_routing_exposure": {
            "documented": True,
            "applicable": ss7_accessible,
            "detail": GT_ROUTING_RISK["detail"],
        },
    }
    summary["mitigation"] = (
        "Deploy SS7 firewall (Eclipse, Cellusys, Anam, TNS) with MAP opcode "
        "allowlist + SCCP GT screening. Migrate to Diameter with IPSec for "
        "4G/LTE S6a, and to HTTP/2 SBI for 5G. SS7 cannot be patched — only "
        "firewalled."
    )

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
