#!/usr/bin/env python3
# HARNESS-VALIDATION v3.3.0 — PROFINET probe (factory automation / Siemens).
# Ports : 34962 (RT-M), 34964 (DCP), 34963 (PTCP).
#
# PROFINET est le standard Ethernet temps réel pour l'automatisation
# industrielle (Siemens, PROFIBUS International). Il remplace PROFIBUS DP.
#
# DCP (Discovery and Configuration Protocol) :
#   - Couche 2 (EtherType 0x8892), multicast 01:0E:CF:00:00:00
#   - NON AUTHENTIFIÉ — toute machine sur le même L2 peut :
#     → Identifier tous devices PROFINET (name, vendor, options)
#     → SET device name (write) → conflit de nommage → arrêt production
#     → Factory reset → arrêt complet de l'équipement
#   - READ ONLY ici : lecture uniquement, pas de write/set
#
# RT (Real-Time) :
#   - Communication cyclique entre PLC et devices
#   - Frames EtherType 0x8892, priorité VLAN 0x8000
#
# Usage : python3 profinet_probe.py <interface> [duration]
# Défaut : eth0, 5 secondes
# READ_ONLY : écoute DCP multicast, n'envoie pas de Set/Reset.
import json
import os
import socket
import struct
import sys
import time
from datetime import datetime, timezone

SEED = int(os.environ.get("SEED", "1337"))
LAB = os.environ.get("LAB", "0")
IFACE = sys.argv[1] if len(sys.argv) > 1 else "eth0"
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 5

# PROFINET constants
ETHERTYPE_PROFINET = 0x8892
DCP_MULTICAST = b"\x01\x0e\xcf\x00\x00\x00"
DCP_IDENTIFY = 0x05  # Service: Identify
DCP_GET = 0x03       # Service: Get
DCP_SET = 0x04       # Service: Set (INTERDIT en read_only)
DCP_RESPONSE = 0x02

# DCP Option/Suboption for device properties
OPT_DEVICE = 0x05
SUB_DEVICE_NAME = 0x02
SUB_DEVICE_VENDOR = 0x01
SUB_DEVICE_OPTIONS = 0x04
SUB_DEVICE_ROLE = 0x05
SUB_DEVICE_ID = 0x03

# Service IDs
SERVICE_NAMES = {
    0x00: "reserved",
    0x01: "Get",
    0x02: "Set",
    0x03: "Identify",
    0x04: "Hello",
}

def lab_guard():
    if LAB != "1":
        print(json.dumps({"module": "profinet_probe", "error": "lab_guard_failed"}))
        sys.exit(1)

def build_dcp_identify_req() -> bytes:
    """Construit un DCP Identify request (multicast).
    Demande à tous les devices PROFINET de s'identifier."""
    # Ethernet header: dst=multicast, src=broadcast placeholder
    dst = DCP_MULTICAST
    src = b"\x00\x00\x00\x00\x00\x00"  # filled by socket
    ethertype = struct.pack("!H", ETHERTYPE_PROFINET)
    # DCP frame header
    # ServiceID=Identify(0x05), ServiceType=Request(0x00), Xid=0x00000001,
    # ResponseDelay=100ms, DCPDataLength=0x0004
    dcp_header = struct.pack("!BBHIH",
                             DCP_IDENTIFY,  # Service ID
                             0x00,           # Service Type (request)
                             0x00000001,     # Transaction ID
                             100,            # Response delay factor (100ms)
                             4)              # DCP data length
    # DCP Data: Option=ALL(0xFF), Suboption=ALL(0xFF), BlockInfo=0x0000,
    # BlockLength=0x0002, Query=ALL(0xFF)
    dcp_data = struct.pack("!BBHHB",
                           0xFF,    # Option (all)
                           0xFF,    # Suboption (all)
                           0x0000,  # Block info
                           0x0002,  # Block length
                           0xFF)    # Query (all)
    # FrameID = 0xFEFE (DCP Identify RPC request)
    frame_id = struct.pack("!H", 0xFEFE)
    return dst + src + ethertype + frame_id + dcp_header + dcp_data

def parse_dcp_response(data: bytes) -> dict:
    """Parse une DCP Identify response."""
    if len(data) < 14 + 6:
        return {"error": "too_short"}
    # Skip ethernet header (14 bytes)
    ethertype = struct.unpack("!H", data[12:14])[0]
    if ethertype != ETHERTYPE_PROFINET:
        return {"error": "not_profinet", "ethertype": hex(ethertype)}
    src_mac = data[6:12]
    src_mac_str = ":".join(f"{b:02x}" for b in src_mac)
    # Frame ID
    frame_id = struct.unpack("!H", data[14:16])[0]
    if frame_id != 0xFEFF:  # 0xFEFF = DCP Identify RPC response
        return {"error": "not_dcp_response", "frame_id": hex(frame_id)}
    # DCP header
    pos = 16
    if len(data) < pos + 10:
        return {"error": "dcp_header_truncated"}
    service_id, service_type, xid, resp_delay, dcp_len = struct.unpack(
        "!BBHIH", data[pos:pos+10])
    pos += 10
    # Parse DCP data blocks
    blocks = []
    while pos < len(data) and pos < 16 + 10 + dcp_len:
        if pos + 4 > len(data):
            break
        option, suboption, block_info, block_len = struct.unpack(
            "!BBHH", data[pos:pos+4])
        pos += 4
        block_data = data[pos:pos+block_len]
        pos += block_len + (1 if block_len % 2 else 0)  # padding
        blocks.append({
            "option": option,
            "suboption": suboption,
            "raw_data": block_data.decode("utf-8", errors="replace")[:100],
        })
    # Extract device info
    device_name = None
    vendor = None
    device_id = None
    for b in blocks:
        if b["option"] == OPT_DEVICE:
            if b["suboption"] == SUB_DEVICE_NAME:
                device_name = b["raw_data"].rstrip("\x00")
            elif b["suboption"] == SUB_DEVICE_VENDOR:
                vendor = b["raw_data"].rstrip("\x00")
            elif b["suboption"] == SUB_DEVICE_ID:
                if len(b["raw_data"].encode()) >= 4:
                    vendor_id, device_num = struct.unpack(
                        "!HH", b["raw_data"].encode()[:4])
                    device_id = f"vendor=0x{vendor_id:04x} device=0x{device_num:04x}"
    return {
        "mac": src_mac_str,
        "device_name": device_name,
        "vendor": vendor,
        "device_id": device_id,
        "blocks_found": len(blocks),
        "service": SERVICE_NAMES.get(service_id, f"unknown(0x{service_id:02x})"),
    }

def listen_dcp_multicast(iface: str, duration: int) -> list:
    """Écoute le multicast DCP pendant `duration` secondes.
    Envoie un Identify request puis collecte les réponses."""
    devices = []
    try:
        # Raw socket for L2 access
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_PROFINET))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        s.settimeout(1)
        # Send Identify request (multicast)
        req = build_dcp_identify_req()
        # Get our MAC address
        try:
            import fcntl
            our_mac = fcntl.ioctl(s.fileno(), 0x8927,  # SIOCGIFHWADDR
                                  struct.pack('256s', iface.encode()[:15]))[18:24]
            req = req[:6] + our_mac + req[12:]  # replace src MAC
        except Exception:
            pass
        s.sendto(req, (DCP_MULTICAST.decode('latin-1') if False else iface, 0))
        # Listen for responses
        t0 = time.time()
        while time.time() - t0 < duration:
            try:
                data = s.recv(65535)
                parsed = parse_dcp_response(data)
                if "error" not in parsed or parsed.get("mac"):
                    devices.append(parsed)
            except socket.timeout:
                # Re-send Identify every 2 seconds
                if int(time.time() - t0) % 2 == 0:
                    s.sendto(req, (iface, 0))
            except Exception:
                pass
        s.close()
    except PermissionError:
        return [{"error": "root_required", "note": "Raw socket nécessite root"}]
    except FileNotFoundError:
        return [{"error": "interface_not_found", "interface": iface}]
    except Exception as e:
        return [{"error": type(e).__name__}]
    return devices

def main():
    lab_guard()
    # Écouter DCP multicast
    raw_devices = listen_dcp_multicast(IFACE, DURATION)
    # Dédupliquer par MAC
    seen_macs = set()
    unique_devices = []
    for d in raw_devices:
        mac = d.get("mac")
        if mac and mac not in seen_macs:
            seen_macs.add(mac)
            unique_devices.append(d)
        elif "error" in d:
            unique_devices.append(d)
    # Compter les devices identifiés
    identified = [d for d in unique_devices if d.get("device_name")]
    report = {
        "module": "profinet_probe",
        "version": "3.3.0",
        "interface": IFACE,
        "listen_duration_s": DURATION,
        "read_only": True,
        "devices_found": len(identified),
        "devices": identified,
        "raw_responses": len(raw_devices),
        "dcp_auth_required": False,  # DCP n'a JAMAIS d'auth
        "write_commands_blocked": True,  # Set/Reset interdits en read_only
        "blocked_operations": [
            "DCP Set (device name) — would cause naming conflict",
            "DCP Factory Reset — would stop the device",
            "RT real-time injection — would corrupt cyclic communication",
        ],
        "seed": SEED,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_note": "DCP sans auth = n'importe qui sur le L2 peut identifier et configurer les devices PROFINET. Set name = arrêt production. Factory reset = arrêt complet.",
        "nerc_cip_note": "PROFINET sans segmentation L2 = violation NERC CIP-005",
    }
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
