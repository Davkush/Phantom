#!/usr/bin/env python3
# HARNESS-VALIDATION v3.3.0 — MQTT probe (IoT/IIoT/telemetry).
# Port 1883 (TCP plaintext), 8883 (TLS), 1884 (WebSocket).
#
# MQTT est omniprésent en IoT, IIoT, smart buildings, SCADA telemetry.
# Vulnérabilités courantes :
#   - Broker sans authentification (très fréquent)
#   - Abonnement wildcard # → exfiltration de tous les messages
#   - Port 1883 en clair → interception
#   - Credentials par défaut (mosquitto:mosquitto, admin:admin)
#   - Topic injection → publication sur topics sensibles
#   - QoS 0 sans rate limiting → DoS
#
# Usage : python3 mqtt_probe.py <host> [port]
# Défaut : 127.0.0.1 1883
# READ_ONLY : ne publie jamais, s'abonne brièvement puis se désabonne.
import json
import os
import socket
import ssl
import struct
import sys
import time
from datetime import datetime, timezone

SEED = int(os.environ.get("SEED", "1337"))
LAB = os.environ.get("LAB", "0")
TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1883
USE_TLS = PORT == 8883 or os.environ.get("MQTT_TLS") == "1"
TIMEOUT = 5

def lab_guard():
    if LAB != "1":
        print(json.dumps({"module": "mqtt_probe", "error": "lab_guard_failed"}))
        sys.exit(1)

def varint(value: int) -> bytes:
    """Encode un entier en MQTT Remaining Length (varint)."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value > 0:
            byte |= 0x80
        out.append(byte)
        if value == 0:
            break
    return bytes(out)

def mqtt_connect(client_id: str, username: str = None, password: str = None,
                 keepalive: int = 60) -> bytes:
    """Construit un packet MQTT CONNECT."""
    # Payload
    payload = b""
    # Client ID
    cid = client_id.encode("utf-8")
    payload += struct.pack("!H", len(cid)) + cid
    # Will (none)
    # Username/Password
    connect_flags = 0x02  # Clean Session
    if username:
        connect_flags |= 0x80
        u = username.encode("utf-8")
        payload += struct.pack("!H", len(u)) + u
        if password:
            connect_flags |= 0x40
            p = password.encode("utf-8")
            payload += struct.pack("!H", len(p)) + p
    # Variable header
    proto_name = b"MQTT"
    var_header = struct.pack("!H", len(proto_name)) + proto_name
    var_header += struct.pack("!B", 4)  # Protocol level (MQTT 3.1.1)
    var_header += struct.pack("!B", connect_flags)
    var_header += struct.pack("!H", keepalive)
    # Fixed header
    remaining = var_header + payload
    fixed = struct.pack("!B", 0x10) + varint(len(remaining))  # CONNECT = 0x10
    return fixed + remaining

def mqtt_subscribe(topic: str, qos: int = 0, packet_id: int = 1) -> bytes:
    """Construit un packet MQTT SUBSCRIBE."""
    topic_b = topic.encode("utf-8")
    payload = struct.pack("!H", packet_id)
    payload += struct.pack("!H", len(topic_b)) + topic_b
    payload += struct.pack("!B", qos)
    fixed = struct.pack("!B", 0x82) + varint(len(payload))  # SUBSCRIBE = 0x82
    return fixed + payload

def mqtt_unsubscribe(topic: str, packet_id: int = 1) -> bytes:
    """Construit un packet MQTT UNSUBSCRIBE."""
    topic_b = topic.encode("utf-8")
    payload = struct.pack("!H", packet_id)
    payload += struct.pack("!H", len(topic_b)) + topic_b
    fixed = struct.pack("!B", 0xA2) + varint(len(payload))
    return fixed + payload

def mqtt_pingreq() -> bytes:
    return struct.pack("!BB", 0xC0, 0)

def mqtt_disconnect() -> bytes:
    return struct.pack("!BB", 0xE0, 0)

def parse_connack(data: bytes) -> dict:
    """Parse un CONNACK packet."""
    if len(data) < 4:
        return {"error": "too_short"}
    if data[0] != 0x20:
        return {"error": "not_connack", "type": hex(data[0])}
    return_code = data[3]
    codes = {
        0: "accepted",
        1: "unacceptable_protocol_version",
        2: "identifier_rejected",
        3: "server_unavailable",
        4: "bad_username_or_password",
        5: "not_authorized",
    }
    return {
        "accepted": return_code == 0,
        "return_code": return_code,
        "status": codes.get(return_code, "unknown"),
    }

def parse_publish(data: bytes) -> dict:
    """Parse un PUBLISH packet reçu pendant l'abonnement."""
    if len(data) < 5:
        return {"error": "too_short"}
    msg_type = (data[0] >> 4) & 0x0F
    if msg_type != 3:
        return {"msg_type": msg_type, "not_publish": True}
    qos = (data[0] >> 1) & 0x03
    remaining = data[1:]  # simplified, no varint handling for large msgs
    topic_len = struct.unpack("!H", remaining[:2])[0]
    topic = remaining[2:2+topic_len].decode("utf-8", errors="replace")
    payload_start = 2 + topic_len
    if qos > 0:
        payload_start += 2  # packet ID
    payload = remaining[payload_start:payload_start+200]  # truncate to 200 bytes
    return {
        "topic": topic,
        "qos": qos,
        "payload_preview": payload.decode("utf-8", errors="replace")[:100],
        "payload_len": len(remaining) - payload_start,
    }

def try_connect(host: str, port: int, use_tls: bool,
                username: str = None, password: str = None) -> dict:
    """Tente une connexion MQTT et retourne le résultat."""
    t0 = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        # Send CONNECT
        cid = f"harness_probe_{SEED}"
        sock.sendall(mqtt_connect(cid, username, password))
        # Read CONNACK
        resp = sock.recv(1024)
        connack = parse_connack(resp)
        if connack.get("accepted"):
            # Try SUBSCRIBE to wildcard # (read-only: brief listen)
            sock.sendall(mqtt_subscribe("#", qos=0))
            sub_resp = sock.recv(1024)
            # Listen briefly for messages (2 seconds)
            messages = []
            sock.settimeout(2)
            try:
                while len(messages) < 10:
                    data = sock.recv(4096)
                    if not data:
                        break
                    pub = parse_publish(data)
                    if not pub.get("not_publish") and not pub.get("error"):
                        messages.append({"topic": pub["topic"],
                                         "preview": pub["payload_preview"][:50]})
            except socket.timeout:
                pass
            # UNSUBSCRIBE + DISCONNECT
            sock.sendall(mqtt_unsubscribe("#"))
            sock.sendall(mqtt_disconnect())
        sock.close()
        return {
            "connected": connack.get("accepted", False),
            "auth_result": connack.get("status"),
            "return_code": connack.get("return_code"),
            "messages_seen": len(messages),
            "topics_seen": [m["topic"] for m in messages],
            "duration_ms": round((time.time() - t0) * 1000, 1),
        }
    except socket.timeout:
        return {"connected": False, "error": "timeout", "duration_ms": TIMEOUT * 1000}
    except ConnectionRefusedError:
        return {"connected": False, "error": "connection_refused"}
    except Exception as e:
        return {"connected": False, "error": type(e).__name__}

def main():
    lab_guard()
    results = []
    # Test 1: connexion sans authentification
    r1 = try_connect(TARGET, PORT, USE_TLS)
    results.append({"test": "no_auth", **r1})
    no_auth_works = r1.get("connected", False)
    # Test 2: credentials par défaut (mosquitto:mosquitto)
    if not no_auth_works:
        r2 = try_connect(TARGET, PORT, USE_TLS, "mosquitto", "mosquitto")
        results.append({"test": "default_creds_mosquitto", **r2})
        r3 = try_connect(TARGET, PORT, USE_TLS, "admin", "admin")
        results.append({"test": "default_creds_admin", **r3})
    # Test 3: TLS check (if plaintext port)
    tls_available = False
    if not USE_TLS:
        r_tls = try_connect(TARGET, 8883, True)
        tls_available = r_tls.get("connected", False)

    report = {
        "module": "mqtt_probe",
        "version": "3.3.0",
        "target": TARGET,
        "port": PORT,
        "tls": USE_TLS,
        "read_only": True,
        "broker_accessible": no_auth_works or any(r.get("connected") for r in results),
        "auth_required": not no_auth_works,
        "auth_bypassed": no_auth_works,
        "default_creds_work": any(r.get("connected") for r in results
                                  if "default_creds" in r.get("test", "")),
        "wildcard_subscription": any(r.get("messages_seen", 0) > 0 for r in results),
        "topics_exposed": list(set(t for r in results for t in r.get("topics_seen", []))),
        "tls_available_on_8883": tls_available,
        "cleartext_on_1883": (PORT == 1883 and not USE_TLS),
        "results": results,
        "seed": SEED,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_note": "Broker sans auth + wildcard # = exfiltration de tous les messages IoT/SCADA",
    }
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
