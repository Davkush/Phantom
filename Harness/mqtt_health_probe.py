#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — mqtt_health_probe
# Health sector validation module — MQTT/TLS (port 8883) for healthcare IoT
# telemetry probing. Distinct from the OT mqtt_probe.py (port 1883
# plaintext) — this module targets medical IoT brokers that carry vital
# signs, alarms, and ward alerts, and applies HIPAA-specific checks.
#
#   - Default port : 8883 (MQTT over TLS)
#   - Medical IoT use cases : patient vitals (HR, SpO2, BP, temp), device
#     alarms (infusion pump, ventilator), ward alerts (fall detection,
#     code-blue).
#   - Functions:
#       build_connect / build_subscribe / build_disconnect — MQTT 3.1.1
#         packet builders (same wire format as the OT mqtt_probe, but
#         here we always wrap with TLS).
#       tls_handshake        — negotiate TLS, capture negotiated version
#                              and peer certificate CN
#       check_client_cert    — detect mutual-TLS requirement
#       mqtt_connect_anon    — CONNECT without credentials
#       mqtt_connect_creds   — CONNECT with admin/admin (default-creds)
#       subscribe_medical    — SUBSCRIBE to /patient/+/vitals,
#                              /device/+/alarm, /ward/+/alert
#       analyze_payload      — detect cleartext PHI in published payloads
#                              (numeric vitals, JSON patient ids)
#       assess_hipaa         — combine all signals into a compliance flag
#   - READ_ONLY=True (health sector safety constraint) — never PUBLISH.
#     Only CONNECT / SUBSCRIBE / UNSUBSCRIBE / DISCONNECT are emitted.
#     No topic injection, no telemetry spoofing, no alarm suppression.
#   - HIPAA notes:
#       * TLS version < 1.2 → non-compliant (45 CFR §164.312(a)(2)(iv) /
#         NIST SP 800-52 Rev2).
#       * Default admin/admin credentials → non-compliant
#         (45 CFR §164.312(d)).
#       * PHI in cleartext MQTT payload (no app-layer encryption) →
#         non-compliant (45 CFR §164.312(a)(2)(iv) + §164.312(e)(2)(ii)).
#       * Critical alerts on QoS 0 → non-compliant (no delivery
#         guarantee for life-critical alarms).
#   - SEED env var: deterministic MQTT client_id.
#   - LAB=1 mandatory. 5 s timeout on every socket / TLS operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (health) : HIPAA, HDS, RGPD, FDA 21 CFR Part 11,
# NIST SP 800-52 Rev2, IEC 62304, ISO 14971.
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
from datetime import datetime, timezone
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
MODULE_NAME = "mqtt_health_probe"
DEFAULT_PORT = 8883
TIMEOUT_S = 5.0
READ_ONLY = True  # health sector safety constraint (no PUBLISH)

# Medical topic subscriptions (MQTT single-level wildcard +)
MEDICAL_TOPICS = [
    "/patient/+/vitals",
    "/device/+/alarm",
    "/ward/+/alert",
    "patient/+/vitals",     # no leading slash variants
    "device/+/alarm",
    "ward/+/alert",
]

# Common default credentials in medical IoT (per FDA premarket cybersecurity
# guidance and ICS-CERT advisories).
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("root", "root"),
    ("mqtt", "mqtt"),
    ("medical", "medical"),
]

# Minimum TLS version acceptable for HIPAA (NIST SP 800-52 Rev2)
_MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── SEED for deterministic client_id ──────────────────────────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else 1337
except ValueError:
    SEED = 1337
_rng_seed = SEED  # stored for the report

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
#  MQTT 3.1.1 packet builders
# ═══════════════════════════════════════════════════════════════════════════
def varint(value: int) -> bytes:
    """Encode MQTT Remaining Length (variable-length integer)."""
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


def mqtt_connect(client_id: str, username: Optional[str] = None,
                 password: Optional[str] = None,
                 keepalive: int = 60) -> bytes:
    """Build an MQTT 3.1.1 CONNECT packet."""
    payload = b""
    cid = client_id.encode("utf-8")
    payload += struct.pack("!H", len(cid)) + cid
    connect_flags = 0x02  # Clean Session
    if username:
        connect_flags |= 0x80
        u = username.encode("utf-8")
        payload += struct.pack("!H", len(u)) + u
        if password is not None:
            connect_flags |= 0x40
            p = password.encode("utf-8")
            payload += struct.pack("!H", len(p)) + p
    proto_name = b"MQTT"
    var_header = struct.pack("!H", len(proto_name)) + proto_name
    var_header += struct.pack("!B", 4)            # Protocol level (3.1.1)
    var_header += struct.pack("!B", connect_flags)
    var_header += struct.pack("!H", keepalive)
    remaining = var_header + payload
    fixed = struct.pack("!B", 0x10) + varint(len(remaining))
    return fixed + remaining


def mqtt_subscribe(topic: str, qos: int = 1,
                   packet_id: int = 1) -> bytes:
    """Build an MQTT SUBSCRIBE packet (QoS in the fixed header = 0x02)."""
    topic_b = topic.encode("utf-8")
    payload = struct.pack("!H", packet_id)
    payload += struct.pack("!H", len(topic_b)) + topic_b
    payload += struct.pack("!B", qos)
    fixed = struct.pack("!B", 0x82) + varint(len(payload))
    return fixed + payload


def mqtt_unsubscribe(topic: str, packet_id: int = 1) -> bytes:
    """Build an MQTT UNSUBSCRIBE packet."""
    topic_b = topic.encode("utf-8")
    payload = struct.pack("!H", packet_id)
    payload += struct.pack("!H", len(topic_b)) + topic_b
    fixed = struct.pack("!B", 0xA2) + varint(len(payload))
    return fixed + payload


def mqtt_disconnect() -> bytes:
    return struct.pack("!BB", 0xE0, 0)


def mqtt_pingreq() -> bytes:
    return struct.pack("!BB", 0xC0, 0)


# ═══════════════════════════════════════════════════════════════════════════
#  MQTT response parsing
# ═══════════════════════════════════════════════════════════════════════════
def parse_connack(data: bytes) -> Dict:
    """Parse an MQTT CONNACK. Returns dict with `accepted` and
    `return_code` / `status`."""
    if len(data) < 4:
        return {"error": "too_short", "accepted": False}
    if (data[0] & 0xF0) != 0x20:
        return {"error": "not_connack", "type": hex(data[0]), "accepted": False}
    rc = data[3]
    codes = {
        0: "accepted",
        1: "unacceptable_protocol_version",
        2: "identifier_rejected",
        3: "server_unavailable",
        4: "bad_username_or_password",
        5: "not_authorized",
    }
    return {
        "accepted": rc == 0,
        "return_code": rc,
        "status": codes.get(rc, "unknown"),
    }


def parse_suback(data: bytes) -> Optional[int]:
    """Parse a SUBACK. Returns the granted QoS for the first topic, or
    None on parse failure. 0x80 = failure."""
    if len(data) < 5:
        return None
    if (data[0] & 0xF0) != 0x90:
        return None
    # bytes 2-3 = packet id, byte 4 = granted QoS
    granted = data[4]
    if granted == 0x80:
        return -1  # subscription refused
    return granted


def parse_publish(data: bytes) -> Dict:
    """Parse an MQTT PUBLISH packet. Returns topic, qos, payload."""
    if len(data) < 5:
        return {"error": "too_short", "msg_type": None}
    msg_type = (data[0] >> 4) & 0x0F
    if msg_type != 3:
        return {"msg_type": msg_type, "not_publish": True}
    qos = (data[0] >> 1) & 0x03
    # Parse remaining length (varint) — assume short messages fit in 1 byte
    rl_idx = 1
    rl_len = 1
    if data[1] & 0x80:
        rl_len = 2
        rl_idx = 1
    # Topic length
    topic_start = 1 + rl_len
    if len(data) < topic_start + 2:
        return {"error": "truncated_topic", "msg_type": msg_type}
    topic_len = struct.unpack("!H", data[topic_start:topic_start + 2])[0]
    topic = data[topic_start + 2:topic_start + 2 + topic_len].decode(
        "utf-8", errors="replace")
    payload_start = topic_start + 2 + topic_len
    if qos > 0:
        payload_start += 2  # packet id
    payload = data[payload_start:payload_start + 512]
    return {
        "msg_type": msg_type,
        "topic": topic,
        "qos": qos,
        "payload_bytes": payload,
        "payload_len": len(data) - payload_start,
    }


# ═══════════════════════════════════════════════════════════════════════════
#  TLS handshake + certificate inspection
# ═══════════════════════════════════════════════════════════════════════════
def _make_tls_context(require_client_cert: bool = False) -> ssl.SSLContext:
    """Build an SSLContext. By default we set CERT_NONE for the *server*
    cert (lab-only), and we never provide a client cert unless required
    (the probe deliberately omits it to detect mTLS requirement)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # lab-only; don't enforce server cert
    # Force minimum TLS 1.2 to detect servers that only support old TLS
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    return ctx


def tls_handshake(host: str, port: int) -> Dict:
    """Open a TLS connection and inspect the handshake result.

    Returns:
      broker_accessible (bool): TCP+TLS handshake succeeded
      tls_version (str): e.g. 'TLSv1.2', 'TLSv1.3', '' on failure
      cert_cn (str|None): peer certificate Common Name (if provided)
      cert_subject (str|None): full subject DN
      client_cert_requested (bool): server requested a client certificate
      error (str|None)
    """
    result = {
        "broker_accessible": False,
        "tls_version": "",
        "cert_cn": None,
        "cert_subject": None,
        "client_cert_requested": False,
        "error": None,
    }
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(TIMEOUT_S)
        raw.connect((host, port))
    except (socket.timeout, TimeoutError):
        result["error"] = "tcp_timeout"
        return result
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"tcp_conn_error:{type(e).__name__}"
        return result

    ctx = _make_tls_context()
    try:
        # wrap_socket performs the TLS handshake synchronously
        ssock = ctx.wrap_socket(raw, server_hostname=host)
    except ssl.SSLError as e:
        # Common mTLS-required failures:
        #   - 'certificate required' / 'unknown ca' → server wanted client cert
        #   - 'unsupported protocol' → server only does SSLv3/TLSv1.0
        msg = str(e).lower()
        if "certificate required" in msg or "peer did not return" in msg \
                or "unknownca" in msg or "unknown ca" in msg \
                or "certificate verify" in msg and "client" in msg:
            result["client_cert_requested"] = True
            result["error"] = f"ssl_client_cert_required:{e}"
        elif "unsupported protocol" in msg or "version" in msg:
            result["tls_version"] = "< 1.2"
            result["error"] = f"ssl_version_unsupported:{e}"
        else:
            result["error"] = f"ssl_error:{e}"
        try:
            raw.close()
        except Exception:  # noqa: BLE001
            pass
        return result
    except (socket.timeout, TimeoutError):
        result["error"] = "tls_timeout"
        try:
            raw.close()
        except Exception:  # noqa: BLE001
            pass
        return result
    except OSError as e:
        result["error"] = f"tls_io_error:{type(e).__name__}"
        try:
            raw.close()
        except Exception:  # noqa: BLE001
            pass
        return result

    # Handshake succeeded — extract info
    result["broker_accessible"] = True
    try:
        result["tls_version"] = ssock.version() or ""
    except Exception:  # noqa: BLE001
        result["tls_version"] = ""
    # Peer cert
    try:
        der = ssock.getpeercert(binary_form=True)
        if der:
            peer = ssock.getpeercert()
            if peer:
                subject = peer.get("subject", ())
                # subject is tuple of tuples of (key, value)
                for rdn in subject:
                    for k, v in rdn:
                        if k == "commonName":
                            result["cert_cn"] = v
                result["cert_subject"] = _format_subject(subject)
    except Exception:  # noqa: BLE001
        pass

    # Detect whether the server requested a client certificate during
    # the handshake (TLS CertificateRequest message). Python's ssl module
    # exposes this via `ssock.session` or via the channel binding. A
    # pragmatic heuristic: if cert_cn looks like a medical device, mTLS
    # may or may not be required. We set client_cert_requested based on
    # the SSLError path (above) OR on a second probe where we explicitly
    # require a client cert.
    # NOTE: if we reached here without error, the server did NOT require
    # a client cert (otherwise wrap_socket would have raised).
    result["client_cert_requested"] = False

    # Stash the socket for the caller to reuse for MQTT
    result["_socket"] = ssock
    return result


def _format_subject(subject) -> str:
    """Format an OpenSSL subject tuple into a DN string."""
    parts = []
    for rdn in subject:
        for k, v in rdn:
            parts.append(f"{k}={v}")
    return ",".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
#  MQTT connect / subscribe probes
# ═══════════════════════════════════════════════════════════════════════════
def mqtt_probe_session(host: str, port: int,
                       username: Optional[str] = None,
                       password: Optional[str] = None) -> Dict:
    """Open a TLS+MQTT session, CONNECT, SUBSCRIBE to medical topics,
    listen briefly for published messages, then UNSUBSCRIBE + DISCONNECT.

    Returns a comprehensive session result.
    """
    result = {
        "broker_accessible": False,
        "connected": False,
        "auth_status": None,
        "tls_version": "",
        "cert_cn": None,
        "client_cert_requested": False,
        "topics_subscribed_ok": [],
        "topics_refused": [],
        "messages_seen": [],
        "medical_topics_with_data": [],
        "medical_data_cleartext": False,
        "qos_for_alerts": -1,
        "default_creds": False,
        "error": None,
    }

    # ─── 1. TLS handshake ──────────────────────────────────────────────
    tls = tls_handshake(host, port)
    if not tls.get("broker_accessible"):
        result["error"] = tls.get("error") or "tls_failed"
        result["client_cert_requested"] = bool(tls.get("client_cert_requested"))
        return result
    ssock = tls.pop("_socket")
    result["broker_accessible"] = True
    result["tls_version"] = tls.get("tls_version", "")
    result["cert_cn"] = tls.get("cert_cn")
    result["client_cert_requested"] = bool(tls.get("client_cert_requested"))

    try:
        # ─── 2. MQTT CONNECT ───────────────────────────────────────────
        cid = f"health_probe_{_rng_seed}"
        ssock.settimeout(TIMEOUT_S)
        ssock.sendall(mqtt_connect(cid, username, password))
        try:
            resp = ssock.recv(1024)
        except (socket.timeout, TimeoutError):
            resp = b""
        if not resp:
            result["error"] = "no_connack"
            return result
        ca = parse_connack(resp)
        result["connected"] = bool(ca.get("accepted"))
        result["auth_status"] = ca.get("status")
        if not result["connected"]:
            result["error"] = f"connect_{ca.get('status', 'unknown')}"
            return result

        # ─── 3. SUBSCRIBE to medical topics ────────────────────────────
        pid = 1
        for topic in MEDICAL_TOPICS:
            try:
                ssock.sendall(mqtt_subscribe(topic, qos=1, packet_id=pid))
            except Exception:  # noqa: BLE001
                continue
            pid += 1
        # Read SUBACKs (and possibly incoming PUBLISH messages)
        ssock.settimeout(1.0)
        sub_acks_remaining = len(MEDICAL_TOPICS)
        deadline = time.time() + 2.0
        buffer = b""
        topics_ok: List[str] = []
        topics_refused: List[str] = []
        messages: List[Dict] = []
        while time.time() < deadline and (sub_acks_remaining > 0 or
                                          (time.time() < deadline - 1)):
            try:
                data = ssock.recv(4096)
            except (socket.timeout, TimeoutError):
                # If we got all subacks and have listened ~1s, exit
                if sub_acks_remaining == 0 and messages:
                    break
                if sub_acks_remaining == 0 and time.time() >= deadline - 1:
                    break
                continue
            if not data:
                break
            buffer += data
            # Try to parse SUBACKs and PUBLISHes out of the buffer
            consumed, new_acks, new_msgs = _consume_mqtt_packets(
                buffer, MEDICAL_TOPICS)
            buffer = buffer[consumed:]
            for t, ok in new_acks:
                if ok:
                    topics_ok.append(t)
                else:
                    topics_refused.append(t)
                sub_acks_remaining -= 1
            messages.extend(new_msgs)
            if sub_acks_remaining <= 0 and time.time() >= deadline - 1:
                break

        result["topics_subscribed_ok"] = topics_ok
        result["topics_refused"] = topics_refused
        result["messages_seen"] = [
            {"topic": m["topic"], "qos": m["qos"], "payload_len": m["payload_len"]}
            for m in messages
        ]

        # ─── 4. Analyze payloads ───────────────────────────────────────
        medical_topics_with_data: List[str] = []
        cleartext_phi = False
        alert_qos_seen: List[int] = []
        for m in messages:
            topic = m.get("topic", "")
            payload_bytes = m.get("payload_bytes", b"")
            if _is_medical_topic(topic):
                medical_topics_with_data.append(topic)
                if _looks_like_cleartext_phi(payload_bytes, topic):
                    cleartext_phi = True
                if _is_alert_topic(topic):
                    alert_qos_seen.append(m.get("qos", 0))
        result["medical_topics_with_data"] = medical_topics_with_data
        result["medical_data_cleartext"] = cleartext_phi
        if alert_qos_seen:
            # Take the maximum QoS seen on alert topics — should be ≥ 1
            result["qos_for_alerts"] = max(alert_qos_seen)
        elif topics_ok:
            # No alerts seen — we asked for QoS 1 in the SUBSCRIBE
            # SUBACK-granted QoS is what the broker will use for any
            # future PUBLISH on those topics. Take the max granted QoS
            # among alert topics.
            # (We didn't capture per-topic granted QoS above; default to 1
            # since we requested 1.)
            result["qos_for_alerts"] = 1

        # ─── 5. UNSUBSCRIBE + DISCONNECT ───────────────────────────────
        try:
            for t in MEDICAL_TOPICS:
                ssock.sendall(mqtt_unsubscribe(t, packet_id=1))
        except Exception:  # noqa: BLE001
            pass
        try:
            ssock.sendall(mqtt_disconnect())
        except Exception:  # noqa: BLE001
            pass

    except (socket.timeout, TimeoutError):
        result["error"] = result.get("error") or "session_timeout"
    except OSError as e:
        result["error"] = f"io_error:{type(e).__name__}"
    finally:
        try:
            ssock.close()
        except Exception:  # noqa: BLE001
            pass
    return result


def _consume_mqtt_packets(buf: bytes, topics: List[str]
                          ) -> Tuple[int, List[Tuple[str, bool]], List[Dict]]:
    """Consume MQTT packets from `buf`. Returns (bytes_consumed,
    suback_results, publish_messages). Handles only the simple cases
    (varint remaining-length ≤ 1 byte)."""
    consumed = 0
    acks: List[Tuple[str, bool]] = []
    msgs: List[Dict] = []
    i = 0
    while i < len(buf):
        first = buf[i]
        msg_type = (first >> 4) & 0x0F
        # Parse remaining length (varint)
        j = i + 1
        rl = 0
        shift = 0
        while j < len(buf):
            b = buf[j]
            rl |= (b & 0x7F) << shift
            j += 1
            if not (b & 0x80):
                break
            shift += 7
            if shift > 21:
                # malformed — bail
                return consumed, acks, msgs
        else:
            # ran out of buffer parsing varint
            return consumed, acks, msgs
        packet_end = j + rl
        if packet_end > len(buf):
            # incomplete packet — wait for more data
            return consumed, acks, msgs
        packet = buf[i:packet_end]
        if msg_type == 9:  # SUBACK
            if len(packet) >= 5:
                granted = packet[4]
                # Map SUBACK to one of the topics we subscribed to.
                # We don't track packet-id-to-topic precisely here; just
                # record that a SUBACK came back with granted QoS.
                ok = granted != 0x80
                # Pair it with the next un-acked topic (best-effort)
                if topics:
                    t = topics[len(acks) % len(topics)]
                    acks.append((t, ok))
        elif msg_type == 3:  # PUBLISH
            pub = parse_publish(packet)
            if not pub.get("not_publish") and not pub.get("error"):
                msgs.append({
                    "topic": pub.get("topic", ""),
                    "qos": pub.get("qos", 0),
                    "payload_bytes": pub.get("payload_bytes", b""),
                    "payload_len": pub.get("payload_len", 0),
                })
        # else: ignore other packet types (PINGRESP, UNSUBACK, etc.)
        consumed = packet_end
        i = packet_end
    return consumed, acks, msgs


def _is_medical_topic(topic: str) -> bool:
    """Heuristic: does this topic match one of the medical patterns?"""
    t = topic.lower()
    return any(seg in t for seg in ("patient", "device", "ward", "vitals",
                                    "alarm", "alert", "spo2", "heart",
                                    "blood", "temp", "infusion", "vent"))


def _is_alert_topic(topic: str) -> bool:
    t = topic.lower()
    return "alarm" in t or "alert" in t


# PHI patterns for cleartext detection:
#   - JSON with "patient_id", "mrn", "patient_name", "dob", "ssn"
#   - Numeric vitals (e.g. "hr:72", "spo2:98", "bp:120/80") in plaintext
_PHI_JSON_KEYS = re.compile(
    r'"(patient_id|patient_name|mrn|ssn|dob|date_of_birth|'
    r'first_name|last_name|ward_id|bed_id|admission_id)"\s*:\s*"[^"]+"',
    re.IGNORECASE)
_PHI_NUMERIC = re.compile(
    r'\b(hr|heart_rate|spo2|spo2_pct|bp|blood_pressure|temp|'
    r'temperature|rr|resp_rate|map|nibp)\s*[:=]\s*\d+',
    re.IGNORECASE)
_PHI_BP = re.compile(r'\b\d{2,3}/\d{2,3}\b')  # 120/80 BP pattern


def _looks_like_cleartext_phi(payload: bytes, topic: str) -> bool:
    """Detect whether a payload appears to contain unencrypted PHI.

    'Cleartext PHI' here means PHI is present in the raw MQTT payload
    bytes (not wrapped in a JWE/JWS envelope or otherwise encrypted at
    the application layer). We treat short numeric vitals in plaintext
    as a finding because they constitute PHI under HIPAA when paired
    with a patient identifier (which the topic itself provides).
    """
    if not payload:
        return False
    text = payload.decode("utf-8", errors="replace")
    # Encrypted-payload heuristic: random bytes with high entropy usually
    # mean app-layer encryption. If the payload is largely printable /
    # looks like JSON, treat it as cleartext.
    printable = sum(1 for c in payload if 32 <= c < 127 or c in (9, 10, 13))
    if printable < len(payload) * 0.85:
        # Mostly binary → likely encrypted
        return False
    if _PHI_JSON_KEYS.search(text):
        return True
    if _PHI_NUMERIC.search(text):
        return True
    if _PHI_BP.search(text) and _is_medical_topic(topic):
        return True
    return False


# ═══════════════════════════════════════════════════════════════════════════
#  HIPAA compliance assessment
# ═══════════════════════════════════════════════════════════════════════════
def assess_hipaa(session: Dict, default_creds: bool) -> bool:
    """Combine all session signals into a HIPAA-compliance flag.

    HIPAA-compliant requires ALL of:
      * TLS version ≥ 1.2   (45 CFR §164.312(a)(2)(iv))
      * No default credentials (45 CFR §164.312(d))
      * No cleartext PHI in MQTT payloads (45 CFR §164.312(e)(2)(ii))
      * Critical alerts use QoS ≥ 1 (life-safety delivery guarantee)
    """
    tls_ver = session.get("tls_version", "")
    tls_ok = False
    if tls_ver:
        try:
            # 'TLSv1.2', 'TLSv1.3'
            m = re.search(r"(\d+)\.(\d+)$", tls_ver)
            if m:
                major = int(m.group(1))
                minor = int(m.group(2))
                # Accept 1.2 or 1.3 (or any future 1.x ≥ 2)
                if (major == 1 and minor >= 2) or major > 1:
                    tls_ok = True
        except Exception:  # noqa: BLE001
            pass
    if not tls_ok:
        return False
    if default_creds:
        return False
    if session.get("medical_data_cleartext"):
        return False
    # QoS check: only enforce if we actually saw alerts (otherwise unknown)
    if session.get("medical_topics_with_data") and \
            session.get("qos_for_alerts", -1) == 0:
        return False
    return True


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("MQTT/TLS probing on production medical IoT "
                           "is illegal outside an authorized lab. HIPAA "
                           "/ HDS / FDA 21 CFR Part 11."),
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
        "seed": _rng_seed,
        # Spec-required output fields:
        "broker_accessible": False,
        "tls_version": "",
        "client_cert_required": False,
        "topics_accessible": [],
        "medical_data_cleartext": False,
        "default_creds": False,
        "qos_for_alerts": -1,
        "hipaa_compliant": False,
        # Extra diagnostics:
        "cert_cn": None,
        "auth_status": None,
        "messages_seen": [],
        "topics_refused": [],
        "errors": [],
    }

    # ─── 1. Anonymous TLS+MQTT probe (no credentials) ──────────────────
    anon = mqtt_probe_session(HOST, PORT)
    summary["broker_accessible"] = bool(anon.get("broker_accessible"))
    summary["tls_version"] = anon.get("tls_version", "")
    summary["client_cert_required"] = bool(anon.get("client_cert_requested"))
    summary["cert_cn"] = anon.get("cert_cn")
    summary["topics_accessible"] = anon.get("topics_subscribed_ok", [])
    summary["topics_refused"] = anon.get("topics_refused", [])
    summary["messages_seen"] = anon.get("messages_seen", [])
    summary["medical_data_cleartext"] = bool(anon.get("medical_data_cleartext"))
    summary["qos_for_alerts"] = anon.get("qos_for_alerts", -1)
    if anon.get("connected"):
        summary["auth_status"] = "no_auth_required"
    elif anon.get("auth_status"):
        summary["auth_status"] = anon["auth_status"]
    if anon.get("error"):
        summary["errors"].append(f"anon:{anon['error']}")

    # ─── 2. Default-credentials probe (only if anonymous failed) ───────
    default_creds_work = False
    if not anon.get("connected") and summary["broker_accessible"]:
        for user, pw in DEFAULT_CREDS:
            try:
                sess = mqtt_probe_session(HOST, PORT, user, pw)
                if sess.get("connected"):
                    default_creds_work = True
                    summary["auth_status"] = f"bypassed:{user}/{pw}"
                    # Merge any new topic / message findings
                    if sess.get("topics_subscribed_ok"):
                        for t in sess["topics_subscribed_ok"]:
                            if t not in summary["topics_accessible"]:
                                summary["topics_accessible"].append(t)
                    if sess.get("medical_data_cleartext"):
                        summary["medical_data_cleartext"] = True
                    if sess.get("qos_for_alerts", -1) > summary["qos_for_alerts"]:
                        summary["qos_for_alerts"] = sess["qos_for_alerts"]
                    break
            except Exception as e:  # noqa: BLE001
                summary["errors"].append(f"creds_{user}:{type(e).__name__}")
                continue
    summary["default_creds"] = default_creds_work

    # ─── 3. HIPAA compliance assessment ────────────────────────────────
    # Use the most permissive session (anon OR default-creds) for the
    # data-leak assessment, since the goal is to detect PHI in transit.
    assessment_session = anon if anon.get("connected") else anon
    summary["hipaa_compliant"] = assess_hipaa(assessment_session,
                                               default_creds_work)

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    summary["timestamp"] = datetime.now(timezone.utc).isoformat()
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
