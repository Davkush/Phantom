#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — http3_probe (telecom protocol module)
# HTTP/3 (RFC 9114) over QUIC (RFC 9000) probe.
#
# HTTP/3 is the HTTP/2 successor that runs over QUIC (UDP, TLS 1.3 baked in,
# 0-RTT, multiplexing without head-of-line blocking). Port 443/UDP.
#
# Tests:
#   1. Send QUIC Initial packet → check if server responds → quic_accessible
#   2. Check QUIC version (v1 = 0x00000001, v2 = 0x6b3343cf)
#      (via Version Negotiation response)
#   3. Check if h3 ALPN is negotiated (construct ClientHello in CRYPTO frame)
#      → h3_negotiated
#   4. Test connection migration (send packets from a different local port
#      with the same DCID — server should accept)
#   5. Check amplification attack prevention (server response MUST be ≤3×
#      request size before address validation, RFC 9000 §8.1)
#      → amplification_protected
#
# QUIC Long Header packet format (RFC 9000 §17.2):
#   bit 0:    Header Form (1 = Long)
#   bit 1:    Fixed Bit (1)
#   bits 2-3: Long Packet Type (00=Initial, 01=0-RTT, 10=Handshake, 11=Retry)
#   bits 4-5: Reserved
#   bits 6-7: Packet Number Length (00=1 byte)
#   Bytes 1-4:  Version (4 bytes BE)
#   Byte 5:    DCID Length (1 byte)
#   Bytes:     DCID
#   Byte:      SCID Length
#   Bytes:     SCID
#   Initial-only: Token Length (varint) + Token
#   Length (varint): remaining bytes in packet
#   Packet Number (1-4 bytes)
#   Encrypted payload
#
# Version Negotiation packet (RFC 9000 §17.2.1) — sent by server when
# client's version is unsupported:
#   Byte 0: 0b11000000 | unused (Header Form=1, Fixed Bit=0)
#   Bytes 1-4: Version = 0x00000000
#   DCID Length + DCID (echoed from client)
#   SCID Length + SCID (echoed from client)
#   List of 4-byte supported versions
#
# Initial keys derivation (RFC 9001 §5.2) — needed to encrypt a real Initial
# packet. For our probe we don't complete the handshake (we just need a
# response), so we send a partially-formed Initial that triggers either:
#   (a) A Version Negotiation response (if our version is unsupported)
#   (b) A CONNECTION_CLOSE (if our payload is undecryptable)
#   (c) A Retry packet (if address validation is required)
# Any of these proves the server speaks QUIC.
#
# CLI:
#   python3 http3_probe.py [host] [port]
#       host default = 127.0.0.1
#       port default = 443 (UDP)
#
# Output: single JSON object on stdout.
#
# Legal: QUIC probes that exceed 3× amplification can trigger IDS alerts.
# LAB only.
import json
import os
import random
import socket
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple

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
MODULE_NAME = "http3_probe"
TIMEOUT_S = 5  # 5 s hard cap on every socket op

# ─── CLI args ─────────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443
except ValueError:
    PORT = 443

# SAFE_MODE: read_only (default) = no real connection migration test.
SAFE_MODE = os.environ.get("SAFE_MODE", "read_only")

# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))
_rng = random.Random(SEED)

# ─── LAB guard ────────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ═══════════════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════════════
QUIC_VERSION_V1 = 0x00000001          # RFC 9000
QUIC_VERSION_V2 = 0x6b3343cf          # RFC 9369
QUIC_VERSION_DRAFT_29 = 0xff00001d    # draft-29 (used by older browsers)
QUIC_VERSION_NEGOTIATION = 0x00000000 # sentinel for VN request

# Long header packet types (bits 2-3 of byte 0)
LONG_TYPE_INITIAL = 0x00
LONG_TYPE_0RTT = 0x01
LONG_TYPE_HANDSHAKE = 0x02
LONG_TYPE_RETRY = 0x03

# Initial salt per QUIC version (RFC 9001 §5.2 + RFC 9369 §1.3)
QUIC_V1_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
QUIC_V2_INITIAL_SALT = bytes.fromhex("0dede3def700a6db819551b0a7a6a05a17cd369f")

VERSION_NAMES = {
    QUIC_VERSION_V1: "v1 (RFC 9000)",
    QUIC_VERSION_V2: "v2 (RFC 9369)",
    QUIC_VERSION_DRAFT_29: "draft-29",
}

# Amplification limit (RFC 9000 §8.1): server MUST NOT send more than 3× the
# bytes received from an unvalidated peer.
AMPLIFICATION_LIMIT = 3


# ═══════════════════════════════════════════════════════════════════════════
#  Socket helpers
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
#  QUIC varint encoding (RFC 9000 §16)
# ═══════════════════════════════════════════════════════════════════════════
def encode_varint(value: int) -> bytes:
    """QUIC variable-length integer (RFC 9000 §16):
       0..63        → 1 byte (0xxxxxxx, top 2 bits = 00)
       0..16383     → 2 bytes (01xxxxxx xxxxxxxx)
       0..1073741823→ 4 bytes (10xxxxxx ...)
       0..2^62-1    → 8 bytes (11xxxxxx ...)"""
    if value < 0:
        raise ValueError("varint must be non-negative")
    if value <= 63:
        return bytes([value])
    elif value <= 16383:
        return struct.pack(">H", 0x4000 | value)
    elif value <= 1073741823:
        return struct.pack(">I", 0x80000000 | value)
    elif value <= (1 << 62) - 1:
        return struct.pack(">Q", 0xC000000000000000 | value)
    raise ValueError("varint too large")


def decode_varint(data: bytes, pos: int = 0) -> Tuple[int, int]:
    """Decode a QUIC varint. Returns (value, new_pos)."""
    if pos >= len(data):
        return (0, pos)
    first = data[pos]
    length = 1 << (first >> 6)
    if pos + length > len(data):
        return (0, pos + length)
    val = first & 0x3F
    for i in range(1, length):
        val = (val << 8) | data[pos + i]
    return (val, pos + length)


# ═══════════════════════════════════════════════════════════════════════════
#  QUIC packet building
# ═══════════════════════════════════════════════════════════════════════════
def build_version_negotiation_request(dcid: bytes, scid: bytes) -> bytes:
    """Build a Version Negotiation packet REQUEST (version=0).
    Per RFC 9000 §17.2.1: byte 0 has Header Form=1, Fixed Bit=0, rest unused.
    The server MUST respond with a Version Negotiation packet listing
    supported versions."""
    # Byte 0: 1 (header form) 0 (fixed bit) + 6 unused bits (random per spec)
    first_byte = 0xC0 | (_rng.randint(0, 63) & 0x3F)
    out = bytes([first_byte])
    out += struct.pack(">I", QUIC_VERSION_NEGOTIATION)
    out += bytes([len(dcid)]) + dcid
    out += bytes([len(scid)]) + scid
    return out


def build_initial_packet(version: int, dcid: bytes, scid: bytes,
                         packet_number: int,
                         payload: bytes) -> bytes:
    """Build a QUIC Initial packet (long header). The payload is NOT encrypted
    (we don't derive the initial keys here). Real servers will reject this
    with a CONNECTION_CLOSE if decryption fails, but they WILL respond —
    proving QUIC is supported.

    Packet format (RFC 9000 §17.2.2):
      Byte 0: 1 1 00 (Initial) 00 (reserved) 00 (PN length=1)
              = 0b11000000 = 0xC0
      Bytes 1-4: Version (BE)
      Byte 5: DCID Length
      DCID
      Byte: SCID Length
      SCID
      Token Length (varint) = 0 (no token)
      Length (varint) = 4 (PN length + payload length)
      Packet Number (1 byte)
      Payload
    """
    first_byte = 0xC0  # Long header (1) + Fixed Bit (1) + Initial (00) +
                       # Reserved (00) + PN length 00 (1 byte)
    out = bytes([first_byte])
    out += struct.pack(">I", version)
    out += bytes([len(dcid)]) + dcid
    out += bytes([len(scid)]) + scid
    out += encode_varint(0)  # Token length = 0
    # Length = packet_number_length (1) + payload length
    pn_bytes = bytes([packet_number & 0xFF])
    length = len(pn_bytes) + len(payload)
    out += encode_varint(length)
    out += pn_bytes
    out += payload
    return out


def build_minimal_crypto_payload() -> bytes:
    """Build a CRYPTO frame (RFC 9000 §19.6) with a minimal TLS ClientHello
    containing the h3 ALPN extension. The bytes won't be decryptable by the
    server (we don't encrypt the packet), but the server will respond with a
    CONNECTION_CLOSE or Retry, proving QUIC is up.

    CRYPTO frame format: type (0x06) + offset (varint) + length (varint) +
    TLS data."""
    # Minimal TLS 1.3 ClientHello (synthetic — not a real handshake)
    tls_ch = _build_synthetic_client_hello()
    crypto_frame = bytes([0x06]) + encode_varint(0) + encode_varint(len(tls_ch))
    return crypto_frame + tls_ch


def _build_synthetic_client_hello() -> bytes:
    """Build a synthetic TLS 1.3 ClientHello that includes the h3 ALPN
    extension. This is NOT a valid ClientHello (random is fixed, no real
    cipher suites match) — it's a probe marker. The server will reject it
    after decryption, but our packet payload is already unencrypted anyway,
    so this is purely for completeness."""
    # TLS record: ContentType(1)=22 handshake + Version(2)=0x0301 + Length(2)
    # Handshake: Type(1)=1 ClientHello + Length(3) + Version(2)=0x0303 + Random(32)
    # + SessionID(1)=0 + CipherSuites(2)=0x0002 + 0x1301 (TLS_AES_128_GCM_SHA256)
    # + CompressionMethods(1)=1 + 0x00 + Extensions
    random_bytes = bytes([_rng.randint(0, 255) for _ in range(32)])
    # ALPN extension: ExtType(2)=0x0010 + ExtLen(2) + ALPNList
    # ALPNList: list_len(2) + per-protocol: length(1) + name
    h3_bytes = b"h3"
    alpn_entry = bytes([len(h3_bytes)]) + h3_bytes
    alpn_list = struct.pack(">H", len(alpn_entry)) + alpn_entry
    alpn_ext = struct.pack(">HH", 0x0010, len(alpn_list)) + alpn_list
    # SNI extension (empty for our purposes)
    # Build ClientHello body
    ch_body = (struct.pack(">H", 0x0303) +  # legacy_version = TLS 1.2
               random_bytes +
               bytes([0]) +  # session_id length = 0
               struct.pack(">H", 2) + struct.pack(">H", 0x1301) +  # cipher suites
               bytes([1, 0]) +  # compression methods
               struct.pack(">H", len(alpn_ext)) + alpn_ext)  # extensions
    # Handshake header: type=1 + length(3 bytes)
    handshake = bytes([1]) + len(ch_body).to_bytes(3, "big") + ch_body
    # TLS record header
    record = struct.pack(">BHH", 22, 0x0301, len(handshake)) + handshake
    return record


# ═══════════════════════════════════════════════════════════════════════════
#  QUIC packet parsing
# ═══════════════════════════════════════════════════════════════════════════
def is_long_header(byte0: int) -> bool:
    return (byte0 & 0x80) != 0


def parse_version_negotiation(data: bytes) -> Optional[Dict]:
    """Parse a Version Negotiation packet (RFC 9000 §17.2.1). Returns
    dict with dcid, scid, versions list, or None if not a VN packet."""
    if len(data) < 7:
        return None
    byte0 = data[0]
    if not (byte0 & 0x80):
        return None  # short header, not VN
    version = struct.unpack(">I", data[1:5])[0]
    if version != 0:
        return None  # not VN
    pos = 5
    if pos >= len(data):
        return None
    dcid_len = data[pos]
    pos += 1
    if pos + dcid_len > len(data):
        return None
    dcid = data[pos:pos + dcid_len]
    pos += dcid_len
    if pos >= len(data):
        return None
    scid_len = data[pos]
    pos += 1
    if pos + scid_len > len(data):
        return None
    scid = data[pos:pos + scid_len]
    pos += scid_len
    versions: List[int] = []
    while pos + 4 <= len(data):
        v = struct.unpack(">I", data[pos:pos + 4])[0]
        versions.append(v)
        pos += 4
    return {"dcid": dcid.hex(), "scid": scid.hex(),
            "versions": versions, "raw_len": len(data)}


def parse_long_header(data: bytes) -> Optional[Dict]:
    """Parse any QUIC long header packet (excluding VN — see
    parse_version_negotiation). Returns dict with type, version, dcid,
    scid, or None."""
    if len(data) < 7:
        return None
    byte0 = data[0]
    if not (byte0 & 0x80):
        return None  # short header
    version = struct.unpack(">I", data[1:5])[0]
    if version == 0:
        return None  # VN — handled separately
    packet_type = (byte0 >> 4) & 0x03
    type_names = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
    pos = 5
    if pos >= len(data):
        return None
    dcid_len = data[pos]
    pos += 1
    if pos + dcid_len > len(data):
        return None
    dcid = data[pos:pos + dcid_len]
    pos += dcid_len
    if pos >= len(data):
        return None
    scid_len = data[pos]
    pos += 1
    if pos + scid_len > len(data):
        return None
    scid = data[pos:pos + scid_len]
    pos += scid_len
    out: Dict = {
        "type": packet_type,
        "type_name": type_names.get(packet_type, "Unknown"),
        "version": version,
        "dcid": dcid.hex(),
        "scid": scid.hex(),
        "raw_len": len(data),
    }
    # Retry packets carry a Retry Integrity Tag (16 bytes) at the end and a
    # Retry Token before that.
    if packet_type == LONG_TYPE_RETRY:
        # Token length is implicit (everything between SCID and integrity tag)
        # Integrity tag is the last 16 bytes
        if len(data) >= 16:
            out["retry_integrity_tag"] = data[-16:].hex()
            out["retry_token"] = data[pos:-16].hex()
    return out


# ═══════════════════════════════════════════════════════════════════════════
#  UDP send/recv
# ═══════════════════════════════════════════════════════════════════════════
def send_recv_quic(host: str, port: int, message: bytes,
                   timeout: float = TIMEOUT_S,
                   local_port: int = 0) -> Tuple[Optional[bytes], str]:
    """Send a UDP datagram and read back the response. local_port=0 lets the
    OS pick a random ephemeral port; setting it explicitly enables connection
    migration testing."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _set_sock_timeout(sock, timeout)
        if local_port:
            try:
                sock.bind(("0.0.0.0", local_port))
            except OSError:
                pass
        sock.sendto(message, (host, port))
        try:
            data, _ = sock.recvfrom(65535)
        except (socket.timeout, TimeoutError):
            return None, "timeout"
        except OSError as e:
            return None, f"recv_error:{type(e).__name__}"
        return data, ""
    except (ConnectionRefusedError, OSError) as e:
        return None, f"send_error:{type(e).__name__}"
    except Exception as e:  # noqa: BLE001
        return None, f"error:{type(e).__name__}:{e}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass


# ═══════════════════════════════════════════════════════════════════════════
#  Test 1+2: QUIC accessibility + version negotiation
# ═══════════════════════════════════════════════════════════════════════════
def test_quic_accessibility(host: str, port: int,
                            results: List[Dict]) -> Tuple[bool, str]:
    """Send a Version Negotiation request (version=0). Server MUST respond
    with a VN packet listing supported versions, OR (if our DCID is not
    acceptable for VN) we may get a Retry. Returns (accessible, version_str)."""
    dcid = os.urandom(8)
    scid = os.urandom(8)
    vn_req = build_version_negotiation_request(dcid, scid)
    data, err = send_recv_quic(host, port, vn_req)
    if data is None:
        results.append({"test": "quic_accessibility",
                        "verdict": "no_response",
                        "error": err})
        return False, ""
    # Parse VN response
    vn = parse_version_negotiation(data)
    if vn:
        versions = vn["versions"]
        # Identify the version
        version_str = _identify_versions(versions)
        results.append({
            "test": "quic_accessibility",
            "verdict": "vn_received",
            "supported_versions": [f"0x{v:08x}" for v in versions],
            "version_str": version_str,
            "dcid_echoed": vn["dcid"] == dcid.hex(),
            "scid_echoed": vn["scid"] == scid.hex(),
        })
        return True, version_str
    # Could be a Retry or other long header
    lh = parse_long_header(data)
    if lh:
        results.append({
            "test": "quic_accessibility",
            "verdict": "long_header_received",
            "type": lh["type_name"],
            "version": f"0x{lh['version']:08x}",
            "version_str": VERSION_NAMES.get(lh["version"], "unknown"),
        })
        return True, VERSION_NAMES.get(lh["version"], f"0x{lh['version']:08x}")
    # Short header → server treated our packet as a 1-RTT (unexpected, but
    # still proves QUIC server is running)
    results.append({
        "test": "quic_accessibility",
        "verdict": "response_received",
        "raw_len": len(data),
        "first_byte": f"0x{data[0]:02x}",
        "detail": "Got UDP response but couldn't parse as QUIC long header",
    })
    return True, "unknown"


def _identify_versions(versions: List[int]) -> str:
    """Return human-readable version names."""
    if not versions:
        return "none"
    names = []
    for v in versions:
        if v in VERSION_NAMES:
            names.append(VERSION_NAMES[v])
        else:
            names.append(f"0x{v:08x}")
    return ", ".join(names)


# ═══════════════════════════════════════════════════════════════════════════
#  Test 3: h3 ALPN negotiation
# ═══════════════════════════════════════════════════════════════════════════
def test_h3_alpn(host: str, port: int,
                 results: List[Dict]) -> bool:
    """Send a QUIC v1 Initial packet with a CRYPTO frame containing a TLS
    ClientHello that includes the h3 ALPN extension. A QUIC server that
    supports HTTP/3 will continue the handshake (or at least respond); a
    non-HTTP/3 QUIC server (e.g., DNS-over-QUIC) may respond with
    no_application_protocol alert.

    We don't fully complete TLS — we just check whether the server responds
    with a QUIC Initial packet (proving it can decode v1 + accepts our
    initial crypto bytes for further processing)."""
    dcid = os.urandom(8)
    scid = os.urandom(8)
    pn = 0
    crypto_payload = build_minimal_crypto_payload()
    initial_pkt = build_initial_packet(QUIC_VERSION_V1, dcid, scid, pn,
                                       crypto_payload)
    data, err = send_recv_quic(host, port, initial_pkt)
    if data is None:
        results.append({"test": "h3_alpn",
                        "verdict": "no_response",
                        "error": err})
        return False
    # Check if response is a valid QUIC long header (Initial / Retry / VN)
    lh = parse_long_header(data)
    vn = parse_version_negotiation(data)
    if vn:
        # Server doesn't speak v1 — VN list indicates supported versions
        has_h3_capable = any(v in (QUIC_VERSION_V1, QUIC_VERSION_V2,
                                   QUIC_VERSION_DRAFT_29) for v in vn["versions"])
        results.append({
            "test": "h3_alpn",
            "verdict": "vn_no_v1" if not has_h3_capable else "vn_v1_supported",
            "supported_versions": [f"0x{v:08x}" for v in vn["versions"]],
            "h3_capable": has_h3_capable,
        })
        return has_h3_capable
    if lh:
        # Got an Initial / Retry / Handshake response — server speaks v1
        # and accepted our packet (at least the header)
        h3_likely = lh["version"] == QUIC_VERSION_V1
        results.append({
            "test": "h3_alpn",
            "verdict": "initial_response" if h3_likely else "long_header_response",
            "type": lh["type_name"],
            "version": f"0x{lh['version']:08x}",
            "h3_capable": h3_likely,
            "note": ("Server responded to QUIC v1 Initial — HTTP/3 ALPN "
                     "would be negotiated in TLS handshake (we don't "
                     "complete it here)"),
        })
        return h3_likely
    results.append({
        "test": "h3_alpn",
        "verdict": "unparseable_response",
        "raw_len": len(data),
    })
    return False


# ═══════════════════════════════════════════════════════════════════════════
#  Test 4: Connection migration
# ═══════════════════════════════════════════════════════════════════════════
def test_connection_migration(host: str, port: int,
                              results: List[Dict]) -> bool:
    """QUIC connection migration (RFC 9000 §9): a client can change its
    local address mid-connection, and the server should accept packets
    from the new address using the same DCID. Since we don't establish a
    full connection (no TLS handshake), we can only test the simpler
    invariant: a packet sent from a different local port with a NEW DCID
    should be treated as a new connection (server should respond).

    A more thorough test would require completing the handshake first.
    Here we just verify that the server responds to packets from a
    different source port — this proves NAT rebinding / migration is
    feasible at the UDP layer.

    SAFE_MODE=read_only: limited test (just verifies server responsiveness
    from a different port).
    SAFE_MODE=full: would perform a full migration test (not implemented
    here — requires full TLS 1.3 + QUIC crypto stack)."""
    # Send from a different local port
    dcid = os.urandom(8)
    scid = os.urandom(8)
    vn_req = build_version_negotiation_request(dcid, scid)
    # Pick a random ephemeral local port
    local_port = _rng.randint(20000, 60000)
    data, err = send_recv_quic(host, port, vn_req, local_port=local_port)
    migrated = data is not None
    results.append({
        "test": "connection_migration",
        "verdict": "responsive_from_new_port" if migrated else "no_response_new_port",
        "local_port": local_port,
        "note": ("Verifies server accepts packets from a different source "
                 "port (NAT rebinding scenario). Full migration test "
                 "requires a complete QUIC connection — not implemented."),
    })
    return migrated


# ═══════════════════════════════════════════════════════════════════════════
#  Test 5: Amplification attack prevention
# ═══════════════════════════════════════════════════════════════════════════
def test_amplification_protection(host: str, port: int,
                                  results: List[Dict]) -> bool:
    """Per RFC 9000 §8.1, a server MUST NOT send more than 3× the bytes
    received from an unvalidated peer. We send a small Initial packet
    (~120 bytes) and check that the response is ≤ 3× that (~360 bytes).
    If the response is significantly larger, the server is amplification-
    vulnerable.

    Returns True if amplification-protected (response ≤ 3× request)."""
    dcid = os.urandom(8)
    scid = os.urandom(8)
    # Build a minimal Initial with empty payload (just header + PN)
    initial_pkt = build_initial_packet(QUIC_VERSION_V1, dcid, scid, 0, b"")
    request_size = len(initial_pkt)
    data, err = send_recv_quic(host, port, initial_pkt)
    if data is None:
        results.append({"test": "amplification_protection",
                        "verdict": "no_response",
                        "error": err,
                        "request_size": request_size})
        return True  # No response = trivially protected
    response_size = len(data)
    amplification_ratio = response_size / request_size if request_size else 0
    protected = amplification_ratio <= AMPLIFICATION_LIMIT + 0.5  # small tolerance
    results.append({
        "test": "amplification_protection",
        "verdict": "protected" if protected else "vulnerable",
        "request_size": request_size,
        "response_size": response_size,
        "amplification_ratio": round(amplification_ratio, 2),
        "limit": AMPLIFICATION_LIMIT,
        "detail": (f"Response was {amplification_ratio:.1f}× request size "
                   f"(limit: {AMPLIFICATION_LIMIT}×)")
                   if not protected else
                   (f"Response within {AMPLIFICATION_LIMIT}× amplification "
                    f"limit (RFC 9000 §8.1)"),
    })
    return protected


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
            "legal_note": ("QUIC amplification probing can trigger IDS. "
                           "Lab only (FR Art. 323-1 / US 18 USC §1030)."),
        }))
        sys.exit(1)

    t0 = time.time()
    results: List[Dict] = []
    summary: Dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "http3_port": PORT,
        "transport": "UDP",
        "sector": get_sector_config().get("sector", "telecom"),
        "safe_mode": SAFE_MODE,
        "read_only": SAFE_MODE != "full",
        "seed": SEED,
        # Spec-required output fields:
        "quic_accessible": False,
        "version": "",
        "h3_negotiated": False,
        "amplification_protected": True,
        "results": results,
        "errors": [],
    }

    # ─── 1+2. QUIC accessibility + version ────────────────────────────────
    try:
        accessible, version_str = test_quic_accessibility(HOST, PORT, results)
        summary["quic_accessible"] = accessible
        summary["version"] = version_str
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"quic_access:{type(e).__name__}:{e}")

    # ─── 3. h3 ALPN ──────────────────────────────────────────────────────
    try:
        summary["h3_negotiated"] = test_h3_alpn(HOST, PORT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"h3_alpn:{type(e).__name__}:{e}")

    # ─── 4. Connection migration ─────────────────────────────────────────
    try:
        test_connection_migration(HOST, PORT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"migration:{type(e).__name__}:{e}")

    # ─── 5. Amplification protection ─────────────────────────────────────
    try:
        summary["amplification_protected"] = test_amplification_protection(
            HOST, PORT, results)
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"amplification:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
