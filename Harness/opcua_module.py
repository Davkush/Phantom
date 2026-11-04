#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — opcua_probe
# OT/ICS validation module — OPC-UA binary protocol probing.
#
#   - Default port : 4840 (OPC-UA binary)
#   - Functions    : get_endpoints (GetEndpoints → security policies list),
#                    check_anonymous (SecurityPolicy.None + Anonymous),
#                    browse_root (browse Objects/Server folder),
#                    read_node (read Server.ServerStatus.CurrentTime, i=2258)
#   - Uses asyncua (opcua-asyncio) if installed, else falls back to a raw
#     socket implementation of Hello + GetEndpoints (no browse/read without
#     the library — those endpoints are reported as "library_not_available").
#   - LAB=1 mandatory. Timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (OT) : NERC CIP, NIS2, IEC 62443.
import asyncio
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
    is_write_allowed,
    get_safe_mode,
)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "opcua_probe"
DEFAULT_PORT = 4840
TIMEOUT_S = 5.0
OPCUA_NS = "http://opcfoundation.org/UA/"

# ─── Optional asyncua import (graceful degrade) ──────────────────────────
ASYNCUA_AVAILABLE = False
try:
    import asyncua  # type: ignore
    ASYNCUA_AVAILABLE = True
except ImportError:
    try:
        from opcua import Client as _SyncClient  # type: ignore  # legacy opcua-py
        ASYNCUA_AVAILABLE = True
        asyncua = None  # mark as legacy-sync
    except ImportError:
        asyncua = None

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

ENDPOINT_URL = f"opc.tcp://{HOST}:{PORT}"

# ─── LAB guard ─────────────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"

# ─── Sector / SAFE_MODE config ─────────────────────────────────────────────
SECTOR_CFG = get_sector_config()
SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")


# ═══════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET OPC-UA TRANSPORT (fallback for Hello + GetEndpoints)
# ═══════════════════════════════════════════════════════════════════════════
# OPC-UA binary framing on TCP:
#   MessageType(3) + ChunkType(1) + MessageSize(uint32 LE) + payload
# Hello (HEL)  : ProtocolVersion + RecvBufSize + SendBufSize + MaxMsgSize
#                + MaxChunkCount + EndpointUrl (uint32 LE length + bytes)
# Acknowledge (ACK) : same numeric fields as Hello (server reply)
# Error (ERR)       : same prefix + Error(uint32) + Reason(string)
#
# After Hello+Ack, full secure-channel/open/getendpoints requires
# asymmetric encoding & X.509 — that's only done via asyncua. The raw
# socket fallback below implements only Hello+Acknowledge and a best-
# effort OpenSecureChannel+GetEndpoints with SecurityPolicy.None (no
# signing/encryption), which works against many test servers.
class OpcuaRawClient:
    """Minimal OPC-UA binary client (raw sockets). Hello → Ack →
    OpenSecureChannel (SecurityPolicy.None) → GetEndpoints."""

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

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

    def __enter__(self) -> "OpcuaRawClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _recvn(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    # ── Hello / Acknowledge ─────────────────────────────────────────────
    def hello(self) -> bool:
        url = ENDPOINT_URL.encode("utf-8")
        payload = struct.pack(
            "<IIIII",
            0,                   # protocol version
            0xFFFF,              # receive buffer size
            0xFFFF,              # send buffer size
            0xFFFF,              # max message size
            0x100,               # max chunk count
        ) + struct.pack("<I", len(url)) + url
        msg = b"HEL" + b"F" + struct.pack("<I", 8 + len(payload)) + payload
        self.sock.sendall(msg)
        # Read response header (8 bytes)
        hdr = self._recvn(8)
        if len(hdr) < 8:
            raise OSError("opcua_short_header")
        msg_type = hdr[0:3]
        if msg_type == b"ACK":
            return True
        if msg_type == b"ERR":
            raise OSError("opcua_server_error")
        raise OSError(f"opcua_unexpected_response:{msg_type.decode('latin-1', errors='replace')}")

    # ── OpenSecureChannel + GetEndpoints (best-effort, no signing) ──────
    def get_endpoints_raw(self) -> list:
        """Send an OpenSecureChannel + GetEndpoints sequence.

        This is a simplified implementation that produces a SecurityPolicy.None
        request without X.509 certificate, and parses the endpoint list from
        the GetEndpoints response. It may fail on strict servers — callers
        should handle the 'library_not_available' fallback.
        """
        # We construct the OPN message (OpenSecureChannel) with no security.
        # ChannelHeader (OPN) :
        #   MessageType="OPN", ChunkType="F", MessageSize(4 LE)
        #   SecureChannelId(4 LE) = 0
        #   SecurityPolicyUri (4 LE length + bytes, prefixed by 4 LE length again?)
        #   SenderCertificate (4 LE length = -1 / 0xFFFFFFFF means empty)
        #   ReceiverCertificateThumbprint (4 LE length = -1 / empty)
        # Then ASYMMETRIC message header:
        #   SequenceNumber(4 LE) + RequestId(4 LE)
        # Then encoded OpenSecureChannelRequest body (binary encoded NodeId +
        # RequestHeader + body fields).

        policy_uri = b"http://opcfoundation.org/UA/SecurityPolicy#None"
        # Body: OpenSecureChannelRequest
        # BinaryNodeId (2-byte form): EncodingDefault=2, NumericNodeId=446
        # → encoded as 0x01 (encoding numeric), then 2-byte namespace 0x0000,
        # then 2-byte identifier 0x01BE (446)
        body = b""
        body += b"\x01\x00\xbe\x01"  # NodeId encoding: NS0, id 446 (OpenSecureChannelRequest)
        # RequestHeader
        body += struct.pack("<I", 0)            # AuthenticationToken (null NodeId = numeric 0)
        body += b"\x00\x00\x00"                  # Timestamp (skipped — min DateTime)
        body += struct.pack("<I", 0)             # RequestHandle
        body += struct.pack("<I", 0)             # ReturnDiagnostics
        body += struct.pack("<I", 0xFFFFFFFF)    # AuditEntryId (null string)
        body += struct.pack("<I", 0xFFFFFFFF)    # TimeoutHint = 0 (we set in OPN)
        # AdditionalHeader (null ExtensionObject)
        body += struct.pack("<I", 0)             # TypeId (null NodeId encoding)
        body += b"\x00"                           # Encoding mask = 0 (no body)
        # OpenSecureChannelRequest body
        body += struct.pack("<I", 0)             # ClientProtocolVersion
        body += struct.pack("<I", 0)             # RequestType: 0 = Issue
        body += struct.pack("<I", 0)             # SecurityMode: 0 = Invalid → use 1 = None
        body = body[:-4] + struct.pack("<I", 1)  # fix SecurityMode → 1 (None)
        body += struct.pack("<I", 0xFFFFFFFF)    # RequestedLifetime (ms) = default
        # Sequence header
        seq = struct.pack("<II", 1, 1)           # SequenceNumber, RequestId
        # Security header (asymmetric, no cert)
        sec = struct.pack("<I", len(policy_uri)) + policy_uri  # SecurityPolicyUri
        sec += struct.pack("<i", -1)             # SenderCertificate (null)
        sec += struct.pack("<i", -1)             # ReceiverCertificateThumbprint (null)
        # Channel header
        payload = struct.pack("<I", 0) + sec + seq + body  # SecureChannelId=0
        msg = b"OPN" + b"F" + struct.pack("<I", 8 + len(payload)) + payload
        try:
            self.sock.sendall(msg)
            self._read_message()  # OPN response (we ignore content)
        except Exception:
            return []

        # GetEndpoints request: NodeId 428 (GetEndpointsRequest)
        ge_body = b""
        ge_body += b"\x01\x00\xac\x01"          # NodeId NS0 id 428
        # RequestHeader
        ge_body += struct.pack("<I", 0)          # AuthenticationToken
        ge_body += b"\x00\x00\x00"                # Timestamp
        ge_body += struct.pack("<I", 1)          # RequestHandle
        ge_body += struct.pack("<I", 0)          # ReturnDiagnostics
        ge_body += struct.pack("<I", 0xFFFFFFFF) # AuditEntryId
        ge_body += struct.pack("<I", 10000)      # TimeoutHint
        ge_body += struct.pack("<I", 0)          # AdditionalHeader (null ExtObject TypeId)
        ge_body += b"\x00"                        # encoding mask = 0
        # GetEndpoints body
        ge_body += struct.pack("<I", 0xFFFFFFFF) # EndpointUrl (null) — server uses its own
        ge_body += struct.pack("<I", 0)          # LocaleIds count = 0
        ge_body += struct.pack("<I", 0)          # ProfileUris count = 0
        seq = struct.pack("<II", 2, 2)
        # Symmetric security header (MSG): TokenId(4 LE) = 0
        sym = struct.pack("<I", 0)
        payload = sym + seq + ge_body
        msg = b"MSG" + b"F" + struct.pack("<I", 8 + len(payload)) + payload
        try:
            self.sock.sendall(msg)
            resp = self._read_message()
        except Exception:
            return []
        return _parse_endpoints_from_message(resp)

    def _read_message(self) -> bytes:
        hdr = self._recvn(8)
        if len(hdr) < 8:
            raise OSError("opcua_short_msg_header")
        size = struct.unpack("<I", hdr[4:8])[0]
        body = self._recvn(size - 8)
        return hdr + body


def _parse_endpoints_from_message(msg: bytes) -> list:
    """Best-effort parse of a GetEndpointsResponse.

    We don't fully decode the OPC-UA binary type system; instead we scan for
    'http://opcfoundation.org/UA/SecurityPolicy#' URI prefixes in the bytes
    and extract the security policy suffix (None, Basic128, Basic256, etc.).
    This works for most plain-text (SecurityPolicy.None) responses.
    """
    policies = set()
    endpoints = []
    idx = 0
    prefix = b"http://opcfoundation.org/UA/SecurityPolicy#"
    while True:
        pos = msg.find(prefix, idx)
        if pos < 0:
            break
        end = msg.find(b"\x00", pos)
        if end < 0:
            end = pos + 80
        suffix = msg[pos + len(prefix):end].decode("latin-1", errors="replace")
        policies.add(suffix)
        endpoints.append({
            "endpoint_url": None,
            "security_policy": f"None#{suffix}" if suffix else "None",
            "security_mode": None,
            "user_token_types": [],
        })
        idx = end + 1
    if not policies:
        return []
    return endpoints


# ═══════════════════════════════════════════════════════════════════════════
#  PROBE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
def get_endpoints() -> dict:
    """GetEndpoints → list of security policies.

    Returns {endpoints_found, security_policies, endpoints, error}.
    """
    result = {
        "endpoints_found": 0,
        "security_policies": [],
        "endpoints": [],
        "error": None,
    }

    if ASYNCUA_AVAILABLE and asyncua is not None:
        async def _run() -> None:
            client = asyncua.Client(ENDPOINT_URL, timeout=TIMEOUT_S)
            try:
                await client.connect()
                eps = await client.get_endpoints()
                policies = []
                endpoints = []
                for ep in eps:
                    pol = str(getattr(ep, "SecurityPolicyUri", "") or "")
                    if pol not in policies:
                        policies.append(pol)
                    tokens = []
                    for tok in (getattr(ep, "UserIdentityTokens", None) or []):
                        tokens.append(str(getattr(tok, "TokenType", "?")))
                    endpoints.append({
                        "endpoint_url": str(getattr(ep, "EndpointUrl", "") or ""),
                        "security_policy": pol,
                        "security_mode": int(getattr(ep, "SecurityMode", 0) or 0),
                        "user_token_types": tokens,
                    })
                result["security_policies"] = policies
                result["endpoints"] = endpoints
                result["endpoints_found"] = len(endpoints)
            finally:
                try:
                    await client.disconnect()
                except Exception:
                    pass
        try:
            asyncio.run(_run())
        except RuntimeError:
            # Fallback for environments where asyncio.run() cannot create a new
            # event loop (e.g. when one is already running in a host process).
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(_run())
            finally:
                loop.close()
        except Exception as e:
            result["error"] = f"asyncua:{type(e).__name__}:{e}"
        return result

    # Legacy opcua-py (sync)
    if ASYNCUA_AVAILABLE and asyncua is None:
        try:
            from opcua import Client as _SyncClient  # type: ignore
            client = _SyncClient(ENDPOINT_URL)
            client.connect()
            try:
                eps = client.get_endpoints()
                policies = []
                endpoints = []
                for ep in eps:
                    pol = str(getattr(ep, "SecurityPolicyUri", "") or "")
                    if pol not in policies:
                        policies.append(pol)
                    tokens = [str(getattr(t, "TokenType", "?"))
                              for t in (getattr(ep, "UserIdentityTokens", None) or [])]
                    endpoints.append({
                        "endpoint_url": str(getattr(ep, "EndpointUrl", "") or ""),
                        "security_policy": pol,
                        "security_mode": int(getattr(ep, "SecurityMode", 0) or 0),
                        "user_token_types": tokens,
                    })
                result["security_policies"] = policies
                result["endpoints"] = endpoints
                result["endpoints_found"] = len(endpoints)
            finally:
                client.disconnect()
        except Exception as e:
            result["error"] = f"opcua_py:{type(e).__name__}:{e}"
        return result

    # Raw socket fallback — Hello + best-effort GetEndpoints
    try:
        with OpcuaRawClient(HOST, PORT, timeout=TIMEOUT_S) as c:
            c.hello()
            eps = c.get_endpoints_raw()
            result["endpoints"] = eps
            result["endpoints_found"] = len(eps)
            result["security_policies"] = sorted({
                e["security_policy"] for e in eps if e.get("security_policy")
            })
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"conn_error:{type(e).__name__}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def check_anonymous() -> dict:
    """Try connecting with SecurityPolicy.None + Anonymous identity.

    Returns {anonymous_access, error}.
    """
    result = {"anonymous_access": False, "error": None}

    if not ASYNCUA_AVAILABLE:
        result["error"] = "library_not_available"
        return result

    if asyncua is not None:
        async def _run() -> None:
            client = asyncua.Client(ENDPOINT_URL, timeout=TIMEOUT_S)
            try:
                await client.connect()
                # If connect() succeeded without explicit identity,
                # asyncua defaults to anonymous → anonymous access granted.
                result["anonymous_access"] = True
            except Exception as e:
                result["error"] = f"asyncua:{type(e).__name__}:{e}"
            finally:
                try:
                    await client.disconnect()
                except Exception:
                    pass
        try:
            asyncio.get_event_loop().run_until_complete(_run())
        except RuntimeError:
            asyncio.run(_run())
        except Exception as e:
            result["error"] = f"asyncua_runtime:{type(e).__name__}:{e}"
        return result

    # Legacy sync opcua-py
    try:
        from opcua import Client as _SyncClient  # type: ignore
        client = _SyncClient(ENDPOINT_URL)
        client.connect()
        result["anonymous_access"] = True
        client.disconnect()
    except Exception as e:
        result["error"] = f"opcua_py:{type(e).__name__}:{e}"
    return result


def browse_root() -> dict:
    """Browse the root folder (if connected).

    Returns {nodes_browsable, nodes, error}.
    """
    result = {"nodes_browsable": False, "nodes": [], "error": None}

    if not ASYNCUA_AVAILABLE:
        result["error"] = "library_not_available"
        return result

    if asyncua is not None:
        async def _run() -> None:
            client = asyncua.Client(ENDPOINT_URL, timeout=TIMEOUT_S)
            try:
                await client.connect()
                root = client.nodes.root
                children = await root.get_children()
                names = []
                for ch in children[:50]:
                    try:
                        bn = await ch.read_browse_name()
                        names.append(str(bn))
                    except Exception:
                        names.append("?")
                result["nodes"] = names
                result["nodes_browsable"] = True
            except Exception as e:
                result["error"] = f"asyncua:{type(e).__name__}:{e}"
            finally:
                try:
                    await client.disconnect()
                except Exception:
                    pass
        try:
            asyncio.run(_run())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(_run())
            finally:
                loop.close()
        except Exception as e:
            result["error"] = f"asyncua_runtime:{type(e).__name__}:{e}"
        return result

    # Legacy sync opcua-py
    try:
        from opcua import Client as _SyncClient  # type: ignore
        client = _SyncClient(ENDPOINT_URL)
        client.connect()
        root = client.get_root_node()
        children = root.get_children()
        names = []
        for ch in children[:50]:
            try:
                names.append(str(ch.get_browse_name()))
            except Exception:
                names.append("?")
        result["nodes"] = names
        result["nodes_browsable"] = True
        client.disconnect()
    except Exception as e:
        result["error"] = f"opcua_py:{type(e).__name__}:{e}"
    return result


def read_node(node_id: str = "i=2258") -> dict:
    """Read a node by Numeric NodeId. Default i=2258 =
    Server.ServerStatus.CurrentTime.

    Returns {sample_read, node_value, node_type, error}.
    """
    result = {"sample_read": False, "node_id": node_id,
              "node_value": None, "node_type": None, "error": None}

    if not ASYNCUA_AVAILABLE:
        result["error"] = "library_not_available"
        return result

    if asyncua is not None:
        async def _run() -> None:
            client = asyncua.Client(ENDPOINT_URL, timeout=TIMEOUT_S)
            try:
                await client.connect()
                node = client.get_node(f"ns=0;{node_id}")
                val = await node.read_value()
                # Coerce to a JSON-serializable form
                if hasattr(val, "isoformat"):
                    val_repr = val.isoformat()
                elif isinstance(val, (int, float, str, bool)):
                    val_repr = val
                else:
                    val_repr = str(val)
                result["node_value"] = val_repr
                result["node_type"] = type(val).__name__
                result["sample_read"] = True
            except Exception as e:
                result["error"] = f"asyncua:{type(e).__name__}:{e}"
            finally:
                try:
                    await client.disconnect()
                except Exception:
                    pass
        try:
            asyncio.run(_run())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(_run())
            finally:
                loop.close()
        except Exception as e:
            result["error"] = f"asyncua_runtime:{type(e).__name__}:{e}"
        return result

    # Legacy sync opcua-py
    try:
        from opcua import Client as _SyncClient  # type: ignore
        from opcua import NodeId  # type: ignore
        client = _SyncClient(ENDPOINT_URL)
        client.connect()
        # Parse "i=2258" into a NodeId
        if node_id.startswith("i="):
            nid = NodeId(int(node_id[2:]))
        else:
            result["error"] = f"unsupported_node_id_format:{node_id}"
            client.disconnect()
            return result
        node = client.get_node(nid)
        val = node.get_value()
        if hasattr(val, "isoformat"):
            val_repr = val.isoformat()
        elif isinstance(val, (int, float, str, bool)):
            val_repr = val
        else:
            val_repr = str(val)
        result["node_value"] = val_repr
        result["node_type"] = type(val).__name__
        result["sample_read"] = True
        client.disconnect()
    except Exception as e:
        result["error"] = f"opcua_py:{type(e).__name__}:{e}"
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
            "legal_note": ("OPC-UA probing on production SCADA is illegal "
                           "outside an authorized lab. NERC CIP / IEC 62443."),
        }))
        sys.exit(1)

    t0 = time.time()
    summary: dict = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": HOST,
        "port": PORT,
        "endpoint": ENDPOINT_URL,
        "sector": SECTOR_CFG.get("sector"),
        "safe_mode": SAFE_MODE,
        "library": ("asyncua" if (ASYNCUA_AVAILABLE and asyncua is not None)
                    else ("opcua-py" if ASYNCUA_AVAILABLE else "raw_socket")),
        "endpoints_found": 0,
        "security_policies": [],
        "anonymous_access": False,
        "nodes_browsable": False,
        "sample_read": False,
        "node_value": None,
        "errors": [],
    }

    # 1. GetEndpoints
    try:
        ep = get_endpoints()
        summary["endpoints_found"] = int(ep.get("endpoints_found", 0))
        summary["security_policies"] = ep.get("security_policies", [])
        if ep.get("error"):
            summary["errors"].append(f"get_endpoints:{ep['error']}")
    except Exception as e:
        summary["errors"].append(f"get_endpoints:{type(e).__name__}:{e}")

    # 2. Anonymous access check
    try:
        anon = check_anonymous()
        summary["anonymous_access"] = bool(anon.get("anonymous_access"))
        if anon.get("error") and anon.get("error") != "library_not_available":
            summary["errors"].append(f"check_anonymous:{anon['error']}")
    except Exception as e:
        summary["errors"].append(f"check_anonymous:{type(e).__name__}:{e}")

    # 3. Browse root (only if library available)
    try:
        br = browse_root()
        summary["nodes_browsable"] = bool(br.get("nodes_browsable"))
        if br.get("error") and br.get("error") != "library_not_available":
            summary["errors"].append(f"browse_root:{br['error']}")
    except Exception as e:
        summary["errors"].append(f"browse_root:{type(e).__name__}:{e}")

    # 4. Read node i=2258 (Server.ServerStatus.CurrentTime)
    try:
        rd = read_node("i=2258")
        summary["sample_read"] = bool(rd.get("sample_read"))
        summary["node_value"] = rd.get("node_value")
        if rd.get("error") and rd.get("error") != "library_not_available":
            summary["errors"].append(f"read_node:{rd['error']}")
    except Exception as e:
        summary["errors"].append(f"read_node:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
