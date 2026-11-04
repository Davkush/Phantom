#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — opcua_probe (OT protocol module)
# Read-only OPC-UA binary probe for SCADA/ICS validation.
#
# Default port: 4840 (OPC-UA binary, IANA-assigned).
# Stack: TCP → OPC-UA binary message (HEL → ACK → OpenSecureChannel →
#        GetEndpoints → Browse / Read).
#
# Probes performed (ALL read-only — no Write/Call/Method/Subscribe-CREATE
# with write semantics):
#   1. Send OPC-UA Hello (HEL) message        → check ACK → opcua_accessible
#   2. GetEndpoints (OpenSecureChannel-free)  → auth_mode, security policies
#      (we attempt this with raw socket; if a library is available we use it
#       for deeper enumeration)
#   3. If asyncua/opcua library is available:
#        - connect, read Server.ServerStatus
#        - browse the root Objects folder → nodes_browsable
#      If not available: report library_not_installed hint and fall back to
#      raw-socket HEL only.
#
# The critical security finding this module surfaces is SecurityPolicy None
# + anonymous identity → CRITICAL per IEC 62443.
#
# OPC-UA binary message format (HEL, from OPC-UA Part 6 §6.7.2):
#   MessageType(3, ASCII "HEL") | ChunkType(1, 'F' final) | MessageSize(4, LE)
#   | ProtocolVersion(4, LE) | ReceiveBufferSize(4, LE)
#   | SendBufferSize(4, LE)  | MaxMessageSize(4, LE)
#   | MaxChunkCount(4, LE)   | EndpointUrl(4, LE len + n bytes incl. null)
#
# Reproducibility: SEED not directly used here (HEL is deterministic).
#
# Legal: isolated lab only (NERC CIP / IEC 62443 / NIS2).
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

from sector_base import get_sector_config  # noqa: E402

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "opcua_probe"
DEFAULT_PORT = 4840
TIMEOUT_S = 5.0

# ─── Optional OPC-UA library import (graceful degrade) ────────────────────
OPCUA_LIBRARY = None
try:
    import opcua  # type: ignore  # legacy sync opcua library
    OPCUA_LIBRARY = "opcua"
except ImportError:
    try:
        import asyncua  # type: ignore  # modern async asyncua library
        OPCUA_LIBRARY = "asyncua"
    except ImportError:
        OPCUA_LIBRARY = None

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

SEED = int(os.environ.get("SEED", "1337"))

SECTOR_CFG = get_sector_config()
SAFE_MODE = SECTOR_CFG.get("safe_mode", "read_only")


# ═══════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET OPC-UA HEL PROBE
# ═══════════════════════════════════════════════════════════════════════════
def build_opcua_hello(endpoint_url: str = "opc.tcp://127.0.0.1:4840",
                      proto_version: int = 0,
                      recv_buf: int = 0xFFFF, send_buf: int = 0xFFFF,
                      max_msg: int = 0xFFFF, max_chunks: int = 0xFF) -> bytes:
    """Construct an OPC-UA Hello (HEL) message.

    Layout (all integers little-endian, OPC-UA binary spec Part 6 §6.7.2):
      "HEL" (3 ASCII) | "F" (final chunk) | MessageSize (4, LE, total)
      | ProtocolVersion (4) | ReceiveBufferSize (4) | SendBufferSize (4)
      | MaxMessageSize (4) | MaxChunkCount (4)
      | EndpointUrl length (4) | EndpointUrl bytes (incl. null)
    """
    url_bytes = endpoint_url.encode("utf-8") + b"\x00"
    # Pad URL to multiple of 4 bytes? OPC-UA uses length-prefixed strings,
    # no alignment requirement for HEL endpoint URL specifically.
    body = struct.pack("<IIIII", proto_version, recv_buf, send_buf,
                       max_msg, max_chunks)
    body += struct.pack("<I", len(url_bytes)) + url_bytes
    # Total message size = header(8) + body
    msg_size = 8 + len(body)
    msg = b"HEL" + b"F" + struct.pack("<I", msg_size) + body
    return msg


def parse_opcua_ack(data: bytes) -> dict:
    """Parse an OPC-UA Acknowledge (ACK) message.

    ACK layout: "ACK" | "F" | MessageSize(4) | ProtocolVersion(4)
                | ReceiveBufferSize(4) | SendBufferSize(4)
                | MaxMessageSize(4) | MaxChunkCount(4)
    """
    out = {"ack": False, "protocol_version": None, "recv_buf": None,
           "send_buf": None, "max_msg": None, "max_chunks": None,
           "error": None}
    if len(data) < 8:
        out["error"] = "short_ack"; return out
    if data[:3] != b"ACK":
        # Could be an ERR message
        if data[:3] == b"ERR":
            # ERR layout: "ERR" | "F" | size(4) | error(4) | reason(len-prefixed)
            out["error"] = "opcua_error_message"
            if len(data) >= 16:
                err_code = struct.unpack("<I", data[8:12])[0]
                out["error"] = f"opcua_err:0x{err_code:08X}"
            return out
        out["error"] = f"unexpected_msg_type:{data[:3]!r}"
        return out
    # Full ACK = 8 + 20 = 28 bytes
    if len(data) < 28:
        out["error"] = "truncated_ack"; return out
    (_proto, recv_b, send_b, max_m, max_c) = struct.unpack("<IIIII", data[8:28])
    out.update({"ack": True, "protocol_version": _proto,
                "recv_buf": recv_b, "send_buf": send_b,
                "max_msg": max_m, "max_chunks": max_c})
    return out


def send_opcua_hello(host: str, port: int, endpoint: str,
                     timeout: float = TIMEOUT_S) -> dict:
    """Send a HEL message and wait for an ACK.

    Returns {opcua_accessible, ack, error}.
    """
    out = {"opcua_accessible": False, "ack": None, "error": None}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            sock.sendall(build_opcua_hello(endpoint_url=endpoint))
            # Read at least the 8-byte header first to determine full length
            hdr = b""
            while len(hdr) < 8:
                chunk = sock.recv(8 - len(hdr))
                if not chunk:
                    break
                hdr += chunk
            if len(hdr) < 8:
                out["error"] = "no_response"
                return out
            msg_size = struct.unpack("<I", hdr[4:8])[0]
            remaining = msg_size - 8
            body = b""
            while remaining > 0 and len(body) < remaining:
                chunk = sock.recv(remaining - len(body))
                if not chunk:
                    break
                body += chunk
            full = hdr + body
            ack = parse_opcua_ack(full)
            out["ack"] = ack
            out["opcua_accessible"] = bool(ack.get("ack"))
            if ack.get("error"):
                out["error"] = ack["error"]
        finally:
            sock.close()
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except ConnectionRefusedError:
        out["error"] = "connection_refused"
    except OSError as e:
        out["error"] = f"conn_error:{type(e).__name__}"
    except Exception as e:
        out["error"] = f"{type(e).__name__}:{e}"
    return out


# ═══════════════════════════════════════════════════════════════════════════
#  LIBRARY-BASED DEEP PROBE (optional, requires opcua/asyncua)
# ═══════════════════════════════════════════════════════════════════════════
def deep_probe_with_library(host: str, port: int,
                             timeout: float = TIMEOUT_S) -> dict:
    """Use opcua/asyncua to read Server.ServerStatus + browse Objects folder.

    Returns {server_status, nodes_browsable, endpoints, auth_mode, error}.
    """
    out = {"server_status": None, "nodes_browsable": False,
           "endpoints": [], "auth_mode": None, "security_policies": [],
           "error": None}
    endpoint = f"opc.tcp://{host}:{port}"

    if OPCUA_LIBRARY == "opcua":
        try:
            client = opcua.Client(endpoint, timeout=timeout)
            client.connect()
            try:
                # Server.ServerStatus
                try:
                    status_node = client.get_node("i=2256")  # Server.ServerStatus
                    status_val = status_node.get_value()
                    out["server_status"] = str(status_val)
                except Exception as e:
                    out["server_status"] = f"read_error:{type(e).__name__}"
                # GetEndpoints → auth modes + security policies
                try:
                    eps = client.get_endpoints()
                    auth_modes = set()
                    policies = set()
                    for ep in eps:
                        pol = getattr(ep, "SecurityPolicyUri", "") or ""
                        policies.add(str(pol))
                        for tok in (getattr(ep, "UserIdentityTokens", None) or []):
                            tt = getattr(tok, "TokenType", None)
                            if tt == 0:
                                auth_modes.add("None")
                            elif tt == 1:
                                auth_modes.add("Username")
                            elif tt == 2:
                                auth_modes.add("Certificate")
                            elif tt == 3:
                                auth_modes.add("IssuedToken")
                    out["security_policies"] = sorted(policies)
                    out["auth_mode"] = sorted(auth_modes) or ["None"]
                    out["endpoints"] = [str(getattr(ep, "EndpointUrl", ""))
                                        for ep in eps]
                except Exception as e:
                    out["error"] = f"endpoints:{type(e).__name__}:{e}"
                # Browse Objects (id=85) → nodes_browsable
                try:
                    objects = client.get_node("i=85")  # ObjectsFolder
                    children = objects.get_children()
                    out["nodes_browsable"] = bool(children)
                except Exception as e:
                    out["nodes_browsable"] = False
            finally:
                try:
                    client.disconnect()
                except Exception:
                    pass
        except Exception as e:
            out["error"] = f"opcua_lib:{type(e).__name__}:{e}"
        return out

    if OPCUA_LIBRARY == "asyncua":
        # We can't run async code synchronously without an event loop.
        # Use asyncio.run to invoke the async API.
        import asyncio
        async def _probe() -> dict:
            res = {"server_status": None, "nodes_browsable": False,
                   "endpoints": [], "auth_mode": None,
                   "security_policies": [], "error": None}
            client = asyncua.Client(endpoint)
            try:
                await client.connect()
                try:
                    try:
                        st = await client.get_node("i=2256").read_value()
                        res["server_status"] = str(st)
                    except Exception as e:
                        res["server_status"] = f"read_error:{type(e).__name__}"
                    try:
                        eps = await client.get_endpoints()
                        auth_modes = set()
                        policies = set()
                        for ep in eps:
                            pol = getattr(ep, "SecurityPolicyUri", "") or str(ep.SecurityPolicyUri)
                            policies.add(str(pol))
                            for tok in ep.UserIdentityTokens:
                                tt = getattr(tok, "TokenType", None)
                                if tt == 0:   auth_modes.add("None")
                                elif tt == 1: auth_modes.add("Username")
                                elif tt == 2: auth_modes.add("Certificate")
                                elif tt == 3: auth_modes.add("IssuedToken")
                        res["security_policies"] = sorted(policies)
                        res["auth_mode"] = sorted(auth_modes) or ["None"]
                        res["endpoints"] = [str(ep.EndpointUrl) for ep in eps]
                    except Exception as e:
                        res["error"] = f"endpoints:{type(e).__name__}:{e}"
                    try:
                        objs = client.get_node("i=85")
                        children = await objs.get_children()
                        res["nodes_browsable"] = bool(children)
                    except Exception as e:
                        res["nodes_browsable"] = False
                finally:
                    try:
                        await client.disconnect()
                    except Exception:
                        pass
            except Exception as e:
                res["error"] = f"asyncua_lib:{type(e).__name__}:{e}"
            return res
        try:
            return asyncio.run(_probe())
        except Exception as e:
            out["error"] = f"asyncio:{type(e).__name__}:{e}"
            return out

    out["error"] = "library_not_installed"
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
        "read_only": True,
        "safe_mode": SAFE_MODE,
        "library": OPCUA_LIBRARY or "raw_socket",
        "device_identified": False,
        "opcua_accessible": False,
        "auth_mode": None,
        "server_status": None,
        "nodes_browsable": False,
        "results": {},
        "errors": [],
    }

    endpoint = f"opc.tcp://{HOST}:{PORT}"

    # 1. HEL → ACK probe (raw socket, always attempted)
    try:
        hel = send_opcua_hello(HOST, PORT, endpoint, timeout=TIMEOUT_S)
        summary["opcua_accessible"] = bool(hel.get("opcua_accessible"))
        summary["results"]["hello_ack"] = {
            "ack": hel.get("ack"), "error": hel.get("error"),
        }
        if hel.get("error"):
            summary["errors"].append(f"hello:{hel['error']}")
    except Exception as e:
        summary["errors"].append(f"hello:{type(e).__name__}:{e}")

    # If OPC-UA TCP is up, attempt deep probe via library
    if summary["opcua_accessible"]:
        if OPCUA_LIBRARY is None:
            # Surface the library hint but keep raw-socket result usable
            summary["results"]["library_hint"] = {
                "error": "library_not_installed",
                "hint": "pip install asyncua  # or: pip install opcua",
            }
            # Best-effort: try to derive auth_mode from raw GetEndpoints
            # (too complex without a full SecureChannel — we leave it None).
            summary["auth_mode"] = "unknown"
        else:
            try:
                deep = deep_probe_with_library(HOST, PORT, timeout=TIMEOUT_S)
                summary["server_status"]  = deep.get("server_status")
                summary["nodes_browsable"] = bool(deep.get("nodes_browsable"))
                summary["auth_mode"]       = deep.get("auth_mode")
                summary["results"]["deep_probe"] = {
                    "endpoints": deep.get("endpoints"),
                    "security_policies": deep.get("security_policies"),
                    "error": deep.get("error"),
                }
                if deep.get("error"):
                    summary["errors"].append(f"deep:{deep['error']}")
            except Exception as e:
                summary["errors"].append(f"deep:{type(e).__name__}:{e}")

        # device_identified = OPC-UA responded to HEL OR has a non-null
        # server_status / endpoints list
        summary["device_identified"] = bool(
            summary["opcua_accessible"] or summary["server_status"]
        )

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
