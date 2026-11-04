#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — dnp3_sav5_probe
# Energy sector module — DNP3 Secure Authentication v5 (SAv5, IEEE 1815-2012
# §11 / IEC 60870-6-802). SAv5 is the authentication & authorization layer
# for DNP3 — every "sensitive" application function (READ, OPERATE,
# DIRECT_OPERATE, …) must be preceded by a successful SAv5 challenge /
# response exchange, or the outstation rejects it with
# IIN1.5 = NO_FUNC_CODE_AUTHORIZATION.
#
#   - Default port : 20000 (DNP3 over TCP/IP, IEEE 1815-2012 §9)
#   - Layer stack  : TCP → DNP3 data-link (0x0564 …) → transport →
#                    application (ASDU: AC + FC + IIN + objects)
#                    → SAv5 (group 92, variations 1..10)
#
#   - Probes performed (READ-ONLY — no OPERATE / DIRECT_OPERATE is sent):
#       1. link_status         — link FC=9 (ctrl=0xC9) → link_active
#       2. unauth_class0_read  — application FC=0x01 (READ class 0) WITHOUT
#                                any preceding SAv5 exchange. If the outstation
#                                returns data ⇒ unauthenticated_read_works=True
#                                ⇒ SAv5 NOT enforced. If it returns
#                                IIN1.5=NO_FUNC_AUTH ⇒ SAv5 IS active.
#       3. sa_auth_probe       — application FC=0x21 (AUTHENTICATE REQ) with
#                                group 92 var 1 (Challenge Request). If the
#                                outstation returns a Challenge (var 1) or
#                                Reply (var 2) ⇒ challenge_response=True.
#                                If it returns IIN2.1 NO_FUNC_SUPPORT ⇒ SAv5
#                                not implemented.
#       4. sa_version_detect   — examine the variation of the returned group
#                                92 object:
#                                  var 1 (Challenge) HMAC/AES-GCM      → v5
#                                  var 7 (HMAC-SHA-256 challenge)      → v5
#                                  var 8 (HMAC-SHA-1 challenge)        → v5
#                                  var 9 (AES-128-GCM challenge)       → v5
#                                  var 10 (AES-256-GCM challenge)      → v5
#                                  legacy v2/v3 used 16-byte challenge
#                                  wrapped in DES / 3DES (no var #).
#       5. key_rotation        — heuristic: if the challenge contains a
#                                user-id byte + key-wrap field ⇒ key
#                                rotation is implemented (return True).
#                                v5 mandates session keys with rotation.
#       6. aggressive_mode     — if SAv5 is active AND unauth class0 read
#                                fails immediately (IIN1.5) ⇒ Aggressive
#                                Mode is enabled (pre-authentication
#                                enforcement). If SAv5 is active but
#                                unauth read still returns data ⇒
#                                Aggressive Mode disabled.
#
#   - DNP3 frame: 0x0564 + length(1) + control(1) + dst(2 LE) + src(2 LE)
#                  + header CRC(2 LE) + ≤16-byte data blocks each with their
#                  own 2-byte CRC. CRC-16 poly 0x3D65, init 0x0000, reflected
#                  (= 0xA6BC).
#   - Application: AC(1)=FIR|FIN|CON|UNS|seq + FC(1) + IIN1(1) + IIN2(1)
#                  + object headers.
#
#   - READ_ONLY=True  (energy/OT safety constraint — no OPERATE)
#   - SEED env var    : deterministic application-layer sequence number
#   - LAB=1 mandatory ; 5 s timeout on every socket operation.
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Règlements applicables (energy) : NERC CIP, NIS2, ENISA, IEEE 1815,
#   IEC 62351-3 / -5 / -7 (DNP3 over TLS).
import json
import os
import random
import socket
import struct
import sys
import time
from typing import Dict, List, Optional

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
MODULE_NAME = "dnp3_sav5_probe"
DEFAULT_PORT = 20000
TIMEOUT_S = 5.0
READ_ONLY = True  # OT safety constraint — no OPERATE / DIRECT_OPERATE

# ─── DNP3 link / application constants ─────────────────────────────────────
DNP3_START = b"\x05\x64"                    # link-layer sync bytes

# Link-layer control bytes (DIR=1 PRM=1 from primary)
LINK_CTRL_LINK_STATUS_REQ = 0xC9            # FC=9 Request Link Status
LINK_CTRL_RESET_LINK       = 0xC0           # FC=0 Reset Remote Link
LINK_CTRL_USER_DATA_NO_ACK = 0xC3           # FC=3 Send user data no-ACK

# Application-layer function codes
APP_FC_READ            = 0x01
APP_FC_OPERATE         = 0x02               # WRITE — never sent (READ_ONLY)
APP_FC_DIRECT_OPERATE  = 0x05               # WRITE — never sent (READ_ONLY)
APP_FC_AUTHENTICATE    = 0x21               # SAv5 Authenticate Request
APP_FC_RESPONSE        = 0x81
APP_FC_UNSOLICITED_RSP = 0x82
APP_FC_AUTH_RESPONSE   = 0xA1               # SAv5 Authenticate Response (echo)

# Application control byte (FIR=1, FIN=1, CON=0, UNS=0, seq=0)
APP_AC_REQUEST_FIR_FIN = 0xC0

# Object groups / variations
OBJ_GROUP_CLASS_0    = 0x3C                  # group 60 = static data
OBJ_VAR_CLASS_0      = 0x01
OBJ_GROUP_AUTH       = 0x5C                  # group 92 = SAv5 authentication
OBJ_VAR_AUTH_CHALLENGE = 0x01                # var 1: Challenge
OBJ_VAR_AUTH_REPLY     = 0x02                # var 2: Reply
OBJ_VAR_AUTH_KEYSTATUS = 0x03                # var 3: Session Key Status
OBJ_VAR_AUTH_RSA_CERT  = 0x05                # var 5: RSA Cert
OBJ_VAR_AUTH_ECDSA_CERT = 0x06               # var 6: ECDSA Cert
OBJ_VAR_AUTH_HMAC_SHA256 = 0x07              # var 7: HMAC-SHA-256 challenge
OBJ_VAR_AUTH_HMAC_SHA1   = 0x08              # var 8: HMAC-SHA-1 challenge
OBJ_VAR_AUTH_AES128      = 0x09              # var 9: AES-128-GCM challenge
OBJ_VAR_AUTH_AES256      = 0x0A              # var 10: AES-256-GCM challenge

# SAv5 variations that are uniquely v5 (HMAC / AES-GCM)
SAV5_VARIATIONS = (
    OBJ_VAR_AUTH_HMAC_SHA256,
    OBJ_VAR_AUTH_HMAC_SHA1,
    OBJ_VAR_AUTH_AES128,
    OBJ_VAR_AUTH_AES256,
)

# Qualifier field codes
QUAL_ALL_POINTS  = 0x00                      # all points in object
QUAL_8BIT_STOP   = 0x06                      # 8-bit stop index, no prefix
QUAL_16BIT_STOP  = 0x07                      # 16-bit stop index, no prefix
QUAL_FREE_FORMAT = 0x5B                      # free-format (used for SAv5 challenges)

# IIN (Internal Indications) bits
IIN1_NO_FUNC_AUTH     = 0x20                 # IIN1.5 = NO_FUNC_CODE_AUTHORIZATION
IIN2_NO_FUNC_SUPPORT  = 0x02                 # IIN2.1 = function not supported
IIN2_OBJECT_UNKNOWN   = 0x04                 # IIN2.2 = object unknown
IIN2_PARAM_ERROR      = 0x20                 # IIN2.4 = parameter error
IIN2_NEED_TIME        = 0x08                 # IIN2.3 = time sync needed

# Lab default source/destination DNP3 addresses (configurable via env)
DNP3_SRC = int(os.environ.get("DNP3_SRC", "1"))
DNP3_DST = int(os.environ.get("DNP3_DST", "1"))

# ─── CLI args ──────────────────────────────────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
try:
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
except ValueError:
    PORT = DEFAULT_PORT

# ─── SEED for deterministic app seq ────────────────────────────────────────
_SEED_RAW = os.environ.get("SEED", "")
try:
    SEED = int(_SEED_RAW) if _SEED_RAW.strip() else 1337
except ValueError:
    SEED = 1337
_app_seq_state = {"seq": random.Random(SEED).randint(0, 31)}


def _next_seq() -> int:
    _app_seq_state["seq"] = (_app_seq_state["seq"] + 1) & 0x1F
    return _app_seq_state["seq"]


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
#  CRC-16 (DNP3 — polynomial 0x3D65, reflected = 0xA6BC, init 0x0000)
# ═══════════════════════════════════════════════════════════════════════════
_CRC_TABLE: Optional[List[int]] = None


def _crc_table() -> List[int]:
    global _CRC_TABLE
    if _CRC_TABLE is not None:
        return _CRC_TABLE
    POLY = 0xA6BC    # reflected form of 0x3D65
    table: List[int] = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ POLY
            else:
                crc >>= 1
        table.append(crc)
    _CRC_TABLE = table
    return table


def dnp3_crc(data: bytes) -> int:
    """Compute the DNP3 CRC-16 over `data` (init=0x0000)."""
    table = _crc_table()
    crc = 0x0000
    for b in data:
        crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
    return crc & 0xFFFF


# ═══════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET DNP3 CLIENT (SAv5-focused)
# ═══════════════════════════════════════════════════════════════════════════
class Dnp3SaV5Client:
    """Minimal DNP3 client focused on Secure Authentication v5 probing.

    Builds:
      • Link-only frames  (Link Status)
      • Link + app frames (unauthenticated Class-0 READ, SAv5 AUTHENTICATE)

    All probes are READ-ONLY. No OPERATE / DIRECT_OPERATE frame is ever sent.
    """

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = TIMEOUT_S,
                 src: int = DNP3_SRC, dst: int = DNP3_DST):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.src = src & 0xFFFF
        self.dst = dst & 0xFFFF
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

    def __enter__(self) -> "Dnp3SaV5Client":
        self.connect(); return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- frame builders ----------------------------------------------------
    def _build_link_frame(self, ctrl: int, data: bytes = b"") -> bytes:
        """Build a complete link-layer frame.

        Header (10 B): 0x05 0x64 | len | ctrl | dst(2 LE) | src(2 LE)
        + header CRC(2 LE) + ≤16-byte data blocks each with their own CRC.
        `len` = 5 + len(data) (per IEEE 1815 §5.2).
        """
        length = 5 + len(data)
        if length > 255:
            raise ValueError("DNP3 frame too long")
        header = (
            DNP3_START
            + struct.pack("<BB", length, ctrl)
            + struct.pack("<H", self.dst)
            + struct.pack("<H", self.src)
        )
        header_crc = struct.pack("<H", dnp3_crc(header))
        out = header + header_crc
        if data:
            off = 0
            while off < len(data):
                chunk = data[off:off + 16]
                out += chunk + struct.pack("<H", dnp3_crc(chunk))
                off += 16
        return out

    def _build_app_unauth_class0(self) -> bytes:
        """Build an unauthenticated Class-0 READ application fragment.

        AC = 0xC0 | seq (FIR=1, FIN=1, CON=0, UNS=0)
        FC = 0x01 (READ)
        IIN = 0x00 0x00 (requests have no IIN)
        Object header: group(60) var(1) qualifier(0x06=8-bit stop) stop=0
        """
        ac = APP_AC_REQUEST_FIR_FIN | _next_seq()
        return bytes([ac, APP_FC_READ, 0x00, 0x00,
                      OBJ_GROUP_CLASS_0, OBJ_VAR_CLASS_0,
                      QUAL_8BIT_STOP, 0x00])

    def _build_app_sav5_challenge_request(self) -> bytes:
        """Build a SAv5 AUTHENTICATE-NO-ACK request (FC=0x21).

        Per IEEE 1815-2012 §11.3.1: the master sends an Authenticate Request
        with a Challenge Request object (group 92 var 1) containing the user
        identifier and a challenge length of zero. The outstation MUST reply
        with a Challenge (var 1) or Reply (var 2) carrying a fresh challenge
        value, or set IIN2.1 NO_FUNC_SUPPORT if SAv5 is not implemented.
        """
        ac = APP_AC_REQUEST_FIR_FIN | _next_seq()
        # SAv5 challenge request:
        #   AC + FC + IIN(2) + obj header (group 92 var 1)
        #   qualifier 0x5B (free-format, 16-bit length follows)
        #   challenge-length (2 LE) = 0 → empty challenge (request fresh one)
        #   user-id (1) = 1 (default SAv5 user)
        obj_hdr = bytes([
            OBJ_GROUP_AUTH, OBJ_VAR_AUTH_CHALLENGE,
            QUAL_FREE_FORMAT, 0x00,
        ])
        # Free-format value: a 2-byte length (LE) + a 1-byte user-id
        ff_value = struct.pack("<H", 1) + bytes([0x01])
        return bytes([ac, APP_FC_AUTHENTICATE, 0x00, 0x00]) + obj_hdr + ff_value

    # -- send / recv -------------------------------------------------------
    def _recvn(self, n: int) -> bytes:
        if self.sock is None:
            raise RuntimeError("socket not connected")
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _recv_link_frame(self) -> Dict:
        """Receive one link-layer frame and decode header + payload.

        Returns {ctrl, dst, src, data, valid_crc, error}.
        """
        out: Dict = {"ctrl": None, "dst": None, "src": None,
                     "data": b"", "valid_crc": True, "error": None}
        start = self._recvn(2)
        if start != DNP3_START:
            out["error"] = f"bad_start_bytes:{start.hex()}"
            return out
        length_byte = self._recvn(1)
        if not length_byte:
            out["error"] = "no_length_byte"; return out
        length = length_byte[0]
        rest_hdr = self._recvn(5 + 2)
        if len(rest_hdr) < 7:
            out["error"] = "truncated_header"; return out
        ctrl = rest_hdr[0]
        dst, src = struct.unpack("<HH", rest_hdr[1:5])
        hdr_crc = struct.unpack("<H", rest_hdr[5:7])[0]
        full_hdr = start + length_byte + rest_hdr[:5]
        if dnp3_crc(full_hdr) != hdr_crc:
            out["valid_crc"] = False
        out["ctrl"], out["dst"], out["src"] = ctrl, dst, src
        data_len = length - 5
        if data_len < 0:
            out["error"] = f"bad_length:{length}"; return out
        data = b""
        remaining = data_len
        while remaining > 0:
            blk_len = min(remaining, 16)
            blk = self._recvn(blk_len + 2)
            if len(blk) < blk_len + 2:
                out["error"] = "truncated_data_block"; break
            blk_data = blk[:blk_len]
            blk_crc = struct.unpack("<H", blk[blk_len:])[0]
            if dnp3_crc(blk_data) != blk_crc:
                out["valid_crc"] = False
            data += blk_data
            remaining -= blk_len
        out["data"] = data
        return out

    # -- high-level probes -------------------------------------------------
    def send_link_status(self) -> Dict:
        """Link Status request (link FC=9, ctrl=0xC9)."""
        out: Dict = {"link_active": False, "link_ctrl_recv": None,
                     "valid_crc": True, "error": None}
        try:
            frame = self._build_link_frame(LINK_CTRL_LINK_STATUS_REQ)
            self.sock.sendall(frame)
            resp = self._recv_link_frame()
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"; return out
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"; return out
        except Exception as e:  # noqa: BLE001
            out["error"] = f"{type(e).__name__}:{e}"; return out
        if resp.get("error"):
            out["error"] = resp["error"]; return out
        ctrl_recv = resp.get("ctrl")
        out["link_ctrl_recv"] = ctrl_recv
        out["valid_crc"] = resp.get("valid_crc", True)
        # Secondary Link Status reply: DIR=0 PRM=0, FC=0x0B
        if ctrl_recv is not None and (ctrl_recv & 0x0F) == 0x0B:
            out["link_active"] = True
        else:
            out["error"] = f"unexpected_link_ctrl:0x{(ctrl_recv or 0):02X}"
        return out

    def send_unauth_class0_read(self) -> Dict:
        """Send an unauthenticated Class-0 READ.

        Returns:
          unauthenticated_read_works: True if we got back data (response_fc
          == 0x81 with at least one object header) WITHOUT any auth step.
        """
        out: Dict = {
            "unauthenticated_read_works": False,
            "iin": None, "response_fc": None,
            "auth_required_iin": False, "error": None,
        }
        app = self._build_app_unauth_class0()
        frame = self._build_link_frame(LINK_CTRL_USER_DATA_NO_ACK, data=app)
        try:
            self.sock.sendall(frame)
            resp = self._recv_link_frame()
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"; return out
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"; return out
        except Exception as e:  # noqa: BLE001
            out["error"] = f"{type(e).__name__}:{e}"; return out
        if resp.get("error"):
            out["error"] = resp["error"]; return out
        data = resp.get("data", b"")
        if len(data) < 4:
            out["error"] = "short_app_response"; return out
        _ac, fc, iin1, iin2 = data[0], data[1], data[2], data[3]
        out["iin"] = {"iin1": iin1, "iin2": iin2,
                      "no_func_auth": bool(iin1 & IIN1_NO_FUNC_AUTH),
                      "no_func_support": bool(iin2 & IIN2_NO_FUNC_SUPPORT)}
        out["response_fc"] = fc
        out["auth_required_iin"] = bool(iin1 & IIN1_NO_FUNC_AUTH)
        if fc == APP_FC_RESPONSE and not (iin1 & IIN1_NO_FUNC_AUTH):
            # Got a real Response with data → unauth read succeeded
            # Count object headers as evidence
            n_obj = 0
            idx = 4
            while idx + 4 <= len(data):
                _grp, _var, qf, _ = data[idx], data[idx + 1], data[idx + 2], data[idx + 3]
                n_obj += 1
                idx += 4
                if qf in (0x00, 0x01):
                    idx += 2
                elif qf == 0x06:
                    idx += 1
                elif qf == 0x07:
                    idx += 2
                else:
                    idx += 1
            out["unauthenticated_read_works"] = n_obj > 0
        elif fc == APP_FC_RESPONSE and (iin1 & IIN1_NO_FUNC_AUTH):
            # SAv5 active — read was rejected with NO_FUNC_AUTH
            out["unauthenticated_read_works"] = False
        else:
            out["error"] = f"unexpected_app_fc:0x{fc:02X}"
        return out

    def probe_sav5_challenge(self) -> Dict:
        """Send a SAv5 AUTHENTICATE Challenge Request (FC=0x21).

        Returns:
          challenge_response: True if the outstation returned a group-92
            object (any variation), False otherwise.
          sa_version: "v5" if the variation is in SAV5_VARIATIONS,
                      "legacy_v2v3" if var is 1/2/3 (older DES/3DES-wrap),
                      None if unknown.
          challenge_variation: the variation byte (1..10), or None.
          key_rotation: True if a Session Key Status object (var 3) is
            present in the response, or if the challenge carries a
            user-id + key-wrap field (heuristic for v5 key rotation).
          aggressive_mode: inferred by the caller from this result combined
            with the unauth_read result.
        """
        out: Dict = {
            "challenge_response": False,
            "challenge_variation": None,
            "sa_version": None,
            "key_rotation": False,
            "aggressive_mode": None,   # set by caller
            "iin": None,
            "error": None,
        }
        app = self._build_app_sav5_challenge_request()
        frame = self._build_link_frame(LINK_CTRL_USER_DATA_NO_ACK, data=app)
        try:
            self.sock.sendall(frame)
            resp = self._recv_link_frame()
        except (socket.timeout, TimeoutError):
            out["error"] = "timeout"; return out
        except (ConnectionRefusedError, OSError) as e:
            out["error"] = f"conn_error:{type(e).__name__}"; return out
        except Exception as e:  # noqa: BLE001
            out["error"] = f"{type(e).__name__}:{e}"; return out
        if resp.get("error"):
            out["error"] = resp["error"]; return out
        data = resp.get("data", b"")
        if len(data) < 4:
            out["error"] = "short_app_response"; return out
        _ac, fc, iin1, iin2 = data[0], data[1], data[2], data[3]
        out["iin"] = {"iin1": iin1, "iin2": iin2,
                      "no_func_auth": bool(iin1 & IIN1_NO_FUNC_AUTH),
                      "no_func_support": bool(iin2 & IIN2_NO_FUNC_SUPPORT),
                      "object_unknown": bool(iin2 & IIN2_OBJECT_UNKNOWN),
                      "param_error": bool(iin2 & IIN2_PARAM_ERROR)}
        # If the function is unsupported, SAv5 is NOT implemented.
        if iin2 & IIN2_NO_FUNC_SUPPORT:
            out["challenge_response"] = False
            out["sa_version"] = "none"
            return out
        # Scan object headers for group 92 (0x5C)
        idx = 4
        found_grp92 = False
        found_var = None
        found_key_status = False
        # SAv5 challenge body heuristic markers:
        challenge_value = b""
        while idx + 4 <= len(data):
            grp, var, qf, qval = data[idx], data[idx + 1], data[idx + 2], data[idx + 3]
            if grp == OBJ_GROUP_AUTH:
                found_grp92 = True
                if var == OBJ_VAR_AUTH_KEYSTATUS:
                    found_key_status = True
                if found_var is None:
                    found_var = var
                # Try to extract the challenge value (for key-rotation heuristic)
                # Skip the qualifier prefix and read the rest of this object.
                # For free-format (0x5B), the next 2 bytes are length (LE).
                if qf == QUAL_FREE_FORMAT and idx + 6 <= len(data):
                    ff_len = struct.unpack("<H", data[idx + 4:idx + 6])[0]
                    end = idx + 6 + ff_len
                    if end <= len(data):
                        challenge_value = data[idx + 6: end]
                # Move past this header conservatively
                idx += 4
                if qf in (0x00, 0x01):
                    idx += 2
                elif qf == 0x06:
                    idx += 1
                elif qf == 0x07:
                    idx += 2
                elif qf == QUAL_FREE_FORMAT and idx + 2 <= len(data):
                    ff_len = struct.unpack("<H", data[idx:idx + 2])[0]
                    idx += 2 + ff_len
                else:
                    idx += 1
            else:
                idx += 4
                if qf in (0x00, 0x01):
                    idx += 2
                elif qf == 0x06:
                    idx += 1
                elif qf == 0x07:
                    idx += 2
                else:
                    idx += 1
        if found_grp92:
            out["challenge_response"] = True
            out["challenge_variation"] = found_var
            out["key_rotation"] = bool(found_key_status or len(challenge_value) >= 20)
            if found_var in SAV5_VARIATIONS or found_var in (
                OBJ_VAR_AUTH_CHALLENGE, OBJ_VAR_AUTH_REPLY,
            ):
                # var 1 (Challenge) + var 7..10 (HMAC/AES-GCM) → v5
                # var 1 alone is also part of v5 (it is the canonical
                # challenge container).
                out["sa_version"] = "v5"
            else:
                # var 2/3 in isolation with small challenge value → legacy
                out["sa_version"] = "legacy_v2v3" if found_var in (2, 3) else "unknown"
        else:
            # No group 92 object → either auth disabled (response with iin1.5
            # already cleared) or outstation ignored our probe.
            out["challenge_response"] = False
            if not (iin2 & IIN2_NO_FUNC_SUPPORT):
                # Treat as: SAv5 not enforced
                out["sa_version"] = "none"
        return out


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "lab_guard_not_satisfied",
            "detail": "Set LAB=1 to confirm isolated lab authorization.",
            "legal_note": ("DNP3 SAv5 probing on production SCADA / power "
                           "infrastructure is illegal outside an authorized "
                           "lab. NERC CIP / IEEE 1815 / IEC 62351-3,-5,-7."),
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
        "dnp3_src": DNP3_SRC,
        "dnp3_dst": DNP3_DST,
        # Spec-required output fields:
        "link_active": False,
        "sa_v5_active": False,
        "unauthenticated_read_works": False,
        "challenge_response": False,
        "aggressive_mode": False,
        "key_rotation": False,
        # Extra diagnostic fields:
        "sa_version": None,
        "iin_unauth": None,
        "iin_auth": None,
        "errors": [],
    }

    try:
        with Dnp3SaV5Client(HOST, PORT, timeout=TIMEOUT_S,
                            src=DNP3_SRC, dst=DNP3_DST) as client:
            # ── 1. Link status ──────────────────────────────────────────────
            try:
                lr = client.send_link_status()
                summary["link_active"] = bool(lr.get("link_active"))
                if lr.get("error"):
                    summary["errors"].append(f"link_status:{lr['error']}")
            except Exception as e:  # noqa: BLE001
                summary["errors"].append(f"link_status:{type(e).__name__}:{e}")

            if not summary["link_active"]:
                # No point in continuing — link is dead.
                summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
                print(json.dumps(summary, indent=2, default=str))
                return

            # ── 2. Unauthenticated Class-0 READ ────────────────────────────
            # This MUST be the first application-layer probe so that we can
            # observe the outstation's reaction WITHOUT a preceding SAv5
            # exchange (i.e. Aggressive Mode).
            try:
                ur = client.send_unauth_class0_read()
                summary["unauthenticated_read_works"] = bool(
                    ur.get("unauthenticated_read_works"))
                summary["iin_unauth"] = ur.get("iin")
                if ur.get("error"):
                    summary["errors"].append(f"unauth_read:{ur['error']}")
            except Exception as e:  # noqa: BLE001
                summary["errors"].append(f"unauth_read:{type(e).__name__}:{e}")

            # ── 3. SAv5 AUTHENTICATE challenge ─────────────────────────────
            try:
                sr = client.probe_sav5_challenge()
                summary["challenge_response"] = bool(sr.get("challenge_response"))
                summary["key_rotation"] = bool(sr.get("key_rotation"))
                summary["sa_version"] = sr.get("sa_version")
                summary["iin_auth"] = sr.get("iin")
                if sr.get("error"):
                    summary["errors"].append(f"sav5_probe:{sr['error']}")
            except Exception as e:  # noqa: BLE001
                summary["errors"].append(f"sav5_probe:{type(e).__name__}:{e}")

            # ── 4. SAv5 active inference ───────────────────────────────────
            # SAv5 is "active" if EITHER:
            #   - the unauth READ returned IIN1.5 NO_FUNC_AUTH (rejected)
            #   - the AUTHENTICATE challenge returned a group-92 object
            unauth_iin = summary["iin_unauth"] or {}
            auth_iin = summary["iin_auth"] or {}
            auth_rejected = bool(unauth_iin.get("no_func_auth"))
            challenge_present = bool(summary["challenge_response"])
            auth_unsupported = bool(auth_iin.get("no_func_support"))

            if auth_rejected or challenge_present:
                summary["sa_v5_active"] = True
            elif auth_unsupported and not auth_rejected:
                summary["sa_v5_active"] = False
            else:
                # Inconclusive — leave False
                summary["sa_v5_active"] = False

            # ── 5. Aggressive Mode inference ───────────────────────────────
            # Aggressive Mode = SAv5 enforces auth BEFORE the first normal
            # request. If unauth READ was rejected with IIN1.5 ⇒ Aggressive.
            # If SAv5 is active but unauth READ still succeeded (i.e. the
            # outstation tolerates pre-auth reads) ⇒ NOT Aggressive.
            if summary["sa_v5_active"] and auth_rejected:
                summary["aggressive_mode"] = True
            else:
                summary["aggressive_mode"] = False

    except (socket.timeout, TimeoutError):
        summary["errors"].append("transport:timeout")
    except ConnectionRefusedError:
        summary["errors"].append("transport:ConnectionRefusedError")
    except OSError as e:
        summary["errors"].append(f"transport:{type(e).__name__}:{e}")
    except Exception as e:  # noqa: BLE001
        summary["errors"].append(f"transport:{type(e).__name__}:{e}")

    summary["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
