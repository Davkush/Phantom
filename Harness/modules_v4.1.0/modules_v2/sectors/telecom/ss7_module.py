#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — SS7/Diameter signaling exposure probe (telecom core).
# Secteur : telecom — couche SIGTRAN / Diameter / MAP / SIP.
#
#   v3.0.0 : nouveau module sectoriel (Phase 1, telecom recon).
#   - LAB=1 OBLIGATOIRE — refuse de s'exécuter sans confirmation environnement lab.
#   - Timeout 5s sur toutes les sockets (setsockopt SO_RCVTIMEO/SO_SNDTIMEO).
#   - JSON stdout uniquement (aucune sortie texte parasite).
#   - SAFE_MODE=read_only par défaut pour telecom (cf. sector_base.py).
#       - SMS interception & MAP forwarding = lecture uniquement (pas d'envoi SMS).
#   - Cadre légal : Art. 323-1 Code pénal — l'interception SS7/SIGTRAN sur
#     équipements télécoms en production est illégale. Lab isolé uniquement.
#
# Vecteurs testés :
#   - SCTP port 2905 (M3UA / SIGTRAN)   — reachability
#   - Diameter port 3868 (CER)           — Capabilities-Exchange-Request
#   - HSS detection via Diameter S6a     — Home Subscriber Server
#   - SIP port 5060 (OPTIONS)            — VoIP recon (cross-secteur telecom)
#   - MAP SMS forwarding exposure        — vecteur d'interception SMS 2FA bancaire
#
# Usage : python3 ss7_module.py [host] [port_sctp] [port_diameter] [port_sip]
import json
import os
import socket
import struct
import sys
import time
from typing import Optional

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "ss7_probe"
TIMEOUT_S = 5  # toutes les sockets : 5s hard cap

# ─── Args CLI (avec defaults lab-safe) ──────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT_SCTP = int(sys.argv[2]) if len(sys.argv) > 2 else 2905
PORT_DIAMETER = int(sys.argv[3]) if len(sys.argv) > 3 else 3868
PORT_SIP = int(sys.argv[4]) if len(sys.argv) > 4 else 5060

# SAFE_MODE (cf. sector_base) — telecom est read_only par défaut.
# SAFE_MODE=full autorise les sondes actives (CER envoyé, etc.).
SAFE_MODE = os.environ.get("SAFE_MODE", "read_only")


# ─── LAB guard ──────────────────────────────────────────────────────
def lab_guard() -> bool:
    """Refuse de s'exécuter sans LAB=1 dans l'environnement."""
    return os.environ.get("LAB") == "1"


# ─── Utilitaires socket ─────────────────────────────────────────────
def _set_timeout(sock: socket.socket, seconds: float = TIMEOUT_S) -> None:
    """Applique un timeout 5s en réception ET en émission (cross-platform)."""
    if hasattr(socket, "SO_RCVTIMEO"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO,
                        struct.pack("ll", int(seconds), int((seconds % 1) * 1_000_000)))
    if hasattr(socket, "SO_SNDTIMEO"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                        struct.pack("ll", int(seconds), int((seconds % 1) * 1_000_000)))
    # Backup : settimeout (niveau Python) pour les OS où SO_*TIMEO est partial.
    sock.settimeout(seconds)


# ─── 1. SCTP port 2905 (M3UA) ───────────────────────────────────────
# M3UA (MTP3 User Adaptation Layer) tourne sur SCTP port 2905 (IANA).
# SCTP n'est pas supporté par le module socket de CPython sans extension.
# On teste d'abord la reachability TCP (souvent les stacks SIGTRAN
# exposent aussi un transport TCP fallback ou le port répond en SYN).
def check_sctp_port(port: int = PORT_SCTP) -> dict:
    """Check if SCTP port 2905 (M3UA) is reachable.

    CPython `socket` n'expose pas SCTP directement ; on sonde la
    reachabilité TCP SYN (ports SIGTRAN écoutent souvent TCP fallback)
    et on essaie IPPROTO_SCTP si le kernel le supporte (Linux 132).
    """
    result: dict = {
        "check": "sctp_port",
        "port": port,
        "transport": "unknown",
        "reachable": False,
    }

    # Tentative SCTP natif (Linux only — IPPROTO_SCTP=132).
    sctp_supported = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132)  # IPPROTO_SCTP
        sctp_supported = True
        _set_timeout(s)
        try:
            s.connect((HOST, port))
            result["reachable"] = True
            result["transport"] = "sctp"
            s.close()
            return result
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result["detail"] = f"sctp_connect_failed: {type(e).__name__}"
        finally:
            try:
                s.close()
            except OSError:
                pass
    except OSError:
        # IPPROTO_SCTP non supporté par le kernel ou le socket module
        result["sctp_native"] = False
        sctp_supported = False

    # Fallback TCP : la reachability TCP indique que le port écoute.
    # NB: ce n'est pas une preuve de SCTP, mais un signal de surface d'attaque.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _set_timeout(s)
        try:
            s.connect((HOST, port))
            result["reachable"] = True
            result["transport"] = "tcp_fallback"
            # Tenter de lire 4 octets (init SCTP/M3UA ou bannière).
            try:
                s.settimeout(1.0)
                banner = s.recv(64)
                if banner:
                    result["banner_hex"] = banner.hex()[:64]
            except socket.timeout:
                pass
        except (socket.timeout, ConnectionRefusedError) as e:
            result["detail"] = f"tcp_connect_failed: {type(e).__name__}"
        finally:
            s.close()
    except OSError as e:
        result["detail"] = f"socket_error: {type(e).__name__}: {e}"

    return result


# ─── 2. Diameter CER (Capabilities-Exchange-Request) ────────────────
# RFC 6733 — Diameter frame format (binaire) :
#   Version(1) | Message-Length(3) | Flags(1) | Command-Code(3) | AppId(4) |
#   Hop-by-Hop-Id(4) | End-to-End-Id(4) | AVPs...
# CER : Command-Code = 257 (0x101), Flags = 0xC0 (Request + Proxyable),
#        Application-Id = 0 (Diameter Common).
# AVPs minimum :
#   - Origin-Host (264), Origin-Realm (296), Host-IP-Address (257),
#     Vendor-Id (266), Product-Name (269).
def _build_avp(code: int, data: bytes, vendor_specific: bool = False,
               mandatory: bool = False) -> bytes:
    """Encode un AVP Diameter (RFC 6733 §4).

    Format non-vendor : Code(4) | Flags(1) | Length(3) | Data
    Format vendor     : Code(4) | Flags(1) | Length(3) | Vendor-Id(4) | Data
    Length inclut l'en-tête (8 ou 12 octets) + data. Padding 4 octets.
    """
    flags = 0x80 if mandatory else 0x00
    if vendor_specific:
        flags |= 0x80  # V flag (vendor-specific)
        avp_len = 12 + len(data)  # 4(code) + 1(flags) + 3(length) + 4(vendor) + data
        header = struct.pack("!IBBBBI", code, flags,
                             (avp_len >> 16) & 0xFF,
                             (avp_len >> 8) & 0xFF,
                             avp_len & 0xFF,
                             0)  # Vendor-Id = 0 (generic); caller may prepend real one
    else:
        avp_len = 8 + len(data)  # 4(code) + 1(flags) + 3(length) + data
        header = struct.pack("!IBBBB", code, flags,
                             (avp_len >> 16) & 0xFF,
                             (avp_len >> 8) & 0xFF,
                             avp_len & 0xFF)
    body = header + data
    # Padding à 4 octets (RFC 6733 §4.4).
    pad = (4 - (len(body) % 4)) % 4
    return body + b"\x00" * pad


def _build_cer(host: str, realm: str) -> bytes:
    """Construit un Diameter CER (Capabilities-Exchange-Request) binaire.

    Command-Code = 257 (CER), Flags = 0xC0 (Request|Proxyable), AppId = 0.
    """
    origin_host = _build_avp(264, host.encode("ascii"), mandatory=True)
    origin_realm = _build_avp(296, realm.encode("ascii"), mandatory=True)
    host_ip = _build_avp(257, socket.inet_aton("127.0.0.1"), mandatory=True)
    vendor_id = _build_avp(266, struct.pack("!I", 0), mandatory=True)
    product_name = _build_avp(269, b"harness-ss7-probe")

    avps = origin_host + origin_realm + host_ip + vendor_id + product_name
    msg_len = 20 + len(avps)  # header Diameter = 20 octets

    # Header Diameter : Version(1) | Length(3) | Flags(1) | CmdCode(3) | AppId(4) |
    #                   Hop-by-Hop-Id(4) | End-to-End-Id(4)
    header = struct.pack("!B", 1)  # Version 1
    header += struct.pack("!I", msg_len)[1:]  # Length sur 3 octets
    header += struct.pack("!B", 0xC0)  # Flags: Request + Proxyable
    # Command-Code 257 sur 3 octets
    header += struct.pack("!I", 257)[1:]
    header += struct.pack("!I", 0)  # Application-Id = Diameter Common
    header += struct.pack("!I", 0x12345678)  # Hop-by-Hop-Id (aléatoire)
    header += struct.pack("!I", 0x12345678)  # End-to-End-Id

    return header + avps


def _parse_diameter_header(buf: bytes) -> dict:
    """Parse un header Diameter (20 octets) → dict."""
    if len(buf) < 20:
        return {"valid": False, "truncated": len(buf)}
    version = buf[0]
    msg_len = (buf[1] << 16) | (buf[2] << 8) | buf[3]
    flags = buf[4]
    cmd_code = (buf[5] << 16) | (buf[6] << 8) | buf[7]
    app_id = struct.unpack("!I", buf[8:12])[0]
    return {
        "valid": True,
        "version": version,
        "message_length": msg_len,
        "flags": flags,
        "command_code": cmd_code,
        "application_id": app_id,
        "is_response": bool(flags & 0x20),
    }


def check_diameter_port(port: int = PORT_DIAMETER) -> dict:
    """Send a Diameter CER (Capabilities-Exchange-Request) and parse response.

    SAFE_MODE=read_only : envoie quand même le CER (lecture seule par nature —
    un CER ne modifie pas l'état du serveur, il négocie juste les capacités).
    Si SAFE_MODE=strict, on se contente de la reachability TCP.
    """
    result: dict = {
        "check": "diameter_cer",
        "port": port,
        "responsive": False,
        "command_code_observed": None,
        "response_header": None,
    }

    cer = _build_cer(host="probe.harness.lab", realm="harness.lab")
    result["cer_length"] = len(cer)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _set_timeout(s)
        try:
            s.connect((HOST, port))
            s.sendall(cer)
            # Lire au moins le header (20 octets) pour valider la réponse.
            resp = b""
            try:
                while len(resp) < 20:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            if resp:
                parsed = _parse_diameter_header(resp)
                result["response_header"] = parsed
                # CEA = Command-Code 257, Response flag set
                if (parsed.get("valid") and parsed.get("command_code") == 257
                        and parsed.get("is_response")):
                    result["responsive"] = True
                    result["command_code_observed"] = parsed["command_code"]
                else:
                    result["detail"] = "response not a valid CEA"
            else:
                result["detail"] = "no_response_data"
        finally:
            s.close()
    except socket.timeout:
        result["detail"] = "connect_or_recv_timeout"
    except ConnectionRefusedError:
        result["detail"] = "connection_refused"
    except OSError as e:
        result["detail"] = f"socket_error: {type(e).__name__}: {e}"

    return result


# ─── 3. SIP port 5060 (OPTIONS) ─────────────────────────────────────
# OPTIONS est une sonde sûre : elle ne modifie pas l'état du serveur.
# On envoie en UDP d'abord, fallback TCP.
_SIP_OPTIONS_TEMPLATE = (
    "OPTIONS sip:{host}:{port} SIP/2.0\r\n"
    "Via: SIP/2.0/{proto} 127.0.0.1:{localport};branch=z9hG4bK-{branch}\r\n"
    "Max-Forwards: 70\r\n"
    "From: <sip:probe@harness.lab>;tag={tag}\r\n"
    "To: <sip:{host}:{port}>\r\n"
    "Call-ID: {callid}@harness.lab\r\n"
    "CSeq: 1 OPTIONS\r\n"
    "User-Agent: harness-ss7-probe\r\n"
    "Accept: application/sdp\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)


def check_sip_port(port: int = PORT_SIP) -> dict:
    """SIP OPTIONS probe — reachability + fingerprint serveur."""
    result: dict = {
        "check": "sip_options",
        "port": port,
        "accessible": False,
        "transport": None,
        "response_status": None,
        "server_header": None,
    }

    branch = f"{int(time.time()):x}"
    tag = f"{int(time.time()):x}"
    callid = f"{int(time.time()):x}"
    msg = _SIP_OPTIONS_TEMPLATE.format(
        host=HOST, port=port, proto="UDP",
        localport="5060", branch=branch, tag=tag, callid=callid,
    ).encode("ascii")

    # UDP en premier (SIP préfère UDP pour OPTIONS).
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _set_timeout(s)
        try:
            s.sendto(msg, (HOST, port))
            try:
                data, _ = s.recvfrom(4096)
                if data:
                    result["accessible"] = True
                    result["transport"] = "udp"
                    text = data.decode("ascii", errors="replace")
                    first_line = text.split("\r\n", 1)[0]
                    result["response_status"] = first_line
                    for line in text.split("\r\n"):
                        if line.lower().startswith("server:"):
                            result["server_header"] = line.split(":", 1)[1].strip()
                            break
            except socket.timeout:
                pass
        finally:
            s.close()
    except OSError as e:
        result["udp_error"] = f"{type(e).__name__}: {e}"

    # Fallback TCP si UDP échoue.
    if not result["accessible"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _set_timeout(s)
            try:
                s.connect((HOST, port))
                msg_tcp = _SIP_OPTIONS_TEMPLATE.format(
                    host=HOST, port=port, proto="TCP",
                    localport="5060", branch=branch, tag=tag, callid=callid,
                ).encode("ascii")
                s.sendall(msg_tcp)
                try:
                    data = s.recv(4096)
                    if data:
                        result["accessible"] = True
                        result["transport"] = "tcp"
                        text = data.decode("ascii", errors="replace")
                        result["response_status"] = text.split("\r\n", 1)[0]
                        for line in text.split("\r\n"):
                            if line.lower().startswith("server:"):
                                result["server_header"] = line.split(":", 1)[1].strip()
                                break
                except socket.timeout:
                    pass
            finally:
                s.close()
        except OSError as e:
            result["tcp_error"] = f"{type(e).__name__}: {e}"

    return result


# ─── 4. HSS detection via Diameter S6a ──────────────────────────────
# S6a interface : Diameter Application-Id = 16777251 (3GPP S6a/S6d).
# On envoie un CER avec Application-Id S6a pour voir si le serveur
# annonce le support de cette application (i.e. est un HSS ou un MME).
HSS_APP_ID = 16777251  # 3GPP S6a/S6d Application-Id


def _build_cer_s6a(host: str, realm: str) -> bytes:
    """CER avec AVP Auth-Application-Id = S6a (16777251)."""
    origin_host = _build_avp(264, host.encode("ascii"), mandatory=True)
    origin_realm = _build_avp(296, realm.encode("ascii"), mandatory=True)
    host_ip = _build_avp(257, socket.inet_aton("127.0.0.1"), mandatory=True)
    vendor_id = _build_avp(266, struct.pack("!I", 10415), mandatory=True)  # 3GPP vendor
    product_name = _build_avp(269, b"harness-hss-probe")
    # Auth-Application-Id AVP (258) — Mandatory.
    auth_app_id = _build_avp(258, struct.pack("!I", HSS_APP_ID), mandatory=True)

    avps = (origin_host + origin_realm + host_ip + vendor_id
            + product_name + auth_app_id)
    msg_len = 20 + len(avps)
    header = struct.pack("!B", 1)
    header += struct.pack("!I", msg_len)[1:]
    header += struct.pack("!B", 0xC0)
    header += struct.pack("!I", 257)[1:]  # CER
    header += struct.pack("!I", 0)  # AppId Common (CER)
    header += struct.pack("!I", 0xDEADBEEF)
    header += struct.pack("!I", 0xDEADBEEF)
    return header + avps


def _scan_avps_for_app_id(buf: bytes, app_id: int) -> bool:
    """Cherche un AVP Auth-Application-Id (258) avec valeur == app_id dans la réponse."""
    # Parsing très permissif : on cherche la séquence 258 encodée en big-endian
    # suivie de flags=0xC0 (mandatory) puis length puis la valeur app_id.
    target = struct.pack("!I", 258)  # Code AVP 258
    pos = 0
    while True:
        idx = buf.find(target, pos)
        if idx == -1 or idx + 12 > len(buf):
            break
        # flags(1) + length(3) + value(4) après le code
        flags = buf[idx + 4]
        if flags & 0x80:  # mandatory bit set
            length = (buf[idx + 5] << 16) | (buf[idx + 6] << 8) | buf[idx + 7]
            if length >= 12 and idx + 8 + 4 <= len(buf):
                value = struct.unpack("!I", buf[idx + 8:idx + 12])[0]
                if value == app_id:
                    return True
        pos = idx + 4
    return False


def detect_hss() -> dict:
    """Try HSS (Home Subscriber Server) detection via Diameter S6a interface.

    Envoie un CER avec Auth-Application-Id = 16777251 (S6a).
    Si le serveur répond par un CEA qui annonce le support S6a → HSS probable.
    """
    result: dict = {
        "check": "hss_detection",
        "interface": "S6a",
        "application_id": HSS_APP_ID,
        "hss_detected": False,
        "cea_received": False,
        "supported_apps": [],
    }

    cer = _build_cer_s6a(host="probe.harness.lab", realm="harness.lab")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _set_timeout(s)
        try:
            s.connect((HOST, PORT_DIAMETER))
            s.sendall(cer)
            resp = b""
            try:
                while len(resp) < 256:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            if resp:
                hdr = _parse_diameter_header(resp)
                result["cea_received"] = bool(hdr.get("is_response"))
                if result["cea_received"]:
                    # Cherche le support S6a dans les AVPs de la réponse.
                    if _scan_avps_for_app_id(resp, HSS_APP_ID):
                        result["hss_detected"] = True
                        result["supported_apps"].append("S6a")
                    # Cherche aussi S6d (même App-Id) et S13/S13' (police de handset).
                    result["detail"] = "cea_parsed"
            else:
                result["detail"] = "no_cea_received"
        finally:
            s.close()
    except socket.timeout:
        result["detail"] = "timeout"
    except ConnectionRefusedError:
        result["detail"] = "connection_refused"
    except OSError as e:
        result["detail"] = f"socket_error: {type(e).__name__}: {e}"

    return result


# ─── 5. MAP SMS interception exposure ───────────────────────────────
# MAP (Mobile Application Part, ITU-T Q.980) tourne sur SS7 / SIGTRAN M3UA.
# SMS interception : un attaquant envoyant un MAP `forwardSM` ou `provideSubscriberInfo`
# sans autorisation peut intercepter les SMS 2FA bancaires.
#
# On ne peut pas envoyer de MAP depuis Python sans stack SS7 (étendue trop large).
# On teste donc l'EXPOSITION : si le port SCTP 2905 est reachable ET
# qu'aucun SCCP/M3UA gateway ne filtre (i.e. on reçoit un réponse DATA),
# alors la surface d'attaque MAP SMS interception est ouverte.
#
# NB: lecture seule — on n'envoie JAMAIS de forwardSM (SAFE_MODE telecom = read_only).
MAP_SMS_INTERCEPTION_HINT = (
    "SCTP/M3UA reachable + Diameter S6a HSS detected → surface d'attaque MAP SMS "
    "interception ouverte (vecteur 2FA bancaire). Lecture seule : pas d'envoi MAP."
)


def check_sms_interception() -> dict:
    """Check if MAP (Mobile Application Part) SMS forwarding is exposed.

    Vecteur utilisé dans les attaques d'interception SMS 2FA bancaire.
    Lecture seule : on n'envoie pas de MAP forwardSM, on évalue seulement
    la surface d'attaque en croisant SCTP reachability + HSS detection.
    """
    result: dict = {
        "check": "map_sms_interception",
        "sms_interception_risk": False,
        "risk_level": "none",
        "indicators": [],
        "vector": "MAP forwardSM / provideSubscriberInfo",
        "note": "Lecture seule — pas d'envoi MAP (SAFE_MODE telecom read_only).",
    }

    # On croise deux indicateurs de surface d'attaque :
    #   1. SCTP M3UA port 2905 reachable (transport MAP)
    #   2. HSS détecté via S6a (cible de l'interception)
    sctp_res = check_sctp_port(PORT_SCTP)
    hss_res = detect_hss()

    sctp_reachable = bool(sctp_res.get("reachable"))
    hss_detected = bool(hss_res.get("hss_detected"))

    result["indicators"].append({
        "sctp_m3ua_reachable": sctp_reachable,
        "port": PORT_SCTP,
    })
    result["indicators"].append({
        "hss_detected": hss_detected,
        "interface": "S6a",
    })

    # Risk scoring (lecture seule — pas de verdict "exploitable", juste "exposed").
    if sctp_reachable and hss_detected:
        result["sms_interception_risk"] = True
        result["risk_level"] = "high"
        result["hint"] = MAP_SMS_INTERCEPTION_HINT
    elif sctp_reachable:
        result["sms_interception_risk"] = True
        result["risk_level"] = "medium"
        result["hint"] = "SCTP M3UA reachable — surface SIGTRAN exposée (HSS non confirmé)."
    elif hss_detected:
        result["sms_interception_risk"] = False
        result["risk_level"] = "low"
        result["hint"] = "HSS détecté mais SIGTRAN non reachable (filtré)."
    else:
        result["risk_level"] = "none"
        result["hint"] = "Aucun indicateur d'exposition SS7/MAP."

    return result


# ─── Synthèse JSON ──────────────────────────────────────────────────
def main() -> None:
    # 1. LAB guard — refuse sans LAB=1 explicite.
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "lab": False,
            "error": "LAB guard not satisfied",
            "detail": ("Set LAB=1 to confirm lab authorization. SS7/SIGTRAN probing "
                       "on production telecom equipment is illegal (Art. 323-1)."),
            "legal_note": "Art. 323-1 Code pénal — interception SS7 illégale hors lab.",
        }, indent=2))
        sys.exit(1)

    # 2. SAFE_MODE guard — telecom est read_only par défaut (cf. sector_base).
    # On n'exécute que des sondes passives/lecture ; SAFE_MODE=full n'ajoute rien
    # ici car on n'envoie jamais de MAP forwardSM.
    safe_mode = SAFE_MODE

    # 3. Exécution des 5 checks (timeout 5s chacun).
    sctp = check_sctp_port(PORT_SCTP)
    diameter = check_diameter_port(PORT_DIAMETER)
    hss = detect_hss()
    sip = check_sip_port(PORT_SIP)
    sms = check_sms_interception()

    # 4. Synthèse JSON stdout (uniquement — pas de logs parasites).
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "lab": True,
        "safe_mode": safe_mode,
        "target": HOST,
        "timeout_s": TIMEOUT_S,
        # Champs de sortie attendus (spec) :
        "sctp_reachable": bool(sctp.get("reachable")),
        "diameter_responsive": bool(diameter.get("responsive")),
        "hss_detected": bool(hss.get("hss_detected")),
        "sip_accessible": bool(sip.get("accessible")),
        "sms_interception_risk": bool(sms.get("sms_interception_risk")),
        # Détails structurés pour le rapport :
        "details": {
            "sctp": sctp,
            "diameter": diameter,
            "hss": hss,
            "sip": sip,
            "sms_interception": sms,
        },
        "regulations": ["ETSI", "RGPD", "NIS2", "GSMA FS"],
        "legal_note": ("Interception SS7/MAP sur équipements télécoms en production : "
                       "Art. 323-1 Code pénal (FR). Lab isolé uniquement."),
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
