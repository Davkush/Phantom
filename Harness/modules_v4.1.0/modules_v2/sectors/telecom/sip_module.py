#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — SIP (Session Initiation Protocol) VoIP probe.
# Secteur : telecom — couche VoIP (RTP signalisation, pas de media).
#
#   v3.0.0 : nouveau module sectoriel (Phase 1, telecom recon).
#   - LAB=1 OBLIGATOIRE — refuse de s'exécuter sans confirmation environnement lab.
#   - Timeout 5s sur toutes les sockets (SO_RCVTIMEO/SO_SNDTIMEO + settimeout).
#   - JSON stdout uniquement (aucune sortie texte parasite).
#   - SAFE_MODE=read_only par défaut pour telecom (cf. sector_base.py).
#       - test_toll_fraud (INVITE sans auth vers PSTN) = SAFE_MODE=full ONLY.
#         En read_only on skippe le test (coût réel possible sur telco en prod).
#   - Cadre légal : Art. 323-1 Code pénal — le toll fraud sur PBX en production
#     est illégal et peut coûter des dizaines de milliers d'euros en quelques heures.
#
# Vecteurs testés :
#   - REGISTER sans credentials      → register_accepted (PBX mal configuré)
#   - OPTIONS                        → fingerprint serveur (Asterisk, FreeSWITCH, Kamailio)
#   - ENUM lookup (E.164 → DNS)      → enum_enabled
#   - INVITE vers PSTN sans auth     → toll_fraud_risk (SAFE_MODE=full seulement)
#   - 401 challenge realm/nonce leak → digest_info_leaked (info divulgation)
#
# Usage : python3 sip_module.py [host] [port] [safe_mode]
import json
import os
import re
import socket
import struct
import sys
import time
from typing import Optional

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "sip_probe"
TIMEOUT_S = 5  # toutes les sockets : 5s hard cap

# ─── Args CLI (defaults lab-safe) ───────────────────────────────────
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
# SAFE_MODE peut être surchargé via CLI argv[3] ou env. Defaut = telecom read_only.
SAFE_MODE = (sys.argv[3] if len(sys.argv) > 3
             else os.environ.get("SAFE_MODE", "read_only"))

# Numéro ENUM de test (E.164 —应当按照 ITU-T E.164). On utilise +1 555 0100
# (range reserved for fiction/ lab par ITU-T E.430 — jamais assigné à un opérateur).
ENUM_TEST_E164 = "+15550100"


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
    sock.settimeout(seconds)


# ─── SIP message builders ───────────────────────────────────────────
def _sip_headers(msg_type: str, uri: str, extra: list[tuple[str, str]] = ()) -> str:
    """Construit un message SIP de base (sans body)."""
    branch = f"z9hG4bK-harness-{int(time.time()*1000):x}"
    tag = f"harness{int(time.time()):x}"
    callid = f"harness-{int(time.time()):x}@127.0.0.1"
    lines = [
        f"{msg_type} {uri} SIP/2.0",
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch={branch};rport",
        "Max-Forwards: 70",
        f"From: <sip:probe@harness.lab>;tag={tag}",
        f"To: <{uri}>",
        f"Call-ID: {callid}",
        f"CSeq: 1 {msg_type}",
        "User-Agent: harness-sip-probe/3.0.0",
        "Content-Length: 0",
    ]
    for k, v in extra:
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines) + "\r\n\r\n"


def _send_sip_udp(msg: str, host: str, port: int,
                 timeout: float = TIMEOUT_S) -> Optional[bytes]:
    """Envoie un message SIP en UDP et retourne la réponse (ou None)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _set_timeout(s, timeout)
        try:
            s.sendto(msg.encode("ascii"), (host, port))
            try:
                data, _ = s.recvfrom(4096)
                return data
            except socket.timeout:
                return None
        finally:
            s.close()
    except OSError:
        return None


def _send_sip_tcp(msg: str, host: str, port: int,
                 timeout: float = TIMEOUT_S) -> Optional[bytes]:
    """Envoie un message SIP en TCP et retourne la réponse (ou None)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _set_timeout(s, timeout)
        try:
            s.connect((host, port))
            s.sendall(msg.encode("ascii"))
            try:
                # Lire jusqu'à 8 Ko ; SIP sur TCP peut fragmenter.
                chunks: list[bytes] = []
                total = 0
                while total < 8192:
                    chunk = s.recv(2048)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                if chunks:
                    return b"".join(chunks)
                return None
            except socket.timeout:
                # Si on a déjà des données, on les retourne (réponse partielle).
                if chunks:
                    return b"".join(chunks)
                return None
        finally:
            s.close()
    except OSError:
        return None


def _send_sip(msg: str, host: str = HOST, port: int = PORT) -> Optional[bytes]:
    """Envoie SIP en UDP d'abord, fallback TCP."""
    resp = _send_sip_udp(msg, host, port)
    if resp is None:
        resp = _send_sip_tcp(msg, host, port)
    return resp


def _parse_status(resp: bytes) -> tuple[Optional[str], str]:
    """Retourne (status_line, full_text) à partir d'une réponse SIP."""
    if resp is None:
        return None, ""
    text = resp.decode("ascii", errors="replace")
    first_line = text.split("\r\n", 1)[0]
    return first_line, text


# ─── Fingerprint patterns ───────────────────────────────────────────
# Server / User-Agent headers exposés par les PBX/SBC principaux.
FINGERPRINT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Asterisk",    re.compile(r"asterisk(?:[/ ]PBX)?[\s\d.]*", re.I)),
    ("FreeSWITCH",  re.compile(r"freeswitch[\s()\/\d.]*", re.I)),
    ("Kamailio",    re.compile(r"kamailio(?:\s*\(\d[^)]*\))?", re.I)),
    ("OpenSIPS",    re.compile(r"opensips[\s\d.]*", re.I)),
    ("OpenSER",     re.compile(r"openser[\s\d.]*", re.I)),
    ("SipXecs",     re.compile(r"sipx?ecs", re.I)),
    ("Cisco-CUBE",  re.compile(r"cisco(?:[- ]cube)?\s*sip(?:server|gateway)?", re.I)),
    ("Sonus/SBC",   re.compile(r"sonus|ribbon|sbc\s*@", re.I)),
    ("Brekeke",     re.compile(r"brekeke", re.I)),
    ("Yate",        re.compile(r"yate/\d", re.I)),
    ("Twinkle",     re.compile(r"twinkle", re.I)),
    ("Mini-SIP-Server", re.compile(r"mini[-_ ]?sip[-_ ]?server", re.I)),
]


def _fingerprint(resp_text: str) -> Optional[str]:
    """Fingerprint le serveur SIP via headers Server / User-Agent / status."""
    for name, pat in FINGERPRINT_PATTERNS:
        if pat.search(resp_text):
            return name
    # Fallback : header Server explicite sans match de pattern connu.
    for line in resp_text.split("\r\n"):
        if line.lower().startswith("server:") or line.lower().startswith("user-agent:"):
            val = line.split(":", 1)[1].strip()
            if val:
                return f"unknown:{val[:40]}"
    return None


# ─── 1. REGISTER sans credentials ───────────────────────────────────
def send_register(uri: str = f"sip:{HOST}:{PORT}",
                 user: str = "probe") -> dict:
    """SIP REGISTER without credentials → check if accepted (insecure).

    Un serveur qui accepte un REGISTER sans Authorization header est
    complètement ouvert (compromission immédiate de comptes SIP).
    On attend soit un 200 OK (insécurité totale), soit un 401/407 (challenge).
    """
    result: dict = {
        "check": "register",
        "register_accepted": False,
        "response_status": None,
        "challenge_issued": False,
    }
    msg = _sip_headers("REGISTER", uri, extra=[
        ("Contact", f"<sip:{user}@127.0.0.1:5060>;expires=300"),
    ])
    resp = _send_sip(msg)
    status, text = _parse_status(resp)
    result["response_status"] = status
    if status:
        if status.startswith("SIP/2.0 200"):
            result["register_accepted"] = True
        elif status.startswith("SIP/2.0 401") or status.startswith("SIP/2.0 407"):
            result["challenge_issued"] = True
    return result


# ─── 2. OPTIONS → fingerprint serveur ───────────────────────────────
def send_options(uri: str = f"sip:{HOST}:{PORT}") -> dict:
    """SIP OPTIONS → fingerprint server (Asterisk, FreeSWITCH, Kamailio, ...)."""
    result: dict = {
        "check": "options",
        "responsive": False,
        "response_status": None,
        "server_fingerprint": None,
        "allow_methods": None,
    }
    msg = _sip_headers("OPTIONS", uri)
    resp = _send_sip(msg)
    status, text = _parse_status(resp)
    result["response_status"] = status
    if status:
        result["responsive"] = True
        fp = _fingerprint(text)
        result["server_fingerprint"] = fp
        # Extraire le header Allow (méthodes supportées).
        for line in text.split("\r\n"):
            if line.lower().startswith("allow:"):
                result["allow_methods"] = line.split(":", 1)[1].strip()
                break
    return result


# ─── 3. ENUM (E.164 Number Mapping) DNS lookup ──────────────────────
# ENUM : RFC 6116 — mapping d'un numéro E.164 vers un domaine DNS.
# Transformation : +1 555 0100 → 0.0.1.0.5.5.5.1.e164.arpa
# On cherche un record NAPTR qui pointe vers une URI sip:
def _e164_to_enum_domain(e164: str) -> str:
    """Convertit +1 555 0100 → 0.0.1.0.5.5.5.1.e164.arpa."""
    digits = re.sub(r"[^\d]", "", e164)
    reversed_digits = digits[::-1]
    return ".".join(reversed_digits) + ".e164.arpa"


def check_enum(number: str = ENUM_TEST_E164) -> dict:
    """Test E.164 Number Mapping (ENUM) DNS lookup (NAPTR records).

    Utilise dnspython si disponible, sinon fallback sur `socket.getaddrinfo`
    (qui ne supporte pas NAPTR mais permet de tester la résolution A/AAAA).
    """
    result: dict = {
        "check": "enum",
        "number": number,
        "enum_domain": None,
        "enum_enabled": False,
        "naptr_records": [],
    }
    domain = _e164_to_enum_domain(number)
    result["enum_domain"] = domain

    try:
        import dns.resolver  # type: ignore
        try:
            answers = dns.resolver.resolve(domain, "NAPTR", lifetime=TIMEOUT_S)
            for rdata in answers:
                # NAPTR : order pref flags service regexp replacement
                rec = {
                    "order": int(rdata.order),
                    "preference": int(rdata.preference),
                    "flags": str(rdata.flags),
                    "service": str(rdata.service),
                    "regexp": str(rdata.regexp),
                    "replacement": str(rdata.replacement),
                }
                result["naptr_records"].append(rec)
                if "sip" in str(rdata.service).lower() or "E2U+sip" in str(rdata.service):
                    result["enum_enabled"] = True
        except Exception as e:
            result["detail"] = f"dns_resolve_failed: {type(e).__name__}: {e}"
    except ImportError:
        # Fallback : test de résolution DNS générique (ne détecte pas NAPTR,
        # mais indique si le serveur DNS répond pour le domaine ENUM).
        try:
            socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            result["enum_enabled"] = True  # au moins résolvable
            result["note"] = "dnspython not installed — only A/AAAA checked, NAPTR skipped"
        except socket.gaierror as e:
            result["detail"] = f"resolution_failed: {e}"
            result["note"] = "dnspython not installed — NAPTR not checked"
    return result


# ─── 4. Toll fraud : INVITE vers PSTN sans auth ─────────────────────
# SAFE_MODE=full ONLY — en read_only on skippe (peut coûter de l'argent réel
# si le PBX route l'appel vers le PSTN sans vérifier l'auth).
TOLL_FRAUD_TARGET = "sip:9001234567@%s:%d"  # numéro premium-rate factice

def test_toll_fraud() -> dict:
    """Attempt INVITE to external number without auth → check if routed.

    ONLY if SAFE_MODE=full — un INVITE accepté par un PBX sans auth et
    routé vers le PSTN peut coûter des milliers d'euros en quelques minutes
    sur un opérateur réel (premium-rate numbers, international).
    """
    result: dict = {
        "check": "toll_fraud",
        "executed": False,
        "toll_fraud_risk": False,
        "response_status": None,
        "note": None,
    }

    # SAFE_MODE guard : telecom est read_only par défaut. Le toll fraud n'est
    # testé QUE si SAFE_MODE=full explicitement.
    if SAFE_MODE != "full":
        result["note"] = (f"skipped: SAFE_MODE={SAFE_MODE}. Toll fraud test could "
                          "cost real money on a production PBX. Set SAFE_MODE=full to "
                          "run (lab only).")
        return result

    # Numéro cible : premium-rate factice (900xxx). En lab, le PBX ne route
    # pas réellement vers le PSTN, mais le 200/100 Trying indique l'acceptation.
    uri = TOLL_FRAUD_TARGET % (HOST, PORT)
    msg = _sip_headers("INVITE", uri, extra=[
        ("Contact", "<sip:probe@127.0.0.1:5060>"),
        ("Content-Type", "application/sdp"),
        # SDP body minimal — un INVITE sans SDP peut être rejeté par certains PBX.
    ])
    # On triche : Content-Length: 0 ci-dessus ; on ajoute un SDP minimal.
    sdp = (
        "v=0\r\n"
        "o=- 0 0 IN IP4 127.0.0.1\r\n"
        "s=harness-probe\r\n"
        "c=IN IP4 127.0.0.1\r\n"
        "t=0 0\r\n"
        "m=audio 8000 RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
    )
    # Reconstruire avec Content-Length correct.
    msg = msg.replace("Content-Length: 0", f"Content-Length: {len(sdp)}")
    msg = msg + sdp  # SDP après les \r\n\r\n de fin des headers.

    result["executed"] = True
    resp = _send_sip(msg)
    status, text = _parse_status(resp)
    result["response_status"] = status
    if status:
        # 100 Trying = le PBX a accepté et route (toll fraud possible).
        # 200 OK = pire — l'appel est établi.
        # 401/407 = challenge (sûr).
        # 403/404 = rejet (sûr).
        if status.startswith("SIP/2.0 100") or status.startswith("SIP/2.0 200"):
            result["toll_fraud_risk"] = True
            result["note"] = "INVITE accepted without auth — PBX routes to PSTN."
        elif status.startswith("SIP/2.0 401") or status.startswith("SIP/2.0 407"):
            result["toll_fraud_risk"] = False
            result["note"] = "PBX challenged — auth required."
        else:
            result["toll_fraud_risk"] = False
            result["note"] = f"INVITE rejected: {status}"
    return result


# ─── 5. SIP digest leak (realm/nonce in 401 challenge) ──────────────
# Un serveur SIP qui envoie un 401 Unauthorized avec un header
# WWW-Authenticate: Digest realm="...", nonce="..." leak le realm
# (info sur le domaine géré) et un nonce (qui peut être réutilisé si
# la mise en œuvre est faible — replay attack).
DIGEST_HEADER_RE = re.compile(
    r"(?:WWW-Authenticate|Proxy-Authenticate):\s*Digest\s+(.+?)(?:\r\n|$)",
    re.I | re.S,
)
DIGEST_PARAM_RE = re.compile(
    r'(\w+)=(?:"([^"]*)"|([^,]+))'
)


def check_sip_digest_leak() -> dict:
    """Check if server leaks realm/nonce in 401 challenge.

    Le realm indique le domaine géré (info divulgation). Le nonce peut être
    analysé pour la qualité de la mise en œuvre (prédictible = replay attack).
    """
    result: dict = {
        "check": "digest_leak",
        "digest_info_leaked": False,
        "realm": None,
        "nonce": None,
        "algorithm": None,
        "qop": None,
        "challenge_received": False,
    }

    # Provoquer un 401 en envoyant un REGISTER sans Authorization.
    uri = f"sip:{HOST}:{PORT}"
    msg = _sip_headers("REGISTER", uri, extra=[
        ("Contact", "<sip:leak-probe@127.0.0.1:5060>;expires=300"),
    ])
    resp = _send_sip(msg)
    status, text = _parse_status(resp)
    result["response_status"] = status
    if status and (status.startswith("SIP/2.0 401")
                   or status.startswith("SIP/2.0 407")):
        result["challenge_received"] = True
        m = DIGEST_HEADER_RE.search(text)
        if m:
            params_str = m.group(1)
            params: dict[str, str] = {}
            for pm in DIGEST_PARAM_RE.finditer(params_str):
                key = pm.group(1)
                val = pm.group(2) if pm.group(2) is not None else pm.group(3)
                params[key] = val.strip()
            if "realm" in params:
                result["realm"] = params["realm"]
                result["digest_info_leaked"] = True
            if "nonce" in params:
                result["nonce"] = params["nonce"]
                result["digest_info_leaked"] = True
            if "algorithm" in params:
                result["algorithm"] = params["algorithm"]
            if "qop" in params:
                result["qop"] = params["qop"]
    return result


# ─── Synthèse JSON ──────────────────────────────────────────────────
def main() -> None:
    # 1. LAB guard.
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "lab": False,
            "error": "LAB guard not satisfied",
            "detail": ("Set LAB=1 to confirm lab authorization. SIP probing on "
                       "production PBX/VoIP infra is illegal (Art. 323-1)."),
            "legal_note": ("Art. 323-1 Code pénal — toll fraud SIP illégal. "
                           "Lab isolé uniquement."),
        }, indent=2))
        sys.exit(1)

    # 2. Exécution des 5 checks (timeout 5s chacun).
    register = send_register()
    options = send_options()
    enum = check_enum()
    toll = test_toll_fraud()
    digest = check_sip_digest_leak()

    # 3. Synthèse JSON stdout.
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "lab": True,
        "safe_mode": SAFE_MODE,
        "target": HOST,
        "port": PORT,
        "timeout_s": TIMEOUT_S,
        # Champs de sortie attendus (spec) :
        "register_accepted": bool(register.get("register_accepted")),
        "server_fingerprint": options.get("server_fingerprint"),
        "enum_enabled": bool(enum.get("enum_enabled")),
        "toll_fraud_risk": bool(toll.get("toll_fraud_risk")),
        "digest_info_leaked": bool(digest.get("digest_info_leaked")),
        # Détails structurés pour le rapport :
        "details": {
            "register": register,
            "options": options,
            "enum": enum,
            "toll_fraud": toll,
            "digest_leak": digest,
        },
        "regulations": ["ETSI", "RGPD", "NIS2", "GSMA FS"],
        "legal_note": ("Toll fraud SIP sur PBX en production : Art. 323-1 Code pénal. "
                       "Le test toll_fraud n'est exécuté qu'en SAFE_MODE=full (lab)."),
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
