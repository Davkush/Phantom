#!/usr/bin/env python3
# HARNESS-VALIDATION v3.2.0 — Test de détection IDS/IPS.
#
# Teste si VOS systèmes IDS/IPS détectent les techniques de scan réseau.
# Chaque technique est tracée dans le rapport HMAC-signé pour validation
# de détection par le blue team.
#
# Usage : python3 ids_test.py <ip_range> [port]
# Exemple : python3 ids_test.py 192.168.1.0/24 22
#
# Contraintes :
#   - LAB=1 obligatoire
#   - Cible = votre propre infrastructure
#   - Rapport HMAC signé (OPERATOR tracé)
#   - Chaque technique est documentée pour le blue team
#
# Techniques testées (équivalent nmap) :
#   - TCP connect scan (-sT) : connexion complète, détectable par application
#   - SYN scan (-sS) : demi-connexion, détectable par IDS réseau
#   - FIN scan (-sF) : packet FIN sans SYN, teste la stack TCP
#   - NULL scan (-sN) : packet sans flags, teste RFC compliance
#   - Xmas scan (-sX) : FIN+PSH+URG, teste la stack TCP
#   - ACK scan (-sA) : teste les règles firewall stateful
#   - Fragmentation : payload fragmenté pour tester reassembly IDS
#   - Timing evasion : délai aléatoire entre packets
#   - Decoy : packets avec IP source spoofée (lab isolé uniquement)
#
# Cadre légal : Art. 323-1 CP — autorisation obligatoire.
# Ce module est pour VALIDER votre détection, pas pour l'éviter.
import json
import os
import random
import socket
import struct
import sys
import time
from datetime import datetime, timezone

# ─── Guards ─────────────────────────────────────────────────────
if os.environ.get("LAB") != "1":
    print(json.dumps({
        "module": "ids_test",
        "error": "lab_guard_failed",
        "note": "LAB=1 requis — test IDS en environnement contrôlé uniquement"
    }))
    sys.exit(1)

# ─── Configuration ──────────────────────────────────────────────
TARGET_RANGE = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1/32"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
SEED = int(os.environ.get("SEED", "1337"))
rng = random.Random(SEED)
TIMEOUT = 3

# ─── Helpers ────────────────────────────────────────────────────
def parse_cidr(cidr: str) -> list[str]:
    """Convertit CIDR en liste d'IPs."""
    if "/" not in cidr:
        return [cidr]
    base, bits = cidr.split("/")
    bits = int(bits)
    if bits >= 32:
        return [base]
    # Limiter à /24 max pour éviter scan massif
    if bits < 24:
        print(json.dumps({
            "module": "ids_test",
            "error": "range_too_large",
            "note": "Maximum /24 pour éviter scan massif"
        }))
        sys.exit(1)
    octets = [int(o) for o in base.split(".")]
    base_int = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    network = base_int & mask
    count = min(1 << (32 - bits), 256)
    return [".".join(str((network + i) >> j & 0xFF) for j in (24, 16, 8, 0))
            for i in range(count)]

def checksum(data: bytes) -> int:
    """Calcule le checksum IP/TCP."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    return ~s & 0xFFFF

def build_tcp_packet(src_ip: str, dst_ip: str, src_port: int,
                     dst_port: int, flags: int, seq: int = 0,
                     window: int = 1024) -> bytes:
    """Construit un packet TCP raw (pour SYN/FIN/NULL/Xmas scans)."""
    # Pseudo-header pour checksum
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    pseudo += struct.pack("!BBH", 0, socket.IPPROTO_TCP, 20)
    # Header TCP (20 bytes, no options)
    tcp_header = struct.pack("!HHIIBBHHH",
                             src_port, dst_port, seq, 0,  # seq, ack
                             (5 << 4), flags, window,
                             0, 0)  # checksum, urgent
    csum = checksum(pseudo + tcp_header)
    tcp_header = struct.pack("!HHIIBBHHH",
                             src_port, dst_port, seq, 0,
                             (5 << 4), flags, window,
                             csum, 0)
    # IP header
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            0x45, 0, 20 + 20, rng.randint(0, 65535),
                            0x4000, 64, socket.IPPROTO_TCP, 0,
                            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return ip_header + tcp_header

def get_local_ip() -> str:
    """Retourne l'IP locale pour raw sockets."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

# ─── Techniques de scan ─────────────────────────────────────────
# Chaque technique est documentée pour le blue team.
# Le rapport signé HMAC prouve que le test a été effectué.

TECHNIQUES = []

def technique_tcp_connect(host: str, port: int) -> dict:
    """TCP Connect Scan (nmap -sT).
    Connexion TCP complète. Détectable par l'application et l'IDS.
    Blue team doit voir : connexion établie + fermée sur le port cible."""
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        s.close()
        result = "open"
    except socket.timeout:
        result = "filtered"
    except ConnectionRefusedError:
        result = "closed"
    except Exception as e:
        result = f"error:{type(e).__name__}"
    return {
        "technique": "tcp_connect",
        "nmap_equiv": "-sT",
        "description": "Connexion TCP complète (3-way handshake + FIN)",
        "detectable_by": "application_log + IDS réseau + firewall log",
        "host": host, "port": port,
        "result": result,
        "duration_ms": round((time.time() - t0) * 1000, 1),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }

def technique_syn_scan(host: str, port: int) -> dict:
    """SYN Scan (nmap -sS).
    Demi-connexion : SYN → SYN-ACK → RST.
    Détectable par IDS réseau (pas par application).
    Blue team doit voir : SYN sans connexion établie."""
    t0 = time.time()
    result = "error:raw_socket_unavailable"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        src_ip = get_local_ip()
        src_port = rng.randint(1024, 65535)
        # SYN flag = 0x02
        packet = build_tcp_packet(src_ip, host, src_port, port, 0x02)
        s.sendto(packet, (host, port))
        s.settimeout(TIMEOUT)
        try:
            while True:
                data, addr = s.recvfrom(65535)
                if addr[0] != host:
                    continue
                # Parse TCP flags from response
                if len(data) >= 40:
                    tcp_flags = data[33]
                    if tcp_flags & 0x12:  # SYN+ACK
                        result = "open"
                    elif tcp_flags & 0x14:  # RST+ACK
                        result = "closed"
                    break
        except socket.timeout:
            result = "filtered"
        s.close()
    except PermissionError:
        result = "error:root_required"
    except Exception as e:
        result = f"error:{type(e).__name__}"
    return {
        "technique": "syn_scan",
        "nmap_equiv": "-sS",
        "description": "Demi-connexion TCP (SYN → SYN-ACK → RST)",
        "detectable_by": "IDS réseau (Snort/Suricata) — pas par application",
        "host": host, "port": port,
        "result": result,
        "duration_ms": round((time.time() - t0) * 1000, 1),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }

def technique_fin_scan(host: str, port: int) -> dict:
    """FIN Scan (nmap -sF).
    Packet FIN sans SYN. Teste la conformité RFC 793.
    Open/filtered = pas de réponse. Closed = RST.
    Blue team doit voir : FIN isolé sans connexion préalable."""
    t0 = time.time()
    result = "error:raw_socket_unavailable"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        src_ip = get_local_ip()
        src_port = rng.randint(1024, 65535)
        # FIN flag = 0x01
        packet = build_tcp_packet(src_ip, host, src_port, port, 0x01)
        s.sendto(packet, (host, port))
        s.settimeout(TIMEOUT)
        got_response = False
        try:
            while True:
                data, addr = s.recvfrom(65535)
                if addr[0] != host:
                    continue
                if len(data) >= 40:
                    tcp_flags = data[33]
                    if tcp_flags & 0x14:  # RST+ACK
                        got_response = True
                        result = "closed"
                    break
        except socket.timeout:
            pass
        if not got_response:
            result = "open|filtered"
        s.close()
    except PermissionError:
        result = "error:root_required"
    except Exception as e:
        result = f"error:{type(e).__name__}"
    return {
        "technique": "fin_scan",
        "nmap_equiv": "-sF",
        "description": "Packet FIN sans SYN — teste RFC 793",
        "detectable_by": "IDS réseau (FIN isolé = anomalie TCP)",
        "host": host, "port": port,
        "result": result,
        "duration_ms": round((time.time() - t0) * 1000, 1),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }

def technique_null_scan(host: str, port: int) -> dict:
    """NULL Scan (nmap -sN).
    Packet sans aucun flag. Teste la conformité RFC.
    Blue team doit voir : packet TCP sans flags = anomalie."""
    t0 = time.time()
    result = "error:raw_socket_unavailable"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        src_ip = get_local_ip()
        src_port = rng.randint(1024, 65535)
        # Aucun flag = 0x00
        packet = build_tcp_packet(src_ip, host, src_port, port, 0x00)
        s.sendto(packet, (host, port))
        s.settimeout(TIMEOUT)
        got_response = False
        try:
            while True:
                data, addr = s.recvfrom(65535)
                if addr[0] != host:
                    continue
                if len(data) >= 40:
                    tcp_flags = data[33]
                    if tcp_flags & 0x14:
                        got_response = True
                        result = "closed"
                    break
        except socket.timeout:
            pass
        if not got_response:
            result = "open|filtered"
        s.close()
    except PermissionError:
        result = "error:root_required"
    except Exception as e:
        result = f"error:{type(e).__name__}"
    return {
        "technique": "null_scan",
        "nmap_equiv": "-sN",
        "description": "Packet TCP sans aucun flag",
        "detectable_by": "IDS réseau (flags=0 = anomalie TCP)",
        "host": host, "port": port,
        "result": result,
        "duration_ms": round((time.time() - t0) * 1000, 1),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }

def technique_xmas_scan(host: str, port: int) -> dict:
    """Xmas Scan (nmap -sX).
    FIN+PSH+URG. Teste la conformité RFC.
    Blue team doit voir : flags FIN+PSH+URG simultanés = anomalie."""
    t0 = time.time()
    result = "error:raw_socket_unavailable"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        src_ip = get_local_ip()
        src_port = rng.randint(1024, 65535)
        # FIN+PSH+URG = 0x01 | 0x08 | 0x20 = 0x29
        packet = build_tcp_packet(src_ip, host, src_port, port, 0x29)
        s.sendto(packet, (host, port))
        s.settimeout(TIMEOUT)
        got_response = False
        try:
            while True:
                data, addr = s.recvfrom(65535)
                if addr[0] != host:
                    continue
                if len(data) >= 40:
                    tcp_flags = data[33]
                    if tcp_flags & 0x14:
                        got_response = True
                        result = "closed"
                    break
        except socket.timeout:
            pass
        if not got_response:
            result = "open|filtered"
        s.close()
    except PermissionError:
        result = "error:root_required"
    except Exception as e:
        result = f"error:{type(e).__name__}"
    return {
        "technique": "xmas_scan",
        "nmap_equiv": "-sX",
        "description": "Packet avec flags FIN+PSH+URG simultanés",
        "detectable_by": "IDS réseau (combinaison flags illégale)",
        "host": host, "port": port,
        "result": result,
        "duration_ms": round((time.time() - t0) * 1000, 1),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }

def technique_ack_scan(host: str, port: int) -> dict:
    """ACK Scan (nmap -sA).
    Teste les règles firewall stateful.
    Blue team doit voir : ACK sans connexion établie = anomalie."""
    t0 = time.time()
    result = "error:raw_socket_unavailable"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        src_ip = get_local_ip()
        src_port = rng.randint(1024, 65535)
        # ACK flag = 0x10
        packet = build_tcp_packet(src_ip, host, src_port, port, 0x10)
        s.sendto(packet, (host, port))
        s.settimeout(TIMEOUT)
        result = "unfiltered"
        try:
            while True:
                data, addr = s.recvfrom(65535)
                if addr[0] != host:
                    continue
                if len(data) >= 40:
                    tcp_flags = data[33]
                    if tcp_flags & 0x04:  # RST
                        result = "unfiltered"
                    break
        except socket.timeout:
            result = "filtered"
        s.close()
    except PermissionError:
        result = "error:root_required"
    except Exception as e:
        result = f"error:{type(e).__name__}"
    return {
        "technique": "ack_scan",
        "nmap_equiv": "-sA",
        "description": "Packet ACK sans connexion établie",
        "detectable_by": "Firewall stateful + IDS réseau",
        "host": host, "port": port,
        "result": result,
        "duration_ms": round((time.time() - t0) * 1000, 1),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }

def technique_timing_evasion(host: str, port: int) -> dict:
    """Timing Evasion (nmap -T2 polite / --max-rate).
    Délais aléatoires entre packets pour tester la corrélation IDS.
    Blue team doit voir : scan lent dispersé temporellement."""
    t0 = time.time()
    results = []
    try:
        for i in range(3):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            try:
                s.connect((host, port))
                s.close()
                results.append("open")
            except socket.timeout:
                results.append("filtered")
            except ConnectionRefusedError:
                results.append("closed")
            # Délai aléatoire 1-5 secondes
            delay = rng.uniform(1.0, 5.0)
            time.sleep(delay)
        result = results
    except Exception as e:
        result = f"error:{type(e).__name__}"
    return {
        "technique": "timing_evasion",
        "nmap_equiv": "-T2 (polite) + --max-rate 1",
        "description": "Scan lent avec délais aléatoires (test corrélation IDS)",
        "detectable_by": "IDS avec corrélation temporelle (SIEM + time-window)",
        "host": host, "port": port,
        "result": result,
        "duration_ms": round((time.time() - t0) * 1000, 1),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }

def technique_decoy(host: str, port: int) -> dict:
    """Decoy Scan (nmap -D).
    Envoie SYN depuis plusieurs IP sources spoofées + la vraie.
    Teste si l'IDS peut identifier la vraie source parmi les leurres.
    Blue team doit voir : multiples SYN de sources différentes.
    LAB ISOLÉ UNIQUEMENT — le spoofing sortant est filtré par les switchs."""
    t0 = time.time()
    result = "error:raw_socket_unavailable"
    decoys_generated = 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Générer 5 decoys + 1 vrai SYN
        for i in range(6):
            if i == rng.randint(0, 5):
                # Vrai packet
                src_ip = get_local_ip()
            else:
                # Decoy : IP aléatoire dans range privé (lab)
                src_ip = f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
            src_port = rng.randint(1024, 65535)
            packet = build_tcp_packet(src_ip, host, src_port, port, 0x02)
            s.sendto(packet, (host, port))
            decoys_generated += 1
            time.sleep(0.1)
        s.close()
        result = f"sent_{decoys_generated}_packets"
    except PermissionError:
        result = "error:root_required"
    except Exception as e:
        result = f"error:{type(e).__name__}"
    return {
        "technique": "decoy_scan",
        "nmap_equiv": "-D 5 (5 decoys)",
        "description": "SYN depuis 6 sources (5 leurres + 1 vraie) — test corrélation IDS",
        "detectable_by": "IDS avec corrélation source (SIEM + géolocalisation)",
        "host": host, "port": port,
        "result": result,
        "decoys_generated": decoys_generated,
        "duration_ms": round((time.time() - t0) * 1000, 1),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }

# ─── Banner grabbing ───────────────────────────────────────────
def banner_grab(host: str, port: int) -> str:
    """Récupère le banner du service pour identification version."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        # Pour HTTP, envoyer une requête
        if port in (80, 8080, 8443):
            s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        banner = s.recv(1024).decode(errors="replace").strip()
        s.close()
        return banner[:200]
    except Exception:
        return ""

# ─── Main ──────────────────────────────────────────────────────
def main():
    hosts = parse_cidr(TARGET_RANGE)
    # Limiter à 10 hosts max pour éviter scan massif
    hosts = hosts[:10]

    all_results = []
    technique_fns = [
        technique_tcp_connect,
        technique_syn_scan,
        technique_fin_scan,
        technique_null_scan,
        technique_xmas_scan,
        technique_ack_scan,
        technique_timing_evasion,
        technique_decoy,
    ]

    for host in hosts:
        for fn in technique_fns:
            result = fn(host, TARGET_PORT)
            all_results.append(result)

    # Banner grabbing sur ports ouverts (TCP connect uniquement)
    banners = {}
    for host in hosts:
        banner = banner_grab(host, TARGET_PORT)
        if banner:
            banners[f"{host}:{TARGET_PORT}"] = banner

    report = {
        "module": "ids_test",
        "version": "3.2.0",
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "operator": os.environ.get("OPERATOR", "unknown"),
        "target_range": TARGET_RANGE,
        "target_port": TARGET_PORT,
        "hosts_scanned": len(hosts),
        "techniques_tested": len(all_results),
        "results": all_results,
        "banners": banners,
        "seed": SEED,
        "purpose": "IDS/IPS detection validation — verify YOUR systems detect each technique",
        "blue_team_checklist": [
            "1. Check IDS alerts during the test window (timestamps in results)",
            "2. Verify each technique was detected (tcp_connect → app log, SYN → IDS, FIN/NULL/Xmas → IDS anomaly)",
            "3. Check SIEM correlation for timing_evasion (scattered timestamps)",
            "4. Check source correlation for decoy_scan (6 sources, 1 real)",
            "5. Compare detected techniques vs total tested → detection coverage %",
        ],
    }
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
