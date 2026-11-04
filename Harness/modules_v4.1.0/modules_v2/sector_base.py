#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — Base sectorielle.
# Fournit la configuration sectorielle (HVT_KEYWORDS, PORT_MAP, SAFE_MODE)
# sélectionnable via la variable d'environnement SECTOR.
#
# Secteurs supportés :
#   it       — IT générique (défaut, comportement v2.x)
#   ot       — SCADA / Systèmes industriels (ICS/OT)
#   banking  — Bancaire (SWIFT, core banking, cartes)
#   health   — Santé (DICOM, HL7, dispositifs médicaux)
#   energy   — Énergie / Utilities (IEC104, DNP3, BACnet)
#   telecom  — Télécom (SS7, SIP, Diameter)
#   crypto   — Crypto-exchange (geth RPC, Web3)
#
# Usage dans les modules :
#   from sector_base import get_sector_config, HVT_KEYWORDS, PORT_MAP, SAFE_MODE
#   sector = get_sector_config()  # dict avec toutes les configs du secteur
import os
import sys
from typing import Dict, List, Tuple

HARNESS_VERSION = "3.0.0"

# ─── Sélecteur de secteur ─────────────────────────────────────
VALID_SECTORS = ("it", "ot", "banking", "health", "energy", "telecom", "crypto")

def get_sector() -> str:
    """Retourne le secteur actif depuis SECTOR env var (défaut: it)."""
    s = os.environ.get("SECTOR", "it").lower().strip()
    if s not in VALID_SECTORS:
        print(f"[sector_base] SECTOR='{s}' invalide. Valides: {VALID_SECTORS}",
              file=sys.stderr)
        sys.exit(2)
    return s

# ─── HVT_KEYWORDS par secteur ──────────────────────────────────
# High-Value Target keywords pour post_exploit_enum
_HVT_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "it": (
        "wallet", "signer", "key", "bitcoin", "ethereum", "geth", "parity",
        "node", "redis", "postgres", "mysql", "docker", "kubelet",
        "nginx", "apache", "jenkins", "grafana", "kibana",
    ),
    "ot": (
        # Historians
        "osipi", "wonderware", "ignition", "kepware", "avgae",
        # SCADA/DCS
        "wincc", "rslogix", "factorytalk", "clearscada", "intouch",
        # Engineering workstations
        "step7", "tia portal", "studio 5000", "cimplicity",
        # PLCs
        "plc", "s7", "modbus", "dnp3", "iec104", "opcua",
        # OT-specific
        "rtac", "relay", "scada", "hmi", "historian", "oms",
    ),
    "banking": (
        # Core banking
        "temenos", "finastra", "fiserv", "jack henry", "sap banking",
        # Trading/risk
        "murex", "calypso", "bloomberg", "reuters", "fidessa",
        # SWIFT
        "alliance", "swift", "saa",
        # Mainframe
        "cics", "racf", "vsam", "cobol", "ims",
        # Payment
        "hsm", "thales", "utimaco", "safenet",
    ),
    "health": (
        # EHR/HIS
        "epic", "meditech", "cerner", "allscripts", "athenahealth",
        # PACS/RIS
        "pacs", "ris", "dicom", "dcm4che", "orthanc",
        # LIS
        "lims", "laboratory",
        # Pharmacy
        "pyxis", "omnicell",
        # Devices
        "ventilator", "infusion", "monitor", "anesthesia",
    ),
    "energy": (
        # EMS/DMS
        "ems", "dms", "adms", "scada", "oms",
        # Historians
        "historian", "osipi", "proficy",
        # Controllers
        "rtac", "relay", "plc", "ied", "rtu",
        # Protection
        "sel", "abb", "siemens", "ge", "schneider",
    ),
    "telecom": (
        # Core
        "mme", "sgw", "pgw", "hss", "pcf", "upf", "smf", "amf",
        # VoIP
        "asterisk", "freeswitch", "kamailio", "opensips",
        # Signaling
        "diameter", "sigtran", "ss7", "sip",
        # OSS/BSS
        "billing", "provisioning", "inventory",
    ),
    "crypto": (
        # Nodes
        "geth", "parity", "erigon", "besu", "nethermind",
        # Wallets
        "wallet", "signer", "custody", "fireblocks", "bitgo",
        # Exchange
        "matching", "orderbook", "settlement", "clearing",
        # DeFi
        "uniswap", "aave", "compound", "maker",
        # Infra
        "ethereum", "bitcoin", "solana", "polygon",
    ),
}

# ─── PORT_MAP par secteur ──────────────────────────────────────
_PORT_MAP_BASE = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https",
    445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 5984: "couchdb", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

_PORT_MAP_OT = {
    **_PORT_MAP_BASE,
    102: "s7comm/mms",          # Siemens S7 / IEC 61850 MMS
    502: "modbus",              # Modbus TCP
    4840: "opcua",              # OPC-UA
    1089: "ff-annunc",          # Foundation Fieldbus
    1090: "ff-fms",
    1091: "ff-sm",
    2000: "ethernet-ip",        # EtherNet/IP (old)
    2404: "iec104",             # IEC 60870-5-104
    4878: "profinet-rtm",       # PROFINET RT
    5060: "sip",                # SIP (OT VoIP)
    9600: "omron-fins",         # OMRON FINS
    10001: "fox",               # Niagara Fox
    20000: "dnp3",              # DNP3
    34962: "profinet-cm",       # PROFINET Context Manager
    34964: "profinet-dcp",
    44818: "ethernet-ip",       # EtherNet/IP (CIP)
    1883: "mqtt",               # MQTT (IoT/IIoT telemetry)
    47808: "bacnet",            # BACnet
    50000: "isosentrotcp",      # Siemens ISO-on-TCP-RTL
}

_PORT_MAP_BANKING = {
    **_PORT_MAP_BASE,
    1433: "mssql",              # Core banking DB fréquemment MSSQL
    1521: "oracle",             # Oracle Financials / T24
    3270: "tn3270",             # Terminal IBM mainframe
    5250: "tn5250",             # IBM AS/400 iSeries
    8443: "finastra",           # Finastra Fusion
    9080: "temenos-t24",        # Temenos T24 jBase
    9443: "swift-alliance",     # SWIFT Alliance Access
    15000: "murex",             # Murex MX.3
    21000: "calypso",           # Calypso
}

_PORT_MAP_HEALTH = {
    **_PORT_MAP_BASE,
    104: "dicom",               # DICOM (imagerie médicale)
    111: "dicom-alt",           # DICOM alternatif
    2575: "hl7-mllp",           # HL7 MLLP v2
    8080: "fhir-api",           # FHIR REST API
    8443: "fhir-https",         # FHIR HTTPS
    5683: "coap",               # CoAP (IoT médical)
    1883: "mqtt",               # MQTT (IoT/IIoT telemetry)
    47808: "bacnet",            # BACnet (HVAC hôpitaux)
}

_PORT_MAP_ENERGY = {
    **_PORT_MAP_OT,  # Hérite du mapping OT
    2404: "iec104",             # IEC 60870-5-104 (énergie)
    20000: "dnp3",              # DNP3
    1883: "mqtt",               # MQTT (IoT/IIoT telemetry)
    47808: "bacnet",            # BACnet (bâtiments data center)
}

_PORT_MAP_TELECOM = {
    **_PORT_MAP_BASE,
    2905: "mgcp",               # MGCP
    2944: "mgcp-alt",
    3868: "diameter",           # Diameter
    5060: "sip",                # SIP
    5061: "sip-tls",            # SIP TLS
    3668: "qsig",
    1719: "h323-ras",           # H.323 RAS
    1720: "h323",               # H.323
    2727: "mgcp-sig",
    9443: "sbc",                # Session Border Controller
}

_PORT_MAP_CRYPTO = {
    **_PORT_MAP_BASE,
    8545: "geth-rpc",           # Ethereum JSON-RPC
    8546: "geth-ws",            # Ethereum WebSocket
    30303: "ethereum-p2p",      # Ethereum P2P
    13000: "erigon-grpc",       # Erigon gRPC
    9090: "erigon-snapshot",
    7878: "reth-rpc",           # Reth RPC
    9650: "avalanche",          # Avalanche
    8899: "solana-rpc",         # Solana RPC
    8000: "near-rpc",           # NEAR Protocol
    26657: "cosmos-rpc",        # Cosmos Hub
    1317: "tezos-rpc",          # Tezos
}

_PORT_MAP: Dict[str, Dict[int, str]] = {
    "it": _PORT_MAP_BASE,
    "ot": _PORT_MAP_OT,
    "banking": _PORT_MAP_BANKING,
    "health": _PORT_MAP_HEALTH,
    "energy": _PORT_MAP_ENERGY,
    "telecom": _PORT_MAP_TELECOM,
    "crypto": _PORT_MAP_CRYPTO,
}

# ─── SAFE_MODE par secteur ─────────────────────────────────────
# En OT/énergie/santé, l'écriture sur un équipement peut avoir des
# conséquences physiques. SAFE_MODE=read_only interdit toute écriture.
_SAFE_MODE: Dict[str, str] = {
    "it": "full",           # Lecture + écriture autorisées (lab)
    "crypto": "full",       # Lecture + écriture (lab deprotocole)
    "banking": "read_only", # Pas d'écriture sur core banking
    "health": "read_only",  # Pas d'écriture sur dispositifs médicaux
    "energy": "read_only",  # Pas de commande sur équipements électriques
    "telecom": "read_only", # Pas d'interception active
    "ot": "read_only",      # Pas d'écriture sur PLC/SCADA
}

# ─── Régulations par secteur ───────────────────────────────────
_REGULATIONS: Dict[str, Tuple[str, ...]] = {
    "it": ("RGPD", "ISO 27001"),
    "ot": ("NERC CIP", "NIS2", "IEC 62443"),
    "banking": ("DORA", "PCI-DSS", "PSD2", "SWIFT CSP"),
    "health": ("HIPAA", "HDS", "RGPD", "FDA 21 CFR Part 11"),
    "energy": ("NERC CIP", "NIS2", "ENISA"),
    "telecom": ("ETSI", "RGPD", "NIS2", "GSMA FS"),
    "crypto": ("PSAN-AMF", "RGPD", "Travel Rule FATF"),
}

# ─── API publique ──────────────────────────────────────────────
def get_sector_config() -> dict:
    """Retourne la configuration complète du secteur actif."""
    s = get_sector()
    return {
        "sector": s,
        "hvt_keywords": _HVT_KEYWORDS[s],
        "port_map": _PORT_MAP[s],
        "safe_mode": _SAFE_MODE[s],
        "regulations": _REGULATIONS[s],
        "harness_version": HARNESS_VERSION,
    }

def get_hvt_keywords() -> Tuple[str, ...]:
    return _HVT_KEYWORDS[get_sector()]

def get_port_map() -> Dict[int, str]:
    return _PORT_MAP[get_sector()]

def get_safe_mode() -> str:
    return _SAFE_MODE[get_sector()]

def is_write_allowed() -> bool:
    """Vérifie si les opérations d'écriture sont autorisées dans ce secteur."""
    return get_safe_mode() == "full"

def check_write_allowed(module_name: str) -> None:
    """Guard : exit si écriture interdite dans le secteur actif."""
    if not is_write_allowed():
        print(f'{{"module":"{module_name}","error":"write_not_allowed",'
              f'"sector":"{get_sector()}","safe_mode":"{get_safe_mode()}",'
              f'"reason":"Ce secteur est en read-only (impact physique possible)"}}')
        sys.exit(3)

if __name__ == "__main__":
    import json
    cfg = get_sector_config()
    print(json.dumps(cfg, indent=2, default=str))
