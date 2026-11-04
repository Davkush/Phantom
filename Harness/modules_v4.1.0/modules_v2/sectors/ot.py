# sectors/ot.py — Configuration secteur SCADA / ICS / OT (systèmes industriels)
# Risque max : impact physique (coupure électrique, contamination eau, explosion).
# Régulation : NERC CIP (Amérique du Nord), NIS2 (EU), IEC 62443.

HVT_KEYWORDS = (
    # Historians (pont IT/OT)
    "osipi", "osisoft", "pi-server",
    "wonderware", "aveva",
    "ignition",
    "kepware", "ptc-kepware",
    # SCADA / DCS / HMI
    "wincc", "simatic",
    "rslogix", "factorytalk", "rockwell",
    "clearscada", "schneider",
    "intouch",
    "cimplicity", "ge-cimplicity",
    # Engineering workstations
    "step7", "tia-portal", "tia_portal",
    "studio5000", "studio-5000",
    # PLC runtime
    "plc", "s7", "controller",
    # OT security gateways
    "oproxd", "onetech",
)

PORT_MAP = {
    # IT hérité
    22: "ssh", 80: "http", 443: "https",
    135: "rpc-dcom",
    139: "smb", 445: "smb",
    1433: "mssql",  # WinCC DB fréquente
    3389: "rdp",
    # ─── Protocoles OT spécifiques ───
    102:   "s7comm-mms",       # Siemens S7 / IEC 61131
    1089:  "ff-annunc",        # Foundation Fieldbus
    1090:  "ff-fms",
    1091:  "ff-sm",
    161:   "snmp",             # OT devices exposent SNMP
    502:   "modbus-tcp",       # Modbus TCP (non authentifié)
    2000:  "cspv4",            # CodeSys
    2404:  "iec-60870-104",    # IEC 60870-5-104 (énergie)
    3962:  "niagara-fox",      # Niagara Framework (Tridium)
    4840:  "opc-ua",           # OPC-UA (IIoT moderne)
    5094:  "osa-cb",           # OSA-CB
    7878:  "codesys-webvisu",  # CodeSys WebVisu
    9600:  "omron-fins",       # OMRON FINS
    19150: "tridium-fox",      # Tridium Fox
    20000: "dnp3",             # DNP3 (énergie, eau)
    34962: "profinet-rtm",     # PROFINET RT-M
    34964: "profinet-dcp",     # PROFINET DCP
    44818: "ethernet-ip",      # EtherNet/IP (Allen-Bradley)
    1883:  "mqtt",              # MQTT (IoT/IIoT telemetry)
    47808: "bacnet",           # BACnet (bâtiments/HVAC)
    4822:  "melsoft",          # Mitsubishi MELSOFT
}

AIR_GAP_INDICATORS = (
    # Ponts IT/OT — si présents, l'air gap est compromis
    "historian",         # OSIsoft PI, Wonderware — pont par design
    "dmz",               # Zone démilitarisée IT/OT
    "gateway",           # OT security gateway
    "data-diode",        # Diode de données (unidirectionnel)
    # Processus indiquant un reachable OT depuis IT
    "opc-da",            # OLE for Process Control (pont Windows/OT)
    "modbus-gateway",    # Pont TCP Modbus
    "edge-gateway",      # Edge computing OT
)

MODULES = [
    # Modules génériques IT (réseau IT autour de l'OT)
    "osint_leak", "sqli", "ssrf", "preauth",
    "docker_escape", "gdb_extract", "post_exploit_enum",
    "persistence", "static_analysis",
    # ─── Modules OT spécifiques ───
    "modbus_probe",       # Modbus TCP (port 502)
    "dnp3_probe",         # DNP3 (port 20000)
    "s7comm_probe",       # Siemens S7 (port 102)
    "opcua_probe",        # OPC-UA (port 4840)
    "iec104_probe",       # IEC 60870-5-104 (port 2404)
    "bacnet_probe",       # BACnet (port 47808)
    "ethernetip_probe",   # EtherNet/IP (port 44818)
]

MATRIX_OVERRIDE = {
    "modbus_probe": {
        "expected": "summary.get('device_identified') is not None",
        "note": "device_identified sans auth = absence de sécurité de base. Critique NERC CIP.",
    },
    "s7comm_probe": {
        "expected": "summary.get('read_ok') is not None",
        "note": "lecture sans auth = réseau OT non segmenté. Stuxnet vector.",
    },
    "dnp3_probe": {
        "expected": "summary.get('authenticated') is not None",
        "note": "authenticated=False = DNP3 SA v5 non activé. Critique énergie.",
    },
    "opcua_probe": {
        "expected": "summary.get('auth_mode') is not None",
        "note": "auth_mode=None = OPC-UA sans auth. Accès direct aux variables.",
    },
    "iec104_probe": {
        "expected": "summary.get('stations_found') is not None",
        "note": "stations_found > 0 = sous-stations accessibles. Coupure possible.",
    },
    "bacnet_probe": {
        "expected": "summary.get('devices_found') is not None",
        "note": "devices_found > 0 = BACnet exposé. HVAC contrôlable.",
    },
    "ethernetip_probe": {
        "expected": "summary.get('devices_found') is not None",
        "note": "Allen-Bradley devices accessibles. Modification setpoints possible.",
    },
}

DOCKER_BASE_IMAGE = "python:3.11-slim"
READ_ONLY_DEFAULT = True   # OT : read-only obligatoire en production
CRITICAL_RISK = "physical"  # conséquences physiques potentiellement irréversibles
REGULATION = "NERC CIP (NA), NIS2 (EU), IEC 62443, ISO/IEC 27019"
