# sectors/energy.py — Configuration secteur Énergie / Utilities
# Risque max : coupure réseau électrique, contamination eau, explosion.
# Régulation : NERC CIP (NA), NIS2 (EU), ENISA, IEC 62351.

HVT_KEYWORDS = (
    # Energy Management Systems
    "ems", "energy-management",
    "dms", "distribution-management",
    "adms", "advanced-distribution",
    "oms", "outage-management",
    # SCADA
    "scada", "clearscada",
    # Historians
    "osipi", "osisoft", "pi-server",
    "proficy", "ge-proficy", "ihistorian",
    # Protective relays
    "relay", "protective-relay",
    "sel", "schweitzer",
    "abb-relay",
    "siemens-relay",
    "ge-relay",
    # RTU / RTAC
    "rtu", "rtac",
    "sel-rtac",
    # Power plant specific
    "dcs", "distributed-control",
    "turbine", "generator",
    "boiler", "cooling-tower",
    # Grid operations
    "iso", "rto",           # Independent System Operator
    "agc", "avadnt",        # Automatic Generation Control
    "scada-rtu",
)

PORT_MAP = {
    # IT standard
    22: "ssh", 80: "http", 443: "https",
    502:  "modbus-tcp",     # Modbus (commun en énergie)
    2404: "iec-60870-104",  # IEC 104 (sous-stations électriques) — CRITIQUE
    20000:"dnp3",           # DNP3 (électricité, eau Amérique du Nord)
    4840: "opc-ua",         # OPC-UA (IIoT moderne)
    102:  "s7comm",         # Siemens (centrales, sous-stations)
    # Energy-specific
    4712: "iec-61850-mms",  # IEC 61850 MMS (Manufacturing Message Spec)
    102:  "iec-61850-mms-alt",
    38722:"iccptls",        # IEC 60870-5-104 over TLS
    19999:"synchrophasor",  # IEEE C37.118 synchrophasor (PMU)
    1234:"energy-legacy",   # Protocoles legacy variés
}

AIR_GAP_INDICATORS = (
    # Ponts IT/OT en énergie
    "pi-server",         # OSIsoft PI = pont IT/OT par design
    "historian",
    "opc-gateway",
    "energy-gateway",
    # Indicateurs de compromission grid
    "agc",               # Automatic Generation Control compromis = changement fréquence
    "scada-rtu",         # RTU compromis = commande physique directe
    "relay-controller",  # Relay = protection jeu de barres
)

MODULES = [
    # Modules génériques
    "osint_leak", "sqli", "ssrf", "preauth",
    "docker_escape", "gdb_extract", "post_exploit_enum",
    "persistence", "static_analysis",
    # ─── Modules énergie spécifiques ───
    "iec104_probe",       # IEC 60870-5-104 (sous-stations) — CRITIQUE
    "dnp3_probe",         # DNP3 (électricité, eau)
    "iec61850_probe",     # IEC 61850 (sous-stations modernes)
    "modbus_probe",       # Modbus (commun en énergie)
    "synchrophasor_probe",# IEEE C37.118 (PMU)
]

MATRIX_OVERRIDE = {
    "iec104_probe": {
        "expected": "summary.get('stations_found') is not None",
        "note": "stations_found > 0 = sous-stations accessibles. Disjoncteur commandable.",
    },
    "dnp3_probe": {
        "expected": "summary.get('authenticated') is not None",
        "note": "authenticated=False = DNP3 SA v5 non activé. Commande operate possible.",
    },
    "iec61850_probe": {
        "expected": "summary.get('ied_found') is not None",
        "note": "IED found = Intelligent Electronic Device accessible. GOOSE manipulable.",
    },
    "synchrophasor_probe": {
        "expected": "summary.get('pmu_found') is not None",
        "note": "PMU found = Phasor Measurement Unit accessible. Manipulation fréquence.",
    },
}

DOCKER_BASE_IMAGE = "python:3.11-slim"
READ_ONLY_DEFAULT = True   # Énergie : read-only OBLIGATOIRE (coupure possible)
CRITICAL_RISK = "physical"  # coupure réseau, explosion, contamination
REGULATION = "NERC CIP (NA), NIS2 (EU), ENISA, IEC 62351, IEC 61850-90-2"
