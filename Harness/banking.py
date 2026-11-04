# sectors/banking.py — Configuration secteur bancaire (hors crypto)
# Risque max : fraude virement, vol données cartes, compromission core banking.
# Régulation : DORA (EU), PCI-DSS, Bâle III, SWIFT CSP.

HVT_KEYWORDS = (
    # Core banking
    "temenos", "t24",
    "finastra", "fusion",
    "fiserv", "dna",
    "jack-henry", "silverlake",
    "sap-banking", "bank-analyzer",
    # Trading/risk
    "murex", "mx3",
    "calypso",
    "bloomberg", "bval",
    "reuters", "eikon", "elektron",
    "fidessa",
    "summit",
    # SWIFT
    "swift", "alliance", "saa",
    "swift-alliance-access",
    # Cards/payments
    "base24", "connections",
    "hsm", "thales", "utimaco",
    # Middleware
    "tibco", "webmethods", "mule",
    # Mainframe
    "cics", "racf", "vsam",
    "db2", "ims",
)

PORT_MAP = {
    # IT standard
    22: "ssh", 80: "http", 443: "https",
    1433: "mssql",         # Core banking DB fréquemment MSSQL
    1521: "oracle",        # Oracle Financials / T24
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    7001: "weblogic",      # Oracle WebLogic (banques)
    8443: "https-alt",
    9080: "websphere",     # IBM WebSphere
    9443: "swift-alliance",# SWIFT Alliance Access
    # ─── Spécifique banking ───
    3270: "tn3270",        # Terminal IBM mainframe (COBOL banking)
    5250: "tn5250",        # IBM AS/400 (iSeries banking)
    8443: "finastra",      # Finastra Fusion
    9080: "temenos-t24",   # Temenos T24
    15000: "murex",        # Murex MX.3
    21000: "calypso",      # Calypso
    2575: "hl7-mllp",      # (si pont avec santé pour assurance)
    # HSM
    3000: "thales-hsm",    # Thales payShield
    3001: "utimaco-hsm",   # Utimaco SecurityServer
}

AIR_GAP_INDICATORS = (
    # Ponts entre réseau bancaire et externe
    "swift-gateway",
    "payment-gateway",
    "core-banking-gateway",
    "dmz-banking",
    # Mainframe accessible depuis réseau distribué
    "tn3270",
    "cics",
    "racf",
)

MODULES = [
    # Modules génériques IT
    "osint_leak", "sqli", "ssrf", "preauth", "waf_bypass",
    "docker_escape", "gdb_extract", "post_exploit_enum",
    "persistence", "fuzzer_send", "static_analysis",
    # ─── Modules banking spécifiques ───
    "swift_probe",         # SWIFT Alliance Access (port 9443)
    "iso8583_probe",       # ISO 8583 transactions cartes
    "core_banking_probe",  # APIs SOAP/REST cores (T24, Finastra)
    "open_banking_probe",  # PSD2 / Open Banking (FAPI)
]

MATRIX_OVERRIDE = {
    "swift_probe": {
        "expected": "summary.get('alliance_accessible') is not None",
        "note": "Alliance Access accessible = vecteur fraude Bangladesh Bank type.",
    },
    "iso8583_probe": {
        "expected": "summary.get('response_code_forged') is not None",
        "note": "Response code '00' forgé = transaction approuvée illégalement.",
    },
    "core_banking_probe": {
        "expected": "summary.get('transfer_tested') is not None",
        "note": "Transfer API testée. Race condition = double-spend bancaire.",
    },
    "open_banking_probe": {
        "expected": "summary.get('fapi_compliant') is not None",
        "note": "FAPI non compliant = non-conformité PSD2. mTLS obligatoire.",
    },
}

DOCKER_BASE_IMAGE = "python:3.11-slim"
READ_ONLY_DEFAULT = False
CRITICAL_RISK = "financial"  # fraude virement, vol données cartes
REGULATION = "DORA (EU), PCI-DSS, Bâle III, SWIFT CSP, RGPD"
