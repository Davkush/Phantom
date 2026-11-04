# sectors/health.py — Configuration secteur Santé / Hôpitaux
# Risque max : vie patient, fuite données médicales (PII + PHI).
# Régulation : HIPAA (US), HDS (FR), RGPD (EU), ISO 27799.

HVT_KEYWORDS = (
    # EHR / EMR (Electronic Health Records)
    "epic", "epic-systems",
    "meditech",
    "cerner", "oracle-cerner",
    "allscripts",
    "athena", "athenahealth",
    "nextgen",
    # Imaging (DICOM PACS)
    "pacs", "dcm4che", "orthanc", "ge-pacs", "philips-pacs",
    "ris", "radiology",
    "dicom",
    # Pharmacy / médicaments
    "pyxis", "bd-pyxis",
    "omnicell",
    # Lab
    "lims", "laboratory",
    "mysis",
    # Devices médicaux
    "ventilator", "respirator",
    "infusion", "pump",
    "monitor", "vitals",
    "anesthesia",
    # Infrastructure
    "hl7", "fhir",
    "mirth", "nextgen-mirth",  # Mirth Connect (HL7 integration engine)
)

PORT_MAP = {
    # IT standard
    22: "ssh", 80: "http", 443: "https",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    # ─── Spécifique santé ───
    104:   "dicom",         # DICOM (imagerie, non authentifié par défaut)
    111:   "dicom-tls",     # DICOM over TLS
    2575:  "hl7-mllp",      # HL7 v2 Minimum Lower Layer Protocol
    5050:  "hl7-v3",        # HL7 v3
    8080:  "fhir-api",      # FHIR R4 REST API
    7474:  "neo4j",         # Graph DB (parfois utilisé en recherche médicale)
    # Medical devices
    4000:  "medical-device",  # Plage commune devices médicaux
    4001:  "medical-device",
    4170:  "rx-machine",      # X-ray machine interface
    9100:  "printer-pacs",    # Imprimante DICOM
}

AIR_GAP_INDICATORS = (
    # Ponts entre réseau médical et IT bureautique
    "mirth-connect",     # Integration engine = pont par design
    "hl7-gateway",
    "dicom-gateway",
    "pacs-bridge",
    # Devices médicaux accessibles depuis IT
    "ventilator-web",
    "infusion-web",
    "monitor-dashboard",
)

MODULES = [
    # Modules génériques IT
    "osint_leak", "sqli", "ssrf", "preauth", "waf_bypass",
    "docker_escape", "gdb_extract", "post_exploit_enum",
    "persistence", "fuzzer_send", "static_analysis",
    # ─── Modules santé spécifiques ───
    "dicom_probe",        # DICOM (port 104) — imagerie
    "hl7_probe",          # HL7 v2/v3 + FHIR (ports 2575, 8080)
    "med_device_probe",   # Dispositifs médicaux connectés
]

MATRIX_OVERRIDE = {
    "dicom_probe": {
        "expected": "summary.get('patients_accessible') is not None",
        "note": "patients_accessible > 0 = dump imagerie sans auth. HIPAA violation.",
    },
    "hl7_probe": {
        "expected": "summary.get('messages_intercepted') is not None",
        "note": "HL7 en clair sur MLLP = interception données patient. HDS violation.",
    },
    "med_device_probe": {
        "expected": "summary.get('devices_found') is not None",
        "note": "devices_found > 0 = dispositifs accessibles. URGENT/11 CVE check.",
    },
}

DOCKER_BASE_IMAGE = "python:3.11-slim"
READ_ONLY_DEFAULT = True   # Santé : read-only obligatoire (vie patient)
CRITICAL_RISK = "patient_safety"  # modification images → faux diagnostic, dosage
REGULATION = "HIPAA (US), HDS (FR), RGPD (EU), ISO 27799, FDA 510(k)"
