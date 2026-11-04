# HARNESS-VALIDATION v3.0.0 — Guide multi-secteur

## Vue d'ensemble

Harness de validation sécurité **multi-secteur**. 17 modules IT génériques + 19 modules sectoriels couvrant 6 secteurs : OT/SCADA, Banking, Santé, Énergie, Télécom, Crypto-exchange. Le moteur (orchestrateur, sandbox, signature HMAC) est universel — la sectorialisation se fait par configuration.

```
SECTOR=it       → 17 modules IT génériques (défaut)
SECTOR=ot       → modules SCADA (Modbus, S7, OPC-UA, DNP3)
SECTOR=banking  → modules bancaires (SWIFT, ISO8583, core banking)
SECTOR=health   → modules santé (DICOM, HL7, dispositifs médicaux)
SECTOR=energy   → modules énergie (IEC104, BACnet, DNP3)
SECTOR=telecom  → modules télécom (SS7, SIP, Diameter)
SECTOR=crypto   → modules crypto (geth RPC, Web3, DeFi)
```

## Architecture

```
modules_v2/
├── orchestrator.py          # v3.0 — sector-aware, HMAC signé, chain mode
├── sector_base.py           # NEW — SECTOR selector, HVT_KEYWORDS, PORT_MAP, SAFE_MODE
├── sandbox_runner.py        # 36 profils (17 IT + 19 sectoriels)
├── matrix.json              # IT générique (17 targets)
├── matrix_ot.json           # OT (6 targets)
├── matrix_banking.json      # Banking (6 targets)
├── matrix_health.json       # Health (6 targets)
├── matrix_energy.json       # Energy (6 targets)
├── matrix_telecom.json      # Telecom (6 targets)
├── modules_config.json      # IT générique
├── modules_config_*.json    # 5 configs sectorielles
├── requirements_*.txt       # 7 requirements sectoriels
├── sectors/
│   ├── ot/                  # modbus, s7comm, opcua, dnp3
│   ├── banking/             # swift, iso8583, core_banking
│   ├── health/              # dicom, hl7, med_device
│   ├── energy/              # iec104, bacnet
│   ├── telecom/             # ss7, sip
│   ├── crypto/              # geth_rpc, web3
│   └── jwt_oauth, websocket, supply_chain  # cross-sector
└── docker/
    └── sectors/             # 7 Dockerfiles sectoriels
```

## Utilisation par secteur

### IT générique (défaut)
```bash
export SEED=1337 LAB=1 REPORT_KEY="$(openssl rand -hex 32)"
python3 orchestrator.py
```

### OT/SCADA
```bash
export SEED=1337 LAB=1 SECTOR=ot REPORT_KEY="$(openssl rand -hex 32)"
python3 orchestrator.py
# Modules : modbus_probe, s7comm_probe, opcua_probe, dnp3_probe, post_exploit_enum, persistence
# SAFE_MODE=read_only (pas d'écriture sur PLC)
# Régulations : NERC CIP, NIS2, IEC 62443
```

### Banking
```bash
export SEED=1337 LAB=1 SECTOR=banking REPORT_KEY="$(openssl rand -hex 32)"
python3 orchestrator.py
# Modules : swift_probe, iso8583_probe, core_banking_probe, jwt_oauth_probe, post_exploit_enum, persistence
# SAFE_MODE=read_only (pas d'écriture sur core banking)
# Régulations : DORA, PCI-DSS, PSD2, SWIFT CSP
```

### Santé
```bash
export SEED=1337 LAB=1 SECTOR=health REPORT_KEY="$(openssl rand -hex 32)"
python3 orchestrator.py
# Modules : dicom_probe, hl7_probe, med_device_probe, jwt_oauth_probe, post_exploit_enum, persistence
# SAFE_MODE=read_only (pas d'écriture sur dispositifs médicaux)
# Régulations : HIPAA, HDS, RGPD, FDA 21 CFR Part 11
```

### Énergie
```bash
export SEED=1337 LAB=1 SECTOR=energy REPORT_KEY="$(openssl rand -hex 32)"
python3 orchestrator.py
# Modules : iec104_probe, dnp3_probe, bacnet_probe, modbus_probe, post_exploit_enum, persistence
# SAFE_MODE=read_only (PAS DE COMMANDE SUR ÉQUIPEMENTS ÉLECTRIQUES)
# Régulations : NERC CIP, NIS2, ENISA
```

### Télécom
```bash
export SEED=1337 LAB=1 SECTOR=telecom REPORT_KEY="$(openssl rand -hex 32)"
python3 orchestrator.py
# Modules : ss7_probe, sip_probe, jwt_oauth_probe, websocket_probe, post_exploit_enum, persistence
# SAFE_MODE=read_only (pas d'interception active)
# Régulations : ETSI, RGPD, NIS2, GSMA FS
```

### Crypto-exchange
```bash
export SEED=1337 LAB=1 SECTOR=crypto REPORT_KEY="$(openssl rand -hex 32)"
python3 orchestrator.py
# Modules IT + crypto : geth_rpc_probe, web3_probe, sqli, ssrf, docker_escape, gdb_extract, persistence
# SAFE_MODE=full (lecture + écriture en lab)
# Régulations : PSAN-AMF, RGPD, Travel Rule FATF
```

## SAFE_MODE par secteur

| Secteur | SAFE_MODE | Écriture autorisée | Raison |
|---|---|---|---|
| it | full | ✅ | Lab IT standard |
| crypto | full | ✅ | Tests de protocole blockchain |
| banking | read_only | ❌ | Pas d'écriture sur core banking |
| health | read_only | ❌ | Pas d'écriture sur dispositifs médicaux |
| energy | read_only | ❌ | Impact physique possible |
| telecom | read_only | ❌ | Pas d'interception active |
| ot | read_only | ❌ | Conséquences physiques irréversibles |

## Modules par secteur

### OT/SCADA (sectors/ot/)
| Module | Protocole | Port | Test |
|---|---|---|---|
| modbus_module.py | Modbus TCP | 502 | Read Device ID, read coils/registers, write (si full) |
| s7comm_module.py | Siemens S7 | 102 | Read SZL, read DB, write DB (si full) |
| opcua_module.py | OPC-UA | 4840 | GetEndpoints, anonymous access, browse, read |
| dnp3_module.py | DNP3 | 20000 | Link status, read Class 0, auth v5, operate (si full) |

### Banking (sectors/banking/)
| Module | Protocole | Port | Test |
|---|---|---|---|
| swift_module.py | SWIFT Alliance | 9443 | Alliance access, API endpoints, HSM, log integrity |
| iso8583_module.py | ISO 8583 | variable | Network mgmt, signon, unauthorized txn, vendor detect |
| core_banking_module.py | REST/SOAP | 443/9080 | Vendor detect, auth, enumeration, race condition |

### Santé (sectors/health/)
| Module | Protocole | Port | Test |
|---|---|---|---|
| dicom_module.py | DICOM | 104/111 | C-ECHO, C-FIND patient, C-MOVE, C-STORE (si full) |
| hl7_module.py | HL7 v2/FHIR | 2575/8080 | MLLP ADT, patient query, FHIR anonymous, consent |
| med_device_module.py | Multi | variable | Port scan, device fingerprint, URGENT/11, default creds |

### Énergie (sectors/energy/)
| Module | Protocole | Port | Test |
|---|---|---|---|
| iec104_module.py | IEC 60870-5-104 | 2404 | STARTDT, TESTFR, interrogation, single command (si full) |
| bacnet_module.py | BACnet/IP | 47808 | Who-Is, ReadProperty, ReadAnalogInputs, WriteProperty (si full) |

### Télécom (sectors/telecom/)
| Module | Protocole | Port | Test |
|---|---|---|---|
| ss7_module.py | SS7/Diameter | 2905/3868 | SCTP, Diameter CER, HSS detection, SMS interception risk |
| sip_module.py | SIP | 5060 | REGISTER, OPTIONS, fingerprint, ENUM, toll fraud risk |

### Crypto (sectors/crypto/)
| Module | Protocole | Port | Test |
|---|---|---|---|
| geth_rpc_module.py | Ethereum JSON-RPC | 8545 | Block number, accounts, personal API, admin API, sendTransaction |
| web3_module.py | Web3/DeFi | 8545 | Contract read, storage dump, reentrancy, flash loan, MEV |

### Cross-sector (sectors/)
| Module | Applique à | Test |
|---|---|---|
| jwt_oauth_module.py | Tous (REST API) | JWT decode, alg:none, algorithm confusion, kid injection, PKCE, expiry |
| websocket_module.py | Tous (temps réel) | Handshake, origin validation, injection, auth, cross-user leak |
| supply_chain_module.py | Tous (code source) | npm/pip/composer scan, typosquatting, install scripts, malicious, git deps |

## Déploiement sectoriel

```bash
# Déploiement OT
SECTOR=ot ./deploy.sh /opt/harness-ot
cd /opt/harness-ot
pip install -r requirements_ot.txt
docker build -t harness/ot -f docker/sectors/Dockerfile.ot .

# Déploiement banking
SECTOR=banking ./deploy.sh /opt/harness-banking
pip install -r requirements_banking.txt

# etc. pour chaque secteur
```

## Rapport signé multi-secteur

Le rapport HMAC-SHA-256 inclut maintenant le champ `sector` :
```json
{
  "harness_version": "3.0.0",
  "sector": "ot",
  "seed": 1337,
  "generated_at": 1730520000.123,
  "results": [...],
  "global_sha256": "...",
  "signature": "..."
}
```

Le rapport est reproductible avec le même `SEED` + `SECTOR` + `PYTHONHASHSEED=0`.

## Régulations par secteur

| Secteur | Régulations |
|---|---|
| it | RGPD, ISO 27001 |
| ot | NERC CIP, NIS2, IEC 62443 |
| banking | DORA, PCI-DSS, PSD2, SWIFT CSP |
| health | HIPAA, HDS, RGPD, FDA 21 CFR Part 11 |
| energy | NERC CIP, NIS2, ENISA |
| telecom | ETSI, RGPD, NIS2, GSMA FS |
| crypto | PSAN-AMF, RGPD, Travel Rule FATF |

## Cadre légal

Ce harness implémente des techniques offensives. Usage autorisé uniquement sur environnements labellisés (LAB=1). Référentiels : Art. 323-1 CP, ANSSI, NERC CIP, HIPAA, DORA, NIS2.
