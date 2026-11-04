# HARNESS-VALIDATION v3.0.0 — Guide Multi-Sectoriel

## Vue d'ensemble

Harness de validation sécurité **multi-sectoriel** — 7 secteurs supportés via une architecture
"sectoriel par configuration". Le moteur (orchestrateur, sandbox, rapport signé HMAC) est générique ;
ce qui change par secteur : protocoles, HVT keywords, port maps, matrix, Dockerfiles.

**17 modules génériques** (IT/crypto) + **22 modules protocoles** sectoriels = **39 modules au total**.

## Secteurs supportés

```
SECTOR=crypto    → Crypto Exchange (geth RPC, wallet extraction, 10 modules)
SECTOR=ot        → SCADA / ICS / OT (Modbus, DNP3, S7comm, OPC-UA, IEC104, BACnet, EtherNet/IP, 11 modules)
SECTOR=banking   → Bancaire (SWIFT, ISO 8583, core banking, open banking PSD2, JWT/OAuth, 10 modules)
SECTOR=health    → Santé (DICOM, HL7/FHIR, medical devices, 8 modules)
SECTOR=energy    → Énergie (IEC 61850, synchrophasor, IEC104, DNP3, Modbus, 9 modules)
SECTOR=telecom   → Télécom (SS7, SIP, WebSocket, JWT/OAuth, 8 modules)
SECTOR=it        → IT générique (défaut, comportement v2.x, 17 modules)
```

## Architecture

```
modules_v2/
├── orchestrator.py          # Moteur générique — HMAC, safe_eval, LAB guard
├── sector_base.py           # Config sectorielle (HVT, ports, safe_mode, régulations)
├── sandbox_runner.py        # Isolation Docker (17+ profils)
├── matrix.json              # Matrix générique (IT)
├── matrix_<sector>.json     # Matrix sectorielles (6 fichiers)
├── modules_config.json      # Config modules générique
├── modules_config_<sector>.json  # Configs sectorielles (6 fichiers)
│
├── protocols/               # 22 modules protocoles sectoriels
│   ├── ot/                  # 7 modules: modbus, dnp3, s7comm, opcua, iec104, bacnet, ethernetip
│   ├── banking/             # 5 modules: swift, iso8583, core_banking, open_banking, jwt_oauth
│   ├── crypto/              # 2 modules: eth_rpc, wallet_extract
│   ├── health/              # 3 modules: dicom, hl7, med_device
│   ├── energy/              # 2 modules: iec61850, synchrophasor
│   └── telecom/             # 3 modules: ss7, sip, websocket
│
├── sectors/                 # Configs Python par secteur (HVT keywords, port maps)
│   ├── crypto.py, ot.py, banking.py, health.py, energy.py
│
├── docker/                  # 23 Dockerfiles
│   ├── Dockerfile.ot-protocols, Dockerfile.banking-protocols, ...
│   └── Dockerfile.sector-base (universal, tous protocoles)
│
├── osint_leak.py            # Phase 1: OSINT/leak detection
├── sqli_module.py           # Phase 2: SQL injection
├── ssrf_module.py           # Phase 2: SSRF
├── preauth.py               # Phase 2: Command injection
├── waf_bypass.py            # Phase 2: WAF bypass
├── docker_escape.py         # Phase 3: Container escape
├── gdb_extract.sh + .py     # Phase 3: Memory extraction
├── post_exploit_enum.py     # Phase 3: Local enumeration
├── persistence_module.py    # Phase 4: Persistence (LAB=1 required)
├── c_heap_exploit.c         # Phase 2: Heap exploit glibc 2.31
├── php_uaf.php              # Phase 2: PHP UAF
├── php_chain.php            # Phase 2: Deserialization chain
├── fuzzer_send.py           # Fuzzing HTTP
├── fuzz_module.py           # Fuzzing AFL++
├── llm_exploit_loop.py      # LLM exploit loop
└── static_analysis.py       # Semgrep + CodeQL
```

## Utilisation

### Déploiement par secteur

```bash
# 1. Sélectionner le secteur
export SECTOR=ot          # ou crypto, banking, health, energy, telecom, it

# 2. Générer la clé de signature
export REPORT_KEY="$(openssl rand -hex 32)"

# 3. Activer le mode lab
export LAB=1

# 4. Lancer le harness
python3 orchestrator.py

# → Charge automatiquement:
#   - modules_config_<sector>.json (liste des modules du secteur)
#   - matrix_<sector>.json (expressions expected sectorielles)
#   - sector_base.py (HVT keywords, port maps, safe_mode)
#   - SECTOR propagé aux modules enfants
```

### Mode read-only (OT/Health/Energy)

Les secteurs OT, Health et Energy sont en **read_only par défaut** — les modules ne font
aucune écriture sur les équipements (pas de Modbus write, pas de DNP3 operate, pas de
commande disjoncteur). Pour activer l'écriture en lab isolé :

```bash
export SAFE_MODE=full  # Override — DANGEREUX en production
```

### Rapport signé

```bash
# Vérifier un rapport
python3 -c "
from orchestrator import verify_report_file
print(verify_report_file('reports/report_1337.json', b'$REPORT_KEY'))
"
```

## Tableau comparatif sectoriel

```
Secteur     Protocoles              Ports clés     Risque max         Régulation
──────────────────────────────────────────────────────────────────────────────────
crypto      HTTP/JSON-RPC           8545,30303     Vol clés/fonds     PSAN-AMF, MiCA
ot          Modbus,DNP3,S7,OPC-UA   502,102,4840   Impact physique    NERC CIP, NIS2
banking     SWIFT,ISO8583,FAPI      9443,1521      Fraude virement    DORA, PCI-DSS
health      DICOM,HL7,FHIR          104,2575       Vie patient        HIPAA, HDS
energy      IEC104,IEC61850,PMU     2404,102       Coupure réseau     NERC CIP, NIS2
telecom     SS7,SIP,WebSocket       2905,5060      Interception comm. ETSI, RGPD
it          HTTP,SQL,Docker         80,443,3306    Standard           ISO 27001, RGPD
```

## Dockerfiles

| Image | Secteur | Libraries |
|---|---|---|
| `harness/sector-base` | Universal | pymodbus, pydicom, iso8583, mnemonic, requests |
| `harness/ot-protocols` | OT | pymodbus, pycomm3, BAC0, python-snap7, asyncua |
| `harness/banking-protocols` | Banking | iso8583, cryptography, requests |
| `harness/health-protocols` | Health | pydicom, pynetdicom, hl7apy, requests |
| `harness/energy-protocols` | Energy | pymodbus (raw-socket fallback) |
| `harness/crypto-protocols` | Crypto | web3, eth-account, mnemonic |

## Cadre légal

Ce harness implémente des techniques offensives. Il ne doit être exécuté que sur des
environnements explicitement autorisés (LAB=1). Référentiels par secteur :

- **OT/Energy** : NERC CIP, NIS2, IEC 62443 — impact physique possible
- **Banking** : DORA, PCI-DSS, SWIFT CSP — fraude financière
- **Health** : HIPAA, HDS, RGPD — données médicales + vie patient
- **Crypto** : PSAN-AMF, MiCA, Travel Rule FATF
- **Tous** : Art. 323-1 CP (France), autorisation obligatoire
