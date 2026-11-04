#!/usr/bin/env python3
# HARNESS-VALIDATION v2.7.0 — osint_leak : reconnaissance & fuite de secrets (Phase 1).
# Python 3.10+. Read-only recon — aucune action destructive.
#
# Comble le gap Phase 1 (Reconnaissance) du harness :
#   1. Certificate Transparency (crt.sh) — énumération de sous-domaines via les SANs.
#   2. Détection de fuites — GitHub Code Search API si GITHUB_TOKEN présent,
#      sinon scan local d'un répertoire (argv[2] ou ./source) pour motifs de secrets.
#   3. Fichiers exposés — vérification des chemins communs sur la cible (lab: 127.0.0.1).
#   4. Brute-force DNS — wordlist intégrée, résolution via socket.getaddrinfo.
#
# Sécurité lab :
#   - Toutes les requêtes réseau vont vers 127.0.0.1 ou des APIs publiques légitimes
#     (crt.sh, api.github.com). Aucune exploitation, uniquement lecture.
#   - SEED env var : RNG déterministe pour ordre d'énumération reproductible.
#   - Timeouts courts sur chaque requête ; rate-limiting crt.sh géré par retry/backoff.
#   - GITHUB_TOKEN n'est jamais loggé ni inclus dans la sortie JSON.
#
# Usage :
#   python3 osint_leak.py <domain> [github_org|local_dir]
#   SEED=1337 python3 osint_leak.py example.com ./source
import json
import os
import random
import re
import socket
import sys
import time
from pathlib import Path

import requests

HARNESS_VERSION = "2.7.0"
MODULE_NAME = "osint_leak"

# ─── Arguments & environnement ────────────────────────────────────
TARGET_DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "example.com"
# argv[2] est surchargé : org GitHub si GITHUB_TOKEN présent, sinon chemin local.
ARGV2 = sys.argv[2] if len(sys.argv) > 2 else None

SEED = int(os.environ.get("SEED", "1337"))
# RNG déterministe — utilisé pour l'ordre d'énumération (shuffle reproductible).
random.seed(SEED)

# Lab target : la cible HTTP est attendue sur 127.0.0.1 (aucune sortie externe).
LAB_HOST = os.environ.get("LAB_HOST", "127.0.0.1")
LAB_PORT = int(os.environ.get("LAB_PORT", "8080"))
LAB_BASE = f"http://{LAB_HOST}:{LAB_PORT}"

# crt.sh — API publique Certificate Transparency (légitime, lecture seule).
CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"
CRT_SH_TIMEOUT = 15
CRT_SH_MAX_RETRIES = 3

# GitHub Code Search API — requiert un token (jamais loggé).
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_API = "https://api.github.com/search/code"
GITHUB_TIMEOUT = 15

# ─── Motifs de secrets & fichiers sensibles ───────────────────────
# Ordre important : on teste les motifs les plus spécifiques d'abord.
SECRET_PATTERNS = [
    ("aws_key",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_pat",  re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("github_oauth",re.compile(r"\bgho_[0-9A-Za-z]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b")),
    ("google_api",  re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]

# Fichiers sensibles à rechercher dans le scan local (si pas de GITHUB_TOKEN).
SENSITIVE_FILENAMES = {
    ".env",
    "docker-compose.yml",
    "docker-compose.yaml",
    "id_rsa",
    "id_ed25519",
    "config.json",
    "credentials.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
}

# Chemins exposés à vérifier sur la cible HTTP (lab : 127.0.0.1).
EXPOSED_PATHS = [
    "/.env",
    "/.git/config",
    "/docker-compose.yml",
    "/package.json",
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
]

# Wordlist intégrée pour le brute-force DNS (volontairement petite, lab-safe).
DNS_WORDLIST = [
    "admin", "api", "dev", "staging", "test", "internal",
    "vpn", "mail", "git", "jenkins", "grafana", "kibana", "prometheus",
]


# ─── 1. Certificate Transparency (crt.sh) ─────────────────────────
def enumerate_subdomains_crtsh(domain: str) -> list[str]:
    """Énumère les sous-domaines via l'API crt.sh (Certificate Transparency).
    Extrait les SANs des certificats émis pour *.domain.
    Gère le rate-limiting par retry avec backoff exponentiel."""
    url = CRT_SH_URL.format(domain=domain)
    subdomains: set[str] = set()
    last_err = None

    for attempt in range(1, CRT_SH_MAX_RETRIES + 1):
        try:
            r = requests.get(url, timeout=CRT_SH_TIMEOUT, headers={
                "User-Agent": f"harness/{HARNESS_VERSION}",
                "Accept": "application/json",
            })
            if r.status_code == 429 or r.status_code >= 500:
                # Rate-limiting / erreur serveur crt.sh : backoff exponentiel.
                last_err = f"http_{r.status_code}"
                time.sleep(min(2 ** attempt, 8))
                continue
            if r.status_code != 200:
                last_err = f"http_{r.status_code}"
                break
            try:
                entries = r.json()
            except (json.JSONDecodeError, ValueError):
                # crt.sh renvoie parfois du JSON invalide en cas de charge.
                last_err = "invalid_json"
                time.sleep(min(2 ** attempt, 8))
                continue

            for entry in entries:
                # Le champ 'name_value' contient les SANs (séparés par \n).
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and name.endswith(domain) and name != domain:
                        subdomains.add(name)
            last_err = None
            break
        except requests.Timeout:
            last_err = "timeout"
            time.sleep(min(2 ** attempt, 8))
        except requests.RequestException as e:
            last_err = type(e).__name__
            time.sleep(min(2 ** attempt, 8))

    # Tri déterministe (ne dépend pas du RNG) pour un output stable.
    result = sorted(subdomains)
    return result if not last_err else []  # en cas d'erreur, on retourne vide


# ─── 2a. Scan local de fuites (fallback sans GITHUB_TOKEN) ────────
def _scan_local_leaks(directory: str) -> list[dict]:
    """Scan récursif d'un répertoire local pour motifs de secrets & fichiers sensibles.
    Évite les binaires et limite la taille des fichiers lus (anti-bloat)."""
    leaks: list[dict] = []
    root = Path(directory)
    if not root.exists() or not root.is_dir():
        return leaks

    MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB — ignore les fichiers plus gros.

    # os.walk avec gestion d'erreurs (permissions, liens cassés).
    files_scanned = 0
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        # Filtrer les répertoires bruyants (venv, .git interne, node_modules).
        dirnames[:] = [d for d in dirnames if d not in {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
        }]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            try:
                if fpath.stat().st_size > MAX_FILE_BYTES:
                    continue
                raw = fpath.read_bytes()
            except (OSError, PermissionError):
                continue

            # Décode en text permissif pour le matching regex.
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                continue

            rel = str(fpath.relative_to(root))

            # (a) Nom de fichier sensible — signale même si contenu vide.
            if fname in SENSITIVE_FILENAMES:
                leaks.append({
                    "type": "sensitive_file",
                    "pattern": fname,
                    "file": rel,
                    "line": 0,
                })

            # (b) Motifs de secrets dans le contenu — ligne précise.
            for stype, pat in SECRET_PATTERNS:
                for m in pat.finditer(text):
                    # Numéro de ligne calculé depuis l'offset du match.
                    line_no = text.count("\n", 0, m.start()) + 1
                    # Masque partiellement le secret dans la sortie (sanitization).
                    matched = m.group(0)
                    masked = matched[:6] + "*" * min(len(matched) - 6, 8)
                    leaks.append({
                        "type": stype,
                        "pattern": masked,
                        "file": rel,
                        "line": line_no,
                    })
            files_scanned += 1

    return leaks


# ─── 2b. GitHub Code Search API (si GITHUB_TOKEN présent) ─────────
def _github_leak_search(org: str) -> list[dict]:
    """Recherche de secrets/fichiers sensibles via GitHub Code Search API.
    Requiert GITHUB_TOKEN. Le token n'est JAMAIS inclus dans la sortie."""
    leaks: list[dict] = []
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": f"harness/{HARNESS_VERSION}",
    }

    # Construit une query GitHub code search pour l'org.
    # GitHub limite à 1000 résultats par query ; on échantillonne par motif.
    queries = [
        ("aws_key",      f"AKIA org:{org}"),
        ("github_pat",   f"ghp_ org:{org}"),
        ("slack_token",  f"xox org:{org}"),
        ("google_api",   f"AIza org:{org}"),
        ("env_file",     f"filename:.env org:{org}"),
        ("compose_file", f"filename:docker-compose.yml org:{org}"),
        ("rsa_file",     f"filename:id_rsa org:{org}"),
        ("config_json",  f"filename:config.json org:{org}"),
    ]

    for label, q in queries:
        try:
            r = requests.get(
                GITHUB_API,
                params={"q": q, "per_page": 30},
                headers=headers,
                timeout=GITHUB_TIMEOUT,
            )
            if r.status_code == 403:
                # Rate-limit GitHub — on arrête proprement.
                leaks.append({"type": "github_rate_limited", "pattern": label,
                              "file": "", "line": 0})
                break
            if r.status_code != 200:
                continue
            data = r.json()
            for item in data.get("items", []):
                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                leaks.append({
                    "type": label,
                    "pattern": path[:60],
                    "file": f"{repo}/{path}",
                    "line": 0,
                })
        except (requests.RequestException, json.JSONDecodeError):
            continue

    return leaks


def detect_leaks() -> tuple[list[dict], str]:
    """Détecte les fuites de secrets. Retourne (leaks, source).
    source = 'github_api' | 'local_scan' | 'none'."""
    if GITHUB_TOKEN:
        org = ARGV2 or TARGET_DOMAIN.split(".")[0]
        return _github_leak_search(org), "github_api"
    local_dir = ARGV2 or "./source"
    return _scan_local_leaks(local_dir), "local_scan"


# ─── 3. Fichiers exposés (cible HTTP lab 127.0.0.1) ───────────────
def check_exposed_files() -> list[dict]:
    """Vérifie les chemins communs sur la cible HTTP (lab: 127.0.0.1).
    En lab mode, si la cible n'est pas joignable, on liste quand même les
    chemins candidats (ce qui WOULD be checked) avec status null."""
    results: list[dict] = []
    session = requests.Session()
    session.headers.update({
        "User-Agent": f"harness/{HARNESS_VERSION}",
        "X-Forwarded-For": "127.0.0.1",
    })

    for path in EXPOSED_PATHS:
        url = f"{LAB_BASE}{path}"
        entry = {"path": path, "url": url, "status": None, "accessible": False}
        try:
            r = session.get(url, timeout=4, allow_redirects=False)
            entry["status"] = r.status_code
            # HTTP 200 = fichier exposé. On note aussi la taille (signal).
            entry["accessible"] = (r.status_code == 200)
            if r.status_code == 200:
                entry["len"] = len(r.content)
        except requests.RequestException:
            # Cible non joignable en lab — entry reste à status None.
            entry["error"] = "unreachable"
        results.append(entry)

    return results


# ─── 4. Brute-force DNS (wordlist intégrée) ───────────────────────
def dns_bruteforce(domain: str) -> list[dict]:
    """Résolution DNS de <word>.<domain> via socket.getaddrinfo.
    Ordre d'énumération déterministe (RNG seedé par SEED)."""
    # Shuffle reproductible — l'ordre ne dépend pas du SEED uniquement pour
    # le rendu, les résultats restent les mêmes (juste triés à la fin).
    words = list(DNS_WORDLIST)
    random.shuffle(words)

    resolved: list[dict] = []
    for word in words:
        host = f"{word}.{domain}"
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            # Extraire les IPs uniques (IPv4 + IPv6).
            addrs = sorted({info[4][0] for info in infos})
            if addrs:
                resolved.append({
                    "subdomain": host,
                    "ips": addrs[:4],  # plafonné pour la lisibilité.
                })
        except (socket.gaierror, socket.herror):
            continue
        except OSError:
            continue

    # Tri déterministe final (indépendant du shuffle).
    resolved.sort(key=lambda d: d["subdomain"])
    return resolved


# ─── Main ─────────────────────────────────────────────────────────
def main() -> None:
    t0 = time.time()
    domain = TARGET_DOMAIN.strip().lower()

    # (1) Certificate Transparency.
    crt_subdomains = enumerate_subdomains_crtsh(domain)

    # (2) Détection de fuites (GitHub API ou scan local).
    leaks, leak_source = detect_leaks()

    # (3) Fichiers exposés.
    exposed = check_exposed_files()
    exposed_found = sum(1 for e in exposed if e.get("accessible"))

    # (4) Brute-force DNS.
    dns_results = dns_bruteforce(domain)
    dns_subdomains = [r["subdomain"] for r in dns_results]

    # Fusionne tous les sous-domaines découverts (crt.sh + DNS), dédupliqués.
    all_subs = sorted(set(crt_subdomains) | set(dns_subdomains))

    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "target": domain,
        "subdomains_found": len(all_subs),
        "subdomains": all_subs,
        "subdomains_source": {
            "crt_sh": len(crt_subdomains),
            "dns_bruteforce": len(dns_subdomains),
        },
        "leaks_found": len(leaks),
        "leaks": leaks,
        "leak_source": leak_source,
        "exposed_files_checked": len(exposed),
        "exposed_files_found": exposed_found,
        "exposed_files": exposed,
        "dns_bruteforce": {
            "wordlist_size": len(DNS_WORDLIST),
            "resolved": dns_results,
        },
        "seed": SEED,
        "elapsed_ms": round((time.time() - t0) * 1000, 1),
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
