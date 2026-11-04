#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — Ethereum node JSON-RPC exposure probe.
# Secteur : crypto — couche geth/erigon/besu RPC (port 8545).
#
#   v3.0.0 : nouveau module sectoriel (Phase 1, crypto recon).
#   - LAB=1 OBLIGATOIRE — refuse de s'exécuter sans confirmation environnement lab.
#   - Timeout 5s sur toutes les requêtes HTTP (requests).
#   - JSON stdout uniquement (aucune sortie texte parasite).
#   - SAFE_MODE=full par défaut pour crypto (cf. sector_base.py).
#       - personal_unlockAccount, eth_sendTransaction testés en full.
#       - En SAFE_MODE=read_only, on skippe les calls qui modifient l'état.
#   - Cadre légal : accès non autorisé à un nœud Ethereum ouvert = vol potentiel
#     (Art. 311-1 Code pénal). Lab isolé uniquement.
#
# Vecteurs testés :
#   - eth_blockNumber          → connectivité de base
#   - eth_accounts             → comptes débloqués (CRITICAL si > 0)
#   - eth_getBalance           → solde d'adresses connues
#   - personal_listAccounts    → personal API exposé (devrait être désactivé)
#   - personal_unlockAccount   → unlock sans password (SAFE_MODE=full)
#   - eth_sendTransaction      → API accepte-t-elle des tx ? (dry-run, no gas)
#   - admin_nodeInfo           → admin API exposé (info leak : version, peers, enode)
#   - txpool_status            → tx pool exposé (info leak)
#
# Usage : python3 geth_rpc_module.py [rpc_url]
import json
import os
import sys
from typing import Any, Optional

# requests est requis (déjà dans requirements.txt du harness).
try:
    import requests
except ImportError:
    print(json.dumps({
        "module": "geth_rpc_probe",
        "harness_version": "3.0.0",
        "lab": False,
        "error": "requests_not_installed",
        "hint": "pip install requests",
    }))
    sys.exit(2)

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "geth_rpc_probe"
TIMEOUT_S = 5  # toutes les requêtes HTTP : 5s hard cap

# ─── Args CLI ───────────────────────────────────────────────────────
RPC_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8545"

# SAFE_MODE : crypto = full par défaut (cf. sector_base).
# Surcharge via env (read_only pour un audit passif-only).
SAFE_MODE = os.environ.get("SAFE_MODE", "full")

# Adresse zero (utilisée pour tester eth_getBalance sans cibler un compte réel).
ZERO_ADDR = "0x" + "0" * 40
# Adresse de test bien connue (vitalik.eth — adresse publique, balance publique).
# Utilisée uniquement pour vérifier que eth_getBalance fonctionne.
PUBLIC_TEST_ADDR = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

# Session requests réutilisable (keep-alive).
_SESSION = requests.Session()
_SESSION.headers.update({"Content-Type": "application/json"})


# ─── LAB guard ──────────────────────────────────────────────────────
def lab_guard() -> bool:
    """Refuse de s'exécuter sans LAB=1 dans l'environnement."""
    return os.environ.get("LAB") == "1"


# ─── JSON-RPC client ────────────────────────────────────────────────
def rpc_call(method: str, params: Optional[list] = None,
             url: str = RPC_URL, timeout: float = TIMEOUT_S) -> dict:
    """Effectue un appel JSON-RPC vers le nœud Ethereum.

    Retourne un dict avec :
      - method : la méthode appelée
      - ok : True si la requête HTTP a abouti
      - result : le champ "result" de la réponse JSON-RPC (si succès)
      - error : le champ "error" de la réponse JSON-RPC (si erreur RPC)
      - http_status : code HTTP
      - detail : message d'erreur (en cas d'échec HTTP/timeout)
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params if params is not None else [],
    }
    result: dict = {"method": method, "ok": False, "result": None,
                    "error": None, "http_status": None, "detail": None}
    try:
        r = _SESSION.post(url, data=json.dumps(payload), timeout=timeout,
                          allow_redirects=False)
        result["http_status"] = r.status_code
        if r.status_code == 200:
            try:
                j = r.json()
                if "result" in j:
                    result["ok"] = True
                    result["result"] = j["result"]
                elif "error" in j:
                    result["ok"] = False  # RPC error
                    result["error"] = j["error"]
                else:
                    result["detail"] = "malformed_jsonrpc_response"
            except ValueError as e:
                result["detail"] = f"json_decode_error: {e}"
        else:
            result["detail"] = f"http_{r.status_code}"
    except requests.exceptions.Timeout:
        result["detail"] = "timeout"
    except requests.exceptions.ConnectionError as e:
        result["detail"] = f"connection_error: {type(e).__name__}"
    except requests.exceptions.RequestException as e:
        result["detail"] = f"request_error: {type(e).__name__}: {e}"
    return result


# ─── 1. eth_blockNumber ─────────────────────────────────────────────
def eth_blockNumber() -> dict:
    """Basic connectivity check — eth_blockNumber."""
    r = rpc_call("eth_blockNumber")
    return {
        "check": "eth_blockNumber",
        "rpc_accessible": r.get("ok", False),
        "block_number": r.get("result"),
        "http_status": r.get("http_status"),
        "detail": r.get("detail") or r.get("error"),
    }


# ─── 2. eth_accounts (CRITICAL si non vide) ─────────────────────────
def eth_accounts() -> dict:
    """List accounts (if unlocked accounts exist = CRITICAL)."""
    r = rpc_call("eth_accounts")
    accounts = r.get("result") or []
    return {
        "check": "eth_accounts",
        "accounts_listed": r.get("ok", False) and len(accounts) > 0,
        "accounts_count": len(accounts) if isinstance(accounts, list) else 0,
        "accounts": accounts if isinstance(accounts, list) else [],
        "detail": r.get("detail") or r.get("error"),
    }


# ─── 3. eth_getBalance ──────────────────────────────────────────────
def eth_getBalance(address: str = PUBLIC_TEST_ADDR,
                   block: str = "latest") -> dict:
    """Check balance of a known address."""
    r = rpc_call("eth_getBalance", params=[address, block])
    return {
        "check": "eth_getBalance",
        "address": address,
        "balance_wei": r.get("result"),
        "ok": r.get("ok", False),
        "detail": r.get("detail") or r.get("error"),
    }


# ─── 4. personal_listAccounts ───────────────────────────────────────
def personal_listAccounts() -> dict:
    """Check if personal API is enabled (should be disabled on prod nodes).

    Le namespace `personal_*` gère les keystores du nœud. S'il est exposé,
    un attaquant peut lister/débloquer les comptes locaux du nœud.
    """
    r = rpc_call("personal_listAccounts")
    err = r.get("error")
    # Si le nœud répond "the method personal_listAccounts does not exist/is not available"
    # → personal API désactivée (sûr). Sinon, exposée (CRITICAL).
    method_disabled = False
    if err and isinstance(err, dict):
        msg = str(err.get("message", "")).lower()
        if "not exist" in msg or "not available" in msg or "unknown method" in msg:
            method_disabled = True
    return {
        "check": "personal_listAccounts",
        "personal_api": r.get("ok", False) and not method_disabled,
        "accounts": r.get("result") if r.get("ok") else None,
        "method_disabled": method_disabled,
        "detail": r.get("detail") or err,
    }


# ─── 5. personal_unlockAccount (SAFE_MODE=full only) ────────────────
def personal_unlockAccount() -> dict:
    """Try to unlock an account without password.

    ONLY if SAFE_MODE=full — crypto sector default is full (cf. sector_base).
    On teste l'unlock avec un mot de passe vide sur le zero address.
    Un nœud mal configuré peut accepter et débloquer un compte existant.
    """
    result: dict = {
        "check": "personal_unlockAccount",
        "executed": False,
        "accounts_unlocked": False,
        "note": None,
    }
    if SAFE_MODE != "full":
        result["note"] = (f"skipped: SAFE_MODE={SAFE_MODE}. personal_unlockAccount "
                          "is a state-modifying call. Set SAFE_MODE=full to run (lab).")
        return result

    result["executed"] = True
    # On teste l'unlock sur le zero address (n'existe pas normalement) avec
    # password vide + duration 1s. Un nœud correct répondra "account not found".
    # Un nœud mal configuré qui exposerait des comptes pourrait accepter.
    r = rpc_call("personal_unlockAccount",
                 params=[ZERO_ADDR, "", 1])
    err = r.get("error")
    res = r.get("result")
    # Si result == True → unlock accepté (CRITICAL).
    if r.get("ok") and res is True:
        result["accounts_unlocked"] = True
        result["note"] = "CRITICAL: account unlock accepted without password."
    elif err and isinstance(err, dict):
        msg = str(err.get("message", "")).lower()
        if "not exist" in msg or "could not decrypt" in msg or "invalid" in msg:
            result["note"] = f"safe: account rejected ({msg[:80]})"
        else:
            result["note"] = f"rpc_error: {msg[:80]}"
    else:
        result["note"] = "unexpected response"
    result["raw_result"] = res
    result["raw_error"] = err
    return result


# ─── 6. eth_sendTransaction (dry-run check) ─────────────────────────
# SAFE_MODE=full : on teste si l'API accepte la soumission. On envoie
# une tx avec from=zero addr (inexistante) → le nœud doit rejeter.
# Si l'API répond avec "account not found" → OK (sûr).
# Si l'API répond avec un hash de tx → CRITICAL (tx acceptée).
def eth_sendTransaction() -> dict:
    """Try to send a transaction (dry-run check: does the API accept it?).

    On envoie une tx from=zero addr (qui n'existe pas sur le nœud). Un nœud
    correct rejette ("sender account not found"). Si l'API renvoie un hash
    de transaction → CRITICAL (tx acceptée même sans compte).
    """
    result: dict = {
        "check": "eth_sendTransaction",
        "executed": False,
        "send_transaction_possible": False,
        "note": None,
    }
    if SAFE_MODE != "full":
        result["note"] = (f"skipped: SAFE_MODE={SAFE_MODE}. eth_sendTransaction "
                          "is a state-modifying call. Set SAFE_MODE=full to run (lab).")
        return result

    result["executed"] = True
    # Tx from zero addr, to zero addr, value 0, gas 21000 — totalement bénigne
    # mais teste si l'API accepte la soumission.
    tx = {
        "from": ZERO_ADDR,
        "to": ZERO_ADDR,
        "value": "0x0",
        "gas": "0x5208",      # 21000
        "gasPrice": "0x1",    # 1 wei
    }
    r = rpc_call("eth_sendTransaction", params=[tx])
    err = r.get("error")
    res = r.get("result")
    if r.get("ok") and isinstance(res, str) and res.startswith("0x"):
        result["send_transaction_possible"] = True
        result["note"] = "CRITICAL: tx submission accepted (returned hash)."
        result["tx_hash"] = res
    elif err and isinstance(err, dict):
        msg = str(err.get("message", "")).lower()
        if "account not found" in msg or "sender" in msg and "not found" in msg:
            result["note"] = "safe: sender account rejected."
        elif "insufficient funds" in msg:
            result["note"] = "safe: insufficient funds for sender."
        else:
            result["note"] = f"rpc_error: {msg[:80]}"
    else:
        result["note"] = "unexpected response"
    result["raw_result"] = res
    result["raw_error"] = err
    return result


# ─── 7. admin_nodeInfo ──────────────────────────────────────────────
def admin_nodeInfo() -> dict:
    """Check if admin API is exposed (node info leak).

    admin_nodeInfo leak : version du nœud, liste des peers, enode URL,
    configuration réseau. Info utile pour cibler des exploits spécifiques
    à la version de geth.
    """
    r = rpc_call("admin_nodeInfo")
    err = r.get("error")
    method_disabled = False
    if err and isinstance(err, dict):
        msg = str(err.get("message", "")).lower()
        if "not exist" in msg or "not available" in msg or "unknown method" in msg:
            method_disabled = True
    info = r.get("result") if r.get("ok") else None
    # Extraire la version du nœud (champ "name" dans nodeInfo).
    node_version: Optional[str] = None
    if isinstance(info, dict):
        node_version = info.get("name") or info.get("version")
    return {
        "check": "admin_nodeInfo",
        "admin_api": r.get("ok", False) and not method_disabled,
        "node_version": node_version,
        "node_info_keys": list(info.keys()) if isinstance(info, dict) else None,
        "enode": info.get("enode") if isinstance(info, dict) else None,
        "method_disabled": method_disabled,
        "detail": r.get("detail") or err,
    }


# ─── 8. txpool_status ───────────────────────────────────────────────
def txpool_status() -> dict:
    """Check transaction pool (info leak)."""
    r = rpc_call("txpool_status")
    err = r.get("error")
    method_disabled = False
    if err and isinstance(err, dict):
        msg = str(err.get("message", "")).lower()
        if "not exist" in msg or "not available" in msg or "unknown method" in msg:
            method_disabled = True
    status = r.get("result") if r.get("ok") else None
    pending: Optional[int] = None
    queued: Optional[int] = None
    if isinstance(status, dict):
        # txpool_status retourne {pending: hex, queued: hex}
        try:
            pending = int(status.get("pending", "0x0"), 16)
        except (TypeError, ValueError):
            pass
        try:
            queued = int(status.get("queued", "0x0"), 16)
        except (TypeError, ValueError):
            pass
    return {
        "check": "txpool_status",
        "txpool_api": r.get("ok", False) and not method_disabled,
        "pending_count": pending,
        "queued_count": queued,
        "method_disabled": method_disabled,
        "detail": r.get("detail") or err,
    }


# ─── Synthèse JSON ──────────────────────────────────────────────────
def main() -> None:
    # 1. LAB guard.
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "lab": False,
            "error": "LAB guard not satisfied",
            "detail": ("Set LAB=1 to confirm lab authorization. Accessing an "
                       "unauthorized Ethereum node is theft (Art. 311-1 Code pénal)."),
            "legal_note": ("Art. 311-1 Code pénal — accès non autorisé à un nœud "
                           "Ethereum ouvert = vol potentiel. Lab isolé uniquement."),
        }, indent=2))
        sys.exit(1)

    # 2. Exécution des 8 checks (timeout 5s chacun).
    bn = eth_blockNumber()
    accts = eth_accounts()
    bal = eth_getBalance()
    personal_list = personal_listAccounts()
    personal_unlock = personal_unlockAccount()
    send_tx = eth_sendTransaction()
    node_info = admin_nodeInfo()
    txpool = txpool_status()

    # 3. Synthèse JSON stdout.
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "lab": True,
        "safe_mode": SAFE_MODE,
        "target": RPC_URL,
        "timeout_s": TIMEOUT_S,
        # Champs de sortie attendus (spec) :
        "rpc_accessible": bool(bn.get("rpc_accessible")),
        "accounts_listed": bool(accts.get("accounts_listed")),
        "accounts_unlocked": bool(personal_unlock.get("accounts_unlocked")),
        "personal_api": bool(personal_list.get("personal_api")),
        "admin_api": bool(node_info.get("admin_api")),
        "send_transaction_possible": bool(send_tx.get("send_transaction_possible")),
        "node_version": node_info.get("node_version"),
        # Détails structurés pour le rapport :
        "details": {
            "eth_blockNumber": bn,
            "eth_accounts": accts,
            "eth_getBalance": bal,
            "personal_listAccounts": personal_list,
            "personal_unlockAccount": personal_unlock,
            "eth_sendTransaction": send_tx,
            "admin_nodeInfo": node_info,
            "txpool_status": txpool,
        },
        "regulations": ["PSAN-AMF", "RGPD", "Travel Rule FATF"],
        "legal_note": ("Accès non autorisé à un nœud Ethereum ouvert : "
                       "Art. 311-1 Code pénal (vol). Lab isolé uniquement."),
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
