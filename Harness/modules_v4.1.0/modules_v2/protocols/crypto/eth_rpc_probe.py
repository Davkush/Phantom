#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — protocol probe : Ethereum JSON-RPC node exposure.
# Secteur : crypto — SAFE_MODE=full par défaut (cf. sector_base).
#
#   - v3.1 : eth_blockNumber     → connectivité de base
#   - v3.1 : eth_accounts        → CRITICAL si non vide (comptes exposés)
#   - v3.1 : eth_getBalance      → balance queryable sans auth ?
#   - v3.1 : personal_unlockAccount → existence check SANS appel réel
#   - v3.1 : eth_sendTransaction → existence check SANS appel réel (CRITICAL si no auth)
#   - v3.1 : admin_nodeInfo      → admin methods exposés + version leak
#   - v3.1 : CORS headers        → wildcard = cross-origin requests acceptées
#   - v3.1 : SEED reproducibility, LAB=1 guard, timeout 5s
#
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
# Accès non autorisé à un nœud Ethereum ouvert = vol potentiel
# (Art. 311-1 Code pénal). Lab isolé uniquement.
#
# Stratégie "method existence without execution" :
#   Pour personal_unlockAccount et eth_sendTransaction, on n'appelle PAS la
#   méthode avec des paramètres valides (qui pourrait modifier l'état). On
#   envoie la méthode AVEC un nombre incorrect de params (ex: 0 params au
#   lieu de 2-3 attendus). Le nœud répond alors par :
#     - {"error":{"code":-32602,"message":"too few arguments ..."}}
#       → method EXISTS (params validation échouée mais méthode connue)
#     - {"error":{"code":-32601,"message":"the method personal_xxx does not exist/is not available"}}
#       → method DISABLED (l'utilisateur ne l'a pas activée — safe)
#   Cette technique teste l'existence de la méthode sans l'exécuter.
import json
import os
import sys
import time
from typing import Any, Optional

try:
    import requests
except ImportError:
    print(json.dumps({
        "module": "eth_rpc_probe",
        "harness_version": "3.1.0",
        "error": "requests_not_installed",
        "hint": "pip install requests",
    }))
    sys.exit(2)

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "eth_rpc_probe"
DEFAULT_PORT = 8545              # Ethereum JSON-RPC (cf. sector_base _PORT_MAP_CRYPTO)
TIMEOUT_S = 5                   # 5s strict

# ─── Import sector_base (best-effort) ─────────────────────────────────────────
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from sector_base import (  # type: ignore
        get_sector_config,
        get_safe_mode as _sector_safe_mode,
    )
    _HAS_SECTOR_BASE = True
except Exception:  # noqa: BLE001
    _HAS_SECTOR_BASE = False

    def get_sector_config() -> dict:  # type: ignore[no-redef]
        return {
            "sector": "crypto",
            "safe_mode": "full",
            "regulations": ("PSAN-AMF", "RGPD", "Travel Rule FATF"),
            "harness_version": HARNESS_VERSION,
        }

    def _sector_safe_mode() -> str:  # type: ignore[no-redef]
        return "full"


def get_safe_mode() -> str:
    env_sm = os.environ.get("SAFE_MODE", "").lower().strip()
    if env_sm in ("read_only", "full"):
        return env_sm
    return _sector_safe_mode()


# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))
_RPC_ID_SEQ = [0]

def _next_rpc_id() -> int:
    """RPC id déterministe (SEED + incrément). Permet de reproduire les appels
    JSON-RPC à l'identique pour audit (logs nœud corrélables)."""
    _RPC_ID_SEQ[0] += 1
    return SEED + _RPC_ID_SEQ[0]


# ─── Guards ───────────────────────────────────────────────────────────────────
def _check_lab_guard() -> None:
    if os.environ.get("LAB") != "1":
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "lab_guard_failed",
            "reason": "LAB env var must be set to 1 (isolated lab only)",
            "legal_note": (
                "Accès non autorisé à un nœud Ethereum ouvert : Art. 311-1 "
                "Code pénal (vol). Lab isolé uniquement."
            ),
        }))
        sys.exit(2)


def _check_safe_mode() -> str:
    sm = get_safe_mode()
    if sm not in ("read_only", "full"):
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "invalid_safe_mode",
            "safe_mode": sm,
            "valid": ("read_only", "full"),
        }))
        sys.exit(2)
    return sm


# ─── Args CLI ────────────────────────────────────────────────────────────────
# Usage: eth_rpc_probe.py <host> [port]
TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
RPC_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

# Adresses de test bien connues (publiques, balance publique — vitalik.eth).
PUBLIC_TEST_ADDR = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
ZERO_ADDR = "0x" + "0" * 40


# ─── Session HTTP réutilisable ────────────────────────────────────────────────
_SESSION = requests.Session()
_SESSION.headers.update({
    "Content-Type": "application/json",
    "User-Agent": f"harness/{HARNESS_VERSION} ({MODULE_NAME}) seed={SEED}",
    "Origin": f"http://{TARGET_HOST}:{TARGET_PORT}",  # pour tester CORS
})


# ─── JSON-RPC client ──────────────────────────────────────────────────────────
def rpc_call(method: str, params: Optional[list] = None,
             url: str = RPC_URL, timeout: float = TIMEOUT_S) -> dict:
    """Effectue un appel JSON-RPC vers le nœud Ethereum.
    Capture toutes les erreurs sans lever."""
    payload = {
        "jsonrpc": "2.0",
        "id": _next_rpc_id(),
        "method": method,
        "params": params if params is not None else [],
    }
    result: dict = {
        "method": method,
        "ok": False,
        "result": None,
        "error": None,
        "http_status": None,
        "detail": None,
    }
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


def _method_disabled(rpc_result: dict) -> bool:
    """True si l'erreur indique que la méthode n'existe pas / n'est pas disponible.
    Patterns communs : "the method X does not exist/is not available",
    "unknown method", "not supported", code -32601 (method not found)."""
    err = rpc_result.get("error")
    if not isinstance(err, dict):
        return False
    code = err.get("code")
    msg = str(err.get("message", "")).lower()
    if code == -32601:  # JSON-RPC spec: method not found
        return True
    if any(s in msg for s in (
        "not exist", "not available", "unknown method", "not supported",
        "no such method", "missing method",
    )):
        return True
    return False


def _method_invalid_params(rpc_result: dict) -> bool:
    """True si l'erreur indique un problème de PARAMS (mais la méthode existe).
    Patterns : "too few arguments", "missing value for required argument",
    "invalid params", code -32602."""
    err = rpc_result.get("error")
    if not isinstance(err, dict):
        return False
    code = err.get("code")
    msg = str(err.get("message", "")).lower()
    if code == -32602:  # JSON-RPC spec: invalid params
        return True
    if any(s in msg for s in (
        "too few", "too many", "missing value", "invalid params",
        "argument", "params", "expects", "required argument",
    )):
        return True
    return False


# ─── 1. eth_blockNumber → connectivité ───────────────────────────────────────
def check_eth_blockNumber() -> dict:
    """Basic connectivity — eth_blockNumber."""
    r = rpc_call("eth_blockNumber")
    return {
        "check": "eth_blockNumber",
        "rpc_accessible": r.get("ok", False),
        "block_number": r.get("result"),
        "http_status": r.get("http_status"),
        "detail": r.get("detail") or r.get("error"),
    }


# ─── 2. eth_accounts → CRITICAL si non vide ──────────────────────────────────
def check_eth_accounts() -> dict:
    """List accounts exposed by the node.
    CRITICAL : if returns non-empty, accounts are exposed without auth.
    eth_accounts returns the list of accounts the node manages (unlocked or not).
    On production nodes, this should return [] (or method should be disabled)."""
    r = rpc_call("eth_accounts")
    accounts = r.get("result") or []
    accounts_count = len(accounts) if isinstance(accounts, list) else 0
    exposed = r.get("ok", False) and accounts_count > 0
    return {
        "check": "eth_accounts",
        "ok": r.get("ok", False),
        "accounts_count": accounts_count,
        "accounts_exposed": exposed,
        # NEVER expose full addresses in production report — but eth_accounts
        # returns public addresses (not private keys), so we keep first 10 chars
        # + *** as a precaution (some hardened deployments redact addresses).
        "accounts_redacted": [
            (a[:8] + "***") if isinstance(a, str) and len(a) > 8 else a
            for a in (accounts if isinstance(accounts, list) else [])
        ],
        "severity": "critical" if exposed else "info",
        "detail": r.get("detail") or r.get("error"),
    }


# ─── 3. eth_getBalance → balance queryable sans auth ─────────────────────────
def check_eth_getBalance() -> dict:
    """Check balance of a known PUBLIC address (vitalik.eth).
    If returns ok without auth → balance queryable → info leak (acceptable
    for public chain nodes but CRITICAL for private/custodial nodes)."""
    r = rpc_call("eth_getBalance", params=[PUBLIC_TEST_ADDR, "latest"])
    return {
        "check": "eth_getBalance",
        "address": PUBLIC_TEST_ADDR,
        "balance_wei": r.get("result"),
        "ok": r.get("ok", False),
        "queryable_without_auth": r.get("ok", False),
        "detail": r.get("detail") or r.get("error"),
    }


# ─── 4. personal_unlockAccount → existence check (NO real call) ──────────────
def check_personal_unlockAccount() -> dict:
    """Check if personal_unlockAccount METHOD EXISTS without actually unlocking
    any account. Technique : call with 0 params (wrong count). The node will
    respond with:
      - "too few arguments" / -32602  → method EXISTS (CRITICAL — unlocking
                                         is possible with valid params)
      - "method does not exist" / -32601 → method DISABLED (safe)
    We NEVER pass a real account + password combination."""
    r = rpc_call("personal_unlockAccount", params=[])  # 0 params — wrong count
    method_disabled = _method_disabled(r)
    method_exists = _method_invalid_params(r)
    # If the method returns a result (e.g. False on some nodes that accept
    # 0 params as "no-op"), that's also an existence signal.
    if r.get("ok"):
        method_exists = True
    return {
        "check": "personal_unlockAccount",
        "method_exists": method_exists,
        "method_disabled": method_disabled,
        "unlock_possible": method_exists and not method_disabled,
        "executed": False,   # NO real unlock attempt
        "params_strategy": "0 params (wrong count) — existence check only",
        "severity": "critical" if method_exists else "info",
        "detail": r.get("detail") or r.get("error"),
        "note": (
            "Existence check only — no real account unlock attempted. "
            "If method_exists=True, an attacker with a known account address "
            "could attempt unlock with password brute-force (CRITICAL for "
            "nodes that manage keystore accounts)."
        ),
    }


# ─── 5. eth_sendTransaction → existence check (NO real call) ─────────────────
def check_eth_sendTransaction() -> dict:
    """Check if eth_sendTransaction METHOD EXISTS without actually sending
    any transaction. Technique : call with 0 params (wrong count).
    If method EXISTS + node is publicly accessible (no auth) → CRITICAL :
    anyone could send transactions from accounts the node manages.
    """
    r = rpc_call("eth_sendTransaction", params=[])  # 0 params — wrong count
    method_disabled = _method_disabled(r)
    method_exists = _method_invalid_params(r)
    if r.get("ok"):
        method_exists = True
    return {
        "check": "eth_sendTransaction",
        "method_exists": method_exists,
        "method_disabled": method_disabled,
        "send_transaction_enabled": method_exists and not method_disabled,
        "executed": False,   # NO real tx attempt
        "params_strategy": "0 params (wrong count) — existence check only",
        "severity": "critical" if method_exists else "info",
        "detail": r.get("detail") or r.get("error"),
        "note": (
            "Existence check only — no real transaction attempted. "
            "If method_exists=True on a node with unlocked accounts (cf. "
            "eth_accounts check), an attacker can drain funds by calling "
            "eth_sendTransaction with arbitrary from/to/value."
        ),
    }


# ─── 6. admin_nodeInfo → admin methods + version leak ────────────────────────
def check_admin_nodeInfo() -> dict:
    """Check if admin API is exposed (node info leak).
    admin_nodeInfo leaks : node name/version (Geth/Parity/Besu + version),
    enode URL, list of peers, network id, configuration. Useful for
    targeting version-specific CVEs (e.g. Geth < 1.8.18 Denial-of-Service)."""
    r = rpc_call("admin_nodeInfo")
    method_disabled = _method_disabled(r)
    info = r.get("result") if r.get("ok") else None
    node_version: Optional[str] = None
    if isinstance(info, dict):
        node_version = info.get("name") or info.get("version")
    return {
        "check": "admin_nodeInfo",
        "admin_methods_exposed": r.get("ok", False) and not method_disabled,
        "node_version": node_version,
        "node_info_keys": list(info.keys()) if isinstance(info, dict) else None,
        "enode_redacted": (
            # enode URL contains node pubkey + IP — redact for safety
            (info.get("enode", "")[:24] + "***")
            if isinstance(info, dict) and info.get("enode") else None
        ),
        "method_disabled": method_disabled,
        "severity": "high" if (r.get("ok", False) and not method_disabled) else "info",
        "detail": r.get("detail") or r.get("error"),
    }


# ─── 7. CORS headers check ───────────────────────────────────────────────────
def check_cors_headers() -> dict:
    """Send an Origin header and check the Access-Control-Allow-Origin response.
    CRITICAL : if the response is Access-Control-Allow-Origin: *
    (wildcard), then ANY web page can make cross-origin JSON-RPC calls to
    the node. Combined with eth_accounts/sendTransaction enabled, this is
    the standard "browser-based wallet drain" vector (CVE-2018-17144 et al)."""
    t0 = time.time()
    # Preflight OPTIONS + actual POST both checked
    result: dict = {
        "check": "cors_headers",
        "cors_wildcard": False,
        "cors_reflecting": False,
        "cors_present": False,
        "origin_sent": f"http://{TARGET_HOST}:{TARGET_PORT}",
        "acao_header": None,
        "severity": "info",
    }
    try:
        # OPTIONS preflight
        opts = _SESSION.options(
            RPC_URL,
            headers={
                "Origin": f"http://{TARGET_HOST}:{TARGET_PORT}",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
            timeout=TIMEOUT_S,
        )
        aco_opts = opts.headers.get("Access-Control-Allow-Origin")
        result["opts_status"] = opts.status_code
        result["opts_acao"] = aco_opts
        if aco_opts == "*":
            result["cors_wildcard"] = True
            result["cors_present"] = True
        elif aco_opts and "null" not in aco_opts:
            result["cors_present"] = True
            if aco_opts == f"http://{TARGET_HOST}:{TARGET_PORT}":
                result["cors_reflecting"] = True
    except requests.RequestException as e:
        result["opts_error"] = f"{type(e).__name__}: {e}"[:200]

    # Also check actual POST response (some servers only set CORS on actual)
    try:
        r = _SESSION.post(
            RPC_URL,
            data=json.dumps({
                "jsonrpc": "2.0", "id": _next_rpc_id(),
                "method": "eth_blockNumber", "params": [],
            }),
            timeout=TIMEOUT_S,
        )
        aco_post = r.headers.get("Access-Control-Allow-Origin")
        result["post_status"] = r.status_code
        result["post_acao"] = aco_post
        if aco_post == "*":
            result["cors_wildcard"] = True
            result["cors_present"] = True
        elif aco_post and "null" not in aco_post:
            result["cors_present"] = True
            if aco_post == f"http://{TARGET_HOST}:{TARGET_PORT}":
                result["cors_reflecting"] = True
    except requests.RequestException as e:
        result["post_error"] = f"{type(e).__name__}: {e}"[:200]
    result["acao_header"] = result.get("opts_acao") or result.get("post_acao")
    result["ms"] = round((time.time() - t0) * 1000, 1)
    if result["cors_wildcard"]:
        result["severity"] = "critical"
        result["note"] = (
            "CRITICAL: Access-Control-Allow-Origin: * → any web page can make "
            "cross-origin JSON-RPC calls. Combined with eth_sendTransaction "
            "enabled, this is the classic browser-based wallet drain vector."
        )
    elif result["cors_reflecting"]:
        result["severity"] = "high"
        result["note"] = (
            "Server REFLECTS the Origin header → effectively permissive CORS "
            "(any origin allowed via reflection). Same risk as wildcard."
        )
    elif result["cors_present"]:
        result["severity"] = "info"
        result["note"] = "CORS present but restricted (specific origin allowed)."
    else:
        result["severity"] = "info"
        result["note"] = "No CORS headers returned — cross-origin calls blocked by browser SOP."
    return result


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # SAFE_MODE : crypto = full par défaut. Tous les checks ci-dessus sont
    # read-only par construction (existence checks via wrong params count).
    # Aucune exécution réelle de personal_unlockAccount / eth_sendTransaction.

    # Phase 1 : eth_blockNumber
    bn_check = check_eth_blockNumber()

    # Phase 2 : eth_accounts
    accounts_check = check_eth_accounts()

    # Phase 3 : eth_getBalance
    balance_check = check_eth_getBalance()

    # Phase 4 : personal_unlockAccount existence
    unlock_check = check_personal_unlockAccount()

    # Phase 5 : eth_sendTransaction existence
    sendtx_check = check_eth_sendTransaction()

    # Phase 6 : admin_nodeInfo
    admin_check = check_admin_nodeInfo()

    # Phase 7 : CORS headers
    cors_check = check_cors_headers()

    # ─── Synthèse JSON stdout ──────────────────────────────────────────────
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "crypto",
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "seed": SEED,
        "target": {
            "host": TARGET_HOST,
            "port": TARGET_PORT,
            "rpc_url": RPC_URL,
        },
        "regulations": list(get_sector_config().get("regulations", [])),
        "read_only": True,  # existence checks only — no real tx/unlock attempted
        "results": {
            "eth_blockNumber": bn_check,
            "eth_accounts": accounts_check,
            "eth_getBalance": balance_check,
            "personal_unlockAccount": unlock_check,
            "eth_sendTransaction": sendtx_check,
            "admin_nodeInfo": admin_check,
            "cors_headers": cors_check,
        },
        "summary": {
            "rpc_accessible": bn_check.get("rpc_accessible", False),
            "eth_accounts_exposed": accounts_check.get("accounts_exposed", False),
            "send_transaction_enabled": sendtx_check.get("send_transaction_enabled", False),
            "admin_methods_exposed": admin_check.get("admin_methods_exposed", False),
            "cors_wildcard": cors_check.get("cors_wildcard", False),
            "node_version": admin_check.get("node_version"),
        },
        "legal_note": (
            "Accès non autorisé à un nœud Ethereum ouvert : Art. 311-1 Code "
            "pénal (vol). Lab isolé uniquement."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
