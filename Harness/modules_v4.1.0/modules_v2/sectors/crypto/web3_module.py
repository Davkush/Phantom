#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — Web3 / DeFi smart contract attack surface probe.
# Secteur : crypto — couche smart contracts (Ethereum mainnet / testnet).
#
#   v3.0.0 : nouveau module sectoriel (Phase 1, crypto recon).
#   - LAB=1 OBLIGATOIRE — refuse de s'exécuter sans confirmation environnement lab.
#   - Timeout 5s sur toutes les requêtes HTTP/JSON-RPC.
#   - JSON stdout uniquement (aucune sortie texte parasite).
#   - SAFE_MODE=full par défaut pour crypto (cf. sector_base.py).
#       - Tous les checks sont read-only (eth_call, eth_getStorageAt) — pas de
#         modification d'état. SAFE_MODE n'affecte donc pas ce module.
#   - Cadre légal : enumeration non autorisée de smart contracts / DeFi pools
#     sur des mainnets sans autorisation = reconnaissance pour attaque
#     (Art. 323-1 Code pénal). Lab isolé uniquement.
#
# Vecteurs testés :
#   - check_contract_endpoints() — eth_call + eth_getStorageAt slots 0-10
#   - test_reentrancy() — simulation read-only d'un call chain (eth_call)
#   - check_flash_loan_vector() — check Aave/Uniswap V2 pool interactions
#   - check_erc20_approve_race() — approve/transferFrom signature presence
#   - detect_mev_bot() — txpool_content analysis for front-running patterns
#
# Usage : python3 web3_module.py [rpc_url] [contract_address]
import json
import os
import sys
from typing import Any, Optional

# Tente d'importer web3 (optionnel). Fallback sur raw JSON-RPC via requests.
try:
    from web3 import Web3  # type: ignore
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False

try:
    import requests
except ImportError:
    requests = None  # type: ignore

HARNESS_VERSION = "3.0.0"
MODULE_NAME = "web3_probe"
TIMEOUT_S = 5  # toutes les requêtes : 5s hard cap

# ─── Args CLI ───────────────────────────────────────────────────────
RPC_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8545"
# Contract address par défaut : adresse du token WETH sur mainnet Ethereum.
# C'est un contrat public, vérifié, et un point d'entrée canonique pour le
# test des fonctions ERC20 / flash loan.
DEFAULT_CONTRACT = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"  # WETH mainnet
CONTRACT_ADDR = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_CONTRACT

# SAFE_MODE : crypto = full par défaut.
SAFE_MODE = os.environ.get("SAFE_MODE", "full")

# Etherscan API key (optionnel — pour check_contract_endpoints verification).
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "")
ETHERSCAN_API = "https://api.etherscan.io/api"

# Adresses canoniques DeFi mainnet (Ethereum) — pour check_flash_loan_vector.
# Aave V3 Pool (mainnet) :
AAVE_V3_POOL = "0x87870Bca3F3fF6135C69C4DbB0e2b8d8fE1aC7F2"
# Aave V2 LendingPool :
AAVE_V2_POOL = "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9"
# Uniswap V2 Router02 :
UNISWAP_V2_ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
# Uniswap V2 Factory (pour compute pair addresses) :
UNISWAP_V2_FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
# Uniswap V3 Quoter (read-only, pour flash loan-style checks) :
UNISWAP_V3_QUOTER = "0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6"
# dYdX flash loan contract (legacy solo-margin) :
DYDX_SOLO_MARGIN = "0x1E0447b19BB6DfF928A9589311bC0fA78f9d0Ae1"

# Selectors de fonctions ERC20 (keccak256(sig)[:4]).
# approve(address,uint256) = 0x095ea7b3
# transferFrom(address,address,uint256) = 0x23b872dd
# transfer(address,uint256) = 0xa9059cbb
# balanceOf(address) = 0x70a08231
# token0()/token1() (Uniswap V2 pair) — selectors :
# token0() = 0x0dfe1681, token1() = 0xd21220a7
# getReserves() = 0x0902f1ac
SELECTORS = {
    "approve":            "0x095ea7b3",
    "transferFrom":       "0x23b872dd",
    "transfer":           "0xa9059cbb",
    "balanceOf":          "0x70a08231",
    "totalSupply":        "0x18160ddd",
    "token0":             "0x0dfe1681",
    "token1":             "0xd21220a7",
    "getReserves":        "0x0902f1ac",
    "flashLoan":          "0xab9c4c5f",  # Aave V3 flashLoan(address,address,uint256,bytes)
    "flashLoanSimple":    "0x42b7d7e9",  # Aave V3 flashLoanSimple(address,address,uint256,bytes)
    "swapExactTokensForTokens": "0x38ed1739",  # Uniswap V2 router
}

# Session requests réutilisable.
_SESSION = requests.Session() if requests else None


# ─── LAB guard ──────────────────────────────────────────────────────
def lab_guard() -> bool:
    """Refuse de s'exécuter sans LAB=1 dans l'environnement."""
    return os.environ.get("LAB") == "1"


# ─── JSON-RPC / web3 client ─────────────────────────────────────────
def _rpc(method: str, params: Optional[list] = None,
         url: str = RPC_URL, timeout: float = TIMEOUT_S) -> dict:
    """Raw JSON-RPC call via requests. Retourne dict {ok, result, error, detail}."""
    if _SESSION is None:
        return {"ok": False, "detail": "requests_not_installed",
                "result": None, "error": None}
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params if params is not None else [],
    }
    out: dict = {"ok": False, "result": None, "error": None, "detail": None}
    try:
        r = _SESSION.post(url, data=json.dumps(payload), timeout=timeout,
                          allow_redirects=False)
        if r.status_code == 200:
            try:
                j = r.json()
                if "result" in j:
                    out["ok"] = True
                    out["result"] = j["result"]
                elif "error" in j:
                    out["error"] = j["error"]
                else:
                    out["detail"] = "malformed_jsonrpc_response"
            except ValueError as e:
                out["detail"] = f"json_decode_error: {e}"
        else:
            out["detail"] = f"http_{r.status_code}"
    except requests.exceptions.Timeout:
        out["detail"] = "timeout"
    except requests.exceptions.RequestException as e:
        out["detail"] = f"request_error: {type(e).__name__}: {e}"
    return out


def _web3() -> Optional[Any]:
    """Retourne une instance Web3 connectée si web3 est installé, sinon None."""
    if not WEB3_AVAILABLE:
        return None
    try:
        w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": TIMEOUT_S}))
        return w3
    except Exception:
        return None


# ─── Helpers ────────────────────────────────────────────────────────
def _normalize_addr(addr: str) -> str:
    """Normalise une adresse Ethereum (pad à 32 octets pour eth_call/StorageAt)."""
    a = addr.lower()
    if a.startswith("0x"):
        a = a[2:]
    # Pad à 64 hex chars (32 octets).
    return "0x" + a.rjust(64, "0")


def _eth_call(to: str, data: str, from_addr: Optional[str] = None) -> Optional[str]:
    """eth_call read-only. Retourne le résultat hex ou None."""
    params = [{
        "to": to,
        "data": data,
        **({"from": from_addr} if from_addr else {}),
    }, "latest"]
    r = _rpc("eth_call", params=params)
    if r.get("ok"):
        return r.get("result")
    return None


def _eth_getStorageAt(address: str, slot: int) -> Optional[str]:
    """eth_getStorageAt — read storage slot (raw 32-byte hex)."""
    r = _rpc("eth_getStorageAt", params=[address, hex(slot), "latest"])
    if r.get("ok"):
        return r.get("result")
    return None


def _decode_address_from_slot(slot_hex: str) -> Optional[str]:
    """Décode une adresse Ethereum depuis un slot (32 bytes, last 20 bytes)."""
    if not slot_hex or slot_hex == "0x" + "0" * 64:
        return None
    s = slot_hex[2:] if slot_hex.startswith("0x") else slot_hex
    if len(s) < 64:
        return None
    # Les adresses sont stockées dans les 20 derniers octets (padded à gauche).
    addr = s[-40:]
    return "0x" + addr


# ─── 1. check_contract_endpoints ────────────────────────────────────
# Pour un contrat donné :
#   - eth_getStorageAt slots 0..10 (might leak owner, balances, etc.)
#   - eth_call balanceOf(0) pour vérifier qu'il répond (ERC20-like)
#   - Vérification Etherscan API (si ETHERSCAN_API_KEY fournie)
def check_contract_endpoints(address: str = CONTRACT_ADDR) -> dict:
    """For a given contract address, check storage slots 0-10 + Etherscan verification.

    Slots 0-10 sont typiquement : owner, paused-flag, totalSupply,
    balances mapping root, allowances root, etc. Le dump read-only
    peut révéler la structure interne (et des balances brutes).
    """
    result: dict = {
        "check": "contract_endpoints",
        "address": address,
        "contracts_read": False,
        "storage_dumped": False,
        "storage_slots": {},
        "verified_on_etherscan": None,
    }

    # 1. eth_call balanceOf(0) pour vérifier que le contrat répond.
    zero_addr_padded = _normalize_addr("0x" + "0" * 40)
    data_balance_of = SELECTORS["balanceOf"] + zero_addr_padded[2:]
    bal_res = _eth_call(address, data_balance_of)
    if bal_res is not None:
        result["contracts_read"] = True
        result["balance_of_zero_call"] = bal_res

    # 2. eth_getStorageAt slots 0..10.
    slots: dict[str, str] = {}
    any_non_zero = False
    for slot in range(11):
        val = _eth_getStorageAt(address, slot)
        if val is not None:
            slots[str(slot)] = val
            if val != "0x" + "0" * 64:
                any_non_zero = True
    result["storage_slots"] = slots
    result["storage_dumped"] = any_non_zero and len(slots) > 0

    # Tentative de décodage : slot 0 contient souvent l'owner (proxy pattern
    # OZ) ou le totalSupply (token simple). On ne fait que signaler.
    slot0 = slots.get("0")
    if slot0 and slot0 != "0x" + "0" * 64:
        addr_decoded = _decode_address_from_slot(slot0)
        result["slot0_decoded_address"] = addr_decoded

    # 3. Vérification Etherscan API (optionnel — key requise).
    if ETHERSCAN_API_KEY:
        try:
            params = {
                "module": "contract",
                "action": "getabi",
                "address": address,
                "apikey": ETHERSCAN_API_KEY,
            }
            r = _SESSION.get(ETHERSCAN_API, params=params, timeout=TIMEOUT_S)
            if r.status_code == 200:
                j = r.json()
                if j.get("status") == "1":
                    result["verified_on_etherscan"] = True
                    result["abi_length"] = len(str(j.get("result", "")))
                else:
                    result["verified_on_etherscan"] = False
                    result["etherscan_msg"] = j.get("message")
            else:
                result["verified_on_etherscan"] = None
                result["etherscan_detail"] = f"http_{r.status_code}"
        except Exception as e:
            result["etherscan_detail"] = f"error: {type(e).__name__}: {e}"
    else:
        result["verified_on_etherscan"] = None
        result["etherscan_note"] = "ETHERSCAN_API_KEY not set — verification skipped"

    return result


# ─── 2. test_reentrancy (read-only call chain) ──────────────────────
# On ne peut pas tester la réentrance réelle sans envoyer une tx (gas).
# On simule en read-only :
#   - eth_call balanceOf(self) sur le contrat
#   - eth_call totalSupply()
#   - Si le contrat expose une fonction qui appelle un autre contrat (par ex.
#     un token qui appelle une oracle), on le détecte via eth_call.
# La signature réelle de réentrance nécessite l'ABI — on se contente ici
# d'analyser les fonctions read-only disponibles.
def test_reentrancy(address: str = CONTRACT_ADDR) -> dict:
    """Simulate a reentrancy check: call a contract function that calls back.

    Use eth_call (read-only, no gas) to test call chain. On teste :
      - balanceOf(self) — un token qui appelle balanceOf sur lui-même
      - transfer(self, 0) — un token qui se transfère 0 à lui-même
    Si le contrat répond sans erreur → le call chain fonctionne.
    La détection réelle de réentrance nécessiterait l'envoi d'une tx.
    """
    result: dict = {
        "check": "reentrancy",
        "address": address,
        "reentrancy_tested": False,
        "call_chain_works": False,
        "calls": [],
        "note": ("Reentrancy real detection requires sending a tx (gas). "
                 "Here we only test read-only call chains via eth_call."),
    }

    # 1. balanceOf(self)
    self_addr_padded = _normalize_addr(address)
    data_bal = SELECTORS["balanceOf"] + self_addr_padded[2:]
    bal_res = _eth_call(address, data_bal)
    result["calls"].append({
        "function": "balanceOf(self)",
        "data": data_bal,
        "result": bal_res,
        "ok": bal_res is not None,
    })

    # 2. transfer(self, 0) — read-only via eth_call. Encodage :
    #    transfer(address,uint256) → selector + address (32 bytes) + value (32 bytes)
    data_transfer = (SELECTORS["transfer"]
                     + self_addr_padded[2:]
                     + "0" * 64)  # value = 0
    tx_res = _eth_call(address, data_transfer)
    # transfer retourne un bool (32 bytes, last byte 0/1).
    transfer_ok = False
    if tx_res is not None and len(tx_res) >= 66:
        # Dernier byte non-zero = success.
        transfer_ok = tx_res[-1] != "0"
    result["calls"].append({
        "function": "transfer(self, 0)",
        "data": data_transfer,
        "result": tx_res,
        "ok": transfer_ok,
    })

    # 3. transferFrom(self, attacker, 0) — simulacre (address factice).
    attacker = "0x" + "00" * 19 + "01"  # 0x...01
    data_tfrom = (SELECTORS["transferFrom"]
                  + _normalize_addr(address)[2:]      # from
                  + _normalize_addr(attacker)[2:]     # to
                  + "0" * 64)                          # value = 0
    tfrom_res = _eth_call(address, data_tfrom)
    result["calls"].append({
        "function": "transferFrom(self, attacker, 0)",
        "data": data_tfrom,
        "result": tfrom_res,
        "ok": tfrom_res is not None and len(tfrom_res) >= 66 and tfrom_res[-1] != "0",
    })

    # 4. Verdict : si au moins 2 des 3 calls répondent → call_chain_works.
    ok_count = sum(1 for c in result["calls"] if c["ok"])
    result["call_chain_works"] = ok_count >= 2
    result["reentrancy_tested"] = True  # test exécuté (read-only simulation)
    return result


# ─── 3. check_flash_loan_vector ─────────────────────────────────────
# On vérifie que le contrat donné interagit avec des pools de flash loan
# connus (Aave V2/V3, dYdX). On teste via eth_call :
#   - Pour chaque pool, eth_call balanceOf(CONTRACT_ADDR) sur le pool
#     (le pool est lui-même un ERC20-like pour Aave aTokens).
#   - Pour le contrat cible, on regarde s'il a des slots qui ressemblent
#     à des adresses de pools connus (storage slot matching).
def check_flash_loan_vector(address: str = CONTRACT_ADDR) -> dict:
    """Check if contract interacts with Aave/Uniswap V2 flash loan pools.

    Query known Aave/Uniswap/dYdX contract addresses via eth_call.
    On teste :
      - balanceOf(address) sur chaque pool → si > 0, le contrat a des
        fonds déposés dans ce pool.
      - totalSupply() sur chaque pool → sanity check que le pool répond.
    """
    pools = [
        ("Aave_V3_Pool",      AAVE_V3_POOL),
        ("Aave_V2_Pool",      AAVE_V2_POOL),
        ("Uniswap_V2_Router", UNISWAP_V2_ROUTER),
        ("Uniswap_V2_Factory", UNISWAP_V2_FACTORY),
        ("Uniswap_V3_Quoter", UNISWAP_V3_QUOTER),
        ("dYdX_SoloMargin",   DYDX_SOLO_MARGIN),
    ]
    result: dict = {
        "check": "flash_loan_vector",
        "address": address,
        "flash_loan_vector": False,
        "pools_interacting": [],
        "pools_tested": [p[0] for p in pools],
    }

    target_padded = _normalize_addr(address)
    data_bal_of = SELECTORS["balanceOf"] + target_padded[2:]
    data_total_supply = SELECTORS["totalSupply"]

    interacting: list[str] = []
    for name, pool_addr in pools:
        # balanceOf(target) sur le pool — non-zéro = interaction confirmée.
        bal = _eth_call(pool_addr, data_bal_of)
        ts = _eth_call(pool_addr, data_total_supply)
        entry = {
            "pool": name,
            "address": pool_addr,
            "balance_of_target": bal,
            "total_supply": ts,
            "reachable": bal is not None or ts is not None,
            "target_has_funds": False,
        }
        # Decode balance : si non-nul, le contrat a des fonds dans ce pool.
        if bal and bal != "0x" + "0" * 64:
            try:
                v = int(bal, 16)
                if v > 0:
                    entry["target_has_funds"] = True
                    interacting.append(name)
            except ValueError:
                pass
        result["pools_interacting"].append(entry)

    # Verdict : si au moins un pool reachable et le contrat y a des fonds,
    # ou si 3+ pools sont reachables (i.e. le RPC est un mainnet Ethereum),
    # on signale le vecteur flash loan comme étant plausible.
    reachable_count = sum(1 for e in result["pools_interacting"] if e["reachable"])
    funds_count = sum(1 for e in result["pools_interacting"] if e["target_has_funds"])
    result["reachable_pools"] = reachable_count
    result["target_funds_pools"] = interacting
    if funds_count > 0 or reachable_count >= 3:
        result["flash_loan_vector"] = True
        result["note"] = ("Contract target has funds in DeFi pools OR RPC is a "
                          "mainnet with DeFi pools reachable → flash loan attack "
                          "vector plausible (needs ABI for full exploit).")
    else:
        result["note"] = "No flash loan pools reachable / no target funds in pools."
    return result


# ─── 4. check_erc20_approve_race ────────────────────────────────────
# Vérifie que le contrat expose approve() et transferFrom() — la paire
# qui rend le race condition ERC20 possible (approve → front-run via
# transferFrom avant que l'owner ne révise).
# NB : la vuln "approve race" est un défaut de spec ERC20, pas une faille
# du contrat seul. On signale juste l'exposition.
def check_erc20_approve_race(address: str = CONTRACT_ADDR) -> dict:
    """Check if contract has approve/transferFrom (potential race condition)."""
    result: dict = {
        "check": "erc20_approve_race",
        "address": address,
        "erc20_approval_risk": False,
        "approve_present": False,
        "transferFrom_present": False,
        "transfer_present": False,
        "is_erc20": False,
    }

    # approve(spender=0, value=0) — read-only, devrait retourner true.
    zero_padded = _normalize_addr("0x" + "0" * 40)
    data_approve = SELECTORS["approve"] + zero_padded[2:] + "0" * 64
    appr_res = _eth_call(address, data_approve)
    if appr_res is not None and len(appr_res) >= 66 and appr_res[-1] != "0":
        result["approve_present"] = True

    # transferFrom(from=0, to=0, value=0) — read-only.
    data_tfrom = (SELECTORS["transferFrom"]
                  + zero_padded[2:]  # from
                  + zero_padded[2:]  # to
                  + "0" * 64)         # value
    tfrom_res = _eth_call(address, data_tfrom)
    if tfrom_res is not None and len(tfrom_res) >= 66 and tfrom_res[-1] != "0":
        result["transferFrom_present"] = True

    # transfer(0, 0) — read-only.
    data_transfer = SELECTORS["transfer"] + zero_padded[2:] + "0" * 64
    tx_res = _eth_call(address, data_transfer)
    if tx_res is not None and len(tx_res) >= 66 and tx_res[-1] != "0":
        result["transfer_present"] = True

    # Verdict : si approve + transferFrom présents → race condition possible.
    result["is_erc20"] = (
        result["approve_present"] and result["transferFrom_present"]
        and result["transfer_present"]
    )
    result["erc20_approval_risk"] = (
        result["approve_present"] and result["transferFrom_present"]
    )
    if result["erc20_approval_risk"]:
        result["note"] = ("Contract exposes approve + transferFrom. ERC20 approve "
                          "race condition possible (spec-level, not contract bug).")
    else:
        result["note"] = "approve/transferFrom not both present — no ERC20 race."
    return result


# ─── 5. detect_mev_bot ──────────────────────────────────────────────
# On regarde txpool_content pour identifier des patterns de front-running :
#   - Beaucoup de txs en pending du même sender (bot)
#   - Tx qui ciblent des paires Uniswap (data starts with swap selector)
#   - Tx avec gasPrice très élevé (> 100 gwei)
def detect_mev_bot() -> dict:
    """Check mempool (txpool_content) for front-running bot activity."""
    result: dict = {
        "check": "mev_bot_detection",
        "mev_activity": False,
        "txpool_accessible": False,
        "pending_count": 0,
        "queued_count": 0,
        "top_senders": [],
        "high_gas_txs": 0,
        "swap_txs": 0,
        "note": None,
    }

    # 1. txpool_status pour compter (plus léger que txpool_content).
    r_status = _rpc("txpool_status")
    if r_status.get("ok"):
        result["txpool_accessible"] = True
        status = r_status.get("result") or {}
        try:
            result["pending_count"] = int(status.get("pending", "0x0"), 16)
        except (TypeError, ValueError):
            pass
        try:
            result["queued_count"] = int(status.get("queued", "0x0"), 16)
        except (TypeError, ValueError):
            pass

    # 2. txpool_content pour analyser les senders/data.
    r_content = _rpc("txpool_content")
    if r_content.get("ok"):
        result["txpool_accessible"] = True
        content = r_content.get("result") or {}
        sender_counts: dict[str, int] = {}
        swap_selectors = (
            SELECTORS["swapExactTokensForTokens"],  # Uniswap V2
            "0x8803dbee",  # swapTokensForExactTokens
            "0xfb3bdb41",  # swapETHForExactTokens
            "0x7ff36ab5",  # swapExactETHForTokens
            "0x5c11d795",  # swapExactTokensForTokensSupportingFeeOnTransferTokens
            "0xb6f9de95",  # Uniswap V3 exactInputSingle
        )
        # content = {pending: {addr: {nonce: tx}}, queued: {...}}
        for pool_type in ("pending", "queued"):
            pool = content.get(pool_type, {})
            if not isinstance(pool, dict):
                continue
            for sender, txs in pool.items():
                if not isinstance(txs, dict):
                    continue
                sender_counts[sender] = sender_counts.get(sender, 0) + len(txs)
                for _nonce, tx in txs.items():
                    if not isinstance(tx, dict):
                        continue
                    # gasPrice analysis
                    gp = tx.get("gasPrice", "0x0")
                    try:
                        gp_int = int(gp, 16) if isinstance(gp, str) else 0
                        # > 100 gwei = high gas (front-running indicator)
                        if gp_int > 100 * 10**9:
                            result["high_gas_txs"] += 1
                    except (TypeError, ValueError):
                        pass
                    # input data analysis (swap selectors)
                    inp = tx.get("input", "") or ""
                    if inp[:10] in swap_selectors:
                        result["swap_txs"] += 1

        # Top 5 senders (un bot a typiquement bcp de txs en pending).
        top = sorted(sender_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
        result["top_senders"] = [{"address": a, "pending_txs": n} for a, n in top]

    # Verdict : MEV activity plausible si :
    #   - >= 5 swap txs en pending, OU
    #   - 1 sender a >= 10 txs en pending (bot pattern), OU
    #   - >= 3 high-gas (>100 gwei) txs (front-running indicator).
    has_bot_sender = any(n >= 10 for _a, n in
                         [(s["address"], s["pending_txs"])
                          for s in result["top_senders"]])
    if (result["swap_txs"] >= 5 or has_bot_sender
            or result["high_gas_txs"] >= 3):
        result["mev_activity"] = True
        result["note"] = ("MEV / front-running bot activity detected in mempool "
                          f"(swap_txs={result['swap_txs']}, "
                          f"high_gas_txs={result['high_gas_txs']}, "
                          f"max_sender_txs="
                          f"{result['top_senders'][0]['pending_txs'] if result['top_senders'] else 0}).")
    else:
        result["note"] = ("No clear MEV bot pattern in mempool (or txpool_content "
                          "not accessible).")
    return result


# ─── Synthèse JSON ──────────────────────────────────────────────────
def main() -> None:
    # 1. LAB guard.
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "lab": False,
            "error": "LAB guard not satisfied",
            "detail": ("Set LAB=1 to confirm lab authorization. Enumerating "
                       "smart contracts / DeFi pools for attack surface mapping "
                       "without authorization is illegal (Art. 323-1)."),
            "legal_note": ("Art. 323-1 Code pénal — reconnaissance DeFi / smart "
                           "contract pour attaque = préparation d'infraction. "
                           "Lab isolé uniquement."),
        }, indent=2))
        sys.exit(1)

    # 2. Exécution des 5 checks (timeout 5s chacun, read-only).
    endpoints = check_contract_endpoints(CONTRACT_ADDR)
    reentrancy = test_reentrancy(CONTRACT_ADDR)
    flash = check_flash_loan_vector(CONTRACT_ADDR)
    approve_race = check_erc20_approve_race(CONTRACT_ADDR)
    mev = detect_mev_bot()

    # 3. Synthèse JSON stdout.
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "lab": True,
        "safe_mode": SAFE_MODE,
        "target": RPC_URL,
        "contract": CONTRACT_ADDR,
        "timeout_s": TIMEOUT_S,
        "web3_library_available": WEB3_AVAILABLE,
        # Champs de sortie attendus (spec) :
        "contracts_read": bool(endpoints.get("contracts_read")),
        "storage_dumped": bool(endpoints.get("storage_dumped")),
        "reentrancy_tested": bool(reentrancy.get("reentrancy_tested")),
        "flash_loan_vector": bool(flash.get("flash_loan_vector")),
        "erc20_approval_risk": bool(approve_race.get("erc20_approval_risk")),
        "mev_activity": bool(mev.get("mev_activity")),
        # Détails structurés pour le rapport :
        "details": {
            "contract_endpoints": endpoints,
            "reentrancy": reentrancy,
            "flash_loan_vector": flash,
            "erc20_approve_race": approve_race,
            "mev_bot_detection": mev,
        },
        "regulations": ["PSAN-AMF", "RGPD", "Travel Rule FATF"],
        "legal_note": ("Enumeration DeFi / smart contract sans autorisation : "
                       "Art. 323-1 Code pénal (préparation d'infraction). "
                       "Lab isolé uniquement."),
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
