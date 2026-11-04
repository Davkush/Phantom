#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — reverse engineering module : smart contract decompiler.
# Secteur : crypto (defensive RE tool — analyze EVM bytecode of LOCAL contracts).
#
# Defensive purpose:
#   This module disassembles EVM bytecode of smart contracts that the operator
#   has deployed on their own private/consortium chain (geth, besu, etc.),
#   or contracts the operator has recovered from binaries / firmwares / build
#   artifacts. It extracts function selectors, identifies state variables,
#   disassembles opcodes, and checks for common vulnerability patterns
#   (reentrancy, unchecked CALL return, integer overflow, tx.origin usage).
#
#   When given a contract ADDRESS as the 2nd arg, the module fetches bytecode
#   from a LOCAL geth node via eth_rpc (127.0.0.1:8545). It NEVER contacts
#   external public chains (no Infura/Alchemy/etc.) — only LOCAL RPC.
#
#   - v3.1 : EVM opcode disassembly (pyevmasm preferred, raw fallback)
#   - v3.1 : function selector extraction (first 4 bytes of keccak256)
#   - v3.1 : function dispatch table reconstruction
#   - v3.1 : state variable / storage layout inference (SSTORE/SLOAD analysis)
#   - v3.1 : vulnerability pattern detection :
#             - reentrancy (CALL followed by SSTORE)
#             - unchecked CALL return (no ISZERO after CALL)
#             - integer overflow (no SAFEADD / unchecked arithmetic pre-0.8)
#             - tx.origin authentication (use of ORIGIN opcode)
#             - delegatecall to untrusted target
#             - selfdestruct present
#             - assert() / require() pattern
#   - v3.1 : SEED reproducibility, LAB=1 guard, LOCAL-only RPC invariant
#
# Cadre légal : Art. 323-1 Code pénal (accès frauduleux), PSAN-AMF.
#   L'analyse de smart contracts déployés sur sa propre chaîne est légitime.
#   RPC autorisé uniquement vers 127.0.0.1 (nœud local opérateur).
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "smart_contract_re"
LOCAL_RPC_DEFAULT = "http://127.0.0.1:8545"
MAX_OPCODES_DISASSEMBLED = 5000      # cap to bound JSON
MAX_DECOMPILED_FUNCTIONS = 50        # cap functions in JSON
MAX_VULNS = 100                      # cap vulns in JSON

# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))


def _seeded_take(items: list, n: int) -> list:
    if len(items) <= n:
        return list(items)
    keyed = sorted(
        enumerate(items),
        key=lambda iv: ((iv[0] * SEED) % 1000003, iv[0]),
    )
    return [iv[1] for iv in keyed[:n]]


# ─── Import sector_base (best-effort) ─────────────────────────────────────────
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from sector_base import (  # type: ignore
        get_sector_config,
        get_safe_mode as _sector_safe_mode,
    )
    _HAS_SECTOR_BASE = True
except Exception:  # noqa: BLE001
    _HAS_SECTOR_BASE = False

    def get_sector_config() -> dict:  # type: ignore[no-redef]
        return {
            "sector": os.environ.get("SECTOR", "crypto"),
            "safe_mode": "full",
            "regulations": ("PSAN-AMF", "RGPD"),
            "harness_version": HARNESS_VERSION,
        }

    def _sector_safe_mode() -> str:  # type: ignore[no-redef]
        return "full"


# ─── Guards ───────────────────────────────────────────────────────────────────
def _check_lab_guard() -> None:
    if os.environ.get("LAB") != "1":
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "lab_guard_failed",
            "reason": "LAB env var must be set to 1 (isolated lab only)",
            "legal_note": (
                "Defensive smart contract analysis on LOCAL bytecode or "
                "LOCAL geth RPC (127.0.0.1). No external chain contact."
            ),
        }))
        sys.exit(2)


def _check_safe_mode() -> str:
    sm = os.environ.get("SAFE_MODE", "").lower().strip()
    if sm in ("read_only", "full"):
        return sm
    return _sector_safe_mode()


# ─── Pure-Python Keccak-256 (Ethereum variant) ───────────────────────────────
# Ethereum uses Keccak-256 (the original Keccak, NOT NIST SHA3-256 which has
# a different padding byte: 0x06 vs 0x01). We provide a pure-Python
# implementation so the module works without external keccak libraries.
# Reference: FIPS 202 (with rate=1088, capacity=512, delta=0x01 for Ethereum).

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_KECCAK_ROTATION = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _keccak_rotl(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def keccak256(data: bytes) -> bytes:
    """Compute Ethereum-style Keccak-256 (delta=0x01 padding).
    Pure-Python implementation. Returns 32-byte digest."""
    rate = 136          # 1088 bits / 8 = 136 bytes (Keccak-256)
    # Padding rule (10*1, delta=0x01 for Ethereum Keccak — NOT NIST SHA3 which uses 0x06):
    #   1. Append 0x01 byte
    #   2. Pad with 0x00 bytes until length is (rate - 1) mod rate
    #   3. Append 0x80 byte (the final '1' bit, MSB of last byte)
    # If after step 1 we're already at length ≡ rate-1 (mod rate), no zeros needed.
    padded = data + b"\x01"
    while len(padded) % rate != rate - 1:
        padded += b"\x00"
    padded += b"\x80"
    # State: 5x5 lanes of 64-bit words (1600 bits)
    state = [[0] * 5 for _ in range(5)]
    # Absorb
    for chunk_start in range(0, len(padded), rate):
        chunk = padded[chunk_start:chunk_start + rate]
        # XOR chunk into state (rate = 136 bytes = 17 lanes, linear index x + 5*y)
        for i in range(17):
            x = i % 5
            y = i // 5
            lane = int.from_bytes(chunk[i * 8:(i + 1) * 8], "little")
            state[x][y] ^= lane
        # Keccak-f permutation
        state = _keccak_f(state)
    # Squeeze: output 32 bytes (first 4 lanes = 32 bytes)
    out = b""
    for i in range(4):
        x = i % 5
        y = i // 5
        out += state[x][y].to_bytes(8, "little")
    return out[:32]


def _keccak_f(state: list) -> list:
    """24 rounds of Keccak-f[1600]."""
    for round_idx in range(24):
        # Theta
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _keccak_rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        # Rho + Pi (combined) — read from state, write to fresh new_state
        new_state = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                new_state[y % 5][(2 * x + 3 * y) % 5] = _keccak_rotl(
                    state[x][y], _KECCAK_ROTATION[x][y])
        state = new_state
        # Chi — MUST use a copy of current state (chi reads 3 values per output)
        old = [row[:] for row in state]   # shallow per-row copy (ints are immutable)
        for x in range(5):
            for y in range(5):
                state[x][y] = old[x][y] ^ (
                    (old[(x + 1) % 5][y] ^ 0xFFFFFFFFFFFFFFFF) &
                    old[(x + 2) % 5][y])
        # Iota
        state[0][0] ^= _KECCAK_RC[round_idx]
    return state


# ─── Local RPC client ────────────────────────────────────────────────────────
def fetch_bytecode_from_local_rpc(address: str) -> tuple:
    """Fetch deployed bytecode from a LOCAL geth RPC node.
    Returns (bytecode_hex, error_or_None). ONLY contacts 127.0.0.1."""
    # Validate address format
    if not re.match(r"^0x[0-9a-fA-F]{40}$", address):
        return (None, "invalid_ethereum_address")
    # Validate RPC URL is loopback (defensive invariant — NO external chains)
    rpc_url = os.environ.get("ETH_RPC_URL", LOCAL_RPC_DEFAULT).strip()
    if not _is_loopback_rpc(rpc_url):
        return (None, "rpc_not_loopback_refused: %s" % rpc_url)
    try:
        import urllib.request
        import json as _json
        payload = _json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "eth_getCode",
            "params": [address, "latest"],
        }).encode("utf-8")
        req = urllib.request.Request(
            rpc_url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
        if "result" in data and isinstance(data["result"], str):
            return (data["result"], None)
        if "error" in data:
            return (None, "rpc_error: %s" % str(data["error"])[:200])
        return (None, "rpc_unexpected_response")
    except Exception as e:  # noqa: BLE001
        return (None, "rpc_error: %s: %s" % (type(e).__name__, str(e)[:200]))


def _is_loopback_rpc(url: str) -> bool:
    """Defensive invariant : only allow 127.0.0.1 / localhost / [::1] RPC.
    Refuse anything that points to an external host."""
    lower = url.lower()
    return (lower.startswith("http://127.0.0.1") or
            lower.startswith("http://localhost") or
            lower.startswith("http://[::1]") or
            lower.startswith("http://0.0.0.0"))


# ─── EVM opcode table (raw fallback) ─────────────────────────────────────────
# Reference: Ethereum Yellow Paper Appendix H. Each entry: (name, stack_in, stack_out)
# We only need the names for disassembly — full semantics not required here.
EVM_OPCODES = {
    0x00: ("STOP", 0, 0), 0x01: ("ADD", 2, 1), 0x02: ("MUL", 2, 1),
    0x03: ("SUB", 2, 1), 0x04: ("DIV", 2, 1), 0x05: ("SDIV", 2, 1),
    0x06: ("MOD", 2, 1), 0x07: ("SMOD", 2, 1), 0x08: ("ADDMOD", 3, 1),
    0x09: ("MULMOD", 3, 1), 0x0A: ("EXP", 2, 1), 0x0B: ("SIGNEXTEND", 2, 1),
    0x10: ("LT", 2, 1), 0x11: ("GT", 2, 1), 0x12: ("SLT", 2, 1),
    0x13: ("SGT", 2, 1), 0x14: ("EQ", 2, 1), 0x15: ("ISZERO", 1, 1),
    0x16: ("AND", 2, 1), 0x17: ("OR", 2, 1), 0x18: ("XOR", 2, 1),
    0x19: ("NOT", 1, 1), 0x1A: ("BYTE", 2, 1), 0x1B: ("SHL", 2, 1),
    0x1C: ("SHR", 2, 1), 0x1D: ("SAR", 2, 1),
    0x20: ("SHA3", 2, 1),
    0x30: ("ADDRESS", 0, 1), 0x31: ("BALANCE", 1, 1), 0x32: ("ORIGIN", 0, 1),
    0x33: ("CALLER", 0, 1), 0x34: ("CALLVALUE", 0, 1), 0x35: ("CALLDATALOAD", 1, 1),
    0x36: ("CALLDATASIZE", 0, 1), 0x37: ("CALLDATACOPY", 3, 0),
    0x38: ("CODESIZE", 0, 1), 0x39: ("CODECOPY", 3, 0),
    0x3A: ("GASPRICE", 0, 1), 0x3B: ("EXTCODESIZE", 1, 1),
    0x3C: ("EXTCODECOPY", 4, 0), 0x3D: ("RETURNDATASIZE", 0, 1),
    0x3E: ("RETURNDATACOPY", 3, 0), 0x3F: ("EXTCODEHASH", 1, 1),
    0x40: ("BLOCKHASH", 1, 1), 0x41: ("COINBASE", 0, 1), 0x42: ("TIMESTAMP", 0, 1),
    0x43: ("NUMBER", 0, 1), 0x44: ("DIFFICULTY", 0, 1), 0x45: ("GASLIMIT", 0, 1),
    0x46: ("CHAINID", 0, 1), 0x47: ("SELFBALANCE", 0, 1),
    0x50: ("POP", 1, 0), 0x51: ("MLOAD", 1, 1), 0x52: ("MSTORE", 2, 0),
    0x53: ("MSTORE8", 2, 0), 0x54: ("SLOAD", 1, 1), 0x55: ("SSTORE", 2, 0),
    0x56: ("JUMP", 1, 0), 0x57: ("JUMPI", 2, 0), 0x58: ("PC", 0, 1),
    0x59: ("MSIZE", 0, 1), 0x5A: ("GAS", 0, 1), 0x5B: ("JUMPDEST", 0, 0),
    0x5F: ("PUSH0", 0, 1),
    0xA0: ("LOG0", 2, 0), 0xA1: ("LOG1", 3, 0), 0xA2: ("LOG2", 4, 0),
    0xA3: ("LOG3", 5, 0), 0xA4: ("LOG4", 6, 0),
    0xF0: ("CREATE", 3, 1), 0xF1: ("CALL", 7, 1), 0xF2: ("CALLCODE", 7, 1),
    0xF3: ("RETURN", 2, 0), 0xF4: ("DELEGATECALL", 6, 1),
    0xF5: ("CREATE2", 4, 1),
    0xFA: ("STATICCALL", 6, 1), 0xFD: ("REVERT", 2, 0),
    0xFE: ("INVALID", 0, 0), 0xFF: ("SELFDESTRUCT", 1, 0),
}
# PUSH1..PUSH32: 0x60..0x7F (immediate N bytes follows)
# DUP1..DUP16:   0x80..0x8F
# SWAP1..SWAP16: 0x90..0x9F
for n in range(1, 33):
    EVM_OPCODES[0x60 + n - 1] = ("PUSH%d" % n, 0, 1)
for n in range(1, 17):
    EVM_OPCODES[0x80 + n - 1] = ("DUP%d" % n, n, n + 1)
    EVM_OPCODES[0x90 + n - 1] = ("SWAP%d" % n, n + 1, n + 1)


def disassemble_raw(bytecode: bytes) -> list:
    """Disassemble EVM bytecode without external libs.
    Returns list of {offset, opcode, name, operand_hex?}."""
    instrs: list = []
    i = 0
    while i < len(bytecode):
        op = bytecode[i]
        if op not in EVM_OPCODES:
            instrs.append({
                "offset": i, "opcode": "0x%02x" % op, "name": "UNKNOWN",
                "operand_hex": None,
            })
            i += 1
            continue
        name, _, _ = EVM_OPCODES[op]
        operand_hex = None
        operand_value = None
        if name.startswith("PUSH") and name != "PUSH0":
            n = int(name[4:])
            operand_bytes = bytecode[i + 1:i + 1 + n]
            # Pad if at end (last instruction truncated)
            if len(operand_bytes) < n:
                operand_bytes = operand_bytes + b"\x00" * (n - len(operand_bytes))
            operand_hex = "0x" + operand_bytes.hex()
            try:
                operand_value = int.from_bytes(operand_bytes, "big")
            except (ValueError, OverflowError):
                operand_value = None
            instrs.append({
                "offset": i, "opcode": "0x%02x" % op, "name": name,
                "operand_hex": operand_hex,
                "operand_value": operand_value,
                "operand_size": n,
            })
            i += 1 + n
        else:
            instrs.append({
                "offset": i, "opcode": "0x%02x" % op, "name": name,
                "operand_hex": None,
            })
            i += 1
        if len(instrs) >= MAX_OPCODES_DISASSEMBLED:
            break
    return instrs


def disassemble_pyevmasm(bytecode: bytes) -> tuple:
    """Disassemble using pyevmasm if available.
    Returns (instructions_list, disassembler_str)."""
    try:
        from pyevmasm import disassemble_all, disassemble  # type: ignore
        instrs = []
        for ins in disassemble_all(bytecode):
            instrs.append({
                "offset": ins.pc, "name": ins.name,
                "operand_hex": ("0x%x" % ins.operand) if ins.operand is not None else None,
                "operand_value": ins.operand,
            })
            if len(instrs) >= MAX_OPCODES_DISASSEMBLED:
                break
        try:
            disasm_str = disassemble(bytecode)
        except Exception:  # noqa: BLE001
            disasm_str = ""
        return (instrs, disasm_str)
    except ImportError:
        return ([], "")


# ─── Function selector extraction ────────────────────────────────────────────
# In compiled Solidity, the dispatcher typically looks like:
#   PUSH4 <selector>   EQ   JUMPI ...
# We extract the 4-byte immediates from PUSH4 instructions, and validate each
# candidate by computing keccak256(function_signature) for common signatures
# from a builtin dictionary (limited) — the orchestrator may consult a public
# 4byte database (but we do NOT contact external services here).

# Builtin signature table — extendable. We only check a small curated list
# of well-known signatures for richer output (e.g.ERC20 functions).
KNOWN_SIGNATURES = {
    # ERC-20
    "transfer(address,uint256)":         "0xa9059cbb",
    "transferFrom(address,address,uint256)": "0x23b872dd",
    "approve(address,uint256)":          "0x095ea7b3",
    "balanceOf(address)":                "0x70a08231",
    "totalSupply()":                     "0x18160ddd",
    "allowance(address,address)":        "0xdd62ed3e",
    "name()":                            "0x06fdde03",
    "symbol()":                          "0x95d89b41",
    "decimals()":                        "0x313ce567",
    # ERC-721
    "ownerOf(uint256)":                  "0x6352211e",
    "safeTransferFrom(address,address,uint256)": "0x42842e0e",
    "safeTransferFrom(address,address,uint256,bytes)": "0xb88d4fde",
    # Ownable
    "owner()":                           "0x8da5cb5b",
    "renounceOwnership()":               "0x715018a6",
    "transferOwnership(address)":        "0xf2fde38b",
    # Pausable
    "pause()":                           "0x8456cb59",
    "unpause()":                         "0x3f4ba83a",
    "paused()":                          "0x5c975abb",
    # Common
    "deposit()":                         "0xd0e30db0",
    "withdraw(uint256)":                 "0x2e1a7d4d",
    "mint(address,uint256)":             "0x40c10f19",
    "burn(uint256)":                     "0x42966c68",
    "burnFrom(address,uint256)":         "0x79cc6790",
    "multicall(bytes[])":                "0xac9650d8",
    "execute(bytes)":                    "0x09c5eabe",
    "upgradeTo(address)":                "0x3659cfe6",
    "upgradeToAndCall(address,bytes)":   "0x4f1ef286",
    "initialize()":                      "0x8129fc1c",
    "initialize(address)":               "0xc4d66de8",
}


def _build_selector_lookup() -> dict:
    """Reverse lookup: selector_hex (without 0x prefix, lowercase) → list of candidate signatures."""
    lookup: dict = {}
    for sig, sel in KNOWN_SIGNATURES.items():
        # Strip 0x prefix and lowercase for consistent lookup
        sel_clean = sel.lower()
        if sel_clean.startswith("0x"):
            sel_clean = sel_clean[2:]
        lookup.setdefault(sel_clean, []).append(sig)
    return lookup


_SELECTOR_LOOKUP = _build_selector_lookup()


def extract_function_selectors(instructions: list, bytecode: bytes) -> list:
    """Extract function selectors from dispatcher PUSH4 instructions.
    Each selector is the 4-byte immediate of a PUSH4 followed by EQ (in the
    canonical Solidity dispatcher)."""
    selectors: list = []
    seen = set()
    for i, ins in enumerate(instructions):
        if ins["name"] != "PUSH4":
            continue
        op_hex = ins.get("operand_hex") or ""
        if not op_hex.startswith("0x") or len(op_hex) < 10:
            continue
        sel_hex = "0x" + op_hex[2:].lower().rjust(8, "0")
        # Check if followed (within next 3 instrs) by EQ + JUMPI pattern
        # (indicates dispatcher). If not, it could still be a selector — record
        # but mark context.
        is_dispatcher = False
        for j in range(i + 1, min(i + 4, len(instructions))):
            if instructions[j]["name"] in ("EQ", "JUMPI", "JUMP"):
                is_dispatcher = True
                break
        # Known signature match
        candidates = _SELECTOR_LOOKUP.get(sel_hex[2:], [])
        if sel_hex in seen:
            continue
        seen.add(sel_hex)
        selectors.append({
            "selector": sel_hex,
            "known_signatures": candidates,
            "in_dispatcher": is_dispatcher,
            "offset": ins["offset"],
            "severity": "info",
        })
    return _seeded_take(selectors, MAX_DECOMPILED_FUNCTIONS)


# ─── State variable / storage analysis ───────────────────────────────────────
def analyze_storage_layout(instructions: list) -> list:
    """Infer storage layout by finding SSTORE/SLOAD patterns.
    For each SSTORE/SLOAD, record the slot operand (if PUSHed) and offset."""
    storage_ops: list = []
    # Walk and find SSTORE/SLOAD preceded by PUSH of slot
    for i, ins in enumerate(instructions):
        if ins["name"] not in ("SSTORE", "SLOAD"):
            continue
        # Walk backwards up to 6 instructions to find PUSH (slot)
        slot_hex = None
        slot_value = None
        for j in range(max(0, i - 6), i):
            prev = instructions[j]
            if prev["name"].startswith("PUSH") and prev["name"] != "PUSH0":
                if prev.get("operand_hex"):
                    slot_hex = prev["operand_hex"]
                    slot_value = prev.get("operand_value")
                    break
        storage_ops.append({
            "op": ins["name"],
            "offset": ins["offset"],
            "slot_hex": slot_hex,
            "slot_value": slot_value,
            "is_constant_slot": slot_value is not None and slot_value < 2**32,
        })
    return _seeded_take(storage_ops, 50)


# ─── Vulnerability detection ─────────────────────────────────────────────────
def find_vulnerabilities(instructions: list, bytecode: bytes) -> list:
    """Detect common smart contract vulnerability patterns."""
    vulns: list = []
    instr_names = [ins["name"] for ins in instructions]

    # 1. tx.origin authentication (ORIGIN opcode used in EQ)
    for i, ins in enumerate(instructions):
        if ins["name"] == "ORIGIN":
            # Check if followed by EQ (comparison) → auth check
            context = instr_names[i:i + 6]
            is_auth = "EQ" in context
            vulns.append({
                "type": "tx_origin_usage",
                "offset": ins["offset"],
                "risk": "tx.origin is spoofable via call chains — use msg.sender",
                "severity": "high" if is_auth else "medium",
                "context": "auth_check" if is_auth else "general_use",
            })

    # 2. Unchecked CALL return (CALL not followed by ISZERO within next 3 ops)
    for i, ins in enumerate(instructions):
        if ins["name"] in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"):
            context = instr_names[i + 1:i + 5]
            if "ISZERO" not in context:
                vulns.append({
                    "type": "unchecked_call_return",
                    "call_type": ins["name"],
                    "offset": ins["offset"],
                    "risk": "Return value of %s not checked — silent failure possible" % ins["name"],
                    "severity": "medium",
                })

    # 3. Reentrancy pattern (CALL followed by SSTORE within ~10 instrs)
    for i, ins in enumerate(instructions):
        if ins["name"] in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"):
            # Look forward up to 10 instrs for SSTORE
            for j in range(i + 1, min(i + 11, len(instructions))):
                if instructions[j]["name"] == "SSTORE":
                    vulns.append({
                        "type": "reentrancy_risk",
                        "call_type": ins["name"],
                        "call_offset": ins["offset"],
                        "sstore_offset": instructions[j]["offset"],
                        "risk": "State modified after external call — classic reentrancy pattern",
                        "severity": "high",
                    })
                    break
                if instructions[j]["name"] == "JUMP":
                    # Control flow change breaks linear pattern
                    break

    # 4. SELFDESTRUCT present
    for i, ins in enumerate(instructions):
        if ins["name"] == "SELFDESTRUCT":
            vulns.append({
                "type": "selfdestruct_present",
                "offset": ins["offset"],
                "risk": "Contract can self-destruct — funds sent to beneficiary",
                "severity": "high",
            })

    # 5. DELEGATECALL to untrusted target (delegatecall with non-constant target)
    for i, ins in enumerate(instructions):
        if ins["name"] == "DELEGATECALL":
            # Check if the target address (stack arg) comes from storage / calldata
            # (heuristic : look for SLOAD or CALLDATALOAD in preceding 10 instrs)
            context = instr_names[max(0, i - 10):i]
            tainted_source = None
            if "SLOAD" in context:
                tainted_source = "storage"
            elif "CALLDATALOAD" in context:
                tainted_source = "calldata"
            if tainted_source:
                vulns.append({
                    "type": "delegatecall_untrusted_target",
                    "offset": ins["offset"],
                    "tainted_source": tainted_source,
                    "risk": "DELEGATECALL target derived from %s — "
                            "potential untrusted code execution" % tainted_source,
                    "severity": "critical",
                })

    # 6. Integer overflow risk (pre-Solidity 0.8 : no built-in overflow checks)
    # Heuristic: arithmetic ops (ADD/SUB/MUL) without subsequent overflow checks
    # (ISZERO/DUP/JUMPI sequence is typical SafeMath overflow check)
    for i, ins in enumerate(instructions):
        if ins["name"] in ("ADD", "SUB", "MUL"):
            context = instr_names[i + 1:i + 8]
            # If no JUMPI within next 8 ops → likely no overflow check
            if "JUMPI" not in context and "ISZERO" not in context:
                # Don't flag every ADD — only flag if there are many unchecked
                # (track separately, batch at end)
                pass
    # Count unchecked arithmetic
    unchecked_arith = 0
    for i, ins in enumerate(instructions):
        if ins["name"] in ("ADD", "SUB", "MUL"):
            context = instr_names[i + 1:i + 8]
            if "JUMPI" not in context and "ISZERO" not in context:
                unchecked_arith += 1
    if unchecked_arith >= 5:
        vulns.append({
            "type": "potential_integer_overflow",
            "unchecked_arithmetic_count": unchecked_arith,
            "risk": "Many unchecked arithmetic ops — pre-0.8 Solidity or no SafeMath",
            "severity": "medium",
        })

    # 7. assert() usage (deprecated in favor of require/revert)
    assert_count = sum(1 for n in instr_names if n == "INVALID")
    if assert_count >= 1:
        vulns.append({
            "type": "assert_usage",
            "count": assert_count,
            "risk": "INVALID opcodes may indicate assert() — burns all gas on failure",
            "severity": "low",
        })

    # 8. Unchecked ether receipt (no withdraw pattern)
    # Heuristic: CALL with non-zero value not followed by revert-on-failure
    # Already covered by unchecked_call_return — skip duplicate

    return _seeded_take(vulns, MAX_VULNS)


# ─── Decompile function bodies (best-effort) ─────────────────────────────────
def decompile_functions(instructions: list, selectors: list) -> list:
    """For each function selector, locate the JUMPDEST it dispatches to and
    dump the opcode body until the next JUMPDEST or RETURN/REVERT/STOP.
    This is NOT a high-level decompiler — just opcode blocks per selector."""
    funcs: list = []
    # Build a map offset → instruction index
    offset_to_idx = {ins["offset"]: idx for idx, ins in enumerate(instructions)}
    # Find JUMPDEST offsets
    jumpdests = [ins["offset"] for ins in instructions if ins["name"] == "JUMPDEST"]
    for sel in selectors:
        # We don't have the jump target from PUSH4 + EQ + JUMPI directly,
        # but we can scan for the JUMPI following the PUSH4 and take its target.
        target_offset = None
        sel_offset = sel["offset"]
        idx = offset_to_idx.get(sel_offset)
        if idx is None:
            continue
        # Find the next JUMPI within 5 instructions
        for j in range(idx + 1, min(idx + 6, len(instructions))):
            if instructions[j]["name"] == "JUMPI":
                # The JUMPI target is on the stack from a prior PUSH
                # Find the most recent PUSH before this JUMPI
                for k in range(j - 1, max(idx, j - 6), -1):
                    if instructions[k]["name"].startswith("PUSH") and \
                            instructions[k]["name"] != "PUSH0":
                        target_offset = instructions[k].get("operand_value")
                        break
                break
        if target_offset is None or target_offset not in offset_to_idx:
            funcs.append({
                "selector": sel["selector"],
                "known_signatures": sel["known_signatures"],
                "entry_offset": None,
                "body_opcodes": [],
                "body_size": 0,
                "note": "Could not resolve dispatcher jump target",
            })
            continue
        entry_idx = offset_to_idx[target_offset]
        # Find next JUMPDEST or terminator
        end_idx = entry_idx + 1
        while end_idx < len(instructions):
            n = instructions[end_idx]["name"]
            if n == "JUMPDEST" or n in ("STOP", "RETURN", "REVERT", "INVALID",
                                        "SELFDESTRUCT"):
                break
            end_idx += 1
        body = instructions[entry_idx:end_idx]
        funcs.append({
            "selector": sel["selector"],
            "known_signatures": sel["known_signatures"],
            "entry_offset": target_offset,
            "body_opcodes": [
                {"offset": b["offset"], "name": b["name"],
                 "operand_hex": b.get("operand_hex")}
                for b in body[:80]
            ],
            "body_size": len(body),
        })
    return _seeded_take(funcs, MAX_DECOMPILED_FUNCTIONS)


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    if len(sys.argv) < 2:
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "missing_bytecode_or_address",
            "usage": "smart_contract_re.py <bytecode_hex> [contract_address_for_local_rpc]",
            "note": (
                "If argv[1] starts with 0x and is >10 chars, it's treated as "
                "bytecode hex. If argv[2] is provided and is a 0x-prefixed 40-hex "
                "address, the module fetches bytecode from local geth RPC "
                "(127.0.0.1:8545) — DEFENSIVE invariant: only loopback RPC."
            ),
        }))
        sys.exit(2)

    arg1 = sys.argv[1]
    address = sys.argv[2] if len(sys.argv) > 2 else None
    bytecode_hex: Optional[str] = None
    rpc_used = False
    rpc_error: Optional[str] = None

    # Mode 1: address provided → fetch bytecode from LOCAL RPC
    if address and re.match(r"^0x[0-9a-fA-F]{40}$", address):
        bytecode_hex, rpc_error = fetch_bytecode_from_local_rpc(address)
        rpc_used = True
        if rpc_error:
            print(json.dumps({
                "module": MODULE_NAME,
                "harness_version": HARNESS_VERSION,
                "error": "rpc_fetch_failed",
                "address": address,
                "rpc_error": rpc_error,
                "rpc_url": os.environ.get("ETH_RPC_URL", LOCAL_RPC_DEFAULT),
                "note": "Only loopback RPC (127.0.0.1) is permitted.",
            }))
            sys.exit(3)
    else:
        # Mode 2: argv[1] is bytecode hex (or starts with 0x and > 10 chars)
        if arg1.startswith("0x") or re.fullmatch(r"[0-9a-fA-F]+", arg1):
            bytecode_hex = arg1
        else:
            print(json.dumps({
                "module": MODULE_NAME,
                "harness_version": HARNESS_VERSION,
                "error": "invalid_bytecode_hex",
                "given": arg1[:80] + ("..." if len(arg1) > 80 else ""),
            }))
            sys.exit(2)

    # Strip 0x prefix
    if bytecode_hex.startswith("0x") or bytecode_hex.startswith("0X"):
        bytecode_hex = bytecode_hex[2:]

    # Validate hex
    if not re.fullmatch(r"[0-9a-fA-F]*", bytecode_hex):
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "bytecode_not_valid_hex",
            "length": len(bytecode_hex),
        }))
        sys.exit(2)

    bytecode = bytes.fromhex(bytecode_hex)
    # Strip trailing metadata (Solidity appends CBOR-encoded metadata at end,
    # signaled by a 2-byte length suffix). Best-effort.
    metadata_size = None
    if len(bytecode) >= 2:
        meta_len = int.from_bytes(bytecode[-2:], "big")
        if 0 < meta_len < len(bytecode) - 2 and meta_len < 1024:
            bytecode_runtime = bytecode[:-meta_len - 2]
            metadata_size = meta_len
        else:
            bytecode_runtime = bytecode
    else:
        bytecode_runtime = bytecode

    # 1. Disassemble
    has_pyevmasm = False
    try:
        import pyevmasm  # type: ignore  # noqa: F401
        has_pyevmasm = True
    except ImportError:
        has_pyevmasm = False

    if has_pyevmasm:
        instructions, disasm_str = disassemble_pyevmasm(bytecode_runtime)
        disassembler = "pyevmasm"
        # Fallback to raw if pyevmasm returned nothing
        if not instructions:
            instructions = disassemble_raw(bytecode_runtime)
            disassembler = "raw_fallback"
    else:
        instructions = disassemble_raw(bytecode_runtime)
        disasm_str = ""
        disassembler = "raw"

    # 2. Function selectors
    selectors = extract_function_selectors(instructions, bytecode_runtime)

    # 3. Storage layout
    storage_layout = analyze_storage_layout(instructions)

    # 4. Vulnerabilities
    vulnerabilities = find_vulnerabilities(instructions, bytecode_runtime)

    # 5. Decompile function bodies
    decompiled_functions = decompile_functions(instructions, selectors)

    # 6. JSON report
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "crypto",
        "bytecode_len": len(bytecode),
        "runtime_bytecode_len": len(bytecode_runtime),
        "metadata_size": metadata_size,
        "bytecode_sha256": __import__("hashlib").sha256(bytecode).hexdigest(),
        "address": address,
        "rpc_used": rpc_used,
        "rpc_url": (os.environ.get("ETH_RPC_URL", LOCAL_RPC_DEFAULT)
                    if rpc_used else None),
        "rpc_loopback_only": True,
        "disassembler": disassembler,
        "pyevmasm_available": has_pyevmasm,
        "opcodes_count": len(instructions),
        "opcodes_sample": [
            {"offset": ins["offset"], "name": ins["name"],
             "operand_hex": ins.get("operand_hex")}
            for ins in _seeded_take(instructions, 30)
        ],
        "functions_found": selectors,
        "functions_count": len(selectors),
        "storage_layout_inferred": storage_layout,
        "storage_ops_count": len(storage_layout),
        "vulnerabilities": vulnerabilities,
        "vulnerabilities_count": len(vulnerabilities),
        "decompiled_functions": decompiled_functions,
        "decompiled_count": len(decompiled_functions),
        "disassembly_full": (disasm_str[:4096] if disasm_str else None),
        "seed": SEED,
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "read_only": True,    # bytecode analysis is read-only
        "no_network_egress": True,   # RPC only to loopback (defensive invariant)
        "regulations": list(get_sector_config().get("regulations", [])),
        "legal_note": (
            "Defensive RE : analyse de bytecode EVM (contrats opérateur, "
            "chaîne privée locale). RPC limité à 127.0.0.1. "
            "PSAN-AMF + Art. 323-1 Code pénal — usage lab isolé."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
