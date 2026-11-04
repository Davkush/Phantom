#!/usr/bin/env python3
# HARNESS-VALIDATION v4.0.0 — orchestrateur signé, sectoriel.
# FUSION : architecture ingénieur (config unifiée + sectors field + report sectorisé)
#        + sécurité v3.x (HMAC, safe_eval, LAB guard, RE, IDS)
#
# v4.0.0 changelog :
#   - modules_config.json unique avec champ 'sectors' (architecture ingénieur)
#   - report_{SECTOR}_{seed}.json (nom sectorisé)
#   - sector_config.py unifie sector_base + interface ingénieur
#   - 44+ modules protocoles supportés
#   - RE modules + ids_test intégrés
#   - buildings sector ajouté

import ast
import copy
import hashlib
import hmac
import json
import logging
import math
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
OUT  = ROOT / "reports"
OUT.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("harness")

HARNESS_VERSION  = "4.1.0"
MAX_AST_NODES    = 200
MAX_AST_DEPTH    = 20          # v4.1: anti-DoS par profondeur AST
_MODULE_TIMEOUT  = int(os.environ.get("HARNESS_MODULE_TIMEOUT", "300"))

# ─── Import sectoriel unifié ─────────────────────────────────────
try:
    from sector_config import (
        SECTOR, get_sector_modules, get_matrix_file, sector_info,
    )
    log.info("Secteur actif : %s", SECTOR)
except ImportError:
    SECTOR = os.environ.get("SECTOR", "crypto")
    def get_sector_modules(): return []
    def get_matrix_file(): return f"matrix_{SECTOR}.json"
    def sector_info(): return {"sector": SECTOR}
    log.warning("sector_config.py absent — fallback secteur %s", SECTOR)

# ─── Chargement de clé strict + entropie ─────────────────────────
def load_key() -> bytes:
    k = os.environ.get("REPORT_KEY")
    _DEFAULT_KEYS = {"", "harness-lab-key", "changeme", "secret"}
    if k.lower() in _DEFAULT_KEYS:
        log.error("REPORT_KEY absent ou valeur par défaut interdite")
        sys.exit("[FATAL] REPORT_KEY absent. Générer : openssl rand -hex 32")

    fmt = os.environ.get("REPORT_KEY_FORMAT", "auto").lower()

    def _try_hex(s: str) -> bytes | None:
        try:
            if len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
                return bytes.fromhex(s)
        except ValueError:
            pass
        return None

    if fmt == "hex":
        kb = _try_hex(k)
        if kb is None:
            sys.exit("[FATAL] REPORT_KEY_FORMAT=hex mais clé invalide")
        log.info("REPORT_KEY interprétée comme hex")
    elif fmt == "raw":
        kb = k.encode()
        log.info("REPORT_KEY interprétée comme raw bytes")
    else:
        decoded = _try_hex(k)
        kb = decoded if decoded is not None else k.encode()
        log.info("REPORT_KEY auto-détectée (%d bytes)", len(kb))

    if len(kb) < 32:
        sys.exit(f"[FATAL] REPORT_KEY trop courte ({len(kb)} < 32)")

    freq    = {b: kb.count(b) for b in set(kb)}
    n       = len(kb)
    entropy = -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)
    if entropy < 3.5:
        sys.exit(f"[FATAL] REPORT_KEY entropie insuffisante ({entropy:.1f} < 3.5)")
    return kb


# ─── v4.1: helpers DRY ──────────────────────────────────────────
def _canonical_json(obj) -> bytes:
    """JSON canonique pour hash/HMAC (sort_keys + separators compacts)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def sign_report(report: dict, key: bytes) -> dict:
    """Ajoute global_sha256 + signature au rapport (immutable deepcopy)."""
    frozen = {k: v for k, v in report.items() if k not in ("signature", "global_sha256")}
    report = copy.deepcopy(frozen)
    report["global_sha256"] = hashlib.sha256(_canonical_json(frozen)).hexdigest()
    report["signature"] = sign({**frozen, "global_sha256": report["global_sha256"]}, key)
    return report

# ─── v4.1: profondeur AST anti-DoS ──────────────────────────────
def _check_ast_depth(node, depth=0):
    if depth > MAX_AST_DEPTH:
        return False
    for child in ast.iter_child_nodes(node):
        if not _check_ast_depth(child, depth + 1):
            return False
    return True

# ─── HMAC-SHA-256 ────────────────────────────────────────────────
def sign(report: dict, key: bytes) -> str:
    body = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    return hmac.HMAC(key, body, hashlib.sha256).hexdigest()

def verify(report: dict, key: bytes) -> bool:
    """Vérifie signature + global_sha256 (defense in depth, no short-circuit)."""
    sig        = report.get("signature")
    stored_sha = report.get("global_sha256")
    if not sig or not stored_sha:
        return False

    body_only = {k: v for k, v in report.items()
                 if k not in ("signature", "global_sha256")}

    expected_sha = hashlib.sha256(
        json.dumps(body_only, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    body_for_hmac = {**body_only, "global_sha256": stored_sha}
    expected_sig  = sign(body_for_hmac, key)

    sha_ok = hmac.compare_digest(expected_sha, stored_sha)
    sig_ok = hmac.compare_digest(expected_sig, sig)
    return sha_ok and sig_ok

def verify_report_file(path: str | Path, key: bytes) -> bool:
    report = json.loads(Path(path).read_text())
    return verify(report, key)

# ─── safe_eval — AST whitelist + anti-DoS + anti-dunder ──────────
_ALLOWED_NODES = (
    ast.Expression, ast.BoolOp, ast.Compare, ast.Call,
    ast.Attribute, ast.Name, ast.Load, ast.Constant,
    ast.Tuple, ast.List, ast.Dict, ast.Set,
    ast.And, ast.Or,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.In, ast.NotIn, ast.Is, ast.IsNot,
    ast.UnaryOp, ast.Not, ast.USub, ast.UAdd,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div,
    ast.FloorDiv, ast.Mod,
    ast.Subscript, ast.Slice,
)
_ALLOWED_ATTRS = frozenset({"get", "keys", "values", "items", "lower", "upper", "strip"})

def safe_eval(expr: str, context: dict) -> object:
    try:
        tree = ast.parse(expr, mode='eval')
    except SyntaxError:
        return None
    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_AST_NODES:
        log.warning("safe_eval: expression trop complexe (%d nœuds)", len(nodes))
        return None
    for node in nodes:
        if not isinstance(node, _ALLOWED_NODES):
            return None
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("__") or node.attr not in _ALLOWED_ATTRS:
                return None
        if isinstance(node, ast.Name) and node.id.startswith("__"):
            return None
    try:
        return eval(compile(tree, '<safe_eval>', 'eval'),
                    {"__builtins__": {}}, context)
    except Exception:
        return None

# ─── Filtre modules ──────────────────────────────────────────────
def module_exists(cmd: list) -> bool:
    if not cmd:
        return False
    if cmd[0] in ("php", "bash", "sh", "python3"):
        if not shutil.which(cmd[0]):
            log.warning("Interpréteur '%s' non trouvé dans PATH", cmd[0])
            return False
        return len(cmd) > 1 and Path(cmd[1]).is_file()  # v4.1: is_file rejette les dirs
    return Path(cmd[0]).exists()

@dataclass
class Result:
    module:               str
    seed:                 int
    started:              float
    duration_ms:          float
    exit_code:            int
    status:               str
    stdout_sha256:        str
    cmd_canonical_sha256: str
    summary:              dict       = field(default_factory=dict)
    expectation_met:      bool | None = None

def run_module(name: str, cmd: list, seed: int,
               expected_expr: str | None = None) -> Result:
    t0 = time.time()
    child_env = {
        **os.environ,
        "SEED":           str(seed),
        "LAB":            "1",
        "PYTHONHASHSEED": "0",
        "SECTOR":         SECTOR,
    }
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=_MODULE_TIMEOUT, env=child_env,
            text=True, start_new_session=True  # v4.1: isolation + auto-decode
        )
        dt = (time.time() - t0) * 1000
        try:
            summary = json.loads(proc.stdout.decode(errors="replace") or "{}")
        except json.JSONDecodeError:
            full    = proc.stdout.decode(errors="replace")
            summary = {"raw_head": full[:200], "raw_full": full}

        _STATUS_BY_CODE = {0: "OK", 1: "NEGATIVE", 2: "ENV_ERROR"}
        status = _STATUS_BY_CODE.get(proc.returncode, "INTERNAL_BBUG")

        met = None
        if expected_expr:
            met_val = safe_eval(expected_expr, {"summary": summary, **summary})
            met = bool(met_val) if met_val is not None else None

        return Result(
            module=name, seed=seed, started=t0, duration_ms=round(dt, 1),
            exit_code=proc.returncode, status=status,
            stdout_sha256=hashlib.sha256(proc.stdout).hexdigest(),
            cmd_canonical_sha256=hashlib.sha256(
                json.dumps(cmd, separators=(",", ":")).encode()).hexdigest(),
            summary=summary, expectation_met=met,
        )
    except subprocess.TimeoutExpired:
        dt = (time.time() - t0) * 1000
        log.error("Module %s timeout (%ds)", name, _MODULE_TIMEOUT)
        return Result(
            module=name, seed=seed, started=t0, duration_ms=round(dt, 1),
            exit_code=-1, status="INTERNAL_BUG",
            stdout_sha256="", cmd_canonical_sha256="",
            summary={"error": f"timeout_{_MODULE_TIMEOUT}s"},
        )
    except FileNotFoundError:
        return Result(
            module=name, seed=seed, started=t0, duration_ms=0.0,
            exit_code=-2, status="ENV_ERROR",
            stdout_sha256="", cmd_canonical_sha256="",
            summary={"error": "binary_not_found"},
        )

# ─── Config unifiée avec filtrage sectoriel ──────────────────────
def load_modules_config(matrix: dict) -> list:
    """Charge modules_config.json unique avec champ 'sectors'.
    Filtrage : si 'sectors' absent = universel, sinon SECTOR doit être dans la liste."""
    config_path = ROOT / "modules_config.json"
    if not config_path.exists():
        log.warning("modules_config.json absent — fallback hardcoded")
        return _fallback_modules()

    config = json.loads(config_path.read_text())
    result = []
    for name, entry in config.get("modules", {}).items():
        entry_sectors = entry.get("sectors")
        if entry_sectors and SECTOR not in entry_sectors:
            continue
        expected = entry.get("expected") or matrix.get(name, {}).get("expected")
        result.append((name, entry["cmd"], expected))

    log.info("Secteur %s : %d module(s) chargé(s)", SECTOR, len(result))
    return result

def _fallback_modules() -> list:
    return [
        ("osint_leak",    ["python3", str(ROOT / "osint_leak.py"), "example.com", str(ROOT / "source")]),
        ("sqli",          ["python3", str(ROOT / "sqli_module.py"), "http://127.0.0.1:8080/api", "device_id"]),
        ("ssrf",          ["python3", str(ROOT / "ssrf_module.py"), "http://127.0.0.1:8080/fetch", "url"]),
        ("post_exploit_enum", ["python3", str(ROOT / "post_exploit_enum.py")]),
        ("persistence",   ["python3", str(ROOT / "persistence_module.py"), "all"]),
        ("static_analysis", ["python3", str(ROOT / "static_analysis.py"), str(ROOT / "source")]),
    ]

def main():
    # LAB=1 guard
    if os.environ.get("LAB") != "1":
        sys.exit("[FATAL] Positionner LAB=1 pour exécuter le harness")

    key  = load_key()
    seed = int(os.environ.get("SEED", "1337"))
    try:
        seed = int(seed)
    except (ValueError, TypeError):
        seed = 1337

    # Matrix sectorielle
    matrix_file = ROOT / get_matrix_file()
    if not matrix_file.exists():
        log.warning("Matrix %s absente — fallback matrix.json", matrix_file.name)
        matrix_file = ROOT / "matrix.json"
    matrix = json.loads(matrix_file.read_text()) if matrix_file.exists() else {}
    log.info("Matrix chargée : %s", matrix_file.name)

    module_list = load_modules_config(matrix)

    skipped, results = [], []
    for name, cmd, expected in module_list:
        if not module_exists(cmd):
            log.warning("Module %s ignoré (manquant)", name)
            skipped.append({"module": name, "reason": "script_or_interpreter_missing"})
            continue
        log.info("Exécution module %s...", name)
        results.append(run_module(name, cmd, seed, expected))

    # Corps immuable + deepcopy
    report = {
        "harness_version": HARNESS_VERSION,
        "sector":          SECTOR,
        "sector_info":     sector_info(),
        "seed":            seed,
        "generated_at":    round(time.time(), 3),
        "operator":        os.environ.get("OPERATOR", "unknown"),
        "matrix_file":     matrix_file.name,
        "results":         [asdict(r) for r in results],
        "skipped":         skipped,
    }

    frozen_body = copy.deepcopy(report)
    report["global_sha256"] = hashlib.sha256(
        json.dumps(frozen_body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    body_for_hmac       = {**frozen_body, "global_sha256": report["global_sha256"]}
    report["signature"] = sign(body_for_hmac, key)

    # v4.0 : nom sectorisé
    path = OUT / f"report_{SECTOR}_{seed}.json"
    path.write_text(json.dumps(report, indent=2))

    loaded = json.loads(path.read_text())
    if not verify(loaded, key):
        sys.exit("[FATAL] verify() self-test failed")

    log.info("Rapport signé : %s", path)
    print(json.dumps({
        "report":               str(path),
        "sector":               SECTOR,
        "sig":                  report["signature"],
        "modules_ok":           sum(1 for r in results if r.status == "OK"),
        "modules_negative":     sum(1 for r in results if r.status == "NEGATIVE"),
        "modules_env_error":    sum(1 for r in results if r.status == "ENV_ERROR"),
        "modules_internal_bug": sum(1 for r in results if r.status == "INTERNAL_BUG"),
        "skipped":              len(skipped),
        "expectations_met":     sum(1 for r in results if r.expectation_met is True),
        "expectations_unmet":   sum(1 for r in results if r.expectation_met is False),
    }, indent=2))

if __name__ == "__main__":
    main()
