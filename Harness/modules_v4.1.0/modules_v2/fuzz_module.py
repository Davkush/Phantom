#!/usr/bin/env python3
# HARNESS-VALIDATION — module fuzzing AFL++.

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT      = Path(__file__).resolve().parent
AFL_DIR   = Path(os.environ.get("AFL_DIR", "/opt/AFLplusplus"))
TARGET    = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./target_binary")
SEEDS_DIR = Path("./seeds")
OUT_DIR   = Path("./fuzz_out")
# v2.4 : LOG_FILE basé sur ROOT (chemin absolu stable)
LOG_FILE  = ROOT / "fuzz_afl.log"
DURATION  = int(sys.argv[2]) if len(sys.argv) > 2 else 60


class PrereqError(Exception):
    """Erreur de prérequis pour le fuzzing AFL."""
    pass


# v4.1.5 : résolution unique (PATH en priorité, puis AFL_DIR)
AFL_BIN = Path(shutil.which("afl-fuzz") or str(AFL_DIR / "afl-fuzz"))

def check_prereqs():
    """Vérifie les prérequis. Lève PrereqError si manquant."""
    errors = []
    if not AFL_BIN.exists():
        errors.append(f"afl-fuzz not found (PATH + {AFL_DIR})")
    if not TARGET.exists():
        errors.append(f"target binary not found: {TARGET}")
    if errors:
        raise PrereqError("; ".join(errors))


def run_fuzz():
    """Lance la campagne AFL++ bornée en temps."""
    SEEDS_DIR.mkdir(exist_ok=True)
    try:
        has_seeds = any(SEEDS_DIR.iterdir())
    except (PermissionError, OSError):
        has_seeds = False
    if not has_seeds:
        (SEEDS_DIR / "seed1").write_bytes(b"test input\n")
    import shutil
    # v2.4 : nettoyer l'ancienne campagne (AFL refuse -o non-vide)
    shutil.rmtree(OUT_DIR, ignore_errors=True)
    OUT_DIR.mkdir(exist_ok=True)
    # EXIT_ON_TIME : si pas de nouveau coverage pendant DURATION//4 secondes,
    # sortir (la cible est probablement saturée). -V fixe la durée max.
    exit_on_time = max(DURATION // 4, 10)
    env = {**os.environ,
           "AFL_TMPDIR": "/dev/shm",
           "AFL_NO_UI": "1",
           "AFL_EXIT_ON_TIME": str(exit_on_time),
           "AFL_FAST_CAL": "1"}
    cmd = [str(AFL_BIN),
           "-i", str(SEEDS_DIR),
           "-o", str(OUT_DIR),
           "-V", str(DURATION),
           "--", str(TARGET), "@@"]
    # Redirection stdout/stderr vers fichier (pas capture_output en mémoire)
    with open(LOG_FILE, "w") as logf:
        proc = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT,
                              env=env, timeout=DURATION + 60)
    return proc


def collect():
    """Parse les résultats depuis les fichiers AFL (pas depuis stdout)."""
    crashes_dir = OUT_DIR / "default" / "crashes"
    crashes = list(crashes_dir.glob("id:*")) if crashes_dir.exists() else []
    stats_file = OUT_DIR / "default" / "fuzzer_stats"
    stats = {}
    if stats_file.exists():
        for line in stats_file.read_text().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                stats[k.strip()] = v.strip()
    return {
        "crashes": len(crashes),
        "execs_done": stats.get("execs_done"),
        "paths_total": stats.get("paths_total"),
        "unique_crashes": stats.get("unique_crashes"),
        "last_update": stats.get("last_update"),
    }


if __name__ == "__main__":
    t0 = time.time()
    try:
        check_prereqs()
    except PrereqError as e:
        print(json.dumps({"module": "afl_fuzz", "error": "prereq_failed", "details": str(e)}))
        sys.exit(2)
    proc = run_fuzz()
    result = collect()
    result.update({
        "module": "afl_fuzz",
        "target": str(TARGET),
        "duration_s": round(time.time() - t0, 1),
        "exit_code": proc.returncode,
        "log_file": str(LOG_FILE),
    })
    print(json.dumps(result, indent=2))
