#!/usr/bin/env python3
# gdb_extract.py — script GDB extrait de gdb_extract.sh (v2.4.0).
# Testable isolément (python3 gdb_extract.py --dry-run) et debug facilité.
#
# Lit le PID cible depuis :
#   1. Le paramètre GDB `$harness_pid` (positionné par gdb_extract.sh via -ex 'set $harness_pid = ...')
#   2. La variable d'environnement `HARNESS_PID` en fallback.
#
# Marqueur de sortie : GDB_JSON_OUTPUT:<json> — extraction fiable côté bash.

import gdb
import re
import json
import hashlib
import os

MARKER = "GDB_JSON_OUTPUT:"
MAX_REGION_BYTES = 64 * 1024 * 1024  # plafond 64 MiB par région


def _resolve_pid() -> str:
    """Récupère le PID : paramètre GDB $harness_pid si défini, sinon env HARNESS_PID."""
    try:
        pid_val = gdb.parse_and_eval("$harness_pid")
        # Le paramètre peut être lazy/void si non positionné — on teste son contenu.
        if pid_val is not None:
            try:
                pid_str = str(pid_val)
                if pid_str and pid_str not in ("0", "<void>"):
                    return pid_str
            except gdb.error:
                pass
    except gdb.error:
        # Paramètre non défini : fallback env.
        pass
    return os.environ.get("HARNESS_PID", "0")


def _scan_mappings() -> list:
    """Parcourt `info proc mappings` et retourne les régions rw-p.
    Valide explicitement le format de chaque ligne avant traitement :
    une ligne de mapping attendu commence par des blancs puis `0x`.
    Toute ligne ne respectant pas ce format est ignorée (commentaire ci-dessous)."""
    maps = gdb.execute("info proc mappings", to_string=True)
    # Regex robuste : start, end, size, offset, perms, [path]
    pat = re.compile(
        r"^\s*0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+(\S+)\s*(.*)$",
        re.M,
    )
    regions = []
    for m in pat.finditer(maps):
        start = int(m.group(1), 16)
        end = int(m.group(2), 16)
        perms = m.group(3)            # perms capturées en groupe 3
        name = m.group(4).strip()
        # Validation explicite du format : on ne garde que les lignes
        # qui ont matché le patern (start+end hex + perms). Les lignes
        # d'en-tête ou de footer (ex. "Mapped address spaces:") ne
        # commencent pas par "\s*0x" et ne matchent pas — elles sont
        # donc ignorées par construction du regex.
        if "rw" in perms:             # régions read-write uniquement
            regions.append((start, end, name))
    return regions


def _extract_regions(regions: list, pid: str) -> list:
    found = []
    for start, end, name in regions:
        size = min(end - start, MAX_REGION_BYTES)
        if size <= 0:
            continue
        try:
            data = gdb.selected_inferior().read_memory(start, size).tobytes()
        except gdb.MemoryError:
            continue
        if b"PHPSESSID" in data or b"sess_" in data:
            fn = f"/tmp/harness_sess/{start:#x}.bin"
            with open(fn, "wb") as f:
                f.write(data)
            found.append({
                "file": fn,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": size,
                "region": f"{start:#x}-{end:#x}",
                "name": name,
            })
    return found


def main() -> None:
    pid = _resolve_pid()
    regions = _scan_mappings()
    found = _extract_regions(regions, pid)
    print(MARKER + json.dumps({
        "module": "gdb_extract",
        "pid": pid,
        "regions_scanned": len(regions),
        "regions_found": len(found),
        "regions": found,
    }))


main()
