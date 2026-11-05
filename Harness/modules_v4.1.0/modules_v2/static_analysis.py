#!/usr/bin/env python3
# HARNESS-VALIDATION — analyse statique Semgrep + CodeQL.

import json
import subprocess
import sys
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

TARGET = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./source")
TIMEOUT = int(os.environ.get("SEMGREP_TIMEOUT", "600"))

# v2.4 : Path("") résout vers "." → check explicite sur string vide
_codeql_db_str = os.environ.get("CODEQL_DB", "").strip()
CODEQL_DB = Path(_codeql_db_str) if _codeql_db_str else None
CODEQL_PACK = os.environ.get("CODEQL_PACK", "codeql/cpp-queries")

SEMGREP_RULES = [
    "p/php",
    "p/c",
    "p/security-audit",
]


def run_semgrep():
    """Lance Semgrep avec les règles configurées (en parallèle)."""
    def _run_one(rule):
        # v2.4 : sortie stdout redirigée vers fichier temporaire (anti RAM-bloat)
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmpf:
            tmpfile_path = tmpf.name
        try:
            try:
                proc = subprocess.run(
                    ["semgrep", "--config", rule, "--json", "--quiet",
                     "--timeout", str(TIMEOUT), str(TARGET)],
                    stdout=__import__('contextlib').closing(open(tmpfile_path, 'w')),
                    stderr=subprocess.PIPE,
                    timeout=TIMEOUT + 30)
            except FileNotFoundError:
                # v2.4 : semgrep absent → ENV_ERROR propre
                return {"config": rule, "findings": [], "count": 0,
                        "error": "semgrep_not_installed"}
            try:
                data = json.loads(Path(tmpfile_path).read_text() or "{}")
            except (json.JSONDecodeError, FileNotFoundError):
                data = {"results": [],
                        "error": proc.stderr[:200].decode(errors="replace")
                                 if proc.stderr else "unknown"}
        finally:
            Path(tmpfile_path).unlink(missing_ok=True)

        findings = [
            {
                "rule": r.get("check_id"),
                "path": r.get("path"),
                "line": r.get("start", {}).get("line"),
                "severity": r.get("extra", {}).get("severity"),
            }
            for r in data.get("results", [])
        ]
        return {
            "config": rule,
            "findings": findings,
            "count": len(findings),
        }

    results = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(_run_one, rule): rule for rule in SEMGREP_RULES}
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


def run_codeql():
    """Lance CodeQL si une base de données est disponible."""
    # v2.4 : None-safe (Path("") résolvait ".")
    if CODEQL_DB is None or not CODEQL_DB.exists():
        return {
            "available": False,
            "hint": "Créer la base : codeql database create codeql-db "
                    "--language=cpp --source-root=. --overwrite",
        }
    sarif_path = "/tmp/codeql_results.sarif"
    try:
        proc = subprocess.run(
            ["codeql", "database", "analyze", str(CODEQL_DB),
             CODEQL_PACK,
             "--format=sarif-latest",
             f"--output={sarif_path}",
             "--download-codeql"],
            capture_output=True, timeout=900)
    except FileNotFoundError:
        # v2.4 : codeql absent → ENV_ERROR propre
        return {"available": True, "error": "codeql_not_installed"}
    except subprocess.TimeoutExpired:
        return {"available": True, "error": "codeql_timeout_900s"}
    # Parse SARIF
    summary = {"total": 0, "by_severity": {}}
    try:
        sarif = json.loads(Path(sarif_path).read_text())
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                sev = result.get("level", "note")
                summary["total"] += 1
                summary["by_severity"][sev] = \
                    summary["by_severity"].get(sev, 0) + 1
    except (json.JSONDecodeError, FileNotFoundError):
        pass
    return {
        "available": True,
        "exit_code": proc.returncode,
        "sarif_path": sarif_path,
        "summary": summary,
    }


if __name__ == "__main__":
    report = {
        "module": "static_analysis",
        "target": str(TARGET),
        "semgrep": run_semgrep(),
        "codeql": run_codeql(),
    }
    report["semgrep_total"] = sum(s["count"] for s in report["semgrep"])
    print(json.dumps(report, indent=2))
