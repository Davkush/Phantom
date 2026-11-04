#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — Cross-sector: supply chain security probe.
# Applies to every sector that ships software (banking core, health PACS,
# energy SCADA, telecom core, crypto exchange, IT). Scans a project's
# dependency manifests for known-vulnerable patterns and typosquatting.
#
# Checks performed:
#   - NPM packages        (package-lock.json — names + versions)
#   - Python packages     (requirements.txt, Pipfile.lock, poetry.lock)
#   - PHP packages        (composer.lock)
#   - Typosquatting       (built-in confusion list)
#   - Install scripts     (preinstall/postinstall in package.json —
#                          primary supply-chain attack vector)
#   - Known malicious     (built-in allowlist of historical malicious pkg)
#   - Git deps            (git+/github: deps — mutable, not pinned)
#
# Pure stdlib (os + json + re). No network. LAB=1 guard (consistency
# with the cross-sector module family — this module is read-only but
# the guard enforces lab framing for the whole harness).
#
# Usage:
#   LAB=1 python3 supply_chain_module.py [project_dir]
#   LAB=1 python3 supply_chain_module.py ./source
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ─── Constants ───────────────────────────────────────────────────────
HARNESS_VERSION = "3.0.0"
MODULE_NAME = "supply_chain_probe"

# Built-in typosquatting confusion list (typo → legitimate package).
# These are real-world impersonation attempts observed on PyPI / npm.
TYPOSQUAT_LIST: Dict[str, str] = {
    # Python
    "reqeusts": "requests",
    "requets": "requests",
    "request": "requests",
    "requessts": "requests",
    "python-dateutil2": "python-dateutil",
    "pyyaml3": "pyyaml",
    "openpi": "openpyxl",
    "openpyxl2": "openpyxl",
    "crptography": "cryptography",
    "cryptograpy": "cryptography",
    "cryptography2": "cryptography",
    "pip-install": "pip",
    "setuptool": "setuptools",
    "djanggo": "django",
    "flaskk": "flask",
    "pyjwt2": "pyjwt",
    "boto3-core": "boto3",
    "beautifulsoup": "beautifulsoup4",
    "numpy2": "numpy",
    "pandas2": "pandas",
    "tensorflow-gpu2": "tensorflow",
    # JavaScript
    "lodahs": "lodash",
    "lodsh": "lodash",
    "loadsh": "lodash",
    "lodhash": "lodash",
    "express2": "express",
    "reacct": "react",
    "reactt": "react",
    "axios2": "axios",
    "momet": "moment",
    "momnt": "moment",
    "chalk2": "chalk",
    "vuexy": "vuex",
    "angualr": "angular",
    # PHP
    "guzzlehtt": "guzzlehttp",
    "symfony2": "symfony",
    "monolog2": "monolog",
}

# Built-in list of historically malicious packages (real cases).
# Sources: Socket.dev, GitHub Security Advisories, PyPI/NPM takedowns.
KNOWN_MALICIOUS = {
    # npm — event-stream incident (2018)
    "event-stream",
    "flatmap-stream",
    # npm — ua-parser-js supply chain compromise (2021)
    "ua-parser-jr",
    "ua-parser-js-old",
    # npm — restler (credential stealer, 2020)
    "restler",
    # npm — coa / rc (2021 Urok)
    "coa",
    "rc.tgz",
    # npm — colors.js / faker sabotage (2022 Marak Squires)
    "colors.js-old",
    # PyPI — PyMafka, etc. (sample set, not exhaustive)
    "pymafka",
    "py-proactive",
    "python3-dateutil",
    "jeIlyfish",                  # note lowercase-L substituted with capital-I
    "cryptofree",
    # PyPI — colour-picker / lmaolol
    "colour-picker",
    "lmaolol",
}

# file → parser mapping is done inline; these are the manifests we look for.
NPM_MANIFESTS = ("package-lock.json",)
NPM_PKG_JSON = ("package.json",)
PY_MANIFESTS = ("requirements.txt", "Pipfile.lock", "poetry.lock",
                "requirements-dev.txt", "constraints.txt")
PHP_MANIFESTS = ("composer.lock",)

INSTALL_SCRIPT_KEYS = ("preinstall", "postinstall", "prepare", "prepublish",
                       "publish", "postpublish")

# Regexes for unpinned Python requirements.
PINNED_REQ_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+!]+)")
UNPINNED_REQ_RE = re.compile(r"^[A-Za-z0-9_.\-]+\s*(>=|<=|~=|>|<|!=|;|=)")
BARE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")

# Regex for git / github URL deps.
GIT_DEP_RE = re.compile(r"(git\+|github:|bitbucket:|gitlab:|https?://github\.com/|"
                        r"https?://gitlab\.com/|https?://bitbucket\.org/)", re.I)


# ─── LAB guard ──────────────────────────────────────────────────────
def lab_guard() -> bool:
    return os.environ.get("LAB") == "1"


# ─── CLI args ────────────────────────────────────────────────────────
PROJECT_DIR = sys.argv[1] if len(sys.argv) > 1 else "./source"


# ─── Helpers ─────────────────────────────────────────────────────────
def _safe_read_json(path: Path) -> Optional[Any]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        return json.loads(text)
    except (OSError, json.JSONDecodeError):
        return None


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _iter_manifests(root: Path, names: Tuple[str, ...]) -> List[Path]:
    """Walk root recursively, return all matching manifest paths (max 200)."""
    found: List[Path] = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            # Skip obvious noise dirs to keep the scan fast & focused.
            dirnames[:] = [d for d in dirnames
                           if d not in {".git", "node_modules", ".venv", "venv",
                                        "__pycache__", ".tox", "dist", "build",
                                        ".cache", ".idea", ".vscode"}]
            for fn in filenames:
                if fn in names:
                    found.append(Path(dirpath) / fn)
                    if len(found) >= 200:
                        return found
    except OSError:
        pass
    return found


# ─── NPM ─────────────────────────────────────────────────────────────
def scan_npm_packages(root: Path) -> Dict[str, Any]:
    """Parse package-lock.json (v1/v2/v3) and extract package names+versions."""
    manifests = _iter_manifests(root, NPM_MANIFESTS)
    packages: List[Dict[str, str]] = []
    parsed_files: List[str] = []
    for mpath in manifests:
        data = _safe_read_json(mpath)
        if not isinstance(data, dict):
            continue
        parsed_files.append(str(mpath))
        # Lockfile v1: top-level "dependencies"
        deps = data.get("dependencies", {})
        if isinstance(deps, dict):
            for name, info in deps.items():
                if isinstance(info, dict):
                    ver = info.get("version") or ""
                    integrity = info.get("integrity") or ""
                    resolved = info.get("resolved") or ""
                    packages.append({
                        "name": name,
                        "version": ver,
                        "integrity": integrity,
                        "resolved": resolved,
                        "source": str(mpath),
                        "registry": "npm",
                    })
        # Lockfile v2/v3: packages (flattened) — also includes node_modules paths
        pkgs = data.get("packages", {})
        if isinstance(pkgs, dict):
            for key, info in pkgs.items():
                # key looks like "node_modules/lodash" or scoped
                name = key.split("node_modules/")[-1] if "node_modules/" in key else key
                if not name or name == "":
                    continue
                if isinstance(info, dict):
                    ver = info.get("version") or ""
                    integrity = info.get("integrity") or ""
                    resolved = info.get("resolved") or ""
                    # Skip the project root entry (version is empty for the project)
                    if ver == "" and not integrity:
                        continue
                    packages.append({
                        "name": name,
                        "version": ver,
                        "integrity": integrity,
                        "resolved": resolved,
                        "source": str(mpath),
                        "registry": "npm",
                    })
    # Deduplicate by (name, version, resolved).
    seen = set()
    unique: List[Dict[str, str]] = []
    for p in packages:
        k = (p["name"], p["version"], p["resolved"])
        if k in seen:
            continue
        seen.add(k)
        unique.append(p)
    return {
        "manifests": parsed_files,
        "packages": unique,
        "count": len(unique),
    }


# ─── Python ──────────────────────────────────────────────────────────
def _parse_requirements_txt(path: Path) -> List[Dict[str, str]]:
    pkgs: List[Dict[str, str]] = []
    text = _safe_read_text(path)
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip environment markers, extras.
        line = re.split(r"\s*;", line)[0].strip()
        line = re.sub(r"\[.*?\]", "", line).strip()
        # Pinned (==).
        m = PINNED_REQ_RE.match(line)
        if m:
            pkgs.append({"name": m.group(1).lower(), "version": m.group(2),
                         "pinned": True, "source": str(path), "registry": "pypi"})
            continue
        # Unpinned (>=, ~=, >, etc.) → flag as risky.
        m = UNPINNED_REQ_RE.match(line)
        if m:
            name = re.split(r"\s*(>=|<=|~=|>|<|!=|;|=)", line)[0].strip().lower()
            pkgs.append({"name": name, "version": line[len(name):].strip(),
                         "pinned": False, "source": str(path), "registry": "pypi"})
            continue
        # Bare name (no version) → definitely unpinned.
        m = BARE_NAME_RE.match(line)
        if m:
            pkgs.append({"name": m.group(0).lower(), "version": "",
                         "pinned": False, "source": str(path), "registry": "pypi"})
    return pkgs


def _parse_lockfile_json(path: Path, deps_key: str,
                         default_info_keys: Tuple[str, ...]) -> List[Dict[str, str]]:
    pkgs: List[Dict[str, str]] = []
    data = _safe_read_json(path)
    if not isinstance(data, dict):
        return pkgs
    deps = data.get(deps_key)
    if not isinstance(deps, dict):
        return pkgs
    for name, info in deps.items():
        if isinstance(info, dict):
            ver = info.get("version", "")
            if not ver:
                # Pipfile.lock stores "version" under the info dict.
                ver = info.get("version", "") or ""
            pkgs.append({"name": name.lower(), "version": str(ver),
                         "pinned": True, "source": str(path), "registry": "pypi"})
        elif isinstance(info, str):
            pkgs.append({"name": name.lower(), "version": info,
                         "pinned": True, "source": str(path), "registry": "pypi"})
    return pkgs


def scan_python_packages(root: Path) -> Dict[str, Any]:
    """Parse requirements.txt / Pipfile.lock / poetry.lock / constraints.txt."""
    packages: List[Dict[str, str]] = []
    parsed: List[str] = []
    txt_manifests = _iter_manifests(root, ("requirements.txt", "requirements-dev.txt",
                                           "constraints.txt"))
    for mpath in txt_manifests:
        pkgs = _parse_requirements_txt(mpath)
        if pkgs:
            parsed.append(str(mpath))
            packages.extend(pkgs)

    for mname, key, info_keys in (
        ("Pipfile.lock", None, ("version",)),
    ):
        if mname == "Pipfile.lock":
            manifests = _iter_manifests(root, ("Pipfile.lock",))
            for mpath in manifests:
                data = _safe_read_json(mpath)
                if not isinstance(data, dict):
                    continue
                # Pipfile.lock stores default + develop groups.
                for group in ("default", "develop"):
                    grp = data.get(group) or {}
                    for name, info in grp.items():
                        if isinstance(info, dict):
                            ver = info.get("version", "")
                            pkgs_d = [{"name": name.lower(), "version": str(ver),
                                       "pinned": True, "source": str(mpath),
                                       "registry": "pypi"}]
                            packages.extend(pkgs_d)
                parsed.append(str(mpath))

    manifests = _iter_manifests(root, ("poetry.lock",))
    for mpath in manifests:
        # poetry.lock v1.x: top-level [[package]] sections as a TOML file
        # but newer lockfile (>=2) is also TOML. We do a regex fallback
        # to avoid pulling in a TOML parser dep.
        text = _safe_read_text(mpath)
        # Match: name = "version"
        for m in re.finditer(r'^\s*name\s*=\s*"([^"]+)"\s*$\n'
                             r'\s*version\s*=\s*"([^"]+)"', text, re.MULTILINE):
            packages.append({"name": m.group(1).lower(), "version": m.group(2),
                             "pinned": True, "source": str(mpath), "registry": "pypi"})
        parsed.append(str(mpath))

    # Deduplicate.
    seen = set()
    unique: List[Dict[str, str]] = []
    for p in packages:
        k = (p["name"], p["version"], p["source"])
        if k in seen:
            continue
        seen.add(k)
        unique.append(p)
    return {
        "manifests": parsed,
        "packages": unique,
        "count": len(unique),
    }


# ─── PHP ─────────────────────────────────────────────────────────────
def scan_php_packages(root: Path) -> Dict[str, Any]:
    """Parse composer.lock — extract packages + dev-packages."""
    manifests = _iter_manifests(root, PHP_MANIFESTS)
    packages: List[Dict[str, str]] = []
    parsed: List[str] = []
    for mpath in manifests:
        data = _safe_read_json(mpath)
        if not isinstance(data, dict):
            continue
        parsed.append(str(mpath))
        for group in ("packages", "packages-dev"):
            grp = data.get(group) or []
            if not isinstance(grp, list):
                continue
            for entry in grp:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name") or ""
                ver = entry.get("version") or ""
                packages.append({
                    "name": name,
                    "version": ver,
                    "pinned": True,
                    "source": str(mpath),
                    "registry": "packagist",
                    "dev": group == "packages-dev",
                })
    seen = set()
    unique: List[Dict[str, str]] = []
    for p in packages:
        k = (p["name"], p["version"], p["source"])
        if k in seen:
            continue
        seen.add(k)
        unique.append(p)
    return {
        "manifests": parsed,
        "packages": unique,
        "count": len(unique),
    }


# ─── Typosquatting ───────────────────────────────────────────────────
def check_typosquatting(packages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Compare each package name against the built-in typo list.

    Returns list of matches: {typo, legitimate, version, source}.
    """
    matches: List[Dict[str, Any]] = []
    for pkg in packages:
        name = (pkg.get("name") or "").lower()
        # Strip scoped npm prefix "@scope/" for the lookup.
        bare = name.rsplit("/", 1)[-1] if "/" in name else name
        if bare in TYPOSQUAT_LIST:
            matches.append({
                "typo": name,
                "legitimate": TYPOSQUAT_LIST[bare],
                "version": pkg.get("version"),
                "source": pkg.get("source"),
                "registry": pkg.get("registry"),
            })
        # Edit-distance heuristic: flag any name within edit distance 1 of
        # a high-value target not already in the static list — only for
        # common targets to keep noise low.
        for target in ("requests", "lodash", "openpyxl", "cryptography",
                       "django", "flask", "express", "react", "axios",
                       "moment", "vue", "angular", "pyjwt"):
            if bare == target:
                break
            if abs(len(bare) - len(target)) <= 1 and _edit_distance(bare, target) == 1:
                matches.append({
                    "typo": name,
                    "legitimate": target,
                    "version": pkg.get("version"),
                    "source": pkg.get("source"),
                    "registry": pkg.get("registry"),
                    "heuristic": "edit_distance_1",
                })
                break
    return matches


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (no external dep)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


# ─── Install scripts (npm package.json) ──────────────────────────────
def check_install_scripts(root: Path) -> List[Dict[str, Any]]:
    """Detect preinstall/postinstall/prepare/etc. in package.json files.
    These are the primary vector for npm supply-chain attacks (e.g.
    event-stream, ua-parser-js).
    """
    manifests = _iter_manifests(root, NPM_PKG_JSON)
    findings: List[Dict[str, Any]] = []
    for mpath in manifests:
        data = _safe_read_json(mpath)
        if not isinstance(data, dict):
            continue
        scripts = data.get("scripts") or {}
        if not isinstance(scripts, dict):
            continue
        dangerous = {k: v for k, v in scripts.items() if k in INSTALL_SCRIPT_KEYS}
        if dangerous:
            findings.append({
                "file": str(mpath),
                "package_name": data.get("name", ""),
                "scripts": dangerous,
            })
    return findings


# ─── Known malicious ─────────────────────────────────────────────────
def check_known_malicious(packages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Match package names against the built-in KNOWN_MALICIOUS list."""
    matches: List[Dict[str, Any]] = []
    for pkg in packages:
        name = (pkg.get("name") or "").lower()
        bare = name.rsplit("/", 1)[-1] if "/" in name else name
        if bare in KNOWN_MALICIOUS:
            matches.append({
                "name": pkg.get("name"),
                "version": pkg.get("version"),
                "source": pkg.get("source"),
                "registry": pkg.get("registry"),
                "reason": "known_malicious",
            })
    return matches


# ─── Git deps ────────────────────────────────────────────────────────
def check_git_deps(root: Path) -> List[Dict[str, Any]]:
    """Scan all manifests for git+ / GitHub URL dependencies (mutable refs)."""
    findings: List[Dict[str, Any]] = []
    # We re-scan all manifest types for textual git references.
    manifest_names = NPM_MANIFESTS + NPM_PKG_JSON + PY_MANIFESTS + PHP_MANIFESTS
    for mpath in _iter_manifests(root, manifest_names):
        text = _safe_read_text(mpath)
        if not text:
            continue
        # Per-line scan (works for both JSON and requirements.txt).
        for line_no, line in enumerate(text.splitlines(), 1):
            if GIT_DEP_RE.search(line):
                # Trim the line for display.
                snippet = line.strip()[:200]
                # Heuristic: unpinned git dep (no @commit / no #semver) is worse.
                # Look for a SHA or tag after "@" or "#".
                has_pin = bool(re.search(r"@[0-9a-f]{7,40}|#[\w.^~>=<!-]{3,}|@v?\d+\.\d+",
                                         line))
                findings.append({
                    "file": str(mpath),
                    "line": line_no,
                    "snippet": snippet,
                    "pinned": has_pin,
                })
    return findings


# ─── Main ────────────────────────────────────────────────────────────
def main() -> None:
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "lab": False,
            "error": "LAB guard not satisfied",
            "detail": ("Set LAB=1 in the environment to confirm lab framing. "
                       "Although this module is read-only, the guard keeps the "
                       "cross-sector module family consistent."),
        }, indent=2))
        sys.exit(1)

    root = Path(PROJECT_DIR).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "lab": True,
            "error": "project_dir_not_found",
            "project_dir": str(root),
            "detail": "Pass a valid directory as argv[1] (default: ./source).",
        }, indent=2))
        sys.exit(2)

    # ── Aggregate package lists per ecosystem ──────────────────────
    npm_result = scan_npm_packages(root)
    py_result = scan_python_packages(root)
    php_result = scan_php_packages(root)

    all_packages = (npm_result["packages"] + py_result["packages"]
                    + php_result["packages"])

    # ── Cross-cutting checks ───────────────────────────────────────
    typosquatting_found = check_typosquatting(all_packages)
    install_scripts = check_install_scripts(root)
    malicious_packages = check_known_malicious(all_packages)
    git_deps = check_git_deps(root)

    # ── Total vulnerability tally ──────────────────────────────────
    total_vulnerabilities = (
        len(typosquatting_found)
        + len(install_scripts)
        + len(malicious_packages)
        + sum(1 for g in git_deps if not g.get("pinned"))
    )

    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "lab": True,
        "project_dir": str(root),
        "packages_scanned": len(all_packages),
        "by_ecosystem": {
            "npm": {"count": npm_result["count"],
                    "manifests": npm_result["manifests"]},
            "python": {"count": py_result["count"],
                       "manifests": py_result["manifests"]},
            "php": {"count": php_result["count"],
                    "manifests": php_result["manifests"]},
        },
        "typosquatting_found": typosquatting_found,
        "install_scripts": install_scripts,
        "malicious_packages": malicious_packages,
        "git_deps": git_deps,
        "total_vulnerabilities": total_vulnerabilities,
        # High-level verdicts:
        "findings": {
            "critical_known_malicious": bool(malicious_packages),
            "critical_install_scripts": bool(install_scripts),
            "high_typosquatting": bool(typosquatting_found),
            "medium_unpinned_git_deps": any(not g.get("pinned") for g in git_deps),
            "unpinned_python_reqs": any(
                not p.get("pinned") for p in py_result["packages"]),
        },
        # Sample package list (first 25) for traceability.
        "packages_sample": all_packages[:25],
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
