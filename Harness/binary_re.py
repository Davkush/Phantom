#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — reverse engineering module : binary static analysis.
# Secteur : cross-sector (defensive RE tool — analyze LOCAL binaries).
#
# Defensive purpose:
#   This module performs static reverse engineering of binaries located on the
#   operator's OWN systems (firmware binaries, system daemons, executables
#   recovered during incident response, or vendor binaries the operator has
#   purchased and deployed). It is NOT a network attack tool — no remote
#   target is contacted. All inputs are LOCAL files passed as CLI args.
#
#   - v3.1 : function-list extraction via Ghidra headless analyzer
#   - v3.1 : fallback chain : Ghidra → objdump -t → nm → strings(1)
#   - v3.1 : imports via readelf -d (DT_NEEDED) + objdump -T
#   - v3.1 : architecture detection via readelf -h / file(1)
#   - v3.1 : vulnerability pattern detection (strcpy, sprintf, system,
#            execve, gets, scanf %s, hardcoded addresses, small buffers)
#   - v3.1 : decompiled snippets via Ghidra headless PseudoCodePython export
#            (limited to top-N functions to keep JSON bounded)
#   - v3.1 : SEED reproducibility (function ordering, sample sizes),
#            LAB=1 guard, strict local-file-only invariant
#
# Cadre légal : Art. 323-1 Code pénal (accès frauduleux), Art. 331-1 (vol).
#   L'analyse de binaires présents sur ses propres systèmes ou de firmwares
#   de matériel que l'on a acheté et déployé est légitime (défense, audit).
#   Aucune exfiltration, aucune sortie réseau.
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "binary_re"
TIMEOUT_S = 120                    # per-tool cap (Ghidra can be slow)
MAX_FUNCTIONS = 500                # cap function list to bound JSON
MAX_DECOMPILED = 20                # cap decompiled snippets (top-N)
MAX_STRINGS_LEN = 4096             # cap per-string snippet

# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))

# Deterministic sampling helper (no secrets — just reproducible ordering)
def _seeded_take(items: list, n: int) -> list:
    """Deterministic sampling of n items from a list using SEED.
    Sorts by (len descending, hash) for reproducibility."""
    if len(items) <= n:
        return list(items)
    keyed = sorted(
        enumerate(items),
        key=lambda iv: (-(len(str(iv[1]))), (iv[0] * SEED) % 1000003, iv[0]),
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
            "sector": os.environ.get("SECTOR", "it"),
            "safe_mode": "full",
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
                "Defensive reverse engineering of LOCAL binaries on operator-owned "
                "systems. No network egress. Lab isolation required."
            ),
        }))
        sys.exit(2)


def _check_safe_mode() -> str:
    sm = os.environ.get("SAFE_MODE", "").lower().strip()
    if sm in ("read_only", "full"):
        return sm
    return _sector_safe_mode()


# ─── Tool availability ───────────────────────────────────────────────────────
def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _find_ghidra() -> Optional[str]:
    """Locate Ghidra analyzeHeadless binary.
    Checks GHIDRA_HOME env, common install paths, then PATH."""
    # 1. Env override
    ghidra_home = os.environ.get("GHIDRA_HOME", "").strip()
    if ghidra_home:
        cand = Path(ghidra_home) / "support" / "analyzeHeadless"
        if cand.exists():
            return str(cand)
        cand2 = Path(ghidra_home) / "support" / "analyzeHeadless.bat"
        if cand2.exists():
            return str(cand2)
    # 2. Common install locations
    for base in ("/opt/ghidra", "/usr/local/ghidra", "/usr/share/ghidra",
                 "/Applications/ghidra"):
        for sub in ("support/analyzeHeadless",):
            cand = Path(base) / sub
            if cand.exists():
                return str(cand)
    # 3. PATH
    p = _which("analyzeHeadless")
    return p


# ─── Architecture detection ──────────────────────────────────────────────────
def detect_arch(binary: Path) -> dict:
    """Detect architecture via readelf -h (preferred), file(1) fallback."""
    info = {"arch": "unknown", "bits": 0, "endian": "unknown",
            "machine": "unknown", "elf": False, "tool": "none"}
    # readelf -h
    if _which("readelf"):
        try:
            proc = subprocess.run(
                ["readelf", "-h", str(binary)],
                capture_output=True, text=True, timeout=15)
            if proc.returncode == 0:
                info["tool"] = "readelf"
                info["elf"] = True
                out = proc.stdout
                # Class field: "ELF32" or "ELF64" — extract bits directly (32 or 64)
                m = re.search(r"Class:\s+ELF(\d+)", out)
                if m:
                    info["bits"] = int(m.group(1))   # 32 or 64 (NOT *32)
                # Data field: "2's complement, little endian" or "... big endian"
                m = re.search(r"Data:.*?(little|big)\s+endian", out, re.I)
                if m:
                    info["endian"] = m.group(1).lower()
                m = re.search(r"Machine:\s+(.+)", out)
                if m:
                    info["machine"] = m.group(1).strip()
                    # Normalize arch
                    mt = info["machine"].lower()
                    if "x86-64" in mt or "x86_64" in mt:
                        info["arch"] = "x86_64"
                    elif "intel 80386" in mt or "i386" in mt:
                        info["arch"] = "x86"
                    elif "aarch64" in mt:
                        info["arch"] = "arm64"
                    elif "arm" in mt:
                        info["arch"] = "arm"
                    elif "mips" in mt:
                        info["arch"] = "mips"
                    elif "powerpc" in mt or "ppc" in mt:
                        info["arch"] = "ppc"
                    elif "risc-v" in mt:
                        info["arch"] = "riscv"
                    else:
                        info["arch"] = info["machine"].split()[0].lower()
                return info
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    # file(1) fallback
    if _which("file"):
        try:
            proc = subprocess.run(
                ["file", "-b", str(binary)],
                capture_output=True, text=True, timeout=10)
            out = proc.stdout.lower()
            info["tool"] = "file"
            info["elf"] = "elf" in out
            if "x86-64" in out or "x86_64" in out:
                info["arch"] = "x86_64"; info["bits"] = 64
            elif "intel 80386" in out or ", x86" in out:
                info["arch"] = "x86"; info["bits"] = 32
            elif "aarch64" in out or "arm-64" in out:
                info["arch"] = "arm64"; info["bits"] = 64
            elif "arm" in out:
                info["arch"] = "arm"; info["bits"] = 32
            elif "mips" in out:
                info["arch"] = "mips"
            elif "powerpc" in out or "ppc" in out:
                info["arch"] = "ppc"
            if "lsb" in out:
                info["endian"] = "little"
            elif "msb" in out:
                info["endian"] = "big"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    return info


# ─── Function list extraction ────────────────────────────────────────────────
def extract_functions_objdump(binary: Path) -> list:
    """Extract function symbols via objdump -t (symbol table)."""
    if not _which("objdump"):
        return []
    try:
        proc = subprocess.run(
            ["objdump", "-t", str(binary)],
            capture_output=True, text=True, timeout=TIMEOUT_S)
        funcs = []
        for line in proc.stdout.splitlines():
            # Format: 0000000000001040 g     F .text    0000000000000015 main
            m = re.match(
                r"^([0-9a-f]+)\s+(\S+)\s+F\s+\S+\s+([0-9a-f]+)\s+(.+)$", line)
            if m:
                addr, scope, size_hex, name = m.groups()
                try:
                    size = int(size_hex, 16)
                except ValueError:
                    size = 0
                funcs.append({
                    "name": name.strip(),
                    "addr": "0x" + addr,
                    "size": size,
                    "scope": scope,
                })
        # Dedupe by (name, addr), cap, deterministic order
        seen = set()
        out = []
        for f in funcs:
            k = (f["name"], f["addr"])
            if k in seen:
                continue
            seen.add(k)
            out.append(f)
            if len(out) >= MAX_FUNCTIONS:
                break
        return out
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def extract_functions_nm(binary: Path) -> list:
    """Extract function symbols via nm (fallback when objdump absent)."""
    if not _which("nm"):
        return []
    try:
        proc = subprocess.run(
            ["nm", "-n", str(binary)],
            capture_output=True, text=True, timeout=TIMEOUT_S)
        funcs = []
        for line in proc.stdout.splitlines():
            m = re.match(r"^([0-9a-f]+)\s+([TtWw])\s+(.+)$", line)
            if m:
                addr, sym, name = m.groups()
                funcs.append({
                    "name": name.strip(),
                    "addr": "0x" + addr,
                    "size": 0,
                    "scope": sym.upper(),
                })
                if len(funcs) >= MAX_FUNCTIONS:
                    break
        return funcs
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def extract_functions_ghidra(binary: Path, ghidra: str) -> tuple:
    """Run Ghidra headless analyzer to extract functions list.
    Returns (functions_list, decompiled_snippets, error_or_None)."""
    funcs: list = []
    snippets: list = []
    # Create a temp project dir + post-script
    with tempfile.TemporaryDirectory(prefix="ghidra_re_") as proj_dir:
        proj_dir_p = Path(proj_dir)
        # Ghidra postScript : dump function list + decompiled top-N
        script_path = proj_dir_p / "DumpFuncs.py"
        funcs_json = proj_dir_p / "funcs.json"
        decomp_json = proj_dir_p / "decomp.json"
        # Ghidra Jython post-script (limited to Python 2 syntax via Jython)
        script_path.write_text(
            "# Ghidra headless post-script — dumps functions + decompiled top-N\n"
            "# @category Harness\n"
            "from ghidra.app.decompiler import DecompInterface\n"
            "from ghidra.util.task import ConsoleTaskMonitor\n"
            "import json\n"
            "fm = currentProgram.getFunctionManager()\n"
            "funcs = []\n"
            "for f in fm.getFunctions(True):\n"
            "    funcs.append({'name': f.getName(), 'addr': str(f.getEntryPoint()),\n"
            "                  'size': f.getBody().getNumAddresses()})\n"
            "with open('%s', 'w') as fh:\n"
            "    json.dump(funcs, fh)\n" % str(funcs_json).replace("\\", "/") +
            "# Decompile top-N by size\n"
            "decomp = []\n"
            "try:\n"
            "    di = DecompInterface()\n"
            "    di.openProgram(currentProgram)\n"
            "    mon = ConsoleTaskMonitor()\n"
            "    sorted_f = sorted(funcs, key=lambda x: x.get('size', 0), reverse=True)\n"
            "    for fmeta in sorted_f[:%d]:\n"
            "        fn = fm.getFunctionAt(toAddr(fmeta['addr']))\n"
            "        if fn is None:\n"
            "            continue\n"
            "        res = di.decompileFunction(fn, 60, mon)\n"
            "        if res and res.getDecompiledFunction():\n"
            "            code = res.getDecompiledFunction().getC()\n"
            "            decomp.append({'name': fmeta['name'],\n"
            "                           'code': code[:4096]})\n"
            "    with open('%s', 'w') as fh:\n"
            "        json.dump(decomp, fh)\n" % (MAX_DECOMPILED, str(decomp_json).replace("\\", "/")) +
            "except Exception as e:\n"
            "    pass\n"
        )
        cmd = [
            ghidra, str(proj_dir_p), "harness_proj",
            "-import", str(binary),
            "-postScript", str(script_path),
            "-scriptPath", str(proj_dir_p),
            "-deleteProject",
            "-noanalysis",  # we WANT analysis — remove this if it skips
        ]
        # Actually we want analysis enabled — Ghidra auto-analyzes by default
        cmd = [c for c in cmd if c != "-noanalysis"]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=TIMEOUT_S + 60)
            if funcs_json.exists():
                try:
                    funcs = json.loads(funcs_json.read_text())
                except (json.JSONDecodeError, OSError):
                    funcs = []
            if decomp_json.exists():
                try:
                    snippets = json.loads(decomp_json.read_text())
                except (json.JSONDecodeError, OSError):
                    snippets = []
        except subprocess.TimeoutExpired:
            return ([], [], "ghidra_timeout")
        except (FileNotFoundError, OSError) as e:
            return ([], [], "ghidra_exec_error: %s" % type(e).__name__)
    return (funcs[:MAX_FUNCTIONS], snippets[:MAX_DECOMPILED], None)


# ─── Imports extraction ──────────────────────────────────────────────────────
def extract_imports(binary: Path) -> list:
    """Extract imported shared libs (DT_NEEDED) + imported symbols."""
    imports: list = []
    if _which("readelf"):
        try:
            proc = subprocess.run(
                ["readelf", "-d", str(binary)],
                capture_output=True, text=True, timeout=15)
            for line in proc.stdout.splitlines():
                m = re.search(r"NEEDED\s+Shared library:\s+\[(.+?)\]", line)
                if m:
                    imports.append({"type": "lib", "name": m.group(1)})
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    if _which("objdump"):
        try:
            proc = subprocess.run(
                ["objdump", "-T", str(binary)],
                capture_output=True, text=True, timeout=15)
            # objdump -T format variants:
            #   "0000...  DF *UND*  0000...  (GLIBC_2.3)  __ctype_toupper_loc"
            #   "0000...  DF *UND*  0000...  Base        cap_to_text"
            #   "0000...  DF *UND*  0000...              printf"
            # Robust parse: split on whitespace, last token = name,
            # 2nd token = symbol type (D=global, F=function, O=object).
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue
                # parts[0] = addr, parts[1] = sym_type (e.g. "DF"/"DO"/"IF"/"wF")
                # parts[2] = section, parts[3] = size_hex
                # parts[4..-1] = version (in parens or bare) + name
                sym_type = parts[1]
                if "F" not in sym_type and "O" not in sym_type:
                    continue
                # The name is always the LAST token. Intermediate tokens
                # between size and name may be a bare version like "Base".
                name = parts[-1]
                # Strip version suffix like "@GLIBC_2.2.5" or "@@GLIBC_2.2.5"
                name = re.sub(r"@@?[A-Za-z0-9_.]+$", "", name)
                if not name or name in ("Base", "*UND*"):
                    continue
                imports.append({
                    "type": "func" if "F" in sym_type else "obj",
                    "name": name,
                    "section": parts[2],
                })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    # Cap imports to bound JSON
    return _seeded_take(imports, 200)


# ─── Vulnerability pattern detection ─────────────────────────────────────────
DANGEROUS_FUNCS = {
    "strcpy":   "stack buffer overflow — no bounds",
    "strcat":   "stack buffer overflow — no bounds",
    "gets":     "classic buffer overflow — unbounded read",
    "sprintf":  "buffer overflow — no bounds",
    "vsprintf": "buffer overflow — no bounds",
    "scanf":    "potential overflow if %s without width",
    "sscanf":   "potential overflow if %s without width",
    "system":   "command injection if arg tainted",
    "popen":    "command injection if arg tainted",
    "execve":   "exec with tainted args",
    "execvp":   "exec with tainted args",
    "execl":    "exec with tainted args",
    "execlp":   "exec with tainted args",
    "wordexp":  "shell expansion — command injection",
    "atoi":     "no overflow detection — use strtol",
    "atol":     "no overflow detection — use strtol",
    "memcpy":   "potential overflow if len tainted",
    "memmove":  "potential overflow if len tainted",
    "alloca":   "stack exhaustion if len tainted",
    "tmpnam":   "race / predictable name — use mkstemp",
    "mktemp":   "race / predictable name — use mkstemp",
    "rand":     "weak PRNG — use getrandom/arc4random",
    "crypt":    "weak hashing — use bcrypt/argon2",
    "chdir":    "TOCTOU / path traversal if tainted",
    "open":     "TOCTOU / symlink if tainted",
}

HARDCODED_ADDR_RE = re.compile(r"\b0x[0-9a-f]{8,16}\b")
SMALL_BUFFER_RE = re.compile(
    r"\b(?:char|u?int8_t|BYTE)\s+\w+\s*\[\s*(\d+)\s*\]"
)


def find_vulns(binary: Path, funcs: list, imports: list,
               snippets: list) -> list:
    """Find vulnerability patterns from imports + decompiled snippets."""
    vulns: list = []
    # 1. Dangerous imports
    imp_names = {i.get("name", "") for i in imports if i.get("type") == "func"}
    for imp_name in imp_names:
        # Strip PLT/@plt / version suffixes
        bare = re.sub(r"[@.].*$", "", imp_name)
        if bare in DANGEROUS_FUNCS:
            vulns.append({
                "type": "dangerous_import",
                "func": bare,
                "risk": DANGEROUS_FUNCS[bare],
                "severity": "high" if bare in ("strcpy", "gets", "system",
                                               "sprintf", "execve")
                            else "medium",
                "location": "import table",
            })
    # 2. Pattern-match in decompiled snippets
    for snip in snippets:
        code = snip.get("code", "")
        name = snip.get("name", "?")
        for df, risk in DANGEROUS_FUNCS.items():
            for m in re.finditer(r"\b" + re.escape(df) + r"\s*\(", code):
                vulns.append({
                    "type": "dangerous_call",
                    "func": df,
                    "risk": risk,
                    "severity": "high" if df in ("strcpy", "gets", "system",
                                                 "sprintf", "execve")
                                else "medium",
                    "location": "function:%s" % name,
                    "offset": m.start(),
                })
        # Small buffers in source-style decompiled code
        for m in SMALL_BUFFER_RE.finditer(code):
            sz = int(m.group(1))
            if 1 <= sz <= 64:
                vulns.append({
                    "type": "small_buffer",
                    "size": sz,
                    "risk": "small fixed buffer — verify no overflow",
                    "severity": "medium",
                    "location": "function:%s" % name,
                })
        # Hardcoded addresses (could be ROP gadgets / shellcode refs)
        for m in HARDCODED_ADDR_RE.finditer(code):
            addr = m.group(0)
            if addr.lower() in ("0x00000000", "0xffffffffffffffff",
                                "0xffffffff"):
                continue
            vulns.append({
                "type": "hardcoded_address",
                "addr": addr,
                "risk": "hardcoded pointer — possible ROP/shellcode ref",
                "severity": "low",
                "location": "function:%s" % name,
            })
    # Cap vulns to bound JSON
    return _seeded_take(vulns, 200)


# ─── Strings extraction (lightweight — for analysis_type=strings) ────────────
def extract_strings(binary: Path, n: int = 200) -> list:
    """Use strings(1) for printable strings (cap to n)."""
    if not _which("strings"):
        # Fallback: naive regex on raw bytes
        try:
            data = binary.read_bytes()
            return [s.decode("ascii", errors="ignore")
                    for s in re.findall(rb"[\x20-\x7e]{6,}", data)][:n]
        except OSError:
            return []
    try:
        proc = subprocess.run(
            ["strings", "-n", "6", str(binary)],
            capture_output=True, text=True, timeout=TIMEOUT_S)
        lines = proc.stdout.splitlines()
        return _seeded_take(lines, n)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    if len(sys.argv) < 2:
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "missing_binary_path",
            "usage": "binary_re.py <binary_path> [analysis_type]",
            "analysis_types": ["decompile", "functions", "strings", "vulns"],
        }))
        sys.exit(2)

    binary_path = Path(sys.argv[1]).resolve()
    analysis_type = sys.argv[2] if len(sys.argv) > 2 else "functions"

    if analysis_type not in ("decompile", "functions", "strings", "vulns"):
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "invalid_analysis_type",
            "given": analysis_type,
            "valid": ["decompile", "functions", "strings", "vulns"],
        }))
        sys.exit(2)

    if not binary_path.exists() or not binary_path.is_file():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "binary_not_found",
            "path": str(binary_path),
        }))
        sys.exit(2)

    # Defensive invariant : LOCAL file only — no network operations performed
    # anywhere in this module. SEED preserved for reproducibility.

    # 1. Tool availability — refuse to run if no RE tools installed
    ghidra = _find_ghidra()
    has_objdump = bool(_which("objdump"))
    has_readelf = bool(_which("readelf"))
    has_nm = bool(_which("nm"))
    has_strings = bool(_which("strings"))
    has_file = bool(_which("file"))

    if not (ghidra or has_objdump or has_readelf or has_nm or has_file):
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "tools_not_installed",
            "hint": "Install Ghidra or binutils (objdump, readelf, nm, strings)",
            "lab": os.environ.get("LAB", "?"),
            "seed": SEED,
        }))
        sys.exit(3)

    # 2. Architecture
    arch_info = detect_arch(binary_path)

    # 3. Imports (always — cheap)
    imports = extract_imports(binary_path)

    # 4. Functions + decompiled (per analysis_type)
    functions: list = []
    decompiled_snippets: list = []
    tool_used = "none"
    ghidra_error: Optional[str] = None

    if analysis_type in ("decompile", "functions", "vulns"):
        if ghidra and analysis_type == "decompile":
            functions, decompiled_snippets, ghidra_error = \
                extract_functions_ghidra(binary_path, ghidra)
            tool_used = "ghidra"
        if not functions and has_objdump:
            functions = extract_functions_objdump(binary_path)
            tool_used = tool_used if tool_used != "none" else "objdump"
        if not functions and has_nm:
            functions = extract_functions_nm(binary_path)
            tool_used = tool_used if tool_used != "none" else "nm"

    # 5. Strings (only if requested — strings.py is the dedicated tool)
    strings_list: list = []
    if analysis_type == "strings":
        strings_list = extract_strings(binary_path, n=300)

    # 6. Vulnerability patterns
    vulns_found: list = []
    if analysis_type == "vulns":
        # Need functions + snippets to scan code patterns
        if not functions and has_objdump:
            functions = extract_functions_objdump(binary_path)
        if not functions and has_nm:
            functions = extract_functions_nm(binary_path)
        # Try a lightweight Ghidra decompile if available (for code patterns)
        if ghidra and not decompiled_snippets:
            _, decompiled_snippets, ghidra_error = \
                extract_functions_ghidra(binary_path, ghidra)
        vulns_found = find_vulns(binary_path, functions, imports,
                                  decompiled_snippets)

    # 7. JSON report
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "binary": str(binary_path),
        "analysis_type": analysis_type,
        "arch": arch_info,
        "tool_used": tool_used,
        "ghidra_available": ghidra is not None,
        "binutils_available": {
            "objdump": has_objdump, "readelf": has_readelf,
            "nm": has_nm, "strings": has_strings, "file": has_file,
        },
        "functions": functions,
        "functions_count": len(functions),
        "imports": imports,
        "imports_count": len(imports),
        "vulns_found": vulns_found,
        "vulns_count": len(vulns_found),
        "decompiled_snippets": decompiled_snippets,
        "decompiled_count": len(decompiled_snippets),
        "strings_sample": strings_list,
        "strings_count": len(strings_list),
        "seed": SEED,
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "read_only": True,    # no modifications to binary
        "no_network_egress": True,
        "ghidra_error": ghidra_error,
        "legal_note": (
            "Defensive RE : analyse statique de binaires LOCAUX (systèmes "
            "opérateur, firmwares achetés). Aucune sortie réseau. "
            "Art. 323-1 Code pénal (accès frauduleux) — usage lab isolé."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
