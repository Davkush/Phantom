#!/usr/bin/env python3
# HARNESS-VALIDATION v4.0.0 — sandbox_runner.py (FUSION)
# 68 profils — tous secteurs + RE + IDS.
from __future__ import annotations
import json, os, shutil, subprocess, sys
from pathlib import Path
from typing import TypedDict

ROOT = Path(__file__).parent.resolve()
TIMEOUT = 290

class ModuleProfile(TypedDict, total=False):
    image: str; caps: list[str]; net: str; tmpfs_exec: bool
    pid: str; mounts: list[tuple[str, str]]; privileged: bool

def _check_timeout_available(): return bool(shutil.which("timeout"))
def check_docker_daemon():
    try:
        p = subprocess.run(["docker","info","--format","{{.ServerVersion}}"],capture_output=True,timeout=5)
        return p.returncode == 0
    except: return False

PROFILES = {
  "php_uaf": {
    "image": "harness/php-asan:7.4",
    "net": "none",
    "tmpfs_exec": True
  },
  "php_chain": {
    "image": "harness/php-chain:latest",
    "net": "none",
    "tmpfs_exec": True
  },
  "c_heap": {
    "image": "harness/glibc-2.31:latest",
    "caps": [
      "SYS_PTRACE"
    ],
    "net": "none"
  },
  "gdb_extract": {
    "image": "harness/gdb:latest",
    "caps": [
      "SYS_PTRACE"
    ],
    "net": "none",
    "pid": "host"
  },
  "esxi_evasion": {
    "image": "harness/busybox:latest",
    "net": "none",
    "tmpfs_exec": True
  },
  "preauth": {
    "image": "harness/net-tools:latest",
    "net": "host"
  },
  "docker_escape": {
    "image": "docker:cli",
    "net": "none",
    "mounts": [
      [
        "/var/run/docker.sock",
        "/var/run/docker.sock"
      ]
    ],
    "privileged": True
  },
  "waf_bypass": {
    "image": "harness/net-h2:latest",
    "net": "host"
  },
  "fuzzer_send": {
    "image": "harness/net-tools:latest",
    "net": "host"
  },
  "afl_fuzz": {
    "image": "harness/aflpp:latest",
    "net": "none",
    "tmpfs_exec": True
  },
  "static_analysis": {
    "image": "harness/sast:latest",
    "net": "none"
  },
  "llm_exploit": {
    "image": "harness/llm-sandbox:latest",
    "net": "host",
    "tmpfs_exec": True
  },
  "osint_leak": {
    "image": "harness/net-tools:latest",
    "net": "host"
  },
  "post_exploit_enum": {
    "image": "harness/gdb:latest",
    "caps": [
      "SYS_PTRACE"
    ],
    "net": "none",
    "pid": "host"
  },
  "persistence": {
    "image": "harness/net-tools:latest",
    "net": "host",
    "tmpfs_exec": True
  },
  "ids_test": {
    "image": "harness/glibc-2.31:latest",
    "caps": [
      "NET_RAW"
    ],
    "net": "host",
    "tmpfs_exec": True
  },
  "binary_re": {
    "image": "harness/glibc-2.31:latest",
    "net": "none"
  },
  "firmware_re": {
    "image": "harness/glibc-2.31:latest",
    "net": "none"
  },
  "strings_secrets": {
    "image": "harness/glibc-2.31:latest",
    "net": "none"
  },
  "protocol_re": {
    "image": "harness/glibc-2.31:latest",
    "net": "none"
  },
  "malware_sandbox": {
    "image": "harness/llm-sandbox:latest",
    "net": "none",
    "tmpfs_exec": True
  },
  "smart_contract_re": {
    "image": "harness/crypto-protocols:latest",
    "net": "none"
  },
  "modbus_probe": {
    "image": "harness/ot-protocols:latest",
    "net": "host"
  },
  "dnp3_probe": {
    "image": "harness/ot-protocols:latest",
    "net": "host"
  },
  "s7comm_probe": {
    "image": "harness/ot-protocols:latest",
    "net": "host"
  },
  "opcua_probe": {
    "image": "harness/ot-protocols:latest",
    "net": "host"
  },
  "iec104_probe": {
    "image": "harness/ot-protocols:latest",
    "net": "host"
  },
  "bacnet_probe": {
    "image": "harness/ot-protocols:latest",
    "caps": [
      "NET_RAW"
    ],
    "net": "host"
  },
  "ethernetip_probe": {
    "image": "harness/ot-protocols:latest",
    "net": "host"
  },
  "mqtt_probe": {
    "image": "harness/ot-protocols:latest",
    "net": "host"
  },
  "profinet_probe": {
    "image": "harness/ot-protocols:latest",
    "caps": [
      "NET_RAW"
    ],
    "net": "host"
  },
  "swift_probe": {
    "image": "harness/banking-protocols:latest",
    "net": "host"
  },
  "iso8583_probe": {
    "image": "harness/banking-protocols:latest",
    "net": "host"
  },
  "core_banking_probe": {
    "image": "harness/banking-protocols:latest",
    "net": "host"
  },
  "open_banking_probe": {
    "image": "harness/banking-protocols:latest",
    "net": "host"
  },
  "psd2_probe": {
    "image": "harness/banking-protocols:latest",
    "net": "host"
  },
  "ebics_probe": {
    "image": "harness/banking-protocols:latest",
    "net": "host"
  },
  "sftp_probe": {
    "image": "harness/banking-protocols:latest",
    "net": "host"
  },
  "as2_probe": {
    "image": "harness/banking-protocols:latest",
    "net": "host"
  },
  "ftps_probe": {
    "image": "harness/banking-protocols:latest",
    "net": "host"
  },
  "jwt_oauth_probe": {
    "image": "harness/banking-protocols:latest",
    "net": "host"
  },
  "eth_rpc_probe": {
    "image": "harness/crypto-protocols:latest",
    "net": "host"
  },
  "wallet_extract": {
    "image": "harness/crypto-protocols:latest",
    "net": "none",
    "tmpfs_exec": True
  },
  "dicom_probe": {
    "image": "harness/health-protocols:latest",
    "net": "host"
  },
  "hl7_probe": {
    "image": "harness/health-protocols:latest",
    "net": "host"
  },
  "fhir_probe": {
    "image": "harness/health-protocols:latest",
    "net": "host"
  },
  "med_device_probe": {
    "image": "harness/health-protocols:latest",
    "net": "host"
  },
  "ieee11073_probe": {
    "image": "harness/health-protocols:latest",
    "net": "host"
  },
  "poct1_probe": {
    "image": "harness/health-protocols:latest",
    "net": "host"
  },
  "mqtt_health_probe": {
    "image": "harness/health-protocols:latest",
    "net": "host"
  },
  "iec61850_probe": {
    "image": "harness/energy-protocols:latest",
    "net": "host"
  },
  "iec62351_probe": {
    "image": "harness/energy-protocols:latest",
    "net": "host"
  },
  "dnp3_sav5_probe": {
    "image": "harness/energy-protocols:latest",
    "net": "host"
  },
  "iccp_probe": {
    "image": "harness/energy-protocols:latest",
    "net": "host"
  },
  "dlms_probe": {
    "image": "harness/energy-protocols:latest",
    "net": "host"
  },
  "synchrophasor_probe": {
    "image": "harness/energy-protocols:latest",
    "net": "host"
  },
  "ss7_probe": {
    "image": "harness/telecom-probe:latest",
    "caps": [
      "NET_RAW"
    ],
    "net": "host"
  },
  "sip_probe": {
    "image": "harness/telecom-probe:latest",
    "caps": [
      "NET_RAW"
    ],
    "net": "host"
  },
  "websocket_probe": {
    "image": "harness/telecom-probe:latest",
    "net": "host"
  },
  "netconf_probe": {
    "image": "harness/telecom-probe:latest",
    "net": "host"
  },
  "restconf_probe": {
    "image": "harness/telecom-probe:latest",
    "net": "host"
  },
  "grpc_probe": {
    "image": "harness/telecom-probe:latest",
    "net": "host"
  },
  "gprs_probe": {
    "image": "harness/telecom-probe:latest",
    "net": "host"
  },
  "http2_probe": {
    "image": "harness/telecom-probe:latest",
    "net": "host"
  },
  "http3_probe": {
    "image": "harness/telecom-probe:latest",
    "net": "host"
  },
  "snmp_probe": {
    "image": "harness/telecom-probe:latest",
    "caps": [
      "NET_RAW"
    ],
    "net": "host"
  }
}

def build_docker_args(module, p):
    args = []
    if _check_timeout_available(): args += ["timeout", str(TIMEOUT)]
    args += ["docker","run","--rm","-i",
             "--network",p["net"],
             "--read-only",
             "--cap-drop","ALL",
             "--memory","512m",
             "--cpus","1.0",
             "--pids-limit","128",              # v4.1: anti fork-bomb
             "--ulimit","nofile=1024:1024",     # v4.1: limite FD
             "--security-opt","no-new-privileges"]  # v4.1: anti privesc
    t = "rw,nosuid,size=512m"
    if not p.get("tmpfs_exec",False): t += ",noexec"
    args += ["--tmpfs", f"/tmp:{t}"]
    for c in p.get("caps",[]): args += ["--cap-add", c]
    if p.get("pid")=="host": args += ["--pid","host"]
    for h,c in p.get("mounts",[]): args += ["-v",f"{h}:{c}"]
    if p.get("privileged"): args += ["--privileged"]
    args += ["-v",f"{ROOT}:/harness:ro","-w","/harness",p["image"]]
    return args

def run_sandboxed(module, cmd):
    p = PROFILES.get(module)
    if not p: return {"error":f"no profile for {module}","available":list(PROFILES.keys())}
    if not check_docker_daemon(): return {"error":"docker_daemon_not_running"}
    args = build_docker_args(module, p) + cmd
    try:
        proc = subprocess.run(args, capture_output=True, timeout=TIMEOUT+10)
        return {"exit_code":proc.returncode,"stdout":proc.stdout.decode(errors="replace")[:65536],"stderr":proc.stderr.decode(errors="replace")[:2000]}
    except subprocess.TimeoutExpired: return {"error":"timeout","exit_code":-1}
    except FileNotFoundError: return {"error":"docker_not_installed"}
    except Exception as e: return {"error":type(e).__name__}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"profiles":list(PROFILES.keys()),"total_profiles":len(PROFILES)},indent=2))
        sys.exit(0)
    print(json.dumps(run_sandboxed(sys.argv[1], sys.argv[2:]), indent=2))
