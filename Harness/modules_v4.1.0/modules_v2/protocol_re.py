#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — reverse engineering module : protocol RE from PCAP.
# Secteur : cross-sector (defensive RE tool — analyze LOCAL PCAP captures).
#
# Defensive purpose:
#   This module analyzes PCAP captures of network traffic that the operator
#   has collected from their OWN systems (e.g. via tcpdump on a router they
#   own, or from a sensor deployed on their network). It infers the protocol
#   structure (binary/text/hybrid), identifies message fields, extracts
#   opcodes, and produces fuzzer seed candidates. All analysis is on the LOCAL
#   PCAP file — no live capture, no network egress.
#
#   - v3.1 : tshark-based packet decoding (preferred if installed)
#   - v3.1 : scapy fallback for parsing (if tshark absent)
#   - v3.1 : raw PCAP parser fallback (libpcap format, no deps)
#   - v3.1 : protocol type inference (binary / text / hybrid)
#   - v3.1 : field-boundary detection (length-prefix, magic-byte, delimiter)
#   - v3.1 : opcode extraction (first N bytes of request payloads, by cluster)
#   - v3.1 : command/response pattern matching (req+resp size deltas)
#   - v3.1 : fuzzer seed candidates (typed fields with observed value ranges)
#   - v3.1 : SEED reproducibility (packet sampling order),
#            LAB=1 guard, strict local-file-only invariant
#
# Cadre légal : Art. 323-1 Code pénal (accès frauduleux).
#   L'analyse de captures PCAP de son propre réseau est légitime (défense,
#   audit, IR). Aucune exfiltration, aucune capture live.
import collections
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Optional

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "protocol_re"
TIMEOUT_S = 60                     # tshark can be slow on big PCAPs
MAX_PACKETS_ANALYZE = 5000         # cap to bound scan time
MAX_OPCODES = 50                   # cap opcodes in JSON
MAX_FIELDS = 50                    # cap fields in JSON
MAX_FUZZER_SEEDS = 50              # cap fuzzer seeds in JSON

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
                "Defensive protocol RE on LOCAL PCAP captures (operator-owned "
                "network). No live capture, no network egress. Lab isolation."
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


# ─── Packet structure ────────────────────────────────────────────────────────
# A "flow" = (src_ip, src_port, dst_ip, dst_port, transport_proto)
# A "message" = payload bytes (application layer) of one packet in a flow.

def parse_pcap_tshark(pcap: Path, bpf_filter: Optional[str]) -> list:
    """Parse PCAP via tshark. Returns list of flow dicts.
    Each flow: {flow_key, packets: [{ts, dir, payload_hex, payload_len, ip_proto}]}"""
    tshark = _which("tshark")
    if not tshark:
        return []
    fields = [
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "tcp.srcport",
        "-e", "ip.dst", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "ip.proto",
        "-e", "tcp.payload", "-e", "udp.payload",
        "-e", "data.data",
    ]
    cmd = ["tshark", "-r", str(pcap), "-Y", "ip"] + fields
    if bpf_filter:
        cmd = ["tshark", "-r", str(pcap), "-Y", bpf_filter] + fields
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=TIMEOUT_S)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []
    flows: dict = {}
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 11:
            continue
        ts = parts[0]
        src_ip = parts[1]
        src_tcp = parts[2] or parts[5]  # tcp.srcport or udp.srcport
        dst_ip = parts[3]
        dst_tcp = parts[4] or parts[6]
        ip_proto = parts[7]
        tcp_payload = parts[8]
        udp_payload = parts[9]
        data_payload = parts[10]
        payload_hex = tcp_payload or udp_payload or data_payload or ""
        if not payload_hex:
            continue
        if not src_ip or not dst_ip or not src_tcp or not dst_tcp:
            continue
        # Normalize flow key (sort endpoints so bidirectional flows merge)
        end_a = (src_ip, src_tcp)
        end_b = (dst_ip, dst_tcp)
        if end_a <= end_b:
            flow_key = "%s:%s-%s:%s-%s" % (src_ip, src_tcp, dst_ip, dst_tcp,
                                            ip_proto)
            direction = "a_to_b"
        else:
            flow_key = "%s:%s-%s:%s-%s" % (dst_ip, dst_tcp, src_ip, src_tcp,
                                            ip_proto)
            direction = "b_to_a"
        try:
            ts_f = float(ts)
        except ValueError:
            ts_f = 0.0
        payload = bytes.fromhex(payload_hex.replace(":", ""))
        flows.setdefault(flow_key, []).append({
            "ts": ts_f,
            "dir": direction,
            "payload_len": len(payload),
            "payload": payload,
        })
    # Cap flows + packets per flow
    return [{"flow_key": fk, "packets": pkts[:MAX_PACKETS_ANALYZE]}
            for fk, pkts in
            _seeded_take(list(flows.items()), 100)]


def parse_pcap_scapy(pcap: Path) -> list:
    """Parse PCAP via scapy (fallback)."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, Raw  # type: ignore
    except ImportError:
        return []
    try:
        pkts = rdpcap(str(pcap))
    except Exception:  # noqa: BLE001
        return []
    flows: dict = {}
    count = 0
    for p in pkts:
        if count >= MAX_PACKETS_ANALYZE:
            break
        if IP not in p:
            continue
        ip = p[IP]
        if TCP in p:
            l4 = p[TCP]
            proto = "6"
        elif UDP in p:
            l4 = p[UDP]
            proto = "17"
        else:
            continue
        if not hasattr(l4, "payload") or not isinstance(l4.payload, Raw):
            continue
        payload = bytes(l4.payload)
        if not payload:
            continue
        end_a = (ip.src, str(l4.sport))
        end_b = (ip.dst, str(l4.dport))
        if end_a <= end_b:
            flow_key = "%s:%s-%s:%s-%s" % (ip.src, l4.sport, ip.dst, l4.dport,
                                            proto)
            direction = "a_to_b"
        else:
            flow_key = "%s:%s-%s:%s-%s" % (ip.dst, l4.dport, ip.src, l4.sport,
                                            proto)
            direction = "b_to_a"
        flows.setdefault(flow_key, []).append({
            "ts": float(p.time),
            "dir": direction,
            "payload_len": len(payload),
            "payload": payload,
        })
        count += 1
    return [{"flow_key": fk, "packets": pkts} for fk, pkts in
            _seeded_take(list(flows.items()), 100)]


def parse_pcap_raw(pcap: Path) -> list:
    """Raw libpcap format parser (no deps). Handles pcap (not pcapng)."""
    flows: dict = {}
    try:
        with open(pcap, "rb") as fh:
            magic = fh.read(4)
            if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                             b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                return []
            # Little vs big endian
            little = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
            endian = "<" if little else ">"
            header = fh.read(20)
            if len(header) < 20:
                return []
            # pcap global header (after magic, 20 bytes):
            #   H version_major, H version_minor, i thiszone,
            #   I sigfigs, I snaplen, I linktype
            _, _, _, _, snaplen, linktype = struct.unpack(
                endian + "HHiIII", header)
            # Only support Ethernet (1) and Linux SLL (113)
            count = 0
            while count < MAX_PACKETS_ANALYZE:
                rec = fh.read(16)
                if len(rec) < 16:
                    break
                ts_sec, ts_usec, inc_len, orig_len = struct.unpack(
                    endian + "IIII", rec)
                data = fh.read(inc_len)
                if len(data) < inc_len:
                    break
                # Strip L2 header
                offset = 0
                if linktype == 1 and len(data) >= 14:
                    # Ethernet : skip 14 bytes
                    offset = 14
                elif linktype == 113 and len(data) >= 16:
                    # Linux SLL : skip 16 bytes
                    offset = 16
                else:
                    count += 1
                    continue
                ip_pkt = data[offset:]
                if len(ip_pkt) < 20:
                    count += 1
                    continue
                # IPv4 ?
                ver_ihl = ip_pkt[0]
                if (ver_ihl >> 4) != 4:
                    count += 1
                    continue
                ihl = (ver_ihl & 0xf) * 4
                if len(ip_pkt) < ihl:
                    count += 1
                    continue
                proto = ip_pkt[9]
                src_ip = "%d.%d.%d.%d" % tuple(ip_pkt[12:16])
                dst_ip = "%d.%d.%d.%d" % tuple(ip_pkt[16:20])
                if proto not in (6, 17):
                    count += 1
                    continue
                l4 = ip_pkt[ihl:]
                if len(l4) < 8:
                    count += 1
                    continue
                src_port, dst_port = struct.unpack(">HH", l4[:4])
                # TCP/UDP header offset
                if proto == 6:
                    # TCP header length
                    if len(l4) < 12:
                        count += 1
                        continue
                    data_off = (l4[12] >> 4) * 4
                    payload = l4[data_off:]
                else:
                    payload = l4[8:]
                if not payload:
                    count += 1
                    continue
                end_a = (src_ip, str(src_port))
                end_b = (dst_ip, str(dst_port))
                if end_a <= end_b:
                    flow_key = "%s:%s-%s:%s-%s" % (src_ip, src_port,
                                                    dst_ip, dst_port,
                                                    str(proto))
                    direction = "a_to_b"
                else:
                    flow_key = "%s:%s-%s:%s-%s" % (dst_ip, dst_port,
                                                    src_ip, src_port,
                                                    str(proto))
                    direction = "b_to_a"
                flows.setdefault(flow_key, []).append({
                    "ts": float(ts_sec) + ts_usec / 1e6,
                    "dir": direction,
                    "payload_len": len(payload),
                    "payload": payload,
                })
                count += 1
    except OSError:
        return []
    return [{"flow_key": fk, "packets": pkts} for fk, pkts in
            _seeded_take(list(flows.items()), 100)]


# ─── Protocol type inference ─────────────────────────────────────────────────
def infer_protocol_type(payloads: list) -> str:
    """Infer if protocol is binary, text, or hybrid.
    - binary  : >80% non-printable bytes
    - text    : >80% printable ASCII (incl. common delimiters)
    - hybrid  : mixed
    """
    if not payloads:
        return "unknown"
    total_bytes = 0
    printable_bytes = 0
    for p in payloads:
        for b in p:
            total_bytes += 1
            if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d):
                printable_bytes += 1
    if total_bytes == 0:
        return "unknown"
    ratio = printable_bytes / total_bytes
    if ratio > 0.80:
        return "text"
    elif ratio < 0.20:
        return "binary"
    else:
        return "hybrid"


# ─── Field-boundary detection ────────────────────────────────────────────────
def detect_field_boundaries(payloads: list) -> list:
    """Detect common message structure patterns.
    Looks for: length-prefix, magic bytes, fixed delimiters, fixed offsets."""
    fields: list = []
    if not payloads:
        return fields

    # 1. Length-prefix detection (first 1/2/4 bytes vs total length)
    sample = payloads[:50]
    for prefix_len in (1, 2, 4):
        if all(len(p) > prefix_len for p in sample):
            diffs = []
            for p in sample:
                if prefix_len == 1:
                    hdr = p[0]
                elif prefix_len == 2:
                    hdr = struct.unpack(">H", p[:2])[0]
                else:
                    hdr = struct.unpack(">I", p[:4])[0]
                diffs.append(hdr - len(p))
            # If most diffs are constant → length-prefix detected
            common = collections.Counter(diffs).most_common(1)
            if common and common[0][1] >= len(sample) * 0.7:
                fields.append({
                    "name": "length_prefix_%d_bytes" % prefix_len,
                    "offset": 0,
                    "size": prefix_len,
                    "type": "uint_be" if prefix_len > 1 else "uint8",
                    "encoding": "length_prefix",
                    "constant_offset": common[0][0],
                    "confidence": round(common[0][1] / len(sample), 2),
                })
                break

    # 2. Magic-byte detection (constant first N bytes)
    if sample:
        max_magic = min(8, min(len(p) for p in sample))
        magic_len = 0
        for i in range(max_magic):
            bytes_i = [p[i] for p in sample if len(p) > i]
            if len(set(bytes_i)) == 1:
                magic_len = i + 1
            else:
                break
        if magic_len >= 2:
            magic_hex = sample[0][:magic_len].hex()
            fields.append({
                "name": "magic_bytes",
                "offset": 0,
                "size": magic_len,
                "type": "bytes",
                "value_hex": magic_hex,
                "confidence": 1.0,
            })

    # 3. Delimiter detection (text protocols)
    text_sample = [p for p in sample if all(
        0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d) for b in p[:32])]
    if text_sample:
        for delim in (b"\r\n", b"\n", b" ", b":", b"|", b"\t"):
            count_with = sum(1 for p in text_sample[:30] if delim in p)
            if count_with >= len(text_sample[:30]) * 0.5:
                fields.append({
                    "name": "delimiter_%s" % delim.hex(),
                    "type": "delimiter",
                    "value_repr": delim.decode("ascii", errors="replace"),
                    "occurrence_rate": round(count_with / max(1, len(text_sample[:30])), 2),
                    "confidence": round(count_with / max(1, len(text_sample[:30])), 2),
                })

    # 4. Fixed-size tail (e.g. checksum/CRC)
    if len(sample) >= 10 and all(len(p) >= 8 for p in sample):
        # Look for trailing constant bytes
        tail_lens = []
        for tl in (1, 2, 4):
            if all(len(p) >= tl for p in sample):
                tails = [p[-tl:] for p in sample]
                if len(set(tails)) == 1:
                    tail_lens.append(tl)
        if tail_lens:
            tl = max(tail_lens)
            fields.append({
                "name": "trailer_%d_bytes" % tl,
                "offset": -tl,
                "size": tl,
                "type": "bytes",
                "value_hex": sample[0][-tl:].hex(),
                "risk": "possibly checksum/CRC",
                "confidence": 1.0,
            })

    return _seeded_take(fields, MAX_FIELDS)


# ─── Opcode extraction ───────────────────────────────────────────────────────
def extract_opcodes(payloads: list, opcode_len: int = 2) -> list:
    """Extract opcode candidates by clustering first N bytes of request payloads.
    Each unique opcode = first `opcode_len` bytes observed in >=1 payload.
    Returns list of {opcode_hex, count, sample_payload_hex}."""
    if not payloads:
        return []
    counter = collections.Counter()
    samples: dict = {}
    for p in payloads:
        if len(p) >= opcode_len:
            op = p[:opcode_len]
            counter[op] += 1
            if op not in samples:
                samples[op] = p[:32].hex()
    opcodes = []
    for op, count in counter.most_common():
        opcodes.append({
            "opcode_hex": op.hex(),
            "count": count,
            "sample_payload_hex": samples[op],
        })
    return _seeded_take(opcodes, MAX_OPCODES)


# ─── Command/response pattern matching ───────────────────────────────────────
def match_cmd_response(flow: dict) -> list:
    """Match request/response pairs by alternating direction."""
    patterns: list = []
    pkts = flow.get("packets", [])
    if len(pkts) < 2:
        return patterns
    # Walk packets, pair (req, resp) where dir alternates
    pairs = []
    i = 0
    while i < len(pkts) - 1:
        if pkts[i]["dir"] != pkts[i + 1]["dir"]:
            pairs.append((pkts[i], pkts[i + 1]))
            i += 2
        else:
            i += 1
    # Summarize
    for req, resp in _seeded_take(pairs, 20):
        patterns.append({
            "req_dir": req["dir"],
            "req_len": req["payload_len"],
            "resp_len": resp["payload_len"],
            "delta": resp["payload_len"] - req["payload_len"],
            "req_first8_hex": req["payload"][:8].hex(),
            "resp_first8_hex": resp["payload"][:8].hex(),
        })
    return patterns


# ─── Fuzzer seed candidates ──────────────────────────────────────────────────
def build_fuzzer_seeds(fields: list, opcodes: list, protocol_type: str,
                       sample_payloads: list) -> list:
    """Build fuzzer seed candidates for downstream fuzz_module.py.
    Each seed describes a typed field boundary + a mutation strategy."""
    seeds: list = []
    # 1. Opcode enumeration seeds
    for op in opcodes[:10]:
        seeds.append({
            "seed_id": "opcode_%s" % op["opcode_hex"],
            "type": "opcode_enum",
            "opcode_hex": op["opcode_hex"],
            "payload_template_hex": op["sample_payload_hex"],
            "strategy": "enumerate_opcodes",
            "protocol_type": protocol_type,
        })
    # 2. Length-field mutation seeds
    for f in fields:
        if f.get("encoding") == "length_prefix":
            seeds.append({
                "seed_id": "len_field_off%d" % f.get("offset", 0),
                "type": "length_field_overflow",
                "field": f["name"],
                "offset": f["offset"],
                "size": f["size"],
                "strategy": "overflow_length_field",
                "protocol_type": protocol_type,
            })
        elif f.get("name") == "magic_bytes":
            seeds.append({
                "seed_id": "magic_field",
                "type": "magic_field_fuzz",
                "field": "magic_bytes",
                "size": f["size"],
                "expected_value_hex": f.get("value_hex"),
                "strategy": "mutate_magic",
                "protocol_type": protocol_type,
            })
        elif f.get("type") == "delimiter":
            seeds.append({
                "seed_id": "delimiter_%s" % f.get("name", "?"),
                "type": "delimiter_fuzz",
                "field": f["name"],
                "delimiter_repr": f.get("value_repr"),
                "strategy": "inject_delimiter",
                "protocol_type": protocol_type,
            })
    # 3. Reproduce actual payloads (golden corpus)
    for i, p in enumerate(sample_payloads[:10]):
        seeds.append({
            "seed_id": "replay_%d" % i,
            "type": "replay_capture",
            "payload_hex": p[:64].hex(),
            "payload_len": len(p),
            "strategy": "replay_then_mutate",
            "protocol_type": protocol_type,
        })
    return _seeded_take(seeds, MAX_FUZZER_SEEDS)


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    if len(sys.argv) < 2:
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "missing_pcap_path",
            "usage": "protocol_re.py <pcap_path> [display_filter]",
        }))
        sys.exit(2)

    pcap_path = Path(sys.argv[1]).resolve()
    display_filter = sys.argv[2] if len(sys.argv) > 2 else None

    if not pcap_path.exists() or not pcap_path.is_file():
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "pcap_not_found",
            "path": str(pcap_path),
        }))
        sys.exit(2)

    tshark = _which("tshark")
    try:
        import scapy  # type: ignore  # noqa: F401
        has_scapy = True
    except ImportError:
        has_scapy = False

    if not (tshark or has_scapy):
        # Will fall back to raw parser — but warn
        tool_warn = "no_tshark_no_scapy_using_raw_pcap_parser"
    else:
        tool_warn = None

    # Defensive invariant : LOCAL PCAP file only — no live capture.

    # Compute PCAP sha256 for traceability
    try:
        with open(pcap_path, "rb") as fh:
            pcap_sha256 = hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        pcap_sha256 = None

    # 1. Parse PCAP
    flows: list = []
    parser_used = "none"
    if tshark:
        flows = parse_pcap_tshark(pcap_path, display_filter)
        parser_used = "tshark"
    if not flows and has_scapy:
        flows = parse_pcap_scapy(pcap_path)
        parser_used = "scapy"
    if not flows:
        flows = parse_pcap_raw(pcap_path)
        parser_used = "raw_pcap"

    # 2. Aggregate stats
    total_packets = sum(len(f["packets"]) for f in flows)
    flows_count = len(flows)

    # 3. Pick the flow with most packets for in-depth analysis
    if flows:
        target_flow = max(flows, key=lambda f: len(f["packets"]))
        all_payloads = [p["payload"] for p in target_flow["packets"]
                        if p.get("payload")]
        req_payloads = [p["payload"] for p in target_flow["packets"]
                        if p["dir"] == "a_to_b" and p.get("payload")]
    else:
        target_flow = {"flow_key": "none", "packets": []}
        all_payloads = []
        req_payloads = []

    # 4. Protocol type inference
    protocol_type = infer_protocol_type(all_payloads)

    # 5. Field-boundary detection
    fields_identified = detect_field_boundaries(all_payloads)

    # 6. Opcode extraction (from request payloads)
    opcodes_found = extract_opcodes(req_payloads, opcode_len=2)

    # 7. Command/response patterns
    cmd_resp_patterns = match_cmd_response(target_flow)

    # 8. Fuzzer seed candidates
    fuzzer_seeds = build_fuzzer_seeds(
        fields_identified, opcodes_found, protocol_type,
        all_payloads[:20])

    # 9. JSON report
    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "pcap": str(pcap_path),
        "pcap_sha256": pcap_sha256,
        "display_filter": display_filter,
        "parser_used": parser_used,
        "tool_warning": tool_warn,
        "tools_available": {
            "tshark": bool(tshark),
            "scapy": has_scapy,
            "raw_parser": True,
        },
        "packets_analyzed": total_packets,
        "flows_count": flows_count,
        "target_flow": target_flow["flow_key"],
        "protocol_type": protocol_type,
        "fields_identified": fields_identified,
        "fields_count": len(fields_identified),
        "opcodes_found": opcodes_found,
        "opcodes_count": len(opcodes_found),
        "command_response_patterns": cmd_resp_patterns,
        "fuzzer_seeds": fuzzer_seeds,
        "fuzzer_seeds_count": len(fuzzer_seeds),
        "notes": (
            "Inferred protocol structure from LOCAL PCAP. Fuzzer seeds are "
            "candidates for downstream fuzz_module.py — review before use."
        ),
        "seed": SEED,
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "read_only": True,    # no modifications to PCAP
        "no_network_egress": True,
        "legal_note": (
            "Defensive RE : analyse de captures PCAP LOCALES (réseau "
            "opérateur). Aucune capture live, aucune sortie réseau. "
            "Art. 323-1 Code pénal — usage lab isolé."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
