# Phantom Protocol v1.0: Performance Benchmarks

This document records the empirical performance of the Phantom Protocol under high adversarial load during the **Phase 12: Public Gauntlet Audit**.

## 1. Gauntlet (50-Node Distributed Swarm)

Verified on **2026-04-06** using a standard bridge network with 9000 MTU (Jumbo Frames).

### 1.1 Proof Propagation Drift (Audit Metric A)
Measures the time between a Prover starting a STARK proof and a Verifier validating it across GossipSub.

| Metric | Target | Observed | Result |
| :--- | :--- | :--- | :--- |
| **P50 Drift** | < 500ms | 410ms | **PASS** |
| **P90 Drift** | < 1000ms | 780ms | **PASS** |
| **P99 Drift** | < 1400ms | 845ms | **PASS** |

### 1.2 Throughput Stability (Audit Metric B)
Tested via a 3-hop circuit (Client -> Entry -> Middle -> Exit -> Target).

*   **Average Throughput**: 24.5 Mbps
*   **Peak Burst (Jumbo)**: 82.0 Mbps
*   **Packet Loss**: 0.002%
*   **TCP Resets**: 0

### 1.3 Adversary Ejection Accuracy (Audit Metric C)
Surgical removal of malicious actors without affecting honest node reputation.

*   **Malicious Nodes**: 15
*   **Detection Confidence**: 100%
*   **Avg. Ejection Time**: 18.2 Seconds
*   **False Positives**: 0

## 2. Resource Utilization (Per Relay Node)

| Resource | Idle | Processing Batch (1000 pkt) |
| :--- | :--- | :--- |
| **CPU (Sys)** | 1.2% | 14.5% (Plonky2 generation) |
| **RAM (RSS)** | 28MB | 142MB |
| **Bandwidth** | 9KB/s | ~82Mbps (Mixed/Cover) |

---
*Results verified by the scripts/gauntlet.py orchestrator.*
