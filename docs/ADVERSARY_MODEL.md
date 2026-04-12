# Phantom Protocol: Formal Adversary Model (v1.0)

This document defines the threat model and security assumptions for the Phantom Protocol, providing the basis for the Gauntlet pass/fail criteria and the cryptographic proofs.

## 1. Adversary Definition: The Global Passive Adversary (GPA)

We assume an adversary with the capability to observe all network links (e.g., a Tier-1 ISP or state-level actor).

*   **Passive Capabilities**: The GPA can observe the timing, size, and metadata of all packets entering and leaving the mixnet.
*   **Active Capabilities**: The adversary can corrupt a subset of nodes ($f < 1/3$) and perform active attacks including:
    *   **Selective Dropping**: Suppressing packets to observe changes in stream behavior.
    *   **STARK Suppression**: Failing to broadcast shuffle proofs to trigger node ejections and network instability.
    *   **Sybil Injection**: Deploying multiple corrupted nodes to minimize the honest path length.

## 2. Security Objectives

### 2.1 Relationship Anonymity
The adversary cannot link a specific sender $S$ to a specific receiver $R$ with a probability significantly greater than $1/N$, where $N$ is the number of active honest nodes in the mix-batch.

### 2.2 Resistance to Intersection Attacks
By enforcing randomized Churn scheduling (2-6 hours online) and drain coordination, the protocol limits the effectiveness of long-term statistical intersection attacks.

## 3. Gauntlet Pass/Fail Criteria (Metric A, B, C)

The `gauntlet.py` orchestrator verifies these criteria under adversarial load:

| Metric | Target | Failure Condition |
| :--- | :--- | :--- |
| **A: Proof Drift** | < 1400ms (P99) | Proof propagation is slower than the Poisson dispatch window. |
| **B: Stability** | 0 TCP Resets | Intersection-disruption (Churn) causes active stream failure. |
| **C: Ejection** | 100% Ejection | Malicious nodes suppressing proofs are not removed within 30s. |

## 4. Cryptographic Assumptions

*   **Lattice Hardness**: Resistance against quantum adversaries via Kyber-1024 and Dilithium-3.
*   **STARK Soundness**: Batch shuffle integrity via FRI-based transparent STARKs (Plonky2).
*   **PoW Hardness**: Argon2id memory-hardness ensures Sybil entry cost is high ($>64$MB RAM per identity).
