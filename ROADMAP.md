# Phantom Protocol — Remediation & Mainnet Roadmap

> **Status:** Active development — April 2026
> **Scope:** This document is both the remediation roadmap (addressing all findings from the March 2026 security audit) and the implementation plan linking each task to its target Rust module and acceptance criteria.
> **How to read it:** Each task is tagged with the audit finding it closes (e.g. `CRIT-01`), its status, and any hard dependencies. Tasks marked **[BLOCKING]** must be complete before the next task in their sequence begins.

---

## Phase 1 — Cryptographic & Sybil hardening [IMMEDIATE]

### Task 1.1 — Standardize KEM Block Lay-out (Approach B) [CRIT-01]
- **Issue:** The Kyber-1024 ciphertext is being fragmented, causing a Fujisaki-Okamoto (FO) transform breakdown.
- **Remediation:** Enforce the 1,600-byte "Sidecar Sidecar" geometry across the whole codebase.
- **Target:** `phantom-core/src/packet.rs`.
- **Status:** Done.

### Task 1.2 — STARK Shuffle Proof Binding [CRIT-02]
- **Issue:** The ZK shuffle proof only binds the first 32 bits of the batch hash, allowing mix-and-match attacks.
- **Remediation:** Implement full 256-bit hash binding using Random Linear Combination (RLC) inside the Plonky2 circuit.
- **Target:** `phantom-core/src/zk/shuffling.rs`.
- **Status:** Done.

### Task 1.3 — Sybil Hardening (Argon2id) [CRIT-03]
- **Issue:** BLAKE3 PoW is vulnerable to GPU scaling.
- **Remediation:** Implement Argon2id (64MB, t=3, p=1) for node admission and burst-detection adaptive difficulty.
- **Target:** `phantom-core/src/identity.rs`.
- **Status:** Done.

### Task 1.4 — Real QUIC Transport for DHT [BLOCKING]
- **Issue:** `rpc_find_node` is a simulation.
- **Remediation:** Replace mock RPCs with actual QUIC transport (Quinn) enforcing MTU 9000.
- **Target:** `phantom-core/src/dht/`.
- **Status:** IN PROGRESS.

---

## Phase 2 — Verifiability & statistical resistance [MIX LAYER]

### Task 2.1 — ZK Circuit Constraints [CRIT-04]
- **Issue:** The circuit uses `assert_one` placeholders instead of actual decryption/MAC verification.
- **Remediation:** Replace stubs with real field relationship constraints modeling the Sphinx transition.
- **Target:** `phantom-core/src/zk/shuffling.rs`.
- **Status:** Done.

---

## Phase 3 — Transport invisibility & sustainability [GATEWAY LAYER]

### Task 3.1 — Poisson-Distributed Timing [MED-01]
- **Issue:** Constant-rate traffic is vulnerable to interval correlation.
- **Remediation:** Implement Poisson dispatching with 700ms interval ($\pm 50ms$).
- **Target:** `phantom-node/src/mix_loop.rs`.

---

## Phase 4 — Extreme resilience [DECENTRALIZED GOVERNANCE]

### Task 4.1 — 5-of-9 Multisig Upgrades [SR-DHT]
- **Issue:** Genesis configuration is static.
- **Remediation:** Implement multisig verification for DHT-based protocol updates.
- **Target:** `phantom-core/src/governance/`.
