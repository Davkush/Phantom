# Phantom Protocol Implementation Plan

This document serves as the high-level technical bridge between the `SPECIFICATION.md` and the current state of the codebase. It tracks the progress of the remediation tasks required for the 2026 Mainnet release.

## Current Focus: Phase 1 & 2 Remediation

### 1. Cryptographic Hardening
- [x] **ZK Shuffle Binding**: Implementing 256-bit RLC in Plonky2 to prevent mix-and-match attacks.
- [x] **KEM Geometry (Approach B)**: Enforcing the 9KB packet layout with a 1,600-byte sidecar.
- [x] **SURB Security**: Transitioning SurbBlocks from 96-byte Kyber fragments to 1568-byte full ciphertexts (Task 1.1).

### 2. Sybil Resistance
- [x] **Argon2id PoW**: Aligning admission difficulty with high-memory ASIC-resistant parameters (64MB, t=3).
- [x] **Real QUIC Transport**: Replacing simulated DHT RPCs with Quinn-based networking. MTU 9000 and 500ms timeout configured. `DhtTransport` abstraction implemented and multi-path lookup integrated (Task 1.4).

### 3. Hidden Services
- [x] **Address Derivation v2**: Moved to `phantom-hs-v2` derived from permanent signing keys for improved forward secrecy (LOW-04).
- [ ] **Dual-Blind Handshake**: Implementation of IP (Introduction Point) and RP (Rendezvous Point) logic.

## Module Ownership

- `phantom-core::zk`: STARK proof systems and shuffling circuits.
- `phantom-core::dht`: Kademlia routing and node admission logic.
- `phantom-node::transport`: QUIC and physical wire management.
- `phantom-node::proxy`: SOCKS5 and Exit logic.

---
*Generated: April 2026*
