# Phantom Protocol Technical Specification v1.1

## 1. Mathematical Foundations

### 1.1 Post-Quantum Sphinx Packet (9216 bytes)
The Phantom Sphinx packet is designed to be **Bitwise and Volumetric Indistinguishable** from random noise.
*   **Packet Size**: Exactly 9216 bytes (9KB).
*   **Entropy**: All packets are padded with high-entropy noise.
*   **PQ Security**: Every hop performs a full Kyber-1024 decapsulation and X25519 blinded scalar multiplication.

#### 1.1.1 Header Geometry (Approach B - Separated Sidecar)
Phantom uses a separated KEM sidecar layout to maximize payload:

| Region | Size | Description |
|---|---|---|
| Current KEM Block | 1,600 B | Current hop's X25519 Ephemeral PK + Kyber-1024 CT |
| Routing Info | 68 B | Encrypted RoutingAction + c_batch + Epoch |
| Per-hop MAC | 32 B | BLAKE3 MAC (Verified PRIOR to KEM decapsulation) |
| KEM Sidecar | 6,400 B | 4 remaining hops' KEM blocks (onion-encrypted) |
| **Header Total** | **8,100 B** | Total structure overhead |
| **Payload** | **1,116 B** | Usable application data |

### 1.2 STARK Verifiable Shuffling (Plonky2)
To solve the "Relay Trust" problem, Phantom implements a permutation argument circuit.
*   **Grand Product Argument**: A permutation $\pi$ of $n$ packets is proven via $H(in, \pi) = H(out)$.
*   **Proof Size**: ~15-18KB (non-recursive).
*   **Verification**: Proofs are propagated via GossipSub (`phantom/v1/shuffles`). Failure to broadcast a proof triggers automated DHT-based node ejection.

## 2. Bidirectional Reliability & SURBs

### 2.1 Single-Use Reply Blocks (SURBs)
Phantom enables anonymous return paths without the exit node knowing the client's identity.
*   **Piggybacking**: 5 SURBs are included in every outbound 9KB packet.
*   **Replenishment**: SURB pools are maintained by the StreamManager to prevent TCP starvation.

### 2.2 PhantomStream (The Reliability Layer)
*   **Payload Envelope**: Encapsulates 9KB of data with a 128-bit stream identifier.
*   **Cumulative ACKs**: 5-packet window with a 500ms heartbeat.

## 3. Decentralized Infrastructure

### 3.1 5-of-9 Multisig Governance
The network's Genesis configuration and PoW difficulty are governed by a 9-member committee.
*   **Threshold**: Any protocol-wide update requires 5 valid Ed25519 signatures.
*   **Propagation**: Updates are distributed via the DHT `phantom/v1/upgrade` record.

### 3.2 Reciprocal Routing (Tit-for-Tat)
*   **Scoring**: Nodes maintain a local interaction ledger per NodeID.
*   **Priority Lane**: Every 500 successful packet hand-offs grants a peer +1 priority boost (Max 10), reducing publication jitter.

## 4. Operational Parameters

| Parameter | Value | Description |
| :--- | :--- | :--- |
| **MTU** | 9000 (JUMBO) | Enforced to prevent 9KB Sphinx fragmentation |
| **Poisson Interval** | 700ms | Publication window jitter ($\pm 50ms$) |
| **Argon2id Diff** | T = 3, M = 64MB | Sybil resistance PoW |
| **Max Hops** | 5 | Standard anonymity depth |
| **Port Mapping** | UPnP Port 443 | Automatic NAT traversal |

## 5. Version 2 Address Derivation

### 5.1 Overview
Phantom addresses use a hierarchical derivation scheme based on SLIP-0010 (similar to BIP-32) for both Ed25519 (identity keys) and Kyber-1024 (post-quantum keys). This enables:

- **Hierarchical Deterministic (HD) Key Derivation**: Generate multiple addresses from a single master seed
- **Post-Quantum Security**: Kyber-1024 keys for resistance against quantum attacks
- **Forward secrecy**: Derive ephemeral keys for each session

### 5.2 Derivation Path
```
m / purpose' / type' / index'
```

| Level | Value | Description |
|---|---|---|
| `purpose` | `1234567'` | Phantom protocol identifier |
| `type` | `0'` | Ed25519 master key derivation |
| `type` | `1'` | Kyber-1024 PQ key derivation |
| `index` | `N` | Sequential address index |

### 5.3 Implementation
```rust
// Ed25519 path: m/1234567'/0'/0'
let ed_path = slip10::path!("m/1234567'/0'/0'");

// Kyber path: m/1234567'/1'/0'
let kyber_path = slip10::path!("m/1234567'/1'/0'");

// Derive master keys from seed
let master_key = MasterKey::from_seed(&seed);

// Generate addresses
let ed_key = master_key.derive_key(ed_path);
let pq_key = master_key.derive_key(kyber_path);
let address = HybridPublicKey::combine(ed_key, pq_key);
```

### 5.4 Address Format
```
phatom1[base32-encoded-hybrid-key]
```

Example: `phatom1qpz5evrpqqq0f5x7y3j2z8n9m0k4l6h8o2p1q9r5s6t7u8v9w0x1y2z3`


---
*© 2026 Phantom Protocol Foundation. Released under Apache 2.0.*
