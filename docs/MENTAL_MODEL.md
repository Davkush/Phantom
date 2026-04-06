# Phantom: The Mental Model (Technical Deep-Dive)

This document provides a rigorous breakdown of the **Sphinx-Plus-ZK** architecture. It is intended for external auditors and security engineers.

## 1. 9KB Sphinx (Bit-Indistinguishability)

Phantom departs from Tor's variable-length routing by enforcing a **Constant-Width 9216-byte (9KB) packet footprint**.

### Why 9KB?
The choice of 9KB is driven by **Post-Quantum Cryptography (PQC)**. A standard Kyber-1024 ciphertext is 1568 bytes. To support 5-hop routing with overhead for SURBs, a 9KB payload ensures that no fragmentation occurs across the network's JUMBO-frame (MTU 9000) bridge.

---

## 2. The Heartbeat (Synchronized Mix-Batching)

Unlike Tor, which is asynchronous, Phantom's anonymity is derived from **Synchronous Intervals**.

### 2.1 The Batch Period
A node collects packets for $T$ milliseconds (default 700ms). This creates a **Crowd-Anonymity Set**. An adversary observing the wire cannot link any incoming packet $I_n$ to any outgoing packet $O_m$ because they all leave "simultaneously" (under Poisson jitter).

### 2.2 Plonky2 STARK Shuffling
To ensure the node isn't dropping or replacing packets (Selective Attack), the node generates a **Permutation Argument** ($H(input) = H(\pi(input))$).
-   **Verification**: The network (via GossipSub) verifies the STARK proof.
-   **Ejection**: If a proof is not broadcast within 2 batch cycles ($2T$), the node is surgically blacklisted from the DHT.

---

## 3. SURBs (Single-Use Reply Blocks)

Phantom solves the **Return Path Anonymity** problem using SURBs.

-   **Forward Trip**: The client includes a "Return Onion" (the SURB) in the outbound packet's slack space.
-   **Exit Node**: The exit node applies the SURB header to the target's response.
-   **Anonymity**: The exit node knows the content (unless encrypted at the app-layer), but **never knows the client's identity**.

---

## 4. Reciprocal Routing (The Incentive Engine)

To move away from centralized token economies (like Nym), Phantom uses a **Local ledger of Peer Contribution**.

```rust
pub async fn get_priority_boost(&self, node_id: [u8; 32]) -> u32 {
    let scores = self.scores.read().await;
    let score = scores.get(&node_id).copied().unwrap_or(0);
    
    // Priority Lane: +1 for every 500 successful packets, max 10.
    (score / 500).min(10) as u32
}
```

Wait, this is the "Biological Incentive." If you route for the network, the network routes for you. This is how the **Agentic Swarm** maintains high performance without a central clearinghouse.

---
*© 2026 Phantom Protocol. Verifiable. Metadata-Hard. Post-Quantum.*
