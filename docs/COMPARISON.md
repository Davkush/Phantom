# Phantom Protocol vs. The World: Strategic Comparison

Phantom is not a general-purpose privacy tool. It is a high-assurance anonymity gateway designed for the era of the **Global Passive Adversary (GPA)**.

## 1. Threat Model Personas

| Persona | Primary Goal | Recommended Tool | Why? |
| :--- | :--- | :--- | :--- |
| **Privacy Enthusiast** | Unblock geo-restricted content, hide traffic from ISP. | **VPN / Tor** | High throughput, low latency, easy setup. |
| **State-Level Dissident** | Communicate with zero metadata linkage between sessions. | **Phantom** | **GPA Resistance**. Tor's circuit timing is vulnerable to correlation. |
| **Whistleblower** | Publish 10GB+ evidence without IP discovery. | **Phantom** | **Volumetric Indistinguishability**. Tor's "cell" frequency can leak payload size. |

## 2. Technical Comparison: The Honest Truth

### 2.1 Phantom vs. Tor
-   **Latency**: Tor is circuit-switched (low latency). Phantom is mix-batched (high latency, ~700ms).
-   **Anonymity**: Tor relies on "Circuit Diversity." Phantom relies on **Synchronized Entropy Batches**. 
-   **Resilience**: A GPA observing entry and exit nodes of Tor can correlate traffic in minutes. A GPA observing Phantom sees only constant-size 9KB pulses that never change frequency.

### 2.2 Phantom vs. Nym
-   **Incentives**: Nym's token-based economy (NYM) introduces "Proof-of-Stake" risks. Phantom uses **Reciprocal Routing** (Tit-for-Tat), making it an "Incentive-Aligned OS" rather than a market.
-   **Verification**: Phantom uses **STARKs** (Plonky2) for per-batch honesty proofs. Nym primarily relies on reputation staking.

## 3. The Epoch Boundary

To maintain perfect forward secrecy and Sybil resistance, Phantom rotates its **Epoch Boundary** periodically.

-   **KEM Rotation**: Every epoch, nodes rotate their Kyber-1024 keys. 
-   **The Flicker**: You may notice a 1-second "flicker" in connectivity as the SR-DHT (Storage-Resistant DHT) converges on the new identity keys. This is the **Price of Sovereign Security**.

---
*© 2026 Phantom Protocol. For those who cannot afford to be discovered.*
