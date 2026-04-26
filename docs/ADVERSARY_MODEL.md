# Phantom Protocol — Formal Adversary Model

> **Version:** 0.1 — Draft for Phase 2 review  
> **Status:** Required prerequisite for Task 4.3 (Gauntlet Audit). The Phase 4 audit pass/fail
> criteria are defined exclusively by this document. No audit result can be described as
> "passed" without reference to the adversary classes and guarantee boundaries defined here.  
> **Scope:** This document covers the Phantom mix network, DPKI layer, hidden services
> protocol, and DC-Net extreme mode. It does not cover the application layer above
> `HsStream` or physical device security.

---

## Table of Contents

1. [Adversary Classification](#1-adversary-classification)
2. [Network and Participation Model](#2-network-and-participation-model)
3. [Per-Mode Anonymity Guarantees](#3-per-mode-anonymity-guarantees)
4. [Security Properties by Protocol Layer](#4-security-properties-by-protocol-layer)
5. [Known Limitations and Out-of-Scope Threats](#5-known-limitations-and-out-of-scope-threats)
6. [Composition of Security Properties](#6-composition-of-security-properties)
7. [Audit Pass/Fail Criteria Reference](#7-audit-passfail-criteria-reference)

---

## 1. Adversary Classification

Phantom Protocol is designed to resist adversaries across four dimensions: observation
capability, computational power, network control, and adaptation speed.

### 1.1 Observation Capability

| Class | Abbreviation | Definition |
|---|---|---|
| Local Passive Adversary | LPA | Observes traffic on a single link or within a single AS. Cannot correlate across the network. |
| Global Passive Adversary | GPA | Observes all network links simultaneously. Cannot modify traffic. The primary threat model for long-term deanonymization. |
| Local Active Adversary | LAA | Can inject, delay, drop, or modify traffic on links they control. Limited to a subset of the network. |
| Global Active Adversary | GAA | Can inject, delay, drop, or modify traffic on any network link. The maximum threat class; certain guarantees do not hold against a GAA. |

**Primary threat model:** Phantom's core anonymity guarantees target a **GPA** — a nation-state
level adversary monitoring all internet links simultaneously. This is a stronger assumption than
Tor's threat model (which assumes a local passive adversary) and reflects the deployment
context of Phantom Protocol.

### 1.2 Computational Power

| Class | Definition | Applies to |
|---|---|---|
| Computationally bounded | Cannot break standard cryptographic hardness assumptions (ECDLP, LWE/Kyber, SIS/Dilithium) in polynomial time | All adversary classes above |
| Quantum-capable | Has access to a cryptanalytically relevant quantum computer; can break ECDLP and RSA but not LWE/SIS | Future-model; Phantom's PQ layer targets this |
| Computationally unbounded | No restriction on compute; breaks all computational security | Only information-theoretic guarantees hold; DC-Net extreme mode only |

**Assumption:** All adversaries are computationally bounded unless explicitly stated. The
PQ-hybrid construction (X25519 + Kyber-1024) provides security against a quantum-capable
adversary as long as at least one primitive remains secure.

### 1.3 Network Control

| Class | Definition |
|---|---|
| Non-colluding | Controls no Phantom relay nodes |
| Minority colluding | Controls fewer than 50% of relay nodes; honest majority holds |
| Majority colluding | Controls ≥ 50% of relay nodes; breaks consensus-dependent guarantees |
| Targeted node compromise | Compromises specific named relay nodes without global control |

**Assumption:** All security proofs assume **minority colluding** adversary (< 50% of nodes
controlled). Majority collusion is explicitly out of scope — see §5.

### 1.4 Adaptive vs. Static Adversary

| Class | Definition |
|---|---|
| Static | Selects which nodes to corrupt before the protocol begins; cannot adapt based on observed traffic |
| Adaptive | Can corrupt new nodes at any time during protocol execution based on what it observes |

**Assumption:** Phantom's ZK shuffle proof security (Task 2.1) is proven against a **static**
adversary. The Churn Manager (Task 2.3) provides partial mitigation against adaptive
adversaries by rotating node participation patterns. Full adaptive adversary security is a
research goal, not a current guarantee.

---

## 2. Network and Participation Model

### 2.1 Honest Majority Assumption

The protocol assumes that at any given epoch, at least 50% + 1 of active Phantom nodes
are honest — they follow the protocol specification, do not collude, and do not leak
information to adversaries.

This assumption is enforced probabilistically by:
- Argon2id identity puzzle (T=3, M=64MB) raising Sybil creation cost
- Per-epoch dynamic PoW difficulty (C2) adjusting to burst admission
- Multi-path disjoint DHT lookup (d=5, quorum=3) requiring adversary control of ≥ 3 of 5
  independent paths simultaneously for a successful eclipse

### 2.2 Epoch Model

Time is divided into epochs of 3600 seconds. The security analysis is conducted per-epoch.
Cross-epoch security (multi-epoch or long-term) is subject to the intersection attack
described in §5.1 and is **not** currently formally guaranteed.

### 2.3 Traffic Model

All nodes produce cover traffic at a Poisson-distributed interval (mean 700ms, ±50ms jitter
per publication window). This creates a baseline anonymity set of all nodes active in the
same epoch. The anonymity set size is denoted **k** throughout this document.

---

## 3. Per-Mode Anonymity Guarantees

> ⚠️ **Critical distinction:** Phantom provides different guarantees in different modes and at
> different time horizons. Conflating them leads to overconfidence. Read this section carefully
> before making any security claims about the protocol.

### 3.1 Standard Mix Mode

| Property | Guarantee | Type | Adversary |
|---|---|---|---|
| Sender anonymity | 1/k per epoch (k = active nodes in epoch) | Computational | GPA |
| Receiver anonymity | 1/k per epoch | Computational | GPA |
| Unlinkability (send↔receive) | Computational; depends on ZK shuffle proof soundness | Computational | GPA |
| Long-term (multi-epoch) anonymity | **Not formally guaranteed** — see §5.1 | — | GPA |
| Content confidentiality | IND-CCA2 under X25519 + Kyber-1024 hybrid | Computational | GPA + Quantum |
| Traffic analysis resistance | Probabilistic; depends on cover traffic uniformity | Computational | GPA |

**The 1/k guarantee means:** given a GPA observing all links, the probability of correctly
identifying the sender of any given message is at most 1/k, where k is the number of nodes
active in that epoch. This is a per-epoch, per-message guarantee. It does not accumulate
across epochs.

### 3.2 DC-Net Extreme Mode

| Property | Guarantee | Type | Adversary |
|---|---|---|---|
| Sender anonymity within group | Information-theoretic (unconditional) | IT | Any passive |
| Sender anonymity against active jammers | **Not currently guaranteed** — Task 4.1 is the fix | None | LAA within group |
| Content confidentiality | IT (XOR of shared pads) | IT | Computationally unbounded |
| Jammer detection | **Not implemented** until Task 4.1 (Verdict-style ZK) | None | — |

> ⚠️ **Current DC-Net limitation (pre-Task 4.1):** DC-Net extreme mode provides
> information-theoretic anonymity **only against passive adversaries**. A single malicious
> group member broadcasting random bits will silently destroy every DC-Net round. This must
> be disclosed to users before DC-Net mode is exposed in any interface. After Task 4.1
> (Verdict-style ZK proofs per participant), jamming becomes detectable and the jammer
> ejectable.

### 3.3 Hidden Services

| Property | Guarantee | Type | Adversary |
|---|---|---|---|
| Server IP concealment | Server IP never in any protocol message | Structural | GPA |
| Client IP concealment from server | Client builds independent circuit; server sees only rendezvous node | Structural | GPA |
| Service existence concealment | DHT key = BLAKE3(address \|\| epoch); brute-force infeasible | Computational | GPA |
| Forward secrecy (epoch KEM keys) | Sessions before epoch end protected after epoch KEM key deletion | Computational | Targeted compromise |
| Post-quantum key exchange | IND-CCA2 session key under Kyber-1024 | Computational | Quantum-capable |
| Address self-authentication | Verifiable from address bytes alone; no CA required | Structural | Any |

---

## 4. Security Properties by Protocol Layer

### 4.1 Sphinx⁺ Packet Layer

**Confidentiality:** Each hop decrypts only its own layer. Intermediate relays learn:
- Their own position in the circuit (not the hop number)
- The next hop's address
- Nothing about the sender, receiver, payload content, or other hops

**Integrity:** Per-hop BLAKE3 MAC prevents modification without detection. MAC is verified
**before** Kyber decapsulation at each hop (critical ordering — prevents chosen-ciphertext
attacks).

**Replay protection:** Time-bucketed Bloom filter keyed on `alpha_cl`. Replays within the
same half-epoch are rejected. Memory bounded at 500,000 entries per filter.

**Post-quantum security:** Full Kyber-1024 ciphertext (1568 bytes) per hop. The FO transform
is preserved by carrying the complete ciphertext — truncation is not permitted. Session key
derivation: `BLAKE3("phantom-v1" || X25519_ss || Kyber_ss || context)`.

### 4.2 ZK Shuffle Proof Layer (Plonky2)

**Transparency:** PoseidonGoldilocksConfig over the Goldilocks field (p = 2⁶⁴ − 2³² + 1).
FRI-based proof system. No trusted setup ceremony required. Soundness error:
approximately 2⁻¹⁶⁸ at rate bits = 3, query rounds = 28.

**Circuit constraints (all three required for security):**
1. **Permutation completeness:** every input commitment appears in the output exactly once
2. **Decryption correctness:** `C_out[π(i)] == decrypt(C_in[i])` for all i
3. **MAC validity:** per-packet MAC is valid post-decryption for each output packet

Constraint 1 alone is insufficient — a relay can satisfy permutation while replacing payloads.
Constraints 2 and 3 together prevent payload substitution attacks.

**Ejection:** A relay that fails to publish a valid proof within the batch window, or whose proof
fails verification by any peer, is ejected via the gossip ejection protocol. Ejection is
permanent within the epoch and recorded with a monotonic ejection counter.

**`VerifierOnlyData` distribution:** Must be signed with the distributing node's Ed25519 key
and epoch-tagged before GossipSub broadcast. Unsigned distribution allows adversaries to
inject crafted verifier state.

### 4.3 DPKI / DHT Layer

**Node identity:** `node_id = BLAKE3("phantom-node-v1" || pk_ed || pk_dil || pk_x25519 || pk_kyber)`. Self-certifying — no CA required.

**Sybil resistance:** Argon2id static puzzle (T=3, M=64MB) for identity creation. Dynamic
puzzle (C2) adjusts per epoch based on admission rate. Burst detection: > 1,000 admissions
in 10 minutes increments C2 by 2 immediately without waiting for epoch end.

**Eclipse resistance:** d=5 disjoint path lookup with quorum=3. An adversary must control
≥ 3 of 5 independent lookup paths to eclipse a target. Long-lived node preference in routing
path selection further raises the bar.

**Descriptor integrity:** Every `NodeDescriptor` returned by a DHT lookup must pass
`verify_full()` before entering the routing table. This covers: Ed25519 signature, Dilithium-3
signature, epoch validity, PoW solution, and admission certificate.

### 4.4 Epoch and Clock Security

**Epoch acceptance window:** ±30 seconds from local epoch boundary. Packets from outside
this window are rejected. NTS (RFC 8915) clock synchronisation is a hard dependency —
nodes with clock drift > 30 seconds from network consensus are not admitted to the routing
table.

**Ejected node window:** The monotonic ejection counter prevents ejected nodes from
re-entering via the 120-second overlap window. Once ejected in epoch N, a node is barred
from all epochs ≥ N regardless of descriptor validity.

---

## 5. Known Limitations and Out-of-Scope Threats

### 5.1 Long-Term Intersection Attack (Multi-Epoch Deanonymization)

**Status:** Known limitation. Not currently mitigated beyond the Churn Manager (Task 2.3).

A GPA that observes which Phantom nodes are online across multiple epochs can perform an
intersection attack: a sender Alice can only be in a message's anonymity set if she was online
during that epoch. Over many epochs, the intersection of observed online sets narrows toward
a single node.

**Formal bound:** The intersection attack converges in O(log k / log(1/p_offline)) epochs,
where p_offline is the probability a node is offline in any given epoch and k is the anonymity
set size.

**Current mitigation:** The Churn Manager (Task 2.3) introduces randomised offline periods
drawn from a Poisson distribution, increasing p_offline and slowing convergence.

**Guarantee boundary:** Phantom provides **per-epoch** sender anonymity of 1/k.
Long-term (multi-epoch) anonymity against a sustained GPA intersection attack is **not**
currently formally guaranteed and should not be claimed.

### 5.2 Traffic Analysis via Timing Correlation

A GPA observing packet timing at both ends of a circuit can perform timing correlation even
under the Poisson cover traffic model. The cover traffic interval (mean 700ms) provides a
probabilistic window within which the true message is hidden, but sustained timing analysis
over many messages degrades this protection.

**Status:** Partially mitigated by the ±50ms C_in publication jitter and per-hop C_batch
encryption. Not fully resolved. FRONT-style traffic shaping (Task 3.1) is the planned
additional mitigation.

### 5.3 Majority Adversary

If an adversary controls ≥ 50% of active Phantom nodes, all consensus-dependent
guarantees fail: the multi-path DHT lookup quorum is broken, ejection gossip can be
suppressed, and ZK proof verification can be outvoted.

**Status:** Out of scope. The honest majority assumption (§2.1) is a protocol precondition,
not a guarantee. Majority collusion resistance is a research problem beyond the current
design.

### 5.4 Physical Device Compromise

Active session keys (`session_key` in `HsSession`) are held in process memory during a
session. Physical access to the running process exposes current session keys.

**Status:** Out of scope. This is a fundamental property of any in-memory session key, not a
Phantom-specific limitation. Mitigated by process isolation recommendations in the hidden
services spec (§4.2 — key-signing daemon separation).

### 5.5 Breaking NIST PQC Standards

The post-quantum security layer assumes that Kyber-1024 (FIPS 203) and Dilithium-3
(FIPS 204) are not broken. If either standard is cryptanalysed, the PQ layer of the protocol
fails. The classical layer (X25519, Ed25519) remains independently secure under
non-quantum assumptions.

**Status:** Out of scope. Phantom's hybrid construction ensures security if **either** the
classical or PQ primitive holds. Breaking both simultaneously is required to compromise
Phantom's cryptographic layer.

### 5.6 DC-Net Jamming (Pre-Task 4.1)

**Status:** Active limitation. A malicious DC-Net group member can silently jam all rounds at
zero cost. No cryptographic mechanism currently exists to detect or attribute jamming.

**Planned fix:** Task 4.1 — Verdict-style verifiable DC-Net. Each participant will prove via ZK
that their broadcast share is the correct XOR of shared pads. Until Task 4.1 is complete,
DC-Net extreme mode must be documented as passive-adversary-only.

---

## 6. Composition of Security Properties

### 6.1 ZK Shuffle + DC-Net Composition

The ZK shuffle proof (computational, game-based security) and DC-Net (information-theoretic
security for passive adversaries) are used in separate modes, not simultaneously. They do
not need to compose — a packet is routed through either the standard mix layer or the DC-Net
group layer, not both. There is no known security conflict between the two modes.

### 6.2 PQ Hybrid Composition

The X25519 + Kyber-1024 hybrid is secure if either primitive holds. BLAKE3 is used as the
combiner: `session_key = BLAKE3(domain_sep || X25519_ss || Kyber_ss || context)`. This
construction follows the dual-PRF combiner pattern and provides security under the
assumption that BLAKE3 is a secure PRF, which is a standard assumption.

### 6.3 Hidden Services + Mix Network

The hidden services rendezvous protocol runs on top of Sphinx⁺ routing. The anonymity
properties of the mix network apply to all hidden service traffic — the rendezvous node sees
only ciphertexts and cannot correlate client and service identity. The ZK shuffle proof applies
equally to hidden service circuits and standard circuits.

---

## 7. Audit Pass/Fail Criteria Reference

The Phase 4 Gauntlet Audit (Task 4.3) uses this section as its objective pass/fail standard.
An audit result is only meaningful when stated in terms of these criteria.

### Pass Criteria (all must hold)

| # | Criterion | Verification method |
|---|---|---|
| A1 | Per-epoch sender anonymity (1/k) holds under full GPA observation of all links for the duration of the test epoch | Traffic correlation attack across all Sphinx⁺ hops; no sender identified with probability > 1/k |
| A2 | ZK shuffle proof rejects invalid permutations; ejection counter increments within one batch window | Negative test: inject invalid permutation; observe ejection |
| A3 | No deanonymization achieved within the threat model (minority colluding GPA, computationally bounded) over a 72-hour sustained attack period | Intersection attack over 3 epochs; anonymity set does not collapse to 1 node |
| A4 | DHT eclipse attempt with 30% adversarial nodes fails to prevent honest descriptor retrieval | 15 adversarial nodes in 50-node testnet; quorum lookup succeeds |
| A5 | Epoch clock skew injection does not allow ejected nodes to continue routing | Inject packets from ejected node with manipulated epoch field; all rejected |
| A6 | Proof suppression by adversarial relay triggers ejection within one batch window | Adversarial relay withholds proof; peer ejection confirmed |
| A7 | DC-Net jamming detected and jammer ejected (only after Task 4.1 is complete) | Malicious group member broadcasts random bits; ejected within one round |
| A8 | Hidden service address self-authentication holds; client correctly rejects spoofed descriptors | Inject malformed ServiceDescriptor; client verify() returns Err |

### Fail Criteria (any one causes audit failure)

| # | Criterion |
|---|---|
| F1 | Any message sender is identified with probability > 1/k by any attack within the defined threat model |
| F2 | An invalid ZK shuffle proof is accepted by any honest verifier |
| F3 | An ejected node successfully routes traffic after the ejection epoch |
| F4 | A DHT lookup with ≤ 3 adversarial paths (of 5) fails to return the correct descriptor |
| F5 | Any open CRITICAL or HIGH finding from the security audit remains unresolved at audit time |

### Out-of-Scope at Audit Time

The following are explicitly not tested in the Phase 4 audit, as they are known limitations
documented in §5:

- Long-term (multi-epoch, > 3 epoch) deanonymization via intersection attack
- Majority adversary (≥ 50% node control)
- Physical device compromise
- Breaking NIST PQC standards

---

## Change Log

| Date | Change |
|---|---|
| 2026-04 | v0.1 — Initial draft. Covers Phase 1 completed state and Phase 2 in-progress guarantees. DC-Net limitation (§5.6) and long-term intersection (§5.1) documented explicitly. |

---
