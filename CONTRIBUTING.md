# Contributing to Phantom Protocol

Welcome to the Phantom Protocol development community! We are building the world's first post-quantum, metadata-resistant mixnet.

## Security First

Any changes to `phantom-core` must prioritize:
1. **Bitwise Indistinguishability**: Fixed-size headers and sidecars.
2. **IND-CCA2 Compliance**: Always use full Kyber KEM ciphertexts.
3. **Total Integrity**: MAC-before-decapsulation.

## Pull Request Process

1. **Verify Geometry**: All header changes must be reflected in `constants.rs` and documented in `SPECIFICATION.md`.
2. **ZK Proofs**: Any structural change to the packet or batching logic requires updating the Plonky2 circuits in `zk/shuffling.rs`.
3. **Tests**: Ensure `cargo test --all` passes. New features must include a unit test and, where applicable, a `Gauntlet` benchmark simulation.
4. **Style**: We follow standard Rust formatting. Run `cargo fmt` before submitting.

## Reporting Vulnerabilities

Please do not open public issues for security vulnerabilities. Send an encrypted report to the security team (signing key in `docs/KEYS.md`).

---
"The gates are open. The shadows are ours."
