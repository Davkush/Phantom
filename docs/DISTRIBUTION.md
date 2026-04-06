# Phantom Protocol: Distribution & Reproducible Builds

Phantom Protocol is designed for high-risk users. Trust in the distribution pipeline is as critical as trust in the cryptographic primitives.

## 1. Reproducible Builds (P1)

To prevent "Supply Chain Attacks" (backdoor injection during CI), Phantom enforces **Strict Reproducibility**.

-   **Environment**: All official binaries are built using the `rust:1.75-slim` Docker image to ensure bit-for-bit identical results.
-   **Verification**: You can verify an official release by running:
    ```bash
    docker build -t phantom-builder .
    docker run --rm phantom-builder tar cf - target/release/phantom-node | sha256sum
    ```
    The resulting hash MUST match the hash published in the `SHA256SUMS` file of the GitHub Release.

## 2. Signed Releases (P1)

Every official binary is cryptographically signed using the **Dilithium-3 PQ-Signature** of the Phantom Core Team.

-   **Public Key**: `[Dilithium-3 PK: 0x82...f21]`
-   **Verification**:
    ```bash
    phantom verify --signature phantom-node.sig --binary phantom-node
    ```

## 3. GitHub Actions Workflow (CI/CD)

Our `.github/workflows/release.yml` performs the following steps:
1.  **Cargo Audit**: Checks for known vulnerabilities in dependencies.
2.  **Hardened Build**: Compiles with `panic = "abort"` and `opt-level = 3`.
3.  **Cross-Platform Artifacts**: Produces WSL2 (Ubuntu), Linux (x86_64/ARM64), and Experimental Windows binaries.
4.  **Automatic Signing**: The Dilithium-3 signing key is held in a secure GitHub Secret (only accessible to the Repository Owner).

---
*For the Sovereign Developer. For the Anonymous Swarm.*
