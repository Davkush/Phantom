# Example: The "Ghost Browser" (Librewolf/Firefox)

Phantom provides a **SOCKS5 proxy** at `127.0.0.1:9050` by default. To route your traffic through the mixnet without leaking DNS or metadata, follow this high-security recipe.

## 1. Network Settings
In Librewolf or Firefox settings, go to **Network Settings** and configure the following:

-   **Proxy Type**: Manual Proxy Configuration
-   **SOCKS Host**: `127.0.0.1` | **Port**: `9050`
-   **Protocol**: SOCKS v5
-   **DNS Over SOCKS**: **[REQUIRED] Check the box "Proxy DNS when using SOCKS v5".** This prevents "DNS Leakage" to your ISP.

## 2. Advanced Hardening (about:config)
To ensure the browser doesn't bypass the mixnet for specific requests, set these flags:

-   `network.proxy.socks_remote_dns`: `true`
-   `network.trr.mode`: `5` (Disable built-in DoH, use Phantom SOCKS5 DNS)
-   `media.peerconnection.enabled`: `false` (Prevents WebRTC from leaking your real IP)

## 3. Verification
Once configured, navigate to `http://check.phantom-protocol.net` (simulated). 
-   **Exited at Relay ID**: `[3b8f...ae21]`
-   **Circuit Entropy**: `High`
-   **Global Passive Resistance**: `Active`

---
*Recommended Environment: WSL2 for Windows users.*
