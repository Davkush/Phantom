# sectors/crypto.py — Configuration secteur Crypto Exchange
# Risque max : vol de clés/fonds. Régulation : variable (MiCA EU, BSA US).

HVT_KEYWORDS = (
    # Hot wallets
    "wallet", "hot_wallet", "signing", "signer",
    # Blockchain nodes
    "geth", "parity", "openethereum", "besu", "nethermind",
    "bitcoind", "lnd", "c-lightning", "electrs",
    # Indexers/explorers
    "blockstream", "mempool", "esplora",
    # Database/cache
    "postgres", "mysql", "redis", "mongodb",
    # Infrastructure
    "docker", "kubelet", "nginx", "envoy",
    # API/trading
    "grpc", "graphql", "trading", "matching", "orderbook",
)

PORT_MAP = {
    22:   "ssh",
    80:   "http",
    443:  "https",
    3000: "grafana",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    8080: "http-alt",
    8545: "ethereum-rpc",      # JSON-RPC geth/besu
    8546: "ethereum-ws",       # WebSocket geth
    9090: "prometheus",
    9200: "elasticsearch",
    11211: "memcached",
    30303: "ethereum-p2p",     # devp2p (geth)
    8333: "bitcoin-p2p",       # Bitcoin Core
    9735: "lightning-p2p",     # LND
}

AIR_GAP_INDICATORS = (
    "eth_accounts",       # RPC exposant les comptes
    "personal_unlockAccount",  # RPC dangereux
    "eth_sendTransaction",     # RPC critique
    "admin_nodeInfo",          # RPC admin
    "debug_traceTransaction",  # RPC debug
)

MODULES = [
    # Modules génériques IT (déjà dans le harness)
    "osint_leak", "sqli", "ssrf", "preauth", "waf_bypass",
    "docker_escape", "gdb_extract", "post_exploit_enum",
    "persistence", "fuzzer_send", "static_analysis",
    # Modules spécifiques crypto (à créer)
    "eth_rpc_probe",
    "wallet_extract",
]

MATRIX_OVERRIDE = {
    "eth_rpc_probe": {
        "expected": "summary.get('rpc_accessible') is not None",
        "note": "RPC Ethereum accessible (8545). eth_accounts exposé = critique.",
    },
    "wallet_extract": {
        "expected": "summary.get('keys_found') is not None",
        "note": "Extraction clés privées depuis mémoire process wallet.",
    },
}

DOCKER_BASE_IMAGE = "python:3.11-slim"
READ_ONLY_DEFAULT = False
CRITICAL_RISK = "financial"  # vol de fonds, manipulation de balances
REGULATION = "MiCA (EU), BSA/FinCEN (US), AMF (FR)"
