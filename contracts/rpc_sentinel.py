# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
RPC SENTINEL — Decentralized RPC Integrity Monitor.

A GenLayer Intelligent Contract that answers ONE narrow, objectively
demonstrable question:

    "Does this public blockchain RPC endpoint currently behave
    consistently with the expected blockchain network and basic
    JSON-RPC integrity requirements?"

Anyone may request an integrity check of a PUBLIC, READ-ONLY EVM RPC
endpoint together with the chain ID they expect it to serve. GenLayer
validators then INDEPENDENTLY probe the endpoint over JSON-RPC,
normalize their observations into a fixed schema, and reach a
consensus-backed integrity classification. Only a consensus-verified
normalized observation becomes authoritative on-chain state — a leader
proposal is never persisted on its own.

RPC SENTINEL IS NOT:
  * an endorsement that an RPC provider is honest or malicious;
  * a guarantee an endpoint stays healthy after a check;
  * a claim that an endpoint is canonical or load-balanced correctly;
  * a network/port scanner or a general uptime dashboard.

It establishes EXACTLY the scope of its defined probe (PROBE PLAN).

CLASSIFICATION MODEL (6 statuses, deterministic derivation)
===========================================================
  HEALTHY       — endpoint reachable, valid JSON-RPC 2.0 responses,
                  observed chain ID == expected chain ID, valid block
                  number, freshness bucket CURRENT or
                  SLIGHTLY_BEHIND, no probe instability.
  MISCONFIGURED — endpoint reachable, valid JSON-RPC, but observed
                  chain ID != expected chain ID.
  STALE         — chain ID matches and the endpoint responds, but the
                  target's block height is demonstrably behind the
                  chain's reference height beyond the freshness
                  tolerance (bucket STALE).
  DEGRADED      — all primary methods pass; one or more optional
                  secondary methods (net_version /
                  web3_clientVersion) fail or disagree with
                  eth_chainId.
  UNREACHABLE   — no valid JSON-RPC response obtainable from the
                  endpoint (DNS/connection failure, timeout, HTTP
                  error status, non-JSON body, JSON-RPC error object,
                  missing result field, malformed hex quantity).
  INCONSISTENT  — the endpoint's own repeated responses conflict
                  within a single prober (alternating chain IDs,
                  regressing block numbers, or impossible height),
                  preventing one safe classification.

Cross-prober conflict (a validator independently deriving a
different classification) never persists ANY result: consensus
fails, the check stays CONSENSUS_FAILED, and the frontend reports
"INCONSISTENT (consensus failure)". That is the INCONSISTENT display
path for validator-vs-leader disagreement.

PROBE PLAN (identical for leader and every validator; 8 requests)
==================================================================
  P1 eth_chainId          (primary, stability check A)
  P2 eth_chainId          (primary, stability check B)
  P3 eth_blockNumber      (primary, stability check A)
  P4 eth_blockNumber      (primary, stability check B)
  P5 net_version          (optional secondary)
  P6 web3_clientVersion   (optional secondary)
  R1 eth_chainId + R2 eth_blockNumber on the chain REFERENCE
     endpoint (freshness anchor; two requests)

Optional method failure NEVER fails the check (DEGRADED at most).
Primary method failure fails the probe (UNREACHABLE) with a
machine-readable code.

FRESHNESS POLICY (no trusted clock, no cross-prober block equality)
====================================================================
Block numbers change between requests, so block heights are NEVER
compared for equality across probers. Instead each prober derives a
freshness BUCKET from its own paired observation:

    delta = reference_block - target_block
      delta <= 2    -> CURRENT
      delta <= 30   -> SLIGHTLY_BEHIND
      otherwise     -> STALE
      delta < -60   -> AHEAD_ANOMALY (implausible: INCONSISTENT,
                       never HEALTHY)
      reference unusable (unreachable, wrong chain, malformed)
                    -> UNKNOWN (check stays HEALTHY-eligible: a
                       broken PUBLIC REFERENCE must not fail a good
                       target)

The reference endpoints are fixed per-chain public read-only RPCs in
the contract code (REF_ENDPOINTS) — identical for all validators, so
the derived bucket is consensus-stable even though raw block numbers
differ between leader and validators. A negative delta (target ahead
of reference — load-balanced rotation) maps to CURRENT. STALE can
only fire when the reference is valid AND the target is >30 blocks
behind it.

CONSENSUS MODEL (deterministic equivalence)
===========================================
  leader_fn():    probes the target + reference; normalizes into a
                  fixed-schema observation; derives the
                  classification deterministically from the
                  normalized fields; returns the bound result.
  validator_fn(): INDEPENDENTLY probes the SAME target + reference,
                  normalizes + classifies exactly the same way, then
                  verifies the leader proposal against its OWN
                  observation:
                    * binding fields must match exactly
                      (schema_version, probe_version, check_id,
                       target_url, target_url_hash,
                       expected_chain_id);
                    * classification, failure_code, freshness bucket,
                      chain-id match, reachability, JSON-RPC
                      validity, client availability must match
                      exactly;
                    * observed_chain_id must match exactly;
                    * observed_block_number uses a tolerance window
                      (leader_block >= validator_block - 6): block
                      heights advance during the consensus round —
                      never equality;
                    * client_family must match exactly (a flapping
                      client identity across validators IS endpoint
                      inconsistency and rightly fails consensus).
                  Any mismatch => validator rejects. A lying or
                  mistaken leader cannot survive unless the endpoint
                  behaves identically for the validator.

Validators do NOT merely "agree with the leader": they re-derive
everything from their own probe and compare substance.

NO LLM IS USED. Every authoritative field is mechanically derived
from JSON-RPC responses. An LLM could only add hallucination risk
into authoritative state; deterministic structured consensus is the
correct tool here (README "Why no LLM").

URL SECURITY (SSRF-aware canonicalization) — documented rules
=============================================================
  1. Trim leading/trailing whitespace.
  2. Require "https://" scheme exactly (case-insensitive) — anything
     else refused.
  3. Reject embedded credentials ("user:pass@host").
  4. Reject query strings ("?...") and fragments ("#...") — a query
     string is a common carrier for tokens/API keys; RPC endpoints
     are path/address forms.
  5. Reject empty hosts, IPv4/IPv6 literals, "localhost",
     "*.localhost", and internal-sounding suffixes.
  6. Reject the request unless the port (if explicit) is 443 or 8443;
     an explicit ":443" is normalized away (it is the default HTTPS
     port and adds no information).
  7. Keep meaningful path components verbatim — a trailing "/" is
     NOT stripped: some providers treat "url" and "url/" differently,
     so the contract never silently transforms the endpoint.
  8. Lowercase the host; preserve percent-encoding verbatim.
  9. Length <= 200 characters.
 10. The canonical form + keccak-256 hash bind the consensus request;
     validators recompute both and reject on mismatch.

The GenVM network sandbox performs the actual fetch; these checks
are contract-layer defense-in-depth. NO secrets, API keys, or
credentials are ever accepted or stored. Users must submit only
public, read-only endpoints.

IMMUTABILITY BOUNDARY
=====================
A stored check result is bound to: check_id, canonical target URL,
target URL hash, expected chain id, and probe schema version. The
bound values are set ONLY at request time; every persisted record
re-binds them, and no update method exists. History is append-only.

PUBLIC LICENSE: MIT.
"""

import json
import re

from genlayer import *  # noqa: F401,F403
from genlayer.py.keccak import Keccak256  # GenVM std-lib primitive


# ---------------------------------------------------------------------------
# Constants — schema v1 (fixed, versioned, deterministic)
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "1"
PROBE_VERSION = "1"

# Classifications (canonical enum)
C_HEALTHY = "HEALTHY"
C_MISCONFIGURED = "MISCONFIGURED"
C_STALE = "STALE"
C_DEGRADED = "DEGRADED"
C_UNREACHABLE = "UNREACHABLE"
C_INCONSISTENT = "INCONSISTENT"
CLASSIFICATIONS = (
    C_HEALTHY, C_MISCONFIGURED, C_STALE, C_DEGRADED,
    C_UNREACHABLE, C_INCONSISTENT,
)

# Freshness buckets
B_CURRENT = "CURRENT"
B_SLIGHTLY_BEHIND = "SLIGHTLY_BEHIND"
B_STALE = "STALE"
B_UNKNOWN = "UNKNOWN"
B_AHEAD_ANOMALY = "AHEAD_ANOMALY"
BUCKETS = (
    B_CURRENT, B_SLIGHTLY_BEHIND, B_STALE, B_UNKNOWN, B_AHEAD_ANOMALY,
)
# Bucket families compared across probers: the CURRENT/SLIGHTLY_BEHIND
# boundary (delta 2 vs 3) can legitimately flip between leader and
# validator as both chains advance during the consensus round, so
# validators compare the FAMILY (fresh/not) plus classification —
# never the exact bucket at that boundary.
FRESH_FAMILY = (B_CURRENT, B_SLIGHTLY_BEHIND)

# Freshness thresholds (blocks behind the chain reference).
# Coarse by design: order-of-magnitude freshness, not real-time
# precision. 30 blocks ~ 6 min on 12s-chains; L2s are stricter.
FRESH_CURRENT_MAX = 2           # delta <= 2  -> CURRENT
FRESH_SLIGHTLY_BEHIND_MAX = 30  # delta <= 30 -> SLIGHTLY_BEHIND

# Cross-prober consensus stability: raw block heights are NEVER
# compared across probers (block time is 2s on L2s; a 45-90s consensus
# round legitimately shifts heights by tens of blocks). Instead the
# validator compares the leader's FRESHNESS DELTA (reference minus
# target, measured by each prober against the same fixed reference
# endpoint) inside a tolerance window, and the freshness BUCKET FAMILY.
CROSS_DELTA_TOLERANCE = 12
CROSS_BLOCK_TOLERANCE = 6  # retained for the within-prober sanity only

# Impossible-height guard: no major chain is near 2^40 (~1.1e12)
# blocks; a target or reference claiming more is rejected as
# implausible instead of passing freshness.
MAX_PLAUSIBLE_BLOCK = 2 ** 40
# Target far AHEAD of the reference beyond tolerance is a load-balance
# anomaly, not freshness: classify INCONSISTENT, never HEALTHY.
AHEAD_ANOMALY = 60

# Storage hygiene
MAX_CHECKS = 5000
MAX_HISTORY_PER_TARGET = 10

# Chain reference endpoints: chain_id -> public read-only reference
# RPC used ONLY as the freshness anchor. No keys, no auth. A chain
# without a reference entry gets bucket UNKNOWN (never fails a good
# target) and STALE can never fire for it.
REF_ENDPOINTS = {
    1: "https://ethereum-rpc.publicnode.com",
    8453: "https://base-rpc.publicnode.com",
    137: "https://polygon-bor-rpc.publicnode.com",
    42161: "https://arbitrum-rpc.publicnode.com",
    10: "https://optimism-rpc.publicnode.com",
    43114: "https://avalanche-c-chain-rpc.publicnode.com",
    11155111: "https://ethereum-sepolia-rpc.publicnode.com",
    84532: "https://base-sepolia-rpc.publicnode.com",
}

# URL refusal reason codes (machine-readable)
R_SCHEME = "url_scheme_not_https"
R_CREDS = "url_embedded_credentials"
R_QUERY = "url_query_not_allowed"
R_LOCAL = "url_localhost_not_allowed"
R_PRIVATE = "url_private_address_not_allowed"
R_PORT = "url_port_not_allowed"
R_MALFORMED = "url_malformed"
R_TOOLONG = "url_too_long"
R_HOSTEMPTY = "url_host_empty"
R_CHAIN = "expected_chain_id_invalid"

# Probe failure codes (normalized observation)
PR_OK = ""
PR_NETERR = "network_error"
PR_HTTP = "http_status_error"
PR_JSON = "invalid_json"
PR_SHAPE = "invalid_response_shape"
PR_RPCERR = "jsonrpc_error_response"
PR_RESULT = "missing_result"
PR_HEX = "malformed_hex_quantity"

# Classification failure codes (derived)
F_CHAIN_MISMATCH = "chain_id_mismatch"
F_CHAIN_FLAP = "chain_id_instability"
F_BLOCK_REGRESS = "block_regression"
F_STALE = "stale_block_height"
F_SECONDARY = "secondary_probe_unavailable"
F_AHEAD_ANOMALY = "implausible_height_ahead"


# Events — exactly one indexed positional field + str/int blob kwargs
# (EVENT_MAX_TOPICS=4: 1 signature topic + 3 indexed max)

class CheckRequestedEvent(gl.Event):
    def __init__(self, check_id: str, /, **blob): ...


class CheckFinalizedEvent(gl.Event):
    def __init__(self, check_id: str, /, **blob): ...


# ---------------------------------------------------------------------------
# Deterministic helpers (pure functions — identical on every node)
# ---------------------------------------------------------------------------

def _canon_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _keccak_hex(s):
    # Keccak-256 (UTF-8) hex — GenVM std-lib, identical on every node.
    return Keccak256(s.encode("utf-8")).hexdigest()


def _now_epoch():
    # Node-assigned ISO-8601 timestamp -> epoch seconds via Howard
    # Hinnant's days_from_civil (pure integer math). Used ONLY for
    # display/ordering — never consensus-compared.
    s = str(gl.message_raw["datetime"])
    y = int(s[0:4]); m = int(s[5:7]); d = int(s[8:10])
    hh = int(s[11:13]); mm = int(s[14:16]); ss = int(s[17:19])
    y2 = y - (1 if m <= 2 else 0)
    era = (y2 if y2 >= 0 else y2 - 399) // 400
    yoe = y2 - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return days * 86400 + hh * 3600 + mm * 60 + ss


# ---------------------------------------------------------------------------
# URL canonicalization (SSRF-aware) — implementation of documented rules
# ---------------------------------------------------------------------------

_RE_HOST = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_RE_HOST_SINGLE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_RE_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_RE_IPV6 = re.compile(r"^\[[0-9a-fA-F:]+\]$")
_RE_BAD_SUFFIX = re.compile(
    r"(^|\.)(localhost|local|internal|intranet|corp|lan|home)$",
    re.IGNORECASE,
)


def _canonicalize_url(raw: str):
    """(canonical_url, url_hash) or raises gl.vm.UserError with a
    machine-readable reason code. Pure; validators recompute."""
    if not isinstance(raw, str):
        raise gl.vm.UserError(R_MALFORMED)
    s = raw.strip()
    if len(s) < 9 or len(s) > 200:
        raise gl.vm.UserError(R_TOOLONG)
    if not s.lower().startswith("https://"):
        raise gl.vm.UserError(R_SCHEME)
    s = s[len("https://"):]
    if "@" in s:
        raise gl.vm.UserError(R_CREDS)
    if "?" in s or "#" in s:
        raise gl.vm.UserError(R_QUERY)
    slash = s.find("/")
    hostport = s if slash == -1 else s[:slash]
    path = "" if slash == -1 else s[slash:]
    if hostport.startswith("[") or _RE_IPV6.match(hostport):
        raise gl.vm.UserError(R_PRIVATE)
    port = ""
    if ":" in hostport:
        hp = hostport.rsplit(":", 1)
        if len(hp) != 2 or not hp[1].isdigit():
            raise gl.vm.UserError(R_MALFORMED)
        p = int(hp[1])
        if p not in (443, 8443):
            raise gl.vm.UserError(R_PORT)
        host = hp[0]
        if p == 8443:
            port = ":8443"
        # p == 443: default HTTPS port, normalized away
    else:
        host = hostport
    if host == "":
        raise gl.vm.UserError(R_HOSTEMPTY)
    host = host.lower()
    if _RE_IPV4.match(host):
        # ALL IPv4 literals refused (public OR private): the product
        # probes public DNS-named endpoints, not raw IPs.
        raise gl.vm.UserError(R_PRIVATE)
    if host == "localhost" or host.endswith(".localhost"):
        raise gl.vm.UserError(R_LOCAL)
    # search, not match: the bad token may start at a dot anywhere
    # (match() anchors at position 0 and let "node.internal" through)
    if _RE_BAD_SUFFIX.search(host):
        raise gl.vm.UserError(R_LOCAL)
    if not (_RE_HOST.match(host) or _RE_HOST_SINGLE.match(host)):
        raise gl.vm.UserError(R_MALFORMED)
    canonical = "https://" + host + port + path
    return canonical, _keccak_hex(canonical)


def _validate_chain_id(v) -> int:
    """Expected chain id: 1..2**31-1 (EVM chain ids fit comfortably).
    Accepts the canonical str form (ABI) or int (internal calls);
    bools are rejected explicitly."""
    if isinstance(v, bool):
        raise gl.vm.UserError(R_CHAIN)
    if isinstance(v, int):
        n = v
    elif isinstance(v, str):
        s = v.strip()
        if not re.fullmatch(r"[0-9]+", s):
            raise gl.vm.UserError(R_CHAIN)
        n = int(s)
    else:
        raise gl.vm.UserError(R_CHAIN)
    if n < 1 or n > 2**31 - 1:
        raise gl.vm.UserError(R_CHAIN)
    return n


# ---------------------------------------------------------------------------
# JSON-RPC probe machinery (runs INSIDE leader/validator only)
# ---------------------------------------------------------------------------

def _rpc_call(url: str, method: str, params: list):
    """One JSON-RPC POST. Returns (ok, code, result_or_none).
    Never raises — every failure maps to a machine-readable code.
    A response is valid ONLY if the JSON body has the expected
    JSON-RPC 2.0 shape; HTTP 200 alone proves nothing."""
    payload = _canon_json(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    )
    try:
        resp = gl.nondet.web.post(
            url,
            body=payload,
            headers={"Content-Type": "application/json"},
        )
    except Exception:
        return False, PR_NETERR, None
    try:
        status = int(resp.status)
    except Exception:
        return False, PR_NETERR, None
    if status < 200 or status > 299:
        return False, PR_HTTP, None
    try:
        body = resp.body
        if body is None:
            return False, PR_JSON, None
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        doc = json.loads(body)
    except Exception:
        return False, PR_JSON, None
    if not isinstance(doc, dict):
        return False, PR_SHAPE, None
    if doc.get("error") is not None:
        return False, PR_RPCERR, None
    if "result" not in doc:
        return False, PR_RESULT, None
    return True, PR_OK, doc["result"]


def _hex_to_int_loose(h):
    """0x-hex quantity -> int; leading zeros tolerated. None on any
    malformed input. (eth_chainId/eth_blockNumber quantities.)"""
    if not isinstance(h, str) or not h.startswith("0x") or len(h) < 3:
        return None
    try:
        return int(h[2:], 16)
    except ValueError:
        return None


def _net_version_to_int(v):
    """net_version returns a DECIMAL string (occasionally hex).
    Strictly numeric only; None otherwise."""
    if not isinstance(v, str):
        return None
    s = v.strip()
    if s.lower().startswith("0x"):
        try:
            return int(s[2:], 16)
        except ValueError:
            return None
    if re.fullmatch(r"[0-9]+", s):
        return int(s)
    return None


def _client_family(client_str):
    """Coarse client-family token from web3_clientVersion. Lowercase
    alphabetic token; empty when unavailable."""
    if not isinstance(client_str, str):
        return ""
    t = client_str.strip().lower()
    for fam in (
        "op-reth", "reth", "geth", "nethermind", "besu", "erigon",
        "openethereum", "parity", "bor", "nitro", "cloudflare-ethereum",
        "ganache", "anvil", "hardhat",
    ):
        if t.startswith(fam):
            return fam
    m = re.match(r"^[a-z][a-z0-9-]*", t)
    return m.group(0) if m else ""


# ---------------------------------------------------------------------------
# Probe pipeline — leader AND every validator run EXACTLY this
# ---------------------------------------------------------------------------

def _probe_endpoint(target_url: str, expected_chain_id: int) -> dict:
    """The full 9-request probe plan -> NORMALIZED OBSERVATION (v1).

    Consensus-stability design:
      * identity fields (chain id, client family) — exact compare;
      * block number — tolerance compare (never equality);
      * freshness bucket — derived from OWN paired observation, so
        elapsed consensus time cancels out;
      * no timestamps in any consensus-compared field.
    """
    # ---- primary probes (each twice) ----
    ok1, code1, chain1 = _rpc_call(target_url, "eth_chainId", [])
    ok2, code2, chain2 = _rpc_call(target_url, "eth_chainId", [])
    ok3, code3, blk1 = _rpc_call(target_url, "eth_blockNumber", [])
    ok4, code4, blk2 = _rpc_call(target_url, "eth_blockNumber", [])

    # ---- chain id normalization ----
    observed_chain_id = None
    c1v = _hex_to_int_loose(chain1) if ok1 else None
    c2v = _hex_to_int_loose(chain2) if ok2 else None
    if c1v is not None:
        observed_chain_id = c1v
    elif c2v is not None:
        observed_chain_id = c2v
    chain_code = PR_OK
    if observed_chain_id is None:
        if not ok1 and not ok2:
            chain_code = code1
        else:
            chain_code = PR_HEX
    chain_id_instability = (
        c1v is not None and c2v is not None and c1v != c2v
    )

    # ---- block number normalization ----
    b1 = _hex_to_int_loose(blk1) if ok3 else None
    b2 = _hex_to_int_loose(blk2) if ok4 else None
    blocks = [b for b in (b1, b2) if b is not None]
    observed_block = blocks[0] if blocks else None
    block_code = PR_OK
    if not ok3 and not ok4:
        block_code = code3
    elif b1 is None and b2 is None:
        block_code = PR_HEX
        observed_block = None
    block_regression = (
        b1 is not None and b2 is not None and b2 < b1
    )
    if block_regression:
        block_code = F_BLOCK_REGRESS
        observed_block = None
    block_number_valid = (
        observed_block is not None and block_code == PR_OK
    )
    # impossible height: block 0 on a major PoS chain (probe sanity)
    if block_number_valid and observed_block == 0 and \
            expected_chain_id in (1, 10, 137, 42161, 8453, 43114):
        block_number_valid = False
        block_code = PR_HEX
        observed_block = None

    # ---- reachability / validity flags ----
    primary_ok = ok1 and ok2 and ok3 and ok4
    reachable = primary_ok
    jsonrpc_valid = primary_ok
    chain_id_match = (
        observed_chain_id is not None
        and observed_chain_id == expected_chain_id
    )

    # ---- optional secondary probes ----
    ok5, code5, netv = _rpc_call(target_url, "net_version", [])
    net_version_ok = ok5 and _net_version_to_int(netv) is not None
    nv = _net_version_to_int(netv) if ok5 else None
    net_version_agrees = (
        net_version_ok and observed_chain_id is not None
        and nv == observed_chain_id
    )
    ok6, code6, client = _rpc_call(target_url, "web3_clientVersion", [])
    client_available = (
        ok6 and isinstance(client, str) and len(client.strip()) > 0
    )
    client_fam = _client_family(client) if client_available else ""

    # ---- reference endpoint (freshness anchor) ----
    ref_url = REF_ENDPOINTS.get(expected_chain_id, "")
    ref_block = None
    ref_valid = False
    if ref_url != "":
        rok, _rc, rchain = _rpc_call(ref_url, "eth_chainId", [])
        rok2, _rc2, rblk = _rpc_call(ref_url, "eth_blockNumber", [])
        rchainv = _hex_to_int_loose(rchain) if rok else None
        rblkv = _hex_to_int_loose(rblk) if rok2 else None
        ref_valid = (
            rchainv is not None and rchainv == expected_chain_id
            and rblkv is not None and rblkv <= MAX_PLAUSIBLE_BLOCK
        )
        if rblkv is not None:
            ref_block = rblkv

    # impossible target height: no major chain is near 2^40 blocks
    if observed_block is not None and observed_block > MAX_PLAUSIBLE_BLOCK:
        observed_block = None
        block_number_valid = False
        block_code = PR_HEX

    delta = None
    if ref_valid and observed_block is not None:
        delta = ref_block - observed_block
    bucket = B_UNKNOWN
    if delta is not None:
        if delta < -AHEAD_ANOMALY:
            # target implausibly far AHEAD of the chain reference —
            # a load-balance anomaly (or a lying endpoint), never
            # freshness. Not HEALTHY-eligible.
            bucket = B_AHEAD_ANOMALY
        elif delta < 0:
            bucket = B_CURRENT  # target ahead within tolerance:
                                # normal load-balanced rotation
        elif delta <= FRESH_CURRENT_MAX:
            bucket = B_CURRENT
        elif delta <= FRESH_SLIGHTLY_BEHIND_MAX:
            bucket = B_SLIGHTLY_BEHIND
        else:
            bucket = B_STALE

    # ---- deterministic classification ladder (first match wins) ----
    classification = C_HEALTHY
    failure_code = PR_OK

    if not primary_ok:
        fcode = (
            code1 if not ok1 else
            code2 if not ok2 else
            code3 if not ok3 else code4
        )
        classification = C_UNREACHABLE
        failure_code = fcode
    elif chain_id_instability:
        classification = C_INCONSISTENT
        failure_code = F_CHAIN_FLAP
    elif observed_chain_id is None:
        classification = C_UNREACHABLE
        failure_code = chain_code
    elif block_regression:
        classification = C_INCONSISTENT
        failure_code = F_BLOCK_REGRESS
    elif not chain_id_match:
        classification = C_MISCONFIGURED
        failure_code = F_CHAIN_MISMATCH
    elif not block_number_valid:
        classification = C_UNREACHABLE
        failure_code = block_code
    elif bucket == B_AHEAD_ANOMALY:
        classification = C_INCONSISTENT
        failure_code = F_AHEAD_ANOMALY
    elif bucket == B_STALE:
        classification = C_STALE
        failure_code = F_STALE
    elif (not net_version_ok) or (net_version_ok and not net_version_agrees):
        classification = C_DEGRADED
        failure_code = F_SECONDARY
    elif not client_available:
        classification = C_DEGRADED
        failure_code = F_SECONDARY
    # else HEALTHY

    return {
        # binding
        "schema_version": SCHEMA_VERSION,
        "probe_version": PROBE_VERSION,
        "target_url": target_url,
        "target_url_hash": _keccak_hex(target_url),
        "expected_chain_id": expected_chain_id,
        # normalized evidence
        "rpc_reachable": reachable,
        "jsonrpc_valid": jsonrpc_valid,
        "observed_chain_id": observed_chain_id,
        "chain_id_match": chain_id_match,
        "observed_block_number": observed_block,
        "block_number_valid": block_number_valid,
        "freshness_bucket": bucket,
        "freshness_delta": delta,
        "net_version_ok": net_version_ok,
        "net_version_agrees": net_version_agrees,
        "client_available": client_available,
        "client_family": client_fam,
        # verdict
        "classification": classification,
        "failure_code": failure_code,
    }


# ---------------------------------------------------------------------------
# Equivalence — validator independently re-derives and compares
# ---------------------------------------------------------------------------

def _obs_substance(obs: dict):
    """The consensus-compared substance of a normalized observation:
    everything EXCEPT the time-varying block fields (raw height and
    derived delta advance during the consensus round) and the exact
    freshness bucket (compared by FAMILY — the CURRENT/
    SLIGHTLY_BEHIND boundary can legitimately flip)."""
    keys = (
        "schema_version", "probe_version", "target_url",
        "target_url_hash", "expected_chain_id", "rpc_reachable",
        "jsonrpc_valid", "observed_chain_id", "chain_id_match",
        "block_number_valid", "net_version_ok",
        "net_version_agrees", "client_available", "client_family",
        "classification", "failure_code",
    )
    return _canon_json({k: obs.get(k) for k in keys})


def _bucket_family(b):
    if b in FRESH_FAMILY:
        return "FRESH"
    return b  # STALE / UNKNOWN / AHEAD_ANOMALY compare exactly


def _validator_observation_matches(mine: dict, leader: dict) -> bool:
    """Exact match on all binding + identity + verdict fields;
    bounded tolerance on the time-varying block measurements."""
    # 1) binding — the result belongs to THIS exact request
    for k in ("schema_version", "probe_version", "target_url",
              "target_url_hash", "expected_chain_id"):
        if mine.get(k) != leader.get(k):
            return False
    # 2) type sanity on the leader's persisted-shape fields
    loc = leader.get("observed_chain_id")
    if loc is not None and (
        isinstance(loc, bool) or not isinstance(loc, int)
    ):
        return False
    if leader.get("classification") not in CLASSIFICATIONS:
        return False
    if leader.get("freshness_bucket") not in BUCKETS:
        return False
    # 3) verdict + identity substance must match exactly
    if _obs_substance(mine) != _obs_substance(leader):
        return False
    # 4) freshness: bucket FAMILY must match (exact bucket can flip
    #    at the CURRENT/SLIGHTLY_BEHIND boundary mid-round)
    if _bucket_family(mine.get("freshness_bucket")) != \
            _bucket_family(leader.get("freshness_bucket")):
        return False
    # 5) block fields — never raw equality. Both probers measure the
    #    same quantity (reference minus target) against the same
    #    fixed reference endpoints; the measurement is stable even
    #    though both heights advance. Tolerance covers chain drift
    #    between the two measurement instants.
    mb = mine.get("observed_block_number")
    lb = leader.get("observed_block_number")
    if (mb is None) != (lb is None):
        return False
    md = mine.get("freshness_delta")
    ld = leader.get("freshness_delta")
    if (md is None) != (ld is None):
        return False
    if md is not None:
        if ld < md - CROSS_DELTA_TOLERANCE:
            return False   # leader measured implausibly more stale
        if ld > md + CROSS_DELTA_TOLERANCE:
            return False   # leader measured implausibly fresher
    # (raw heights are NOT compared: see CROSS_DELTA_TOLERANCE docs)
    return True


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------

class RpcSentinel(gl.Contract):
    """Decentralized RPC integrity monitor. See module docstring."""

    # storage: uniform TreeMap[str, str] (gltest/GenVM best practice)
    checks: TreeMap[str, str]                 # check_id -> check JSON
    history: TreeMap[str, str]                # url_hash -> ids (<=10)
    latest_by_target: TreeMap[str, str]       # url_hash -> check_id
    meta: TreeMap[str, str]                   # counters/config

    def __init__(self):
        self.checks = TreeMap()
        self.history = TreeMap()
        self.latest_by_target = TreeMap()
        self.meta = TreeMap()
        self.meta["next_check_id"] = "1"
        self.meta["check_count"] = "0"
        self.meta["finalized_count"] = "0"
        self.meta["consensus_failed_count"] = "0"
        self.meta["schema_version"] = SCHEMA_VERSION
        self.meta["probe_version"] = PROBE_VERSION

    # ------------------------------------------------------------------
    # request_check — deterministic request recording (state:
    # REQUESTED). No probing happens here.
    # ------------------------------------------------------------------

    @gl.public.write
    def request_check(self, target_url: str, expected_chain_id: str) -> str:
        """Register an integrity check request. Returns check_id.
        The canonical URL + hash + expected chain id are bound at
        request time and never change. Consensus runs separately in
        run_consensus()."""
        if int(self.meta["check_count"]) >= MAX_CHECKS:
            raise gl.vm.UserError("check_limit_reached")
        canonical, url_hash = _canonicalize_url(target_url)
        chain_id = _validate_chain_id(expected_chain_id)
        seq = int(self.meta["next_check_id"])
        check_id = "chk-%d" % seq
        now = _now_epoch()
        check = {
            "check_id": check_id,
            "seq": str(seq),
            "target_url": canonical,
            "target_url_hash": url_hash,
            "expected_chain_id": str(chain_id),
            "schema_version": SCHEMA_VERSION,
            "probe_version": PROBE_VERSION,
            "status": "REQUESTED",       # REQUESTED -> CONSENSUS_RUN
                                          # -> FINALIZED |
                                          #    CONSENSUS_FAILED
            "classification": "",
            "failure_code": "",
            "freshness_bucket": "",
            "observed_chain_id": "",
            "observed_block_number": "",
            "jsonrpc_valid": "",
            "rpc_reachable": "",
            "client_family": "",
            "requested_by": str(gl.message.sender_address),
            "requested_at": str(now),
            "finalized_at": "",
            "consensus_rounds": "",
            "consensus_error": "",
        }
        self.checks[check_id] = json.dumps(check)
        self.meta["next_check_id"] = str(seq + 1)
        self.meta["check_count"] = str(int(self.meta["check_count"]) + 1)
        CheckRequestedEvent(
            check_id,
            target_url_hash=url_hash,
            expected_chain_id=str(chain_id),
            canonical_host=canonical.split("/")[2],
        ).emit()
        return check_id

    # ------------------------------------------------------------------
    # run_consensus — the nondeterministic probe round. Persists the
    # consensus-verified result ONLY on majority agreement.
    # ------------------------------------------------------------------

    @gl.public.write
    def run_consensus(self, check_id: str) -> str:
        """Run the GenLayer consensus probe round for a REQUESTED
        check. Returns check_id. On majority-agree the FINALIZED
        normalized observation is persisted; on consensus failure the
        check transitions to CONSENSUS_FAILED and NOTHING from the
        leader is persisted."""
        raw = self.checks.get(str(check_id), "")
        if raw == "":
            raise gl.vm.UserError("check_not_found")
        check = json.loads(raw)
        if check["status"] not in ("REQUESTED", "CONSENSUS_FAILED"):
            raise gl.vm.UserError("check_not_pending")
        # Copy to plain values BEFORE the nondeterministic boundary —
        # no storage access inside leader/validator.
        target_url = check["target_url"]
        url_hash = check["target_url_hash"]
        expected_chain_id = int(check["expected_chain_id"])
        check_id_val = check["check_id"]

        def leader_fn() -> dict:
            try:
                obs = _probe_endpoint(target_url, expected_chain_id)
                return {
                    "check_id": check_id_val,
                    "url_hash": url_hash,
                    "observation": obs,
                }
            except Exception:
                return {
                    "check_id": check_id_val,
                    "url_hash": url_hash,
                    "observation": None,
                }

        def validator_fn(leader_res) -> bool:
            try:
                if not isinstance(leader_res, gl.vm.Return):
                    return False
                ld = leader_res.calldata
                if not isinstance(ld, dict):
                    return False
                if ld.get("check_id") != check_id_val:
                    return False
                if ld.get("url_hash") != url_hash:
                    return False
                leader_obs = ld.get("observation")
                if not isinstance(leader_obs, dict):
                    return False
                mine = _probe_endpoint(target_url, expected_chain_id)
                return _validator_observation_matches(mine, leader_obs)
            except Exception:
                return False

        result = gl.vm.run_nondet(leader_fn, validator_fn)

        # ---- deterministic post-consensus persistence ----
        # NO unverified promotion: run_nondet returning a value means
        # majority-agree on the leader's proposal AND the captured
        # validators re-derived a matching observation. Even so, the
        # persisted record re-checks every binding field.
        if not isinstance(result, dict):
            self._mark_consensus_failed(
                check_id_val, "result_shape_invalid")
            return check_id_val
        obs = result.get("observation")
        if not isinstance(obs, dict):
            self._mark_consensus_failed(
                check_id_val, "observation_shape_invalid")
            return check_id_val
        # binding re-verification before ANY persistence
        if result.get("check_id") != check_id_val:
            self._mark_consensus_failed(
                check_id_val, "check_id_mismatch")
            return check_id_val
        if result.get("url_hash") != url_hash:
            self._mark_consensus_failed(
                check_id_val, "url_hash_mismatch")
            return check_id_val
        if obs.get("target_url") != target_url:
            self._mark_consensus_failed(
                check_id_val, "url_mismatch")
            return check_id_val
        if obs.get("target_url_hash") != url_hash:
            self._mark_consensus_failed(
                check_id_val, "url_hash_mismatch")
            return check_id_val
        if obs.get("expected_chain_id") != expected_chain_id:
            self._mark_consensus_failed(
                check_id_val, "expected_chain_id_mismatch")
            return check_id_val
        if obs.get("schema_version") != SCHEMA_VERSION:
            self._mark_consensus_failed(
                check_id_val, "schema_version_mismatch")
            return check_id_val
        if obs.get("probe_version") != PROBE_VERSION:
            self._mark_consensus_failed(
                check_id_val, "probe_version_mismatch")
            return check_id_val
        if obs.get("classification") not in CLASSIFICATIONS:
            self._mark_consensus_failed(
                check_id_val, "classification_invalid")
            return check_id_val
        if obs.get("freshness_bucket") not in BUCKETS:
            self._mark_consensus_failed(
                check_id_val, "bucket_invalid")
            return check_id_val

        check = json.loads(self.checks[check_id_val])
        check["status"] = "FINALIZED"
        check["classification"] = obs["classification"]
        check["failure_code"] = str(obs["failure_code"])
        check["freshness_bucket"] = obs["freshness_bucket"]
        check["observed_chain_id"] = (
            "" if obs["observed_chain_id"] is None
            else str(obs["observed_chain_id"])
        )
        check["observed_block_number"] = (
            "" if obs["observed_block_number"] is None
            else str(obs["observed_block_number"])
        )
        check["jsonrpc_valid"] = str(bool(obs["jsonrpc_valid"])).lower()
        check["rpc_reachable"] = str(bool(obs["rpc_reachable"])).lower()
        check["client_family"] = str(obs.get("client_family", ""))
        check["net_version_ok"] = str(
            bool(obs.get("net_version_ok"))).lower()
        check["net_version_agrees"] = str(
            bool(obs.get("net_version_agrees"))).lower()
        check["client_available"] = str(
            bool(obs.get("client_available"))).lower()
        check["finalized_at"] = str(_now_epoch())
        self.checks[check_id_val] = json.dumps(check)
        # append-only history + latest pointer
        prev = self.history.get(url_hash, "")
        ids = [x for x in prev.split(",") if x != ""]
        ids.append(check_id_val)
        if len(ids) > MAX_HISTORY_PER_TARGET:
            ids = ids[-MAX_HISTORY_PER_TARGET:]
        self.history[url_hash] = ",".join(ids)
        self.latest_by_target[url_hash] = check_id_val
        self.meta["finalized_count"] = str(
            int(self.meta["finalized_count"]) + 1)
        CheckFinalizedEvent(
            check_id_val,
            classification=obs["classification"],
            failure_code=str(obs["failure_code"]),
            target_url_hash=url_hash,
            freshness_bucket=obs["freshness_bucket"],
        ).emit()
        return check_id_val

    def _mark_consensus_failed(self, check_id: str, reason: str):
        check = json.loads(self.checks[check_id])
        check["status"] = "CONSENSUS_FAILED"
        check["consensus_error"] = reason
        check["finalized_at"] = str(_now_epoch())
        self.checks[check_id] = json.dumps(check)
        self.meta["consensus_failed_count"] = str(
            int(self.meta["consensus_failed_count"]) + 1)
        CheckFinalizedEvent(
            check_id,
            classification="",
            failure_code="",
            target_url_hash=check["target_url_hash"],
            freshness_bucket="",
            consensus_failed=reason,
        ).emit()

    # ------------------------------------------------------------------
    # Views
    # ------------------------------------------------------------------

    @gl.public.view
    def get_check(self, check_id: str) -> str:
        """Full check record (JSON). Includes every binding field and
        the consensus status. Leader-only data is never exposed as
        authoritative: fields are empty until FINALIZED."""
        raw = self.checks.get(str(check_id), "")
        if raw == "":
            raise gl.vm.UserError("check_not_found")
        return raw

    @gl.public.view
    def get_check_by_target(self, target_url: str) -> str:
        """Latest check for a canonical target URL (JSON) or the
        'not found' marker."""
        canonical, url_hash = _canonicalize_url(target_url)
        cid = self.latest_by_target.get(url_hash, "")
        if cid == "":
            return json.dumps({"found": False})
        return json.dumps({"found": True, "check": json.loads(
            self.checks[cid])})

    @gl.public.view
    def get_history(self, target_url: str) -> str:
        """History of finalized checks for a target (JSON array)."""
        canonical, url_hash = _canonicalize_url(target_url)
        raw = self.history.get(url_hash, "")
        ids = [x for x in raw.split(",") if x != ""]
        out = []
        for cid in ids:
            rec = json.loads(self.checks[cid])
            if rec["status"] == "FINALIZED":
                out.append({
                    "check_id": rec["check_id"],
                    "classification": rec["classification"],
                    "observed_chain_id": rec["observed_chain_id"],
                    "freshness_bucket": rec["freshness_bucket"],
                    "finalized_at": rec["finalized_at"],
                })
        return json.dumps(out)

    @gl.public.view
    def get_recent_checks(self, limit: int) -> str:
        """Most recent checks (all statuses), newest first, for the
        public history view. limit capped at 50."""
        if isinstance(limit, str):
            n = int(limit) if limit.strip().isdigit() else 10
        elif isinstance(limit, int):
            n = limit
        else:
            n = 10
        if n < 1:
            n = 1
        if n > 50:
            n = 50
        total = int(self.meta["check_count"])
        out = []
        seq = int(self.meta["next_check_id"]) - 1
        while len(out) < n and seq >= 1:
            cid = "chk-%d" % seq
            raw = self.checks.get(cid, "")
            if raw != "":
                rec = json.loads(raw)
                out.append({
                    "check_id": rec["check_id"],
                    "target_host": rec["target_url"].split("/")[2],
                    "target_url": rec["target_url"],
                    "expected_chain_id": rec["expected_chain_id"],
                    "status": rec["status"],
                    "classification": rec["classification"],
                    "freshness_bucket": rec["freshness_bucket"],
                    "finalized_at": rec["finalized_at"],
                })
            seq -= 1
        return json.dumps(out)

    @gl.public.view
    def get_stats(self) -> str:
        """Aggregate counters."""
        return json.dumps({
            "check_count": self.meta["check_count"],
            "finalized_count": self.meta["finalized_count"],
            "consensus_failed_count":
                self.meta["consensus_failed_count"],
            "schema_version": self.meta["schema_version"],
            "probe_version": self.meta["probe_version"],
        })

    @gl.public.view
    def get_config(self) -> str:
        """Public, deterministic probe configuration (transparency):
        freshness thresholds, tolerance, reference endpoints, probe
        plan, classification rules summary."""
        refs = {str(k): v for k, v in REF_ENDPOINTS.items()}
        return json.dumps({
            "fresh_current_max": FRESH_CURRENT_MAX,
            "fresh_slightly_behind_max": FRESH_SLIGHTLY_BEHIND_MAX,
            "cross_block_tolerance": CROSS_BLOCK_TOLERANCE,
            "reference_endpoints": refs,
            "schema_version": SCHEMA_VERSION,
            "probe_version": PROBE_VERSION,
            "classifications": list(CLASSIFICATIONS),
            "buckets": list(BUCKETS),
        })
