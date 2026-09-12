# RPC Sentinel

**Consensus-backed integrity checks for blockchain RPC endpoints.**

RPC Sentinel is a GenLayer Intelligent Contract + public dApp that
answers ONE narrow, objectively demonstrable question:

> Does this public blockchain RPC endpoint currently behave
> consistently with the expected blockchain network and basic
> JSON-RPC integrity requirements?

It does **not** try to prove that an RPC provider is honest or
malicious. It does not guarantee an endpoint stays healthy after a
check, and it does not claim any endpoint is canonical.

---

## Why this needs GenLayer (and not a normal monitor)

Crypto applications routinely trust a single centralized RPC
response. A frontend developer has no neutral way to ask "is this
endpoint actually serving the chain I think it is, right now?" —
any answer from the provider itself is self-reported.

Traditional monitoring:

```
User
 |
 v
Centralized monitoring server        <-- YOU must trust this server
 |
 v
RPC endpoint
```

RPC Sentinel:

```
User
 |
 v
GenLayer Intelligent Contract
 |
 +--> Validator A --probes--> RPC endpoint
 +--> Validator B --probes--> RPC endpoint
 +--> Validator C --probes--> RPC endpoint
 |
 v
Consensus-approved normalized observation   <-- only this persists
 |
 v
Authoritative check result
```

GenLayer validators **independently** probe the same public RPC
endpoint over JSON-RPC, normalize their observations into a fixed
schema, and only a consensus-approved normalized observation becomes
the authoritative on-chain check result. A leader proposal is never
persisted on its own.

This is a real GenLayer use case because external network data is
nondeterministic (block heights advance between requests, endpoints
flap) — the contract is explicitly designed so that validators can
independently reproduce the observation and agree on the substance.

---

## How it works

### 1. Request (deterministic, on-chain)

Anyone calls `request_check(target_url, expected_chain_id)`:

* the URL is canonicalized through an SSRF-aware rule set
  (HTTPS-only, no credentials, no query strings, no localhost /
  internal suffixes / raw IP literals, ports 443/8443 only);
* the canonical URL + its Keccak-256 hash + the expected chain id
  are **bound** to the check and never change;
* the check is recorded as `REQUESTED`. Nothing is probed yet.

### 2. Consensus probe round (nondeterministic)

`run_consensus(check_id)` runs the GenLayer leader/validator pattern:

* **leader_fn** executes the probe plan and returns a strictly
  structured, request-bound normalized observation;
* **validator_fn** does NOT "agree with the leader" — it
  **independently executes the same probe plan**, re-derives the
  classification, and compares the leader's proposal against its OWN
  observation.

**Probe plan** (identical for every prober — 8 JSON-RPC requests):

| # | Method | Role |
|---|--------|------|
| P1, P2 | `eth_chainId` (x2) | primary + stability |
| P3, P4 | `eth_blockNumber` (x2) | primary + stability |
| P5 | `net_version` | optional secondary |
| P6 | `web3_clientVersion` | optional secondary |
| R1, R2 | `eth_chainId`, `eth_blockNumber` on the chain **reference endpoint** | freshness anchor |

A response is valid only if the JSON-RPC body has the expected
shape — HTTP 200 alone proves nothing. Every failure mode (HTTP
error, transport error, invalid JSON, JSON-RPC error object,
missing `result`, malformed hex) maps to a machine-readable code.

### 3. Classification (deterministic ladder, first match wins)

| Classification | Deterministic rule |
|----------------|-------------------|
| `UNREACHABLE` | any primary probe failed to yield a valid JSON-RPC result |
| `INCONSISTENT` | the endpoint's own repeated responses conflict (alternating chain ids, regressing blocks, implausible height ahead of the chain reference) |
| `MISCONFIGURED` | reachable + valid, but observed chain id != expected |
| `STALE` | chain matches, block valid, but far behind the chain reference |
| `DEGRADED` | primaries pass, an optional secondary is unavailable/abnormal |
| `HEALTHY` | everything passes and freshness is CURRENT/SLIGHTLY_BEHIND |

### 4. Freshness policy (the consensus-critical part)

Block heights are time-sensitive: they are **never compared for
equality across probers**. Each prober derives a freshness bucket
from its own paired observation against a fixed public reference
endpoint:

```
delta = reference_block - target_block
  delta <= 2    -> CURRENT
  delta <= 30   -> SLIGHTLY_BEHIND
  otherwise     -> STALE
  delta < -60   -> AHEAD_ANOMALY (implausible: INCONSISTENT, never HEALTHY)
  reference unusable -> UNKNOWN (a broken public reference must not fail a good target)
```

Validators compare **derived substance, never raw values**:

* binding fields (schema version, probe version, check id, target
  URL, URL hash, expected chain id) — exact match;
* classification, failure code, observed chain id, client family —
  exact match;
* **freshness delta** — tolerance window (±12), because both
  heights advance during the consensus round;
* **freshness bucket family** (CURRENT/SLIGHTLY_BEHIND are one
  "fresh" family) — the 2-vs-3 boundary can legitimately flip
  mid-round.

### 5. Persistence (no unverified state promotion)

```
REQUESTED -> CONSENSUS_EVALUATION -> CONSENSUS_VERIFIED_RESULT -> PERSISTED_CHECK
                                   \-> CONSENSUS_FAILED (nothing from the leader persists)
```

Even after `run_nondet` returns, the contract re-verifies every
binding field before ANY persistence. History is append-only; check
results are immutable. The frontend shows "Consensus pending" until
finalized — leader-only data is never displayed as authoritative.

### Why no LLM

Every authoritative field is mechanically derived from JSON-RPC
responses. An LLM could only add hallucination risk into
authoritative state; deterministic structured consensus is the
correct tool for a binary-integrity question. GenLayer's value here
is the **independent multi-validator probe + consensus**, not
language reasoning.

---

## Security

* RPC URLs are untrusted input: SSRF-aware canonicalization rejects
  localhost, loopback, RFC1918/link-literal forms, internal-suffix
  hosts, non-HTTPS schemes, embedded credentials, query strings
  (token carriers), raw IP literals, and non-(443|8443) ports.
* No port scanning, no arbitrary redirects, no user-controlled
  headers. The contract performs exactly the 8-request probe plan.
* Users must submit **public, read-only** RPC endpoints only. No
  API keys, secrets, or credentials are ever accepted or stored.
* Reference endpoints are fixed public read-only RPCs compiled into
  the contract (identical for all validators).

Full rule documentation: `contracts/rpc_sentinel.py` module docstring.

---

## Contract interface

| Method | Type | Purpose |
|--------|------|---------|
| `request_check(target_url, expected_chain_id)` | write | register a check (binds canonical URL + hash + chain id) |
| `run_consensus(check_id)` | write | execute the consensus probe round |
| `get_check(check_id)` | view | full check record incl. binding fields |
| `get_check_by_target(target_url)` | view | latest check for a target |
| `get_history(target_url)` | view | finalized checks for a target (append-only) |
| `get_recent_checks(limit)` | view | public history feed |
| `get_stats()` | view | aggregate counters |
| `get_config()` | view | deterministic probe configuration (transparency) |

Storage is minimal: check records + history index + counters, all
values small strings/JSON. No raw RPC bodies are stored.

---

## Repository layout

```
contracts/rpc_sentinel.py     the Intelligent Contract
tests/direct/                 98 direct-mode tests (units, consensus,
                              adversarial leader-forgery, SSRF/security,
                              regressions)
frontend/                     public dApp (GitHub Pages)
scripts/                      deployment + smoke-test harnesses
docs/                         evidence logs, submission draft
```

## Testing

```
pip install genlayer-test==0.29.2 pytest
python -m pytest tests/direct/ -q
```

All RPC responses in tests are served by an in-process scripted
router — no test touches a live network. CI runs the same suite on
a clean runner plus `genvm-lint`.

## License

MIT.
