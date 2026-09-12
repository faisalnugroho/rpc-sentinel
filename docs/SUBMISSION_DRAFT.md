# RPC Sentinel — GenLayer Portal Submission Draft

**Contract**: RPC Sentinel — Decentralized RPC Integrity Monitor
**Repository**: https://github.com/faisalnugroho/rpc-sentinel
**Category**: Intelligent Contract (GenLayer Portal)
**Studionet address**: `0x7a8b2Dbf83164010453C364fF2F4f3D547e28750`
**Deploy tx**: `0x6ea821784c26cf344f468e8892b30e68162923dd9e89ad58ac1c13a469b55de3`
**Code sha256[:16]**: `98c72e86da1f5b09` (byte-identical to `contracts/rpc_sentinel.py` at HEAD)
**Live dApp**: https://faisalnugroho.github.io/rpc-sentinel/

## What it does

RPC Sentinel is a decentralized, consensus-backed integrity monitor
for blockchain RPC endpoints. A caller registers a PUBLIC, READ-ONLY
EVM RPC endpoint together with the chain ID they expect it to serve.
A GenLayer consensus round then has validators INDEPENDENTLY probe
the endpoint over JSON-RPC (eth_chainId ×2, eth_blockNumber ×2,
net_version, web3_clientVersion, plus a fixed public reference
endpoint as freshness anchor — 8 requests, identical for every
prober), normalize their observations into a fixed schema, and
derive a deterministic classification:

- `HEALTHY` — valid JSON-RPC, observed chain == expected, valid
  block, freshness CURRENT/SLIGHTLY_BEHIND
- `MISCONFIGURED` — endpoint responds, observed chain != expected
- `STALE` — correct chain but block height far behind the chain
  reference beyond the documented freshness policy
- `DEGRADED` — primaries pass, an optional secondary probe
  (net_version / web3_clientVersion) is unavailable or abnormal
- `UNREACHABLE` — no valid JSON-RPC response obtainable (HTTP
  error, transport failure, invalid JSON, JSON-RPC error object,
  missing result, malformed hex quantity)
- `INCONSISTENT` — the endpoint's own repeated responses conflict
  (alternating chain ids, regressing blocks, implausible height),
  or validators could not converge (nothing is persisted then)

### Trust model

- **Only a consensus-approved normalized observation becomes
  authoritative state.** A leader proposal is never persisted on
  its own: the validator independently executes the SAME probe
  plan, re-derives the classification, and compares the proposal
  against its OWN observation. It rejects mismatched target URL,
  URL hash, expected chain id, schema/probe version, malformed or
  missing fields, unsupported classifications, and implausible
  block measurements. It does not merely "agree with the leader".
- **Binding**: every consensus evaluation binds schema_version,
  probe_version, check_id, canonical target URL + Keccak-256 hash,
  and expected chain id; the contract re-verifies every binding
  field again before ANY persistence.
- **Block numbers are never compared for equality across probers**
  (block height advances during the consensus round). Validators
  compare the derived FRESHNESS DELTA (reference − target, measured
  against the same fixed reference endpoint) inside a ±12 window,
  plus the freshness bucket FAMILY — the CURRENT↔SLIGHTLY_BEHIND
  boundary (delta 2 vs 3) can legitimately flip mid-round.
- **No unverified state promotion**: REQUESTED → consensus
  evaluation → FINALIZED or CONSENSUS_FAILED (nothing from the
  leader persists on failure; a failed check can be re-run). The
  frontend shows "pending" until finalization and never displays
  leader-only data as authoritative.
- **Why no LLM**: every authoritative field is mechanically
  derived from JSON-RPC responses; an LLM could only add
  hallucination risk into authoritative state. GenLayer's value
  here is the independent multi-validator probe + consensus, not
  language reasoning.
- **URL security**: the target is untrusted input — SSRF-aware
  canonicalization (HTTPS only, no embedded credentials, no query
  strings/fragments, no localhost/internal-suffix hosts, no raw IP
  literals, ports 443/8443 only, deterministic canonical form +
  hash). No secrets or API keys are ever accepted or stored.

### Scope and limitations

RPC Sentinel answers ONE narrow question: whether the endpoint
currently behaves consistently with the expected network and basic
JSON-RPC integrity requirements, per the public probe
configuration. It is NOT an endorsement that a provider is honest
or malicious, NOT a guarantee an endpoint stays healthy, NOT a
claim any endpoint is canonical, and NOT a network/port scanner.
History is the app's own on-chain record, not an independent
archival oracle.

## Evidence

- Test suite: **98 direct-mode tests** (units, classification
  ladder, adversarial leader-forgery matrix, SSRF/security surface,
  regression pins) — locally and on CI: 98 passed
- Lint: `genvm-lint check` — **3 checks pass, validation passed**
  (locally and CI; 0 errors)
- Live Studionet verification: **deploy (full consensus) + 5
  consensus-verified checks** — all rounds MAJORITY_AGREE
  (3 agree / 0 disagree / 2 idle validators per round), logged in
  `docs/deployment_log.json` with TX hashes
- dApp E2E: burner wallet → request → consensus → finalized
  HEALTHY rendered live in the browser (chk-5, Base, chain 8453
  observed, client `reth`, freshness CURRENT)

### Live verification runs

| Step | Check | Classification | Vote | Verify txs (request + consensus) |
|---|---|---|---|---|
| S1 healthy | chk-1 | HEALTHY / CURRENT | MAJORITY_AGREE | `0x4913c95b4652ea6c79d5bcdbb59a4205cbfc8059fd76f76b96416d33a5f17600` + `0xef00d041241bcf3406460de780f827d754930ec61130f2c5b24ed6b06bda160e` |
| S2 misconfigured | chk-2 | MISCONFIGURED / chain_id_mismatch | MAJORITY_AGREE | `0xead416df5a4f2959e0c148d60dfbf71328ae70babc006a20bf97a94967427f65` + `0xa0e833ba6d0daea86bd97e9c94295db2ef0906946c03b6dca54f38dd5f035e2e` |
| S3 unreachable | chk-3 | UNREACHABLE / network_error | MAJORITY_AGREE | `0x224453a61ade5d5c57b98f9cdafdb820ab58ad19a795f91a49eef84fd0639f49` + `0x911bdd41ae0acfb7c7ed44da1994a03064dec7c514bfae4cdf0d188f23d28cfd` |
| S4 determinism re-run | chk-4 | HEALTHY / CURRENT (same verdict as S1 on a fresh check) | MAJORITY_AGREE | `0xa9c3dad97cd94985d0a0f62053977f5a399189fbd8f6fc4ed53c49d0ae6ce72b` + `0xd27a154c882dcf6b9fad1b4091b970628e66add041300251af0ea65e7cfc6a6c` |
| dApp E2E | chk-5 | HEALTHY / CURRENT (Base, chain 8453, client reth) | MAJORITY_AGREE | via the public dApp (burner wallet), recorded on-chain |

(Exact hashes are also in `docs/deployment_log.json`; verify any of
them on the Studionet explorer.)

## Contract interface

- `request_check(target_url, expected_chain_id)` — write; registers
  an immutable check request (canonical URL + hash + expected
  chain bound at request time)
- `run_consensus(check_id)` — write; executes the consensus probe
  round; persists only the consensus-approved observation
- Views: `get_check`, `get_check_by_target`, `get_history`,
  `get_recent_checks`, `get_stats`, `get_config` (full public
  probe configuration for transparency)

## Notes for reviewers

- The FIRST deploy harness run exited 1 AFTER a successful
  full-consensus deployment (its vote parser expected a
  MAJORITY_AGREE string; live receipts expose `consensus_data.votes`
  instead). The deployment itself succeeded (validators agreed,
  contract live, verified via get_config/get_stats). The smoke run
  attaches to that single deployment — there is exactly ONE
  contract, ONE deploy tx. Disclosed in `docs/deployment_log.json`.
- All tests run against an in-process scripted RPC router — no
  test ever touches a live network; live behavior is proven by the
  on-chain smoke evidence above.
- History is capped (10 per target, 5000 checks) and stores only
  the minimal normalized evidence — no raw RPC bodies.

**Status: READY FOR MANUAL PORTAL SUBMISSION**
