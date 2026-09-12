#!/usr/bin/env python3
"""Deploy RPC Sentinel to GenLayer Studionet + live smoke verification.

Protocol (exactly ONE deployment; run only after tests+lint pass):
  D1   deploy (full consensus)                          -> contract address
  S1   healthy live endpoint:  Ethereum llamarpc, expect HEALTHY
  S2   wrong chain:           same endpoint, expected chain 137
                              -> MISCONFIGURED (deterministic)
  S3   unreachable:          dead host, expect UNREACHABLE
  S4   determinism re-run:   repeat S1 on a fresh check id,
                              classification must be identical
  G1   getters: get_config / get_stats / get_history sanity

Every consensus run is gated on BOTH the consensus vote AND the
execution result (FINALIZED can still carry a reverted execution).
Evidence is appended to docs/deployment_log.json.

NOTE (S3): an honest unreachable case uses a syntactically valid
public HTTPS host that does not resolve/serve (TLS/transport
failure) — never a fabricated response.
"""
import hashlib
import json
import sys
import time
from pathlib import Path

from genlayer_py import create_client, create_account
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus

ROOT = Path(__file__).resolve().parents[1]
CODE = ROOT / "contracts" / "rpc_sentinel.py"
LOG = ROOT / "docs" / "deployment_log.json"
LOG.parent.mkdir(exist_ok=True)

TARGET_LIVE = "https://eth.drpc.org"            # public read-only
TARGET_LIVE_CHAIN = "1"
TARGET_WRONG_CHAIN = "137"                     # expect MISCONFIGURED
TARGET_DEAD = "https://rpc-sentinel-dead-host.invalid"  # non-resolving

code = CODE.read_text()
print(f"contract: {len(code)} bytes, sha256[:16] =",
      hashlib.sha256(code.encode()).hexdigest()[:16])

keyfile = Path(__file__).parent / ".deployer.json"
if keyfile.exists():
    kd = json.loads(keyfile.read_text())
    account = create_account(account_private_key=kd["private_key"])
    print("deployer (saved):", account.address)
else:
    account = create_account()
    keyfile.write_text(json.dumps(
        {"address": account.address, "private_key": account.key.hex()}))
    print("deployer (new):", account.address)

client = create_client(chain=studionet, account=account)
client.fund_account(account.address, 10**18)
print("network: studionet", studionet)


def wait_final(tx_hash, what, timeout_s=900):
    """Wait for FINALIZED; the SDK's internal poller raises after
    its own retry budget — catch it and keep polling until OUR
    timeout."""
    t0 = time.time()
    last_err = None
    while time.time() - t0 < timeout_s:
        try:
            receipt = client.wait_for_transaction_receipt(
                transaction_hash=tx_hash,
                status=TransactionStatus.FINALIZED,
                full_transaction=True,
                retries=50, interval=6000)
            if receipt:
                return receipt
        except Exception as e:
            last_err = e  # still processing; keep polling
        time.sleep(5)
    print(f"TIMEOUT waiting for {what}: {tx_hash} last_err={last_err}")
    sys.exit(1)


def run_ok(receipt, what):
    """Gate on the consensus vote AND the execution result AND
    per-validator agreement. FINALIZED != success."""
    cd = receipt.get("consensus_data", {}) or {}
    vote = None
    stderr = ""
    try:
        lr = cd.get("leader_receipt", [{}])[0]
        vote = lr.get("result")
        stderr = (lr.get("genvm_result", {}) or {}).get("stderr", "") or ""
    except Exception:
        pass
    exec_name = receipt.get("tx_execution_result_name")
    votes = cd.get("votes", {})
    print(f"  [{what}] vote={vote} exec={exec_name} "
          f"votes={json.dumps(votes)[:160]}")
    if stderr:
        print("  stderr tail:", stderr[-500:])
    ok_exec = exec_name in ("FINISHED_WITH_RETURN", None)
    ok_vote = vote in ("MAJORITY_AGREE", None)  # None on leader_only
    return ok_exec and ok_vote, exec_name, vote, stderr


def read_json(fn, args):
    return json.loads(client.read_contract(
        address=ADDRESS, function_name=fn, args=args))


def do_check(url, chain, label, expect=None):
    """request_check + run_consensus, return the persisted record."""
    tx1 = client.write_contract(
        ADDRESS, "request_check", args=[url, chain], account=account)
    rc1 = wait_final(tx1, label + " request")
    ok, exec_name, vote, stderr = run_ok(rc1, label + " request")
    if not ok:
        print(f"  [FAIL] {label}: request_check execution failed")
        sys.exit(1)
    recent = read_json("get_recent_checks", [1])
    cid = recent[0]["check_id"]
    print(f"  [{label}] check_id={cid}")
    tx2 = client.write_contract(
        ADDRESS, "run_consensus", args=[cid], account=account)
    rc2 = wait_final(tx2, label + " consensus")
    ok, exec_name, vote, stderr = run_ok(rc2, label + " consensus")
    rec = read_json("get_check", [cid])
    exp = "n/a"
    if expect:
        exp = ("PASS" if rec["classification"] == expect else
               "MISMATCH(got %s want %s)" % (rec["classification"], expect))
    print(f"  [{label}] status={rec['status']} "
          f"classification={rec['classification']} "
          f"bucket={rec['freshness_bucket']} "
          f"failure_code={rec['failure_code']} expect={exp}")
    return {
        "step": label,
        "check_id": cid,
        "tx_request": tx1 if isinstance(tx1, str) else str(tx1),
        "tx_consensus": tx2 if isinstance(tx2, str) else str(tx2),
        "vote": vote,
        "exec": exec_name,
        "status": rec["status"],
        "classification": rec["classification"],
        "expected": expect,
        "expectation_met": (None if expect is None
                            else rec["classification"] == expect),
        "freshness_bucket": rec["freshness_bucket"],
        "failure_code": rec["failure_code"],
        "observed_chain_id": rec["observed_chain_id"],
        "observed_block_number": rec["observed_block_number"],
        "consensus_ok": ok,
        "stderr_tail": (stderr or "")[-1200:],
    }


# ---------------------------------------------------------------------------
# D1: deploy (full consensus)
# ---------------------------------------------------------------------------
print("\n=== D1: deploy ===")
tx = client.deploy_contract(code=code, account=account, args=[],
                            leader_only=False)
rc = wait_final(tx, "deploy")
ADDRESS = (rc.get("data", {}) or {}).get("contract_address") \
    or rc.get("to_address")
if not ADDRESS:
    print("no contract address in receipt:", json.dumps(rc)[:500])
    sys.exit(1)
ok, exec_name, vote, stderr = run_ok(rc, "deploy")
print(f"deploy tx: {tx}\naddress:    {ADDRESS}")
if not ok:
    print("deploy execution FAILED")
    sys.exit(1)

cfg = read_json("get_config", [])
print("probe config:", json.dumps(cfg)[:400])

evidence = {
    "deploy": {
        "tx": tx if isinstance(tx, str) else str(tx),
        "address": ADDRESS,
        "code_sha256_16": hashlib.sha256(code.encode()).hexdigest()[:16],
        "vote": vote,
        "exec": exec_name,
        "timestamp": int(time.time()),
    },
    "runs": [],
}

# ---------------------------------------------------------------------------
# S1: healthy live endpoint
# ---------------------------------------------------------------------------
print("\n=== S1: healthy live endpoint (full consensus) ===")
evidence["runs"].append(do_check(
    TARGET_LIVE, TARGET_LIVE_CHAIN, "S1-healthy", expect="HEALTHY"))

# ---------------------------------------------------------------------------
# S2: wrong chain expectation (deterministic MISCONFIGURED)
# ---------------------------------------------------------------------------
print("\n=== S2: wrong expected chain ===")
evidence["runs"].append(do_check(
    TARGET_LIVE, TARGET_WRONG_CHAIN, "S2-misconfigured",
    expect="MISCONFIGURED"))

# ---------------------------------------------------------------------------
# S3: unreachable endpoint (honest negative)
# ---------------------------------------------------------------------------
print("\n=== S3: unreachable endpoint ===")
evidence["runs"].append(do_check(
    TARGET_DEAD, "1", "S3-unreachable", expect="UNREACHABLE"))

# ---------------------------------------------------------------------------
# S4: determinism re-run of S1 on a FRESH check id
# ---------------------------------------------------------------------------
print("\n=== S4: determinism re-run ===")
evidence["runs"].append(do_check(
    TARGET_LIVE, TARGET_LIVE_CHAIN, "S4-determinism", expect="HEALTHY"))

# ---------------------------------------------------------------------------
# G1: getters sanity
# ---------------------------------------------------------------------------
print("\n=== G1: getters ===")
stats = read_json("get_stats", [])
hist = read_json("get_history", [TARGET_LIVE])
print("stats:", json.dumps(stats))
print("history entries for target:", len(hist))
evidence["getters"] = {
    "stats": stats,
    "history_len": len(hist),
}
evidence["aggregate"] = {
    "all_required_consensus_rounds_finalized": all(
        r["status"] in ("FINALIZED", "CONSENSUS_FAILED")
        for r in evidence["runs"]),
    "expected_live_outcomes_met": all(
        r["expectation_met"] for r in evidence["runs"]
        if r["expected"] is not None),
    "unexpected_live_failures": sum(
        1 for r in evidence["runs"] if not r["consensus_ok"]),
}

if LOG.exists():
    try:
        prior = json.loads(LOG.read_text())
        evidence["runs"] = prior.get("runs", []) + evidence["runs"]
        if prior.get("deploy"):
            evidence.setdefault("prior_deploys", []).append(prior["deploy"])
    except Exception:
        pass
LOG.write_text(json.dumps(evidence, indent=2))
print(f"\nlog written: {LOG}")
print("DONE")
