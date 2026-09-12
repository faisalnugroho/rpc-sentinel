#!/usr/bin/env python3
"""Attach-mode smoke run for the LIVE RPC Sentinel deployment.

The contract was already deployed (deploy tx
0x6ea821784c26cf344f468e8892b30e68162923dd9e89ad58ac1c13a469b55de3,
address 0x7a8b2Dbf83164010453C364fF2F4f3D547e28750 — full consensus,
validators agree, deploy execution verified via get_config probe).
This script NEVER deploys; it attaches and runs the S1-S4 + G1
scenarios, appending evidence to docs/deployment_log.json.
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

ADDRESS = "0x7a8b2Dbf83164010453C364fF2F4f3D547e28750"
DEPLOY_TX = ("0x6ea821784c26cf344f468e8892b30e68162923dd9e89a"
             "d58ac1c13a469b55de3")

TARGET_LIVE = "https://eth.drpc.org"
TARGET_LIVE_CHAIN = "1"
TARGET_WRONG_CHAIN = "137"
TARGET_DEAD = "https://rpc-sentinel-dead-host.invalid"

code = CODE.read_text()
keyfile = Path(__file__).parent / ".deployer.json"
kd = json.loads(keyfile.read_text())
account = create_account(account_private_key=kd["private_key"])
print("deployer:", account.address)

client = create_client(chain=studionet, account=account)
client.fund_account(account.address, 10**18)


def wait_final(tx_hash, what, timeout_s=900):
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
            last_err = e
        time.sleep(5)
    print(f"TIMEOUT waiting for {what}: {tx_hash} last_err={last_err}")
    sys.exit(1)


def run_ok(receipt, what):
    cd = receipt.get("consensus_data", {}) or {}
    votes = cd.get("votes", {}) or {}
    n_agree = sum(1 for v in votes.values() if v == "agree")
    n_dis = sum(1 for v in votes.values() if v == "disagree")
    n_idle = sum(1 for v in votes.values() if v == "idle")
    vote = "MAJORITY_AGREE" if (n_agree and n_agree > n_dis) else (
        "MAJORITY_DISAGREE" if n_dis else None)
    stderr = ""
    try:
        lr = cd.get("leader_receipt", [{}])[0]
        stderr = (lr.get("genvm_result", {}) or {}).get("stderr", "") or ""
        if vote is None and isinstance(lr.get("result"), dict):
            vote = lr["result"].get("status")
    except Exception:
        pass
    exec_name = receipt.get("tx_execution_result_name")
    print(f"  [{what}] vote={vote} exec={exec_name} "
          f"votes(a/d/i)={n_agree}/{n_dis}/{n_idle}")
    if stderr:
        print("  stderr tail:", stderr[-500:])
    ok_exec = exec_name in ("FINISHED_WITH_RETURN", None)
    ok_vote = vote in ("MAJORITY_AGREE", "return", None) and not n_dis
    return ok_exec and ok_vote, exec_name, vote, stderr


def read_json(fn, args):
    return json.loads(client.read_contract(
        address=ADDRESS, function_name=fn, args=args))


def do_check(url, chain, label, expect=None):
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
        "tx_request": str(tx1),
        "tx_consensus": str(tx2),
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


print("\n=== S1: healthy live endpoint (full consensus) ===")
runs = []
runs.append(do_check(TARGET_LIVE, TARGET_LIVE_CHAIN, "S1-healthy",
                     expect="HEALTHY"))

print("\n=== S2: wrong expected chain ===")
runs.append(do_check(TARGET_LIVE, TARGET_WRONG_CHAIN, "S2-misconfigured",
                     expect="MISCONFIGURED"))

print("\n=== S3: unreachable endpoint ===")
runs.append(do_check(TARGET_DEAD, "1", "S3-unreachable",
                     expect="UNREACHABLE"))

print("\n=== S4: determinism re-run ===")
runs.append(do_check(TARGET_LIVE, TARGET_LIVE_CHAIN, "S4-determinism",
                     expect="HEALTHY"))

print("\n=== G1: getters ===")
stats = read_json("get_stats", [])
hist = read_json("get_history", [TARGET_LIVE])
print("stats:", json.dumps(stats))
print("history entries for target:", len(hist))

evidence = {
    "deploy": {
        "tx": DEPLOY_TX,
        "address": ADDRESS,
        "code_sha256_16": hashlib.sha256(code.encode()).hexdigest()[:16],
        "note": ("deployed by scripts/deploy_studionet.py first run; "
                 "that run exited 1 AFTER a successful full-consensus "
                 "deploy because its vote parser expected a "
                 "MAJORITY_AGREE string (live receipts expose "
                 "consensus_data.votes instead). Contract verified "
                 "live via get_config/get_stats. This is the ONE "
                 "deployment; smoke attaches, never redeploys."),
        "timestamp": int(time.time()),
    },
    "runs": runs,
    "getters": {"stats": stats, "history_len": len(hist)},
    "aggregate": {
        "all_required_consensus_rounds_finalized": all(
            r["status"] in ("FINALIZED", "CONSENSUS_FAILED") for r in runs),
        "expected_live_outcomes_met": all(
            r["expectation_met"] for r in runs if r["expected"] is not None),
        "unexpected_live_failures": sum(
            1 for r in runs if not r["consensus_ok"]),
    },
}

if LOG.exists():
    try:
        prior = json.loads(LOG.read_text())
        evidence["runs"] = prior.get("runs", []) + runs
        if prior.get("deploy"):
            evidence.setdefault("prior_deploys", []).append(prior["deploy"])
    except Exception:
        pass
LOG.write_text(json.dumps(evidence, indent=2))
print(f"\nlog written: {LOG}")
print("DONE")
