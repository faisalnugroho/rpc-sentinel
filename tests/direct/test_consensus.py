"""Consensus + adversarial trust-boundary tests for RPC Sentinel.

gltest direct mode consensus model: the leader runs inside the
contract call; vm.run_validator() executes the CAPTURED validator
against the leader's actual result — or a forged one — with an
independently re-installed RPC router. This proves the validator
independently re-probes and re-derives, and that only substance
(bound fields + classification + delta tolerance) is compared.

RPC responses come from the scripted in-process router
(helpers.install_rpc_router) — no live network.

Adversarial matrix (brief section 20):
  1  leader HEALTHY chain A, validator probes chain B  -> reject
  2  leader target X, actual request target Y          -> reject
  3  wrong expected_chain_id in leader result          -> reject
  4  wrong target_url_hash in leader result            -> reject
  5  unsupported schema version                        -> reject
  6  HEALTHY claim but observed != expected chain      -> reject
  7  HEALTHY claim but required fields absent          -> reject
  8  modest block drift, both derive CURRENT           -> ACCEPT
  9  significant drift, validator derives STALE      -> not HEALTHY
  10 optional method fails, required pass             -> DEGRADED
  11 required RPC call fails                          -> UNREACHABLE
  12 validator cannot obtain evidence                  -> reject
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import (  # noqa: E402
    deploy, install_rpc_router, target_script, reference_script,
    rpc, T_HOST, R_HOST,
)


def _req(c, url=T_HOST, chain="1"):
    return c.request_check(url, chain)


def _get(c, cid):
    return json.loads(c.get_check(cid))


def _router(vm, *, t=None, r=None):
    """Install the standard router: healthy target + CURRENT ref."""
    t = dict(chain_id="0x1", block="0x100") if t is None else t
    install_rpc_router(
        vm,
        target={"url": T_HOST, "script": target_script(**t)},
        reference={"url": R_HOST, "script": reference_script(**r)}
        if r is not None else None,
    )


# ---------------------------------------------------------------------------
# Happy path + equivalence mechanics
# ---------------------------------------------------------------------------

class TestConsensusHappyPath:
    def test_healthy_finalized(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, r={"chain_id": "0x1", "block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["status"] == "FINALIZED"
        assert rec["classification"] == "HEALTHY"
        assert rec["freshness_bucket"] == "CURRENT"
        assert rec["observed_chain_id"] == "1"
        assert rec["observed_block_number"] == "256"  # 0x100
        assert rec["jsonrpc_valid"] == "true"
        assert rec["rpc_reachable"] == "true"
        assert rec["client_family"] == "geth"
        assert rec["failure_code"] == ""
        s = json.loads(c.get_stats())
        assert s["finalized_count"] == "1"
        assert s["consensus_failed_count"] == "0"

    def test_case8_validator_accepts_modest_drift(self, direct_vm,
                                                  direct_deploy):
        """Leader at block 256 (delta 1); validator measures 40
        blocks later (target 296, ref 297 — delta 1): heights differ
        by 40, deltas agree. ACCEPT (raw heights never compared)."""
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, r={"block": "0x101"})
        c.run_consensus(cid)
        direct_vm.clear_mocks()
        _router(direct_vm,
                t={"block": "0x128"},           # 296
                r={"block": "0x129"})           # 297 -> delta 1
        assert direct_vm.run_validator() is True

    def test_case1_validator_probes_other_chain(self, direct_vm,
                                                direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, r={"block": "0x101"})
        c.run_consensus(cid)
        direct_vm.clear_mocks()
        _router(direct_vm, t={"chain_id": "0x89"}, r={"block": "0x101"})
        assert direct_vm.run_validator() is False

    def test_case12_validator_obtains_nothing(self, direct_vm,
                                              direct_deploy):
        """Validator-side transport failure on ALL target methods:
        the validator's own probe yields UNREACHABLE — cannot match a
        HEALTHY leader — reject (never blindly accept)."""
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, r={"block": "0x101"})
        c.run_consensus(cid)
        direct_vm.clear_mocks()
        # validator sees a dead target (reference still fine)
        install_rpc_router(
            direct_vm,
            target={"url": T_HOST,
                    "script": target_script(fail_all=True)},
            reference={"url": R_HOST, "script": reference_script(
                block="0x101")},
        )
        assert direct_vm.run_validator() is False


# ---------------------------------------------------------------------------
# Classification ladder (deterministic derivation)
# ---------------------------------------------------------------------------

class TestClassificationLadder:
    def test_misconfigured_chain_mismatch(self, direct_vm,
                                          direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c, chain="1")
        _router(direct_vm, t={"chain_id": "0x89"}, r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "MISCONFIGURED"
        assert rec["failure_code"] == "chain_id_mismatch"
        assert rec["observed_chain_id"] == "137"

    def test_stale(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, t={"block": "0x64"}, r={"block": "0x1000"})
        c.run_consensus(cid)  # delta 3996 > 30 -> STALE
        rec = _get(c, cid)
        assert rec["classification"] == "STALE"
        assert rec["failure_code"] == "stale_block_height"
        assert rec["freshness_bucket"] == "STALE"

    def test_slightly_behind_is_healthy(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, t={"block": "0x100"},
                r={"block": "0x115"})  # delta 21
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "HEALTHY"
        assert rec["freshness_bucket"] == "SLIGHTLY_BEHIND"

    def test_case10_degraded_net_version_missing(self, direct_vm,
                                                 direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, t={"net_version": None},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "DEGRADED"
        assert rec["failure_code"] == "secondary_probe_unavailable"

    def test_degraded_client_version_missing(self, direct_vm,
                                             direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, t={"client": None}, r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "DEGRADED"

    def test_degraded_net_version_disagrees(self, direct_vm,
                                            direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, t={"net_version": "137"},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "DEGRADED"
        assert rec["failure_code"] == "secondary_probe_unavailable"

    def test_case11_unreachable_http_error(self, direct_vm,
                                           direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm,
                t={"raw": {"eth_chainId": (500, "oops"),
                           "eth_blockNumber": (500, "oops"),
                           "net_version": (500, "oops"),
                           "web3_clientVersion": (500, "oops")}},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "UNREACHABLE"
        assert rec["failure_code"] == "http_status_error"
        assert rec["rpc_reachable"] == "false"

    def test_unreachable_transport(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, t={"fail_all": True}, r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "UNREACHABLE"
        assert rec["failure_code"] == "network_error"

    def test_unreachable_jsonrpc_error_object(self, direct_vm,
                                              direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm,
                t={"raw": {"eth_blockNumber": rpc(
                    None, error={"code": -32000,
                                "message": "prohibited"})}},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "UNREACHABLE"
        assert rec["failure_code"] == "jsonrpc_error_response"

    def test_unreachable_invalid_json(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm,
                t={"raw": {"eth_blockNumber": (200, "<html>gw</html>")}},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "UNREACHABLE"
        assert rec["failure_code"] == "invalid_json"

    def test_unreachable_missing_result(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm,
                t={"raw": {"eth_blockNumber": (200, json.dumps(
                    {"jsonrpc": "2.0", "id": 1}))}},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "UNREACHABLE"
        assert rec["failure_code"] == "missing_result"

    def test_unreachable_malformed_hex(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm,
                t={"raw": {"eth_blockNumber": rpc("0xZZ")}},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "UNREACHABLE"
        assert rec["failure_code"] == "malformed_hex_quantity"

    def test_unreachable_block_zero_major_chain(self, direct_vm,
                                                direct_deploy):
        # block 0 on Ethereum mainnet: impossible CURRENT height
        c = deploy(direct_vm)
        cid = _req(c, chain="1")
        _router(direct_vm, t={"block": "0x0"}, r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "UNREACHABLE"
        assert rec["observed_block_number"] == ""

    def test_inconsistent_chain_flap(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, t={"chain_id": "0x1", "chain_id2": "0x89"},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "INCONSISTENT"
        assert rec["failure_code"] == "chain_id_instability"

    def test_inconsistent_block_regression(self, direct_vm,
                                           direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, t={"block": "0x200", "block2": "0x100"},
                r={"block": "0x201"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "INCONSISTENT"
        assert rec["failure_code"] == "block_regression"

    def test_inconsistent_ahead_anomaly(self, direct_vm, direct_deploy):
        # target 65536 vs ref 257: delta -65279 -> AHEAD_ANOMALY
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, t={"block": "0x10000"},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "INCONSISTENT"
        assert rec["failure_code"] == "implausible_height_ahead"
        assert rec["freshness_bucket"] == "AHEAD_ANOMALY"

    def test_impossible_height_rejected(self, direct_vm, direct_deploy):
        # 2^41 blocks > MAX_PLAUSIBLE_BLOCK (2^40)
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, t={"block": hex(2 ** 41)},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "UNREACHABLE"
        assert rec["failure_code"] == "malformed_hex_quantity"

    def test_broken_reference_unknown_bucket_healthy(self, direct_vm,
                                                     direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, r={"broken": True})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "HEALTHY"
        assert rec["freshness_bucket"] == "UNKNOWN"

    def test_wrong_chain_reference_unknown_bucket(self, direct_vm,
                                                  direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c, chain="1")
        _router(direct_vm, r={"chain_id": "0x89", "block": "0x101"})
        c.run_consensus(cid)
        rec = _get(c, cid)
        assert rec["classification"] == "HEALTHY"
        assert rec["freshness_bucket"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# Adversarial leader-forgery tests (validator must reject)
# ---------------------------------------------------------------------------

class TestAdversarialLeaderForgery:
    """vm.run_validator(leader_result=forged) proves the validator
    rejects ANY proposal not bound to the exact request."""

    def _capture(self, direct_vm):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, r={"block": "0x101"})
        c.run_consensus(cid)
        return c, cid

    @staticmethod
    def _obs(**over):
        obs = {
            "schema_version": "1",
            "probe_version": "1",
            "target_url": T_HOST,
            "target_url_hash": None,  # filled per-test
            "expected_chain_id": 1,
            "rpc_reachable": True,
            "jsonrpc_valid": True,
            "observed_chain_id": 1,
            "chain_id_match": True,
            "observed_block_number": 256,
            "block_number_valid": True,
            "freshness_bucket": "CURRENT",
            "freshness_delta": 1,
            "net_version_ok": True,
            "net_version_agrees": True,
            "client_available": True,
            "client_family": "geth",
            "classification": "HEALTHY",
            "failure_code": "",
        }
        obs.update(over)
        return obs

    def _forged(self, cid, obs):
        return {
            "check_id": cid,
            "url_hash": "x",
            "observation": obs,
        }

    def test_case4_wrong_url_hash_rejected(self, direct_vm,
                                           direct_deploy):
        c, cid = self._capture(direct_vm)
        obs = self._obs(target_url_hash="0x" + "ab" * 32)
        assert direct_vm.run_validator(
            leader_result=self._forged(cid, obs)) is False

    def test_wrong_check_id_rejected(self, direct_vm, direct_deploy):
        c, cid = self._capture(direct_vm)
        obs = self._obs(target_url_hash=None)
        assert direct_vm.run_validator(
            leader_result=self._forged("chk-999", obs)) is False

    def test_case5_wrong_schema_version_rejected(self, direct_vm,
                                                 direct_deploy):
        c, cid = self._capture(direct_vm)
        obs = self._obs(target_url_hash=None, schema_version="2")
        assert direct_vm.run_validator(
            leader_result=self._forged(cid, obs)) is False

    def test_case6_healthy_claim_chain_mismatch_rejected(self,
                                                        direct_vm,
                                                        direct_deploy):
        c, cid = self._capture(direct_vm)
        obs = self._obs(target_url_hash=None, observed_chain_id=137,
                        chain_id_match=False)
        assert direct_vm.run_validator(
            leader_result=self._forged(cid, obs)) is False

    def test_case7_missing_required_fields_rejected(self, direct_vm,
                                                    direct_deploy):
        c, cid = self._capture(direct_vm)
        obs = self._obs(target_url_hash=None)
        del obs["observed_chain_id"]
        del obs["classification"]
        assert direct_vm.run_validator(
            leader_result=self._forged(cid, obs)) is False

    def test_unsupported_classification_rejected(self, direct_vm,
                                                 direct_deploy):
        c, cid = self._capture(direct_vm)
        obs = self._obs(target_url_hash=None, classification="GREAT")
        assert direct_vm.run_validator(
            leader_result=self._forged(cid, obs)) is False

    def test_unsupported_bucket_rejected(self, direct_vm, direct_deploy):
        c, cid = self._capture(direct_vm)
        obs = self._obs(target_url_hash=None,
                        freshness_bucket="SUPER_FRESH")
        assert direct_vm.run_validator(
            leader_result=self._forged(cid, obs)) is False

    def test_leader_error_rejected(self, direct_vm, direct_deploy):
        c, cid = self._capture(direct_vm)
        import genlayer.gl.vm as glvm
        assert direct_vm.run_validator(
            leader_error=glvm.UserError(message="boom")) is False

    def test_non_dict_result_rejected(self, direct_vm, direct_deploy):
        c, cid = self._capture(direct_vm)
        assert direct_vm.run_validator(leader_result="HEALTHY") is False

    def test_case2_leader_target_mismatch_rejected(self, direct_vm,
                                                   direct_deploy):
        c, cid = self._capture(direct_vm)
        obs = self._obs(
            target_url_hash=None,
            target_url="https://other-rpc.example.com")
        assert direct_vm.run_validator(
            leader_result=self._forged(cid, obs)) is False

    def test_case9_significant_drift_not_healthy(self, direct_vm,
                                                direct_deploy):
        """Leader proposes STALE(delta 300); validator measures
        CURRENT(delta 1): family + delta window both reject."""
        c, cid = self._capture(direct_vm)
        obs = self._obs(
            target_url_hash=None,
            freshness_bucket="STALE", freshness_delta=300,
            classification="STALE",
            failure_code="stale_block_height")
        assert direct_vm.run_validator(
            leader_result=self._forged(cid, obs)) is False

    def test_case3_wrong_expected_chain_id_rejected(self, direct_vm,
                                                    direct_deploy):
        c, cid = self._capture(direct_vm)
        obs = self._obs(target_url_hash=None, expected_chain_id=137)
        assert direct_vm.run_validator(
            leader_result=self._forged(cid, obs)) is False

    def test_true_leader_observation_accepted(self, direct_vm,
                                              direct_deploy):
        """Sanity: the leader's ACTUAL result passes its own
        validator against identical mocks (round-trip honesty)."""
        c, cid = self._capture(direct_vm)
        direct_vm.clear_mocks()
        _router(direct_vm, r={"block": "0x101"})
        assert direct_vm.run_validator() is True


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

class TestStateMachine:
    def test_finalized_check_is_immutable(self, direct_vm,
                                          direct_deploy):
        c = deploy(direct_vm)
        cid = _req(c)
        _router(direct_vm, r={"block": "0x101"})
        c.run_consensus(cid)
        with pytest.raises(Exception):
            c.run_consensus(cid)  # FINALIZED -> not pending -> refuse
