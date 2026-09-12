"""Regression tests — one per bug fixed during RPC Sentinel
development. Each test names the bug it pins.
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
from test_units import module  # noqa: E402


def _router(vm, *, t=None, r=None):
    t = dict(chain_id="0x1", block="0x100") if t is None else t
    install_rpc_router(
        vm,
        target={"url": T_HOST, "script": target_script(**t)},
        reference={"url": R_HOST, "script": reference_script(**r)}
        if r is not None else None,
    )


class TestRegressions:
    def test_reg_cross_block_raw_equality_false_rejects(self,
                                                        direct_vm,
                                                        direct_deploy):
        """BUG (design review): validator compared RAW block heights
        with ±6 tolerance. On fast chains (2s blocks) a 45-90s
        consensus round drifts heights by 20-45 blocks — an honest
        leader would be REJECTED. Fix: compare the freshness DELTA
        (reference − target, measured against the same fixed
        reference) with ±CROSS_DELTA_TOLERANCE. Pin: heights differ
        by 40 blocks, deltas agree -> ACCEPT."""
        c = deploy(direct_vm)
        cid = c.request_check(T_HOST, "1")
        _router(direct_vm, r={"block": "0x101"})
        c.run_consensus(cid)
        direct_vm.clear_mocks()
        _router(direct_vm,
                t={"block": "0x128"},           # 296
                r={"block": "0x129"})           # 297 -> delta 1
        assert direct_vm.run_validator() is True

    def test_reg_delta_drift_beyond_tolerance_rejected(self,
                                                       direct_vm,
                                                       direct_deploy):
        """The delta window is bounded: leader delta 1 (CURRENT),
        validator delta 30 (SLIGHTLY_BEHIND family) — 29 apart, way
        beyond ±12 — rejected."""
        c = deploy(direct_vm)
        cid = c.request_check(T_HOST, "1")
        _router(direct_vm, r={"block": "0x101"})
        c.run_consensus(cid)
        direct_vm.clear_mocks()
        _router(direct_vm,
                t={"block": "0x100"},
                r={"block": "0x11e"})  # delta 30
        assert direct_vm.run_validator() is False

    def test_reg_bucket_boundary_flip_accepted(self, direct_vm,
                                               direct_deploy):
        """BUG (design review): validator compared the EXACT
        freshness bucket; delta 2 (CURRENT) vs 3 (SLIGHTLY_BEHIND)
        flips on one block of chain drift mid-round -> spurious
        consensus failure. Fix: compare bucket FAMILY."""
        c = deploy(direct_vm)
        cid = c.request_check(T_HOST, "1")
        _router(direct_vm, r={"block": "0x102"})  # delta 2
        c.run_consensus(cid)
        rec = json.loads(c.get_check(cid))
        assert rec["freshness_bucket"] == "CURRENT"
        direct_vm.clear_mocks()
        _router(direct_vm, r={"block": "0x103"})  # delta 3
        assert direct_vm.run_validator() is True

    def test_reg_ahead_of_reference_not_healthy(self, direct_vm,
                                                direct_deploy):
        """BUG (design review): delta < 0 mapped unconditionally to
        CURRENT, so an endpoint claiming a wildly higher height
        passed as HEALTHY. Fix: delta < -60 -> AHEAD_ANOMALY ->
        INCONSISTENT."""
        c = deploy(direct_vm)
        cid = c.request_check(T_HOST, "1")
        _router(direct_vm, t={"block": "0x10000"},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = json.loads(c.get_check(cid))
        assert rec["classification"] == "INCONSISTENT"
        assert rec["failure_code"] == "implausible_height_ahead"

    def test_reg_small_negative_delta_still_current(self, direct_vm,
                                                   direct_deploy):
        """Guard the guard: small negative delta (target a few blocks
        ahead — normal LB rotation) stays CURRENT / HEALTHY."""
        c = deploy(direct_vm)
        cid = c.request_check(T_HOST, "1")
        _router(direct_vm, t={"block": "0x105"},
                r={"block": "0x101"})
        c.run_consensus(cid)
        rec = json.loads(c.get_check(cid))
        assert rec["classification"] == "HEALTHY"
        assert rec["freshness_bucket"] == "CURRENT"

    def test_reg_reference_never_fails_good_target(self, direct_vm,
                                                   direct_deploy):
        """BUG (design review): a broken PUBLIC REFERENCE endpoint
        could have failed a good target. Fix: invalid reference ->
        bucket UNKNOWN, classification stays HEALTHY."""
        c = deploy(direct_vm)
        cid = c.request_check(T_HOST, "1")
        _router(direct_vm, r={"broken": True})
        c.run_consensus(cid)
        rec = json.loads(c.get_check(cid))
        assert rec["classification"] == "HEALTHY"
        assert rec["freshness_bucket"] == "UNKNOWN"

    def test_reg_bool_chain_id_rejected(self, direct_vm):
        """BUG (design review): _validate_chain_id accepted True
        (bool subclasses int) — `expected_chain_id=true` would
        decode as chain 1. Bool explicitly rejected."""
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._validate_chain_id(True)
        with pytest.raises(Exception):
            m._validate_chain_id(False)

    def test_reg_validator_bool_sanity(self, direct_vm, direct_deploy):
        """Validator type-sanity rejects a leader observation whose
        observed_chain_id is a bool (True == 1 in Python)."""
        c = deploy(direct_vm)
        cid = c.request_check(T_HOST, "1")
        _router(direct_vm, r={"block": "0x101"})
        c.run_consensus(cid)
        forged = {
            "check_id": cid,
            "url_hash": "x",
            "observation": {
                "schema_version": "1", "probe_version": "1",
                "target_url": T_HOST, "target_url_hash": "x",
                "expected_chain_id": 1,
                "rpc_reachable": True, "jsonrpc_valid": True,
                "observed_chain_id": True,  # bool, not int
                "chain_id_match": True,
                "observed_block_number": 256,
                "block_number_valid": True,
                "freshness_bucket": "CURRENT", "freshness_delta": 1,
                "net_version_ok": True, "net_version_agrees": True,
                "client_available": True, "client_family": "geth",
                "classification": "HEALTHY", "failure_code": "",
            },
        }
        assert direct_vm.run_validator(leader_result=forged) is False

    def test_reg_explicit_443_normalized(self, direct_vm):
        """BUG (design review): https://host:443 kept the port in the
        canonical form, so one endpoint could be bound under TWO
        canonical URLs. Fix: :443 normalized away."""
        m = module(direct_vm)
        a, ha = m._canonicalize_url("https://rpc.example.com:443")
        b, hb = m._canonicalize_url("https://rpc.example.com")
        assert a == b and ha == hb

    def test_reg_block_zero_major_chain(self, direct_vm, direct_deploy):
        """Impossible CURRENT height (block 0 on a live major chain)
        must not pass as HEALTHY. Pinned: UNREACHABLE."""
        c = deploy(direct_vm)
        cid = c.request_check(T_HOST, "1")
        _router(direct_vm, t={"block": "0x0"}, r={"block": "0x101"})
        c.run_consensus(cid)
        rec = json.loads(c.get_check(cid))
        assert rec["classification"] == "UNREACHABLE"
        assert rec["observed_block_number"] == ""

    def test_reg_internal_suffix_bypass(self, direct_vm):
        """BUG (caught by the security suite, first run):
        _RE_BAD_SUFFIX.match() anchors at position 0, so hosts like
        node.internal / node.corp / node.lan passed canonicalization
        (only a LEADING 'internal' matched). Fix: .search() — the
        bad token may begin at any dot."""
        m = module(direct_vm)
        for host in ("https://node.internal", "https://node.corp",
                     "https://node.lan", "https://node.home",
                     "https://node.local", "https://node.intranet",
                     "https://metadata.google.internal"):
            with pytest.raises(Exception):
                m._canonicalize_url(host)

    def test_reg_mock_method_blindspot(self, direct_vm, direct_deploy):
        """BUG (test infrastructure, first run): the gltest web mock
        keys only on (url, HTTP method) — all six JSON-RPC probe
        POSTs to one URL returned the FIRST registered response, so
        early tests asserted nonsense (chainId body parsed as block
        1). Fix: scripted RPC router keyed on the JSON-RPC method
        inside the request body. This pin asserts the router wiring:
        distinct responses per method actually reach the contract."""
        c = deploy(direct_vm)
        cid = c.request_check(T_HOST, "1")
        install_rpc_router(
            direct_vm,
            target={"url": T_HOST, "script": target_script(
                chain_id="0x1", block="0x200", net_version="1")},
            reference={"url": R_HOST, "script": reference_script(
                block="0x201")},
        )
        c.run_consensus(cid)
        rec = json.loads(c.get_check(cid))
        assert rec["observed_chain_id"] == "1"       # not 512
        assert rec["observed_block_number"] == "512"  # 0x200, not 1
        assert rec["classification"] == "HEALTHY"
