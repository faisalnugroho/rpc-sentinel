"""Unit tests for RPC Sentinel pure functions + contract surface.

Runs the contract through gltest direct mode. RPC responses are
served by the scripted in-process router (helpers.install_rpc_router)
— no test ever touches a live network.
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

M = None


def module(direct_vm):
    """Load the contract module ONCE (pure functions only).

    vm.activate().__exit__ evicts the contract module from
    sys.modules, so we snapshot the module's namespace into a plain
    types.SimpleNamespace while still inside the activate() block.
    """
    global M
    if M is not None:
        return M
    import types
    from gltest.direct.loader import load_contract_class, create_address
    from gltest.direct.vm import VMContext
    from pathlib import Path as P
    vm = VMContext()
    vm.sender = create_address("unit-bootstrap")
    with vm.activate():
        cls = load_contract_class(
            P(__file__).resolve().parents[2] / "contracts" / "rpc_sentinel.py",
            vm,
        )
        mod = sys.modules[cls.__module__]
        ns = types.SimpleNamespace()
        for k in dir(mod):
            if not k.startswith("__"):
                setattr(ns, k, getattr(mod, k))
    M = ns
    return M


# ---------------------------------------------------------------------------
# URL canonicalization
# ---------------------------------------------------------------------------

class TestCanonicalUrl:
    def test_accepts_plain_https(self, direct_vm):
        m = module(direct_vm)
        url, h = m._canonicalize_url("https://eth.llamarpc.com")
        assert url == "https://eth.llamarpc.com"
        # Keccak256.hexdigest() = 64 hex chars, no 0x prefix
        assert len(h) == 64 and int(h, 16) >= 0

    def test_trims_whitespace(self, direct_vm):
        m = module(direct_vm)
        url, _ = m._canonicalize_url("  https://eth.llamarpc.com  ")
        assert url == "https://eth.llamarpc.com"

    def test_lowercases_host_preserves_path(self, direct_vm):
        m = module(direct_vm)
        url, _ = m._canonicalize_url(
            "https://RPC.Example.COM/v3/AbCdEf")
        assert url == "https://rpc.example.com/v3/AbCdEf"

    def test_explicit_443_normalized_away(self, direct_vm):
        m = module(direct_vm)
        url, _ = m._canonicalize_url("https://rpc.example.com:443")
        assert url == "https://rpc.example.com"

    def test_port_8443_kept(self, direct_vm):
        m = module(direct_vm)
        url, _ = m._canonicalize_url("https://rpc.example.com:8443")
        assert url == "https://rpc.example.com:8443"

    def test_rejects_http(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._canonicalize_url("http://eth.llamarpc.com")

    def test_rejects_ftp(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._canonicalize_url("ftp://eth.llamarpc.com")

    def test_rejects_embedded_credentials(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._canonicalize_url("https://user:pass@eth.llamarpc.com")

    def test_rejects_query_string(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._canonicalize_url("https://eth.llamarpc.com?token=x")

    def test_rejects_fragment(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._canonicalize_url("https://eth.llamarpc.com#frag")

    def test_rejects_localhost(self, direct_vm):
        m = module(direct_vm)
        for u in ("https://localhost", "https://localhost:8443",
                  "https://rpc.localhost"):
            with pytest.raises(Exception):
                m._canonicalize_url(u)

    def test_rejects_internal_suffix(self, direct_vm):
        m = module(direct_vm)
        for u in ("https://node.internal", "https://node.corp",
                  "https://node.lan", "https://node.local",
                  "https://node.intranet", "https://node.home",
                  "https://metadata.google.internal"):
            with pytest.raises(Exception):
                m._canonicalize_url(u)

    def test_rejects_ipv4_literal(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._canonicalize_url("https://192.168.1.1")
        with pytest.raises(Exception):
            m._canonicalize_url("https://1.1.1.1")  # even public

    def test_rejects_ipv6_literal(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._canonicalize_url("https://[::1]")

    def test_rejects_bad_port(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._canonicalize_url("https://rpc.example.com:8545")

    def test_rejects_empty_host(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._canonicalize_url("https://")

    def test_rejects_too_long(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._canonicalize_url("https://" + "a" * 250 + ".com")

    def test_rejects_non_string(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._canonicalize_url(None)
        with pytest.raises(Exception):
            m._canonicalize_url(123)

    def test_hash_deterministic(self, direct_vm):
        m = module(direct_vm)
        _, h1 = m._canonicalize_url("https://rpc.example.com")
        _, h2 = m._canonicalize_url("https://RPC.EXAMPLE.COM ")
        assert h1 == h2  # same canonical -> same hash


# ---------------------------------------------------------------------------
# Chain-id validation
# ---------------------------------------------------------------------------

class TestChainId:
    def test_accepts_numeric_string(self, direct_vm):
        m = module(direct_vm)
        assert m._validate_chain_id("1") == 1
        assert m._validate_chain_id("8453") == 8453

    def test_accepts_int(self, direct_vm):
        m = module(direct_vm)
        assert m._validate_chain_id(137) == 137

    def test_rejects_empty_and_junk(self, direct_vm):
        m = module(direct_vm)
        for v in ("", "abc", "0x1", "-1", "1.5"):
            with pytest.raises(Exception):
                m._validate_chain_id(v)

    def test_rejects_zero_and_overflow(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._validate_chain_id("0")
        with pytest.raises(Exception):
            m._validate_chain_id(str(2**31))

    def test_rejects_bool(self, direct_vm):
        m = module(direct_vm)
        with pytest.raises(Exception):
            m._validate_chain_id(True)


# ---------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------

class TestParsers:
    def test_hex_quantity(self, direct_vm):
        m = module(direct_vm)
        assert m._hex_to_int_loose("0x1") == 1
        assert m._hex_to_int_loose("0x64") == 100
        assert m._hex_to_int_loose("0x0") == 0   # valid zero quantity
        assert m._hex_to_int_loose("64") is None  # no 0x
        assert m._hex_to_int_loose("0x") is None  # too short
        assert m._hex_to_int_loose("0xzz") is None
        assert m._hex_to_int_loose(None) is None
        assert m._hex_to_int_loose(12) is None

    def test_net_version_forms(self, direct_vm):
        m = module(direct_vm)
        assert m._net_version_to_int("1") == 1
        assert m._net_version_to_int("8453") == 8453
        assert m._net_version_to_int("0x2105") == 8453
        assert m._net_version_to_int("abc") is None
        assert m._net_version_to_int(None) is None
        assert m._net_version_to_int(1) is None

    def test_client_family(self, direct_vm):
        m = module(direct_vm)
        assert m._client_family(
            "Geth/v1.13.0/linux/go1.21") == "geth"
        assert m._client_family("besu/v24.1") == "besu"
        assert m._client_family("Nethermind/v1.25") == "nethermind"
        assert m._client_family("op-reth/v0.2") == "op-reth"
        assert m._client_family("") == ""
        assert m._client_family(None) == ""
        assert m._client_family("v1.2.3 xyz") == "v1"  # coarse token


# ---------------------------------------------------------------------------
# Contract surface: request/record lifecycle (no probing)
# ---------------------------------------------------------------------------

class TestRequestLifecycle:
    def test_request_check_binds_and_returns_id(self, direct_vm):
        c = deploy(direct_vm)
        cid = c.request_check("https://rpc.example.com", "1")
        assert cid == "chk-1"
        rec = json.loads(c.get_check(cid))
        assert rec["target_url"] == "https://rpc.example.com"
        assert rec["expected_chain_id"] == "1"
        assert rec["status"] == "REQUESTED"
        assert rec["classification"] == ""
        assert rec["requested_by"].startswith("0x")

    def test_sequential_ids(self, direct_vm):
        c = deploy(direct_vm)
        assert c.request_check(T_HOST, "1") == "chk-1"
        assert c.request_check(T_HOST, "1") == "chk-2"

    def test_get_check_not_found(self, direct_vm):
        c = deploy(direct_vm)
        with pytest.raises(Exception):
            c.get_check("chk-99")

    def test_run_consensus_on_missing_check(self, direct_vm):
        c = deploy(direct_vm)
        with pytest.raises(Exception):
            c.run_consensus("chk-99")

    def test_stats(self, direct_vm):
        c = deploy(direct_vm)
        s = json.loads(c.get_stats())
        assert s["check_count"] == "0"
        assert s["finalized_count"] == "0"
        c.request_check(T_HOST, "1")
        s = json.loads(c.get_stats())
        assert s["check_count"] == "1"

    def test_config_public(self, direct_vm):
        c = deploy(direct_vm)
        cfg = json.loads(c.get_config())
        assert cfg["schema_version"] == "1"
        assert cfg["probe_version"] == "1"
        assert "HEALTHY" in cfg["classifications"]
        assert cfg["reference_endpoints"]["1"] == R_HOST

    def test_history_view_empty(self, direct_vm):
        c = deploy(direct_vm)
        h = json.loads(c.get_history(T_HOST))
        assert h == []

    def test_get_check_by_target_not_found(self, direct_vm):
        c = deploy(direct_vm)
        r = json.loads(c.get_check_by_target(T_HOST))
        assert r["found"] is False

    def test_recent_checks_view(self, direct_vm):
        c = deploy(direct_vm)
        c.request_check(T_HOST, "1")
        c.request_check(T_HOST, "1")
        recs = json.loads(c.get_recent_checks(10))
        assert len(recs) == 2
        assert recs[0]["check_id"] == "chk-2"  # newest first
        assert recs[0]["target_host"] == "eth.llamarpc.com"
