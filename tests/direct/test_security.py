"""Security tests for RPC Sentinel: SSRF surface, untrusted input,
secrets hygiene, and the trust-boundary state machine.

Every URL the contract will ever fetch is either a fixed contract
constant (reference endpoints) or a canonicalized user target that
passed _canonicalize_url. These tests attack that guarantee.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import (  # noqa: E402
    deploy, install_rpc_router, target_script, reference_script,
    T_HOST, R_HOST,
)
from test_units import module  # noqa: E402


BAD_URLS = [
    # scheme / transport
    "http://rpc.example.com",
    "HTTP://rpc.example.com",
    "ftp://rpc.example.com",
    "file:///etc/passwd",
    "gopher://rpc.example.com",
    "ws://rpc.example.com",
    # credentials
    "https://user:pass@rpc.example.com",
    "https://user@rpc.example.com",
    # query / fragment (token carriers)
    "https://rpc.example.com/?token=secret",
    "https://rpc.example.com#frag",
    # loopback / internal
    "https://localhost",
    "https://localhost:8443",
    "https://rpc.localhost",
    "https://node.internal",
    "https://node.intranet",
    "https://node.corp",
    "https://node.lan",
    "https://node.home",
    "https://node.local",
    "https://metadata.google.internal",
    # raw IPs (SSRF classic)
    "https://127.0.0.1",
    "https://192.168.0.1",
    "https://10.0.0.1",
    "https://172.16.0.1",
    "https://169.254.169.254",   # cloud metadata service
    "https://0.0.0.0",
    "https://[::1]",
    "https://[fe80::1]",
    "https://[2001:db8::1]",
    # ports
    "https://rpc.example.com:8545",
    "https://rpc.example.com:22",
    "https://rpc.example.com:8080",
    # malformed
    "https://",
    "https://...",
    "https://-bad-.com",
    "https://rpc..example.com",
    "",
    "rpc.example.com",
    "https://" + "a" * 250 + ".com",
]

GOOD_URLS = [
    "https://eth.llamarpc.com",
    "https://rpc.example.com:8443",
    "https://rpc.example.com/v3/abc123",
    "https://RPC.EXAMPLE.COM",
    "  https://rpc.example.com  ",
]


class TestSSRFSurface:
    def test_bad_urls_rejected_at_request_time(self, direct_vm,
                                               direct_deploy):
        c = deploy(direct_vm)
        for u in BAD_URLS:
            with pytest.raises(Exception):
                c.request_check(u, "1")

    def test_bad_urls_rejected_in_canonicalizer(self, direct_vm):
        m = module(direct_vm)
        for u in BAD_URLS:
            with pytest.raises(Exception):
                m._canonicalize_url(u)

    def test_good_urls_accepted(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        for u in GOOD_URLS:
            cid = c.request_check(u, "1")
            assert cid.startswith("chk-")

    def test_canonical_never_contains_at_or_query(self, direct_vm):
        m = module(direct_vm)
        url, _ = m._canonicalize_url(
            "https://rpc.example.com/deep/path")
        assert "@" not in url and "?" not in url and "#" not in url


class TestUntrustedInput:
    def test_chain_id_bounds(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        for bad in ("0", "-5", "abc", "", "99999999999999999999",
                    "12.5", " 1.0"):
            with pytest.raises(Exception):
                c.request_check(T_HOST, bad)

    def test_unknown_chain_still_checkable(self, direct_vm,
                                           direct_deploy):
        """Chain 999999 has no reference endpoint: allowed; no
        reference fetch happens, bucket UNKNOWN, HEALTHY-eligible."""
        c = deploy(direct_vm)
        cid = c.request_check(T_HOST, "999999")
        # router with NO reference route: target only, serving the
        # actual chain id (999999 = 0xf423f)
        install_rpc_router(
            direct_vm,
            target={"url": T_HOST, "script": target_script(
                chain_id=hex(999999), net_version="999999")},
        )
        c.run_consensus(cid)
        rec = json.loads(c.get_check(cid))
        assert rec["classification"] == "HEALTHY"
        assert rec["freshness_bucket"] == "UNKNOWN"

    def test_reference_endpoints_are_https_public(self, direct_vm):
        m = module(direct_vm)
        for chain_id, url in m.REF_ENDPOINTS.items():
            assert url.startswith("https://")
            assert "@" not in url and "?" not in url
            canon, _ = m._canonicalize_url(url)
            assert canon == url


class TestNoSecrets:
    def test_contract_source_has_no_secrets(self, direct_vm):
        src = Path(Path(__file__).resolve().parents[2],
                   "contracts", "rpc_sentinel.py").read_text()
        low = src.lower()
        # precise tokens only — the docstring legitimately contains
        # the WORD "secrets" ("no secrets, api keys ... are stored").
        for bad in ("private_key", "apikey=", "api_key=", "password=",
                    "authorization:", "bearer ", "mnemonic",
                    "0x" + "0" * 40):
            assert bad not in low, f"secret-ish token in source: {bad}"
        # no 64-hex private-key-looking literal either
        import re as _re
        assert not _re.search(r'["\'][0-9a-f]{64}["\']', low)

    def test_storage_never_holds_credentials(self, direct_vm,
                                             direct_deploy):
        # a URL with credentials is refused BEFORE any storage write
        c = deploy(direct_vm)
        before = json.loads(c.get_stats())
        with pytest.raises(Exception):
            c.request_check("https://u:p@rpc.example.com", "1")
        after = json.loads(c.get_stats())
        assert before == after  # no state change on refusal


class TestStateMachine:
    def test_transport_failure_finalizes_unreachable(self, direct_vm,
                                                      direct_deploy):
        """With NO router installed, every fetch raises inside the
        probe. Direct mode runs the leader only, and the correct
        safe outcome is a FINALIZED, well-formed UNREACHABLE record
        with the network_error code — never garbage, never HEALTHY
        (brief §19: never silently convert an error into HEALTHY).

        The CONSENSUS_FAILED -> retry transition requires live
        multi-validator disagreement (direct mode cannot produce it
        through the public API); it is exercised by the Studionet
        smoke run's negative case."""
        c = deploy(direct_vm)
        cid = c.request_check(T_HOST, "1")
        c.run_consensus(cid)
        rec = json.loads(c.get_check(cid))
        assert rec["status"] == "FINALIZED"
        assert rec["classification"] == "UNREACHABLE"
        assert rec["failure_code"] == "network_error"
        assert rec["rpc_reachable"] == "false"
        assert rec["jsonrpc_valid"] == "false"
        s = json.loads(c.get_stats())
        assert s["finalized_count"] == "1"

    def test_history_append_only(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        for _ in range(3):
            cid = c.request_check(T_HOST, "1")
            install_rpc_router(
                direct_vm,
                target={"url": T_HOST, "script": target_script()},
                reference={"url": R_HOST,
                           "script": reference_script(block="0x101")},
            )
            c.run_consensus(cid)
        h = json.loads(c.get_history(T_HOST))
        assert len(h) == 3
        for entry in h:
            assert entry["classification"] == "HEALTHY"

    def test_latest_by_target_pointer(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        for _ in range(2):
            cid = c.request_check(T_HOST, "1")
            install_rpc_router(
                direct_vm,
                target={"url": T_HOST, "script": target_script()},
                reference={"url": R_HOST,
                           "script": reference_script(block="0x101")},
            )
            c.run_consensus(cid)
        got = json.loads(c.get_check_by_target(T_HOST))
        assert got["found"] is True
        assert got["check"]["check_id"] == "chk-2"

    def test_get_recent_checks_cap(self, direct_vm, direct_deploy):
        c = deploy(direct_vm)
        for _ in range(5):
            c.request_check(T_HOST, "1")
        recs = json.loads(c.get_recent_checks(3))
        assert len(recs) == 3
        recs = json.loads(c.get_recent_checks(50))
        assert len(recs) == 5
