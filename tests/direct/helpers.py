"""Shared direct-mode test helpers for RPC Sentinel.

The gltest direct-mode web mock matches ONLY (url-regex, HTTP method)
— it cannot distinguish two JSON-RPC calls to the same URL (all six
probe requests are POSTs to one endpoint). So RPC Sentinel tests use
the VM's live-web-handler hook with a scripted RPC router: the
handler parses the JSON-RPC `method` from the request body and serves
from a per-(url, method) script table. Every response is explicit —
nothing hits a real network.

  - script_rpc(): register a handler for one endpoint
  - rpc(): well-formed JSON-RPC response body builder
  - deploy(): deploy the contract under test
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = str(ROOT / "contracts" / "rpc_sentinel.py")

# Mock targets used across tests (hosts only; nothing here is claimed
# healthy — live behavior is proven by the Studionet smoke run only).
T_HOST = "https://eth.drpc.org"                # target endpoint (mock key only)
R_HOST = "https://ethereum-rpc.publicnode.com"  # chain-1 reference

GETH = "Geth/v1.13.0-omnibus/linux-amd64/go1.21.5"


def rpc(result, error=None):
    """Well-formed JSON-RPC 2.0 response body (str)."""
    if error is not None:
        return json.dumps({"jsonrpc": "2.0", "id": 1, "error": error})
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result})


ERR_METHOD_NOT_FOUND = {"code": -32601, "message": "method not found"}


def install_rpc_router(vm, *, target=None, reference=None):
    """Install one URL-aware router serving target and reference.

    target / reference: dicts {"url": ..., "script": {...}} built by
    target_script()/reference_script() helpers below.
    """
    routes = {}
    if target:
        routes[target["url"]] = target["script"]
    if reference:
        routes[reference["url"]] = reference["script"]

    counters = {}

    def handler(data):
        url = data.get("url", "")
        script = routes.get(url)
        if script is None:
            raise ConnectionError(f"no script for {url}")
        body = data.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        try:
            method = json.loads(body).get("method", "")
        except Exception:
            method = ""
        out = script.get(method, rpc(None, error=ERR_METHOD_NOT_FOUND))
        # list-valued entries serve in order (stability/flap tests):
        # [first_response, second_response, then_second_repeats]
        if isinstance(out, list):
            key = (url, method)
            i = counters.get(key, 0)
            counters[key] = i + 1
            out = out[i] if i < len(out) else out[-1]
        if out is None:
            raise ConnectionError("scripted network failure")
        st = 200
        if isinstance(out, tuple):
            st, out = out
        return {
            "ok": {
                "response": {
                    "status": st,
                    "headers": {},
                    "body": out.encode("utf-8") if isinstance(out, str) else out,
                }
            }
        }

    vm._live_web_handler = handler


def target_script(
    *,
    chain_id="0x1",
    chain_id2=None,
    block="0x100",
    block2=None,
    net_version="1",
    client=GETH,
    raw=None,
    fail_all=False,
):
    """Build a target script (see install_rpc_router)."""
    cid2 = chain_id if chain_id2 is None else chain_id2
    blk2 = block if block2 is None else block2
    script = {
        "eth_chainId": rpc(chain_id),
        "eth_blockNumber": rpc(block),
    }
    if net_version is not None:
        script["net_version"] = rpc(net_version)
    if client is not None:
        script["web3_clientVersion"] = rpc(client)
    if fail_all:
        script = {k: None for k in (
            "eth_chainId", "eth_blockNumber", "net_version",
            "web3_clientVersion")}
    if chain_id2 is not None:
        script["eth_chainId"] = [rpc(chain_id), rpc(chain_id2)]
    if block2 is not None:
        script["eth_blockNumber"] = [rpc(block), rpc(block2)]
    if raw:
        script.update(raw)
    return script


def reference_script(
    *,
    chain_id="0x1",
    block="0x101",
    broken=False,
    raw=None,
):
    """Build a reference script (see install_rpc_router). broken=True
    serves transport failure on every method."""
    if broken:
        return {k: None for k in ("eth_chainId", "eth_blockNumber")}
    script = {
        "eth_chainId": rpc(chain_id),
        "eth_blockNumber": rpc(block),
    }
    if raw:
        script.update(raw)
    return script


def deploy(vm, contract_path=CONTRACT):
    from gltest.direct.loader import deploy_contract
    return deploy_contract(contract_path, vm)
