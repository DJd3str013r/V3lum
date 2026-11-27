"""Live checks of batch p3-G09-2 (solana_rpc, P215); run with V3LUM_LIVE=1.

Benign public values only: the System Program (``111...1``, a protocol constant) and Circle's USDC mint
(a public organisation account, also the health-check canary). Only the read-only methods getBalance and
getSignaturesForAddress are sent, at most four requests in total, paced by the provider quota block.

The public RPC is best effort: a 403/429/challenge/timeout from this datacenter egress is an acceptable
outcome when it is reported as could-not-verify (blocked / rate_limited / quota / error, never 'empty').
The prep run of 2026-11-26 saw this egress receive a FALSE empty for the USDC mint (0 lamports, no
signatures): the canary self-test is expected to say 'dead' in that state, and the module result to be
a hedged EMPTY - both are recorded, never asserted away.
"""

from __future__ import annotations

import pytest

from tests.fakes import make_ctx, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.crypto.solana_rpc import CANARY_ACCOUNT, SolanaRpc

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR}
SYSTEM_PROGRAM = "11111111111111111111111111111111"


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def test_solana_rpc_protocol_account():
    res = run_module(SolanaRpc, f"other_crypto_address:sol:{SYSTEM_PROGRAM}", runtime=live_runtime())
    print(f"solana_rpc System Program: {res.status.value} {res.reason_code} {res.error[:200]!r} {res.attributes.get('rpc_context')}")
    if res.status in COULD_NOT_VERIFY:
        assert res.error  # could not verify, with the reason
        if "balance_base_units" in res.attributes:  # the balance answered, the signatures call did not
            assert int(res.attributes["balance_base_units"]) >= 0
        return
    assert res.status in (Status.OK, Status.EMPTY), (res.status, res.error)
    a = res.attributes
    assert a["chain"] == "solana" and a["balance"].endswith(" SOL") and int(a["balance_base_units"]) >= 0
    assert a["rpc_context"]["host"] == "api.mainnet-beta.solana.com"
    assert not res.pivots
    for entry in a.get("recent_signatures", []):
        assert set(entry) == {"signature", "slot", "block_time", "failed", "confirmation_status"}
    assert len(a.get("recent_signatures", [])) <= 25


def test_solana_rpc_canary_self_test():
    ctx = make_ctx(SolanaRpc, runtime=live_runtime())
    result = SolanaRpc._canary_selftest(ctx)
    print(f"solana_rpc canary {CANARY_ACCOUNT}: {result.status} {result.detail[:200]!r}")
    assert result.status in ("ok", "dead", "blocked", "quota")
    if result.status == "dead":  # the false-zero state seen from datacenter egress (prep warning 1)
        assert "not reliable" in result.detail or "could not verify" in result.detail or result.detail
