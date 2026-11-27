"""solana_rpc (P215): getBalance + getSignaturesForAddress (limit 25) on the Solana JSON-RPC.

Fixtures in tests/fixtures/solana_rpc/ (prep batch p3-G09-2, captured 2026-11-26 from a datacenter
egress against api.mainnet-beta.solana.com; JSON-RPC bodies verbatim - they hold only protocol or
organisation accounts and a synthetic key):

* ``balance_ok.json`` / ``balance_ok_live.json`` - getBalance of the System Program (1 lamport), research
  sample and live capture;
* ``balance_zero_unused.json`` - the synthetic never-used key (base58 of sha256('v3lum-doc-solana-unused'));
* ``balance_zero_known_account.json`` - Circle's USDC mint answered 0 lamports: a FALSE empty (the account
  exists and holds >= 1,461,600 lamports), the reason empty answers are hedged and never cached;
* ``signatures_empty.json`` - live ``[]``;
* ``error_invalid_param.json`` - live JSON-RPC -32602 inside HTTP 200;
* ``headers_live.json`` - the live x-ratelimit-* / x-rpc-node headers and the exact requests sent;
* ``malformed_truncated.json`` - the first 50 bytes of a live answer;
* ``challenge_vercel.html`` - the Vercel Security Checkpoint (HTTP 429) of the solana.com evidence page;
* DERIVED (documented shapes, documentation values; never provoked live): ``signatures_ok_derived.json``
  (5 entries: one failed, one with a memo, one with a null blockTime; synthetic signatures = base58 of
  sha512('v3lum-doc-solana-signature-<n>')), ``signatures_full_page_derived.json`` (25 entries),
  ``rate_limited_429_derived.json``, ``blocked_403_derived.json``, ``disabled_410_derived.json`` and
  ``node_behind_derived.json`` (Agave -32005).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.core.providers import registry
from v3lum.modules.crypto import solana_rpc as sr
from v3lum.modules.crypto.solana_rpc import SolanaRpc

URL = "https://api.mainnet-beta.solana.com"
ADDR = "FEoEdUV1jQrToA1h25gVEj8hibA2eBajswoxjNGHbo1n"  # synthetic key nobody controls (documentation value)
SYSTEM_PROGRAM = "11111111111111111111111111111111"
TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
SEED = f"other_crypto_address:sol:{ADDR}"
JSON_HDRS = {"content-type": "application/json; charset=utf-8"}


def raw(name: str) -> bytes:
    return (FIXTURES / "solana_rpc" / name).read_bytes()


def reply(name: str, status: int = 200, headers: dict | None = None) -> dict:
    return {"body": raw(name), "status": status, "headers": {**JSON_HDRS, **(headers or {})}}


def live_headers(method: str) -> dict:
    return module_fixture("solana_rpc", "headers_live.json")[method]["headers"]


def rpc_http(balance: str = "balance_ok.json", signatures: str | None = "signatures_ok_derived.json", **kw) -> FakeHttp:
    http = FakeHttp().add("POST", URL, times=1, **reply(balance, headers=live_headers("getBalance")), **kw)
    if signatures is not None:
        http.add("POST", URL, times=1, **reply(signatures, headers=live_headers("getSignaturesForAddress")), **kw)
    return http


def bodies(http: FakeHttp) -> list[dict]:
    return [json.loads(c["body"]) for c in http.calls if c.get("body")]


def everything(res) -> str:
    return json.dumps({"a": res.attributes, "raw": res.raw, "f": [f.to_dict() for f in res.findings], "e": res.error}, default=str)


# ------------------------------------------------------------------ metadata (FC1, FC3)
def test_metadata_follows_the_council_decision():
    cls = SolanaRpc
    assert cls.terms == "open" and cls.trust_tier == "trusted" and cls.default_enabled is False
    assert cls.opsec.name == "PASSIVE" and cls.disclosure == "third_party" and cls.shares_input is True
    assert cls.provider == "solana_foundation" and cls.sources == ("solana_foundation.rpc", "internal_solana_rpc.rpc")
    assert cls.hosts == ("api.mainnet-beta.solana.com",) and cls.accepts == {T.CRYPTO} and not cls.produces
    assert cls.max_requests == 2 and cls.max_pivots == 0 and cls.cache_ttl == 3600
    assert cls.min_interval == 1.0 and cls.daily_quota == 1000 and cls.timeout >= 10
    prov = registry().get("solana_foundation")
    assert prov.tier == "trusted" and registry().source("solana_foundation.rpc").terms.class_ == "open"
    assert prov.quota.rate_per_second == 1.0 and prov.quota.day == 1000 and prov.quota.scope == "egress_ip"
    internal = registry().get("internal_solana_rpc")
    assert internal.internal is True and internal.hosts_from_settings == ("solana_rpc_url",)
    hc = cls.health_check()
    assert hc.etype is T.CRYPTO and hc.value == "sol:" + sr.CANARY_ACCOUNT and hc.selftest is not None


# ------------------------------------------------------------------ happy path (FC1, FC3)
def test_balance_and_recent_signatures_only():
    http = rpc_http()
    res = run_module(SolanaRpc, SEED, http)
    assert res.status is Status.OK
    sent = bodies(http)
    assert [b["method"] for b in sent] == ["getBalance", "getSignaturesForAddress"]
    assert sent[0]["params"] == [ADDR] and sent[1]["params"] == [ADDR, {"limit": 25}]
    assert all(b["jsonrpc"] == "2.0" and b["id"] == 1 for b in sent)
    a = res.attributes
    assert a["chain"] == "solana" and a["balance"] == "0.000000001 SOL" and a["balance_base_units"] == "1"
    sigs = a["recent_signatures"]
    assert len(sigs) == 5 and set(sigs[0]) == {"signature", "slot", "block_time", "failed", "confirmation_status"}
    assert [s["failed"] for s in sigs].count(True) == 1 and sigs[1]["failed"] is True
    assert any(s["block_time"] is None for s in sigs)  # a null blockTime is kept as unknown, never invented
    assert a["more_history"] is False and a["activity_window"]["first_seen_exact"] is True
    assert a["last_activity"] == a["activity_window"]["last_seen"] and a["activity_window"]["txs_examined"] == 5
    assert a["rpc_context"]["host"] == "api.mainnet-beta.solana.com" and a["rpc_context"]["node"] == "pit186"
    assert a["rpc_context"]["api_version"] == "4.4.0" and a["disclosed_to"] == ["api.mainnet-beta.solana.com"]
    assert not res.pivots  # FC3: no counterparties, token accounts or signature entities
    finding = res.findings[0]
    assert finding.severity.label == "info" and finding.source == "solana_foundation.rpc"
    assert "1 failed" in finding.description and finding.observed_last
    assert "memo" not in everything(res) and "doc-memo-001" not in everything(res)  # memos are free text: dropped
    http.assert_hosts_within(SolanaRpc)


def test_full_page_means_older_history_may_exist():
    http = rpc_http(signatures="signatures_full_page_derived.json")
    res = run_module(SolanaRpc, SEED, http)
    a = res.attributes
    assert len(a["recent_signatures"]) == 25 and a["more_history"] is True
    assert a["activity_window"]["first_seen_exact"] is False
    finding = res.findings[0]
    assert finding.observed_first is None and "older history exists" in finding.description


def test_an_rpc_ignoring_the_limit_is_cut_to_25():
    page = json.loads(raw("signatures_full_page_derived.json"))
    extra = json.loads(raw("signatures_ok_derived.json"))["result"]
    page["result"] = page["result"] + extra  # 30 entries
    http = FakeHttp().add("POST", URL, times=1, **reply("balance_ok.json")).add("POST", URL, times=1, json=page)
    res = run_module(SolanaRpc, SEED, http)
    assert len(res.attributes["recent_signatures"]) == 25 and res.raw["signatures"]["cut_to_limit"] is True


def test_live_research_sample_balance_parses():
    http = rpc_http(balance="balance_ok_live.json")
    res = run_module(SolanaRpc, f"other_crypto_address:sol:{SYSTEM_PROGRAM}", http)
    assert res.status is Status.OK and res.attributes["balance_base_units"] == "1"
    assert res.attributes["rpc_context"]["slot"] == 474097837


# ------------------------------------------------------------------ empty answers (rule 5, warning 1)
def test_zero_balance_and_no_signatures_is_a_hedged_empty():
    http = rpc_http(balance="balance_zero_unused.json", signatures="signatures_empty.json")
    res = run_module(SolanaRpc, SEED, http)
    assert res.status is Status.EMPTY and not res.findings
    status = res.attributes["wallet_status"]
    assert "not proof that the address was never used" in status and "unused" not in status.replace("never used", "")


def test_false_empty_answers_are_never_cached():
    # the public RPC answered 0/[] for Circle's USDC mint: such an answer must not be replayed for 1 h
    http = FakeHttp()
    for _ in range(2):
        http.add("POST", URL, times=1, **reply("balance_zero_known_account.json"))
        http.add("POST", URL, times=1, **reply("signatures_empty.json"))
    rt = make_runtime(http, cache=True)
    for _ in range(2):
        res = run_module(SolanaRpc, f"other_crypto_address:sol:{sr.CANARY_ACCOUNT}", http, runtime=rt)
        assert res.status is Status.EMPTY
    assert len(http.calls) == 4  # every run asked again


def test_answers_with_data_are_cached_per_request_body():
    http = rpc_http()
    rt = make_runtime(http, cache=True)
    first = run_module(SolanaRpc, SEED, http, runtime=rt)
    second = run_module(SolanaRpc, SEED, http, runtime=rt)
    assert first.status is second.status is Status.OK and len(http.calls) == 2  # balance and signatures cached apart
    assert second.attributes["recent_signatures"] == first.attributes["recent_signatures"]


# ------------------------------------------------------------------ FC2: explicit Solana inputs only
def test_a_bare_base58_seed_is_never_sent_without_confirmation():
    http = FakeHttp()  # any request would fail the test
    res = run_module(SolanaRpc, f"other_crypto_address:{ADDR}", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert "sol:<address>" in res.error and http.calls == []


def test_a_bare_seed_runs_when_the_analyst_selected_the_module():
    http = rpc_http()
    res = run_module(SolanaRpc, f"other_crypto_address:{ADDR}", http, options=ScanOptions(include={"solana_rpc"}))
    assert res.status is Status.OK and bodies(http)[0]["params"] == [ADDR]
    assert res.raw["rpc"]["basis"] == "analyst_selected"


def test_prefix_variants_are_explicit():
    for value in (f"sol:{ADDR}", f"SOL:{ADDR}", f"solana:{ADDR}"):
        assert sr.parse_solana_input(value) == (ADDR, True)
    assert sr.parse_solana_input(f"solana:{ADDR}?amount=1&memo=x") == (ADDR, True)  # Solana Pay: recipient only
    assert sr.parse_solana_input(ADDR) == (ADDR, False)
    assert sr.parse_solana_input("sol:not-a-solana-address") == (None, False)
    assert sr.parse_solana_input(TRON) == (None, False)  # 25-byte base58check: not a 32-byte key
    assert sr.parse_solana_input("0OIl" * 10) == (None, False)  # characters outside base58


def test_pivots_run_only_from_solana_specific_sources():
    http = FakeHttp()
    res = run_module(SolanaRpc, SEED, http, is_seed=False, depth=1,
                     provenance=[("other_crypto_address:x", "listed_with", "crypto_sanctions_offline")])
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []
    assert "crypto_sanctions_offline" in res.error
    gate = sr.solana_input_gate(ADDR, is_seed=False, explicitly_selected=False, parent_module="solana_source",
                                solana_sources=frozenset({"solana_source"}))
    assert gate["run"] is True and gate["basis"] == "solana_pivot"
    assert not sr.SOLANA_SPECIFIC_SOURCES  # no approved Solana pivot source in this build


def test_an_unconfirmed_seed_is_not_an_explicit_input():
    http = FakeHttp()
    res = run_module(SolanaRpc, f"other_crypto_address:{ADDR}", http, is_seed=False, options=ScanOptions(include={"solana_rpc"}))
    assert res.status is Status.SKIPPED and http.calls == []


def test_non_solana_values_are_not_applicable():
    http = FakeHttp()
    for value in (f"other_crypto_address:{TRON}", "other_crypto_address:sol:notasolanaaddress0000000"):
        res = run_module(SolanaRpc, value, http, options=ScanOptions(include={"solana_rpc"}))
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


# ------------------------------------------------------------------ could not verify (rule 5, P321)
@pytest.mark.parametrize("status", [200, 429])
def test_json_rpc_429_is_rate_limited(status):
    http = FakeHttp().add("POST", URL, **reply("rate_limited_429_derived.json", status=status))
    res = run_module(SolanaRpc, SEED, http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


@pytest.mark.parametrize("status", [200, 403])
def test_egress_block_is_blocked(status):
    http = FakeHttp().add("POST", URL, **reply("blocked_403_derived.json", status=status))
    res = run_module(SolanaRpc, SEED, http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_bare_403_and_401_are_blocked_for_a_keyless_source():
    for status in (401, 403):
        http = FakeHttp().add("POST", URL, status=status, text="Forbidden")
        res = run_module(SolanaRpc, SEED, http)
        assert res.status is Status.BLOCKED


def test_a_bot_wall_answering_429_is_a_challenge_not_a_rate_limit():
    http = FakeHttp().add("POST", URL, status=429, body=raw("challenge_vercel.html"),
                          headers={"content-type": "text/html; charset=utf-8", "server": "Vercel", "x-vercel-mitigated": "challenge"})
    res = run_module(SolanaRpc, SEED, http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_disabled_call_is_an_error():
    for status in (200, 410):
        http = FakeHttp().add("POST", URL, **reply("disabled_410_derived.json", status=status))
        res = run_module(SolanaRpc, SEED, http)
        assert res.status is Status.ERROR


@pytest.mark.parametrize(("fixture", "words"), [("error_invalid_param.json", "invalid param"), ("node_behind_derived.json", "node unhealthy or behind")])
def test_json_rpc_errors_inside_http_200_are_errors_and_never_cached(fixture, words):
    http = FakeHttp().add("POST", URL, times=2, **reply(fixture))
    rt = make_runtime(http, cache=True)
    for _ in range(2):
        res = run_module(SolanaRpc, SEED, http, runtime=rt)
        assert res.status is Status.ERROR and words in res.error and "could not verify" in res.error
    assert len(http.calls) == 2


def test_malformed_json_is_an_error():
    http = FakeHttp().add("POST", URL, **reply("malformed_truncated.json"))
    res = run_module(SolanaRpc, SEED, http)
    assert res.status is Status.ERROR and "malformed" in res.error


@pytest.mark.parametrize("body", [
    {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 1}, "value": "1"}},  # string lamports
    {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 1}, "value": True}},  # bool
    {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 1}, "value": -5}},
    {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 1}, "value": 2**64}},
    {"jsonrpc": "2.0", "id": 1, "result": [1, 2]},
    {"jsonrpc": "2.0", "id": 7, "result": {"context": {"slot": 1}, "value": 1}},  # id mismatch
    {"jsonrpc": "1.0", "id": 1, "result": {"context": {"slot": 1}, "value": 1}},
    [{"jsonrpc": "2.0", "id": 1, "result": {"value": 1}}],  # batch array
    {"jsonrpc": "2.0", "id": 1},
])
def test_unexpected_balance_answers_are_errors(body):
    http = FakeHttp().add("POST", URL, json=body)
    res = run_module(SolanaRpc, SEED, http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_html_instead_of_json_rpc_is_an_error():
    http = FakeHttp().add("POST", URL, text="<html><body>maintenance</body></html>")
    res = run_module(SolanaRpc, SEED, http)
    assert res.status is Status.ERROR and "HTML" in res.error


def test_server_errors_and_dead_network_are_errors():
    http = FakeHttp().add("POST", URL, status=500, text="oops")
    assert run_module(SolanaRpc, SEED, http).status is Status.ERROR
    dead = FakeHttp().add("POST", URL, error=NetworkError("connection timed out"))
    res = run_module(SolanaRpc, SEED, dead)
    assert res.status is Status.ERROR and res.reason_code in ("error", "timeout")


# ------------------------------------------------------------------ partial runs and the provider's own budget
def test_rate_limit_on_the_second_call_keeps_the_balance():
    http = (FakeHttp().add("POST", URL, times=1, **reply("balance_ok.json"))
            .add("POST", URL, **reply("rate_limited_429_derived.json", status=429)))
    res = run_module(SolanaRpc, SEED, http)
    assert res.status is Status.OK and res.partial is True and res.stop_reason == "rate_limited"
    assert res.attributes["balance"] == "0.000000001 SOL" and "recent_signatures" not in res.attributes


def test_an_exhausted_provider_bucket_stops_before_the_second_call():
    headers = {**live_headers("getBalance"), "x-ratelimit-rps-remaining": "0"}
    http = FakeHttp().add("POST", URL, times=1, **reply("balance_ok.json", headers=headers))
    res = run_module(SolanaRpc, SEED, http)
    assert len(http.calls) == 1 and res.partial is True and res.stop_reason == "rate_limited"
    assert res.status is Status.OK and "rps request budget exhausted" in res.error


def test_unlimited_and_per_method_buckets_never_stop_the_run():
    headers = live_headers("getBalance")  # endpoint 'unlimited' with remaining -16712
    assert int(headers["x-ratelimit-endpoint-remaining"]) < 0 and sr.ratelimit_exhausted(headers) == ""
    assert sr.ratelimit_exhausted({**headers, "x-ratelimit-method-remaining": "0", "x-ratelimit-pubsub-remaining": "0"}) == ""
    assert "connrate" in sr.ratelimit_exhausted({**headers, "x-ratelimit-connrate-remaining": "-1"})


def test_a_json_rpc_error_on_the_signatures_call_is_reported_with_the_balance():
    http = rpc_http(signatures="node_behind_derived.json")
    res = run_module(SolanaRpc, SEED, http)
    assert res.status is Status.ERROR and res.error.startswith("balance read; recent signatures")
    assert res.attributes["balance"] == "0.000000001 SOL"


@pytest.mark.parametrize("result", [{"not": "a list"}, [{"signature": "junk"}, 3]])
def test_unexpected_signature_answers_are_errors(result):
    http = FakeHttp().add("POST", URL, times=1, **reply("balance_ok.json")).add("POST", URL, json={"jsonrpc": "2.0", "id": 1, "result": result})
    res = run_module(SolanaRpc, SEED, http)
    assert res.status is Status.ERROR and "could not verify" in res.error


# ------------------------------------------------------------------ configurable RPC (FC1)
def test_the_configured_node_is_used_instead_of_the_public_rpc():
    node = "https://solana-rpc.corp.example/rpc"
    http = (FakeHttp().add("POST", node, times=1, **reply("balance_ok.json"))
            .add("POST", node, times=1, **reply("signatures_ok_derived.json")))
    res = run_module(SolanaRpc, SEED, http, settings={"solana_rpc_url": node})
    assert res.status is Status.OK and http.urls() == [node, node]
    a = res.attributes
    assert a["rpc_context"]["internal"] is True and "disclosed_to" not in a  # nothing left the organisation
    assert res.findings[0].source == "internal_solana_rpc.rpc"
    http.assert_hosts_within(SolanaRpc)


@pytest.mark.parametrize("url", [
    "http://solana-rpc.corp.example/",
    "https://user:pw@solana-rpc.corp.example/",
    "https://10.0.0.5:8899/",
    "https://solana-node/",
    "https://api.devnet.solana.com",
    "https://mainnet.helius-rpc.example/?api-key=00000000-0000-0000-0000-000000000000",
    "https://example-node.solana-mainnet.quiknode.example/abc123def456ghi789jkl0/",
    "not a url",
])
def test_a_refused_rpc_setting_is_skipped_config_before_any_request(url):
    http = FakeHttp()
    res = run_module(SolanaRpc, SEED, http, settings={"solana_rpc_url": url})
    assert res.status is Status.SKIPPED and res.reason_code == "config" and http.calls == []
    assert "00000000-0000" not in res.error and "abc123def456" not in res.error  # the credential never echoes


def test_the_public_url_in_the_setting_stays_the_public_source():
    endpoint = sr.rpc_endpoint("https://api.mainnet-beta.solana.com")
    assert endpoint["ok"] and endpoint["source"] == "solana_foundation.rpc" and endpoint["internal"] is False
    assert sr.rpc_endpoint("")["url"] == URL
    assert sr.rpc_endpoint("https://solana-node.corp.example/solana-mainnet-rpc")["ok"] is True  # words, not a token


def test_a_source_outside_the_licence_profile_is_skipped():
    http = FakeHttp()
    res = run_module(SolanaRpc, SEED, http, allowed_sources={"internal_solana_rpc.rpc"})
    assert res.status is Status.SKIPPED and res.reason_code == "licence" and http.calls == []


# ------------------------------------------------------------------ requests and parsers
def test_only_the_two_read_only_methods_can_be_built():
    for method in ("sendTransaction", "requestAirdrop", "getTransaction", "getTokenAccountsByOwner"):
        with pytest.raises(ValueError):
            sr.build_rpc_request(method, ADDR)
    with pytest.raises(ValueError):
        sr.build_rpc_request("getBalance", "not-a-solana-address")
    assert sr.build_rpc_request("getSignaturesForAddress", ADDR, limit=500)["params"][1] == {"limit": 25}
    assert sr.clamp_limit(0) == 1 and sr.clamp_limit(True) == 25 and sr.clamp_limit("9") == 25
    live = module_fixture("solana_rpc", "headers_live.json")
    for method in ("getBalance", "getSignaturesForAddress"):
        assert sr.build_rpc_request(method, sr.CANARY_ACCOUNT) == live[method]["request"]  # what was verified live


def test_lamports_are_formatted_exactly():
    assert sr.format_sol(1) == "0.000000001" and sr.format_sol(1_000_000_000) == "1"
    assert sr.format_sol(1_461_600) == "0.0014616" and sr.format_sol(-1) is None and sr.format_sol(True) is None


def test_signature_parser_drops_memos_and_junk():
    doc = json.loads(raw("signatures_ok_derived.json"))
    parsed = sr.parse_signatures([{"signature": "x"}, "junk"] + doc["result"])
    assert parsed["count"] == 5 and parsed["skipped"] == 2 and "memo" not in json.dumps(parsed)
    assert parsed["failed_count"] == 1 and parsed["newest"] > parsed["oldest"]
    assert sr.parse_signatures([]) == {**sr.parse_signatures([]), "count": 0, "page_full": False}
    assert sr.parse_signatures([{"signature": "x"}]) is None and sr.parse_signatures({}) is None


def test_cache_veto_keeps_only_answers_with_data():
    class R:
        def __init__(self, name: str):
            self.content = raw(name)

    assert sr.cacheable_answer(R("balance_ok.json")) and sr.cacheable_answer(R("signatures_ok_derived.json"))
    for name in ("balance_zero_unused.json", "signatures_empty.json", "error_invalid_param.json", "malformed_truncated.json"):
        assert not sr.cacheable_answer(R(name))


# ------------------------------------------------------------------ health check (canary, warning 1)
def _selftest(http: FakeHttp):
    ctx = make_ctx(SolanaRpc, http)
    return SolanaRpc._canary_selftest(ctx)


def test_canary_detects_the_false_zero():
    result = _selftest(FakeHttp().add("POST", URL, **reply("balance_zero_known_account.json")))
    assert result.status == "dead" and "not reliable" in result.detail


def test_canary_passes_on_a_plausible_balance_and_maps_refusals():
    ok = {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 5}, "value": 1_461_600}}
    assert _selftest(FakeHttp().add("POST", URL, json=ok)).status == "ok"
    assert _selftest(FakeHttp().add("POST", URL, **reply("rate_limited_429_derived.json", status=429))).status == "quota"
    assert _selftest(FakeHttp().add("POST", URL, **reply("blocked_403_derived.json"))).status == "blocked"
    assert _selftest(FakeHttp().add("POST", URL, **reply("error_invalid_param.json"))).status == "dead"
    http = FakeHttp().add("POST", URL, json=ok)
    _selftest(http)
    assert bodies(http)[0]["params"] == [sr.CANARY_ACCOUNT]  # the probe never sends an investigated value
