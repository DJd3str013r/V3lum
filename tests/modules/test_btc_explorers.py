"""btc_explorers / btc_esplora_internal (P211): one Esplora parser, sequential failover, summary, pivots.

Fixtures in tests/fixtures/btc_explorers/ (prep batch p2-G09-2, recorded 2026-11-26 from blockstream.info,
mempool.space, litecoinspace.org, blockchain.info and api.blockcypher.com keyless; minimised; every wallet
other than the public genesis address 1A1zP1... was replaced consistently by documentation/test-vector
addresses (Bitcoin wiki, BIP-84/86/173/350); empty-case addresses were freshly minted random ones). Files
with ``docshape`` are the documented schema (Blockchair needs the commercial key; no capture possible).
``blockchair_rate_limited_430.json`` is the real answer our egress got on the second keyless call.
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, assert_no_secret, make_runtime, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.modules.crypto import btc_explorers as be
from v3lum.modules.crypto.btc_explorers import BtcEsploraInternal, BtcExplorers

GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
EMPTY_BTC = "bc1q56wquxqw3wxuggm6m3fu52dglkgljm8yr7k225"
EMPTY_LTC = "ltc1qzn9caqwrf3qgkc3hrvy3sph0qzvurrk0f3mznm"
EMPTY_DOGE = "DEFw37aJW6oPxB1VX41zBsmwVJok656iMS"
DASH = "XagqqFetxiDb9wbartKDrXgnqLah6SqX2S"  # version 0x4c + 20 zero bytes (test value)
BS = "https://blockstream.info/api"
MP = "https://mempool.space/api"
LS = "https://litecoinspace.org/api"
PAGE2_AFTER = "9cc9edd11f8ae17d41c3d3762625c8a36368a4a60be3952962aabe1d75904259"
INTERNAL = "https://esplora.corp.example/api"
BLOCKCHAIR_KEY = "bc-commercial-key-0123456789abcdef"
BLOCKCYPHER_TOKEN = "bcy-token-0123456789abcdef0123"


def raw(name: str) -> bytes:
    return (FIXTURES / "btc_explorers" / name).read_bytes()


def js(name: str) -> dict:
    return {"body": raw(name), "headers": {"content-type": "application/json"}}


def esplora_routes(http: FakeHttp, base: str, address: str = GENESIS, *, page2: bool = True) -> FakeHttp:
    http.add("GET", f"{base}/address/{address}", **js("esplora_address_ok.json"))
    http.add("GET", f"{base}/address/{address}/txs", **js("esplora_txs_ok.json"))
    if page2:
        http.add("GET", f"{base}/address/{address}/txs/chain/{PAGE2_AFTER}", **js("esplora_txs_page2_ok.json"))
    http.add("GET", f"{base}/blocks/tip/height", body=raw("esplora_tip_height.txt"), headers={"content-type": "text/plain"})
    return http


# ------------------------------------------------------------------ metadata (cond 6)
def test_metadata_follows_the_council_decision():
    cls = BtcExplorers
    assert cls.terms == "key-terms" and cls.trust_tier == "community" and cls.default_enabled is True
    assert cls.disclosure == "third_party" and cls.opsec is Opsec.PASSIVE and cls.shares_input is True
    assert set(cls.hosts) == {"blockstream.info", "mempool.space", "litecoinspace.org", "blockchain.info", "api.blockcypher.com",
                              "api.blockchair.com"}
    assert cls.optional_keys == ("blockcypher", "blockchair") and cls.max_requests <= 10 and cls.cache_ttl == 3600
    assert cls.terms_sources == {"internal_esplora.esplora": "open", "blockstream.esplora_api": "open", "mempool_space.esplora_api": "open",
                                 "litecoinspace.esplora_api": "open", "blockchain_com.data_api": "open", "blockcypher.api": "key-terms",
                                 "blockchair.api": "key-terms"}
    internal = BtcEsploraInternal
    assert internal.disclosure == "internal" and internal.terms == "open" and internal.hosts == () and internal.default_enabled is True
    assert getattr(internal.max_tlp, "name", "") == "RED"
    # per-adapter terms and tiers (cond 6)
    tiers = {k: v["tier"] for k, v in be.UTXO_PROVIDERS.items()}
    assert tiers == {"esplora_internal": "n/a", "blockstream": "trusted", "mempool": "community", "litecoinspace": "community",
                     "blockchain_com": "trusted", "blockcypher": "trusted", "blockchair": "trusted"}
    assert {k for k, v in be.UTXO_PROVIDERS.items() if v["terms"] == "key-terms"} == {"blockcypher", "blockchair"}


def test_failover_plan_order_keys_and_licence_filter():
    assert be.utxo_failover_plan("btc") == ["blockstream", "mempool", "blockchain_com"]
    assert be.utxo_failover_plan("btc", {"btc": INTERNAL}, {"blockchair"}) == ["esplora_internal", "blockstream", "mempool", "blockchain_com", "blockchair"]
    assert be.utxo_failover_plan("ltc") == ["litecoinspace", "blockcypher"]
    assert be.utxo_failover_plan("doge") == ["blockcypher"]
    assert be.utxo_failover_plan("btc", {"btc": INTERNAL}, internal_only=True) == ["esplora_internal"]
    assert be.utxo_failover_plan("btc", internal_only=True) == []
    allowed = frozenset({"blockstream.esplora_api", "blockchain_com.data_api"})  # e.g. AMBER+STRICT drops community adapters
    assert be.utxo_failover_plan("btc", allowed=allowed) == ["blockstream", "blockchain_com"]
    assert be.should_failover("rate_limited") and be.should_failover("error") and not be.should_failover("empty")


def test_address_validation_picks_the_chain_and_never_sends_invalid_values():
    assert be.address_chain(GENESIS) == "btc" and be.address_chain(EMPTY_LTC) == "ltc"
    assert be.address_chain(EMPTY_DOGE) == "doge" and be.address_chain(DASH) == "dash"
    assert be.address_chain("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb") is None  # bad checksum
    http = FakeHttp()
    res = run_module(BtcExplorers, "other_crypto_address:0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


# ------------------------------------------------------------------ parsers (cond 1, 2, 5)
def test_one_esplora_parser_balance_is_funded_minus_spent():
    s = be.parse_esplora_address(raw("esplora_address_ok.json"))
    assert s["balance"] == 5772103060 and s["tx_count"] == 67599 and not s["is_empty"]
    assert be.units_str(s["balance"], 8) == "57.72103060"
    assert be.parse_esplora_address(raw("litecoinspace_address_empty.json"))["is_empty"] is True
    assert be.parse_esplora_address(b"<html>nope</html>") is None and be.parse_esplora_address(b"{") is None
    assert be.parse_esplora_tip_height(raw("esplora_tip_height.txt")) == 977642
    txs = be.parse_esplora_txs(raw("esplora_txs_ok.json"))
    assert len(txs) == 6 and txs[0]["time"] == "2026-11-25T23:31:48Z" and txs[0]["block_height"] == 977587
    assert be.parse_esplora_txs(raw("esplora_txs_empty.json")) == []


def test_blockchain_com_and_blockcypher_and_blockchair_parsers():
    r = be.parse_blockchain_rawaddr(raw("blockchain_rawaddr_ok.json"))
    assert r["summary"]["balance"] == 10773139348 and r["summary"]["tx_count"] == 67617 and len(r["txs"]) == 3
    m = be.parse_blockchain_multiaddr(raw("blockchain_multiaddr_ok.json"))
    assert m["addresses"][EMPTY_BTC]["is_empty"] is True and m["tip_height"]
    assert all(t["outputs_filtered"] for t in m["txs"])  # never used for counterparties
    assert be.utxo_counterparties(m["txs"], GENESIS) == []
    assert be.multiaddr_active_param([GENESIS, EMPTY_BTC, "bad|value"]) == f"{GENESIS}%7C{EMPTY_BTC}"
    assert be.parse_blockchain_balance(raw("blockchain_balance_empty.json"))[EMPTY_BTC]["tx_count"] == 0
    assert be.blockchain_error(raw("blockchain_rawaddr_invalid_404.json")).startswith("not-found-or-invalid-arg")
    bc = be.parse_blockcypher_full(raw("blockcypher_full_ok.json"))
    assert bc["summary"]["has_more"] and len(bc["txs"]) == 2 and be.blockcypher_next_before(bc) == 977582
    assert be.parse_blockcypher_chain(raw("blockcypher_chain_ltc.json"))["height"] == 3219589
    assert be.blockcypher_error(raw("blockcypher_invalid_address_400.json")).endswith("non-matching checksum.")
    d = be.parse_blockchair_dashboard(raw("blockchair_dashboard_ok_docshape.json"), GENESIS)
    assert d["summary"]["first_seen"] == "2009-01-03T18:15:05Z" and d["context"]["tip_height"] == 977642
    assert be.blockchair_status(raw("blockchair_rate_limited_430.json"), 430)[0] == "rate_limited"
    assert be.blockchair_status(b'{"data":null,"context":{"code":402,"error":"x"}}', 402)[0] == "quota"
    assert be.blockchair_status(b'{"data":null,"context":{"code":434}}', 434)[0] == "blocked"


def test_counterparties_are_proportional_and_skip_change():
    tx_in = {"txid": "a", "time": "2026-01-01T00:00:00Z", "inputs": [{"address": "S1", "value": 300}, {"address": "S2", "value": 100}],
             "outputs": [{"address": "ME", "value": 200}, {"address": "S1", "value": 190}]}
    tx_out = {"txid": "b", "time": "2026-01-02T00:00:00Z", "inputs": [{"address": "ME", "value": 500}],
              "outputs": [{"address": "R1", "value": 400}, {"address": "ME", "value": 90}]}
    recs = {r["address"]: r for r in be.utxo_counterparties([tx_in, tx_out], "ME")}
    assert recs["S1"]["received_from"] == 150 and recs["S2"]["received_from"] == 50 and recs["S1"]["direction"] == "in"
    assert recs["R1"]["sent_to"] == 400 and recs["R1"]["direction"] == "out" and "ME" not in recs  # change excluded
    top = be.top_counterparties(list(recs.values()), 2)
    assert [t["address"] for t in top] == ["R1", "S1"] and top[0]["label"] == "counterparty (role unknown)"


# ------------------------------------------------------------------ happy path (cond 1, 3, 5)
def test_blockstream_answers_and_the_summary_is_complete():
    http = esplora_routes(FakeHttp(), BS)
    res = run_module(BtcExplorers, f"btc_address:{GENESIS}", http)
    assert res.status is Status.OK
    assert http.hosts() == {"blockstream.info"}  # sequential: nobody else saw the address
    a = res.attributes
    assert a["chain"] == "bitcoin" and a["balance"] == "57.72103060 BTC" and a["balance_base_units"] == "5772103060"
    assert a["tx_count"] == 67599 and a["total_sent"] == "0.00000000 BTC"
    assert a["activity_window"]["first_seen_exact"] is False and a["activity_window"]["txs_examined"] == 8
    assert "first_seen" not in a and a["last_seen"] == "2026-11-25T23:31:48Z"  # first activity is a sample: not claimed
    fresh = a["data_freshness"]
    assert fresh["provider"] == "blockstream" and fresh["provider_tip_height"] == 977642 and fresh["blocks_since_latest_tx"] == 55
    fo = a["explorer_failover"]
    assert fo["answered_by"] == "blockstream" and fo["order"] == ["blockstream"] and a["disclosed_to"] == ["blockstream"]
    pivots = [p for p in res.pivots if p.relation == "transacted_with"]
    assert len(pivots) == 7 and all(p.expand is False and p.entity.type is T.BTC for p in pivots)  # P213 decides expansion
    assert all("counterparty (role unknown)" in p.note for p in pivots)
    tops = a["top_counterparties"]
    assert tops[0]["address"] == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" and tops[0]["direction"] == "in"
    assert tops[0]["received_from"] == "0.00193679 BTC" and tops[1]["tx_count"] == 4
    assert res.findings[0].severity.label == "info" and "never compared across providers" in res.findings[0].description
    assert ("mempool.space address page", f"https://mempool.space/address/{GENESIS}") in res.links
    # evidence keeps the summary and transaction ids, never the counterparties' histories (cond 5)
    assert set(res.raw) == {"provider", "source", "summary", "txids", "pages", "tip_height"} and len(res.raw["txids"]) == 8
    http.assert_hosts_within(BtcExplorers)


def test_top_counterparties_are_capped_at_ten():
    txs = [{"txid": f"t{i}", "vin": [{"prevout": {"scriptpubkey_address": f"bc1qsender{i:02d}", "value": 1000 + i}}],
            "vout": [{"scriptpubkey_address": GENESIS, "value": 1000 + i}], "status": {"confirmed": True, "block_height": 100 + i,
                                                                                    "block_time": 1795000000 + i}} for i in range(15)]
    import json

    http = FakeHttp()
    http.add("GET", f"{BS}/address/{GENESIS}", json={"address": GENESIS, "chain_stats": {"funded_txo_sum": 1, "spent_txo_sum": 0, "tx_count": 15},
                                                     "mempool_stats": {}})
    http.add("GET", f"{BS}/address/{GENESIS}/txs", body=json.dumps(txs).encode(), headers={"content-type": "application/json"})
    http.add("GET", f"{BS}/blocks/tip/height", text="200")
    res = run_module(BtcExplorers, f"btc_address:{GENESIS}", http)
    assert res.status is Status.OK and len(res.attributes["top_counterparties"]) == 10
    # invalid 'addresses' (not checksummed) are listed but never pivoted
    assert res.pivots == [] or all(p.entity.type is T.BTC for p in res.pivots)


# ------------------------------------------------------------------ failover (cond 3, 4)
def test_429_fails_over_records_disclosure_and_short_circuits_the_host():
    http = FakeHttp().add("GET", f"{BS}/address/{GENESIS}", status=429, text="Too Many Requests")
    esplora_routes(http, MP)
    rt = make_runtime(http)
    res = run_module(BtcExplorers, f"btc_address:{GENESIS}", http, runtime=rt)
    assert res.status is Status.OK and res.attributes["explorer_failover"]["answered_by"] == "mempool"
    per = {p["provider"]: p["status"] for p in res.attributes["explorer_failover"]["per_provider"]}
    assert per == {"blockstream": "rate_limited", "mempool": "ok"}
    assert res.attributes["disclosed_to"] == ["blockstream", "mempool"]
    assert res.source_statuses["blockstream.esplora_api"]["status"] in ("rate_limited", Status.RATE_LIMITED)
    sent = len([c for c in http.calls if "blockstream.info" in c["url"]])
    # same run (same HTTP client): blockstream is short-circuited, never contacted again
    res2 = run_module(BtcExplorers, f"btc_address:{GENESIS}", http, runtime=rt)
    assert res2.status is Status.OK and len([c for c in http.calls if "blockstream.info" in c["url"]]) == sent
    assert "short-circuited" in res2.attributes["explorer_failover"]["per_provider"][0]["reason"]


def test_every_provider_failing_is_could_not_verify_never_empty():
    http = (FakeHttp()
            .add("GET", f"{BS}/address/{GENESIS}", status=503, text="unavailable")
            .add("GET", f"{MP}/address/{GENESIS}", status=429, text="slow down")
            .add("GET", f"https://blockchain.info/rawaddr/{GENESIS}?limit=50&offset=0", status=500, text="oops"))
    res = run_module(BtcExplorers, f"btc_address:{GENESIS}", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    assert "could not verify" in res.error and "blockstream" in res.error and "blockchain_com" in res.error
    assert res.attributes["explorer_failover"]["answered_by"] is None


def test_error_in_200_challenge_and_malformed_bodies_are_errors():
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = (FakeHttp()
            .add("GET", f"{BS}/address/{GENESIS}", text=page)
            .add("GET", f"{MP}/address/{GENESIS}", body=b"{not json", headers={"content-type": "application/json"})
            .add("GET", f"https://blockchain.info/rawaddr/{GENESIS}?limit=50&offset=0",
                 json={"error": "user-error", "message": "invalid address"}))
    res = run_module(BtcExplorers, f"btc_address:{GENESIS}", http)
    assert res.status in (Status.ERROR, Status.BLOCKED) and res.status is not Status.EMPTY
    per = {p["provider"]: p["status"] for p in res.attributes["explorer_failover"]["per_provider"]}
    assert per == {"blockstream": "blocked", "mempool": "error", "blockchain_com": "error"}
    assert res.status is Status.BLOCKED  # the challenge is the most informative 'could not verify'


def test_esplora_400_invalid_address_moves_on_with_the_reason():
    http = (FakeHttp()
            .add("GET", f"{BS}/address/{GENESIS}", status=400, body=raw("esplora_invalid_address_400.txt"), headers={"content-type": "text/plain"}))
    esplora_routes(http, MP)
    res = run_module(BtcExplorers, f"btc_address:{GENESIS}", http)
    first = res.attributes["explorer_failover"]["per_provider"][0]
    assert res.status is Status.OK and first["status"] == "error" and "Invalid Bitcoin address" in first["reason"]


def test_empty_address_is_a_genuine_absence():
    http = FakeHttp().add("GET", f"{BS}/address/{EMPTY_BTC}", **js("esplora_address_empty.json"))
    res = run_module(BtcExplorers, f"btc_address:{EMPTY_BTC}", http)
    assert res.status is Status.EMPTY and "no transactions on-chain per blockstream" in res.attributes["wallet_status"]
    assert len(http.calls) == 1 and res.pivots == []


def test_explorer_budget_stops_the_failover():
    http = (FakeHttp()
            .add("GET", f"{BS}/address/{GENESIS}", status=503, text="slow", latency=4.0)
            .add("GET", f"{MP}/address/{GENESIS}", status=503, text="slow", latency=4.0))
    res = run_module(BtcExplorers, f"btc_address:{GENESIS}", http)
    fo = res.attributes["explorer_failover"]
    assert res.status is Status.ERROR and fo["over_budget"] is True and "blockchain_com" not in fo["order"]
    assert not any("blockchain.info" in c["url"] for c in http.calls)


# ------------------------------------------------------------------ self-hosted first (cond 1)
def test_self_hosted_esplora_is_tried_first_and_discloses_nothing():
    http = esplora_routes(FakeHttp(), INTERNAL)
    res = run_module(BtcExplorers, f"btc_address:{GENESIS}", http, settings={"btc_explorers_esplora_url": INTERNAL})
    assert res.status is Status.OK and http.hosts() == {"esplora.corp.example"}
    fo = res.attributes["explorer_failover"]
    assert fo["answered_by"] == "esplora_internal" and fo["disclosed_to"] == [] and "disclosed_to" not in res.attributes
    http.assert_hosts_within(BtcExplorers, extra=("esplora.corp.example",))


# ------------------------------------------------------------------ LTC / DOGE / DASH (cond 2)
def test_litecoin_uses_litecoinspace_first():
    http = FakeHttp().add("GET", f"{LS}/address/{EMPTY_LTC}", **js("litecoinspace_address_empty.json"))
    res = run_module(BtcExplorers, f"other_crypto_address:{EMPTY_LTC}", http)
    assert res.status is Status.EMPTY and res.attributes["chain"] == "litecoin" and http.hosts() == {"litecoinspace.org"}


def test_dogecoin_needs_blockcypher_which_is_key_terms():
    allowed = frozenset(s for s in BtcExplorers.sources if s != "blockcypher.api")  # corporate without a business plan
    http = FakeHttp()
    res = run_module(BtcExplorers, f"other_crypto_address:{EMPTY_DOGE}", http, allowed_sources=allowed)
    assert res.status is Status.SKIPPED and res.reason_code == "licence" and http.calls == []
    http2 = FakeHttp().add("GET", f"https://api.blockcypher.com/v1/doge/main/addrs/{EMPTY_DOGE}/full?limit=50",
                           **js("blockcypher_address_empty_doge.json"))
    res2 = run_module(BtcExplorers, f"other_crypto_address:{EMPTY_DOGE}", http2)
    assert res2.status is Status.EMPTY and res2.attributes["chain"] == "dogecoin"


def test_blockcypher_token_is_sent_only_as_redacted_query_and_paginates():
    full = f"https://api.blockcypher.com/v1/dash/main/addrs/{DASH}/full"
    http = (FakeHttp()
            .add("GET", f"{full}?limit=50&token={BLOCKCYPHER_TOKEN}", **js("blockcypher_full_ok.json"))
            .add("GET", f"{full}?limit=50&token={BLOCKCYPHER_TOKEN}&before=977582", **js("blockcypher_full_ok.json"))
            .add("GET", f"https://api.blockcypher.com/v1/dash/main?token={BLOCKCYPHER_TOKEN}", **js("blockcypher_chain_ltc.json")))
    res = run_module(BtcExplorers, f"other_crypto_address:{DASH}", http, keys={"blockcypher": BLOCKCYPHER_TOKEN})
    assert res.status is Status.OK and res.attributes["chain"] == "dash" and len(http.calls) == 3
    assert res.attributes["data_freshness"]["provider_tip_height"] == 3219589
    assert_no_secret(BLOCKCYPHER_TOKEN, res.attributes, res.findings, res.raw, res.error, res.source_statuses)


def test_blockcypher_400_invalid_is_error_never_empty():
    http = FakeHttp().add("GET", f"https://api.blockcypher.com/v1/doge/main/addrs/{EMPTY_DOGE}/full?limit=50", status=400,
                          **js("blockcypher_invalid_address_400.json"))
    res = run_module(BtcExplorers, f"other_crypto_address:{EMPTY_DOGE}", http)
    assert res.status is Status.ERROR and "non-matching checksum" in res.error


# ------------------------------------------------------------------ Blockchair (key only, cond 2/4)
def _all_btc_fail(http: FakeHttp) -> FakeHttp:
    return (http.add("GET", f"{BS}/address/{GENESIS}", status=503, text="x")
                .add("GET", f"{MP}/address/{GENESIS}", status=503, text="x")
                .add("GET", f"https://blockchain.info/rawaddr/{GENESIS}?limit=50&offset=0", status=503, text="x"))


def test_blockchair_only_with_its_commercial_key():
    assert "blockchair" not in be.utxo_failover_plan("btc")
    url = f"https://api.blockchair.com/bitcoin/dashboards/address/{GENESIS}?limit=10&key={BLOCKCHAIR_KEY}"
    http = _all_btc_fail(FakeHttp()).add("GET", url, **js("blockchair_dashboard_ok_docshape.json"))
    res = run_module(BtcExplorers, f"btc_address:{GENESIS}", http, keys={"blockchair": BLOCKCHAIR_KEY})
    assert res.status is Status.OK and res.attributes["explorer_failover"]["answered_by"] == "blockchair"
    assert res.attributes["first_seen"] == "2009-01-03T18:15:05Z" and res.attributes["activity_window"]["first_seen_exact"] is True
    assert res.attributes["data_freshness"]["provider_tip_height"] == 977642
    assert_no_secret(BLOCKCHAIR_KEY, res.attributes, res.findings, res.raw, res.error, res.links, res.source_statuses)


def test_blockchair_430_is_rate_limited_never_empty():
    url = f"https://api.blockchair.com/bitcoin/dashboards/address/{GENESIS}?limit=10&key={BLOCKCHAIR_KEY}"
    http = _all_btc_fail(FakeHttp()).add("GET", url, status=430, **js("blockchair_rate_limited_430.json"))
    res = run_module(BtcExplorers, f"btc_address:{GENESIS}", http, keys={"blockchair": BLOCKCHAIR_KEY})
    per = {p["provider"]: p["status"] for p in res.attributes["explorer_failover"]["per_provider"]}
    assert per["blockchair"] == "rate_limited" and res.status is Status.RATE_LIMITED


def test_failover_report_shape():
    rep = be.failover_report([
        {"provider": "esplora_internal", "status": "error", "sent": True, "elapsed_s": 1.0},
        {"provider": "blockstream", "status": "rate_limited", "sent": True, "elapsed_s": 0.5},
        {"provider": "mempool", "status": "ok", "sent": True, "elapsed_s": 0.4},
    ])
    assert rep["answered_by"] == "mempool" and rep["disclosed_to"] == ["blockstream", "mempool"] and not rep["over_budget"]


@pytest.mark.parametrize("value", ["", None, 12, "0" * 40])
def test_chain_detection_tolerates_junk(value):
    assert be.address_chain(value) is None
