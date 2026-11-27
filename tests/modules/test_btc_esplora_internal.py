"""btc_esplora_internal (P211 cond 1, A8 BR7): the organisation's own Esplora only, for TLP:AMBER+STRICT and RED.

Fixtures in tests/fixtures/btc_esplora_internal/: real Esplora answers (blockstream.info, recorded
2026-11-26 by the prep of batch p2-G09-2; a self-hosted Esplora/electrs serves the same schema) for the
public genesis address, with every other wallet replaced by documentation/test-vector addresses.
"""

from __future__ import annotations

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.models import Status
from v3lum.modules.crypto.btc_explorers import BtcEsploraInternal

GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
EMPTY_LTC = "ltc1qzn9caqwrf3qgkc3hrvy3sph0qzvurrk0f3mznm"
INTERNAL = "https://esplora.corp.example/api"
INTERNAL_LTC = "https://esplora-ltc.corp.example/api"
PAGE2_AFTER = "9cc9edd11f8ae17d41c3d3762625c8a36368a4a60be3952962aabe1d75904259"
SETTINGS = {"btc_explorers_esplora_url": INTERNAL, "btc_explorers_esplora_ltc_url": INTERNAL_LTC}


def raw(name: str) -> bytes:
    return (FIXTURES / "btc_esplora_internal" / name).read_bytes()


def own_instance(http: FakeHttp) -> FakeHttp:
    js = {"headers": {"content-type": "application/json"}}
    http.add("GET", f"{INTERNAL}/address/{GENESIS}", body=raw("esplora_address_ok.json"), **js)
    http.add("GET", f"{INTERNAL}/address/{GENESIS}/txs", body=raw("esplora_txs_ok.json"), **js)
    http.add("GET", f"{INTERNAL}/address/{GENESIS}/txs/chain/{PAGE2_AFTER}", body=raw("esplora_txs_page2_ok.json"), **js)
    http.add("GET", f"{INTERNAL}/blocks/tip/height", body=raw("esplora_tip_height.txt"), headers={"content-type": "text/plain"})
    return http


def test_metadata_internal_class():
    cls = BtcEsploraInternal
    assert cls.disclosure == "internal" and cls.terms == "open" and cls.hosts == () and cls.provider == "internal_esplora"
    assert cls.sources == ("internal_esplora.esplora",) and cls.default_enabled is True and cls.trust_tier == "n/a"
    assert getattr(cls.max_tlp, "name", "") == "RED"


def test_answers_from_the_own_instance_and_discloses_nothing():
    http = own_instance(FakeHttp())
    res = run_module(BtcEsploraInternal, f"btc_address:{GENESIS}", http, settings=SETTINGS, tlp="amber+strict")
    assert res.status is Status.OK and http.hosts() == {"esplora.corp.example"}
    fo = res.attributes["explorer_failover"]
    assert fo["answered_by"] == "esplora_internal" and fo["order"] == ["esplora_internal"] and fo["disclosed_to"] == []
    assert res.attributes["balance"] == "57.72103060 BTC" and res.attributes["data_freshness"]["provider_tip_height"] == 977642
    assert all(p.expand is False for p in res.pivots)
    http.assert_hosts_within(BtcEsploraInternal, extra=("esplora.corp.example",))


def test_never_fails_over_to_a_public_explorer():
    http = FakeHttp().add("GET", f"{INTERNAL}/address/{GENESIS}", status=503, text="down")
    res = run_module(BtcEsploraInternal, f"btc_address:{GENESIS}", http, settings=SETTINGS, tlp="red")
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert res.attributes["explorer_failover"]["order"] == ["esplora_internal"] and http.hosts() == {"esplora.corp.example"}


def test_rate_limited_own_instance_is_never_empty():
    http = FakeHttp().add("GET", f"{INTERNAL}/address/{GENESIS}", status=429, text="slow down")
    res = run_module(BtcEsploraInternal, f"btc_address:{GENESIS}", http, settings=SETTINGS, tlp="red")
    assert res.status is Status.RATE_LIMITED


def test_litecoin_uses_its_own_setting():
    http = FakeHttp().add("GET", f"{INTERNAL_LTC}/address/{EMPTY_LTC}", body=raw("litecoinspace_address_empty.json"),
                          headers={"content-type": "application/json"})
    res = run_module(BtcEsploraInternal, f"other_crypto_address:{EMPTY_LTC}", http, settings=SETTINGS, tlp="red")
    assert res.status is Status.EMPTY and res.attributes["chain"] == "litecoin"


def test_runs_only_for_restricted_tlp_and_needs_its_setting():
    res = run_module(BtcEsploraInternal, f"btc_address:{GENESIS}", FakeHttp(), settings=SETTINGS, tlp="amber")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    res2 = run_module(BtcEsploraInternal, f"btc_address:{GENESIS}", FakeHttp(), tlp="red")
    assert res2.status is Status.SKIPPED and res2.reason_code == "config"
    res3 = run_module(BtcEsploraInternal, f"btc_address:{GENESIS}", FakeHttp(), settings={"btc_explorers_esplora_url": "http://plain.example/api"}, tlp="red")
    assert res3.status is Status.SKIPPED and res3.reason_code == "config"  # https only
