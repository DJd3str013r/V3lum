"""crypto_sanctions_offline (P205): OFAC sanctioned-address lists matched offline (disclosure none).

Fixtures in tests/fixtures/crypto_sanctions_offline/ (prep batch p1-G09-1, recorded 2026-11-26 from
raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses, branch 'lists'; the
addresses are public OFAC SDN data): ``ofac_xbt_list_ok.txt`` (P2PKH, P2SH, bech32 lines),
``ofac_eth_list_ok.txt`` (mixed EIP-55 and lower-case lines), ``ofac_trx_list_ok.txt``,
``ofac_usdt_list_ok.txt`` (EVM, TRON and Omni lines in one list), ``ofac_minimal_list_ok.txt`` (one
line per other family: LTC, ZEC, BCH cashaddr, SOL, XMR) and ``ofac_list_not_found.txt`` (the verbatim
404 body of an unknown asset).
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_ctx, make_runtime, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.crypto import crypto_sanctions_offline as off
from v3lum.modules.crypto.crypto_sanctions_offline import ASSETS, LIST_URL, CryptoSanctionsOffline

OWN = {"XBT": "ofac_xbt_list_ok.txt", "ETH": "ofac_eth_list_ok.txt", "TRX": "ofac_trx_list_ok.txt", "USDT": "ofac_usdt_list_ok.txt"}
LISTED_ETH = "0x0330070FD38Ec3bB94F58FA55D40368271E9e54A"
EF = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"


def body(name: str) -> bytes:
    return (FIXTURES / "crypto_sanctions_offline" / name).read_bytes()


def lists_http(**overrides) -> FakeHttp:
    """One route per asset list: the recorded lists for XBT/ETH/TRX/USDT, the minimal list elsewhere;
    ``overrides`` maps an asset to (status, body)."""
    http = FakeHttp()
    for asset in ASSETS:
        status, content = overrides.get(asset, (200, body(OWN.get(asset, "ofac_minimal_list_ok.txt"))))
        http.add("GET", LIST_URL.format(asset=asset), status=status, body=content, headers={"content-type": "text/plain; charset=utf-8"})
    return http


# ------------------------------------------------------------------ metadata (cond 1, 7)
def test_metadata_is_offline_and_tlp_red_safe():
    cls = CryptoSanctionsOffline
    assert (cls.disclosure, cls.hosts, cls.provider, cls.sources) == ("none", (), "", ("github.crypto_sanctions_offline_ofac_lists",))
    assert cls.terms == "open" and cls.default_enabled is True and cls.max_requests == 0 and cls.trust_tier == "n/a"
    assert cls.max_tlp.value_str == "red" and cls.shares_input is False
    assert len(ASSETS) == 18 and "DOGE" not in ASSETS
    for asset in ASSETS:
        reg = DATASETS[off.dataset_name(asset)]
        assert reg["url"] == LIST_URL.format(asset=asset) and reg["ttl"] == 86400 and reg["essential"] is True
        assert reg["terms_class"] == "open" and reg["source"] == "github.crypto_sanctions_offline_ofac_lists" and reg["large"] is False


# ------------------------------------------------------------------ matching (cond 1, 5, 6)
def test_listed_evm_address_matches_lowercase_with_list_date_and_sha():
    http = lists_http()
    res = run_module(CryptoSanctionsOffline, f"eth_address:{LISTED_ETH}", http)
    assert res.status is Status.OK and res.requests == 0  # only dataset downloads: the wallet never leaves the machine
    assert {u for u in http.urls()} == {LIST_URL.format(asset=a) for a in ASSETS}
    [finding] = res.findings
    assert finding.title == "Address on the OFAC SDN list (US)" and finding.severity.label == "critical" and "sanctions" in finding.tags
    assert finding.confidence_label.value == "confirmed" and finding.data["lists"] == ["ETH"]
    assert "stop transactions and escalate to compliance" in finding.description.lower()
    assert "not a legal determination" in finding.description and "LGPD art. 20" in finding.description
    hit = finding.data["hits"][0]
    assert hit["asset"] == "ETH" and hit["list_date"] and len(hit["list_sha256"]) == 64
    a = res.attributes
    assert a["sanctioned"] is True and a["sanctions_status"].startswith("on the OFAC SDN list (US) as of")
    assert ("OFAC Sanctions List Search (SDN entity and programme)", "https://sanctionssearch.ofac.treas.gov/") in res.links
    assert len(res.datasets) == len(ASSETS)  # every list consulted is cited (name, sha256, fetched_at)


@pytest.mark.parametrize(
    "entity,lists",
    [
        ("other_crypto_address:TYK29mbyvVxLaLUKdFSTRADMwoxaVbVZQg", ["USDT"]),  # TRON line inside the USDT list
        ("btc_address:16iWn2J1McqjToYLHSsAyS6En3QA8YQ91H", ["USDT"]),  # Omni line inside the USDT list
        ("btc_address:BC1Q05AKTDDF9CE4P7HH3STGSF253M4VWEU7NKHTMW", ["XBT"]),  # bech32 compared lower-case
        ("other_crypto_address:TNrX2FwrHKoo4XACGkmSzqeK4pdnKYn6Z7", ["TRX"]),  # base58 exact
        ("eth_address:0x175d44451403edf28469df03a9280c1197adb92c", ["USDT"]),  # EVM line of the USDT list
        ("other_crypto_address:LNf2JDiuunBz7GMDKFYHN4rq5meXWxiwfb", ["BCH", "BSV", "BTG", "DASH", "LTC", "SOL", "XMR", "XRP", "XVG", "ZEC", "ARB", "BSC", "ETC", "USDC"]),
    ],
)
def test_matching_is_by_address_format_not_by_list_name(entity, lists):
    res = run_module(CryptoSanctionsOffline, entity, lists_http())
    assert res.status is Status.OK and sorted(res.findings[0].data["lists"]) == sorted(lists)


def test_base58_is_exact_and_a_miss_reads_not_on_ofac_lists():
    res = run_module(CryptoSanctionsOffline, "other_crypto_address:tyk29mbyvvxlalukdfstradmwoxavbvzqg", lists_http())
    assert res.status is Status.EMPTY  # base58 is case-sensitive: a lower-cased TRON address is another value
    res = run_module(CryptoSanctionsOffline, f"eth_address:{EF}", lists_http())
    assert res.status is Status.EMPTY and not res.findings
    status = res.attributes["sanctions_status"]
    assert status.startswith("not on OFAC lists as of 20") and "not sanctioned" not in status and "sanctioned" not in res.attributes


# ------------------------------------------------------------------ could not verify, staleness (cond 6, rule 5)
def test_an_unreadable_list_makes_a_miss_could_not_verify():
    http = lists_http(XMR=(404, body("ofac_list_not_found.txt")))
    res = run_module(CryptoSanctionsOffline, f"eth_address:{EF}", http)
    assert res.status is Status.ERROR and "XMR" in res.error and "sanctions_status" not in res.attributes
    res = run_module(CryptoSanctionsOffline, f"eth_address:{LISTED_ETH}", lists_http(XMR=(404, body("ofac_list_not_found.txt"))))
    assert res.status is Status.OK and res.findings[0].data["lists_unavailable"] == ["XMR"]


def test_html_instead_of_a_list_is_refused():
    http = lists_http(ETH=(200, b"<html><body>rate limited</body></html>"))
    res = run_module(CryptoSanctionsOffline, f"eth_address:{LISTED_ETH}", http)
    assert res.status is Status.ERROR and "ETH" in res.error  # the ETH copy was refused: never 'not listed'


def test_stale_lists_are_flagged(monkeypatch):
    monkeypatch.setattr(off, "STALE_HOURS", -1)
    res = run_module(CryptoSanctionsOffline, f"eth_address:{EF}", lists_http())
    assert res.status is Status.EMPTY and len(res.attributes["ofac_list_stale"]) == len(ASSETS)
    assert "stale lists" in res.attributes["sanctions_status"]


def test_never_downloaded_and_offline_is_unavailable_dataset():
    rt = make_runtime(FakeHttp(), offline=True)
    res = run_module(CryptoSanctionsOffline, f"eth_address:{EF}", runtime=rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code in ("dataset", "offline")


def test_health_selftest_reports_missing_and_fresh_lists():
    hc = CryptoSanctionsOffline.health_check()
    assert hc.offline is True
    ctx = make_ctx(CryptoSanctionsOffline, lists_http())
    assert hc.selftest(ctx).status == "dead"
    run_module(CryptoSanctionsOffline, f"eth_address:{EF}", lists_http())
    assert hc.selftest(make_ctx(CryptoSanctionsOffline, FakeHttp())).status == "ok"


# ------------------------------------------------------------------ helpers
def test_match_keys_and_list_parser():
    assert off.match_key(LISTED_ETH) == LISTED_ETH.lower()
    cash = "qpf2cphc5dkuclkqur7lhj2yuqq9pk3hmukle77vhq"
    assert off.match_key("bitcoincash:QPF2CPHC5DKUCLKQUR7LHJ2YUQQ9PK3HMUKLE77VHQ") == cash  # cashaddr is single-case
    assert off.match_key(cash.upper()) == cash and off.address_family(cash.upper()) == "cashaddr"
    assert off.address_family("qpf2cphc5dkuclkqur7lhj2yuqq9pk3hmukle77vhQ") == "base58"  # mixed case is no cashaddr
    assert off.match_key("bitcoincash:" + cash) == cash
    assert off.address_family("TYK29mbyvVxLaLUKdFSTRADMwoxaVbVZQg") == "base58" and off.address_family("bc1q05aktddf9ce4p7hh3stgsf253m4vweu7nkhtmw") == "bech32"
    assert off.parse_list("# c\n\nTNrX2FwrHKoo4XACGkmSzqeK4pdnKYn6Z7\n<html>\nshort\n") == ["TNrX2FwrHKoo4XACGkmSzqeK4pdnKYn6Z7"]
    assert off.parse_list("") == []


def test_entity_types_accepted():
    assert CryptoSanctionsOffline.accepts == {T.BTC, T.ETH, T.CRYPTO, T.XMR}
