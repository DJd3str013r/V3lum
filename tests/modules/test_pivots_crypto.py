"""pivots_crypto (P216): chain-aware explorer links, manual only.

Vectors: tests/fixtures/pivots_crypto/address_vectors.json (public BIP-173/350, EIP-55 and cashaddr spec
vectors, the genesis address, Tether's public USDT contract, synthetic addresses from the genesis hash160).
Maintainer checks: tests/fixtures/pivots_crypto/verified_templates.json. V3LUM never fetches these URLs."""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core import links
from v3lum.core.entities import Entity
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.crypto import pivots_crypto as pc
from v3lum.modules.crypto.pivots_crypto import PivotsCrypto
from v3lum.modules.utility import pivot_pack_render as pr

VECTORS = module_fixture("pivots_crypto", "address_vectors.json")
VERIFIED = module_fixture("pivots_crypto", "verified_templates.json")
GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"


def urls(res):
    return [url for _label, url in res.links]


# ------------------------------------------------------------------ cond 8: chain validation
@pytest.mark.parametrize("vector", VECTORS["valid"], ids=lambda v: v["value"][:14])
def test_valid_vectors_route_to_their_chain(vector):
    if vector["chain"] not in ("btc", "evm", "ltc", "doge", "bch", "tron"):  # e.g. Dash: no explorer link in the pack
        assert pc.chain_of(vector["value"]) is None
        return
    assert pc.chain_of(vector["value"]) == (vector["chain"], vector["url_value"])


@pytest.mark.parametrize("vector", VECTORS["invalid"], ids=lambda v: v["why"])
def test_invalid_vectors_select_no_explorer(vector):
    assert pc.chain_of(vector["value"]) is None


def test_testnet_and_unsupported_chains_get_no_link():
    assert pc.chain_of("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") is None  # testnet: mainnet explorers would say 'invalid'
    res = run_module(PivotsCrypto, "other_crypto_address:rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh")  # XRP
    assert res.status is Status.EMPTY and not res.links and res.raw["chain"] is None


def test_a_btc_address_never_reaches_the_litecoin_route():
    """Blockchair answers 200 with an empty 'Litecoin address <btc>' page for that mistake (2026-11-26)."""
    mismatch = next(c for c in VERIFIED["checks"] if c["case"] == "blockchair_ltc_chain_mismatch")
    assert mismatch["status"] == 200
    ml = pr.module_links("crypto")["blockchair_ltc"]
    assert pr.render(ml, Entity.make("other_crypto_address", GENESIS), {"ltc": None}) is None
    res = run_module(PivotsCrypto, f"other_crypto_address:{GENESIS}", tlp="clear")
    assert res.raw["chain"] == "btc" and not any("litecoin" in u for u in urls(res))


def test_eip55_display_and_lowercase_matching():
    assert pc.eip55(USDT) == "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    for spec_lower, spec_display in VECTORS["eip55_spec"].items():
        assert pc.eip55(spec_lower) == spec_display
    assert pc.chain_of("0xdAC17F958D2ee523a2206206994597C13D831eC7") is None  # wrong mixed-case checksum: no link
    assert Entity.make("eth_address", "0xdAC17F958D2ee523a2206206994597C13D831ec7").value == USDT  # URLs use lower case
    rendered = links.render("crypto:ethplorer_address", Entity.make("eth_address", USDT))
    assert rendered.url == f"https://ethplorer.io/address/{USDT}"


# ------------------------------------------------------------------ module runs
@pytest.mark.parametrize(("value", "url"), [
    ("LUEweDxDA4WhvWiNXXSxjM9CYzHPJv4QQF", "https://blockchair.com/litecoin/address/LUEweDxDA4WhvWiNXXSxjM9CYzHPJv4QQF"),
    ("ltc1qvt5s0v2uhuna2sjnn84ldu8m2r4m3rcc3n0rm5", "https://blockchair.com/litecoin/address/ltc1qvt5s0v2uhuna2sjnn84ldu8m2r4m3rcc3n0rm5"),
    ("DEA5vGb2NpAwCiCp5yTE16F3DueQUVivQp", "https://blockchair.com/dogecoin/address/DEA5vGb2NpAwCiCp5yTE16F3DueQUVivQp"),
    ("bitcoincash:qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy", "https://blockchair.com/bitcoin-cash/address/qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy"),
    ("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "https://tronscan.org/#/address/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
])
def test_other_chains_get_their_explorer_only(value, url):
    res = run_module(PivotsCrypto, f"other_crypto_address:{value}", FakeHttp(), tlp="clear")
    assert res.status is Status.OK and res.requests == 0
    assert urls(res) == [url]


def test_tronscan_is_unverified_with_the_antibot_badge():
    res = run_module(PivotsCrypto, "other_crypto_address:TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", tlp="clear")
    label = res.links[0][0]
    assert "unverified" in label and pr.ANTIBOT_BADGE in label


def test_btc_typed_as_other_gets_the_bitcoin_pack_links_verified_first():
    res = run_module(PivotsCrypto, f"other_crypto_address:{GENESIS}", tlp="clear")
    got = urls(res)
    assert got[0] == f"https://mempool.space/address/{GENESIS}"
    assert got[-1] == f"https://www.bitcoinwhoswho.com/address/{GENESIS}"  # unverified last
    assert f"https://bitref.com/{GENESIS}" in got
    assert "unknown operator" in dict((u, lab) for lab, u in res.links)[f"https://bitref.com/{GENESIS}"]


def test_evm_typed_as_other_gets_the_evm_links_with_the_eip55_form():
    res = run_module(PivotsCrypto, f"other_crypto_address:{USDT}", tlp="clear")
    by_url = {u: lab for lab, u in res.links}
    assert f"https://ethplorer.io/address/{USDT}" in by_url
    assert "EIP-55 0xdAC17F958D2ee523a2206206994597C13D831ec7" in by_url[f"https://ethplorer.io/address/{USDT}"]
    assert pr.ANTIBOT_BADGE in by_url[f"https://etherscan.io/address/{USDT}"]


def test_core_pack_links_for_btc_and_eth_in_curated_order():
    btc = [r.ref for r in links.pivot_links_for(Entity.make("btc_address", GENESIS), categories=("crypto",))]
    assert btc == ["crypto:mempool_address", "crypto:blockchair_btc", "crypto:walletexplorer_address", "crypto:blockchain_com_btc",
                   "crypto:bitref_address", "crypto:bitcoinwhoswho_address"]
    eth = [r.ref for r in links.pivot_links_for(Entity.make("eth_address", USDT), categories=("crypto",))]
    assert eth[:3] == ["crypto:ethplorer_address", "crypto:blockchair_eth", "crypto:blockchain_com_eth"]
    assert set(eth[3:]) == {"crypto:etherscan_address", "crypto:bscscan_address", "crypto:arkham_address"}
    assert not any("chainabuse" in r for r in btc + eth)  # P216 cond 10: Chainabuse belongs to P304


# ------------------------------------------------------------------ TLP
def test_amber_labels_carry_the_value_actually_sent():
    res = run_module(PivotsCrypto, "other_crypto_address:bitcoincash:qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy")
    assert res.links[0][0].endswith(
        "opening sends qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy (for bitcoincash:qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy) to blockchair.com")
    assert not res.raw["links"][0]["clickable"]


def test_red_emits_nothing():
    res = run_module(PivotsCrypto, "other_crypto_address:TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", tlp="red")
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and not res.links


def test_cashaddr_rejects_mixed_case_wrong_prefix_and_bad_payload():
    assert pc.cashaddr_payload("BITCOINCASH:QP3WJPA3TJLJ042Z2WV7HAHSLDGWHWY0RQ9SYWJPYY") == "qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy"
    assert pc.cashaddr_payload("bitcoincash:QP3WJPA3TJLJ042Z2WV7HAHSLDGWHWY0RQ9SYWJPYY") is None  # one letter case only
    assert pc.cashaddr_payload("bitcoincash:qP3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy") is None
    assert pc.cashaddr_payload("bchtest:qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy") is None
    assert pc.cashaddr_payload("qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyb") is None
    assert pc.cashaddr_payload(None) is None


def test_never_fetches_anything():
    ctx = make_ctx(PivotsCrypto, FakeHttp())
    with pytest.raises(PolicyError):
        ctx.http.get(f"https://blockchair.com/bitcoin/address/{GENESIS}")
