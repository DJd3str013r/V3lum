"""goplus_security (P206): GoPlus address/token/phishing-site checks; Honeypot.is behind its registry review.

Fixtures in tests/fixtures/goplus_security/ (prep batch p2-G09-1): live 2026-11-26 answers of
api.gopluslabs.io - ``address_clean.json`` (Ethereum Foundation wallet), ``address_flagged.json`` (the
OFAC SDN-listed Ronin-bridge exploiter, a public IOC), ``address_not_evaluated.json`` (chain_id=999999:
'ok' with contract_address '-1'), ``address_tron.json`` (USDT-TRC20 contract), ``token_not_token.json``
(token_security on a wallet); research samples ``token_ok.json`` (USDT; holder wallets replaced with
documentation addresses) and ``phishing_site_ok.json`` (example.com). Derived (marked): ``error_code_derived``
(documented GoPlus code 4029), ``phishing_site_flagged_derived``, ``challenge_derived.html``. Honeypot.is:
live ``honeypot_ok.json`` (USDT) and ``honeypot_not_applicable_404.json`` (a wallet), derived positive and
simulation-failure answers.
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.core.providers import registry
from v3lum.modules.crypto.goplus_security import (
    ADDRESS_URL,
    AUTH_URL,
    EF_WALLET,
    HONEYPOT_SOURCE,
    PHISHING_URL,
    TOKEN_URL,
    GoplusSecurity,
    honeypot_allowed,
    parse_honeypot_is,
    phishing_url,
)

RONIN = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
USDT_TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def fx(name: str):
    return module_fixture("goplus_security", name)


def address(http: FakeHttp, addr: str, chain: str = "1", **kw) -> FakeHttp:
    return http.add("GET", f"{ADDRESS_URL.format(address=addr)}?chain_id={chain}", **kw)


def ef_token(http: FakeHttp, chain: str = "1") -> FakeHttp:
    """The EF wallet is a contract (multisig, contract_address '1' live): token_security answers 'not a token'."""
    return http.add("GET", f"{TOKEN_URL.format(chain_id=chain)}?contract_addresses={EF_WALLET}", json=fx("token_not_token.json"))


def contract_like(doc: dict) -> dict:
    out = {**doc, "result": {**doc["result"], "contract_address": "1"}}
    return out


def test_metadata_key_terms_community_and_honeypot_not_declared():
    cls = GoplusSecurity
    assert cls.terms == "key-terms" and cls.trust_tier == "community" and cls.default_enabled is True
    assert cls.optional_keys == ("goplus",) and cls.hosts == ("api.gopluslabs.io",) and HONEYPOT_SOURCE not in cls.sources
    assert registry().get("honeypot_is").tier == "unknown"  # the P206 cond 5 review
    assert honeypot_allowed(declared=cls.sources) is False
    assert honeypot_allowed(declared=(HONEYPOT_SOURCE,)) is False  # tier unknown: still not queried


def test_clean_wallet_is_empty_with_cast_flags():
    http = ef_token(address(FakeHttp(), EF_WALLET, json=fx("address_clean.json")))
    res = run_module(GoplusSecurity, f"eth_address:{EF_WALLET}", http)
    assert res.status is Status.EMPTY and not res.findings and res.attributes["is_contract"] is True
    assert "goplus_contract" not in res.attributes  # a multisig contract, not a token
    flags = res.attributes["goplus_flags"]["1"]
    assert flags["phishing_activities"] is False and flags["sanctioned"] is False and all(isinstance(v, bool) for v in flags.values())
    assert "sanctioned" not in res.attributes or res.attributes["sanctioned"] is not False
    http.assert_hosts_within(GoplusSecurity)


def test_flagged_address_named_findings_tags_and_non_authoritative_sanctions():
    http = address(FakeHttp(), RONIN, json=fx("address_flagged.json"))
    res = run_module(GoplusSecurity, f"eth_address:{RONIN}", http)
    assert res.status is Status.OK
    by_flag = {f.data["flag"]: f for f in res.findings}
    assert set(by_flag) == {"stealing_attack", "blacklist_doubt", "sanctioned"}
    theft = by_flag["stealing_attack"]
    assert theft.title == "GoPlus: stealing attack (theft)" and theft.severity.label == "medium" and theft.tags == ["theft"]
    assert theft.data["data_sources"] == ["SlowMist", "BlockSec"] and "SlowMist, BlockSec" in theft.criterion
    assert by_flag["blacklist_doubt"].severity.label == "low" and by_flag["blacklist_doubt"].confidence_label.value == "possible"
    sanctioned = by_flag["sanctioned"]
    assert sanctioned.severity.label == "info" and "sanctions" not in sanctioned.tags and "Not a sanctions determination" in sanctioned.description
    assert res.attributes["sanctioned"] is True  # labelled by g09_sanctions_non_authoritative
    assert res.attributes["goplus_data_sources"] == ["SlowMist", "BlockSec"] and res.attributes["is_contract"] is False


def test_unsupported_chain_is_could_not_verify_never_clean():
    http = address(FakeHttp(), EF_WALLET, chain="56", json=fx("address_not_evaluated.json"))
    res = run_module(GoplusSecurity, f"eth_address:{EF_WALLET}", http, settings={"goplus_security_evm_chains": ["56"]})
    assert res.status is Status.ERROR and "contract_address -1" in res.error


def test_several_chains_partial_evaluation():
    http = ef_token(address(FakeHttp(), EF_WALLET, json=fx("address_clean.json")))
    address(http, EF_WALLET, chain="137", json=fx("address_not_evaluated.json"))
    res = run_module(GoplusSecurity, f"eth_address:{EF_WALLET}", http, settings={"goplus_security_evm_chains": ["1", "137", "bogus"]})
    assert res.status is Status.EMPTY and set(res.attributes["goplus_flags"]) == {"1"} and "137" in res.raw["note"]


def test_contract_gets_token_security_with_features_as_attributes():
    http = address(FakeHttp(), USDT, json=contract_like(fx("address_clean.json")))
    http.add("GET", f"{TOKEN_URL.format(chain_id='1')}?contract_addresses={USDT}", json=fx("token_ok.json"))
    res = run_module(GoplusSecurity, f"eth_address:{USDT}", http)
    assert res.status is Status.EMPTY  # mintable/blacklist/pausable are normal for a stablecoin: attributes only
    contract = res.attributes["goplus_contract"]
    assert contract["symbol"] == "USDT" and contract["holders"] == 15973588 and contract["cex_list"] == ["Binance", "Coinbase"]
    assert contract["features"]["is_mintable"] is True and contract["trusted_listing"] is True
    assert contract["owner"] == "0xc6cde7c39eb2f0f0095f41570af89efc2c1ea828" and res.attributes["is_contract"] is True
    assert len(http.calls) == 2


def test_honeypot_contract_is_a_finding():
    doc = fx("token_ok.json")
    doc["result"][USDT] = {**doc["result"][USDT], "is_honeypot": "1", "sell_tax": "0.99", "trust_list": "0"}
    http = address(FakeHttp(), USDT, json=contract_like(fx("address_clean.json")))
    http.add("GET", f"{TOKEN_URL.format(chain_id='1')}?contract_addresses={USDT}", json=doc)
    res = run_module(GoplusSecurity, f"eth_address:{USDT}", http)
    titles = {f.title for f in res.findings}
    assert "GoPlus: token is a honeypot (cannot be sold)" in titles and "GoPlus: sell tax of at least 50%" in titles
    assert all("crypto_scam" in f.tags for f in res.findings)


def test_wallet_token_security_is_not_applicable():
    http = address(FakeHttp(), EF_WALLET, json=contract_like(fx("address_clean.json")))
    http.add("GET", f"{TOKEN_URL.format(chain_id='1')}?contract_addresses={EF_WALLET}", json=fx("token_not_token.json"))
    res = run_module(GoplusSecurity, f"eth_address:{EF_WALLET}", http)
    assert res.status is Status.EMPTY and "goplus_contract" not in res.attributes


def test_tron_address_uses_chain_tron_and_no_token_call():
    http = address(FakeHttp(), USDT_TRON, chain="tron", json=fx("address_tron.json"))
    res = run_module(GoplusSecurity, f"other_crypto_address:{USDT_TRON}", http)
    assert res.status is Status.EMPTY and res.attributes["chain"] == "tron" and "is_contract" not in res.attributes
    assert len(http.calls) == 1


def test_non_tron_other_address_is_not_applicable():
    http = FakeHttp()
    res = run_module(GoplusSecurity, "other_crypto_address:LcHKrkpNmwUFdoyMWqaVR2F1Qsta3yJnLs", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_error_code_in_200_and_rate_limit_code():
    http = address(FakeHttp(), EF_WALLET, json={"code": 2004, "message": "contract address format error", "result": None})
    res = run_module(GoplusSecurity, f"eth_address:{EF_WALLET}", http)
    assert res.status is Status.ERROR and "2004" in res.error
    http2 = address(FakeHttp(), EF_WALLET, json=fx("error_code_derived.json"))
    assert run_module(GoplusSecurity, f"eth_address:{EF_WALLET}", http2).status is Status.RATE_LIMITED


@pytest.mark.parametrize("status,expected", [(429, Status.RATE_LIMITED), (500, Status.ERROR), (403, Status.BLOCKED)])
def test_http_failures(status, expected):
    body = (FIXTURES / "goplus_security" / "challenge_derived.html").read_text() if status == 403 else "x"
    http = address(FakeHttp(), EF_WALLET, status=status, text=body, times=2)
    assert run_module(GoplusSecurity, f"eth_address:{EF_WALLET}", http).status is expected


def test_malformed_json_is_error():
    http = address(FakeHttp(), EF_WALLET, json=["unexpected"])
    assert run_module(GoplusSecurity, f"eth_address:{EF_WALLET}", http).status is Status.ERROR


# ------------------------------------------------------------------ phishing_site (cond 1, 2)
def test_url_without_crypto_context_is_never_sent():
    http = FakeHttp()
    res = run_module(GoplusSecurity, "url:https://example.com/login?user=victim@example.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_url_from_a_wallet_is_sent_stripped():
    url = "https://wallet-support.example/claim/someone@example.com?ref=abcdefghijklmnop1234#frag"
    http = FakeHttp().add("GET", f"{PHISHING_URL}?url=https://wallet-support.example/", json=fx("phishing_site_flagged_derived.json"))
    res = run_module(GoplusSecurity, f"url:{url}", http, provenance=[(f"eth_address:{RONIN}", "related", "chainabuse")])
    assert res.status is Status.OK
    sent = res.attributes["goplus_phishing_site"]
    assert sent["url_sent"] == "https://wallet-support.example/" and set(sent["removed"]) == {"query", "fragment", "path"}
    [finding] = res.findings
    assert finding.title == "GoPlus: crypto phishing site" and set(finding.tags) == {"phishing", "crypto_scam"}


def test_domain_listed_by_the_analyst_and_clean_answer():
    http = FakeHttp().add("GET", f"{PHISHING_URL}?url=example.com", json=fx("phishing_site_ok.json"))
    res = run_module(GoplusSecurity, "domain:example.com", http, settings={"goplus_security_crypto_context": ["example.com"]})
    assert res.status is Status.EMPTY and res.attributes["goplus_phishing_site"]["flagged"] is False


def test_full_url_only_with_a_per_url_opt_in():
    url = "https://drainer.example/c?x=1"
    http = FakeHttp().add("GET", f"{PHISHING_URL}?url={url}", json=fx("phishing_site_ok.json"))
    res = run_module(GoplusSecurity, f"url:{url}", http, settings={"goplus_security_crypto_context": [url], "goplus_security_full_url": [url]})
    assert res.status is Status.EMPTY and res.attributes["goplus_phishing_site"]["removed"] == []


def test_phishing_url_helper():
    assert phishing_url("http://user:pw@a.example:8080/p?q=1#f") == {"url": "http://a.example:8080/p", "removed": ["userinfo", "query", "fragment"]}
    assert phishing_url("https://a.example/u/someone%40example.com")["removed"] == ["path"]
    assert phishing_url("ftp://a.example/") is None


# ------------------------------------------------------------------ optional key (cond 5)
def test_company_key_is_exchanged_for_an_access_token():
    http = FakeHttp().add("POST", AUTH_URL, json={"code": 1, "message": "OK", "result": {"access_token": "gp-access-0123456789", "expires_in": 7200}})
    address(http, EF_WALLET, json=fx("address_clean.json"), match_headers={"Authorization": "gp-access-0123456789"})
    ef_token(http)
    res = run_module(GoplusSecurity, f"eth_address:{EF_WALLET}", http, keys={"goplus": "appkey0123:appsecret4567"})
    assert res.status is Status.EMPTY and http.calls[0]["method"] == "POST"
    assert "gp-access-0123456789" not in repr(res.to_dict()) and "appsecret4567" not in repr(res.to_dict())


def test_malformed_company_key_is_config():
    res = run_module(GoplusSecurity, f"eth_address:{EF_WALLET}", FakeHttp(), keys={"goplus": "no-secret-part"})
    assert res.status is Status.SKIPPED and res.reason_code == "config"


# ------------------------------------------------------------------ Honeypot.is parser (cond 1, 6)
def test_honeypot_parser_on_recorded_answers():
    assert parse_honeypot_is(fx("honeypot_not_applicable_404.json"), 404)["status"] == "not_applicable"
    ok = parse_honeypot_is(fx("honeypot_ok.json"))
    assert ok["status"] == "empty" and ok["is_honeypot"] is False and ok["risk"] == "low"
    positive = parse_honeypot_is(fx("honeypot_positive_derived.json"))
    assert positive["status"] == "found" and positive["sell_tax"] == 100
    failed = parse_honeypot_is(fx("honeypot_simulation_failed_derived.json"))
    assert failed["status"] == "error" and "could not verify" in failed["reason"]
