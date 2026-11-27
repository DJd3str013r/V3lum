"""tron_explorer (P207): TronGrid account + TRC-20 transfers (2 pages), Tronscan labels with a key.

Fixtures in tests/fixtures/tron_explorer/ (prep batch p1-G09-1, recorded 2026-11-26 from api.trongrid.io
keyless; the queried account and counterparties replaced with documentation addresses built from
repeated bytes, tx ids hashed, spam-token contracts replaced; values, symbols, decimals, timestamps and
fingerprints real): ``account_ok.json`` (normal account), ``account_contract_ok.json`` (the USDT
contract account), ``account_not_found.json`` (``data: []``: never activated), ``invalid_address.json``
(HTTP 400 success=false), ``trc20_page1.json`` / ``trc20_page2.json`` (USDT, look-alike tokens, empty
token_info, fingerprints) and ``tronscan_needs_key.html`` (401 openresty page without a key). The
throttled answer is not recorded live (no deliberate hammering): its markers are tested inline.
"""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from tests.fakes import FIXTURES, FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.crypto import tron_explorer as te
from v3lum.modules.crypto.tron_explorer import USDT_CONTRACT, TronExplorer

ADDR = "TBXSw8fM4jpQkGc6zZjsVABFpVN7UvXPdV"
ACCOUNT = f"https://api.trongrid.io/v1/accounts/{ADDR}"
TRC20 = f"{ACCOUNT}/transactions/trc20?limit=50&only_confirmed=true"
FP1 = module_fixture("tron_explorer", "trc20_page1.json")["meta"]["fingerprint"]
TRONSCAN = f"https://apilist.tronscanapi.com/api/accountv2?address={ADDR}"
KEY = "tg-team-key-0123456789abcdef"


def raw(name: str) -> bytes:
    return (FIXTURES / "tron_explorer" / name).read_bytes()


def jbody(name: str) -> dict:
    return {"body": raw(name), "headers": {"content-type": "application/json;charset=utf-8"}}


def full_http(**kw) -> FakeHttp:
    return (FakeHttp()
            .add("GET", ACCOUNT, **jbody("account_ok.json"), **kw)
            .add("GET", TRC20, **jbody("trc20_page1.json"), **kw)
            .add("GET", f"{TRC20}&fingerprint={FP1}", **jbody("trc20_page2.json"), **kw))


# ------------------------------------------------------------------ metadata (cond 5)
def test_metadata_follows_the_council_decision():
    cls = TronExplorer
    assert cls.terms == "key-terms" and cls.trust_tier == "trusted" and cls.default_enabled is True
    assert cls.sources == ("trongrid.api", "tronscan.api") and set(cls.hosts) == {"api.trongrid.io", "apilist.tronscanapi.com"}
    assert cls.optional_keys == ("trongrid", "tronscan") and cls.max_requests == 4 and cls.cache_ttl == 3600
    assert cls.produces == {T.CRYPTO} and cls.accepts == {T.CRYPTO}
    hc = cls.health_check()
    assert hc.etype is T.CRYPTO and hc.value == USDT_CONTRACT


# ------------------------------------------------------------------ summary (cond 1-3)
def test_account_and_two_trc20_pages_give_the_summary():
    http = full_http()
    res = run_module(TronExplorer, f"other_crypto_address:{ADDR}", http)
    assert res.status is Status.OK
    assert len(http.calls) == 3  # account + 2 pages; page 2's next link is never followed (2-page cap)
    assert f"fingerprint={FP1}" in http.urls()[2] and "api.trongrid.io" in http.urls()[2]
    a = res.attributes
    assert a["chain"] == "tron" and a["balance"] == "7.407061 TRX" and a["token_balances"] == {"USDT": "0.00698 USDT"}
    assert a["first_seen"].startswith("2020-07-28") and a["last_activity"].startswith("2026-11-26")
    assert a["transfers_seen"] == 11 and a["lookalike_token_transfers"] == 4  # fake 'USDT', UDST x2, QSDT
    tops = a["top_counterparties"]
    assert [c["address"] for c in tops] == ["TGCAjMXComunWZEXCT1LPBdcYbDVuyexBv", "TEdvoHEatmDKvTh3o9vBRB9Vdtbhn4QFhy", "TD5gsCwxykWsLN9aPrq2TAfNjByuZKYp4E"]
    assert tops[0]["usdt_in"] == "168 USDT" and tops[1]["usdt_in"] == "103.026775 USDT" and tops[2]["usdt_in"] == "44.760508 USDT"
    assert all(c["label"] is None for c in tops)  # labels come from crypto_address_labels (P358)
    pivots = [p for p in res.pivots if p.relation == "transacted_with"]
    assert len(pivots) == 3 and all(p.expand is False and p.entity.type is T.CRYPTO for p in pivots)  # P213 decides expansion
    info = res.findings[0]
    assert info.severity.label == "info" and "only the 2 newest pages were read" in info.description
    assert ("Tronscan address page", f"https://tronscan.org/#/address/{ADDR}") in res.links
    http.assert_hosts_within(TronExplorer)


def test_key_goes_in_the_header_never_in_a_url():
    http = full_http(match_headers={"TRON-PRO-API-KEY": KEY})
    res = run_module(TronExplorer, f"other_crypto_address:{ADDR}", http, keys={"trongrid": KEY})
    assert res.status is Status.OK and all(KEY not in u for u in http.urls())
    assert_no_secret(KEY, res.findings, res.attributes, res.raw, res.links, res.error)


def test_never_activated_account_is_empty_and_reads_no_transfers():
    http = FakeHttp().add("GET", ACCOUNT, **jbody("account_not_found.json"))
    res = run_module(TronExplorer, f"other_crypto_address:{ADDR}", http)
    assert res.status is Status.EMPTY and len(http.calls) == 1
    assert res.attributes["wallet_status"].startswith("not activated on-chain")


def test_contract_account_without_timestamps():
    acc = te.parse_account(module_fixture("tron_explorer", "account_contract_ok.json"))
    assert acc["type"] == "Contract" and acc["address"] == USDT_CONTRACT and acc["account_name"] == "TetherToken"
    assert acc["created_at"] is None and acc["trx_balance"] == "1097543.613638 TRX" and acc["other_tokens"] == 2


# ------------------------------------------------------------------ validation and errors (cond 2)
def test_invalid_addresses_are_never_sent():
    for value in ("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "TInvalidAddress1234567890"):
        http = FakeHttp()
        res = run_module(TronExplorer, f"other_crypto_address:{value}", http)
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and not http.calls


@pytest.mark.parametrize(
    "kw,expected",
    [
        ({"status": 429, "text": "Too Many Requests", "times": 3}, Status.RATE_LIMITED),
        ({"json": {"success": False, "error": "internal error"}}, Status.ERROR),
        ({"json": {"Error": "request rate exceeded the allowed_rps(15), and the query server is suspended for 1s"}}, Status.RATE_LIMITED),
        ({"status": 400, "body": raw("invalid_address.json"), "headers": {"content-type": "application/json"}}, Status.ERROR),
        ({"status": 503, "text": "upstream unavailable", "times": 3}, Status.ERROR),
        ({"text": "<html><body>gateway</body></html>"}, Status.ERROR),
    ],
)
def test_throttling_and_error_bodies_are_could_not_verify(kw, expected):
    http = FakeHttp().add("GET", ACCOUNT, **kw)
    res = run_module(TronExplorer, f"other_crypto_address:{ADDR}", http)
    assert res.status is expected and "wallet_status" not in res.attributes


def test_licence_blocked_trongrid_is_skipped():
    res = run_module(TronExplorer, f"other_crypto_address:{ADDR}", FakeHttp(), allowed_sources=())
    assert res.status is Status.SKIPPED and res.reason_code == "licence"


# ------------------------------------------------------------------ Tronscan only with its key (cond 4)
def test_no_tronscan_row_without_its_key():
    http = full_http()
    res = run_module(TronExplorer, f"other_crypto_address:{ADDR}", http)
    assert "apilist.tronscanapi.com" not in http.hosts() and "tronscan.api" not in res.source_statuses


def test_tronscan_labels_and_count_with_the_key():
    doc = {"address": ADDR, "totalTransactionCount": 123, "redTag": "Scam", "publicTag": "", "feedbackRisk": True}
    http = full_http().add("GET", TRONSCAN, json=doc, match_headers={"TRON-PRO-API-KEY": "ts-team-key-0123456789"})
    res = run_module(TronExplorer, f"other_crypto_address:{ADDR}", http, keys={"tronscan": "ts-team-key-0123456789"})
    assert res.attributes["tx_count"] == 123 and res.attributes["wallet_labels"] == ["redTag: Scam"]
    risky = next(f for f in res.findings if f.title == "Wallet labelled as risky by Tronscan")
    assert risky.severity.label == "medium" and "fraud" in risky.tags and risky.source == "tronscan.api"


def test_tronscan_401_is_recorded_per_feed():
    http = full_http().add("GET", TRONSCAN, status=401, body=raw("tronscan_needs_key.html"), headers={"content-type": "text/html"})
    res = run_module(TronExplorer, f"other_crypto_address:{ADDR}", http, keys={"tronscan": "ts-team-key-0123456789"})
    assert res.status is Status.OK and res.source_statuses["tronscan.api"]["status"] == "needs_key"


# ------------------------------------------------------------------ helpers
def test_address_conversion_amounts_and_abi_words():
    assert te.tron_base58_to_hex(USDT_CONTRACT) == "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
    assert te.tron_hex_to_base58("41a614f803b6fd780986a42c78ec9c7f77e6ded13c") == USDT_CONTRACT
    assert te.is_tron_address(te.TRON_ZERO_ADDRESS) and not te.is_tron_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u")
    assert te.abi_address_word("TYK29mbyvVxLaLUKdFSTRADMwoxaVbVZQg") == "000000000000000000000000f512078e07f61a2e28081c8ea86c6056788d18b4"
    assert te.abi_address_word("0x0330070FD38Ec3bB94F58FA55D40368271E9e54A").endswith("0330070fd38ec3bb94f58fa55d40368271e9e54a")
    with pytest.raises(ValueError):
        te.abi_address_word("not-an-address")
    assert te.format_amount(te.amount("3000000000000000000", 18), "UDST") == "3 UDST"
    assert te.amount("12", True) is None and te.amount("x", 6) is None and te.amount("-5", 6) is None
    assert te.format_amount(Decimal(0), "USDT") == "0 USDT"
    assert te.decode_abi_bool("0x" + "0" * 63 + "1") is True and te.decode_abi_bool("0x" + "0" * 63 + "2") is None


def test_constant_call_parser():
    frozen = json.loads((FIXTURES / "crypto_sanctions_onchain" / "tron_usdt_frozen.json").read_text())
    assert te.parse_constant_bool(frozen) == (True, "")
    failed = {"result": {"code": "CONTRACT_VALIDATE_ERROR", "message": b"Smart contract is not exist.".hex()}}
    value, why = te.parse_constant_bool(failed)
    assert value is None and "Smart contract is not exist." in why


def test_parsers_never_raise():
    for bad in (None, 1, "x", [], {}, {"data": "x"}, {"data": [None, 3]}, {"data": [{"trc20": "x", "balance": "1"}]},
                {"data": [{"token_info": "x", "value": True}], "meta": "x"}):
        te.parse_account(bad)
        te.parse_trc20_page(bad)
        te.parse_tronscan(bad)
        te.parse_constant_bool(bad)
    assert te.summarize(ADDR, None, []) ["transfers_seen"] == 0
