"""crypto_sanctions_onchain (P205): Chainalysis oracle + USDT/USDC freezes by eth_call, USDT-TRC20 freeze
through TronGrid, Chainalysis REST with a key.

Fixtures in tests/fixtures/crypto_sanctions_onchain/ (prep batch p1-G09-1, recorded 2026-11-26):
``rpc_batch_ok.json`` (POST ethereum-rpc.publicnode.com: eth_chainId + oracle/USDT/USDC calls for an
OFAC-listed address, ids 2/4/6, and the Ethereum Foundation address, ids 3/5/7 - verbatim), its single
elements (``chain_id_ok.json``, ``oracle_*``, ``usdt_*``, ``usdc_*``), ``rpc_error_in_200.json`` (a
JSON-RPC error object inside HTTP 200), ``tron_usdt_frozen.json`` / ``tron_usdt_not_frozen.json``
(TronGrid triggerconstantcontract, raw_data_hex removed) and ``chainalysis_rest_blocked.html`` (the 403
'not on the Chainalysis Allowed IPs List' page without a key). A Chainalysis REST success needs a key
and an allow-listed egress IP: its documented shape is tested inline.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, FakeHttp, assert_no_secret, run_module
from v3lum.core.datasets import DataStore
from v3lum.core.models import Status
from v3lum.modules.crypto import crypto_sanctions_onchain as oc
from v3lum.modules.crypto.crypto_sanctions_onchain import CryptoSanctionsOnchain

RPC = "https://ethereum-rpc.publicnode.com"
TRIGGER = "https://api.trongrid.io/wallet/triggerconstantcontract"
LISTED = "0x0330070FD38Ec3bB94F58FA55D40368271E9e54A"
EF = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"
TRON_LISTED = "TYK29mbyvVxLaLUKdFSTRADMwoxaVbVZQg"
BTC = "12sjrrhoFEsedNRhtgwvvRqjFTh8fZTDX9"
CHAINALYSIS_KEY = "ca-team-key-0123456789abcdef"


def fx(name: str):
    return json.loads((FIXTURES / "crypto_sanctions_onchain" / name).read_text(encoding="utf-8"))


def batch_answer(oracle: str, usdt: str, usdc: str, chain: str = "chain_id_ok.json") -> list:
    """The batch answer for the module's ids (1 chainId, 2 oracle, 3 USDT, 4 USDC) from recorded elements."""
    out = []
    for i, name in enumerate((chain, oracle, usdt, usdc), start=1):
        item = dict(fx(name))
        item["id"] = i
        out.append(item)
    return out


def rpc_http(answer, **kw) -> FakeHttp:
    return FakeHttp().add("POST", RPC, json=answer, **kw)


# ------------------------------------------------------------------ metadata (cond 1-3, 7)
def test_metadata_follows_the_council_decision():
    cls = CryptoSanctionsOnchain
    assert cls.terms == "key-terms" and cls.default_enabled is True and cls.trust_tier == "trusted"
    assert cls.terms_sources == {"publicnode.ethereum_rpc": "open", "trongrid.api": "key-terms", "chainalysis.sanctions_api": "key-terms"}
    assert cls.disclosure == "third_party" and cls.optional_keys == ("trongrid", "chainalysis")
    assert cls.settings["eth_rpc"].default == RPC and cls.max_requests == 2
    assert cls.health_check().value == EF


def test_contract_table_and_abi_encoding():
    table = oc.load_contracts(DataStore.bundled_json(oc.CONTRACTS_DATA))
    eth = table["evm"]["ethereum"]["contracts"]
    assert [oc.function_selector(eth[k]["signature"]) for k in ("chainalysis_oracle", "usdt", "usdc")] == ["df592f7d", "e47d6060", "fe575a87"]
    assert all(entry["source"] for entry in eth.values()) and table["tron"]["usdt_trc20"]["selector"] == "e47d6060"
    assert oc.eth_call_request(eth["chainalysis_oracle"]["address"], "df592f7d", LISTED, 2) == {
        "jsonrpc": "2.0", "id": 2, "method": "eth_call",
        "params": [{"to": "0x40C57923924B5c5c5455c48D93317139ADDaC8fb",
                    "data": "0xdf592f7d0000000000000000000000000330070fd38ec3bb94f58fa55d40368271e9e54a"}, "latest"]}
    bad = json.loads(json.dumps(table))
    bad["evm"]["ethereum"]["contracts"]["usdt"]["selector"] = "deadbeef"
    with pytest.raises(ValueError):
        oc.load_contracts(bad)


def test_recorded_batch_answer_parses_to_the_verified_values():
    by_id = {item["id"]: item for item in fx("rpc_batch_ok.json")}
    assert oc.parse_chain_id(by_id[1]) == 1
    assert {i: oc.parse_bool_response(by_id[i])[0] for i in range(2, 8)} == {2: True, 3: False, 4: True, 5: False, 6: True, 7: False}


# ------------------------------------------------------------------ EVM checks (cond 2, 5)
def test_sanctioned_and_frozen_address():
    http = rpc_http(batch_answer("oracle_sanctioned.json", "usdt_frozen.json", "usdc_frozen.json"))
    res = run_module(CryptoSanctionsOnchain, f"eth_address:{LISTED}", http)
    assert res.status is Status.OK and len(http.calls) == 1  # one JSON-RPC batch
    sent = json.loads(http.calls[0]["body"])
    assert [c["method"] for c in sent] == ["eth_chainId", "eth_call", "eth_call", "eth_call"]
    assert sent[1]["params"][0]["data"] == "0xdf592f7d0000000000000000000000000330070fd38ec3bb94f58fa55d40368271e9e54a"
    sanctions = [f for f in res.findings if "sanctions" in f.tags]
    freezes = [f for f in res.findings if "issuer_freeze" in f.tags]
    assert len(sanctions) == 1 and sanctions[0].severity.label == "critical" and sanctions[0].title == "Address on the OFAC SDN list (US)"
    assert "stop transactions and escalate to compliance" in sanctions[0].description.lower() and "LGPD art. 20" in sanctions[0].description
    assert len(freezes) == 2 and all(f.severity.label == "high" and "sanctions" not in f.tags for f in freezes)
    assert {f.data["issuer"] for f in freezes} == {"Tether (USDT on Ethereum)", "Circle (USDC on Ethereum)"}
    assert all("sanctioned" not in f.title.lower() for f in freezes)  # a freeze is never 'sanctioned' (cond 5)
    a = res.attributes
    assert a["sanctioned"] is True and a["issuer_frozen"] == ["Tether (USDT on Ethereum)", "Circle (USDC on Ethereum)"]
    assert a["onchain_checks"] == {"chainalysis_oracle": "listed", "usdt_freeze": "frozen", "usdc_freeze": "frozen"}
    http.assert_hosts_within(CryptoSanctionsOnchain)


def test_clean_address_reads_not_listed_never_not_sanctioned():
    http = rpc_http(batch_answer("oracle_not_sanctioned.json", "usdt_not_frozen.json", "usdc_not_frozen.json"))
    res = run_module(CryptoSanctionsOnchain, f"eth_address:{EF}", http)
    assert res.status is Status.EMPTY and not res.findings
    status = res.attributes["sanctions_status"]
    assert status.startswith("not listed by the Chainalysis sanctions checks as of") and "not sanctioned" not in status
    assert "sanctioned" not in res.attributes


@pytest.mark.parametrize(
    "answer,reason",
    [
        (fx("rpc_error_in_200.json"), "JSON-RPC error object for the whole batch (provider marker)"),
        ("bad_item", "one call answered with a JSON-RPC error"),
        ("bad_word", "a result that is not exactly 0 or 1"),
        ("bad_chain", "the RPC is on another chain"),
    ],
)
def test_anything_but_a_0_1_answer_is_could_not_verify(answer, reason):
    if answer == "bad_item":
        answer = batch_answer("oracle_not_sanctioned.json", "usdt_not_frozen.json", "usdc_not_frozen.json")
        answer[1] = {"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "execution reverted"}}
    elif answer == "bad_word":
        answer = batch_answer("oracle_not_sanctioned.json", "usdt_not_frozen.json", "usdc_not_frozen.json")
        answer[1]["result"] = "0x" + "0" * 63 + "2"
    elif answer == "bad_chain":
        answer = batch_answer("oracle_not_sanctioned.json", "usdt_not_frozen.json", "usdc_not_frozen.json")
        answer[0]["result"] = "0x89"
    res = run_module(CryptoSanctionsOnchain, f"eth_address:{EF}", rpc_http(answer))
    assert res.status is Status.ERROR, reason
    assert "could not verify" in res.error and "sanctions_status" not in res.attributes


@pytest.mark.parametrize("kw,expected", [
    ({"status": 429, "text": "Too Many Requests", "times": 3}, Status.RATE_LIMITED),
    ({"status": 502, "text": "bad gateway", "times": 3}, Status.ERROR),
    ({"text": "<html><body>blocked</body></html>"}, Status.ERROR),
])
def test_rpc_refusals_are_could_not_verify(kw, expected):
    res = run_module(CryptoSanctionsOnchain, f"eth_address:{EF}", FakeHttp().add("POST", RPC, **kw))
    assert res.status is expected and "sanctions_status" not in res.attributes


def test_unregistered_eth_rpc_host_is_refused_before_any_request():
    http = FakeHttp()
    res = run_module(CryptoSanctionsOnchain, f"eth_address:{EF}", http, settings={"eth_rpc": "https://rpc.example.net/v3/0123456789abcdef0123"})
    assert res.status is Status.SKIPPED and res.reason_code == "config" and not http.calls
    assert "no provider entry" in res.error


# ------------------------------------------------------------------ TRON (cond 2)
def test_tron_usdt_freeze_through_trongrid():
    http = FakeHttp().add("POST", TRIGGER, json=fx("tron_usdt_frozen.json"))
    res = run_module(CryptoSanctionsOnchain, f"other_crypto_address:{TRON_LISTED}", http)
    assert res.status is Status.OK
    sent = json.loads(http.calls[0]["body"])
    assert sent == {"owner_address": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb", "contract_address": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                    "function_selector": "isBlackListed(address)",
                    "parameter": "000000000000000000000000f512078e07f61a2e28081c8ea86c6056788d18b4", "visible": True}
    [freeze] = res.findings
    assert freeze.data["issuer"] == "Tether (USDT on TRON)" and freeze.severity.label == "high" and "issuer_freeze" in freeze.tags
    http = FakeHttp().add("POST", TRIGGER, json=fx("tron_usdt_not_frozen.json"))
    res = run_module(CryptoSanctionsOnchain, "other_crypto_address:TBXSw8fM4jpQkGc6zZjsVABFpVN7UvXPdV", http)
    assert res.status is Status.EMPTY and res.attributes["onchain_checks"] == {"tron_usdt_freeze": "not frozen"}


def test_tron_constant_call_failure_and_licence():
    failed = {"result": {"code": "CONTRACT_VALIDATE_ERROR", "message": b"Smart contract is not exist.".hex()}}
    res = run_module(CryptoSanctionsOnchain, f"other_crypto_address:{TRON_LISTED}", FakeHttp().add("POST", TRIGGER, json=failed))
    assert res.status is Status.ERROR and "Smart contract is not exist." in res.error
    res = run_module(CryptoSanctionsOnchain, f"other_crypto_address:{TRON_LISTED}", FakeHttp(), allowed_sources=["publicnode.ethereum_rpc"])
    assert res.status is Status.SKIPPED and res.reason_code == "licence"  # key-terms TronGrid without a business plan


# ------------------------------------------------------------------ Chainalysis REST (cond 4)
CHAINALYSIS_URL = f"https://public.chainalysis.com/api/v1/address/{BTC}"
HIT = {"identifications": [{"category": "sanctions", "name": "SANCTIONS: OFAC SDN Example Entity 2026-11-01",
                            "description": "Example entity designated under a sanctions programme (documentation sample).",
                            "url": "https://home.treasury.gov/news/press-releases"}]}


def test_non_evm_chains_need_the_chainalysis_key():
    http = FakeHttp()
    res = run_module(CryptoSanctionsOnchain, f"btc_address:{BTC}", http)
    assert res.status is Status.NEEDS_KEY and "V3LUM_CHAINALYSIS_KEY" in res.error and not http.calls


def test_chainalysis_rest_hit_names_the_designation():
    http = FakeHttp().add("GET", CHAINALYSIS_URL, json=HIT, match_headers={"X-API-Key": CHAINALYSIS_KEY})
    res = run_module(CryptoSanctionsOnchain, f"btc_address:{BTC}", http, keys={"chainalysis": CHAINALYSIS_KEY})
    [finding] = res.findings
    assert finding.severity.label == "critical" and "SANCTIONS: OFAC SDN Example Entity" in finding.description
    assert res.attributes["chainalysis_identifications"][0]["category"] == "sanctions"
    assert_no_secret(CHAINALYSIS_KEY, res.findings, res.attributes, res.raw, res.links, res.error)
    http = FakeHttp().add("GET", CHAINALYSIS_URL, json={"identifications": []})
    res = run_module(CryptoSanctionsOnchain, f"btc_address:{BTC}", http, keys={"chainalysis": CHAINALYSIS_KEY})
    assert res.status is Status.EMPTY and res.attributes["sanctions_status"].startswith("not listed by the Chainalysis")


def test_chainalysis_ip_allow_list_page_is_blocked():
    page = (FIXTURES / "crypto_sanctions_onchain" / "chainalysis_rest_blocked.html").read_bytes()
    http = FakeHttp().add("GET", CHAINALYSIS_URL, status=403, body=page, headers={"content-type": "text/html"})
    res = run_module(CryptoSanctionsOnchain, f"btc_address:{BTC}", http, keys={"chainalysis": CHAINALYSIS_KEY})
    assert res.status is Status.BLOCKED and "Allowed IPs List" in res.error
    # as a second check next to the on-chain oracle, the refusal is per feed and the oracle answer stands
    eth_url = f"https://public.chainalysis.com/api/v1/address/{EF}"
    http = rpc_http(batch_answer("oracle_not_sanctioned.json", "usdt_not_frozen.json", "usdc_not_frozen.json"))
    http.add("GET", eth_url, status=403, body=page, headers={"content-type": "text/html"})
    res = run_module(CryptoSanctionsOnchain, f"eth_address:{EF}", http, keys={"chainalysis": CHAINALYSIS_KEY})
    assert res.status is Status.EMPTY and res.source_statuses["chainalysis.sanctions_api"]["status"] == "blocked"
    assert res.attributes["onchain_checks"]["chainalysis_oracle"] == "not listed"


def test_parsers_never_raise():
    for bad in (None, 1, "x", [], {}, {"identifications": "x"}, {"identifications": [None, {"category": 5}]}):
        oc.parse_identifications(bad)
        oc.parse_bool_response(bad)
        oc.parse_chain_id(bad)
        oc.rpc_error(bad)
    assert oc.parse_bool_response({"result": None}) == (None, "unexpected eth_call result 'None'")
