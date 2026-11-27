"""evm_explorers (P212): Blockscout first, Etherscan/Ethplorer with team keys, PublicNode RPC, ENS, findings.

Fixtures in tests/fixtures/evm_explorers/ (prep batch p2-G09-2, recorded 2026-11-26 from eth.blockscout.com and
ethereum-rpc.publicnode.com keyless, plus the research samples of api.etherscan.io and api.ethplorer.io; the
investigated public addresses are the Ethereum Foundation multisig and the ens.eth DAO timelock; every other
wallet and the contract deployer were replaced by EIP-55/documentation test-vector addresses). Files with
``docshape`` carry the documented schema because no real capture was possible (Etherscan bodies need a key,
the Blockscout scam flag and token balances could not be captured benignly, the counters endpoint was not
called live).
"""

from __future__ import annotations

import hashlib

from tests.fakes import FIXTURES, FakeHttp, assert_no_secret, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.core.validators import keccak256
from v3lum.modules.crypto import evm_explorers as ev
from v3lum.modules.crypto.evm_explorers import EvmExplorers

EF = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"
EF_EIP55 = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
UNKNOWN = "0x77cd85c4734c0d33ec9036547cbe38cd3fb9a3bc"
SCAM = "0x27b1fdb04752bbc536007a920d24acb045561c26"
RPC = "https://ethereum-rpc.publicnode.com"
BS = "https://eth.blockscout.com/api/v2"
ES = "https://api.etherscan.io/v2/api"
ETHERSCAN_KEY = "ES0123456789ABCDEF0123456789ABCDEF"
ETHPLORER_KEY = "EK-team-0123456789abcdef"


def raw(name: str) -> bytes:
    return (FIXTURES / "evm_explorers" / name).read_bytes()


def js(name: str, **kw) -> dict:
    return {"body": raw(name), "headers": {"content-type": "application/json"}, **kw}


def rpc_route(http: FakeHttp, name: str = "eth_rpc_batch_contract_ok.json") -> FakeHttp:
    return http.add("POST", RPC, **js(name))


def blockscout_routes(http: FakeHttp, address: str = EF, *, address_fixture: str = "blockscout_address_ok.json") -> FakeHttp:
    base = f"{BS}/addresses/{address}"
    http.add("GET", base, **js(address_fixture))
    http.add("GET", f"{base}/transactions", **js("blockscout_txs_ok.json"))
    http.add("GET", f"{base}/token-balances", **js("blockscout_token_balances_docshape.json"))
    http.add("GET", f"{base}/counters", **js("blockscout_counters_docshape.json"))
    return http


def es_url(**params) -> str:
    q = "&".join(f"{k}={v}" for k, v in {"chainid": 1, **params, "apikey": ETHERSCAN_KEY}.items())
    return f"{ES}?{q}"


# ------------------------------------------------------------------ metadata (cond 5)
def test_metadata_follows_the_council_decision():
    cls = EvmExplorers
    assert cls.terms == "key-terms" and cls.trust_tier == "community" and cls.default_enabled is True
    assert cls.disclosure == "third_party" and cls.opsec is Opsec.PASSIVE and cls.shares_input is True
    assert set(cls.hosts) == {"eth.blockscout.com", "ethereum-rpc.publicnode.com", "api.etherscan.io", "api.ethplorer.io"}
    assert cls.terms_sources == {"blockscout.api_v2": "open", "publicnode.ethereum_rpc": "open", "etherscan.api": "key-terms",
                                 "ethplorer.api": "key-terms"}
    assert cls.optional_keys == ("etherscan", "ethplorer") and cls.max_requests <= 10
    tiers = {k: v["tier"] for k, v in ev.EVM_PROVIDERS.items()}
    assert tiers == {"blockscout": "community", "eth_rpc": "trusted", "etherscan": "trusted", "ethplorer": "community", "oklink": "trusted"}


def test_failover_plan_keys_and_oklink_gate():
    assert ev.evm_failover_plan() == ["blockscout"]
    assert ev.evm_failover_plan({"etherscan", "ethplorer"}) == ["blockscout", "etherscan", "ethplorer"]
    assert ev.evm_failover_plan({"oklink"}) == ["blockscout"]  # no recorded success fixture: never used
    assert ev.evm_failover_plan({"oklink"}, oklink_ready=True) == ["blockscout", "oklink"]
    assert ev.evm_failover_plan({"etherscan"}, allowed={"blockscout.api_v2"}) == ["blockscout"]  # licence gate


def test_eip55_uses_keccak_not_sha3():
    assert ev.keccak_is_not_sha3()
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert hashlib.sha3_256(b"").hexdigest() != keccak256(b"").hex()
    # EIP-55 test vectors (eips.ethereum.org/EIPS/eip-55)
    for v in ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
              "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"):
        assert ev.eip55(v.lower()) == v
    assert ev.evm_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD") is None  # a mixed-case typo is never sent
    assert ev.evm_address(EF_EIP55) == EF


def test_mixed_case_typo_is_refused_by_the_helper():
    # the core entity normaliser lower-cases eth_address values; the helper refuses a mixed-case EIP-55
    # mismatch wherever a raw value reaches it (e.g. creator/counterparty fields of an answer)
    assert ev.evm_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD") is None
    http = FakeHttp()
    res = run_module(EvmExplorers, "keyword:not-an-address", http)
    assert res.status is Status.SKIPPED and http.calls == []


# ------------------------------------------------------------------ parsers (cond 1-4)
def test_parsers():
    a = ev.parse_blockscout_address(raw("blockscout_address_ok.json"))
    assert a["known"] and a["is_contract"] and a["creator_address"] == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    assert ev.parse_blockscout_address(raw("blockscout_address_unknown.json"))["known"] is False
    assert ev.parse_blockscout_address(b"<html>") is None
    tops = ev.top_token_holdings(ev.parse_blockscout_token_balances(raw("blockscout_token_balances_docshape.json")))
    assert [t["symbol"] for t in tops] == ["WETH", "USDC", "ENS", "DAI", "USDT"] and len(tops) == 5
    assert ev.parse_blockscout_counters(raw("blockscout_counters_docshape.json"))["tx_count"] == 1203
    found = ev.parse_blockscout_search(raw("blockscout_search_ens_ok.json"), "ens.eth")
    assert found["address"] == "0xFe89cc7aBB2C4183683ab71653C4cdc9B02D44b7"
    assert ev.parse_blockscout_search(raw("blockscout_search_ens_ok.json"), "ens")["address"] is None  # token hits are not resolutions
    assert ev.parse_ethplorer_address(raw("ethplorer_address_ok.json"))["creation_time"] == "2015-08-08T15:44:00Z"
    assert len(ev.parse_etherscan_txlist(raw("etherscan_txlist_ok_docshape.json"))) == 6
    assert ev.parse_etherscan_txlist(raw("etherscan_txlist_empty_docshape.json")) == []
    assert ev.parse_etherscan_contract_creation(raw("etherscan_contract_creation_ok_docshape.json"))[0]["creator"].startswith("0x5aaeb6")
    assert ev.parse_etherscan_balance(raw("etherscan_balance_ok_docshape.json")) == 4774551794456062094343


def test_etherscan_status_zero_is_never_empty():
    assert ev.etherscan_problem(raw("etherscan_error_in_200_nokey.json")) == ("error", "Etherscan: Missing/Invalid API Key")
    assert ev.etherscan_problem(raw("etherscan_rate_limited_docshape.json"))[0] == "rate_limited"
    assert ev.etherscan_problem(b'{"status":"0","message":"NOTOK","result":"You have exceeded your daily credit limit"}')[0] == "quota"
    assert ev.etherscan_problem(raw("etherscan_txlist_empty_docshape.json")) is None  # documented genuine empty
    assert ev.etherscan_problem(b'{"status":"0","message":"No transactions found","result":"x"}')[0] == "error"
    assert ev.etherscan_problem(b"<html>") == ("error", "Etherscan: HTML page instead of JSON")


def test_scam_flag_and_suspicious_tags_become_findings_naming_blockscout():
    bf = ev.blockscout_findings(ev.parse_blockscout_address(raw("blockscout_address_scam_docshape.json")))
    kinds = [f["kind"] for f in bf["findings"]]
    assert kinds == ["scam", "suspicious_label", "suspicious_label"] and bf["stop_node"] is None
    sanction = ev.blockscout_findings({"tags": [{"label": "OFAC: Sanctioned", "slug": ""}, {"label": "Binance 14", "slug": ""}]})
    assert sanction["findings"][0]["severity"] == "info" and sanction["stop_node"] == "exchange"
    assert ev.blockscout_findings({"tags": [{"label": "Tornado.Cash: Router", "slug": ""}]})["stop_node"] == "mixer"


# ------------------------------------------------------------------ happy path (cond 1, 2, 4)
def test_blockscout_answers_with_rpc_balance_and_code():
    http = blockscout_routes(rpc_route(FakeHttp()))
    res = run_module(EvmExplorers, f"eth_address:{EF}", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["chain"] == "ethereum" and a["balance"] == "4774.551794456062094343 ETH" and a["is_contract"] is True
    assert a["tx_count"] == 1203 and [t["symbol"] for t in a["top_token_holdings"]][:2] == ["WETH", "USDC"]
    assert a["wallet_labels"] == ["EthDev", "Ethereum Foundation"]  # from the transaction party objects
    assert a["explorer_failover"]["answered_by"] == "blockscout" and a["disclosed_to"] == ["eth_rpc", "blockscout"]
    assert a["activity_window"]["first_seen_exact"] is False and "first_seen" not in a  # more pages exist
    creator = [p for p in res.pivots if p.relation == "contract_creator"]
    assert len(creator) == 1 and creator[0].expand is False and creator[0].entity.value == "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
    cps = [p for p in res.pivots if p.relation == "transacted_with"]
    assert len(cps) == 6 and all(p.expand is False and p.entity.type is T.ETH for p in cps)
    assert a["top_counterparties"][0]["address"] == "0x52908400098527886E0F7030069857D2E4169EE7"  # EIP-55 display
    assert res.findings[0].title == "Ethereum contract summary" and res.findings[0].severity.label == "info"
    assert len(http.calls) == 5
    http.assert_hosts_within(EvmExplorers)


def test_unknown_address_is_a_genuine_empty():
    http = rpc_route(FakeHttp(), "eth_rpc_batch_eoa_empty.json")
    http.add("GET", f"{BS}/addresses/{UNKNOWN}", **js("blockscout_address_unknown.json"))
    res = run_module(EvmExplorers, f"eth_address:{UNKNOWN}", http)
    # the EOA fixture has no chain-id answer: the RPC is could-not-verify, Blockscout's 'never seen' stands
    assert res.status is Status.EMPTY and "never seen by Blockscout" in res.attributes["wallet_status"]
    assert res.source_statuses["publicnode.ethereum_rpc"]["status"] in ("error", Status.ERROR)


def test_scam_address_findings():
    http = rpc_route(FakeHttp(), "eth_rpc_batch_contract_ok.json")
    base = f"{BS}/addresses/{SCAM}"
    http.add("GET", base, **js("blockscout_address_scam_docshape.json"))
    http.add("GET", f"{base}/transactions", json={"items": [], "next_page_params": None})
    http.add("GET", f"{base}/token-balances", json=[])
    http.add("GET", f"{base}/counters", json={"transactions_count": "3", "token_transfers_count": "0"})
    res = run_module(EvmExplorers, f"eth_address:{SCAM}", http)
    sev = {f.title: (f.severity.label, f.source, sorted(f.tags)) for f in res.findings}
    assert sev["Blockscout flags this address as a scam"] == ("high", "blockscout.api_v2", ["crypto_scam", "fraud"])
    assert sev["Blockscout public tag marks the address as suspicious"][0] == "medium"
    assert all(f.criterion for f in res.findings if f.severity.label != "info")


# ------------------------------------------------------------------ failover (cond 3, 4)
def test_blockscout_429_fails_over_to_etherscan_with_a_redacted_key():
    http = rpc_route(FakeHttp())
    http.add("GET", f"{BS}/addresses/{EF}", status=429, text="Too Many Requests")
    http.add("GET", es_url(module="account", action="balance", address=EF, tag="latest"), **js("etherscan_balance_ok_docshape.json"))
    http.add("GET", es_url(module="account", action="txlist", address=EF, page=1, offset=50, sort="desc"), **js("etherscan_txlist_ok_docshape.json"))
    http.add("GET", es_url(module="contract", action="getcontractcreation", contractaddresses=EF), **js("etherscan_contract_creation_ok_docshape.json"))
    res = run_module(EvmExplorers, f"eth_address:{EF}", http, keys={"etherscan": ETHERSCAN_KEY})
    assert res.status is Status.OK and res.attributes["explorer_failover"]["answered_by"] == "etherscan"
    per = {p["provider"]: p["status"] for p in res.attributes["explorer_failover"]["per_provider"]}
    assert per == {"eth_rpc": "ok", "blockscout": "rate_limited", "etherscan": "ok"}
    assert [p.entity.value for p in res.pivots if p.relation == "contract_creator"] == ["0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"]
    assert_no_secret(ETHERSCAN_KEY, res.attributes, res.findings, res.raw, res.error, res.source_statuses, res.links)


def test_etherscan_error_in_200_is_never_empty():
    http = FakeHttp().add("GET", f"{BS}/addresses/{EF}", status=503, text="down")
    http.add("GET", es_url(module="account", action="balance", address=EF, tag="latest"), **js("etherscan_error_in_200_nokey.json"))
    res = run_module(EvmExplorers, f"eth_address:{EF}", http, keys={"etherscan": ETHERSCAN_KEY},
                     allowed_sources=frozenset({"blockscout.api_v2", "etherscan.api"}))
    assert res.status is Status.ERROR and "could not verify" in res.error
    per = {p["provider"]: p["status"] for p in res.attributes["explorer_failover"]["per_provider"]}
    assert per["etherscan"] == "error"
    http2 = FakeHttp().add("GET", f"{BS}/addresses/{EF}", status=503, text="down")
    http2.add("GET", es_url(module="account", action="balance", address=EF, tag="latest"), **js("etherscan_rate_limited_docshape.json"))
    res2 = run_module(EvmExplorers, f"eth_address:{EF}", http2, keys={"etherscan": ETHERSCAN_KEY},
                      allowed_sources=frozenset({"blockscout.api_v2", "etherscan.api"}))
    assert res2.status is Status.RATE_LIMITED


def test_ethplorer_team_key_only_never_freekey():
    http = FakeHttp().add("GET", f"{BS}/addresses/{EF}", status=503, text="down")
    res = run_module(EvmExplorers, f"eth_address:{EF}", http, keys={"ethplorer": "freekey"},
                     allowed_sources=frozenset({"blockscout.api_v2", "ethplorer.api"}))
    assert not any("ethplorer" in c["url"] for c in http.calls)
    per = {p["provider"]: p for p in res.attributes["explorer_failover"]["per_provider"]}
    assert per["ethplorer"]["status"] == "needs_key" and "shared public test key" in per["ethplorer"]["reason"]
    http2 = FakeHttp().add("GET", f"{BS}/addresses/{EF}", status=503, text="down")
    http2.add("GET", f"https://api.ethplorer.io/getAddressInfo/{EF}?apiKey={ETHPLORER_KEY}", **js("ethplorer_address_ok.json"))
    res2 = run_module(EvmExplorers, f"eth_address:{EF}", http2, keys={"ethplorer": ETHPLORER_KEY},
                      allowed_sources=frozenset({"blockscout.api_v2", "ethplorer.api"}))
    a = res2.attributes
    assert res2.status is Status.OK and a["explorer_failover"]["answered_by"] == "ethplorer"
    assert a["first_seen"] == "2015-08-08T15:44:00Z" and a["activity_window"]["first_seen_exact"] is True
    assert a["top_token_holdings"][0]["symbol"] == "WETH"
    assert_no_secret(ETHPLORER_KEY, res2.attributes, res2.findings, res2.raw, res2.source_statuses)


def test_rpc_error_in_200_is_reported_and_blockscout_still_answers():
    http = blockscout_routes(FakeHttp().add("POST", RPC, **js("eth_rpc_error_in_200.json")))
    res = run_module(EvmExplorers, f"eth_address:{EF}", http)
    assert res.status is Status.OK and res.attributes["balance"] == "4774.551794456062094343 ETH"  # Blockscout's balance
    assert res.source_statuses["publicnode.ethereum_rpc"]["status"] in ("error", Status.ERROR)


def test_everything_failing_is_could_not_verify():
    http = FakeHttp().add("POST", RPC, status=503, text="down").add("GET", f"{BS}/addresses/{EF}", status=403,
                                                                     text="<html><head><title>Just a moment...</title></head>cf-chl-widget</html>")
    res = run_module(EvmExplorers, f"eth_address:{EF}", http)
    assert res.status in (Status.BLOCKED, Status.ERROR) and res.status is not Status.EMPTY
    assert res.status is Status.BLOCKED


def test_malformed_blockscout_answer_is_error_never_empty():
    http = FakeHttp().add("GET", f"{BS}/addresses/{EF}", body=b"{oops", headers={"content-type": "application/json"})
    http.add("GET", f"{BS}/addresses/{EF}/transactions", body=b"[1,2", headers={"content-type": "application/json"})
    res = run_module(EvmExplorers, f"eth_address:{EF}", http, allowed_sources=frozenset({"blockscout.api_v2"}))
    assert res.status is Status.ERROR


def test_blockscout_address_timeout_still_uses_the_transaction_list():
    http = rpc_route(FakeHttp())
    base = f"{BS}/addresses/{EF}"
    http.add("GET", base, status=504, text="gateway timeout")
    http.add("GET", f"{base}/transactions", **js("blockscout_txs_ok.json"))
    http.add("GET", f"{base}/token-balances", json=[])
    http.add("GET", f"{base}/counters", **js("blockscout_counters_docshape.json"))
    res = run_module(EvmExplorers, f"eth_address:{EF}", http)
    assert res.status is Status.OK and res.attributes["explorer_failover"]["answered_by"] == "blockscout"
    assert "address endpoint" in res.attributes["explorer_failover"]["per_provider"][1]["reason"]
    assert res.attributes["wallet_labels"] == ["EthDev", "Ethereum Foundation"]


def test_licence_profile_without_any_source_skips():
    res = run_module(EvmExplorers, f"eth_address:{EF}", FakeHttp(), allowed_sources=frozenset())
    assert res.status is Status.SKIPPED and res.reason_code == "licence"


# ------------------------------------------------------------------ ENS (cond 1)
def test_ens_name_resolves_through_blockscout_search():
    http = FakeHttp().add("GET", f"{BS}/search?q=ens.eth", **js("blockscout_search_ens_ok.json"))
    res = run_module(EvmExplorers, "domain:ens.eth", http)
    assert res.status is Status.OK and res.attributes["ens_name"] == "ens.eth"
    piv = res.pivots[0]
    assert piv.relation == "ens_resolves_to" and piv.entity.value == "0xfe89cc7abb2c4183683ab71653c4cdc9b02d44b7"
    res2 = run_module(EvmExplorers, "domain:example.com", FakeHttp())
    assert res2.status is Status.SKIPPED and res2.reason_code == "not_applicable"


def test_ens_name_without_record_is_empty():
    http = FakeHttp().add("GET", f"{BS}/search?q=nobody-here.eth", json={"items": [], "next_page_params": None})
    res = run_module(EvmExplorers, "keyword:nobody-here.eth", http)
    assert res.status is Status.EMPTY


def test_problem_labels_survive_the_sanitizer():
    http = rpc_route(FakeHttp())
    base = f"{BS}/addresses/{EF}"
    http.add("GET", base, **js("blockscout_address_ok.json"))
    http.add("GET", f"{base}/transactions", **js("blockscout_txs_ok.json"))
    http.add("GET", f"{base}/token-balances", status=500, text="ReadTimeout")
    http.add("GET", f"{base}/counters", **js("blockscout_counters_docshape.json"))
    res = run_module(EvmExplorers, f"eth_address:{EF}", http)
    reason = res.attributes["explorer_failover"]["per_provider"][1]["reason"]
    assert res.status is Status.OK and reason.startswith("holdings endpoint failed") and "secret:" not in reason
