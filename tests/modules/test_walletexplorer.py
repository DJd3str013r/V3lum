"""walletexplorer (P208): Bitcoin wallet clustering and service labels (WalletExplorer.com).

Fixtures in tests/fixtures/walletexplorer/ (prep batch p2-G09-1, live 2026-11-26 from www.walletexplorer.com):
``lookup_labelled.json`` (the API page's own example address, label BTC-e.com), ``lookup_unlabelled.json``
(genesis address, research sample), ``lookup_not_found.json`` (a synthetic never-used P2PKH address),
``lookup_invalid_input.json`` ('1NonExistingAddress': identical to a real miss), ``error_derived.json``
(the API page's documented {'error': ...} form) and ``home_service_index.html`` (16 real <li> items of the
home page's 'Top wallets' table under its 5 headings, plus the real footer status line).
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.crypto.walletexplorer import (
    HOME_URL,
    LABEL_NOTE,
    LOOKUP_URL,
    Walletexplorer,
    classify_label,
    parse_lookup,
    parse_service_index,
    validate_caller_id,
)

LABELLED = "16SbwNa22nBwhLtg6HzWVYFQiUxtNzAUpt"
GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
UNUSED = "1KwdXzmjqp39iuZCecTGytQfxVtHiLmg1Z"
CALLER = "cti@company.example"
SETTINGS = {"contact_email": CALLER}


@pytest.fixture(autouse=True)
def no_backoff():
    from v3lum.modules.darkweb_ransomware import onion_safety

    onion_safety._FAILED.clear()


def lookup(http: FakeHttp, address: str, caller: str = CALLER, **kw) -> FakeHttp:
    return http.add("GET", f"{LOOKUP_URL}?address={address}&caller={caller}", **kw)


def with_index(http: FakeHttp, status: int = 200) -> FakeHttp:
    body = (FIXTURES / "walletexplorer" / "home_service_index.html").read_bytes()
    return http.add("GET", HOME_URL, status=status, body=body, headers={"content-type": "text/html; charset=UTF-8"})


def test_metadata():
    cls = Walletexplorer
    assert cls.terms == "open" and cls.trust_tier == "community" and cls.default_enabled is True
    assert (cls.provider, cls.hosts, cls.min_interval, cls.max_requests) == ("walletexplorer", ("www.walletexplorer.com",), 1.0, 1)
    assert "walletexplorer_caller_id" in cls.settings and cls.manual_link == "https://www.walletexplorer.com/address/{q}"


def test_without_caller_id_is_skipped_config_and_sends_nothing():
    http = FakeHttp()
    res = run_module(Walletexplorer, f"btc_address:{LABELLED}", http)
    assert res.status is Status.SKIPPED and res.reason_code == "config" and http.calls == []


@pytest.mark.parametrize(
    "caller,why",
    [
        ("john.doe@company.example", "personal e-mail"),
        (f"team-{LABELLED}", "investigated value"),
        ("case-2026-0042-soc", "case id"),
        ("soc team", "spaces"),
    ],
)
def test_identifying_caller_ids_are_refused(caller, why):
    http = FakeHttp()
    res = run_module(Walletexplorer, f"btc_address:{LABELLED}", http, settings={"walletexplorer_caller_id": caller}, case_id="case-2026-0042")
    assert res.status is Status.SKIPPED and res.reason_code == "config" and http.calls == [], why


def test_caller_precedence_core_setting_then_module_then_contact_email():
    http = lookup(FakeHttp(), UNUSED, caller="v3lum-cti", json=module_fixture("walletexplorer", "lookup_not_found.json"))
    res = run_module(Walletexplorer, f"btc_address:{UNUSED}", http, settings={**SETTINGS, "walletexplorer_caller_id": "v3lum-cti"})
    assert res.status is Status.EMPTY
    http2 = lookup(FakeHttp(), UNUSED, caller="shared-team-id", json=module_fixture("walletexplorer", "lookup_not_found.json"))
    res2 = run_module(Walletexplorer, f"btc_address:{UNUSED}", http2, settings={"caller_id": "shared-team-id", "walletexplorer_caller_id": "v3lum-cti"})
    assert res2.status is Status.EMPTY


def test_exchange_label_is_a_stop_node_and_a_legal_request_lead():
    http = with_index(lookup(FakeHttp(), LABELLED, json=module_fixture("walletexplorer", "lookup_labelled.json")))
    res = run_module(Walletexplorer, f"btc_address:{LABELLED}", http, settings=SETTINGS)
    assert res.status is Status.OK and res.requests == 1  # the service index is a dataset download
    cluster = res.attributes["wallet_cluster"]
    assert cluster == {"wallet_id": "000003a2f31608c0", "updated_to_block": 977103, "label": "BTC-e.com", "category": "exchange",
                       "legal_request_lead": True, "note": LABEL_NOTE}
    assert res.attributes["stop_node_hint"] == "exchange" and res.attributes["wallet_labels"] == ["BTC-e.com"]
    [finding] = res.findings
    assert finding.title == "WalletExplorer service label" and finding.severity.label == "info"
    assert set(finding.tags) == {"stop_node", "exchange"} and finding.confidence_label.value == "possible"
    assert LABEL_NOTE in finding.description and "legal request to BTC-e.com" in finding.description
    assert "not proof of ownership" in finding.description and "WalletExplorer.com" in finding.description
    assert "WalletExplorer.com" in res.attributes["data_attribution"]
    http.assert_hosts_within(Walletexplorer)


@pytest.mark.parametrize(
    "label,category,severity,tags,lead",
    [
        ("HelixMixer-old3", "mixer", "low", {"stop_node", "mixer"}, False),
        ("AlphaBayMarket", "darknet_market", "medium", {"stop_node", "darknet_market"}, False),
        ("CryptoLocker", "ransomware", "medium", {"stop_node", "ransomware"}, False),
        ("SatoshiDice.com", "gambling", "info", {"stop_node", "crypto_service"}, True),
    ],
)
def test_label_classes(label, category, severity, tags, lead):
    doc = {"found": True, "label": label, "wallet_id": "00000000deadbeef", "updated_to_block": 977103}
    http = with_index(lookup(FakeHttp(), LABELLED, json=doc))
    res = run_module(Walletexplorer, f"btc_address:{LABELLED}", http, settings=SETTINGS)
    [finding] = res.findings
    assert res.attributes["wallet_cluster"]["category"] == category and finding.severity.label == severity
    assert set(finding.tags) == tags and res.attributes["wallet_cluster"]["legal_request_lead"] is lead


def test_label_without_the_service_index_falls_back_to_name_rules():
    http = with_index(lookup(FakeHttp(), LABELLED, json=module_fixture("walletexplorer", "lookup_labelled.json")), status=503)
    res = run_module(Walletexplorer, f"btc_address:{LABELLED}", http, settings=SETTINGS)
    assert res.status is Status.OK and res.attributes["wallet_cluster"]["category"] == "service"
    assert res.attributes["wallet_cluster"]["legal_request_lead"] is True


def test_unlabelled_cluster_is_info():
    http = lookup(FakeHttp(), GENESIS, json=module_fixture("walletexplorer", "lookup_unlabelled.json"))
    res = run_module(Walletexplorer, f"btc_address:{GENESIS}", http, settings=SETTINGS)
    assert res.status is Status.OK and res.findings[0].title == "WalletExplorer cluster (unlabelled)"
    assert res.attributes["wallet_cluster"]["wallet_id"] == "9155adea5d855091" and "stop_node_hint" not in res.attributes


def test_not_found_is_empty_with_the_data_block():
    http = lookup(FakeHttp(), UNUSED, json=module_fixture("walletexplorer", "lookup_not_found.json"))
    res = run_module(Walletexplorer, f"btc_address:{UNUSED}", http, settings=SETTINGS)
    assert res.status is Status.EMPTY and res.attributes["wallet_cluster"]["updated_to_block"] == 977103


def test_error_in_200_and_malformed_answers():
    http = lookup(FakeHttp(), UNUSED, json=module_fixture("walletexplorer", "error_derived.json"))
    res = run_module(Walletexplorer, f"btc_address:{UNUSED}", http, settings=SETTINGS)
    assert res.status is Status.ERROR and "could not verify" in res.error
    http2 = lookup(FakeHttp(), UNUSED, json={"updated_to_block": 1})
    assert run_module(Walletexplorer, f"btc_address:{UNUSED}", http2, settings=SETTINGS).status is Status.ERROR
    http3 = lookup(FakeHttp(), UNUSED, text="<html>maintenance</html>")
    assert run_module(Walletexplorer, f"btc_address:{UNUSED}", http3, settings=SETTINGS).status is Status.ERROR


@pytest.mark.parametrize("status,expected", [(429, Status.RATE_LIMITED), (500, Status.ERROR)])
def test_http_failures(status, expected):
    http = lookup(FakeHttp(), UNUSED, status=status, text="x", times=2)
    assert run_module(Walletexplorer, f"btc_address:{UNUSED}", http, settings=SETTINGS).status is expected


def test_parsers():
    labels = parse_service_index((FIXTURES / "walletexplorer" / "home_service_index.html").read_text())
    assert labels["BTC-e.com-old"] == {"category": "exchange", "base": "BTC-e.com"}
    assert labels["SlushPool.com"]["category"] == "mining_pool" and labels["CryptoLocker"]["category"] == "historic"
    assert classify_label("CryptoLocker", labels)["category"] == "ransomware"
    assert classify_label("Btcst.com-pirateat40", labels)["category"] == "fraud_scheme"
    assert parse_lookup(module_fixture("walletexplorer", "lookup_invalid_input.json"))["status"] == "empty"
    assert validate_caller_id("cti@company.example") is None and validate_caller_id("v3lum-csirt") is None
    assert validate_caller_id("") and validate_caller_id("someone@company.example")
