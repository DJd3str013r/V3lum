"""ton_explorer (P214): Toncenter v3 wallet lookups and the Telegram collectible owner lead.

Fixtures in tests/fixtures/ton_explorer/ (prep batch p3-G09-1, live 2026-11-26 from toncenter.com, 8 requests):
``wallet_information_ok.json`` and ``transactions_ok.json`` (TON Foundation wallet; counterparties replaced by
synthetic ``0:<sha256('v3lum-doc-ton-...')>`` addresses, memos by 'example memo N'), ``wallet_information_not_wallet_409``
(a collection contract), ``invalid_address_422.json``, ``nft_items_username_ok.json`` (the @github/@google username
NFTs of the Telegram Usernames collection; owners replaced by synthetic wallets), ``nft_items_not_found.json``,
``nft_transfers_ok.json`` (synthetic previous/new owners), ``nft_collections_ok.json``, ``masterchain_info_ok.json``;
DERIVED: ``nft_items_on_sale_derived.json``, ``nft_items_number_derived.json`` (SYNTHETIC +888 0000 0000 item),
``transactions_empty_derived.json`` and ``rate_limited_429_derived.json`` (the v2 error envelope).
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlencode

import pytest

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.crypto import ton_explorer as ton
from v3lum.modules.crypto.ton_explorer import TonExplorer

BASE = "https://toncenter.com/api/v3/"
FOUNDATION = "0:83DFD552E63729B472FCBCC8C45EBCC6691702558B68EC7527E1BA403A0F31A8"
FOUNDATION_EQ = "EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N"
FOUNDATION_UQ = "UQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqEBI"
CP1 = "0:1F4024AB38A6A7661739F6B31D9F211C008C9A15172E585A2D209D462B1A7998"
OWNER_GITHUB = "0:0881FBEDAFD2853D9FC32C1C48554F8B377361903274BB8B64ABCEF86DCDCFAB"
OWNER_NUMBER = "0:A49E8CF6C87386EB4540FCF6A285840B9D224815FF4DB540E6B6012AEEB503B4"
GITHUB_ITEM = "0:118616A1E94829BDFDCE00C74011F5A9AEB780D46C07BAFAA1D069E8A3F5A470"
NUMBER_ITEM = "0:53529D89A929416F5C348E0536DC2F0BBB01AAD7E7E2DA3FE3E4F0E4160D994B"
CASE = "fraud investigation of a Telegram scam (ticket SEC-1)"


def fx(name: str) -> bytes:
    return (FIXTURES / "ton_explorer" / name).read_bytes()


def url(path: str, **params: str) -> str:
    return BASE + path + ("?" + urlencode(params) if params else "")


def wallet_url(raw: str = FOUNDATION) -> str:
    return url("walletInformation", address=raw, use_v2="false")


def tx_url(raw: str = FOUNDATION) -> str:
    return url("transactions", account=raw, limit="20", offset="0", sort="desc")


def items_url(kind: str, token: str) -> str:
    params, _ = ton.nft_request(kind, token)
    return url("nft/items", **params)


def transfers_url(item: str) -> str:
    return url("nft/transfers", item_address=item, limit="3", offset="0", sort="desc")


def add(http: FakeHttp, u: str, name: str, status: int = 200, **kw) -> FakeHttp:
    return http.add("GET", u, status=status, body=fx(name), headers={"content-type": "application/json"}, **kw)


def subject(entity: Entity, role: str = "fraud", purpose: str = CASE) -> ScanOptions:
    return ScanOptions(subject_roles={entity.key: role}, purpose=purpose)


# ------------------------------------------------------------------ metadata (cond 1, 4)
def test_metadata_matches_the_council_decision():
    cls = TonExplorer
    assert cls.default_enabled is False and cls.terms == "open" and cls.trust_tier == "community"
    assert (cls.provider, cls.hosts, cls.sources, cls.optional_keys) == ("toncenter", ("toncenter.com",), ("toncenter.api_v3",), ("toncenter",))
    assert cls.opsec.name == "PASSIVE" and cls.disclosure == "third_party" and cls.shares_input is True
    assert "tonapi.io" not in cls.hosts and "api.getgems.io" not in cls.hosts  # held (cond 4)
    assert cls.health_check().etype is T.CRYPTO and cls.health_check().value == FOUNDATION


# ------------------------------------------------------------------ cond 1: address codec
def test_crc16_xmodem_check_value():
    assert ton.crc16_xmodem(b"123456789") == 0x31C3


def test_friendly_and_raw_forms_decode_and_encode():
    info = ton.decode_ton_address(FOUNDATION_EQ)
    assert info["raw"] == FOUNDATION and info["bounceable"] is True and info["testnet"] is False
    assert ton.decode_ton_address(FOUNDATION_UQ)["bounceable"] is False
    assert ton.encode_ton_address(FOUNDATION) == FOUNDATION_EQ and ton.encode_ton_address(FOUNDATION, bounceable=False) == FOUNDATION_UQ
    assert ton.ton_raw(ton.TELEGRAM_USERNAMES_COLLECTION) == ton.TELEGRAM_USERNAMES_RAW
    assert ton.ton_raw(ton.ANONYMOUS_NUMBERS_COLLECTION) == ton.ANONYMOUS_NUMBERS_RAW
    master = ton.decode_ton_address("Ef8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM0vF")
    assert master["workchain"] == -1 and master["raw"].startswith("-1:3333")
    assert ton.decode_ton_address(FOUNDATION.lower())["raw"] == FOUNDATION
    testnet = ton.encode_ton_address(FOUNDATION, testnet=True)
    assert ton.decode_ton_address(testnet)["testnet"] is True


@pytest.mark.parametrize("bad", [
    "EQCA14o1-VWhS2efqoh_9M1b_A9DtKTuoqfmkn83AbJzwnPj",  # bad CRC
    "EQCA14o1-VWhS2efqoh_9M1b_A9DtKTuoqfmkn83AbJzwnP",  # 47 characters
    "EQCA14o1+VWhS2efqoh_9M1b_A9DtKTuoqfmkn83AbJzwnPi",  # mixed alphabets
    "1:" + "A" * 64, "0:" + "A" * 63, None, "", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
])
def test_invalid_addresses_are_refused(bad):
    assert ton.decode_ton_address(bad) is None


def test_bad_flags_are_refused():
    import base64

    raw = bytes.fromhex(FOUNDATION[2:])
    body = bytes([0x22, 0]) + raw
    body += ton.crc16_xmodem(body).to_bytes(2, "big")
    assert ton.decode_ton_address(base64.urlsafe_b64encode(body).decode()) is None


# ------------------------------------------------------------------ address lookups
def test_wallet_lookup_reports_state_and_counterparties_without_memos():
    http = add(add(FakeHttp(), wallet_url(), "wallet_information_ok.json"), tx_url(), "transactions_ok.json")
    res = run_module(TonExplorer, f"other_crypto_address:{FOUNDATION}", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["chain"] == "ton" and a["balance"] == "1593484.520291669 TON" and a["account_type"] == "wallet v3 r2"
    assert a["ton_address_forms"]["non_bounceable"] == FOUNDATION_UQ and a["transfers_seen"] == 2
    [cp] = a["top_counterparties"]  # the second transaction is aborted: not a counterparty
    assert cp["address"] == CP1 and cp["received_from"] == "10 TON" and cp["direction"] == "in"
    [pivot] = res.pivots
    assert (pivot.entity.value, pivot.relation, pivot.expand) == (CP1, "transacted_with", False)
    assert "example memo" not in repr(res.to_dict())  # comments are counted, never stored
    assert res.findings[0].data["counterparties_total"] == 1
    assert any("tonviewer.com" in u for _, u in res.links)
    http.assert_hosts_within(TonExplorer)


def test_keyless_and_keyed_requests():
    http = add(add(FakeHttp(), wallet_url(), "wallet_information_ok.json", match_headers={"X-API-Key": "k" * 64}), tx_url(), "transactions_ok.json")
    res = run_module(TonExplorer, f"other_crypto_address:{FOUNDATION}", http, keys={"toncenter": "k" * 64})
    assert res.status is Status.OK
    assert "k" * 64 not in repr(res.to_dict())


def test_rejected_key_is_needs_key():
    http = FakeHttp().add("GET", wallet_url(), status=401, json={"ok": False, "error": "API key does not exist", "code": 401})
    res = run_module(TonExplorer, f"other_crypto_address:{FOUNDATION}", http, keys={"toncenter": "k" * 64})
    assert res.status is Status.NEEDS_KEY


def test_contract_address_is_reported_as_contract():
    raw = ton.TELEGRAM_USERNAMES_RAW
    http = add(add(FakeHttp(), wallet_url(raw), "wallet_information_not_wallet_409.json", status=409), tx_url(raw), "transactions_empty_derived.json")
    res = run_module(TonExplorer, f"other_crypto_address:{raw}", http)
    assert res.status is Status.OK and res.attributes["account_type"] == "contract (not a wallet)" and res.pivots == []


def test_never_used_wallet_is_empty():
    http = FakeHttp().add("GET", wallet_url(), json={"balance": "0", "status": "uninit"})
    res = run_module(TonExplorer, f"other_crypto_address:{FOUNDATION}", http)
    assert res.status is Status.EMPTY and "no on-chain activity" in res.attributes["wallet_status"]


def test_invalid_address_422_is_error():
    http = add(FakeHttp(), wallet_url(), "invalid_address_422.json", status=422)
    res = run_module(TonExplorer, f"other_crypto_address:{FOUNDATION}", http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_rate_limits_challenges_and_server_errors_are_could_not_verify():
    http = add(FakeHttp(), wallet_url(), "rate_limited_429_derived.json", status=429)
    assert run_module(TonExplorer, f"other_crypto_address:{FOUNDATION}", http).status is Status.RATE_LIMITED
    http = add(FakeHttp(), wallet_url(), "rate_limited_429_derived.json")  # error-in-200 (v2 envelope)
    assert run_module(TonExplorer, f"other_crypto_address:{FOUNDATION}", http).status is Status.RATE_LIMITED
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", wallet_url(), status=403, text=page)
    assert run_module(TonExplorer, f"other_crypto_address:{FOUNDATION}", http).status is Status.BLOCKED
    http = FakeHttp().add("GET", wallet_url(), status=503, text="unavailable", times=3)
    assert run_module(TonExplorer, f"other_crypto_address:{FOUNDATION}", http).status is Status.ERROR


@pytest.mark.parametrize("body", [b"{not json", b"[]", b'{"error": "internal"}'])
def test_malformed_answers_are_error(body):
    http = FakeHttp().add("GET", wallet_url(), body=body, headers={"content-type": "application/json"})
    assert run_module(TonExplorer, f"other_crypto_address:{FOUNDATION}", http).status is Status.ERROR


def test_non_ton_addresses_are_never_sent():
    http = FakeHttp()
    res = run_module(TonExplorer, "other_crypto_address:TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


# ------------------------------------------------------------------ cond 2: gates
def test_phone_and_username_gates():
    assert ton.ton_phone_gate("+888 0123 4567") == "88801234567" and ton.ton_phone_gate("+888 8 888") == "8888888"
    assert ton.ton_phone_gate("+55 11 5555-0100") is None and ton.ton_phone_gate("+8881234") == "8881234"
    assert ton.ton_phone_gate("+888123") is None
    assert ton.ton_username_gate("@GitHub") == "github" and ton.ton_username_gate("https://t.me/github") == "github"
    assert ton.ton_username_gate("github.t.me") == "github"
    for bad in ("abc", "1abc", "bad__name", "name_", "x" * 33, None):
        assert ton.ton_username_gate(bad) is None


@pytest.mark.parametrize("entity", [Entity(T.PHONE, "+5511555501000"), Entity(T.USERNAME, "a_b_")])
def test_ordinary_numbers_and_usernames_never_apply(entity):
    http = FakeHttp()
    res = run_module(TonExplorer, entity, http, options=subject(entity))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_collectible_lookup_needs_a_fraud_or_threat_subject_with_purpose():
    entity = Entity.make(T.USERNAME, "github")
    for options in (ScanOptions(purpose=CASE), subject(entity, role="incident_victim"), subject(entity, purpose="")):
        http = FakeHttp()
        res = run_module(TonExplorer, entity, http, options=options)
        assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []


def test_collectible_lookup_never_runs_on_pivots():
    entity = Entity.make(T.USERNAME, "github")
    http = FakeHttp()
    res = run_module(TonExplorer, entity, http, options=subject(entity), is_seed=False, depth=1,
                     provenance=(("domain:example.com", "uses_username", "some_module"),))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []


# ------------------------------------------------------------------ cond 3: NFT -> owner lead
def test_nft_index_is_sha256_of_the_token():
    assert ton.nft_index("github") == int.from_bytes(hashlib.sha256(b"github").digest(), "big")
    assert str(ton.nft_index("github")) == "87155146687651342500831811744211008803830373161988111035888956821006684411726"  # live


def test_collectible_username_gives_a_dated_probable_owner_lead():
    entity = Entity.make(T.TELEGRAM_HANDLE, "@github")
    http = add(add(FakeHttp(), items_url("username", "github"), "nft_items_username_ok.json"), transfers_url(GITHUB_ITEM), "nft_transfers_ok.json")
    res = run_module(TonExplorer, entity, http, options=subject(entity, role="threat"))
    assert res.status is Status.OK
    [lead] = res.pivots
    assert (lead.entity.type, lead.entity.value, lead.relation) == (T.CRYPTO, OWNER_GITHUB, "current_nft_owner")
    assert lead.expand is False and lead.confidence_label.value == "probable"
    assert "ownership can change" in lead.note and "2024-11-04" in lead.note and "never identity proof" in lead.note
    c = res.attributes["ton_collectible"]
    assert c["token"] == "@github" and c["transfer_date"].startswith("2024-11-04") and c["on_sale"] is False
    [finding] = res.findings
    assert finding.confidence_label.value == "probable" and finding.data["identity_proof"] is False
    assert finding.severity.label == "info" and "collectible_owner" in finding.tags
    assert "a_TON_of_privacy" in TonExplorer.notice
    http.assert_hosts_within(TonExplorer)


def test_on_sale_owner_is_the_seller_and_the_date_is_hidden():
    entity = Entity.make(T.USERNAME, "github")
    http = add(add(FakeHttp(), items_url("username", "github"), "nft_items_on_sale_derived.json"), transfers_url(GITHUB_ITEM), "nft_transfers_ok.json")
    res = run_module(TonExplorer, entity, http, options=subject(entity))
    assert res.status is Status.OK and res.pivots[0].entity.value == OWNER_GITHUB  # real_owner, not the sale contract
    c = res.attributes["ton_collectible"]
    assert c["on_sale"] is True and c["sale_contract"].startswith("EQ")


def test_anonymous_number_lookup():
    entity = Entity(T.PHONE, "+88800000000")  # built directly: the core phone normaliser refuses +888 (core request)
    http = add(add(FakeHttp(), items_url("number", "88800000000"), "nft_items_number_derived.json"), transfers_url(NUMBER_ITEM), "nft_transfers_ok.json")
    res = run_module(TonExplorer, entity, http, options=subject(entity))
    assert res.status is Status.OK and res.pivots[0].entity.value == OWNER_NUMBER
    assert res.attributes["ton_collectible"]["kind"] == "number"
    assert "another wallet" in res.attributes["ton_collectible"]["transfer_date_note"]  # transfers are of another item


def test_not_collectible_and_mismatched_answers_are_empty():
    entity = Entity.make(T.USERNAME, "microsoft")
    http = add(FakeHttp(), items_url("username", "microsoft"), "nft_items_not_found.json")
    res = run_module(TonExplorer, entity, http, options=subject(entity))
    assert res.status is Status.EMPTY and "not a Telegram collectible username" in res.attributes["wallet_status"]
    http = add(FakeHttp(), items_url("username", "microsoft"), "nft_items_username_ok.json")  # answers for other tokens
    res = run_module(TonExplorer, entity, http, options=subject(entity))
    assert res.status is Status.EMPTY and res.pivots == []  # never a wrong owner


def test_transfer_history_failure_keeps_the_owner_without_a_date():
    entity = Entity.make(T.USERNAME, "github")
    http = add(FakeHttp(), items_url("username", "github"), "nft_items_username_ok.json")
    http.add("GET", transfers_url(GITHUB_ITEM), status=500, text="boom", times=3)
    res = run_module(TonExplorer, entity, http, options=subject(entity))
    assert res.status is Status.OK and res.pivots[0].entity.value == OWNER_GITHUB
    assert res.attributes["ton_collectible"]["transfer_date"] is None
    assert "could not be read" in res.attributes["ton_collectible"]["transfer_date_note"]


def test_collectible_lookup_rate_limited():
    entity = Entity.make(T.USERNAME, "github")
    http = add(FakeHttp(), items_url("username", "github"), "rate_limited_429_derived.json", status=429)
    assert run_module(TonExplorer, entity, http, options=subject(entity)).status is Status.RATE_LIMITED


# ------------------------------------------------------------------ pure parsers
def test_parsers_on_live_fixtures():
    import json

    tx = ton.parse_transactions(json.loads(fx("transactions_ok.json")), FOUNDATION)
    assert len(tx["transactions"]) == 2 and tx["transactions"][1]["aborted"] is True
    assert ton.parse_transactions({"transactions": "x"}, FOUNDATION) is None
    assert ton.parse_wallet_information({"error": "not a wallet"}, 409)["status"] == "not_wallet"
    assert ton.nano_to_ton("1500000000") == "1.5" and ton.nano_to_ton("x") is None and ton.nano_to_ton(True) is None
    assert ton.parse_nft_transfers({"nft_transfers": []})["status"] == "empty"
    collections = json.loads(fx("nft_collections_ok.json"))
    assert {ton.ton_raw(c["address"]) for c in collections["nft_collections"]} == {ton.TELEGRAM_USERNAMES_RAW, ton.ANONYMOUS_NUMBERS_RAW}
