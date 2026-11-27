"""ens_resolver (P209): ENS resolution through ENSData.

Fixtures in tests/fixtures/ens_resolver/ (prep batch p3-G09-1, live 2026-11-26 from api.ensdata.net):
``name_ok.json`` (ens.eth, the ENS DAO's name), ``address_ok.json`` (ENS DAO wallet -> wallet.ensdao.eth),
``address_not_found_404.json`` (Ethereum Foundation wallet, no reverse record), ``name_not_found_404.json``,
``invalid_name_400.json`` (verbatim live answers); DERIVED with documentation values only:
``name_text_records_derived.json`` (a person's record rebuilt with example values), ``hostile_records_derived.json``,
``error_in_200_derived.json``, ``challenge_derived.html``; ``malformed_truncated.json`` (a truncated body).
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.crypto import ens_resolver as ens
from v3lum.modules.crypto.ens_resolver import EnsResolver

API = "https://api.ensdata.net/"
DAO = "0xfe89cc7abb2c4183683ab71653c4cdc9b02d44b7"
EF = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"
OWNER = "0x1111111111111111111111111111111111111111"


def fx(name: str) -> bytes:
    return (FIXTURES / "ens_resolver" / name).read_bytes()


def http_for(path: str, name: str, status: int = 200, ctype: str = "application/json;charset=utf-8") -> FakeHttp:
    return FakeHttp().add("GET", API + path, status=status, body=fx(name), headers={"content-type": ctype})


def pivots(res, relation=None):
    return {(p.entity.type, p.entity.value): p for p in res.pivots if relation is None or p.relation == relation}


# ------------------------------------------------------------------ metadata (registry decision, cond 3)
def test_metadata_matches_the_council_decision():
    cls = EnsResolver
    assert (cls.terms, cls.opsec.name, cls.disclosure, cls.provider, cls.hosts) == ("open", "PASSIVE", "third_party", "ensdata", ("api.ensdata.net",))
    assert cls.default_enabled is True and cls.trust_tier == "community" and cls.shares_input is True
    assert cls.sources == ("ensdata.api",) and cls.absent_statuses == frozenset({404})
    assert {T.DOMAIN, T.KEYWORD, T.ETH} == set(cls.accepts)
    hc = cls.health_check()
    assert hc.etype is T.KEYWORD and hc.value == "ens.eth"


# ------------------------------------------------------------------ cond 1: what is sent
@pytest.mark.parametrize("entity", ["domain:example.com", "keyword:not an ens name", "keyword:bad_name.eth", "domain:ab--c.eth"])
def test_ordinary_domains_and_bad_names_are_never_sent(entity):
    http = FakeHttp()
    res = run_module(EnsResolver, entity, http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_normalisation_and_urls():
    assert ens.normalize_ens_name(" Vitalik.ETH. ") == "vitalik.eth"
    assert ens.normalize_ens_name("_lead.eth") == "_lead.eth" and ens.normalize_ens_name("a_b.eth") is None
    assert ens.normalize_ens_name("x.com") is None and ens.normalize_ens_name("a/b.eth") is None
    assert ens.ensdata_url("name", "café.eth") == API + "caf%C3%A9.eth"
    assert ens.ensdata_url("address", DAO.upper().replace("0X", "0x")) == API + DAO


# ------------------------------------------------------------------ name lookups
def test_name_lookup_live_ens_eth():
    http = http_for("ens.eth", "name_ok.json")
    res = run_module(EnsResolver, "domain:ens.eth", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["ens_name"] == "ens.eth" and a["ens_primary_name"] == "wallet.ensdao.eth" and a["ens_reverse_verified"] is False
    assert a["ens_text_records"]["github"] == "ensdomains" and a["ens_profile"]["contentHash"].startswith("f5909b52")
    wallet = pivots(res, "ens_resolves_to")[(T.ETH, DAO)]
    assert wallet.confidence_label.value == "probable" and wallet.expand is True  # forward record only
    claims = pivots(res, "ens_text_record")
    assert set(claims) == {(T.USERNAME, "ensdomains"), (T.URL, "https://ens.domains/"), (T.DOMAIN, "ens.domains")}
    for (etype, _), p in claims.items():
        assert p.confidence_label.value == "possible" and "self-asserted by the ENS owner" in p.note  # cond 2
        assert p.expand is (etype is not T.USERNAME)  # cond 3: personal identifiers never auto-expand
    assert "hxxps://ens[.]domains/" in claims[(T.URL, "https://ens.domains/")].note  # cond 3: defanged display
    [finding] = res.findings
    assert finding.severity.label == "info" and finding.source == "ensdata.api"
    http.assert_hosts_within(EnsResolver)


def test_text_records_of_a_person_are_possible_and_personal_ones_not_expanded():
    http = http_for("v3lum-fixture-owner.eth", "name_text_records_derived.json")
    res = run_module(EnsResolver, "keyword:v3lum-fixture-owner.eth", http)
    assert res.status is Status.OK
    assert pivots(res, "ens_resolves_to")[(T.ETH, OWNER)].confidence_label.value == "confirmed"  # forward + reverse agree
    claims = pivots(res, "ens_text_record")
    assert claims[(T.EMAIL, "owner@example.com")].expand is False
    assert "owner[@]example[.]com" in claims[(T.EMAIL, "owner@example.com")].note
    assert claims[(T.USERNAME, "example_handle")].expand is False and claims[(T.USERNAME, "example-org")].expand is False
    assert (T.USERNAME, "example_channel") in claims and (T.USERNAME, "example.user") in claims
    records = pivots(res, "ens_address_record")
    assert records[(T.BTC, "1KwdXzmjqp39iuZCecTGytQfxVtHiLmg1Z")].expand is False
    assert records[(T.CRYPTO, "FEoEdUV1jQrToA1h25gVEj8hibA2eBajswoxjNGHbo1n")].confidence_label.value == "possible"


def test_hostile_records_are_rejected_or_cleaned():
    http = http_for("v3lum-fixture-hostile.eth", "hostile_records_derived.json")
    res = run_module(EnsResolver, "domain:v3lum-fixture-hostile.eth", http)
    assert res.status is Status.OK
    claims = pivots(res, "ens_text_record")
    assert set(claims) == {(T.USERNAME, "example_handle"), (T.USERNAME, "example_user")}  # @handle, x.com URL, reddit URL
    rejected = {r["record"]: r["reason"] for r in res.attributes["ens_rejected_records"]}
    assert set(rejected) >= {"url", "email", "github", "telegram", "wallets.btc"}  # javascript:, junk, markup, int, bad btc
    desc = res.attributes["ens_profile"]["description"]
    assert "\x1b" not in desc and "\x07" not in desc and len(desc) <= 300
    assert all("javascript" not in p.entity.value for p in res.pivots)


def test_name_not_registered_404_is_empty():
    http = http_for("v3lum-prep-unregistered-7f3a9c0d.eth", "name_not_found_404.json", status=404)
    res = run_module(EnsResolver, "domain:v3lum-prep-unregistered-7f3a9c0d.eth", http)
    assert res.status is Status.EMPTY and "not registered" in res.attributes["wallet_status"]


# ------------------------------------------------------------------ address lookups (cond 1)
def test_address_lookup_gives_the_primary_name_as_a_fact():
    http = http_for(DAO, "address_ok.json")
    res = run_module(EnsResolver, f"eth_address:{DAO}", http)
    assert res.status is Status.OK
    assert res.attributes["ens_name"] == "wallet.ensdao.eth" and res.attributes["ens_reverse_verified"] is True
    assert not [p for p in res.pivots if p.entity.type is T.DOMAIN]  # an ENS name is never sent to DNS modules
    assert res.findings[0].confidence_label.value == "confirmed"


def test_address_without_reverse_record_is_empty_never_absent_wallet():
    http = http_for(EF, "address_not_found_404.json", status=404)
    res = run_module(EnsResolver, f"eth_address:{EF}", http)
    assert res.status is Status.EMPTY
    assert "says nothing about the wallet" in res.attributes["ens_reverse_record"]
    assert "presence" not in res.attributes  # never 'absent'


def test_404_error_in_200_is_the_same_empty():
    http = FakeHttp().add("GET", API + EF, json={"error": True, "status": 404, "message": "Unable to resolve"})
    assert run_module(EnsResolver, f"eth_address:{EF}", http).status is Status.EMPTY


# ------------------------------------------------------------------ could not verify (rule 5)
def test_invalid_name_400_is_error_not_empty():
    res = ens.parse_ensdata(module_fixture("ens_resolver", "invalid_name_400.json"), "name", "x_y.eth")
    assert res["status"] == "invalid"
    # a name the local gate lets through but the provider rejects (ENSIP-15 disallows U+2010): simulate that answer
    http = FakeHttp().add("GET", API + "%E2%80%90bad.eth", status=400, body=fx("invalid_name_400.json"))
    out = run_module(EnsResolver, Entity(T.KEYWORD, "\u2010bad.eth"), http)
    assert out.status is Status.ERROR and "could not verify" in out.error


def test_error_in_200_is_error():
    http = http_for("ens.eth", "error_in_200_derived.json")
    res = run_module(EnsResolver, "domain:ens.eth", http)
    assert res.status is Status.ERROR and "Internal error" in res.error


def test_rate_limit_in_200_and_429_are_rate_limited():
    http = FakeHttp().add("GET", API + "ens.eth", json={"error": True, "status": 429, "message": "slow down"})
    assert run_module(EnsResolver, "domain:ens.eth", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", API + "ens.eth", status=429, text="Too Many Requests")
    assert run_module(EnsResolver, "domain:ens.eth", http).status is Status.RATE_LIMITED


def test_challenge_page_is_blocked():
    http = http_for("ens.eth", "challenge_derived.html", status=403, ctype="text/html; charset=UTF-8")
    res = run_module(EnsResolver, "domain:ens.eth", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    http = http_for("ens.eth", "challenge_derived.html", status=404, ctype="text/html; charset=UTF-8")
    assert run_module(EnsResolver, "domain:ens.eth", http).status is Status.BLOCKED  # never an absence


def test_server_errors_and_dead_network_are_could_not_verify():
    http = FakeHttp().add("GET", API + "ens.eth", status=502, text="bad gateway", times=3)
    assert run_module(EnsResolver, "domain:ens.eth", http).status is Status.ERROR
    http = FakeHttp().add("GET", API + "ens.eth", error="timeout", times=3)
    assert run_module(EnsResolver, "domain:ens.eth", http).status is Status.ERROR


def test_a_404_that_is_not_the_ensdata_document_is_never_an_absence():
    http = FakeHttp().add("GET", API + "ens.eth", status=404, text="<html><body>Not Found</body></html>", headers={"content-type": "text/html"})
    res = run_module(EnsResolver, "domain:ens.eth", http)
    assert res.status is Status.ERROR and "could not verify" in res.error


@pytest.mark.parametrize("body", [fx("malformed_truncated.json"), b"[1, 2]", b"", b'{"foo": "bar"}'])
def test_malformed_answers_are_error_never_empty(body):
    http = FakeHttp().add("GET", API + "ens.eth", body=body, headers={"content-type": "application/json"})
    res = run_module(EnsResolver, "domain:ens.eth", http)
    assert res.status is Status.ERROR and "could not verify" in res.error


# ------------------------------------------------------------------ cond 2 helper
def test_claim_confidence_upgrades_only_when_the_profile_points_back():
    assert ens.ens_claim_confidence(["building things, see v3lum-fixture-owner.eth"], "v3lum-fixture-owner.eth")[0] == "probable"
    assert ens.ens_claim_confidence(["tips: " + OWNER.upper()], None, [OWNER])[0] == "probable"
    assert ens.ens_claim_confidence(["see notv3lum-fixture-owner.eth.example"], "v3lum-fixture-owner.eth")[0] == "possible"
    assert ens.ens_claim_confidence([], "x.eth") == ("possible", None)
    assert ens.ens_claim_confidence([None, 3], "x.eth", ["short"]) == ("possible", None)
