"""Offline tests of the keybase module (P104) on trimmed real and documented-shape Keybase answers
(tests/fixtures/keybase/: live answers for the reserved org accounts, the missing user, the code-100 input error
and the empty reverse lookup; synthetic documentation-value accounts with proofs and with a revoked proof)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social.keybase import (
    BANNER,
    Keybase,
    assess_proof,
    keybase_username_ok,
    lookup_status,
    lookup_url,
    request_plan,
)
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T

API = "https://keybase.io/_/api/1.0/user/lookup.json"
FIELDS = "fields=basics,proofs_summary,public_keys"
FPR = "05038F7802BB049DE654DA1751C59484928D2719"


def url(kind: str, value: str) -> str:
    return f"{API}?{kind}={value}&{FIELDS}"


def pivots(res) -> dict:
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots}


def test_lookup_url_keeps_only_the_three_fields_and_never_the_sigchain():
    assert lookup_url("usernames", "ExampleOrg") == url("usernames", "exampleorg")
    assert lookup_url("domain", "Example.COM") == url("domain", "example.com")
    assert lookup_url("github", "exampleorg") == url("github", "exampleorg")
    assert lookup_url("usernames", "a" * 17) is None  # > 16 characters: code 100, never sent
    assert lookup_url("sig", "x") is None
    assert "sigchain" not in url("usernames", "x") and "sig/get" not in url("usernames", "x")
    assert keybase_username_ok("ab") and not keybase_username_ok("a") and not keybase_username_ok("bad__name")


def test_request_plan_routes_seeds_to_one_lookup():
    assert request_plan(Entity.make(T.USERNAME, "exampleorg")) == ("usernames", "exampleorg")
    assert request_plan(Entity.make(T.DOMAIN, "example.com")) == ("domain", "example.com")
    assert request_plan(Entity.make(T.SOCIAL_ACCOUNT, "github:exampleorg")) == ("github", "exampleorg")
    assert request_plan(Entity.make(T.SOCIAL_ACCOUNT, "x:exampleorg")) == ("twitter", "exampleorg")
    assert request_plan(Entity.make(T.URL, "https://keybase.io/exampleorg")) == ("usernames", "exampleorg")
    kind, why = request_plan(Entity.make(T.USERNAME, "a-very-long-handle-name"))
    assert kind is None and "code 100" in why


def test_found_user_with_proofs_keys_and_emails():
    http = FakeHttp().add("GET", url("usernames", "exampleorg"), json=module_fixture("keybase", "found_with_proofs.json"))
    res = run_module(Keybase, "username:exampleorg", http)
    assert res.status is Status.OK, res.error
    assert http.urls() == [url("usernames", "exampleorg")]  # one request, three fields only (cond 1)
    http.assert_hosts_within(Keybase)
    prof = res.attributes["keybase_profile"][0]
    assert prof["username"] == "exampleorg" and prof["has_sigchain"] is True and prof["pgp_fingerprints"] == [FPR]
    assert BANNER in res.attributes["data_notices"]  # cond 5
    assert res.attributes["data_age"]["as_of"].startswith("2019-08-12") and res.attributes["data_age"]["age_days"] > 1000
    assert res.attributes["presence"]["state"] == "found"
    p = pivots(res)
    gh = p[("social_account", "github:exampleorg")]
    assert gh.relation == "keybase_proof" and gh.confidence_label == "probable" and gh.expand is True  # cond 3: never CONFIRMED alone
    assert "signed on or before 2019-06-01" in gh.note and "historical" in gh.note  # > 3 years (cond 4)
    assert p[("social_account", "x:exampleorg")].confidence_label == "probable"
    dom = p[("domain", "example.com")]
    assert dom.relation == "keybase_proof" and "passive modules only" in dom.note
    assert ("url", "https://www.example.com/") in p and ("domain", "www.example.com") in p
    fpr = p[("pgp_fingerprint", FPR)]
    assert fpr.relation == "pgp_key" and fpr.expand is False
    for email in ("security@example.com", "keybase@example.org"):  # PGP UIDs: POSSIBLE, expand=False (cond 4)
        e = p[("email", email)]
        assert e.relation == "gpg_uid_email" and e.confidence_label == "possible" and e.expand is False
    btc = p[("btc_address", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")]
    assert btc.expand is False and btc.confidence_label == "possible"
    assert p[("social_account", "keybase:exampleorg")].confidence_label == "confirmed"
    titles = {f.title: f for f in res.findings}
    assert titles["Keybase-verified identity proofs"].label.value == "probable"
    assert BANNER in titles["Keybase account"].description
    assert all(f.criterion for f in res.findings)


def test_reserved_org_account_without_sigchain():
    http = FakeHttp().add("GET", url("usernames", "cloudflare"), json=module_fixture("keybase", "found_no_proofs.json"))
    res = run_module(Keybase, "username:cloudflare", http)
    assert res.status is Status.OK
    assert res.attributes["keybase_profile"][0]["has_sigchain"] is False
    assert "reserved or never activated" in res.findings[0].description
    assert not any(p.relation == "keybase_proof" for p in res.pivots)


def test_revoked_and_broken_proofs_are_historical_claims():
    http = FakeHttp().add("GET", url("usernames", "exampleorg"), json=module_fixture("keybase", "revoked_proof.json"))
    res = run_module(Keybase, "username:exampleorg", http)
    p = pivots(res)
    reddit = p[("social_account", "reddit:exampleorg")]
    assert reddit.confidence_label == "possible" and reddit.expand is False and "revoked" in reddit.note
    web = p[("domain", "old.example.com")]
    assert web.confidence_label == "possible" and web.expand is False and "broken" in web.note
    assert p[("social_account", "github:exampleorg")].confidence_label == "probable"
    proofs = {x["proof_type"]: x for x in res.attributes["keybase_proofs"]}
    assert proofs["reddit"]["state_name"] == "revoked" and proofs["reddit"]["label"] == "historical"
    assert "Revoked or broken Keybase proofs (historical claims)" in {f.title for f in res.findings}


def test_missing_user_is_an_absence_with_evidence():
    http = FakeHttp().add("GET", url("usernames", "qz7k2v9m4p1w8n3x"), json=module_fixture("keybase", "not_found.json"))
    res = run_module(Keybase, "username:qz7k2v9m4p1w8n3x", http)
    assert res.status is Status.EMPTY
    assert res.attributes["presence"]["state"] == "absent" and "them=[null]" in res.attributes["presence"]["marker"]


def test_code_100_input_error_is_not_applicable_never_absent():
    http = FakeHttp().add("GET", url("usernames", "exampleorg"), json=module_fixture("keybase", "input_error.json"))
    res = run_module(Keybase, "username:exampleorg", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert "presence" not in res.attributes


def test_names_longer_than_16_characters_are_skipped_without_a_request():
    http = FakeHttp()
    res = run_module(Keybase, "username:a_handle_longer_than_16", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def test_reverse_domain_lookup_without_prover_is_empty():
    http = FakeHttp().add("GET", url("domain", "example.com"), json=module_fixture("keybase", "reverse_empty.json"))
    res = run_module(Keybase, "domain:example.com", http)
    assert res.status is Status.EMPTY and "no Keybase user has proven" in res.error
    assert "presence" not in res.attributes  # nobody proved it: not an absence of anything


def test_reverse_github_lookup_points_to_the_prover():
    http = FakeHttp().add("GET", url("github", "exampleorg"), json=module_fixture("keybase", "found_with_proofs.json"))
    res = run_module(Keybase, "social_account:github:exampleorg", http)
    assert res.status is Status.OK
    p = pivots(res)
    kb = p[("social_account", "keybase:exampleorg")]
    assert kb.relation == "keybase_prover" and kb.expand is False and kb.confidence_label == "probable"
    assert not any(pv.relation == "keybase_proof" for pv in res.pivots)  # the prover's other proofs stay in the attribute
    assert res.attributes["keybase_proofs"][0]["username"] == "exampleorg"
    assert "presence" not in res.attributes


def test_batch_answer_keeps_positions_and_nulls():
    state, _code, _reason = lookup_status(module_fixture("keybase", "batch_mixed.json"))
    assert state == "ok"
    assert lookup_status({"status": {"code": 0, "name": "OK"}, "them": [None, None]})[0] == "absent"


def test_other_status_codes_and_odd_answers_are_could_not_verify():
    http = FakeHttp().add("GET", url("usernames", "exampleorg"), json={"status": {"code": 205, "name": "NOT_FOUND", "desc": "user not found"}})
    res = run_module(Keybase, "username:exampleorg", http)
    assert res.status is Status.ERROR and "205" in res.error
    http = FakeHttp().add("GET", url("usernames", "exampleorg"), json={"status": {"code": 0, "name": "OK"}})
    assert run_module(Keybase, "username:exampleorg", http).status is Status.ERROR
    http = FakeHttp().add("GET", url("usernames", "exampleorg"), json=["not", "an", "object"])
    assert run_module(Keybase, "username:exampleorg", http).status is Status.ERROR
    http = FakeHttp().add("GET", url("usernames", "exampleorg"), body=b"{not json", headers={"content-type": "application/json"})
    assert run_module(Keybase, "username:exampleorg", http).status is Status.ERROR


def test_429_5xx_and_challenge_pages_are_could_not_verify():
    http = FakeHttp().add("GET", url("usernames", "exampleorg"), status=429, text="slow down")
    assert run_module(Keybase, "username:exampleorg", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", url("usernames", "exampleorg"), status=503, text="unavailable", times=5)
    res = run_module(Keybase, "username:exampleorg", http)
    assert res.status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", url("usernames", "exampleorg"), status=403, text=page)
    assert run_module(Keybase, "username:exampleorg", http).status is Status.BLOCKED


def test_proof_assessment_wording_and_labels():
    ok = assess_proof({"proof_type": "github", "nametag": "x", "state": 1}, "2026-01-01T00:00:00Z", "2026-11-26T00:00:00Z")
    assert ok["confidence"] == "probable" and ok["label"] == "date unknown"
    assert ok["wording"] == "Keybase-verified proof, signed on or before 2026-01-01"
    dated = assess_proof({"proof_type": "github", "nametag": "x", "proof_state": "ok", "ctime": 1420113600}, None, "2026-11-26T00:00:00Z")
    assert dated["wording"].startswith("Keybase-verified proof, signed 2015-01-01") and dated["label"] == "historical"
    bad = assess_proof({"proof_type": "twitter", "nametag": "x", "state": 3}, "2026-01-01", "2026-11-26")
    assert bad["confidence"] == "possible" and "broken" in bad["wording"]
    assert assess_proof("junk", None, None) is None


def test_golden_domain_acceptance_routes_replay():
    from tests.fakes import fixture

    routes = fixture("acceptance/domain/keybase.json")
    assert routes["schema"] == "v3lum.acceptance_routes/1" and routes["module"] == "keybase"
    http = FakeHttp()
    for r in routes["routes"]:
        http.add(r["method"], r["url"], status=r["status"], headers=r.get("headers"), json=r["json"])
    res = run_module(Keybase, "domain:example.com", http)
    assert res.status is Status.EMPTY and len(http.calls) == len(routes["routes"]) == 1
