"""leak_lookup_public (P140): Leak-Lookup PUBLIC key - breach names only, merged per normalised name.

Fixtures in tests/fixtures/leak_lookup_public/: ``needs_key_missing.json`` is the real 2026-11-25 keyless
answer (HTTP 200 {'error': 'true', 'message': 'MISSING API KEY'}); ``hibp_catalogue_subset.json`` is a
trimmed real copy of the keyless HIBP catalogue (P132 helper); the error bodies use the messages
documented at leak-lookup.com/docs/search (checked 2026-11-26); the success bodies are SYNTHETIC in the
documented public format ({'error': 'false', 'message': {'<breach>': []}}) - P140 cond 6: a trimmed
real answer captured with the company public key replaces them before merge.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import sanitize
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.breach_leak.leak_lookup_public import (
    FORBIDDEN_TYPES,
    SEARCH_URL,
    TYPES,
    LeakLookupPublic,
    leaklookup_form_allowed,
    leaklookup_request,
    parse_leaklookup,
    sensitive_breach_name,
)

MOD = LeakLookupPublic
KEY = "llfixturepublickey0000"
CATALOGUE = "https://haveibeenpwned.com/api/v3/breaches"
OWN = "analyst@acme.com.br"
ORG = {"domains": [{"name": "acme.com.br", "verification": "attested", "attested_by": "fixture analyst", "attested_date": "2026-11-26"}]}
SCOPE_ALL = ScanOptions(breach_scope="all", purpose="incident 2026-11 phishing triage")
KEYS = {"leaklookup": KEY}


@pytest.fixture(autouse=True)
def small_catalogue(monkeypatch):
    """The trimmed HIBP catalogue has a few breaches; the production floor (500) guards real downloads."""
    from v3lum.core import datasets
    from v3lum.modules.breach_leak import hibp_catalog as hc

    monkeypatch.setattr(hc, "MIN_BREACHES", 5)
    monkeypatch.setitem(datasets.DATASETS[hc.CATALOG_DATASET], "min_bytes", 1)


def fx(name):
    return module_fixture(MOD, name)


def body(name):
    data = fx(name)
    if isinstance(data, dict) and data.get("_envelope"):
        return data["body"]
    return {k: v for k, v in data.items() if not k.startswith("_")}


def with_catalogue(http):
    return http.add("GET", CATALOGUE, json=fx("hibp_catalogue_subset.json")["body"])


def org():
    return OrgProfile.from_dict(ORG)


def run(http, value=f"email:{OWN}", **kw):
    kw.setdefault("keys", KEYS)
    kw.setdefault("org_profile", org())
    return run_module(MOD, value, http, **kw)


def posted(http):
    call = next(c for c in http.calls if c["url"] == SEARCH_URL)
    return {k: v[0] for k, v in parse_qs(call["body"].decode()).items()}


# ---------------------------------------------------------------------- cond 1-2: request allow-list


def test_only_public_key_searches_of_allowed_types_can_be_built():
    req = leaklookup_request(T.EMAIL, "Analyst@ACME.com.br", KEY)
    assert req == {"url": SEARCH_URL, "form": {"key": KEY, "type": "email_address", "query": OWN}}
    assert leaklookup_form_allowed(req["form"])
    assert leaklookup_request(T.DOMAIN, "acme.com.br", KEY)["form"]["type"] == "domain"
    assert leaklookup_request(T.USERNAME, "analyst01", KEY)["form"]["type"] == "username"
    for etype in (T.IPV4, T.PHONE, T.SHA1, "password", "fullname"):
        with pytest.raises(ValueError):
            leaklookup_request(etype, "x", KEY)
    for bad_type in FORBIDDEN_TYPES:
        assert not leaklookup_form_allowed({"key": KEY, "type": bad_type, "query": "x"})
    assert not leaklookup_form_allowed({"key": KEY, "type": "email_address", "query": "x", "extra": "1"})
    with pytest.raises(ValueError):
        leaklookup_request(T.EMAIL, OWN, "bad key&type=password")
    assert not set(TYPES.values()) & FORBIDDEN_TYPES and "password" not in TYPES.values()


def test_own_address_breach_names_are_joined_masked_and_mergeable():
    http = with_catalogue(FakeHttp().add("POST", SEARCH_URL, json=body("ok_email.json")))
    res = run(http)
    assert res.status is Status.OK
    form = posted(http)
    assert form == {"key": KEY, "type": "email_address", "query": OWN}  # key in the POST body, never the URL
    assert KEY not in http.calls[0]["url"]
    by_key = {f.data["breach_key"]: f for f in res.findings}
    tracks = by_key["8tracks"]  # '8tracks.com' joined to the HIBP catalogue entry 8tracks (P132 helper)
    assert tracks.data["name"] == "8tracks.com" and tracks.data["date"] == "2017-06-27"
    assert "Passwords" in tracks.data["data_classes"]
    assert tracks.severity.label == "medium" and "credential_exposure" in tracks.tags
    assert tracks.source == "leaklookup.search" and tracks.criterion
    names = {f.data["name"] for f in res.findings}
    assert "sensitive breach (name withheld)" in names  # Hjedd/AshleyMadison/Zoosk (IsSensitive) and datingsite.example
    assert sum(1 for k in by_key if k.startswith("sensitive:")) == 4
    text = json.dumps(res.to_dict(), default=str)
    for hidden in ("Hjedd", "hjedd", "AshleyMadison", "ashleymadison", "datingsite", "Zoosk"):
        assert hidden not in text
    assert "regionalshop.example" in names  # not in the catalogue: kept as a name without date
    assert by_key["rivercitymedia"].severity.label == "info"  # spam list: never counted
    assert res.attributes["breach_count"] >= 4
    http.assert_hosts_within(MOD, extra=("haveibeenpwned.com",))


def test_list_form_and_documented_absence():
    http = with_catalogue(FakeHttp().add("POST", SEARCH_URL, json=body("ok_list_form.json")))
    res = run(http)
    assert res.status is Status.OK and {f.data["breach_key"] for f in res.findings} == {"adobe", "zomato"}
    http = FakeHttp().add("POST", SEARCH_URL, json=body("not_found.json"))
    res = run(http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    http = FakeHttp().add("POST", SEARCH_URL, json={"error": "false", "message": {}})
    assert run(http).status is Status.EMPTY


def test_private_tier_records_never_reach_the_module_and_the_answer_is_refused():
    data = body("private_records.json")
    out = json.loads(sanitize.sanitize_body("leaklookup.search", json.dumps(data).encode(), "application/json"))
    assert out == {"error": "false", "message": {"examplebreach.example": [{}]}}  # no record field survives the schema
    http = FakeHttp().add("POST", SEARCH_URL, json=data)
    res = run(http)
    assert res.status is Status.ERROR and "private tier" in res.error
    text = json.dumps(res.to_dict(), default=str)
    for leaked in ("FIXTURE-NOT-A-PASSWORD", "192.0.2.10", "example-user", "5555-0100", "0000000000000000000000000000000000000000"):
        assert leaked not in text


# ---------------------------------------------------------------------- cond 3: error-in-200


def test_error_in_200_bodies_are_never_empty():
    assert run(FakeHttp().add("POST", SEARCH_URL, json=body("needs_key_missing.json"))).status is Status.ERROR
    res = run(FakeHttp().add("POST", SEARCH_URL, json=body("error_invalid_key.json")))
    assert res.status is Status.ERROR and "key" in res.error.lower()
    res = run(FakeHttp().add("POST", SEARCH_URL, json=body("error_limit.json")))
    assert res.status is Status.QUOTA and res.reason_code == "quota"
    res = run(FakeHttp().add("POST", SEARCH_URL, json=body("error_rate_limit.json")))
    assert res.status is Status.RATE_LIMITED
    assert run(FakeHttp().add("POST", SEARCH_URL, json=body("error_other.json"))).status is Status.ERROR
    assert run(FakeHttp().add("POST", SEARCH_URL, json={"error": True, "message": "SEARCH FAILED"})).status is Status.ERROR
    assert run(FakeHttp().add("POST", SEARCH_URL, json={"message": {"x": []}})).status is Status.ERROR  # no error flag


def test_http_failures_are_could_not_verify():
    assert run(FakeHttp().add("POST", SEARCH_URL, status=429, text="slow down")).status is Status.RATE_LIMITED
    assert run(FakeHttp().add("POST", SEARCH_URL, status=502, text="bad gateway")).status is Status.ERROR
    assert run(FakeHttp().add("POST", SEARCH_URL, status=401, text="")).status is Status.NEEDS_KEY
    page = fx("blocked_challenge.html")
    assert run(FakeHttp().add("POST", SEARCH_URL, status=403, text=page)).status is Status.BLOCKED
    assert run(FakeHttp().add("POST", SEARCH_URL, text="<html>maintenance</html>")).status is Status.ERROR
    assert run(FakeHttp().add("POST", SEARCH_URL, json=["a", "b"])).status is Status.ERROR


def test_missing_key_is_needs_key_before_any_request():
    http = FakeHttp()
    res = run(http, keys={})
    assert res.status is Status.NEEDS_KEY and http.calls == []


# ---------------------------------------------------------------------- cond 5: scope


def test_scope_third_parties_usernames_and_domains():
    http = FakeHttp()
    res = run(http, "email:someone@thirdparty.com.br")
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []
    assert run(FakeHttp(), "username:analyst01").status is Status.SKIPPED
    http = with_catalogue(FakeHttp().add("POST", SEARCH_URL, json=body("ok_list_form.json")))
    res = run(http, "email:someone@thirdparty.com.br", options=SCOPE_ALL)
    assert res.status is Status.OK
    assert all({"context_only", "third_party"} <= set(f.tags) for f in res.findings)
    assert all(f.severity.label in ("info", "low", "medium") for f in res.findings)
    http = with_catalogue(FakeHttp().add("POST", SEARCH_URL, json=body("ok_list_form.json")))
    assert run(http, "username:analyst01", options=SCOPE_ALL).status is Status.OK
    assert posted(http)["type"] == "username"
    # a domain query only for a verified own domain (Leak-Lookup terms: no mass-domain queries)
    http = FakeHttp()
    res = run(http, "domain:thirdparty.com.br", options=SCOPE_ALL)
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset" and http.calls == []


def test_own_domain_search_gives_one_summary_finding():
    http = with_catalogue(FakeHttp().add("POST", SEARCH_URL, json=body("ok_email.json")))
    res = run(http, "domain:acme.com.br")
    assert res.status is Status.OK and posted(http)["type"] == "domain"
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity.label == "medium" and "own_asset" in f.tags and f.criterion
    assert "Hjedd" not in json.dumps(res.to_dict(), default=str)


def test_generic_address_is_flagged_and_never_scored():
    http = with_catalogue(FakeHttp().add("POST", SEARCH_URL, json=body("ok_list_form.json")))
    res = run(http, "email:contato@acme.com.br")
    assert res.status is Status.OK and res.attributes["generic_address"]
    assert [f.title for f in res.findings] == ["Generic or shared identity listed in breaches"]
    assert res.findings[0].severity.label == "info" and "context_only" in res.findings[0].tags


# ---------------------------------------------------------------------- helpers


def test_parser_and_sensitive_names():
    assert parse_leaklookup({"error": "false", "message": {"a.example": [], "b.example": []}})["names"] == ["a.example", "b.example"]
    assert parse_leaklookup({"error": "true"})["state"] == "error"
    assert parse_leaklookup({"error": "false", "message": [{"email_address": "x"}]})["state"] == "private"
    assert parse_leaklookup({"error": "false", "message": 5})["state"] == "error"
    assert sensitive_breach_name("adultfriendfinder.com") and sensitive_breach_name("Some Dating Site")
    assert not sensitive_breach_name("essex-shop.example") and not sensitive_breach_name("archive.org")


# ---------------------------------------------------------------------- cond 4: merge with the other breach sources


def test_merge_rule_folds_leaklookup_into_the_partner_finding():
    from tests.fakes import graph_fixture
    from v3lum.correlations.p3_g04_2 import RULE_LEAKLOOKUP_MERGE, leaklookup_breach_merge

    graph, results, _rctx = graph_fixture(f"tests/fixtures/rules/{RULE_LEAKLOOKUP_MERGE}/positive_leaklookup_and_hibp_same_breach.json")
    out = list(leaklookup_breach_merge(graph, results))
    assert len(out) == 1 and out[0].severity.label == "info"
    node = next(iter(graph.nodes.values()))
    by = {(f.module, f.data["breach_key"]): f for f in node.findings}
    hibp, ll = by[("hibp_account", "8tracks")], by[("leak_lookup_public", "8tracks")]
    assert hibp.severity.label == "medium" and "leaklookup.search" in hibp.data["sources"]
    assert ll.severity.label == "info" and "context_only" in ll.tags and ll.data["merged_into"] == hibp.id
    assert by[("leak_lookup_public", "sensitive:0123456789ab")].severity.label == "medium"  # no partner: untouched
    assert list(leaklookup_breach_merge(graph, results))[0].severity.label == "info"  # re-run: never lowered twice
    assert ll.data["severity_before_merge"] == "medium"


def test_evidence_keeps_sensitive_names_masked():
    http = with_catalogue(FakeHttp().add("POST", SEARCH_URL, json=body("ok_email.json")))
    res = run(http)
    names = res.raw["leaklookup.search"]["message"]
    assert "sensitive breach (name withheld)" in names and "8tracks.com" in names
    assert not [n for n in names if "jedd" in n.lower() or "dating" in n.lower() or "ashley" in n.lower() or "zoosk" in n.lower()]
