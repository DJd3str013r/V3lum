"""Offline tests of the mastodon module (P105) on trimmed real Mastodon answers (tests/fixtures/mastodon/: the
Mastodon project account and the FSF account resolved through mastodon.social, live 404s, the documented 429 and a
documentation-value account with unverified fields and a 'moved' target)."""

from __future__ import annotations

import json

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.username_social.mastodon import INSTANCES, Mastodon, load_instances, lookup_url, parse_seed, plan, webfinger_url
from v3lum.core.providers import registry


def env(name: str) -> dict:
    d = module_fixture("mastodon", name)
    return {"status": d["status"], "headers": d["headers"], "body": d["body"].encode()}


def pivots(res) -> dict:
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots}


def test_known_instance_list_has_a_registry_entry_per_host():
    inst = load_instances()
    assert inst["hosts"] == Mastodon.hosts and inst["resolver"] == "mastodon.social"
    reg = registry()
    for host, provider in inst["providers"].items():
        prov = reg.get(provider)
        assert prov is not None and host in prov.hosts and prov.tier in ("trusted", "community")  # cond 1
        assert prov.sources["accounts_api"].terms.class_ == "open"
    assert Mastodon.trust_tier == "community"


def test_routing_never_contacts_unlisted_domains():
    assert plan(parse_seed(Entity.make(T.FEDIVERSE_HANDLE, "@Mastodon@mastodon.social")))["lookups"] == [("mastodon.social", "mastodon", True)]
    email = plan(parse_seed(Entity.make(T.EMAIL, "someone@corp.example")))
    assert email["lookups"] == [] and email["skip"][0] == "not_applicable" and "never sent a WebFinger" in email["skip"][1]  # cond 2
    listed_email = plan(parse_seed(Entity.make(T.EMAIL, "someone@hachyderm.io")))
    assert listed_email["lookups"] == [("hachyderm.io", "someone", True)]
    remote = plan(parse_seed(Entity.make(T.FEDIVERSE_HANDLE, "fsf@hostux.social")))
    assert remote["lookups"] == [("mastodon.social", "fsf@hostux.social", False)] and remote["webfinger"] is False
    via = plan(parse_seed(Entity.make(T.URL, "https://fosstodon.org/@fsf@hostux.social")))
    assert via["lookups"] == [("fosstodon.org", "fsf@hostux.social", False)]
    users = plan(parse_seed(Entity.make(T.URL, "https://mastodon.social/users/Mastodon")))
    assert users["lookups"] == [("mastodon.social", "Mastodon", True)]
    sweep = plan(parse_seed(Entity.make(T.USERNAME, "exampleorg")))
    assert [h for h, _a, _home in sweep["lookups"]] == list(INSTANCES["hosts"])
    assert all(len([x for x in sweep["lookups"] if x[0] == h]) <= 3 for h in INSTANCES["hosts"])  # <= 3 requests per instance


def test_found_on_home_instance_with_rel_me_verified_links():
    http = (FakeHttp().add("GET", lookup_url("mastodon.social", "mastodon"), json=module_fixture("mastodon", "lookup_ok.json"))
            .add("GET", webfinger_url("Mastodon", "mastodon.social"), json=module_fixture("mastodon", "webfinger_ok.json")))
    res = run_module(Mastodon, "fediverse_handle:@Mastodon@mastodon.social", http)
    assert res.status is Status.OK, res.error
    http.assert_hosts_within(Mastodon)
    acc = res.attributes["fediverse_account"]
    assert acc["acct"] == "mastodon@mastodon.social" and acc["resolved_via"] is None
    assert acc["webfinger"]["matches"] is True
    assert res.attributes["disclosed_to"] == ["mastodon.social"]  # cond 6
    assert res.attributes["created"].startswith("2016-11-23") and res.attributes["followers"] == 878862
    p = pivots(res)
    home = p[("url", "https://joinmastodon.org/")]
    assert home.relation == "verified_profile_link" and home.confidence_label == "confirmed" and home.expand is True
    assert "verified 2018-10-31" in home.note
    titles = {f.title for f in res.findings}
    assert {"Fediverse account", "rel=me verified profile links"} <= titles
    assert len(http.calls) == 2  # lookup + WebFinger confirmation (<= 3 per instance)


def test_unverified_fields_are_claims_and_moved_is_probable():
    http = (FakeHttp().add("GET", lookup_url("hachyderm.io", "exampleorg"), json={**module_fixture("mastodon", "lookup_unverified.json"),
                                                                                 "acct": "exampleorg"})
            .add("GET", webfinger_url("exampleorg", "hachyderm.io"), **env("webfinger_not_found.http.json")))
    res = run_module(Mastodon, "fediverse_handle:exampleorg@hachyderm.io", http)
    assert res.status is Status.OK
    p = pivots(res)
    site = p[("url", "https://www.example.com/")]
    assert site.relation == "link_on_profile" and site.confidence_label == "possible" and site.expand is False
    status = p[("url", "https://status.example.org/")]
    assert status.confidence_label == "confirmed"
    moved = p[("fediverse_handle", "exampleorg@social.example")]
    assert moved.relation == "moved_to" and moved.confidence_label == "probable" and moved.expand is False
    fields = {f["name"]: f for f in res.attributes["fediverse_account"]["fields"]}
    assert fields["Location"]["urls"] == [] and "text" not in fields["Location"]  # link-less field text is not kept


def test_remote_account_through_resolver_cache():
    http = FakeHttp().add("GET", lookup_url("mastodon.social", "fsf@hostux.social"), json=module_fixture("mastodon", "lookup_remote_ok.json"))
    res = run_module(Mastodon, "fediverse_handle:fsf@hostux.social", http)
    assert res.status is Status.OK
    assert http.hosts() == {"mastodon.social"}  # hostux.social itself is never contacted
    acc = res.attributes["fediverse_account"]
    assert acc["resolved_via"] == "mastodon.social" and acc["home_host"] == "hostux.social"
    assert pivots(res)[("url", "https://www.fsf.org/")].confidence_label == "confirmed"
    assert res.findings[0].label.value == "probable"


def test_not_found_on_home_instance_is_absent_but_not_known_to_resolver_is_not():
    http = FakeHttp().add("GET", lookup_url("mastodon.social", "qz7k2v9m4p1w8n3"), **env("lookup_not_found.http.json"))
    res = run_module(Mastodon, "fediverse_handle:qz7k2v9m4p1w8n3@mastodon.social", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    http = FakeHttp().add("GET", lookup_url("mastodon.social", "someone@hostux.social"), **env("lookup_not_found.http.json"))
    res = run_module(Mastodon, "fediverse_handle:someone@hostux.social", http)
    assert res.status is Status.EMPTY and "not known to mastodon.social" in res.error and "not absent" in res.error
    assert "presence" not in res.attributes


def test_unlisted_email_domain_is_skipped_without_any_request():
    http = FakeHttp()
    res = run_module(Mastodon, "email:someone@corp.example", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_plain_username_sweeps_listed_instances_once_each():
    http = FakeHttp()
    for host in INSTANCES["hosts"]:
        if host == "mastodon.social":
            http.add("GET", lookup_url(host, "mastodon"), json=module_fixture("mastodon", "lookup_ok.json"))
        else:
            http.add("GET", lookup_url(host, "mastodon"), **env("lookup_not_found.http.json"))
    res = run_module(Mastodon, "username:mastodon", http)
    assert res.status is Status.OK
    assert sorted(http.hosts()) == sorted(INSTANCES["hosts"]) and len(http.calls) == len(INSTANCES["hosts"])
    assert res.attributes["disclosed_to"] == sorted(INSTANCES["hosts"])
    assert "Same handle elsewhere does not prove the same person" in res.findings[0].description


def test_plain_username_absent_everywhere_and_partial_failures():
    http = FakeHttp()
    for host in INSTANCES["hosts"]:
        http.add("GET", lookup_url(host, "qz7k2v9m4p1w8n3"), **env("lookup_not_found.http.json"))
    res = run_module(Mastodon, "username:qz7k2v9m4p1w8n3", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    http = FakeHttp()
    for host in INSTANCES["hosts"]:
        http.add("GET", lookup_url(host, "qz7k2v9m4p1w8n3"), status=503, text="down", times=5)
    res = run_module(Mastodon, "username:qz7k2v9m4p1w8n3", http)
    assert res.status is Status.ERROR and "could not" in res.error  # never absent when nothing answered
    assert "presence" not in res.attributes


def test_429_and_403_are_could_not_verify():
    http = FakeHttp().add("GET", lookup_url("mastodon.social", "mastodon"), **env("rate_limited.http.json"))
    assert run_module(Mastodon, "fediverse_handle:mastodon@mastodon.social", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", lookup_url("mastodon.social", "mastodon"), status=403, json={"error": "forbidden"})
    res = run_module(Mastodon, "fediverse_handle:mastodon@mastodon.social", http)
    assert res.status is Status.BLOCKED and "presence" not in res.attributes


def test_error_in_200_and_malformed_answers_are_errors():
    http = FakeHttp().add("GET", lookup_url("mastodon.social", "mastodon"), json={"error": "This method requires an authenticated user"})
    assert run_module(Mastodon, "fediverse_handle:mastodon@mastodon.social", http).status is Status.ERROR
    http = FakeHttp().add("GET", lookup_url("mastodon.social", "mastodon"), body=b"{oops", headers={"content-type": "application/json"})
    assert run_module(Mastodon, "fediverse_handle:mastodon@mastodon.social", http).status is Status.ERROR
    http = FakeHttp().add("GET", lookup_url("mastodon.social", "mastodon"), body=json.dumps(["x"]).encode(), headers={"content-type": "application/json"})
    assert run_module(Mastodon, "fediverse_handle:mastodon@mastodon.social", http).status is Status.ERROR


def test_profile_url_parsing():
    assert parse_seed(Entity.make(T.URL, "https://example.com/about"))["kind"] == "invalid"
    assert parse_seed(Entity.make(T.URL, "http://mastodon.social/@x"))["kind"] == "invalid"  # https only
    s = parse_seed(Entity.make(T.URL, "https://mastodon.social/@fsf@hostux.social"))
    assert s["kind"] == "profile_url" and s["host"] == "hostux.social" and s["via_host"] == "mastodon.social"


def test_golden_email_acceptance_sends_nothing():
    from tests.fakes import fixture

    routes = fixture("acceptance/email/mastodon.json")
    assert routes["schema"] == "v3lum.acceptance_routes/1" and routes["module"] == "mastodon" and routes["routes"] == []
    http = FakeHttp()
    res = run_module(Mastodon, "email:someone@example.com", http)
    assert res.status is Status.SKIPPED and http.calls == []
    assert run_module(Mastodon, "url:https://example.com/", FakeHttp()).status is Status.SKIPPED
