"""Offline tests of npm_maintainer (P100) on trimmed real npm registry answers (tests/fixtures/npm_maintainer/),
plus the pack-level rules of P100 (HackerOne not in this build, one adapter per platform)."""

from __future__ import annotations

import json

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import module as modreg
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.username_social import dev_registries
from v3lum.modules.username_social.dev_profiles import NpmMaintainer
from v3lum.modules.username_social.dev_registries import npm_search_url, parse_npm_search

URL = "https://registry.npmjs.org/-/v1/search?text=maintainer:{u}&size=20"


def env(name: str) -> dict:
    d = module_fixture("npm_maintainer", name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def blob(res) -> str:
    return json.dumps(res.to_dict(), default=str)


def test_multi_maintainer_keeps_only_the_seed_email():
    http = FakeHttp().add("GET", URL.format(u="example-dev"), json=module_fixture("npm_maintainer", "search_multi_maintainer.json"))
    res = run_module(NpmMaintainer, "username:example-dev", http, options=ScanOptions(seed_tlp={"email:dev@example.com": "amber"}))
    assert res.status is Status.OK
    names = [p["name"] for p in res.attributes["registry_packages"]]
    assert names == ["example-pkg-a", "example-pkg-b", "@example-org/pkg-c", "example-pkg-d"]
    counted = res.attributes["third_party_counts"]
    assert counted == {"co_maintainers": 3, "other_emails": 4, "system_publishers": 1, "not_seed_packages": 1}
    emails = {p.entity.value: p for p in res.pivots if p.entity.type is T.EMAIL}
    assert set(emails) == {"dev@example.com", "dev@work.example.net"}
    assert all(p.expand is False and p.relation == "maintainer_email" for p in emails.values())
    assert emails["dev@example.com"].confidence_label == "possible"  # A4: test domain capped at POSSIBLE
    text = blob(res)
    for third in ("co1@example.org", "co2@example.net", "co3@example.org", "contact@example.org", "co-maintainer-1",
                  "co-maintainer-2", "else@example.org", "someone-else", "publisher-oidc@example.org"):
        assert third not in text  # cond 6: counted, never stored, listed or pivoted
    summary = res.attributes["platform_summary"]
    assert summary["platform"] == "npm" and summary["count"] == 4 and summary["created"] == "2018-02-02T10:00:00Z"
    assert len(summary["top"]) <= 5
    http.assert_hosts_within(NpmMaintainer)


def test_seed_email_probable_only_when_in_case(monkeypatch):
    monkeypatch.setattr(dev_registries, "is_generic_email", lambda _e: False)  # lift the A4 test-domain cap
    data = module_fixture("npm_maintainer", "search_multi_maintainer.json")
    parsed = parse_npm_search(data, "example-dev", ["dev@example.com"])
    conf = {e["email"]: e["confidence"] for e in parsed["emails"]}
    assert conf == {"dev@example.com": "probable", "dev@work.example.net": "possible"}
    recurs = {e["email"]: e["recurrence"] for e in parsed["emails"]}
    assert recurs["dev@example.com"] == 3  # recurring on >= 2 packages is still POSSIBLE unless in the case
    assert parse_npm_search(data, "example-dev", [])["emails"][0]["confidence"] == "possible"
    counts_only = parse_npm_search(data, None)  # P359: no seed -> counts only, never e-mails
    assert counts_only["emails"] == [] and counts_only["summary"]["count"] == 5


def test_live_shaped_answer_of_an_organisation_account():
    http = FakeHttp().add("GET", URL.format(u="npm"), json=module_fixture("npm_maintainer", "search_ok.json"))
    res = run_module(NpmMaintainer, "social_account:npm:npm", http)
    assert res.status is Status.OK
    assert res.attributes["profile_url"] == "https://www.npmjs.com/~npm"
    assert "co-maintainer-2@example.org" not in blob(res)
    assert "www.npmjs.com" not in " ".join(http.urls())  # the profile page (Cloudflare challenge) is never fetched


def test_total_zero_is_absent():
    http = FakeHttp().add("GET", URL.format(u="qz7k2v9m4p1w8n3x5c6b"), json=module_fixture("npm_maintainer", "search_empty.json"))
    res = run_module(NpmMaintainer, "username:qz7k2v9m4p1w8n3x5c6b", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"


def test_search_noise_only_is_not_an_absence():
    data = {"objects": [{"package": {"name": "x", "maintainers": [{"username": "someone-else", "email": "e@example.org"}]}}], "total": 1}
    http = FakeHttp().add("GET", URL.format(u="example-dev"), json=data)
    res = run_module(NpmMaintainer, "username:example-dev", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "unknown"
    assert "e@example.org" not in blob(res)


def test_challenge_429_and_malformed_are_could_not_verify():
    http = FakeHttp().add("GET", URL.format(u="example-dev"), **env("challenge.http.json"))
    res = run_module(NpmMaintainer, "username:example-dev", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    http = FakeHttp().add("GET", URL.format(u="example-dev"), **env("rate_limited.http.json"))
    assert run_module(NpmMaintainer, "username:example-dev", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", URL.format(u="example-dev"), json=module_fixture("npm_maintainer", "search_malformed.json"))
    assert run_module(NpmMaintainer, "username:example-dev", http).status is Status.ERROR
    http = FakeHttp().add("GET", URL.format(u="example-dev"), json={"error": "internal"})
    assert run_module(NpmMaintainer, "username:example-dev", http).status is Status.ERROR


def test_input_validation():
    assert npm_search_url("Bad Name!") is None
    http = FakeHttp()
    res = run_module(NpmMaintainer, "social_account:github:example-dev", http)  # another platform's account
    assert res.status is Status.SKIPPED and http.calls == []


def test_pack_rules_hackerone_not_in_build_and_one_adapter_per_platform():
    hosts = {h for cls in modreg.REGISTRY.values() for h in getattr(cls, "hosts", ())}
    assert "hackerone.com" not in hosts  # P100 cond 2: undocumented GraphQL, terms unknown -> backlog
    pack = {"npm_maintainer": "npm", "pypi_package": "pypi", "codeberg_user": "codeberg", "devto_user": "dev_to",
            "huggingface_user": "huggingface"}
    for name, provider in pack.items():
        cls = modreg.REGISTRY[name]
        assert cls.provider == provider and len(cls.hosts) == 1 and cls.run_on == "seeds" and cls.terms == "open"
        assert cls.default_enabled is True and cls.max_requests == 1 and cls.opsec.name == "PASSIVE"
    assert modreg.REGISTRY["codeberg_user"].trust_tier == "community"
