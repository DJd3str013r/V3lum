"""onion_lookup (P199): AIL onion-lookup (CIRCL) behind the Ahmia banned-onion safety filter.

Fixtures in tests/fixtures/onion_lookup/ (prep batch p2-G09-1, live 2026-11-26):
``ail_found.json`` (lookup of the Tor Project's onion; languages cut to 5 and titles to 4 of 42),
``ail_not_found.json`` (a synthetic valid-checksum onion), ``ail_malformed_empty_object.json``
(lookup of 'notanonion.onion'), ``ahmia_banned_ok.txt`` (first 6 and last real md5 lines of
ahmia.fi/blacklist/banned/; line 7 is SYNTHETIC: md5 of the documentation onion BANNED below) and
``ahmia_blacklist_page.html`` (the offer quoted as terms evidence, with Ahmia's worked example).
"""

from __future__ import annotations

import hashlib
import re

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.darkweb_ransomware import onion_safety
from v3lum.modules.darkweb_ransomware.onion_lookup import AIL_LOOKUP_URL, TOR_PROJECT_ONION, OnionLookup, parse_ail_lookup
from v3lum.modules.darkweb_ransomware.onion_safety import (
    AHMIA_BANNED_URL,
    AHMIA_DATASET,
    BANNED_ONION_TEXT,
    is_banned_onion,
    is_onion_hostname,
    onion_ban_hashes,
    onion_service_domain,
    parse_ahmia_banned,
)

FIX = FIXTURES / "onion_lookup"
BANNED = "yrb5vnqn4gnkmamewpbq6so6oe6dejqr36eroyjpvi26mdj7kq4exnqd.onion"
NOT_FOUND = "7lv6yjwjmm4xc5kxdf4lozqu5vjeq4s4il4ut5gg4wg2vcpumg7rvxyd.onion"


@pytest.fixture(autouse=True)
def small_banned_list(monkeypatch):
    monkeypatch.setattr(onion_safety, "MIN_HASHES", 1)  # the fixture holds 8 of the 60,407 live lines
    onion_safety._FAILED.clear()


def with_ahmia(http: FakeHttp | None = None, status: int = 200) -> FakeHttp:
    http = http or FakeHttp()
    return http.add("GET", AHMIA_BANNED_URL, status=status, body=(FIX / "ahmia_banned_ok.txt").read_bytes(),
                    headers={"content-type": "text/plain; charset=utf-8"})


def ail(onion: str, http: FakeHttp, **kw) -> FakeHttp:
    return http.add("GET", AIL_LOOKUP_URL.format(onion=onion), **kw)


# ------------------------------------------------------------------ metadata (cond 1, 6)
def test_metadata():
    cls = OnionLookup
    assert (cls.disclosure, cls.provider, cls.sources, cls.hosts) == ("third_party", "circl", ("circl.onion_lookup_ail",), ("onion.ail-project.org",))
    assert cls.terms == "open" and cls.trust_tier == "trusted" and cls.max_tlp.value_str == "amber+strict" and cls.default_enabled is True
    assert cls.max_requests == 1 and cls.min_interval == 2.0 and cls.daily_quota == 200 and cls.cache_ttl == 86400
    assert cls.manual_link == "https://ahmia.fi/" and cls.shares_input is True
    reg = DATASETS[AHMIA_DATASET]
    assert reg["url"] == AHMIA_BANNED_URL and reg["ttl"] == 86400 and reg["essential"] is True and reg["large"] is False
    assert reg["terms_class"] == "open" and reg["source"] == "ahmia.banned_list"


# ------------------------------------------------------------------ AIL answers (cond 1, 6)
def test_found_onion_titles_dates_and_tags():
    http = ail(TOR_PROJECT_ONION, with_ahmia(), json=module_fixture("onion_lookup", "ail_found.json"))
    res = run_module(OnionLookup, f"onion:{TOR_PROJECT_ONION}", http)
    assert res.status is Status.OK and res.requests == 1
    a = res.attributes
    assert a["first_seen"] == "2023-04-22" and a["last_seen"] == "2026-11-05"
    assert a["languages"] == ["ru", "sw", "hu", "pl", "de"] and a["tags"] == ['infoleak:automatic-detection="onion"']
    assert "Tor Project | Anonymity Online" in a["onion_titles"] and len(a["onion_titles"]) == 4
    [finding] = res.findings
    assert finding.title == "Onion service seen by AIL (CIRCL)" and finding.severity.label == "info"
    assert finding.source == "circl.onion_lookup_ail" and finding.observed_last and "[.]onion" in finding.description
    assert not res.pivots
    assert [u for u in http.urls() if "ail-project" in u] == [AIL_LOOKUP_URL.format(onion=TOR_PROJECT_ONION)]
    http.assert_hosts_within(OnionLookup, extra=("ahmia.fi",))
    assert any(d["name"] == AHMIA_DATASET for d in res.datasets)


def test_subdomain_is_looked_up_as_the_service_domain():
    http = ail(TOR_PROJECT_ONION, with_ahmia(), json=module_fixture("onion_lookup", "ail_found.json"))
    assert run_module(OnionLookup, f"onion:www.{TOR_PROJECT_ONION}", http).status is Status.OK


def test_domain_not_found_is_empty():
    http = ail(NOT_FOUND, with_ahmia(), json=module_fixture("onion_lookup", "ail_not_found.json"))
    res = run_module(OnionLookup, f"onion:{NOT_FOUND}", http)
    assert res.status is Status.EMPTY and not res.findings
    assert ("Ahmia search (manual: type the onion; search is never automated)", "https://ahmia.fi/") in res.links


def test_empty_object_and_other_error_bodies_are_could_not_verify():
    http = ail(NOT_FOUND, with_ahmia(), json=module_fixture("onion_lookup", "ail_malformed_empty_object.json"))
    res = run_module(OnionLookup, f"onion:{NOT_FOUND}", http)
    assert res.status is Status.ERROR and "could not verify" in res.error
    http2 = ail(NOT_FOUND, with_ahmia(), json={"error": "internal error"})
    assert run_module(OnionLookup, f"onion:{NOT_FOUND}", http2).status is Status.ERROR
    http3 = ail(NOT_FOUND, with_ahmia(), json=["not", "an", "object"])
    assert run_module(OnionLookup, f"onion:{NOT_FOUND}", http3).status is Status.ERROR


def test_answer_for_another_onion_is_refused():
    http = ail(NOT_FOUND, with_ahmia(), json=module_fixture("onion_lookup", "ail_found.json"))
    res = run_module(OnionLookup, f"onion:{NOT_FOUND}", http)
    assert res.status is Status.ERROR and "different onion" in res.error


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (429, "slow down", Status.RATE_LIMITED),
        (503, "unavailable", Status.ERROR),
        (403, "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>", Status.BLOCKED),
    ],
)
def test_http_failures_are_could_not_verify(status, body, expected):
    http = ail(NOT_FOUND, with_ahmia(), status=status, text=body, times=2)
    assert run_module(OnionLookup, f"onion:{NOT_FOUND}", http).status is expected


def test_galaxy_tags_pivot_to_threat_actors_without_expansion():
    doc = dict(module_fixture("onion_lookup", "ail_found.json"))
    doc["tags"] = doc["tags"] + ['misp-galaxy:ransomware="LockBit"', 'misp-galaxy:threat-actor="Example Actor"']
    http = ail(TOR_PROJECT_ONION, with_ahmia(), json=doc)
    res = run_module(OnionLookup, f"onion:{TOR_PROJECT_ONION}", http)
    assert {(p.entity.value, p.relation, p.expand) for p in res.pivots} == {("LockBit", "listed_for_actor", False), ("Example Actor", "listed_for_actor", False)}


def test_titles_are_plain_deduplicated_and_capped():
    doc = {"id": TOR_PROJECT_ONION, "titles": ["A‮B\x07C", "A B C", "<b>x</b>"] + [f"t{i}" for i in range(20)], "tags": [], "languages": []}
    parsed = parse_ail_lookup(doc, TOR_PROJECT_ONION)
    assert parsed["titles"][0] == "A B C" and parsed["titles"].count("A B C") == 1
    assert len(parsed["titles"]) == 10 and parsed["title_count"] == 22


# ------------------------------------------------------------------ Ahmia safety filter (cond 2, 3)
def test_banned_onion_is_never_sent_and_shows_only_the_fixed_text():
    http = with_ahmia()  # no AIL route: a request would fail the test
    res = run_module(OnionLookup, f"onion:{BANNED}", http)
    assert res.status is Status.OK and res.requests == 0
    [finding] = res.findings
    assert finding.title == BANNED_ONION_TEXT == finding.description and not finding.data
    assert res.attributes == {} and res.pivots == [] and res.links == [] and not res.raw


def test_no_banned_list_means_nothing_is_sent():
    http = with_ahmia(status=503)
    res = run_module(OnionLookup, f"onion:{NOT_FOUND}", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and res.requests == 0


def test_banned_list_that_is_html_is_refused():
    page = (FIX / "ahmia_blacklist_page.html").read_text()
    parsed = parse_ahmia_banned(page)
    assert parsed["status"] == "invalid" and "HTML" in parsed["reason"]
    assert parse_ahmia_banned("51feb7ecc851bd5fe03e10839d2ca592\nnot-a-hash\n")["status"] == "invalid"
    with_floor = parse_ahmia_banned((FIX / "ahmia_banned_ok.txt").read_text(), min_hashes=10000)
    assert with_floor["status"] == "invalid" and "< expected 10000" in with_floor["reason"]


def test_hash_rule_matches_ahmias_worked_example():
    page = (FIX / "ahmia_blacklist_page.html").read_text()
    assert "You can use this to filter child sexual abuse material from your own search indexes." in " ".join(page.split())
    onion, digest = re.search(r"if the onion is <code>([a-z2-7.]+)</code>.*?would be <code>([0-9a-f]{32})</code>", page, re.S).groups()
    assert onion_ban_hashes(onion) == [digest] == ["c50b9578b6357a561909ff29331ad7ad"]
    sub = onion_ban_hashes(f"http://www.{BANNED}/x")
    assert sub[0] == hashlib.md5(BANNED.encode()).hexdigest() and len(sub) == 2  # a subdomain cannot dodge the filter
    banned = frozenset((FIX / "ahmia_banned_ok.txt").read_text().split())
    assert is_banned_onion(f"https://{BANNED}:443/path", banned=banned) is True
    assert is_banned_onion(NOT_FOUND, banned=banned) is False
    assert is_banned_onion("example.com", banned=banned) is False and is_banned_onion(NOT_FOUND, banned=frozenset()) is None


def test_onion_helpers():
    assert onion_service_domain(f"http://x.{TOR_PROJECT_ONION}/a") == TOR_PROJECT_ONION
    assert onion_service_domain("ranionjgot5cud3p.onion") is None  # v2: never sent
    assert onion_service_domain(TOR_PROJECT_ONION.replace("2gzy", "2gzz")) is None  # bad checksum
    assert is_onion_hostname("ABC.ONION.") and is_onion_hostname("http://a.onion:80/") and not is_onion_hostname("onion.example")


# ------------------------------------------------------------------ cond 4: onion names never reach the network
def test_core_http_refuses_onion_hosts_for_passive_modules():
    http = FakeHttp()
    ctx = make_ctx(OnionLookup, http, entity=f"onion:{NOT_FOUND}")
    with pytest.raises(PolicyError):
        ctx.http.get(f"http://{NOT_FOUND}/")
    assert http.calls == [] and http.unexpected == []


@pytest.mark.xfail(strict=False, reason="core DNS layer does not refuse .onion names yet (P199 cond 4): core request in docs/backlog/p2-G09-1.md")
def test_core_dns_refuses_onion_names():
    http = FakeHttp()
    ctx = make_ctx(OnionLookup, http, entity=f"onion:{NOT_FOUND}")
    answer = ctx.dns.query(NOT_FOUND, "A")
    assert answer.could_not_verify and http.calls == [] and http.unexpected == []
