"""Display grouping (P335, WP19): union-find over the same breach, URL variants and the same CVE.

Grouping is presentation only: the case JSON, STIX and MISP keep every finding (cond 1, 6); URL
variants are grouped visually and exported separately; a URL without a path never groups (cond 5);
identity entities are never merged (cond 2); keys are deterministic and documented (cond 4).
"""

from __future__ import annotations

import copy
import json

import pytest

from v3lum.core.context import ScanOptions
from v3lum.core.engine import CaseResult
from v3lum.core.entities import Entity
from v3lum.core.graph import Graph
from v3lum.core.grouping import FindingGroup, group_correlations, group_findings, normalize_url_key
from v3lum.core.models import Correlation, ModuleResult, Severity

EMAIL = Entity.make("email", "maria.silva@acme-industria.com.br")


def finding(entity, title, *, module, sev="low", conf="probable", tags=("breach",), data=None, source="", key=""):
    res = ModuleResult(module=module, entity=entity)
    return res.finding(title, sev, "synthetic", confidence=conf, criterion=f"{module}: synthetic criterion", tags=list(tags),
                       data=dict(data or {}), source=source, key=key)


def case_dict(seeds, findings, correlations=()):
    g = Graph(noise_check=False)
    for s in seeds:
        g.add_node(s, seed=True)
    for f in findings:
        g.add_finding(f)
    case = CaseResult(case_id="c-grouping", created="2026-11-26T12:00:00+00:00", seeds=list(seeds), options=ScanOptions(), graph=g,
                      correlations=list(correlations))
    return case.to_dict()


def three_breach_sources():
    return [
        finding(EMAIL, "Listed in breach: SynthForum", module="hibp_account", sev="medium", conf="confirmed", data={"breach_key": "synthforum"}),
        finding(EMAIL, "Listed in breach: SynthForum", module="xposedornot", sev="low", conf="probable", data={"breach_key": "synthforum"}),
        finding(EMAIL, "Listed in breach: synth forum", module="leakcheck_public", sev="low", conf="possible", data={"name": "Synth Forum"}),
    ]


# ------------------------------------------------------------------ the URL key (cond 5)


@pytest.mark.parametrize(
    ("url", "key"),
    [
        ("https://www.Example.com.br/a/b/", "example.com.br/a/b"),
        ("http://m.example.com.br/a/b", "example.com.br/a/b"),
        ("hxxps://www[.]example[.]com[.]br/a/b?utm_source=mail&z=1&a=2&fbclid=x", "example.com.br/a/b?a=2&z=1"),
        ("https://example.com.br/a?gclid=1&igshid=2&ref=3&si=4&hl=pt&trk=5&UTM_Medium=6", "example.com.br/a"),
        ("https://example.com.br:443/a#fragment", "example.com.br/a"),
        ("https://user:pass@example.com.br:8443/a", "example.com.br:8443/a"),
        ("ftp://files.example.com.br/pub/x", "ftp://files.example.com.br/pub/x"),
        ("https://www.m.co/x", "m.co/x"),
    ],
)
def test_normalize_url_key(url, key):
    assert normalize_url_key(url) == key


@pytest.mark.parametrize("url", ["https://example.com.br", "https://www.example.com.br/", "https://example.com.br/?id=7", "", None, 42, "https://"])
def test_urls_without_a_path_never_group(url):
    assert normalize_url_key(url) is None


# ------------------------------------------------------------------ the same breach (cond 2, 3, 6)


def test_the_same_breach_from_three_sources_is_one_row_and_three_findings():
    data = case_dict([EMAIL], three_breach_sources())
    before = copy.deepcopy(data)
    groups = group_findings(data["findings"])
    assert len(groups) == 1
    (g,) = groups
    assert isinstance(g, FindingGroup) and g.kind == "breach" and g.key == f"breach|{EMAIL.key}|synthforum"
    assert g.count == 3 and sorted(g.member_ids) == sorted(f["id"] for f in data["findings"])
    assert g.severity == "medium" and g.confidence_label == "confirmed" and g.criterion == "hibp_account: synthetic criterion"
    assert g.sources == ("hibp_account", "leakcheck_public", "xposedornot")
    assert g.label() == "seen by 3 sources: hibp_account, leakcheck_public, xposedornot"
    assert g.principal_id == g.member_ids[0] and g.entities == (EMAIL.key,)
    assert data == before and len(data["findings"]) == 3  # the case JSON keeps every finding
    assert g.to_dict()["member_ids"] == list(g.member_ids)


def test_withheld_sensitive_breach_names_never_group():
    a = finding(EMAIL, "Listed in breach", module="m_a", data={"name": "sensitive breach (name withheld)"})
    b = finding(EMAIL, "Listed in breach", module="m_b", data={"name": "sensitive breach (name withheld)"})
    assert len(group_findings([a, b])) == 2


# ------------------------------------------------------------------ URL variants (cond 1, 5)


def test_url_variants_are_grouped_for_display_and_exported_separately():
    u1 = Entity.make("url", "https://www.shop-login.com.br/login/?utm_source=mail")
    u2 = Entity.make("url", "http://shop-login.com.br/login")
    f1 = finding(u1, "Listed as phishing", module="t_feed_a", sev="high", conf="confirmed", tags=("phishing",))
    f2 = finding(u2, "Listed as phishing", module="t_feed_b", sev="medium", conf="probable", tags=("phishing",))
    data = case_dict([u1, u2], [f1, f2])
    before = copy.deepcopy(data)
    (g,) = group_findings(data["findings"])
    assert g.kind == "url" and g.key == "url|shop-login.com.br/login|phishing" and g.count == 2
    assert g.entities == tuple(sorted([u1.key, u2.key]))  # distinct IOCs, one row
    assert data == before and len(data["findings"]) == 2 and {e["key"] for e in data["entities"]} == {u1.key, u2.key}


def test_grouping_never_removes_a_finding_from_stix_or_misp():
    from v3lum.report import misp, stix

    u1 = Entity.make("url", "https://www.shop-login.com.br/login/?utm_source=mail")
    u2 = Entity.make("url", "http://shop-login.com.br/login")
    data = case_dict([u1, u2], [
        finding(u1, "Listed as phishing", module="t_feed_a", sev="high", conf="confirmed", tags=("phishing",)),
        finding(u2, "Listed as phishing", module="t_feed_b", sev="high", conf="confirmed", tags=("phishing",)),
    ])
    assert len(group_findings(data["findings"])) == 1
    bundle = json.dumps(stix.bundle(data))
    event = json.dumps(misp.event(data))
    for url in (u1.value, u2.value):
        assert url in bundle and url in event  # both variants are exported


def test_a_homepage_url_never_groups():
    home1 = Entity.make("url", "https://portal.gov-example.com.br/")
    home2 = Entity.make("url", "https://www.portal.gov-example.com.br")
    groups = group_findings([
        finding(home1, "Mentioned in a record", module="t_a", tags=("phishing",)),
        finding(home2, "Mentioned in a record", module="t_b", tags=("phishing",)),
    ])
    assert len(groups) == 2 and all(g.kind == "finding" for g in groups)


def test_different_facts_about_one_url_stay_apart():
    u = Entity.make("url", "https://shop-login.com.br/login")
    groups = group_findings([
        finding(u, "Listed as phishing", module="t_a", tags=("phishing",)),
        finding(u, "Serves malware", module="t_b", tags=("malware",)),
    ])
    assert len(groups) == 2


# ------------------------------------------------------------------ the same CVE (cond 2)


def test_the_same_cve_from_several_sources_groups_per_subject():
    host = Entity.make("ipv4", "198.51.100.40")
    other = Entity.make("ipv4", "198.51.100.41")
    a = finding(host, "Vulnerable to CVE-2021-44228", module="t_scan_a", sev="high", tags=("vulnerable",), data={"cve": "CVE-2021-44228"})
    b = finding(host, "Log4Shell (cve-2021-44228) exposed", module="t_scan_b", sev="critical", tags=("vulnerable", "kev"))
    c = finding(host, "Vulnerable to CVE-2023-0001", module="t_scan_a", sev="high", tags=("vulnerable",), data={"cve": "CVE-2023-0001"})
    d = finding(other, "Vulnerable to CVE-2021-44228", module="t_scan_a", sev="high", tags=("vulnerable",), data={"cve": "CVE-2021-44228"})
    groups = group_findings([a, b, c, d])
    by_key = {g.key: g for g in groups}
    shared = by_key[f"cve|{host.key}|CVE-2021-44228|vulnerability"]
    assert shared.count == 2 and shared.severity == "critical" and set(shared.member_ids) == {a.id, b.id}
    assert len(groups) == 3  # another CVE and another host stay apart


# ------------------------------------------------------------------ identities (cond 2)


def test_usernames_and_other_identities_are_never_merged():
    alice = Entity.make("username", "alice")
    alice2 = Entity.make("username", "alice_")
    e2 = Entity.make("email", "maria.silva@outra-empresa.com.br")
    groups = group_findings([
        finding(alice, "Account found", module="t_a", tags=("account",)),
        finding(alice2, "Account found", module="t_b", tags=("account",)),
        finding(EMAIL, "Listed in breach: X", module="t_a", data={"breach_key": "x"}),
        finding(e2, "Listed in breach: X", module="t_b", data={"breach_key": "x"}),
    ])
    assert len(groups) == 4 and all(g.count == 1 for g in groups)


# ------------------------------------------------------------------ review additions (WP19 review)


def test_a_group_is_named_by_a_key_its_members_share():
    u1 = Entity.make("url", "https://shop-login.com.br/login")
    u2 = Entity.make("url", "https://www.shop-login.com.br/login/")
    a = finding(u1, "Phishing kit exploiting CVE-2020-12345", module="t_a", tags=("phishing",))  # a CVE only this member names
    b = finding(u2, "Listed as phishing", module="t_b", tags=("phishing",))
    (g,) = group_findings([a, b])
    assert g.kind == "url" and g.key == "url|shop-login.com.br/login|phishing" and g.count == 2


def test_rows_built_from_finding_objects_never_carry_a_raw_secret():
    raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlLXZhbHVl"
    token = Entity.make("jwt", raw)
    f = finding(token, "JWT exposed in a public paste", module="t_a", sev="high", tags=("exposure",))
    (g,) = group_findings([f])
    assert g.entities and raw not in g.entities[0] and g.entities[0].startswith("jwt:")
    assert raw not in json.dumps(g.to_dict())


# ------------------------------------------------------------------ general properties (cond 4, 6)


def test_every_finding_lands_in_exactly_one_group_deterministically():
    u = Entity.make("url", "https://shop-login.com.br/login")
    items = three_breach_sources() + [
        finding(u, "Listed as phishing", module="t_a", tags=("phishing",)),
        finding(Entity.make("domain", "lonely.com.br"), "Something", module="t_c", tags=("suspicious",)),
    ]
    dicts = [f.to_dict() for f in items]
    first = group_findings(dicts)
    again = group_findings(list(reversed(dicts)))
    assert [g.key for g in first] == [g.key for g in again]
    ids = [i for g in first for i in g.member_ids]
    assert sorted(ids) == sorted(d["id"] for d in dicts) and len(ids) == len(set(ids))
    assert group_findings(items)[0].key == first[0].key  # Finding objects work too
    assert [g.severity for g in first] == sorted((g.severity for g in first), key=lambda s: -["info", "low", "medium", "high", "critical"].index(s))
    singles = [g for g in first if g.count == 1]
    assert all(g.key == f"finding|{g.member_ids[0]}" and g.kind == "finding" for g in singles)
    assert group_findings([]) == []


def test_correlations_are_grouped_by_entity():
    dom = Entity.make("domain", "shop-login.com.br")
    other = Entity.make("domain", "elsewhere.com.br")
    c1 = Correlation("t_rule_a", "weak e-mail security", Severity.MEDIUM, "x", [dom], confidence="probable", criterion="r")
    c2 = Correlation("t_rule_b", "lookalike of the brand", Severity.HIGH, "x", [dom, other], confidence="confirmed", criterion="r2")
    c3 = Correlation("t_rule_a", "weak e-mail security", Severity.LOW, "x", [other], confidence="possible", criterion="r")
    data = [c.to_dict() for c in (c1, c2, c3)]
    before = copy.deepcopy(data)
    groups = group_correlations(data)
    assert [g.key for g in groups] == [f"entity|{dom.key}", f"entity|{other.key}"]
    first = groups[0]
    assert first.kind == "correlation" and first.count == 2 and first.severity == "high" and first.confidence_label == "confirmed"
    assert first.criterion == "r2" and first.sources == ("t_rule_a", "t_rule_b") and set(first.member_ids) == {c1.id, c2.id}
    assert data == before
    assert [g.key for g in group_correlations([c1, c2, c3])] == [g.key for g in groups]  # objects work too
