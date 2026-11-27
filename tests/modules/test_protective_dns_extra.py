"""protective_dns_extra (P020 cond 2, opt-in): AdGuard (JSON DoH), OpenDNS standard / FamilyShield and
CleanBrowsing (RFC 8484), offline.

Fixtures in tests/fixtures/protective_dns_extra/ (batch p2-G01-3 prep, recorded 2026-11-25/26 from a
datacenter egress): live AdGuard default/family answers for example.com (and the research one), a live
AdGuard NODATA (example.com answers non-existent labels NOERROR) and nic.br NXDOMAIN, live OpenDNS and
FamilyShield wire answers for example.com, a live OpenDNS nic.br NXDOMAIN with SOA, synthetic block forms
(AdGuard 0.0.0.0, OpenDNS / FamilyShield Umbrella block pages) and the research CleanBrowsing JSON 400.
CleanBrowsing wire answers are built here with dnspython: its free filters may not be used by
organisations, so they were not re-checked live.
"""

from __future__ import annotations

import json
import re

import pytest

from tests.fakes import FakeHttp, doh_url, module_fixture, run_module
from v3lum.core.models import Confidence, Severity, Status
from v3lum.modules.domain_dns import protective_dns as pd
from v3lum.modules.domain_dns.protective_dns import DEFAULT_RESOLVERS
from v3lum.modules.domain_dns.protective_dns_extra import EXTRA_RESOLVERS, ProtectiveDnsExtra

AG_DEF = "https://dns.adguard-dns.com/resolve?name={n}&type=A"
AG_FAM = "https://family.adguard-dns.com/resolve?name={n}&type=A"
OPENDNS = re.compile(r"^https://doh\.opendns\.com/dns-query\?dns=[A-Za-z0-9_-]+$")
FAMILYSHIELD = re.compile(r"^https://doh\.familyshield\.opendns\.com/dns-query\?dns=[A-Za-z0-9_-]+$")
CB_SEC = re.compile(r"^https://doh\.cleanbrowsing\.org/doh/security-filter/dns-query\?dns=[A-Za-z0-9_-]+$")
CB_FAM = re.compile(r"^https://doh\.cleanbrowsing\.org/doh/family-filter/dns-query\?dns=[A-Za-z0-9_-]+$")
BAD = "malware-test.example.net"
ADULT = "adult-test.example.net"
NICBR = "zz-nonexistent-label-7q3.nic.br"
SOURCES = {s.source for s in EXTRA_RESOLVERS}
needs_dns = pytest.mark.skipif(pd._load_dns() is None, reason="dnspython (extra 'full') not installed: wire resolvers report UNAVAILABLE")


def fx(name):
    return module_fixture("protective_dns_extra", name)


def wire(name):
    import base64

    return dict(body=base64.b64decode(fx(name)["wire_b64"]), headers={"content-type": "application/dns-message"})


def synth_wire(name, *ips, rcode="NOERROR", ttl=60):
    """An RFC 8484 answer built by dnspython (id 0, no EDNS), for the CleanBrowsing cases."""
    import dns.rrset

    dns_mod = pd._load_dns()
    query = dns_mod.message.make_query(name, dns_mod.rdatatype.A)
    query.id = 0
    response = dns_mod.message.make_response(query)
    response.set_rcode(dns_mod.rcode.from_text(rcode))
    if ips:
        response.answer.append(dns.rrset.from_text(name + ".", ttl, "IN", "A", *ips))
    return dict(body=response.to_wire(), headers={"content-type": "application/dns-message"})


def answer(name, *ips, ttl=300):
    return {"Status": 0, "Answer": [{"name": name + ".", "type": 1, "TTL": ttl, "data": ip} for ip in ips]}


def http_for(name, ref, **routes):
    """``routes``: ag_def, ag_fam, opendns, familyshield, cb_sec, cb_fam (None = no route)."""
    urls = {"ag_def": AG_DEF.format(n=name), "ag_fam": AG_FAM.format(n=name), "opendns": OPENDNS, "familyshield": FAMILYSHIELD,
            "cb_sec": CB_SEC, "cb_fam": CB_FAM}
    http = FakeHttp()
    for key, url in urls.items():
        if routes.get(key) is not None:
            http.add("GET", url, **routes[key])
    if ref is not None:
        http.add("GET", doh_url(name, "A", provider="cloudflare"), **ref)
    return http


def benign_example():
    ok = "104.20.23.154"
    return dict(ag_def=dict(json=fx("agdef_example_ok.json")), ag_fam=dict(json=fx("agfam_example_ok.json")),
                opendns=wire("opendns_example_ok.wire.json"), familyshield=wire("opendns_familyshield_example_ok.wire.json"),
                cb_sec=synth_wire("example.com", ok), cb_fam=synth_wire("example.com", ok))


def resolving_bad(**overrides):
    ok = "198.51.100.66"
    routes = dict(ag_def=dict(json=answer(BAD, ok)), ag_fam=dict(json=answer(BAD, ok)), opendns=synth_wire(BAD, ok),
                  familyshield=synth_wire(BAD, ok), cb_sec=synth_wire(BAD, ok), cb_fam=synth_wire(BAD, ok))
    routes.update(overrides)
    return routes


REF_BAD = dict(json=module_fixture("protective_dns", "ref_google_resolves_blocked_name_synthetic.json"))


def verdicts(res):
    return {v["resolver"]: v["verdict"] for v in res.attributes["protective_dns"]["verdicts"]}


# ------------------------------------------------------------------ metadata (cond 2, 4)
def test_contract_metadata():
    cls = ProtectiveDnsExtra
    assert cls.default_enabled is False and cls.terms == "unknown" and cls.trust_tier == "trusted"
    assert cls.terms_sources == {
        "adguard.default": "unknown", "adguard.family": "unknown", "opendns.standard": "unknown", "opendns.familyshield": "unknown",
        "cleanbrowsing.security_filter": "noncommercial", "cleanbrowsing.family_filter": "noncommercial"}
    assert cls.upstream_families == frozenset({"protective_dns"})
    assert cls.max_requests == len(EXTRA_RESOLVERS) == 6 and set(cls.sources) == SOURCES
    assert {s.url.split("/")[2] for s in EXTRA_RESOLVERS} == set(cls.hosts)
    assert not {s.id for s in EXTRA_RESOLVERS} & {s.id for s in DEFAULT_RESOLVERS}
    assert {s.category for s in EXTRA_RESOLVERS} == {"security", "family", "ads"}


# ------------------------------------------------------------------ recorded benign answers
@needs_dns
@pytest.mark.parametrize("family_fixture", ["agfam_example_ok.json", "research_agfam_example.json"])
def test_recorded_answers_read_not_blocked(family_fixture):
    routes = benign_example()
    routes["ag_fam"] = dict(json=fx(family_fixture))
    http = http_for("example.com", dict(json=module_fixture("protective_dns", "ref_google_example_ok.json")), **routes)
    res = run_module(ProtectiveDnsExtra, "domain:example.com", http)
    assert res.status is Status.OK and not res.partial and res.findings == []
    assert set(verdicts(res).values()) == {"not_blocked"}
    assert res.attributes["protective_dns"]["summary"].startswith("not blocked by 2 security resolver(s) at ")
    assert {k: v["status"] for k, v in res.source_statuses.items()} == dict.fromkeys(SOURCES, "ok")
    cleanbrowsing = [u for u in http.urls() if "cleanbrowsing" in u]
    assert len(cleanbrowsing) == 2 and all("?dns=" in u for u in cleanbrowsing)  # wire only: JSON answers 400 (research)
    http.assert_hosts_within(ProtectiveDnsExtra)
    assert not http.hosts() & {"security.cloudflare-dns.com", "family.cloudflare-dns.com", "dns.quad9.net"}


def test_adguard_answers_parse_like_cloudflare():
    research = pd.parse_json_answer(json.dumps(fx("research_agfam_example.json")))
    assert research.rcode == "NOERROR" and research.addresses == ["104.20.23.154", "172.66.147.243"] and research.ttl == 3
    nodata = pd.parse_json_answer(json.dumps(fx("agfam_nodata_example.json")))  # Answer: null
    assert nodata.rcode == "NOERROR" and nodata.addresses == [] and not nodata.has_soa
    nx = pd.parse_json_answer(json.dumps(fx("agfam_nxdomain_nicbr.json")))  # no Authority section at all
    assert nx.rcode == "NXDOMAIN" and not nx.has_soa
    sig = pd.load_signatures()["resolvers"]["adguard_family"]
    assert pd.match_signature(sig, nx) is None  # AdGuard NXDOMAIN is never a block signature


# ------------------------------------------------------------------ content filters vs security blocks (cond 5, 6)
@needs_dns
@pytest.mark.parametrize(("route", "resolver", "category"), [("ag_fam", "adguard_family", "family"), ("ag_def", "adguard_default", "ads")])
def test_adguard_zero_answer_is_only_a_content_filter(route, resolver, category):
    http = http_for(BAD, REF_BAD, **resolving_bad(**{route: dict(json=fx("agfam_blocked_synthetic.json"))}))
    res = run_module(ProtectiveDnsExtra, f"domain:{BAD}", http)
    assert verdicts(res)[resolver] == "blocked"
    [finding] = res.findings
    assert finding.title == "Content filter (adult/ads)" and finding.severity is Severity.INFO
    assert finding.data["categories"] == [category] and "suspicious" not in finding.tags
    assert res.attributes["protective_dns"]["security_blocked"] == []


@needs_dns
def test_opendns_block_page_is_a_low_security_block():
    http = http_for(BAD, REF_BAD, **resolving_bad(opendns=wire("opendns_blockpage_synthetic.wire.json")))
    res = run_module(ProtectiveDnsExtra, f"domain:{BAD}", http)
    [finding] = res.findings
    assert finding.title == "Blocked by OpenDNS" and finding.severity is Severity.LOW
    assert Confidence.from_value(finding.confidence) is Confidence.POSSIBLE
    assert finding.data["signatures"] == {"OpenDNS": "block answer 146.112.61.108"} and finding.source == "opendns.standard"
    assert set(finding.tags) == {"suspicious", "protective_dns_block"}


@needs_dns
def test_two_security_blocks_are_medium_with_the_generic_cleanbrowsing_rule():
    http = http_for(BAD, REF_BAD, **resolving_bad(opendns=wire("opendns_blockpage_synthetic.wire.json"),
                                                  cb_sec=synth_wire(BAD, rcode="NXDOMAIN")))
    res = run_module(ProtectiveDnsExtra, f"domain:{BAD}", http)
    [finding] = res.findings
    assert finding.severity is Severity.MEDIUM and finding.title == "Blocked by OpenDNS, CleanBrowsing (security)"
    assert finding.data["signatures"]["CleanBrowsing (security)"] == "NXDOMAIN"
    assert finding.data["consensus_votes"] == 1  # one upstream family: never HIGH (cond 7)


@needs_dns
def test_familyshield_block_page_is_only_a_content_filter():
    ok = "198.51.100.67"
    http = http_for(ADULT, dict(json=answer(ADULT, ok)), ag_def=dict(json=answer(ADULT, ok)), ag_fam=dict(json=answer(ADULT, ok)),
                    opendns=synth_wire(ADULT, ok), familyshield=wire("opendns_familyshield_blockpage_synthetic.wire.json"),
                    cb_sec=synth_wire(ADULT, ok), cb_fam=synth_wire(ADULT, ok))
    res = run_module(ProtectiveDnsExtra, f"domain:{ADULT}", http)
    assert verdicts(res)["opendns_familyshield"] == "blocked"
    [finding] = res.findings
    assert finding.title == "Content filter (adult/ads)" and finding.data["resolvers"] == ["OpenDNS FamilyShield"]
    assert res.attributes["protective_dns"]["lines"][0].startswith("not blocked by 2 security resolver(s)")


# ------------------------------------------------------------------ the reference rule (cond 5)
@needs_dns
def test_real_nxdomain_and_nodata_are_not_applicable():
    nx_ref = dict(json=module_fixture("protective_dns", "ref_google_nxdomain_nicbr.json"))
    http = http_for(NICBR, nx_ref, ag_def=dict(json=fx("agfam_nxdomain_nicbr.json")), ag_fam=dict(json=fx("agfam_nxdomain_nicbr.json")),
                    opendns=wire("opendns_nxdomain_nicbr.wire.json"), familyshield=wire("opendns_nxdomain_nicbr.wire.json"),
                    cb_sec=synth_wire(NICBR, rcode="NXDOMAIN"), cb_fam=synth_wire(NICBR, rcode="NXDOMAIN"))
    res = run_module(ProtectiveDnsExtra, f"domain:{NICBR}", http)
    assert set(verdicts(res).values()) == {"not_applicable"} and res.findings == []  # CleanBrowsing 'any' NXDOMAIN included
    label = "zz-nonexistent-label-7q3.example.com"
    nodata_ref = dict(json={"Status": 0, "Question": [{"name": label + ".", "type": 1}]})
    http2 = http_for(label, nodata_ref, ag_def=dict(json=fx("agfam_nodata_example.json")), ag_fam=dict(json=fx("agfam_nodata_example.json")),
                     opendns=synth_wire(label), familyshield=synth_wire(label), cb_sec=synth_wire(label), cb_fam=synth_wire(label))
    res2 = run_module(ProtectiveDnsExtra, f"domain:{label}", http2)
    assert set(verdicts(res2).values()) == {"not_applicable"} and res2.findings == []


@needs_dns
def test_opendns_nxdomain_while_the_reference_resolves_is_could_not_verify():
    # OpenDNS never hijacks NXDOMAIN: no signature, so not 'blocked' - and not 'not blocked' either
    http = http_for(BAD, REF_BAD, **resolving_bad(opendns=wire("opendns_nxdomain_nicbr.wire.json")))
    res = run_module(ProtectiveDnsExtra, f"domain:{BAD}", http)
    assert verdicts(res)["opendns"] == "could_not_verify" and res.partial and res.findings == []
    assert "could not verify OpenDNS" in res.attributes["protective_dns"]["lines"]


# ------------------------------------------------------------------ rule 5: failures are 'could not verify'
@needs_dns
def test_cleanbrowsing_400_and_adguard_429_are_could_not_verify():
    recorded = fx("cleanbrowsing_json_400.http.json")["response"]
    routes = benign_example()
    routes["cb_sec"] = dict(status=recorded["status"], text=recorded["body"], headers=recorded["headers"])
    routes["ag_def"] = dict(status=429, text="Too Many Requests")
    http = http_for("example.com", dict(json=module_fixture("protective_dns", "ref_google_example_ok.json")), **routes)
    res = run_module(ProtectiveDnsExtra, "domain:example.com", http)
    rows = res.source_statuses
    assert rows["cleanbrowsing.security_filter"]["status"] == "error"
    assert rows["adguard.default"]["status"] == "rate_limited" and rows["adguard.default"]["reason_code"] == "rate_limited"
    assert res.status is Status.OK and res.partial and res.findings == []
    lines = res.attributes["protective_dns"]["lines"]
    assert lines[0].startswith("not blocked by 1 security resolver(s)") and "could not verify CleanBrowsing (security)" in lines


def test_every_resolver_failing_is_never_empty():
    http = http_for("example.com", dict(json=module_fixture("protective_dns", "ref_google_example_ok.json")),
                    ag_def=dict(status=503, text="busy"), ag_fam=dict(text="<html>maintenance</html>"),
                    opendns=dict(status=403, text="Forbidden"), familyshield=dict(status=502, text="bad gateway"),
                    cb_sec=dict(status=400, text="400 Bad Request"), cb_fam=dict(status=500, text="oops"))
    res = run_module(ProtectiveDnsExtra, "domain:example.com", http)
    assert res.status in (Status.ERROR, Status.BLOCKED, Status.UNAVAILABLE) and res.status is not Status.EMPTY
    assert "could not verify" in res.error and res.findings == []


# ------------------------------------------------------------------ policy gate and dnspython (cond 2, 3)
def test_only_allowed_feeds_are_queried():
    allowed = {"adguard.default", "adguard.family"}
    http = http_for("example.com", dict(json=module_fixture("protective_dns", "ref_google_example_ok.json")),
                    ag_def=dict(json=fx("agdef_example_ok.json")), ag_fam=dict(json=fx("agfam_example_ok.json")))
    res = run_module(ProtectiveDnsExtra, "domain:example.com", http, allowed_sources=allowed)
    assert set(res.source_statuses) == allowed  # the engine reports the licence-blocked rest
    assert http.hosts() <= {"dns.adguard-dns.com", "family.adguard-dns.com", "cloudflare-dns.com"}
    empty = FakeHttp()
    res2 = run_module(ProtectiveDnsExtra, "domain:example.com", empty, allowed_sources=set())
    assert res2.status is Status.SKIPPED and res2.reason_code == "config" and empty.calls == []


def test_without_dnspython_the_wire_resolvers_are_unavailable(monkeypatch):
    monkeypatch.setattr(pd, "_load_dns", lambda: None)
    http = http_for("example.com", dict(json=module_fixture("protective_dns", "ref_google_example_ok.json")),
                    ag_def=dict(json=fx("agdef_example_ok.json")), ag_fam=dict(json=fx("agfam_example_ok.json")))
    res = run_module(ProtectiveDnsExtra, "domain:example.com", http)
    rows = res.source_statuses
    for source in ("opendns.standard", "opendns.familyshield", "cleanbrowsing.security_filter", "cleanbrowsing.family_filter"):
        assert rows[source]["status"] == "unavailable" and rows[source]["reason_code"] == "package"
    assert rows["adguard.default"]["status"] == "ok" and res.partial
    assert not any("opendns" in u or "cleanbrowsing" in u for u in http.urls())
