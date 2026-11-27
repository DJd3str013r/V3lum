"""typosquat_live_checks (P025, LIGHT): passive-first classification, one homepage GET + favicon,
page fingerprints compared with the brand reference page (in the module when the brand page is already
in the case, else by the p9g131 rules), mail capability from DNS facts only (no SMTP), the hostile-host
guard, the 20-candidate cap and the LIGHT envelope (seed binding, GET only, manual redirects, kill switch).

Fixtures: tests/fixtures/typosquat_live_checks/ (synthetic brand/clone/unrelated/parked/meta-refresh
pages under .example, a real Cloudflare challenge capture with tokens removed, real DoH answers). ppdeep
is an optional extra: the tests use a deterministic stand-in (difflib over the normalised HTML) so they
pass with or without the package installed.
"""

from __future__ import annotations

import base64
import datetime
import difflib
import hashlib
import json
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.fakes import FIXTURES, FakeHttp, add_dns, add_dns_failure, make_runtime, run_module
from v3lum.core import correlate
from v3lum.core import module as core_module
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.http import Blocked
from v3lum.core.lint import blocking, lint_module_source
from v3lum.core.models import Opsec, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.correlations import p9_g13_1 as rules
from v3lum.modules.domain_dns import typosquat_live_checks as mod
from v3lum.modules.domain_dns.typosquat_live_checks import TyposquatLiveChecks

FIX = Path(FIXTURES) / "typosquat_live_checks"
BRAND = "bancoexemplo.example"
CAND = "bancoexernplo.example"
OTHER = "bancoexemplo-receitas.example"
ORG = OrgProfile.from_dict({
    "org": {"name": "Banco Exemplo S.A."},
    "domains": [{"name": BRAND, "verification": "txt_verified", "criticality": "high"}],
    "brands": [{"keyword": "bancoexemplo", "criticality": "high"}],
})
LIGHT = ScanOptions(mode=Opsec.LIGHT)


class FakePpdeep:
    """Deterministic ppdeep stand-in: hash() remembers the input, compare() is difflib's ratio x 100."""

    def __init__(self) -> None:
        self.inputs: dict[str, bytes] = {}

    def hash(self, data: bytes) -> str:
        raw = bytes(data)
        digest = hashlib.sha256(raw).hexdigest()
        value = f"24:{digest[:32]}:{digest[32:48]}"
        self.inputs[value] = raw
        return value

    def compare(self, a: str, b: str) -> int:
        return int(difflib.SequenceMatcher(None, self.inputs[a], self.inputs[b], autojunk=False).ratio() * 100)


@pytest.fixture(autouse=True)
def ppdeep(monkeypatch):
    fake = FakePpdeep()
    monkeypatch.setattr(mod, "load_ppdeep", lambda: fake)
    monkeypatch.setattr(rules, "load_ppdeep", lambda: fake)
    return fake


def page(name: str) -> bytes:
    return (FIX / name).read_bytes()


def recorded(name: str) -> tuple[int, dict, bytes]:
    data = json.loads((FIX / name).read_text(encoding="utf-8"))
    resp = data["response"]
    body = base64.b64decode(resp["body_b64"]) if "body_b64" in resp else str(resp.get("body") or "").encode("utf-8")
    return resp["status"], dict(resp.get("headers") or {}), body


def html(http: FakeHttp, url: str, name: str) -> None:
    http.add("GET", url, body=page(name), headers={"content-type": "text/html; charset=utf-8"})


def icon(http: FakeHttp, url: str, name: str = "favicon_brand.png") -> None:
    http.add("GET", url, body=page(name), headers={"content-type": "image/png"})


def resolve(http: FakeHttp, host: str, ip: str = "93.184.216.40") -> None:
    add_dns(http, host, "A", [ip])
    add_dns(http, host, "AAAA", [])


def brand_site(http: FakeHttp) -> None:
    resolve(http, BRAND, "93.184.216.34")
    html(http, f"https://{BRAND}/", "brand_home.html")
    icon(http, f"https://{BRAND}/static/favicon.png")


def case_graph(*, brand_fp: dict | None = None, cand: str = CAND, facts: dict | None = None, edge: bool = True) -> Graph:
    graph = Graph()
    brand = Entity.make(T.DOMAIN, BRAND)
    graph.add_node(brand, seed=True)
    if brand_fp is not None:
        graph.add_attributes(brand, {"page_fingerprint": brand_fp}, "typosquat_live_checks")
    ent = Entity.make(T.DOMAIN, cand)
    graph.add_node(ent, seed=True)
    attrs = {"registered": True, "nameservers": ["ns1.cheap-dns.example"], "a_records": ["93.184.216.40"],
             "mx": [f"mx.{cand}"], "spf": "v=spf1 -all"}
    attrs.update(facts or {})
    graph.add_attributes(ent, {k: v for k, v in attrs.items() if v is not None}, "dns_records")
    if edge:
        graph.add_edge(brand, ent, "lookalike", "typosquat", 0.7, expand=False)
    return graph


def runtime(http: FakeHttp, graph: Graph | None = None, org=ORG):
    rt = make_runtime(http, org_profile=org)
    rt.policy_context = SimpleNamespace(graph=graph if graph is not None else Graph())
    return rt


def run(http: FakeHttp, value: str = CAND, *, graph: Graph | None = None, rt=None, **kw):
    rt = rt or runtime(http, graph if graph is not None else case_graph())
    return run_module(TyposquatLiveChecks, f"domain:{value}", http, runtime=rt, options=kw.pop("options", LIGHT), **kw)


def target_calls(http: FakeHttp, host: str) -> list[dict]:
    return [c for c in http.calls if c["url"].startswith((f"https://{host}", f"http://{host}"))]


def brand_fingerprint(http: FakeHttp | None = None) -> dict:
    http = http or FakeHttp()
    brand_site(http)
    res = run(http, BRAND, graph=Graph())
    assert res.status is Status.OK, res.error
    return res.attributes["page_fingerprint"]


# ---------------------------------------------------------------------------------- pure helpers (FC1, FC2, FC4, FC7)
def test_normalize_html_blanks_each_link_attribute_without_eating_the_text_between():
    out = mod.normalize_html(b'<a  href="/a">one</a>\n<img src=\'x.png\'> two <form action="https://x.example/p">'
                             b'<div style="background:url(/bg.jpg)">three</div>')
    assert out == b'<a href="">one</a> <img src=""> two <form action=""><div style="background:url()">three</div>'


def test_page_features_reads_title_forms_and_meta_refresh_and_discards_non_html_unparsed():
    feats = mod.page_features(page("clone_home.html"), f"https://{CAND}/")
    assert feats["title"] == "Banco Exemplo | Internet Banking"
    assert feats["login_form"] and feats["posts_offsite"] and feats["offsite_form_hosts"] == ["coletor.example.net"]
    refresh = mod.page_features(page("meta_refresh_to_brand.html"), f"https://{CAND}/")
    assert refresh["meta_refresh"] == f"https://www.{BRAND}/"
    _status, headers, body = recorded("non_html_200.http.json")
    zipped = mod.page_features(body, f"https://{CAND}/", headers["content-type"])
    assert zipped == {"html": False, "reason": "non-HTML body (application/zip) discarded unparsed"}


def test_mail_capability_comes_from_dns_facts_only():
    yes = mod.mail_capability({"mx": [f"mx.{CAND}"], "spf": "v=spf1 -all", "dmarc": "v=DMARC1;p=reject;sp=reject"})
    assert (yes["can_receive_mail"], yes["label"], yes["spf_all"], yes["dmarc_policy"]) == (True, mod.MAIL_LABEL, "-all", "reject")
    assert yes["source"] == "dns facts (no SMTP contact)"
    null = mod.mail_capability({"mx": [""]})
    assert (null["can_receive_mail"], null["null_mx"]) == (False, True) and "null MX" in null["label"]
    implicit = mod.mail_capability({"mx": [], "has_address": True})
    assert implicit["can_receive_mail"] == "possible" and "implicit MX" in implicit["label"]
    assert mod.mail_capability({})["can_receive_mail"] is None  # unknown is never 'no mail'


def test_passive_classify_never_fetches_unregistered_parked_defensive_or_addressless_names():
    base = {"registered": True, "ns": ["ns1.cheap-dns.example"], "a": ["93.184.216.40"]}
    assert mod.passive_classify({"registered": False})["state"] == "unregistered"
    assert mod.passive_classify({**base, "ns": [f"ns1.{BRAND}"]}, own_zones=[BRAND])["state"] == "defensive"
    assert mod.passive_classify({**base, "own_verdict": "defensive_probable"})["state"] == "defensive"
    redirect = mod.passive_classify({**base, "redirect_evidence": [f"https://www.{BRAND}/"], "brand_hosts": [BRAND]})
    assert redirect["state"] == "defensive" and "archived" in redirect["reason"]
    parked = mod.passive_classify({**base, "ns": ["ns1.sedoparking.com"]}, parking_ns=lambda h: h.endswith("sedoparking.com"))
    assert parked["state"] == "parked" and not parked["contact"]
    assert mod.passive_classify({**base, "a": []})["state"] == "no_address"
    assert mod.passive_classify({"registered": None})["state"] == "could_not_verify"
    assert mod.passive_classify(base) == {"state": "fetch", "reason": "registered, has an address, not parked or defensive", "contact": True}


def test_compare_fingerprints_scores_ppdeep_plus_title_favicon_and_login_form(ppdeep):
    brand = {"ppdeep": ppdeep.hash(mod.normalize_html(page("brand_home.html"))), "title": "A", "favicon_mmh3": 7, "login_form": True}
    clone = {"ppdeep": ppdeep.hash(mod.normalize_html(page("clone_home.html"))), "title": "a ", "favicon_mmh3": 7, "login_form": True}
    other = {"ppdeep": ppdeep.hash(mod.normalize_html(page("unrelated_home.html"))), "title": "B", "favicon_mmh3": 8}
    hit = mod.compare_fingerprints(brand, clone, ppdeep=ppdeep)
    assert hit["state"] == "live_clone" and hit["score"] >= mod.LIVE_CLONE_THRESHOLD
    assert hit["title_match"] and hit["favicon_match"] and hit["form_match"]
    miss = mod.compare_fingerprints(brand, other, ppdeep=ppdeep)
    assert miss["state"] == "unrelated" and miss["score"] < mod.LIVE_CLONE_THRESHOLD
    assert mod.compare_fingerprints(brand, clone, ppdeep=None)["state"] == "could_not_verify"  # no ppdeep, different hashes
    assert mod.compare_fingerprints(brand, {**other, "favicon_mmh3": 99}, ppdeep=ppdeep, org_favicons=["99"])["favicon_match"]
    assert "malicious" not in mod.verdict_wording("live_clone", 91, "https://x.example/")
    # FC7 form-action hosts: a page that posts to the brand's own login host scores the form component
    proxy = {**other, "form_action_hosts": [f"login.{BRAND}"]}
    posts = mod.compare_fingerprints({**brand, "login_form": False, "form_action_hosts": [f"LOGIN.{BRAND}."]}, proxy, ppdeep=ppdeep)
    assert posts["form_match"] and any(m.startswith("form posts to the brand's host") for m in posts["matched"])
    no_form = mod.compare_fingerprints({**brand, "login_form": False}, other, ppdeep=ppdeep)
    assert not no_form["form_match"] and posts["score"] == no_form["score"] + 10


# ---------------------------------------------------------------------------------- candidate runs
def candidate_site(http: FakeHttp, name: str = "clone_home.html", host: str = CAND) -> None:
    resolve(http, host)
    html(http, f"https://{host}/", name)
    icon(http, f"https://{host}/favicon.png")


def test_live_clone_when_the_brand_page_is_already_in_the_case():
    ref = brand_fingerprint()
    http = FakeHttp()
    candidate_site(http)
    res = run(http, graph=case_graph(brand_fp=ref))
    assert res.status is Status.OK, res.error
    live = res.attributes["live_check"]
    assert live["state"] == "live_clone" and live["contacted"] and live["requests"] == 2
    cmp = live["comparison"]
    assert cmp["score"] >= mod.LIVE_CLONE_THRESHOLD and cmp["brand"] == BRAND
    assert cmp["wording"].startswith(f"page {cmp['score']}% similar to https://{BRAND}/ -> likely live clone")
    assert "lookalike / phishing-capable indicator" in cmp["wording"] and "malicious" not in json.dumps(res.attributes)
    fp = res.attributes["page_fingerprint"]
    assert fp["role"] == "candidate" and fp["favicon_mmh3"] == ref["favicon_mmh3"] and fp["posts_offsite"]
    assert "body" not in fp and "senha" not in json.dumps(fp)  # hashes and metadata only, never the page or form values
    pivots = {(p.entity.value, p.relation, p.expand) for p in res.pivots}
    assert ("coletor.example.net", "form_posts_to", False) in pivots  # IOC for passive modules only (A13)
    calls = target_calls(http, CAND)
    assert [c["url"] for c in calls] == [f"https://{CAND}/", f"https://{CAND}/favicon.png"]
    assert {c["method"] for c in calls} == {"GET"} and not target_calls(http, BRAND)
    assert res.attributes["mail_capability"]["label"] == mod.MAIL_LABEL
    assert not res.findings  # the verdict is reported once, by the p9g131 rule


def test_unrelated_page_is_recorded_as_unrelated():
    ref = brand_fingerprint()
    http = FakeHttp()
    candidate_site(http, "unrelated_home.html", OTHER)
    http.add("GET", f"https://{OTHER}/favicon.ico", status=404, text="not found")
    res = run(http, OTHER, graph=case_graph(brand_fp=ref, cand=OTHER))
    live = res.attributes["live_check"]
    assert live["state"] == "unrelated" and live["comparison"]["score"] < mod.LIVE_CLONE_THRESHOLD
    assert live["reason"].endswith("-> unrelated content")


def test_brand_and_candidate_in_any_order_the_rule_compares_after_the_scan():
    http = FakeHttp()
    candidate_site(http)
    graph = case_graph()  # the brand page is not in the case yet (concurrent LIGHT phase)
    cand = run(http, graph=graph)
    assert cand.attributes["live_check"]["state"] == "fetched" and "comparison" not in cand.attributes["live_check"]
    graph.add_attributes(Entity.make(T.DOMAIN, CAND), cand.attributes, "typosquat_live_checks")
    graph.add_attributes(Entity.make(T.DOMAIN, BRAND), {"page_fingerprint": brand_fingerprint()}, "typosquat_live_checks")
    rctx = correlate.RuleContext(now=datetime.datetime(2026, 11, 26, 12, tzinfo=datetime.timezone.utc), org=ORG)
    clones = list(rules.p9g131_typosquat_live_clone(graph, [], rctx))
    assert len(clones) == 1 and clones[0].severity.label == "high" and clones[0].label.value == "probable"
    assert clones[0].description.startswith(f"{CAND}: page ") and "likely live clone" in clones[0].description
    assert [e.value for e in clones[0].entities] == [CAND, BRAND]
    assert not list(rules.p9g131_typosquat_page_unrelated(graph, [], rctx))


def test_fetched_parking_page_is_parked_and_never_compared():
    http = FakeHttp()
    resolve(http, CAND)
    html(http, f"https://{CAND}/", "parked_home.html")
    res = run(http)
    assert res.attributes["live_check"]["state"] == "parked" and "page_fingerprint" not in res.attributes
    assert len(target_calls(http, CAND)) == 1  # no favicon for a parked page


def test_passively_parked_unregistered_or_addressless_candidates_are_never_contacted():
    for facts, state in (({"is_parked": True}, "parked"), ({"registered": False, "a_records": None, "nameservers": None, "mx": None}, "unregistered")):
        http = FakeHttp()
        res = run(http, graph=case_graph(facts=facts))
        assert res.attributes["live_check"]["state"] == state, (facts, res.attributes)
        assert res.attributes["live_check"]["contacted"] is False and not http.calls
    # no address in the case: the resolvers (never the candidate) confirm it before 'no_address' is written
    http = FakeHttp()
    add_dns(http, CAND, "A", [], provider="all")
    add_dns(http, CAND, "AAAA", [], provider="all")
    res = run(http, graph=case_graph(facts={"a_records": []}))
    assert res.attributes["live_check"]["state"] == "no_address" and res.attributes["live_check"]["contacted"] is False
    assert not target_calls(http, CAND) and {c["url"].split("/")[2] for c in http.calls} <= {"dns.google", "cloudflare-dns.com"}


def test_a_case_without_addresses_is_checked_by_doh_before_no_address():
    """FC4: a P012 row lists the name as registered (NS only, no A) and the lookalike is IPv6-only: DoH finds
    the address, so it is fetched instead of being written off as 'no A/AAAA record'."""
    graph = case_graph(facts={"a_records": None})
    graph.add_attributes(Entity.make(T.DOMAIN, BRAND), {"typosquat_lookalikes": [
        {"domain": CAND, "state": "registered", "ns": ["ns1.cheap-dns.example"], "mx_present": False}]}, "typosquat")
    http = FakeHttp()
    add_dns(http, CAND, "A", [], provider="all")
    add_dns(http, CAND, "AAAA", ["2606:2800:220:1:248:1893:25c8:1946"], provider="all")
    html(http, f"https://{CAND}/", "clone_home.html")
    icon(http, f"https://{CAND}/favicon.png")
    res = run(http, graph=graph)
    live = res.attributes["live_check"]
    assert live["state"] == "fetched" and live["contacted"] and "page_fingerprint" in res.attributes
    # the resolvers could not answer: could not verify, never 'no address', and nothing is contacted
    failing = FakeHttp()
    add_dns_failure(failing, CAND, "A", kind="servfail", provider="all")
    add_dns_failure(failing, CAND, "AAAA", kind="servfail", provider="all")
    out = run(failing, graph=case_graph(facts={"a_records": None}))
    assert out.attributes["live_check"]["state"] == "could_not_verify" and out.status is Status.ERROR
    assert not target_calls(failing, CAND)


def test_supplier_name_servers_never_make_a_lookalike_defensive():
    """Only the organisation's own domains make a registration defensive: a lookalike on a supplier's DNS is checked."""
    org = OrgProfile.from_dict({
        "org": {"name": "Banco Exemplo S.A."},
        "domains": [{"name": BRAND, "verification": "txt_verified", "criticality": "high"}],
        "suppliers": [{"name": "Provedor de DNS", "domains": ["dns-provedor.example"]}],
    })
    http = FakeHttp()
    candidate_site(http)
    rt = runtime(http, case_graph(facts={"nameservers": ["ns1.dns-provedor.example"]}), org=org)
    res = run(http, rt=rt)
    assert res.attributes["live_check"]["state"] == "fetched" and res.attributes["live_check"]["contacted"]


def test_p012_own_or_defensive_verdict_is_never_contacted():
    graph = case_graph()
    graph.add_attributes(Entity.make(T.DOMAIN, BRAND), {"typosquat_own_registrations": [
        {"domain": CAND, "ownership": "defensive_probable", "evidence": ["registrant matches the org profile"]}]}, "typosquat")
    http = FakeHttp()
    res = run(http, graph=graph)
    assert res.attributes["live_check"]["state"] == "defensive" and not http.calls


def test_defensive_301_to_the_brand_is_never_flagged_and_the_brand_is_not_requested():
    http = FakeHttp()
    resolve(http, CAND)
    status, headers, _ = recorded("defensive_redirect_301.http.json")
    http.add("GET", f"https://{CAND}/", status=status, headers=headers)
    res = run(http)
    live = res.attributes["live_check"]
    assert live["state"] == "defensive" and "redirects to the brand" in live["reason"] and "not flagged" in live["reason"]
    assert len(target_calls(http, CAND)) == 1 and not target_calls(http, f"www.{BRAND}")
    assert not res.findings and "page_fingerprint" not in res.attributes


def test_meta_refresh_to_the_brand_is_defensive_and_not_followed():
    http = FakeHttp()
    resolve(http, CAND)
    html(http, f"https://{CAND}/", "meta_refresh_to_brand.html")
    res = run(http)
    assert res.attributes["live_check"]["state"] == "defensive" and "meta refresh" in res.attributes["live_check"]["reason"]
    assert len(http.calls) - len([c for c in http.calls if "dns" in c["url"]]) == 1


def test_offsite_redirect_is_not_followed_and_becomes_a_passive_pivot():
    http = FakeHttp()
    resolve(http, CAND)
    http.add("GET", f"https://{CAND}/", status=302, headers={"location": "https://kit.example.org/inicio"})
    res = run(http)
    assert res.attributes["live_check"]["state"] == "could_not_verify"
    assert ("https://kit.example.org/inicio", "redirects_to", False) in {(p.entity.value, p.relation, p.expand) for p in res.pivots}
    assert not target_calls(http, "kit.example.org")


def test_same_site_redirect_is_followed_hop_by_hop():
    http = FakeHttp()
    resolve(http, CAND)
    resolve(http, f"www.{CAND}")
    http.add("GET", f"https://{CAND}/", status=301, headers={"location": f"https://www.{CAND}/"})
    html(http, f"https://www.{CAND}/", "clone_home.html")
    icon(http, f"https://www.{CAND}/favicon.png")
    res = run(http)
    assert res.attributes["page_fingerprint"]["final_url"] == f"https://www.{CAND}/"
    # every hop is its own request, checked before it is sent (the core never follows the redirect itself)
    assert [c["url"] for c in target_calls(http, CAND) + target_calls(http, f"www.{CAND}") if "dns" not in c["url"]] == [
        f"https://{CAND}/", f"https://www.{CAND}/", f"https://www.{CAND}/favicon.png"]


def test_non_html_body_is_discarded_and_no_favicon_is_fetched():
    http = FakeHttp()
    resolve(http, CAND)
    status, headers, body = recorded("non_html_200.http.json")
    http.add("GET", f"https://{CAND}/", status=status, headers=headers, body=body)
    res = run(http)
    assert res.attributes["live_check"]["state"] == "could_not_verify" and "discarded" in res.attributes["live_check"]["reason"]
    assert len(target_calls(http, CAND)) == 1 and "page_fingerprint" not in res.attributes


def test_challenge_is_blocked_could_not_verify_and_429_is_rate_limited():
    http = FakeHttp()
    resolve(http, CAND)
    status, headers, body = recorded("challenge_403.http.json")
    http.add("GET", f"https://{CAND}/", status=status, headers=headers, body=body)
    res = run(http)
    assert (res.status, res.reason_code) == (Status.BLOCKED, "challenge")
    assert res.attributes["live_check"]["state"] == "could_not_verify"
    limited = FakeHttp()
    resolve(limited, CAND)
    limited.add("GET", f"https://{CAND}/", status=429, headers={"retry-after": "120"}, text="slow down")
    out = run(limited)
    assert out.status is Status.RATE_LIMITED and len(target_calls(limited, CAND)) == 1


def test_451_is_a_geo_block_could_not_verify():
    http = FakeHttp()
    resolve(http, CAND)
    http.add("GET", f"https://{CAND}/", status=451, text="Unavailable For Legal Reasons")
    res = run(http)
    assert (res.status, res.reason_code) == (Status.BLOCKED, "geo_block")
    assert res.attributes["live_check"]["state"] == "could_not_verify"


def test_hostile_redirect_refusal_is_blocked_hostile_host_with_manual_pivots(monkeypatch):
    def refuse(*a, **k):
        raise Blocked("redirect target refused by the hostile-host guard (needs non-corporate egress)", 0, f"https://{CAND}/",
                      reason_code="hostile_host")

    monkeypatch.setattr(mod, "safe_get", refuse)
    res = run(FakeHttp())
    assert (res.status, res.reason_code) == (Status.BLOCKED, "hostile_host")
    labels = {label for label, _url in res.links}
    assert {"urlscan search (passive)", "Wayback Machine archived copies"} <= labels


def test_unreadable_brand_page_is_could_not_verify_never_empty():
    http = FakeHttp()
    resolve(http, BRAND, "93.184.216.34")
    http.add("GET", f"https://{BRAND}/", status=302, headers={"location": "https://kit.example.org/"})
    res = run(http, BRAND, graph=Graph())
    assert res.status is Status.ERROR and "no brand reference page" in res.error
    assert "page_fingerprint" not in res.attributes


def test_only_with_mode_light_even_for_verified_own_seeds():
    """FC2 is stricter than light_for_own_assets: no contact without an explicit --mode light."""
    http = FakeHttp()
    brand_site(http)
    rt = make_runtime(http, org_profile=ORG, settings={"light_for_own_assets": True})
    rt.policy_context = SimpleNamespace(graph=Graph())
    res = run_module(TyposquatLiveChecks, f"domain:{BRAND}", http, runtime=rt, options=ScanOptions())
    assert (res.status, res.reason_code) == (Status.SKIPPED, "opsec")
    assert not target_calls(http, BRAND) and "page_fingerprint" not in res.attributes


def test_missing_ppdeep_is_unavailable_before_any_contact(monkeypatch):
    monkeypatch.setattr(mod, "load_ppdeep", lambda: None)
    http = FakeHttp()
    res = run(http)
    assert (res.status, res.reason_code) == (Status.UNAVAILABLE, "package") and not http.calls


def test_pivots_are_never_contacted():
    http = FakeHttp()
    res = run(http, is_seed=False)
    assert (res.status, res.reason_code) == (Status.SKIPPED, "scope") and not http.calls


def test_at_most_twenty_candidates_are_contacted_per_run():
    http = FakeHttp()
    candidate_site(http)
    rt = runtime(http, case_graph())
    rt.meta[mod._RUN_KEY] = {f"other{i}.example" for i in range(mod.MAX_LIGHT_CANDIDATES)}
    res = run(http, rt=rt)
    assert (res.status, res.reason_code) == (Status.SKIPPED, "not_applicable") and not target_calls(http, CAND)


def test_kill_switch_stops_before_contact():
    http = FakeHttp()
    candidate_site(http)
    rt = runtime(http, case_graph())
    rt.cancel("analyst kill switch")
    res = run(http, rt=rt)
    assert res.partial and res.stop_reason == "cancelled" and not target_calls(http, CAND)
    assert "page_fingerprint" not in res.attributes


def test_dns_facts_come_from_passive_doh_when_the_case_has_none():
    http = FakeHttp()
    for rtype, records in (("NS", ["ns1.cheap-dns.example."]), ("A", ["93.184.216.40"]), ("AAAA", []), ("MX", ["10 mx.bancoexernplo.example."])):
        add_dns(http, CAND, rtype, records, provider="all")
    add_dns(http, CAND, "TXT", ['"v=spf1 -all"'], provider="all")
    add_dns(http, f"_dmarc.{CAND}", "TXT", ['"v=DMARC1;p=reject;sp=reject"'], provider="all")
    html(http, f"https://{CAND}/", "clone_home.html")
    icon(http, f"https://{CAND}/favicon.png")
    graph = Graph()
    graph.add_node(Entity.make(T.DOMAIN, CAND), seed=True)
    res = run(http, graph=graph)
    mail = res.attributes["mail_capability"]
    assert (mail["can_receive_mail"], mail["spf_all"], mail["dmarc_policy"]) == (True, "-all", "reject")
    assert res.attributes["live_check"]["state"] == "fetched" and res.attributes["live_check"]["brands"] == [BRAND]


def test_no_smtp_connection_to_ports_25_465_587(monkeypatch):
    attempts: list[object] = []
    real_connect = socket.socket.connect

    def spy_create(address, *a, **k):
        attempts.append(address)
        raise AssertionError(f"unexpected socket connection to {address}")

    def spy_connect(self, address):
        attempts.append(address)
        if isinstance(address, tuple) and len(address) >= 2 and address[1] in (25, 465, 587):
            raise AssertionError(f"SMTP connection attempted: {address}")
        return real_connect(self, address)

    monkeypatch.setattr(socket, "create_connection", spy_create)
    monkeypatch.setattr(socket.socket, "connect", spy_connect)
    ref = brand_fingerprint()
    http = FakeHttp()
    candidate_site(http)
    rt = runtime(http, case_graph(brand_fp=ref))
    res = run(http, rt=rt)
    assert res.attributes["mail_capability"]["label"] == mod.MAIL_LABEL  # MX present: inferred, never probed
    assert attempts == []
    assert not any(":25" in c["url"] or ":465" in c["url"] or ":587" in c["url"] for c in http.calls)
    assert "net.connect" not in Path(mod.__file__).read_text(encoding="utf-8") and "smtplib" not in Path(mod.__file__).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------------- brand seed (FC3)
def test_brand_seed_records_the_reference_and_lists_lookalikes_without_contacting_them():
    http = FakeHttp()
    brand_site(http)
    graph = Graph()
    brand = Entity.make(T.DOMAIN, BRAND)
    graph.add_node(brand, seed=True)
    rows = [{"domain": f"bancoexemplo{i:02d}.example", "state": "registered"} for i in range(25)]
    rows.append({"domain": "bancoexemplo99.example", "state": "unregistered"})
    graph.add_attributes(brand, {"typosquat_lookalikes": rows}, "typosquat")
    res = run(http, BRAND, graph=graph)
    assert res.attributes["page_fingerprint"]["role"] == "brand_reference"
    listed = res.attributes["live_check_candidates"]
    assert len(listed) == mod.MAX_LIGHT_CANDIDATES and {c["state"] for c in listed} == {"awaiting_confirmation"}
    assert res.raw["candidates_over_cap"] == 5 and "bancoexemplo99.example" not in {c["domain"] for c in listed}
    contacted = {(c["url"].split("/")[2]) for c in http.calls if "dns" not in c["url"]}
    assert contacted == {BRAND}


# ---------------------------------------------------------------------------------- hostile-host guard (FC5)
def test_hostile_guard_blocks_lookalikes_of_the_org_brand_from_the_corporate_egress(monkeypatch):
    monkeypatch.setattr(core_module, "package_available", lambda name: True)
    http = FakeHttp()
    rt = runtime(http, case_graph())
    engine = Engine(rt, ScanOptions(mode=Opsec.LIGHT, include={"typosquat_live_checks"}))
    decision = engine.decide_single(TyposquatLiveChecks, Entity.make(T.DOMAIN, CAND))
    assert (decision.allowed, decision.reason_code) == (False, "hostile_host")
    assert "non-corporate egress" in decision.reason and "lookalike of the org brand" in decision.reason
    case = Engine(runtime(http, case_graph()), ScanOptions(mode=Opsec.LIGHT, include={"typosquat_live_checks"})).investigate(
        [Entity.make(T.DOMAIN, CAND)])
    cov = case.coverage["typosquat_live_checks"]
    assert (cov["status"], cov["reason_code"]) == ("blocked", "hostile_host") and not target_calls(http, CAND)
    override = Engine(runtime(http, case_graph()), ScanOptions(mode=Opsec.LIGHT, include={"typosquat_live_checks"},
                                                               egress_override="brand-protection review T-1"))
    assert override.decide_single(TyposquatLiveChecks, Entity.make(T.DOMAIN, CAND)).allowed


# ---------------------------------------------------------------------------------- contract
def test_contract_light_target_default_off_and_offline_selftest(ppdeep):
    cls = TyposquatLiveChecks
    assert (cls.opsec, cls.disclosure, cls.default_enabled, cls.requires_packages) == (Opsec.LIGHT, "target", False, ("ppdeep",))
    hc = cls.health_check()
    assert hc.offline and hc.selftest(None).status == "ok"
    assert blocking(lint_module_source(Path(mod.__file__))) == []
    assert blocking(lint_module_source(Path(rules.__file__), profile="code")) == []
    header = Path(mod.__file__).read_text(encoding="utf-8").splitlines()[:5]
    assert "dnstwist" in header[0] and "Apache License, Version 2.0" in header[2]


def test_real_ppdeep_scores_the_recorded_clone_and_not_the_unrelated_page():
    real = pytest.importorskip("ppdeep")  # the optional extra; skipped when it is not installed
    digest = {n: mod.ppdeep_hash(real, mod.normalize_html(page(n))) for n in ("brand_home.html", "clone_home.html", "unrelated_home.html")}
    brand = {"ppdeep": digest["brand_home.html"], "title": "Banco Exemplo | Internet Banking", "login_form": True}
    clone = {"ppdeep": digest["clone_home.html"], "title": "Banco Exemplo | Internet Banking", "login_form": True}
    other = {"ppdeep": digest["unrelated_home.html"], "title": "Receitas"}
    assert mod.compare_fingerprints(brand, clone, ppdeep=real)["state"] == "live_clone"
    assert mod.compare_fingerprints(brand, other, ppdeep=real)["state"] == "unrelated"
