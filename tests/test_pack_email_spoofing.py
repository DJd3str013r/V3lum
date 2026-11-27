"""E-mail spoofing pack (P027: CR01-CR03): one test per final condition beyond the graph fixtures run
by tests/test_rule_fixtures.py (spoofable_email_domain, spf_lookup_limit,
dmarc_reports_external_unauthorized)."""

from __future__ import annotations

import datetime as dt
import inspect
from pathlib import Path

import pytest

from v3lum.core import correlate, vocab
from v3lum.core.context import ScanOptions
from v3lum.core.correlate import RuleContext, load_graph_fixture, run_rules
from v3lum.core.entities import Entity
from v3lum.core.graph import Graph
from v3lum.core.models import Confidence, Finding, Severity
from v3lum.core.orgprofile import OrgProfile
from v3lum.correlations import email_spoofing as es

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures" / "rules"
PACK_RULES = ("spoofable_email_domain", "spf_lookup_limit", "dmarc_reports_external_unauthorized")
P = "email_security_posture"


def rctx(**kw) -> RuleContext:
    return RuleContext(now=NOW, **kw)


def domain(g: Graph, value: str, *, seed: bool = True, depth: int = 0, **attrs):
    node, _ = g.add_node(Entity.make("domain", value), depth, seed=seed)
    for name, val in attrs.items():
        node.attributes.setdefault(name, []).append((val, P))
    return node


def spf_attrs(kind: str) -> dict:
    """SPF facts as email_security_posture writes them."""
    if kind == "missing":
        return {"spf_status": "none", "email_posture": {"spf": "absent"}}
    if kind == "permerror":
        return {"spf_status": "permerror", "spf": "v=spf1 include:a.example -all", "spf_lookups": 12, "spf_void_lookups": 0}
    if kind == "no_all":
        return {"spf_status": "ok", "spf": "v=spf1 ip4:192.0.2.0/24"}
    return {"spf_status": "ok", "spf": f"v=spf1 include:_spf.mail.example {kind}"}


def dmarc_attrs(kind: str) -> dict:
    if kind == "missing":
        return {"email_posture": {"dmarc": "absent"}}
    policy, _, pct = kind.partition("@")
    return {"dmarc": f"v=DMARC1; p={policy}" + (f"; pct={pct}" if pct else ""), "dmarc_policy": policy, "dmarc_pct": int(pct or 100), "dmarc_sp": policy}


def merged(*parts: dict) -> dict:
    out: dict = {}
    for part in parts:
        for key, value in part.items():
            if key == "email_posture" and key in out:
                out[key] = {**out[key], **value}
            else:
                out[key] = value
    return out


def cr01(g: Graph, **kw):
    return run_rules(g, [], only={"spoofable_email_domain"}, rctx=rctx(**kw))


# ------------------------------------------------------------------ cond 1: weak DMARC AND weak SPF
@pytest.mark.parametrize("dmarc", ["missing", "none", "quarantine@50", "quarantine@100", "reject", "reject@20"])
@pytest.mark.parametrize("spf", ["missing", "~all", "?all", "+all", "permerror", "-all", "no_all"])
def test_spoofable_needs_weak_dmarc_and_weak_spf(dmarc, spf):
    g = Graph(noise_check=False)
    domain(g, "mail-target.example", **merged(spf_attrs(spf), dmarc_attrs(dmarc)))
    weak_dmarc = dmarc in ("missing", "none", "quarantine@50", "reject@20")
    weak_spf = spf != "-all"
    out = cr01(g)
    assert bool(out) is (weak_dmarc and weak_spf), (dmarc, spf, [c.title for c in out])
    if out:
        assert out[0].severity is Severity.HIGH and out[0].label is Confidence.CONFIRMED


# ------------------------------------------------------------------ cond 2: CR02 thresholds, CR03
@pytest.mark.parametrize(("lookups", "void", "expected"), [(9, 0, None), (10, 0, Severity.LOW), (11, 0, Severity.MEDIUM), (5, 2, None), (5, 3, Severity.MEDIUM)])
def test_spf_lookup_limit_thresholds(lookups, void, expected):
    g = Graph(noise_check=False)
    domain(g, "lookups.example", spf="v=spf1 include:x.example -all", spf_status="ok", spf_lookups=lookups, spf_void_lookups=void)
    out = run_rules(g, [], only={"spf_lookup_limit"}, rctx=rctx())
    assert [c.severity for c in out] == ([expected] if expected else [])
    assert (es.SPF_MAX_LOOKUPS, es.SPF_MAX_VOID_LOOKUPS) == (10, 2)


def test_dmarc_report_authorization_false_fires_and_null_is_could_not_verify():
    g = Graph(noise_check=False)
    node = domain(g, "acme-corp.example", dmarc="v=DMARC1; p=reject; rua=mailto:a@vendor.example", dmarc_policy="reject",
                  dmarc_rua_external=[{"dest_domain": "vendor.example", "authorized": None}])
    assert run_rules(g, [], only={"dmarc_reports_external_unauthorized"}, rctx=rctx()) == []
    node.attributes["dmarc_rua_external"] = [([{"dest_domain": "vendor.example", "authorized": False}, {"dest_domain": "slow.example", "authorized": None}], P)]
    [corr] = run_rules(g, [], only={"dmarc_reports_external_unauthorized"}, rctx=rctx())
    assert corr.severity is Severity.LOW and "acme-corp.example._report._dmarc.vendor.example" in " ".join(corr.evidence)
    assert "Could not verify: slow.example" in corr.description and "INFO in the terminal" in corr.description


# ------------------------------------------------------------------ cond 3: vocab-only inputs, no network
def test_inputs_are_vocabulary_attributes_declared_by_the_pack_fragment():
    vocab.reload()
    # core and pack-declared inputs; 'spf_status' and 'email_posture' are declared by their producer
    # (the e-mail posture module batch), so a core tree without that batch does not know them yet
    inputs = ("spf", "spf_lookups", "spf_void_lookups", "dmarc", "dmarc_policy", "dmarc_pct", "dmarc_sp", "dmarc_rua_external", "mx")
    assert all(vocab.is_known_attribute(name) for name in inputs)
    source = inspect.getsource(es)
    for name in ("spf_lookups", "spf_void_lookups", "dmarc_pct", "dmarc_sp", "dmarc_rua_external"):
        assert f'"{name}"' in source
    import json

    fragment = json.loads((Path(vocab.FRAGMENT_DIR) / "pack_email_spoofing.json").read_text(encoding="utf-8"))
    assert {"spf_lookups", "spf_void_lookups", "dmarc_pct", "dmarc_sp", "dmarc_rua_external"} <= set(fragment["attributes"])


def test_pack_rules_make_no_network_call(monkeypatch):
    import requests

    def refuse(*a, **k):
        raise AssertionError("a correlation rule tried to use the network")

    monkeypatch.setattr(requests.Session, "request", refuse)
    import socket  # below requests too: no socket, no name resolution

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    for rid in PACK_RULES:
        for path in sorted((FIXTURES / rid).glob("*.json")):
            fx = load_graph_fixture(path)
            run_rules(fx.graph, fx.results, only=set(PACK_RULES), rctx=fx.rctx)
    assert not {rid: correlate.RULE_ERRORS[rid] for rid in PACK_RULES if rid in correlate.RULE_ERRORS}


# ------------------------------------------------------------------ cond 4: DMARC discovery via the organisational domain
def test_subdomain_inherits_the_organisational_sp_tag():
    org_record = "v=DMARC1; p=reject; sp=none"
    g = Graph(noise_check=False)
    org = domain(g, "acme-corp.example", spf="v=spf1 -all", spf_status="ok", dmarc=org_record, dmarc_policy="reject", dmarc_sp="none", dmarc_pct=100)
    sub = domain(g, "news.acme-corp.example", spf_status="none", dmarc=org_record, dmarc_policy="none", dmarc_sp="none", dmarc_pct=100,
                 email_posture={"spf": "absent", "dmarc": "p=none (organisational domain acme-corp.example)"})
    out = {(c.entity_keys()[0], c.key): c for c in cr01(g)}
    assert set(out) == {(org.key, "subdomains"), (sub.key, "name")}
    assert "sp=none" in out[(org.key, "subdomains")].title
    # an org with p=reject (sp inherits p) protects a subdomain without its own record
    g2 = Graph(noise_check=False)
    domain(g2, "acme-corp.example", spf="v=spf1 -all", spf_status="ok", dmarc="v=DMARC1; p=reject", dmarc_policy="reject", dmarc_sp="reject")
    domain(g2, "news.acme-corp.example", spf_status="none", dmarc="v=DMARC1; p=reject", dmarc_policy="reject", dmarc_sp="reject")
    assert cr01(g2) == []


# ------------------------------------------------------------------ cond 6: rule 5
@pytest.mark.parametrize("attrs", [
    {"spf_status": "could_not_verify", "email_posture": {"spf": "could not verify", "dmarc": "could not verify"}},
    {"spf_status": "temperror", "email_posture": {"spf": "present; include chain could not be verified", "dmarc": "absent"}},
    {"spf_status": "ok", "spf": "v=spf1 ~all", "email_posture": {"dmarc": "could not verify"}},
    {"spf_status": "none", "email_posture": {"spf": "absent"}},  # DMARC never checked: unknown, not missing
    {},
])
def test_could_not_verify_never_reads_missing(attrs):
    g = Graph(noise_check=False)
    domain(g, "unverified.example", **attrs)
    assert run_rules(g, [], only=set(PACK_RULES), rctx=rctx()) == []


# ------------------------------------------------------------------ cond 7: ownership scoping
WEAK = merged(spf_attrs("~all"), dmarc_attrs("none"))


def test_high_for_seeds_verified_org_domains_and_the_phishing_sender_low_for_pivots():
    org = OrgProfile.from_dict({"org": {"name": "Acme"}, "domains": [{"name": "acme-corp.example", "verification": "txt_verified"},
                                                                       {"name": "acme-seeded.example", "verification": "seeded"}]})
    g = Graph(noise_check=False)
    seed = domain(g, "typed.example", **WEAK)
    own = domain(g, "mail.acme-corp.example", seed=False, depth=1, **WEAK)
    seeded = domain(g, "acme-seeded.example", seed=False, depth=1, **WEAK)
    msg, _ = g.add_node(Entity.make("email", "billing@sender-corp.example"), 0, seed=True)
    sender = domain(g, "sender-corp.example", seed=False, depth=1, **WEAK)
    g.add_edge(msg.entity, sender.entity, "email_domain", "email_basics")
    pivot = domain(g, "pivot.example", seed=False, depth=1, **WEAK)
    deep = domain(g, "deep.example", seed=False, depth=2, **WEAK)
    sev = {c.entity_keys()[0]: c.severity for c in cr01(g, org=org)}
    assert sev == {seed.key: Severity.HIGH, own.key: Severity.HIGH, sender.key: Severity.HIGH, seeded.key: Severity.LOW, pivot.key: Severity.LOW}
    assert deep.key not in sev  # omitted at depth >= 2


def test_unconfirmed_seeds_and_attacker_domains():
    g = Graph(noise_check=False)
    extracted = domain(g, "from-text.example", **WEAK)
    attacker = domain(g, "acme-login.example", **WEAK)
    g.add_finding(Finding(title="phish", severity=Severity.HIGH, criterion="feed", tags=["phishing"], entity=attacker.entity, module="url_domain_blocklists"))
    out = cr01(g, options=ScanOptions(unconfirmed_seeds={extracted.key}))
    assert [(c.entity_keys()[0], c.severity) for c in out] == [(extracted.key, Severity.LOW)]  # not analyst-typed; attacker skipped


def test_sender_domain_of_an_analysed_email_is_high():
    g = Graph(noise_check=False)
    headers, _ = g.add_node(Entity.make("text_blob", "Received: from mx.sender.example ..."), 0, seed=True)
    sender = domain(g, "sender.example", seed=False, depth=1, **WEAK)
    g.add_edge(headers.entity, sender.entity, "sender_domain", "email_header_analyzer")
    [corr] = cr01(g)
    assert corr.severity is Severity.HIGH and "sending domain of the phishing case" in " ".join(corr.evidence)


# ------------------------------------------------------------------ cond 8: non-sending domains
@pytest.mark.parametrize("mx", [{"mx": ["."]}, {"email_posture": {"mx": "null MX (no mail)"}}, {"email_posture": {"mx": "none (implicit MX)"}}])
def test_non_sending_domains_are_medium_with_the_specific_advice(mx):
    g = Graph(noise_check=False)
    attrs = merged(spf_attrs("missing"), dmarc_attrs("missing"), {k: v for k, v in mx.items() if k == "email_posture"})
    seed = domain(g, "no-mail.example", **attrs)
    pivot = domain(g, "no-mail-pivot.example", seed=False, depth=1, **attrs)
    if "mx" in mx:
        for node in (seed, pivot):
            node.attributes["mx"] = [(mx["mx"], "dns_records")]
    sev = {c.entity_keys()[0]: c for c in cr01(g)}
    assert sev[seed.key].severity is Severity.MEDIUM and sev[pivot.key].severity is Severity.LOW
    assert sev[seed.key].recommendation == es.NON_SENDING_ADVICE == "no mail service: publish v=spf1 -all, a null MX and DMARC p=reject"
    assert "publish SPF: v=spf1 -all" in sev[seed.key].evidence and "publish DMARC: v=DMARC1; p=reject" in sev[seed.key].evidence


# ------------------------------------------------------------------ cond 9: observed record, record to publish, criterion, ATT&CK
def test_findings_show_observed_and_published_records_criterion_and_attack():
    g = Graph(noise_check=False)
    domain(g, "acme-mail.example", **merged(WEAK, {"spf_lookups": 11, "spf_void_lookups": 0,
                                                   "dmarc_rua_external": [{"dest_domain": "vendor.example", "authorized": False}]}))
    out = run_rules(g, [], only=set(PACK_RULES), rctx=rctx())
    assert {c.rule for c in out} == set(PACK_RULES)
    for corr in out:
        assert corr.criterion and corr.attack == ["T1566", "T1684.001"]
        assert any(line.startswith("observed ") for line in corr.evidence)
        assert any(line.startswith("publish") for line in corr.evidence)
    cr01_corr = next(c for c in out if c.rule == "spoofable_email_domain")
    assert "observed SPF: v=spf1 include:_spf.mail.example ~all" in cr01_corr.evidence
    assert any(line.startswith("publish SPF: an SPF record within 10 DNS lookups") for line in cr01_corr.evidence)  # permerror (11 lookups)
    g2 = Graph(noise_check=False)
    domain(g2, "acme-mail.example", **WEAK)
    [plain] = cr01(g2)
    assert "publish SPF: v=spf1 include:_spf.mail.example -all" in plain.evidence
    assert "observed DMARC: v=DMARC1; p=none" in plain.evidence
    assert plain.criterion == "DMARC p=none and SPF ~all (verified answers)"


def test_thresholds_are_named_constants():
    assert es.DMARC_FULL_PCT == 100 and es.OMIT_DEPTH == 2
    assert sorted(es.ENFORCING_POLICIES) == ["quarantine", "reject"] and sorted(es.WEAK_ALL) == ["+all", "?all", "~all"]
    assert es.SPOOFING_ATTACK == ("T1566", "T1684.001")


def test_no_address_and_no_mx_is_non_sending():
    g = Graph(noise_check=False)
    node = domain(g, "unused-brand.example", **merged(spf_attrs("missing"), dmarc_attrs("missing")))
    node.attributes["email_posture"] = [({"spf": "absent", "dmarc": "absent"}, P)]
    g.add_finding(Finding(title="No web-facing address (no A/AAAA/CNAME)", severity=Severity.INFO, entity=node.entity, module="dns_records",
                          criterion="NOERROR answers without A, AAAA or CNAME records", tags=["info"]))
    [corr] = cr01(g)
    assert corr.severity is Severity.MEDIUM and corr.recommendation == es.NON_SENDING_ADVICE
    node.attributes["mx"] = [(["mx.unused-brand.example"], "dns_records")]  # it receives mail: a mail domain
    [corr2] = cr01(g)
    assert corr2.severity is Severity.HIGH


# ------------------------------------------------------------------ review additions (WP23 review)
def test_an_unevaluated_include_chain_is_could_not_verify_even_with_a_readable_top_record():
    """Cond 6: 'an unevaluated SPF chain means could not verify and the rule must not fire' - a
    temperror include chain never feeds CR01, even when the top record ends in ~all; a lookup count
    already above the limit is still permerror (the count is a lower bound past it)."""
    chain = {"spf_status": "temperror", "spf": "v=spf1 include:_spf.flaky.example ~all",
             "email_posture": {"spf": "present; include chain could not be verified (~all)"}}
    g = Graph(noise_check=False)
    node = domain(g, "chain.example", **merged(chain, dmarc_attrs("none")))
    assert run_rules(g, [], only=set(PACK_RULES), rctx=rctx()) == []
    assert es.spf_state(node).known is False
    node.attributes["spf_lookups"] = [(12, P)]
    out = {c.rule: c for c in run_rules(g, [], only=set(PACK_RULES), rctx=rctx())}
    assert out["spoofable_email_domain"].severity is Severity.HIGH and "permerror" in out["spoofable_email_domain"].title
    assert out["spf_lookup_limit"].severity is Severity.MEDIUM


def test_a_name_that_does_not_exist_is_non_sending():
    g = Graph(noise_check=False)
    gone = domain(g, "gone.example", **merged(spf_attrs("missing"), {"email_posture": {"spf": "absent", "dmarc": "absent", "mx": "NXDOMAIN"}}))
    [corr] = cr01(g)
    assert corr.severity is Severity.MEDIUM and corr.recommendation == es.NON_SENDING_ADVICE
    g2 = Graph(noise_check=False)
    gone2 = domain(g2, "gone2.example", **merged(spf_attrs("missing"), dmarc_attrs("missing")))
    gone2.attributes["valid"] = [(False, "dns_records")]  # NXDOMAIN confirmed by a second resolver
    [corr2] = cr01(g2)
    assert corr2.severity is Severity.MEDIUM and gone.key != gone2.key


def test_an_org_profile_domain_tagged_by_a_feed_is_still_judged_attacker_domains_are_not():
    org = OrgProfile.from_dict({"org": {"name": "Acme"}, "domains": [{"name": "acme-corp.example", "verification": "txt_verified"}]})
    g = Graph(noise_check=False)
    own = domain(g, "acme-corp.example", **WEAK)
    lookalike = domain(g, "acme-c0rp.example", **WEAK)
    for node in (own, lookalike):
        g.add_finding(Finding(title="phish", severity=Severity.HIGH, criterion="feed", tags=["phishing"], entity=node.entity, module="url_domain_blocklists"))
    assert [(c.entity_keys()[0], c.severity) for c in cr01(g, org=org)] == [(own.key, Severity.HIGH)]


def test_a_subdomain_without_a_record_inherits_the_organisational_record_from_the_graph():
    """Cond 4 in the rule itself: when a producer only reports a verified absence at _dmarc.<sub>,
    the organisational domain's record in the graph applies (its sp=, default p=)."""
    absent_sub = merged(spf_attrs("missing"), {"email_posture": {"spf": "absent", "dmarc": "absent", "mx": "mx.acme-corp.example"}})
    g = Graph(noise_check=False)
    domain(g, "acme-corp.example", spf="v=spf1 -all", spf_status="ok", dmarc="v=DMARC1; p=reject", dmarc_policy="reject", dmarc_sp="reject")
    sub = domain(g, "news.acme-corp.example", **absent_sub)
    assert cr01(g) == []
    state = es.dmarc_state(sub, g)
    assert state.policy == "reject" and state.inherited_from == "acme-corp.example" and es.dmarc_state(sub).missing
    g2 = Graph(noise_check=False)
    domain(g2, "acme-corp.example", spf="v=spf1 -all", spf_status="ok", dmarc="v=DMARC1; p=reject; sp=none", dmarc_policy="reject", dmarc_sp="none")
    sub2 = domain(g2, "news.acme-corp.example", **absent_sub)
    named = {(c.entity_keys()[0], c.key): c for c in cr01(g2)}
    assert "(organisational domain acme-corp.example)" in named[(sub2.key, "name")].title


def test_cr03_is_low_in_the_case_and_info_for_the_terminal():
    g = Graph(noise_check=False)
    domain(g, "acme-mail.example", dmarc_rua_external=[{"dest_domain": "vendor.example", "authorized": False}])
    [corr] = run_rules(g, [], only={"dmarc_reports_external_unauthorized"}, rctx=rctx())
    assert corr.severity is Severity.LOW and es.TERMINAL_SEVERITY[corr.rule] is Severity.INFO
