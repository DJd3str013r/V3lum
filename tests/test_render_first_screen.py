"""AR14 / P328 cond 7 / P302 cond 6 / P311 / A2: the terminal's first screen is honest.

The header carries the TLP label and the 'N of M applicable sources answered; K could not verify'
line; the merge order is header -> bottom line -> attention -> correlations -> findings; skip reasons
are one line each; readings say 'inconclusive' / 'no findings', never 'clean'; at AMBER links are
non-clickable text with the disclosure warning and at RED third-party links are hidden.
"""

from __future__ import annotations

import io
import re
import sys
import types

import pytest
from rich.console import Console

import v3lum.core
from tests.fakes import define_module, make_runtime
from v3lum.core import http
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.models import Severity
from v3lum.ui.live import LiveFeed
from v3lum.ui.render import MAX_HEADER_SEEDS, MAX_LINKS_PER_SEED, render_case, render_single
from v3lum.ui.theme import THEME, make_console

SEED = "ipv4:203.0.113.10"


def _render(case: dict, *, width: int = 240, **kw) -> str:
    console = make_console(no_color=True, width=width)
    with console.capture() as cap:
        render_case(console, case, **kw)
    return cap.get()


def _base(**extra) -> dict:
    case = {
        "schema": "v3lum.case/2", "case_id": "20261126-130000-scrn", "tlp": "amber", "seeds": [SEED],
        "inputs": [{"type": "ipv4", "value": "203.0.113.10", "confidence": 1.0, "reason": "IPv4 address"}],
        "options": {"mode": "passive", "depth": 1},
        "summary": {"entities": 1, "findings": 0, "module_runs": 3, "requests": 2, "duration": 1.0},
        "risk": {"score": 0.0, "level": "clean", "entities": {}, "top": []},
        "entities": [{"key": SEED, "type": "ipv4", "value": "203.0.113.10", "depth": 0, "seed": True, "tags": [],
                      "attributes": {"asn": [{"value": "AS64500", "source": "asn_mod"}], "country": [{"value": "BR", "source": "asn_mod"}]}}],
        "edges": [], "findings": [], "correlations": [],
        "modules": [{"module": "rep_a", "entity": SEED, "status": "ok", "hosts": {"dns.google": 1}}],
        "coverage": {},
        "answered": {SEED: {"applicable": 3, "answered": 2, "could_not_verify": 1,
                            "sources": [{"module": "rep_a", "source": "", "status": "ok", "reason_code": ""},
                                        {"module": "rep_b", "source": "", "status": "empty", "reason_code": ""},
                                        {"module": "rep_c", "source": "", "status": "blocked", "reason_code": "challenge"}],
                            "reputation_applicable": 3, "reputation_answered": 2}},
        "skips": {}, "links": {}, "timeline": [], "notes": [], "meta": {},
    }
    case.update(extra)
    return case


def _fake_attention(monkeypatch, points=("ATTENTION-POINT-ONE",), limits=("LIMITATION-ONE",)):
    """Install a stand-in for core.attention (WP16) so the test does not depend on its wording."""
    fake = types.ModuleType("v3lum.core.attention")
    fake.attention_points = lambda case: list(points)
    fake.limitations = lambda case: list(limits)
    monkeypatch.setitem(sys.modules, "v3lum.core.attention", fake)
    monkeypatch.setattr(v3lum.core, "attention", fake, raising=False)


# ---------------------------------------------------------------------------------------- header


def test_header_carries_tlp_label_and_answered_line():
    out = _render(_base())
    assert "TLP:AMBER" in out.splitlines()[0]  # in the panel title
    assert "2 of 3 applicable sources answered; 1 could not verify (rep_c: challenge)" in out
    assert "value disclosed to 1 third-party provider" in out and "Google Public DNS" in out
    assert "mode passive · egress default route" in out
    assert out.rstrip().splitlines()[-1].lstrip().startswith("TLP:AMBER")  # footer marking


@pytest.mark.parametrize("tlp,label", [("clear", "TLP:CLEAR"), ("green", "TLP:GREEN"), ("amber+strict", "TLP:AMBER+STRICT"), ("red", "TLP:RED"), ("bogus", "TLP:RED")])
def test_header_tlp_label_is_generated_from_the_case(tlp, label):
    assert label in _render(_base(tlp=tlp)).splitlines()[0]


def test_tlp_label_uses_its_tlp_colour(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)  # the suite runs with NO_COLOR=1
    buf = io.StringIO()
    console = Console(file=buf, width=200, force_terminal=True, color_system="truecolor", theme=THEME)
    render_case(console, _base(tlp="red"))
    assert "255;43;43" in buf.getvalue()  # FIRST TLP 2.0 red #FF2B2B
    buf = io.StringIO()
    console = Console(file=buf, width=200, force_terminal=True, color_system="truecolor", theme=THEME)
    render_case(console, _base(tlp="amber"))
    assert "255;192;0" in buf.getvalue()  # TLP 2.0 amber #FFC000


def test_partial_results_go_to_the_header_not_to_the_end():
    note = "scan deadline (global timeout 90s) reached: partial results (4 pending source run(s) SKIPPED 'deadline')"
    out = _render(_base(partial={"deadline": True}, notes=[note, "entity budget reached (150); raise --max-entities to go further"]))
    header = out[: out.index("bottom line")]
    assert "PARTIAL RESULT: scan deadline (global timeout 90s) reached" in header
    assert "PARTIAL RESULT: entity budget reached (150)" in header
    assert "[!] scan deadline" not in out  # not repeated among the closing notes


def test_purpose_ticket_legal_basis_and_header_notes_are_shown():
    case = _base(meta={"header_notes": ["TLS interception detected: CorpProxy CA"]})
    case["options"].update(purpose="incident 42 triage", ticket="INC-42", legal_basis="legitimate_interest")
    out = _render(case)
    assert "purpose: incident 42 triage · ticket: INC-42 · legal basis: legitimate_interest" in out
    assert "TLS interception detected: CorpProxy CA" in out[: out.index("bottom line")]


def test_header_caps_a_batch_of_inputs_unless_full():
    seeds = [f"ipv4:203.0.113.{i}" for i in range(1, 15)]
    case = _base(seeds=seeds, inputs=[{"type": "ipv4", "value": s.partition(":")[2], "confidence": 1.0, "reason": "IPv4"} for s in seeds], answered={})
    out = _render(case)
    header = out[: out.index("bottom line")]
    assert "+4 more inputs (--full or the HTML report)" in header
    assert header.count("· reading: inconclusive") == MAX_HEADER_SEEDS  # one answered line per shown seed
    assert "+4 more inputs: 0 of 0 applicable sources answered; 0 could not verify · 4 inconclusive" in header
    full = _render(case, full=True)
    full_header = full[: full.index("bottom line")]
    assert full_header.count("· reading: inconclusive") == 14 and "more inputs" not in full_header


# ---------------------------------------------------------------------------------------- order


def test_merge_order_header_bottom_line_attention_correlations_findings(monkeypatch):
    _fake_attention(monkeypatch)
    case = _base(
        risk={"score": 70.0, "level": "high", "entities": {SEED: {"score": 70.0, "level": "high"}}, "top": [{"entity": SEED, "score": 70.0, "level": "high"}]},
        findings=[{"id": "f1", "title": "FINDING-TITLE-HIGH", "severity": "high", "confidence": 0.9, "confidence_label": "confirmed",
                   "criterion": "listed by two feeds", "entity": SEED, "module": "rep_a", "tags": ["malicious"]}],
        correlations=[{"id": "c1", "rule": "multi_source_malicious", "title": "CORRELATION-TITLE", "severity": "high", "confidence": 0.8,
                       "entities": [SEED], "recommendation": "Block 203.0.113.10 at the perimeter", "description": ""}],
        skips={"not_default": ["opt_a"]},
        coverage={"rep_a": {"status": "ok"}, "rep_c": {"status": "blocked", "reason_code": "challenge", "reason": "anti-bot page"}},
        links={SEED: [{"label": "Shodan host", "url": "https://www.shodan.io/host/203.0.113.10", "host": "www.shodan.io", "category": "reputation", "verified": True}]},
        notes=["CLOSING-NOTE"],
    )
    out = _render(case)
    marks = ["TLP:AMBER", "bottom line", "What it is:", "ATTENTION-POINT-ONE", "LIMITATION-ONE", "cross-referenced intelligence",
             "CORRELATION-TITLE", "⚑ findings", "FINDING-TITLE-HIGH", "1 opt-in source not run (use --preset deep)", "source coverage",
             "manual pivots", "CLOSING-NOTE"]
    positions = []
    for m in marks:  # each marker searched after the previous one: the order of the sections
        positions.append(out.index(m, positions[-1] if positions else 0))
    assert out.index("ATTENTION-POINT-ONE") > out.index("Next step:")  # attention after the whole bottom line
    assert out.index("cross-referenced intelligence") > out.index("LIMITATION-ONE")
    assert out.index("⚑ findings") > out.index("cross-referenced intelligence")
    assert "Next step: Block 203.0.113.10 at the perimeter" in out  # the highest recommendation


def test_bottom_line_has_three_lines_what_why_next():
    case = _base(
        risk={"score": 62.0, "level": "high", "entities": {SEED: {"score": 62.0, "level": "high"}},
              "contributors": [{"finding_id": "f1", "entity": SEED, "confidence_label": "probable", "weight": 0.49, "words": "listed as a botnet C2 by Feodo Tracker"}]},
        findings=[{"id": "f1", "title": "Feodo C2", "severity": "high", "confidence": 0.7, "entity": SEED, "module": "rep_a", "tags": ["c2"]}],
    )
    out = _render(case)
    block = out[out.index("bottom line"): out.index("bottom line") + 1200]
    assert "What it is: ipv4 203[.]0[.]113[.]10 - asn AS64500; country BR" in block  # c2-tagged: defanged
    assert "Why: HIGH 62/100 (triage aid, not a conclusion) - listed as a botnet C2 by Feodo Tracker [PROBABLE]" in block
    assert "Next step:" in block


# ---------------------------------------------------------------------------------------- skips


def test_one_line_per_skip_reason():
    case = _base(skips={"licence": ["shodan_internetdb", "abusech"], "not_default": ["a", "b", "c"], "needs_key": ["vt"], "own_asset": ["hibp_domain"]},
                 meta={"quota_lines": ["HackerTarget: 50/50 today, 12 lookups deferred"]})
    out = _render(case)
    expected = [
        "2 sources skipped: licence profile corporate - v3lum doctor --licences",
        "3 opt-in sources not run (use --preset deep)",
        "1 source needs an API key: v3lum keys",
        "1 own-asset module needs a verified org profile: v3lum org",
        "HackerTarget: 50/50 today, 12 lookups deferred",
    ]
    for line in expected:
        assert out.count(line) == 1, line
    positions = [out.index(line) for line in expected]
    assert positions == sorted(positions)


def test_coverage_lists_reason_codes_per_status():
    case = _base(coverage={
        "rep_a": {"status": "ok"}, "rep_b": {"status": "empty"}, "rep_c": {"status": "blocked", "reason_code": "challenge", "reason": "anti-bot page"},
        "otx": {"status": "quota", "reason_code": "quota", "reason": "daily budget"},
        "agg": {"status": "ok", "sources": {"agg.feed1": {"status": "rate_limited", "reason_code": "rate_limited", "reason": "429"}}},
        "skipped_a": {"status": "skipped", "reason_code": "licence"}, "skipped_b": {"status": "skipped", "reason_code": "not_default"},
    })
    out = _render(case)
    assert "quota (1)" in out and "otx [quota: daily budget]" in out
    assert "blocked (1)" in out and "rep_c [challenge: anti-bot page]" in out
    assert "licence: skipped_a; not_default: skipped_b" in out
    assert "agg/agg.feed1 [rate_limited]" in out


def test_coverage_shows_status_counts_when_outcomes_differ():
    """P328 cond 3: blocked on the seed and empty on a pivot reads blocked, with the counts."""
    case = _base(coverage={"rep_c": {"status": "blocked", "reason_code": "challenge", "reason": "anti-bot page",
                                     "counts": {"empty": 2, "blocked": 1}, "entities": {}},
                           "rep_a": {"status": "ok", "counts": {"ok": 3}}})
    out = _render(case)
    assert "rep_c [challenge: anti-bot page] (blocked 1 · empty 2)" in out
    assert "rep_a (" not in out  # a single outcome needs no counts


# ---------------------------------------------------------------------------------------- readings


def test_inconclusive_below_two_reputation_answers_and_never_clean():
    case = _base()
    case["answered"][SEED]["reputation_answered"] = 1
    out = _render(case)
    assert "reading: inconclusive (reputation sources answered: 1; at least 2 needed)" in out
    assert "INCONCLUSIVE" in out  # the score bar
    assert "Why: inconclusive - fewer than 2 reputation sources answered" in out
    assert "clean" not in out.lower()


def test_no_findings_with_enough_reputation_answers():
    out = _render(_base())
    assert "reading: no findings" in out and "NO FINDINGS" in out
    assert "Why: no findings - 2 of 3 applicable sources answered and none reported a risk signal" in out
    assert "clean" not in out.lower()


def test_inconclusive_never_hides_a_scored_level():
    case = _base(risk={"score": 60.0, "level": "high", "entities": {SEED: {"score": 60.0, "level": "high"}}})
    case["answered"][SEED]["reputation_answered"] = 0
    out = _render(case)
    assert "reading: inconclusive" in out and "highest scored level high" in out and "HIGH" in out


def test_v1_case_with_clean_level_reads_inconclusive():
    v1 = {
        "schema": "v3lum.case/1", "case_id": "20250101-000000-beef", "created": "2025-01-01T00:00:00+00:00", "inputs": [],
        "seeds": ["domain:evil.example"], "options": {"mode": "passive"},
        "summary": {"risk_score": 0.0, "risk_level": "clean", "entities": 1, "findings": 0, "correlations": 0},
        "risk": {"score": 0.0, "level": "clean"},
        "entities": [{"key": "domain:evil.example", "type": "domain", "value": "evil.example", "display": "evil.example", "depth": 0, "seed": True, "attributes": {}, "findings": []}],
        "edges": [], "findings": [], "correlations": [], "modules": [], "coverage": {}, "links": {}, "timeline": [], "notes": [],
    }
    out = _render(v1)
    assert "TLP:AMBER" in out and "inconclusive" in out
    assert "clean" not in out.lower()


def test_engine_case_where_nothing_answered_never_prints_clean(clean_registry):
    def blocked(self, entity, ctx):
        raise http.Blocked("anti-bot challenge", 403, reason_code="challenge")

    mod = define_module("t_first_blocked", ["domain"], blocked, tags={"reputation"})
    case = Engine(make_runtime(), ScanOptions(include={mod.name}, save_evidence=False)).investigate([Entity.make("domain", "example.com")]).to_dict()
    out = _render(case)  # the wave-2 engine note names the v1 level ('clean'): the terminal never prints it
    assert "clean" not in out.lower()
    assert "0 of 1 applicable sources answered; 1 could not verify (t_first_blocked: challenge)" in out
    assert "reading: inconclusive" in out


def test_engine_answered_line_counts_reputation_sources(clean_registry):
    def ok(self, entity, ctx):
        res = self.result(entity)
        res.attr("country", "US")
        return res

    def empty(self, entity, ctx):
        return self.result(entity).mark("empty")

    def quota(self, entity, ctx):
        raise http.QuotaExceeded("daily budget used up", 429)

    names = [define_module(n, ["domain"], fn, tags={"reputation"}).name for n, fn in (("t_rep_ok", ok), ("t_rep_empty", empty), ("t_rep_quota", quota))]
    case = Engine(make_runtime(), ScanOptions(include=set(names), save_evidence=False)).investigate([Entity.make("domain", "example.com")]).to_dict()
    out = _render(case)
    assert "2 of 3 applicable sources answered; 1 could not verify (t_rep_quota: quota)" in out
    assert "reading: no findings" in out and "clean" not in out.lower()


# ---------------------------------------------------------------------------------------- findings


def test_confidence_label_on_every_finding_and_criterion_for_high():
    case = _base(findings=[
        {"id": "f1", "title": "HIGH-ONE", "severity": "high", "confidence": 0.9, "criterion": "CRITERION-HIGH", "entity": SEED, "module": "m"},
        {"id": "f2", "title": "LOW-ONE", "severity": "low", "confidence": 0.6, "criterion": "CRITERION-LOW", "entity": SEED, "module": "m"},
        {"id": "f3", "title": "MEDIUM-ONE", "severity": "medium", "confidence_label": "possible", "confidence": 0.4, "criterion": "POSSIBLE - on warninglist x", "entity": SEED, "module": "m"},
    ])
    out = _render(case)
    rows = {t: next(line for line in out.splitlines() if t in line) for t in ("HIGH-ONE", "LOW-ONE", "MEDIUM-ONE")}
    assert "CONFIRMED" in rows["HIGH-ONE"] and "PROBABLE" in rows["LOW-ONE"] and "POSSIBLE" in rows["MEDIUM-ONE"]
    assert "criterion: CRITERION-HIGH" in out
    assert "CRITERION-LOW" not in out  # criterion only for HIGH/CRITICAL on the first screen
    assert "CRITERION-LOW" in _render(case, full=True)


def test_possible_identity_links_never_in_the_top_findings():
    case = _base(
        findings=[{"id": "f9", "title": "IDENTITY-SAME-HANDLE", "severity": "medium", "confidence": 0.4, "confidence_label": "possible",
                   "criterion": "same handle does not prove identity", "entity": SEED, "module": "u", "tags": ["identity"]}],
        correlations=[{"id": "c9", "rule": "identity_link_strength", "title": "IDENTITY-CORRELATION", "severity": "low", "confidence_label": "possible", "confidence": 0.4, "entities": [SEED]}],
    )
    out = _render(case)
    assert "IDENTITY-SAME-HANDLE" not in out and "IDENTITY-CORRELATION" not in out
    assert "1 possible identity link(s) not listed here" in out


def test_engine_findings_show_labels(clean_registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.finding("Listed as C2", Severity.HIGH, criterion="two feeds agree", confidence="probable", tags=("c2",))
        return res

    mod = define_module("t_first_finding", ["domain"], run)
    case = Engine(make_runtime(), ScanOptions(include={mod.name}, save_evidence=False)).investigate([Entity.make("domain", "example.com")]).to_dict()
    out = _render(case)
    row = next(line for line in out.splitlines() if "Listed as C2" in line)
    assert "PROBABLE" in row and "criterion: two feeds agree" in out


# ---------------------------------------------------------------------------------------- manual pivots


def _links(n: int = 3, **item) -> list[dict]:
    base = [
        {"label": "Shodan host", "url": "https://www.shodan.io/host/203.0.113.10", "host": "www.shodan.io", "category": "reputation", "verified": True},
        {"label": "OTX", "url": "https://otx.alienvault.com/indicator/ip/203.0.113.10", "host": "otx.alienvault.com", "category": "reputation", "verified": True},
        {"label": "urlscan", "url": "https://urlscan.io/ip/203.0.113.10", "host": "urlscan.io", "category": "history", "verified": True},
    ]
    out = base[:n]
    if item:
        out.append(item)
    return out


def test_amber_renders_links_as_non_clickable_text():
    out = _render(_base(links={SEED: _links()}))
    assert "opening sends 203.0.113.10 to www.shodan.io" in out
    assert "hxxps://www[.]shodan[.]io/host/203.0.113.10" in out
    assert "https://www.shodan.io" not in out
    assert "not clickable at TLP:AMBER" in out
    buf = io.StringIO()  # and no terminal hyperlink is emitted on a real terminal
    render_case(Console(file=buf, width=220, force_terminal=True, color_system="truecolor", theme=THEME), _base(links={SEED: _links()}))
    assert "\x1b]8;" not in buf.getvalue()


def test_clear_renders_clickable_links():
    out = _render(_base(tlp="clear", links={SEED: _links()}))
    assert "https://www.shodan.io/host/203.0.113.10" in out and "opening sends" not in out
    buf = io.StringIO()
    render_case(Console(file=buf, width=220, force_terminal=True, color_system="truecolor", theme=THEME), _base(tlp="clear", links={SEED: _links()}))
    assert "\x1b]8;" in buf.getvalue() and "https://www.shodan.io/host/203.0.113.10" in buf.getvalue()


def test_red_hides_third_party_links():
    out = _render(_base(tlp="red", links={SEED: _links()}))
    assert "shodan" not in out.lower() and "otx.alienvault" not in out
    assert "3 third-party manual pivot(s) hidden at TLP:RED: only `v3lum links <input>` shows them" in out


def test_touches_target_links_are_defanged_with_a_warning_and_hidden_for_hostile_entities():
    fetch = {"label": "Live fetch", "url": "https://check.example.net/?url=203.0.113.10", "host": "check.example.net", "category": "other", "verified": True, "touches_target": True}
    out = _render(_base(tlp="clear", links={SEED: _links(1, **fetch)}))
    assert "hxxps://check[.]example[.]net/?url=203.0.113.10" in out and "opens the target" in out
    assert "https://check.example.net" not in out
    hostile = _base(tlp="clear", links={SEED: _links(1, **fetch)})
    hostile["entities"][0]["tags"] = ["malicious"]
    out = _render(hostile)
    assert "check[.]example[.]net" not in out and "1 target-contact link(s) hidden for hostile entities" in out
    assert "check[.]example[.]net" in _render(hostile, full=True)  # the analyst expands them


def _osc8_targets(case: dict) -> list[str]:
    buf = io.StringIO()
    render_case(Console(file=buf, width=240, force_terminal=True, color_system="truecolor", theme=THEME), case)
    return [m for m in re.findall(r"\x1b\]8;[^;]*;([^\x1b\x07]*)", buf.getvalue()) if m]


def test_a_link_to_the_investigated_host_is_never_clickable():
    """P311 cond 8: a module link (res.link, no declared host or touches_target) that opens the
    investigated target itself is defanged with the warning even at TLP:CLEAR."""
    own = {"label": "Admin page", "url": "https://203.0.113.10/admin"}
    case = _base(tlp="clear", links={SEED: _links(1, **own)})
    out = _render(case)
    assert "hxxps://203[.]0[.]113[.]10/admin" in out and "opens the target" in out
    assert "https://203.0.113.10/admin" not in out
    assert _osc8_targets(case) == ["https://www.shodan.io/host/203.0.113.10"]
    hostile = _base(tlp="clear", links={SEED: _links(1, **own)})
    hostile["entities"][0]["tags"] = ["c2"]
    out = _render(hostile)
    assert "203[.]0[.]113[.]10/admin" not in out and "1 target-contact link(s) hidden for hostile entities" in out
    assert "hxxps://203[.]0[.]113[.]10/admin" in _render(hostile, full=True)


def test_a_link_to_a_hostile_entity_of_the_case_is_never_clickable():
    case = _base(tlp="clear", links={SEED: _links(1, label="Panel", url="https://panel.evil.example/login")})
    case["entities"].append({"key": "domain:evil.example", "type": "domain", "value": "evil.example", "depth": 1, "seed": False, "tags": ["phishing"], "attributes": {}})
    assert "https://panel.evil.example/login" not in _osc8_targets(case)
    out = _render(case)
    assert "panel[.]evil[.]example" not in out and "1 target-contact link(s) hidden for hostile entities" in out
    full = _render(case, full=True)
    assert "hxxps://panel[.]evil[.]example/login" in full and "opens the target" in full


def test_amber_module_link_without_a_host_names_the_url_host():
    case = _base(links={SEED: [{"label": "Shodan", "url": "https://www.shodan.io/host/203.0.113.10"}]})
    assert "opening sends 203.0.113.10 to www.shodan.io" in _render(case)


def test_at_most_eight_links_per_seed_verified_first_grouped_by_question():
    links = []
    for i in range(12):
        links.append({"label": f"LINK-{i:02d}", "url": f"https://h{i}.example/203.0.113.10", "host": f"h{i}.example",
                      "category": "history" if i % 2 else "reputation", "verified": i >= 6, "badge": "" if i >= 6 else "unverified"})
    out = _render(_base(tlp="clear", links={SEED: links}))
    shown = [f"LINK-{i:02d}" for i in range(12) if f"LINK-{i:02d}" in out]
    assert len(shown) == MAX_LINKS_PER_SEED
    assert all(f"LINK-{i:02d}" in shown for i in range(6, 12))  # the six verified links come first
    assert "+4 more manual pivots" in out
    assert out.index("reputation") < out.index("history")
    assert "[unverified]" in out


def test_manual_fallback_links_show_their_note():
    item = {"label": "VirusTotal", "url": "https://www.virustotal.com/gui/ip-address/203.0.113.10", "host": "www.virustotal.com", "category": "reputation",
            "verified": True, "manual": True, "note": "automation skipped: licence", "module": "virustotal"}
    out = _render(_base(links={SEED: [item]}))
    assert "VirusTotal (automation skipped: licence)" in out


# ---------------------------------------------------------------------------------------- single run / live feed


def test_render_single_shows_reason_code_and_amber_links():
    console = make_console(no_color=True, width=200)
    with console.capture() as cap:
        render_single(console, {
            "module": "shodan_internetdb", "entity": SEED, "status": "blocked", "reason_code": "challenge", "error": "anti-bot page", "duration": 0.3,
            "findings": [{"title": "Open ports", "severity": "high", "confidence": 0.7, "criterion": "InternetDB answered"}],
            "attributes": {"open_ports": [22, 443]}, "pivots": [], "links": [{"label": "Shodan", "url": "https://www.shodan.io/host/203.0.113.10"}],
        })
    out = cap.get()
    assert "[blocked: challenge]" in out and "TLP:AMBER" in out and "PROBABLE" in out and "criterion: InternetDB answered" in out
    assert "opening sends 203.0.113.10 to www.shodan.io" in out and "https://www.shodan.io" not in out
    with console.capture() as cap:
        render_single(console, {"module": "m", "entity": SEED, "status": "ok", "duration": 0, "findings": [], "attributes": {}, "pivots": [],
                                "links": [{"label": "Shodan", "url": "https://www.shodan.io/host/203.0.113.10"}], "tlp": "red"})
    assert "shodan.io" not in cap.get() and "hidden at TLP:RED" in cap.get()


def test_render_single_never_makes_the_investigated_host_clickable():
    run = {"module": "m", "entity": "url:https://evil.example/x", "status": "ok", "duration": 0, "findings": [], "attributes": {}, "pivots": [],
           "links": [{"label": "Login", "url": "https://evil.example/login"}, {"label": "VT", "url": "https://www.virustotal.com/gui/url/x"}], "tlp": "clear"}
    buf = io.StringIO()
    render_single(Console(file=buf, width=220, force_terminal=True, color_system="truecolor", theme=THEME), run)
    raw = buf.getvalue()
    assert "\x1b]8;id=" in raw or "\x1b]8;;" in raw  # the third-party link stays clickable at CLEAR
    assert "https://evil.example/login" not in raw and "hxxps://evil[.]example/login" in raw and "opens the target" in raw
    hostile = dict(run, findings=[{"title": "phishing kit", "severity": "high", "tags": ["phishing"], "criterion": "c"}])
    console = make_console(no_color=True, width=200)
    with console.capture() as cap:
        render_single(console, hostile)
    assert "evil[.]example/login" not in cap.get() and "1 target-contact link(s) hidden for a hostile entity" in cap.get()


def test_live_feed_module_lines_show_reason_codes(clean_registry):
    def blocked(self, entity, ctx):
        raise http.Blocked("geo-blocked", 451, reason_code="geo_block")

    mod = define_module("t_live_geo", ["domain"], blocked)
    console = make_console(no_color=True, width=200)
    feed = LiveFeed(console, verbosity=1)
    rt = make_runtime()
    rt.events.subscribe(feed)
    with console.capture() as cap:
        Engine(rt, ScanOptions(include={mod.name}, save_evidence=False)).investigate([Entity.make("domain", "example.com")])
    out = cap.get()
    assert "t_live_geo → blocked (geo_block)" in out
    assert "TLP:AMBER" in out


def test_personal_entity_score_only_with_its_top_contributor():
    """P302 cond 10: the entity map never shows a bare score about a person."""
    email = "email:ana@corp.example"
    case = _base(
        seeds=[email], inputs=[{"type": "email", "value": "ana@corp.example", "confidence": 1.0, "reason": "e-mail"}], answered={},
        entities=[{"key": email, "type": "email", "value": "ana@corp.example", "depth": 0, "seed": True, "tags": [], "attributes": {}}],
        risk={"score": 41.0, "level": "medium", "entities": {email: {"score": 41.0, "level": "medium"}, SEED: {"score": 41.0, "level": "medium"}}},
        findings=[{"id": "f1", "title": "In 2 breaches (data classes only)", "severity": "medium", "confidence": 0.9, "criterion": "HIBP", "entity": email, "module": "hibp"}],
    )
    out = _render(case)
    tree = out[out.index("entity map"):]
    assert "[medium: In 2 breaches (data classes only)]" in tree
    assert "[medium 41]" not in tree
