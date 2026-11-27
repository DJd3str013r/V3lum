"""Reports v2 (WP20): TLP markings everywhere, honest first screen, licence/disclosure/engagement
sections, grouped rows, personal-data rules - HTML, Markdown, JSON, file names and the terminal.

Every case here is built by hand (v2 shape of ``CaseResult.to_dict()``); nothing depends on the
module-batch data fragments of ``v3lum/data``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from v3lum.report import FORMATS, report_name, write_reports
from v3lum.report import html as H
from v3lum.report import markdown as M
from v3lum.report import summary as S
from v3lum.ui.render import render_case
from v3lum.ui.theme import THEME

CASE_ID = "20261126-101500-ab12"
CPF = "52998224725"  # valid check digits (test value)


def base_case(**over: Any) -> dict[str, Any]:
    case: dict[str, Any] = {
        "schema": "v3lum.case/2",
        "tool": {"name": "V3LUM", "version": "2.0.0"},
        "case_id": CASE_ID,
        "created": "2026-11-26T10:15:00+00:00",
        "tlp": "amber",
        "inputs": [{"type": "domain", "value": "acme-target.example", "reason": "typed"}],
        "seeds": ["domain:acme-target.example"],
        "options": {"mode": "passive", "depth": 1},
        "summary": {"risk_score": 42.0, "risk_level": "medium", "entities": 1, "findings": 1, "correlations": 0, "module_runs": 1, "duration": 1.2},
        "risk": {"score": 42.0, "level": "medium", "entities": {"domain:acme-target.example": {"score": 42.0, "level": "medium"}}},
        "entities": [
            {"key": "domain:acme-target.example", "type": "domain", "value": "acme-target.example", "seed": True, "depth": 0, "sources": ["t_src"], "attributes": {}},
        ],
        "edges": [],
        "findings": [
            {"id": "f-dom-1", "title": "Domain registered 5 days ago", "severity": "medium", "entity": "domain:acme-target.example",
             "module": "t_src", "confidence": 0.9, "confidence_label": "confirmed", "criterion": "RDAP creation date", "tags": [], "references": []},
        ],
        "correlations": [],
        "modules": [{"module": "t_src", "entity": "domain:acme-target.example", "status": "ok", "hosts": {}}],
        "coverage": {"t_src": {"status": "ok", "runs": 1}},
        "answered": {},
        "skips": {},
        "links": {},
        "timeline": [],
        "notes": [],
        "meta": {},
        "case_dir": "",
    }
    case.update(over)
    return case


def sections(html: str) -> list[str]:
    return re.findall(r"<section[^>]*>(.*?)</section>", html, flags=re.S)


def section(html: str, sid: str) -> str:
    m = re.search(rf'<section id="{re.escape(sid)}">(.*?)</section>', html, flags=re.S)
    assert m, f"section {sid} missing"
    return m.group(1)


def md_sections(md: str) -> list[str]:
    return re.split(r"\n## ", md)[1:]


def terminal(case: dict[str, Any]) -> str:
    console = Console(record=True, width=220, theme=THEME)
    render_case(console, case)
    return console.export_text()


# ======================================================================================
# TLP markings (A2, AR17, P336 cond 5)
# ======================================================================================


@pytest.mark.parametrize("tlp,label", [("clear", "TLP:CLEAR"), ("green", "TLP:GREEN"), ("amber", "TLP:AMBER"), ("amber+strict", "TLP:AMBER+STRICT"), ("red", "TLP:RED")])
def test_tlp_marking_in_header_footer_every_section_and_print_css(tlp, label):
    html = H.render(base_case(tlp=tlp))
    header = html.split("</header>", 1)[0]
    assert label in header and S.TLP_DESCRIPTIONS[tlp] in header.replace("&#x27;", "'")
    secs = sections(html)
    assert len(secs) >= 6
    for body in secs:
        assert label in body.split("</h2>", 1)[0], "the marking opens every section"
    footer = html.split("<footer>", 1)[1]
    assert label in footer
    assert re.search(r"@media print\{[^}]*\{[^}]*\}", html) and f'content:"{label}"' in html  # print CSS carries the label
    assert f"<title>V3LUM case {CASE_ID} - {label}</title>" in html


def test_markdown_first_line_and_every_section_marked():
    md = M.render(base_case(tlp="green"))
    assert md.splitlines()[0] == "**TLP:GREEN**"
    assert S.TLP_DESCRIPTIONS["green"] in md.splitlines()[2]
    secs = md_sections(md)
    assert len(secs) >= 5
    for body in secs:
        assert "**TLP:GREEN**" in "\n".join(body.splitlines()[:3])
    assert md.rstrip().splitlines()[-1].startswith("*SHA-256 of the report content above")


def test_unreadable_tlp_fails_closed_to_red():
    html = H.render(base_case(tlp="purple"))
    assert "TLP:RED" in html and "TLP:PURPLE" not in html


def test_file_names_carry_the_label_and_json_has_tlp(tmp_path):
    case = base_case(tlp="amber+strict")
    written = write_reports(case, ["html", "md", "json", "pivots"], tmp_path)
    assert Path(written["html"]).name == f"{CASE_ID}.TLP-AMBER+STRICT.html"
    assert Path(written["md"]).name == f"{CASE_ID}.TLP-AMBER+STRICT.md"
    assert Path(written["json"]).name == f"{CASE_ID}.TLP-AMBER+STRICT.json"
    assert Path(written["pivots"]).name == f"{CASE_ID}.TLP-AMBER+STRICT.pivots.html"
    data = json.loads(Path(written["json"]).read_text(encoding="utf-8"))
    assert next(iter(data)) == "tlp" and data["tlp"] == "amber+strict"
    assert report_name(base_case(tlp=""), "stix") == f"{CASE_ID}.TLP-AMBER.stix.json"  # nothing recorded: the A2 default
    assert "misp" in FORMATS and "pivots" in FORMATS
    v1 = base_case()
    v1.pop("tlp")
    data = json.loads(Path(write_reports(v1, ["json"], tmp_path / "v1")["json"]).read_text(encoding="utf-8"))
    assert data["tlp"] == "amber"


# ======================================================================================
# personal data (AR24, P336 cond 7, A4)
# ======================================================================================


def personal_case() -> dict[str, Any]:
    case = base_case(
        inputs=[{"type": "cpf", "value": CPF, "reason": "typed"}],
        seeds=[f"cpf:{CPF}"],
        entities=[{"key": f"cpf:{CPF}", "type": "cpf", "value": CPF, "seed": True, "depth": 0, "attributes": {}}],
        findings=[{"id": "f-cpf", "title": f"CPF {CPF} listed in a public register", "severity": "low", "entity": f"cpf:{CPF}",
                   "module": "t_src", "confidence_label": "probable", "criterion": "official register", "tags": [], "references": []}],
        risk={"score": 10.0, "level": "low", "entities": {f"cpf:{CPF}": {"score": 10.0, "level": "low"}}},
    )
    return case


def test_personal_data_notice_and_cpf_masked_everywhere(tmp_path):
    case = personal_case()
    written = write_reports(case, ["html", "md", "json"], tmp_path)
    for fmt in ("html", "md", "json"):
        text = Path(written[fmt]).read_text(encoding="utf-8")
        assert CPF not in text and "529.982.247-25" not in text, fmt
    html = Path(written["html"]).read_text(encoding="utf-8")
    md = Path(written["md"]).read_text(encoding="utf-8")
    assert "***.982.247-**" in html and "contains personal data (LGPD)" in html
    assert "contains personal data (LGPD)" in md
    assert "contains personal data" not in H.render(base_case())  # domain only: no notice


def test_show_personal_unmasks_the_view_with_a_notice():
    html = H.render(personal_case(), show_personal=True)
    assert CPF in html and "shown unmasked" in html
    recorded = personal_case()
    recorded["options"]["show_personal"] = True  # the flag recorded in the case (audited) is the default
    assert CPF in M.render(recorded)
    assert CPF not in M.render(recorded, show_personal=False)


def test_personal_scores_only_with_their_top_contributor():
    case = base_case(
        seeds=["email:ana@acme.example"],
        inputs=[{"type": "email", "value": "ana@acme.example"}],
        entities=[{"key": "email:ana@acme.example", "type": "email", "value": "ana@acme.example", "seed": True, "depth": 0, "attributes": {}}],
        findings=[{"id": "f-e", "title": "Address in 3 breaches", "severity": "high", "entity": "email:ana@acme.example", "module": "t_src",
                   "confidence_label": "probable", "criterion": "breach catalogue", "tags": ["breach"]}],
        risk={"score": 70.0, "level": "high", "entities": {"email:ana@acme.example": {"score": 70.0, "level": "high"}}},
    )
    assert S.score_text(case, "email:ana@acme.example") == "high: Address in 3 breaches"
    assert S.score_text(base_case(), "domain:acme-target.example") == "medium 42"
    html = H.render(case)
    assert "high: Address in 3 breaches" in section(html, "entity-map")
    assert "high 70" not in html


# ======================================================================================
# engagement (A7), licence (A1, P377), disclosure (A8)
# ======================================================================================


def light_case() -> dict[str, Any]:
    case = base_case(options={"mode": "light", "depth": 0, "authorization_ref": "ENG-2026-042"})
    case["engagement"] = {
        "mode": "light", "authorization_ref": "ENG-2026-042", "scope_sha256": "ab" * 32,
        "window": {"start": "2026-11-26T08:00:00Z", "end": "2026-11-26T18:00:00Z"},
        "egress": {"profile": "proxy_light", "ip": "198.51.100.7"}, "targets_touched": {"acme-target.example": 12},
        "request_count": 12, "refusals": [{"target": "domain:out-of-scope.example", "module": "t_light", "reason_code": "scope", "reason": "not in the scope file"}],
    }
    return case


def test_engagement_block_on_every_section_of_a_light_case():
    case = light_case()
    banner = S.engagement_banner(case)
    for part in ("LIGHT engagement", "authorization ENG-2026-042", "scope sha256 abababababababab", "window 2026-11-26T08:00:00Z",
                 "egress proxy_light", "198.51.100.7", "targets touched 1", "12 target requests"):
        assert part in banner, part
    html = H.render(case)
    for body in sections(html):
        assert "LIGHT engagement" in body.split("</h2>", 1)[0]
    assert "out-of-scope" in html and "not in the scope file" in html  # refusals listed
    md = M.render(case)
    for body in md_sections(md):
        assert "LIGHT engagement" in "\n".join(body.splitlines()[:3])
    assert S.engagement_banner(base_case()) == ""  # passive: no banner
    assert "engagement" not in "".join(s.split("</h2>", 1)[0] for s in sections(H.render(base_case())))


def test_every_refusal_and_touched_target_is_listed_in_the_report_body():
    """A7: 'out-of-scope refusals list each target and the reason' - the header keeps the first ten,
    the coverage section of the HTML and Markdown reports lists all of them and every target touched."""
    case = light_case()
    case["engagement"]["refusals"] = [
        {"target": f"domain:out{i:02d}.example", "module": "t_light", "reason_code": "scope", "reason": f"reason {i:02d}"} for i in range(14)
    ]
    case["engagement"]["refusals_omitted"] = 3
    details = S.engagement_details(case)
    assert len(details["refusals"]) == 14 and details["omitted"] == 3 and details["touched"] == [("acme-target.example", 12)]
    header = "\n".join(S.header_lines(case))
    assert "out13.example" not in header and "+7 more targets" in header  # the header stays short
    coverage = section(H.render(case), "coverage")
    md = M.render(case)
    for i in range(14):
        assert f"out{i:02d}.example" in coverage and f"reason {i:02d}" in coverage
        assert f"out{i:02d}" in md
    assert "+3 more refusals" in coverage and "+3 more refusals" in md
    assert "acme-target.example" in coverage and "`acme-target.example` (12 requests)" in md
    assert S.engagement_details(base_case()) == {"touched": [], "refusals": [], "omitted": 0}


def test_licence_banner_on_a_research_case():
    case = base_case(licence_profile="research", licence_used={"shodan.internetdb": {"class": "noncommercial", "basis": "research:LEGAL-7"}})
    html = H.render(case)
    assert "LICENCE: research profile (recorded legal basis)" in html
    assert "shodan.internetdb (noncommercial, research:LEGAL-7)" in html
    md = M.render(case)
    assert "LICENCE: research profile" in "\n".join(md.splitlines()[:8])  # banner under the marking


def test_licence_banner_on_a_corporate_case_with_an_allow_listed_source():
    case = base_case(licence_profile="corporate", licence_used={"isc.api": {"class": "noncommercial", "basis": "allow:LEGAL-2026-014"}})
    app = S.appendix_licence(case)
    assert app["banner"].startswith("LICENCE: licence profile corporate")
    assert app["allow_entries"] == [{"source": "isc.api", "class": "noncommercial", "legal_ref": "LEGAL-2026-014"}]
    html = H.render(case)
    assert "LICENCE: licence profile corporate" in html
    cov = section(html, "coverage")
    assert "licence allow-list entries used" in cov and "LEGAL-2026-014" in cov
    assert not S.appendix_licence(base_case())["banner"]


def test_coverage_lost_under_the_licence_profile_appendix():
    case = base_case(
        skips={"licence": ["t_nc"]},
        coverage={"t_src": {"status": "ok", "runs": 1},
                  "t_nc": {"status": "skipped", "reason_code": "licence", "reason": "skipped: noncommercial terms (licence profile corporate)",
                           "entities": {"domain:acme-target.example": {"status": "skipped", "reason_code": "licence", "reason": "skipped: noncommercial terms"}}}},
    )
    app = section(H.render(case), "appendix-licence")
    assert "Coverage lost under licence profile" in app and "domain: t_nc (noncommercial)" in app
    assert "1 source skipped: licence profile corporate - v3lum doctor --licences" in app
    md = M.render(case)
    assert "Appendix: Coverage lost under licence profile" in md and "domain: t\\_nc (noncommercial)" in md


def test_deferred_lookups_listed_per_source():
    case = base_case(deferred=[{"module": "t_q", "entity": "domain:acme-target.example", "reason": "quota"},
                               {"module": "t_q", "entity": "ipv4:203.0.113.9", "reason": "quota"}])
    lines = S.appendix_licence(case)["deferred"]
    assert lines == [f"t_q: 2 lookups deferred by provider quota (1 domain, 1 ipv4) - v3lum cases resume {CASE_ID}"]
    assert lines[0] in section(H.render(case), "coverage")


def test_disclosure_ledger_counts_hosts_and_receivers():
    case = base_case(
        entities=[
            {"key": "domain:acme-target.example", "type": "domain", "value": "acme-target.example", "seed": True, "depth": 0, "attributes": {}},
            {"key": "ipv4:203.0.113.9", "type": "ipv4", "value": "203.0.113.9", "depth": 1, "attributes": {}},
        ],
        modules=[
            {"module": "t_a", "entity": "domain:acme-target.example", "status": "ok", "hosts": {"api.unregistered-one.example": 2}},
            {"module": "t_b", "entity": "ipv4:203.0.113.9", "status": "ok", "hosts": {"api.unregistered-one.example": 1, "lookup.unregistered-two.example": 3}},
            {"module": "t_c", "entity": "domain:acme-target.example", "status": "ok", "hosts": {"acme-target.example": 1}},
        ],
    )
    app = S.appendix_disclosure(case)
    rows = {r["host"]: r for r in app["hosts"]}
    assert rows["api.unregistered-one.example"]["requests"] == 3 and rows["api.unregistered-one.example"]["tier"] == "unknown"
    assert rows["lookup.unregistered-two.example"]["requests"] == 3
    assert rows["acme-target.example"]["role"] == "investigated target"
    assert app["line"].startswith("value disclosed to 2 third-party providers")
    receivers = dict(app["by_entity"])
    assert receivers["ipv4 203.0.113.9"] == ["api.unregistered-one.example", "lookup.unregistered-two.example"]
    html = H.render(case)
    assert "value disclosed to 2 third-party providers" in html.split("</header>", 1)[0]
    ledger = section(html, "appendix-disclosure")
    assert "Disclosure ledger" in ledger and "lookup.unregistered-two.example" in ledger and "investigated target" in ledger
    assert "value disclosed to 2 third-party providers" in M.render(case)


# ======================================================================================
# content order (A11, P258, P335, P322, P302, AR14)
# ======================================================================================


def test_your_assets_section_comes_first():
    case = base_case(findings=[
        {"id": "f-other", "title": "Third-party host exposed", "severity": "high", "entity": "domain:acme-target.example", "module": "t_src",
         "confidence_label": "probable", "criterion": "banner", "tags": [], "ownership": "third_party"},
        {"id": "f-own", "title": "Own login page exposed", "severity": "medium", "entity": "domain:acme-target.example", "module": "t_src",
         "confidence_label": "confirmed", "criterion": "own profile", "tags": ["own_asset"], "ownership": "own_asset"},
    ])
    html = H.render(case)
    assert html.index('id="your-assets"') < html.index('id="correlations"') < html.index('id="findings"')
    assert "Own login page exposed" in section(html, "your-assets") and "Third-party host exposed" not in section(html, "your-assets")
    assert "Own login page exposed" not in section(html, "findings")
    md = M.render(case)
    assert md.index("## Your assets") < md.index("## Findings")
    assert 'id="your-assets"' not in H.render(base_case())


def test_possible_identity_links_only_in_the_entity_details():
    case = base_case(findings=[
        {"id": "f-id", "title": "Same handle on another platform", "severity": "low", "entity": "domain:acme-target.example", "module": "t_id",
         "confidence_label": "possible", "criterion": "same handle does not prove identity", "tags": ["identity"]},
        {"id": "f-ok", "title": "Regular finding", "severity": "low", "entity": "domain:acme-target.example", "module": "t_src",
         "confidence_label": "probable", "criterion": "c", "tags": []},
    ])
    html = H.render(case)
    assert "Same handle on another platform" not in section(html, "findings")
    assert "Same handle on another platform" in section(html, "entities") and "POSSIBLE" in section(html, "entities")
    assert "Same handle on another platform" not in M.render(case)
    assert "Same handle on another platform" not in terminal(case)


def test_confidence_label_and_criterion_on_every_row_and_the_analyst_override():
    case = base_case(findings=[
        {"id": "f-low", "title": "Low thing", "severity": "low", "entity": "domain:acme-target.example", "module": "t_src",
         "confidence_label": "possible", "criterion": "POSSIBLE - on warninglist alexa", "tags": []},
        {"id": "f-ov", "title": "Overridden thing", "severity": "high", "entity": "domain:acme-target.example", "module": "t_src",
         "confidence_label": "confirmed", "criterion": "kit hash", "tags": [],
         "override": {"label": "confirmed", "severity": "high", "verdict": "right", "note": "checked the kit by hand", "analyst": "ana"}},
    ])
    findings = section(H.render(case), "findings")
    assert "POSSIBLE - on warninglist alexa" in findings and "criterion:" in findings and "CONFIRMED" in findings
    assert "analyst: confirmed / high / right (checked the kit by hand)" in findings
    md = M.render(case)
    assert "POSSIBLE - on warninglist alexa" in md and "analyst: confirmed / high / right (checked the kit by hand)" in md


def breach_case() -> dict[str, Any]:
    findings = []
    for i, src in enumerate(("hibp.account", "xposedornot.check", "leakcheck.public")):
        findings.append({
            "id": f"f-breach-{i}", "title": "Address found in breach Adobe", "severity": "medium", "entity": "email:ana@acme.example",
            "module": f"t_breach_{i}", "source": src, "confidence_label": "probable", "criterion": "listed by the breach service",
            "tags": ["breach"], "data": {"name": "Adobe", "data_classes": ["Email addresses", "Passwords", "Password hints"], "password_form": "bcrypt"},
        })
    return base_case(
        seeds=["email:ana@acme.example"],
        inputs=[{"type": "email", "value": "ana@acme.example"}],
        entities=[{"key": "email:ana@acme.example", "type": "email", "value": "ana@acme.example", "seed": True, "depth": 0, "attributes": {}}],
        findings=findings,
    )


def test_grouped_rows_render_one_row_and_keep_every_finding(tmp_path):
    case = breach_case()
    rows = S.finding_rows(case["findings"])
    assert len(rows) == 1 and rows[0].count == 3 and rows[0].grouped
    assert rows[0].sources_text().startswith("seen by 3 sources: ")
    html = H.render(case)
    findings = section(html, "findings")
    assert findings.count("<tr data-row") == 1 and "3 grouped findings" in findings
    assert all(f"f-breach-{i}" in findings for i in range(3))  # every member keeps its id
    written = write_reports(case, ["json", "md"], tmp_path)
    assert len(json.loads(Path(written["json"]).read_text(encoding="utf-8"))["findings"]) == 3  # exports stay atomic
    assert "seen by 3 sources" in Path(written["md"]).read_text(encoding="utf-8")
    text = terminal(case)
    table = text.split("⚑ findings", 1)[1].split("⌬ entity map", 1)[0]
    assert table.count("Address found in breach Adobe") == 1 and "seen by 3 sources" in table


def test_breach_password_form_in_plain_words_never_a_value():
    case = breach_case()
    case["findings"][0]["data"]["password_form"] = "PlainText"
    case["findings"][1]["data"]["password_form"] = "hunter2"  # never a form word: never printed
    case["findings"][2]["data"]["password_form"] = "hashed: SHA-1"
    facts = S.breach_facts(case["findings"][0])
    assert facts == ["data classes: Email addresses, Passwords, Password hints", "passwords: plaintext"]
    assert S.password_words("bcrypt") == "passwords: hashed (bcrypt)"
    assert S.password_words(["hashed: sha-1", "unknown"]) == "passwords: hashed (sha-1), storage form unknown"
    assert S.password_words("hunter2") == "" and S.password_words("$2y$10$abcdefabcdefabcdefabcdef") == ""
    html, md = H.render(case), M.render(case)
    term = terminal(case)
    for text in (html, md, term):
        assert "passwords: plaintext" in text
        assert "hunter2" not in text
    assert "passwords:" not in "".join(S.breach_facts(base_case()["findings"][0]))  # not a breach finding


def test_breach_notice_when_the_breach_rules_fired():
    case = breach_case()
    assert "LGPD art. 20" not in H.render(case)
    case["correlations"] = [{"id": "c-1", "rule": "corporate_credentials_in_infostealer", "title": "Corporate credentials in a stealer log",
                             "severity": "high", "entities": ["email:ana@acme.example"], "confidence_label": "probable", "criterion": "own domain, 3 months"}]
    for text in (H.render(case), M.render(case)):
        assert S.BREACH_NOTICE.split(" (")[0] in text and "LGPD art. 20" in text


def test_score_label_and_top_contributors_with_ids_and_paths():
    case = base_case(risk={
        "score": 64.0, "level": "high", "label": S.SCORE_LABEL, "entities": {},
        "contributors": [
            {"finding_id": "f-dom-1", "entity": "domain:acme-target.example", "path": ["domain:acme-target.example", "ipv4:203.0.113.9"],
             "confidence_label": "confirmed", "weight": 0.4, "words": "young domain hosting a kit"},
        ],
    })
    lines = S.contributor_lines(case)
    assert lines == ["1. young domain hosting a kit [CONFIRMED] (finding f-dom-1; path acme-target.example -> 203.0.113.9)"]
    html = H.render(case)
    bottom = section(html, "bottom-line")
    assert "young domain hosting a kit [CONFIRMED]" in bottom and "finding f-dom-1" in bottom and S.SCORE_LABEL in bottom
    assert S.SCORE_LABEL in html.split("</header>", 1)[0]
    term = terminal(case)
    assert "top contributors:" in term and "finding f-dom-1" in term


def test_v1_level_clean_never_printed():
    case = base_case(summary={"risk_score": 0, "risk_level": "clean"}, risk={"score": 0, "level": "clean"}, findings=[])
    case["answered"] = {"domain:acme-target.example": {"applicable": 3, "answered": 3, "could_not_verify": 0, "reputation_answered": 2}}
    html, md = H.render(case), M.render(case)
    assert "NO FINDINGS" in html and "risk-clean" not in html and ">clean<" not in html.lower()
    assert "NO FINDINGS" in md and "CLEAN" not in md
    assert ".st-quota" in html  # carry-forward: quota coverage is styled


# ======================================================================================
# header lines: since last run (P324 cond 8), TLS interception (P329), internal sightings (P375, A12)
# ======================================================================================


def test_since_last_run_and_tls_interception_header_lines():
    case = base_case(since_last_run={"previous_case": "20261120-090000-aaaa", "new": 2, "resolved": 1, "not_rechecked": 0},
                     meta={"tls_interception": {"intercepted": True, "issuer": "Corp Inspection CA", "profile": "default"}})
    lines = S.header_lines(case)
    assert "since last run (case 20261120-090000-aaaa): 2 new findings, 1 resolved" in lines
    assert any(line.startswith("TLS-intercepted by Corp Inspection CA (egress profile default)") and "inconclusive" in line for line in lines)
    header = H.render(case).split("</header>", 1)[0]
    assert "2 new findings, 1 resolved" in header and "TLS-intercepted by Corp Inspection CA" in header
    # the audit hook already added it as a header note: printed once
    noted = base_case(since_last_run={"new": 2, "resolved": 1}, meta={"header_notes": ["since last run: 2 new findings, 1 resolved"]})
    assert sum("since last run" in line for line in S.header_lines(noted)) == 1
    assert not S.tls_interception_line(base_case(meta={"tls_interception": {"intercepted": False, "issuer": "x"}}))


def sightings_case(tlp: str) -> dict[str, Any]:
    case = base_case(tlp=tlp)
    case["entities"][0]["attributes"] = {
        "sightings": [{"value": {"count": 3, "last": "2026-11-20", "verdict": "malicious", "restricted": 0}, "source": "case_sightings"}],
        "internal_sightings": [{"value": [{"platform": "thehive", "ref": "TheHive case #7", "tlp": "amber"},
                                          {"platform": "misp", "ref": "MISP event #12", "tlp": "green"},
                                          {"platform": "misp", "ref": "MISP event #99", "tlp": "red"}], "source": "misp_sightings"}],
    }
    case["findings"].append({"id": "f-seen", "title": "seen in 3 previous cases, last 2026-11-20, verdict: malicious", "severity": "info",
                             "entity": "domain:acme-target.example", "module": "case_sightings", "confidence_label": "confirmed",
                             "criterion": "case DB sighting", "tags": []})
    return case


def test_internal_sightings_first_and_omitted_at_clear():
    amber = sightings_case("amber")
    lines = S.sighting_lines(amber, "domain:acme-target.example")
    assert lines == ["seen in 3 previous cases, last 2026-11-20, verdict: malicious", "known internally: MISP event #12, TheHive case #7"]
    html = H.render(amber)
    assert "seen in 3 previous cases" in html.split("</header>", 1)[0]  # in the summary
    details = section(html, "entities")
    assert details.index("internal sightings") < details.index("<table>")  # first per entity
    assert "MISP event #99" not in html  # marked above the case TLP
    clear = sightings_case("clear")
    for text in (H.render(clear), M.render(clear)):
        assert "previous cases" not in text and "MISP event" not in text and "TheHive" not in text  # A2: no cross-case references


def test_report_notices_and_attention_points():
    case = base_case(coverage={"t_src": {"status": "ok", "runs": 1}, "t_blocked": {"status": "blocked", "reason_code": "challenge", "runs": 1}})
    points, limits = S.attention(case)
    assert any("t_blocked" in x for x in limits)
    att = section(H.render(case), "attention")
    assert "limitation" in att and "t_blocked" in att


# ======================================================================================
# attributions (P336 cond 6)
# ======================================================================================


def test_attributions_generated_from_the_sources_and_datasets_used(tmp_path, monkeypatch, clean_registry):
    from v3lum.core import datasets

    notices = tmp_path / "notices"
    notices.mkdir()
    (notices / "t_notice.json").write_text(json.dumps({
        "schema": "v3lum.notice/1", "name": "t_notice", "source_url": "https://data.example.org/", "version": "1", "sha256": "",
        "licence": "CC-BY-4.0", "attribution": "Example data by Example Org, CC BY 4.0.", "bundled": False, "files": ["v3lum/modules/x/t_used.py"],
    }), encoding="utf-8")
    (notices / "t_unused.json").write_text(json.dumps({
        "schema": "v3lum.notice/1", "name": "t_unused", "source_url": "https://other.example.org/", "version": "1", "sha256": "",
        "licence": "CC-BY-4.0", "attribution": "Never shown.", "bundled": False, "files": ["v3lum/modules/x/t_not_run.py"],
    }), encoding="utf-8")
    monkeypatch.setattr(S, "_NOTICES_DIR", notices)
    monkeypatch.setattr(S, "_NOTICE_CACHE", {})
    monkeypatch.setattr(S, "_module_files", lambda name: {f"v3lum/modules/x/{name}.py"})
    monkeypatch.setattr(S, "_module_provider", lambda name: "openstreetmap" if name == "t_used" else "")
    datasets.register_dataset("t_attr_ds", "https://data.example.org/ds.json", licence="ODbL-1.0", terms_class="open",
                              attribution="Dataset by the Example Foundation (ODbL).")
    case = base_case(
        modules=[
            {"module": "t_used", "entity": "domain:acme-target.example", "status": "ok", "hosts": {}, "datasets": [{"name": "t_attr_ds"}]},
            {"module": "t_not_run", "entity": "domain:acme-target.example", "status": "skipped", "hosts": {}},
        ],
    )
    case["findings"][0]["attack"] = ["T1583.001"]
    names = {a["name"]: a for a in S.attributions(case)}
    assert names["t_notice"]["text"] == "Example data by Example Org, CC BY 4.0." and names["t_notice"]["used_by"] == ["t_used"]
    assert "t_unused" not in names
    assert names["dataset t_attr_ds"]["licence"] == "ODbL-1.0"
    assert names["OpenStreetMap"]["licence"] == "ODbL-1.0"
    assert "mitre_attack" in names and "MITRE" in names["mitre_attack"]["text"]
    footer = H.render(case).split("<footer>", 1)[1]
    assert "<details><summary>Attributions" in footer and "Example data by Example Org" in footer and "Never shown" not in footer
    assert "Example data by Example Org" in M.render(case)
