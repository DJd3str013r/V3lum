"""report.summary: each pure function over hand-built case dicts (v2 and stored v1 shapes)."""

from __future__ import annotations

import copy
import json

import pytest

from tests.fakes import test_provider
from v3lum.report import summary as S

SEED = "domain:example.com"
IP = "ipv4:203.0.113.7"


def v2_case(**extra) -> dict:
    case = {
        "schema": "v3lum.case/2", "case_id": "20261126-140000-summ", "tlp": "amber", "seeds": [SEED],
        "inputs": [{"type": "domain", "value": "example.com", "confidence": 1.0, "reason": "domain name"}],
        "options": {"mode": "passive", "depth": 1, "preset": "quick"},
        "summary": {"risk_score": 0.0, "risk_level": "clean"},
        "risk": {"score": 0.0, "level": "clean", "entities": {}, "top": []},
        "entities": [{"key": SEED, "type": "domain", "value": "example.com", "depth": 0, "seed": True, "tags": [],
                      "attributes": {"registrar": [{"value": "Example Registrar Inc.", "source": "rdap"}], "created": [{"value": "1995-08-14", "source": "rdap"}],
                                     "a_records": [{"value": ["93.184.216.34", "93.184.216.35", "93.184.216.36"], "source": "dns_records"}],
                                     "registrant_email": [{"value": "owner@example.com", "source": "rdap"}]}}],
        "edges": [], "findings": [], "correlations": [],
        "modules": [{"module": "dns_records", "entity": SEED, "status": "ok", "hosts": {"dns.google": 3}},
                    {"module": "rep_a", "entity": SEED, "status": "empty", "hosts": {"urlhaus-api.abuse.ch": 1}}],
        "coverage": {},
        "answered": {SEED: {"applicable": 4, "answered": 3, "could_not_verify": 1,
                            "sources": [{"module": "rep_b", "source": "", "status": "blocked", "reason_code": "challenge"},
                                        {"module": "agg", "source": "agg.feed", "status": "ok", "reason_code": ""}],
                            "reputation_applicable": 3, "reputation_answered": 2}},
        "skips": {}, "links": {}, "notes": [], "meta": {}, "licence_profile": "corporate", "licence_used": {},
    }
    case.update(extra)
    return case


def v1_case(**extra) -> dict:
    case = {
        "schema": "v3lum.case/1", "case_id": "20250101-000000-beef", "created": "2025-01-01T00:00:00+00:00", "inputs": [],
        "seeds": ["domain:evil.example"], "options": {"mode": "passive", "tlp": "clear"},
        "summary": {"risk_score": 30.0, "risk_level": "medium", "entities": 1, "findings": 1, "interrupted": True},
        "risk": {"score": 30.0, "level": "medium", "entities": {"domain:evil.example": {"score": 30.0, "level": "medium"}},
                 "top": [{"entity": "domain:evil.example", "score": 30.0, "level": "medium"}]},
        "entities": [{"key": "domain:evil.example", "type": "domain", "value": "evil.example", "display": "evil.example", "depth": 0, "seed": True, "attributes": {}}],
        "edges": [],
        "findings": [{"id": "0a1b2c3d4e5f", "title": "Listed by a feed", "severity": "medium", "description": "", "confidence": 0.9,
                      "data": {}, "tags": ["malicious"], "references": [], "entity": "domain:evil.example", "module": "src"}],
        "correlations": [],
        "modules": [{"module": "src", "entity": "domain:evil.example", "status": "ok", "findings": ["0a1b2c3d4e5f"], "error": ""},
                    {"module": "dead", "entity": "domain:evil.example", "status": "rate_limited", "error": "429"}],
        "coverage": {"src": {"title": "src", "status": "ok", "reason": ""}}, "links": {}, "timeline": [], "notes": [],
    }
    case.update(extra)
    return case


def _all_text(case: dict) -> str:
    parts = S.header_lines(case) + S.bottom_line(case) + S.skip_lines(case) + S.licence_lines(case) + S.followup_lines(case) + S.note_lines(case)
    parts += [S.case_level(case)] + [S.seed_level(case, s) for s in case.get("seeds", [])]
    return "\n".join(parts)


# ---------------------------------------------------------------------------------------- levels


def test_level_label_never_says_clean():
    assert S.level_label("clean") == "no findings" and S.level_label("") == "no findings" and S.level_label(None) == "no findings"
    assert S.level_label("no findings") == "no findings" and S.level_label("HIGH") == "high"


@pytest.mark.parametrize("answered,level,expected", [
    (0, "clean", "inconclusive"), (1, "clean", "inconclusive"), (2, "clean", "no findings"), (3, "no findings", "no findings"),
    (2, "high", "high"), (1, "high", "inconclusive"),
])
def test_seed_level(answered, level, expected):
    case = v2_case(risk={"score": 0, "level": level, "entities": {SEED: {"score": 60.0, "level": level}}})
    case["answered"][SEED]["reputation_answered"] = answered
    assert S.seed_level(case, SEED) == expected


def test_seed_level_without_an_answered_record_is_inconclusive():
    assert S.seed_level(v1_case(), "domain:evil.example") == "inconclusive"  # stored v1 case
    case = v2_case()
    assert S.seed_level(case, "domain:other.example") == "inconclusive"  # no row for that seed
    case["risk"]["inconclusive"] = [SEED]  # the risk model v2 list counts too
    assert S.seed_level(case, SEED) == "inconclusive"


def test_case_level():
    assert S.case_level(v2_case()) == "no findings"
    case = v2_case()
    case["answered"][SEED]["reputation_answered"] = 1
    assert S.case_level(case) == "inconclusive"
    assert S.case_level(v2_case(risk={"score": 70, "level": "high"})) == "high"
    assert S.case_level(v1_case()) == "medium"
    assert S.case_level(v1_case(risk={"score": 0, "level": "clean"}, summary={})) == "inconclusive"
    assert S.case_level({}) == "inconclusive"


def test_no_function_ever_returns_clean():
    for case in (v2_case(), v1_case(), v1_case(risk={"score": 0.0, "level": "clean"}),
                 v2_case(notes=["inconclusive: no source answered (2 run(s) could not verify) - a 'clean' risk level is not a verdict"])):
        assert "clean" not in _all_text(case).lower()


# ---------------------------------------------------------------------------------------- header


def test_header_lines_v2():
    case = v2_case(meta={"header_notes": ["TLS interception detected: CorpProxy CA"]})
    case["options"].update(purpose="phishing triage", ticket="INC-7", legal_basis="legitimate_interest")
    lines = S.header_lines(case)
    assert lines[0] == "TLP:AMBER"
    assert lines[1] == "mode passive · egress default route · preset quick · depth 1"
    assert "example.com: 3 of 4 applicable sources answered; 1 could not verify (rep_b: challenge) · reading: no findings" in lines
    assert any(line.startswith("value disclosed to 2 third-party providers: ") for line in lines)
    assert "purpose: phishing triage · ticket: INC-7 · legal basis: legitimate_interest" in lines
    assert lines[-1] == "TLS interception detected: CorpProxy CA"
    assert [k for k, _ in S.header_items(case)][:2] == ["tlp", "mode"]


def test_header_lines_v1_shape():
    lines = S.header_lines(v1_case())
    assert lines[0] == "TLP:CLEAR"  # the v1 options recorded it
    assert "PARTIAL RESULT: scan interrupted: partial results" in lines
    assert "evil[.]example: 1 of 2 applicable sources answered; 1 could not verify (dead: rate_limited) · reading: inconclusive (reputation sources answered: 0; at least 2 needed) · highest scored level medium" in lines  # tagged malicious: defanged
    assert "value disclosure not recorded (stored v1 case)" in lines
    assert S.header_lines({"seeds": []})[0] == "TLP:AMBER"  # nothing recorded: the A2 default


def test_header_partial_notes_and_synthesised_reasons():
    case = v2_case(partial={"deadline": True, "window": True},
                   notes=["scan deadline (global timeout 90s) reached: partial results (3 pending source run(s) SKIPPED 'deadline')", "other note"])
    partial = [line for line in S.header_lines(case) if line.startswith("PARTIAL RESULT")]
    assert partial == [
        "PARTIAL RESULT: scan deadline (global timeout 90s) reached: partial results (3 pending source run(s) SKIPPED 'deadline')",
        "PARTIAL RESULT: engagement window ended: partial results",
    ]
    assert S.note_lines(case) == ["other note"]


def test_header_engagement_and_light_mode():
    case = v2_case(engagement={"authorization_ref": "PT-2026-001", "scope_sha256": "ab" * 32, "window": {"start": "2026-11-26T08:00Z", "end": "2026-11-26T18:00Z"},
                               "egress": {"profile": "light", "proxy": "socks5h://127.0.0.1:9050"}, "targets_touched": {"example.com": 4}, "request_count": 4,
                               "refusals": [{"target": "10.0.0.1", "module": "probe", "reason_code": "scope", "reason": "outside the scope"}]})
    case["options"].update(mode="light", authorization_ref="PT-2026-001")
    lines = S.header_lines(case)
    assert lines[1] == "mode light · egress light socks5h://127.0.0.1:9050 · preset quick · depth 1 · authorization PT-2026-001"
    assert "engagement: authorization PT-2026-001 · scope sha256 abababababababab · window 2026-11-26T08:00Z - 2026-11-26T18:00Z · targets touched 1 · 4 target requests" in lines
    assert "refused: 10.0.0.1 (probe: scope) outside the scope" in lines
    case.pop("engagement")
    assert "egress not recorded" in S.header_lines(case)[1]


def test_header_engagement_read_from_meta_and_refused_targets_masked():
    """WP15 records the engagement in case['meta'] too; refused targets are entity displays."""
    eng = {"authorization_ref": "PT-9", "egress": {"profile": "proxy_light", "ip": "198.51.100.7", "checked_at": "2026-11-26"},
           "egress_override": "", "request_count": 2, "refusals": [{"target": "domain:evil.example", "module": "probe", "reason_code": "hostile_host", "reason": "hostile"}],
           "refusals_omitted": 3}
    case = v2_case(meta={"engagement": eng}, entities=[{"key": "domain:evil.example", "type": "domain", "value": "evil.example", "tags": ["c2"], "attributes": {}}])
    case["options"].update(mode="light", authorization_ref="PT-9")
    lines = S.header_lines(case)
    assert lines[1].startswith("mode light · egress proxy_light public IP 198.51.100.7")
    assert "engagement: authorization PT-9 · 2 target requests" in lines
    assert "refused: evil[.]example (probe: hostile_host) hostile" in lines  # c2-tagged: defanged
    assert "refused: +3 more targets (see the report)" in lines


def test_mode_line_records_override_offline_and_allow_unknown():
    case = v2_case()
    case["options"].update(egress_override="INC-77 approved by SOC lead", offline=True, allow_unknown=True)
    line = S.header_lines(case)[1]
    assert "egress override INC-77 approved by SOC lead" in line
    assert "offline (no network)" in line and "unknown-tier providers allowed (--allow-unknown)" in line


def test_header_caps_answered_lines_with_max_seeds():
    seeds = [f"domain:d{i}.example" for i in range(5)]
    answered = {s: {"applicable": 2, "answered": 1, "could_not_verify": 1, "sources": [], "reputation_applicable": 2, "reputation_answered": 1 if i % 2 else 2}
                for i, s in enumerate(seeds)}
    case = v2_case(seeds=seeds, answered=answered)
    full = [line for kind, line in S.header_items(case) if kind == "answered"]
    assert len(full) == 5
    capped = [line for kind, line in S.header_items(case, max_seeds=2) if kind == "answered"]
    assert len(capped) == 3 and capped[0].startswith("d0.example: 1 of 2")
    assert capped[-1] == "+3 more inputs: 3 of 6 applicable sources answered; 3 could not verify · 1 inconclusive (the report lists every input)"
    assert S.header_lines(case, max_seeds=2) == [text for _k, text in S.header_items(case, max_seeds=2)]


def test_licence_banner():
    case = v2_case(licence_used={"shodan.internetdb": {"class": "noncommercial", "basis": "allow:LEGAL-2026-014"}, "core_doh.resolvers": {"class": "open", "basis": "open"}})
    assert "LICENCE: licence profile corporate - noncommercial/license sources used: shodan.internetdb (noncommercial, allow:LEGAL-2026-014)" in S.header_lines(case)
    research = v2_case(licence_profile="research")
    assert "LICENCE: research profile (recorded legal basis) - no noncommercial/license source was used in this run" in S.header_lines(research)
    assert not any(line.startswith("LICENCE") for line in S.header_lines(v2_case()))  # corporate, open sources only


def test_header_masks_and_defangs_entity_displays():
    cpf = "cpf:52998224725"
    case = v2_case(seeds=[cpf], answered={cpf: {"applicable": 0, "answered": 0, "could_not_verify": 0, "sources": []}})
    lines = S.header_lines(case)
    assert any(line.startswith("***.982.247-**: no applicable source answered (none ran)") for line in lines)
    assert "52998224725" not in "\n".join(lines)
    assert any(line.startswith("529.982.247-25:") for line in S.header_lines(case, show_personal=True))
    url = "url:https://evil.example/x"
    hostile = v2_case(seeds=[url], entities=[{"key": url, "type": "url", "value": "https://evil.example/x", "tags": ["phishing"], "attributes": {}}], answered={})
    assert any(line.startswith("hxxps://evil[.]example/x:") for line in S.header_lines(hostile))
    assert any(line.startswith("https://evil.example/x:") for line in S.header_lines(hostile, no_defang=True))


# ---------------------------------------------------------------------------------------- bottom line


def test_bottom_line_no_findings():
    what, why, nxt = S.bottom_line(v2_case())
    assert what == "What it is: domain example.com - registrar Example Registrar Inc.; created 1995-08-14; a records 93.184.216.34, 93.184.216.35 (+1)"
    assert why == "Why: no findings - 3 of 4 applicable sources answered and none reported a risk signal (triage aid, not a conclusion)"
    assert nxt.startswith("Next step: no action suggested by the automated sources")
    assert "owner@example.com" not in what  # personal facts are never 'key facts'


def test_bottom_line_with_contributors_v2():
    case = v2_case(
        risk={"score": 66.0, "level": "high", "entities": {SEED: {"score": 66.0, "level": "high"}},
              "contributors": [{"finding_id": "f1", "entity": SEED, "confidence_label": "confirmed", "weight": 0.7, "words": "hosts a phishing kit (URLhaus)"},
                               {"finding_id": "f2", "entity": SEED, "confidence_label": "possible", "weight": 0.1, "words": "same handle on a forum"}],
              "label": "triage aid, not a conclusion"},
        findings=[{"id": "f1", "title": "Phishing kit", "severity": "high", "confidence": 0.9, "entity": SEED, "module": "urlhaus", "tags": ["phishing"]},
                  {"id": "f2", "title": "Same handle", "severity": "low", "confidence": 0.4, "confidence_label": "possible", "entity": SEED, "module": "u", "tags": ["identity"]}],
        correlations=[{"id": "c1", "rule": "r", "title": "Phishing infrastructure", "severity": "high", "confidence": 0.8, "recommendation": "Request a takedown and block the domain"}],
    )
    _what, why, nxt = S.bottom_line(case)
    assert why == "Why: HIGH 66/100 (triage aid, not a conclusion) - hosts a phishing kit (URLhaus) [CONFIRMED]"  # POSSIBLE identity link left out
    assert nxt == "Next step: Request a takedown and block the domain"
    assert S.bottom_line(case)[0].startswith("What it is: domain example[.]com")  # tagged phishing: defanged


def test_bottom_line_v1_falls_back_to_top_entities():
    what, why, nxt = S.bottom_line(v1_case())
    assert what == "What it is: domain evil[.]example - no facts collected"
    assert why == "Why: MEDIUM 30/100 (triage aid, not a conclusion) - evil[.]example: Listed by a feed (medium) [CONFIRMED]"
    assert nxt == "Next step: confirm the medium finding 'Listed by a feed' on evil[.]example with its evidence before acting"


def test_bottom_line_inconclusive_suggests_coverage():
    case = v2_case(skips={"needs_key": ["vt"], "not_default": ["a"], "licence": ["shodan_internetdb"]}, deferred=[{"module": "otx", "entity": SEED, "reason": "quota"}])
    case["answered"][SEED]["reputation_answered"] = 1
    _what, why, nxt = S.bottom_line(case)
    assert why == "Why: inconclusive - fewer than 2 reputation sources answered (example.com: 1 of 3 answered; 1 source could not verify); not a verdict either way"
    assert nxt == ("Next step: add coverage before concluding - configure the missing API keys (v3lum keys); run the opt-in sources (--preset deep); "
                   "retry the sources that could not verify (v3lum cases resume 20261126-140000-summ); review the coverage lost to the licence profile (v3lum doctor --licences)")


def test_bottom_line_multiple_inputs_and_text_seed():
    text = "text_blob:beacon to 203.0.113.7"
    case = v2_case(seeds=[SEED, text, IP], answered={})
    case["edges"] = [{"src": text, "dst": IP, "relation": "mentions", "module": "ioc_extract", "confidence": 0.9}]
    what = S.bottom_line(case)[0]
    assert what.startswith("What it is: 3 inputs - domain example.com (registrar Example Registrar Inc.; created 1995-08-14); text_blob beacon to 203.0.113.7 (1 values extracted); ipv4 203.0.113.7")


# ---------------------------------------------------------------------------------------- skip lines


def test_skip_lines_one_per_reason_code_then_quota_lines():
    case = v2_case(skips={"not_default": ["a", "b"], "licence": ["c"], "needs_key": ["d", "e"], "own_asset": ["f"], "tlp": ["g"], "weird_code": ["h"]},
                   meta={"quota_lines": ["HackerTarget: 50/50 today, 12 lookups deferred", ""]})
    assert S.skip_lines(case) == [
        "1 source skipped: licence profile corporate - v3lum doctor --licences",
        "2 opt-in sources not run (use --preset deep)",
        "2 sources need an API key: v3lum keys",
        "1 own-asset module needs a verified org profile: v3lum org",
        "1 source skipped at TLP:AMBER: the value may not leave for them at this TLP",
        "1 source skipped (weird_code)",
        "HackerTarget: 50/50 today, 12 lookups deferred",
    ]


def test_skip_lines_count_licence_blocked_feeds_of_aggregators():
    case = v2_case(skips={"licence": ["shodan_internetdb"]},
                   coverage={"ip_blocklists": {"status": "ok", "sources": {"blocklists.cins": {"status": "skipped", "reason_code": "licence", "reason": "skipped: noncommercial terms (licence profile corporate)"},
                                                                         "blocklists.spamhaus": {"status": "ok", "reason_code": ""}}},
                             "shodan_internetdb": {"status": "skipped", "reason_code": "licence", "sources": {"shodan.internetdb": {"status": "skipped", "reason_code": "licence"}}}})
    assert S.skip_lines(case)[0] == "2 sources skipped: licence profile corporate - v3lum doctor --licences"
    assert S.skip_lines(v1_case()) == []


# ---------------------------------------------------------------------------------------- disclosure


def test_disclosure_summary_maps_hosts_to_providers():
    summary = S.disclosure_summary(v2_case())
    assert set(summary) == {"dns.google", "urlhaus-api.abuse.ch"}
    dns = summary["dns.google"]
    assert dns["provider"] == "google_public_dns" and dns["tier"] == "trusted" and dns["third_party"] is True
    assert dns["requests"] == 3 and dns["entities"] == [SEED] and dns["terms"] == "open"
    assert summary["urlhaus-api.abuse.ch"]["provider"] == "abusech"


def test_disclosure_unknown_hosts_targets_and_internal_providers(clean_registry):
    with test_provider("t_internal_tip", hosts=("tip.corp.example",), internal=True):
        case = v2_case(modules=[
            {"module": "x", "entity": SEED, "status": "ok", "hosts": {"api.unregistered.example": 2}},
            {"module": "y", "entity": SEED, "status": "ok", "hosts": {"www.example.com": 1}},  # the investigated host itself
            {"module": "z", "entity": SEED, "status": "ok", "hosts": {"tip.corp.example": 5}},
        ])
        summary = S.disclosure_summary(case)
        by_entity = S.disclosure_by_entity(case)
    unknown = summary["api.unregistered.example"]
    assert unknown["provider"] == "" and unknown["tier"] == "unknown" and unknown["third_party"] is True
    target = summary["www.example.com"]
    assert target["target"] is True and target["third_party"] is False and target["tier"] == "n/a"
    internal = summary["tip.corp.example"]
    assert internal["internal"] is True and internal["third_party"] is False
    assert by_entity == {SEED: ["api.unregistered.example"]}  # neither the target nor the internal TIP


def test_disclosure_by_entity_and_header_count():
    case = v2_case()
    case["modules"].append({"module": "ip_mod", "entity": IP, "status": "ok", "hosts": {"dns.google": 1}})
    by_entity = S.disclosure_by_entity(case)
    assert by_entity[SEED] == ["abuse.ch platforms", "Google Public DNS (DNS-over-HTTPS JSON API)"] or len(by_entity[SEED]) == 2
    assert IP in by_entity and len(by_entity[IP]) == 1
    line = next(line for line in S.header_lines(case) if line.startswith("value disclosed"))
    assert line.startswith("value disclosed to 2 third-party providers: ")
    no_hosts = v2_case(modules=[{"module": "m", "entity": SEED, "status": "ok", "hosts": {}}])
    assert "value disclosed to 0 third-party providers" in S.header_lines(no_hosts)


# ---------------------------------------------------------------------------------------- licence lines


def test_licence_lines_per_entity_type():
    case = v2_case(
        skips={"licence": ["shodan_internetdb"]},
        coverage={
            "shodan_internetdb": {"status": "skipped", "reason_code": "licence",
                                  "entities": {IP: {"status": "skipped", "reason_code": "licence", "reason": "skipped: noncommercial terms (licence profile corporate)"}},
                                  "sources": {"shodan.internetdb": {"status": "skipped", "reason_code": "licence", "reason": "skipped: noncommercial terms (licence profile corporate)"}}},
            "abusech": {"status": "ok",
                        "entities": {IP: {"status": "ok"}, SEED: {"status": "empty"}},
                        "sources": {"abusech.urlhaus": {"status": "skipped", "reason_code": "licence", "reason": "skipped: license terms (licence profile corporate)"},
                                    "abusech.feodo": {"status": "ok"}}},
            "plain": {"status": "ok", "entities": {SEED: {"status": "ok"}}},
            "old_style": {"status": "skipped", "reason_code": "licence", "reason": "skipped: unknown terms (licence profile corporate)"},
        },
    )
    assert S.licence_lines(case) == [
        "any: old_style (unknown)",
        "domain: abusech.urlhaus (license)",
        "ipv4: abusech.urlhaus (license), shodan.internetdb (noncommercial)",
    ]
    assert S.licence_lines(v2_case()) == [] and S.licence_lines(v1_case()) == []


# ---------------------------------------------------------------------------------------- helpers


def test_followup_and_note_lines():
    case = v2_case(deferred=[{"module": "otx", "entity": SEED, "reason": "quota"}, {"module": "xon", "entity": SEED, "reason": "quota"}],
                   pending_personal=[{"entity": "email:a@corp.example", "parent": "text_blob:x", "relation": "mentions"},
                                     {"entity": "phone:+5511987654321", "parent": "text_blob:x", "relation": "mentions"}],
                   notes=["inconclusive: no source answered (1 run(s) could not verify) - a 'clean' risk level is not a verdict", "TLP raised to AMBER"])
    lines = S.followup_lines(case)
    assert lines[0] == "2 lookups deferred by provider quota: v3lum cases resume 20261126-140000-summ"
    assert lines[1].startswith("2 personal values found in the input not investigated automatically (1 email, 1 phone)")
    assert "a@corp.example" not in "\n".join(lines) and "987654321" not in "\n".join(lines)  # counts and types only
    assert S.note_lines(case) == ["inconclusive: no source answered (1 run(s) could not verify) - the risk level is not a verdict", "TLP raised to AMBER"]


def test_identity_links_and_confidence_labels():
    assert S.is_identity_link({"tags": ["identity"], "confidence_label": "possible"})
    assert S.is_identity_link({"rule": "identity_link_strength", "confidence": 0.4})
    assert not S.is_identity_link({"tags": ["identity"], "confidence_label": "probable"})
    assert not S.is_identity_link({"tags": ["phishing"], "confidence_label": "possible"})
    assert [S.confidence_label({"confidence": c}) for c in (0.9, 0.85, 0.6, 0.55, 0.2)] == ["confirmed", "confirmed", "probable", "probable", "possible"]
    assert S.confidence_label({"confidence_label": "PROBABLE", "confidence": 0.1}) == "probable"


def test_functions_are_pure():
    for case in (v2_case(), v1_case()):
        before = copy.deepcopy(case)
        _all_text(case)
        S.disclosure_summary(case)
        S.disclosure_by_entity(case)
        assert case == before
        json.dumps(case)


def test_strings_carry_no_control_characters():
    case = v2_case(meta={"header_notes": ["note\x1b[2J\x07"], "quota_lines": ["quota\x1b]0;x\x07"]},
                   skips={"not_default": ["a"]}, notes=["n\x1b[31m"])
    case["options"]["purpose"] = "p\x1b[31m"
    text = _all_text(case)
    assert "\x1b" not in text and "\x07" not in text


def test_contract_additions_names_resolve():
    """Every backticked v3lum name of docs/contract_additions/WP14.md is importable."""
    import importlib
    import re
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "docs" / "contract_additions" / "WP14.md").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`(v3lum\.[A-Za-z0-9_.]+)`", text)))
    assert names
    for name in names:
        parts = name.split(".")
        for cut in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:cut]))
            except ImportError:
                continue
            for attr in parts[cut:]:
                obj = getattr(obj, attr)
            break
        else:  # pragma: no cover - nothing importable
            raise AssertionError(name)


# ---------------------------------------------------------------------------------------- review additions

CPF = "52998224725"


def test_levels_and_contributor_labels_from_a_stored_case_are_sanitised():
    assert S.level_label("HIGH\x1b[2J") == "high[2j"  # controls removed (lower-cased like every level)
    assert "\x1b" not in S.level_label("\x1b]0;x\x07critical") and S.level_label(None) == S.NO_FINDINGS
    case = v2_case(findings=[{"id": "f1", "title": "Listed", "severity": "high", "confidence_label": "probable", "entity": SEED, "tags": []}])
    case["risk"] = {"score": 60.0, "level": "high", "entities": {SEED: {"score": 60.0, "level": "high"}},
                    "contributors": [{"finding_id": "f1", "words": "listed by a feed", "confidence_label": "[/b]\x1b[2Jpwned"}]}
    why = S.bottom_line(case)[1]
    assert "listed by a feed [PROBABLE]" in why and "pwned" not in why and "\x1b" not in why
    case["findings"][0]["severity"] = "high\x1b[2J"
    case["risk"].pop("contributors")
    assert "\x1b" not in "\n".join(S.bottom_line(case))


def test_cpfs_quoted_in_case_text_are_masked_unless_show_personal():
    case = v2_case(notes=[f"m on cpf:{CPF}: guard yielded", f"scan deadline (global timeout 5s) reached: partial results for cpf:{CPF}"],
                   meta={"header_notes": [f"reviewed with doc {CPF}"]},
                   findings=[{"id": "f1", "title": f"holder {CPF}", "severity": "high", "confidence_label": "confirmed", "entity": SEED, "tags": []}],
                   correlations=[{"id": "c1", "rule": "r", "title": "t", "severity": "high", "recommendation": f"check {CPF} by hand", "entities": [SEED]}])
    case["risk"] = {"score": 60.0, "level": "high", "entities": {SEED: {"score": 60.0, "level": "high"}}}
    text = "\n".join(S.header_lines(case) + S.bottom_line(case) + S.note_lines(case))
    assert CPF not in text and text.count("***.982.247-**") >= 5
    shown = "\n".join(S.header_lines(case, show_personal=True) + S.bottom_line(case, show_personal=True) + S.note_lines(case, show_personal=True))
    assert CPF in shown
    assert S.partial_notes(case) == ["scan deadline (global timeout 5s) reached: partial results for cpf:***.982.247-**"]


def test_entity_host():
    assert S.entity_host("url:https://Evil.Example./x?y") == "evil.example"
    assert S.entity_host("email:a@corp.example") == "corp.example"
    assert S.entity_host("domain:example.com") == "example.com" and S.entity_host("ipv6:2001:db8::1") == "2001:db8::1"
    assert S.entity_host("cpf:" + CPF) == "" and S.entity_host("") == ""
