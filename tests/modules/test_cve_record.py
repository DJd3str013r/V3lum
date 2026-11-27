"""cve_record (P183): MITRE CVE Services + NVD 2.0 + CWE names, the shared CVE 5 parser, the CVE fan-out
rule and the consolidated CVE card (rule g08_cve_card).

Fixtures in tests/fixtures/cve_record/ (prep batch p1-G08-1, recorded 2026-11-26): cveawg
``cveawg_log4shell.json`` (CNA + CISA ADP: CVSS, SSVC, KEV relay; credits and individual researchers'
references removed) and ``cveawg_heartbleed.json`` (CNA 'n/a', CVSS/CWE only in the ADP container),
``cveawg_not_found_404.http.json`` (CVE_RECORD_DNE), the synthetic ``cveawg_rejected_synthetic.json``;
NVD ``nvd_log4shell.json`` (3 configurations, 11 references, role mailboxes of organisations only),
``nvd_empty.json``, ``nvd_bad_param_404.http.json`` (reason only in the 'message' header),
``nvd_rolling_window_403_synthetic.http.json``, ``nvd_challenge_403.http.json`` (a real Cloudflare
template, tokens replaced), ``nvd_truncated.txt``; CWE catalogue ``cwe_catalog_ok.xml(.zip)`` (15 real
entries of CWE 5.0) and the synthetic ``cwe_catalog_entity_synthetic.xml`` (DTD/ENTITY expansion).
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, define_module, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.correlate import load_rules
from v3lum.core.datasets import DATASETS
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.modules.vulnerability_cve import cve_record as mod
from v3lum.modules.vulnerability_cve.cve_record import (
    CASE_COUNTERS,
    CVE_FANOUT_SETTING,
    CWE_DATASET,
    CWE_XML_URL,
    NVD_CASE_BUDGET_SETTING,
    NVD_NOTICE,
    CveRecord,
    cr15_severity_cap,
    cve5_attributes,
    parse_cve5_record,
    parse_cwe_catalog,
    parse_nvd_cves,
    patch_priority,
    plan_cve_fanout,
    read_zip_member,
    register_cve_mirror,
    unregister_cve_mirror,
)

CVE = "CVE-2021-44228"
CVEAWG = "https://cveawg.mitre.org/api/cve/{cve}"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
LOG4SHELL = module_fixture(CveRecord, "cveawg_log4shell.json")
HEARTBLEED = module_fixture(CveRecord, "cveawg_heartbleed.json")
REJECTED = module_fixture(CveRecord, "cveawg_rejected_synthetic.json")
NVD_LOG4SHELL = module_fixture(CveRecord, "nvd_log4shell.json")
CHALLENGE = module_fixture(CveRecord, "nvd_challenge_403.http.json")["response"]
CWE_ZIP = (FIXTURES / "cve_record" / "cwe_catalog_ok.xml.zip").read_bytes()


@pytest.fixture(autouse=True)
def fresh_counters():
    CASE_COUNTERS.reset()
    yield
    CASE_COUNTERS.reset()


def seed_http(cve: str = CVE, cveawg=LOG4SHELL, nvd=NVD_LOG4SHELL) -> FakeHttp:
    http = FakeHttp().add("GET", CVEAWG.format(cve=cve), json=cveawg)
    return http.add("GET", NVD.format(cve=cve), json=nvd) if nvd is not None else http


def strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in strings(k) + strings(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in strings(v)]
    return []


# ------------------------------------------------------------------ metadata (P183 council values)
def test_metadata_matches_the_council():
    cls = CveRecord
    assert (cls.disclosure, cls.provider, cls.terms, cls.default_enabled) == ("third_party", "mitre", "open", True)
    assert cls.hosts == ("cveawg.mitre.org", "services.nvd.nist.gov")  # NVD web pages: links only
    assert cls.sources == ("mitre.cve_services", "nist_nvd.cve_api", "mitre.cve_record_cwe_catalog")
    assert cls.trust_tier == "trusted" and cls.providers == frozenset({"mitre", "nist_nvd"})
    assert cls.optional_keys == ("nvd",) and cls.cache_ttl == 86400 and cls.max_requests == 2
    assert NVD_NOTICE in cls.notice and NVD_NOTICE == "This product uses data from the NVD API but is not endorsed or certified by the NVD."
    assert cls.settings[CVE_FANOUT_SETTING].default == 20 and cls.settings[NVD_CASE_BUDGET_SETTING].default == 10
    from v3lum.config import key_registry

    assert "V3LUM_NVD_KEY" in key_registry()["nvd"].env  # one key per provider, team account alias
    reg = DATASETS[CWE_DATASET]
    assert reg["url"] == CWE_XML_URL and reg["source"] == "mitre.cve_record_cwe_catalog" and reg["terms_class"] == "open"


# ------------------------------------------------------------------ seed CVE: cveawg + NVD (cond 1, 5)
def test_seed_cve_gets_the_record_cpe_configurations_and_provenance():
    http = seed_http()
    res = run_module(CveRecord, f"cve:{CVE}", http)
    assert res.status is Status.OK and res.requests == 2
    a = res.attributes
    assert a["cve_state"] == "PUBLISHED" and a["cve_assigner"] == "apache" and a["cve_published"] == "2021-12-10"
    assert a["cve_title"].startswith("Apache Log4j2 JNDI features")
    assert a["cvss"] == 10.0 and a["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    sources = [(c["source"], c["version"]) for c in a["cvss_scores"]]
    assert sources[0] == ("NVD", "3.1")  # NVD Primary first (the CNA gave a text severity only)
    assert ("CISA-ADP", "3.1") in sources and sources.count(("CISA-ADP", "3.1")) == 1  # one entry for cveawg + NVD alias
    assert ("NVD", "2.0") in sources
    assert a["cwe"] == ["CWE-502", "CWE-400", "CWE-20", "CWE-917"]
    assert a["ssvc"]["exploitation"] == "active" and a["exploited"] == {"CISA-ADP SSVC": "2025-02-04"}
    assert a["kev"] is True and a["kev_date_added"] == "2021-12-10" and a["kev_due_date"] == "2021-12-24"  # CISA relays
    assert a["exploit_available"] is True and a["exploit_count"] == 3 and all("packetstormsecurity" in u for u in a["exploit_refs"])
    assert any("cisco-sa-apache-log4j" in u for u in a["vendor_advisories"])
    fixed = {(f["product"], f["fixed"]) for f in a["fixed_versions"]}
    assert ("Apache Software Foundation Apache Log4j2", "2.15.0") in fixed and ("apache:log4j", "2.3.1") in fixed
    assert a["affected"][0]["product"] == "Apache Log4j2" and a["cpe_total"] == 11
    siemens = [c for c in a["cpe_matches"] if c.get("vendor") == "siemens"]
    assert siemens and siemens[0]["running_on"] == ["cpe:2.3:h:siemens:6bk1602-0aa12-0tp0:-:*:*:*:*:*:*:*"]
    assert a["nvd_status"] == "Analyzed" and a["data_notices"] == [NVD_NOTICE]  # the NVD notice travels with NVD data
    assert not any("@" in s for s in strings(a))  # NVD role mailboxes become organisation names, never addresses
    assert not res.findings  # facts for the card, no separate findings (cond 5)
    kw = [p for p in res.pivots if p.entity.type is T.KEYWORD]
    assert [p.entity.value for p in kw] == ["Apache Software Foundation Apache Log4j2"]
    assert kw[0].relation == "affects" and kw[0].expand is False  # never a fan-out to products
    assert ("CVE record (cve.org)", f"https://www.cve.org/CVERecord?id={CVE}") in res.links
    assert ("NVD vulnerability detail (web page)", f"https://nvd.nist.gov/vuln/detail/{CVE}") in res.links
    assert "credits" not in json.dumps(res.raw)  # evidence keeps no names of natural persons
    http.assert_hosts_within(CveRecord)


def test_pivot_cve_reads_cveawg_only():
    http = seed_http(nvd=None)
    res = run_module(CveRecord, f"cve:{CVE}", http, is_seed=False, depth=1, case_id="case-pivot")
    assert res.status is Status.OK and res.requests == 1
    assert "nvd_status" not in res.attributes and "data_notices" not in res.attributes
    assert res.attributes["cvss_scores"][0]["source"] == "CISA-ADP"


def test_pivot_from_an_org_asset_gets_nvd():
    http = seed_http()
    res = run_module(
        CveRecord, f"cve:{CVE}", http, is_seed=False, depth=1, case_id="case-asset",
        provenance=[("ipv4:203.0.113.10", "has_vuln", "shodan_internetdb")],
        org_profile={"org": {"name": "Corp"}, "cidrs": ["203.0.113.0/24"]},
    )
    assert res.requests == 2 and res.attributes["nvd_status"] == "Analyzed"


def test_nvd_key_is_sent_as_header_and_never_leaks():
    key = "nvd-test-key-0123456789abcdef"
    http = FakeHttp().add("GET", CVEAWG.format(cve=CVE), json=LOG4SHELL)
    http.add("GET", NVD.format(cve=CVE), json=NVD_LOG4SHELL, match_headers={"apiKey": key})
    res = run_module(CveRecord, f"cve:{CVE}", http, keys={"nvd": key}, is_seed=False, depth=1, case_id="case-key")
    assert res.requests == 2 and res.attributes["nvd_status"] == "Analyzed"  # the key alone justifies NVD (cond 1)
    from tests.fakes import assert_no_secret

    assert_no_secret(key, res.to_dict(), res.raw, res.error)


def test_legacy_record_with_cna_na_uses_the_adp_container():
    http = seed_http("CVE-2014-0160", HEARTBLEED, nvd=None)
    res = run_module(CveRecord, "cve:CVE-2014-0160", http, is_seed=False, depth=1, case_id="case-legacy")
    a = res.attributes
    assert "affected" not in a  # 'n/a' vendor/product are not products
    assert a["cvss"] == 7.5 and a["cvss_scores"][0]["source"] == "CISA-ADP" and a["cwe"] == ["CWE-125"]
    assert a["kev"] is True and a["kev_date_added"] == "2022-05-04"
    assert not [p for p in res.pivots if p.entity.type is T.KEYWORD]


# ------------------------------------------------------------------ absences and REJECTED (cond 4)
def test_unassigned_id_is_a_documented_absence():
    dne = module_fixture(CveRecord, "cveawg_not_found_404.http.json")["response"]
    http = FakeHttp().add("GET", CVEAWG.format(cve="CVE-2021-9999999"), status=404, text=dne["body"], headers=dne["headers"])
    res = run_module(CveRecord, "cve:CVE-2021-9999999", http, is_seed=False, depth=1, case_id="case-dne")
    assert res.status is Status.EMPTY and "CVE_RECORD_DNE" in res.error
    http2 = FakeHttp().add("GET", CVEAWG.format(cve="CVE-2021-9999999"), status=404, text=dne["body"])
    http2.add("GET", NVD.format(cve="CVE-2021-9999999"), json=module_fixture(CveRecord, "nvd_empty.json"))
    seed = run_module(CveRecord, "cve:CVE-2021-9999999", http2)
    assert seed.status is Status.EMPTY and seed.source_statuses["nist_nvd.cve_api"]["status"] == "empty"


def test_rejected_record_is_information_never_scored():
    http = seed_http("CVE-2099-0001", REJECTED, nvd=None)
    res = run_module(CveRecord, "cve:CVE-2099-0001", http, is_seed=False, depth=1, case_id="case-rej")
    assert res.attributes["cve_state"] == "REJECTED" and "duplicate of CVE-2099-0002" in res.attributes["cve_rejected_reason"]
    assert [f.severity for f in res.findings] == [Severity.INFO]
    assert {"info", "context_only"} <= set(res.findings[0].tags)
    assert [(p.entity.value, p.relation) for p in res.pivots if p.entity.type is T.CVE] == [("CVE-2099-0002", "related")]
    assert patch_priority({"scorable": False, "state": "REJECTED", "kev": {"listed": True}})["label"] == "no action"


# ------------------------------------------------------------------ status mapping (rule 5, P321)
def test_cveawg_429_and_challenge_are_could_not_verify():
    http = FakeHttp().add("GET", CVEAWG.format(cve=CVE), status=429, text="slow down")
    res = run_module(CveRecord, f"cve:{CVE}", http, is_seed=False, depth=1, case_id="case-429")
    assert res.status is Status.RATE_LIMITED and not res.attributes.get("cve_state")
    http2 = FakeHttp().add("GET", CVEAWG.format(cve=CVE), status=403, text=CHALLENGE["body"], headers=CHALLENGE["headers"])
    res2 = run_module(CveRecord, f"cve:{CVE}", http2, is_seed=False, depth=1, case_id="case-403")
    assert res2.status is Status.BLOCKED and res2.reason_code == "challenge"


def test_cveawg_outage_and_unexpected_answers_are_never_empty():
    http = FakeHttp().add("GET", CVEAWG.format(cve=CVE), status=503, text="unavailable")
    assert run_module(CveRecord, f"cve:{CVE}", http, is_seed=False, depth=1, case_id="case-503").status is Status.ERROR
    for body in ([], "text", {"cveMetadata": {"cveId": "nope"}}):
        http = FakeHttp().add("GET", CVEAWG.format(cve=CVE), json=body)
        res = run_module(CveRecord, f"cve:{CVE}", http, is_seed=False, depth=1, case_id="case-odd")
        assert res.status is Status.ERROR and "could not verify" in res.error, body
    http = FakeHttp().add("GET", CVEAWG.format(cve=CVE), text="{\"dataType\": \"CVE_RECORD\", \"cveMeta", headers={"content-type": "application/json"})
    assert run_module(CveRecord, f"cve:{CVE}", http, is_seed=False, depth=1, case_id="case-trunc").status is Status.ERROR


def test_cveawg_failure_on_a_seed_keeps_the_nvd_answer():
    http = FakeHttp().add("GET", CVEAWG.format(cve=CVE), status=429, text="slow down")
    http.add("GET", NVD.format(cve=CVE), json=NVD_LOG4SHELL)
    res = run_module(CveRecord, f"cve:{CVE}", http)
    assert res.status is Status.OK and res.attributes["nvd_status"] == "Analyzed" and res.attributes["cve_state"] == "PUBLISHED"
    assert res.source_statuses["mitre.cve_services"]["status"] == "rate_limited"


@pytest.mark.parametrize(("fixture", "status", "code"), [
    ("nvd_rolling_window_403_synthetic.http.json", "rate_limited", "rate_limited"),  # provider marker: NVD's own signal
    ("nvd_challenge_403.http.json", "blocked", "challenge"),  # a Cloudflare challenge stays a challenge
    ("nvd_bad_param_404.http.json", "error", "error"),  # reason only in the 'message' header
])
def test_nvd_failures_never_hide_the_cveawg_record(fixture, status, code):
    resp = module_fixture(CveRecord, fixture)["response"]
    http = FakeHttp().add("GET", CVEAWG.format(cve=CVE), json=LOG4SHELL)
    http.add("GET", NVD.format(cve=CVE), status=resp["status"], text=resp["body"], headers=resp["headers"])
    res = run_module(CveRecord, f"cve:{CVE}", http)
    assert res.status is Status.OK and res.attributes["cve_state"] == "PUBLISHED"
    row = res.source_statuses["nist_nvd.cve_api"]
    assert (row["status"], row["reason_code"]) == (status, code)
    assert "nvd_status" not in res.attributes and "data_notices" not in res.attributes
    if fixture.startswith("nvd_bad_param"):
        assert "Invalid cveId parameter." in row["reason"]


def test_nvd_truncated_and_refused_key():
    truncated = (FIXTURES / "cve_record" / "nvd_truncated.txt").read_text(encoding="utf-8")
    http = FakeHttp().add("GET", CVEAWG.format(cve=CVE), json=LOG4SHELL)
    http.add("GET", NVD.format(cve=CVE), text=truncated, headers={"content-type": "application/json"})
    res = run_module(CveRecord, f"cve:{CVE}", http)
    assert res.status is Status.OK and res.source_statuses["nist_nvd.cve_api"]["status"] == "error"
    http2 = FakeHttp().add("GET", CVEAWG.format(cve=CVE), json=LOG4SHELL)
    http2.add("GET", NVD.format(cve=CVE), status=404, body=b"", headers={"message": "Invalid apiKey"})
    res2 = run_module(CveRecord, f"cve:{CVE}", http2, keys={"nvd": "nvd-bad-key-0000000000"})
    assert res2.source_statuses["nist_nvd.cve_api"]["status"] == "needs_key"


# ------------------------------------------------------------------ budgets (cond 2, 3)
def test_keyless_nvd_case_budget():
    http = seed_http("CVE-2021-44228")
    http.add("GET", CVEAWG.format(cve="CVE-2014-0160"), json=HEARTBLEED)
    settings = {NVD_CASE_BUDGET_SETTING: 1}
    first = run_module(CveRecord, f"cve:{CVE}", http, settings=settings, case_id="case-nvd")
    assert first.requests == 2
    second = run_module(CveRecord, "cve:CVE-2014-0160", http, settings=settings, case_id="case-nvd")
    assert second.status is Status.OK and second.requests == 1
    assert second.source_statuses["nist_nvd.cve_api"]["status"] == "quota"


def test_fanout_budget_defers_pivot_cves_never_seeds():
    http = seed_http(nvd=None)
    settings = {CVE_FANOUT_SETTING: 1}
    assert run_module(CveRecord, f"cve:{CVE}", http, settings=settings, is_seed=False, depth=1, case_id="case-fo").status is Status.OK
    deferred = run_module(CveRecord, "cve:CVE-2014-0160", FakeHttp(), settings=settings, is_seed=False, depth=1, case_id="case-fo")
    assert deferred.status is Status.QUOTA and deferred.reason_code == "quota" and deferred.requests == 0
    assert "fan-out budget" in deferred.error and "offline" in deferred.error
    seed = run_module(CveRecord, "cve:CVE-2014-0160", seed_http("CVE-2014-0160", HEARTBLEED), settings=settings, case_id="case-fo")
    assert seed.status is Status.OK


def test_fanout_ranking_puts_kev_and_epss_first():
    plan = plan_cve_fanout(["CVE-2024-0001"], ["CVE-2020-0001", "CVE-2021-44228", "CVE-2022-0002", "CVE-2024-0001"], budget=2,
                           kev_ids=["CVE-2021-44228"], epss_scores={"CVE-2022-0002": 0.4, "CVE-2020-0001": 0.01})
    assert plan["online"] == ["CVE-2024-0001", "CVE-2021-44228", "CVE-2022-0002"] and plan["deferred"] == ["CVE-2020-0001"]


# ------------------------------------------------------------------ CWE names from the dataset (cond 2)
def test_cwe_names_come_from_the_registered_catalogue(monkeypatch):
    monkeypatch.setitem(DATASETS[CWE_DATASET], "min_bytes", 10)
    monkeypatch.setattr(mod, "CWE_MIN_ENTRIES", 1)
    http = FakeHttp().add("GET", CWE_XML_URL, body=CWE_ZIP, times=1)
    rt = make_runtime(http)
    assert rt.data.update(CWE_DATASET).status == "updated"  # `v3lum data update cwe_catalog`, never per CVE
    http.add("GET", CVEAWG.format(cve=CVE), json=LOG4SHELL)
    res = run_module(CveRecord, f"cve:{CVE}", runtime=rt, is_seed=False, depth=1, case_id="case-cwe")
    assert res.attributes["cwe_names"] == ["CWE-502 Deserialization of Untrusted Data", "CWE-400 Uncontrolled Resource Consumption",
                                           "CWE-20 Improper Input Validation"]
    assert not any("cwe-api.mitre.org" in u for u in http.urls())
    assert CWE_DATASET in [d["name"] for d in res.datasets]
    from v3lum.core.context import ModuleState

    cached = ModuleState("cve_record").get("cwe_names")  # the derived index survives the process (ctx.state)
    assert cached["names"]["CWE-264"] == "Permissions, Privileges, and Access Controls" and len(cached["sha"]) == 16


def test_cwe_catalogue_parser_refuses_entities_and_bombs():
    parsed, reason = parse_cwe_catalog((FIXTURES / "cve_record" / "cwe_catalog_ok.xml").read_bytes())
    assert reason is None and parsed["meta"]["version"] == "5.0" and parsed["meta"]["entries"] == 16
    assert parsed["entries"]["CWE-264"] == {"name": "Permissions, Privileges, and Access Controls", "kind": "category", "status": "Obsolete"}
    refused, why = parse_cwe_catalog((FIXTURES / "cve_record" / "cwe_catalog_entity_synthetic.xml").read_bytes())
    assert refused is None and "DTD/ENTITY" in why
    assert parse_cwe_catalog(b"<not-xml")[0] is None and parse_cwe_catalog(b"<Other/>")[0] is None
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("cwec_v9.xml", b"<a>" + b" " * 3_000_000 + b"</a>")
    assert "compression ratio" in read_zip_member(bomb.getvalue())[1]
    two = io.BytesIO()
    with zipfile.ZipFile(two, "w") as zf:
        zf.writestr("a.xml", "<a/>")
        zf.writestr("b.xml", "<b/>")
    assert "exactly one .xml member" in read_zip_member(two.getvalue())[1]
    assert read_zip_member(CWE_ZIP)[1] is None


# ------------------------------------------------------------------ keyword input (key 'nvd' only)
def test_keyword_needs_the_nvd_key():
    http = FakeHttp()
    res = run_module(CveRecord, "keyword:log4j", http)
    assert res.status is Status.SKIPPED and res.reason_code == "config" and http.calls == []
    key = "nvd-test-key-0123456789abcdef"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=log4j&resultsPerPage=20"
    http2 = FakeHttp().add("GET", url, json=NVD_LOG4SHELL, match_headers={"apiKey": key})
    res2 = run_module(CveRecord, "keyword:log4j", http2, keys={"nvd": key})
    assert res2.status is Status.OK and res2.attributes["cve_matches"] == [{"cve": CVE, "cvss": 10.0, "published": "2021-12-10", "state": "PUBLISHED"}]
    assert [(p.entity.value, p.expand) for p in res2.pivots] == [(CVE, False)]


# ------------------------------------------------------------------ P352 hook: mirror first (cond 1)
def test_registered_mirror_is_read_before_cveawg():
    register_cve_mirror("t_mirror", lambda ctx, cve: LOG4SHELL if cve == CVE else None)
    try:
        http = FakeHttp()
        res = run_module(CveRecord, f"cve:{CVE}", http, is_seed=False, depth=1, case_id="case-mirror")
        assert res.status is Status.OK and res.requests == 0 and res.raw["cve5_origin"] == "t_mirror"
    finally:
        unregister_cve_mirror("t_mirror")


# ------------------------------------------------------------------ shared parser + CR15 reference
def test_shared_parser_and_normaliser_are_defensive():
    for junk in (None, [], "x", {"cveMetadata": {}}, {"cveMetadata": {"cveId": "CVE-12"}}):
        assert parse_cve5_record(junk) is None
    weird = {"cveMetadata": {"cveId": "cve-2024-12345", "state": "PUBLISHED"},
             "containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": "11"}}, {"cvssV3_1": {"baseScore": 5, "vectorString": 3}}],
                                    "affected": "x", "references": [{"url": "javascript:alert(1)"}, 7]}}}
    rec = parse_cve5_record(weird)
    assert rec["cve"] == "CVE-2024-12345" and [c["score"] for c in rec["cvss"]] == [5.0]
    assert rec["references"] == [] and cve5_attributes(rec)["cvss"] == 5.0
    assert "kev" not in cve5_attributes(parse_cve5_record(LOG4SHELL), include_kev=False)  # non-CISA relays (P181)
    assert parse_nvd_cves({"vulnerabilities": "x"})["reason"]


@pytest.mark.parametrize(("kev", "epss", "verified", "own", "inferred", "cap"), [
    (True, None, True, True, False, "critical"),
    (True, None, False, True, True, "high"),
    (False, 0.2, False, True, True, "medium"),
    (True, 0.9, True, False, False, "info"),
    (False, 0.01, True, True, False, "high"),
])
def test_cr15_reference(kev, epss, verified, own, inferred, cap):
    assert cr15_severity_cap(kev, epss, verified, own, inferred)["cap"] == cap


@pytest.mark.parametrize(("card", "line"), [
    ({"kev": {"listed": True}, "epss": {"score": 0.97}}, "KEV + EPSS 0.97: patch now"),
    ({"kev": {"listed": True, "ransomware_known": True}}, "KEV (known ransomware use): patch now"),
    ({"epss": {"score": 0.6, "percentile": 0.99}}, "EPSS 0.60 (top 1%): patch urgently"),
    ({"epss": {"score": 0.02, "percentile": 0.96}}, "EPSS 0.02 (top 5%): patch soon"),
    ({"cvss": 9.8}, "CVSS 9.8: patch soon (high impact, exploitation not yet likely)"),
    ({}, "no KEV/EPSS answer: normal patch cycle (exploitation signals could not be verified)"),
])
def test_patch_priority_line(card, line):
    assert patch_priority(card)["line"] == line


# ------------------------------------------------------------------ the batch test (P183 cond 6)
def test_five_cve_modules_give_one_card_and_no_critical_case_level(clean_registry, monkeypatch):
    """cisa_kev, epss, epss_api, cve_record and a CIRCL-style CVE 5 source (the shared parser, P181) on
    one CVE: one CVE node, one card, the patch-priority line, and no CRITICAL case level."""
    from v3lum.modules.vulnerability_cve import cisa_kev as kev_mod
    from v3lum.modules.vulnerability_cve import epss as epss_mod
    from v3lum.modules.vulnerability_cve.cisa_kev import KEV_DATASET, KEV_FEED_URL
    from v3lum.modules.vulnerability_cve.epss import EPSS_CSV_URL, EPSS_DATASET

    monkeypatch.setitem(DATASETS[KEV_DATASET], "min_bytes", 100)
    monkeypatch.setattr(kev_mod, "KEV_MIN_ENTRIES", 1)
    monkeypatch.setitem(DATASETS[EPSS_DATASET], "min_bytes", 10)
    monkeypatch.setattr(epss_mod, "EPSS_MIN_ROWS", 1)

    def circl_like(self, entity, ctx):  # stands in for P181: CIRCL serves the same CVE 5 schema
        res = self.result(entity)
        for key, value in cve5_attributes(parse_cve5_record(LOG4SHELL)).items():
            res.attr(key, value)
        return res

    define_module("t_circl_like", {T.CVE}, circl_like, category="vulnerability_cve")
    # the local EPSS file of 2026-11-25 does not score Log4Shell; the scan runs on 2026-11-28, so
    # epss reports 'no score in the file' and epss_api asks FIRST (cond 2)
    lines = (FIXTURES / "epss" / "bulk_ok.csv").read_text(encoding="utf-8").splitlines()
    import gzip

    epss_gz = gzip.compress(("\n".join(line for line in lines if CVE not in line) + "\n").encode())
    hop = module_fixture("epss", "redirect_dated_302.http.json")["response"]
    http = FakeHttp()
    http.add("GET", KEV_FEED_URL, json=module_fixture("cisa_kev", "catalog_ok.json"))
    http.add("GET", EPSS_CSV_URL, status=hop["status"], headers=hop["headers"])
    http.add("GET", "https://epss.empiricalsecurity.com/epss_scores-2026-11-25.csv.gz", body=epss_gz)
    http.add("GET", CVEAWG.format(cve=CVE), json=LOG4SHELL)
    http.add("GET", NVD.format(cve=CVE), json=NVD_LOG4SHELL)
    http.add("GET", f"https://api.first.org/data/v1/epss?cve={CVE}", json=module_fixture("epss_api", "ok.json"))
    rt = make_runtime(http, clock=FakeClock(datetime(2026, 11, 28, 15, 0, tzinfo=timezone.utc)))
    assert rt.data.update(KEV_DATASET).ok and rt.data.update(EPSS_DATASET).ok  # `v3lum data update --essential`
    load_rules()
    modules = {"cisa_kev", "epss", "epss_api", "cve_record", "t_circl_like"}
    case = Engine(rt, ScanOptions(include=modules, depth=1)).investigate([Entity.make(T.CVE, CVE)])

    cve_nodes = case.graph.of_type(T.CVE)
    assert [n.key for n in cve_nodes] == [f"cve:{CVE}"]
    node = cve_nodes[0]
    contributors = {m for values in node.attributes.values() for _v, m in values}
    assert modules <= contributors  # five modules, one node, provenance per fact
    assert {r.module: r.status for r in case.results if r.module in modules} == {
        "cisa_kev": Status.OK, "epss": Status.EMPTY, "epss_api": Status.OK, "cve_record": Status.OK, "t_circl_like": Status.OK}
    cards = [c for c in case.correlations if c.rule == "g08_cve_card"]
    assert len(cards) == 1 and cards[0].severity is Severity.INFO
    assert cards[0].title == f"{CVE}: KEV (known ransomware use) + EPSS 0.99+: patch now"
    evidence = "\n".join(cards[0].evidence)
    assert "[cisa_kev, cve_record]" in evidence and "[epss_api]" in evidence and "t_circl_like (not CISA KEV)" in evidence
    assert NVD_NOTICE in cards[0].description
    assert not [f for f in case.findings if f.severity >= Severity.LOW]  # facts, not separate findings
    assert case.risk["level"] != "critical" and not [c for c in case.correlations if c.severity >= Severity.HIGH]


def test_default_scan_of_a_cve_seed_runs_the_cve_modules(monkeypatch):
    """No -M: the policy gate's default set runs the four modules (default_enabled True); the KEV
    catalogue (1.9 MB) is fetched during the scan, the large EPSS file never is (UNAVAILABLE 'dataset'),
    so epss_api answers for the seed; one INFO card, no CRITICAL case level."""
    from v3lum.modules.vulnerability_cve import cisa_kev as kev_mod
    from v3lum.modules.vulnerability_cve.cisa_kev import KEV_DATASET, KEV_FEED_URL

    monkeypatch.setitem(DATASETS[KEV_DATASET], "min_bytes", 100)
    monkeypatch.setattr(kev_mod, "KEV_MIN_ENTRIES", 1)
    http = FakeHttp()
    http.add("GET", KEV_FEED_URL, json=module_fixture("cisa_kev", "catalog_ok.json"))
    http.add("GET", CVEAWG.format(cve=CVE), json=LOG4SHELL)
    http.add("GET", NVD.format(cve=CVE), json=NVD_LOG4SHELL)
    http.add("GET", f"https://api.first.org/data/v1/epss?cve={CVE}", json=module_fixture("epss_api", "ok.json"))
    rt = make_runtime(http)
    load_rules()
    case = Engine(rt, ScanOptions()).investigate([Entity.make(T.CVE, CVE)])
    mine = {r.module: (r.status, r.reason_code) for r in case.results if r.module in {"cisa_kev", "epss", "epss_api", "cve_record"}}
    assert mine["cisa_kev"] == (Status.OK, "") and mine["cve_record"] == (Status.OK, "") and mine["epss_api"] == (Status.OK, "")
    epss_row = mine.get("epss") or (Status(case.coverage["epss"]["status"]), case.coverage["epss"].get("reason_code", ""))
    assert epss_row == (Status.UNAVAILABLE, "dataset")  # large: `v3lum data update epss_scores`, never mid-scan
    cards = [c for c in case.correlations if c.rule == "g08_cve_card"]
    assert len(cards) == 1 and cards[0].title == f"{CVE}: KEV (known ransomware use) + EPSS 0.99+: patch now"
    assert case.risk["level"] != "critical"


def test_network_timeouts_are_could_not_verify():
    from v3lum.core.http import NetworkError

    http = FakeHttp().add("GET", CVEAWG.format(cve=CVE), error=NetworkError("read timed out (cveawg.mitre.org)"))
    res = run_module(CveRecord, f"cve:{CVE}", http, is_seed=False, depth=1, case_id="case-timeout")
    assert res.status is Status.ERROR and "could not verify" in res.error and not res.attributes.get("cve_state")
    http2 = FakeHttp().add("GET", CVEAWG.format(cve=CVE), json=LOG4SHELL)
    http2.add("GET", NVD.format(cve=CVE), error=NetworkError("read timed out (services.nvd.nist.gov)"))
    seed = run_module(CveRecord, f"cve:{CVE}", http2)
    assert seed.status is Status.OK and seed.source_statuses["nist_nvd.cve_api"]["status"] == "error"
