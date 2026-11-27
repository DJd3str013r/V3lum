"""siem_search (P349): internal SIEM look-back through SOC-approved templates.

Fixtures in tests/fixtures/siem_search/ are SYNTHETIC (A12 / P349 C7: the SIEM is a self-hosted
internal platform that the build egress cannot reach): OpenSearch/Elasticsearch ``_search`` answers
and error envelopes shaped on the OpenSearch search API reference and the Elasticsearch 8.x error
format, Splunk REST 10.6 saved-search dispatch / job / results answers. Documentation values only
(198.51.100.x, *.example.com, the placeholder service account ``svc-v3lum-ro``, ``user0042``).
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import parse_qs

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.cti_framework import siem_search as ss
from v3lum.modules.cti_framework.siem_search import SiemSearch

ES = "https://siem.example.com:9200"
SPLUNK = "https://splunk.example.com:8089"
KEY = "siem-test-token-0123456789abcdef"
KEYS = {"siem": KEY}
ES_PARAMS = "ignore_unavailable=true&allow_no_indices=true&allow_partial_search_results=false"
ES_IP_URL = f"{ES}/logs-proxy-*,logs-dns-*/_search?{ES_PARAMS}"
IP = "198.51.100.23"
NS = f"{SPLUNK}/servicesNS/nobody/soc_v3lum"
SID = "svc-v3lum-ro__svc-v3lum-ro__soc_v3lum__v3lum_ioc_ip_at_1795675260_4242"
DISPATCH_URL = f"{NS}/saved/searches/v3lum_ioc_ip/dispatch"
JOB_URL = f"{NS}/search/jobs/{SID}?output_mode=json"
RESULTS_URL = f"{NS}/search/v2/jobs/{SID}/results?output_mode=json&count=1000"
DEF_URL = f"{NS}/saved/searches/v3lum_ioc_ip?output_mode=json"


def fx(name):
    return module_fixture(SiemSearch, name)


def add_fx(http, method, url, name, *, times=None, match_headers=None):
    """Route one fixture: '*.http.json' exchanges keep their status, headers and body."""
    kw = {"times": times, "match_headers": match_headers}
    if name.endswith(".http.json"):
        resp = fx(name)["response"]
        body, headers = resp["body"], resp.get("headers") or {}
        if isinstance(body, (dict, list)):
            return http.add(method, url, status=resp["status"], json=body, headers=headers, **kw)
        return http.add(method, url, status=resp["status"], body=body.encode(), headers=headers, **kw)
    if name.endswith(".json"):
        return http.add(method, url, json=fx(name), **kw)
    ctype = "application/xml" if name.endswith(".xml") else "application/json"
    return http.add(method, url, body=fx(name).encode(), headers={"content-type": ctype}, **kw)


@pytest.fixture
def es_templates(tmp_path):
    return _templates(tmp_path, "templates_approved_es.json")


@pytest.fixture
def splunk_templates(tmp_path):
    return _templates(tmp_path, "templates_approved_splunk.json")


def _templates(tmp_path, name, mode=0o600, doc=None):
    path = tmp_path / name
    path.write_text(json.dumps(doc if doc is not None else fx(name)), encoding="utf-8")
    os.chmod(path, mode)
    return str(path)


def es_settings(path, **extra):
    return {"siem_url": ES, "siem_search_templates": path, **extra}


def splunk_settings(path, **extra):
    return {"siem_url": SPLUNK, "siem_search_templates": path, **extra}


def run(http, entity, settings, **kw):
    kw.setdefault("keys", KEYS)
    return run_module(SiemSearch, entity, http, settings=settings, **kw)


def body_of(call):
    return json.loads(call["body"])


def form_of(call):
    raw = call["body"].decode() if isinstance(call["body"], bytes) else call["body"]
    return {k: v[0] for k, v in parse_qs(raw).items()}


def blob(res):
    return json.dumps({"findings": [f.to_dict() for f in res.findings], "attributes": res.attributes, "raw": res.raw,
                       "pivots": [p.entity.value for p in res.pivots], "error": res.error}, default=str)


# ------------------------------------------------------------------ C1: metadata
def test_contract_metadata():
    cls = SiemSearch
    assert (cls.name, cls.category, cls.disclosure, cls.provider, cls.sources, cls.hosts) == (
        "siem_search", "cti_framework", "internal", "internal_siem", ("internal_siem.search",), ())
    assert cls.default_enabled is False and cls.terms == "open" and cls.trust_tier == "n/a"
    assert cls.max_tlp.value_str == "red" and cls.shares_input is False
    assert cls.requires_keys == ("siem",) and cls.cache_ttl == 0 and cls.max_pivots == 0 and not cls.produces
    assert cls.timeout <= 30 and cls.max_requests == 11 and cls.min_interval >= 1.0
    assert {"siem_url", "siem_search_templates", "siem_search_timeout", "siem_search_window_days"} <= set(cls.settings)
    assert {t.value for t in cls.accepts} == set(ss.INPUT_TYPES)


# ------------------------------------------------------------------ C4/C5: OpenSearch / Elasticsearch
def test_es_seen_in_our_logs(es_templates):
    http = FakeHttp()
    add_fx(http, "POST", ES_IP_URL, "es_ok.json", match_headers={"Authorization": f"ApiKey {KEY}"})
    res = run(http, f"ipv4:{IP}", es_settings(es_templates))
    assert res.status is Status.OK
    sighting = res.attributes["siem_sighting"]
    assert sighting["count"] == 42 and sighting["first_seen"] == "2026-10-28T09:14:03Z" and sighting["last_seen"] == "2026-11-25T13:12:44Z"
    assert sighting["line"] == "seen in our logs: 42 events, first 2026-10-28, last 2026-11-25 (last 30 days, logs-proxy-*, logs-dns-*)"
    assert sighting["template_id"] == "ioc_ip_proxy_dns" and sighting["template_version"] == "2026.11.1" and sighting["personal"] is False
    (finding,) = res.findings
    assert finding.title == "Seen in our logs (SIEM)" and finding.severity.label == "info"
    assert set(finding.tags) == {"internal_sighting", "seen_in_logs"} and finding.source == "internal_siem.search"
    assert finding.description.startswith("seen in our logs: 42 events")
    assert finding.observed_first.startswith("2026-10-28") and finding.observed_last.startswith("2026-11-25")
    assert res.attributes["internal_sightings"] == [{"platform": "siem", "ref": "SIEM ioc_ip_proxy_dns", "org": None, "tlp": None,
                                                     "date": "2026-11-25", "verdict": "observed"}]
    assert res.pivots == [] and res.tlp == "amber+strict"
    body = body_of(http.calls[0])
    assert body["size"] == 0 and body["track_total_hits"] == 1000 and body["timeout"] == "14s"
    should = body["query"]["bool"]["filter"][0]["bool"]["should"]
    assert should == [{"term": {"source.ip": {"value": IP}}}, {"term": {"destination.ip": {"value": IP}}}]
    assert body["query"]["bool"]["filter"][1] == {"range": {"@timestamp": {"gte": "now-30d", "lte": "now"}}}
    assert set(body["aggs"]) == {"first_seen", "last_seen"}
    assert len(http.calls) == 1
    http.assert_hosts_within(SiemSearch)


def test_es_count_capped_at_1000(es_templates):
    http = FakeHttp()
    add_fx(http, "POST", ES_IP_URL, "es_capped.json")
    res = run(http, f"ipv4:{IP}", es_settings(es_templates))
    assert res.status is Status.OK
    assert res.attributes["siem_sighting"]["count_capped"] is True
    assert res.attributes["siem_sighting"]["line"].startswith("seen in our logs: 1000+ events, first 2026-10-27, last 2026-11-26")


def test_es_not_seen_is_a_real_answer(es_templates):
    http = FakeHttp()
    add_fx(http, "POST", ES_IP_URL, "es_empty.json")
    res = run(http, f"ipv4:{IP}", es_settings(es_templates))
    assert res.status is Status.EMPTY and res.findings == []
    assert res.error == "not seen in our logs (last 30 days, logs-proxy-*, logs-dns-*)"
    assert res.attributes["siem_sighting"]["count"] == 0 and res.attributes["siem_sighting"]["seen"] is False
    assert "internal_sightings" not in res.attributes
    assert res.raw["query_log"]["outcome"] == "not seen"


def test_opensearch_integer_total_and_bearer_scheme(es_templates):
    http = FakeHttp()
    add_fx(http, "POST", ES_IP_URL, "opensearch_ok_int_total.json", match_headers={"Authorization": f"Bearer {KEY}"})
    res = run(http, f"ipv4:{IP}", es_settings(es_templates, siem_search_auth_scheme="Bearer"))
    assert res.status is Status.OK
    sighting = res.attributes["siem_sighting"]
    assert sighting["count"] == 7 and sighting["first_seen"] == "2026-11-02T16:45:00Z" and sighting["last_seen"] == "2026-11-19T08:05:31Z"


def test_domain_template_adds_its_constant_filter_and_window(es_templates):
    http = FakeHttp()
    add_fx(http, "POST", f"{ES}/logs-dns-*,logs-proxy-*/_search?{ES_PARAMS}", "es_ok.json")
    res = run(http, "domain:Evil.Example.NET", es_settings(es_templates, siem_search_window_days=400))
    assert res.status is Status.OK
    filters = body_of(http.calls[0])["query"]["bool"]["filter"]
    assert filters[0]["bool"]["should"][0] == {"term": {"dns.question.name": {"value": "evil.example.net"}}}
    assert filters[1]["range"]["@timestamp"]["gte"] == "now-90d"  # an explicit longer window is capped at 90 days
    assert filters[2] == {"term": {"event.category": {"value": "network"}}}


@pytest.mark.parametrize(
    ("name", "status", "code"),
    [
        ("es_unauthorized.http.json", Status.NEEDS_KEY, "needs_key"),
        ("opensearch_unauthorized.http.json", Status.NEEDS_KEY, "needs_key"),
        ("es_rate_limited.http.json", Status.RATE_LIMITED, "rate_limited"),
        ("es_html_login.http.json", Status.BLOCKED, "login_wall"),
        ("es_forbidden.http.json", Status.ERROR, "error"),
        ("es_index_not_found.http.json", Status.ERROR, "error"),
        ("es_bad_request.http.json", Status.ERROR, "error"),
        ("es_search_phase_failure.http.json", Status.ERROR, "error"),
        ("es_timed_out.json", Status.ERROR, "timeout"),
        ("es_shard_failures.json", Status.ERROR, "error"),
        ("es_malformed.txt", Status.ERROR, "error"),
    ],
)
def test_es_failures_are_could_not_verify(es_templates, name, status, code):
    http = FakeHttp()
    add_fx(http, "POST", ES_IP_URL, name)
    res = run(http, f"ipv4:{IP}", es_settings(es_templates))
    assert res.status is status and res.reason_code == code
    assert res.error.startswith("SIEM: could not verify (")
    assert res.findings == [] and "siem_sighting" not in res.attributes
    assert res.raw["query_log"]["outcome"].startswith("could not verify")


def test_server_error_and_dead_network_are_errors(es_templates):
    http = FakeHttp()
    http.add("POST", ES_IP_URL, status=502, text="bad gateway")
    res = run(http, f"ipv4:{IP}", es_settings(es_templates))
    assert res.status is Status.ERROR
    http2 = FakeHttp()
    http2.add("POST", ES_IP_URL, error=ConnectionError("connection refused"))
    assert run(http2, f"ipv4:{IP}", es_settings(es_templates)).status is Status.ERROR


# ------------------------------------------------------------------ C2/C3: hostile values
HOSTILE = ['x" OR * | delete', "*", "$args.value$ | delete", "[search index=* | delete]", "`macro`", "a\x00b", " ", "?*"]


def test_hostile_user_agent_is_only_a_json_term_value(tmp_path):
    path = _templates(tmp_path, "templates_approved_es.json")
    http = FakeHttp()
    add_fx(http, "POST", f"{ES}/logs-auth-*,logs-proxy-*/_search?{ES_PARAMS}", "es_empty.json")
    res = run(http, Entity.make(T.USER_AGENT, 'x" OR * | delete'), es_settings(path, analyst="analyst-a"),
              case_id="case-hostile-1", options=ScanOptions(purpose="incident INC-1 phishing response", ticket="INC-1"))
    assert res.status is Status.EMPTY
    body = body_of(http.calls[0])
    assert {"term": {"user_agent.original": {"value": 'x" OR * | delete'}}} in body["query"]["bool"]["filter"][0]["bool"]["should"]
    assert not set(ss._walk_keys(body)) & ss.ES_FORBIDDEN_CLAUSES  # no query_string/wildcard/match/regexp/prefix clause
    assert ss.request_allowed({"method": "POST", "path": "/logs-auth-*/_search", "params": dict(ss.ES_PARAMS), "json": body}) is None


def test_bare_wildcard_never_reaches_a_siem(es_templates):
    http = FakeHttp()
    res = run(http, Entity.make(T.USER_AGENT, "*"), es_settings(es_templates, analyst="analyst-a"), case_id="case-star",
              options=ScanOptions(purpose="incident INC-2", ticket="INC-2"))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


@pytest.mark.parametrize("value", HOSTILE)
def test_hostile_values_are_refused_for_splunk_and_wildcards_everywhere(value):
    for etype in ("ipv4", "domain", "md5", "sha256", "email", "url", "username", "user_agent"):
        canon, why = ss.splunk_value_allowed(etype, value)
        assert canon is None and why.startswith("not_applicable")
    saved = {"id": "s", "name": "v3lum_ioc_ip", "owner": "nobody", "app": "soc_v3lum", "arg": "value", "entity_types": ["ipv4", "domain"]}
    assert ss.build_splunk_dispatch(saved, "domain", value)[0] is None
    if value.strip() in ("*", "?*", "") or "\x00" in value:
        assert ss.canonical_value("user_agent", value)[0] is None


def test_strict_splunk_charset_accepts_canonical_iocs():
    assert ss.splunk_value_allowed("ipv4", "198.51.100.23") == ("198.51.100.23", None)
    assert ss.splunk_value_allowed("ipv6", "2001:DB8::1") == ("2001:db8::1", None)
    assert ss.splunk_value_allowed("domain", "Evil.Example.NET.") == ("evil.example.net", None)
    assert ss.splunk_value_allowed("email", "Someone@Example.com") == ("someone@example.com", None)
    assert ss.splunk_value_allowed("email", 'a"b@example.com')[0] is None
    for etype in ("url", "username", "user_agent"):
        assert ss.splunk_value_allowed(etype, "harmless")[0] is None


@pytest.mark.parametrize(
    "req",
    [
        {"method": "DELETE", "path": "/servicesNS/nobody/soc_v3lum/search/jobs/abc"},
        {"method": "POST", "path": "/logs-proxy-*/_delete_by_query", "json": {"size": 0}},
        {"method": "POST", "path": "/_bulk", "json": {}},
        {"method": "POST", "path": "/servicesNS/nobody/soc_v3lum/search/jobs", "form": {"search": "search *"}},
        {"method": "POST", "path": "/logs-proxy-*/_search", "params": {"q": "*"}, "json": {"size": 0, "track_total_hits": 10}},
        {"method": "POST", "path": "/logs-proxy-*/_search", "params": {},
         "json": {"size": 0, "track_total_hits": 10, "query": {"query_string": {"query": "x OR *"}}}},
        {"method": "POST", "path": "/logs-proxy-*/_search", "params": {}, "json": {"size": 10, "track_total_hits": 10}},
        {"method": "POST", "path": "/logs-proxy-*/_search", "params": {}, "json": {"size": 0, "track_total_hits": 5000}},
        {"method": "POST", "path": "/logs-proxy-*/_search", "params": {},
         "json": {"size": 0, "track_total_hits": 10, "aggs": {"hosts": {"terms": {"field": "host.name"}}}}},
        {"method": "POST", "path": "/servicesNS/nobody/soc_v3lum/saved/searches/x/dispatch",
         "form": {"args.value": "1.2.3.4", "trigger_actions": "1"}},
        {"method": "POST", "path": "/servicesNS/nobody/soc_v3lum/saved/searches/x/dispatch",
         "form": {"args.value": 'x" | delete', "trigger_actions": "0"}},
        {"method": "POST", "path": "/servicesNS/nobody/soc_v3lum/saved/searches/x/dispatch",
         "form": {"args.value": "1.2.3.4", "search": "| delete"}},
        {"method": "GET", "path": "/servicesNS/nobody/soc_v3lum/search/v2/jobs/abc/results", "params": {"search": "| delete"}},
        {"method": "POST", "path": "/servicesNS/nobody/soc_v3lum/saved/searches/x", "form": {"search": "| delete"}},
        {"method": "GET", "path": "/../_cat/indices"},
    ],
)
def test_read_only_allow_list_refuses_writes_and_text_queries(req):
    assert ss.request_allowed(req).startswith("policy: ")


def test_built_requests_pass_the_allow_list():
    spec = ss.validate_templates(fx("templates_approved_es.json"))
    req, _ = ss.build_es_search(spec["templates"]["ioc_hash_edr"], "sha256", "A" * 64)
    assert ss.request_allowed(req) is None and req["json"]["query"]["bool"]["filter"][0]["bool"]["should"][0] == {
        "term": {"file.hash.md5": {"value": "a" * 64}}}
    sp = ss.validate_templates(fx("templates_approved_splunk.json"))
    dreq, _ = ss.build_splunk_dispatch(sp["splunk"]["v3lum_ioc_ip"], "ipv4", IP)
    assert ss.request_allowed(dreq) is None
    assert ss.request_allowed(ss.splunk_job_request(sp["splunk"]["v3lum_ioc_ip"], SID)[0]) is None
    assert ss.request_allowed(ss.splunk_results_request(sp["splunk"]["v3lum_ioc_ip"], SID)[0]) is None
    assert ss.splunk_job_request(sp["splunk"]["v3lum_ioc_ip"], "../../admin")[0] is None  # server sid never becomes a path


# ------------------------------------------------------------------ C1/C2: the template file
def test_approved_template_files_validate():
    es = ss.validate_templates(fx("templates_approved_es.json"))
    assert es["errors"] == [] and es["backend"] == "elasticsearch" and es["version"] == "2026.11.1"
    assert set(es["templates"]) == {"ioc_ip_proxy_dns", "ioc_domain_dns_proxy", "ioc_url_proxy", "ioc_hash_edr", "person_email_mail", "person_user_auth"}
    sp = ss.validate_templates(fx("templates_approved_splunk.json"))
    assert sp["errors"] == [] and set(sp["splunk"]) == {"v3lum_ioc_ip", "v3lum_ioc_domain", "v3lum_ioc_hash", "v3lum_person_email"}


def test_rejected_template_files():
    es = ss.validate_templates(fx("templates_rejected_es.json"))
    assert es["fatal"] and es["templates"] == {} and es["splunk"] == {}  # unversioned file: adapter disabled
    text = " | ".join(es["errors"])
    for expected in ("version missing", "raw query keys", "query_string", "index pattern '*'", "fields must be explicit",
                     "not flagged personal", "entity_types must be", "Splunk saved search in an elasticsearch"):
        assert expected in text
    sp = ss.validate_templates(fx("templates_rejected_splunk.json"))
    assert not sp["fatal"] and sp["splunk"] == {} and len(sp["errors"]) >= 5
    doc = dict(fx("templates_approved_es.json"), backend="splunk")
    assert ss.validate_templates(doc)["templates"] == {}  # primary SIEM only: no ES template in a splunk file


def test_configuration_problems_are_skipped_config(tmp_path, es_templates):
    http = FakeHttp()
    assert run(http, f"ipv4:{IP}", {"siem_search_templates": es_templates}).reason_code == "config"
    assert run(http, f"ipv4:{IP}", {"siem_url": "http://siem.example.com:9200", "siem_search_templates": es_templates}).reason_code == "config"
    res = run(http, f"ipv4:{IP}", {"siem_url": ES})
    assert res.status is Status.SKIPPED and res.reason_code == "config" and "siem_search_templates" in res.error
    writable = _templates(tmp_path, "templates_approved_splunk.json", mode=0o666)
    res = run(http, f"ipv4:{IP}", es_settings(writable))
    assert res.status is Status.SKIPPED and "group/world-writable" in res.error
    unversioned = _templates(tmp_path, "templates_rejected_es.json")
    assert run(http, f"ipv4:{IP}", es_settings(unversioned)).reason_code == "config"
    assert http.calls == []


def test_missing_key_is_needs_key(es_templates):
    res = run(FakeHttp(), f"ipv4:{IP}", es_settings(es_templates), keys={})
    assert res.status is Status.NEEDS_KEY


def test_type_without_an_approved_template_is_not_applicable(tmp_path):
    doc = fx("templates_approved_es.json")
    doc["templates"] = [t for t in doc["templates"] if t["id"] != "ioc_url_proxy"]
    path = _templates(tmp_path, "no_url.json", doc=doc)
    res = run(FakeHttp(), "url:https://evil.example.net/login", es_settings(path))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


# ------------------------------------------------------------------ C6/C7: personal identifiers, covert flag
PERSONAL_OPTS = {"purpose": "incident INC-2026-0042: phishing campaign response", "ticket": "INC-2026-0042"}


def test_personal_identifier_needs_a_case_purpose_and_ticket(es_templates):
    http = FakeHttp()
    res = run(http, "email:someone@example.com", es_settings(es_templates, analyst="analyst-a"))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "case_id" in res.error
    res = run(http, "email:someone@example.com", es_settings(es_templates, analyst="analyst-a"), case_id="case-p1",
              options=ScanOptions(purpose=PERSONAL_OPTS["purpose"]))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "ticket" in res.error
    assert http.calls == []


def test_personal_identifier_pivots_are_never_searched(es_templates):
    res = run(FakeHttp(), "username:user0042", es_settings(es_templates, analyst="analyst-a"), case_id="case-p2",
              options=ScanOptions(**PERSONAL_OPTS), is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "analyst-typed seed" in res.error


@pytest.mark.parametrize("purpose", ["avaliação de desempenho do colaborador", "HR investigation", "productivity check", "RH"])
def test_hr_or_performance_purposes_are_refused(es_templates, purpose):
    res = run(FakeHttp(), "email:someone@example.com", es_settings(es_templates, analyst="analyst-a"), case_id="case-hr",
              options=ScanOptions(purpose=purpose, ticket="T-1"))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "HR or performance" in res.error


def test_personal_search_in_an_incident_case_is_logged_with_analyst_and_case(es_templates):
    http = FakeHttp()
    add_fx(http, "POST", f"{ES}/logs-mail-*/_search?{ES_PARAMS}", "es_ok.json")
    res = run(http, "email:Someone@Example.com", es_settings(es_templates, analyst="analyst-a"), case_id="case-p3",
              options=ScanOptions(**PERSONAL_OPTS))
    assert res.status is Status.OK and res.attributes["siem_sighting"]["personal"] is True
    log = res.raw["query_log"]
    assert log["analyst"] == "analyst-a" and log["case_id"] == "case-p3" and log["ticket"] == "INC-2026-0042"
    assert re.fullmatch(r"[0-9a-f]{12}", log["value_ref"]) and log["template_id"] == "person_email_mail"
    assert "someone@example.com" not in json.dumps(res.raw)  # the value is logged only as its keyed HMAC
    with pytest.raises(ValueError):
        ss.audit_record(analyst="a", case_id="c", ticket="", backend="es", template_id="t", template_version="1",
                        entity_type="email", value_ref="someone@example.com", outcome="seen", queried_at="")


def test_covert_exercise_skips_siem_lookups(es_templates):
    from v3lum.modules.cti_framework import internal_tip_sightings as tip

    opts = ScanOptions()
    opts.covert = True
    http = FakeHttp()
    res = run(http, f"ipv4:{IP}", es_settings(es_templates), options=opts)
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and "covert" in res.error and http.calls == []
    opts2 = ScanOptions()
    opts2.no_internal = True
    assert ss.covert_refusal(opts2) and tip.covert_refusal(opts2)  # one flag for TIP and SIEM (P348 C8)


def test_at_most_n_queries_per_scan(es_templates):
    http = FakeHttp()
    add_fx(http, "POST", ES_IP_URL, "es_empty.json")
    settings = es_settings(es_templates, siem_search_max_queries=2)
    statuses = [run(http, f"ipv4:{IP}", settings, case_id="case-cap").status for _ in range(3)]
    assert statuses == [Status.EMPTY, Status.EMPTY, Status.QUOTA] and len(http.calls) == 2
    assert run(http, f"ipv4:{IP}", es_settings(es_templates, siem_search_max_queries=500), case_id="case-cap2").status is Status.EMPTY


# ------------------------------------------------------------------ Splunk saved searches
def splunk_routes(http, *, job=("splunk_job_running.json", "splunk_job_done.json"), results="splunk_results_ok.json",
                  dispatch="splunk_dispatch_ok.json", definition="splunk_saved_search_def.json"):
    auth = {"Authorization": f"Bearer {KEY}"}
    if definition:
        add_fx(http, "GET", DEF_URL, definition, match_headers=auth)
    if dispatch:
        add_fx(http, "POST", DISPATCH_URL, dispatch, match_headers=auth)
    for name in job:
        add_fx(http, "GET", JOB_URL, name, times=1, match_headers=auth)
    if results:
        add_fx(http, "GET", RESULTS_URL, results, match_headers=auth)
    return http


def test_splunk_saved_search_dispatch(splunk_templates):
    http = splunk_routes(FakeHttp())
    res = run(http, f"ipv4:{IP}", splunk_settings(splunk_templates))
    assert res.status is Status.OK
    sighting = res.attributes["siem_sighting"]
    assert sighting["backend"] == "splunk" and sighting["count"] == 42 and sighting["template_id"] == "v3lum_ioc_ip"
    assert sighting["first_seen"] == "2026-10-28T09:14:03Z" and sighting["index_patterns"] == ["index=proxy OR index=dns"]
    form = form_of(next(c for c in http.calls if c["method"] == "POST"))
    assert form == {"args.value": IP, "dispatch.earliest_time": "-30d", "dispatch.latest_time": "now", "dispatch.max_count": "1000",
                    "dispatch.max_time": "15", "dispatch.ttl": "300", "dispatchAs": "user", "trigger_actions": "0", "output_mode": "json"}
    assert [c["method"] for c in http.calls] == ["GET", "POST", "GET", "GET", "GET"]  # lint, dispatch, 2 polls, results
    assert res.raw["definition_lint"]["linted"] is True and res.raw["definition_lint"]["problems"] == []
    http.assert_hosts_within(SiemSearch)


def test_splunk_xml_dispatch_answer(splunk_templates):
    http = splunk_routes(FakeHttp(), dispatch="splunk_dispatch_ok.xml", job=("splunk_job_done.json",))
    assert run(http, f"ipv4:{IP}", splunk_settings(splunk_templates)).status is Status.OK


def test_splunk_extra_columns_are_dropped(splunk_templates):
    http = splunk_routes(FakeHttp(), job=("splunk_job_done.json",), results="splunk_results_extra_fields.json")
    res = run(http, f"ipv4:{IP}", splunk_settings(splunk_templates))
    assert res.status is Status.OK and res.attributes["siem_sighting"]["count"] == 42
    assert res.attributes["siem_sighting"]["index_patterns"] == ["proxy", "dns"]
    assert res.raw["dropped_fields"] == ["_raw", "host", "user"]
    text = blob(res)
    assert "ws-0042" not in text and "user0042" not in text and "dns01" not in text and res.pivots == []


def test_splunk_results_empty(splunk_templates):
    http = splunk_routes(FakeHttp(), job=("splunk_job_done.json",), results="splunk_results_empty.json")
    res = run(http, f"ipv4:{IP}", splunk_settings(splunk_templates))
    assert res.status is Status.EMPTY and res.error == "not seen in our logs (last 30 days, index=proxy OR index=dns)"


@pytest.mark.parametrize(
    ("routes", "status", "code"),
    [
        ({"job": ("splunk_job_done.json",), "results": "splunk_results_partial.json"}, Status.ERROR, "error"),
        ({"job": ("splunk_job_failed.json",), "results": None}, Status.ERROR, "error"),
        ({"job": ("splunk_job_finalized.json",), "results": None}, Status.ERROR, "timeout"),
        ({"job": ("splunk_job_queued.json",) * 8, "results": None}, Status.RATE_LIMITED, "rate_limited"),
        ({"job": ("splunk_job_running.json",) * 8, "results": None}, Status.ERROR, "timeout"),
        ({"dispatch": "splunk_quota.http.json", "job": (), "results": None}, Status.RATE_LIMITED, "rate_limited"),
        ({"dispatch": "splunk_unauthorized.http.json", "job": (), "results": None}, Status.NEEDS_KEY, "needs_key"),
        ({"dispatch": "splunk_forbidden.http.json", "job": (), "results": None}, Status.ERROR, "error"),
        ({"dispatch": "splunk_saved_search_not_found.http.json", "job": (), "results": None}, Status.ERROR, "error"),
    ],
)
def test_splunk_failures_are_could_not_verify(splunk_templates, routes, status, code):
    http = splunk_routes(FakeHttp(), **routes)
    res = run(http, f"ipv4:{IP}", splunk_settings(splunk_templates))
    assert res.status is status and res.reason_code == code and res.findings == []
    assert len(http.calls) <= SiemSearch.max_requests


def test_splunk_never_receives_url_username_or_user_agent(splunk_templates):
    http = FakeHttp()
    for entity in ("url:https://evil.example.net/x", "user_agent:Mozilla/5.0 test"):
        res = run(http, entity, splunk_settings(splunk_templates, analyst="a"), case_id="case-s",
                  options=ScanOptions(**PERSONAL_OPTS))
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def test_saved_search_failing_the_lint_is_never_dispatched(splunk_templates):
    bad = fx("splunk_saved_search_def.json")
    bad["entry"][0]["content"]["search"] = "search index=proxy src_ip=$args.value$ | stats count"
    http = FakeHttp()
    http.add("GET", DEF_URL, json=bad)
    res = run(http, f"ipv4:{IP}", splunk_settings(splunk_templates))
    assert res.status is Status.SKIPPED and res.reason_code == "config" and "safety lint" in res.error
    assert [c["method"] for c in http.calls] == ["GET"]


def test_lint_runs_once_a_day_and_unreadable_definitions_do_not_block(splunk_templates):
    http = splunk_routes(FakeHttp(), definition=None, job=("splunk_job_done.json", "splunk_job_done.json"))
    add_fx(http, "GET", DEF_URL, "splunk_forbidden.http.json", times=1)
    first = run(http, f"ipv4:{IP}", splunk_settings(splunk_templates))
    assert first.status is Status.OK and first.raw["definition_lint"]["linted"] is False
    second = run(http, f"ipv4:{IP}", splunk_settings(splunk_templates))
    assert second.status is Status.OK
    assert sum(1 for c in http.calls if c["method"] == "GET" and c["url"].startswith(DEF_URL.split("?")[0])) == 1  # state: once a day


def test_saved_search_lint():
    good = fx("splunk_saved_search_def.json")["entry"][0]["content"]["search"]
    assert ss.splunk_saved_search_lint(good) == []
    assert any("outside double quotes" in p for p in ss.splunk_saved_search_lint('search x=$args.value$ | stats count'))
    assert any("subsearch" in p for p in ss.splunk_saved_search_lint('search [search y="$args.value$"] | stats count'))
    assert any("delete" in p for p in ss.splunk_saved_search_lint('search x="$args.value$" | delete'))
    assert any("stats count" in p for p in ss.splunk_saved_search_lint('search x="$args.value$" | table _raw'))


def test_poll_schedule_fits_the_budget():
    delays = ss.splunk_poll_delays(15)
    assert len(delays) <= 8 and sum(delays) <= 15 and min(delays) >= 1.0
    assert ss.effective_timeout(120) == 30.0 and ss.effective_timeout(None) == 15.0
    assert ss.effective_window(None) == 30 and ss.effective_window(365) == 90


# ------------------------------------------------------------------ health check
def test_health_check_self_test(es_templates):
    http = FakeHttp()
    http.add("GET", f"{ES}/", json={"name": "node-data-01", "cluster_name": "soc", "version": {"number": "8.15.0"}}, times=1)
    add_fx(http, "GET", f"{ES}/", "es_unauthorized.http.json", times=1)
    hc = SiemSearch.health_check()
    assert hc.offline is False and hc.selftest is not None
    ctx = make_ctx(SiemSearch, http, keys=KEYS, settings=es_settings(es_templates))
    assert hc.selftest(ctx).status == "ok"
    assert hc.selftest(ctx).status == "needs_key"
    ctx2 = make_ctx(SiemSearch, FakeHttp(), keys={}, settings=es_settings(es_templates))
    assert hc.selftest(ctx2).status == "needs_key"


def test_fixture_files_carry_no_secret_or_real_identity():
    for path in (FIXTURES / "siem_search").iterdir():
        text = path.read_text(encoding="utf-8")
        assert KEY not in text
        assert not re.search(r"(?i)(apikey|bearer)\s+[A-Za-z0-9+/=]{16,}", text)
        for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
            assert email.endswith("example.com")


# ------------------------------------------------------------------ policy gate (A2/A12): internal is allowed at TLP:RED
def test_policy_gate_allows_the_internal_siem_at_tlp_red():
    from tests.fakes import make_runtime
    from v3lum.core.engine import Engine

    settings = {"siem_url": ES}
    allowed = Engine(make_runtime(keys=KEYS, settings=settings), ScanOptions(tlp="red")).decide_single(SiemSearch, Entity.make(T.IPV4, IP))
    assert allowed.allowed is True
    personal = Engine(make_runtime(keys=KEYS, settings=settings), ScanOptions(tlp="red")).decide_single(SiemSearch, Entity.make(T.EMAIL, "someone@example.com"))
    assert personal.allowed is False and personal.reason_code == "privacy"
    no_key = Engine(make_runtime(settings=settings), ScanOptions(tlp="red")).decide_single(SiemSearch, Entity.make(T.IPV4, IP))
    assert no_key.allowed is False and no_key.reason_code == "needs_key"
