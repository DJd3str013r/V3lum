"""intelx_metadata (P139): Intelligence X intelligent-search metadata (system id, bucket, date only).

Fixtures in tests/fixtures/intelx_metadata/: ``needs_key_401.json`` is the real 2026-11-25 answer of
free.intelx.io without a key (HTTP 401, empty body); every other fixture is SYNTHETIC in the shapes the
IntelligenceX SDK documents (search start -> id/status; result -> records + status 0 results, 1 done,
2 id not found, 3 pending) with documentation values (UUIDs 1111..., 'fixture-item-N.txt' names). P139
cond 6: a trimmed real success answer captured with the company key replaces them before merge
(docs/backlog/p3-G04-2.md).
"""

from __future__ import annotations

import copy
import json

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import sanitize
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.breach_leak import intelx_metadata as ix
from v3lum.modules.breach_leak.intelx_metadata import (
    ENDPOINTS,
    FORBIDDEN_WORDS,
    MAX_POLL_SECONDS,
    MAX_POLLS,
    IntelxMetadata,
    bucket_display,
    clean_url_selector,
    intelx_headers,
    intelx_url,
    intelx_url_allowed,
    manual_link,
    next_action,
    search_body,
    summarise_records,
)

MOD = IntelxMetadata
KEY = "ixfixture-0000-1111-2222-333344445555"
SID = "2b3d6c9e-0f1a-4c5b-9d7e-8a6b5c4d3e2f"
START = "https://free.intelx.io/intelligent/search"
RESULT = f"https://free.intelx.io/intelligent/search/result?id={SID}&limit=100"
TERMINATE = f"https://free.intelx.io/intelligent/search/terminate?id={SID}"
OWN = "analyst@acme.com.br"
ORG = {"domains": [{"name": "acme.com.br", "verification": "attested", "attested_by": "fixture analyst", "attested_date": "2026-11-26"}]}
SCOPE_ALL = ScanOptions(breach_scope="all", purpose="incident 2026-11 phishing triage")
KEYS = {"intelx": KEY}


def fx(name):
    return module_fixture(MOD, name)


def org():
    return OrgProfile.from_dict(ORG)


def result(status, records=True):
    body = copy.deepcopy(fx("search_result_ok.json"))
    body["status"] = status
    if not records:
        body["records"] = []
    return body


def add_env(http, method, url, name):
    data = fx(name)
    return http.add(method, url, status=data["status"], text=data.get("body") or "", headers=data.get("headers"))


def run(http, value=f"email:{OWN}", **kw):
    kw.setdefault("keys", KEYS)
    kw.setdefault("org_profile", org())
    return run_module(MOD, value, http, **kw)


def dump(res) -> str:
    return json.dumps(res.to_dict(), default=str)


# ---------------------------------------------------------------------- cond 1: allow-list


def test_content_endpoints_can_never_be_built():
    for op in ("file_preview", "file_view", "file_read", "file_download", "export", "authenticate_info", "intelligent_export"):
        with pytest.raises(ValueError):
            intelx_url(op, id=SID)
    for method, path, _params in ENDPOINTS.values():
        assert method in ("GET", "POST") and not any(word in path.lower() for word in FORBIDDEN_WORDS)
    refused = (
        ("GET", "https://free.intelx.io/file/preview?sid=x"), ("GET", "https://free.intelx.io/file/view?f=0&storageid=x"),
        ("GET", "https://free.intelx.io/file/read?type=0&storageid=x"), ("GET", "https://free.intelx.io/intelligent/search/export?id=x"),
        ("GET", "https://free.intelx.io/authenticate/info"), ("GET", f"https://2.intelx.io/intelligent/search/result?id={SID}"),
        ("GET", f"http://free.intelx.io/intelligent/search/result?id={SID}"), ("GET", f"https://free.intelx.io:8443/intelligent/search/result?id={SID}"),
        ("GET", f"https://u:p@free.intelx.io/intelligent/search/result?id={SID}"), ("GET", f"{RESULT}&k=secret"),
        ("POST", RESULT), ("GET", START), ("DELETE", TERMINATE), ("GET", f"{RESULT}#x"),
    )
    for method, url in refused:
        assert not intelx_url_allowed(method, url), url
    for op, params in (("intelligent_search", {}), ("intelligent_result", {"id": SID, "limit": 100}), ("terminate", {"id": SID}),
                       ("phonebook_search", {}), ("phonebook_result", {"id": SID, "limit": 1000, "offset": -1})):
        method, url = intelx_url(op, **params)
        assert intelx_url_allowed(method, url)
    # no string constant of the module names a content endpoint
    constants = json.dumps([v for k, v in vars(ix).items() if isinstance(v, str) and not k.startswith("__")])
    for path in ("/file/", "/preview", "/view", "/read", "/download", "/export", "/authenticate"):
        assert path not in constants


def test_url_builder_rejects_bad_ids_params_and_keys_in_urls():
    with pytest.raises(ValueError):
        intelx_url("intelligent_result", id="../file/read", limit=10)
    with pytest.raises(ValueError):
        intelx_url("intelligent_result", id=SID, k=KEY)
    with pytest.raises(ValueError):
        intelx_url("terminate")
    with pytest.raises(ValueError):
        intelx_headers("bad key\r\nx: y")
    assert intelx_headers(f" {KEY} ") == {"x-key": KEY}
    assert KEY not in intelx_url("intelligent_result", id=SID, limit=100)[1]


def test_search_body_and_url_selector_cleaning():
    body = search_body("Analyst@ACME.com.br", "intelligent", ix.T.EMAIL)
    assert body["term"] == "analyst@acme.com.br" and body["maxresults"] == 100 and body["buckets"] == [] and body["media"] == 0
    assert clean_url_selector("https://user:pw@portal.acme.com.br:8443/a/b?token=abc#frag") == "https://portal.acme.com.br:8443/a/b"
    assert clean_url_selector("ftp://acme.com.br/x") is None
    with pytest.raises(ValueError):
        search_body("analyst@acme.com.br", "phonebook", ix.T.EMAIL)  # phonebook: own domains only


# ---------------------------------------------------------------------- cond 3: bounded polling


def test_next_action_bounds():
    total, polls, state = 0.0, 0, None
    while True:
        act = next_action(polls, total, state)
        if act["action"] == "stop":
            break
        total += act["delay"]
        polls += 1
        state = "pending"
    assert polls == MAX_POLLS and act["terminate"] and act["reason"] == "poll_cap" and total <= MAX_POLL_SECONDS
    assert next_action(2, MAX_POLL_SECONDS - 1, "results")["reason"] == "time_budget"
    assert next_action(0, 0, "done") == {"action": "stop", "delay": None, "terminate": False, "partial": False, "reason": "done"}
    assert next_action(1, 1, "results", collected=100, maxresults=100)["reason"] == "maxresults"
    assert next_action(1, 1, "garbage")["terminate"] is True


def test_polling_is_bounded_and_the_search_terminated():
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, json=fx("search_result_pending.json"))
    http.add("GET", TERMINATE, status=204, text="")
    res = run(http)
    polls = [c for c in http.calls if "/search/result" in c["url"]]
    assert len(polls) == MAX_POLLS
    assert [c["url"] for c in http.calls].count(TERMINATE) == 1 and len(http.calls) == MAX_POLLS + 2 <= MOD.max_requests
    assert res.status is Status.ERROR and "could not verify" in res.error  # unfinished search: never 'absent'
    http.assert_hosts_within(MOD)


def test_poll_cap_with_items_keeps_them_as_partial():
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, json=result(0), times=1)
    http.add("GET", RESULT, json=fx("search_result_pending.json"))
    http.add("GET", TERMINATE, status=204, text="")
    res = run(http)
    assert res.status is Status.OK
    assert res.attributes["intelx_search"]["partial"] is True and res.attributes["intelx_search"]["stop"] == "poll_cap"
    assert res.attributes["intelx_search"]["terminated"] is True
    assert "partial" in res.findings[0].description


# ---------------------------------------------------------------------- cond 4-6: what is kept


def test_own_address_keeps_ids_dates_masked_buckets_and_links():
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"), match_headers={"x-key": KEY})
    http.add("GET", RESULT, json=fx("search_result_pending.json"), times=1, match_headers={"x-key": KEY})
    http.add("GET", RESULT, json=result(0), times=1)
    http.add("GET", RESULT, json=result(1, records=False), times=1)
    res = run(http)
    assert res.status is Status.OK
    sent = json.loads(http.calls[0]["body"])
    assert sent["term"] == OWN and sent["maxresults"] == 100
    buckets = {b["bucket"]: b for b in res.attributes["intelx_buckets"]}
    assert set(buckets) == {"leaks.public.general", "pastes", "darknet.tor", "leaks.logs", "leaks.private (name withheld)",
                            "sensitive bucket (name withheld)"}
    assert buckets["darknet.tor"]["first_date"] == "2024-01-15"  # placeholder item date -> indexing date
    assert buckets["leaks.logs"]["category"] == "stealer logs"
    records = res.attributes["intelx_records"]
    assert len(records) == 6 and set(records[0]) == {"systemid", "bucket", "date"}
    links = [u for _label, u in res.links]
    assert len(links) == 6 and all(u.startswith("https://intelx.io/?did=11111111-") for u in links)
    f = res.findings[0]
    assert f.severity.label == "medium" and "own_asset" in f.tags and "leak_index" in f.tags and f.label.value == "possible"
    assert f.criterion and f.source == "intelx.search" and str(f.observed_first).startswith("2018-01-01")
    text = dump(res)
    for forbidden in ("fixture-item", "examplesite", "adultsite", "storageid", "Data Leaks: Public", "randomid"):
        assert forbidden not in text
    assert not any(w in c["url"] for c in http.calls for w in ("/file/", "preview", "/view", "download"))
    assert KEY not in text
    http.assert_hosts_within(MOD)


def test_third_party_selector_keeps_bucket_names_and_dates_only():
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, json=result(1))
    res = run(http, "email:someone@thirdparty.com.br", options=SCOPE_ALL)
    assert res.status is Status.OK
    assert "intelx_records" not in res.attributes and not res.links
    text = dump(res)
    assert "11111111-2222" not in text and "systemid" not in text  # no system ids for non-own selectors (cond 5)
    f = res.findings[0]
    assert f.severity.label == "info" and {"context_only", "third_party", "privacy"} <= set(f.tags)
    assert {b["bucket"] for b in res.attributes["intelx_buckets"]} >= {"pastes", "leaks.logs"}


def test_third_party_address_without_breach_scope_is_skipped_before_any_request():
    http = FakeHttp()
    res = run(http, "email:someone@thirdparty.com.br")
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []


def test_third_party_domain_and_url_need_the_breach_scope_too():
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, json=result(1))
    res = run(http, "url:https://user:pw@login.thirdparty.com.br/path?token=abcdef#x", options=SCOPE_ALL)
    assert res.status is Status.OK
    assert json.loads(http.calls[0]["body"])["term"] == "https://login.thirdparty.com.br/path"  # no userinfo/query
    assert run(FakeHttp(), "domain:thirdparty.com.br").status is Status.SKIPPED


def test_generic_address_is_flagged_and_never_scored():
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, json=result(1))
    own_example = {"domains": [{"name": "example.com", "verification": "attested", "attested_by": "fixture analyst", "attested_date": "2026-11-26"}]}
    res = run(http, "email:contato@example.com", org_profile=OrgProfile.from_dict(own_example))
    assert res.status is Status.OK and res.attributes["generic_address"]
    f = res.findings[0]
    assert f.severity.label == "info" and "context_only" in f.tags and f.criterion.startswith("POSSIBLE - generic")


def test_finished_search_without_items_is_a_declared_absence():
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, json=fx("search_result_done_empty.json"))
    res = run(http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    assert [c["url"] for c in http.calls].count(TERMINATE) == 0


# ---------------------------------------------------------------------- statuses (rule 5)


def test_missing_key_is_needs_key_before_any_request():
    http = FakeHttp()
    res = run(http, keys={})
    assert res.status is Status.NEEDS_KEY and http.calls == []


def test_401_402_429_5xx_and_challenges_are_could_not_verify():
    http = add_env(FakeHttp(), "POST", START, "needs_key_401.json")
    assert run(http).status is Status.NEEDS_KEY
    http = add_env(FakeHttp(), "POST", START, "quota_402.json")
    res = run(http)
    assert res.status is Status.QUOTA and res.reason_code == "quota"
    http = FakeHttp().add("POST", START, status=429, text="slow down")
    assert run(http).status is Status.RATE_LIMITED
    http = FakeHttp().add("POST", START, status=503, text="unavailable", times=2)
    assert run(http).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("POST", START, status=403, text=page)
    assert run(http).status is Status.BLOCKED


def test_search_start_states_and_lost_ids_are_errors():
    http = FakeHttp().add("POST", START, json=fx("search_start_invalid_term.json"))
    res = run(http)
    assert res.status is Status.ERROR and "rejected the term" in res.error
    busy = dict(fx("search_start_ok.json"), status=2)
    assert run(FakeHttp().add("POST", START, json=busy)).status is Status.RATE_LIMITED
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, json=fx("search_result_id_not_found.json"))
    res = run(http)
    assert res.status is Status.ERROR and "lost the search" in res.error
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, status=404, json={})
    assert run(http).status is Status.ERROR


def test_malformed_and_unexpected_answers_are_errors_never_empty():
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, text=fx("malformed.txt"), headers={"content-type": "application/json"})
    http.add("GET", TERMINATE, status=204, text="")
    assert run(http).status is Status.ERROR
    http = FakeHttp().add("POST", START, json=["not", "an", "object"])
    assert run(http).status is Status.ERROR
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, json={"status": 0, "records": "nope"})
    http.add("GET", TERMINATE, status=204, text="")
    assert run(http).status is Status.ERROR


# ---------------------------------------------------------------------- helpers


def test_bucket_masking():
    assert bucket_display("leaks.public.general") == {"bucket": "leaks.public.general", "category": "data leaks", "masked": False}
    assert bucket_display("web.public.br")["masked"] is False
    assert bucket_display("leaks.private.examplesite") == {"bucket": "leaks.private (name withheld)", "category": "data leaks", "masked": True}
    assert bucket_display("leaks.public.adultsite")["bucket"] == "sensitive bucket (name withheld)"
    assert bucket_display("leaks.private (name withheld)")["masked"] is True  # idempotent
    assert bucket_display(None)["bucket"] is None


def test_summaries_and_links():
    recs = [{"systemid": "11111111-2222-4333-8444-555555555551", "bucket": "pastes", "category": "pastes", "masked": False, "date": "2020-01-01"},
            {"systemid": "11111111-2222-4333-8444-555555555551", "bucket": "pastes", "category": "pastes", "masked": False, "date": "2020-01-01"}]
    third = summarise_records(recs, own=False, selector_type="email")
    assert third["total"] == 1 and "records" not in third and "links" not in third
    own = summarise_records(recs, own=True, selector_type="email")
    assert own["links"] == ["https://intelx.io/?did=11111111-2222-4333-8444-555555555551"]
    assert manual_link("not-a-uuid") is None


def test_sanitizer_schema_drops_item_content_before_the_module():
    body = json.dumps(fx("search_result_ok.json")).encode()
    out = json.loads(sanitize.sanitize_body("intelx.search", body, "application/json"))
    assert set(out) == {"status", "records"}
    assert all(set(r) <= {"systemid", "bucket", "date", "added"} for r in out["records"])
    assert "fixture-item" not in json.dumps(out)
