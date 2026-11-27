"""P127 brasilapi_ddd (batch p3-G06-1): the 67 registered DDD parts, their update path through the dataset
manager, the out-of-band refresh job, offline lookups and the FC3 report shapes.

Fixtures (``tests/fixtures/brasilapi_ddd/``) are real BrasilAPI answers captured on 2026-11-26 (public
municipality names, no personal data; request ids dropped): DDD 11, DDD 61 (state DF with Goiás towns),
DDD 83 (223 names), the documented 404 DDD_NOT_FOUND body and a 304. Answers that were not observed live
(429, challenge pages, 5xx, error objects in HTTP 200, HTML, truncated JSON) are built inline and labelled
synthetic.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_ctx, make_runtime, module_fixture
from v3lum.core import datasets
from v3lum.core.datasets import DATASETS, DataStore, dataset_errors
from v3lum.core.http import NetworkError
from v3lum.core.providers import registry
from v3lum.modules.phone import brasilapi_ddd as b
from v3lum.modules.phone import phone_parse as pp
from v3lum.modules.phone.phone_parse import PhoneParse

ROOT = Path(__file__).resolve().parents[2]
URL = "https://brasilapi.com.br/api/ddd/v1/{ddd}"
ANY_DDD = re.compile(r"^https://brasilapi\.com\.br/api/ddd/v1/\d\d$")
CHALLENGE = ("<html><head><title>Just a moment...</title></head><body><div id='cf-chl-widget'></div>"
             "<script>window._cf_chl_opt={}</script></body></html>")  # synthetic Cloudflare challenge
TABLE = DataStore.bundled_json(b.DDD_TABLE)  # phone_parse's bundled Anatel table (P126 FC3)


def envelope(name: str) -> dict:
    return module_fixture("brasilapi_ddd", name)


def body(name: str) -> bytes:
    return envelope(name)["response"]["body"].encode("utf-8")


def add_fixture(http: FakeHttp, name: str, **kw) -> FakeHttp:
    env = envelope(name)
    r = env["response"]
    return http.add("GET", env["request"].split(" ", 1)[1], status=r["status"], body=r["body"].encode("utf-8"),
                    headers=r["headers"], **kw)


def synthetic_answer(ddd: str) -> dict:
    """Synthetic body for DDDs without a captured fixture: the table UF and 80 made-up names (labelled)."""
    letters = "ABCDEFGHIJ"
    names = [f"CIDADE {letters[i // 10]}{letters[i % 10]} DDD {''.join(letters[int(c)] for c in ddd)}" for i in range(80)]
    return {"state": TABLE["ddd"][ddd]["uf"], "cities": names}


def all_ddds_http(http: FakeHttp | None = None) -> FakeHttp:
    """Every allocated DDD answers: the three captured fixtures, synthetic bodies for the other 64."""
    http = http or FakeHttp()
    for name in ("ok_11.http.json", "ok_61_multi_uf.http.json", "ok_83_large.http.json"):
        add_fixture(http, name)
    for ddd in sorted(b.BR_DDD_CODES - {"11", "61", "83"}):
        http.add("GET", URL.format(ddd=ddd), json=synthetic_answer(ddd))
    return http


class TimedHttp(FakeHttp):
    """FakeHttp that records the runtime clock at every send (pacing checks)."""

    def __init__(self) -> None:
        super().__init__()
        self.times: list[float] = []

    def send(self, method, url, **kw):  # noqa: ANN001 - Transport protocol
        self.times.append(self.clock.monotonic())
        return super().send(method, url, **kw)


# ------------------------------------------------------------------------------------------------ FC1 registration


def test_67_parts_registered_with_council_metadata():
    assert len(b.PARTS) == 67 and set(b.PARTS) == b.BR_DDD_CODES
    for ddd, name in b.PARTS.items():
        reg = DATASETS[name]
        assert name == f"brasilapi_ddd.{ddd}" and b.ddd_of_part(name) == ddd and b.part_name(ddd) == name
        assert reg["url"] == URL.format(ddd=ddd) and b.ddd_url_problem(reg["url"]) is None
        assert reg["ttl"] == 30 * 86400  # FC1: 30-day TTL
        assert reg["large"] is True  # never downloaded during a scan (no per-scan network call)
        assert reg["essential"] is False and reg["active"] is False and reg["expect"] == "json"
        assert reg["source"] == "brasilapi.ddd" and reg["provider"] == "brasilapi" and reg["terms_class"] == "open"
        assert "MIT" in reg["licence"] and "Anatel" in reg["licence"] and "BrasilAPI" in reg["attribution"]
        assert callable(reg["validate"]) and reg["max_bytes"] <= 256 * 1024
    assert not [e for e in dataset_errors() if "brasilapi_ddd" in e]
    assert b.register_parts() == b.PARTS  # idempotent
    # the single name 'brasilapi_ddd' stays free (phone_parse reads it only when registered: contract gap)
    assert "brasilapi_ddd" not in DATASETS or DATASETS["brasilapi_ddd"]["url"] != URL.format(ddd="11")


def test_registry_provider_is_community_and_open():
    reg = registry()
    src = reg.source("brasilapi.ddd")
    assert src is not None and src.terms.class_ == "open" and src.upstream_family == "anatel"
    provider = reg.get("brasilapi")
    assert provider.tier == "community" and reg.provider_for_host("brasilapi.com.br").id == "brasilapi"
    assert provider.http_profile.min_interval >= 1.0 and provider.http_profile.concurrency == 1  # FC1: <= 1 req/s


def test_constants_match_phone_parse():
    assert b.BR_DDD_CODES == pp.BR_DDD_CODES
    assert b.CITY_LIST_UNAVAILABLE == pp.CITY_LIST_UNAVAILABLE  # FC2 verbatim
    assert b.DATASET == pp.BRASILAPI_DDD_DATASET and b.DDD_TABLE == pp.DDD_TABLE
    assert set(TABLE["ddd"]) == b.BR_DDD_CODES


def test_fetch_plan_is_67_sorted_ddd_only_urls():
    plan = b.ddd_fetch_plan()
    assert [p["ddd"] for p in plan] == sorted(b.BR_DDD_CODES) and len(plan) == 67
    assert all(b.ddd_url_problem(p["url"]) is None and p["url"].rsplit("/", 1)[1] == p["ddd"] for p in plan)
    with pytest.raises(ValueError):
        b.part_name("10")
    assert b.ddd_of_part("brasilapi_ddd.10") is None and b.ddd_of_part("brasilapi_ddd") is None


@pytest.mark.parametrize(("url", "needle"), [
    ("https://brasilapi.com.br/api/ddd/v1/11999990000", "never a phone number"),
    ("https://brasilapi.com.br/api/ddd/v1/11?number=1199999", "query"),
    ("https://brasilapi.com.br/api/ddd/v1/11#x", "query or fragment"),
    ("https://brasilapi.com.br/api/ddd/v1/", "path"),
    ("https://brasilapi.com.br/api/ddd/v1/10", "not allocated"),
    ("http://brasilapi.com.br/api/ddd/v1/11", "https"),
    ("https://evil.example/api/ddd/v1/11", "declared host"),
    ("https://user@brasilapi.com.br/api/ddd/v1/11", "declared host"),
    ("https://brasilapi.com.br:8443/api/ddd/v1/11", "declared host"),
    (None, "not a string"),
])
def test_url_guard_refuses_anything_but_a_ddd(url, needle):
    assert needle in (b.ddd_url_problem(url) or "")


# ------------------------------------------------------------------------------------------------ FC1 parsing


def test_parse_real_answers():
    sp = b.parse_ddd_payload(body("ok_11.http.json"))
    assert sp["ok"] and sp["state"] == "SP" and len(sp["cities"]) == 64 and "SÃO PAULO" in sp["cities"]
    assert sp["cities"] == sorted(sp["cities"], key=lambda n: (b.fold(n), n)) and not sp["dropped"]
    df = b.parse_ddd_payload(body("ok_61_multi_uf.http.json"))
    assert df["state"] == "DF" and len(df["cities"]) == 13 and "VALPARAÍSO DE GOIÁS" in df["cities"]
    pb = b.parse_ddd_payload(body("ok_83_large.http.json"))
    assert pb["ok"] and len(pb["cities"]) == 223 and any("'" in c for c in pb["cities"]) and not pb["dropped"]
    assert b.parse_ddd_payload(body("not_found_404.http.json"))["reason"] == "not_found"
    assert b.parse_ddd_payload(json.loads(body("ok_61_multi_uf.http.json")))["ok"]  # parsed JSON accepted


@pytest.mark.parametrize(("payload", "reason"), [
    (b"", "empty body"),
    (b"<!doctype html><html><head><title>Vercel Security Checkpoint</title></head><body></body></html>", "HTML page"),
    (body("ok_11.http.json")[:300], "malformed JSON"),  # synthetic: truncated transfer of the real body
    (b'{"message":"Too many requests","type":"too_many_requests","name":"TooManyRequestsError"}', "rate_limited"),
    (b'{"message":"boom","type":"internal_error","name":"InternalError"}', "BrasilAPI error InternalError"),
    (b'["SP"]', "not an object"),
    (b'{"state":"XX","cities":["A"]}', "invalid state"),
    (b'{"state":"SP"}', "missing cities"),
    (b'{"state":"SP","cities":[]}', "empty city list"),
    (b'{"state":"SP","cities":[1, "", "<b>X</b>", "12 DE OUTUBRO"]}', "empty city list"),
    (json.dumps({"state": "SP", "cities": [f"CIDADE {chr(65 + i // 26 // 26)}{chr(65 + i // 26 % 26)}{chr(65 + i % 26)}"
                                           for i in range(1001)]}).encode(), "implausible city count"),
    (b"x" * (256 * 1024 + 1), "body too large"),
])
def test_parse_is_defensive_never_an_empty_success(payload, reason):
    out = b.parse_ddd_payload(payload)
    assert out["ok"] is False and reason in out["reason"] and out["cities"] == []
    assert b.part_problems(payload)


def test_city_names_are_cleaned_and_deduplicated():
    out = b.clean_city_names(["SÃO PAULO", "Sao  Paulo", "OLHO D'ÁGUA", "EMBU-GUAÇU", "<script>", "X1", None, " "])
    assert out["cities"] == ["EMBU-GUAÇU", "OLHO D'ÁGUA", "SÃO PAULO"] and len(out["dropped"]) == 4
    assert b.clean_city_names("not a list") == {"cities": [], "dropped": []}


# ------------------------------------------------------------------------------------------------ FC1 update path


def test_update_installs_a_part_and_revalidates_with_the_etag():
    http = add_fixture(FakeHttp(), "ok_61_multi_uf.http.json", times=1)
    etag = envelope("not_modified_304.http.json")["response"]["headers"]["etag"]
    add_fixture(http, "not_modified_304.http.json", match_headers={"If-None-Match": etag})
    store = make_runtime(http).data
    first = store.update("brasilapi_ddd.61")
    assert first.status == "updated" and b.update_outcome(first) == "ok"
    rec = b.installed_part(store, "61")
    assert rec["ok"] and rec["state"] == "DF" and len(rec["cities"]) == 13 and rec["stale"] is False
    second = store.update("brasilapi_ddd.61")  # conditional GET -> 304: the installed copy stays
    assert second.status == "unchanged" and b.update_outcome(second) == "not_modified"
    assert [c["url"] for c in http.calls] == [URL.format(ddd="61")] * 2
    assert http.calls[1]["headers"].get("If-None-Match") == etag


@pytest.mark.parametrize(("label", "route", "outcome"), [
    ("429 (synthetic)", {"status": 429, "text": "slow down"}, "rate_limited"),
    ("challenge 403 (synthetic)", {"status": 403, "text": CHALLENGE}, "blocked"),
    ("challenge in 200 (synthetic)", {"status": 200, "text": CHALLENGE}, "blocked"),
    ("keyless 403 (synthetic)", {"status": 403, "json": {"message": "forbidden"}}, "blocked"),
    ("500 (synthetic)", {"status": 500, "json": {"message": "x", "type": "internal", "name": "InternalError"}}, "error"),
    ("network error (synthetic)", {"error": NetworkError("connection reset")}, "error"),
    ("error object in 200 (synthetic)", {"json": {"message": "x", "type": "too_many_requests", "name": "TooManyRequestsError"}}, "rate_limited"),
    ("other error object in 200 (synthetic)", {"json": {"message": "x", "type": "internal", "name": "InternalError"}}, "error"),
    ("HTML in 200 (synthetic)", {"text": "<html><body>maintenance</body></html>"}, "error"),
    ("malformed JSON (synthetic)", {"body": b'{"state":"SP","cities":["A'}, "error"),
    ("documented 404 (retired DDD)", {"status": 404, "body": body("not_found_404.http.json")}, "not_found"),
])
def test_failed_updates_keep_the_installed_copy(label, route, outcome):
    http = add_fixture(FakeHttp(), "ok_11.http.json", times=1)
    http.add("GET", URL.format(ddd="11"), **route)
    store = make_runtime(http).data
    assert store.update("brasilapi_ddd.11").status == "updated"
    before = b.installed_part(store, "11")
    res = store.update("brasilapi_ddd.11")
    assert res.status == "failed" and b.update_outcome(res) == outcome, (label, res.reason)
    after = b.installed_part(store, "11")
    assert after["ok"] and after["cities"] == before["cities"] and after["sha256"] == before["sha256"]


def test_failed_first_download_installs_nothing():
    http = FakeHttp().add("GET", URL.format(ddd="11"), json={"state": "SP", "cities": []})  # synthetic empty list
    store = make_runtime(http).data
    res = store.update("brasilapi_ddd.11")
    assert res.status == "failed" and "empty city list" in res.reason
    assert b.installed_part(store, "11") is None and not store.info("brasilapi_ddd.11").present


# ------------------------------------------------------------------------------------------------ FC1 refresh job


def test_refresh_fetches_67_ddds_in_order_at_most_one_per_second():
    http = all_ddds_http(TimedHttp())
    rt = make_runtime(http)
    lines: list[str] = []
    summary = b.refresh_parts(rt.data, log=lines.append)
    assert summary["status"] == "ok" and len(summary["updated"]) == 67 and not summary["failed"]
    urls = [c["url"] for c in http.calls]
    assert urls == [URL.format(ddd=d) for d in sorted(b.BR_DDD_CODES)]  # one GET per DDD, fixed order
    assert all(b.ddd_url_problem(u) is None for u in urls)  # only the 2-digit DDD ever leaves
    gaps = [later - earlier for earlier, later in zip(http.times, http.times[1:])]
    assert gaps and min(gaps) >= 1.0 - 1e-9  # FC1: <= 1 request/s (provider profile pacing)
    inst = summary["installed"]
    assert inst["complete"] and inst["present"] == 67 and inst["total_cities"] == 64 + 13 + 223 + 64 * 80
    assert inst["note"] is None and "installed 67/67 DDDs" in summary["line"] and len(lines) == 67
    again = b.refresh_parts(rt.data)  # nothing changed upstream: same bytes, installed copies kept
    assert again["status"] == "ok" and len(again["unchanged"]) == 67


def test_refresh_stops_at_once_on_a_challenge():
    http = FakeHttp().add("GET", URL.format(ddd="11"), status=403, text=CHALLENGE)  # synthetic
    summary = b.refresh_parts(make_runtime(http).data)
    assert summary["status"] == "stopped" and "never bypassed" in summary["stopped_reason"]
    assert len(http.calls) == 1 and summary["records"][0]["outcome"] == "blocked"
    assert summary["installed"]["present"] == 0 and summary["installed"]["complete"] is False


def test_refresh_stops_after_three_consecutive_failures():
    http = FakeHttp().add("GET", ANY_DDD, status=500, json={"message": "x", "type": "internal", "name": "InternalError"})
    summary = b.refresh_parts(make_runtime(http).data)
    assert summary["status"] == "stopped" and "3 consecutive failures" in summary["stopped_reason"]
    assert [r["ddd"] for r in summary["records"]] == ["11", "12", "13"] and len(http.calls) == 3


def test_refresh_stops_at_a_rate_limit_and_keeps_the_installed_copies():
    http = all_ddds_http(FakeHttp())
    rt = make_runtime(http)
    assert b.refresh_parts(rt.data)["status"] == "ok"
    later = FakeHttp().add("GET", URL.format(ddd="11"), status=304, headers={"etag": '"x"'}, times=1)
    later.add("GET", URL.format(ddd="12"), status=429, text="slow down")  # synthetic
    summary = b.refresh_parts(make_runtime(later).data)
    assert summary["status"] == "stopped" and "rate limited" in summary["stopped_reason"]
    assert [r["outcome"] for r in summary["records"]] == ["not_modified", "rate_limited"] and len(later.calls) == 2
    assert summary["installed"]["complete"] and summary["installed"]["present"] == 67  # previous copies kept


def test_refresh_reports_a_retired_ddd_for_maintainer_review():
    http = FakeHttp().add("GET", URL.format(ddd="11"), status=404, body=body("not_found_404.http.json"))
    all_ddds_http(http)
    summary = b.refresh_parts(make_runtime(http).data)
    assert summary["not_found"] == ["11"] and summary["status"] == "partial" and len(summary["updated"]) == 66


def test_refresh_is_refused_inside_a_scan_and_offline():
    http = FakeHttp()
    rt = make_runtime(http)
    rt.in_scan = True
    assert b.refresh_parts(rt.data)["status"] == "refused" and not http.calls
    offline = make_runtime(http, offline=True)
    out = b.refresh_parts(offline.data)
    assert out["status"] == "refused" and "offline" in out["stopped_reason"] and not http.calls
    assert b.refresh_parts(None)["status"] == "refused"


def test_abort_rules():
    assert b.update_abort_reason([{"ddd": "11", "outcome": "ok"}, {"ddd": "12", "outcome": "blocked", "reason": "x"}])
    assert b.update_abort_reason([{"outcome": "error"}, {"outcome": "error"}, {"outcome": "ok"}, {"outcome": "error"}]) is None
    assert b.update_abort_reason([{"outcome": "error"}] * 3)
    assert "rate limited" in b.update_abort_reason([{"ddd": "11", "outcome": "rate_limited", "reason": "HTTP 429"}])
    assert b.update_abort_reason([{"outcome": "not_found"}, {"outcome": "not_modified"}]) is None
    assert b.update_abort_reason([None, "x"]) is None


def test_main_entry_point_refreshes_the_parts(capsys):
    assert b.main([], runtime=make_runtime(all_ddds_http())) == 0
    out = capsys.readouterr().out
    assert "brasilapi_ddd.99: ok" in out and "installed 67/67 DDDs" in out
    assert b.main([], runtime=make_runtime(FakeHttp(), offline=True)) == 1
    assert "offline" in capsys.readouterr().out


# ------------------------------------------------------------------------------------------------ FC2 offline reads


def test_reads_never_download_and_cite_the_part():
    ctx = make_ctx(PhoneParse, FakeHttp())  # an offline (disclosure none) module's ctx.data
    assert b.installed_part(ctx.data, "11") is None  # not downloaded: no request, no download mid-run
    assert b.installed_records(ctx.data) == {} and ctx.data.used == []
    store = make_runtime(add_fixture(FakeHttp(), "ok_11.http.json")).data
    assert store.update("brasilapi_ddd.11").status == "updated"
    rec = b.installed_part(ctx.data, "11")
    assert rec["ok"] and len(rec["cities"]) == 64 and rec["fetched_at"]
    assert [d["name"] for d in ctx.data.used] == ["brasilapi_ddd.11"] and "MIT" in ctx.data.used[0]["licence"]
    assert b.installed_records(ctx.data, ["11", "61", "x"]) == {"11": {"state": "SP", "cities": rec["cities"]}}
    assert b.installed_part(ctx.data, "10") is None and b.installed_part(None, "11") is None


def test_unusable_local_copy_is_never_an_empty_list():
    store = make_runtime(add_fixture(FakeHttp(), "ok_11.http.json")).data
    store.update("brasilapi_ddd.11")
    store.path("brasilapi_ddd.11").write_text('{"state":"SP","cities":["<b>x</b>"]}', encoding="utf-8")  # tampered copy
    rec = b.installed_part(store, "11")
    assert rec["ok"] is False and rec["cities"] == [] and "empty city list" in rec["reason"]
    look = b.lookup_ddd("11", rec, TABLE)
    assert look["coverage"] == b.CITY_LIST_UNAVAILABLE and any("unusable" in n for n in look["notes"])
    assert b.installed_records(store, ["11"]) == {}


def test_lookup_with_the_installed_city_list():
    rec = {"ok": True, "state": "SP", "cities": b.parse_ddd_payload(body("ok_11.http.json"))["cities"],
           "name": "brasilapi_ddd.11", "fetched_at": "2026-11-26T09:31:00Z", "age_hours": 26.0, "stale": False}
    look = b.lookup_ddd("11", rec, TABLE)
    assert (look["uf"], look["ufs"], look["main_city"], look["uf_source"]) == ("SP", ["SP"], "São Paulo", "bundled_table")
    assert look["city_count"] == 64 and look["cities_source"] == "brasilapi_ddd" and look["coverage"] is None
    assert look["main_city_in_list"] is True and look["attribution"] == b.ATTRIBUTION and not look["notes"]
    assert look["dataset"]["age_days"] == 1.1 and look["stale"] is False
    assert b.city_in_ddd("Guarulhos", look) is True and b.city_in_ddd("Recife", look) is False


def test_lookup_without_the_dataset_uses_the_bundled_table():
    look = b.lookup_ddd("61", None, TABLE)
    assert look["coverage"] == b.CITY_LIST_UNAVAILABLE == pp.CITY_LIST_UNAVAILABLE
    assert (look["uf"], look["ufs"], look["main_city"]) == ("DF", ["DF", "GO"], "Brasília")
    assert look["cities"] is None and look["city_count"] is None
    no_table = b.lookup_ddd("61", None, None)
    assert no_table["uf"] is None and any("bundled DDD table" in n for n in no_table["notes"])


def test_lookup_stale_mismatch_and_unallocated():
    cities = b.parse_ddd_payload(body("ok_83_large.http.json"))["cities"]
    stale = b.lookup_ddd("83", {"ok": True, "state": "PB", "cities": cities, "age_hours": 24 * 45, "stale": True}, TABLE)
    assert stale["stale"] and stale["city_count"] == 223 and any("45.0 days old" in n for n in stale["notes"])
    mismatch = b.lookup_ddd("83", {"ok": True, "state": "RN", "cities": cities}, TABLE)  # synthetic state
    assert mismatch["uf"] == "PB" and any("differs from the bundled table" in n for n in mismatch["notes"])
    dataset_only = b.lookup_ddd("83", {"ok": True, "state": "PB", "cities": cities}, None)
    assert dataset_only["uf"] == "PB" and dataset_only["uf_source"] == "brasilapi_ddd"
    assert b.lookup_ddd("20", None, TABLE)["allocated"] is False


def test_lookup_phone_reads_only_the_number_ddd():
    ctx = make_ctx(PhoneParse, FakeHttp())
    store = make_runtime(add_fixture(add_fixture(FakeHttp(), "ok_61_multi_uf.http.json"), "ok_11.http.json")).data
    store.update("brasilapi_ddd.61")
    store.update("brasilapi_ddd.11")
    look = b.lookup_phone(ctx.data, "+556155550100")
    assert look["ddd"] == "61" and look["city_count"] == 13 and look["ufs"] == ["DF", "GO"]
    assert [d["name"] for d in ctx.data.used if d["name"].startswith("brasilapi_ddd")] == ["brasilapi_ddd.61"]
    assert b.lookup_phone(ctx.data, "+550800729000") is None and b.lookup_phone(ctx.data, "+14155550100") is None
    assert b.ddd_from_e164("+5511955550100") == "11" and b.ddd_from_e164("+552055550100") is None
    assert b.ddd_from_e164(5511) is None


def test_records_plug_into_phone_parse():
    store = make_runtime(add_fixture(FakeHttp(), "ok_61_multi_uf.http.json")).data
    store.update("brasilapi_ddd.61")
    parsed = pp.parse_ddd_dataset(b.installed_records(store))  # the shape phone_parse's reader expects
    info = pp.ddd_info("61", TABLE, parsed["61"])
    assert info["cities_source"] == "brasilapi_ddd" and info["coverage"] is None and len(info["cities"]) == 13


# ------------------------------------------------------------------------------------------------ FC3 report shapes


def test_report_summary_toggle_and_json():
    cities = b.parse_ddd_payload(body("ok_61_multi_uf.http.json"))["cities"]
    rep = b.ddd_report(b.lookup_ddd("61", {"ok": True, "state": "DF", "cities": cities}, TABLE))
    assert rep["terminal"] == rep["markdown"] == "DDD 61: DF (also GO) - Brasília - 13 cities in DDD"
    assert "VALPARA" not in rep["terminal"]  # the list never reaches terminal/Markdown
    assert rep["html"]["toggle"]["label"] == "13 cities in DDD 61" and "Valparaíso de Goiás" in rep["html"]["toggle"]["items"]
    assert rep["json"]["cities"] == cities and rep["json"]["city_count"] == 13 and rep["attribution"] == b.ATTRIBUTION
    missing = b.ddd_report(b.lookup_ddd("11", None, TABLE))
    assert missing["terminal"] == "DDD 11: SP - São Paulo" and missing["html"]["toggle"] is None
    assert missing["coverage"] == b.CITY_LIST_UNAVAILABLE and missing["json"]["cities"] is None
    assert b.ddd_report(b.lookup_ddd("10"))["terminal"] == "DDD 10: not an allocated Brazilian area code"
    assert b.ddd_report(None)["terminal"].startswith("DDD ?")


def test_labels_and_display_names():
    assert b.cities_label(1) == "1 city in DDD" and b.cities_label(223) == "223 cities in DDD"
    assert b.display_city("SÃO JOSÉ DOS CAMPOS") == "São José dos Campos"
    assert b.display_city("OLHO D'ÁGUA") == "Olho d'Água" and b.display_city("D'OESTE") == "D'Oeste"
    assert b.display_city("EMBU-GUAÇU") == "Embu-Guaçu" and b.display_city("  ") == ""


# ------------------------------------------------------------------------------------------------ notices, fixtures


def test_notice_fragment():
    notice = json.loads((ROOT / "v3lum/data/notices/brasilapi_ddd.json").read_text(encoding="utf-8"))
    assert notice["schema"] == "v3lum.notice/1" and notice["name"] == "brasilapi_ddd" and notice["bundled"] is False
    assert notice["licence"] == b.LICENCE and notice["attribution"] == b.ATTRIBUTION and notice["sha256"] == ""
    assert all((ROOT / f).is_file() for f in notice["files"])


def test_fixtures_carry_no_personal_data_or_request_ids():
    for path in sorted((ROOT / "tests/fixtures/brasilapi_ddd").glob("*.json")):
        env = json.loads(path.read_text(encoding="utf-8"))
        text = json.dumps(env, ensure_ascii=False)
        assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text) and not re.search(r"\d{8,}", env["response"]["body"])
        assert not {"set-cookie", "cookie", "authorization", "cf-ray", "x-vercel-id"} & set(env["response"]["headers"])
        assert b.ddd_url_problem(env["request"].split(" ", 1)[1]) in (None, "DDD 10 is not allocated")


def test_dataset_module_has_no_scan_time_module():
    from v3lum.core.module import REGISTRY, load_modules

    load_modules()
    assert "brasilapi_ddd" not in REGISTRY  # FC1: folded into phone_parse, no per-scan module
    assert datasets.DATASETS is DATASETS
