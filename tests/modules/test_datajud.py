"""Offline tests of datajud (P241) and the shared CNJ parser over tests/fixtures/datajud/.

Fixtures: trimmed research captures of DataJud (found 0700055-10.2018.8.01.0022 - public court metadata, no
parties; not found; HTTP 200 with failed shards; HTTP 429 es_rejected_execution_exception), the live 401
without a key, and the wiki access page reduced to its article with the published key replaced by a FAKE
Elasticsearch-shaped key (base64 of 'FixtureKeyId00000000:FixtureSecret000000000').
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import cnj_process as cnj
from v3lum.modules.brazil_public_data import datajud as mod
from v3lum.modules.brazil_public_data.datajud import DataJud

FX = FIXTURES / "datajud"
NUM = "0700055-10.2018.8.01.0022"
TJAC = "https://api-publica.datajud.cnj.jus.br/api_publica_tjac/_search"
TJDFT = "https://api-publica.datajud.cnj.jus.br/api_publica_tjdft/_search"
WIKI = "https://datajud-wiki.cnj.jus.br/api-publica/acesso/"
FAKE_KEY = "Rml4dHVyZUtleUlkMDAwMDAwMDA6Rml4dHVyZVNlY3JldDAwMDAwMDAwMA=="
CONFIGURED = "Q29uZmlndXJlZEtleTAwMDA6Q29uZmlndXJlZFNlY3JldDAwMDA="  # base64 of a fake '<id>:<secret>'
ALIASES_91 = {
    "stj", "stm", "tse", "tst", "tjac", "tjal", "tjam", "tjap", "tjba", "tjce", "tjdft", "tjes", "tjgo", "tjma",
    "tjmg", "tjms", "tjmt", "tjpa", "tjpb", "tjpe", "tjpi", "tjpr", "tjrj", "tjrn", "tjro", "tjrr", "tjrs", "tjsc",
    "tjse", "tjsp", "tjto", "tjmmg", "tjmrs", "tjmsp", "trf1", "trf2", "trf3", "trf4", "trf5", "trf6", "tre-ac",
    "tre-al", "tre-am", "tre-ap", "tre-ba", "tre-ce", "tre-dft", "tre-es", "tre-go", "tre-ma", "tre-mg", "tre-ms",
    "tre-mt", "tre-pa", "tre-pb", "tre-pe", "tre-pi", "tre-pr", "tre-rj", "tre-rn", "tre-ro", "tre-rr", "tre-rs",
    "tre-sc", "tre-se", "tre-sp", "tre-to",
} | {f"trt{n}" for n in range(1, 25)}


@pytest.fixture(autouse=True)
def _fresh_key_cache():
    mod.forget_published_key()
    yield
    mod.forget_published_key()


def make_cnj(seq: str, year: str, seg: str, tr: str, orig: str) -> str:
    return cnj.cnj_format(f"{seq}{cnj.cnj_dv(seq, year, seg, tr, orig):02d}{year}{seg}{tr}{orig}")


def wiki(http: FakeHttp, name: str = "wiki_acesso.html", times: int | None = None) -> FakeHttp:
    return http.add("GET", WIKI, text=(FX / name).read_text(encoding="utf-8"), times=times)


def exchange(http: FakeHttp, url: str, name: str, **kw) -> FakeHttp:
    rec = module_fixture(DataJud, name)
    resp = rec["response"]
    body = resp["body"]
    headers = {k: v for k, v in resp["headers"].items() if isinstance(v, str)}
    if isinstance(body, dict):
        return http.add("POST", url, status=resp["status"], json=body, headers=headers, **kw)
    if body is None:
        return http.add("POST", url, status=resp["status"], body=b"", headers=headers, **kw)
    return http.add("POST", url, status=resp["status"], text=body, headers=headers, **kw)


# ---------------------------------------------------------------------------- CNJ parser (cond 3-4)
def test_alias_table_matches_the_91_published_indices():
    assert len(cnj.DATAJUD_ALIASES) == 91 and set(cnj.DATAJUD_ALIASES) == ALIASES_91


def test_cnj_parse_real_vector():
    p = cnj.cnj_parse(NUM)
    assert p["valid"] and p["check_ok"] and p["index"] == "api_publica_tjac" and p["court"] == "TJAC"
    assert (p["sequence"], p["dv"], p["year"], p["segment"], p["tribunal_code"], p["origin"]) == ("0700055", "10", 2018, "8", "01", "0022")
    assert int(p["sequence"] + "2018" + "8" + "01" + "0022" + p["dv"]) % 97 == 1
    assert cnj.cnj_parse("07000551020188010022")["formatted"] == NUM
    bad = cnj.cnj_parse(NUM.replace("2018", "2019"))
    assert not bad["valid"] and bad["index"] is None and bad["reason"] == "check digits do not match"
    assert not cnj.cnj_parse("123")["valid"] and cnj.looks_like_cnj(NUM) and not cnj.looks_like_cnj(NUM + " x")


@pytest.mark.parametrize(("seg", "tr", "index", "court"), [
    ("8", "26", "api_publica_tjsp", "TJSP"), ("8", "07", "api_publica_tjdft", "TJDFT"),
    ("8", "03", "api_publica_tjap", "TJAP"), ("8", "04", "api_publica_tjam", "TJAM"),
    ("8", "25", "api_publica_tjse", "TJSE"), ("4", "01", "api_publica_trf1", "TRF1"),
    ("4", "06", "api_publica_trf6", "TRF6"), ("5", "00", "api_publica_tst", "TST"),
    ("5", "24", "api_publica_trt24", "TRT24"), ("6", "00", "api_publica_tse", "TSE"),
    ("6", "07", "api_publica_tre-dft", "TRE-DF"), ("6", "26", "api_publica_tre-sp", "TRE-SP"),
    ("3", "00", "api_publica_stj", "STJ"), ("7", "00", "api_publica_stm", "STM"),
    ("9", "13", "api_publica_tjmmg", "TJMMG"), ("9", "26", "api_publica_tjmsp", "TJMSP"),
    ("1", "00", None, "STF"), ("4", "90", None, "CJF"), ("5", "90", None, "CSJT"), ("9", "05", None, None),
])
def test_cnj_routing(seg, tr, index, court):
    p = cnj.cnj_parse(make_cnj("0001234", "2024", seg, tr, "0100"))
    assert p["valid"] and p["index"] == index and p["court"] == court
    if index is None:
        assert p["reason"].startswith("no public DataJud index")


def test_extract_caps_at_five_and_pivot_args():
    nums = [make_cnj(f"{i:07d}", "2023", "8", "26", "0100") for i in range(1, 8)]
    text = (f"Processo {nums[0]}; repetido {nums[0]}; invalido 0700055-11.2018.8.01.0022; sem mascara "
            f"{nums[1].replace('-', '').replace('.', '')}; " + "; ".join(nums[2:]))
    out = cnj.extract_cnj_numbers(text)
    assert [n["formatted"] for n in out["numbers"]] == nums[:5]
    assert out["invalid"] == 1 and out["over_limit"] == 2
    args = cnj.cnj_pivot_args(out["numbers"][0])
    assert args["expand"] is False and args["value"] == nums[0] and args["relation"] == "mentions"
    assert cnj.extract_cnj_numbers("telefone 11987654321 e boleto 23790.12345 60000.000005")["numbers"] == []


def test_key_extraction_is_strict():
    assert mod.extract_datajud_key((FX / "wiki_acesso.html").read_text(encoding="utf-8")) == FAKE_KEY
    assert mod.extract_datajud_key((FX / "wiki_acesso_bad_value.html").read_text(encoding="utf-8")) is None
    assert mod.extract_datajud_key((FX / "wiki_acesso_no_key.html").read_text(encoding="utf-8")) is None
    assert mod.extract_datajud_key("APIKey atual: Authorization: APIKey [Chave Pública]") is None


def test_parse_search_whitelists_and_filters():
    multi = module_fixture(DataJud, "ok_multi.json")
    out = mod.parse_search(multi, "07000551020188010022")
    assert out["status"] == "found" and {h["grau"] for h in out["hits"]} == {"G1", "G2"}
    assert all(h["numero"] == NUM and not h["sigilo"] for h in out["hits"])  # unrelated and sealed hits dropped
    allowed = {"numero", "numero_digits", "tribunal", "grau", "index", "classe", "assuntos", "orgao_julgador", "data_ajuizamento",
               "sistema", "formato", "ultima_atualizacao", "movimentos_recentes", "movimentos_total", "sigilo"}
    assert all(set(h) == allowed for h in out["hits"])
    assert mod.parse_search(module_fixture(DataJud, "partial_shards_200.json"), "x")["status"] == "overloaded"
    assert mod.parse_search(module_fixture(DataJud, "not_found.json"), "x")["status"] == "not_found"
    assert mod.parse_search(b"<html>", "x")["status"] == "error"
    assert mod.parse_search(["not", "an", "object"], "x")["status"] == "error"
    assert mod.parse_search({"took": 1}, "x")["reason"].startswith("DataJud answer format changed")


# ---------------------------------------------------------------------------- module runs
def test_found_metadata_only_with_published_key():
    http = wiki(FakeHttp())
    http.add("POST", TJAC, json=module_fixture(DataJud, "ok.json"), match_headers={"Authorization": f"APIKey {FAKE_KEY}"})
    res = run_module(DataJud, f"keyword:{NUM}", http)
    assert res.status is Status.OK
    cases = res.attributes["court_cases"]
    assert cases[0]["numero"] == NUM and cases[0]["tribunal"] == "TJAC" and cases[0]["classe"]["nome"] == "Execução Fiscal"
    movs = cases[0]["movimentos_recentes"]
    assert len(movs) <= 5 and [m["data"] for m in movs] == sorted((m["data"] for m in movs), reverse=True)
    assert res.attributes["export_restriction"]["redistributable"] is False
    assert res.attributes["datajud_status"][NUM].startswith("found in public DataJud")
    f = res.findings[0]
    assert f.severity.name == "INFO" and "no_export" in f.tags and f.source == "cnj.datajud"
    assert res.pivots == [] and res.links == []
    body = json.loads(http.calls[-1]["body"])
    assert body == {"query": {"match": {"numeroProcesso": "07000551020188010022"}}, "size": 10}
    assert_no_secret(FAKE_KEY, res.raw, res.attributes, [f.to_dict() for f in res.findings], res.error)
    http.assert_hosts_within(DataJud)


def test_configured_key_is_used_and_wiki_never_read():
    http = FakeHttp().add("POST", TJAC, json=module_fixture(DataJud, "ok.json"), match_headers={"Authorization": f"APIKey {CONFIGURED}"})
    res = run_module(DataJud, f"keyword:{NUM}", http, keys={"datajud": CONFIGURED})
    assert res.status is Status.OK and WIKI not in http.urls()


def test_not_found_is_never_no_case():
    http = wiki(FakeHttp()).add("POST", TJAC, json=module_fixture(DataJud, "not_found.json"))
    res = run_module(DataJud, f"keyword:{NUM}", http)
    assert res.status is Status.EMPTY and "not found in public DataJud" in res.error and "never 'no case'" in res.error
    assert "no case" not in res.attributes["datajud_status"][NUM].replace("never 'no case'", "")


def test_401_refreshes_the_published_key_once():
    http = FakeHttp()
    exchange(http, TJAC, "auth_401_bad_key.http.json", match_headers={"Authorization": f"APIKey {CONFIGURED}"})
    wiki(http)
    http.add("POST", TJAC, json=module_fixture(DataJud, "ok.json"), match_headers={"Authorization": f"APIKey {FAKE_KEY}"})
    res = run_module(DataJud, f"keyword:{NUM}", http, keys={"datajud": CONFIGURED})
    assert res.status is Status.OK and http.urls().count(WIKI) == 1


def test_401_with_unchanged_published_key_is_needs_key_not_empty():
    http = wiki(FakeHttp(), times=2)
    exchange(http, TJAC, "auth_401_nokey.http.json", times=3)
    res = run_module(DataJud, f"keyword:{NUM}", http)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert http.urls().count(WIKI) == 2  # the first read, then exactly one refresh in this run


def test_key_page_without_key_is_needs_key():
    http = wiki(FakeHttp(), "wiki_acesso_no_key.html")
    res = run_module(DataJud, f"keyword:{NUM}", http)
    assert res.status is Status.NEEDS_KEY and "APIKey atual" in res.error


def test_429_overload_is_rate_limited_and_the_core_backoff_stops_resends():
    """HTTP 429 es_rejected_execution_exception: RATE_LIMITED 'could not verify: DataJud overloaded'. The core
    client backs the provider off for the rest of the run (no Retry-After, P334), so the next number of the same
    text is not sent either (still 'could not verify', never 'not found')."""
    http = wiki(FakeHttp())
    exchange(http, TJDFT, "rate_limited_429.http.json", times=1)
    first = make_cnj("0001234", "2024", "8", "07", "0001")
    second = make_cnj("0001235", "2024", "8", "07", "0001")
    res = run_module(DataJud, f"text:{first} e {second}", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    assert "could not verify: DataJud overloaded" in res.error
    assert [c["url"] for c in http.calls].count(TJDFT) == 1
    assert all("overloaded" in v for v in res.attributes["datajud_status"].values())


def test_429_without_body_is_rate_limited():
    http = wiki(FakeHttp())
    exchange(http, TJAC, "rate_limited_429_no_body.http.json")
    res = run_module(DataJud, f"keyword:{NUM}", http)
    assert res.status is Status.RATE_LIMITED


def test_failed_shards_retried_once_after_backoff_then_found():
    http = wiki(FakeHttp())
    http.add("POST", TJAC, json=module_fixture(DataJud, "partial_shards_200.json"), times=1)
    http.add("POST", TJAC, json=module_fixture(DataJud, "ok.json"))
    res = run_module(DataJud, f"keyword:{NUM}", http)
    assert res.status is Status.OK and res.raw["queries"][0]["attempts"] == 2


def test_failed_shards_in_http_200_are_could_not_verify():
    http = wiki(FakeHttp()).add("POST", TJAC, json=module_fixture(DataJud, "partial_shards_200.json"), times=2)
    res = run_module(DataJud, f"keyword:{NUM}", http)
    assert res.status is Status.RATE_LIMITED and "overloaded" in res.error


def test_no_retry_when_the_deadline_is_too_close():
    http = wiki(FakeHttp())
    http.add("POST", TJAC, json=module_fixture(DataJud, "partial_shards_200.json"), latency=50.0)
    res = run_module(DataJud, f"keyword:{NUM}", http)
    assert res.status is Status.RATE_LIMITED and [c["url"] for c in http.calls].count(TJAC) == 1


def test_html_502_and_timeout_are_errors():
    http = wiki(FakeHttp())
    exchange(http, TJAC, "html_502.http.json")
    res = run_module(DataJud, f"keyword:{NUM}", http)
    assert res.status is Status.ERROR and "HTTP 502" in res.error
    captured = module_fixture(DataJud, "timeout.http.json")["transport_error"]  # research capture: no byte in 25 s
    http2 = wiki(FakeHttp()).add("POST", TJAC, error=NetworkError(captured, retryable=False, kind="Timeout"))
    res2 = run_module(DataJud, f"keyword:{NUM}", http2)
    assert res2.status is Status.ERROR and "could not verify" in res2.error


def test_malformed_json_is_error_never_empty():
    http = wiki(FakeHttp()).add("POST", TJAC, text="<html>maintenance</html>", headers={"content-type": "application/json"})
    res = run_module(DataJud, f"keyword:{NUM}", http)
    assert res.status is Status.ERROR


def test_text_blob_queries_at_most_five_and_skips_unroutable():
    stf = make_cnj("0001234", "2024", "1", "00", "0000")
    others = [make_cnj(f"{i:07d}", "2023", "8", "01", "0001") for i in range(1, 7)]
    text = f"STF {stf}; " + "; ".join(others)
    http = wiki(FakeHttp()).add("POST", TJAC, json=module_fixture(DataJud, "not_found.json"), times=5)
    res = run_module(DataJud, f"text:{text}", http)
    nums = res.attributes["cnj_numbers"]
    assert len(nums["numbers"]) == 5 and nums["over_limit"] == 2
    assert res.attributes["datajud_status"][stf].startswith("no public DataJud index for STF")
    assert [c["url"] for c in http.calls].count(TJAC) == 4
    assert res.status is Status.EMPTY


def test_only_unroutable_numbers_are_not_applicable_and_send_nothing():
    stf = make_cnj("0001234", "2024", "1", "00", "0000")
    res = run_module(DataJud, f"keyword:{stf}", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_non_cnj_inputs_are_not_applicable():
    assert run_module(DataJud, "keyword:empresa exemplo", FakeHttp()).reason_code == "not_applicable"
    assert run_module(DataJud, "text:no process number here 12345", FakeHttp()).reason_code == "not_applicable"


def test_metadata_contract():
    assert DataJud.terms == "noncommercial" and DataJud.default_enabled is False and DataJud.run_on == "seeds"
    assert DataJud.expected_latency > 10 and DataJud.timeout == 60.0 and DataJud.trust_tier == "trusted"
    assert set(DataJud.hosts) == {"api-publica.datajud.cnj.jus.br", "datajud-wiki.cnj.jus.br"}


def test_off_under_the_corporate_licence_profile():
    """P241 cond 2: noncommercial terms -> SKIPPED 'licence' under corporate, even when selected explicitly."""
    from tests.fakes import make_runtime
    from v3lum.core import policy
    from v3lum.core.context import ScanOptions
    from v3lum.core.entities import Entity
    from v3lum.core.entities import EntityType as T

    from v3lum.core.context import RunInfo

    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.KEYWORD, NUM)
    pctx = policy.make_context(rt, ScanOptions(include={"datajud"}), explicit=("datajud",))
    run = RunInfo(entity=ent, is_seed=True, depth=0, provenance=(), allowed_sources=None, tlp="", deadline=None, case_id="",
                  priority="seed", internal_seed=False)
    decision = policy.decide(DataJud, ent, pctx, run=run)
    assert not decision.allowed and decision.reason_code == "licence"
    assert "noncommercial" in decision.blocked_sources["cnj.datajud"]


def test_module_refuses_when_the_source_is_not_allowed():
    res = run_module(DataJud, f"keyword:{NUM}", FakeHttp(), allowed_sources=())
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
