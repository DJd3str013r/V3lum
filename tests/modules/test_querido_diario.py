"""querido_diario (P243): Querido Diario municipal-gazette search.

Fixtures in tests/fixtures/querido_diario/ (batch p2-G10-3 prep, 2026-11-25/26):

* live captures, names of officials replaced by 'Pessoa Exemplo ...': ``ok.json`` (CNPJ query for Banco do
  Brasil, 8 gazettes, total 468, co-mentioned CNPJs, a cut and a malformed CNPJ, routine 'multa de
  transito'), ``empty.json``, ``error_422.http.json``, ``timeout.http.json``, ``old_host_tls.http.json``,
  ``malformed_truncated.json`` (the live body cut at 700 bytes);
* the four research captures (P243 FC7): ``research_cnpj_ok.json``, ``research_newhost_ok.json``,
  ``cities_ok.json``, ``themes_ok.json`` (excerpts already redacted there);
* synthetic (not observable from the research egress, labelled so): ``penalty_cnj_synthetic.json``,
  ``error_5xx_synthetic.http.json``, ``error_500_synthetic.http.json``, ``rate_limited_synthetic.http.json``,
  ``challenge_synthetic.http.json``, ``error_in_200_synthetic.json``, ``inconsistent_synthetic.json``,
  ``company_info_mei_synthetic.json`` (documentation CPF 123.456.789-09);
* ``company_info_ok.json`` and ``company_info_not_found.http.json``: the /company/info answers of batch
  p1-G10-2 (contacts replaced by documentation values).
"""

from __future__ import annotations

import json
import re

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Severity, Status
from v3lum.modules.brazil_public_data import querido_diario as Q
from v3lum.modules.brazil_public_data.querido_diario import QueridoDiario

BB = "00000000000191"
BB_FMT = '"00.000.000/0001-91"'
SINCE, UNTIL = "2024-11-26", "2026-11-26"  # FakeClock: 2026-11-26, 2-year window
COMPANY = "https://api.queridodiario.org.br/company/info/{}"


def fx(name: str):
    return module_fixture("querido_diario", name)


def http_fx(name: str) -> dict:
    return fx(name)["response"]


def url(q: str, since: str = SINCE, until: str = UNTIL) -> str:
    return Q.gazettes_url(q, since, until)


def add_envelope(http: FakeHttp, route: str, name: str) -> FakeHttp:
    r = http_fx(name)
    body = r["body"]
    kw = {"json": body} if isinstance(body, (dict, list)) else {"text": body}
    return http.add("GET", route, status=r["status"], headers=r.get("headers") or {}, **kw)


def bb_http(*, razao: dict | None = None, info: str = "company_info_ok.json") -> FakeHttp:
    http = FakeHttp().add("GET", url(BB_FMT), json=fx("ok.json"))
    http.add("GET", COMPANY.format(BB), json=fx(info))
    http.add("GET", url('"BANCO DO BRASIL SA"'), **(razao or {"json": fx("research_newhost_ok.json")}))
    return http


def gm(res) -> dict:
    return res.attributes["gazette_mentions"]


def pivots(res, etype=None) -> dict:
    return {p.entity.value: p for p in res.pivots if etype is None or p.entity.type is etype}


# ======================================================================================
# happy path: CNPJ seed (FC2-FC5)
# ======================================================================================


def test_cnpj_seed_searches_formatted_cnpj_then_record_names():
    http = bb_http()
    res = run_module(QueridoDiario, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    urls = http.urls()
    assert urls[0].startswith(Q.GAZETTES_URL) and "querystring=%2200.000.000%2F0001-91%22" in urls[0]
    assert urls[1] == COMPANY.format(BB)
    # razao social searched; the nome fantasia 'DIRECAO GERAL' is a department label and is skipped
    assert len(urls) == 3 and "BANCO+DO+BRASIL+SA" in urls[2]
    assert not any("DIRECAO" in u for u in urls)
    m = gm(res)
    assert m["count"] == 468 and m["counts"] == {"cnpj": 468, "razao_social": 20}
    assert m["window"] == {"since": SINCE, "until": UNTIL}
    assert [q["kind"] for q in m["queries"]] == ["cnpj", "razao_social"]
    assert len(m["top"]) == 5 and m["attribution"] == Q.QD_ATTRIBUTION
    assert m["coverage"] == Q.COVERAGE_NOTE
    http.assert_hosts_within(QueridoDiario)


def test_request_parameters_bound_the_output():
    http = bb_http()
    run_module(QueridoDiario, f"cnpj:{BB}", http)
    first = http.urls()[0]
    for param in ("size=10", "number_of_excerpts=1", "excerpt_size=300", "published_since=2024-11-26",
                  "published_until=2026-11-26", "sort_by=descending_date", "offset=0"):
        assert param in first


def test_mentions_are_info_context_only_and_never_scored():
    res = run_module(QueridoDiario, f"cnpj:{BB}", bb_http())
    f = next(f for f in res.findings if f.title == "Mentioned in municipal gazettes (Querido Diario)")
    assert f.severity is Severity.INFO and "context_only" in f.tags
    assert f.confidence_label == "confirmed"  # the formatted CNPJ itself was found
    assert f.source == Q.SOURCE and f.criterion
    assert all(x.severity is Severity.INFO for x in res.findings)


def test_minimisation_excerpts_links_and_no_person_entities():
    res = run_module(QueridoDiario, f"cnpj:{BB}", bb_http())
    top = gm(res)["top"]
    assert all(len(e) <= 300 for h in top for e in h["excerpts"])
    assert all(set(h) <= {"municipality", "state", "territory_id", "date", "edition", "extra_edition", "url", "excerpts",
                          "penalty_terms", "queries"} for h in top)
    assert {p.entity.type for p in res.pivots} <= {T.CNPJ, T.KEYWORD}  # never PERSON (FC4)
    links = dict((u, lbl) for lbl, u in res.links)
    assert 0 < len(links) <= 5 and all(u.startswith("https://data.queridodiario.ok.org.br/") for u in links)
    assert "txt_url" not in json.dumps(gm(res))


def test_co_mentioned_cnpjs_are_non_expanding_hypotheses():
    res = run_module(QueridoDiario, f"cnpj:{BB}", bb_http())
    cnpjs = pivots(res, T.CNPJ)
    assert BB not in cnpjs  # the queried CNPJ itself
    assert "24851511001904" in cnpjs and "05816451000115" in cnpjs and "00360305000104" in cnpjs
    assert "9040088800001" not in "".join(cnpjs)  # malformed '90.400.888/00001-42' ignored
    assert not any(v.endswith("306294000145") for v in cnpjs)  # cut at the excerpt edge
    assert 0 < len(cnpjs) <= Q.MAX_CNPJ_PIVOTS
    for p in cnpjs.values():
        assert p.expand is False and p.relation == "co_mentioned_in_gazette" and p.confidence_label == "possible"
        assert "hypothesis" in p.note


def test_penalty_terms_rank_first_and_cnj_numbers_pivot_without_expanding():
    http = FakeHttp().add("GET", url(BB_FMT), json=fx("penalty_cnj_synthetic.json"))
    http.add("GET", COMPANY.format(BB), status=404, json={"detail": "Company not found."})
    res = run_module(QueridoDiario, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    top = gm(res)["top"]
    assert top[0]["municipality"] == "São Paulo" and top[0]["penalty_terms"] == ["multa", "penalidade", "rescisao", "suspensao"]
    salinas = next(h for h in top if h["municipality"] == "Salinas")
    assert salinas["penalty_terms"] == []  # 'multas de transito' is routine
    assert len(salinas["excerpts"]) == 2
    text = json.dumps(gm(res), ensure_ascii=False)
    assert "123.456.789-09" not in text and "***.***.***-**" in text  # CPF masked (rule 4)
    assert all(len(e) <= 300 for h in top for e in h["excerpts"])
    kw = pivots(res, T.KEYWORD)
    assert set(kw) == {"0700055-10.2018.8.01.0022"}  # the invalid number is not extracted, the bare repeat deduplicated
    assert kw["0700055-10.2018.8.01.0022"].expand is False and kw["0700055-10.2018.8.01.0022"].relation == "mentions"
    cnpjs = pivots(res, T.CNPJ)
    assert "12ABC34501DE35" in cnpjs  # alphanumeric CNPJ (IN RFB 2.229/2024)
    assert "00000000000192" not in cnpjs  # wrong check digit
    pen = next(f for f in res.findings if f.title == "Municipal gazette excerpts mention penalty terms")
    assert pen.severity is Severity.INFO and "penalty_term" in pen.tags
    assert res.source_statuses[Q.SOURCE_COMPANY]["status"] == "empty"


def test_at_most_ten_excerpts_per_query():
    body = {"total_gazettes": 2000, "gazettes": [
        {"territory_id": "3550308", "date": f"2026-10-{d:02d}", "territory_name": "São Paulo", "state_code": "SP",
         "url": f"https://data.queridodiario.ok.org.br/3550308/2026-10-{d:02d}/x{d}.pdf",
         "excerpts": [f"trecho {d}a CNPJ 00.000.000/0001-91", f"trecho {d}b CNPJ 00.000.000/0001-91"]} for d in range(1, 16)]}
    parsed = Q.parse_gazettes(body, ["00.000.000/0001-91"], BB)
    assert parsed["ok"] and parsed["total"] == 2000
    assert sum(len(h["excerpts"]) for h in parsed["hits"]) == 10
    assert all(len(h["excerpts"]) <= 1 for h in parsed["hits"])  # first excerpts before any second one


def test_research_captures_parse():
    for name, total in (("research_cnpj_ok.json", 2292), ("research_newhost_ok.json", 20)):
        parsed = Q.parse_gazettes(fx(name))
        assert parsed["ok"] and parsed["total"] == total and parsed["returned"] == 1
        assert parsed["hits"][0]["url"].startswith("https://data.queridodiario.ok.org.br/")
    cities = Q.parse_cities(fx("cities_ok.json"))
    assert len(cities) == 6 and [c["name"] for c in cities if c["covered"]] == ["Corumbá"]
    assert Q.parse_themes(fx("themes_ok.json")) == ["Políticas Ambientais", "Tecnologias na Educação"]
    assert Q.parse_cities({"cities": "x"}) == [] and Q.parse_themes(["x"]) == []


# ======================================================================================
# FC6: empty wording and rule 5
# ======================================================================================


def test_empty_reads_not_found_in_covered_gazettes():
    http = FakeHttp().add("GET", url(BB_FMT), json=fx("empty.json"))
    add_envelope(http, COMPANY.format(BB), "company_info_not_found.http.json")
    res = run_module(QueridoDiario, f"cnpj:{BB}", http)
    assert res.status is Status.EMPTY
    assert res.error == Q.QD_EMPTY_TEXT and "no mentions" not in res.error
    assert gm(res)["count"] == 0 and gm(res)["line"] == Q.QD_EMPTY_TEXT
    assert not res.findings and not res.pivots


@pytest.mark.parametrize(
    ("fixture", "status", "code"),
    [
        ("rate_limited_synthetic.http.json", Status.RATE_LIMITED, "rate_limited"),
        ("challenge_synthetic.http.json", Status.BLOCKED, "challenge"),
        ("error_5xx_synthetic.http.json", Status.ERROR, "error"),
        ("error_500_synthetic.http.json", Status.ERROR, "error"),
        ("error_422.http.json", Status.ERROR, "error"),
    ],
)
def test_http_failures_are_could_not_verify(fixture, status, code):
    http = add_envelope(FakeHttp(), url(BB_FMT), fixture)
    res = run_module(QueridoDiario, f"cnpj:{BB}", http)
    assert res.status is status and res.reason_code == code
    assert "not found in covered gazettes" not in res.error
    assert "gazette_mentions" not in res.attributes


def test_keyless_403_without_marker_is_blocked():
    http = FakeHttp().add("GET", url(BB_FMT), status=403, text="Forbidden")
    assert run_module(QueridoDiario, f"cnpj:{BB}", http).status is Status.BLOCKED


def test_401_is_blocked_never_empty():
    http = FakeHttp().add("GET", url(BB_FMT), status=401, json={"detail": "Not authenticated"})
    res = run_module(QueridoDiario, f"cnpj:{BB}", http)
    assert res.status is Status.BLOCKED


def test_timeout_is_error():
    http = FakeHttp().add("GET", url(BB_FMT), error=NetworkError("The read operation timed out", kind="ReadTimeout"))
    res = run_module(QueridoDiario, f"cnpj:{BB}", http)
    assert res.status is Status.ERROR


@pytest.mark.parametrize("fixture", ["error_in_200_synthetic.json", "inconsistent_synthetic.json"])
def test_error_in_200_bodies_are_errors_and_never_cached(fixture):
    http = FakeHttp().add("GET", url(BB_FMT), json=fx(fixture))
    rt = make_runtime(http, cache=True)
    res = run_module(QueridoDiario, f"cnpj:{BB}", runtime=rt)
    assert res.status is Status.ERROR and "could not verify" in res.error
    run_module(QueridoDiario, f"cnpj:{BB}", runtime=rt)
    assert len(http.urls()) == 2  # the error body never entered the cache


@pytest.mark.parametrize("body", [b'["not", "an", "object"]', b'{"total_gazettes": "12", "gazettes": []}',
                                  b'{"total_gazettes": 3, "gazettes": {"a": 1}}', b'{"gazettes": []}'])
def test_unexpected_shapes_are_errors(body):
    http = FakeHttp().add("GET", url(BB_FMT), body=body, headers={"content-type": "application/json"})
    assert run_module(QueridoDiario, f"cnpj:{BB}", http).status is Status.ERROR


def test_malformed_truncated_json_is_error_and_not_cached():
    raw = (FIXTURES / "querido_diario" / "malformed_truncated.json").read_bytes()
    http = FakeHttp().add("GET", url(BB_FMT), body=raw, headers={"content-type": "application/json"})
    rt = make_runtime(http, cache=True)
    assert run_module(QueridoDiario, f"cnpj:{BB}", runtime=rt).status is Status.ERROR
    assert run_module(QueridoDiario, f"cnpj:{BB}", runtime=rt).status is Status.ERROR
    assert len(http.urls()) == 2


def test_good_answers_are_cached_24h():
    http = FakeHttp().add("GET", url('"EMPRESA EXEMPLO LTDA"'), json=fx("research_newhost_ok.json"))
    rt = make_runtime(http, cache=True)
    first = run_module(QueridoDiario, "company_name:EMPRESA EXEMPLO LTDA", runtime=rt)
    second = run_module(QueridoDiario, "company_name:EMPRESA EXEMPLO LTDA", runtime=rt)
    assert first.status is second.status is Status.OK
    assert len(http.urls()) == 1
    assert QueridoDiario.cache_ttl == 86400 and QueridoDiario.min_interval >= 1.0


def test_name_query_failure_after_cnpj_hits_keeps_the_hits():
    http = bb_http(razao={"error": NetworkError("The read operation timed out", kind="ReadTimeout")})
    res = run_module(QueridoDiario, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    q = {r["kind"]: r for r in gm(res)["queries"]}
    assert q["cnpj"]["state"] == "ok" and q["razao_social"]["state"] == "could_not_verify"
    assert q["razao_social"]["reason"] == "timeout"
    assert "could not verify: razao_social query (timeout)" in gm(res)["line"]


def test_name_query_rate_limited_after_hits_is_partial():
    http = bb_http(razao={"status": 429, "json": {"detail": "Too Many Requests"}})
    res = run_module(QueridoDiario, f"cnpj:{BB}", http)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"


def test_name_query_failure_with_no_hit_decides_the_status():
    http = FakeHttp().add("GET", url(BB_FMT), json=fx("empty.json"))
    http.add("GET", COMPANY.format(BB), json=fx("company_info_ok.json"))
    http.add("GET", url('"BANCO DO BRASIL SA"'), status=429, json={"detail": "Too Many Requests"})
    res = run_module(QueridoDiario, f"cnpj:{BB}", http)
    assert res.status is Status.RATE_LIMITED  # never 'not found in covered gazettes'


def test_company_info_failure_only_costs_the_name_queries():
    http = FakeHttp().add("GET", url(BB_FMT), json=fx("ok.json"))
    http.add("GET", COMPANY.format(BB), status=502, text="<html><title>502: Bad gateway</title></html>")
    res = run_module(QueridoDiario, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    assert http.urls().count(COMPANY.format(BB)) == 2  # the core retries a 502 once; no name query follows
    assert not any("BANCO+DO+BRASIL" in u for u in http.urls())
    assert res.source_statuses[Q.SOURCE_COMPANY]["status"] == "error"


# ======================================================================================
# FC2: query policy
# ======================================================================================


def test_mei_record_names_are_never_searched():
    mei = "11222333000181"
    http = FakeHttp().add("GET", url('"11.222.333/0001-81"'), json=fx("empty.json"))
    http.add("GET", COMPANY.format(mei), json=fx("company_info_mei_synthetic.json"))
    res = run_module(QueridoDiario, f"cnpj:{mei}", http)
    assert res.status is Status.EMPTY and len(http.urls()) == 2
    assert not any("PESSOA" in u or "12345678909" in u for u in http.urls())


def test_alphanumeric_cnpj_skips_company_info():
    alnum = "12ABC34501DE35"
    http = FakeHttp().add("GET", url('"12.ABC.345/01DE-35"'), json=fx("empty.json"))
    res = run_module(QueridoDiario, f"cnpj:{alnum}", http)
    assert res.status is Status.EMPTY and len(http.urls()) == 1
    assert res.source_statuses[Q.SOURCE_COMPANY]["status"] == "skipped"


def test_pivoted_cnpj_runs_only_on_explicit_request():
    res = run_module(QueridoDiario, f"cnpj:{BB}", FakeHttp(), is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    http = bb_http()
    res = run_module(QueridoDiario, f"cnpj:{BB}", http, is_seed=False, depth=1, options=ScanOptions(include={"querido_diario"}))
    assert res.status is Status.OK


def test_company_name_seed_single_exact_phrase():
    http = FakeHttp().add("GET", url('"EMPRESA EXEMPLO LTDA"'), json=fx("empty.json"))
    res = run_module(QueridoDiario, 'company_name:EMPRESA "EXEMPLO" LTDA', http)
    assert res.status is Status.EMPTY and len(http.urls()) == 1


def test_company_name_pivot_or_record_name_is_not_searched():
    res = run_module(QueridoDiario, "company_name:EMPRESA EXEMPLO LTDA", FakeHttp(), is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    res = run_module(QueridoDiario, "company_name:BANCO DO BRASIL SA", FakeHttp(), is_seed=False, depth=1,
                     provenance=[(f"cnpj:{BB}", "legal_name", "cnpj_lookup")], options=ScanOptions(include={"querido_diario"}))
    assert res.status is Status.SKIPPED and "CNPJ record" in res.error


def test_keyword_only_on_explicit_request():
    res = run_module(QueridoDiario, "keyword:licitacao exemplo", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_default"
    http = FakeHttp().add("GET", url("licitacao exemplo"), json=fx("empty.json"))
    res = run_module(QueridoDiario, "keyword:licitacao exemplo", http, options=ScanOptions(include={"querido_diario"}))
    assert res.status is Status.EMPTY


def test_person_name_needs_a_typed_seed_and_a_recorded_purpose():
    res = run_module(QueridoDiario, "person_name:Pessoa Exemplo Silva", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    res = run_module(QueridoDiario, "person_name:Pessoa Exemplo Silva", FakeHttp(), is_seed=False, depth=1,
                     provenance=[(f"cnpj:{BB}", "partner_of", "cnpj_lookup")], options=ScanOptions(purpose="due diligence"))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"  # never QSA names
    http = FakeHttp().add("GET", url('"Pessoa Exemplo Silva"'), json=fx("empty.json"))
    res = run_module(QueridoDiario, "person_name:Pessoa Exemplo Silva", http,
                     options=ScanOptions(purpose="supplier due diligence, ticket DD-1"))
    assert res.status is Status.EMPTY and len(http.urls()) == 1


def test_window_setting():
    http = FakeHttp().add("GET", url('"EMPRESA EXEMPLO LTDA"', since="2025-11-26"), json=fx("empty.json"))
    res = run_module(QueridoDiario, "company_name:EMPRESA EXEMPLO LTDA", http, settings={"querido_diario_window_years": 1})
    assert res.status is Status.EMPTY


# ======================================================================================
# FC1: host, metadata
# ======================================================================================


def test_metadata_matches_the_council_decision():
    assert QueridoDiario.hosts == ("api.queridodiario.org.br",)
    assert QueridoDiario.default_enabled is True and QueridoDiario.terms == "open"
    assert QueridoDiario.trust_tier == "community" and QueridoDiario.shares_input is True
    assert QueridoDiario.opsec.label == "passive"
    assert all("ok.org.br" not in h for h in QueridoDiario.hosts)
    assert QueridoDiario.cache_ttl == 86400 and QueridoDiario.min_interval == 1.0


def test_old_host_is_never_contacted():
    http = bb_http()
    run_module(QueridoDiario, f"cnpj:{BB}", http)
    assert all(not re.search(r"api\.queridodiario\.ok\.org\.br", u) for u in http.urls())
    assert fx("old_host_tls.http.json")["transport_error"].count("HANDSHAKE_FAILURE") == 1
    assert fx("timeout.http.json")["response"] is None


def test_helpers():
    assert Q.quote_phrase('A "B" \\ C') == '"A B C"' and Q.quote_phrase("  ") is None
    assert Q.usable_trade_name("DIRECAO GERAL", "BANCO DO BRASIL SA") is None
    assert Q.usable_trade_name("Banco do Brasil SA", "BANCO DO BRASIL SA") is None
    assert Q.usable_trade_name("Padaria Exemplo", "PADARIA EXEMPLO EIRELI") == "Padaria Exemplo"
    assert Q.error_in_200({"detail": "x"}).startswith("API error detail")
    assert Q.error_in_200({"total_gazettes": 0, "gazettes": []}) is None


def test_golden_path_acceptance_routes_replay():
    doc = json.loads((FIXTURES / "acceptance" / "cnpj" / "querido_diario.json").read_text())
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "querido_diario"
    http = FakeHttp()
    for r in doc["routes"]:
        http.add(r["method"], r["url"], status=r["status"], json=r["json"], headers=r.get("headers"))
    res = run_module(QueridoDiario, "cnpj:00000000000191", http)
    assert res.status is Status.OK and len(http.urls()) == len(doc["routes"])
    assert sum(1 for f in res.findings if f.severity is not Severity.INFO) == 0  # benign golden input: INFO only
