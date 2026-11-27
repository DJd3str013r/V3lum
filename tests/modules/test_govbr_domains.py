"""govbr_domains (P009): the SISP gov.br list as a dataset, exact matching, URL-level non-suppression.

Fixtures in tests/fixtures/govbr_domains/: ``csv_ok.csv`` is the real dominios_gov_br.csv of 2026-11-26
trimmed to the header and 12 rows, with the natural-person column ``nome_contato`` replaced by
'Contato Exemplo NN'; ``s3_403_access_denied.xml`` the real S3 answer for a missing object (request ids
redacted). Derived from the real file: ``csv_bad_header.csv`` (comma header) and ``csv_truncated.csv``
(2 rows).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.models import ModuleResult, Status
from v3lum.core.scoring import score
from v3lum.modules.domain_dns import govbr_domains as mod
from v3lum.modules.domain_dns.govbr_domains import DATASET, URL, GovbrDomains

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "govbr_domains"


@pytest.fixture(autouse=True)
def small_list(monkeypatch):
    monkeypatch.setattr(mod, "MIN_ROWS", 5)  # the trimmed fixture has 12 rows (the real list 1,280)


def csv_bytes(name: str = "csv_ok.csv") -> bytes:
    return (FIXTURES / name).read_bytes()


def installed(http: FakeHttp | None = None):
    http = http or FakeHttp()
    http.add("GET", URL, body=csv_bytes(), headers={"content-type": "binary/octet-stream", "etag": '"abc"'}, times=1)
    rt = make_runtime(http)
    assert rt.data.update(DATASET).ok
    http.calls.clear()
    return http, rt


def test_contract_metadata():
    cls = GovbrDomains
    assert (cls.terms, cls.disclosure, cls.hosts, cls.provider, cls.sources) == ("open", "none", (), "", ("sisp.dominios_gov_br",))
    assert cls.default_enabled is True and cls.shares_input is False
    assert getattr(cls.max_tlp, "name", cls.max_tlp) in ("RED", "red")  # cond 2: allowed at TLP:RED
    assert {T.DOMAIN, T.CNPJ} == set(cls.accepts) and T.URL not in cls.accepts  # cond 3: never a URL


def test_exact_listed_domain_is_official_with_registrant_cnpj():
    http, rt = installed()
    res = run_module(GovbrDomains, "domain:receita.gov.br", runtime=rt)
    assert res.status is Status.OK
    official = res.attributes["official_gov_br"]
    assert official["registrant_cnpj"] == "33683111000107" and official["registrant"].startswith("SERVICO FEDERAL")
    assert official["list_date"] == "2026-07-17"  # latest ultima_atualizacao of the file (cond 1 provenance)
    (finding,) = res.findings
    assert set(finding.tags) == {"official_gov_br", "known_good"} and finding.severity.label == "info"
    (piv,) = res.pivots
    assert (piv.entity.type, piv.entity.value, piv.relation) == (T.CNPJ, "33683111000107", "registrant")
    assert "Contato Exemplo" not in repr(res.to_dict())  # nome_contato (natural persons) is never kept
    assert not http.calls  # local match: nothing leaves the machine
    assert res.datasets and res.datasets[0]["name"] == DATASET


def test_subdomain_gets_context_only_never_official_status():
    _http, rt = installed()
    res = run_module(GovbrDomains, "domain:www.receita.gov.br", runtime=rt)
    assert res.status is Status.OK and res.attributes["govbr_parent_listed"] == "receita.gov.br"
    assert "official_gov_br" not in res.attributes and not res.findings  # no known_good dampener on subdomains


def test_state_zone_names_and_misses_have_honest_wording():
    _http, rt = installed()
    res = run_module(GovbrDomains, "domain:prefeitura.sp.gov.br", runtime=rt)
    assert res.status is Status.EMPTY and "state zone sp.gov.br" in res.error
    miss = run_module(GovbrDomains, "domain:naoexiste.gov.br", runtime=rt)
    assert miss.status is Status.EMPTY and miss.error == mod.MISS_WORDING and "not an official" not in miss.error


def test_cnpj_input_lists_its_gov_br_domains():
    _http, rt = installed()
    res = run_module(GovbrDomains, "cnpj:33.683.111/0001-07", runtime=rt)
    assert res.attributes["govbr_domains"] == ["receita.gov.br", "serpro.gov.br"]
    none = run_module(GovbrDomains, "cnpj:11.222.333/0001-81", runtime=rt)
    assert none.status is Status.EMPTY


def test_non_gov_br_domain_is_not_applicable():
    res = run_module(GovbrDomains, "domain:example.com", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_missing_dataset_is_unavailable_never_not_official():
    http = FakeHttp().add("GET", URL, status=403, body=module_fixture(GovbrDomains, "s3_403_access_denied.xml").encode(),
                          headers={"content-type": "application/xml"})
    res = run_module(GovbrDomains, "domain:receita.gov.br", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "could not verify" in res.error


@pytest.mark.parametrize("bad", ["csv_bad_header.csv", "csv_truncated.csv"])
def test_bad_downloads_never_replace_the_cached_copy(bad):
    http, rt = installed()
    http.add("GET", URL, body=csv_bytes(bad))
    result = rt.data.update(DATASET)
    assert result.status == "failed" and "rejected" in result.reason
    res = run_module(GovbrDomains, "domain:receita.gov.br", runtime=rt)
    assert res.status is Status.OK and res.attributes["official_gov_br"]["domain"] == "receita.gov.br"


def test_url_level_findings_are_never_suppressed():
    """cond 3: the known_good marker lands on the exact listed domain only; a phishing URL on the host
    keeps its finding and its score."""
    _http, rt = installed()
    res = run_module(GovbrDomains, "domain:receita.gov.br", runtime=rt)
    domain = Entity.make(T.DOMAIN, "receita.gov.br")
    url = Entity.make(T.URL, "https://receita.gov.br/phish/login.php")
    assert mod.dampener_applies(domain, mod.lookup("receita.gov.br", {"rows": {"receita.gov.br": {"domain": "receita.gov.br"}}}))
    assert not mod.dampener_applies(url, {"official": True, "row": {"domain": "receita.gov.br"}})
    graph = Graph()
    graph.add_node(domain, 0, source="seed")
    for f in res.findings:
        graph.add_finding(f)
    phishing = ModuleResult(module="url_feed", entity=url)
    phishing.finding("Listed as phishing", "high", "feed listing", confidence="probable", criterion="feed verdict", tags=["phishing"])
    graph.add_node(url, 1, source="url_feed")
    graph.add_finding(phishing.findings[0])
    scores = score(graph, [])["entities"]
    assert url.key in scores and scores[url.key]["score"] > 0
    assert not any("known_good" in f.tags for f in graph.get(url).findings)


def test_shared_protected_domains_helper():
    _http, rt = installed()
    ctx = make_ctx(GovbrDomains, runtime=rt, entity="domain:receita.gov.br")
    domains, brands, note = mod.protected_entries(ctx)
    names = {d["domain"] for d in domains}
    assert note == "" and brands == [{"keyword": "govbr", "source": "govbr"}]
    assert "receita.gov.br" in names and "sp.gov.br" not in names and "www.gov.br" not in names and "pf.gov.br" not in names
    assert all(d["source"] == "govbr" and len(d["cnpj_root"]) == 8 for d in domains)
    merged_domains, _brands, notes = mod.protected_domains(ctx)
    assert {d["domain"] for d in merged_domains} >= names and "bcb" in notes  # BCB list not installed here
    merged = mod.merge_protected(domains, [{"domain": "bcb.gov.br", "source": "bcb", "cnpj_root": "00038166"}])
    bcb = next(m for m in merged if m["domain"] == "bcb.gov.br")
    assert bcb["sources"] == ["govbr", "bcb"] and bcb["cnpj_roots"] == ["00038166"]


def test_helper_never_downloads():
    http = FakeHttp()
    ctx = make_ctx(GovbrDomains, http, entity="domain:receita.gov.br")
    domains, brands, note = mod.protected_entries(ctx)
    assert (domains, brands) == ([], []) and "not downloaded" in note and not http.calls


def test_parser_limits_and_junk():
    assert mod.parse_csv(b"<html><body>error</body></html>")["error"].startswith("HTML/XML")
    assert mod.parse_csv(b"")["error"] == "empty body"
    huge = "dominio;documento;nome;nome_contato;data_cadastro;ultima_atualizacao\nx.gov.br;" + "1" * 5000 + ";a;b;c;d\n"
    assert mod.parse_csv(huge, min_rows=0)["error"].startswith("csv error")  # field-size limit
    assert mod.cnpj_digits("033.683.111/0001-07") == "33683111000107" and mod.cnpj_digits("033.683.111/0001-08") is None
    parsed = mod.parse_csv(csv_bytes(), min_rows=0)
    assert parsed["row_count"] == 12 and parsed["max_updated"] == "2026-07-17 14:23:57"
    assert all("Contato" not in repr(r) for r in parsed["rows"])


def test_golden_path_cnpj_route_replays():
    """tests/fixtures/acceptance/cnpj/govbr_domains.json: the trimmed list is below the validation floor of
    the real module, so the golden CNPJ reads 'could not verify' (UNAVAILABLE dataset), never an absence."""
    import base64

    from tests.fakes import fixture

    (route,) = fixture("acceptance/cnpj/govbr_domains.json")["routes"]
    http = FakeHttp().add(route["method"], route["url"], status=route["status"], body=base64.b64decode(route["body_b64"]), headers=route["headers"])
    mod.MIN_ROWS = 1000  # the shipped floor (the autouse fixture lowered it for the other tests)
    res = run_module(GovbrDomains, "cnpj:00000000000191", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
