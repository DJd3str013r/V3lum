"""Offline tests of ibge_name_frequency (P252) and the shared homonym helper over tests/fixtures/ibge_name_frequency/.

IBGE nomes API captures (aggregate Census 2010 statistics, no personal data): jose_ok / jose_accented_ok /
teodorico_rare / empty / ranking_br / ranking_br_f / ranking_br_m (live 2026-11-26), maria_ok, maria_ok_osint,
maria_by_uf and ranking_rj (research captures); the 502 is synthetic.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.person_name import ibge_name_frequency as mod
from v3lum.modules.person_name.ibge_name_frequency import IbgeNameFrequency

NOMES = "https://servicodados.ibge.gov.br/api/v2/censos/nomes/{}"
PURPOSE = ScanOptions(purpose="due diligence of a supplier (ticket DD-1)")
RANKING_FIXTURES = {
    "ibge_name_frequency.ranking.json": "ranking_br.json",
    "ibge_name_frequency.ranking_f.json": "ranking_br_f.json",
    "ibge_name_frequency.ranking_m.json": "ranking_br_m.json",
}


def fx(name: str):
    return module_fixture("ibge_name_frequency", name)


def runtime_with_ranking(http: FakeHttp | None = None):
    http = http or FakeHttp()
    rt = make_runtime(http)
    for name, fixture in RANKING_FIXTURES.items():
        http.add("GET", mod.RANKING_DATASETS[name], json=fx(fixture))
        assert rt.data.update(name).ok
    return rt, http


# --------------------------------------------------------------------------------------
# the homonym helper (P252 cond 1-2, 4-6)
# --------------------------------------------------------------------------------------


def test_offline_table_is_the_union_of_the_national_rankings():
    rt, _http = runtime_with_ranking()
    table = mod.offline_table(rt.data)
    assert table["MARIA"] == 11734129 and table["JOSE"] == 5754529
    assert "FRANCISCA" in table and "ADRIANA" in table  # from the per-sex lists (only the totals are kept)


def test_offline_table_is_empty_when_never_downloaded():
    http = FakeHttp()
    assert mod.offline_table(make_runtime(http).data) == {}  # never downloaded: empty, never a request
    assert http.calls == []


def test_jose_da_silva_is_a_high_homonym_risk():
    rt, _http = runtime_with_ranking()
    h = mod.homonym_risk("JOSE DA SILVA", table=mod.offline_table(rt.data))
    assert h["risk"] == "high" and h["factor"] == pytest.approx(0.32)
    assert h["phrase"] == "very common name: name-only matches are unreliable"
    assert mod.apply_homonym_curve(0.5, h) == pytest.approx(0.16)


def test_rare_name_low_risk_and_unknown_name_neutral():
    assert mod.homonym_risk("Teodorico Exemplar", frequency=1165)["risk"] == "low"
    unknown = mod.homonym_risk("Xqzvkw Exemplar")
    assert unknown["risk"] == "unknown" and unknown["factor"] == 1.0 and unknown["phrase"] == "name frequency unknown"
    assert mod.homonym_risk("Xqzvkw da Silva")["risk"] == "medium"  # a common surname alone
    empty = mod.homonym_risk("Xqzvkw Exemplar", frequency=0)  # an empty IBGE answer: rare, never an error
    assert empty["first_name_tier"] == "rare" and empty["risk"] == "low"


def test_first_name_only_and_no_inference():
    assert mod.first_name("Dr. José da Silva") == "JOSE"
    h = mod.homonym_risk("MARIA DA SILVA", frequency=11734129)
    assert set(h) == {"first_name", "first_name_frequency", "first_name_tier", "common_surname", "factor", "risk", "phrase"}


def test_parsers_keep_only_national_totals():
    assert mod.parse_ibge_nomes(fx("jose_ok.json"))["total"] == 5754529
    assert mod.parse_ibge_nomes(fx("jose_accented_ok.json"))["total"] == 5754529
    assert mod.parse_ibge_nomes(fx("empty.json")) == {"empty": True, "total": 0}
    by_uf = mod.parse_ibge_nomes(fx("maria_by_uf.json"))
    assert set(by_uf) == {"empty", "total"} and by_uf["total"] > 10_000_000  # national sum only, never per UF
    assert mod.parse_ibge_nomes({"erro": "x"}) is None and mod.parse_ibge_nomes([{"nome": "X"}]) is None
    assert mod.parse_ranking(fx("ranking_rj.json")) == {}  # a state ranking never enters the national table
    assert mod.parse_ranking(fx("maria_ok.json")) == {}


# --------------------------------------------------------------------------------------
# the opt-in module (P252 cond 3-5)
# --------------------------------------------------------------------------------------


def test_offline_table_answers_without_any_request():
    rt, http = runtime_with_ranking()
    before = len(http.calls)
    res = run_module(IbgeNameFrequency, "person_name:José da Silva", None, runtime=rt, options=PURPOSE)
    assert res.status is Status.OK
    assert res.attributes["first_name_frequency"] == {"first_name": "JOSE", "frequency": 5754529,
                                                      "source": "IBGE Census 2010 ranking (offline dataset)"}
    assert res.attributes["homonym_risk"]["risk"] == "high"
    assert len(http.calls) == before  # nothing left the machine
    assert not res.findings  # the module never emits findings


def test_online_lookup_sends_only_the_folded_first_name_and_is_kept_365_days():
    http = FakeHttp().add("GET", NOMES.format("teodorico"), json=fx("teodorico_rare.json"), times=1)
    rt = make_runtime(http)
    res = run_module(IbgeNameFrequency, "person_name:Teodorico Exemplar", None, runtime=rt, options=PURPOSE)
    assert res.status is Status.OK
    assert res.attributes["first_name_frequency"]["frequency"] == 1165
    assert res.attributes["homonym_risk"]["risk"] == "low"
    assert http.urls() == [NOMES.format("teodorico")]
    again = run_module(IbgeNameFrequency, "person_name:Teodorico Exemplo", None, runtime=rt, options=PURPOSE)
    assert again.attributes["first_name_frequency"]["source"] == "IBGE nomes API (kept 365 days)"
    assert len(http.urls()) == 1
    http.assert_hosts_within(IbgeNameFrequency)


def test_accented_name_and_empty_answer():
    http = FakeHttp().add("GET", NOMES.format("jose"), json=fx("jose_accented_ok.json"))
    res = run_module(IbgeNameFrequency, "person_name:José Exemplar", http, options=PURPOSE)
    assert res.attributes["first_name_frequency"]["frequency"] == 5754529
    http2 = FakeHttp().add("GET", NOMES.format("xqzvkw"), json=fx("empty.json"))
    res2 = run_module(IbgeNameFrequency, "person_name:Xqzvkw Exemplar", http2, options=PURPOSE)
    assert res2.status is Status.OK  # rare/unknown name, never an error
    assert res2.attributes["homonym_risk"]["first_name_tier"] == "rare"


def test_never_online_at_tlp_red():
    res = run_module(IbgeNameFrequency, "person_name:Teodorico Exemplar", FakeHttp(), options=PURPOSE, tlp="red")
    assert res.status is Status.SKIPPED and res.reason_code == "tlp"


def test_errors_are_could_not_verify():
    ex = fx("server_error_synthetic.http.json")["response"]
    http = FakeHttp().add("GET", NOMES.format("jose"), status=ex["status"], text=ex["body"], times=2)
    assert run_module(IbgeNameFrequency, "person_name:Jose Exemplar", http, options=PURPOSE).status is Status.ERROR
    http2 = FakeHttp().add("GET", NOMES.format("jose"), status=429, text="slow down")
    assert run_module(IbgeNameFrequency, "person_name:Jose Exemplar", http2, options=PURPOSE).status is Status.RATE_LIMITED
    http3 = FakeHttp().add("GET", NOMES.format("jose"), json={"erro": "formato"})
    assert run_module(IbgeNameFrequency, "person_name:Jose Exemplar", http3, options=PURPOSE).status is Status.ERROR


def test_metadata_follows_the_council():
    assert IbgeNameFrequency.default_enabled is False and IbgeNameFrequency.category == "person_name"
    assert IbgeNameFrequency.run_on == "seeds" and IbgeNameFrequency.trust_tier == "trusted"
    assert IbgeNameFrequency.hosts == ("servicodados.ibge.gov.br",)
