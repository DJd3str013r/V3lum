"""pivots_brazil (P250): Brazilian company pages (CNPJ and company name only, never a CPF or a person).

Vectors: tests/fixtures/pivots_brazil/cnpj_vectors.json (Banco do Brasil's public CNPJ and the RFB alphanumeric
example). Maintainer checks (status and title only): tests/fixtures/pivots_brazil/verified_templates.json.
V3LUM never fetches these URLs."""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core import links
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data.pivots_brazil import PivotsBrazil
from v3lum.modules.utility import pivot_pack_render as pr

VECTORS = module_fixture("pivots_brazil", "cnpj_vectors.json")
VERIFIED = module_fixture("pivots_brazil", "verified_templates.json")
CNPJ = "00000000000191"


def urls(res):
    return [url for _label, url in res.links]


# ------------------------------------------------------------------ cond 8, 12: CNPJ encoders
@pytest.mark.parametrize("vector", VECTORS["valid"], ids=lambda v: v["value"])
def test_cnpj_encoders(vector):
    assert links.cnpj_fmt(vector["value"]) == vector["fmt"]
    assert links.cnpj_digits(vector["value"]) == vector["digits"]
    assert links.cnpj_root(vector["value"]) == vector["root"]
    rendered = links.render("brazil:transparencia_busca_cnpj", Entity.make("cnpj", vector["value"]))
    assert rendered.url == f"https://portaldatransparencia.gov.br/busca?termo={vector['url_fmt']}"


@pytest.mark.parametrize("value", VECTORS["invalid"])
def test_invalid_cnpj_never_renders(value):
    for ref in ("brazil:transparencia_busca_cnpj", "brazil:receita_comprovante", "brazil:casadosdados_cnpj"):
        out = links.render(ref, Entity(T.CNPJ, value))
        if value.strip() != value and out is not None:  # surrounding whitespace is normalised away by the encoder
            assert out.url == links.render(ref, Entity.make("cnpj", value.strip())).url
            continue
        assert out is None


def test_portal_uses_the_formatted_cnpj_and_never_the_bot_challenge_page():
    waf = next(c for c in VERIFIED["checks"] if c["case"] == "transparencia_waf_captcha")
    assert links.render("brazil:transparencia_busca_cnpj", Entity.make("cnpj", CNPJ)).url == waf["url"]
    for item in pr.pack_data("brazil")["links"]:
        assert "/pessoa-juridica/" not in item["template"]


def test_cnpj_links_are_privacy_links_for_opted_in_typed_seeds():
    cnpj = Entity.make("cnpj", CNPJ)
    assert not [r for r in links.pivot_links_for(cnpj) if r.ref.startswith("brazil:")]
    refs = [r.ref for r in links.pivot_links_for(cnpj, include_privacy=True) if r.ref.startswith("brazil:")]
    assert refs == ["brazil:transparencia_busca_cnpj", "brazil:jusbrasil_busca_cnpj", "brazil:escavador_busca_cnpj",
                    "brazil:receita_comprovante", "brazil:casadosdados_cnpj"]


def test_company_name_links_are_unrestricted_and_complaints_are_labelled():
    out = {r.ref: r for r in links.pivot_links_for(Entity.make("company_name", "Banco do Brasil"))}
    assert {"brazil:transparencia_busca_nome", "brazil:reclameaqui_busca", "brazil:jusbrasil_busca_nome",
            "brazil:escavador_busca_nome"} <= set(out)
    assert "consumer complaints: context, not proof" in out["brazil:reclameaqui_busca"].label
    assert out["brazil:reclameaqui_busca"].antibot and not out["brazil:reclameaqui_busca"].verified


def test_receita_uses_the_digits_and_keeps_alphanumeric_cnpj():
    assert links.render("brazil:receita_comprovante", Entity.make("cnpj", "12ABC34501DE35")).url.endswith("cnpj=12ABC34501DE35")


# ------------------------------------------------------------------ cond 9: rule 4
def test_no_cpf_or_person_template_exists():
    for item in [*pr.pack_data("brazil")["links"], *pr.pack_data("brazil")[pr.EXT_KEY]]:
        assert set(item["entity_types"]) <= {"cnpj", "company_name"}, item["id"]
    assert links.render("brazil:transparencia_busca_nome", Entity.make("person_name", "Fulano de Tal")) is None
    assert links.render("brazil:transparencia_busca_cnpj", Entity.make("cpf", "52998224725")) is None


# ------------------------------------------------------------------ cond 10-11: static pages (module)
def test_cnpj_seed_gets_consumidor_and_sintegra_static_pages():
    res = run_module(PivotsBrazil, f"cnpj:{CNPJ}", FakeHttp(), tlp="clear")
    assert res.status is Status.OK and res.requests == 0
    assert urls(res) == ["https://www.consumidor.gov.br/pages/principal/", "https://www.sintegra.gov.br/"]
    by_url = {u: lab for lab, u in res.links}
    assert "consumer complaints: context, not proof" in by_url["https://www.consumidor.gov.br/pages/principal/"]
    assert "type the CNPJ" in by_url["https://www.sintegra.gov.br/"]
    assert CNPJ not in "".join(urls(res))  # static pages carry no value


def test_company_name_seed_gets_only_consumidor():
    res = run_module(PivotsBrazil, "company_name:Banco do Brasil", tlp="clear")
    assert urls(res) == ["https://www.consumidor.gov.br/pages/principal/"]


def test_static_pages_at_amber_say_opening_sends_nothing():
    res = run_module(PivotsBrazil, f"cnpj:{CNPJ}")
    assert all("opening sends nothing; typing 00.000.000/0001-91 on that page sends it to" in label for label, _url in res.links)


def test_discovered_entities_get_nothing():
    res = run_module(PivotsBrazil, f"cnpj:{CNPJ}", is_seed=False, depth=1, options=ScanOptions())
    assert res.status is Status.SKIPPED and not res.links


def test_red_emits_nothing():
    res = run_module(PivotsBrazil, f"cnpj:{CNPJ}", tlp="red")
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and not res.links


def test_login_walled_ccc_is_not_shipped():
    ccc = next(c for c in VERIFIED["checks"] if c["case"] == "ccc_login_redirect")
    assert ccc["status"] == 302
    assert not any("svrs" in item["host"] for item in [*pr.pack_data("brazil")["links"], *pr.pack_data("brazil")[pr.EXT_KEY]])


def test_never_fetches_anything():
    ctx = make_ctx(PivotsBrazil, FakeHttp())
    with pytest.raises(PolicyError):
        ctx.http.get("https://portaldatransparencia.gov.br/busca?termo=x")
