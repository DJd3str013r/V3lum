"""Live checks of batch p2-G10-1 (gleif, cep_lookup, cnae_tables, portal_transparencia_api); run with V3LUM_LIVE=1.

Benign public values only: CNPJ 00.000.000/0001-91 (Banco do Brasil, the golden CNPJ input), CEP 01001-000
(Praça da Sé, a public square), the typed address of that square, the IBGE CNAE tree through the dataset
manager (`v3lum data update cnae`) and, for the keyed Portal da Transparencia API, the no-key path only (no
request is sent without the team key).

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is reported as
could-not-verify (blocked / rate_limited / error / quota, never 'empty').
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import cnae_tables as ct
from v3lum.modules.brazil_public_data.cep_lookup import CepLookup
from v3lum.modules.brazil_public_data.portal_transparencia_api import PortalTransparenciaApi
from v3lum.modules.company_org.gleif import Gleif

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
BB = "cnpj:00000000000191"


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def test_gleif_banco_do_brasil_by_formatted_cnpj():
    rt = live_runtime()
    res = run_module(Gleif, BB, runtime=rt)
    print(res.status, res.reason_code, res.error, res.attributes.get("lei_summary"), res.requests)
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"GLEIF could not be verified from this egress: {res.status} {res.error}")
    assert res.status is Status.OK, (res.status, res.error)
    assert res.attributes["lei"] == "QE0Q0253K88YAGNPE356"
    assert res.attributes["lei_summary"].startswith("LEI QE0Q0253K88YAGNPE356 | BANCO DO BRASIL SA |")
    assert res.attributes["lei_record"]["registered_as"] == "00.000.000/0001-91"
    assert res.requests <= Gleif.max_requests
    assert all(p.relation in ("partner", "company_of") for p in res.pivots)


def test_cep_lookup_praca_da_se():
    res = run_module(CepLookup, "cep:01001000", runtime=live_runtime())
    print(res.status, res.reason_code, res.error, res.attributes.get("provider_chain"), res.attributes.get("cep_record"))
    assert res.attributes.get("cep_uf_hint") == "SP"  # offline, whatever the providers answer
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"no CEP provider answered from this egress: {res.status} {res.error}")
    assert res.status is Status.OK, (res.status, res.error)
    assert res.attributes["city"] == "São Paulo" and res.attributes["region"] == "SP" and res.attributes["ibge_code"] == "3550308"
    assert all(p.expand is False for p in res.pivots)


def test_cep_lookup_unknown_cep_is_empty_or_could_not_verify():
    res = run_module(CepLookup, "cep:99999999", runtime=live_runtime())
    print(res.status, res.reason_code, res.error, res.attributes.get("provider_chain"))
    assert res.status in {Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    assert "city" not in res.attributes  # the bogus 200 records (Sarandi-PR for an RS CEP) are discarded


def test_cep_lookup_reverse_search_of_a_typed_address():
    res = run_module(CepLookup, "keyword:Praça da Sé, São Paulo - SP", runtime=live_runtime())
    print(res.status, res.reason_code, res.error, (res.attributes.get("cep_reverse_matches") or [])[:3])
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"ViaCEP could not be verified from this egress: {res.status} {res.error}")
    assert res.status is Status.OK
    assert any(m["postal_code"] == "01001-000" for m in res.attributes["cep_reverse_matches"])


def test_cnae_refresher_validates_the_live_ibge_tree():
    rt = live_runtime()
    out = rt.data.store.update(ct.DATASET) if hasattr(rt.data, "store") else rt.data.update(ct.DATASET)
    print(out)
    status = getattr(out, "status", "")
    if status not in ("updated", "unchanged", "ok", "installed"):
        pytest.skip(f"IBGE CNAE API could not be refreshed from this egress: {out}")
    tables = ct.load_tables(rt.data)
    assert tables.cnae["counts"]["subclasses"] >= ct.CNAE_MIN_SUBCLASSES
    assert ct.cnae_describe("6422100", tables)["label"] == "BANCOS MÚLTIPLOS, COM CARTEIRA COMERCIAL"


def test_portal_transparencia_without_the_team_key_sends_nothing():
    http = FakeHttp()  # no route: a request would fail the test
    res = run_module(PortalTransparenciaApi, BB, http)
    print(res.status, res.reason_code, res.error)
    assert res.status is Status.NEEDS_KEY and not http.calls
