"""Live checks of batch p2-G10-3 (querido_diario, cnpj_name_resolver, cnpj_name_resolver_wikidata,
djen_court_communications); run with V3LUM_LIVE=1.

Keyless sources only, benign public values: the golden CNPJ 00.000.000/0001-91 (Banco do Brasil) and the
company name 'Banco do Brasil S.A.'. A 403/429/challenge/geo-block/timeout from this datacenter egress is
an acceptable outcome when it is reported as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR),
never as an absence.

* querido_diario: the real /gazettes and /company/info answers on api.queridodiario.org.br;
* cnpj_name_resolver: the CVM listed-company register (cvm_cia_aberta.csv) and the BCB sets downloaded and
  validated by the dataset manager, then the offline match plus the live GLEIF fallback;
* cnpj_name_resolver_wikidata: Wikidata answers 429 to clients without an identifying contact, so the test
  sets a documentation contact (soc@example.com) the way the Wikimedia policy asks;
* djen_court_communications: no automated request exists before the Brazilian-egress capture (P362 FC1);
  the test only checks that the module sends nothing.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import bcb_authorized_institutions as B
from v3lum.modules.brazil_public_data import cnpj_name_resolver as R
from v3lum.modules.brazil_public_data.cnpj_name_resolver import CnpjNameResolver, CnpjNameResolverWikidata
from v3lum.modules.brazil_public_data.djen_court_communications import DjenCourtCommunications
from v3lum.modules.brazil_public_data.querido_diario import QD_EMPTY_TEXT, QueridoDiario

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
BB = "00000000000191"


def live_runtime(**settings: object) -> Runtime:
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def test_querido_diario_cnpj_seed():
    res = run_module(QueridoDiario, f"cnpj:{BB}", runtime=live_runtime())
    print(res.status, res.reason_code, res.error[:200], res.attributes.get("gazette_mentions", {}).get("line"))
    if res.status in COULD_NOT_VERIFY:
        assert "not found in covered gazettes" not in res.error
        pytest.skip(f"Querido Diario could not be verified from this egress: {res.status.value} {res.error[:160]}")
    assert res.status is Status.OK, (res.status, res.error)
    m = res.attributes["gazette_mentions"]
    assert m["counts"]["cnpj"] > 0 and 0 < len(m["top"]) <= 5
    assert all(len(e) <= 300 for h in m["top"] for e in h["excerpts"])
    assert all(p.expand is False for p in res.pivots)
    assert all("api.queridodiario.ok.org.br" not in u for _lbl, u in res.links)


def test_querido_diario_nonsense_phrase_is_not_found_in_covered_gazettes():
    res = run_module(QueridoDiario, "company_name:ZZQX V3LUM EMPRESA INEXISTENTE LTDA", runtime=live_runtime())
    print(res.status, res.error[:200])
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"could not verify from this egress: {res.status.value}")
    assert res.status is Status.EMPTY and res.error == QD_EMPTY_TEXT


def test_cnpj_name_resolver_registries_and_gleif():
    rt = live_runtime()
    for name in (R.CIA_ABERTA_DATASET, B.DOMINIOS.dataset, *(s.dataset for s in B.SEDES)):
        result = rt.data.update(name)
        print(f"{name}: {result.status} {result.reason[:160]} {result.new_sha256[:12]}")
        assert result.status in ("updated", "unchanged", "failed")
    res = run_module(CnpjNameResolver, "company_name:Banco do Brasil S.A.", runtime=rt)
    print(res.status, res.error[:200], res.attributes.get("name_resolution", {}).get("sources"))
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"could not verify from this egress: {res.status.value} {res.error[:160]}")
    assert res.status is Status.OK, (res.status, res.error)
    hyps = res.attributes["cnpj_hypotheses"]
    assert BB in {h["cnpj"] for h in hyps[:5]}
    rn = res.attributes["name_resolution"]
    assert rn["local_index"]["state"] == "not_installed" and rn["online_fallback"] is True
    print(rn["sources"], rn["auto_chain"])


def test_cnpj_name_resolver_wikidata_with_a_contact():
    res = run_module(CnpjNameResolverWikidata, "company_name:Banco do Brasil", runtime=live_runtime(contact_email="soc@example.com"))
    print(res.status, res.reason_code, res.error[:200])
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"Wikidata could not be verified from this egress: {res.status.value} {res.error[:160]}")
    assert res.status in (Status.OK, Status.EMPTY)
    if res.status is Status.OK:
        assert all(h["source"] == "wikidata" and h["label"] == R.ONLINE_LABEL for h in res.attributes["cnpj_hypotheses"])


def test_djen_sends_nothing_before_the_brazilian_capture():
    http = FakeHttp()
    res = run_module(DjenCourtCommunications, f"cnpj:{BB}", http)
    assert http.urls() == [] and res.status is Status.SKIPPED and res.reason_code == "config"
