"""Live checks of batch p1-G10-3 (bcb_authorized_institutions, cvm_person_registry); run with V3LUM_LIVE=1.

Keyless official sources only, through the dataset manager (the modules themselves never touch the
network): the five BCB Olinda entity sets (olinda.bcb.gov.br) and the CVM cadastral zips
(dados.cvm.gov.br) are downloaded, validated (FC2 floors) and installed, then matched offline with
benign public values: www.bb.com.br and CNPJ 00.000.000/0001-91 (Banco do Brasil, the golden CNPJ
input), example.com, an open-redirect URL pattern on bb.com.br pointing to evil.example.com, and an
invented person name (no real person is ever searched).

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is reported
as could-not-verify (a failed update keeps no copy; the modules then answer UNAVAILABLE 'dataset',
never an absence).
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import bcb_authorized_institutions as B
from v3lum.modules.brazil_public_data import cvm_registries as C
from v3lum.modules.brazil_public_data.bcb_authorized_institutions import BcbAuthorizedInstitutions
from v3lum.modules.brazil_public_data.cvm_person_registry import CvmPersonRegistry

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
BCB_SETS = [B.DOMINIOS.dataset, *(s.dataset for s in B.SEDES)]
CVM_SETS = [C.REGISTRIES[k].dataset for k in C.PJ_REGISTRIES]


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _update(rt: Runtime, names: list[str]) -> dict[str, object]:
    out = {}
    for name in names:
        result = rt.data.update(name)
        out[name] = result
        print(f"{name}: {result.status} {result.reason[:160]} {result.new_sha256[:12]}")
        assert result.status in ("updated", "unchanged", "failed")
        if result.status == "failed":  # could not verify from this egress: reported, nothing installed or kept stale
            assert result.reason
    return out


def test_registries_download_validate_and_match_offline():
    rt = live_runtime()
    results = _update(rt, BCB_SETS + CVM_SETS)
    dominios_ok = results[B.DOMINIOS.dataset].ok
    res = run_module(BcbAuthorizedInstitutions, "domain:www.bb.com.br", runtime=rt)
    if not dominios_ok:
        assert res.status in COULD_NOT_VERIFY, (res.status, res.error)
        pytest.skip(f"BCB DominiosVerificados not installed from this egress: {results[B.DOMINIOS.dataset].reason}")
    assert res.status is Status.OK, (res.status, res.error)
    assert res.attributes["known_good"] is True and res.attributes["bcb_verified_domain"]["domain"] == "bb.com.br"
    assert res.findings[0].data["cnpj_root"] == "00000000" and res.findings[0].data["datasets"][0]["date"]
    index = B.local_index()
    assert len(index.domains) >= B.MIN_UNIQUE_DOMAINS and index.sedes == all(results[n].ok for n in BCB_SETS[1:])
    assert run_module(BcbAuthorizedInstitutions, "domain:example.com", runtime=rt).status is Status.EMPTY
    redirect = run_module(BcbAuthorizedInstitutions, "url:https://www.bb.com.br/x?next=https%3A%2F%2Fevil.example.com%2F", runtime=rt)
    assert redirect.attributes["known_good"] is False and redirect.attributes["redirect_targets"] == ["evil.example.com"]
    company = run_module(BcbAuthorizedInstitutions, "cnpj:00000000000191", runtime=rt)
    assert company.status is Status.OK, (company.status, company.error)
    line = company.attributes["bcb_cvm_authorisation"]
    assert line.startswith("authorised by BCB/CVM: yes (") and "Banco do Brasil" in line
    assert (T.DOMAIN, "bb.com.br") in {(p.entity.type, p.entity.value) for p in company.pivots}
    if all(results[n].ok for n in CVM_SETS):
        assert "CVM: " in line and company.source_statuses["cvm.cadastral"]["status"] == "ok"
    brands = {b["registrable_domain"]: b for b in B.protected_brands(index)}
    assert "00000000" in brands["bb.com.br"]["institution_cnpj_roots"]


def test_natural_person_registries_parse_and_an_invented_name_is_not_found():
    rt = live_runtime()
    names = [C.REGISTRIES[k].dataset for k in C.PF_REGISTRIES]
    results = _update(rt, names)
    res = run_module(CvmPersonRegistry, "person_name:Pessoa Exemplo Inexistente Silva", runtime=rt,
                     options=ScanOptions(purpose="live check of the CVM natural-person registry parser (no real person)"))
    if not any(r.ok for r in results.values()):
        assert res.status in COULD_NOT_VERIFY, (res.status, res.error)
        return
    assert res.status is Status.EMPTY, (res.status, res.error)
    assert all(m["rows"] > 1000 for m in res.raw["datasets"])
