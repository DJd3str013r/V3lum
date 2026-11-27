"""Live checks of batch p1-G10-2 (cnpj_lookup, tcu_certidoes, cgu_sanctions_bulk, ibge_name_frequency); run
with V3LUM_LIVE=1.

Benign public values only: CNPJ 00.000.000/0001-91 (Banco do Brasil, the golden CNPJ input), a synthetic
check-digit-valid CNPJ that is not registered (98.765.012/0001-01), the two smallest CGU sanction files
(CNEP, leniency agreements) through the dataset manager, the IBGE national first-name rankings and an
invented person name (only the first name 'teodorico' leaves the machine; no real person is searched).

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is reported as
could-not-verify (blocked / rate_limited / error / unavailable, never 'empty').
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import cgu_sanctions_bulk as cgu
from v3lum.modules.brazil_public_data.cgu_sanctions_bulk import CguSanctionsBulk
from v3lum.modules.brazil_public_data.cnpj_lookup import CnpjLookup
from v3lum.modules.brazil_public_data.tcu_certidoes import LIST_SOURCES, TcuCertidoes
from v3lum.modules.person_name import ibge_name_frequency as ibge
from v3lum.modules.person_name.ibge_name_frequency import IbgeNameFrequency

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
BB = "cnpj:00000000000191"
UNREGISTERED = "cnpj:98765012000101"  # synthetic, check digits valid, not in the RFB registry
PURPOSE = ScanOptions(purpose="live check of batch p1-G10-2 with an invented name")


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def test_cnpj_lookup_reads_the_registry_record_of_banco_do_brasil():
    res = run_module(CnpjLookup, BB, runtime=live_runtime())
    print(res.status, res.reason_code, res.error, res.attributes.get("provider_chain"))
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"no CNPJ provider answered from this egress: {res.status} {res.error}")
    assert res.status is Status.OK, (res.status, res.error)
    assert "BANCO DO BRASIL" in str(res.attributes["legal_name"]).upper()
    assert str(res.attributes["status"]).upper() == "ATIVA"
    assert res.attributes["provider_chain"] and res.attributes["field_sources"]
    assert not any(k in res.attributes for k in ("cpf", "cpfs"))


def test_cnpj_lookup_unregistered_number_is_not_found_or_could_not_verify():
    res = run_module(CnpjLookup, UNREGISTERED, runtime=live_runtime())
    print(res.status, res.reason_code, res.error, res.attributes.get("provider_chain"))
    assert res.status in {Status.EMPTY, Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    assert "legal_name" not in res.attributes
    if res.status is Status.OK:  # two independent pipelines agree: RFB 'not found' is reported as an INFO finding
        assert [f.title for f in res.findings] == ["CNPJ not found in RFB open data"]


def test_tcu_certificate_of_banco_do_brasil():
    res = run_module(TcuCertidoes, BB, runtime=live_runtime())
    print(res.status, res.reason_code, res.error, res.attributes.get("certificate_lists"))
    if res.status in COULD_NOT_VERIFY:
        assert set(res.attributes["certificate_lists"]) == set(LIST_SOURCES)
        assert all(v["state"] == "unknown" for v in res.attributes["certificate_lists"].values())
        pytest.skip(f"TCU certificate service could not be verified from this egress: {res.status} {res.error}")
    assert res.status in (Status.OK, Status.EMPTY), (res.status, res.error)
    assert res.attributes["tcu_base_found"] is True and res.attributes["certificate_issued_at"]
    lists = res.attributes["certificate_lists"]
    assert set(lists) == set(LIST_SOURCES)
    assert all(v["state"] in ("consta", "nada_consta", "unknown") for v in lists.values())
    for lid, src in LIST_SOURCES.items():
        assert res.source_statuses[src]["status"] in ("ok", "empty", "error"), (lid, res.source_statuses[src])


def test_cgu_small_lists_install_and_screen_offline():
    rt = live_runtime()
    keys = ("cnep", "acordos_leniencia")
    results = dict(zip(keys, cgu.update_lists(rt.data, keys), strict=True))
    for key, r in results.items():
        print(key, r.name, r.status, r.reason[:200], r.new_sha256[:12])
        assert r.status in ("updated", "unchanged", "failed", "needs_accept")
        if not r.ok:
            assert r.reason
    res = run_module(CguSanctionsBulk, BB, runtime=rt)
    print(res.status, res.reason_code, res.error, res.attributes.get("sanctions_screening"))
    if not any(r.ok for r in results.values()):
        assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
        pytest.skip("no CGU list installed from this egress: " + "; ".join(r.reason[:120] for r in results.values()))
    assert res.status in (Status.OK, Status.EMPTY), (res.status, res.error)
    status = {k: v["status"] for k, v in res.source_statuses.items()}
    for key in ("ceis", "cepim"):  # never downloaded here: not screened, never "no record" (PEP is for persons only)
        assert status[cgu.LISTS[key].source] == "unavailable"
    for key, r in results.items():
        if r.ok:
            assert status[cgu.LISTS[key].source] in ("ok", "empty")
            store = cgu.ListStore(rt.data.path(r.name))
            try:
                assert int(store.meta["rows"]) >= cgu.MIN_ROWS[key]
                assert store.meta["schema"] == "v3lum.cgu_sanctions/1"
            finally:
                store.close()


def test_ibge_rankings_install_and_an_invented_name_is_looked_up_by_first_name_only():
    rt = live_runtime()
    installed = []
    for name in ibge.RANKING_DATASETS:
        r = rt.data.update(name)
        print(name, r.status, r.reason[:160])
        assert r.status in ("updated", "unchanged", "failed")
        installed.append(r.ok)
    if all(installed):
        table = ibge.offline_table(rt.data)
        assert table["MARIA"] > 10_000_000 and table["JOSE"] > 5_000_000
        risk = ibge.homonym_risk("JOSE DA SILVA", table=table)
        assert risk["risk"] == "high" and risk["factor"] == pytest.approx(0.32)
    res = run_module(IbgeNameFrequency, "person_name:Teodorico Exemplar", runtime=rt, options=PURPOSE)
    print(res.status, res.reason_code, res.error, res.attributes)
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"IBGE nomes API could not be verified from this egress: {res.status} {res.error}")
    assert res.status is Status.OK
    freq = res.attributes["first_name_frequency"]
    assert freq["first_name"] == "TEODORICO" and isinstance(freq["frequency"], int)
    assert res.attributes["homonym_risk"]["risk"] in ("low", "medium")
    assert not res.findings
