"""Live checks of batch p3-G10-2 (iana_pen, anac_rab, br_cnpj_risk_lists, br_public_spending, br_public_spending_br);
run with V3LUM_LIVE=1.

Keyless official sources only, with benign public values: the IANA PEN registry (Microsoft PEN 311, the Google CT
OID), the ANAC RAB file (parser and minimisation statistics only; no aircraft of a person is looked up), the MTE /
CVM / BrasilAPI risk lists matched against CNPJ 00.000.000/0001-91 (Banco do Brasil, the golden CNPJ input), the PGFN
directory plan (listing + Range 0-0 heads, nothing imported) and BNDES/SALIC for the same CNPJ. The BR-egress module
is checked through the policy gate only: from this non-Brazilian egress it must be SKIPPED 'egress_country' with its
manual link, and no request is sent (A9).

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is reported as
could-not-verify (a failed update keeps no copy; the modules then answer UNAVAILABLE 'dataset', never an absence).
"""

from __future__ import annotations

import json
import re

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import anac_rab as A
from v3lum.modules.brazil_public_data import br_cnpj_risk_lists as R
from v3lum.modules.brazil_public_data import pgfn_import as P
from v3lum.modules.brazil_public_data.anac_rab import AnacRab
from v3lum.modules.brazil_public_data.br_cnpj_risk_lists import BrCnpjRiskLists
from v3lum.modules.brazil_public_data.br_public_spending import BrPublicSpending, BrPublicSpendingBr
from v3lum.modules.company_org import iana_pen as I
from v3lum.modules.company_org.iana_pen import IanaPen

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
BB = "00000000000191"


def live_runtime(**settings) -> Runtime:
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def _update(rt: Runtime, name: str):
    result = rt.data.update(name)
    print(f"{name}: {result.status} {result.reason[:200]} {result.new_sha256[:12]}")
    assert result.status in ("updated", "unchanged", "failed")
    if result.status == "failed":
        assert result.reason
    return result


def _no_personal(res) -> None:
    blob = json.dumps({"a": res.attributes, "r": res.raw, "f": [f.to_dict() for f in res.findings]}, default=str)
    assert not re.search(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", blob)  # no CPF ever


def test_iana_pen_registry_download_and_offline_lookups():
    rt = live_runtime()
    result = _update(rt, I.DATASET)
    res = run_module(IanaPen, "company_name:Microsoft", runtime=rt)
    if not result.ok:
        assert res.status in COULD_NOT_VERIFY, (res.status, res.error)
        pytest.skip(f"IANA PEN registry not installed from this egress: {result.reason}")
    assert res.status is Status.OK, (res.status, res.error)
    assert 311 in {h["number"] for h in res.attributes["iana_pen"]}
    assert res.attributes["iana_pen_registry"]["records"] > 60000 and re.match(r"\d{4}-\d{2}-\d{2}", res.attributes["iana_pen_registry"]["updated"])
    oid = run_module(IanaPen, "keyword:1.3.6.1.4.1.11129.2.4.2", runtime=rt)
    assert oid.attributes["iana_pen"][0]["organization"].startswith("Google")
    blob = json.dumps(res.attributes)
    assert "@" not in blob and "&" not in blob.replace("AT&T", "")


def test_anac_rab_download_parse_and_minimise():
    rt = live_runtime()
    result = _update(rt, A.DATASET)
    if not result.ok:
        res = run_module(AnacRab, "keyword:mark:PR-AAA", runtime=rt)
        assert res.status in COULD_NOT_VERIFY, (res.status, res.error)
        pytest.skip(f"ANAC RAB not installed from this egress: {result.reason}")
    index, meta = A.load_index(rt.data.scoped())
    print(f"RAB as of {index.updated}: {len(index.rows)} aircraft, stats {index.stats}")
    assert len(index.rows) > 15000 and index.stats["dropped_parties"] > 0 and index.stats["kept_parties"] > 0
    assert not any(re.fullmatch(r"\d{3}X{6}\d{2}", p["cnpj"]) for r in index.rows[:2000] for p in r["owners"] + r["operators"])
    some = next(r for r in index.rows if r["owners"] and r["owners"][0]["cnpj_valid"])
    res = run_module(AnacRab, f"cnpj:{some['owners'][0]['cnpj']}", runtime=rt)  # a company owner taken from the file itself
    assert res.status is Status.OK, (res.status, res.error)
    assert res.attributes["anac_rab_date"] == index.updated
    _no_personal(res)


def test_br_cnpj_risk_lists_download_and_screen_the_golden_cnpj():
    rt = live_runtime()
    results = {name: _update(rt, name) for name in (R.MTE_DATASET, R.SANCTIONS_DATASET, R.BROKERS_DATASET, R.CIA_DATASET,
                                                    "cvm_intermed.csv")}
    res = run_module(BrCnpjRiskLists, f"cnpj:{BB}", runtime=rt)
    if not any(r.ok for r in results.values()):
        assert res.status in COULD_NOT_VERIFY, (res.status, res.error)
        pytest.skip("no risk list installed from this egress")
    assert res.status is Status.OK, (res.status, res.error)
    screening = res.attributes["risk_lists_screening"]
    print(json.dumps(screening, indent=1))
    print(res.attributes.get("cvm_authorisation"))
    assert screening["pgfn_divida_ativa"]["state"] == "not_screened"  # opt-in import not done here
    if results[R.MTE_DATASET].ok:
        assert screening["mte_lista_suja"]["state"] in ("no_record", "listed")
        mte = R.load_mte(rt.data.scoped())
        assert len(mte.rows) > 50 and mte.extra["dropped_persons"] > 100  # most employers are persons: dropped
    if results["cvm_intermed.csv"].ok:
        assert res.attributes["cvm_authorisation"].startswith("registered with CVM: active")
    _no_personal(res)


def test_pgfn_plan_lists_the_quarter_and_sizes_without_importing():
    rt = live_runtime()
    try:
        plan = P.plan(rt)
    except P.ImportError_ as exc:
        pytest.skip(f"PGFN listing could not be read from this egress: {exc}")
    print(f"PGFN {plan['quarter']}: " + ", ".join(f"{f['name']} {f['bytes']:,} B" for f in plan["files"]))
    assert re.fullmatch(r"\d{4}_trimestre_0[1-4]", plan["quarter"]) and plan["files"]
    assert all(f["bytes"] > 1_000_000 for f in plan["files"]) and plan["download_bytes"] > 100_000_000
    assert P.open_index()[0] is None  # nothing imported


def test_br_public_spending_bndes_and_salic_for_the_golden_cnpj():
    rt = live_runtime()
    res = run_module(BrPublicSpending, f"cnpj:{BB}", runtime=rt)
    print(res.status, res.reason_code, res.error[:200], json.dumps(res.source_statuses, indent=1))
    if res.status in COULD_NOT_VERIFY:
        assert res.error
        pytest.skip(f"public-spending providers could not be verified from this egress: {res.error[:200]}")
    assert res.status in (Status.OK, Status.EMPTY)
    salic = res.source_statuses.get("minc.salic_incentivadores", {})
    if salic.get("status") == "ok":
        assert any(r["source"] == "salic" for r in res.attributes["public_funding"])
    _no_personal(res)


def test_br_public_spending_indirect_masked_query():
    rt = live_runtime(br_public_spending_bndes_indirect=True)
    res = run_module(BrPublicSpending, "cnpj:92816560000137", runtime=rt)
    print(res.status, res.reason_code, res.error[:200], json.dumps(res.source_statuses, indent=1),
          [r["match"] for r in res.attributes.get("public_funding", [])])
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY
    _no_personal(res)


def test_br_egress_module_is_gated_outside_brazil():
    rt = live_runtime()
    decision = Engine(rt, ScanOptions()).decide_single(BrPublicSpendingBr, Entity.make(T.CNPJ, BB))
    assert decision.allowed is False and decision.reason_code == "egress_country"
