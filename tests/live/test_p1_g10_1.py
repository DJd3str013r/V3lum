"""Live checks of batch p1-G10-1 (sanctions_lists, boleto_pix; br_validators has no network source); run with V3LUM_LIVE=1.

Keyless official downloads through the dataset manager only (the modules themselves never touch the
network): the OFAC Sanctions List Service exports SDN/SDN_COMMENTS/ALT/ADD.CSV (302 to a pre-signed S3
link), the UN consolidated XML (302 to Azure blob storage), the EU FSF CSV (the Commission's public
token), the BCB ParticipantesSTR.csv and the BrasilAPI bank and PIX participant tables. Every copy is
validated (row floors, end-of-file marker, safe XML, ';' + BOM) before it is installed, then matched
offline with benign public values: the ETH address published in the SDN entry of LAZARUS GROUP, the
designated company 'Korea Mining Development Trading Corporation' (KOMID, on all three lists), the actor
name 'Lazarus Group', the clean company 'Banco do Brasil S.A.' / CNPJ 00.000.000/0001-91, and the
documentation boleto line and PIX BR Codes of the offline fixtures. No natural person is ever screened.

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is reported as
could-not-verify: a failed update installs nothing and the list then reads 'not screened' (UNAVAILABLE
'dataset' when no list is installed), never 'no match'.
"""

from __future__ import annotations

import time

import pytest

from tests.fakes import module_fixture, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import boleto_pix as BP
from v3lum.modules.brazil_public_data import br_parsers as P
from v3lum.modules.brazil_public_data.boleto_pix import BoletoPix
from v3lum.modules.brazil_public_data.br_validators import BrValidators
from v3lum.modules.company_org import namematch as nm
from v3lum.modules.company_org import sanctions_data as sd
from v3lum.modules.company_org import sanctions_lists as SL
from v3lum.modules.company_org.sanctions_lists import SanctionsLists

pytestmark = pytest.mark.live
LAZARUS_ETH = "0x098B716B8AAF21512996DC57EB0615E2383E2F96"  # published in the SDN entry of LAZARUS GROUP (DPRK3)
KOMID = "Korea Mining Development Trading Corporation"


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _update(rt: Runtime, names) -> dict[str, bool]:
    ok: dict[str, bool] = {}
    for name in names:
        t0 = time.monotonic()
        result = rt.data.update(name)
        info = rt.data.info(name)
        print(f"{name}: {result.status} {info.bytes if info.present else '-'} bytes {time.monotonic() - t0:.1f}s {result.reason[:200]}")
        assert result.status in ("updated", "unchanged", "failed")
        if result.status == "failed":  # could not verify from this egress: reported, nothing installed
            assert result.reason and not info.present
        ok[name] = result.status != "failed"
    return ok


def test_sanctions_lists_download_validate_and_screen_offline():
    rt = live_runtime()
    ok = _update(rt, SL.SANCTIONS_DATASETS)
    lists = {"OFAC SDN": ok[SL.DS_OFAC_SDN], "UN": ok[SL.DS_UN], "EU FSF": ok[SL.DS_EU]}
    if ok[SL.DS_OFAC_SDN]:
        sdn = sd.parse_ofac_sdn_csv(rt.data.path(SL.DS_OFAC_SDN).read_bytes())
        assert sdn["trailer"] and sdn["rows"] >= sd.OFAC_SDN_MIN_ROWS and sdn["bad_rows"] == 0
        print(f"OFAC SDN rows {sdn['rows']}, remarks cut at 1000 characters: {sum(e['remarks_truncated'] for e in sdn['entries'])}")
    if ok[SL.DS_UN]:
        un = sd.parse_un_consolidated(rt.data.path(SL.DS_UN).read_bytes())
        assert len(un["entries"]) >= sd.UN_MIN_ENTRIES and un["date_generated"]
        print(f"UN {un['date_generated']}: {un['individuals']} individuals, {un['entities']} entities")
    if ok[SL.DS_EU]:
        eu = sd.parse_eu_fsf_csv(rt.data.path(SL.DS_EU))
        assert eu["bom"] and not eu["truncated"] and len(eu["entries"]) >= sd.EU_MIN_ENTITIES
        print(f"EU FSF {eu['file_generation_date']}: {eu['rows']} rows, {len(eu['entries'])} subjects")

    wallet = run_module(SanctionsLists, "eth_address:" + LAZARUS_ETH, runtime=rt)
    if ok[SL.DS_OFAC_SDN]:
        assert wallet.status is Status.OK, (wallet.status, wallet.error)
        (hit,) = wallet.findings
        assert hit.severity.label == "critical" and hit.confidence_label.value == "confirmed" and "DPRK3" in hit.data["programmes"]
        assert wallet.attributes["sanctioned"] is True and hit.data["list_date"]
    else:
        assert wallet.status is Status.UNAVAILABLE and wallet.reason_code == "dataset"

    komid = run_module(SanctionsLists, "company_name:" + KOMID, runtime=rt)
    if not any(lists.values()):
        assert komid.status is Status.UNAVAILABLE and komid.reason_code == "dataset" and "no match" not in komid.error
        pytest.skip("no sanctions list could be installed from this egress")
    assert komid.status is Status.OK, (komid.status, komid.error)
    screening = komid.attributes["sanctions_screening"]
    for label, installed in lists.items():
        assert screening[label]["state"] == ("listed" if installed else "not_screened"), (label, screening[label])
    assert len(komid.findings) == sum(lists.values())
    for f in komid.findings:
        assert f.severity.label == "medium" and f.confidence_label.value == "possible" and "sanctioned" not in f.title.lower()
        assert 1 <= len(f.data["candidates"]) <= 5 and f.data["candidates"][0]["score"] >= nm.NAME_MATCH_THRESHOLD
    assert "sanctioned" not in komid.attributes and komid.attributes["data_attribution"]

    clean = run_module(SanctionsLists, "company_name:Banco do Brasil S.A.", runtime=rt)
    assert clean.status is Status.OK and clean.findings == [] and "sanctioned" not in clean.attributes
    assert {s["state"] for s in clean.attributes["sanctions_screening"].values()} <= {"no_record", "not_screened"}
    company = run_module(SanctionsLists, "cnpj:00000000000191", runtime=rt)
    assert company.findings == [] and company.status is (Status.OK if ok[SL.DS_OFAC_SDN] else Status.UNAVAILABLE)

    actor = run_module(SanctionsLists, "threat_actor:Lazarus Group", runtime=rt)
    if ok[SL.DS_OFAC_SDN]:
        line = actor.attributes["sanctions_designation"]
        assert line.startswith("OFAC") and line.endswith("payments may be prohibited, escalate to legal")
        assert all(f.severity.label == "medium" for f in actor.findings)


def test_bank_tables_download_and_boleto_pix_offline():
    rt = live_runtime()
    ok = _update(rt, (BP.DS_STR, BP.DS_BANKS, BP.DS_PIX))
    for name, parser in ((BP.DS_STR, P.parse_bcb_str_csv), (BP.DS_BANKS, P.parse_brasilapi_banks), (BP.DS_PIX, P.parse_brasilapi_pix_participants)):
        if ok[name]:
            parsed = parser(rt.data.path(name).read_bytes())
            assert parsed["ok"] and len(parsed["entries"]) >= 100, (name, parsed.get("error"))
            print(f"{name}: {len(parsed['entries'])} rows")
    lines = {c["id"]: c["line"] for c in module_fixture(BoletoPix, "boleto_cases.json")["cases"]}
    res = run_module(BoletoPix, "boleto:" + lines["bancario_ok_new_cycle"], runtime=rt)
    assert res.status is Status.OK and res.findings == [], (res.status, res.error)
    assert res.attributes["boleto_verdict"].startswith("Boleto: check digits OK - bank 341 (ITAÚ UNIBANCO")
    assert res.attributes["boleto_facts"]["bank_ispb"] == "60701190"
    tables = {t["table"]: t for t in res.attributes["bank_tables"]}
    print(tables)
    assert tables["BCB STR participants"]["source"] == ("dataset" if ok[BP.DS_STR] else "bundled snapshot")
    for name, label in ((BP.DS_BANKS, "BrasilAPI banks"), (BP.DS_PIX, "BrasilAPI PIX participants")):
        assert tables[label]["source"] == ("dataset" if ok[name] else "not downloaded")
    brcodes = {c["id"]: c["payload"] for c in module_fixture(BoletoPix, "brcode_cases.json")["cases"]}
    pix = run_module(BoletoPix, "pix_brcode:" + brcodes["cnpj_key"], runtime=rt)
    assert pix.status is Status.OK and pix.attributes["pix_crc_status"] == "CRC OK"
    assert ("cnpj:00000000000191", "pix_key_of") in {(p.entity.key, p.relation) for p in pix.pivots}
    manual = run_module(BoletoPix, "pix_brcode:" + module_fixture(BoletoPix, "brcode_bcb_manual.txt").strip(), runtime=rt)
    assert manual.attributes["pix_crc_status"] == "CRC OK"


def test_br_validators_needs_no_network():
    rt = live_runtime()
    res = run_module(BrValidators, "cnpj:00000000000191", runtime=rt)
    assert res.status is Status.OK and res.attributes["valid"] is True
    assert res.attributes["cnpj_structure"]["is_headquarters"] is True and res.attributes["formatted_value"] == "00.000.000/0001-91"
