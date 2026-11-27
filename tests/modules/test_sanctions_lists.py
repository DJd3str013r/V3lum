"""sanctions_lists (P219): offline screening against OFAC SDN, the UN consolidated list and EU FSF.

Fixtures in tests/fixtures/sanctions_lists/ (prep batch p1-G10-1, recorded 2026-11-26 from the
research egress; untrusted data, minimised): ``ofac_sdn_ok.csv`` (10 real SDN rows - entities and one
vessel - byte-exact except two 'Linked To:' persons replaced by DOE, John / ROE, Richard, plus synthetic
individuals 99000001 (BIP-173 test-vector wallet, a 0x...dEaD1 address) and 99000002 (a common name with
the documentation CPF in its remarks); CRLF + the 0x1A trailer; three remarks cut at 1000 characters),
``ofac_sdn_comments_ok.csv`` (the real continuations), ``ofac_alt_ok.csv`` / ``ofac_add_ok.csv`` (real
rows of entities 36/306 + synthetic rows), ``ofac_publication.json`` (the live 302 Location with every
credential redacted), ``un_ok.xml`` (real ENTITY 690735 KOMID and 6908777 ISIL-K + a synthetic
INDIVIDUAL), ``eu_fsf_ok.csv`` (the real header + entity 201 aliases in five languages + a synthetic
person; UTF-8 BOM, ';'), ``eu_fsf_forbidden.http.json`` (the live 403 without token) and synthetic error
documents (``ofac_s3_expired.xml``, ``un_azure_expired.xml``, ``un_doctype.xml`` (DTD/XXE),
``un_malformed.xml``, ``un_empty.xml``, ``eu_fsf_truncated.csv``, ``ofac_sdn_malformed.csv``).
``name_queries.json`` holds the matcher cases (the common-name non-match and the Petrobras calibration).
"""

from __future__ import annotations

import json
import os
import random
import re
import time
from datetime import datetime, timezone

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.context import ScanOptions
from v3lum.core.datasets import DATASETS, DatasetUnavailable
from v3lum.core.entities import EntityType as T
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.company_org import namematch as nm
from v3lum.modules.company_org import sanctions_data as sd
from v3lum.modules.company_org import sanctions_lists as SL
from v3lum.modules.company_org.sanctions_lists import SanctionsLists

DD = ScanOptions(purpose="supplier onboarding due diligence DD-2026-001")
INSTALL = {
    SL.DS_OFAC_SDN: "ofac_sdn_ok.csv", SL.DS_OFAC_COMMENTS: "ofac_sdn_comments_ok.csv", SL.DS_OFAC_ALT: "ofac_alt_ok.csv",
    SL.DS_OFAC_ADD: "ofac_add_ok.csv", SL.DS_UN: "un_ok.xml", SL.DS_EU: "eu_fsf_ok.csv",
}


def fx(name: str) -> bytes:
    return (FIXTURES / "sanctions_lists" / name).read_bytes()


#: installed copies carry a fixed fetch time (file mtime, no MANIFEST entry) so dates never follow the wall clock
FETCHED_AT = datetime(2026, 11, 26, 6, 0, tzinfo=timezone.utc).timestamp()


def install(*names: str) -> None:
    for name in names or tuple(INSTALL):
        path = paths.datasets_dir() / name
        path.write_bytes(fx(INSTALL[name]))
        os.utime(path, (FETCHED_AT, FETCHED_AT))


@pytest.fixture(autouse=True)
def fresh_memos():
    for memo in (SL._MEMO, SL._ALIAS_MEMO, SL._HISTORY_MEMO):
        memo.clear()
    yield
    for memo in (SL._MEMO, SL._ALIAS_MEMO, SL._HISTORY_MEMO):
        memo.clear()


@pytest.fixture(scope="module")
def ofac():
    sdn = sd.parse_ofac_sdn_csv(fx("ofac_sdn_ok.csv"))
    com = sd.parse_ofac_comments_csv(fx("ofac_sdn_comments_ok.csv"))
    merged = sd.merge_ofac_remarks(sdn["entries"], com["comments"])
    return {"sdn": sdn, "com": com, "merged": merged, "by_uid": {e["uid"]: e for e in merged},
            "list": SL.build_ofac(fx("ofac_sdn_ok.csv"), fx("ofac_sdn_comments_ok.csv"), fx("ofac_alt_ok.csv"), fx("ofac_add_ok.csv"))}


# ------------------------------------------------------------------ metadata and datasets (cond 1-3)
def test_metadata_offline_open_trusted_sources_default_on():
    cls = SanctionsLists
    assert (cls.disclosure, cls.hosts, cls.provider) == ("none", (), "")
    assert cls.sources == ("ofac_sls.sdn", "unsc_sanctions.consolidated", "eu_fsf.fsf_csv") and cls.terms == "open"
    assert cls.default_enabled is True and cls.opsec.label == "passive" and cls.max_tlp.value_str == "red"
    assert not any("opensanctions" in s for s in cls.sources)  # cond 1: CC BY-NC data belongs to P222
    assert {T.ORG, T.PERSON, T.THREAT_ACTOR, T.BTC, T.ETH, T.XMR, T.CRYPTO, T.CNPJ} == set(cls.accepts)
    assert cls.health_check().offline is True
    ttl = {SL.DS_OFAC_SDN: 86400, SL.DS_OFAC_COMMENTS: 86400, SL.DS_OFAC_ALT: 86400, SL.DS_OFAC_ADD: 86400, SL.DS_UN: 86400, SL.DS_EU: 3 * 86400}
    for name, seconds in ttl.items():
        reg = DATASETS[name]
        assert reg["ttl"] == seconds and reg["large"] is True and reg["essential"] is True and callable(reg["validate"])
        assert reg["terms_class"] == "open" and reg["licence"] and reg["source"] in cls.sources
    assert DATASETS[SL.DS_EU]["url"].endswith("?token=" + SL.EU_FSF_PUBLIC_TOKEN)
    ctx = make_ctx(SanctionsLists, FakeHttp(), entity="company_name:Example Ltda")
    with pytest.raises(PolicyError):
        ctx.http.get(SL.UN_URL)  # matching is local: the module itself has no network


def test_scans_never_download_the_lists():
    rt = make_runtime(FakeHttp())
    rt.in_scan = True
    for name in SL.SANCTIONS_DATASETS:
        with pytest.raises(DatasetUnavailable):
            rt.data.fetch(name)


def test_ofac_download_follows_the_s3_redirect_and_keeps_the_previous_copy(monkeypatch):
    monkeypatch.setitem(DATASETS[SL.DS_OFAC_SDN], "min_bytes", 100)
    monkeypatch.setattr(sd, "OFAC_SDN_MIN_ROWS", 5)
    location = module_fixture(SanctionsLists, "ofac_publication.json")["location"]
    s3 = re.compile(r"^https://wc2h-sls-prod-public-published\.s3\.us-gov-west-1\.amazonaws\.com/")
    http = FakeHttp().add("GET", SL.OFAC_EXPORTS + "SDN.CSV", redirect_to=location).add("GET", s3, body=fx("ofac_sdn_ok.csv"))
    assert make_runtime(http).data.update(SL.DS_OFAC_SDN).status == "updated"
    good = (paths.datasets_dir() / SL.DS_OFAC_SDN).read_bytes()
    assert good == fx("ofac_sdn_ok.csv") and http.hosts() == {"sanctionslistservice.ofac.treas.gov", "wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com"}
    expired = FakeHttp().add("GET", SL.OFAC_EXPORTS + "SDN.CSV", redirect_to=location).add("GET", s3, status=403, body=fx("ofac_s3_expired.xml"))
    result = make_runtime(expired).data.update(SL.DS_OFAC_SDN)
    assert result.status == "failed" and "pre-signed S3 download link expired" in result.reason
    assert (paths.datasets_dir() / SL.DS_OFAC_SDN).read_bytes() == good
    cut = FakeHttp().add("GET", SL.OFAC_EXPORTS + "SDN.CSV", body=fx("ofac_sdn_ok.csv")[:-3])  # no 0x1A trailer
    assert make_runtime(cut).data.update(SL.DS_OFAC_SDN).status == "failed"


def test_un_and_eu_downloads_are_validated(monkeypatch):
    monkeypatch.setitem(DATASETS[SL.DS_UN], "min_bytes", 100)
    monkeypatch.setitem(DATASETS[SL.DS_EU], "min_bytes", 100)
    monkeypatch.setattr(sd, "UN_MIN_ENTRIES", 3)
    monkeypatch.setattr(sd, "EU_MIN_ENTITIES", 2)
    azure = "https://unsolprodfiles.blob.core.windows.net/publiclegacyxmlfiles/EN/consolidatedLegacyByPRN.xml?sv=2020&se=2026&sr=b&sp=r&sig=REDACTED"
    http = FakeHttp().add("GET", SL.UN_URL, redirect_to=azure).add("GET", azure, body=fx("un_ok.xml"))
    assert make_runtime(http).data.update(SL.DS_UN).status == "updated"
    denied = FakeHttp().add("GET", SL.UN_URL, redirect_to=azure).add("GET", azure, status=403, body=fx("un_azure_expired.xml"))
    assert "Azure storage refused the signed download link" in make_runtime(denied).data.update(SL.DS_UN).reason
    for bad in ("un_doctype.xml", "un_malformed.xml", "un_empty.xml"):
        fresh = FakeHttp().add("GET", SL.UN_URL, body=fx(bad))
        assert make_runtime(fresh).data.update(SL.DS_UN).status == "failed", bad
    rogue = FakeHttp().add("GET", SL.UN_URL, redirect_to="https://files.example.net/consolidated.xml")
    assert "not declared" in make_runtime(rogue).data.update(SL.DS_UN).reason  # every redirect hop is host-checked
    eu = FakeHttp().add("GET", SL.EU_URL, body=fx("eu_fsf_ok.csv"))
    assert make_runtime(eu).data.update(SL.DS_EU).status == "updated"
    forbidden = module_fixture(SanctionsLists, "eu_fsf_forbidden.http.json")
    refused = FakeHttp().add("GET", SL.EU_URL, status=403, json=json.loads(forbidden["body"]))
    assert "public token may have changed" in make_runtime(refused).data.update(SL.DS_EU).reason
    trunc = FakeHttp().add("GET", SL.EU_URL, body=fx("eu_fsf_truncated.csv"))
    assert make_runtime(trunc).data.update(SL.DS_EU).status == "failed"
    for status in (429, 500):
        down = FakeHttp().add("GET", SL.EU_URL, status=status, text="unavailable")
        assert make_runtime(down).data.update(SL.DS_EU).status == "failed"


# ------------------------------------------------------------------ safe XML (cond 5)
def test_safe_xml_refuses_doctype_entities_and_bad_encodings():
    with pytest.raises(sd.XMLRefused):
        sd.safe_xml_parse(fx("un_doctype.xml"))
    assert sd.parse_un_consolidated(fx("un_doctype.xml"))["error"].startswith("refused:")
    with pytest.raises(sd.XMLRefused):
        sd.safe_xml_parse("<a/>".encode("utf-16"))
    with pytest.raises(sd.XMLRefused):
        sd.safe_xml_parse(b'<?xml version="1.0" encoding="ISO-8859-1"?><a/>')


def test_safe_xml_caps_and_malformed():
    with pytest.raises(sd.XMLLimitExceeded):
        sd.safe_xml_parse(fx("un_ok.xml"), max_bytes=1000)
    with pytest.raises(sd.XMLLimitExceeded):
        sd.safe_xml_parse("<a>" * 40 + "</a>" * 40)
    with pytest.raises(sd.XMLLimitExceeded):
        sd.safe_xml_parse("<r>" + "<i/>" * 50 + "</r>", max_elements=10)
    with pytest.raises(sd.XMLMalformed):
        sd.safe_xml_parse(fx("un_malformed.xml"))
    with pytest.raises(sd.XMLMalformed):
        sd.safe_xml_parse("<a>&undefined;</a>")
    assert sd.safe_xml_parse("<a x='1'><b>t</b></a>").find("b").text == "t"


# ------------------------------------------------------------------ OFAC parsing (cond 1, 5, 7)
def test_ofac_sdn_parse_and_merge(ofac):
    sdn = ofac["sdn"]
    assert sdn["ok"] and sdn["rows"] == 12 and sdn["bad_rows"] == 0 and sdn["trailer"] is True
    e = {x["uid"]: x for x in sdn["entries"]}
    assert e[36]["kind"] == "entity" and e[36]["remarks"] is None and e[4243]["kind"] == "vessel"
    assert e[56752]["programs"] == ["SDGT", "ILLICIT-DRUGS-EO14059"] and e[99000001]["kind"] == "individual"
    assert e[27307]["remarks_truncated"] and len(e[27307]["remarks"]) == 1000
    by = ofac["by_uid"]
    assert ofac["com"]["rows"] == 3 and by[27307]["remarks"].endswith("a.k.a. 'APPLEWORM'.")
    assert "1B64QRxfaa35MVkf7sDjuGUYAP5izQt7Qi" in by[33151]["remarks"] and not any(x["remarks_truncated"] for x in ofac["merged"])


def test_ofac_remark_facts_and_no_cpf_kept(ofac):
    by = ofac["by_uid"]
    laz = sd.parse_ofac_remarks(by[27307]["remarks"])
    assert {"type": "aka", "name": "HIDDEN COBRA"} in laz["aliases"] and len(laz["aliases"]) == 11
    assert len(laz["wallets"]) == 8 and laz["wallets"][0]["normalized"] == "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
    ebano = sd.parse_ofac_remarks(by[4243]["remarks"])
    assert ebano["imo"] == ["7406784"] and [a["type"] for a in ebano["aliases"]] == ["fka", "fka"]
    hebei = sd.parse_ofac_remarks(by[32313]["remarks"])
    assert hebei["registrations"] == [{"scheme": "Unified Social Credit Code (USCC)", "number": "91130104MA09YL9T2W", "country": "China"}]
    suex = sd.parse_ofac_remarks(by[33151]["remarks"])
    assert suex["lei"] == ["5299007NTWCC3U23WM81"]
    assert sd.parse_ofac_remarks(by[56752]["remarks"])["cnpjs"] == ["50147517000186"]
    assert sd.parse_ofac_remarks(by[34279]["remarks"])["cnpjs"] == ["35116112000197"]
    john = sd.parse_ofac_remarks(by[99000001]["remarks"])
    assert john["dob"] == ["01 Jan 1970"] and john["nationality"] == ["Exampleland"] and john["documents"] == 1
    assert [w["entity_type"] for w in john["wallets"]] == ["btc_address", "eth_address"]
    jose = sd.parse_ofac_remarks(by[99000002]["remarks"])
    assert jose["cnpjs"] == [] and jose["registrations"] == []  # the CPF in the remarks is never kept (rule 4)
    assert "52998224725" not in json.dumps(ofac["list"].ids) and "529.982.247" not in json.dumps(ofac["list"].entries)


def test_truncated_tail_is_never_indexed_and_the_merge_completes_wallets(ofac):
    raw = SL.build_ofac(fx("ofac_sdn_ok.csv"))  # without SDN_COMMENTS
    assert "SDN_COMMENTS.CSV not downloaded" in " ".join(raw.notes)
    for split in ("1B64QRxfaa35MVkf7sDjuGUYAP5izQt7Qi", "TSbGiFzG9xFXUYgGA6RwbS3jvKNpeA4c3R"):
        assert split not in raw.ids["wallet"] and split in ofac["list"].ids["wallet"]
    assert "TSbGiFzG9xFXUYgGA6Rw" not in raw.ids["wallet"] and "1B64QRxf" not in raw.ids["wallet"]


def test_wallet_normalisation():
    tron = "TSbGiFzG9xFXUYgGA6RwbS3jvKNpeA4c3R"
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for c in tron:
        num = num * 58 + alphabet.index(c)
    hexform = num.to_bytes(25, "big")[:21].hex()
    assert hexform.startswith("41") and sd.normalize_wallet(hexform)["normalized"] == tron
    assert sd.normalize_wallet("0x" + hexform)["normalized"] == tron
    assert sd.normalize_wallet("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")["normalized"] == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert sd.normalize_wallet("bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")["valid_shape"] is False  # mixed case never matches
    assert sd.normalize_wallet("bitcoin:1JPfVv5cWRLx1js9NWxg46dG2CGbeRz4th?amount=1")["normalized"] == "1JPfVv5cWRLx1js9NWxg46dG2CGbeRz4th"
    assert sd.normalize_wallet("not a wallet")["valid_shape"] is False


def test_ofac_alt_add_errors_and_validation(ofac):
    alt = sd.parse_ofac_alt_csv(fx("ofac_alt_ok.csv"))
    assert alt["aliases"][306] == [{"type": "aka", "name": "NATIONAL BANK OF CUBA"}]
    add = sd.parse_ofac_add_csv(fx("ofac_add_ok.csv"))
    assert add["addresses"][36] == [{"city": "Havana", "country": "Cuba"}] and len(add["addresses"][306]) == 4
    assert sd.parse_ofac_sdn_csv(fx("ofac_sdn_empty.csv"))["error"] == "SDN.CSV body is empty"
    bad = sd.parse_ofac_sdn_csv(fx("ofac_sdn_malformed.csv"))
    assert not bad["ok"] and "not valid CSV" in bad["error"] and sd.validate_ofac_sdn(bad) == bad["error"]
    assert sd.parse_ofac_sdn_csv(b"<!DOCTYPE html><html><body>Service Unavailable</body></html>")["error"] == "HTML page instead of SDN.CSV"
    assert sd.parse_ofac_sdn_csv(fx("ofac_s3_expired.xml"))["error"].startswith("download link expired")
    assert sd.validate_ofac_sdn(ofac["sdn"]) == "SDN.CSV has 12 rows (< 5000)" and sd.validate_ofac_sdn(ofac["sdn"], min_rows=5) is None
    assert sd.validate_ofac_sdn(sd.parse_ofac_sdn_csv(fx("ofac_sdn_ok.csv")[:-1]), min_rows=5).startswith("SDN.CSV lacks its end-of-file marker")
    assert sd.parse_ofac_sdn_csv(12345)["ok"] is False


# ------------------------------------------------------------------ UN and EU parsing (cond 1, 5)
def test_un_parse_and_errors():
    un = sd.parse_un_consolidated(fx("un_ok.xml"))
    assert un["ok"] and un["date_generated"] == "2026-11-26T00:00:00.937Z" and (un["individuals"], un["entities"]) == (1, 2)
    komid = next(e for e in un["entries"] if e["dataid"] == "690735")
    assert komid["programs"] == ["DPRK"] and komid["listed_on"] == "2009-04-24" and '"KOMID"' in [a["name"] for a in komid["aliases"]]
    assert sd.validate_un(un) == "UN list has 3 entries (< 300)" and sd.validate_un(un, min_entries=3) is None
    empty = sd.parse_un_consolidated(fx("un_empty.xml"))
    assert empty["ok"] and empty["entries"] == [] and sd.validate_un(empty).startswith("UN list has 0")
    assert sd.parse_un_consolidated(fx("un_azure_expired.xml"))["error"].startswith("storage refused")
    assert sd.parse_un_consolidated(b"<!DOCTYPE html><html><body>Maintenance</body></html>")["error"].startswith("HTML page")
    assert sd.parse_un_consolidated(b"")["error"] == "UN list body is empty"
    assert sd.parse_un_consolidated(b"<OTHER/>")["error"] == "unexpected root element <OTHER>"


def test_eu_fsf_parse_streams_and_validates(tmp_path):
    raw = fx("eu_fsf_ok.csv")
    eu = sd.parse_eu_fsf_csv(raw)
    assert eu["ok"] and eu["bom"] and eu["file_generation_date"] == "2026-11-20" and not eu["truncated"] and eu["rows"] == 14
    ent = next(e for e in eu["entries"] if e["logical_id"] == "201")
    assert ent["kind"] == "entity" and ent["name"] == "Abu Nidal Organisation" and ent["programs"] == ["TERR"]
    assert "Μαύρος Σεπτέμβρης" in [a["name"] for a in ent["aliases"]]
    per = next(e for e in eu["entries"] if e["logical_id"] == "990013")
    assert per["kind"] == "individual" and per["birth_dates"][0]["date"] == "1970-01-01" and per["citizenships"] == ["BR"]
    path = tmp_path / "eu.csv"
    path.write_bytes(raw)
    assert sd.parse_eu_fsf_csv(path)["entries"] == eu["entries"]  # the 25 MB file is read as a stream
    assert sd.validate_eu_fsf(eu, min_entities=2) is None and sd.validate_eu_fsf(eu).startswith("EU FSF has 2 entities")
    trunc = sd.parse_eu_fsf_csv(fx("eu_fsf_truncated.csv"))
    assert trunc["truncated"] and sd.validate_eu_fsf(trunc, min_entities=1).startswith("EU FSF CSV ends")
    assert sd.validate_eu_fsf(sd.parse_eu_fsf_csv(raw[3:]), min_entities=1) == "EU FSF CSV without the expected UTF-8 BOM"
    forbidden = module_fixture(SanctionsLists, "eu_fsf_forbidden.http.json")
    assert sd.parse_eu_fsf_csv(forbidden["body"])["error"].startswith("EU FSF refused the download (HTTP 403 Forbidden)")
    assert sd.parse_eu_fsf_csv(b"a,b,c\n1,2,3\n")["error"] == "not a ';'-separated EU FSF file"
    assert sd.parse_eu_fsf_csv(b"x;y\n1;2\n")["error"].startswith("EU FSF header lacks")


# ------------------------------------------------------------------ the shared matcher (cond 6, 13)
def test_jaro_winkler_reference_values():
    assert round(nm.jaro_winkler_py("MARTHA", "MARHTA"), 4) == 0.9611
    assert round(nm.jaro_winkler_py("DWAYNE", "DUANE"), 4) == 0.84
    assert round(nm.jaro_winkler_py("DIXON", "DICKSONX"), 4) == 0.8133
    assert nm.jaro_winkler_py("", "") == 1.0 and nm.jaro_winkler_py("a", "") == 0.0 and nm.jaro("abc", "xyz") == 0.0


def test_rapidfuzz_accelerator_gives_identical_scores():
    rf = pytest.importorskip("rapidfuzz.distance")
    rnd = random.Random(7)
    for _ in range(500):
        a = "".join(rnd.choice("abcdeilmnorst") for _ in range(rnd.randint(1, 12)))
        b = "".join(rnd.choice("abcdeilmnorst") for _ in range(rnd.randint(1, 12)))
        assert abs(nm.jaro_winkler_py(a, b) - rf.JaroWinkler.similarity(a, b)) < 1e-9


def test_both_scoring_paths_rank_the_same(monkeypatch, ofac):
    calls = []

    def accel(a: str, b: str) -> float:
        calls.append((a, b))
        return nm.jaro_winkler_py(a, b)

    queries = [("Lazarus Group", "entity"), ("Pixwave Solucoes de Pagamento", "entity"), ("John Doe", "person"), ("Petrobras", "entity")]
    monkeypatch.setattr(nm, "_ACCEL", None)
    assert nm.accelerator_name() == "pure-python"
    pure = [nm.match_name(q, ofac["list"].name_index, kind=k) for q, k in queries]
    monkeypatch.setattr(nm, "_ACCEL", accel)
    assert nm.accelerator_name() == "rapidfuzz"
    fast = [nm.match_name(q, ofac["list"].name_index, kind=k) for q, k in queries]
    assert pure == fast and calls


def test_name_tokens_normalisation():
    assert nm.name_tokens("SUEX OTC, S.R.O.") == ("suex", "otc")
    assert nm.name_tokens("HEBEI ATUN TRADING CO., LTD.") == ("hebei", "atun", "trading")
    assert nm.name_tokens("Pixwave Soluções de Pagamentos S/A") == ("pixwave", "solucoes", "pagamentos")
    assert nm.name_tokens("OBSHCHESTVO S OGRANICHENNOI OTVETSTVENNOSTYU KONSTRUKTORSKOE BYURO") == ("konstruktorskoe", "byuro")
    assert nm.name_tokens("José da Silva", "person") == ("jose", "silva")
    assert nm.name_tokens("CO. LTD") in (("co",), ("ltd",), ("co", "ltd"))  # never empties a name


def test_token_set_jw_properties():
    a = nm.name_tokens("Korea Mining Development Trading Corporation")
    assert nm.token_set_jw(a, nm.name_tokens("Trading Development Mining Korea")) == 1.0
    assert nm.token_set_jw(nm.name_tokens("Korea"), a) < 0.9  # a one-word query does not match a long name
    s1 = nm.token_set_jw(nm.name_tokens("pixwave solucoes pagamento"), nm.name_tokens("PIXWAVE SOLUCOES DE PAGAMENTOS LTDA"))
    s2 = nm.token_set_jw(nm.name_tokens("PIXWAVE SOLUCOES DE PAGAMENTOS LTDA"), nm.name_tokens("pixwave solucoes pagamento"))
    assert s1 == s2 and s1 > 0.95


@pytest.fixture(scope="module")
def all_lists(ofac):
    return [ofac["list"], SL.build_un(fx("un_ok.xml")), SL.build_eu(fx("eu_fsf_ok.csv"))]


def test_name_queries_fixture(all_lists):
    for case in module_fixture(SanctionsLists, "name_queries.json")["cases"]:
        got = []
        for lst in all_lists:
            hits = nm.match_name(case["query"], lst.name_index, kind=case["kind"])
            assert len(hits) <= nm.MAX_CANDIDATES and all(h["score"] >= nm.NAME_MATCH_THRESHOLD for h in hits)
            got += [h["entry_id"] for h in hits]
        assert sorted(map(str, got)) == sorted(map(str, case["expect"])), case


def test_petrobras_calibration_is_a_possible_match_never_sanctioned(all_lists):
    (hit,) = nm.match_name("Petrobras", all_lists[0].name_index, kind="entity")
    assert hit["matched_alias"] == "PETROPARS LTD." and 0.90 <= hit["score"] < 0.95
    verdict = SL.name_verdict(hit["score"], person=False, homonym=None)
    assert verdict["severity"] == "medium" and verdict["confidence"] <= 0.5 and "sanctioned" not in json.dumps(verdict)


def _synthetic_aliases(n: int, seed: int = 219) -> list[dict]:
    rnd = random.Random(seed)
    syl = ["ka", "ri", "mo", "sa", "lu", "de", "va", "no", "ti", "ber", "gan", "shi", "ro", "el", "an", "um", "is", "za", "qu", "pha", "tor",
           "vin", "mar", "sol", "ny", "ek", "ost", "ul", "ard", "ive"]
    out = []
    for i in range(n):
        tokens = ["".join(rnd.choice(syl) for _ in range(rnd.randint(2, 4))) for _ in range(rnd.randint(2, 4))]
        out.append({"entry_id": i // 2, "name": " ".join(tokens).upper(), "kind": "person" if i % 3 == 0 else "entity",
                    "alias_type": "primary" if i % 2 == 0 else "aka"})
    return out


def test_benchmark_50k_aliases_under_300ms_per_name():
    records = _synthetic_aliases(50_000)
    index = nm.build_name_index(records)
    rnd = random.Random(13)
    queries = []
    for rec in rnd.sample(records, 15):
        name = rec["name"]
        pos = rnd.randrange(len(name))
        queries.append((name[:pos] + ("X" if name[pos] != "X" else "Y") + name[pos + 1:], rec["kind"]))
    queries += [("TOTALLY ABSENT NAME", "entity"), ("JOAO DA SILVA", "person"), ("MARSOL KARI", "entity"), ("VINTOR OSTEK UMAN", "person"), ("ZAQU", "entity")]
    t0 = time.perf_counter()
    for q, kind in queries:
        nm.match_name(q, index, kind=kind)
    per_name = (time.perf_counter() - t0) / len(queries)
    assert per_name < 0.300, f"{per_name * 1000:.1f} ms per name"


# ------------------------------------------------------------------ verdict levels (cond 8, 9)
def test_name_verdict_levels_never_critical():
    v = SL.name_verdict(0.97, person=False, homonym=None)
    assert (v["severity"], v["title"]) == ("medium", "possible match - confirm identity") and v["confidence"] <= 0.5
    v2 = SL.name_verdict(0.95, person=True, homonym=None, second_identifiers=("dob",))
    assert v2["severity"] == "high" and 0.55 <= v2["confidence"] <= 0.8 and "sanctioned" not in v2["title"]
    for score in (0.9, 0.99, 1.0):
        for second in ((), ("dob", "nationality", "wallet")):
            assert SL.name_verdict(score, person=False, homonym=None, second_identifiers=second)["severity"] != "critical"
    assert SL.name_verdict(1.0, person=False, homonym=None, low_quality_alias=True)["severity"] == "info"


def test_homonym_downgrade_with_both_scorers(monkeypatch):
    common = nm.homonym_risk("Jose da Silva")
    assert common["risk"] == "high" and common["factor"] == 0.32
    assert nm.homonym_risk("Xavier Exemplo")["risk"] == "unknown" and nm.homonym_risk("Xavier Exemplo")["factor"] == 1.0
    base = SL.name_verdict(1.0, person=True, homonym=nm.homonym_risk("Xavier Exemplo"))
    low = SL.name_verdict(1.0, person=True, homonym=common)
    assert base["severity"] == "medium" and low["severity"] == "info" and low["confidence"] < base["confidence"]
    assert SL.name_verdict(1.0, person=False, homonym=common)["severity"] == "medium"  # homonym applies to persons only
    ctx = make_ctx(SanctionsLists, FakeHttp(), entity="person_name:Jose da Silva")
    p252 = SL.person_homonym(ctx, "Jose da Silva")
    assert p252["risk"] == "high" and p252["scorer"] == ("p252" if SL._p252 is not None else "namematch")
    monkeypatch.setattr(SL, "_p252", None)
    assert SL.person_homonym(ctx, "Jose da Silva") == {**common, "scorer": "namematch"}


def test_dob_second_identifier_helper():
    assert sd.normalize_dob("01 Jan 1970") == {"year_from": 1970, "year_to": 1970, "month": 1, "day": 1, "circa": False}
    assert sd.normalize_dob("circa 1965")["circa"] and sd.normalize_dob("1970 to 1972")["year_to"] == 1972 and sd.normalize_dob("??") is None
    un = sd.parse_un_consolidated(fx("un_ok.xml"))
    ind = next(e for e in un["entries"] if e["kind"] == "individual")
    assert sd.dob_matches("1970-01-01", ind["dates_of_birth"]) and sd.dob_matches("1971-06-30", ind["dates_of_birth"])
    assert not sd.dob_matches("1975-01-01", ind["dates_of_birth"]) and not sd.dob_matches(None, ["1970"])
    assert sd.dob_matches("1966-03-01", ["circa 1965"]) and not sd.dob_matches("1970-01-02", ["01 Jan 1970"])


def test_designation_and_history_wording():
    assert sd.actor_designation_line([("OFAC", "2026-11-20"), ("UN", "2019-05-14")]) == (
        "OFAC/UN designated (2026-11-20, 2019-05-14) - payments may be prohibited, escalate to legal")
    assert sd.actor_designation_line([]) is None
    prev = [{"uid": 1, "name": "A", "list": "UN"}, {"uid": 2, "name": "B", "list": "UN"}]
    assert sd.delisted_entries(prev, [{"uid": 2}]) == [{"uid": 1, "name": "A", "list": "UN"}]
    assert sd.formerly_listed_line("2026-11-19") == "formerly listed (2026-11-19)"
    assert set(sd.ATTRIBUTION) == {"OFAC SDN", "UN", "EU FSF"}


# ------------------------------------------------------------------ coverage (cond 4)
def test_missing_lists_are_unavailable_never_no_match():
    http = FakeHttp()
    res = run_module(SanctionsLists, "company_name:Lazarus Group", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "run v3lum data update sanctions" in res.error and "no match" not in res.error
    assert {s["status"] for s in res.source_statuses.values()} == {"unavailable"}
    wallet = run_module(SanctionsLists, "btc_address:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", http)
    assert wallet.status is Status.UNAVAILABLE and wallet.reason_code == "dataset"
    assert http.calls == []


def test_stale_lists_read_could_not_screen_and_never_no_match():
    install()
    later = FakeClock("2026-12-10T12:00:00Z")  # the copies were fetched today: 14 days later they are stale
    res = run_module(SanctionsLists, "company_name:Banco do Brasil S.A.", FakeHttp(), clock=later)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "could not screen against OFAC SDN (dated" in res.error and "no match" not in res.error
    screening = res.attributes["sanctions_screening"]
    assert {v["state"] for v in screening.values()} == {"not_screened"}
    assert screening["UN"]["reason"] == "could not screen against UN (dated 2026-11-26)"
    hit = run_module(SanctionsLists, "company_name:Lazarus Group", FakeHttp(), clock=later)
    assert hit.status is Status.OK and hit.attributes["sanctions_screening"]["OFAC SDN"]["state"] == "listed"
    assert "older than 7 days" in hit.attributes["sanctions_screening"]["OFAC SDN"]["reason"]
    assert hit.source_statuses["unsc_sanctions.consolidated"]["reason"].startswith("could not screen against UN")


def test_one_missing_list_is_reported_while_the_others_screen():
    install(SL.DS_OFAC_SDN, SL.DS_OFAC_COMMENTS, SL.DS_OFAC_ALT, SL.DS_OFAC_ADD)
    res = run_module(SanctionsLists, "company_name:Banco do Brasil S.A.", FakeHttp())
    assert res.status is Status.OK and res.findings == []
    screening = res.attributes["sanctions_screening"]
    assert screening["OFAC SDN"]["state"] == "no_record" and screening["UN"]["state"] == "not_screened"
    assert res.source_statuses["eu_fsf.fsf_csv"] == {"status": "unavailable", "reason_code": "dataset",
                                                     "reason": "EU FSF list not downloaded: run v3lum data update sanctions"}
    assert res.source_statuses["ofac_sls.sdn"]["status"] == "ok"


# ------------------------------------------------------------------ exact identifiers (cond 7)
def test_wallet_exact_hit_is_critical_confirmed_sanctioned():
    install()
    http = FakeHttp()
    res = run_module(SanctionsLists, "eth_address:0x098B716B8AAF21512996DC57EB0615E2383E2F96", http)
    (f,) = res.findings
    assert f.title == "Sanctioned wallet: exact match on OFAC SDN" and f.severity.label == "critical" and f.confidence_label.value == "confirmed"
    assert f.data["programmes"] == ["DPRK3"] and f.data["entry_id"] == 27307 and f.data["list_date"] == "2026-11-26"
    assert f.data["chain"] == "ETH" and f.source == "ofac_sls.sdn" and "sanctions" in f.tags and f.criterion
    assert res.attributes["sanctioned"] is True and res.attributes["sanctions_screening"]["OFAC SDN"]["state"] == "listed"
    assert res.source_statuses["unsc_sanctions.consolidated"]["reason_code"] == "not_applicable"
    btc = run_module(SanctionsLists, "btc_address:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", http)
    assert btc.findings[0].data["entry_id"] == 99000001 and "natural person" in btc.findings[0].description
    tron = run_module(SanctionsLists, "other_crypto_address:TSbGiFzG9xFXUYgGA6RwbS3jvKNpeA4c3R", http)
    assert tron.findings[0].data["entry_id"] == 18647  # the address cut at 1000 characters, completed from SDN_COMMENTS
    clean = run_module(SanctionsLists, "btc_address:1BoatSLRHtKNngkdXEeobR76b53LETtpyT", http)
    assert clean.status is Status.OK and clean.findings == [] and "sanctioned" not in clean.attributes
    assert clean.attributes["sanctions_screening"]["OFAC SDN"]["state"] == "no_record"
    assert http.calls == []


def test_cnpj_exact_hit_and_clean_cnpj():
    install()
    res = run_module(SanctionsLists, "cnpj:50.147.517/0001-86", FakeHttp())
    (f,) = res.findings
    assert f.title == "Sanctioned CNPJ: exact match on OFAC SDN" and f.severity.label == "critical" and f.data["entry_id"] == 56752
    clean = run_module(SanctionsLists, "cnpj:00000000000191", FakeHttp())
    assert clean.findings == [] and clean.attributes["sanctions_screening"] == {"OFAC SDN": {"state": "no_record", "file_date": "2026-11-26", "reason": ""}}


# ------------------------------------------------------------------ names (cond 8-11)
def test_company_name_fuzzy_hit_is_a_possible_match():
    install()
    res = run_module(SanctionsLists, "company_name:Pixwave Soluções de Pagamento Ltda", FakeHttp())
    (f,) = res.findings
    assert f.title == "Possible sanctions match on OFAC SDN - confirm identity" and f.severity.label == "medium"
    assert f.confidence_label.value == "possible" and f.confidence <= 0.6 and "name_only_match" in f.tags
    cand = f.data["candidates"][0]
    assert cand["entry_id"] == 56752 and cand["matched_alias"] == "PIXWAVE SOLUCOES DE PAGAMENTOS LTDA" and cand["score"] >= 0.9
    assert cand["programmes"] == ["SDGT", "ILLICIT-DRUGS-EO14059"] and "listing_date" in cand
    assert "sanctioned" not in res.attributes and "sanctioned" not in f.title.lower()
    assert run_module(SanctionsLists, "company_name:Banco do Brasil S.A.", FakeHttp()).findings == []


def test_only_matched_entries_are_kept_and_reports_carry_attribution():
    install()
    res = run_module(SanctionsLists, "company_name:ISIL Khorasan", FakeHttp())
    kept = {m["entry_id"] for m in res.raw["matches"]}
    assert kept == {18647, "UN:6908777"}  # A10: no other list entry enters the case
    attribution = " ".join(res.attributes["data_attribution"])
    assert "UN public information" in attribution and "European Commission reuse notice" in attribution and "list dated 2026-11-20" in attribution
    assert res.attributes["dataset_age"][0].startswith("OFAC SDN, fetched ")
    assert {d["name"] for d in res.datasets} >= {SL.DS_OFAC_SDN, SL.DS_UN, SL.DS_EU}


def test_person_names_need_a_due_diligence_purpose():
    install()
    no_purpose = run_module(SanctionsLists, "person_name:John Doe", FakeHttp())
    assert no_purpose.status is Status.SKIPPED and no_purpose.reason_code == "privacy" and "purpose" in no_purpose.error
    pivot = run_module(SanctionsLists, "person_name:John Doe", FakeHttp(), options=DD, is_seed=False, depth=1,
                       provenance=[("text_blob:x", "mentions", "ioc_extract")])
    assert pivot.status is Status.SKIPPED and pivot.reason_code == "privacy" and "never names from pivots" in pivot.error
    unconfirmed = run_module(SanctionsLists, "person_name:John Doe",
                             FakeHttp(), options=ScanOptions(purpose="DD-1", unconfirmed_seeds={"person_name:John Doe"}))
    assert unconfirmed.status is Status.SKIPPED and unconfirmed.reason_code == "privacy"
    res = run_module(SanctionsLists, "person_name:John Doe", FakeHttp(), options=DD)
    assert res.status is Status.OK and {f.data["list"] for f in res.findings} == {"OFAC SDN", "UN", "EU FSF"}
    for f in res.findings:
        assert f.severity.label == "medium" and f.confidence_label.value == "possible" and f.data["analyst_confirmation_required"] is True
        assert "sanctioned" not in f.title.lower() and f.data["homonym_applied"] is True
    assert res.attributes["homonym_risk"]["risk"] == "unknown"


def test_qsa_partners_need_the_due_diligence_option():
    install()
    qsa = {"is_seed": False, "depth": 1, "provenance": [("cnpj:00000000000191", "partner_of", "cnpj_lookup")]}
    off = run_module(SanctionsLists, "person_name:John Doe", FakeHttp(), options=DD, **qsa)
    assert off.status is Status.SKIPPED and off.reason_code == "privacy" and SL.SETTING_DD_PARTNERS in off.error
    on = run_module(SanctionsLists, "person_name:John Doe", FakeHttp(), options=DD, settings={SL.SETTING_DD_PARTNERS: True}, **qsa)
    assert on.status is Status.OK and on.findings
    no_purpose = run_module(SanctionsLists, "person_name:John Doe", FakeHttp(), settings={SL.SETTING_DD_PARTNERS: True}, **qsa)
    assert no_purpose.status is Status.SKIPPED and no_purpose.reason_code == "privacy"
    deep = {"is_seed": False, "depth": 2, "provenance": [("domain:example.com", "registrant", "rdap"), ("cnpj:00000000000191", "partner_of", "cnpj_lookup")]}
    assert run_module(SanctionsLists, "person_name:John Doe", FakeHttp(), options=DD, settings={SL.SETTING_DD_PARTNERS: True}, **deep).status is Status.SKIPPED


def test_common_name_person_hit_stays_info():
    install()
    res = run_module(SanctionsLists, "person_name:Jose da Silva", FakeHttp(), options=DD)
    (f,) = res.findings
    assert f.severity.label == "info" and "very common name" in f.data["verdict"] and "context_only" in f.tags
    assert res.attributes["homonym_risk"]["risk"] == "high"


def test_threat_actor_designation_through_the_alias_index(monkeypatch):
    install()
    SL._ALIAS_MEMO["map"] = {"groups": {"lazarus group": ["Lazarus Group", "HIDDEN COBRA", "Diamond Sleet"]},
                             "lookup": {"lazarus group": "lazarus group", "hidden cobra": "lazarus group", "diamond sleet": "lazarus group"}}
    res = run_module(SanctionsLists, "threat_actor:Diamond Sleet", FakeHttp())
    assert res.attributes["sanctions_designation"] == "OFAC designated (2026-11-26) - payments may be prohibited, escalate to legal"
    (f,) = res.findings
    assert f.title == "Possible sanctions designation of the threat actor on OFAC SDN" and f.severity.label == "medium"
    assert f.data["exact_alias"] is True and "Diamond Sleet" in f.data["aliases_used"]
    SL._ALIAS_MEMO.clear()
    both = run_module(SanctionsLists, "threat_actor:ISIL Khorasan", FakeHttp())
    assert both.attributes["sanctions_designation"] == "OFAC/UN designated (2026-11-26, 2019-05-14) - payments may be prohibited, escalate to legal"


def test_alias_index_files_are_read_from_the_frozen_schema(tmp_path, monkeypatch):
    from v3lum.core.datasets import DataStore

    (tmp_path / "actors.json").write_text(json.dumps({"schema": "v3lum.aliases/1", "kind": "threat_actor", "source": "test", "licence": "CC0-1.0",
                                                      "names": {"Example Spider": "Example Group", "Example Group": "Example Group"}}))
    (tmp_path / "malware.json").write_text(json.dumps({"schema": "v3lum.aliases/1", "kind": "malware_family", "names": {"Example Spider": "Nope"}}))
    real = DataStore.bundled_path
    monkeypatch.setattr(DataStore, "bundled_path", staticmethod(lambda name: tmp_path if name == "aliases" else real(name)))
    ctx = make_ctx(SanctionsLists, FakeHttp(), entity="threat_actor:Example Spider")
    assert SL.actor_names(ctx, "Example Spider") == ["Example Spider", "Example Group"]
    assert SL.actor_names(ctx, "Unknown Actor") == ["Unknown Actor"]


def test_health_selftest():
    rt = make_runtime(FakeHttp())
    ctx = make_ctx(SanctionsLists, runtime=rt, entity="company_name:x")
    assert SL._selftest(ctx).status == "dead"
    install()
    assert SL._selftest(ctx).status == "ok"


# ------------------------------------------------------------------ delisting history (cond 12)
LAZARUS_ETH = "0x098B716B8AAF21512996DC57EB0615E2383E2F96"


def sdn_without(*uids: int) -> bytes:
    """The SDN fixture of a later version from which the given entries were removed (delisted)."""
    lines = fx("ofac_sdn_ok.csv").split(b"\r\n")
    kept = [line for line in lines if not any(line.startswith(f"{uid},".encode()) for uid in uids)]
    assert len(kept) == len(lines) - len(uids)
    return b"\r\n".join(kept)


def publish_sdn(raw: bytes, day: int) -> None:
    path = paths.datasets_dir() / SL.DS_OFAC_SDN
    path.write_bytes(raw)
    stamp = datetime(2026, 11, day, 6, 0, tzinfo=timezone.utc).timestamp()
    os.utime(path, (stamp, stamp))


def state_text() -> str:
    path = paths.sub("state") / "sanctions_lists.json"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def test_delisted_wallet_cnpj_and_name_read_formerly_listed():
    install()
    clock = FakeClock("2026-11-26T12:00:00Z")
    first = run_module(SanctionsLists, "eth_address:" + LAZARUS_ETH, FakeHttp(), clock=clock)
    assert first.findings[0].severity.label == "critical" and "sanctions_history" not in first.attributes
    saved = state_text()
    assert '"snapshot_ofac"' in saved and "DOE" not in saved and "DA SILVA" not in saved  # no natural-person name is kept
    assert LAZARUS_ETH.lower() not in saved.lower() and "PETROPARS" not in saved  # identifiers and names are digests
    assert '"LAZARUS GROUP"' in saved  # only the organisations that own a listed identifier keep their name (for the history line)

    publish_sdn(sdn_without(27307, 56752), 27)  # next day: LAZARUS GROUP and PIXWAVE leave the list
    clock = FakeClock("2026-11-27T12:00:00Z")
    wallet = run_module(SanctionsLists, "eth_address:" + LAZARUS_ETH, FakeHttp(), clock=clock)
    assert wallet.status is Status.OK and "sanctioned" not in wallet.attributes
    (f,) = wallet.findings
    assert f.title == "Formerly listed wallet on OFAC SDN - not on the current list"
    assert f.severity.label == "low" and f.confidence_label.value == "confirmed" and "formerly_listed" in f.tags and "sanctions" not in f.tags
    assert f.description.startswith("Formerly listed (2026-11-26): ") and "LAZARUS GROUP" in f.description and "DPRK3" in f.description
    (h,) = wallet.attributes["sanctions_history"]
    assert h == {"list": "OFAC SDN", "match_type": "formerly_wallet", "entry_id": 27307, "listed_name": "LAZARUS GROUP", "programmes": ["DPRK3"],
                 "last_listed": "2026-11-26", "removed_by": "2026-11-27", "line": "formerly listed (2026-11-26)"}
    assert wallet.attributes["sanctions_screening"]["OFAC SDN"]["state"] == "no_record"

    cnpj = run_module(SanctionsLists, "cnpj:50.147.517/0001-86", FakeHttp(), clock=clock)
    (c,) = cnpj.findings
    assert c.title == "Formerly listed CNPJ on OFAC SDN - not on the current list" and c.data["entry_id"] == 56752

    name = run_module(SanctionsLists, "company_name:Pixwave Solucoes de Pagamentos Ltda.", FakeHttp(), clock=clock)
    formerly = [x for x in name.findings if "formerly_listed" in x.tags]
    assert len(formerly) == 1 and formerly[0].severity.label == "info" and formerly[0].confidence_label.value == "possible"
    assert formerly[0].data["line"] == "formerly listed (2026-11-26)" and formerly[0].data["entry_id"] == 56752
    still = run_module(SanctionsLists, "eth_address:0xa0e1c89Ef1a489c9C7dE96311eD5Ce5D32c20E4B", FakeHttp(), clock=clock)
    assert [x.data["match_type"] for x in still.findings] == ["formerly_wallet"]

    publish_sdn(fx("ofac_sdn_ok.csv"), 28)  # re-listed: the history entry goes away and the exact hit is back
    again = run_module(SanctionsLists, "eth_address:" + LAZARUS_ETH, FakeHttp(), clock=FakeClock("2026-11-28T12:00:00Z"))
    assert [x.severity.label for x in again.findings] == ["critical"] and "sanctions_history" not in again.attributes


def test_person_names_have_no_history_and_a_state_failure_never_breaks_screening(monkeypatch):
    from v3lum.core.context import ModuleState, StateError

    install()
    run_module(SanctionsLists, "company_name:Banco do Brasil S.A.", FakeHttp())
    publish_sdn(sdn_without(99000002), 27)
    person = run_module(SanctionsLists, "person_name:Jose da Silva", FakeHttp(), options=DD, clock=FakeClock("2026-11-27T12:00:00Z"))
    assert "sanctions_history" not in person.attributes and all("formerly_listed" not in f.tags for f in person.findings)

    def refuse(self, key, value):
        raise StateError("state of module sanctions_lists would exceed 1048576 bytes")

    SL._HISTORY_MEMO.clear()
    monkeypatch.setattr(ModuleState, "set", refuse)
    publish_sdn(sdn_without(27307), 28)
    res = run_module(SanctionsLists, "eth_address:" + LAZARUS_ETH, FakeHttp(), clock=FakeClock("2026-11-28T12:00:00Z"))
    assert res.status is Status.OK and [f.data["match_type"] for f in res.findings] == ["formerly_wallet"]  # computed, only not saved
    assert any("delisting history not saved" in n for n in res.raw["notes"])


def test_snapshot_and_diff_helpers(ofac):
    snap = SL.list_snapshot(ofac["list"])
    assert set(snap) == {"names", "ids", "meta"} and set(snap["ids"]) == {"wallet", "cnpj"}
    assert snap["meta"]["99000001"]["name"] is None and snap["meta"]["27307"]["name"] == "LAZARUS GROUP"
    assert all(re.fullmatch(r"[a-z2-7]{12}", d) for d in list(snap["names"]) + [d for v in snap["ids"].values() for d in v])
    assert SL.name_digest("Pixwave Soluções de Pagamentos LTDA") == SL.name_digest("PIXWAVE SOLUCOES DE PAGAMENTOS")
    assert SL.wallet_digest(LAZARUS_ETH) == SL.wallet_digest(LAZARUS_ETH.lower())
    prev = {**snap, "date": "2026-11-26"}
    cur = {"names": {}, "ids": {}, "meta": {}}
    rec = SL.delisting_diff(prev, cur, set(), {}, "2026-11-27")
    assert len(rec["names"]) == len(snap["names"]) and len(rec["ids"]["wallet"]) == len(snap["ids"]["wallet"])
    assert SL.delisting_diff(prev, snap, {str(u) for u in ofac["list"].entries}, rec, "2026-11-28") == {"names": {}, "ids": {}}
    monkey = {f"d{i:011d}": {"uid": i, "removed_by": f"2026-11-{1 + i % 28:02d}"} for i in range(SL.HISTORY_MAX_RECORDS + 10)}
    assert len(SL._cap(monkey)) == SL.HISTORY_MAX_RECORDS
