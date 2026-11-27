"""Offline tests of structural_hash_pivots (P351).

MalwareBazaar answers are synthetic (documented fields; reporters and file names neutralised), the
no_results/illegal answers come from the API documentation, the YARAify EICAR and no-results answers
and the 401 are research answers, and the CSCB records are documentation records with example names.
"""

from __future__ import annotations

import copy
import json
import os
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum import paths
from v3lum.core.models import Status
from v3lum.modules.malware_hash import structural_hash_pivots as shp
from v3lum.modules.malware_hash.structural_hash_pivots import StructuralHashPivots

KEY = "abusech-test-auth-key-0123456789"
MB = "https://mb-api.abuse.ch/api/v1/"
YARAIFY = "https://yaraify-api.abuse.ch/api/v1/"
PE_SHA = "7f77b5c7cecc4e05e05fa57efede89d1e031c4152cd8141ddce78ee4eef5b95d"
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
IMPHASH = "cae6529d16a79f2b2590b652488bd8e6"
DOTNET = "f34d5f2d4577ed6d9ceec516c1f5a744"
CSCB_THUMB = "3a5d2552cbce2716d82969a0df06a1bfcebea2c7af7c62453adcd9d48420999a"


def fx(name: str) -> Any:
    return module_fixture("structural_hash_pivots", name)


def forms(http: FakeHttp) -> list[dict[str, str]]:
    out = []
    for call in http.calls:
        if call["url"] == MB:
            body = call["body"].decode() if isinstance(call["body"], bytes) else str(call["body"])
            out.append({k: v[0] for k, v in parse_qs(body).items()})
    return out


def run(entity: str, http: FakeHttp, **kw: Any) -> Any:
    kw.setdefault("keys", {"abusech": KEY})
    return run_module(StructuralHashPivots, entity, http, **kw)


def install_cscb(content: str) -> None:
    path = paths.datasets_dir() / shp.CSCB_DATASET
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    stamp = datetime(2026, 11, 26, 5, 0, tzinfo=timezone.utc).timestamp()
    os.utime(path, (stamp, stamp))


def test_known_sample_chain_yaraify_values_to_grouped_hypotheses() -> None:
    http = (FakeHttp()
            .add("POST", YARAIFY, json=fx("yaraify_pe_synthetic.json"), match_headers={"auth-key": KEY})
            .add("POST", MB, json=fx("mb_tlsh_ok_synthetic.json"), times=1)
            .add("POST", MB, json=fx("mb_imphash_ok_synthetic.json"), times=1)
            .add("POST", MB, json=fx("mb_no_results_docs.json"), times=1))
    res = run(f"sha256:{PE_SHA}", http)
    assert res.status is Status.OK, res.error
    sent = forms(http)
    assert [f["query"] for f in sent] == ["get_tlsh", "get_imphash", "get_dhash_icon"]  # most distinctive first
    assert all(f["limit"] == "50" for f in sent) and sent[1]["imphash"] == IMPHASH
    assert {"imphash", "tlsh", "icon_dhash", "ssdeep"} <= set(res.attributes["similarity_hashes"])
    structural = [p for p in res.pivots if p.relation == "similarity_hash"]
    assert {p.entity.type.value for p in structural} == {"imphash", "tlsh", "icon_dhash", "ssdeep"} and not any(p.expand for p in structural)
    groups = {g["kind"]: g for g in res.attributes["structural_groups"]}
    assert groups["imphash"]["headline"] == "11 samples share this imphash; families AgentTesla (7), Formbook (3); 1 without family"
    assert groups["tlsh"]["headline"].startswith("3 samples share this TLSH; families RedLineStealer (3)")
    assert len(groups["imphash"]["top_samples"]) == 10  # top 10, newest first
    similar = [p for p in res.pivots if p.relation == "similar_to"]
    assert similar and all(not p.expand and 0.3 <= p.confidence <= 0.6 and p.note.startswith("hypothesis:") for p in similar)
    assert PE_SHA not in {p.entity.value for p in similar}  # never the input sample itself
    by_kind = {p.note.split("shares the ")[1].split(" ")[0]: p.confidence for p in similar}
    assert by_kind == {"TLSH": 0.6, "imphash": 0.3}  # mixed families lower the imphash hypothesis
    fams = {p.entity.value.lower() for p in res.pivots if p.relation == "family"}
    assert {"agenttesla", "formbook", "redlinestealer"} <= fams
    assert all(f.severity.label in ("info", "low") and "hypothesis" in f.tags for f in res.findings)
    assert res.raw["groups"] and all("file_name" not in json.dumps(g) for g in res.raw["groups"])
    assert len(http.calls) == 4
    http.assert_hosts_within(StructuralHashPivots)


def test_structural_entity_input_is_one_query() -> None:
    http = FakeHttp().add("POST", MB, json=fx("mb_imphash_ok_synthetic.json"))
    res = run(f"imphash:{IMPHASH.upper()}", http)
    assert res.status is Status.OK
    assert forms(http) == [{"query": "get_imphash", "imphash": IMPHASH, "limit": "50"}]
    assert res.findings[0].title == "Related samples share this imphash (MalwareBazaar)"
    assert res.attributes["structural_groups"][0]["sample_count"] == 12


def test_telfhash_is_queried_in_lower_case() -> None:
    value = "T1" + "AB" * 35
    http = FakeHttp().add("POST", MB, json=fx("mb_no_results_docs.json"))
    res = run(f"telfhash:{value}", http)
    assert res.status is Status.EMPTY and "not" not in res.error.split("no MalwareBazaar")[0]
    assert forms(http)[0]["telfhash"] == value.lower()


def test_stoplisted_dotnet_imphash_is_common_and_never_queried() -> None:
    http = FakeHttp()
    res = run(f"imphash:{DOTNET}", http)
    assert res.status is Status.OK and not http.calls
    assert res.attributes["structural_common"][0]["reason"].startswith("common, not distinctive: .NET")
    assert res.findings[0].severity.label == "info" and "common_value" in res.findings[0].tags
    assert not res.pivots


def test_more_than_ten_unrelated_signatures_is_common_and_not_pivoted() -> None:
    http = FakeHttp().add("POST", MB, json=fx("mb_imphash_generic_synthetic.json"))
    res = run("imphash:" + "ab" * 16, http)
    assert res.status is Status.OK
    reason = res.attributes["structural_common"][0]["reason"]
    m = re.search(r"seen across (\d+) unrelated MalwareBazaar signatures \(> 10\)", reason)
    assert m and int(m.group(1)) > 10  # 14 labels, fewer once P295 aliases fold synonyms
    assert not [p for p in res.pivots if p.relation == "similar_to"]


def test_installer_stub_values_are_common() -> None:
    doc = copy.deepcopy(fx("mb_imphash_ok_synthetic.json"))
    for s in doc["data"]:
        s["tags"] = ["nsis", "exe"]
    res = run("imphash:" + "cd" * 16, FakeHttp().add("POST", MB, json=doc))
    assert "installer/packer stub (nsis)" in res.attributes["structural_common"][0]["reason"]
    assert not [p for p in res.pivots if p.relation == "similar_to"]


def test_no_results_illegal_value_and_could_not_verify_answers() -> None:
    assert run(f"imphash:{IMPHASH}", FakeHttp().add("POST", MB, json=fx("mb_no_results_docs.json"))).status is Status.EMPTY
    res = run(f"imphash:{IMPHASH}", FakeHttp().add("POST", MB, json=fx("mb_illegal_imphash_docs.json")))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    unauth = fx("mb_unauthorized_401.http.json")["response"]
    assert run(f"imphash:{IMPHASH}", FakeHttp().add("POST", MB, status=401, json=unauth["body"])).status is Status.NEEDS_KEY
    assert run(f"imphash:{IMPHASH}", FakeHttp().add("POST", MB, json={"query_status": "unknown_auth_key"})).status is Status.NEEDS_KEY
    assert run(f"imphash:{IMPHASH}", FakeHttp().add("POST", MB, status=429, text="slow down")).status is Status.RATE_LIMITED
    assert run(f"imphash:{IMPHASH}", FakeHttp().add("POST", MB, status=500, text="oops", times=3)).status is Status.ERROR
    assert run(f"imphash:{IMPHASH}", FakeHttp().add("POST", MB, text="<html>", headers={"content-type": "text/plain"})).status is Status.ERROR
    assert run(f"imphash:{IMPHASH}", FakeHttp().add("POST", MB, json={"query_status": "ok", "data": "x"})).status is Status.ERROR


def test_licence_gate_keeps_malwarebazaar_off_but_yaraify_runs() -> None:
    http = FakeHttp().add("POST", YARAIFY, json=fx("yaraify_pe_synthetic.json"))
    res = run(f"sha256:{PE_SHA}", http, allowed_sources={"abusech.yaraify"})
    assert res.status is Status.OK and len(http.calls) == 1  # no MalwareBazaar request at all
    assert "structural_groups" not in res.attributes and res.attributes["similarity_hashes"]["imphash"] == IMPHASH
    http = FakeHttp()
    res = run(f"imphash:{IMPHASH}", http, allowed_sources={"abusech.yaraify"})
    assert res.status is Status.SKIPPED and res.reason_code == "licence" and not http.calls


def test_without_the_auth_key_nothing_is_sent() -> None:
    for entity in (f"sha256:{PE_SHA}", f"imphash:{IMPHASH}", f"code_signing_cert:{CSCB_THUMB}"):
        http = FakeHttp()
        res = run(entity, http, keys={})
        assert res.status is Status.NEEDS_KEY and not http.calls


def test_eicar_has_no_imphash_and_an_unknown_sample_is_an_absence() -> None:
    http = FakeHttp().add("POST", YARAIFY, json=fx("yaraify_eicar.json")).add("POST", MB, json=fx("mb_no_results_docs.json"))
    res = run(f"sha256:{EICAR}", http)
    assert res.status is Status.OK
    assert "imphash" not in res.attributes["similarity_hashes"] and forms(http)[0]["query"] == "get_tlsh"
    res = run(f"sha256:{'1' * 64}", FakeHttp().add("POST", YARAIFY, json=fx("yaraify_no_results.json")))
    assert res.status is Status.EMPTY and "not a verdict" in res.error


def test_certificate_on_the_local_cscb_copy_is_a_high_malicious_signer_finding() -> None:
    install_cscb(fx("cscb_export_synthetic.csv"))
    http = (FakeHttp().add("POST", MB, json=fx("mb_subjectinfo_ok_synthetic.json"), times=1)
            .add("POST", MB, json=fx("mb_issuerinfo_ok_synthetic.json"), times=1))
    res = run(f"code_signing_cert:{CSCB_THUMB.upper()}", http)
    assert res.status is Status.OK, res.error
    f = res.findings[0]
    assert f.title == "Code-signing certificate on the abuse.ch CSCB (malicious signer)" and f.severity.label == "high"
    assert {"malicious", "malicious_signer"} <= set(f.tags)
    assert res.attributes["cscb_listing"]["reason"] == "CobaltStrike" and res.attributes["cscb_listing"]["source"] == "local_copy"
    assert [x["query"] for x in forms(http)] == ["get_subjectinfo", "get_issuerinfo"]
    assert all("limit" not in x for x in forms(http))  # issuer/subject queries take no limit
    assert any(d["name"] == shp.CSCB_DATASET for d in res.datasets)
    hypotheses = [x for x in res.findings if "hypothesis" in x.tags]
    assert hypotheses and all(x.severity.label in ("info", "low") for x in hypotheses)


def test_certificate_via_the_documented_get_cscb_query() -> None:
    http = (FakeHttp().add("POST", MB, json=fx("cscb_api_docs.json"), times=1)
            .add("POST", MB, json=fx("mb_no_results_docs.json"), times=2))
    thumb = "e7241394097402bf9e32c87cada4ba5e0d1e9923f028683713c2f339f6f59fa9"
    res = run(f"code_signing_cert:{thumb}", http)
    assert res.status is Status.OK
    assert res.attributes["cscb_listing"]["source"] == "api" and res.findings[0].severity.label == "high"
    assert forms(http)[0] == {"query": "get_cscb"}
    res = run(f"code_signing_cert:{'ab' * 32}", FakeHttp().add("POST", MB, json=fx("cscb_api_docs.json")))
    assert res.status is Status.EMPTY and "not on the abuse.ch CSCB" in res.error


def test_cscb_listed_signers_of_related_samples_are_low_hypotheses() -> None:
    http = FakeHttp().add("POST", MB, json=fx("mb_issuerinfo_ok_synthetic.json"))
    res = run("imphash:" + "ef" * 16, http)
    certs = [p for p in res.pivots if p.entity.type.value == "code_signing_cert"]
    assert [p.entity.value for p in certs] == [CSCB_THUMB] and not certs[0].expand
    signer = [f for f in res.findings if "malicious_signer" in f.tags]
    assert signer and signer[0].severity.label == "low" and "hypothesis" in signer[0].tags


def test_cscb_parsers() -> None:
    parsed = shp.parse_cscb_csv(fx("cscb_export_synthetic.csv"))
    assert parsed["state"] == "ok" and len(parsed["entries"]) == 3 and parsed["skipped"] == 1
    third = parsed["entries"][2]
    assert third["serial"] == "E3C7CC0950152E9CEEAD4304D01F6C89" and third["subject_cn"] == "Example, Komplekt OOO"
    assert parsed["entries"][1]["serial"] == "B8164F7143E1A313003AB0C834562F"  # leading zero folded
    assert shp.parse_cscb_csv("<!DOCTYPE html><html></html>")["state"] == "error"
    assert shp.parse_cscb_json({"query_status": "unknown_auth_key"})["state"] == "needs_key"
    assert shp.parse_cscb_json([{"serial_number": "x"}])["state"] == "error"


@pytest.mark.parametrize(("form", "body", "url"), [
    ({"query": "get_file", "sha256_hash": PE_SHA}, None, MB),
    ({"query": "get_info", "hash": PE_SHA}, None, MB),
    ({"query": "upload"}, None, MB),
    ({"query": "update", "sha256_hash": PE_SHA, "key": "tags", "value": "x"}, None, MB),
    ({"query": "add_comment", "sha256_hash": PE_SHA, "comment": "x"}, None, MB),
    ({"query": "get_imphash", "imphash": IMPHASH, "limit": "51"}, None, MB),
    ({"query": "get_imphash", "imphash": IMPHASH}, None, MB),
    ({"query": "get_imphash", "imphash": IMPHASH, "limit": "50", "extra": "1"}, None, MB),
    ({"query": "get_issuerinfo", "issuer_cn": "x", "limit": "5"}, None, MB),
    ({"query": "get_cscb", "limit": "5"}, None, MB),
    (None, {"query": "scan"}, YARAIFY),
    (None, {"query": "lookup_hash", "search_term": PE_SHA, "malpedia-token": "x"}, YARAIFY),
    (None, {"query": "get_yara", "search_term": "x"}, YARAIFY),
    ({"query": "get_imphash", "imphash": IMPHASH, "limit": "50"}, None, "https://bazaar.abuse.ch/export/csv/cscb/"),
])
def test_downloads_submissions_and_other_queries_are_never_built(form, body, url) -> None:
    assert shp.request_allowed("POST", url, form=form, json_body=body)


def test_allowed_queries_and_hypothesis_bounds() -> None:
    for kind in ("imphash", "tlsh", "telfhash", "gimphash", "icon_dhash", "issuer_cn", "subject_cn"):
        value = {"imphash": IMPHASH, "tlsh": "T1" + "A" * 70, "telfhash": "t1" + "a" * 70, "gimphash": "a" * 64,
                 "icon_dhash": "e0c0f0f8f0c0e0c0", "issuer_cn": "Example CA", "subject_cn": "Example Ltd"}[kind]
        assert shp.request_allowed("POST", MB, form=shp.mb_form(kind, value)) is None
        for n in (None, 1, 2, 9):
            assert 0.3 <= shp.hypothesis_confidence(kind, n) <= 0.6
    assert shp.request_allowed("GET", MB, form={"query": "get_cscb"})
    assert shp.request_allowed("POST", MB, form={"query": "get_cscb"}) is None
    assert shp.mb_form("authentihash", "a" * 64) is None and shp.mb_form("tlsh", "TNULL") is None
    assert shp.normalize_structural("icon_dhash", "0" * 16) is None and shp.normalize_structural("imphash", "") is None
    assert not hasattr(shp, "tlsh_distance")  # FC6: TLSH comparison waits for a wheel-providing implementation


def test_stoplist_file_is_well_formed() -> None:
    doc = json.loads(shp.STOPLIST_PATH.read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.structural_stoplist/1"
    assert DOTNET in doc["values"]["imphash"]
    assert all(re.fullmatch(r"[a-z0-9-]+", t) for t in doc["installer_packer_tags"])


def test_case_fuzzy_similarity_rule_scores_comparable_digests_with_the_optional_extra(monkeypatch) -> None:
    from types import SimpleNamespace

    from tests.fakes import graph_fixture
    from v3lum.core import correlate
    from v3lum.correlations import p3_g07_2 as rule_pack

    path = "tests/fixtures/rules/p3g072_case_fuzzy_similarity/negative_incomparable_digests.json"
    graph, results, rctx = graph_fixture(path)
    near = "1536:faooayVfn6DZ6VgER1fqdrUG+uD83aASBzO1iMk/:QrhM6yh0586gZpwV/Gx5CrmB"
    other = next(n for n in graph.nodes.values() if n.depth == 1)
    other.attributes["similarity_hashes"] = [({"ssdeep": near}, "virusshare")]
    assert rule_pack.comparable(near, "3072:abc:def") and not rule_pack.comparable(near, "3:a:b")
    monkeypatch.setattr(rule_pack, "_scorer", lambda: None)  # no ppdeep: only identical digests count
    assert not list(correlate.run_rules(graph, results, only={rule_pack.RULE_ID}, rctx=rctx))
    monkeypatch.setattr(rule_pack, "_scorer", lambda: SimpleNamespace(compare=lambda a, b: 88))
    hits = list(correlate.run_rules(graph, results, only={rule_pack.RULE_ID}, rctx=rctx))
    assert len(hits) == 1 and "ssdeep score 88/100" in hits[0].description and hits[0].severity.label == "info"


def test_golden_path_routes_are_complete() -> None:
    """tests/fixtures/acceptance/sha256/structural_hash_pivots.json answers every request of the EICAR run."""
    from tests.fakes import fixture

    doc = fixture("acceptance/sha256/structural_hash_pivots.json")
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "structural_hash_pivots"
    http = FakeHttp()
    for route in doc["routes"]:
        http.add(route["method"], route["url"], status=route["status"], json=route["json"])
    res = run(f"sha256:{EICAR}", http)
    assert res.status is Status.OK and len(http.calls) == len(doc["routes"])
    assert not [f for f in res.findings if f.severity.label != "info"]
