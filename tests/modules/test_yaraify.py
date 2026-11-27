"""yaraify (P175): lookup_hash only, Auth-Key on every call, statuses, rule profiles, structural hashes.

Fixtures in tests/fixtures/yaraify/: the real EICAR answer of 2026-11-25 (tasks trimmed 10 -> 3; YARA
rule authors that are persons replaced by 'Fulano de Tal' / 'Beltrano da Silva', organisation names
kept), the documented lookup_hash answer of the YARAify API page (unpack_results, non-public 'xxx'
matches; persons scrubbed), the real 'no_results' body, a synthetic 'illegal_search_term' body (the
abuse.ch status family) and a 401 exchange modelled on the sibling abuse.ch APIs (no keyed YARAify
call was made from the research egress: P175 FC2 forbids relying on keyless answers).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.malware_hash import yaraify as mod
from v3lum.modules.malware_hash.yaraify import Yaraify

API = "https://yaraify-api.abuse.ch/api/v1/"
KEY = "test-abusech-auth-key-0123456789abcdef"
KEYS = {"abusech": KEY}
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
DOC_MD5 = "b0bb095dd0ad8b8de1c83b13c38e68dd"


def fx(name):
    return module_fixture(Yaraify, name)


def route(http, **kw):
    return http.add("POST", API, match_headers={"Auth-Key": KEY}, **kw)


# ------------------------------------------------------------------ metadata (FC1, FC2, FC5)
def test_contract_metadata():
    cls = Yaraify
    assert (cls.terms, cls.disclosure, cls.provider, cls.sources) == ("open", "third_party", "abusech", ("abusech.yaraify",))
    assert cls.hosts == ("yaraify-api.abuse.ch",) and cls.requires_keys == ("abusech",)
    assert cls.trust_tier == "trusted" and cls.default_enabled is True
    assert cls.upstream_families == frozenset({"abuse.ch"})  # P171: one abuse.ch family
    assert cls.manual_link == "https://yaraify.abuse.ch/search/"


# ------------------------------------------------------------------ FC1: lookup_hash only
def test_only_lookup_hash_is_ever_built():
    http = route(FakeHttp(), json=fx("no_results.json"))
    run_module(Yaraify, f"sha256:{EICAR_SHA256}", http, keys=KEYS)
    [call] = http.calls
    assert call["method"] == "POST" and call["url"] == API
    assert json.loads(call["body"]) == {"query": "lookup_hash", "search_term": EICAR_SHA256}
    assert "?" not in call["url"]


@pytest.mark.parametrize(
    ("method", "url", "body", "files"),
    [
        ("POST", API, {"query": "scan", "search_term": EICAR_SHA256}, None),
        ("POST", API, {"query": "lookup_hash", "search_term": EICAR_SHA256}, {"file": b"x"}),
        ("POST", API, {"query": "get_file", "sha256_hash": EICAR_SHA256}, None),
        ("POST", API, {"query": "rescan_file", "search_term": EICAR_SHA256}, None),
        ("POST", API, {"query": "list_tasks", "identifier": "x"}, None),
        ("POST", API, {"query": "lookup_hash", "search_term": EICAR_SHA256, "malpedia-token": "t"}, None),
        ("GET", API, {"query": "lookup_hash", "search_term": EICAR_SHA256}, None),
        ("POST", "https://yaraify-api.abuse.ch/api/v1/scan/", {"query": "lookup_hash", "search_term": EICAR_SHA256}, None),
        ("POST", API, {"query": "lookup_hash", "search_term": "a" * 128}, None),
    ],
)
def test_scan_upload_and_other_endpoints_are_refused(method, url, body, files):
    assert mod.request_allowed(method, url, body, files=files) is not None


def test_the_lookup_body_is_allowed():
    assert mod.request_allowed("POST", API, mod.lookup_body(EICAR_SHA256)) is None
    assert mod.lookup_body("a" * 128) is None and mod.lookup_body("not hex") is None
    assert mod.lookup_body("a" * 96) == {"query": "lookup_hash", "search_term": "a" * 96}  # SHA3-384


# ------------------------------------------------------------------ FC2: Auth-Key on every call, NEEDS_KEY without it
def test_without_the_key_needs_key_with_the_manual_link_and_no_request():
    http = FakeHttp()
    res = run_module(Yaraify, f"sha256:{EICAR_SHA256}", http)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert ("YARAify search (manual)", "https://yaraify.abuse.ch/search/") in res.links
    assert http.calls == []  # a keyless answer is never relied upon (terms s.2.1)


def test_401_is_needs_key_and_the_key_never_leaks():
    exchange = fx("unauthorized_401.http.json")
    http = route(FakeHttp(), status=401, json=exchange["response"]["body"])
    rt = make_runtime(http, keys=KEYS)
    res = run_module(Yaraify, f"sha256:{EICAR_SHA256}", runtime=rt)
    assert res.status is Status.NEEDS_KEY and "rejected the Auth-Key" in res.error
    assert ("YARAify search (manual)", "https://yaraify.abuse.ch/search/") in res.links
    assert http.calls[0]["headers"]["Auth-Key"] == KEY  # sent in the header only
    assert_no_secret(KEY, res.to_dict(), res.error, [f.to_dict() for f in res.findings], http.calls[0]["url"])


def test_unauthorized_inside_200_is_needs_key():
    http = route(FakeHttp(), json={"error": "Unauthorized"})
    res = run_module(Yaraify, f"sha256:{EICAR_SHA256}", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY


# ------------------------------------------------------------------ FC3: statuses
def test_no_results_is_unknown_never_clean():
    http = route(FakeHttp(), json=fx("no_results.json"))
    res = run_module(Yaraify, f"md5:{EICAR_MD5}", http, keys=KEYS)
    assert res.status is Status.EMPTY and "unknown to YARAify" in res.error
    assert not res.findings and "clean" not in res.error.lower()


def test_illegal_search_term_is_not_applicable():
    http = route(FakeHttp(), json=fx("illegal_search_term.json"))
    res = run_module(Yaraify, f"md5:{EICAR_MD5}", http, keys=KEYS)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_sha512_is_not_applicable_without_a_request():
    http = FakeHttp()
    res = run_module(Yaraify, "sha512:" + "c" * 128, http, keys=KEYS)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


@pytest.mark.parametrize(
    ("status", "kw", "expected"),
    [
        (429, {"text": "slow down"}, Status.RATE_LIMITED),
        (500, {"text": "error"}, Status.ERROR),
        (502, {"text": "bad gateway"}, Status.ERROR),
        (200, {"json": ["not", "an", "object"]}, Status.ERROR),
        (200, {"json": {"query_status": "unknown_query"}}, Status.ERROR),
        (200, {"body": b"<<not json>>", "headers": {"content-type": "application/json"}}, Status.ERROR),
    ],
)
def test_failures_are_could_not_verify(status, kw, expected):
    http = route(FakeHttp(), status=status, **kw)
    res = run_module(Yaraify, f"sha256:{EICAR_SHA256}", http, keys=KEYS)
    assert res.status is expected and not res.findings


def test_answer_for_another_hash_is_never_used():
    http = route(FakeHttp(), json=fx("ok_eicar.json"))
    res = run_module(Yaraify, f"md5:{DOC_MD5}", http, keys=KEYS)
    assert res.status is Status.ERROR and not res.findings


def test_challenge_page_is_blocked():
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = route(FakeHttp(), status=403, text=page)
    res = run_module(Yaraify, f"sha256:{EICAR_SHA256}", http, keys=KEYS)
    assert res.status is Status.BLOCKED


# ------------------------------------------------------------------ FC4/FC5: EICAR hit
def test_eicar_hit_test_signatures_rules_authors_and_structural_hashes():
    http = route(FakeHttp(), json=fx("ok_eicar.json"))
    res = run_module(Yaraify, f"sha256:{EICAR_SHA256}", http, keys=KEYS)
    assert res.status is Status.OK
    assert res.attributes["yara_rules"] == ["malw_eicar", "Multi_EICAR_ac8f42d6", "SUSP_Just_EICAR", "SUSP_Just_EICAR_RID2C24"]
    assert res.attributes["similarity_hashes"] == {
        "ssdeep": "3:a+JraNvsgzsVqSwHq9:tJuOgzsko",
        "tlsh": "T141A022003B0EEE2BA20B00200032E8B00808020E2CE00A3820A020B8C83308803EC228",
    }  # imphash '' and telfhash/gimphash/dhash_icon null are dropped
    assert res.attributes["submission_count"] == 279
    assert res.attributes["first_seen"] == "2022-06-29T20:19:34Z" and res.attributes["last_seen"] == "2026-10-10T23:15:57Z"
    assert res.attributes["md5"] == EICAR_MD5 and "sha256" not in res.attributes
    assert len(res.attributes["av_signatures"]) == 10
    [finding] = res.findings
    assert finding.title == "AV test-file signatures only (YARAify)" and finding.severity.label == "info"
    assert finding.tags == ["test_file"]
    authors = {r["rule_name"]: r["author"] for r in finding.data["rules"]}
    assert authors["Multi_EICAR_ac8f42d6"] == "Elastic Security" and len(authors) == 4
    assert finding.observed_first and finding.observed_last and finding.source == "abusech.yaraify"
    assert not any(p.entity.type.value == "malware_family" for p in res.pivots)
    raw = json.dumps(res.raw)
    assert "eicar.com.txt" not in raw  # submitter file names are never stored
    http.assert_hosts_within(Yaraify)


# ------------------------------------------------------------------ FC4: rule profiles and the alias index
def test_documented_answer_without_alias_index_gives_low_family_hints(monkeypatch):
    monkeypatch.setattr(mod, "alias_index", dict)
    http = route(FakeHttp(), json=fx("ok_doc_example_unpacked.json"))
    res = run_module(Yaraify, f"md5:{DOC_MD5}", http, keys=KEYS)
    [finding] = res.findings
    assert finding.title == "YARA rules suggest a malware family (YARAify)"
    assert finding.severity.label == "low" and finding.label.value == "possible"
    assert set(res.attributes["family_hints"]) == {"Zegost", "mbrlock", "younglotus"}
    assert res.redacted_fields == []  # nothing of the answer is mistaken for a secret by the sanitizer stage
    assert "malware_family" not in res.attributes
    assert finding.data["nonpublic_matches"] == 1 and "xxx" not in res.attributes["yara_rules"]
    assert len(res.attributes["yara_rules"]) == 5 and finding.data["rules_total"] == 7
    unpacked = [p for p in res.pivots if p.relation == "unpacked_to"]
    assert {p.entity.value for p in unpacked} == {
        "8c7236d27b8dbaffcd64d9b5155e8c416f33102604ab27076d32c321681ae5c3",
        "bd1e271a049045633f995ba1d3a80176b2d2a117543e0972b0a2c5e0519cb9b2",
    }
    assert all(p.expand is False for p in unpacked)
    same = {p.entity.value: p for p in res.pivots if p.relation == "same_file"}
    assert same["de7fa65d5cd5314ba0ce6ab19a7dcd9853639a1152447457de7efb39a9ba1f46"].expand is True  # md5 -> sha256


def test_alias_mapped_family_rules_give_a_medium_family_finding(monkeypatch):
    monkeypatch.setattr(mod, "alias_index", lambda: {"younglotus": "YoungLotus", "zegost": "Zegost"})
    http = route(FakeHttp(), json=fx("ok_doc_example_unpacked.json"))
    res = run_module(Yaraify, f"md5:{DOC_MD5}", http, keys=KEYS)
    [finding] = res.findings
    assert finding.title == "YARA rules identify a known malware family (YARAify)"
    assert finding.severity.label == "medium" and "malware" in finding.tags
    assert res.attributes["malware_family"] == ["YoungLotus", "Zegost"]
    families = {p.entity.value: p for p in res.pivots if p.relation == "family"}
    assert set(families) == {"YoungLotus", "Zegost"} and all(not p.expand for p in families.values())
    assert res.attributes["yara_rules"][:2] == ["MALWARE_Win_Zegost", "win_younglotus_auto"]  # family rules first


def test_generic_rules_alone_are_never_above_low(monkeypatch):
    monkeypatch.setattr(mod, "alias_index", lambda: {"upx": "UPX"})
    answer = {"query_status": "ok", "data": {"metadata": {"sha256_hash": EICAR_SHA256}, "tasks": [{"static_results": [
        {"rule_name": "SUSP_Packer_UPX", "author": "Example Lab"}, {"rule_name": "PUA_Generic_Installer", "author": None},
        {"rule_name": "pe_imphash", "author": None},
    ]}]}}
    http = route(FakeHttp(), json=answer)
    res = run_module(Yaraify, f"sha256:{EICAR_SHA256}", http, keys=KEYS)
    [finding] = res.findings
    assert finding.severity.label == "low" and "weak_signal" in finding.tags and "malware" not in finding.tags
    assert "malware_family" not in res.attributes


@pytest.mark.parametrize(
    ("name", "generic", "token"),
    [
        ("win_emotet_auto", False, "emotet"),
        ("Windows_Trojan_CobaltStrike_663fc95d", False, "CobaltStrike"),
        ("Windows_Generic_Threat_ab12cd34", True, "Threat"),
        ("MALWARE_Win_AgentTesla", False, "AgentTesla"),
        ("HKTL_Mimikatz_Jun20", False, "Mimikatz"),
        ("SUSP_Just_EICAR", True, None),
        ("IsPE64", True, None),
        ("with_urls", True, None),
    ],
)
def test_rule_profiles(name, generic, token):
    profile = mod.rule_profile(name, aliases={})
    assert profile["generic"] is generic and profile["family_hint"] == token and profile["family"] is None


def test_alias_index_reads_v3lum_aliases_fragments(tmp_path, monkeypatch):
    (tmp_path / "families.json").write_text(json.dumps({
        "schema": "v3lum.aliases/1", "kind": "malware_family", "source": "test", "licence": "CC0-1.0",
        "names": {"Win.Emotet": "Emotet", "heodo": "Emotet"},
    }))
    (tmp_path / "actors.json").write_text(json.dumps({"schema": "v3lum.aliases/1", "kind": "threat_actor", "names": {"x": "y"}}))
    (tmp_path / "broken.json").write_text("{")
    monkeypatch.setattr(mod, "ALIASES_DIR", tmp_path)
    mod.alias_index.cache_clear()
    try:
        assert mod.alias_index() == {"winemotet": "Emotet", "heodo": "Emotet"}
        assert mod.rule_profile("win_heodo_auto")["family"] == "Emotet"
    finally:
        mod.alias_index.cache_clear()


def test_parsers_tolerate_junk():
    assert mod.structural_hashes({"imphash": "", "tlsh": "TNULL", "ssdeep": "4:a:b", "gimphash": None}) == {}
    parsed = mod.parse_lookup({"query_status": "ok", "data": {"metadata": "x", "tasks": [None, {"static_results": [None, {"rule_name": None}], "clamav_results": "x"}]}})
    assert parsed["rules"] == [] and parsed["structural"] == {}
    assert mod.classify("x")[0] == "error" and mod.classify({"query_status": "ok"})[0] == "ok"
