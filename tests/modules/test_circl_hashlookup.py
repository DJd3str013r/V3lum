"""circl_hashlookup (P173): known files, KnownMalicious, hash expansion, bulk lists, status mapping.

Fixtures in tests/fixtures/circl_hashlookup/ (trimmed real answers, research 2026-11-25 and live
2026-11-26 from hashlookup.circl.lu): an NSRL hit (Windows update manifest), the EICAR record that
carries KnownMalicious=malshare.com (parents trimmed 15 -> 4), a package record with children (one
of them EICAR), an NSRL 'BlackArch Linux' record, the documented 404 and 400 answers, a bulk MD5
answer and a live bulk SHA-1 exchange (unknown hashes silently omitted). conflict_nsrl_record.json
is SYNTHETIC (the real layout with the LOLDrivers iobios64.sys hashes and an invented product: no
LOLDrivers hash was found in hashlookup) and pairs with conflict_loldrivers_entry.json (public P268
data, author scrubbed) for the FC4 test.
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import correlate, scoring
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.models import ModuleResult, Status
from v3lum.modules.malware_hash import circl_hashlookup as mod
from v3lum.modules.malware_hash.circl_hashlookup import CirclHashlookup

BASE = "https://hashlookup.circl.lu"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_SHA512 = (
    "cc805d5fab1fd71a4ab352a9c533e65fb2d5b885518f4e565e68847223b8e6b8"
    "5cb48f3afad842726d99239c9e36505c64b0dc9a061d9e507d833277ada336ab"
)
NSRL_MD5 = "8ed4b4ed952526d89899e723f3488de4"
NSRL_SHA1 = "00000079fd7aac9b2f9c988c50750e1f50b27eb5"
IOBIOS_SHA256 = "314a51fcf6e37eb8550a826df085d5c88c43eb1438682f3a6c33632d36956136"


def fx(name):
    return module_fixture(CirclHashlookup, name)


def lookup(kind, value):
    return f"{BASE}/lookup/{kind}/{value}"


def pivots(res, relation=None):
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots if relation is None or p.relation == relation}


def all_text(res):
    return json.dumps({"findings": [f.to_dict() for f in res.findings], "attributes": res.attributes, "error": res.error}, default=str).lower()


# ------------------------------------------------------------------ metadata (FC1, FC4)
def test_contract_metadata():
    cls = CirclHashlookup
    assert (cls.terms, cls.disclosure, cls.provider, cls.sources) == ("open", "third_party", "circl", ("circl.hashlookup",))
    assert cls.hosts == ("hashlookup.circl.lu",)
    assert cls.trust_tier == "trusted" and cls.default_enabled is True
    assert cls.absent_statuses == frozenset({404})
    assert cls.max_tlp.value_str == "amber+strict"  # third-party disclosure: never at TLP:RED (FC4)
    assert cls.max_requests <= 10 and cls.min_interval > 0 and cls.daily_quota and cls.cache_ttl


# ------------------------------------------------------------------ FC2/FC3: NSRL hit, known-good, wording
def test_nsrl_hit_is_a_known_file_and_known_good():
    http = FakeHttp().add("GET", lookup("md5", NSRL_MD5), json=fx("ok_nsrl.json"))
    res = run_module(CirclHashlookup, f"md5:{NSRL_MD5}", http)
    assert res.status is Status.OK
    assert res.attributes["known_good"] is True
    assert res.attributes["known_file"] == "known file: Cumulative Update for Windows Server 2016 for x64 (KB4338817) 1709 (NSRL)"
    assert res.attributes["known_file_set"] == "nsrl"
    assert res.attributes["hashlookup_trust"] == 50
    assert res.attributes["sha1"] == NSRL_SHA1 and "md5" not in res.attributes
    assert res.attributes["file_size"] == 2520
    [finding] = res.findings
    assert finding.title == "Known file (CIRCL hashlookup)" and finding.severity.label == "info"
    assert finding.tags == ["known_good"] and finding.source == "circl.hashlookup"
    assert "clean" not in all_text(res)  # FC3: never 'clean'
    expansion = pivots(res, "same_file")
    assert expansion[("sha1", NSRL_SHA1)].expand is True  # md5 -> sha1 feeds the chain
    http.assert_hosts_within(CirclHashlookup)


def test_eicar_known_malicious_is_a_medium_malware_finding_never_known_good():
    http = FakeHttp().add("GET", lookup("sha256", EICAR_SHA256), json=fx("ok_known_malicious_eicar.json"))
    res = run_module(CirclHashlookup, f"sha256:{EICAR_SHA256}", http)
    assert res.status is Status.OK
    assert "known_good" not in res.attributes
    assert res.attributes["known_malicious"] == ["malshare.com"]
    listed = [f for f in res.findings if f.title == "Listed as known malicious (CIRCL hashlookup)"]
    assert len(listed) == 1
    finding = listed[0]
    assert finding.severity.label == "medium" and "malware" in finding.tags
    assert "malshare.com" in finding.criterion and finding.source == "circl.hashlookup"
    known = [f for f in res.findings if f.title == "Known file (CIRCL hashlookup)"][0]
    assert "known_good" not in known.tags and "not known-good: flagged KnownMalicious (malshare.com)" in known.description
    assert res.attributes["similarity_hashes"] == {
        "ssdeep": "3:a+JraNvsgzsVqSwHq9:tJuOgzsko",
        "tlsh": "T141A022003B0EEE2BA20B00200032E8B00808020E2CE00A3820A020B8C83308803EC228",
    }
    assert "clean" not in all_text(res)
    assert res.redacted_fields == []  # nothing of the record is mistaken for a secret


def test_hash_expansion_and_parents_from_a_sha256_lookup():
    http = FakeHttp().add("GET", lookup("sha256", EICAR_SHA256), json=fx("ok_known_malicious_eicar.json"))
    res = run_module(CirclHashlookup, f"sha256:{EICAR_SHA256}", http)
    same = pivots(res, "same_file")
    assert set(same) == {("md5", EICAR_MD5), ("sha1", EICAR_SHA1), ("sha512", EICAR_SHA512)}
    # from SHA-256 the weaker forms are listed, not re-investigated (no loop over the same file)
    assert all(p.expand is False for p in same.values())
    parents = pivots(res, "contained_in")
    assert len(parents) == 4 and all(p.expand is False for p in parents.values())
    assert ("sha1", "58179b11178eb8fa6658579e2c51b68595d19ba7") in parents  # the snap parent only has a SHA-1
    assert any("metasploit-6.0.25" in p.note for p in parents.values())


def test_md5_lookup_expands_to_the_stronger_forms():
    http = FakeHttp().add("GET", lookup("md5", EICAR_MD5), json=fx("ok_known_malicious_eicar.json"))
    res = run_module(CirclHashlookup, f"md5:{EICAR_MD5}", http)
    same = pivots(res, "same_file")
    assert same[("sha1", EICAR_SHA1)].expand is True
    assert same[("sha256", EICAR_SHA256)].expand is True
    assert same[("sha512", EICAR_SHA512)].expand is False


def test_package_children_are_context_not_a_finding_on_the_package():
    sha1 = "c056b9697ca6137242e8657af6c8129b4fb17133"
    http = FakeHttp().add("GET", lookup("sha1", sha1), json=fx("ok_package_children.json"))
    res = run_module(CirclHashlookup, f"sha1:{sha1}", http)
    assert res.status is Status.OK
    assert res.attributes["known_file_set"] == "os_package" and res.attributes["known_good"] is True
    assert res.attributes["package"] == {"name": "perl-Net-ClamAV-Client", "version": "0.1", "release": "1.20", "arch": "noarch"}
    children = pivots(res, "contains")
    assert len(children) == 4 and all(not p.expand for p in children.values())
    eicar_child = children[("sha256", EICAR_SHA256)]
    assert "listed as known malicious (malshare.com)" in eicar_child.note
    assert not any("malware" in f.tags for f in res.findings)  # a flagged child is context, not a verdict on the package
    known = res.findings[0]
    assert "contains 1 file(s) listed as known malicious: eicar.com (malshare.com)" in known.description
    assert known.data["children_total"] == 17


def test_offensive_security_distribution_is_never_known_good():
    sha1 = "fffffdac1b1b4c513896c805c2c698d9688be69f"
    http = FakeHttp().add("GET", lookup("sha1", sha1), json=fx("ok_sha1_nsrl_blackarch.json"))
    res = run_module(CirclHashlookup, f"sha1:{sha1}", http)
    assert res.status is Status.OK
    assert "known_good" not in res.attributes
    assert res.attributes["dual_use"] == "BlackArch"
    assert res.attributes["known_file"] == "known file: BlackArch Linux 2017.03.01 (NSRL)"
    assert "offensive-security / dual-use software (BlackArch)" in res.findings[0].description


# ------------------------------------------------------------------ FC4: LOLDrivers hash in NSRL keeps the BYOVD finding
def test_loldrivers_hash_present_in_nsrl_keeps_the_byovd_finding():
    http = FakeHttp().add("GET", lookup("sha256", IOBIOS_SHA256), json=fx("conflict_nsrl_record.json"))
    known = run_module(CirclHashlookup, f"sha256:{IOBIOS_SHA256}", http)
    assert known.attributes["known_good"] is True  # the synthetic NSRL record is a known-good candidate
    entry = fx("conflict_loldrivers_entry.json")
    assert entry["KnownVulnerableSamples"][0]["SHA256"] == IOBIOS_SHA256
    entity = Entity.make(T.SHA256, IOBIOS_SHA256)
    lol = ModuleResult(module="lol_datasets", entity=entity)
    byovd = lol.finding(
        "Vulnerable driver listed by LOLDrivers (BYOVD)", "medium", f"{entry['Category']}: {entry['Tags'][0]}",
        confidence="probable", criterion="LOLDrivers category 'vulnerable driver' for this sample", tags=["vulnerable"],
    )
    graph = Graph()
    graph.add_node(entity, seed=True)
    for res in (known, lol):
        graph.add_attributes(entity, res.attributes, res.module)
        for f in res.findings:
            graph.add_finding(f)
    corr = correlate.run_rules(graph, [known, lol], only={"hashlookup_known_file_conflict"})
    assert [c.title for c in corr] == ["conflict: known file vs listed"]
    assert corr[0].severity.label == "info" and byovd.id in corr[0].evidence
    node = graph.get(entity)
    kept = [f for f in node.findings if f.module == "lol_datasets"]
    assert len(kept) == 1 and kept[0].severity.label == "medium" and kept[0].label.value == "probable"  # untouched
    scores = scoring.score(graph, corr)
    assert scores["entities"][entity.key]["score"] > 0  # the BYOVD listing still scores (known_good never suppresses it)


# ------------------------------------------------------------------ absences and could-not-verify (FC1, rule 5)
def test_404_is_not_in_hashlookup_never_clean():
    exchange = fx("not_found_404.http.json")
    md5 = exchange["response"]["body"]["query"]
    http = FakeHttp().add("GET", lookup("md5", md5), status=404, json=exchange["response"]["body"])
    res = run_module(CirclHashlookup, f"md5:{md5}", http)
    assert res.status is Status.EMPTY
    assert not res.findings and not res.pivots and "known_good" not in res.attributes
    assert "not in hashlookup" in res.error


def test_400_malformed_answer_is_an_error():
    exchange = fx("malformed_400.http.json")
    sha1 = "f" * 40
    http = FakeHttp().add("GET", lookup("sha1", sha1), status=400, json=exchange["response"]["body"])
    res = run_module(CirclHashlookup, f"sha1:{sha1}", http)
    assert res.status is Status.ERROR and not res.findings


@pytest.mark.parametrize(
    ("status", "body", "expected", "code"),
    [
        (429, "slow down", Status.RATE_LIMITED, "rate_limited"),
        (403, "Forbidden", Status.BLOCKED, "challenge"),
        (500, "internal error", Status.ERROR, "error"),
        (503, "maintenance", Status.ERROR, "error"),
    ],
)
def test_refusals_and_failures_are_could_not_verify(status, body, expected, code):
    http = FakeHttp().add("GET", lookup("md5", EICAR_MD5), status=status, text=body)
    res = run_module(CirclHashlookup, f"md5:{EICAR_MD5}", http)
    assert res.status is expected and res.reason_code == code
    assert not res.findings


def test_challenge_page_with_200_is_blocked():
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", lookup("md5", EICAR_MD5), status=200, text=page)
    res = run_module(CirclHashlookup, f"md5:{EICAR_MD5}", http)
    assert res.status is Status.BLOCKED


@pytest.mark.parametrize("body", [["not", "an", "object"], {"message": "maintenance"}, {"MD5": "zz"}])
def test_unexpected_answers_are_errors_never_empty(body):
    http = FakeHttp().add("GET", lookup("md5", EICAR_MD5), json=body)
    res = run_module(CirclHashlookup, f"md5:{EICAR_MD5}", http)
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert not res.findings and not res.pivots


def test_malformed_json_is_an_error():
    http = FakeHttp().add("GET", lookup("md5", EICAR_MD5), body=b"{not json", headers={"content-type": "application/json"})
    res = run_module(CirclHashlookup, f"md5:{EICAR_MD5}", http)
    assert res.status is Status.ERROR


def test_answer_for_another_hash_is_never_used():
    http = FakeHttp().add("GET", lookup("md5", NSRL_MD5), json=fx("ok_known_malicious_eicar.json"))
    res = run_module(CirclHashlookup, f"md5:{NSRL_MD5}", http)
    assert res.status is Status.ERROR and not res.findings


def test_sha512_has_no_lookup_endpoint():
    http = FakeHttp()
    res = run_module(CirclHashlookup, f"sha512:{EICAR_SHA512}", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def test_one_request_per_hash():
    http = FakeHttp().add("GET", lookup("md5", NSRL_MD5), json=fx("ok_nsrl.json"))
    res = run_module(CirclHashlookup, f"md5:{NSRL_MD5}", http)
    assert res.requests == 1 and http.urls() == [lookup("md5", NSRL_MD5)]


# ------------------------------------------------------------------ FC1: pasted lists through the bulk API
def test_pasted_list_uses_the_bulk_endpoint_and_triages_known_files():
    text = f"hashes from the ticket:\n{NSRL_MD5}\n{EICAR_MD5.upper()}\n5f6e7266a27a824c5fc5081add52f892\n"
    http = FakeHttp().add("POST", f"{BASE}/bulk/md5", json=fx("bulk_md5.json"))
    res = run_module(CirclHashlookup, Entity.make(T.TEXT, text), http)
    assert res.status is Status.OK
    sent = json.loads(http.calls[0]["body"])
    assert sent == {"hashes": [NSRL_MD5, EICAR_MD5, "5f6e7266a27a824c5fc5081add52f892"]}
    flagged = [f for f in res.findings if f.title == "Known malicious file in the pasted list (CIRCL hashlookup)"]
    assert len(flagged) == 1 and flagged[0].severity.label == "medium" and flagged[0].data["hash"] == EICAR_MD5
    by_value = pivots(res, "mentions")
    assert by_value[("md5", EICAR_MD5)].expand is True
    assert by_value[("md5", NSRL_MD5)].expand is False  # known-good file: listed, not auto-investigated
    assert ("md5", "5f6e7266a27a824c5fc5081add52f892") not in by_value
    summary = [f for f in res.findings if f.title == "Hash list checked against CIRCL hashlookup"][0]
    assert summary.data["checked"] == 3 and summary.data["not_in_hashlookup"] == 1 and summary.data["known_malicious"] == 1
    assert "clean" not in all_text(res)
    http.assert_hosts_within(CirclHashlookup)


def test_bulk_omits_unknown_hashes_which_stay_unknown():
    exchange = fx("bulk_sha1_partial.http.json")
    sent = exchange["request"]["json"]["hashes"]
    http = FakeHttp().add("POST", f"{BASE}/bulk/sha1", json=exchange["response"]["body"])
    res = run_module(CirclHashlookup, Entity.make(T.TEXT, " ".join(sent)), http)
    summary = [f for f in res.findings if f.title == "Hash list checked against CIRCL hashlookup"][0]
    assert summary.data["checked"] == 6 and summary.data["known_files"] == 2 and summary.data["not_in_hashlookup"] == 4


def test_bulk_lists_are_capped_and_marked_partial():
    values = [hashlib.md5(f"v3lum-{i}".encode()).hexdigest() for i in range(250)]
    http = FakeHttp().add("POST", f"{BASE}/bulk/md5", json=[])
    res = run_module(CirclHashlookup, Entity.make(T.TEXT, "\n".join(values)), http)
    assert [len(json.loads(c["body"])["hashes"]) for c in http.calls] == [100, 100]
    assert res.partial and res.stop_reason == "request_cap"
    summary = res.findings[0]
    assert summary.data["not_checked_cap"] == 50 and summary.data["not_in_hashlookup"] == 200


def test_bulk_with_only_sha256_values_is_not_applicable():
    http = FakeHttp()
    res = run_module(CirclHashlookup, Entity.make(T.TEXT, f"see {EICAR_SHA256}"), http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_bulk_rate_limit_and_odd_answers_are_could_not_verify():
    http = FakeHttp().add("POST", f"{BASE}/bulk/md5", status=429, text="slow down")
    res = run_module(CirclHashlookup, Entity.make(T.TEXT, EICAR_MD5), http)
    assert res.status is Status.RATE_LIMITED
    http2 = FakeHttp().add("POST", f"{BASE}/bulk/md5", json="unexpected")
    res2 = run_module(CirclHashlookup, Entity.make(T.TEXT, EICAR_MD5), http2)
    assert res2.status is Status.ERROR and "could not verify" in res2.error


# ------------------------------------------------------------------ read-only path allow-list (rule 7)
@pytest.mark.parametrize(
    ("method", "url", "allowed"),
    [
        ("GET", f"{BASE}/lookup/md5/{EICAR_MD5}", True),
        ("GET", f"{BASE}/lookup/sha256/{EICAR_SHA256}", True),
        ("POST", f"{BASE}/bulk/sha1", True),
        ("GET", f"{BASE}/session/create/v3lum", False),
        ("GET", f"{BASE}/stats/top", False),
        ("GET", f"{BASE}/lookup/sha512/{'a' * 128}", False),
        ("GET", f"{BASE}/lookup/md5/{EICAR_MD5}?session=x", False),
        ("POST", f"{BASE}/lookup/md5/{EICAR_MD5}", False),
        ("GET", f"https://example.com/lookup/md5/{EICAR_MD5}", False),
        ("GET", f"http://hashlookup.circl.lu/lookup/md5/{EICAR_MD5}", False),
    ],
)
def test_request_allow_list(method, url, allowed):
    assert (mod.request_allowed(method, url) is None) is allowed


def test_parsers_tolerate_junk():
    assert mod.parse_record(None) is None and mod.parse_record({"FileName": "x"}) is None
    rec = mod.parse_record({"MD5": EICAR_MD5, "FileSize": "-3", "hashlookup:trust": 900, "KnownMalicious": None, "parents": "x"})
    assert rec["file_size"] is None and rec["trust"] is None and rec["parents"] == [] and rec["has_known_malicious_field"]
    assert mod.parse_ssdeep("4:abc:def") is None  # block size must be 3 * 2^n
    assert mod.normalize_tlsh("TNULL") is None
    assert mod.parse_bulk("md5", [EICAR_MD5], "junk") is None
    assert re.match(r"^known file: ", mod.known_file_label(rec))
