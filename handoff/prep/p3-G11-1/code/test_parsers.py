"""Offline tests for batch p3-G11-1 parsers (P294 d3fend, P296 malpedia).

Run: cd code && python3 -m pytest -q -p no:cacheprovider .
Fixtures are loaded by path; nothing here touches the network.
"""
import hashlib
import io
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import parsers as P  # noqa: E402

FIX = Path(__file__).parent.parent / "fixtures"


def fx(name):
    return (FIX / name).read_bytes()


def fx_json(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def http_fx(name):
    d = fx_json(name)
    return d["status"], d["headers"], d["body"]


@pytest.fixture(scope="module")
def csv_index():
    return P.build_d3fend_index(P.iter_d3fend_mapping_rows(fx("d3fend__mappings_ok.csv")), version="1.6.0",
                                source_sha256="0" * 64)


@pytest.fixture(scope="module")
def slice_index():
    return fx_json("d3fend__index_slice.json")


# ============================================================================== shared helpers

def test_marker_kind():
    assert P.marker_kind("rate_limited: HTTP 429") == "rate_limited"
    assert P.marker_kind("blocked: HTTP 403") == "blocked"
    assert P.marker_kind("nonsense: x") is None
    assert P.marker_kind(None) is None


def test_looks_like_html_only_for_markup_bodies():
    status, headers, body = http_fx("d3fend__api_no_mapping_404.http.json")
    assert P.looks_like_html(body)
    assert not P.looks_like_html('{"x": "<html><body>in a string</body></html>"}')
    assert not P.looks_like_html(b"off_tech_id,def_tech\r\n")
    assert not P.looks_like_html(None)


def test_load_json_defensive():
    assert P.load_json({"a": 1}) == ({"a": 1}, None)
    assert P.load_json(b"\xef\xbb\xbf[1]") == ([1], None)  # UTF-8 BOM
    assert P.load_json(b"")[1] == "error: empty body"
    assert P.load_json("<!DOCTYPE html><html></html>")[1] == "error: HTML instead of JSON"
    obj, marker = P.load_json(fx("malpedia__get_family_truncated_malformed.json"))
    assert obj is None and marker.startswith("error: malformed JSON")
    assert P.load_json(12345)[1] == "error: empty body"


# ============================================================================== P294 d3fend

# ---- FC1: bulk export through the dataset manager, version recorded, matched locally

def test_fc1_dataset_url_is_versioned_and_validated():
    assert P.d3fend_dataset_url() == "https://d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend-full-mappings.csv"
    assert P.d3fend_dataset_url("1.7.0").endswith("/1.7.0/d3fend-full-mappings.csv")
    for bad in ("latest", "1.6", "../1.6.0", "1.6.0/../../x", None):
        with pytest.raises(ValueError):
            P.d3fend_dataset_url(bad)
    # the unversioned 'latest' link answered 404 live and must not be the registered URL
    assert P.D3FEND_LATEST_URL_BROKEN != P.d3fend_dataset_url()


def test_fc1_version_json_records_version_and_dataset_url():
    v = P.parse_d3fend_version(fx("d3fend__version_ok.json"))
    assert v["marker"] is None
    assert v["ontology_version"] == "1.6.0"
    assert v["release_date"] == "2026-08-31T00:12:00Z"
    assert re.fullmatch(r"[0-9a-f]{64}", v["ontology_hash_sha256"])
    assert v["dataset_url"] == P.d3fend_dataset_url("1.6.0")
    assert P.parse_d3fend_version(b'{"ontology_version": "latest"}')["marker"].startswith("error:")
    status, headers, body = http_fx("d3fend__api_html_200.http.json")
    assert P.parse_d3fend_version(body)["marker"] == "error: HTML instead of JSON"


def test_fc1_validator_accepts_real_export_slice():
    assert P.validate_d3fend_mappings_csv(fx("d3fend__mappings_ok.csv")) is None
    # the validator may be fed only the first chunk of a 14.7 MB download
    assert P.validate_d3fend_mappings_csv(fx("d3fend__mappings_ok.csv")[:20000]) is None


@pytest.mark.parametrize("name,expected", [
    ("d3fend__mappings_header_changed.csv", "error: D3FEND export format changed (missing def_tech)"),
    ("d3fend__mappings_no_attack_rows.csv", "error: no ATT&CK rows in D3FEND export (0 < 1)"),
])
def test_fc1_validator_rejects_drift_and_non_attack_exports(name, expected):
    assert P.validate_d3fend_mappings_csv(fx(name)) == expected


def test_fc1_validator_rejects_github_pages_404_and_empty():
    status, headers, body = http_fx("d3fend__mappings_latest_404.http.json")
    assert status == 404
    assert P.validate_d3fend_mappings_csv(body) == "error: HTML instead of CSV"
    assert P.validate_d3fend_mappings_csv(b"") == "error: empty dataset"
    assert P.validate_d3fend_mappings_csv(b"a,b,c\r\n1,2,3\r\n").startswith("error: D3FEND export format changed")


def test_fc1_rows_normalised_sparta_never_matched():
    rows = list(P.iter_d3fend_mapping_rows(fx("d3fend__mappings_ok.csv")))
    assert len(rows) == 63
    fw = {}
    for r in rows:
        fw[r["framework"]] = fw.get(r["framework"], 0) + 1
    assert fw == {"enterprise": 55, "ics": 6, "sparta": 2}
    sparta = [r for r in rows if r["framework"] == "sparta"]
    assert all(r["technique_id"] is None and r["raw_offensive_id"] == "DE-0006" for r in sparta)
    sub = next(r for r in rows if r["technique_id"] == "T1003.001")
    assert sub["parent_id"] == "T1003" and sub["parent_label"] == "OS Credential Dumping"
    top = next(r for r in rows if r["technique_id"] == "T1059")
    assert top["parent_id"] is None and top["d3fend_id"] is None  # the CSV carries no D3-xx ids
    assert top["d3f"] and P.D3F_NS not in top["d3f"]


def test_fc1_streaming_from_file_handle_equals_bytes(tmp_path):
    p = tmp_path / "export.csv"
    p.write_bytes(fx("d3fend__mappings_ok.csv"))
    with open(p, encoding="utf-8", newline="") as fh:
        streamed = list(P.iter_d3fend_mapping_rows(fh))
    assert streamed == list(P.iter_d3fend_mapping_rows(fx("d3fend__mappings_ok.csv")))


def test_fc1_index_records_version_and_is_json_serialisable(csv_index):
    assert csv_index["version"] == "1.6.0" and csv_index["source_sha256"] == "0" * 64
    assert csv_index["rows"] == 63
    assert csv_index["frameworks"] == {"enterprise": 55, "ics": 6, "sparta": 2}
    assert sorted(csv_index["techniques"]) == ["T0855", "T1003.001", "T1003.002", "T1059", "T1078"]
    assert csv_index["children"] == {"T1003": ["T1003.001", "T1003.002"]}
    assert csv_index["techniques"]["T0855"]["framework"] == "ics"
    assert csv_index["techniques"]["T1078"]["offensive_tactics"] == [
        "Initial Access", "Persistence", "Privilege Escalation", "Stealth"]
    json.dumps(csv_index)  # stored by the dataset post-processing step


def test_fc1_index_slice_from_full_export_metadata(slice_index):
    assert slice_index["version"] == "1.6.0"
    assert slice_index["source_sha256"] == P.D3FEND_PINNED_SHA256
    assert slice_index["rows"] == 16249
    assert slice_index["frameworks"] == {"enterprise": 13387, "ics": 2238, "sparta": 624}


def test_fc1_bad_rows_are_skipped_not_raised():
    text = ",".join(P.D3FEND_REQUIRED_COLUMNS) + "\r\n" + "T1059,x\r\n" + '"unterminated\r\n'
    assert list(P.iter_d3fend_mapping_rows(text)) == []
    assert P.build_d3fend_index([None, 3, {"technique_id": None}])["rows"] == 1


# ---- FC2: per-technique API fallback

@pytest.mark.parametrize("raw,expected", [
    ("T1059", "T1059"), ("t1059.001", "T1059.001"), ("T1059/001", "T1059.001"),
    ("https://attack.mitre.org/techniques/T1059/001/", "T1059.001"), (" T0855 ", "T0855"),
    ("DE-0006", None), ("T105", None), ("T1059.1", None), ("T1059; rm -rf /", None),
    ("https://example.com/techniques/T1059/", None), ("", None), (None, None), (1059, None),
])
def test_fc2_normalize_attack_id(raw, expected):
    assert P.normalize_attack_id(raw) == expected


def test_fc2_api_url_sends_only_the_technique_id():
    assert P.d3fend_api_url("t1059.001") == "https://d3fend.mitre.org/api/offensive-technique/attack/T1059.001.json"
    for bad in ("../version", "T1059?x=1", "example.com", "T1059#a", "DE-0006"):
        with pytest.raises(ValueError):
            P.d3fend_api_url(bad)
    assert P.D3FEND_CACHE_TTL == 30 * 86400


def test_fc2_api_ok_parsed():
    r = P.parse_d3fend_api(fx("d3fend__api_ok.json"), technique="t1059")
    assert r["marker"] is None and not r["empty"] and not r["no_mapping"]
    assert r["technique_id"] == "T1059"
    assert r["technique_label"] == "Command and Scripting Interpreter"
    assert r["framework"] == "enterprise"
    assert r["total"] == 15  # 16 bindings, one carries only the offensive side
    assert r["description"] == ("Adversaries may abuse command and script interpreters to execute commands, "
                                "scripts, or binaries.")
    assert r["subtechniques"] == ["T1059.%03d" % i for i in range(1, 14)]
    assert r["link"] == "https://d3fend.mitre.org/offensive-technique/attack/T1059/"
    fe = next(c for c in r["controls"] if c["d3f"] == "FileEncryption")
    assert fe["d3fend_id"] == "D3-FE" and fe["tactic"] == "Harden" and fe["label"] == "File Encryption"


def test_fc2_api_and_dataset_agree_for_t1059(csv_index, slice_index):
    api = {c["d3f"] for c in P.parse_d3fend_api(fx("d3fend__api_ok.json"), technique="T1059")["controls"]}
    assert api == {c["d3f"] for c in csv_index["techniques"]["T1059"]["controls"]}
    assert api == {c["d3f"] for c in slice_index["techniques"]["T1059"]["controls"]}


def test_fc2_api_ranking_uses_index_specificity(slice_index):
    spec = {c["d3f"]: c["specificity"] for c in slice_index["techniques"]["T1059"]["controls"]}
    r = P.parse_d3fend_api(fx("d3fend__api_ok.json"), technique="T1059", specificity=spec)
    assert [c["label"] for c in r["controls"][:5]] == [
        "Dynamic Analysis", "Emulated File Analysis", "Executable Allowlisting", "Executable Denylisting",
        "File Encryption"]


def test_fc2_404_is_no_mapping_never_an_error():
    status, headers, body = http_fx("d3fend__api_no_mapping_404.http.json")
    r = P.parse_d3fend_api(body, status=status, technique="T1611", content_type=headers["content-type"])
    assert r["no_mapping"] is True and r["empty"] is True and r["marker"] is None
    assert r["link"] == "https://d3fend.mitre.org/offensive-technique/attack/T1611/"
    assert P.d3fend_api_marker(404, body, headers["content-type"]) is None


def test_fc2_200_without_countermeasures_is_no_mapping():
    r = P.parse_d3fend_api(fx("d3fend__api_empty_bindings.json"), technique="T1059")
    assert r["no_mapping"] and r["empty"] and r["marker"] is None and r["total"] == 0


def test_fc2_malformed_and_html_answers_are_errors():
    r = P.parse_d3fend_api(fx("d3fend__api_truncated_malformed.json"), technique="T1059")
    assert r["marker"].startswith("error: malformed JSON") and not r["no_mapping"]
    status, headers, body = http_fx("d3fend__api_html_200.http.json")
    r = P.parse_d3fend_api(body, status=status, technique="T1059", content_type=headers["content-type"])
    assert r["marker"] == "error: HTML instead of JSON"
    assert P.parse_d3fend_api(b'{"off_to_def": []}', technique="T1059")["marker"] == "error: unexpected off_to_def shape"
    assert P.parse_d3fend_api(b"[1,2]", technique="T1059")["marker"] == "error: unexpected JSON shape (list)"


@pytest.mark.parametrize("status,headers,expected", [
    (429, {"Retry-After": "120"}, "rate_limited: HTTP 429 (Retry-After 120)"),
    (429, None, "rate_limited: HTTP 429"),
    (403, None, "blocked: HTTP 403"),
    (451, None, "blocked: HTTP 451"),
    (503, None, "error: HTTP 503"),
    (301, None, "error: HTTP 301"),
    ("200", None, "error: no HTTP status"),
])
def test_fc2_api_markers(status, headers, expected):
    # synthetic statuses: not observed live (GitHub Pages/Fastly answered 200/404 only)
    assert P.d3fend_api_marker(status, b"{}", "application/json", headers) == expected
    r = P.parse_d3fend_api(b"{}", status=status, technique="T1059", headers=headers)
    assert r["marker"] == expected and not r["no_mapping"]


def test_fc2_health_check_treats_404_as_moved():
    assert P.d3fend_health_marker(200, fx("d3fend__api_ok.json"), "application/json") is None
    status, headers, body = http_fx("d3fend__api_no_mapping_404.http.json")
    assert P.marker_kind(P.d3fend_health_marker(status, body, headers["content-type"])) == "unavailable"
    assert P.d3fend_health_marker(200, fx("d3fend__api_empty_bindings.json")).startswith("error: D3FEND API returned no")
    assert P.d3fend_health_marker(429, b"") == "rate_limited: HTTP 429"


# ---- FC3: at most 5 controls, 'recommended controls' section, INFO, links

def test_fc3_t1059_recommendations_from_full_export(slice_index):
    r = P.d3fend_recommendations(slice_index, "T1059")
    assert r["section"] == "recommended controls" and r["severity"] == "info"
    assert r["basis"] == "exact" and r["total"] == 15 and r["shown"] == 5 and not r["empty"]
    assert [(c["label"], c["tactic"]) for c in r["controls"]] == [
        ("Dynamic Analysis", "Detect"), ("Emulated File Analysis", "Detect"), ("Executable Allowlisting", "Isolate"),
        ("Executable Denylisting", "Isolate"), ("File Encryption", "Harden")]
    assert r["link"] == "https://d3fend.mitre.org/offensive-technique/attack/T1059/"
    assert r["controls"][0]["link"] == "https://d3fend.mitre.org/technique/d3f:DynamicAnalysis/"
    assert r["controls"][0]["why"] == "analyzes Executable File; technique executes Executable Script"
    assert r["dataset_version"] == "1.6.0"
    assert r["notice"] == P.d3fend_notice()


@pytest.mark.parametrize("tid,basis,basis_ids,total", [
    ("T1059.001", "parent", ["T1059"], 15),
    ("T1003", "subtechniques", ["T1003.001", "T1003.002"], 14),
    ("T1566", "subtechniques", ["T1566.001"], 31),
    ("T0855", "exact", ["T0855"], 3),
    ("https://attack.mitre.org/techniques/T1486/", "exact", ["T1486"], 11),
])
def test_fc3_lookup_basis(slice_index, tid, basis, basis_ids, total):
    r = P.d3fend_recommendations(slice_index, tid)
    assert (r["basis"], r["basis_ids"], r["total"]) == (basis, basis_ids, total)
    assert 1 <= r["shown"] <= P.D3FEND_MAX_CONTROLS


def test_fc3_never_more_than_five_and_tactic_cap(slice_index):
    for tid in list(slice_index["techniques"]) + ["T1003", "T1566"]:
        for limit in (None, 3, 5, 50, -1, "x"):
            r = P.d3fend_recommendations(slice_index, tid, limit=limit)
            assert r["shown"] <= P.D3FEND_MAX_CONTROLS and len(r["controls"]) == r["shown"]
            if limit == 3:
                assert r["shown"] == min(3, r["total"])
        r = P.d3fend_recommendations(slice_index, tid)
        tactics = [c["tactic"] for c in r["controls"]]
        if r["total"] >= 5 and len({c["tactic"] for c in slice_index["techniques"].get(tid, {"controls": []})["controls"]} or {1, 2}) > 1:
            assert max(tactics.count(t) for t in set(tactics)) <= P.D3FEND_MAX_PER_TACTIC


def test_fc3_no_mapping_and_invalid_inputs(slice_index):
    r = P.d3fend_recommendations(slice_index, "T1611")
    assert r["empty"] and r["reason"] == "no mapping" and r["controls"] == [] and r["basis"] is None
    assert r["link"] == "https://d3fend.mitre.org/offensive-technique/attack/T1611/"
    r = P.d3fend_recommendations(slice_index, "DE-0006")
    assert r["empty"] and r["reason"] == "not an ATT&CK technique id" and r["link"] is None
    r = P.d3fend_recommendations(None, "T1059")
    assert r["empty"] and r["reason"] == "no mapping"
    r = P.d3fend_recommendations(slice_index, "T1059.001", rollup=False)
    assert r["empty"] and r["reason"] == "no mapping"


def test_fc3_rank_controls_deterministic_direct_first():
    controls = [
        {"d3f": "B", "label": "B", "tactic": "Isolate", "specificity": 1},
        {"d3f": "A", "label": "A", "tactic": "Detect", "specificity": 9, "direct": True},
        {"d3f": "C", "label": "C", "tactic": "Harden", "specificity": 1},
        {"d3f": "D", "label": "D", "tactic": "Harden", "specificity": 1},
        "junk", {"label": ""},
    ]
    ranked = P.rank_controls(controls)
    assert [c["d3f"] for c in ranked] == ["A", "C", "B", "D"]  # direct, then Harden/Isolate interleaved
    assert P.rank_controls(list(reversed(controls))) == ranked
    assert P.rank_controls(None) == []


def test_fc3_links():
    assert P.d3fend_technique_link("t1003/001") == "https://d3fend.mitre.org/offensive-technique/attack/T1003.001/"
    assert P.d3fend_technique_link("nope") is None
    assert P.d3fend_countermeasure_link("http://d3fend.mitre.org/ontologies/d3fend.owl#FileEncryption") == \
        "https://d3fend.mitre.org/technique/d3f:FileEncryption/"
    assert P.d3fend_countermeasure_link("d3f:Kernel-basedProcessIsolation").endswith("d3f:Kernel-basedProcessIsolation/")
    assert P.d3fend_countermeasure_link("javascript:alert(1)") is None


# ---- FC4: licence notice

def test_fc4_notice_reproduces_copyright_and_licence():
    n = P.d3fend_notice()
    assert "© 2025 The MITRE Corporation." in n
    assert ("hereby grants you a non-exclusive, royalty-free license to use D3FEND for research, development, "
            "and commercial purposes") in n
    assert "reproduce MITRE's copyright designation and this license in any such copy" in n
    assert "https://d3fend.mitre.org/tou/" in n
    assert "ATT&CK®" in n


# ---- FC5: trimmed real fixtures exist (merge gate)

def test_fc5_real_fixtures_present_and_trimmed():
    m = fx_json("MANIFEST.json")
    assert m["d3fend__mappings_ok.csv"]["origin"].startswith("live 2026-11-26")
    assert m["d3fend__api_ok.json"]["origin"].startswith("live 2026-11-26")
    assert len(fx("d3fend__mappings_ok.csv")) < 100_000
    header = fx("d3fend__mappings_ok.csv").split(b"\r\n", 1)[0].decode()
    assert header.split(",")[:3] == ["query_def_tech_label", "top_def_tech_label", "def_tactic_label"]
    assert len(header.split(",")) == 27  # the real export's columns, unchanged


# ============================================================================== P296 malpedia

ALLOWED_SET = [
    ("list_families", None),
    ("find_actor", "apt28"),
    ("find_actor", "Hidden Cobra"),
    ("get_actor", "apt28"),
    ("get_actor", "lazarus_group"),
    ("get_family", "win.emotet"),
    ("get_family", "apk.popr-d30"),
]


# ---- FC2: endpoint allow-list by construction

def test_fc2_module_url_set_is_allow_listed():
    urls = [P.build_malpedia_url(e, v) for e, v in ALLOWED_SET]
    assert urls[0] == "https://malpedia.caad.fkie.fraunhofer.de/api/list/families"
    assert urls[2] == "https://malpedia.caad.fkie.fraunhofer.de/api/find/actor/Hidden%20Cobra"
    assert urls[5] == "https://malpedia.caad.fkie.fraunhofer.de/api/get/family/win.emotet"
    for u in urls:
        assert P.malpedia_url_allowed(u), u
        assert "sample" not in u and "yara" not in u
    assert set(P.MALPEDIA_ENDPOINTS) == {"list_families", "find_actor", "get_actor", "get_family"}


@pytest.mark.parametrize("endpoint", [
    "get_sample", "get_sample_zip", "get_yara", "list_samples", "list_yara", "find_family", "get_families",
    "get_bib", "get_bib_actor", "get_misp", "scan_binary", "scan_yara", "list_actors", "check_apitoken",
    "get_version", "LIST_FAMILIES", None, "",
])
def test_fc2_builder_refuses_other_endpoints(endpoint):
    with pytest.raises(ValueError):
        P.build_malpedia_url(endpoint, "win.emotet")


SHA = "0" * 64
FORBIDDEN_URLS = [
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/sample/%s/raw" % SHA,
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/sample/%s/zip" % SHA,
    "https://malpedia.caad.fkie.fraunhofer.de/api/list/samples/win.emotet",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/win.emotet",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/win.emotet/zip",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/after/2024-01-01/zip",
    "https://malpedia.caad.fkie.fraunhofer.de/api/list/yara",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/misp",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/bib",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/bib/actor/apt28",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/families",
    "https://malpedia.caad.fkie.fraunhofer.de/api/find/family/emotet",
    "https://malpedia.caad.fkie.fraunhofer.de/api/scan/binary",
    "https://malpedia.caad.fkie.fraunhofer.de/api/list/actors",
    "https://malpedia.caad.fkie.fraunhofer.de/api/check/apitoken",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/family/win.emotet/../../get/sample/%s/raw" % SHA,
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/family/win.emotet%2F..%2Fsample",
    "https://malpedia.caad.fkie.fraunhofer.de/api/find/actor/..%2Fget%2Fsample",
    "https://malpedia.caad.fkie.fraunhofer.de/api/find/actor/apt28%00",
    "https://malpedia.caad.fkie.fraunhofer.de//api/list/families",
    "https://malpedia.caad.fkie.fraunhofer.de/api/list/families?format=zip",
    "https://malpedia.caad.fkie.fraunhofer.de/api/list/families#x",
    "https://malpedia.caad.fkie.fraunhofer.de/api/list/families;a=b",
    "http://malpedia.caad.fkie.fraunhofer.de/api/list/families",
    "https://malpedia.caad.fkie.fraunhofer.de:8443/api/list/families",
    "https://user:pw@malpedia.caad.fkie.fraunhofer.de/api/list/families",
    "https://malpedia.caad.fkie.fraunhofer.de.example.com/api/list/families",
    "https://example.com/api/list/families",
    "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet",
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/family/WIN.EMOTET",
    "", None, 42,
]


@pytest.mark.parametrize("url", FORBIDDEN_URLS)
def test_fc2_url_checker_refuses_download_and_tricks(url):
    assert P.malpedia_url_allowed(url) is False


@pytest.mark.parametrize("endpoint,value", [
    ("get_family", "win.emotet/../../get/sample/x"), ("get_family", "WIN.EMOTET"), ("get_family", "emotet"),
    ("get_family", None), ("get_actor", "apt28/../x"), ("get_actor", "APT 28"), ("get_actor", ".."),
    ("find_actor", "a/b"), ("find_actor", "50%"), ("find_actor", "x?y"), ("find_actor", "x#y"),
    ("find_actor", ".."), ("find_actor", "..."), ("find_actor", ""), ("find_actor", "a" * 65),
    ("find_actor", "a\x00b"), ("find_actor", "a\\b"), ("find_actor", 7), ("list_families", "x"),
])
def test_fc2_builder_refuses_unsafe_values(endpoint, value):
    with pytest.raises(ValueError):
        P.build_malpedia_url(endpoint, value)


# ---- FC3: token tier

def test_fc3_token_only_in_authorization_header():
    assert P.malpedia_auth_headers(None) == {}
    assert P.malpedia_auth_headers("") == {}
    assert P.malpedia_auth_headers("abcDEF0123456789") == {"Authorization": "apitoken abcDEF0123456789"}
    for bad in ("short", "has space token", "tok\r\nX-Evil: 1", 12345678):
        with pytest.raises(ValueError):
            P.malpedia_auth_headers(bad)
    for e, v in ALLOWED_SET:  # no URL can carry a token: queries are refused by construction
        assert "?" not in P.build_malpedia_url(e, v)


def test_fc3_token_tier_material_is_amber():
    assert P.malpedia_source_tlp(False) == "clear"
    assert P.malpedia_source_tlp(True) == "amber"
    assert P.malpedia_source_tlp(True, "win.emotet", {"win.emotet"}) == "clear"
    assert P.malpedia_source_tlp(True, "win.secret", {"win.emotet"}) == "amber"
    pub = P.parse_malpedia_family(fx("malpedia__get_family_ok.json"), "win.emotet", max_urls=None)["urls"]
    tok = pub + ["https://www.example.com/2026/private-report"]
    split = P.split_token_tier_urls(pub, tok + ["javascript:alert(1)"])
    assert split["amber"] == ["https://www.example.com/2026/private-report"]
    assert split["clear"] == pub


# ---- FC1: licence

def test_fc1_licence_constants_and_banner():
    assert P.MALPEDIA_LICENCE == "CC BY-NC-SA 3.0"
    assert "CC BY-NC-SA 3.0" in P.MALPEDIA_TOS_LICENCE_QUOTE and "TLP:AMBER" in P.MALPEDIA_TOS_AMBER_QUOTE
    b = P.malpedia_licence_banner("LEGAL-2026-017")
    assert "non-commercial" in b and "LEGAL-2026-017" in b and "Fraunhofer FKIE" in b
    assert "(missing legal_ref)" in P.malpedia_licence_banner(None)
    assert "\n" not in P.malpedia_licence_banner("x\ny")


# ---- FC5: caching and id formats

def test_fc5_cache_and_id_formats():
    assert P.MALPEDIA_CACHE_TTL["list_families"] == 7 * 86400
    assert all(v <= 30 * 86400 for v in P.MALPEDIA_CACHE_TTL.values())  # A10 30-day cache cap
    assert P.is_malpedia_family_id("win.emotet") and P.is_malpedia_family_id("apk.popr-d30")
    assert not P.is_malpedia_family_id("emotet") and not P.is_malpedia_family_id("win.emotet.x")
    assert P.is_malpedia_actor_id("apt28") and P.is_malpedia_actor_id("lazarus_group")
    assert not P.is_malpedia_actor_id("APT28") and not P.is_malpedia_actor_id("a..b")
    assert P.malpedia_actor_slug("Lazarus Group") == "lazarus_group"
    assert P.malpedia_actor_slug("APT28") == "apt28"
    assert P.malpedia_actor_slug("Águila") is None  # non-ASCII: resolve through find/actor
    assert P.malpedia_actor_slug(None) is None


# ---- parsers over the real captures

def test_list_families_ok():
    r = P.parse_malpedia_families_list(fx("malpedia__list_families_ok.json"))
    assert r["marker"] is None and r["count"] == 33 and r["invalid"] == []
    assert r["platforms"]["win"] == 10 and r["platforms"]["osx"] == 3 and len(r["platforms"]) == 18
    assert "win.emotet" in r["ids"] and r["ids"] == sorted(r["ids"])


def test_list_families_defensive():
    r = P.parse_malpedia_families_list(b'["win.emotet", "win.emotet", 3, "BAD ID", null]')
    assert r["ids"] == ["win.emotet"] and r["invalid"] == ["3", "BAD ID", "None"]
    assert P.parse_malpedia_families_list(b'{"a": 1}')["marker"] == "error: unexpected JSON shape (dict)"
    assert P.parse_malpedia_families_list(b"<html><body>down</body></html>")["marker"] == "error: HTML instead of JSON"


def test_find_actor_ok_and_synonyms():
    r = P.parse_malpedia_find_actor(fx("malpedia__find_actor_ok.json"))
    assert not r["empty"] and r["marker"] is None
    a = r["actors"][0]
    assert (a["actor_id"], a["common_name"]) == ("apt28", "APT28")
    assert len(a["synonyms"]) == 38 and "Fancy Bear" in a["synonyms"]
    assert a["mitre_group_ids"] == ["G0007"]
    assert a["link"] == "https://malpedia.caad.fkie.fraunhofer.de/actor/apt28"
    lz = P.parse_malpedia_find_actor(fx("malpedia__find_actor_lazarus_ok.json"))["actors"][0]
    assert lz["actor_id"] == "lazarus_group" and "Hidden Cobra" in lz["synonyms"]
    assert lz["mitre_group_ids"] == ["G0032", "G0082"]


def test_find_actor_empty_and_errors():
    r = P.parse_malpedia_find_actor(fx("malpedia__find_actor_empty.json"))
    assert r == {"actors": [], "empty": True, "marker": None}
    r = P.parse_malpedia_find_actor(b'{"detail":"No Actor matches the given query."}', status=404)
    assert r["empty"] and r["marker"] is None
    r = P.parse_malpedia_find_actor(b'[{"name": "../x", "synonyms": []}, "junk"]')
    assert r["empty"] and r["actors"] == []
    r = P.parse_malpedia_find_actor(b'[{"name": "apt28", "synonyms": {"vendor": "Sofacy"}}]')
    assert r["actors"][0]["synonyms"] == ["Sofacy"]  # documented future shape


def test_get_actor_ok():
    r = P.parse_malpedia_actor(fx("malpedia__get_actor_ok.json"), "apt28", max_refs=3)
    assert r["marker"] is None and not r["empty"] and not r["not_found"]
    assert (r["name"], r["country"], r["attribution_confidence"]) == ("APT28", "RU", 50)
    assert r["uuid"] == "5b4ee3ea-eee3-4c8e-8323-85ae32658754"
    assert r["mitre_group_ids"] == ["G0007"]
    assert r["ref_count"] == 7 and len(r["refs"]) == 3
    assert r["refs"][0] == "https://securelist.com/a-slice-of-2017-sofacy-activity/83930/"  # newest year first
    assert r["cfr"]["suspected-state-sponsor"] == "Russian Federation"
    assert r["cfr"]["target-category"] == ["Government", "Military"]
    assert [f["family_id"] for f in r["families"]] == ["win.xtunnel", "win.xagent", "osx.komplex", "apk.popr-d30"]
    assert r["families"][3]["url_count"] == 0
    assert r["pivots"][0] == ("malware_family", "win.xtunnel") and len(r["pivots"]) == 4
    assert r["related"][0] == {"uuid": "bef4c620-0787-42a8-a96d-b7eb6e85917c", "type": "similar", "likelihood": "likely"}
    assert r["link"] == "https://malpedia.caad.fkie.fraunhofer.de/actor/apt28"


def test_get_family_ok():
    r = P.parse_malpedia_family(fx("malpedia__get_family_ok.json"), "win.emotet", max_urls=4)
    assert r["marker"] is None and not r["empty"]
    assert (r["family_id"], r["platform"], r["common_name"]) == ("win.emotet", "win", "Emotet")
    assert r["alt_names"] == ["Geodo", "Heodo"]
    assert r["attribution"] == ["GOLD CABIN", "MUMMY SPIDER", "Mealybug"]
    assert r["pivots"] == [("threat_actor", "GOLD CABIN"), ("threat_actor", "MUMMY SPIDER"), ("threat_actor", "Mealybug")]
    assert r["updated"] == "2026-10-28" and r["url_count"] == 10 and len(r["urls"]) == 4
    assert r["urls"][0].startswith("https://blog.cyble.com/2022/")
    assert r["link"] == "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
    assert r["description"].startswith("While Emotet historically was a banking malware")


def test_get_family_not_found_is_empty_not_error():
    status, headers, body = http_fx("malpedia__get_family_not_found.http.json")
    r = P.parse_malpedia_family(body, "win.zz_no_such_family_0000", status=status, headers=headers)
    assert r["not_found"] and r["empty"] and r["marker"] is None
    assert P.malpedia_marker(status, body, headers) is None
    r = P.parse_malpedia_actor(b'{"detail":"No Actor matches the given query."}', "zz_none", status=404)
    assert r["not_found"] and r["marker"] is None
    r = P.parse_malpedia_family(b'{"detail":"No Family matches the given query."}', "win.x", status=200)
    assert r["not_found"] and r["marker"] is None  # same detail behind a 200


def test_get_family_malformed():
    r = P.parse_malpedia_family(fx("malpedia__get_family_truncated_malformed.json"), "win.emotet")
    assert r["marker"].startswith("error: malformed JSON") and not r["not_found"]


@pytest.mark.parametrize("status,body,headers,expected", [
    (429, b'{"detail":"Request was throttled. Expected available in 60 seconds."}', {"retry-after": "60"},
     "rate_limited: HTTP 429 (Retry-After 60) - Request was throttled. Expected available in 60 seconds."),
    (401, b'{"detail":"Invalid token."}', None, "error: authentication failed (Invalid token.)"),
    (403, b'{"detail":"You do not have permission to perform this action."}', None,
     "blocked: HTTP 403 (You do not have permission to perform this action.)"),
    (403, b"<html><head><title>403</title></head></html>", None, "blocked: HTTP 403"),
    (502, b"<html><body>Bad Gateway</body></html>", None, "error: HTTP 502"),
    (200, b"<!DOCTYPE html><html><head><title>Maintenance</title></head></html>", None, "error: HTML instead of JSON"),
    (200, b'{"detail":"Something unexpected."}', None, "error: API message in 200 (Something unexpected.)"),
    (404, b"<!DOCTYPE html><html><head><title>Not Found</title></head></html>", None,
     "error: HTTP 404 HTML page (endpoint moved?)"),
    (None, b"", None, "error: no HTTP status"),
])
def test_malpedia_markers(status, body, headers, expected):
    # synthetic bodies in the DRF/nginx shapes: none of these was observed live (5 requests, all 200/404)
    assert P.malpedia_marker(status, body, headers) == expected
    r = P.parse_malpedia_family(body, "win.emotet", status=status, headers=headers)
    assert r["marker"] == expected and not r["not_found"]


# ---- FC4: corporate path via the MISP galaxy cluster (P295) and manual links (P300)

def test_fc4_galaxy_cluster_slice():
    g = P.parse_galaxy_malpedia_cluster(fx("malpedia__galaxy_cluster_slice.json"))
    assert g["marker"] is None and g["version"] == 25472 and g["count"] == 6
    e = g["families"]["win.emotet"]
    assert e["value"] == "Emotet" and e["synonyms"] == ["Geodo", "Heodo"]
    assert e["details_url"] == "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
    assert all("malpedia.caad.fkie.fraunhofer.de" not in u for u in e["refs"]) and len(e["refs"]) == 3
    assert g["by_name"]["casbaneiro"] == ["win.metamorfo"] and g["by_name"]["guildma"] == ["win.astaroth"]
    assert P.parse_galaxy_malpedia_cluster(b'{"type": "threat-actor", "values": []}')["marker"].startswith("error:")
    assert P.parse_galaxy_malpedia_cluster(b"[]")["marker"] == "error: not a MISP galaxy cluster"


@pytest.mark.parametrize("name,expected", [
    ("Emotet", [("win.emotet", "galaxy")]),
    ("geodo", [("win.emotet", "galaxy")]),
    ("Casbaneiro", [("win.metamorfo", "galaxy")]),
    ("Guildma", [("win.astaroth", "galaxy")]),
    ("WIN.MEKOTIO", [("win.mekotio", "id")]),
    ("win.notinlist", [("win.notinlist", "id (not in list/families)")]),
    ("xagent", [("elf.xagent", "list-name"), ("ios.xagent", "list-name"), ("osx.xagent", "list-name"),
                ("win.xagent", "list-name")]),
    ("unknownthing", []),
    ("", []),
])
def test_fc4_resolve_family_without_find_family(name, expected):
    ids = P.parse_malpedia_families_list(fx("malpedia__list_families_ok.json"))["ids"]
    g = P.parse_galaxy_malpedia_cluster(fx("malpedia__galaxy_cluster_slice.json"))
    got = P.resolve_malpedia_family_ids(name, ids, g)
    assert [(x["family_id"], x["how"]) for x in got] == expected


def test_fc4_manual_links():
    assert P.malpedia_family_link("win.emotet") == "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
    assert P.malpedia_actor_link("apt28") == "https://malpedia.caad.fkie.fraunhofer.de/actor/apt28"
    assert P.malpedia_family_link("../x") is None and P.malpedia_actor_link(None) is None


def test_reference_url_ranking_filters_non_http():
    urls = ["javascript:alert(1)", "https://a.example.com/2019/x", "https://b.example.com/2024/05/y",
            "https://b.example.com/2024/05/y", "ftp://c.example.com/2025/z", "https://d.example.com/none", 5]
    assert P.rank_reference_urls(urls) == ["https://b.example.com/2024/05/y", "https://a.example.com/2019/x",
                                           "https://d.example.com/none"]
    assert P.rank_reference_urls(None) == []
    assert P.extract_mitre_group_ids(["g0007", "https://attack.mitre.org/groups/G0032/", "G12345", None]) == [
        "G0007", "G0032"]


# ============================================================================== fixture hygiene

FIXTURE_NAME = re.compile(r"^(d3fend|malpedia)__[a-z0-9_]+(\.http)?\.(json|csv|txt|xml)$")


def test_manifest_matches_every_fixture():
    m = fx_json("MANIFEST.json")
    files = sorted(p.name for p in FIX.iterdir() if p.is_file() and p.name != "MANIFEST.json")
    assert files == sorted(m)
    for name in files:
        data = fx(name)
        assert FIXTURE_NAME.match(name), name
        assert m[name]["sha256"] == hashlib.sha256(data).hexdigest(), name
        assert m[name]["bytes"] == len(data)
        assert m[name]["origin"]


def test_fixtures_carry_no_personal_data_or_secrets():
    email = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    cpf = re.compile(rb"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
    phone = re.compile(rb"\+?55\s?\(?\d{2}\)?\s?9?\d{4}-?\d{4}")
    for p in FIX.iterdir():
        data = p.read_bytes()
        assert not email.search(data), p.name
        assert not cpf.search(data), p.name
        assert not phone.search(data), p.name
        if p.name == "MANIFEST.json":  # describes what was dropped, by key name
            continue
        for bad in (b"library_entries", b'"authors"', b"apitoken", b"Authorization", b"Set-Cookie", b"set-cookie"):
            assert bad not in data, (p.name, bad)


def test_parsers_source_is_ascii_and_stdlib_only():
    src = (Path(__file__).parent / "parsers.py").read_bytes()
    assert all(b < 128 for b in src)
    imports = set(re.findall(rb"^(?:from|import)\s+([a-zA-Z_][\w]*)", src, flags=re.M))
    assert imports <= {b"__future__", b"csv", b"io", b"json", b"re", b"unicodedata", b"urllib"}


def test_never_raises_on_garbage():
    for raw in (None, b"", b"\xff\xfe\x00", "<html><body>x</body></html>", b"[]", b"{}", b"null", 3.5, [], {}):
        P.parse_d3fend_api(raw, technique="T1059")
        P.parse_d3fend_version(raw)
        P.validate_d3fend_mappings_csv(raw if isinstance(raw, (str, bytes)) else b"")
        P.parse_malpedia_families_list(raw)
        P.parse_malpedia_find_actor(raw)
        P.parse_malpedia_actor(raw, "apt28")
        P.parse_malpedia_family(raw, "win.emotet")
        P.parse_galaxy_malpedia_cluster(raw)
    list(P.iter_d3fend_mapping_rows(io.StringIO("\x00\x00")))
