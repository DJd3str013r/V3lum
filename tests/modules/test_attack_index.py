"""attack_index (P292): offline MITRE ATT&CK cards from a compact index built at `v3lum data update` time.

Fixtures in tests/fixtures/attack_index/ are trimmed real ATT&CK v20.1 bundles (attack-stix-data, fetched
2026-11-26: Enterprise/Mobile/ICS slices keeping the objects the regressions need), a CAPEC 3.9 slice, the
index.json and TAXII 2.1 captures (discovery, collections, an envelope, the 400 'Unsupported Media SubType'
answer to a request without the TAXII Accept header and a 404). The bundles are served through FakeHttp to
the dataset manager, whose validate hooks build the compact parts kept in the module state (FC1, FC3).
"""

from __future__ import annotations

import gzip
import io
import json
import time
import tracemalloc
from pathlib import Path

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum.core.context import ModuleState
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Confidence, Status
from v3lum.modules.cti_framework import attack_index as ai
from v3lum.modules.cti_framework.attack_index import AttackIndex

FIX = FIXTURES / "attack_index"
SLICES = {"attack": "enterprise_slice.json", "attack.mobile": "mobile_slice.json", "attack.ics": "ics_slice.json"}
MIN_BYTES = 100_000  # registered min_bytes of the bundle datasets (the real bundles are 5-55 MB)
CHALLENGE = b"<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


@pytest.fixture(autouse=True)
def fresh_cache():
    ai.reset_cache()
    yield
    ai.reset_cache()


def padded(raw: bytes, size: int = MIN_BYTES + 1) -> bytes:
    """A trimmed fixture padded with trailing whitespace (valid JSON) up to the registered min_bytes."""
    return raw + b"\n" * max(0, size - len(raw))


def slice_bytes(name: str) -> bytes:
    return (FIX / name).read_bytes()


def fixture_index() -> dict:
    return ai.index_from_bundles([FIX / SLICES[n] for n in SLICES], built="2026-11-26")


def bundle_route(http: FakeHttp, dataset: str, body: bytes | None = None, **kw) -> FakeHttp:
    url = ai.BUNDLE_URL.format(domain=ai.DATASET_DOMAINS[dataset])
    if body is None and not kw:
        body = padded(slice_bytes(SLICES[dataset]))
    return http.add("GET", url, body=body, **kw)


def synthetic_capec() -> bytes:
    """The CAPEC slice plus 50 synthetic filler patterns (the validator wants >= 50 patterns)."""
    doc = json.loads(slice_bytes("capec_slice.json"))
    for n in range(50):
        doc["objects"].append({
            "type": "attack-pattern", "spec_version": "2.1", "id": f"attack-pattern--00000000-0000-4000-8000-{n:012d}",
            "name": f"Synthetic filler pattern {n}", "x_capec_status": "Draft",
            "external_references": [{"source_name": "capec", "external_id": f"CAPEC-9{n:03d}"}],
        })
    return padded(json.dumps(doc).encode())


def installed_runtime(*datasets: str, capec: bool = False):
    http = FakeHttp()
    for name in datasets:
        bundle_route(http, name)
    if capec:
        http.add("GET", ai.CAPEC_URL, body=synthetic_capec())
    rt = make_runtime(http)
    for name in datasets:
        result = rt.data.update(name)
        assert result.status == "updated", (name, result.reason)
    if capec:
        assert rt.data.update(ai.CAPEC_DATASET).status == "updated"
    return rt


def run(value: str, rt) -> object:
    res = run_module(AttackIndex, value, runtime=rt)
    return res


# ------------------------------------------------------------------------------- stream parser (FC3)
def test_stream_parser_yields_every_object_with_small_chunks():
    raw = slice_bytes("enterprise_slice.json")
    expected = json.loads(raw)["objects"]
    meta: dict = {}
    got = list(ai.iter_bundle_objects(io.BytesIO(raw), chunk_size=1024, meta=meta))
    assert got == expected
    assert meta["type"] == "bundle" and meta["_objects_found"] is True and meta["id"].startswith("bundle--")


def test_stream_parser_reads_gzip_text_and_bom_input():
    raw = slice_bytes("ics_slice.json")
    n = len(json.loads(raw)["objects"])
    assert sum(1 for _ in ai.iter_bundle_objects(gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(raw))))) == n
    assert sum(1 for _ in ai.iter_bundle_objects(io.StringIO(raw.decode("utf-8")))) == n
    assert sum(1 for _ in ai.iter_bundle_objects(io.BytesIO(b"\xef\xbb\xbf" + raw))) == n
    assert list(ai.iter_bundle_objects(io.BytesIO(b'{"type": "bundle", "objects": []}'))) == []


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        (CHALLENGE, "not a JSON object"),
        (b"404: Not Found", "not a JSON object"),
        (b"", "not a JSON object"),
        (b'{"type": "bundle", "objects": [{"type": "x"}, {"type": ', "truncated"),
        (b'{"type": "bundle", "objects": [1 2]}', "expected"),
        (b"\xff\xfe\x00{", "UTF-8"),
    ],
)
def test_stream_parser_rejects_odd_input(raw, why):
    with pytest.raises(ai.StixStreamError, match=why):
        list(ai.iter_bundle_objects(io.BytesIO(raw)))


def test_truncated_fixture_and_oversized_objects_are_errors():
    with pytest.raises(ai.StixStreamError):
        list(ai.iter_bundle_objects(io.BytesIO(slice_bytes("bundle_truncated.json"))))
    big = json.dumps({"type": "bundle", "objects": [{"type": "x-filler", "description": "a" * 50_000}]}).encode()
    with pytest.raises(ai.StixStreamError, match="larger than"):
        list(ai.iter_bundle_objects(io.BytesIO(big), chunk_size=1024, max_object_bytes=10_000))


def write_synthetic_bundle(path: Path, target_bytes: int) -> int:
    """A synthetic ATT&CK-shaped bundle of ``target_bytes``: the real Enterprise slice plus filler data components
    with long descriptions (skipped by the index builder), written in pieces (never held in memory)."""
    head = json.loads(slice_bytes("enterprise_slice.json"))
    written = 0
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        fh.write('{"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000050", "objects": [')
        for i, obj in enumerate(head["objects"]):
            fh.write(("," if i else "") + json.dumps(obj))
        filler = "synthetic filler description " * 30
        while written < target_bytes:
            piece = "," + json.dumps({"type": "x-mitre-data-component", "id": f"x-mitre-data-component--{count:036d}", "name": f"filler {count}",
                                      "description": filler})
            fh.write(piece)
            written += len(piece)
            count += 1
        fh.write("]}")
    return count


@pytest.mark.slow
def test_a_50_mb_bundle_streams_with_bounded_memory(tmp_path):
    path = tmp_path / "enterprise-attack.json"
    write_synthetic_bundle(path, 50 * 1024 * 1024)
    assert path.stat().st_size > 50 * 1024 * 1024
    tracemalloc.start()
    try:
        part = ai.build_part_from_file(path, built="2026-11-26")
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert part["counts"]["techniques"] >= 10 and part["_meta"]["attack_version"] == "20.1"
    assert peak < 12 * 1024 * 1024, f"peak {peak / 2**20:.1f} MB for a 50 MB bundle"  # json.load would need > 150 MB


# ------------------------------------------------------------------------------- ids (FC5)
@pytest.mark.parametrize(
    ("typed", "canonical"),
    [("T1059/001", "T1059.001"), ("t1059-001", "T1059.001"), ("T1059.001", "T1059.001"), (" T1059 ", "T1059"), ("g0007", "G0007"),
     ("ta0005", "TA0005"), ("S9000", "S9000"), ("DET0455", "DET0455"), ("G0007.001", None), ("T10590", None), ("powershell", None), (None, None)],
)
def test_normalise_attack_id(typed, canonical):
    assert ai.normalise_attack_id(typed) == canonical


def test_attack_urls():
    assert ai.attack_url("T1059/001") == "https://attack.mitre.org/techniques/T1059/001/"
    assert ai.attack_url("TA0005") == "https://attack.mitre.org/tactics/TA0005/"
    assert ai.attack_url("DET0455") == "https://attack.mitre.org/detectionstrategies/DET0455/"
    assert ai.attack_url("G0007") == "https://attack.mitre.org/groups/G0007/"


# ------------------------------------------------------------------------------- index (FC4-FC7, FC9 regressions)
def test_slash_form_resolves_to_powershell_execution():
    index = fixture_index()
    out = ai.resolve_attack_id(index, "T1059/001")
    card = out["card"]
    assert out["status"] == "ok" and card["id"] == "T1059.001" and card["name"] == "PowerShell"
    assert card["tactic_names"] == ["Execution"] and card["parent"] == "T1059" and card["is_subtechnique"] is True
    assert card["stix_id"] == "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736"  # official id (FC6)
    assert card["misp_galaxy_tag"] == 'misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"'
    assert len(card["groups"]) == 10 and card["groups_total"] == 12  # at most 10 related (FC7)
    assert card["detections"] == ["DET0455"] and card["mitigations"] == ["M1042", "M1049"]
    assert "reproduced and distributed with the permission of The MITRE Corporation" in card["notice"]


def test_revoked_ids_are_never_rewritten_silently():
    index = fixture_index()
    out = ai.resolve_attack_id(index, "T1656")
    assert out["status"] == "revoked" and out["display"] == "T1656 revoked -> replaced by T1684.001"
    assert out["replacement"]["name"] == "Impersonation"
    assert ai.resolve_attack_id(index, "T1073")["replaced_by"] == "T1574.001"  # chain T1073 -> T1574.002 -> T1574.001
    assert ai.resolve_attack_id(index, "T1086")["replaced_by"] == "T1059.001"
    assert ai.resolve_attack_id(index, "G0118")["replaced_by"] == "G0016"
    assert ai.resolve_attack_id(index, "T0812")["replaced_by"] == "T1694.001"  # ICS v20 revocation


def test_tactics_come_from_the_data_never_hard_coded():
    index = fixture_index()
    assert ai.attack_card(index, "TA0005")["name"] == "Stealth"  # renamed in ATT&CK v20
    assert ai.attack_card(index, "TA0112")["name"] == "Defense Impairment"
    valid_accounts = ai.attack_card(index, "T1078")
    assert valid_accounts["kind"] == "technique"  # the deprecated course-of-action 'T1078' never shadows it
    assert set(valid_accounts["tactic_names"]) == {"Stealth", "Persistence", "Privilege Escalation", "Initial Access"}
    assert [t["name"] for t in index["tactics"]["ics-attack"]][-1] == "Impact"


def test_deprecated_unknown_and_invalid_ids():
    index = fixture_index()
    assert ai.resolve_attack_id(index, "T1064")["status"] == "deprecated"
    assert ai.resolve_attack_id(index, "T9999")["display"] == "T9999 not in ATT&CK 20.1"
    assert ai.resolve_attack_id(index, "PowerShell")["status"] == "invalid"


def test_merge_keeps_one_entry_per_object_and_the_versions_per_domain():
    index = fixture_index()
    assert index["_meta"]["attack_versions"] == {"enterprise-attack": "20.1", "mobile-attack": "20.1", "ics-attack": "20.1"}
    assert index["software"]["S1094"]["name"] == "BRATA" and index["software"]["S1094"]["domains"] == ["mobile-attack"]
    footer = ai.attack_footer(index)
    assert footer.startswith("MITRE ATT&CK v20.1 (Enterprise 20.1, ICS 20.1, Mobile 20.1), index built 2026-11-26.")
    ref = ai.stix_attack_reference(index, "G0007")
    assert ref["id"].startswith("intrusion-set--") and ref["external_references"][0]["external_id"] == "G0007"


def test_version_comparison():
    assert ai.newer_attack_version("20.0", "20.1") and ai.newer_attack_version(None, "20.1")
    assert not ai.newer_attack_version("20.1", "20.1") and not ai.newer_attack_version("20.1", "9.0") and not ai.newer_attack_version("20.1", None)


# ------------------------------------------------------------------------------- CAPEC (low confidence)
def test_capec_links_are_low_confidence_and_follow_revocations():
    index = fixture_index()
    with (FIX / "capec_slice.json").open("rb") as fh:
        capec = ai.parse_capec_objects(ai.iter_bundle_objects(fh))
    assert capec["version"] == "3.9" and capec["patterns"]["CAPEC-106"]["deprecated"] is True
    via = ai.capec_for_technique(capec, index, "T1685")
    assert via == [{"capec": "CAPEC-578", "name": capec["patterns"]["CAPEC-578"]["name"], "cwe": ["CWE-284"], "via": ["T1562.001"], "confidence": "low"}]
    cands = ai.cwe_attack_candidates(capec, index, "284")
    revoked = next(c for c in cands if c["technique"] == "T1562.001")
    assert revoked["status"] == "revoked" and revoked["replaced_by"] == "T1685" and all(c["confidence"] == "low" for c in cands)
    assert any(c["status"] == "unknown" for c in cands)


# ------------------------------------------------------------------------------- version checks (index.json, TAXII)
def test_index_json_versions():
    parsed = ai.parse_stix_index_json(slice_bytes("stix_index_ok.json"))
    enterprise = next(c for c in parsed["collections"] if c["domain"] == "enterprise-attack")
    assert parsed["marker"] is None and enterprise["latest"]["version"] == "20.1" and enterprise["versions"][:2] == ["20.1", "20.0"]
    assert ai.parse_stix_index_json(CHALLENGE)["marker"] == "error: HTML instead of JSON"
    assert ai.parse_stix_index_json(b'{"name": "x"}')["marker"].startswith("error:")
    assert ai.parse_stix_index_json(b'{"collections": [')["marker"].startswith("error: malformed JSON")


def http_capture(name: str) -> tuple[int, object]:
    doc = json.loads(slice_bytes(name))
    return doc["status"], doc["body"]


def test_taxii_discovery_collections_and_envelope():
    disc = ai.parse_taxii_discovery(slice_bytes("taxii_discovery_ok.json"), 200)
    assert disc["marker"] is None and disc["latest"] == "20.1" and "/api/v21/attack-20.1" in disc["api_roots"]
    cols = ai.parse_taxii_collections(slice_bytes("taxii_collections_ok.json"), 200)
    assert {c["domain"] for c in cols["collections"]} == {"enterprise-attack", "mobile-attack", "ics-attack"}
    status, body = http_capture("taxii_collection_object_ok.http.json")
    env = ai.parse_taxii_envelope(body, status)
    assert env["collection_version"]["version"] == "20.1" and env["collection_version"]["name"] == "ICS ATT&CK"


def test_taxii_errors_are_markers_never_empty():
    status, body = http_capture("taxii_unsupported_media_400.http.json")
    marker = ai.parse_taxii_discovery(body, status)["marker"]
    assert marker.startswith("error: TAXII 400 Unsupported Media SubType") and ai.TAXII_ACCEPT in marker
    status, body = http_capture("taxii_collection_not_found_404.http.json")
    assert ai.parse_taxii_envelope(body, status)["marker"] == "unavailable: TAXII 404 Collection Not Found"
    assert ai.taxii_error_marker(429, {"title": "Too Many Requests", "http_status": "429"}).startswith("rate_limited")
    assert ai.taxii_error_marker(403, {"title": "Forbidden", "http_status": 403}).startswith("blocked")
    assert ai.parse_taxii_collections(CHALLENGE, 200)["marker"] == "error: HTML instead of JSON"


def test_taxii_version_check_sends_the_taxii_accept_header():
    seen = []

    def get_json(url, headers):
        seen.append((url, headers))
        return json.loads(slice_bytes("taxii_discovery_ok.json"))

    assert ai.taxii_version_check(get_json, "20.0") == {"latest": "20.1", "newer": True, "marker": None}
    assert seen == [("https://attack-taxii.mitre.org/taxii2/", {"Accept": "application/taxii+json;version=2.1"})]

    def broken(url, headers):
        raise TimeoutError("timed out")

    out = ai.taxii_version_check(broken, "20.1")
    assert out["newer"] is False and out["marker"] == "error: TimeoutError: could not verify"


# ------------------------------------------------------------------------------- dataset hooks (FC1, FC3)
def test_update_builds_the_compact_part_in_the_module_state():
    rt = installed_runtime("attack")
    entry = ModuleState("attack_index").get("part.attack")
    assert entry["format"] == "gzip+base64/json" and entry["sha256"] == rt.data.info("attack").sha256
    part = ai._decode_part(entry["data"])
    assert part["_meta"]["attack_versions"] == {"enterprise-attack": "20.1"} and part["counts"]["techniques"] >= 10


@pytest.mark.parametrize(
    ("kind", "route"),
    [
        ("404", {"status": 404, "body": b"404: Not Found", "headers": {"content-type": "text/plain"}}),
        ("challenge", {"status": 200, "body": padded(CHALLENGE), "headers": {"content-type": "text/html"}}),
        ("forbidden", {"status": 403, "body": b"Forbidden"}),
        ("rate limited", {"status": 429, "body": b"slow down"}),
        ("server error", {"status": 502, "body": b"bad gateway"}),
        ("timeout", {"error": NetworkError("ReadTimeout contacting raw.githubusercontent.com: timed out")}),
        ("truncated", {"status": 200, "body": padded(b'{"type": "bundle", "objects": [{"type": "x"}, {"type": ')}),
        ("wrong domain", {"status": 200, "body": padded(slice_bytes("mobile_slice.json"))}),
        ("short body", {"status": 200, "body": slice_bytes("enterprise_slice.json")}),
    ],
)
def test_failed_updates_keep_nothing_and_report_why(kind, route):
    http = bundle_route(FakeHttp(), "attack", **route)
    result = make_runtime(http).data.update("attack")
    assert result.status == "failed" and result.reason, kind
    assert ModuleState("attack_index").get("part.attack") is None


def test_capec_and_versions_datasets():
    rt = installed_runtime("attack", capec=True)
    assert ModuleState("attack_index").get("part.attack.capec")["sha256"] == rt.data.info("attack.capec").sha256
    http = FakeHttp().add("GET", ai.CAPEC_URL, body=padded(slice_bytes("capec_slice.json")))
    assert make_runtime(http).data.update("attack.capec").status == "failed"  # only 6 patterns: not a CAPEC release
    http = FakeHttp().add("GET", ai.INDEX_JSON_URL, body=slice_bytes("stix_index_ok.json"), headers={"content-type": "application/json"})
    assert make_runtime(http).data.update("attack.versions").status == "updated"
    http = FakeHttp().add("GET", ai.INDEX_JSON_URL, body=padded(CHALLENGE, 300), headers={"content-type": "text/html"})
    assert make_runtime(http).data.update("attack.versions").status == "failed"


def test_registrations():
    from v3lum.core.datasets import DATASETS

    for name, domain in ai.DATASET_DOMAINS.items():
        reg = DATASETS[name]
        assert reg["url"] == f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json"
        assert reg["large"] is True and reg["essential"] is True and reg["terms_class"] == "open" and reg["source"] == ai.SOURCE
    assert DATASETS["attack.capec"]["source"] == ai.SOURCE_CAPEC and DATASETS["attack.capec"]["essential"] is False


# ------------------------------------------------------------------------------- the module
def test_technique_card_with_context_pivots():
    rt = installed_runtime("attack", "attack.mobile", "attack.ics")
    res = run("mitre:T1059.001", rt)  # the core MITRE normaliser refuses 'T1059/001' (core request); the index takes it
    assert res.status is Status.OK
    a = res.attributes
    assert a["attack_id"] == "T1059.001" and a["attack_name"] == "PowerShell" and a["attack_kind"] == "technique"
    assert a["attack_tactics"] == [{"shortname": "execution", "name": "Execution"}] and a["attack_version"] == "20.1"
    assert a["stix_id"] == "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736"
    assert a["misp_galaxy_tag"] == 'misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"'
    assert a["attack_index_built"]["missing_domains"] == [] and a["attack_related_totals"]["groups"] == 12
    assert {"id": "G0007", "name": "APT28"} in a["attack_groups"] and len(a["attack_groups"]) == 10
    assert any("The MITRE Corporation" in n for n in a["data_notices"])
    card = next(f for f in res.findings if f.title == "MITRE ATT&CK technique card")
    assert "tactics (from ATT&CK 20.1): Execution" in card.description and "never attribution" in card.description
    used_by = [p for p in res.pivots if p.relation == "used_by"]
    assert used_by and all(not p.expand and p.confidence_label is Confidence.POSSIBLE for p in used_by)  # context, never attribution (FC7)
    assert {d["name"] for d in res.datasets} >= {"attack", "attack.mobile", "attack.ics"}


def test_revoked_technique_keeps_the_typed_id_and_pivots_to_the_replacement():
    rt = installed_runtime("attack", "attack.mobile", "attack.ics")
    res = run("mitre:T1656", rt)
    assert res.attributes["attack_status"] == "revoked" and res.attributes["attack_replaced_by"] == "T1684.001"
    finding = next(f for f in res.findings if f.title == "ATT&CK id revoked")
    assert finding.description.startswith("T1656 revoked -> replaced by T1684.001")
    (pivot,) = [p for p in res.pivots if p.relation == "replaced_by"]
    assert pivot.entity.value == "T1684.001" and pivot.expand and pivot.confidence_label is Confidence.CONFIRMED


def test_deprecated_and_unknown_techniques():
    rt = installed_runtime("attack", "attack.mobile", "attack.ics")
    assert any(f.title == "ATT&CK id deprecated" for f in run("mitre:T1064", rt).findings)
    unknown = run("mitre:T9999", rt)
    assert unknown.status is Status.EMPTY and "not in ATT&CK 20.1" in unknown.error


def test_unknown_id_with_a_missing_domain_is_could_not_verify():
    rt = installed_runtime("attack")
    res = run("mitre:T0812", rt)  # an ICS id: the ICS index is not built
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "ics-attack" in res.error
    ok = run("mitre:T1059.001", rt)
    assert ok.status is Status.OK and ok.attributes["attack_index_built"]["missing_domains"] == ["ics-attack", "mobile-attack"]


def test_group_names_and_aliases():
    rt = installed_runtime("attack", "attack.mobile", "attack.ics")
    res = run("threat_actor:Fancy Bear", rt)
    assert res.attributes["attack_id"] == "G0007" and res.attributes["misp_galaxy_tag"] == 'misp-galaxy:mitre-intrusion-set="APT28 - G0007"'
    card = next(f for f in res.findings if f.title == "MITRE ATT&CK group card")
    assert card.label is Confidence.CONFIRMED  # matched on an ATT&CK alias
    assert all(not p.expand for p in res.pivots) and {p.relation for p in res.pivots} <= {"uses_technique", "uses_software"}
    assert run("threat_actor:UNC2452", rt).attributes["attack_id"] == "G0016"


def test_names_unknown_to_attack_go_through_the_alias_index():
    rt = installed_runtime("attack", "attack.mobile", "attack.ics")
    res = run("threat_actor:APT-C-20", rt)  # a 360 name: not an ATT&CK alias, P295 maps it to G0007
    assert res.attributes["attack_id"] == "G0007"
    card = next(f for f in res.findings if f.title == "MITRE ATT&CK group card")
    assert "Matched through the actor/malware alias index (P295)" in card.description and card.label is Confidence.PROBABLE


def test_software_names_including_mobile_banking_trojans():
    rt = installed_runtime("attack", "attack.mobile", "attack.ics")
    res = run("malware:Cobalt Strike", rt)
    assert res.attributes["attack_id"] == "S0154" and res.attributes["misp_galaxy_tag"] == 'misp-galaxy:mitre-malware="Cobalt Strike - S0154"'
    brata = run("malware:BRATA", rt)
    assert brata.attributes["attack_id"] == "S1094" and brata.attributes["attack_domains"] == ["mobile-attack"]
    assert run("malware:Xagent", rt).attributes["attack_id"] == "S0023"
    assert run("malware:v3lum-unlisted-family", rt).status is Status.EMPTY


def test_capec_patterns_on_a_technique_card():
    rt = installed_runtime("attack", "attack.mobile", "attack.ics", capec=True)
    res = run("mitre:T1685", rt)
    assert res.attributes["capec_patterns"][0]["capec"] == "CAPEC-578" and res.attributes["capec_patterns"][0]["confidence"] == "low"


def test_not_built_is_unavailable_with_the_update_hint():
    res = run("mitre:T1059.001", make_runtime(FakeHttp()))
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "run v3lum data update attack attack.mobile attack.ics" in res.error


def test_a_lost_part_is_rebuilt_from_the_local_bundle_outside_a_scan_only():
    rt = installed_runtime("attack", "attack.mobile", "attack.ics")
    ModuleState("attack_index").delete("part.attack")
    ai.reset_cache()
    rt.in_scan = True
    during = run("mitre:T1059.001", rt)
    assert during.status is Status.UNAVAILABLE and "the enterprise-attack index is not built" in during.error  # never parsed mid-scan
    rt.in_scan = False
    after = run("mitre:T1059.001", rt)
    assert after.status is Status.OK and ModuleState("attack_index").get("part.attack")["sha256"] == rt.data.info("attack").sha256


def test_a_broken_local_copy_is_not_reparsed_on_every_lookup(monkeypatch):
    rt = installed_runtime("attack", "attack.mobile", "attack.ics", capec=True)
    state = ModuleState("attack_index")
    state.delete("part.attack")
    state.delete("part.attack.capec")
    rt.data.path("attack").write_bytes(b"{" + b" " * 200)  # the local copy rots; its recorded hash stays
    calls = []
    real = ai.build_part_from_file
    monkeypatch.setattr(ai, "build_part_from_file", lambda path, **kw: calls.append(path) or real(path, **kw))
    ai.reset_cache()
    first = run("mitre:T1059.001", rt)
    second = run("mitre:T1059.001", rt)
    assert first.status is Status.UNAVAILABLE and second.status is Status.UNAVAILABLE and len(calls) == 1
    assert state.get("part.attack.capec") is not None  # the CAPEC part was rebuilt from its intact local copy


def test_a_part_built_for_another_copy_is_not_used():
    rt = installed_runtime("attack")
    state = ModuleState("attack_index")
    entry = state.get("part.attack")
    state.set("part.attack", {**entry, "sha256": "0" * 64})
    ai.reset_cache()
    rt.in_scan = True
    res = run("mitre:T1059.001", rt)
    assert res.status is Status.UNAVAILABLE and "index built for another copy" in res.error


def synthetic_full_size_part() -> dict:
    """A part shaped like Enterprise v20.1 (706 techniques, 178 groups, 842 software, ~20k relationships)."""
    objs: list[dict] = [{"type": "x-mitre-collection", "id": "x-mitre-collection--1", "name": "Enterprise ATT&CK", "x_mitre_version": "20.1"}]

    def ref(eid):
        return [{"source_name": "mitre-attack", "external_id": eid, "url": "https://attack.mitre.org/"}]

    for i in range(706):
        objs.append({"type": "attack-pattern", "id": f"attack-pattern--{i}", "name": f"Technique {i}", "external_references": ref(f"T{1000 + i}"),
                     "x_mitre_domains": ["enterprise-attack"], "x_mitre_platforms": ["Windows", "Linux"], "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]})
    for i in range(178):
        objs.append({"type": "intrusion-set", "id": f"intrusion-set--{i}", "name": f"Group {i}", "aliases": [f"Group {i}", f"Alias {i}"], "external_references": ref(f"G{i:04d}"),
                     "x_mitre_domains": ["enterprise-attack"]})
    for i in range(842):
        objs.append({"type": "malware", "id": f"malware--{i}", "name": f"Software {i}", "x_mitre_aliases": [f"Software {i}"], "external_references": ref(f"S{i:04d}"),
                     "x_mitre_domains": ["enterprise-attack"]})
    n = 0
    for g in range(178):
        for k in range(60):
            objs.append({"type": "relationship", "id": f"relationship--{n}", "relationship_type": "uses", "source_ref": f"intrusion-set--{g}", "target_ref": f"attack-pattern--{(g * 7 + k) % 706}"})
            n += 1
    for s in range(842):
        for k in range(12):
            objs.append({"type": "relationship", "id": f"relationship--{n}", "relationship_type": "uses", "source_ref": f"malware--{s}", "target_ref": f"attack-pattern--{(s * 3 + k) % 706}"})
            n += 1
    return ai.build_attack_index(objs, built="2026-11-26")


def test_the_stored_index_loads_in_under_100_ms():
    part = synthetic_full_size_part()
    state = ModuleState("attack_index")
    ai.store_part("attack", part, "a" * 64, state=state)
    best = 1.0
    for _ in range(3):
        ai.reset_cache()
        started = time.process_time()
        index, _capec, problems = ai.load_index(state, {"attack": "a" * 64})
        best = min(best, time.process_time() - started)
        assert index is not None and index["counts"]["techniques"] == 706
    assert best < 0.1, f"cold load took {best * 1000:.0f} ms of CPU"
    assert problems == {"attack.mobile": "not downloaded", "attack.ics": "not downloaded"}
    again, _capec, _problems = ai.load_index(state, {"attack": "a" * 64})
    assert again is index  # cached per process


def test_module_metadata():
    assert AttackIndex.disclosure == "none" and AttackIndex.hosts == () and AttackIndex.terms == "open"
    assert AttackIndex.default_enabled is True and AttackIndex.sources == ("github.attack_index_stix", "github.attack_index_capec")
    assert AttackIndex.accepts == {T.MITRE, T.THREAT_ACTOR, T.MALWARE}
