"""actor_alias_index (P295): guarded threat-actor / malware alias index, offline.

The bundled sources (v3lum/data/actor_alias_index/alias_sources.json.gz: 16 MISP galaxy clusters at commit
e0483040 + the Microsoft naming map, 2026-11-26) answer the FC9 regressions. Fixtures in
tests/fixtures/actor_alias_index/ are trimmed real galaxy clusters and the MSTIC map (the conflicting
aliases the guards must stop: 'Andariel', 'LABYRINTH CHOLLIMA', 'TA505', umbrella entries carrying two
MITRE ids), real APTmap and CyCat answers (optional / excluded sources) and a synthetic ETDA export
(ETDA is never fetched until legal records its terms, FC2).
"""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum import paths
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Confidence, Status
from v3lum.modules.cti_framework import actor_alias_index as aai
from v3lum.modules.cti_framework.actor_alias_index import ActorAliasIndex

FIX = FIXTURES / "actor_alias_index"
DATA = Path(aai.__file__).parents[2] / "data"
CHALLENGE = b"<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


@pytest.fixture(autouse=True, scope="module")
def fresh_index():
    """One index for the file (the cache key follows the bundle and the local copies of each test's home)."""
    aai.reset_cache()
    yield
    aai.reset_cache()


def fixture_bytes(name: str) -> bytes:
    return (FIX / name).read_bytes()


def fixture_entries() -> list[dict]:
    entries = []
    for path in sorted(FIX.glob("galaxy_*_slice.json")):
        cluster = path.stem[len("galaxy_"):-len("_slice")].replace("_", "-")
        parsed = aai.parse_galaxy_cluster(path.read_bytes(), cluster)
        assert parsed["marker"] is None and parsed["entries"], path.name
        entries += parsed["entries"]
    return entries + aai.parse_mstic_mapping(fixture_bytes("mstic_mapping_ok.json"))["entries"]


def ent(source, display, synonyms=(), *, ns="actor", mitre=(), malp=(), uuid=None, related=()):
    names = [(display, "primary")] + [(s, "synonym") for s in synonyms]
    return aai._entry(source, uuid, display, names, ns, set(mitre), set(malp), {}, list(related))


def canon(res, ns="actors"):
    return [(c["canonical"], c["mitre_ids"] + c["malpedia_ids"]) for c in res[ns]]


def run(value: str, http: FakeHttp | None = None):
    http = http if http is not None else FakeHttp()
    res = run_module(ActorAliasIndex, value, http)
    assert http.calls == [] and http.unexpected == []  # offline module
    return res


# ------------------------------------------------------------------------------- normalisation (FC5, FC7)
@pytest.mark.parametrize(("typed", "norm"), [("APT 28", "apt28"), ("apt-28", "apt28"), ("APT_28", "apt28"), ("APT‑28", "apt28"), ("Ａｐｔ２８", "apt28")])
def test_normalisation(typed, norm):
    assert aai.normalise_alias(typed) == norm


def test_stop_list_short_tokens_and_bare_ids():
    for alias in ("unknown", "apt", "Group", "ab", "G0007", "s0154", "ransomware", ""):
        assert aai.is_stop_alias(aai.normalise_alias(alias)), alias
    assert not aai.is_stop_alias("apt28")


# ------------------------------------------------------------------------------- parsers
def test_galaxy_parser_reads_ids_from_suffixes_refs_and_synonyms():
    parsed = aai.parse_galaxy_cluster(fixture_bytes("galaxy_mitre_intrusion_set_slice.json"), "mitre-intrusion-set")
    apt28 = next(e for e in parsed["entries"] if e["display"] == "APT28")
    assert apt28["mitre_ids"] == ["G0007"] and apt28["namespace"] == "actor" and apt28["source"] == "misp-galaxy/mitre-intrusion-set"
    assert {"Sofacy", "Sednit"} <= {n["alias"] for n in apt28["names"] if n["how"] == "synonym"}
    pencil = next(e for e in parsed["entries"] if e["display"] == "Stolen Pencil")
    assert pencil["related"][0]["kind"] == "revoked_by"
    malpedia = aai.parse_galaxy_cluster(fixture_bytes("galaxy_malpedia_slice.json"), "malpedia")
    assert {e["display"]: e["malpedia_ids"] for e in malpedia["entries"]}["Grandoreiro"] == ["win.grandoreiro"]
    assert all("authors" not in e for e in parsed["entries"] + malpedia["entries"])


@pytest.mark.parametrize(
    ("raw", "marker"),
    [
        (json.loads(fixture_bytes("galaxy_not_found.http.json"))["body"], "unavailable: 404: Not Found"),
        (CHALLENGE, "blocked: challenge page (never bypassed, A9)"),
        (b"", "error: empty body"),
        (b'{"values": [', "error: malformed JSON"),
        (b'{"name": "x"}', "error: galaxy cluster without 'values'"),
    ],
)
def test_galaxy_parser_markers_never_empty_results(raw, marker):
    parsed = aai.parse_galaxy_cluster(raw, "threat-actor")
    assert parsed["marker"].startswith(marker) and parsed["entries"] == [] and parsed["empty"] is False


def test_mstic_parser():
    parsed = aai.parse_mstic_mapping(fixture_bytes("mstic_mapping_ok.json"))
    assert parsed["marker"] is None and len(parsed["entries"]) == 15
    forest = next(e for e in parsed["entries"] if e["display"] == "Forest Blizzard")
    assert forest["source"] == "mstic" and {"STRONTIUM", "APT28", "FANCY BEAR"} <= {n["alias"] for n in forest["names"]}
    assert next(e for e in parsed["entries"] if e["display"] == "Blue Tsunami")["names"] == [{"alias": "Blue Tsunami", "norm": "bluetsunami", "how": "primary"}]
    assert aai.parse_mstic_mapping(b'{"a": 1}')["marker"] == "error: MSTIC map is not a JSON array"


def test_etda_parser_on_a_synthetic_export_builds_card_links():
    parsed = aai.parse_etda_export(fixture_bytes("etda_groups_synthetic.json"))
    sofacy = parsed["entries"][0]
    assert sofacy["source"] == "etda" and sofacy["display"] == "Sofacy" and {"APT 28", "Fancy Bear"} <= {n["alias"] for n in sofacy["names"]}
    assert sofacy["card_url"] == "https://apt.etda.or.th/cgi-bin/showcard.cgi?u=00000000-0000-4000-8000-000000000028"  # FC7 ?u={uuid}
    assert next(e for e in parsed["entries"] if e["display"] == "Winnti Group")["mitre_ids"] == ["G0044"]


def test_aptmap_and_cycat_parsers():
    apt = aai.parse_aptmap(fixture_bytes("aptmap_slice.json"))
    assert [e["display"] for e in apt["entries"]] == ["APT28", "APT29", "Lazarus Group"] and apt["entries"][0]["coordinates"]
    assert aai.parse_aptmap(fixture_bytes("aptmap_rel_slice.json"))["marker"] == "error: APTmap file is not a FeatureCollection"
    search = aai.parse_cycat_search(fixture_bytes("cycat_search_ok.json"))
    assert len(search["uuids"]) == 9 and aai.parse_cycat_search(fixture_bytes("cycat_search_empty.json"))["empty"] is True
    item = aai.parse_cycat_lookup(fixture_bytes("cycat_lookup_item_ok.json"))
    assert item["type"] == "Item" and item["title"] == "OSINT - APT28 malicious NATO document"
    joined = aai.join_cycat_with_galaxy(search["uuids"], [search["uuids"][0]])
    assert joined["in_galaxy"] == [search["uuids"][0]] and len(joined["external"]) == 8


# ------------------------------------------------------------------------------- FC9 regressions on the fixtures
def test_fixture_regressions_stay_separate_and_bankers_resolve_by_id():
    index = aai.build_alias_index(fixture_entries())
    r = aai.resolve_alias
    assert canon(r(index, "Fancy Bear")) == [("APT28", ["G0007"])] and canon(r(index, "Cozy Bear")) == [("APT29", ["G0016"])]
    assert canon(r(index, "Kimsuky")) == [("Kimsuky", ["G0094"])]  # Stolen Pencil G0086 revoked-by G0094 joins it
    lazarus = r(index, "Lazarus")
    assert lazarus["umbrella"] and canon(lazarus) == [("Lazarus Group", ["G0032"])]
    assert canon(r(index, "Conti"), "malware") == [("Conti", ["S0575"])] and canon(r(index, "Black Basta"), "malware") == [("BlackBasta", ["win.blackbasta"])]
    assert canon(r(index, "Casbaneiro"), "malware") == [("Metamorfo", ["S0455", "win.metamorfo"])]
    assert canon(r(index, "Guildma"), "malware") == [("Astaroth", ["S0373", "win.astaroth"])]
    assert canon(r(index, "Mekotio"), "malware") == [("Mekotio", ["win.mekotio"])]


def test_known_conflicting_aliases_are_reported_never_merged():
    index = aai.build_alias_index(fixture_entries())
    report = "\n".join(index.report)
    assert "AMBIGUOUS alias 'andariel' (actor): synonym of several entries in misp-galaxy/threat-actor" in report
    assert "UMBRELLA entry misp-galaxy/threat-actor 'Lazarus Group' carries G0032, G0082" in report
    andariel = aai.resolve_alias(index, "Andariel")
    assert andariel["status"] == "ambiguous" and "Andariel [G0138]" in andariel["alternatives"]["actor"]
    chollima = aai.resolve_alias(index, "LABYRINTH CHOLLIMA")
    assert chollima["status"] == "ambiguous" and len(chollima["actors"]) >= 4  # never one mega-cluster
    ta505 = aai.resolve_alias(index, "TA505")
    assert ta505["umbrella"] and "verify identifiers" in ta505["note"]
    carbanak = aai.resolve_alias(index, "Carbanak")
    assert set(carbanak["alternatives"]) == {"actor", "malware"}  # namespaces stay separate (FC6)


# ------------------------------------------------------------------------------- guards (FC4, FC5)
def test_name_equality_alone_never_merges():
    index = aai.build_alias_index([ent("src-a", "Shadow Fox"), ent("src-b", "Shadow Fox")])
    assert len(index.clusters) == 2
    res = aai.resolve_alias(index, "shadow fox")
    assert res["status"] == "ok" and len(res["actors"]) == 1 and len(res["same_name"]["actor"]) == 1


def test_a_stop_listed_alias_never_bridges():
    index = aai.build_alias_index([ent("src-a", "Alpha Kitten", ["Unknown"], mitre=["G0001"]), ent("src-b", "Beta Kitten", ["unknown"])])
    assert len(index.clusters) == 2


def test_an_explicit_synonym_with_one_shared_id_merges():
    index = aai.build_alias_index([ent("src-a", "Alpha Kitten", ["Gamma Kitten"], mitre=["G0001"]), ent("src-b", "Gamma Kitten", ["Delta"])])
    assert len(index.clusters) == 1
    card = aai.resolve_alias(index, "Delta")["actors"][0]
    assert card["canonical"] == "Alpha Kitten" and card["mitre_ids"] == ["G0001"] and card["wording"] == "vendor assessment, not identity"


def test_ambiguous_unanchored_and_conflicting_aliases_are_refused():
    ambiguous = aai.build_alias_index([ent("src-a", "One", ["Shared"]), ent("src-a", "Two", ["Shared"]), ent("src-b", "Three", ["Shared"], mitre=["G0003"])])
    assert len(ambiguous.clusters) == 3 and any(line.startswith("AMBIGUOUS alias 'shared'") for line in ambiguous.report)
    unanchored = aai.build_alias_index([ent("src-a", "One", ["Common Alias"]), ent("src-b", "Two", ["Common Alias"])])
    assert len(unanchored.clusters) == 2 and unanchored.report == ["UNANCHORED alias 'commonalias' (actor) in 2 sources without a shared id"]
    conflict = aai.build_alias_index([ent("src-a", "One", ["Shared Name"], mitre=["G0001"]), ent("src-b", "Two", ["Shared Name"], mitre=["G0002"])])
    assert len(conflict.clusters) == 2 and conflict.report == ["CONFLICT alias 'sharedname' (actor) maps to G0001, G0002"]
    refused = aai.build_alias_index([ent("src-a", "One", mitre=["G0001"], malp=["actor:a"]), ent("src-b", "Two", mitre=["G0001"], malp=["actor:b"])])
    assert len(refused.clusters) == 2 and refused.report[0].startswith("REFUSED same id G0001: would join ids")


def test_umbrella_entries_are_overlaps_never_bridges():
    index = aai.build_alias_index([
        ent("src-a", "Umbrella Gang", ["Small One", "Small Two"], mitre=["G0001", "G0002"]),
        ent("src-b", "Small One", mitre=["G0001"]),
        ent("src-c", "Small Two", mitre=["G0002"]),
    ])
    assert len(index.clusters) == 3
    res = aai.resolve_alias(index, "Umbrella Gang")
    card = res["actors"][0]
    assert res["umbrella"] and card["umbrella"] and {o["name"] for o in card["overlaps_with"]} == {"Small One", "Small Two"}


def test_related_overlaps_are_listed_never_merged_and_big_clusters_alarm():
    rel = [{"uuid": "00000000-0000-4000-8000-000000000002", "type": "similar", "kind": "overlaps", "likelihood": None, "confidence": "possible"}]
    index = aai.build_alias_index([ent("src-a", "One", uuid="00000000-0000-4000-8000-000000000001", related=rel),
                                   ent("src-b", "Two", uuid="00000000-0000-4000-8000-000000000002")])
    card = aai.resolve_alias(index, "One")["actors"][0]
    assert len(index.clusters) == 2 and card["overlaps_with"][0]["name"] == "Two" and card["overlaps_with"][0]["kind"] == "overlaps"
    many = [ent(f"src-{i}", f"Member {i}", ["Bridge Name"], mitre=["G0009"] if i == 0 else ()) for i in range(4)]
    alarmed = aai.build_alias_index(many, cluster_alarm_size=3)
    assert len(alarmed.clusters) == 1 and "ALARM cluster 'Member 0' has 4 entries" in alarmed.report


def test_cards_cap_aliases_with_their_sources():
    index = aai.build_alias_index(fixture_entries())
    card = aai.resolve_alias(index, "APT28")["actors"][0]
    assert len(card["aliases"]) == 10 and card["aliases_total"] > 10
    first = card["aliases"][0]
    assert first["statement"] == f"{first['alias']} = APT28 according to {', '.join(first['sources'])}"


# ------------------------------------------------------------------------------- the bundled build (FC1, FC5, FC9)
def test_bundled_regressions():
    r = aai.resolve
    assert canon(r("APT 28")) == [("APT28", ["G0007"])] and canon(r("Midnight Blizzard")) == [("APT29", ["G0016"])]
    assert canon(r("Kimsuky")) == [("Kimsuky", ["G0094"])] and r("Lazarus")["umbrella"] is True
    assert canon(r("Conti"), "malware") == [("Conti", ["S0575"])] and canon(r("Black Basta"), "malware") == [("BlackBasta", ["win.blackbasta"])]
    bankers = {name: canon(r(name), "malware")[0] for name in ("Grandoreiro", "Mekotio", "Casbaneiro", "Guildma", "Astaroth", "Mispadu")}
    assert bankers == {
        "Grandoreiro": ("Grandoreiro", ["win.grandoreiro"]), "Mekotio": ("Mekotio", ["win.mekotio"]), "Casbaneiro": ("Metamorfo", ["S0455", "win.metamorfo"]),
        "Guildma": ("Astaroth", ["S0373", "win.astaroth"]), "Astaroth": ("Astaroth", ["S0373", "win.astaroth"]), "Mispadu": ("Mispadu", ["win.mispadu"]),
    }
    assert r("Grandoreiro")["same_name"]["malware"][0]["mitre_ids"] == ["S0531"]  # same name, compatible ids, unmerged (FC4)


def test_the_p292_hand_off_is_per_namespace():
    assert aai.mitre_ids_for("Sofacy", "actor") == ["G0007"]  # several malware clusters are named Sofacy: the actor answer stands
    assert aai.mitre_ids_for("Sofacy", "malware") == []
    assert aai.mitre_ids_for("Cozy Bear") == ["G0016", "S0046"]
    assert aai.mitre_ids_for("Lazarus") == [] and aai.mitre_ids_for("Carbanak") == []  # umbrella / ambiguous: no id


def test_collision_report_matches_the_reviewed_fingerprint():
    index = aai.get_index()
    reviewed = aai.reviewed_report()
    assert index.report_fingerprint == reviewed["fingerprint"], "collision report changed: review it and update collision_report.reviewed.json"
    assert len(index.report) == reviewed["lines"] and reviewed["galaxy_commit"] == index.meta["galaxy_commit"]
    assert (DATA / "actor_alias_index" / "collision_report.txt").read_text(encoding="utf-8") == "\n".join(index.report) + "\n"
    assert not any(line.startswith("ALARM cluster") and "has" in line for line in index.report)  # no mega-cluster in the build


def test_bundle_is_trimmed_attributed_and_matches_its_notice():
    blob = aai.bundle_path().read_bytes()
    assert len(blob) < 2_500_000
    bundle = json.loads(gzip.decompress(blob))
    assert set(bundle["sources"]) == {f"misp-galaxy/{c}" for c in aai.DEFAULT_GALAXY_CLUSTERS} | {"mstic"}
    keep = set(aai._KEEP)
    assert all(set(e) <= keep for s in bundle["sources"].values() for e in s["entries"])  # no authors, refs or free text
    assert not any(e["source"] in ("etda", "aptmap") for s in bundle["sources"].values() for e in s["entries"])  # FC1-FC3
    notice = json.loads((DATA / "notices" / "misp_galaxy_actor_aliases.json").read_text(encoding="utf-8"))
    assert notice["sha256"] == hashlib.sha256(blob).hexdigest() and "MITRE Corporation" in notice["attribution"]
    mstic = json.loads((DATA / "notices" / "mstic_threat_actor_naming.json").read_text(encoding="utf-8"))
    assert mstic["licence"] == "CC-BY-4.0"


def test_shipped_alias_fragments_are_generated_from_the_index():
    for kind in ("threat_actor", "malware_family"):
        shipped = json.loads((DATA / "aliases" / f"misp_galaxy_{kind}.json").read_text(encoding="utf-8"))
        generated = aai.alias_fragments(aai.get_index(), source_note=shipped["source"])[kind]
        assert generated == shipped, f"{kind} fragment out of date"
    actors = json.loads((DATA / "aliases" / "misp_galaxy_threat_actor.json").read_text(encoding="utf-8"))["names"]
    assert actors["APT 28"] == "APT28" and "Lazarus" not in actors and "Carbanak" not in actors  # umbrella / ambiguous names stay out


def test_no_etda_aptmap_or_cycat_dataset_is_registered():
    from v3lum.core.datasets import DATASETS

    names = [n for n in DATASETS if n.startswith(aai.DATASET_PREFIX)]
    assert sorted(names) == sorted([*aai.GALAXY_DATASETS.values(), aai.MSTIC_DATASET])
    assert all(DATASETS[n]["url"].startswith("https://raw.githubusercontent.com/") and DATASETS[n]["large"] for n in names)


# ------------------------------------------------------------------------------- refresh (FC8)
def mstic_rows(n: int) -> bytes:
    rows = json.loads(fixture_bytes("mstic_mapping_ok.json"))
    rows += [{"Threat actor name": f"Example Tempest {i}", "Other names": "", "Origin/Threat": "Financially motivated"} for i in range(n - len(rows))]
    return json.dumps(rows).encode()


def test_weekly_refresh_replaces_one_bundled_source():
    url = aai.GALAXY_RAW_URL.format(cluster="mitre-intrusion-set")
    rt = make_runtime(FakeHttp().add("GET", url, body=fixture_bytes("galaxy_mitre_intrusion_set_slice.json")))
    assert rt.data.update("actor_alias_index.galaxy.mitre-intrusion-set").status == "updated"
    aai.reset_cache()
    index = aai.get_index()
    assert index.downloaded == ["misp-galaxy/mitre-intrusion-set"] and "downloaded" in index.source_dates["misp-galaxy/mitre-intrusion-set"]
    assert canon(aai.resolve_alias(index, "Fancy Bear")) == [("APT28", ["G0007"])]
    aai.reset_cache()


def test_mstic_refresh_needs_a_plausible_map():
    http = FakeHttp().add("GET", aai.MSTIC_URL, body=mstic_rows(60))
    assert make_runtime(http).data.update(aai.MSTIC_DATASET).status == "updated"
    http = FakeHttp().add("GET", aai.MSTIC_URL, body=fixture_bytes("mstic_mapping_ok.json"))
    result = make_runtime(http).data.update(aai.MSTIC_DATASET)
    assert result.status == "failed" and "only 15 MSTIC rows" in result.reason  # not a full naming map: the good copy stays
    aai.reset_cache()


@pytest.mark.parametrize(
    ("kind", "route"),
    [
        ("404", {"status": 404, "body": b"404: Not Found", "headers": {"content-type": "text/plain"}}),
        ("challenge", {"status": 200, "body": CHALLENGE + b" " * 300, "headers": {"content-type": "text/html"}}),
        ("forbidden", {"status": 403, "body": b"Forbidden"}),
        ("rate limited", {"status": 429, "body": b"slow down"}),
        ("server error", {"status": 503, "body": b"unavailable"}),
        ("timeout", {"error": NetworkError("ReadTimeout contacting raw.githubusercontent.com: timed out")}),
        ("malformed json", {"status": 200, "body": b'{"name": "Threat Actor", values: [' + b" " * 300}),
        ("truncated", {"status": 200, "body": b'{"name": "Threat Actor", "values": [{"value": "APT28"' + b" " * 300}),
        ("no values", {"status": 200, "body": b'{"name": "Threat Actor", "type": "threat-actor", "values": []}' + b" " * 300}),
    ],
)
def test_failed_refreshes_keep_the_bundled_source(kind, route):
    http = FakeHttp().add("GET", aai.GALAXY_RAW_URL.format(cluster="threat-actor"), **route)
    result = make_runtime(http).data.update("actor_alias_index.galaxy.threat-actor")
    assert result.status == "failed" and result.reason, kind
    assert not (paths.datasets_dir() / "actor_alias_index.galaxy.threat-actor").exists()


def test_an_unusable_local_copy_never_replaces_the_bundled_source():
    (paths.datasets_dir() / "actor_alias_index.galaxy.threat-actor").write_bytes(CHALLENGE)
    aai.reset_cache()
    index = aai.get_index()
    assert index.downloaded == [] and canon(aai.resolve_alias(index, "APT28")) == [("APT28", ["G0007"])]
    aai.reset_cache()


# ------------------------------------------------------------------------------- the module (FC6-FC8)
def test_single_answer_card_and_expandable_pivot():
    res = run("threat_actor:Fancy Bear")
    assert res.status is Status.OK and res.attributes["alias_status"] == "ok"
    (card,) = res.attributes["alias_cards"]
    assert card["canonical"] == "APT28" and card["mitre_ids"] == ["G0007"] and card["wording"] == "vendor assessment, not identity"
    finding = next(f for f in res.findings if f.title == "Threat actor alias card")
    assert "'Fancy Bear' resolves to APT28 [G0007] (vendor assessment, not identity)" in finding.description
    assert finding.label is Confidence.PROBABLE
    (pivot,) = res.pivots
    assert pivot.entity.type is T.THREAT_ACTOR and pivot.entity.value == "APT28" and pivot.relation == "alias_of" and pivot.expand
    assert res.attributes["threat_actors"] == ["APT28"] and res.attributes["alias_index_build"]["report_fingerprint"] == aai.reviewed_report()["fingerprint"]


def test_umbrella_name_lists_candidates_and_never_expands():
    res = run("keyword:Lazarus")
    assert "umbrella name" in res.attributes["alias_note"]
    assert all(not p.expand for p in res.pivots) and all(p.confidence_label is Confidence.POSSIBLE for p in res.pivots)
    umbrella = next(f for f in res.findings if f.title == "Ambiguous or umbrella actor/malware name")
    assert "umbrella_name" in umbrella.tags and "Verify identifiers" in umbrella.description


def test_ambiguous_names_return_both_namespaces():
    res = run("malware:Carbanak")
    assert res.attributes["alias_status"] == "ambiguous" and set(res.attributes["alias_alternatives"]) == {"actor", "malware"}
    assert {c["namespace"] for c in res.attributes["alias_cards"]} == {"actor", "malware"}
    both = run("threat_actor:Cozy Bear")
    assert {c["namespace"] for c in both.attributes["alias_cards"]} == {"actor", "malware"} and not any(p.expand for p in both.pivots)


def test_same_name_clusters_are_listed():
    res = run("malware:Grandoreiro")
    assert res.attributes["alias_same_name"] == {"malware": ["Grandoreiro [S0531]"]}
    assert res.attributes["malware_family"] == ["Grandoreiro"]


def test_stop_listed_and_unknown_names_are_empty():
    stop = run("keyword:unknown")
    assert stop.status is Status.EMPTY and "generic or too short alias" in stop.error
    assert run("threat_actor:v3lum unlisted actor name").status is Status.EMPTY


def test_unusable_bundle_is_could_not_verify(monkeypatch, tmp_path):
    broken = tmp_path / "alias_sources.json.gz"
    broken.write_bytes(b"not gzip")
    monkeypatch.setattr(aai, "bundle_path", lambda: broken)
    res = run("threat_actor:APT28")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert aai.resolve("APT28") is None and aai.mitre_ids_for("APT28") == []
    monkeypatch.undo()
    aai.reset_cache()


def test_module_metadata():
    assert ActorAliasIndex.disclosure == "none" and ActorAliasIndex.hosts == () and ActorAliasIndex.terms == "open"
    assert ActorAliasIndex.default_enabled is True and ActorAliasIndex.sources == ("github.actor_alias_index_galaxy", "github.actor_alias_index_mstic")
    assert ActorAliasIndex.accepts == {T.THREAT_ACTOR, T.MALWARE, T.KEYWORD} and ActorAliasIndex.produces == {T.THREAT_ACTOR, T.MALWARE}
