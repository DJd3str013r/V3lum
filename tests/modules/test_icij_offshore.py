"""Offline tests for P221 ``icij_offshore`` (local index over the ICIJ bulk CSV, batch p3-G10-1).

The bulk samples in tests/fixtures/icij_offshore/ are trimmed real rows of full-oldb.LATEST.zip plus synthetic
``99xxxxxx`` nodes (README there). Each test builds a small archive from them, installs it where the dataset
manager keeps ``icij`` and builds the index exactly like the dataset validator does.
"""

from __future__ import annotations

import io
import shutil
import sqlite3
import zipfile
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import datasets
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.modules.company_org import icij_offshore as icij
from v3lum.modules.company_org import offline_name_index as oni
from v3lum.modules.company_org.icij_offshore import IcijOffshore

FIX = Path(__file__).resolve().parents[1] / "fixtures/icij_offshore"
SAMPLES = {
    "nodes-entities.csv": "bulk_entities_sample.csv",
    "nodes-officers.csv": "bulk_officers_sample.csv",
    "nodes-intermediaries.csv": "bulk_intermediaries_sample.csv",
    "relationships.csv": "bulk_relationships_sample.csv",
}
ADDRESSES = "node_id,address,name,countries,country_codes,sourceID,valid_until,note\n99300002,1 EXAMPLE STREET,1 EXAMPLE STREET,Brazil,BRA,Pandora Papers,,\n"


def build_zip(path: Path, *, drop: str = "", override: dict[str, str] | None = None) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("GENERATED_ON_20260909.txt", "")
        for member, sample in SAMPLES.items():
            if member == drop:
                continue
            zf.writestr(member, (override or {}).get(member) or (FIX / sample).read_text(encoding="utf-8"))
        zf.writestr("nodes-addresses.csv", ADDRESSES)
    return path


def install(tmp_path: Path, *, index: bool = True) -> Path:
    """Put the archive where the dataset manager keeps 'icij' and (optionally) build its index."""
    archive = build_zip(tmp_path / "full-oldb.zip")
    target = datasets.DataStore(None).path(icij.DATASET)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(archive, target)
    if index:
        assert icij.validate_and_index(target) is True
    return target


def test_zip_manifest_fixture_lists_the_members_the_importer_needs():
    members = {m["name"] for m in module_fixture("icij_offshore", "bulk_zip_members.json")["members"]}
    assert set(icij.MEMBERS.values()) <= members
    assert "nodes-addresses.csv" in members  # present upstream, never imported


def test_import_keeps_entities_linked_names_and_drops_addresses(tmp_path):
    out = tmp_path / "index.sqlite"
    summary = icij.build_index(build_zip(tmp_path / "a.zip"), out)
    assert summary["generated_on"] == "2026-09-09"
    assert summary["entities"] == 6 and summary["linked_nodes"] == 3
    conn = sqlite3.connect(out)
    kinds = {r[0] for r in conn.execute("SELECT rel_type FROM rel")}
    assert "registered_address" not in kinds and "same_address_as" not in kinds
    assert {"officer_of", "intermediary_of", "similar", "same_as"} >= kinds
    names = {r[0] for r in conn.execute("SELECT name FROM node")}
    assert names == {"EXAMPLE PERSON ONE", "EXAMPLE NOMINEE DIRECTORS LTD", "EXAMPLE CORPORATE SERVICES LTD"}
    blob = out.read_bytes()
    assert b"1 EXAMPLE STREET" not in blob and b"addresses" not in blob.lower().replace(b"nodes-addresses", b"")
    conn.close()


def test_entity_dates_and_leak_are_normalised(tmp_path):
    out = tmp_path / "index.sqlite"
    icij.build_index(build_zip(tmp_path / "a.zip"), out)
    with oni.NameIndexReader(out) as reader:
        ent = reader.entry_by_id("10000001")
        assert ent["data"]["incorporation_date"] == "2006-03-23"
        assert ent["data"]["leak"] == "Panama Papers" and ent["data"]["jurisdiction_description"] == "Samoa"
        hits = reader.match("Example Offshore Holdings Ltd.")
        assert hits and hits[0]["entry_id"] == "99000001" and hits[0]["score"] >= 0.9
        assert reader.entry_by_id("99000001")["data"]["leak_detail"] == "Example Provider"


@pytest.mark.parametrize(
    "drop, override, needle",
    [
        ("relationships.csv", None, "without relationships.csv"),
        ("", {"nodes-entities.csv": "node,label\n1,X\n"}, "header changed"),
    ],
)
def test_broken_archives_are_refused(tmp_path, drop, override, needle):
    with pytest.raises(icij.IcijImportError, match=needle):
        icij.build_index(build_zip(tmp_path / "b.zip", drop=drop, override=override), tmp_path / "x.sqlite")
    assert not (tmp_path / "x.sqlite").exists()


def test_compression_bombs_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(icij, "MAX_RATIO", 2)
    bomb = (FIX / "bulk_entities_sample.csv").read_text(encoding="utf-8") + "\n".join(["9,AAAA,,,,,,,,,,,,,,,,,,,"] * 3000)
    with pytest.raises(icij.IcijImportError, match="compression ratio"):
        icij.build_index(build_zip(tmp_path / "c.zip", override={"nodes-entities.csv": bomb}), tmp_path / "y.sqlite")


def test_dataset_is_registered_large_open_and_validated_by_the_importer():
    reg = datasets.DATASETS[icij.DATASET]
    assert reg["url"] == icij.BULK_URL and reg["source"] == "icij.bulk" and reg["terms_class"] == "open"
    assert reg["validate"] is icij.validate_and_index and reg["max_bytes"] == 250_000_000
    assert "ODbL" in reg["licence"] and "CC BY-SA" in reg["attribution"] or "CC-BY-SA" in reg["licence"]


def test_validator_rejects_a_bad_download(tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK\x03\x04 not really a zip")
    with pytest.raises(icij.IcijImportError):
        icij.validate_and_index(bad)


def test_local_possible_match_with_linked_nodes_and_no_pivots(tmp_path):
    install(tmp_path)
    http = FakeHttp()
    res = run_module(IcijOffshore, "company_name:Example Offshore Holdings Limited", http)
    assert res.status is Status.OK, res.error
    assert http.calls == []  # nothing leaves the machine
    (match,) = res.attributes["offshore_leaks_matches"]
    assert match["node_id"] == "99000001" and match["source"] == "local"
    assert match["jurisdiction"] == "British Virgin Islands" and match["leak"] == "Pandora Papers"
    assert match["intermediaries"] == ["EXAMPLE CORPORATE SERVICES LTD"]
    assert {o["name"] for o in match["linked_officers"]} == {"EXAMPLE PERSON ONE", "EXAMPLE NOMINEE DIRECTORS LTD"}
    assert match["related_entities"][0]["node_id"] == "10000005"
    assert match["node_url"] == "https://offshoreleaks.icij.org/nodes/99000001"
    assert res.pivots == []
    (finding,) = res.findings
    assert finding.title == "Possible match: appears in ICIJ Offshore Leaks - not evidence of wrongdoing"
    assert finding.severity is Severity.INFO and finding.confidence_label.value == "possible"
    assert {"offshore_leaks", "context_only", "name_only_match"} <= set(finding.tags) and "malicious" not in finding.tags
    assert "not evidence of wrongdoing" in finding.description and "legitimate uses" in finding.description
    assert "ODbL" in finding.description and finding.source == "icij.bulk"
    screening = res.attributes["offshore_leaks_screening"]
    assert screening["state"] == "matched" and screening["index_generated_on"] == "2026-09-09"
    assert "ODbL" in res.attributes["data_attribution"][0]
    assert "1 EXAMPLE STREET" not in str(res.raw) and "residential" not in str(res.raw)


def test_no_entity_above_threshold_is_empty(tmp_path):
    install(tmp_path)
    res = run_module(IcijOffshore, "company_name:Banco Industrial do Brasil", FakeHttp())
    assert res.status is Status.EMPTY and "0.90" in res.error
    assert res.attributes["offshore_leaks_screening"]["state"] == "no_match"


def test_missing_dataset_is_unavailable_dataset_never_no_match(tmp_path):
    res = run_module(IcijOffshore, "company_name:Example Offshore Holdings Limited", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "v3lum data update icij" in res.error and "icij_offshore_api" in res.error


def test_installed_copy_without_index_is_unavailable(tmp_path):
    install(tmp_path, index=False)
    res = run_module(IcijOffshore, "company_name:Example Offshore Holdings Limited", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "rebuild" in res.error


def test_only_seeds_and_cnpj_resolved_names(tmp_path):
    install(tmp_path)
    pivoted = run_module(IcijOffshore, "company_name:Example Offshore Holdings Limited", FakeHttp(), is_seed=False, depth=1,
                         provenance=[("domain:example.com", "company_of", "wikidata")])
    assert pivoted.status is Status.SKIPPED and pivoted.reason_code == "not_applicable"
    deep = run_module(IcijOffshore, "company_name:Example Offshore Holdings Limited", FakeHttp(), is_seed=False, depth=2,
                      provenance=[("cnpj:00000000000191", "partner_of", "cnpj_lookup"), ("company_name:x", "partner_of", "x")])
    assert deep.status is Status.SKIPPED
    resolved = run_module(IcijOffshore, "company_name:Example Offshore Holdings Limited", FakeHttp(), is_seed=False, depth=1,
                          provenance=[("cnpj:00000000000191", "legal_name", "cnpj_lookup")])
    assert resolved.status is Status.OK


def test_entities_only_person_names_are_not_accepted():
    assert IcijOffshore.accepts == {T.ORG}
    assert IcijOffshore.disclosure == "none" and IcijOffshore.default_enabled is False
    assert IcijOffshore.hosts == () and IcijOffshore.max_pivots == 0


def test_index_reader_refuses_foreign_files(tmp_path):
    other = tmp_path / "other.sqlite"
    conn = sqlite3.connect(other)
    conn.execute("CREATE TABLE meta (key TEXT, value TEXT)")
    conn.execute("INSERT INTO meta VALUES ('schema', 'something/9')")
    conn.commit()
    conn.close()
    with pytest.raises(oni.NameIndexError):
        oni.NameIndexReader(other)
    with pytest.raises(oni.NameIndexError):
        oni.NameIndexReader(tmp_path / "missing.sqlite")


def test_rebuild_command(tmp_path, capsys):
    install(tmp_path, index=False)
    assert icij.main(["--rebuild-index"]) == 0
    assert '"entities": 6' in capsys.readouterr().out
    assert icij.main([]) == 2


def test_capped_stream_refuses_more_than_declared():
    capped = icij._Capped(io.BytesIO(b"x" * 100), 10)
    with pytest.raises(icij.IcijImportError):
        io.BufferedReader(capped).read()
