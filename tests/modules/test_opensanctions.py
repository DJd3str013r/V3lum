"""Offline tests for P222 ``opensanctions`` (licensed bulk data matched locally, batch p3-G10-1).

tests/fixtures/opensanctions/: the real index.json metadata and 307 answer, and the real targets.simple.csv
header with synthetic rows (the CC BY-NC records are never committed; README there).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.licence import LicenceState
from v3lum.core.models import Severity, Status
from v3lum.modules.company_org import offline_name_index as oni
from v3lum.modules.company_org import opensanctions as osx
from v3lum.modules.company_org.opensanctions import OpenSanctions

FIX = Path(__file__).resolve().parents[1] / "fixtures/opensanctions"
CSV = FIX / "targets_simple_sample.csv"
NOW = datetime(2026, 11, 26, tzinfo=timezone.utc)
DD = ScanOptions(purpose="supplier due diligence DD-2026-01")


def licensed() -> LicenceState:
    return LicenceState.from_dict({"schema": "v3lum.licence_allow/1", "entries": [{
        "source_id": "opensanctions.bulk_licensed", "basis": "licence", "scope": "internal screening", "legal_ref": "LEGAL-2026-099",
        "approver": "legal", "decided_at": "2026-11-01", "review_by": "2027-05-01", "evidence_url": "https://www.opensanctions.org/licensing/",
        "quote": "bulk data licence"}]})


def install() -> dict:
    return osx.import_targets(CSV, licence_state=licensed(), now=NOW)


def test_import_is_refused_without_a_recorded_bulk_licence(tmp_path):
    with pytest.raises(osx.OpenSanctionsImportError, match="licence_allow"):
        osx.import_targets(CSV, tmp_path / "t.sqlite", licence_state=LicenceState.from_dict({}), now=NOW)
    assert not (tmp_path / "t.sqlite").exists()
    assert osx.main(["import", str(CSV)]) == 1  # no licence_allow file in the test home


def test_import_drops_contact_and_birth_data_and_keeps_wallets(tmp_path):
    out = tmp_path / "t.sqlite"
    summary = osx.import_targets(CSV, out, licence_state=licensed(), now=NOW)
    assert summary["entries"] == 5 and summary["wallets"] == 1
    blob = out.read_bytes()
    for leaked in (b"person@example.com", b"5555-0100", b"1970-01-01", b"1 Example Street", b"1 Example Road"):
        assert leaked not in blob
    with oni.NameIndexReader(out) as reader:
        (hit,) = reader.by_ident("wallet", "0x000000000000000000000000000000000000dead")
        assert hit["entry_id"] == "NK-example-wallet-1" and hit["data"]["listing"] == "sanction"


def test_index_json_records_the_version_and_checks_the_sha1(tmp_path):
    doc = module_fixture("opensanctions", "bulk_index.json")
    info = osx.parse_index(doc)
    assert info["version"] == "20261125185440-ckr" and info["resources"]["targets.simple.csv"]["size"] == 479535026
    with pytest.raises(osx.OpenSanctionsImportError, match="SHA-1"):
        osx.import_targets(CSV, tmp_path / "a.sqlite", index_doc=doc, licence_state=licensed(), now=NOW)
    for res in doc["resources"]:
        if res["name"] == "targets.simple.csv":
            res["checksum"] = hashlib.sha1(CSV.read_bytes()).hexdigest()  # noqa: S324 - the publisher's checksum algorithm
    summary = osx.import_targets(CSV, tmp_path / "b.sqlite", index_doc=doc, licence_state=licensed(), now=NOW)
    assert summary["version"] == "20261125185440-ckr"


def test_bulk_files_are_never_downloaded_by_the_module():
    redirect = module_fixture("opensanctions", "bulk_index_redirect.http.json")
    assert redirect["status"] == 307 and redirect["headers"]["location"].startswith("https://data.opensanctions.org/artifacts/")
    assert OpenSanctions.hosts == () and OpenSanctions.disclosure == "none"
    assert OpenSanctions.terms == "license" and OpenSanctions.sources == ("opensanctions.bulk_licensed",)
    assert OpenSanctions.default_enabled is False


def test_missing_import_is_unavailable_dataset():
    res = run_module(OpenSanctions, "company_name:Example Sanctioned Trading", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "import" in res.error


def test_company_possible_match_is_never_a_determination():
    install()
    http = FakeHttp()
    res = run_module(OpenSanctions, "company_name:Example Sanctioned Trading Company Ltd", http)
    assert res.status is Status.OK and http.calls == []
    (hit,) = res.attributes["opensanctions_matches"]
    assert hit["entity_id"] == "NK-example-company-1" and hit["listing"] == "sanction" and hit["score"] >= 0.9
    (finding,) = res.findings
    assert finding.title == "OpenSanctions possible match - confirm identity"
    assert finding.severity is Severity.MEDIUM and finding.confidence_label.value == "possible"
    assert finding.tags[:2] == ["sanctions", "name_only_match"]
    assert "threshold 0.9" in finding.description and "NK-example-company-1" in finding.description
    assert finding.source == "opensanctions.bulk_licensed"
    assert res.attributes["opensanctions_screening"]["state"] == "matched"


def test_other_watchlists_are_context():
    install()
    res = run_module(OpenSanctions, "company_name:Example Debarred Builders S.A.", FakeHttp())
    (finding,) = res.findings
    assert finding.severity is Severity.INFO and "context_only" in finding.tags and "sanctions" not in finding.tags


def test_person_needs_a_typed_subject_with_a_purpose():
    install()
    res = run_module(OpenSanctions, "person_name:Maria Example Silva", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    pivot = run_module(OpenSanctions, "person_name:Maria Example Silva", FakeHttp(), options=DD, is_seed=False, depth=1,
                       provenance=[("domain:example.com", "registrant", "rdap")])
    assert pivot.status is Status.SKIPPED and pivot.reason_code == "privacy"


def test_natural_person_never_labelled_sanctioned_and_homonyms_lower_it():
    install()
    res = run_module(OpenSanctions, "person_name:Maria Example Silva", FakeHttp(), options=DD)
    assert res.status is Status.OK
    (finding,) = res.findings
    assert "not a sanctions determination" in finding.title and "sanctions" not in finding.tags
    assert res.attributes["homonym_risk"]["risk"] == "high"
    assert finding.severity is Severity.INFO and "context_only" in finding.tags  # very common name: INFO


def test_pep_hits_are_info_context():
    install()
    res = run_module(OpenSanctions, "person_name:Example Person One", FakeHttp(), options=DD)
    (finding,) = res.findings
    assert finding.severity is Severity.INFO and {"pep", "context_only", "name_only_match"} <= set(finding.tags)
    assert "1970" not in json.dumps(res.raw)


def test_qsa_partners_only_with_the_due_diligence_option():
    install()
    prov = [("cnpj:00000000000191", "partner_of", "cnpj_lookup")]
    off = run_module(OpenSanctions, "person_name:Maria Example Silva", FakeHttp(), options=DD, is_seed=False, depth=1, provenance=prov)
    assert off.status is Status.SKIPPED and off.reason_code == "privacy"
    on = run_module(OpenSanctions, "person_name:Maria Example Silva", FakeHttp(), options=DD, is_seed=False, depth=1, provenance=prov,
                    settings={osx.SETTING_DD_PARTNERS: True})
    assert on.status is Status.OK
    company = run_module(OpenSanctions, "company_name:Example Sanctioned Trading", FakeHttp(), is_seed=False, depth=1,
                         provenance=[("domain:example.com", "company_of", "wikidata")])
    assert company.status is Status.SKIPPED and company.reason_code == "not_applicable"


def test_wallets_match_exactly_after_normalisation():
    install()
    res = run_module(OpenSanctions, "eth_address:0x000000000000000000000000000000000000dEaD", FakeHttp())
    (finding,) = res.findings
    assert finding.title == "OpenSanctions exact wallet match" and finding.severity is Severity.HIGH
    assert finding.confidence_label.value == "confirmed" and finding.tags == ["sanctions"]


def test_no_candidate_is_empty():
    install()
    res = run_module(OpenSanctions, "company_name:Totally Unrelated Widgets", FakeHttp())
    assert res.status is Status.EMPTY and res.attributes["opensanctions_screening"]["state"] == "no_match"
