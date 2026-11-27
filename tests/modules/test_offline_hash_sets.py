"""offline_hash_sets (P350): offline lookup in the local MalwareBazaar recent export.

Fixtures in tests/fixtures/offline_hash_sets/: ``mb_export_recent_*.csv`` follow the MalwareBazaar
export layout (the abuse.ch banner and commented column header of the legacy recent export, the column
set P156 documents) with real sample hashes from the research samples; reporter handles and file
names are replaced (``reporter_a``, ``sample.<type>``). ``*.http.json`` are live (410 legacy export,
the export page) or research (401 'Unauthorized') answers, used here as the body of a bad local copy.
The v2 export answer to a missing key was not observable without a key (see docs/backlog/p2-G07-2.md).
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from datetime import datetime, timezone

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.malware_hash import offline_hash_sets as ohs
from v3lum.modules.malware_hash.offline_hash_sets import OfflineHashSets

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
AGENTTESLA_MD5 = "da752e20f404dc5969d911208c9e3d59"
AGENTTESLA_SHA1 = "f73c88c5403458f3b85abb387a86e896aa844b58"
MISS_SHA256 = "0" * 63 + "1"
FETCHED = datetime(2026, 11, 26, 5, 10, 0, tzinfo=timezone.utc)  # FakeClock now: 2026-11-26 12:00 UTC


def fx(name):
    return module_fixture(OfflineHashSets, name)


def install_copy(content, *, fetched=FETCHED):
    """Place a local copy of the export where the dataset manager keeps it (isolated V3LUM_HOME)."""
    path = paths.datasets_dir() / ohs.MB_EXPORT_DATASET
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    stamp = fetched.timestamp()
    os.utime(path, (stamp, stamp))
    return path


def http_body(name):
    return fx(name)["response"]["body"]


def run(entity, **kw):
    http = kw.pop("http", None) or FakeHttp()
    res = run_module(OfflineHashSets, entity, http, **kw)
    assert http.calls == []  # disclosure none: the hash never leaves the machine
    return res


# ------------------------------------------------------------------ C1/C2/C5: metadata
def test_contract_metadata():
    cls = OfflineHashSets
    assert (cls.name, cls.category, cls.disclosure, cls.hosts, cls.provider) == ("offline_hash_sets", "malware_hash", "none", (), "")
    assert cls.sources == ("abusech.malwarebazaar",) and cls.terms == "license"  # off under corporate until licence-cleared
    assert cls.default_enabled is True and cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red" and cls.shares_input is False
    assert cls.optional_keys == ("abusech",) and cls.requires_keys == () and not cls.produces and cls.max_pivots == 0
    assert {t.value for t in cls.accepts} == {"md5", "sha1", "sha256", "file"}
    assert cls.upstream_families == frozenset({"abuse.ch"})  # one family with abusech (P171 consensus)


def test_one_local_copy_shared_with_abusech():
    from v3lum.modules.threat_intel_ioc import abusech

    assert abusech.EXPORT_DATASETS["malwarebazaar"] == ohs.MB_EXPORT_DATASET  # never downloaded twice (C5)


def test_corporate_profile_skips_it_until_licence_cleared():
    engine = Engine(make_runtime(), ScanOptions())
    decision = engine.decide_single(OfflineHashSets, Entity.make(T.SHA256, EICAR_SHA256))
    assert decision.allowed is False and decision.reason_code == "licence"


# ------------------------------------------------------------------ hits
def test_sha256_hit_reads_known_sample_with_dataset_dates():
    install_copy(fx("mb_export_recent_ok.csv"))
    res = run(f"sha256:{EICAR_SHA256}")
    assert res.status is Status.OK
    (finding,) = res.findings
    assert finding.title == "known MalwareBazaar sample: signature unknown, first seen 2026-11-25"
    assert finding.severity.label == "medium" and finding.tags == ["malware"] and finding.source == "abusech.malwarebazaar"
    assert finding.criterion and finding.observed_first.startswith("2026-11-25T22:40:10")
    assert "fetched 2026-11-26 05:10 UTC, export updated 2026-11-26 05:00 UTC" in finding.description
    dataset = finding.data["dataset"]
    assert dataset["name"] == ohs.MB_EXPORT_DATASET and dataset["export_updated"] == "2026-11-26T05:00:01Z"
    assert dataset["fetched_at"].startswith("2026-11-26T05:10") and dataset["stale"] is False
    assert finding.data["matched_by"] == "sha256" and finding.data["sample_sha256"] == EICAR_SHA256
    (hit,) = res.attributes["hash_set_hits"]
    assert hit["set"] == "MalwareBazaar recent export" and hit["export_updated"] == "2026-11-26T05:00:01Z"
    assert res.attributes["av_signatures"] == ["Win.Test.EICAR_HDB-1"] and res.attributes["file_type"] == "com"
    assert "malware_family" not in res.attributes and res.pivots == []
    assert any(d.get("name") == ohs.MB_EXPORT_DATASET for d in res.datasets)
    assert any("bazaar.abuse.ch" in url for _, url in res.links)


@pytest.mark.parametrize("entity", [f"md5:{AGENTTESLA_MD5}", f"sha1:{AGENTTESLA_SHA1}", f"md5:{AGENTTESLA_MD5.upper()}"])
def test_md5_and_sha1_hits(entity):
    install_copy(fx("mb_export_recent_ok.csv"))
    res = run(entity)
    assert res.status is Status.OK
    assert res.findings[0].title == "known MalwareBazaar sample: AgentTesla, first seen 2026-11-26"
    assert res.attributes["malware_family"] == ["AgentTesla"]
    assert res.attributes["similarity_hashes"] == {"imphash": "f34d5f2d4577ed6d9ceec516c1f5a744"}
    assert res.attributes["first_seen"] == "2026-11-26T04:58:01Z"


def test_reordered_plain_header_export():
    install_copy(fx("mb_export_recent_reordered.csv"))
    res = run("sha256:8348a0588ce681428a89e559d6ddf89f7a6cd425dac606dacc6c333d59e67d59")
    assert res.status is Status.OK and res.findings[0].title == "known MalwareBazaar sample: RemcosRAT, first seen 2026-11-26"
    assert res.findings[0].data["dataset"]["export_updated"] is None


def test_reporters_and_file_names_are_never_kept():
    install_copy(fx("mb_export_recent_ok.csv"))
    res = run(f"sha256:{EICAR_SHA256}")
    text = json.dumps({"f": [f.to_dict() for f in res.findings], "a": res.attributes, "r": res.raw}, default=str)
    assert "reporter_a" not in text and "sample.com" not in text


# ------------------------------------------------------------------ misses and could-not-verify
def test_miss_means_nothing():
    install_copy(fx("mb_export_recent_ok.csv"))
    res = run(f"sha256:{MISS_SHA256}")
    assert res.status is Status.EMPTY and res.findings == [] and res.attributes == {}
    assert "a miss means nothing" in res.error and "fetched 2026-11-26 05:10 UTC" in res.error and "last 48 h" in res.error


def test_header_only_export_is_a_valid_empty_copy():
    install_copy(fx("mb_export_recent_header_only.csv"))
    assert run(f"sha256:{EICAR_SHA256}").status is Status.EMPTY


def test_stale_copy_is_flagged():
    install_copy(fx("mb_export_recent_ok.csv"), fetched=datetime(2026, 11, 20, 5, 0, 0, tzinfo=timezone.utc))
    res = run(f"sha256:{EICAR_SHA256}")
    assert res.status is Status.OK and res.findings[0].data["dataset"]["stale"] is True
    assert "stale" in res.findings[0].description
    miss = run(f"sha256:{MISS_SHA256}")
    assert miss.status is Status.EMPTY and "stale" in miss.error


@pytest.mark.parametrize(
    "content",
    [
        fx("mb_export_recent_truncated.csv"),
        http_body("mb_export_legacy_410.http.json"),
        http_body("mb_unauthorized_401.http.json"),
        http_body("mb_export_docs_html.http.json"),
        "",
        "just,some,text\nwithout,the,export\n",
    ],
)
def test_bad_local_copies_are_never_an_absence(content):
    install_copy(content)
    res = run(f"sha256:{EICAR_SHA256}")
    assert res.status is Status.ERROR and "could not verify" in res.error and res.findings == []


def test_no_local_copy_is_unavailable_dataset():
    res = run(f"sha256:{EICAR_SHA256}")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert ohs.MB_EXPORT_DATASET in res.error and "v3lum keys setup" in res.error
    keyed = run(f"sha256:{EICAR_SHA256}", keys={"abusech": "abusech-test-key-0123456789"})
    assert keyed.status is Status.UNAVAILABLE and "keys setup" not in keyed.error


def test_index_follows_the_dataset_version():
    install_copy(fx("mb_export_recent_header_only.csv"))
    assert run(f"sha256:{EICAR_SHA256}").status is Status.EMPTY
    install_copy(fx("mb_export_recent_ok.csv"))
    assert run(f"sha256:{EICAR_SHA256}").status is Status.OK


# ------------------------------------------------------------------ file inputs
def test_file_input_is_hashed_locally(tmp_path):
    sample = tmp_path / "attachment.bin"
    sample.write_bytes(b"v3lum offline_hash_sets synthetic test file\n" * 3)
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    header = fx("mb_export_recent_header_only.csv")
    row = f'"2026-11-26 01:02:03", "{digest}", "n/a", "n/a", "reporter_a", "sample.bin", "unknown", "application/octet-stream", "TestFamily", "n/a", "n/a", "n/a", "n/a", "n/a"\n'
    install_copy(header + row)
    res = run(Entity.make(T.FILE, str(sample)))
    assert res.status is Status.OK and res.findings[0].title == "known MalwareBazaar sample: TestFamily, first seen 2026-11-26"
    assert "matched by the file's SHA256" in res.findings[0].description and res.findings[0].data["matched_by"] == "sha256"


def test_special_and_vanished_files_are_not_applicable(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert ohs.file_digests(str(fifo), lambda: None) == (None, "not_applicable", "only regular files are hashed")  # never opened
    gone = tmp_path / "gone.bin"
    gone.write_bytes(b"x")
    entity = Entity.make(T.FILE, str(gone))
    gone.unlink()
    install_copy(fx("mb_export_recent_ok.csv"))
    res = run(entity)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


# ------------------------------------------------------------------ parser
def test_parser_on_the_export_layouts():
    ok = ohs.parse_mb_export(fx("mb_export_recent_ok.csv"))
    assert ok["header_found"] and ok["updated"] == "2026-11-26T05:00:01Z" and len(ok["rows"]) == 3 and ok["bad_rows"] == 0
    assert set(ok["rows"][0]) == {"sha256", "md5", "sha1", "first_seen", "signature", "file_type", "mime_type", "imphash", "ssdeep", "tlsh", "clamav"}
    trunc = ohs.parse_mb_export(fx("mb_export_recent_truncated.csv"))
    assert trunc["truncated"] and len(trunc["rows"]) == 1
    crlf = ohs.parse_mb_export("﻿" + fx("mb_export_recent_reordered.csv").replace("\n", "\r\n"))
    assert crlf["header_found"] and crlf["rows"][0]["signature"] == "RemcosRAT"
    index = ohs.build_index(ok["rows"])
    assert index["md5"][EICAR_MD5] == 2 and index["sha1"][AGENTTESLA_SHA1] == 0
    assert ohs.export_problem(fx("mb_export_recent_ok.csv")) is None


def test_fixture_files_carry_no_personal_data():
    for path in (FIXTURES / "offline_hash_sets").iterdir():
        text = path.read_text(encoding="utf-8")
        assert "@" not in text.replace("[at]", "") or "abuse.ch" in text
        rows = [r for r in csv.reader(text.splitlines(), skipinitialspace=True) if r and r[0].startswith("20") and len(r) > 5]
        assert {r[4] for r in rows} <= {"reporter_a"} and all(r[5].startswith("sample.") for r in rows)
