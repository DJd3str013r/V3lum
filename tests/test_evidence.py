"""Evidence store v2 (P324 cond 1-3, 8-9; A4 BR7; A10/AR03).

Content addressing, write-once files, re-collection versions with a diff summary, the request
context (cache-served answers keep their fetched_at), value-free file names, 0600/0700 modes, the
per-file and per-case caps with gzip, the hash-chained evidence index, the manifest and the case DB
rows (evidence_versions).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, define_module, make_runtime, source_ids, test_provider
from v3lum.core import evidence as ev
from v3lum.core import store as store_mod
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.evidence import EvidenceRecord, EvidenceStore, manifest
from v3lum.core.http import RequestInfo
from v3lum.core.models import ModuleResult, Status
from v3lum.core.store import Store

DOMAIN = Entity.make("domain", "example.org")
EMAIL = Entity.make("email", "alice.person@corp.example")


def _result(module: str = "t_ev2", entity: Entity = DOMAIN, raw=None, **kw) -> ModuleResult:
    res = ModuleResult(module, entity, **kw)
    res.raw = {"answer": 1} if raw is None else raw
    return res


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def _index(case_dir: Path) -> list[dict]:
    return [json.loads(line) for line in (case_dir / ev.EVIDENCE_INDEX).read_text(encoding="utf-8").splitlines()]


@pytest.fixture()
def clock():
    return FakeClock("2026-11-26T10:00:00+00:00")


# --------------------------------------------------------------------------------------
# content addressing, write-once, modes
# --------------------------------------------------------------------------------------


def test_content_addressed_write_once_files_with_owner_only_modes(tmp_path, clock):
    store = EvidenceStore(tmp_path / "case-a", now=clock.now)
    old = os.umask(0o022)
    try:
        path, digest = store.save(_result(raw={"answer": 42}), requests=[{"method": "GET", "url": "https://api.example.test/v1?q=x", "status": 200, "host": "api.example.test"}])
    finally:
        os.umask(old)
    blob = Path(path).read_bytes()
    assert hashlib.sha256(blob).hexdigest() == digest  # the stored bytes are what the name addresses
    assert Path(path).name.endswith(f"__{digest[:10]}.json") and Path(path).name.startswith("t_ev2__domain__")
    record = json.loads(blob)
    assert record["schema"] == ev.SCHEMA and record["data"] == {"answer": 42} and record["version"] == 1
    assert record["collected_at"] == "2026-11-26T10:00:00+00:00" and record["case_id"] == "case-a"
    assert record["record_key"] == f"t_ev2|{record['entity_hmac']}" and len(record["entity_hmac"]) == 64
    assert _mode(path) == 0o600 and _mode(tmp_path / "case-a") == 0o700 and _mode(Path(path).parent) == 0o700
    assert _mode(tmp_path / "case-a" / ev.EVIDENCE_INDEX) == 0o600
    assert manifest(tmp_path / "case-a") == [(f"evidence/{Path(path).name}", digest)]


def test_an_unchanged_re_collection_is_not_stored_twice(tmp_path, clock):
    store = EvidenceStore(tmp_path / "case-b", now=clock.now)
    first = store.save(_result(raw={"answer": 1}))
    clock.advance(3600)
    second = store.save(_result(raw={"answer": 1}))
    assert first == second  # same version returned, no new file
    assert len(list((tmp_path / "case-b" / "evidence").iterdir())) == 1 and len(_index(tmp_path / "case-b")) == 1


def test_a_re_collection_writes_a_new_version_with_a_diff_summary_and_never_overwrites(tmp_path, clock):
    case = tmp_path / "case-c"
    store = EvidenceStore(case, now=clock.now)
    path1, sha1 = store.save(_result(raw={"ports": [80, 443], "banner": "nginx", "alice@corp.example": True}))
    before = Path(path1).read_bytes()
    clock.advance(86400)
    path2, sha2 = store.save(_result(raw={"ports": [80, 443, 8080], "os": "linux"}))
    assert path1 != path2 and sha1 != sha2
    assert Path(path1).read_bytes() == before  # version 1 untouched
    v2 = ev.read_evidence(path2)
    assert v2["version"] == 2 and v2["previous_sha256"] == sha1
    diff = v2["diff_summary"]
    assert diff["added"] == ["os"] and diff["removed"] == ["banner"]  # plain field names only
    assert diff["removed_count"] == 2 and "alice@corp.example" not in json.dumps(diff)  # a key that is a value is counted, never written
    assert diff["changed_leaves"] == 4 and diff["previous_version"] == 1
    entries = _index(case)
    assert [(e["seq"], e["version"]) for e in entries] == [(1, 1), (2, 2)]
    assert entries[1]["record_key"] == entries[0]["record_key"] and entries[1]["diff_summary"]["added"] == ["os"]
    assert [m[1] for m in manifest(case)] == [sha1, sha2]
    assert store.latest(entries[0]["record_key"])["sha256"] == sha2


def test_a_name_holding_other_bytes_or_a_planted_link_is_refused(tmp_path):
    target = tmp_path / "evidence"
    target.mkdir()
    data = b'{"x": 1}'
    digest = hashlib.sha256(data).hexdigest()
    path = target / f"m__domain__0123456789ab__{digest[:10]}.json"
    path.write_bytes(b"tampered")
    with pytest.raises(OSError, match="write-once"):
        ev._write_once(path, data, digest)
    assert path.read_bytes() == b"tampered"
    path.unlink()
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched", encoding="utf-8")
    os.symlink(outside, path)
    with pytest.raises(OSError, match="symbolic link"):
        ev._write_once(path, data, digest)
    assert outside.read_text(encoding="utf-8") == "untouched"
    ev._write_once(target / "fresh.json", data, digest)
    ev._write_once(target / "fresh.json", data, digest)  # the same bytes again: accepted (idempotent)
    assert (target / "fresh.json").read_bytes() == data and _mode(target / "fresh.json") == 0o600
    assert not [p for p in target.iterdir() if p.name.endswith(".tmp")]


def test_a_changed_version_file_is_never_reused_and_a_new_version_is_written(tmp_path, clock):
    case = tmp_path / "case-d"
    store = EvidenceStore(case, now=clock.now)
    path1, _sha1 = store.save(_result(raw={"answer": 1}))
    os.chmod(path1, 0o600)
    Path(path1).write_bytes(Path(path1).read_bytes().replace(b'"answer": 1', b'"answer": 2'))
    clock.advance(60)
    path2, _sha2 = store.save(_result(raw={"answer": 1}))
    assert path2 != path1 and ev.read_evidence(path2)["version"] == 2


# --------------------------------------------------------------------------------------
# request context, datasets, fetched_at
# --------------------------------------------------------------------------------------


def test_request_context_redirect_chain_headers_and_datasets(tmp_path, clock):
    infos = [
        {"ts": "2026-11-26T09:59:58+00:00", "method": "GET", "url": "https://short.example.test/a", "host": "short.example.test", "status": 301,
         "opsec": "passive", "egress_profile": "default", "user_agent": "V3LUM/1.0"},
        {"ts": "2026-11-26T09:59:59+00:00", "method": "GET", "url": "https://api.example.test/v1/item?apikey=SECRETKEY123", "host": "api.example.test",
         "status": 200, "bytes": 12, "headers": {"Date": "Thu, 26 Nov 2026 09:59:59 GMT", "Content-Type": "application/json", "Server": "nginx", "Set-Cookie": "x=y"}},
    ]
    res = _result(raw={"a": 1})
    res.datasets = [{"name": "tranco", "sha256": "ab" * 32, "fetched_at": "2026-11-01", "licence": "CC-BY-4.0"}]
    path, _ = EvidenceStore(tmp_path / "case-r", now=clock.now).save(res, requests=infos)
    record = ev.read_evidence(path)
    hop, answer = record["requests"]
    assert hop["redirect_hop"] is True and hop["from_cache"] is False
    assert answer["redirect_chain"] == ["https://short.example.test/a"] and answer["final_url"].startswith("https://api.example.test/v1/item")
    assert "SECRETKEY123" not in json.dumps(record) and "apikey=" in answer["url"]  # AR01: the key-like parameter is masked
    assert answer["headers"] == {"date": "Thu, 26 Nov 2026 09:59:59 GMT", "content-type": "application/json", "server": "nginx"}  # selected only
    assert answer["fetched_at"] == "2026-11-26T09:59:59+00:00" and record["fetched_at"] == "2026-11-26T09:59:58+00:00"
    assert record["datasets"] == res.datasets


def test_redirect_chains_belong_to_the_requesting_module_only():
    """The DoH lookups that pin each hop's target (module egress_resolver) are logged between a 3xx
    hop and the answer that ends it: they never inherit the chain, the module's answer does."""
    def rec(module, url, status):
        return {"ts": "2026-11-26T10:00:00+00:00", "method": "GET", "url": url, "host": url.split("/")[2], "status": status, "module": module}

    out = ev.request_records([
        rec("t_light", "https://example.org/", 302),
        rec("egress_resolver", "https://dns.google/resolve?name=example.org&type=A", 200),
        rec("other_module", "https://api.example.test/v1", 200),
        rec("t_light", "https://www.example.org/", 301),
        rec("egress_resolver", "https://dns.google/resolve?name=www.example.org&type=A", 200),
        rec("t_light", "https://www.example.org/home", 200),
        rec("t_light", "https://www.example.org/next", 200),
    ])
    hop1, doh1, other, hop2, doh2, final, after = out
    assert hop1["redirect_hop"] is True and hop2["redirect_hop"] is True
    for plain in (doh1, other, doh2):
        assert plain["redirect_chain"] == [] and plain["final_url"] == plain["url"]
    assert final["redirect_chain"] == ["https://example.org/", "https://www.example.org/"] and final["final_url"] == "https://www.example.org/home"
    assert after["redirect_chain"] == []  # the chain is consumed by the answer that ended it


def test_a_payload_too_deep_to_encode_is_a_value_error_never_a_crash(tmp_path, monkeypatch):
    def too_deep(*args, **kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(EvidenceRecord, "from_result", classmethod(lambda cls, *a, **k: too_deep()))
    with pytest.raises(ValueError, match="nested too deeply"):
        EvidenceStore(tmp_path / "case-deep").save(_result())  # the engine keeps the result and notes it


def test_cache_served_evidence_keeps_fetched_at(tmp_path, clock):
    """P324 cond 2: an answer served from the cache keeps the cache row time, never the replay time."""
    row_time = "2026-11-20T08:30:00+00:00"
    cached = RequestInfo(ts=clock.now().isoformat(), method="GET", url="https://api.example.test/v1", host="api.example.test", path="/v1", status=200, cached=True)
    object.__setattr__(cached, "fetched_at", row_time)  # a RequestInfo that carries the cache row time
    as_dict = {"ts": clock.now().isoformat(), "method": "GET", "url": "https://api.example.test/v2", "host": "api.example.test", "status": 200, "cached": True, "fetched_at": row_time}
    unknown = {"ts": clock.now().isoformat(), "method": "GET", "url": "https://api.example.test/v3", "host": "api.example.test", "status": 200, "cached": True}
    path, _ = EvidenceStore(tmp_path / "case-f", now=clock.now).save(_result(), requests=[cached, as_dict, unknown])
    record = ev.read_evidence(path)
    assert [r["from_cache"] for r in record["requests"]] == [True, True, True]
    assert [r["fetched_at"] for r in record["requests"]] == [row_time, row_time, None]  # unknown stays unknown: never now()
    assert record["fetched_at"] == row_time and record["collected_at"] == clock.now().isoformat(timespec="seconds")
    assert ev.read_evidence(path)["fetched_at"] != record["collected_at"]


def test_cache_served_answers_through_the_engine_never_claim_the_replay_time(registry, clock):
    """End to end: the second scan is served from the HTTP cache; its evidence says from_cache and
    keeps the original fetch time (or 'unknown' when the client does not report the row time)."""

    def run(self, entity, ctx):
        ctx.http.get("https://api.example.test/ping")
        res = self.result(entity)
        res.raw = {"pong": True}
        return res

    with test_provider() as prov:
        define_module("t_ev_cache", [T.DOMAIN], run, disclosure="third_party", provider=prov.id, sources=source_ids(prov), hosts=prov.hosts, access_model="free_noauth_unlimited", cache_ttl=86400)
        http = FakeHttp(clock=clock).add("GET", "https://api.example.test/ping", json={"pong": True}, times=1)
        rt = make_runtime(http, clock=clock, cache=True)
        first = Engine(rt, ScanOptions(include={"t_ev_cache"})).investigate([DOMAIN])
        clock.advance(7200)
        second = Engine(rt, ScanOptions(include={"t_ev_cache"})).investigate([DOMAIN])
    fresh = ev.read_evidence(first.results[0].evidence)["requests"][0]
    served = ev.read_evidence(second.results[0].evidence)["requests"][0]
    assert fresh["from_cache"] is False and served["from_cache"] is True
    assert served["fetched_at"] in (None, fresh["fetched_at"])  # never the replay time
    assert ev.read_evidence(second.results[0].evidence)["collected_at"] == clock.now().isoformat(timespec="seconds")


# --------------------------------------------------------------------------------------
# value-free names, pseudonyms
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("etype", "value", "fragments"),
    [
        ("email", "alice.person@corp.example", ["alice", "corp.example", "@"]),
        ("phone", "+5511987654321", ["5511987654321", "987654321"]),
        ("cpf", "52998224725", ["52998224725", "529.982.247-25"]),
        ("username", "darkhandle_77", ["darkhandle"]),
    ],
)
def test_no_raw_value_in_any_file_name_or_index_line(tmp_path, clock, etype, value, fragments):
    entity = Entity.make(etype, value)
    case = tmp_path / "case-n"
    store = EvidenceStore(case, now=clock.now)
    store.save(_result(module="t_people", entity=entity, raw={"seen": True}))
    clock.advance(60)
    store.save(_result(module="t_people", entity=entity, raw={"seen": False}))
    names = [p.name for p in case.rglob("*")]
    index_text = (case / ev.EVIDENCE_INDEX).read_text(encoding="utf-8")
    for fragment in fragments:
        assert not any(fragment.lower() in n.lower() for n in names), (fragment, names)
        assert fragment not in index_text
    part = names[[i for i, n in enumerate(names) if n.startswith("t_people__")][0]].split("__")[2]
    from v3lum.core import hmacid

    assert part == hmacid.hmac12(entity.type, entity.value)  # A4 BR7: the keyed HMAC of the installation


def test_without_the_installation_secret_names_are_random_never_a_plain_hash(tmp_path, monkeypatch, clock):
    from v3lum.core import hmacid

    def unavailable(*args, **kwargs):
        raise OSError("secret.key not readable")

    monkeypatch.setattr(hmacid, "hmac12", unavailable)
    path, _ = EvidenceStore(tmp_path / "case-x", now=clock.now).save(_result(entity=EMAIL, raw={"seen": True}))
    part = Path(path).name.split("__")[2]
    record = ev.read_evidence(path)
    assert len(part) == 12 and part != hashlib.sha256(EMAIL.key.encode()).hexdigest()[:12]
    assert record["entity_hmac"] == "" and record["record_key"].startswith("t_ev2|~")


# --------------------------------------------------------------------------------------
# caps and gzip
# --------------------------------------------------------------------------------------


def _bulky(n: int) -> dict:
    return {"rows": [{"id": i, "value": hashlib.sha256(str(i).encode()).hexdigest()} for i in range(n)]}


def test_records_above_64_kb_are_gzip_compressed(tmp_path, clock):
    raw = _bulky(2000)
    path, digest = EvidenceStore(tmp_path / "case-z", now=clock.now, max_file_bytes=0, max_case_bytes=0).save(_result(raw=raw))
    blob = Path(path).read_bytes()
    assert Path(path).name.endswith(f"__{digest[:10]}.json.gz") and blob[:2] == b"\x1f\x8b"
    assert hashlib.sha256(blob).hexdigest() == digest and len(gzip.decompress(blob)) > ev.GZIP_THRESHOLD
    record = ev.read_evidence(path)
    assert record["data"] == raw and record["truncated"] is None
    entry = _index(tmp_path / "case-z")[0]
    assert entry["compressed"] is True and entry["bytes"] == len(blob)


def test_the_file_cap_keeps_a_prefix_and_a_truncation_marker(tmp_path, clock):
    raw = {"blob": os.urandom(40_000).hex()}  # incompressible
    path, _ = EvidenceStore(tmp_path / "case-cap", now=clock.now, max_file_bytes=20_000, max_case_bytes=0).save(_result(raw=raw))
    assert os.path.getsize(path) <= 20_000
    record = ev.read_evidence(path)
    marker = record["truncated"]
    assert marker["reason"] == "evidence_max_file_bytes" and marker["limit"] == 20_000
    original = json.dumps(raw, ensure_ascii=False).encode()
    assert marker["original_bytes"] == len(original) and marker["original_sha256"] == hashlib.sha256(original).hexdigest()
    assert isinstance(record["data"], str) and json.dumps(raw, ensure_ascii=False).startswith(record["data"]) and marker["kept_chars"] == len(record["data"])
    assert _index(tmp_path / "case-cap")[0]["truncated"] is True


def test_the_case_cap_drops_the_data_once_spent_but_keeps_the_record(tmp_path, clock):
    store = EvidenceStore(tmp_path / "case-full", now=clock.now, max_file_bytes=0, max_case_bytes=80_000)
    store.save(_result(module="t_a", raw={"blob": os.urandom(25_000).hex()}))  # ~50 KB: fits
    path_b, _ = store.save(_result(module="t_b", raw={"blob": os.urandom(25_000).hex()}))  # ~30 KB left: a prefix
    record_b = ev.read_evidence(path_b)
    assert record_b["truncated"]["reason"] == "evidence_max_case_bytes" and isinstance(record_b["data"], str)
    path_c, _ = store.save(_result(module="t_c", raw={"blob": os.urandom(25_000).hex()}))  # nothing left
    record = ev.read_evidence(path_c)
    assert record["data"] is None and record["truncated"]["reason"] == "evidence_max_case_bytes"
    assert record["module"] == "t_c" and record["requests"] == []  # the record of the collection stays
    assert sum(os.path.getsize(p) for p in (tmp_path / "case-full" / "evidence").iterdir()) <= 80_000 + 4096


def test_caps_default_to_the_settings(tmp_path):
    assert EvidenceStore(tmp_path / "c1", settings={"evidence_max_file_bytes": 1234, "evidence_max_case_bytes": 0}).caps() == (1234, 0)
    assert EvidenceStore(tmp_path / "c2").caps() == (ev.DEFAULT_MAX_FILE_BYTES, ev.DEFAULT_MAX_CASE_BYTES)


# --------------------------------------------------------------------------------------
# secrets, redaction
# --------------------------------------------------------------------------------------


def test_configured_keys_and_raw_secret_values_never_reach_a_record(tmp_path, clock):
    from v3lum.core import redact

    key = "EvidenceKey0123456789abcd"
    redact.register_secret(key)
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    entity = Entity.make("jwt", jwt)
    res = _result(module="t_sec", entity=entity, raw={"token": jwt, "echo": key, jwt: 1})
    path, _ = EvidenceStore(tmp_path / "case-s", now=clock.now).save(res, requests=[{"method": "GET", "url": f"https://api.example.test/d?t={jwt}&k={key}", "status": 200}])
    text = Path(path).read_text(encoding="utf-8") + (tmp_path / "case-s" / ev.EVIDENCE_INDEX).read_text(encoding="utf-8")
    assert jwt not in text and key not in text and entity.redacted in text


# --------------------------------------------------------------------------------------
# hash chain, manifest, case DB rows, verification helpers
# --------------------------------------------------------------------------------------


def test_the_evidence_index_is_a_hash_chain(tmp_path, clock):
    case = tmp_path / "case-h"
    store = EvidenceStore(case, now=clock.now)
    for i in range(3):
        store.save(_result(module=f"t_m{i}", raw={"i": i}))
    check = ev.verify_chain(case / ev.EVIDENCE_INDEX)
    assert check.ok and check.lines == 3 and check.head == _index(case)[-1]["hash"]
    entries = _index(case)
    assert entries[0]["prev_hash"] == ev.CHAIN_GENESIS and entries[1]["prev_hash"] == entries[0]["hash"]
    assert entries[2]["hash"] == ev.chain_hash(entries[2]["prev_hash"], entries[2])


def test_canonical_json_matches_the_audit_rule_of_the_store():
    sample = {"b": [1, 2.5, None, True], "a": "ação", "z": {"y": "x"}}
    assert ev.canonical_json(sample) == store_mod.canonical_json(sample)
    record = {"case_id": "c", "seq": 1, "ts": "t", "kind": "k", "payload": sample}
    assert ev.chain_hash(store_mod.AUDIT_GENESIS, record) == store_mod.audit_hash(store_mod.AUDIT_GENESIS, record)


def test_sync_versions_writes_append_only_case_db_rows(tmp_path, clock):
    case = tmp_path / "case-db"
    db = Store(tmp_path / "v3lum.db")
    try:
        store = EvidenceStore(case, now=clock.now, store=db, case_id="20261126-100000-ab12")
        store.save(_result(raw={"v": 1}))
        clock.advance(60)
        store.save(_result(raw={"v": 2}))
        assert ev.sync_versions(db, "20261126-100000-ab12", case) == 0  # already recorded at save time
        with db.connection() as conn:
            rows = [dict(r) for r in conn.execute("SELECT record_key, version, sha256, path, collected_at, diff_summary FROM evidence_versions ORDER BY version")]
        assert [r["version"] for r in rows] == [1, 2] and all(r["path"].startswith("evidence/") for r in rows)
        assert rows[0]["sha256"] == _index(case)[0]["sha256"] and json.loads(rows[1]["diff_summary"])["changed_leaves"] == 1
        check = ev.verify_evidence(case, rows=rows)
        assert check.problems == [] and check.files == 2
    finally:
        db.close()


def test_verify_evidence_reports_edited_missing_and_unlisted_files(tmp_path, clock):
    case = tmp_path / "case-v"
    store = EvidenceStore(case, now=clock.now)
    path_a, _ = store.save(_result(module="t_a"))
    path_b, _ = store.save(_result(module="t_b"))
    assert ev.verify_evidence(case).problems == []
    blob = bytearray(Path(path_a).read_bytes())
    blob[5] ^= 0x01
    Path(path_a).write_bytes(bytes(blob))
    os.unlink(path_b)
    (case / "evidence" / "planted__domain__000000000000__0000000000.json").write_text("{}")
    problems = ev.verify_evidence(case).problems
    assert any(Path(path_a).name in p and "does not match the recorded" in p for p in problems)
    assert any(Path(path_b).name in p and "missing" in p for p in problems)
    assert any("planted__domain" in p and "not listed" in p for p in problems)


def test_a_v1_case_directory_is_verified_through_the_hashes_in_the_names(tmp_path):
    case = tmp_path / "case-v1"
    (case / "evidence").mkdir(parents=True)
    data = b'{"data": 1}'
    good = case / "evidence" / f"m__domain__0123456789ab__{hashlib.sha256(data).hexdigest()[:10]}.json"
    good.write_bytes(data)
    check = ev.verify_evidence(case)
    assert check.problems == [] and check.files == 1 and any("before v2" in w for w in check.warnings)
    assert manifest(case) == [(f"evidence/{good.name}", hashlib.sha256(data).hexdigest())]
    good.write_bytes(b'{"data": 2}')
    assert any("does not match the hash in its name" in p for p in ev.verify_evidence(case).problems)


def test_evidence_record_round_trip(tmp_path, clock):
    path, digest = EvidenceStore(tmp_path / "case-rt", now=clock.now).save(_result(status=Status.OK))
    record = EvidenceRecord.from_dict(ev.read_evidence(path), path=path, sha256=digest)
    assert record.module == "t_ev2" and record.entity_type == "domain" and record.status == "ok" and record.sha256 == digest
    assert record.to_dict()["data"] == {"answer": 1}


@pytest.fixture()
def registry(clean_registry):
    clean_registry.clear()
    return clean_registry
