"""Live checks of batch p1-G07-2 (run with V3LUM_LIVE=1; benign values only).

* circl_hashlookup (keyless): the EICAR SHA-256/MD5 lookups (a public AV test file), an unknown MD5
  (404 -> EMPTY) and the bulk endpoint with two well-known hashes. A 403/429/challenge from the
  datacenter egress is an accepted outcome when the module reports it as BLOCKED/RATE_LIMITED.
* yaraify needs the abuse.ch Auth-Key (P175 FC2: keyless answers are never relied upon): without a key
  it must answer NEEDS_KEY without sending anything (live checks are keyless only; the keyed EICAR
  answer is covered offline by tests/modules/test_yaraify.py).
* file_hashing and the internal TIP adapters have no public endpoint (offline / company instances).
"""

from __future__ import annotations

import pytest

from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.malware_hash.circl_hashlookup import CirclHashlookup
from v3lum.modules.malware_hash.yaraify import Yaraify

pytestmark = pytest.mark.live

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
NSRL_MD5 = "8ed4b4ed952526d89899e723f3488de4"  # a Windows update manifest listed in NSRL
UNKNOWN_MD5 = "5f6e7266a27a824c5fc5081add52f892"  # unknown to hashlookup (observed 404, 2026-11-26)
COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED)


def run(cls, entity):
    runtime = Runtime(Config(), no_cache=True)
    return Engine(runtime, ScanOptions()).run_module(cls, entity)


def accept_could_not_verify(res):
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"{res.module}: {res.status.value} {res.reason_code} from this egress (reported correctly): {res.error[:120]}")


def test_circl_hashlookup_eicar_sha256():
    res = run(CirclHashlookup, Entity.make(T.SHA256, EICAR_SHA256))
    accept_could_not_verify(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["known_malicious"] == ["malshare.com"]
    assert "known_good" not in res.attributes
    assert any(f.title == "Listed as known malicious (CIRCL hashlookup)" and f.severity.label == "medium" for f in res.findings)
    assert {p.entity.value for p in res.pivots if p.relation == "same_file"} >= {EICAR_MD5}


def test_circl_hashlookup_nsrl_md5_is_a_known_file():
    res = run(CirclHashlookup, Entity.make(T.MD5, NSRL_MD5))
    accept_could_not_verify(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["known_file_set"] == "nsrl" and res.attributes["known_good"] is True
    assert res.attributes["known_file"].startswith("known file: ")


def test_circl_hashlookup_unknown_md5_is_empty():
    res = run(CirclHashlookup, Entity.make(T.MD5, UNKNOWN_MD5))
    accept_could_not_verify(res)
    assert res.status is Status.EMPTY and "not in hashlookup" in res.error


def test_circl_hashlookup_bulk_md5():
    res = run(CirclHashlookup, Entity.make(T.TEXT, f"{EICAR_MD5}\n{NSRL_MD5}\n{UNKNOWN_MD5}\n"))
    accept_could_not_verify(res)
    assert res.status is Status.OK, res.error
    summary = [f for f in res.findings if f.title == "Hash list checked against CIRCL hashlookup"][0]
    assert summary.data["checked"] == 3 and summary.data["known_malicious"] == 1 and summary.data["not_in_hashlookup"] == 1


def test_yaraify_without_key_sends_nothing():
    res = run(Yaraify, Entity.make(T.SHA256, EICAR_SHA256))
    assert res.status is Status.NEEDS_KEY and res.requests == 0
