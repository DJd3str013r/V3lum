"""Offline tests of grayhatwarfare (P138) with the fixtures in tests/fixtures/grayhatwarfare/.

The 401 'You don't have access to API' answer is a real research capture; the success bodies follow the
public API v2 shape with documentation values (file names built to exercise the P138 cond 3 masking; a
trimmed real capture made with the team key replaces them before merge, cond 5).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum import config
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.breach_leak import grayhatwarfare as mod
from v3lum.modules.breach_leak.grayhatwarfare import GrayhatWarfare, grayhat_url, mask_file_name

KEY = "gh-test-key-0123456789abcdef"  # fake key
KEYS = {"grayhat": KEY}
BUCKETS = grayhat_url("buckets", "exemplo")
FILES = grayhat_url("files", "exemplo")
OPTS = ScanOptions(purpose="brand exposure review, ticket EX-8")
FIXDIR = Path(__file__).resolve().parents[1] / "fixtures/grayhatwarfare"


def fx(name: str):
    return module_fixture("grayhatwarfare", name)


def add(http: FakeHttp, url: str, item, **kw) -> FakeHttp:
    if isinstance(item, dict) and item.get("_envelope"):
        body = item["body"]
        extra = {"json": body} if isinstance(body, (dict, list)) else {"text": body}
        return http.add("GET", url, status=item["status"], headers=item.get("headers"), **extra, **kw)
    return http.add("GET", url, json=item, **kw)


def ok_http() -> FakeHttp:
    http = add(FakeHttp(), BUCKETS, fx("buckets_ok.json"), match_headers={"Authorization": f"Bearer {KEY}"})
    return add(http, FILES, fx("files_ok.json"))


def run(http: FakeHttp, entity: str = "keyword:exemplo", **kw):
    kw.setdefault("keys", KEYS)
    kw.setdefault("options", OPTS)
    return run_module(GrayhatWarfare, entity, http, **kw)


def test_metadata_follows_the_council_decision():
    cls = GrayhatWarfare
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.sensitive) == ("key-terms", False, "community", True)
    assert cls.requires_keys == ("grayhat",) and cls.hosts == ("buckets.grayhatwarfare.com",)
    assert "V3LUM_GRAYHAT_KEY" in config.key_registry()["grayhat"].env


def test_only_the_index_searches_can_be_built():
    assert BUCKETS == "https://buckets.grayhatwarfare.com/api/v2/buckets?keywords=exemplo&start=0&limit=100"
    assert "limit=100" in grayhat_url("files", "exemplo", limit=5000)
    for bad in ("download", "file", "objects", "../files"):
        with pytest.raises(ValueError):
            grayhat_url(bad, "exemplo")
    for bad_term in ("https://exemplo-backup.s3.amazonaws.com/x", "a/b", "", "x" * 101):
        with pytest.raises(ValueError):
            grayhat_url("files", bad_term)
    names = [n for n in dir(mod) if any(w in n.lower() for w in ("download", "fetch_object", "list_objects"))]
    assert names == []


@pytest.mark.parametrize("name, expected, kinds", [
    ("relatorio_123.456.789-00.pdf", "relatorio_[cpf].pdf", ["cpf"]),
    ("export_user@example.com.csv", "[email].csv", ["email"]),  # over-masks the joined prefix on purpose
    ("Maria_Souza_contrato.docx", "[name]_contrato.docx", ["name"]),
    ("curriculo-joao.pdf", "[personal-doc].pdf", ["personal-doc"]),
    ("contatos +55 11 5555-0102.xlsx", "contatos [phone].xlsx", ["phone"]),
    ("dir/sub/logo.png", "logo.png", []),
])
def test_file_names_are_masked_before_storage(name, expected, kinds):
    assert mask_file_name(name) == (expected, kinds)


def test_names_counts_and_unverified_candidates():
    http = ok_http()
    res = run(http)
    assert res.status is Status.OK, res.error
    summary = res.attributes["grayhat_files_summary"]
    assert summary["total"] == 5 and summary["extension_counts"]["pdf"] == 2 and summary["scrubbed_count"] == 4
    candidates = res.attributes["grayhat_buckets"]
    assert {c["bucket"] for c in candidates} == {"exemplo-backup.s3.amazonaws.com", "exemplostorage.blob.core.windows.net/public"}
    assert all(c["ownership"] == "exists, ownership unverified" for c in candidates)
    assert not res.pivots  # cond 4: only confirmed own buckets pivot
    rows = res.attributes["cloud_buckets"]
    assert rows and all(r["attribution"] == "permutation" for r in rows)  # CR24: unattributed (INFO)
    bucket_finding = next(f for f in res.findings if f.title.startswith("Brand-named"))
    assert bucket_finding.severity.name == "LOW" and "ownership_unverified" in bucket_finding.tags
    dump = json.dumps({"a": res.attributes, "raw": res.raw, "f": [f.to_dict() for f in res.findings]})
    for leaked in ("123.456.789-00", "user@example.com", "Maria", "Souza", "curriculo", "fullPath", "s3.amazonaws.com/rh", "https://exemplo-backup"):
        assert leaked not in dump, leaked
    http.assert_hosts_within(GrayhatWarfare)
    assert_no_secret(KEY, res.to_dict())


def test_own_bucket_on_a_verified_domain_pivots_without_expansion():
    org = OrgProfile.from_dict({"domains": [{"name": "exemplo-backup.s3.amazonaws.com", "verification": "attested",
                                             "attested_by": "Analyst Example", "attested_date": "2026-11-20"}],
                                "brands": [{"keyword": "Exemplo"}]})
    res = run(ok_http(), org_profile=org)
    assert res.status is Status.OK
    (pivot,) = res.pivots
    assert pivot.expand is False and pivot.relation == "candidate_bucket" and pivot.entity.value.startswith("https://exemplo-backup")
    assert next(f for f in res.findings if f.title.startswith("Brand-named")).severity.name == "MEDIUM"


def test_pivots_need_an_org_brand_or_domain():
    http = FakeHttp()
    res = run(http, is_seed=False, depth=1, provenance=(("domain:example.com", "related", "x"),))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []
    org = OrgProfile.from_dict({"brands": [{"keyword": "Exemplo"}]})
    res = run(ok_http(), is_seed=False, depth=1, org_profile=org)
    assert res.status is Status.OK


def test_domain_uses_its_registrable_label():
    http = add(FakeHttp(), grayhat_url("buckets", "exemplo"), fx("buckets_ok.json"))
    add(http, grayhat_url("files", "exemplo"), fx("files_ok.json"))
    assert run(http, "domain:www.exemplo.com.br").status is Status.OK


def test_empty_index_answer():
    http = add(FakeHttp(), BUCKETS, {"meta": {"results": 0}, "buckets": []})
    add(http, FILES, fx("empty.json"))
    res = run(http)
    assert res.status is Status.EMPTY and "index coverage only" in res.error


def test_key_errors_rate_limits_challenges_and_error_bodies():
    http = FakeHttp()
    assert run(http, keys={}).status is Status.NEEDS_KEY and http.calls == []
    assert run(add(FakeHttp(), BUCKETS, fx("needs_key_401.json"))).status is Status.NEEDS_KEY
    assert run(add(FakeHttp(), BUCKETS, fx("rate_limited_429.json"), times=2)).status is Status.RATE_LIMITED
    page = (FIXDIR / "blocked_challenge.html").read_text()
    res = run(FakeHttp().add("GET", BUCKETS, status=403, text=page, headers={"content-type": "text/html"}))
    assert res.status is Status.BLOCKED
    res = run(FakeHttp().add("GET", BUCKETS, json={"error": "Something went wrong"}))
    assert res.status is Status.ERROR
    res = run(FakeHttp().add("GET", BUCKETS, text="{not json", headers={"content-type": "application/json"}))
    assert res.status is Status.ERROR
    http = add(FakeHttp(), BUCKETS, fx("buckets_ok.json"))
    http.add("GET", FILES, status=502, text="bad gateway", times=2)
    assert run(http).status is Status.ERROR
