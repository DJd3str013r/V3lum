"""Offline tests for the ACTIVE cloud_buckets module (P282).

Classification is tested directly from the trimmed research fixtures. The end-to-end ACTIVE path
runs over FakeHttp with a scope that lists the cloud-provider endpoints (standing in for the
provider-endpoint allow-list of FC2, not yet in core): the module never contacts a real provider.
"""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace
from typing import Any

import pytest

from tests.fakes import FakeClock, FakeHttp, add_dns, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.http import Cancelled
from v3lum.core.models import Opsec, Status
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon.cloud_buckets import (
    PROVIDER_RPS,
    CloudBuckets,
    _ProviderPacer,
    bucket_names,
    classify_bucket_response,
)

REF = "PENTEST-2026-282"
WINDOW = ("2026-11-26T00:00:00Z", "2026-11-27T00:00:00Z")


def _fixture(name: str) -> dict[str, Any]:
    return module_fixture("cloud_buckets", name)


def _classify(name: str) -> dict[str, Any]:
    d = _fixture(name)["response"]
    return classify_bucket_response(d["status"], d["body"].encode(), d.get("headers"))


# --------------------------------------------------------------------------------------
# pure classification (FC4/FC5/FC7)
# --------------------------------------------------------------------------------------


def test_semantics_from_fixtures():
    assert _classify("s3_absent.json")["state"] == "absent"
    assert _classify("gcs_absent.json")["state"] == "absent"
    assert _classify("s3_private_accessdenied.json")["state"] == "exists_private"
    assert _classify("s3_private_allaccessdisabled.json")["state"] == "exists_private"
    assert _classify("s3_redirect_region.json")["state"] == "exists_other_region"
    assert _classify("s3_public_listing.json")["state"] == "public_listing"
    assert _classify("gcs_public_listing.json")["state"] == "public_listing"


def test_public_listing_keeps_only_the_extension_never_the_key():
    result = _classify("s3_public_listing.json")
    assert result["state"] == "public_listing"
    assert result["sampled_extension"] == ".pdf"
    # the object key name from the fixture never appears in the classifier output
    assert "report.pdf" not in json.dumps(result)
    assert "exports" not in json.dumps(result)


def test_403_without_documented_body_is_could_not_test():
    assert _classify("generic_403_blocked.json")["state"] == "could_not_test"


def test_rate_limit_and_malformed_are_tri_state():
    assert _classify("rate_limited_503.json")["state"] == "could_not_test"
    assert _classify("malformed_200_html.json")["state"] == "could_not_verify"  # never 'absent'


def test_xxe_doctype_body_is_refused_not_parsed():
    evil = b'<?xml version="1.0"?><!DOCTYPE Error [<!ENTITY x SYSTEM "file:///etc/passwd">]><Error><Code>&x;</Code></Error>'
    out = classify_bucket_response(403, evil)
    assert out["state"] == "could_not_test"  # no <Code> extracted from a DOCTYPE body


def test_candidate_names_capped_and_sanitised():
    names = bucket_names(["Example Corp", "acme.com"], cap=10)
    assert len(names) == 10
    assert all(3 <= len(n) <= 63 for n in names)
    assert all(all(c.isalnum() or c == "-" for c in n) for n in names)
    assert "example-corp" in names


# --------------------------------------------------------------------------------------
# ACTIVE contact under the current core: the cloud-provider endpoints are PUBLIC SUFFIXES,
# so they can never be scope targets (Scope.validate refuses them). Until core adds the
# provider-endpoint allow-list (FC2; see docs/backlog/p9-G13-2.md and core_requests), every
# probe is refused by the scope binding and the module reports tri-state 'could not test'
# (never 'absent'/'safe', FC7). This test proves the safe refusal and that NO bucket probe
# ever leaves against a real provider.
# --------------------------------------------------------------------------------------


def _scope() -> Scope:
    return Scope.from_dict({
        "authorization_ref": REF,
        "owner": "Bucket engagement",
        "contacts": ["soc@acme.test"],
        "ticket": "PT-282",
        "window_start": WINDOW[0],
        "window_end": WINDOW[1],
        "targets": {"domains": ["acme.test", "*.acme.test"]},
    })


def _options(scope: Scope) -> ScanOptions:
    return ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF, scope=scope,
                       include={"cloud_buckets"}, threads=1, save_evidence=False)


def test_endpoints_out_of_scope_is_could_not_test_and_never_contacted():
    clock = FakeClock()
    http = FakeHttp(clock=clock)  # no routes: any request that leaves would raise UnexpectedRequest
    rt = make_runtime(http, clock=clock, settings={"cloud_buckets_max_names": 2})
    res = run_module(CloudBuckets, "keyword:examplecorp", runtime=rt, options=_options(_scope()))
    assert res.status is Status.SKIPPED and res.reason_code == "scope"  # not tested, never empty/absent (FC7)
    assert "could not test" in res.error.lower() and "scope" in res.error.lower()
    assert [c for c in http.calls if "amazonaws" in c["url"] or "googleapis" in c["url"] or "digitalocean" in c["url"]] == []
    scan = res.attributes["cloud_bucket_scan"]
    assert scan["existing"] == 0 and scan["could_not_test"] == scan["tested"]


# --------------------------------------------------------------------------------------
# emission logic (FC6 ownership-before-severity, FC8), tested directly without network
# --------------------------------------------------------------------------------------


def _emit_result(state: str, attribution: str, *, extension: str | None = None) -> Any:
    from v3lum.core.entities import Entity, EntityType

    mod = CloudBuckets()
    res = mod.result(Entity.make(EntityType.KEYWORD, "examplecorp"))
    url = "https://examplecorp.s3.amazonaws.com/?max-keys=1"
    mod._emit(res, "examplecorp", "s3", {"state": state, "sampled_extension": extension}, attribution, url)
    return res


def test_public_listing_attributed_is_high():
    res = _emit_result("public_listing", "scope_file", extension=".pdf")
    high = [f for f in res.findings if f.severity.name == "HIGH"]
    assert high and "public cloud bucket" in high[0].title.lower()
    assert list(high[0].attack) == ["T1530"]
    assert {p.entity.value for p in res.pivots} == {"https://examplecorp.s3.amazonaws.com/"}
    assert all(p.expand is False for p in res.pivots)


def test_public_listing_unattributed_is_low_owner_unknown():
    res = _emit_result("public_listing", "permutation", extension=".pdf")
    low = [f for f in res.findings if f.severity.name == "LOW"]
    assert low and "owner unknown" in low[0].title.lower()
    assert not [f for f in res.findings if f.severity.name == "HIGH"]  # never HIGH, never 'ours'


def test_private_bucket_is_low():
    res = _emit_result("exists_private", "dns")
    low = [f for f in res.findings if f.severity.name == "LOW"]
    assert low and "private" in low[0].title.lower()


def test_record_and_attribute_shape_match_the_vocabulary():
    mod = CloudBuckets()
    record = mod._record("examplecorp", "s3", {"state": "exists_other_region", "sampled_extension": None}, "permutation")
    attr = mod._attr(record)
    assert attr["state"] == "redirect"  # vocab enum uses 'redirect' for exists-in-another-region
    assert set(attr) == {"bucket", "provider", "state", "attribution", "evidence"}


# --------------------------------------------------------------------------------------
# ACTIVE path with bucket hosts the scope file lists (FC2/FC6 'listed in the scope file')
# --------------------------------------------------------------------------------------

BUCKET_IP = "93.184.216.34"
PUBLIC_HOST = "acme-backup.s3.amazonaws.com"
PRIVATE_HOST = "acme.s3.amazonaws.com"


def _listed_scope(*hosts: str) -> Scope:
    return Scope.from_dict({
        "authorization_ref": REF,
        "owner": "Bucket engagement",
        "contacts": ["soc@acme.test"],
        "ticket": "PT-282",
        "window_start": WINDOW[0],
        "window_end": WINDOW[1],
        "targets": {"domains": ["acme.test", "*.acme.test", *hosts]},
        "shared_infra_hosts": list(hosts),
    })


def _bucket_route(http: FakeHttp, host: str, fixture: str) -> None:
    d = _fixture(fixture)["response"]
    add_dns(http, host, "A", [BUCKET_IP])
    add_dns(http, host, "AAAA", [])
    http.add("GET", f"https://{host}/?max-keys=1", status=d["status"], body=d["body"].encode(), headers=d.get("headers") or {})


def _listed_run(http: FakeHttp, scope: Scope, **kw: Any) -> Any:
    rt = make_runtime(http, clock=http.clock, settings={"cloud_buckets_max_names": 2})
    return run_module(CloudBuckets, "domain:acme.test", runtime=rt, options=_options(scope), **kw)


def test_scope_listed_public_bucket_is_high_and_private_is_low():
    http = FakeHttp(clock=FakeClock())
    _bucket_route(http, PUBLIC_HOST, "s3_public_listing.json")
    _bucket_route(http, PRIVATE_HOST, "s3_private_accessdenied.json")
    res = _listed_run(http, _listed_scope(PUBLIC_HOST, PRIVATE_HOST))
    assert res.status is Status.OK
    high = [f for f in res.findings if f.severity.name == "HIGH"]
    assert len(high) == 1 and "acme-backup" in high[0].title  # attributed by the scope file (FC6)
    low = [f for f in res.findings if f.severity.name == "LOW"]
    assert any("private" in f.title.lower() for f in low)  # 403 AccessDenied XML = exists-private (FC4)
    # FC5: the sampled key's extension only, never the object key name
    assert "report.pdf" not in json.dumps(res.to_dict(), default=str) and "exports/" not in json.dumps(res.to_dict(), default=str)
    scan = res.attributes["cloud_bucket_scan"]
    assert scan["existing"] == 2 and scan["tested"] == 6 and scan["could_not_test"] == 4  # unlisted hosts: refused, never absent
    # only the two listed bucket hosts were contacted (no request left for the unlisted candidates)
    contacted = {c["url"].split("/")[2] for c in http.calls if "max-keys" in c["url"]}
    assert contacted == {PUBLIC_HOST, PRIVATE_HOST}


def test_challenge_from_listed_bucket_is_could_not_test():
    http = FakeHttp(clock=FakeClock())
    _bucket_route(http, PUBLIC_HOST, "generic_403_blocked.json")
    res = _listed_run(http, _listed_scope(PUBLIC_HOST))
    assert res.status is Status.BLOCKED and not res.findings  # never absent / exists-private (FC7)


def test_pivots_and_text_extracted_entities_never_probed():
    for kw in ({"is_seed": False, "depth": 1}, {"provenance": [("file:notes.txt", "mentions", "ioc_extract")]}):
        http = FakeHttp(clock=FakeClock())
        _bucket_route(http, PUBLIC_HOST, "s3_public_listing.json")
        res = _listed_run(http, _listed_scope(PUBLIC_HOST), **kw)
        assert res.status is Status.SKIPPED  # FC1
        assert not [c for c in http.calls if "max-keys" in c["url"]]
    assert CloudBuckets.run_on == "seeds"


def _fake_ctx(scope: Any, brands: list[str]) -> Any:
    org = SimpleNamespace(is_empty=False, brand_terms=lambda: list(brands))
    return SimpleNamespace(options=SimpleNamespace(scope=scope), org=org)


def test_only_scope_confirmed_brand_terms_become_candidates():
    from v3lum.core.entities import Entity, EntityType

    scope = _listed_scope()  # domains acme.test, *.acme.test
    tokens = CloudBuckets()._base_tokens(Entity.make(EntityType.DOMAIN, "acme.test"), _fake_ctx(scope, ["acme", "zetacorp"]))
    assert "acme" in tokens
    assert "zetacorp" not in tokens  # an org brand the scope file does not confirm (FC2)


def test_brand_named_bucket_is_never_attributed_without_scope_listing():
    # FC6: matching an org brand term is a permutation guess (owner unknown), never 'ours'
    mod = CloudBuckets()
    url = "https://acme.s3.amazonaws.com/?max-keys=1"
    assert mod._attribution("acme", url, _listed_scope(), _fake_ctx(_listed_scope(), ["acme"])) == "permutation"
    assert mod._attribution("acme", url, _listed_scope("acme.s3.amazonaws.com"), None) == "scope_file"
    res = _emit_result("public_listing", mod._attribution("acme", url, _listed_scope(), None), extension=".csv")
    assert not [f for f in res.findings if f.severity.name == "HIGH"]


def test_provider_pacing_is_three_per_second_per_provider():
    clock = FakeClock()
    ctx = SimpleNamespace(runtime=SimpleNamespace(clock=clock), remaining=lambda: None, cancel_event=threading.Event())
    pacer = _ProviderPacer(ctx, PROVIDER_RPS)
    start = clock.monotonic()
    for _ in range(4):
        pacer.wait("s3")
    assert clock.monotonic() - start >= 3 * (1.0 / PROVIDER_RPS) - 1e-6  # 4 requests -> >= 1 s at 3 req/s
    mid = clock.monotonic()
    pacer.wait("gcs")  # another provider is not held back by s3's pacing
    assert clock.monotonic() == mid


def test_provider_pacing_honours_kill_switch():
    clock = FakeClock()
    event = threading.Event()
    ctx = SimpleNamespace(runtime=SimpleNamespace(clock=clock), remaining=lambda: None, cancel_event=event)
    pacer = _ProviderPacer(ctx, PROVIDER_RPS)
    pacer.wait("s3")
    event.set()
    with pytest.raises(Cancelled):
        pacer.wait("s3")


def test_health_selftest_offline():
    hc = CloudBuckets.health_check()
    assert hc.offline is True
    rt = make_runtime()
    ctx = rt.context(CloudBuckets, ScanOptions(mode=Opsec.ACTIVE), run=None)
    assert hc.selftest(ctx).status == "ok"
