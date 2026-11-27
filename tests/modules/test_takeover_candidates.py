"""takeover_candidates (P276, PASSIVE): DoH CNAME chains, two-resolver NXDOMAIN consensus, NODATA zones,
fingerprint statuses and the rule-5 outcomes. Fixtures: tests/fixtures/takeover_candidates/ (DoH
captures in the Google/Cloudflare JSON shapes, the pinned upstream fingerprints.json)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.fakes import FIXTURES, DeadHttp, FakeHttp, add_dns, doh_url, make_runtime, run_module
from v3lum.core.datasets import DataStore
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.models import Confidence, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.pentest_recon import subdomain_takeover as st
from v3lum.modules.pentest_recon.subdomain_takeover import TakeoverCandidates

FIX = Path(FIXTURES) / "takeover_candidates"
UPSTREAM = FIX / "fingerprints_upstream.json"


def fx(name: str) -> dict:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def pinned_rows(monkeypatch):
    """Every test reads the rows of the pinned upstream file (fixture), whatever is installed."""
    rows = st.parse_fingerprints(UPSTREAM.read_text(encoding="utf-8"))["rows"]
    monkeypatch.setattr(st, "load_rows", lambda ctx: (rows, "fixture fingerprints_upstream.json"))
    return rows


def doh(http: FakeHttp, name: str, rtype: str, body: dict, provider: str = "google") -> None:
    http.add("GET", doh_url(name, rtype, provider=provider), json=body)


def nx(name: str) -> dict:
    return {"Status": 3, "Answer": []}


def test_dangling_elastic_beanstalk_is_a_high_probable_candidate_on_a_typed_seed():
    cap = fx("doh_dangling_eb.json")
    target = "exemplo-app.us-east-1.elasticbeanstalk.com"
    http = FakeHttp()
    doh(http, "app.example.com", "A", cap["google"])
    doh(http, target, "A", nx(target))
    doh(http, target, "A", nx(target), provider="cloudflare")
    res = run_module(TakeoverCandidates, "domain:app.example.com", http)
    assert res.status is Status.OK
    check = res.attributes["takeover_check"]
    assert check["state"] == "candidate" and check["service"] == "AWS/Elastic Beanstalk"
    assert check["chain"] == ["app.example.com", target]
    assert check["wording"].startswith("possible takeover candidate (DNS evidence only): app.example.com -> " + target)
    dangling = res.attributes["cname_dangling"]
    assert dangling["confirmed"] is True and dangling["status"] == "NXDOMAIN" and dangling["target"] == target
    finding = res.findings[0]
    assert finding.severity.label == "high" and finding.confidence_label is Confidence.PROBABLE
    assert finding.attack == ["T1584.001"] and "takeover" in finding.tags and "third_party" not in finding.tags
    assert "never claims or registers" in finding.description
    pivot = res.pivots[0]
    assert (pivot.entity.value, pivot.relation, pivot.expand) == (target, "cname_to", False)
    # DoH only: nothing but the two resolvers was contacted (passive module)
    assert http.hosts() <= {"dns.google", "cloudflare-dns.com"}
    http.assert_hosts_within(TakeoverCandidates, extra=("dns.google", "cloudflare-dns.com"))


def test_two_hop_azure_chain_matches_the_deepest_service():
    cap = fx("doh_dangling_azure_2hop.json")
    target = "exemplo-portal.azurewebsites.net"
    http = FakeHttp()
    doh(http, "portal.example.com", "A", cap["google"])
    doh(http, target, "A", nx(target))
    doh(http, target, "A", nx(target), provider="cloudflare")
    res = run_module(TakeoverCandidates, "domain:portal.example.com", http)
    check = res.attributes["takeover_check"]
    assert check["service"] == "Microsoft Azure" and check["chain"][-1] == target and len(check["chain"]) == 3
    assert res.findings[0].severity.label == "high"


def test_not_vulnerable_service_is_dangling_but_never_reported():
    cap = fx("doh_dangling_elb_not_vulnerable.json")
    target = "exemplo-lb-123.sa-east-1.elb.amazonaws.com"
    http = FakeHttp()
    doh(http, "lb.example.com", "A", cap["google"])
    doh(http, target, "A", nx(target))
    doh(http, target, "A", nx(target), provider="cloudflare")
    res = run_module(TakeoverCandidates, "domain:lb.example.com", http)
    assert res.attributes["takeover_check"]["state"] == "not_reported"
    assert res.attributes["cname_dangling"]["confirmed"] is True
    assert res.findings == []


def test_dangling_cname_to_an_unknown_service_is_an_info_hygiene_fact():
    cap = fx("doh_dangling_unknown_service.json")
    target = "legacy-host.example.net"
    http = FakeHttp()
    doh(http, "legacy.example.com", "A", cap["google"])
    doh(http, target, "A", nx(target))
    doh(http, target, "A", nx(target), provider="cloudflare")
    res = run_module(TakeoverCandidates, "domain:legacy.example.com", http)
    assert res.attributes["takeover_check"]["state"] == "dangling_no_fingerprint"
    assert [f.severity.label for f in res.findings] == ["info"]


def test_resolving_s3_target_needs_the_active_verifier_and_raises_no_finding():
    cap = fx("doh_resolves_s3.json")
    http = FakeHttp()
    doh(http, "assets.example.com", "A", cap["google"])
    res = run_module(TakeoverCandidates, "domain:assets.example.com", http)
    check = res.attributes["takeover_check"]
    assert check["state"] == "needs_active_verify" and check["service"] == "AWS/S3"
    assert "takeover_verify" in check["reason"] and res.findings == []
    assert "cname_dangling" not in res.attributes


def test_nodata_target_in_a_nodata_zone_is_could_not_verify(monkeypatch):
    cap = fx("doh_nodata_target.json")
    http = FakeHttp()
    doh(http, "cdn.example.com", "A", cap["google"])
    probe = fx("doh_zone_probe_nodata.json")
    http.add("GET", re.compile(r"^https://dns\.google/resolve\?name=[a-z0-9]+\.zone-cf\.example\.net&type=(A|AAAA)"), json=probe)
    res = run_module(TakeoverCandidates, "domain:cdn.example.com", http)
    assert res.status is Status.ERROR
    assert "NODATA proves nothing" in res.error and "not vulnerable" in res.error
    assert res.findings == []


def test_resolvers_disagreeing_is_could_not_verify():
    cap = fx("doh_resolvers_disagree.json")
    target = "exemplo-app.us-east-1.elasticbeanstalk.com"
    http = FakeHttp()
    doh(http, "app.example.com", "A", cap["google"])
    doh(http, target, "A", nx(target))
    add_dns(http, target, "A", ["93.184.216.80"], provider="cloudflare")
    res = run_module(TakeoverCandidates, "domain:app.example.com", http)
    assert res.status is Status.ERROR and "disagree" in res.error
    assert res.findings == [] and "cname_dangling" not in res.attributes


def test_unconfirmed_nxdomain_is_could_not_verify():
    cap = fx("doh_dangling_eb.json")
    target = "exemplo-app.us-east-1.elasticbeanstalk.com"
    http = FakeHttp()
    doh(http, "app.example.com", "A", cap["google"])
    doh(http, target, "A", nx(target))
    doh(http, target, "A", {"Status": 2, "Answer": []}, provider="cloudflare")  # second resolver SERVFAIL
    res = run_module(TakeoverCandidates, "domain:app.example.com", http)
    assert res.status is Status.ERROR and "not confirmed by a second resolver" in res.error


@pytest.mark.parametrize("kind", ["servfail", "refused"])
def test_servfail_or_refused_on_the_chain_is_never_not_vulnerable(kind):
    http = FakeHttp()
    doh(http, "app.example.com", "A", {"Status": 2 if kind == "servfail" else 5, "Answer": []})
    res = run_module(TakeoverCandidates, "domain:app.example.com", http)
    assert res.status is Status.ERROR
    assert "could not verify" in res.error and res.findings == []


def test_servfail_capture_is_parsed_as_could_not_verify():
    http = FakeHttp()
    doh(http, "app.example.com", "A", fx("doh_servfail.json"))
    assert run_module(TakeoverCandidates, "domain:app.example.com", http).status is Status.ERROR


def test_dead_network_is_error_never_empty():
    res = run_module(TakeoverCandidates, "domain:app.example.com", DeadHttp())
    assert res.status is Status.ERROR


def test_challenge_or_429_from_the_resolvers_is_could_not_verify():
    http = FakeHttp()
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http.add("GET", doh_url("app.example.com", "A"), status=403, text=page)
    http.add("GET", doh_url("app.example.com", "A", provider="cloudflare"), status=429, text="slow down")
    res = run_module(TakeoverCandidates, "domain:app.example.com", http)
    assert res.status is Status.ERROR and res.findings == []


def test_malformed_doh_body_is_could_not_verify():
    http = FakeHttp()
    http.add("GET", doh_url("app.example.com", "A"), text="<html>not json</html>")
    http.add("GET", doh_url("app.example.com", "A", provider="cloudflare"), text="{broken")
    assert run_module(TakeoverCandidates, "domain:app.example.com", http).status is Status.ERROR


def test_no_cname_is_empty():
    http = FakeHttp()
    doh(http, "example.com", "A", fx("doh_no_cname.json"))
    res = run_module(TakeoverCandidates, "domain:example.com", http)
    assert res.status is Status.EMPTY and "no CNAME" in res.error


def test_pivot_outside_a_typed_apex_is_not_applicable():
    res = run_module(TakeoverCandidates, "domain:app.example.com", FakeHttp(), is_seed=False)
    assert (res.status, res.reason_code) == (Status.SKIPPED, "not_applicable")


def test_own_asset_pivot_is_checked_and_high():
    cap = fx("doh_dangling_eb.json")
    target = "exemplo-app.us-east-1.elasticbeanstalk.com"
    http = FakeHttp()
    doh(http, "app.example.com", "A", cap["google"])
    doh(http, target, "A", nx(target))
    doh(http, target, "A", nx(target), provider="cloudflare")
    org = OrgProfile.from_dict({"org": {"name": "Exemplo"}, "domains": [{"name": "example.com", "verification": "attested",
                                                                        "attested_by": "analyst", "attested_date": "2026-11-01"}]})
    res = run_module(TakeoverCandidates, "domain:app.example.com", http, is_seed=False, org_profile=org)
    assert res.status is Status.OK and res.findings[0].severity.label == "high"
    assert res.links == []  # own asset: no third-party security.txt contact


def test_name_under_a_typed_apex_is_checked_but_info_and_third_party():
    """A pivot under the apex the analyst typed is eligible (cond 3); not own and not a typed seed: INFO
    (cond 4), with the owner's security.txt as a manual link (cond 9)."""
    cap = fx("doh_dangling_eb.json")
    target = "exemplo-app.us-east-1.elasticbeanstalk.com"
    http = FakeHttp()
    doh(http, "app.example.com", "A", cap["google"])
    doh(http, target, "A", nx(target))
    doh(http, target, "A", nx(target), provider="cloudflare")
    rt = make_runtime(http)
    graph = Graph(noise_check=False)
    graph.add_node(Entity.make(T.DOMAIN, "example.com"), seed=True)
    rt.policy_context = SimpleNamespace(graph=graph)
    res = run_module(TakeoverCandidates, "domain:app.example.com", http, runtime=rt, is_seed=False, depth=1)
    assert res.status is Status.OK
    finding = res.findings[0]
    assert finding.severity.label == "info" and "third_party" in finding.tags
    assert any("security.txt" in label and url == "https://example.com/.well-known/security.txt" for label, url in res.links)
    # a SAN affiliate (another registrable domain) under no typed apex stays out
    other = run_module(TakeoverCandidates, "domain:app.example.org", FakeHttp(), runtime=rt, is_seed=False, depth=1)
    assert (other.status, other.reason_code) == (Status.SKIPPED, "not_applicable")


def test_edge_case_row_gives_medium(monkeypatch, pinned_rows):
    rows = [*pinned_rows, {"service": "Edgy", "status": "edge_case", "cname_suffixes": ["edgy.example.net"], "ip_targets": [],
                           "kind": "nxdomain", "patterns": [], "regex": False, "http_status": None, "reportable": True,
                           "level": "medium", "docs": None}]
    monkeypatch.setattr(st, "load_rows", lambda ctx: (rows, "synthetic"))
    http = FakeHttp()
    doh(http, "old.example.com", "A", {"Status": 3, "Answer": [{"name": "old.example.com.", "type": 5, "TTL": 60, "data": "x.edgy.example.net."}]})
    doh(http, "x.edgy.example.net", "A", nx("x"))
    doh(http, "x.edgy.example.net", "A", nx("x"), provider="cloudflare")
    res = run_module(TakeoverCandidates, "domain:old.example.com", http)
    assert res.findings[0].severity.label == "medium"


# ---------------------------------------------------------------------------------- fingerprint helper
def test_parse_upstream_fingerprints_counts_and_quirks(pinned_rows):
    parsed = st.parse_fingerprints(UPSTREAM.read_text(encoding="utf-8"))
    assert parsed["counts"] == {"vulnerable": 36, "not_vulnerable": 26, "edge_case": 14}
    by = {r["service"]: r for r in parsed["rows"]}
    assert by["AWS/Elastic Beanstalk"]["kind"] == "nxdomain" and by["AWS/Elastic Beanstalk"]["level"] == "candidate"
    assert by["Helprace"]["kind"] == "http_status" and by["Helprace"]["http_status"] == 301
    assert by["Ghost"]["regex"] is True
    assert by["Vercel"]["cname_suffixes"] == []  # an example URL is never a CNAME suffix
    assert any(r["ip_targets"] for r in parsed["rows"])  # IP addresses listed under 'cname' are A targets
    assert by["AWS/Load Balancer (ELB)"]["reportable"] is False


@pytest.mark.parametrize("raw", ["", "<html>404</html>", "404: Not Found", "{broken", "[]", json.dumps({"x": 1})])
def test_parse_fingerprints_never_raises(raw):
    parsed = st.parse_fingerprints(raw)
    assert parsed["ok"] is False and parsed["error"]


def test_match_service_is_label_wise(pinned_rows):
    assert st.match_service("bucket.s3.amazonaws.com", pinned_rows)["service"] == "AWS/S3"
    assert st.match_service("evil-s3.amazonaws.com.attacker.example", pinned_rows) is None
    assert st.match_service("nots3.amazonaws.com", pinned_rows) is None


def test_bundled_copy_parses_when_present():
    store = DataStore(None)
    if not store.bundled_exists(st.BUNDLED_FINGERPRINTS):
        pytest.skip("bundled WP23 copy not present")
    parsed = st.parse_fingerprints(store.bundled_json(st.BUNDLED_FINGERPRINTS))
    assert parsed["ok"] and parsed["counts"].get("vulnerable", 0) >= 30


def test_pinned_dataset_installs_only_when_its_bytes_match_the_pin():
    """P276 cond 2: refreshed only by `v3lum data update`, pinned by SHA-256 (data/active_locks)."""
    body = UPSTREAM.read_bytes()
    http = FakeHttp().add("GET", st.FINGERPRINTS_URL, body=body, headers={"content-type": "text/plain; charset=utf-8"})
    rt = make_runtime(http)
    result = rt.data.update(st.FINGERPRINTS_DATASET)
    assert result.status in ("updated", "ok", "installed"), result
    assert result.new_sha256 == st.FINGERPRINTS_SHA256
    rows, origin = st.__dict__["parse_fingerprints"](rt.data.scoped().fetch_text(st.FINGERPRINTS_DATASET))["rows"], "dataset"
    assert len(rows) == 76 and origin == "dataset"
    # a changed upstream file is staged, never installed blind (diff summary first)
    changed = json.loads(body)[:-1]
    http2 = FakeHttp().add("GET", st.FINGERPRINTS_URL, body=json.dumps(changed).encode(), headers={"content-type": "text/plain"})
    rt2 = make_runtime(http2)
    again = rt2.data.update(st.FINGERPRINTS_DATASET)
    assert again.status == "needs_accept" and "entries 76 -> 75" in again.diff_summary


def test_golden_domain_acceptance_routes_replay():
    routes = json.loads((Path(FIXTURES) / "acceptance" / "domain" / "takeover_candidates.json").read_text(encoding="utf-8"))
    assert routes["schema"] == "v3lum.acceptance_routes/1" and routes["module"] == "takeover_candidates"
    http = FakeHttp()
    for r in routes["routes"]:
        body = {"json": r["json"]} if "json" in r else {"text": r["text"]}
        http.add(r["method"], r["url"], status=r["status"], headers=r.get("headers"), **body)
    res = run_module(TakeoverCandidates, "domain:example.com", http)
    assert res.status is Status.EMPTY and not res.findings  # example.com has no CNAME: not a candidate
    assert len(http.calls) == len(routes["routes"])
