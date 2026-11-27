"""protective_dns (P020, default module): Cloudflare 1.1.1.2 / 1.1.1.3 (JSON DoH) and Quad9 (RFC 8484), offline.

Fixtures in tests/fixtures/protective_dns/ (batch p2-G01-3 prep, recorded 2026-11-25/26 from a datacenter egress):
the research Cloudflare security/family answers for example.com and live ones (A, a random-label NODATA, a nic.br
NXDOMAIN with SOA), live Quad9 RFC 8484 answers (wire bytes, base64) for example.com, a random-label NODATA and a
nic.br NXDOMAIN carrying the zone SOA, the live Google reference answers (the Quad9 :5053 JSON port resets behind the proxy: wire format only); synthetic
block forms (Cloudflare 0.0.0.0 / ::, Quad9 NXDOMAIN without SOA, an RFC 8914 EDE 15 'Blocked' answer), a reference
resolving the blocked name, REFUSED/SERVFAIL answers and a client timeout. No real block was observed: every
benign value resolves, so the block forms come from vendor documentation and the research records.
"""

from __future__ import annotations

import base64
import json
import re

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, doh_url, make_runtime, module_fixture, run_module
from v3lum.core.datasets import DataStore
from v3lum.core.http import NetworkError
from v3lum.core.models import Severity, Status
from v3lum.modules.domain_dns import protective_dns as pd
from v3lum.modules.domain_dns.protective_dns import DEFAULT_RESOLVERS, ProtectiveDns
from v3lum.modules.domain_dns.protective_dns_extra import EXTRA_RESOLVERS

SEC = "https://security.cloudflare-dns.com/dns-query?name={n}&type=A"
FAM = "https://family.cloudflare-dns.com/dns-query?name={n}&type=A"
QUAD9 = re.compile(r"^https://dns\.quad9\.net/dns-query\?dns=")
BAD = "malware-test.example.net"


def fx(name):
    return module_fixture("protective_dns", name)


def wire(name):
    return dict(body=base64.b64decode(fx(name)["wire_b64"]), headers={"content-type": "application/dns-message"})


def answer(name, *ips, ttl=300):
    return {"Status": 0, "Answer": [{"name": name, "type": 1, "TTL": ttl, "data": ip} for ip in ips]}


def http_for(name, *, sec, fam, quad9, ref):
    http = FakeHttp()
    if sec is not None:
        http.add("GET", SEC.format(n=name), **sec)
    if fam is not None:
        http.add("GET", FAM.format(n=name), **fam)
    if quad9 is not None:
        http.add("GET", QUAD9, **quad9)
    if ref is not None:
        http.add("GET", doh_url(name, "A", provider="cloudflare"), **ref)  # hostile=True: the ECS-free resolver first
    return http


def verdicts(res):
    return {v["resolver"]: v["verdict"] for v in res.attributes["protective_dns"]["verdicts"]}


BLOCKED_REF = dict(json=fx("ref_google_resolves_blocked_name_synthetic.json"))
needs_dns = pytest.mark.skipif(pd._load_dns() is None, reason="dnspython (extra 'full') not installed: Quad9 reports UNAVAILABLE 'package'")


# ------------------------------------------------------------------ metadata and the signature table (cond 1-5)
def test_contract_metadata():
    cls = ProtectiveDns
    assert cls.terms == "open" and cls.default_enabled is True and cls.trust_tier == "trusted"
    assert cls.hosts == ("security.cloudflare-dns.com", "family.cloudflare-dns.com", "dns.quad9.net")
    assert cls.max_requests == 3 and cls.produces == set()
    assert cls.upstream_families == frozenset({"protective_dns"})  # every vote is one family (cond 7)
    assert "reputation" in cls.tags


def test_bundled_signature_table_covers_every_resolver():
    table = DataStore.bundled_json(pd.SIGNATURES_FILE)
    assert table["schema"] == "v3lum.protective_dns_signatures/1" and table["ede_block_codes"] == [15, 16, 17]
    specs = {s.id: s for s in DEFAULT_RESOLVERS + EXTRA_RESOLVERS}
    assert set(table["resolvers"]) == set(specs)
    for rid, entry in table["resolvers"].items():
        spec = specs[rid]
        assert entry["category"] == spec.category and entry["protocol"] == spec.protocol
        assert entry["host"] == spec.url.split("/")[2]
        assert entry["nxdomain"] in (None, "any", "no_soa") and entry["evidence"]
    assert table["resolvers"]["quad9"]["nxdomain"] == "no_soa" and table["resolvers"]["quad9"]["sinks"] == []


# ------------------------------------------------------------------ recorded benign answers (cond 8, 9)
@needs_dns
@pytest.mark.parametrize(("sec", "fam"), [("research_cfsec_example.json", "research_cffam_example.json"),
                                          ("cfsec_example_ok.json", "cffam_example_ok.json")])
def test_recorded_benign_answers_read_not_blocked_never_clean(sec, fam):
    http = http_for("example.com", sec=dict(json=fx(sec)), fam=dict(json=fx(fam)), quad9=wire("quad9_example_ok.wire.json"),
                    ref=dict(json=fx("ref_google_example_ok.json")))
    res = run_module(ProtectiveDns, "domain:example.com", http)
    assert res.status is Status.OK and res.findings == []
    attr = res.attributes["protective_dns"]
    assert attr["summary"] == "not blocked by 2 security resolver(s) at 2026-11-26T12:00:00Z"
    assert "clean" not in json.dumps(attr).lower()
    assert set(verdicts(res).values()) == {"not_blocked"}
    assert {v["status"] for v in res.source_statuses.values()} == {"ok"}
    http.assert_hosts_within(ProtectiveDns)


@needs_dns
def test_wire_query_has_id_zero_and_no_edns_so_never_ecs():
    http = http_for("example.com", sec=dict(json=fx("cfsec_example_ok.json")), fam=dict(json=fx("cffam_example_ok.json")),
                    quad9=wire("quad9_example_ok.wire.json"), ref=dict(json=fx("ref_google_example_ok.json")))
    run_module(ProtectiveDns, "domain:example.com", http)
    sent = [u for u in http.urls() if u.startswith("https://dns.quad9.net/")]
    assert sent == [fx("quad9_example_ok.wire.json")["request"]["url"]]  # byte-identical to the recorded live query
    raw = base64.urlsafe_b64decode(sent[0].split("dns=", 1)[1] + "==")
    assert raw[:2] == b"\x00\x00" and raw[10:12] == b"\x00\x00"  # id 0, ARCOUNT 0 (no OPT record, so no ECS option)
    assert not any("edns_client_subnet" in u for u in http.urls() if "cloudflare" in u)


# ------------------------------------------------------------------ blocks and severity (cond 5-7)
@needs_dns
def test_one_security_block_is_low():
    http = http_for(BAD, sec=dict(json=fx("cfsec_blocked_synthetic.json")), fam=dict(json=fx("cffam_blocked_synthetic.json")),
                    quad9=wire("quad9_example_ok.wire.json"), ref=BLOCKED_REF)
    res = run_module(ProtectiveDns, f"domain:{BAD}", http)
    assert verdicts(res) == {"cloudflare_security": "blocked", "cloudflare_family": "blocked", "quad9": "not_blocked"}
    [finding] = res.findings
    assert finding.title == "Blocked by Cloudflare 1.1.1.2" and finding.severity is Severity.LOW
    assert finding.criterion and set(finding.tags) == {"suspicious", "protective_dns_block"}
    assert finding.data["upstream_family"] == "protective_dns" and finding.data["consensus_votes"] == 1
    assert finding.source == "cloudflare_dns.protective_dns_security"
    assert res.attributes["protective_dns"]["security_blocked"] == ["Cloudflare 1.1.1.2"]


@needs_dns
def test_two_security_blocks_are_medium_naming_them():
    http = http_for(BAD, sec=dict(json=fx("cfsec_blocked_synthetic.json")), fam=dict(json=fx("cffam_example_ok.json")),
                    quad9=wire("quad9_blocked_synthetic.wire.json"), ref=BLOCKED_REF)
    res = run_module(ProtectiveDns, f"domain:{BAD}", http)
    [finding] = res.findings
    assert finding.severity is Severity.MEDIUM and finding.title == "Blocked by Cloudflare 1.1.1.2, Quad9"
    assert "never reaches HIGH" in finding.description  # one upstream family (cond 7)
    assert res.attributes["protective_dns"]["verdicts"][2]["signature"] == "NXDOMAIN without an SOA"


def test_family_block_while_security_resolves_is_content_only():
    """cond 6 test: 1.1.1.3 blocks while 1.1.1.2 resolves -> no malicious finding, an info content-filter tag."""
    http = http_for(BAD, sec=dict(json=answer(BAD, "198.51.100.66")), fam=dict(json=fx("cffam_blocked_synthetic.json")),
                    quad9=wire("quad9_example_ok.wire.json"), ref=BLOCKED_REF)
    res = run_module(ProtectiveDns, f"domain:{BAD}", http)
    [finding] = res.findings
    assert finding.title == "Content filter (adult/ads)" and finding.severity is Severity.INFO
    assert "context_only" in finding.tags and "content_filter" in finding.tags and "suspicious" not in finding.tags
    assert res.attributes["protective_dns"]["security_blocked"] == []


@needs_dns
def test_aaaa_sink_and_ede_block_forms():
    sig = pd.load_signatures()["resolvers"]
    blocked6 = pd.parse_json_answer(json.dumps(fx("cfsec_blocked_aaaa_synthetic.json")))
    assert pd.match_signature(sig["cloudflare_security"], blocked6, [15, 16, 17]) == "block answer ::"
    ede = pd.decode_wire(base64.b64decode(fx("wire_ede_blocked_synthetic.wire.json")["wire_b64"]), pd._load_dns())
    assert ede.ede == [(15, "Blocked")]
    assert pd.match_signature(sig["quad9"], ede, [15, 16, 17]).startswith("Extended DNS Error 15")
    http = http_for(BAD, sec=dict(json=answer(BAD, "198.51.100.66")), fam=dict(json=answer(BAD, "198.51.100.66")),
                    quad9=wire("wire_ede_blocked_synthetic.wire.json"), ref=BLOCKED_REF)
    res = run_module(ProtectiveDns, f"domain:{BAD}", http)
    assert verdicts(res)["quad9"] == "blocked" and res.findings[0].severity is Severity.LOW


@needs_dns
def test_block_signature_needs_the_reference_to_resolve():
    # NXDOMAIN-with-reference cases: Quad9's real NXDOMAIN carries the SOA (not a block form)
    name = "zz-nonexistent-label-7q3.nic.br"
    http = http_for(name, sec=dict(json=fx("cfsec_nxdomain_nicbr.json")), fam=dict(json=fx("cffam_nxdomain_nicbr.json")),
                    quad9=wire("quad9_nxdomain_nicbr.wire.json"), ref=dict(json=fx("ref_google_nxdomain_nicbr.json")))
    res = run_module(ProtectiveDns, f"domain:{name}", http)
    assert set(verdicts(res).values()) == {"not_applicable"} and res.findings == []
    assert "not applicable" in res.attributes["protective_dns"]["summary"]
    # a block form while the reference itself says NXDOMAIN: nothing to block
    http2 = http_for(name, sec=dict(json=fx("cfsec_nxdomain_nicbr.json")), fam=dict(json=fx("cffam_nxdomain_nicbr.json")),
                     quad9=wire("quad9_blocked_synthetic.wire.json"), ref=dict(json=fx("ref_google_nxdomain_nicbr.json")))
    res2 = run_module(ProtectiveDns, f"domain:{name}", http2)
    assert verdicts(res2)["quad9"] == "not_applicable" and res2.findings == []
    # a real NXDOMAIN (with SOA) while the reference resolves: not a block signature -> could not verify
    http3 = http_for(BAD, sec=dict(json=answer(BAD, "198.51.100.66")), fam=dict(json=answer(BAD, "198.51.100.66")),
                     quad9=wire("quad9_nxdomain_nicbr.wire.json"), ref=BLOCKED_REF)
    res3 = run_module(ProtectiveDns, f"domain:{BAD}", http3)
    assert verdicts(res3)["quad9"] == "could_not_verify" and res3.partial and res3.findings == []


def test_block_signature_with_an_unverifiable_reference_is_could_not_verify():
    http = http_for(BAD, sec=dict(json=fx("cfsec_blocked_synthetic.json")), fam=dict(json=fx("cffam_blocked_synthetic.json")),
                    quad9=wire("quad9_blocked_synthetic.wire.json"), ref=dict(json={"Status": 2, "Answer": [], "Comment": "SERVFAIL (test)"}))
    res = run_module(ProtectiveDns, f"domain:{BAD}", http)
    assert set(verdicts(res).values()) == {"could_not_verify"} and res.findings == []
    assert res.status is Status.ERROR and "could not verify" in res.error


# ------------------------------------------------------------------ rule 5 (cond 8)
@needs_dns
def test_timeout_refused_servfail_and_429_are_could_not_verify():
    http = http_for("example.com", sec=dict(error=NetworkError("ReadTimeout contacting security.cloudflare-dns.com: timed out", kind="ReadTimeout")),
                    fam=dict(json=fx("refused_synthetic.json")), quad9=wire("quad9_refused_synthetic.wire.json"),
                    ref=dict(json=fx("ref_google_example_ok.json")))
    res = run_module(ProtectiveDns, "domain:example.com", http)
    assert set(verdicts(res).values()) == {"could_not_verify"}
    assert res.status is Status.ERROR and "could not verify" in res.error and res.findings == []
    lines = res.attributes["protective_dns"]["lines"]
    assert "could not verify Cloudflare 1.1.1.2" in lines and "could not verify Quad9" in lines
    assert res.source_statuses["cloudflare_dns.protective_dns_security"]["reason_code"] == "timeout"
    limited = http_for("example.com", sec=dict(status=429, text="slow down"), fam=dict(status=429, text="slow down"),
                       quad9=dict(status=429, text="slow down"), ref=dict(json=fx("ref_google_example_ok.json")))
    res2 = run_module(ProtectiveDns, "domain:example.com", limited)
    assert res2.status is Status.RATE_LIMITED and res2.reason_code == "rate_limited"


def test_partial_answer_keeps_the_pass_line_and_names_the_rest():
    http = http_for("example.com", sec=dict(json=fx("cfsec_example_ok.json")), fam=dict(json=fx("servfail_synthetic.json")),
                    quad9=dict(status=502, text="<html>bad gateway</html>"), ref=dict(json=fx("ref_google_example_ok.json")))
    res = run_module(ProtectiveDns, "domain:example.com", http)
    assert res.status is Status.OK and res.partial
    assert res.attributes["protective_dns"]["lines"] == [
        "not blocked by 1 security resolver(s) at 2026-11-26T12:00:00Z", "could not verify Cloudflare 1.1.1.3", "could not verify Quad9"]


def test_error_in_200_bodies_are_could_not_verify():
    http = http_for("example.com", sec=dict(text="<html><head><title>Maintenance</title></head></html>"),
                    fam=dict(json={"error": "unsupported"}), quad9=dict(body=b"not a dns message", headers={"content-type": "application/dns-message"}),
                    ref=dict(json=fx("ref_google_example_ok.json")))
    res = run_module(ProtectiveDns, "domain:example.com", http)
    assert set(verdicts(res).values()) == {"could_not_verify"} and res.status is Status.ERROR


@needs_dns
def test_quad9_http_505_is_unavailable_and_asked_again_only_after_a_week():
    """Live 2026-11-26: Quad9 DoH answers 505 HTTP Version Not Supported to HTTP/1.1 (the core client)."""
    clock = FakeClock()
    http = http_for("example.com", sec=dict(json=fx("cfsec_example_ok.json")), fam=dict(json=fx("cffam_example_ok.json")),
                    quad9=dict(status=505, text=""), ref=dict(json=fx("ref_google_example_ok.json")))
    runtime = make_runtime(http, clock=clock)

    def quad9_requests():
        return len([u for u in http.urls() if "dns.quad9.net" in u])

    res = run_module(ProtectiveDns, "domain:example.com", http, runtime=runtime)
    row = res.source_statuses["quad9.protective_dns_security"]
    assert row["status"] == "unavailable" and row["reason_code"] == "package" and "needs HTTP/2" in row["reason"]
    assert res.status is Status.OK and res.partial and "could not verify Quad9" in res.attributes["protective_dns"]["lines"]
    assert quad9_requests() == 1
    again = run_module(ProtectiveDns, "domain:example.com", http, runtime=runtime)
    assert quad9_requests() == 1  # remembered: no request known to fail on every run
    assert again.source_statuses["quad9.protective_dns_security"]["reason_code"] == "package"
    assert "asked again 7 days later" in again.source_statuses["quad9.protective_dns_security"]["reason"]
    clock.advance(8 * 86400)
    run_module(ProtectiveDns, "domain:example.com", http, runtime=runtime)
    assert quad9_requests() == 2  # re-probed after a week (the core may speak HTTP/2 by then)
    only_quad9 = http_for("example.com", sec=None, fam=None, quad9=dict(status=505, text=""), ref=dict(json=fx("ref_google_example_ok.json")))
    res2 = run_module(ProtectiveDns, "domain:example.com", only_quad9, allowed_sources={"quad9.protective_dns_security"})
    assert res2.status is Status.UNAVAILABLE and res2.reason_code == "package"  # never 'empty' or 'clean'


def test_without_dnspython_quad9_is_unavailable_package(monkeypatch):
    monkeypatch.setattr(pd, "_load_dns", lambda: None)
    http = http_for("example.com", sec=dict(json=fx("cfsec_example_ok.json")), fam=dict(json=fx("cffam_example_ok.json")),
                    quad9=None, ref=dict(json=fx("ref_google_example_ok.json")))
    res = run_module(ProtectiveDns, "domain:example.com", http)
    row = res.source_statuses["quad9.protective_dns_security"]
    assert row["status"] == "unavailable" and row["reason_code"] == "package"
    assert not any("quad9" in u for u in http.urls())  # no hand-rolled wire format (cond 3)
    assert res.status is Status.OK and res.partial


# ------------------------------------------------------------------ inputs, cache TTL (cond 3)
def test_url_input_checks_its_host_and_ip_literals_are_not_applicable():
    http = http_for("example.com", sec=dict(json=fx("cfsec_example_ok.json")), fam=dict(json=fx("cffam_example_ok.json")),
                    quad9=wire("quad9_example_ok.wire.json"), ref=dict(json=fx("ref_google_example_ok.json")))
    res = run_module(ProtectiveDns, "url:https://example.com/login?x=1", http)
    assert res.attributes["protective_dns"]["name"] == "example.com"
    empty = FakeHttp()
    res2 = run_module(ProtectiveDns, "url:http://192.0.2.10/admin", empty)
    assert res2.status is Status.SKIPPED and res2.reason_code == "not_applicable" and empty.calls == []


def test_answers_are_cached_only_for_their_record_ttl():
    assert pd._json_ttl(type("R", (), {"content": json.dumps(answer("a.example", "198.51.100.1", ttl=60)).encode()})()) == 60.0
    soa = pd.parse_json_answer(json.dumps(fx("cfsec_nxdomain_nicbr.json")))
    assert soa.ttl == 900 and soa.has_soa  # min(SOA TTL, SOA minimum)
    assert pd._json_ttl(type("R", (), {"content": json.dumps(fx("servfail_synthetic.json")).encode()})()) == 0.0
    assert pd._json_cacheable(type("R", (), {"status": 200, "content": json.dumps(fx("servfail_synthetic.json")).encode()})()) is False
    clock = FakeClock()
    http = http_for("example.com", sec=dict(json=answer("example.com", "198.51.100.1", ttl=60)), fam=dict(json=answer("example.com", "198.51.100.1", ttl=60)),
                    quad9=wire("quad9_example_ok.wire.json"), ref=dict(json=fx("ref_google_example_ok.json")))
    runtime = make_runtime(http, cache=True, clock=clock)
    run_module(ProtectiveDns, "domain:example.com", http, runtime=runtime)
    first = len([u for u in http.urls() if "security.cloudflare" in u])
    run_module(ProtectiveDns, "domain:example.com", http, runtime=runtime)
    assert len([u for u in http.urls() if "security.cloudflare" in u]) == first  # served within the 60 s TTL
    clock.advance(120)
    run_module(ProtectiveDns, "domain:example.com", http, runtime=runtime)
    assert len([u for u in http.urls() if "security.cloudflare" in u]) == first + 1  # never beyond the record TTL


# ------------------------------------------------------------------ AR21 golden path (tests/fixtures/acceptance/)
@pytest.mark.parametrize(("etype", "value"), [("domain", "example.com"), ("url", "https://example.com/")])
def test_acceptance_routes_cover_the_golden_inputs(etype, value):
    """Recorded live 2026-11-26: the Cloudflare reference, 1.1.1.2 and 1.1.1.3 answers for example.com and Quad9's
    HTTP 505 to the HTTP/1.1 core client (RFC 8484 there requires HTTP/2): a pass reads 'not blocked by 1 security
    resolver(s)', Quad9 is 'could not verify' (UNAVAILABLE 'package'), never clean."""
    doc = json.loads((FIXTURES / "acceptance" / etype / "protective_dns.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "protective_dns"
    http = FakeHttp()
    for route in doc["routes"]:
        body = {"json": route["json"]} if "json" in route else {"body": base64.b64decode(route["body_b64"])}
        http.add(route["method"], route["url"], status=route["status"], headers=route.get("headers"),
                 latency=route.get("latency_ms", 0) / 1000.0, **body)
    res = run_module(ProtectiveDns, f"{etype}:{value}", http)
    assert res.status is Status.OK and not http.unexpected and not res.findings
    attr = res.attributes["protective_dns"]
    assert attr["lines"][0].startswith("not blocked by 1 security resolver(s) at ") and not attr["security_blocked"]
    assert "clean" not in json.dumps(attr).lower()
    if pd._load_dns() is not None:
        assert len(http.calls) == len(doc["routes"]) and res.partial
        assert res.source_statuses["quad9.protective_dns_security"]["status"] == "unavailable"
    http.assert_hosts_within(ProtectiveDns)


@needs_dns
def test_live_nodata_everywhere_is_not_applicable_never_blocked():
    """A name that does not exist in a Cloudflare-hosted zone: 1.1.1.2 and Quad9 answer NOERROR/NODATA + SOA (live
    2026-11-26) and so does the reference - nothing to block, never 'not blocked' and never a block."""
    name = "zz-nonexistent-label-7q3.example.com"
    http = http_for(name, sec=dict(json=fx("cfsec_nodata_example.json")), fam=dict(json=fx("cfsec_nodata_example.json")),
                    quad9=wire("quad9_nodata_example.wire.json"), ref=dict(json=fx("cfsec_nodata_example.json")))
    res = run_module(ProtectiveDns, f"domain:{name}", http)
    assert set(verdicts(res).values()) == {"not_applicable"} and res.findings == []
    assert res.attributes["protective_dns"]["lines"] == ["not applicable: the name does not resolve at the unfiltered reference"]


def test_recorded_client_timeout_is_could_not_verify():
    recorded = fx("timeout.http.json")
    http = http_for(BAD, sec=dict(error=NetworkError(recorded["transport_error"], kind="ReadTimeout")),
                    fam=dict(error=NetworkError(recorded["transport_error"], kind="ReadTimeout")),
                    quad9=dict(error=NetworkError(recorded["transport_error"], kind="ReadTimeout")), ref=BLOCKED_REF)
    res = run_module(ProtectiveDns, f"domain:{BAD}", http)
    assert res.findings == [] and res.status in (Status.ERROR, Status.UNAVAILABLE)
    assert res.source_statuses["cloudflare_dns.protective_dns_security"]["reason_code"] == "timeout"
    assert "could not verify Cloudflare 1.1.1.2" in res.attributes["protective_dns"]["lines"]
