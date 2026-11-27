"""takeover_verify (P276, ACTIVE): scope-bound GET of the in-scope name, provider fingerprints, the
random-label wildcard probe and the tri-state outcome; only GET reaches the target, no provider API,
nothing claimed. Fixtures: tests/fixtures/takeover_verify/ (recorded provider error pages) and the
pinned fingerprints of tests/fixtures/takeover_candidates/."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.fakes import FIXTURES, FakeHttp, add_dns, doh_url, make_ctx, make_runtime, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Confidence, Opsec, Status
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon import subdomain_takeover as st
from v3lum.modules.pentest_recon.subdomain_takeover import TakeoverVerify

FIX = Path(FIXTURES) / "takeover_verify"
ROWS = st.parse_fingerprints((Path(FIXTURES) / "takeover_candidates" / "fingerprints_upstream.json").read_text(encoding="utf-8"))["rows"]
REF = "PENTEST-2026-042"
NAME = "assets.example.com"
S3_TARGET = "assets.example.com.s3.amazonaws.com"
DOH_HOSTS = {"dns.google", "cloudflare-dns.com"}


def scope(**targets) -> Scope:
    return Scope.from_dict({
        "authorization_ref": REF, "owner": "Engagement owner (tests)", "contacts": ["soc@example.com"], "ticket": "T-1",
        "window_start": "2026-11-26T00:00:00Z", "window_end": "2026-11-27T00:00:00Z",
        "targets": targets or {"domains": ["example.com", "*.example.com"], "cidrs": ["93.184.216.0/24"]},
    })


def active(sc: Scope | None = None) -> ScanOptions:
    return ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF, scope=sc if sc is not None else scope())


@pytest.fixture(autouse=True)
def pinned_rows(monkeypatch):
    monkeypatch.setattr(st, "load_rows", lambda ctx: (ROWS, "fixture fingerprints_upstream.json"))


def capture(name: str) -> tuple[int, dict, str]:
    data = json.loads((FIX / name).read_text(encoding="utf-8"))
    resp = data["response"]
    return resp["status"], resp.get("headers") or {}, resp.get("body") or ""


def chain_answer(name: str, chain: list[str], ip: str | None) -> dict:
    answers, prev = [], name
    for hop in chain:
        answers.append({"name": prev + ".", "type": 5, "TTL": 60, "data": hop + "."})
        prev = hop
    if ip:
        answers.append({"name": prev + ".", "type": 1, "TTL": 60, "data": ip})
    return {"Status": 0 if ip else 3, "Answer": answers}


def s3_http(ip: str = "93.184.216.20") -> FakeHttp:
    """assets.example.com CNAME -> the S3 bucket name -> an address inside the scope CIDR."""
    http = FakeHttp()
    http.add("GET", doh_url(NAME, "A"), json=chain_answer(NAME, [S3_TARGET, "s3-1-w.amazonaws.com"], ip))
    add_dns(http, NAME, "AAAA", [])
    return http


def add_capture(http: FakeHttp, url: str, name: str) -> None:
    status, headers, body = capture(name)
    http.add("GET", url, status=status, body=body.encode(), headers=headers)


def random_label_dns(http: FakeHttp, *, ip: str | None = "93.184.216.21") -> None:
    # v3lum-<hex> = the module's HTTP wildcard label; 16 characters = the core DoH wildcard probe
    pattern = re.compile(r"^https://dns\.google/resolve\?name=(?:v3lum-[0-9a-f]+|[a-z0-9]{16})\.example\.com&type=(A|AAAA)")
    if ip:
        http.add("GET", re.compile(pattern.pattern.replace("(A|AAAA)", "A")), json={"Status": 0, "Answer": [{"name": "x.", "type": 1, "TTL": 60, "data": ip}]})
        http.add("GET", re.compile(pattern.pattern.replace("(A|AAAA)", "AAAA")), json={"Status": 0, "Answer": []})
    else:
        http.add("GET", pattern, json={"Status": 3, "Answer": []})


def target_calls(http: FakeHttp) -> list[dict]:
    return [c for c in http.calls if not any(h in c["url"] for h in DOH_HOSTS)]


def assert_get_only_and_no_provider_api(http: FakeHttp) -> None:
    """P276 cond 9: only GET/HEAD reach the target; no provider API host is ever contacted."""
    calls = target_calls(http)
    assert calls and {c["method"] for c in calls} <= {"GET", "HEAD"}
    hosts = {re.sub(r"^https?://([^/]+)/.*$", r"\1", c["url"]) for c in calls}
    assert all(h == NAME or re.fullmatch(r"v3lum-[0-9a-f]+\.example\.com", h) for h in hosts), hosts
    assert not any("amazonaws.com" in c["url"] or "api." in c["url"] for c in calls)


def test_s3_nosuchbucket_with_a_differing_wildcard_is_confirmed():
    http = s3_http()
    http.add("GET", f"https://{NAME}/", error=NetworkError("SSLError: hostname mismatch (certificate for *.s3.amazonaws.com)"))
    add_capture(http, f"http://{NAME}/", "s3_nosuchbucket_404.http.json")
    random_label_dns(http)
    add_capture(http, re.compile(r"^http://v3lum-[0-9a-f]+\.example\.com/$"), "wildcard_differs_404.http.json")
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active())
    assert res.status is Status.OK, res.error
    ver = res.attributes["takeover_verification"]
    assert ver["state"] == "confirmed" and ver["service"] == "AWS/S3" and ver["wildcard"]["state"] == "differs"
    fp = res.attributes["takeover_fingerprint"]
    assert fp["service"] == "AWS/S3" and fp["source"] == "takeover_verify" and fp["url"] == f"http://{NAME}/"
    finding = res.findings[0]
    assert finding.severity.label == "high" and finding.confidence_label is Confidence.CONFIRMED
    assert "NOT claimed" in finding.description and finding.attack == ["T1584.001"]
    assert_get_only_and_no_provider_api(http)
    # every target request was pinned to a checked, in-scope address
    assert all(c.get("pin_ip", "").startswith("93.184.216.") for c in target_calls(http))


def test_same_fingerprint_on_a_random_label_is_could_not_test():
    http = s3_http()
    add_capture(http, f"https://{NAME}/", "s3_nosuchbucket_404.http.json")
    random_label_dns(http)
    add_capture(http, re.compile(r"^https://v3lum-[0-9a-f]+\.example\.com/$"), "wildcard_same_404.http.json")
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active())
    ver = res.attributes["takeover_verification"]
    assert ver["state"] == "could_not_test" and "wildcard" in ver["reason"]
    assert res.status is Status.ERROR and "could not test" in res.error
    assert res.findings == [] and "takeover_fingerprint" not in res.attributes


def test_wildcard_probe_outside_the_scope_falls_back_to_the_doh_check():
    """The random label is not in the scope (exact name only): no HTTP probe, the DoH wildcard check decides."""
    sc = scope(domains=[NAME], cidrs=["93.184.216.0/24"])
    http = s3_http()
    add_capture(http, f"https://{NAME}/", "s3_nosuchbucket_404.http.json")
    random_label_dns(http, ip=None)  # random labels answer NXDOMAIN: no DNS wildcard
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active(sc))
    assert res.attributes["takeover_verification"]["state"] == "confirmed"
    assert all(NAME in c["url"] for c in target_calls(http))  # the random name was never contacted


def test_live_site_is_not_observed_never_safe():
    http = s3_http()
    add_capture(http, f"https://{NAME}/", "live_site_200.http.json")
    add_capture(http, f"http://{NAME}/", "live_site_200.http.json")
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active())
    ver = res.attributes["takeover_verification"]
    assert ver["state"] == "not_observed" and "never 'safe'" in ver["reason"]
    assert res.findings == []
    assert "safe" not in json.dumps(res.attributes).replace("never 'safe'", "")


def test_do_spaces_body_does_not_confirm_an_s3_cname_mismatch():
    """The fingerprint must belong to the row matched by the CNAME: a Spaces page under a Ghost CNAME is no proof."""
    http = FakeHttp()
    http.add("GET", doh_url(NAME, "A"), json=chain_answer(NAME, ["exemplo.ghost.io"], "93.184.216.30"))
    add_dns(http, NAME, "AAAA", [])
    add_capture(http, f"https://{NAME}/", "do_spaces_404.http.json")
    add_capture(http, f"http://{NAME}/", "do_spaces_404.http.json")
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active())
    assert res.attributes["takeover_verification"]["state"] == "not_observed"


def test_ghost_regex_fingerprint_and_helprace_status_fingerprint():
    http = FakeHttp()
    http.add("GET", doh_url(NAME, "A"), json=chain_answer(NAME, ["exemplo.ghost.io"], "93.184.216.30"))
    add_dns(http, NAME, "AAAA", [])
    add_capture(http, f"https://{NAME}/", "ghost_200.http.json")
    random_label_dns(http, ip=None)
    add_capture(http, re.compile(r"^https://v3lum-[0-9a-f]+\.example\.com/$"), "wildcard_differs_404.http.json")
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active())
    assert res.attributes["takeover_verification"]["state"] == "confirmed"
    assert res.attributes["takeover_fingerprint"]["service"] == "Ghost"
    row = st.match_service("support.helprace.com", ROWS)
    status, headers, body = capture("helprace_301.http.json")
    assert st.fingerprint_matches(row, status, body) == "HTTP_STATUS=301"
    assert st.fingerprint_matches(row, 200, body) is None
    # the fingerprint belongs to the CNAME-matched row: the S3 text under a Ghost CNAME proves nothing
    gcs_status, _h, gcs_body = capture("gcs_nosuchbucket_404.http.json")
    assert st.fingerprint_matches(st.match_service("b.s3.amazonaws.com", ROWS), gcs_status, gcs_body)
    assert st.fingerprint_matches(st.match_service("exemplo.ghost.io", ROWS), gcs_status, gcs_body) is None


def test_bare_403_without_the_fingerprint_is_could_not_test_never_not_observed():
    """Rule 5: a 403 (WAF, IP block, AccessDenied) that does not carry the provider fingerprint proves nothing."""
    http = s3_http()
    for scheme in ("https", "http"):
        http.add("GET", f"{scheme}://{NAME}/", status=403, headers={"content-type": "application/xml"},
                 text="<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>")
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active())
    ver = res.attributes["takeover_verification"]
    assert ver["state"] == "could_not_test" and res.status is Status.ERROR and "403" in res.error
    assert all(a["state"] == "error" for a in ver["attempts"]) and res.findings == []


def test_wildcard_probe_refused_by_policy_keeps_the_match_as_could_not_test():
    """The random label resolves to a private address the scope does not list: it is never contacted, and the
    fingerprint seen on the name is kept as 'could not test' instead of the whole run being dropped."""
    http = s3_http()
    add_capture(http, f"https://{NAME}/", "s3_nosuchbucket_404.http.json")
    random_label_dns(http, ip="10.0.0.5")
    add_capture(http, re.compile(r"^https://v3lum-[0-9a-f]+\.example\.com/$"), "wildcard_differs_404.http.json")
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active())
    ver = res.attributes["takeover_verification"]
    assert ver["state"] == "could_not_test" and ver["wildcard"]["state"] == "unknown" and "policy" in ver["wildcard"]["reason"]
    assert ver["matched"] and res.findings == [] and res.status is Status.ERROR
    assert [c["url"] for c in target_calls(http)] == [f"https://{NAME}/"]


def test_never_on_pivots_or_names_found_in_text():
    """Cond 6: analyst-typed seeds only (run_on='seeds' plus applies()), even when the name is in the scope."""
    assert TakeoverVerify.run_on == "seeds"
    for kw in ({"is_seed": False}, {"provenance": [("text_blob:abc", "mentions", "ioc_extract")]}):
        http = s3_http()
        res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active(), **kw)
        assert res.status is Status.SKIPPED, (kw, res.status, res.reason_code)
        assert target_calls(http) == []


def test_challenge_is_blocked_could_not_test():
    http = s3_http()
    add_capture(http, f"https://{NAME}/", "challenge_403.http.json")
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active())
    assert (res.status, res.reason_code) == (Status.BLOCKED, "challenge")
    assert res.attributes["takeover_verification"]["state"] == "could_not_test"
    assert len(target_calls(http)) == 1  # stopped at the challenge: never retried, http never tried


def test_429_is_rate_limited_could_not_test():
    http = s3_http()
    http.add("GET", f"https://{NAME}/", status=429, text="slow down")
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active())
    assert res.status is Status.RATE_LIMITED
    assert res.attributes["takeover_verification"]["state"] == "could_not_test"


def test_egress_proxy_refusal_and_errors_are_could_not_test():
    http = s3_http()
    add_capture(http, f"https://{NAME}/", "proxy_refusal_403.http.json")
    http.add("GET", f"http://{NAME}/", status=503, text="upstream unavailable")
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active())
    assert res.status is Status.ERROR and "could not test" in res.error
    assert res.attributes["takeover_verification"]["state"] == "could_not_test"
    assert res.findings == []


def test_no_cname_or_nxdomain_service_never_contacts_the_target():
    http = FakeHttp()
    add_dns(http, NAME, "A", ["93.184.216.20"])
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active())
    assert (res.status, res.reason_code) == (Status.SKIPPED, "not_applicable")
    http2 = FakeHttp()
    http2.add("GET", doh_url("app.example.com", "A"), json=chain_answer("app.example.com", ["x.us-east-1.elasticbeanstalk.com"], None))
    res2 = run_module(TakeoverVerify, "domain:app.example.com", http2, options=active())
    assert (res2.status, res2.reason_code) == (Status.SKIPPED, "not_applicable") and "DNS evidence only" in res2.error
    assert target_calls(http) == [] and target_calls(http2) == []


def test_without_a_scope_nothing_reaches_the_target():
    http = s3_http()
    opts = ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF)
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=opts)
    assert (res.status, res.reason_code) == (Status.SKIPPED, "scope")
    assert target_calls(http) == []


def test_out_of_scope_name_is_refused_before_any_request():
    http = FakeHttp()
    http.add("GET", doh_url("assets.example.org", "A"), json=chain_answer("assets.example.org", ["assets.example.org.s3.amazonaws.com"], "93.184.216.20"))
    res = run_module(TakeoverVerify, "domain:assets.example.org", http, options=active())
    assert (res.status, res.reason_code) == (Status.SKIPPED, "scope")
    assert target_calls(http) == []


def test_policy_gate_refuses_without_an_authorization_or_in_passive_mode():
    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.DOMAIN, NAME)
    no_ref = Engine(rt, ScanOptions(mode=Opsec.ACTIVE, scope=scope())).decide_single(TakeoverVerify, ent)
    assert not no_ref.allowed and no_ref.reason_code == "authorization"
    passive = Engine(rt, ScanOptions()).decide_single(TakeoverVerify, ent)
    assert not passive.allowed and passive.reason_code == "opsec"


def test_kill_switch_stops_before_any_target_request():
    http = s3_http()
    rt = make_runtime(http)
    rt.cancel("cancelled")
    res = run_module(TakeoverVerify, f"domain:{NAME}", http, options=active(), runtime=rt)
    assert target_calls(http) == []
    assert res.findings == []


def test_offline_selftest_is_ok_without_network():
    hc = TakeoverVerify.health_check()
    assert hc.offline is True and callable(hc.selftest)
    ctx = make_ctx(TakeoverVerify, FakeHttp())
    result = hc.selftest(ctx)
    assert result.status == "ok", result.detail
