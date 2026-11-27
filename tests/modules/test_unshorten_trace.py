"""unshorten_trace (P070, LIGHT, opt-in): the short-link redirect tracer, offline.

Every target host answers from FakeHttp, with DoH answers for its name (bound LIGHT runs resolve each
hop through the egress profile and pin the checked address); 93.184.216.34 stands in for public
addresses (TEST-NET ranges are refused by the core SSRF guard like private ones). The redirect chains
come from tests/fixtures/unshorten_trace/ (batch p9-G03-1 prep): the recorded google.com -> www.google.com
chain (research, 2026-11-25) and synthetic shortener chains in the documented shapes (the prep never
follows a real short link): a bit.ly -> rb.gy -> landing chain whose landing URL carries a base64
e-mail, a chain per internal destination (127.0.0.1, 10.0.0.5, 169.254.169.254, router.local) and a
meta-refresh interstitial. No hop is ever sent outside the listed shorteners unless follow-final is on.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, add_dns, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.http import PolicyError
from v3lum.core.models import Opsec, Severity, Status
from v3lum.modules.url_web import unshorten as U
from v3lum.modules.url_web.unshorten import UnshortenTrace

IP = "93.184.216.34"
LIGHT = ScanOptions(mode=Opsec.LIGHT)
FOLLOW = {"unshorten_trace_follow_final": True}
B64_EMAIL = "dXNlckBleGFtcGxlLmNvbQ"  # base64('user@example.com'), unpadded


def target(http: FakeHttp, *hosts: str, ip: str = IP) -> FakeHttp:
    for host in hosts:
        add_dns(http, host, "A", [ip])
        add_dns(http, host, "AAAA", [])
    return http


def target_calls(http: FakeHttp) -> list[tuple[str, str]]:
    return [(c["method"], c["url"]) for c in http.calls if "dns.google" not in c["url"] and "cloudflare-dns" not in c["url"]]


def run(http: FakeHttp, url: str, **kw):
    return run_module(UnshortenTrace, f"url:{url}", http, options=kw.pop("options", LIGHT), **kw)


def add_hops(http: FakeHttp, hops: list[dict], method: str = "HEAD") -> None:
    for hop in hops:
        headers = {"location": hop["location"]} if hop.get("location") else {}
        http.add(method, hop["url"], status=hop["status"], headers=headers, body=b"")


def test_shortener_chain_stops_before_the_landing_page():
    """bit.ly -> rb.gy (both listed: contacted with HEAD) -> landing page: recorded from the Location
    header, never contacted; its base64 e-mail keeps it to a domain pivot and out of the evidence."""
    chain = module_fixture("unshorten_trace", "chain_shortener_synthetic.json")
    hops = [dict(h) for h in chain["hops"]]
    hops[1]["location"] = hops[1]["location"].replace("http://", "https://")  # https landing (the downgrade case is below)
    http = target(FakeHttp(), "bit.ly", "rb.gy")
    add_hops(http, hops)
    res = run(http, hops[0]["url"])
    assert res.status is Status.OK, res.error
    assert target_calls(http) == [("HEAD", "https://bit.ly/3Example"), ("HEAD", "https://rb.gy/abc12")]
    steps = res.attributes["unshorten_chain"]
    assert [(s["contacted"], s["status"]) for s in steps] == [(True, 301), (True, 302), (False, None)]
    assert steps[2]["action"] == "record" and steps[2]["url"].startswith("https://promo.example.net/r?")
    (pivot,) = res.pivots
    assert pivot.relation == "redirects_to" and pivot.entity.value == "promo.example.net" and pivot.expand is True
    flags = set(res.attributes["short_link"]["flags"])
    assert {"known_shortener", "cross_domain_hop", "open_redirect_param"} <= flags
    assert B64_EMAIL not in repr(res.attributes) and B64_EMAIL not in repr(res.raw)
    assert all(c.get("pin_ip") == IP for c in http.calls if c["url"].startswith(("https://bit.ly/", "https://rb.gy/")))


def test_https_to_http_landing_is_recorded_not_followed():
    """The fixture's landing page is plain http: the core refuses the downgrade before any hop check;
    the tracer records it (flag https_downgrade) and never contacts it."""
    chain = module_fixture("unshorten_trace", "chain_shortener_synthetic.json")
    http = target(FakeHttp(), "bit.ly", "rb.gy")
    add_hops(http, chain["hops"])
    res = run(http, "https://bit.ly/3Example")
    assert res.status is Status.OK, res.error
    assert not any("promo.example.net" in u for _m, u in target_calls(http))
    assert "https_downgrade" in res.attributes["short_link"]["flags"]
    assert res.attributes["unshorten_chain"][-1]["contacted"] is False
    assert [p.entity.value for p in res.pivots] == ["promo.example.net"]
    assert B64_EMAIL not in repr(res.attributes)


@pytest.mark.parametrize("hop", module_fixture("unshorten_trace", "redirect_private_synthetic.json")["hops"],
                         ids=["loopback", "rfc1918", "metadata", "dot_local"])
@pytest.mark.parametrize("follow_final", [False, True], ids=["default", "follow_final"])
def test_redirects_to_internal_addresses_are_refused(hop, follow_final):
    host = hop["url"].split("/")[2]
    for location in (hop["location"], hop["location"].replace("http://", "https://")):
        http = target(FakeHttp(), host)
        http.add("HEAD", hop["url"], status=hop["status"], headers={"location": location})
        res = run(http, hop["url"], settings=FOLLOW if follow_final else None)
        assert res.status is Status.OK, res.error
        assert target_calls(http) == [("HEAD", hop["url"])], location
        assert res.pivots == []
        refused = res.attributes["unshorten_refused"]
        assert refused["action"] == "refuse"
        (finding,) = res.findings
        assert finding.severity is Severity.INFO and "refuses" in finding.title


def test_public_name_resolving_to_rfc1918_is_refused_after_resolution():
    """follow-final: a destination whose name resolves to 10.0.0.5 passes the hop plan but the core SSRF
    guard refuses it after resolution: nothing is sent there."""
    http = target(FakeHttp(), "is.gd")
    target(http, "intranet.example.net", ip="10.0.0.5")
    http.add("HEAD", "https://is.gd/example3", status=302, headers={"location": "https://intranet.example.net/"})
    res = run(http, "https://is.gd/example3", settings=FOLLOW)
    assert target_calls(http) == [("HEAD", "https://is.gd/example3")]
    assert res.attributes["unshorten_refused"]["url"] == "https://intranet.example.net/"
    assert res.pivots == []


def test_listed_shortener_resolving_to_a_private_address_is_refused():
    http = target(FakeHttp(), "bit.ly")
    target(http, "rb.gy", ip="192.168.1.10")
    http.add("HEAD", "https://bit.ly/3Example", status=301, headers={"location": "https://rb.gy/abc12"})
    res = run(http, "https://bit.ly/3Example")
    assert target_calls(http) == [("HEAD", "https://bit.ly/3Example")]
    assert res.attributes["unshorten_refused"]["action"] == "refuse"


def test_follow_final_visits_the_destination_through_the_core_guard():
    """The recorded google.com -> www.google.com chain with follow-final (the seed is not a shortener,
    so only follow-final lets the tracer run on it); the final page answers 200 and becomes the pivot."""
    rec = module_fixture("unshorten_trace", "redirect_chain_recorded.json")
    http = target(FakeHttp(), "google.com", "www.google.com")
    add_hops(http, rec["hops"])
    res = run(http, "https://google.com/", settings=FOLLOW)
    assert res.status is Status.OK, res.error
    assert target_calls(http) == [("HEAD", "https://google.com/"), ("HEAD", "https://www.google.com/")]
    assert [s["status"] for s in res.attributes["unshorten_chain"]] == [301, 200]
    (pivot,) = res.pivots
    assert pivot.entity.value == "https://www.google.com/" and pivot.relation == "redirects_to"


def test_non_shortener_seed_is_not_contacted_by_default():
    http = target(FakeHttp(), "google.com")
    res = run(http, "https://google.com/")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert target_calls(http) == []


def test_token_url_is_not_contacted_without_confirmation():
    url = "https://bit.ly/3Example?u=alice%40example.com"
    http = target(FakeHttp(), "bit.ly")
    res = run(http, url)
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and "--confirm-url" in res.error
    assert target_calls(http) == []
    # an opaque token too
    res = run(http, "https://bit.ly/r/9f8e7d6c5b4a39281706")
    assert res.status is Status.SKIPPED and target_calls(http) == []
    # --confirm-url <url> lets this one URL through
    http.add("HEAD", url, status=301, headers={"location": "https://www.example.com/landing"})
    res = run(http, url, options=ScanOptions(mode=Opsec.LIGHT, confirmed_urls=(url,)))
    assert res.status is Status.OK, res.error
    assert target_calls(http) == [("HEAD", url)]
    assert "alice" not in repr(res.attributes)


def test_token_redirect_target_needs_confirmation():
    http = target(FakeHttp(), "bit.ly", "rb.gy")
    http.add("HEAD", "https://bit.ly/3Example", status=301, headers={"location": "https://rb.gy/abc12?t=9f8e7d6c5b4a39281706"})
    res = run(http, "https://bit.ly/3Example")
    assert target_calls(http) == [("HEAD", "https://bit.ly/3Example")]
    refused = res.attributes["unshorten_refused"]
    assert refused["action"] == "confirm" and "9f8e7d6c5b4a39281706" not in refused["url"]


def test_ip_loggers_are_never_contacted():
    http = target(FakeHttp(), "grabify.link", "bit.ly")
    res = run(http, "https://grabify.link/ABC123")
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and target_calls(http) == []
    http.add("HEAD", "https://bit.ly/3Example", status=301, headers={"location": "https://iplogger.org/2abc"})
    res = run(http, "https://bit.ly/3Example")
    assert target_calls(http) == [("HEAD", "https://bit.ly/3Example")]
    assert "ip_logger" in res.attributes["unshorten_refused"]["reason"]


def test_head_refused_then_get_reads_meta_refresh_without_following():
    page = (module_fixture("unshorten_trace", "meta_refresh_synthetic.html"))
    http = target(FakeHttp(), "encurtador.com.br")
    http.add("HEAD", "https://encurtador.com.br/abc12", status=405, body=b"")
    http.add("GET", "https://encurtador.com.br/abc12", text=page)
    res = run(http, "https://encurtador.com.br/abc12")
    assert res.status is Status.OK, res.error
    assert target_calls(http) == [("HEAD", "https://encurtador.com.br/abc12"), ("GET", "https://encurtador.com.br/abc12")]
    last = res.attributes["unshorten_chain"][-1]
    assert last["contacted"] is False and "meta refresh" in last["reason"]
    assert "9f8e7d6c5b4a39281706" not in repr(res.attributes)  # the opaque path token is masked
    (pivot,) = res.pivots
    assert pivot.entity.value == "landing.example.net"  # token URL: domain only
    assert res.attributes["short_link"]["js_hints"] == ["https://landing.example.net/js"]
    assert not any("landing.example.net" in u for _m, u in target_calls(http))


@pytest.mark.parametrize(("status", "body", "expected"), [
    (404, b"", Status.EMPTY),
    (429, b"", Status.RATE_LIMITED),
    (503, b"", Status.ERROR),
])
def test_shortener_answers(status, body, expected):
    http = target(FakeHttp(), "cutt.ly")
    http.add("HEAD", "https://cutt.ly/example2", status=status, body=body)
    res = run(http, "https://cutt.ly/example2")
    assert res.status is expected
    assert res.pivots == []


def test_challenge_page_is_blocked_never_empty():
    http = target(FakeHttp(), "t.co")
    challenge = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http.add("HEAD", "https://t.co/abc123", status=403, body=b"", headers={"server": "cloudflare", "cf-mitigated": "challenge"})
    http.add("GET", "https://t.co/abc123", status=403, text=challenge, headers={"server": "cloudflare", "cf-mitigated": "challenge"})
    res = run(http, "https://t.co/abc123")
    assert res.status is Status.BLOCKED
    assert res.pivots == []


def test_redirect_loop_stops_at_the_core_cap():
    http = target(FakeHttp(), "bit.ly")
    for i in range(7):
        http.add("HEAD", f"https://bit.ly/loop{i}", status=302, headers={"location": f"https://bit.ly/loop{i + 1}"})
    res = run(http, "https://bit.ly/loop0")
    assert len(target_calls(http)) == 6  # the seed + 5 redirects (core MAX_REDIRECTS)
    assert "5 redirects" in res.attributes["unshorten_refused"]["reason"]


def test_never_runs_on_a_pivot():
    http = target(FakeHttp(), "bit.ly")
    res = run(http, "https://bit.ly/3Example", is_seed=False)
    assert res.status is Status.SKIPPED and res.reason_code == "scope"
    assert target_calls(http) == []


def test_kill_switch_stops_before_any_request():
    http = target(FakeHttp(), "bit.ly")
    rt = make_runtime(http)
    rt.cancel("test kill switch")
    res = run(http, "https://bit.ly/3Example", runtime=rt)
    assert target_calls(http) == []
    assert res.status in (Status.EMPTY, Status.ERROR, Status.SKIPPED)


def test_only_head_and_get_are_sent_and_other_methods_are_refused():
    chain = module_fixture("unshorten_trace", "chain_shortener_synthetic.json")
    http = target(FakeHttp(), "bit.ly", "rb.gy")
    add_hops(http, chain["hops"])
    run(http, "https://bit.ly/3Example")
    assert {m for m, _u in target_calls(http)} <= {"HEAD", "GET"}
    ctx = make_ctx(UnshortenTrace, http, entity="url:https://bit.ly/3Example", options=LIGHT)
    before = len(target_calls(http))
    for method in ("POST", "PUT", "DELETE"):
        with pytest.raises(PolicyError):
            ctx.http.request(method, "https://bit.ly/3Example")
    assert len(target_calls(http)) == before


def test_light_budget_reached_is_a_partial_run():
    http = target(FakeHttp(), "bit.ly", "rb.gy")
    http.add("HEAD", "https://bit.ly/3Example", status=301, headers={"location": "https://rb.gy/abc12"})
    rt = make_runtime(http)
    rt.http.ceilings.charge("light", "rb.gy", n=25)
    res = run(http, "https://bit.ly/3Example", runtime=rt)
    assert not any("rb.gy" in u for _m, u in target_calls(http))
    assert res.partial is True and res.stop_reason == "request_cap"


def test_hop_plan_and_masking_helpers():
    assert U.plan_hop("https://bit.ly/x", follow_final=False)["action"] == "contact"
    assert U.plan_hop("https://www.example.com/", follow_final=False)["action"] == "record"
    assert U.plan_hop("https://www.example.com/", follow_final=True)["action"] == "contact_guarded"
    assert U.plan_hop("https://www.example.com/?e=alice%40example.com", follow_final=True)["action"] == "confirm"
    assert U.plan_hop("https://bit.ly:8443/x", follow_final=False)["action"] == "refuse"
    assert U.plan_hop("ftp://bit.ly/x", follow_final=False)["action"] == "refuse"
    assert U.plan_hop("https://user:pw@bit.ly/x", follow_final=False)["action"] == "refuse"
    masked = U.mask_hop_url(f"https://promo.example.net/r?u={B64_EMAIL}&e=bob%40example.org&id=9f8e7d6c5b4a39281706&utm=sms")
    assert B64_EMAIL not in masked and "bob" not in masked and "9f8e7d6c5b4a39281706" not in masked and "utm=sms" in masked
    assert U.mask_hop_url("https://www.example.com/running-shoes-for-women") == "https://www.example.com/running-shoes-for-women"
    assert U.chain_flags(["https://bit.ly/a", "http://x.example.net/?url=https://y"]) == [
        "cross_domain_hop", "https_downgrade", "known_shortener", "open_redirect_param"]


def test_offline_selftest_and_contract_metadata():
    hc = UnshortenTrace.health_check()
    assert hc.offline is True and hc.selftest(None).status == "ok"
    assert UnshortenTrace.opsec is Opsec.LIGHT and UnshortenTrace.disclosure == "target"
    assert UnshortenTrace.default_enabled is False and UnshortenTrace.run_on == "seeds"
    assert UnshortenTrace.max_rate <= 1.0 and UnshortenTrace.hosts == ()
