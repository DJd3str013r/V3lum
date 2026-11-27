"""Offline tests for the ACTIVE cors_probe module (P283).

The classifier (CR20) is tested from the trimmed research fixtures. The end-to-end ACTIVE path runs
over a header-aware FakeHttp with a scope listing the target domain: the module sends the forged
Origin headers to the in-scope seed only and never contacts anything else.
"""

from __future__ import annotations

from typing import Any

from tests.fakes import FakeClock, FakeHttp, add_dns, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Opsec, Status
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon.cors_probe import CorsProbe, classify_cors, forged_origins

REF = "PENTEST-2026-283"
WINDOW = ("2026-11-26T00:00:00Z", "2026-11-27T00:00:00Z")
HOST = "app.acme.test"
SEED = f"https://{HOST}/"
PUBLIC_IP = "93.184.216.34"


def _fixture(name: str) -> dict[str, Any]:
    return module_fixture("cors_probe", name)


def _classify(name: str, *, user_data: bool = False) -> dict[str, Any]:
    d = _fixture(name)
    origin = d["request"]["headers"]["Origin"]
    r = d["response"]
    return classify_cors(origin, r.get("headers"), endpoint_returns_user_data=user_data, status=r["status"], body=r.get("body"))


# --------------------------------------------------------------------------------------
# forged Origins (FC4) and the classifier (FC5/FC6)
# --------------------------------------------------------------------------------------


def test_forged_origins_are_invalid_tld_and_null_only():
    origins = forged_origins("app.example.com")
    kinds = {o["kind"] for o in origins}
    assert kinds == {"arbitrary", "null", "prefix", "suffix"}
    for o in origins:
        assert o["origin"] == "null" or o["origin"].endswith(".invalid")
    # the target host stays intact in the prefix/suffix tricks (FC4), always under .invalid
    prefix = next(o for o in origins if o["kind"] == "prefix")
    suffix = next(o for o in origins if o["kind"] == "suffix")
    assert prefix["origin"].startswith("https://app.example.com.") and prefix["origin"].endswith(".invalid")
    assert "app.example.com" in suffix["origin"] and not suffix["origin"].startswith("https://app.example.com")
    assert suffix["origin"].endswith(".invalid")


def test_forged_origins_never_leave_invalid_for_odd_hosts():
    for host in ("", "UPPER.Example.COM.", "a..b", "xn--bcher-kva.example", "bücher.example", "bad host/../x"):
        for o in forged_origins(host):
            assert o["origin"] == "null" or (o["origin"].startswith("https://") and o["origin"].endswith(".invalid"))
            assert " " not in o["origin"] and "/.." not in o["origin"]


def test_reflected_with_credentials_is_high():
    assert _classify("reflected_with_credentials.json")["severity"] == "high"


def test_null_origin_with_credentials_is_high():
    out = _classify("null_with_credentials.json")
    assert out["severity"] == "high" and out["reflected"] is True


def test_reflection_without_credentials_low_or_medium():
    assert _classify("reflected_no_credentials.json", user_data=False)["severity"] == "low"
    assert _classify("reflected_no_credentials_userdata.json", user_data=True)["severity"] == "medium"


def test_wildcard_is_info():
    assert _classify("wildcard.json")["severity"] == "info"


def test_no_cors_header_is_not_observed():
    out = _classify("no_cors.json")
    assert out["state"] == "not_observed" and out["severity"] is None


def test_blocked_403_is_could_not_test():
    assert _classify("blocked_403.json")["state"] == "could_not_test"


def test_preflight_options_204_still_classifies_from_headers():
    # an OPTIONS preflight with an empty 204 body still classifies on the headers alone (FC4)
    assert _classify("preflight_options_reflected_creds.json")["severity"] == "high"


def test_fixed_allowlisted_origin_is_not_a_finding():
    out = classify_cors("https://x.v3lum-probe.invalid", {"access-control-allow-origin": "https://trusted.example.com"})
    assert out["state"] == "not_observed" and out["reflected"] is False


# --------------------------------------------------------------------------------------
# end-to-end ACTIVE path over a header-aware FakeHttp
# --------------------------------------------------------------------------------------


def _scope(**changes: Any) -> Scope:
    data = {
        "authorization_ref": REF,
        "owner": "CORS engagement",
        "contacts": ["soc@acme.test"],
        "ticket": "PT-283",
        "window_start": WINDOW[0],
        "window_end": WINDOW[1],
        "targets": {"domains": ["acme.test", "*.acme.test"]},
    }
    data.update(changes)
    return Scope.from_dict(data)


def _options(scope: Scope) -> ScanOptions:
    return ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF, scope=scope,
                       include={"cors_probe"}, threads=1, save_evidence=False)


# the deterministic 'prefix' forged Origin for HOST (the random 'arbitrary' one is unpredictable)
PREFIX_ORIGIN = f"https://{HOST}.v3lum-probe.invalid"
USER_BODY = b'{"username": "redacted", "profile": {"id": 1}}'  # synthetic account-like fields (FC5)
PUBLIC_BODY = b'{"status": "ok", "version": 3}'  # structured, but no user data


def _http(reflect: bool = False, *, acac: bool = False, user_data: bool = True, wildcard: bool = False,
          blocked: bool = False, preflight_reflect: bool = False, challenge_200: bool = False) -> FakeHttp:
    """A FakeHttp answering the seed GET (and the OPTIONS preflight the module sends when a GET carries no
    CORS header). For a reflecting server, a route matched on the (deterministic) 'prefix' forged Origin
    echoes it; the other forged Origins hit the catch-all routes."""
    clock = FakeClock()
    http = FakeHttp(clock=clock)
    add_dns(http, HOST, "A", [PUBLIC_IP])
    add_dns(http, HOST, "AAAA", [])
    ctype = "application/json"
    body = USER_BODY if user_data else PUBLIC_BODY
    if blocked:
        http.add("GET", SEED, status=403, text="Just a moment...", headers={"server": "cloudflare", "cf-mitigated": "challenge"})
        return http
    if challenge_200:
        # an anti-bot interstitial served with HTTP 200 (error-in-200): the core's P321 classifier flags it
        http.add("GET", SEED, status=200, text="<html><head><title>Just a moment...</title></head><body>cf-chl</body></html>",
                 headers={"content-type": "text/html", "cf-mitigated": "challenge"})
        return http
    if reflect:
        reflected = {"content-type": ctype, "access-control-allow-origin": PREFIX_ORIGIN, "vary": "Origin"}
        if acac:
            reflected["access-control-allow-credentials"] = "true"
        http.add("GET", SEED, status=200, body=body, headers=reflected, match_headers={"origin": PREFIX_ORIGIN})
    base = {"content-type": ctype}
    if wildcard:
        base["access-control-allow-origin"] = "*"
    http.add("GET", SEED, status=200, body=body, headers=base)  # catch-all for the other Origins
    if preflight_reflect:
        pre = {"access-control-allow-origin": PREFIX_ORIGIN, "access-control-allow-credentials": "true",
               "access-control-allow-methods": "GET, OPTIONS"}
        http.add("OPTIONS", SEED, status=204, body=b"", headers=pre,
                 match_headers={"origin": PREFIX_ORIGIN, "access-control-request-method": "GET"})
    http.add("OPTIONS", SEED, status=204, body=b"", headers={})  # preflight without CORS headers
    return http


def _run(http: FakeHttp, **kw: Any) -> Any:
    rt = make_runtime(http, clock=http.clock)
    return run_module(CorsProbe, f"url:{SEED}", runtime=rt, options=_options(_scope()), **kw)


def test_reflected_with_credentials_end_to_end_is_high():
    res = _run(_http(reflect=True, acac=True))
    assert res.status is Status.OK
    high = [f for f in res.findings if f.severity.name == "HIGH"]
    assert high and "forged origin with credentials" in high[0].title.lower()
    assert list(high[0].attack) == ["T1539"]
    rows = res.attributes["cors_results"]
    assert any(r["acao_reflected"] and r["acac"] for r in rows)
    assert res.attributes["cors_endpoints_tested"] == 1


def test_reflection_without_credentials_user_data_is_medium():
    res = _run(_http(reflect=True, acac=False, user_data=True))
    med = [f for f in res.findings if f.severity.name == "MEDIUM"]
    assert med and not [f for f in res.findings if f.severity.name == "HIGH"]


def test_wildcard_is_info_once_per_endpoint():
    res = _run(_http(wildcard=True))
    info = [f for f in res.findings if f.severity.name == "INFO"]
    assert len(info) == 1  # ACAO '*' recorded once, not once per forged Origin (dedup)


def test_no_cors_is_ok_no_finding():
    res = _run(_http(reflect=False))
    assert res.status is Status.OK
    assert not res.findings
    assert res.attributes["cors_endpoints_tested"] == 1


def test_blocked_is_could_not_test_never_empty():
    res = _run(_http(blocked=True))
    assert res.status is Status.BLOCKED
    assert "could not test" in res.error.lower()


def test_each_forged_origin_is_actually_sent():
    http = _http(reflect=True, acac=True)
    _run(http)
    sent = {c["headers"].get("Origin") for c in http.calls if "acme.test" in c["url"] and c.get("headers")}
    assert "null" in sent
    assert PREFIX_ORIGIN in sent  # the target host intact, under .invalid (FC4)
    assert any(o and o.endswith(".invalid") and HOST in o and not o.startswith(f"https://{HOST}") for o in sent)  # suffix trick
    assert sum(1 for o in sent if o and ".v3lum-probe.invalid" in o) >= 2
    assert all(o == "null" or o.endswith(".invalid") for o in sent if o)


def test_only_get_and_options_without_credentials_are_sent():
    http = _http(reflect=False)
    _run(http)
    target_calls = [c for c in http.calls if "acme.test" in c["url"] and "dns" not in c["url"]]
    assert target_calls and {c["method"] for c in target_calls} <= {"GET", "OPTIONS"}
    for c in target_calls:
        names = {k.lower() for k in (c.get("headers") or {})}
        assert not names & {"cookie", "authorization", "proxy-authorization"}
        if c["method"] == "OPTIONS":
            assert (c.get("headers") or {}).get("Access-Control-Request-Method") == "GET"
    # 1 endpoint x 4 forged Origins, each GET plus at most one preflight (FC3 cap)
    assert len(target_calls) <= 8


def test_preflight_only_reflection_with_credentials_is_high():
    res = _run(_http(reflect=False, preflight_reflect=True))
    high = [f for f in res.findings if f.severity.name == "HIGH"]
    assert high
    assert any(r["method"] == "OPTIONS" and r["acao_reflected"] and r["acac"] for r in res.attributes["cors_results"])


def test_reflection_without_credentials_public_json_is_low_not_medium():
    res = _run(_http(reflect=True, acac=False, user_data=False))
    assert [f for f in res.findings if f.severity.name == "LOW"]
    assert not [f for f in res.findings if f.severity.name in ("MEDIUM", "HIGH")]


def test_challenge_in_http_200_is_could_not_test():
    res = _run(_http(challenge_200=True))
    assert res.status is Status.BLOCKED
    assert not res.findings


def test_pivots_and_text_extracted_entities_never_probed():
    # FC1: never on pivots or on entities extracted from text/files - nothing is sent
    for kw in ({"is_seed": False, "depth": 1}, {"provenance": [("file:report.txt", "mentions", "ioc_extract")]}):
        http = _http(reflect=True, acac=True)
        res = _run(http, **kw)
        assert res.status is Status.SKIPPED
        assert not [c for c in http.calls if c["url"].startswith(SEED)]
    assert CorsProbe.run_on == "seeds"


def test_health_selftest_offline():
    hc = CorsProbe.health_check()
    assert hc.offline is True
    rt = make_runtime()
    ctx = rt.context(CorsProbe, ScanOptions(mode=Opsec.ACTIVE), run=None)
    assert hc.selftest(ctx).status == "ok"
