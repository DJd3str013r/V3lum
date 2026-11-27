"""path_discovery (P285): ACTIVE forced browsing - offline tests with tests/fakes.py and a loopback server.

Safety expectations proven here: no request outside the scope or to a pivot, GET only, the host stops
at the first 429/challenge, forbidden actuator/introspection paths are never requested, redirect hops
are re-checked by the core (an out-of-scope hop is never sent), the kill switch stops the loop, the
default list stays <= 50 paths and a wordlist above 5,000 entries is refused.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
from importlib import resources
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.fakes import FakeHttp, add_dns, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.clock import SYSTEM_CLOCK
from v3lum.core.context import ScanOptions
from v3lum.core.http import RequestsTransport
from v3lum.core.models import Opsec, Severity, Status
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon import forced_browsing as fb
from v3lum.modules.pentest_recon.path_discovery import (
    DEFAULT_LIST,
    DEFAULT_LIST_SHA256,
    PathDiscovery,
    base_url,
    load_default_list,
)

REF = "PENTEST-2026-042"
HOST = "www.acme.example"
IP = "93.184.216.34"
BASE = f"https://{HOST}"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "path_discovery"
FORBIDDEN = ("heapdump", "/env", "logfile", "threaddump", "configprops", "__schema", "introspection", "jolokia", "/api/login")


def scope(**changes):
    data = {
        "authorization_ref": REF, "owner": "Engagement owner (tests)", "contacts": ["soc@acme.example"], "ticket": "T-1",
        "window_start": "2026-11-26T00:00:00Z", "window_end": "2026-11-27T00:00:00Z",
        "targets": {"domains": ["acme.example", "*.acme.example"], "cidrs": ["93.184.216.0/24"]},
        "exclusions": {"domains": ["mail.acme.example"]},
    }
    data.update(changes)
    return Scope.from_dict(data)


def active(sc=None, **kw):
    return ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF, scope=sc or scope(), **kw)


def exchange_fixture(name):
    """The response part of a trimmed exchange fixture (tests/fixtures/path_discovery/*.http.json)."""
    data = module_fixture("path_discovery", name)
    resp = data["response"]
    return resp["status"], resp.get("headers") or {}, resp.get("body") or ""


def target(*, soft404=True):
    http = FakeHttp()
    add_dns(http, HOST, "A", [IP])
    add_dns(http, HOST, "AAAA", [])
    return http


def route(http, path, name):
    status, headers, body = exchange_fixture(name)
    http.add("GET", BASE + path, status=status, text=body, headers=headers)


def soft404_catch_all(http):
    status, headers, body = exchange_fixture("soft404_miss.http.json")
    # the soft-404 page reflects the requested path: the engine normalises it away
    http.add("GET", BASE + "/*", status=status, text=body.replace("/api/v2", "/whatever"), headers=headers)


def target_calls(http):
    return [c for c in http.calls if c["url"].startswith(BASE)]


def paths_sent(http):
    return [c["url"][len(BASE):] for c in target_calls(http)]


# --------------------------------------------------------------------------------------------- lists


def test_default_list_is_pinned_capped_and_policy_clean():
    raw = resources.files("v3lum.data").joinpath(DEFAULT_LIST).read_bytes()
    entries = load_default_list(raw)
    assert 0 < len(entries) <= fb.DEFAULT_LIST_CAP == 50
    assert all(fb.path_policy_reason(e["path"]) is None and e["source"] for e in entries)
    with pytest.raises(ValueError, match="pin"):
        load_default_list(raw + b" ")
    assert DEFAULT_LIST_SHA256


def test_wordlist_cap_5000_and_policy_filter():
    big = "\n".join(f"dir{i}" for i in range(5001)).encode()
    parsed = fb.parse_wordlist(big)
    assert parsed["over_cap"] and parsed["total"] == 5001 and len(parsed["entries"]) == fb.WORDLIST_CAP == 5000
    text = (FIXTURES / "wordlist_spring_boot.txt").read_bytes()
    spring = fb.parse_wordlist(text)
    assert not spring["over_cap"] and spring["dropped"]["forbidden_fc6_actuator"] > 0
    assert not any(any(w in p for w in ("heapdump", "/env", "threaddump")) for p in spring["entries"])
    malformed = fb.parse_wordlist((FIXTURES / "wordlist_malformed.txt").read_bytes())
    assert all(fb.path_policy_reason(p) is None for p in malformed["entries"])


def test_over_cap_wordlist_is_refused_never_truncated(tmp_path, monkeypatch):
    listing = tmp_path / "huge.txt"
    listing.write_text("\n".join(f"p{i}" for i in range(6000)))
    ctx = make_ctx(PathDiscovery, entity=f"domain:{HOST}", options=active(), settings={"path_discovery_wordlist": "common"})
    monkeypatch.setattr(ctx.data, "fetch", lambda name, *a, **k: listing)
    with pytest.raises(ValueError, match="5,000"):
        PathDiscovery()._paths(ctx, "common")


@pytest.mark.parametrize(("path", "reason"), [
    ("/actuator/heapdump", "forbidden_fc6_actuator"), ("/env", "forbidden_fc6_actuator"), ("/actuator/trace", "sensitive_actuator"),
    ("/graphql?query={__schema{types{name}}}", "graphql_introspection"), ("/api/login", "operation_name"),
    ("/../../etc", "traversal"), ("https://evil.example/x", "absolute_url"), ("/a?b=c", "query_string"), ("/FUZZ", "placeholder"),
])
def test_path_policy_refuses_forbidden_paths(path, reason):
    assert fb.path_policy_reason(path) == f"policy: {reason}"


def test_base_url_from_domain_and_url():
    from v3lum.core.entities import Entity

    assert base_url(Entity.make("domain", HOST)) == BASE
    assert base_url(Entity.make("url", f"{BASE}/app/index.php?x=1")) == f"{BASE}/app"
    assert base_url(Entity.make("url", f"{BASE}/")) == BASE


# --------------------------------------------------------------------------------------------- runs


def test_soft404_host_confirms_only_signatures_and_lists_actuator_dumps_without_requesting_them():
    http = target()
    route(http, "/openapi.json", "openapi_ok.http.json")
    route(http, "/actuator", "actuator_index_ok.http.json")
    route(http, "/manager/html", "tomcat_manager_401.http.json")
    route(http, "/graphql", "graphql_get_400.http.json")
    http.add("GET", BASE + "/admin/", redirect_to=BASE + "/accounts/login/?next=/admin/")
    http.add("GET", BASE + "/accounts/login/?next=/admin/", text="<html><title>Log in</title></html>")
    soft404_catch_all(http)
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status is Status.OK, res.error
    summary = res.attributes["path_discovery"]
    assert summary["list"] == "default" and summary["list_sha256"] == DEFAULT_LIST_SHA256
    assert summary["calibration"] == "soft_404" and summary["tested"] == 41
    found = {c["path"]: c for c in summary["confirmed"]}
    assert set(found) == {"/openapi.json", "/actuator", "/manager/html", "/graphql"}
    assert set(found["/openapi.json"]) == {"path", "status", "content_type", "title", "length", "kind", "detail"}
    assert summary["actuator"]["forbidden_present"] and "heapdump" in summary["actuator"]["forbidden_present"]
    titles = {f.title: f for f in res.findings}
    assert titles["Actuator index lists sensitive endpoints"].severity is Severity.HIGH
    assert {"API description document exposed", "GraphQL endpoint reachable", "Administration panel reachable"} <= set(titles)
    assert all(p.expand is False and p.relation == "discovered_path" for p in res.pivots)
    sent = paths_sent(http)
    assert all(fb.path_policy_reason(p) is None for p in sent)
    assert not any(word in p.lower() for p in sent for word in FORBIDDEN)
    assert all(c["method"] == "GET" for c in target_calls(http))
    # the redirect to a login page is a miss: the core never follows it (login wall) and the engine says not observed
    assert "/accounts/login/?next=/admin/" not in sent and "/admin/" not in found
    http.assert_hosts_within(PathDiscovery, extra=(HOST,))


def test_hard_404_host_with_nothing_found_is_not_observed():
    http = target()
    route(http, "/swagger-ui.html", "swagger_ui_ok.http.json")
    http.add("GET", BASE + "/*", status=404, text="<html><title>404 Not Found</title></html>")
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    summary = res.attributes["path_discovery"]
    assert res.status is Status.OK and summary["calibration"] == "hard_404"
    assert [c["path"] for c in summary["confirmed"]] == ["/swagger-ui.html"]
    assert summary["counts"]["not_observed"] == 40


def test_nothing_found_reports_counts_not_absence():
    http = target()
    http.add("GET", BASE + "/*", status=404, text="nope")
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status is Status.OK
    summary = res.attributes["path_discovery"]
    assert summary["state"] == "not_observed" and summary["counts"] == {"confirmed": 0, "not_observed": 41, "could_not_test": 0}
    assert not res.pivots


def test_429_at_calibration_stops_the_host_at_the_first_answer():
    http = target()
    status, headers, body = exchange_fixture("rate_limited_429.http.json")
    http.add("GET", BASE + "/*", status=status, text=body, headers=headers)
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status is Status.RATE_LIMITED
    assert len(target_calls(http)) <= 2  # the first 429 stops the host (at most the core's single short Retry-After retry)


@pytest.mark.parametrize("name", ["challenge_cloudflare.http.json", "error_in_200_f5.http.json", "aws_waf_challenge_202.http.json"])
def test_challenge_or_waf_page_at_calibration_is_blocked(name):
    http = target()
    status, headers, body = exchange_fixture(name)
    http.add("GET", BASE + "/*", status=status, text=body, headers=headers)
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert len(target_calls(http)) == 1


def test_challenge_mid_run_stops_the_host_and_is_could_not_test():
    http = target()
    status, headers, body = exchange_fixture("challenge_cloudflare.http.json")
    http.add("GET", BASE + "/swagger.json", status=status, text=body, headers=headers)
    http.add("GET", BASE + "/*", status=404, text="nope")
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status is Status.BLOCKED
    summary = res.attributes["path_discovery"]
    assert summary["host_stop"].startswith("challenge") and summary["counts"]["could_not_test"] >= 30
    assert paths_sent(http)[-1] == "/swagger.json"  # nothing after the stop


def test_403_for_random_paths_is_blocked_never_absent():
    http = target()
    status, headers, body = exchange_fixture("forbidden_403.http.json")
    http.add("GET", BASE + "/*", status=status, text=body, headers=headers)
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status is Status.BLOCKED and len(target_calls(http)) == 3


def test_timeouts_are_errors_never_absent():
    from v3lum.core.http import NetworkError

    http = target()
    http.add("GET", BASE + "/*", error=NetworkError("read timed out", kind="ReadTimeout"))
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status is Status.ERROR and "could not test" in res.error


def test_proxy_answer_is_egress_could_not_test():
    http = target()
    status, headers, body = exchange_fixture("proxy_error.http.json")
    http.add("GET", BASE + "/*", status=status, text=body, headers=headers)
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status in (Status.ERROR, Status.BLOCKED) and res.status is not Status.EMPTY


def test_malformed_and_odd_answers_never_crash():
    http = target()
    status, headers, body = exchange_fixture("malformed.http.json")
    http.add("GET", BASE + "/openapi.json", status=status, text=body, headers=headers)
    http.add("GET", BASE + "/*", status=404, text="nope")
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status in (Status.OK, Status.EMPTY)


def test_out_of_scope_redirect_hop_is_never_sent():
    http = target()
    http.add("GET", BASE + "/api", redirect_to="https://cdn.example.net/assets/")
    http.add("GET", BASE + "/*", status=404, text="nope")
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status is Status.OK
    assert not [c for c in http.calls if "example.net" in c["url"]]
    assert res.attributes["path_discovery"]["counts"]["could_not_test"] >= 1


def test_out_of_scope_seed_gets_no_request():
    http = FakeHttp()
    add_dns(http, "www.other.example", "A", ["93.184.217.66"])
    add_dns(http, "www.other.example", "AAAA", [])
    res = run_module(PathDiscovery, "domain:www.other.example", http, options=active())
    assert res.status is Status.SKIPPED
    assert not [c for c in http.calls if c["url"].startswith("https://www.other.example")]


def test_pivots_are_never_probed():
    http = target()
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active(), is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and not target_calls(http)


def test_without_scope_active_contact_is_refused():
    http = target()
    opts = ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF)
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=opts)
    assert res.status is Status.SKIPPED and not target_calls(http)


def test_kill_switch_stops_the_loop():
    class Cancelling(FakeHttp):
        def __init__(self):
            super().__init__()
            self.rt = None

        def send(self, method, url, **kw):
            resp = super().send(method, url, **kw)
            if url.startswith(BASE) and len([c for c in self.calls if c["url"].startswith(BASE)]) == 6:
                self.rt.cancel("cancelled")
            return resp

    http = Cancelling()
    add_dns(http, HOST, "A", [IP])
    add_dns(http, HOST, "AAAA", [])
    http.add("GET", BASE + "/*", status=404, text="nope")
    rt = make_runtime(http)
    http.rt = rt
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active(), runtime=rt)
    assert len(target_calls(http)) <= 7
    assert res.partial and res.stop_reason == "cancelled"


def test_login_redirect_for_every_path_is_a_login_wall_never_not_observed():
    http = target()
    http.add("GET", BASE + "/*", redirect_to=BASE + "/login?next=/x")
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status is Status.BLOCKED and res.reason_code == "login_wall", res.error
    summary = res.attributes["path_discovery"]
    assert summary["baseline_wall"] == "login_wall"
    assert summary["counts"] == {"confirmed": 0, "not_observed": 0, "could_not_test": 41}
    assert not [c for c in http.calls if "/login" in c["url"]]  # never followed
    assert not res.pivots


def test_login_wall_host_still_confirms_a_public_signature():
    http = target()
    route(http, "/actuator/health", "actuator_health_ok.http.json")
    http.add("GET", BASE + "/*", redirect_to=BASE + "/login?next=/x")
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status is Status.OK, res.error
    summary = res.attributes["path_discovery"]
    assert [c["path"] for c in summary["confirmed"]] == ["/actuator/health"]
    assert summary["counts"]["could_not_test"] == 40 and summary["counts"]["not_observed"] == 0


def test_401_for_random_paths_is_could_not_test_never_not_observed():
    http = target()
    http.add("GET", BASE + "/*", status=401, text="<html><title>401 Authorization Required</title></html>",
             headers={"content-type": "text/html", "www-authenticate": 'Basic realm="staging"'})
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.status is Status.BLOCKED and res.reason_code == "login_wall", res.error
    summary = res.attributes["path_discovery"]
    assert summary["calibration"] == "auth" and summary["baseline_wall"] == "auth"
    assert summary["counts"]["not_observed"] == 0 and summary["counts"]["could_not_test"] == 41


def test_run_deadline_mid_loop_is_partial_and_sends_nothing_after_it():
    from v3lum.core.http import DeadlineExceeded

    http = target()
    route(http, "/openapi.json", "openapi_ok.http.json")
    http.add("GET", BASE + "/swagger.json", error=DeadlineExceeded("run deadline reached: request not sent"))
    http.add("GET", BASE + "/*", status=404, text="nope")
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active())
    assert res.partial and res.stop_reason == "deadline", (res.status, res.error)
    assert res.status is Status.OK
    sent = paths_sent(http)
    assert sent[-1] == "/swagger.json" and "/swagger.yaml" not in sent  # nothing after the deadline
    summary = res.attributes["path_discovery"]
    assert [c["path"] for c in summary["confirmed"]] == ["/openapi.json"]
    assert summary["tested"] == 2 and summary["counts"]["could_not_test"] == 39


def test_seclists_wordlist_run_is_pinned_policy_filtered_and_paced_at_5_per_second():
    from v3lum.modules.pentest_recon.path_discovery import SECLISTS_COMMIT, WORDLISTS, dataset_name

    class Timed(FakeHttp):
        def send(self, method, url, **kw):
            if url.startswith(BASE):
                self.sent_at.append(self.clock.monotonic())
            return super().send(method, url, **kw)

    http = Timed()
    http.sent_at = []
    add_dns(http, HOST, "A", [IP])
    add_dns(http, HOST, "AAAA", [])
    raw = (FIXTURES / "wordlist_graphql.txt").read_bytes()
    seclists = f"https://raw.githubusercontent.com/danielmiessler/SecLists/{SECLISTS_COMMIT}/{WORDLISTS['graphql'][0]}"
    http.add("GET", seclists, body=raw, headers={"content-type": "text/plain; charset=utf-8"})
    http.add("GET", BASE + "/*", status=404, text="nope")
    rt = make_runtime(http, settings={"path_discovery_wordlist": "graphql"})
    installed = rt.data.update(dataset_name("graphql"))
    assert installed.new_sha256 == WORDLISTS["graphql"][1], installed
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active(), runtime=rt)
    summary = res.attributes["path_discovery"]
    assert summary["list"] == "seclists:graphql" and summary["list_sha256"] == WORDLISTS["graphql"][1]
    expected = fb.parse_wordlist(raw)["entries"]
    assert paths_sent(http)[3:] == expected and summary["tested"] == len(expected)  # 3 calibration probes first
    assert all(fb.path_policy_reason(p) is None for p in paths_sent(http))
    gaps = [b - a for a, b in zip(http.sent_at, http.sent_at[1:])]
    assert gaps and min(gaps) >= 0.2 - 1e-9  # <= 5 req/s per host for SecLists lists (P285 cond 4)


def test_wordlist_not_installed_is_unavailable_and_never_fetched_mid_run():
    http = target()
    http.add("GET", "https://raw.githubusercontent.com/*", body=b"graphql\n", headers={"content-type": "text/plain"})
    http.add("GET", BASE + "/*", status=404, text="nope")
    res = run_module(PathDiscovery, f"domain:{HOST}", http, options=active(), settings={"path_discovery_wordlist": "graphql"})
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert not [c for c in http.calls if "githubusercontent" in c["url"]] and not target_calls(http)  # `v3lum data update` only


def test_offline_selftest():
    hc = PathDiscovery.health_check()
    assert hc.offline and callable(hc.selftest)
    ctx = make_ctx(PathDiscovery)
    assert hc.selftest(ctx).status == "ok"


# --------------------------------------------------------------------------------------------- loopback


class _Site(BaseHTTPRequestHandler):
    """Loopback target: soft-404 pages that echo the path, a login redirect and a phpMyAdmin panel."""

    seen: list[tuple[str, str]] = []

    def log_message(self, *args):  # silence
        pass

    def do_GET(self):  # noqa: N802 - http.server API
        type(self).seen.append((self.command, self.path))
        if self.path == "/phpmyadmin/":
            self._send(200, "<html><head><title>phpMyAdmin</title></head><body>Welcome</body></html>")
        elif self.path == "/admin/":
            self.send_response(302)
            self.send_header("Location", "/user/login?next=/admin/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path.startswith("/user/login"):
            self._send(200, "<html><head><title>Sign in</title></head><body>form</body></html>")
        elif self.path == "/v3/api-docs":
            self._send(200, json.dumps({"openapi": "3.0.1", "info": {"title": "demo"}}), "application/json")
        else:
            self._send(200, f"<html><head><title>Example</title></head><body>Page {self.path} not found, id 12345678</body></html>")

    def _send(self, status, body, ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def site():
    _Site.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def test_loopback_server_soft404_login_redirect_and_panel(site):
    url = f"http://127.0.0.1:{site}/"
    now = _dt.datetime.now(_dt.timezone.utc)
    window = {"window_start": (now - _dt.timedelta(hours=1)).isoformat(), "window_end": (now + _dt.timedelta(hours=1)).isoformat()}
    sc = scope(targets={"domains": ["acme.example"], "cidrs": ["127.0.0.1/32"]}, **window)
    rt = make_runtime(RequestsTransport(trust_env=False), clock=SYSTEM_CLOCK)
    res = run_module(PathDiscovery, f"url:{url}", options=active(sc), runtime=rt)
    assert res.status is Status.OK, res.error
    summary = res.attributes["path_discovery"]
    assert summary["calibration"] == "soft_404"
    assert {c["path"] for c in summary["confirmed"]} == {"/phpmyadmin/", "/v3/api-docs"}
    assert all(method == "GET" for method, _ in _Site.seen)
    assert ("GET", "/user/login?next=/admin/") not in _Site.seen  # a redirect to a login page is a miss, never followed
    assert not any(w in p for _, p in _Site.seen for w in ("heapdump", "__schema"))
    assert len(_Site.seen) == 3 + 41  # calibration + the default list, nothing else
