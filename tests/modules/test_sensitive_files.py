"""sensitive_files (P279, ACTIVE): content signatures on the first KB, soft-404 calibration, login
redirects, the 429/challenge stop, tri-state outcomes, evidence without values or secrets, the
pinned path list, and the A7 envelope (scope, GET only, Range, no-store). Fixtures:
tests/fixtures/sensitive_files/ (answers built to the real formats: git, httpd mod_status, php-src,
stdlib zip/gzip, a real Cloudflare challenge capture). A loopback HTTP server exercises the real
transport (FC10)."""

from __future__ import annotations

import base64
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tests.fakes import FIXTURES, FakeHttp, add_dns, assert_no_secret, make_ctx, make_runtime, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Confidence, Opsec, Status
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon import sensitive_files as sf
from v3lum.modules.pentest_recon.sensitive_files import SensitiveFiles

FIX = Path(FIXTURES) / "sensitive_files"
REF = "PENTEST-2026-042"
HOST = "www.example.com"
BASE = f"https://{HOST}"
CALIBRATION = re.compile(r"^https://www\.example\.com/\.?[0-9a-f]{24}$")
SECRETS = (
    "s3nh4-f4ls4-de-teste", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "fake-stripe-test-secret-0000",
    "ZmFrZS1rZXktZm9yLXRlc3RzLW9ubHktMDAwMDAwMDA=", "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000", "$apr1$abcdefgh$FAKEFAKEFAKEFAKEFAKE00",
    "usuario-exemplo", "s3nh4-wp-f4ls4", "FAKETOKENFAKETOKEN1234", "203.0.113.77", "usuario1@example.com", "beyond-the-first-kb",
)


def scope(**targets) -> Scope:
    return Scope.from_dict({
        "authorization_ref": REF, "owner": "Engagement owner (tests)", "contacts": ["soc@example.com"], "ticket": "T-1",
        "window_start": "2026-11-26T00:00:00Z", "window_end": "2026-11-27T00:00:00Z",
        "targets": targets or {"domains": ["example.com", "*.example.com"], "cidrs": ["93.184.216.0/24"]},
    })


def active(sc: Scope | None = None) -> ScanOptions:
    return ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF, scope=sc if sc is not None else scope())


def load(name: str) -> tuple[int, dict, bytes]:
    data = json.loads((FIX / name).read_text(encoding="utf-8"))
    resp = data["response"]
    body = base64.b64decode(resp["body_b64"]) if "body_b64" in resp else str(resp.get("body") or "").encode("utf-8")
    return resp["status"], dict(resp.get("headers") or {}), body


def answer(http: FakeHttp, url, name: str) -> None:
    status, headers, body = load(name)
    http.add("GET", url, status=status, body=body, headers=headers)


def site(**overrides: str) -> FakeHttp:
    """A target whose every unlisted path answers 404; ``overrides`` maps a path to a fixture name."""
    http = FakeHttp()
    add_dns(http, HOST, "A", ["93.184.216.34"])
    add_dns(http, HOST, "AAAA", [])
    calibration = overrides.pop("calibration", "calibration_404.http.json")
    for path, name in overrides.items():
        answer(http, BASE + path, name)
    answer(http, CALIBRATION, calibration)
    answer(http, re.compile(r"^https://www\.example\.com/.*$"), "not_found_404.http.json")
    return http


def target_calls(http: FakeHttp) -> list[dict]:
    return [c for c in http.calls if c["url"].startswith(BASE + "/")]


def run(http: FakeHttp, **kw):
    return run_module(SensitiveFiles, f"domain:{HOST}", http, options=kw.pop("options", None) or active(), **kw)


# ---------------------------------------------------------------------------------- confirmed exposures
def test_git_head_and_env_are_confirmed_by_content_and_env_keeps_names_only():
    http = site(**{"/.git/HEAD": "git_head_206.http.json", "/.env": "env_206.http.json"})
    res = run(http)
    assert res.status is Status.OK, res.error
    rows = {r["path"]: r for r in res.attributes["sensitive_files"]}
    assert set(rows) == {"/.git/HEAD", "/.env"}
    assert rows["/.git/HEAD"]["signature"] == "git HEAD ref" and len(rows["/.env"]["sha256"]) == 64
    summary = res.attributes["sensitive_files_summary"]
    assert summary["paths_tested"] == 23 and summary["confirmed"] == 2 and summary["list"] == ["/.git/HEAD", "/.env"]
    env = next(f for f in res.findings if f.key == "/.env")
    assert env.severity.label == "high" and env.confidence_label is Confidence.CONFIRMED
    assert set(env.attack) == {"T1213", "T1552.001"}
    assert "DB_PASSWORD" in env.data["env_names"] and "AWS_SECRET_ACCESS_KEY" in env.data["flagged_names"]
    assert env.data["excerpt"].startswith("variable names (values dropped): APP_NAME, APP_ENV")
    head = next(f for f in res.findings if f.key == "/.git/HEAD")
    assert head.data["excerpt"] == "ref: refs/heads/main" and head.attack == ["T1213"]
    # values and secrets never reach the result (evidence, attributes, findings)
    for secret in SECRETS:
        assert_no_secret(secret, res.to_dict())
    # exposures are listed for the analyst, never auto-expanded (would leak them to third-party URL services)
    assert {p.entity.value for p in res.pivots} == {BASE + "/.git/HEAD", BASE + "/.env"} and not any(p.expand for p in res.pivots)


def test_every_request_is_a_first_kb_get_to_the_scope_and_no_forbidden_path():
    http = site(**{"/.git/HEAD": "git_head_206.http.json"})
    run(http)
    calls = target_calls(http)
    assert len(calls) == 25  # 2 calibration paths + 23 pinned paths (max_requests)
    assert {c["method"] for c in calls} == {"GET"}
    assert all(c["headers"].get("Range") == "bytes=0-1023" and c["max_bytes"] == 1024 for c in calls)
    assert all(c.get("pin_ip") == "93.184.216.34" for c in calls)
    forbidden = re.compile(r"\.git/(objects|index|packed-refs|refs|logs)|\.svn/wc\.db|\.\.")
    assert not any(forbidden.search(c["url"]) for c in calls)
    assert any(c["url"] == BASE + "/example.com.zip" for c in calls)  # '{domain}' = the registrable domain


@pytest.mark.parametrize(("path", "name", "signature", "severity"), [
    ("/.git/config", "git_config_206.http.json", "git config [core]", "high"),
    ("/.DS_Store", "ds_store_206.http.json", ".DS_Store magic", "medium"),
    ("/backup.zip", "zip_206.http.json", "zip local header PK\\x03\\x04", "high"),
    ("/backup.tar.gz", "gzip_206.http.json", "gzip magic 1f8b08", "high"),
    ("/.htpasswd", "htpasswd_206.http.json", "htpasswd user:hash lines", "high"),
    ("/server-status", "server_status_200.http.json", "Apache server-status page", "medium"),
    ("/phpinfo.php", "phpinfo_206.http.json", "phpinfo() stylesheet", "medium"),
    ("/backup.sql", "sql_dump_206.http.json", "SQL dump statements", "high"),
    ("/wp-config.php.bak", "wp_config_bak_206.http.json", "PHP config source", "high"),
    ("/main.js.map", "source_map_webpack_206.http.json", 'source map "mappings"', "low"),
    ("/app.js.map", "source_map_esbuild_206.http.json", 'source map v3 "sources"', "low"),
    ("/.svn/entries", "svn_entries_200.http.json", "svn entries format", "medium"),
    ("/.git/HEAD", "git_head_detached_200.http.json", "git HEAD ref", "high"),
])
def test_signatures_and_masked_evidence(path, name, signature, severity):
    http = site(**{path: name})
    res = run(http)
    finding = next(f for f in res.findings if f.key == path)
    assert finding.data["signature"] == signature and finding.severity.label == severity
    for secret in SECRETS:
        assert_no_secret(secret, res.to_dict())
    if path == "/.git/config":
        assert finding.data["remote_hosts"] == ["git.example.com"] and finding.data["remote_url_userinfo"] is True
    if path == "/server-status":
        assert finding.data["server_version"].startswith("Apache/2.4.62")
    if path == "/wp-config.php.bak":
        assert "DB_PASSWORD" in finding.data["constant_names"]


# ---------------------------------------------------------------------------------- misses (never confirmed)
def test_soft_404_and_html_pages_are_never_confirmed():
    http = site(calibration="calibration_1_soft404_200.http.json", **{"/.env": "soft404_hit_200.http.json",
                                                                       "/.env.bak": "env_html_200.http.json",
                                                                       "/.env.production": "env_malformed_binary_200.http.json"})
    res = run(http)
    assert "sensitive_files" not in res.attributes and res.findings == []
    assert res.attributes["sensitive_files_summary"]["not_observed"] == 23


def test_login_redirect_is_a_miss_and_never_followed():
    http = site(**{"/.env": "login_redirect_302.http.json"})
    res = run(http)
    assert res.findings == [] and res.status is Status.OK
    assert not any("/login" in c["url"] for c in target_calls(http))


def test_range_ignored_reads_only_the_first_kb():
    http = site(**{"/.env.production": "range_ignored_200.http.json"})
    res = run(http)
    finding = next(f for f in res.findings if f.key == "/.env.production")
    assert finding.data["bytes_read"] <= 1024 and "LATE_SECRET" not in finding.data["env_names"]
    assert_no_secret("beyond-the-first-kb", res.to_dict())


def test_416_and_503_are_not_observed_and_could_not_test():
    http = site(**{"/.env.bak": "range_416.http.json", "/server-status": "server_error_503.http.json"})
    summary = run(http).attributes["sensitive_files_summary"]
    assert summary["could_not_test"] == 1 and summary["not_observed"] == 22


# ---------------------------------------------------------------------------------- rule 5: could not verify
def test_first_429_stops_the_host_and_keeps_what_was_confirmed():
    http = site(**{"/.git/HEAD": "git_head_206.http.json", "/.git/config": "rate_limited_429.http.json"})
    res = run(http)
    assert (res.status, res.reason_code) == (Status.RATE_LIMITED, "rate_limited") and res.partial
    assert [r["path"] for r in res.attributes["sensitive_files"]] == ["/.git/HEAD"]
    urls = [c["url"] for c in target_calls(http)]
    assert urls[-1] == BASE + "/.git/config"  # nothing after the 429
    assert "first 429" in res.error


def test_challenge_stops_the_host_blocked():
    http = site(**{"/.env": "challenge_403.http.json"})
    res = run(http)
    assert (res.status, res.reason_code) == (Status.BLOCKED, "challenge")
    assert [c["url"] for c in target_calls(http)][-1] == BASE + "/.env"


def test_every_path_forbidden_is_could_not_verify_never_absent():
    http = FakeHttp()
    add_dns(http, HOST, "A", ["93.184.216.34"])
    add_dns(http, HOST, "AAAA", [])
    answer(http, CALIBRATION, "calibration_404.http.json")
    answer(http, re.compile(r"^https://www\.example\.com/.*$"), "forbidden_403.http.json")
    res = run(http)
    assert (res.status, res.reason_code) == (Status.BLOCKED, "challenge")
    assert res.attributes["sensitive_files_summary"]["could_not_test"] == 23


def test_every_path_failing_with_5xx_is_error_not_a_challenge():
    http = FakeHttp()
    add_dns(http, HOST, "A", ["93.184.216.34"])
    add_dns(http, HOST, "AAAA", [])
    answer(http, CALIBRATION, "calibration_404.http.json")
    answer(http, re.compile(r"^https://www\.example\.com/.*$"), "server_error_503.http.json")
    res = run(http)
    assert (res.status, res.reason_code) == (Status.ERROR, "error") and "never 'absent'" in res.error
    summary = res.attributes["sensitive_files_summary"]
    assert summary["could_not_test"] == 23 and summary["denied"] == 0 and summary["confirmed"] == 0


def test_kill_switch_mid_run_keeps_what_was_confirmed_as_a_partial_result(monkeypatch):
    http = site(**{"/.git/HEAD": "git_head_206.http.json"})
    rt = make_runtime(http)
    real = SensitiveFiles._fetch
    seen: list[str] = []

    def fetch_then_stop(ctx, origin, path):
        out = real(ctx, origin, path)
        seen.append(path)
        if path == "/.git/HEAD":
            rt.cancel("cancelled")
        return out

    monkeypatch.setattr(SensitiveFiles, "_fetch", staticmethod(fetch_then_stop))
    res = run_module(SensitiveFiles, f"domain:{HOST}", http, options=active(), runtime=rt)
    assert res.partial and res.stop_reason == "cancelled"
    assert [r["path"] for r in res.attributes["sensitive_files"]] == ["/.git/HEAD"]
    summary = res.attributes["sensitive_files_summary"]
    assert summary["paths_tested"] == 1 and summary["paths_planned"] == 23 and "kill switch" in summary["stopped"]
    assert seen[-1] == "/.git/HEAD"  # nothing requested after the kill switch


def test_never_on_pivots_or_values_found_in_text():
    """Cond 1: analyst-typed seeds only (run_on='seeds' plus applies()), even for an in-scope host."""
    assert SensitiveFiles.run_on == "seeds"
    for kw in ({"is_seed": False}, {"provenance": [("text_blob:abc", "mentions", "ioc_extract")]}):
        http = site()
        res = run(http, **kw)
        assert res.status is Status.SKIPPED, (kw, res.status, res.reason_code)
        assert target_calls(http) == []


def test_repeated_timeouts_stop_the_host_as_error():
    http = FakeHttp()
    add_dns(http, HOST, "A", ["93.184.216.34"])
    add_dns(http, HOST, "AAAA", [])
    answer(http, CALIBRATION, "calibration_404.http.json")
    detail = json.loads((FIX / "timeout.json").read_text(encoding="utf-8"))["detail"]
    http.add("GET", re.compile(r"^https://www\.example\.com/.*$"), error=NetworkError(f"ReadTimeout: {detail}", reason_code="timeout"))
    res = run(http)
    assert res.status is Status.ERROR and "consecutive transport failures" in res.error
    assert len(target_calls(http)) == 2 + 3


# ---------------------------------------------------------------------------------- A7 envelope
def test_without_a_scope_or_out_of_scope_nothing_is_sent():
    http = site()
    res = run(http, options=ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF))
    assert (res.status, res.reason_code) == (Status.SKIPPED, "scope") and target_calls(http) == []
    http2 = site()
    res2 = run(http2, options=active(scope(domains=["acme.example"], cidrs=["93.184.216.0/24"])))
    assert (res2.status, res2.reason_code) == (Status.SKIPPED, "scope") and target_calls(http2) == []


def test_policy_gate_needs_active_mode_and_an_authorization():
    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.DOMAIN, HOST)
    assert Engine(rt, ScanOptions()).decide_single(SensitiveFiles, ent).reason_code == "opsec"
    assert Engine(rt, ScanOptions(mode=Opsec.ACTIVE, scope=scope())).decide_single(SensitiveFiles, ent).reason_code == "authorization"


def test_answers_are_never_cached():
    http = site(**{"/.git/HEAD": "git_head_206.http.json"})
    rt = make_runtime(http, )
    rt_cached = make_runtime(http, cache=True)
    for runtime in (rt, rt_cached):
        run_module(SensitiveFiles, f"domain:{HOST}", http, options=active(), runtime=runtime)
    cached = [c for c in http.calls if c["url"] == BASE + "/.git/HEAD"]
    assert len(cached) == 2  # the second runtime (with a cache) requested it again: no-store


def test_kill_switch_stops_before_any_target_request():
    http = site()
    rt = make_runtime(http)
    rt.cancel("cancelled")
    run_module(SensitiveFiles, f"domain:{HOST}", http, options=active(), runtime=rt)
    assert target_calls(http) == []


def test_path_list_is_pinned_and_forbidden_paths_are_refused(monkeypatch):
    monkeypatch.setattr(sf, "pins_for", lambda name: {"bundled": "0" * 64})
    res = run(site())
    assert (res.status, res.reason_code) == (Status.UNAVAILABLE, "dataset")
    for bad in ("/.git/objects/ab/cdef", "/.git/index", "/.git/packed-refs", "/../etc/passwd", "relative", "/.svn/wc.db"):
        with pytest.raises(ValueError):
            sf.assert_path_allowed(bad)


def test_pinned_list_has_fewer_than_30_paths():
    ctx = make_ctx(SensitiveFiles, FakeHttp())
    rows = sf.load_paths(ctx)
    assert 0 < len(rows) < 30 and {r["sig"] for r in rows} <= set(sf._SEVERITY)


def test_offline_selftest_is_ok():
    hc = SensitiveFiles.health_check()
    assert hc.offline is True
    assert hc.selftest(make_ctx(SensitiveFiles, FakeHttp())).status == "ok"


def test_one_forced_browsing_engine_shared_with_p285():
    """Cond 5: the soft-404 comparison, login-redirect test and host-stop markers are path_discovery's engine."""
    from v3lum.modules.pentest_recon import forced_browsing

    assert sf.fb is forced_browsing
    doc = {"path": "/.env", "status": 200, "headers": {"content-type": "text/html"}, "body": b"<title>x</title>/.env", "history": [],
           "final_url": None, "error": ""}
    assert sf.body_profile(200, {"content-type": "text/html"}, b"<title>x</title>/.env", "/.env") == forced_browsing.response_signature(doc)


def test_waf_block_page_in_a_200_stops_the_host():
    """An error inside an HTTP 200 (a WAF block page) is could not verify, never 'not observed'."""
    waf = ("<html><head><title>Sucuri WebSite Firewall - Access Denied</title></head><body>Sucuri Website Firewall: "
           "access denied</body></html>")
    http2 = FakeHttp()
    add_dns(http2, HOST, "A", ["93.184.216.34"])
    add_dns(http2, HOST, "AAAA", [])
    answer(http2, CALIBRATION, "calibration_404.http.json")
    answer(http2, BASE + "/.git/HEAD", "git_head_206.http.json")
    http2.add("GET", BASE + "/.git/config", status=200, body=waf.encode(), headers={"content-type": "text/html"})
    answer(http2, re.compile(r"^https://www\.example\.com/.*$"), "not_found_404.http.json")
    res = run(http2)
    assert (res.status, res.reason_code) == (Status.BLOCKED, "challenge") and res.partial
    assert [r["path"] for r in res.attributes["sensitive_files"]] == ["/.git/HEAD"]
    assert [c["url"] for c in target_calls(http2)][-1] == BASE + "/.git/config"


def test_calibration_block_page_stops_before_any_listed_path():
    waf = "<html><body>Request blocked. Incapsula incident ID: 0-000000000000000</body></html>"
    http = FakeHttp()
    add_dns(http, HOST, "A", ["93.184.216.34"])
    add_dns(http, HOST, "AAAA", [])
    http.add("GET", CALIBRATION, status=200, body=waf.encode(), headers={"content-type": "text/html"})
    res = run(http)
    assert res.status is Status.BLOCKED and "calibration" in res.error
    assert all(CALIBRATION.match(c["url"]) for c in target_calls(http))


def test_soft_404_helper_and_login_redirect_helper():
    base = sf.body_profile(200, {}, b"<html>Pagina nao encontrada /abc123 volte</html>", "/abc123")
    assert sf.is_soft_404(sf.body_profile(200, {}, b"<html>Pagina nao encontrada /.env volte</html>", "/.env"), [base])
    assert not sf.is_soft_404(sf.body_profile(206, {}, b"ref: refs/heads/main\n", "/.git/HEAD"), [base])
    assert sf.is_login_redirect(302, {"Location": "https://x.example/login?next=/.env"})
    assert not sf.is_login_redirect(302, {"Location": "https://x.example/.env/"})


# ---------------------------------------------------------------------------------- loopback server (real transport)
class _Site(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    files = {"/.git/HEAD": (b"ref: refs/heads/main\n", "text/plain"), "/.env": (b"APP_ENV=production\nDB_PASSWORD=s3nh4-f4ls4-de-teste\n", "text/plain")}
    seen: list[tuple[str, str, str]] = []

    def log_message(self, *args):  # silence
        pass

    def do_GET(self):  # noqa: N802 - http.server API
        type(self).seen.append((self.command, self.path, self.headers.get("Range", "")))
        body, ctype = self.files.get(self.path, (b"<html>404</html>", "text/html"))
        status = 206 if self.path in self.files else 404
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        if status == 206:
            self.send_header("Content-Range", f"bytes 0-{len(body) - 1}/{len(body)}")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def loopback_site():
    _Site.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def test_loopback_server_through_the_real_transport(loopback_site, monkeypatch):
    """FC10: a local loopback server listed in the scope (127.0.0.1/32); the real HTTP client, the
    SSRF guard and the scope binding decide; a short path list keeps the 2 req/s pacing quick."""
    short = [{"path": "/.git/HEAD", "sig": "git_head"}, {"path": "/.env", "sig": "env"}, {"path": "/.DS_Store", "sig": "ds_store"}]
    monkeypatch.setattr(sf, "load_paths", lambda ctx: short)
    port = loopback_site
    sc = scope(cidrs=["127.0.0.1/32"], url_prefixes=[f"http://127.0.0.1:{port}/"])
    rt = Runtime(Config(), no_cache=True)
    res = Engine(rt, active(sc)).run_module(SensitiveFiles, Entity.make(T.URL, f"http://127.0.0.1:{port}/"))
    assert res.status is Status.OK, res.error
    assert {r["path"] for r in res.attributes["sensitive_files"]} == {"/.git/HEAD", "/.env"}
    assert all(method == "GET" and rng == "bytes=0-1023" for method, _p, rng in _Site.seen)
    assert len(_Site.seen) == 2 + 3
    assert_no_secret("s3nh4-f4ls4-de-teste", res.to_dict())
