"""Declarative specs (P331, WP12): schema, compiler, loader, fixture convention and safety rules.

* every bundled spec (``v3lum/data/specs/<name>.json``) runs over its fixtures
  ``tests/fixtures/specs/<name>/{ok.*, error_in_200.*, expected.json}`` (parametrized);
* the self-test set ``tests/fixtures/specs/_selftest/`` is installed as user specs in a temporary
  ``~/.v3lum/specs`` and exercises json, ndjson, csv, rss, xml, html_json, pagination, multi_match,
  found/absent/unknown, an A5 profile site and an unknown-tier source;
* refusals: templated host, http URL, POST, unknown placeholder, missing contract field, insecure user
  spec dir, missing fixtures, ReDoS regexes, XML entities, A5/A8 violations and more;
* acceptance: a compiled spec is indistinguishable from a hand-written module for policy, quotas and
  the registry contract test, and no spec can reach a host other than its literal declared hosts.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

from tests.fakes import FakeHttp, make_ctx, provider_fragment, run_module
from v3lum.core import lint, providers, specs
from v3lum.core import module as modreg
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.http import PolicyError
from v3lum.core.models import Opsec, Status

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SPEC_FIXTURES = FIXTURES / "specs"
SELFTEST = SPEC_FIXTURES / "_selftest"
SELFTEST_NAMES = sorted(p.stem for p in SELFTEST.glob("*.json") if not p.name.startswith("_"))
BUNDLED_NAMES = sorted(p.stem for p in specs.BUNDLED_DIR.glob("*.json") if not p.name.startswith(("_", ".")))
CONTENT_TYPES = {
    ".json": "application/json",
    ".ndjson": "application/x-ndjson",
    ".jsonl": "application/x-ndjson",
    ".csv": "text/csv; charset=utf-8",
    ".rss": "application/rss+xml",
    ".xml": "application/xml",
    ".html": "text/html; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
}
#: bodies served for pages without an ok_page<N> fixture (an empty page of the format)
EMPTY_PAGES = {
    "json": b"{}",
    "ndjson": b"",
    "csv": b"",
    "rss": b"<rss><channel></channel></rss>",
    "xml": b"<empty/>",
    "html_json": b"<html><body></body></html>",
}


# --------------------------------------------------------------------------------------
# helpers: fixtures -> FakeHttp routes
# --------------------------------------------------------------------------------------


def content_type(path: Path) -> str:
    return CONTENT_TYPES.get(path.suffix.lower(), "application/octet-stream")


def fixture_path(folder: Path, stem: str) -> Path | None:
    found = sorted(p for p in folder.glob(f"{stem}.*") if p.is_file() and p.name != "expected.json")
    return found[0] if found else None


def route_fixture(http: FakeHttp, cls: Any, entity: Entity, folder: Path, stem: str = "ok", *, status: int = 200, pages: int | None = None) -> list[str]:
    """Answer the spec's request(s) for ``entity`` with ``<stem>.*`` (page 1) and ``<stem>_page<N>.*``."""
    compiled = cls._compiled
    urls = []
    plan = compiled.pages(cls.max_requests)
    for index, page in enumerate(plan[: pages or len(plan)]):
        name = stem if index == 0 else f"{stem}_page{index + 1}"
        path = fixture_path(folder, name)
        if path is not None:
            body, ctype = path.read_bytes(), content_type(path)
        elif index == 0:
            raise AssertionError(f"fixture {folder / name}.* missing")
        else:
            body, ctype = EMPTY_PAGES[compiled.fmt], "text/plain"
        url = compiled.url_for(entity, page)
        http.add("GET", url, status=status, body=body, headers={"content-type": ctype})
        urls.append(url)
    return urls


def health_entity(cls: Any) -> Entity:
    hc = cls.health_check()
    assert hc is not None and hc.entity is not None, f"{cls.name}: no health-check value"
    return hc.entity


def check_ok(res: Any, expected: dict[str, Any]) -> None:
    assert res.status.value == expected["status"], (res.status, res.reason_code, res.error)
    for key, value in (expected.get("attributes") or {}).items():
        assert res.attributes.get(key) == value, f"attribute {key}: {res.attributes.get(key)!r} != {value!r}"
    keys = {p.entity.key for p in res.pivots}
    missing = set(expected.get("pivots") or []) - keys
    assert not missing, f"pivots {sorted(missing)} not in {sorted(keys)}"


def check_error(res: Any, expected: dict[str, Any]) -> None:
    assert res.status.value == expected["status"], (res.status, res.reason_code, res.error)
    assert res.reason_code == expected["reason_code"]
    assert res.status.could_not_verify  # rule 5: an error inside HTTP 200 is never an absence
    assert not res.attributes and not res.pivots and not res.findings


def run_fixture(cls: Any, folder: Path, stem: str) -> Any:
    http = FakeHttp()
    entity = health_entity(cls)
    route_fixture(http, cls, entity, folder, stem, pages=1 if stem != "ok" else None)
    res = run_module(cls, entity, http)
    http.assert_hosts_within(cls)
    return res


def spec_errors() -> dict[str, str]:
    return {k: v for k, v in modreg.load_errors().items() if k.startswith("spec:")}


def secure_tree(root: Path) -> None:
    """Owner-only modes on a copied user spec tree (AR12: never group/world-writable)."""
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def selftest_providers() -> list[dict[str, Any]]:
    return json.loads((SELFTEST / "_providers.json").read_text(encoding="utf-8"))["providers"]


def register_selftest_providers() -> None:
    for fragment in selftest_providers():
        providers.register(copy.deepcopy(fragment), origin="tests:selftest")


def install_user_specs(home: Path, names: list[str] | None = None) -> Path:
    user = home / "specs"
    user.mkdir(exist_ok=True)
    for name in names or SELFTEST_NAMES:
        shutil.copy(SELFTEST / f"{name}.json", user / f"{name}.json")
        shutil.copytree(SELFTEST / name, user / name)
    secure_tree(user)
    return user


def selftest_spec(name: str) -> dict[str, Any]:
    return json.loads((SELFTEST / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture()
def spec_state():
    """Keep specs' module-level state (last load) isolated per test."""
    saved = (dict(specs._LOADED), dict(specs._DISABLED))
    yield
    specs._LOADED.clear()
    specs._LOADED.update(saved[0])
    specs._DISABLED.clear()
    specs._DISABLED.update(saved[1])


@pytest.fixture()
def selftest_providers_registered(clean_registry, spec_state):
    register_selftest_providers()
    yield clean_registry


@pytest.fixture()
def selftest(selftest_providers_registered, isolated_home, tmp_path):
    """The self-test spec set loaded as user specs from a temporary ~/.v3lum/specs."""
    user = install_user_specs(isolated_home)
    empty = tmp_path / "no_bundled_specs"
    empty.mkdir()
    loaded = specs.load_specs(bundled_dir=empty, user_dir=user)
    assert spec_errors() == {}, spec_errors()
    return {cls.name: cls for cls in loaded}


@pytest.fixture()
def compile_one(selftest_providers_registered):
    """Compile (and register) one spec dict in the isolated registry."""

    def build(spec: dict[str, Any], origin: str = "tests:inline") -> Any:
        return specs.compile_spec(spec, origin=origin)

    return build


# --------------------------------------------------------------------------------------
# public API and bundled specs
# --------------------------------------------------------------------------------------


def test_public_api_names():
    from v3lum.core.specs import SPEC_SCHEMA, SpecError, compile_spec, load_specs, validate_spec

    assert SPEC_SCHEMA == "v3lum.spec/1"
    assert issubclass(SpecError, ValueError)
    assert callable(compile_spec) and callable(load_specs) and callable(validate_spec)
    assert set(specs.FORMATS) == {"json", "ndjson", "csv", "rss", "xml", "html_json"}
    assert set(specs.PLACEHOLDERS) == {"value", "value_q", "value_qp", "domain", "user", "b64"}


def test_bundled_specs_load_cleanly():
    modreg.load_modules()
    assert spec_errors() == {}
    for name in BUNDLED_NAMES:
        cls = modreg.REGISTRY.get(name)
        assert cls is not None and cls.spec_origin.startswith("bundled:"), f"bundled spec {name} is not registered"


def bundled_class(name: str) -> Any:
    modreg.load_modules()
    cls = modreg.REGISTRY.get(name)
    assert cls is not None and getattr(cls, "spec_origin", "").startswith("bundled:"), (
        f"bundled spec {name} is not registered: {spec_errors()}"
    )
    return cls


@pytest.mark.parametrize("name", BUNDLED_NAMES)
def test_bundled_spec_ok_fixture(name):
    cls = bundled_class(name)
    folder = SPEC_FIXTURES / name
    expected = json.loads((folder / "expected.json").read_text(encoding="utf-8"))
    check_ok(run_fixture(cls, folder, "ok"), expected["ok"])


@pytest.mark.parametrize("name", BUNDLED_NAMES)
def test_bundled_spec_error_in_200(name):
    cls = bundled_class(name)
    folder = SPEC_FIXTURES / name
    expected = json.loads((folder / "expected.json").read_text(encoding="utf-8"))
    check_error(run_fixture(cls, folder, "error_in_200"), expected["error_in_200"])


# --------------------------------------------------------------------------------------
# the self-test spec set (user specs)
# --------------------------------------------------------------------------------------


def test_selftest_set_loads_as_user_specs(selftest):
    assert sorted(selftest) == SELFTEST_NAMES
    for name, cls in selftest.items():
        assert modreg.REGISTRY[name] is cls
        assert cls.spec_origin.startswith("user:") and cls.spec_origin.endswith(f"{name}.json")
        info = cls.describe()
        assert info["spec_origin"] == cls.spec_origin and info["spec_disabled"] == ""
        assert info["disclosure"] == "third_party" and info["opsec"] == "passive"
        assert issubclass(cls, specs.SpecModule) and issubclass(cls, modreg.Module)
    assert specs.loaded().keys() == selftest.keys()
    formats = {cls._compiled.fmt for cls in selftest.values()}
    assert formats == set(specs.FORMATS)


@pytest.mark.parametrize("name", SELFTEST_NAMES)
def test_selftest_ok_fixture(selftest, name):
    expected = json.loads((SELFTEST / name / "expected.json").read_text(encoding="utf-8"))
    check_ok(run_fixture(selftest[name], SELFTEST / name, "ok"), expected["ok"])


@pytest.mark.parametrize("name", SELFTEST_NAMES)
def test_selftest_error_in_200(selftest, name):
    expected = json.loads((SELFTEST / name / "expected.json").read_text(encoding="utf-8"))
    check_error(run_fixture(selftest[name], SELFTEST / name, "error_in_200"), expected["error_in_200"])


def test_json_spec_maps_tag_finding_and_evidence(selftest):
    cls = selftest["selftest_json"]
    http = FakeHttp().add("GET", "https://api.selftest.test/v1/ip/8.8.8.8?format=json", json={
        "data": {"country": "BR", "tags": ["scanner-mass", "scanner-research"], "hostnames": ["a.example.com", "b.example.com"], "abuse_score": "87"},
    })
    res = run_module(cls, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK
    titles = {f.title: f for f in res.findings}
    tag = titles["Selftest: scanner activity"]
    assert tag.tags == ["scanner"] and tag.severity.label == "info" and tag.source == "selftest_api.lookup"
    assert tag.data["values"] == ["scanner"]  # a regex yields the matched text (first value only without match_all)
    high = titles["Selftest: high abuse score"]
    assert high.severity.label == "medium" and high.criterion and high.tags == ["suspicious"]
    assert high.data["count"] == 1 and high.data["matched"] == ["87"]
    assert [p.entity.key for p in res.pivots] == ["domain:a.example.com", "domain:b.example.com"]
    assert all(not p.expand and p.confidence == 0.5 for p in res.pivots)
    assert res.raw["data"]["country"] == "BR"  # parsed answer kept as evidence
    call = http.calls[0]
    assert call["headers"].get("Accept") == "application/json"


@pytest.mark.parametrize(
    ("status", "body", "expected", "code"),
    [
        (404, {"detail": "never seen"}, Status.EMPTY, ""),  # documented absence (absent_statuses)
        (403, "<html>forbidden</html>", Status.BLOCKED, "challenge"),  # keyless 403: could not verify
        (429, {"error": "slow down"}, Status.RATE_LIMITED, "rate_limited"),
        (500, "boom", Status.ERROR, "error"),
        (200, "not json at all", Status.ERROR, "error"),
        (200, "", Status.ERROR, "error"),
        (202, {"status": "queued"}, Status.ERROR, "error"),  # accepted, answer not ready: never 'nothing found'
        (206, {"data": {}}, Status.ERROR, "error"),  # partial content
        (200, '{"data": {"country": NaN}}', Status.EMPTY, ""),  # a non-finite number is no value
    ],
)
def test_http_outcomes_follow_rule_5(selftest, status, body, expected, code):
    cls = selftest["selftest_json"]
    http = FakeHttp()
    url = "https://api.selftest.test/v1/ip/8.8.8.8?format=json"
    if isinstance(body, dict):
        http.add("GET", url, status=status, json=body)
    else:
        http.add("GET", url, status=status, body=body.encode(), headers={"content-type": "text/html"})
    res = run_module(cls, "ipv4:8.8.8.8", http)
    assert (res.status, res.reason_code) == (expected, code), res.error
    assert "presence" not in res.attributes


@pytest.mark.parametrize(
    "body",
    [
        b"[" * 200000,  # nested deeper than any parser recursion limit
        b'{"data": ' * 50000 + b"1" + b"}" * 50000,
        b"\x00\xff" * 1000,
        b"<html><script id='__NEXT_DATA__'>" + b"[" * 100000 + b"</script></html>",
    ],
)
def test_hostile_bodies_are_could_not_verify_never_a_crash(selftest, body):
    for name in ("selftest_json", "selftest_html"):
        cls = selftest[name]
        entity = health_entity(cls)
        http = FakeHttp().add("GET", cls._compiled.url_for(entity, None), body=body, headers={"content-type": "application/json"})
        res = run_module(cls, entity, http)
        assert res.status is Status.ERROR and res.reason_code == "error", (name, res.status, res.error)
        assert not res.raw or "traceback" not in json.dumps(res.raw)


def test_csv_spec_on_an_html_error_page_is_could_not_verify(selftest):
    cls = selftest["selftest_csv"]
    entity = health_entity(cls)
    http = FakeHttp().add("GET", cls._compiled.url_for(entity, None), body=b"<html><head><title>Down for maintenance</title></head></html>",
                          headers={"content-type": "text/html"})
    res = run_module(cls, entity, http)
    assert (res.status, res.reason_code) == (Status.ERROR, "error") and "not CSV" in res.error
    assert not res.attributes and not res.findings


def test_challenge_is_blocked_with_the_manual_link(selftest):
    """A9: a challenge page (even with HTTP 200) is BLOCKED, never EMPTY, and carries the manual link."""
    cls = selftest["selftest_json"]
    http = FakeHttp()
    route_fixture(http, cls, Entity.make(EntityType.IPV4, "8.8.8.8"), SELFTEST / "selftest_rss", "error_in_200")
    res = run_module(cls, "ipv4:8.8.8.8", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert res.links == [("api.selftest.test (manual lookup)", "https://api.selftest.test/ui/ip/8.8.8.8")]
    assert not res.attributes and not res.findings


def test_ndjson_multi_match_onlyif(selftest):
    cls = selftest["selftest_ndjson"]
    res = run_fixture(cls, SELFTEST / "selftest_ndjson", "ok")
    assert all(p.entity.type is EntityType.IPV4 for p in res.pivots)
    assert "mail.example.com" not in json.dumps(res.attributes)  # the MX record failed onlyif


def test_csv_records_and_high_finding(selftest):
    res = run_fixture(selftest["selftest_csv"], SELFTEST / "selftest_csv", "ok")
    (finding,) = res.findings
    assert finding.severity.label == "high" and finding.tags == ["malware"]
    assert finding.criterion.startswith("the selftest feed lists")
    assert finding.data["matched"] == ["EICAR-Test-File"]


def test_rss_items_pivots_and_finding(selftest):
    res = run_fixture(selftest["selftest_rss"], SELFTEST / "selftest_rss", "ok")
    assert [p.entity.key for p in res.pivots] == [
        "url:https://api.selftest.test/advisories/cve-2021-44228",
        "url:https://api.selftest.test/advisories/cve-2021-44228-patch",
    ]
    assert all(p.confidence_label.value == "possible" and not p.expand for p in res.pivots)
    (finding,) = res.findings
    assert finding.title == "Selftest: exploit mentioned in the advisory feed" and finding.data["count"] == 1


def test_html_json_without_embedded_json_is_could_not_verify(selftest):
    cls = selftest["selftest_html"]
    http = FakeHttp().add("GET", "https://api.selftest.test/v1/site/example.com", text="<html><body>new layout</body></html>")
    res = run_module(cls, "domain:example.com", http)
    assert res.status is Status.ERROR and "no embedded JSON" in res.error


def test_html_json_placeholder_not_applicable(selftest):
    """{domain} of a URL whose host is an IP cannot be computed: SKIPPED not_applicable, no request."""
    spec = selftest_spec("selftest_html")
    spec.update(name="selftest_html_url", accepts=["domain", "url"], health_check={"etype": "domain", "value": "example.com", "expect": "ok"})
    cls = specs.compile_spec(spec, origin="tests:inline")
    http = FakeHttp()
    res = run_module(cls, "url:https://203.0.113.9/login", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def test_pagination_requests_pages_until_empty(selftest):
    cls = selftest["selftest_pages"]
    http = FakeHttp()
    urls = route_fixture(http, cls, Entity.make(EntityType.DOMAIN, "example.com"), SELFTEST / "selftest_pages")
    res = run_module(cls, "domain:example.com", http)
    assert res.status is Status.OK and len(urls) == 5
    assert [c["url"] for c in http.calls] == urls[:3]  # page 3 is empty: pages 4-5 never requested
    assert [re.search(r"page=(\d)", u).group(1) for u in urls[:3]] == ["1", "2", "3"]
    assert res.requests == 3 and not res.partial


def test_pagination_later_page_block_keeps_earlier_pages(selftest):
    cls = selftest["selftest_pages"]
    entity = Entity.make(EntityType.DOMAIN, "example.com")
    compiled = cls._compiled
    http = FakeHttp()
    http.add("GET", compiled.url_for(entity, 1), json={"subdomains": [{"name": "www.example.com"}]})
    http.add("GET", compiled.url_for(entity, 2), status=200, text="<html><title>Just a moment...</title>cf-chl-</html>")
    res = run_module(cls, entity, http)
    assert res.status is Status.OK and [p.entity.key for p in res.pivots] == ["domain:www.example.com"]
    assert "page 2" in res.error and "could not be verified" in res.error


def test_pagination_later_page_rate_limit_is_a_partial_run(selftest):
    cls = selftest["selftest_pages"]
    entity = Entity.make(EntityType.DOMAIN, "example.com")
    compiled = cls._compiled
    http = FakeHttp()
    http.add("GET", compiled.url_for(entity, 1), json={"subdomains": [{"name": "www.example.com"}]})
    http.add("GET", compiled.url_for(entity, 2), status=429, json={"error": "too many requests"})
    res = run_module(cls, entity, http)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    assert [p.entity.key for p in res.pivots] == ["domain:www.example.com"]
    assert res.raw == {"subdomains": [{"name": "www.example.com"}]}  # evidence of the pages read


def test_confinement_refusal_is_skipped_policy(selftest, monkeypatch):
    """Should a rendered URL ever leave the literal host, run() refuses it: SKIPPED 'policy', no request."""
    cls = selftest["selftest_json"]
    broken = specs._Compiled(**{**cls._compiled.__dict__, "host": "elsewhere.selftest.test"})
    monkeypatch.setattr(cls, "_compiled", broken)
    http = FakeHttp()
    res = run_module(cls, "ipv4:8.8.8.8", http)
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and http.calls == []


# --------------------------------------------------------------------------------------
# presence (found / absent / unknown) and the A5 profile-site rules
# --------------------------------------------------------------------------------------


def _profile_run(cls: Any, *, status: int = 200, body: Any = None) -> tuple[Any, FakeHttp]:
    http = FakeHttp()
    url = "https://profiles.selftest.test/api/users/octocat"
    if isinstance(body, (dict, list)):
        http.add("GET", url, status=status, json=body)
    else:
        http.add("GET", url, status=status, body=(body or "").encode(), headers={"content-type": "text/plain"})
    return run_module(cls, "username:octocat", http), http


@pytest.mark.parametrize(
    ("status", "fixture", "body", "state", "marker"),
    [
        (200, "ok.json", None, "found", "found: user.login matches"),
        (200, "absent.json", None, "absent", 'absent: error equals "user_not_found"'),
        (404, None, {"message": "Not Found"}, "absent", "HTTP 404 (documented absence)"),
        (200, "unknown.json", None, "unknown", "no marker matched"),
        (200, None, {"user": {"login": "octocat"}, "error": "user_not_found"}, "unknown", "contradictory markers"),
    ],
)
def test_presence_is_tri_state(selftest, status, fixture, body, state, marker):
    cls = selftest["selftest_profile"]
    if fixture is not None:
        body = json.loads((SELFTEST / "selftest_profile" / fixture).read_text(encoding="utf-8"))
    res, _http = _profile_run(cls, status=status, body=body)
    presence = res.attributes["presence"]
    assert presence["state"] == state and presence["marker"].startswith(marker)
    assert presence["url"] == "https://profiles.selftest.test/api/users/octocat"
    assert presence["source"] == "selftest_profiles.profiles"
    assert res.status is Status.OK


@pytest.mark.parametrize("status", [403, 429, 503])
def test_presence_never_absent_when_the_source_did_not_answer(selftest, status):
    cls = selftest["selftest_profile"]
    res, http = _profile_run(cls, status=status, body="<html>error</html>")
    assert res.status.could_not_verify and "presence" not in res.attributes
    assert len(http.calls) == 1  # A5: one request per handle, no retries


def test_profile_spec_follows_a5(selftest):
    cls = selftest["selftest_profile"]
    assert cls.run_on == "seeds" and cls.default_enabled is False and cls.min_interval >= 1.0 and cls.max_requests == 1
    res, http = _profile_run(cls, body=json.loads((SELFTEST / "selftest_profile" / "ok.json").read_text(encoding="utf-8")))
    (finding,) = res.findings
    assert finding.label.value == "possible" and set(finding.tags) == {"account", "weak_signal"}
    assert "does not prove identity" in finding.criterion
    assert all(not p.expand and p.confidence_label.value == "possible" for p in res.pivots)
    assert http.calls[0]["timeout"] <= specs.PROFILE_TIMEOUT
    # a redirect is evaluated, never followed (A5)
    http2 = FakeHttp().add("GET", "https://profiles.selftest.test/api/users/octocat", status=302,
                           headers={"location": "https://profiles.selftest.test/"})
    res2 = run_module(cls, "username:octocat", http2)
    assert len(http2.calls) == 1 and res2.status.could_not_verify and "presence" not in res2.attributes
    # a redirect to a login page is a login wall (BLOCKED), never an absence
    http3 = FakeHttp().add("GET", "https://profiles.selftest.test/api/users/octocat", status=302,
                           headers={"location": "https://profiles.selftest.test/login?next=/api/users/octocat"})
    res3 = run_module(cls, "username:octocat", http3)
    assert (res3.status, res3.reason_code) == (Status.BLOCKED, "login_wall") and "presence" not in res3.attributes
    assert len(http3.calls) == 1


def test_profile_tag_findings_are_possible_and_short_handles_high_collision(selftest_providers_registered):
    spec = selftest_spec("selftest_profile")
    spec["results"].append({"key": "user.verified", "pretty_name": "Selftest profiles: verified badge", "tag": "account"})
    cls = specs.compile_spec(spec, origin="tests:inline")
    body = {"user": {"login": "bob", "name": "Bob", "profile_url": "https://profiles.selftest.test/bob", "verified": True}}
    http = FakeHttp().add("GET", "https://profiles.selftest.test/api/users/bob", json=body)
    res = run_module(cls, "username:bob", http)
    titles = {f.title: f for f in res.findings}
    assert titles["Selftest profiles: verified badge"].label.value == "possible"  # A5: weak signal, POSSIBLE at most
    found = titles["Account found: Selftest profile site"]
    assert "high_collision" in found.tags and "shorter than 5 characters" in found.description
    assert all(f.label.value == "possible" for f in res.findings)
    long = FakeHttp().add("GET", "https://profiles.selftest.test/api/users/octocat", json={"user": {"login": "octocat"}})
    (finding,) = run_module(cls, "username:octocat", long).findings
    assert "high_collision" not in finding.tags


def test_source_outside_allowed_sources_is_never_queried(selftest):
    cls = selftest["selftest_json"]
    http = FakeHttp()
    res = run_module(cls, "ipv4:8.8.8.8", http, allowed_sources=())
    assert res.status is Status.SKIPPED and res.reason_code == "licence" and http.calls == []


def test_unknown_tier_spec_receives_ioc_types_only(selftest):
    cls = selftest["selftest_unknown"]
    assert cls.trust_tier == "unknown" and cls.default_enabled is False and cls.terms == "unknown"
    assert cls.accepts <= {EntityType.IPV4}
    spec = selftest_spec("selftest_unknown")
    spec.update(name="selftest_unknown_email", accepts=["email", "ipv4"])
    problems = specs.validate_spec(spec)
    assert any("unknown-tier provider receives IOC types only" in p for p in problems)


# --------------------------------------------------------------------------------------
# refusals
# --------------------------------------------------------------------------------------


def _mutate(spec: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(spec)
    target = out
    parts = path.split(".")
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    last = parts[-1]
    if value is _DELETE:
        del target[last]
    elif isinstance(target, list):
        target[int(last)] = value
    else:
        target[last] = value
    return out


_DELETE = object()

REFUSALS = [
    ("templated host", "request.url", "https://{domain}/v1/ip/{value}", "templated host"),
    ("templated host via value", "request.url", "https://{value}.api.selftest.test/x", "templated host"),
    ("userinfo", "request.url", "https://api.selftest.test@evil.test/v1/{value}", "userinfo"),
    ("http URL", "request.url", "http://api.selftest.test/v1/ip/{value}", "https only"),
    ("explicit port", "request.url", "https://api.selftest.test:8443/v1/ip/{value}", "explicit ports"),
    ("undeclared host", "request.url", "https://evil.test/v1/ip/{value}", "not one of the spec's literal hosts"),
    ("fragment", "request.url", "https://api.selftest.test/v1/ip/{value}#x", "fragments are not allowed"),
    ("path glued to host", "request.url", "https://api.selftest.test{value}", "templated host"),
    ("non-ascii url", "request.url", "https://api.selftest.test/v1/ç/{value}", "non-ASCII"),
    ("POST", "request.method", "POST", "only 'GET'"),
    ("unknown placeholder", "request.url", "https://api.selftest.test/v1/ip/{target}", "unknown placeholder"),
    ("format-string attack", "request.url", "https://api.selftest.test/v1/ip/{0.__class__}", "malformed placeholder"),
    ("placeholder type", "request.url", "https://api.selftest.test/v1/ip/{domain}", "placeholder {domain} applies only"),
    ("request body", "request.data", {"q": "{value}"}, "request bodies cannot be expressed"),
    ("cookies", "request.cookies", {"session": "abc"}, "cookies cannot be expressed"),
    ("login", "request.auth", "selftest_api", "logins cannot be expressed"),
    ("cookie header", "request.headers", {"Cookie": "sid=1"}, "cannot be set by a spec"),
    ("user agent header", "request.headers", {"User-Agent": "curl/8"}, "cannot be set by a spec"),
    ("literal credential", "request.headers", {"Authorization": "Bearer abc123"}, "credentials are never literal"),
    ("value in header", "request.headers", {"X-Query": "{value}"}, "literal value or '{key:<name>}' only"),
    ("unknown key reference", "request.headers", {"X-Api-Key": "{key:nope}"}, "not in requires_keys/optional_keys"),
    ("credential param", "request.params", {"apikey": "abc"}, "credential-like parameters are refused"),
    ("credential-like param", "request.params", {"api_token": "abc123def456"}, "credential-like parameters are refused"),
    ("access key param", "request.params", {"access_key": "abc123def456"}, "credential-like parameters are refused"),
    ("session param", "request.params", {"session_id": "abc123def456"}, "credential-like parameters are refused"),
    ("literal vendor key header", "request.headers", {"X-RapidAPI-Key": "abc123def456"}, "credentials are never literal"),
    ("literal private token header", "request.headers", {"Private-Token": "abc123def456"}, "credentials are never literal"),
    ("vendor key header by reference", "request.headers", {"X-RapidAPI-Key": "{key:selftest_api}"}, "not in requires_keys/optional_keys"),
    ("plain literal header", "request.headers", {"Accept-Language": "pt-BR"}, None),
    ("plain search param", "request.params", {"keyword": "{value}", "author": "x"}, None),
    ("key in params", "request.params", {"k": "{key:selftest_api}"}, "malformed placeholder"),
    ("ignored refusal", "request.ignored_status_codes", [403], "cannot be ignored"),
    ("absent refusal", "absent_statuses", [429], "never an absence"),
    ("password reset probe", "request.url", "https://api.selftest.test/password/reset?email={value_q}", "LINT-03"),
    ("submission endpoint", "request.url", "https://api.selftest.test/v1/submit?url={value_q}", "LINT-05"),
    ("recent searches board", "request.url", "https://api.selftest.test/recent-searches/{value}", "LINT-05"),
    ("missing contract field", "terms", _DELETE, "missing contract field(s) ['terms']"),
    ("missing request field", "request.method", _DELETE, "request.method: required"),
    ("unknown field", "x_ok_but", "fine", None),
    ("unknown top field", "unexpected", 1, "unknown field(s) ['unexpected']"),
    ("wrong schema", "schema", "v3lum.spec/2", "schema: must be"),
    ("target disclosure", "disclosure", "target", "'third_party' lookups"),
    ("active opsec", "opsec", "active", "are 'passive'"),
    ("cpf", "accepts", ["cpf"], "never sent to a provider"),
    ("too many pages", "max_requests", 6, "max_requests: must be an integer 1..5"),
    ("non-benign health value", "health_check.value", "1.1.1.1", "central benign value '8.8.8.8'"),
    ("health type not accepted", "health_check.etype", "domain", "not accepted by the spec"),
    ("unknown attribute", "results.0.attribute", "not_a_vocab_name", "not a vocabulary attribute"),
    ("presence attribute", "results.0.attribute", "presence", "found/absent rules only"),
    ("pivot type not produced", "results.5.pivot.type", "ipv4", "not listed in produces"),
    ("pivot relation", "results.5.pivot.relation", "made_up", "not a vocabulary relation"),
    ("finding without criterion", "findings.0.criterion", _DELETE, "criterion: required for severity >= low"),
    ("finding tag", "findings.0.tags", ["nope_tag"], "not vocabulary tags"),
    ("redos nested", "results.4.regex", "(a+)+$", "nested repeats"),
    ("redos alternation", "results.4.regex", "(a|aa)*b", "alternation inside a repeated group"),
    ("redos backreference", "results.4.regex", "(x)\\1", "backreferences"),
    ("regex too long", "results.4.regex", "a" * 201, "longer than 200"),
    ("two unbounded", "results.4.regex", "\\d+\\.\\d+", "at most 1 unbounded"),
    ("marker regex unbounded", "error_markers.0", {"id": "x", "regex": "quota.*exceeded", "maps_to": "quota", "reason": "r"}, "at most 0 unbounded"),
    ("terms mismatch", "terms", "noncommercial", "most restrictive source class is 'open'"),
    ("unregistered provider", "provider", "nobody_here", "is not registered"),
    ("unregistered source", "sources", ["selftest_api.nope"], "is not a registered"),
    ("wildcard host", "hosts", ["*.selftest.test"], "wildcards are refused"),
    ("breach category", "category", "breach_leak", "breach/leak sources"),
    ("offline tag", "tags", ["free", "offline"], "'offline' is reserved"),
    ("another provider's key", "optional_keys", ["shodan"], "belongs to provider 'shodan'"),
    ("legacy key without provider", "optional_keys", ["virustotal"], "legacy key without a provider"),
    ("own provider's key", "optional_keys", ["selftest_api"], None),
    ("default person-name source", "accepts", ["ipv4", "person_name"], "person-name sources are never default"),
]


@pytest.mark.parametrize(("label", "path", "value", "needle"), REFUSALS, ids=[r[0] for r in REFUSALS])
def test_validate_spec_refusals(selftest_providers_registered, label, path, value, needle):
    spec = _mutate(selftest_spec("selftest_json"), path, value)
    problems = specs.validate_spec(spec)
    if needle is None:
        assert problems == [], problems
        return
    assert any(needle in p for p in problems), f"{label}: {needle!r} not in {problems}"
    with pytest.raises(specs.SpecError) as exc:
        specs.compile_spec(spec, origin="tests:refusal")
    assert exc.value.name == spec.get("name") and exc.value.problems == problems


def _paths(obj: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    out: list[tuple[Any, ...]] = []
    items = obj.items() if isinstance(obj, dict) else enumerate(obj) if isinstance(obj, list) else ()
    for key, value in items:
        out.append((*prefix, key))
        out.extend(_paths(value, (*prefix, key)))
    return out


@pytest.mark.parametrize("name", ["selftest_json", "selftest_profile", "selftest_pages"])
def test_malformed_specs_never_crash_the_validator(selftest_providers_registered, name):
    """Any field of a spec replaced by another JSON type (or deleted) gives problems, never an exception."""
    base = selftest_spec(name)
    for path in _paths(base):
        for value in (None, 1, "x", [], {}, True, [None], {"path": 1}, "{value}", 10 ** 400, -1e308, _DELETE):
            spec = copy.deepcopy(base)
            target = spec
            for part in path[:-1]:
                target = target[part]
            if value is _DELETE:
                target.pop(path[-1])
            else:
                target[path[-1]] = value
            problems = specs.validate_spec(spec)
            assert isinstance(problems, list)
            if not problems:
                specs.compile_spec(spec, origin="tests:fuzz", register_class=False)


PROFILE_REFUSALS = [
    ("run_on", "any", "analyst-typed seeds only"),
    ("default_enabled", True, "never default"),
    ("found", None, "explicit presence marker"),
    ("min_interval", 0.0, "waits >= 1.0 s"),
    ("max_requests", 2, "exactly one request per handle"),
    ("results.1.pivot.expand", True, "never expand"),
    ("results.1.pivot.confidence", "probable", "POSSIBLE at most"),
]


@pytest.mark.parametrize(("path", "value", "needle"), PROFILE_REFUSALS, ids=[r[0] for r in PROFILE_REFUSALS])
def test_profile_spec_a5_refusals(selftest_providers_registered, path, value, needle):
    spec = _mutate(selftest_spec("selftest_profile"), path, value)
    assert any(needle in p for p in specs.validate_spec(spec)), specs.validate_spec(spec)


def test_email_local_part_lookups_follow_a5(selftest_providers_registered):
    """{user} of an e-mail sends the local part as a handle: a username lookup derived from an
    address, which A5 allows only on analyst-typed seeds (never on pivots, never default)."""
    spec = selftest_spec("selftest_json")
    spec.update(accepts=["email"], produces=["domain"], health_check={"etype": "email", "value": "someone@example.com", "expect": "ok"})
    spec["request"]["url"] = "https://api.selftest.test/v1/users/{user}"
    problems = specs.validate_spec(spec)
    for needle in ("analyst-typed seeds only", "never default", "explicit presence marker", "waits >= 1.0 s"):
        assert any(needle in p for p in problems), (needle, problems)
    spec["request"]["url"] = "https://api.selftest.test/v1/domains/{domain}"  # the domain part is no handle
    assert not any("profile-site spec" in p for p in specs.validate_spec(spec))


def test_profile_spec_needs_an_absence_marker(selftest_providers_registered):
    spec = selftest_spec("selftest_profile")
    spec.update(absent=None, absent_statuses=[])
    assert any("explicit absence marker" in p for p in specs.validate_spec(spec))
    spec["absent_statuses"] = [404]  # a documented absence status is an absence marker
    assert specs.validate_spec(spec) == []


def test_provider_flags_refused(clean_registry, spec_state):
    spec = selftest_spec("selftest_json")
    for flag, needle in (("publishes_queries", "rule 7"), ("sensitive", "flagged sensitive")):
        fragment = provider_fragment("selftest_api", hosts=["api.selftest.test"], tier="community", sources=("lookup",), **{flag: True})
        providers.register(fragment, origin="tests")
        assert any(needle in p for p in specs.validate_spec(spec))
        providers.unregister("selftest_api")
    fragment = provider_fragment("selftest_api", hosts=["api.selftest.test"], tier="community", sources=("lookup",), hosts_from_settings=["misp_url"])
    providers.register(fragment, origin="tests")
    assert any("hosts_from_settings" in p for p in specs.validate_spec(spec))


def test_unknown_tier_spec_must_not_be_default(selftest_providers_registered):
    spec = selftest_spec("selftest_unknown")
    spec["default_enabled"] = True
    problems = specs.validate_spec(spec)
    assert any("unknown-tier provider (A3/A8)" in p for p in problems)
    assert any("unknown terms (A1/A3)" in p for p in problems)


def test_registration_errors_surface_as_spec_errors(selftest_providers_registered):
    modreg.load_modules()
    spec = selftest_spec("selftest_json")
    spec["name"] = "dns_records"  # a hand-written reference module owns the name
    with pytest.raises(specs.SpecError) as exc:
        specs.compile_spec(spec, origin="tests:inline")
    assert "duplicate module name" in str(exc.value)
    assert modreg.REGISTRY["dns_records"].__module__.startswith("v3lum.modules.")


def test_compile_spec_needs_an_origin(selftest_providers_registered):
    with pytest.raises(specs.SpecError, match="origin"):
        specs.compile_spec(selftest_spec("selftest_json"), origin="")


def test_compile_spec_refuses_a_second_spec_with_a_registered_name(selftest_providers_registered):
    """Every compiled class is 'Spec_<name>': @register's same-class rule (re-imported module files)
    would let a second spec silently replace the first one."""
    first = specs.compile_spec(selftest_spec("selftest_json"), origin="tests:first")
    other = selftest_spec("selftest_json")
    other["title"] = "Another lookup"
    with pytest.raises(specs.SpecError, match="duplicate module name"):
        specs.compile_spec(other, origin="tests:second")
    assert modreg.REGISTRY["selftest_json"] is first
    assert specs.compile_spec(other, origin="tests:unregistered", register_class=False) is not first


def test_spec_origin_is_set_by_the_compiler_only(clean_registry):
    body = {
        "name": "t_fake_spec", "title": "t", "description": "t", "category": "utility", "accepts": {EntityType.DOMAIN},
        "terms": "open", "opsec": Opsec.PASSIVE, "disclosure": "none", "hosts": (), "spec_origin": "bundled:fake.json",
        "run": lambda self, entity, ctx: self.result(entity),
    }
    with pytest.raises(modreg.RegistrationError, match="spec_origin"):
        modreg.register(type("FakeSpec", (modreg.Module,), body))
    # the compiler's marker alone does not make a hand-written class a compiled spec (whose tests are
    # its spec fixtures): it must derive from SpecModule and carry no code of its own
    marked = {**body, modreg.SPEC_MARK: True}
    with pytest.raises(modreg.RegistrationError, match="spec_origin"):
        modreg.register(type("MarkedFake", (modreg.Module,), marked))
    with pytest.raises(modreg.RegistrationError, match="spec_origin"):
        modreg.register(type("MarkedSpecFake", (specs.SpecModule,), marked))


def test_compiled_classes_carry_no_code_of_their_own(selftest):
    for cls in selftest.values():
        assert modreg._compiled_spec_class(cls), cls.name
        assert not any(callable(v) for k, v in vars(cls).items() if not k.startswith("__"))


# --------------------------------------------------------------------------------------
# regexes, extractor, conversions and parsers
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "unbounded", "needle"),
    [
        ("^scanner", 1, None),
        ("CVE-\\d{4}-\\d{4,7}", 1, None),
        ("(\\d{1,3}(?:\\.\\d{1,3}){3})", 1, None),
        ("listed in the (\\w+)", 1, None),
        ("(?i)exploit", 0, None),
        ("(a+)+$", 1, "nested repeats"),
        ("(\\w+\\s?)*$", 1, "nested repeats"),
        ("(a|aa)*b", 1, "alternation inside a repeated group"),
        ("(?:ab|cd){2,5}", 1, "alternation inside a repeated group"),
        ("(a{1,9}){1,9}", 1, "nested repeats"),
        ("(x)\\1", 1, "backreferences"),
        ("(?P<a>x)(?(a)y|z)", 1, "backreferences"),
        (".*a.*b", 1, "at most 1 unbounded"),
        ("a{100}", 0, "at most 0 unbounded"),  # a maximum above 64 counts as unbounded
        ("a{64}", 0, None),
        ("quota.*", 0, "at most 0 unbounded"),
        ("(unclosed", 1, "does not compile"),
        ("", 1, "non-empty"),
        # exponential and high-degree shapes the nesting rule alone lets through (ReDoS cost model)
        ("(?:\\w?){24}\\d", 1, "backtracking cost"),
        ("(?:a?){18}a{18}", 1, "backtracking cost"),
        ("\\w{0,64}\\w{0,64}\\w{0,64}x", 1, "backtracking cost"),
        ("\\w+\\w{0,127}x", 1, "backtracking cost"),
        ("\\w+@\\w{2,16}", 1, None),
        ("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$", 1, None),
        ("(?:ab?){3}", 1, None),
        ("quota.{0,40}exceeded", 0, None),
        ("[a-z]{1,64}[0-9]{1,64}", 0, "backtracking cost"),  # error markers scan 64 KB: a 128 times smaller budget
    ],
)
def test_regex_problems(pattern, unbounded, needle):
    problems = specs.regex_problems(pattern, max_unbounded=unbounded)
    if needle is None:
        assert problems == []
    else:
        assert any(needle in p for p in problems), problems


def test_catastrophic_regexes_are_refused_without_running_them():
    """The ReDoS smoke test only runs on patterns within the cost budget: a catastrophic pattern is
    refused by analysis, it never hangs the loader inside the smoke test itself."""
    import time

    start = time.perf_counter()
    for pattern in ("(?:\\w?){24}\\d", "(?:[a-z]{1,2}){30}!", "(?:\\d{0,2}){20}x"):
        assert any("backtracking cost" in p for p in specs.regex_problems(pattern)), pattern
    assert time.perf_counter() - start < 2.0


def test_result_values_are_bounded():
    rule = specs._ResultRule(key="v", pretty_name="", kind="attribute", target="title")
    (text,) = rule.values({"v": "x" * 10_000})
    assert len(text) == specs.MAX_VALUE_CHARS + 1 and text.endswith("\u2026")
    assert rule.values({"v": {"blob": "y" * (specs.MAX_VALUE_JSON + 10)}}) == []  # an oversized object is dropped
    assert rule.values({"v": {"small": 1}}) == [{"small": 1}]


def test_mapping_stops_at_the_run_deadline_and_on_cancel():
    """Mapping a huge answer is CPU work the HTTP deadline never sees: it stops when the run is
    cancelled or past its deadline - partial results when something was mapped, else could not verify."""
    from v3lum.core.http import Cancelled, DeadlineExceeded
    from v3lum.core.models import ModuleResult

    class Ctx:
        def __init__(self, cancelled=False, left=None):
            self._cancelled, self._left = cancelled, left

        def cancelled(self):
            return self._cancelled

        def remaining(self):
            return self._left

    entity = Entity.make(EntityType.IPV4, "8.8.8.8")
    empty, mapped = ModuleResult(module="m", entity=entity), ModuleResult(module="m", entity=entity)
    mapped.attributes["country"] = "BR"
    specs.SpecModule._check_time(Ctx(left=5.0), empty)  # time left: nothing happens
    specs.SpecModule._check_time(Ctx(), empty)  # no deadline at all
    with pytest.raises(Cancelled):
        specs.SpecModule._check_time(Ctx(cancelled=True), mapped)
    with pytest.raises(DeadlineExceeded):
        specs.SpecModule._check_time(Ctx(left=0.0), empty)
    with pytest.raises(Cancelled) as exc:
        specs.SpecModule._check_time(Ctx(left=0.0), mapped)
    assert exc.value.stop_reason == "deadline"


def test_regex_inputs_are_bounded():
    rule = specs._ResultRule(key="v", pretty_name="", kind="attribute", target="title", regex=re.compile("(y{1,3})"))
    assert rule.values({"v": "a" * 600 + "y"}) == []  # only the first 512 characters are ever searched
    assert rule.values({"v": "a" * 100 + "y"}) == ["y"]


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("@", [{"a": {"b": [1, 2]}, "l": [{"n": "x"}, {"n": "y"}], "one": {"n": "z"}, "m": {"k1": 1, "k2": 2}}]),
        ("a.b", [[1, 2]]),
        ("a.b[]", [1, 2]),
        ("a.b.1", [2]),
        ("l[].n", ["x", "y"]),
        ("one[].n", ["z"]),  # a single object counts as a one-element list (XML)
        ("m.*", [1, 2]),
        ("missing.x", []),
        ("a.b.9", []),
    ],
)
def test_extract(path, expected):
    doc = {"a": {"b": [1, 2]}, "l": [{"n": "x"}, {"n": "y"}], "one": {"n": "z"}, "m": {"k1": 1, "k2": 2}}
    assert specs.extract(doc, path) == expected


def test_extract_root_list():
    assert specs.extract([{"x": 1}, {"x": 2}], "[].x") == [1, 2]


def test_extract_non_ascii_digit_segments_are_names():
    """'²' or '٣' pass str.isdigit() but int() refuses them: a valid path segment never crashes a run."""
    assert specs._path_problem("a.²") == ""
    assert specs.extract({"a": [1, 2]}, "a.²") == []
    assert specs.extract({"a": {"٣": "x"}}, "a.٣") == ["x"]


def test_hostile_numbers_never_crash_conversions():
    huge = 10 ** 400
    assert specs._number(huge) is None and specs._number("9" * 500) is None
    assert specs._convert("int", huge) is specs._SKIP and specs._convert("as_time", huge) is specs._SKIP
    rule = specs._Match("v", "gte", expected=5)
    assert rule.hits({"v": huge}) == []
    assert specs._parse_json('{"a": NaN, "b": Infinity, "c": -Infinity, "d": 1e400, "e": 1.5}') == {
        "a": None, "b": None, "c": None, "d": None, "e": 1.5,
    }


def test_ndjson_and_csv_split_lines_on_lf_only():
    """U+2028/U+2029, VT and FF are legal inside JSON strings and CSV fields: str.splitlines() would
    cut a valid answer into invalid lines."""
    rows = specs._parse_ndjson('{"a": "x\u2028y\u0085z"}\r\n{"a": 2}\n\n')
    assert rows == [{"a": "x\u2028y\u0085z"}, {"a": 2}]
    assert specs._parse_csv("name,note\r\nfoo,a\u2029b\u000bc\r\n") == [{"name": "foo", "note": "a\u2029b\u000bc"}]


@pytest.mark.parametrize(
    ("fmt", "value", "expected"),
    [
        ("as_time", 1764000000, "2025-11-24T16:00:00Z"),
        ("as_time", "1764000000000", "2025-11-24T16:00:00Z"),
        ("as_time", "2024-01-02T03:04:05+02:00", "2024-01-02T01:04:05Z"),
        ("as_time", "Fri, 10 Dec 2021 12:00:00 GMT", "2021-12-10T12:00:00Z"),
        ("as_time", "not a date", specs._SKIP),
        ("bool", "yes", True),
        ("bool", 0, False),
        ("bool", "maybe", specs._SKIP),
        ("int", "42", 42),
        ("int", "x", specs._SKIP),
        ("float", "1.5", 1.5),
        ("lower", "TXT", "txt"),
        ("str", 3.0, "3"),
        ("str", {"a": 1}, specs._SKIP),
    ],
)
def test_conversions(fmt, value, expected):
    assert specs._convert(fmt, value) == expected


def test_csv_parser_header_and_comments():
    rows = specs._parse_csv("# comment\n\nsha256 , family\nabc, Mirai \n# trailing\n")
    assert rows == [{"sha256": "abc", "family": "Mirai"}]


def test_rss_and_atom_parsers():
    atom = (b'<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>t</title>'
            b'<entry><title>a</title><link href="https://x.test/1"/></entry></feed>')
    doc = specs._parse_rss(atom)
    assert doc["items"] == [{"title": "a", "link": {"@href": "https://x.test/1"}}]
    with pytest.raises(specs._ParseError):
        specs._parse_rss(b"<html><body>no feed</body></html>")


@pytest.mark.parametrize(
    "body",
    [
        b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><r>&lol2;</r>',
        b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
        b'<?xml version="1.0"?><!DOCTYPE r SYSTEM "https://evil.test/x.dtd"><r/>',
        '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE r [<!ENTITY a "b">]><r>&a;</r>'.encode("utf-16"),
        b'<?xml version="1.0"?><r>&undefined;</r>',
    ],
)
def test_xml_entities_are_never_expanded(body):
    with pytest.raises(specs._ParseError):
        specs._parse_xml(body)


def test_xml_conversion():
    doc = specs._parse_xml(b'<a x="1"><b>t</b><b>u</b><c y="2">v</c>txt</a>')
    assert doc == {"a": {"@x": "1", "b": ["t", "u"], "c": {"@y": "2", "#text": "v"}, "#text": "txt"}}


def test_rss_1_0_rdf_feed():
    body = (b'<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
            b'xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">'
            b'<channel rdf:about="https://x.test/"><title>t</title></channel>'
            b'<item rdf:about="https://x.test/1"><title>a</title><link>https://x.test/1</link><dc:date>2024-01-02</dc:date></item>'
            b'<item rdf:about="https://x.test/2"><title>b</title><link>https://x.test/2</link></item></rdf:RDF>')
    doc = specs._parse_rss(body)
    assert doc["channel"]["title"] == "t"
    assert [i["link"] for i in doc["items"]] == ["https://x.test/1", "https://x.test/2"]
    assert doc["items"][0]["dc:date"] == "2024-01-02"  # prefixed element names are kept and addressable


def test_feed_text_mentioning_doctype_is_data_not_a_declaration():
    """An advisory feed describing an XXE payload in CDATA is a valid feed (no false 'could not
    verify'); a real DOCTYPE or entity declaration is still refused by the parser handlers."""
    body = (b'<?xml version="1.0"?><rss version="2.0"><channel><title>t</title><item><title>XXE advisory</title>'
            b'<description><![CDATA[<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>]]></description>'
            b'</item></channel></rss>')
    doc = specs._parse_rss(body)
    assert doc["items"][0]["title"] == "XXE advisory" and "<!ENTITY xxe" in doc["items"][0]["description"]


@pytest.mark.parametrize(
    ("fmt", "body"),
    [
        ("csv", b"<!DOCTYPE html>\n<html><head><title>502 Bad Gateway</title></head><body>oops</body></html>\n"),
        ("csv", b'{"error": "maintenance"}'),
        ("csv", b"  <html><body>Service temporarily down</body></html>"),
        ("xml", b"<?xml version='1.0'?><html xmlns='http://www.w3.org/1999/xhtml'><body>maintenance</body></html>"),
    ],
)
def test_error_pages_are_never_parsed_as_data(fmt, body):
    """Rule 5: an HTML/JSON error page served with HTTP 200 to a CSV/XML spec is 'could not verify',
    never rows of noise or 'no rows'."""
    with pytest.raises(specs._ParseError):
        specs._parse(fmt, body, body.decode("utf-8"))


# --------------------------------------------------------------------------------------
# keys in headers
# --------------------------------------------------------------------------------------


def test_header_keys(selftest_providers_registered):
    spec = selftest_spec("selftest_json")
    spec.update(name="selftest_keyed", requires_keys=["selftest_api"], access_model="free_auth_limited")
    spec["request"]["headers"] = {"Authorization": "Bearer {key:selftest_api}", "Accept": "application/json"}
    cls = specs.compile_spec(spec, origin="tests:inline")
    res = run_module(cls, "ipv4:8.8.8.8", FakeHttp())
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    http = FakeHttp().add("GET", "https://api.selftest.test/v1/ip/8.8.8.8?format=json", json={"data": {"country": "US"}},
                          match_headers={"Authorization": "Bearer sk-selftest-0123456789"})
    res = run_module(cls, "ipv4:8.8.8.8", http, keys={"selftest_api": "sk-selftest-0123456789"})
    assert res.status is Status.OK and res.attributes["country"] == "US"
    assert "sk-selftest" not in http.calls[0]["url"]


def test_optional_key_header_is_omitted_without_the_key(selftest_providers_registered):
    spec = selftest_spec("selftest_json")
    spec.update(name="selftest_optkey", optional_keys=["selftest_api"])
    spec["request"]["headers"] = {"X-Api-Key": "{key:selftest_api}"}
    cls = specs.compile_spec(spec, origin="tests:inline")
    http = FakeHttp().add("GET", "https://api.selftest.test/v1/ip/8.8.8.8?format=json", json={"data": {"country": "US"}})
    res = run_module(cls, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK and "X-Api-Key" not in http.calls[0]["headers"]


# --------------------------------------------------------------------------------------
# loader: AR12 ownership, fixtures, lint, reload, load_modules
# --------------------------------------------------------------------------------------


def _load_user(home: Path, tmp_path: Path, names: list[str] | None = None) -> tuple[list[Any], Path]:
    user = install_user_specs(home, names)
    empty = tmp_path / "no_bundled"
    empty.mkdir(exist_ok=True)
    return specs.load_specs(bundled_dir=empty, user_dir=user), user


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX permissions")
def test_insecure_user_spec_dir_is_refused(selftest_providers_registered, isolated_home, tmp_path):
    user = install_user_specs(isolated_home, ["selftest_json"])
    os.chmod(user, 0o777)
    loaded = specs.load_specs(bundled_dir=tmp_path, user_dir=user)
    assert loaded == [] and "selftest_json" not in modreg.REGISTRY
    errors = spec_errors()
    assert list(errors) == [f"spec:{user}"] and "world-writable" in errors[f"spec:{user}"]


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX permissions")
def test_group_writable_spec_or_fixture_is_refused(selftest_providers_registered, isolated_home, tmp_path):
    user = install_user_specs(isolated_home, ["selftest_json", "selftest_csv"])
    os.chmod(user / "selftest_json.json", 0o620)
    os.chmod(user / "selftest_csv" / "ok.csv", 0o666)
    loaded = specs.load_specs(bundled_dir=tmp_path, user_dir=user)
    assert loaded == []
    errors = spec_errors()
    assert "group-writable" in errors["spec:selftest_json"]
    assert "ok.csv" in errors["spec:selftest_csv"] and "world-writable" in errors["spec:selftest_csv"]


def test_missing_fixtures_refuse_a_spec(selftest_providers_registered, isolated_home, tmp_path):
    user = install_user_specs(isolated_home, ["selftest_json", "selftest_csv"])
    shutil.rmtree(user / "selftest_json")
    (user / "selftest_csv" / "error_in_200.csv").unlink()
    loaded = specs.load_specs(bundled_dir=tmp_path, user_dir=user)
    assert loaded == []
    errors = spec_errors()
    assert "fixtures missing" in errors["spec:selftest_json"]
    assert "error_in_200.*" in errors["spec:selftest_csv"]


@pytest.mark.parametrize(
    ("expected", "needle"),
    [
        ({"ok": {"status": "ok"}, "error_in_200": {"status": "empty", "reason_code": ""}}, "never an absence"),
        ({"ok": {"status": "ok"}, "error_in_200": {"status": "blocked", "reason_code": "quota"}}, "not a canonical code"),
        ({"ok": {"status": "fine"}, "error_in_200": {"status": "error", "reason_code": "error"}}, "ok.status"),
        ({"ok": {"status": "ok"}}, "must be"),
    ],
)
def test_expected_json_is_validated(tmp_path, expected, needle):
    folder = tmp_path / "spec"
    folder.mkdir()
    (folder / "ok.json").write_text("{}")
    (folder / "error_in_200.json").write_text("{}")
    (folder / "expected.json").write_text(json.dumps(expected))
    assert any(needle in p for p in specs.fixture_problems(folder))


@pytest.mark.parametrize(
    "expected",
    [
        {"ok": {"status": ["ok"]}, "error_in_200": {"status": "error", "reason_code": "error"}},
        {"ok": {"status": "ok"}, "error_in_200": {"status": ["error"], "reason_code": "error"}},
        {"ok": {"status": "ok"}, "error_in_200": {"status": "error", "reason_code": ["error"]}},
        {"ok": {"status": "error"}, "error_in_200": {"status": "error", "reason_code": "error"}},
        [1, 2, 3],
    ],
)
def test_fixture_problems_never_raise(tmp_path, expected):
    folder = tmp_path / "spec"
    folder.mkdir()
    (folder / "ok.json").write_text("{}")
    (folder / "error_in_200.json").write_text("{}")
    (folder / "expected.json").write_text(json.dumps(expected))
    assert specs.fixture_problems(folder)


def test_expected_ok_status_matches_the_health_check(tmp_path):
    folder = tmp_path / "spec"
    folder.mkdir()
    (folder / "ok.json").write_text("{}")
    (folder / "error_in_200.json").write_text("{}")
    (folder / "expected.json").write_text(json.dumps({"ok": {"status": "empty"}, "error_in_200": {"status": "error", "reason_code": "error"}}))
    assert specs.fixture_problems(folder) == []
    assert any("health_check.expect 'ok'" in p for p in specs.fixture_problems(folder, expect="ok"))


@pytest.mark.parametrize(
    ("file_name", "content"),
    [
        ("aaa_latin1.json", b'{"name": "\xff\xfe"}'),
        ("aaa_deep.json", b"[" * 100000 + b"]" * 100000),
        ("aaa_unhashable.json", None),
    ],
)
def test_one_broken_user_spec_never_stops_the_others(selftest_providers_registered, isolated_home, tmp_path, file_name, content):
    """Each spec loads in isolation: an undecodable, absurdly nested or otherwise broken file is
    reported under its path while every other spec still loads (never 'spec:*')."""
    user = install_user_specs(isolated_home, ["selftest_json", "selftest_csv"])
    if content is None:  # a spec whose fixtures hold an unhashable expected status
        spec = selftest_spec("selftest_xml")
        spec["name"] = "aaa_unhashable"
        content = json.dumps(spec).encode()
        shutil.copytree(SELFTEST / "selftest_xml", user / "aaa_unhashable")
        (user / "aaa_unhashable" / "expected.json").write_text(json.dumps({"ok": {"status": ["ok"]}, "error_in_200": {}}))
    (user / file_name).write_bytes(content)
    secure_tree(user)
    loaded = specs.load_specs(bundled_dir=tmp_path / "none", user_dir=user)
    assert {cls.name for cls in loaded} == {"selftest_json", "selftest_csv"}
    errors = spec_errors()
    assert "spec:*" not in errors and len(errors) == 1, errors
    assert next(iter(errors)) in (f"spec:{user / file_name}", "spec:aaa_unhashable")


def test_user_specs_must_pass_their_own_fixtures(selftest_providers_registered, isolated_home, tmp_path):
    """No CI runs a user spec: at load it runs offline over its own fixtures (P331 cond 7). A spec
    whose error marker misses its own error-in-200 body (rule 5) or whose ok fixture does not give
    expected.json is refused; the others load."""
    user = install_user_specs(isolated_home, ["selftest_json", "selftest_csv", "selftest_pages"])
    blind = selftest_spec("selftest_json")
    blind["error_markers"] = []  # the quota body inside HTTP 200 would read as 'nothing found'
    (user / "selftest_json.json").write_text(json.dumps(blind))
    wrong = json.loads((user / "selftest_csv" / "expected.json").read_text(encoding="utf-8"))
    wrong["ok"]["attributes"] = {"malware_family": "NotWhatTheFixtureSays"}
    (user / "selftest_csv" / "expected.json").write_text(json.dumps(wrong))
    secure_tree(user)
    loaded = specs.load_specs(bundled_dir=tmp_path / "none", user_dir=user)
    assert [cls.name for cls in loaded] == ["selftest_pages"]
    errors = spec_errors()
    assert "fixture error_in_200" in errors["spec:selftest_json"] and "could not verify" in errors["spec:selftest_json"]
    assert "attributes ['malware_family'] differ" in errors["spec:selftest_csv"]
    assert "selftest_json" not in modreg.REGISTRY and "selftest_csv" not in modreg.REGISTRY


def test_check_fixtures_runs_offline(selftest):
    for name, cls in selftest.items():
        assert specs.check_fixtures(cls, SELFTEST / name) == [], name
    assert specs.check_fixtures(selftest["selftest_json"], SELFTEST / "selftest_csv")  # someone else's fixtures fail
    assert specs.check_fixtures(modreg.REGISTRY["dns_records"], SELFTEST / "selftest_json") == [
        "not a compiled spec with a health-check value"
    ]


def test_spec_file_problems_are_recorded(selftest_providers_registered, isolated_home, tmp_path):
    user = install_user_specs(isolated_home, ["selftest_json"])
    shutil.move(user / "selftest_json.json", user / "other_name.json")
    (user / "broken.json").write_text("{not json")
    os.chmod(user / "broken.json", 0o600)
    loaded = specs.load_specs(bundled_dir=tmp_path, user_dir=user)
    assert loaded == []
    errors = spec_errors()
    # a file whose declared name differs from its stem is reported under its path, never under the
    # name it claims (that name may belong to another module: see test_refused_spec_never_disables_*)
    assert "file name must be 'selftest_json.json'" in errors[f"spec:{user / 'other_name.json'}"]
    assert "spec:selftest_json" not in errors
    assert "invalid JSON" in errors[f"spec:{user / 'broken.json'}"]


def _policy_decision(cls: Any) -> Any:
    policy = pytest.importorskip("v3lum.core.policy")
    from tests.fakes import make_runtime

    entity = Entity.make(EntityType.IPV4, "8.8.8.8")
    pctx = policy.make_context(make_runtime(FakeHttp()), ScanOptions(tlp="clear"), explicit=(cls.name,))
    return policy.decide(cls, entity, pctx, run=RunInfo(entity=entity, is_seed=True, depth=0, tlp="clear"))


def test_user_spec_never_shadows_a_module(selftest_providers_registered, isolated_home, tmp_path):
    modreg.load_modules()
    user = isolated_home / "specs"
    user.mkdir()
    spec = selftest_spec("selftest_json")
    spec["name"] = "shodan_internetdb"
    (user / "shodan_internetdb.json").write_text(json.dumps(spec))
    shutil.copytree(SELFTEST / "selftest_json", user / "shodan_internetdb")
    secure_tree(user)
    original = modreg.REGISTRY["shodan_internetdb"]
    assert specs.load_specs(bundled_dir=tmp_path, user_dir=user) == []
    errors = spec_errors()
    assert "collides with module" in errors[f"spec:{user / 'shodan_internetdb.json'}"]
    assert "spec:shodan_internetdb" not in errors
    assert modreg.REGISTRY["shodan_internetdb"] is original


@pytest.mark.parametrize("declared_elsewhere", [False, True])
def test_refused_spec_never_disables_the_module_it_collides_with(selftest_providers_registered, isolated_home, tmp_path, declared_elsewhere):
    """Regression: the policy gate (POL-02) skips a registered class whose name carries a
    'spec:<name>' load error; a colliding (or misnamed) user spec must not disable the real module."""
    modreg.load_modules()
    before = _policy_decision(modreg.REGISTRY["shodan_internetdb"])
    user = isolated_home / "specs"
    user.mkdir()
    spec = selftest_spec("selftest_json")
    spec["name"] = "shodan_internetdb"
    stem = "innocent_name" if declared_elsewhere else "shodan_internetdb"
    (user / f"{stem}.json").write_text(json.dumps(spec))
    shutil.copytree(SELFTEST / "selftest_json", user / stem)
    secure_tree(user)
    specs.load_specs(bundled_dir=tmp_path, user_dir=user)
    assert spec_errors()  # the refusal is reported ...
    after = _policy_decision(modreg.REGISTRY["shodan_internetdb"])
    assert after.rule_id != "POL-02", after  # ... but never against the hand-written module
    assert (after.allowed, after.status, after.reason_code) == (before.allowed, before.status, before.reason_code)


def test_user_spec_never_shadows_a_bundled_spec(selftest_providers_registered, isolated_home, tmp_path):
    bundled = tmp_path / "bundled"
    bundled.mkdir()
    shutil.copy(SELFTEST / "selftest_csv.json", bundled / "selftest_csv.json")
    fixtures = tmp_path / "fixtures"
    shutil.copytree(SELFTEST / "selftest_csv", fixtures / "selftest_csv")
    user = install_user_specs(isolated_home, ["selftest_csv"])
    loaded = specs.load_specs(bundled_dir=bundled, user_dir=user, fixtures_dir=fixtures)
    assert [cls.spec_origin.split(":", 1)[0] for cls in loaded] == ["bundled"]
    errors = spec_errors()
    assert "name already used by bundled:" in errors[f"spec:{user / 'selftest_csv.json'}"]
    assert "spec:selftest_csv" not in errors  # the registered bundled spec carries no load error
    decision = _policy_decision(loaded[0])
    assert decision.rule_id != "POL-02", decision


def test_reload_unregisters_removed_specs(selftest_providers_registered, isolated_home, tmp_path):
    loaded, user = _load_user(isolated_home, tmp_path, ["selftest_json", "selftest_csv"])
    assert {cls.name for cls in loaded} == {"selftest_json", "selftest_csv"}
    (user / "selftest_csv.json").unlink()
    loaded = specs.load_specs(bundled_dir=tmp_path / "no_bundled", user_dir=user)
    assert [cls.name for cls in loaded] == ["selftest_json"]
    assert "selftest_csv" not in modreg.REGISTRY and "selftest_json" in modreg.REGISTRY


def test_lint_issues_refuse_a_spec(selftest_providers_registered, isolated_home, tmp_path, monkeypatch):
    class Issue:
        rule_id, message, allowed = "LINT-05", "submission endpoint", False

    def fake_lint(path: Any, **_kw: Any) -> list[Any]:
        name = path.get("name") if isinstance(path, dict) else Path(path).stem
        return [Issue()] if name == "selftest_csv" else []

    monkeypatch.setattr(lint, "lint_data_file", fake_lint, raising=False)
    loaded, _user = _load_user(isolated_home, tmp_path, ["selftest_json", "selftest_csv"])
    assert [cls.name for cls in loaded] == ["selftest_json"]
    assert "LINT-05: submission endpoint" in spec_errors()["spec:selftest_csv"]
    # compile_spec lints the document on every path, not only the loader
    with pytest.raises(specs.SpecError, match="LINT-05"):
        specs.compile_spec(selftest_spec("selftest_csv"), origin="tests:inline")


def test_the_data_lint_refuses_mailbox_verification_hosts(clean_registry, spec_state):
    """The P327 data lint runs inside validate_spec: a provider host of an SMTP/mailbox verification
    service (team rule 2) is refused even when the URL path looks harmless."""
    probe = lint.lint_data_file({"schema": "v3lum.spec/1", "hosts": ["api.emailable.com"], "request": {"url": "https://api.emailable.com/v1/x", "method": "GET"}}, kind="spec")
    if not any(i.rule_id for i in probe):
        pytest.skip("the WP09 lint tables do not list this host")
    fragment = provider_fragment("mailcheck_t", hosts=["api.emailable.com"], tier="community", sources=("lookup",))
    providers.register(fragment, origin="tests")
    spec = selftest_spec("selftest_json")
    spec.update(provider="mailcheck_t", sources=["mailcheck_t.lookup"], hosts=["api.emailable.com"], name="mailcheck_t_spec")
    spec["request"]["url"] = "https://api.emailable.com/v1/ip/{value}"
    spec["manual_link"] = ""
    assert any(p.startswith("lint: ") for p in specs.validate_spec(spec)), specs.validate_spec(spec)


def test_load_modules_compiles_bundled_specs(selftest_providers_registered, tmp_path, monkeypatch):
    bundled = tmp_path / "data_specs"
    bundled.mkdir()
    fixtures = tmp_path / "fixtures_specs"
    for name in ("selftest_json", "selftest_xml"):
        shutil.copy(SELFTEST / f"{name}.json", bundled / f"{name}.json")
        shutil.copytree(SELFTEST / name, fixtures / name)
    broken = selftest_spec("selftest_csv")
    broken["request"]["method"] = "POST"
    (bundled / "selftest_csv.json").write_text(json.dumps(broken))
    monkeypatch.setattr(specs, "BUNDLED_DIR", bundled)
    monkeypatch.setattr(specs, "BUNDLED_FIXTURES_DIR", fixtures)
    modreg.load_modules(force=True)
    for name in ("selftest_json", "selftest_xml"):
        cls = modreg.REGISTRY[name]
        assert cls.describe()["spec_origin"] == f"bundled:{bundled / (name + '.json')}"
    assert "selftest_csv" not in modreg.REGISTRY
    assert "only 'GET'" in modreg.load_errors()["spec:selftest_csv"]
    assert "dns_records" in modreg.REGISTRY  # hand-written modules are unaffected


def test_user_specs_load_only_with_user_directories(selftest_providers_registered, isolated_home, tmp_path, monkeypatch):
    """A bare load_modules() (tests, tools) never reads ~/.v3lum/specs; the App and the Engine, which
    load the user directories (extra_dirs), compile the user specs too."""
    install_user_specs(isolated_home, ["selftest_json"])
    monkeypatch.setattr(specs, "BUNDLED_DIR", tmp_path / "none")
    modreg.load_modules(force=True)
    assert "selftest_json" not in modreg.REGISTRY
    modreg.load_modules(extra_dirs=[str(tmp_path / "no_plugins")], force=True)
    assert modreg.REGISTRY["selftest_json"].spec_origin.startswith("user:")
    modreg.load_modules(extra_dirs=[str(tmp_path / "no_plugins")], force=True, user_specs=False)
    assert "selftest_json" not in modreg.REGISTRY
    modreg.load_modules(force=True, user_specs=True)
    assert "selftest_json" in modreg.REGISTRY


def test_dot_segment_values_are_never_rendered(selftest_providers_registered):
    cls = specs.compile_spec(selftest_spec("selftest_profile"), origin="tests:inline")
    for raw in (".", ".."):
        entity = Entity(EntityType.USERNAME, raw)  # bypasses normalisation on purpose
        with pytest.raises(specs._NotApplicable):
            cls._compiled.url_for(entity, None)
        assert cls().applies(entity, None) is False


def test_describe_is_json_serialisable_with_setting_specs(clean_registry):
    """module.describe() unwraps SettingSpec declarations (module settings may declare them)."""
    from v3lum.config import SettingSpec

    body = {
        "name": "t_settingspec_describe", "title": "t", "description": "t", "category": "utility",
        "accepts": {EntityType.DOMAIN}, "terms": "open", "opsec": Opsec.PASSIVE, "disclosure": "none", "hosts": (),
        "settings": {"t_settingspec_describe_limit": SettingSpec(5, "limit"), "t_settingspec_describe_flag": True},
        "run": lambda self, entity, ctx: self.result(entity),
    }
    cls = modreg.register(type("SettingSpecDescribe", (modreg.Module,), body))
    info = cls.describe()
    assert info["settings"] == {"t_settingspec_describe_limit": 5, "t_settingspec_describe_flag": True}
    json.dumps(info)


def test_hand_written_describe_has_no_spec_fields():
    modreg.load_modules()
    info = modreg.REGISTRY["shodan_internetdb"].describe()
    assert "spec_origin" not in info and "spec_disabled" not in info


# --------------------------------------------------------------------------------------
# health: auto-disable after 7 consecutive failing days (P331 cond 9)
# --------------------------------------------------------------------------------------


def test_auto_disable_after_seven_failing_days(selftest_providers_registered, isolated_home, tmp_path):
    import datetime as dt

    health_mod = pytest.importorskip("v3lum.core.health")
    state = health_mod.HealthState(tmp_path / "health.json")
    start = dt.datetime(2026, 11, 1, 9, 0, tzinfo=dt.timezone.utc)
    for day in range(6):
        state.record_check("selftest_json", "dead", now=start + dt.timedelta(days=day))
    loaded, user = _load_user(isolated_home, tmp_path, ["selftest_json"])
    assert specs.auto_disabled("selftest_json", health=state) == ""
    loaded = specs.load_specs(bundled_dir=tmp_path / "no_bundled", user_dir=user, health=state)
    assert loaded[0].spec_disabled == "" and specs.disabled() == {}
    state.record_check("selftest_json", "dead", now=start + dt.timedelta(days=6))
    (cls,) = specs.load_specs(bundled_dir=tmp_path / "no_bundled", user_dir=user, health=state)
    assert specs.failing_days("selftest_json", health=state) == 7
    assert cls.spec_disabled.startswith("auto-disabled") and specs.disabled() == {"selftest_json": cls.spec_disabled}
    assert cls.default_enabled is False and cls.describe()["spec_disabled"] == cls.spec_disabled
    assert any("auto-disabled" in n for n in state.notices())
    res = run_module(cls, "ipv4:8.8.8.8", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "demoted"
    # doctor can still probe it: the health check carries a self-test doing the real lookup
    hc = cls.health_check()
    assert hc.entity == Entity.make(EntityType.IPV4, "8.8.8.8") and callable(hc.selftest)
    http = FakeHttp()
    route_fixture(http, cls, hc.entity, SELFTEST / "selftest_json")
    result = hc.selftest(make_ctx(cls, http, entity="ipv4:8.8.8.8"))
    assert result.status == "ok"
    blocked = FakeHttp()
    route_fixture(blocked, cls, hc.entity, SELFTEST / "selftest_rss", "error_in_200")
    assert hc.selftest(make_ctx(cls, blocked, entity="ipv4:8.8.8.8")).status == "blocked"
    state.record_check("selftest_json", result, now=start + dt.timedelta(days=7))
    (cls,) = specs.load_specs(bundled_dir=tmp_path / "no_bundled", user_dir=user, health=state)
    assert cls.spec_disabled == "" and cls.default_enabled is True and specs.disabled() == {}


def _disabled_spec(spec: dict[str, Any]) -> Any:
    return specs.compile_spec(spec, origin="tests:inline", disabled="auto-disabled: tests")


def test_disabled_spec_selftest_judges_the_declared_expectation(selftest_providers_registered):
    from v3lum.core.http import Cancelled

    cls = _disabled_spec(selftest_spec("selftest_json"))  # health_check.expect 'ok'
    hc = cls.health_check()
    url = "https://api.selftest.test/v1/ip/8.8.8.8?format=json"
    empty = FakeHttp().add("GET", url, json={})
    result = hc.selftest(make_ctx(cls, empty, entity="ipv4:8.8.8.8"))
    assert result.status == "dead" and "expected 'ok'" in result.detail  # the source stopped answering with data
    quota = FakeHttp().add("GET", url, json={"error": {"code": "quota_exceeded"}})
    assert hc.selftest(make_ctx(cls, quota, entity="ipv4:8.8.8.8")).status == "quota"
    # environment refusals are never recorded as a failed day: they propagate to doctor
    with pytest.raises(PolicyError):
        hc.selftest(make_ctx(cls, FakeHttp(), entity="ipv4:8.8.8.8", allowed_sources=()))
    cancelled = FakeHttp().add("GET", url, error=Cancelled())
    with pytest.raises(Cancelled):
        hc.selftest(make_ctx(cls, cancelled, entity="ipv4:8.8.8.8"))
    spec = selftest_spec("selftest_json")
    spec.update(name="selftest_json_empty", health_check={"etype": "ipv4", "value": "8.8.8.8", "expect": "empty"})
    empty_cls = _disabled_spec(spec)
    assert empty_cls.health_check().selftest(make_ctx(empty_cls, FakeHttp().add("GET", url, json={}), entity="ipv4:8.8.8.8")).status == "ok"


# --------------------------------------------------------------------------------------
# acceptance 1: indistinguishable from a hand-written module (contract test, policy, quotas)
# --------------------------------------------------------------------------------------


def test_compiled_specs_pass_the_registry_contract(selftest, tmp_path, monkeypatch):
    import tests.test_registry_contract as contract

    fixtures = tmp_path / "contract_fixtures"
    for name in selftest:
        shutil.copytree(SELFTEST / name, fixtures / "specs" / name)
    monkeypatch.setattr(contract, "FIXTURES", fixtures)
    for name, cls in selftest.items():
        assert contract.module_problems(cls) == [], name
    shutil.rmtree(fixtures / "specs" / "selftest_json")
    assert any("compiled spec without tests/fixtures/specs/selftest_json" in p for p in contract.module_problems(selftest["selftest_json"]))


_CONTRACT_FIELDS = (
    "title", "description", "category", "reference", "tags", "notice", "accepts", "produces", "run_on", "terms", "opsec",
    "disclosure", "hosts", "provider", "sources", "access_model", "requires_keys", "optional_keys", "max_requests",
    "expected_latency", "min_interval", "cache_ttl", "absent_statuses", "manual_link", "default_enabled", "requires_egress",
)


def _hand_written_twin(cls: Any, name: str) -> Any:
    body = {field: getattr(cls, field) for field in _CONTRACT_FIELDS}
    body["error_markers"] = tuple(m.to_dict() for m in cls.error_markers)
    body["name"] = name
    body["run"] = lambda self, entity, ctx: self.result(entity)
    return modreg.register(type("HandWrittenTwin", (modreg.Module,), body))


def test_compiled_spec_is_indistinguishable_from_a_hand_written_module(selftest):
    import tests.test_registry_contract as contract

    spec_cls = selftest["selftest_json"]
    twin = _hand_written_twin(spec_cls, "selftest_json_twin")
    spec_info, twin_info = spec_cls.describe(), twin.describe()
    for info in (spec_info, twin_info):
        info.pop("name")
        info.pop("spec_origin", None)
        info.pop("spec_disabled", None)
    assert spec_info == twin_info
    for attr in modreg.DERIVED:
        assert getattr(spec_cls, attr) == getattr(twin, attr), attr
    assert spec_cls.health_check() == twin.health_check()
    def not_test_rule(problems: list[str]) -> list[str]:
        return [p for p in problems if "tests/modules/test_" not in p and "tests/fixtures/" not in p]

    assert not_test_rule(contract.module_problems(spec_cls)) == not_test_rule(contract.module_problems(twin)) == []
    # quotas: the provider budget (registry quota block) is the same for both
    ctx_spec, ctx_twin = make_ctx(spec_cls, FakeHttp()), make_ctx(twin, FakeHttp())
    assert ctx_spec.quota_remaining() == ctx_twin.quota_remaining() == 800
    assert ctx_spec.http.max_requests == ctx_twin.http.max_requests == 1
    assert ctx_spec.http.allowed_hosts == ctx_twin.http.allowed_hosts == ("api.selftest.test",)
    # a provider quota marker inside HTTP 200 gives the same QUOTA outcome
    body = json.loads((SELFTEST / "selftest_json" / "error_in_200.json").read_text(encoding="utf-8"))
    http = FakeHttp().add("GET", "https://api.selftest.test/v1/ip/8.8.8.8?format=json", json=body, times=1)
    assert run_module(spec_cls, "ipv4:8.8.8.8", http).status is Status.QUOTA


def test_policy_treats_specs_like_hand_written_modules(selftest):
    policy = pytest.importorskip("v3lum.core.policy")
    if not hasattr(policy, "decide") or not hasattr(policy, "make_context"):
        pytest.skip("policy gate not available in this tree")
    from tests.fakes import make_runtime

    spec_cls = selftest["selftest_json"]
    twin = _hand_written_twin(spec_cls, "selftest_json_twin")
    unknown_cls = selftest["selftest_unknown"]
    unknown_twin = _hand_written_twin(unknown_cls, "selftest_unknown_twin")
    runtime = make_runtime(FakeHttp())
    entity = Entity.make(EntityType.IPV4, "8.8.8.8")
    for tlp in ("clear", "amber", "red"):
        pctx = policy.make_context(runtime, ScanOptions(tlp=tlp), explicit=())
        run = RunInfo(entity=entity, is_seed=True, depth=0, tlp=tlp)
        for left, right in ((spec_cls, twin), (unknown_cls, unknown_twin)):
            a, b = policy.decide(left, entity, pctx, run=run), policy.decide(right, entity, pctx, run=run)
            assert (a.allowed, a.status, a.reason_code, a.rule_id) == (b.allowed, b.status, b.reason_code, b.rule_id), (tlp, left.name, a, b)


# --------------------------------------------------------------------------------------
# acceptance 2: no spec can reach a host other than its literal declared hosts
# --------------------------------------------------------------------------------------


ADVERSARIAL_URLS = [
    "https://evil.test/",
    "https://evil.test/@api.selftest.test",
    "https://user:pass@evil.test:8080/a?b=c#d",
    "https://example.com/../../etc/passwd?x=1&y=2",
    "https://example.com/%2e%2e/%40evil.test",
    "https://example.com/?q=a#b",
]


@pytest.mark.parametrize("placeholder", ["value", "value_q", "value_qp", "b64"])
@pytest.mark.parametrize("value", ADVERSARIAL_URLS)
def test_entity_values_never_change_the_host(selftest_providers_registered, placeholder, value):
    spec = selftest_spec("selftest_json")
    spec.update(name="selftest_hosts", accepts=["url", "ipv4"], health_check={"etype": "ipv4", "value": "8.8.8.8", "expect": "ok"})
    token = "{" + placeholder + "}"
    spec["request"]["url"] = f"https://api.selftest.test/v1/{token}/x?u={token}"
    spec["request"]["params"] = {"p": token}
    cls = specs.compile_spec(spec, origin="tests:inline")
    entity = Entity.try_make(EntityType.URL, value)
    if entity is None:
        pytest.skip(f"{value!r} is not a valid URL entity")
    url = cls._compiled.url_for(entity, None)
    parts = re.match(r"^https://([^/?#]*)/v1/", url)
    assert parts is not None and parts.group(1) == "api.selftest.test", url
    assert "#" not in url


def test_redirects_to_undeclared_hosts_are_refused(clean_registry, spec_state):
    fragment = provider_fragment("selftest_api", hosts=["api.selftest.test", "cdn.selftest.test"], tier="community", sources=("lookup",))
    providers.register(fragment, origin="tests")
    spec = selftest_spec("selftest_json")
    cls = specs.compile_spec(spec, origin="tests:inline")
    assert cls.hosts == ("api.selftest.test",)
    url = "https://api.selftest.test/v1/ip/8.8.8.8?format=json"
    for target in ("https://cdn.selftest.test/v1/ip/8.8.8.8", "https://evil.test/collect", "https://api.selftest.test.evil.test/"):
        http = FakeHttp().add("GET", url, redirect_to=target).add("GET", target, json={"data": {"country": "US"}})
        res = run_module(cls, "ipv4:8.8.8.8", http)
        assert res.status is Status.SKIPPED and res.reason_code == "policy", (target, res.status, res.error)
        assert http.hosts() == {"api.selftest.test"}, target
    # a redirect inside the literal host is followed
    http = FakeHttp().add("GET", url, redirect_to="https://api.selftest.test/v2/ip/8.8.8.8").add(
        "GET", "https://api.selftest.test/v2/ip/8.8.8.8", json={"data": {"country": "US"}})
    assert run_module(cls, "ipv4:8.8.8.8", http).attributes["country"] == "US"


def test_rendered_urls_are_confined_at_runtime():
    for url in ("https://evil.test/x", "http://api.selftest.test/x", "https://u@api.selftest.test/x", "https://api.selftest.test:444/x",
                "https://api.selftest.test/x#frag", "https://api.selftest.test/a b"):
        with pytest.raises(PolicyError):
            specs._confine(url, "api.selftest.test")
    specs._confine("https://api.selftest.test/v1/x?y=1", "api.selftest.test")


def test_compiled_spec_hosts_are_the_literal_hosts(selftest):
    for cls in selftest.values():
        compiled = cls._compiled
        assert compiled.host in cls.hosts and all(not h.startswith("*.") for h in cls.hosts)
        ctx = make_ctx(cls, FakeHttp())
        assert set(ctx.http.allowed_hosts) == set(cls.hosts)


# --------------------------------------------------------------------------------------
# source hygiene
# --------------------------------------------------------------------------------------


def test_no_eval_exec_or_str_format_templates():
    source = Path(specs.__file__).read_text(encoding="utf-8")
    code = re.sub(r'""".*?"""', "", source, flags=re.S)
    assert not re.search(r"\beval\(|\bexec\(|__import__\(|compile\(\s*[a-z_]+\s*,\s*['\"]", code)
    assert ".format(" not in code and "format_map(" not in code
