"""username_check (P113 default username pack) and the shared checker engine.

Fixtures in tests/fixtures/username_check/: real answers recorded 2026-11-26 from official or
organisation accounts and random 20-character controls (Gravatar, Dribbble, About.me, Kaggle,
Linktree, TikTok oEmbed, Pinterest), a Cloudflare managed challenge (Medium), a real 429 (generic
username service), a Cloudflare bot-management page that is not a challenge, trimmed WhatsMyName /
Sherlock data (handles replaced by example values) and the rule-2 lint entries FC6 names.
Synthetic packs below use .example.test hosts with these recorded bodies.
"""

from __future__ import annotations

import json
import random
import re
from typing import Any

import pytest

from tests.fakes import FakeClock, FakeHttp, make_ctx, module_fixture, run_module, test_provider
from v3lum.core import datasets as datasets_mod
from v3lum.core import providers
from v3lum.core.context import ModuleState, ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.lint import forbidden_probe
from v3lum.core.models import Opsec, Status
from v3lum.core.module import register
from v3lum.modules.username_social import username_check as uc
from v3lum.modules.username_social.username_check import UsernameCheck

FIX = "username_check"
GRAVATAR = "https://en.gravatar.com/{}.json"
CONTROL_GRAVATAR = re.compile(r"^https://en\.gravatar\.com/[a-z][a-z0-9]{19}\.json$")
FOUND, ABSENT, UNKNOWN = uc.FOUND, uc.ABSENT, uc.UNKNOWN


# --------------------------------------------------------------------------------------- helpers
def env(name: str) -> dict[str, Any]:
    return module_fixture(FIX, name)


def text(name: str) -> str:
    return module_fixture(FIX, name)


def add_env(http: FakeHttp, url: Any, name: str, *, latency: float = 0.0, times: int | None = None) -> FakeHttp:
    e = env(name)
    return http.add("GET", url, status=e["status"], text=e["body"], headers=e["headers"], latency=latency, times=times)


def add_sherlock(http: FakeHttp, *, exclusions: str | None = None) -> FakeHttp:
    http.add("GET", uc.SHERLOCK_URL, text=json.dumps(env("sherlock_manifest_ok.json")))
    http.add("GET", uc.SHERLOCK_EXCLUSIONS_URL, text=exclusions if exclusions is not None else text("sherlock_exclusions_ok.txt"))
    return http


def ev(site: dict[str, Any], name: str, username: str | None = None) -> dict[str, Any]:
    e = env(name)
    return uc.evaluate_response(site, e["status"], e["headers"], e["body"], username=username)


def overlay_defs() -> dict[str, dict[str, Any]]:
    return uc.load_overlay()["definitions"]


def wmn_sites() -> dict[str, dict[str, Any]]:
    parsed = uc.parse_wmn_dataset(json.dumps(env("wmn_dataset_ok.json")))
    assert parsed["ok"], parsed["error"]
    return {s["name"]: s for s in parsed["sites"]}


def maigret_sites() -> dict[str, dict[str, Any]]:
    parsed = uc.parse_maigret_db(json.dumps(module_fixture("username_check_extended", "maigret_db_ok.json")))
    assert parsed["ok"], parsed["error"]
    return {s["name"]: s for s in parsed["sites"]}


def gravatar_found_run(handle: str = "automattic", **kw: Any) -> tuple[Any, FakeHttp]:
    http = add_sherlock(FakeHttp())
    add_env(http, GRAVATAR.format(handle), "gravatar_ok.json")
    add_env(http, CONTROL_GRAVATAR, "gravatar_not_found.json")
    return run_module(UsernameCheck, f"username:{handle}", http, **kw), http


def site_evidence(res: Any) -> list[dict[str, Any]]:
    return res.raw["sites"]


# ------------------------------------------------------------------------- metadata (council decision)
def test_metadata_matches_the_council_decision():
    cls = UsernameCheck
    assert (cls.name, cls.category, cls.run_on, cls.default_enabled) == ("username_check", "username_social", "seeds", True)
    assert (cls.terms, cls.opsec, cls.disclosure, cls.access_model) == ("open", Opsec.PASSIVE, "third_party", "free_noauth_limited")
    assert cls.accepts == frozenset({T.USERNAME}) and cls.produces == frozenset({T.URL, T.USERNAME})
    assert cls.max_requests == 150 and cls.timeout >= uc.DEFAULT_DEADLINE and cls.min_interval >= 1.0
    assert cls.expected_latency <= 10 and {"curated_pack", "pack"} <= cls.tags
    assert cls.hosts == uc.pack_hosts("username_check") == ("en.gravatar.com",)
    assert "gravatar.profiles" in cls.sources and set(uc.DEFAULT_DATASET_SOURCES) <= set(cls.sources)
    assert cls.trust_tier == "trusted" and cls.shares_input
    assert "username_default_sites" in cls.settings
    hc = cls.health_check()
    assert hc is not None and hc.etype is None and not hc.offline and callable(hc.selftest)


def test_bundled_packs_hold_only_tiered_open_calibrated_sites():
    """FC2/FC8/FC16: the default selection holds only overlay-tiered sites with registry terms 'open'
    and a 'correct' calibration; the overlay and the provider registry agree on every site."""
    overlay = uc.load_overlay()
    reg = providers.registry()
    assert uc._bundled()["errors"] == []
    for sid, rec in overlay["sites"].items():
        assert uc.site_registry_problems(sid, rec, reg) == [], sid
        assert rec["tier"] in uc.TIERS_QUERYABLE and rec["tier_rationale"]
    default = uc.pack_site_ids("username_check")
    assert 0 < len(default) <= uc.HARD_MAX_SITES
    for sid in default:
        rec = overlay["sites"][sid]
        assert reg.source(rec["source"]).terms.class_ == "open"
        assert rec["verdict"] == "correct" and uc.two_sided_markers(overlay["definitions"][sid])
    assert not set(default) & set(uc.pack_site_ids("username_check_extended"))
    assert "v3lum:linktree" in overlay["exclusions"]  # Sherlock exclusion list (FC5), no override recorded


def test_overlay_markers_are_v3lum_measurements_not_wmn_text():
    """FC4: V3LUM definitions never reuse a WhatsMyName presence marker for the same site."""
    wmn = wmn_sites()
    pairs = {"v3lum:gravatar": "Gravatar", "v3lum:dribbble": "Dribbble", "v3lum:aboutme": "about.me", "v3lum:kaggle": "Kaggle"}
    for sid, wmn_name in pairs.items():
        ours = overlay_defs()[sid]
        theirs = wmn[wmn_name]
        assert set(ours["presence"]["strings"]).isdisjoint(theirs["presence"]["strings"]), sid


# ------------------------------------------------------------------------------- engine through run_module
def test_found_with_absent_control_is_a_weak_possible_hit():
    res, http = gravatar_found_run()
    assert res.status is Status.OK
    assert res.attributes["site_checks"] == "username_check: 1 found · 0 could not verify · 0 absent · 0 not checked: budget"
    assert res.attributes["profiles"] == [{"platform": "Gravatar", "url": "https://gravatar.com/automattic", "display_name": "", "site_id": "v3lum:gravatar"}]
    (finding,) = res.findings
    assert finding.title == "Same handle found on Gravatar" and finding.severity.label == "info"
    assert finding.label.value == "possible" and "same handle does not prove identity" in finding.description
    assert finding.source == "gravatar.profiles" and finding.data["control"] == "absent" and "weak_signal" in finding.tags
    (pivot,) = res.pivots
    assert (pivot.entity.value, pivot.relation, pivot.expand, pivot.confidence_label.value) == ("https://gravatar.com/automattic", "has_account", False, "possible")
    assert pivot.note == "same handle does not prove identity"
    # FC9: one request per handle per site plus one control on the FOUND site, no retries, polite
    site_urls = [u for u in http.urls() if "gravatar" in u]
    assert len(site_urls) == 2 and site_urls[0] == GRAVATAR.format("automattic") and CONTROL_GRAVATAR.match(site_urls[1])
    calls = [c for c in http.calls if "gravatar" in c["url"]]
    assert all(c["method"] == "GET" and not c.get("body") for c in calls)
    assert not any(k.lower() in ("cookie", "authorization") for c in calls for k in c["headers"])
    assert res.requests == 2 and res.hosts == {"en.gravatar.com": 2}
    http.assert_hosts_within(UsernameCheck, extra=("raw.githubusercontent.com",))


def test_evidence_keeps_markers_and_body_hashes_never_bodies():
    res, _ = gravatar_found_run()
    claimed, control = site_evidence(res)
    assert claimed["state"] == FOUND and control["state"] == ABSENT and control["control"] is True
    assert claimed["marker"].startswith("HTTP 200 + ") and claimed["status"] == 200 and claimed["checked_at"].startswith("2026-11-26")
    assert re.fullmatch(r"[0-9a-f]{64}", claimed["body_sha256"])
    raw = json.dumps(res.raw)
    assert "preferredUsername\\\":\\\"automattic" not in raw and "thumbnailUrl" not in raw
    names = {d["name"] for d in res.datasets}
    assert {uc.SHERLOCK_DATA, uc.SHERLOCK_EXCLUSIONS} <= names


def test_display_name_from_profile_json():
    http = add_sherlock(FakeHttp())
    body = json.loads(env("gravatar_ok.json")["body"])
    body["entry"][0]["displayName"] = "Example Org Team"
    http.add("GET", GRAVATAR.format("exampleorg"), status=200, text=json.dumps(body), headers={"content-type": "application/json"})
    add_env(http, CONTROL_GRAVATAR, "gravatar_not_found.json")
    res = run_module(UsernameCheck, "username:exampleorg", http)
    assert res.attributes["profiles"][0]["display_name"] == "Example Org Team"
    assert "Example Org Team" in res.findings[0].description


def test_absent_on_the_absence_marker_is_empty():
    http = add_sherlock(FakeHttp())
    add_env(http, GRAVATAR.format("oj5nsqgky6am1w4be0ud"), "gravatar_not_found.json")
    res = run_module(UsernameCheck, "username:oj5nsqgky6am1w4be0ud", http)
    assert res.status is Status.EMPTY
    assert res.attributes["site_checks"] == "username_check: 0 found · 0 could not verify · 1 absent · 0 not checked: budget"
    assert not res.findings and not res.pivots
    assert site_evidence(res)[0]["marker"] == "HTTP 404 + 'User not found'"
    assert len([u for u in http.urls() if "gravatar" in u]) == 1  # no control on an ABSENT site


def test_control_found_turns_the_hit_into_could_not_verify_and_strikes_the_site():
    http = add_sherlock(FakeHttp())
    add_env(http, GRAVATAR.format("someorgname"), "gravatar_ok.json")
    add_env(http, CONTROL_GRAVATAR, "gravatar_ok.json")  # the site answers FOUND for anything
    res = run_module(UsernameCheck, "username:someorgname", http)
    assert res.status is Status.ERROR and "control handle also found" in res.error
    assert not res.findings and not res.pivots
    assert res.attributes["site_checks"].startswith("username_check: 0 found · 1 could not verify")
    health = ModuleState(uc.ENGINE_STATE).get("health")
    assert health["v3lum:gravatar"]["strikes"] == 1 and not health["v3lum:gravatar"]["disabled"]


def test_three_wrong_marks_disable_a_site_until_it_passes_again():
    ModuleState(uc.ENGINE_STATE).set("health", {"v3lum:gravatar": uc.health_update({}, "", strikes=3)})
    http = add_sherlock(FakeHttp())
    res = run_module(UsernameCheck, "username:someorgname", http)
    assert res.status is Status.SKIPPED and res.reason_code == "demoted"
    assert not any("gravatar" in u for u in http.urls())
    assert res.source_statuses["gravatar.profiles"]["reason_code"] == "demoted"


@pytest.mark.parametrize(
    ("fixture", "status", "code"),
    [
        ("rate_limited_429.json", Status.RATE_LIMITED, "rate_limited"),
        ("challenge_cloudflare_403.json", Status.BLOCKED, "challenge"),
    ],
)
def test_429_and_challenges_are_could_not_verify_never_absent(fixture, status, code):
    http = add_sherlock(FakeHttp())
    add_env(http, GRAVATAR.format("someorgname"), fixture)
    res = run_module(UsernameCheck, "username:someorgname", http)
    assert res.status is status and res.reason_code == code
    assert not res.findings and "0 absent" in res.attributes["site_checks"]
    assert res.source_statuses["gravatar.profiles"]["reason_code"] == code
    assert len([u for u in http.urls() if "gravatar" in u]) == 1  # no control, no retry
    assert any(label.startswith("Gravatar: could not verify") for label, _ in res.links)  # A9 manual follow-up


def test_keyless_403_without_markers_is_blocked():
    http = add_sherlock(FakeHttp()).add("GET", GRAVATAR.format("someorgname"), status=403, text="Forbidden")
    res = run_module(UsernameCheck, "username:someorgname", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_5xx_and_timeouts_are_errors_never_empty():
    http = add_sherlock(FakeHttp()).add("GET", GRAVATAR.format("someorgname"), status=503, text="upstream unavailable")
    res = run_module(UsernameCheck, "username:someorgname", http)
    assert res.status is Status.ERROR and res.reason_code == "error" and "server error" in res.error
    http = add_sherlock(FakeHttp()).add("GET", GRAVATAR.format("someorgname"), error=NetworkError("ReadTimeout contacting en.gravatar.com: timed out"))
    res = run_module(UsernameCheck, "username:someorgname", http)
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    assert [u for u in http.urls() if "gravatar" in u] == [GRAVATAR.format("someorgname")]  # one request, no retry (FC9)


def test_error_and_challenge_inside_http_200_are_never_found_or_absent():
    for body in ('{"error": "temporarily unavailable"}', "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"):
        http = add_sherlock(FakeHttp()).add("GET", GRAVATAR.format("someorgname"), status=200, text=body)
        res = run_module(UsernameCheck, "username:someorgname", http)
        assert res.status in (Status.ERROR, Status.BLOCKED), body
        assert not res.findings and "1 could not verify" in res.attributes["site_checks"]


def test_malformed_json_is_could_not_verify():
    http = add_sherlock(FakeHttp()).add("GET", GRAVATAR.format("someorgname"), status=200, text='{"entry": [ {"preferredUser')
    res = run_module(UsernameCheck, "username:someorgname", http)
    assert res.status is Status.ERROR and "no marker matched" in res.error


def test_redirects_are_evaluated_not_followed():
    http = add_sherlock(FakeHttp()).add("GET", GRAVATAR.format("someorgname"), status=302, text="", headers={"location": "/profiles/someorgname"})
    res = run_module(UsernameCheck, "username:someorgname", http)
    assert res.status is Status.ERROR and "unexpected redirect" in res.error
    assert not any("/profiles/" in u for u in http.urls())
    http = add_sherlock(FakeHttp()).add("GET", GRAVATAR.format("someorgname"), status=302, text="", headers={"location": "https://en.gravatar.com/login?next=x"})
    res = run_module(UsernameCheck, "username:someorgname", http)
    assert res.status is Status.BLOCKED and res.reason_code == "login_wall"


def test_cloudflare_bot_management_script_on_a_normal_page_is_not_a_challenge():
    e = env("regression_cf_jsd_200.json")
    http = add_sherlock(FakeHttp()).add("GET", GRAVATAR.format("someorgname"), status=200, text=e["body"], headers=e["headers"])
    res = run_module(UsernameCheck, "username:someorgname", http)
    assert res.status is Status.ERROR and res.reason_code == "error"  # no marker: could not verify, not BLOCKED


# --------------------------------------------------------------------------------------- privacy, TLP, syntax
def test_packs_run_only_on_typed_confirmed_seeds():
    for kw in ({"is_seed": False, "depth": 1}, {"provenance": [("text:pasted notes", "mentions", "ioc_extract")]}):
        http = FakeHttp()
        res = run_module(UsernameCheck, "username:someorgname", http, **kw)
        assert res.status is Status.SKIPPED and res.reason_code == "privacy", kw
        assert http.urls() == []
    options = ScanOptions(unconfirmed_seeds={"username:someorgname"})
    http = FakeHttp()
    res = run_module(UsernameCheck, "username:someorgname", http, options=options)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "username:" in res.error
    assert http.urls() == []


def test_tlp_red_sends_nothing_and_amber_strict_keeps_trusted_sites():
    http = FakeHttp()
    res = run_module(UsernameCheck, "username:someorgname", http, tlp="red")
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and http.urls() == []
    res, _ = gravatar_found_run(tlp="amber+strict")  # Gravatar is trusted
    assert res.status is Status.OK


def test_sherlock_regex_skips_a_handle_the_site_cannot_hold():
    http = add_sherlock(FakeHttp())  # Sherlock's Gravatar pattern refuses dots
    res = run_module(UsernameCheck, "username:some.org", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert not any("gravatar" in u for u in http.urls())
    assert "skipped: 1 syntax" in res.attributes["site_checks_coverage"]


def test_sherlock_exclusion_list_drops_a_site_at_runtime():
    http = add_sherlock(FakeHttp(), exclusions="Linktree\nGravatar\n")
    res = run_module(UsernameCheck, "username:someorgname", http)
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and "Sherlock" in res.error
    assert not any("gravatar" in u for u in http.urls())


def test_unusable_sherlock_datasets_degrade_without_hiding_the_site():
    http = FakeHttp()
    http.add("GET", uc.SHERLOCK_URL, status=404, text=text("dataset_not_found.txt"))
    http.add("GET", uc.SHERLOCK_EXCLUSIONS_URL, status=404, text=text("dataset_not_found.txt"))
    add_env(http, GRAVATAR.format("automattic"), "gravatar_ok.json")
    add_env(http, CONTROL_GRAVATAR, "gravatar_not_found.json")
    res = run_module(UsernameCheck, "username:automattic", http)
    assert res.status is Status.OK and len(res.findings) == 1
    assert res.source_statuses[uc.SRC_SHERLOCK]["status"] == "error"


def test_high_collision_handles_are_flagged_and_stay_info():
    lists = uc._bundled()["collision"]
    kw = {"common": lists["common_usernames"], "first_names": lists["first_names"], "dictionary": lists["dictionary_words"]}
    assert uc.high_collision_reason("maria", **kw) == "common first name"
    assert uc.high_collision_reason("admin", **kw) == "common username"
    assert uc.high_collision_reason("abcd", **kw).startswith("short handle")
    assert uc.high_collision_reason("shadow", **kw) == "dictionary word"
    assert uc.high_collision_reason("x9k2examplehandle", **kw) is None
    res, _ = gravatar_found_run("maria")
    assert res.attributes["collision_reason"] == "common first name"
    (finding,) = res.findings
    assert finding.severity.label == "info" and "high_collision" in finding.tags and "high-collision" in finding.description


# ------------------------------------------------------------------------- synthetic packs (engine limits)
SITE_SOURCE = "t_username_sites.profile"


def _site(i: int, *, presence: str = '"preferredUsername":"', absence: str = "User not found", path: str = "{account}.json") -> dict[str, Any]:
    host = f"site{i:02d}.example.test"
    return {"name": f"Site {i:02d}", "check_url": f"https://{host}/{path}", "profile_url": f"https://{host}/{{account}}",
            "presence": {"status": 200, "strings": [presence]}, "absence": {"status": 404, "strings": [absence]}, "category": "social"}


def _overlay(n: int, *, tier: str = "trusted", wmn: dict[str, str] | None = None) -> dict[str, Any]:
    sites: dict[str, Any] = {}
    for i in range(1, n + 1):
        sites[f"v3lum:site{i:02d}"] = {"name": f"Site {i:02d}", "provider": "t_username_sites", "source": SITE_SOURCE,
                                       "hosts": [f"site{i:02d}.example.test"], "tier": tier, "tier_rationale": "test site",
                                       "calibration": {"claimed": "exampleorg", "verdict": "correct"}, "definition": _site(i)}
    for sid, host in (wmn or {}).items():
        sites[sid] = {"name": sid, "provider": "t_username_sites", "source": SITE_SOURCE, "hosts": [host], "tier": tier,
                      "tier_rationale": "test site", "calibration": {"verdict": "correct"}}
    return uc.parse_overlay({"sites": sites, "exclusions": {}})


@pytest.fixture
def pack_module(clean_registry):
    """Register a synthetic pack module over example.test hosts (n sites, built per test)."""
    made: list[Any] = []

    def build(n: int, *, cap: int = 150, default: bool = True, site_ids: tuple[str, ...] | None = None, overlay: dict[str, Any] | None = None,
              extra_hosts: tuple[str, ...] = (), tier: str = "trusted") -> Any:
        site_hosts = tuple(f"site{i:02d}.example.test" for i in range(1, n + 1)) + extra_hosts
        ctx = test_provider("t_username_sites", hosts=site_hosts, tier=tier, sources=("profile",))
        ctx.__enter__()
        made.append(ctx)
        ov = overlay or _overlay(n, tier=tier)
        ids = site_ids if site_ids is not None else tuple(f"v3lum:site{i:02d}" for i in range(1, n + 1))

        class SyntheticPack(uc.UsernamePackBase):
            name = "t_username_pack"
            title = "synthetic username pack"
            description = "synthetic pack over example.test hosts"
            category = "username_social"
            accepts = {T.USERNAME}
            terms = "open"
            opsec = Opsec.PASSIVE
            disclosure = "third_party"
            hosts = tuple(sorted(set(site_hosts)))
            max_requests = cap
            expected_latency = 8.0
            provider = "t_username_sites"
            sources = (SITE_SOURCE, uc.SRC_SHERLOCK, uc.SRC_SHERLOCK_EXCLUSIONS, uc.SRC_WMN)
            access_model = "free_noauth_limited"
            timeout = uc.DEFAULT_DEADLINE + uc.GRACE
            min_interval = 1.0
            tags = {"pack", "curated_pack"}
            default_enabled = False
            run_on = "seeds"
            pack_id = "t_username_pack"
            default_pack = default

            @classmethod
            def load_pack(cls) -> uc.Pack:
                return uc.Pack("t_username_pack", ids, ov, {}, default, uc._bundled()["collision"])

        return register(SyntheticPack)

    yield build
    for ctx in reversed(made):
        ctx.__exit__(None, None, None)


def _route_site(http: FakeHttp, i: int, handle: str, fixture: str, *, latency: float = 0.0, control: str | None = "gravatar_not_found.json") -> None:
    host = f"site{i:02d}.example.test"
    add_env(http, f"https://{host}/{handle}.json", fixture, latency=latency)
    if control:
        add_env(http, re.compile(rf"^https://{re.escape(host)}/[a-z][a-z0-9]{{19}}\.json$"), control, latency=latency)


def test_default_pack_on_recorded_fixtures_finishes_within_30s_simulated(pack_module):
    """FC15: a pack on recorded fixtures (recorded latencies, fake clock) prints the counts line well
    inside 30 s simulated; the deterministic scheduler model agrees for a full 100-site pack."""
    cls = pack_module(20)
    clock = FakeClock()
    http = add_sherlock(FakeHttp(clock=clock))
    rec = {name: env(name)["_meta"]["elapsed_s"] for name in ("gravatar_ok.json", "gravatar_not_found.json")}
    for i in range(1, 21):
        _route_site(http, i, "exampleorg", "gravatar_ok.json" if i % 4 == 0 else "gravatar_not_found.json", latency=rec["gravatar_ok.json"])
    start = clock.monotonic()
    res = run_module(cls, "username:exampleorg", http, clock=clock)
    elapsed = clock.monotonic() - start
    assert res.attributes["site_checks"] == "t_username_pack: 5 found · 0 could not verify · 15 absent · 0 not checked: budget"
    assert elapsed <= 30.0, elapsed
    latencies = [0.307, 0.142, 0.287, 0.159, 0.177, 0.207, 0.149, 0.11, 0.403, 0.208, 0.575, 0.554]
    jobs = [(f"h{i}", latencies[i % len(latencies)]) for i in range(100)] + [(f"h{i}", latencies[i % len(latencies)]) for i in range(0, 100, 5)]
    sim = uc.simulate_schedule(jobs)
    assert sim["completed"] == 120 and sim["not_checked"] == 0 and sim["makespan"] <= 30.0
    assert uc.simulate_schedule(jobs, concurrency=8, deadline=2.0)["not_checked"] > 0


def test_request_cap_counts_controls_and_reports_not_checked_budget(pack_module):
    cls = pack_module(6, cap=4)
    http = add_sherlock(FakeHttp())
    for i in range(1, 7):
        _route_site(http, i, "exampleorg", "gravatar_ok.json")
    res = run_module(cls, "username:exampleorg", http)
    counts = res.raw["counts"]
    assert counts["found"] + counts["unknown"] + counts["absent"] <= 4
    assert res.raw["requests_budget"]["used"] == 4 and counts["not_checked"] >= 2
    assert res.partial and res.stop_reason == "request_cap"
    assert re.search(r"· [1-9] not checked: budget$", res.attributes["site_checks"])
    assert len([u for u in http.urls() if "example.test" in u]) == 4


def _one_host_overlay(n: int) -> tuple[dict[str, Any], tuple[str, ...]]:
    """n sites on site01.example.test (one host: one worker, requests one after the other)."""
    ov = _overlay(1)
    ids = ["v3lum:site01"]
    for k in range(2, n + 1):
        sid = f"v3lum:site01p{k}"
        ov["definitions"][sid] = dict(ov["definitions"]["v3lum:site01"], id=sid, name=f"Site 01 path {k}", check_url=f"https://site01.example.test/p{k}/{{account}}")
        ov["sites"][sid] = dict(ov["sites"]["v3lum:site01"], name=f"Site 01 path {k}")
        ids.append(sid)
    return ov, tuple(ids)


def test_deadline_stops_new_requests_and_keeps_partial_results(pack_module):
    """FC10: no request starts when less than GRACE seconds remain; what was checked is kept."""
    ov, ids = _one_host_overlay(5)
    cls = pack_module(1, overlay=ov, site_ids=ids)
    clock = FakeClock()
    http = add_sherlock(FakeHttp(clock=clock))
    add_env(http, "https://site01.example.test/exampleorg.json", "gravatar_not_found.json", latency=60.0)
    for k in range(2, 6):
        add_env(http, f"https://site01.example.test/p{k}/exampleorg", "gravatar_not_found.json", latency=60.0)
    res = run_module(cls, "username:exampleorg", http, clock=clock)
    assert res.status is Status.EMPTY and res.partial and res.stop_reason == "deadline"
    assert res.raw["counts"]["absent"] == 2 and res.raw["counts"]["not_checked"] == 3
    assert res.attributes["site_checks"].endswith("· 2 absent · 3 not checked: budget")
    assert "not checked: 3 deadline" in res.attributes["site_checks_coverage"]
    assert len([u for u in http.urls() if "example.test" in u]) == 2


def test_a_block_stops_the_remaining_sites_of_that_host(pack_module):
    ov = _overlay(1)
    second = dict(ov["definitions"]["v3lum:site01"], id="v3lum:site01b", name="Site 01 bis", check_url="https://site01.example.test/u/{account}")
    ov["definitions"]["v3lum:site01b"] = second
    ov["sites"]["v3lum:site01b"] = dict(ov["sites"]["v3lum:site01"], name="Site 01 bis")
    cls = pack_module(1, overlay=ov, site_ids=("v3lum:site01", "v3lum:site01b"))
    http = add_sherlock(FakeHttp())
    add_env(http, "https://site01.example.test/exampleorg.json", "rate_limited_429.json")
    res = run_module(cls, "username:exampleorg", http)
    assert [r["state"] for r in res.raw["sites"]] == ["unknown"]
    assert "1 host stopped after a block" in res.attributes["site_checks_coverage"]
    assert not any("/u/" in u for u in http.urls())


def test_unknown_tier_sites_never_receive_the_handle(pack_module):
    cls = pack_module(2, tier="community")
    ov = cls.load_pack().overlay
    ov["sites"]["v3lum:site02"]["tier"] = "unknown"
    http = add_sherlock(FakeHttp())
    _route_site(http, 1, "exampleorg", "gravatar_not_found.json", control=None)
    res = run_module(cls, "username:exampleorg", http)
    assert not any("site02" in u for u in http.urls())
    assert "skipped: 1 tier" in res.attributes["site_checks_coverage"]
    # AMBER+STRICT: community sites are not queried either (FC8)
    http2 = add_sherlock(FakeHttp())
    res2 = run_module(cls, "username:exampleorg", http2, tlp="amber+strict")
    assert res2.status is Status.SKIPPED and res2.reason_code in ("tlp", "tier")
    assert not any("example.test" in u for u in http2.urls())


def test_username_default_sites_limits_the_default_pack(pack_module):
    cls = pack_module(5)
    http = add_sherlock(FakeHttp())
    for i in range(1, 3):
        _route_site(http, i, "exampleorg", "gravatar_not_found.json", control=None)
    res = run_module(cls, "username:exampleorg", http, settings={"username_default_sites": 2})
    assert res.raw["counts"]["absent"] == 2
    assert sum(1 for s in res.raw["skipped"] if "pack size" in s["reason"]) == 3


def test_wmn_sites_resolve_from_the_pinned_runtime_dataset(pack_module, monkeypatch):
    """FC3: a WhatsMyName id of the selection resolves from the runtime download (pinned SHA-256) and
    is re-checked by the runtime filters; the dataset is cited for the report footer."""
    tik = {"name": "Example oEmbed", "uri_check": "https://site09.example.test/oembed?url=https://www.example.com/@{account}",
           "uri_pretty": "https://www.example.com/@{account}", "e_code": 200, "e_string": "\"embed_type\":\"profile\"",
           "m_code": 400, "m_string": "Something went wrong", "known": ["example-claimed-1"], "cat": "social"}
    dataset = json.dumps({"license": ["CC BY-SA 4.0 (test)"], "authors": [], "categories": ["social"], "sites": [tik] + [dict(tik, name=f"Pad {i}") for i in range(80)]})
    monkeypatch.setitem(datasets_mod.DATASETS[uc.WMN], "pinned_sha256", uc.sha256_hex(dataset))
    ov = _overlay(0, wmn={"wmn:Example oEmbed": "site09.example.test"})
    cls = pack_module(0, overlay=ov, site_ids=("wmn:Example oEmbed",), extra_hosts=("site09.example.test",))
    http = add_sherlock(FakeHttp()).add("GET", uc.WMN_URL, text=dataset)
    add_env(http, "https://site09.example.test/oembed?url=https://www.example.com/@exampleorg", "tiktok_ok.json")
    add_env(http, re.compile(r"^https://site09\.example\.test/oembed\?url=https://www\.example\.com/@[a-z][a-z0-9]{19}$"), "tiktok_not_found.json")
    res = run_module(cls, "username:exampleorg", http)
    assert res.status is Status.OK
    assert res.attributes["profiles"][0]["url"] == "https://www.example.com/@exampleorg"
    assert res.attributes["profiles"][0]["display_name"] == "TikTok"
    assert uc.WMN in {d["name"] for d in res.datasets}


def test_a_changed_wmn_download_is_refused_by_the_pin(pack_module):
    ov = _overlay(0, wmn={"wmn:Example": "site09.example.test"})
    cls = pack_module(0, overlay=ov, site_ids=("wmn:Example",), extra_hosts=("site09.example.test",))
    http = add_sherlock(FakeHttp()).add("GET", uc.WMN_URL, text=json.dumps(env("wmn_dataset_ok.json")))
    res = run_module(cls, "username:exampleorg", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert res.source_statuses[uc.SRC_WMN]["status"] == "error"
    assert not any("example.test" in u for u in http.urls())


# --------------------------------------------------------------------------------------- self-test (FC15)
def test_selftest_rotates_records_health_and_runs_once_a_day():
    http = FakeHttp()
    add_env(http, GRAVATAR.format("automattic"), "gravatar_ok.json")
    add_env(http, CONTROL_GRAVATAR, "gravatar_not_found.json")
    ctx = make_ctx(UsernameCheck, http)
    result = uc.run_selftest(UsernameCheck, ctx, rng=random.Random(7))
    assert result.status == "ok" and result.detail.startswith("1/1 sites correct")
    assert ModuleState(uc.ENGINE_STATE).get("health")["v3lum:gravatar"]["last_verdict"] == "correct"
    calls = len(http.calls)
    again = uc.run_selftest(UsernameCheck, make_ctx(UsernameCheck, http), rng=random.Random(7))
    assert again.status == "ok" and "cached" in again.detail and len(http.calls) == calls


def test_selftest_disables_a_site_whose_control_is_found():
    http = FakeHttp()
    add_env(http, GRAVATAR.format("automattic"), "gravatar_ok.json")
    add_env(http, CONTROL_GRAVATAR, "gravatar_ok.json")
    result = uc.run_selftest(UsernameCheck, make_ctx(UsernameCheck, http), rng=random.Random(3))
    assert result.status == "dead" and "disabled: v3lum:gravatar" in result.detail
    record = ModuleState(uc.ENGINE_STATE).get("health")["v3lum:gravatar"]
    assert record["disabled"] and record["last_verdict"] == "false_positive"


def test_health_rules_and_rotation():
    rec = uc.health_update({}, "false_positive")
    assert rec["disabled"] and rec["reason"] == "self-test false_positive"
    assert not uc.health_update(rec, "correct")["disabled"]
    assert not uc.health_update({}, "unknown")["disabled"]  # could not verify is never a failure
    assert uc.health_update({"strikes": 2}, "", strikes=1)["disabled"]
    ids = [f"s{i:03d}" for i in range(60)]
    days = [uc.doctor_rotation(ids, d) for d in range(3)]
    assert all(len(d) == 25 for d in days) and set(days[0]).isdisjoint(days[1])
    assert uc.doctor_rotation(ids[:5], 9) == sorted(ids[:5])


# ------------------------------------------------------------------------------------ parsers and filters
def test_wmn_dataset_parse_and_download_failures():
    parsed = uc.parse_wmn_dataset(json.dumps(env("wmn_dataset_ok.json")))
    assert parsed["ok"] and len(parsed["sites"]) >= 30
    gravatar = next(s for s in parsed["sites"] if s["name"] == "Gravatar")
    assert gravatar["check_type"] == "markers" and gravatar["host"] == "en.gravatar.com"
    assert uc.parse_wmn_dataset(text("dataset_not_found.txt"))["error"] == "download answered '404: Not Found'"
    assert "malformed JSON" in uc.parse_wmn_dataset(text("wmn_dataset_malformed.txt"))["error"]
    assert uc.parse_wmn_dataset("<!DOCTYPE html><html><body>oops</body></html>")["error"] == "HTML page instead of dataset"


def test_sherlock_regexes_exclusions_and_nested_quantifiers():
    manifest = uc.parse_sherlock_manifest(json.dumps(env("sherlock_manifest_ok.json")))
    assert manifest["ok"] and "$v3lum_fixture" not in manifest["sites"]
    regexes = uc.sherlock_username_regexes(manifest)["by_host"]
    assert regexes["en.gravatar.com"] == "^((?!\\.).)*$" and "dribbble.com" in regexes
    excl = uc.parse_sherlock_exclusions(text("sherlock_exclusions_ok.txt"))
    assert excl["ok"] and "Linktree" in excl["names"]
    assert "linktr.ee" in uc.sherlock_excluded_hosts(excl["names"], manifest)["hosts"]
    assert uc.parse_sherlock_exclusions(text("dataset_not_found.txt"))["ok"] is False
    assert uc.has_nested_quantifier("^(-?[a-z]+)+$") and uc.has_nested_quantifier("(x{2,})*")
    assert not uc.has_nested_quantifier("^[a-zA-Z][a-zA-Z0-9_-]*$") and not uc.has_nested_quantifier("^((?!\\.).)*$")
    assert uc.safe_regex("(a+)+$") is None and uc.safe_regex("[") is None


def test_rule2_lint_drops_the_named_oracle_fixtures_and_logs_them():
    """FC6: X username_available, Discord username-attempt-unauthed, Fiverr validate_username, Roblox
    usernames/validate, Steemit and Pikabu sign-up are dropped by the lint."""
    oracles = env("lint_oracles.json")
    wmn = {s["name"]: uc.normalise_wmn_site(s) for s in oracles["wmn"]}
    for name in ("X", "Discord (User)", "Fiverr", "Roblox", "Steemit", "Pikabu", "Quizlet", "WordPress.org (Profiles)", "Minds", "lichess.org", "TryHackMe"):
        assert uc.oracle_lint(wmn[name]), name
    mg = {n: uc.normalise_maigret_site(n, s) for n, s in oracles["maigret"].items()}
    for name in ("Discord", "ProtonMail", "Omg.lol", "Diskusjon.no", "Kvinneguiden", "partner-login.altaitechnologies.com"):
        assert uc.oracle_lint(mg[name]), name
    for name, entry in oracles["sherlock"].items():
        assert forbidden_probe(entry["urlProbe"]) or uc.oracle_lint({"check_url": entry["urlProbe"]}), name
    log = uc.build_selection(overlay=uc.load_overlay(), wmn=json.dumps({"license": [], "sites": oracles["wmn"]}))["build_log"]
    assert {"wmn:X", "wmn:Discord (User)", "wmn:Fiverr", "wmn:Roblox", "wmn:Steemit", "wmn:Pikabu"} <= set(log["lint_dropped"])


def test_rule2_lint_keeps_plain_profile_endpoints():
    """Lookalikes that are no oracle stay (Wayback availability API, npm registry, 500px registeredAt,
    Vimeo available_for_hire, hosts 451unavailable/loginid); the shared P327 table drops two more
    conservatively (MediaWiki usprop=registration, a '?login=' parameter): dropped, never queried."""
    clean = env("lint_clean.json")
    for entry in clean["wmn"]:
        site = uc.normalise_wmn_site(entry)
        assert site is not None and not uc.oracle_lint(site), entry["name"]
    mg = {n: uc.normalise_maigret_site(n, s) for n, s in clean["maigret"].items()}
    for name in ("NPM", "500px", "Vimeo", "Archive.orgTwitterProfiles"):
        assert uc.oracle_lint(mg[name]) is None, name
    for name in ("wiki.subnautica.com", "Fotka"):
        assert uc.oracle_lint(mg[name]) == "oracle:LINT-03 (url)", name
    for url in ("https://wiki.451unavailable.org.uk/index.php?title=User:{username}", "https://forum.loginid.dev/u/{username}"):
        assert uc.oracle_lint({"check_url": url}) is None, url
    for site in overlay_defs().values():
        assert uc.oracle_lint(site) is None, site["id"]


def test_legal_floor_platforms_and_sensitive_categories():
    mg = maigret_sites()
    assert any("activation" in r for r in uc.legal_floor_reasons(mg["Twitter"]))
    assert any("anti-bot protection" in r for r in uc.legal_floor_reasons(mg["MercadoLivre"]))
    assert any("Tor/I2P" in r for r in uc.legal_floor_reasons(mg["HiddenAnswers"]))
    assert any("HudsonRock" in r for r in uc.legal_floor_reasons(mg["Hudson Rock"]))
    wmn = wmn_sites()
    assert any("only GET" in r for r in uc.legal_floor_reasons(wmn["Discord (User)"]))
    assert any("credential query:api_key" in r for r in uc.legal_floor_reasons(wmn["Disqus"]))
    assert uc.excluded_platform_reason(wmn["GitHub (User)"]) == "excluded platform: P111 github_user"
    assert "P105" in uc.excluded_platform_reason(wmn["Fosstodon.org (Mastodon Instance)"])
    assert "YouTube" in uc.excluded_platform_reason(wmn["YouTube User2"])
    assert "FC16 page wrapped" in uc.excluded_platform_reason(wmn["Twitter archived profile"])
    assert "nsfw" in uc.sensitive_reasons(wmn["AdmireMe.VIP"]) and "nsfw" in uc.sensitive_reasons(mg["RoyalCams"])
    assert "sensitive:dating" in uc.sensitive_reasons(wmn["FriendFinder-X"])
    assert "sensitive:health" in uc.sensitive_reasons(wmn["PatientsLikeMe"])
    assert "sensitive:religion" in uc.sensitive_reasons(mg["Bible.com"])
    assert uc.sensitive_reasons(wmn["FriendFinder-X"], nsfw_sites=True, sensitive_sites=True) == []


def test_no_oracle_or_forbidden_entry_remains_in_either_pack():
    """FC7 (A5 rule 2): every site of both bundled selection lists passes the lint and the legal floor."""
    defs = overlay_defs()
    for pack in ("username_check", "username_check_extended"):
        for sid in uc.pack_site_ids(pack):
            site = defs[sid]
            assert uc.oracle_lint(site) is None and uc.legal_floor_reasons(site) == [], sid
            assert uc.excluded_platform_reason(site) is None and uc.sensitive_reasons(site) == [], sid
            assert forbidden_probe(site["check_url"]) is None, sid


def test_build_selection_from_recorded_datasets():
    packs = uc.build_selection(
        overlay=uc.load_overlay(), wmn=json.dumps(env("wmn_dataset_ok.json")),
        maigret=json.dumps(module_fixture("username_check_extended", "maigret_db_ok.json")),
        sherlock=json.dumps(env("sherlock_manifest_ok.json")), exclusions=text("sherlock_exclusions_ok.txt"),
    )
    assert packs["packs"]["username_check"]["site_ids"] == ["v3lum:gravatar"]
    assert packs["packs"]["username_check_extended"]["site_ids"] == ["v3lum:aboutme", "v3lum:dribbble", "v3lum:kaggle"]
    assert set(packs["datasets"]) == {"wmn", "maigret", "sherlock", "sherlock_exclusions"}
    reasons = packs["build_log"]["not_selected"]
    assert reasons.get("FC8: tier unknown") and reasons.get("excluded platform: P111 github_user")
    # the bundled selection lists were built the same way (site ids + dataset SHA-256, no merged data)
    bundled = json.loads((datasets_mod.DataStore.bundled_path(uc.PACKS_FILE)).read_text(encoding="utf-8"))
    assert bundled["datasets"]["wmn"]["sha256"] == uc.WMN_SHA256
    assert set(bundled["packs"]) == {"username_check", "username_check_extended"}
    assert all(set(spec) == {"site_ids"} for spec in bundled["packs"].values())


def test_two_sided_markers_and_probe_rendering():
    defs = overlay_defs()
    assert all(uc.two_sided_markers(site) for site in defs.values())
    wmn = wmn_sites()
    assert not uc.two_sided_markers(wmn["35photo"])  # WhatsMyName entry without an absence string (FC2)
    probe = uc.render_probe(defs["v3lum:gravatar"], "@ExampleOrg")
    assert probe["ok"] and probe["url"] == "https://en.gravatar.com/ExampleOrg.json" and probe["profile_url"] == "https://gravatar.com/ExampleOrg"
    assert uc.render_probe(defs["v3lum:gravatar"], "a/b") == {"ok": False, "reason": "handle syntax"}
    assert uc.render_probe(defs["v3lum:dribbble"], "9lives", extra_regex="^[a-zA-Z][a-zA-Z0-9_-]*$")["reason"] == "site username syntax"
    assert uc.render_probe(wmn["Discord (User)"], "exampleorg")["reason"] == "legal floor: only GET"
    mg = maigret_sites()
    assert uc.render_probe(mg["Gravatar"], "exampleorg")["url"] == "https://en.gravatar.com/exampleorg.json"  # http -> https
    control = uc.control_probe(defs["v3lum:gravatar"], random.Random(1))
    assert control["ok"] and re.fullmatch(r"[a-z][a-z0-9]{19}", control["handle"])


@pytest.mark.parametrize(
    ("sid", "ok_case", "nf_case", "handle"),
    [
        ("v3lum:gravatar", "gravatar_ok.json", "gravatar_not_found.json", "automattic"),
        ("v3lum:dribbble", "dribbble_ok.json", "dribbble_not_found.json", "dribbble"),
        ("v3lum:aboutme", "aboutme_ok.json", "aboutme_not_found.json", "microsoft"),
        ("v3lum:kaggle", "kaggle_ok.json", "kaggle_not_found.json", "kaggleteam"),
    ],
)
def test_v3lum_measured_markers_on_recorded_answers(sid, ok_case, nf_case, handle):
    site = overlay_defs()[sid]
    assert ev(site, ok_case, handle)["state"] == FOUND
    assert ev(site, nf_case)["state"] == ABSENT


def test_evaluation_edge_cases():
    defs = overlay_defs()
    assert ev(defs["v3lum:aboutme"], "aboutme_redirect.json")["reason"] == "redirect"  # 302 /team, not followed
    kaggle_404 = ev(defs["v3lum:kaggle"], "kaggle_not_found.json")
    assert kaggle_404["state"] == ABSENT  # reCAPTCHA words on a 404 are not a block
    wmn = wmn_sites()
    assert ev(wmn["Pinterest"], "pinterest_marker_drift.json")["state"] == UNKNOWN
    assert ev(wmn["TikTok"], "tiktok_ok.json")["state"] == FOUND and ev(wmn["TikTok"], "tiktok_not_found.json")["state"] == ABSENT
    both = dict(defs["v3lum:gravatar"], absence={"status": 200, "strings": ["automattic"]})
    assert ev(both, "gravatar_ok.json")["reason"] == "both_markers"
    assert uc.evaluate_response(defs["v3lum:gravatar"], 429, {}, "")["stop_host"]
    assert uc.evaluate_response(defs["v3lum:gravatar"], 500, {}, "")["reason"] == "server_error"
    assert uc.evaluate_response(defs["v3lum:gravatar"], None, error="ReadTimeout: timed out")["reason"] == "timeout"
    truncated = uc.evaluate_response(defs["v3lum:gravatar"], 200, {}, '{"entry":', truncated=True)
    assert truncated["state"] == UNKNOWN and truncated["reason"] == "truncated"


def test_maigret_check_types():
    mg = maigret_sites()
    msg = mg["Alura"]
    assert uc.evaluate_response(msg, 200, {}, msg["presence"]["strings"][0] if msg["presence"]["strings"] else "exampleorg", username="exampleorg")["state"] == FOUND
    status_site = mg["Filmow"]
    assert uc.evaluate_response(status_site, 200, {}, "<html>profile</html>")["state"] == FOUND
    assert uc.evaluate_response(status_site, 404, {}, "")["state"] == ABSENT
    resp_url = mg["MicrosoftLearn"]
    assert uc.evaluate_response(resp_url, 302, {"location": "/en-us/"}, "")["state"] == ABSENT
    assert uc.evaluate_response(resp_url, 403, {}, "")["state"] == UNKNOWN


def test_control_folding_and_output_helpers():
    found = {"state": FOUND, "reason": None}
    assert uc.apply_control(found, {"state": ABSENT})["control"] == "absent"
    assert uc.apply_control(found, {"state": FOUND})["reason"] == "control_found"
    assert uc.apply_control(found, None)["control"] == "unverified"
    results = [{"state": UNKNOWN, "reason": r} for r in ("challenge",) * 22 + ("timeout",) * 3] + [{"state": FOUND}, {"state": ABSENT}]
    assert uc.unknown_breakdown(results) == "22 blocked/WAF, 3 timeouts"
    assert uc.counts_line("username_check", results, 2) == "username_check: 1 found · 25 could not verify · 1 absent · 2 not checked: budget"
    assert uc.found_rows([{"state": FOUND, "name": "Gravatar", "profile_url": "https://gravatar.com/x", "display_name": "X"}]) == [
        {"site": "Gravatar", "url": "https://gravatar.com/x", "display_name": "X"}]
    assert uc.hit_confidence(())["confidence"] == "possible"
    assert uc.hit_confidence(["bio_link_known_entity"])["confidence"] == "probable"
    assert uc.hit_confidence((), "common username")["severity_cap"] == "info"
    assert uc.calibration_verdict({"state": FOUND}, {"state": ABSENT}) == "correct"
    assert uc.calibration_verdict({"state": FOUND}, {"state": FOUND}) == "false_positive"
    assert uc.calibration_verdict({"state": ABSENT}, None) == "stale_fixture"
    assert uc.extract_display_name(env("aboutme_ok.json")["body"], "microsoft") == ""
    assert uc.extract_display_name(env("kaggle_ok.json")["body"], "kaggleteam") == "Kaggle Team Bot"
    assert uc.extract_display_name(env("dribbble_ok.json")["body"], "someone") == "Dribbble"
    assert uc.clean_display_name("Microsoft on about.me") == "Microsoft"


def test_run_gate_rules():
    assert uc.pack_run_gate(is_seed=False)
    assert uc.pack_run_gate(is_seed=True, provenance=[("text:abc", "mentions", "ioc_extract")])
    assert uc.pack_run_gate(is_seed=True, entity_key="username:x", unconfirmed={"username:x"})
    assert uc.pack_run_gate(is_seed=True, entity_key="username:x") is None


def test_defensive_inputs_never_raise():
    junk = [None, 1, 1.5, True, "", "x", b"\xff\xfe", [], {}, [1, 2], {"sites": "x"}, {"sites": [None, 1, {"name": 3}]}]
    for value in junk:
        for fn in (uc.parse_wmn_dataset, uc.parse_maigret_db, uc.parse_maigret_db_meta, uc.parse_sherlock_manifest, uc.parse_sherlock_exclusions, uc.parse_overlay):
            assert isinstance(fn(value), dict)
        assert uc.oracle_lint(value) is None or isinstance(uc.oracle_lint(value), str)
        assert isinstance(uc.legal_floor_reasons(value), list) and isinstance(uc.pack_filter_reasons(value), list)
        assert isinstance(uc.render_probe(value, value), dict)
        assert uc.evaluate_response(value, value, value, value)["state"] == UNKNOWN
        assert isinstance(uc.extract_display_name(value), str)


class _SlowHttp(FakeHttp):
    """FakeHttp whose site answers take a little real time, to observe the scheduler's overlap."""

    def __init__(self) -> None:
        super().__init__()
        import threading

        self.lock = threading.Lock()
        self.in_flight: dict[str, int] = {}
        self.max_total = 0
        self.max_per_host = 0

    def send(self, method: str, url: str, **kw: Any) -> Any:
        import time
        from urllib.parse import urlsplit

        host = urlsplit(url).hostname or ""
        if not host.endswith(".example.test"):
            return super().send(method, url, **kw)
        with self.lock:
            self.in_flight[host] = self.in_flight.get(host, 0) + 1
            self.max_total = max(self.max_total, sum(self.in_flight.values()))
            self.max_per_host = max(self.max_per_host, self.in_flight[host])
        try:
            time.sleep(0.02)
            return super().send(method, url, **kw)
        finally:
            with self.lock:
                self.in_flight[host] -= 1


def test_global_concurrency_is_bounded_and_one_request_per_host(pack_module):
    """FC9: at most 8 requests in flight across the pack, one per host (claimed then control)."""
    cls = pack_module(12)
    http = add_sherlock(_SlowHttp())
    for i in range(1, 13):
        _route_site(http, i, "exampleorg", "gravatar_ok.json")
    res = run_module(cls, "username:exampleorg", http)
    assert res.raw["counts"]["found"] == 12
    assert 1 < http.max_total <= uc.MAX_CONCURRENCY
    assert http.max_per_host == 1
    controls = [e for e in res.raw["sites"] if e["control"]]
    claimed = {e["url"].split("/")[2]: e["checked_at"] for e in res.raw["sites"] if not e["control"]}
    assert len(controls) == 12 and all(c["checked_at"] >= claimed[c["url"].split("/")[2]] for c in controls)


def test_control_waits_at_least_min_interval_on_the_same_host():
    """FC9: >= 1 s between two requests to one host (the HttpClient limiter, fake clock)."""
    from datetime import datetime

    res, _ = gravatar_found_run()
    claimed, control = (datetime.fromisoformat(e["checked_at"].replace("Z", "+00:00")) for e in site_evidence(res))
    assert (control - claimed).total_seconds() >= 1.0
