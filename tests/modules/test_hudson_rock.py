"""hudson_rock (P134): infostealer exposure METADATA for own identities, allowlist-sanitized.

Fixtures in tests/fixtures/hudson_rock/ keep the real metadata of live answers (dates, counts,
families; 2026-11-26) and carry SYNTHETIC values in every victim field (computer name, Windows
user path, masked IP, masked passwords/logins, antivirus, OS) plus an unknown future field, so the
tests prove that the allowlist drops them before the cache, evidence, logs, case DB, reports and
events (P134 cond 1-3 and 10, A4 BR13).
"""

from __future__ import annotations

import copy
import json
import logging

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.context import ScanOptions
from v3lum.core.engine import CaseResult
from v3lum.core.evidence import EvidenceStore
from v3lum.core.graph import Graph
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.store import Store
from v3lum.modules.breach_leak.hudson_rock import NEXT_STEPS, HudsonRock, strip_url
from v3lum.report import write_reports

MOD = HudsonRock
API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
EMAIL = API + "search-by-email?email={}"
USERNAME = API + "search-by-username?username={}"
IP = API + "search-by-ip?ip={}"
CHALLENGE = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
ORG = {"domains": [{"name": "acme.com.br", "verification": "txt_verified"}, {"name": "seeded-corp.com.br", "verification": "seeded"}], "cidrs": ["192.0.2.0/24"]}
#: victim values of the synthetic fixtures: none may survive anywhere (A4 BR13)
DROPPED_VALUES = (
    "DESKTOP-V3LUMFX", "fixture-user", "192.0.2.**", "f*********1", "v******e", "t***@example.com", "f*********r",
    "v3lum-fixture.exe", "Fixture Antivirus", "Windows 10 Pro x64", "schema drift must not leak", "future_field_v3lum_test",
    "is associated with a computer",
)
DROPPED_KEYS = ("top_passwords", "top_logins", "computer_name", "malware_path", "antiviruses", "operating_system", "message", "future_field_v3lum_test")


def fx(name):
    return module_fixture(MOD, name)


def org():
    return OrgProfile.from_dict(ORG)


def own_body(n=2, date=None, corp=None):
    body = copy.deepcopy(fx("email_generic.json"))
    body["stealers"] = body["stealers"][:n]
    for s in body["stealers"]:
        if date:
            s["date_compromised"] = date
        if corp is not None:
            s["total_corporate_services"] = corp
    return body


def scope_all():
    return ScanOptions(breach_scope="all", purpose="incident 2026-11 phishing triage")


def blob(*items):
    return json.dumps(items, default=lambda o: o.to_dict() if hasattr(o, "to_dict") else str(o))


# ------------------------------------------------------------------ own identities (C7, C8, C9)
def test_recent_own_identity_is_critical_with_next_steps():
    http = FakeHttp().add("GET", EMAIL.format("analyst%40acme.com.br"), json=own_body())
    res = run_module(MOD, "email:analyst@acme.com.br", http, org_profile=org())
    assert res.status is Status.OK
    assert res.attributes["infostealer"] is True and len(res.attributes["stealer_logs"]) == 2
    finding = res.findings[0]
    assert finding.severity.label == "critical" and finding.label.value == "probable"
    assert {"infostealer", "credential_exposure"} <= set(finding.tags)
    assert "2026-11-25" in finding.description and finding.observed_first.startswith("2026-11-25")
    assert finding.data["next_steps"] == list(NEXT_STEPS) and "never used for login attempts" in finding.description
    assert finding.source == "hudsonrock.search_by_email"
    http.assert_hosts_within(MOD)


def test_older_logs_high_with_corporate_services_else_medium():
    old_corp = run_module(MOD, "email:analyst@acme.com.br", FakeHttp().add("GET", EMAIL.format("analyst%40acme.com.br"), json=own_body(1, "2023-01-02T00:00:00.000Z", 3)), org_profile=org())
    assert old_corp.findings[0].severity.label == "high" and "verify rotation" in old_corp.findings[0].description
    old = run_module(MOD, "email:analyst@acme.com.br", FakeHttp().add("GET", EMAIL.format("analyst%40acme.com.br"), json=own_body(1, "2023-01-02T00:00:00.000Z", 0)), org_profile=org())
    assert old.findings[0].severity.label == "medium" and "historical exposure, verify rotation" in old.findings[0].description
    assert "2023-01-02" in old.findings[0].description  # the date is shown


def test_generic_address_is_flagged_never_scored():
    """test@example.com answered 5 computers live: >= 5 computers or an A4 role address = generic (C6)."""
    http = FakeHttp().add("GET", EMAIL.format("analyst%40acme.com.br"), json=fx("email_generic.json"))
    res = run_module(MOD, "email:analyst@acme.com.br", http, org_profile=org())
    assert res.attributes["generic_address"].startswith("shared")
    assert [f.title for f in res.findings] == ["Generic address in infostealer logs"]
    generic = res.findings[0]
    assert generic.severity.label == "info" and generic.label.value == "possible" and "context_only" in generic.tags
    role = run_module(MOD, "email:info@acme.com.br", FakeHttp().add("GET", EMAIL.format("info%40acme.com.br"), json=own_body(1)), org_profile=org())
    assert role.attributes["generic_address"] == "role" and role.findings[0].severity.label == "info"


# ------------------------------------------------------------------ privacy and scope (A4, C7)
def test_third_party_addresses_are_skipped_without_breach_scope_all():
    http = FakeHttp()
    res = run_module(MOD, "email:jdoe@other-corp.com.br", http, org_profile=org())
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "not an org domain" in res.error
    seeded = run_module(MOD, "email:analyst@seeded-corp.com.br", http, org_profile=org())  # seeded != verified
    assert seeded.status is Status.SKIPPED and seeded.reason_code == "privacy"
    pivot = run_module(MOD, "email:jdoe@other-corp.com.br", http, options=scope_all(), is_seed=False, depth=1)
    assert pivot.status is Status.SKIPPED  # never for pivots
    assert http.calls == []


def test_third_party_seed_with_breach_scope_all_is_context_at_most_medium():
    http = FakeHttp().add("GET", EMAIL.format("jdoe%40other-corp.com.br"), json=own_body(2, corp=7))
    res = run_module(MOD, "email:jdoe@other-corp.com.br", http, options=scope_all())
    assert res.status is Status.OK
    assert all(f.severity.label in ("low", "medium") for f in res.findings)
    assert all("context_only" in f.tags and "credential_exposure" not in f.tags for f in res.findings)
    assert all(f.label.value == "possible" for f in res.findings)


def test_username_only_as_typed_seed_and_families():
    http = FakeHttp().add("GET", USERNAME.format("fixtureuser"), json=fx("username_ok.json"))
    assert run_module(MOD, "username:fixtureuser", http).status is Status.SKIPPED
    res = run_module(MOD, "username:fixtureuser", http, options=scope_all())
    assert res.status is Status.OK and res.attributes["malware_family"] == ["Generic Stealer"]
    assert all("context_only" in f.tags for f in res.findings)


def test_username_not_found_is_empty():
    http = FakeHttp().add("GET", USERNAME.format("cleanhandle"), json=fx("username_not_found.json"))
    res = run_module(MOD, "username:cleanhandle", http, options=scope_all())
    assert res.status is Status.EMPTY and not res.findings


def test_ip_only_inside_org_cidrs():
    http = FakeHttp().add("GET", IP.format("192.0.2.10"), json=fx("ip_ok.json"))
    res = run_module(MOD, "ipv4:192.0.2.10", http, org_profile=org())
    assert res.status is Status.OK and res.findings[0].severity.label == "medium"  # 2020 log, no corporate services
    outside = run_module(MOD, "ipv4:198.51.100.7", FakeHttp(), org_profile=org(), options=scope_all())
    assert outside.status is Status.SKIPPED and outside.reason_code == "own_asset"


# ------------------------------------------------------------------ sanitizer allowlist (C1, C2, C3, C10)
def test_allowlist_drops_every_victim_field_and_new_fields():
    http = FakeHttp().add("GET", EMAIL.format("analyst%40acme.com.br"), json=own_body(3))
    res = run_module(MOD, "email:analyst@acme.com.br", http, org_profile=org())
    for record in res.raw["hudsonrock.search_by_email"]["stealers"]:
        assert set(record) <= {"date_compromised", "stealer_family", "total_corporate_services", "total_user_services"}
    text = blob(res.raw, res.attributes, res.findings, res.pivots, res.links, res.error)
    for value in DROPPED_VALUES:
        assert value not in text, value
    for key in DROPPED_KEYS:
        assert f'"{key}"' not in text, key


def test_a4_br13_grep_cache_evidence_case_reports_events_and_debug(tmp_path, caplog):
    """End-to-end A4 BR13 grep over the synthetic fixtures: nothing dropped reaches the HTTP cache,
    evidence, the case DB, any report or export format, the event stream or --debug logging."""
    caplog.set_level(logging.DEBUG)
    events: list[tuple[str, dict]] = []
    http = FakeHttp().add("GET", EMAIL.format("analyst%40acme.com.br"), json=fx("email_generic.json")).add("GET", USERNAME.format("fixtureuser"), json=fx("username_ok.json"))
    rt = make_runtime(http, org_profile=org(), cache=True)
    rt.events.subscribe(lambda kind, payload: events.append((kind, payload)))
    results = [
        run_module(MOD, "email:analyst@acme.com.br", runtime=rt),
        run_module(MOD, "username:fixtureuser", runtime=rt, options=scope_all()),
    ]
    assert all(r.status is Status.OK for r in results)
    again = run_module(MOD, "email:analyst@acme.com.br", runtime=rt)  # served from the sanitized cache
    assert again.status is Status.OK and again.cache_hits == 1
    case_dir = tmp_path / "case"
    store = EvidenceStore(case_dir)
    graph = Graph()
    for res in results:
        res.evidence, res.evidence_sha256 = store.save(res)
        graph.add_node(res.entity, seed=True)
        graph.add_attributes(res.entity, res.attributes, res.module)
        for finding in res.findings:
            graph.add_finding(finding)
    case = CaseResult(case_id="t-hudson-rock", created="2026-11-26T12:00:00Z", seeds=[r.entity for r in results], options=ScanOptions(), graph=graph, results=results)
    case_dict = case.to_dict()
    write_reports(case_dict, ["html", "md", "json", "stix"], tmp_path / "reports")
    Store(paths.home() / "v3lum.db").save_case(case_dict)
    haystack = [paths.home(), tmp_path, blob(events), caplog.text]
    for value in DROPPED_VALUES:
        for item in haystack:
            data = item if isinstance(item, str) else "\n".join(
                p.read_bytes().decode("utf-8", errors="replace") for p in item.rglob("*") if p.is_file()
            )
            assert value not in data, f"{value!r} leaked into {item if isinstance(item, str) and len(item) < 80 else type(item).__name__}"


# ------------------------------------------------------------------ rule 5 (C10)
def test_timeout_is_error_timeout_never_absent():
    timeout = NetworkError("read timed out after 30 s", kind="ReadTimeout", reason_code="timeout", retryable=False)
    http = FakeHttp().add("GET", EMAIL.format("analyst%40acme.com.br"), error=timeout)
    res = run_module(MOD, "email:analyst@acme.com.br", http, org_profile=org())
    assert res.status is Status.ERROR and res.reason_code == "timeout" and not res.findings
    assert http.calls[0]["timeout"] is not None and http.calls[0]["timeout"] <= 30.0


def test_refusals_and_odd_answers_are_could_not_verify():
    def run(**route):
        http = FakeHttp().add("GET", EMAIL.format("analyst%40acme.com.br"), **route)
        return run_module(MOD, "email:analyst@acme.com.br", http, org_profile=org())

    assert run(status=429, text="Too Many Requests").status is Status.RATE_LIMITED
    assert run(status=403, text=CHALLENGE).status is Status.BLOCKED
    assert run(status=200, text=CHALLENGE).status is Status.BLOCKED
    assert run(status=502, text="bad gateway").status is Status.ERROR
    malformed = run(body=(paths_fixture("malformed.json")), headers={"content-type": "application/json"})
    assert malformed.status is Status.ERROR
    error_in_200 = run(json={"error": "Something went wrong"})
    assert error_in_200.status is Status.ERROR and not error_in_200.attributes
    limited_in_200 = run(json={"message": "Too many requests, slow down"})
    assert limited_in_200.status is Status.RATE_LIMITED
    no_list = run(json={"total_corporate_services": 0})
    assert no_list.status is Status.ERROR and "could not verify" in no_list.error


def paths_fixture(name):
    from tests.fakes import FIXTURES

    return (FIXTURES / "hudson_rock" / name).read_bytes()


def test_strip_url_for_attack_surface():
    assert strip_url("https://sso.example.org/login?username=x&session=AbC123xYz789QwE456#frag") == "https://sso.example.org/login"
    assert strip_url("https://user:pw@ftp.example.org/files/report.pdf") == "https://ftp.example.org/files/report.pdf"
    assert strip_url("https://gitlab.example.org/users/jdoe/emails") == "https://gitlab.example.org/users/{redacted}/emails"
    assert strip_url("https://portal.example.org/password_reset/Zk9xQ2V4YW1wbGVUb2tlbjEyMzQ1Njc4OTA") == "https://portal.example.org/password_reset/{redacted}"
    assert strip_url("https://example.org/~jdoe/index.html") == "https://example.org/{redacted}/index.html"
    assert strip_url("javascript:alert(1)") is None and strip_url(None) is None


def test_metadata_matches_the_council_decision():
    assert MOD.default_enabled is False and MOD.terms == "unknown" and MOD.trust_tier == "community"
    assert MOD.run_on == "own_assets" and MOD.sensitive is True and MOD.cache_ttl <= 7 * 86400
    assert MOD.notice.startswith("licence: terms unknown")
