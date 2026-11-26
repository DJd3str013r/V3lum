"""P145 complete (WP09): golden tests over trimmed Hudson Rock, LeakCheck, XposedOrNot and HIBP fixtures,
an exposed .env sample and a MalwareBazaar answer (tests/fixtures/breach/, tests/fixtures/malware/;
synthetic personal data), the cache hook through HttpClient, the fail-closed engine stage, value
detectors, secrets, the password FORM and scrub_text."""

from __future__ import annotations

import copy
import hashlib
import json
import time
from pathlib import Path
from urllib.parse import quote

import pytest

from tests.fakes import FIXTURES, FakeHttp, allow_vocab, assert_no_secret, define_module, make_runtime, run_module, source_ids, test_provider
from v3lum import paths
from v3lum.core import redact, sanitize
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity, parse_fingerprint, secret_preview
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Pivot, Status
from v3lum.core.store import Store
from v3lum.report import write_reports
from v3lum.core.sanitize import (
    HASH_EXEMPT_CATEGORIES,
    SECOND_NET_FIELDS,
    SECRET_PATTERNS,
    find_secrets,
    is_password_form,
    normalize_password_form,
    sanitize_body,
    sanitize_result,
    scrub_text,
)

BREACH = FIXTURES / "breach"
MALWARE = FIXTURES / "malware"
HOST = "breach.example.test"
URL = f"https://{HOST}/v1/lookup?q=someone%40example.com"
EMAIL = "someone@example.com"
TEST_VOCAB = ["password_form", "t_payload", "t_secret", "t_env", "breaches_seen"]

# ------------------------------------------------------------------ golden cases (fixture, schema, leaks, expected sanitized body)
HR_KEEP = [
    "stealers[].date_compromised", "stealers[].stealer_family", "stealers[].total_corporate_services",
    "stealers[].total_user_services", "stealers[].operating_system", "total_corporate_services", "total_user_services",
]
HR_LEAKS = [
    "SYNTH-PC-0042", "DESKTOP-SYN7Q2X", "203.0.113.77", "198.51.100.23", "synthetic-loader.exe", "Synthetic Owner",
    "SynthSetup.exe", "synthuser", "S*******9", "q*****y", "s******r@example.com", "synth***", "h*****2", "s*****r",
]
HR_KEPT = {
    "stealers": [
        {"total_corporate_services": 3, "total_user_services": 41, "date_compromised": "2026-10-02T00:00:00.000Z",
         "stealer_family": "RedLine", "operating_system": "Windows 10 Pro"},
        {"total_corporate_services": 0, "total_user_services": 12, "date_compromised": "2024-05-26T17:37:44.000Z",
         "stealer_family": "StealC", "operating_system": "Windows 11 Home"},
    ],
    "total_corporate_services": 3,
    "total_user_services": 53,
}
LC_KEEP = ["found", "fields", "sources[].name", "sources[].date"]
LC_KEPT = {
    "found": 3,
    "fields": ["username", "password", "ip", "dob", "phone", "address"],  # data classes are metadata
    "sources": [{"name": "SynthForum.example", "date": "2019-07"}, {"name": "Collection 1", "date": "2019-01"},
                {"name": "Stealer Logs", "date": ""}],
}
LC2_KEEP = ["found", "result[].source.name", "result[].source.breach_date", "result[].source.compilation", "result[].fields"]
LC2_LEAKS = ["Synth3tic!Pass", "5f4dcc3b5aa765d61d8327deb882cf99", "someone@example.com:Synth3tic!Pass", "synth_user_42"]
LC2_KEPT = {
    "found": 2,
    "result": [
        {"source": {"name": "SynthForum.example", "breach_date": "2019-07", "compilation": 0}, "fields": ["first_name", "last_name", "username", "password"]},
        {"source": {"name": "Collection 1", "breach_date": "2019-01", "compilation": 1}, "fields": ["password"]},
    ],
}
XON_KEEP = ["breaches", "status"]
XON_KEPT = {"breaches": [["Adobe", "SynthForum", "Collection-1"]], "status": "success"}
XONA_KEEP = [
    "ExposedBreaches.breaches_details[].breach", "ExposedBreaches.breaches_details[].domain",
    "ExposedBreaches.breaches_details[].verified", "ExposedBreaches.breaches_details[].xposed_data",
    "ExposedBreaches.breaches_details[].xposed_date", "ExposedBreaches.breaches_details[].xposed_records",
    "ExposedBreaches.breaches_details[].password_risk", "BreachMetrics.risk", "BreachMetrics.passwords_strength",
]
XONA_KEPT = {
    "BreachMetrics": {"risk": [{"risk_label": "Medium", "risk_score": 47}]},  # passwords_strength: second net wins over the schema
    "ExposedBreaches": {"breaches_details": [
        {"breach": "Adobe", "domain": "adobe.com", "verified": "Yes", "xposed_data": "Email addresses;Password hints;Passwords;Usernames",
         "xposed_date": "2013", "xposed_records": 152445165, "password_form": "hashed: weak"},
        {"breach": "SynthForum", "domain": "synthforum.example", "verified": "Yes", "xposed_data": "Email addresses;Passwords;IP addresses",
         "xposed_date": "2019", "xposed_records": 12345, "password_form": "plaintext"},
    ]},
}
HIBP_KEEP = ["[].Name", "[].Domain", "[].BreachDate", "[].PwnCount", "[].DataClasses", "[].IsVerified", "[].IsFabricated",
             "[].IsSpamList", "[].IsMalware", "[].IsStealerLog"]
HIBP_KEPT = [
    {"Name": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04", "PwnCount": 152445165,
     "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"], "IsVerified": True, "IsFabricated": False,
     "IsSpamList": False, "IsMalware": False, "IsStealerLog": False},
    {"Name": "SynthForum", "Domain": "synthforum.example", "BreachDate": "2019-07-12", "PwnCount": 12345,
     "DataClasses": ["Email addresses", "IP addresses", "Passwords"], "IsVerified": True, "IsFabricated": False,
     "IsSpamList": False, "IsMalware": False, "IsStealerLog": False},
]
GOLDEN = [
    pytest.param("hudsonrock_search_by_email.json", HR_KEEP, HR_LEAKS, HR_KEPT, id="hudsonrock"),
    pytest.param("leakcheck_public.json", LC_KEEP, [], LC_KEPT, id="leakcheck_public"),
    pytest.param("leakcheck_api_v2.json", LC2_KEEP, LC2_LEAKS, LC2_KEPT, id="leakcheck_v2"),
    pytest.param("xposedornot_check_email.json", XON_KEEP, [], XON_KEPT, id="xposedornot"),
    pytest.param("xposedornot_breach_analytics.json", XONA_KEEP, [], XONA_KEPT, id="xposedornot_analytics"),
    pytest.param("hibp_breachedaccount.json", HIBP_KEEP, [], HIBP_KEPT, id="hibp"),
]
ENV_LEAKS = [
    "Synth-Db-Pass-0042", "SynthRedisPw99", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "Synth Mail Pass",
    "SynthJwtSecretValue0042", "SynthApiToken-0042-abcdef", "U1lOVEhFVElDIEtFWSBGT1IgVEVTVFMgT05MWQ",
    "U3ludGhldGljQXBwS2V5Rm9yVjNMVU1UZXN0c09ubHk",
]


def _sensitive_provider(keep: list[str] | None, pid: str = "t_golden"):
    return test_provider(pid, hosts=(HOST,), sensitive=True, sources=("lookup",), sanitizer={"keep": keep} if keep else None)


def _sensitive_module(name: str, prov, run, **attrs):
    attrs.setdefault("category", "breach_leak")
    return define_module(name, [T.EMAIL, T.IPV4], run, disclosure="third_party", provider=prov.id, sources=source_ids(prov),
                         hosts=prov.hosts, access_model="free_noauth_unlimited", **attrs)


def _evidence_payload(res: ModuleResult, case_dir: Path):
    """The evidence written for ``res`` (WP08's EvidenceStore when present, else the same payload)."""
    try:
        from v3lum.core.evidence import EvidenceStore
    except ImportError:  # pragma: no cover - evidence store of another wave
        return {"module": res.module, "entity": res.entity.key, "redacted_fields": res.redacted_fields, "data": res.raw}
    EvidenceStore(case_dir).save(res)
    return case_dir


def _second_net_values(payload) -> list[str]:
    """Every string a careless module could copy out of the second-net fields of a payload."""
    out: list[str] = []

    def walk(obj, under):
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, under or sanitize.is_second_net_field(k))
        elif isinstance(obj, list):
            for v in obj:
                walk(v, under)
        elif under and isinstance(obj, str) and obj.strip() and obj not in out:
            out.append(obj)

    walk(payload, False)
    return out


def _everything(res: ModuleResult) -> list:
    return [res.to_dict(), res.raw, res.attributes, [f.to_dict() for f in res.findings], [p.to_dict() for p in res.pivots],
            res.links, res.error, res.redacted_fields]


# ------------------------------------------------------------------ golden: the HTTP cache never holds a raw sensitive body (acceptance)
@pytest.mark.parametrize(("fixture", "keep", "leaks", "kept"), GOLDEN)
def test_golden_cache_and_module_see_only_the_sanitized_body(clean_registry, fixture, keep, leaks, kept):
    body = (BREACH / fixture).read_bytes()
    seen: list = []

    def fetch(self, entity, ctx):
        res = self.result(entity)
        data = ctx.http.get_json(URL)
        seen.append(copy.deepcopy(data))
        res.raw = data
        res.attr("breach_count", 1)
        return res

    with _sensitive_provider(keep) as prov:
        cls = _sensitive_module("t_golden_fetch", prov, fetch)
        http = FakeHttp().add("GET", URL, body=body, headers={"Content-Type": "application/json; charset=utf-8"}, times=1)
        rt = make_runtime(http, cache=True)
        first = run_module(cls, f"email:{EMAIL}", http, runtime=rt)
        second = run_module(cls, f"email:{EMAIL}", http, runtime=rt)  # the route answers once: a cache hit or a test failure
    assert first.status is Status.OK and second.status is Status.OK and second.cache_hits == 1
    assert seen[0] == kept and seen[1] == kept  # the module never receives the raw body (P145 cond 7)
    assert first.raw == kept
    cache_db = paths.cache_file()
    assert cache_db.exists()
    for leak in leaks:
        assert_no_secret(leak, cache_db, first.raw, second.raw)
    assert b'"password"' not in cache_db.read_bytes()


def test_sensitive_body_without_a_schema_is_never_cached(clean_registry):
    body = (BREACH / "hudsonrock_search_by_email.json").read_bytes()
    with _sensitive_provider(None, pid="t_noschema") as prov:
        http = FakeHttp().add("GET", URL, body=body, headers={"Content-Type": "application/json"}, times=2)
        rt = make_runtime(http, cache=True)
        resp = rt.http.request("GET", URL, source=f"{prov.id}.lookup")
        assert resp.content == body  # raw in memory only (the engine sanitizer still applies)
        assert not rt.http.request("GET", URL, source=f"{prov.id}.lookup").from_cache
    for leak in HR_LEAKS:
        assert_no_secret(leak, paths.cache_file())


def test_sensitive_html_answer_is_never_cached(clean_registry):
    page = b"<html><body>DESKTOP-SYN7Q2X 203.0.113.77 S*******9</body></html>"
    with _sensitive_provider(HR_KEEP, pid="t_html") as prov:
        http = FakeHttp().add("GET", URL, body=page, headers={"Content-Type": "text/html"}, times=2)
        rt = make_runtime(http, cache=True)
        rt.http.request("GET", URL, source=f"{prov.id}.lookup")
        assert not rt.http.request("GET", URL, source=f"{prov.id}.lookup").from_cache
    for leak in ("DESKTOP-SYN7Q2X", "203.0.113.77", "S*******9"):
        assert_no_secret(leak, paths.cache_file())


# ------------------------------------------------------------------ golden: the engine stage over a careless module
@pytest.mark.parametrize(("fixture", "keep", "leaks", "kept"), GOLDEN)
def test_golden_engine_stage_drops_what_a_careless_module_copies(clean_registry, tmp_path, fixture, keep, leaks, kept):
    payload = json.loads((BREACH / fixture).read_text())

    values = _second_net_values(payload)

    def careless(self, entity, ctx):  # copies the raw provider answer everywhere (no HTTP: the cache hook is not involved)
        res = self.result(entity)
        dump = json.dumps(payload)
        res.raw = copy.deepcopy(payload)
        res.attr("t_payload", copy.deepcopy(payload))
        res.finding("Exposure reported by the provider", "medium", f"provider said {dump}", criterion=f"copied: {dump[:3000]}",
                    data={"payload": copy.deepcopy(payload), "text": dump, "values": values})
        for value in values:  # a careless module pivots on the stealer IP, the computer name, the login...
            res.pivot(T.IPV4 if value.count(".") == 3 and value.replace(".", "").isdigit() else T.KEYWORD, value, "mentions",
                      expand=False, note=f"value {value}")
        if values:
            res.link(f"follow {values[0]}", "https://www.example.com/search?q=" + quote(values[0]))
            res.error = f"partial: {'; '.join(values)}"
        return res

    with _sensitive_provider(keep) as prov, allow_vocab(attributes=TEST_VOCAB):
        cls = _sensitive_module("t_golden_careless", prov, careless)
        res = run_module(cls, f"email:{EMAIL}", FakeHttp())
    assert res.status is Status.OK
    assert res.raw == kept
    assert res.redacted_fields
    evidence = _evidence_payload(res, tmp_path / "case")
    for leak in leaks:
        assert_no_secret(leak, *_everything(res), evidence)


@pytest.mark.parametrize(("fixture", "keep", "leaks", "kept"), GOLDEN)
def test_golden_grep_over_case_db_evidence_reports_and_events(clean_registry, tmp_path, fixture, keep, leaks, kept):
    """P145 cond 10: a full scan with a careless module, then a grep of the case DB, the evidence, every
    report format (HTML, Markdown, JSON, STIX), the events and the whole V3LUM home finds no leak."""
    payload = json.loads((BREACH / fixture).read_text())
    values = _second_net_values(payload)

    def careless(self, entity, ctx):
        res = self.result(entity)
        dump = json.dumps(payload)
        res.raw = copy.deepcopy(payload)
        res.attr("t_payload", copy.deepcopy(payload))
        res.finding("Exposure reported by the provider", "medium", f"provider said {dump}", criterion=f"copied: {dump[:3000]}",
                    data={"payload": copy.deepcopy(payload), "values": values})
        for value in values:
            res.pivot(T.IPV4 if value.count(".") == 3 and value.replace(".", "").isdigit() else T.KEYWORD, value, "mentions",
                      expand=False, note=f"value {value}")
        if values:
            res.link(f"follow {values[0]}", "https://www.example.com/search?q=" + quote(values[0]))
        return res

    events: list[str] = []
    with _sensitive_provider(keep) as prov, allow_vocab(attributes=TEST_VOCAB):
        cls = _sensitive_module("t_golden_case", prov, careless)
        rt = make_runtime(FakeHttp())
        rt.events.subscribe(lambda kind, data: events.append(f"{kind} {data!r}"))
        options = ScanOptions(include={cls.name}, purpose="P145 golden grep test", breach_scope="all", save_evidence=True)
        case = Engine(rt, options).investigate([Entity.make("email", EMAIL)])
    case_dict = case.to_dict()
    assert case_dict["coverage"][cls.name]["status"] == "ok"  # the module really ran (not skipped by the policy gate)
    db = tmp_path / "case.sqlite"
    Store(db).save_case(case_dict)
    reports = write_reports(case_dict, ["html", "md", "json", "stix"], tmp_path / "reports")
    assert len(reports) == 4
    for leak in leaks:
        assert_no_secret(leak, case_dict, db, tmp_path / "reports", paths.home(), "\n".join(events))


def test_engine_stage_keeps_the_investigated_ip_and_drops_victim_ips(clean_registry):
    def stealer(self, entity, ctx):
        res = self.result(entity)
        res.raw = {"stealers": [{"ip": "198.51.100.23", "computer_name": "DESKTOP-SYN7Q2X", "date_compromised": "2024-05-26"}]}
        res.finding("Infostealer infection seen from this IP", "high", f"{entity.value} also seen with 198.51.100.23 on DESKTOP-SYN7Q2X",
                    criterion=f"stealer log lists {entity.value}")
        res.pivot(T.IPV4, "198.51.100.23", "mentions", expand=False)
        return res

    with _sensitive_provider(["stealers[].date_compromised", "stealers[].ip"]) as prov:
        cls = _sensitive_module("t_hr_ip", prov, stealer)
        res = run_module(cls, "ipv4:203.0.113.77", FakeHttp())
    f = res.findings[0]
    assert "203.0.113.77" in f.description and "198.51.100.23" not in f.description and "DESKTOP-SYN7Q2X" not in f.description
    assert res.raw == {"stealers": [{"date_compromised": "2024-05-26"}]} and res.pivots == []
    assert {"raw.stealers[].ip", "findings:second_net", "pivots:second_net"} <= set(res.redacted_fields)


def test_a_raising_schema_drops_raw_and_ends_error_sanitizer(clean_registry, monkeypatch):
    payload = json.loads((BREACH / "hudsonrock_search_by_email.json").read_text())

    def run(self, entity, ctx):
        res = self.result(entity)
        res.raw = payload
        res.finding("Stealer log", "high", "DESKTOP-SYN7Q2X", criterion="listed")
        return res

    def broken(obj, schema):
        raise RuntimeError("schema bug")

    with _sensitive_provider(HR_KEEP) as prov:
        cls = _sensitive_module("t_raising_schema", prov, run)
        monkeypatch.setattr(sanitize, "apply_schema", broken)
        res = run_module(cls, f"email:{EMAIL}", FakeHttp())
    assert res.status is Status.ERROR and res.reason_code == "sanitizer"
    assert res.raw is None and res.findings == [] and res.pivots == [] and res.attributes == {}
    for leak in HR_LEAKS:
        assert_no_secret(leak, *_everything(res))


# ------------------------------------------------------------------ combos keep only the e-mail
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("alice@corp.example:hunter2", "alice@corp.example"),
        ("q=alice%40corp.example%3Ahunter2&page=1", "q=alice%40corp.example&page=1"),
        ("alice%40corp.example%7CS3cret!", "alice%40corp.example"),
        ("alice@corp.example\tSpring2024!\nbob@corp.example,hunter2", "alice@corp.example\nbob@corp.example"),
        ("https://user:pw123@files.example.net/a", "https://files.example.net/a"),
    ],
)
def test_combos_keep_only_the_email(text, expected):
    hits: list[dict[str, str]] = []
    assert scrub_text(text, hits=hits) == expected
    assert hits and hits[0] == {"kind": "combo", "action": "drop", "value": ""}


@pytest.mark.parametrize(
    "text",
    [
        "alice%40corp.example%3Bbob%40corp.example",  # an encoded address list
        "bob@corp.example,198.51.100.7\ncarol@corp.example,3\ndave@corp.example,evil.example",  # indicators and counts stay
        "md5 44d88612fea8a8f36de82e1278abb02f of evil.example",
        "ssh://git@github.com:22/org/repo",
    ],
)
def test_scrub_text_keeps_indicators(text):
    assert scrub_text(text) == text


def test_every_module_loses_encoded_combos():
    res = ModuleResult(module="t_any", entity=Entity.make("domain", "example.org"))
    res.raw = {"seen": "https://evil.example/?u=alice%40corp.example%3Ahunter2"}
    sanitize_result(res, type("M", (), {"name": "t_any", "category": "utility"}))
    assert res.raw == {"seen": "https://evil.example/?u=alice%40corp.example"} and "raw:combo" in res.redacted_fields


# ------------------------------------------------------------------ secrets: type + first 4/last 4 + SHA-256 only
def test_exposed_env_sample_is_masked_and_passwords_dropped():
    text = (BREACH / "exposed_env.txt").read_text()
    hits: list[dict[str, str]] = []
    out = scrub_text(text, hits=hits)
    assert_no_secret("Synth-Db-Pass-0042", out)
    for leak in ENV_LEAKS:
        assert leak not in out, leak
    assert "DB_PASSWORD=\n" in out and 'MAIL_PASSWORD=""' in out  # passwords dropped, never hashed
    assert "REDIS_URL=redis://cache.synthshop.example:6379" in out  # the URL password is a combo: dropped
    assert "APP_DEBUG=false" in out and "DB_HOST=db.synthshop.example" in out and "SENTRY_DSN=https://public@o0.ingest.sentry.example/1" in out
    fingerprints = [h["value"] for h in hits if h["action"] == "mask"]
    kinds = {h["kind"] for h in hits}
    assert {"aws_access_key_id", "aws_secret_access_key", "private_key", "secret", "password", "combo"} <= kinds
    aws = next(fp for fp in fingerprints if fp.startswith("aws_access_key_id:"))
    kind, preview, sha16 = parse_fingerprint(aws)
    assert (kind, preview, sha16) == ("aws_access_key_id", "AKIA…MPLE", hashlib.sha256(b"AKIAIOSFODNN7EXAMPLE").hexdigest()[:16])
    assert aws in out
    assert all(parse_fingerprint(fp) is not None for fp in fingerprints)


def test_secrets_in_a_light_module_result(clean_registry):
    env = (BREACH / "exposed_env.txt").read_text()
    slack = "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X" * 24
    github = "ghp_" + "SyntheticTokenForV3lumTests0000000000"[:36]

    def light(self, entity, ctx):
        res = self.result(entity)
        res.raw = {"/.env": env, "token": github, "nested": [{"key": "AKIAIOSFODNN7EXAMPLE"}]}
        res.attr("t_env", "found GitHub token " + github)
        res.finding("Exposed .env file", "high", f"the file holds {github} and AKIAIOSFODNN7EXAMPLE", criterion="HTTP 200 on /.env")
        res.link("Slack webhook", slack)
        res.pivot(T.URL, f"https://{entity.value}/hook?t={github}", "mentions", expand=False)
        return res

    with allow_vocab(attributes=TEST_VOCAB):
        cls = define_module("t_light_env", [T.DOMAIN], light, opsec="light")
        res = run_module(cls, "domain:shop.synthshop.example", FakeHttp())
    for leak in [*ENV_LEAKS, github, slack.rsplit("/", 1)[-1]]:
        assert_no_secret(leak, *_everything(res))
    masked = res.raw["token"]
    assert masked == {"type": "github_token", "preview": github[:4] + "…" + github[-4:], "sha256": hashlib.sha256(github.encode()).hexdigest()}
    assert res.raw["nested"][0]["key"]["type"] == "aws_access_key_id"
    assert "github_token:" in res.findings[0].description and res.links == []
    assert [p.entity.value for p in res.pivots] == [] or all(github not in p.entity.value for p in res.pivots)
    assert {"raw.token", "raw.nested[].key", "raw:secret", "findings:secret", "links:secret"} <= set(res.redacted_fields)


def test_secret_patterns_shape_and_distinctive_only():
    kinds = {p.kind for p in SECRET_PATTERNS}
    assert {"private_key", "aws_access_key_id", "github_token", "slack_token", "slack_webhook", "jwt", "stripe_secret_key",
            "google_api_key", "telegram_bot_token", "assignment"} <= kinds
    assert all(p.action in ("mask", "drop") for p in SECRET_PATTERNS)
    url = "https://evil.example/gate.php?api_key=abcdefghijkl1234&id=1"
    assert find_secrets(url, distinctive_only=True) == []  # key-like parameters of indicators stay (AR01)
    assert [h.kind for h in find_secrets("api_key: abcdefghijkl1234")] == ["secret"]
    hit = find_secrets("token " + "xoxb-" + "1234567890-abcdefghij")[0]
    assert hit.kind == "slack_token" and hit.action == "mask"
    assert find_secrets("password: plaintext") == [] and find_secrets("token: none") == []


def test_redaction_pass_masks_registered_keys_inside_the_sanitizer():
    redact.register_secret("SynthConfiguredKey-000042")
    res = ModuleResult(module="t_any", entity=Entity.make("domain", "example.org"))
    res.raw = {"echo": "GET https://api.example.com/v1?apikey=SynthConfiguredKey-000042"}
    res.error = "upstream said SynthConfiguredKey-000042 is invalid"
    sanitize_result(res, type("M", (), {"name": "t_any", "category": "utility"}))
    assert_no_secret("SynthConfiguredKey-000042", res.raw, res.error)


def test_values_under_password_or_secret_keys_in_any_module():
    """A LIGHT/ACTIVE module that records an exposed config as a dict: the key is the label."""
    res = ModuleResult(module="t_any", entity=Entity.make("domain", "example.org"))
    res.raw = {"config": {"db_password": "Synth-Db-Pass-0042", "api_token": "SynthApiToken-0042-abcdef", "token_type": "Bearer",
                          "password_form": "plaintext", "user": "admin", "hash": "5f4dcc3b5aa765d61d8327deb882cf99", "retries": "3"}}
    sanitize_result(res, type("M", (), {"name": "t_any", "category": "utility"}))
    cfg = res.raw["config"]
    assert "db_password" not in cfg and cfg["api_token"]["type"] == "secret" and cfg["api_token"]["preview"] == "Synt…cdef"
    assert cfg["token_type"] == "Bearer" and cfg["password_form"] == "plaintext" and cfg["hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert {"raw.config.db_password", "raw.config.api_token"} <= set(res.redacted_fields)
    assert_no_secret("Synth-Db-Pass-0042", res.raw)
    assert_no_secret("SynthApiToken-0042-abcdef", res.raw)
    web = ModuleResult(module="t_any", entity=Entity.make("domain", "example.org"))
    web.raw = {"cookies": ["PHPSESSID", "JSESSIONID"], "cookie": "sessionid=0123456789abcdef"}
    sanitize_result(web, type("M", (), {"name": "t_any", "category": "utility"}))
    assert web.raw["cookies"] == ["PHPSESSID", "JSESSIONID"]  # cookie names are a fingerprint signal
    assert_no_secret("0123456789abcdef", web.raw)  # a session value is not


# ------------------------------------------------------------------ the 'hash' rule and malware modules (P145 cond 6)
def test_malwarebazaar_fixture_keeps_file_hashes(clean_registry):
    answer = json.loads((MALWARE / "malwarebazaar_get_info.json").read_text())
    sample = answer["data"][0]

    def lookup(self, entity, ctx):
        res = self.result(entity)
        res.raw = copy.deepcopy(answer)
        res.finding("Known malware sample", "high", f"{sample['signature']} md5 {sample['md5_hash']}", criterion="MalwareBazaar lists the hash",
                    data={"sha256": sample["sha256_hash"], "md5": sample["md5_hash"], "sha1": sample["sha1_hash"]})
        return res

    cls = define_module("t_mb_lookup", [T.SHA256], lookup, category="malware_hash")
    res = run_module(cls, f"sha256:{sample['sha256_hash']}", FakeHttp())
    assert res.raw == answer and res.redacted_fields == []
    assert res.findings[0].data == {"sha256": sample["sha256_hash"], "md5": sample["md5_hash"], "sha1": sample["sha1_hash"]}
    assert sample["md5_hash"] in res.findings[0].description


@pytest.mark.parametrize("category", sorted(HASH_EXEMPT_CATEGORIES))
def test_sensitive_malware_modules_are_exempt_from_the_hash_rule_only(category):
    class SensitiveMalware:
        name = "t_sens_mb"
        sensitive = True
        sources = ("t_sens_mb.feed",)

    SensitiveMalware.category = category
    sanitize.register_schema("t_sens_mb.feed", keep=["data[].*"])
    try:
        sample = json.loads((MALWARE / "malwarebazaar_get_info.json").read_text())["data"][0]
        res = ModuleResult(module="t_sens_mb", entity=Entity.make("sha256", sample["sha256_hash"]))
        res.raw = {"data": [{"sha256_hash": sample["sha256_hash"], "md5_hash": sample["md5_hash"], "hash": sample["sha1_hash"],
                             "reporter": "synthetic_reporter", "password": "infected-archive-pass", "uploader": {"email": "x@example.com",
                             "file_md5": sample["md5_hash"]}}]}
        sanitize_result(res, SensitiveMalware)
    finally:
        sanitize.unregister_schema("t_sens_mb.feed")
    row = res.raw["data"][0]
    assert row["sha256_hash"] == sample["sha256_hash"] and row["md5_hash"] == sample["md5_hash"] and row["hash"] == sample["sha1_hash"]
    assert "password" not in row and "raw.data[].password" in res.redacted_fields
    assert row["uploader"]["file_md5"] == sample["md5_hash"]  # no hex-hash dropping next to e-mails either


def test_hash_rule_applies_to_breach_payloads():
    assert sanitize.is_second_net_field("sha256_hash") and not sanitize.is_second_net_field("sha256_hash", hash_rule=False)
    assert sanitize.is_second_net_field("password_hash", hash_rule=False)  # the password rule still applies
    assert {"hash", "password", "computer_name", "malware_path", "content"} <= SECOND_NET_FIELDS
    assert sanitize.is_second_net_field("maskedEmail") and sanitize.is_second_net_field("hintText")


def test_password_hashes_next_to_credentials_are_dropped():
    class Breach:
        name = "t_breach_hashes"
        category = "breach_leak"
        sources = ("t_bh.lookup",)

    sanitize.register_schema("t_bh.lookup", keep=["records[].*", "notes"])
    try:
        res = ModuleResult(module="t_breach_hashes", entity=Entity.make("email", EMAIL))
        res.raw = {
            "records": [
                {"email": EMAIL, "value": "5f4dcc3b5aa765d61d8327deb882cf99", "breach": "SynthForum", "breach_id": "f" * 32},
                {"breach": "Other", "dump_sha1": "3395856ce81f2b7382dee72602f798b642f14140"},
                {"user": "synth_user_42", "crypt": "$2b$12$" + "a" * 53, "list": ["5f4dcc3b5aa765d61d8327deb882cf99", "ok"]},
            ],
            "notes": f"{EMAIL} 5f4dcc3b5aa765d61d8327deb882cf99 and $2y$10$" + "b" * 53,
        }
        sanitize_result(res, Breach)
    finally:
        sanitize.unregister_schema("t_bh.lookup")
    rows = res.raw["records"]
    assert rows[0] == {"email": EMAIL, "breach": "SynthForum"}  # a hex value next to an account key is a password hash
    assert rows[1] == {"breach": "Other", "dump_sha1": "3395856ce81f2b7382dee72602f798b642f14140"}  # no credential next to it
    assert rows[2] == {"user": "synth_user_42", "list": ["ok"]}
    assert "5f4dcc3b" not in res.raw["notes"] and "$2y$" not in res.raw["notes"]
    assert {"raw.records[].value", "raw.records[].breach_id", "raw.records[].crypt", "raw.records[].list[]"} <= set(res.redacted_fields)


# ------------------------------------------------------------------ the password FORM (f)
def test_password_form_values():
    for good in ("plaintext", "hashed", "hashed: bcrypt", "unknown", ["plaintext", "hashed: md5"]):
        assert is_password_form(good), good
    for bad in ("hunter2", "hashed: 5f4dcc3b5aa765d61d8327deb882cf99", "hashed: $2b$12$abc", "a@b.example", [], None, 3):
        assert not is_password_form(bad), bad
    assert normalize_password_form("PlainText") == "plaintext"
    assert normalize_password_form("easytocrack") == "hashed: weak"
    assert normalize_password_form("bcrypt") == "hashed: bcrypt"
    assert normalize_password_form("hunter2") is None and normalize_password_form(42) is None


def test_password_form_survives_only_as_password_form():
    class Breach:
        name = "t_breach_form"
        category = "breach_leak"
        sources = ("t_bf.lookup",)

    sanitize.register_schema("t_bf.lookup", keep=["breaches[].name", "breaches[].password_risk", "breaches[].PasswordType"])
    try:
        res = ModuleResult(module="t_breach_form", entity=Entity.make("email", EMAIL))
        res.raw = {"breaches": [{"name": "A", "password_risk": "PlainText"}, {"name": "B", "PasswordType": "hunter2"}]}
        res.attributes = {"password_form": "hunter2", "breaches_seen": 2}
        res.finding("In 2 breaches", "info", "passwords: plaintext (A)", data={"password_form": ["plaintext", "hashed: bcrypt"]})
        sanitize_result(res, Breach)
    finally:
        sanitize.unregister_schema("t_bf.lookup")
    assert res.raw == {"breaches": [{"name": "A", "password_form": "plaintext"}, {"name": "B"}]}
    assert res.attributes == {"breaches_seen": 2}  # an invalid form is dropped
    assert res.findings[0].data == {"password_form": ["plaintext", "hashed: bcrypt"]}
    assert res.findings[0].description == "passwords: plaintext (A)"  # the form in plain words is metadata
    assert {"raw.breaches[].password_risk:password_form", "raw.breaches[].PasswordType", "attributes.password_form"} <= set(res.redacted_fields)


# ------------------------------------------------------------------ sensitive free text
def test_sensitive_free_text_pass():
    class Stealer:
        name = "t_stealer_text"
        category = "breach_leak"
        sources = ("t_st.lookup",)

    sanitize.register_schema("t_st.lookup", keep=["stealers[].date_compromised"])
    try:
        res = ModuleResult(module="t_stealer_text", entity=Entity.make("email", EMAIL))
        res.raw = {"stealers": [{"date_compromised": "2026-10-02", "computer_name": "Utente", "top_logins": ["synth_login"]}]}
        f = res.finding("Stealer log", "high", "machine Utente; computer_name=WS-CUSTOM-7 ip: 192.0.2.44 path C:\\Users\\Ana Souza\\x.exe "
                        "hint s******r and **bold** note", criterion="listed by the provider")
        res.pivots.append(Pivot(Entity.make(T.DOMAIN, "corp.example"), "mentions", note="login synth_login seen"))
        res.links.append(("Utente profile", "https://www.example.com/u/Utente"))
        res.links.append(("Provider page", "https://www.example.com/free-tools"))
        sanitize_result(res, Stealer)
    finally:
        sanitize.unregister_schema("t_st.lookup")
    text = f.description
    for leak in ("Utente", "WS-CUSTOM-7", "192.0.2.44", "Ana Souza", "x.exe", "s******r"):
        assert leak not in text, (leak, text)
    assert "**bold**" in text and f.title == "Stealer log"
    assert res.pivots[0].note == "login [redacted] seen"
    assert res.links == [("Provider page", "https://www.example.com/free-tools")]


def test_sanitize_body_formats_and_failures():
    body = json.dumps(json.loads((BREACH / "hudsonrock_search_by_email.json").read_text())).encode()
    sanitize.register_schema("t_body.lookup", keep=HR_KEEP)
    try:
        assert json.loads(sanitize_body("t_body.lookup", body, "application/json")) == HR_KEPT
        assert json.loads(sanitize_body("t_body.lookup", body, "text/plain; charset=utf-8")) == HR_KEPT
        assert json.loads(sanitize_body("t_body.lookup", body, "")) == HR_KEPT
        assert sanitize_body("t_body.lookup", b"<html>DESKTOP-SYN7Q2X</html>", "text/html") is None
        assert sanitize_body("t_body.lookup", b"DESKTOP-SYN7Q2X,203.0.113.77", "text/csv") is None
        assert sanitize_body("t_body.lookup", b"{broken", "application/json") is None
        assert sanitize_body("t_body.nothing", body, "application/json") is None
    finally:
        sanitize.unregister_schema("t_body.lookup")


# ------------------------------------------------------------------ review additions (wave 2)
class _Odd:
    """A custom object whose str() carries a combo and a token (the stores serialise with default=str)."""

    def __str__(self) -> str:
        return "alice@corp.example:hunter2 ghp_" + "B" * 36


def test_sets_bytes_and_custom_objects_cannot_bypass_the_sanitizer():
    import datetime

    token = "ghp_" + "A" * 36
    when = datetime.datetime(2026, 1, 2, 3, 4, 5)
    res = ModuleResult(module="t_any", entity=Entity.make("domain", "example.org"))
    res.raw = {"seen": {"alice@corp.example:hunter2", "ok"}, "blob": b"bob@corp.example:Spring2024!", "frozen": frozenset({token}),
               "obj": _Odd(), "when": when, b"bkey": 1, ("t", 1): "tuple key"}
    res.attributes = {"t_secret": {token}}
    res.finding("F", "info", "d", data={"set": {"carol@corp.example:pw12345"}})
    sanitize_result(res, type("M", (), {"name": "t_any", "category": "utility"}))
    for leak in ("hunter2", "Spring2024!", token, "pw12345", "B" * 36):
        assert_no_secret(leak, json.dumps(res.raw, default=str), json.dumps(res.attributes, default=str),
                         json.dumps(res.findings[0].data, default=str))
    assert res.raw["seen"] == ["alice@corp.example", "ok"] and res.raw["blob"] == "bob@corp.example"
    assert res.raw["frozen"][0]["type"] == "github_token" and res.raw["when"] is when  # harmless objects stay as built
    assert res.raw["bkey"] == 1 and res.raw["('t', 1)"] == "tuple key"  # keys become JSON keys
    assert res.findings[0].data == {"set": ["carol@corp.example"]}


def test_hex_hashes_anywhere_under_a_credential_record_are_dropped():
    class Breach:
        name = "t_breach_nested"
        category = "breach_leak"
        sources = ("t_bn.lookup",)

    sanitize.register_schema("t_bn.lookup", keep=["records[].*"])
    md5 = "5f4dcc3b5aa765d61d8327deb882cf99"
    try:
        res = ModuleResult(module="t_breach_nested", entity=Entity.make("email", EMAIL))
        res.raw = {"records": [{"email": EMAIL, "details": {"v": md5, "breach": "SynthForum"}, "values": [{"x": md5}, md5]}]}
        res.attributes = {}
        sanitize_result(res, Breach)
    finally:
        sanitize.unregister_schema("t_bn.lookup")
    assert_no_secret(md5, res.raw)
    assert res.raw["records"][0]["details"] == {"breach": "SynthForum"}


def test_password_form_refuses_free_text_after_hashed():
    for bad in ("hashed: hunter2", "hashed: md5/hunter2", "hashed: Summer2024"):
        assert not is_password_form(bad), bad
    for good in ("hashed: encrypted", "hashed: md5/sha1", "hashed: des-crypt", "hashed: sha256 + salt", "hashed: weak", "hashed: unknown"):
        assert is_password_form(good), good
    assert normalize_password_form("hashed - hunter2") is None
    res = ModuleResult(module="t_any", entity=Entity.make("domain", "example.org"))
    res.attributes = {"password_form": "hashed: hunter2"}
    sanitize_result(res, type("M", (), {"name": "t_any", "category": "utility"}))
    assert res.attributes == {} and "attributes.password_form" in res.redacted_fields


def test_http_basic_credentials_are_dropped_everywhere():
    creds = "YWRtaW46U3VwM3JTZWNyZXQ="  # base64('admin:Sup3rSecret')
    hits: list[dict[str, str]] = []
    assert scrub_text(f"curl -H 'Authorization: Basic {creds}' https://x.example", hits=hits) == \
        "curl -H 'Authorization: Basic ' https://x.example"
    assert {"kind": "basic_auth", "action": "drop", "value": ""} in hits
    for benign in ("basic information about the case", "Basic dGVzdA==", "Basic auth is disabled"):  # 'dGVzdA==' is 'test'
        assert scrub_text(benign) == benign
    res = ModuleResult(module="t_any", entity=Entity.make("domain", "example.org"))
    res.raw = {"request": f"GET / HTTP/1.1\r\nAuthorization: Basic {creds}"}
    res.finding("Exposed request log", "high", f"log line Authorization: Basic {creds}", criterion="HTTP 200 on /logs")
    sanitize_result(res, type("M", (), {"name": "t_any", "category": "utility", "opsec": "light"}))
    assert_no_secret(creds, res.raw, res.findings[0].description)
    assert_no_secret("Sup3rSecret", res.raw, res.findings[0].description)


def test_more_credential_names_in_breach_payloads():
    class Breach:
        name = "t_breach_names"
        category = "breach_leak"
        sources = ("t_bnm.lookup",)

    sanitize.register_schema("t_bnm.lookup", keep=["rows[].*"])
    row = {"breach": "SynthForum", "passcode": "Synth-0042", "passphrase": "correct horse battery", "pin": "4321",
           "otp_secret": "JBSWY3DPEHPK3PXP", "kennwort": "Geheim-0042", "mot_de_passe": "Secret-0042", "security_answer": "Rex"}
    try:
        res = ModuleResult(module="t_breach_names", entity=Entity.make("email", EMAIL))
        res.raw = {"rows": [dict(row)]}
        sanitize_result(res, Breach)
    finally:
        sanitize.unregister_schema("t_bnm.lookup")
    assert res.raw == {"rows": [{"breach": "SynthForum"}]}
    assert {"passcode", "passphrase", "pin", "otp", "totp", "kennwort", "mot_de_passe"} <= SECOND_NET_FIELDS


def test_observed_dates_are_scrubbed_like_every_finding_field():
    res = ModuleResult(module="t_any", entity=Entity.make("domain", "example.org"))
    f = res.finding("F", "info", "d")
    f.observed_first = "2026-01-01 alice@corp.example:hunter2"
    f.observed_last = "token ghp_" + "C" * 36
    sanitize_result(res, type("M", (), {"name": "t_any", "category": "utility"}))
    assert_no_secret("hunter2", f.observed_first)
    assert_no_secret("C" * 36, f.observed_last)


def test_sanitized_cache_body_is_ascii_json_whatever_the_declared_charset(clean_registry):
    body = json.dumps({"breaches": ["Ação Synthética"], "password": "Synth3tic!Pass"}, ensure_ascii=False).encode("utf-8")
    sanitize.register_schema("t_ascii.lookup", keep=["breaches"])
    try:
        out = sanitize_body("t_ascii.lookup", body, "application/json")
        assert out is not None and out.decode("ascii")  # pure ASCII: decodes the same under latin-1, cp1252, utf-8
        assert json.loads(out.decode("latin-1")) == {"breaches": ["Ação Synthética"]}
    finally:
        sanitize.unregister_schema("t_ascii.lookup")


def test_structured_masks_and_inline_fingerprints_show_the_same_preview():
    secret = "Sy7nth-tok-42"  # 13 characters: a 4+4 preview would leave 5 unknown characters next to the SHA-256
    res = ModuleResult(module="t_any", entity=Entity.make("domain", "example.org"))
    res.raw = {"config": {"api_token": secret}, "line": f"api_token={secret}"}
    sanitize_result(res, type("M", (), {"name": "t_any", "category": "utility"}))
    masked = res.raw["config"]["api_token"]
    assert masked["preview"] == secret_preview(secret) == "Sy…42"
    assert masked["sha256"] == hashlib.sha256(secret.encode()).hexdigest()
    kind, preview, _sha16 = parse_fingerprint(res.raw["line"].split("=", 1)[1])
    assert preview == masked["preview"]
    assert_no_secret(secret, res.raw)


def test_sanitizer_stays_fast_on_a_large_ordinary_payload():
    rows = [{"id": i, "issuer_name": f"C=US, O=Example CA, CN=R{i % 10}", "common_name": f"h{i}.example.com",
             "name_value": f"h{i}.example.com\n*.w{i}.example.com", "not_before": "2026-01-01T00:00:00",
             "serial_number": f"{i:032x}", "entry_timestamp": "2026-01-01T00:00:00.123"} for i in range(20_000)]
    res = ModuleResult(module="t_any", entity=Entity.make("domain", "example.com"))
    res.raw = rows
    start = time.perf_counter()
    sanitize_result(res, type("M", (), {"name": "t_any", "category": "domain_dns"}))
    assert time.perf_counter() - start < 8.0  # every module result passes this stage
    assert res.raw[123]["common_name"] == "h123.example.com"


# ------------------------------------------------------------------ robustness
def test_detectors_stay_linear_on_hostile_text():
    hostile = [
        "a" * 200_000, "=" * 100_000, "a:" * 50_000, "eyJ" + "a" * 100_000, "-----BEGIN PRIVATE KEY-----" * 2_000,
        "x" + "%41" * 30_000 + "%40a.co%3A" + "b" * 1_000, "alice@corp.example\t" * 20_000, "AKIA" * 50_000, "password:" * 30_000,
        "*" * 100_000 + "a", ("a" * 30 + ".") * 5_000, "$2b$12$" * 20_000, "1.2.3." * 40_000, ":" * 100_000 + "1",
        "C:\\" + "a\\" * 50_000,
    ]
    start = time.perf_counter()
    for text in hostile:
        scrub_text(text)
    assert time.perf_counter() - start < 4.0

    class Breach:
        name = "t_hostile"
        category = "breach_leak"
        sources = ("t_hostile.lookup",)

    sanitize.register_schema("t_hostile.lookup", keep=["items[]"])
    try:
        res = ModuleResult(module="t_hostile", entity=Entity.make("email", EMAIL))
        res.raw = {"items": hostile[:8]}
        start = time.perf_counter()
        sanitize_result(res, Breach)
        assert time.perf_counter() - start < 6.0
    finally:
        sanitize.unregister_schema("t_hostile.lookup")
