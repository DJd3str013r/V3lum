"""P326 per-provider HTTP profiles applied by the client: UA/Accept/Accept-Language, timeout,
retries, byte cap, politeness, cache key, TTL clamps, sensitive providers (P145 cond 7)."""

from __future__ import annotations

import json
import sqlite3

import pytest

from tests.fixtures.http.stub_transport import StubClock, StubTransport, load, provider, registry
from v3lum import __version__
from v3lum.core import providers as providers_mod
from v3lum.core import sanitize
from v3lum.core.http import BR_ACCEPT_LANGUAGE, DEFAULT_UA_LIGHT, SENSITIVE_MAX_TTL, ConfigError, HttpCache, HttpClient, ScopedHttp
from v3lum.core.models import Opsec

CONTACT = "cti-team@example.org"
CONTACT_URL = "https://cti.example.org/v3lum"
UA_LIGHT = "Mozilla/5.0 (X11; Linux x86_64) TestBrowser/1.0"
SETTINGS = {"contact_email": CONTACT, "contact_url": CONTACT_URL, "ua_light": UA_LIGHT, "user_agent": f"V3LUM/{__version__}"}
NEUTRAL = f"V3LUM/{__version__}"


def client_for(transport: StubTransport, reg=None, *, settings=None, cache=None, clock=None, **kw) -> HttpClient:
    clock = clock or StubClock()
    transport.clock = clock
    return HttpClient(transport=transport, clock=clock, providers=reg if reg is not None else registry(), settings=SETTINGS if settings is None else settings, cache=cache, **kw)


def concrete(host: str) -> str:
    return "www" + host[1:] if host.startswith("*.") else host


def expected_ua(profile: providers_mod.HttpProfile, tier: str) -> str:
    """Independent oracle of the UA rules (P326 cond 3-5)."""
    spec = profile.user_agent
    if spec in (None, "neutral"):
        return NEUTRAL
    if spec == "browser":
        return UA_LIGHT
    if tier == "unknown" and (spec == "contact" or "{contact" in spec):
        return NEUTRAL
    if spec == "contact":
        return f"V3LUM/{__version__} (+{CONTACT})"
    return spec.replace("{version}", __version__).replace("{contact_url}", CONTACT_URL).replace("{contact}", CONTACT).replace("{app}", "v3lum")


def expected_language(profile: providers_mod.HttpProfile, host: str) -> str | None:
    if profile.accept_language:
        return profile.accept_language
    return BR_ACCEPT_LANGUAGE if host.endswith(".br") else None


def _profiled() -> list:
    out = []
    for prov in providers_mod.registry().providers():
        if prov.http_profile == providers_mod.HttpProfile():
            continue
        for host in prov.hosts:
            out.append(pytest.param(prov.id, concrete(host), id=f"{prov.id}:{host}"))
    return out


# --------------------------------------------------------------------------------------
# every registered profile (batch fragments are covered automatically, P326 cond 1)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(("pid", "host"), _profiled())
def test_every_registered_profile_is_applied(pid, host):
    reg = providers_mod.registry()
    prov = reg.get(pid)
    profile = prov.http_profile
    t = StubTransport().add("GET", f"https://{host}/probe", json={"ok": True})
    c = client_for(t, reg)
    resp = c.request("GET", f"https://{host}/probe")
    assert resp.ok
    assert t.header(0, "User-Agent") == expected_ua(profile, prov.tier)
    assert t.header(0, "Accept") == profile.accept
    assert t.header(0, "Accept-Language") == expected_language(profile, host)
    if profile.timeout is not None:
        assert t.calls[0]["timeout"] == pytest.approx(profile.timeout)
    if profile.max_bytes is not None:
        assert t.calls[0]["max_bytes"] == profile.max_bytes
    if profile.ttl is not None:
        assert c.effective_ttl("GET", None, profile, sensitive=prov.flags.sensitive) <= profile.ttl
        assert c.effective_ttl("GET", 10 * 86400, profile, sensitive=prov.flags.sensitive) <= profile.ttl  # the profile TTL is a ceiling


def _requirements() -> list:
    return [pytest.param(pattern, req, id=pattern) for pattern, req in providers_mod.PROFILE_REQUIREMENTS.items()]


@pytest.mark.parametrize(("pattern", "req"), _requirements())
def test_profile_requirements_through_a_synthetic_provider(pattern, req, tmp_path):
    """Each PROFILE_REQUIREMENTS entry, on a synthetic provider owning that host (P326 cond 3, 4, 7, 11)."""
    host = concrete(pattern)
    fields = {k: v for k, v in req.items() if k in ("user_agent", "accept", "accept_language", "ttl")}
    prov = provider("req_owner", (pattern,), name="Required", sensitive=bool(req.get("flags.sensitive", False)), profile=fields)
    assert providers_mod.profile_violations(prov) == []
    cache = HttpCache(str(tmp_path / "c.db"))
    try:
        t = StubTransport().add("GET", f"https://{host}/probe", json={"ok": True})
        c = client_for(t, registry(prov), cache=cache, sanitizer=lambda *_: None)
        c.request("GET", f"https://{host}/probe")
        assert t.header(0, "User-Agent") == expected_ua(prov.http_profile, "trusted")
        if "user_agent" in req and req["user_agent"] == "neutral":
            assert t.header(0, "User-Agent") == NEUTRAL  # never a browser UA (registro.br, HIBP)
        if "accept" in req:
            assert t.header(0, "Accept") == req["accept"]
        if "accept_language" in req:
            assert t.header(0, "Accept-Language") == req["accept_language"]
        if "ttl" in req:
            assert c.effective_ttl("GET", 30 * 86400, prov.http_profile, sensitive=prov.flags.sensitive) <= req["ttl"]
        if req.get("flags.sensitive"):
            assert cache.stats()["entries"] == 0  # no schema: no-store
    finally:
        cache.close()


# --------------------------------------------------------------------------------------
# User-Agent rules
# --------------------------------------------------------------------------------------


def test_default_ua_is_neutral_and_no_accept_language_by_default():
    t = StubTransport().add("GET", "https://api.example.test/x", text="ok")
    HttpClient(transport=t, providers=registry()).request("GET", "https://api.example.test/x")
    assert t.header(0, "User-Agent") == NEUTRAL
    assert t.header(0, "Accept-Language") is None  # the v1 hard-coded 'en-US' default is gone


def test_settings_user_agent_is_the_neutral_ua():
    t = StubTransport().add("GET", "https://api.example.test/x", text="ok")
    client_for(t, settings={"user_agent": "V3LUM/9.9 test"}).request("GET", "https://api.example.test/x")
    assert t.header(0, "User-Agent") == "V3LUM/9.9 test"


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        (None, NEUTRAL),
        ("neutral", NEUTRAL),
        ("contact", f"V3LUM/{__version__} (+{CONTACT})"),
        ("browser", UA_LIGHT),
        ("keycdn-tools:{contact_url}", f"keycdn-tools:{CONTACT_URL}"),
        ("phishtank/{app}", "phishtank/v3lum"),
        ("V3LUM/{version} (+{contact}) python-requests", f"V3LUM/{__version__} (+{CONTACT}) python-requests"),
    ],
)
def test_profile_user_agents(spec, expected):
    t = StubTransport().add("GET", "https://api.example.test/x", text="ok")
    c = client_for(t, registry(provider("ua_demo", ("api.example.test",), profile={"user_agent": spec})))
    c.request("GET", "https://api.example.test/x")
    assert t.header(0, "User-Agent") == expected


@pytest.mark.parametrize(
    ("spec", "missing"),
    [("contact", "contact_email"), ("keycdn-tools:{contact_url}", "contact_url"), ("V3LUM/{version} (+{contact})", "contact_email")],
)
def test_contact_ua_without_the_setting_is_config_error(spec, missing):
    t = StubTransport()
    c = client_for(t, registry(provider("ua_demo", ("api.example.test",), profile={"user_agent": spec})), settings={"contact_email": "", "contact_url": ""})
    with pytest.raises(ConfigError) as err:
        c.request("GET", "https://api.example.test/x")
    assert err.value.reason_code == "config" and missing in str(err.value)
    assert t.calls == []  # nothing is sent


def test_unknown_placeholder_is_config_error():
    c = client_for(StubTransport(), registry(provider("ua_demo", ("api.example.test",), profile={"user_agent": "tool/{analyst}"})))
    with pytest.raises(ConfigError, match="unknown placeholder"):
        c.request("GET", "https://api.example.test/x")


def test_contact_ua_never_goes_to_unknown_tier_providers():
    t = StubTransport().add("GET", "https://api.example.test/x", text="ok")
    c = client_for(t, registry(provider("ua_demo", ("api.example.test",), tier="unknown", profile={"user_agent": "contact"})))
    c.request("GET", "https://api.example.test/x")
    assert t.header(0, "User-Agent") == NEUTRAL


@pytest.mark.parametrize("opsec", [Opsec.LIGHT, Opsec.ACTIVE, "light", 2])
def test_light_and_active_requests_use_ua_light_never_the_identity(opsec):
    t = StubTransport().add("GET", "https://target.example.test/", text="ok", times=3)
    c = client_for(t, registry(provider("ua_demo", ("target.example.test",), profile={"user_agent": "contact"})))
    c.request("GET", "https://target.example.test/", opsec=opsec)
    assert t.header(0, "User-Agent") == UA_LIGHT
    c.request("GET", "https://target.example.test/", opsec=opsec, headers={"User-Agent": f"V3LUM/{__version__} (+{CONTACT})"})
    assert t.header(1, "User-Agent") == UA_LIGHT  # an identifying caller UA is replaced
    c.request("GET", "https://target.example.test/", opsec=opsec, user_agent="RoE-Engagement-Token-42")
    assert t.header(2, "User-Agent") == "RoE-Engagement-Token-42"


def test_ua_light_falls_back_to_a_browser_ua():
    t = StubTransport().add("GET", "https://target.example.test/", text="ok")
    client_for(t, settings={}).request("GET", "https://target.example.test/", opsec="light")
    assert t.header(0, "User-Agent") == DEFAULT_UA_LIGHT


# --------------------------------------------------------------------------------------
# Accept / Accept-Language
# --------------------------------------------------------------------------------------


def test_accept_language_pt_br_for_br_hosts():
    t = StubTransport().add("GET", "https://brasilapi.com.br/api/cnpj/v1/00000000000191", json={})
    t.add("GET", "https://www.example.com/", text="ok")
    c = client_for(t)
    c.request("GET", "https://brasilapi.com.br/api/cnpj/v1/00000000000191")
    c.request("GET", "https://www.example.com/")
    assert t.header(0, "Accept-Language") == BR_ACCEPT_LANGUAGE
    assert t.header(1, "Accept-Language") is None


def test_profile_and_caller_headers_win_in_order():
    rdap = provider("registro_br_demo", ("rdap.registro.br",), profile={"user_agent": "neutral", "accept": "application/rdap+json", "accept_language": "pt-BR"})
    t = StubTransport().add("GET", "https://rdap.registro.br/domain/nic.br", json={}, times=2)
    c = client_for(t, registry(rdap))
    ScopedHttp(c).get_json("https://rdap.registro.br/domain/nic.br")  # get_json's default Accept never beats the profile
    assert t.header(0, "Accept") == "application/rdap+json" and t.header(0, "Accept-Language") == "pt-BR"
    c.request("GET", "https://rdap.registro.br/domain/nic.br", headers={"Accept": "application/json", "Accept-Language": "en"})
    assert t.header(1, "Accept") == "application/json" and t.header(1, "Accept-Language") == "en"


def test_get_json_sets_accept_json_without_a_profile():
    t = StubTransport().add("GET", "https://api.example.test/x", json={"a": 1})
    assert ScopedHttp(client_for(t)).get_json("https://api.example.test/x") == {"a": 1}
    assert t.header(0, "Accept") == "application/json"


# --------------------------------------------------------------------------------------
# timeout, retries, byte cap, politeness
# --------------------------------------------------------------------------------------


def test_timeout_retries_and_max_bytes_from_the_profile():
    t = StubTransport()
    t.add("GET", "https://slow.example.test/x", status=503, text="busy", times=2)
    t.add("GET", "https://slow.example.test/x", body=b"y" * 5000)
    prov = provider("slow_demo", ("slow.example.test",), profile={"timeout": 7.5, "retries": 2, "max_bytes": 1000})
    clock = StubClock()
    c = client_for(t, registry(prov), clock=clock)
    resp = c.request("GET", "https://slow.example.test/x")
    assert resp.ok and resp.truncated and len(resp.content) == 1000
    assert [call["timeout"] for call in t.calls] == [7.5, 7.5, 7.5]
    assert all(call["max_bytes"] == 1000 for call in t.calls)
    assert len(clock.sleeps) == 2  # backoff happened on the fake clock


def test_caller_values_override_the_profile():
    t = StubTransport().add("GET", "https://slow.example.test/x", status=503, text="busy")
    prov = provider("slow_demo", ("slow.example.test",), profile={"timeout": 7.5, "retries": 2})
    resp = client_for(t, registry(prov)).request("GET", "https://slow.example.test/x", retries=0, timeout=3.0)
    assert resp.status == 503 and len(t.calls) == 1 and t.calls[0]["timeout"] == 3.0


@pytest.mark.parametrize(("module_interval", "profile_interval", "expected"), [(0.5, 2.0, 2.0), (3.0, 1.0, 3.0), (0.0, 0.0, 0.0)])
def test_politeness_is_the_max_of_module_and_profile(module_interval, profile_interval, expected):
    t = StubTransport().add("GET", "https://polite.example.test/x", text="ok", times=2)
    prov = provider("polite_demo", ("polite.example.test",), profile={"min_interval": profile_interval})
    clock = StubClock()
    c = client_for(t, registry(prov), clock=clock)
    c.request("GET", "https://polite.example.test/x", min_interval=module_interval)
    c.request("GET", "https://polite.example.test/x", min_interval=module_interval)
    assert sum(clock.sleeps) == pytest.approx(expected)


def test_a_declared_interval_binds_every_later_request_to_that_host():
    t = StubTransport().add("GET", "https://polite.example.test/x", text="ok", times=3)
    clock = StubClock()
    c = client_for(t, clock=clock)
    c.request("GET", "https://polite.example.test/x", min_interval=2.0)
    c.request("GET", "https://polite.example.test/x", min_interval=0.0)  # still waits (P334 cond 4)
    assert sum(clock.sleeps) == pytest.approx(2.0)


# --------------------------------------------------------------------------------------
# cache key and TTL
# --------------------------------------------------------------------------------------


def test_cache_key_differs_by_accept_and_credentials():
    base = HttpClient.cache_key("GET", "https://api.example.test/x")
    assert base == HttpClient.cache_key("GET", "https://api.example.test/x", None)  # v1 key unchanged
    assert base != HttpClient.cache_key("GET", "https://api.example.test/x", accept="application/json")
    assert HttpClient.cache_key("GET", "https://api.example.test/x", accept="text/html") != HttpClient.cache_key("GET", "https://api.example.test/x", accept="application/json")
    assert base != HttpClient.cache_key("GET", "https://api.example.test/x", credential_hash="ab" * 32)


def test_keyed_and_keyless_answers_never_mix(tmp_path):
    cache = HttpCache(str(tmp_path / "c.db"))
    try:
        t = StubTransport().add("GET", "https://api.example.test/x", json={"n": 1}, times=4)
        c = client_for(t, cache=cache)
        c.request("GET", "https://api.example.test/x")
        assert c.request("GET", "https://api.example.test/x").from_cache
        c.request("GET", "https://api.example.test/x", headers={"X-Api-Key": "key-aaaaaaaa"})
        c.request("GET", "https://api.example.test/x", headers={"X-Api-Key": "key-bbbbbbbb"})
        c.request("GET", "https://api.example.test/x", headers={"Accept": "text/html"})
        assert len(t.calls) == 4
    finally:
        cache.close()


def test_ttl_clamped_by_cache_max_age_and_retention():
    c = HttpClient(settings={"cache_max_age_days": 1, "retention_days": 180}, providers=registry(), transport=StubTransport())
    assert c.effective_ttl("GET", 10 * 86400) == 86400
    c = HttpClient(settings={"cache_max_age_days": 30, "retention_days": 0.5}, providers=registry(), transport=StubTransport())
    assert c.effective_ttl("GET", 10 * 86400) == 43200
    c = HttpClient(default_ttl=3600, providers=registry(), transport=StubTransport())
    assert c.effective_ttl("GET", None) == 3600
    assert c.effective_ttl("POST", None) == 0  # POST is cached only on request
    assert c.effective_ttl("GET", 30 * 86400, sensitive=True) == SENSITIVE_MAX_TTL


def test_clamped_ttl_expires_cached_rows(tmp_path):
    cache = HttpCache(str(tmp_path / "c.db"))
    try:
        clock = StubClock()
        t = StubTransport().add("GET", "https://api.example.test/x", json={"n": 1}, times=2)
        c = client_for(t, cache=cache, clock=clock, settings={"cache_max_age_days": 1, "retention_days": 180})
        c.request("GET", "https://api.example.test/x", ttl=10 * 86400)
        clock.advance(86400 - 60)
        assert c.request("GET", "https://api.example.test/x", ttl=10 * 86400).from_cache
        clock.advance(120)
        assert not c.request("GET", "https://api.example.test/x", ttl=10 * 86400).from_cache
    finally:
        cache.close()


# --------------------------------------------------------------------------------------
# sensitive providers (P145 cond 7, P326 veto_lift 1)
# --------------------------------------------------------------------------------------

STEALER = "hudsonrock_stealer_synthetic.json"
LEAKS = ("DESKTOP-FAKE0042", "203.0.113.77", "fake-stealer.exe", "f********9", "f*****r@example.com")


def _cache_dump(path) -> bytes:
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute("SELECT url, headers, body, history FROM cache").fetchall()
    finally:
        conn.close()
    return b"\n".join((r[0] or "").encode() + (r[1] or "").encode() + (r[2] or b"") + (r[3] or "").encode() for r in rows)


def test_sensitive_provider_without_schema_is_no_store(tmp_path):
    cache = HttpCache(str(tmp_path / "c.db"))
    try:
        body = load(STEALER)
        t = StubTransport().add("GET", "https://cavalier.example.test/api/search?email=someone@example.com", body=body, content_type="application/json", times=2)
        prov = provider("stealer_demo", ("cavalier.example.test",), sensitive=True, sources=("search",))
        c = client_for(t, registry(prov), cache=cache)
        resp = c.request("GET", "https://cavalier.example.test/api/search?email=someone@example.com", source="stealer_demo.search")
        assert resp.content == body  # raw body in memory only
        assert cache.stats()["entries"] == 0
        assert not c.request("GET", "https://cavalier.example.test/api/search?email=someone@example.com", source="stealer_demo.search").from_cache
    finally:
        cache.close()


def test_sensitive_provider_with_schema_stores_and_returns_only_the_sanitized_body(tmp_path):
    db = tmp_path / "c.db"
    cache = HttpCache(str(db))
    calls: list[tuple[str, str]] = []

    def sanitizer(source_id: str, content: bytes, content_type: str) -> bytes | None:
        calls.append((source_id, content_type))
        data = json.loads(content)
        kept = {"stealers": [{k: s[k] for k in ("date_compromised", "total_corporate_services", "total_user_services")} for s in data["stealers"]]}
        return json.dumps(kept).encode()

    try:
        t = StubTransport().add("GET", "https://cavalier.example.test/api/search?email=someone@example.com", body=load(STEALER), content_type="application/json")
        prov = provider("stealer_demo", ("cavalier.example.test",), sensitive=True, sources=("search",))
        c = client_for(t, registry(prov), cache=cache, sanitizer=sanitizer)
        scoped = ScopedHttp(c, sources=("stealer_demo.search",))
        data = scoped.get_json("https://cavalier.example.test/api/search?email=someone@example.com")
        assert data == {"stealers": [{"date_compromised": "2026-10-02T00:00:00.000Z", "total_corporate_services": 3, "total_user_services": 41}]}
        assert calls == [("stealer_demo.search", "application/json")]  # the scope's single source is used
        assert cache.stats()["entries"] == 1
        assert scoped.get_json("https://cavalier.example.test/api/search?email=someone@example.com") == data
        dump = _cache_dump(db)
        for leak in LEAKS:
            assert leak.encode() not in dump, leak
    finally:
        cache.close()


def test_sensitive_provider_uses_the_core_sanitizer_by_default(tmp_path):
    db = tmp_path / "c.db"
    cache = HttpCache(str(db))
    sanitize.register_schema("stealer_core.search", keep=["stealers[].date_compromised", "stealers[].total_corporate_services", "total_user_services"])
    try:
        t = StubTransport().add("GET", "https://cavalier.example.test/api/search?email=someone@example.com", body=load(STEALER), content_type="application/json")
        prov = provider("stealer_core", ("cavalier.example.test",), sensitive=True, sources=("search",))
        c = client_for(t, registry(prov), cache=cache)
        resp = c.request("GET", "https://cavalier.example.test/api/search?email=someone@example.com", source="stealer_core.search")
        kept = resp.json()
        assert kept["stealers"][0]["date_compromised"] == "2026-10-02T00:00:00.000Z"
        assert "computer_name" not in json.dumps(kept)
        dump = _cache_dump(db)
        for leak in LEAKS:
            assert leak.encode() not in dump, leak
    finally:
        sanitize.unregister_schema("stealer_core.search")
        cache.close()


# --------------------------------------------------------------------------------------
# review additions
# --------------------------------------------------------------------------------------


def test_a_profile_ttl_of_zero_means_never_cached(tmp_path):
    cache = HttpCache(str(tmp_path / "c.db"))
    try:
        prov = provider("volatile_demo", ("live.example.test",), profile={"ttl": 0})
        t = StubTransport().add("GET", "https://live.example.test/x", json={"n": 1}, times=2)
        c = client_for(t, registry(prov), cache=cache)
        assert c.effective_ttl("GET", 3600, prov.http_profile) == 0.0  # a requested TTL never widens it
        c.request("GET", "https://live.example.test/x", ttl=3600)
        assert not c.request("GET", "https://live.example.test/x", ttl=3600).from_cache
        assert cache.stats()["entries"] == 0
    finally:
        cache.close()


def test_a_caller_contact_ua_never_reaches_unknown_tier_or_unregistered_hosts():
    contact_ua = f"V3LUM/{__version__} (+{CONTACT})"
    reg = registry(
        provider("unknown_demo", ("shady.example.test",), tier="unknown"),
        provider("trusted_demo", ("sec.example.test",), tier="trusted"),
    )
    t = StubTransport().add("GET", "https://shady.example.test/x", text="ok").add("GET", "https://nobody.example.test/x", text="ok")
    t.add("GET", "https://sec.example.test/x", text="ok")
    c = client_for(t, reg)
    c.request("GET", "https://shady.example.test/x", user_agent=contact_ua)
    c.request("GET", "https://nobody.example.test/x", headers={"User-Agent": f"tool ({CONTACT_URL})"})
    c.request("GET", "https://sec.example.test/x", user_agent=contact_ua)
    assert t.header(0, "User-Agent") == NEUTRAL and t.header(1, "User-Agent") == NEUTRAL
    assert t.header(2, "User-Agent") == contact_ua  # a trusted provider may get the caller's UA


def test_sensitive_bodies_never_reach_exception_text():
    """An unusable answer of a sensitive provider (no schema, error marker) raises without quoting it."""
    marker = {"id": "stealer_error", "json_path": "message", "regex": "infected", "maps_to": "error", "reason": "Stealer demo: refused"}
    body = load(STEALER)
    t = StubTransport().add("GET", "https://cavalier.example.test/api/search?email=someone@example.com", body=body, content_type="application/json", times=2)
    t.add("GET", "https://cavalier.example.test/api/broken", status=500, body=body, content_type="application/json")
    prov = provider("stealer_demo", ("cavalier.example.test",), sensitive=True, sources=("search",), markers=(marker,))
    c = client_for(t, registry(prov))
    resp = c.request("GET", "https://cavalier.example.test/api/search?email=someone@example.com", source="stealer_demo.search")
    assert resp.classification is not None and resp.sensitive
    errors = []
    for call in (resp.raise_for_status, lambda: c.request("GET", "https://cavalier.example.test/api/broken").raise_for_status()):
        with pytest.raises(Exception) as err:
            call()
        errors.append(err.value)
    for exc in errors:
        text = str(exc) + str(getattr(exc, "body", ""))
        for leak in LEAKS:
            assert leak not in text, (leak, type(exc).__name__)
