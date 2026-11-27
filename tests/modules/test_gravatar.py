"""gravatar (P087): v3 profile by locally computed SHA-256 hash + avatar existence (d=404).

Fixtures in tests/fixtures/gravatar/: ``not_found.json`` and ``avatar_absent.json`` are live answers of
2026-11-26 for sha256(test@example.com); ``profile_org.json`` is Gravatar's own organisation profile
(live, verbatim); ``profile_verified.json`` is the research schema-only sample filled with documentation
values (a hidden account, a javascript: URL and free-text links included); ``avatar_found.json`` keeps
the live headers only (the image bytes are never stored: tests use a few synthetic JPEG bytes).
"""

from __future__ import annotations

import hashlib
import json

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.email.gravatar import Gravatar, gravatar_hashes, parse_profile, profile_url

MOD = Gravatar
PROFILE = "https://api.gravatar.com/v3/profiles/{}"
AVATAR = "https://gravatar.com/avatar/{}?d=404"
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00synthetic avatar bytes\xff\xd9"
CHALLENGE = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


def fx(name):
    return module_fixture(MOD, name)


def env(http, url, name, **kw):
    data = fx(name)
    if isinstance(data, dict) and data.get("_envelope"):
        body = data.get("body")
        if isinstance(body, (dict, list)):
            return http.add("GET", url, status=data["status"], json=body, headers=data.get("headers"), **kw)
        return http.add("GET", url, status=data["status"], text=body or "", headers=data.get("headers"), **kw)
    return http.add("GET", url, json=data, **kw)


def sha(email):
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()


def avatar_found(http, avatar_hash):
    headers = dict(fx("avatar_found.json")["headers"])
    return http.add("GET", AVATAR.format(avatar_hash), body=JPEG, headers=headers)


def test_address_is_hashed_locally_and_never_sent():
    email = "Someone@Example.com "
    h = sha(email)
    assert profile_url(email) == PROFILE.format(h)
    assert gravatar_hashes(email)["md5"] == hashlib.md5(b"someone@example.com").hexdigest()  # noqa: S324 - legacy avatar key
    http = FakeHttp()
    env(http, PROFILE.format(h), "not_found.json")
    env(http, AVATAR.format(h), "avatar_absent.json")
    res = run_module(MOD, "email:someone@example.com", http)
    assert all("@" not in u and "someone" not in u.lower() for u in http.urls())
    assert res.status is Status.EMPTY
    assert res.attributes["presence"]["state"] == "absent"
    assert "no public Gravatar profile" in res.error
    http.assert_hosts_within(MOD)


def test_verified_profile_is_minimised_with_probable_and_possible_pivots():
    email = "dev@acme.com.br"
    data = fx("profile_verified.json")
    avatar_hash = data["avatar_url"].rsplit("/", 1)[-1]
    http = FakeHttp().add("GET", PROFILE.format(sha(email)), json=data)
    avatar_found(http, avatar_hash)
    res = run_module(MOD, f"email:{email}", http)
    assert res.status is Status.OK
    card = res.attributes["gravatar_profile"]
    assert card["display_name"] == "Example Dev" and card["avatar_hash"] == avatar_hash
    assert card["avatar_sha256"] == hashlib.sha256(JPEG).hexdigest()
    blob = json.dumps([res.attributes, res.raw, [f.to_dict() for f in res.findings]], default=str)
    for dropped in ("Sao Paulo", "free-text bio", "Engineer", "Example Org", "javascript:", "service_icon"):
        assert dropped not in blob  # cond 4: location, bio, job, company and unsafe URLs never kept
    urls = {p.entity.value: p for p in res.pivots if p.entity.type.value == "url"}
    assert urls["https://github.com/example-dev"].confidence_label.value == "probable"
    users = {p.entity.value for p in res.pivots if p.entity.type.value == "username"}
    assert {"example-dev", "exampledev"} <= users
    handles = {p.entity.value for p in res.pivots if p.entity.type.value == "fediverse_handle"}
    assert {h.lstrip("@") for h in handles} == {"exampledev@mastodon.example"}
    assert all(p.expand is False for p in res.pivots)
    links = [lnk for lnk in data.get("links") or [] if str(lnk.get("url", "")).startswith("http")]
    if links:
        possible = [p for p in res.pivots if p.confidence_label.value == "possible"]
        assert possible  # free-text links are POSSIBLE
    assert res.attributes["avatar_url"] == AVATAR.format(avatar_hash)  # a link, never embedded
    assert all("hidden" not in json.dumps(a) for a in card["verified_accounts"])


def test_org_profile_by_username_slug():
    data = fx("profile_org.json")
    http = FakeHttp().add("GET", PROFILE.format("gravatar"), json=data)
    avatar_found(http, data["hash"])
    res = run_module(MOD, "username:gravatar", http)
    assert res.status is Status.OK
    assert res.attributes["gravatar_profile"]["verified_accounts"] == []
    assert res.attributes["presence"]["state"] == "found"


def test_avatar_without_profile_is_reported_as_info():
    email = "dev@acme.com.br"
    h = sha(email)
    http = FakeHttp()
    env(http, PROFILE.format(h), "not_found.json")
    avatar_found(http, h)
    res = run_module(MOD, f"email:{email}", http)
    assert res.status is Status.OK
    assert res.findings[0].title == "Gravatar avatar without a public profile"
    assert res.attributes["avatar_hash"] == h


def test_rate_limit_is_could_not_verify():
    email = "dev@acme.com.br"
    http = FakeHttp()
    env(http, PROFILE.format(sha(email)), "rate_limited.json")
    res = run_module(MOD, f"email:{email}", http)
    assert res.status is Status.RATE_LIMITED


def test_challenge_and_errors_are_never_absent():
    email = "dev@acme.com.br"
    http = FakeHttp().add("GET", PROFILE.format(sha(email)), status=403, text=CHALLENGE)
    assert run_module(MOD, f"email:{email}", http).status is Status.BLOCKED
    http2 = FakeHttp().add("GET", PROFILE.format(sha(email)), status=502, text=fx("malformed.html"), times=3)
    assert run_module(MOD, f"email:{email}", http2).status is Status.ERROR
    http3 = FakeHttp().add("GET", PROFILE.format(sha(email)), json={"unexpected": True})
    assert run_module(MOD, f"email:{email}", http3).status is Status.ERROR


def test_avatar_check_failure_is_not_absence():
    email = "dev@acme.com.br"
    h = sha(email)
    http = FakeHttp()
    env(http, PROFILE.format(h), "not_found.json")
    http.add("GET", AVATAR.format(h), status=429, text="slow down")
    assert run_module(MOD, f"email:{email}", http).status is Status.RATE_LIMITED


def test_optional_key_is_a_bearer_header():
    email = "dev@acme.com.br"
    h = sha(email)
    http = FakeHttp()
    http.add("GET", PROFILE.format(h), status=404, json={"error": "Profile not found"}, match_headers={"Authorization": "Bearer grav-fixture-key-0000"})
    env(http, AVATAR.format(h), "avatar_absent.json")
    res = run_module(MOD, f"email:{email}", http, keys={"gravatar": "grav-fixture-key-0000"})
    assert res.status is Status.EMPTY


def test_parse_profile_is_defensive():
    assert parse_profile({"error": "Profile not found"}) is None
    assert parse_profile([1, 2]) is None
    assert parse_profile({"hash": "x", "verified_accounts": "nope", "links": [None, {"url": "ftp://x"}]})["verified_accounts"] == []
