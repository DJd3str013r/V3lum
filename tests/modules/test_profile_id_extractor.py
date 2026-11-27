"""P107 profile_id_extractor: the shared no-network helper (batch p2-G05-2).

Saved pages are trimmed real captures (LIVE) or documentation-shaped pages with documentation values
(``tests/fixtures/profile_id_extractor/pages.json`` records the origin of each); one per enabled scheme
(cond 7).
"""

from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path

import pytest

from tests.fakes import fixture, module_fixture
from v3lum.core import lint
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult
from v3lum.modules.username_social import profile_id_extractor as pid

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "profile_id_extractor"
PAGES = module_fixture("profile_id_extractor", "pages.json")["pages"]


def page(name: str) -> tuple[str, str]:
    return (FIX / name).read_text(encoding="utf-8"), PAGES[name]["url"]


def result_for(value: str = "example-dev") -> ModuleResult:
    return ModuleResult(module="github_user", entity=Entity.make(T.USERNAME, value))


# ------------------------------------------------------------------------------------- cond 1/2/7


def test_every_enabled_scheme_has_a_saved_page():
    covered = {meta["scheme"] for meta in PAGES.values() if meta["scheme"] in pid.ENABLED_SCHEMES}
    assert covered == set(pid.ENABLED_SCHEMES)  # cond 7: one trimmed saved page per enabled scheme


@pytest.mark.parametrize("name", sorted(n for n, m in PAGES.items() if m["scheme"] in pid.ENABLED_SCHEMES and m["origin"] != "SYNTHETIC"))
def test_every_saved_page_extracts_with_its_pinned_scheme(name):
    text, url = page(name)
    assert pid.scheme_for_url(url) == PAGES[name]["scheme"]
    out = pid.extract_profile_fields(text, url)
    assert out.get("_extractor") == PAGES[name]["scheme"] and "_error" not in out
    assert all(isinstance(v, str) for v in out.values())


def test_scheme_pinning_by_host_and_path():
    assert pid.scheme_for_url("https://api.github.com/users/example-dev") == "GitHub API"
    assert pid.scheme_for_url("https://api.github.com/search/users?q=x+type:org") is None
    assert pid.scheme_for_url("https://api.github.com.example.net/users/x") is None
    assert pid.scheme_for_url("https://t.me/s/telegram") is None
    assert pid.scheme_for_url("https://my.mail.ru/mail/example/") is None
    assert pid.scheme_for_url("https://about.me/microsoft") is None
    assert pid.scheme_for_url("ftp://gitlab.com/api/v4/users") is None
    assert pid.scheme_for_url(None) is None
    assert "My Mail.ru" in pid.NOT_ENABLED_SCHEMES
    assert not set(pid.ENABLED_SCHEMES) & set(pid.NOT_ENABLED_SCHEMES)


def test_a_search_body_with_profile_flags_never_reaches_the_user_scheme():
    body = json.dumps({"total_count": 1, "items": [{"login": "example-org", "gists_url": "x", "received_events_url": "y"}]})
    assert pid.extract_profile_fields(body, "https://api.github.com/search/users?q=example+type:org") == {}
    assert pid.extract_profile_ids("https://api.github.com/search/users?q=example", body) is None


def test_body_is_capped_at_two_megabytes_before_any_regex():
    text, truncated = pid.cap_body(b"a" * (pid.MAX_BODY_BYTES + 10))
    assert truncated and len(text.encode()) == pid.MAX_BODY_BYTES
    assert pid.cap_body(b"\xef\xbb\xbfsmall") == ("small", False)
    assert pid.cap_body(None) == ("", False)
    big = '{"did":"x","handle":"x","followersCount":1,"pad":"' + "z" * pid.MAX_BODY_BYTES + '"}'
    out = pid.extract_profile_fields(big, "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=x")
    assert out == {"_extractor": "Bluesky API", "_error": "regex_no_match", "_truncated": "True"}  # cut JSON never parses


def test_the_helper_imports_no_network_or_socid_code():
    source = Path(pid.__file__).read_text(encoding="utf-8")
    for banned in ("import socket", "import requests", "urllib.request", "http.client", "socid_extractor import", "import socid"):
        assert banned not in source
    assert "socid_extractor" not in sys.modules  # the library is never imported (plugin execution on import)
    issues = lint.blocking(lint.lint_module_source(Path(pid.__file__)))
    assert issues == []


# ------------------------------------------------------------------------------------- per scheme


def test_github_api_page():
    out = pid.extract_profile_fields(*page("github_api_ok.json"))
    assert out["uid"] == "1000001" and out["fullname"] == "Example Dev" and out["created_at"] == "2015-04-02T12:00:00Z"
    assert out["twitter_username"] == "example_dev" and out["blog_url"] == "https://dev.example.com"
    assert out["bio"] == "Security engineer." and "gravatar_id" not in out


def test_gitlab_api_pages_and_gravatar_postprocessor():
    out = pid.extract_profile_fields(*page("gitlab_api_ok.json"))
    assert out["uid"] == "1786152" and out["username"] == "gitlab-bot" and out["state"] == "active" and "email" not in out
    out = pid.extract_profile_fields(*page("gitlab_api_public_email.json"))
    md5 = hashlib.md5(b"dev@example.com").hexdigest()
    assert out["email"] == "dev@example.com" and out["email_username"] == "dev"
    assert out["gravatar_email_md5_hash"] == md5 and out["gravatar_url"] == f"https://gravatar.com/{md5}"


def test_dockerhub_api_page_reads_date_joined():
    out = pid.extract_profile_fields(*page("dockerhub_api_ok.json"))
    assert out["username"] == "exampledev" and out["type"] == "User"
    assert out["created_at"] == "2019-01-15T12:00:00.000000Z"  # socid 0.1.2 reads the typo 'data_joined': fixed here
    org = json.dumps({"id": "x", "orgname": "docker", "type": "Organization", "profile_url": "https://www.docker.com"},
                     separators=(",", ":"))
    assert pid.extract_profile_fields(org, "https://hub.docker.com/v2/users/docker/") == {}


def test_bluesky_huggingface_keybase_pages():
    out = pid.extract_profile_fields(*page("bluesky_api_ok.json"))
    assert out["uid"] == "did:plc:z72i7hdynmk6r22z27h6tvur" and out["username"] == "bsky.app"
    out = pid.extract_profile_fields(*page("huggingface_api_ok.json"))
    assert out["uid"] == "635fd4cc14657fb8cff2a081" and out["username"] == "SFconvertbot" and out["is_pro"] == "False"
    out = pid.extract_profile_fields(*page("keybase_api_ok.json"))
    assert out["twitter_username"] == "example_dev" and out["github_username"] == "example-dev" and "reddit_username" not in out


def test_gravatar_pages():
    out = pid.extract_profile_fields(*page("gravatar_json_ok.json"))
    assert out["username"] == "automattic" and out["name"] == "Automattic"
    assert out["gravatar_email_sha256_hash"].startswith("9f3d4f18")
    out = pid.extract_profile_fields(*page("gravatar_json_accounts.json"))
    assert out["gravatar_id"] == "1000003"
    assert ast.literal_eval(out["links"]) == ["https://github.com/example-dev", "https://x.com/example_dev", "https://dev.example.com"]


def test_html_scheme_pages():
    out = pid.extract_profile_fields(*page("telegram_ok.html"))
    assert out["fullname"] == "BotFather" and out["bio"].startswith("BotFather is the one bot")
    out = pid.extract_profile_fields(*page("dribbble_ok.html"))
    assert out["username"] == "dribbble" and out["image"].startswith("https://cdn.dribbble.com/")


def test_linktree_pages():
    out = pid.extract_profile_fields(*page("linktree_ok.html"))
    assert out["id"] == "18563289" and out["tier"] == "paid2" and "social_links" not in out
    out = pid.extract_profile_fields(*page("linktree_social.html"))
    assert ast.literal_eval(out["social_links"])["email"] == "mailto:dev@example.com"


def test_no_match_stale_and_malformed_pages():
    assert pid.extract_profile_fields(*page("aboutme_stale_scheme.html")) == {}
    assert pid.extract_profile_fields(*page("no_scheme.html")) == {}
    assert pid.extract_profile_fields(*page("malformed_json.json")) == {"_extractor": "Gitlab API", "_error": "malformed_json"}
    assert pid.extract_profile_fields("<html>gists_url received_events_url</html>", "https://api.github.com/users/example-dev") == {
        "_extractor": "GitHub API", "_error": "regex_no_match"}


# ------------------------------------------------------------------------------------- cond 3-6


def test_is_plausible_username_vectors():
    for ok in ("alice", "alice.bob", "alice_bob-42", "Алиса", "httpie", "wwwsuperstar"):
        assert pid.is_plausible_username(ok), ok
    for bad in ("https://gravatar.com/alice", "//example.com/alice", "www.facebook.com/zuck", "user/alice",
                "alice@example.com", "", "   ", None, 42):
        assert not pid.is_plausible_username(bad), bad


def test_normaliser_on_hostile_owner_written_output():
    fields = module_fixture("profile_id_extractor", "socid_output_mixed.json")
    out = pid.normalise_profile_ids(fields, "https://en.gravatar.com/exampledev.json")
    rejected = {(k, v): r for k, v, r in out["rejected"]}
    assert rejected[("twitter_username", "https://twitter.com/example_dev")] == "url"
    assert rejected[("instagram_username", "user@example.com")] == "email"
    assert rejected[("reddit_username", "example dev")] == "whitespace"
    assert rejected[("telegram_username", "example/dev")] == "path"
    assert rejected[("email_username", "dev")] == "derived_from_email"
    assert rejected[("links", "javascript:alert(1)")] == "not_http_url"
    assert rejected[("links", "https://192.0.2.10/admin")] == "ip_or_bad_host"
    accounts = {(a["platform"], a["handle"]) for a in out["linked_accounts"]}
    assert {("github", "example-dev"), ("x", "example_dev"), ("instagram", "example_dev"), (None, "example_dev2")} <= accounts
    assert all(a["source_page"] == "https://en.gravatar.com/exampledev.json" for a in out["linked_accounts"])
    assert out["links"] == ["https://dev.example.com"]
    assert out["personal"]["emails"] == ["dev@example.com"] and out["personal"]["phones"] == ["+55 11 5555-0123"]
    assert out["attributes"]["uid"] == "1000003"
    assert out["gravatar_hashes"] == [{"algo": "md5", "hash": hashlib.md5(b"dev@example.com").hexdigest()}]
    assert out["own_username"] == "exampledev"


def test_own_profile_link_is_not_a_linked_account():
    info = pid.extract_profile_ids(PAGES["gitlab_api_ok.json"]["url"], page("gitlab_api_ok.json")[0])
    assert info["platform"] == "gitlab" and info["own_username"] == "gitlab-bot" and info["linked_accounts"] == []
    assert info["avatar_urls"][0].startswith("https://gitlab.com/uploads/-/system/user/avatar/")
    assert pid.normalise_profile_ids("not a dict", "x")["error"] == "not_a_dict"


def test_apply_records_attributes_and_expand_false_pivots_only():
    text, url = page("gravatar_json_accounts.json")
    info = pid.extract_profile_ids(url, text)
    res = result_for()
    made = pid.apply_profile_ids(res, info)
    assert made == len(res.pivots) and made >= 5
    assert res.attributes["profile_ids"]["fields"]["gravatar_id"] == "1000003"
    assert res.attributes["profile_ids"]["source_page"] == url
    assert {(a["platform"], a["handle"]) for a in res.attributes["linked_accounts"]} >= {("github", "example-dev"), ("x", "example_dev")}
    assert res.attributes["profile_personal"]["confidence"] == "possible"
    assert all(p.expand is False for p in res.pivots)  # cond 4/6: nothing auto-expands
    assert all(p.confidence_label.value == "possible" for p in res.pivots)
    assert all("owner-written" in p.note for p in res.pivots)  # cond 7
    by_type = {p.entity.type: p for p in res.pivots}
    assert by_type[T.EMAIL].relation == "email_on_profile" and "breach" in by_type[T.EMAIL].note
    assert by_type[T.PERSON].relation == "name_on_profile" and "person_name" in by_type[T.PERSON].note
    assert {p.entity.value for p in res.pivots if p.entity.type is T.SOCIAL_ACCOUNT} >= {"github:example-dev", "x:example_dev"}
    assert any(p.entity.type is T.URL and p.relation == "link_on_profile" for p in res.pivots)


def test_apply_maps_bluesky_and_telegram_to_their_handle_types():
    res = result_for()
    info = {"scheme": "Gravatar", "source_page": "https://en.gravatar.com/x.json", "attributes": {}, "personal": {},
            "linked_accounts": [{"platform": "telegram", "handle": "example_dev"}, {"platform": "bluesky", "handle": "example.bsky.social"},
                                {"platform": None, "handle": "example_dev2"}], "links": []}
    pid.apply_profile_ids(res, info)
    types = {p.entity.type for p in res.pivots}
    assert {T.TELEGRAM_HANDLE, T.BSKY_HANDLE, T.USERNAME} <= types
    bare = next(p for p in res.pivots if p.entity.type is T.USERNAME)
    assert "analyst-typed seed" in bare.note  # cond 5: bare handles never reach the packs automatically


def test_apply_ignores_pages_without_a_scheme():
    res = result_for()
    assert pid.apply_profile_ids(res, None) == 0
    assert pid.apply_profile_ids(res, pid.normalise_profile_ids({}, "https://www.example.com/")) == 0
    assert res.pivots == [] and res.attributes == {}


def test_plan_profile_expansion_rules():
    accs = [{"platform": "github", "handle": "example-dev"}, {"platform": "gitlab", "handle": "example-dev"},
            {"platform": "bluesky", "handle": "example.bsky.social"}, {"platform": "instagram", "handle": "ex"},
            {"platform": None, "handle": "example_dev2"}]
    plan = pid.plan_profile_expansion(accs)
    assert plan["enrich"] == [] and plan["needs_confirmation"] == ["example_dev2"]
    assert ("github:example-dev", "default_preset_expand_false") in plan["held"]
    plan = pid.plan_profile_expansion(accs, preset="deep", link_confidence="probable")
    assert [e[0] for e in plan["enrich"]] == ["github", "gitlab"]  # at most 2 per seed
    assert ("bluesky:example.bsky.social", "auto_cap") in plan["held"]
    assert ("instagram:ex", "no_platform_enricher") in plan["held"]
    assert pid.plan_profile_expansion(accs, preset="deep", link_confidence="possible")["enrich"] == []
    plan = pid.plan_profile_expansion(accs, preset="deep", link_confidence="probable", depth=1)
    assert plan["enrich"] == [] and all(r == "depth" for _, r in plan["held"])
    plan = pid.plan_profile_expansion(accs, analyst_selected=["bluesky:example.bsky.social", "example_dev2"])
    assert plan["enrich"] == [("bluesky", "example.bsky.social", "bluesky")] and plan["promote_to_seed"] == ["example_dev2"]


def test_literal_values_are_never_evaluated():
    assert pid._parse_value("['a', 'b']") == ["a", "b"]
    assert pid._parse_value("[__import__('os')]") == "[__import__('os')]"
    assert pid._parse_value("[" * 100000) == "[" * 100000


def test_pages_manifest_is_a_fixture():
    assert fixture("profile_id_extractor/pages.json")["pages"]
