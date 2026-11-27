"""Pack-level tests of P116 community_profiles_pack (v3lum/modules/username_social/community_profiles.py):
the FC2 lint (Duolingo and e-mail/phone lookups impossible by construction), the FC3 URL gate, FC4/FC9
metadata per platform and the FC8 content-relevance rule. Platform behaviour is tested per module
(tests/modules/test_<module>.py)."""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.username_social import community_profiles as cp

MODULES = {
    "steam": cp.SteamCommunityProfile, "chesscom": cp.ChesscomPlayer, "lichess": cp.LichessUser, "medium": cp.MediumFeed,
    "snapchat": cp.SnapchatProfile, "disqus": cp.DisqusProfile, "mojang": cp.MojangProfile, "pinterest": cp.PinterestProfile,
    "stackexchange": cp.StackexchangeUser,
}


def test_built_specs_lint_clean_and_duolingo_is_impossible():
    assert cp.lint_pack_specs(cp.PLATFORM_SPECS) == []
    assert not any("duolingo" in str(s).lower() for s in cp.PLATFORM_SPECS)
    for spec in cp.PLATFORM_SPECS:
        assert not set(spec["inputs"]) & {"email", "phone"}
    assert cp.profile_url_to_handle("https://www.duolingo.com/profile/example") is None
    for cls in MODULES.values():
        assert not ({T.EMAIL, T.PHONE} & set(cls.accepts)), cls.name
        assert not any("duolingo" in h for h in cls.hosts)


def test_lint_flags_email_phone_duolingo_and_templated_hosts():
    bad = module_fixture("community_profiles", "pack_specs_bad_synthetic.json")["specs"]
    problems = cp.lint_pack_specs(bad)
    ids = {sid for sid, _ in problems}
    assert {"duolingo_email", "duolingo_username", "phone_param"} <= ids
    assert any("email" in p for _, p in problems) and any("Duolingo" in p for _, p in problems)


@pytest.mark.parametrize("url,platform,kind,handle", [
    ("https://steamcommunity.com/id/exampleplayer/", "steam", "username", "exampleplayer"),
    ("https://steamcommunity.com/profiles/76561190000000001", "steam", "steam_id64", "76561190000000001"),
    ("https://www.chess.com/member/ExampleStreamer", "chesscom", "username", "ExampleStreamer"),
    ("https://lichess.org/@/ExampleTos", "lichess", "username", "ExampleTos"),
    ("https://medium.com/@example.writer/about", "medium", "username", "example.writer"),
    ("https://www.snapchat.com/add/exampleshop", "snapchat", "username", "exampleshop"),
    ("https://disqus.com/by/exampleuser/", "disqus", "username", "exampleuser"),
    ("https://namemc.com/profile/MHF_Steve.1", "mojang", "username", "MHF_Steve"),
    ("https://br.pinterest.com/exampleshop/", "pinterest", "username", "exampleshop"),
    ("https://stackoverflow.com/users/-1/community", "stackexchange", "user_id", "-1"),
    ("https://stackoverflow.com/users/filter?search=Example%20Dev", "stackexchange", "display_name", "Example Dev"),
])
def test_has_account_urls_map_to_one_platform(url, platform, kind, handle):
    hit = cp.profile_url_to_handle(url)
    assert hit and (hit["platform"], hit["kind"], hit["handle"]) == (platform, kind, handle)
    ent = Entity.make(T.URL, url)
    assert [name for name, cls in MODULES.items() if cls().applies(ent, None)] == [platform]


@pytest.mark.parametrize("url", [
    "https://www.pinterest.com/ideas/", "https://user:pw@lichess.org/@/x", "ftp://lichess.org/@/x",
    "https://evil.example/lichess.org/@/x", "https://steamcommunity.com/groups/example", "https://www.twitch.tv/example",
])
def test_other_urls_never_reach_a_platform(url):
    assert cp.profile_url_to_handle(url) is None


def test_request_urls_use_literal_hosts_and_encoded_handles():
    assert cp.platform_request_url("chesscom", "ExampleStreamer") == "https://api.chess.com/pub/player/examplestreamer"
    assert cp.platform_request_url("steam", "76561190000000001", "steam_id64") == "https://steamcommunity.com/profiles/76561190000000001/?xml=1"
    assert cp.platform_request_url("lichess", "../admin") is None
    assert cp.platform_request_url("stackexchange", "Example Dev", "display_name").endswith("inname=Example%20Dev&site=stackoverflow")
    assert cp.platform_request_url("duolingo", "example") is None


def test_council_metadata_per_platform():
    for name, cls in MODULES.items():
        assert cls.default_enabled is False, name  # FC3
        assert cls.disclosure == "third_party" and cls.run_on == "any"
        assert cls.max_requests == (2 if name == "stackexchange" else 1)
    assert cp.SnapchatProfile.terms == "unknown" and cp.DisqusProfile.terms == "unknown"  # FC4: disabled until legal
    for name in ("steam", "chesscom", "lichess", "medium", "mojang", "pinterest", "stackexchange"):
        assert MODULES[name].terms == "open", name
    assert cp.LichessUser.trust_tier == "community"  # FC9
    assert all(MODULES[n].trust_tier == "trusted" for n in MODULES if n != "lichess")
    assert cp.DisqusProfile.optional_keys == ("disqus",) and cp.StackexchangeUser.optional_keys == ("stackexchange",)


def test_content_is_shown_only_when_it_mentions_a_case_entity():
    url = "https://lichess.org/api/user/ExampleTos"
    body = module_fixture("lichess_user", "tos_synthetic.json")
    http = FakeHttp().add("GET", url, json=body)
    res = run_module(cp.LichessUser, "url:https://lichess.org/@/ExampleTos", http)
    assert res.status is Status.OK
    assert "profile_content" not in res.attributes and res.attributes["content_withheld"] == ["bio", "flag", "location", "real_name"]
    assert "Example Person" not in str(res.to_dict())
    opts = ScanOptions(seed_tlp={"domain:example.org": "amber"})
    http = FakeHttp().add("GET", url, json=body)
    res = run_module(cp.LichessUser, "url:https://lichess.org/@/ExampleTos", http, options=opts)
    assert res.attributes["profile_content"]["bio"] == "see example.org/about"
    assert res.attributes["bio"] == "see example.org/about"
