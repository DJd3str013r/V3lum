"""Live checks of batch p3-G05-2 (git_metadata_identity, the P116 community profile enrichers, tiktok_public):
keyless sources, benign public values only - organisation and system accounts (the official Chess.com, Lichess,
Medium, Snapchat, Disqus and Pinterest accounts, Mojang's MHF_Steve helper, Stack Exchange's 'Community' user -1,
the public github/gitignore repository) plus random never-registered control handles. No private person's
identifier is sent anywhere. TikTok is never contacted: its terms class is 'license' and this build has no
provider_grant, so the check asserts the licence gate itself (no request).

Run once with ``V3LUM_LIVE=1 pytest -q -m live tests/live/test_p3_g05_2.py``. A 403/429/challenge or an egress-proxy
refusal from a datacenter egress is an acceptable outcome when the module reports it as blocked / rate_limited (rule 5).
"""

from __future__ import annotations

import secrets
import string

import pytest

from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.username_social import community_profiles as cp
from v3lum.modules.username_social.git_metadata_identity import GitMetadataIdentity
from v3lum.modules.username_social.tiktok_public import TiktokPublic

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA)


def _run(cls, etype: T, value: str, options: ScanOptions | None = None):
    runtime = Runtime(Config(), no_cache=True)
    return Engine(runtime, options or ScanOptions()).run_module(cls, Entity.make(etype, value))


def _control(n: int = 18) -> str:
    return "zq" + "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _skip_if_refused(res) -> None:
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"{res.module} could not verify from this egress: {res.status.value} {res.reason_code} {res.error}")


def test_live_steam_xml_absence_is_a_200_with_error():
    res = _run(cp.SteamCommunityProfile, T.URL, f"https://steamcommunity.com/id/{_control()}/")
    _skip_if_refused(res)
    assert res.status is Status.EMPTY, res.error  # 'The specified profile could not be found.'


def test_live_chesscom_official_account():
    res = _run(cp.ChesscomPlayer, T.URL, "https://www.chess.com/member/chesscom")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["account_id"] and res.attributes["created"]
    absent = _run(cp.ChesscomPlayer, T.URL, f"https://www.chess.com/member/{_control()}")
    assert absent.status in (Status.EMPTY, *COULD_NOT_VERIFY)


def test_live_lichess_official_account():
    res = _run(cp.LichessUser, T.URL, "https://lichess.org/@/lichess")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["created"].startswith("2010")


def test_live_medium_official_feed():
    res = _run(cp.MediumFeed, T.URL, "https://medium.com/@Medium")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["platform_facts"]["posts_in_feed"] >= 1


def test_live_snapchat_official_profile():
    res = _run(cp.SnapchatProfile, T.URL, "https://www.snapchat.com/@teamsnapchat")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error  # the schema check holds on today's page
    assert res.attributes["platform_facts"]["username"].lower() == "teamsnapchat"


def test_live_disqus_official_profile_page():
    res = _run(cp.DisqusProfile, T.URL, "https://disqus.com/by/disqus/")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["platform_facts"]["username"] == "disqus"


def test_live_mojang_helper_account():
    res = _run(cp.MojangProfile, T.URL, "https://api.mojang.com/users/profiles/minecraft/MHF_Steve")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert len(res.attributes["account_id"]) == 32


def test_live_pinterest_official_account():
    res = _run(cp.PinterestProfile, T.URL, "https://www.pinterest.com/pinterest/")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["display_name"]


def test_live_stackexchange_community_user():
    res = _run(cp.StackexchangeUser, T.URL, "https://stackoverflow.com/users/-1/community")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["display_name"] == "Community" and res.attributes["data_attribution"]


def test_live_git_metadata_public_repository():
    opts = ScanOptions(purpose="build live check: public github/gitignore repository (organisation-owned)")
    res = _run(GitMetadataIdentity, T.URL, "https://github.com/github/gitignore", options=opts)
    _skip_if_refused(res)  # the research egress proxy refuses api.github.com paths (BLOCKED, could not verify)
    assert res.status in (Status.OK, Status.EMPTY), res.error
    assert not res.attributes.get("git_identities")  # an organisation never authors commits: members are counted only


def test_live_tiktok_never_contacted_without_a_provider_grant():
    res = _run(TiktokPublic, T.USERNAME, "tiktok")
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    assert not res.hosts
    assert any(url == "https://www.tiktok.com/@tiktok" for _label, url in res.links)
