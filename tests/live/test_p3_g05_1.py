"""Live checks of batch p3-G05-1 (keybase, hackernews, mastodon, memory_lol, reddit_archive, youtube); run with
``V3LUM_LIVE=1 pytest -q -m live tests/live/test_p3_g05_1.py``.

Benign public values only: organisation and bot accounts (Keybase's reserved 'cloudflare' account, the Hacker News
'whoishiring' bot, the Mastodon project account, the official 'reddit' account, the Google for Developers YouTube
channel and one of its videos), the documentation domain example.com and the 'github' handle on memory.lol. Every
module is keyless here (the YouTube Data API needs the team key and is not called). A 403/429/challenge or a timeout
from the datacenter egress is an acceptable outcome when the module reports it as could-not-verify (blocked /
rate_limited / quota / error), never as empty (rule 5).
"""

from __future__ import annotations

import pytest

from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR)


def _run(cls, etype: T, value: str):
    runtime = Runtime(Config(), no_cache=True)
    return Engine(runtime, ScanOptions()).run_module(cls, Entity.make(etype, value))


def _could_not_verify(res, what: str) -> None:
    if res.status in COULD_NOT_VERIFY:
        assert res.status is not Status.EMPTY and (res.error or res.reason_code)
        pytest.skip(f"{what} could not verify from this egress: {res.status.value} {res.reason_code} {res.error[:200]}")


def test_live_keybase_reserved_org_account_and_unproven_domain():
    from v3lum.modules.username_social.keybase import BANNER, Keybase

    res = _run(Keybase, T.USERNAME, "cloudflare")
    _could_not_verify(res, "Keybase")
    assert res.status is Status.OK, res.error
    prof = res.attributes["keybase_profile"][0]
    assert prof["username"] == "cloudflare" and prof["has_sigchain"] is False
    assert BANNER in res.attributes["data_notices"] and set(res.hosts) == {"keybase.io"}
    dom = _run(Keybase, T.DOMAIN, "example.com")
    assert dom.status in (Status.EMPTY, Status.OK, *COULD_NOT_VERIFY)
    if dom.status is Status.EMPTY:
        assert "no Keybase user has proven" in dom.error


def test_live_hackernews_bot_account_and_activity():
    from v3lum.modules.username_social.hackernews import HackerNews

    res = _run(HackerNews, T.USERNAME, "whoishiring")
    _could_not_verify(res, "Hacker News")
    assert res.status is Status.OK, res.error
    acc = res.attributes["hn_account"]
    assert acc["id"] == "whoishiring" and acc["created"].startswith("2010-10-20") and acc["submitted_count"] > 100
    assert set(res.hosts) <= {"hacker-news.firebaseio.com", "hn.algolia.com"}
    if "hn_activity" in res.attributes:  # Algolia may refuse the datacenter egress: reported per source, never empty
        assert res.attributes["hn_activity"]["items_total"] > 0
    else:
        assert res.source_statuses.get("algolia.hn_search")


def test_live_mastodon_project_account_on_home_instance():
    from v3lum.modules.username_social.mastodon import Mastodon

    res = _run(Mastodon, T.FEDIVERSE_HANDLE, "@Mastodon@mastodon.social")
    _could_not_verify(res, "mastodon.social")
    assert res.status is Status.OK, res.error
    acc = res.attributes["fediverse_account"]
    assert acc["acct"] == "mastodon@mastodon.social" and acc["created_at"].startswith("2016")
    assert any(f["verified"] for f in acc["fields"])  # rel=me verified links (cond 5)
    assert set(res.hosts) == {"mastodon.social"} and res.attributes["disclosed_to"] == ["mastodon.social"]


def test_live_memory_lol_empty_window_wording():
    from v3lum.modules.username_social.memory_lol import EMPTY_WORDING, MemoryLol

    res = _run(MemoryLol, T.USERNAME, "github")
    _could_not_verify(res, "memory.lol")
    assert res.status in (Status.EMPTY, Status.OK), res.error
    if res.status is Status.EMPTY:
        assert EMPTY_WORDING in res.error  # never 'no previous handles' (cond 3)
    assert set(res.hosts) == {"api.memory.lol"}


def test_live_reddit_archive_official_account():
    from v3lum.modules.username_social.reddit_archive import RedditArchive

    res = _run(RedditArchive, T.USERNAME, "reddit")
    _could_not_verify(res, "Arctic Shift")
    assert res.status is Status.OK, res.error
    act = res.attributes["reddit_activity"]
    assert act["posts"] + act["comments"] > 0 and act["last_activity"]
    assert "subreddit" not in str(act).lower()
    assert set(res.hosts) == {"arctic-shift.photon-reddit.com"}


def test_live_youtube_keyless_feed_and_oembed():
    from v3lum.modules.username_social.youtube import YouTube

    res = _run(YouTube, T.KEYWORD, "UC_x5XG1OV2P6uZZ5FSM9Ttw")
    _could_not_verify(res, "YouTube feed")
    assert res.status is Status.OK, res.error
    ch = res.attributes["youtube_channel"]
    assert ch["channel_id"] == "UC_x5XG1OV2P6uZZ5FSM9Ttw" and ch["created"].startswith("2007-08-23")
    assert res.attributes["youtube_uploads"]["uploads_in_feed"] > 0
    assert set(res.hosts) == {"www.youtube.com"}  # no Data API call without the team key
    vid = _run(YouTube, T.URL, "https://www.youtube.com/watch?v=WN5O4vWCa54")
    assert vid.status in (Status.OK, Status.EMPTY, *COULD_NOT_VERIFY)
    if vid.status is Status.OK:
        assert vid.attributes["youtube_video"]["author_url"].startswith("https://www.youtube.com/")
    handle = _run(YouTube, T.USERNAME, "googledevelopers")
    assert handle.status is Status.NEEDS_KEY and handle.hosts == {}  # never scraped (cond 1)
