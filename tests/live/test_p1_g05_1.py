"""Live checks of batch p1-G05-1 (github_user, github_user_search, telegram_public): keyless sources,
benign public values only (Telegram's own channel, user and bot accounts; GitHub's octocat mascot).

Run once with ``V3LUM_LIVE=1 pytest -q -m live tests/live/test_p1_g05_1.py``. A 403/429/geo-block from a
datacenter egress is an acceptable outcome when the module reports it as blocked / rate_limited (rule 5):
the research egress refuses GitHub user paths with a proxy-policy 403 (P111 cond 10 recapture pending).
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
from v3lum.modules.username_social.github_user import GithubUser
from v3lum.modules.username_social.github_user_search import GithubUserSearch
from v3lum.modules.username_social.telegram_public import TME_GENERIC_REASON, TelegramPublic

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA)


def _run(cls, etype: T, value: str, *, preset: str = "quick"):
    runtime = Runtime(Config(), no_cache=True)
    return Engine(runtime, ScanOptions(preset=preset)).run_module(cls, Entity.make(etype, value))


def _could_not_verify(res) -> bool:
    """A refusal, or t.me's generic page for an account that certainly exists (t.me serves it to
    request bursts and some user agents: 'private or missing: could not read', never absent)."""
    return res.status in COULD_NOT_VERIFY or (res.status is Status.ERROR and TME_GENERIC_REASON in (res.error or ""))


def test_live_telegram_official_channel_and_posts():
    res = _run(TelegramPublic, T.TELEGRAM_HANDLE, "telegram")
    if _could_not_verify(res):
        pytest.skip(f"t.me could not be verified from this egress: {res.status.value} {res.error}")
    assert res.status is Status.OK, res.error
    assert res.attributes["presence"]["state"] == "found"
    assert res.attributes["account_type"] == "channel" and res.attributes.get("subscribers", 0) > 1_000_000
    assert res.attributes.get("has_preview") is True and res.attributes.get("posts_read", 0) >= 10
    assert set(res.hosts) <= {"t.me"} and res.requests <= TelegramPublic.max_requests


def test_live_telegram_user_and_generic_page():
    user = _run(TelegramPublic, T.TELEGRAM_HANDLE, "BotSupport")
    if _could_not_verify(user):
        pytest.skip(f"t.me could not be verified from this egress: {user.status.value} {user.error}")
    assert user.status is Status.OK and user.attributes["account_type"] == "user"
    assert set(user.attributes) == {"presence", "account_type", "display_name"}
    control = "zq" + "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(18))
    generic = _run(TelegramPublic, T.TELEGRAM_HANDLE, control)
    assert generic.status in (Status.ERROR, *COULD_NOT_VERIFY)  # never EMPTY/absent (P112 cond 2)
    if generic.status is Status.ERROR:
        assert TME_GENERIC_REASON in generic.error and generic.attributes["presence"]["state"] == "unknown"


def test_live_github_octocat_profile_or_could_not_verify():
    res = _run(GithubUser, T.USERNAME, "octocat")
    assert res.status in (Status.OK, *COULD_NOT_VERIFY), f"{res.status.value}: {res.error}"
    if res.status is Status.OK:
        assert res.attributes["presence"]["state"] == "found" and res.attributes["account_id"] == 583231
    else:
        assert "presence" not in res.attributes  # a refusal is never 'absent' (rule 5)


def test_live_github_name_search_or_could_not_verify():
    res = _run(GithubUserSearch, T.PERSON, "The Octocat")
    assert res.status in (Status.OK, Status.EMPTY, *COULD_NOT_VERIFY), f"{res.status.value}: {res.error}"
    if res.status is Status.OK:
        assert all(p.expand is False for p in res.pivots)
