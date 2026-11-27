"""Live checks of batch p2-G05-1 (bluesky, npm_maintainer, pypi_package, codeberg_user, devto_user,
huggingface_user, discord_invite, dockerhub, gitlab_user): keyless sources, benign public values only
(official organisation/bot accounts: Bluesky's bsky.app, npm's 'npm', PyPA's sampleproject, Forgejo,
DEV's staff account, Hugging Face's conversion bot, Discord's developer server, the docker organisation,
GitLab's bot) plus random never-registered control handles.

Run once with ``V3LUM_LIVE=1 pytest -q -m live tests/live/test_p2_g05_1.py``. A 403/429/challenge from a
datacenter egress is an acceptable outcome when the module reports it as blocked / rate_limited (rule 5).
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
from v3lum.modules.username_social.bluesky import Bluesky
from v3lum.modules.username_social.dev_profiles import CodebergUser, DevtoUser, HuggingfaceUser, NpmMaintainer, PypiPackage
from v3lum.modules.username_social.discord_invite import DiscordInvite
from v3lum.modules.username_social.dockerhub import Dockerhub
from v3lum.modules.username_social.gitlab_user import GitlabUser

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA)


def _run(cls, etype: T, value: str):
    runtime = Runtime(Config(), no_cache=True)
    return Engine(runtime, ScanOptions()).run_module(cls, Entity.make(etype, value))


def _control() -> str:
    return "zq" + "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(18))


def _skip_if_refused(res) -> None:
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"{res.module} could not verify from this egress: {res.status.value} {res.reason_code} {res.error}")


def test_live_bluesky_official_handle_is_confirmed():
    res = _run(Bluesky, T.BSKY_HANDLE, "bsky.app")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["bsky_profile"]["did"].startswith("did:plc:")
    assert res.attributes["bsky_domain_link"]["confidence"] == "confirmed"
    assert res.attributes["handle_history"]["timeline"]
    assert set(res.hosts) <= {"public.api.bsky.app", "plc.directory", "dns.google", "cloudflare-dns.com"}
    absent = _run(Bluesky, T.USERNAME, _control())
    assert absent.status in (Status.EMPTY, *COULD_NOT_VERIFY)


def test_live_npm_registry_search():
    res = _run(NpmMaintainer, T.USERNAME, "npm")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["registry_packages"] and res.attributes["platform_summary"]["platform"] == "npm"
    absent = _run(NpmMaintainer, T.USERNAME, _control())
    assert absent.status in (Status.EMPTY, *COULD_NOT_VERIFY)


def test_live_pypi_sampleproject():
    res = _run(PypiPackage, T.KEYWORD, "sampleproject")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["pypi_project"]["release_count"] >= 5


def test_live_codeberg_forgejo():
    res = _run(CodebergUser, T.USERNAME, "forgejo")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["created"].startswith("2022-")
    absent = _run(CodebergUser, T.USERNAME, _control())
    assert absent.status in (Status.EMPTY, *COULD_NOT_VERIFY)


def test_live_devto_staff_account_or_bot_block():
    res = _run(DevtoUser, T.USERNAME, "thepracticaldev")
    _skip_if_refused(res)  # the DEV edge answered 'Forbidden Bots' to the research egress (BLOCKED, never absent)
    assert res.status is Status.OK, res.error
    assert res.attributes["created"].startswith("2016-")


def test_live_huggingface_bot():
    res = _run(HuggingfaceUser, T.USERNAME, "SFconvertbot")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["platform_summary"]["platform"] == "huggingface"
    absent = _run(HuggingfaceUser, T.USERNAME, _control())
    assert absent.status in (Status.EMPTY, *COULD_NOT_VERIFY)


def test_live_discord_developers_invite():
    res = _run(DiscordInvite, T.URL, "https://discord.gg/discord-developers")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["discord_invite"]["guild"]["id"] == "613425648685547541"
    assert res.attributes["members"] > 1000
    expired = _run(DiscordInvite, T.DISCORD_INVITE, _control())
    assert expired.status in (Status.EMPTY, *COULD_NOT_VERIFY)


def test_live_dockerhub_docker_organisation():
    res = _run(Dockerhub, T.USERNAME, "docker")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["account_type"] == "org"
    assert set(res.hosts) <= {"hub.docker.com"}
    assert res.requests <= Dockerhub.max_requests


def test_live_gitlab_bot():
    res = _run(GitlabUser, T.USERNAME, "gitlab-bot")
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["account_id"] == 1786152
    absent = _run(GitlabUser, T.USERNAME, _control())
    assert absent.status in (Status.EMPTY, *COULD_NOT_VERIFY)
