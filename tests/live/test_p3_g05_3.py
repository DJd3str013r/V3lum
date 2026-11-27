"""Live checks of batch p3-G05-3 (x_twitter_public, x_twitter_recovery, wikimedia, x_archive_import,
name_permutations); run with ``V3LUM_LIVE=1 pytest -q -m live tests/live/test_p3_g05_3.py``.

Benign public values only: the U.S. Department of the Interior post that X's own oEmbed documentation uses
(twitter.com/Interior/status/507185938620219395), the non-existent status 1, and the organisation handle
'Interior' for the archive recovery (an official government account, never a private person). A
403/429/challenge or a connection reset from the datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (blocked / rate_limited / error), never as empty (rule 5).

Wikimedia: the live check never sends a contact address (no team role mailbox is configured on this egress
and none may be invented): it asserts that the module refuses to run without ``contact_email`` (SKIPPED
'config') and sends nothing. The offline modules run through the real engine and must not touch the network.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tests.fakes import FIXTURES
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR)
POST = "https://twitter.com/Interior/status/507185938620219395"


def _run(cls, etype: T, value: str, options: ScanOptions | None = None):
    runtime = Runtime(Config(), no_cache=True)
    return Engine(runtime, options or ScanOptions()).run_module(cls, Entity.make(etype, value))


def test_live_x_oembed_public_post_and_unavailable_post():
    from v3lum.modules.username_social.x_twitter_public import X_UNAVAILABLE_TEXT, XTwitterPublic

    res = _run(XTwitterPublic, T.URL, POST)
    if res.status in COULD_NOT_VERIFY:
        assert res.status is not Status.EMPTY and res.error
        pytest.skip(f"X oEmbed could not verify from this egress: {res.status.value} {res.reason_code} {res.error}")
    assert res.status is Status.OK, res.error
    assert res.attributes["x_post"]["handle"].lower() == "interior"
    assert res.attributes["created"].startswith("2014-09-03")
    assert set(res.hosts) <= {"publish.twitter.com", "publish.x.com"}
    gone = _run(XTwitterPublic, T.URL, "https://twitter.com/Interior/status/1")
    assert gone.status in (Status.OK, *COULD_NOT_VERIFY)
    if gone.status is Status.OK:
        assert gone.attributes["post_availability"] == X_UNAVAILABLE_TEXT


def test_live_x_recovery_reports_archive_state_honestly():
    from v3lum.modules.username_social.x_twitter_public import XTwitterRecovery

    opts = ScanOptions(purpose="live check of the deleted-post recovery on an official account", include={"x_twitter_recovery"})
    res = _run(XTwitterRecovery, T.USERNAME, "Interior", opts)
    assert res.status in (Status.OK, Status.EMPTY, *COULD_NOT_VERIFY), res.status
    assert set(res.hosts) <= {"web.archive.org", "publish.twitter.com", "publish.x.com"}
    if res.status in COULD_NOT_VERIFY:
        assert "could not verify" in res.error or res.reason_code in ("rate_limited", "challenge", "quota", "timeout")
        pytest.skip(f"Wayback CDX could not be verified from this egress: {res.status.value} {res.reason_code} {res.error}")
    if res.status is Status.OK:
        rec = res.attributes["x_recovery"]
        assert rec["archived_statuses"] >= 1 and rec["checked"] >= 1


def test_live_wikimedia_refuses_without_a_role_mailbox():
    from v3lum.modules.username_social.wikimedia import Wikimedia

    res = _run(Wikimedia, T.USERNAME, "Example")
    assert res.status is Status.SKIPPED and res.reason_code == "config"
    assert res.hosts == {}  # nothing was sent without the identifying contact UA


def test_live_offline_modules_never_touch_the_network(tmp_path: Path):
    from v3lum.modules.person_name.name_permutations import NamePermutations
    from v3lum.modules.username_social.x_archive_import import PROVENANCE_SUFFIX, XArchiveImport

    archive = tmp_path / "ok.zip"
    shutil.copyfile(FIXTURES / "x_archive_import" / "ok.zip", archive)
    (tmp_path / ("ok.zip" + PROVENANCE_SUFFIX)).write_text(json.dumps(
        {"source": "synthetic fixture", "date": "2026-11-26", "legal_basis": "account_holder"}), encoding="utf-8")
    res = _run(XArchiveImport, T.FILE, str(archive))
    assert res.status is Status.OK and res.hosts == {} and res.attributes["x_archive"]["posts"] == 30
    names = _run(NamePermutations, T.PERSON, "José Carlos de Oliveira Júnior")
    assert names.status is Status.OK and names.hosts == {}
    assert names.attributes["username_candidates"][0]["value"] == "joseoliveira"
