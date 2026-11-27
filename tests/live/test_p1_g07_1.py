"""Live checks of batch p1-G07-1 (otx_keyless, abusech, ioc_feeds_offline); run with V3LUM_LIVE=1.

Keyless sources only, benign values only:
* otx_keyless: the 'general' section of 8.8.8.8 (allow-listed on OTX) and CVE-2021-44228;
* abusech without the Auth-Key: the single coverage line and no API request, then the CC0 Feodo
  Tracker and SSLBL lists through the dataset manager and a local match;
* ioc_feeds_offline: TweetFeed (week), signature-base hash/C2 and the CIRCL manifest through the
  dataset manager, then local matches of values taken from the downloaded copies (the 42 MB CIRCL
  hashes.csv is left to `v3lum data update`).
The keyed otx module, the licence-gated abuse.ch APIs (no team key yet) and ioc_feeds_unreviewed
(terms 'unknown': disabled until legal records a class) are not run live.

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR), never as an absence.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum import paths
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.threat_intel_ioc import abusech, ioc_feeds_offline
from v3lum.modules.threat_intel_ioc.abusech import Abusech
from v3lum.modules.threat_intel_ioc.ioc_feeds_offline import IocFeedsOffline
from v3lum.modules.threat_intel_ioc.otx import OtxKeyless

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR}


def live_runtime():
    return Runtime(Config(), no_cache=True)


def test_otx_keyless_general_8888():
    res = run_module(OtxKeyless, "ipv4:8.8.8.8", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert [f.severity.label for f in res.findings] == ["info"]  # allow-listed: never malicious
        assert res.attributes["allowlisted"]


def test_otx_keyless_general_cve():
    res = run_module(OtxKeyless, "cve:CVE-2021-44228", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["otx_pulse_count"] > 0
        assert not any("malicious" in f.tags for f in res.findings)  # CVEs are never tagged malicious


def test_abusech_without_key_sends_nothing():
    http = FakeHttp()
    res = run_module(Abusech, "url:https://example.com/", http)
    assert res.status is Status.NEEDS_KEY and res.error == abusech.NO_KEY_LINE and http.calls == []


def test_abusech_open_feeds_download_and_match():
    rt = live_runtime()
    results = {name: rt.data.update(name) for name in (abusech.FEODO_DATASET, abusech.SSLBL_DATASET)}
    for name, result in results.items():
        assert result.ok or result.reason, name
    if results[abusech.FEODO_DATASET].ok:
        res = run_module(Abusech, "ipv4:8.8.8.8", runtime=rt)
        assert res.status is Status.EMPTY  # Feodo answered: not listed; the APIs need the key
        assert res.source_statuses["abusech.feodotracker"]["status"] == "empty"
    if results[abusech.SSLBL_DATASET].ok:
        body = (paths.datasets_dir() / abusech.SSLBL_DATASET).read_text(encoding="utf-8", errors="replace")
        parsed = abusech.parse_sslbl(body)
        assert parsed["rows"], "the live SSLBL list parsed to 0 certificates"
        sha1 = next(iter(parsed["rows"]))
        res = run_module(Abusech, f"cert_fingerprint:{sha1}", runtime=rt)
        assert res.status is Status.OK and res.findings[0].title == "Certificate listed on SSLBL"


def test_ioc_feeds_offline_download_and_match():
    rt = live_runtime()
    names = (ioc_feeds_offline.DS_TWEETFEED, ioc_feeds_offline.DS_SIGBASE_HASH, ioc_feeds_offline.DS_SIGBASE_C2, ioc_feeds_offline.DS_CIRCL_MANIFEST)
    results = {name: rt.data.update(name) for name in names}
    for name, result in results.items():
        assert result.ok or result.reason, name
    if results[ioc_feeds_offline.DS_SIGBASE_HASH].ok:
        rows = ioc_feeds_offline.parse_sigbase_hash((paths.datasets_dir() / ioc_feeds_offline.DS_SIGBASE_HASH).read_text())
        assert len(rows) > 1000
        etype, value, _extra = rows[0]
        res = run_module(IocFeedsOffline, f"{etype.value}:{value}", runtime=rt)
        assert res.status is Status.OK and "signature-base hashes" in res.findings[0].description
    if results[ioc_feeds_offline.DS_TWEETFEED].ok:
        rows = ioc_feeds_offline.parse_tweetfeed((paths.datasets_dir() / ioc_feeds_offline.DS_TWEETFEED).read_text())
        assert rows, "the live TweetFeed week list parsed to 0 rows"
        for etype, value, _extra in rows:
            ent, _why = ioc_feeds_offline.validate(etype, value)
            if ent is not None and not ioc_feeds_offline.is_noise(ent):
                res = run_module(IocFeedsOffline, ent, runtime=rt)
                assert res.status is Status.OK and "TweetFeed" in res.findings[0].description
                break
    res = run_module(IocFeedsOffline, "domain:example.com", runtime=rt)
    assert res.status in (Status.EMPTY, Status.UNAVAILABLE)
