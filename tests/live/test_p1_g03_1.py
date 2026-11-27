"""Live checks of batch p1-G03-1 (url_unwrap P064, urlscan_search P066, url_domain_blocklists P071,
secret_scanner P312); run with V3LUM_LIVE=1. Benign values only.

* url_unwrap and secret_scanner are offline: they run through the real engine with no request (the
  SafeLinks value is the documentation fixture; the secret is generated at test time). The bundled
  gitleaks ruleset is compared with the current upstream config/gitleaks.toml (MIT) to catch drift:
  the upstream file must still parse and compile with the RE2 converter;
* urlscan_search: keyless search for example.com and 8.8.8.8 (searches only: nothing is submitted);
* url_domain_blocklists: the open lists CERT.PL, Botvrij, spmedia and MetaMask through the dataset
  manager (validator = index build), then a local match of a value taken from each downloaded copy
  and an absence for example.com; url_domain_blocklists_c2: CyberCrime-Tracker the same way. The
  noncommercial OpenPhish / Phishing Army lists are not downloaded (consent / licence gate).

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR), never as an absence.
"""

from __future__ import annotations

import hashlib
import random
import string
import urllib.request

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.url_web import url_domain_blocklists as B
from v3lum.modules.url_web.url_domain_blocklists import UrlDomainBlocklists, UrlDomainBlocklistsC2
from v3lum.modules.url_web.url_unwrap import UrlUnwrap
from v3lum.modules.url_web.urlscan_search import UrlscanSearch
from v3lum.modules.utility import secret_scanner as S
from v3lum.modules.utility.secret_scanner import SecretScanner

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR}
GITLEAKS_UPSTREAM = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"


def live_runtime():
    return Runtime(Config(), no_cache=True)


def test_url_unwrap_offline_through_the_engine():
    http = FakeHttp()
    url = ("https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpayout.example.org%2Flogin"
           "&data=05%7C02%7Cuser%40example.com%7C0000%7C1&sdata=AAAA&reserved=0")
    res = run_module(UrlUnwrap, f"url:{url}", http)
    assert res.status is Status.OK and http.calls == []
    assert any(p.entity.value == "https://payout.example.org/login" for p in res.pivots)
    assert "user@example.com" not in repr(res.attributes) + repr(res.raw)


def test_urlscan_search_keyless_domain():
    res = run_module(UrlscanSearch, "domain:example.com", runtime=live_runtime())
    print(f"urlscan example.com: {res.status.value} ({res.requests} requests) {res.attributes.get('urlscan_totals')} {res.error[:80]}")
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    assert set(res.hosts) <= {"urlscan.io"} and res.requests <= UrlscanSearch.max_requests
    if res.status is Status.OK:
        assert res.attributes.get("urlscan_totals") is not None


def test_urlscan_search_keyless_ip():
    res = run_module(UrlscanSearch, "ipv4:8.8.8.8", runtime=live_runtime())
    print(f"urlscan 8.8.8.8: {res.status.value} ({res.requests} requests) {res.attributes.get('urlscan_totals')} {res.error[:80]}")
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    assert set(res.hosts) <= {"urlscan.io"} and res.requests <= UrlscanSearch.max_requests


def _listed_entity(dataset: str, table: str) -> Entity | None:
    """An ordinary listed value of the downloaded copy (read back from the index the validator built)."""
    idx = B.BlocklistIndex(B.index_path())
    try:
        bit = 1 << B.PARTS[dataset][0].bit
        rows = idx.conn.execute(f"SELECT key FROM {table} WHERE feeds & ? LIMIT 200", (bit,)).fetchall()  # noqa: S608 - fixed table names
    finally:
        idx.close()
    for (key,) in rows:
        if B.host_scope(key) != "":
            continue  # platforms, tenants and protected domains never get host verdicts
        entity = Entity.try_make(T.IPV4, key) or Entity.try_make(T.DOMAIN, key)
        if entity is not None:
            return entity
    return None


@pytest.mark.parametrize("dataset", [
    "url_domain_blocklists.certpl.csv",
    "url_domain_blocklists.botvrij.csv",
    "url_domain_blocklists.spmedia.txt",
    "url_domain_blocklists.metamask.config.json",
])
def test_url_domain_blocklists_open_feed_download_and_match(dataset):
    rt = live_runtime()
    result = rt.data.update(dataset)
    assert result.ok or result.reason, dataset
    if not result.ok:
        pytest.skip(f"{dataset} not downloaded from this egress: {result.reason}")
    feed = B.PARTS[dataset][0]
    entity = _listed_entity(dataset, "dom")
    assert entity is not None, f"{dataset}: the live copy indexed no ordinary host"
    res = run_module(UrlDomainBlocklists, entity, runtime=rt)
    print(f"{dataset}: {result.ok} -> {entity.value}: {res.status.value} {[h['list'] for h in res.attributes.get('blocklist_hits', [])]}")
    assert res.status is Status.OK and any(h["feed"] == feed.id for h in res.attributes["blocklist_hits"]), (entity.value, res.status)
    absent = run_module(UrlDomainBlocklists, "domain:example.com", runtime=rt)
    assert absent.status is Status.EMPTY  # not listed on the lists that were checked
    assert feed.list_name in absent.raw["checked"]


def test_url_domain_blocklists_c2_download_and_match():
    rt = live_runtime()
    dataset = "url_domain_blocklists.cybercrime_tracker.txt"
    result = rt.data.update(dataset)
    if not result.ok:
        res = run_module(UrlDomainBlocklistsC2, "ipv4:192.0.2.10", runtime=rt)
        assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"  # 'not checked', never 'empty'
        pytest.skip(f"CyberCrime-Tracker not downloaded from this egress: {result.reason}")
    idx = B.BlocklistIndex(B.index_path())
    try:
        row = idx.conn.execute("SELECT key FROM urlhost WHERE feeds & ? LIMIT 1", (1 << B.FEEDS["cybercrime_tracker"].bit,)).fetchone()
    finally:
        idx.close()
    assert row, "the live CyberCrime-Tracker copy indexed to 0 hosts"
    etype = T.IPV4 if all(part.isdigit() for part in row[0].split(".")) else T.DOMAIN
    res = run_module(UrlDomainBlocklistsC2, Entity.make(etype, row[0]), runtime=rt)
    assert res.status is Status.OK and res.attributes["blocklist_hits"][0]["category"] == "c2"
    assert all(p.expand is False for p in res.pivots)


def test_secret_scanner_offline_with_a_generated_token():
    rng = random.Random("live")
    token = "ghp_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))
    http = FakeHttp()
    res = run_module(SecretScanner, Entity.make(T.TEXT, f'GITHUB_TOKEN="{token}"\n'), http)
    assert res.status is Status.OK and http.calls == [] and res.pivots == []
    [finding] = [f for f in res.findings if f.data.get("rule") == "github-pat"]
    assert finding.data["masked"]["sha256"] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in repr(finding.data) + repr(res.raw)


def test_gitleaks_upstream_ruleset_still_converts():
    try:
        with urllib.request.urlopen(GITLEAKS_UPSTREAM, timeout=30) as resp:  # noqa: S310 - fixed https URL
            raw = resp.read(4 * 1024 * 1024)
    except OSError as exc:
        pytest.skip(f"upstream gitleaks.toml not reachable from this egress: {exc}")
    parsed = S.parse_gitleaks_toml(raw)  # parsed as data only (TOML), never executed
    assert parsed["ok"], parsed["error"]
    assert parsed["stats"]["compile_errors"] == 0 and parsed["stats"]["rules"] >= 200
    bundled = S.default_engine()["sha256"]
    upstream = hashlib.sha256(raw).hexdigest()
    print(f"gitleaks upstream {upstream[:12]} vs bundled {bundled[:12]}: {'same' if upstream == bundled else 'drift'}"
          f" ({parsed['stats']['rules']} upstream rules)")
