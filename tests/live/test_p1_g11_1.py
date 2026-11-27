"""Live checks of batch p1-G11-1 (warninglists P169, attack_index P292, actor_alias_index P295); run with V3LUM_LIVE=1.

The three modules are offline (disclosure 'none'): only the dataset manager downloads, from
raw.githubusercontent.com (MISP warninglists, MITRE attack-stix-data and CAPEC, MISP galaxy, the Microsoft
naming map). Each check refreshes a few datasets through the real dataset manager (validate hooks included),
then answers benign public values offline: 8.8.8.8 / 1.1.1.1 (public resolvers), the ICS and Mobile ATT&CK
bundles (T0819, BRATA) and the APT28 aliases. The TAXII 2.1 discovery document is read with the TAXII
Accept header (version check only, FC3); nothing is ever sent to a service that publishes submissions.

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is reported as
could-not-verify (a failed update keeps no copy; the modules then keep the bundled data or answer
UNAVAILABLE 'dataset', never an absence).
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.http import HttpError
from v3lum.core.models import Status
from v3lum.modules.cti_framework import actor_alias_index as aai
from v3lum.modules.cti_framework import attack_index as ai
from v3lum.modules.cti_framework.actor_alias_index import ActorAliasIndex
from v3lum.modules.cti_framework.attack_index import AttackIndex
from v3lum.modules.threat_intel_ioc import warninglists as wl
from v3lum.modules.threat_intel_ioc.warninglists import Warninglists

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _update(rt: Runtime, names: list[str]) -> dict[str, object]:
    out = {}
    for name in names:
        result = rt.data.update(name)
        out[name] = result
        print(f"{name}: {result.status} {result.reason[:160]} {result.new_sha256[:12]}")
        assert result.status in ("updated", "unchanged", "failed")
        if result.status == "failed":  # could not verify from this egress: reported, nothing installed
            assert result.reason
    return out


def test_warninglists_weekly_refresh_live():
    rt = live_runtime()
    results = _update(rt, ["warninglists.public-dns-v4", "warninglists.sinkholes", "warninglists.cloudflare"])
    wl.reset_cache()
    res = run_module(Warninglists, "ipv4:8.8.8.8", runtime=rt)
    assert res.status is Status.OK and res.attributes["warninglist_outcome"] == "suppress"
    dns = next(m for m in res.attributes["warninglist_matches"] if m["list"] == "public-dns-v4")
    if not results["warninglists.public-dns-v4"].ok:
        assert dns["origin"] == "bundled"  # the bundled list keeps answering
        pytest.skip(f"public-dns-v4 not refreshed from this egress: {results['warninglists.public-dns-v4'].reason}")
    assert dns["origin"] == "downloaded" and dns["version_date"]
    assert run_module(Warninglists, "ipv4:1.1.1.1", runtime=rt).attributes["warninglist_outcome"] == "suppress"
    assert run_module(Warninglists, "domain:v3lum-unlisted-test-name.example", runtime=rt).status is Status.EMPTY
    wl.reset_cache()


def test_attack_index_builds_from_the_ics_and_mobile_bundles_live():
    rt = live_runtime()
    results = _update(rt, ["attack.versions", "attack.ics", "attack.mobile"])
    ai.reset_cache()
    if not results["attack.ics"].ok:
        res = run_module(AttackIndex, "mitre:T0819", runtime=rt)
        assert res.status in COULD_NOT_VERIFY
        pytest.skip(f"ICS bundle not installed from this egress: {results['attack.ics'].reason}")
    res = run_module(AttackIndex, "mitre:T0819", runtime=rt)
    assert res.status is Status.OK, (res.status, res.error)
    assert res.attributes["attack_name"] == "Exploit Public-Facing Application" and res.attributes["attack_domains"] == ["ics-attack"]
    assert res.attributes["stix_id"].startswith("attack-pattern--") and res.attributes["attack_tactics"]
    assert "enterprise-attack" in res.attributes["attack_index_built"]["missing_domains"]
    if results["attack.versions"].ok:
        versions = ai.parse_stix_index_json(rt.data.path("attack.versions").read_bytes())
        ics = next(c for c in versions["collections"] if c["domain"] == "ics-attack")
        assert ics["latest"]["version"] == res.attributes["attack_index_built"]["versions"]["ics-attack"]
    if results["attack.mobile"].ok:
        brata = run_module(AttackIndex, "malware:BRATA", runtime=rt)
        assert brata.attributes["attack_id"] == "S1094" and brata.attributes["attack_domains"] == ["mobile-attack"]
    ai.reset_cache()


def test_taxii_discovery_reports_the_latest_release_live():
    rt = live_runtime()
    url = f"{ai.TAXII_ROOT}/taxii2/"
    try:
        resp = rt.http.request("GET", url, headers={"Accept": ai.TAXII_ACCEPT}, ttl=0)
    except HttpError as exc:
        pytest.skip(f"TAXII discovery could not be verified from this egress: {exc}")
    parsed = ai.parse_taxii_discovery(resp.content, resp.status)
    print(f"TAXII {resp.status}: latest {parsed['latest']} ({len(parsed['api_roots'])} api roots) marker={parsed['marker']}")
    assert parsed["marker"] is None and parsed["latest"] and ai.newer_attack_version("1.0", parsed["latest"])


def test_alias_index_refresh_live():
    rt = live_runtime()
    results = _update(rt, ["actor_alias_index.galaxy.mitre-intrusion-set", aai.MSTIC_DATASET])
    aai.reset_cache()
    index = aai.get_index()
    expected = sorted(src for name, src in (("actor_alias_index.galaxy.mitre-intrusion-set", "misp-galaxy/mitre-intrusion-set"), (aai.MSTIC_DATASET, "mstic"))
                      if results[name].ok)
    assert sorted(index.downloaded) == expected
    res = run_module(ActorAliasIndex, "threat_actor:Forest Blizzard", runtime=rt)
    assert res.status is Status.OK and res.attributes["alias_cards"][0]["canonical"] == "APT28"
    assert res.attributes["alias_cards"][0]["mitre_ids"] == ["G0007"]
    assert aai.resolve("APT29")["actors"][0]["mitre_ids"] == ["G0016"]  # APT28 and APT29 stay separate
    aai.reset_cache()
