"""Live checks of batch p2-G14-1 (G14 pivot packs: pivots_domain_dns P026, pivots_ip_network P057, pivots_url_web
P083, pivots_threat_intel P170, packs malware_hash P180 and vulnerability P194); run with V3LUM_LIVE=1.

Every module of the batch is offline (disclosure 'none'): the packs are offline data and V3LUM never requests
these URLs (cond 1 of every proposal). The live check therefore (1) runs the modules through the real engine,
provider registry and pack files on benign public values and asserts the rendered links (a FakeHttp without
routes proves nothing is fetched), and (2) as a maintainer re-check (cond 7), sends one polite GET to a few
verified, non-target-touching templates rendered for benign values, outside V3LUM's runtime. A 403/429/5xx or a
TLS/proxy refusal from this datacenter egress counts as 'could not verify' (skip), never as a broken template.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.core import links, providers
from v3lum.core.entities import Entity
from v3lum.core.models import Status
from v3lum.modules.utility import pivot_gated_links as pg

pytestmark = pytest.mark.live


def _urls(res):
    return [url for _label, url in res.links]


MY_PROVIDERS = (
    "completedns", "dnsviz", "whoxy", "dmarcian", "domaintools", "intodns", "mxtoolbox", "verisignlabs", "who_is",
    "whois_com", "hurricane_electric", "scamalytics", "cidr_report", "myipms", "aa419", "crawlgraph", "securityheaders",
    "scamadviser", "w3techs", "website_informer", "webtechsurvey", "cesnet_nerd", "fortiguard", "multirbl", "urlvoid",
    "threatbook", "sploitus", "rapid7", "netcraft__p2-G14-1",
)


def test_packs_and_registry_live():
    mine = [e for e in providers.registry().errors if e.split(".json", 1)[0] in MY_PROVIDERS]
    assert mine == []  # other batches' fragments may be mid-edit
    reg = providers.registry()
    assert all(reg.get(pid) is not None for pid in MY_PROVIDERS if "__" not in pid)
    assert pg.module_link_errors() == []
    for name in pg.PACKS:
        assert name in links.packs()
        assert not [e for e in links.errors() if e.startswith(f"{name}.json")]


def test_pivots_domain_dns_live():
    from v3lum.modules.domain_dns.pivots_domain_dns import PivotsDomainDns

    http = FakeHttp()
    sha256 = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6"  # ISRG Root X1
    res = run_module(PivotsDomainDns, f"cert_fingerprint:{sha256}", http, tlp="clear")
    assert res.status in (Status.OK, Status.EMPTY) and http.calls == []
    rendered = {r.ref for r in links.pivot_links_for(Entity.make("domain", "example.com"))}
    assert {"domain_dns:dnsviz", "domain_dns:completedns", "domain_dns:intodns"} <= rendered


def test_pivots_ip_network_live():
    from v3lum.modules.ip_network.pivots_ip_network import PivotsIpNetwork

    http = FakeHttp()
    res = run_module(PivotsIpNetwork, "ipv4:9.9.9.9", http, tlp="green")
    assert res.status is Status.OK and http.calls == []
    assert _urls(res) == ["https://search.criminalip.io/asset/report/9.9.9.9", "https://en.fofa.info/result?qbase64=aXA9IjkuOS45Ljki"]
    assert run_module(PivotsIpNetwork, "ipv4:100.64.0.1", http, tlp="green").links == []


def test_pivots_url_web_and_threat_intel_live():
    from v3lum.modules.threat_intel_ioc.pivots_threat_intel import PivotsThreatIntel
    from v3lum.modules.url_web.pivots_url_web import PivotsUrlWeb

    http = FakeHttp()
    web = run_module(PivotsUrlWeb, "domain:example.com", http, tlp="clear")
    assert web.status is Status.OK and http.calls == []
    assert "https://securityheaders.com/?q=example.com&hide=on&followRedirects=on" in _urls(web)
    ti = run_module(PivotsThreatIntel, "url:https://example.com/panel/gate.php", http)
    assert _urls(ti) == ["https://cybercrime-tracker.net/index.php?search=example.com%2Fpanel%2Fgate.php"]
    assert run_module(PivotsThreatIntel, "domain:example.com", http).reason_code == "tlp"  # default AMBER


# Verified templates re-checked once each (benign values, no target-touching or scan-trigger page).
RECHECK = [
    ("domain_dns:dnsviz", "domain", "example.com", "example.com"),
    ("ip_network:bgphe_ip", "ipv4", "8.8.8.8", "8.8.8.8"),
    ("malware_hash:triage_hash", "md5", "44d88612fea8a8f36de82e1278abb02f", ""),
    ("vulnerability:rapid7_db", "cve", "CVE-2021-44228", "CVE-2021-44228"),
    ("threat_intel_ioc:nerd_ip", "ipv4", "8.8.8.8", "8.8.8.8"),
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003 - a 3xx is recorded, never followed
        return None


@pytest.mark.parametrize(("ref", "etype", "value", "echo"), RECHECK, ids=[r[0] for r in RECHECK])
def test_verified_templates_still_answer(ref, etype, value, echo):
    rendered = links.render(ref, Entity.make(etype, value))
    assert rendered is not None and not rendered.touches_target
    time.sleep(1.5)  # polite: one request per host, spaced
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(rendered.url, headers={"Accept": "text/html", "User-Agent": "V3LUM-live-check"})
    try:
        with opener.open(request, timeout=30) as resp:
            status, body = resp.status, resp.read(262144).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, body = exc.code, ""
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        pytest.skip(f"could not verify {rendered.host}: {type(exc).__name__}")
    if status in (401, 403, 407, 429) or status >= 500:
        pytest.skip(f"could not verify {rendered.host}: HTTP {status} from this egress")
    assert status in (200, 301, 302), status
    if status == 200 and echo:
        assert echo.lower() in body.lower()
