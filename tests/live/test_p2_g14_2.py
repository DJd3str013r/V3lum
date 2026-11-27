"""Live checks of batch p2-G14-2 (G14 pivot packs: pivots_darkweb P203, pivots_crypto P216, pivots_company_org P231,
pivots_brazil P250, pivots_pentest P290, pivots_cti P300); run with V3LUM_LIVE=1.

Every module of the batch is offline (disclosure 'none'): the packs are offline data and V3LUM never requests
these URLs or any API behind them (cond 1 of every proposal). The live check therefore runs the modules through
the real engine (bundled P295 alias index, bundled ATT&CK data, the real provider registry and pack files) on
benign public values and asserts the rendered links; a FakeHttp with no routes proves nothing is fetched. The
templates themselves were checked by the maintainer on 2026-11-25/26 (tests/fixtures/pivots_*/
verified_templates.json: status and page title only).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.core import links, providers
from v3lum.core.entities import Entity
from v3lum.core.models import Status
from v3lum.modules.utility import pivot_pack_render as pr

pytestmark = pytest.mark.live


def _urls(res):
    return [url for _label, url in res.links]


def test_packs_and_registry_live():
    assert providers.registry().errors == []
    assert pr.module_link_errors() == []
    for name in pr.BATCH_PACKS:
        assert name in links.packs() and not [e for e in links.errors() if e.startswith(f"{name}.json")]


def test_pivots_darkweb_live():
    from v3lum.modules.darkweb_ransomware.pivots_darkweb import PivotsDarkweb

    http = FakeHttp()
    res = run_module(PivotsDarkweb, "threat_actor:LockBit 3.0", http, tlp="clear")
    assert res.status is Status.OK and http.calls == []
    assert _urls(res) == ["https://www.ransomlook.io/group/lockbit3", "https://www.ransomware.live/group/lockbit3"]
    hidden = run_module(PivotsDarkweb, "domain:example.com", http)  # TLP:AMBER default: onion search hidden
    assert hidden.status is Status.SKIPPED and hidden.reason_code == "tlp"


def test_pivots_crypto_live():
    from v3lum.modules.crypto.pivots_crypto import PivotsCrypto

    http = FakeHttp()
    res = run_module(PivotsCrypto, "other_crypto_address:TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", http, tlp="clear")  # USDT-TRC20 contract
    assert res.status is Status.OK and http.calls == []
    assert _urls(res) == ["https://tronscan.org/#/address/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"]
    genesis = links.pivot_links_for(Entity.make("btc_address", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), categories=("crypto",))
    assert genesis[0].url == "https://mempool.space/address/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def test_pivots_company_org_pack_live():
    out = {r.ref: r.url for r in links.pivot_links_for(Entity.make("company_name", "GITHUB"))}
    assert out["company_org:companies_house_search"] == "https://find-and-update.company-information.service.gov.uk/search/companies?q=GITHUB"


def test_pivots_brazil_live():
    from v3lum.modules.brazil_public_data.pivots_brazil import PivotsBrazil

    http = FakeHttp()
    res = run_module(PivotsBrazil, "cnpj:00.000.000/0001-91", http, tlp="clear")  # Banco do Brasil (public company data)
    assert res.status is Status.OK and http.calls == []
    assert _urls(res) == ["https://www.consumidor.gov.br/pages/principal/", "https://www.sintegra.gov.br/"]


def test_pivots_pentest_live():
    from v3lum.modules.pentest_recon.pivots_pentest import PivotsPentest

    http = FakeHttp()
    res = run_module(PivotsPentest, "domain:example.com", http)  # not an org asset, no opt-in: privacy skip
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []
    ssl = links.render("pentest:ssllabs_analyze", Entity.make("domain", "example.com"))
    assert ssl.touches_target and ssl.url.endswith("&hideResults=on&latest")


def test_pivots_cti_live():
    from v3lum.modules.cti_framework.pivots_cti import PivotsCti

    http = FakeHttp()
    technique = run_module(PivotsCti, "mitre_technique:T1059.001", http, tlp="clear")
    assert _urls(technique) == ["https://attack.mitre.org/techniques/T1059/001/"]
    malware = run_module(PivotsCti, "malware_family:Emotet", http, tlp="clear")
    assert _urls(malware) == ["https://attack.mitre.org/software/S0367/", "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"]
    actor = run_module(PivotsCti, "threat_actor:APT28", http, tlp="clear")
    assert _urls(actor) == ["https://attack.mitre.org/groups/G0007/"]
    assert http.calls == []
