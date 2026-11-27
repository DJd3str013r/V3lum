"""pivots_domain_dns (P026): domain & DNS tools, manual links only. V3LUM never fetches these URLs.

Verification records: tests/fixtures/pivots_domain_dns/verified_templates.json (status, date, size); golden URLs:
render_golden.json (the URLs requested live)."""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core import links
from v3lum.core.entities import Entity
from v3lum.core.models import Status
from v3lum.modules.domain_dns.pivots_domain_dns import PivotsDomainDns
from v3lum.modules.utility import pivot_gated_links as pg

SHA256 = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6"  # ISRG Root X1 (public CA)
GOLDEN = module_fixture("pivots_domain_dns", "render_golden.json")
CHECKS = module_fixture("pivots_domain_dns", "verified_templates.json")["checks"]


def domain_links(value="example.com"):
    return {r.ref: r for r in links.pivot_links_for(Entity.make("domain", value)) if r.ref.startswith("domain_dns:")}


@pytest.fixture
def no_core_duplicate(monkeypatch):
    """The crt.sh fingerprint URL is also served by ct_rdap_lookups (another batch): hide it to see this pack's link."""
    monkeypatch.setattr(pg._links, "pivot_links_for", lambda entity, **kw: [])


# ------------------------------------------------------------------ cond 9: crt.sh lookup only for SHA-256
def test_sha256_fingerprint_gets_the_crtsh_certificate_lookup(no_core_duplicate):
    http = FakeHttp()
    res = run_module(PivotsDomainDns, f"cert_fingerprint:{SHA256.upper()}", http, tlp="clear")
    assert res.status is Status.OK and http.calls == [] and res.requests == 0
    assert res.links == [("crt.sh: certificate by SHA-256 fingerprint (CT log entries)", f"https://crt.sh/?q={SHA256}")]
    assert res.raw["links"][0]["clickable"] is True and res.raw["links"][0]["verified"] is True


def test_colon_separated_sha256_is_normalised_first(no_core_duplicate):
    colon = ":".join(SHA256[i:i + 2] for i in range(0, 64, 2)).upper()
    res = run_module(PivotsDomainDns, f"cert_fingerprint:{colon}", tlp="green")
    assert [u for _l, u in res.links] == [f"https://crt.sh/?q={SHA256}"]


@pytest.mark.parametrize("value", ["a" * 40, "AB:" * 19 + "CD"])
def test_other_fingerprint_forms_get_no_link(value, no_core_duplicate):
    res = run_module(PivotsDomainDns, f"cert_fingerprint:{value}", tlp="clear")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and res.links == []
    assert "64-hex SHA-256" in res.raw["hidden"][0]["reason"]


def test_no_duplicate_when_another_pack_already_lists_the_url():
    res = run_module(PivotsDomainDns, f"cert_fingerprint:{SHA256}", tlp="clear")
    if any(r.url == f"https://crt.sh/?q={SHA256}" for r in links.pivot_links_for(Entity.make("cert_fingerprint", SHA256))):
        assert res.status is Status.EMPTY and res.links == []
        assert res.raw["hidden"][0]["reason"].startswith("already listed by ")
    else:
        assert res.status is Status.OK


def test_amber_emits_the_link_for_the_renderers_to_show_as_text(no_core_duplicate):
    res = run_module(PivotsDomainDns, f"cert_fingerprint:{SHA256}")  # default TLP:AMBER
    assert res.status is Status.OK and res.raw["tlp"] == "amber"
    item = res.raw["links"][0]
    assert item["clickable"] is False and item["disclosure"] == f"opening sends {SHA256} to crt.sh"


def test_red_emits_nothing(no_core_duplicate):
    res = run_module(PivotsDomainDns, f"cert_fingerprint:{SHA256}", tlp="red")
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and res.links == []


def test_direct_run_with_make_ctx_never_touches_the_network(no_core_duplicate):
    http = FakeHttp()
    ctx = make_ctx(PivotsDomainDns, http, entity=f"cert_fingerprint:{SHA256}", tlp="clear")
    res = PivotsDomainDns().run(Entity.make("cert_fingerprint", SHA256), ctx)
    assert res.status is Status.OK and http.calls == []


# ------------------------------------------------------------------ cond 8, 10, 11: the core pack links
def test_domain_gets_every_cond8_entry_in_file_order():
    out = domain_links()
    assert list(out) == [f"domain_dns:{i}" for i in (
        "dnsviz", "whoxy", "hostio", "mxtoolbox_spf", "mxtoolbox_dmarc", "mxtoolbox_mx", "dmarcian", "completedns",
        "domaintools_reverse_ip", "intodns", "verisign_dnssec_debugger", "whois_is", "whois_com", "domaintools_whois")]
    assert links.render("ct_rdap_lookups:crtsh_domain", Entity.make("domain", "example.com")).url == "https://crt.sh/?q=example.com"
    assert out["domain_dns:completedns"].url == "https://completedns.com/dns-history/?domain=example.com"
    assert out["domain_dns:mxtoolbox_dmarc"].url == "https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3aexample.com&run=toolpage"


def test_target_querying_pages_are_touches_target_and_dnsviz_warns():
    out = domain_links()
    touching = {ref.split(":")[1] for ref, r in out.items() if r.touches_target}
    assert touching == {"mxtoolbox_spf", "mxtoolbox_dmarc", "mxtoolbox_mx", "dmarcian", "intodns", "verisign_dnssec_debugger"}
    assert "'Analyze' button runs and publishes a fresh analysis" in out["domain_dns:dnsviz"].label


def test_domaintools_whois_is_antibot_unverified_and_last():
    out = domain_links()
    whois = out["domain_dns:domaintools_whois"]
    assert whois.antibot and not whois.verified and links.BADGE_UNVERIFIED in whois.badge
    assert list(out)[-1] == "domain_dns:domaintools_whois"
    assert out["domain_dns:domaintools_reverse_ip"].antibot is True


@pytest.mark.parametrize("value", ["EXAMPLE.COM.", "münchen.de"])
def test_values_are_normalised_and_idn_goes_as_punycode(value):
    out = domain_links(value)
    assert all(r.url.isascii() for r in out.values())
    if value.startswith("m"):
        assert out["domain_dns:whois_com"].url == "https://www.whois.com/whois/xn--mnchen-3ya.de"


def test_golden_urls_and_verification_records():
    for g in GOLDEN:
        entity = Entity.make(g["type"], g["value"])
        rendered = links.render(g["ref"], entity) if g["renderer"] == "core" else pg.render(
            pg.module_links("domain_dns")[g["ref"].split(":")[1]], entity)
        assert rendered is not None and rendered.url == g["url"]
    statuses = {c["check"]: c["status"] for c in CHECKS}
    assert statuses["crtsh_sha256_isrg_root_x1_retry"] == 200 and statuses["whoxy__ok"] == 301


def test_module_metadata_is_the_council_decision():
    cls = PivotsDomainDns
    assert cls.default_enabled is True and cls.terms == "open" and cls.disclosure == "none" and cls.hosts == ()
    assert cls.opsec.name == "PASSIVE" and cls.max_requests == 0
