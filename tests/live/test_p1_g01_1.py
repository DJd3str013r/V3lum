"""Live checks of batch p1-G01-1 (ct_logs, ct_logs_extra, email_security_posture, rdap); run with V3LUM_LIVE=1.

Keyless sources and benign values only: example.com / example.net (RFC 2606), google.com and nic.br /
NIC.BR's own address space (200.160.0.0/20, AS22548), 8.8.8.8 and AS15169. No key is used: Cert
Spotter is queried in its keyless 'evaluation' allowance (a couple of requests), MerkleMap without a
key must answer NEEDS_KEY without any request.

A 403/429/challenge/reset/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR / UNAVAILABLE), never as an
absence. Known from the research egress (2026-11-26): crt.sh answers slowly (10-60 s) or with 502/503
under load; rdap.registro.br may answer 403 with an empty body to datacenter addresses for a few
seconds, then 200; LACNIC answers 307 to rdap.registro.br for Brazilian resources.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.domain_dns.ct_logs import CtLogs
from v3lum.modules.domain_dns.ct_logs_extra import CtLogsExtra
from v3lum.modules.domain_dns.email_security_posture import EmailSecurityPosture
from v3lum.modules.domain_dns.rdap import Rdap

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime(**settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


# ------------------------------------------------------------------ ct_logs (P001)
def test_ct_logs_example_com():
    res = run_module(CtLogs, "domain:example.com", runtime=live_runtime(ct_logs_budget=60))
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    statuses = {s: v["status"] for s, v in res.source_statuses.items()}
    assert statuses, "every queried CT source reports its own status"
    if res.status is Status.OK:
        subs = [p for p in res.pivots if p.relation == "subdomain"]
        assert all(p.entity.value.endswith(".example.com") for p in subs)
        assert res.attributes["ct_summary"]["cert_count"] >= 1
        assert all(not p.expand for p in res.pivots if p.relation in ("has_certificate", "cert_san"))
    for source, status in statuses.items():  # a refusal is never 'no certificates'
        assert status in ("ok", "empty", "skipped", "needs_key", "blocked", "rate_limited", "quota", "error", "unavailable"), (source, status)
    assert set(res.hosts) <= set(CtLogs.hosts) | {"dns.google", "cloudflare-dns.com"}


def test_ct_logs_subdomain_is_not_applicable_offline():
    res = run_module(CtLogs, "domain:www.example.com", runtime=live_runtime())
    assert res.status is Status.SKIPPED and not res.hosts


# ------------------------------------------------------------------ ct_logs_extra (P001 cond 1, opt-in)
def test_ct_logs_extra_crtname_example_com():
    res = run_module(CtLogsExtra, "domain:example.com", runtime=live_runtime(ct_logs_check_liveness=False), tlp="green",
                     options=ScanOptions(include={"ct_logs_extra"}, include_disabled=True, allow_unknown=True, tlp="green"))
    assert res.status in {Status.OK, Status.EMPTY, Status.SKIPPED} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.SKIPPED:
        assert res.reason_code in ("tier", "licence", "tlp", "not_default"), res.reason_code
        return
    assert res.source_statuses.get("merklemap.search", {}).get("status") in (None, "needs_key")
    assert "api.merklemap.com" not in res.hosts  # no key: MerkleMap is never contacted
    if res.status is Status.OK:
        assert all(p.entity.value.endswith("example.com") for p in res.pivots if p.relation == "subdomain")


# ------------------------------------------------------------------ email_security_posture (P002)
def test_email_security_posture_example_com():
    res = run_module(EmailSecurityPosture, "domain:example.com", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        table = res.attributes["email_posture"]
        assert table["spf"].startswith("valid") and "-all" in table["spf"]
        assert table["mx"] in ("null MX (no mail)", "could not verify")
        assert "missing" not in table["dkim"]
        assert [f.severity.label for f in res.findings] == ["info"]  # not an own domain: the summary only
    assert set(res.hosts) <= {"dns.google", "cloudflare-dns.com"}


def test_email_security_posture_google_com():
    res = run_module(EmailSecurityPosture, "domain:google.com", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["spf_status"] in ("ok", "temperror")
        assert res.attributes["spf_lookups"] <= 10
        assert res.attributes.get("dmarc_policy") in ("reject", "quarantine", None)
        third = {c["cidr"] for c in res.attributes.get("third_party_mail_cidrs", [])}
        assert not any(p.entity.value in third for p in res.pivots)  # SaaS netblocks never pivot


def test_email_security_posture_nic_br():
    res = run_module(EmailSecurityPosture, "domain:nic.br", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["spf_status"] in ("ok", "temperror", "permerror")
        assert all(p.expand is False for p in res.pivots)


# ------------------------------------------------------------------ rdap (P003)
def test_rdap_example_com_through_the_bootstrap():
    res = run_module(Rdap, "domain:example.com", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["registered"] is True and res.attributes["rdap_server"] == "rdap.verisign.com"
        assert res.attributes["registrar_iana_id"] == "376"
        assert all(p.entity.type is T.DOMAIN and p.relation == "nameserver" for p in res.pivots)


def test_rdap_nic_br_at_registrobr():
    res = run_module(Rdap, "domain:nic.br", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["registrant_kind"] == "org" and res.attributes["registrant_doc"] == "05.506.560/0001-36"
        assert [p.entity.value for p in res.pivots if p.entity.type is T.CNPJ] == ["05506560000136"]
        assert res.raw["minimised"]["dropped"]["cpf_ids"] == 0
    else:  # registro.br refused this egress: could not verify, with the manual whois link
        assert any("registro.br/tecnologia/ferramentas/whois" in url for _label, url in res.links)


def test_rdap_ipv4_8_8_8_8_at_arin():
    res = run_module(Rdap, "ipv4:8.8.8.8", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["rdap_server"] == "rdap.arin.net"
        assert "8.8.8.0/24" in res.attributes["rdap_network"]["cidrs"]


def test_rdap_asn_15169_at_arin():
    res = run_module(Rdap, "asn:AS15169", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["rdap_autnum"]["start"] <= 15169 <= res.attributes["rdap_autnum"]["end"]


def test_rdap_brazilian_space_follows_lacnic_to_registrobr():
    res = run_module(Rdap, "ipv4:200.160.0.1", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["rdap_server"] in ("rdap.registro.br", "rdap.lacnic.net")
        if res.attributes["rdap_server"] == "rdap.lacnic.net":  # registro.br refused: LACNIC data kept, status recorded
            assert res.source_statuses["registrobr.rdap"]["status"] in ("blocked", "rate_limited", "error", "quota")
