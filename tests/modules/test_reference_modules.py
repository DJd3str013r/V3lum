"""Tests for the four reference modules shipped with the core."""

from __future__ import annotations

from tests.fakes import FakeHttp, add_dns, add_nxdomain_everything, fixture, make_ctx
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.domain_dns.dns_records import DnsRecords
from v3lum.modules.email.email_basics import EmailBasics
from v3lum.modules.ip_network.shodan_internetdb import ShodanInternetDB
from v3lum.modules.utility.ioc_extract import IocExtract


def pivots(res, etype=None):
    return {p.entity.value for p in res.pivots if etype is None or p.entity.type is etype}


# ------------------------------------------------------------------ shodan_internetdb
def test_internetdb_real_sample():
    http = FakeHttp().add("GET", "https://internetdb.shodan.io/1.1.1.1", json=fixture("shodan_internetdb_1.1.1.1.json"))
    res = ShodanInternetDB().run(Entity.make("ipv4", "1.1.1.1"), make_ctx(ShodanInternetDB, http))
    assert res.status is Status.OK
    assert res.attributes["open_ports"][:3] == [53, 80, 443]
    assert "one.one.one.one" in pivots(res, T.DOMAIN)
    assert any("open port" in f.title for f in res.findings)


def test_internetdb_vulns_and_risky_ports():
    data = {"ip": "45.33.32.156", "ports": [22, 3389, 6379], "hostnames": [], "cpes": [], "tags": [], "vulns": ["CVE-2023-0001", "CVE-2023-0002"]}
    http = FakeHttp().add("GET", "https://internetdb.shodan.io/45.33.32.156", json=data)
    res = ShodanInternetDB().run(Entity.make("ipv4", "45.33.32.156"), make_ctx(ShodanInternetDB, http))
    assert pivots(res, T.CVE) == {"CVE-2023-0001", "CVE-2023-0002"}
    assert all(p.relation == "has_vuln" for p in res.pivots if p.entity.type is T.CVE)
    tags = {t for f in res.findings for t in f.tags}
    assert {"exposure", "misconfiguration", "vulnerable"} <= tags


def test_internetdb_not_found_and_private_ip():
    http = FakeHttp().add("GET", "https://internetdb.shodan.io/45.33.32.156", status=404, json={"detail": "No information available"})
    res = ShodanInternetDB().run(Entity.make("ipv4", "45.33.32.156"), make_ctx(ShodanInternetDB, http))
    assert res.status is Status.EMPTY
    assert not ShodanInternetDB().applies(Entity.make("ipv4", "10.0.0.1"), make_ctx(ShodanInternetDB))


# ------------------------------------------------------------------ dns_records
def test_dns_records_full():
    http = FakeHttp()
    add_dns(http, "acme.com.br", "A", ["93.184.215.14"], ad=True)
    add_dns(http, "acme.com.br", "AAAA", ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"])
    add_dns(http, "acme.com.br", "CNAME", [])
    add_dns(http, "acme.com.br", "MX", ["10 mx.acme.com.br."])
    add_dns(http, "acme.com.br", "NS", ["a.dns.br.", "b.dns.br."])
    add_dns(http, "acme.com.br", "TXT", ['"v=spf1 include:_spf.google.com ~all"'])
    add_dns(http, "acme.com.br", "SOA", ["a.dns.br. hostmaster.registro.br. 1 2 3 4 5"])
    add_dns(http, "acme.com.br", "CAA", ['0 issue "letsencrypt.org"'])
    res = DnsRecords().run(Entity.make("domain", "acme.com.br"), make_ctx(DnsRecords, http))
    assert res.attributes["a_records"] == ["93.184.215.14"]
    assert res.attributes["spf"].startswith("v=spf1")
    assert res.attributes["dnssec"] is True
    assert "93.184.215.14" in pivots(res, T.IPV4)
    mx = next(p for p in res.pivots if p.relation == "mx_host")
    assert mx.entity.value == "mx.acme.com.br" and mx.expand is False


def test_dns_records_subdomain_parent_and_nxdomain():
    http = FakeHttp()
    add_dns(http, "www.example.org", "CNAME", ["example.org."])
    add_nxdomain_everything(http)
    res = DnsRecords().run(Entity.make("domain", "www.example.org"), make_ctx(DnsRecords, http))
    assert "example.org" in pivots(res, T.DOMAIN)
    http2 = FakeHttp()
    add_nxdomain_everything(http2)
    res2 = DnsRecords().run(Entity.make("domain", "nope.example"), make_ctx(DnsRecords, http2))
    assert res2.attributes.get("valid") is False


# ------------------------------------------------------------------ email_basics
def test_email_basics_corporate():
    http = FakeHttp()
    add_dns(http, "acme.com", "MX", ["10 mx.acme.com."])
    res = EmailBasics().run(Entity.make("email", "john.doe+news@acme.com"), make_ctx(EmailBasics, http))
    assert res.attributes["free_provider"] is False and res.attributes["mx_valid"] is True
    assert "acme.com" in pivots(res, T.DOMAIN)
    assert "john.doe@acme.com" in pivots(res, T.EMAIL)


def test_email_basics_free_and_dead_domain():
    http = FakeHttp()
    add_dns(http, "gmail.com", "MX", ["5 gmail-smtp-in.l.google.com."])
    res = EmailBasics().run(Entity.make("email", "someone@gmail.com"), make_ctx(EmailBasics, http))
    assert res.attributes["free_provider"] is True
    dom = next(p for p in res.pivots if p.entity.type is T.DOMAIN)
    assert dom.expand is False
    http2 = FakeHttp()
    add_dns(http2, "no-such-domain.example", "MX", [], status=3)
    add_dns(http2, "no-such-domain.example", "A", [], status=3)
    res2 = EmailBasics().run(Entity.make("email", "x@no-such-domain.example"), make_ctx(EmailBasics, http2))
    assert any("does not exist" in f.title for f in res2.findings)


# ------------------------------------------------------------------ ioc_extract
def test_ioc_extract_text_and_file(tmp_path):
    text = "C2 hxxp://bad-site[.]xyz/gate and 45.33.32.156\nhash 44d88612fea8a8f36de82e1278abb02f"
    res = IocExtract().run(Entity.make("text_blob", text), make_ctx(IocExtract))
    assert {"45.33.32.156", "44d88612fea8a8f36de82e1278abb02f", "bad-site.xyz"} <= pivots(res)
    f = tmp_path / "notes.log"
    f.write_text(text)
    ent = Entity.make("file", str(f))
    assert IocExtract().applies(ent, make_ctx(IocExtract))
    assert "45.33.32.156" in pivots(IocExtract().run(ent, make_ctx(IocExtract)))
    binary = tmp_path / "image.png"
    binary.write_bytes(b"\x89PNG....")
    assert not IocExtract().applies(Entity.make("file", str(binary)), make_ctx(IocExtract))
