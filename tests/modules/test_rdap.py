"""rdap (P003): IANA bootstrap -> authoritative registry, rdap.org fallback, registro.br for .br and BR space.

Fixtures in tests/fixtures/rdap/ (batch p1-G01-1 prep, recorded 2026-11-26, trimmed and scrubbed): the
four IANA bootstrap files (trimmed to a few services, real URLs) plus a truncated download; registro.br
answers for bb.com.br (registrant CNPJ), nic.br, 200.160.0.0/20 and AS22548 (contact names replaced by
placeholders 'Beltrano da Silva' / 'Fulano de Tal', e-mails by example.com), a synthetic individual-held
.br name with the placeholder CPF 000.000.000-00, registro.br's 403 with an empty body and its 200
parent-object answer for a name below nic.br; Verisign answers for example.com, github.com and the empty
404; ARIN answers for 8.8.8.8 and AS13335 and its 303 (with a /8 body) for 1.1.1.1; rdap.org's 302 and
'No RDAP service' 404; a synthetic LACNIC country=BR answer and a synthetic privacy/proxy domain.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.domain_dns import rdap as rdap_mod
from v3lum.modules.domain_dns.rdap import (
    BootstrapUnavailable,
    Rdap,
    answer_matches_query,
    bootstrap_lookup,
    brand_label_match,
    load_privacy_list,
    match_asn,
    match_domain,
    match_ip,
    minimise_rdap,
    parse_bootstrap,
    pick_base_url,
    tld_has_rdap,
)

BOOT = {kind: f"https://data.iana.org/rdap/{kind}.json" for kind in ("dns", "ipv4", "ipv6", "asn")}
VERISIGN = "https://rdap.verisign.com/com/v1/domain/{}"
REGISTROBR = "https://rdap.registro.br/{}"
ARIN = "https://rdap.arin.net/registry/{}"
LACNIC = "https://rdap.lacnic.net/rdap/{}"
APNIC = "https://rdap.apnic.net/{}"
RDAP_ORG = "https://rdap.org/{}"
PLACEHOLDER_PERSONS = ("Beltrano", "Fulano", "beltrano@", "fulano@", "000.000.000-00", "tel:+55.1155550103")

#: a synthetic APNIC answer for 1.1.1.1 (documentation shape of an RDAP ip network object)
APNIC_1111 = {
    "objectClassName": "ip network", "handle": "1.1.1.0 - 1.1.1.255", "startAddress": "1.1.1.0", "endAddress": "1.1.1.255",
    "name": "APNIC-LABS", "country": "AU", "cidr0_cidrs": [{"v4prefix": "1.1.1.0", "length": 24}],
    "entities": [{"objectClassName": "entity", "handle": "ORG-ARAD1-AP", "roles": ["registrant"],
                  "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "APNIC Research and Development"],
                                           ["kind", {}, "text", "org"]]]}],
}


def fx(name):
    return module_fixture(Rdap, name)


def boot(http, kind, data=None, **kw):
    http.add("GET", BOOT[kind], json=fx(f"iana_{kind}_bootstrap.json") if data is None else data, **kw)
    return http


def exchange(http, url, name, **kw):
    """Serve a recorded ``*.http.json`` exchange (JSON or text body, recorded headers)."""
    resp = fx(name)["response"]
    body = resp["body"]
    if isinstance(body, (dict, list)):
        return http.add("GET", url, status=resp["status"], json=body, headers=resp["headers"], **kw)
    return http.add("GET", url, status=resp["status"], text=body, headers=resp["headers"], **kw)


def rdap_json(http, url, body, **kw):
    return http.add("GET", url, json=body, headers={"content-type": "application/rdap+json"}, **kw)


def run(entity, http, **kw):
    return run_module(Rdap, entity, http, **kw)


def res_now():
    return FakeClock.DEFAULT_START


def parse(value):
    return rdap_mod.parse_iso8601(value)


def dump(res):
    return json.dumps(res.to_dict(), default=str) + json.dumps(res.raw, default=str)


def assert_no_person_data(res):
    blob = dump(res)
    for marker in PLACEHOLDER_PERSONS:
        assert marker not in blob, marker


# ------------------------------------------------------------------ metadata (P003)
def test_contract_metadata():
    cls = Rdap
    assert cls.terms == "open" and cls.default_enabled is True and cls.max_requests <= 10
    assert cls.accepts == frozenset({T.DOMAIN, T.IPV4, T.IPV6, T.CIDR, T.ASN})
    assert {"data.iana.org", "rdap.org", "rdap.registro.br", "rdap.arin.net", "rdap.lacnic.net", "rdap.verisign.com"} <= set(cls.hosts)
    assert {"iana.tlds", "registrobr.rdap", "arin.rdap", "rdap_org.redirector", "rdap_lacnic.rdap"} <= set(cls.sources)
    for kind, (name, url) in rdap_mod.BOOTSTRAP.items():
        assert DATASETS[name]["url"] == url == BOOT[kind] and DATASETS[name]["ttl"] == 86400


# ------------------------------------------------------------------ bootstrap helpers (cond 1)
def test_parse_bootstrap_validates_shape_and_required_entries(tmp_path):
    assert len(parse_bootstrap(fx("iana_dns_bootstrap.json"), "dns")) == 7
    for bad, why in (({"services": []}, "version"), ({"version": "1.0", "services": []}, "no usable"),
                     ({"version": "1.0", "services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}, "br"), ("<html>", "services")):
        with pytest.raises(ValueError, match=why):
            parse_bootstrap(bad, "dns")
    truncated = tmp_path / "dns.json"
    truncated.write_text((FIXTURES / "rdap" / "iana_dns_bootstrap_truncated.json").read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError):  # the dataset validator rejects a cut download (JSONDecodeError is a ValueError)
        rdap_mod._validator("dns")(truncated)
    good = tmp_path / "ok.json"
    good.write_text(json.dumps(fx("iana_dns_bootstrap.json")), encoding="utf-8")
    assert rdap_mod._validator("dns")(good) is True


def test_match_helpers():
    dns = parse_bootstrap(fx("iana_dns_bootstrap.json"), "dns")
    assert match_domain(dns, "example.com").base == "https://rdap.verisign.com/com/v1/"
    assert match_domain(dns, "bb.com.br").host == "rdap.registro.br"
    kg = match_domain(dns, "example.kg")
    assert kg.http_only and kg.base is None
    assert match_domain(dns, "yandex.ru") is None
    v4 = parse_bootstrap(fx("iana_ipv4_bootstrap.json"), "ipv4")
    assert match_ip(v4, "8.8.8.8", "ipv4").host == "rdap.arin.net" and match_ip(v4, "200.160.0.0/20", "ipv4").host == "rdap.lacnic.net"
    assert match_ip(v4, "5.5.5.5", "ipv4") is None and match_ip(v4, "not-an-ip", "ipv4") is None
    v6 = parse_bootstrap(fx("iana_ipv6_bootstrap.json"), "ipv6")
    assert match_ip(v6, "2800:3f0:4001::1", "ipv6").host == "rdap.lacnic.net"
    asn = parse_bootstrap(fx("iana_asn_bootstrap.json"), "asn")
    assert match_asn(asn, 13335).host == "rdap.arin.net" and match_asn(asn, 262150).host == "rdap.lacnic.net"
    assert match_asn(asn, 64512) is None
    assert pick_base_url(["http://x.example/", "https://rdap.example/rdap"]) == "https://rdap.example/rdap/"
    assert pick_base_url(["http://only.example/"]) is None


def test_shared_helpers_for_whois_fallback():
    http = boot(FakeHttp(), "dns")
    ctx = make_ctx(Rdap, http)
    assert tld_has_rdap(ctx, "example.com") is True
    assert tld_has_rdap(ctx, "example.kg") is False  # http only
    assert tld_has_rdap(ctx, "yandex.ru") is False  # absent from the bootstrap
    assert bootstrap_lookup(ctx, "dns", "registro.br").host == "rdap.registro.br"
    assert http.urls().count(BOOT["dns"]) == 1  # one download, then the local copy


def test_unreadable_bootstrap_is_none_never_false():
    dead_ctx = make_ctx(Rdap, FakeHttp().add("GET", BOOT["dns"], status=503, text="unavailable"))
    assert tld_has_rdap(dead_ctx, "example.com") is None  # could not verify, never False
    with pytest.raises(BootstrapUnavailable):
        bootstrap_lookup(dead_ctx, "dns", "example.com")


def test_truncated_bootstrap_download_falls_back_to_rdap_org():
    cut = (FIXTURES / "rdap" / "iana_dns_bootstrap_truncated.json").read_text(encoding="utf-8")
    http = FakeHttp().add("GET", BOOT["dns"], text=cut, headers={"content-type": "application/json"})
    exchange(http, RDAP_ORG.format("domain/example.com"), "rdaporg_redirect.http.json")
    rdap_json(http, VERISIGN.format("example.com"), fx("verisign_domain_ok.json"))
    res = run("domain:example.com", http)
    assert res.status is Status.OK and res.raw["via_rdap_org"] is True
    assert not (paths.datasets_dir() / "iana_rdap_dns.json").exists()  # the cut body never became the copy


# ------------------------------------------------------------------ .br through registro.br (cond 2, 4-6)
def test_br_domain_with_cnpj_registrant():
    http = rdap_json(FakeHttp(), REGISTROBR.format("domain/bb.com.br"), fx("registrobr_domain_cnpj.json"),
                     match_headers={"accept": "application/rdap+json"})
    res = run("domain:bb.com.br", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["registered"] is True and a["registrant_kind"] == "org"
    assert a["registrant"] == "BANCO DO BRASIL S.A." and a["registrant_doc"] == "00.000.000/0001-91" and a["cnpj_roots"] == ["00000000"]
    assert (a["created"], a["expires"], a["updated"]) == ("1998-03-04T19:54:24Z", "2028-03-04T19:54:24Z", "2026-05-29T12:00:10Z")
    assert a["delegation_signed"] is True and a["nameservers"] == ["dns1.bb.com.br", "dns2.bb.com.br"] and a["rdap_server"] == "rdap.registro.br"
    cnpj = [p for p in res.pivots if p.entity.type is T.CNPJ]
    assert [(p.entity.value, p.relation) for p in cnpj] == [("00000000000191", "registrant")]
    org = [p for p in res.pivots if p.entity.type is T.ORG]
    assert [(p.entity.value, p.expand) for p in org] == [("BANCO DO BRASIL S.A.", False)]
    assert {p.entity.value for p in res.pivots if p.relation == "nameserver"} == {"dns1.bb.com.br", "dns2.bb.com.br"}
    assert all(not p.expand for p in res.pivots if p.relation == "nameserver")
    assert res.raw["minimised"]["dropped"]["legal_representative"] == 1
    assert_no_person_data(res)  # administrative/technical persons and the legal representative are dropped (cond 4-5)
    assert http.urls() == [REGISTROBR.format("domain/bb.com.br")]  # .br never needs the bootstrap
    http.assert_hosts_within(Rdap)


def test_nic_br_persons_are_dropped_but_counted():
    http = rdap_json(FakeHttp(), REGISTROBR.format("domain/nic.br"), fx("registrobr_domain_persons.json"))
    res = run("domain:nic.br", http)
    assert res.status is Status.OK and res.attributes["registrant_doc"] == "05.506.560/0001-36"
    dropped = res.raw["minimised"]["dropped"]
    assert dropped["person_fields"] >= 2 and dropped["legal_representative"] == 1 and dropped["cpf_ids"] == 0
    assert "rdap_contacts" not in res.attributes  # every non-registrant contact here is a natural person
    assert_no_person_data(res)


def test_individual_holder_drops_cpf_and_flags_the_org_brand():
    body = fx("registrobr_domain_individual.json")
    org = OrgProfile.from_dict({"brands": [{"keyword": "Exemplo"}], "domains": [{"name": "example.com", "verification": "confirmed"}]})
    http = rdap_json(FakeHttp(), REGISTROBR.format("domain/exemplo-teste-0000.com.br"), body)
    res = run("domain:exemplo-teste-0000.com.br", http, org_profile=org)
    assert res.status is Status.OK
    a = res.attributes
    assert a["registrant_kind"] == "individual" and a["brand_match"] == "exemplo"
    assert not any(p.entity.type in (T.CNPJ, T.ORG) for p in res.pivots)  # natural persons never pivot (cond 6)
    assert "registrant" not in a and "registrant_doc" not in a
    assert res.raw["minimised"]["dropped"]["cpf_ids"] == 1
    assert_no_person_data(res)  # CPF never stored (team rule 4, LGPD)
    brand = [f for f in res.findings if f.title == "Org brand in an individual-held .br name"]
    assert len(brand) == 1 and brand[0].severity.label == "info"


def test_individual_holder_without_org_profile_has_no_brand_finding():
    http = rdap_json(FakeHttp(), REGISTROBR.format("domain/exemplo-teste-0000.com.br"), fx("registrobr_domain_individual.json"))
    res = run("domain:exemplo-teste-0000.com.br", http)
    assert "brand_match" not in res.attributes and not res.findings


def test_registrobr_403_is_blocked_with_manual_link_and_never_cached():
    http = exchange(FakeHttp(), REGISTROBR.format("domain/bb.com.br"), "registrobr_blocked.http.json", times=1)
    rdap_json(http, REGISTROBR.format("domain/bb.com.br"), fx("registrobr_domain_cnpj.json"))
    rt = make_runtime(http, cache=True)
    first = run("domain:bb.com.br", None, runtime=rt)
    assert first.status is Status.BLOCKED and "could not verify" in first.error
    assert ("Registro.br web whois (manual lookup)", "https://registro.br/tecnologia/ferramentas/whois/?search=bb.com.br") in first.links
    assert not first.pivots and "registered" not in first.attributes
    second = run("domain:bb.com.br", None, runtime=rt)  # the refusal was not cached: the next scan retries
    assert second.status is Status.OK and len(http.calls) == 2


def test_registrobr_429_and_timeout_are_could_not_verify():
    from v3lum.core.http import NetworkError

    limited = FakeHttp().add("GET", REGISTROBR.format("domain/bb.com.br"), status=429, text="Too Many Requests", headers={"retry-after": "120"})
    res = run("domain:bb.com.br", limited)
    assert res.status is Status.RATE_LIMITED and "could not verify" in res.error and res.links
    slow = FakeHttp().add("GET", REGISTROBR.format("domain/bb.com.br"), error=NetworkError("ReadTimeout contacting rdap.registro.br: timed out"))
    res = run("domain:bb.com.br", slow)
    assert res.status is Status.ERROR and res.reason_code == "timeout" and "could not verify" in res.error


def test_registrobr_parent_object_is_never_registered():
    body = fx("registrobr_parent_answer.http.json")["response"]["body"]
    assert answer_matches_query(body, "zz-nonexistent-label-7q3.nic.br") == "parent"
    http = rdap_json(FakeHttp(), REGISTROBR.format("domain/exemplo-teste-0000.com.br"), body)
    res = run("domain:exemplo-teste-0000.com.br", http)
    assert res.status is Status.ERROR and "instead of" in res.error
    assert "registered" not in res.attributes and not res.pivots


# ------------------------------------------------------------------ other TLDs through the bootstrap (cond 1, 3)
def test_com_domain_through_the_bootstrap_to_verisign():
    http = boot(FakeHttp(), "dns")
    rdap_json(http, VERISIGN.format("example.com"), fx("verisign_domain_ok.json"))
    res = run("domain:example.com", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["registrar"] == "RESERVED-Internet Assigned Numbers Authority" and a["registrar_iana_id"] == "376"
    assert a["nameservers"] == ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"] and a["delegation_signed"] is True
    assert a["created"] == "1995-08-14T04:00:00Z" and a["updated"] == "2026-08-14T08:01:43Z"  # not 'last update of RDAP database'
    assert a["domain_age_days"] == (res_now() - parse("1995-08-14T04:00:00Z")).days
    assert "abuse_contact" not in a  # the empty abuse vCard gives nothing
    assert res.raw["via_rdap_org"] is False
    assert http.urls() == [BOOT["dns"], VERISIGN.format("example.com")]


def test_registrar_abuse_contact_is_kept():
    http = boot(FakeHttp(), "dns")
    rdap_json(http, VERISIGN.format("github.com"), fx("verisign_domain_registrar_abuse.json"))
    res = run("domain:github.com", http)
    a = res.attributes
    assert (a["registrar"], a["registrar_iana_id"], a["abuse_contact"], a["abuse_phone"]) == ("MarkMonitor Inc.", "292", "abuse@example.com", "tel:+55.1155550101")
    assert a["delegation_signed"] is False and "registrant_kind" not in a  # Verisign (thin registry) names no registrant


def test_authoritative_404_is_not_registered():
    http = boot(FakeHttp(), "dns")
    exchange(http, VERISIGN.format("zz-unregistered-0000.com"), "verisign_not_found.http.json")
    res = run("domain:zz-unregistered-0000.com", http)
    assert res.status is Status.OK and res.attributes["registered"] is False and res.attributes["rdap_server"] == "rdap.verisign.com"
    finding = res.findings[0]
    assert finding.title == "Not registered at the authoritative registry" and "authoritative" in finding.criterion


def test_rdap_org_no_service_404_is_not_applicable_never_unregistered():
    http = boot(FakeHttp(), "dns")
    exchange(http, RDAP_ORG.format("domain/yandex.ru"), "rdaporg_no_service.http.json")
    res = run("domain:yandex.ru", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "WHOIS fallback" in res.error
    assert "registered" not in res.attributes


def test_rdap_org_plain_404_is_could_not_verify():
    http = boot(FakeHttp(), "dns")
    http.add("GET", RDAP_ORG.format("domain/yandex.ru"), status=404, json={"errorCode": 404, "title": "Not Found"})
    res = run("domain:yandex.ru", http)
    assert res.status is Status.ERROR and "never 'not registered'" in res.error and "registered" not in res.attributes


def test_bootstrap_unavailable_falls_back_to_rdap_org_and_follows_only_declared_hosts():
    http = FakeHttp().add("GET", BOOT["dns"], status=503, text="<html>503</html>")
    exchange(http, RDAP_ORG.format("domain/example.com"), "rdaporg_redirect.http.json")
    rdap_json(http, VERISIGN.format("example.com"), fx("verisign_domain_ok.json"))
    res = run("domain:example.com", http)
    assert res.status is Status.OK and res.raw["via_rdap_org"] is True and res.attributes["rdap_server"] == "rdap.verisign.com"
    http.assert_hosts_within(Rdap)


def test_br_names_never_go_through_the_bootstrap_or_rdap_org():
    http = FakeHttp().add("GET", BOOT["dns"], status=503, text="unavailable")
    exchange(http, RDAP_ORG.format("domain/nic.br"), "rdaporg_redirect_br.http.json")
    rdap_json(http, REGISTROBR.format("domain/nic.br"), fx("registrobr_domain_persons.json"))
    res = run("domain:nic.br", http)
    assert res.status is Status.OK and http.urls() == [REGISTROBR.format("domain/nic.br")]


def test_rdap_org_redirect_to_an_undeclared_host_is_skipped_policy():
    http = FakeHttp().add("GET", BOOT["dns"], status=503, text="unavailable")
    http.add("GET", RDAP_ORG.format("domain/example.com"), status=302, headers={"location": "https://rdap.registry.example.net/domain/example.com"})
    res = run("domain:example.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "policy"
    assert ("rdap.org lookup (manual)", "https://rdap.org/domain/example.com") in res.links
    assert "rdap.registry.example.net" not in http.hosts()


def test_undeclared_authoritative_server_is_skipped_policy_with_a_link():
    dns = fx("iana_dns_bootstrap.json")
    custom = {**dns, "services": [*dns["services"], [["tw"], ["https://ccrdap.twnic.tw/tw/"]]]}
    http = boot(FakeHttp(), "dns", custom)
    res = run("domain:example.tw", http)
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and "ccrdap.twnic.tw" in res.error
    assert res.links and http.hosts() == {"data.iana.org"}


def test_http_only_registry_is_not_applicable():
    http = boot(FakeHttp(), "dns")
    res = run("domain:example.kg", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "http://" in res.error
    assert http.hosts() == {"data.iana.org"}


def test_errors_inside_http_200_are_could_not_verify():
    for body in ({"errorCode": 500, "title": "Internal error"}, ["not", "an", "object"], {"ldhName": "example.com"}):
        http = boot(FakeHttp(), "dns")
        rdap_json(http, VERISIGN.format("example.com"), body)
        res = run("domain:example.com", http)
        assert res.status is Status.ERROR and "could not verify" in res.error, body
    http = boot(FakeHttp(), "dns").add("GET", VERISIGN.format("example.com"), text="<html><body>maintenance</body></html>")
    res = run("domain:example.com", http)
    assert res.status in (Status.ERROR, Status.BLOCKED) and "registered" not in res.attributes


def test_challenge_page_is_blocked():
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = boot(FakeHttp(), "dns").add("GET", VERISIGN.format("example.com"), status=403, text=page)
    res = run("domain:example.com", http)
    assert res.status is Status.BLOCKED and "registered" not in res.attributes


def test_bootstrap_is_downloaded_once_per_runtime():
    http = boot(FakeHttp(), "dns")
    rdap_json(http, VERISIGN.format("example.com"), fx("verisign_domain_ok.json"))
    rdap_json(http, VERISIGN.format("github.com"), fx("verisign_domain_registrar_abuse.json"))
    rt = make_runtime(http)
    assert run("domain:example.com", None, runtime=rt).status is Status.OK
    assert run("domain:github.com", None, runtime=rt).status is Status.OK
    assert http.urls().count(BOOT["dns"]) == 1


def test_subdomains_and_unknown_tlds_are_not_applicable():
    http = FakeHttp()
    for value in ("www.example.com", "com.br", "example.invalidtld"):
        assert run(f"domain:{value}", http).status is Status.SKIPPED
    assert http.calls == []


# ------------------------------------------------------------------ IP / ASN (cond 2, 9)
def test_ipv4_at_arin():
    http = boot(FakeHttp(), "ipv4")
    rdap_json(http, ARIN.format("ip/8.8.8.8"), fx("arin_ip_ok.json"))
    res = run("ipv4:8.8.8.8", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["rdap_network"]["cidrs"] == ["8.8.8.0/24"] and a["rdap_network"]["name"] == "GOGL" and a["rdap_server"] == "rdap.arin.net"
    assert a["registrant"] == "Google LLC" and a["abuse_contact"] == "network-abuse@example.com"
    assert [(p.entity.value, p.relation, p.expand) for p in res.pivots if p.entity.type is T.CIDR] == [("8.8.8.0/24", "in_network", False)]
    assert any(c.get("roles") == ["abuse"] and c.get("email") == "network-abuse@example.com" for c in a["rdap_contacts"])


def test_asn_at_arin():
    http = boot(FakeHttp(), "asn")
    rdap_json(http, ARIN.format("autnum/13335"), fx("arin_asn.json"))
    res = run("asn:AS13335", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["rdap_autnum"]["start"] == 13335 and a["rdap_autnum"]["name"] == "CLOUDFLARENET"
    assert a["as_org"] == "Cloudflare, Inc." and a["abuse_contact"] == "abuse@example.com"
    assert a["created"] == "2010-07-14T22:35:57Z"  # -04:00 normalised to UTC


def test_lacnic_307_to_registrobr_for_brazilian_space():
    http = boot(FakeHttp(), "ipv4")
    http.add("GET", LACNIC.format("ip/200.160.0.1"), status=307, redirect_to=REGISTROBR.format("ip/200.160.0.1"))
    rdap_json(http, REGISTROBR.format("ip/200.160.0.1"), fx("registrobr_ip.json"))
    res = run("ipv4:200.160.0.1", http)
    assert res.status is Status.OK and res.attributes["rdap_server"] == "rdap.registro.br"
    assert res.attributes["rdap_network"]["cidrs"] == ["200.160.0.0/20"] and res.attributes["asn"] == "AS22548"
    assert [(p.entity.value, p.relation) for p in res.pivots if p.entity.type is T.CNPJ] == [("05506560000136", "registrant")]
    assert ("AS22548", "belongs_to_asn") in {(p.entity.value, p.relation) for p in res.pivots}
    assert "Beltrano" not in dump(res) and "Fulano" not in dump(res)


def test_lacnic_br_answer_without_redirect_queries_registrobr():
    http = boot(FakeHttp(), "ipv4")
    rdap_json(http, LACNIC.format("ip/200.160.0.1"), fx("lacnic_ip_br.json"))
    rdap_json(http, REGISTROBR.format("ip/200.160.0.1"), fx("registrobr_ip.json"))
    res = run("ipv4:200.160.0.1", http)
    assert res.status is Status.OK and res.attributes["rdap_server"] == "rdap.registro.br"
    assert http.urls() == [BOOT["ipv4"], LACNIC.format("ip/200.160.0.1"), REGISTROBR.format("ip/200.160.0.1")]


def test_lacnic_br_answer_kept_when_registrobr_refuses():
    http = boot(FakeHttp(), "ipv4")
    rdap_json(http, LACNIC.format("ip/200.160.0.1"), fx("lacnic_ip_br.json"))
    exchange(http, REGISTROBR.format("ip/200.160.0.1"), "registrobr_blocked.http.json")
    res = run("ipv4:200.160.0.1", http)
    assert res.status is Status.OK and res.attributes["rdap_server"] == "rdap.lacnic.net"
    assert res.attributes["registrant"] == "Nucleo de Inf. e Coord. do Ponto BR - NIC.BR"
    assert res.source_statuses["registrobr.rdap"]["status"] == "blocked" and "could not verify" in res.error
    assert any("registro.br/tecnologia/ferramentas/whois" in url for _label, url in res.links)


def test_arin_303_to_apnic_never_uses_the_redirect_body():
    http = boot(FakeHttp(), "ipv4", {"version": "1.0", "services": [[["1.0.0.0/8"], ["https://rdap.arin.net/registry/"]]]})
    resp = fx("arin_redirect_303.http.json")["response"]
    http.add("GET", ARIN.format("ip/1.1.1.1"), status=303, json=resp["body"], headers=resp["headers"])
    rdap_json(http, APNIC.format("ip/1.1.1.1"), APNIC_1111)
    res = run("ipv4:1.1.1.1", http)
    assert res.status is Status.OK and res.attributes["rdap_server"] == "rdap.apnic.net"
    assert res.attributes["rdap_network"]["name"] == "APNIC-LABS" and res.attributes["country"] == "AU"
    assert "APNIC-1" not in dump(res)


def test_asn_22548_follows_arin_303_and_lacnic_307_to_registrobr():
    http = boot(FakeHttp(), "asn")
    http.add("GET", ARIN.format("autnum/22548"), status=303, redirect_to=LACNIC.format("autnum/22548"))
    http.add("GET", LACNIC.format("autnum/22548"), status=307, redirect_to=REGISTROBR.format("autnum/22548"))
    rdap_json(http, REGISTROBR.format("autnum/22548"), fx("registrobr_asn.json"))
    res = run("asn:AS22548", http)
    assert res.status is Status.OK and res.attributes["rdap_server"] == "rdap.registro.br"
    assert res.attributes["as_org"] == "Núcleo de Inf. e Coord. do Ponto BR - NIC.BR"
    assert [(p.entity.value, p.relation) for p in res.pivots if p.entity.type is T.CNPJ] == [("05506560000136", "registrant")]
    assert "Beltrano" not in dump(res) and "Fulano" not in dump(res)


def test_private_reserved_and_unallocated_values():
    http = FakeHttp()
    for value in ("ipv4:10.0.0.1", "ipv4:192.0.2.1", "ipv6:2001:db8::1", "asn:AS64512", "asn:AS4200000000", "asn:AS23456"):
        assert run(value, http).status is Status.SKIPPED, value
    assert http.calls == []
    http = boot(FakeHttp(), "ipv4")
    res = run("ipv4:5.5.5.5", http)  # global, but not in the (trimmed) bootstrap
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "bootstrap" in res.error


def test_cidr_entity_queries_the_prefix():
    http = boot(FakeHttp(), "ipv4")
    rdap_json(http, ARIN.format("ip/8.8.8.0/24"), fx("arin_ip_ok.json"))
    res = run("cidr:8.8.8.0/24", http)
    assert res.status is Status.OK and res.attributes["rdap_network"]["start"] == "8.8.8.0"


# ------------------------------------------------------------------ minimisation units (cond 4-8)
def test_privacy_proxy_registrant_is_redacted_and_never_pivots():
    privacy = load_privacy_list()
    mini = minimise_rdap(fx("privacy_proxy_domain.json"), res_now(), privacy)
    assert mini["privacy_proxy"] is True and mini["registrant_kind"] == "redacted"
    assert mini["registrant"]["org"] is None and mini["cnpj"] == []
    assert mini["registrar"] == {"name": "Example Registrar, LLC", "iana_id": "146", "abuse": {"email": "abuse@example.com", "tel": "tel:+55.1155550105"}}
    assert "domainsbyproxy" not in json.dumps(mini)
    body = dict(fx("privacy_proxy_domain.json"), ldhName="EXAMPLE-SHOP.COM")
    http = boot(FakeHttp(), "dns")
    rdap_json(http, VERISIGN.format("example-shop.com"), body)
    res = run("domain:example-shop.com", http)
    assert res.attributes["privacy_proxy"] is True and res.attributes["registrant_kind"] == "redacted"
    assert not any(p.entity.type in (T.ORG, T.CNPJ) for p in res.pivots)


def test_privacy_list_matches_patterns_and_mail_domains():
    privacy = load_privacy_list()
    assert privacy.matches("REDACTED FOR PRIVACY") and privacy.matches("x@domainsbyproxy.com")
    assert not privacy.matches("Banco do Brasil S.A.") and not privacy.matches("")


def test_brand_label_match():
    assert brand_label_match("exemplo-teste-0000.com.br", ["exemplo"]) == "exemplo"
    assert brand_label_match("bancoexemplo.com.br", ["Exémplo"]) == "exemplo"
    assert brand_label_match("abc.com.br", ["abc"]) is None  # brands shorter than 4 characters never match
