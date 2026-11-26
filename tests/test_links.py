"""P311 pivot-link engine: schema, legacy migration, whitelist rendering, encoders, validation and lint."""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from v3lum.core import links
from v3lum.core.entities import Entity, EntityType, secret_entity

T = EntityType


def pack(*items, name="test_pack", **extra):
    return {"schema": "v3lum.pivot_pack/1", "pack": name, "title": "Test pack", "links": list(items), **extra}


def item(**overrides):
    base = {
        "id": "vt_domain",
        "label": "VirusTotal domain",
        "template": "https://www.virustotal.com/gui/domain/{domain}",
        "entity_types": ["domain"],
        "category": "reputation",
        "host": "www.virustotal.com",
        "verified": False,
        "checked_at": "",
        "privacy": False,
        "publishes": False,
        "touches_target": False,
        "login_required": False,
        "antibot": False,
        "notes": "",
    }
    base.update(overrides)
    return base


@pytest.fixture()
def tiers(monkeypatch):
    """Deterministic provider tiers: host -> tier (unlisted hosts are unregistered = unknown)."""
    table: dict[str, str] = {}
    flags: dict[str, bool] = {}

    def fake(host):
        if host in table or host in flags:
            return SimpleNamespace(tier=table.get(host, "unknown"), flags=SimpleNamespace(publishes_queries=flags.get(host, False)))
        return None

    original = links._provider_for_host
    monkeypatch.setattr(links, "_provider_for_host", fake)
    links.reload()
    yield SimpleNamespace(tier=table, publishes=flags)
    monkeypatch.setattr(links, "_provider_for_host", original)
    links.reload()


@pytest.fixture()
def extra_packs(tmp_path):
    def load(files: dict[str, object]):
        for fname, data in files.items():
            (tmp_path / fname).write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")
        links.reload(extra_dirs=[tmp_path])

    yield load
    links.reload()


# ---------------------------------------------------------------- shipped packs


def test_shipped_packs_are_clean():
    assert links.errors() == []
    assert set(links.packs()) >= {"core_reference"}
    refs = {link.ref for link in links.templates()}
    assert {"core_reference:shodan_host", "core_reference:iana_whois"} <= refs
    shodan = links.get_link("core_reference:shodan_host")
    assert shodan.template == "https://www.shodan.io/host/{ip}" and shodan.entity_types == (T.IPV4, T.IPV6)
    assert (shodan.category, shodan.host, shodan.verified) == ("reputation", "www.shodan.io", True)
    iana = links.get_link("core_reference:iana_whois")
    assert iana.template == "https://www.iana.org/whois?q={domain}" and iana.entity_types == (T.DOMAIN,)
    assert (iana.category, iana.host, iana.verified) == ("history", "www.iana.org", True)
    for data_file in links.PACKS_DIR.glob("*.json"):
        assert links.lint_pack(json.loads(data_file.read_text(encoding="utf-8")), source=data_file.name) == []


FIXTURE_VALUES = {
    T.IPV4: "8.8.8.8", T.IPV6: "2001:4860:4860::8888", T.DOMAIN: "example.com", T.URL: "https://example.com/",
    T.EMAIL: "someone@example.com", T.SHA256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    T.CNPJ: "00000000000191", T.ASN: "AS15169", T.PHONE: "+5511987654321", T.USERNAME: "octocat",
    # types used by module-batch pivot packs (v3lum/data/pivot_links/<batch>.json)
    T.MD5: "44d88612fea8a8f36de82e1278abb02f", T.SHA1: "3395856ce81f2b7382dee72602f798b642f14140",
    T.CERT_FP: "5ef2f2c1b5b2bbd2a31b4b0b4e3a3ab4b9b9c4d7c0c2e0f3a6d2b4f1e3a5c7d9", T.CVE: "CVE-2021-44228",
    T.MALWARE: "emotet",
}


def test_every_bundled_template_renders_a_valid_https_url():
    seen = 0
    for link in links.templates():
        for etype in link.entity_types:
            if etype not in FIXTURE_VALUES and not link.ref.startswith("core_reference:"):
                continue  # a batch pack's new type: its pack is linted by test_registry_contract (lint_pack)
            assert etype in FIXTURE_VALUES, f"add a fixture value for {etype.value}"
            rendered = links.render(link, Entity.make(etype, FIXTURE_VALUES[etype]))
            if link.privacy:
                continue
            assert rendered is not None, link.ref
            parts = urlsplit(rendered.url)
            assert parts.scheme == "https" and parts.hostname == link.host and not parts.username and parts.port is None
            seen += 1
    assert seen >= 3


def test_links_for_legacy_signature():
    # module-batch pivot packs add links after the core reference pack: the core entries come first
    assert links.links_for(Entity.make("ipv4", "8.8.8.8"))[0] == ("Shodan host", "https://www.shodan.io/host/8.8.8.8")
    assert ("IANA WHOIS", "https://www.iana.org/whois?q=example.com") in links.links_for(Entity.make("domain", "example.com"), categories={"history"})
    assert links.links_for(Entity.make("domain", "example.com"), categories={"social"}) == []
    assert links.links_for(Entity.make("cpf", "52998224725")) == []


def test_frozen_schema_names():
    assert set(links.PLACEHOLDERS) == {
        "q", "qp", "raw", "domain", "user", "b64", "b64url", "e164", "e164_plus", "br_national", "br_national_no9",
        "wa", "cnpj_fmt", "cnpj_digits", "cnpj_root", "idn", "punycode", "ip", "asn_num",
    }
    assert links.LINK_CATEGORIES == (
        "reputation", "history", "passive_dns", "code_paste", "social", "company", "crypto", "geo", "search", "other",
    )
    assert set(links.PLACEHOLDER_TYPES) <= set(links.PLACEHOLDERS)
    assert links.SCHEMA == "v3lum.pivot_pack/1"
    assert links._RE_PLACEHOLDER.pattern == r"\{([a-z0-9_]+)\}"


# ---------------------------------------------------------------- legacy format migration


def test_legacy_items_are_migrated(extra_packs, tiers):
    legacy = [
        {"name": "Shodan search", "types": ["ipv4"], "url": "https://www.shodan.io/search?query={q}",
         "category": "threat_intel", "description": "Search Shodan", "source": "Ceos fontes_manuais"},
        {"name": "Shodan search", "types": ["ipv4"], "url": "https://www.shodan.io/search?query=ip:{q}"},
        {"name": "Old http", "types": ["domain"], "url": "http://insecure.example/{domain}"},
    ]
    extra_packs({"legacy_tools.json": legacy, "legacy_box.json": {"links": [legacy[0] | {"url": "https://www.shodan.io/x/{q}"}]}})
    first = links.get_link("legacy_tools:shodan_search")
    assert first is not None
    assert (first.label, first.template, first.entity_types, first.host) == (
        "Shodan search", "https://www.shodan.io/search?query={q}", (T.IPV4,), "www.shodan.io")
    assert first.verified is False and first.category == "reputation" and "Ceos" in first.notes
    assert links.get_link("legacy_tools:shodan_search_2") is not None  # unique ids for repeated names
    assert links.get_link("legacy_box:shodan_search") is not None  # {"links": [...]} container without schema
    assert any("legacy_tools.json" in e and "https only" in e for e in links.errors())
    rendered = links.render("legacy_tools:shodan_search", Entity.make("ipv4", "1.2.3.4"))
    assert rendered.url == "https://www.shodan.io/search?query=1.2.3.4" and rendered.badge == "unknown operator, unverified"


def test_lint_pack_reports_legacy_and_schema_problems():
    assert links.lint_pack({"schema": "v3lum.pivot_pack/2", "links": []}, source="x.json")[0].endswith("(expected 'v3lum.pivot_pack/1')")
    assert any("must equal the file stem" in e for e in links.lint_pack(pack(item(), name="other"), source="test_pack.json"))
    assert any("missing \"schema\"" in e for e in links.lint_pack({"links": [item()]}, source="test_pack.json"))
    assert links.lint_pack("nope", source="x.json") == ["x.json: a pack is an object (or a legacy list)"]


# ---------------------------------------------------------------- encoders


def test_phone_encoders():
    assert links.encode_e164("(11) 98765-4321") == "5511987654321"
    assert links.encode_e164("+5511987654321", plus=True) == "+5511987654321"
    assert links.encode_wa("+55 11 98765-4321") == "5511987654321"
    assert links.encode_br_national("+5511987654321") == "11987654321"
    assert links.encode_br_national("+5511987654321", with_nine=False) == "1187654321"
    assert links.encode_br_national("+551187654321") == "11987654321"  # mobile written without the 9
    assert links.encode_br_national("+551187654321", with_nine=False) == "1187654321"
    assert links.encode_br_national("+551133334444") == links.encode_br_national("+551133334444", with_nine=False) == "1133334444"
    with pytest.raises(ValueError):
        links.encode_br_national("+14155552671")
    with pytest.raises(ValueError):
        links.encode_e164("not a phone")


def test_cnpj_and_domain_encoders():
    assert links.cnpj_fmt("00000000000191") == "00.000.000/0001-91"
    assert links.cnpj_fmt("12.abc.345/01de-35") == "12.ABC.345/01DE-35"
    assert links.cnpj_digits("00.000.000/0001-91") == "00000000000191"
    assert links.cnpj_root("00.000.000/0001-91") == "00000000"
    with pytest.raises(ValueError):
        links.cnpj_fmt("00.000.000/0001-92")
    assert links.punycode("münchen.de") == "xn--mnchen-3ya.de"
    assert links.idn_unicode("xn--mnchen-3ya.de") == "münchen.de"
    assert links.idn_unicode("example.com") == "example.com"


def test_base64_encoders():
    assert links.b64("example.com") == "ZXhhbXBsZS5jb20="
    assert links.b64url("https://example.com/?a=b") == "aHR0cHM6Ly9leGFtcGxlLmNvbS8_YT1i"
    assert "=" not in links.b64url("a")


@pytest.mark.parametrize(
    "template,etype,value,expected",
    [
        ("https://h.example/s?q={q}", T.DOMAIN, "example.com", "https://h.example/s?q=example.com"),
        ("https://h.example/s?q={q}", T.URL, "https://example.com/a b", "https://h.example/s?q=https%3A%2F%2Fexample.com%2Fa%20b"),
        ("https://h.example/s?q={qp}", T.KEYWORD, "acme corp", "https://h.example/s?q=acme+corp"),
        ("https://h.example/web/{raw}", T.URL, "https://example.com/x?y=1", "https://h.example/web/https://example.com/x?y=1"),
        ("https://h.example/d/{domain}", T.EMAIL, "someone@example.com", "https://h.example/d/example.com"),
        ("https://h.example/d/{domain}", T.URL, "https://sub.example.com/x", "https://h.example/d/sub.example.com"),
        ("https://h.example/u/{user}", T.EMAIL, "someone@example.com", "https://h.example/u/someone"),
        ("https://h.example/u/{user}", T.SOCIAL_ACCOUNT, "x:jack", "https://h.example/u/jack"),
        ("https://h.example/r?qbase64={b64}", T.DOMAIN, "example.com", "https://h.example/r?qbase64=ZXhhbXBsZS5jb20%3D"),
        ("https://h.example/r/{b64url}", T.DOMAIN, "example.com", "https://h.example/r/ZXhhbXBsZS5jb20"),
        ("https://h.example/p/{e164}", T.PHONE, "+5511987654321", "https://h.example/p/5511987654321"),
        ("https://h.example/p?n={e164_plus}", T.PHONE, "+5511987654321", "https://h.example/p?n=%2B5511987654321"),
        ("https://h.example/p/{br_national}/{br_national_no9}", T.PHONE, "+5511987654321", "https://h.example/p/11987654321/1187654321"),
        ("https://h.example/{wa}", T.PHONE, "+5511987654321", "https://h.example/5511987654321"),
        ("https://h.example/c?f={cnpj_fmt}&d={cnpj_digits}&r={cnpj_root}", T.CNPJ, "00000000000191",
         "https://h.example/c?f=00.000.000%2F0001-91&d=00000000000191&r=00000000"),
        ("https://h.example/i/{idn}/{punycode}", T.DOMAIN, "xn--mnchen-3ya.de", "https://h.example/i/m%C3%BCnchen.de/xn--mnchen-3ya.de"),
        ("https://h.example/ip/{ip}", T.IPV6, "2001:db8::1", "https://h.example/ip/2001:db8::1"),
        ("https://h.example/as/{asn_num}", T.ASN, "AS15169", "https://h.example/as/15169"),
    ],
)
def test_placeholder_rendering(tiers, template, etype, value, expected):
    tiers.tier["h.example"] = "trusted"  # personal/company/keyword values need a reviewed provider tier
    link = links.PivotLink("t", "x", "X", template, (etype,), "other", "h.example", privacy=True)
    assert links.validate_template(template, host="h.example", entity_types=[etype]) == []
    rendered = links.render(link, Entity.make(etype, value))
    assert rendered is not None and rendered.url == expected
    assert rendered.tier == "trusted"  # from the provider registry


def test_raw_placeholder_encodes_unsafe_characters(tiers):
    tiers.tier["h.example"] = "community"
    link = links.PivotLink("t", "x", "X", "https://h.example/k/{raw}", (T.KEYWORD,), "search", "h.example")
    url = links.render(link, Entity.make("keyword", 'a b"<script>{x}')).url
    assert url == "https://h.example/k/a%20b%22%3Cscript%3E%7Bx%7D"


def test_caller_built_links_are_linted_and_never_trust_a_claimed_tier(tiers):
    mail = Entity.make("email", "someone@example.com")
    claimed = links.PivotLink("t", "m", "M", "https://h.example/m/{q}", (T.EMAIL,), "social", "h.example", privacy=True, tier="trusted")
    assert links.render(claimed, mail) is None  # h.example is unregistered = unknown, whatever the link claims
    tiers.tier["h.example"] = "community"
    assert links.render(claimed, mail).tier == "community"
    scan = links.PivotLink("t", "s", "S", "https://urlscan.io/api/v1/scan/?url={q}", (T.URL,), "reputation", "urlscan.io", tier="trusted")
    assert links.render(scan, Entity.make("url", "https://example.com/")) is None  # LINT-05 also for ad-hoc links
    reset = links.PivotLink("t", "r", "R", "https://h.example/reset?email={q}", (T.EMAIL,), "other", "h.example", privacy=True)
    assert links.render(reset, mail) is None  # LINT-03: a password-reset probe
    unverified_claim = links.PivotLink("t", "v", "V", "https://h.example/d/{domain}", (T.DOMAIN,), "other", "h.example", verified=True)
    assert links.render(unverified_claim, Entity.make("domain", "example.com")) is None  # verified needs checked_at
    domain = Entity.make("domain", "example.com")
    ok = links.PivotLink("t", "d", "D", "https://h.example/d/{domain}", (T.DOMAIN,), "other", "h.example")
    assert links.render(ok, domain).url == "https://h.example/d/example.com"
    for bad in (replace(ok, label="D\x1b[2J"), replace(ok, label=""), replace(ok, category="threat"),
                replace(ok, entity_types=["domain"])):
        assert links.render(bad, domain) is None
    assert links.pivot_links_for("example.com") == []  # not an Entity


def test_unknown_tier_hosts_receive_ioc_types_only(tiers):
    """A8: unknown-tier providers may receive IOC_TYPES values only (lint and render)."""
    company = item(id="company_search", template="https://ioc.example/c?q={q}", host="ioc.example",
                   entity_types=["company_name"], category="company")
    errs = lint_errors(company)
    assert any("IOC_TYPES values only" in e and "company_name" in e for e in errs)
    mixed = item(id="mixed", template="https://ioc.example/q?q={q}", host="ioc.example", entity_types=["domain", "keyword"])
    assert any("keyword" in e and "IOC_TYPES values only" in e for e in lint_errors(mixed))
    assert lint_errors(item(id="ioc", template="https://ioc.example/d/{domain}", host="ioc.example")) == []
    tiers.tier["ioc.example"] = "community"
    assert lint_errors(company) == [] and lint_errors(mixed) == []
    tiers.tier["ioc.example"] = "unknown"
    adhoc = links.PivotLink("t", "k", "K", "https://ioc.example/k/{q}", (T.KEYWORD, T.MALWARE), "search", "ioc.example")
    assert links.render(adhoc, Entity.make("keyword", "acme")) is None
    assert links.render(adhoc, Entity.make("malware_family", "Emotet")) is None
    hashes = links.PivotLink("t", "h", "H", "https://ioc.example/h/{q}", (T.SHA256, T.IMPHASH), "reputation", "ioc.example")
    sample = Entity.make("sha256", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert links.render(hashes, sample).badge == "unknown operator, unverified"


# ---------------------------------------------------------------- whitelist and template validation


def test_unknown_placeholders_and_str_format_injection_are_rejected():
    for template in ("https://h.example/{0.__class__}", "https://h.example/{entity.value}", "https://h.example/{value!r}",
                     "https://h.example/{Q}", "https://h.example/{ q }"):
        errs = links.validate_template(template, host="h.example", entity_types=["domain"])
        assert any("malformed placeholder" in e for e in errs), template
    assert any("unknown placeholders ['cpf']" in e for e in links.validate_template(
        "https://h.example/{cpf}", host="h.example", entity_types=["domain"]))
    injected = links.PivotLink("t", "x", "X", "https://h.example/{0.__class__}{q}", (T.DOMAIN,), "other", "h.example", tier="trusted")
    assert links.render(injected, Entity.make("domain", "example.com")) is None  # never str.format
    unknown = links.PivotLink("t", "x", "X", "https://h.example/{secret_key}", (T.DOMAIN,), "other", "h.example", tier="trusted")
    assert links.render(unknown, Entity.make("domain", "example.com")) is None


@pytest.mark.parametrize(
    "template,host,fragment",
    [
        ("http://h.example/{q}", "h.example", "https only"),
        ("ftp://h.example/{q}", "h.example", "https only"),
        ("https://other.example/{q}", "h.example", "differs from the declared host"),
        ("https://{domain}/x", "h.example", "only in the path, query or fragment"),
        ("https://h.example.{domain}/x", "h.example", "only in the path, query or fragment"),
        ("https://user@h.example/{q}", "h.example", "userinfo"),
        ("https://h.example:8443/{q}", "h.example", "explicit ports"),
        ("https://h.example/{q} x", "h.example", "whitespace"),
        ("//h.example/{q}", "h.example", "absolute https URL"),
        ("https://H.example/{q}", "H.example", "must be lower-case"),
        ("https://münchen.de/{q}", "münchen.de", "canonical"),
    ],
)
def test_template_url_validation(template, host, fragment):
    errs = links.validate_template(template, host=host, entity_types=["domain"])
    assert any(fragment in e for e in errs), errs


def test_type_restricted_placeholders():
    errs = links.validate_template("https://h.example/{e164}", host="h.example", entity_types=["phone", "email"])
    assert errs == ["placeholder {e164} is valid only for phone (declared email)"]
    assert links.validate_template("https://h.example/{ip}", host="h.example", entity_types=["ipv4", "ipv6"]) == []
    assert any("valid only for" in e for e in links.validate_template("https://h.example/{cnpj_root}", host="h.example",
                                                                       entity_types=["domain"]))
    assert any("unknown entity type 'hostname'" in e for e in links.validate_template(
        "https://h.example/{q}", host="h.example", entity_types=["hostname"]))
    # at render time a restricted placeholder that does not apply drops the link
    link = links.PivotLink("t", "x", "X", "https://h.example/{br_national}", (T.PHONE,), "other", "h.example", privacy=True, tier="trusted")
    assert links.render(link, Entity.make("phone", "+14155552671")) is None


@pytest.mark.parametrize(
    "template",
    ["https://h.example/s?url={raw}", "https://h.example/{raw}/x", "https://h.example/{raw}?lang=en",
     "https://h.example/a/{raw}{raw}", "https://h.example/#/{raw}", "https://h.example/s?u={q}&r={raw}"],
)
def test_raw_placeholder_only_at_the_end_of_the_path(template):
    errs = links.validate_template(template, host="h.example", entity_types=["url"])
    assert any("{raw} is allowed only once" in e for e in errs), errs


def test_untrusted_values_cannot_inject_query_parameters(tiers):
    url = Entity.make("url", "https://evil.example/x?y=1&private=0#frag")
    safe = links.PivotLink("t", "s", "S", "https://h.example/scan-result?url={q}&private=1", (T.URL,), "reputation", "h.example")
    rendered = links.render(safe, url).url
    assert rendered.endswith("&private=1") and rendered.count("&") == 1 and "#" not in rendered
    archive = links.PivotLink("t", "a", "A", "https://h.example/web/{raw}", (T.URL,), "history", "h.example")
    assert links.render(archive, url).url == "https://h.example/web/https://evil.example/x?y=1&private=0#frag"
    injected = links.PivotLink("t", "i", "I", "https://h.example/s?url={raw}&private=1", (T.URL,), "reputation", "h.example")
    assert links.render(injected, url) is None  # caller-built links are validated too


def test_rendered_urls_are_rechecked():
    sneaky = links.PivotLink("t", "x", "X", "https://h.example{raw}", (T.KEYWORD,), "other", "h.example", tier="trusted")
    assert links.render(sneaky, Entity.make("keyword", "@evil.example")) is None
    assert links.render(sneaky, Entity.make("keyword", ".evil.example")) is None


# ---------------------------------------------------------------- lint


def lint_errors(*items, name="test_pack"):
    return links.lint_pack(pack(*items, name=name), source=f"{name}.json")


def test_lint_accepts_a_clean_ioc_link(tiers):
    assert lint_errors(item()) == []


def test_lint_rejects_cpf_templates(tiers):
    tiers.tier["www.gov.example"] = "trusted"
    errs = lint_errors(item(template="https://www.gov.example/consulta/{q}", host="www.gov.example", entity_types=["cpf"], privacy=True))
    assert any("no template accepts CPF" in e for e in errs)
    errs = lint_errors(item(template="https://www.gov.example/consulta?cpf={q}", host="www.gov.example", entity_types=["domain"]))
    assert any("LINT-04" in e for e in errs)


@pytest.mark.parametrize(
    "template,host",
    [
        ("https://urlscan.io/api/v1/scan/?url={q}", "urlscan.io"),
        ("https://www.virustotal.com/gui/home/upload?u={q}", "www.virustotal.com"),
        ("https://web.archive.org/save/{raw}", "web.archive.org"),
        ("https://archive.ph/submit/?url={q}", "archive.ph"),
        ("https://www.ssllabs.com/ssltest/analyze.html?d={domain}", "www.ssllabs.com"),
        ("https://tools.example/recent-searches?q={q}", "tools.example"),
        ("https://tools.example/submit?url={q}", "tools.example"),
    ],
)
def test_lint_rejects_submission_endpoints(tiers, template, host):
    errs = lint_errors(item(template=template, host=host, entity_types=["url"]))
    assert any("LINT-05" in e for e in errs), errs


def test_lint_rejects_scan_trigger_publishes_and_login(tiers):
    assert any("scan_trigger" in e for e in lint_errors(item(scan_trigger=True)))
    assert any("publishes must be false" in e for e in lint_errors(item(publishes=True)))
    assert any("login_required must be false" in e for e in lint_errors(item(login_required=True)))
    assert any("LINT-03" in e for e in lint_errors(item(template="https://www.virustotal.com/login?next={domain}")))
    tiers.publishes["www.virustotal.com"] = True
    assert any("publishes_queries" in e for e in lint_errors(item()))


@pytest.mark.parametrize("host", ["tudosobretodos.info", "www.dehashed.com", "cadastropre.com.br", "consulta.paineldados.xyz"])
def test_lint_rejects_people_search_hosts(tiers, host):
    tiers.tier[host] = "community"
    errs = lint_errors(item(template=f"https://{host}/busca?q={{q}}", host=host, entity_types=["phone"], privacy=True))
    assert any("LINT-04" in e for e in errs), errs


def test_lint_personal_and_company_values_need_privacy_and_a_reviewed_tier(tiers):
    phone = item(id="phone_search", template="https://search.example/p/{e164}", host="search.example",
                 entity_types=["phone"], category="search")
    errs = lint_errors(phone)
    assert any("need privacy=true" in e for e in errs)
    assert any("only go to trusted/community provider hosts" in e and "is unknown" in e for e in errs)  # unregistered
    phone["privacy"] = True
    assert any("is unknown" in e for e in lint_errors(phone))
    tiers.tier["search.example"] = "unknown"
    assert any("is unknown" in e for e in lint_errors(phone))
    tiers.tier["search.example"] = "community"
    assert lint_errors(phone) == []
    cnpj = item(id="cnpj_lookup", template="https://cnpj.example/{cnpj_digits}", host="cnpj.example",
                entity_types=["cnpj"], category="company")
    assert any("cnpj" in e and "unknown" in e for e in lint_errors(cnpj))
    tiers.tier["cnpj.example"] = "trusted"
    cnpj["privacy"] = True
    assert lint_errors(cnpj) == []
    vat = item(id="vat_lookup", template="https://vat.example/{q}", host="vat.example", entity_types=["eu_vat"], privacy=True)
    assert any("eu_vat" in e for e in lint_errors(vat))


def test_lint_field_rules(tiers):
    assert any("unknown fields ['verifed']" in e for e in lint_errors(item(verifed=True)))
    assert lint_errors(item(x_owner="batch g07")) == []
    assert any("category 'threat'" in e for e in lint_errors(item(category="threat")))
    assert any("checked_at" in e for e in lint_errors(item(verified=True)))
    assert lint_errors(item(verified=True, checked_at="2026-11-25")) == []
    assert any("invalid id" in e for e in lint_errors(item(id="Bad-Id")))
    assert any("verified must be true or false" in e for e in lint_errors(item(verified="yes")))
    assert any("no placeholder" in e for e in lint_errors(item(template="https://www.virustotal.com/gui/home")))
    assert any("jwt values never go into links" in e for e in lint_errors(item(entity_types=["jwt"], template="https://www.virustotal.com/{q}")))
    assert any("duplicate link id" in e for e in lint_errors(item(), item()))
    assert any("checked_at must be a date" in e for e in lint_errors(item(verified=True, checked_at="2026-13-45")))
    assert any("notes must be a string" in e for e in lint_errors(item(notes={"x": 1})))


@pytest.mark.parametrize(
    "template,host",
    [
        ("https://hunter.io/verify/{q}", "hunter.io"),  # SMTP verification of an address
        ("https://api.example.com/check?email={q}", "api.example.com"),  # existence oracle
        ("https://api.example.com/v1/usernames/{user}/available", "api.example.com"),
        ("https://www.example.com/password/new?email={q}", "www.example.com"),
    ],
)
def test_lint_rejects_enumeration_templates(tiers, template, host):
    errs = lint_errors(item(template=template, host=host, entity_types=["email", "username"], privacy=True))
    assert any("LINT-03" in e for e in errs), errs


def test_reputation_check_pages_stay_allowed(tiers):
    abuseipdb = item(id="abuseipdb", template="https://www.abuseipdb.com/check/{ip}", host="www.abuseipdb.com", entity_types=["ipv4"])
    assert lint_errors(abuseipdb) == []


def test_pack_without_schema_is_not_loaded(extra_packs, tiers):
    extra_packs({"test_pack.json": {"pack": "test_pack", "title": "No schema", "links": [item()]}})
    assert links.get_link("test_pack:vt_domain") is None
    assert "test_pack" not in links.packs()
    assert any("test_pack.json" in e and "missing \"schema\"" in e for e in links.errors())


def test_invalid_links_are_dropped_fail_closed(extra_packs, tiers):
    # a template of its own: a bundled batch pack may already serve the default one (deduplicated)
    good = item(template="https://www.virustotal.com/gui/domain/{domain}/test-pack")
    extra_packs({"test_pack.json": pack(good, item(id="bad", template="http://www.virustotal.com/{q}"))})
    assert links.get_link("test_pack:vt_domain") is not None
    assert links.get_link("test_pack:bad") is None
    assert any("test_pack:bad" in e for e in links.errors())


def test_duplicate_pack_names_and_unreadable_files(extra_packs, tiers):
    extra_packs({"core_reference.json": pack(item(), name="core_reference"), "zz_broken.json": "{not json"})
    errs = "\n".join(links.errors())
    assert "duplicate pack name 'core_reference'" in errs and "zz_broken.json: unreadable pack" in errs


# ---------------------------------------------------------------- badges, ordering, privacy at render time


def test_unknown_operator_badge_for_ioc_links(extra_packs, tiers):
    tiers.tier["www.shodan.io"] = "trusted"
    extra_packs({"test_pack.json": pack(
        item(id="unknown_host", template="https://ioc.example/d/{domain}", host="ioc.example", verified=True, checked_at="2026-11-25"),
        item(id="unverified_known", template="https://www.shodan.io/domain/{domain}", host="www.shodan.io"),
    )})
    rendered = {r.ref: r for r in links.pivot_links_for(Entity.make("domain", "example.com"))}
    assert rendered["test_pack:unknown_host"].badge == "unknown operator"
    assert rendered["test_pack:unknown_host"].tier == "unknown"
    assert rendered["test_pack:unverified_known"].badge == "unverified"
    order = [r.verified for r in links.pivot_links_for(Entity.make("domain", "example.com"))]
    assert order == sorted(order, reverse=True)  # verified first


def test_privacy_links_only_on_request(extra_packs, tiers):
    tiers.tier["people.example"] = "community"
    extra_packs({"test_pack.json": pack(item(id="mail_lookup", template="https://people.example/m/{q}", host="people.example",
                                             entity_types=["email"], privacy=True, category="social"))})
    mail = Entity.make("email", "someone@example.com")
    assert links.pivot_links_for(mail) == []
    assert links.links_for(mail) == []
    with_privacy = links.pivot_links_for(mail, include_privacy=True)
    assert [r.ref for r in with_privacy] == ["test_pack:mail_lookup"] and with_privacy[0].privacy is True
    assert links.pivot_links_for(mail, include_privacy=True, categories="reputation") == []


def test_render_refuses_cpf_and_secrets_even_from_a_bad_link():
    any_type = links.PivotLink("t", "x", "X", "https://h.example/{q}",
                               (T.CPF, T.JWT, T.SECRET, T.PAYMENT_CARD, T.TELEGRAM_BOT_TOKEN, T.TEXT), "other", "h.example",
                               privacy=True, tier="trusted")
    for entity in (Entity.make("cpf", "52998224725"), Entity.make("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"),
                   secret_entity("aws_access_key", "AKIAIOSFODNN7EXAMPLE"), Entity.make("payment_card", "4111111111111111"),
                   Entity.make("text_blob", "some pasted text")):
        assert links.render(any_type, entity) is None
    personal_unknown = links.PivotLink("t", "y", "Y", "https://h.example/{q}", (T.EMAIL,), "other", "h.example", privacy=True, tier="unknown")
    assert links.render(personal_unknown, Entity.make("email", "a@b.com")) is None
    not_private = links.PivotLink("t", "z", "Z", "https://h.example/{q}", (T.EMAIL,), "other", "h.example", privacy=False, tier="trusted")
    assert links.render(not_private, Entity.make("email", "a@b.com")) is None


def test_render_by_ref_and_wrong_type():
    ip = Entity.make("ipv4", "1.1.1.1")
    rendered = links.render("core_reference:shodan_host", ip)
    assert rendered.url == "https://www.shodan.io/host/1.1.1.1" and rendered.ref == "core_reference:shodan_host"
    assert rendered.to_dict()["host"] == "www.shodan.io"
    assert links.render("core_reference:shodan_host", Entity.make("domain", "example.com")) is None
    assert links.render("core_reference:missing", ip) is None
    assert links.get_link("core_reference:shodan_host").to_dict()["entity_types"] == ["ipv4", "ipv6"]


# ---------------------------------------------------------------- manual links (Module.manual_link)


def test_validate_manual_link():
    assert links.validate_manual_link("") == [] and links.validate_manual_link(None) == []
    assert links.validate_manual_link("core_reference:shodan_host") == []
    assert links.validate_manual_link("core_reference:nope")
    assert links.validate_manual_link("https://www.virustotal.com/gui/domain/{domain}") == []
    assert any("https only" in e for e in links.validate_manual_link("http://www.virustotal.com/gui/domain/{domain}"))
    assert any("malformed placeholder" in e for e in links.validate_manual_link("https://h.example/{0.__class__}"))
    assert any("LINT-05" in e for e in links.validate_manual_link("https://urlscan.io/api/v1/scan/?u={q}"))
    assert any("LINT-04" in e for e in links.validate_manual_link("https://tudosobretodos.info/busca?q={q}"))
    assert links.validate_manual_link("shodan host page") == ["manual_link must be '<pack>:<link_id>' or an https URL template"]
    assert links.validate_manual_link(42) == ["manual_link must be a string"]


def test_render_manual_with_a_ref_and_an_inline_template(tiers):
    ip = Entity.make("ipv4", "8.8.8.8")
    by_ref = links.render_manual("core_reference:shodan_host", ip)
    assert by_ref.url == "https://www.shodan.io/host/8.8.8.8"
    inline = links.render_manual("https://www.virustotal.com/gui/ip-address/{ip}", ip)
    assert inline.url == "https://www.virustotal.com/gui/ip-address/8.8.8.8"
    assert (inline.ref, inline.host, inline.verified, inline.badge) == ("inline:manual", "www.virustotal.com", False, "unknown operator, unverified")
    assert links.render_manual("https://www.virustotal.com/gui/ip-address/{ip}", Entity.make("domain", "example.com")) is None
    assert links.render_manual("https://urlscan.io/api/v1/scan/?u={q}", ip) is None
    mail = Entity.make("email", "someone@example.com")
    assert links.render_manual("https://people.example/{q}", mail, include_privacy=True) is None  # unknown host
    tiers.tier["people.example"] = "trusted"
    assert links.render_manual("https://people.example/{q}", mail) is None  # personal values need the opt-in
    opted_in = links.render_manual("https://people.example/{q}", mail, include_privacy=True)
    assert opted_in.url == "https://people.example/someone%40example.com" and opted_in.privacy is True
    assert links.render_manual("https://people.example/{q}", Entity.make("cpf", "52998224725"), include_privacy=True) is None
    assert links.render_manual("", ip) is None
    assert links.render_manual("core_reference:shodan_host", "8.8.8.8") is None  # not an Entity


def test_render_manual_privacy_refs_and_placeholderless_forms(extra_packs, tiers):
    tiers.tier["people.example"] = "community"
    tiers.tier["forms.example"] = "trusted"
    extra_packs({"test_pack.json": pack(item(id="phone_lookup", template="https://people.example/p/{e164}", host="people.example",
                                             entity_types=["phone"], privacy=True, category="social"))})
    phone = Entity.make("phone", "+5511987654321")
    assert links.render_manual("test_pack:phone_lookup", phone) is None
    assert links.render_manual("test_pack:phone_lookup", phone, include_privacy=True).url == "https://people.example/p/5511987654321"
    # an anti-bot search form has no URL parameter: the analyst types the value (A9 manual link)
    form = links.render_manual("https://forms.example/consulta", Entity.make("domain", "example.com"))
    assert form is not None and form.url == "https://forms.example/consulta" and form.badge == "unverified"
    assert any("no placeholder" in e for e in lint_errors(item(template="https://forms.example/consulta", host="forms.example")))


# ---------------------------------------------------------------- provider registry integration


def test_tiers_come_from_the_provider_registry():
    providers = pytest.importorskip("v3lum.core.providers")
    shodan = links.get_link("core_reference:shodan_host")
    provider = providers.registry().provider_for_host("www.shodan.io")
    assert shodan.tier == (provider.tier if provider is not None else "unknown")
    assert links.host_tier("unregistered-host.example") == "unknown"


def test_disclosure_note_uses_the_masked_value():
    ip = Entity.make("ipv4", "8.8.8.8")
    rendered = links.render("core_reference:shodan_host", ip)
    assert links.disclosure_note(ip, rendered) == "opening sends 8.8.8.8 to www.shodan.io"
    cpf = Entity.make("cpf", "52998224725")  # never rendered, but the note itself never shows a full CPF
    assert "52998224725" not in links.disclosure_note(cpf, rendered)
