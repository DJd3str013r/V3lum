"""Standalone manual-pivot page (P311 cond 5/8/10/11, P336, A2).

The first test renders every bundled pivot template with a fixture value per entity type and asserts
a valid https URL on the declared host (P311 cond 11); the others build their own link items.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import pytest

from v3lum.core import links
from v3lum.core.entities import Entity, EntityType
from v3lum.report import html as H
from v3lum.report import pivot_page as P
from v3lum.report import summary as S
from v3lum.ui.safe import safe_href

#: One valid fixture value per entity type a pivot template may accept (CPF, secrets, blobs and files
#: never go into a link: links.NO_LINK_TYPES).
FIXTURE_VALUES: dict[str, str] = {
    "email": "analyst@example.com", "domain": "example.com", "url": "https://example.com/path?a=1", "ipv4": "8.8.8.8",
    "ipv6": "2001:4860:4860::8888", "cidr": "8.8.8.0/24", "asn": "AS15169", "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    "ssdeep": "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C", "phone": "+5511987654321", "username": "analyst_handle",
    "person_name": "Maria Silva", "company_name": "Example Industries", "cnpj": "11.222.333/0001-81", "cep": "01310-100",
    "btc_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "eth_address": "0x52908400098527886E0F7030069857D2E4169EE7",
    "other_crypto_address": "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7", "cve": "CVE-2024-3400", "mitre_technique": "T1566.001",
    "threat_actor": "APT28", "malware_family": "Emotet", "mac_address": "00:1A:2B:3C:4D:5E",
    "onion": "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", "plate_br": "ABC1D23", "keyword": "example keyword",
    "user_agent": "Mozilla/5.0", "analytics_id": "UA-12345678-1", "card_bin": "411111", "coordinates": "-23.5505,-46.6333",
    "imei": "490154203237518", "favicon_hash": "-1234567890", "cert_fingerprint": "aa" * 32, "telegram_handle": "@example_channel",
    "telegram_invite": "https://t.me/+AbCdEfGhIjKlMnOp", "discord_invite": "https://discord.gg/abcdef", "social_account": "twitter:example",
    "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744", "tlsh": "T1" + "A" * 70, "telfhash": "t1" + "a" * 70, "gimphash": "a" * 64,
    "authentihash": "b" * 64, "icon_dhash": "0123456789abcdef", "code_signing_cert": "c" * 64, "pgp_fingerprint": "ABCD" * 10,
    "fediverse_handle": "@user@mastodon.social", "bsky_handle": "example.bsky.social", "steam_profile": "profiles:76561197960287930",
    "port_service": "8.8.8.8:443/tcp", "tiktok_video_id": "7234567890123456789", "snowflake_id": "175928847299117063",
    "vin": "1HGCM82633A004352",
}


def test_every_bundled_template_renders_a_valid_https_url():
    """P311 cond 11: each loaded template (every pack under v3lum/data/pivot_links) with a fixture value
    per accepted type renders to an https URL on its declared host; V3LUM never fetches it."""
    templates = links.templates()
    assert templates, "no pivot template loaded"
    missing, failed = set(), []
    checked = 0
    for link in templates:
        for etype in link.entity_types:
            value = FIXTURE_VALUES.get(etype.value)
            if value is None:
                missing.add(etype.value)
                continue
            rendered = links.render(link, Entity.make(etype.value, value))
            if rendered is None:
                failed.append(f"{link.ref} ({etype.value})")
                continue
            parts = urlsplit(rendered.url)
            if parts.scheme != "https" or parts.hostname != link.host or safe_href(rendered.url) != rendered.url:
                failed.append(f"{link.ref} ({etype.value}): {rendered.url}")
            checked += 1
    assert not missing, f"add a fixture value for these entity types: {sorted(missing)}"
    assert not failed, failed
    assert checked >= len(templates)


def test_fixture_values_are_valid_entities():
    for etype, value in FIXTURE_VALUES.items():
        assert Entity.make(etype, value).type is EntityType(etype)
    assert not set(FIXTURE_VALUES) & {t.value for t in links.NO_LINK_TYPES}  # CPF and secrets never go into a link


# --------------------------------------------------------------------------------------
# the page
# --------------------------------------------------------------------------------------

SEED = "domain:acme-target.example"


def page_case(tlp: str = "amber", **over: Any) -> dict[str, Any]:
    case: dict[str, Any] = {
        "schema": "v3lum.case/2", "case_id": "20261126-120000-ef56", "created": "2026-11-26T12:00:00Z", "tlp": tlp,
        "seeds": [SEED], "inputs": [{"type": "domain", "value": "acme-target.example"}], "options": {"mode": "passive"},
        "entities": [{"key": SEED, "type": "domain", "value": "acme-target.example", "seed": True, "depth": 0, "attributes": {}},
                     {"key": "ipv4:203.0.113.9", "type": "ipv4", "value": "203.0.113.9", "depth": 1, "attributes": {}}],
        "findings": [], "correlations": [], "modules": [], "coverage": {},
        "links": {
            SEED: [
                {"label": "History unverified", "url": "https://hist.example.org/d/acme-target.example", "host": "hist.example.org", "ref": "t:hist",
                 "category": "history", "verified": False, "badge": "unknown operator, unverified"},
                {"label": "Reputation verified", "url": "https://rep.example.org/d/acme-target.example", "host": "rep.example.org", "ref": "t:rep",
                 "category": "reputation", "verified": True},
                {"label": "Manual fallback", "url": "https://manual.example.org/?q=acme-target.example", "host": "manual.example.org", "ref": "t:man",
                 "category": "reputation", "manual": True, "note": "automation skipped: licence"},
                {"label": "Opens the target", "url": "https://acme-target.example/", "host": "acme-target.example", "ref": "t:open", "category": "other"},
            ],
            "ipv4:203.0.113.9": [{"label": "IP rep", "url": "https://rep.example.org/ip/203.0.113.9", "host": "rep.example.org", "ref": "t:ip", "category": "reputation", "verified": True}],
        },
    }
    case.update(over)
    return case


def anchors(html: str) -> list[str]:
    return re.findall(r'<a href="([^"]+)"', html)


def test_amber_renders_non_clickable_text_with_the_disclosure_warning():
    html = P.render(page_case("amber"))
    assert anchors(html) == []
    assert "opening sends acme-target.example to rep.example.org" in html
    assert "hxxps://rep[.]example[.]org/d/acme-target.example" in html
    assert "not clickable" in html


def test_clear_renders_clickable_templates_never_the_target():
    html = P.render(page_case("clear"))
    hrefs = anchors(html)
    assert "https://rep.example.org/d/acme-target.example" in hrefs and "https://hist.example.org/d/acme-target.example" in hrefs
    assert not [h for h in hrefs if urlsplit(h).hostname == "acme-target.example"]  # the investigated host is never a link
    assert "opens the target" in html and "hxxps://acme-target[.]example/" in html


def test_red_omits_third_party_links():
    html = P.render(page_case("red"))
    assert "rep.example.org" not in html and "3 third-party" not in html
    assert "omitted at TLP:RED" in html and "v3lum links" in html


def test_page_is_self_contained_with_the_report_csp_and_markings():
    html = P.render(page_case("green"))
    assert f'content="{H.e(H.csp())}"' in html and "<script>" + H.JS + "</script>" in html
    assert '<meta name="referrer" content="no-referrer">' in html
    assert not re.search(r"<[A-Za-z][^>]*\ssrc\s*=", html) and "url(" not in html.split("</style>", 1)[0].split("<style>", 1)[1]
    assert "TLP:GREEN" in html.split("</header>", 1)[0] and "TLP:GREEN" in html.split("<footer>", 1)[1]
    for body in re.findall(r"<section[^>]*>(.*?)</section>", html, re.S):
        assert "TLP:GREEN" in body.split("</h2>", 1)[0]
    assert "V3LUM never fetches these links" in html


def test_grouped_by_analyst_question_manual_and_verified_first_with_badges():
    plan = S.pivot_plan(page_case("clear"))
    seed = plan.entities[0]
    assert seed.key == SEED and seed.seed
    cats = [cat for cat, _items in seed.groups]
    assert cats == [c for c in links.LINK_CATEGORIES if c in cats] and cats[0] == "reputation"
    rep = dict(seed.groups)["reputation"]
    assert [i.label for i in rep] == ["Manual fallback", "Reputation verified"]  # manual fallbacks, then verified
    html = P.render(page_case("clear"))
    assert "[unknown operator, unverified]" in html and "(automation skipped: licence)" in html
    assert html.index("reputation</h3>") < html.index("history</h3>")
    assert "203.0.113.9" in html  # discovered entities are listed after the seeds


def test_hostile_entity_target_links_need_an_explicit_expand():
    case = page_case("clear")
    case["entities"][0]["tags"] = ["phishing"]
    html = P.render(case)
    block = re.search(r"target-contact link\(s\) of a hostile entity \(expand to show, defanged\)</summary>(.*?)</details>", html, re.S)
    assert block and "Opens the target" in block.group(1)
    assert "https://acme-target.example/" not in anchors(html)


@pytest.mark.parametrize("show_personal,expected", [(False, False), (True, True)])
def test_personal_links_only_when_the_view_opts_in(show_personal, expected):
    case = page_case("clear")
    case["links"][SEED].append({"label": "People pivot", "url": "https://people.example.org/?q=x", "host": "people.example.org",
                                "ref": "t:ppl", "category": "social", "privacy": True})
    assert ("People pivot" in P.render(case, show_personal=show_personal)) is expected


def test_empty_case_renders_a_page_without_links():
    html = P.render(page_case("amber", links={}))
    assert "No manual pivot links for this case." in html and "TLP:AMBER" in html
