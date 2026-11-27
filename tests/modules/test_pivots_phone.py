"""pivots_phone (P128): manual phone pivot links, the 'phone' pack and its registry tiers.

V3LUM never fetches these links. tests/fixtures/pivots_phone/verified_templates.json records the
maintainer verification of 2026-11-26 (status codes and observations only, documentation numbers).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from v3lum import config
from v3lum.core import links, providers
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.phone import pivots_phone as pv
from v3lum.modules.phone.pivots_phone import PivotsPhone

SEED = "phone:+55 11 95555-0101"
OPTED_IN = ScanOptions(show_personal=True, purpose="fraud case ticket 123")
PACK = json.loads((links.PACKS_DIR / "phone.json").read_text(encoding="utf-8"))
VERIFIED = module_fixture("pivots_phone", "verified_templates.json")


def phone(value="+5511955550101"):
    return Entity.make("phone", value)


def urls(res):
    return [url for _label, url in res.links]


# ------------------------------------------------------------------ the pack (FC1, FC3, FC5)
def test_pack_loads_and_lints_clean():
    assert links.lint_pack(PACK, source="phone.json") == []
    assert not [e for e in links.errors() if "phone" in e]
    link = links.get_link("phone:spamcalls_num")
    assert link is not None and link.privacy and not link.publishes and link.tier == "community"
    assert link.entity_types == (T.PHONE,) and link.verified and link.checked_at == "2026-11-26"


def test_e164_placeholder_is_digits_without_plus():
    """FC3: spamcalls.net decodes a literal '+' as a space, so {e164} must carry the digits only."""
    assert links.render("phone:spamcalls_num", phone()).url == "https://spamcalls.net/en/num/5511955550101"
    assert links.encode_e164("+5511955550101") == "5511955550101" == links.encode_wa("+5511955550101")
    assert links.encode_e164("+5511955550101", plus=True) == "+5511955550101"
    rendered = links.render(links.PivotLink(pack="t", id="x", label="x", template="https://spamcalls.net/en/num/{e164_plus}",
                                            entity_types=(T.PHONE,), category="reputation", host="spamcalls.net", privacy=True), phone())
    assert rendered is not None and rendered.url.endswith("/%2B5511955550101")  # never a literal '+'


def test_verified_templates_render_the_recorded_urls():
    links_by_id = {"spamcalls_num": "phone:spamcalls_num", "abrtelecom_consulta_numero": pv.ABR_LINK,
                   **{link.id: link for link in pv.MESSAGING_LINKS}}
    for check in VERIFIED["checks"]:
        if check.get("rejected"):
            continue
        rendered = links.render(links_by_id[check["id"]], phone(check["number"]))
        assert rendered is not None and rendered.url == check["url"], check["id"]


def test_every_template_passes_the_lint_and_stays_on_its_host():
    for link in ("phone:spamcalls_num", pv.ABR_LINK, *pv.MESSAGING_LINKS):
        rendered = links.render(link, phone())
        assert rendered is not None and rendered.url.startswith(f"https://{rendered.host}/")
        assert rendered.privacy and rendered.tier in ("trusted", "community")
        assert "52998224725" not in rendered.url  # no CPF ever (team rule 4)


def test_registry_tiers_and_flags():
    reg = providers.registry()
    assert reg.errors == []
    expected = {"spamcalls.net": ("spamcalls", "community"), "wa.me": ("whatsapp", "trusted"), "t.me": ("telegram", "trusted"),
                pv.ABR_HOST: ("abrtelecom", "trusted")}
    for host, (pid, tier) in expected.items():
        prov = reg.provider_for_host(host)
        assert prov is not None and (prov.id, prov.tier) == (pid, tier) and links.host_tier(host) == tier
        assert prov.flags.publishes_queries is False  # rule 7: a publishing host would be refused by the lint
    assert reg.get("spamcalls").flags.reuses_queries is True  # ad/analytics partners receive the page URL


def test_lint_rejects_unknown_tier_hosts_cpf_and_missing_privacy():
    bad = {"schema": "v3lum.pivot_pack/1", "pack": "phone", "title": "bad", "links": [
        dict(PACK["links"][0], id="unknown_host", host="phonelookup.example", template="https://phonelookup.example/{e164}"),
        dict(PACK["links"][0], id="cpf_link", entity_types=["cpf"], template="https://spamcalls.net/en/num/{q}"),
        dict(PACK["links"][0], id="not_private", privacy=False),
        dict(PACK["links"][0], id="plus_in_host", template="https://{e164}.spamcalls.net/x"),
        dict(PACK["links"][0], id="no_value", template="https://spamcalls.net/en/"),
    ]}
    problems = "\n".join(links.lint_pack(bad, source="phone.json"))
    assert "unknown_host" in problems and "A8 BR4" in problems
    assert "no template accepts CPF" in problems
    assert "need privacy=true" in problems
    assert "placeholders are allowed only in the path" in problems
    assert "template has no placeholder" in problems
    unknown = links.PivotLink(pack="t", id="x", label="x", template="https://phonelookup.example/{e164}", entity_types=(T.PHONE,),
                              category="reputation", host="phonelookup.example", privacy=True)
    assert links.render(unknown, phone()) is None


# ------------------------------------------------------------------ the module (FC2, FC4)
def test_setting_is_registered_off_by_default():
    spec = config.SETTINGS_META[pv.SETTING]
    assert spec.default is False and spec.owner == "pivots_phone"
    assert PivotsPhone.disclosure == "none" and PivotsPhone.run_on == "seeds" and PivotsPhone.default_enabled is True


def test_hidden_until_the_case_opts_in():
    res = run_module(PivotsPhone, SEED)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and not res.links
    no_purpose = run_module(PivotsPhone, SEED, options=ScanOptions(show_personal=True))
    assert no_purpose.status is Status.SKIPPED and no_purpose.reason_code == "privacy"


def test_auto_discovered_numbers_get_no_links():
    res = run_module(PivotsPhone, SEED, options=OPTED_IN, is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and not res.links


def test_clear_tlp_links_without_messaging_by_default():
    res = run_module(PivotsPhone, SEED, FakeHttp(), options=OPTED_IN, tlp="clear")
    assert res.status is Status.OK and res.requests == 0
    assert urls(res) == ["https://spamcalls.net/en/num/5511955550101", pv.ABR_URL]
    labels = [label for label, _url in res.links]
    assert "user reports, unverified" in labels[0] and "opening sends" not in labels[0]
    assert "type the number on the page" in labels[1]
    hidden = {h["id"]: h["reason"] for h in res.raw["hidden"]}
    assert hidden == {"whatsapp_chat": "off by default (setting phone_messaging_links=false)", "telegram_chat": "off by default (setting phone_messaging_links=false)"}
    assert all(item["clickable"] for item in res.raw["links"])


def test_messaging_links_need_the_setting_and_carry_the_notice():
    res = run_module(PivotsPhone, SEED, options=OPTED_IN, tlp="green", settings={pv.SETTING: True})
    by_url = {url: label for label, url in res.links}
    assert "https://wa.me/5511955550101" in by_url and "https://t.me/+5511955550101" in by_url
    for url in ("https://wa.me/5511955550101", "https://t.me/+5511955550101"):
        assert pv.MESSAGING_NOTICE in by_url[url]
    assert res.raw["messaging_links"] is True and res.raw["hidden"] == []


@pytest.mark.parametrize("level", ["amber", "amber+strict"])
def test_amber_and_above_carry_the_disclosure_warning(level):
    res = run_module(PivotsPhone, SEED, options=OPTED_IN, tlp=level, settings={pv.SETTING: True})
    by_url = {url: label for label, url in res.links}
    assert by_url["https://spamcalls.net/en/num/5511955550101"].endswith("opening sends +5511955550101 to spamcalls.net")
    assert by_url["https://wa.me/5511955550101"].endswith("opening sends +5511955550101 to wa.me")
    assert by_url["https://t.me/+5511955550101"].endswith("opening sends +5511955550101 to t.me")
    assert "opening sends nothing; typing +5511955550101 on that page sends it to consultanumero.abrtelecom.com.br" in by_url[pv.ABR_URL]
    assert not any(item["clickable"] for item in res.raw["links"])


def test_red_hides_third_party_links():
    res = run_module(PivotsPhone, SEED, options=OPTED_IN, tlp="red", settings={pv.SETTING: True})
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and not res.links


def test_non_brazilian_numbers_get_no_abr_link():
    res = run_module(PivotsPhone, "phone:+1 415-555-0100", options=OPTED_IN, tlp="clear")
    assert urls(res) == ["https://spamcalls.net/en/num/14155550100"]
    assert {"id": "abrtelecom_consulta_numero", "reason": "Brazilian (+55) numbers only"} in res.raw["hidden"]


def test_unreadable_tlp_fails_closed():
    ctx = make_ctx(PivotsPhone, options=OPTED_IN, tlp="purple")
    assert pv.tlp_level(ctx).value_str == "red"


def test_never_fetches_anything():
    ctx = make_ctx(PivotsPhone, FakeHttp(), options=OPTED_IN)
    with pytest.raises(PolicyError):  # disclosure 'none': ctx.http refuses every request
        ctx.http.get("https://spamcalls.net/en/num/5511955550101")
