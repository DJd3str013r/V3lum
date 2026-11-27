"""Batch p2-G14-2: the six G14 pivot packs (P203 darkweb, P216 crypto, P231 company_org, P250 brazil,
P290 pentest, P300 cti) and the shared module-link renderer v3lum.modules.utility.pivot_pack_render.

Covers the conditions every pack shares: cond 1 (frozen schema, publishes=false, disclosure none), cond 3
(sample and hostile values: https on the declared host, whitelisted placeholders through the declared
encoder), cond 4-5 (a provider-registry entry with the reviewed tier for every host, A8 type limits), cond 6
(curated order), cond 7 (checked_at and the re-check report), plus the batch lint rules. V3LUM never fetches
these links; the tests are offline (tests/fakes.py)."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture
from v3lum.core import links, providers
from v3lum.core.entities import IOC_TYPES, Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import PolicyError
from v3lum.core.module import REGISTRY, load_modules
from v3lum.modules.utility import pivot_pack_render as pr

PACKS = pr.BATCH_PACKS
SAMPLES = {
    T.DOMAIN: "example.com",
    T.ONION: "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
    T.ORG: "Banco do Brasil",
    T.KEYWORD: "lockbit",
    T.THREAT_ACTOR: "APT28",
    T.MALWARE: "Emotet",
    T.MITRE: "T1059.001",
    T.BTC: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    T.ETH: "0xdac17f958d2ee523a2206206994597c13d831ec7",
    T.CRYPTO: "LUEweDxDA4WhvWiNXXSxjM9CYzHPJv4QQF",
    T.CNPJ: "00000000000191",
    T.PERSON: "Fulano de Tal",
    T.EMAIL: "analista.teste@example.com",
}
RESOLVER_SAMPLES = {"mitre_path": "T1059/001", "attack_id": "G0007", "malpedia_id": "win.emotet", "ransomlook_slug": "inc ransom",
                    "rlive_slug": "lockbit3", "ltc": SAMPLES[T.CRYPTO], "doge": "DEA5vGb2NpAwCiCp5yTE16F3DueQUVivQp",
                    "bch": "qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy", "tron": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"}
HOSTILE = ['a"b\'c', "two words", "ação ünïcode", "line\nbreak", "../../admin", "a/b?c=d#e&f=g", "{q}{raw}", "%2e%2e", "x" * 300]
TIERS = {  # P203/P216/P231/P250/P290/P300 cond 5 (registry reviewer confirms)
    "www.ransomlook.io": "community", "www.ransomware.live": "community", "onionsearchengine.com": "unknown",
    "blockchain.com": None, "www.blockchain.com": "trusted", "blockchair.com": "trusted", "mempool.space": "community",
    "www.walletexplorer.com": "community", "www.bitcoinwhoswho.com": "community", "ethplorer.io": "community", "bitref.com": "unknown",
    "www.opensanctions.org": "trusted", "find-and-update.company-information.service.gov.uk": "trusted", "opencorporates.com": "trusted",
    "search.gleif.org": "trusted", "viewdns.info": "community",
    "portaldatransparencia.gov.br": "trusted", "solucoes.receita.fazenda.gov.br": "trusted", "www.sintegra.gov.br": "trusted",
    "www.consumidor.gov.br": "trusted", "www.jusbrasil.com.br": "trusted", "www.reclameaqui.com.br": "trusted",
    "www.escavador.com": "community", "casadosdados.com.br": "community",
    "www.ssllabs.com": "trusted", "buckets.grayhatwarfare.com": "community",
    "attack.mitre.org": "trusted", "d3fend.mitre.org": "trusted", "malpedia.caad.fkie.fraunhofer.de": "trusted",
}


def pack_file(name):
    return json.loads((links.PACKS_DIR / f"{name}.json").read_text(encoding="utf-8"))


def all_entries():
    for name in PACKS:
        data = pack_file(name)
        for item in data["links"]:
            yield name, item, False
        for item in data.get(pr.EXT_KEY, []):
            yield name, item, True


# ------------------------------------------------------------------ cond 1: the packs load clean
@pytest.mark.parametrize("name", PACKS)
def test_pack_lints_clean_and_loads(name):
    data = pack_file(name)
    assert data["schema"] == links.SCHEMA and data["pack"] == name
    assert pr.lint_pack_data(data, pack=name) == []
    assert not [e for e in links.errors() if e.startswith(f"{name}.json")]
    assert pr.module_link_errors(name) == []
    loaded = links.packs()[name]
    assert [link.id for link in loaded.links] == [item["id"] for item in data["links"]]  # nothing dropped or deduplicated away


def test_every_entry_uses_the_frozen_fields_publishes_false_and_no_login():
    frozen = {"id", "label", "template", "entity_types", "category", "host", "verified", "checked_at", "privacy", "publishes",
              "touches_target", "login_required", "antibot", "notes"}
    for name, item, _module in all_entries():
        assert frozen <= set(item), (name, item["id"])
        assert all(k in frozen or k.startswith("x_") for k in item), (name, item["id"])
        assert item["publishes"] is False and item["login_required"] is False
        assert item["template"].startswith("https://" + item["host"] + "/")


def test_modules_are_offline_default_open_passive():
    load_modules()
    for mod in ("pivots_darkweb", "pivots_crypto", "pivots_brazil", "pivots_pentest", "pivots_cti"):
        cls = REGISTRY[mod]
        assert cls.disclosure == "none" and cls.hosts == () and cls.terms == "open" and cls.default_enabled is True
        assert cls.max_requests == 0 and cls.produces == frozenset() and cls.opsec.name == "PASSIVE"
        ctx = make_ctx(cls, FakeHttp())
        with pytest.raises(PolicyError):  # disclosure 'none': no network at all
            ctx.http.get("https://www.ransomware.live/")


# ------------------------------------------------------------------ cond 3: sample and hostile values
def _check_url(url, host):
    assert url.startswith(f"https://{host}/"), url
    assert pr.url_ok(url, host), url
    assert not any(c.isspace() for c in url) and "{" not in url and "}" not in url


def test_every_template_renders_a_sample_per_declared_type_on_its_host():
    rendered_any = 0
    for name, item, is_module in all_entries():
        for t in item["entity_types"]:
            etype = T(t)
            entity = Entity.make(etype, SAMPLES[etype])
            if is_module:
                ml = pr.module_links(name)[item["id"]]
                values = {p: RESOLVER_SAMPLES[p] for p in ml.placeholders if p in RESOLVER_SAMPLES}
                out = pr.render(ml, entity, values)
            else:
                out = links.render(f"{name}:{item['id']}", entity)
            assert out is not None, (name, item["id"], t)
            _check_url(out.url, item["host"])
            rendered_any += 1
    assert rendered_any > 40


@pytest.mark.parametrize("hostile", HOSTILE)
def test_hostile_values_stay_encoded_in_the_query_or_path_segment(hostile):
    for name, item, is_module in all_entries():
        for t in item["entity_types"]:
            entity = Entity(T(t), hostile)  # built raw on purpose: never normalised
            if is_module:
                ml = pr.module_links(name)[item["id"]]
                out = pr.render(ml, entity, {p: hostile for p in ml.placeholders if p != "q"})
                if out is not None and "mitre_path" in ml.placeholders:  # '/' only between vetted segments
                    assert "/" not in hostile.strip("/") or all(pr.safe_token(s) == s for s in hostile.split("/"))
                    continue
            else:
                out = links.render(f"{name}:{item['id']}", entity)
            if out is None:
                continue  # a typed encoder ({cnpj_fmt}, {domain}...) refused the value
            _check_url(out.url, item["host"])
            if "{" not in item["template"]:  # static page (P250): the URL never carries the value
                assert out.url == item["template"]
                continue
            prefix, rest = item["template"].split("{", 1)
            suffix = rest.split("}", 1)[1]
            assert out.url.startswith(prefix) and out.url.endswith(suffix), (name, item["id"], out.url)
            middle = out.url[len(prefix): len(out.url) - len(suffix)]
            assert not any(ch in middle for ch in "/?#&\"' \n{}"), (name, item["id"], out.url)  # the value stays one encoded token


def test_resolver_encoders_refuse_dot_segments_and_odd_characters():
    assert pr.encode_value("mitre_path", "T1059/001") == "T1059/001"
    assert pr.encode_value("ransomlook_slug", "inc ransom") == "inc%20ransom"
    for bad in ("..", ".", "a/b", "x\ny", "", "a?b", "a#b", "<x>", "T1059/../x", None, 5):
        assert pr.encode_value("ransomlook_slug", bad) is None, bad
    for bad in ("T1059/..", "../T1059", "T1059//001", "T1059/001/x/y/z"):
        assert pr.encode_value("mitre_path", bad) is None, bad


def test_the_renderer_never_uses_str_format_or_raw():
    for _name, item, _module in all_entries():
        assert "{raw}" not in item["template"] and "{0" not in item["template"] and "!s}" not in item["template"]


# ------------------------------------------------------------------ cond 4-5: registry tiers, A8 limits
def test_every_link_host_has_a_registry_entry_with_the_reviewed_tier():
    reg = providers.registry()
    assert reg.errors == []
    hosts = {item["host"] for _name, item, _m in all_entries()}
    for host in sorted(hosts):
        prov = reg.provider_for_host(host)
        assert prov is not None, host
        assert prov.tier_rationale and prov.tier_reviewer and prov.tier_date
        if TIERS.get(host):
            assert prov.tier == TIERS[host] == links.host_tier(host), host
        assert prov.flags.publishes_queries is False  # rule 7


def test_unknown_tier_hosts_take_ioc_values_only_and_carry_the_badge():
    for name, item, is_module in all_entries():
        if links.host_tier(item["host"]) != "unknown":
            continue
        assert all(T(t) in IOC_TYPES for t in item["entity_types"]), (name, item["id"])
        etype = T(item["entity_types"][0])
        entity = Entity.make(etype, SAMPLES[etype])
        out = pr.render(pr.module_links(name)[item["id"]], entity) if is_module else links.render(f"{name}:{item['id']}", entity)
        assert out is not None and pr.UNKNOWN_OPERATOR_BADGE in out.badge
    # an unknown-tier host never receives a company name, keyword or actor name (A8 BR4)
    bad = dict(pack_file("darkweb")[pr.EXT_KEY][-1], entity_types=["domain", "company_name"])
    problems = "\n".join(pr.lint_pack_data({**pack_file("darkweb"), pr.EXT_KEY: [bad]}, pack="darkweb"))
    assert "IOC_TYPES values only" in problems


def test_personal_and_cnpj_templates_are_privacy_links_to_trusted_or_community_hosts():
    for name, item, _module in all_entries():
        types = {T(t) for t in item["entity_types"]}
        if types & links.PRIVACY_TYPES:
            assert item["privacy"] is True, (name, item["id"])
            assert links.host_tier(item["host"]) in links.TRUSTED_TIERS
        assert T.CPF not in types  # rule 4: never a CPF


# ------------------------------------------------------------------ batch lint rules
@pytest.mark.parametrize(("pack", "mutation", "expected"), [
    ("darkweb", {"template": "https://www.ransomware.live/id/{q}"}, "rule 3"),
    ("darkweb", {"template": "https://www.ransomware.live/download/{q}"}, "rule 3"),
    ("darkweb", {"template": "https://www.ransomware.live/victims/{q}"}, "rule 3"),
    ("darkweb", {"template": "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/?q={q}",
                 "host": "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"}, ".onion"),
    ("darkweb", {"template": "https://onionsearchengine.com/search.php?search={q}&submit=Search", "host": "onionsearchengine.com",
                 "entity_types": ["domain"]}, "LINT-05"),
    ("crypto", {"template": "https://mempool.space/swap/{q}", "host": "mempool.space", "entity_types": ["btc_address"]}, "wallet-connect"),
    ("crypto", {"template": "https://mempool.space/donate/{q}", "host": "mempool.space", "entity_types": ["btc_address"]}, "donation"),
    ("crypto", {"template": "https://www.chainabuse.com/address/{q}", "host": "www.chainabuse.com", "entity_types": ["btc_address"]}, "P304"),
    ("crypto", {"template": "https://blockchair.com.evil.example/bitcoin/address/{q}", "host": "blockchair.com",
                "entity_types": ["btc_address"]}, "differs from the declared host"),
    ("company_org", {"template": "https://viewdns.info/reverseip/?host={q}&t=1", "host": "viewdns.info", "entity_types": ["domain"]}, "reverseip"),
    ("company_org", {"template": "https://viewdns.info/iphistory/?domain={q}", "host": "viewdns.info", "entity_types": ["domain"]}, "iphistory"),
    ("company_org", {"template": "https://viewdns.info/reversewhois/?q={q}", "host": "viewdns.info", "entity_types": ["person_name"],
                     "privacy": False}, "need privacy=true"),
    ("brazil", {"template": "https://portaldatransparencia.gov.br/busca?termo={q}", "host": "portaldatransparencia.gov.br",
                "entity_types": ["cpf"]}, "CPF"),
    ("brazil", {"template": "https://portaldatransparencia.gov.br/busca?termo={q}", "host": "portaldatransparencia.gov.br",
                "entity_types": ["person_name"], "privacy": True}, "rule 4"),
    ("brazil", {"template": "https://cnpj.example/{cnpj_digits}", "host": "cnpj.example", "entity_types": ["cnpj"], "privacy": True}, "A8 BR4"),
    ("pentest", {"template": "https://www.ssllabs.com/ssltest/analyze.html?d={domain}", "host": "www.ssllabs.com", "entity_types": ["domain"],
                 "touches_target": True}, "hideResults"),
    ("pentest", {"template": "https://www.ssllabs.com/ssltest/analyze.html?d={domain}&hideResults=on&latest", "host": "www.ssllabs.com",
                 "entity_types": ["domain"], "touches_target": False}, "touches_target=true"),
    ("pentest", {"template": "https://buckets.grayhatwarfare.com/files/{q}", "host": "buckets.grayhatwarfare.com",
                 "entity_types": ["keyword"], "privacy": True}, "never file links or downloads"),
])
def test_batch_lint_rejects_bad_entries(pack, mutation, expected):
    data = pack_file(pack)
    base = dict(data["links"][0])
    bad = {**base, **mutation, "id": "bad_entry"}
    problems = "\n".join(pr.lint_pack_data({**data, "links": [*data["links"], bad]}, pack=pack))
    assert "bad_entry" in problems and expected in problems, problems


def test_module_link_lint_drops_bad_entries_fail_closed(tmp_path, monkeypatch):
    data = pack_file("cti")
    good = data[pr.EXT_KEY][0]
    bad = [
        dict(good, id="str_format", template="https://attack.mitre.org/techniques/{mitre_path!s}/"),
        dict(good, id="unknown_placeholder", template="https://attack.mitre.org/techniques/{technique}/"),
        dict(good, id="two_placeholders", template="https://attack.mitre.org/techniques/{mitre_path}/{q}"),
        dict(good, id="other_host", template="https://attack.mitre.org.example/techniques/{mitre_path}/"),
        dict(good, id="no_value", template="https://attack.mitre.org/techniques/"),
        dict(good, id="bad_tlp", x_max_tlp="purple"),
        dict(good, id="fallback_nowhere", x_fallback_for="missing_link"),
    ]
    monkeypatch.setattr(links, "PACKS_DIR", tmp_path)
    (tmp_path / "cti.json").write_text(json.dumps({**data, pr.EXT_KEY: [good, *bad]}), encoding="utf-8")
    pr.reset_cache()
    try:
        assert list(pr.module_links("cti")) == [good["id"]]
        errors = "\n".join(pr.module_link_errors("cti"))
        for item in bad:
            assert item["id"] in errors, item["id"]
    finally:
        pr.reset_cache()


# ------------------------------------------------------------------ cond 6-7: order, checked_at, re-check report
def test_curated_order_inside_each_pack():
    ids = {name: [i["id"] for i in pack_file(name)["links"]] for name in PACKS}
    assert ids["crypto"][:6] == ["mempool_address", "blockchair_btc", "walletexplorer_address", "bitcoinwhoswho_address",
                                 "blockchain_com_btc", "bitref_address"]
    assert ids["crypto"][6:8] == ["ethplorer_address", "blockchair_eth"]
    assert ids["company_org"][:5] == ["opensanctions_company", "opensanctions_person", "companies_house_search",
                                      "opencorporates_search", "gleif_search"]
    assert ids["company_org"][5:] == ["viewdns_rwhois_org", "viewdns_rwhois_person"]
    assert ids["brazil"][0].startswith("transparencia") and ids["brazil"][2] == "reclameaqui_busca"
    assert ids["brazil"][-1] == "casadosdados_cnpj"
    assert ids["pentest"] == ["grayhat_files", "ssllabs_analyze"]
    assert [i["id"] for i in pack_file("cti")[pr.EXT_KEY]][:3] == ["attack_technique", "attack_group", "attack_software"]
    assert [i["id"] for i in pack_file("darkweb")[pr.EXT_KEY]][-1] == "onionsearch"  # group pages first, then onion search


def test_pivot_links_for_puts_verified_links_first():
    out = links.pivot_links_for(Entity.make("btc_address", SAMPLES[T.BTC]), categories=("crypto",))
    flags = [r.verified for r in out]
    assert flags == sorted(flags, reverse=True) and flags[-1] is False  # BitcoinWhosWho (unverified) last
    assert out[0].url == "https://mempool.space/address/" + SAMPLES[T.BTC]


def test_verified_links_carry_checked_at_and_the_recheck_report_lists_unverified_and_stale_links():
    for _name, item, _module in all_entries():
        if item["verified"]:
            dt.date.fromisoformat(item["checked_at"])
    today = dt.date(2026, 11, 27)
    report = pr.recheck_report(today)
    refs = {r["ref"] for r in report}
    assert "crypto:etherscan_address" in refs and "crypto:bitcoinwhoswho_address" in refs
    assert "darkweb:onionsearch (module link)" in refs
    assert all(r["reason"] == "unverified" for r in report)
    later = pr.recheck_report(today + dt.timedelta(days=200))
    stale = {r["ref"] for r in later if r["reason"].startswith("last checked")}
    assert "cti:d3fend_technique" in stale and "cti:attack_technique (module link)" in stale


def test_verification_records_match_the_templates():
    """The URLs the maintainer checked are exactly what the templates render (fixtures per module)."""
    from v3lum.modules.crypto import pivots_crypto as pc

    checked = 0
    for module in ("pivots_darkweb", "pivots_crypto", "pivots_company_org", "pivots_brazil", "pivots_pentest", "pivots_cti"):
        for check in module_fixture(module, "verified_templates.json")["checks"]:
            if not check.get("link"):
                continue
            etype, value = check["entity"].split(":", 1)
            entity = Entity.make(etype, value)
            pack, ident = check["link"].split(":", 1)
            if pack == links.INLINE_PACK:
                url = pr.render(pr.module_links("brazil")[ident], entity).url
            elif ident in pr.module_links(pack):
                ml = pr.module_links(pack)[ident]
                values = {}
                if "ransomlook_slug" in ml.placeholders or "rlive_slug" in ml.placeholders:
                    from v3lum.modules.darkweb_ransomware.pivots_darkweb import resolve_slugs

                    slugs, _note = resolve_slugs(entity.value)
                    values = {"ransomlook_slug": slugs.get("ransomlook"), "rlive_slug": slugs.get("ransomware_live")}
                elif ml.placeholders and ml.placeholders[0] in pc.CHAIN_LINKS:
                    values = {ml.placeholders[0]: pc.chain_of(entity.value)[1]}
                elif "mitre_path" in ml.placeholders:
                    values = {"mitre_path": entity.value.replace(".", "/")}
                elif "attack_id" in ml.placeholders or "malpedia_id" in ml.placeholders:
                    from v3lum.modules.cti_framework import pivots_cti as pv

                    ns = "actor" if entity.type is T.THREAT_ACTOR else "malware"
                    mitre, malp, _note = pv.alias_ids(entity.value, ns)
                    values = {"attack_id": mitre[0]} if "attack_id" in ml.placeholders else {"malpedia_id": pv.malpedia_value(malp, ns)}
                url = pr.render(ml, entity, values).url
            else:
                url = links.render(check["link"], entity).url
            assert url == check["url"], check["case"]
            checked += 1
    assert checked >= 25
