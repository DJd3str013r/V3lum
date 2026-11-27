"""typosquat (P012): permutation helper, offline reverse mode, staged DoH forward scan, .br RDAP,
ownership, severity ladder, caps and rule 5.

Fixtures in tests/fixtures/typosquat/: real DoH answers recorded 2026-11-26 (Google with the ECS echo,
Cloudflare NS/NXDOMAIN/NODATA), derived SERVFAIL/REFUSED/parked-NS/truncated answers, real RDAP answers
(registro.br with the CNPJ publicId, Verisign google.com with MarkMonitor) minimised, a derived
privacy-redacted RDAP answer, BCB DominiosVerificados rows and the OData error body (research), and the
research sample of 12 github.com permutations (lookalike IPs replaced with 192.0.2.x).
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

from tests.fakes import (
    FakeHttp,
    add_dns,
    add_dns_failure,
    add_nxdomain_everything,
    make_ctx,
    module_fixture,
    run_module,
)
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.domain_dns import typosquat as TS
from v3lum.modules.domain_dns import typosquat_permutations as P
from v3lum.modules.domain_dns.typosquat import Typosquat

LURES_PATH = Path(__file__).resolve().parents[2] / "v3lum" / "data" / "typosquat" / "brand_lures_pt.json"
ORG = {
    "name": "Banco Exemplo",
    "domains": [{"name": "itau.com.br", "verification": "confirmed"}, {"name": "itau.net.br", "verification": "confirmed"}],
    "brands": [{"keyword": "itau", "variants": ["itaú"]}],
    "cnpj_roots": ["11222333"],
}
RDAP_BR = "https://rdap.registro.br/domain/{}"


@pytest.fixture(scope="module")
def lures():
    return json.loads(LURES_PATH.read_text(encoding="utf-8"))["words"]


def fx(name):
    return module_fixture(Typosquat, name)


def serve(http, name, *, ns=(), a=(), mx=(), aaaa=(), providers=("cloudflare", "google")):
    for prov in providers:
        add_dns(http, name, "NS", list(ns), provider=prov)
        add_dns(http, name, "A", list(a), provider=prov)
        add_dns(http, name, "MX", list(mx), provider=prov)
        add_dns(http, name, "AAAA", list(aaaa), provider=prov)


def rdap_org(cnpj, created="2026-11-20T10:00:00Z", ns="ns1.hostinger.com"):
    doc = fx("rdap_br_cnpj_registrant.json")
    doc["ldhName"] = "x.com.br"
    doc["entities"][0]["publicIds"][0]["identifier"] = cnpj
    doc["entities"][0]["vcardArray"][1][2][3] = "Golpe Exemplo Ltda"
    doc["events"] = [{"eventAction": "registration", "eventDate": created}]
    doc["nameservers"] = [{"objectClassName": "nameserver", "ldhName": ns}]
    return doc


def titles(res):
    return [f.title for f in res.findings]


def by_title(res, title):
    return [f for f in res.findings if f.title == title]


# =================================================================== metadata
def test_contract_metadata():
    cls = Typosquat
    assert (cls.terms, cls.disclosure, cls.provider, cls.run_on) == ("open", "third_party", "core_doh", "seeds")
    assert cls.sources == ("core_doh.resolvers", "registrobr.rdap", "bcb.olinda_institutions")
    assert cls.hosts == ("rdap.registro.br",)
    assert cls.default_enabled is True and cls.max_requests == 10 and cls.timeout == 45.0
    assert cls.expected_latency <= 10 and cls.accepts == {T.DOMAIN, T.KEYWORD}
    assert "Apache-2.0" in cls.notice


# =================================================================== permutation helper (c1-c3, c5)
def test_itau_combo_set_and_idn(lures):
    """P012 c3/c12 unit test: brand 'itau' yields itau-seguranca.com.br and the punycode of itaú.com.br."""
    cands = P.generate("itau", lures=lures, dictionary=lures[: TS.DICTIONARY_WORDS])
    names = {c["domain"]: c for c in cands}
    for n in ("itau-seguranca.com.br", "seguranca-itau.com.br", "itauseguranca.com.br", "xn--ita-boa.com.br"):
        assert n in names, n
    assert names["xn--ita-boa.com.br"]["domain_unicode"] == "itaú.com.br"
    assert names["xn--ita-boa.com.br"]["fuzzer"] == "homoglyph" and names["itau-seguranca.com.br"]["fuzzer"] == "combo"
    top, cap_hit = P.rank(cands, 150)
    top_names = {c["domain"] for c in top}
    assert len(top) == 150 and cap_hit is True
    assert {"itau-seguranca.com.br", "xn--ita-boa.com.br"} <= top_names  # both in the default scan
    for c in cands:  # c1: every candidate passed IDNA/UTS-46 and VALID_FQDN
        assert P.VALID_FQDN.match(c["domain"]) and P.idna_ascii(c["domain_unicode"]) == c["domain"]


def test_tld_swaps_cover_the_condition_list(lures):
    names = {c["domain"] for c in P.generate("itau", lures=lures)}
    for tld in ("net.br", "app.br", "online", "site", "top", "xyz", "shop", "vip", "com"):
        assert f"itau.{tld}" in names, tld


def test_br_accent_homoglyphs_stay_in_the_registro_br_set():
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.") | set("àáâãéêíóôõúüç")
    homo = [c for c in P.generate("cartao.com.br", fuzzers=["homoglyph"]) if c["fuzzer"] == "homoglyph"]
    assert homo and all(set(c["domain_unicode"]) <= allowed for c in homo)
    uni = {c["domain_unicode"] for c in homo}
    assert {"cartão.com.br", "çartao.com.br", "cartaõ.com.br", "carta0.com.br"} <= uni


def test_ascii_homoglyphs_rn_vv_l1_o0():
    m = {c["domain"] for c in P.generate("modelo.com", fuzzers=["homoglyph"])}
    assert {"rnodelo.com", "mode1o.com", "model0.com"} <= m
    assert "vvave.com" in {c["domain"] for c in P.generate("wave.com", fuzzers=["homoglyph"])}


def test_the_research_github_permutations_are_generated():
    sample = fx("research_github_permutations.json")["checked"]
    names = {c["domain"] for c in P.generate("github.com")}
    assert all(d in names for d in sample)
    assert len([d for d, v in sample.items() if not v["nxdomain"]]) == 10  # research: 10 of 12 registered


def test_idna_validation_drops_invalid_names_and_the_seed_itself():
    assert P.idna_ascii("a" * 64 + ".com") is None
    assert P.idna_ascii("ex_ample.com") is None
    assert P.idna_ascii("itaú.com.br") == "xn--ita-boa.com.br"
    names = {c["domain"] for c in P.generate("a" * 62 + ".com", fuzzers=["addition", "repetition"])}
    assert names and all(len(n.split(".")[0]) <= 63 for n in names)
    cands = P.generate("itau.com.br", fuzzers=["vowel-swap"])
    assert [c["fuzzer"] for c in cands if c["domain"] == "itau.com.br"] == ["*original"]  # a->a swap is not a candidate
    assert P.generate("") == [] and P.generate(None) == []


def test_split_domain_uses_the_public_suffix_list():
    assert P.split_domain("www.itau.com.br") == ("www", "itau", "com.br")
    assert P.split_domain("registro.br") == ("", "registro", "br")
    assert P.split_domain("a.b.example.com") == ("a.b", "example", "com")
    assert P.split_domain("x.y.example.co.uk") == ("x.y", "example", "co.uk")
    assert P.split_domain("itaú.com.br") == ("", "itaú", "com.br")


def test_rank_is_deterministic_diverse_and_capped(lures):
    a, cap_a = P.rank(P.generate("bradesco.com.br", lures=lures), 150)
    b, _cap_b = P.rank(P.generate("bradesco.com.br", lures=lures), 150)
    assert [c["domain"] for c in a] == [c["domain"] for c in b] and cap_a
    assert {"combo", "homoglyph", "tld-swap", "typo"} <= {P.FAMILY_OF.get(c["fuzzer"], "other") for c in a}
    deep, _ = P.rank(P.generate("bradesco.com.br", lures=lures), 500)
    assert len(deep) == 500
    small, cap = P.rank(P.generate("bb.com.br", fuzzers=["omission"]), 150)
    assert cap is False and small


def test_lure_dictionary_file():
    doc = json.loads(LURES_PATH.read_text(encoding="utf-8"))
    words = doc["words"]
    assert len(words) >= 60 and len(words) == len(set(words))
    assert all(re.fullmatch(r"[a-z0-9-]+", w) for w in words)
    required = {"pix", "boleto", "fatura", "2via", "atualizar", "cadastro", "seguranca", "desbloqueio", "token", "resgate", "pontos",
                "beneficio", "fgts", "inss", "cnh", "detran", "ipva", "receita", "cpf", "gov", "app", "online", "conta", "sac",
                "segunda-via", "cartao", "credito", "emprestimo", "regularizar", "premio", "cashback", "login", "atualizacao"}
    assert required <= set(words)  # P012 c2 and P028 c8 words
    assert not {"caixa", "correios", "nubank", "itau", "bradesco", "santander", "serasa"} & set(words)  # no brand names
    assert "own work" in doc["licence"].lower() and "gpl" not in doc["licence"].lower().replace("never replace it with gpl", "")


# =================================================================== reverse mode (c4)
def _index(lures=()):
    bcb = TS.parse_bcb_rows(fx("bcb_dominios_verificados_ok.json"))
    return P.build_protected_index([{"domain": "itau.com.br", "source": "org_profile"}] + bcb, [{"keyword": "itaú", "source": "org_profile"}])


@pytest.mark.parametrize("query,protected,technique", [
    ("itau-seguranca.com.br", "itau.com.br", "combo"),
    ("xn--ita-boa.com.br", "itau.com.br", "homoglyph"),
    ("1tau.com.br", "itau.com.br", "homoglyph"),
    ("itau.online", "itau.com.br", "tld-swap"),
    ("itua.com.br", "itau.com.br", "transposition"),
    ("ita-u.com.br", "itau.com.br", "hyphenation"),
    ("itau.com.br.login-seguro.top", "itau.com.br", "subdomain"),
    ("bb-pix.com", "bb.com.br", "combo"),
    ("brb-boleto.online", "brb.com.br", "combo"),
])
def test_reverse_match(query, protected, technique, lures):
    r = P.reverse_match(query, _index(lures), lures=lures)
    assert r["own_asset"] is None
    top = [m for m in r["matches"] if m["protected"] == protected]
    assert top and top[0]["technique"] == technique


@pytest.mark.parametrize("query", ["itau.com.br", "www.itau.com.br", "bb.com.br", "dtvm.brb.com.br"])
def test_reverse_match_own_and_protected_domains_are_not_lookalikes(query, lures):
    r = P.reverse_match(query, _index(lures), lures=lures)
    assert r["own_asset"] is not None and r["matches"] == []


@pytest.mark.parametrize("query", ["example.com", "besc-historia.org", "bbc.co.uk", "capitaurbano.com.br"])
def test_reverse_match_negatives(query, lures):
    assert P.reverse_match(query, _index(lures), lures=lures)["matches"] == []


def test_reverse_mode_is_fast(lures):
    idx = P.build_protected_index([{"domain": f"banco{i:04d}exemplo.com.br", "source": "bcb"} for i in range(5000)])
    t0 = time.perf_counter()
    r = P.reverse_match("banco0042exemplo-pix.com", idx, lures=lures)
    assert time.perf_counter() - t0 < 1.0
    assert r["matches"][0]["protected"] == "banco0042exemplo.com.br"


def test_reverse_mode_strictness_by_source(lures):
    idx = P.build_protected_index([{"domain": "bradesco.com.br", "source": "bcb"}, {"domain": "exemplo.com.br", "source": "org_profile"}],
                                  [{"keyword": "exemplo", "source": "org_profile"}])
    assert P.reverse_match("bradesco-historia.com", idx, lures=lures)["matches"] == []  # BCB entries need a lure word
    assert P.reverse_match("bradesco-pix.com", idx, lures=lures)["matches"][0]["technique"] == "combo"
    assert P.reverse_match("bradesc0.com.br", idx, lures=lures)["matches"][0]["technique"] == "homoglyph"
    assert P.reverse_match("meuexemplo-app.site", idx, lures=lures)["matches"][0]["technique"] == "contains-brand"


def test_module_reverse_match_gives_one_finding_and_expand_false_pivots():
    http = FakeHttp()
    res = run_module(Typosquat, "domain:itau-seguranca.com.br", http, org_profile=ORG)
    assert res.status is Status.OK and http.calls == []  # reverse mode is offline: no request at all
    finding = by_title(res, "Lookalike of a protected domain or brand")[0]
    assert finding.severity.label == "info" and "typosquat" in finding.tags and finding.criterion
    assert res.attributes["lookalike_matches"][0]["protected"] == "itau.com.br"
    assert res.attributes["lookalike_matches"][0]["lure"] == "seguranca"
    pivots = {(p.entity.type, p.entity.value): p for p in res.pivots}
    assert pivots[(T.DOMAIN, "itau.com.br")].relation == "lookalike_of"
    assert all(p.expand is False for p in res.pivots)
    assert "not run" in res.attributes["typosquat_coverage"]["forward"]  # not explicit, not an org asset: reverse only


def test_module_reverse_mode_on_an_own_domain_and_without_protected_entries():
    own = run_module(Typosquat, "domain:www.itau.com.br", FakeHttp(), org_profile=ORG)
    assert own.status is Status.EMPTY and not own.findings  # subdomain of an own domain: no lookalike, no forward scan
    none = run_module(Typosquat, "domain:itau-seguranca.com.br", FakeHttp())
    assert none.status is Status.SKIPPED and none.reason_code == "not_applicable"
    unrelated = run_module(Typosquat, "domain:example.com", FakeHttp(), org_profile=ORG)
    assert unrelated.status is Status.EMPTY


def test_bcb_list_is_used_when_installed(monkeypatch, lures):
    rows = TS.parse_bcb_rows(fx("bcb_dominios_verificados_ok.json"))
    monkeypatch.setattr(TS, "_bcb_dataset", lambda ctx: (rows, ""))
    res = run_module(Typosquat, "domain:bb-pix.com", FakeHttp())
    f = by_title(res, "Lookalike of a protected domain or brand")[0]
    assert f.severity.label == "info" and f.source == "bcb.olinda_institutions"  # no automatic HIGH for BCB lookalikes
    assert res.attributes["lookalike_matches"][0]["source"] == "bcb"


def test_bcb_rows_and_dataset_discovery(monkeypatch):
    rows = TS.parse_bcb_rows(fx("bcb_dominios_verificados_ok.json"))
    assert [r["domain"] for r in rows][:3] == ["bb.com.br", "besc.com.br", "brb.com.br"]
    assert rows[0]["cnpj_root"] == "00000000" and rows[2]["cnpj_root"] == "00000208"
    assert TS.parse_bcb_rows(module_fixture(Typosquat, "bcb_dominios_verificados_error_500.txt")) == []
    ctx = make_ctx(Typosquat)
    assert TS._bcb_dataset(ctx)[1].startswith("BCB DominiosVerificados list not installed")
    from v3lum.core import datasets

    reg = {"url": "https://olinda.bcb.gov.br/olinda/servico/Instituicoes_em_funcionamento/versao/v1/odata/DominiosVerificados?$format=json",
           "source": "bcb.olinda_institutions"}
    monkeypatch.setitem(datasets.DATASETS, "test_bcb_dominios", reg)
    assert "not downloaded" in TS._bcb_dataset(ctx)[1]  # registered by P360 but no local copy: never forced here


# =================================================================== forward scan (c5-c10)
def _forward_http():
    """Three registered lookalikes of itau.com.br; everything else NXDOMAIN on both resolvers."""
    http = FakeHttp()
    serve(http, "itau-seguranca.com.br", ns=["ns1.hostinger.com."], a=["203.0.113.10"], mx=["10 mx.hostinger.com."])
    serve(http, "xn--ita-boa.com.br", ns=["ns1.sedoparking.com.", "ns2.sedoparking.com."], a=["203.0.113.11"], mx=["10 mail.example.net."])
    serve(http, "itau.online", ns=["ns1.example.net."])
    add_nxdomain_everything(http)
    http.add("GET", RDAP_BR.format("itau-seguranca.com.br"), json=rdap_org("44.555.666/0001-81"))
    http.add("GET", RDAP_BR.format("xn--ita-boa.com.br"), json=rdap_org("44.555.666/0001-81", ns="ns1.sedoparking.com"))
    return http


def test_forward_scan_ladder_pivots_and_coverage():
    http = _forward_http()
    res = run_module(Typosquat, "domain:itau.com.br", http, org_profile=ORG)
    assert res.status is Status.OK, res.error
    cov = res.attributes["typosquat_coverage"]
    assert cov["why"] == "org_profile domain" and cov["candidates_ranked"] == 150 and cov["candidate_cap_hit"] is True
    assert cov["registered"] >= 3 and cov["could_not_verify"] == 0 and cov["rdap_lookups"] == 2
    high = [f for f in by_title(res, "Registered lookalike domain") if f.severity.label == "high"]
    assert [f.data["domain"] for f in high] == ["itau-seguranca.com.br"]
    assert set(high[0].data["signals"]) == {"mx", "nrd<=30d", "a_non_parking"} and high[0].data["ownership"] == "not_brand_owned"
    assert high[0].observed_first and "T1583.001" in high[0].attack and "malicious" not in high[0].tags
    parked = [f for f in by_title(res, "Registered lookalike domain") if f.data["domain"] == "xn--ita-boa.com.br"][0]
    assert parked.severity.label == "low" and "parked" in parked.tags and "capped at LOW (parked)" in parked.criterion
    info = by_title(res, "Registered lookalike domains without activity signals")[0]
    assert "itau.online" in info.data["domains"]
    top = res.attributes["typosquat_top"]
    assert top[0]["domain"] == "itau-seguranca.com.br" and len(top) <= 10
    pivots = {p.entity.value: p for p in res.pivots}
    assert {"itau-seguranca.com.br", "xn--ita-boa.com.br", "itau.online"} <= set(pivots)
    assert all(p.relation == "lookalike" and p.expand is False for p in res.pivots)  # c10: never expanded
    http.assert_hosts_within(Typosquat)
    assert {c["url"].split("/")[2] for c in http.calls} <= {"cloudflare-dns.com", "dns.google", "rdap.registro.br"}  # no candidate contact


def test_ecs_present_on_every_doh_query():
    """P012 c12 / P029 c2: every Google DoH query carries edns_client_subnet=0.0.0.0/0; Cloudflare none."""
    http = _forward_http()
    run_module(Typosquat, "domain:itau.com.br", http, org_profile=ORG)
    google = [c["url"] for c in http.calls if "dns.google" in c["url"]]
    cloudflare = [c["url"] for c in http.calls if "cloudflare-dns.com" in c["url"]]
    assert google and cloudflare
    assert all("edns_client_subnet=0.0.0.0%2F0" in u or "edns_client_subnet=0.0.0.0/0" in u for u in google)
    assert not [u for u in cloudflare if "edns_client_subnet" in u and "0.0.0.0" not in u]
    assert all(c["url"].startswith("https://") for c in http.calls)


def test_defensive_registration_goes_to_the_own_asset_section():
    """A .br lookalike registered by the organisation's own CNPJ root is listed in the own-asset
    section, never as a typosquat finding; an org_profile domain among the candidates likewise."""
    http = FakeHttp()
    serve(http, "itau-seguranca.com.br", ns=["ns1.hostinger.com."], a=["203.0.113.10"], mx=["10 mx.hostinger.com."])
    add_nxdomain_everything(http)
    http.add("GET", RDAP_BR.format("itau-seguranca.com.br"), json=rdap_org("11.222.333/0001-81"))
    res = run_module(Typosquat, "domain:itau.com.br", http, org_profile=ORG)
    assert not [f for f in res.findings if "typosquat" in f.tags and f.data.get("domain") == "itau-seguranca.com.br"]
    own = by_title(res, "Own or defensive registrations among lookalike candidates")[0]
    assert "own_asset" in own.tags and "typosquat" not in own.tags
    assert "itau-seguranca.com.br" in own.data["domains"] and "itau.net.br" in own.data["domains"]  # org domain: not queried
    owned = {r["domain"]: r for r in res.attributes["typosquat_own_registrations"]}
    assert owned["itau-seguranca.com.br"]["ownership"] == "own_asset"
    assert "itau-seguranca.com.br" not in {p.entity.value for p in res.pivots}
    assert not [c for c in http.calls if re.search(r"name=itau\.net\.br(&|$)", c["url"])]


def test_brand_protection_registrar_is_defensive_probable():
    google = TS.parse_rdap(fx("rdap_brand_protection_registrar.json"))
    assert google["registrar"] == "MarkMonitor Inc." and google["registrar_iana_id"] == "292"
    verdict = TS.brand_ownership({"domain": "google-login.com", "ns": ["ns1.google.com"], "registrar": google["registrar"]},
                                 {"domains": ["example.com"]})
    assert verdict["verdict"] == "defensive_probable"
    assert TS.severity_ladder({"mx": True, "nrd_days": 2}, verdict["verdict"])["section"] == "own_assets"


def test_parked_cap_from_the_parking_ns_list():
    """P012 c9/c12: parking NS caps a lookalike at LOW (and suppresses the A-record signal)."""
    http = FakeHttp()
    parked = fx("doh_parked_ns_derived.json")
    for prov in ("cloudflare", "google"):
        from tests.fakes import doh_url

        http.add("GET", doh_url("itau-pix.com.br", "NS", provider=prov), json=parked)
    serve(http, "itau-pix.com.br", a=["203.0.113.20"], mx=["10 mx.example.net."], providers=("cloudflare", "google"))
    add_nxdomain_everything(http)
    http.add("GET", RDAP_BR.format("itau-pix.com.br"), json=rdap_org("44.555.666/0001-81", ns="ns1.sedoparking.com"))
    res = run_module(Typosquat, "domain:itau.com.br", http, org_profile=ORG)
    f = [f for f in by_title(res, "Registered lookalike domain") if f.data["domain"] == "itau-pix.com.br"][0]
    assert f.severity.label == "low" and f.data["parked"] is True and "parked" in f.tags
    assert "a_non_parking" not in f.data["signals"] and set(f.data["signals"]) == {"mx", "nrd<=30d"}


def test_doh_budget_cap_hit_is_reported_in_coverage():
    http = _forward_http()
    res = run_module(Typosquat, "domain:itau.com.br", http, org_profile=ORG, settings={"typosquat_doh_budget": 12})
    cov = res.attributes["typosquat_coverage"]
    assert cov["doh_cap_hit"] is True and cov["doh_queries"] <= 12 and cov["unchecked"] > 0
    assert cov["stopped"] == "DoH budget reached" and cov["unchecked_sample"]
    assert res.partial is True and res.stop_reason == "request_cap" and res.status is Status.OK


def test_servfail_refused_and_timeouts_are_could_not_verify_never_unregistered():
    """P012 c7 (rule 5): only an NXDOMAIN counts as unregistered."""
    http = FakeHttp()
    for kind, name in (("servfail", "itau-pix.com.br"), ("refused", "itau-boleto.com.br"), ("timeout", "itau-fatura.com.br")):
        add_dns_failure(http, name, "NS", kind=kind, provider="cloudflare")
        add_dns_failure(http, name, "NS", kind=kind, provider="google")
    add_nxdomain_everything(http)
    res = run_module(Typosquat, "domain:itau.com.br", http, org_profile=ORG)
    cov = res.attributes["typosquat_coverage"]
    assert cov["could_not_verify"] == 3 and set(cov["could_not_verify_sample"]) == {"itau-pix.com.br", "itau-boleto.com.br", "itau-fatura.com.br"}
    rows = {r["domain"]: r for r in res.raw["candidates"]}
    assert rows["itau-pix.com.br"]["state"] == "could_not_verify" and rows["itau-pix.com.br"]["doh"]["NS"] == "SERVFAIL"
    assert rows["itau-boleto.com.br"]["doh"]["NS"] == "REFUSED"
    assert not {"itau-pix.com.br", "itau-boleto.com.br", "itau-fatura.com.br"} & {p.entity.value for p in res.pivots}


def test_unregistered_needs_an_nxdomain_confirmed_by_a_second_resolver():
    http = FakeHttp()
    add_nxdomain_everything(http)
    res = run_module(Typosquat, "domain:itau.com.br", http, org_profile=ORG, settings={"typosquat_candidates": 5})
    rows = [r for r in res.raw["candidates"] if r.get("doh")]  # the org's own itau.net.br is listed without a query
    assert len(rows) == 5 and all(r["state"] == "unregistered" and r["nxdomain_confirmed"] is True for r in rows)
    first = rows[0]["domain"]
    hosts = [c["url"].split("/")[2] for c in http.calls if f"name={first}&" in c["url"] or c["url"].endswith(f"name={first}")]
    assert "cloudflare-dns.com" in hosts and "dns.google" in hosts  # a different resolver confirmed it
    assert res.status is Status.OK and res.attributes["typosquat_coverage"]["unregistered"] == 5


def test_dead_doh_ends_could_not_verify():
    http = FakeHttp()
    http.add("GET", re.compile(r"^https://(dns\.google/resolve|cloudflare-dns\.com/dns-query)\?"), status=503, text="unavailable")
    res = run_module(Typosquat, "domain:itau.com.br", http, org_profile=ORG, settings={"typosquat_candidates": 3})
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert res.source_statuses["core_doh.resolvers"]["status"] == "error"


def test_malformed_doh_body_is_never_an_absence():
    http = FakeHttp()
    from tests.fakes import doh_url

    for prov in ("cloudflare", "google"):
        http.add("GET", doh_url("itau-pix.com.br", "NS", provider=prov), text=(Path(__file__).resolve().parents[1] / "fixtures" / "typosquat" / "doh_malformed_truncated.json").read_text())
    add_nxdomain_everything(http)
    res = run_module(Typosquat, "domain:itau.com.br", http, org_profile=ORG)
    row = {r["domain"]: r for r in res.raw["candidates"]}["itau-pix.com.br"]
    assert row["state"] == "could_not_verify"


@pytest.mark.parametrize("status,kind", [(429, "rate_limited"), (403, "blocked")])
def test_rdap_429_and_403_are_could_not_verify_and_the_scan_goes_on(status, kind):
    http = FakeHttp()
    serve(http, "itau-seguranca.com.br", ns=["ns1.hostinger.com."], a=["203.0.113.10"], mx=["10 mx.hostinger.com."])
    add_nxdomain_everything(http)
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>" if status == 403 else "slow down"
    http.add("GET", RDAP_BR.format("itau-seguranca.com.br"), status=status, text=page)
    res = run_module(Typosquat, "domain:itau.com.br", http, org_profile=ORG)
    assert res.status is Status.OK
    assert res.source_statuses["registrobr.rdap"]["status"] == kind
    f = [f for f in by_title(res, "Registered lookalike domain") if f.data["domain"] == "itau-seguranca.com.br"][0]
    assert f.severity.label == "medium" and f.data["ownership"] != "not_brand_owned"  # no RDAP facts: never HIGH


def test_rdap_error_inside_200_and_404():
    http = FakeHttp()
    serve(http, "itau-seguranca.com.br", ns=["ns1.hostinger.com."], a=["203.0.113.10"])
    serve(http, "itau-boleto.com.br", ns=["ns1.hostinger.com."], a=["203.0.113.12"])
    add_nxdomain_everything(http)
    http.add("GET", RDAP_BR.format("itau-seguranca.com.br"), json={"errorCode": 500, "title": "internal"})
    http.add("GET", RDAP_BR.format("itau-boleto.com.br"), status=404, json={"errorCode": 404})
    res = run_module(Typosquat, "domain:itau.com.br", http, org_profile=ORG)
    rows = {r["domain"]: r for r in res.attributes["typosquat_lookalikes"]}
    assert rows["itau-seguranca.com.br"]["rdap"] == "could_not_verify" and rows["itau-boleto.com.br"]["rdap"] == "not_found"


def test_forward_scan_gating():
    """c4: never on pivots, subdomains or arbitrary hostile domains; explicit -M runs it."""
    pivot = run_module(Typosquat, "domain:itau.com.br", FakeHttp(), org_profile=ORG, is_seed=False, depth=1)
    assert pivot.status is Status.EMPTY and not pivot.findings
    arbitrary = run_module(Typosquat, "domain:example.org", FakeHttp(), org_profile=ORG)
    assert arbitrary.status is Status.EMPTY
    http = FakeHttp()
    add_nxdomain_everything(http)
    explicit = run_module(Typosquat, "domain:example.org", http, org_profile=ORG, settings={"typosquat_candidates": 4},
                          options=ScanOptions(include={"typosquat"}))
    assert explicit.attributes["typosquat_coverage"]["why"] == "explicit -M typosquat" and len(explicit.raw["candidates"]) == 4
    sub = run_module(Typosquat, "domain:login.example.org", FakeHttp(), org_profile=ORG, options=ScanOptions(include={"typosquat"}))
    assert sub.status is Status.EMPTY and not [c for c in sub.raw or []]


def test_keyword_seed_of_an_org_brand_and_deep_preset():
    http = FakeHttp()
    add_nxdomain_everything(http)
    res = run_module(Typosquat, "keyword:itau", http, org_profile=ORG, settings={"typosquat_doh_budget": 30})
    cov = res.attributes["typosquat_coverage"]
    assert cov["why"] == "org_profile brand" and cov["candidates_ranked"] == 150
    dead = FakeHttp()
    add_nxdomain_everything(dead)
    deep = run_module(Typosquat, "keyword:itau", dead, org_profile=ORG, settings={"typosquat_doh_budget": 1},
                      options=ScanOptions(preset="deep"))
    assert deep.attributes["typosquat_coverage"]["candidates_ranked"] == 500
    assert not Typosquat().applies(Entity.make(T.KEYWORD, "ransomware"), make_ctx(Typosquat, org_profile=ORG))


def test_cancellation_keeps_what_was_checked():
    http = FakeHttp()
    add_nxdomain_everything(http)
    ctx = make_ctx(Typosquat, http, org_profile=ORG, settings={"typosquat_candidates": 20})
    calls = {"n": 0}
    real = ctx.cancelled

    def cancelled():
        calls["n"] += 1
        return calls["n"] > 6 or real()

    ctx.cancelled = cancelled
    res = Typosquat().run(Entity.make(T.DOMAIN, "itau.com.br"), ctx)
    assert res.partial and res.stop_reason == "cancelled"
    assert 0 < res.attributes["typosquat_coverage"]["candidates_checked"] < 20


# =================================================================== ladder, ownership, RDAP minimisation (c6, c8, c9)
@pytest.mark.parametrize("signals,ownership,parked,expected", [
    ({}, "not_brand_owned", False, ("info", "info_table")),
    ({"nrd_days": 45}, "not_brand_owned", False, ("info", "info_table")),
    ({"mx": True}, "not_brand_owned", False, ("medium", "findings")),
    ({"ct_cert_days": 5}, "unknown", False, ("medium", "findings")),
    ({"mx": True, "nrd_days": 10}, "not_brand_owned", False, ("high", "findings")),
    ({"mx": True, "nrd_days": 10}, "unknown", False, ("medium", "findings")),
    ({"ct_cert_days": 10, "a_non_parking": True}, "not_brand_owned", False, ("high", "findings")),
    ({"phishing_list": True, "page_similarity": True}, "not_brand_owned", False, ("high", "findings")),
    ({"mx": True, "nrd_days": 10}, "not_brand_owned", True, ("low", "findings")),
    ({"a_non_parking": True}, "not_brand_owned", True, ("info", "info_table")),
    ({"mx": True}, "own_asset", False, (None, "own_assets")),
    ({"mx": True, "nrd_days": 1}, "defensive_probable", False, (None, "own_assets")),
])
def test_severity_ladder(signals, ownership, parked, expected):
    r = TS.severity_ladder(signals, ownership, parked=parked)
    assert (r["severity"], r["section"]) == expected


def test_ownership_verdicts():
    own = {"domains": ["itau.com.br"], "cnpj_roots": ["11222333"]}
    assert TS.brand_ownership({"domain": "x.com.br", "cnpj_roots": ["11222333"]}, own)["verdict"] == "own_asset"
    assert TS.brand_ownership({"domain": "x.com", "ns": ["ns1.itau.com.br"]}, own)["verdict"] == "own_asset"
    assert TS.brand_ownership({"domain": "x.com", "ns": ["ns1.cloudflare.com"], "registrar": "Example Registrar"}, own)["verdict"] == "not_brand_owned"
    br = TS.brand_ownership({"domain": "x.com.br", "ns": ["ns1.hostinger.com"], "cnpj_roots": ["44555666"]}, own)
    assert br["verdict"] == "not_brand_owned" and br["registrant_checked"] is True  # .br: CNPJ stands in for the registrar
    assert TS.brand_ownership({"domain": "x.com", "ns": ["ns1.example.net"]}, own)["verdict"] == "unknown"
    assert TS.brand_ownership({"domain": "www.itau.com.br"}, own)["verdict"] == "own_asset"


def test_rdap_minimisation_drops_people_and_cpf():
    br = TS.parse_rdap(fx("rdap_br_cnpj_registrant.json"))
    assert br["registrant_kind"] == "org" and br["cnpj_roots"] == ["05506560"] and br["registrar"] is None
    assert br["nameservers"][0] == "a.dns.br" and br["created"] == "1999-02-21T12:00:00Z"
    redacted = TS.parse_rdap(fx("rdap_redacted_derived.json"))
    assert redacted["registrant_kind"] == "redacted" and redacted["registrant_org"] is None and redacted["registrar"] == "Example Registrar, LLC"
    person = {"objectClassName": "domain", "entities": [{"roles": ["registrant"], "publicIds": [{"type": "cpf", "identifier": "123.456.789-09"}],
                                                         "vcardArray": ["vcard", [["fn", {}, "text", "Maria Exemplo"], ["kind", {}, "text", "individual"]]]}]}
    out = TS.parse_rdap(person)
    assert out["registrant_kind"] == "individual" and out["cpf_seen"] is True
    assert "Maria" not in json.dumps(out) and "123.456" not in json.dumps(out)
    assert TS.parse_rdap(["junk"])["error"] and TS.parse_rdap({"errorCode": 404})["error"]


def test_parsers_never_raise_on_junk():
    for junk in (None, 1, "x", [], {}, {"value": "x"}, b"\xff"):
        TS.parse_bcb_rows(junk)
        TS.parse_rdap(junk)
        TS.brand_ownership(junk if isinstance(junk, dict) else {}, {})
        P.reverse_match(junk, [], lures=())
        P.generate(junk if isinstance(junk, str) else None)
