"""dork_generator (P306, batch p2-G14-3): search-engine dork links, BR phone variants and the pasted-URL router.

Links only: the module never sends a request (cond 1). Vectors: tests/fixtures/dork_generator/ (documentation values;
phone numbers in the 5555-01xx documentation range)."""

from __future__ import annotations

import copy
import socket
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.providers import registry
from v3lum.modules.search_dorks import dork_generator as dg
from v3lum.modules.search_dorks.dork_generator import DorkGenerator

OPTED_IN = ScanOptions(show_personal=True, purpose="incident INC-2026-001")
PHONES = module_fixture("dork_generator", "phone_variants_expected.json")
URLS = module_fixture("dork_generator", "pasted_urls_expected.json")


def rows_of(res):
    return {r["id"]: r for r in res.raw["rows"]}


def query_of(url: str) -> str:
    return parse_qs(urlsplit(url).query)["q"][0]


# ------------------------------------------------------------------ cond 2, 5: pack lint
def test_shipped_pack_is_clean_and_rows_respect_the_limits():
    data, rows, errors = dg.load_pack()
    assert errors == [] and len(rows) == len(data["dorks"]) >= 30
    for row in rows:
        sites = data["site_lists"].get(row.get("site_list"), {}).get("sites", [])
        expanded = row["query"].replace("{sites}", dg.sites_clause(sites))
        assert dg.count_words(expanded) <= dg.MAX_DORK_WORDS, row["id"]
        assert dg.site_operators(expanded) < dg.MAX_SITE_OPERATORS, row["id"]


BAD = [
    ({"query": "\"{name}\" cpf"}, "DL05"),
    ({"query": "\"{name}\" (senha OR password)"}, "DL05"),
    ({"query": "\"{name}\" vazamento"}, "DL05"),
    ({"query": "\"{name}\" site:pastebin.com"}, "DL05"),
    ({"query": "\"{name}\" 529.982.247-25"}, "DL04"),
    ({"entity_types": ["cpf"], "query": "\"{name}\""}, "DL04"),
    ({"privacy": False}, "DL07"),
    ({"query": "site:linkedin.com/in \"{name}\""}, "DL08"),
    ({"query": "\"{name}\" {0.__class__}"}, "DL01"),
    ({"query": "\"{secret}\""}, "DL01"),
    ({"query": " ".join(["w"] * 40) + " {name}"}, "DL02"),
    ({"query": "\"{name}\" (" + " OR ".join(f"site:s{i}.example" for i in range(31)) + ")"}, "DL03"),
    ({"engines": ["yandex"]}, "DL09"),
]


@pytest.mark.parametrize(("over", "rule"), BAD)
def test_lint_rejects_unsafe_rows(over, rule):
    row = {"id": "person_test", "family": "person", "group": "person", "label": "test", "query": "\"{name}\"",
           "entity_types": ["person_name"], "engines": ["google"], "privacy": True, "scope": "seed_only",
           "curated": False}
    row.update(over)
    problems = dg.lint_dork(row, {})
    assert any(p.startswith(rule) for p in problems), problems


def test_lint_rejects_paste_dorks_for_people_and_ip_operator_off_bing():
    paste = {"id": "u_paste", "family": "username", "group": "person", "label": "x", "query": "\"{user}\" site:pastebin.com",
             "entity_types": ["username"], "engines": ["google"], "privacy": True, "scope": "seed_only", "curated": False}
    assert any(p.startswith("DL06") for p in dg.lint_dork(paste, {}))
    ip = {"id": "ip_google", "family": "bing_operator", "group": "b", "label": "x", "query": "ip:{ip}",
          "entity_types": ["ipv4"], "engines": ["google"], "privacy": False, "scope": "seed_only", "curated": False}
    assert any(p.startswith("DL09") for p in dg.lint_dork(ip, {}))
    exposure = {"id": "exp_user", "family": "exposure", "group": "e", "label": "x", "query": "\"{user}\" filetype:pdf",
                "entity_types": ["username"], "engines": ["google"], "privacy": True, "scope": "typed_or_own", "curated": False}
    assert any(p.startswith("DL11") for p in dg.lint_dork(exposure, {}))


def test_broken_pack_is_refused(tmp_path):
    data, _rows, _e = dg.load_pack()
    bad = copy.deepcopy(data)
    bad["dorks"][0]["query"] = "{domain} {cpf}"
    path = tmp_path / "dorks.json"
    import json

    path.write_text(json.dumps(bad), encoding="utf-8")
    loaded = dg.load_pack(path)
    assert loaded[2] and len(loaded[1]) == len(data["dorks"]) - 1  # the bad row is dropped (fail closed)


# ------------------------------------------------------------------ cond 1: zero HTTP
def test_zero_http_while_building_links(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("dork_generator must never open a connection")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    http = FakeHttp()
    for value in ("domain:example.com", "company_name:Example Org", "ipv4:8.8.8.8", "phone:+5511955550123"):
        res = run_module(DorkGenerator, value, http, tlp="clear", options=OPTED_IN)
        assert res.requests == 0
    assert http.calls == []


def test_engines_are_registered_trusted_providers():
    for host in ("www.google.com", "www.bing.com", "duckduckgo.com"):
        provider = registry().provider_for_host(host)
        assert provider is not None and provider.tier == "trusted", host
    assert set(dg.ENGINES) == {"google", "bing", "duckduckgo"}
    assert dg.dork_url("duckduckgo", "a b") == "https://duckduckgo.com/?q=a+b"


# ------------------------------------------------------------------ cond 3: exposure gates
def test_typed_domain_gets_exposure_dorks():
    res = run_module(DorkGenerator, "domain:example.com", tlp="clear")
    assert res.status is Status.OK
    rows = rows_of(res)
    assert {"exp_documents", "exp_configs", "exp_panels", "exp_directory_listing"} <= set(rows)
    assert rows["exp_documents"]["query"].startswith("site:example.com (filetype:pdf")
    url = next(u for _l, u in res.links if "filetype" in query_of(u))
    assert url.startswith("https://www.google.com/search?q=")


def test_pivoted_third_party_domain_gets_no_exposure_dorks():
    res = run_module(DorkGenerator, "domain:example.net", tlp="clear", is_seed=False, depth=1,
                     provenance=[("ipv4:203.0.113.5", "reverse_dns", "x")])
    assert not [r for r in res.raw.get("rows", []) if r["family"] == "exposure"]
    assert any("exposure dorks only" in s["reason"] for s in res.raw["skipped"])


def test_name_under_a_typed_apex_and_org_assets_get_exposure_dorks():
    res = run_module(DorkGenerator, "domain:www.example.com", tlp="clear", is_seed=False, depth=1,
                     provenance=[("domain:example.com", "subdomain", "subdomains_passive")])
    assert "exp_documents" in rows_of(res)
    org = OrgProfile.from_dict({"org": {"name": "Example Org"}, "domains": [{"name": "example.org", "verification": "confirmed"}]})
    res = run_module(DorkGenerator, "domain:example.org", tlp="clear", is_seed=False, depth=2, org_profile=org,
                     provenance=[("ipv4:203.0.113.5", "reverse_dns", "x")])
    assert "exp_documents" in rows_of(res)


def test_bing_operators_and_site_categories():
    res = run_module(DorkGenerator, "ipv4:8.8.8.8", tlp="clear")
    assert [u for _l, u in res.links] == ["https://www.bing.com/search?q=ip%3A8.8.8.8"]
    res = run_module(DorkGenerator, "company_name:Example Org", tlp="clear")
    rows = rows_of(res)
    assert "site:reclameaqui.com.br" in rows["site_br_complaints"]["query"]
    assert "site:jusbrasil.com.br" in rows["site_br_legal"]["query"]
    assert "site:gov.br" in rows["site_br_gov"]["query"]
    assert "fraud_company_terms" in rows


def test_quotes_in_values_cannot_inject_operators():
    res = run_module(DorkGenerator, 'company_name:Example" OR site:evil.example "x', tlp="clear")
    q = rows_of(res)["fraud_company_terms"]["query"]
    assert q.startswith('"Example OR site:evil.example x" (golpe')
    assert q.count('"') == 4  # only the template's own quotes


# ------------------------------------------------------------------ cond 4: BR fraud families and phones
@pytest.mark.parametrize("case", PHONES)
def test_br_phone_variants(case):
    out = dg.br_phone_variants(case["e164"])
    if case["expect"] is None:
        assert out is None
    else:
        assert out["kind"] == case["expect"]["kind"] and out["e164"] == case["expect"]["e164"]
        assert out["wa"] == case["expect"]["wa"] and out["variants"] == case["expect"]["variants"]


def test_cnpj_fraud_dorks():
    res = run_module(DorkGenerator, "cnpj:11.222.333/0001-81", tlp="clear")
    rows = rows_of(res)
    assert rows["fraud_cnpj_terms"]["query"] == '("11.222.333/0001-81" OR "11222333000181") (golpe OR fraude OR estelionato)'
    assert "site:reclameaqui.com.br" in rows["fraud_cnpj_sites"]["query"]


def test_phone_dorks_need_a_typed_seed_and_the_case_opt_in():
    res = run_module(DorkGenerator, "phone:+5511955550123", tlp="clear")
    assert res.status is Status.EMPTY and "privacy" in res.error and not res.links
    res = run_module(DorkGenerator, "phone:+5511955550123", tlp="clear", options=OPTED_IN)
    rows = rows_of(res)
    assert '"(11) 95555-0123"' in rows["phone_exact"]["query"] and '"1155550123"' in rows["phone_exact"]["query"]
    assert '"wa.me/5511955550123"' in rows["fraud_wa_links"]["query"]
    assert res.attributes["br_phone_variants"][0] == "+55 11 95555-0123"
    res = run_module(DorkGenerator, "phone:+5511955550123", tlp="clear", options=OPTED_IN, is_seed=False, depth=1)
    assert not res.links
    unconfirmed = ScanOptions(show_personal=True, purpose="x", unconfirmed_seeds={"phone:+5511955550123"})
    assert not run_module(DorkGenerator, "phone:+5511955550123", tlp="clear", options=unconfirmed).links


def test_pix_random_keys_only():
    res = run_module(DorkGenerator, "pix_key:123e4567-e89b-12d3-a456-426614174000", tlp="clear", options=OPTED_IN)
    assert rows_of(res)["fraud_pix"]["query"].startswith('"123e4567-e89b-12d3-a456-426614174000" (golpe')


# ------------------------------------------------------------------ cond 5: no CPF, no person + leak terms
def test_cpf_never_reaches_a_dork():
    assert T.CPF not in DorkGenerator.accepts
    res = run_module(DorkGenerator, "keyword:529.982.247-25", tlp="clear")
    assert not res.links and not res.raw.get("rows")
    assert dg.dork_values(Entity.make("keyword", "cliente 52998224725")) is None
    data, rows, _e = dg.load_pack()
    for row in rows:
        assert not dg.contains_cpf(row["query"])
        if set(row["entity_types"]) & {t.value for t in dg.PERSON_TYPES}:
            assert not dg.FORBIDDEN_PERSON_TERMS.search(row["query"]), row["id"]


def test_paste_site_dorks_are_for_domains_and_brands_only():
    data, rows, _e = dg.load_pack()
    for row in rows:
        sites = data["site_lists"].get(row.get("site_list"), {}).get("sites", [])
        text = (row["query"] + " " + " ".join(sites)).lower()
        if any(p in text for p in dg.PASTE_SITES):
            assert {T(t) for t in row["entity_types"]} <= dg.BRAND_TYPES, row["id"]


# ------------------------------------------------------------------ cond 6: privacy and LinkedIn X-ray
def test_person_dorks_are_privacy_rows():
    res = run_module(DorkGenerator, "person_name:Maria Exemplo", tlp="clear")
    assert not res.links
    res = run_module(DorkGenerator, "person_name:Maria Exemplo", tlp="clear", options=OPTED_IN)
    assert set(rows_of(res)) == {"person_exact"}  # no LinkedIn X-ray without an own organisation


def test_linkedin_xray_only_for_the_own_organisation():
    org = OrgProfile.from_dict({"org": {"name": "Example Org S.A."}, "brands": [{"keyword": "exampleorg"}]})
    res = run_module(DorkGenerator, "person_name:Maria Exemplo", tlp="clear", options=OPTED_IN, org_profile=org)
    assert rows_of(res)["linkedin_xray_person"]["query"] == 'site:linkedin.com/in "Maria Exemplo" "Example Org S.A."'
    res = run_module(DorkGenerator, "company_name:Example Org", tlp="clear", options=OPTED_IN, org_profile=org)
    assert "linkedin_xray_company" in rows_of(res)
    res = run_module(DorkGenerator, "company_name:Other Company", tlp="clear", options=OPTED_IN, org_profile=org)
    assert "linkedin_xray_company" not in rows_of(res)
    res = run_module(DorkGenerator, "company_name:Example Org", tlp="clear", org_profile=org)
    assert "linkedin_xray_company" not in rows_of(res)  # privacy row: opt-in needed


# ------------------------------------------------------------------ cond 7, 8: rendering and caps
def test_amber_labels_carry_the_disclosure_warning():
    res = run_module(DorkGenerator, "domain:example.com")  # default TLP:AMBER
    assert res.links and all("opening sends the query" in label and "www.google.com" in label for label, _u in res.links)
    clear = run_module(DorkGenerator, "domain:example.com", tlp="clear")
    assert all("opening sends" not in label for label, _u in clear.links)


def test_red_emits_nothing():
    res = run_module(DorkGenerator, "domain:example.com", tlp="red")
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and not res.links


def test_engine_setting_and_bing_only_rows():
    res = run_module(DorkGenerator, "domain:example.com", tlp="clear", settings={"dork_generator_engine": "duckduckgo"})
    engines = {r["id"]: [x["engine"] for x in r["links"]] for r in res.raw["rows"]}
    for shown in res.raw["shown"]:
        expected = "duckduckgo" if "duckduckgo" in engines[shown["id"]] else engines[shown["id"]][0]
        assert shown["engine"] == expected and shown["url"].startswith(dg.ENGINES[expected][1])
    assert any(s["engine"] == "duckduckgo" for s in res.raw["shown"])
    res = run_module(DorkGenerator, "url:https://example.com/a", tlp="clear", settings={"dork_generator_engine": "google"})
    assert [u for _l, u in res.links] == ["https://www.bing.com/search?q=url%3Ahttps%3A%2F%2Fexample.com%2Fa"]


def test_caps_terminal_five_curated_and_twenty_report_links():
    rows = [{"id": f"r{i}", "group": "g", "family": "exposure", "curated": i % 2 == 0} for i in range(30)]
    capped = dg.cap_rows(rows)
    assert len(capped["report"]) == dg.REPORT_LINK_CAP and len(capped["terminal"]) == dg.TERMINAL_DORK_CAP
    assert capped["report"][0]["curated"] and capped["overflow_hint"] == "v3lum links --all"
    assert len(capped["overflow"]) == 10
    res = run_module(DorkGenerator, "domain:example.com", tlp="clear")
    assert len(res.links) <= dg.REPORT_LINK_CAP and len(res.raw["terminal"]) <= dg.TERMINAL_DORK_CAP
    assert all(r["curated"] for r in res.raw["rows"] if r["id"] in res.raw["terminal"])


def test_every_link_is_on_its_engine_host():
    res = run_module(DorkGenerator, "company_name:Example Org", tlp="clear", options=OPTED_IN)
    hosts = {urlsplit(u).hostname for r in res.raw["rows"] for u in (x["url"] for x in r["links"])}
    assert hosts <= {"www.google.com", "www.bing.com", "duckduckgo.com"}


# ------------------------------------------------------------------ cond 9: pasted-URL router
@pytest.mark.parametrize("case", URLS["cases"])
def test_route_pasted_url(case):
    out = dg.route_pasted_url(case["url"])
    for key, value in case["expect"].items():
        got = out.get(key)
        assert (list(got) if isinstance(got, tuple) else got) == value, (case["url"], key, out)


def test_router_never_fetches_and_keeps_leak_pages_for_manual_triage():
    out = dg.route_pasted_url("https://pastebin.com/AbCd1234")
    assert out["kind"] == "exposure" and "never fetched" in out["label"]
    assert dg.route_pasted_url("https://x.com/search/status/1")["kind"] != "post_x"
