"""Offline tests for batch p3-G14-1 reference helpers (fixtures under ../fixtures, no network).

Run: cd code && python3 -m pytest -q -p no:cacheprovider .
"""
import datetime as dt
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

import parsers as P

FIX = Path(__file__).parent.parent / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text("utf-8"))


def env(name):
    d = load(name)
    return d["status"], d.get("headers", {}), d["body"]


TIERS = load("host_tiers_draft.json")["tiers"]
PACKS = {"email": load("pivots_email__pack_draft.json"),
         "username_social": load("pivots_username_social__pack_draft.json"),
         "person": load("pivots_person__pack_draft.json")}
VECTORS = load("render_vectors.json")


def link_of(pack, lid):
    return next(lk for lk in PACKS[pack]["links"] if lk["id"] == lid)


def seed_view(link, etype, value, **kw):
    args = dict(tlp="clear", provenance="seed", privacy_opt_in=True, purpose="case 42: own-brand abuse",
                host_tier=TIERS.get(link["host"]))
    args.update(kw)
    return P.link_view(link, etype, value, **args)


# ------------------------------------------------------------------------------------------ pack lint (FC1/FC4)

@pytest.mark.parametrize("pack", sorted(PACKS))
def test_pack_drafts_lint_clean(pack):
    assert P.lint_pack(PACKS[pack], host_tiers=TIERS) == []


@pytest.mark.parametrize("pack", sorted(PACKS))
def test_pack_drafts_use_frozen_keys_only(pack):
    data = PACKS[pack]
    assert data["schema"] == P.PACK_SCHEMA and data["pack"] == pack
    for lk in data["links"]:
        assert set(lk) <= set(P.FROZEN_LINK_KEYS) | set(P.EXTENSION_LINK_KEYS)
        assert lk["publishes"] is False and lk["login_required"] is False
        assert lk["verified"] is True and lk["checked_at"] == "2026-11-26"
        if "max_tlp" in lk:
            assert pack == "person"


def _bad_cases():
    for f in ("pivots_email__lint_bad_entries.json", "pivots_username_social__lint_bad_entries.json",
              "pivots_person__lint_bad_entries.json"):
        d = load(f)
        for i, case in enumerate(d["cases"]):
            yield pytest.param(d["pack"], case["entry"], case["expect"], id=f"{d['pack']}-{i}")


@pytest.mark.parametrize("pack,entry,expect", list(_bad_cases()))
def test_lint_rejects_bad_entries(pack, entry, expect):
    problems = P.lint_link(entry, pack=pack, host_tiers=TIERS)
    assert any(expect in p for p in problems), problems


def test_person_link_dropped_when_webmii_is_unknown_tier():
    d = load("pivots_person__lint_bad_entries.json")["tier_case"]
    problems = P.lint_pack(PACKS["person"], host_tiers=d["host_tiers"])
    for expect in d["expect"]:
        assert any(expect in p for p in problems), problems
    view = seed_view(link_of("person", "webmii_people"), "person_name", "Maria Exemplo", host_tier="unknown")
    assert view["where"] == "hidden" and view["reason"] == "tier"


def test_registry_draft_records_webmii_unknown_and_evidence():
    frag = load("pivots_person__registry_draft.json")["entries"][0]["fragment"]
    assert frag["tier"] == "unknown" and frag["hosts"] == ["webmii.com"]
    ev = load("pivots_person__operator_evidence.json")
    assert ev["app_store"]["seller_kind"] == "individual"
    assert ev["links_on_site"] == {"terms": False, "privacy_policy_linked": False, "legal_entity_named": False}


def test_registry_drafts_shape():
    for f in ("pivots_email__registry_draft.json", "pivots_username_social__registry_draft.json",
              "pivots_person__registry_draft.json", "web_search_api__registry_draft.json"):
        for e in load(f)["entries"]:
            if e["action"] != "new":
                continue
            fr = e["fragment"]
            assert fr["schema"] == "v3lum.provider/1" and fr["tier"] in P.TIERS
            assert set(fr["flags"]) == {"publishes_queries", "reuses_queries", "fetches_target", "sensitive"}
            for s in fr["sources"].values():
                assert s["terms"]["class"] in ("open", "key-terms", "license", "noncommercial", "unknown")
            for m in fr["error_markers"]:
                assert m["maps_to"] in ("blocked", "rate_limited", "quota", "error")
    hosts = [e.get("host") for e in load("web_search_api__registry_draft.json")["entries"]]
    assert "serpapi.com" in hosts  # recorded as refused, never as a provider
    assert all(e["fragment"]["id"] != "serpapi" for e in load("web_search_api__registry_draft.json")["entries"]
               if e["action"] == "new")


def test_no_pack_attaches_hibp_to_entities():
    assert P.breach_pack_problems(PACKS.values()) == []
    bad = {"pack": "breach", "links": [{"id": "hibp_kw", "host": "haveibeenpwned.com",
                                        "template": "https://haveibeenpwned.com/breach/{q}",
                                        "entity_types": ["keyword"]}]}
    assert P.breach_pack_problems([bad])


def test_template_problems_refuse_format_fields_and_foreign_hosts():
    assert any("unknown placeholder {0}" in p for p in P.template_problems("https://webmii.com/people?n={0}",
                                                                           "webmii.com", ["person_name"]))
    for tpl in ("https://webmii.com/people?n={q!r}", "https://webmii.com/people?n={}", "https://webmii.com/{q}}"):
        assert any("stray brace" in p for p in P.template_problems(tpl, "webmii.com", ["person_name"])), tpl
    assert any("host" in p for p in P.template_problems("https://evil.example.org/people?n={q}", "webmii.com",
                                                        ["person_name"]))
    assert any("scheme/host" in p for p in P.template_problems("https://{domain}/x", "{domain}", ["domain"]))
    assert P.template_problems("https://webmii.com/people?n={q}", "webmii.com", ["person_name"]) == []


# ------------------------------------------------------------------------------------------ rendering (FC3)

@pytest.mark.parametrize("vec", VECTORS["samples"], ids=lambda v: f"{v['link']}-{v['value']}")
def test_render_samples(vec):
    lk = link_of(vec["pack"], vec["link"])
    url = P.render_link(lk, vec["etype"], vec["value"])
    assert url == vec["url"]
    if url:
        assert P.check_rendered_url(url, lk["template"], lk["host"]) == []


def _hostile_cases():
    for pack, data in PACKS.items():
        for lk in data["links"]:
            for et in lk["entity_types"]:
                for v in VECTORS["hostile_values"]:
                    yield pytest.param(lk, et, v, id=f"{lk['id']}-{et}-{v!r}"[:80])


@pytest.mark.parametrize("lk,etype,value", list(_hostile_cases()))
def test_render_hostile_values_stay_on_declared_host(lk, etype, value):
    url = P.render_link(lk, etype, value)
    if url is None:
        return
    assert url.startswith("https://" + lk["host"] + "/")
    assert P.check_rendered_url(url, lk["template"], lk["host"]) == []
    assert not any(c in url for c in ' "\n\r\t<>‮')
    assert urlsplit(url).hostname == lk["host"]


def test_never_str_format_and_no_resubstitution():
    assert P.render_template("https://x.example.org/{q}", "keyword", "{q}{domain}", "x.example.org") == \
        "https://x.example.org/%7Bq%7D%7Bdomain%7D"
    assert P.render_template("https://x.example.org/{nope}", "keyword", "a", "x.example.org") is None
    assert P.render_template("https://x.example.org/{raw}", "keyword", "a", "x.example.org") is None


def test_cpf_never_reaches_a_link():
    assert P.enc_q("123.456.789-09") is None and P.enc_q("12345678909") is None
    assert P.type_value("cpf", "Maria") is None
    assert P.person_name_value("Maria 123.456.789-09") is None
    assert P.hibp_breach_url("123.456.789-09") is None


# ---------------------------------------------------------------------------------------- P098 pivots_email

def test_email_label_and_template_fc8_fc9():
    lk = link_of("email", "email_format_domain")
    assert P.EMAIL_PATTERN_LABEL in lk["label"]
    assert lk["template"] == "https://www.email-format.com/d/{domain}/" and lk["entity_types"] == ["domain"]


def test_email_company_name_only_through_known_domains():
    assert P.email_link_domains("domain", "Example.COM.") == ["example.com"]
    assert P.email_link_domains("company_name", "Example Corp") == []
    assert P.email_link_domains("company_name", "Example Corp",
                                ["Example.com", "bad domain", "example.com", "nic.br"]) == ["example.com", "nic.br"]
    assert P.email_link_domains("username", "example.com") == []
    lk = link_of("email", "email_format_domain")
    assert P.render_link(lk, "company_name", "Example Corp") is None  # never the company name itself


def test_email_recheck_ok_and_markers():
    st, h, body = env("pivots_email__ok.http.json")
    assert P.classify_check("email_format", st, h, body, "example.com") == {
        "state": "ok", "detail": "Email Address Format for example.com (Example) | Email Format"}
    assert P.challenge_marker(st, h, body) is None  # reCAPTCHA removal form on a 200 is not a challenge
    assert P.meta_content(body, "og:site_name") is None  # the RocketReach og block is inside a comment
    assert P.meta_content(body, "og:url") == "https://www.email-format.com/d/example.com/"
    assert "data-cfemail" not in body  # no sample addresses kept
    st, h, body = env("pivots_email__ok_br.http.json")
    assert P.classify_check("email_format", st, h, body, "nic.br")["state"] == "ok"
    assert P.classify_check("email_format", st, h, body, "example.com")["state"] == "mismatch"


def test_email_recheck_not_found_and_redirect():
    st, h, body = env("pivots_email__not_found.http.json")
    assert st == 302 and P.classify_check("email_format", st, h, body, "invalid.example.com")["state"] == "not_found"
    st, h, body = env("pivots_email__redirect_apex.http.json")
    r = P.classify_check("email_format", st, h, body, "example.com")
    assert st == 301 and r == {"state": "redirect", "detail": "https://www.email-format.com/d/example.com/"}


def test_email_link_at_amber_is_text_with_disclosure():
    lk = link_of("email", "email_format_domain")
    v = P.link_view(lk, "domain", "example.com", tlp="amber", provenance="pivot", host_tier="community")
    assert v["where"] == "report" and v["clickable"] is False
    assert "opening sends example.com to www.email-format.com" in v["text"] and v["text"].startswith("hxxps://")
    g = P.link_view(lk, "domain", "example.com", tlp="green", provenance="pivot", host_tier="community")
    assert g["clickable"] is True and g["text"] == "https://www.email-format.com/d/example.com/"
    r = P.link_view(lk, "domain", "example.com", tlp="red", provenance="seed", host_tier="community")
    assert r["where"] == "links_only" and r["reason"] == "tlp_red" and r["warnings"]
    u = P.link_view(lk, "domain", "example.com", tlp="green", host_tier="unknown")
    assert P.BADGE_UNKNOWN_OPERATOR in u["badges"] and u["where"] == "report"  # domain is an IOC type


# ------------------------------------------------------------------------------------- P125 username_social

@pytest.mark.parametrize("value,expect", [
    ("@Mastodon@mastodon.social", ("Mastodon", "mastodon.social")),
    ("acct:user_1@Social.Example.org", ("user_1", "social.example.org")),
    ("user@@mastodon.social", None), ("@mastodon.social", None), ("a b@mastodon.social", None),
    ("user@mastodon.social/../x", None), (None, None)])
def test_parse_fediverse_handle(value, expect):
    assert P.parse_fediverse_handle(value) == expect


def test_fedi_user_only_for_the_link_instance():
    assert P.fedi_user_value("@Mastodon@mastodon.social", "mastodon.social") == "Mastodon"
    assert P.fedi_user_value("@Mastodon@mastodon.social.evil.example.org", "mastodon.social") is None
    assert P.fedi_user_value("@someone@social.example.org", "mastodon.social") is None
    assert P.fedi_user_value("@" + "a" * 31 + "@mastodon.social", "mastodon.social") is None
    assert P.fedi_user_value("@a.b@mastodon.social", "mastodon.social") is None  # not a local username


def test_bsky_placeholders():
    assert P.bsky_handle_value("@Jay.Bsky.Team", "bsky_handle") == "jay.bsky.team"
    assert P.bsky_handle_value("octocat", "username") is None  # bare usernames: dead links
    assert P.bsky_handle_value("did:plc:z72i7hdynmk6r22z27h6tvur", "bsky_handle") is None
    assert P.bsky_handle_value("x.local", "bsky_handle") is None
    assert P.bsky_handle_value("bsky.app", "email") is None
    assert P.bsky_social_value("Octo-Cat") == "octo-cat.bsky.social"
    for bad in ("ab", "a" * 19, "-abc", "abc-", "a_b", "bsky.app"):
        assert P.bsky_social_value(bad) is None
    assert P.bsky_social_value("octocat", "bsky_handle") is None


def test_social_links_are_seed_only_with_opt_in():
    lk = link_of("username_social", "bluesky_profile")
    assert P.SAME_HANDLE_LABEL in lk["label"] and lk["privacy"] is True
    ok = seed_view(lk, "bsky_handle", "bsky.app")
    assert ok["where"] == "report" and P.BADGE_PRIVACY in ok["badges"]
    assert seed_view(lk, "bsky_handle", "bsky.app", provenance="pivot")["reason"] == "privacy_not_seed"
    assert seed_view(lk, "bsky_handle", "bsky.app", provenance="extracted")["reason"] == "privacy_not_seed"
    assert seed_view(lk, "bsky_handle", "bsky.app", privacy_opt_in=False)["reason"] == "privacy_opt_in"
    assert seed_view(lk, "bsky_handle", "bsky.app", purpose=" ")["reason"] == "privacy_opt_in"


def test_skip_profiles_username_check_already_linked():
    views = [seed_view(link_of("username_social", "bluesky_profile"), "bsky_handle", "bsky.app"),
             seed_view(link_of("username_social", "mastodon_social_profile"), "fediverse_handle",
                       "@mastodon@mastodon.social")]
    out = P.skip_already_linked(views, ["https://bsky.app/profile/BSKY.APP"])
    assert out[0]["where"] == "hidden" and out[0]["reason"] == "username_check"
    assert out[1]["where"] == "report"
    out = P.skip_already_linked(views, ["https://mastodon.social/@Mastodon"])
    assert out[1]["reason"] == "username_check" and out[0]["where"] == "report"
    assert P.profile_key("https://mastodon.social/users/Mastodon") == ("mastodon.social", "mastodon")


def test_social_order_bluesky_then_mastodon():
    views = [seed_view(link_of("username_social", "mastodon_social_profile"), "fediverse_handle",
                       "@Mastodon@mastodon.social"),
             seed_view(link_of("username_social", "bluesky_profile"), "bsky_handle", "bsky.app")]
    file_order = [seed_view(lk, et, v) for lk, et, v in (
        (link_of("username_social", "bluesky_profile"), "bsky_handle", "bsky.app"),
        (link_of("username_social", "mastodon_social_profile"), "fediverse_handle", "@Mastodon@mastodon.social"))]
    shown, rest = P.order_views(file_order)
    assert [v["ref"] for v in shown] == ["bluesky_profile", "mastodon_social_profile"] and rest == []
    assert [v["ref"] for v in P.order_views(views)[0]] == ["mastodon_social_profile", "bluesky_profile"]


def test_social_rechecks():
    st, h, body = env("pivots_username_social__bsky_ok.http.json")
    assert P.classify_check("bsky_profile", st, h, body, "bsky.app")["state"] == "ok"
    assert P.meta_content(body, "twitter:value1") == "did:plc:z72i7hdynmk6r22z27h6tvur"
    st, h, body = env("pivots_username_social__bsky_not_found.http.json")
    assert st == 200 and P.classify_check("bsky_profile", st, h, body, "example.com")["state"] == "not_found"
    st, h, body = env("pivots_username_social__mastodon_ok.http.json")
    assert P.classify_check("mastodon_profile", st, h, body, "@mastodon@mastodon.social")["state"] == "ok"
    st, h, body = env("pivots_username_social__mastodon_not_found.http.json")
    assert P.classify_check("mastodon_profile", st, h, body, "@x@mastodon.social")["state"] == "not_found"
    st, h, body = env("pivots_username_social__mastodon_gone.http.json")
    assert P.classify_check("mastodon_profile", st, h, body, "@github@mastodon.social")["state"] == "gone"


# ------------------------------------------------------------------------------------- P144 HIBP breach link

def test_hibp_names_from_responses():
    assert P.hibp_names(env("pivots_breach_leak__api_breach_ok.http.json")[2]) == ["Adobe"]
    cat = load("pivots_breach_leak__catalog_ok.json")["body"]
    assert P.hibp_names(cat) == ["000webhost", "17Media", "2844Breaches", "7-Eleven", "Abandonia2022"]
    assert P.hibp_names(env("pivots_breach_leak__api_breach_not_found.http.json")[2]) == []  # 'Not found'
    assert P.hibp_names(env("pivots_breach_leak__page_ok.http.json")[2]) == []  # HTML, not JSON
    assert P.hibp_names([{"Name": "Adobe"}, {"Name": "Adobe"}, {"Name": 3}, "x"]) == ["Adobe"]  # truncated form


def test_hibp_link_from_hibp_name():
    link = P.hibp_link_for("Adobe", from_hibp=True)
    assert link == {"name": "Adobe", "url": "https://haveibeenpwned.com/breach/Adobe", "host": "haveibeenpwned.com",
                    "attribution": "Have I Been Pwned", "licence": "CC BY 4.0",
                    "label": "Adobe on Have I Been Pwned (breach details)"}


def test_hibp_link_for_other_providers_only_on_exact_match():
    idx = P.hibp_catalog_index(load("pivots_breach_leak__catalog_ok.json")["body"])
    idx.update(P.hibp_catalog_index(env("pivots_breach_leak__api_breach_ok.http.json")[2]))
    assert P.hibp_link_for("ADOBE", catalog_index=idx)["url"] == "https://haveibeenpwned.com/breach/Adobe"
    assert P.hibp_link_for("7-eleven", catalog_index=idx)["name"] == "7-Eleven"
    assert P.hibp_link_for("Adobe Systems", catalog_index=idx) is None  # no fuzzy match: no dead links
    assert P.hibp_link_for("Abandonia (2022)", catalog_index=idx) is None  # Title is not the Name
    assert P.hibp_link_for("Adobe") is None  # no HIBP data in the case


@pytest.mark.parametrize("vec", VECTORS["hibp"], ids=lambda v: repr(v["name"]))
def test_hibp_url_spaces_unicode_hostile(vec):
    url = P.hibp_breach_url(vec["name"])
    assert url == vec["url"]
    if url:
        assert P.check_rendered_url(url, P.HIBP_BREACH_TEMPLATE, "haveibeenpwned.com") == []


def test_hibp_page_rechecks():
    st, h, body = env("pivots_breach_leak__page_ok.http.json")
    assert P.challenge_marker(st, h, body) is None  # Cloudflare precursor beacon on a normal 200 page
    assert P.classify_check("hibp_breach_page", st, h, body, "Adobe")["state"] == "ok"
    st, h, body = env("pivots_breach_leak__page_not_found.http.json")
    assert st == 404 and P.classify_check("hibp_breach_page", st, h, body, "Example")["state"] == "not_found"


def test_hibp_catalog_facts_flags():
    rows = P.hibp_catalog_facts(load("pivots_breach_leak__catalog_ok.json")["body"])
    row = next(r for r in rows if r["name"] == "2844Breaches")
    assert row["title"] == "2,844 Separate Data Breaches" and row["IsSensitive"] is False
    assert P.hibp_catalog_facts("<html>") == []


# --------------------------------------------------------------------------------------- P257 pivots_person

def test_person_entry_fc1_fc3():
    lk = link_of("person", "webmii_people")
    assert lk["max_tlp"] == "clear" and lk["privacy"] is True and P.PEOPLE_SEARCH_LABEL in lk["label"]


@pytest.mark.parametrize("tlp,where,reason", [("clear", "report", ""), ("green", "links_only", "max_tlp"),
                                              ("amber", "links_only", "max_tlp"),
                                              ("amber+strict", "links_only", "max_tlp"),
                                              ("red", "links_only", "tlp_red")])
def test_person_link_only_at_clear(tlp, where, reason):
    v = seed_view(link_of("person", "webmii_people"), "person_name", "Maria Exemplo", tlp=tlp)
    assert (v["where"], v["reason"]) == (where, reason)
    assert v["disclosure"] == "opening sends Maria Exemplo to webmii.com"
    assert v["clickable"] is (tlp == "clear")


def test_person_never_for_qsa_partner_or_extracted_names():
    lk = link_of("person", "webmii_people")
    # depth-1 QSA partner of a typed CNPJ: a pivot, never a seed
    assert seed_view(lk, "person_name", "Maria Exemplo", provenance="pivot")["reason"] == "privacy_not_seed"
    assert seed_view(lk, "person_name", "Maria Exemplo", provenance="extracted")["reason"] == "privacy_not_seed"
    assert seed_view(lk, "person_name", "Maria Exemplo", pack_enabled=False)["reason"] == "pack_disabled"


@pytest.mark.parametrize("value,expect", [
    ("Maria  Exemplo", "Maria Exemplo"), ("José da Silva", "José da Silva"), ("Anne-Marie O'Neil", "Anne-Marie O'Neil"),
    ("Maria", None), ("maria@example.com", None), ("Maria 2", None), ('Maria "X" Silva', None),
    ("Maria\nSilva", None), ("Maria <b>Silva</b>", None), ("- -", None), (42, None)])
def test_person_name_value(value, expect):
    assert P.person_name_value(value) == expect


def test_webmii_recheck():
    st, h, body = env("pivots_person__ok.http.json")
    r = P.classify_check("webmii_people", st, h, body, "Banco do Brasil")
    assert r["state"] == "ok" and "client-side" in r["detail"]
    assert "connect.facebook.net" in body and "cse.google.com" in body  # third parties the page loads


# ----------------------------------------------------------------------------------- A2/FC6/FC7 common rules

def test_open_decision():
    v = {"url": "https://webmii.com/people?n=Maria%20Exemplo", "host": "webmii.com"}
    assert P.open_decision(v, "clear", tty=False) == "open"
    assert P.open_decision(v, "amber", tty=False) == "refuse"
    assert P.open_decision(v, "amber", tty=True) == "ask"
    assert P.open_decision(v, "amber", tty=True, confirmed_host="evil.example.org") == "ask"
    assert P.open_decision(v, "red", tty=True, confirmed_host="webmii.com") == "open"
    assert P.open_decision({}, "clear", tty=True) == "refuse"


def test_terminal_cap_eight():
    lk = link_of("email", "email_format_domain")
    views = [P.link_view(dict(lk, id=f"l{i}", verified=i % 2 == 0), "domain", "example.com", tlp="green",
                         host_tier="community") for i in range(12)]
    shown, rest = P.order_views(views)
    assert len(shown) == 8 and len(rest) == 4
    assert all(v["verified"] for v in shown[:6])  # verified first, then file order


def test_doctor_links():
    packs = list(PACKS.values())
    assert P.doctor_links(packs, "2026-11-26") == []
    stale = P.doctor_links(packs, dt.date(2027, 6, 1))
    assert len(stale) == 5 and all(s["age_days"] == 187 for s in stale)
    unv = {"pack": "x", "links": [{"id": "a", "verified": False}, {"id": "b", "verified": True,
                                                                    "checked_at": "nope"}]}
    assert [r["reason"] for r in P.doctor_links([unv], "2026-11-26")] == ["unverified", "bad checked_at"]


def test_tlp_level():
    assert P.tlp_level("TLP:AMBER+STRICT") == 3 and P.tlp_level("clear") == 0 and P.tlp_level("x") is None


# ---------------------------------------------------------------------------------------- P307 web_search_api

def test_serpapi_refused_and_never_a_provider():
    assert P.refused_host("serpapi.com") and P.refused_host("API.SerpApi.com.")
    assert P.refused_host("api.search.brave.com") is None
    assert P.provider_gate("serpapi")["status"] == "policy"
    assert all(p["host"] != "serpapi.com" for p in P.PROVIDERS.values())
    assert load("web_search_api__serpapi_never_requested.json")["body"]["search_metadata"]["status"] == "Success"


@pytest.mark.parametrize("pid,kw,status", [
    ("brave", {}, "needs_key"),
    ("brave", {"key_present": True}, "licence"),
    ("brave", {"key_present": True, "business_plan": True}, "ok"),
    ("brave", {"key_present": True, "business_plan": True, "tlp": "amber+strict"}, "ok"),
    ("brave", {"key_present": True, "business_plan": True, "tlp": "red"}, "tlp"),
    ("duckduckgo", {}, "ok"),
    ("duckduckgo", {"tlp": "red"}, "tlp"),
    ("marginalia", {"key_present": True}, "licence"),
    ("marginalia", {"key_present": True, "licence_cleared": True}, "ok"),
    ("marginalia", {"key_present": True, "licence_cleared": True, "tlp": "amber+strict"}, "tlp"),
    ("tavily", {"key_present": True, "legal_terms_recorded": True}, "tlp"),  # reuses_queries placeholder: AMBER+
    ("tavily", {"tlp": "green", "key_present": True}, "unknown_terms"),
    ("exa", {"tlp": "green", "legal_terms_recorded": True}, "needs_key"),
    ("exa", {"tlp": "green", "legal_terms_recorded": True, "key_present": True}, "ok"),
])
def test_provider_gate(pid, kw, status):
    assert P.provider_gate(pid, **kw)["status"] == status


@pytest.mark.parametrize("pid,fixture,status,needle", [
    ("brave", "web_search_api__brave_needs_key.http.json", "needs_key", "X-Subscription-Token"),
    ("tavily", "web_search_api__tavily_needs_key.http.json", "needs_key", "401"),
    ("exa", "web_search_api__exa_x402.http.json", "needs_key", "no autonomous payments"),
    ("marginalia", "web_search_api__marginalia_quota.http.json", "quota", "Daily Limit"),
    ("brave", "web_search_api__brave_rate_limited_synthetic.http.json", "rate_limited", "429"),
    ("brave", "web_search_api__brave_quota_synthetic.http.json", "quota", "quota"),
    ("duckduckgo", "web_search_api__ddg_malformed_synthetic.http.json", "malformed", "JSON"),
])
def test_classify_search_errors(pid, fixture, status, needle):
    st, h, body = env(fixture)
    r = P.classify_search_response(pid, st, h, body)
    assert r["status"] == status and needle.lower() in r["reason"].lower()


@pytest.mark.parametrize("pid,fixture", [
    ("duckduckgo", "web_search_api__ddg_ok.http.json"), ("duckduckgo", "web_search_api__ddg_empty.http.json"),
    ("brave", "web_search_api__brave_ok_synthetic.http.json"),
    ("marginalia", "web_search_api__marginalia_ok_synthetic.http.json"),
    ("tavily", "web_search_api__tavily_ok_synthetic.http.json"), ("exa", "web_search_api__exa_ok_synthetic.http.json")])
def test_classify_search_ok(pid, fixture):
    st, h, body = env(fixture)
    assert P.classify_search_response(pid, st, h, body) is None


def test_ddg_answers_202_with_a_full_body():
    st, h, body = env("web_search_api__ddg_ok.http.json")
    assert st == 202 and h["content-type"] == "application/x-javascript"


def test_x402_offer_variants():
    st, h, body = env("web_search_api__exa_x402.http.json")
    assert "x402" in P.x402_offer(st, h, body)
    assert P.x402_offer(200, {}, {"results": []}) is None
    assert "Payment" in P.x402_offer(401, {"WWW-Authenticate": 'Payment id="x"'}, "")
    assert "402" in P.x402_offer(402, {}, "")
    assert P.classify_search_response("brave", 402, {}, "")["status"] == "needs_key"


def test_parse_brave_url_and_title_only():
    st, h, body = env("web_search_api__brave_ok_synthetic.http.json")
    out = P.parse_brave_web(body)
    assert out["query"] == "example.com" and out["more_results"] is True
    assert out["results"] == [
        {"url": "https://example.com/", "title": "Example Domain", "host": "example.com"},
        {"url": "https://docs.example.org/page?ref=1", "title": "Example & Docs", "host": "docs.example.org"}]
    assert "snippet" not in json.dumps(out) and "documentation examples" not in json.dumps(out)
    assert P.parse_brave_web(env("web_search_api__brave_needs_key.http.json")[2]) is None
    assert P.parse_brave_web("<html>") is None
    assert P.brave_rate_headers(h) == {"limit": [1, 15000], "remaining": [0, 14990], "reset": [1, 1419704],
                                       "month_remaining": 14990}


def test_evidence_records_and_pivots():
    res = P.parse_brave_web(env("web_search_api__brave_ok_synthetic.http.json")[2])["results"]
    assert P.evidence_records(res, ["https://example.com/"]) == [{"url": "https://example.com/",
                                                                  "title": "Example Domain"}]
    assert len(P.evidence_records(res)) == 2 and P.evidence_records(res, []) == []
    assert P.result_pivots(res) == [("url", "https://example.com/"), ("domain", "example.com"),
                                    ("url", "https://docs.example.org/page?ref=1"), ("domain", "docs.example.org")]


def test_parse_ddg_context():
    f = P.parse_ddg(env("web_search_api__ddg_ok.http.json")[2])
    assert f["heading"] == "example.com" and f["abstract_source"] == "Wikipedia"
    assert f["abstract_url"] == "https://en.wikipedia.org/wiki/example.com" and f["official_domain"] == "example.com"
    assert {"label": "Owner", "value": "Internet Assigned Numbers Authority"} in f["infobox"]
    assert f["related"][0]["url"] == "https://duckduckgo.com/d/.example" and len(f["results"]) == 1
    assert f["empty"] is False and f["attribution"] == "Results from DuckDuckGo (source: Wikipedia)"


def test_parse_ddg_drops_people_from_company_infobox():
    f = P.parse_ddg(env("web_search_api__ddg_ok_company.http.json")[2])
    labels = {r["label"] for r in f["infobox"]}
    assert {"Type", "Industry", "Founded", "Number of employees"} <= labels
    assert not labels & {"Founders", "Key people", "Instagram profile", "Facebook profile"}
    assert "Person Example" not in json.dumps(f)


def test_parse_ddg_empty_and_malformed():
    assert P.parse_ddg(env("web_search_api__ddg_empty.http.json")[2])["empty"] is True
    assert P.parse_ddg(env("web_search_api__ddg_malformed_synthetic.http.json")[2]) is None


@pytest.mark.parametrize("fn,fixture,url", [
    (P.parse_marginalia, "web_search_api__marginalia_ok_synthetic.http.json", "https://blog.example.net/post"),
    (P.parse_tavily, "web_search_api__tavily_ok_synthetic.http.json", "https://example.com/"),
    (P.parse_exa, "web_search_api__exa_ok_synthetic.http.json", "https://example.com/")])
def test_parse_other_engines_url_title_only(fn, fixture, url):
    out = fn(env(fixture)[2])
    assert out["results"][0]["url"] == url and set(out["results"][0]) == {"url", "title", "host"}
    assert "dropped" not in json.dumps(out) and "page copy" not in json.dumps(out)
    assert fn("Daily Limit Exceeded") is None


@pytest.mark.parametrize("query,bad", [
    ('site:example.com "Example Corp"', False), ("https://example.com/reset?token=abc", True),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.x", True), ("example api_key=abc", True),
    ("a" * 40, True), ("123.456.789-09", True), ("x" * 401, True), ("line\nbreak", True), ("", True),
    (" ".join(["w"] * 51), True)])
def test_query_problem(query, bad):
    assert (P.query_problem(query) is not None) is bad


def test_build_query_seed_only_and_purpose():
    assert P.build_query("person_name", "Maria Exemplo", provenance="pivot", purpose="x")[0] is None
    assert P.build_query("person_name", "Maria Exemplo")[0] is None  # no recorded purpose
    assert P.build_query("person_name", "Maria Exemplo", purpose="case 42") == ('"Maria Exemplo"', None)
    assert P.build_query("email", "someone@example.com", purpose="case 42") == ('"someone@example.com"', None)
    assert P.build_query("domain", "Example.com") == ("site:example.com", None)
    assert P.build_query("company_name", 'Example "Corp"') == ('"Example Corp"', None)
    assert P.build_query("ipv4", "8.8.8.8")[0] is None


def test_budget():
    assert P.budget_allows(9) and not P.budget_allows(10) and not P.budget_allows("x")
    assert P.budget_line(3) == "3/10 queries used"


# ------------------------------------------------------------------------------------------ P289 employee_xray

GATE = load("employee_xray__gate_cases.json")


@pytest.mark.parametrize("case", GATE["cases"], ids=lambda c: c["name"])
def test_xray_gate(case):
    r = P.xray_gate(case["company"], case["domain"], org_profile=GATE["org_profile"], scope=case["scope"],
                    now=GATE["now"])
    assert {k: r[k] for k in ("run", "basis", "reason_code")} == case["expect"]


def test_xray_queries_budget():
    assert P.xray_queries("Example Corp") == ['site:linkedin.com/in "Example Corp"',
                                              'site:br.linkedin.com/in "Example Corp"']
    assert P.xray_queries('Example "Corp"', budget_left=1) == ['site:linkedin.com/in "Example Corp"']
    assert P.xray_queries("Example Corp", budget_left=0) == [] and P.xray_queries(None) == []


@pytest.mark.parametrize("title,expect", [
    ("Alice Example - Analista de Segurança - Example Corp | LinkedIn",
     {"name": "Alice Example", "role": "Analista de Segurança", "org": "Example Corp"}),
    ("Gabriela Example – Example Corp | LinkedIn", {"name": "Gabriela Example", "role": None, "org": "Example Corp"}),
    ("Bob Example | LinkedIn", {"name": "Bob Example", "role": None, "org": None}),
    ("12345 - LinkedIn", None), (None, None)])
def test_parse_linkedin_title(title, expect):
    assert P.parse_linkedin_title(title) == expect


@pytest.mark.parametrize("role,dept", [
    ("Analista de Segurança da Informação", "security"), ("CISO", "security"), ("Diretor Financeiro", "executive"),
    ("Software Engineer", "engineering"), ("Analista de RH", "hr"), ("Executivo de Contas", "sales"),
    ("Coordenador de TI", "it"), ("Advogada", "legal"), ("Contador", "finance"), ("", "other"), (None, "other")])
def test_department_of(role, dept):
    assert P.department_of(role) == dept


def test_aggregate_xray_counts_only_company_profiles():
    st, h, body = env("employee_xray__brave_ok_synthetic.http.json")
    agg = P.aggregate_xray(P.parse_brave_web(body)["results"], "Example Corp")
    assert agg["label"] == "social-engineering exposure (aggregate)"
    assert agg["profiles"] == 7  # duplicate, other employer, company page and non-LinkedIn URL excluded
    assert agg["by_department"] == {"engineering": 1, "executive": 1, "hr": 1, "it": 1, "other": 1, "sales": 1,
                                    "security": 1}
    assert len(agg["sample_names"]) == 7 and "Henrique Exemplo" not in agg["sample_names"]
    assert agg["pivots"] == [] and agg["emails"] == [] and agg["auto_check"] is False
    assert "snippet" not in json.dumps(agg)


def test_aggregate_xray_sample_cap_and_empty():
    res = [{"url": f"https://br.linkedin.com/in/p{i}", "title": f"Pessoa Exemplo{i} - Analista - Example Corp"}
           for i in range(15)]
    agg = P.aggregate_xray(res, "Example Corp", max_samples=50)
    assert agg["profiles"] == 15 and len(agg["sample_names"]) == 10
    empty = P.parse_brave_web(env("employee_xray__brave_empty_synthetic.http.json")[2])
    assert empty["results"] == [] and P.aggregate_xray(empty["results"], "Example Corp")["profiles"] == 0


def test_export_view_strips_names_unless_include_personal():
    agg = P.aggregate_xray([{"url": "https://br.linkedin.com/in/a", "title": "Ana Exemplo - TI - Example Corp"}],
                           "Example Corp")
    out = P.export_view(agg)
    assert "sample_names" not in out and out["personal_included"] is False and out["profiles"] == 1
    assert P.export_view(agg, include_personal=True)["sample_names"] == ["Ana Exemplo"]


def test_sample_expiry_first_of_window_and_retention():
    t0 = "2026-11-26T12:00:00Z"
    assert P.sample_expiry(t0, retention_days=30, window_end="2026-12-01T00:00:00Z").isoformat() == \
        "2026-12-01T00:00:00+00:00"
    assert P.sample_expiry(t0, retention_days=3, window_end="2026-12-31T00:00:00Z").isoformat() == \
        "2026-11-29T12:00:00+00:00"
    assert P.sample_expiry("bad", retention_days=3) is None


# ---------------------------------------------------------------------------------------------- defensiveness

JUNK = [None, 42, 3.5, True, b"\xff\xfe", "", "<html><title>x</title></html>", [], {}, [1, "a"], {"a": None}]


@pytest.mark.parametrize("junk", JUNK, ids=repr)
def test_functions_never_raise(junk):
    for fn in (P.json_body, P.html_title, P.hibp_names, P.hibp_catalog_index, P.hibp_catalog_facts,
               P.parse_brave_web, P.parse_ddg, P.parse_marginalia, P.parse_tavily, P.parse_exa, P.domain_value,
               P.person_name_value, P.parse_fediverse_handle, P.hibp_breach_url, P.query_problem,
               P.parse_linkedin_title, P.department_of, P.profile_key, P.clean_text, P.enc_q, P.refused_host):
        fn(junk)
    P.lower_headers(junk)
    P.meta_content(junk, "og:title")
    P.classify_check("email_format", junk, junk, junk, "example.com")
    P.classify_search_response("brave", junk, junk, junk)
    P.x402_offer(junk, junk, junk)
    P.challenge_marker(junk, junk, junk)
    P.link_view(junk, "domain", junk)
    P.lint_link(junk, pack="email", host_tiers=TIERS)
    P.lint_pack(junk, host_tiers=TIERS)
    P.aggregate_xray(junk if isinstance(junk, list) else [], junk)
    P.xray_gate(junk, junk, org_profile=junk, scope=junk, now="2026-11-26T00:00:00Z")
    P.doctor_links(junk if isinstance(junk, list) else [], "2026-11-26")
    P.skip_already_linked(junk if isinstance(junk, list) else [], junk if isinstance(junk, list) else [])
