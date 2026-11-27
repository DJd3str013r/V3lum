"""Offline tests for batch p3-G14-2 (P308 pivots_search). Run:
cd code && python3 -m pytest -q -p no:cacheprovider .
FCn = final condition n of P308 (specs/p3-G14-2.md)."""
import json
import re
from datetime import date
from pathlib import Path

import pytest

import parsers as P

FIX = Path(__file__).parent.parent / "fixtures"
TIERS = {"lyzem.com": "unknown", "search.wikileaks.org": "community"}
TIERS_PROMOTED = {"lyzem.com": "community", "search.wikileaks.org": "community"}


def load_json(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def load_text(name):
    return (FIX / name).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def pack():
    return load_json("pivots_search__pack_draft.json")


@pytest.fixture(scope="module")
def pending():
    return load_json("pivots_search__pending_after_tier_review.json")


@pytest.fixture(scope="module")
def registry():
    return load_json("pivots_search__registry_draft.json")


def link_by_id(pk, lid):
    return next(lk for lk in pk["links"] if lk["id"] == lid)


# ----------------------------------------------------------------------------------------------------
# FC1 - pack schema
# ----------------------------------------------------------------------------------------------------

def test_fc1_pack_lints_clean_with_registry_tiers(pack, registry):
    tiers = {}
    for prov in registry["providers"]:
        for h in prov["fragment"]["hosts"]:
            tiers[h] = prov["fragment"]["tier"]
    assert tiers == TIERS
    assert P.lint_pack(pack, host_tiers=tiers) == []


def test_fc1_frozen_fields_present_and_publishes_false(pack):
    assert pack["schema"] == P.PACK_SCHEMA and pack["pack"] == "search"
    for lk in pack["links"]:
        for k in P.REQUIRED_LINK_KEYS:
            assert k in lk
        assert lk["publishes"] is False and lk["login_required"] is False and lk["touches_target"] is False
        assert set(lk) <= set(P.FROZEN_LINK_KEYS) | set(P.EXTENSION_LINK_KEYS)


def test_fc1_pack_is_offline_no_network_host_beyond_link_hosts(pack):
    # the pack only names the two link hosts; V3LUM itself requests nothing (disclosure 'none')
    assert {lk["host"] for lk in pack["links"]} == set(P.PACK_HOSTS)


# ----------------------------------------------------------------------------------------------------
# FC3 - rendering through whitelisted encoders, sample and hostile values
# ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("case", load_json("pivots_search__render_golden.json")["cases"],
                         ids=lambda c: f"{c['link']}-{c['etype']}-{c['value'][:20]!r}")
def test_fc3_render_golden(case, pack, pending):
    src = pending if case.get("pending") else pack
    lk = link_by_id(src, case["link"])
    assert P.render_link(lk, case["etype"], case["value"]) == case["url"]
    if case["url"]:
        assert P.check_rendered_url(case["url"], lk["template"], lk["host"]) == []


def _all_links(pack, pending):
    return pack["links"] + pending["links"]


def test_fc3_every_template_renders_a_sample_per_declared_type(pack, pending):
    samples = {"domain": "example.com", "keyword": "golpe pix", "company_name": "Banco do Brasil",
               "person_name": "Fulano de Tal", "username": "example_user", "url": "https://example.com/"}
    for lk in _all_links(pack, pending):
        for et in lk["entity_types"]:
            url = P.render_link(lk, et, samples[et])
            assert url and url.startswith("https://" + lk["host"] + "/"), (lk["id"], et)
            assert P.check_rendered_url(url, lk["template"], lk["host"]) == []


def test_fc3_hostile_values_never_escape_the_declared_host(pack, pending):
    values = load_json("pivots_search__hostile_values.json")["values"]
    rendered = refused = 0
    for lk in _all_links(pack, pending):
        for et in lk["entity_types"]:
            for v in values:
                url = P.render_link(lk, et, v)
                if url is None:
                    refused += 1
                    continue
                rendered += 1
                assert P.check_rendered_url(url, lk["template"], lk["host"]) == [], (lk["id"], et, v, url)
                assert "\n" not in url and "\r" not in url and " " not in url
    assert rendered > 20 and refused > 20


def test_fc3_never_str_format(pack):
    # a value that looks like a format field stays inert text
    lk = link_by_id(pack, "wikileaks_search")
    assert P.render_link(lk, "keyword", "{0}{q}") == "https://search.wikileaks.org/?query=%7B0%7D%7Bq%7D"
    assert P.template_problems("https://search.wikileaks.org/?query={0}", "search.wikileaks.org", ["keyword"])


def test_fc3_template_checks_reject_bad_templates():
    tp = P.template_problems
    assert "not https" in tp("http://lyzem.com/search?q={q}", "lyzem.com", ["keyword"])
    assert any("placeholder in scheme/host" in x for x in tp("https://{q}/search", "lyzem.com", ["keyword"]))
    assert any("{raw}" in x for x in tp("https://lyzem.com/search?q={raw}", "lyzem.com", ["keyword"]))
    assert any("fragment" in x for x in tp("https://lyzem.com/search#q={q}", "lyzem.com", ["keyword"]))
    assert any("not an encoder of this pack" in x for x in tp("https://lyzem.com/s?q={b64}", "lyzem.com", ["keyword"]))
    assert tp("https://lyzem.com/search?q={domain}", "lyzem.com", ["domain"]) == []


def test_fc3_check_rendered_url_detects_injection():
    t = "https://search.wikileaks.org/?query={q}"
    h = "search.wikileaks.org"
    assert P.check_rendered_url("https://search.wikileaks.org/?query=a&x=1", t, h) == ["query parameters changed"]
    assert "host/userinfo/port changed" in P.check_rendered_url("https://evil.example/?query=a", t, h)
    assert "path changed" in P.check_rendered_url("https://search.wikileaks.org/x?query=a", t, h)
    assert "whitespace/control character in URL" in P.check_rendered_url(
        "https://search.wikileaks.org/?query=a b", t, h)
    assert "fragment added" in P.check_rendered_url("https://search.wikileaks.org/?query=a#b", t, h)


def test_fc3_encoders():
    assert P.enc_q("a b/c") == "a%20b%2Fc"
    assert P.enc_qp("a b") == "a+b"
    assert P.enc_q("..") is None and P.enc_q(None) is None and P.enc_q(3) is None
    assert P.domain_value("Bücher.Example.") == "xn--bcher-kva.example"
    assert P.domain_value("a..example") is None and P.domain_value(b"example.com") is None


# ----------------------------------------------------------------------------------------------------
# FC8 / P311 cond 6 - personal values in free text never render
# ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("value,reason", [
    ("golpe 123.456.789-00", "cpf"), ("00000000191", "cpf"), ("contato analyst@example.com", "email"),
    ("+55 11 5555-0123", "phone"), ("(11) 95555-0123", "phone"),
])
def test_fc8_personal_marker(value, reason):
    assert P.personal_marker(value) == reason


@pytest.mark.parametrize("value", ["CVE-2021-44228", "Banco do Brasil", "golpe pix", "2021 2022",
                                   "00000000190", "d41d8cd98f00b204e9800998ecf8427e", "AS13335", None, 5])
def test_fc8_personal_marker_negative(value):
    assert P.personal_marker(value) is None


# ----------------------------------------------------------------------------------------------------
# FC4, FC5, FC8, FC9, FC10 - lint
# ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("case", load_json("pivots_search__lint_bad_entries.json")["cases"], ids=lambda c: c["case"])
def test_lint_rejects_bad_entries(case):
    tiers = case["host_tiers"] or load_json("pivots_search__lint_bad_entries.json")["default_host_tiers"]
    problems = P.lint_link(case["link"], host_tiers=tiers)
    assert problems, case["case"]
    assert any(case["expect"] in p for p in problems), (case["case"], problems)


def test_fc4_fc9_pending_entries_rejected_while_lyzem_unknown(pending):
    for lk in pending["links"]:
        assert P.lint_link(lk, host_tiers=TIERS), lk["id"]


def test_fc5_fc9_pending_entries_pass_once_promoted(pack, pending):
    for lk in pending["links"]:
        assert P.lint_link(lk, host_tiers=TIERS_PROMOTED) == [], lk["id"]
    merged = P.activate_pending(pack, pending, TIERS_PROMOTED)
    assert [lk["id"] for lk in merged["links"]] == [
        "lyzem_telegram_domain", "lyzem_telegram_search", "lyzem_telegram_subject", "wikileaks_search"]
    assert P.lint_pack(merged, host_tiers=TIERS_PROMOTED) == []
    assert P.activate_pending(pack, pending, TIERS) is pack  # unknown tier: unchanged


def test_fc4_pack_fails_when_a_host_has_no_registry_entry(pack):
    problems = P.lint_pack(pack, host_tiers={"search.wikileaks.org": "community"})
    assert any("no provider-registry entry (FC4)" in p for p in problems)


def test_fc6_lint_enforces_file_order(pack):
    swapped = dict(pack, links=list(reversed(pack["links"])))
    assert "file order must be Lyzem entries, then WikiLeaks (FC6)" in P.lint_pack(swapped, host_tiers=TIERS)


def test_fc1_lint_pack_shape_errors():
    assert P.lint_pack([], host_tiers=TIERS) == ["pack is not an object"]
    probs = P.lint_pack({"schema": "x", "pack": "other", "links": []}, host_tiers=TIERS)
    assert "schema must be v3lum.pivot_pack/1" in probs and "links must be a non-empty list" in probs
    assert P.lint_link("nope", host_tiers=TIERS) == ["entry is not an object"]
    assert any("missing template" in p for p in P.lint_link({"id": "x"}, host_tiers=TIERS))


def test_fc8_wikileaks_banner_and_types(pack):
    wl = link_by_id(pack, "wikileaks_search")
    assert wl["warning"] == P.WIKILEAKS_BANNER == "leaked documents: open manually and handle per policy"
    assert set(wl["entity_types"]) == {"company_name", "keyword"}
    assert P.render_link(wl, "person_name", "Fulano de Tal") is None
    assert P.render_link(wl, "username", "example_user") is None


def test_fc9_lyzem_pre_review_is_ioc_only(pack):
    ly = link_by_id(pack, "lyzem_telegram_domain")
    assert set(ly["entity_types"]) <= P.LYZEM_PRE_REVIEW_TYPES
    assert set(ly["entity_types"]) <= P.IOC_TYPES


def test_fc10_every_link_seed_only_with_caution(pack, pending):
    for lk in _all_links(pack, pending):
        assert lk["seed_only"] is True and lk["warning"].strip()


# ----------------------------------------------------------------------------------------------------
# FC2, FC4, FC9, FC10 - the A2/P311 view
# ----------------------------------------------------------------------------------------------------

def test_fc2_green_clickable_amber_text_with_disclosure(pack):
    wl = link_by_id(pack, "wikileaks_search")
    g = P.link_view(wl, "company_name", "Banco do Brasil", tlp="green", host_tier="community")
    assert g["where"] == "report" and g["clickable"] and g["text"] == g["url"]
    a = P.link_view(wl, "company_name", "Banco do Brasil", tlp="TLP:AMBER", host_tier="community")
    assert a["where"] == "report" and not a["clickable"]
    assert a["disclosure"] == "opening sends Banco do Brasil to search.wikileaks.org"
    assert a["text"].startswith("hxxps://search[.]wikileaks.org/") and a["disclosure"] in a["text"]
    s = P.link_view(wl, "company_name", "Banco do Brasil", tlp="amber+strict", host_tier="community")
    assert s["where"] == "report" and not s["clickable"]


def test_fc2_red_links_only_with_warning(pack):
    wl = link_by_id(pack, "wikileaks_search")
    r = P.link_view(wl, "keyword", "golpe pix", tlp="red", host_tier="community")
    assert r["where"] == "links_only" and not r["clickable"] and r["reason"] == "tlp_red"
    assert P.RED_WARNING in r["warnings"]


def test_fc2_default_tlp_is_amber(pack):
    wl = link_by_id(pack, "wikileaks_search")
    v = P.link_view(wl, "keyword", "golpe pix", tlp="bogus", host_tier="community")
    assert not v["clickable"]


@pytest.mark.parametrize("tlp,tty,confirmed,expected", [
    ("green", False, None, "open"), ("amber", False, "search.wikileaks.org", "refuse"),
    ("amber", True, None, "ask"), ("amber", True, "lyzem.com", "ask"),
    ("amber", True, "search.wikileaks.org", "open"), ("red", True, "search.wikileaks.org", "open"),
])
def test_fc2_open_decision(pack, tlp, tty, confirmed, expected):
    wl = link_by_id(pack, "wikileaks_search")
    v = P.link_view(wl, "keyword", "golpe pix", tlp=tlp, host_tier="community")
    assert P.open_decision(v, tlp, tty=tty, confirmed_host=confirmed) == expected
    assert P.open_decision({}, "green", tty=True) == "refuse"


def test_fc8_fc10_caution_marker_and_banner_in_view(pack):
    wl = link_by_id(pack, "wikileaks_search")
    v = P.link_view(wl, "keyword", "golpe pix", tlp="amber", host_tier="community")
    assert P.BADGE_CAUTION in v["badges"] and P.WIKILEAKS_BANNER in v["warnings"]
    ly = link_by_id(pack, "lyzem_telegram_domain")
    v = P.link_view(ly, "domain", "example.com", tlp="amber", host_tier="unknown")
    assert P.BADGE_CAUTION in v["badges"] and P.BADGE_UNKNOWN_OPERATOR in v["badges"]
    assert P.LYZEM_WARNING in v["warnings"]


def test_fc10_pivots_and_extracted_values_get_no_link(pack):
    wl = link_by_id(pack, "wikileaks_search")
    for prov in ("pivot", "extracted", "qsa_partner"):
        v = P.link_view(wl, "company_name", "Banco do Brasil", provenance=prov, host_tier="community")
        assert v["where"] == "hidden" and v["reason"] == "seed_only" and v["url"] is None


def test_fc4_unknown_tier_view_refuses_free_text_even_if_pack_misdeclares():
    bad = {"id": "x", "template": "https://lyzem.com/search?q={q}", "entity_types": ["keyword"], "host": "lyzem.com",
           "seed_only": True, "warning": "w"}
    v = P.link_view(bad, "keyword", "golpe pix", host_tier="unknown")
    assert v["where"] == "hidden" and v["reason"] == "tier"


def test_fc9_subject_link_needs_seed_opt_in_and_purpose(pending):
    subj = link_by_id(pending, "lyzem_telegram_subject")
    kw = {"tlp": "amber", "host_tier": "community"}
    assert P.link_view(subj, "person_name", "Fulano de Tal", **kw)["reason"] == "privacy_opt_in"
    assert P.link_view(subj, "person_name", "Fulano de Tal", privacy_opt_in=True, **kw)["reason"] == "privacy_opt_in"
    v = P.link_view(subj, "person_name", "Fulano de Tal", privacy_opt_in=True, purpose="case 42 fraud", **kw)
    assert v["where"] == "report" and P.BADGE_PRIVACY in v["badges"]
    v = P.link_view(subj, "person_name", "Fulano de Tal", privacy_opt_in=True, purpose="x", display="F*** d* T**", **kw)
    assert v["disclosure"] == "opening sends F*** d* T** to lyzem.com"
    hidden = P.link_view(subj, "username", "example_user", provenance="pivot", privacy_opt_in=True, purpose="x", **kw)
    assert hidden["where"] == "hidden"
    # while lyzem.com is unknown tier the subject link never shows, opt-in or not
    v = P.link_view(subj, "person_name", "Fulano de Tal", privacy_opt_in=True, purpose="x", host_tier="unknown")
    assert v["reason"] == "tier"


# ----------------------------------------------------------------------------------------------------
# FC6 - ordering and terminal cap
# ----------------------------------------------------------------------------------------------------

def test_fc6_order_lyzem_then_wikileaks_and_cap(pack, pending):
    merged = P.activate_pending(pack, pending, TIERS_PROMOTED)
    views = [P.link_view(lk, "keyword", "golpe pix", tlp="amber", host_tier="community") for lk in merged["links"]]
    term, rest = P.order_views(views)
    assert [v["ref"] for v in term] == ["lyzem_telegram_search", "wikileaks_search"] and rest == []
    many = [dict(views[-1], ref=f"r{i}", verified=(i % 2 == 0)) for i in range(11)]
    term, rest = P.order_views(many)
    assert len(term) == 8 and len(rest) == 3
    assert all(v["verified"] for v in term[:6]) and not term[6]["verified"]


# ----------------------------------------------------------------------------------------------------
# FC7 - doctor --links
# ----------------------------------------------------------------------------------------------------

def test_fc7_doctor_links(pack):
    assert P.doctor_links([pack], date(2026, 11, 26)) == []
    assert P.doctor_links([pack], date(2027, 5, 25)) == []  # 180 days: still fine
    stale = P.doctor_links([pack], date(2027, 5, 26))
    assert [d["ref"] for d in stale] == ["search:lyzem_telegram_domain", "search:wikileaks_search"]
    assert stale[0]["age_days"] == 181
    unver = dict(pack, links=[dict(pack["links"][0], verified=False), dict(pack["links"][1], checked_at="soon")])
    reasons = [d["reason"] for d in P.doctor_links([unver], date(2026, 11, 26))]
    assert reasons == ["unverified", "bad checked_at"]


# ----------------------------------------------------------------------------------------------------
# FC7 re-check evidence - live page fixtures
# ----------------------------------------------------------------------------------------------------

def test_recheck_lyzem_ok():
    body = load_text("pivots_search__lyzem_ok.html")
    facts = P.parse_lyzem_results(body)
    assert facts["query"] == "example.com" and facts["results_total"] == 38 and facts["took_ms"] == 56
    assert facts["items"] == 3 and facts["item_types"] == {"post": 1, "article": 2} and facts["complete"]
    r = P.classify_check("lyzem", 200, {"content-type": "text/html; charset=utf-8"}, body, "example.com")
    assert r["verdict"] == "ok" and r["reason"] == "38 results"


def test_recheck_lyzem_space_encoding_echo():
    body = load_text("pivots_search__lyzem_space_encoding_ok.html")
    r = P.classify_check("lyzem", 200, {}, body, "CVE-2021-44228 log4j")
    assert r["verdict"] == "ok" and r["facts"]["results_total"] == 235004


def test_recheck_lyzem_url_is_tokenised_noise():
    body = load_text("pivots_search__lyzem_url_tokenised_noise.html")
    f = P.parse_lyzem_results(body)
    assert f["query"] == "https://example.com/" and f["results_total"] == 1835042
    assert f["with_profile"] == 1 and f["item_types"] == {"channel": 1, "article": 1}


def test_recheck_lyzem_empty():
    r = P.classify_check("lyzem", 200, {}, load_text("pivots_search__lyzem_empty.html"), "zqxvkjw9183pt")
    assert r["verdict"] == "empty" and r["facts"]["items"] == 0 and r["facts"]["results_total"] == 0


def test_recheck_lyzem_mismatch_when_echo_differs():
    r = P.classify_check("lyzem", 200, {}, load_text("pivots_search__lyzem_ok.html"), "example.org")
    assert r["verdict"] == "mismatch"


@pytest.mark.parametrize("name", ["pivots_search__lyzem_malformed_truncated.html",
                                  "pivots_search__lyzem_malformed_no_count.html"])
def test_recheck_lyzem_malformed(name):
    r = P.classify_check("lyzem", 200, {}, load_text(name), "example.com")
    assert r["verdict"] == "malformed"


def test_recheck_not_found_envelopes():
    for name, src in (("pivots_search__lyzem_not_found_404.http.json", "lyzem"),
                      ("pivots_search__wikileaks_not_found_404.http.json", "wikileaks")):
        st, hd, body = P.parse_envelope(load_text(name))
        assert st == 404
        assert P.classify_check(src, st, hd, body)["verdict"] == "not_found"


def test_recheck_wikileaks_ok_counts_only():
    body = load_text("pivots_search__wikileaks_ok.html")
    f = P.parse_wikileaks_results(body)
    assert f["query"] == "Banco do Brasil" and f["results_total"] == 9196 and f["items"] == 2
    assert f["leak_totals"] == {"Global Intelligence Files": 4879, "Sony": 4076, "Sony Documents": 4076}
    # FC8 / rule 3: no document title, excerpt or link is extracted
    assert "FIXTURE DOCUMENT" not in json.dumps(f) and "plusd/cables" not in json.dumps(f)
    r = P.classify_check("wikileaks", 200, {}, body, "Banco do Brasil")
    assert r["verdict"] == "ok" and r["reason"] == "9196 results"


def test_recheck_wikileaks_empty():
    r = P.classify_check("wikileaks", 200, {}, load_text("pivots_search__wikileaks_empty.html"), "CVE-2021-44228")
    assert r["verdict"] == "empty" and r["facts"]["no_filters"] and r["facts"]["leak_totals"] == {}


def test_recheck_wikileaks_hostile_echo_decoded():
    body = load_text("pivots_search__wikileaks_hostile_quotes_unicode_ok.html")
    r = P.classify_check("wikileaks", 200, {}, body, "\"Ação\" example")
    assert r["verdict"] == "ok" and r["facts"]["results_total"] == 52
    assert r["facts"]["query"] == "\"Ação\" example"


def test_recheck_wikileaks_malformed():
    r = P.classify_check("wikileaks", 200, {}, load_text("pivots_search__wikileaks_malformed_truncated.html"),
                         "Banco do Brasil")
    assert r["verdict"] == "malformed"


# markers that were NOT observed live on 2026-11-26 (no fixture invented): inline samples

@pytest.mark.parametrize("src,status,headers,body,verdict", [
    ("lyzem", 429, {"Retry-After": "60"}, "", "rate_limited"),
    ("wikileaks", 403, {"cf-mitigated": "challenge"}, "<title>Just a moment...</title>", "challenge"),
    ("lyzem", 200, {}, '<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/x"></script>',
     "challenge"),
    ("lyzem", 302, {"Location": "https://lyzem.com/login?next=/search"}, "", "login_wall"),
    ("wikileaks", 301, {"Location": "https://wikileaks.org/"}, "", "redirect"),
    ("wikileaks", 502, {}, "<html>bad gateway</html>", "error"),
    ("lyzem", 200, {}, '{"error": "maintenance"}', "error_in_200"),
    ("wikileaks", 200, {}, "<html><title>Maintenance</title></html>", "error_in_200"),
    ("lyzem", 200, {}, "", "error_in_200"),
    ("lyzem", 200, {}, b"\xff\xfe\x00garbage", "error_in_200"),
    ("other", 200, {}, "<title>x</title>", "error"),
    ("lyzem", "200", {}, "", "error"),
])
def test_recheck_markers(src, status, headers, body, verdict):
    assert P.classify_check(src, status, headers, body)["verdict"] == verdict


def test_rate_limit_marker_reason():
    assert P.rate_limit_marker(429, {"retry-after": "30"}) == "rate_limited: retry after 30"
    assert P.rate_limit_marker(200, {}) is None


def test_parsers_defensive_on_garbage():
    for fn in (P.parse_lyzem_results, P.parse_wikileaks_results):
        for junk in (None, "", b"", 42, "<html>", "{}", "<p class=\"is-size-6\"> many results - fast ms</p>"):
            out = fn(junk)
            assert out["results_total"] is None and out["items"] == 0 and not out["complete"]
    assert P.parse_envelope("not json") == (-1, {}, "")
    assert P.parse_envelope({"status": "404", "headers": [], "body": 3}) == (-1, {}, "")


def test_fixtures_hold_no_personal_data_or_secrets():
    personal = re.compile(r"(?i)(\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|set-cookie|cookie:|authorization:|api[_-]?key)")
    handle = re.compile(r"https://t\.me/(?!example_)[A-Za-z0-9_]+")
    for path in FIX.iterdir():
        text = path.read_text(encoding="utf-8")
        if path.name in ("pivots_search__render_golden.json", "pivots_search__lint_bad_entries.json"):
            continue  # hold synthetic CPF-shaped test values on purpose (refused by the guard)
        assert not personal.search(text), path.name
        assert not handle.search(text), path.name
        assert "@" not in re.sub(r"(?i)[a-z0-9._%+-]+@example\.(com|org)", "", text) or path.suffix == ".json", path.name
