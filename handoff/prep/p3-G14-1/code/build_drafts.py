"""Write the authored drafts of batch p3-G14-1 into fixtures/ (run with python3 -I code/build_drafts.py).

Pack drafts (data/pivot_links/<pack>.json, schema v3lum.pivot_pack/1), provider-registry drafts
(v3lum.provider/1 fragments, each marked new / extend / exists), lint-must-fail entries and render vectors.
Nothing here is downloaded data.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "fixtures")
D = "2026-11-26"


def write(name, obj):
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    print(name)


def link(**kw):
    base = {"privacy": False, "publishes": False, "touches_target": False, "login_required": False,
            "antibot": False, "verified": True, "checked_at": D}
    base.update(kw)
    order = ("id", "label", "template", "entity_types", "category", "host", "verified", "checked_at", "privacy",
             "publishes", "touches_target", "login_required", "antibot", "max_tlp", "notes")
    return {k: base[k] for k in order if k in base}


EMAIL_PACK = {"schema": "v3lum.pivot_pack/1", "pack": "email", "title": "E-mail: corporate address pattern",
              "links": [link(
                  id="email_format_domain",
                  label="Email Format (email-format.com): corporate address pattern: use the pattern, never the "
                        "sample people",
                  template="https://www.email-format.com/d/{domain}/", entity_types=["domain"], category="company",
                  host="www.email-format.com",
                  notes="P098. Verified 2026-11-26: /d/example.com/ and /d/nic.br/ answer 200 titled 'Email Address "
                        "Format for <domain> (<Name>)'; unknown domains 302 to /i/main/; the apex host 301s to www "
                        "(template uses www). company_name entities get this link only through a known domain "
                        "(P098 FC8). The page lists sample addresses of real people: V3LUM never fetches, scrapes "
                        "or ingests it (FC1, FC9). Never link /m/export_xlsx (exports the addresses).")]}

SOCIAL_PACK = {"schema": "v3lum.pivot_pack/1", "pack": "username_social",
               "title": "Social profiles: Bluesky and Mastodon",
               "links": [
                   link(id="bluesky_profile",
                        label="Bluesky profile (bsky.app): same handle does not prove identity",
                        template="https://bsky.app/profile/{bsky_handle}", entity_types=["bsky_handle", "username"],
                        category="social", host="bsky.app", privacy=True,
                        notes="P125 FC8: domain-style handles only ({bsky_handle} refuses bare usernames and DIDs). "
                              "Verified 2026-11-26: /profile/bsky.app 200 titled '@bsky.app on Bluesky' with "
                              "og:title and the account DID; handles are case-insensitive (/profile/BSKY.APP same "
                              "page); an unresolvable handle answers a 200 app shell titled 'Bluesky' without "
                              "og:title (soft 404)."),
                   link(id="bluesky_profile_bsky_social",
                        label="Bluesky profile, guessed <user>.bsky.social handle: same handle does not prove "
                              "identity",
                        template="https://bsky.app/profile/{bsky_social}", entity_types=["username"],
                        category="social", host="bsky.app", privacy=True,
                        notes="P125 FC8: bare usernames only through the vetted {bsky_social} placeholder "
                              "(3-18 chars of [a-z0-9-]) and only for analyst-typed seeds (privacy=true). Same "
                              "/profile/ route as bluesky_profile (verified 2026-11-26); the handle is a guess."),
                   link(id="mastodon_social_profile",
                        label="Mastodon profile (mastodon.social): same handle does not prove identity",
                        template="https://mastodon.social/@{fedi_user}", entity_types=["fediverse_handle"],
                        category="social", host="mastodon.social", privacy=True,
                        notes="P125 FC9: full fediverse handles @user@mastodon.social only ({fedi_user} renders "
                              "only when the handle's instance equals this host). Verified 2026-11-26: @Mastodon 200 "
                              "titled 'Mastodon (@Mastodon@mastodon.social) - Mastodon.social', case-insensitive; "
                              "unknown handle 404; deleted/suspended handles 410. Add other allow-listed instances "
                              "as separate entries with their own registry host (trusted/community only).")]}

PERSON_PACK = {"schema": "v3lum.pivot_pack/1", "pack": "person", "title": "Person web presence (opt-in)",
               "links": [link(
                   id="webmii_people", label="Webmii (webmii.com): people search engine - homonyms likely",
                   template="https://webmii.com/people?n={q}", entity_types=["person_name"], category="social",
                   host="webmii.com", privacy=True, max_tlp="clear",
                   notes="P257. Verified 2026-11-26 with a company name (rules forbid real people): "
                         "/people?n=Banco%20do%20Brasil 200 titled 'Webmii - Banco Do Brasil'; results load "
                         "client-side. Opening the page also loads Google Tag Manager, Google Custom Search and the "
                         "Facebook SDK, which receive the page URL with the name. A8 gate (FC4): the operator is an "
                         "individual developer with no terms page; if the reviewer records 'unknown' this entry is "
                         "removed (unknown operators never receive person names).")]}

PACKS = {"pivots_email": EMAIL_PACK, "pivots_username_social": SOCIAL_PACK, "pivots_person": PERSON_PACK}
for mod, pack in PACKS.items():
    write(f"{mod}__pack_draft.json", pack)

HOST_TIERS = {"www.email-format.com": "community", "bsky.app": "community", "mastodon.social": "community",
              "webmii.com": "community", "haveibeenpwned.com": "trusted"}
write("host_tiers_draft.json", {"_note": "tiers proposed by the final conditions (registry reviewer to confirm); "
                                         "evidence in notes.md suggests 'unknown' for webmii.com and possibly "
                                         "for www.email-format.com", "tiers": HOST_TIERS})


def terms(cls, url, quote, free_business):
    return {"class": cls, "evidence_url": url, "quote": quote, "checked_at": D, "reviewer": "pending (legal)",
            "free_plan_business_use": free_business}


def fragment(pid, name, operator, hosts, tier, rationale, flags, grade, why, profile, sources, keys=None,
             quota=None, markers=None):
    return {"schema": "v3lum.provider/1", "id": pid, "name": name, "operator": operator, "hosts": hosts,
            "hosts_from_settings": [], "internal": False, "tier": tier, "tier_rationale": rationale,
            "tier_reviewer": "pending (registry reviewer)", "tier_date": D,
            "flags": dict(zip(("publishes_queries", "reuses_queries", "fetches_target", "sensitive"), flags)),
            "personal_data_review": None, "reliability": {"grade": grade, "justification": why},
            "http_profile": profile, "quota": quota, "error_markers": markers or [], "keys": keys or {},
            "sources": sources}


def src(title, t, notes):
    return {"title": title, "terms": t, "upstream_family": None, "sanitizer": None, "dataset": None, "notes": notes}


LINK_PROFILE = {"user_agent": None, "ttl": 0}
write("pivots_email__registry_draft.json", {"entries": [{"action": "new", "fragment": fragment(
    "email_format", "Email Format (email-format.com)",
    "not named on the site (privacy policy effective 2018-09-07 names no legal entity; contact by web form; US "
    "servers)", ["www.email-format.com", "email-format.com"], "community",
    "P098 FC5 proposes community. Evidence 2026-11-26: >= 2 years (policy dated 2018), public privacy policy, no "
    "identifiable operator, a commented-out RocketReach og: block in the page template. A8 asks an identifiable "
    "operator for community: the reviewer may record 'unknown' (the link stays: domain is an IOC type, with the "
    "'unknown operator' badge).",
    (False, False, False, False), "D", "aggregated pattern guesses with percentages; manual use only",
    LINK_PROFILE, {"pattern_page": src("Corporate e-mail address pattern page /d/{domain}/ (manual link only)",
                                       terms("open", "https://www.email-format.com/i/privacy_policy/",
                                             "manual link only: V3LUM never requests the page", None),
                                       "Pack email.json; disclosure none (links are never fetched).")})}]})
write("pivots_username_social__registry_draft.json", {"entries": [
    {"action": "new", "fragment": fragment(
        "bluesky", "Bluesky (bsky.app web app)", "Bluesky Social PBC", ["bsky.app"], "community",
        "P125 FC5 (community, Bluesky PBC). Identifiable company with published terms and privacy policy since "
        "2023; the reviewer could also justify trusted.", (False, False, False, False), "C",
        "profile pages render server-side OG metadata for existing handles", LINK_PROFILE,
        {"profile_page": src("Profile page /profile/{handle} (manual link only)",
                             terms("open", "https://bsky.social/about/support/tos", "manual link only", None),
                             "Pack username_social.json")})},
    {"action": "new", "fragment": fragment(
        "mastodon_social", "Mastodon.social (flagship Mastodon instance)", "Mastodon gGmbH", ["mastodon.social"],
        "community", "P125 FC5 (community, Mastodon gGmbH): identifiable non-profit operator, server rules and "
                     "privacy policy, running since 2016.", (False, False, False, False), "C",
        "profile pages are server-rendered; 404 unknown, 410 deleted/suspended", LINK_PROFILE,
        {"profile_page": src("Profile page /@{user} (manual link only)",
                             terms("open", "https://mastodon.social/terms", "manual link only", None),
                             "Pack username_social.json; the curated instance allow-list of P125 FC9 is the set "
                             "of pack entries whose host is trusted/community here.")})}]})
write("pivots_person__registry_draft.json", {"entries": [{"action": "new", "fragment": fragment(
    "webmii", "Webmii (people search mash-up)", "individual developer (App Store seller); no legal entity named",
    ["webmii.com"], "unknown",
    "P257 FC4 requires community (identifiable operator, terms, >= 2 years) before the link ships. Evidence "
    "2026-11-26: no terms page, a 3-sentence privacy statement not linked from the site, App Store seller is a "
    "natural person (A8 'individual operator' = unknown). Recorded here as unknown: the pack entry is dropped "
    "unless the reviewer records community with a rationale.", (False, False, False, False), "E",
    "aggregates third-party search results client-side; homonyms likely", LINK_PROFILE,
    {"people_page": src("People page /people?n={name} (manual link only, opt-in pack)",
                        terms("unknown", "https://webmii.com/privacy", "no terms of use published", None),
                        "Pack person.json (default_enabled false, max_tlp clear).")})}]})
write("pivots_breach_leak__registry_draft.json", {"entries": [{"action": "exists", "provider": "hibp",
                                                              "source": "breach_pages",
                                                              "note": "seeded fragment hibp (tier trusted, sources "
                                                                      "catalog/account/breach_pages); P144 adds "
                                                                      "nothing: confirm the breach_pages source "
                                                                      "carries the CC BY 4.0 attribution text"}]})

ERR = lambda i, st, jp, eq, rx, maps, reason: {"id": i, "statuses": st, "json_path": jp, "equals": eq, "regex": rx,
                                               "final_url_regex": None, "maps_to": maps, "reason_code": maps,
                                               "reason": reason}
write("web_search_api__registry_draft.json", {"entries": [
    {"action": "new", "fragment": fragment(
        "brave_search", "Brave Search API", "Brave Software, Inc.", ["api.search.brave.com"], "trusted",
        "P307 FC5 trusted: established company, own index, published API terms and plans.",
        (False, False, False, False), "B", "first-party index; results are URL/title leads only",
        {"user_agent": "neutral", "accept": "application/json", "timeout": 15, "retries": 0, "ttl": 0,
         "min_interval": 1.0, "concurrency": 1},
        {"web": src("Web search /res/v1/web/search (X-Subscription-Token)",
                    terms("key-terms", "https://brave.com/search/api/",
                          "Search plan US$5 per 1,000 requests incl. US$5 free credits/month; storing results "
                          "needs a custom plan with storage rights", False),
                    "FC6: never cached raw (ttl 0), keep URL+title of selected results only.")},
        keys={"brave_search": {"description": "Brave Search API subscription token (X-Subscription-Token)",
                               "signup_url": "https://brave.com/search/api/", "env": ["V3LUM_BRAVE_KEY"],
                               "multi_key": False,
                               "plan_hint": "company account; business plan recorded in key_plans (FC2)"}},
        quota={"scope": "key", "month": 1000, "rate_per_second": 1, "burst": 1, "published": True,
               "evidence_url": "https://brave.com/search/api/", "safety_margin": 0.8},
        markers=[ERR("brave_quota", [429], "error.code", "QUOTA_LIMITED", None, "quota",
                     "Brave Search: monthly quota/credits exhausted"),
                 ERR("brave_rate", [429], "error.code", "RATE_LIMITED", None, "rate_limited",
                     "Brave Search: rate limited")])},
    {"action": "new", "fragment": fragment(
        "duckduckgo", "DuckDuckGo Instant Answer API", "Duck Duck Go, Inc.", ["api.duckduckgo.com"], "trusted",
        "P307 FC5 trusted: established company with published terms; Instant Answer is context, not web search.",
        (False, False, False, False), "C", "Wikipedia/Wikidata-derived abstracts and infoboxes; often empty",
        {"user_agent": "neutral", "accept": "application/json", "timeout": 10, "retries": 1, "ttl": 86400,
         "min_interval": 1.0, "concurrency": 1},
        {"instant_answer": src("Instant Answer /?q=&format=json&no_html=1&skip_disambig=1",
                               terms("open", "https://duckduckgo.com/duckduckgo-help-pages/open-source/"
                                             "instant-answer-interface/",
                                     "free API with attribution; not a web-search API", True),
                               "Answers HTTP 202 with a complete JSON body (content-type application/x-javascript) "
                               "from this egress; never scrape html.duckduckgo.com.")})},
    {"action": "new", "fragment": fragment(
        "marginalia", "Marginalia Search API", "Marginalia Search (open-source project, Sweden)",
        ["api2.marginalia-search.com"], "community", "P307 FC5 community.", (False, False, False, False), "D",
        "small-web index; sparse", {"user_agent": "neutral", "accept": "application/json", "ttl": 0,
                                    "min_interval": 1.0, "concurrency": 1},
        {"search": src("Search /search?query=&count= (API-Key header)",
                       terms("license", "https://about.marginalia-search.com/article/api/",
                             "free keys: results licensed CC BY-NC-SA 4.0", False),
                       "FC3: off under corporate until a commercial key plan or licence_allow entry.")},
        keys={"marginalia": {"description": "Marginalia API key (API-Key header)", "env": ["V3LUM_MARGINALIA_KEY"],
                             "multi_key": False, "plan_hint": "commercial key only (FC3)"}},
        markers=[ERR("marginalia_daily", [429], None, None, "Daily Limit Exceeded", "quota",
                     "Marginalia: daily limit exceeded")])},
    {"action": "new", "fragment": fragment(
        "tavily", "Tavily Search API", "Tavily (company)", ["api.tavily.com"], "community",
        "P307 FC5 community; terms class unknown until legal records them (FC4).", (False, True, False, False), "D",
        "returns third-party page copies", {"user_agent": "neutral", "ttl": 0, "min_interval": 1.0},
        {"search": src("POST /search (Authorization: Bearer)",
                       terms("unknown", "https://tavily.com/terms", "pending legal review", None),
                       "reuses_queries=true is a conservative placeholder until legal reads the terms.")},
        keys={"tavily": {"description": "Tavily API key (company account)", "env": ["V3LUM_TAVILY_KEY"],
                         "multi_key": False, "plan_hint": "company account; terms recorded by legal (FC4)"}},
        markers=[ERR("tavily_plan_limit", [432, 433], None, None, None, "quota", "Tavily: plan usage limit")])},
    {"action": "new", "fragment": fragment(
        "exa", "Exa Search API", "Exa Labs, Inc.", ["api.exa.ai"], "community",
        "P307 FC5 community; terms class unknown until legal records them (FC4). Keyless calls get an x402 "
        "pay-per-call offer, which V3LUM never accepts.", (False, True, False, False), "D",
        "neural index; returns page contents on request", {"user_agent": "neutral", "ttl": 0, "min_interval": 1.0},
        {"search": src("POST /search (x-api-key)", terms("unknown", "https://exa.ai/terms", "pending legal review",
                                                         None),
                       "HTTP 402 / x402 offer -> NEEDS_KEY in module code (the marker enum has no needs_key).")},
        keys={"exa": {"description": "Exa API key (company account)", "env": ["V3LUM_EXA_KEY"], "multi_key": False,
                      "plan_hint": "company account; never keyless x402 payments (FC4)"}})},
    {"action": "refused", "host": "serpapi.com", "note": "P307 FC1: no registry entry; a unit test asserts no "
                                                         "request ever reaches it"}]})
write("employee_xray__registry_draft.json", {"entries": [{"action": "exists", "provider": "brave_search",
                                                         "source": "web",
                                                         "note": "P289 FC2: automated only through P307's Brave "
                                                                 "source; key V3LUM_BRAVE_KEY (not "
                                                                 "V3LUM_SEARCH_API_KEY); no own provider"}]})

# -------------------------------------------------------------------------- lint entries that must fail
base_email = EMAIL_PACK["links"][0]
base_bsky, base_bsky_social, base_masto = SOCIAL_PACK["links"]
base_person = PERSON_PACK["links"][0]
write("pivots_email__lint_bad_entries.json", {"pack": "email", "cases": [
    {"entry": dict(base_email, host="email-format.com",
                   template="https://email-format.com/d/{domain}/"), "expect": "www host"},
    {"entry": dict(base_email, entity_types=["domain", "company_name"]), "expect": "domain entities only"},
    {"entry": dict(base_email, template="https://www.email-format.com/d/{raw}/"), "expect": "{raw}"},
    {"entry": dict(base_email, label="Email Format"), "expect": "P098 FC9"},
    {"entry": dict(base_email, template="https://www.email-format.com/m/export_xlsx/?domains={domain}"),
     "expect": "export/search/account"},
    {"entry": dict(base_email, publishes=True), "expect": "publishes must be false"},
    {"entry": dict(base_email, verified=True, checked_at=None), "expect": "checked_at"},
    {"entry": dict(base_email, template="http://www.email-format.com/d/{domain}/"), "expect": "not https"}]})
write("pivots_username_social__lint_bad_entries.json", {"pack": "username_social", "cases": [
    {"entry": dict(base_bsky, template="https://bsky.app/profile/{user}"), "expect": "never a raw username"},
    {"entry": dict(base_bsky, privacy=False), "expect": "privacy=true"},
    {"entry": dict(base_bsky, label="Bluesky profile"), "expect": "same handle does not prove identity"},
    {"entry": dict(base_bsky_social, entity_types=["username", "bsky_handle"]), "expect": "username seeds only"},
    {"entry": dict(base_masto, id="mastodon_evil", host="mastodon.evil.example.org",
                   template="https://mastodon.evil.example.org/@{fedi_user}"), "expect": "trusted/community"},
    {"entry": dict(base_masto, template="https://mastodon.social/@{q}", entity_types=["username"]),
     "expect": "https://<instance>/@{fedi_user}"},
    {"entry": dict(base_masto, entity_types=["fediverse_handle", "cpf"]), "expect": "CPF"}]})
write("pivots_person__lint_bad_entries.json", {"pack": "person", "cases": [
    {"entry": dict(base_person, privacy=False), "expect": "privacy=true"},
    {"entry": {k: v for k, v in base_person.items() if k != "max_tlp"}, "expect": "max_tlp=clear"},
    {"entry": dict(base_person, max_tlp="amber"), "expect": "max_tlp=clear"},
    {"entry": dict(base_person, label="Webmii"), "expect": "homonyms likely"},
    {"entry": dict(base_person, entity_types=["person_name", "email"]), "expect": "person_name only"},
    {"entry": dict(base_person, template="https://webmii.com/people?n={raw}"), "expect": "{raw}"}],
    "tier_case": {"host_tiers": {"webmii.com": "unknown"}, "expect": ["unknown-tier", "P257 FC4"]}})

# -------------------------------------------------------------------------------------- render vectors
HOSTILE = ['a"b', "x' OR 1=1--", "a b", "line\nbreak", "tab\tvalue", "../../admin", "a/b?c=d#e", "%2e%2e",
           "‮evil", "<script>alert(1)</script>", "exámple.com", "ação.com.br", "example.com\r\nX-H: y",
           "@user@mastodon.social.evil.example.org", "user@mastodon.social/../x", "", " ", ".", "..",
           "123.456.789-09", "José da Silva", "名前 テスト", "@@mastodon.social", "user@@mastodon.social"]
write("render_vectors.json", {
    "hostile_values": HOSTILE,
    "samples": [
        {"pack": "email", "link": "email_format_domain", "etype": "domain", "value": "example.com",
         "url": "https://www.email-format.com/d/example.com/"},
        {"pack": "email", "link": "email_format_domain", "etype": "domain", "value": "Nic.BR.",
         "url": "https://www.email-format.com/d/nic.br/"},
        {"pack": "email", "link": "email_format_domain", "etype": "domain", "value": "ação.com.br",
         "url": "https://www.email-format.com/d/xn--ao-siap.com.br/"},
        {"pack": "username_social", "link": "bluesky_profile", "etype": "bsky_handle", "value": "@bsky.app",
         "url": "https://bsky.app/profile/bsky.app"},
        {"pack": "username_social", "link": "bluesky_profile", "etype": "username", "value": "BSKY.APP",
         "url": "https://bsky.app/profile/bsky.app"},
        {"pack": "username_social", "link": "bluesky_profile", "etype": "username", "value": "octocat",
         "url": None},
        {"pack": "username_social", "link": "bluesky_profile_bsky_social", "etype": "username",
         "value": "octocat", "url": "https://bsky.app/profile/octocat.bsky.social"},
        {"pack": "username_social", "link": "bluesky_profile_bsky_social", "etype": "username",
         "value": "bsky.app", "url": None},
        {"pack": "username_social", "link": "mastodon_social_profile", "etype": "fediverse_handle",
         "value": "@Mastodon@mastodon.social", "url": "https://mastodon.social/@Mastodon"},
        {"pack": "username_social", "link": "mastodon_social_profile", "etype": "fediverse_handle",
         "value": "Mastodon@MASTODON.SOCIAL", "url": "https://mastodon.social/@Mastodon"},
        {"pack": "username_social", "link": "mastodon_social_profile", "etype": "fediverse_handle",
         "value": "@someone@social.example.org", "url": None},
        {"pack": "username_social", "link": "mastodon_social_profile", "etype": "username",
         "value": "Mastodon", "url": None},
        {"pack": "person", "link": "webmii_people", "etype": "person_name", "value": "Maria Exemplo",
         "url": "https://webmii.com/people?n=Maria%20Exemplo"},
        {"pack": "person", "link": "webmii_people", "etype": "person_name", "value": "José  da Silva",
         "url": "https://webmii.com/people?n=Jos%C3%A9%20da%20Silva"},
        {"pack": "person", "link": "webmii_people", "etype": "person_name", "value": "Maria",
         "url": None},
        {"pack": "person", "link": "webmii_people", "etype": "person_name", "value": "Maria 123.456.789-09",
         "url": None}],
    "hibp": [
        {"name": "Adobe", "url": "https://haveibeenpwned.com/breach/Adobe"},
        {"name": "7-Eleven", "url": "https://haveibeenpwned.com/breach/7-Eleven"},
        {"name": "Sony Pictures", "url": "https://haveibeenpwned.com/breach/Sony%20Pictures"},
        {"name": "Société Générale", "url": "https://haveibeenpwned.com/breach/Soci%C3%A9t%C3%A9%20G%C3%A9n%C3%A9rale"},
        {"name": "名前", "url": "https://haveibeenpwned.com/breach/%E5%90%8D%E5%89%8D"},
        {"name": "a/b?c#d", "url": "https://haveibeenpwned.com/breach/a%2Fb%3Fc%23d"},
        {"name": "someone@example.com", "url": None},
        {"name": "line\nbreak", "url": None},
        {"name": "..", "url": None}]})
