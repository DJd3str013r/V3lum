# Batch p3-G14-1 prep notes (G14: P098, P125, P144, P257, P289, P307)

This batch was prepared on 2026-11-26 from the research datacenter egress, which is outside Brazil. All requests
used curl's default User-Agent, no cookie jar, and did not follow redirects. Nothing in the V3LUM repository was
read or changed, and no module classes were written.

"FCn" means final condition n of the proposal in `specs/p3-G14-1.md`. The binding rules are elsewhere:

- A2, A5 and A8 are in `specs/_common.md`;
- P311 and P321 are in `specs/core_G15.md`;
- the frozen pack schema is `module_author_contract` section 15 in `impl/core/plan.json` (schema
  `v3lum.pivot_pack/1`).

## Folder contents

| path | content |
|---|---|
| `code/parsers.py` | Reference helpers: standard library only, pure, defensive. Covers placeholders and encoders, the re.sub renderer and rendered-URL invariants, the batch pack lint, the A2/P311 link view, ordering and the terminal cap, `doctor --links`, the P125 de-duplication, the P098 company-to-domain rule, the P144 HIBP link, maintainer re-check classifiers, P307 provider gates, error/x402 classification and parsers, and the P289 gate, queries and aggregate. |
| `code/test_parsers.py` | 340 tests. Run `cd code && python3 -m pytest -q -p no:cacheprovider .` |
| `code/build_fixtures.py` | Rebuilds the minimised and scrubbed HTTP fixtures from `raw/` (`python3 -I code/build_fixtures.py`). |
| `code/build_drafts.py` | Writes the pack drafts, registry drafts, lint-must-fail entries and render vectors. |
| `code/live_check.py`, `code/live_plan_round{1..9}.json` | The polite checker: at most 5 requests per host across all runs, at least 1.5 s apart, GET only, no redirects followed, Set-Cookie/CF-Ray/report-to dropped. |
| `code/peek.py`, `code/inspect_page.py` | Read-only viewers for the untrusted files. |
| `fixtures/<module>__pack_draft.json` | The three packs, `email.json`, `username_social.json` and `person.json`, in the frozen schema, plus `max_tlp`. |
| `fixtures/<module>__registry_draft.json` | `v3lum.provider/1` fragments, each marked `new`, `exists` or `refused`. |
| `fixtures/host_tiers_draft.json` | The host tiers proposed by the final conditions, used by the tests. |
| `fixtures/<module>__lint_bad_entries.json` | Entries that must fail the lint, each with the expected reason. |
| `fixtures/render_vectors.json` | Sample and hostile values with the expected URLs (FC3, P144 FC5). |
| `fixtures/<module>__<case>.http.json` | Envelopes `{_provenance, url, status, headers, body}`. Real captures are minimised. Synthetic ones carry `_provenance.synthetic=true` and are not P307 FC10 merge-gate evidence. |
| `fixtures/<module>__live_checks.meta.json` | Per-module summary of every live request (status, latency, kept headers). |
| `raw/live/`, `raw/research/` | Untrusted downloads (31 live requests) and copies of the research samples. Never copy these into the repository. Two changes were made here: the email-format sample addresses (`data-cfemail` payloads) were scrubbed, and the App Store page bodies were deleted because they name the individual Webmii seller. |

Live requests per host (all caps respected):

| host | requests | statuses | latency |
|---|---|---|---|
| www.email-format.com | 5 | 200, 302 | 0.19-0.65 s |
| email-format.com | 1 | 301 | 0.26 s |
| bsky.app | 3 | 200 | 0.26-0.31 s |
| mastodon.social | 5 | 200, 404, 410 | 0.33-0.61 s |
| haveibeenpwned.com | 5 | 200, 404 | 0.11-0.42 s |
| webmii.com | 5 | 200 | 0.41-0.48 s |
| apps.apple.com | 2 | 301, 200 | 0.40-0.56 s |
| api.duckduckgo.com | 5 | 202 | 0.17-0.57 s |

No request was sent to Brave, Tavily, Exa, Marginalia or SerpApi. Those fixtures come from the research samples:
the keyless 422/401/402/429 answers and SerpApi's cached keyless answer.

---

## 0. Read this first (blockers and cross-cutting gaps)

1. **P257 Webmii will probably not pass its own A8 gate (FC4).**
   - Evidence collected 2026-11-26 from `/`, `/about`, `/privacy` and the App Store listing:
     - there is no terms-of-use page;
     - the privacy text is three sentences and is not linked anywhere on the site;
     - no legal entity is named;
     - the App Store seller is a natural person (2021). The name is deliberately not recorded here.
   - A8 classes "anonymous or individual operators, no terms" as **unknown**. FC4 then says the link is dropped.
   - The registry draft records `unknown` with this rationale (`fixtures/pivots_person__registry_draft.json`,
     `pivots_person__operator_evidence.json`). The pack draft ships the entry for the reviewer, and the lint fails
     it while the tier is unknown (tested).
   - **P311 cond 4 conflict.** The P311 lint rejects "people-search/'painel'" sites, and Webmii calls itself a
     "people search engine" / "people search mash up".
     - Check that `lint.PEOPLE_SEARCH_DENYLIST` does not hold `webmii.com`. The sibling batch notes say it is seeded
       from other research ids.
     - If it does hold it, P257 needs an architect/legal decision.
   - **The disclosure warning is incomplete.** The result page loads Google Tag Manager/Analytics, Google Custom
     Search (`cse.google.com`) and the Facebook SDK. Those receive the page URL, and with it the person's name.
     'opening sends <name> to webmii.com' understates this. Suggested wording: "... to webmii.com (and the Google
     and Facebook scripts it embeds)".
2. **Proposed placeholders (core work in `core/links.py`; the frozen list has none of them).** P125 FC8 and FC9 ask
   for "vetted placeholders":

   | placeholder | accepts | renders |
   |---|---|---|
   | `{bsky_handle}` | `bsky_handle`, `username` | a domain-style handle in atproto syntax only (a dot, valid labels, no .local/.onion/...); bare usernames and DIDs give no link |
   | `{bsky_social}` | `username` | `<user>.bsky.social` only for 3-18 of `[a-z0-9-]` |
   | `{fedi_user}` | `fediverse_handle` | the user part only when the handle's instance equals **the link's declared host**, so the renderer must pass `link.host` to the placeholder |

   - Reference code: `parsers.bsky_handle_value`, `bsky_social_value` and `fedi_user_value`, plus
     `placeholder_value(name, etype, value, host)`.
   - Without these placeholders, `{user}` gives dead links (FC8) and would send usernames to arbitrary instances
     (FC9, A8). P125 cannot ship as written.
3. **`max_tlp` is not in the frozen key list (section 15).**
   - P257 FC1 says the phase-0 schema "must include" it. P203 and P304 in the sibling batches need it too.
   - Check whether the frozen loader rejects unknown keys or ignores them. If it ignores them, nothing enforces
     FC3, so test it: `test_person_link_only_at_clear`.
4. **P144 is not a pack (FC1).**
   - It is a helper the breach modules call: `parsers.hibp_link_for(name, from_hibp=..., catalog_index=...)` and
     `hibp_breach_url`. The result is emitted with `ModuleResult.link()` next to each breach name.
   - The `hibp` provider fragment is already seeded with the source `breach_pages` (tier trusted, flags.sensitive
     true). No new provider is needed.
   - The FC2 "exact case-insensitive match in data already in the case" should reuse the shared hibp_catalog
     helper from P132 cond 3 (batch G04).
   - Coordinate with the G04 owners of `hibp_account`/`hibp_catalog`.
   - Do **not** add a pack entry on `keyword`: `parsers.breach_pack_problems` checks this.
5. **P289 key and budget.**
   - The proposal header lists `V3LUM_SEARCH_API_KEY`, but FC2 says P289 is automated only through P307's Brave
     source. Use the Brave provider's key, `V3LUM_BRAVE_KEY` (one key per provider, contract section 13), and do
     not register `V3LUM_SEARCH_API_KEY`.
   - The "<= 10 queries per case" budget should share the P307 `web_search_case_budget` counter, so that X-ray and
     generic queries cannot add up to 20.
6. **P289 scope flag.**
   - `social_engineering: true` is not in the A7 scope-file schema (`docs/ROE.md`, `core/scope.py`). It is a core
     addition: accept it, refuse non-boolean values, and expose it to policy.
   - The draft also proposes an optional `organisations` list, so that a company name can be in scope.
   - Map the own-organisation check to the P378/WP18 `orgprofile` API: `txt_verified`/`attested` entries count,
     unverified ones do not.
   - `parsers.xray_gate` uses a normalised `{names, domains: {domain: status}}` view (`fixtures/employee_xray__gate_cases.json`).
7. **The error-marker `maps_to` enum has no `needs_key`.**
   - The enum is blocked, rate_limited, quota and error. P307 FC4 maps HTTP 402 and x402 offers to NEEDS_KEY, and
     Brave's 422 "x-subscription-token Field required" is also NEEDS_KEY.
   - These are therefore handled in module code (`parsers.classify_search_response`, `x402_offer`). Only the quota
     and rate markers are declared in the registry drafts.
8. **DuckDuckGo IA answers HTTP 202, not 200.**
   - All five requests got a 202 with a complete JSON body and `content-type: application/x-javascript`.
   - The module must accept any 2xx and parse JSON whatever the content-type. P321 must not treat 202 as an error
     or as "accepted, retry later".
9. **False-positive traps for the P321 strong markers, both observed on normal 200 pages.**
   - haveibeenpwned.com loads `/cdn-cgi/challenge-platform/scripts/precursor/main.js` (the Cloudflare beacon).
   - email-format.com carries a Google reCAPTCHA (its "domain removal" form).
   - The strong Cloudflare marker must be `cf-mitigated: challenge`, the 'Just a moment' or 'Attention Required'
     title, `_cf_chl_opt` or `/cdn-cgi/challenge-platform/h/`. A bare `challenge-platform` is not enough, and
     captcha words count only on 403/429/503. Tested.
10. **Soft 404s.**
    - bsky.app answers 200 for an unresolvable handle, with an app shell titled "Bluesky" and no og:title.
    - mastodon.social answers 404 for an unknown handle and 410 for deleted or suspended ones. `@microsoft` and
      `@github` both answered 410.
    - These matter only for maintainer re-checks. V3LUM never fetches pack URLs.
11. **email-format.com operator.**
    - The privacy policy (effective 2018-09-07, US servers) names no legal entity; contact is by web form only.
    - The page template also carries a commented-out RocketReach og: block.
    - FC5 proposes `community`. A8 asks for an identifiable operator, so the reviewer may record `unknown`.
    - The link still ships either way, because `domain` is an IOC type. With `unknown` it carries the 'unknown
      operator' badge.
12. **Placeholders for unobserved responses.**
    - The Brave 429 codes (`RATE_LIMITED`/`QUOTA_LIMITED`), the `X-RateLimit-*` "1, 15000" format and the Tavily
      432/433 statuses come from provider documentation. No key was available, so none was observed.
    - Tavily and Exa `reuses_queries=true` is a conservative placeholder until legal reads their terms. It excludes
      them at AMBER+ (A2).

---

## P098 `pivots_email`: data/pivot_links/email.json (offline pack)

- **Source:** email-format.com, research C0222. One entry, `email_format_domain`:
  - template `https://www.email-format.com/d/{domain}/`;
  - entity_types `["domain"]`, category `company`, host `www.email-format.com`;
  - `verified: true`, `checked_at: 2026-11-26`;
  - privacy false, publishes false, touches_target false, login_required false, antibot false.
  - Draft: `fixtures/pivots_email__pack_draft.json`.
- **Auth:** none. **Terms:** council class `open`. The site states no automation terms (research: "Site ToS (no
  automated scraping stated)"); manual link only.
- **Live behaviour:**
  - `/d/example.com/` and `/d/nic.br/` answer 200, titled "Email Address Format for <domain> (<Name>) | Email
    Format", with a canonical link.
  - An unknown domain gets a 302 to `/i/main/`.
  - The apex host gets a 301 to www, so the template uses www.
  - Cloudflare fronts the site (`cf-cache-status: DYNAMIC`); there was no challenge.
  - The page carries Google reCAPTCHA (domain-removal form), Google Ads and a third-party script from
    `dev.aftyr.dev`.
  - It lists 10 format rows with percentages, and every row has a sample address of a real person (Cloudflare
    email-protection). Those were scrubbed from fixtures and raw.
  - The no-trailing-slash form was not checked (the host cap was spent on operator evidence). Keep the slash.
- **Recommended values:** disclosure `none`, max_requests 0, expected_latency 0. cache_ttl, min_interval and
  daily_quota are n/a. Doctor re-check age 180 days.
- **Pivots/attributes:** none; it is a manual link.
- **FC to code:**

  | FC | implementation |
  |---|---|
  | FC1 | Pack draft (frozen keys). Disclosure none; V3LUM never requests it. |
  | FC2 | `link_view`: AMBER+ text with 'opening sends example.com to www.email-format.com'; RED goes to links_only; `open_decision`. |
  | FC3 | `render_template`/`check_rendered_url` with `render_vectors.json` and the hostile values. `{domain}` validates and punycodes, so bad values give no link. |
  | FC4 | `lint_link`: unknown tier means IOC types only (domain passes, with the badge). |
  | FC5 | Registry draft `email_format` (community proposed; see 0.11). |
  | FC6 | `order_views`: a single entry. |
  | FC7 | `doctor_links` (180 days). |
  | FC8 | `email_link_domains(etype, value, related_domains)`: a company_name gets the link only through its known domain(s) (graph relation or org_profile), never with the company name in the URL. The lint forces `["domain"]` and the exact template. |
  | FC9 | The label carries "corporate address pattern: use the pattern, never the sample people". The lint rejects `/m/export*`, `/i/search` and `/i/account`; the page offers "Export to Excel" with `inc_emails`. Nothing parses the page's addresses: the only page helper is the title check in `classify_check('email_format', ...)`. |

## P125 `pivots_username_social`: data/pivot_links/username_social.json (offline pack)

- **Sources:** C0283 (bsky.app) and C0284 (mastodon.social). The entries, in curated order (FC6, Bluesky then
  Mastodon):
  1. `bluesky_profile`: `https://bsky.app/profile/{bsky_handle}`, types `bsky_handle` and `username`.
  2. `bluesky_profile_bsky_social`: `https://bsky.app/profile/{bsky_social}`, type `username` only.
  3. `mastodon_social_profile`: `https://mastodon.social/@{fedi_user}`, type `fediverse_handle` only.

  All three are privacy=true, category `social`, labelled "same handle does not prove identity", and verified
  2026-11-26.
- **Auth:** none. **Terms:** council class `open` (Bluesky ToS, instance ToS); manual links.
- **Live behaviour:**
  - bsky.app/profile/bsky.app answers 200, titled "@bsky.app on Bluesky", with og:title "Bluesky (@bsky.app)" and
    `twitter:value1` = the account DID.
  - `BSKY.APP` returns the same page (case-insensitive).
  - `example.com` gets a 200 app shell titled "Bluesky" with no og:title (soft 404).
  - mastodon.social/@Mastodon answers 200, titled "Mastodon (@Mastodon@mastodon.social) - Mastodon.social"; it is
    case-insensitive.
  - A random control handle gets a 404 ("isn't here"). `@microsoft` and `@github` get a 410 ("doesn't exist here
    anymore").
  - No rate-limit headers were seen.
  - Mastodon sends `cache-control: max-age=15, public`.
- **Recommended values:** disclosure `none`, max_requests 0. Doctor re-check age 180 days.
- **FC to code:**

  | FC | implementation |
  |---|---|
  | FC1-FC3 | As P098; the hostile values include `@user@mastodon.social.evil.example.org`, `user@mastodon.social/../x` and RLO. |
  | FC4 | fediverse_handle, bsky_handle and username are PERSONAL_TYPES, so the lint requires privacy=true and a trusted/community host. |
  | FC5 | Registry drafts `bluesky` (Bluesky Social PBC) and `mastodon_social` (Mastodon gGmbH), both community. |
  | FC8 | `{bsky_handle}` gives no link for a bare username; `{bsky_social}` handles bare usernames, only through the privacy=true entry, so only for analyst-typed seeds. The lint rejects `/profile/{user}` and `{q}`. |
  | FC9 | `{fedi_user}` checks the instance against the link host. The curated allow-list is the set of pack entries whose host is trusted/community in the registry. To add an instance, add an entry and a provider fragment; the lint rejects unknown-tier instances. |
  | FC10 | `link_view` gives `privacy_not_seed` for pivots and extracted handles, and `privacy_opt_in` without opt-in plus purpose. `skip_already_linked(views, username_check_found_urls)` uses `profile_key`, which ignores case and treats `/users/<name>` and `/@<name>` as equal. |

## P144 `pivots_breach_leak`: HIBP breach-page link (no pack)

- **Source:** C0322, `https://haveibeenpwned.com/breach/{Name}` (lower-case `/breach/`, as FC1 says).
  - `/breach/Adobe` and `/Breach/Adobe` both answer 200, titled "Have I Been Pwned: Adobe Data Breach".
  - `/breach/Example` answers 404, titled "Have I Been Pwned: 404 Error — ...".
  - The keyless `/api/v3/breach/Adobe` returns the breach JSON (`cache-control: public, max-age=300`).
    `/api/v3/breach/Example` returns 404 `text/plain` "Not found".
  - HIBP pages carry Cloudflare's precursor beacon (see 0.9).
- **Auth:** none for the page. **Terms:** `open`; breach pages are CC BY 4.0, attributed "Have I Been Pwned".
  Provider `hibp` is already seeded (trusted).
- **Code:**
  - `hibp_names(obj)` reads the Name field of any HIBP response: one breach, a list, or a truncated
    breachedaccount answer.
  - `hibp_catalog_index` and `hibp_catalog_facts` (flags IsSensitive, IsSpamList, IsFabricated...).
  - `hibp_breach_url(name)` uses the P311 `{q}` encoder. It refuses '@' (FC3), CPF-like values, newlines and
    dot-only names.
  - `hibp_link_for(name, from_hibp=True|False, catalog_index=...)` returns `{name, url, host, attribution,
    licence, label}` or None.
- **FC to code:**

  | FC | implementation |
  |---|---|
  | FC1 | Helper, not a template (`breach_pack_problems`). |
  | FC2 | Other providers' names get a link only on an exact case-insensitive Name match. HIBP's spelling is used. "Adobe Systems" and Titles like "Abandonia (2022)" get none. |
  | FC3 | The URL carries only the breach name; the helper refuses '@'. |
  | FC4 | The breach module renders the link through the same `link_view` rules (AMBER+ text, RED hidden). The attribution string is returned. |
  | FC5 | `test_hibp_url_spaces_unicode_hostile`. |

- **Recommended values:** no module requests. If the implementer wraps it as a module, use disclosure `none`,
  max_requests 0.

## P257 `pivots_person`: data/pivot_links/person.json (offline, opt-in pack)

- **Source:** C0596. Entry `webmii_people`:
  - template `https://webmii.com/people?n={q}`, type `person_name`, category `social`, host `webmii.com`;
  - privacy true, max_tlp `clear`;
  - label "Webmii (webmii.com): people search engine - homonyms likely";
  - verified 2026-11-26, with a company name rather than a person.
  - FC2 gives `n={name}` without quotes. The research form `n=%22{first}%20{last}%22` (exact phrase) also answered
    200 with the same title.
- **Auth:** none. **Terms:** council class `open`, but the site publishes no terms (see 0.1). The registry draft
  records the source terms class as `unknown`.
- **Live behaviour:**
  - `/people?n=...` answers 200, titled "Webmii - <Title Cased Name>".
  - The score ("---") and results load client-side.
  - Third-party scripts: GTM/GA, the Facebook SDK and Google CSE.
  - Apache/PHP 7.3.31, `cache-control: no-store`.
- **Recommended values:** disclosure `none`, default_enabled False (pack-level opt-in). The pack is hidden unless
  person_name modules are enabled for the case.
- **FC to code:**

  | FC | implementation |
  |---|---|
  | FC1 | Pack draft with `max_tlp`; see 0.3. |
  | FC2 | `person_name_value` needs 2+ alphabetic tokens and refuses digits, '@', URL characters and newlines. `link_view` gives `privacy_not_seed` for any pivot (a depth-1 QSA partner is a pivot) or extracted name. Tested. |
  | FC3 | `link_view` gives `links_only` with reason `max_tlp` above CLEAR. Tested for green, amber, amber+strict and red. |
  | FC4 | The lint fails while the tier is unknown, and `link_view` gives reason `tier`. See 0.1. |
  | FC5 | `link_view(pack_enabled=False)` gives `pack_disabled`. The caller computes it from the case's enabled person_name modules. |
  | FC6 | Render tests. |

## P289 `employee_xray`: aggregate X-ray through P307's Brave source (keyed)

- **Source:** Brave Search API `GET https://api.search.brave.com/res/v1/web/search?q=<query>&count=20`, header
  `X-Subscription-Token: $V3LUM_BRAVE_KEY`.
  - Queries from `xray_queries(company)`: `site:linkedin.com/in "<company>"` and `site:br.linkedin.com/in
    "<company>"`, at most 2 by default and never above the remaining case budget (<= 10).
  - No LinkedIn request, no SerpApi and no scraping. CrossLinked is study material only (GPL, A6).
- **Live:** `needs_key`. Without a token the answer is 422 VALIDATION "x-subscription-token Field required"
  (research sample). Fixtures are synthetic Brave responses with fictional names, as FC6 asks.
- **Module recommendations:**

  | setting | value |
  |---|---|
  | provider | `brave_search` |
  | sources | `brave_search.web` |
  | terms | `key-terms` |
  | disclosure | `third_party` (Brave receives the company name) |
  | opsec | passive |
  | run_on | `seeds`, with `xray_gate` called through policy (FC1); `own_assets_only` would block the engagement path |
  | default_enabled | False (A3 person-search category) |
  | max_requests | 2 |
  | expected_latency | 3 s |
  | timeout | 30 s |
  | cache_ttl | 0 (Brave raw results are never cached, P307 FC6) |
  | min_interval | 1.0 s |
  | daily_quota | None (monthly credits through P334) |
  | requires_keys | the Brave key |
  | produces | nothing |

  - FC3: no person_name pivots.
  - Attributes: `exposure_aggregate = {label, company, profiles, by_department, ...}`.
  - `sample_names` stays case-only.
- **FC to code:**

  | FC | implementation |
  |---|---|
  | FC1 | `xray_gate` gives reason_code `own_asset` (not own org, no engagement) or `scope` (engagement without `social_engineering: true`, a string "true", target not listed, outside the window). FakeHttp test: assert zero requests whenever `run` is false. |
  | FC2 | Brave only. `xray_queries` plus `budget_allows`. |
  | FC3 | `aggregate_xray` counts only linkedin.com/in profile URLs whose title names the company. It drops duplicates, other employers, company pages and non-LinkedIn URLs, and reads titles only, never snippets. It keeps at most 10 sample names; `pivots` and `emails` are always empty. `export_view(include_personal=False)` strips the names. |
  | FC4 | No e-mail generation exists in the code. |
  | FC5 | `sample_expiry(collected_at, retention_days, window_end)` returns the earlier date, for the A10 purge. |
  | FC6 | The label is "social-engineering exposure (aggregate)"; fixtures are synthetic. |

## P307 `web_search_api`: Brave, DuckDuckGo IA, Marginalia, Tavily, Exa (SerpApi refused)

- **Endpoints:**

  | sub-source | request | key | terms | tier |
  |---|---|---|---|---|
  | Brave | `GET https://api.search.brave.com/res/v1/web/search?q=&count=20`, header `X-Subscription-Token` | `V3LUM_BRAVE_KEY` | key-terms | trusted |
  | DuckDuckGo | `GET https://api.duckduckgo.com/?q=<term>&format=json&no_html=1&skip_disambig=1` | none | open | trusted |
  | Marginalia | `GET https://api2.marginalia-search.com/search?query=&count=`, header `API-Key` | `V3LUM_MARGINALIA_KEY` | license | community |
  | Tavily | `POST https://api.tavily.com/search`, `Authorization: Bearer` | `V3LUM_TAVILY_KEY` | unknown | community |
  | Exa | `POST https://api.exa.ai/search`, `x-api-key` | `V3LUM_EXA_KEY` | unknown | community |
  | SerpApi | none: no registry entry, never requested (FC1) | | | |

  - DuckDuckGo is context only, with attribution.
  - The module's own class is `unknown` (most restrictive), and it is default_enabled False.
- **Live and research behaviour:**
  - DuckDuckGo: 5/5 answers were HTTP **202** with a full JSON body, latency 0.17-0.57 s, and no rate-limit
    headers.
    - example.com, registro.br, nic.br and cloudflare.com returned Wikipedia abstracts and infoboxes (Entity
      infobox/organization/company/top level domain).
    - 9.9.9.9 returned every field empty, with `meta.id: just_another_test`.
    - Company infoboxes name founders and executives. `parse_ddg` allow-lists infobox labels so those rows (and
      social-profile rows) are never ingested.
  - Brave: 422 without a token (0.39 s, `awselb/2.0`).
  - Tavily: 401 `{"detail":{"error":"Unauthorized: missing or invalid API key."}}`.
  - Exa: 402 with an x402 v2 offer (USDC on Base/Solana, about US$0.007 per search) and `WWW-Authenticate:
    Payment ...`.
  - Marginalia: 429 `Daily Limit Exceeded` on the shared public key.
  - SerpApi (research): a keyless call returned another user's cached `q=test` search.
- **Recommended values:**

  | setting | value |
  |---|---|
  | max_requests | 5 per entity per run (1 Brave plus 1 DDG, plus at most 1 per enabled alternate) |
  | expected_latency | 2 s |
  | timeout | 30 s |
  | min_interval | 1.0 s per provider (Brave free tier 1 QPS) |
  | cache_ttl | Brave 0 (FC6); DDG 86400 (open context); Marginalia/Tavily/Exa 0 |
  | per-case budget | 10 (`web_search_case_budget`, shared with P289) |
  | monthly budget | Brave 1,000 requests/month (US$5 free credits), via P334 with QUOTA status |
  | daily_quota | None |

  - Coverage line: `budget_line` returns "3/10 queries used".
- **Pivots/attributes:** `url` and `domain` from result URLs (`result_pivots`); evidence is URL plus title of the
  analyst-selected results (`evidence_records`). DDG facts are context attributes:

  | attribute | content |
  |---|---|
  | `ddg_heading` | heading |
  | `ddg_abstract` | abstract, with `abstract_source`/`abstract_url` |
  | `ddg_entity` | entity type |
  | `official_website` | official website |
  | `infobox` | allow-listed rows only |
  | `attribution` | "Results from DuckDuckGo (source: Wikipedia)" |

- **FC to code:**

  | FC | implementation |
  |---|---|
  | FC1 | `refused_host` (serpapi.com and subdomains), `provider_gate('serpapi')` gives policy. FakeHttp test: serve `web_search_api__serpapi_never_requested.json` for serpapi.com and assert it is never requested. |
  | FC2-FC4 | `provider_gate`: Brave needs a key and a business plan, otherwise needs_key or licence. Marginalia needs a licence or commercial plan, otherwise licence. Tavily and Exa need legal terms, otherwise unknown_terms. `x402_offer` and `classify_search_response` map 402 to needs_key; no payment path exists. |
  | FC5 | One gate result per provider (separate coverage rows). Keys go in headers; the Marginalia v1 key-in-path form is not used, and AR01 still redacts. |
  | FC6 | `parse_brave_web` and the other parsers return url/title/host only (tested: no snippet text survives). Use cache ttl 0 and keep the results the analyst selected. |
  | FC7 | `build_query`: seed-only; person_name/e-mail only with a recorded purpose; `query_problem` rejects URLs with query strings, JWTs, `key=`/`token=` parameters, 32+ character opaque tokens, CPFs, more than 400 characters and more than 50 words. |
  | FC8 | `budget_allows`/`budget_line`. TLP: RED excludes everything; AMBER+ excludes reuses_queries providers; AMBER+STRICT allows trusted only. |
  | FC9 | default_enabled False, run only by `-M`, `--preset deep` or a P287/P289 call. |
  | FC10 | Real no-key fixtures: Brave 422, Tavily 401, Exa 402, Marginalia 429. Success fixtures are synthetic placeholders and must be replaced by real captures before each provider is enabled. |
