# p3-G10-3 prep notes (P253 adverse_media_rss, P254 wanted_notices)

Prepared 2026-11-26 from the datacenter egress of this sandbox. Nothing here imports V3LUM. Layout:

- `code/parsers.py` - pure stdlib parsers and marker helpers (docstrings name the final condition, FC).
- `code/test_parsers.py` - 30 offline tests over `fixtures/` (`cd code && python3 -m pytest -q -p no:cacheprovider .`).
- `code/build_*_fixtures.py`, `code/scan_fixtures_pii.py` - how the fixtures were made and checked (python3 -I).
- `code/live_gdelt.sh` - the GDELT live probe, as run.
- `raw/` - unminimised live downloads. The FBI pages hold real names, dates of birth and photo URLs of listed
  persons. The GDELT 429 body holds the operator's e-mail address. Never copy `raw/` into the repo.

Live request budget used: api.fbi.gov 5 (3 list pages, /docs, /openapi.json), api.gdeltproject.org 5 (spaced 60-90 s
apart), ws-public.interpol.int 0, news.google.com 0. The last two are manual links only (see below).

---------------------------------------------------------------------------------------------------------------
## P253 `adverse_media_rss` - adverse-media mentions (GDELT DOC 2.0; Google News = manual link)

### Sources, endpoints, auth
| source | use | endpoint | auth / env | terms class (spec) | tier |
|---|---|---|---|---|---|
| GDELT DOC 2.0 | automated, one call per entity | `GET https://api.gdeltproject.org/api/v2/doc/doc?query=<q>&mode=artlist&format=json&maxrecords=50&timespan=3months&sort=datedesc` | none / none | `open` (about.html: "unlimited and unrestricted use for any academic, commercial, or governmental use"; any use must cite the GDELT Project with a link) | community |
| Google News | **manual pivot link only** (FC2) | `https://news.google.com/search?q=<q>&hl=pt-BR&gl=BR&ceid=BR:pt-419` | - | unofficial endpoint, unknown terms (A1: never automated in any profile) | - |

`q` = `"<distinctive name>" (fraude OR corrupcao OR ... OR "ataque hacker" OR ...) sourcelang:portuguese` (or
`sourcecountry:brazil`). Build it with `build_gdelt_query()`. The URL comes from `gdelt_request_url()`, with spaces as
%20 and `:` as %3A.

`Module.hosts` should be `('api.gdeltproject.org',)` only. The chair header lists `news.google.com` as a host, but
FC2 makes it a link and never a request. Declaring it would let ScopedHttp reach it. Register Google News in the
provider registry as a manual-link source with terms `unknown`, so it is never automated.

### Observed live behaviour (this egress, 2026-11-26)
- 10:43:58Z: **429** after 11.1 s. Body 444 bytes of text: `Please limit requests to one every 5 seconds or contact <operator e-mail> for larger queries. All high-traffic users should switch to our ngrams dataset ...`. Headers: only `Date`, `Server: GDELT Server` and `Content-Length: 444`, with **no Content-Type and no Retry-After**. This was the first GDELT call of the session, so the 429 is for the shared egress IP.
- 10:45:45Z, 10:46:58Z, 10:48:10Z (60 s apart): **TLS connection reset** after ~12 s (`curl: (35) Recv failure: Connection reset by peer`). Calls covered positive, empty and short-phrase queries.
- 10:49:52Z (90 s later): **429** again after 11.7 s, with the same body.
- No 200 from this egress. The research egress got one `200 {}` (the no-match answer) and otherwise only 429s and resets.
- Latency: every answer, the throttled ones included, took 11-12 s.
- Google News RSS was not requested (FC2). The research record has `503` after 10 s from a datacenter egress.

### Recommended settings
- `max_requests = 1` per entity (FC3). Do not retry a 429.
- Provider-level token bucket (P334 quota block in the registry): `min_interval = 5 s` per **egress IP**, shared by every module and analyst through the team quota DB (`scope: egress_ip, shared: true`). After a 429 or a reset, hold the whole provider in a cool-down of 60 s or more. `transport_reason()` returns `cool_down: True` for resets.
- `daily_quota`: GDELT publishes none. Suggest a team-wide 300/day to stay a polite client.
- `cache_ttl = 24 h` (news window is 3 months; A10 30-day cap applies). Never cache 429, reset, error-in-200 or challenge answers.
- `expected_latency = 12 s` (p50 observed), request timeout 25 s. The p50 is above 10 s, so `default_enabled` must be False under A3 as well (FC5 already says so).
- `disclosure = 'third_party'` (GDELT receives the name). Tier community: runs at CLEAR, GREEN and AMBER, and is skipped at AMBER+STRICT (trusted only) and RED.

### Output, pivots, attributes
- Per mention (one story cluster): `title`, `url` (newest article), `domain`, `date` (ISO), `outlets[]`, `urls[]`, `articles`, `matched_terms[]`, `label` and `severity='info'`. The output keeps no socialimage, no article text and no description.
- Result: `name_phrase`, `kind`, `terms_version` (`pt-risk-v1`), `articles_total`, `articles_matched`, `clusters_total`, `mentions` (at most 10), `truncated`, `summary_severity` (`low` when there is a mention, else None), `risk_scored=False`, `citation`, `homonym`.
- Pivots: `url` for each article URL with **expand=False** (`url_pivots()`). Articles are never fetched or scraped.
- The `citation` string `Source: The GDELT Project (https://www.gdeltproject.org/)` must reach the report or evidence (FC1).
- Manual link: `google_news_manual_link(name, kind)` (FC2), emitted on every run, including BLOCKED and RATE_LIMITED runs.

### Final conditions -> code
1. GDELT, keyless, JSON preferred: `gdelt_request_params()` sets format=json, mode=artlist. `parse_gdelt_artlist()` reads JSON. `parse_gdelt_rss()` handles format=rss only behind `safe_xml_fromstring()`, which refuses DOCTYPE/ENTITY. In the module, use the core safe-XML helper instead of this mirror. The citation is `GDELT_CITATION`.
2. Google News is not automated: `google_news_manual_link()` builds the link. Keep the host out of `Module.hosts`.
3. One request per entity: `build_gdelt_query()` combines all risk terms in one OR group. The shared 5 s bucket is configured in the core and registry, with `GDELT_MIN_INTERVAL_S` as the documented constant. `gdelt_marker()` returns `rate_limited` for status 429 **or** the "Please limit requests" text on any status, mapped to RATE_LIMITED `rate_limited`. `parse_gdelt_artlist()` raises `ParseError` on that text, so it can never become 'no news'. Resets go through `transport_reason()` to ERROR `error` with a cool-down.
4. Query: `name_phrase()` gives distinctive tokens. It strips legal suffixes (LTDA, S.A., S/A, EIRELI, ME, EPP, CIA...) and honorifics, and keeps inner particles because GDELT matches phrases. The term lists `RISK_TERMS_PT`, `RISK_TERMS_PT_ORG`, `RISK_TERMS_EN` and `RISK_TERMS_EN_ORG` carry `RISK_TERMS_VERSION`. Ship them in `data/` and keep the parser constants in sync. Organisations get the CTI terms; persons never do. The source filter is the `source_filter` parameter.
5. Opt-in gate: `adverse_media_query_allowed(kind, analyst_typed, purpose, source)` returns a reason (reason_code `privacy`). Companies are allowed by default. Person names need an analyst-typed seed with a recorded purpose. QSA, pivot and text-extracted names are refused, and an employment-screening purpose (PT/EN keywords) is refused. The module also sets `default_enabled=False` and category person_name.
6. Output: `headline_match()` requires the exact name phrase (word-bounded, accent- and case-insensitive, so "Comercializadora" does not match "Comercial") **and** a risk term (`TERM_PATTERNS` covers plural, gender and noun forms). `cluster_headlines()` groups titles with Jaccard >= `TITLE_SIMILARITY_THRESHOLD` (0.8). `MAX_HEADLINES` is 10. Each mention keeps only outlet domain, date and URL.
7. Mentions are INFO with summary LOW and `risk_scored=False`. For persons, `homonym` = the phrase passed in. Call core namematch `homonym_risk(name)['phrase']` (P252); `HOMONYM_DEFAULT_PHRASE` is only a fallback.
8. Merge gate: **cannot be met from this egress.** No positive GDELT answer was obtained (2x 429, 3x reset). The positive fixture `adverse_media_rss__gdelt_artlist_ok_synthetic.json` is SYNTHETIC: it uses the documented artlist shape about a fictional company ("Exemplo Comercial") on example.* outlets. The 429 body is live, and the empty `{}` is the research-observed answer. **A real positive capture from the team network is still required before merge.** Use a public company name such as "Banco do Brasil", minimise to about 5 articles, and scrub any person names in headlines.

### Open points for the implementer
- **Accent handling is not verified.** It is unknown whether GDELT matches `corrupcao` against "corrupção". The binding list is unaccented. If the team-network capture shows misses, add accented variants (corrupção, denúncia, operação, invasão, prisão) to the same OR group.
- The GDELT limit on query length or number of OR terms is not verified. The org query is about 250 characters. The query error texts (e.g. "The specified phrase is too short.") arrive as **HTTP 200 plain text**. `gdelt_marker()` maps any non-JSON, non-XML 200 body to `error_in_200:<first line>` (ERROR `error`). The fixture with the exact wording is synthetic. `gdelt_query_problem()` refuses phrases shorter than 4 characters before sending.
- EN equivalents: with `sourcelang:portuguese` they rarely appear in titles. The parser defaults to `include_en=False` to keep the single query short. Set `include_en=True` when the filter is `sourcecountry:brazil`. Headline matching uses whatever list built the query.
- A `{}` answer is EMPTY ("no matching headlines in GDELT for the last 3 months"). It is not a claim that no news exists.

---------------------------------------------------------------------------------------------------------------
## P254 `wanted_notices` - FBI Wanted cyber list (local matching); INTERPOL = manual link

### Sources, endpoints, auth
| source | use | endpoint | auth / env | terms class (spec) | tier |
|---|---|---|---|---|---|
| FBI Wanted API | dataset, refreshed daily, matched locally | `GET https://api.fbi.gov/wanted/v1/list?poster_classification=default&pageSize=50&page=N` (documented as `/@wanted` in `https://api.fbi.gov/openapi.json`) | none / none | `open` (US government public information) | trusted |
| INTERPOL notices | **manual link only** (FC3) | `https://www.interpol.int/How-we-work/Notices/Red-Notices/View-Red-Notices` (no name in the URL). Yellow notices are excluded entirely. | - | unknown (A1: never automated) | - |

`Module.hosts` should be `('api.fbi.gov',)` only. Do not declare `ws-public.interpol.int`, even though the chair header lists it (A9: Akamai-walled sources are manual links). `www.fbi.gov` poster and PDF URLs are rendered as links and never fetched. Photos are never downloaded (FC4).

### Observed live behaviour (this egress, 2026-11-26)
- `list?subjects=Cyber%27s%20Most%20Wanted&pageSize=50&page=1`: **200**, 1.6 s, 175 KB. `total` is **1283**, the whole list, because **the API has no subject filter**. `/openapi.json` lists title, field_offices, person_classification, poster_classification, status, physical filters, page, pageSize, sort_on and sort_order. Of 50 items, 17 were cyber. The research endpoint `subjects=` is silently ignored, and the research sample shows the same (`total: 1283`, non-cyber items).
- `list?pageSize=100&page=13`: **200**, 50 items. **pageSize is clamped to 50.**
- `list?poster_classification=default&pageSize=50&page=1`: **200**, 0.2 s (Cloudflare HIT), `total` **730**, all 17 cyber posters of page 1 present. All 25 cyber posters seen across 100 unfiltered items had `poster_classification=default`.
- Headers: `server: cloudflare`, `cache-control: public, max-age=600`, `cf-cache-status: MISS|HIT`, `x-robots-tag: noindex, nofollow, nosnippet, noarchive`. There were no rate-limit headers and no block. `/docs` (Swagger UI, 200 HTML) carries Cloudflare's passive `/cdn-cgi/challenge-platform/scripts/jsd/` script. That script is **not** a challenge, and `detect_block()` ignores it (tested).
- INTERPOL was not requested. The research probe (2026-11-25) got **403 text/html, 407 bytes, `<title>Access Denied</title>`** (Akamai) for `ws-public.interpol.int/notices/v1/red?...`.

### FC1 page cap: cannot be met as written
The unfiltered walk is 1283 items / 50 = **26 pages, above the 25-page cap**. The recommended walk is `poster_classification=default`: 730 items = **15 pages**, with "Cyber's Most Wanted" selected locally by `fbi_is_cyber()` (subjects, or a `/wanted/cyber/` path). The residual risk is a cyber poster under another classification. For more coverage, also walk `poster_classification=information`. Its size was not measured; it was 11 of 50 on one sample page, so roughly 6 pages, for about 21 pages in total within the cap. Measure it when implementing. `fbi_pages_needed()` reports `capped`/`missing_items`, so a run that hits the cap is partial with stop_reason `request_cap`.

### Recommended settings
- Refresh the dataset as a P330/AR10 dataset (`v3lum data update fbi_wanted_cyber`), using a custom pager because the dataset manager fetches one URL. Run it daily (`cache_ttl = 24 h`), at most 25 requests per refresh, 1 s between pages, timeout 20 s per page. Keep only the minimised cyber records (`normalise_fbi_item()`, about 2.5 KB per poster including match_text, measured over 42 live records; the total cyber count was not measured, but 25 of 100 sampled unfiltered items were cyber) with fetched_at and sha256. A full 15-page walk is about 2.5 MB over the wire and 5-25 s.
- Scan-time matching is local: `max_requests = 0` at scan time and `disclosure = 'none'` (FC1). Under A8, disclosure-'none' modules get **no network**, so the refresh must run in the dataset manager, not through `ctx.http` in the module. With no dataset, return UNAVAILABLE reason_code `dataset` ("run v3lum data update fbi_wanted_cyber").
- `daily_quota`: about 50 requests (one walk plus retries). `expected_latency`: about 0.05 s at scan time (local).
- `default_enabled = False` (FC5). Inputs: `threat_actor`, and `person_name` only from analyst-typed seeds. There are **no keyword lookups** (FC2) and the `title=` API filter is not used, so no name is ever sent.

### Output, pivots, attributes
- Actor card: `match_actor(records, actor, aliases)` returns `summary` = `'N indicted individuals linked to <actor> - FBI'` (exact FC2 wording), `individuals[]` (title, aliases, charges, url, poster_urls, status, path, `via` = direct | group_poster | links_to_group), `groups[]`, `matched[]`, `label` = `'possible match - not identity proof'`, `severity='info'` and `confidence='medium'`. Group posters (e.g. "APT 41 GROUP") link to member posters through the `<a href="https://www.fbi.gov/wanted/cyber/...">` anchors in `caution`. Members link back to the group. Both directions are used.
- Person seed: `match_person(records, name, homonym_phrase)` returns `match_type` = name_exact | alias_exact | name_subset. Seeds need at least 2 tokens, matching ignores token order and accents, group posters are skipped, and each hit carries the same label, severity and confidence plus the P252 homonym phrase.
- Pivots: **none** (the spec's `produces` is empty). Names and aliases must not become person_name pivots (FC2). Poster URLs are links or attributes and are never expanded.
- Manual links: `fbi_manual_link()` (www.fbi.gov/wanted/cyber) and `interpol_manual_link()`.

### Final conditions -> code
1. `fbi_list_params()`, `fbi_page_meta()`, `fbi_pages_needed()`, `parse_fbi_list()` (local cyber filter), `merge_fbi_pages()` and `match_actor()` against P295 alias lists. `actor_alias_forms()` treats "APT41", "APT 41" and "APT-41" as equal, also matches "Lazarus Group" as "lazarus", and drops forms under 4 characters and generic words. **The page cap needs the poster_classification filter** (see above).
2. The FC2 wording is in `match_actor()`. `match_person()` is for analyst-typed seeds only; the module enforces seed origin (`ctx.is_seed`, no pivots, QSA or text names). There is no keyword input.
3. `interpol_manual_link()` takes no name parameter and never links yellow notices. `detect_block()` returns `challenge:akamai` or `challenge:cloudflare`, which maps to BLOCKED `challenge`, then the host is short-circuited and the manual link emitted. There is no UA spoofing or retry.
4. `normalise_fbi_item()` drops images, physical description, dates of birth, places and remarks. `fbi_public_view()` returns name, aliases, charges, poster URLs and status. The label, severity and confidence constants are in `match_*`.
5. Opt-in: `default_enabled=False` on the module (no parser).
6. Fixtures: the trimmed real FBI capture `wanted_notices__fbi_list_ok.json` (5 posters, all names, handles, slugs, uids and places replaced, checked by `scan_fixtures_pii.py` against 287 real names and aliases with 0 hits). 403 samples: the Akamai derived (INTERPOL) and Cloudflare synthetic (api.fbi.gov) files. Also an empty page (derived), a truncated JSON (derived) and the real `/docs` 200 HTML (not a challenge). FakeHttp, the registry entry for `api.fbi.gov`, the contract test and the P327 lint are for the implementer.

### Matching expectations encoded in the tests (fixture `wanted_notices__fbi_list_ok.json`)
- APT41 + [APT 41, BARIUM, Winnti, Wicked Panda, Brass Typhoon] -> 2 individuals: example-member-two (direct, matched in caution "APT 41 and BARIUM") and example-member-one (link from the group poster).
- "DPRK IT Workers" -> 3 individuals: member-three and member-four come from the group poster's anchors, and member-five links back to the group.
- "Lazarus Group" -> 0, with summary None.

---------------------------------------------------------------------------------------------------------------
## Fixture inventory
| file | origin | case |
|---|---|---|
| adverse_media_rss__gdelt_artlist_ok_synthetic.json | synthetic (documented GDELT artlist shape, fictional company) | ok, clustering, filters, bad records |
| adverse_media_rss__gdelt_empty.json | research-observed `{}` | empty |
| adverse_media_rss__gdelt_rate_limited_429.http.json | live 2026-11-26 (e-mail scrubbed) | rate_limited |
| adverse_media_rss__gdelt_connection_reset.http.json | live 2026-11-26 (transport) | blocked/throttled transport |
| adverse_media_rss__gdelt_error_in_200_synthetic.txt | synthetic | error_in_200 |
| adverse_media_rss__gdelt_malformed_truncated_derived.json | derived | malformed |
| adverse_media_rss__gdelt_rss_ok_synthetic.xml | synthetic | RSS ok |
| adverse_media_rss__gdelt_rss_dtd_entities_malicious_synthetic.xml | synthetic | XML entity bomb refused |
| wanted_notices__fbi_list_ok.json | live 2026-11-26, trimmed + scrubbed | ok (actor/person matches) |
| wanted_notices__fbi_list_empty_page_derived.json | derived | empty/not_found |
| wanted_notices__fbi_list_malformed_truncated_derived.json | derived | malformed |
| wanted_notices__fbi_blocked_403_cloudflare_synthetic.http.json | synthetic (api.fbi.gov is Cloudflare-fronted) | blocked |
| wanted_notices__interpol_blocked_403_akamai_derived.http.json | derived (research 403 + Akamai template) | blocked |
| wanted_notices__fbi_docs_html_200_not_challenge.html | live 2026-11-26 (ray ids zeroed) | HTML instead of JSON, not a challenge |
