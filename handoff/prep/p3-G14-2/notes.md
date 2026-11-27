# Batch p3-G14-2 prep notes: P308 `pivots_search` (Lyzem Telegram search, WikiLeaks search)

I prepared this on 2026-11-26 from the datacenter egress, which is outside Brazil. I used curl's own User-Agent.
I did not read or change anything in the V3LUM repository, and I wrote no module class. I took the contract from
the scratchpad plan: `module_author_contract` section 13 (provider fragments), section 15 (pivot packs, schema
`v3lum.pivot_pack/1`) and section 20 (entity types). I also used the P311 final conditions in
`specs/core_G15.md` and the sibling pivot-pack preps `p2-G14-1` and `p2-G14-2`, so that the extension-key names
stay the same across batches.

"FCn" means final condition n of P308 in `specs/p3-G14-2.md`. A1, A2, A8 and A9 are the rules in
`specs/_common.md`.

## Folder contents

| path | content |
|---|---|
| `fixtures/pivots_search__pack_draft.json` | Draft of `v3lum/data/pivot_links/search.json`: 2 links that pass the lint today. |
| `fixtures/pivots_search__pending_after_tier_review.json` | Lyzem keyword/company and subject links, which become active once the registry records `lyzem.com` as community or trusted. Also holds the excluded entries, each with its reason. |
| `fixtures/pivots_search__registry_draft.json` | Two new provider fragments (`lyzem`, `wikileaks`) in schema `v3lum.provider/1`, with review notes. |
| `fixtures/pivots_search__lint_bad_entries.json` | 33 entries the lint must reject, each with the expected reason. |
| `fixtures/pivots_search__render_golden.json` | Hand-checked expected URLs: one sample per type, plus hostile values (FC3). |
| `fixtures/pivots_search__hostile_values.json` | The FC3 hostile value list (quotes, spaces, NFC/NFD, newline, CR, tab, NUL, bidi, URL metacharacters, dot-segments, `{q}`/`{0}`, long values). |
| `fixtures/pivots_search__lyzem_*.html`, `..._wikileaks_*.html` | Minimised live result pages: ok, empty, space and UTF-8 echo, URL noise, and malformed (truncated). |
| `fixtures/pivots_search__*_not_found_404.http.json` | Live 404 envelopes `{_provenance, url, status, headers, body}`. |
| `fixtures/pivots_search__live_checks.meta.json` | Every request made: status, latency, headers. No bodies. |
| `fixtures/_provenance.json` | The origin of each fixture, plus the facts taken from the raw pages. |
| `code/parsers.py` | Reference semantics: encoders, renderer, URL invariants, pack lint, TLP view, ordering, `doctor --links`, pending activation, and the re-check classifiers. |
| `code/test_parsers.py` | 148 tests. Run `cd code && python3 -m pytest -q -p no:cacheprovider .` |
| `code/build_fixtures.py` | Rebuilds the page fixtures from `raw/live/` with `python3 -I code/build_fixtures.py`. |
| `code/live_check.py`, `code/live_plan_round{1,2}.json`, `code/peek.py` | The polite checker that was used (GET only, no redirects followed, at least 1.2 s apart, at most 5 per host, no cookies) and a read-only viewer for the bodies. |
| `raw/live/` | The unminimised bodies, headers and `_log.jsonl`: 10 requests to 2 hosts. They hold third-party Telegram content, including t.me handles and phone-like strings, and WikiLeaks document excerpts. **Never copy them into the repository.** |

**This module is data, not code.** P308 ships three things:

- the pack file `v3lum/data/pivot_links/search.json`;
- two provider fragments, `v3lum/data/providers/lyzem.json` and `v3lum/data/providers/wikileaks.json`;
- tests.

There is no Module subclass, no network access, no key and no environment variable.

---

## 0. Read this first: decisions and contract gaps

1. **Extension keys (proposed; the contract is frozen).** The pack uses two per-link keys beyond the frozen list.
   - **`seed_only: true`** (FC10): the link renders only for analyst-typed seeds. Batch p2-G14-1 proposes the same
     name for its touches_target links.
   - **`warning: "<text>"`** (FC8 banner and FC10 caution marker): batch p2-G14-2 proposes the same name.
   - Check whether the frozen loader rejects unknown keys or ignores them:
     - If it rejects them, the pack cannot load until the keys are added through `docs/contract_additions/`.
     - If it ignores them, nothing enforces FC10. Core must then implement the seed-only and caution behaviour, and
       tests must cover it.
   - Reference behaviour is `parsers.link_view`:
     - `seed_only` with any provenance other than `seed` gives `hidden`, with reason `seed_only`.
     - `warning` adds the badge `caution` and the text.
   - Fallback if no key can be added:
     - FC10 can be met in core by a pack-level rule: every link of the `search` pack is seed-only and gets the
       caution badge.
     - The banner then goes in the label. The label already says "WikiLeaks - documents ...", so append
       " (leaked documents: open manually and handle per policy)".
2. **Lyzem ships with `domain` only. `url` is left out on purpose (FC9).**
   - FC9 limits Lyzem to IOC values (domain, url) until the reviewer records community tier. That is an upper
     bound, not a requirement to template both.
   - Live result: Lyzem tokenises the query and ORs the terms.
     - `q=https://example.com/` returned **1,835,042** results, highlighted on `https`.
     - `q=CVE-2021-44228 log4j` returned 235,004.
     - `q=example.com` returned 38 exact mentions.
   - A url link would therefore be noise. Add it only if core gains a placeholder that extracts the host
     (proposed `{url_host}`). The domain link already covers the host.
   - The Lyzem link uses **`{domain}`** (validated, IDNA), not `{q}`. Only a syntactically valid domain can reach
     the unknown-tier host; free text cannot (FC4).
   - Side effect: an IDN domain is sent as punycode (`xn--bcher-kva.example`), so Telegram messages that write it
     in Unicode are missed. This is rare and acceptable. If wanted later, add a second link with `{idn}` under the
     same tier rule.
3. **The pending Lyzem entries** (FC5, FC9) are in `pivots_search__pending_after_tier_review.json`. They must not
   be in `search.json` while the tier is unknown, because the lint rejects them (FC4).
   - `lyzem_telegram_search` takes keyword and company_name, with `privacy: false`.
   - `lyzem_telegram_subject` takes person_name and username, with `privacy: true` (FC9).
   - When the reviewer records `tier: community` with `tier_reviewer` and `tier_date`:
     - legal_dpo also records `personal_data_review` (A8) for the subject entry;
     - insert both entries after `lyzem_telegram_domain`. `parsers.activate_pending` shows the order (FC6).
   - The two kinds stay separate links because `privacy` is set per link. A mixed link would hide the keyword
     links behind the opt-in. The lint enforces this.
4. **WikiLeaks takes `company_name` and `keyword` only** (FC8).
   - Research C0693 also listed person_name, email and domain.
   - person_name, username and email are forbidden (people search over leaked data).
   - `domain` is not in the FC8 list, so it is left out. An analyst can still type a domain as a keyword.
   - The template is the search page only. The lint rejects document paths and the `wikileaks.org` host
     (rule 3: link only, nothing ingested or stored).
5. **Personal-value guard for free text (proposed core behaviour).** A keyword or company_name that contains any
   of the following does not render (`parsers.personal_marker`):
   - a CPF: any formatted CPF shape, or a bare 11-digit run with valid check digits;
   - an e-mail address;
   - a phone number.

   Reasons: P311 cond 6 says a CPF never appears in a link, and FC8 forbids people search on WikiLeaks. Typing an
   e-mail address as a "keyword" would get around both. If core `links.render` has no such guard, add it, or at
   least the CPF part, which is binding.
6. **Value hygiene.** `_clean_free_text` refuses:
   - control characters (newline, CR, tab, NUL);
   - bidi override and isolate characters (U+202A..202E, U+2066..2069, U+200E/F). They could spoof how the value
     reads in "opening sends <value> to <host>";
   - empty values, dot-only values and values over 200 characters.

   It NFC-normalises first, so the NFD form `Ação` encodes like the NFC form. The bidi refusal is proposed; the
   control-character refusal matches the sibling batches.
7. **`{q}` semantics.**
   - The reference is `quote(v, safe='')`. Both hosts accepted `%20` and UTF-8 percent-encoding live:
     - Lyzem echoed `CVE-2021-44228 log4j`;
     - WikiLeaks echoed `"Ação" example`, where the quotes acted as a phrase operator and gave 52 results.
   - If core `{q}` keeps `quote`'s default `safe='/'`, a `/` stays literal. Both templates put the value in the
     query, so this is harmless here (`check_rendered_url` still passes).
   - WikiLeaks' own pagination uses `+` (`/advanced?query=Banco+do+Brasil&page=2`), so `{qp}` would work too. It
     is not needed.
8. **Registry fragments** (FC4, FC5): both are new. No seed, owner or sibling batch declares these hosts.
   - **lyzem**:
     - `tier: unknown`, with no reviewer or date yet (FC5: "pending review").
     - Evidence for the reviewer: no operator name, no terms or privacy link on the search page, and third-party
       ads (an `.onion` crypto link in the menu and an "AD to report" dialog).
     - A8 community needs an identifiable operator, public terms and a track record of at least 2 years. Nothing
       seen live shows those, so the reviewer must find the evidence elsewhere or keep unknown.
   - **wikileaks**:
     - `tier: community` as FC5's initial value. `tier_reviewer` holds a placeholder ("P308 council ... registry
       reviewer to confirm"). Replace it with the real reviewer.
     - `sensitive: true` is a conservative default, because the collections hold leaked personal data. It has no
       effect on a link-only provider, but it forces a P145 sanitizer if anyone automates it later.
   - **`sources: {}`** for both. V3LUM consumes no data from either host, so neither is a registry *source* of
     the pack. A1 says a disclosure-'none' module with no registry source declares terms='open', which is the
     council's P308 terms.
     - If the registry contract test requires at least one source per provider, add
       `web_search: {terms: {class: "open", evidence_url: null, ...}}` the way p2-G14-2 does.
     - Do not use `unknown` there: it would push the pack's derived terms to unknown and disable it.
   - Flags `publishes_queries` and `reuses_queries` are false on both. Nothing proves them either way, because
     neither site publishes terms. No public recent-searches page was seen. Lyzem's "Blank for random" shows
     random items, not queries.
9. **Category.** Both links use `category: "search"`, from the frozen enum. With one category, FC6's "group by
   analyst question, verified first" reduces to file order: Lyzem first, then WikiLeaks. The lint checks this
   order.

---

## 1. Module P308 `pivots_search`

### Sources and exact templates

| id | template | entity_types | host (tier) | verified / checked_at | privacy | extension keys |
|---|---|---|---|---|---|---|
| `lyzem_telegram_domain` | `https://lyzem.com/search?q={domain}` | domain | lyzem.com (**unknown**, pending review) | true / 2026-11-26 | false | `seed_only`, `warning` = `LYZEM_WARNING` |
| `wikileaks_search` | `https://search.wikileaks.org/?query={q}` | company_name, keyword | search.wikileaks.org (community, to confirm) | true / 2026-11-26 | false | `seed_only`, `warning` = `leaked documents: open manually and handle per policy` |
| *pending* `lyzem_telegram_search` | `https://lyzem.com/search?q={q}` | keyword, company_name | lyzem.com (needs community) | true / 2026-11-26 | false | same as Lyzem |
| *pending* `lyzem_telegram_subject` | `https://lyzem.com/search?q={q}` | person_name, username | lyzem.com (needs community + personal_data_review) | true / 2026-11-26 (endpoint; verified with non-personal values only) | **true** | same as Lyzem |

- **Method:** GET, opened by the analyst's browser.
- **Auth:** none. **Key env var:** none.
- **Static fields:** every link has `publishes: false`, `touches_target: false`, `login_required: false` and
  `antibot: false`. No CDN or anti-bot was seen on either host.
- **Parameters seen on the pages, not used:**
  - Lyzem: `f=all|channels|groups|bots|telegraph|messages`, `per-page`, `p`.
  - WikiLeaks: `exact_phrase`, `any_of`, `exclude_words`, date ranges, `publication_type[]`, `order_by`.
  - Keep the templates minimal. Any extra parameter must pass `check_rendered_url`.

### Observed live behaviour (2026-11-26, datacenter egress, curl default UA)

| UTC | request | status | total s | bytes | server / cache |
|---|---|---|---|---|---|
| 10:43:18 | lyzem.com/robots.txt | 404 (`404 page not found`, text/plain) | 0.66 | 19 | Caddy |
| 10:43:20 | search.wikileaks.org/robots.txt | 404 (HTML "Not Found") | 1.20 | 198 gz | nginx + Varnish 7.7, `cache-control: public, max-age=1200` |
| 10:43:23 | lyzem.com/search?q=example.com | 200, 38 results, 10 items | 0.86 | 24,931 | Caddy |
| 10:43:25 | search.wikileaks.org/?query=Banco%20do%20Brasil | 200, 9,196 results, 20 items | 1.31 | 13,704 gz | nginx + Varnish |
| 10:43:27 | lyzem.com/search?q=zqxvkjw9183pt | 200, `0 results` | 0.83 | 11,842 | Caddy |
| 10:43:29 | search.wikileaks.org/?query=zqxvkjw9183pt | 200, `0 results`, "No filters available" | 1.29 | 10,115 gz | nginx + Varnish |
| 10:44:27 | lyzem.com/search?q=CVE-2021-44228%20log4j | 200, 235,004 results (OR-matched) | 1.02 | 22,391 | Caddy |
| 10:44:29 | search.wikileaks.org/?query=CVE-2021-44228 | 200, 0 results | 0.92 | 10,116 gz | nginx + Varnish |
| 10:44:31 | lyzem.com/search?q=https%3A%2F%2Fexample.com%2F | 200, 1,835,042 results (matched `https`) | 1.09 | 24,768 | Caddy |
| 10:44:34 | search.wikileaks.org/?query=%22A%C3%A7%C3%A3o%22%20example | 200, 52 results, echo decoded | 1.24 | 14,188 gz | nginx + Varnish |

**Blocks, errors and limits**

- Neither host sent rate-limit headers (`x-ratelimit-*`, `ratelimit-*` or `retry-after`).
- No challenge, block page, redirect or login wall was seen.
- No robots.txt exists on either host (both return 404).

**Lyzem results page**

| element | live markup |
|---|---|
| title | `Search results` |
| echo | `<input ... name="q" ... value="...">` |
| count line | `<p class="is-size-6"> N results – Xms </p>` (no thousands separator) |
| items | `<li class="search-result">` with a `search-result-type-wrapper` |
| plain item | `title="post\|article\|group\|channel\|bot"` |
| profile item | `search-result-with-profile" data-profile-link="https://t.me/<handle>" title="channel - with profile"` |

- One group description came back double-encoded (UTF-8 mojibake). The parser only counts items, so this does
  not affect it.

**WikiLeaks results page**

| element | live markup |
|---|---|
| title | `Search WikiLeaks` |
| echo | `<input type="text" name="query" value="...">` and `Searching for <i>...</i>` |
| count | `<div class="total-count"><span>9,196 results </span>` |
| per-release facets | `<label ... class="label">Plusd</label><div class="total">311</div>` |
| no hits | `No filters available` |
| items | `<div class="result">` holding title, excerpt, leak label and dates. The parser never extracts these (rule 3). |

**Not observed, so no fixture was invented:**

- error-in-200;
- 429 or other rate limiting;
- challenge, CAPTCHA or other block pages;
- login wall.

`classify_check` handles these, and they are tested with inline samples.

### Recommended settings

| setting | value | why |
|---|---|---|
| max_requests | 0 | It is a pack (FC1). V3LUM never requests these URLs. |
| expected_latency | ~0 s | Rendering takes microseconds. Opening a page manually takes 0.7-1.3 s, as measured above. |
| cache_ttl / min_interval / daily_quota | n/a | No runtime requests. |
| `doctor --links` re-check age | 180 days | FC7 |
| maintainer re-check | at most 1 request/s and 5 requests per host per session | GET only; stop at the first challenge and never bypass it (A9). Classify each answer with `parsers.classify_check(source, status, headers, body, value)`. Re-check with benign values only: a domain (example.com), a CVE, a public company. Never a person name or username, even for `lyzem_telegram_subject`: its endpoint is the same as `lyzem_telegram_search`. |
| default_enabled | True | Council decision; manual links are default-on (A3). |
| disclosure / tier / terms / opsec | none / n/a / open / passive | Council decision. |

### Pivots and attributes to emit

None. The pack creates no entities, attributes or findings, and it never ingests a result (FC8, rule 3). It only
contributes manual links to the report, the per-case manual-pivot page (P311 cond 11) and `v3lum links`.

Fields per link view (`parsers.link_view`):

- `ref`, `label`, `host`, `category`, `verified`, `url`, `where`, `clickable`, `text`, `disclosure`;
- `badges`: `caution`, `unknown operator` for Lyzem, `unverified`, `privacy: analyst-typed seed, case opt-in` for
  the pending subject link;
- `warnings`: the FC8 banner or the Lyzem caution text, plus the RED warning;
- `reason`: `not_applicable`, `seed_only`, `tier`, `privacy_not_seed`, `privacy_opt_in`, `tlp_red` or `max_tlp`.

### Final conditions mapped to code

| FC | what | where |
|---|---|---|
| 1 | Pack in the frozen schema, offline data, `publishes=false` | `pivots_search__pack_draft.json`; `lint_pack` and `lint_link` (keys, booleans, publishes, login, touches_target); tests `test_fc1_*` |
| 2 | AMBER and above: non-clickable text with "opening sends <value> to <host>"; RED: `links_only` with the warning; never auto-opened; `--open` at AMBER and above needs a TTY confirmation naming the host | `link_view` (`where`, `clickable`, `text`, `disclosure`, `RED_WARNING`); `open_decision`; tests `test_fc2_*` |
| 3 | CI renders a sample per declared type plus hostile values; https on the declared host; whitelisted placeholders through the declared encoder; never `str.format`, never `{raw}` | `render_template` (re.sub), `enc_q`, `domain_value`, `template_problems` (stray-brace, `{raw}`, unknown or foreign placeholder, host position, fragment), `check_rendered_url`; `render_golden.json`, `hostile_values.json`; tests `test_fc3_*` |
| 4 | Every host has a registry entry with tier and rationale; unknown tier gets IOC values only (no PERSONAL_TYPES, CNPJ, company names, keywords or other free text) and the `unknown operator` badge | `registry_draft.json`; `lint_link` ("no provider-registry entry", "unknown-tier host takes IOC_TYPES only, never free text", "personal/CNPJ values to an unknown-tier host"); `link_view` reason `tier` and the badge; tests `test_fc4_*` |
| 5 | Initial tiers: WikiLeaks community, Lyzem unknown until recorded | `registry_draft.json`; `activate_pending` only for community or trusted; tests `test_fc5_*` |
| 6 | Group by question, verified first, then file order (Lyzem, then WikiLeaks); terminal shows at most 8 per seed | `order_views`; the `lint_pack` order rule; tests `test_fc6_*` |
| 7 | Verified links carry `checked_at`; `doctor --links` (offline) lists unverified links and links older than 180 days; ships in phase 1 | `lint_link` (date check), `doctor_links`; re-check tooling `classify_check`; tests `test_fc7_*` and `test_recheck_*` |
| 8 | WikiLeaks: company names and keywords only, never person names or usernames; link only; banner | `lint_link` WikiLeaks rules (types, banner, search path only); `personal_marker` guard; `parse_wikileaks_results` extracts counts only; tests `test_fc8_*`, `test_recheck_wikileaks_ok_counts_only` |
| 9 | Lyzem: person-name and username links are privacy=true, entered subjects with opt-in only; IOC values only until community | Pack ships `domain` only; pending file; `lint_link` Lyzem rules; `link_view` (`privacy_not_seed`, `privacy_opt_in`, `tier`); tests `test_fc9_*` and `test_fc4_fc9_*` |
| 10 | All links only for analyst-typed seeds, with the caution marker | `seed_only` and `warning` keys; `lint_link` ("seed_only must be true", "caution marker"); `link_view` reason `seed_only` and badge `caution`; tests `test_fc10_*` |

### Conditions that cannot be met as written

- **FC9 `url`.** It is allowed, but it would be a degenerate link (see section 0.2). The pack meets FC9 with
  `domain` only, and the `url` entry is parked with the condition that would unblock it.
- **FC5 and the pending Lyzem entries.** These need a human registry reviewer, plus legal_dpo for
  `personal_data_review`. No code can record that. Until it happens, the subject and keyword links stay out of
  the pack.
- **FC10 and FC8 rendering.** They need the `seed_only` and `warning` keys, or an equivalent pack-level rule in
  core (section 0.1). With the frozen key list alone, the data cannot express them.
- **FC2 and FC6.** These are core renderer behaviour (P311, A2). This batch ships the data and reference tests
  only. The implementer should assert them against `v3lum.core.links` with the same cases as
  `test_fc2_*` and `test_fc6_*`.

### Terms class per source (as the spec states it)

| source | terms |
|---|---|
| P308 pack (council) | **open**: disclosure none, link only |
| C0692 Lyzem | "site terms". No terms page is linked from the search page, and no robots.txt exists (404). |
| C0693 WikiLeaks | "site terms". No terms page is linked from the search page, and no robots.txt exists (404). |

Under A1 the pack has no registry source, so it declares terms='open'. Section 0.8 explains why the provider
fragments have empty `sources`.
