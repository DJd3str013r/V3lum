# p3-G11-1 prep notes (group G11 cti_framework)

Modules: `d3fend` (P294) and `malpedia` (P296).

Prepared on 2026-11-26 from the datacenter egress. The live checks ran from 09:33 to 09:40 UTC: 11 keyless GETs in total, 6 to d3fend.mitre.org and 5 to malpedia.caad.fkie.fraunhofer.de. Requests to the same host were at least 7 s apart, and curl used its default client identity. Nothing here imports V3LUM or reads the V3LUM repository.

## Layout

- `fixtures/`: 20 fixtures named `<module>__<case>.<ext>`, plus `MANIFEST.json`.
  - The manifest records, per fixture: origin, upstream URL, licence, SHA-256, size and a note.
  - `*.http.json` files are `{status, headers, body}` captures, used where the status matters.
  - **derived** fixtures are edited copies of real ones, and their manifest origin says so. Examples: a renamed CSV column, the bindings removed, a header-only CSV.
  - There are no synthetic fixtures. The marker cases that were never observed live (429/401/403/5xx bodies) are inline test inputs and are labelled as such in `test_parsers.py`.
- `raw/`: unminimised downloads, response headers (Set-Cookie dropped), `live_log.tsv` and the full-data measurements `measure_d3fend.json` / `measure_malpedia.json`.
  - **Never copy `raw/` into the repository.**
  - `raw/` holds the 14.7 MB D3FEND export, which includes SPARTA rows under a separate Aerospace licence.
  - It also holds full Malpedia answers (CC BY-NC-SA). Their `library_entries` carry author surnames, and their reference lists include individual researchers' blogs.
- `code/parsers.py`: pure parsers, index builders, URL guards and marker helpers.
  - Standard library only (`csv io json re unicodedata urllib.parse`). The source is ASCII, with no I/O and no network access.
- `code/test_parsers.py`: 162 tests. Run `cd code && python3 -m pytest -q -p no:cacheprovider .` and expect **162 passed**.
- `code/build_fixtures.py`: rebuilds `fixtures/` from `raw/`, the research samples and the misp-galaxy clone. Run it with `python3 -I build_fixtures.py`.
  - The rebuild is deterministic: `MANIFEST.json` is byte-identical across rebuilds (checked).
- `code/measure_full.py`: full-data measurements, written to `raw/measure_*.json`.
  - It covers the D3FEND index build time and memory, the controls-per-technique distribution, the API-versus-export cross-check, and Malpedia list/galaxy coverage.
- `code/fetch.sh`: the live-check curl wrapper. It sets `--max-time 20`, keeps TLS verification on, uses the default proxy and drops Set-Cookie lines.
- `code/peek.py`, `code/html_text.py`, `code/analyse_d3fend.py`: read-only viewers. Run them with `python3 -I`.

### Marker convention (same as p1-G11-1)

Helpers return `None` or `'<kind>: <reason>'`, where kind is one of `error | rate_limited | quota | blocked | unavailable`. `marker_kind()` extracts the kind.

A marker never means EMPTY. EMPTY (no mapping, not found) is the result's `empty` / `no_mapping` / `not_found` flag.

| situation | helper | result |
|---|---|---|
| D3FEND API 404 (missing per-technique JSON) | `d3fend_api_marker`, `parse_d3fend_api` | `None` + `no_mapping=True` (FC2) |
| D3FEND API 200 with no countermeasure binding | `parse_d3fend_api` | `None` + `no_mapping=True` |
| D3FEND API 200 HTML / malformed JSON / wrong shape | `parse_d3fend_api` | `error: HTML instead of JSON` / `error: malformed JSON (...)` / `error: unexpected ... shape` |
| D3FEND 429 / 401,403,451 / 5xx / other | `d3fend_api_marker` | `rate_limited: HTTP 429 (Retry-After N)` / `blocked: HTTP n` / `error: HTTP n` |
| D3FEND health probe T1059 answers 404 | `d3fend_health_marker` | `unavailable: D3FEND API answered 404 for T1059 (API moved?)` |
| export is the GitHub Pages 404 HTML / header drift / no ATT&CK rows / empty | `validate_d3fend_mappings_csv` | `error: HTML instead of CSV` / `error: D3FEND export format changed (missing ...)` / `error: no ATT&CK rows ...` / `error: empty dataset` |
| Malpedia 404 `{"detail":"No <X> matches the given query."}` (also behind a 200) | `malpedia_marker` | `None` + `not_found=True` |
| Malpedia find/actor `[]` | `parse_malpedia_find_actor` | `None` + `empty=True` |
| Malpedia 429 (DRF throttle) | `malpedia_marker` | `rate_limited: HTTP 429 (Retry-After N) - <detail>` |
| Malpedia 401/403 with token wording | `malpedia_marker` | `error: authentication failed (<detail>)` |
| Malpedia 403 otherwise | `malpedia_marker` | `blocked: HTTP 403 (<detail>)` |
| Malpedia 200 HTML / other `detail` in 200 / 404 HTML page | `malpedia_marker` | `error: HTML instead of JSON` / `error: API message in 200 (...)` / `error: HTTP 404 HTML page (endpoint moved?)` |

No challenge page, CAPTCHA or geo-block was seen on either host. Nothing was retried with other headers.

## Live check summary (2026-11-26, datacenter egress)

| # | host | request | result | latency | notes |
|---|---|---|---|---|---|
| 1 | d3fend.mitre.org | `/resources/` | 200 HTML, 181 KB | 0.39 s | GitHub Pages via Fastly (`server: GitHub.com`, `via: 1.1 varnish`) |
| 2 | d3fend.mitre.org | `/api-docs/` | 200 HTML, 215 KB | 0.30 s | lists `/api/offensive-technique/attack/[technique].json`, `/api/version.json`, `/api/ontology/inference/d3fend-full-mappings.csv` |
| 3 | d3fend.mitre.org | `/api/ontology/inference/d3fend-full-mappings.csv` (the unversioned "latest" link on /resources/ontology/) | **404**, GitHub Pages "Page not found" HTML (5,254 B gzip) | 0.47 s | the advertised latest link is broken, so use the versioned path |
| 4 | d3fend.mitre.org | `/resources/ontology/` | 200 HTML | 0.49 s | prerendered `/api/version.json`: ontology **1.6.0**, release 2026-08-31, ontology sha256 `744a9fda...6804`, UI 0.26.1; versioned downloads from 0.17.0 to 1.6.0 |
| 5 | d3fend.mitre.org | `/ontologies/d3fend/1.6.0/d3fend-full-mappings.csv` | 200 `text/csv`, **591,115 B gzip -> 14,751,588 B** | 0.55 s | 16,249 rows, 27 columns, CRLF; weak ETag `W/"6ab493b2-e11764"`, Last-Modified 2026-09-24, `cache-control: max-age=600`; sha256 (decompressed) `2b86a5a1...d79f` |
| 6 | d3fend.mitre.org | `/api/offensive-technique/attack/T1059.json` | 200 JSON, 2,366 B gzip -> 38,654 B | 0.25 s | 16 SPARQL bindings (15 with a countermeasure), `description`, `subtechniques`, `framework` blocks; weak ETag; no rate-limit headers |
| 7 | malpedia.caad.fkie.fraunhofer.de | `/api/list/families` | 200 JSON, 19,174 B gzip -> 60,487 B | 1.24 s | 3,846 ids, all `<platform>.<name>` (18 platforms) |
| 8 | malpedia | `/api/get/family/win.emotet` | 200 JSON, 15,008 B gzip -> 40,350 B | 1.16 s | 325 urls, `library_entries` (author-keyed) present, body has no id field |
| 9 | malpedia | `/api/get/actor/apt28` | 200 JSON, 17,801 B gzip -> 54,926 B | 1.05 s | 41 families (with urls), 56 refs, 38 synonyms incl. `G0007`, 4 `related` |
| 10 | malpedia | `/api/get/family/win.zz_no_such_family_0000` | **404** `{"detail":"No Family matches the given query."}` | 0.77 s | DRF not-found shape |
| 11 | malpedia | `/api/find/actor/zz_no_such_actor_0000` | 200 `[]` | 0.89 s | no match = empty list (not 404) |

Malpedia headers: `server: nginx`, `Cache-Control: max-age=7200`, `Allow: GET, OPTIONS`, `Vary: Accept, Cookie`. There are no rate-limit headers and no cookies were needed.

Two cases were not requested, to stay within the ~5-requests-per-source cap:

- **D3FEND per-technique 404.** The host is static GitHub Pages, so a missing `T*.json` gets the same GitHub Pages 404 page as request 3. That page is fixture `d3fend__api_no_mapping_404.http.json`.
- **Malpedia positive find/actor.** The research sample from 2026-11-25 is used instead.

## P294 `d3fend` - MITRE D3FEND (ATT&CK -> defensive techniques)

**Council:** approved P3, default_enabled=True, provider_tier trusted, terms **open**, opsec passive. Input `mitre_technique`, no produced entity types. Auth none; no key env var.

### Sources and exact endpoints

1. **Primary (FC1): bulk export through the dataset manager.**
   - Version discovery: `GET https://d3fend.mitre.org/api/version.json`, parsed by `parse_d3fend_version`. Use `ontology_version`.
   - Dataset URL: `https://d3fend.mitre.org/ontologies/d3fend/{ontology_version}/d3fend-full-mappings.csv`, from `d3fend_dataset_url`. Pinned 1.6.0.
   - Do **not** register `/api/ontology/inference/d3fend-full-mappings.csv`: it answered 404 (`D3FEND_LATEST_URL_BROKEN`).
   - Suggested `register_dataset(name="d3fend_mappings", url=d3fend_dataset_url(v), ttl=D3FEND_DATASET_TTL (30 d), licence="MITRE D3FEND Terms of Use", terms_class="open", attribution=d3fend_notice(), validate=validate_d3fend_mappings_csv, expect="csv", min_bytes=5_000_000, max_bytes=64_000_000, large=True, pinned_sha256=D3FEND_PINNED_SHA256 when pinned to 1.6.0)`.
   - At 14.7 MB the file is above the A6/AR10 5 MB limit, so it is fetched only by `v3lum data update d3fend_mappings`.
   - Without the dataset the module returns UNAVAILABLE `dataset` ("run v3lum data update d3fend_mappings"). Consider adding it to `--essential`, because the module is default-enabled.
   - The transfer is gzip content-encoded (591 KB), so `requests` decompresses it. `max_bytes` must count the decompressed size.
2. **Post-processing.** Build the compact index after the download:
   - `build_d3fend_index(iter_d3fend_mapping_rows(fh), version, source_sha256)`, streamed from the file handle.
   - Measured on 1.6.0: 1.5-2.9 s, peak 6.8 MB.
   - Result: 392 ATT&CK technique ids (326 Enterprise, 66 ICS). That is 1,128,131 B JSON, or 56,553 B gzip.
   - Loading takes 0.02 s and a lookup takes 0.03 ms.
   - Store the index next to the CSV or in its place. Keep the CSV only if SPARTA notices are added (see Warnings).
   - A16/A6 allow bundling only MIT/BSD/Apache-2.0/CC0/CC BY 4.0/IANA/PSL data. The D3FEND licence is MITRE's own royalty-free licence, so **do not bundle** the index under A6 as written. Runtime download only, unless legal adds it to the list.
3. **Fallback (FC2), optional: `GET https://d3fend.mitre.org/api/offensive-technique/attack/{TID}.json`.**
   - Build the URL with `d3fend_api_url`. It sends only a normalised `T####[.###]` id and anything else raises ValueError.
   - Parse with `parse_d3fend_api`. Cache 200 and 404 for 30 days (`D3FEND_CACHE_TTL`).
   - A 404 means no mapping. It is never an error.
   - Pass `specificity` from a loaded index when one exists. Without it, the API-only ranking is plain tactic interleaving: for T1059 it shows File Encryption, Dynamic Analysis, Content Filtering, File Eviction, Restore File.
   - Health check: `d3fend_health_marker` on T1059. There, a 404 means "API moved", which stops a site restructure from silently turning every technique into "no mapping".

### Recommended runtime settings

| setting | dataset module (recommended shape) | API fallback (if kept, separate module) |
|---|---|---|
| disclosure | `none` (works at TLP:RED, FC1) | `third_party` (the technique id goes to d3fend.mitre.org) |
| cache_ttl | dataset ttl 30 d; index loaded per run | 30 d (FC2), 200 and 404 |
| min_interval | n/a (no network in a scan) | 1 s |
| daily_quota | n/a | none published ("fair use"); suggest a soft 500/day |
| max_requests | 0 per scan | 1 per distinct technique, cap 25 per run |
| expected_latency | <0.1 s (local) | 0.5 s (observed 0.25 s) |
| health check | dataset age and validator (doctor) | `d3fend_health_marker` on T1059 |

### Output (FC3)

`d3fend_recommendations(index, technique)` returns one block per technique:

- `section: "recommended controls"` and `severity: "info"`.
- `controls`: at most 5 items `{label, tactic, d3f, d3fend_id, why, link}`.
- `total`, `basis` (exact | parent | subtechniques), `basis_ids`, `dataset_version` and `notice`.
- `link` = `https://d3fend.mitre.org/offensive-technique/attack/{id}/`.

The block emits no pivots and no entities. Suggested attributes on the `mitre_technique` entity are `d3fend_total_controls` and `d3fend_basis`.

Lookup order:

- the technique itself;
- for a sub-technique with no rows of its own, its parent (for example T1059.001 -> T1059);
- for a parent with only sub-technique rows, the union of its subs (39 parents in 1.6.0, for example T1003, T1566, T1110 and T1055).

In 1.6.0, 113 of 392 ids have 5 or fewer controls. The median is 10 and the maximum 37, so the cap matters.

**Ranking.** The ranking is a V3LUM heuristic, not D3FEND's own, and should be documented as such in the report footnote. It is deterministic and runs in four steps:

1. Countermeasures that act on the same artifact the technique uses come first.
2. Then specificity: fewer ATT&CK techniques mapped to the countermeasure across the whole export ranks higher.
3. Then more artifact paths.
4. Ties are broken by interleaving tactics in Harden > Detect > Isolate > Evict > Restore > Deceive > Model order, then by label.

At most 3 of the 5 shown controls may share a tactic. With the full 1.6.0 export, T1059 shows Dynamic Analysis, Emulated File Analysis, Executable Allowlisting, Executable Denylisting and File Encryption. T1486 shows File Encryption, File Analysis, Content Filtering, File Eviction and Restore File. More examples are in `raw/measure_d3fend.json`.

**Links.** The countermeasure page pattern `https://d3fend.mitre.org/technique/d3f:<Name>/` is taken from the api-docs routes. It was **not** live-checked; the technique-page link in FC3 was verified by research.

### Final conditions -> code

| FC | how | where |
|---|---|---|
| 1 bulk export via dataset manager, version recorded, matched locally, disclosure none, TLP:RED | versioned URL from version.json; validator; streaming parser; offline index carrying `version` + `source_sha256`; `dataset_version` on every block | `parse_d3fend_version`, `d3fend_dataset_url`, `validate_d3fend_mappings_csv`, `iter_d3fend_mapping_rows`, `build_d3fend_index`; tests `test_fc1_*` |
| 2 API fallback: only the id, cache 30 d, 404 = no mapping | id normaliser + URL guard; 404 -> `no_mapping` with no marker; 200 without countermeasures -> `no_mapping`; `D3FEND_CACHE_TTL` | `normalize_attack_id`, `d3fend_api_url`, `parse_d3fend_api`, `d3fend_api_marker`, `d3fend_health_marker`; tests `test_fc2_*` |
| 3 <=5 controls, 'recommended controls', INFO, links | hard cap (any `limit` is clamped to 5), tactic cap 3, technique link + countermeasure links | `d3fend_recommendations`, `rank_controls`, `d3fend_technique_link`, `d3fend_countermeasure_link`; tests `test_fc3_*` |
| 4 MITRE copyright + licence text in data/NOTICE, THIRD_PARTY_NOTICES, every report with D3FEND content | `d3fend_notice()` reproduces the ToU text verbatim (checked against the legal_dpo capture of /tou/ on 2026-11-26) plus the ATT&CK trademark/ToU line; attached to every recommendations block | constants `D3FEND_COPYRIGHT`, `D3FEND_LICENCE_TEXT`, `D3FEND_TRADEMARK`, `D3FEND_ATTACK_NOTICE`; `test_fc4_*` |
| 5 trimmed real fixture of the export and of one API answer | `d3fend__mappings_ok.csv` (real 1.6.0 rows, all 27 columns, CRLF) and `d3fend__api_ok.json` (real T1059 answer, unused keys dropped); full-export index slice `d3fend__index_slice.json` | `test_fc5_*`, `test_fc2_api_and_dataset_agree_for_t1059` (API set == export set for T1059) |

**Conditions that cannot be met exactly as written**

- **Disclosure conflict (FC1 vs FC2).** The council metadata says `shares_input=True`, while FC1 asks for disclosure `none` so the module works at TLP:RED. A V3LUM module declares a single disclosure class, so one module cannot be both.
  - Recommendation: `d3fend` = dataset only, disclosure `none`.
  - The per-technique API fallback is then either dropped, or shipped as a separate opt-in `d3fend_api` module with disclosure `third_party` that runs only when the dataset is missing. The parser and helpers are ready for either.
- **FC5 "one API answer".** Met with a real 200 answer. The per-technique **404** was not requested (request cap). Its fixture is the same host's GitHub Pages 404 page, captured on another missing path.
- **FC4 wording.** The ToU footer renders the trademark line as "MITRE D3FEND; and the MITRE D3FEND logo ..." (a stray ';' where the title shows the TM sign). Legal should confirm `D3FEND_TRADEMARK`. The copyright line on the page reads `(c) 2025 The MITRE Corporation.` and is reproduced as `© 2025`.

**Terms class:** `open`. MITRE D3FEND Terms of Use grant a royalty-free licence for research, development and commercial purposes with the notice. Registry evidence: `https://d3fend.mitre.org/tou/`, quote = `D3FEND_LICENCE_TEXT`, checked_at 2026-11-26.

## P296 `malpedia` - Malpedia (families, actors, references)

**Council:** approved P3, **default_enabled=False**, provider_tier trusted, terms **noncommercial** (A1 initial class, binding), opsec passive, disclosure third_party. Inputs `malware_family`, `threat_actor`, `keyword`. Produces `malware_family`, `threat_actor`.

**Auth.** None for the four metadata endpoints. The optional team-account token is read from `V3LUM_MALPEDIA_TOKEN`; the spec also lists `V3LUM_MALPEDIA_KEY`, so treat one as an alias of the other. It is sent only as `Authorization: apitoken <token>` (`malpedia_auth_headers`).

**Live status.** The keyless path is ok. The token tier is **needs_key**: not verified, because there is no account.

### Endpoints (FC2 allow-list, the only ones the builder can produce)

| endpoint key | URL | cache_ttl | use |
|---|---|---|---|
| `list_families` | `GET https://malpedia.caad.fkie.fraunhofer.de/api/list/families` | **7 d** (FC5, binding) | family id validation and name-part resolution |
| `find_actor` | `GET .../api/find/actor/{needle}` (percent-encoded, 1-64 chars, no `/ \ % ? #`, controls or `..`) | 7 d | synonym -> actor id (`name` field), e.g. Hidden Cobra -> `lazarus_group` |
| `get_actor` | `GET .../api/get/actor/{actor_id}` (`[a-z0-9][a-z0-9_.-]*`) | 7 d | actor card |
| `get_family` | `GET .../api/get/family/{platform.name}` | 7 d | family card |

- `build_malpedia_url` raises ValueError for anything else, by construction.
- `malpedia_url_allowed` is the checker for the unit test over the module's URL set and for the P327 lint. It refuses:
  - `/api/get/sample/*`, `/api/list/samples/*`, `/api/get/yara/*`, `/api/list/yara`, `/api/scan/*`;
  - `/api/get/misp`, `/api/get/bib*`, `/api/get/families`, `/api/find/family/*`, `/api/list/actors`, `/api/check/apitoken`;
  - query strings, fragments, `;` params, userinfo, other ports, http, look-alike hosts, `//`, encoded `/` or `..`, NUL.
- Suggested P327 lint patterns for this host: `/api/get/sample`, `/api/list/samples`, `/api/get/yara`, `/api/list/yara`, `/api/scan/`.
- The server's own `max-age` is 7200 s. Caching 7 days stays within the A10 30-day cap.

### Recommended runtime settings

- cache_ttl: as in the table above.
- min_interval: **2 s** (`MALPEDIA_MIN_INTERVAL`). The limit is unpublished, so be polite.
- daily_quota: soft 200/day.
- max_requests per seed: 6. That is 1 `list_families` if the cache is cold, 1 `find_actor`, up to 2 `get_actor` and up to 3 `get_family`.
- expected_latency: **1.5 s** (observed 0.77-1.24 s).
- Health check: `list_families` (cached) must parse with count > 1,000.

### Flow per input type

- **`malware_family`**
  1. Resolve with `resolve_malpedia_family_ids(name, list_ids, galaxy)`: an explicit id first, then the galaxy synonyms (Geodo -> win.emotet, Casbaneiro -> win.metamorfo, Guildma -> win.astaroth), then a name match against the cached list (xagent -> four platform ids).
  2. Call `get_family` for at most 3 ids.
  - `find/family` is not allow-listed, so there is no server-side family search.
- **`threat_actor`**
  1. A valid slug goes straight to `get_actor`.
  2. Otherwise `find_actor(name)`, then `get_actor` for the top 1-2 `actor_id`s.
  - `malpedia_actor_slug` is a best-effort guess, verified only on apt28 and lazarus_group.
- **`keyword`**: `find_actor` plus family resolution (no `get_*` without a resolved id).

### Output, pivots and attributes

- **Family card** (`parse_malpedia_family`): `common_name`, `alt_names` (aliases), `attribution` (actor **names** such as `MUMMY SPIDER`), `description` (<=600 chars), `updated`, `uuid`, ranked report `urls` (cap 10; `url_count` keeps the total; newest year in the path first), `link` (`/details/<id>`, the P300 manual page).
  - Pivots: `("threat_actor", <name>)` for each attribution entry. P295 resolves the names to ids.
- **Actor card** (`parse_malpedia_actor`): `name`, `country`, `synonyms`, `mitre_group_ids` (from synonyms and attack.mitre.org refs, for example `G0007`; pivot to P292 attack_index), `refs` (cap 10, with `ref_count`), `cfr` (suspected state sponsor, incident type, victims, target categories), `attribution_confidence`, `related` (uuid, type, likelihood) and `link` (`/actor/<id>`).
  - Families are sorted by `updated` descending.
  - Pivots: `("malware_family", <family_id>)`. apt28 has 41 families, so cap the pivots (for example 10) and list the rest as text.
- Report URLs should be links in the card, not URL entities. Fetching and IOC extraction from them is an analyst pivot, not automatic.

### Final conditions -> code

| FC | how | where |
|---|---|---|
| 1 noncommercial; off under corporate until a licence_allow entry (written FKIE agreement); research basis -> licence banner | `terms='noncommercial'` (policy core skips it with reason `licence`); banner text with `legal_ref`; ToS quotes for the registry | `MALPEDIA_LICENCE`, `MALPEDIA_TOS_LICENCE_QUOTE`, `MALPEDIA_TOS_AMBER_QUOTE`, `malpedia_licence_banner`; `test_fc1_licence_constants_and_banner` |
| 2 allow-list list/families, find/actor, get/actor, get/family only; no sample/YARA/download URL can be built | allow-list dict + builder that raises + independent checker; parametrised tests over 18 forbidden endpoint keys, 33 forbidden URLs and 19 unsafe values | `MALPEDIA_ENDPOINTS`, `build_malpedia_url`, `malpedia_url_allowed`; `test_fc2_*` |
| 3 token only in the Authorization header; token-tier material TLP:AMBER, kept in the case, never exported | header helper (format-checked, CR/LF refused); URLs can never carry a query; `malpedia_source_tlp` (keyless = clear, token = amber unless the id is also public); `split_token_tier_urls` (URLs only visible with the token -> amber) | `test_fc3_*` |
| 4 corporate path: ids and reference URLs from the bundled MISP galaxy cluster (P295); module only adds live detail; manual pages via P300 | galaxy parser (family id from the `/details/` ref, synonyms, non-Malpedia refs) + resolver; manual links | `parse_galaxy_malpedia_cluster`, `resolve_malpedia_family_ids`, `malpedia_family_link`, `malpedia_actor_link`; `test_fc4_*` |
| 5 list/families 7 d; ids `apt28`/`lazarus_group` and `<platform>.<name>`; opt-in | `MALPEDIA_CACHE_TTL`, id validators (all 3,846 live ids pass); default_enabled False in the module | `test_fc5_cache_and_id_formats` |
| 6 offline tests over trimmed real fixtures without personal data; registry entry per host; registry contract test; P327 lint | 9 malpedia fixtures (5 live captures, 3 research samples, 1 galaxy slice), privacy scan test, manifest hash test; the registry entry, contract test and lint belong to the implementer (inputs: `MALPEDIA_HOST`, the ToS quotes, the lint patterns above) | `test_manifest_matches_every_fixture`, `test_fixtures_carry_no_personal_data_or_secrets` |

**Conditions that cannot be met exactly as written**

- **FC4, actor ids from the galaxy.** The MISP galaxy `malpedia` cluster lists **families only**: 3,683 values, 3,685 family ids, version 25472. Across all galaxy clusters in the 2026-11-25 clone, only **one** link to a Malpedia actor page exists, in `ransomware.json`.
  - Under the corporate profile, family ids and reference URLs do come from the galaxy, but Malpedia **actor ids** do not.
  - The threat-actor galaxy gives names and synonyms, which P295 can use for joins.
  - `malpedia_actor_slug` is only a guess for building the P300 manual link `/actor/<slug>`.
- **FC4, galaxy freshness.** The galaxy lags the live list. 165 live family ids are missing from the galaxy. 4 galaxy ids are not in the live list: `js.unidentified_007`, `py.unidentified_001`, `win.guloader`, `win.zgrat`. This is visible coverage loss under corporate.
- **FC3, token tier.** It could not be verified (needs_key). `split_token_tier_urls` assumes that comparing a keyless answer with a token answer is how "non-public" material is identified, because Malpedia does not label its fields by TLP. Without a keyless copy, everything fetched with the token is amber (`malpedia_source_tlp`). That is the fail-safe reading.
- **FC6, "the 6 Malpedia captures".** Only one of the 6 research captures is truncated: `malpedia_get_family.txt`, cut at 30,000 B, is the malformed case. Two find/actor samples are used as they are. `live_cti__malpedia_families.json` (a 50-id excerpt), `live_cti__malpedia_get_family.json` and `caipora_apis_cti__malpedia_api_actor.json` are superseded by this run's complete live captures of the same endpoints, which were trimmed into the fixtures.

**Terms class:** `noncommercial` (CC BY-NC-SA 3.0). Registry evidence: `https://malpedia.caad.fkie.fraunhofer.de/usage/tos`, with quotes `MALPEDIA_TOS_LICENCE_QUOTE` and `MALPEDIA_TOS_AMBER_QUOTE` from the legal_dpo capture of 2026-11-26. A6: never bundled; runtime only.

## Fixtures

| fixture | case | origin |
|---|---|---|
| `d3fend__mappings_ok.csv` | ok: 63 real rows (T1059 complete 46, T1003.001 x3, T1003.002 x2, T1078 x4 one per tactic, T0855 complete 6 ICS, DE-0006 x2 SPARTA) | live |
| `d3fend__mappings_header_changed.csv` | malformed: format drift | derived |
| `d3fend__mappings_no_attack_rows.csv` | empty: SPARTA-only export | derived |
| `d3fend__mappings_latest_404.http.json` | blocked/not_found: the broken "latest" link, GitHub Pages 404 HTML | live |
| `d3fend__index_slice.json` | ok: index built from the **full** export (real specificity), 7 techniques | derived |
| `d3fend__api_ok.json` | ok: T1059 | live |
| `d3fend__api_empty_bindings.json` | empty: 200 without countermeasures | derived |
| `d3fend__api_no_mapping_404.http.json` | not_found: 404 = no mapping | live (same host's 404 page) |
| `d3fend__api_truncated_malformed.json` | malformed: truncated capture | research sample |
| `d3fend__api_html_200.http.json` | error_in_200: HTML where JSON was expected | live (api-docs head) |
| `d3fend__version_ok.json` | ok: version.json | live (prerendered) |
| `malpedia__list_families_ok.json` | ok: 33 of 3,846 ids | live |
| `malpedia__find_actor_ok.json` | ok: apt28 | research sample |
| `malpedia__find_actor_lazarus_ok.json` | ok: synonym normalisation, two G-ids | research sample |
| `malpedia__find_actor_empty.json` | empty: `[]` | live |
| `malpedia__get_actor_ok.json` | ok: apt28 trimmed | live |
| `malpedia__get_family_ok.json` | ok: win.emotet trimmed | live |
| `malpedia__get_family_not_found.http.json` | not_found: DRF 404 detail | live |
| `malpedia__get_family_truncated_malformed.json` | malformed: truncated capture | research sample |
| `malpedia__galaxy_cluster_slice.json` | ok: MISP galaxy malpedia cluster, 6 values | misp-galaxy clone |

These cases were not observed live: rate_limited, blocked or challenge pages, and error_in_200 for Malpedia. Their markers are tested with inline inputs.

**Scrubbing.**

- Malpedia `library_entries` (author surnames), `notes`, `sources`, `name-attribution` and the other unused meta keys were dropped.
- Report URLs were kept only from organisation domains (allow-list in `build_fixtures.py`), so no individual researchers' blogs remain.
- The galaxy `authors` list (real names) was dropped.
- No e-mails, phones, CPFs, cookies or tokens appear in any fixture; a test enforces this.

## Warnings for the implementer

1. **One disclosure per module.** Keep `d3fend` dataset-only (disclosure `none`), and put any API fallback in a separate opt-in module. See the D3FEND FC table above.
2. **D3FEND is >5 MB, so runtime only.**
   - Use `v3lum data update`, never a download mid-scan. Without the dataset the module returns UNAVAILABLE `dataset`. Because it is default_enabled, add it to the `--essential` hint.
   - Do not bundle the index: the MITRE licence is not on the A6 bundle list. Legal could add it, since the licence is permissive with a notice.
3. **SPARTA content in the export.** The export carries 624 SPARTA rows (Aerospace Corporation, separate royalty-free licence with its own copyright and licence notice). The index drops them (`technique_id` None).
   - If the raw CSV is kept on disk, add the SPARTA notice to data/NOTICE, or delete the CSV after the index build and keep only its sha256.
   - The test fixture keeps 2 SPARTA rows; its MANIFEST licence names SPARTA.
4. **ATT&CK content.** Technique labels in the index and the API answers are ATT&CK content, so `d3fend_notice()` includes the ATT&CK trademark/ToU line. Reuse P292's ATT&CK notice entry where one exists.
5. **Unversioned "latest" link.** `/api/ontology/inference/d3fend-full-mappings.csv` answers 404 although /resources/ontology/ advertises it. Always resolve the version through `/api/version.json`.
6. **Malpedia licensing.**
   - Malpedia is noncommercial (CC BY-NC-SA 3.0) and off under the corporate profile until legal records a written Fraunhofer FKIE agreement in licence_allow. Under research it runs with `malpedia_licence_banner(legal_ref)`.
   - The 6 Malpedia fixtures with Malpedia content (list, two find/actor, get/actor, get/family, truncated family) are small CC BY-NC-SA excerpts with attribution in MANIFEST. Legal should confirm that test fixtures inside the internal repo are acceptable; they are not a bundled dataset in the A6 sense. The galaxy slice is CC0/BSD.
7. **No binaries, ever.** The allow-list makes sample and YARA URLs impossible to build. Keep `malpedia_url_allowed` as the HttpClient-level assertion as well as the lint input.
8. **Family bodies carry no id.** The `get/family` body has no family id, so pass the requested id to `parse_malpedia_family`.
9. **Not-found shapes.** Malpedia returns `{"detail": "No Family matches the given query."}` with 404, and find/actor returns `[]` with 200. Both mean EMPTY. Any other `detail` is an error marker.
10. **Token variable name.** The spec lists two env var names for one optional token (`V3LUM_MALPEDIA_TOKEN`, `V3LUM_MALPEDIA_KEY`). Pick one canonical name in the key registry and accept the other as an alias.
