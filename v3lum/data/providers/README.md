# Provider registry fragments (`v3lum.provider/1`)

Every host V3LUM contacts and every feed a module reads belongs to exactly one **provider** described
here. `v3lum/core/providers.py` merges the files of this directory at load time (sorted by file name)
into one registry (AR11) that drives host enforcement, licence and TLP gates, HTTP profiles, quotas,
error-in-200 markers, keys, scoring and doctor.

Problems never crash the tool: they are listed in `providers.registry().errors` and the offending
provider or extension is **left out** (fail closed: its hosts stay unregistered, so modules needing it
cannot register). `tests/test_providers_registry.py` and the registry contract test require
`errors == []` on the shipped tree.

**Ownership rule: one owning package per provider fragment; others extend it.** A package never edits
another package's `<id>.json`; it adds a `<id>__<suffix>.json` extension instead. Shared hosting
platforms (GitHub, ...) are core fragments that packages extend with their dataset sources.

## The three file kinds

| file name | schema | content |
|---|---|---|
| `<provider_id>.json` | `v3lum.provider/1` | one provider; `id` equals the file stem |
| `<provider_id>__<suffix>.json` | `v3lum.provider-ext/1` | `{"schema", "extends": "<provider_id>", "hosts": [...], "sources": {...}, "error_markers": [...]}` - **adds only**; a host, source id or marker id that already exists is an error and the whole extension is skipped |
| `_set_<name>.json` | `v3lum.provider-set/1` | `{"schema", "providers": [<provider objects>]}` - data-driven site lists owned by one package (each object uses the provider schema; `schema` may be omitted inside) |

Programmatic fragments (tests, plugins) go through `providers.register(fragment)` (same validation,
raises `ValueError`) and `providers.unregister(provider_id)`.

## Provider fields (all required unless marked optional)

| field | rule |
|---|---|
| `schema` | `"v3lum.provider/1"` (required in `<id>.json` files; may be omitted inside a provider set and in `providers.register()`) |
| `id` | `^[a-z][a-z0-9_]{1,63}$`, equals the file stem; unique in the registry |
| `name`, `operator` | non-empty text (operator = the legal entity or team running the service) |
| `hosts` | list of lower-case exact host names, IP literals or `*.suffix` wildcards (suffix with >= 2 labels; a wildcard matches strict subdomains only). `[]` for virtual/internal providers. **A host belongs to exactly one provider** (an identical host or wildcard in two providers is an error). Refused: a wildcard over a public-suffix namespace of the bundled PSL (`*.co.uk`, `*.github.io`, `*.amazonaws.com`: hosts there belong to unrelated registrants, so PASSIVE modules could reach arbitrary sites - list the exact hosts) and private, loopback, link-local or reserved IP literals (internal platforms come from `hosts_from_settings`) |
| `hosts_from_settings` | list of setting names whose **https** URL host is added at runtime (internal platforms: `misp_url`, `opencti_url`, `doh_internal`). A configured host that another provider owns is ignored (a community MISP registered as a third-party provider never becomes an internal host) |
| `internal` | boolean: company-operated or contracted platform (A12; modules with disclosure `internal` must use such a provider) |
| `tier` | `trusted` \| `community` \| `unknown` (A8 definitions), with `tier_rationale`, `tier_reviewer` and `tier_date` (`YYYY-MM-DD`) |
| `flags` | object with **all four** booleans: `publishes_queries` (rule 7: never receives values), `reuses_queries` (excluded at TLP:AMBER and above), `fetches_target` (only cached/no-publish modes may be default), `sensitive` (breach/infostealer/people data: sanitizer schema mandatory, cache sanitized or no-store, A4) |
| `personal_data_review` | `null` or `{"basis", "reviewer", "date"}` - required before a provider receiving PERSONAL_TYPES enters the default set |
| `reliability` | `{"grade": "A".."F", "justification"}` (Admiralty; `providers.ADMIRALTY` maps grades to scoring weights) |
| `http_profile` | optional object, see below |
| `quota` | `null` or an object, see below |
| `error_markers` | list of error-in-200 markers, see below (marker ids unique per provider) |
| `keys` | object `key_name -> {"description", "signup_url", "env": ["ALIAS", ...], "multi_key": false, "plan_hint"}`; key names `^[a-z][a-z0-9_]{1,63}$`, unique across providers; `V3LUM_KEY_<NAME>` always works and the `env` aliases are added (config.key_registry()). `multi_key: true` is an error in this build: one key per provider (P332 veto_lift) |
| `sources` | object `source_id -> source`, see below. Modules reference sources as `"<provider_id>.<source_id>"` |
| `notes` | optional text |
| `x_*` | optional free-form extension fields (kept in `Provider.extra`); any other unknown field is an error |

### `http_profile` (P326; consumed by the HTTP client for every host of the provider)

| field | default | rule |
|---|---|---|
| `user_agent` | `null` | `null`/`"neutral"` = setting `user_agent` (`V3LUM/<version>`, identifies neither the organisation nor the analyst); `"contact"` = identifying UA with setting `contact_email` (only where the provider's terms ask for it); `"browser"` = setting `ua_light` (only where a public page needs it, never to pass a bot wall); or a template using only `{version}`, `{contact}` (contact_email), `{contact_url}` (contact_url) and `{app}` (`v3lum`). A provider whose UA needs an empty setting is SKIPPED `config`. Templates that look like a browser UA are refused (use `"browser"`), and so is an identifying UA (`"contact"`, `{contact}`, `{contact_url}`) on a provider of tier `unknown` (P326 cond 5) |
| `accept`, `accept_language` | `null` | sent when the module does not set them (hosts under `.br` get `pt-BR` by default) |
| `timeout` | `null` | seconds |
| `retries` | `1` | 0..5; one retry honouring Retry-After <= 15 s; a block is never retried with other headers |
| `max_bytes` | `null` | response size cap (also for target responses) |
| `ttl` | `null` | HTTP cache TTL in seconds; the effective TTL is `min(ttl, cache_max_age_days, retention_days)` |
| `min_interval` | `0` | seconds between requests per host (politeness = max(module, profile)) |
| `concurrency` | `4` | parallel requests per host |

TTL guidance per data class (`providers.TTL_CLASSES`): DNS 3600 (1 h), RDAP 86400 (24 h), CNPJ 259200
(72 h), sanitized breach payloads 604800 (7 d), crypto 3600 (1 h), sanctions 86400 (24 h). Long-lived
reference data belongs in datasets, not in the HTTP cache.

**Binding host profiles** (`providers.PROFILE_REQUIREMENTS`, whoever owns the host; values must match
exactly except `ttl`, which is a maximum the profile must declare): `rdap.registro.br`, `registro.br` ->
UA `neutral`, Accept `application/rdap+json`, Accept-Language `pt-BR`, ttl <= 86400; `www.sec.gov`,
`data.sec.gov`, `efts.sec.gov`, `nominatim.openstreetmap.org`, `bgp.tools` -> UA `contact`;
`*.wikipedia.org`, `*.wikimedia.org`, `www.wikidata.org`, `query.wikidata.org` -> UA
`V3LUM/{version} (+{contact}) python-requests`; `haveibeenpwned.com`, `api.pwnedpasswords.com` -> UA
`neutral`, `flags.sensitive` true, ttl <= 604800; `isc.sans.edu` -> Accept `application/json`;
`tools.keycdn.com` -> UA `keycdn-tools:{contact_url}`; `checkurl.phishtank.com`, `data.phishtank.com` ->
UA `phishtank/{app}`; `dns.google`, `cloudflare-dns.com`, `dns.quad9.net` -> ttl <= 3600. A
contradicting fragment is a registry error.

### `quota` (P334; budgets are per provider, shared by every module and endpoint of it)

`{"scope": "egress_ip" | "key", "hour", "day", "month", "rate_per_second", "burst" (default 1),
"published": true | false, "evidence_url", "safety_margin" (default 0.8)}`. At least one of hour/day/
month/rate_per_second; limits are the provider's figures (`published: true`, `evidence_url` pointing to
them) or observed ones (`published: false`). Budgets use at most 80% of the limit (`safety_margin` in
(0, 0.8]); keyless (`egress_ip`) budgets are global per installation and egress, never multiplied by
keys, proxies or exits. DoH is never charged.

### Error markers (P321; the same schema as `Module.error_markers` and P331 specs)

```json
{"id": "api_count_exceeded", "statuses": [200], "json_path": null, "equals": null,
 "regex": "API count exceeded", "final_url_regex": null,
 "maps_to": "quota", "reason_code": "quota",
 "reason": "HackerTarget: daily quota exhausted (API count exceeded)"}
```

`id` `^[a-z0-9][a-z0-9_.-]{0,63}$`; `statuses` non-empty list (default `[200]`); at least one matcher:
`json_path` (dotted path) with a non-null `equals` (or a `regex` over that value), `regex` (over the
first 64 KB of the body) or `final_url_regex`; `maps_to` `blocked` | `rate_limited` | `quota` | `error`
(never an absence); optional `reason_code` canonical for that status (blocked: `challenge`, `geo_block`,
`login_wall`, `circuit`, `hostile_host`; rate_limited: `rate_limited`; quota: `quota`; error: `error`,
`timeout`, `sanitizer`); `reason` is human text naming the provider. Detection only: no bypass hints.
Each marker ships one trimmed real fixture with a test.

### Sources (A1/P377 terms evidence; P171 families)

| field | rule |
|---|---|
| `title` | non-empty text |
| `terms` | `{"class", "evidence_url", "quote", "checked_at", "reviewer", "free_plan_business_use"}`: `class` one of `open` < `key-terms` < `license` < `noncommercial` < `unknown` (A1 definitions); `evidence_url` (http/https) and a verbatim `quote` are required unless the class is `unknown` (when the research record has no quote, quote the binding council text and set reviewer `council-1 (A1)`); `checked_at` `YYYY-MM-DD`; `reviewer` required; `free_plan_business_use` `true` \| `false` \| `null` (`null` = decided by `key_plans.<key>`). Contradictions are errors: `open` with `false`, `license`/`noncommercial` with `true` |
| `upstream_family` | e.g. `abuse.ch`, `spamhaus`, `dns` (`^[a-z0-9][a-z0-9._-]{0,63}$`): consensus counts families, never modules |
| `sanitizer` | `null` or `{"keep": ["breaches[].Name", ...], "notes"}` (P145 keep paths: dotted keys, `[]` for list elements, `*` for any key - validated; mandatory for sources of sensitive modules unless the module registers a schema) |
| `dataset` | `null` or the name of the registered dataset served by this source |
| `notes` | optional text |
| `embeds` | optional list of upstream families an aggregator re-serves (FireHOL/IPsum, OTX pulses relaying abuse.ch count as those families) |
| `licensed_alternative` | optional text naming the licensed source that restores the coverage (printed by `doctor --licences`) |

A1 initial classes are binding when a fragment is created: abuse.ch MalwareBazaar, URLhaus, ThreatFox
= `license`; YARAify, Feodo Tracker, SSLBL = `open`; Shodan InternetDB, Shodan CVEDB, VirusTotal public
API, Censys free = `noncommercial`; see `docs/COUNCIL_1.md` (A1) for the rest. A chair may only make a
class stricter.

## Core seeds (owned by WP02)

`core_doh` (virtual DoH chain, source `core_doh.resolvers`), `google_public_dns`, `cloudflare_dns`,
`quad9`, `internal_doh` (setting `doh_internal`), `shodan` (`internetdb`/`cvedb` noncommercial, `api`
key-terms), `iana` (`tlds`), `publicsuffix` (`psl`), `github` (no sources: extend it with your dataset
sources), `abusech` (six sources, family `abuse.ch`), `internal_misp` (`events`, setting `misp_url`),
`internal_opencti` (`graphql`, setting `opencti_url`).
