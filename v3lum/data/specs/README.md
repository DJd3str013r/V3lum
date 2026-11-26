# Declarative specs (`v3lum.spec/1`, P331)

Module contract v2, section 17 (frozen schema) and [docs/contract_additions/WP12.md](../../../docs/contract_additions/WP12.md).
A **declarative spec** is one JSON file `v3lum/data/specs/<name>.json` that describes one GET lookup
against a public API and how its answer maps to the shared vocabulary. `v3lum.core.specs` compiles it
into a **real Module subclass** whose class body declares every contract field of the spec, so
`@register` (the contract lint), the policy gate, quotas, status semantics, the sanitizer and the
registry contract test treat it exactly like a hand-written module. `v3lum info <name>` shows a spec
like any module (terms, tier, hosts) plus its `spec_origin`.

Use a spec for small keyless (or single-key) JSON/NDJSON/CSV/RSS/XML/HTML-embedded-JSON lookups.
Anything that needs logic (several endpoints, decoding, scoring rules, breach data) is a hand-written
module (`docs/MODULE_GUIDE.md`).

## Where specs come from

| origin | spec file | fixtures | loaded when |
|---|---|---|---|
| bundled | `v3lum/data/specs/<name>.json` | `tests/fixtures/specs/<name>/` | the fixtures exist and the spec validates |
| user | `~/.v3lum/specs/<name>.json` | `~/.v3lum/specs/<name>/` | the directory, the spec file and every fixture are owned by the current user and not group/world-writable (AR12), the fixtures exist, the spec validates and it gives `expected.json` on its own fixtures (`specs.check_fixtures`) |

Files starting with `_` or `.` are ignored. The file name equals the spec `name`. A user spec never
replaces a module or a bundled spec of the same name. Problems never crash the tool and each file
loads in isolation (an unreadable, non-UTF-8, oversized (> 512 KB) or otherwise broken file never
stops the others): they are listed in `module.load_errors()` under `spec:<name>`, and under
`spec:<path>` for an unreadable file, a refused directory, a file whose `name` differs from its stem,
and a file whose name is already taken by a module or another spec - a refused file never reports
under the name of a registered class, because the policy gate (POL-02) skips a registered module
whose name carries a `spec:<name>` load error. The spec is not registered. `module.load_modules()` calls `specs.load_specs()` after
importing the module package; user specs are user content like the plugins and are compiled when the
application loads its user directories (the App and the Engine do; `load_modules(user_specs=True)`),
never by a bare `load_modules()` (tests, tools).

## Fields

Every field below is **declared explicitly** (no implicit defaults, like the MUST-declare fields of a
module): a spec missing any of them is refused. `null`/`[]`/`""` are written where the field allows it.

| field | rule |
|---|---|
| `schema` | `"v3lum.spec/1"` |
| `name` | module name `^[a-z][a-z0-9_]{2,63}$` (= file stem) |
| `title`, `description` | non-empty text |
| `category` | one of `module.CATEGORIES` (never `breach_leak`: breach sources are hand-written modules with a P145 schema) |
| `accepts` | non-empty list of canonical entity types (`"ipv4"`, `"domain"`...); never `cpf`, secrets, `text_blob`, `file` or `email_headers` |
| `produces` | entity types the spec may pivot to (every pivot type is listed here) |
| `provider`, `sources` | registered provider id and its `"provider.source"` ids ([providers](../providers/README.md)); the provider may not be internal, sensitive, publishing (`publishes_queries`, rule 7) or declare `hosts_from_settings` |
| `hosts` | literal lower-case host names owned by the providers of the sources (no `*.` wildcards) |
| `terms` | the most restrictive terms class of the sources (A1) |
| `disclosure` | `"third_party"` |
| `opsec` | `"passive"` |
| `access_model` | one of `module.ACCESS_MODELS` (a keyed spec is not `free_noauth_*`) |
| `run_on` | `any` \| `seeds` \| `own_assets` \| `own_assets_only` |
| `requires_keys`, `optional_keys` | keys declared in the `keys` block of the spec's own provider fragment(s): a spec never sends another provider's key to its hosts (legacy keys without a provider are refused) |
| `max_requests` | 1..5 (one request per page) |
| `expected_latency`, `min_interval` | seconds |
| `cache_ttl` | `null` or seconds |
| `absent_statuses` | documented meaningful absences (e.g. `[404]`); never 401/403/407/429/430/451, 5xx or 2xx |
| `error_markers` | error-in-200 markers (provider marker schema); regexes have no unbounded quantifier |
| `manual_link` | `""`, `'<pack>:<link_id>'` or an inline https template (emitted with a BLOCKED result) |
| `default_enabled` | candidate flag (A3): `false` for unknown terms, an unknown-tier provider and profile sites |
| `health_check` | `{"etype", "value", "expect": "ok" \| "empty"}`: an accepted type and its central benign value (`module.BENIGN_VALUES`) |
| `request` | see below |
| `format` | `json` \| `ndjson` \| `csv` \| `rss` \| `xml` \| `html_json` |
| `results` | list of result rules (see below) |
| `multi_match` | `null` or `{"path", "onlyif": null \| {"path", "equals"}}` |
| `found`, `absent` | `null` or `{"path", "equals" \| "regex"}` |
| `findings` | list of finding rules (see below) |

Optional: `reference` (http(s) documentation/terms URL), `tags` (module tags, e.g. `free`,
`reputation`), `notice`, `requires_egress` (ISO country codes, A9) and `notes`; `x_*` keys and
`$comment` are ignored. Any other key is refused.

### `request`

```json
{"url": "https://api.example.test/v1/ip/{value}", "method": "GET", "params": {"format": "json"},
 "headers": {"Accept": "application/json", "Authorization": "Bearer {key:example_key}"},
 "ignored_status_codes": [], "paginate": null}
```

* `url`: `https://` + **one literal host of `hosts`** + `/path?query`. The host is never templated
  (a passive spec never contacts the target), no userinfo, port or fragment. The rendered URL is
  re-checked before every request and `ctx.http` refuses every other host, redirect hops included.
* placeholders (path, query and `params` values only; `re.sub`, never `str.format`):

  | placeholder | value | types |
  |---|---|---|
  | `{value}` | the entity value, percent-encoded (`:` and `@` kept) | any accepted |
  | `{value_q}` | the value, percent-encoded (nothing kept) | any accepted |
  | `{value_qp}` | the value, form-encoded (`quote_plus`) | any accepted |
  | `{domain}` | domain/onion, e-mail domain or URL host name | domain, url, email, onion |
  | `{user}` | e-mail local part, username or handle | email, username and handle types |
  | `{b64}` | base64 of the value | any accepted |

  In `params` the raw value is substituted and the whole query is URL-encoded once.
* `method`: `"GET"` only (no POST of values, rule 7). `data`, `json`, `body`, `auth`, `cookies` are
  refused: the language cannot express request bodies, logins, cookies or CAPTCHA handling.
* `headers`: literal values or `{key:<name>}` (optionally `Bearer {key:<name>}`, also `Token`, `Key`,
  `ApiKey`, `Api-Key`, `Bot`, `SSWS`) with `<name>` in `requires_keys`/`optional_keys`. Credential
  headers are never literal: besides the known credential headers, any header whose name carries a
  credential word (`key`, `token`, `secret`, `auth`, `session`, `signature`, `passw`...: e.g.
  `X-RapidAPI-Key`, `Private-Token`) takes `{key:<name>}` or nothing, so a key is never written in a
  spec file where the central redactor cannot mask it. `Cookie`, `User-Agent`, `Host`, `Referer`,
  `Origin`, proxy and forwarding headers are refused (the provider profile chooses the User-Agent).
  An optional key that is not configured drops its header; a missing required key gives NEEDS_KEY.
* `params`: literal names, never credential-like ones (`key`, `apikey`, `token`, `api_token`,
  `access_key`, `session_id`...: an API that takes its key in the query cannot be a spec); values may
  use placeholders.
* `ignored_status_codes`: statuses that end the lookup without data and without error (e.g. `400`
  for unsupported input); never refusals, failures or 2xx. `204` always counts as ignored.
* `paginate`: `null` or `{"param", "start", "step", "max_pages" (<= 5), "stop_when_empty"}` - pages
  `start, start+step, ...` are requested while they produce values (`stop_when_empty`, default true),
  at most `min(max_pages, max_requests)`.
* request URLs are linted with `lint.forbidden_probe` (account enumeration, password reset, login,
  people-search and submission endpoints are refused: team rules 2, 4 and 7).

### Answers and paths

| format | parsed document |
|---|---|
| `json` | the JSON value |
| `ndjson` | list of the JSON lines (`multi_json`) |
| `csv` | list of rows keyed by the header row (blank and `#` comment lines skipped); an answer that starts like HTML/XML or a JSON object/array is ERROR (could not verify: an error page served with HTTP 200) |
| `rss` | `{"channel": {...}, "items": [...]}` for RSS 2.0, RSS 1.0 (`rdf:RDF`) and Atom (`entry` items); roots and items are matched by local name |
| `xml` | `{root_tag: element}`; an element is its text, or an object with `@attr` keys, one key per child tag (a list when repeated) and `#text`; tags keep their prefix (`dc:date`); an (X)HTML root is ERROR (could not verify) |
| `html_json` | `{"next_data": <__NEXT_DATA__ JSON>, "ld_json": [<application/ld+json objects>]}`; a page with neither is ERROR (could not verify) |

XML is parsed with expat directly: the parser handlers refuse a DOCTYPE or entity declaration the
moment they meet it, before anything is declared or expanded (no entity expansion, no external
entities or DTDs); text that merely mentions `<!DOCTYPE` (an advisory feed's CDATA) is data. JSON
`NaN`/`Infinity` and out-of-range numbers parse as `null`. NDJSON and CSV lines are split on LF only
(U+2028 and friends are legal inside values). Answers above 5 MB, truncated answers and HTTP 202
(accepted, not ready) / 206 (partial) answers are ERROR (could not verify), never 'nothing found'.

Paths are minimal dotted paths (no JSONPath): `a.b` walks object keys, `items[]` iterates a list
(a single object counts as a one-element list), `[]` iterates the root list, `*` takes every value
of an object, a number indexes a list and `@` is the record itself.

### Records, results, presence and findings

* **records**: without `multi_match` the document is the only record; with it, the records are the
  values at `multi_match.path` (a list contributes its items), kept when `onlyif.path` equals
  `onlyif.equals`. Results and finding rules are evaluated per record; `found`/`absent` on the
  document of the first page.
* **results** `[{"key", "pretty_name", "attribute" | "tag" | "pivot", "regex", "match_all", "format"}]`:
  * `attribute`: a vocabulary attribute (core or `v3lum/data/vocab` fragments; never `presence`):
    the first value, or every value with `"format": "as_list"`;
  * `tag`: a vocabulary tag: one info finding per rule, titled `pretty_name`, when a value is truthy;
  * `pivot`: `{"type", "relation", "expand" (default true), "confidence" (default 0.9)}` - type in
    `produces`, relation from the vocabulary; invalid values are dropped, at most `max_pivots`;
  * `regex` (optional): the value is the first group, else the whole match; `match_all` takes every
    value (and every match), otherwise the first one;
  * `format`: `str`, `int`, `float`, `bool`, `lower`, `as_list`, `as_time` (epoch seconds or ms,
    ISO-8601 or RFC 2822 dates -> `YYYY-MM-DDTHH:MM:SSZ`);
  * values are bounded: text is cut to 4096 characters (ending with an ellipsis) and an object or
    list above 64 KB of JSON is dropped; mapping stops at the run deadline or on cancel (partial
    results when something was mapped, else ERROR `timeout`).
* **presence** (`found`/`absent`, tri-state attribute `presence`): `found` when only the found rule
  matches, `absent` when only the absent rule matches or the status is in `absent_statuses`,
  `unknown` otherwise (contradictory or no marker, ignored status). Without found/absent rules an
  absence status gives EMPTY. Errors, refusals, challenges and timeouts are never an absence (rule 5).
* **findings** `[{"when": {"path", "equals" | "regex" | "gte"}, "title", "severity", "criterion", "tags", "confidence"}]`:
  one finding per rule and run (counts and matched values in `data`); `criterion` is mandatory for
  severity >= low (P322); titles are unique and stable (finding ids derive from them).

Equality is the error-marker equality (`"0" == 0`, `"true" == true`, case-insensitive text).

### Regexes

Bounded and reviewed: at most 200 characters; no backreferences or conditional groups; no repeat
inside a repeat unless both are small and bounded; no alternation inside a repeated group (use a
character class); at most one unbounded quantifier (`+`, `*`, `{n,}` or a maximum above 64) - none in
error markers, which scan up to 64 KB; a worst-case backtracking cost within
`specs.REGEX_COST_BUDGET` (`specs.MARKER_COST_BUDGET` for error markers): sequences multiply their
quantifier ranges, alternatives add, and an optional or variable repeat inside a repeated group
(`(a?){24}`, `(\w{1,2}){24}`) or a stack of overlapping quantifiers (`\w{0,64}\w{0,64}\w{0,64}`)
is refused by analysis, so the ReDoS smoke test that follows at load always ends quickly. Values are
cut to 512 characters before matching.

### Status semantics

The P321 classifier runs first (`ctx.http.check`): the spec's and the provider's error markers, then
challenge/geo-block/login-wall fingerprints. A challenge ends BLOCKED with the rendered `manual_link`
(A9); quota and rate-limit markers end QUOTA/RATE_LIMITED; other classified errors end ERROR. A later
page that fails keeps the earlier pages (rate limit, quota, deadline and request cap make a partial
run; a block or error is noted in the result's error text). The request's source is never queried
when the policy removed it from `ctx.allowed_sources` (SKIPPED `licence`).

## A3/A5/A8 rules

* `terms: "unknown"` or an unknown-tier provider => `default_enabled: false`; an unknown-tier
  provider accepts IOC types only (never PERSONAL_TYPES, company ids or keywords, at any TLP).
* **profile-site specs** (accepting `username` or a handle type, or sending the local part of an
  e-mail as a handle with `{user}`) follow the A5 username rules:
  `run_on: "seeds"`, `default_enabled: false`, trusted/community provider, a `found` rule plus an
  `absent` rule or `absent_statuses`, `max_requests: 1` without pagination or ignored statuses,
  `min_interval >= 1`, pivots with `expand: false` and POSSIBLE confidence at most. One request, no
  retries, 10 s timeout, redirects not followed: a redirect is classified (a login redirect is BLOCKED
  `login_wall`), is an absence only when its status is in `absent_statuses`, and is ERROR (could not
  verify) otherwise. A found account adds an info finding 'Account found: <title>' (POSSIBLE, tags
  `account`, `weak_signal`, plus `high_collision` for handles shorter than 5 characters): the same
  handle does not prove identity. Tag findings of a profile site are POSSIBLE as well.
* a spec that receives person names (`person_name`) is never default (A3); the reserved tag
  `offline` is refused (a spec is a third-party lookup).

## Fixtures (mandatory)

```
tests/fixtures/specs/<name>/        (user specs: ~/.v3lum/specs/<name>/)
    ok.<ext>              trimmed real answer for the health_check value (json, ndjson, csv, rss, xml, html)
    ok_page<N>.<ext>      optional further pages of a paginated spec (N = 2, 3...)
    error_in_200.<ext>    a real error/quota/challenge body served with HTTP 200 by the same source
    expected.json         {"ok": {"status", "attributes" (subset), "pivots" (subset of 'type:value')},
                           "error_in_200": {"status": blocked|quota|rate_limited|error, "reason_code"}}
```

`ok.status` is `ok` or `empty` and equals the spec's `health_check.expect` (the ok fixture is the
answer for the health-check value). User specs, which no CI runs, are run over their own fixtures at
load (`specs.check_fixtures`, offline, both fixtures served with HTTP 200) and refused when the
outcome differs from `expected.json`. `tests/test_specs.py` runs every bundled spec over its fixtures
(`ok` -> expected status, attributes and pivots; `error_in_200` -> the could-not-verify status and
reason code) and the registry contract test accepts these files instead of
`tests/modules/test_<name>.py`. Fixtures are trimmed real responses without personal data.
Unknown-tier or unknown-terms specs need them too.

## Health

Doctor (`v3lum doctor --sources`) runs `health_check` and records the result in
`health.HealthState`. A spec whose checks failed on 7 consecutive days loads **auto-disabled**
(`specs.disabled()`, `HealthState.notices()`): it stays listed, is never default and refuses to run
(SKIPPED `demoted`), while its health check carries a self-test doing the real lookup, so the next
passing check re-enables it. The self-test judges the declared `expect` (an `ok` spec that answers
without data fails), maps quota/rate limits to `quota` and missing keys to `needs_key` (neutral),
and lets cancellation, policy/licence refusals, configuration errors and offline mode propagate to
doctor: what the environment refuses is never recorded as a failed day.

## Template

```json
{
  "schema": "v3lum.spec/1",
  "name": "example_iprep",
  "title": "Example IP reputation",
  "description": "Reputation verdict and hostnames for an IP from the Example API.",
  "category": "threat_intel_ioc",
  "accepts": ["ipv4"],
  "produces": ["domain"],
  "provider": "examplerep",
  "sources": ["examplerep.ip"],
  "hosts": ["api.examplerep.test"],
  "terms": "open",
  "disclosure": "third_party",
  "opsec": "passive",
  "access_model": "free_noauth_limited",
  "run_on": "any",
  "requires_keys": [],
  "optional_keys": [],
  "max_requests": 1,
  "expected_latency": 1.0,
  "min_interval": 0.0,
  "cache_ttl": 86400,
  "absent_statuses": [404],
  "error_markers": [
    {"id": "examplerep.quota", "json_path": "error.code", "equals": "quota_exceeded", "maps_to": "quota",
     "reason": "ExampleRep: daily quota exhausted"}
  ],
  "manual_link": "",
  "default_enabled": true,
  "health_check": {"etype": "ipv4", "value": "8.8.8.8", "expect": "ok"},
  "request": {"url": "https://api.examplerep.test/v1/ip/{value}", "method": "GET", "params": {}, "headers": {},
              "ignored_status_codes": [], "paginate": null},
  "format": "json",
  "results": [
    {"key": "data.country", "attribute": "country"},
    {"key": "data.hostnames[]", "pivot": {"type": "domain", "relation": "hosted_domain", "expand": false, "confidence": "probable"}, "match_all": true}
  ],
  "multi_match": null,
  "found": null,
  "absent": null,
  "findings": [
    {"when": {"path": "data.verdict", "equals": "malicious"}, "title": "Example: IP listed as malicious", "severity": "medium",
     "criterion": "ExampleRep verdict 'malicious' (community reports and honeypot hits)", "tags": ["malicious"], "confidence": "probable"}
  ],
  "reference": "https://docs.examplerep.test/api",
  "tags": ["free", "reputation"]
}
```

The self-test set in `tests/fixtures/specs/_selftest/` shows every format, pagination, multi_match,
presence and an A5 profile site (with its synthetic providers in `_providers.json`).

Attribution: the declarative pattern is re-implemented from Machinae (MIT, Copyright (c) 2015
Hurricane Labs; notice `v3lum/data/notices/machinae.json`); Machinae's site list is not ported.
