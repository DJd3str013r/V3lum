# V3LUM module contract v2 - FROZEN 2026-11-26

> **Frozen (A16).** This guide is the module-author contract v2, frozen at the end of wave 1 on the
> green integrated tree. Names and behaviour described here change only through an
> architect-approved migration recorded in this file; later packages may only **add** names, each in
> its own file under [`docs/contract_additions/`](contract_additions/README.md) (see the last
> section). `tests/test_module_guide.py` keeps the guide honest: every backticked `v3lum.` name
> resolves, the example module below runs with its example test, and the class-variable table
> matches `v3lum.core.module.Module`.

A module is one small class that takes **one entity** (an e-mail, a domain, an IP...) and returns a
`v3lum.core.models.ModuleResult`: facts (*attributes*), judgements (*findings*), discovered entities
(*pivots*) and manual follow-up URLs (*links*). The core does everything else: policy gates,
concurrency, caching, provider HTTP profiles, classification of errors and challenge pages,
redaction, retries, quotas, deadlines, pivoting, correlation, scoring, evidence and reports. A module
**fetches, parses and translates** into the shared vocabulary - nothing more.

Contents: [0 Sequencing and merge gates](#0-sequencing-and-merge-gates) ·
[1 Module class](#1-the-module-class) · [2 Derived attributes](#2-derived-attributes) ·
[3 Statuses](#3-statuses-reason-codes-partial-runs) · [4 Confidence](#4-confidence) ·
[5 Results](#5-results-and-findings) · [6 Context](#6-the-context-ctx) · [7 HTTP](#7-http) ·
[8 DNS](#8-dns) · [9 Datasets](#9-datasets) · [10 Keys](#10-keys) · [11 Settings](#11-settings) ·
[12 Sanitizer](#12-sanitizer) · [13 Provider fragments](#13-provider-fragments) ·
[14 Vocabulary](#14-vocabulary) · [15 Pivot links](#15-pivot-link-packs) ·
[16 Correlation rules](#16-correlation-rules) · [17 Declarative specs](#17-declarative-specs) ·
[18 Noise](#18-noise-and-warning-lists) · [19 Other fragments](#19-other-decentralised-registration) ·
[20 Entity types](#20-entity-types) · [21 Testing](#21-testing) ·
[22 Contract test](#22-registry-contract-test) · [23 Team rules and defaults](#23-team-rules-lgpd-licence-and-tlp-defaults) ·
[24 Reference modules](#24-worked-examples-the-four-reference-modules) ·
[25 Arriving later](#25-arriving-later) · [26 Additions after the freeze](#26-additions-after-the-freeze)

---

## 0. Sequencing and merge gates

* **From wave 1 on** every name in this guide exists with a working implementation. Authors add
  module files, tests, fixtures and data fragments only - they never edit shared core files.
* **Enforcement that arrives later without changing any name**: the policy gate and the licence,
  TLP, tier, privacy, own-asset, scope and egress gates (wave 2), the full sanitizer stage and the
  forbidden-capability lint (wave 2), provider quotas (wave 2), egress/SSRF/scope binding (wave 2),
  the declarative-spec compiler (wave 2), evidence/audit (wave 3), data rules (wave 4), the AR20
  safety suite (wave 5) and the AR21 golden-path harness (wave 5).
* **Merge gate per module (A16)**: `tests/test_registry_contract.py` green; trimmed **real**
  fixtures without personal data; offline tests with `tests/fakes.py` (unmatched requests fail, the
  network guard is active); a provider-registry entry for every host and feed; the P327 lint (from
  wave 2).
* A source module counts as **default** only through the policy gate (wave 2). Until the gate
  lands, source modules (disclosure `third_party`, `internal`, `target`) run only when selected
  explicitly (`-M name`; interim A16 guard in the engine).
* **LIGHT/ACTIVE module files are not added before `tests/safety/test_scope.py` exists** (WP28,
  wave 5): the contract test fails otherwise (A7 merge gate).
* Per group, the AR21 golden-path fixtures go to `tests/fixtures/acceptance/<type>/<module>.json`
  ([format](../tests/fixtures/acceptance/README.md)).
* Module-facing additions after the freeze are documented per package in
  `docs/contract_additions/<package>.md` (section 26).

---

## 1. The module class

`v3lum.core.module.Module`, one file per module under `v3lum/modules/<category>/`, auto-discovered
by `v3lum.core.module.load_modules` and decorated with `v3lum.core.module.register`. Module files
are side-effect free at import time except for registrations (datasets, sanitizer schemas, noise
lists).

### 1.1 Skeleton: the worked example

The provider of the example: a fragment `v3lum/data/providers/examplerep.json` (section 13). Every
host and source a module uses is registered there first.

```json guide-provider
{
  "schema": "v3lum.provider/1",
  "id": "examplerep",
  "name": "ExampleRep (fictional provider used by the module guide)",
  "operator": "ExampleRep Ltd. (fictional)",
  "hosts": ["api.examplerep.test"],
  "hosts_from_settings": [],
  "internal": false,
  "tier": "community",
  "tier_rationale": "Identifiable operator, public API documentation, published terms and privacy policy, more than two years of public track record (A8 community).",
  "tier_reviewer": "module guide",
  "tier_date": "2026-11-26",
  "flags": {"publishes_queries": false, "reuses_queries": false, "fetches_target": false, "sensitive": false},
  "personal_data_review": null,
  "reliability": {"grade": "C", "justification": "Community reports plus honeypot hits; verdicts are usually but not always right."},
  "http_profile": {"user_agent": "neutral", "accept": "application/json", "ttl": 86400},
  "quota": {"scope": "egress_ip", "day": 1000, "published": true, "evidence_url": "https://docs.examplerep.test/limits"},
  "error_markers": [],
  "keys": {},
  "sources": {
    "ip": {
      "title": "IP reputation lookups",
      "terms": {
        "class": "open",
        "evidence_url": "https://examplerep.test/terms",
        "quote": "Free for any use, commercial use included; do not resell the data.",
        "checked_at": "2026-11-26",
        "reviewer": "module guide",
        "free_plan_business_use": true
      },
      "upstream_family": "examplerep",
      "sanitizer": null,
      "dataset": null,
      "notes": "404 means 'IP never seen' (documented absence)."
    }
  }
}
```

The module (`v3lum/modules/threat_intel_ioc/example_rep.py`):

```python guide-example
from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

SOURCE = "examplerep.ip"
API = "https://api.examplerep.test/v1/ip/{ip}"


@register
class ExampleRep(Module):
    # ---- identity --------------------------------------------------------------------
    name = "example_rep"
    title = "ExampleRep IP reputation"
    description = "Malicious/benign verdict, country and reverse names for an IP from ExampleRep."
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.IPV6}
    produces = {T.DOMAIN}
    tags = {"reputation"}  # reserved: returns a malicious/suspicious/benign verdict
    reference = "https://docs.examplerep.test/api"
    # ---- MUST be declared in the class body ---------------------------------------------
    terms = "open"  # = the most restrictive class of its sources
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # ExampleRep receives the IP
    hosts = ("api.examplerep.test",)
    max_requests = 1  # networked modules: requests per entity per run
    expected_latency = 1.0  # declared p50 seconds
    # ---- registry and behaviour -----------------------------------------------------------
    provider = "examplerep"
    sources = (SOURCE,)
    access_model = "free_noauth_limited"
    absent_statuses = frozenset({404})  # documented: 'IP never seen'
    error_markers = (
        {"id": "examplerep_quota", "statuses": [200], "json_path": "error", "equals": "quota exceeded",
         "maps_to": "quota", "reason": "ExampleRep: daily quota exhausted"},
    )

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        data = ctx.http.get_json(API.format(ip=entity.value), source=SOURCE)
        if data is None:  # 404 in absent_statuses: a documented absence
            return res.mark("empty")
        if not isinstance(data, dict):  # untrusted data: an odd answer is 'could not verify', never empty
            return res.mark("error", "unexpected ExampleRep answer: could not verify")
        res.raw = data  # evidence (sanitized, SHA-256)
        res.attr("country", data.get("country"))
        hostnames = data.get("hostnames")
        for host in hostnames if isinstance(hostnames, list) else []:
            res.pivot(T.DOMAIN, host, "reverse_dns", confidence="probable")  # invalid values are dropped
        if data.get("verdict") == "malicious":
            res.finding(
                "Listed as malicious by ExampleRep",
                "high",
                data.get("reason", ""),
                confidence="probable",
                criterion="ExampleRep verdict 'malicious' (community reports and honeypot hits)",
                tags=["malicious"],
                source=SOURCE,
                observed_last=data.get("last_seen"),
            )
        return res
```

Its test (`tests/modules/test_example_rep.py`; a real module loads trimmed real answers with
`module_fixture("example_rep", "malicious.json")` from `tests/fixtures/example_rep/`):

```python guide-example-test
from tests.fakes import FakeHttp, run_module
from v3lum.core.models import Status
from v3lum.modules.threat_intel_ioc.example_rep import ExampleRep

URL = "https://api.examplerep.test/v1/ip/{ip}"
MALICIOUS = {"verdict": "malicious", "reason": "SSH brute force", "country": "BR",
             "hostnames": ["scanner.example.net"], "last_seen": "2026-11-20T10:00:00Z"}


def test_malicious_verdict():
    http = FakeHttp().add("GET", URL.format(ip="203.0.113.7"), json=MALICIOUS)
    res = run_module(ExampleRep, "ipv4:203.0.113.7", http)
    assert res.status is Status.OK
    assert res.attributes["country"] == "BR"
    finding = res.findings[0]
    assert finding.criterion and finding.source == "examplerep.ip"
    assert {p.entity.value for p in res.pivots} == {"scanner.example.net"}
    http.assert_hosts_within(ExampleRep)


def test_404_is_a_documented_absence():
    http = FakeHttp().add("GET", URL.format(ip="203.0.113.8"), status=404, json={"detail": "not seen"})
    assert run_module(ExampleRep, "ipv4:203.0.113.8", http).status is Status.EMPTY


def test_quota_inside_http_200_is_never_absent():
    http = FakeHttp().add("GET", URL.format(ip="203.0.113.9"), json={"error": "quota exceeded"})
    res = run_module(ExampleRep, "ipv4:203.0.113.9", http)
    assert res.status is Status.QUOTA and res.reason_code == "quota"


def test_429_and_challenge_pages_are_could_not_verify():
    http = FakeHttp().add("GET", URL.format(ip="203.0.113.10"), status=429, text="slow down")
    assert run_module(ExampleRep, "ipv4:203.0.113.10", http).status is Status.RATE_LIMITED
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http2 = FakeHttp().add("GET", URL.format(ip="203.0.113.11"), status=403, text=page)
    assert run_module(ExampleRep, "ipv4:203.0.113.11", http2).status is Status.BLOCKED


def test_unexpected_answer_is_never_empty():
    http = FakeHttp().add("GET", URL.format(ip="203.0.113.12"), json=["not", "an", "object"])
    assert run_module(ExampleRep, "ipv4:203.0.113.12", http).status is Status.ERROR
```

Put the file in the matching `v3lum/modules/<category>/` package; nothing else is edited.

### 1.2 Identity, inputs and outputs

* `name` (`^[a-z][a-z0-9_]{2,63}$`, unique; CLI `v3lum run <name> <input>`), `title`,
  `description`, `category` (one of `v3lum.core.module.CATEGORIES`, the same 21 keys as v1),
  `reference` (documentation/terms URL), `tags` (free; reserved tags in 1.5), `notice` (legal or
  ethical note shown by `v3lum info`).
* `accepts` (non-empty set of `v3lum.core.entities.EntityType`), `produces` (documentation and
  planning), `run_on` (one of `v3lum.core.module.RUN_ON`): `'any'` (default) | `'seeds'`
  (analyst-typed seeds only) | `'own_assets'` (per-person breach/stealer: verified org domains, or
  `--breach-scope all` + `--purpose` on typed seeds) | `'own_assets_only'` (txt_verified/attested
  org entries only).
* `applies(entity, ctx) -> bool` hook: an extra applicability filter; False ends the run SKIPPED
  `not_applicable`.

**Must be declared in the class body** (`v3lum.core.module.MUST_DECLARE`): `terms`
(`v3lum.core.module.TERMS`: `'open' | 'key-terms' | 'license' | 'noncommercial' | 'unknown'`; the
base default `'unknown'` fails closed), `opsec` (`Opsec.PASSIVE | LIGHT | ACTIVE`), `disclosure`
(`v3lum.core.module.DISCLOSURES`: `'none' | 'internal' | 'third_party' | 'target'`; no default) and
`hosts` (tuple of exact hosts or `'*.suffix'` wildcards; `()` for none/target/DoH-only modules).
When `disclosure != 'none'` also `max_requests` and `expected_latency`
(`v3lum.core.module.MUST_DECLARE_NETWORKED`). "Declared" means present in the class's own body or
in a base class other than Module (mixins and compiled specs count).

Removed in v2 (`v3lum.core.module.REMOVED`; declaring them fails registration): `user_agent` (the
provider `http_profile` chooses the UA), `shares_input` (derived) and every derived name of
section 2.

### 1.3 Class variables and defaults

| ClassVar | default | meaning |
|---|---|---|
| `name` | `""` | unique snake_case id |
| `title` | `""` | shown in tables |
| `description` | `""` | one or two sentences: what and from where |
| `category` | `"utility"` | one of CATEGORIES |
| `reference` | `""` | documentation / terms URL (http/https) |
| `tags` | `frozenset()` | free tags; reserved meanings in 1.5 |
| `notice` | `""` | legal/ethical note for `v3lum info` |
| `accepts` | `frozenset()` | entity types handled (must be non-empty) |
| `produces` | `frozenset()` | entity types it may pivot to |
| `run_on` | `"any"` | `any`, `seeds`, `own_assets`, `own_assets_only` |
| `terms` | `"unknown"` | must be declared: most restrictive class of its sources |
| `opsec` | `Opsec.PASSIVE` | must be declared: PASSIVE, LIGHT or ACTIVE |
| `disclosure` | `""` | must be declared: `none`, `internal`, `third_party`, `target` |
| `hosts` | `()` | must be declared: exact hosts or `*.suffix` wildcards |
| `provider` | `""` | primary provider id (required for third_party/internal) |
| `sources` | `()` | registry source ids `provider.source` (required for third_party/internal) |
| `access_model` | `""` | required for third_party; default `offline` (none), `internal` (internal), `free_noauth_unlimited` (target) |
| `requires_keys` | `()` | registered key names that must be configured (NEEDS_KEY otherwise) |
| `optional_keys` | `()` | registered key names that unlock more data or quota |
| `requires_packages` | `()` | import names among OPTIONAL_PACKAGES (UNAVAILABLE `package` otherwise) |
| `max_requests` | `10` | ctx.http requests per entity per run (0..100000; DoH not counted) |
| `expected_latency` | `5.0` | declared p50 seconds |
| `timeout` | `60.0` | run deadline in seconds (0 = none) |
| `min_interval` | `0.0` | seconds between requests to the module's hosts |
| `max_rate` | `None` | LIGHT <= 1.0, ACTIVE <= 10.0 requests/s per target host |
| `daily_quota` | `None` | fallback budget when the provider has no quota block |
| `cache_ttl` | `None` | HTTP cache TTL seconds (None = provider profile / global) |
| `max_pivots` | `100` | pivots kept from one run |
| `requires_egress` | `frozenset()` | ISO alpha-2 egress countries (e.g. `{'BR'}`) |
| `absent_statuses` | `frozenset()` | documented meaningful absences (e.g. `{404}`) |
| `error_markers` | `()` | error-in-200 markers (schema in section 7) |
| `manual_link` | `""` | `'<pack>:<link_id>'` or an https template, emitted when automation is skipped/blocked |
| `default_enabled` | `True` | candidate flag: can lower, never force, the effective default set |
| `settings` | `{}` | module settings name -> default (`ctx.setting`, `v3lum config set`) |

`access_model` takes one of `v3lum.core.module.ACCESS_MODELS` (`free_noauth_unlimited`,
`free_noauth_limited`, `free_auth_limited`, `free_auth_unlimited`, `commercial_only`, `internal`,
`offline`), shown in plain words through `v3lum.core.module.ACCESS_LABELS`.
`requires_packages` accepts only `v3lum.core.module.OPTIONAL_PACKAGES`: the core extras merged with
fragments `v3lum/data/extras/<package>.json` (schema `v3lum.extra/1`: `{package, pip, extra,
licence, justification}`); a batch adds a fragment and never edits `pyproject.toml`. Rate ceilings
are `v3lum.core.module.CEILINGS`.

### 1.4 Health checks

`health_check()` (classmethod) returns `v3lum.core.module.HealthCheck`
`(etype, value, expect='ok', offline=False, selftest=None)` or None. Default: None for disclosure
`none` and for target modules; otherwise the first accepted type found in
`v3lum.core.module.BENIGN_VALUES` (example.com, https://example.com/, someone@example.com,
8.8.8.8, 2001:4860:4860::8888, 8.8.8.0/24, AS15169, the EICAR md5/sha1/sha256, CVE-2021-44228,
octocat). **LIGHT/ACTIVE modules MUST override it** with `HealthCheck(offline=True,
selftest=fn)`: `fn(ctx) -> v3lum.core.module.HealthResult(status, detail='')` with status
`'ok' | 'blocked' | 'quota' | 'needs_key' | 'dead'`. With `offline=True` the ctx has no network
beyond loopback; with `offline=False` it is a normal passive ctx (e.g. a pack sampling claimed and
unclaimed handles). Doctor (P337) and the keys wizard (P379) use it; its calls count against quotas.

### 1.5 Reserved tags

`v3lum.core.module.RESERVED_TAGS` maps each reserved tag to its meaning: `core`, `offline`, `slow`,
`noisy`, `brazil`, `free`, `curated_pack`, `cached_only`, `high_fp`, `bulk_download`,
`people_sweep`, `sensitive_sites`, `fresh_assessment`, `cert_derived`, `pack`, plus the review
additions **`reputation`** (the module returns a malicious/suspicious/benign verdict for its IOC
types: it counts for 'inconclusive', the A3 minimum answer set and doctor), **`watch_source`** (a
polling source invoked by each `v3lum watch` cycle on org-profile rule entities; it reports new
names in attribute `watch_hits`) and **`watch_only`** (never selected outside `v3lum watch`).

### 1.6 What `@register` refuses

`v3lum.core.module.register` raises `v3lum.core.module.RegistrationError`
(`'<module>: <problem> - <how to fix>'`) for any module failing: identity/enums; the must-declare
names; opsec LIGHT/ACTIVE <=> disclosure `target`; disclosure `none` => `hosts == ()` and
`provider == ''`; `internal` => an internal provider; `third_party` => a registered provider and
sources, every host owned by a provider of the module's sources; `terms` == the most restrictive
class of its sources (`open < key-terms < license < noncommercial < unknown`; no sources =>
disclosure none/target and terms `open`); `max_rate` ceilings; `requires_egress` codes;
`absent_statuses` 100-599; the error-marker schema; a resolvable `manual_link`; setting
collisions; the A3 default rule (`default_enabled` MUST be False for LIGHT/ACTIVE, terms unknown,
tier unknown, `max_requests > 10` without tag `curated_pack`, `expected_latency > 10`, category
`person_name` with disclosure `third_party`, tags `high_fp`/`bulk_download`/`people_sweep`/
`sensitive_sites`/`fresh_assessment`, `fetches_target` providers without tag `cached_only`);
sensitive modules without a sanitizer schema for every source; unregistered `requires_keys`/
`optional_keys`; unknown `requires_packages`. Failures never crash the tool: they appear in
`v3lum.core.module.load_errors` (the contract test requires none).

### 1.7 Readiness and description

`v3lum.core.module.readiness_check` `(cls, keys, mode, authorized=False)` returns
`v3lum.core.module.Readiness(ready, status, reason_code, reason)`: missing package -> UNAVAILABLE
`package`; missing `requires_keys` -> NEEDS_KEY `needs_key`; opsec above the mode -> SKIPPED
`opsec`; ACTIVE without authorization -> SKIPPED `authorization`. `v3lum.core.module.readiness` is
the legacy `(ready, reason)` wrapper. `describe()` keeps every v1 key and adds every v2 field
(`contract: 'v2'`); `v3lum info` and doctor print it.

---

## 2. Derived attributes

Set by `@register` from the provider registry (`v3lum.core.module.DERIVED`); **never declared**:

| derived | value |
|---|---|
| `trust_tier` | lowest tier of the providers of its sources (`trusted`, `community`, `unknown`); `n/a` for none/internal/target |
| `providers` | frozenset: the primary provider plus the providers of its sources |
| `upstream_families` | upstream families of its sources (and what they embed) |
| `reliability` | Admiralty grade A-F of the primary provider |
| `sensitive` | category `breach_leak` or any sensitive provider |
| `publishes_queries` | any provider publishes submitted values (rule 7: never receives values) |
| `reuses_queries` | any provider may reuse submitted values (excluded at TLP:AMBER and above) |
| `fetches_target` | any provider fetches the target live |
| `shares_input` | `disclosure in {'third_party', 'target'}` (v1 alias) |
| `max_tlp` | `v3lum.core.tlp.max_tlp`: none/internal -> RED; target -> AMBER (RED only for verified own assets not third_party_hosted); trusted -> AMBER+STRICT; community -> AMBER; unknown or reuses_queries -> GREEN; publishes_queries -> never |
| `access_label` | plain words of `access_model` (e.g. 'free, no key, limited') |
| `terms_sources` | `{source id: terms class}` |

---

## 3. Statuses, reason codes, partial runs

`v3lum.core.models.Status`: `ok`, `empty`, `error`, `skipped`, `needs_key`, `rate_limited`,
`blocked`, `unavailable` (unchanged v1 values) + **`quota`** (budget/daily/monthly limit, distinct
from the transient `rate_limited`).

`v3lum.core.models.REASON_CODES` holds the canonical A3 codes - the only ones:

| status | reason codes |
|---|---|
| SKIPPED | not_default, demoted, licence, tlp, tier, privacy, own_asset, opsec, authorization, scope, egress_country, deadline, policy, config, not_applicable |
| NEEDS_KEY | needs_key |
| UNAVAILABLE | package, dataset, offline |
| QUOTA | quota |
| RATE_LIMITED | rate_limited |
| BLOCKED | hostile_host, circuit, challenge (anti-bot/WAF challenge, keyless HTTP 403, DNSBL refusal), geo_block, login_wall |
| ERROR | timeout, sanitizer, error |

`v3lum.core.models.DEFAULT_REASON` gives the default code per status,
`v3lum.core.models.status_for` maps a code to its status and `v3lum.core.models.valid_reason`
validates a pair.

**Partial runs** keep status ok/empty with `ModuleResult.partial = True` and a stop reason in
`v3lum.core.models.STOP_REASONS` = {`request_cap`, `deadline`, `quota`, `rate_limited`,
`cancelled`}. The engine recovers the result a module was building when `ctx.http` raises
RequestCapReached/Cancelled/QuotaExceeded/RateLimited mid-run (`v3lum.core.models.collect_results`),
so modules simply **let these exceptions propagate**.

**Rule 5 everywhere**: 403/429/challenges/timeouts/SERVFAIL mean "could not verify", never
"absent". Never write 'not found', 'not listed', 'no account', 'clean' or 'does not exist' for a
source that did not answer.

Exception -> status mapping, done by the engine (`v3lum.core.engine.Engine`):

| raised by the module / ctx | status / reason_code |
|---|---|
| `v3lum.core.http.QuotaExceeded` | quota / quota |
| `v3lum.core.http.RateLimited` | rate_limited / rate_limited |
| `v3lum.core.http.Blocked` | blocked / its `reason_code` (challenge, geo_block, login_wall, circuit, hostile_host) |
| `v3lum.core.http.AuthRequired` | needs_key for keyed modules; blocked / challenge for keyless ones |
| `v3lum.core.http.OfflineError` | unavailable / offline |
| `v3lum.core.datasets.DatasetUnavailable` | unavailable / dataset |
| `v3lum.core.http.PolicyError` | skipped / its reason_code (default policy) |
| `v3lum.core.http.ConfigError` | skipped / config |
| `v3lum.core.http.DeadlineExceeded` | error / timeout |
| `v3lum.core.http.NetworkError`, `v3lum.core.http.HttpError`, anything else | error / error |
| sanitizer failure | error / sanitizer (raw dropped) |
| `applies()` False | skipped / not_applicable |

---

## 4. Confidence

`v3lum.core.models.Confidence`: CONFIRMED / PROBABLE / POSSIBLE (`'confirmed'`, `'probable'`,
`'possible'`); weights 1.0 / 0.7 / 0.4 for scoring and STIX 90 / 70 / 40
(`v3lum.core.models.CONFIDENCE_TABLE`). `Confidence.from_value` maps floats (>= 0.85 confirmed,
>= 0.55 probable, else possible) and labels. `criterion` (text) is **mandatory for severity >= low**
(strict mode raises `v3lum.core.models.ContractViolation` in tests).

Automatic downgrades happen only through named suppression rules (`Finding.downgrade(rule, reason,
*, to=None)` -> criterion `'POSSIBLE - on warninglist <name>'`; `to=Confidence.POSSIBLE` jumps
straight to POSSIBLE); upgrades are at most +1 and only with >= 2 independent upstream families
(`Finding.upgrade`). **Analyst overrides always win**: `Finding.override` /
`Finding.apply_override(*, label, severity, verdict, analyst, note, at)` (set by `v3lum cases
override|confirm`, stored by deterministic finding id, re-applied by the engine); downgrade() and
upgrade() never cross an override (they only record `blocked_by: analyst`). Pivot edges carry the
same labels.

---

## 5. Results and findings

Build results with `self.result(entity)` (a `v3lum.core.models.ModuleResult`):

* `res.finding(title, severity='info', description='', *, confidence=0.8|'probable', criterion='',
  data=None, tags=(), references=(), source='', observed_first=None, observed_last=None, attack=(),
  key='') -> Finding`. `Finding.id` = `v3lum.core.models.finding_id` = sha256('module|entity.key|
  title|key')[:16]: **keep titles stable**, put counts in description/data and use `key=` to
  separate same-title findings. `source` = registry source id; `observed_first`/`observed_last` =
  provider timestamps (ISO-8601; they drive decay; omit when unknown). `attack` = ATT&CK ids
  validated against `v3lum.core.attack.is_valid`.
* `res.pivot(etype, value, relation, *, confidence=0.9|label, expand=True, note='') -> Entity|None`
  (invalid values are dropped).
* `res.attr(key, value)` (vocabulary names only); `res.link(label, url)` (http/https only).
* `res.mark(status, error='', *, reason_code='') -> res` (default reason per status; validated).
* `res.stop(stop_reason) -> res` (`partial = True`).
* `res.presence(state, *, marker='', url='', checked_at=None, source='')`, state `found | absent |
  unknown` (tri-state existence; `absent` needs a marker or URL as positive evidence) -> attribute
  `presence`.
* `res.set_marking(tlp)`: results carrying a platform marking raise the entity/case TLP (A12).
* `res.source_status(source_id, status, *, reason_code='', reason='')`: aggregators report the
  per-feed outcome of one of their sources (a blocked or rate-limited feed while the others
  answered). Feeds outside `ctx.allowed_sources` are reported by the engine (reason `licence`).
* `res.raw` (saved as sanitized evidence), `res.reason_code`, `res.partial`, `res.stop_reason`,
  `res.tlp`; `res.hosts`, `res.datasets` and `res.redacted_fields` are filled by the engine.
* **Secrets**: never put raw secrets anywhere; use `v3lum.core.sanitize.mask_secret` (`{type,
  preview first4…last4, sha256}`) or `v3lum.core.entities.secret_entity`; combos (email:password)
  are dropped by the core (`v3lum.core.sanitize.drop_combos`).
* **Strict contract mode** (`V3LUM_STRICT=1`, always on in tests; `v3lum.core.vocab.strict_enabled`):
  unknown vocabulary names, a missing criterion, non-http(s) links and `absent` without evidence
  raise.
* Finding tag **`context_only`** = shown as context, never scored (third-party breach context,
  generic/role/test addresses, anonymity networks).

---

## 6. The context (ctx)

`v3lum.core.context.Context`, built by `v3lum.core.context.Runtime` for each (module, entity) run:

| ctx. | what it is |
|---|---|
| `http` | `v3lum.core.http.ScopedHttp` carrying the module's metadata: host allow-list (declared hosts + `hosts_from_settings` hosts of its providers; static provider hosts it does not declare stay refused), `max_requests`, run deadline, error markers, `absent_statuses`, keyless flag, cancel event, priority |
| `doh` | the per-run **core DoH scope**: not counted in `max_requests` or quotas, no module UA/min_interval, restricted to the resolver hosts; its hosts reach the disclosure ledger (`res.hosts`) |
| `dns` | `v3lum.core.dns.Resolver` over `ctx.doh`; public resolvers off for disclosure `none`/`internal` and at TLP:RED; no public fallback from an internal resolver at AMBER and above |
| `net` | `v3lum.core.net.Connector`: raw sockets for target modules only (PolicyError otherwise) |
| `data` | a dataset view (`v3lum.core.datasets.DataView`; `ctx.data.used` becomes `res.datasets`) |
| `org` | the organisation profile (`v3lum.core.orgprofile.OrgProfile`; empty when none is configured) |
| `state` | `v3lum.core.context.ModuleState`: `get/set/delete/all`, persistent per-module JSON under `~/.v3lum/state/<module>.json` (0600, 1 MB cap, JSON values only; never personal identifiers or secrets) - **the only persistence a module may use**; the same object is available to `HealthCheck.selftest(ctx)` |
| `key(name)`, `has_key(name)`, `key_plan(name)` | configured keys; plan `'business' \| 'free' \| ''` |
| `setting(name, default=None)` | core and module settings |
| `log(message, level='info')` | a line in the live feed (configured key values and key-like URL parameters are masked first) |
| `cancelled()` | stop long loops early (kill switch) |
| `now()` | aware UTC now (frozen in tests) |
| `remaining()` | seconds to the run deadline, or None |
| `quota_remaining()` | remaining provider/module budget, or None when unknown |
| `mode`, `authorized`, `options` | scan mode, authorization flag, `v3lum.core.context.ScanOptions` |
| `entity`, `is_seed`, `depth`, `provenance` | the run entity, analyst-typed or pivot, depth, parent path `((parent_key, relation, module), ...)` |
| `allowed_sources` | frozenset of source ids the module may query in this run: aggregators MUST query only these (the engine reports the blocked rest) and use `res.source_status` for runtime per-feed failures |
| `allowed_opsec` | `min(scan mode, module opsec)` |
| `tlp` | entity TLP value `'clear' \| 'green' \| 'amber' \| 'amber+strict' \| 'red'` |
| `purpose`, `case_id`, `deadline` | recorded purpose, case id, monotonic run deadline |

The per-run facts come from `v3lum.core.context.RunInfo` (frozen: `entity`, `is_seed`, `depth`,
`provenance`, `allowed_sources`, `tlp`, `deadline`, `case_id`, `priority`, `internal_seed`).
Modules **never choose proxies, user agents or resolvers**. The context enforces the declared
`disclosure`: a Module subclass without a valid one (unregistered, `@register` bypassed) fails
closed to `none` - no network, no public resolver. An "internal" DoH entry (`doh_internal`, an
https URL in `doh_providers`) counts only when it has no credentials and is not a public resolver.

`v3lum.core.context.ScanOptions` keeps every v1 field and adds `authorization_ref`, `scope_path`,
`scope`, `preset` ('quick' | 'deep'), `purpose`, `ticket`, `legal_basis`, `breach_scope`
('own' | 'all'), `expand_personal`, `allow_unknown`, `egress_override`, `licence_profile`,
`show_personal`, `no_defang`, `seed_tlp`, `unconfirmed_seeds` and `only_pairs`; `tlp` defaults to
**'amber'** (A2). `Runtime` exposes `clock`, `providers`, `org`, `meta`, `in_scan`,
`cancel_reason`, `case_hooks`, `doh_scope()` and `cancel(reason)`; `v3lum.core.context.EventBus`
emits `http` and the structured `http_request` event (`info=` `v3lum.core.http.RequestInfo`).

---

## 7. HTTP

`ctx.http.get/head/post/request(url, *, params=None, headers=None, data=None, json_body=None,
timeout=None, ttl=None, allow_redirects=True, max_bytes=None, source='', cache_if=None,
retries=None) -> Response`; `ctx.http.get_json(url, *, absent=None, **kw)` / `post_json(...)` ->
parsed JSON, or None **only** when the status is in `absent_statuses` or `absent` (`ok404=True` is
a deprecated alias of `absent={404}`); `ctx.http.check(resp)` raises per classification (call it
when you parse HTML/text yourself); `ctx.http.evict(resp)` drops a cached response you judged
unusable; `cache_if=callable(resp) -> bool` vetoes caching. Counters: `requests`, `cache_hits`,
`hosts`, `bytes`, `request_log`.

`v3lum.core.http.Response`: `status`, `url` (final), `headers` (lower-case), `content`, `text`,
`json()`, `ok`, `elapsed`, `from_cache`, `fetched_at`, `truncated`, `history` (hop URLs),
`request_url`, `host`, `source`, `classification`, `blocked` (legacy reason), `raise_for_status()`.

Exceptions, all importable from `v3lum.core.http`: `v3lum.core.http.HttpError` (`reason_code`),
`v3lum.core.http.RateLimited`, `v3lum.core.http.AuthRequired`, `v3lum.core.http.Blocked`
(`reason_code` challenge | geo_block | login_wall | circuit | hostile_host),
`v3lum.core.http.QuotaExceeded`, `v3lum.core.http.NetworkError`, `v3lum.core.http.OfflineError`,
`v3lum.core.http.DeadlineExceeded`, `v3lum.core.http.Cancelled`,
`v3lum.core.http.RequestCapReached`, `v3lum.core.http.PolicyError` (`reason_code`),
`v3lum.core.http.ConfigError`.

Core behaviour you can rely on: the provider `http_profile` is applied by host (UA, Accept,
Accept-Language, timeout, retries, max_bytes, ttl, min_interval, concurrency; the default UA is the
neutral `V3LUM/<version>`; a contact UA only where the profile asks and `contact_email` is set,
else SKIPPED/config); an own redirect loop (<= 5 hops, every hop host-checked, credential headers
stripped on a host change, https->http refused); PASSIVE modules reach only their declared hosts
(PolicyError -> SKIPPED/policy); disclosure `none` modules get no network; `max_requests` ->
RequestCapReached; run deadline / cancel -> DeadlineExceeded / Cancelled; one retry honouring
Retry-After <= 15 s and never a retry with another UA after a block; classified, 401/403/429/5xx and
truncated responses are never cached; sensitive providers are cached only sanitized or not at all;
every URL and message leaving the client is redacted (`v3lum.core.redact.redact_url`,
`v3lum.core.redact.redact_text`: configured key values and key-like parameters are masked).

**Body-error classification (P321)**: `v3lum.core.http.classify` `(resp, *, markers=(),
keyless=False) -> Classification(status 'blocked'|'rate_limited'|'quota'|'error', reason_code,
reason, marker_id) | None` runs on every response before parsing and caching: module and provider
error markers, login-wall/geo-block/challenge final-URL and body fingerprints (weak captcha words
only on error statuses), 429 -> rate_limited, keyless 403 -> blocked/challenge. Error-marker
schema (module `error_markers` and provider `error_markers`, parsed by
`v3lum.core.providers.parse_marker`):

```json
{"id": "hackertarget_quota", "statuses": [200], "json_path": null, "equals": null,
 "regex": "API count exceeded", "final_url_regex": null,
 "maps_to": "quota", "reason_code": "quota", "reason": "HackerTarget: daily quota exhausted (API count exceeded)"}
```

(`maps_to` is `blocked | rate_limited | quota | error`; `reason_code` optional, canonical; the
`reason` names the provider.)

---

## 8. DNS

`ctx.dns.query(name, rtype='A', *, hostile=False) -> DnsAnswer(name, rtype, status, records, ttl,
authenticated, error, resolver)` (`v3lum.core.dns.DnsAnswer`) with `.ok`, `.nxdomain` (only from a
real NXDOMAIN, DoH Status 3), `.nodata` and `.could_not_verify` (SERVFAIL, REFUSED, timeouts,
transport errors). `authenticated` is the AD flag: **'validated by resolver', never proof**.
`ctx.dns.ptr(ip)`, `ctx.dns.addresses(name)`, `ctx.dns.wildcard(zone) -> bool|None`,
`ctx.dns.confirm_nxdomain(name, rtype='A') -> bool|None` (a second resolver; **required** before
using NXDOMAIN for takeover, typosquat or 'domain does not exist' decisions) and
`ctx.dns.dnsbl(query_name, zone) -> DnsblResult(listed: bool|None, codes, status, reason)`
(`v3lum.core.dns.DnsblResult`; never through public resolvers; refusal codes 127.255.255.x are
blocked/rate_limited/error, never 'not listed').

Resolvers: `v3lum.core.dns.DOH_PROVIDERS` (Google with `edns_client_subnet=0.0.0.0/0` on every
query, Cloudflare ECS-free and first for `hostile=True` names, Quad9 wire format through dnspython,
and the organisation's internal DoH from setting `doh_internal`, listed first when set - the opsec
option for typosquat permutation lists). Failover only on transport errors, 5xx and 429 (never on an
NXDOMAIN/SERVFAIL answer), <= 5 s per query, a per-run circuit breaker after 3 failures.
`dns_mode=system` runs only when configured, never as a silent fallback.

**DoH-only modules** declare `provider='core_doh'`, `sources=('core_doh.resolvers',)`, `hosts=()`,
`disclosure='third_party'`, `terms='open'` and `max_requests = 0`: DoH is not counted in
`max_requests` or quotas.

---

## 9. Datasets

`v3lum.core.datasets.register_dataset` `(name, url, *, ttl=86400, description='', licence='',
terms_class='unknown', attribution='', provider='', source='', validate=None, min_bytes=1,
expect='bytes'|'json'|'lines'|'csv'|'text', pinned_sha256='', max_bytes=None (200 MB), large=None,
essential=False, active=False, archive=None|'gz'|'bz2'|'zip', member='')`, called at import time in
the module file (name `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`; `source` = a registered registry
source). Reading: `ctx.data.fetch/fetch_text/fetch_json/fetch_lines(name, url=None, *, ttl=None,
headers=None, max_bytes=None)`, `ctx.data.bundled_text/bundled_json/bundled_lines/bundled_path/
bundled_exists(name)`, `ctx.data.index(name)` -> `v3lum.core.datasets.DatasetIndex` (`.contains`),
`ctx.data.info(name)` -> `v3lum.core.datasets.DatasetInfo` (sha256, fetched_at, licence,
terms_class, attribution, age_hours, stale...), `ctx.data.used` (citations copied into
`ModuleResult.datasets`).

Downloads are atomic (a challenge page, a short body or bad JSON keeps the previous copy). Datasets
> 5 MB are never downloaded during a scan: `v3lum.core.datasets.DatasetUnavailable` ->
UNAVAILABLE/dataset ('run v3lum data update <name>'); stale copies are served while the refresh is
deferred. GPL, CC BY-SA and NC data are runtime downloads only, never bundled (A6). Datasets that
drive LIGHT/ACTIVE behaviour use `active=True` and ship a pin in
`v3lum/data/active_locks/<name>.json` (`{"schema": "v3lum.active_lock/1", "name", "sha256", "url",
"commit", "reason"}`). Archives go through `v3lum.core.datasets.safe_extract`.

---

## 10. Keys

Keys are declared in the provider fragment `keys` block: `{"<key_name>": {"description",
"signup_url", "env": ["ALIAS"], "multi_key": false, "plan_hint"}}`. `V3LUM_KEY_<NAME>` always
works; `v3lum.config.key_registry` merges the legacy `v3lum.config.KNOWN_KEYS` with the fragments
and `v3lum.config.key_env_names` feeds the test env scrub automatically. **One key per provider**
(no rotation; `multi_key: true` is a registry error, P332 veto_lift). `requires_keys` and
`optional_keys` reference registered names; key values are registered with the central redactor
(`v3lum.core.redact.register_secret`) automatically. `ctx.key_plan(name)` returns the plan recorded
by `v3lum keys set <name> --plan business` (setting `key_plans`).

---

## 11. Settings

`Module.settings` (name -> default) registers module settings through
`v3lum.config.register_settings` (names unique across core and modules; collisions refuse
registration); `ctx.setting(name)` reads them and `v3lum config set` changes them. Core settings
are `v3lum.config.DEFAULT_SETTINGS` with descriptions in `v3lum.config.SETTINGS_META`
(`v3lum.config.SettingSpec`): `tlp`, `licence_profile`, `scan_deadline`, `retention_days`,
`egress_country`, `nsfw_sites`, `sensitive_sites`, `default_region`, `contact_email`,
`contact_url`, `doh_providers`, `doh_internal`, ... **Never read `os.environ` in modules.**

---

## 12. Sanitizer

`v3lum.core.sanitize.register_schema` `(source_id, *, keep=[...], notes='')` at import time (top
level of the module file, above the `@register` class), or a `sanitizer: {"keep": [...]}` block on
the source in the provider fragment. Keep paths are dotted keys with `[]` for list elements and `*`
for any key (`"breaches[].Name"`, `"stealers[].date_compromised"`, `"total_corporate_services"`).
Sensitive modules (category `breach_leak` or a provider flagged sensitive) cannot register without
a schema per source (`v3lum.core.sanitize.schema_for`). The engine sanitizes every result after
`run()` (`v3lum.core.sanitize.sanitize_result`; fail closed: error/sanitizer, raw dropped). Modules
put the password FORM in a kept field `password_form` (`'plaintext'` | `'hashed: <algorithm>'`)
and never keep passwords, hashes, salts, masked hints, cookies, tokens, computer names,
infected-host IPs, malware paths or combo lines (A4; `v3lum.core.sanitize.SECOND_NET_FIELDS`).

---

## 13. Provider fragments

The single provider registry (AR11) merges `v3lum/data/providers/` at load time
(`v3lum.core.providers.registry`; problems land in `registry().errors`, never raised):

* `<provider_id>.json`, schema `v3lum.provider/1` - the full schema is the example in 1.1: `id`
  (= file stem, `^[a-z][a-z0-9_]{1,63}$`), `name`, `operator`, `hosts`, `hosts_from_settings`
  (setting names whose URL host is added at runtime), `internal`, `tier`
  (`v3lum.core.providers.TIERS`) with `tier_rationale`/`tier_reviewer`/`tier_date`, `flags` (all
  four booleans required: `publishes_queries`, `reuses_queries`, `fetches_target`, `sensitive`),
  `personal_data_review` (null or `{basis, reviewer, date}`), `reliability` (`{grade A..F,
  justification}`, weights `v3lum.core.providers.ADMIRALTY`), `http_profile` (`user_agent`
  null | `neutral` | `contact` | `browser` | a template with `{version}` `{contact}`
  `{contact_url}` `{app}`; `accept`, `accept_language`, `timeout`, `retries` (default 1),
  `max_bytes`, `ttl`, `min_interval` (default 0), `concurrency` (default 4)), `quota` (null or
  `{scope egress_ip|key, hour, day, month, rate_per_second, burst, published, evidence_url,
  safety_margin (default 0.8)}`), `error_markers`, `keys` and `sources`
  (`{"<sid>": {title, terms: {class, evidence_url, quote, checked_at, reviewer,
  free_plan_business_use}, upstream_family, sanitizer, dataset, notes, embeds,
  licensed_alternative}}`).
* `<provider_id>__<suffix>.json`, schema `v3lum.provider-ext/1` (`{schema, extends, hosts,
  sources, error_markers}`): adds only, so parallel packages extend one provider.
* `_set_<name>.json`, schema `v3lum.provider-set/1` (`{schema, providers: [...]}`): data-driven
  site lists owned by one package.

A host belongs to exactly one provider; each fragment has one owning package and others extend it.
Core seeds (wave 1): `core_doh`, `google_public_dns`, `cloudflare_dns`, `quad9`, `internal_doh`,
`shodan`, `iana`, `publicsuffix`, `github`, `abusech`, `internal_misp`, `internal_opencti`. API:
`v3lum.core.providers.registry` (`.get`, `.source`, `.provider_for_host`, `.providers`, `.keys`,
`.errors`, `.hosts_for`), `v3lum.core.providers.register` / `v3lum.core.providers.unregister`
(tests and plugins), `v3lum.core.providers.most_restrictive`, `v3lum.core.providers.TERMS_ORDER`.

Review additions: a source may declare `embeds` (upstream families an aggregator re-serves, P171
consensus) and `licensed_alternative` (text for `doctor --licences`) - `v3lum.core.providers.Source`;
`v3lum.core.providers.PROFILE_REQUIREMENTS` binds the `http_profile` of named hosts whoever owns
their fragment (registro.br RDAP neutral UA + `application/rdap+json` + pt-BR; SEC, Wikimedia,
Nominatim, bgp.tools contact UA; HIBP neutral UA + `flags.sensitive`; SANS ISC JSON; KeyCDN and
PhishTank UA templates; DoH ttl <= 3600) and `v3lum.core.providers.TTL_CLASSES` documents
`http_profile.ttl` per data class (DNS 1 h, RDAP 24 h, CNPJ 72 h, sanitized breach 7 d, crypto 1 h,
sanctions 24 h). Hosts under `.br` get Accept-Language pt-BR by default.

---

## 14. Vocabulary

Attribute, tag and relation names come from the core vocabulary (`v3lum.core.vocab.ATTRIBUTES`,
`v3lum.core.vocab.TAGS`, `v3lum.core.vocab.RELATIONS`) merged with fragments
`v3lum/data/vocab/<pack>.json` (schema `v3lum.vocab/1`: `{"attributes": {name: description},
"tags": {...}, "relations": {...}}`; names `^[a-z][a-z0-9_]{0,63}$`; core first, then fragments in
file order; a re-declared name is allowed - first description wins, listed by
`v3lum.core.vocab.redeclarations`). Names outside the merged vocabulary fail strict mode
(`v3lum.core.vocab.UnknownVocab`). An optional `"timeline": {attribute: label}` section puts a
dated attribute on the case timeline (`v3lum.core.vocab.timeline_attributes`). API:
`v3lum.core.vocab.attributes`, `v3lum.core.vocab.tags`, `v3lum.core.vocab.relations`,
`v3lum.core.vocab.is_known_attribute`, `v3lum.core.vocab.check`, `v3lum.core.vocab.errors`.

Core review additions: attributes `presence`, `sightings`, `generic_address`, `watch_hits`
(list of `{name, registrable_domain, serial, cert_sha256, issuer, not_before, source}` reported by
`watch_source` modules); tags `context_only`, `version_inferred`, `own_asset`, `third_party`,
`unknown_operator`, ...; relations `similar_to`, `same_m365_tenant`. The reference modules' extra
names (`caa`, `soa`) live in `v3lum/data/vocab/reference_modules.json`.

---

## 15. Pivot-link packs

`v3lum/data/pivot_links/<pack>.json`, schema `v3lum.pivot_pack/1` (frozen): `{"pack" (= file stem),
"title", "links": [{"id", "label", "template", "entity_types", "category" (reputation | history |
passive_dns | code_paste | social | company | crypto | geo | search | other), "host", "verified",
"checked_at", "privacy", "publishes" (must be false), "touches_target", "login_required" (must be
false), "antibot", "notes"}]}`. Placeholders (`v3lum.core.links.PLACEHOLDERS`; whitelist via
re.sub, never str.format): `{q} {qp} {raw} {domain} {user} {b64} {b64url} {e164} {e164_plus}
{br_national} {br_national_no9} {wa} {cnpj_fmt} {cnpj_digits} {cnpj_root} {idn} {punycode} {ip}
{asn_num}`. Templates: https only, host equal to the declared host, the value only in
path/query/fragment; **no CPF ever**; no submit/publish/scan endpoints, no login, no
people-search/painel/leak sites; PERSONAL_TYPES/CNPJ templates only to trusted/community provider
hosts (`privacy: true`); unknown-tier hosts only for IOC types, with an 'unknown operator' badge.

API: `v3lum.core.links.render`, `v3lum.core.links.pivot_links_for`, `v3lum.core.links.links_for`
(legacy), `v3lum.core.links.get_link` (`'pack:id'`), `v3lum.core.links.render_manual` (for
`manual_link`), `v3lum.core.links.validate_manual_link`, `v3lum.core.links.lint_pack`.
`v3lum.core.lint.forbidden_probe` `(url, *, method='GET') -> rule id | None` applies the same
tables to runtime-downloaded site lists (A5 rule 2): drop every entry it flags.

---

## 16. Correlation rules

Python rules in `v3lum/correlations/<pack>.py`:
`@rule(rule_id, title, description='', *, version='1', code='', severity='info', criterion='',
references=(), attack=(), false_positives='', fixtures=())` (`v3lum.core.correlate.rule`);
`fn(graph, results)` or `fn(graph, results, rctx)` with `v3lum.core.correlate.RuleContext(now,
org, options, providers, settings, meta)`. Rules only read the graph (`v3lum.core.graph.Graph`)
and emit `v3lum.core.models.Correlation` objects (deterministic ids via
`v3lum.core.models.correlation_id`, criterion, confidence_label, attack, why, recommendation,
evidence); they never schedule modules or pivots and never change opsec or scope.

Every new rule ships positive and negative graph fixtures
`tests/fixtures/rules/<rule_id>/positive_*.json` and `negative_*.json` (schema
`v3lum.graph_fixture/1`: `{"now", "options", "org_profile", "meta", "nodes": [{key, depth, seed,
noise, noise_kind, ownership, criticality, tlp, path_confidence, tags, attributes {name: [{value,
source}]}, findings [...]}], "edges": [{src, dst, relation, module, confidence}], "results": [...],
"expect": {"<rule_id>": {"min", "max", "severity", "confidence_label"}}}`), run automatically by
`tests/test_rule_fixtures.py` through `v3lum.core.correlate.load_graph_fixture`. The eight
`v3lum.core.correlate.LEGACY_RULES` are exempt until replaced. Data rules
(`v3lum/data/rules/*.json|toml`, P301) arrive in wave 4; Python rules stay first-class. ATT&CK ids
extra to core go into `v3lum/data/attack/<pack>.json` (`v3lum.attack_index/1`; `v3lum.core.attack`).

---

## 17. Declarative specs

P331, schema frozen now, compiler in wave 2: `v3lum/data/specs/<name>.json`, schema `v3lum.spec/1`
- fields `name`, `title`, `description`, `category`, `accepts`, `produces`, `provider`, `sources`,
`hosts` (literal), `terms`, `disclosure` (`third_party`), `opsec` (`passive`), `access_model`,
`run_on`, `requires_keys`, `optional_keys`, `max_requests`, `expected_latency`, `min_interval`,
`cache_ttl`, `absent_statuses`, `error_markers`, `manual_link`, `default_enabled`, `health_check
{etype, value, expect}`, `request {url (https, literal declared host; placeholders {value}
{value_q} {value_qp} {domain} {user} {b64} in path/query only), method 'GET', params, headers
(literal or '{key:<name>}'), ignored_status_codes, paginate {param, start, step, max_pages <= 5,
stop_when_empty}}`, `format` json | ndjson | csv | rss | xml | html_json, `results [{key (dotted,
[] for lists), pretty_name, attribute|tag|pivot {type, relation, expand, confidence}, regex,
match_all, format}]`, `multi_match {path, onlyif {path, equals}}`, `found {path, equals|regex}`,
`absent {path, equals|regex}`, `findings [{when {path, equals|regex|gte}, title, severity,
criterion, tags, confidence}]`. Fixtures `tests/fixtures/specs/<name>/` (`ok.*`,
`error_in_200.*`, `expected.json`; [format](../tests/fixtures/specs/README.md)) are mandatory for a
spec to load; compiled classes carry `spec_origin`.

---

## 18. Noise and warning lists

`v3lum/data/noise/<list>.json`, schema `v3lum.noise/1`: `{"kind": cdn|cloud|resolver|webmail|
hosting|saas|sinkhole|parked|benign_scanner|warninglist, "source", "licence", "domains", "ips",
"cidrs"}`. API: `v3lum.core.noise.is_noise`, `v3lum.core.noise.noise_kind`,
`v3lum.core.noise.is_sinkhole`, `v3lum.core.noise.is_parked`, `v3lum.core.noise.is_cdn`,
`v3lum.core.noise.legit_platform`, `v3lum.core.noise.warninglists` (list names) and
`v3lum.core.noise.errors`. Kind `warninglist` marks a named warninglist: warninglisted values are
listed, not auto-pivoted, and their malicious findings become `'POSSIBLE - on warninglist
<name>'`. Runtime warninglists backed by a registered dataset use
`v3lum.core.noise.register_list` `(name, *, kind='warninglist', dataset, fmt='misp_warninglist' |
'lines' | 'cidrs', description='')` at import time.

---

## 19. Other decentralised registration

| what | where | schema |
|---|---|---|
| third-party notices | `v3lum/data/notices/<name>.json` + a header in adapted MIT/BSD/Apache code (source URL, commit, licence; never GPL/AGPL/LGPL code, A6) | `v3lum.notice/1` ([format](../v3lum/data/notices/README.md)) |
| backlog entries | `docs/backlog/<package_or_batch>.md` (item, reason, unblock condition) | [format](backlog/README.md) |
| golden-path acceptance routes | `tests/fixtures/acceptance/<type>/<module>.json` for domain `example.com`, ipv4 `8.8.8.8`, url `https://example.com/`, sha256 `275a021b…` (EICAR), email `someone@example.com`, cnpj `00000000000191` | `v3lum.acceptance_routes/1` ([format](../tests/fixtures/acceptance/README.md)) |
| generic / role / test addresses | core `v3lum/data/generic_addresses.json`, read through `v3lum.core.entities.generic_address_kind` | `v3lum.generic_addresses/1` |
| social platforms | `v3lum/data/platforms/<name>.json` (`{platforms: {name: {title, aliases, profile_url_patterns}}}`), merged into `v3lum.core.entities.SOCIAL_PLATFORMS` | `v3lum.platforms/1` |
| actor / malware aliases | `v3lum/data/aliases/<name>.json` (`{kind: malware_family \| threat_actor, source, licence, names: {alias: canonical}}`; consulted by detection from wave 3) | `v3lum.aliases/1` |
| default avatars | `v3lum/data/default_avatars/<platform>.json` (`{platform, dhash, sha256, source}`; never identity evidence) | `v3lum.default_avatars/1` |
| method allow-list | `v3lum/data/policy/method_allowlist/<module>.json` (`{module, methods: {method: justification}, approved_by, decision_ref}`; a core policy decision, only for state-changing methods toward targets) | `v3lum.method_allow/1` |
| optional dependencies | `v3lum/data/extras/<package>.json` (section 1.3) | `v3lum.extra/1` |

---

## 20. Entity types

`v3lum.core.entities.EntityType` (fixed in wave 1): every v1 type plus `email_headers`,
`telegram_handle`, `telegram_invite`, `discord_invite`, `social_account` (`'<platform>:<handle>'`),
`pix_brcode`, `imphash`, `tlsh`, `telfhash`, `gimphash`, `authentihash`, `icon_dhash`,
`code_signing_cert`, `pgp_fingerprint`, `fediverse_handle`, `bsky_handle`, `steam_profile`,
`port_service`, `vin`, `telegram_bot_token`, `secret` (masked fingerprint
`'<kind>:<first4>…<last4>:<sha16>'`), `payment_card` (BIN6…last4, never the full PAN), `eu_vat`,
`tiktok_video_id`, `snowflake_id`. Build entities with `v3lum.core.entities.Entity`
(`Entity.make` / `Entity.try_make`); normalizers reject invalid values.

Type sets (A8): `v3lum.core.entities.PERSONAL_TYPES`, `v3lum.core.entities.IOC_TYPES`,
`v3lum.core.entities.SECRET_TYPES` (never sent anywhere or exported),
`v3lum.core.entities.NO_AUTO_EXPAND`; `v3lum.core.entities.STIX_SCO`;
`v3lum.core.entities.display_value` `(etype, value, *, show_personal=False)` (CPF
`***.456.789-**`), `v3lum.core.entities.redacted_value`, `v3lum.core.entities.secret_entity`,
`v3lum.core.entities.generic_address_kind`, `v3lum.core.entities.platform_for_url`. Validators:
`v3lum.core.validators.crypto_address_info` -> `v3lum.core.validators.CryptoInfo(chain, kind,
network, checksum_ok, confidence)`, `v3lum.core.validators.keccak256`,
`v3lum.core.validators.eip55_checksum`, `v3lum.core.validators.xmr_address_valid`,
`v3lum.core.validators.xrp_address_valid`, `v3lum.core.validators.sol_address_plausible`,
`v3lum.core.validators.onion_valid`, `v3lum.core.validators.btc_address_info`.

---

## 21. Testing

Every module gets `tests/modules/test_<name>.py` plus trimmed real fixtures in
`tests/fixtures/<name>/`. **Unit tests never touch the network.** The kit is `tests/fakes.py`:

| name | use |
|---|---|
| `tests.fakes.FakeHttp` | Transport + legacy client: `add(method, url \| prefix* \| regex, *, status, json, text, body, headers, error, final_url, match_headers, redirect_to, times, latency)`; `calls`, `urls()`, `hosts()`, `unexpected`, `assert_hosts_within(module_cls, *, extra=())`. Exact URLs compare normalised (lower-case scheme/host, query order-insensitive); `times` gives a response sequence; unmatched requests raise `tests.fakes.UnexpectedRequest` (an AssertionError) and are recorded in `unexpected` |
| `tests.fakes.DeadHttp` | every request fails like a dead network |
| `tests.fakes.FakeClock` | `now`, `monotonic`, `sleep` (never blocks), `advance` |
| `tests.fakes.DOH_HOSTS`, `tests.fakes.doh_url`, `tests.fakes.doh` | the core DoH hosts, the exact resolver URLs (Google carries `edns_client_subnet=0.0.0.0/0`), a DoH JSON answer |
| `tests.fakes.add_dns` | `(http, name, rtype, records, *, status=0, ad=False, provider='google' \| 'cloudflare' \| 'all')` |
| `tests.fakes.add_dns_failure` | `(http, name, rtype, *, kind='servfail' \| 'refused' \| 'http500' \| 'http429' \| 'challenge' \| 'timeout', provider='google')` |
| `tests.fakes.add_nxdomain_everything` | every other DoH query answers NXDOMAIN (both resolvers) |
| `tests.fakes.make_runtime` | `(http=None, *, keys, settings, clock, org_profile, cache=False, offline=False)`: the real HttpClient over the fake transport |
| `tests.fakes.make_ctx` | `(module_cls, http=None, *, keys, options, settings, entity, is_seed=True, depth=0, provenance=(), allowed_sources=None, tlp=None (= options, amber), org_profile, clock, runtime)` |
| `tests.fakes.run_module` | `(module_cls, entity, http=None, **ctx_kwargs)` through `Engine.run_module` (status mapping, sanitizer, caps): **the recommended way**; a request without a route fails the test even though the engine maps the module's exception to an ERROR result |
| `tests.fakes.define_module` | `(name, accepts, run, **attrs)` synthetic module (defaults terms open, disclosure none, hosts (), PASSIVE, category utility) |
| `tests.fakes.test_provider` | context manager registering a synthetic provider fragment (`provider_id='test_provider', *, hosts=('api.example.test',), tier, terms, sensitive, sources=('default',), keys, **extra`); `tests.fakes.source_ids` lists its qualified source ids |
| `tests.fakes.allow_vocab` | `(attributes=(), tags=(), relations=())` temporarily extends the vocabulary |
| `tests.fakes.fixture`, `tests.fakes.module_fixture` | `tests/fixtures/<name>`, `tests/fixtures/<module>/<name>` (JSON parsed) |
| `tests.fakes.graph_fixture` | `(path) -> (Graph, results, RuleContext)` |
| `tests.fakes.assert_no_secret` | `(secret, *items)`: str/bytes/dict/objects/Paths (directories recursively, SQLite as bytes; raw, URL-encoded and base64 forms) |

`tests/conftest.py` gives every test an isolated `V3LUM_HOME`, **the network guard** (only
loopback unless `@pytest.mark.live` with `V3LUM_LIVE=1`: TCP connects, UDP `sendto`/`sendmsg`,
`getaddrinfo` and the legacy `gethostbyname`/`gethostbyaddr`/`getnameinfo` lookups; proxy
variables removed), an environment scrubbed of every key variable (`v3lum.config.key_env_names` +
`*_API_KEY`, `*_TOKEN`, `*_AUTH_KEY`, `*_APIKEY`, `*_KEY`, `*_SECRET`, `*_PASSWORD` and `V3LUM_*`
except `V3LUM_HOME`/`V3LUM_LIVE`), `V3LUM_STRICT=1`, the fixtures `clean_registry`
(snapshot/restore of the module REGISTRY, correlation rules, programmatic provider registrations,
module settings, sanitizer schemas, datasets, runtime noise lists, module load errors and the
vocab/link caches; the same as the `registry_snapshot()` context manager), `fake_clock`,
`fake_http`, and the markers `live`, `safety`, `acceptance`, `slow`. Live checks go in
`tests/live/`, benign values only.

Write at least, per module: a parse test on a trimmed real fixture, a test per meaningful absence
(`absent_statuses`), a 429 test, a challenge-page test (and an error-in-200 test for every declared
marker), a dead-network test for DNS modules, and `http.assert_hosts_within(Module)`.

Run: `pytest -q` (offline) · `V3LUM_LIVE=1 pytest -q -m live` · `ruff check v3lum tests`.

---

## 22. Registry contract test

`tests/test_registry_contract.py` gates every merge. It re-checks the metadata of every registered
module **independently of `@register`** (a bypassed registration or a class without `@register` is
still caught: the registration mark must be present and the section 2 derived attributes -
`trust_tier`, `providers`, `sensitive`, `publishes_queries`, `reuses_queries`, `fetches_target`,
`shares_input`, `max_tlp` - must equal what the provider registry gives) and requires: no
`load_errors()`, provider registry, vocabulary, link, rule, noise or ATT&CK errors; v2 enums and
explicit declarations (`access_model` declared for third_party); every host and source registered,
hosts owned by the providers of the module's sources and the primary provider among them; terms ==
the most restrictive source class; the A3 default rules; an offline health self-test for
LIGHT/ACTIVE modules and the safety-suite gate (fails while `tests/safety/test_scope.py` is
absent); probe health checks on an accepted type with the central benign value of
`v3lum.core.module.BENIGN_VALUES` (never a personal type without one, P332 cond 9);
`requires_keys` registered; unique settings; a test file using `tests/fakes.py` + fixtures per
module (disclosure `none` modules may use inline data but still need the file; compiled P331 specs
use `tests/fixtures/specs/<name>/`); sanitizer schemas for sensitive modules; rule fixtures for
non-legacy rules; registered dataset sources and licences (`v3lum.core.datasets.dataset_errors`);
parseable notice fragments (attribution present, sha256 empty or hex, existing repository paths,
no copyleft/share-alike/NC material bundled). `PROFILE_REQUIREMENTS` violations surface as registry
errors. The P327 lint gate (`tests/test_lint.py`) arrives in wave 2. Vocabulary re-declarations
with a different description are printed as warnings.

---

## 23. Team rules, LGPD, licence and TLP defaults

Team rules (inherited from Céos, approved by Council #1) - enforced in code where possible:

1. **Open/public sources only.** No CAPTCHA or anti-bot bypass, no logging into third-party
   accounts, no borrowed cookies or session ids. Challenge-protected sites are manual links only
   (A9).
2. **No account enumeration** through password-reset/sign-up endpoints and no SMTP probing
   (`v3lum.core.lint.forbidden_probe`).
3. **Breach data is metadata only**: breach names, dates, data classes, counts, the password form.
   Never store or print passwords, hashes, masked password hints or leaked file contents (A4, the
   sanitizer of section 12).
4. **No people-search in leaked databases** (CPF/name/phone 'painéis'). Official open data (CNPJ,
   QSA) is fine; **CPF is validated offline only** and never appears in a link or a request.
5. **403/429/timeouts mean "could not verify"**, never "absent", and errors inside HTTP-200 bodies
   must be detected (error markers, classification).
6. **Respect provider limits and quotas** (`min_interval`, provider quota blocks, `daily_quota`).
7. **Never send values to services that publish submissions** (`publishes_queries` providers never
   receive a value; search endpoints only).

Also binding: active probing only with explicit authorization (`--authorized REF` + a scope file,
A7); reports are self-contained; no biometrics or sensitive-data inference.

Defaults that every module inherits:

* **Licence (A1)**: `licence_profile = 'corporate'`: `open` sources run; `key-terms` only with a
  business plan (`free_plan_business_use` or `key_plans.<key> = 'business'`); `noncommercial` and
  `license` only through an active licence_allow entry; `unknown` never. A licence-blocked source
  is SKIPPED `licence`, is never replaced by a LIGHT/ACTIVE alternative and gets its manual link.
* **TLP (A2)**: scans default to **TLP:AMBER**; AMBER excludes unknown-tier and query-reusing
  providers, AMBER+STRICT allows trusted providers only, RED allows offline and internal platforms
  only (DNS then needs an internal resolver, otherwise 'could not verify'); TLP is inherited by
  pivots. `v3lum.core.tlp.TLP`, `v3lum.core.tlp.parse`.
* **Privacy (A4, A8, LGPD)**: per-person breach/stealer modules use `run_on='own_assets'`;
  PERSONAL_TYPES never go to unknown-tier providers; generic/role/test addresses are context only;
  personal values are pseudonymised (keyed HMAC) in file names and search indexes; purpose and
  ticket are recorded when a seed is personal (AR16). TLP is not a privacy classification: the LGPD
  controls apply at every TLP.
* **Tier (A8)**: unknown-tier providers are never default, excluded at AMBER and above and need
  `--allow-unknown` at CLEAR/GREEN.
* **Default set (A3)**: `default_enabled` only lowers the computed default set (section 1.6).

---

## 24. Worked examples: the four reference modules

The four reference modules are the templates to copy. Each has its test file in
`tests/modules/` and trimmed real fixtures in `tests/fixtures/<name>/`.

### 24.1 `dns_records` - DoH-only module, rule 5 for DNS

```python
@register
class DnsRecords(Module):
    name = "dns_records"
    category = "domain_dns"
    accepts = {T.DOMAIN}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"           # the resolver operator sees the name, never the target
    provider = "core_doh"
    sources = ("core_doh.resolvers",)
    hosts = ()                           # DoH hosts are core, not declared
    access_model = "free_noauth_unlimited"
    max_requests = 0                     # ctx.dns is not counted
    expected_latency = 1.5
```

It queries A/AAAA/CNAME/MX/NS/TXT/SOA/CAA through `ctx.dns`, records vocabulary attributes and the
resolver of every answer in the evidence, and pivots on addresses and hosts (MX/NS with
`expand=False`). Rule 5: when no answer is NOERROR the run ends ERROR 'could not verify';
'Domain does not resolve (NXDOMAIN)' needs `ctx.dns.confirm_nxdomain()` to return True; 'No
web-facing address' needs NOERROR answers for A, AAAA **and** CNAME; types that could not be
verified are named in `res.error`, never turned into absences. The AD flag is 'validated by
resolver'. Tests: real example.com/github.com answers, a dead-DoH test, unconfirmed NXDOMAIN,
partial SERVFAIL, 429/challenge/5xx/timeout on both resolvers.

### 24.2 `email_basics` - DoH-backed facts about an address

Same DoH-only metadata. It pivots to the domain (`expand=False` for free webmail), the base mailbox
of plus-addressing (`same_person`, `expand=False`: a derived personal identifier waits for the
analyst) and the local part as a weak username (`possible`, `expand=False`, never for generic
mailboxes). `mx_valid` is set only from NOERROR answers (MX, or the implicit MX of RFC 5321
through A/AAAA) or a confirmed NXDOMAIN; a DoH failure leaves it unset, never yields 'Email
domain does not accept mail' (P328 cond 8) and is recorded with
`res.source_status('core_doh.resolvers', 'error', ...)` so coverage counts the source as 'could
not verify' while the offline facts about the address stand. Generic, role and test addresses are
flagged through `v3lum.core.entities.generic_address_kind` (attribute `generic_address`, tags
`info` and `context_only`, never scored).

### 24.3 `shodan_internetdb` - keyless HTTP API module

```python
@register
class ShodanInternetDB(Module):
    name = "shodan_internetdb"
    accepts = {T.IPV4, T.IPV6}
    terms = "noncommercial"              # A1 initial class: off under corporate until licence-cleared
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "shodan"
    sources = ("shodan.internetdb",)
    hosts = ("internetdb.shodan.io",)
    access_model = "free_noauth_limited"
    absent_statuses = frozenset({404})   # 'No information available' (documented)
    max_requests = 1
    expected_latency = 1.0
    manual_link = "core_reference:shodan_host"
    notice = "Shodan InternetDB terms are noncommercial: off under the corporate profile until licence-cleared."
```

`ctx.http.get_json(url, source=...)` returns None for the documented 404 (EMPTY); 429 becomes
RATE_LIMITED, challenge pages (even with HTTP 200) BLOCKED/challenge and a keyless 403
BLOCKED/challenge - the module just lets the exceptions propagate. Findings carry
`source='shodan.internetdb'`; CVEs are one finding per host, 'CVE(s) associated with exposed
software (version-inferred)', severity medium, confidence `possible`, tag `version_inferred`,
criterion 'version-inferred, distro backports not considered: confirm on the host'; CVE pivots are
`possible`. Hostnames on CDN/cloud edges are recorded but not expanded. The answer is untrusted
data: a body that is not a JSON object ends ERROR 'could not verify' (never EMPTY) and every field
is type-checked (junk CVE ids and non-list fields are dropped).

### 24.4 `ioc_extract` - offline module

```python
@register
class IocExtract(Module):
    name = "ioc_extract"
    accepts = {T.TEXT, T.FILE}
    terms = "open"                       # no registry source
    opsec = Opsec.PASSIVE
    disclosure = "none"                  # the text never leaves the machine: ctx.http refuses everything
    hosts = ()
    access_model = "offline"
```

IOC_TYPES pivot with `expand=True`; PERSONAL_TYPES with `expand=False` and the note 'personal
identifier from text: analyst selection required'; CPF and SECRET_TYPES are never pivoted - they
are counted and shown as masked previews only (`v3lum.core.entities.display_value`). Files are
read only when they are regular text files of at most 20 MB (a vanished file, a FIFO or a device
is not applicable; an unreadable one ends ERROR).

---

## 25. Arriving later

Names that later waves add (not importable yet; `tests/test_module_guide.py` does not resolve the
names of this table). Each lands with its package's `docs/contract_additions/<package>.md`.

| name | package (wave) | what |
|---|---|---|
| `v3lum.core.policy.decide` | WP07 (wave 2) | the single policy gate -> Decision(allowed, status, reason_code, reason) |
| `v3lum.core.licence.source_allowed` | WP07 (wave 2) | licence profile and allow-list evaluation |
| `v3lum.core.sanitize.scrub_text` | WP09 (wave 2) | free-text scrubbing of combos and masked hints |
| `v3lum.core.lint.lint_module_source` | WP09 (wave 2) | the forbidden-capability lint (P327 static rules) |
| `v3lum.core.specs.compile_spec` | WP12 (wave 2) | declarative spec -> Module subclass |
| `v3lum.core.scope.Scope` | WP11 (wave 2) | ACTIVE scope files (A7) |
| `v3lum.core.tools.ToolSpec` | WP11 (wave 2) | external binaries for LIGHT/ACTIVE modules through `ctx.net.run_tool` |
| `v3lum.core.evidence.EvidenceStore` | WP08 (wave 2) | evidence store v2 |
| `v3lum.core.hmacid.hmac12` | WP10 (wave 2) | keyed HMAC pseudonyms |
| `v3lum.core.ioc.extract` | WP17 (wave 3) | IOC extraction engine (decode, refang, validate, warninglist) |
| `v3lum.core.rules_engine.compile_rule` | WP22 (wave 4) | data rules `v3lum.rule/1` |
| `v3lum.core.tls.check_interception` | WP25 (wave 5) | TLS-interception check |
| `v3lum.core.watch.Watcher` | WP26 (wave 5) | the watch-source invocation of `v3lum watch` |

---

## 26. Additions after the freeze

After the freeze the contract only grows. Every package that adds module-facing names documents
them in its own file `docs/contract_additions/<package>.md` (additions only; never a rename or a
behaviour change; format in [docs/contract_additions/README.md](contract_additions/README.md)). A
behaviour change needs an architect-approved migration recorded in this guide.
