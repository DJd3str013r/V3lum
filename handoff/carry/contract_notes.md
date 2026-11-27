# Contract notes from finished waves

## Wave 1 (integrator)

docs/MODULE_GUIDE.md is FROZEN as contract v2 (header 'FROZEN 2026-11-26') on the green integrated tree. It now describes the code exactly and marks behaviour that is enforced later as 'from wave N'. Later packages only add names, documented in docs/contract_additions/<package>.md. tests/test_module_guide.py resolves every backticked v3lum./tests.fakes. name, runs the guide example module with its test, and checks the ClassVar and derived-attribute tables. The section 24 excerpts were verified against the reference classes (WP17 will change ioc_extract in wave 3: update that excerpt only through the guide's migration rule).

Names and behaviour added or changed by the integration (all wave-1 files):
- v3lum.core.context.settings_hosts(module_cls, config, registry=None) is the single hosts_from_settings rule (https only, never a host owned by another provider), used by ctx.http and tests.fakes.
- ctx.setting() unwraps SettingSpec declarations, so module settings may declare SettingSpec(default, description, choices=...).
- @register refuses absent_statuses that contain 401/403/407/429/430/451 or 5xx.
- Inherited normalised attributes are listed in the registration mark (inherited settings keep their owner).
- Engine.run_module(cls, entity) without run= treats the run as an analyst-typed seed at depth 0.
- Engine.investigate() calls runtime.http.reset_circuit() at the start of every scan.
- Coverage reason_code is always valid for the merged coverage status.
- vocab: the core tables are always read live; fragments merge on top.
- tests/conftest.registry_snapshot also restores correlate.RULE_REPLACED and correlate._COMPILERS.
- tests/test_registry_contract.registered_ancestors(cls) exists; the contract test also checks entities.platform_errors() and module.extras_errors().
- tests/fixtures/rules/young_domain/ is the worked graph-fixture example.
- The generic/role address list includes administrator, helpdesk, hr, it, ti.

Interim wave-1 behaviour authors must know (documented in the guide):
- A plain `v3lum scan` runs only disclosure 'none' modules. Source modules need -M, --all-modules or `v3lum run` until WP08's policy gate.
- TLP:RED keeps third_party/target modules away in scans; publishes_queries modules never run (rule 7, also in run_module); an exhausted daily_quota gives QUOTA 'quota'.
- ctx.allowed_sources is every declared source in wave 1.
- run_on, licence, tier and privacy gates arrive in wave 2.
- In --offline mode, DoH-only modules end ERROR 'could not verify' (uncached DoH answers carry error 'offline: ...'), not UNAVAILABLE 'offline'. Deliberately unchanged to keep offline facts such as email_basics' generic-address flag.
- The CLI --tlp flag still defaults to 'clear' (WP13).

Process note: the orchestrator committed checkpoint 1ca9c1b during this run. `git diff 8c7a71b` shows all integration changes. The 25 files are listed in the fixes, including two outside the wave: v3lum/ui/render.py and v3lum/ui/theme.py (WP14 owner).

## Wave 1 (auditor)

The guide stays marked 'V3LUM module contract v2 - FROZEN 2026-11-26'. My edits only add documentation and the four behaviours below. No public name was renamed and every plan public_api name now appears in backticks and resolves.

Behaviours later waves and module authors must know:
(1) Engine.run_module: a run() returning anything but a ModuleResult ends ERROR 'error' (never EMPTY).
(2) Right after the sanitizer, engine._redact_result masks configured key values and KEY_PARAMS query parameters, using redact.redact_text, in: finding title, description, criterion, key, references and data; attributes; links; pivot notes; source_statuses; res.error; res.raw. Pivot entity values change only when they contain a registered secret, so a key-like parameter of an investigated URL stays part of the IOC. Finding ids are computed after this pass. The pass fails closed with the sanitizer (ERROR 'sanitizer').
(3) Evidence files are created 0600.
(4) A case where no module answered gets the note 'inconclusive: no source answered (...)'. WP14/WP19/WP20 should turn this into the 'inconclusive' level.
(5) correlate: legacy=True is honoured only for correlate.LEGACY_RULES ids. Any other id gets RuleInfo.legacy=False and a RULE_ERRORS entry, which fails the contract test. Pack rules in WP22-WP24 must ship tests/fixtures/rules/<id>/positive_*.json and negative_*.json.
(6) HttpClient: a body from a provider flagged sensitive is sanitized and cached only when the request's source= is one of that provider's own sources ('<sensitive pid>.<sid>'). Otherwise it is no-store: the module gets the raw body in memory and the engine sanitizer still applies. Sensitive modules with several sources must name the right source=.

Test kit additions: tests/test_engine_status_mapping.py gained four tests; test_rule_api, test_http_profiles, test_orgprofile and test_datasets gained one each. The suite is green on 3.13 (1960) and on the 3.10 venv (1957 passed, 3 TOML skipped).

## Wave 2 (integrator)

Contract v2 (docs/MODULE_GUIDE.md) is unchanged and test_module_guide is green. Everything below is an addition or a gate behaviour the plan mandates.

(1) Provider token bucket (P334): HttpClient now spends quota.reserve's wait before every request to a provider's hosts. That includes ctx.data downloads of the provider, which share the bucket. The longest accepted wait is max(quota.RATE_WAIT_MAX = 15 s, one provider interval = 1/(rate_per_second x safety_margin)), still bounded by the run deadline. Anything longer is RATE_LIMITED 'could not verify now', never an absence. A module making two requests to a slow provider needs a timeout above one interval. Known limit: a slot reserved and then refused for lack of time is not released.

(2) LINT-07: a P145 schema keep path may name a password-FORM carrier (password_risk/passwordRisk/password_type/password_algorithm...; lint.is_password_form_carrier). The sanitizer renames it password_form or drops it.

(3) LINT-03 flags SMTP-probe APIs (smtp-check, smtpVerify, smtp_test, smtp-probe...). '_smtp._tls' DNS names are fine.

(4) scope.PLACEHOLDER_REFS equals policy.AUTH_REF_PLACEHOLDERS: confirmed, yes, ok, none, n/a, test, tbd, todo, xxx, null, true, authorized.

(5) Profile-site specs (A5) need their provider fragment to declare http_profile.concurrency 1. specs.AUTO_DISABLE_DAYS is health.SPEC_DISABLE_DAYS.

(6) POL-03: gated --offline runs make third_party/internal/target modules (DoH-only ones included) UNAVAILABLE 'offline'. Ungated Engine.run_module keeps the wave-1 'ERROR could not verify' DoH behaviour.

(7) Engine passes reason_code to health.record_run; BLOCKED 'circuit'/'hostile_host' runs are neutral for demotion.

(8) The contact guard reads graph collections through snapshots (thread-safe for redirect hops).

(9) CTI labels whose literal matches brute[-_ ]?forc (e.g. the tag 'bruteforce') trip LINT-09 and need a justified pragma.

(10) Orphan wave-1 tests (test_links, test_noise, test_datasets, test_entity_types_v2) now tolerate module-batch data fragments (pivot packs, warninglists, essential datasets, platforms). Batch data may grow those registries freely.

## Wave 2 (auditor)

No contract v2 name was renamed and no frozen behaviour changed. tests/test_module_guide.py passes, and every new ctx-facing name is either in MODULE_GUIDE or in docs/contract_additions/WP07..WP12.md; each doc names its package's public_api additions. Behaviours added in this audit: (1) LINT-01 now flags the v1 ad-hoc dataset download form ctx.data.fetch*(name, url) in module, plugin and spec sources. Module authors call register_dataset(...) in the module file and fetch by name; the runtime still accepts the form, as guide section 9 says. Documented in docs/contract_additions/WP09.md. (2) The contact guard reads the live case graph through snapshots, so a racing graph update never causes a spurious hostile_host refusal on redirect hops. (3) Engine policy-failure log lines are redacted. Note for module batches: POL-14 ties every large registered dataset of a source to every module that lists that source. If two batches share a registry source and one adds a large dataset, the other module becomes UNAVAILABLE 'dataset' until that dataset is downloaded. Use distinct source ids when the datasets are independent. Wave 3 is already wired as WP08 requires: app.py calls Store.record_cache_keys and record_report_paths, and v3lum run goes through Engine.decide_single then run_module(decision=).
