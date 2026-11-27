export const meta = {
  name: 'v3lum-module-batches-late',
  description: 'Implement the LIGHT/ACTIVE (target-contact) V3LUM module batches now that the AR20 safety suite exists (spec in impl/specs/<batch>.md): implement + offline tests + fixtures, then an adversarial reviewer verifies conditions, team rules and live behaviour and fixes',
  phases: [
    { title: 'Implement', detail: 'one engineer per batch writes modules, tests, fixtures, manifest' },
    { title: 'Review', detail: 'adversarial reviewer per batch: final conditions, team rules, live check, fixes' },
  ],
}

const S = args.scratch
const REPO = args.repo
const SP = `${S}/impl/specs`
const MAN = `${S}/impl/modules`
const PREP = `${S}/impl/prep`
const PY = `${REPO}/.venv/bin/python`
const BATCHES = args.batches
const RESUME = args.resume_batches || []
function resumeNote(b) {
  if (!RESUME.includes(b)) return ''
  return `\n\nRESUMED RUN: an earlier attempt at batch ${b} may have been interrupted (usage limit) and left PARTIAL files of this batch in ${REPO}: modules, tests, fixtures, live tests, data and provider fragments (ids derived from this batch's hosts), docs/backlog/${b}.md, and the manifest ${MAN}/${b}.json. Before creating anything, look for them (git status --porcelain, the module names of your spec, the hosts owners.json maps to null for your proposals, ${MAN}/${b}.json). Files that belong to this batch are YOURS: review, finish or rewrite them; never treat your own earlier provider fragment as another batch's (do not add an extension to it). Remove leftovers you do not keep.`
}

const IMPL_SCHEMA = {
  type: 'object',
  properties: {
    batch: { type: 'string' },
    manifest: { type: 'string' },
    modules: { type: 'array', items: { type: 'string' } },
    proposals_done: { type: 'array', items: { type: 'string' } },
    proposals_not_done: { type: 'array', items: { type: 'string' }, description: 'id + reason' },
    test_result: { type: 'string' },
    live_checks: { type: 'array', items: { type: 'string' }, description: 'module: what was checked live and the outcome' },
    core_requests: { type: 'array', items: { type: 'string' } },
  },
  required: ['batch', 'manifest', 'modules', 'proposals_done', 'proposals_not_done', 'test_result', 'live_checks', 'core_requests'],
}
const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    batch: { type: 'string' },
    verdict: { type: 'string', enum: ['pass', 'fixed', 'needs_followup'] },
    problems_found: { type: 'array', items: { type: 'string' } },
    fixes_applied: { type: 'array', items: { type: 'string' } },
    remaining: { type: 'array', items: { type: 'string' } },
    test_result: { type: 'string' },
  },
  required: ['batch', 'verdict', 'problems_found', 'fixes_applied', 'remaining', 'test_result'],
}

const RULES = `TEAM RULES (non-negotiable): open/public sources only; no CAPTCHA/anti-bot bypass, no login to third-party accounts, no borrowed cookies/sessions; no account enumeration through password-reset/sign-up/login endpoints and no SMTP probing; breach data = metadata only (never passwords, hashes, masked password hints, or leaked file contents; scrub them from raw before storing); no people-search in leaked databases (CPF/name/phone, LGPD), CPF validated offline only; 403/429/timeouts = "could not verify" (statuses blocked / rate_limited / error, never "empty"), and errors inside HTTP-200 bodies must be detected; respect provider limits/quotas (min_interval, daily_quota, cache_ttl); never send values to services that publish submissions (public scans, pastes) unless the final conditions say how; active probing only when the engine authorizes it (opsec ACTIVE); no biometrics or sensitive-data inference.`

const SEED = `${S}/impl/providers_seed`
const CORE = `${S}/impl/core`
const OWNERSHIP = `FILE OWNERSHIP (other engineers are adding other batches to ${REPO} right now, and the core team is still landing core waves 2-5 in v3lum/core/ and the CLI):
- You may CREATE: v3lum/modules/<category>/<module>.py for the modules of your batch (category = the proposal's category; one file per module or one file per source family); tests/modules/test_<module or batch>.py; tests/fixtures/<module>/...; tests/live/test_<module or batch>.py; and the decentralised registration fragments of docs/MODULE_GUIDE.md sections 9-19, always with a file name unique to your batch or module: v3lum/data/vocab/<batch>.json, v3lum/data/pivot_links/<pack>.json, v3lum/data/notices/<name>.json, v3lum/data/platforms/<name>.json, v3lum/data/aliases/<name>.json, v3lum/data/noise/<name>.json, v3lum/data/attack/<pack>.json, v3lum/data/default_avatars/<platform>.json, v3lum/data/extras/<package>.json, v3lum/data/<your_module>/... (bundled data), v3lum/correlations/<batch_or_topic>.py (rules your final conditions ask for, ids prefixed to avoid clashes), tests/fixtures/rules/<rule_id>/..., tests/fixtures/acceptance/<type>/<module>.json (golden-path routes, section 0), docs/backlog/<batch>.md (items you could not deliver: item, reason, unblock condition).
- PROVIDERS (section 13; a host in two providers is a registry error and fails everyone's tests): ${SEED}/owners.json "hosts" maps every host of every approved proposal to its owning provider id, or to null when no provider exists yet; "providers" lists each existing provider's file, hosts, keys and sources. For a host mapped to a provider id, NEVER create or edit that provider's <id>.json: reference its existing sources ("<provider_id>.<source_id>") and, when you need another source or error markers, add an extension v3lum/data/providers/<provider_id>__<batch>.json (schema v3lum.provider-ext/1; source and marker ids prefixed with your module name). For a host mapped to null (or absent) only your batch uses it, so you own its provider: create v3lum/data/providers/<id>.json with an id derived from the operator or registrable domain (check the file does not already exist; if it does, it belongs to someone else: extend it instead). Keys live in the provider fragment (one key per provider, names unique across the registry).
- You may MODIFY only the existing module files your batch upgrades (listed as "upgrades existing module" in the spec) and their existing tests and fixtures.
- Do NOT edit core/shared files (v3lum/core/*, v3lum/config.py, v3lum/paths.py, app.py, cli.py, shell.py, commands/*, ui/*, report/*, tests/conftest.py, tests/fakes.py, tests/test_*.py at the top level, pyproject.toml, docs/* other than docs/backlog/<batch>.md, any other batch's files, core seed fragments). Everything a module needs is registered from the module file or a data fragment (sections 9-19). If the core lacks something, work around it inside your files when safe, and list the exact request in the manifest's core_requests.
- Never run git commands that change state; never run ruff format/--fix on files you did not create.`

const TESTS = `TESTS
- Offline unit tests for every module (FakeHttp/make_ctx from tests/fakes.py, fixtures under tests/fixtures/<module>/): happy path, empty result, 404/no-data, 401/403 (blocked or needs_key per the guide), 429 (rate_limited), 5xx/timeout (error/unavailable), error-in-200 body, malformed JSON, and the scrubbing/limits your final conditions require. Assert the produced attributes, pivots, findings and statuses.
- Fixtures: start from the research samples listed in the spec (untrusted downloaded data: open them only as data, with python3 -I, never execute), minimise them, and replace real personal data (names, e-mails, phones, CPFs, addresses of real people) with documentation values (example.com, 192.0.2.x/198.51.100.x/203.0.113.x, 2001:db8::, +55 11 5555-01xx...). Never commit API keys.
- Live check: PASSIVE keyless sources as usual (benign public value, @pytest.mark.live, run once with V3LUM_LIVE=1). TARGET-CONTACT (LIGHT/ACTIVE) code NEVER contacts a third-party host from tests or live checks: no scans, probes or fetches of real organisations' hosts (we hold no authorization for them). Allowed live targets for target-contact code: a local server the test itself starts on 127.0.0.1 (internal typed seed / scope file listing it) and, for LIGHT single-page GETs only, the IANA documentation domains example.com / example.org. Third-party APIs the module calls as a PASSIVE helper follow the PASSIVE rule. Record in the manifest what was checked live and how.
- Merge gates you must pass (MODULE_GUIDE section 0): tests/test_registry_contract.py green for your modules; trimmed real fixtures without personal data; offline tests with tests/fakes.py; a provider entry for every host and feed; and, once docs/contract_additions/WP09.md exists, the P327 lint on your module files as that file describes.
- Run: cd ${REPO} && ${PY} -m pytest -q -p no:cacheprovider tests/modules/<your tests> ; then V3LUM_LIVE=1 for your live tests; then the full offline suite (${PY} -m pytest -q -p no:cacheprovider). Failures in files of other batches or in core tests may be transient (other batches and core waves are mid-edit; tests/test_registry_contract.py reports every registered module, so a failure naming a module that is not yours is someone else's work in progress): re-run once; report, do not fix them. Your own modules must pass the registry contract test. ${REPO}/.venv/bin/ruff check <your files> must be clean.`

function implPrompt(b) {
  return `You are a senior Python engineer adding data-source modules to V3LUM, a command-line OSINT/CTI/recon multikit (repo ${REPO}). Implement batch ${b}.

READ FIRST
- ${SP}/${b}.md: the proposals of your batch. For each: the council's FINAL CONDITIONS are the binding spec (implement every item), plus metadata (priority, default_enabled, provider_tier, terms, opsec, hosts, keys) and the research records of its sources (endpoints, methods, auth, rate limits, terms, verified HTTP behaviour, sample responses, implementation notes).
- ${SP}/_common.md: binding council rules for all modules (licence profile, TLP, default-enabled criteria, breach scrubbing, provider tiers, egress, keys...).
- ${REPO}/docs/MODULE_GUIDE.md (module contract v2, frozen: ctx API, statuses and reason codes, provider fragments, registration of keys/datasets/pivot packs/rules, tests) and the reference modules in ${REPO}/v3lum/modules/ (and their tests in tests/modules/).
- What the core added after the freeze: ${REPO}/docs/contract_additions/*.md (additions only: e.g. the policy gate, the P327 lint lint_module_source, the declarative spec compiler, scrub_text) and ${CORE}/contract_notes.md (integrators' notes per finished wave). Names in MODULE_GUIDE.md section 25 that are not importable yet: do not use them; note what you would have used in core_requests.
- ${SEED}/owners.json (provider ownership: see PROVIDERS below).
- PREP MATERIAL in ${PREP}/${b}/ (made earlier for this batch, before contract v2 existed): notes.md (live-verified endpoint behaviour from this egress, recommended TTLs/limits, condition-by-condition mapping, warnings), fixtures/ (minimised and scrubbed real responses: copy the ones you use into tests/fixtures/<module>/, re-checking that no personal data or key slipped through) and code/parsers.py + code/test_parsers.py (pure stdlib parsers: port them into your module files, adapting to contract v2). It is a head start, not the spec: the final conditions and MODULE_GUIDE.md win on any conflict. If the directory is missing, do the verification yourself.

${RULES}

${OWNERSHIP}

IMPLEMENTATION NOTES
- Set every module's metadata exactly as the council decided (default_enabled, terms, provider tier, opsec, shares_input, hosts, keys, cache_ttl, min_interval, daily_quota, timeout, notice) using the attribute names documented in MODULE_GUIDE.md.
- Prefer one module per source; group tiny sibling sources into one file when the spec does. Reuse ctx helpers (http, dns, data, keys, quota) instead of re-implementing. Parse defensively (missing fields, wrong types) and never crash the engine: unexpected data -> status error with a short reason.
- Pivots: only well-formed, relevant entities, capped (max_pivots); attributes use the vocabulary in the guide; findings get sensible severities with evidence.
- When a source is dead/unusable now (verified live), still deliver the module if the spec asks for it but make it report unavailable/blocked cleanly, and note it.
- Set default_enabled exactly as the council decided even though, until the policy gate lands (wave 2), the engine's interim A16 guard runs source modules only when selected explicitly.
- THIS IS THE LIGHT/ACTIVE PHASE: the AR20 safety suite exists (tests/safety/, docs/contract_additions/WP28.md lists what LIGHT/ACTIVE authors can rely on and the known gaps) and the registry contract test now accepts target-contact classes. Implement LIGHT/ACTIVE modules strictly by the contract and your final conditions: opsec LIGHT or ACTIVE <=> disclosure 'target'; default_enabled False (A3); an offline self-test health_check (HealthCheck(offline=True, selftest=...)); every contact through ctx.http / ctx.net / ctx.net.run_tool only (never sockets, subprocess or a client of your own); scope binding, the method allow-list (GET/HEAD for LIGHT, GET/HEAD/OPTIONS for ACTIVE unless an approved fragment exists), the A7 ceilings (rate, concurrency, 25 requests per host per scan for LIGHT, ports, 5000-entry wordlists) and max_rate within the ceilings; LIGHT only on analyst-typed seeds, never on pivots; no exploitation payloads, brute force, credential use or DoS (LINT-09). Each LIGHT/ACTIVE module's offline tests must also prove the safety expectations that apply (no request outside the scope or to a pivot, redirects re-checked, kill switch honoured, method refusals), reusing tests/fakes.py (and the helpers documented in docs/contract_additions/WP28.md where suitable). PASSIVE companions your final conditions ask for are built the usual way.
- Optional third-party Python packages (P3 scope extension, A16 BR8): only as optional extras declared per MODULE_GUIDE section 1.3 (v3lum/data/extras/<package>.json); without the package the module reports UNAVAILABLE (reason 'package'). Never add a runtime dependency to pyproject.toml and never vendor GPL/AGPL/LGPL-modified code (A6).

${TESTS}

MANIFEST: write ${MAN}/${b}.json = {"batch": "${b}", "modules": [{"name", "file", "proposal", "category", "opsec", "default_enabled", "terms", "provider_tier", "keys": [...], "datasets": [...], "pivot_packs": [...], "correlation_rules": [...], "new_vocabulary": [...], "live_check": "..."}], "proposals_not_done": [{"id", "reason"}], "core_requests": ["..."], "files": ["every repository path you created or modified, relative to the repo root (modules, tests, fixtures, data fragments, backlog file)"], "notes": "..."}. The files list is used to commit your batch: keep it complete and exact.
Return the summary object when tests pass.${resumeNote(b)}`
}

function reviewPrompt(b) {
  return `You are an adversarial senior reviewer of V3LUM batch ${b} (repo ${REPO}). The implementer claims it is done; assume it is not.

READ: ${SP}/${b}.md (final conditions per proposal = the spec), ${SP}/_common.md (binding rules), ${MAN}/${b}.json (manifest), ${REPO}/docs/MODULE_GUIDE.md, ${REPO}/docs/contract_additions/*.md, ${SEED}/owners.json (shared provider ownership), then every file the manifest lists and its tests.

CHECK every proposal of the batch, condition by condition:
- each final condition is implemented (not stubbed) and covered by a test that would fail without it;
- metadata matches the council decision (default_enabled, terms, provider tier, opsec, shares_input, keys, hosts, quotas, TTLs);
- error handling: 401/403/404/429/5xx/timeouts/error-in-200/malformed data map to the right statuses (never "empty" when we could not verify);
- the team rules: no enumeration, metadata-only breach data actually scrubbed (check raw too), no people-search, nothing sent to publishing services, opsec level honest (a PASSIVE module never contacts the target), no secrets in raw/evidence/logs;
- pivots and attributes: correct entity types, normalised, capped, not noisy; findings severities sensible;
- provider fragments: no host of ${SEED}/owners.json re-declared (only <id>__<batch>.json extensions for those), every host and feed registered, terms/tier as the council decided, registry errors empty for the batch's fragments; the registry contract test and (if docs/contract_additions/WP09.md exists) the P327 lint pass for the batch's modules;
- fixtures contain no real personal data or keys; tests offline and deterministic; ruff clean;
- live: run the batch's live tests with V3LUM_LIVE=1 (keyless sources); if a parser breaks on the real response, fix it.

${RULES}

${OWNERSHIP}

Fix every problem directly in the batch's files, re-run its tests (offline + live) and the full offline suite, update the manifest (its "files" list must name exactly every repository path the batch created or modified: check with git status against the batch's naming), then return the summary object.`
}

const results = await pipeline(
  BATCHES,
  (b) => agent(implPrompt(b), { label: `impl:${b}`, phase: 'Implement', schema: IMPL_SCHEMA })
    .then(r => { if (r) log(`${b}: ${r.modules.length} modules, tests: ${r.test_result}, not done: ${r.proposals_not_done.length}`); return r }),
  (impl, b) => agent(reviewPrompt(b), { label: `review:${b}`, phase: 'Review', schema: REVIEW_SCHEMA })
    .then(v => { if (v) log(`${b}: review ${v.verdict} (${v.problems_found.length} problems, ${v.remaining.length} remaining)`); return { batch: b, impl, review: v } }),
)
return { results }
