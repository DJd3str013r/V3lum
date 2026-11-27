export const meta = {
  name: 'v3lum-core-plan',
  description: 'Plan the Council #1 core changes (G15 proposals + architecture actions + binding agenda rules) into dependency-ordered work packages with disjoint file ownership, then critique and fix the plan',
  phases: [
    { title: 'Plan', detail: 'lead engineer writes impl/core/plan.json' },
    { title: 'Critique', detail: 'independent reviewer checks coverage, ownership, ordering and fixes the plan' },
  ],
}

const S = args.scratch
const REPO = args.repo
const SP = `${S}/impl/specs`
const PLAN = `${S}/impl/core/plan.json`

const PLAN_SCHEMA = {
  type: 'object',
  properties: {
    plan_file: { type: 'string' },
    waves: { type: 'integer' },
    packages: { type: 'integer' },
    uncovered: { type: 'array', items: { type: 'string' }, description: 'approved G15 ids / AR ids / agenda rules NOT covered, with reason' },
    notes: { type: 'string' },
  },
  required: ['plan_file', 'waves', 'packages', 'uncovered', 'notes'],
}

const PLAN_FORMAT = `PLAN FILE ${PLAN} (JSON):
{"waves": [
  {"wave": 1, "goal": "...", "packages": [
     {"id": "WP01", "title": "...", "proposals": ["P3xx", ...], "architecture_actions": ["AR01", ...], "agenda_rules": ["A1", "A3", ...],
      "owns": ["v3lum/core/module.py", "tests/test_module_api.py", ...],   // files this package may create/modify (exclusive within its wave)
      "reads": ["v3lum/core/engine.py", ...],                              // files it relies on but must not modify
      "depends_on": ["WP00"],                                              // packages of earlier waves
      "spec": "precise description of what to build: classes, functions, attribute names, config keys + defaults, CLI flags, statuses, behaviours, error handling",
      "public_api": "the exact names other packages and module authors will use (import paths, signatures)",
      "tests": "which tests to write (offline, deterministic) and what they assert",
      "acceptance": ["checkable criterion", ...],
      "effort": "S|M|L"}
  ]}
 ],
 "module_author_contract": "what module authors (who start after the core is done) can rely on: the Module ClassVars and their allowed values, ctx helpers, statuses, result helpers, registration of keys/datasets/pivot packs/correlation rules, test helpers",
 "deferred": [{"item": "P3xx / ARxx", "reason": "..."}]}
Validate with: python3 -I -c "import json; d=json.load(open('${PLAN}')); print(sum(len(w['packages']) for w in d['waves']), 'packages')"`

const CONSTRAINTS = `CONSTRAINTS FOR THE PLAN
- Work runs as parallel AI engineers in ONE shared working tree (${REPO}); packages of the same wave run at the same time, so their "owns" lists must be disjoint (no file owned by two packages of one wave). A later wave may modify a file an earlier wave owned. Tests files count as owned files too.
- Wave 1 must deliver the module-author contract first (module API metadata, statuses, ctx helpers, result helpers, key registration, body-error helpers, test helpers) because ~300 source modules will be written right after the core, in parallel, by authors who may only ADD files (modules, tests, fixtures, data/pivot_links/<pack>.json, correlation rule files) and cannot edit shared core files. So anything that would otherwise need a central edit (API key names/aliases/env vars, the provider registry of AR11 - make it a directory of fragments such as v3lum/data/providers/<provider>.json merged at load time, never one big shared file -, HTTP profiles, quota blocks, error markers, vocabulary, datasets, pivot packs, correlation rules, declarative collector specs, noise/warning lists, conftest env-var scrubbing) must become decentralised registration in wave 1.
- The module batches START RIGHT AFTER WAVE 1 and run in parallel with waves 2+. Therefore: (a) wave 1 delivers every module-facing name and signature (Module ClassVars and allowed values, statuses, confidence labels, result/finding helpers, ctx.http/dns/data/keys/quota helpers, body-error classification helpers, sanitizer hooks, provider-fragment schema, test helpers in tests/fakes.py, the registry contract test) even where the enforcement behind them is completed by a later wave (a thin but working implementation is fine); (b) wave 1 ends with docs/MODULE_GUIDE.md rewritten for contract v2 and FROZEN; (c) later waves must not rename or change the behaviour of anything in the module-author contract (they may only add); state this in every later package's spec.
- Existing reference modules (dns_records, email_basics, shodan_internetdb, ioc_extract) are migrated to contract v2 in wave 1 by the package that owns the contract (they serve as the examples in MODULE_GUIDE.md); deeper upgrades of those modules belong to the module batches.
- Keep the number of waves small (3-5) and packages per wave <= 6; each package should be a coherent chunk one engineer can finish in one sitting (effort S/M/L), including tests.
- Prefer extending existing modules of the core over rewriting them; the existing test suite (tests/) must stay green after every wave.
- Python 3.10+, dependencies: rich + requests (optional extras: phonenumbers, dnspython, Pillow, pypdf, PySocks). A new third-party dependency needs a justification in the package spec and must be optional (module reports UNAVAILABLE without it).
- Everything approved in ${SP}/core_G15.md (the G15 proposals with their final conditions) and the P1/P2 architecture actions + binding agenda rules in ${SP}/_common.md must be covered by some package, or listed in "deferred" with a reason (P3 actions may be deferred; say so).
- Each package spec must be precise enough that an engineer who reads only the spec, the referenced final conditions/binding rules and the code can implement it without guessing names.`

const planPrompt = `You are the lead engineer of V3LUM, a Python command-line OSINT/CTI/recon multikit (repo ${REPO}). Council #1 just approved the core changes. Turn them into an implementation plan.

READ FIRST
- ${SP}/_common.md: binding agenda decisions A1-A16 (licence profile, TLP, default-enabled criteria, breach scrubbing, username packs, GPL data, active-module rules of engagement, provider tiers, BR-egress/anti-bot sources, retention, org profile, internal platforms, egress profiles, watch mode, keys wizard/budget, build scope) and the consolidated architecture actions AR01...
- ${SP}/core_G15.md: every approved core proposal with its final conditions (the binding spec).
- The current code: ${REPO}/v3lum/core/*.py, v3lum/app.py, v3lum/cli.py, v3lum/shell.py, v3lum/config.py, v3lum/ui/*, v3lum/report/*, v3lum/correlations/*, tests/*, docs/ARCHITECTURE.md, docs/MODULE_GUIDE.md.

${CONSTRAINTS}

${PLAN_FORMAT}

Write the plan file, validate it, and return the summary object.`

const critiquePrompt = `You are a principal engineer reviewing the V3LUM core implementation plan at ${PLAN}. Assume it has gaps and find them.
Inputs: ${SP}/_common.md (binding agenda rules + architecture actions), ${SP}/core_G15.md (approved core proposals with final conditions), the code in ${REPO}.

${CONSTRAINTS}

CHECK
1. Coverage: every approved G15 proposal id, every P1/P2 architecture action and every binding agenda rule that needs code is covered by a package (or explicitly deferred with a valid reason). List what is missing and add it to the right package.
2. Ownership: no file owned by two packages of the same wave; every file a package must modify is in its "owns"; shared hot spots (v3lum/core/module.py, models.py, context.py, http.py, engine.py, app.py, cli.py, config.py, tests/conftest.py, tests/fakes.py) are sequenced across waves sensibly.
3. Ordering: the module-author contract is complete after wave 1 (authors can add modules with only new files); depends_on is consistent; no package needs something only a later wave delivers.
4. Precision: names, signatures, config keys/defaults, statuses and CLI flags are explicit and consistent across packages and with the final conditions; tests and acceptance criteria are concrete.
5. Scope sanity: packages are not too big for one engineer; nothing contradicts the team rules (open sources only, no account enumeration, metadata-only breach data, no people-search, CPF offline only, no CAPTCHA/anti-bot bypass, active probing only with authorization, 403/429/timeouts = could not verify, never send values to services that publish submissions).
Fix the plan file directly (keep it valid JSON in the same format), then return the summary object (uncovered = anything still not covered after your fixes).

${PLAN_FORMAT}`

phase('Plan')
const plan = await agent(planPrompt, { label: 'core-plan', phase: 'Plan', schema: PLAN_SCHEMA })
log(`plan: ${plan ? plan.packages : '?'} packages in ${plan ? plan.waves : '?'} waves`)
phase('Critique')
const crit = await agent(critiquePrompt, { label: 'core-plan-critique', phase: 'Critique', schema: PLAN_SCHEMA })
return { plan, crit }
