export const meta = {
  name: 'v3lum-core-wave',
  description: 'Implement one wave of V3LUM core work packages (from impl/core/plan.json): implement with tests, then an adversarial reviewer verifies against the spec and fixes',
  phases: [
    { title: 'Implement', detail: 'one engineer per work package' },
    { title: 'Review', detail: 'adversarial reviewer per package: spec compliance, team rules, tests, fixes' },
  ],
}

const S = args.scratch
const REPO = args.repo
const SP = `${S}/impl/specs`
const PLAN = `${S}/impl/core/plan.json`
const WAVE = args.wave
const PKGS = args.packages
const OVERLAP = args.overlap || ''
const NOTES = args.notes || {}
function scopeNote(id) { return NOTES[id] ? `\nSCOPE OF THIS RUN (overrides the plan where they differ): ${NOTES[id]}\n` : '' }
const PY = `${REPO}/.venv/bin/python`

const IMPL_SCHEMA = {
  type: 'object',
  properties: {
    package: { type: 'string' },
    done: { type: 'boolean' },
    files_changed: { type: 'array', items: { type: 'string' } },
    tests_added: { type: 'array', items: { type: 'string' } },
    public_api: { type: 'string', description: 'names other packages / module authors use' },
    test_result: { type: 'string', description: 'last full pytest summary line' },
    open_issues: { type: 'array', items: { type: 'string' } },
  },
  required: ['package', 'done', 'files_changed', 'tests_added', 'public_api', 'test_result', 'open_issues'],
}
const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    package: { type: 'string' },
    verdict: { type: 'string', enum: ['pass', 'fixed', 'needs_followup'] },
    problems_found: { type: 'array', items: { type: 'string' } },
    fixes_applied: { type: 'array', items: { type: 'string' } },
    remaining: { type: 'array', items: { type: 'string' } },
    test_result: { type: 'string' },
  },
  required: ['package', 'verdict', 'problems_found', 'fixes_applied', 'remaining', 'test_result'],
}

const RULES = `TEAM RULES (non-negotiable, enforce in code where relevant): open/public sources only; no CAPTCHA/anti-bot bypass, no login to third-party accounts, no borrowed cookies/sessions; no account enumeration through password-reset/sign-up endpoints and no SMTP probing; breach data = metadata only (never passwords, hashes, masked password hints or leaked file contents); no people-search in leaked databases (CPF/name/phone, LGPD), CPF validated offline only; 403/429/timeouts = "could not verify" (never "absent") and errors inside HTTP-200 bodies must be detected; respect provider limits/quotas; never send values to services that publish submissions; active probing only with explicit authorization; reports are self-contained; no biometrics or sensitive-data inference.`

const MODULE_NOTE = `MODULE BATCHES IN FLIGHT (from wave 2 on): other engineers are adding Council-approved source modules at the same time: new files under v3lum/modules/ (other than the four reference modules dns_records, email_basics, shodan_internetdb, ioc_extract), tests/modules/, tests/fixtures/<module>/, tests/live/, tests/fixtures/acceptance/, docs/backlog/<batch>.md and data fragments in v3lum/data/ (providers/<id>.json and <id>__<batch>.json, vocab/, pivot_links/, notices/, platforms/, noise/ ...). Never edit those files. A failure inside them, or a tests/test_registry_contract.py failure naming one of their modules, is their work in progress, not yours: re-run once and move on. But if YOUR change breaks a module written against the frozen contract (docs/MODULE_GUIDE.md), restore compatibility in your own files: the contract only grows.`

const SHARED = `SHARED WORKING TREE: other engineers are editing OTHER files of ${REPO} at the same time (their files are owned by their packages in ${PLAN}).
- Modify/create ONLY the files your package owns (its "owns" list). If you truly need a change in a file you do not own, do not make it: put it in open_issues with the exact change needed.
- Never run git commands that change state (no commit, stash, checkout, reset, clean); never run "ruff format" or auto-fixers on files you do not own (use: ${REPO}/.venv/bin/ruff check <your files>).
- Run tests with: cd ${REPO} && ${PY} -m pytest -q -x -p no:cacheprovider <your test files>, and at the end the full suite: cd ${REPO} && ${PY} -m pytest -q -p no:cacheprovider. A failure in a test file owned by another package of this wave may be transient (they are mid-edit): re-run once after a minute; report it if it persists, do not fix their files.
- Tests are offline and deterministic (use tests/fakes.py FakeHttp/make_ctx patterns; no real network; no sleeping > 0.2 s).
${WAVE >= 2 ? '- ' + MODULE_NOTE : ''}
${OVERLAP ? '- CONCURRENT CORE WORK (waves overlap to save time): ' + OVERLAP + ' Never edit files owned only by those packages. Failures in their test files are their work in progress: re-run once, report if persistent, do not fix them. A file your package shares with an EARLIER package (several owners in the plan) is yours now, but the earlier wave\'s integrator may make a small glue fix in it at the same time: re-read the file right before each change and use small targeted edits, never a whole-file rewrite.' : ''}`

const CORE = `${S}/impl/core`
function carryNote(id) {
  if (WAVE === 1) return ''
  return `- CARRY-FORWARD: ${CORE}/carry/${id}.md (if it exists) lists items earlier waves' implementers, reviewers, integrators and auditors left for ${id}: resolve every one inside your package's scope, or say in your report why it is wrong or already done. ${CORE}/contract_notes.md says what the finished waves added or changed (read it: it is the integrated truth where it differs from the plan).
- CONTRACT FREEZE: docs/MODULE_GUIDE.md is FROZEN (module contract v2). Do not edit it and do not rename or change the behaviour of any name it documents; only ADD names, and document every module-facing addition of ${id} in docs/contract_additions/${id}.md (what, signature, semantics, which module authors need it); ${id} owns that file even when its owns list does not name it.`
}

function implPrompt(id) {
  return `You are a senior Python engineer on V3LUM, a command-line OSINT/CTI/recon multikit (repo ${REPO}). Implement core work package ${id} of wave ${WAVE}.

READ FIRST
- ${PLAN}: find package ${id} (spec, public_api, owns, reads, tests, acceptance, proposals, architecture_actions, agenda_rules) and skim the other packages so names line up; module_author_contract describes what module authors will rely on.
- ${SP}/core_G15.md: the final conditions of the proposals your package covers (binding spec), ${SP}/_common.md: binding agenda rules and architecture actions (implement the ones your package lists).
- The existing code you touch and the code you rely on; docs/ARCHITECTURE.md and docs/MODULE_GUIDE.md.
${carryNote(id)}
${scopeNote(id)}
${RULES}

${SHARED}

DELIVER: working code + offline tests for every acceptance criterion; keep backward compatibility for the existing modules and tests unless the spec says otherwise (then update those call sites only if you own them, else open_issues); docstrings for public API. When everything passes, return the summary object.`
}

function reviewPrompt(id) {
  return `You are an adversarial senior reviewer for V3LUM core work package ${id} (wave ${WAVE}) in ${REPO}. The implementer claims it is done. Assume it is not: find what is missing, wrong or unsafe, and fix it.

READ: ${PLAN} (package ${id}: spec, public_api, owns, tests, acceptance), ${SP}/core_G15.md (final conditions of its proposals), ${SP}/_common.md (binding rules it lists), then the code in its "owns" files (use git diff / git status in ${REPO} to see what changed; do not change git state).
${carryNote(id)}
${scopeNote(id)}
CHECK, item by item: every acceptance criterion and every final condition of the covered proposals is implemented and tested (not just stubbed); names match the plan's public_api; edge cases (empty/invalid input, network errors, 403/429/5xx, errors inside 200 bodies, timeouts, cancellation, thread safety where the engine runs modules concurrently); security (no secrets in logs/cache/reports, no TLS-verification bypass, no shell injection, no path traversal when writing files, untrusted data never executed); the team rules; tests actually assert behaviour (not tautologies) and are offline/deterministic; ruff clean on the owned files.

${RULES}

${SHARED}

Fix every problem you find directly in the package's owned files (same ownership rule as the implementer), re-run its tests and the full suite, then return the summary object.`
}

const results = await pipeline(
  PKGS,
  (id) => agent(implPrompt(id), { label: `impl:${id}`, phase: 'Implement', schema: IMPL_SCHEMA })
    .then(r => { if (r) log(`${id}: done=${r.done} tests=${r.test_result} open=${r.open_issues.length}`); return r }),
  (impl, id) => agent(reviewPrompt(id), { label: `review:${id}`, phase: 'Review', schema: REVIEW_SCHEMA })
    .then(v => { if (v) log(`${id}: review ${v.verdict}, problems=${v.problems_found.length}, remaining=${v.remaining.length}`); return { id, impl, review: v } }),
)
return { wave: WAVE, results }
