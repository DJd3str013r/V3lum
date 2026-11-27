export const meta = {
  name: 'v3lum-core-integrate',
  description: 'Integrate one finished wave of V3LUM core work packages: run the whole suite, fix cross-package glue and defects, then an independent auditor verifies the integrated wave (and, for wave 1, the frozen MODULE_GUIDE v2 against the code)',
  phases: [
    { title: 'Integrate', detail: 'wave integrator: whole suite green, cross-package fixes, contract docs' },
    { title: 'Audit', detail: 'independent auditor: acceptance criteria across the wave, guide vs code, fixes' },
  ],
}

const S = args.scratch
const REPO = args.repo
const SP = `${S}/impl/specs`
const PLAN = `${S}/impl/core/plan.json`
const WAVE = args.wave
const PKGS = args.packages
const REPORTS = args.reports_file
const NEXT = args.next_wave || null
const NEXT_NOTE = NEXT
  ? `NEXT WAVE IN FLIGHT (waves overlap to save time): core packages ${NEXT.packages.join(', ')} are being implemented and reviewed in the same tree right now, on top of this wave (their owns lists are in the plan). Do not edit files only they own. Files owned both by a package of this wave and by one of them (${NEXT.shared_files.join(', ') || 'none'}) are shared with that later package, which is editing them now: you may make small targeted glue fixes there (re-read the file right before each change, never rewrite the whole file, keep their in-progress additions intact); anything larger goes to open_defects, starting with that later package's id (it is carried to that package's reviewer). Failures in their test files are their work in progress: do not count them against this wave and do not fix them; if one of their in-progress changes breaks this wave's own tests, report it in open_defects with their package id.`
  : ''
const PY = `${REPO}/.venv/bin/python`

const SCHEMA = {
  type: 'object',
  properties: {
    wave: { type: 'integer' },
    suite: { type: 'string', description: 'final full pytest summary line' },
    ruff: { type: 'string' },
    fixes: { type: 'array', items: { type: 'string' } },
    open_defects: { type: 'array', items: { type: 'string' }, description: 'anything still wrong or missing, with the package id' },
    contract_notes: { type: 'string', description: 'what later waves and module authors must know (names added, behaviours)' },
  },
  required: ['wave', 'suite', 'ruff', 'fixes', 'open_defects', 'contract_notes'],
}

const MODULE_NOTE = `MODULE BATCHES IN FLIGHT (from wave 2 on): other engineers are adding Council-approved source modules at the same time: new files under v3lum/modules/ (other than the four reference modules dns_records, email_basics, shodan_internetdb, ioc_extract), tests/modules/, tests/fixtures/<module>/, tests/live/, tests/fixtures/acceptance/, docs/backlog/<batch>.md and data fragments in v3lum/data/ (providers/<id>.json and <id>__<batch>.json, vocab/, pivot_links/, notices/, platforms/, noise/ ...). Never edit those files. A failure inside them, or a tests/test_registry_contract.py failure naming one of their modules, is their work in progress, not yours: re-run once and move on. But if YOUR change breaks a module written against the frozen contract (docs/MODULE_GUIDE.md), restore compatibility in your own files: the contract only grows.`

const RULES = `TEAM RULES (non-negotiable): open/public sources only; no CAPTCHA/anti-bot bypass, no login to third-party accounts, no borrowed sessions; no account enumeration via reset/sign-up endpoints, no SMTP probing; breach data = metadata only (never passwords, hashes, masked hints, leaked file contents); no people-search in leaked databases, CPF validated offline only; 403/429/timeouts = could not verify, errors inside 200 bodies detected; respect provider limits; never send values to services that publish submissions; active probing only with explicit authorization; reports self-contained; no biometrics or sensitive inference.`

const freezeNote = WAVE === 1
  ? `This is wave 1: it delivers module contract v2. docs/MODULE_GUIDE.md must describe EXACTLY what the code provides (names, signatures, ClassVars and allowed values, statuses and reason codes, ctx helpers, provider fragments, registration of keys/settings/datasets/pivot packs/rules/noise lists/vocabulary, test helpers in tests/fakes.py, the registry contract test and merge gates), with the four migrated reference modules as worked examples; ~80 module batches will be written against it by engineers who read only the guide, the reference modules and their own spec. When the integrated tree is green and the guide matches the code, mark the guide FROZEN (contract v2) at the top.`
  : `Contract v2 (docs/MODULE_GUIDE.md) is frozen: later waves only ADD names (documented in docs/contract_additions/<WP>.md). Verify nothing in this wave renamed or changed the behaviour of a contract name; if something did, restore compatibility (keep the old name/behaviour, add the new one).`

const integratePrompt = `You are the integrator of wave ${WAVE} of the V3LUM core rewrite (repo ${REPO}; Python command-line OSINT/CTI/recon multikit). The wave's packages ${PKGS.join(', ')} were implemented in parallel by different engineers in the shared tree and each was reviewed on its own. Your job: make the wave work as one.

READ: ${PLAN} (wave ${WAVE}: goal, intra-wave protocol, every package's spec/public_api/owns/acceptance; module_author_contract), ${REPORTS} (implementer and reviewer reports per package: files changed, open issues, remaining problems), ${SP}/_common.md and ${SP}/core_G15.md where a package's spec cites them, and the code (git status / git diff in ${REPO}; do not change git state).

DO
1. Run the whole suite: cd ${REPO} && ${PY} -m pytest -q -p no:cacheprovider ; and ${REPO}/.venv/bin/ruff check v3lum tests . Fix every failure and every cross-package mismatch (a package calling a sibling name that does not exist or behaves differently than the plan says, import cycles, duplicated helpers, inconsistent constants). All packages of this wave are finished, so you may edit any file the wave's packages own (except files of the next wave in flight, see below); do not touch files outside the wave unless the fix is impossible otherwise (then keep it minimal and list it).
2. Resolve every open issue / remaining problem from the reports that falls inside this wave's scope (implement what is missing; a request for a file owned by a later wave goes to open_defects with the target package id).
3. Check the acceptance criteria of every package of the wave against the integrated tree; implement what is missing.
4. ${freezeNote}
5. Keep the existing behaviour of the CLI working (v3lum --help, scan on a domain with --offline against FakeHttp-backed tests).
${WAVE >= 2 ? '6. ' + MODULE_NOTE + ' Do not count their in-progress failures against the wave; list any that persist and look caused by this wave in open_defects.' : ''}
${NEXT ? '7. ' + NEXT_NOTE : ''}

${RULES}

Never run git commands that change state. Return the summary object when the whole suite and ruff are green.`

const auditPrompt = `You are an independent auditor of wave ${WAVE} of the V3LUM core rewrite (repo ${REPO}). The integrator claims the wave is complete and green. Assume it is not.

READ: ${PLAN} (wave ${WAVE} packages ${PKGS.join(', ')}: spec, public_api, acceptance; module_author_contract), ${SP}/core_G15.md (final conditions of the covered proposals), ${SP}/_common.md (binding rules the packages list), then the code.

CHECK
- every acceptance criterion and every covered final condition is implemented for real and covered by a test that would fail without it (spot-check by reading code, not just test names);
- public names match the plan's public_api exactly (module authors and later waves depend on them);
- safety properties the wave claims (redaction, fail-closed defaults, no TLS bypass, no secrets in cache/logs/events, deterministic ids, permissions, policy refusals) hold on the code paths, including error paths;
- ${WAVE === 1 ? 'docs/MODULE_GUIDE.md v2 matches the code (every documented name exists with the documented signature and semantics; every module-facing name in the code is documented; the reference modules follow the guide); write a tiny throwaway module in a temp dir (outside the repo) following only the guide and run it through tests/fakes.py make_ctx to prove the guide is sufficient;' : 'no contract v2 name was renamed or changed in behaviour; additions are documented in docs/contract_additions/;'}
- the whole suite and ruff are green: cd ${REPO} && ${PY} -m pytest -q -p no:cacheprovider ; ${REPO}/.venv/bin/ruff check v3lum tests .
${WAVE >= 2 ? '- ' + MODULE_NOTE : ''}
${NEXT ? '- ' + NEXT_NOTE : ''}

${RULES}

Fix every problem directly (any file of this wave; keep changes minimal elsewhere), re-run the suite, and return the summary object. Never run git commands that change state.`

phase('Integrate')
const integ = await agent(integratePrompt, { label: `integrate:w${WAVE}`, phase: 'Integrate', schema: SCHEMA })
if (integ) log(`integrate w${WAVE}: ${integ.suite}; fixes ${integ.fixes.length}; open ${integ.open_defects.length}`)
phase('Audit')
const audit = await agent(auditPrompt, { label: `audit:w${WAVE}`, phase: 'Audit', schema: SCHEMA })
if (audit) log(`audit w${WAVE}: ${audit.suite}; fixes ${audit.fixes.length}; open ${audit.open_defects.length}`)
return { integ, audit }
