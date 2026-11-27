export const meta = {
  name: 'v3lum-provider-seed',
  description: 'Seed the V3LUM provider registry with every provider that more than one module batch uses, before the batches run in parallel: plan ids and host ownership, write the fragments in parallel slices, then validate the whole registry and publish the owners map',
  phases: [
    { title: 'Plan', detail: 'one engineer assigns provider ids, hosts and sources for the shared domains' },
    { title: 'Write', detail: 'parallel writers create v3lum/data/providers/<id>.json for their slice' },
    { title: 'Validate', detail: 'registry errors == [], tests green, owners map for the batches' },
  ],
}

const S = args.scratch
const REPO = args.repo
const SEED = `${S}/impl/providers_seed`
const PY = `${REPO}/.venv/bin/python`
const SLICES = args.slices || 3

const PLAN_SCHEMA = {
  type: 'object',
  properties: {
    plan_file: { type: 'string' },
    providers: { type: 'integer' },
    hosts: { type: 'integer' },
    slices: { type: 'array', items: { type: 'array', items: { type: 'string' } }, description: `exactly ${SLICES} lists of provider ids, balanced by work` },
    notes: { type: 'array', items: { type: 'string' } },
  },
  required: ['plan_file', 'providers', 'hosts', 'slices', 'notes'],
}
const WRITE_SCHEMA = {
  type: 'object',
  properties: {
    slice: { type: 'integer' },
    files: { type: 'array', items: { type: 'string' } },
    errors_for_my_ids: { type: 'array', items: { type: 'string' } },
    notes: { type: 'array', items: { type: 'string' } },
  },
  required: ['slice', 'files', 'errors_for_my_ids', 'notes'],
}
const VALIDATE_SCHEMA = {
  type: 'object',
  properties: {
    registry_errors: { type: 'array', items: { type: 'string' } },
    suite: { type: 'string' },
    owners_file: { type: 'string' },
    fixes: { type: 'array', items: { type: 'string' } },
    notes: { type: 'array', items: { type: 'string' } },
  },
  required: ['registry_errors', 'suite', 'owners_file', 'fixes', 'notes'],
}

const CONTEXT = `CONTEXT: V3LUM (repo ${REPO}) is a command-line OSINT/CTI/recon multikit for a corporate CyberSecurity team in Brazil. Module contract v2 is frozen (docs/MODULE_GUIDE.md). Every host a module contacts must belong to exactly one provider fragment in ${REPO}/v3lum/data/providers/ (schema and rules: ${REPO}/v3lum/data/providers/README.md; loader and validation: ${REPO}/v3lum/core/providers.py; core seed fragments already there: abusech, github, shodan, iana, publicsuffix, the DoH resolvers, internal MISP/OpenCTI). About 80 module batches will soon run IN PARALLEL, each writing its own modules; a provider used by two batches would be created twice and collide (a host in two providers is a registry error and the registry fails closed). So the providers that more than one batch uses are seeded now, once; batches will only EXTEND them (<id>__<batch>.json: extra sources and error markers) and reference their sources as "<provider_id>.<source_id>".
INPUT: ${SEED}/dossier.md (per shared registrable domain: every host of that domain that any batch uses, the council-approved proposals using them with auth, keys, council terms class and tier, opsec, the relevant final conditions, and the research records with endpoints, rate limits and terms evidence), ${SEED}/shared.json and ${SEED}/hosts.json (host -> batches, proposals, modules, registrable domain, core owner).
BINDING COUNCIL RULES: the proposal's council terms class and provider_tier are binding (a fragment may only be stricter). A1 initial classes in the README are binding. Tier rationale/reviewer: "council-1 (A8)", tier_date and checked_at 2026-11-26. When the research record has no verbatim terms quote, quote the binding council condition text and set the reviewer to "council-1 (A1)" (README rule). flags.publishes_queries is true for services that publish submissions (public scan feeds); flags.sensitive for breach/infostealer/people data; flags.reuses_queries when the operator reuses lookups; flags.fetches_target when the service fetches the target on our behalf. Keys: one key per provider, key names unique across the registry, env aliases from the proposals' key_env_vars (the V3LUM_KEY_<NAME> form always works). Quotas: provider-wide, published figures with evidence_url or observed (published false), safety_margin <= 0.8. Never put a real key, cookie or personal data in a fragment.`

const planPrompt = `You are the provider-registry planner of V3LUM.

${CONTEXT}

TASK: write ${SEED}/plan.json = {"providers": [{"id", "name", "operator", "hosts": [...], "batches": [...], "proposals": [...], "keys": [{"name", "env": [...]}], "sources": [{"id", "title", "terms_class", "for_modules": [...]}], "tier", "notes"}]} covering EVERY host of every registrable domain in the dossier (each host in exactly one provider; none of them may be a host a core seed already owns - those stay with the core owner and batches extend that one).
- One provider = one operator's service with ONE key and ONE shared budget. Split a registrable domain into several providers when different services there have different keys, budgets or terms (for example separate Google APIs on googleapis.com; a third-party app hosted on firebaseio.com belongs to its real operator, e.g. the Hacker News API to Y Combinator; independent operators on a public-suffix platform are separate providers). Keep one provider when it is one service (abuse.ch-style families share one).
- ids: ^[a-z][a-z0-9_]{1,63}$, short and stable (e.g. circl, brasilapi, urlscan, otx), never an id that already exists in v3lum/data/providers/.
- sources: one per distinct dataset/API family the proposals use, ids ^[a-z0-9][a-z0-9_.-]* short (e.g. "hashlookup", "pdns", "cnpj"), with the council terms class of the proposals using it (the strictest when several).
- Balance the work into exactly ${SLICES} slices (lists of provider ids) for parallel writers.
Validate the plan with a python3 -I script of your own (in ${SEED}/work_plan/): every dossier host covered once, no core-owned host, ids unique and unused. Write only inside ${SEED}/. Return the summary object.`

function writePrompt(i) {
  return `You are writing provider registry fragments for V3LUM (slice ${i} of ${SLICES}).

${CONTEXT}

STAGING: the core team is integrating wave 1 in ${REPO} right now, so you do NOT write into the repository. Write each fragment to ${SEED}/staging/<id>.json (create the directory if needed); a validator copies the whole validated set into ${REPO}/v3lum/data/providers/ in one step afterwards.

TASK: read ${SEED}/plan.json (and its notes) and create ${SEED}/staging/<id>.json (schema v3lum.provider/1, ALL required fields, per ${REPO}/v3lum/data/providers/README.md and the parser in ${REPO}/v3lum/core/providers.py) for every provider id of your slice (listed at the end of this prompt). Use the plan's ids, hosts, keys and sources exactly (other writers and the batches rely on those ids); fill tier (with rationale), flags, personal_data_review (null unless the dossier records one), reliability (Admiralty grade with justification), http_profile (UA neutral unless a binding host profile or the provider's terms require otherwise; ttl per the README's data-class guidance; min_interval/timeout/max_bytes from the research and final conditions), quota (published figures with evidence_url, else observed with published false, else null), error_markers (only markers the dossier documents with a real sample; otherwise [] - the owning batches add them later with fixtures), keys, and sources with full terms evidence (evidence_url + verbatim quote from the research record, or the council text with reviewer "council-1 (A1)") and upstream_family.
Respect the binding host profiles in providers.PROFILE_REQUIREMENTS (rdap.registro.br, registro.br, haveibeenpwned.com, api.pwnedpasswords.com, query.wikidata.org/www.wikidata.org ...).
CHECK with a python3 -I script in ${SEED}/work_write${i}/: copy ${REPO}/v3lum/data/providers/*.json and ALL of ${SEED}/staging/*.json into a fresh temp directory and run (cd ${REPO} && ${PY} -c "import sys; from v3lum.core import providers; r = providers.load_dir(sys.argv[1]); print(r.errors)" <tempdir>). Fix every error that names one of your ids or files (errors naming other ids may be another writer's work in progress: ignore them). Create ONLY your slice's staging files; never touch the repository; never run git commands. Return the summary object.`
}

const validatePrompt = `You are the validator of the V3LUM provider seed.

${CONTEXT}

The planner wrote ${SEED}/plan.json and ${SLICES} writers created the fragments in ${SEED}/staging/ (all writers are finished). The core team may still be integrating wave 1 in ${REPO}: never edit anything there except adding the seeded fragments.
DO
1. Assemble a check directory: copies of ${REPO}/v3lum/data/providers/*.json plus every ${SEED}/staging/*.json; providers.load_dir(<dir>).errors must be [] - fix every error in the staging fragments (never edit core seed fragments).
2. Check each staged fragment against the plan (ids, hosts, keys and sources exactly as planned; every planned provider present), the README rules, the binding council terms/tier of the proposals in ${SEED}/dossier.md (never looser), and that no real key, cookie or personal data is present.
3. Copy the staged fragments into ${REPO}/v3lum/data/providers/ with one python3 -I script (refuse to overwrite an existing file; report it instead). Then: cd ${REPO} && ${PY} -c "from v3lum.core import providers; print(providers.registry().errors)" must print []; run ${PY} -m pytest -q -p no:cacheprovider tests/test_providers_registry.py tests/test_registry_contract.py and the full offline suite (${PY} -m pytest -q -p no:cacheprovider; note that -q is already in addopts, so check the exit code). A failure caused by the seeded fragments is yours to fix (in the fragments); a failure elsewhere may be the wave-1 integrator's work in progress: re-run once and report it in notes.
4. Write ${SEED}/owners.json = {"hosts": {host: provider_id} for every host in ${SEED}/hosts.json and every host of the seeded or core fragments, "providers": {provider_id: {"file", "hosts": [...], "keys": [...], "sources": {source_id: {"title", "terms_class"}}, "tier", "seeded": true|false}}} - batches read it to know which providers to EXTEND instead of creating, and which "<provider>.<source>" ids exist. Include the core seed providers too (seeded false).
Never run git commands that change state. Return the summary object.`

phase('Plan')
const plan = await agent(planPrompt, { label: 'plan', phase: 'Plan', schema: PLAN_SCHEMA })
if (!plan) return { error: 'planner failed' }
log(`plan: ${plan.providers} providers, ${plan.hosts} hosts, slices ${plan.slices.map(s => s.length).join('/')}`)
if (args.plan_only) return { plan }
const sliceIds = plan.slices.slice(0, SLICES)
phase('Write')
const writes = await parallel(sliceIds.map((ids, k) => () =>
  agent(writePrompt(k + 1) + `\n\nYOUR SLICE ${k + 1} PROVIDER IDS: ${ids.join(', ')}`, { label: `write:${k + 1}`, phase: 'Write', schema: WRITE_SCHEMA })
    .then(r => { if (r) log(`slice ${k + 1}: ${r.files.length} files, own errors ${r.errors_for_my_ids.length}`); return r })))
phase('Validate')
const val = await agent(validatePrompt, { label: 'validate', phase: 'Validate', schema: VALIDATE_SCHEMA })
if (val) log(`validate: registry errors ${val.registry_errors.length}; ${val.suite}`)
return { plan, writes, validate: val }
