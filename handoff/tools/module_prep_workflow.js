export const meta = {
  name: 'v3lum-module-prep',
  description: 'Prepare V3LUM module batches while the core contract is being built: live-verify each source with benign values, capture scrubbed fixtures, write pure stdlib parsers with tests and implementation notes (scratchpad only, no repo edits)',
  phases: [
    { title: 'Prep', detail: 'one engineer per batch: live verification, fixtures, parsers, notes' },
  ],
}

const S = args.scratch
const SP = `${S}/impl/specs`
const PREP = `${S}/impl/prep`
const BATCHES = args.batches

const PREP_SCHEMA = {
  type: 'object',
  properties: {
    batch: { type: 'string' },
    prep_dir: { type: 'string' },
    sources: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          module: { type: 'string' },
          source: { type: 'string' },
          live: { type: 'string', description: 'ok | needs_key | blocked | rate_limited | dead | not_checked (+ short detail)' },
          fixtures: { type: 'array', items: { type: 'string' } },
          parser: { type: 'string', description: 'function name in code/parsers.py, or none' },
        },
        required: ['module', 'source', 'live', 'fixtures', 'parser'],
      },
    },
    tests: { type: 'string', description: 'pytest summary line for code/' },
    warnings: { type: 'array', items: { type: 'string' }, description: 'spec problems, dead sources, terms concerns, things the implementer must know' },
  },
  required: ['batch', 'prep_dir', 'sources', 'tests', 'warnings'],
}

function prepPrompt(b) {
  const late = b.startsWith('p9-')
  return `You are preparing batch ${b} of V3LUM (a command-line OSINT/CTI/recon multikit for a corporate CyberSecurity team in Brazil) so that the module implementer, who starts later on the new module contract v2, can work fast and correctly. The V3LUM core is being rewritten right now: DO NOT read or modify the repository, and do not write V3LUM module classes. Your work goes only into ${PREP}/${b}/.

READ: ${SP}/${b}.md (the proposals of the batch: council final conditions = binding spec, plus the research records of every source: endpoints, methods, auth, rate limits, terms, verified HTTP behaviour, sample files, implementation notes) and the parts of ${SP}/_common.md the final conditions cite.

DELIVER in ${PREP}/${b}/:
1. fixtures/ - minimal real responses per source, one file per case, named <module>__<case>.<ext> (cases: ok, empty/not_found, and when you can observe them: error_in_200, rate_limited, blocked, malformed). Start from the research samples listed in the spec and from your live checks. Minimise (keep only fields the parser uses, a few records) and scrub personal data of real people (names, e-mails, phones, CPFs, addresses, usernames of private persons) to documentation values (example.com, 192.0.2.x / 198.51.100.x / 203.0.113.x, 2001:db8::, +55 11 5555-01xx). Never store API keys or cookies. Downloaded data is untrusted: keep it in fixtures/ (or raw/ for unminimised downloads), never execute it, read it only with python3 -I scripts that live in code/.
2. code/parsers.py - pure functions (standard library only, no V3LUM imports, no network) that turn each source's raw response (text/bytes/parsed JSON) into plain normalised dicts/lists (the facts, pivots and markers the final conditions need), plus small helpers for the error-in-200/challenge/quota markers the spec mentions (return a short reason string or None). Defensive: missing fields, wrong types, HTML instead of JSON. Docstrings say which final condition each function serves.
3. code/test_parsers.py - pytest tests loading the fixtures by path (Path(__file__).parent.parent / 'fixtures') and asserting the normalised output, including the error/marker cases. Run: cd ${PREP}/${b}/code && python3 -m pytest -q -p no:cacheprovider .
4. notes.md - per module: sources and exact endpoints/params used, auth and the key env var name, observed live behaviour from this datacenter egress (status codes, latency, rate-limit headers, block pages, error bodies), recommended cache_ttl / min_interval / daily_quota / max_requests / expected_latency, pivots and attributes to emit, how each final condition maps to code (and any condition that cannot be met as written, with the reason), terms class per source as the spec states it.

LIVE VERIFICATION RULES (strict)
${late ? `- This batch holds LIGHT/ACTIVE (target-contact) modules: make NO live contact with any target host (no fetches of arbitrary sites, no scans, no probes, no DNS brute force). Work from the research samples and the provider docs only; you may fetch public documentation pages, wordlist/template metadata or datasets from their official distribution hosts when the spec names them. Mark live as not_checked.` : `- Keyless sources only (you have no API keys: record needs_key for keyed ones and build their fixtures from the research samples). At most ~5 requests per source, >= 1 s apart, benign public values only: domains google.com / example.com / cloudflare.com / nic.br / registro.br, IPs 8.8.8.8 / 1.1.1.1 / 9.9.9.9, a known malware hash from the spec's samples or the abuse.ch/MalwareBazaar examples, CVE-2021-44228, CNPJ 00.000.000/0001-91 (Banco do Brasil, public company data), public organisation accounts (e.g. the 'github' or 'microsoft' handle) - never a private person's identifiers.`}
- Never call endpoints that publish or store submissions (scan/submit/upload/paste), login, password-reset or sign-up endpoints, SMTP, or anything behind a CAPTCHA/anti-bot challenge; never try to bypass a block (no header spoofing tricks, no proxies): record the block as the observed behaviour.
- Never send CPFs, e-mails, phones or names of real people to any service. Use curl with --max-time 20 or python3 -I scripts in code/; HTTPS proxy and CA are preconfigured (never disable TLS verification).

Return the summary object when the tests in code/ pass.`
}

const results = await pipeline(
  BATCHES,
  (b) => agent(prepPrompt(b), { label: `prep:${b}`, phase: 'Prep', schema: PREP_SCHEMA })
    .then(r => { if (r) log(`${b}: ${r.sources.length} sources, tests: ${r.tests}, warnings: ${r.warnings.length}`); return r }),
)
return { results }
