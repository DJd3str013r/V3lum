# V3LUM — lift the veil

```
██╗   ██╗██████╗ ██╗     ██╗   ██╗███╗   ███╗
██║   ██║╚════██╗██║     ██║   ██║████╗ ████║
██║   ██║ █████╔╝██║     ██║   ██║██╔████╔██║
╚██╗ ██╔╝ ╚═══██╗██║     ██║   ██║██║╚██╔╝██║
 ╚████╔╝ ██████╔╝███████╗╚██████╔╝██║ ╚═╝ ██║
  ╚═══╝  ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝
```

**OSINT · Cyber Threat Intelligence · recon multikit for the command line.**

Type *anything* — an email, a domain, an IP, a URL, a hash, a phone number, a `@handle`, a CNPJ,
a crypto wallet, a CVE, an ATT&CK id, a file, or a whole paragraph full of IOCs. V3LUM recognizes
what it is, runs every relevant source, pivots on what it discovers, **cross-references** the
results, scores the risk, writes a report with evidence, and then asks you whether the answer
made sense — your feedback tunes how much each source is trusted next time.

> Built for an internal CSIRT/CTI team. Passive by default. Findings are leads, not verdicts.

---

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[full]"          # core + optional extras (phone parsing, EXIF, PDF, SOCKS/Tor, system DNS)
v3lum doctor                       # checks Python, packages, network, keys
```

Requires Python 3.10+. Without installing: `python v3lum.py <command>` from the checkout.

## Use

```bash
v3lum                                   # interactive console: type anything to investigate it
v3lum scan suspicious-domain.com        # one-shot investigation + report
v3lum scan john.doe@acme.com -d 2       # deeper pivoting
v3lum scan 185.220.101.4 CVE-2024-3400 44d88612fea8a8f36de82e1278abb02f
v3lum scan "@johndoe" -M username_check # only one module
v3lum scan -i iocs.txt -f html,stix     # batch from a file, STIX 2.1 export for MISP/OpenCTI
v3lum extract incident.txt --defang     # pull IOCs out of a text (defanged forms understood)
v3lum detect 52998224725                # how an input is recognized (CPF vs phone?)
v3lum links example.com                 # manual pivots: web tools pre-filled with the value
v3lum modules -c email                  # the arsenal, per category, with readiness
v3lum keys set shodan                   # API keys (hidden prompt, stored 0600)
v3lum cases list / cases show last      # past investigations, re-render reports
v3lum --tor scan target.example         # route everything through Tor
```

### Modes (OPSEC)

| mode | touches the target? | use |
|---|---|---|
| `passive` (default) | never — third-party sources only | investigations, CTI enrichment |
| `light` | like a normal visitor (homepage, robots.txt, TLS handshake, favicon) | web footprinting |
| `active` | intrusive probes (ports, paths, AXFR, buckets) — needs `--authorized` | **authorized** pentests only |

### What a scan produces

* live feed of every source queried, then a terminal report: risk gauge, cross-referenced
  conclusions, findings by severity, entity map, facts, timeline, source coverage, manual pivots;
* files: self-contained dark **HTML** (opens offline, loads nothing external), **Markdown**,
  **JSON**, **STIX 2.1**;
* evidence: every raw response saved with its **SHA-256**;
* the closing question — *did this make sense?* — whose answers re-weight noisy sources.

## Rules of engagement

V3LUM inherits the rules of the team's Céos project and they were confirmed by the review council:

1. open/public sources only; no CAPTCHA/anti-bot bypass; no logging into third-party accounts;
2. no account enumeration via password-reset/sign-up endpoints (holehe-style);
3. breach data is metadata only — never passwords or leaked files;
4. no people-search on leaked databases (CPF/phone "painéis"); CPF is validated offline only (LGPD);
5. 403/429/timeouts mean "could not verify", never "does not exist";
6. active probing only with written authorization (`--authorized`, recorded in the case).

## Documentation

* [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how the engine, guard rails, evidence and feedback work
* [`docs/MODULE_GUIDE.md`](docs/MODULE_GUIDE.md) — write a new source in ~40 lines (+ tests)
* `v3lum --help`, `v3lum <command> --help`, `help` inside the console

## Tests

```bash
pytest -q                       # offline suite (no network)
V3LUM_LIVE=1 pytest -q -m live  # live checks against the real APIs
ruff check v3lum tests
```
