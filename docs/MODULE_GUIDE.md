# Writing a V3LUM module

A module is a small class that takes **one entity** (an email, a domain, an IP...) and returns a
`ModuleResult`: facts about it (*attributes*), judgements (*findings*), newly discovered entities
(*pivots*) and manual follow-up URLs (*links*). The engine handles concurrency, caching, retries,
rate limits, pivoting, correlation, scoring, evidence and reports, so a module only has to
**fetch, parse and translate** into the shared vocabulary.

## 1. Skeleton

```python
# v3lum/modules/<category>/<source>.py
from __future__ import annotations

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register


@register
class ExampleSource(Module):
    name = "example_source"            # unique snake_case id (CLI: v3lum run example_source <input>)
    title = "Example Source"           # shown in tables
    description = "What it returns and from where (one or two sentences)."
    category = "ip_network"            # one of v3lum.core.module.CATEGORIES
    accepts = {T.IPV4, T.IPV6}         # entity types handled
    produces = {T.DOMAIN}              # entity types it may pivot to (documentation)
    opsec = Opsec.PASSIVE              # PASSIVE | LIGHT | ACTIVE (see section 4)
    requires_keys = ()                 # e.g. ("shodan",) -> skipped with "needs key" when absent
    optional_keys = ()                 # keys that unlock more data but are not required
    requires_packages = ()             # e.g. ("phonenumbers",) -> "unavailable" when not installed
    hosts = ("api.example.com",)       # every host contacted (doctor, proxies, docs)
    reference = "https://api.example.com/docs"
    tags = {"free"}                    # free-form: free, brazil, slow, noisy, offline...
    cache_ttl = 86400                  # seconds; None = global default
    min_interval = 0.0                 # seconds between requests to this module's hosts (ToS!)
    default_enabled = True             # False = opt-in (slow/noisy); run with -M name or --all-modules
    notice = ""                        # legal/ethical note shown by `v3lum info`

    def applies(self, entity: Entity, ctx) -> bool:   # optional extra filter
        return True

    def run(self, entity: Entity, ctx) -> ModuleResult:
        res = self.result(entity)
        data = ctx.http.get_json(f"https://api.example.com/v1/ip/{entity.value}", ok404=True)
        if not data:
            return res.mark("empty")
        res.raw = data                                   # saved as evidence (SHA-256)
        res.attr("country", data.get("country"))         # vocabulary keys only (core/vocab.py)
        for host in data.get("hostnames", []):
            res.pivot(T.DOMAIN, host, "reverse_dns")     # invalid values are dropped silently
        if data.get("malicious"):
            res.finding("Listed as malicious by Example", "high", "why it matters",
                        tags=["malicious"], confidence=0.8,
                        references=[f"https://example.com/ip/{entity.value}"])
        res.link("Example web view", f"https://example.com/ip/{entity.value}")
        return res
```

Put the file in the matching `v3lum/modules/<category>/` package. It is discovered automatically;
nothing else has to be edited.

## 2. What `ctx` gives you

| `ctx.` | use |
|---|---|
| `http.get(url, params=, headers=, timeout=, ttl=, allow_redirects=, max_bytes=)` | returns `Response` (`.status .ok .text .json() .headers .url .history .from_cache`) |
| `http.get_json(url, ok404=False, ...)` / `http.post_json(...)` | parsed JSON; raises `RateLimited` (429), `AuthRequired` (401/403), `HttpError` (other non-2xx) |
| `http.post(url, json_body=..., data=...)` | POST (not cached unless `ttl=` given) |
| `dns.query(name, "MX")` | `DnsAnswer(records=[...], status, authenticated, error)`; `dns.ptr(ip)`, `dns.addresses(name)` |
| `key("shodan")` / `has_key(...)` | API keys (env `V3LUM_KEY_<NAME>` or `v3lum keys set`) |
| `data.bundled_json/bundled_text/bundled_lines(name)` | files shipped in `v3lum/data/` |
| `data.fetch_json/fetch_text/fetch_lines(name, url, ttl=)` | downloadable datasets cached in `~/.v3lum/datasets` |
| `mode`, `authorized`, `options` | current opsec mode / authorization |
| `setting(name)` | config values (e.g. `nsfw_sites`, `default_region`) |
| `log(msg, level)` | line in the live feed (`debug` only shown with `-v`) |
| `cancelled()` | stop long loops early when the analyst hits Ctrl+C |
| `now()` | timezone-aware UTC now (use it, tests freeze it) |

Register downloadable datasets at import time so `v3lum data update` can pre-fetch them:

```python
from v3lum.core.datasets import register_dataset
KEV = register_dataset("cisa_kev.json", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                       ttl=6 * 3600, description="CISA Known Exploited Vulnerabilities")
...
data = ctx.data.fetch_json(KEV, "https://www.cisa.gov/...", ttl=6 * 3600)
```

## 3. Vocabulary (mandatory)

Correlation rules and reports only understand the names in `v3lum/core/vocab.py`:

* **attributes** (`res.attr`): `country`, `asn`, `as_org`, `created`, `registrar`, `nameservers`,
  `open_ports`, `vulns`, `breach_count`, `breaches`, `infostealer`, `disposable`, `free_provider`,
  `profiles`, `legal_name`, `partners`, `kev`, `epss`, `cvss`, `malicious`, `is_tor_exit`...
* **finding tags**: `malicious`, `suspicious`, `phishing`, `malware`, `c2`, `breach`, `infostealer`,
  `vulnerable`, `kev`, `exploit_available`, `exposure`, `misconfiguration`, `weak_email_security`,
  `typosquat`, `newly_registered`, `takeover`, `ransomware`, `darkweb`, `sanctions`, `identity`,
  `account`, `known_good`, `privacy`, `info`...
* **relations** (`res.pivot(..., relation)`): `resolves_to`, `reverse_dns`, `hosted_domain`, `mx_host`,
  `nameserver`, `subdomain`, `parent_domain`, `email_domain`, `contact_email`, `belongs_to_asn`,
  `has_account`, `uses_username`, `commit_email`, `partner`, `has_vuln`, `family`, `attributed_to`,
  `uses_technique`, `victim_of`, `lookalike`, `mentions`...

If you need a new name, add it to `vocab.py` with a description in the same change.

Severity guide: `info` = context; `low` = weak signal; `medium` = worth a look; `high` = likely
problem / strong indicator; `critical` = confirmed compromise, active exploitation, sanctions,
ransomware listing. Set `confidence` (0-1) honestly: version-based CVE matches, homonyms and
"same username" are low-confidence.

## 4. Opsec levels and safety rules

* `PASSIVE` (default): only third-party sources. The target never sees the request.
* `LIGHT`: benign direct contact with the target, like a normal visitor (homepage, robots.txt,
  security.txt, TLS handshake, favicon). Runs with `--mode light`.
* `ACTIVE`: intrusive probing (port scans, path discovery, AXFR, bucket brute force...). Runs only
  with `--mode active --authorized`; keep probes bounded and polite.

Team rules (inherited from Céos, approved by the council):

1. Open/public sources only. No CAPTCHA or anti-bot bypass, no logging into third-party accounts,
   no borrowed cookies/session ids.
2. No account enumeration through password-reset / sign-up endpoints (holehe-style).
3. Breach data is **metadata only** (breach names, dates, data classes). Never store or print
   passwords, hashes of passwords, or leaked file contents. Masked hints from a source must not be
   persisted.
4. No people-search over leaked databases (CPF/name/phone "painéis"). Brazilian official open data
   (CNPJ, QSA, CEP...) is fine; CPF is validated offline only.
5. `403`, `429`, timeouts and errors mean **"could not verify"**, never "does not exist".
6. Respect provider limits: set `min_interval` and `cache_ttl`; identify yourself with a UA only
   when the provider asks for it (e.g. Nominatim, SEC).
7. Do not send the investigated value to services that publish submissions (e.g. urlscan public
   scans) — search only.

## 5. Tests (mandatory, offline)

Every module gets `tests/modules/test_<module>.py` using the fakes — **unit tests never touch the
network** (unmatched requests fail the test):

```python
from tests.fakes import FakeHttp, fixture, make_ctx
from v3lum.core.entities import Entity
from v3lum.modules.ip_network.example_source import ExampleSource

def test_parses_response():
    http = FakeHttp().add("GET", "https://api.example.com/v1/ip/1.2.3.4", json=fixture("example_source.json"))
    res = ExampleSource().run(Entity.make("ipv4", "1.2.3.4"), make_ctx(ExampleSource, http))
    assert res.attributes["country"] == "US"
    assert any(p.entity.value == "host.example" for p in res.pivots)

def test_not_found():
    http = FakeHttp().add("GET", "https://api.example.com/v1/ip/1.2.3.4", status=404)
    res = ExampleSource().run(Entity.make("ipv4", "1.2.3.4"), make_ctx(ExampleSource, http))
    assert res.status.value == "empty"
```

* Fixtures (`tests/fixtures/*.json|txt`) are trimmed real responses (no personal data).
* DNS: `add_dns(http, "example.com", "MX", ["10 mx.example.com."])` builds DoH answers.
* Keys: `make_ctx(Cls, http, keys={"shodan": "test"})`.
* Live checks go in `tests/live/test_<area>.py`, marked `@pytest.mark.live`; they run only with
  `V3LUM_LIVE=1` and must use benign public values (example.com, 8.8.8.8, octocat...).

Run: `pytest -q` (offline) · `V3LUM_LIVE=1 pytest -q -m live` (live) · `ruff check v3lum tests`.
