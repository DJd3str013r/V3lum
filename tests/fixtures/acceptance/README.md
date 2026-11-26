# Golden-path acceptance routes (`v3lum.acceptance_routes/1`)

Module contract v2, section 19 (frozen in `docs/MODULE_GUIDE.md`). The AR21 golden-path harness
(wave 5, WP27) replays these routes through `tests.fakes.FakeHttp` to run a **default scan** of each
golden input offline and check the A3 time budget (first screen <= 20 s, p90 completion <= 60 s with
the recorded latencies), at most 25 non-info findings on benign inputs, coverage and TLP shown and no
secret in any output.

## Layout

One file per (entity type, module):

```
tests/fixtures/acceptance/<type>/<module>.json
```

`<type>` is the entity type value of a golden input and `<module>` the module name. Every module
that runs by default on a golden type ships its file in the same change as the module (merge gate,
A16). Golden inputs (benign values only):

| type | value |
|---|---|
| `domain` | `example.com` |
| `ipv4` | `8.8.8.8` |
| `url` | `https://example.com/` |
| `sha256` | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` (EICAR) |
| `email` | `someone@example.com` |
| `cnpj` | `00000000000191` |

## Format

```json
{
  "schema": "v3lum.acceptance_routes/1",
  "module": "shodan_internetdb",
  "routes": [
    {
      "method": "GET",
      "url": "https://internetdb.shodan.io/8.8.8.8",
      "status": 200,
      "json": {"cpes": [], "hostnames": ["dns.google"], "ip": "8.8.8.8", "ports": [53, 443], "tags": [], "vulns": []},
      "headers": {"content-type": "application/json"},
      "latency_ms": 450
    }
  ]
}
```

| field | meaning |
|---|---|
| `schema` | always `v3lum.acceptance_routes/1` |
| `module` | the module name (must equal the file stem) |
| `routes[].method` | HTTP method (`GET`, `HEAD`, `POST`) |
| `routes[].url` | exact URL as the core sends it (query order does not matter; DoH routes carry `edns_client_subnet=0.0.0.0/0` for Google, see `tests.fakes.doh_url`) |
| `routes[].status` | HTTP status |
| `routes[].json` / `text` / `body_b64` | the body: exactly one of them (`body_b64` = base64 of raw bytes) |
| `routes[].headers` | response headers (optional, lower-case names) |
| `routes[].latency_ms` | recorded p50 latency of the real source (drives the fake clock) |

Rules: trimmed **real** responses recorded from the source (no personal data, no keys); DoH answers
for DNS modules; one route per request the module makes on the golden input. The harness fails on
any request without a route (unmatched requests raise, the network guard is active).
