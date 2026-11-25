# V3LUM architecture

```
 input ──► detect ──► seeds ──► ENGINE ─────────────────────────────────► correlate ──► score ──► report ──► feedback
 (any)    (40+ types,           │  pipelined BFS over entities                │ rules over     │ noisy-OR   │ terminal   │ "did it make
           TYPE:value           │  · select modules (type, opsec, keys)       │ the graph      │ per entity │ HTML/MD    │  sense?" ->
           override)            │  · run in thread pool (ctx.http/dns)        │ (cross-source) │ + case     │ JSON/STIX  │  module
                                │  · merge attrs/findings into graph          │                │            │ evidence   │  reliability
                                │  · pivot on new entities (guard rails)      │                │            │            │
```

## Layers

| Layer | Files | Responsibility |
|---|---|---|
| Entities | `core/entities.py`, `core/validators.py`, `core/psl.py` | 43 entity types, canonical normalization (IDNA, E.164, CNPJ alfanumérico, bech32m, onion v3...), refang/defang |
| Detection | `core/detect.py` | what did the analyst type? scored interpretations, ambiguity handling, IOC extraction from text/files |
| Module API | `core/module.py`, `core/models.py`, `core/vocab.py` | plugin contract, registry/auto-discovery, readiness (keys, packages, opsec), result model, shared vocabulary |
| Plumbing | `core/http.py`, `core/dns.py`, `core/datasets.py`, `core/context.py` | cached/rate-limited/retrying HTTP (never caches 401/403/429/5xx), DoH resolver, downloadable datasets, per-run context |
| Engine | `core/engine.py`, `core/graph.py`, `core/noise.py`, `core/links.py` | scheduling, pivot guard rails, knowledge graph, evidence (SHA-256), manual pivot links |
| Analysis | `core/correlate.py`, `correlations/*.py`, `core/scoring.py` | cross-source rules, risk 0-100 per entity and per case |
| Persistence | `core/store.py`, `paths.py`, `config.py` | SQLite cases, feedback + module reliability, config/keys (0600) |
| UI | `ui/theme.py`, `ui/banner.py`, `ui/live.py`, `ui/render.py`, `cli.py`, `shell.py`, `app.py` | dark-theme terminal UI, live feed, report rendering, CLI + interactive console |
| Reports | `report/{html,markdown,stix}.py` | self-contained HTML (no external resources), Markdown, JSON, STIX 2.1 bundle |

## Guard rails (why scans stay bounded and polite)

* **Depth** (`--depth`, default 1): inputs = depth 0; their discoveries = depth 1.
* **Entity budget** (`--max-entities`, default 150) and optional global timeout.
* **Per-parent caps** per entity type (e.g. at most 12 subdomains or 10 IPs expanded from one parent).
* **Never auto-expanded**: free text, files, keywords, person names, CPF, coordinates, JWTs, card BINs, IMEIs.
* **Noise suppression**: public resolvers, big webmail/CDN/cloud providers and private/reserved IPs are
  recorded but not pivoted on (`core/noise.py`, `data/noise.json`).
* **Module pivot cap** (`max_pivots`) and `expand=False` for weak relations (MX/NS hosts, co-tenants on CDNs).
* **Opsec**: `passive` by default; `light` touches the target like a visitor; `active` needs `--authorized`
  plus an interactive confirmation, and the authorization reference is stored in the case.
* **Politeness**: per-host minimum interval and concurrency, cache, collapse of identical in-flight requests.

## Evidence and auditability

Each module run with raw data writes `~/.v3lum/cases/<case>/evidence/<module>__<type>__<value>__<sha>.json`
(collected_at + raw response). The report lists every evidence file with its SHA-256. Cases are stored in
`~/.v3lum/v3lum.db` and can be re-rendered (`v3lum cases report <id>`).

## Feedback loop

After an interactive scan V3LUM asks *"did this report make sense?"*. Verdicts are stored; per-finding
right/wrong flags update a Laplace-smoothed reliability per module (floor 0.3) that weights that module's
findings in future risk scores (`v3lum feedback` shows the table).

## Extending

* New source: one file in `v3lum/modules/<category>/` (see `docs/MODULE_GUIDE.md`).
* New cross-reference: a function with `@rule(...)` in `v3lum/correlations/`.
* Private plugins: drop `*.py` files in `~/.v3lum/plugins/` (loaded at start).
* New manual pivot: an entry in `v3lum/data/pivot_links.json`.
