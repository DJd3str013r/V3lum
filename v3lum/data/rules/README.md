# Data correlation rules (`v3lum.rule/1`, P301)

Correlation rules can be written as data instead of Python. A data rule is compiled by
`v3lum.core.rules_engine.compile_rule` into the same `correlate.RuleInfo` a `@rule` function
produces (`kind: "data"`), is registered in the same registry, runs in the same single pass after the
investigation (`correlate.run_rules`) and is listed by `v3lum rules`. Python rules stay first-class:
use a data rule when the logic is "select entities, bucket them, count".

* **Bundled rules** live here, one file per rule: `v3lum/data/rules/<rule_id>.json` or `.toml`
  (never YAML: core has no YAML dependency). Each one ships positive and negative graph fixtures in
  `tests/fixtures/rules/<rule_id>/` like any rule (contract section 16).
* **User rules** live in `~/.v3lum/rules/` (JSON, TOML, or YAML with the optional extra `yaml`,
  parsed with `yaml.safe_load` only). They load only when the directory and every file are owned by
  the current user and not group/world-writable (AR12), pass the P327 data lint and do not reuse a
  registered id. `v3lum rules` and doctor show what loaded and what was refused.

Schema errors are `correlate.RULE_ERRORS` entries: the registry contract test fails in CI.

## Document

```json
{
  "schema": "v3lum.rule/1",
  "id": "rare_registrar",
  "version": "1",
  "code": "",
  "title": "Rare registrar among the investigated domains",
  "description": "optional longer text",
  "severity": "low",
  "confidence": "possible",
  "criterion": "registrar used by <= 10% of >= 10 investigated domains",
  "references": ["https://example.org/why-this-matters"],
  "attack": ["T1583.001"],
  "false_positives": "Small portfolios legitimately mix registrars.",
  "tags": ["infrastructure"],
  "collections": [
    {"name": "domains", "entity_types": ["domain"],
     "filters": [{"field": "attr:registrar", "op": "exists"}]}
  ],
  "aggregation": {"field": "attr:registrar"},
  "analysis": {"method": "outlier", "minimum": 10, "percentile": 10},
  "headline": "{count} domain(s) use the rare registrar {value}",
  "recommendation": "Check who registered these domains and whether the organisation knows them.",
  "suppress": [
    {"name": "parked", "when": [{"field": "tag:parked", "op": "exists"}],
     "to": "possible", "severity": "info", "reason": "parked domains say little about ownership"}
  ]
}
```

| key | required | meaning |
|---|---|---|
| `schema` | yes | `v3lum.rule/1` |
| `id` | yes | `^[a-z][a-z0-9_]{1,63}$`, unique across all rules |
| `version`, `title`, `severity`, `criterion`, `recommendation` | yes | rule metadata (severity `info`..`critical`) |
| `collections` | yes | 1-8 `{name, entity_types, filters, include_noise?}` |
| `analysis` | yes | `{method, minimum?, maximum?, percentile?, noisy_percent?, match?}` |
| `headline` | yes | title template; placeholders `{value}` `{count}` `{total}` `{percent}` `{field}` `{collection}` `{entities}` `{rule}` `{severity}` only |
| `code`, `description`, `references` (https), `attack` (validated ATT&CK ids), `false_positives`, `tags` (vocab), `fixtures` | no | metadata shared with Python rules |
| `confidence` | no | label of the correlations (`possible` by default) |
| `aggregation` | no | `{field}`, default `entity` (one bucket per entity) |
| `suppress` | no | named suppression rules (below) |
| `natural_person` | no | `true` declares a rule about people (also implied by `person_name`/`cpf` collections) |

### Fields and operators

Fields: `attr:<name>` (a vocabulary attribute), `tag:<name>` (a vocabulary tag of the entity or of
one of its evidence findings), `relation:<name>` (a vocabulary relation in either direction; `eq`,
`in` and `regex` test the neighbour's value, `gte`/`lte` count neighbours), `type`, `value` (the
entity value), `finding.source` (registry source or module of a finding) and `finding.severity`.
Aggregation also accepts `entity`. Unknown attribute, tag and relation names are schema errors:
declare them in a `v3lum/data/vocab/` fragment first.

Operators: `eq`, `in` (list), `regex`, `gte`, `lte`, `exists`; `"negate": true` inverts a filter.
Finding filters of one collection must hold on the same finding, and only evidence findings count
(never `context_only` or `SUP-*`-suppressed ones). Noise nodes (CDN, resolvers, webmail...) are
skipped, as entities and as `relation:` neighbours (AR06: a shared CDN address links nothing), unless
the collection sets `"include_noise": true`.

Regexes (ReDoS guard): at most 200 characters, no backreferences, no unbounded repeat inside another
repeat (`(a+)+`, `([a-z]+\.)+`), no repeated alternation whose branches do not start with distinct
literal characters (`(a|aa)+`) and no two unbounded repeats over overlapping characters without a
separator the first one cannot match (`\w*\w*x`, `.*foo.*bar`, `a+a+b`: write `foo.{0,64}bar` or
put a disjoint character between them). Matched text is truncated to 1024 characters: graph values
come from the investigated targets and are untrusted.

### Analysis methods (SpiderFoot model)

| method | keeps | parameters |
|---|---|---|
| `threshold` | buckets holding between `minimum` (default 1) and `maximum` entities | `minimum`, `maximum` |
| `outlier` | buckets holding <= `percentile`% (default 10) of the entities, only when there are >= `minimum` (default 10) entities and the data is not too flat (average bucket share >= `noisy_percent`, default 10) | `minimum`, `percentile`, `noisy_percent` |
| `first_collection_only` | values of collection 1 absent from every other collection | `minimum`, `maximum` |
| `match_all_to_first_collection` | values of collection 1 matched by values of the other collections (`match`: `exact`, `contains`, `subnet`) | `match`, `minimum`, `maximum` |
| `both_collections` | values present in every collection | `minimum`, `maximum` |

`minimum`/`maximum` of the last three bound the number of entities of a kept bucket. Each kept bucket
gives one correlation (at most 100 per rule and run): its entities, the evidence used (finding ids
and facts such as `attr:registrar=X`, `share=4.0%`), a one-line `why`, the recommendation and the
ATT&CK ids.

### Suppression

`suppress` entries only downgrade: when any entity of a bucket matches `when` (one filter or a list,
all must hold), the correlation's label goes one level down (or to `to`) and, optionally, its
severity to `severity` (never above the rule's). The entry is recorded as
`<rule_id>:<name>` with its `reason` (and, when the severity was lowered, `from`/`to` severity labels)
in `suppressed_by` and in the criterion: nothing is deleted.

`tags` never include the reserved run-time tags `precision_demoted` and `analyst_confirmed`, and
`references` never point at people-search, submission or account-enumeration services (the P327 lint
tables): both are schema errors.

### Guarantees

Rules only read the graph and emit correlations: they never schedule modules or pivots, change the
opsec mode or widen the scope. `run_rules` applies to data and Python rules alike: per-rule precision
(< 0.3 after >= 10 analyst votes: one severity level lower, labelled `P301-precision`, never
disabled) and the P258 cap (correlations about natural persons stay PROBABLE at most without analyst
confirmation). Rules about natural persons run only in cases with a recorded purpose (AR16).

The model is adapted from the SpiderFoot correlation engine (MIT; notice
`v3lum/data/notices/spiderfoot_correlations.json`).
