# Correlation-rule graph fixtures

Every correlation rule that is not one of the eight legacy rules of
`v3lum/correlations/generic.py` (`correlate.LEGACY_RULES`) ships at least one **positive** and one
**negative** graph fixture here (module-author contract v2, section 16):

```
tests/fixtures/rules/<rule_id>/positive_<case>.json   # the rule must fire
tests/fixtures/rules/<rule_id>/negative_<case>.json   # the rule must stay silent
```

`tests/test_rule_fixtures.py` discovers every directory automatically and runs
`correlate.run_rules(graph, results, only={rule_id}, rctx=rctx)` on each file
(`correlate.check_fixture(rule_id, path)`); nothing has to be registered by hand. File names
start with `positive_` or `negative_` and each directory holds at least one of each.
Fixtures are synthetic or trimmed real data: no personal data, no secrets, documentation
addresses only (`example.com/.net/.org`, `*.example`, `192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`, `2001:db8::/32`).

## Format (`"schema": "v3lum.graph_fixture/1"`)

```json
{
  "schema": "v3lum.graph_fixture/1",
  "now": "2026-11-26T12:00:00Z",
  "options": {"mode": "passive", "tlp": "amber", "depth": 1},
  "org_profile": {"name": "Corp", "domains": [{"name": "corp.example", "verification": "txt_verified"}]},
  "settings": {"attack_surface_min_assets": 20},
  "meta": {"anything": "the rule reads from rctx.meta"},
  "nodes": [
    {
      "key": "domain:corp.example",
      "depth": 0, "seed": true, "noise": false, "noise_kind": "",
      "ownership": "own_asset", "criticality": "high", "tlp": "amber", "path_confidence": 1.0,
      "tags": ["own_asset"],
      "attributes": {"registrar": [{"value": "Example Registrar", "source": "rdap_lookup"}]},
      "findings": [
        {"title": "Listed by feed A", "severity": "high", "confidence": 0.9, "confidence_label": "confirmed",
         "criterion": "feed verdict", "tags": ["malicious"], "module": "feed_a", "source": "feeds.a",
         "observed_first": "2026-11-01T00:00:00Z", "data": {}}
      ]
    },
    {"key": "ipv4:203.0.113.10", "depth": 1}
  ],
  "edges": [{"src": "domain:corp.example", "dst": "ipv4:203.0.113.10", "relation": "resolves_to",
             "module": "dns_records", "confidence": 0.9}],
  "results": [{"module": "dns_records", "entity": "domain:corp.example", "status": "ok",
               "attributes": {"a_records": ["203.0.113.10"]}}],
  "expect": {"<rule_id>": {"min": 1, "max": 1, "severity": "high", "confidence_label": "probable"}}
}
```

| key | meaning |
|---|---|
| `now` | **required**: the rule's clock (`rctx.now`, aware UTC). |
| `options` | `ScanOptions` fields (`mode`, `tlp`, `depth`, `include`...); unknown names are ignored. |
| `org_profile` | optional: `rctx.org = orgprofile.OrgProfile.from_dict(...)` (P378 schema). |
| `settings` | optional: config setting overrides read through `rctx.setting(name)` / `rctx.settings`. |
| `meta` | optional: `rctx.meta`. |
| `nodes` | entities: `key` (`"type:value"`, values already canonical) or `type` + `value`; graph context fields as above; `attributes` as `{name: [{value, source}]}` (a bare value means one value from source `fixture`); `findings` as full finding dicts (`Finding.from_dict`, entity = the node). |
| `edges` | `{src, dst, relation, module, confidence}`; both ends must be listed in `nodes`. |
| `results` | optional `ModuleResult.to_dict()`-shaped entries for rules that read `results`. |
| `expect` | positive fixtures: `{rule_id: {min (default 1), max (optional), severity (optional), confidence_label (optional)}}`; every correlation of the rule must match the given severity/label. Negative fixtures need no `expect`: the rule must produce nothing. |

Unknown keys are ignored. An invalid node, an edge to an unknown node or a missing `now`
raises (fixtures must be exact). A fixture also fails when the rule raises while running it or
emits ATT&CK ids missing from the bundled index (`v3lum/data/attack/`); each fixture is checked on
its own, so the same failure is reported for every fixture that triggers it. Load one by hand with `correlate.load_graph_fixture(path)`
(-> `GraphFixture(graph, results, rctx, expect)`) or `tests.fakes.graph_fixture(path)`.
