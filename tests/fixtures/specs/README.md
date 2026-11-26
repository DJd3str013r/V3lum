# Declarative-spec fixtures (P331)

Module contract v2, section 17. A declarative spec (`v3lum/data/specs/<name>.json`, schema
`v3lum.spec/1`) compiles into a real Module subclass (wave 2, WP12 `v3lum.core.specs`). A spec is
**loaded only when its fixtures exist** here:

```
tests/fixtures/specs/<name>/
    ok.<ext>             trimmed real answer for the spec's health_check value (ext = json, ndjson, csv, xml, rss, html)
    error_in_200.<ext>   a real error/quota/challenge body served with HTTP 200 by the same source
    expected.json        what the compiled module must produce for each fixture
```

`<name>` is the spec (module) name. Compiled spec classes carry a non-empty `spec_origin`; for them
these three files replace the `tests/modules/test_<name>.py` + `tests/fixtures/<name>/` rule of the
registry contract test (`tests/test_registry_contract.py`), and a parametrized test (WP12,
`tests/test_specs.py`) runs every spec over its fixtures.

## expected.json

```json
{
  "ok": {
    "status": "ok",
    "attributes": {"country": "BR"},
    "pivots": ["domain:example.com"]
  },
  "error_in_200": {
    "status": "rate_limited",
    "reason_code": "rate_limited"
  }
}
```

* `ok.status` - expected `ModuleResult.status` for `ok.*`; `ok.attributes` is a **subset** of the
  result attributes; `ok.pivots` a subset of the pivot entity keys (`type:value`).
* `error_in_200.status` / `reason_code` - the could-not-verify outcome of the error body (P321: the
  classifier runs before the result rules, so an error inside an HTTP 200 is never an absence).

Rules: fixtures are trimmed real responses without personal data; the error fixture must come from
the same provider (quota text, `{"success": false}`, challenge page...). Unknown-tier or
unknown-terms specs still need fixtures although they ship `default_enabled=false` (A3/A8).
