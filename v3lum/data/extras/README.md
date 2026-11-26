# Optional-dependency fragments (`v3lum.extra/1`)

Core V3LUM depends only on `rich` and `requests` (A16 BR8). Every other runtime dependency is an
**optional extra**: a module that needs it lists the import name in `Module.requires_packages`, and
reports `UNAVAILABLE` reason `package` (with a `pip install 'v3lum[<extra>]'` hint) when the package is
missing. `@register` refuses a `requires_packages` entry that is not a known optional package.

Known optional packages = `module.CORE_OPTIONAL_PACKAGES` (phonenumbers, dns, PIL, pypdf, socks ->
`full`; websocket -> `watch`; yaml -> `yaml`) merged with the fragments of this directory into
`module.OPTIONAL_PACKAGES` (import name -> extra). **A batch adds a fragment here and never edits
`pyproject.toml`**; the packaging work (WP29) keeps the pyproject extras in sync with these files.

## Fragment: `v3lum/data/extras/<package>.json`

```json
{
  "schema": "v3lum.extra/1",
  "package": "websocket",
  "pip": "websocket-client>=1.6",
  "extra": "watch",
  "licence": "Apache-2.0",
  "justification": "CertStream-compatible WebSocket consumer for `v3lum watch` (A14), optional"
}
```

| field | rule |
|---|---|
| `schema` | `"v3lum.extra/1"` |
| `package` | the **import name** (what `requires_packages` lists, e.g. `websocket`, `PIL`); equals the file stem |
| `pip` | the requirement spec installed by the extra (e.g. `websocket-client>=1.6`) |
| `extra` | the pyproject extra that installs it (`^[a-z][a-z0-9_-]{0,31}$`, e.g. `full`, `watch`) |
| `licence` | SPDX-style licence of the package. Permissive licences, or LGPL used unmodified as an optional extra (A6). **GPL/AGPL packages are refused**: such tools run only as separately installed external processes |
| `justification` | why the dependency is needed and why it is optional |
| `notes` | optional text |

A package already known with another extra, a duplicate package, an unknown field or a missing field
is an error: the fragment is ignored, listed by `module.extras_errors()` and reported by
`module.load_errors()` as `extras:<file>` (the registry contract test requires none).
