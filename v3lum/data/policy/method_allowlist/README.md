# Method allow-list for target contact (`v3lum.method_allow/1`)

LIGHT and ACTIVE modules send only **GET/HEAD (LIGHT)** or **GET/HEAD/OPTIONS (ACTIVE)** to
targets (A7). A module may send another method toward targets only when a core policy decision
allow-lists it here for a **documented read-only reason** (for example a GraphQL introspection
query that must be a `POST`). No fragment ships: every entry is a recorded architect/legal
decision, never something a module batch adds on its own.

The HTTP client (`v3lum.core.http`) enforces it for every LIGHT/ACTIVE request; the P327 lint
(LINT-06, WP09) reads the same fragments for module source code.

## File

One file per module: `v3lum/data/policy/method_allowlist/<module>.json`

```json
{
  "schema": "v3lum.method_allow/1",
  "module": "graphql_introspection",
  "methods": {"POST": "GraphQL introspection is a read: the query is fixed and never mutates"},
  "approved_by": "architect (council-2)",
  "decision_ref": "ADR-0042",
  "notes": "optional"
}
```

| field | rule |
|---|---|
| `schema` | `"v3lum.method_allow/1"` |
| `module` | the module name; equals the file stem |
| `methods` | object `METHOD -> justification` (a non-empty written reason per method) |
| `approved_by` | who approved the decision (required) |
| `decision_ref` | the recorded decision (ADR, council item, ticket; required) |
| `notes` | optional text |

## Rules

* A fragment without `approved_by` **and** `decision_ref` is **ignored and reported**
  (`v3lum.core.http.method_allowlist_errors()`, shown by doctor).
* `PUT`, `PATCH`, `DELETE`, `TRACE`, `TRACK`, `CONNECT`, `PROPPATCH`, `MKCOL`, `COPY`, `MOVE`,
  `LOCK` and `UNLOCK` can **never** be allow-listed: writes, deletes, tracing and tunnelling
  toward targets are forbidden in every mode and engagement (A7). A fragment that names one is
  rejected as a whole.
* A Tor egress profile carries LIGHT reads only (GET/HEAD) whatever this list says (A13).
* An allow-listed method changes nothing else: scope, SSRF guard, ceilings, the hostile-host
  guard and the ledger apply as for any other request.

API: `v3lum.core.http.method_allowlist()` (approved entries by module),
`v3lum.core.http.method_allowlist_errors()`, `v3lum.core.http.allowed_methods(module, opsec)`,
`v3lum.core.http.reload_method_allowlist(extra_dirs=None)` (tests).
