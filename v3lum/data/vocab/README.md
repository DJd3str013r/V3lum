# Vocabulary fragments (`v3lum/data/vocab/<pack>.json`)

The shared vocabulary (attribute keys, finding/entity tags, relation names) is the core set in
`v3lum/core/vocab.py` merged with the fragments of this directory (module-author contract v2,
section 14). Packs and module batches **add a fragment file**; nobody edits `vocab.py` or another
package's fragment.

```json
{
  "schema": "v3lum.vocab/1",
  "pack": "breach",
  "attributes": {"first_seen_breach": "ISO date of the oldest breach that lists the entity"},
  "tags": {"stealer_corporate": "corporate credentials seen in infostealer logs (metadata only)"},
  "relations": {"same_tenant": "domain -> domain hosted in the same SaaS tenant"},
  "timeline": {"first_seen_breach": "first seen in a breach"}
}
```

Rules (checked at load time; problems never raise, they are listed by `vocab.errors()` and the
registry contract test requires none):

* `schema` must be `"v3lum.vocab/1"`. Optional metadata keys: `pack`, `title`, `description`,
  `owner`, `notes`, `$comment`. Any other top-level key is reported.
* `attributes`, `tags`, `relations` are objects of `name -> description`; names match
  `^[a-z][a-z0-9_]{0,63}$` and descriptions are non-empty strings. A malformed entry is reported
  and skipped; the valid entries of the same file still load.
* Merge order: core names first, then fragment files sorted by file name. Re-declaring an existing
  name is allowed (the first description wins) and is listed by `vocab.redeclarations()` as
  `(kind, name, file)` for review.
* `timeline` (optional): `attribute -> timeline label`. The attribute must exist in the merged
  vocabulary (core or any fragment). `vocab.timeline_attributes()` returns the core dated
  attributes (created, updated, expires, first_seen, last_seen, opened, archive_first,
  cert_not_after) merged with these entries, and the engine's case timeline uses it. Core labels
  win over fragment labels.

API: `vocab.attributes()`, `tags()`, `relations()` (merged dicts), `is_known_attribute/tag/relation()`,
`check(kind, name)` (`'attribute' | 'tag' | 'relation'`), `timeline_attributes()`, `errors()`,
`redeclarations()`, `reload()` (tests), `strict_enabled()`.

Strict contract mode (`V3LUM_STRICT=1`, always on in tests): `ModuleResult.attr()`,
`finding(tags=...)` and `pivot(relation=...)` raise `vocab.UnknownVocab` (a `ContractViolation`)
for names outside the merged vocabulary. Outside strict mode unknown names are kept and logged
once per (module, name) on logger `v3lum.contract`. Tests may extend the vocabulary temporarily
with `tests.fakes.allow_vocab(...)`.
