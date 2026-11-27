# Actor / malware alias index fragments (`v3lum.aliases/1`)

Module contract v2, section 18 table ("actor / malware aliases"); read by detection from wave 3
(WP17, AR18). Known malware-family and threat-actor names typed by the analyst, or written in
pasted text, are typed `malware_family` / `threat_actor` (confidence 0.8) instead of `username`.

## File

`v3lum/data/aliases/<name>.json`, one JSON object per file:

```json
{
  "schema": "v3lum.aliases/1",
  "kind": "malware_family",
  "source": "MISP galaxy commit e048304... (16 clusters), built 2026-11-26",
  "licence": "CC0-1.0 OR BSD-2-Clause",
  "notes": "optional free text",
  "names": {"Sofacy": "APT28", "Fancy Bear": "APT28"}
}
```

| field | meaning |
|---|---|
| `schema` | always `v3lum.aliases/1` |
| `kind` | `malware_family` or `threat_actor` (one kind per file) |
| `source` | where the names come from (dataset, commit, build date) |
| `licence` | SPDX expression; copyleft or non-commercial data is rejected (A6) unless an `OR` alternative is permissive |
| `names` | alias -> canonical name; the canonical names are indexed too |

## Rules

* Aliases are matched case-insensitively with whitespace collapsed; 3-64 characters.
* An alias that resolves to several clusters (umbrella names, vendor disagreements) must not be
  shipped: the P295 generator (`v3lum/modules/cti_framework/actor_alias_index.py`) keeps only
  aliases that resolve to exactly one non-umbrella cluster. Equivalences are vendor assessments,
  not identities.
* `v3lum.core.detect.detect()` types a single value found in the index (`detect("Sofacy")` ->
  threat_actor 'APT28'); an explicit `@handle` or `user:` prefix stays a username.
* `v3lum.core.ioc.extract()` types aliases in free text only when the name is distinctive
  (digits, all caps of 5+ letters, CamelCase, multi-word Title Case) or a CTI cue (malware,
  ransomware, loader, stealer, APT, ...) appears in the same sentence; ordinary product and
  platform words (Telegram, Python, Update, ...) are never typed from free text.
* Problems are collected by `v3lum.core.ioc.alias_errors()`; `reload_aliases(extra_dirs)` re-reads
  the fragments (plus a test's tmp directory) and `reload_aliases()` restores the bundled set.
* A batch adds its own fragment file and never edits another package's file.
