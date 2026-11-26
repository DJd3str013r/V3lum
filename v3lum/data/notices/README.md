# Third-party notice fragments (`v3lum.notice/1`)

Module contract v2, section 19. Every piece of third-party material V3LUM ships or downloads at run
time - adapted code, bundled data, runtime-downloaded datasets, marker lists ported from other
tools - has one notice fragment here, added in the same change that brings the material in. The
notices registry (wave 5, WP29: `python -m v3lum.tools.notices`) builds `THIRD_PARTY_NOTICES.md`
and `v3lum/data/NOTICE` from these files; the registry contract test checks that every fragment
parses.

## File

`v3lum/data/notices/<name>.json`, one per notice; `<name>` matches `^[a-z0-9][a-z0-9_.-]{0,63}$` and
equals the `name` field.

```json
{
  "schema": "v3lum.notice/1",
  "name": "maigret_sherlock_markers",
  "source_url": "https://github.com/soxoj/maigret",
  "version": "commit 0123abc (2026-11-25)",
  "sha256": "",
  "licence": "MIT",
  "attribution": "Error/WAF marker strings adapted from maigret (COMMON_ERRORS) and sherlock (WAFHitMsgs), MIT licence.",
  "bundled": true,
  "files": ["v3lum/core/http.py"]
}
```

| field | meaning |
|---|---|
| `schema` | always `v3lum.notice/1` |
| `name` | notice id (= file stem) |
| `source_url` | where the material comes from (https) |
| `version` | release, commit or download date of the copy used |
| `sha256` | digest of the bundled file when one file is bundled as-is (`""` otherwise) |
| `licence` | SPDX id (`MIT`, `BSD-3-Clause`, `Apache-2.0`, `CC0-1.0`, `CC-BY-4.0`, `MPL-2.0`...) |
| `attribution` | the attribution text the licence requires |
| `bundled` | `true` when shipped inside the package, `false` for runtime downloads |
| `files` | repository paths that contain or use the material |

## Rules (A6)

* Adapted MIT/BSD/Apache code also carries a header comment in the source file: source URL, commit
  and licence. **Never** copy GPL/AGPL/LGPL code; GPL tools may only be studied as references.
* GPL, CC BY-SA and NC data are runtime downloads only (`bundled: false`), never bundled.
* One fragment per source; a later package adds its own file and never edits another package's.
