# Active dataset pins (`v3lum.active_lock/1`)

Datasets that drive LIGHT/ACTIVE behaviour (wordlists, takeover fingerprints, nuclei template sets...)
are registered with `register_dataset(..., active=True)` and are **pinned**: `ctx.data` serves them
only while the SHA-256 of the local copy matches a pin, and only `v3lum data update` installs or
refreshes them - never in the middle of an engagement (A6, A7, AR10).

## Bundled pins: `v3lum/data/active_locks/<name>.json`

One file per dataset, named after the dataset (`<name>` = the registered dataset name):

```json
{
  "schema": "v3lum.active_lock/1",
  "name": "takeover_fingerprints.json",
  "sha256": "<64 hex: SHA-256 of the stored file (or of the downloaded body for archives)>",
  "url": "https://raw.githubusercontent.com/<owner>/<repo>/<commit>/fingerprints.json",
  "commit": "<upstream commit or release tag the hash was taken from>",
  "reason": "why this version was reviewed and accepted (reviewer, date)"
}
```

Rules:

* `schema` must be `v3lum.active_lock/1` and `name` must equal the file stem; anything else is ignored.
* Prefer commit-pinned URLs so the pinned bytes stay downloadable.
* A pin is a review decision: the PR that changes it records who reviewed the new version.

## Analyst-accepted pins: `~/.v3lum/datasets/active.lock`

When an active dataset changes upstream, `DataStore.update(name)` downloads and validates it, stages
it under `~/.v3lum/datasets/.pending/<name>` and returns `needs_accept` with a diff summary
(`sha256 old -> new: +N / -M lines`). Accepting it (`update(name, accept_new=True)`, optionally with
the reviewed `expect_sha256`) installs exactly the staged bytes and records the decision (0600). A
change is never accepted blind: `accept_new=True` without a staged copy stages it and returns
`needs_accept` first, unless the reviewed `expect_sha256` matches the downloaded bytes.

```json
{
  "schema": "v3lum.active_lock_user/1",
  "datasets": {
    "<name>": {
      "sha256": "<accepted hash>",
      "url": "<redacted source URL>",
      "accepted_at": "2026-11-26T12:00:00Z",
      "previous_sha256": "<hash it replaced>",
      "diff_summary": "sha256 1a2b3c4d5e6f -> 7a8b9c0d1e2f: +12 / -3 lines (980 -> 989)"
    }
  }
}
```

An active dataset is usable when its hash matches the bundled pin **or** the accepted user pin.
`datasets.pins_for(name)` lists both.
