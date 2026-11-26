# Social platform fragments (`v3lum.platforms/1`)

`entities.SOCIAL_PLATFORMS` is the core set (`core.json`, owned by WP05) merged with every other
`*.json` fragment in this directory, so batches add platforms **without editing `entities.py`**.
`social_account` entities (`'<platform>:<handle>'`) accept merged platforms only, and
`entities.platform_for_url(url)` maps a profile URL to `(platform, handle)` (used by WP17 detection).

```json
{
  "schema": "v3lum.platforms/1",
  "platforms": {
    "mastodon_social": {
      "title": "mastodon.social",
      "aliases": [],
      "profile_url_patterns": ["https://mastodon.social/@{handle}"],
      "reserved_handles": ["about", "explore"]
    }
  }
}
```

Rules (violations are listed by `entities.platform_errors()`, never raised):

* one file per batch (`<batch_or_package>.json`); `core.json` is loaded first, then the others in name
  order;
* platform names match `^[a-z][a-z0-9_]{0,31}$` (the core `x` is a single letter); aliases `^[a-z][a-z0-9_.-]{0,31}$` and must not belong to
  another platform (e.g. `twitter` is an alias of `x`);
* `profile_url_patterns` are URL templates `https://<host>/<path>{handle}[suffix]` with exactly one
  `{handle}` (never regular expressions): the host must be exact (`www.`, `m.`, `mobile.` and `web.`
  prefixes are ignored when matching), the URL query and fragment are ignored, and a trailing slash is
  optional. Handles match `[A-Za-z0-9_.-]{1,64}` and are lower-cased;
* `reserved_handles` lists path words that are not profiles on that platform (`p`, `explore`, ...); a
  global list (login, signup, settings, search, ...) always applies;
* re-declaring an existing platform only **adds** aliases, patterns and reserved handles (the first title
  wins; the merge is listed for review).

Matching is offline and static: profile URLs are parsed, never fetched. A matched handle is a weak
identity signal (same handle does not prove the same person) and `social_account` is a PERSONAL_TYPES
entity: never auto-expanded and never sent to unknown-tier providers (A8).

Tests may load a temporary fragment with `entities.reload_platforms(extra_dirs=[tmp_path])` and restore
the bundled set with `entities.reload_platforms()`.
