# github_user fixtures (batch p1-G05-1, P111)

Trimmed fixtures for `tests/modules/test_github_user.py`. `*.http.json` files are envelopes
`{status, headers, body}`; the other files are raw bodies.

**P111 cond 10 is still open**: api.github.com and github.com user paths were refused by the research
egress proxy on 2026-11-25/26 (HTTP 403 "sessions are bound to their configured repositories", captured
in `blocked_proxy.http.json`), so the GitHub bodies below are DOC-SHAPED (GitHub REST v2022-11-28 field
layout with documentation values) and must be recaptured from the team network before the module enters
the default set (see docs/backlog/p1-G05-1.md).

| file | provenance |
|---|---|
| `user_ok.json`, `org_ok.json` | DOC-SHAPED (User / Organization; the org e-mail is a system address) |
| `events_ok.json`, `events_empty.json` | DOC-SHAPED: legacy PushEvent with commits (seed, noreply, third party, system), trimmed PushEvent, PR/Issue/Create/Watch/Fork |
| `commits_ok.json`, `commits_empty.json`, `commits_repo_empty.http.json` (409) | DOC-SHAPED; commit layout of the real research search-commits sample |
| `keys_ok.txt` | REAL public data: GitHub's own published SSH host keys (fingerprints documented by GitHub) |
| `keys_with_comments.txt`, `keys_empty.txt`, `keys_not_found.http.json` | format-shaped / DOC-SHAPED |
| `gpg_ok.txt` | GENERATED throwaway public keys (Ed25519+Cv25519 with a noreply UID; RSA-2048), private halves deleted; fingerprints cross-checked with GnuPG 2.4.4 |
| `gpg_empty.txt`, `gpg_malformed.txt` | DOC-SHAPED (wording unverified) / corrupted copy |
| `patch_ok.txt`, `patch_html.html` | DOC-SHAPED (RFC 2047 author, Co-authored-by) / HTML instead of a patch |
| `not_found.http.json`, `rate_limited.http.json`, `secondary_rate_limited.http.json`, `bad_credentials.http.json` | DOC-SHAPED: 404; 403 with remaining 0 (60/h); 429 with Retry-After; 401 |
| `blocked_proxy.http.json` | REAL capture 2026-11-26 (egress proxy policy 403, not GitHub): blocked, never absent |
| `html_instead_of_json.html` | DOC-SHAPED GitHub "Unicorn" page (error in 200, marker `github_user_html_instead_of_data`) |
| `token_classic_scoped.http.json`, `token_classic_noscope.http.json` | DOC-SHAPED /rate_limit answers (P111 cond 4 doctor check) |
| `rate_limit_ok.json` | REAL research capture of /rate_limit (minimised) |

No personal data: every address and name is a documentation value (example.com/.org/.net).
