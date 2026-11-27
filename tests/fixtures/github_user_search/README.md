# github_user_search fixtures (batch p1-G05-1, P111 cond 2)

| file | provenance |
|---|---|
| `ok.json` | REAL research capture 2026-11-25 of /search/users (q=octocat), minimised; logins other than GitHub's own `octocat` replaced by documentation values |
| `empty.json` | DOC-SHAPED empty search |
| `incomplete.json` | DOC-SHAPED from the real capture: `incomplete_results` true |
| `rate_limited.http.json` | DOC-SHAPED search 403 (10/min keyless, `x-ratelimit-resource: search`) |
| `validation_failed.http.json` | DOC-SHAPED 422 |

The GitHub search API was reachable only through the research proxy (which injected a token), so the
anonymous 10/min behaviour is not verified yet (P111 cond 10 recapture).
