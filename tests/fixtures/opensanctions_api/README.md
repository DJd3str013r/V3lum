# opensanctions_api fixtures (batch p3-G10-1, P222)

* `api_nokey.http.json` - live 2026-11-26: keyless `GET /search/default` answers 401 `{"detail":"No API key provided."}`.
* `match_ok.json`, `match_empty.json`, `quota_429.http.json`, `match_invalid_422.http.json` - **synthetic
  placeholders** in the documented yente shapes (documentation values only). P222 cond 9 requires a success
  capture made with the company's licensed key before the module is enabled: replace them then.
