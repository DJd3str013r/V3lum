# uk_companies_house fixtures (batch p3-G10-1, P227)

* `search_nokey.http.json` - live 2026-11-26: keyless `GET /search/companies?q=google` answers 401
  `{"error":"Empty Authorization header","type":"ch:service"}`.
* `search_ok.json`, `company_ok.json`, `officers_ok.json`, `psc_ok.json`, `company_not_found.http.json`,
  `rate_limited.http.json` - **placeholders in the documented Companies House API shapes** with documentation
  values only (EXAMPLE names, 0000000x numbers, example addresses). Research captured nothing with a key; P227
  cond 6 requires trimmed real captures made with the team key: replace these before the module is enabled.
  The officer/PSC bodies keep date of birth, nationality and address fields on purpose, to prove the parser drops them.

Companies House data: Open Government Licence v3.0.
