# icij_offshore_api fixtures (batch p3-G10-1, P221)

Answers of the ICIJ Offshore Leaks reconciliation API (`POST https://offshoreleaks.icij.org/api/v1/reconcile`):

* `reconcile_typed_ok.json` - live 2026-11-26, entity-typed query "Banco do Brasil" (HTTP 201, 5 Entity
  candidates; the best one, "Banco Industrial do Brasil S.A.", scores below the 0.90 matcher).
* `reconcile_weak_only.json` - live, "Qwzx Vrklm Example Nonexistent Holdings": 5 weak candidates (ICIJ never
  answers 'no candidate' while a token overlaps).
* `reconcile_empty.json` - live, nonsense tokens: `{"q0": {"result": []}}`.
* `reconcile_untyped_mixed.json` - research capture of an untyped query, trimmed to 6 of 25 candidates
  (Entity and Intermediary nodes; the node named after natural persons was removed).
* `reconcile_manifest.json` - live GET of the OpenRefine service manifest.
* `reconcile_truncated.txt` - the typed answer cut mid-way (derived): must be ERROR, never EMPTY.
* `web_search_challenge.http.json` - research: the web search page answers 202 with `x-amzn-waf-action:
  challenge` and an empty body; it is never fetched (cond 7) and the same answer on the API host is could-not-verify.

Contains information from the ICIJ Offshore Leaks Database (ODbL database, CC BY-SA contents).
