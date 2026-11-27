# wikidata fixtures (batch p3-G10-1, P224)

Wikidata is CC0.

* `wbsearchentities_ok.json` - research + live assembly 2026-11-26 for "Banco do Brasil": a listed building and an
  archive item (exact alias/label, not organisations) and the bank Q610817 (pageid of the assembled entry is a placeholder).
* `sparql_claims_ok.json` - live answer of the fixed claims template for those three candidates (only Q610817 is
  an organisation; P856 https://www.bb.com.br/, P355 Banco do Brasil Americas; no P6204).
* `sparql_domain_derived.json` - the shape of the domain template answer derived from the live values.
* `rate_limited_envoy.http.json`, `rate_limited_varnish.http.json` (live) and `rate_limited_wbgetclaims.http.json`
  (research): 429 answers of the API gateway and the edge.
* `api_error_in_200.json`, `sparql_timeout.http.json`, `wbsearchentities_empty.json` and the `*_synthetic.json`
  files are synthetic (documentation values, Q999999xx ids, example.com/example.org sites, the classic example CNPJ).
