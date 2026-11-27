# eu_vies fixtures (batch p3-G10-1, P225)

VIES REST answers (`ec.europa.eu/taxation_customs/vies/rest-api/ms/{CC}/vat/{number}`), always HTTP 200:

* live 2026-11-26: `valid_lu.json` (LU26375245, a legal entity S.A R.L.), `valid_cz.json` (CZ00177041, a.s.,
  answered after 11 s while check-status said CZ was unavailable), `invalid.json` (isValid false + INVALID),
  `invalid_input_in_200.json` (INVALID_INPUT).
* synthetic, on the live envelope: `ms_unavailable_in_200.json` (MS_UNAVAILABLE, the body P225 cond 6 asks for),
  `rate_limited_in_200.json` (MS_MAX_CONCURRENT_REQ), `valid_sole_trader_synthetic.json` (a name without a
  legal-entity form, documentation address) and `valid_name_withheld.json` (name '---').
