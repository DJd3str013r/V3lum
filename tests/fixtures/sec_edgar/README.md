# sec_edgar fixtures (batch p3-G10-1, P223)

Trimmed SEC EDGAR answers (U.S. Government work, public domain):

* `company_tickers_sample.json` - live 2026-11-26, 11 rows of www.sec.gov/files/company_tickers.json with their
  original index keys (GOOG/GOOGL and PBR/PBR-A share a CIK; Navient Holdings differs from NAVIENT CORP).
* `submissions_ok.json` - live data.sec.gov/submissions/CIK0000789019.json, trimmed to six filings (the 8-K of
  2024-01-19 and the 8-K/A of 2024-03-08 carry Item 1.05); addresses and phone removed.
* `submissions_no_cyber.json` - research capture without any Item 1.05 filing; `submissions_truncated.txt` - a
  derived truncated body (must be ERROR).
* `efts_ok.json` - live EFTS `"Microsoft" "Item 1.05" OR "cybersecurity incident"`, 7 of 73 hits;
  `efts_mentions.json` - research capture of other registrants' Item 1.05 8-Ks; `efts_empty.json` - live
  no-hit answer; `efts_parentheses_literal.json` - live proof that parentheses become literal phrases.
* `blocked_403.http.json` - live Akamai 403 'Request Rate Threshold Exceeded' page served to an undeclared tool UA.
