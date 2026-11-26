# case_sightings fixtures

Synthetic stored cases (schema `v3lum.case/2`, trimmed to the keys the case DB reads) used by
`tests/modules/test_case_sightings.py` and `tests/test_sightings.py`: documentation domains and
addresses only (`*.example`, `203.0.113.0/24`), a benign test hash (EICAR SHA-256) and the
documentation address `victim@example.com`. No real case, person or indicator.

| file | case | what it exercises |
|---|---|---|
| `earlier_case_amber.json` | TLP:AMBER passive case, verdict `malicious` on `recurrent-c2.example` | visible at AMBER and above, counted only from GREEN/CLEAR |
| `earlier_case_strict.json` | TLP:AMBER+STRICT passive case | counted only from AMBER and below |
| `earlier_case_red.json` | TLP:RED passive case | never surfaces below RED |
| `earlier_case_engagement.json` | TLP:AMBER LIGHT engagement case | never surfaces below AMBER |
