# Breach and infostealer fixtures (WP09, P145 golden tests)

Inputs of `tests/test_sanitize.py`. Each file keeps the **shape** of a real provider answer recorded
during the research sweep (samples in the research scratchpad, verified 2026-11-25/26) and replaces
every value that could identify a person or a machine with synthetic data: documentation IPs
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), `*.example` hosts, `someone@example.com`, invented
computer names, paths, masked hints and passwords. Nothing here was copied from a real breach record.

| fixture | research sample (shape only) | what the golden test checks |
|---|---|---|
| `hudsonrock_search_by_email.json` | `hudsonrock_search_by_email_test_example.json`, `live_osint__hudsonrock_username.json` | computer names, victim IPs, malware paths, masked passwords/logins never reach the cache, the result or the evidence; dates, families and service counts are kept |
| `leakcheck_public.json` | `leakcheck_public_test_example.json` | breach names, dates and data classes ('password' as a data-class *value*) are kept |
| `leakcheck_api_v2.json` | LeakCheck API v2 documentation shape | plaintext password, MD5 next to the e-mail, the combo `line` and usernames are dropped |
| `xposedornot_check_email.json` | `xposedornot_check_email_test_example.json` | breach list kept |
| `xposedornot_breach_analytics.json` | `live_osint__xposedornot_breach_analytics.json` | `password_risk` becomes `password_form` ('hashed: weak', 'plaintext'); `passwords_strength` is dropped by the second net |
| `hibp_breachedaccount.json` | `hibp_breach_single.json`, `hibp_breaches_by_domain.json` (public breach metadata of Adobe) plus one synthetic breach | data classes kept, descriptions outside the schema dropped |
| `exposed_env.txt` | synthetic `.env` of an exposed web application | passwords dropped (never hashed), keys/tokens/private keys masked as type + first 4/last 4 + SHA-256, URL credentials dropped |

The AWS values in `exposed_env.txt` are the documentation examples published by AWS
(`AKIAIOSFODNN7EXAMPLE`); the private-key block is base64 of the text "SYNTHETIC KEY FOR TESTS ONLY
NOT A REAL KEY". Tokens that secret scanners match by format are built at test time instead of being
stored here.
