# HTTP classifier fixtures (WP03, P321/P326/P145)

Trimmed response bodies used by `tests/test_http_classify.py`, `tests/test_http_profiles.py`,
`tests/test_scoped_http.py` and `tests/test_redaction.py`. Every random token, nonce, Ray ID, request
id and egress IP was replaced by `TRIMMED` or a TEST-NET address (192.0.2.0/24, 203.0.113.0/24); no
personal data is kept.

`stub_transport.py` holds the test doubles of these tests (a scripted one-hop `Transport`, a fake
clock and an injectable provider registry builder).

## Real research samples, trimmed

| fixture | research sample | expected |
|---|---|---|
| `cloudflare_challenge.html` | `live_cti__ipapi_co_403.html` (403 "Just a moment...") | blocked / challenge |
| `cloudflare_block.html` | `live_cti__talos_ip_blacklist_403.txt` (403 "Attention Required! \| Cloudflare") | blocked / challenge |
| `vercel_checkpoint.html` | `tmp_caipora_infra/bodies/p_spur.body` (Vercel Security Checkpoint) | blocked / challenge |
| `isc_blockme.html` | `live_cti__isc_ipdetails.html` (final URL `/blockme.html`) | blocked / challenge |
| `cloudfront_503_not_geo.html` | `lists_global__intercept_weekly_sample.txt` (CloudFront 503 Lambda error) | not a geo-block (5xx error) |
| `normal_200_awswaf_sdk.html` | `tmp_caipora_br_gov/bodies/transp_busca.body` (Portal da Transparencia search page, HTTP 200, embeds the AWS WAF JS SDK and reCAPTCHA v3) | not blocked (weak-marker regression) |
| `hackertarget_quota_exceeded.txt` | `caipora_infra__hackertarget_quota_exceeded.txt` | quota |
| `criminalip_nokey.json` | `live_cti__criminalip_nokey.json` | error |
| `ipqs_nokey.json` | `live_cti__ipqs_nokey.json` | error |
| `etherscan_nokey.json` | `caipora_apis_cti__etherscan_v2_nokey.json` | error |
| `checkphish_nokey.json` | `live_cti__checkphish_nokey.json` (support address removed) | error |
| `hunter_how_nokey.json` | `live_cti__hunter_how_nokey.json` | error |
| `tcu_certidoes_indisponivel.json` / `tcu_certidoes_ok.json` | `brgov__tcu_certidoes.json` (public company 00.000.000/0001-91) | error / usable |
| `receitaws_ok.json` | `brgov__receitaws.json` (public company, trimmed to five fields) | usable |
| `abusech_browser_check.html` | `tmp_caipora_infra/bodies/p_mb_sample.body` (MalwareBazaar web UI, HTTP 200 after a redirect to `/verify-ua/`; URLhaus and ThreatFox serve the same page) | blocked / challenge |
| `domaintools_captcha.html` | `tmp_caipora_infra/bodies/p_domaintools.body` (whois.domaintools.com, HTTP 200 "Whois Lookup Captcha") | blocked / challenge |
| `netcraft_challenge.html` | `tmp_caipora_infra/bodies/p_netcraft_dns.body` (searchdns.netcraft.com JS challenge, HTTP 200, unchanged) | blocked / challenge |
| `facebook_rd_challenge.html` | `tmp_caipora_people/bodies/fb_ads_library.body` (Ad Library HTTP 403 `executeChallenge()` page; verify token removed) | blocked / challenge |
| `reddit_network_security_block.html` | `tmp_caipora_people/bodies/reddit_about.body` (HTTP 403; the message sits after ~190 KB of inline CSS, trimmed here and padded back by the test) | blocked / challenge (tail scan) |
| `cloudflare_custom_block.html` | `tmp_caipora_infra/bodies/entrust_ct2.body` (HTTP 403 Cloudflare custom WAF rule page; ray id and beacon token removed) | blocked / challenge |

## Reconstructions (no research sample of the page itself)

The sweeps recorded these vendors only as marker strings (maigret COMMON_ERRORS, sherlock WAFHitMsgs)
or as documented error shapes; the fixtures rebuild the minimal page/body carrying those markers.

| fixture | basis | expected |
|---|---|---|
| `aws_waf_challenge.html` | sherlock `AwsWafIntegration.forceRefreshToken`, AWS WAF challenge interstitial (`window.gokuProps`) | blocked / challenge |
| `perimeterx_block.html` | `px-captcha` block page | blocked / challenge |
| `incapsula_block.html` | maigret `Incapsula incident ID`, `_Incapsula_Resource?CWUDNSAI` iframe | blocked / challenge |
| `ddos_guard_challenge.html` | maigret `<title>DDoS-Guard</title>` | blocked / challenge |
| `captcha_page.html` | weak captcha words (`g-recaptcha`, "verify you are human") | blocked on 403, usable on 200 |
| `cloudfront_geo_block.html` | CloudFront geo-restriction page (same template as the real 503 sample) | blocked / geo_block |
| `akamai_access_denied.html` | Akamai "Access Denied ... Reference #" page (entity-encoded like the real ones) | blocked / geo_block |
| `linkedin_authwall.html` | body served at `linkedin.com/authwall` | blocked / login_wall (by final URL) |
| `leak_lookup_error.json` | research note "Leak-Lookup missing key = HTTP 200 with error:true" | error |
| `receitaws_error.json` | ReceitaWS documented error shape `{"status": "ERROR", "message": ...}` | error |
| `json_api_with_page_titles.json` | an API answer carrying challenge page titles as data | usable (fingerprints never apply to JSON) |
| `hudsonrock_stealer_synthetic.json` | Hudson Rock `search-by-email` shape with synthetic values | sanitized or not stored |
| `incapsula_js_challenge.html` | the near-empty noindex page that only loads `/_Incapsula_Resource?SWJIYLWA=...` (Incapsula JS challenge) | blocked / challenge |
| `incapsula_normal_page.html` | a normal page behind Incapsula, which loads the same script (weak-marker regression) | usable |
