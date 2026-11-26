# DoH fixtures (P029)

Trimmed DNS-over-HTTPS JSON answers recorded live on 2026-11-25/26 from a datacenter egress by the
research sweep (`research/samples/`, records C0003 and the DNSBL probes). Only public DNS data of
benign domains (example.com, github.com, google.com, cloudflare.com, IANA test points) is kept;
upstream resolver IPs in `Comment` were dropped except in `live_cti__doh_google_aaaa.json`, which
keeps one to show that `Comment` is ignored on NOERROR answers. `live_cti__doh_google_txt.json`
keeps 3 of the 24 TXT records.

| file | resolver | what it exercises |
| --- | --- | --- |
| `caipora_infra__doh_google_mx.json` | google | null MX `0 .`, AD flag |
| `caipora_infra__doh_cloudflare_txt.json` | cloudflare | quoted TXT (Cloudflare style) |
| `design_email_posture_doh.json` | both | trimmed design record (CAA list, MX, DMARC/MTA-STS, AD) replayed as answers |
| `live_cti__doh_google_a_dnssec.json` | google | A with RRSIG in the answer (filtered), AD |
| `live_cti__doh_cloudflare_a_ad.json` | cloudflare | A, AD |
| `live_cti__doh_cloudflare_mx.json` | cloudflare | MX |
| `live_cti__doh_google_aaaa.json` | google | AAAA, `Comment` |
| `live_cti__doh_google_caa.json` | google | CAA |
| `live_cti__doh_google_dmarc.json` | google | DMARC TXT (unquoted, Google style) |
| `live_cti__doh_google_ds.json` | google | DS, AD |
| `live_cti__doh_google_https_rr.json` | google | HTTPS (SVCB) record |
| `live_cti__doh_google_mtasts.json` | google | MTA-STS TXT |
| `live_cti__doh_google_mx.json` | google | MX |
| `live_cti__doh_google_ns.json` | google | NS set |
| `live_cti__doh_google_nxdomain.json` | google | a non-existent name under a Cloudflare zone: **NOERROR/NODATA**, not NXDOMAIN |
| `live_cti__doh_google_ptr.json` | google | PTR |
| `live_cti__doh_google_soa.json` | google | SOA |
| `live_cti__doh_google_txt.json` | google | TXT verification tokens and SPF |
| `caipora_infra__dnsbl_spamhaus_via_public_resolver.json` | google | real `Status 3` NXDOMAIN with authority SOA (and why DNSBL never uses public resolvers: the listed test point reads NXDOMAIN) |
| `dnsbl_spamhaus_public_resolver.json` | cloudflare | Spamhaus refusal code `127.255.255.254` (open/public resolver) |
| `live_cti__dnsbl_uribl_test_cf.json` | cloudflare | URIBL refusal `127.0.0.1` |
| `live_cti__dnsbl_surbl_test_cf.json` | cloudflare | SERVFAIL with an EDE `Comment` list |

Tests: `tests/test_dns.py`, `tests/test_dns_hardening.py`.
