# Research catalogue

Every tool, API, dataset and pivot site found during the research phase (800 unique candidates from 12 sweeps: the caipora.pro catalogue, GitHub tools (read for useful code, never vendored), awesome lists, the Céos design and live API checks on 2026-11-25/26), with the proposal that covers it and the Council #1 outcome. Status = what the live check saw from a datacenter egress (`verified_live`, `verified_needs_key`, `unverified`, `error`, `dead`).

- status: {'verified_live': 502, 'unverified': 152, 'verified_needs_key': 101, 'error': 35, 'dead': 10}
- kind: {'api': 392, 'offline_lib_or_algorithm': 139, 'dataset_download': 129, 'scrape': 21, 'url_template': 119}

## Domains & DNS (81)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0001 | azmap.dev Microsoft 365 tenant domain map | api | none | verified_live | Third-party service, no published terms found. bbot module is AGPL-3.0 -> reimplement, ... | P011 `m365_tenant` approved |
| C0002 | crt.sh CT search (JSON) | api | none | verified_live | [caipora_infra] Free public service; data from public CT logs ‖ [gh_infra] Free public ... | P001 `ct_logs` approved |
| C0003 | DNS-over-HTTPS resolver layer (Google + Cloudflare JSON) | api | none | verified_live | [caipora_infra] Free public resolvers (Google/Cloudflare terms) ‖ [design_ceos] Google ... | P029 `doh_resolver_hardening` approved |
| C0004 | dnstwist scanner: registration check + MX-spy + LSH/pHash page simi... | offline_lib_or_algorithm | none | unverified | Apache-2.0 | P025 `typosquat_live_checks` approved |
| C0005 | E-mail security posture (SPF lookup count, DMARC, DKIM selectors, M... | offline_lib_or_algorithm | none | verified_live | [caipora_infra] n/a (own code) ‖ [caipora_people] Cloudflare/Google public resolver ter... | P002 `email_security_posture` approved |
| C0006 | RDAP (rdap.org redirector + IANA bootstrap) | api | none | verified_live | [caipora_infra] Free; registry ToS apply; contact data mostly redacted (GDPR) ‖ [gh_inf... | P003 `rdap` approved |
| C0007 | Typosquat / brand-impersonation permutation engine (dnstwist algori... | offline_lib_or_algorithm | none | verified_live | [design_ceos] Apache-2.0: fuzzer code may be adapted with attribution ‖ [gh_infra] Apac... | P012 `typosquat` approved |
| C0008 | Cert Spotter issuances API | api | none | verified_live | [caipora_infra] SSLMate commercial service with free tier ‖ [gh_infra] SSLMate API term... | P001 `ct_logs` approved |
| C0009 | CertStream real-time Certificate Transparency firehose | api | none | verified_live | [caipora_cli] certstream-server (MIT) - public instance best-effort; self-host certstre... | P030 `watch_mode` approved |
| C0010 | CIRCL Passive DNS | api | login_required | verified_needs_key | Free for CSIRTs/security teams on request (CIRCL terms; TLP handling). | P015 `passive_dns` approved |
| C0011 | Domain ownership verifier (company + person) via RDAP, homepage and CT | offline_lib_or_algorithm | none | unverified | team-owned | P013 `domain_ownership` approved |
| C0012 | HackerTarget free API (host search, reverse IP, DNS, ASN) | api | free_key | verified_live | [caipora_infra] HackerTarget free API terms ‖ [gh_infra] HackerTarget ToS; free tier fo... | P014 `hackertarget` approved |
| C0013 | host.io API (domain relations) | api | free_key | verified_needs_key | host.io terms | P004 `hostio` approved |
| C0014 | IANA RDAP bootstrap registries | dataset_download | none | verified_live | IANA public data | P003 `rdap` approved |
| C0015 | mnemonic PassiveDNS v3 | api | none | verified_live | [gh_cti_ioc] Mnemonic public pDNS terms (TLP:WHITE data). ‖ [gh_infra] mnemonic public ... | P015 `passive_dns` approved |
| C0016 | ProjectDiscovery Chaos dataset API | api | free_key | verified_needs_key | ProjectDiscovery ToS | P007 `subdomains_keyed` approved |
| C0017 | SecurityTrails API | api | free_key | verified_needs_key | [caipora_infra] SecurityTrails (Recorded Future) terms ‖ [gh_infra] SecurityTrails ToS ... | P006 `securitytrails` approved |
| C0018 | Shodan CT hostnames (ctl.shodan.io) | api | none | verified_live | Shodan public CT service, no key; Shodan ToS apply | P001 `ct_logs` approved |
| C0019 | SPF/MX/DMARC record mining -> netblocks & third-party providers | offline_lib_or_algorithm | none | unverified | Re-implementation (recon-ng is GPL-3.0: idea only) | P002 `email_security_posture` approved |
| C0020 | THC subdomain / rDNS database (ip.thc.org) | api | none | verified_live | Free community service by THC; no formal ToS | P016 `subdomains_passive` approved |
| C0021 | Validin API (passive DNS, host responses, certificates) | api | free_key | error | [caipora_apis_cti] Validin ToS (community API key on registration). ‖ [live_cti] Validi... | P017 `validin` approved |
| C0022 | WhoisDS newly registered domains (daily list) | dataset_download | none | verified_live | WhoisDS free NRD list terms (paid DB for full WHOIS) | P005 `nrd_feeds` approved |
| C0023 | AnubisDB subdomains | api | none | verified_live | Free community DB | P016 `subdomains_passive` approved |
| C0024 | BeVigil OSINT (mobile-app derived subdomains/URLs) | api | free_key | verified_needs_key | [caipora_infra] BeVigil terms ‖ [gh_infra] BeVigil ToS | P007 `subdomains_keyed` approved |
| C0025 | cl0q domain search engine (favicon-hash / tech / ASN pivots) | api | free_key | verified_needs_key | cl0q terms (free API tier). | P018 `cl0q` approved |
| C0026 | crt.name CT index | api | none | verified_live | Free service | P001 `ct_logs` approved |
| C0027 | DNSDumpster API | api | free_key | verified_needs_key | [gh_infra] DNSDumpster ToS ‖ [live_cti] DNSDumpster terms (free account) | P007 `subdomains_keyed` approved |
| C0028 | dnstwister API (typosquat fuzzing + checks) | api | none | verified_live | Free public service (open-source project) | P012 `typosquat` approved |
| C0029 | FullHunt domain subdomains | api | free_key | verified_needs_key | [caipora_infra] FullHunt terms ‖ [gh_infra] FullHunt ToS | P007 `subdomains_keyed` approved |
| C0030 | Google Digital Asset Links API | api | none | verified_live | Google APIs ToS | P008 `digital_asset_links` approved; P346 `mobile_app_impersonation` approved |
| C0031 | gov.br official domain list | dataset_download | none | verified_live | Open government data | P009 `govbr_domains` approved |
| C0032 | MerkleMap CT search | api | free_key | verified_needs_key | MerkleMap ToS | P001 `ct_logs` approved |
| C0033 | Microsoft ODC federationprovider (tenant ID by domain) | api | none | verified_live | Public (undocumented) Microsoft Office endpoint. Technique from bbot (AGPL) -> reimplem... | P011 `m365_tenant` approved |
| C0034 | MxToolbox REST API lookups | api | none | verified_live | MxToolbox API terms | P019 `mxtoolbox_api` deferred |
| C0035 | myssl.com subdomain discovery API | api | none | verified_live | MySSL/TrustAsia service terms (not reviewed). Used by bbot (AGPL) and corptrace (AGPL) ... | P016 `subdomains_passive` approved |
| C0036 | Protective-DNS block check (Cloudflare Families, AdGuard, Quad9, Op... | api | none | verified_live | [caipora_cli] web-check MIT (resolver list + isBlocked logic portable). ‖ [gh_cti_ioc] ... | P020 `protective_dns` approved |
| C0037 | RapidDNS subdomain and same-IP search (HTML scrape) | scrape | none | verified_live | [caipora_infra] Scraping of public pages - check ToS before production use ‖ [gh_infra]... | P016 `subdomains_passive` approved |
| C0038 | Registro.br domains-in-release list | dataset_download | none | verified_live | Public registry notice | P005 `nrd_feeds` approved |
| C0039 | ScanMalware CT/hosts/SMQL | api | none | verified_live | Free service | P016 `subdomains_passive` approved |
| C0040 | smet.cz newly registered domains feed | dataset_download | none | verified_live | Unclear license - check before redistribution | P005 `nrd_feeds` approved |
| C0041 | Subdomain Center | api | none | verified_live | Free service, no formal ToS | P016 `subdomains_passive` approved |
| C0042 | Tranco domain popularity ranking | api | none | verified_live | Free; cite Le Pochat et al. (NDSS 2019) | P010 `tranco_rank` approved |
| C0043 | WhoisXML API family (WHOIS, history, reverse WHOIS, DNS, netblocks) | api | free_key | verified_needs_key | [caipora_infra] WhoisXML API terms ‖ [gh_infra] WhoisXML ToS | P022 `whois_history_keyed` approved |
| C0044 | Whoxy API (WHOIS, history, reverse WHOIS by email/name/company) | api | paid_key | verified_needs_key | Whoxy ToS. | P022 `whois_history_keyed` approved |
| C0045 | BufferOver TLS dataset | api | free_key | verified_needs_key | BufferOver ToS | P007 `subdomains_keyed` approved |
| C0046 | DomainsDB keyword domain search | api | free_key | verified_needs_key | DomainsDB terms | P005 `nrd_feeds` approved |
| C0047 | HackerTarget zone-transfer API (third-party AXFR) | api | none | verified_live | HackerTarget terms | P281 `axfr` approved |
| C0048 | jsmon subdomains | api | free_key | verified_needs_key | jsmon ToS | P007 `subdomains_keyed` approved |
| C0049 | OONI API (internet censorship measurements per domain/country) | api | none | verified_live | OONI open data (see ooni.org/data for license terms). | P023 `ooni` approved |
| C0050 | openSquat NRD feed + look-alike scoring (restricted feed) | dataset_download | none | error | openSquat AGPL-3.0 (ideas only); feed served only to the openSquat client. | P024 `reject_dead_domain_sources` rejected |
| C0051 | Registro.br domain availability API | api | none | verified_live | registro.br public web service | P021 `registrobr_domain_status` approved |
| C0052 | sub.md search | api | none | error | Unknown | P024 `reject_dead_domain_sources` rejected |
| C0053 | subdomain.app query API | api | none | verified_live | Free service | P016 `subdomains_passive` approved |
| C0054 | WhoisFreaks API | api | free_key | verified_needs_key | WhoisFreaks terms | P022 `whois_history_keyed` approved |
| C0055 | certificatedetails.com (Digitorus) | scrape | none | error | Unknown | P024 `reject_dead_domain_sources` rejected |
| C0056 | recon.cloud search | api | none | dead |  | P024 `reject_dead_domain_sources` rejected |
| C0057 | CompleteDNS nameserver history (pivot) | url_template | none | verified_live | site ToS | P026 `pivots_domain_dns` approved |
| C0058 | crt.sh lookup by certificate SHA-256 (pivot) | url_template | none | verified_live | [design_ceos] Sectigo crt.sh public service ‖ [live_cti] site terms | P026 `pivots_domain_dns` approved |
| C0059 | DNSViz DNSSEC analysis page | url_template | none | verified_live | [design_ceos] Sandia/Verisign Labs service ‖ [lists_global] Free service (DNSViz is GPL... | P026 `pivots_domain_dns` approved |
| C0060 | host.io domain page | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P026 `pivots_domain_dns` approved |
| C0061 | SecurityTrails web | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0062 | Whoxy WHOIS + history page | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P026 `pivots_domain_dns` approved |
| C0063 | CentralOps Domain Dossier | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0064 | Cloudflare Radar domain / ASN pages | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0065 | dmarcian DMARC Inspector (pivot) | url_template | none | verified_live | dmarcian terms | P026 `pivots_domain_dns` approved |
| C0066 | DNSlytics search pages | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0067 | DomainTools Whois / Reverse IP | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P026 `pivots_domain_dns` approved |
| C0068 | dotDB keyword domain search | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0069 | intoDNS report | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P026 `pivots_domain_dns` approved |
| C0070 | MXToolbox SPF lookup (pivot) | url_template | none | verified_live | MXToolbox terms | P026 `pivots_domain_dns` approved |
| C0071 | Verisign DNSSEC Debugger page | url_template | none | verified_live | Free Verisign Labs tool. | P026 `pivots_domain_dns` approved |
| C0072 | Who.is WHOIS page | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P026 `pivots_domain_dns` approved |
| C0073 | Whois.com lookup page | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P026 `pivots_domain_dns` approved |
| C0074 | ICANN Lookup | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0755 | Direct CT log polling (Google CT log list v3 + RFC 6962 get-sth/get... | api | none | verified_live | Public CT logs (RFC 6962, C2SP static-ct-api). | P030 `watch_mode` approved |
| C0756 | certstream-server-go (self-hosted CertStream-compatible server, MIT) | offline_lib_or_algorithm | none | verified_live | MIT (LICENSE verified). | P030 `watch_mode` approved |
| C0757 | ICANN CZDS gTLD zone files (daily zones per approved TLD, team acco... | dataset_download | free_key | verified_needs_key | CZDS terms of use (lawful use, no redistribution/resale of zone data). | P005 `nrd_feeds` approved |
| C0776 | IANA Registrar IDs registry (IANA id -> registrar name + RDAP base ... | dataset_download | none | verified_live | IANA registries (public). | P345 `takedown_packet` approved |
| C0785 | who-dat WHOIS/RDAP-over-HTTPS (normalised JSON; MIT; self-hostable) | api | none | verified_live | MIT (code); data from registries' RDAP/WHOIS. | P343 `whois_fallback` approved |
| C0786 | Direct port-43 WHOIS using the IANA root-zone WHOIS server per TLD | api | none | unverified | Registry WHOIS terms of use (no bulk queries, no marketing use). | P343 `whois_fallback` approved |
| C0796 | DNS TXT SaaS verification-token map (vendor prefixes -> SaaS in use) | offline_lib_or_algorithm | none | verified_live | Public DNS. | P342 `saas_verification_tokens` approved |

## IP & network (69)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0075 | RIPEstat Data API | api | none | verified_live | [caipora_infra] RIPEstat terms (free) ‖ [gh_infra] RIPE NCC Data API ToS (free) ‖ [live... | P031 `ripestat` approved; P345 `takedown_packet` approved |
| C0076 | Shodan InternetDB | api | none | verified_live | [caipora_infra] Shodan InternetDB terms: free, non-commercial use ‖ [design_ceos] Shoda... | P043 `shodan_internetdb` approved |
| C0077 | Team Cymru IP-to-ASN via DNS (DoH) | api | none | verified_live | [caipora_infra] Team Cymru free community service ‖ [live_cti] Team Cymru community ser... | P032 `team_cymru_asn` approved |
| C0078 | ARIN RDAP + Whois-RWS (nets, orgs, POCs) | api | none | verified_live | ARIN Terms of Use for Whois/RDAP | P003 `rdap` approved |
| C0079 | Censys Platform API (v3) | api | free_key | verified_needs_key | [caipora_infra] Censys terms ‖ [gh_infra] Censys ToS (free = non-commercial research) | P044 `censys` approved |
| C0080 | Cloud/CDN provider IP-range datasets | dataset_download | none | verified_live | [caipora_infra] Official public data from each provider ‖ [design_ceos] public provider... | P034 `cloud_ranges` approved |
| C0081 | cloudcheck consolidated cloud/CDN provider signatures | dataset_download | none | verified_live | Repository AGPL-3.0 (do not copy code). JSON is compiled from providers' public range f... | P034 `cloud_ranges` approved |
| C0082 | DB-IP Lite databases | dataset_download | none | verified_live | CC BY 4.0 (attribution to DB-IP required) | P047 `ip_offline_db` approved |
| C0083 | DNSBL checks (SpamCop, Spamhaus ZEN/DBL via DQS, DroneBL, UCEPROTEC... | api | none | verified_live | [caipora_infra] Each DNSBL's usage policy (most free for low-volume non-commercial; Spa... | P045 `dnsbl` approved |
| C0084 | IPinfo API (Lite / core) | api | free_key | verified_needs_key | IPinfo terms; Lite data CC BY-SA 4.0 (attribution) | P036 `ipinfo` approved |
| C0085 | IPLogs IP reputation / anonymizer check | api | none | verified_live | IPLogs terms (free). | P046 `ip_anonymizer_consensus` approved |
| C0086 | IPtoASN dataset | dataset_download | none | verified_live | PDDL (public domain) | P047 `ip_offline_db` approved |
| C0087 | Netlas | api | free_key | verified_live | [caipora_infra] Netlas terms ‖ [gh_infra] Netlas ToS | P037 `netlas` approved |
| C0088 | NIC.br ASN block list (AS -> owner -> CNPJ -> prefixes) | dataset_download | none | verified_live | Public NIC.br registry data | P038 `nicbr_asn` approved |
| C0089 | Registro.br RDAP (IP / ASN -> owner CNPJ) | api | none | verified_live | NIC.br RDAP terms | P003 `rdap` approved |
| C0090 | Robtex free API (IP, ASN, passive DNS) | api | none | verified_live | [caipora_infra] Robtex free API terms (non-abusive use) ‖ [gh_infra] Robtex free API te... | P015 `passive_dns` approved |
| C0091 | Shadowserver: public IP/ASN API + free network reports for own netb... | api | none | verified_live | Shadowserver free public benefit service; reports free for network owners/CSIRTs after ... | P033 `asn_context` approved |
| C0092 | Shodan REST API | api | free_key | verified_needs_key | [caipora_infra] Shodan API terms ‖ [live_cti] Shodan ToS; membership/API plans for comm... | P039 `shodan_api` approved |
| C0093 | Tor exit-node check (bulk exit list + Onionoo) | dataset_download | none | verified_live | [design_ceos] Tor Project public data (CC0/CC-BY per Tor metrics) ‖ [gh_infra] Tor Proj... | P040 `tor_relays` approved |
| C0094 | Tor Onionoo | api | none | verified_live | Tor Project (public data) | P040 `tor_relays` approved |
| C0095 | VPNDetection.io | api | none | verified_live | VPNDetection terms (free tier). | P046 `ip_anonymizer_consensus` approved |
| C0096 | Abusix abuse contact DB (DNS) | api | none | verified_live | Abusix contact DB free use. | P041 `abusix_contacts` approved; P345 `takedown_packet` approved |
| C0097 | bgp.tools asns.csv | dataset_download | none | verified_live | bgp.tools terms (free use, descriptive UA required) | P047 `ip_offline_db` approved |
| C0098 | CIRCL BGP Ranking | api | none | verified_live | [gh_cti_ioc] CIRCL open service. ‖ [live_cti] CIRCL (free) | P033 `asn_context` approved |
| C0099 | Criminal IP API | api | free_key | verified_needs_key | [caipora_infra] Criminal IP terms ‖ [gh_infra] Criminal IP ToS | P048 `criminalip` approved |
| C0100 | FOFA search | api | paid_key | unverified | FOFA ToS | P049 `fofa` approved |
| C0101 | FreeIPAPI | api | none | verified_live | free for commercial and non-commercial use (site) | P051 `ip_geolocation` approved |
| C0102 | InternetData.io IP intelligence | api | none | verified_live | InternetData terms (free tier). | P046 `ip_anonymizer_consensus` approved |
| C0103 | ip.guide | api | none | verified_live | free public service (terms not reviewed) | P051 `ip_geolocation` approved |
| C0104 | IP2Location.io geolocation API | api | none | verified_live | IP2Location.io terms | P051 `ip_geolocation` approved |
| C0105 | ipapi.is | api | free_key | verified_live | ipapi.is free tier terms | P046 `ip_anonymizer_consensus` approved |
| C0106 | IPHub proxy/VPN/hosting detection | api | free_key | verified_needs_key | IPHub terms | P050 `ip_anonymizer_keyed` deferred |
| C0107 | IPLocate.io | api | free_key | verified_live | IPLocate terms (free tier). | P046 `ip_anonymizer_consensus` approved |
| C0108 | IPQualityScore IP/URL reputation | api | free_key | verified_needs_key | IPQS terms | P052 `ipqualityscore` approved |
| C0109 | IPQuery.io | api | none | verified_live | IPQuery terms (free). | P046 `ip_anonymizer_consensus` approved |
| C0110 | ipwho.is | api | none | verified_live | free tier "commercial use allowed" (ipwhois.io pricing) | P051 `ip_geolocation` approved |
| C0111 | ONYPHE API | api | free_key | verified_needs_key | [caipora_infra] ONYPHE terms ‖ [gh_infra] Onyphe ToS | P042 `onyphe` approved |
| C0112 | Open-proxy / anonymizer reputation (FireHOL proxies ipset) | dataset_download | none | verified_live | FireHOL aggregation of third-party lists - each source keeps its own terms | P035 `ip_context_lists` approved |
| C0113 | PeeringDB API (ASN -> organisation, IXPs, facilities, policies) | api | none | verified_live | PeeringDB AUP (free; contact data restricted). | P033 `asn_context` approved |
| C0114 | proxycheck.io v2 | api | free_key | verified_live | proxycheck.io terms | P046 `ip_anonymizer_consensus` approved |
| C0115 | X4BNet VPN/datacenter IP ranges | dataset_download | none | verified_live | Check repo license | P035 `ip_context_lists` approved |
| C0116 | ZoomEye API | api | free_key | verified_needs_key | [caipora_infra] ZoomEye terms ‖ [gh_infra] ZoomEye ToS | P053 `zoomeye` approved |
| C0117 | Driftnet internet-scan API | api | free_key | unverified | Driftnet ToS | P054 `scan_engines_minor` deferred |
| C0118 | FraudGuard IP risk API | api | free_key | verified_needs_key | FraudGuard terms. | P050 `ip_anonymizer_keyed` deferred |
| C0119 | GeoJS IP geolocation (keyless) | api | none | verified_live | GeoJS free service (GeoLite-derived data; attribution appreciated). | P051 `ip_geolocation` approved |
| C0120 | hunter.how | api | free_key | verified_needs_key | hunter.how terms | P054 `scan_engines_minor` deferred |
| C0121 | KeyCDN IP location API | api | none | verified_live | KeyCDN tools terms | P051 `ip_geolocation` approved |
| C0122 | MaxMind GeoLite2 | dataset_download | free_key | verified_needs_key | [caipora_infra] GeoLite2 EULA (CC BY-SA 4.0 + EULA) ‖ [live_cti] GeoLite2 EULA (free ac... | P047 `ip_offline_db` approved |
| C0123 | BGPView API | api | none | dead |  | P055 `reject_dead_ip_sources` rejected |
| C0124 | BinaryEdge | api | paid_key | dead |  | P055 `reject_dead_ip_sources` rejected |
| C0125 | Focsec VPN/proxy/Tor detection | api | free_key | verified_needs_key | Focsec terms. | P050 `ip_anonymizer_keyed` deferred |
| C0126 | ip-api.com | api | paid_key | verified_needs_key | free tier NON-commercial only | P056 `reject_ip_api_com` rejected |
| C0127 | ipapi.co | api | none | error | ipapi.co terms | P055 `reject_dead_ip_sources` rejected |
| C0128 | Shodan host page / search | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0129 | bgp.he.net (Hurricane Electric BGP toolkit) | url_template | none | verified_live | [caipora_infra] Free web UI; provider ToS apply (manual analyst use) ‖ [gh_infra] HE si... | P057 `pivots_ip_network` approved |
| C0130 | Censys host page | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0131 | FOFA search | url_template | none | verified_live | [caipora_infra] Free web UI; provider ToS apply (manual analyst use) ‖ [design_ceos] FO... | P057 `pivots_ip_network` approved |
| C0132 | Criminal IP asset report page | url_template | none | verified_live | [caipora_infra] Free web UI; provider ToS apply (manual analyst use) ‖ [live_cti] site ... | P057 `pivots_ip_network` approved |
| C0133 | IPinfo ASN page | url_template | none | verified_live | [caipora_infra] Free web UI; provider ToS apply (manual analyst use) ‖ [live_cti] site ... | P057 `pivots_ip_network` approved |
| C0134 | Netlas host page | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0135 | Scamalytics IP fraud risk | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P057 `pivots_ip_network` approved |
| C0136 | Tor ExoneraTor | url_template | none | verified_live | site terms | P057 `pivots_ip_network` approved |
| C0137 | CIDR Report AS report page | url_template | none | verified_live | Free (APNIC/Geoff Huston CIDR Report). | P057 `pivots_ip_network` approved |
| C0138 | hunter.how search | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0139 | I Know What You Download (torrent activity per IP) | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P058 `pivot_iknowwhatyoudownload` rejected |
| C0140 | Myip.ms IP/hosting pages | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P057 `pivots_ip_network` approved |
| C0141 | Spur IP context | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0142 | ZoomEye search | url_template | none | error | Free web UI; provider ToS apply (manual analyst use) | P309 `reject_pivots_broken` rejected |
| C0794 | Apple iCloud Private Relay egress IP ranges (context tag privacy_re... | dataset_download | none | verified_live | Published by Apple for geolocation/allow-listing. | P035 `ip_context_lists` approved |

## URLs & websites (68)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0143 | urlscan.io search API | api | none | verified_live | [caipora_infra] urlscan.io terms ‖ [gh_infra] urlscan.io ToS | P066 `urlscan_search` approved; P347 `page_capture` approved |
| C0144 | Wayback Machine CDX API | api | none | error | [caipora_infra] Internet Archive terms of use ‖ [gh_infra] Internet Archive ToS (resear... | P059 `web_archives` approved; P287 `public_docs_discovery` approved |
| C0145 | Analytics / tag-manager / AdSense ID extraction and reverse lookup | offline_lib_or_algorithm | none | unverified | Regexes adapted from bellingcat/wayback-google-analytics (MIT, read) | P061 `analytics_ids` approved |
| C0146 | Common Crawl index server | api | none | error | Common Crawl terms of use (free) | P059 `web_archives` approved |
| C0147 | Google Safe Browsing Lookup API v4 | api | free_key | verified_needs_key | [caipora_infra] Safe Browsing API is for non-commercial use; commercial use = Web Risk ... | P067 `google_safe_browsing` approved |
| C0148 | HTTP security headers & cookie-flag audit (OWASP Secure Headers lists) | offline_lib_or_algorithm | none | verified_live | OWASP Secure Headers Project data: Apache-2.0 (vendor JSON with attribution). Note: htt... | P063 `security_headers` approved |
| C0149 | JS endpoint & secret extraction (LinkFinder regex + gitleaks rules) | offline_lib_or_algorithm | none | verified_live | [design_ceos] MIT (both) - adapt with attribution ‖ [gh_infra] MIT (copy regex with att... | P068 `js_endpoints` approved |
| C0150 | URL unshortening / redirect-chain tracer | offline_lib_or_algorithm | none | verified_live | Own code; ideas from WhereGoes, Redirect Detective, urlExpander (SMAPPNYU) rows | P070 `unshorten` approved |
| C0151 | Wayback historical-favicon hashing & content mining (chronos techni... | offline_lib_or_algorithm | none | unverified | chronos MIT (Go) - port logic. | P060 `archive_mining` approved |
| C0152 | Wayback Machine availability API (closest snapshot) | api | none | verified_live | Internet Archive terms of use | P059 `web_archives` approved |
| C0153 | waymore multi-archive URL harvesting + filters | offline_lib_or_algorithm | none | unverified | MIT (config.yml filter lists adaptable with attribution). | P060 `archive_mining` approved |
| C0154 | webappanalyzer technology fingerprints (Wappalyzer-format) | dataset_download | none | verified_live | [design_ceos] GPL-3.0 DATA (enthec/webappanalyzer and HTTPArchive/wappalyzer are both G... | P072 `web_fingerprint` approved |
| C0155 | Arquivo.pt CDX (Portuguese web archive) | api | none | verified_live | Arquivo.pt terms (public service, FCT Portugal) | P059 `web_archives` approved |
| C0156 | BuiltWith domain API | api | free_key | unverified | BuiltWith ToS | P073 `builtwith` approved |
| C0157 | BuiltWith Free API | api | free_key | verified_needs_key | BuiltWith terms | P073 `builtwith` approved |
| C0158 | CERT.PL Hole (warning list) | dataset_download | none | verified_live | [caipora_infra] CERT Polska terms ‖ [live_cti] CERT Polska public list | P071 `url_domain_blocklists` approved |
| C0159 | FLAGGED: xeuledoc public Google Docs owner metadata | api | none | unverified | AGPL-3.0. | P081 `reject_xeuledoc` rejected |
| C0160 | Google Transparency Report Safe Browsing status (unofficial) | api | none | verified_live | Undocumented internal endpoint behind the public Site Status page | P067 `google_safe_browsing` approved |
| C0161 | HaGeZi Threat Intelligence Feeds (TIF) | dataset_download | none | verified_live | GPL-3.0 (data) -> download at runtime, do not vendor | P071 `url_domain_blocklists` approved |
| C0162 | Historical robots.txt via Wayback (Robofinder technique) | offline_lib_or_algorithm | none | unverified | Technique from Spix0r/robofinder (MIT, read) | P060 `archive_mining` approved |
| C0163 | Mozilla HTTP Observatory API v2 (third-party header grade) | api | none | verified_live | [caipora_cli] Mozilla MDN Observatory public API (code MPL-2.0). ‖ [design_ceos] Mozill... | P076 `posture_third_party` approved |
| C0164 | Phishing.Database | dataset_download | none | verified_live | MIT | P071 `url_domain_blocklists` approved |
| C0165 | PhishStats API | api | none | verified_live | [caipora_infra] PhishStats terms (free) ‖ [gh_cti_ioc] PhishStats free API terms. | P074 `phishstats` approved |
| C0166 | PhishTank data dump | dataset_download | none | verified_live | [caipora_infra] PhishTank terms ‖ [live_cti] PhishTank (Cisco Talos) terms | P071 `url_domain_blocklists` approved |
| C0167 | Procon-SP "Evite estes sites" list | scrape | none | error | Public consumer-protection notice | P071 `url_domain_blocklists` approved |
| C0168 | QR/barcode decoding from images (quishing) | offline_lib_or_algorithm | none | unverified | OpenCV Apache-2.0 / pyzbar MIT (needs libzbar) | P261 `qr_decode` approved |
| C0169 | Qualys SSL Labs API v3 (cached TLS assessment) | api | none | verified_live | [caipora_cli] Free, subject to Qualys SSL Labs terms (stated in /info messages). API v4... | P076 `posture_third_party` approved |
| C0170 | robots.txt / sitemap.xml inventory | offline_lib_or_algorithm | none | verified_live | own code | P065 `wellknown_files` approved |
| C0171 | security.txt (RFC 9116) fetch & validation | offline_lib_or_algorithm | none | verified_live | [caipora_cli] Open standards; logic in web-check (MIT) security-txt.js / mail-config.js... | P065 `wellknown_files` approved |
| C0172 | spmedia Crypto Scam & Crypto Phishing feed | dataset_download | none | verified_live | MIT (Edmond Major III). | P071 `url_domain_blocklists` approved |
| C0173 | Sucuri SiteCheck API | api | none | verified_live | Sucuri (GoDaddy) free scanner | P078 `url_scanners_third_party` approved |
| C0174 | Target-website contact harvesting (emails, phones, social links) | scrape | none | unverified | theHarvester GPL-2.0 (ideas only) | P077 `site_contacts` approved |
| C0175 | unshorten.me JSON API | api | none | verified_live | unshorten.me terms | P070 `unshorten` approved |
| C0176 | urlDNA API (URL scans: screenshots, tech, phishing/brand impersonat... | api | free_key | verified_needs_key | [caipora_apis_cti] urlDNA ToS. ‖ [caipora_infra] urlDNA terms | P078 `url_scanners_third_party` approved |
| C0177 | Wayback Save Page Now (evidence preservation) | api | free_key | unverified | Internet Archive ToS; waybackpy MIT (not cloned). | P080 `reject_save_page_now` rejected |
| C0178 | Web-Check API (Lissy93/web-check, MIT) | api | none | verified_live | MIT license (code reusable with attribution) | P078 `url_scanners_third_party` approved |
| C0179 | APIs.guru OpenAPI directory | dataset_download | none | verified_live | APIs.guru: CC0 data | P069 `public_api_exposure` approved |
| C0180 | CarbonDate web page age estimator | api | none | verified_live | Academic research service | P059 `web_archives` approved |
| C0181 | CheckPhish (Bolster) | api | free_key | verified_needs_key | Bolster terms | P078 `url_scanners_third_party` approved |
| C0182 | CIRCL Lookyloo public instance API | api | none | verified_live | CIRCL terms | P078 `url_scanners_third_party` approved |
| C0183 | CrawlGraph backlinks API | api | free_key | verified_needs_key | CrawlGraph terms; data derived from Common Crawl. | P079 `backlinks` deferred |
| C0184 | HSTS preload list status API | api | none | verified_live | Chromium HSTS preload service, public. | P076 `posture_third_party` approved |
| C0185 | urlquery.net API | api | free_key | verified_needs_key | urlquery terms | P078 `url_scanners_third_party` approved |
| C0186 | UK Web Archive CDX | api | none | error | Free (British Library). | P059 `web_archives` approved |
| C0187 | WOT (Web of Trust) scorecard API | api | free_key | verified_needs_key | WOT API terms. | P082 `reject_low_value_web` rejected |
| C0188 | BuiltWith technology & relationship profiles | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P083 `pivots_url_web` approved |
| C0189 | urlscan.io domain page | url_template | none | verified_live | [caipora_infra] Free web UI; provider ToS apply (manual analyst use) ‖ [gh_infra] urlsc... | P083 `pivots_url_web` approved |
| C0190 | Wayback Machine calendar / URL list | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0191 | aa419 Fake Sites Database search | url_template | none | verified_live | Volunteer anti-fraud database; terms on site. | P083 `pivots_url_web` approved |
| C0192 | archive.today (archive.ph) captures list | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0193 | CrawlGraph backlinks page | url_template | none | verified_live | Free web UI. | P083 `pivots_url_web` approved |
| C0194 | Netcraft site report | url_template | none | verified_live | [caipora_infra] Free web UI; provider ToS apply (manual analyst use) ‖ [gh_infra] Netcr... | P083 `pivots_url_web` approved |
| C0195 | securityheaders.com report (pivot) | url_template | none | verified_live | Snyk/Probely service terms; web use | P083 `pivots_url_web` approved |
| C0196 | Ghostarchive search | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P083 `pivots_url_web` approved |
| C0197 | MDN Observatory report page (pivot) | url_template | none | verified_live | Mozilla | P083 `pivots_url_web` approved |
| C0198 | ScamAdviser website check | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P083 `pivots_url_web` approved |
| C0199 | W3Techs site info (pivot) | url_template | none | verified_live | site ToS | P083 `pivots_url_web` approved |
| C0200 | Website Informer | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P083 `pivots_url_web` approved |
| C0201 | WebTechSurvey website technology page | url_template | none | verified_live | Free web UI. | P083 `pivots_url_web` approved |
| C0729 | Google Web Risk API (commercial Safe Browsing: uris.search / hashes... | api | paid_key | verified_needs_key | Google Cloud Web Risk terms: the commercial counterpart of Safe Browsing (Safe Browsing... | P067 `google_safe_browsing` approved |
| C0775 | Playwright headless capture (screenshot, DOM, HAR) for phishing/rec... | offline_lib_or_algorithm | none | verified_live | Apache-2.0. | P347 `page_capture` approved |
| C0777 | Abuse / takedown report forms and contacts (Google Safe Browsing re... | url_template | none | verified_live | Provider forms (manual submissions by the analyst). | P345 `takedown_packet` approved |
| C0778 | Apple iTunes Search / Lookup API (apps by brand or seller, country=br) | api | none | verified_live | Apple Search API terms (documented for promoting App Store content through the Performa... | P346 `mobile_app_impersonation` approved |
| C0779 | Google Play store search and app-details pages (manual pivot links) | url_template | none | verified_live | Google Play terms (no scraping). | P083 `pivots_url_web` approved |
| C0780 | F-Droid repository index v2 (entry.json + index-v2.json; offline ma... | dataset_download | none | verified_live | F-Droid metadata (repository data; app texts under their licences). | P346 `mobile_app_impersonation` approved |
| C0789 | Google Tag Manager container expansion (gtm.js?id=GTM-XXXX -> GA4 /... | api | none | verified_live | Public JavaScript served by Google. | P061 `analytics_ids` approved |
| C0790 | SpyOnWeb API (reverse analytics / AdSense / IP lookups; free token) | api | free_key | error | SpyOnWeb terms. | P061 `analytics_ids` approved |
| C0791 | RetireJS vulnerability repository jsrepository-v4.json (Apache-2.0) | dataset_download | none | verified_live | Apache-2.0 (LICENSE verified). | P344 `retirejs_check` approved |

## Email (21)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0202 | Gravatar profiles (username JSON + v3 by e-mail hash) | api | none | verified_live | [caipora_people] Gravatar/Automattic terms ‖ [gh_infra] Gravatar/Automattic API terms ‖... | P087 `gravatar` approved |
| C0203 | V3LUM e-mail header analyzer (stdlib prototype) | offline_lib_or_algorithm | none | verified_live | own code on Python stdlib (EmailAnalyzer is GPL-3.0 -> ideas only) | P085 `email_header_analyzer` approved |
| C0204 | checkdmarc (SPF/DMARC/MTA-STS/TLS-RPT/BIMI validator) | offline_lib_or_algorithm | none | unverified | Apache-2.0 - may be adapted with attribution. | P002 `email_security_posture` approved |
| C0205 | Disposable / temporary email domain lists | dataset_download | none | verified_live | [caipora_people] disposable-email-domains: CC0 1.0; FakeFilter: check repo LICENSE befo... | P088 `email_hygiene` approved |
| C0206 | EmailRep.io reputation | api | free_key | verified_needs_key | [caipora_people] Sublime Security EmailRep terms ‖ [live_osint] Sublime Security EmailR... | P089 `emailrep` approved |
| C0207 | GitHub user search by published e-mail (in:email) | api | none | verified_live | GitHub API ToS. | P086 `github_email_pivot` approved |
| C0208 | Hunter.io (domain-search, email-finder, verifier, email-count) | api | free_key | verified_needs_key | Hunter ToS | P090 `hunter_io` approved |
| C0209 | mail-parser (Received/addresses/defects parsing) | offline_lib_or_algorithm | none | verified_live | Apache-2.0 - code may be adapted with attribution + NOTICE. | P085 `email_header_analyzer` approved |
| C0210 | PGP keyservers (keys.openpgp.org VKS + keyserver.ubuntu.com HKP) | api | none | verified_live | [caipora_people] SKS/Hockeypuck public keyserver ‖ [gh_infra] Public keyservers ‖ [gh_p... | P091 `pgp_keyservers` approved |
| C0211 | Proton Mail public key server lookup | api | none | verified_live | Proton public key directory | P092 `proton_pks` approved |
| C0212 | EmailAnalyzer (reference) | offline_lib_or_algorithm | none | unverified | GPL-3.0 - ideas only. | P085 `email_header_analyzer` approved |
| C0213 | Google Calendar public ICS by e-mail | api | none | verified_live | Google ToS (public calendar feed) | P093 `google_calendar_ics` approved |
| C0214 | MailCheck.ai domain & email check | api | none | verified_live | MailCheck.ai terms. | P088 `email_hygiene` approved |
| C0215 | Offline e-mail hygiene checks (AfterShip email-verifier technique) | offline_lib_or_algorithm | none | unverified | email-verifier: MIT (raw LICENSE verified); email-validator: Unlicense | P088 `email_hygiene` approved |
| C0216 | Commercial identity aggregators (OSINT Industries, Predicta Search,... | api | paid_key | unverified | commercial ToS | P095 `reject_identity_aggregators` rejected |
| C0217 | GHunt (Google account OSINT) | offline_lib_or_algorithm | login_required | unverified | [caipora_people] GHunt AGPL-3.0; Google ToS ‖ [gh_people] AGPL-3.0 (no copying) | P094 `reject_ghunt` rejected |
| C0218 | Kickbox Open disposable-domain API | api | none | verified_live | Kickbox Open terms | P088 `email_hygiene` approved |
| C0219 | MHA - Mail Header Analyzer (reference) | offline_lib_or_algorithm | none | unverified | GPL-3.0 - ideas only. | P085 `email_header_analyzer` approved |
| C0220 | SMTP mailbox verification (check-if-email-exists style) | offline_lib_or_algorithm | none | unverified | check-if-email-exists is AGPL-3.0 (ideas only); commercial APIs need keys | P096 `reject_smtp_verify` rejected |
| C0221 | Account enumeration via signup/password-reset endpoints (holehe, us... | offline_lib_or_algorithm | none | unverified | [caipora_cli] Zehef AGPL-3.0, Eyes AGPL-3.0, mailcat Apache-2.0, mailto_analyzer no lic... | P097 `reject_account_enumeration` rejected |
| C0222 | email-format.com (corporate email pattern) | url_template | none | verified_live | [caipora_people] site terms ‖ [gh_infra] Site ToS (no automated scraping stated) | P098 `pivots_email` approved |

## Usernames & social media (63)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0223 | Céos cross-account linking heuristics | offline_lib_or_algorithm | none | unverified | Team-owned code (port to English). | P258 `correlation_pack_identity_company` approved |
| C0224 | GitHub commit search by author-email | api | none | verified_live | GitHub API ToS (no spam/resale of personal data). | P086 `github_email_pivot` approved |
| C0225 | GitHub user profile / public events / SSH+GPG keys / .patch | api | none | unverified | [gh_people] GitHub ToS / API terms ‖ [live_osint] GitHub API ToS. | P111 `github_user` approved |
| C0226 | Maigret site database + db_meta manifest | dataset_download | none | verified_live | [caipora_people] MIT (code+data) - may be adapted with attribution ‖ [gh_people] MIT (C... | P113 `username_check` approved |
| C0227 | Telegram t.me public preview + channel web view | scrape | none | verified_live | [caipora_people] Telegram ToS (public preview pages) ‖ [live_osint] Telegram public web... | P112 `telegram_public` approved; P357 `telegram_channel_watch` approved |
| C0228 | WhatsMyName site dataset (final, archived) | dataset_download | none | verified_live | [caipora_people] CC BY-SA 4.0 (data): attribution + share-alike if V3LUM redistributes/... | P113 `username_check` approved |
| C0229 | Arctic Shift Reddit archive API (Pushshift successor) | api | none | verified_live | Community archive; respect usage guidance | P108 `reddit_archive` approved |
| C0230 | Avatar correlation (perceptual hash) + avatar upload dating | offline_lib_or_algorithm | none | verified_live | [caipora_people] own implementation (Pillow); imagehash (BSD-2) optional ‖ [design_ceos... | P114 `avatar_correlation` approved |
| C0231 | Bluesky AppView public profile | api | none | verified_live | [caipora_people] Bluesky public API terms ‖ [gh_people] Bluesky ToS; public API ‖ [live... | P099 `bluesky` approved |
| C0232 | Calibrated same-username checker (14 sites, tri-state result) | api | none | unverified | team-owned; each site's ToS | P113 `username_check` approved |
| C0233 | Discord invite resolver | api | none | verified_live | Discord developer terms | P101 `discord_invite` approved |
| C0234 | Docker Hub user + image-layer e-mails | api | none | verified_live | [design_ceos] public APIs; team-owned code ‖ [gh_people] Docker Hub ToS; public API | P102 `dockerhub` approved; P359 `org_code_footprint` approved |
| C0235 | gitcolombo git-metadata identity extraction & linking | offline_lib_or_algorithm | none | verified_live | MIT (adaptable with attribution). | P115 `git_metadata_identity` approved |
| C0236 | GitHub user discovery (search page embedded JSON) + commit-email ha... | api | none | unverified | GitHub ToS (API preferred; HTML scraping is fragile and ToS-sensitive) | P111 `github_user` approved |
| C0237 | GitHub/GitLab public SSH & GPG keys per user | scrape | none | unverified | GitHub/GitLab ToS (public data) | P111 `github_user` approved |
| C0238 | GitLab users API | api | none | verified_live | GitLab.com ToS; public API | P103 `gitlab_user` approved |
| C0239 | Keybase user lookup + sigchain | api | none | verified_live | [gh_infra] Keybase API (public) ‖ [gh_people] Keybase ToS (service in maintenance mode ... | P104 `keybase` approved |
| C0240 | Mastodon / Fediverse WebFinger + accounts lookup | api | none | verified_live | [caipora_people] per-instance terms ‖ [gh_people] Instance ToS; public API | P105 `mastodon` approved |
| C0241 | memory.lol X/Twitter handle history | api | none | verified_live | [caipora_people] Free service by Travis Brown (open-source code); data from archived tw... | P106 `memory_lol` approved |
| C0242 | npm registry search by maintainer | api | none | verified_live | npm ToS (public metadata) | P100 `dev_profiles_pack` approved; P359 `org_code_footprint` approved |
| C0243 | PLC directory audit log (Bluesky DID history) | api | none | verified_live | [gh_people] PLC directory terms ‖ [live_osint] Public PLC directory. | P099 `bluesky` approved |
| C0244 | socid_extractor profile-ID extractor | offline_lib_or_algorithm | none | unverified | [caipora_people] MIT - schemes may be adapted with attribution ‖ [gh_people] MIT (PyPI ... | P107 `profile_id_extractor` approved |
| C0245 | Codeberg / Forgejo / Gitea users API | api | none | verified_live | [gh_people] Codeberg ToS ‖ [live_osint] Codeberg e.V. ToS. | P100 `dev_profiles_pack` approved |
| C0246 | Deleted-tweet recovery via Wayback (twayback technique) | offline_lib_or_algorithm | none | unverified | twayback Apache-2.0. | P119 `x_twitter_public` approved |
| C0247 | DEV Community user API | api | none | verified_live | Forem/DEV ToS | P100 `dev_profiles_pack` approved |
| C0248 | Hacker News Firebase API | api | none | verified_live | [gh_people] HN API terms (public) ‖ [live_osint] Public HN API (Y Combinator). | P109 `hackernews` approved |
| C0249 | HackerOne public GraphQL user | api | none | verified_live | HackerOne ToS | P100 `dev_profiles_pack` approved |
| C0250 | HN Algolia search API | api | none | verified_live | [caipora_people] free public API ‖ [live_osint] HN Search by Algolia - public. | P109 `hackernews` approved |
| C0251 | Hugging Face user overview | api | none | verified_live | Hugging Face ToS | P100 `dev_profiles_pack` approved |
| C0252 | Instagram anonymous public-profile reader | scrape | none | unverified | [caipora_people] Meta ToS ‖ [design_ceos] Meta/Instagram ToS prohibit automated collection | P122 `reject_instagram_scraper` rejected |
| C0253 | PyPI JSON API (package metadata) | api | none | verified_live | PyPI ToS. | P100 `dev_profiles_pack` approved |
| C0254 | Reddit user about.json | api | free_key | error | Reddit Data API Terms (free tier non-commercial; commercial needs agreement). | P117 `reddit_api` deferred |
| C0255 | Reddit user API (OAuth app-only) | api | free_key | verified_needs_key | Reddit Data API terms (free for non-commercial; register an app) | P117 `reddit_api` deferred |
| C0256 | Sherlock false-positive exclusions list | dataset_download | none | verified_live | MIT (same repo) | P113 `username_check` approved |
| C0257 | Sherlock site manifest | dataset_download | none | verified_live | MIT (Copyright 2019 Sherlock Project) | P113 `username_check` approved |
| C0258 | Steam Community XML profile | api | none | verified_live | [caipora_people] Steam subscriber agreement (public profile data) ‖ [gh_people] Steam W... | P116 `community_profiles_pack` approved |
| C0259 | TikTok public profile JSON (SSR hydration) | scrape | none | verified_live | TikTok ToS (scraping restricted) | P118 `tiktok_public` approved |
| C0260 | X/Twitter syndication tweet JSON (no login) | api | none | verified_live | Undocumented embed endpoint (may change without notice) | P119 `x_twitter_public` approved |
| C0261 | YouTube Data API v3 | api | free_key | verified_needs_key | Google API ToS | P110 `youtube` approved |
| C0262 | YouTube handle resolution + channel RSS + oEmbed (no key) | scrape | none | verified_live | YouTube ToS | P110 `youtube` approved |
| C0263 | Blackbird (WMN-based checker + email list) | offline_lib_or_algorithm | none | unverified | GPL-3.0 (docs/LICENSE) and CC BY-NC-SA 4.0 (.github/LICENSE) - study ideas only | P124 `reject_socialscan_blackbird` rejected |
| C0264 | Chess.com PubAPI player | api | none | verified_live | Chess.com PubAPI terms | P116 `community_profiles_pack` approved |
| C0265 | Disqus profile page (+ API with public key) | scrape | none | verified_live | Disqus ToS. | P116 `community_profiles_pack` approved |
| C0266 | Duolingo public user search (by username) | api | none | verified_live | [caipora_people] Undocumented endpoint (Duolingo ToS) ‖ [gh_people] Duolingo ToS (undoc... | P116 `community_profiles_pack` approved |
| C0267 | FLAGGED: account-session Telegram/Discord scrapers (Telethon / user... | api | login_required | unverified | not cloned (Telepathy, Telerecon, TGSpyder, Geogramint, Telegram-Trilateration, doxcord... | P123 `reject_session_scrapers` rejected |
| C0268 | GitHub profile activity & stack classifier | offline_lib_or_algorithm | none | unverified | team-owned | P111 `github_user` approved |
| C0269 | Lichess user API | api | none | verified_live | [gh_people] Lichess API ToS (AGPL server, open API) ‖ [live_osint] Lichess API (open, A... | P116 `community_profiles_pack` approved |
| C0270 | Medium user RSS | api | none | verified_live | Medium ToS. | P116 `community_profiles_pack` approved |
| C0271 | Pinterest public widget API | api | none | verified_live | Pinterest widget terms | P116 `community_profiles_pack` approved |
| C0272 | Snapchat public profile page (Next.js data) | scrape | none | verified_live | Snap ToS | P116 `community_profiles_pack` approved |
| C0273 | Stack Exchange API users | api | none | verified_live | Stack Exchange API terms; content CC BY-SA. | P116 `community_profiles_pack` approved |
| C0274 | Status-code HTML profile checks (About.me, Dribbble, Linktree, Kaggle) | scrape | none | verified_live | Each site's ToS | P113 `username_check` approved |
| C0275 | Twitch Helix users | api | free_key | verified_needs_key | Twitch Developer Agreement. | P116 `community_profiles_pack` approved |
| C0276 | unavatar.io avatar resolver | api | free_key | verified_needs_key | unavatar terms | P114 `avatar_correlation` approved |
| C0277 | Wikimedia global account info | api | none | verified_live | Wikimedia API terms + UA policy | P120 `wikimedia` approved |
| C0278 | Wikipedia/MediaWiki contributions by IP or user | api | none | error | CC BY-SA content; Wikimedia API policy | P120 `wikimedia` approved |
| C0279 | X/Twitter data import + behaviour and automation indicators | offline_lib_or_algorithm | none | unverified | team-owned (twitter-archive-parser GPL was read as reference only) | P121 `x_archive_import` approved |
| C0280 | X/Twitter oEmbed | api | none | verified_live | X developer terms (oEmbed is a public endpoint) | P119 `x_twitter_public` approved |
| C0281 | Mojang/Minecraft profile API | api | none | verified_live | Mojang API terms | P116 `community_profiles_pack` approved |
| C0282 | socialscan (username/email availability) | offline_lib_or_algorithm | none | unverified | MPL-2.0 | P124 `reject_socialscan_blackbird` rejected |
| C0283 | Bluesky profile page | url_template | none | verified_live | Bluesky ToS. | P125 `pivots_username_social` approved |
| C0284 | Mastodon profile page | url_template | none | verified_live | Instance ToS. | P125 `pivots_username_social` approved |
| C0285 | TGStat channel analytics (pivot) | url_template | none | unverified | site terms (paid API exists) | P304 `pivots_unverified` approved |

## Phone numbers (15)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0286 | libphonenumber (python 'phonenumbers') | offline_lib_or_algorithm | none | verified_live | Apache-2.0 | P126 `phone_parse` approved |
| C0287 | BrasilAPI DDD | api | none | verified_live | [caipora_br_gov] MIT code; Anatel data ‖ [live_osint] BrasilAPI (MIT) / Anatel data. | P127 `brasilapi_ddd` approved |
| C0288 | DDD -> UF table | offline_lib_or_algorithm | none | verified_live | own implementation of public specifications | P126 `phone_parse` approved |
| C0289 | Numverify (APILayer) number validation | api | free_key | verified_needs_key | APILayer ToS | P129 `phone_validation_keyed` rejected |
| C0290 | AbstractAPI phone validation | api | free_key | verified_needs_key | Abstract ToS. | P129 `phone_validation_keyed` rejected |
| C0291 | AreaCodeCheck phone API | api | none | verified_live | AreaCodeCheck terms (attribution field in response). | P130 `phone_numbering_minor` rejected |
| C0292 | OVH telephony detailedZones | api | none | verified_live | OVH API terms | P130 `phone_numbering_minor` rejected |
| C0293 | Veriphone phone validation | api | free_key | verified_needs_key | [lists_global] Veriphone terms. ‖ [live_osint] Veriphone ToS. | P129 `phone_validation_keyed` rejected |
| C0294 | Cadastro Pre (prepaid lines by CPF) | scrape | none | unverified | public open data / free public API | P255 `reject_br_people_search` rejected |
| C0295 | Caller-ID crowdsourced apps (Truecaller, Getcontact, Sync.me) - FLA... | api | login_required | unverified | ToS forbid automation | P131 `reject_caller_id_presence` rejected |
| C0296 | WhatsApp/Telegram number presence checkers - FLAGGED | api | login_required | unverified | violates WhatsApp/Telegram ToS | P131 `reject_caller_id_presence` rejected |
| C0297 | spamcalls.net number page | url_template | none | verified_live | spamcalls.net ToS. | P128 `pivots_phone` approved |
| C0298 | tellows Brazil caller reputation (pivot) | url_template | none | unverified | site terms | P304 `pivots_unverified` approved |
| C0798 | Messaging deep links as manual pivots (wa.me/<E164>, t.me/+<E164>) | url_template | none | verified_live | Platform terms (manual use). | P128 `pivots_phone` approved |
| C0800 | Anatel numbering open data (number blocks per operator; non-geograp... | dataset_download | none | unverified | Brazilian open data. | P126 `phone_parse` approved |

## Breaches & leaks (metadata only) (24)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0299 | Breach data-minimization guards (never store passwords or combo lines) | offline_lib_or_algorithm | none | unverified | team-owned | P145 `breach_minimization_guards` approved |
| C0300 | Breach validation heuristics with suggested verdict (positive / fal... | offline_lib_or_algorithm | none | unverified | team-owned | P146 `correlation_pack_breach` approved |
| C0301 | Have I Been Pwned - breached account | api | paid_key | verified_needs_key | [gh_people] HIBP API terms (attribution required) ‖ [live_osint] Paid subscription; CC ... | P133 `hibp_account` approved |
| C0302 | HIBP breach catalog (+domain filter) | api | none | verified_live | [caipora_people] HIBP API terms (CC BY 4.0 attribution for data) ‖ [design_ceos] CC BY ... | P132 `hibp_catalog` approved |
| C0303 | Hudson Rock Cavalier free OSINT endpoints (search-by-email/username... | api | none | verified_live | [caipora_infra] Hudson Rock free tools terms ‖ [design_ceos] Hudson Rock free OSINT too... | P134 `hudson_rock` approved |
| C0304 | LeakCheck public API | api | none | verified_live | [design_ceos] LeakCheck terms (public endpoint; check commercial use) ‖ [live_osint] Fr... | P135 `leakcheck_public` approved |
| C0305 | Lunar (Webz.io) Domain Exposure API | api | none | verified_live | Webz.io/Lunar free API; commercial provider - terms at webz.io. | P136 `lunar_domain_exposure` approved |
| C0306 | XposedOrNot breach-analytics | api | none | verified_live | [caipora_people] XposedOrNot terms (open-source project) ‖ [design_ceos] XposedOrNot te... | P137 `xposedornot` approved |
| C0307 | XposedOrNot breaches catalog (+domain filter) | api | none | verified_live | Free public API (XposedOrNot). | P137 `xposedornot` approved |
| C0308 | Breach.House (ransomware/breach/stealer tracker) - FLAGGED | api | paid_key | verified_needs_key | [caipora_apis_cti] Commercial ToS. ‖ [gh_infra] Breach.House API terms | P202 `ransomware_breach_trackers_keyed` rejected |
| C0309 | GrayhatWarfare open buckets / shorteners | api | free_key | verified_needs_key | GrayhatWarfare terms | P138 `grayhatwarfare` approved |
| C0310 | HIBP Pwned Passwords range (k-anonymity) | api | none | verified_live | CC BY 4.0 (attribution to HIBP). | P141 `pwned_passwords_internal` approved |
| C0311 | Intelligence X (free key, selector metadata) | api | free_key | verified_needs_key | Intelligence X ToS | P139 `intelx_metadata` approved |
| C0312 | Intelligence X phonebook | api | free_key | unverified | IntelX ToS | P139 `intelx_metadata` approved |
| C0313 | Leak-Lookup public API (breach names only) | api | free_key | verified_needs_key | Leak-Lookup ToS | P140 `leak_lookup_public` approved |
| C0314 | XposedOrNot domain-breaches (verified domains) | api | free_key | verified_needs_key | Free account; domain ownership must be verified (DNS/HTML/email). | P137 `xposedornot` approved |
| C0315 | Library of Leaks (Aleph) search - FLAGGED | api | none | verified_live | DDoSecrets-run archive; leaked content | P142 `reject_library_of_leaks` rejected |
| C0316 | ProxyNova COMB search API - FLAGGED | api | none | verified_live | [caipora_cli] leaker MIT; provider terms vary. ‖ [caipora_people] unclear legality of r... | P143 `reject_plaintext_leak_sources` rejected |
| C0317 | psbdmp.ws paste dump search | api | none | error | psbdmp terms | P143 `reject_plaintext_leak_sources` rejected |
| C0318 | BreachDirectory (RapidAPI) | api | free_key | verified_needs_key | RapidAPI + BreachDirectory ToS | P143 `reject_plaintext_leak_sources` rejected |
| C0319 | BreachDirectory - FLAGGED | api | paid_key | unverified | commercial | P143 `reject_plaintext_leak_sources` rejected |
| C0320 | Plaintext-leak / password-check / leaked-DB services - DO NOT INTEG... | api | paid_key | unverified | [caipora_apis_cti] Various; many operate in legal grey zones. ‖ [caipora_people] commer... | P143 `reject_plaintext_leak_sources` rejected |
| C0321 | Plaintext-leak backends used by h8mail (DeHashed, Snusbase, Scylla,... | api | paid_key | unverified | [gh_infra] DeHashed ToS ‖ [gh_people] Commercial / illegal-origin data | P143 `reject_plaintext_leak_sources` rejected |
| C0322 | HIBP breach page | url_template | none | verified_live | HIBP (CC BY 4.0). | P144 `pivots_breach_leak` approved |

## Threat intel & reputation (90)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0323 | AbuseIPDB API v2 | api | free_key | verified_needs_key | AbuseIPDB terms | P157 `abuseipdb` approved |
| C0324 | AlienVault OTX indicator API | api | none | verified_live | [gh_cti_ioc] LevelBlue/AT&T OTX terms (free community). ‖ [gh_infra] OTX terms (free ac... | P153 `otx` approved |
| C0325 | CrowdSec CTI API (smoke) | api | free_key | verified_needs_key | [caipora_cli] CrowdSec CTI API terms (free tier - check commercial-use clause). ‖ [list... | P152 `crowdsec_cti` approved |
| C0326 | IOC extraction + defang/refang from text, files and email bodies | offline_lib_or_algorithm | none | verified_live | [design_ceos] own code. iocextract is GPL-2.0 and fhightower/ioc-finder is GPL-3.0 (stu... | P172 `ioc_extraction_engine` approved |
| C0327 | MISP warninglists (false-positive suppression + context tagging) | dataset_download | none | verified_live | [design_ceos] CC0 1.0 (public domain); X4BNet-derived VPN/datacenter lists keep MIT not... | P169 `warninglists` approved |
| C0328 | OffSeq Mirage honeypot feed | dataset_download | none | verified_live | CC BY 4.0, TLP:CLEAR (stated on feeds.offseq.com) - attribution required. | P147 `honeypot_intel` approved |
| C0329 | ThreatFox API | api | free_key | verified_needs_key | [gh_cti_ioc] abuse.ch terms (CC0 data). ‖ [gh_infra] abuse.ch ToS (CC0 data) ‖ [live_ct... | P156 `abusech` approved |
| C0330 | URLhaus API | api | free_key | verified_needs_key | [caipora_infra] abuse.ch terms (free incl. commercial use per abuse.ch ToS - re-check) ... | P156 `abusech` approved |
| C0331 | VirusTotal API v3 | api | free_key | verified_needs_key | [caipora_infra] VT public API terms ‖ [gh_infra] VirusTotal ToS (public API: non-commer... | P158 `virustotal` approved |
| C0332 | abuse.ch bulk exports (ThreatFox / URLhaus / MalwareBazaar) | dataset_download | free_key | verified_needs_key | abuse.ch terms (CC0 data). | P156 `abusech` approved; P350 `offline_hash_sets` approved |
| C0333 | CIRCL MISP OSINT feed | dataset_download | none | verified_live | [gh_cti_ioc] CIRCL OSINT feed, TLP:CLEAR; attribute CIRCL. ‖ [live_cti] TLP:CLEAR OSINT... | P159 `ioc_feeds_offline` approved |
| C0334 | Feodo Tracker blocklist | dataset_download | none | verified_live | [gh_cti_ioc] abuse.ch terms (CC0 data). ‖ [live_cti] CC0, free for commercial and non-c... | P149 `ip_blocklists` approved |
| C0335 | GreyNoise Community API | api | none | verified_live | GreyNoise community terms | P148 `greynoise_community` approved |
| C0336 | HoneyLabs honeypot API (CVE / port / ASN telemetry) | api | free_key | verified_live | Free community service; API/MCP surface is closed-source; data covers the last ~90 days... | P147 `honeypot_intel` approved |
| C0337 | ioc-extractor (refang regexes + validators) | offline_lib_or_algorithm | none | verified_live | MIT (Copyright 2018 Manabu Niseki) - port with attribution. | P172 `ioc_extraction_engine` approved |
| C0338 | ioc-finder (pyparsing grammars) | offline_lib_or_algorithm | none | unverified | LGPL-3.0 (COPYING + COPYING.LESSER) - no code copying; using it unmodified as a pip dep... | P172 `ioc_extraction_engine` approved |
| C0339 | IPGuardian blocklist aggregator | api | none | verified_live | IPGuardian terms (free). | P150 `ip_reputation_keyless` approved |
| C0340 | IPsum aggregated threat IPs | dataset_download | none | verified_live | [caipora_infra] Check repo license (aggregated public lists) ‖ [gh_cti_ioc] Unlicense (... | P149 `ip_blocklists` approved |
| C0341 | Maltiverse IoC lookup | api | none | verified_live | [gh_cti_ioc] Maltiverse terms (free community tier). ‖ [gh_infra] Maltiverse ToS ‖ [liv... | P154 `maltiverse` approved |
| C0342 | mthcht awesome-lists (CTI/DFIR detection lists: VPN, proxy, RMM, Dy... | dataset_download | none | verified_live | MIT (adaptable with attribution). | P035 `ip_context_lists` approved |
| C0343 | OpenPhish community feed | dataset_download | none | verified_live | [caipora_infra] OpenPhish community feed terms (free, attribution) ‖ [gh_cti_ioc] OpenP... | P071 `url_domain_blocklists` approved |
| C0344 | Pulsedive indicator info | api | none | verified_live | Pulsedive terms (free community tier). | P160 `pulsedive` approved |
| C0345 | SANS ISC / DShield IP API | api | none | verified_live | [gh_cti_ioc] SANS ISC API terms (free; attribution; check commercial-use wording). ‖ [g... | P151 `isc_dshield` approved |
| C0346 | Spamhaus DROP / ASN-DROP | dataset_download | none | verified_live | Spamhaus DROP terms (free to use; check redistribution). | P149 `ip_blocklists` approved |
| C0347 | TweetFeed IOC feed (IOCs shared on X) | api | none | verified_live | [caipora_infra] Check repo license ‖ [caipora_people] free community feed ‖ [gh_cti_ioc... | P159 `ioc_feeds_offline` approved |
| C0348 | blocklist.de attack IPs | dataset_download | none | verified_live | [caipora_infra] blocklist.de terms (free) ‖ [gh_cti_ioc] Free use per blocklist.de. ‖ [... | P149 `ip_blocklists` approved |
| C0349 | C2IntelFeeds (drb-ra) - C2 servers from Censys queries | dataset_download | none | verified_live | [caipora_infra] Check repo license ‖ [gh_cti_ioc] No LICENSE file in repo (404) - treat... | P159 `ioc_feeds_offline` approved |
| C0350 | CINS Army bad-guys list | dataset_download | none | verified_live | [caipora_infra] Free list (Sentinel IPS terms) ‖ [gh_cti_ioc] Free for use (CINS terms)... | P149 `ip_blocklists` approved |
| C0351 | CyberCrime-Tracker C2 panel list | dataset_download | none | verified_live | Free | P071 `url_domain_blocklists` approved |
| C0352 | Emerging Threats compromised IPs | dataset_download | none | verified_live | [caipora_infra] ET Open terms ‖ [gh_cti_ioc] ET Open (Proofpoint) terms - free. ‖ [gh_i... | P149 `ip_blocklists` approved |
| C0353 | FireHOL level1 aggregated blocklist | dataset_download | none | verified_live | [caipora_infra] Aggregated lists keep their original licenses (see each ipset header) ‖... | P149 `ip_blocklists` approved |
| C0354 | GreenSnow IP blocklist | dataset_download | none | verified_live | [caipora_infra] Free list ‖ [gh_cti_ioc] Free (GreenSnow). ‖ [gh_infra] Free for non-co... | P149 `ip_blocklists` approved |
| C0355 | HoneyDB API | api | free_key | verified_needs_key | HoneyDB terms (free for research/defensive use). | P147 `honeypot_intel` approved |
| C0356 | IBM X-Force Exchange API | api | free_key | verified_needs_key | [caipora_infra] IBM X-Force terms ‖ [live_cti] IBM X-Force Exchange terms | P155 `ibm_xforce` approved |
| C0357 | InQuest iocextract (reference only) | offline_lib_or_algorithm | none | unverified | GPL-2.0 - study ideas only, no copying. | P172 `ioc_extraction_engine` approved |
| C0358 | isMalicious API (IP/domain/email/wallet reputation aggregated from ... | api | free_key | verified_needs_key | [caipora_apis_cti] Commercial ToS with free tier. ‖ [caipora_infra] isMalicious terms | P161 `ismalicious` deferred |
| C0359 | James Brine threat feeds | dataset_download | none | verified_live | Free public feeds; no explicit licence found on the homepage - check /faq and attribute. | P147 `honeypot_intel` approved |
| C0360 | Kaspersky OpenTIP API | api | free_key | verified_needs_key | Kaspersky OpenTIP terms | P162 `kaspersky_opentip` approved |
| C0361 | Meta threat-research indicators (CIB networks, malware campaigns) | dataset_download | none | verified_live | MIT. | P159 `ioc_feeds_offline` approved |
| C0362 | NetAPI compromised check + compromised IP/URL feeds | api | none | verified_live | NetAPI terms (free feeds; paid datasets). | P150 `ip_reputation_keyless` approved |
| C0363 | Open-Source Threat Intel Feeds catalog (Bert-JanP) | dataset_download | none | verified_live | BSD-3-Clause (attribution) | P159 `ioc_feeds_offline` approved |
| C0364 | Phishing Army blocklist | dataset_download | none | verified_live | [caipora_infra] Check license (attribution required) ‖ [gh_cti_ioc] Believed CC BY-NC 4... | P071 `url_domain_blocklists` approved |
| C0365 | PhishTank checkurl API (single-URL verdict) | api | none | verified_live | PhishTank terms (free, attribution). | P075 `phishtank_checkurl` approved |
| C0366 | ScamSearch.io API (scam reports by email/username/phone/crypto/URL) | api | free_key | verified_needs_key | Free API key on registration; site ToS. | P163 `scamsearch` deferred |
| C0367 | SSLBL malicious TLS certificate blacklist | dataset_download | none | verified_live | [gh_cti_ioc] abuse.ch terms (CC0 data). ‖ [live_cti] CC0 (commercial OK) | P149 `ip_blocklists` approved |
| C0368 | Stop Forum Spam API (IP / email / username spam reputation) | api | none | verified_live | [caipora_apis_cti] Stop Forum Spam ToS (free, non-abusive use). ‖ [gh_cti_ioc] StopForu... | P164 `spam_bot_reputation` approved |
| C0369 | Telegram bot-token intelligence (Tosint/TeleTracker) - FLAGGED | api | none | verified_live | [caipora_cli] No license file (all rights reserved). ‖ [caipora_people] Tosint GPL-3.0 ... | P165 `reject_telegram_bot_token_use` rejected |
| C0370 | teler-resources web-attack & bad-actor datasets (log analysis) | dataset_download | none | verified_live | Collection CC-BY-4.0 (attribution). Upstreams: PHPIDS filters (LGPL-3.0 - ship as separ... | P317 `user_agent_analysis` approved; P340 `log_file_input` approved |
| C0371 | Threatview.io C2 / IOC feeds | dataset_download | none | verified_live | [caipora_infra] Free feeds (ThreatView terms) ‖ [gh_cti_ioc] Free community feeds (site... | P159 `ioc_feeds_offline` approved |
| C0372 | Binary Defense Artillery banlist | dataset_download | none | verified_live | public use only; no commercial resale/products charging fees | P149 `ip_blocklists` approved |
| C0373 | BotScout bot/spammer check | api | free_key | verified_live | BotScout API terms (free). | P164 `spam_bot_reputation` approved |
| C0374 | Botvrij.eu domain blocklist | dataset_download | none | verified_live | Free (botvrij.eu) | P071 `url_domain_blocklists` approved |
| C0375 | DataPlane.org feeds | dataset_download | none | verified_live | free for NON-commercial use only; no redistribution | P149 `ip_blocklists` approved |
| C0376 | InQuest Labs (DFI / IOCdb / REPdb) | api | none | error | InQuest Labs terms. | P166 `reject_dead_ti_sources` rejected |
| C0377 | JA4 fingerprint DB (FoxIO) | dataset_download | none | error | FoxIO: JA4 (TLS client) BSD-3; JA4+ others FoxIO License 1.1 (non-commercial restrictio... | P167 `reject_ja4db` rejected |
| C0378 | Project Honey Pot http:BL (DNS) | api | free_key | verified_needs_key | Project Honey Pot terms (free account). | P045 `dnsbl` approved |
| C0379 | StevenBlack unified hosts | dataset_download | none | verified_live | MIT (aggregated lists carry their own licences) | P071 `url_domain_blocklists` approved |
| C0380 | ThreatMiner domain/host API | api | none | error | Free | P166 `reject_dead_ti_sources` rejected |
| C0381 | botvrij.eu IOC lists | dataset_download | none | dead |  | P166 `reject_dead_ti_sources` rejected |
| C0382 | C2-Tracker (montysecurity) | dataset_download | none | dead |  | P168 `reject_dead_feeds` rejected |
| C0383 | Cisco Talos IP blocklist download | dataset_download | none | error | Requires accepting terms (HTML T&C page returned instead of a list) | P168 `reject_dead_feeds` rejected |
| C0384 | CoinBlockerLists (cryptojacking domains) | dataset_download | none | error | GPL-3.0 list | P168 `reject_dead_feeds` rejected |
| C0385 | CRXcavator (Chrome extension risk) | api | none | dead |  | P166 `reject_dead_ti_sources` rejected |
| C0386 | CyberCure free IOC feeds | api | none | error | Free (historically). | P168 `reject_dead_feeds` rejected |
| C0387 | Intercept (FastIntercept) threat lists | dataset_download | free_key | error | Free token by e-mail sign-up. | P168 `reject_dead_feeds` rejected |
| C0388 | RST Cloud rstthreats GitHub feed | dataset_download | none | dead | MIT. | P168 `reject_dead_feeds` rejected |
| C0389 | VoIPBL | dataset_download | none | verified_live | Free for non-commercial use; attribute source | P149 `ip_blocklists` approved |
| C0390 | VX Vault URL list | dataset_download | none | error |  | P168 `reject_dead_feeds` rejected |
| C0391 | VirusTotal GUI deep links | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0392 | abuse.ch web pages (MalwareBazaar / URLhaus / ThreatFox) | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0393 | AbuseIPDB check page | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0394 | Cisco Talos reputation lookup | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0395 | OTX indicator pages | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0396 | CESNET NERD IP reputation | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P170 `pivots_threat_intel` approved |
| C0397 | FortiGuard search (IP/URL reputation page) | url_template | none | verified_live | [caipora_infra] Free web UI; provider ToS apply (manual analyst use) ‖ [gh_infra] Forti... | P170 `pivots_threat_intel` approved |
| C0398 | GreyNoise Visualizer IP page | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P170 `pivots_threat_intel` approved |
| C0399 | HoneyLabs IP report page | url_template | none | verified_live | Free web UI. | P170 `pivots_threat_intel` approved |
| C0400 | IBM X-Force Exchange pages | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0401 | MultiRBL lookup | url_template | none | verified_live | [caipora_infra] Free web UI; provider ToS apply (manual analyst use) ‖ [caipora_people]... | P170 `pivots_threat_intel` approved |
| C0402 | URLVoid scan page | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P170 `pivots_threat_intel` approved |
| C0403 | CyberCrime-Tracker search | url_template | none | verified_live | Public site. | P170 `pivots_threat_intel` approved |
| C0404 | Kaspersky OpenTIP lookup page | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0405 | Spamhaus IP & domain reputation checker | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0406 | ThreatBook research page | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P170 `pivots_threat_intel` approved |
| C0733 | MISP REST restSearch on the team's own instance (attributes, events... | api | free_key | unverified | Own data. MISP server is AGPL (not embedded); PyMISP is BSD-2-Clause but 3.0.0 requires... | P348 `internal_tip_sightings` approved |
| C0734 | OpenCTI GraphQL API on the team's own platform (indicators, stixCyb... | api | free_key | unverified | pycti is Apache-2.0 (7.261124.0) but must match the platform version -> plain GraphQL o... | P348 `internal_tip_sightings` approved |
| C0735 | TheHive 5/6 + Cortex API on the team's own instance (observable sea... | api | free_key | unverified | Own data; TheHive licence held by the team (docs.strangebee.com now documents TheHive 6). | P348 `internal_tip_sightings` approved |
| C0736 | SIEM search APIs behind explicit configuration (OpenSearch/Elastics... | api | free_key | unverified | Own data; read-only service account. | P349 `siem_search` approved |
| C0792 | ViriBack C2 Tracker dump (C2 panels: family, URL, IP, first seen) | dataset_download | none | verified_live | No published terms -> unknown (corporate profile: legal review). | P159 `ioc_feeds_offline` approved |
| C0793 | LOLRMM catalogue of RMM tools (legit but abused: names, domains, in... | dataset_download | none | verified_live | Apache-2.0 (repository LICENSE verified). | P268 `lol_datasets` approved |

## Malware & file hashes (25)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0407 | CIRCL hashlookup | api | none | verified_live | [gh_cti_ioc] CIRCL public service (NSRL is US-gov public data). ‖ [live_cti] CIRCL open... | P173 `circl_hashlookup` approved |
| C0408 | MalwareBazaar API | api | free_key | verified_needs_key | [gh_cti_ioc] abuse.ch terms of use (data CC0; fair use). ‖ [live_cti] abuse.ch terms (c... | P156 `abusech` approved; P351 `structural_hash_pivots` approved |
| C0409 | Hybrid Analysis API v2 (hash search) | api | free_key | verified_needs_key | [caipora_infra] Hybrid Analysis terms ‖ [live_cti] Hybrid Analysis (CrowdStrike) terms | P174 `hybrid_analysis` approved |
| C0410 | Neo23x0 signature-base (YARA rules + IOC lists) | dataset_download | none | verified_live | Detection Rule License (DRL) 1.1 - free use incl. commercial, attribution to the author... | P159 `ioc_feeds_offline` approved |
| C0411 | Recorded Future Triage API (search) | api | free_key | verified_needs_key | Triage terms | P177 `hash_lookup_keyed` approved |
| C0412 | Team Cymru Malware Hash Registry (MHR) via DNS-over-HTTPS | api | none | verified_live | [gh_cti_ioc] Team Cymru MHR terms: free for non-commercial use (believed; corporate use... | P176 `cymru_mhr` approved |
| C0413 | YARAify lookup_hash | api | free_key | verified_live | [gh_cti_ioc] abuse.ch terms (CC0 data, fair use). ‖ [live_cti] CC0, free for commercial... | P175 `yaraify` approved; P351 `structural_hash_pivots` approved |
| C0414 | Filescan.io hash reputation (OPSWAT) | api | none | verified_live | OPSWAT Filescan terms | P178 `filescan_reputation` approved |
| C0415 | MalShare | api | free_key | verified_needs_key | MalShare terms | P177 `hash_lookup_keyed` approved |
| C0416 | MetaDefender Cloud API (hash lookup) | api | free_key | verified_needs_key | OPSWAT terms | P177 `hash_lookup_keyed` approved |
| C0417 | PolySwarm hash search API | api | free_key | verified_needs_key | PolySwarm terms | P177 `hash_lookup_keyed` approved |
| C0418 | VirusShare API v2 (hash metadata) | api | free_key | verified_live | VirusShare terms (free account for researchers). | P177 `hash_lookup_keyed` approved |
| C0419 | hashdd known-level | api | none | verified_live | hashdd terms. | P179 `hash_lookup_keyless_minor` rejected |
| C0420 | Malprob hash search | api | none | verified_live | Malprob terms (not reviewed). | P179 `hash_lookup_keyless_minor` rejected |
| C0421 | DigitalSide Threat-Intel feeds | dataset_download | none | error | MIT (repository). | P168 `reject_dead_feeds` rejected |
| C0422 | Virushee hash check | api | none | error |  | P166 `reject_dead_ti_sources` rejected |
| C0423 | Triage reports search | url_template | none | verified_live | [caipora_infra] Free web UI; provider ToS apply (manual analyst use) ‖ [live_cti] site ... | P180 `pivots_malware_hash` approved |
| C0424 | Hybrid Analysis search page | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0425 | Filescan.io search page | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0426 | Joe Sandbox search | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0427 | MetaDefender hash results page | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0730 | VirusShare MD5 hash lists (historical known-malware sample set, dow... | dataset_download | none | verified_live | No published licence for the hash lists (site 'Because Sharing is Caring'; sample downl... | P350 `offline_hash_sets` approved |
| C0731 | CIRCL hashlookup full Bloom filter (offline known-file prefilter) | dataset_download | none | verified_live | CIRCL open data (NSRL public domain + CIRCL CC0/CC-BY mix). | P350 `offline_hash_sets` approved |
| C0781 | Koodous APK intelligence API (APK search by hash/package; free token) | api | free_key | verified_needs_key | Koodous terms (key-terms). | P346 `mobile_app_impersonation` approved |
| C0795 | Structural / fuzzy hash entity types and pivots (imphash, TLSH, tel... | offline_lib_or_algorithm | none | verified_live | ppdeep ASL 2.0, py-tlsh Apache/BSD, telfhash Apache; abuse.ch data CC0 (terms as P156). | P351 `structural_hash_pivots` approved |

## Vulnerabilities (CVE) (32)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0428 | CIRCL Vulnerability-Lookup | api | none | verified_live | CIRCL open service (CC BY 4.0 data where applicable) | P181 `circl_vulnlookup` approved |
| C0429 | CISA KEV catalog | dataset_download | none | verified_live | [caipora_infra] US Government public data ‖ [live_cti] US public domain | P182 `cisa_kev` approved |
| C0430 | FIRST EPSS API | api | none | verified_live | [caipora_infra] FIRST EPSS terms (free) ‖ [live_cti] FIRST EPSS (free, attribution) | P184 `epss` approved |
| C0431 | MITRE CVE Services API (cveawg) | api | none | verified_live | CVE terms of use (free) | P183 `cve_record` approved |
| C0432 | NVD CVE API 2.0 | api | none | verified_live | [caipora_infra] NIST public data ‖ [live_cti] US public domain | P183 `cve_record` approved |
| C0433 | SecurityContext CVE intelligence API (vulnx backend) | api | none | verified_live | vulnx client MIT. SecurityContext service terms not reviewed - check before production ... | P188 `securitycontext_cve` approved |
| C0434 | Shodan CVEDB | api | none | verified_live | Free for NON-commercial use; commercial use needs a Shodan license (cvedb.shodan.io) | P189 `shodan_cvedb` approved |
| C0435 | Exploit-DB files_exploits.csv (CVE -> public exploit) | dataset_download | none | verified_live | Repository under GPL-2.0: download as external data at runtime, do not vendor into V3LUM | P190 `exploit_index` approved |
| C0436 | Metasploit modules metadata | dataset_download | none | verified_live | BSD-3-Clause | P190 `exploit_index` approved |
| C0437 | OSV.dev API | api | none | verified_live | OSV data CC-BY 4.0 (per-source licenses) | P185 `osv_ghsa` approved |
| C0438 | PoC-in-GitHub (nomi-sec) | dataset_download | none | verified_live | repo metadata of public GitHub projects (no explicit data licence) | P190 `exploit_index` approved |
| C0439 | VulnCheck KEV / NVD++ | api | free_key | verified_needs_key | VulnCheck community terms | P186 `vulncheck` approved |
| C0440 | endoflife.date API | api | none | verified_live | MIT (data) | P187 `endoflife` approved |
| C0441 | ENISA EU Vulnerability Database (EUVD) API | api | none | verified_live | ENISA (EU) public service | P191 `euvd` approved |
| C0442 | GitHub Advisory Database REST API | api | free_key | unverified | GitHub terms; advisory data CC-BY 4.0 | P185 `osv_ghsa` approved |
| C0443 | nuclei-templates cves.json | dataset_download | none | verified_live | MIT | P190 `exploit_index` approved |
| C0444 | trickest/cve | dataset_download | none | verified_live | check repo licence before redistribution | P190 `exploit_index` approved |
| C0445 | CVEdetails API | api | free_key | verified_needs_key | CVEdetails ToS. | P192 `cve_keyed_minor` deferred |
| C0446 | ICHI critical vulnerability advisories (RSS) | api | none | verified_live | Free public feed; terms on ichi.global. | P298 `cti_news_rss` approved |
| C0447 | MITRE CWE REST API | api | none | verified_live | CWE terms of use (free) | P183 `cve_record` approved |
| C0448 | OpenCVE API | api | free_key | verified_needs_key | OpenCVE terms; software AGPL-3 (ideas only). | P192 `cve_keyed_minor` deferred |
| C0449 | VulDB API | api | free_key | verified_needs_key | VulDB ToS (commercial). | P192 `cve_keyed_minor` deferred |
| C0450 | KEVin API (CISA KEV mirror) | api | none | dead | Free. | P193 `reject_kevin` rejected |
| C0451 | CIRCL Vulnerability-Lookup page | url_template | none | verified_live | site terms | P194 `pivots_vulnerability` approved |
| C0452 | CVE reference pages (CVEdetails, Vulners, NVD, Exploit-DB search) | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0453 | Sploitus exploit search | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P194 `pivots_vulnerability` approved |
| C0454 | Rapid7 Vulnerability & Exploit DB | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P194 `pivots_vulnerability` approved |
| C0741 | BushidoUK Ransomware Vulnerability Matrix (CVE -> ransomware groups... | dataset_download | none | verified_live | CC BY 4.0 (LICENSE file verified 2026-11-25; the gap listed it as unchecked). | P372 `ransomware_matrices` approved |
| C0762 | Microsoft MSRC CVRF API v3 (Patch Tuesday: KBs, affected products, ... | api | none | verified_live | Microsoft security update data (public). | P353 `msrc_patch_tuesday` approved |
| C0763 | CSAF 2.0 vendor advisories via provider-metadata.json (Cisco, Sieme... | dataset_download | none | verified_live | Public vendor advisories (CSAF role csaf_trusted_provider); Red Hat states its security... | P354 `csaf_advisories` approved |
| C0764 | CVEProject cvelistV5 bulk mirror (deltaLog + records incl. CISA ADP... | dataset_download | none | verified_live | CVE terms of use (free, attribution); CISA ADP content public domain. | P352 `cve_offline_mirror` approved |
| C0765 | Debian security tracker JSON (per-package CVE status and fixed vers... | dataset_download | none | verified_live | Debian security tracker data (public). | P355 `debian_security_tracker` approved |

## Dark web & ransomware (19)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0455 | Onion v3 address validation (offline) | offline_lib_or_algorithm | none | verified_live | Own implementation of the public Tor spec. | P217 `detector_crypto_onion_validators` approved |
| C0456 | RansomLook API | api | none | verified_live | [caipora_apis_cti] RansomLook software AGPL-3.0 (service use OK; do not copy code witho... | P196 `ransomlook` approved |
| C0457 | Ransomware.live API v2 (free, keyless) | api | none | verified_live | [caipora_apis_cti] Ransomware.live (Julien Mousqueton) - free for research; attribute t... | P197 `ransomware_live` approved |
| C0458 | Ransomware.live PRO API (free key: IOCs, ransom notes, YARA, negoti... | api | free_key | verified_needs_key | Free API key from ransomware.live/my; ToS of ransomware.live. | P197 `ransomware_live` approved |
| C0459 | AIL onion-lookup (CIRCL) - onion service metadata | api | none | verified_live | Service by CIRCL/AIL; software AGPL-3.0. | P199 `onion_lookup` approved |
| C0460 | deepdarkCTI curated dark-web CTI source lists | dataset_download | none | verified_live | GPL-3.0: fetch/parse at runtime, do not copy into V3LUM source. | P198 `deepdarkcti_index` approved; P357 `telegram_channel_watch` approved |
| C0461 | Have I Been Ransomed? (DarkEye) domain metadata | api | free_key | unverified | DarkEye API terms (key from haveibeenransom.com/howapi) | P202 `ransomware_breach_trackers_keyed` rejected |
| C0462 | RansomPosts bulk datasets + Atom feed (privtools; mirror of ransomw... | dataset_download | none | verified_live | ransomposts: EUPL-1.2 (data derived from ransomware.live, attribute both); ransomwatch ... | P200 `ransomposts_bulk` deferred |
| C0463 | spmedia Threat-Actor-Usernames-Scrape (offline dataset) | dataset_download | none | verified_live | MIT (Edmond Major III). | P195 `threat_actor_handles` approved |
| C0464 | Threat Actor Usernames search API | api | none | verified_live | Free community service (3M+ records). | P195 `threat_actor_handles` approved |
| C0465 | Tor exit/relay history: CollecTor exit-lists + mthcht TOR node hist... | dataset_download | none | verified_live | Tor Metrics data is public (CC0-like); mthcht/awesome-lists MIT. | P040 `tor_relays` approved |
| C0466 | Ahmia datasets (onion index list + banned/CSAM filter list); search... | dataset_download | none | verified_live | Ahmia ToS forbids scraping/replicating the service without permission; code BSD-3. | P199 `onion_lookup` approved |
| C0467 | Dark-web news RSS (DarkFeed, Dark Web Informer) | api | none | verified_live | Publisher content (headline + link use only). | P298 `cti_news_rss` approved; P357 `telegram_channel_watch` approved |
| C0468 | Gated Tor search/fetch module (Robin-style multi-engine onion searc... | offline_lib_or_algorithm | none | unverified | MIT (Robin) - adaptable with attribution. | P201 `tor_gated_search` rejected |
| C0469 | RansomLook group page | url_template | none | verified_live | site terms | P203 `pivots_darkweb` approved |
| C0470 | ransomware.live group page | url_template | none | verified_live | site terms | P203 `pivots_darkweb` approved |
| C0471 | Ahmia (Tor search) | url_template | none | unverified | Ahmia terms | P304 `pivots_unverified` approved |
| C0472 | OnionSearchEngine.com clearnet search (pivot) | url_template | none | verified_live | site ToS | P203 `pivots_darkweb` approved |
| C0738 | ransomfeed.it RSS + REST API (ransomware leak-site claims, CC BY 4.0) | api | none | verified_live | Ransomfeed (c) 2026 Dario Fadda, licensed under CC BY 4.0 (site footer): commercial use... | P356 `ransomfeed` approved |

## Crypto assets (39)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0473 | Blockscout API v2 (keyless EVM explorer with scam flags and public ... | api | none | verified_live | Blockscout open-source (GPL-3 server code); hosted API free to use. | P212 `evm_explorers` approved |
| C0474 | Blockstream Esplora API (Bitcoin) | api | none | verified_live | [caipora_apis_cti] Public API of Blockstream (Esplora, MIT-licensed server software; se... | P211 `btc_explorers` approved |
| C0475 | Chainabuse scam reports (TRM Labs; successor of BitcoinAbuse) | api | free_key | verified_needs_key | [caipora_apis_cti] Chainabuse API terms (account required for key). ‖ [live_osint] Chai... | P204 `chainabuse` approved |
| C0476 | Etherscan API V2 (multichain EVM: ETH, BSC, Polygon, Arbitrum, Base... | api | free_key | verified_needs_key | [caipora_apis_cti] Etherscan API ToS (attribution "Powered by Etherscan"). ‖ [live_osin... | P212 `evm_explorers` approved |
| C0477 | GoPlus Security API (malicious address, token, phishing-site checks) | api | none | verified_live | GoPlus Security API terms (free tier). | P206 `goplus_security` approved |
| C0478 | OFAC sanctioned digital currency addresses (0xB10C auto-extracted l... | dataset_download | none | verified_live | [caipora_apis_cti] MIT (repo); underlying OFAC data is US public domain. ‖ [live_osint]... | P205 `crypto_sanctions` approved |
| C0479 | Offline crypto address detection & validation (BTC/LTC/DOGE/DASH/TR... | offline_lib_or_algorithm | none | verified_live | [caipora_apis_cti] Own implementation from public specs (no third-party code). ‖ [live_... | P217 `detector_crypto_onion_validators` approved |
| C0480 | TronGrid API (TRON / USDT-TRC20) | api | none | verified_live | [caipora_apis_cti] TronGrid (TRON DAO) API terms. ‖ [live_osint] TronGrid ToS. | P207 `tron_explorer` approved |
| C0481 | Blockchain.com Data API (rawaddr / balance / multiaddr) | api | none | verified_live | Blockchain.com API terms (free, attribution appreciated). | P211 `btc_explorers` approved |
| C0482 | Blockchair API (40+ chains: BTC, BCH, LTC, DOGE, DASH, ZEC, ETH, XR... | api | none | verified_live | Blockchair API terms; keyless use limited, non-commercial free tier on request. | P211 `btc_explorers` approved |
| C0483 | BlockCypher API (BTC, LTC, DOGE, DASH) + Dogechain fallback | api | none | verified_live | [caipora_apis_cti] BlockCypher API terms (free tier); dogechain.info public API. ‖ [liv... | P211 `btc_explorers` approved |
| C0484 | Chainalysis sanctions oracle (on-chain, keyless) | api | none | verified_live | Chainalysis free sanctions oracle (public contract). | P205 `crypto_sanctions` approved |
| C0485 | Ethplorer API (freekey) | api | none | verified_live | Ethplorer API terms (free with attribution). | P212 `evm_explorers` approved |
| C0486 | mempool.space / litecoinspace.org API (BTC + LTC, Esplora-compatible) | api | none | verified_live | [caipora_apis_cti] mempool open-source project (AGPL-3 server code, self-hostable); pub... | P211 `btc_explorers` approved |
| C0487 | ScamSniffer crypto-phishing domain blocklist | dataset_download | none | verified_live | GPL-3.0 repository: fetch at runtime, do not vendor the list into V3LUM code. | P071 `url_domain_blocklists` approved |
| C0488 | Stablecoin issuer blacklist check (USDT/USDC on-chain) | offline_lib_or_algorithm | none | verified_live | Reads public blockchain state; RPC provider ToS apply. | P205 `crypto_sanctions` approved |
| C0489 | WalletExplorer API (Bitcoin wallet clustering + service labels) | api | none | verified_live | WalletExplorer (Ales Janda) free API; attribution. | P208 `walletexplorer` approved |
| C0490 | Chainalysis free sanctions screening REST API | api | free_key | verified_needs_key | Chainalysis free API terms. | P205 `crypto_sanctions` approved |
| C0491 | ENS name resolution (ensdata.net) | api | none | verified_live | [caipora_apis_cti] ensdata.net public API. ‖ [live_osint] ENSData terms. | P209 `ens_resolver` approved |
| C0492 | MetaMask eth-phishing-detect config (blacklist + fuzzy look-alike l... | dataset_download | none | verified_live | "Don't Be A Dick" public license (permissive). | P071 `url_domain_blocklists` approved |
| C0493 | Public Ethereum JSON-RPC (PublicNode) | api | none | verified_live | PublicNode (Allnodes) ToS. | P212 `evm_explorers` approved |
| C0494 | Ransomwhere ransomware payment addresses | dataset_download | none | verified_live | Open crowdsourced dataset - cite ransomwhe.re | P210 `ransomwhere` approved |
| C0495 | TON: Toncenter API + Telegram +888 / collectible-username owner loo... | api | none | verified_live | Toncenter/TonAPI terms; a_TON_of_privacy is MIT (code adaptable with attribution). | P214 `ton_explorer` approved |
| C0496 | Transaction-graph expansion with stop-nodes (Orbit-style BFS) | offline_lib_or_algorithm | none | unverified | Orbit is GPL-3: ideas only, no code copying. | P213 `crypto_tx_graph` approved |
| C0497 | Tronscan API | api | free_key | verified_needs_key | Tronscan API terms. | P207 `tron_explorer` approved |
| C0498 | Bitaps Bitcoin API | api | none | verified_live | Bitaps public API. | P211 `btc_explorers` approved |
| C0499 | Honeypot.is token honeypot check | api | none | verified_live | Honeypot.is terms | P206 `goplus_security` approved |
| C0500 | OKLink Explorer API (multi-chain incl. BTC/TRON/EVM) | api | free_key | verified_needs_key | OKLink API terms. | P212 `evm_explorers` approved |
| C0501 | SoChain v3 (BTC/LTC/DOGE/ZEC) | api | free_key | verified_live | SoChain terms. | P211 `btc_explorers` approved |
| C0502 | Solana public JSON-RPC | api | none | verified_live | Solana Foundation public RPC (best-effort, no SLA). | P215 `solana_rpc` approved |
| C0503 | Blockchain explorer pivot links (BTC + EVM + TRON) | url_template | none | verified_live | each site ToS | P216 `pivots_crypto` approved |
| C0504 | BitcoinWhosWho address report | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P216 `pivots_crypto` approved |
| C0505 | Chainabuse address reports | url_template | none | unverified | Free web UI; provider ToS apply (manual analyst use) | P304 `pivots_unverified` approved |
| C0506 | WalletExplorer address page | url_template | none | verified_live | WalletExplorer ToS. | P216 `pivots_crypto` approved |
| C0507 | Blockchain.com explorer page | url_template | none | verified_live | Blockchain.com ToS. | P216 `pivots_crypto` approved |
| C0508 | Blockchair address page | url_template | none | verified_live | Blockchair ToS. | P216 `pivots_crypto` approved |
| C0509 | Ethplorer address page | url_template | none | verified_live | Ethplorer ToS. | P216 `pivots_crypto` approved |
| C0787 | GraphSense public TagPacks (address -> actor / category attribution... | dataset_download | none | verified_live | MIT (LICENSE verified); tags must come from public sources and contain no PII (reposito... | P358 `crypto_address_labels` approved |
| C0788 | Exchange proof-of-reserves address lists (OKX signed address list, ... | dataset_download | none | unverified | Exchange website terms (manual download for internal labelling). | P358 `crypto_address_labels` approved |

## Companies & organizations (36)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0510 | Minha Receita | api | none | verified_live | [caipora_br_gov] MIT (moved from GitHub to Codeberg; GitHub repo now only a README) ‖ [... | P236 `cnpj_lookup` approved |
| C0511 | OFAC SDN list (Sanctions List Service exports) | dataset_download | none | verified_live | [caipora_infra] US Government public data ‖ [live_osint] US Government work - public do... | P219 `sanctions_lists` approved |
| C0512 | RFB CNPJ open data bulk (WebDAV) | dataset_download | none | verified_live | [caipora_br_gov] Dados abertos RFB (public) ‖ [design_ceos] Receita Federal open data (... | P238 `rfb_cnpj_bulk` approved |
| C0513 | CNPJa open API | api | none | verified_live | CNPJa terms: free public tier; commercial API is paid | P236 `cnpj_lookup` approved |
| C0514 | Company risk signals + cross-company coincidences | offline_lib_or_algorithm | none | unverified | team-owned | P258 `correlation_pack_identity_company` approved |
| C0515 | GLEIF LEI API (legal entities, incl. CNPJ <-> LEI) | api | none | verified_live | [caipora_br_gov] GLEIF data CC0 ‖ [live_osint] CC0 1.0. | P220 `gleif` approved; P361 `cnpj_name_resolver` approved |
| C0516 | ICIJ Offshore Leaks database (reconcile API + bulk CSV) | api | none | verified_live | [caipora_br_gov] ICIJ Offshore Leaks DB: ODbL database / CC BY-SA contents, attribution... | P221 `icij_offshore` approved |
| C0517 | Microsoft Entra ID tenant discovery (OpenID config + GetUserRealm) | api | none | verified_live | [caipora_infra] Public Microsoft identity endpoints ‖ [caipora_people] Microsoft public... | P011 `m365_tenant` approved |
| C0518 | OpenCNPJ | api | none | verified_live | free public API over RFB open data (check site terms) | P236 `cnpj_lookup` approved |
| C0519 | OpenSanctions (API + bulk datasets) | api | free_key | verified_needs_key | Data CC BY-NC 4.0 - commercial/corporate use requires a paid licence. | P222 `opensanctions` approved |
| C0520 | publica.cnpj.ws | api | none | verified_live | [caipora_br_gov] cnpj.ws public tier terms; commercial tier needs token ‖ [live_osint] ... | P236 `cnpj_lookup` approved |
| C0521 | Sanctions screening lists: UN consolidated, EU FSF, OpenSanctions | dataset_download | none | verified_live | [caipora_apis_cti] UN/EU lists: public. OpenSanctions data CC BY-NC 4.0 - business use ... | P219 `sanctions_lists` approved |
| C0522 | SEC EDGAR (submissions + full-text search) | api | none | verified_live | US Government - public domain. | P223 `sec_edgar` approved |
| C0523 | Wikidata (wbsearchentities + SPARQL) | api | none | verified_live | CC0. | P224 `wikidata` approved; P361 `cnpj_name_resolver` approved |
| C0524 | EU Financial Sanctions Files (FSF) | dataset_download | none | verified_live | EU open data (reuse with attribution). | P219 `sanctions_lists` approved |
| C0525 | EU VIES VAT validation (official REST) | api | none | verified_live | Official EC service, free. | P225 `eu_vies` approved |
| C0526 | NetworksDB.io organisation -> IP ranges | api | free_key | verified_needs_key | NetworksDB terms. Flow taken from corptrace (AGPL) -> reimplement. | P218 `networksdb` approved |
| C0527 | OpenCorporates API | api | free_key | verified_needs_key | [caipora_apis_cti] Data ODbL (share-alike, attribution). ‖ [live_osint] Paid for commer... | P226 `opencorporates` deferred |
| C0528 | Querido Diario company info/partners | api | none | verified_live | Open Knowledge Brasil API (open data) | P236 `cnpj_lookup` approved |
| C0529 | ReceitaWS | api | none | verified_live | [caipora_br_gov] ReceitaWS terms; free tier may serve cached data ‖ [live_osint] Receit... | P236 `cnpj_lookup` approved |
| C0530 | UK Companies House API | api | free_key | verified_needs_key | UK Open Government Licence | P227 `uk_companies_house` approved |
| C0531 | dilisense AML screening API | api | free_key | verified_needs_key | dilisense commercial terms. | P230 `sanctions_api_second_opinion` rejected |
| C0532 | IANA Private Enterprise Numbers registry | dataset_download | none | verified_live | IANA public registry | P228 `iana_pen` approved |
| C0533 | LittleSis power-network API | api | none | verified_live | CC BY-SA 4.0 | P229 `littlesis` rejected |
| C0534 | W System sanctions screening (EU/UN/OFAC/UK) | api | none | verified_live | W System commercial terms. | P230 `sanctions_api_second_opinion` rejected |
| C0535 | Open Ownership Register | api | none | dead | public open data / free public API | P249 `reject_br_blocked_or_stale` rejected |
| C0536 | VATComply (VIES wrapper) | api | none | verified_live | Free open-source service (check its repository licence before reuse). | P225 `eu_vies` approved |
| C0537 | ViewDNS reverse WHOIS | url_template | none | verified_live | [caipora_infra] Free web UI; provider ToS apply (manual analyst use) ‖ [gh_infra] ViewD... | P231 `pivots_company_org` approved |
| C0538 | Meta Ad Library search (pivot) | url_template | none | unverified | Meta terms (official Ad Library API needs a verified developer identity) | P304 `pivots_unverified` approved |
| C0539 | OpenSanctions web search | url_template | none | verified_live | Free web UI (licence restrictions apply to bulk/API). | P231 `pivots_company_org` approved |
| C0540 | UK Companies House web search | url_template | none | verified_live | public open data / free public API | P231 `pivots_company_org` approved |
| C0753 | GDELT DOC 2.0 API (keyless global news search with sourcelang / sou... | api | none | verified_live | GDELT terms (about.html): datasets 'available for unlimited and unrestricted use for an... | P253 `adverse_media_rss` approved |
| C0758 | GitHub REST organisation endpoints (search users type:org, /orgs/{o... | api | none | verified_live | GitHub API terms. | P359 `org_code_footprint` approved |
| C0759 | GitLab groups API (search with top_level_only + group projects) | api | none | verified_live | GitLab API terms. | P359 `org_code_footprint` approved |
| C0760 | Codeberg / Forgejo organisation API (org profile + repositories) | api | none | verified_live | Codeberg terms. | P359 `org_code_footprint` approved |
| C0761 | PyPI organisation pages (HTML: organisation -> projects) | scrape | none | verified_live | PyPI terms of use. | P359 `org_code_footprint` approved |

## Brazil public data (48)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0541 | BrasilAPI CNPJ | api | none | verified_live | [caipora_br_gov] code MIT (BrasilAPI/BrasilAPI); data = RFB CNPJ open data ‖ [design_ce... | P236 `cnpj_lookup` approved |
| C0542 | CNPJ validator incl. new alphanumeric CNPJ | offline_lib_or_algorithm | none | verified_live | [caipora_br_gov] own implementation of public specifications ‖ [design_ceos] team-owned | P232 `br_validators` approved |
| C0543 | Portal da Transparencia API (CGU) | api | free_key | verified_needs_key | [caipora_br_gov] Open government data (CGU); free key by e-mail registration (gov.br lo... | P237 `portal_transparencia_api` approved |
| C0544 | registro.br RDAP (.br domain -> registrant CNPJ) | api | none | verified_live | [caipora_br_gov] NIC.br RDAP terms (notices[] Use and Privacy Policy) ‖ [caipora_infra]... | P003 `rdap` approved |
| C0545 | TCU consolidated certificates API | api | none | verified_live | official public service (TCU) | P239 `tcu_certidoes` approved |
| C0546 | Boleto parser (bancario 47 / arrecadacao 48 digits) | offline_lib_or_algorithm | none | verified_live | own implementation of public specifications | P233 `boleto_pix` approved |
| C0547 | BrasilAPI CEP v2 | api | none | verified_live | [caipora_br_gov] MIT code; multi-provider (ViaCEP, OpenCEP, Correios...) ‖ [live_osint]... | P234 `cep_lookup` approved |
| C0548 | CGU bulk sanctions downloads (CEIS/CNEP/CEPIM/Leniencia) | dataset_download | none | verified_live | [caipora_br_gov] Open government data (CGU) ‖ [live_osint] CGU open data. | P240 `cgu_sanctions_bulk` approved |
| C0549 | CNJ unified process number parser -> DataJud router | offline_lib_or_algorithm | none | verified_live | own implementation of public specifications | P241 `datajud` approved |
| C0550 | CPF validator + fiscal-region digit | offline_lib_or_algorithm | none | verified_live | own implementation of public specifications | P232 `br_validators` approved |
| C0551 | DataJud CNJ public API | api | none | verified_live | [caipora_br_gov] CNJ terms of use (Portaria 160/2020); the API key is PUBLIC and publis... | P241 `datajud` approved |
| C0552 | DOU search (Diario Oficial da Uniao) | scrape | none | verified_live | [caipora_br_gov] Official gazette (public); low-volume scraping of the public search pa... | P242 `dou_search` approved |
| C0553 | PIX key type detector + BR Code (Pix copia-e-cola / QR) parser | offline_lib_or_algorithm | none | verified_live | own implementation of public specifications | P233 `boleto_pix` approved |
| C0554 | Querido Diario gazette search API | api | none | verified_live | [caipora_br_gov] Open Knowledge Brasil (open data / MIT tooling) ‖ [live_osint] Open Kn... | P243 `querido_diario` approved |
| C0555 | ViaCEP (CEP + reverse address search) | api | none | verified_live | [caipora_br_gov] Free public service ‖ [live_osint] ViaCEP free service. | P234 `cep_lookup` approved |
| C0556 | BCB STR participants CSV (bank code / ISPB table) | dataset_download | none | verified_live | Banco Central do Brasil public data | P233 `boleto_pix` approved |
| C0557 | BrasilAPI banks + PIX participants | api | none | verified_live | [caipora_br_gov] MIT code; BCB data ‖ [live_osint] BrasilAPI (MIT) / Banco Central data. | P233 `boleto_pix` approved |
| C0558 | BrasilAPI registro.br availability | api | none | verified_live | BrasilAPI (MIT). | P021 `registrobr_domain_status` approved |
| C0559 | Camara dos Deputados open data API | api | none | verified_live | [caipora_br_gov] Open government data ‖ [live_osint] Brazilian open data (LAI). | P245 `br_politics_pep` rejected |
| C0560 | Casa dos Dados scraper (name -> companies/partner roles) | scrape | none | unverified | [caipora_br_gov] public open data / free public API ‖ [design_ceos] third-party site te... | P249 `reject_br_blocked_or_stale` rejected |
| C0561 | CVM open data (issuers, intermediaries, sanctions) | dataset_download | none | verified_live | [caipora_br_gov] Open government data (CVM, ODbL-like terms on portal) ‖ [live_osint] C... | P244 `br_cnpj_risk_lists` approved |
| C0562 | Escavador API v2 | api | paid_key | verified_needs_key | Escavador commercial ToS | P247 `escavador` deferred |
| C0563 | IBGE Localidades API | api | none | verified_live | IBGE open data | P234 `cep_lookup` approved |
| C0564 | MTE Lista Suja (employers using slave-like labour) | dataset_download | none | verified_live | Official public register (MTE) | P244 `br_cnpj_risk_lists` approved |
| C0565 | PGFN Divida Ativa da Uniao open data | dataset_download | none | verified_live | Open government data (PGFN) | P244 `br_cnpj_risk_lists` approved |
| C0566 | PNCP API (national public procurement portal) | api | none | error | Open government API | P246 `br_public_spending` approved |
| C0567 | Receita code tables + CNAE sector and sensitive-division map | offline_lib_or_algorithm | none | unverified | team-owned (data from Receita public tables) | P235 `cnae_tables` approved |
| C0568 | ANAC RAB aircraft registry dataset | dataset_download | none | verified_live | Open government data (ANAC) | P248 `anac_rab` approved |
| C0569 | AwesomeAPI CEP | api | none | error | public open data / free public API | P234 `cep_lookup` approved |
| C0570 | BNDES open data (financing operations) | api | none | verified_live | Open data (BNDES CKAN) | P246 `br_public_spending` approved |
| C0571 | Brasil.IO API | api | free_key | verified_needs_key | Brasil.IO terms (CC BY-SA data) | P249 `reject_br_blocked_or_stale` rejected |
| C0572 | BrasilAPI CVM brokers | api | none | verified_live | MIT code; CVM open data | P244 `br_cnpj_risk_lists` approved |
| C0573 | CEP -> UF range table | offline_lib_or_algorithm | none | verified_live | own implementation of public specifications | P234 `cep_lookup` approved |
| C0574 | Compras.gov.br dados abertos API | api | none | error | Open government API (spec at /v3/api-docs) | P246 `br_public_spending` approved |
| C0575 | dados.gov.br catalog API | api | free_key | verified_needs_key | Open government data (key via gov.br account) | P249 `reject_br_blocked_or_stale` rejected |
| C0576 | IBGE CNAE API | api | none | verified_live | IBGE open data | P235 `cnae_tables` approved |
| C0577 | OpenCEP | api | none | verified_live | public open data / free public API | P234 `cep_lookup` approved |
| C0578 | Other BR identifiers (titulo de eleitor, PIS/NIS, RENAVAM, CNS, CNH) | offline_lib_or_algorithm | none | unverified | own implementation of public specifications | P232 `br_validators` approved |
| C0579 | SALIC API (Lei Rouanet) | api | none | verified_live | Open government API (MinC) | P246 `br_public_spending` approved |
| C0580 | TSE DivulgaCandContas REST | api | none | error | Official public data (TSE) | P245 `br_politics_pep` rejected |
| C0581 | TSE open data portal (CKAN) | dataset_download | none | verified_live | Official open data (TSE) | P245 `br_politics_pep` rejected |
| C0582 | Vehicle plate validator / old<->Mercosul converter | offline_lib_or_algorithm | none | verified_live | own implementation of public specifications | P232 `br_validators` approved |
| C0583 | BNMP arrest-warrant search (CNJ) | api | none | error | public open data / free public API | P255 `reject_br_people_search` rejected |
| C0584 | Portal da Transparencia web search | url_template | none | verified_live | public open data / free public API | P250 `pivots_brazil` approved |
| C0743 | RFB light company-name index (Empresas + Estabelecimentos files onl... | offline_lib_or_algorithm | none | verified_live | RFB open data (free reuse). | P361 `cnpj_name_resolver` approved |
| C0744 | CVM open-data CKAN API + cadastral registries (listed companies, in... | api | none | verified_live | Open Database License (ODbL) per CKAN metadata: internal use fine; share-alike only if ... | P360 `bcb_authorized_institutions` approved; P361 `cnpj_name_resolver` approved |
| C0745 | BCB Olinda 'Instituicoes_em_funcionamento' v1 (verified domains and... | api | none | verified_live | BCB open data (dados abertos). | P360 `bcb_authorized_institutions` approved; P361 `cnpj_name_resolver` approved |
| C0770 | CNJ DJEN / Comunica PJe public API (Diario de Justica Eletronico Na... | api | none | unverified | Official public court communications (CNJ Resolucao 455/2022). | P362 `djen_court_communications` approved |

## People (names) (12)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0585 | Identity resolution / anti-homonym rules (CPF-aware) | offline_lib_or_algorithm | none | unverified | team-owned | P258 `correlation_pack_identity_company` approved |
| C0586 | Name -> username/email permutator + spelling variants (offline) | offline_lib_or_algorithm | none | verified_live | [caipora_people] NAMINT is MIT (adaptable); own implementation ‖ [gh_infra] Re-implemen... | P251 `name_permutations` approved |
| C0587 | Adverse-media search via Google News RSS | api | none | error | Google News RSS (unofficial, ToS-sensitive) | P253 `adverse_media_rss` approved |
| C0588 | IBGE nomes API (first-name frequency) | api | none | verified_live | [caipora_br_gov] IBGE open data (aggregated, no personal data) ‖ [live_osint] IBGE open... | P252 `ibge_name_frequency` approved |
| C0589 | FBI Wanted API (incl. Cyber's Most Wanted) | api | none | verified_live | US government public information. | P254 `wanted_notices` approved |
| C0590 | INTERPOL public notices API | api | none | error | INTERPOL terms (public notices) | P254 `wanted_notices` approved |
| C0591 | BCB "Valores a Receber" REST endpoint | api | none | unverified | public open data / free public API | P255 `reject_br_people_search` rejected |
| C0592 | BuscaPrime | scrape | none | unverified | public open data / free public API | P255 `reject_br_people_search` rejected |
| C0593 | CPF brute-force / discovery scripts | offline_lib_or_algorithm | none | unverified | public open data / free public API | P255 `reject_br_people_search` rejected |
| C0594 | Genderize / Agify / Nationalize name statistics | api | none | verified_live | Demografix terms. | P256 `reject_demographic_inference` rejected |
| C0595 | Tudo Sobre Todos | scrape | paid_key | unverified | public open data / free public API | P255 `reject_br_people_search` rejected |
| C0596 | Webmii person web-presence (pivot) | url_template | none | verified_live | site terms | P257 `pivots_person` approved |

## Geo, images & metadata (20)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0597 | Pillow EXIF/GPS extraction | offline_lib_or_algorithm | none | verified_live | [caipora_people] Pillow HPND, exif-py BSD-3; ExifTool Artistic/GPL (call as external bi... | P259 `image_metadata` approved |
| C0598 | beaconDB Wi-Fi/cell geolocation | api | none | verified_live | beaconDB (community successor to Mozilla Location Service) - check beacondb.net for dat... | P263 `wifi_geolocation` deferred |
| C0599 | ExifRead | offline_lib_or_algorithm | none | unverified | BSD-3-Clause (LICENSE: Gene Cash, Ianare Sevi and contributors). | P259 `image_metadata` approved |
| C0600 | Nominatim (OpenStreetMap) geocoding | api | none | verified_live | [design_ceos] ODbL - attribution '© OpenStreetMap contributors' on maps ‖ [gh_infra] OD... | P262 `geocoding` approved |
| C0601 | Overpass API (POIs around coordinates) | api | none | error | ODbL. | P262 `geocoding` approved |
| C0602 | Photon geocoder (komoot) | api | none | verified_live | ODbL (OSM data); Photon Apache-2.0 (self-hostable). | P262 `geocoding` approved |
| C0603 | Error Level Analysis (image tamper heuristic) | offline_lib_or_algorithm | none | verified_live | own implementation (Pillow) | P264 `image_ela` approved |
| C0604 | Mylnikov Wi-Fi/cell geolocation (BSSID -> lat/lon) | api | none | verified_live | Open data mode uses community datasets. | P263 `wifi_geolocation` deferred |
| C0605 | Plate Recognizer ALPR API | api | free_key | verified_needs_key | Plate Recognizer commercial ToS | P265 `reject_plate_recognizer` rejected |
| C0606 | WiGLE Wi-Fi BSSID/SSID geolocation | api | free_key | verified_needs_key | WiGLE ToS: free accounts non-commercial; commercial use needs a license. geowifi has no... | P263 `wifi_geolocation` deferred |
| C0607 | Facial-recognition search engines - FLAGGED | api | paid_key | unverified | commercial | P266 `reject_facial_recognition` rejected |
| C0608 | geocode.xyz geocoding/geoparsing | api | none | error | Free tier throttled; paid auth key. | P262 `geocoding` approved |
| C0609 | Google Lens reverse image search by URL (pivot) | url_template | none | verified_live | Google ToS | P260 `pivots_geo_image` approved |
| C0610 | Yandex reverse image search by URL (pivot) | url_template | none | verified_live | Yandex ToS | P260 `pivots_geo_image` approved |
| C0611 | ImgOps meta reverse-image launcher (pivot) | url_template | none | verified_live | site terms | P260 `pivots_geo_image` approved |
| C0612 | TinEye reverse image search by URL (pivot) | url_template | none | verified_live | TinEye ToS | P260 `pivots_geo_image` approved |
| C0613 | Bing Visual Search by URL (pivot) | url_template | none | error | Microsoft ToS | P309 `reject_pivots_broken` rejected |
| C0614 | Google Maps URL scheme | url_template | none | verified_live | Google Maps ToS. | P260 `pivots_geo_image` approved |
| C0615 | OpenStreetMap map link | url_template | none | verified_live | ODbL. | P260 `pivots_geo_image` approved |
| C0782 | Tesseract OCR via pytesseract (por + eng tessdata_fast models), pyp... | offline_lib_or_algorithm | none | verified_live | Tesseract and tessdata_fast Apache-2.0; pytesseract Apache-2.0; pypdf BSD-3-Clause; alt... | P363 `image_ocr` approved |

## File analysis (21)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0616 | LOLDrivers dataset | dataset_download | none | verified_live | Apache-2.0 | P268 `lol_datasets` approved |
| C0617 | oletools / olefile (maldoc triage) | offline_lib_or_algorithm | none | unverified | BSD-2-Clause (python-oletools; the thirdparty/ folder has its own licenses); olefile BSD. | P269 `document_metadata` approved |
| C0618 | pefile (PE header/imports/imphash) | offline_lib_or_algorithm | none | unverified | MIT (Copyright 2004-2024 Ero Carrera). | P271 `pe_triage` approved |
| C0619 | Document metadata extraction (PDF info/XMP via pypdf + OOXML/ODF do... | offline_lib_or_algorithm | none | verified_live | [caipora_people] pypdf BSD-3, olefile BSD-2, stdlib ‖ [gh_cti_ioc] pypdf 7.1.1 = BSD-3-... | P269 `document_metadata` approved |
| C0620 | V3LUM magic-byte file-type sniffer | offline_lib_or_algorithm | none | verified_live | Own code. | P270 `file_type_sniff` approved |
| C0621 | yara-python + YARA Forge rule packages | dataset_download | none | verified_live | yara-python Apache-2.0; YARA Forge aggregates rules from many repos - each rule keeps i... | P272 `yara_scan` approved |
| C0622 | filetype.py | offline_lib_or_algorithm | none | unverified | MIT (Copyright 2016 Tomas Aparicio). | P270 `file_type_sniff` approved |
| C0623 | HijackLibs dataset | dataset_download | none | verified_live | HijackLibs project (check license; data published openly with attribution) | P268 `lol_datasets` approved |
| C0624 | Identity signals in free text / PDFs (name windows + nearest CPF) | offline_lib_or_algorithm | none | unverified | team-owned; pypdf BSD-3 | P273 `document_identity_signals` approved |
| C0625 | Magika (Google, ML content-type detection) | offline_lib_or_algorithm | none | unverified | Apache-2.0. | P270 `file_type_sniff` approved |
| C0626 | ppdeep (pure-Python ssdeep) | offline_lib_or_algorithm | none | unverified | Apache-2.0 (setup.py "ASL 2.0"). | P267 `file_hashing` approved |
| C0627 | py-tlsh (TLSH fuzzy hash) | offline_lib_or_algorithm | none | unverified | Apache-2.0 or BSD-3-Clause (dual). | P267 `file_hashing` approved; P351 `structural_hash_pivots` approved |
| C0628 | python-magic (libmagic binding) | offline_lib_or_algorithm | none | unverified | MIT (binding); libmagic BSD-2. | P270 `file_type_sniff` approved |
| C0629 | extract-msg (Outlook .msg parser, reference) | offline_lib_or_algorithm | none | unverified | GPL-3.0 (PyPI) - ideas only. | P085 `email_header_analyzer` approved |
| C0630 | hachoir (metadata for 50+ formats) | offline_lib_or_algorithm | none | unverified | GPL-2.0 - ideas only. | P270 `file_type_sniff` approved |
| C0747 | androguard APK static triage (manifest, permissions, components, si... | offline_lib_or_algorithm | none | verified_live | Apache-2.0 (repository LICENCE file; the PyPI classifier wrongly says 'Other/Proprietar... | P364 `apk_triage` approved |
| C0748 | LnkParse3 Windows shortcut (LNK) parser | offline_lib_or_algorithm | none | verified_live | MIT. | P367 `windows_artifact_triage` approved |
| C0749 | Archive and disk-image listing (zipfile/tarfile stdlib, rarfile ISC... | offline_lib_or_algorithm | none | verified_live | stdlib (PSF), rarfile ISC, py7zr LGPL-2.1-or-later, pycdlib LGPL-2.1-only (dynamic impo... | P365 `archive_listing` approved |
| C0750 | MSI and OneNote parsers (olefile/oletools BSD for MSI tables & Cust... | offline_lib_or_algorithm | none | verified_live | olefile/oletools BSD, pymsi MIT, pyOneNote Apache-2.0 (licence verified on PyPI). | P367 `windows_artifact_triage` approved |
| C0751 | Script de-obfuscation for triage (PowerShell -EncodedCommand, JS/VB... | offline_lib_or_algorithm | none | unverified | V3LUM code (techniques are public; no GPL tool code copied). | P366 `script_decoder` approved |
| C0752 | ELF basic triage (pyelftools headers/sections/dynamic imports/inter... | offline_lib_or_algorithm | none | verified_live | pyelftools public domain; telfhash Apache. | P368 `elf_triage` approved |

## Pentest & recon (25)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0631 | can-i-take-over-xyz subdomain-takeover fingerprints | dataset_download | none | verified_live | [design_ceos] CC-BY-4.0 data: attribution required ‖ [gh_infra] CC-BY-4.0 (data may be ... | P276 `subdomain_takeover` approved |
| C0632 | TLS certificate & protocol inspection (+ interception detection) | offline_lib_or_algorithm | none | verified_live | stdlib (PSF) + cryptography (Apache-2.0/BSD) | P275 `tls_inspect` approved; P277 `tls_protocol_scan` approved; P329 `tls_interception_check` approved |
| C0633 | CDN origin-IP hypothesis builder (CloakQuest3r / Cloudmare technique) | offline_lib_or_algorithm | free_key | unverified | CloakQuest3r MIT (adaptable); Cloudmare AGPL-3.0 (ideas only). | P278 `cdn_origin_hypothesis` approved |
| C0634 | Favicon hash (Shodan-compatible mmh3) + MD5/SHA256 | offline_lib_or_algorithm | none | verified_live | [caipora_infra] favihunter MIT (engine URL list in engines.yaml) ‖ [caipora_people] fav... | P062 `favicon_hash` approved |
| C0635 | jsluice JavaScript endpoint & secret extraction | offline_lib_or_algorithm | none | unverified | MIT (matcher lists portable with attribution). | P068 `js_endpoints` approved |
| C0636 | Postman public workspace / collection search | api | none | verified_live | Postman ToS; undocumented website API (can change). bbot code AGPL-3.0 -> reimplement. | P069 `public_api_exposure` approved |
| C0637 | Sensitive file exposure checks (.git/HEAD, .env, backups, .DS_Store... | offline_lib_or_algorithm | none | unverified | own code (ideas from nuclei exposures templates, MIT) | P279 `sensitive_files` approved |
| C0638 | wafw00f WAF fingerprint signatures | offline_lib_or_algorithm | none | unverified | [caipora_cli] MIT (web-check) - table portable with attribution. ‖ [design_ceos] wafw00... | P072 `web_fingerprint` approved; P280 `waf_active_probe` rejected |
| C0639 | Active subdomain takeover verifier (multi-resolver + wildcard probe) | offline_lib_or_algorithm | none | unverified | GPL-2.0 (theHarvester): re-implement the idea, do not copy code | P276 `subdomain_takeover` approved |
| C0640 | Cloud storage bucket permutations (S3 / GCS / Azure Blob / DO Spaces) | offline_lib_or_algorithm | none | verified_live | [caipora_infra] Own code ‖ [gh_infra] Re-implementation (MIT idea) | P282 `cloud_buckets` approved |
| C0641 | Common API path discovery | offline_lib_or_algorithm | none | unverified | GPL-2.0 (idea only) | P285 `path_discovery` approved |
| C0642 | CORS misconfiguration probe | offline_lib_or_algorithm | none | verified_live | own code | P283 `cors_probe` approved |
| C0643 | DNS zone transfer (AXFR) test | offline_lib_or_algorithm | none | unverified | [design_ceos] dnspython ISC ‖ [gh_infra] Re-implementation (MIT idea) | P281 `axfr` approved |
| C0644 | Employee-name harvesting via search-engine X-ray (CrossLinked-style) | scrape | free_key | unverified | CrossLinked is GPL-3.0 -> ideas only | P289 `employee_xray` approved |
| C0645 | JARM active TLS server fingerprint | offline_lib_or_algorithm | none | unverified | BSD-3-Clause (Salesforce) - adapt with attribution. JA3S is superseded; JA4 (client) is... | P284 `jarm` approved |
| C0646 | LeakIX host lookup | api | free_key | verified_needs_key | [caipora_infra] LeakIX terms ‖ [gh_infra] LeakIX ToS | P274 `leakix` approved |
| C0647 | Public-document discovery for a domain (metagoofil-style) | scrape | free_key | unverified | Metagoofil GPL-2.0 / PyMeta GPL-3.0 -> ideas only | P287 `public_docs_discovery` approved |
| C0648 | TCP connect port scan (top-N) + banner grab | offline_lib_or_algorithm | none | unverified | own code | P286 `port_scan` approved |
| C0649 | Check-Host.net multi-location checks | api | none | verified_live | Free service terms | P288 `check_host` deferred |
| C0650 | SecLists wordlists (for gated active modules) | dataset_download | none | unverified | MIT | P285 `path_discovery` approved; P370 `dns_bruteforce` approved |
| C0651 | GrayhatWarfare public buckets search | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P290 `pivots_pentest` approved |
| C0652 | SSL Labs report page (pivot) | url_template | none | verified_live | Qualys terms | P290 `pivots_pentest` approved |
| C0783 | Subdomain permutation patterns (alterx / dnsgen style: word, number... | offline_lib_or_algorithm | none | verified_live | alterx MIT, dnsgen MIT (2025 Aleph Null), SecLists MIT (all licences verified). | P370 `dns_bruteforce` approved |
| C0784 | nuclei engine + nuclei-templates allow-list (exposures / misconfigu... | offline_lib_or_algorithm | none | verified_live | nuclei and nuclei-templates MIT (verified). | P369 `nuclei_runner` approved |
| C0797 | SaaS tenant discovery endpoints (Okta openid-configuration differen... | api | none | verified_live | Vendor public endpoints (no authentication). | P371 `saas_tenant_discovery` approved |

## CTI frameworks (ATT&CK, actors) (31)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0653 | MISP Galaxy clusters (threat actors, ransomware, malware families, ... | dataset_download | none | verified_live | [caipora_apis_cti] Dual CC0 1.0 / BSD-2-Clause (bundle-able). ‖ [gh_cti_ioc] Dual-licen... | P295 `actor_alias_index` approved |
| C0654 | MITRE ATT&CK Enterprise (STIX 2.1 bundle) | dataset_download | none | verified_live | [caipora_infra] ATT&CK terms of use (free, attribution) ‖ [design_ceos] MITRE ATT&CK te... | P292 `attack_index` approved |
| C0655 | Risk-scoring model (severity x confidence x reliability x decay, no... | offline_lib_or_algorithm | none | verified_live | own model; MISP decay formula is public | P302 `risk_model` approved |
| C0656 | SpiderFoot correlation-rule engine (YAML rules) | offline_lib_or_algorithm | none | unverified | [design_ceos] SpiderFoot MIT: engine design and its 37 rules may be adapted with attrib... | P301 `correlation_engine` approved |
| C0657 | ETDA/ThaiCERT Threat Group Cards (actor + tool encyclopedia) | dataset_download | none | verified_live | [caipora_apis_cti] No explicit license (c) ETDA/ThaiCERT, published free: attribute, fe... | P295 `actor_alias_index` approved |
| C0658 | Malpedia API (actor/family lookup) | api | none | verified_live | [caipora_apis_cti] Content CC BY-NC-SA 3.0 (non-commercial!); non-public material TLP:A... | P296 `malpedia` approved |
| C0659 | MalwareIntel knowledge-graph API | api | none | verified_live | Free platform aggregating 70-100+ public CTI feeds; no explicit licence for data - attr... | P297 `malwareintel` deferred |
| C0660 | mihari rule-based hunting & alerting engine (design reference) | offline_lib_or_algorithm | none | unverified | MIT (Ruby) - patterns adaptable. | P030 `watch_mode` approved |
| C0661 | MISP / OpenCTI / IntelOwl interoperability (STIX 2.1 + MISP event e... | offline_lib_or_algorithm | none | unverified | stix2 (BSD-3), PyMISP (BSD-2), pycti (Apache-2.0) usable as deps; IntelOwl AGPL (ideas ... | P303 `export_stix_misp` approved |
| C0662 | MITRE ATT&CK TAXII 2.1 | api | none | verified_live | [gh_cti_ioc] MITRE ATT&CK Terms of Use (same notice). ‖ [live_cti] ATT&CK terms of use ... | P292 `attack_index` approved |
| C0663 | ORKL CTI report library | api | none | verified_live | Community-driven CTI library; reports keep their publishers' copyright - store referenc... | P293 `orkl` approved |
| C0664 | SpiderFoot event-type model + data-source auth taxonomy | offline_lib_or_algorithm | none | verified_live | MIT (Copyright 2022 Steve Micallef) - code/structures may be adapted with attribution. | P332 `module_metadata_taxonomy` approved |
| C0665 | STIX 2.1 bundle export (hand-rolled; cti-python-stix2 only as test ... | offline_lib_or_algorithm | none | verified_live | [design_ceos] OASIS STIX 2.1 spec; cti-python-stix2 BSD-3-Clause ‖ [gh_cti_ioc] stix2 3... | P303 `export_stix_misp` approved |
| C0666 | IntelOwl analyzer catalog (observable taxonomy + free analyzer chec... | offline_lib_or_algorithm | none | verified_live | AGPL-3.0 - ideas/catalog only, no code copying. | P332 `module_metadata_taxonomy` approved |
| C0667 | LOLBAS dataset | dataset_download | none | verified_live | GPL-3.0 project data -> fetch at runtime, do not vendor | P268 `lol_datasets` approved |
| C0668 | MITRE D3FEND API | api | none | verified_live | MITRE D3FEND terms | P294 `d3fend` approved |
| C0669 | Security-news RSS watcher (entity mentions) | api | none | verified_live | Publisher feeds: store headline + link only, link back. Feed list from osint_toolkit (A... | P298 `cti_news_rss` approved |
| C0670 | APTmap dataset (geo + relations of APT groups) | dataset_download | none | verified_live | CC BY 4.0 (attribution). | P295 `actor_alias_index` approved |
| C0671 | Cortex-Analyzers catalog (dataType taxonomy) | offline_lib_or_algorithm | none | verified_live | AGPL-3.0 - ideas only. | P332 `module_metadata_taxonomy` approved |
| C0672 | CyCat (Cybersecurity Resource Catalogue) | api | none | verified_live | CIRCL/CyCat open data (verify per item). | P295 `actor_alias_index` approved |
| C0673 | Wiz Cloud Threat Landscape STIX/RSS | dataset_download | none | verified_live | Check Wiz terms for reuse | P299 `wiz_cloud_threats` deferred |
| C0674 | Malpedia family / actor pages | url_template | none | verified_live | site terms | P300 `pivots_cti` approved |
| C0675 | MITRE ATT&CK technique page | url_template | none | verified_live | [caipora_infra] Free web UI; provider ToS apply (manual analyst use) ‖ [live_cti] site ... | P300 `pivots_cti` approved |
| C0739 | CISA #StopRansomware advisories (per-advisory STIX 2.1 / JSON IOC f... | dataset_download | none | unverified | US Government work (public domain). | P374 `cisa_advisories` approved |
| C0740 | BushidoUK Ransomware Tool Matrix (group -> RMM / exfiltration / cre... | dataset_download | none | verified_live | CC BY 4.0 (LICENSE verified: 'free to share and adapt ... including commercial use, pro... | P372 `ransomware_matrices` approved |
| C0742 | DataBreaches.net RSS (breach, extortion and leak news) | api | none | verified_live | Site content (c) DataBreaches.net: store headlines + links only (no article copies). | P298 `cti_news_rss` approved |
| C0754 | Brazilian CERT and security-news feeds (CERT.br RSS; CTIR Gov alert... | api | none | verified_live | Public feeds; headlines + links only. | P298 `cti_news_rss` approved |
| C0766 | MITRE CAPEC STIX 2.1 bundle (attack patterns <-> ATT&CK techniques ... | dataset_download | none | verified_live | CAPEC terms of use (MITRE; free use with the copyright notice kept). | P292 `attack_index` approved |
| C0767 | SigmaHQ detection rules (sigma_core.zip release asset, Detection Ru... | dataset_download | none | verified_live | Rules: Detection Rule License (DRL) 1.1 (attribution required); Sigma specification pub... | P373 `technique_detections_tests` approved |
| C0768 | Atomic Red Team index (technique -> atomic test names/GUIDs/executo... | dataset_download | none | verified_live | MIT. | P373 `technique_detections_tests` approved |
| C0769 | Microsoft threat actor naming map (MSTIC public feed, CC BY 4.0) | dataset_download | none | verified_live | CC BY 4.0 (repository LICENSE: Attribution 4.0 International). | P295 `actor_alias_index` approved |

## Search & dorks (21)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0676 | GitHub code-search dork pack (secrets & mentions of the org) | api | free_key | verified_needs_key | [caipora_cli] github-dorks Apache-2.0 (217 dorks across categories ai, cloud, ... in gi... | P305 `code_search` approved |
| C0677 | SerpApi (Google/Bing/DDG results as JSON for dork automation) | api | free_key | verified_needs_key | SerpApi ToS. | P307 `web_search_api` approved |
| C0678 | Sourcegraph public code search (stream API) | api | none | verified_live | Sourcegraph.com ToS | P305 `code_search` approved |
| C0679 | DuckDuckGo Instant Answer API | api | none | verified_live | DuckDuckGo API terms (attribution) | P307 `web_search_api` approved |
| C0680 | GitLab blob search | api | free_key | unverified | GitLab ToS | P305 `code_search` approved |
| C0681 | grep.app code search | api | none | error | grep.app ToS | P310 `reject_search_scrapers` rejected |
| C0682 | Marginalia Search API | api | free_key | verified_needs_key | Free, open-source search engine (AGPL code - ideas only). | P307 `web_search_api` approved |
| C0683 | Marple (username search via search engines) | scrape | none | unverified | MIT | P310 `reject_search_scrapers` rejected |
| C0684 | Google Custom Search JSON API (deprecated) | api | free_key | dead | Google API terms | P310 `reject_search_scrapers` rejected |
| C0685 | Manual pivot-link page generator | url_template | none | unverified | team-owned | P311 `pivot_link_engine` approved |
| C0686 | Search-engine dork pack (exposed docs, configs, panels, errors) | url_template | none | verified_live | Operators are facts. dorks_hunter and Fast-Google-Dorks-Scan have no license file (all ... | P306 `dork_generator` approved |
| C0687 | Bing ip:/url: operators (reverse IP via search engine) | url_template | none | verified_live | Free web UI; provider ToS apply (manual analyst use) | P306 `dork_generator` approved |
| C0688 | Dork builder + pasted-URL router | url_template | none | unverified | team-owned; search engines' ToS (no server-side automation of Google) | P306 `dork_generator` approved |
| C0689 | Search-engine dork links (LinkedIn X-ray, person/phone/email dorks) | url_template | none | unverified | search engine ToS | P306 `dork_generator` approved |
| C0690 | Search-engine dork links for phone / username / e-mail | url_template | none | verified_live | Search engine ToS (no automated scraping) | P306 `dork_generator` approved |
| C0691 | Site-category dork pivots (sitedorks approach) | url_template | none | verified_live | sitedorks is AGPL-3.0 (26 CSVs, ~13k rows; WorldWide.csv ~650 sites with category colum... | P306 `dork_generator` approved |
| C0692 | Lyzem Telegram content search (pivot) | url_template | none | verified_live | site terms | P308 `pivots_search` approved |
| C0693 | WikiLeaks search | url_template | none | verified_live | site terms | P308 `pivots_search` approved |
| C0771 | Brave Search API (web search with X-Subscription-Token) | api | free_key | verified_needs_key | Brave Search API terms: storing results or training needs a custom plan with storage ri... | P307 `web_search_api` approved |
| C0772 | Tavily Search API (LLM-oriented web search; free credits with key) | api | free_key | verified_needs_key | Tavily terms. | P307 `web_search_api` approved |
| C0773 | Exa Search API (neural web search; API key or x402 pay-per-call) | api | paid_key | verified_needs_key | Exa terms. | P307 `web_search_api` approved |

## Utilities (40)

| id | name | kind | auth | status | terms / licence | council |
|---|---|---|---|---|---|---|
| C0694 | Analyst verdict, suggested attention points, auto-limitations and f... | offline_lib_or_algorithm | none | unverified | team-owned | P325 `feedback_verdict` approved |
| C0695 | Bot-wall / error-page fingerprint classifier | offline_lib_or_algorithm | none | unverified | MIT (both) | P321 `body_error_detection` approved |
| C0696 | Brazilian identifier validators/parsers (offline) | offline_lib_or_algorithm | none | verified_live | Public algorithms; own implementation. | P232 `br_validators` approved |
| C0697 | Collection policy as code (Céos docs/07 rules) | offline_lib_or_algorithm | none | unverified | team-owned | P327 `policy_as_code` approved |
| C0698 | Evidence store with SHA-256, re-collection versioning and audit trail | offline_lib_or_algorithm | none | unverified | team-owned | P324 `evidence_store` approved |
| C0699 | Finding + confidence model (CONFIRMED / PROBABLE / POSSIBLE with ma... | offline_lib_or_algorithm | none | unverified | team-owned | P322 `confidence_model` approved |
| C0700 | HTTP cache session with per-host TTL, negative caching and per-URL ... | offline_lib_or_algorithm | none | unverified | team-owned code (port freely, translate to English) | P326 `http_profiles` approved |
| C0701 | lemmeknow / pywhat identification regex DB | offline_lib_or_algorithm | none | verified_live | MIT (data derived from pywhat, MIT) - adapt with attribution | P323 `detector_patterns` approved |
| C0702 | Staged collection pipeline with per-service lanes + terminal log ma... | offline_lib_or_algorithm | none | unverified | team-owned | P339 `pipeline_lanes` approved |
| C0703 | Brazilian entity extractor for text blobs | offline_lib_or_algorithm | none | unverified | own implementation of public specifications | P232 `br_validators` approved |
| C0704 | Duplicate grouping for triage/report (union-find) | offline_lib_or_algorithm | none | unverified | team-owned (tests/test_agrupar.py exists) | P335 `report_grouping` approved |
| C0705 | gitleaks secret-detection ruleset | offline_lib_or_algorithm | none | verified_live | MIT (Copyright 2019 Zachary Rice) - rules may be bundled with attribution. | P312 `secret_scanner` approved |
| C0706 | Hash type identification | offline_lib_or_algorithm | none | unverified | Own code; ideas from Hash Identifier/Hash Analyzer rows (Name-That-Hash is GPL: ideas o... | P267 `file_hashing` approved |
| C0707 | IANA TLD list | dataset_download | none | verified_live | IANA public data. | P330 `bundled_reference_data` approved |
| C0708 | IEEE OUI registries (offline) | dataset_download | none | verified_live | IEEE public registry | P315 `mac_oui` approved |
| C0709 | Quota-aware batching for free APIs | offline_lib_or_algorithm | none | unverified | team-owned | P334 `quota_token_buckets` approved |
| C0710 | SafeLinks / URL-rewrite unwrapping | offline_lib_or_algorithm | none | verified_live | Own code (algorithm). | P064 `url_unwrap` approved |
| C0711 | Self-contained hashed report (no external resources) | offline_lib_or_algorithm | none | unverified | team-owned | P336 `report_integrity` approved |
| C0712 | Snowflake/ID -> timestamp decoders (X, Discord, TikTok, LinkedIn) | offline_lib_or_algorithm | none | verified_live | Algorithms are public knowledge; tiktok-timestamp is MIT (Bellingcat) | P314 `id_timestamp_decoders` approved |
| C0713 | Source health check ('doctor') | offline_lib_or_algorithm | none | unverified | team-owned | P337 `source_health_doctor` approved |
| C0714 | SpiderFoot offline extractors (analytics IDs, hashes, crypto, SRV, ... | offline_lib_or_algorithm | none | unverified | MIT | P323 `detector_patterns` approved |
| C0715 | DeepL API Free (report translation) | api | free_key | verified_needs_key | DeepL API Free terms (texts may be used to improve the service on the free plan). | P341 `report_translation` rejected |
| C0716 | Exposure posture checklist + suggested posture (weak / regular / good) | offline_lib_or_algorithm | none | unverified | team-owned | P338 `exposure_posture` approved |
| C0717 | ioc-fanger (data-driven fang/defang patterns) | offline_lib_or_algorithm | none | unverified | MIT (PyPI classifier) - patterns may be adapted with attribution. | P172 `ioc_extraction_engine` approved |
| C0718 | JWT decode & weak-configuration analysis | offline_lib_or_algorithm | none | verified_live | own code | P316 `jwt_analysis` approved |
| C0719 | maclookup.app API | api | none | verified_live | maclookup.app terms. | P315 `mac_oui` approved |
| C0720 | macvendors.com API | api | none | verified_live | [caipora_apis_cti] MACVendors free API (IEEE data). ‖ [live_cti] free tier ‖ [live_osin... | P315 `mac_oui` approved |
| C0721 | Unfurl URL/ID decoder (obsidianforensics/unfurl) | offline_lib_or_algorithm | none | unverified | Apache-2.0 (per project page; re-check LICENSE before adapting) | P064 `url_unwrap` approved |
| C0722 | Binlist.net (card BIN -> scheme, type, issuer, country) | api | none | verified_live | [caipora_apis_cti] binlist.net free service. ‖ [live_osint] Free community service. | P318 `card_bin` approved |
| C0723 | IMEI validation + TAC lookup | offline_lib_or_algorithm | none | verified_live | Own code; imeidb ToS. | P319 `imei_check` approved |
| C0724 | NHTSA vPIC VIN decoder | api | none | verified_live | US government open data (public domain). | P320 `vin_decoder` approved |
| C0725 | trufflehog detectors (architecture reference) | offline_lib_or_algorithm | none | unverified | AGPL-3.0 - ideas only. | P312 `secret_scanner` approved |
| C0726 | BCB SGS / Olinda PTAX | api | none | verified_live | BCB open data | P313 `reject_br_utility_low_value` rejected |
| C0727 | BrasilAPI misc utilities (feriados, NCM, ISBN, FIPE, CPTEC, cambio,... | api | none | verified_live | MIT code | P313 `reject_br_utility_low_value` rejected |
| C0728 | Licence/terms run profile (licence_profile = corporate / research) ... | offline_lib_or_algorithm | none | verified_live | Evidence quotes captured 2026-11-25: VT public API 'must not be used in commercial prod... | P377 `licence_profile` approved |
| C0732 | First-run key setup wizard (`v3lum keys setup`) for the free keys t... | offline_lib_or_algorithm | none | verified_live | abuse.ch terms: platforms free for not-for-profit purposes within query/export volume l... | P379 `keys_setup_wizard` approved |
| C0737 | V3LUM case database cross-case sightings (core/store.py) | offline_lib_or_algorithm | none | unverified | V3LUM code. | P375 `case_db_sightings` approved |
| C0746 | Organisation profile (org_profile.yaml: own domains, brand keywords... | offline_lib_or_algorithm | none | verified_live | V3LUM code; seed sources open. | P378 `org_profile` approved |
| C0774 | Per-opsec egress profiles (proxy_light / proxy_active / Tor socks5h... | offline_lib_or_algorithm | none | unverified | V3LUM code; PySocks BSD. | P376 `egress_profiles` approved |
| C0799 | binlist/data ranges.csv (offline BIN seed, ~2% of binlist.net data) | dataset_download | none | verified_live | No licence file in the repository -> terms unknown (seed only, legal review for corpora... | P318 `card_bin` approved |

