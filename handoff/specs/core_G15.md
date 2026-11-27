# Core (G15) proposals approved by Council #1

## P027 `correlation_pack_email_spoofing` - Correlation pack: e-mail spoofing posture (CR01-CR03)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: domain_dns; group: G15; inputs: domain; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. Rules in v3lum/correlations/email_spoofing.py. CR01 spoofable_email_domain: no DMARC, p=none or pct<100 (p=quarantine with pct=100 counts as enforcing) AND SPF missing, ~all, ?all, +all or permerror.
2. CR02 spf_lookup_limit: MEDIUM when SPF evaluation needs > 10 DNS-mechanism lookups or > 2 void lookups (RFC 7208 permerror), LOW at exactly 10. CR03 dmarc_reports_external_unauthorized: LOW in HTML/MD, INFO in the terminal, when a rua/ruf destination outside the policy domain lacks its authorization record (<domain>._report._dmarc.<dest>, checked by P002); a failed lookup = could not verify.
3. Inputs are only vocab attributes produced by email_security_posture/dns_records: spf, dmarc, dmarc_policy plus the new keys spf_lookups, spf_void_lookups, dmarc_pct, dmarc_sp and dmarc_rua_external, added to core/vocab.py in the same change. Rules make no network calls.
4. DMARC discovery for subdomains: when a subdomain has no _dmarc record, use the organisational domain's record (PSL) and its sp= tag before raising CR01. An org with p=reject and a subdomain without a record is not spoofable.
5. SPF evaluation in the producing module is bounded: <= 10 DNS-mechanism lookups and 2 void lookups, a recursion cap and include-loop detection. All lookups go through the core DoH resolver on the passive egress, never directly to the target's authoritative NS.
6. Rule 5: rules consume only DNS answers with status NOERROR/NXDOMAIN. SERVFAIL, REFUSED, timeouts or an unevaluated SPF chain mean 'could not verify' and the rule must not fire; never report 'SPF/DMARC missing' on missing data.
7. Ownership scoping: CR01 is HIGH only for analyst-typed seeds, verified org_profile domains, or the sending domain of the phishing case under triage. Pivot/third-party domains get LOW, omitted at depth >= 2. No spoofing-posture findings on entities tagged malicious/phishing, because attacker domains are not the subject.
8. Non-sending domains (null MX '0 .', no MX, or no A record) get CR01 at MEDIUM instead of HIGH (pivot/third-party domains stay LOW) with the specific advice 'no mail service: publish v=spf1 -all, a null MX and DMARC p=reject' instead of the generic text.
9. Every finding shows the record observed, the record to publish and a P322 criterion. It carries the ATT&CK ids T1566 and T1684.001, validated against the bundled ATT&CK data. Thresholds are named constants in one place.
10. Tests: positive and negative graph fixtures per rule, including a DoH SERVFAIL/timeout case that must not fire, p=none + ~all (HIGH on a seed, LOW on a pivot), a missing record, sp=none on the org domain, > 10 lookups, null MX and quarantine with pct=100.

Chair rationale: Approved 6-0 at median P1. All conditions are consolidated. cti_lead and analyst_ux asked for ownership-scoped severity. osint_investigator and redteam_lead asked for DMARC sp= inheritance via the PSL, the parked-domain variant and no findings on attacker domains. redteam_lead asked for a bounded SPF evaluation through DoH. The architect's floor requires vocab-only inputs and a SERVFAIL fixture that must not fire (rule 5, the same trap email_basics falls into today). legal_dpo raised no concern.

Synthesizer conditions (background; the final conditions win on conflict): Rules CR01 spoofable_email_domain (HIGH: no DMARC/p=none/pct<100 AND SPF missing/~all/?all/+all/permerror), CR02 spf_lookup_limit (MEDIUM >10 lookups or >2 void; LOW at 10), CR03 dmarc_reports_external_unauthorized (LOW); inputs from email_security_posture.
Notes: Most common finding for corporate domains (T1566, T1684.001).

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

## P028 `correlation_pack_typosquat` - Correlation pack: typosquat & brand abuse (CR04-CR06, CR35)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: domain_dns; group: G15; inputs: domain, keyword; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. Rules CR04 and CR05. CR04 typosquat_phishing_capable: HIGH when registered + MX + RDAP registration <= 90 days + registrant/NS/MX not the brand's. CR05 typosquat_with_fresh_certificate: HIGH when the FIRST certificate ever logged for the name (earliest not_before) is <= 30 days old, never on the latest auto-renewal.
2. Rules CR06 and CR35. CR06 typosquat_on_malicious_infra is CRITICAL under the consensus condition below. CR35 new_brand_keyword_domain: MEDIUM when the domain is <= 30 days old and combines a brand keyword with a lure word.
3. Rules make no network calls. They read only existing graph facts and vocab attributes: lookalike relations to an org_profile domain or brand (P012 permutations, CT and NRD hits), RDAP registration date and registrant, MX/A/NS answers, the CT first certificate and TI verdicts. New attribute keys go to core/vocab.py in the same change.
4. Protected brands, domains and NS come only from org_profile (P378), including its suppliers list: never hard-coded and never from ad-hoc flags. Without a profile the rules do not fire (no typosquat-of-google noise).
5. Own-asset suppression: domains in org_profile, domains whose RDAP registrant/NS/MX match the profile (registro.br publicIds CNPJ root in cnpj_roots) and BCB DominiosVerificados domains (P360) are never flagged and are tagged own_asset / verified_fi. CR04 stays POSSIBLE when RDAP is redacted or unavailable.
6. CR06 is CRITICAL only when >= 2 independent upstream families (P171 definition, after warninglist suppression) flag the IP AND the IP is neither a CDN/shared-hosting edge (is_cdn and is_hosting false, < 50 co-hosted names) nor a sinkhole. Otherwise it is HIGH. Shared-hosting hits never count unless the domain itself is flagged.
7. Parked domains (parking NS/IPs) are capped at MEDIUM with a 'parked' label until their MX, A record or certificate changes.
8. Lure words live in data/brand_lures_pt.json (editable, tested), PT and EN: conta, pix, boleto, sac, segunda-via/2via, fatura, cartao, credito, emprestimo, fgts, inss, gov, receita, regularizar, desbloqueio, premio, cashback, pontos, login, seguranca, atualizacao, token. They match after IDNA->Unicode, accent and homoglyph folding.
9. Wording is 'lookalike / phishing-capable indicator', never 'malicious' unless CR06 consensus applies, to avoid labelling registrants (possibly natural persons) without evidence. No automated takedown or abuse report: notification is a manual, separately approved action.
10. A registrant CNPJ exposed by registro.br RDAP becomes a cnpj pivot (company due diligence). CPF registrants and legalRepresentative names are never pivoted and are masked in every output.
11. The pack only correlates existing results. It never triggers LIGHT contact with candidate domains: page similarity stays in LIGHT modules behind the P376 egress guard. Values are shown defanged, and each alert prints its evidence chain on one line (registered N days ago, MX yes/no, first cert date, TI sources).
12. Tests: positive and negative graph fixtures per rule from real typosquat samples. A parked lookalike stays <= MEDIUM, a fresh MX-enabled lookalike is HIGH, and both an own defensive registration and a legitimate brand subsidiary are suppressed.

Chair rationale: Approved 6-0 at median P1 (redteam_lead voted P2). The suppression of own defensive registrations, asked for by osint_investigator, redteam_lead, the architect and analyst_ux, is the core of the spec. Brand data comes only from org_profile, a legal_dpo and architect floor. CR06 counts independent upstreams and excludes CDN/sinkhole/shared hosting (cti_lead, analyst_ux). CR05 uses the first certificate (analyst_ux). The wording avoids defaming registrants and no takedown is automated (legal_dpo). The pack never contacts candidates (redteam_lead). analyst_ux's ad-hoc --brand flag is not adopted, because legal_dpo's floor limits brand keywords to org_profile; partner brands go into the profile's suppliers list instead.

Synthesizer conditions (background; the final conditions win on conflict): CR04 typosquat_phishing_capable (HIGH: registered + MX + RDAP <= 90 d + registrant/NS not the brand's), CR05 typosquat_with_fresh_certificate (HIGH: CT cert <= 30 d), CR06 typosquat_on_malicious_infra (CRITICAL: IP flagged by >= 2 TI sources after warninglists), CR35 new_brand_keyword_domain (MEDIUM: <= 30 d with brand + phishing words incl. PT: conta, pix, boleto, sac).
Notes: Brand-protection alerts with explicit evidence.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

## P029 `doh_resolver_hardening` - DoH resolver layer hardening (multi-provider, wire format, AD flag, TXT normalisation)

- council: **approved**, priority P1, default_enabled=True, provider_tier=trusted, terms=open, opsec=passive, shares_input=True
- category: domain_dns; group: G15; inputs: domain, ipv4, ipv6; produces: 
- auth: none; key env vars: -; hosts: dns.google, cloudflare-dns.com
- upgrades existing module: core/dns.py

### Final conditions (binding spec - implement every item)

1. core/dns.py keeps the Google/Cloudflare JSON resolvers with automatic failover as the default. Failover happens only on transport errors, 5xx and 429, never on NXDOMAIN. Failover time per query is <= 5 s across resolvers, and a per-run circuit breaker skips a resolver after 3 consecutive failures.
2. Every Google DoH JSON query sends edns_client_subnet=0.0.0.0/0 (verified live 2026-11-26), and a unit test asserts it on every request. Cloudflare stays ECS-free and is preferred for names tagged hostile. RFC 8484 providers are used only through no-ECS endpoints (e.g. dns.quad9.net, not dns11).
3. NXDOMAIN only comes from an answer with Status 3. SERVFAIL, REFUSED, timeouts and transport errors stay distinct and reach modules as could-not-verify, never empty/NXDOMAIN. Fix Resolver._system: only EAI_NONAME maps to NXDOMAIN; EAI_AGAIN, timeouts and other OSError map to SERVFAIL with the error text.
4. DoH is the default. dns_mode=system (dnspython, UDP/53) runs only when configured explicitly, never as a silent fallback, because the corporate resolver's IP would reach the target's NS; doctor warns when dns_mode=system. RFC 8484 wire format comes only through dnspython as an optional extra, with no hand-rolled DNS message parser.
5. The resolver list is configurable (setting doh_providers, https only, validated) and may include the company's internal DoH, listed first when set. The docs present it as the opsec option for typosquat permutation lists, since a public resolver operator sees every permutation.
6. Default resolvers are limited to providers whose terms allow business use, recorded with evidence in the provider registry (Google Public DNS, Cloudflare 1.1.1.1, Quad9; tier trusted). OpenDNS and CleanBrowsing free resolvers keep terms 'unknown' (off under corporate) until reviewed.
7. TLP: the chain never moves a query from the system/internal resolver to a public DoH provider when the case is TLP:AMBER or above, or when the caller has disclosure 'none'/'internal'; it answers SERVFAIL / could-not-verify instead. Under RED only an internal resolver may be used (A2).
8. The AD flag is reported as 'validated by resolver', never as proof. TXT quoting and multi-string answers are normalised. Each DnsAnswer records the resolver used, and evidence files carry it.
9. DNSBL lookups (Spamhaus etc.) never go through public resolvers. Refusal codes (127.255.255.x) map to BLOCKED/RATE_LIMITED, never to 'not listed'.
10. Helper ctx.dns.wildcard(zone) runs a random-label A/AAAA probe, cached per run, so modules can tell wildcard and Cloudflare NOERROR/NODATA zones from real records. An NXDOMAIN used for takeover/typosquat decisions is confirmed by a second resolver.
11. DoH gets its own HTTP scope on the default passive egress: no module UA or min_interval, not counted in module quotas or max_requests. Parser tests run over the 18 recorded DoH fixtures (AD flag, multi-string TXT, CAA/HTTPS/DS), plus one test per status mapping.

Chair rationale: Approved 6-0 at median P1 (architect and analyst_ux voted P2); the chair keeps P1 and phase 0 because every DNS module depends on these semantics. cti_lead and redteam_lead documented the ECS leak of the egress subnet to attacker-run NS (verified live). osint_investigator, redteam_lead and analyst_ux documented the getaddrinfo-to-NXDOMAIN rule-5 bug. legal_dpo's floor limits default resolvers to business-compatible terms and stops public fallback for AMBER/RED and offline modules. The architect's floor: keep the JSON failover, wire format only via dnspython, its own HTTP scope, fixture tests. The resolvers are a data source: tier trusted, terms open per the registry evidence.

Synthesizer conditions (background; the final conditions win on conflict): core/dns.py: Google + Cloudflare JSON with automatic failover, optional RFC 8484 wire format (Quad9/CleanBrowsing/OpenDNS), AD flag for DNSSEC, normalise TXT quoting/multi-string, configurable resolver list, automatic fallback to DoH when UDP/53 fails; NXDOMAIN vs SERVFAIL vs refused kept distinct (Spamhaus refusals).
Notes: Every DNS-based module depends on it behind HTTPS-only proxies.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0003 DNS-over-HTTPS resolver layer (Google + Cloudflare JSON) - dns.google / cloudflare-dns.com
- kind: api; status: verified_live (HTTP seen: [200]); passive: True; touches_target: False
- endpoint: https://dns.google/resolve?name={name}&type={type} | https://cloudflare-dns.com/dns-query?name={name}&type={type} (header accept: application/dns-json) ‖ https://dns.google/resolve?name={name}&type={type}&do=1 | https://cloudflare-dns.com/dns-query?name={name}&type={type} (header accept: application/dns-json)
- method: GET JSON
- inputs: ['domain', 'ipv4', 'ipv6', 'email']
- outputs: [caipora_infra] Answer[] for A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/SRV/PTR/DS/DNSKEY; AD flag (DNSSEC validated). Pivots: IPs, mail hosts, nameservers, SPF/DMARC text. ‖ [design_ceos] A/AAAA/CNAME/MX/NS/TXT/CAA/DS/SOA answers, rcode (3 = NXDOMAIN), AD (DNSSEC validated) flag ‖ [live_cti] A/AAAA/MX/NS/TXT(SPF, verification tokens -> SaaS pivots)/CAA/SOA/DS/PTR/HTTPS(SVCB)/_dmarc/_mta-sts/_smtp._tls/DKIM selectors; Status (0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN); AD flag = DNSSEC validated
- auth: none
- rate limit: [caipora_infra] Generous fair use. ‖ [design_ceos] generous public limits; cache per TTL ‖ [live_cti] very high; no documented limit for reasonable use
- terms / licence: [caipora_infra] Free public resolvers (Google/Cloudflare terms) ‖ [design_ceos] Google Public DNS / Cloudflare 1.1.1.1 terms
- risk: [caipora_infra] Queries are visible to the resolver operator; the target's authoritative NS sees only the resolver (standard passive DNS). ‖ [design_ceos] OPSEC: the resolver operator sees every name you look up (typosquat lists reveal what brand you investigate). Make the resolver configurable (corporate DoH endpoint). ‖ [live_cti] Queries go to the resolver, not to the target; still the target's authoritative NS sees the resolver lookup (low OPSEC risk).
- implementation notes: [caipora_infra] Use dnspython for normal resolution and DoH as transport where UDP/TCP 53 is blocked (HTTPS-only proxies). Also the transport for Team Cymru and DNSBL lookups. Covers caipora dig/nslookup/propagation web tools. ‖ [design_ceos] Core utility for all DNS-based modules: in this sandbox (and many corporate networks) UDP/TCP 53 is blocked and only HTTPS via proxy works; socket.getaddrinfo failed for example.com. Implement fallback order: corporate DoH -> Google -> Cloudflare; use Cloudflare to double-check NXDOMAIN before declaring takeover/typosquat states. ‖ [live_cti] Verified types A, AAAA, MX, NS, TXT, CAA, SOA, DS, PTR, HTTPS(65), DMARC, MTA-STS and NXDOMAIN (Authority SOA). AD:true for example.com (signed), false for github.com. TXT quoting differs (Cloudflare quotes). EDE errors arrive in "Comment". Quad9 JSON (:5053) reset from this egress -> skip.
- sample: <scratch>/research/samples/caipora_infra__doh_google_mx.json (valid_json)
- sample: <scratch>/research/samples/caipora_infra__doh_cloudflare_txt.json (valid_json)
- sample: <scratch>/research/samples/design_email_posture_doh.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_a_dnssec.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_cloudflare_a_ad.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_cloudflare_mx.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_aaaa.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_caa.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_dmarc.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_ds.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_https_rr.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_mtasts.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_mx.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_ns.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_nxdomain.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_ptr.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_soa.json (valid_json)
- sample: <scratch>/research/samples/live_cti__doh_google_txt.json (valid_json)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/caipora_infra__doh_google_mx.json
- <scratch>/research/samples/caipora_infra__doh_cloudflare_txt.json
- <scratch>/research/samples/design_email_posture_doh.json
- <scratch>/research/samples/live_cti__doh_google_a_dnssec.json
- <scratch>/research/samples/live_cti__doh_cloudflare_a_ad.json
- <scratch>/research/samples/live_cti__doh_cloudflare_mx.json
- <scratch>/research/samples/live_cti__doh_google_aaaa.json
- <scratch>/research/samples/live_cti__doh_google_caa.json
- <scratch>/research/samples/live_cti__doh_google_dmarc.json
- <scratch>/research/samples/live_cti__doh_google_ds.json
- <scratch>/research/samples/live_cti__doh_google_https_rr.json
- <scratch>/research/samples/live_cti__doh_google_mtasts.json
- <scratch>/research/samples/live_cti__doh_google_mx.json
- <scratch>/research/samples/live_cti__doh_google_ns.json
- <scratch>/research/samples/live_cti__doh_google_nxdomain.json
- <scratch>/research/samples/live_cti__doh_google_ptr.json
- <scratch>/research/samples/live_cti__doh_google_soa.json
- <scratch>/research/samples/live_cti__doh_google_txt.json

## P030 `watch_mode` - Watch mode: CertStream real-time CT + rule-based hunting with first_seen diffing (mihari-style)

- council: **approved**, priority P2, default_enabled=False, provider_tier=community, terms=open, opsec=passive, shares_input=True
- category: domain_dns; group: G15; inputs: keyword, domain; produces: domain
- auth: none; key env vars: -; hosts: certstream.calidog.io, www.gstatic.com, ct.googleapis.com, ct.cloudflare.com, storage.googleapis.com, raw.githubusercontent.com

### Final conditions (binding spec - implement every item)

1. `v3lum watch` is a separate command, never part of scan. It runs in the foreground only, with --once for cron/systemd timers, --max-runtime (default 8 h) and --max-alerts, and has no daemon or service management.
2. Rules come only from org_profile brands, domains, CNPJ roots, card BINs (P357) and the supplier list, plus IOC types. No rule may target a natural person (names, personal e-mails, usernames, phones), except own-domain addresses for infostealer exposure. Matching is local after IDNA->Unicode, accent folding and the P012 permutation set, and keywords are never sent to any third party.
3. Phase 1: saved hunts re-run on an interval over approved polling sources (crt.sh/Cert Spotter deltas for org domains, NRD feeds), with first_seen diffing persisted in SQLite through a schema migration (AR04).
4. CertStream: a WebSocket consumer only in the optional extra v3lum[watch] (pure-Python client) with a configurable URL. A configured self-hosted certstream-server-go is used first, and certstream.calidog.io is a community-tier best-effort source. Direct RFC 6962/static-ct-api log polling is deferred to BACKLOG.md.
5. Registry: certstream.calidog.io is tier community, terms open (public CT data, MIT server; evidence recorded per A1); a self-hosted certstream-server-go is disclosure 'internal'. The consumer sends no investigated value because all filtering is local, and the polling sources keep their own modules' registry tier and terms.
6. Bounds: a keyword/permutation prefilter runs before queueing; the queue is bounded (drop and count); dedupe uses an LRU; reconnects use backoff with jitter and a maximum reconnect rate; memory is capped.
7. Alerts fire only for NEW registrable domains, deduplicated by registrable domain plus certificate serial. Each is one terminal line with the reason it matched, a JSONL record (timestamp, rule id, matched name, registrable domain, reason, cert sha256, issuer, not_before) and a case-DB entry. Certificate metadata only. Above 200 alerts per hour a summary line replaces the rest.
8. Hits only enqueue a normal passive scan through the policy gate, capped at 30 auto-enrichments per hour, with the rest listed for the analyst. Watch never makes automatic LIGHT/ACTIVE contact with hits (A13).
9. Ransomware victim watch runs only with the ransomware.live PRO key (terms-compatible) and only on victim metadata; leaked files are never downloaded or opened (rule 3). Telegram public-channel watch is delivered only by P357, under its own conditions (A14 BR7).
10. Mutes exist per rule and per domain, and per-rule precision comes from P325 feedback. Alerts and first_seen state follow retention_days and the case TLP (default AMBER).
11. doctor shows source health (CertStream reachability, polling source status). Offline tests replay recorded certstream messages through an injectable transport with a fake clock.

Chair rationale: Approved 6-0 at median P2. Brand CT monitoring is early warning for BR phishing waves (cti_lead, osint_investigator), and local filtering of the whole stream reveals nothing about what is watched (redteam_lead). legal_dpo's floor: org_profile-only rules, no natural persons, local keywords, terms-compatible victim feeds, retention and TLP. The architect's floor: a foreground --once command, polling phase 1 with first_seen diffing, CertStream only as an optional bounded extra, direct log polling deferred, replay tests. analyst_ux asked for the polling MVP and the one-line digest. It is opt-in by nature (a separate command), hence default_enabled false. Auditor: provider_tier/terms set to community/open because the CertStream consumer is itself a data source, and the Telegram exclusion was replaced by the approved P357 conditions (A14).

Synthesizer conditions (background; the final conditions win on conflict): Explicit `v3lum watch` sub-command (never part of scan): CertStream WebSocket (wss://certstream.calidog.io, verified 101 handshake) filtered by brand keywords + typosquat permutations, with timeout/max-runtime and reconnect backoff; saved hunting rules (mihari MIT design) re-run on schedule with first_seen diffing so only new hits alert; alerts written to the case DB. Gap fill: certstream.calidog.io is best effort -> preferred source is a self-hosted certstream-server-go (MIT, same message format); fallback direct polling of usable logs from the Google log list v3 (RFC 6962 get-sth/get-entries deltas, static-ct-api checkpoints/tiles) with per-log rate limits; Cert Spotter remains the per-domain crt.sh fallback.
Notes: Real-time brand monitoring complementing daily NRD feeds.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0009 CertStream real-time Certificate Transparency firehose - certstream.calidog.io (CaliDog)
- kind: api; status: verified_live (HTTP seen: [101, 200]); passive: True; touches_target: False
- endpoint: wss://certstream.calidog.io/ (full JSON) ; wss://certstream.calidog.io/domains-only ‖ wss://certstream.calidog.io/ (full) ; wss://certstream.calidog.io/domains-only ; https://certstream.calidog.io/example.json (latest sample)
- method: WebSocket (HTTP/1.1 Upgrade), client-side keyword/regex filtering ‖ WebSocket (RFC 6455) - handshake returned 101 Switching Protocols; HTTP GET for example.json
- inputs: ['keyword', 'domain']
- outputs: [caipora_cli] certificate_update messages: leaf_cert.all_domains, subject/issuer, not_before/not_after, fingerprint, CT log source -> new domain/subdomain entities matching brand keywords (phishing / look-alike early warning). ‖ [lists_global] certificate_update messages: leaf_cert.all_domains, subject, issuer, not_before/not_after, fingerprint, serial, extensions (SAN, AIA...), cert_index + cert_link (CT log get-entries URL), source log. New pivots: domains matching brand/typosquat patterns, cert_fingerprint.
- auth: none
- rate limit: [caipora_cli] Firehose (hundreds of certs/s); no quota; public instance is best-effort with past outages. ‖ [lists_global] Firehose (hundreds of certs/s); no backfill. Run only in an explicit 'watch' mode with timeout.
- terms / licence: [caipora_cli] certstream-server (MIT) - public instance best-effort; self-host certstream-server-go for production. ‖ [lists_global] Public best-effort service by Calidog (certstream-server is MIT; can self-host certstream-server-go).
- risk: none (public CT data). Operational risk only.
- implementation notes: [caipora_cli] For V3LUM 'watch' mode: long-running consumer, reconnect with backoff, match SANs against brand keywords + dnstwist permutations, then push hits through the normal pipeline (DNS, urlscan, Safe Browsing, PhishTank). May overlap a lists_global candidate; verified here via HTTP 101 handshake. ‖ [lists_global] Implement with the 'websockets' or 'websocket-client' lib; filter messages where message_type=='certificate_update' against brand keywords + dnstwist permutations; emit new domain entities. Complements crt.sh/CertSpotter (covered) which lag minutes-hours.
- sample: <scratch>/research/samples/lists_global__certstream_example.json (valid_json)

#### C0660 mihari rule-based hunting & alerting engine (design reference) - github.com/ninoseki/mihari
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- endpoint: n/a (architecture). Analyzers: Censys, CIRCL PDNS, crt.sh, dnstwister, FOFA, GreyNoise, Hunter.how, Onyphe, OTX, PassiveTotal, Pulsedive, SecurityTrails, Shodan, urlscan, Validin, VirusTotal(+Intelligence), ZoomEye, generic JSON 'feed' (URL + JSONPath selector).
- inputs: ['domain', 'ipv4', 'url', 'keyword', 'favicon_hash', 'cert_fingerprint', 'sha256']
- outputs: Rules (YAML: id, title, queries[{analyzer, query}], data_types, falsepositives, tags) executed on a schedule -> artifacts (ip/domain/url/mail/hash) with first_seen; only NEW artifacts are emitted (database, MISP, TheHive, Slack, webhook, Yeti); enrichers add Google Public DNS, MMDB (geo/ASN), Shodan InternetDB, whois.
- auth: none
- terms / licence: MIT (Ruby) - patterns adaptable.
- implementation notes: Blueprint for V3LUM 'watch': store rule + last artifact set in SQLite, diff each run, alert on new; analyst feedback ('made sense? y/n') updates per-rule falsepositives. The generic feed analyzer (URL + selector) lets many open feeds be added by config instead of code.

#### C0755 Direct CT log polling (Google CT log list v3 + RFC 6962 get-sth/get-entries + static-ct-api checkpoints/tiles) - Certificate Transparency log operators (Google, Cloudflare, DigiCert, Sectigo, Let's Encrypt, ...)
- kind: api; status: verified_live (HTTP seen: [200]); passive: True; touches_target: False
- endpoint: https://www.gstatic.com/ct/log_list/v3/log_list.json -> {log url}ct/v1/get-sth and ct/v1/get-entries?start={i}&end={j} (RFC 6962) ; {monitoring_url}checkpoint and tile/... (static-ct-api)
- method: GET
- inputs: ['keyword', 'domain', 'company_name']
- outputs: New certificate entries (SANs, issuer, not_before) from usable logs since the last tree head -> brand/typosquat matches.
- auth: none
- rate limit: Each log rate-limits get-entries (batches of up to ~256-1,024 entries); logs hold billions of entries (Nimbus2026 tree_size 6,830,572,393) -> follow only new STH deltas of usable logs.
- terms / licence: Public CT logs (RFC 6962, C2SP static-ct-api).
- risk: High volume (thousands of certificates per second across logs): run only in watch mode with keyword pre-filtering; parsing precertificates needs ASN.1 handling.
- implementation notes: Log list v3 version 98.6 (2026-11-25): 11 operators, 26 RFC 6962 logs (17 usable) + 63 tiled logs (89 total). Replaces the single public certstream websocket as watch-mode source when self-hosting certstream-server-go is not possible; Cert Spotter remains the per-domain fallback for crt.sh.
- sample: <scratch>/research/samples/gaps__ct_streaming.json (valid_json)

#### C0756 certstream-server-go (self-hosted CertStream-compatible server, MIT) - d-Rickyy-b (GitHub)
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: [200]); passive: True; touches_target: False
- endpoint: self-hosted ws://{internal}/ (full) | /domains-only | /full-stream ; source https://github.com/d-Rickyy-b/certstream-server-go
- method: local
- inputs: ['keyword', 'domain']
- outputs: CertStream-format websocket (full or domains-only) fed directly from the CT logs on the team's own host.
- auth: none
- rate limit: Own deployment.
- terms / licence: MIT (LICENSE verified).
- risk: Needs a small always-on host; the public certstream.calidog.io stays a best-effort fallback (its example.json answered).
- implementation notes: Drop-in replacement of wss://certstream.calidog.io for P030 watch mode: same message format (message_type certificate_update, data.leaf_cert.all_domains), so the consumer code does not change.
- sample: <scratch>/research/samples/gaps__ct_streaming.json (valid_json)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/lists_global__certstream_example.json
- <scratch>/research/samples/gaps__ct_streaming.json

## P084 `correlation_pack_web_hygiene` - Correlation pack: web hygiene (CR17-CR24)

- council: **approved**, priority P2, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: url_web; group: G15; inputs: url, domain, jwt, text_blob, company_name; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. Rules: CR17 weak_or_expired_tls, CR18 login_page_without_hsts, CR19 insecure_session_cookie, CR20 cors_credentialed_reflection, CR21 secret_in_public_asset, CR22 jwt_weak_configuration, CR23 sensitive_file_exposed and CR24 public_cloud_bucket, each with a P322 criterion and positive/negative graph fixtures.
2. Rules only consume facts from LIGHT/ACTIVE modules that already ran under the policy gate. A rule never triggers new contact or further probing.
3. Ownership scoping: CR17-CR20 and CR22 keep their severity only for verified org_profile own assets, in-scope targets or an explicit web-assessment run (an analyst-typed seed scanned with --mode light or active). On other third-party hosts they are INFO context.
4. On hostile hosts (tagged malicious/phishing/c2), every rule CR17-CR24 yields INFO context only. INFO context never raises the case score and is hidden from the terminal top list.
5. CR17-CR19 become inconclusive when TLS interception was detected for the run (shared core/tls.py helper, P329).
6. CR20 is produced only from the ACTIVE cors_probe on in-scope authorized targets, because a crafted Origin header is not visitor traffic. LIGHT data may only report observed ACAO headers.
7. CR21 reports type, asset URL and line, SHA-256 and a masked preview (first 4/last 4 chars), entropy-gated. The secret is never validated, tested, used or turned into a pivot. Key types that are public by design (Google Maps/Firebase web keys, Stripe pk_, Sentry DSN) are excluded or capped at LOW.
8. CR22 is static analysis only (alg none, HS* on public tokens, missing or very long exp, kid/jku/x5u anomalies): no offline secret cracking.
9. CR23 requires a content-signature match kept in evidence, never the HTTP status alone. Evidence keeps SHA-256, size, the signature and a redacted excerpt, never the full body (rule 3).
10. CR24: 403 = LOW 'bucket exists, private; ownership not verified'. It fires only for buckets attributed to the target by evidence (referenced in its pages, DNS or CNAME). Permutation-only hits are 'unattributed' (INFO, existence only, no listing). Nothing is ever written to a bucket.
11. Findings on assets outside org_profile are labelled third_party. Recommendations for them stop at 'notify the owner through a manual, approved disclosure process'.
12. Test: a phishing-kit fixture yields no MEDIUM-or-higher hygiene finding.

Chair rationale: Approved 6-0 at median P2. cti_lead, osint_investigator and analyst_ux scoped severity to own assets, so hygiene noise on phishing kits never competes with the verdict. redteam_lead tied each rule to its opsec level and authorization, ruled out credential attacks and limited CR24 to attributed buckets. legal_dpo's floor: secrets reported masked and never used, sensitive files kept as hash plus redacted excerpt, third-party findings never trigger probing. The architect's floor: rules never trigger contact, TLS-interception awareness, content signatures.

Synthesizer conditions (background; the final conditions win on conflict): CR17 weak_or_expired_tls (skipped when interception detected), CR18 login_page_without_hsts, CR19 insecure_session_cookie, CR20 cors_credentialed_reflection, CR21 secret_in_public_asset (entropy-gated, never validated), CR22 jwt_weak_configuration, CR23 sensitive_file_exposed (content signature, not HTTP 200), CR24 public_cloud_bucket (403 = LOW exists/private).
Notes: Turns light/active web checks into consistent findings.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

## P145 `breach_minimization_guards` - Breach data-minimisation sanitizer (never store passwords or combo lines)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: breach_leak; group: G15; inputs: email, text_blob; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. core/sanitize.py runs as a mandatory engine stage in Engine.run_module right after Module.run returns. It covers res.raw, attributes, findings.data, pivot notes and links, before graph merge, evidence, case DB, events/live feed, reports, STIX/MISP exports and --debug output. Modules cannot opt out.
2. Fail closed: if sanitizing raises, the raw payload is dropped and the run ends Status.ERROR with reason_code 'sanitizer'.
3. Per-source ALLOW-list schemas for breach_leak, infostealer and people-data sources keep only declared metadata: breach name, breach date, data classes, counts, stealer family, log/compromise date, corporate/user service counts, and the password FORM (plaintext, or hashed: <algorithm>). A sensitive module without a schema cannot register.
4. Second net for those categories (case-insensitive, nested): drop password, passwd, pass, pwd, senha, hash, password_hash, salt, top_passwords, top_logins, masked/hint fields, cookies, session, token, autofill, computer_name, infected-host ip, malware_path and combo/line fields.
5. Value detectors drop (never mask) email:password and user:pass@host combos in every module result and in text/file inputs, before anything is stored, extracted or shown (a pasted combo keeps only the e-mail). Inside breach, infostealer and people-data payloads, bcrypt/argon/MD5/SHA hex values next to a credential are dropped too.
6. Category-scoped: the denylist does not apply to malware/hash modules, which keep their sha256/md5/'hash' fields (regression test with a MalwareBazaar fixture).
7. HTTP cache (P326 veto_lift): bodies from providers flagged sensitive in the registry are sanitized with the source schema before cache.put and before they reach the module, or fetched no-store when no schema exists. They are never stored raw in http_cache.db.
8. Secrets found by detectors or by LIGHT/ACTIVE modules (API keys, tokens, private keys, connection strings, .env values) are stored as type + first 4/last 4 + SHA-256 only.
9. Evidence records a redacted_fields list. Reports show data classes and the password form in plain words ('passwords: plaintext', 'hashed: bcrypt').
10. Golden tests with trimmed Hudson Rock, LeakCheck, XposedOrNot and HIBP fixtures and an exposed .env sample: a grep of http_cache.db, evidence, case DB, HTML/MD/JSON/STIX/MISP outputs, events and --debug output finds no masked password or login, computer name, victim IP or malware path.

Chair rationale: Approved 6-0 at median P1; it is a phase-0 and A4 item. All members found the same gap: the HTTP cache stores raw breach bodies for the TTL, so a module-level sanitizer cannot satisfy rule 3. legal_dpo's floor: one fail-closed choke point that also covers cache, exports and --debug. The architect's floor: an engine stage modules cannot opt out of, plus cache handling and golden tests. cti_lead set allow-list schemas first with the denylist as a second net. redteam_lead extended the rule to recon secrets. analyst_ux scoped the 'hash' rule so malware analysis keeps file hashes.

Synthesizer conditions (background; the final conditions win on conflict): Mandatory sanitizer between every collector and persistence/evidence: drop fields named password/pass/hash/senha/top_passwords/top_logins, refuse values that look like email:password, keep only data classes and the password FORM (plaintext/hashed algorithm); masks from sources never reach reports or evidence files; unit tests with Hudson Rock/LeakCheck fixtures.
Notes: Enforces rule 3 technically.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0299 Breach data-minimization guards (never store passwords or combo lines) - Céos ceos/exposicao.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: registrar_vazamento (_PARECE_COMBO = \S+[:;|]\S+ refused in 'affected account'), SENHA forms (no/hash/plaintext/yes/unknown), DADOS categories
- inputs: ['email', 'text_blob']
- outputs: sanitized breach records (categories, not values)
- auth: none
- terms / licence: team-owned
- implementation notes: Implement as a mandatory sanitizer between every collector and persistence: drop fields named password/pass/hash/senha, refuse values that look like email:password, store only data categories + password FORM; masks from sources stay inside raw evidence and never reach reports. This is how V3LUM enforces the team's breach rule technically, not just by policy.

## P146 `correlation_pack_breach` - Correlation pack: breach & infostealer validation (CR09-CR12 + Céos breach heuristics)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: breach_leak; group: G15; inputs: email, domain; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. Rules CR09 corporate_credentials_in_infostealer, CR10 email_in_multiple_password_breaches, CR11 generic_or_shared_email_suppression and CR12 breach_predates_domain read only P145-sanitized metadata (breach names, dates, data classes, counts, stealer family). They replace the existing breach_and_infostealer rule, and their output passes the P145 sanitizer.
2. Suppression runs first and only downgrades, with a visible label; it never deletes. CR11 caps at POSSIBLE, and never scores as exposure, any address in data/generic_addresses.json and any hit with LeakCheck found >= 100 or Hudson Rock >= 5 computers.
3. data/generic_addresses.json holds role/test local parts (test, info, contato, contact, sac, admin, noreply, no-reply, suporte, support, vendas, financeiro, rh, webmaster, postmaster, abuse) and example.* / IANA test domains.
4. CR12 needs the domain creation date (RDAP) and stays silent when it is unavailable. A breach that predates the domain downgrades confidence, with that criterion.
5. CR09 is CRITICAL only when the address is on a verified org_profile domain AND the stealer log is <= 12 months old. Older own-domain logs with corporate services > 0 are HIGH, other older ones MEDIUM (decay tau 1 year). Third-party addresses are context only, at most MEDIUM, never CRITICAL.
6. CR10 (>= 3 verified breaches, or confirmed by 2 sources, at least one within the last 3 years) is HIGH for own-domain addresses. For third-party addresses it is context only, at most MEDIUM.
7. Third-party addresses are evaluated only when the A4 breach scope allows it (--breach-scope all + purpose, analyst-typed seeds only), and their findings carry no exposure score.
8. Breach counts from the same upstream (aggregators re-serving HIBP-type data) count once.
9. Ceos verdict heuristics (IsFabricated against, spam-list alert, compilation doubt, >= 2 sources agree, profile on the breached service plausible) are named, individually tested functions, each emitting a P322 criterion. The suggested verdict (positive / false positive / inconclusive) is shown with the 2-3 criteria that drove it.
10. Emit attribute first_seen_breach (earliest breach date) to the timeline as account-age evidence, with no score.
11. Wording is a suggestion. Reports state that infostealer findings about employees go to incident response and are not a basis for disciplinary decisions without human review (LGPD art. 20). Leaked credentials are never tested in any mode.
12. Tests: positive and negative graph fixtures per rule. test@example.com with 5 generic stealers is capped at POSSIBLE with no CRITICAL; a recent own-domain log is CRITICAL; a 2-year-old log is HIGH or MEDIUM.

Chair rationale: Approved 6-0 at median P1. cti_lead pointed out that 'or corporate services > 0' would turn 4-year-old logs into CRITICALs, so CRITICAL now requires an own-domain address and a recent log. This matches osint_investigator, analyst_ux and legal_dpo's floor (third parties at most MEDIUM, and only under the A4 breach scope). Suppression only downgrades (all members). osint_investigator added first_seen_breach as an account-age pivot. legal_dpo required the LGPD art. 20 notice. The architect's floor: sanitized inputs only, named tested heuristics. redteam_lead: credentials are never tested.

Synthesizer conditions (background; the final conditions win on conflict): CR09 corporate_credentials_in_infostealer (CRITICAL <= 12 months or corporate services > 0), CR10 email_in_multiple_password_breaches (>= 3 verified or 2-source confirmed, one in last 3 years), CR11 generic_or_shared_email_suppression (LeakCheck >= 100 or Hudson Rock >= 5 computers -> cap at POSSIBLE, never delete), CR12 breach_predates_domain; port Céos verdict heuristics (IsFabricated against, spam list alert, compilations doubt, >= 2 sources ok, profile on breached service plausible). Extends existing breach_and_infostealer rule.
Notes: Reduces breach false positives while surfacing infostealer exposure.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0300 Breach validation heuristics with suggested verdict (positive / false positive / inconclusive) - Céos ceos/exposicao.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: sinais_avaliacao, _sinais_stealer, _generico, listado_por/confirmar, registros_de_dominios; _COMPILACAO regex, MUITOS_VAZAMENTOS=100, hudsonrock.MUITOS=5
- inputs: ['email']
- outputs: signals [{level ok|alert|doubt|against, text, source}] + suggested verdict
- auth: none
- terms / licence: team-owned
- implementation notes: Rules: email informed by client = ok, found elsewhere = alert; HIBP IsFabricated -> against; verified -> ok, unverified -> alert; spam list -> alert (email circulated, no account); compilation (collection|combo|compilation|antipublic|exploit.in) -> doubt; stealer/malware -> alert; subject has a profile on the breached service domain -> ok (plausible); confirmed by >= 2 sources -> ok; email's domain registered (RDAP) AFTER the breach date -> against (false positive); too many hits -> generic-email alert. Verdict: fabricated or domain-after-breach -> false; (verified or 2 sources) and not spam/compilation and (strong ownership or plausible service) and not generic -> positive; else inconclusive. Becomes correlation rules CR10-CR12.

## P171 `correlation_pack_threat_intel` - Correlation pack: threat-intel consensus (CR27-CR30)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: threat_intel_ioc; group: G15; inputs: ipv4, domain, url, sha256, favicon_hash; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. Rules: CR27 multi_source_malicious, CR28 anonymized_infrastructure, CR29 favicon_clone_cluster and CR30 jarm_matches_known_c2. CR27 replaces the existing multi_source_malicious (CRITICAL at 2 module names), with a test documenting the change.
2. Independence: Finding.source (a registry source id) maps to an upstream family in the provider registry (AR11). The abuse.ch feeds (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker, SSLBL, YARAify) form one family, and Spamhaus another. Consensus counts distinct families, never modules, and records which sources were deduplicated.
3. Aggregators: FireHOL/IPsum aggregates count as the families they embed, and OTX pulses relaying abuse.ch count as abuse.ch.
4. CR27 is HIGH when >= 2 independent families list the entity inside the type's decay window (ip/url 30 days, domain 90 days), and MEDIUM with 1. Older hits are shown as history and not counted.
5. Suppression runs before CR27 and only downgrades, never deletes: warninglists (P169), sinkholes, benign scanners (GreyNoise 'benign', known research scanners) and noise/CDN ranges.
6. IPs in noise/CDN/shared-hosting ranges never give CR27 consensus to the domains behind them. Feeds disabled by the licence profile (P377) are not counted.
7. CR28: Tor exit / VPN / proxy membership is context only. It never exceeds LOW and is never tagged malicious, because these are lawful privacy tools.
8. CR29 needs at least one extra non-similarity signal (young domain, typosquat, phishing tag). An org_profile brand favicon served by a non-owned host, plus one extra signal, gives HIGH 'brand favicon clone'. Indexed favicon hashes are used first; fetching a hostile site's favicon is LIGHT and passes the P376 guard.
9. CR30 uses passive JARM values from indexed scan data. A live JARM probe is ACTIVE and runs only on in-scope authorized targets (A7); for hostile or other out-of-scope hosts only indexed values are used, whatever the egress. CR30 needs at least one extra signal and is low confidence otherwise.
10. Evidence lists the contributing sources, their upstream families, last_seen dates and terms class.
11. Graph fixtures: two modules sharing one upstream feed count once; a stale hit is not counted; a CDN IP does not taint co-hosted domains.

Chair rationale: Approved 6-0 at median P1. cti_lead and the architect showed that 'independent' means 'two module names' today, so URLhaus plus ThreatFox, or a FireHOL aggregate, double-count one upstream. Hence upstream families in the registry (architect floor) plus decay windows (cti_lead, analyst_ux). legal_dpo's floor: anonymity networks never above LOW, licence-disabled feeds not counted, terms class in evidence. redteam_lead: JARM/favicon from indexed data first, live probes gated. osint_investigator: brand favicon clones from org_profile.

Synthesizer conditions (background; the final conditions win on conflict): CR27 multi_source_malicious (HIGH with >= 2 independent sources after warninglist suppression; 1 source MEDIUM; sources sharing upstream data count once), CR28 anonymized_infrastructure (Tor exit / FireHOL proxies), CR29 favicon_clone_cluster, CR30 jarm_matches_known_c2 (needs >= 1 extra signal). Extends existing multi_source_malicious rule.
Notes: Consensus verdicts instead of single-feed alarms.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

## P172 `ioc_extraction_engine` - IOC extraction engine upgrade (decode -> refang -> span-masked extract -> validate -> warninglist)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: threat_intel_ioc; group: G15; inputs: text_blob, file, url; produces: url, domain, ipv4, ipv6, email, md5, sha1, sha256, cve, mitre_technique, btc_address, eth_address
- auth: none; key env vars: -; hosts: -
- upgrades existing module: modules/utility/ioc_extract.py

### Final conditions (binding spec - implement every item)

1. One implementation in core/ioc.py, with detect.extract_iocs and modules/utility/ioc_extract.py as thin wrappers. Stage order: decode layers -> refang -> span-masked extraction (URLs, e-mails, domains, IPs, hashes, CVE/ATT&CK, crypto) -> validation -> warninglist annotation -> pivot.
2. Licences: MIT patterns from ninoseki ioc-extractor and ioc-fanger are adapted with attribution in THIRD_PARTY_NOTICES.md. InQuest iocextract (GPL-2) and ioc-finder (LGPLv3+) are study material only, and there is no ioc-finder/pyparsing dependency.
3. Validation: ipaddress, IANA TLD + PSL, checksums (P217), ATT&CK ids against the bundled ATT&CK index (P292), plausible CVE years. Bogon/private IPs are kept but marked. TLDs that look like file extensions (.zip .mov .py .sh .md) get low confidence unless defanged, with a scheme, or resolving.
4. Bounds: decode depth <= 3, decoded output <= 2x input and <= 20 MB, base64 only for plausible blocks, embedded archives never decompressed. The 5,000-IOC limit is kept and reported when hit.
5. Performance tests: every regex is reviewed for catastrophic backtracking, with a pathological-input test (1 MB of dots/hyphens < 2 s); 1 MB of text extracts in < 2 s and 10 MB in < 10 s.
6. Brazilian scam text: national phone formats without '+' ((11) 98765-4321, 11 98765-4321, 0800), validated against the ANATEL DDD list; wa.me/<digits> and api.whatsapp.com/send?phone= -> phone; t.me/<name> and t.me/+<invite> -> telegram types (P333); instagram/tiktok/x profile URLs -> platform-qualified accounts; PIX BR Code (000201...6304+CRC) handed to P233; 14-digit CNPJ with a valid DV.
7. Privacy (legal floor): from text/file inputs only IOC_TYPES auto-expand. PERSONAL_TYPES (every e-mail, org_profile addresses included, phones, usernames, person names, CPF) become expand=False pivots listed for analyst selection (AR07). org_profile domains, the sender's own domain and warninglisted values are listed but not auto-pivoted.
8. CPFs and card numbers found in text are masked in every output (CPF as ***.456.789-**; a PAN truncated to BIN6 + last 4 at extraction) and are never expanded.
9. Pasted material is attacker-controlled. Extraction is static and offline (disclosure 'none'): files are never rendered, and remote templates, UNC paths, URLs and images are never resolved. IOCs from text are passive-only pivots: LIGHT/ACTIVE modules never run on them automatically.
10. URLs carrying a recipient identifier (an org_profile e-mail in plain, URL-encoded or base64 form) are flagged 'recipient token' and never fetched automatically (A7).
11. Output is defanged by default in terminal, HTML and Markdown (--no-defang disables it) and raw in JSON/STIX/MISP. Each IOC keeps its span (offset/line) as provenance. In interactive mode a one-screen preview ('37 IOCs: 12 domains, 5 IPs, 4 low-confidence') precedes scanning, with confirmation above 25 IOCs.
12. Tests: the existing test_detect/extract cases pass unchanged. A corpus test (real CTI reports and phishing e-mails, including a PT-BR SMS/WhatsApp text with personal data replaced) has precision/recall targets and an expected entity list.

Chair rationale: Approved 6-0 at median P1; core of 'paste anything'. Licences follow A6: no GPL/LGPL code or dependency, with ioc-finder not adopted (cti_lead, osint_investigator, architect floor; legal_dpo would only have allowed it as an optional extra). legal_dpo's privacy floor stops personal identifiers in pasted text from being auto-investigated. osint_investigator added the Brazilian scam-text formats, redteam_lead static parsing, passive-only pivots and recipient tokens. The architect's floor: one bounded, ReDoS-tested engine. analyst_ux asked for speed and the preview, cti_lead for defanged reports.

Synthesizer conditions (background; the final conditions win on conflict): Extends ioc_extract: stage order decode layers -> refang (ioc-fanger data patterns, MIT) -> extract with span masking (URLs, e-mails, domains, IPs, hashes, CVE/ATT&CK/crypto) -> validate (ipaddress, IANA TLD + PSL, checksums, ATT&CK ids exist, plausible CVE years) -> warninglist -> pivot; TLDs that look like extensions (.zip .mov .py .sh .md) low confidence unless defanged/scheme/resolves; print IOCs defanged by default. ninoseki ioc-extractor MIT (adapt); iocextract GPL-2 and ioc-finder LGPL-3 study only (ioc-finder allowed only as an unmodified dependency if the council agrees).
Notes: Core of the 'paste anything' workflow.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0326 IOC extraction + defang/refang from text, files and email bodies - V3LUM (own regex set; ideas from InQuest/iocextract GPL-2 & ninoseki/ioc-extractor MIT & swanandx/lemmeknow MIT)
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: []); passive: True; touches_target: False
- endpoint: offline ‖ n/a (local)
- method: refang first ([.] (.) {.} [dot] [@] (at) hxxp fxp [:]) -> typed regexes -> validators (IP octets, hash length/charset with sha256 checked before md5, Base58Check for BTC, EIP-55 optional, Luhn for cards, DV for CPF/CNPJ) -> warninglist filter ‖ Python re (stdlib) + ipaddress + IANA TLD set + PSL
- inputs: ['text_blob', 'file', 'email_headers', 'url']
- outputs: [design_ceos] ipv4/ipv6, domains, urls, emails, md5/sha1/sha256/sha512, CVE, ATT&CK ids, BTC/ETH/XMR wallets, onion, JWT, analytics ids, CNPJ/CPF (validated DV), phone, ASN -> every item becomes a pivot entity ‖ [gh_cti_ioc] Typed entities: url, domain, email, ipv4, ipv6, cidr, asn, md5/sha1/sha256/sha512, ssdeep, cve, mitre_technique (T/TA/G/S/M/C ids), btc/eth/xmr addresses, mac_address, analytics_id (UA-/G-/GTM-/pub-), user_agent, registry keys, file paths, TLP label, onion; each with span, original (defanged) text, confidence and warninglist tags.
- auth: none
- terms / licence: [design_ceos] own code. iocextract is GPL-2.0 and fhightower/ioc-finder is GPL-3.0 (study only); lemmeknow (MIT) and ninoseki/ioc-extractor (MIT) regexes may be adapted with attribution ‖ [gh_cti_ioc] Own code; MIT/Apache sources (ioc-extractor, mail-parser, gitleaks) may be adapted with attribution; GPL/LGPL sources (iocextract, ioc-finder) inspire ideas only.
- risk: none; defang all IOCs in reports/terminal output by default (hxxps://evil[.]com) to avoid accidental clicks.
- implementation notes: [design_ceos] Verified offline on a mixed sample: refanged hxxps/[.]/[@], extracted 2 IPs, 2 URLs, email, 3 domains, md5, sha256, CVE-2021-44228, T1566.002, BTC, ETH. Gotchas: domain regex must use the Public Suffix List (psl_full.dat is in the scratchpad) instead of a TLD whitelist; skip version strings (1.2.3.4 inside 'v1.2.3.4'), filenames (.js/.png), and the sample's own email domain. ‖ [gh_cti_ioc] Pipeline: (1) decode layers: URL-encoding, HTML entities, quoted-printable, base64 runs that decode to printable text (trufflehog decoder idea), hex-encoded "http" (687474703a2f2f), and iocextract-style base64 URL prefixes. (2) refang (port of ioc-extractor MIT regexes): " . " / [.] / (.) / {.} / \. / [dot] / (dot) -> "."; [:] -> ":"; [/] -> "/"; [://] -> "://"; [@] / [at] / (at) -> "@"; hxxp(s) / h**p(s) -> http(s); plus iocextract ideas: fxp/ftx -> ftp, "http__"/":__" -> "://", "http:\\" -> "//", Cisco ESA "example .com", fullwidth dot U+30FB/U+FF0E. Keep original span for the report. (3) extract in masking order (ioc-finder idea): URLs first, mask their spans, then emails, then domains (walk labels right-to-left to the longest suffix whose last label is in the IANA TLD set; registrable domain via PSL), IPv4 (validate with ipaddress; reject leading-zero octets or normalize; strip /CIDR into a separate cidr entity), IPv6 (validate with ipaddress; blank "[IPv6:" tags first; reject time strings like 12:30:45), hashes by hex length with non-hex boundaries (accept 0x-prefix), CVE-\d{4}-\d{4,7}, ATT&CK ids validated against the offline index, BTC (base58check + bech32 checksum to avoid MD5 FPs: ioc-finder issue #226), ETH 0x[0-9a-fA-F]{40} (EIP-55 checksum when mixed case), XMR 4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}, ASN (AS|ASN)\d+, MAC, ssdeep \d+:[A-Za-z0-9/+]{3,}:[A-Za-z0-9...
- sample: <scratch>/research/samples/design_cti_analysis_checks.json (valid_json)

#### C0337 ioc-extractor (refang regexes + validators) - github.com/ninoseki/ioc-extractor
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: []); passive: True; touches_target: False
- method: TypeScript source (src/aux/regexes.ts, utils.ts, validators.ts); port to Python
- inputs: ['text_blob']
- outputs: asns, btcs, cves, domains, emails, eths, gaPubIDs, gaTrackIDs, ipv4s, ipv6s, macAddresses, md5s, sha1s, sha256s, sha512s, ssdeeps, urls, xmrs (+ strict TLD option).
- auth: none
- terms / licence: MIT (Copyright 2018 Manabu Niseki) - port with attribution.
- implementation notes: Portable pieces: DOT_RE alternation [\s\.\s, ([[({])\.([\])}]), ([[({])\., \.([\])}]), \\\., ([[({])dot([\])}])], COLON_RE [[({]:[\])}], SLASH_RE, COLON_SLASH_RE [[({]://[\])}], AT_RE [[({](?:at|@)[\])}], HTTP_RE h(?:xx|\*\*)p(s?):// ; cheap has*() substring guards before running each regex (fast path); strict TLD list (aux/tlds.ts, 1,573 lines) vs non-strict [a-z-]{2,63}; punycode.toASCII for IDNs. Simple hash/crypto regexes (\b[A-F0-9]{32}\b etc.) need V3LUM's extra validation (see engine notes).

#### C0338 ioc-finder (pyparsing grammars) - github.com/fhightower/ioc-finder
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: pip ioc-finder 9.4.1 (deps: pyparsing>=3.1, ioc-fanger 5.1.x, click); Python>=3.10
- inputs: ['text_blob']
- outputs: ~35 observable types: urls (+complete), domains, emails (+complete), ipv4/ipv6/cidrs, socket addresses, asns, cves, md5/sha1/sha256/sha512/imphash/authentihash/ssdeep, registry key paths, Google AdSense/Analytics ids, bitcoin/monero, xmpp, mac, user agents, file paths, phone numbers, ATT&CK (enterprise/mobile/pre) tactics/techniques/mitigations, TLP labels.
- auth: none
- terms / licence: LGPL-3.0 (COPYING + COPYING.LESSER) - no code copying; using it unmodified as a pip dependency is LGPL-compatible (council decision).
- risk: LGPL: OK as an unmodified dependency, not OK to paste code. pyparsing grammars are slow on large blobs (it added regex fast paths).
- implementation notes: Best-in-class FP handling ideas: parse URLs first and mask spans so URL paths/queries do not resurface as domains (issue #244); remove URL userinfo before email parsing; remove "[IPv6:" before IPv6 parsing; domain walk right-to-left to last valid IANA TLD ("foo.com.invalid" -> "foo.com"); hash word-start excludes x/X so "0x<hash>" works (#41); BTC grammar warns about MD5/SHA collisions (#226); user-agent platform must not be followed by ":" (avoids eating "TLP:RED", #227); CVE year regex [12][0-9]{3} with ASCII-only digits. Options find_iocs(parse_domain_from_url, parse_from_url_path, parse_domain_from_email_address, parse_address_from_cidr, parse_urls_without_scheme, included_ioc_types) map well to V3LUM CLI flags.

#### C0357 InQuest iocextract (reference only) - github.com/InQuest/iocextract
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: pip iocextract 1.16.1 (depends on the third-party "regex" module and requests)
- inputs: ['text_blob']
- outputs: URLs (incl. bracket/backslash/hex/urlencoded/base64-encoded), IPv4/IPv6, emails, MD5/SHA1/SHA256/SHA512, YARA rules, US phone numbers, custom regex IOCs; refang/defang helpers.
- auth: none
- terms / licence: GPL-2.0 - study ideas only, no copying.
- risk: GPL-2.0: cannot embed code in V3LUM unless the whole tool goes GPL.
- implementation notes: Ideas worth re-implementing: scheme anchor [fhstu]\S\S?[px]s? to catch hxxp/fxp/ftx; delimiters :// | :\\ | [:]// | :?__ ; END_PUNCTUATION trimming (incl. \u201d \u2019 fullwidth brackets); base64 URL detection via precomputed base64 prefixes of "http://", "https://", "ftp://" at the 3 alignment offsets; refang via urlparse then netloc cleanup ([dot], (dot), [.], commas, U+30FB); defang = netloc dots -> [.] and scheme t->x. Telephone regex is US-only (not useful for BR).

#### C0717 ioc-fanger (data-driven fang/defang patterns) - pypi.org/project/ioc-fanger
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: pip ioc-fanger 5.1.1 (Python>=3.10)
- inputs: ['text_blob']
- outputs: Fanged (refanged) text; defanged text for safe report output.
- auth: none
- terms / licence: MIT (PyPI classifier) - patterns may be adapted with attribution.
- implementation notes: GitHub clone of fhightower/ioc-fanger failed (repo moved/private) - read the sdist from PyPI if adopting. ioc-finder calls ioc_fanger.fang() before parsing. V3LUM should also DEFANG every IOC it prints by default (hxxp, [.]) so reports pasted into chat/tickets do not become clickable.

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/design_cti_analysis_checks.json

## P217 `detector_crypto_onion_validators` - Checksum validators for crypto addresses and onion v3

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: crypto; group: G15; inputs: text_blob, btc_address, eth_address, xmr_address, other_crypto_address, onion; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/validators.py

### Final conditions (binding spec - implement every item)

1. Stdlib-only validators in core/validators.py, ported from the research prototype (all test vectors pass): onion v3 checksum (SHA3-256); BTC/LTC/DOGE/DASH/TRON base58check version bytes; bech32 vs bech32m by witness version; EIP-55 with a pure-python Keccak-256 (hashlib.sha3_256 is NOT Keccak); Monero block-base58 + Keccak checksum; the XRP alphabet.
2. Solana addresses stay low-confidence (no checksum). MD5-looking strings are never typed as BTC without a passing checksum.
3. TRON base58check is supported from day one, because USDT on TRON is a common payment rail in Brazilian scams. The validated chain selects the right explorer and pivot links.
4. The validators are offline (disclosure 'none') and add no dependency. Each format has positive and negative test vectors, and the existing detect tests pass unchanged.
5. P172 extraction and P333 typing use these validators. A failing checksum means the value is not typed, or gets low confidence when the context (TYPE:value prefix) is explicit.

Chair rationale: Approved 6-0 with no conditions from any member; the median is P2 (osint_investigator, legal_dpo and the architect voted P1). Offline, stdlib-only and already passing its vectors; osint_investigator stressed TRON for Brazilian fraud. The conditions restate the synthesizer's spec so it stands alone. Auditor: priority raised from the median P2 (a 3-3 tie) to P1 because P172 (P1) depends on these validators in phase 1 (A16 BR4); osint_investigator, legal_dpo and the architect voted P1 and the effort is S.

Synthesizer conditions (background; the final conditions win on conflict): Stdlib-only validators from the research prototype (all test vectors pass): onion v3 checksum (SHA3-256), BTC/LTC/DOGE/DASH/TRON base58check version bytes, bech32 vs bech32m by witness version, EIP-55 with pure-python Keccak-256 (hashlib.sha3_256 is NOT Keccak), Monero block-base58 + Keccak checksum, XRP alphabet; Solana stays low-confidence (no checksum); MD5-looking strings never typed as BTC without checksum.
Notes: Removes most crypto false positives and selects the right explorer.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0479 Offline crypto address detection & validation (BTC/LTC/DOGE/DASH/TRON/ETH/XMR/XRP/SOL/TON) - V3LUM (specs: BIP-173/350, EIP-55, Monero base58, rend-spec)
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: []); passive: True; touches_target: False
- endpoint: offline (stdlib only: hashlib sha256/sha3_256 + 40-line pure-python Keccak-256) ‖ local code (no network)
- method: offline
- inputs: ['btc_address', 'eth_address', 'xmr_address', 'other_crypto_address', 'text_blob']
- outputs: [caipora_apis_cti] chain + address type (p2pkh/p2sh/segwit v0/taproot, tron, doge...), checksum validity, normalized/checksummed form; lets the router pick the right providers and kill regex false positives ‖ [live_osint] chain/type + checksum validity: BTC base58check P2PKH(1)/P2SH(3), bech32/bech32m bc1q/bc1p (BIP-173/350), LTC (L/M/ltc1), DOGE (D), TRON (T, 0x41), EVM EIP-55, XMR (95/106 chars, 4/8), SOL (base58 32 bytes)
- auth: none
- rate limit: Offline.
- terms / licence: [caipora_apis_cti] Own implementation from public specs (no third-party code). ‖ [live_osint] Public specs; own implementation.
- implementation notes: [caipora_apis_cti] Prototype at research/tmp_caipora_apis_cti/validators.py, all test vectors pass: base58check version bytes (0x00 BTC, 0x05 P2SH, 0x30/0x32 LTC, 0x1e/0x16 DOGE, 0x4c DASH, 0x41 TRON), bech32 vs bech32m by witness version, EIP-55 needs Keccak-256 (NOT hashlib.sha3_256 - different padding), Monero = block base58 (8 bytes->11 chars) + keccak checksum, netbyte 0x12/0x2a/0x13; XRP uses alphabet rpshnaf39w...; Solana has no checksum (low confidence). XMR: no public balance/tx lookup by address is possible (privacy) - V3LUM should only validate XMR, report OFAC hits and link xmrchain.net for tx ids. ‖ [live_osint] Selftest passed (genesis address base58check, BIP-173 vector). GOTCHA: hashlib.sha3_256 is NIST SHA-3, not Keccak-256 (sha3_256('')=a7ffc6f8... vs keccak256('')=c5d24601...) -> EIP-55 needs pycryptodome Crypto.Hash.keccak or a pure-Python Keccak.
- sample: <scratch>/research/samples/caipora_apis_cti__offline_validators_results.json (valid_json)
- sample: <scratch>/research/samples/live_osint__offline_validators_selftest.json (valid_json)

#### C0455 Onion v3 address validation (offline) - V3LUM (Tor rend-spec-v3)
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: []); passive: True; touches_target: False
- endpoint: offline: base32 decode 56 chars -> pubkey(32) | checksum(2) | version(1)=3; checksum = SHA3-256(".onion checksum" + pubkey + version)[:2]
- inputs: ['onion', 'text_blob', 'url']
- outputs: valid/invalid v3 onion, embedded ed25519 public key; rejects deprecated v2 (16-char) onions
- auth: none
- terms / licence: Own implementation of the public Tor spec.
- implementation notes: Verified with torproject.org and duckduckgo onions (valid) and a 1-char mutation (invalid). hashlib.sha3_256 is correct here (NIST SHA3, unlike Ethereum Keccak). Use in the entity detector and before any onion enrichment.
- sample: <scratch>/research/samples/caipora_apis_cti__offline_validators_results.json (valid_json)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/caipora_apis_cti__offline_validators_results.json
- <scratch>/research/samples/live_osint__offline_validators_selftest.json

## P258 `correlation_pack_identity_company` - Correlation pack: identity links & company signals (CR32-CR34 + Céos identity/company heuristics)

- council: **approved**, priority P2, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: person_name; group: G15; inputs: username, email, person_name, cnpj, domain; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. Rules CR32 shared_registrant_cluster, CR33 shell_company_indicators and CR34 identity_link_strength, plus the Ceos anti-homonym and cross-company heuristics. These correlations never create pivots and never expand anything.
2. CR34 levels: CONFIRMED only for cryptographic proof or an analyst decision. PROBABLE only with an explicit linkage signal kept as evidence (linked profile, non-default avatar dHash <= 8, Gravatar hash, PGP UID, Docker label). POSSIBLE = same handle only, labelled 'same handle does not prove identity'.
3. Links between natural persons are capped at PROBABLE without analyst confirmation, and an automatic level never rises above an analyst decision.
4. Avatar matching is image re-use detection only: dHash via the optional Pillow extra, on images already fetched by an approved passive module. Images are never stored (hash only), per-platform default avatars (a hash blocklist) never count, and there is no face recognition and no biometric template (LGPD art. 11).
5. CR33 is titled 'shell-company indicators (n of m)', never 'shell', 'laranja' or 'front', and is MEDIUM at most. It uses only official RFB fields (situacao, abertura, natureza juridica, porte/MEI, capital social, QSA). Named constants: opened < 1 year or lived < 2 years, AND MEI or capital < R$5,000, AND a shared address/phone/e-mail/co-partner. Each indicator is listed with its source.
6. Shared address/phone/e-mail signals are discounted when the contact is shared by >= 20 companies in the source, and labelled 'possible accountant/virtual office'.
7. Partner matching across companies needs the name plus compatible masked-CPF digits from QSA. A name-only match stays POSSIBLE, and IBGE name frequency (P252) lowers common names. Filiation, date of birth and other 'painel' attributes are never used.
8. Person names enter these rules automatically only from official registers (QSA/RFB) with the masked-CPF check above; any other name (free text, pages, pivots, RDAP legalRepresentative) is used only after analyst confirmation.
9. CPF is used only when the analyst supplied it or it is already present in collected official open data. It is masked in every output (***.456.789-**), never a pivot, and never looked up or sent to any third party (rule 4).
10. Person names from QSA and from RDAP legalRepresentative are never auto-expanded. Every CR32-CR34 finding is tagged privacy and excluded from STIX/MISP exports unless the analyst selects it (--include-personal).
11. The rules run only in cases with a recorded purpose (AR16). Outputs are suggestions requiring analyst validation, never the sole basis for a decision about a person (LGPD art. 20). Linked profiles are never used to infer sensitive data (art. 11).
12. Presentation: every identity link shows its level and evidence chain. POSSIBLE links appear only in the entity map and HTML details, never in the terminal top findings. Analyst decisions win and survive re-runs.
13. Tests: positive and negative graph fixtures, including a homonym case that stays POSSIBLE with the label, a default-avatar match that does not count, and an accountant contact shared by 20+ companies.

Chair rationale: Approved 6-0 at median P2. These rules profile natural persons, so legal_dpo's floor governs: PROBABLE cap without analyst confirmation, CPF minimisation, no biometrics, no sensitive inference, a recorded purpose, art. 20. The architect's floor: never escalate or expand automatically, hashes only via the optional extra, named constants, a homonym fixture. osint_investigator removed the two classic false links (shared accountant contacts, default avatars). cti_lead asked for export exclusion, analyst_ux for visibility of level and evidence. redteam_lead found the synthesizer conditions sufficient. Auditor: cti_lead's export exclusion and analyst-confirmed names restored. default_enabled stays true because P258 is an offline, purpose-gated correlation pack, not a person_name source module (A3 BR2 as clarified).

Synthesizer conditions (background; the final conditions win on conflict): CR32 shared_registrant_cluster, CR33 shell_company_indicators (opened < 1 y or lived < 2 y AND MEI/capital < R$5,000 AND shared address/phone/e-mail/co-partner), CR34 identity_link_strength (CONFIRMED = cryptographic proof; PROBABLE = linked profile/avatar dHash <= 8/Gravatar hash/PGP UID/Docker label; POSSIBLE = same handle only, labelled 'same handle does not prove identity'); Céos anti-homonym rules (CPF-aware without ever looking CPFs up) and cross-company coincidences; confidence never raised automatically above analyst decisions.
Notes: Explainable identity and shell-company signals (Céos core value).

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0223 Céos cross-account linking heuristics - Céos ceos/coletores/mesmo_usuario.py + ceos/perfil_extra.py (team code)
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- endpoint: ceos/coletores/mesmo_usuario.py (avaliar, enriquecer, verificar), ceos/perfil_extra.py (dhash, plana, hashes_gravatar, docker_emails, pgp_emails/_uids_pgp, keybase_linha_tempo, hackerone)
- method: contas, cruzamentos, buscas_telegram (https://chatcrawler.app/c/search?q={handle} as pivot link) ‖ offline (+ the public APIs listed separately)
- inputs: ['username', 'email', 'image']
- outputs: [design_ceos] cross-links {type: same handle | same photo | registered email | same email, text, ids}; Telegram ChatCrawler search links ‖ [gh_people] Confidence (probable/possible/discard) for 'same handle = same person': linked-account proof (profile points to already linked GitHub; Keybase proofs; Gravatar verified accounts), name match against name forms, Gravatar hash (MD5/SHA-256 of normalized email) == target email, Docker image LABEL maintainer email == target email, Keybase PGP UID email == target email, avatar dHash (64-bit, Hamming <= 8, flat-image filter stddev<6).
- auth: none
- terms / licence: Team-owned code (port to English).
- risk: [design_ceos] ChatCrawler is behind a Cloudflare bot challenge: links only (no automation). ‖ [gh_people] Same handle is never proof of identity; keep 'possible' unless a linkage signal exists.
- implementation notes: [design_ceos] Becomes correlation rule CR34 (identity link strength). Platform derived at read time (evidence first, URL second). ‖ [gh_people] Port wholesale: per-site 'aceita' regex, verificar() tri-state (403/429/5xx/exceptions = failure, never absent), avaliar() levels, enrichment. Pillow needed for dHash.

#### C0585 Identity resolution / anti-homonym rules (CPF-aware) - Céos ceos/identidade.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: normalizar (NFKD ASCII upper), nome_igual, nome_compativel (target name contained in order, same first+last), casar_nome, nome_contido, cpf_compativel (full or masked ***.123.456-**), classificar
- inputs: ['person_name', 'cpf']
- outputs: (confidence, criterion) or None when the record is clearly someone else
- auth: none
- terms / licence: team-owned
- risk: LGPD: CPF only when supplied by the analyst for an authorized case; mask in exports (Céos postponed masking - V3LUM should mask by default).
- implementation notes: Rules to keep verbatim: full CPF equal -> CONFIRMED; masked CPF compatible -> strong signal; CPF incompatible -> automatic discard (homonym); same city or mother's name in text -> PROBABLE; same state (UF) only -> weak (stays POSSIBLE); name only -> POSSIBLE; name 'contained' (missing middle names) never above PROBABLE and only with partial CPF; no typo tolerance. Generalize signals for non-BR subjects (DOB, city, employer, email).

#### C0514 Company risk signals + cross-company coincidences - Céos ceos/empresas.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: _sinais, _sinais_cruzados, _completar (fill empty fields from other sources with origin), _peso_ficha, _MOTIVOS_GRAVES, _SOBRENOMES_COMUNS, _sobrenomes, _tel_chave
- inputs: ['cnpj', 'company_name', 'person_name']
- outputs: signals {level high|medium|info, text, origin} per company and across the subject's companies
- auth: none
- terms / licence: team-owned
- implementation notes: High: situação INAPTA/SUSPENSA/NULA, situação especial. Medium: BAIXADA for omissão/inexistência de fato/inaptidão/irregular; sensitive CNAE; opened < 1 year; lived < 2 years; indirect control (subject is legal representative of a PJ partner). Info: single partner, MEI or capital < R$5,000, company email uses subject's name or a free provider, company outside subject's city, co-partner shares an UNCOMMON surname (25 most common BR surnames excluded) -> possible relative, divergent status between sources, branches. Cross: same phone (DDD+last 8), same email, same address, same co-partner, same legal representative across different holdings. Feed CR33.

## P291 `correlation_pack_attack_surface` - Correlation pack: attack surface exposure (CR07, CR08, CR13-CR16, CR25, CR26, CR31)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: pentest_recon; group: G15; inputs: domain, ipv4, cve, asn; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. Rules CR07 subdomain_takeover_candidate, CR08 dangling_cloud_ip, CR13 exposed_remote_admin, CR14 exposed_database_or_cache, CR15 known_exploited_vuln_on_asset, CR16 outdated_version_disclosed, CR25 stale_host, CR26 shadow_it_outlier and CR31 certificate_san_affiliate (INFO). They replace the existing exploitable_exposure rule, which gets the same caps.
2. Rules consume only vocab facts (open_ports, services, cpes, vulns, kev, epss, cvss, CNAME/NXDOMAIN facts) and KEV/EPSS through core/datasets. Rules make no network calls.
3. CR15 is CRITICAL only when (KEV or EPSS >= 0.5) AND the vulnerability is verified AND the asset is an org_profile own asset or in-scope target. Verified means: the source marks it verified, evidence specific to the CVE goes beyond a version string, or an authorized ACTIVE check confirmed it. CVSS >= 9 alone never yields CRITICAL.
4. Version-inferred matches (InternetDB/Shodan CPE, CR16) are POSSIBLE, capped at HIGH when in KEV and at MEDIUM otherwise, with the label 'version-inferred, distro backports not considered: confirm on the host'. They produce one finding per host+product, not one per CVE.
5. Ownership: CR13-CR16, CR25 and CR26 keep their severity only for org_profile own assets or in-scope targets; third-party hosts get INFO context. On entities tagged malicious/phishing/c2 the same facts are INFO pivots for infrastructure fingerprinting.
6. CR07 needs a CNAME to a service fingerprint marked vulnerable (pinned, attributed list) AND dangling evidence (NXDOMAIN of the CNAME target, or the provider's unclaimed-resource fingerprint). It is worded 'candidate' and never claims or registers the resource.
7. CR08 is POSSIBLE unless the evidence is strong, and never re-acquires IPs. CR07/CR08 use passive evidence unless an ACTIVE module ran under the gate.
8. CR13/CR14 carry the observation date; data older than 30 days lowers confidence by one level. CR25 stale_host needs >= 3 bad signals, and a missing security.txt is not one.
9. CR26 (outlier <= 10% of assets) runs only with >= 20 org assets (configurable threshold).
10. Findings outside org_profile are labelled third_party and never trigger ACTIVE verification automatically. SAN affiliates (CR31) and co-hosted domains never join the active scope.
11. Tests: positive and negative graph fixtures per rule. An nginx host with 20 CPE CVEs and one KEV entry gives one HIGH POSSIBLE finding, not 20 CRITICALs.

Chair rationale: Approved 6-0 at median P1 (cti_lead and osint_investigator voted P2). The members agree that version-inferred CVEs are the biggest false-positive generator: CRITICAL now needs verification plus KEV/EPSS on an owned or in-scope asset (redteam_lead, analyst_ux, cti_lead; the architect's floor enforces the caps in code). legal_dpo's floor: takeover candidates are never verified by claiming, third-party findings never trigger ACTIVE work. osint_investigator turned exposure on attacker infrastructure into INFO pivots, and redteam_lead kept SAN affiliates out of scope.

Synthesizer conditions (background; the final conditions win on conflict): CR07 subdomain_takeover_candidate, CR08 dangling_cloud_ip, CR13 exposed_remote_admin, CR14 exposed_database_or_cache, CR15 known_exploited_vuln_on_asset (CRITICAL: KEV or EPSS >= 0.5 or CVSS >= 9), CR16 outdated_version_disclosed (version-inferred: low confidence), CR25 stale_host (>= 3 bad signals), CR26 shadow_it_outlier (SpiderFoot outlier <= 10% of assets), CR31 certificate_san_affiliate (INFO). Extends existing exploitable_exposure rule.
Notes: Prioritised exposure findings for the org's own assets.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

## P301 `correlation_engine` - SpiderFoot-style YAML correlation rule engine

- council: **approved**, priority P2, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: cti_framework; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/correlate.py

### Final conditions (binding spec - implement every item)

1. Python @rule stays first-class. The approved packs (P027, P028, P084, P146, P171, P258, P291) ship now as @rule functions and are not blocked by the YAML engine.
2. Both kinds of rule share one metadata API: id, version, title, severity, criterion, references, ATT&CK ids, false-positive notes, positive and negative graph fixtures. There is one registry and one listing (`v3lum rules`), with per-rule precision.
3. YAML/JSON/TOML rules are optional data compiled into the same RuleInfo objects (one engine, one result type). They are loaded with a safe parser (JSON/TOML; PyYAML safe_load only as an optional extra; no eval/exec or object tags) and schema-validated at load, and validation errors fail CI.
4. The SpiderFoot correlation model is ported with MIT attribution (THIRD_PARTY_NOTICES.md): collections with exact or regex filters (bounded, reviewed regexes) -> aggregation field -> analysis method -> headline. Analysis methods are limited to threshold | outlier | first_collection_only | match_all_to_first_collection | both_collections over vocab-keyed graph queries.
5. Rules run once after the BFS, because the pipelined engine has no pivot rounds. They only read the graph and emit correlations: they never schedule modules or pivots, change the opsec mode or widen the scope. Correlation adds < 2 s to a scan.
6. Every correlation carries evidence (finding ids + facts used), a one-line 'why', a recommendation and ATT&CK ids validated against the bundled ATT&CK data, with revoked ids mapped to their replacements (e.g. T1656 -> T1684.001).
7. Suppression rules only downgrade confidence, with a visible label, and never delete. Rules touching natural persons inherit the P258 caps.
8. Per-rule precision comes from P325: a rule with precision < 0.3 after >= 10 votes is demoted one severity level and flagged in doctor, never silently disabled.
9. User rule directories (~/.v3lum/rules) follow the plugin ownership/permission checks (AR12), are linted like modules and are listed by doctor.

Chair rationale: Approved 6-0 at median P2 (legal_dpo P1, analyst_ux P3). cti_lead, osint_investigator and analyst_ux insisted that the correlation packs must not wait for this L-effort engine. The architect's floor: YAML compiles into the existing RuleInfo, safe loader, schema validation, rules run once after the BFS and never schedule pivots. redteam_lead: rule files are data and cannot trigger collection. legal_dpo: SpiderFoot MIT notice, downgrade-only suppression, P258 caps. Demotion of imprecise rules is analyst_ux's, the doctor flag osint_investigator's.

Synthesizer conditions (background; the final conditions win on conflict): Port the SpiderFoot correlation model (MIT): collections with exact/regex filters -> aggregation field -> analysis method (threshold | outlier | first_collection_only | match_all_to_first_collection | both_collections) -> headline; runs after each pivot round; results carry ATT&CK ids (attack_mapping table from design_ceos, ids validated, revoked T1656 -> T1684.001) and evidence links; rule precision tracked by the feedback loop (rules with precision < 0.3 after >= 10 votes flagged). Keep the existing @rule Python functions working alongside YAML rules.
Notes: Turns many weak per-source facts into explainable cross-source findings.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0656 SpiderFoot correlation-rule engine (YAML rules) - github.com/smicallef/spiderfoot
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- endpoint: offline ‖ local: correlations/*.yaml (37 rules + template) evaluated over the scan result store
- method: rule = meta(id,name,severity,description) + collections (exact/regex filters on entity type/value/source/field) + aggregation (group by field) + analysis (threshold, outlier, first_collection_only, match_all_to_first_collection, both_collections) + headline template
- inputs: ['text_blob']
- outputs: [design_ceos] correlation results {rule id, severity, headline, entities, evidence finding ids, ATT&CK ids} ‖ [gh_infra] Correlation findings {rule id, risk INFO/LOW/MEDIUM/HIGH, headline, contributing entities}.
- auth: none
- terms / licence: [design_ceos] SpiderFoot MIT: engine design and its 37 rules may be adapted with attribution ‖ [gh_infra] MIT (rules and engine may be adapted with attribution)
- risk: none; rules that SUPPRESS (generic email, breach-before-domain) must only downgrade confidence, never delete.
- implementation notes: [design_ceos] SpiderFoot ships 37 rules (e.g. stale_host = >=3 distinct bad-signal types on one host; outlier_registrar = registrar used by <=10% of domains; email_in_multiple_breaches). V3LUM rule list (35, with severity + ATT&CK) is in the top-level 'correlation_rules' key and summarized in design_notes. Rules run after every pivot round, so new entities can trigger more collection (bounded by max depth). ‖ [gh_infra] STATUS NOTE: this is an offline algorithm. "unverified" only means it was not executed, because cloned code is read-only in this sweep; its behaviour is taken from line-by-line code reading. Rule = {id, version, meta{name, description, risk}, collections[ {collect:[ {method: exact|regex, field, value(s)} ]} ], aggregation{field}, analysis[...], headline "...{field}..."}. field can be type, module, data, or the same with a source./child./entity. prefix (the event graph). A value prefixed "not " negates the match. Analysis methods: threshold (minimum/maximum count per bucket, count_unique_only); outlier (keep buckets whose share is below maximum_percent, but skip the rule when the average bucket share is below noisy_percent, default 10, because the data is too flat); first_collection_only (items found ONLY by collection 1, e.g. hosts seen only in CT logs or only via brute force); match_all_to_first_collection (match_method exact|contains|subnet, e.g. Wikipedia edits from target-owned netblocks). Rules worth adopting in V3LUM: multiple_malicious (same entity flagged by 2+ distinct sources = HIGH; cohost and affiliate variants = LOW); email_in_multiple_breaches (2+ breaches, metadata only); outlier_{cloud,country,registrar,webserver,hostname,email,ipaddress} (shadow-IT hints); host_only_from_certificatetransparency and host_only_from_bruteforce (provenanc...

## P302 `risk_model` - Risk model (severity x confidence x Admiralty reliability x MISP decay x asset criticality, noisy-OR)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: cti_framework; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/scoring.py

### Final conditions (binding spec - implement every item)

1. A pure function in core/scoring.py with documented constants. W_sev: CRITICAL 10 / HIGH 7 / MEDIUM 4 / LOW 2 / INFO 0. C_conf (P322): CONFIRMED 1.0 / PROBABLE 0.7 / POSSIBLE 0.4. R_src, the Admiralty prior from the provider registry: A 1.0, B 0.85, C 0.7, D 0.5, E 0.3, F 0.5. Per-finding weight = W_sev/10 x C_conf x R_src x decay x A_crit, combined by noisy-OR and capped at 100.
2. Decay follows the MISP polynomial base x (1 - (t/tau)^(1/delta)), with named constants tau: ip 30 d, url 30 d, domain 90 d, typosquat 180 d, breach 3 y, infostealer 1 y, hashes no decay; delta defaults to 1.0. t is computed from Finding.observed_last. Findings without a provider timestamp get no decay and the label 'age unknown'.
3. Severity ceiling: an entity or case level never exceeds the highest severity among its contributing findings and correlations. Weak signals escalate only through an explicit correlation rule.
4. Correlations never add on top of the findings they are built from: they take the max/uplift, not a second noisy-OR term. Contributions are deduplicated per (entity, tag family, upstream family). '+1 confidence level' applies only with >= 2 independent upstream families (P171).
5. Case score = seeds + correlations + the top-5 pivot entities, not every pivot. Pivot contributions are weighted by path confidence (AR07). Shared-infrastructure relations (co-hosted, same ASN, same NS/MX, CDN) cap the transferred contribution at LOW. Own assets and known-good/verified entities (BCB verified FI domains, gov.br) never inherit risk from neighbours.
6. A seed reads 'inconclusive' (never 'clean' or 'no findings') when fewer than 2 reputation-capable sources answered OK/EMPTY for it. The lowest level is renamed 'no findings', and the thresholds 80/55/30/8 stay.
7. A warninglist hit makes the finding POSSIBLE, with a label. Sources disabled by the licence profile contribute nothing. R_src is Beta-updated only by explicit feedback, after >= 5 votes (P325), with a floor of 0.3.
8. Asset criticality from org_profile gives A_crit: critical 1.0, high 0.95, medium 0.85, low 0.6. Entities without profile criticality use 1.0.
9. Output: the top-3 contributors with finding ids, path and confidence label, printed in plain words next to the score. Every report labels scores 'triage aid, not a conclusion'. The risk.score/level JSON fields stay backward compatible so stored cases still render.
10. For PERSONAL_TYPES entities the score is shown only with its top contributors. It is never exported to STIX/MISP as a score about a person and never drives an automated action (LGPD art. 20).
11. The model lands after the fields it needs (Finding.observed_last, Finding.source with its upstream family, the P322 labels). Golden-case tests: 30 pivots with one LOW each stay <= low (83.1 = critical today); one CONFIRMED CRITICAL outranks any number of LOWs; 2 HIGH findings plus their correlation stay HIGH; frozen-time tests per decay class.

Chair rationale: Approved 6-0 at median P1 (redteam_lead and the architect voted P2). analyst_ux measured the inflation: 30 single-LOW pivots score CRITICAL, and the draft formula ranks 10 LOW above 1 PROBABLE CRITICAL. Hence the severity ceiling, deduplication and top-5 pivots. cti_lead found double counting with correlations and 'clean' scores for unverified seeds, osint_investigator the guilt by association. The architect's floor: a pure function, golden tests, provenance and timestamps first, no decay without a timestamp, backward-compatible JSON. legal_dpo's floor: 'triage aid', no person scores exported, no automated action on them.

Synthesizer conditions (background; the final conditions win on conflict): Implement risk_model from design_ceos: W_sev CRITICAL 10/HIGH 7/MEDIUM 4/LOW 2/INFO 0; C_conf CONFIRMED 1.0/PROBABLE 0.7/POSSIBLE 0.4; R_src Admiralty A 1.0..E 0.3, F 0.5; MISP polynomial decay with tau ip 30 d, url 30 d, domain 90 d, typosquat 180 d, breach 3 y, infostealer 1 y, hashes no decay; noisy-OR aggregate capped at 100 with top-3 contributors; +1 confidence when >= 2 independent sources agree; warninglist hit -> POSSIBLE + label; Beta feedback per source and rule.
Notes: Explainable 0-100 scores replacing ad-hoc weights.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0655 Risk-scoring model (severity x confidence x reliability x decay, noisy-OR aggregate) - V3LUM (MISP decaying-model formula + Admiralty code)
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: []); passive: True; touches_target: False
- endpoint: offline
- method: see top-level 'risk_model'
- inputs: ['text_blob']
- outputs: per-finding risk 0-10, per-entity and per-case score 0-100 with top contributing findings (explainable)
- auth: none
- terms / licence: own model; MISP decay formula is public
- risk: Scores are triage aids, never conclusions (Céos rule: signals are not verdicts).
- implementation notes: Polynomial decay s(t)=b*(1-(t/tau)^(1/delta)) verified (b=80, tau=30 d, delta=2: 80 -> 65.4 @1d -> 41.4 @7d -> 23.4 @15d -> 0 @30d). Analyst feedback ('did this make sense?') updates per-source/per-rule Beta(alpha,beta) reliability.
- sample: <scratch>/research/samples/design_cti_analysis_checks.json (valid_json)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/design_cti_analysis_checks.json

## P303 `export_stix_misp` - STIX 2.1 determinism + MISP event export

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: cti_framework; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: report/stix.py

### Final conditions (binding spec - implement every item)

1. STIX 2.1 and MISP event JSON are hand-rolled, with no stix2/PyMISP runtime dependency; both serve only as dev test oracles. MISP galaxy data is used under its licence, with notice.
2. Deterministic ids. SCOs = uuid5(namespace 00abedb4-aa42-466c-9c01-fed23315a9b7, JCS of the id-contributing properties), with hash preference MD5 > SHA-1 > SHA-256 > SHA-512. Findings and notes use the deterministic Finding ids (AR09).
3. Global SDOs get stable ids, never case-scoped: vulnerability = uuid5 of the CVE id; attack-pattern = the official ATT&CK STIX id from P292; malware/threat-actor = the MISP galaxy uuid.
4. Markings: every SDO/SCO carries object_marking_refs from the case TLP (TLP 2.0 marking definitions, AMBER+STRICT supported). MISP events get tlp:* tags and distribution 0 (your organisation only) for AMBER, AMBER+STRICT and RED. Research-profile cases carry the licence banner.
5. Indicators are emitted only for CR27 consensus or analyst-confirmed findings; today a single 0.3-confidence finding becomes an indicator. They carry confidence 90/70/40 from P322, valid_until from the P302 decay tau and ATT&CK/kill-chain refs when known. POSSIBLE and warninglisted IOCs export as observables only (MISP to_ids=false) unless --include-weak.
6. Personal data is excluded by default: PERSONAL_TYPES SCOs (email-addr, user-account, phone, person names, CPF) and person identities need --include-personal, and CPF stays masked even then. report.description and notes never list seeds of those types; today bundle() writes every seed key there. Analyst notes and local evidence paths are never exported.
7. STIX pattern values are escaped for every type, so an e-mail containing a quote cannot break the pattern.
8. Export writes files. A REST push to the team's MISP/OpenCTI exists only as an explicit command with a dry-run summary ('1 event, 23 attributes, 4 to_ids') and confirmation, and only to configured internal instances with TLS verification on (ca_bundle). Pushed events are unpublished, distribution 0 (your organisation only) at every TLP, with no sharing group and no auto-sync.
9. Pushes never go to external sharing communities or to other organisations' instances.
10. Never pushed: RED cases and research-profile cases. Cases from LIGHT/ACTIVE engagements are excluded unless the analyst flags them exportable. AMBER+STRICT cases go only to the organisation's own instance with distribution 0.
11. Golden-file tests are validated against the stix2 oracle in dev and against the MISP JSON format, including personal-data stripping, markings on every object and quote-containing values.

Chair rationale: Approved 6-0. The chair raises the priority from the median P2 to P1 on the legal floor: today stix.py leaks every seed (CPF, person, phone) into report.description and emits no markings, and A2 requires markings on every export (legal_dpo and cti_lead voted P1 and list it as a must-have). cti_lead supplied indicator gating, stable SDO ids and decay; redteam_lead the organisation-only, unpublished push and engagement exclusion; osint_investigator and legal_dpo personal-data stripping; the architect's floor hand-rolled JSON, deterministic ids, escaping and an explicit draft-only push; analyst_ux weak IOCs as observables only.

Synthesizer conditions (background; the final conditions win on conflict): Hand-rolled STIX 2.1 (no stix2 runtime dependency; stix2 only as a dev test oracle): deterministic SCO ids = uuid5(namespace 00abedb4-aa42-466c-9c01-fed23315a9b7, JCS of id-contributing properties), hash preference MD5 > SHA-1 > SHA-256 > SHA-512; add a MISP event JSON export (attributes + galaxy tags with MISP galaxy uuids) without PyMISP; optional REST push to the team's MISP/OpenCTI only with explicit config.
Notes: Results flow into the team's MISP/OpenCTI.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0665 STIX 2.1 bundle export (hand-rolled; cti-python-stix2 only as test oracle) - github.com/oasis-open/cti-python-stix2
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: []); passive: True; touches_target: False
- endpoint: offline (export file) ‖ n/a (local)
- method: deterministic SCO ids = UUIDv5(namespace 00abedb4-aa42-466c-9c01-fed23315a9b7, canonical JSON of id-contributing properties); TLP:CLEAR/GREEN/AMBER/AMBER+STRICT/RED standard marking-definition ids ‖ Library-free: json + uuid
- inputs: ['text_blob']
- outputs: [design_ceos] bundle with identity (V3LUM), SCOs (domain-name, ipv4-addr, url, email-addr, file hashes...), indicators (STIX patterns), observed-data, attack-patterns (external_id), relationships, TLP 2.1 markings ‖ [gh_cti_ioc] STIX 2.1 bundle of the V3LUM case: identity, report, indicator (pattern), SCOs (ipv4-addr, ipv6-addr, domain-name, url, email-addr, file{hashes}, autonomous-system, x509-certificate), threat-actor/intrusion-set, malware, attack-pattern (external_id refs), relationship, sighting/note (analyst feedback). Importable into MISP/OpenCTI.
- auth: none
- terms / licence: [design_ceos] OASIS STIX 2.1 spec; cti-python-stix2 BSD-3-Clause ‖ [gh_cti_ioc] stix2 3.0.2 = BSD-3-Clause (OASIS); hand-rolled code is ours.
- risk: Default marking TLP:AMBER (internal team); strip analyst notes and personal data (CPF etc.) unless explicitly exported.
- implementation notes: [design_ceos] Built and saved a 6-object bundle without any library; SCO id determinism verified (same value -> same id, so MISP/OpenCTI dedupe works). Map V3LUM confidence CONFIRMED/PROBABLE/POSSIBLE -> STIX confidence 90/70/40. Optional: MISP event JSON export with the same objects. ‖ [gh_cti_ioc] Recommendation: hand-roll the emitter, keep stix2 as a dev/test dependency only. stix2 pulls pytz, requests, simplejson, stix2-patterns (antlr4 runtime) - too heavy for an export-only need. Deterministic SCO ids (read in stix2/base.py): id = "<type>--" + uuid5(UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), JCS(id-contributing props)). JCS (RFC 8785) == json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False) when all values are strings. ID-contributing props: ipv4/ipv6/domain-name/url/email-addr/mac-addr -> value; file -> hashes,name,parent_directory_ref,extensions; autonomous-system -> number; x509-certificate -> hashes,serial_number; user-account -> account_type,user_id,account_login; windows-registry-key -> key,values. Hashes: keep ONE in this preference order MD5 > SHA-1 > SHA-256 > SHA-512 (stix2 _choose_one_hash). Computed here: ipv4-addr 8.8.8.8 -> ipv4-addr--2f689bf9-0ff2-545f-aa61-e495eb8cecc7; domain-name example.com -> domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7 (cross-check once in a test venv with stix2). SDO ids = uuid4; timestamps RFC3339 with ms + Z; indicator pattern e.g. "[domain-name:value = 'example.com']", pattern_type "stix", valid_from required. Escape quotes/backslashes in pattern values.
- sample: <scratch>/research/samples/design_stix21_bundle.json (valid_json)

#### C0661 MISP / OpenCTI / IntelOwl interoperability (STIX 2.1 + MISP event export) - misp-project.org / OpenCTI-Platform / intelowlproject
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- endpoint: offline export; optional REST: {MISP}/events/add (Authorization: key), OpenCTI GraphQL {url}/graphql, IntelOwl {url}/api/analyze_observable
- inputs: ['text_blob']
- outputs: V3LUM case -> STIX 2.1 bundle (indicators, observables, threat-actor, relationships) and MISP event JSON; optional push to the team MISP/OpenCTI and pull of IntelOwl analyzer results
- auth: none
- terms / licence: stix2 (BSD-3), PyMISP (BSD-2), pycti (Apache-2.0) usable as deps; IntelOwl AGPL (ideas only).
- implementation notes: Makes V3LUM output reusable by platforms the team may already run. Use MISP galaxy cluster uuids for actor tags so exports merge cleanly.

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/design_stix21_bundle.json

## P311 `pivot_link_engine` - Pivot-link engine and page generator (Céos fontes_manuais port)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: search_dorks; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/links.py

### Final conditions (binding spec - implement every item)

1. core/links.py loads data/pivot_links/*.json packs. The schema is frozen in phase 0, before G14 starts: label, template, entity_types, category, host (discloses_to), verified, checked_at, privacy, publishes (must be false), touches_target, login_required, antibot. The current loader format is migrated, with a test.
2. Templates are rendered by whitelist placeholder substitution ({q}, {qp}, {raw}, {domain}, {user}, {b64}, {e164}, {cnpj_fmt}...) via re.sub, never str.format. Each template is validated at load: https only; fixed scheme and a host equal to the declared host; the value only in path/query through the declared encoder; known placeholders and entity types only.
3. Per-type encoders, unit-tested: E.164 digits; BR national format (DDD + number, with and without the 9); wa.me digits; CNPJ formatted, digits-only and 8-digit root; IDN Unicode and punycode; base64 (FOFA, Pulsedive).
4. The CI lint applies rules 7 and 4 to links. It rejects templates that submit or publish the value (urlscan public scan, VirusTotal upload, archive.org/save, public recent-searches pages, any scan_trigger), people-search/'painel' and leaked-database sites, and pages that need a login.
5. TLP (A2): at AMBER and above, links render as non-clickable text with 'opening sends <value> to <host>'. At RED, third-party links are hidden from reports and shown only by `v3lum links`, with the warning. Links are never auto-opened, and `links --open` at AMBER and above needs an interactive confirmation.
6. privacy=true links (person, phone, e-mail) apply only to analyst-typed seeds, never to auto-discovered entities such as QSA partners, and stay hidden unless the analyst opts in for the case. No template accepts CPF: a CPF never appears in a link (team rule 4, AR24), and the lint rejects such templates.
7. Templates that carry PERSONAL_TYPES or CNPJ values must point to trusted or community hosts; the lint rejects unknown-tier hosts for them (A8 BR4). Links to unknown-tier hosts (IOC types only) carry an 'unknown operator' badge.
8. touches_target links (they open the target, or make a third party fetch it live) render defanged and non-clickable with a warning, and are hidden for hostile entities unless the analyst expands them. The investigated URL itself is never a clickable link. rel=noreferrer and the no-referrer meta stay.
9. Fallback: when a module is skipped or blocked (licence, needs_key, BLOCKED, egress_country, quota, hostile_host), the engine emits that source's manual link (Module.manual_link: a template or pack id) with the reason 'automation skipped: <reason>'.
10. Ranking: links are grouped by analyst question (reputation, history, passive DNS, code/paste, social), verified first and unverified with a badge. The terminal shows at most 8 per seed; the rest go to HTML and `v3lum links`.
11. Each case gets a standalone manual-pivot HTML page, self-contained with the P336 CSP. V3LUM never fetches the links itself. A test renders every bundled template with a fixture value per type and asserts a valid https URL.

Chair rationale: Approved 6-0 at median P1. Manual links are the fallback whenever automation is blocked or not allowed (cti_lead, osint_investigator). legal_dpo's floor: rules 7 and 4 apply to links, a CI denylist, plain text with a disclosure warning at AMBER/RED, never auto-opened. The architect's floor: injection-safe whitelist substitution instead of str.format, validation at load, encoder tests. redteam_lead added touches_target handling and non-clickable target URLs, osint_investigator the encoders and the skip-reason fallback, analyst_ux the ranking and noted that no pack ships today.

Synthesizer conditions (background; the final conditions win on conflict): core/links.py loads data/pivot_links/*.json packs ({label, template, entity_types, category, verified, scan_trigger, privacy}) with per-type encoders (base64 for FOFA, base64 for Pulsedive, E.164 digits for phones, formatted CNPJ); renders verified first, unverified with badge; emits a standalone manual-pivot HTML page per case (no external resources).
Notes: Backbone for every pivot pack proposal.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0685 Manual pivot-link page generator - Céos ceos/fontes_manuais.py
- kind: url_template; status: unverified (HTTP seen: []); passive: True; touches_target: False
- endpoint: (no network) generated links
- method: montar/gerar
- inputs: ['person_name', 'username', 'email', 'cnpj']
- outputs: HTML/terminal list of prefilled links (LinkedIn, Lattes, ORCID, GitHub, Jusbrasil, Escavador, handles, emails, company names)
- auth: none
- terms / licence: team-owned
- implementation notes: This is exactly V3LUM's 'pivot_link' tier: keep a registry of verified URL templates per entity type, render them grouped by entity in the final report; never fetch them automatically.

## P321 `body_error_detection` - Body-level error and bot-wall detection (error-in-200, WAF/challenge fingerprints)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: url; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/http.py block_reason

### Final conditions (binding spec - implement every item)

1. One classifier in core/http.py (extending block_reason) runs on every response before any parsing and BEFORE cache.put. Responses classified blocked, rate_limited, quota or error-in-200 are never written to the HTTP cache; today a 200 'Just a moment' page and an 'API count exceeded' body are cached and replayed. ScopedHttp offers evict(resp) and a cache_if hook for module-level detections.
2. Generic markers come from maigret COMMON_ERRORS and sherlock WAFHitMsgs (MIT, attributed): Cloudflare 'Just a moment'/challenge-platform, AWS WAF, PerimeterX, Incapsula, DDoS-Guard, Vercel checkpoint and captcha pages, plus final-URL checks (ISC blockme.html redirect).
3. Weak markers (captcha words) apply only on error statuses. A regression test proves that normal pages mentioning captcha are not marked blocked.
4. Login walls (a redirect or final URL to /login, /accounts/login or /signin, the LinkedIn authwall, Instagram/Facebook login interstitials) give BLOCKED reason_code 'login_wall'. Geo-block pages (CloudFront 'request could not be satisfied', Akamai reference pages) give BLOCKED 'geo_block' with an egress_country hint. Neither is ever EMPTY or ABSENT.
5. Per-source error-in-200 rules are declared data, shared with P331 specs: error_markers in the registry or the module, each a JSON path + value or a regex mapping to blocked | rate_limited | quota | error.
6. Initial error-in-200 rules: HackerTarget 'API count exceeded', Criminal IP {'status':403}, IPQS success:false, Etherscan status '0', CheckPhish errorMessage, hunter.how {'code':401}, Leak-Lookup error:true, ReceitaWS status ERROR, TCU SISTEMA_INDISPONIVEL.
7. DNSBL refusal codes (Spamhaus 127.255.255.x) map to BLOCKED, never to 'listed' or 'not listed'. Keyless sources map HTTP 403 to BLOCKED, not ERROR.
8. Classification never yields EMPTY. Each rule maps to a human-readable reason shown in coverage (e.g. 'HackerTarget: daily quota exhausted (API count exceeded)').
9. Detection only (rule 1): no retry with another UA, headers, cookies, proxy/IP or solver. The maigret/sherlock bypass helpers are not ported, and messages give no bypass hints.
10. A host that returned a challenge or geo-block is short-circuited for the rest of the run (in memory, reason_code 'circuit') and never cached across runs. Generic challenge markers give BLOCKED reason_code 'challenge' (A3 BR16, A9).
11. Each marker ships one trimmed real fixture (from the research samples) with a test.

Chair rationale: Approved 6-0 at median P1; a phase-0 item. cti_lead, osint_investigator and the architect verified that block pages and error-in-200 bodies are cached and replayed today, so classification must precede caching (architect floor: one classifier, declared markers, never EMPTY). legal_dpo's floor: detection never becomes circumvention, and MIT attribution. osint_investigator added login-wall and geo-block detection, analyst_ux human-readable reasons and the weak-marker regression. redteam_lead agreed it keeps WAF pages out of LIGHT/ACTIVE findings.

Synthesizer conditions (background; the final conditions win on conflict): Generic classifier used by every collector before parsing: maigret COMMON_ERRORS + sherlock WAFHitMsgs (MIT): Cloudflare 'Just a moment'/challenge-platform, AWS WAF, PerimeterX, Incapsula, DDoS-Guard, Vercel checkpoint, captcha pages, ISC blockme.html redirect (check final URL); per-source error-in-200 rules: HackerTarget 'API count exceeded', Criminal IP {'status':403}, IPQS success:false, Etherscan status '0', CheckPhish errorMessage, hunter.how {'code':401}, Leak-Lookup error:true, ReceitaWS status ERROR, TCU SISTEMA_INDISPONIVEL, Spamhaus 127.255.255.x -> Status.BLOCKED/RATE_LIMITED/ERROR, never EMPTY.
Notes: Prevents 'blocked' or 'quota' pages from being read as 'nothing found' (rule 5).

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0695 Bot-wall / error-page fingerprint classifier - github.com/soxoj/maigret (errors.py, error_detection.py) + sherlock WAFHitMsgs
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- endpoint: maigret/maigret/errors.py COMMON_ERRORS; maigret/maigret/error_detection.py detect_error_page; sherlock_project/sherlock.py WAFHitMsgs
- method: offline
- inputs: ['url', 'username']
- outputs: Classifies a response as UNKNOWN(blocked) instead of absent/present: Cloudflare ('<title>Just a moment', '/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page', challenge-error-text, 'Attention Required! | Cloudflare'), AWS WAF (AwsWafIntegration.forceRefreshToken), PerimeterX, Incapsula incident ID, DDoS-Guard, Anubis PoW ('/.within.website/x/'), window.POW_CHALLENGE_DATA, Vercel Security Checkpoint, Google 'unusual traffic'/recaptcha challengepage, Imunify360, Stile, SlardarWAF, Blazingfast, RU censorship pages; HTTP 401/403/429/999/>=500.
- auth: none
- terms / licence: MIT (both)
- risk: Detection only - never use maigret's bypass suggestions (proxy rotation, FlareSolverr).
- implementation notes: Port as a single fingerprint table (marker -> (type, vendor)) run BEFORE site rules on every response (generic for all collectors, not only usernames). 999 = LinkedIn anti-bot. Code-reviewed, not executed (clones are read-only).

## P322 `confidence_model` - Finding confidence model (CONFIRMED/PROBABLE/POSSIBLE with mandatory criterion)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/models.py Finding

### Final conditions (binding spec - implement every item)

1. Finding carries confidence_label (confirmed | probable | possible) and criterion (text). res.finding(..., confidence=) accepts a label or a float, backward compatible: >= 0.85 -> confirmed, >= 0.55 -> probable, else possible. Labels map to 1.0 / 0.7 / 0.4 for scoring (P302) and 90 / 70 / 40 for STIX (P303), documented in one table.
2. criterion is mandatory for severity >= low; the module contract test fails otherwise. Finding.to_dict gains confidence_label and criterion, and stored cases without them still render.
3. Analyst overrides are stored separately, keyed by the deterministic finding id (AR09). They always win and survive re-runs.
4. Automatic downgrades happen only through named suppression rules (warninglist, sinkhole, generic/role address, stale listing, version-inferred CVE, homonym), recorded with the rule id and reason in the criterion (e.g. 'POSSIBLE - on warninglist <name>').
5. Automatic upgrades are at most +1 level and only with >= 2 independent upstream families. No automatic change ever crosses an analyst decision.
6. Pivot edges use the same labels, which feed path confidence (AR07).
7. The terminal findings table shows the label for every finding and the criterion for HIGH/CRITICAL; HTML/MD always show both.
8. Lands in phase 0, before group implementation (API freeze). Tests: the float mapping, override precedence, and a warninglisted IOC showing 'POSSIBLE - on warninglist <name>'.

Chair rationale: Approved 6-0 at median P1. cti_lead and analyst_ux found that 'confidence never decreases automatically' contradicts the suppression rules of P146, P171 and P302. The chair resolves it their way: the lock applies only across analyst decisions, and rule-driven downgrades are allowed with a recorded criterion. This matches the architect's floor (downgrades only via explicit suppression rules recorded with the rule id), which also requires a backward-compatible API frozen in phase 0. osint_investigator extended the labels to pivot edges. legal_dpo, redteam_lead and osint_investigator approved without conditions.

Synthesizer conditions (background; the final conditions win on conflict): Every finding carries a qualitative confidence plus the criterion that justifies it (Céos 'criterio'); confidence never decreases automatically and never overrides analyst decisions; mapping to numeric confidence for scoring.
Notes: Explains why each finding is believed.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0699 Finding + confidence model (CONFIRMED / PROBABLE / POSSIBLE with mandatory criterion) - Céos ceos/models.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: dataclasses Pessoa/Achado; constants CONFIRMADO/PROVAVEL/POSSIVEL, ORDEM_CONFIANCA, MODULOS
- inputs: ['text_blob']
- outputs: Finding(module, source, title, summary, url, reference_date, confidence, criterion, raw)
- auth: none
- terms / licence: team-owned
- implementation notes: Rename: Achado->Finding, Pessoa->Subject, criterio->criterion (the human-readable WHY), bruto->raw_evidence. Keep the ordering map for 'principal' selection and 'confidence never goes down automatically'. Module list -> English: identity, criminal_records, lawsuits, sanctions_integrity, corporate_links, digital_footprint, official_gazettes, resume_validation, professional_presence, adverse_media, data_exposure, other; add CTI modules (infrastructure, threat_intel, vulnerabilities, brand_protection).

## P323 `detector_patterns` - Identification regex DB for text blobs (lemmeknow/pywhat, SpiderFoot extractors)

- council: **approved**, priority P2, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob, url, domain; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/detect.py

### Final conditions (binding spec - implement every item)

1. The pattern DB serves text_blob/file extraction and typing suggestions only. Single-value detect() keeps today's precedence, so a typed username or phone is never re-typed, and the existing test_detect suite passes unchanged.
2. From lemmeknow/pywhat regex.json and the SpiderFoot offline extractors (MIT, attributed in THIRD_PARTY_NOTICES.md), import only patterns with a validator or a distinctive prefix/checksum: cloud keys, JWT, crypto with checksum, analytics ids, IBAN, cards with Luhn, SRV names, odd headers.
3. Generic patterns (phone, date, generic ids) are disabled by default. A pattern without a validator cannot exceed confidence 0.5.
4. Each adopted pattern ships a confidence, a validator and positive + negative vectors. Patterns with no consuming module and no masking need are not emitted as entities.
5. Payment card numbers are truncated to BIN(6)+last4 at detection time; the full PAN is never stored, logged or rendered (PCI DSS). IBAN, CPF-like numbers and other national ids are masked in every output.
6. Secret types (cloud keys, tokens, JWTs, bot tokens, private keys) are SECRET_TYPES: kept as type + masked preview (first 4/last 4) + SHA-256 only, NO_AUTO_EXPAND, never validated, used or sent anywhere (rule 1), and reported once as 'sensitive data in pasted text'.
7. Financial and secret hits yield local-only findings: no pivots, never passed to modules with disclosure third_party or target (shares_input=True), masked in terminal, reports, evidence and case DB.
8. Detection-triggered SRV/DNS lookups obey the TLP gate (no public DoH under TLP:RED).
9. Every imported regex gets a ReDoS review and a pathological-input test. Test: a mixed incident text sends no card number or secret off the machine.

Chair rationale: Approved 6-0 at median P2 (legal_dpo voted P1). All members feared 142 unfiltered patterns would flood pastes and route secrets or card numbers to third parties. Patterns are therefore restricted to validated or distinctive ones (cti_lead, architect floor: no validator -> confidence <= 0.5, existing detection untouched). legal_dpo's floor: PAN truncation at detection, never testing secrets, the TLP gate on lookups. redteam_lead and the architect added NO_AUTO_EXPAND and local-only handling, osint_investigator and analyst_ux kept single-value detection unchanged.

Synthesizer conditions (background; the final conditions win on conflict): Seed detect.py with lemmeknow regex.json (MIT, 142 patterns: crypto, JWT, cloud keys...) and SpiderFoot offline extractors (MIT: analytics IDs, IBAN, credit cards with Luhn, SRV names list, odd headers); mask card/IBAN hits; each pattern gets a confidence and a validator.
Notes: Better typing of pasted text before any collector runs.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0701 lemmeknow / pywhat identification regex DB - github.com/swanandx/lemmeknow
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: []); passive: True; touches_target: False
- endpoint: src/data/regex.json in the repo (read locally)
- method: local
- inputs: ['text_blob']
- outputs: 142 named regexes with rarity/tags: emails, IPv4/6, URLs, crypto wallets (BTC/BCH/ETH/XMR/LTC/DOGE/XRP/NANO), JWT, UUID/ULID, coordinates, phone, SSH/PGP keys, cloud/API secrets (AWS, GitHub, Slack, Stripe, Google...), card numbers, timestamps.
- auth: none
- terms / licence: MIT (data derived from pywhat, MIT) - adapt with attribution
- risk: Card-number and SSN regexes match sensitive data: mask matches in reports; secrets found in public text must not be tested (no credential use).
- implementation notes: Use as seed for V3LUM's entity auto-detection/extraction (text_blob -> typed entities). Rarity field helps rank ambiguous matches. Add Brazil-specific patterns (CPF/CNPJ with check digits, CEP, Pix keys, BR plates) on top.

#### C0714 SpiderFoot offline extractors (analytics IDs, hashes, crypto, SRV, odd headers) - github.com/smicallef/spiderfoot
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- endpoint: local regexes + DNS SRV queries for 25 names: _ldap._tcp, _gc._msdcs, _ldap._tcp.pdc._msdcs, _ldap._tcp.gc._msdcs, _kerberos._tcp.dc._msdcs, _kerberos._tcp/_udp, _kerberos-master._tcp/_udp, _kpasswd._tcp/_udp, _ntp._udp, _sip._tcp/_udp/_tls, _sips._tcp, _stun._tcp/_udp, _stuns._tcp, _turn._tcp/_udp, _turns._tcp, _jabber._tcp, _xmpp-client._tcp, _xmpp-server._tcp
- inputs: ['text_blob', 'url', 'domain']
- outputs: Web analytics/verification IDs (Google UA-, AdSense pub-, GTM-, google-site-verification, Quantcast p-, ahrefs, LogMeIn, DocuSign, GlobalSign verification TXT), hashes (MD5/SHA1/SHA256/SHA512), BTC/ETH addresses, PGP key blocks, emails, IBANs, credit cards (Luhn), URLs from robots.txt; DNS SRV service discovery; unusual HTTP headers.
- auth: none
- terms / licence: MIT
- risk: The credit-card and IBAN extractors can surface personal financial data. Mask it in reports (LGPD). SRV lookups go through public DNS, not the target directly.
- implementation notes: STATUS NOTE: this is an offline algorithm. "unverified" only means it was not executed, because cloned code is read-only in this sweep; its behaviour is taken from line-by-line code reading. Regexes (from sfp_webanalytics): \bua\-\d{4,10}\-\d{1,4}\b ; \b(pub-\d{10,20})\b ; \b(GTM-[0-9a-zA-Z]{6,10})\b ; <meta name="google-site-verification" content="([a-z0-9\-\+_=]{43,44})" ; TXT google-site-verification=([a-z0-9\-\+_=]{43,44})$ ; logmein-domain-confirmation ([A-Z0-9]{24})$ ; docusign=<uuid>$ ; globalsign-domain-verification=([a-z0-9\-\+_=]{42,44})$ ; ahrefs-site-verification [a-f0-9]{64}. Add GA4 (G-[A-Z0-9]{8,12}), Meta pixel (fbq\('init', '(\d{15,16})'), Hotjar and Microsoft Clarity IDs. Shared analytics IDs across domains are a strong same-owner pivot: search them via the BuiltWith relationships API, urlscan, or the publicwww pivot. Hash regex: (?:[^a-fA-F\d]|\b)([a-fA-F\d]{32|40|64|128})(?:[^a-fA-F\d]|\b). ETH: [\s:=\>](0x[a-fA-F0-9]{40}). BTC: base58 plus bech32 with checksum validation in code. sfp_strangeheaders keeps a 59-entry allowlist of standard headers and reports anything else (e.g. X-Backend-Server leaks internal hostnames).

## P324 `evidence_store` - Evidence store with re-collection versioning and audit trail (Céos port)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/store.py

### Final conditions (binding spec - implement every item)

1. Evidence is content-addressed (SHA-256 of the stored, already-sanitized bytes, P145) and write-once: 0600 files in a 0700 case directory. A re-collection writes a new version plus an append-only audit row, never an overwrite, and the version keeps a diff summary.
2. Each evidence record stores the request context: method; redacted URL (AR01); final URL and redirect chain; HTTP status; selected response headers (date, content-type, server); UA and egress profile; from_cache; fetched_at (the cache row time when served from cache, not now()); collected_at from rt.now(); dataset name and SHA-256 for dataset-derived results.
3. Filenames follow <module>__<type>__<hmac12>__<sha10>.json (the A4 keyed HMAC). No raw e-mail, phone, CPF, username or any other value appears in a path.
4. Per-case audit trail (schema migration): case purpose, legal-basis code, requester/ticket (AR16), analyst (OS user or config), opsec mode, authorization reference, scope SHA-256, engagement window, egress profile and its public IP when known (last `v3lum doctor --egress` check, with its time), TLP changes, overrides (egress, breach scope, show-personal) and the org profile hash.
5. Per-case JSONL request ledger for every LIGHT/ACTIVE request: UTC time, module, method, host, resolved IP, port, redacted path, status, bytes, egress profile, opsec. It is written even with --no-evidence. Ledger and audit are append-only and hash-chained, and the report summarises targets touched and request counts.
6. `v3lum cases verify <id>` recomputes every evidence and report hash and the ledger/audit hash chains offline, and prints a pass/fail summary.
7. Retention (A10): 'immutable' means append-only within the retention period. Purge deletes every version and keeps a value-free tombstone. The minimal engagement audit and ledger (no bodies, paths redacted) follow audit_retention_days, which defaults to retention_days; a longer period needs a written legal decision.
8. Evidence has a size cap per file and per case, with gzip. Scans get no extra prompts: identity comes from config/OS user and the reference from the existing gate. On re-collection the report header shows 'since last run: N new findings, M resolved'.
9. Tests: tamper detection (edited file, broken chain), cache-served evidence keeps fetched_at, no raw value in filenames, and purge removes all versions.
10. Merge order: this proposal's audit record and request ledger land before any LIGHT/ACTIVE module merges, and the AR20 safety suite checks them (A7 BR13, A16 BR6).

Chair rationale: Approved 6-0. The chair raises the priority from the median P2 to P1: A7 binds every LIGHT/ACTIVE run to an audit record and a request ledger, so this must land before any LIGHT/ACTIVE module merges, and legal_dpo, osint_investigator and redteam_lead voted P1 (legal floor, A7/A10). redteam_lead defined the ledger, osint_investigator the request context and pseudonymised filenames, cti_lead the cache fetched_at. legal_dpo's floor: purpose and legal basis in the audit, append-only only within retention, sanitizer before any version. The architect's floor: content addressing, migrations, delete removes files and rows, tamper tests. analyst_ux: no extra prompts, a one-command verify.

Synthesizer conditions (background; the final conditions win on conflict): Extend the SHA-256 evidence files with immutable versions on re-collection (diff summary), audit trail of who/when/why (case, analyst, authorization reference), and integrity verification command.
Notes: Chain-of-custody quality for incident and legal use.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0698 Evidence store with SHA-256, re-collection versioning and audit trail - Céos ceos/db.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: salvar_evidencia_bytes, salvar_achado, _mesmo_achado, _subir_confianca, auditar, bruto_atual, excluir_achado (only discarded findings)
- inputs: ['text_blob']
- outputs: evidence files + hashes, finding versions, audit rows, hashed final report
- auth: none
- terms / licence: team-owned
- implementation notes: Raw evidence = canonical JSON (sort_keys, UTF-8) hashed with SHA-256; identical hash -> not stored twice; same finding (module+source+title+url+criterion, or same URL for profile modules) re-collected with different content -> appended as new evidence version ('nova_coleta'), confidence only goes UP and only while still pending, analyst decisions (accepted/discarded) are never overwritten; every decision/edit goes to an audit table; final report stored with its SHA-256 (chain of custody). V3LUM CLI: ~/.v3lum/cases/<case>/ (sqlite + evidence/).

## P325 `feedback_verdict` - Analyst verdict, attention points and feedback (Céos parecer port)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/store.py feedback

### Final conditions (binding spec - implement every item)

1. Fix app.App.ask_feedback now. Only explicit judgements are stored: findings the analyst lists are wrong; unlisted ones stay unrated (no row). An overall 'yes' stores only the case verdict and credits no finding, and an optional 'which were right?' step records explicit positive votes. Today 'no' + Enter marks all 30 reviewed findings correct.
2. Votes are idempotent per (case, deterministic finding id, analyst): a re-vote replaces the earlier one and never double-counts (today a repeated `cases feedback` increments module_stats again). This requires the AR09 deterministic ids.
3. Beta(alpha, beta) is kept per source (registry source id) and per correlation rule, stored via a migration. The prior comes from the source's Admiralty grade, and 'partly' counts 0.5. Weights change only after >= 5 votes, with a floor of 0.3, and votes older than 12 months weigh half.
4. The overall verdict takes one keypress. The optional per-item review is capped at 10 items ordered by score contribution, correlations included (per-rule votes), with an optional one-key reason for 'wrong' (homonym / outdated / benign infra / wrong type) stored for tuning.
5. Attention points and the limitations section ('could not verify: X, Y (reason)') are generated from coverage statuses (blocked, quota, needs_key, licence, tlp, policy, timeout, deadline) by a tested pure function and shown on the first screen. They are worded as suggestions, and the analyst's verdict prevails.
6. Feedback never deletes or hides findings. Per-rule statistics feed P301 precision and A3 demotion.
7. Feedback notes and per-finding votes are case data, purged with the case (A10). Only aggregated per-source/per-rule counters without entity values survive.
8. Tests cover the yes / partial / no paths, idempotent re-votes and the rule that fewer than 5 votes have no effect.

Chair rationale: Approved 6-0. The chair raises the priority from the median P2 to P1 because the current loop corrupts the reliability statistics that P302 (P1) consumes: 'no' + Enter reinforces every finding (analyst_ux) and 'yes' auto-credits all of them, saturating at 1.0 (cti_lead). The two members differed on whether 'yes' should credit displayed findings; the chair takes cti_lead's stricter verdict-only rule and offers analyst_ux's explicit 'which were right?' step. The architect's floor: deterministic ids, idempotent votes, Beta after >= 5 votes with a 0.3 floor. legal_dpo's floor: votes and notes purged with the case, the analyst's verdict prevails.

Synthesizer conditions (background; the final conditions win on conflict): Extend the 'did this make sense?' loop with per-finding/per-rule votes (made sense / did not / partly = 0.5) updating Beta(alpha, beta) per source and per correlation rule (R_src after >= 5 votes), auto-generated attention points and limitations section (sources blocked/quota/unverified) in the case opinion.
Notes: Closes the loop between analysts and source reliability.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0694 Analyst verdict, suggested attention points, auto-limitations and feedback - Céos ceos/analise.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: sugestoes (from company/domain/profile signals + accepted findings in sensitive modules; adopt or ignore), limitacoes_auto (from coverage), pronto_para_final
- inputs: ['text_blob']
- outputs: case opinion (executive summary, conclusion, confidence high/moderate/low + reason, limitations, recommendations), suggested points linked to findings
- auth: none
- terms / licence: team-owned
- implementation notes: This maps directly onto the V3LUM end-of-run step the user asked for: after the report, ask 'Did this make sense? [y/n/partly]' per section/finding, store answers, and feed them into source/rule reliability (risk_model.feedback). Keep 'not found is not proof of absence' limitations text generated from skipped/failed sources.

## P326 `http_profiles` - Per-host HTTP profiles (UA, Accept, timeout, retries, TTL, negative caching)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: url; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/http.py

### Final conditions (binding spec - implement every item)

1. Host profiles are entries of the single provider registry (data/providers.json, AR11): per provider user_agent, accept, accept_language, timeout, retries, max_bytes, ttl, min_interval and concurrency, consumed by HttpClient. There is no second table. FakeHttp gains header matching, and every profile entry has a unit test (UA/Accept per host).
2. veto_lift (1): hosts of providers flagged sensitive (XposedOrNot, LeakCheck, Hudson Rock, HIBP and similar breach, infostealer or people-data providers) are no-store in the HTTP cache, or the cache stores only the P145-sanitized payload. A test proves that no masked password/login, computer_name or IP from the Hudson Rock fixture appears in cache rows.
3. veto_lift (2): the default UA (setting user_agent) becomes a neutral 'V3LUM/<version>' that identifies neither the organisation, the team nor the analyst (no company name or mailbox), replacing today's spoofed Chrome string. Identifying UAs with a role mailbox (setting contact_email) appear only in profiles of providers whose terms ask for them: SEC, Wikimedia, Nominatim, bgp.tools.
4. registro.br gets a non-browser UA and Accept application/rdap+json. A provider that requires a contact UA while contact_email is empty is SKIPPED with reason_code 'config'.
5. veto_lift (2, continued): LIGHT/ACTIVE requests never carry the organisation's identity. They use the egress-profile UA (setting ua_light, a common browser UA by default) or, for ACTIVE, the scope file's ROE UA/header, which may carry an engagement token agreed with the scope owner but never the organisation's name, team, mailbox or analyst. The contact UA never goes to unknown-tier providers.
6. veto_lift (3): a block, challenge or 403 is never retried with a different UA or headers. No UA rotation and no browser spoofing to defeat bot controls; a browser UA is used only where a provider's public page needs one, never to pass a bot wall (rule 1).
7. veto_lift (4): the effective TTL = min(profile ttl, cache_max_age_days, retention_days). Defaults: DNS 1 h, RDAP 24 h, CNPJ 72 h, sanitized breach payloads 7 d, crypto 1 h, sanctions 24 h. Long-lived reference data (IBGE/DDD) goes to datasets, not to the HTTP cache.
8. Retries: one retry honouring Retry-After <= 15 s, otherwise RATE_LIMITED. Retries and waits are bounded by the run deadline (AR05). Per-provider byte caps also apply to target responses.
9. Negative caching is unchanged: 401/403/429/5xx and P321-classified bodies are never cached, and failures are short-circuited only in memory for the rest of the run.
10. cache_key includes Accept and a hash of credential-bearing headers and params, so keyed and keyless answers never mix. Per-host politeness is max(module, host profile) (P334).
11. Other profiles from the research: HIBP (any UA), SANS ISC (Accept application/json), KeyCDN ('keycdn-tools:<site>'), PhishTank ('phishtank/<app>'), and Accept-Language pt-BR for Brazilian hosts. Host profiles never override opsec, scope, TLP or egress decisions.

Chair rationale: Mechanical status: vetoed by legal_dpo (yes 5 / reject 1). veto_lift adopted: legal_dpo's four lift conditions (sensitive hosts no-store or sanitized only, a neutral default UA without organisation or mailbox with identifying UAs only where providers ask, no UA/header retry after a block, TTLs within retention) are conditions 2-7, so the proposal is approved at its median P1 in phase 0. Most live failures in the sweeps were UA/Accept problems (cti_lead, osint_investigator). redteam_lead, osint_investigator and analyst_ux independently objected to the team-mailbox UA for opsec reasons. The architect's floor: profiles live in the single provider registry, the contact UA never goes to targets, Retry-After <= 15 s, header-matching tests.

Synthesizer conditions (background; the final conditions win on conflict): Extend core/http.py with a host-profile table (beyond per-module user_agent): HIBP needs any UA, SEC 'Org contact@email', Wikimedia 'Tool/ver (URL; contact) lib/ver', Nominatim identifying UA, registro.br non-browser UA + Accept application/rdap+json, ISC Accept: application/json, KeyCDN 'keycdn-tools:<site>', PhishTank 'phishtank/<app>', bgp.tools descriptive UA; per-host TTLs (DNS 1 h, RDAP 24 h, CNPJ 72 h, XON/LeakCheck/Hudson Rock 7 d, crypto 1 h, sanctions daily, IBGE/DDD forever), one retry honouring Retry-After, per-provider byte caps; default UA 'V3LUM/<version> (+internal CTI; contact: <team mailbox>)' configurable; port Céos cache_http negative caching (never cache 401/403/429/5xx).
Notes: Most live failures in the sweeps were UA/Accept problems, not dead services.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0700 HTTP cache session with per-host TTL, negative caching and per-URL lock (SessaoCache) - Céos ceos/cache_http.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- endpoint: local SQLite (CEOS_DATA/cache_http.db -> V3LUM ~/.v3lum/cache.db)
- method: SessaoCache(requests.Session).get/_consultar/post_json; ler/gravar/gravar_falha/trava/validade_horas/limpar/resumo/avisar_consultas
- inputs: ['url']
- outputs: cached responses, cache/network counters per run, live request log lines
- auth: none
- terms / licence: team-owned code (port freely, translate to English)
- implementation notes: Port as v3lum/core/http.py HttpClient. Keep: TTL table by host suffix (RDAP/crt.sh/BrasilAPI/Minha Receita/breach APIs/avatars 168 h, GitHub 24 h, news 6 h, Nominatim/OSM tiles 720 h, default 24 h); cache ONLY 200 and 404 (404 is information); negative cache of connection errors/timeouts for 1 h (status -1, replays the exception); NEVER cache 403/429/5xx; per-URL threading.Lock so identical concurrent requests collapse into one; cache key = sha256(prepared URL with params); POST-for-read (GraphQL) key = URL + '#post-' + sha256(sorted JSON body)[:16], forbidden for form submission; counters do_cache/da_rede -> 'N from cache, M from network' in coverage; thread-local observer callback -> Rich live log. Add for V3LUM: per-host token-bucket rate limiter, Retry-After handling, ETag/If-Modified-Since revalidation, `v3lum cache --clear [--site host]`.

## P327 `policy_as_code` - Collection policy as code (Céos docs/07 rules) + TLP gate

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. One pure function, core/policy.py decide(module_cls, entity, options, profiles) -> Decision(allowed, status, reason_code, reason), used by Engine.select, App.run_single, the shell, extract --scan, batch, watch and doctor health checks. No gate exists anywhere else, and decide() and the engine use only the canonical A3 reason codes and their Status mapping.
2. decide() order, first failure wins: metadata validity, offline, licence (A1), TLP (A2), tier/--allow-unknown (A8), privacy (run_on, breach scope, purpose, PERSONAL_TYPES to unknown tier; A4/A8), own_asset (A11), opsec vs mode, ACTIVE authorization + scope / LIGHT seeds-only (A7), egress_country (A9), keys, packages, datasets, quota (P334), circuit.
3. Secure defaults: Module.terms='unknown', provider tier 'unknown', no implicit disclosure. @register (also for ~/.v3lum/plugins and P331 specs) refuses a module whose class body does not declare terms, opsec, disclosure and hosts, or whose hosts and feeds lack a provider-registry entry.
4. Runtime enforcement: ScopedHttp and Resolver know the module's opsec, disclosure and hosts. PASSIVE modules reach only declared hosts (exact or '*.' wildcard) and core DoH; redirects to undeclared hosts are not followed; target-derived hosts only for LIGHT/ACTIVE.
5. Disclosure 'none' modules get no network at all, and 'internal' modules reach only their configured internal hosts (A8 BR9). A violation ends SKIPPED reason_code 'policy', recorded in the case audit and shown by doctor.
6. LIGHT/ACTIVE modules use only the core HTTP client and the core socket connector. The lint fails direct socket, urllib, http.client or subprocess network use in modules. ctx.allowed_opsec = min(scan mode, module opsec).
7. A forbidden-capability lint runs in CI over modules, plugins, P331 specs and data files (username site lists, pivot packs).
8. The lint rejects sign-up, register, availability, check_username, validate, password-reset and login endpoints; CAPTCHA solvers; FlareSolverr, cloudscraper and undetected browsers; credential/password fields outside P145 schemas; CPF-lookup or 'painel' hosts; publishing endpoints (rule 7); state-changing methods toward targets.
9. Forbidden actions (A7 BR8-BR9), enforced in code and by the lint in every mode: exploitation or payload confirmation; credential brute force, spraying, default-login checks or any login attempt; use of leaked or found credentials and keys; JWT/hash cracking; DoS/stress; uploads, writes or deletes; takeover claims; OAST/interactsh callbacks. ACTIVE uses only GET/HEAD/OPTIONS unless allow-listed.
10. Modules flagged sensitive, or returning passwords, must declare a P145 sanitizer schema; otherwise registration fails.
11. Registry-wide CI lint: metadata enums, declared hosts present in the registry, vocab-only attribute/tag/relation names, and a fixture-backed test per module. Tests assert that requested hosts are a subset of declared hosts plus DoH (FakeHttp records hosts).
12. Table-driven tests over TLP x disclosure x licence x tier x opsec x scope x org_profile x run_on, including App.run_single refusals under TLP:RED, with an exhausted quota and without authorization.
13. Each policy rule has an id, quoted in failure messages and in docs/RULES.md (generated from the rule table, AR22). The policy file is versioned with the council decision ids.
14. Analyst output: every denial maps to a readable reason in coverage (e.g. 'skipped: noncommercial terms (licence profile corporate)'), and the terminal aggregates denials into one line per reason. `v3lum info <module>` explains which policy applies and why. Registration and CI checks fail the build, never the analyst's scan.

Chair rationale: Approved 6-0 at median P1; the keystone of phase 0. The architect showed two execution paths, one of which (`v3lum run`) skips TLP, quota and the active-mode confirmation, so the floor is one pure decide() on every path plus table-driven tests. legal_dpo's floor: fail-closed metadata at registration (plugins and specs too), runtime enforcement, all gates at one choke point, a forbidden-capability denylist. redteam_lead: a metadata lint cannot stop a PASSIVE module that fetches the target, hence host-layer enforcement and the core socket connector. osint_investigator extended the lint to data files, cti_lead to declared hosts, analyst_ux asked for readable aggregated reasons.

Synthesizer conditions (background; the final conditions win on conflict): Encode team rules as machine-checked policy: modules declaring forbidden capabilities (signup/reset endpoints, login, captcha solving, plaintext breach fields, CPF lookups) fail registration tests; active modules require authorization + scope file + audit; TLP:RED inputs only reach shares_input=False modules; a CI test lints module metadata (terms, opsec, hosts) against this policy. Gap fill: policy also enforces licence_profile per source (licence_profile proposal), own-asset conditions from org_profile, and a disclosure class per source (none / internal / third_party) so internal TIP/SIEM lookups are allowed for TLP:RED while third-party sources are not.
Notes: Makes the council's decisions enforceable, not just documented.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0697 Collection policy as code (Céos docs/07 rules) - Céos docs/07-regras-e-limites.md
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: declarative flags on each collector: passive|light|active, login_required, returns_secrets, scrape, enumerates_accounts, needs_key, lgpd_sensitive
- inputs: ['text_blob']
- outputs: per-collector policy flags enforced at runtime
- auth: none
- terms / licence: team-owned
- implementation notes: Encode the team rules so they are enforced by code: refuse collectors with login_required/enumerates_accounts/returns_secrets; active collectors require the authorization gate; scrapers need pause/UA/caps and stop on 429; every request through the cache client (no bare requests.get); no external images in reports; breach sanitizer mandatory.

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/gaps__licence_profile.json

## P328 `result_status_semantics` - Result status semantics: quota vs not-found vs blocked vs unknown (tri-state)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: url; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/models.py Status

### Final conditions (binding spec - implement every item)

1. Status gains QUOTA (budget, daily or monthly limit), distinct from RATE_LIMITED (transient 429). The existing 8 values stay stable, and _STATUS_RANK, coverage and the renderers are updated.
2. ModuleResult gains reason_code (the canonical A3 codes) and partial (bool). A per-source execution report (completed / partial / rate_limited / quota / failed + stop_reason) is kept in the case JSON and in the coverage table.
3. Coverage is computed per (seed, module) with status counts, not per module with the last reason. Summaries rank could-not-verify statuses (quota, rate_limited, blocked, error, needs_key, unavailable) above empty; today 'blocked on the seed, empty on a pivot' is summarised as empty.
4. Tri-state convention for existence checks: attribute presence = found | absent | unknown, with the evidence (marker, URL, checked_at). ABSENT only on documented positive evidence.
5. Meaningful 404s are declared per module in Module.absent_statuses (e.g. {404}), replacing ok404. They are documented per source (InternetDB, GreyNoise, CIRCL hashlookup, PoC-in-GitHub, Cymru NXDOMAIN, HIBP breachedaccount) and tested.
6. Keyless modules map HTTP 403 to BLOCKED ('could not verify'), not ERROR as Engine.run_module does today. DNS SERVFAIL/REFUSED/timeouts mean UNKNOWN. A run that overruns its deadline ends ERROR with reason_code 'timeout'.
7. No output says 'not found', 'not listed', 'no account', 'clean' or 'does not exist' for a source that did not answer. The first screen shows 'N of M applicable sources answered; K could not verify' with the list, and a seed below the coverage threshold reads 'inconclusive' (P302).
8. Fix the reference modules with dead-DoH tests: email_basics must not turn a DoH failure into mx_valid=False or 'domain does not accept mail', and dns_records may emit negative findings only after OK A/AAAA/CNAME answers.
9. One test per status mapping and per meaningful-404 declaration.

Chair rationale: Approved 6-0 at median P1; a phase-0 item implementing rule 5 uniformly. The architect's floor: QUOTA added while the 8 values stay stable, keyless 403 -> BLOCKED, declared absent_statuses, the execution report. cti_lead and analyst_ux made could-not-verify visible on the first screen with 'inconclusive' instead of 'clean'. osint_investigator asked for the per-entity matrix and no absence claims. cti_lead flagged the email_basics rule-5 bug in the reference module. legal_dpo and redteam_lead approved without conditions.

Synthesizer conditions (background; the final conditions win on conflict): Add Status.QUOTA (budget/daily limit) distinct from RATE_LIMITED (transient 429); per-source execution report (completed/partial/rate-limited/failed + stop_reason like theHarvester SourceExecutionReport) shown in the report coverage section; tri-state results for existence checks (FOUND/ABSENT/UNKNOWN) with ABSENT only on positive evidence; meaningful 404s documented per source (InternetDB, GreyNoise, CIRCL hashlookup, PoC-in-GitHub, Cymru NXDOMAIN, HIBP breachedaccount).
Notes: Implements rule 5 consistently across all modules.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

## P329 `tls_interception_check` - Global TLS-interception detection (corporate proxy/AV re-signing)

- council: **approved**, priority P2, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=light, shares_input=False
- category: utility; group: G15; inputs: url, domain; produces: 
- auth: none; key env vars: -; hosts: -
- sources shared with other proposals: {"C0632": ["P275", "P277"]}

### Final conditions (binding spec - implement every item)

1. This is an infrastructure self-check, not a LIGHT module, and is not gated by --mode. It contacts only a fixed list of benign hosts (the configured DoH provider, pypi.org...), never investigated targets.
2. A shared helper, core/tls.py, is used by tls_inspect (P275), P084 and doctor, so the logic is not duplicated. It checks chains against certifi's Mozilla bundle only: when the system store verifies but the Mozilla-only check fails, the issuer is recorded as 'TLS-intercepted by <issuer>'. Verification is never disabled and the corporate proxy is never bypassed.
3. It runs in doctor, and at most once per 24 h per egress profile (result cached in the home dir). At scan start it runs only when cert-derived modules are selected, in parallel, never blocking the scan start, and never in --offline.
4. When interception is detected: case metadata records the issuer, cert-derived findings (tls_inspect, CT comparisons, JARM, P084 CR17-CR19) are marked inconclusive for that run, and one header line says so (not one line per finding).
5. The check runs per egress profile, because interception differs per route. When the LIGHT/ACTIVE route is intercepted, a warning says that target traffic passes the corporate inspection proxy.
6. Unit tests use recorded chains (the design_tls_inspect fixture) and injected SSL contexts.

Chair rationale: Approved 6-0 at median P2. Corporate TLS inspection would otherwise make certificate findings describe the proxy (Ceos and the research sandbox hit it). redteam_lead and the architect reclassified it as an infrastructure check, since it never touches targets. It runs per egress profile (redteam_lead), at most daily and never blocking startup (osint_investigator, architect floor, analyst_ux), with shared core/tls.py code (architect floor). cti_lead: the benign host list and inconclusive cert findings. legal_dpo raised no issue.

Synthesizer conditions (background; the final conditions win on conflict): At startup and in `v3lum doctor`, verify a few known hosts against certifi's Mozilla bundle only; if the system store verifies but Mozilla-only fails, record 'TLS-intercepted by <issuer>' in the case metadata, warn in the report, and make cert-derived findings (tls_inspect, CT comparisons) inconclusive for that run. Reuses tls_inspect logic (shared candidate).
Notes: Céos hit exactly this with an antivirus; the sweep sandbox proxy re-signed github.com.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0632 TLS certificate & protocol inspection (+ interception detection) - python stdlib ssl + cryptography
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: [200]); passive: True; touches_target: True
- endpoint: tcp://{host}:443 (TLS handshake, SNI={host}); behind an HTTP proxy use CONNECT {host}:443
- method: socket.create_connection (or CONNECT tunnel) -> ssl.SSLContext.wrap_socket(server_hostname) -> getpeercert(binary_form=True) -> cryptography.x509.load_der_x509_certificate
- inputs: ['domain', 'url', 'ipv4']
- outputs: leaf cert subject/issuer/serial/validity/SAN list/key type+size/signature hash, SHA-256+SHA-1 fingerprints, negotiated TLS version/cipher/ALPN. New pivots: every SAN dNSName -> domain entity; cert SHA-256 -> cert_fingerprint (crt.sh / Censys pivots); issuer -> CA usage profile.
- auth: none
- rate limit: 1 handshake per host per run (+ up to 4 extra for protocol-version probing)
- terms / licence: stdlib (PSF) + cryptography (Apache-2.0/BSD)
- risk: Light-touch: a TLS handshake is normal visitor traffic. Protocol downgrade probing (TLS1.0/1.1, weak ciphers) is still benign but noisier; keep it optional. In corporate networks with TLS-inspecting proxies/AV (Céos hit exactly this) the observed cert is the proxy's: results must be flagged, never reported as the target's cert.
- implementation notes: TOUCH: light-touch. ALGORITHM: (1) handshake with default context (system store) -> collect cert+version+cipher; (2) second handshake with a context loaded ONLY with certifi's Mozilla bundle: if (1) verifies and (2) fails with 'self-signed certificate in chain', the path is TLS-intercepted -> mark result 'intercepted_by=<issuer>' and suppress cert-based findings. Verified live 2026-11-25: example.com passed through (real Cloudflare ECC CA 3 cert, verified by Mozilla store), github.com was intercepted by 'CCR agent-proxy interception CA' and the Mozilla-only check failed exactly as designed. (3) Findings: expired (HIGH), expires<14d (MEDIUM), <30d (LOW), hostname not in SAN (HIGH), self-signed (MEDIUM), RSA<2048 or EC<256 (MEDIUM), SHA-1 signature (MEDIUM), wildcard (INFO), validity>398d (INFO). (4) Optional protocol probe: ctx.minimum_version=maximum_version=TLSv1/TLSv1_1; many OpenSSL builds refuse old protocols client-side (SECLEVEL) -> report 'could not test' not 'disabled'. SAFETY: 10 s timeout, max 5 handshakes/host, never send application data. Map: weak TLS -> ATT&CK T1557 (enabler).
- sample: <scratch>/research/samples/design_tls_inspect.json (valid_json)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/design_tls_inspect.json

## P330 `bundled_reference_data` - Bundled reference data refresh (IANA TLD list, PSL, NOTICE file)

- council: **approved**, priority P2, default_enabled=True, provider_tier=trusted, terms=open, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: domain, text_blob; produces: 
- auth: none; key env vars: -; hosts: data.iana.org
- upgrades existing module: v3lum/data

### Final conditions (binding spec - implement every item)

1. `v3lum data update` refreshes iana_tlds.txt (data.iana.org) and public_suffix_list.dat (publicsuffix.org) into ~/.v3lum/datasets, never into the installed package. The bundled copies stay as fallbacks. Both providers are registered as tier trusted, terms open (IANA public data; PSL MPL-2.0).
2. Downloads are validated before they replace the previous copy: PSL markers '===BEGIN ICANN DOMAINS===', the IANA '# Version' header, minimum entry counts (com and br present), and anti-bot/error pages rejected through P321. The replace is atomic, and the previous copy is kept on failure.
3. One machine-readable registry (bundled files, register_dataset licence/terms/attribution fields, adapted MIT/BSD/Apache code) generates data/NOTICE and THIRD_PARTY_NOTICES.md. Each entry: name, source URL, version/commit or etag, SHA-256, licence, attribution text, bundled or runtime.
4. CI fails when a bundled file has no NOTICE entry, or when a GPL/AGPL/CC BY-SA/NC dataset is bundled instead of downloaded at runtime (A6).
5. The PSL stays an unmodified MPL-2.0 file with its notice, and the IANA list is public data. Attributions (ATT&CK, CC BY sources, runtime-only GPL datasets) are generated from the registry.

Chair rationale: Approved 6-0 at median P2 (legal_dpo voted P1). osint_investigator asked for validation before replacing, because a challenge page replacing the PSL would silently break every domain pivot. legal_dpo's floor: a machine-checked inventory and a CI block on bundled copyleft/NC data, the PSL kept unmodified. The architect's floor: datasets written to the home dir, never the package, atomic replace with a bundled fallback, notices generated from metadata. IANA and the PSL are data sources: tier trusted, terms open.

Synthesizer conditions (background; the final conditions win on conflict): `v3lum data update` refreshes data/iana_tlds.txt and public_suffix_list.dat (keep bundled fallbacks); add data/NOTICE listing every bundled/runtime dataset with source URL, version/commit and licence (ATT&CK notice, CC BY attributions, GPL runtime-only datasets).
Notes: Correct domain detection and licence compliance.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0707 IANA TLD list - data.iana.org
- kind: dataset_download; status: verified_live (HTTP seen: [200]); passive: True; touches_target: False
- endpoint: https://data.iana.org/TLD/tlds-alpha-by-domain.txt
- method: GET (first line is a version/date comment)
- inputs: ['domain', 'text_blob']
- outputs: Current set of valid TLDs (ASCII, IDN in xn-- form).
- auth: none
- rate limit: Static; weekly refresh.
- terms / licence: IANA public data.
- implementation notes: 9.5 KB. Used by the IOC extractor to validate domain candidates (ioc-finder/ioc-extractor do the same); combine with the Public Suffix List (already fetched by another sweep: <scratch>/psl_full.dat) for registrable-domain computation.

## P331 `declarative_json_collector` - Declarative JSON/CSV/RSS collector (Machinae-style specs)

- council: **approved**, priority P2, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: url; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. Each spec compiles into a real Module subclass with the full contract: terms with evidence, provider and tier, disclosure, opsec passive, hosts, quotas/min_interval, run_on, error_markers, found/absent rules, absent_statuses and a health_check value. Policy, quotas and status semantics therefore apply unchanged, and a spec without these fails the P327 lint.
2. Specs are bundled in v3lum/data/specs. User specs load only from ~/.v3lum/specs, with the plugin ownership/permission checks (AR12). Specs are schema-validated at load, with no eval and only whitelisted placeholders taking type-validated, URL-encoded values.
3. The request URL host must be a literal declared host of the spec (https only). Templating the host from the entity is refused, so a passive spec can never contact the target. Only GET search lookups are allowed (no POST of the value to submission or publishing endpoints, rule 7), and the spec language cannot express logins, cookies or CAPTCHA handling.
4. Machinae's declarative pattern is re-implemented with MIT attribution: request {url template, params, method, headers, ignored_status_codes}, results [{key dotted.path, pretty_name, regex, match_all, format}], multi_match onlyif, paginated, multi_json (NDJSON).
5. Supported formats: JSON, NDJSON, CSV, RSS/XML and HTML-embedded JSON (__NEXT_DATA__, ld+json). A minimal dotted-path extractor is used (no JSONPath library), with bounded, reviewed regexes. Machinae's site list is not ported.
6. The P321 classifier runs first, and challenge-protected sites are link-only (A9).
7. A spec is enabled only with a trimmed real fixture and a parametrized test (spec + fixture -> expected attributes/status), plus an error-in-200 fixture.
8. Defaults follow A3/A8: specs for unknown-tier operators or with unknown terms ship default_enabled=False and stay disabled under corporate until reviewed. Unknown-tier specs never receive PERSONAL_TYPES, and community profile-site specs follow the A5 username rules.
9. Specs failing their health checks on 7 consecutive days are auto-disabled with a doctor notice. `v3lum info` shows spec sources like any module (terms, tier, hosts).

Chair rationale: Approved 6-0 at median P2 (osint_investigator P1; cti_lead and analyst_ux P3, wary of adding long-tail unknown operators). The engine is approved, while each spec still faces the A1/A3/A8 gates and the default-off rule for unknown tiers or terms (legal_dpo, cti_lead). The architect's floor: specs compile into real Module subclasses, schema validation, declared hosts, a fixture per spec. redteam_lead: a URL template is code, hence the literal-host rule. legal_dpo: a spec cannot express logins, cookies or POSTs to publishing endpoints. osint_investigator: formats, health-based auto-disable.

Synthesizer conditions (background; the final conditions win on conflict): Re-implement (MIT attribution) Machinae's declarative pattern: {name, otypes, request:{url template, params, method, headers, ignored_status_codes}, results:[{key dotted.path, pretty_name, regex, match_all, format}], multi_match onlyif, paginated, multi_json (NDJSON)} plus V3LUM fields (found/absent rules, error_markers, vocab mapping, opsec, terms, keys, min_interval); one spec line per long-tail keyless API (VPNDetection, IPLogs, IPQuery, InternetData, NetAPI, MailCheck, AreaCodeCheck, MalwareIntel, HoneyLabs CVE, community profile sites); do NOT port Machinae's site list (mostly dead/paid).
Notes: Cuts implementation effort for ~40 small keyless sources.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

## P332 `module_metadata_taxonomy` - Module metadata taxonomy (access model, health check, TLP limits) from SpiderFoot/IntelOwl/Cortex

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/module.py

### Final conditions (binding spec - implement every item)

1. veto_lift: the subfinder-style multi-key random rotation is dropped. One key per provider per installation, or per user where the provider licenses per-user keys. Quotas are counted per key and per egress (P334).
2. veto_lift (continued): several keys only where the provider's terms explicitly allow multiple keys for one organisation (e.g. paid seats), selected deterministically by owner/plan alias and logged by alias, never by value. Never to multiply free-tier limits or to use other people's keys.
3. One consolidated schema replaces the overlapping fields, frozen in phase 0 as contract v2. Declared by the module: terms, disclosure (none | internal | third_party | target), hosts, provider, sources, access_model, run_on, max_requests, expected_latency, requires_egress, max_rate, absent_statuses, error_markers, manual_link, health_check().
4. Derived from the provider registry, never declared by the module: trust_tier, upstream families, reliability (Admiralty grade), sensitive, publishes_queries, reuses_queries and fetches_target (A8 BR8).
5. max_rate is the LIGHT/ACTIVE request rate per target host in req/s, never above the A7 ceilings.
6. access_model takes one of free_noauth_unlimited | free_noauth_limited | free_auth_limited | free_auth_unlimited | commercial_only | internal | offline, and is shown in `modules`/`info` with a plain-words label (e.g. 'free, no key, limited').
7. max_tlp (A2) is derived by core/policy.py from disclosure, tier and the publishes/reuses flags, never hand-set, and enforced by the engine: none/internal -> red; target -> amber (red only on verified own assets not third_party_hosted); trusted -> amber+strict; community -> amber; unknown or reuses_queries -> green (unknown only with --allow-unknown); publishes_queries -> never.
8. shares_input becomes a derived alias of disclosure (disclosure in {third_party, target}).
9. health_check() returns a benign value from one central list (example.com, 8.8.8.8, EICAR, CVE-2021-44228, octocat), or an offline self-test for LIGHT/ACTIVE modules. doctor (P337) and the keys wizard (P379) use it, and its calls count against quotas.
10. describe(), `v3lum info` and doctor show every field. A registry-wide contract test validates all registered modules (enums, explicit declarations, registry entries). Existing modules and stored cases keep working.

Chair rationale: Mechanical status: vetoed by legal_dpo (yes 5 / reject 1). veto_lift adopted: random rotation across several keys exists to evade per-key quotas (rule 6, and rule 1 when the keys belong to others). Dropping it, with one key per provider unless the terms allow more, is condition 1. Everything else is approved as legal_dpo's lift allows, with max_tlp aligned to A2. cti_lead, osint_investigator, redteam_lead, the architect and analyst_ux all asked for the same drop. The chair raises the priority from the median P2 to P1 on the architect floor: the A16 phase-0 freeze needs this schema before ~300 modules are written (architect and cti_lead voted P1). One disclosure concept replaces shares_input + max_tlp (architect, analyst_ux); max_rate is redteam_lead's.

Synthesizer conditions (background; the final conditions win on conflict): Add to Module: access_model (FREE_NOAUTH_UNLIMITED, FREE_NOAUTH_LIMITED, FREE_AUTH_LIMITED, FREE_AUTH_UNLIMITED, COMMERCIAL_ONLY), max_tlp (IntelOwl maximum_tlp: TLP:AMBER/RED inputs never sent to third parties; complements shares_input), health_check() self-test hook, subfinder-style key handling (several keys per source, random pick, per-source stats); surfaced in `v3lum info`/doctor.
Notes: Lets the engine and the council reason about every source uniformly.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0664 SpiderFoot event-type model + data-source auth taxonomy - github.com/smicallef/spiderfoot
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: []); passive: True; touches_target: False
- endpoint: n/a (spiderfoot/db.py eventDetails, modules/sfp_*.py meta)
- method: Code reading
- inputs: ['text_blob']
- outputs: Design artifact: 170 normalized event types (ENTITY 55, DESCRIPTOR 79, DATA 30, SUBENTITY 5) e.g. INTERNET_NAME, DOMAIN_NAME, IP_ADDRESS, EMAILADDR, AFFILIATE_*, CO_HOSTED_SITE, BLACKLISTED_*, MALICIOUS_*, LEAKSITE_*, BITCOIN_ADDRESS; module meta: watchedEvents/producedEvents, flags, useCases, categories, dataSource.model.
- auth: none
- terms / licence: MIT (Copyright 2022 Steve Micallef) - code/structures may be adapted with attribution.
- implementation notes: Adopt the pub/sub pattern for V3LUM: each collector declares consumes=[entity types], produces=[entity types], auth_model, passive, touches_target; the engine schedules collectors whenever a new entity of a consumed type appears (bounded by pivot depth + per-type budget). dataSource.model distribution over 238 modules: FREE_NOAUTH_UNLIMITED 85, FREE_NOAUTH_LIMITED 7, FREE_AUTH_LIMITED 52, FREE_AUTH_UNLIMITED 9, COMMERCIAL_ONLY 7, PRIVATE_ONLY 1, none 72 - reuse these labels for V3LUM's source registry and for "which keys unlock what" in the CLI. 44 FREE_NOAUTH reputation/leak modules found (blocklist.de, CINS, GreenSnow, ET, botvrij, VXVault, VoIPBL, StevenBlack hosts, protective DNS: Quad9/Cloudflare/AdGuard/CleanBrowsing/OpenDNS/Yandex...).

#### C0666 IntelOwl analyzer catalog (observable taxonomy + free analyzer checklist) - github.com/intelowlproject/IntelOwl
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: []); passive: True; touches_target: False
- endpoint: api_app/analyzers_manager/migrations/0002_*_analyzer_config_*.py (plugin/params dicts)
- method: Parsed with ast.literal_eval (no import/exec): <scratch>/research/tmp_gh_cti_ioc/intelowl_probe.py -> <scratch>/research/tmp_gh_cti_ioc/intelowl_analyzers.json
- inputs: ['text_blob']
- outputs: Checklist of 224 analyzers (152 observable / 72 file; 20 docker-based; 133 without a required secret) with observable_supported (ip, domain, url, hash, generic), supported_filetypes, maximum_tlp, required secrets.
- auth: none
- terms / licence: AGPL-3.0 - ideas/catalog only, no code copying.
- risk: AGPL: do not copy analyzer code. Several listed analyzers break team rules (Dehashed_Search, IntelX intelligent search/file access, HudsonRock infostealer data, DownloadFileFromUri, active scanners like Knock/Nuclei/WAD) - excluded from this sweep.
- implementation notes: Useful IntelOwl ideas: a per-analyzer maximum_tlp (V3LUM should refuse to send TLP:RED/AMBER inputs to third-party APIs), health_check per analyzer (V3LUM "doctor" command), observable classification "generic" fallback for emails/phones/CVEs. Free analyzers worth having that are covered in this sweep: CIRCL hashlookup, Cymru MHR, YARAify, Feodo, ThreatFox/URLhaus/MalwareBazaar (key), OTX, Pulsedive, Maltiverse (Cortex), ORKL, CyCat, TweetFeed, DShield, BGP Ranking, Mnemonic pDNS, Abusix, Spamhaus DROP, FireHOL, Tor exits, PhishStats, Phishing Army, CheckDMARC, protective DNS (Cloudflare/Quad9/DNS0/UltraDNS/AdGuard/Mullvad).

#### C0671 Cortex-Analyzers catalog (dataType taxonomy) - github.com/TheHive-Project/Cortex-Analyzers
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: []); passive: True; touches_target: False
- endpoint: analyzers/*/*.json flavor manifests
- method: Parsed JSON manifests (read-only)
- inputs: ['text_blob']
- outputs: 164 analyzer folders / 288 flavors (44 with no required config). dataTypeList taxonomy: ip, domain, fqdn, url, uri_path, mail, mail_subject, hash, file, filename, registry, user-agent, ja4-fingerprint, other.
- auth: none
- terms / licence: AGPL-3.0 - ideas only.
- risk: AGPL: no code copying.
- implementation notes: Extra free ideas not in IntelOwl: MSDefenderOffice365_SafeLinksDecoder (offline URL unwrapping), MISPWarningLists (FP filter), QrDecode (quishing QR in images/PDF), Abuse_Finder (abuse contacts), TeamCymruMHR, NSRL, Virusshare hash lists, StopForumSpam, Maltiverse_Report, ScanMalware, DShield_lookup, DomainMailSPFDMARC, Msg_Parser, PDFPreview (render in sandbox).

## P333 `new_entity_types` - New entity types and detector patterns suggested by the sweeps

- council: **approved**, priority P2, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/entities.py

### Final conditions (binding spec - implement every item)

1. A type is added only if an approved module or pivot pack in this build accepts or produces it. Each new type names its consumer/producer and gets a normalizer, validator, display, a STIX mapping (or an explicit 'no STIX object') and collision tests. md5/sha1/sha256 detection is unchanged and the existing detect suite passes.
2. First wave: email_headers (raw header blocks, .eml, .msg) for phishing triage; telegram_handle and telegram_invite (t.me/<name>, t.me/+<invite>); discord_invite; social_account (platform + handle from profile URLs and platform-context @handles, never blindly expanded into a multi-site sweep); pix_brcode detection (EMV '000201'...'6304' + CRC16) feeding P233.
3. Also first wave: the structural hashes imphash, tlsh (T1 + 70 hex), telfhash, gimphash, authentihash, icon_dhash and code_signing_cert, needed by P351. Second wave: pgp_fingerprint, fediverse and bsky handles, steam profile, port/service. eu_vat, vin, tiktok video id and snowflake id may slip to P3.
4. Detection comes only from an explicit TYPE:value prefix, a URL pattern (t.me/, discord.gg/, bsky.app/...) or an unambiguous structure (header block, T1+70-hex TLSH, a leading-@ @user@instance). Detection is offline: no WebFinger or other lookup. Never from bare hex or digit length (imphash = MD5 length, authentihash = SHA-256 length, snowflake/TikTok ids vs phone/CPF).
5. Personal-identifier types (telegram, fediverse, bsky and steam handles, social_account, invites, vin, email_headers) join PERSONAL_TYPES: not auto-expanded from text/file inputs, excluded from cross-case sightings by default, and masked where they carry personal data (VIN partly).
6. CPF stays never-expanded, and person names are typed and used only after analyst confirmation.
7. Secret-like types (telegram_bot_token and similar) are detect-only SECRET_TYPES: NO_AUTO_EXPAND, masked, never used or validated against any API, never shared or exported.
8. email_headers/.eml/.msg parsing is static and offline: it never fetches remote images, tracking pixels, CSS or links, and recipient lists are not pivoted.
9. image: EXIF GPS is location data, tagged privacy, and never auto-pivoted to map or reverse-geocoding services.
10. Invites: public preview metadata only, never joining, logging in or accepting. port/service entities never trigger probing on pivot. The similar_to relation is low confidence and never auto-expanded.
11. Vocab additions (same_m365_tenant, intercepted_by, quota status) go to core/vocab.py. Local fuzzy-hash computation (py-tlsh, telfhash) comes only via optional extras.
12. Phasing: the first-wave types consumed by P1 proposals (email_headers, telegram_handle, telegram_invite, discord_invite, social_account, pix_brcode; used by P172, P112 and P233) land in phase 1 with P172. The rest follows this proposal's P2.

Chair rationale: Approved 6-0 at median P2 (osint_investigator voted P1). The architect's floor and analyst_ux: add only consumed types, never guess hex/digit-length formats, keep detection unchanged. cti_lead put email_headers and structural hashes first, osint_investigator social_account and pix_brcode for Brazilian scams. legal_dpo's floor: new personal identifiers join the protected class, EXIF GPS is never auto-pivoted, invites are preview-only, secrets are never used. redteam_lead: static e-mail parsing (tracking pixels reveal the investigation), no probing on port pivots.

Synthesizer conditions (background; the final conditions win on conflict): Add to core/entities.py + detect.py: email_headers (raw header blocks/.eml/.msg), image (subtype of file), pgp_fingerprint (40 hex), eu_vat, vin (17 chars), port/service, tweet/status URL id, telegram handle/invite (t.me/<name>, t.me/+invite), discord_invite, telegram_bot_token (detect only), fediverse handle (@user@instance; try WebFinger vs e-mail), bsky handle, steam profile, tiktok video id, snowflake id; plus vocab additions (same_m365_tenant relation, intercepted_by attribute, quota status). Keep CPF never-expanded and person names analyst-confirmed. Gap fill: add structural/fuzzy hash entity types with validators: imphash (32 hex, context-typed), tlsh (T1 + 70 hex), telfhash, gimphash, authentihash (64 hex), icon_dhash (16 hex), code_signing_cert (serial + issuer / thumbprint) and relation similar_to (low confidence, never auto-expanded).
Notes: Many collectors need inputs that the detector cannot type today.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/gaps__structural_hashes.json

## P334 `quota_token_buckets` - Per-source quotas and token buckets (daily/monthly budgets, shared-egress awareness)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: url; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. Budgets are keyed by provider (the registry quota block: per egress_ip or per key; hour/day/month UTC windows plus a token bucket for rate), not by module. All endpoints of a provider share one counter, and only requests to that provider's hosts count (DoH is not charged).
2. Quota is reserved before sending, inside HttpClient/ScopedHttp, with an atomic SQLite update that holds across threads and processes, so 12 threads cannot overshoot a 50/day budget. Exhaustion raises QuotaExceeded -> Status.QUOTA with 'could not verify' wording.
3. Budgets come from the registry with evidence of the published limit and default to at most 80% of it. Keyless budgets are global per installation and egress, never multiplied by keys, proxies or Tor exits. An optional team-shared quota DB path (setting quota_db_path) serves analysts behind one NAT. Keyed plans get monthly counters.
4. A per-destination-host limiter is shared by all modules: interval = the max of every interval declared for that host by modules and profiles, and of the opsec floor, and the slot is always reserved (today HostLimiter.wait_turn returns early for min_interval 0).
5. Hard ceilings: LIGHT <= 1 req/s and <= 25 requests per target host per scan; ACTIVE <= 10 req/s and <= 2 concurrent connections per host, lowered by the scope file when it says so.
6. 20% of each daily budget is reserved for seeds; pivots at depth >= 2 never consume it. Seeds are prioritised and low-value calls deferred.
7. Each exhausted source gets one report line (e.g. 'HackerTarget: 50/50 today, 12 lookups deferred'), and deferred lookups are listed per source. `v3lum cases resume <id>` re-runs only the deferred or could-not-verify (module, entity) pairs.
8. The provider's own quota signal (P321 error markers) wins when counters disagree: the counter is set to exhausted until the window resets.
9. Exhaustion never triggers a fallback to LIGHT/ACTIVE alternatives, another account or another egress. Health checks (P337) and key tests (P379) count against budgets.
10. Module.daily_quota stays as a fallback for providers without a registry quota. Quota state is shown in coverage and doctor. Tests use a fake clock, plus a 12-thread overshoot test.

Chair rationale: Approved 6-0. The chair raises the priority from the median P2 to P1 on the architect floor: it is in the A16 phase-0 list because per-module accounting is both inaccurate and racy, and free quotas shared per egress IP ran out during research (the architect, legal_dpo and redteam_lead voted P1). The architect's floor: buckets per provider, atomic reservation before sending, QuotaExceeded -> QUOTA. legal_dpo's floor: budgets from published limits at <= 80%, never multiplied, no fallback to another account or egress. redteam_lead: the shared per-host limiter and hard ceilings. analyst_ux: the seed reserve, deferral lines and resume. cti_lead and osint_investigator: a shared quota store.

Synthesizer conditions (background; the final conditions win on conflict): Per-source token bucket (rate) + persistent daily/monthly budget counters in SQLite (XON 25/h 100/day, VT 4/min 500/day, HackerTarget 50/day, ...); 'quota exhausted' surfaced per source in the report; keyless quotas are per egress IP (corporate NAT shared by all analysts) -> budget is global per installation; Céos quota-aware batching port (prioritise seeds, defer low-value calls).
Notes: Keyless quotas were already exhausted from shared IPs during the sweeps.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0709 Quota-aware batching for free APIs - Céos ceos/exposicao.py + ceos/coletores/vazamentos.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: MAX_POR_VEZ=10, contas_para_consultar, consultar_todos (stops on LimiteAtingido and reports 'faltam')
- inputs: ['email']
- outputs: consulted/new/remaining counters, stop-on-limit
- auth: none
- terms / licence: team-owned
- implementation notes: Generalize into QuotaManager(source, per_second, per_hour, per_day) persisted in sqlite; queue the remainder for the next run and print 'N pending (quota)'. Needed for XposedOrNot (25/h, 100/day), GitHub (60/h), abuse.ch, etc.

## P335 `report_grouping` - Duplicate grouping for triage/report (union-find)

- council: **approved**, priority P2, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. Grouping happens only in the presentation layer (terminal, HTML, MD). Case JSON, STIX/MISP exports and evidence keep every entity, finding, source and link. Distinct IOCs are never merged: URL variants are grouped visually and exported separately.
2. Only findings stating the same fact about the same subject are grouped: the same breach across sources; URL variants of one resource (refanged, www/no-www, tracking-param variants); the same CVE from several sources. Distinct identity entities (username, social_account, person_name, email, phone) are never merged.
3. A grouped row shows the highest severity and confidence with its criterion, the count, and the sources and upstream families (e.g. 'seen by 3 sources: XON, HIBP, LeakCheck'). Every member keeps its evidence and feedback id.
4. Correlations are grouped by entity. Grouping keys (normalized URL, breach name) are deterministic, documented and tested. Score de-duplication stays in scoring (P302), not in the renderer.
5. Normalized URL key (Ceos rules): lowercase host without www./m., no trailing slash, tracking parameters (utm_*, fbclid, gclid, igshid, ref, si, hl, trk) dropped and the query sorted. A URL without a path never groups, because portals reuse the homepage for different records.
6. Union-find implementation. Test: the same breach from 3 sources renders as 1 row and exports as 3 findings.

Chair rationale: Approved 6-0 at median P2 (analyst_ux voted P1). Display-only grouping that keeps machine-readable outputs atomic is the architect's floor and cti_lead's condition for TIP ingestion. osint_investigator: never merge identities (homonyms), keep every source and evidence link. analyst_ux: row format and variant grouping. legal_dpo and redteam_lead raised no issue.

Synthesizer conditions (background; the final conditions win on conflict): Group near-duplicate findings/entities (same breach across sources, same URL variants) with union-find before rendering; keep all evidence links.
Notes: Shorter, clearer reports.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0704 Duplicate grouping for triage/report (union-find) - Céos ceos/agrupar.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: chave_url, chave_perfil, _palavras_titulo, _semelhanca (Jaccard), agrupar; LIMIAR_NOTICIA=0.8; _RASTREIO tracking-param regex
- inputs: ['url', 'text_blob']
- outputs: groups {principal, others, reason, ids}
- auth: none
- terms / licence: team-owned (tests/test_agrupar.py exists)
- implementation notes: Display-only grouping (each finding keeps its own evidence/hash). Same profile (platform+handle), same normalized URL (no www/m., no trailing slash, tracking params utm_/fbclid/gclid/igshid/ref/si/hl/trk dropped, sorted query), URL without path NEVER groups (portals reuse the homepage for different records), news titles without ' - Outlet' with Jaccard >= 0.8. Principal = highest confidence then oldest. V3LUM: also group IOCs by refanged canonical value and correlation results by entity.

## P336 `report_integrity` - Self-contained hashed report (no external resources)

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: report/html.py

### Final conditions (binding spec - implement every item)

1. HTML carries a Content-Security-Policy meta: default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src limited to the hash of the bundled JS (no 'unsafe-inline' script). All assets are embedded, and no external images, fonts or resources of any kind load (Gravatar/XON logos never).
2. One safe_href() (http/https only) is used for every anchor in HTML and Markdown, including case and manual-pivot links; today only references are scheme-checked.
3. Entity-derived URLs (targets, IOCs, references pointing at investigated hosts) and entities tagged malicious/phishing/c2/suspicious are defanged and non-clickable. Only pivot templates and allow-listed reference hosts are clickable, with rel=noreferrer, and pivot links only at TLP:CLEAR/GREEN: at AMBER and above they render as non-clickable text with the disclosure warning (A2, P311).
4. The evidence manifest (file, SHA-256) is embedded. The report's own SHA-256 goes to a sidecar <report>.sha256 and to the case DB, because a file cannot contain its own hash; any hash shown in the footer states that it covers the content above it. `v3lum cases verify` checks both.
5. TLP 2.0 marking (label and colour) appears in the header and footer of every report, at the top of every section and in print CSS. Markdown and JSON carry the tlp field and banner, and file names carry the label (A2).
6. A licence banner lists every noncommercial/license or allow-listed source used. Required attributions are generated from source/dataset metadata for the sources actually used (MITRE ATT&CK, HIBP CC BY 4.0, OSM ODbL, DB-IP CC BY 4.0, WhatsMyName CC BY-SA 4.0, OffSeq...) and shown in a collapsed footer section.
7. A 'contains personal data (LGPD)' notice appears when PERSONAL_TYPES entities are present. CPF is masked, and report files are written 0600.
8. LIGHT/ACTIVE cases get an engagement block: authorization reference, scope SHA-256, window, egress profile/IP, targets touched and request counts (A7).
9. Tests assert no external loads, neutralized javascript:/data: links, phishing URL fixtures rendered defanged, and markings present on every section.

Chair rationale: Approved 6-0. The chair raises the priority from the median P2 to P1 on the legal floor: A2 requires the TLP marking on every page and section, CC BY sources require attribution, and reports hold personal data and must be 0600 (legal_dpo, osint_investigator and the architect voted P1). The architect's floor: a CSP with a script hash, http(s)-only hrefs, a sidecar hash, generated attributions. osint_investigator and redteam_lead: no click into a phishing kit from a report, and the engagement block. analyst_ux: notices in a collapsed footer. cti_lead: attributions from the sources actually used.

Synthesizer conditions (background; the final conditions win on conflict): HTML report embeds all assets (no external images/fonts; Gravatar/XON logos never loaded), includes its own SHA-256 manifest of evidence and a report hash in the footer, plus attribution notices (MITRE ATT&CK, HIBP, OSM, DB-IP, WMN, OffSeq...).
Notes: Safe to open offline and to hand over as evidence.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0711 Self-contained hashed report (no external resources) - Céos ceos/relatorio.py + templates/
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: montar_html, previa_html, gerar; avatar/map as data: URIs
- inputs: ['text_blob']
- outputs: HTML report with embedded images (base64), SHA-256 registered, 'do not distribute' banner; accepted findings only in final mode
- auth: none
- terms / licence: team-owned
- implementation notes: Rule to keep: opening the report must not contact any third party (no remote images/fonts/scripts) - prevents tipping off the subject. V3LUM: terminal report (Rich) + exports HTML/Markdown/JSON/STIX, each hashed and logged.

## P337 `source_health_doctor` - Source health check ('doctor') with per-source self-tests

- council: **approved**, priority P2, default_enabled=False, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=True
- category: utility; group: G15; inputs: url; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: cli doctor

### Final conditions (binding spec - implement every item)

1. `v3lum doctor` stays fast (< 15 s): environment, permissions, keys, proxy/egress routes, TLS interception (P329) and at most 3 reachability probes. Per-module health checks run only through `v3lum doctor --sources [names]`, never at scan time or at startup.
2. Each module's health_check() uses benign values from one central list (example.com, 8.8.8.8, EICAR, CVE-2021-44228, octocat). Username packs use the platform's official account as claimed and a random 20-char handle as unclaimed, sampling 25 sites per run in rotation.
3. LIGHT/ACTIVE health checks are offline self-tests (binary/dataset presence and pinned hashes, a local loopback fixture on 127.0.0.1), never network probes against any host. LIGHT self-tests never contact third-party sites.
4. Sources disabled by the licence profile or by TLP are not called, even with benign values.
5. Checks are quota-aware: they count in the quota book; providers with a daily budget <= 100, or below 20% remaining, are skipped unless --include-quota-sources; each source is checked at most once per day.
6. Concurrency is bounded (<= 4), with per-host politeness and a per-check timeout. Results (ok / blocked / quota / needs_key / dead, with their age) are cached 24 h and shown in coverage (e.g. 'last source check 2 d ago: 5 failing'). Scans never run health checks.
7. Results feed the A3 demotion state: repeated failures move a source out of the default set with a notice, and dead sources are flagged, never silently removed. They also feed the P331 auto-disable.
8. doctor also reports, on request, the egress_country verification (A9) and each egress profile's public IP, and lists loaded plugins. The doctor runner has offline tests with FakeHttp.

Chair rationale: Approved 6-0 at median P2 (osint_investigator voted P1). All members worried that ~300 health checks from a shared NAT would burn keyless quotas, hence explicit `--sources` checks that are quota-aware, cached and sampled (architect floor, redteam_lead, analyst_ux). legal_dpo's floor: active self-tests only against 127.0.0.1, licence-disabled sources never called. osint_investigator and cti_lead: benign values and the degraded flag in coverage. It is an explicit command and never runs during scans, hence default_enabled false.

Synthesizer conditions (background; the final conditions win on conflict): `v3lum doctor` runs each module's health_check (benign values, e.g. example.com, 8.8.8.8, EICAR, CVE-2021-44228, octocat) and reports ok/blocked/quota/needs_key/dead plus TLS-interception status and proxy reachability; username packs run their claimed/unclaimed self-tests; results stored for the coverage section.
Notes: Detects source drift before analysts rely on it.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0713 Source health check ('doctor') - Céos ceos/saude.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: estado, resumo_para_coleta, testar (one uncached probe), RESOLVER hints, _TESTES probe URLs
- inputs: ['text_blob']
- outputs: per-source state ready/limited/stopped/attention + fix hint
- auth: none
- terms / licence: team-owned
- implementation notes: `v3lum doctor`: missing key env var -> stopped with exact variable name; GitHub without token -> limited (60/h); last run error -> attention; on-demand probe bypasses the cache on purpose (cache would hide the failure). Show it before each run so the analyst knows coverage up-front.

## P338 `exposure_posture` - Exposure posture checklist + suggested posture (weak/regular/good)

- council: **approved**, priority P3, default_enabled=False, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: email, username, person_name, domain; produces: 
- auth: none; key env vars: -; hosts: -

### Final conditions (binding spec - implement every item)

1. A pure function and report section over existing vocab tags and correlation results: no new collectors, no network.
2. The posture is computed only for subjects with a recorded purpose: own-domain employees within the security programme, VIP protection with the person's knowledge (executives opted in via org_profile), or incident victims. Never for any other third party, not even with an analyst opt-in (legal floor).
3. Employees' personal social-media life is excluded unless the person opted in (VIP programme). The 'predictable posting routine' (pattern-of-life) signal is dropped.
4. Wording: 'suggested posture (weak/regular/good)' with the evidence list per checklist item, plus one summary line naming the 3 items that drove it; the analyst confirms. No sensitive-data inference.
5. 'good' is never shown when any core source for the subject could not verify: the posture then reads 'inconclusive' and lists the unverified items.
6. Never used for HR or disciplinary decisions (LGPD art. 20, human review). Posture labels stay inside the case, follow its retention and are not exported.

Chair rationale: Approved 6-0 at median P3; it is implemented in this build only if cheap (A16). A weak/regular/good label per person is profiling, so legal_dpo's floor governs: a recorded purpose, never other third parties (the auditor removed an analyst opt-in for other subjects as looser than the floor), no HR use, labels kept inside the case. osint_investigator dropped the pattern-of-life signal. analyst_ux: 'inconclusive' instead of false reassurance. The architect: a pure function over existing data. It runs only for opted-in subjects, hence default_enabled false.

Synthesizer conditions (background; the final conditions win on conflict): Céos port: per-subject checklist (breaches, infostealer, public profiles, exposed contacts, weak e-mail posture) producing a suggested posture with the evidence that drove it; wording as suggestion, analyst decides.
Notes: Executive summary for awareness and incident cases.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0716 Exposure posture checklist + suggested posture (weak / regular / good) - Céos ceos/exposicao.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: checklist, sugerir_postura, _rotina_x
- inputs: ['email', 'username', 'person_name']
- outputs: checklist items {level risk|attention|not_verified|ok, text, origin, ids} + suggested posture
- auth: none
- terms / licence: team-owned
- implementation notes: Weak if any 'risk' (infostealer, plaintext password breach); regular if >= 2 'attention' (public email/phone/location in profiles, same handle in >= 3 networks, same photo across profiles, predictable posting routine: 70% of posts within <= 8 h); good otherwise - always listing 'not verified' items (absence of evidence is not evidence). V3LUM: reuse for person AND organization (email posture, exposed services) summaries; the analyst confirms the posture.

## P339 `pipeline_lanes` - Staged collection pipeline with per-service lanes (Céos coleta port)

- council: **approved**, priority P2, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/engine.py

### Final conditions (binding spec - implement every item)

1. This lands after per-run deadlines are enforced (AR05). It is implemented inside the existing single thread pool as a priority order (offline -> keyless passive -> keyed passive -> slow/opt-in -> light/active) plus per-module and per-provider concurrency caps, with no extra pools. Stages are priorities, not barriers: the pipelined BFS and all engine tests stay green.
2. The per-entity passive-before-LIGHT/ACTIVE ordering that the hostile-host guard needs is delivered with P376. Lanes must never reorder it.
3. Username and profile packs run in their own bounded lane (concurrency cap, run budget), so hundreds of site checks never starve other modules. Per-provider lanes serialise calls to the same upstream for quota safety.
4. LIGHT/ACTIVE work gets its own caps inside the single pool (<= 2 connections per target host and a bounded share of the pool's slots), so it never takes the slots of fast passive modules and no extra pool is created (architect floor). Cancellation stops LIGHT/ACTIVE work within 2 s.
5. Keyed calls may be skipped when cheap sources already answered (setting skip_keyed_when_answered, default false).
6. When the fast stage completes (target <= 20 s), a provisional summary line (risk so far, findings so far, sources pending) is printed. The live feed shows markers per lane.
7. Licence, TLP and scope gates stay in core/policy.decide; no lane bypasses them.
8. A deterministic test with simulated slow modules shows that fast results are not blocked. A bench test checks that a default domain scan completes at p90 <= 60 s with recorded latencies.

Chair rationale: Approved 6-0 at median P2 (analyst_ux P1, architect P3). The architect's floor: only after deadlines are enforced, inside the existing pool as priorities, with the guard ordering owned by P376. cti_lead, osint_investigator and redteam_lead require passive-before-light per entity, so the guard sees TI tags. redteam_lead: separate LIGHT/ACTIVE concurrency and 2-s cancellation. analyst_ux: the provisional summary and the time budget. legal_dpo: no lane bypasses the gates.

Synthesizer conditions (background; the final conditions win on conflict): Optional engine scheduling refinement: stages (offline -> cheap keyless -> keyed -> slow/light) and per-provider lanes so slow sources never block fast ones; live-feed markers per lane; must not break the existing pipelined BFS.
Notes: Faster first results and fewer wasted keyed calls.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0702 Staged collection pipeline with per-service lanes + terminal log markers - Céos ceos/coleta.py
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- method: ETAPAS (stage per collector), RAIAS (lane per upstream service), ROTULOS, _selecionar, _rodar_um, linha_consulta
- inputs: ['text_blob']
- outputs: ordered execution with coverage rows and live log
- auth: none
- terms / licence: team-owned
- implementation notes: Becomes V3LUM's pivot scheduler: stage N consumes entities produced by stage N-1 (domains need companies, GitHub needs domains, breach checks need all emails found); inside a stage collectors run in parallel, but collectors hitting the same upstream API share a lane and run serially (quota safety). One failing source never aborts the run; skipped/unavailable sources are listed in coverage. Keep the marker grammar for the dark-web UI: [>] start, [+] ok, [~] skipped, [-] unavailable, [!] error, ' GET host/path 200 · 0.4 s|cache'. Add max pivot depth and per-entity-type budgets.

## P340 `log_file_input` - Log-file input type (web access logs) with teler-resources matching

- council: **approved**, priority P3, default_enabled=True, provider_tier=n/a, terms=open, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: file, text_blob; produces: ipv4, url, user_agent
- auth: none; key env vars: -; hosts: raw.githubusercontent.com
- upgrades existing module: core/detect.py
- sources shared with other proposals: {"C0370": ["P317"]}

### Final conditions (binding spec - implement every item)

1. New input detection for Apache/Nginx/IIS access logs with a streaming parser: the file is never read whole, the line length cap is 8 KB, and size/line caps are reported when hit. 1M lines must parse in < 30 s offline, with progress shown.
2. Matching runs offline against the teler-resources web-attack patterns and bad-crawler lists (CC BY 4.0, attributed) and PHPIDS (LGPL-3.0), downloaded at runtime and never bundled (A6), compiled once. Patterns with catastrophic backtracking are excluded by a pathological-line test. One loader is shared with P317 user_agent_analysis.
3. Aggregation per client IP/path/UA happens before any pivot. Only IPs that matched attack signatures or bad-crawler lists become entities and may be enriched, capped at the top 20 by suspicious hits. Benign visitors' IPs are counted, not stored (customer IPs are personal data).
4. Private/internal IPs and hostnames from logs are never sent to third parties. URLs from logs lose their query strings before any external lookup (logs carry session and reset tokens). Request lines are stored with query-string values redacted and without cookies.
5. IPs from logs get passive enrichment only, never LIGHT/ACTIVE contact.
6. Log-derived cases default to TLP:AMBER. The log file is not copied into the case: evidence keeps the matched lines (redacted) and the file's SHA-256.
7. The first screen is a summary (e.g. '312 IPs, 14 matched rules, top 10 by hits, paths attacked').

Chair rationale: Approved with yes 5 / defer 1 at median P3; it is implemented only if cheap (A16). cti_lead deferred because mass-enriching customer IPs from logs discloses personal data and risks graph explosion. The conditions address exactly that: only signature-matched IPs leave the machine, capped at 20 (osint_investigator's cap, stricter than analyst_ux's 25 and the architect's 50), with legal_dpo's floor on redaction and evidence. The architect's floor: streaming, caps, ReDoS-safe runtime patterns. redteam_lead: passive only, private IPs and query strings never sent out. Auditor: terms set to 'open' from the dataset licences (runtime download plus attribution, A1/A6); provider_tier stays 'n/a' because matching is offline and no investigated value leaves the machine during it.

Synthesizer conditions (background; the final conditions win on conflict): New input detection for Apache/Nginx/IIS access logs: parse lines, extract client IPs, paths, UAs; match teler-resources web-attack patterns and bad-crawler lists (CC BY 4.0) offline; aggregate per IP before pivoting (cap distinct IPs, noise filter) so a 1M-line log does not explode the graph; shared candidate with user_agent_analysis.
Notes: Lets the SOC paste server logs directly.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0370 teler-resources web-attack & bad-actor datasets (log analysis) - github.com/kitabisa/teler-resources
- kind: dataset_download; status: verified_live (HTTP seen: [200]); passive: True; touches_target: False
- endpoint: https://raw.githubusercontent.com/kitabisa/teler-resources/master/db/{common-web-attacks.json|cves.json|bad-ip-addresses.txt|bad-referrers.txt|bad-crawlers.txt|directory-bruteforces.txt}
- method: GET (daily updated), cache locally
- inputs: ['file', 'text_blob', 'user_agent', 'ipv4', 'url']
- outputs: common-web-attacks.json (76 PHPIDS regex filters: id, rule, description, tags xss/sqli/lfi/rfi/csrf..., impact), cves.json (nuclei-derived request signatures), bad-ip-addresses.txt, bad-referrers.txt, bad-crawlers.txt (Crawler-Detect UA regexes), directory-bruteforces.txt -> matches in the team's access logs become attack events (tags, CVE) + attacker IP entities.
- auth: none
- rate limit: Static GitHub raw files.
- terms / licence: Collection CC-BY-4.0 (attribution). Upstreams: PHPIDS filters (LGPL-3.0 - ship as separate data file with credit), Crawler-Detect (MIT), nuclei-templates (MIT). teler code Apache-2.0 (adaptable).
- risk: none (offline matching of the team's own logs)
- implementation notes: Adds a new V3LUM input: web access log (combined format). Reimplement teler's per-field matching (request_uri vs CWA/CVE rules, referrer vs bad-referrers, UA vs bad-crawlers, remote_addr vs bad IPs); extracted attacker IPs then flow into IP-reputation collectors (CrowdSec, AbuseIPDB, GreyNoise).
- sample: <scratch>/research/samples/teler_common_web_attacks.json (valid_json)
- sample: <scratch>/research/samples/teler_bad_crawlers.txt (text)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/teler_common_web_attacks.json
- <scratch>/research/samples/teler_bad_crawlers.txt

## P375 `case_db_sightings` - Cross-case sightings from the V3LUM case database

- council: **approved**, priority P2, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: ipv4, ipv6, domain, url, email, md5, sha1, sha256, username, cnpj, btc_address, keyword; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/store.py

### Final conditions (binding spec - implement every item)

1. An index table (entity key, case id, case TLP, created, verdict) is written at save time via a migration. Lookups are offline (disclosure 'none', allowed at TLP:RED), and findings are never copied across cases.
2. The default index covers IOC_TYPES only. PERSONAL_TYPES (every e-mail, org-domain ones included, username, phone, person, CPF, pix_key, P333 handles) are indexed only as the keyed HMAC (A4), and only when the team enables it (setting sightings_personal, default false) with a recorded purpose. Equality lookups still work.
3. TLP (A2): a case sees sightings only from cases with TLP <= its own. Higher AMBER/AMBER+STRICT cases appear as 'seen in N restricted cases' with no ids, dates or verdicts. RED and LIGHT/ACTIVE engagement cases never surface in a lower-TLP case. CLEAR/GREEN exports and shareable reports omit cross-case references.
4. Noise entities (public resolvers, CDNs, big providers, warninglists, sinkholes) and own org assets are excluded from the 'recurrent' logic.
5. The rule recurrent_infrastructure fires when the same IOC (domain, IP, URL, hash or wallet) appears in >= 2 cases. It never applies to natural persons or to PERSONAL_TYPES.
6. When there is at least one prior case, one line appears on the entity and in the summary (e.g. 'seen in 3 previous cases, last 2026-11-20, verdict: malicious'), shown first among internal sightings (A12).
7. The retention purge (A10) removes a case's index rows immediately.
8. Explicit tests for TLP leakage (RED never surfaces; higher AMBER is counted only) and for noise exclusion.

Chair rationale: Approved 6-0 at median P2 (cti_lead, osint_investigator and analyst_ux voted P1). legal_dpo's floor keeps it from becoming a watchlist: IOC types by default, personal identifiers only as a keyed HMAC and only when enabled with a purpose, the recurrent rule never on persons. That is why osint_investigator's 'same PIX key/phone' recurrence is not adopted; pix_key can be a CPF or phone. The architect's floor: migration-backed index, TLP <= own case, explicit leakage tests. redteam_lead: RED and engagement cases never surface in exports. analyst_ux and cti_lead: noise and own-asset exclusion, the one-line display.

Synthesizer conditions (background; the final conditions win on conflict): Index normalised entities per case at save time; enrichment attribute 'seen in N previous cases (ids, dates, verdicts)' respecting case TLP/access (no findings copied across cases); correlation rule 'recurrent infrastructure' when the same IOC appears in >= 2 cases; offline (TLP:RED OK).
Notes: Zero-cost 'seen before' answer even without a TIP.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0737 V3LUM case database cross-case sightings (core/store.py) - V3LUM core
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: []); passive: True; touches_target: False
- endpoint: local SQLite ~/.v3lum/v3lum.db (entities x cases index)
- method: local
- inputs: ['ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'username', 'cnpj', 'btc_address', 'keyword']
- outputs: Previous cases (id, date, analyst verdict, risk) in which the same normalised entity appeared, with the feedback verdicts given then.
- auth: none
- rate limit: n/a (local)
- terms / licence: V3LUM code.
- risk: Respect case access rules (a TLP:RED case must not leak into a lower-TLP report); show case ids, not other cases' findings, unless the analyst opens them.
- implementation notes: Index normalised entity values per case at save time; a 'seen in N previous cases' attribute feeds correlation (recurrent infrastructure) and the feedback loop (earlier analyst verdicts).
- sample: <scratch>/research/samples/gaps__internal_tip.json (valid_json)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/gaps__internal_tip.json

## P376 `egress_profiles` - Per-opsec egress profiles and hostile-host contact guard

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: url, domain, ipv4; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/http.py

### Final conditions (binding spec - implement every item)

1. Settings: proxy (the default route: third-party APIs and DoH), proxy_light and proxy_active. HttpClient and a core socket connector pick the session per request from module opsec and case tags; modules never choose proxies. Third-party API calls always stay on the default route.
2. Non-default profiles get their own requests.Session with trust_env=False (no environment proxies, NO_PROXY bypass or ~/.netrc credentials) and explicit proxies. Names are resolved through the profile (socks5h via optional PySocks, or DoH through that proxy), and a test asserts no local getaddrinfo for target hosts.
3. Fail closed: when a configured LIGHT/ACTIVE profile's proxy is down, the request is blocked and never sent through the default/corporate route. Tor is allowed for LIGHT reads only, never as proxy_active. The research VPN/proxy is a contracted provider, because it sees target URLs.
4. Raw-socket work (TLS handshake, JARM, port scan, AXFR, websocket) obtains sockets only from the core connector applying the profile. The lint fails direct socket use in modules.
5. Two-phase scheduling per entity in Engine: LIGHT/ACTIVE modules for an entity are submitted from _absorb only after its passive results (TI and archive lookups included) are absorbed and the guard has been evaluated.
6. Guard, on by default on every path including `v3lum run`: LIGHT/ACTIVE contact, redirect targets included, with an entity tagged malicious/phishing/c2/suspicious (in the case or in case-DB sightings), or listed by a consensus source, gives BLOCKED reason_code 'hostile_host' ('needs non-corporate egress').
7. The guard treats hostile-shaped entities the same way: org-brand lookalikes, domains <= 30 days old, lure-word domains, and URLs/domains extracted from text or e-mail inputs.
8. The guard yields only when proxy_light/proxy_active is configured or --egress-override "<reason>" is passed. The override is recorded in the case audit and the report banner.
9. The refusal message gives the reason, passive alternatives (urlscan search results, archived copies, sandbox reports), the config command for proxy_light and the override syntax. The refused contact becomes a manual pivot.
10. URLs with probable per-recipient tokens (an org_profile e-mail in plain, URL-encoded or base64 form, or opaque tokens of >= 16 chars in path/query) are never fetched automatically and need a per-URL confirmation (A7 BR15).
11. Each evidence file and ledger entry records the egress profile, and the public IP when known. `v3lum doctor --egress` shows each profile's public IP on request via a benign echo service. The report header shows the egress used, and `links --open` on a flagged host shows the contact warning.
12. Egress profiles serve opsec separation only, never quota evasion: P334 budgets are global regardless of egress. FakeHttp tests assert profile selection, fail-closed behaviour and refusals.

Chair rationale: Approved 6-0 at median P1; redteam_lead called it the most important opsec control of the build. All members require the guard to decide after the entity's passive results, which the pipelined engine does not do today, hence two-phase scheduling. redteam_lead: fail-closed sessions, trust_env=False, DNS through the profile, the socket factory. The architect's floor: the core picks profiles, the lint on sockets, no Tor for ACTIVE, IPs only on request. legal_dpo's floor: third-party APIs on the default route, a contracted VPN, never quota evasion, recorded overrides. osint_investigator: hostile-shaped heuristics, victim tokens, manual-pivot fallback. analyst_ux: the explanatory refusal and the override flag.

Synthesizer conditions (background; the final conditions win on conflict): Config proxy (third-party APIs), proxy_light and proxy_active (research VPN or socks5h Tor via PySocks; DNS through the proxy); core/http.py picks the session per request from module opsec and entity tags; a LIGHT/ACTIVE request to a host tagged malicious/phishing/c2 is refused (status blocked, reason 'needs non-corporate egress') unless a non-corporate profile is configured; each evidence file records the egress profile used; `v3lum doctor` shows the public IP of each profile.
Notes: Contacting attacker infrastructure from the corporate IP reveals the investigation.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0774 Per-opsec egress profiles (proxy_light / proxy_active / Tor socks5h via PySocks) + guard against LIGHT contact with malicious-tagged hosts from the corporate egress - V3LUM core
- kind: offline_lib_or_algorithm; status: unverified (HTTP seen: [200]); passive: True; touches_target: False
- endpoint: config: proxy (passive APIs), proxy_light, proxy_active, tor_socks (socks5h://127.0.0.1:9050) ; pip PySocks 1.7.1 (BSD)
- method: local
- inputs: ['url', 'domain', 'ipv4']
- outputs: Per-request choice of egress by opsec level and target reputation; refusal (blocked status) when a LIGHT/ACTIVE request would reach a malicious-tagged host through the corporate egress.
- auth: none
- rate limit: n/a (local)
- terms / licence: V3LUM code; PySocks BSD.
- risk: Tor exits are blocked by many sites and leak nothing about the team but may violate some providers' terms; DNS must go through the proxy (socks5h) to avoid leaks.
- implementation notes: core/http.py selects the session by module opsec + entity tags (malicious/phishing/c2 from earlier results); third-party APIs keep the normal proxy; report records which egress was used per request (evidence).
- sample: <scratch>/research/samples/gaps__hostile_url_handling.json (valid_json)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/gaps__hostile_url_handling.json

## P377 `licence_profile` - Licence profile (corporate | research) enforced per source + `v3lum doctor --licences` coverage report

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: -
- upgrades existing module: core/module.py terms + policy_as_code

### Final conditions (binding spec - implement every item)

1. Per-source terms live in the provider registry (providers.<id>.sources.<source>.terms: class, evidence_url, quote, checked_at, reviewer, free_plan_business_use). A CI test checks that every module and every feed of aggregator modules (P149, P071, P159) has an entry, and that Module.terms equals the most restrictive source class.
2. Module.terms defaults to 'unknown' (fail closed). shodan_internetdb is relabelled 'noncommercial' now, with its tests updated, because it is the template others copy. App.doctor stops calling internetdb.shodan.io under corporate.
3. Setting licence_profile = corporate (default) | research. Corporate allows open sources; key-terms only with free_plan_business_use=true or key_plans.<key>='business'; noncommercial/license only with an active licence_allow entry; unknown never (A1).
4. research is allowed only when a research_basis records a legal basis (provider grant or written permission). It is selected by config or --licence-profile research and recorded in case metadata. Every report then carries a banner listing the NC/license sources actually used, research cases are never pushed (P303), and unknown-terms sources stay disabled in every profile.
5. The licence_allow file (licence_allow_path, 0600) holds entries {source_id, basis, scope, legal_ref, approver, decided_at, review_by <= 12 months, evidence_url, quote}. Expired entries are inactive (doctor warns 30 days ahead). Active entries are shown in `v3lum info` and in the report coverage section.
6. Enforcement happens only in core/policy.py (P327), for scan, run, shell, watch and doctor. Blocked sources are SKIPPED with reason_code 'licence'. Aggregators receive ctx.allowed_sources and report their blocked feeds. A blocked source is never replaced by an automatic LIGHT/ACTIVE alternative, and its manual pivot link is emitted where the web UI allows manual use.
7. Initial classes (A1): abuse.ch MalwareBazaar/URLhaus/ThreatFox = 'license' (terms 2026-10-21 s.4.1) until a subscription or written decision; YARAify, Feodo Tracker and SSLBL = 'open' (CC0, s.3.4); Shodan InternetDB, VirusTotal public and Censys free = 'noncommercial'.
8. The terminal prints one line (e.g. '12 sources skipped by licence profile corporate - v3lum doctor --licences'). The HTML/MD appendix 'Coverage lost under licence profile' lists the sources per entity type.
9. `v3lum doctor --licences` runs offline from metadata. It prints per-entity-type coverage before and after; the unknown-terms review queue ranked by coverage impact, with reviewer and date stored; and attack-surface coverage lost (ports/services, CVEs, subdomains) with the licensed alternative.
10. doctor --licences also prints the budget list: HIBP Core, Google Web Risk, ransomware.live PRO, a Spamhaus/abuse.ch subscription, xonAPI+, a commercial Shodan/Censys/Netlas tier and the OpenSanctions business licence.
11. `doctor --licences --refresh` re-fetches terms pages last checked more than 30 days ago (meant to run monthly; doctor reminds when a check is overdue) and flags changed pages for re-review. It never enables or disables a source automatically.

Chair rationale: Approved 6-0 at median P1; a phase-0 item implementing A1. legal_dpo's floor: corporate default, research only with a recorded legal basis, key-terms only with a business plan, the abuse.ch split, the InternetDB relabel, monthly terms re-checks, allow-list entries with scope and a 12-month review. The architect's floor: per-source data plus one gate, a CI test per feed, the reference module fixed. cti_lead, osint_investigator, redteam_lead and analyst_ux made the loss visible and recoverable: the review queue, manual-link fallback, no LIGHT/ACTIVE substitution, a one-line terminal summary.

Synthesizer conditions (background; the final conditions win on conflict): Add per-SOURCE terms (not only Module.terms: aggregators like P149/P071/P159 mix open and non-commercial feeds) in data/source_terms.json with evidence URL/quote/date; config licence_profile=corporate|research (default corporate for this team); corporate allows 'open', 'key-terms' only with a configured key flagged as business plan, and per-source legal allow-list entries (e.g. ISC 'protect your own network', abuse.ch not-for-profit decision); disables 'noncommercial', 'license' without a recorded licence and 'unknown' until reviewed; the report gains 'Coverage lost under licence profile' and `v3lum doctor --licences` prints per-entity-type coverage before/after and the licences to budget (HIBP Core from US$4.39/month, Google Web Risk, ransomware.live PRO key (free), Spamhaus DQS commercial, xonAPI+ from US$9/month).
Notes: Decides what actually runs in production for an internal corporate team (e.g. ipv4 keyless modules 31 -> 19, sha256 9 -> 5).

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0728 Licence/terms run profile (licence_profile = corporate | research) with per-source terms registry and `v3lum doctor --licences` - V3LUM core (extends policy_as_code P327)
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: [200, 403]); passive: True; touches_target: False
- endpoint: local: v3lum/data/source_terms.json + config 'licence_profile' + `v3lum doctor --licences` (evidence pages: docs.virustotal.com/reference/public-vs-premium-api, developers.google.com/safe-browsing, www.ransomware.live/api, www.spamhaus.org/blocklists/dnsbl-fair-use-policy/, abuse.ch/terms-of-use/, isc.sans.edu/api/, www.team-cymru.com/mhr, malpedia.caad.fkie.fraunhofer.de/usage/tos, www.opensanctions.org/licensing/, xposedornot.com/api_doc, haveibeenpwned.com/TermsOfUse)
- method: local
- inputs: ['text_blob']
- outputs: Per-SOURCE terms record (open / noncommercial / license / key-terms / unknown, evidence URL + quote, date checked, legal decision, licence id/expiry when bought), profile filter result (sources and modules disabled), per-entity-type coverage table before/after filtering (keyless vs keyed), list of cheap licences that would restore coverage.
- auth: none
- rate limit: n/a (local); terms pages re-checked by `v3lum doctor --licences` at most monthly
- terms / licence: Evidence quotes captured 2026-11-25: VT public API 'must not be used in commercial products or services ... business workflows that do not contribute new files'; Safe Browsing v4 'for non-commercial use only; commercial users should refer to the Web Risk API' (v4 deprecated, v5 also non-commercial); ransomware.live free API 'not intended for corporate or business use' (API PRO is free with a key); Spamhaus public mirror 'free of charge for non-commercial use by small and medium sized organisations'; abuse.ch platforms free for 'not-for-profit purposes' within volume limits (Feodo/SSLBL/YARAify free without limitation); SANS ISC 'ok to use this data for commercial purposes, for example to protect your own company's network ... do not resell' (formal licence CC BY-NC-SA 4.0); Team Cymru MHR 'free for non-commercial use'; Malpedia content CC BY-NC-SA 3.0; OpenSanctions CC BY-NC (commercial licence); XON free API 'for personal and low-volume use', xonAPI+ from US$9/month; HIBP unauthenticated catalogue endpoints usable 'for any lawful purpose, including within commercial products'.
- risk: Module.terms is per module but several modules aggregate feeds with different terms (P149 ip_blocklists mixes Spamhaus DROP (open) with blocklist.de/CINS/ET/GreenSnow (NC); P071, P159 likewise): the profile must filter per source. 'unknown' terms count as disabled in the corporate profile until legal records a decision (Hudson Rock, LeakCheck, Filescan, MalwareIntel, SecurityContext, VirusShare lists, ViriBack, binlist/data).
- implementation notes: Coverage computed offline from proposals.json (P001-P341): 249 approved automated proposals = 149 open, 51 key-terms, 20 unknown, 15 noncommercial, 14 license. Corporate keyless coverage drops: ipv4 31 -> 19 keyless modules, md5/sha1 8 -> 5, sha256 9 -> 5, threat_actor 13 -> 7, malware_family 7 -> 3, mitre_technique 4 -> 2, email 14 -> 10 (see gaps__licence_profile_coverage.json). Implementation: source_terms.json keyed by source id (catalog C####/host), loaded by policy_as_code; profile 'corporate' = allow open + key-terms with business plan flag + per-source legal allow-list (e.g. ISC 'protect own network'); report section 'Coverage lost under licence profile' listing disabled sources per entity type; `v3lum doctor --licences` prints the table and the licences to budget (HIBP Core, Web Risk, ransomware.live PRO key, Spamhaus DQS, xonAPI+).
- sample: <scratch>/research/samples/gaps__licence_profile.json (valid_json)
- sample: <scratch>/research/samples/gaps__licence_profile_coverage.json (valid_json)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/gaps__licence_profile.json
- <scratch>/research/samples/gaps__licence_profile_coverage.json

## P378 `org_profile` - Organisation profile (own domains, brands, CNPJ roots, ASNs/CIDRs, app ids) with auto-seeding and own-asset tagging

- council: **approved**, priority P1, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: domain, cnpj, asn, cidr, company_name, keyword; produces: domain, cidr, asn, cnpj
- auth: none; key env vars: -; hosts: ftp.registro.br, stat.ripe.net
- upgrades existing module: config.py

### Final conditions (binding spec - implement every item)

1. The profile is org_profile.toml (tomllib) or JSON at setting org_profile_path (default ~/.v3lum/org_profile.toml; a team-maintained read-only path is allowed). It is 0600 in a 0700 home and schema-validated with clear errors. PyYAML is only an optional extra, used with safe_load.
2. Entries: domains (verification seeded | confirmed | txt_verified | attested {by, date}); brands (accent-folded and IDN/homoglyph variants); cnpj_roots; card_bins (own card BIN prefixes, used by P357); asns; cidrs; app_ids (e.g. M365 tenant); favicon hashes; suppliers.
3. Also: executives (explicit opt-in only, informed under the VIP-protection programme); criticality per entry (critical|high|medium|low); a third_party_hosted flag.
4. Membership uses the PSL registrable domain plus a subdomain match, and ipaddress containment; never string suffix matching. Tests cover subdomains, IDN and IPv6.
5. Own-asset-only modules (run_on='own_assets_only': HIBP/XON domain search, stealer domain searches, IntelX phonebook, Hunter domain search) require a txt_verified entry (DNS TXT 'v3lum-verify=<token>') or an attested entry (name and date) and refuse anything else: SKIPPED with reason_code 'own_asset'. Without a profile they print one hint line.
6. Per-person breach/infostealer modules (run_on='own_assets', A4) treat an address as own only when its domain entry is txt_verified or attested; seeded or merely confirmed entries do not unlock them (legal floor, A11 BR4).
7. The profile is never exported or sent out: reports, STIX/MISP and case JSON carry only own_asset/third_party tags and the profile SHA-256 (case metadata). Watch and typosquat matching are local.
8. Commands: `v3lum org show|check|seed|verify`. `seed` proposes entries from passive sources (registro.br RDAP publicIds CNPJ, NIC.br ASN list, RIPEstat announced prefixes, M365 tenant domains, CT SAN affiliates, BCB/gov.br lists) as a normal passive scan through the policy gate, never LIGHT/ACTIVE. Every entry needs analyst confirmation, and nothing is auto-trusted.
9. The ACTIVE scope never defaults from the profile. `v3lum scope draft --from-org` writes a draft scope file that the analyst confirms and binds to the authorization reference (A7). third_party_hosted entries (CDN, cloud front doors, SaaS, detected by ASN/warninglists) are excluded from ACTIVE network probes unless the scope lists them.
10. Findings are tagged own_asset or third_party, and reports list 'your assets' findings first in their own section. own_asset tags drive the severity rules of P027, P028, P084, P146 and P291, and criticality feeds P302.
11. Profile changes are logged in the audit trail. 'LinkedIn X-ray' exists only as manual links or through an official API, never as automated search-engine scraping.

Chair rationale: Approved 6-0 at median P1; several approved conditions (own-domain-only endpoints, scope files, brand watch, ownership-dependent severity) cannot be enforced without it. legal_dpo's floor: a sensitive inventory that is 0600 and never exported, verification before people-data modules unlock, executives only with notice, changes audited, no LinkedIn scraping. The architect's floor: TOML/JSON, schema validation, PSL/ipaddress membership, seeding through the policy gate. redteam_lead: the profile informs but never becomes the active scope (stricter than the draft, consistent with legal_dpo's mandatory --scope). osint_investigator, cti_lead and analyst_ux: brand variants, criticality, the team-shared file, a single hint line.

Synthesizer conditions (background; the final conditions win on conflict): ~/.v3lum/org_profile.yaml (0600) loaded by config and enforced by policy_as_code: own-domain-only modules (HIBP/XON domain search, IntelX phonebook, Hunter domain-search, LinkedIn X-ray) refuse domains not in the verified profile; active mode scope file defaults to profile CIDRs/domains; watch mode uses brand keywords; `v3lum org seed` proposes entries from NIC.br ASN list, RIPEstat announced-prefixes, M365 tenant domains, CT SAN affiliates, registro.br RDAP CNPJ and BCB/gov.br lists for analyst confirmation (never auto-trusted); findings tagged own_asset/third_party with separate report sections; executives only by explicit opt-in.
Notes: Several approved conditions (own domains only, scope files, brand watch) cannot be enforced without it.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0746 Organisation profile (org_profile.yaml: own domains, brand keywords, CNPJ roots, ASNs/CIDRs, app ids, optional executives) with auto-seeding - V3LUM core
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: [200, 206]); passive: True; touches_target: False
- endpoint: local ~/.v3lum/org_profile.yaml ; seeding from https://ftp.registro.br/pub/numeracao/origin/nicbr-asn-blk-latest.txt (ASN -> CNPJ -> prefixes), https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{n}, M365 tenant related domains (P011), CT SAN affiliates (P001), registro.br RDAP CNPJ, gov.br/BCB official domain lists
- method: local
- inputs: ['domain', 'cnpj', 'asn', 'cidr', 'company_name', 'keyword']
- outputs: Verified own-asset inventory used to tag findings own_asset / third_party, enforce own-domain-only conditions and feed brand/ASM watch modules.
- auth: none
- rate limit: Seeding is occasional (on demand); the profile itself never leaves the machine.
- terms / licence: V3LUM code; seed sources open.
- risk: The profile is sensitive (asset inventory, executive names): file mode 0600, never exported in reports; executives only by explicit opt-in.
- implementation notes: Seeds are proposals the analyst confirms (never auto-trusted): e.g. NIC.br list gives ASN|owner|CNPJ|prefixes (AS1251 FAPESP 43.828.151/0001-45 ...), RIPEstat announced-prefixes AS15169 -> 1,453 prefixes; policy_as_code checks own-domain-only modules (HIBP/XON domain search, IntelX phonebook, Hunter domain-search, LinkedIn X-ray) against verified profile entries.
- sample: <scratch>/research/samples/gaps__org_profile.json (valid_json)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/gaps__org_profile.json

## P379 `keys_setup_wizard` - First-run key setup wizard (`v3lum keys setup`): free keys ranked by coverage gained

- council: **approved**, priority P2, default_enabled=True, provider_tier=n/a, terms=n/a, opsec=passive, shares_input=False
- category: utility; group: G15; inputs: text_blob; produces: 
- auth: none; key env vars: -; hosts: auth.abuse.ch, mb-api.abuse.ch, threatfox-api.abuse.ch, urlhaus-api.abuse.ch
- upgrades existing module: v3lum keys

### Final conditions (binding spec - implement every item)

1. `v3lum keys setup` content is generated from REGISTRY (requires_keys/optional_keys, coverage gained per entity type) and from the provider registry (licence class, tier, free_plan_business_use), never from a hand-maintained list.
2. Keys are ranked by coverage gained under the active licence profile. Each step says what the key unlocks and the provider's terms in plain words. VirusTotal public and Censys free are not offered under corporate.
3. Under corporate, keys of noncommercial/license providers are shown as 'requires licence/legal decision'. A key alone never enables their modules; only an active licence_allow entry or recorded licence does (A1 BR4).
4. abuse.ch is presented per its 2026-10-21 terms: MalwareBazaar, URLhaus and ThreatFox are license-class (a subscription may be required, s.4.1); YARAify, Feodo Tracker and SSLBL are open (CC0, s.3.4).
5. The wizard offers the free Brazilian Portal da Transparencia API key (P237: CEIS/CNEP/CEPIM, contracts) next to OTX, GreyNoise community, AbuseIPDB, urlscan (search only), ransomware.live PRO and the GitHub token.
6. The wizard records each key's plan (business | free) in key_plans (A1). Every step can be skipped (Enter) and the wizard can be resumed.
7. Sign-up URLs are only shown or opened; there is no automated sign-up. Accounts are created by hand under the corporate identity by an employee authorised to accept the provider's terms, one account per provider unless its terms allow more; never multiple free accounts or shared personal accounts.
8. Keys are entered with hidden input (getpass), stored 0600, displayed masked, and never printed or logged. Key values are registered with the central redactor (AR01), so URLs that embed keys (abuse.ch v2 exports) never reach cache rows, the live feed, errors, evidence or reports. Unit test with a fake key in a query string and in a path.
9. One benign test call per key runs through the module's health_check (P337), counted in quotas, and reports ok / invalid / quota. `v3lum keys test` re-checks all keys non-interactively.
10. The first scan with no keys configured prints one hint line.

Chair rationale: Approved 6-0 at median P2 (cti_lead and analyst_ux voted P1); it is a release must-have (A16). legal_dpo's floor: the licence class decides what is offered, NC/license keys leave their modules disabled under corporate, abuse.ch per its current terms, accounts opened by authorised employees, one per provider. The architect's floor: generated from metadata, getpass/0600, tests via health_check, central redaction. osint_investigator added the Portal da Transparencia key, redteam_lead redaction across all sinks, analyst_ux skippable steps, `keys test` and the first-scan hint.

Synthesizer conditions (background; the final conditions win on conflict): Interactive CLI listing free keys with what each unlocks (abuse.ch Auth-Key first: MalwareBazaar, ThreatFox, URLhaus, v2 exports, CSCB), sign-up URL opened for the analyst (no automated sign-ups), one benign test call per key (EICAR hash / example.com), storage in the 0600 keys file, licence-profile warning for keys whose free plan is non-commercial (VirusTotal public, Censys free); keys never printed or written to evidence (abuse.ch export URLs embed the key: redact).
Notes: Without keys hash enrichment mostly answers 'unknown'; one Auth-Key restores most abuse.ch coverage.

### Sources (research records, verified 2026-11-25/26 from a datacenter egress)

#### C0732 First-run key setup wizard (`v3lum keys setup`) for the free keys that unlock most coverage (abuse.ch Auth-Key first) - V3LUM core
- kind: offline_lib_or_algorithm; status: verified_live (HTTP seen: [200, 401, 410]); passive: True; touches_target: False
- endpoint: local CLI ; sign-up page https://auth.abuse.ch/ (X / Google / LinkedIn / GitHub / e-mail link login) ; test calls POST https://mb-api.abuse.ch/api/v1/ (Auth-Key header)
- method: local
- inputs: ['text_blob']
- outputs: Guided list of free keys with what each unlocks, sign-up URL, test call and storage in the 0600 keys file; abuse.ch: one Auth-Key for MalwareBazaar get_info, ThreatFox search_hash, URLhaus payload/url and the v2 file exports.
- auth: none
- rate limit: n/a (local); each test call costs one request of the provider quota
- terms / licence: abuse.ch terms: platforms free for not-for-profit purposes within query/export volume limits, continued excessive use may require a paid (Spamhaus) subscription; Feodo Tracker, SSL Blacklist and YARAify free without limitation.
- risk: The analyst creates the accounts personally (no automated sign-up, no shared team accounts unless the provider allows them); keys never logged or put in URLs that reach evidence files (abuse.ch v2 export URLs embed the key in the path).
- implementation notes: Keyless tests 2026-11-25: MalwareBazaar get_info, ThreatFox search_hash, URLhaus payload -> 401 'Unauthorized'; legacy bazaar exports -> 410 ('Since 21 October 2026, abuse.ch file exports need an Auth-Key'); YARAify lookup_hash still answered keyless. Wizard order by coverage gained per minute: abuse.ch, OTX, GreyNoise community, Hybrid Analysis, Triage, MetaDefender, Pulsedive, URLscan, VirusTotal (only if licensing allows).
- sample: <scratch>/research/samples/gaps__hash_verdicts.json (valid_json)

### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)

- <scratch>/research/samples/gaps__hash_verdicts.json

