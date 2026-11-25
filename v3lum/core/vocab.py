"""Shared vocabulary: attribute keys, finding tags and relation names.

Modules MUST use these names so correlation rules and reports can cross-reference
results coming from different sources. Add new names here (with a description)
rather than inventing ad-hoc keys inside a module.
"""

from __future__ import annotations

# ----------------------------------------------------------------------------------------
# Attributes: facts about the subject entity, recorded with ModuleResult.attr(key, value).
# Values should be JSON-serializable (str/int/float/bool/list/dict). Dates are ISO-8601.
# ----------------------------------------------------------------------------------------
ATTRIBUTES: dict[str, str] = {
    # generic
    "country": "ISO-3166 alpha-2 country code (e.g. 'BR')",
    "city": "city name",
    "region": "state / region",
    "org": "organization / owner name as reported by the source",
    "first_seen": "ISO date the entity was first observed by the source",
    "last_seen": "ISO date the entity was last observed by the source",
    "created": "creation/registration date (ISO)",
    "updated": "last update date (ISO)",
    "expires": "expiry date (ISO)",
    "malicious": "bool: a reputable source flags it as malicious",
    "suspicious": "bool: flagged as suspicious / low reputation",
    "reputation": "dict {source: verdict/score}",
    "tags": "list of source-provided tags/labels",
    "names": "list of names/aliases associated with the entity",
    # network
    "asn": "autonomous system number, e.g. 'AS15169'",
    "as_org": "AS owner name",
    "isp": "ISP / hosting provider",
    "prefix": "announced prefix (CIDR)",
    "rdns": "reverse DNS hostname(s)",
    "open_ports": "list[int] of open ports",
    "services": "list of service/banner descriptions",
    "cpes": "list of CPE strings",
    "vulns": "list of CVE ids affecting the host/software",
    "hostnames": "list of hostnames seen on the IP",
    "is_tor_exit": "bool",
    "is_proxy": "bool (open proxy / anonymizer)",
    "is_vpn": "bool",
    "is_hosting": "bool (datacenter / hosting range)",
    "is_cdn": "bool (CDN / shared edge)",
    "abuse_contact": "abuse email for the network",
    "blocklists": "list of blocklist names that list the entity",
    # domain / DNS / web
    "registrar": "domain registrar",
    "registrant": "registrant name/organization (if public)",
    "registrant_email": "registrant contact email (if public)",
    "registrant_doc": "registrant document id when public (e.g. masked CPF/CNPJ from registro.br)",
    "nameservers": "list of NS hostnames",
    "mx": "list of MX hostnames",
    "a_records": "list of IPv4 addresses",
    "aaaa_records": "list of IPv6 addresses",
    "txt": "list of TXT records",
    "spf": "SPF record text",
    "dmarc": "DMARC record text",
    "dmarc_policy": "none|quarantine|reject",
    "dnssec": "bool",
    "domain_age_days": "int: days since registration",
    "subdomains": "list of discovered subdomains",
    "http_status": "HTTP status of the homepage",
    "title": "HTML <title>",
    "server": "Server header / software",
    "technologies": "list of detected technologies",
    "waf": "WAF/CDN name if detected",
    "favicon_mmh3": "Shodan-style favicon hash",
    "cert_issuer": "TLS certificate issuer",
    "cert_subject": "TLS certificate subject CN",
    "cert_sans": "list of SANs in the TLS certificate",
    "cert_not_after": "certificate expiry (ISO)",
    "cert_sha256": "certificate SHA-256 fingerprint",
    "analytics_ids": "list of tracking ids (UA-/G-/GTM-/pub-) found on the site",
    "security_headers_missing": "list of missing recommended HTTP security headers",
    "archive_first": "first Wayback snapshot date",
    "archive_count": "number of archived snapshots",
    # email / identity
    "disposable": "bool: disposable/temporary email provider",
    "free_provider": "bool: free webmail provider (gmail, outlook...)",
    "mx_valid": "bool: the email domain accepts mail (MX/A present)",
    "breach_count": "int: number of known breaches containing the entity",
    "breaches": "list of breach names",
    "breach_data_classes": "list of exposed data classes (never the data itself)",
    "infostealer": "bool: entity seen in infostealer logs",
    "gravatar": "bool: has a Gravatar profile/avatar",
    "profiles": "list of {platform, url} public profiles",
    "display_name": "public display name found on a profile",
    "avatar_url": "public avatar URL",
    "bio": "public bio/description",
    "followers": "follower count",
    "location": "self-declared location",
    # phone
    "carrier": "carrier/operator",
    "line_type": "mobile|fixed|voip|toll_free|...",
    "valid": "bool: passes validation for its type",
    "timezone": "list of time zones",
    # company / Brazil
    "legal_name": "registered legal name (razao social)",
    "trade_name": "trade name (nome fantasia)",
    "status": "registration status (e.g. ATIVA/BAIXADA)",
    "cnae": "main economic activity code + description",
    "partners": "list of partner/officer names (QSA)",
    "address": "registered address string",
    "capital": "share capital",
    "opened": "company opening date (ISO)",
    "sanctioned": "bool: appears on a sanctions list",
    "lei": "Legal Entity Identifier",
    # malware / vuln / crypto
    "malware_family": "malware family name(s)",
    "file_type": "file type / magic",
    "file_size": "size in bytes",
    "known_good": "bool: hash in a known-software set (e.g. NSRL)",
    "cvss": "CVSS base score (float)",
    "cvss_vector": "CVSS vector string",
    "epss": "EPSS probability (0-1)",
    "kev": "bool: in CISA Known Exploited Vulnerabilities",
    "exploit_available": "bool: public exploit/PoC exists",
    "balance": "crypto balance (string with unit)",
    "tx_count": "number of transactions",
    "total_received": "total received (string with unit)",
    "ransomware_group": "ransomware group name",
}

# ----------------------------------------------------------------------------------------
# Finding tags: semantic labels used by correlation rules and risk scoring.
# ----------------------------------------------------------------------------------------
TAGS: dict[str, str] = {
    "malicious": "confirmed malicious by a reputable source",
    "suspicious": "suspicious / low reputation",
    "phishing": "phishing infrastructure or lure",
    "malware": "malware sample or distribution",
    "c2": "command-and-control infrastructure",
    "botnet": "botnet-related",
    "spam": "spam source",
    "scanner": "internet scanner / mass exploitation noise",
    "tor": "Tor network related",
    "proxy": "proxy / VPN / anonymizer",
    "breach": "appears in a data breach",
    "infostealer": "appears in infostealer logs",
    "credential_exposure": "credentials or secrets exposed",
    "vulnerable": "affected by known vulnerabilities",
    "kev": "known exploited vulnerability",
    "exploit_available": "public exploit available",
    "exposure": "exposed service / data / admin interface",
    "misconfiguration": "security misconfiguration",
    "weak_email_security": "SPF/DMARC/DKIM weakness enabling spoofing",
    "typosquat": "lookalike / typosquatting domain",
    "newly_registered": "recently registered domain",
    "takeover": "possible subdomain takeover",
    "ransomware": "ransomware related (victim listing, group)",
    "darkweb": "found on dark web sources",
    "sanctions": "on a sanctions list",
    "pep": "politically exposed person",
    "fraud": "fraud indicator",
    "identity": "identity link (same person/org)",
    "account": "public account/profile found",
    "infrastructure": "infrastructure relationship",
    "known_good": "known benign / allow-listed",
    "noise": "common benign infrastructure (low pivot value)",
    "privacy": "personal data: handle with care (LGPD/GDPR)",
    "info": "informational",
}

# ----------------------------------------------------------------------------------------
# Relations used in Pivot(relation=...). Read as: <subject> <relation> <pivot>.
# ----------------------------------------------------------------------------------------
RELATIONS: dict[str, str] = {
    "resolves_to": "domain -> IP (A/AAAA)",
    "reverse_dns": "IP -> hostname (PTR)",
    "hosted_domain": "IP -> domain observed on it (passive DNS/certs)",
    "cname_to": "domain -> canonical name",
    "mx_host": "domain -> mail exchanger",
    "nameserver": "domain -> NS",
    "subdomain": "domain -> subdomain",
    "parent_domain": "subdomain -> registrable domain",
    "email_domain": "email -> its domain",
    "contact_email": "domain/org -> contact email (WHOIS/security.txt/site)",
    "registrant": "domain -> registrant org/person",
    "belongs_to_asn": "IP -> ASN",
    "in_network": "IP -> CIDR",
    "announces": "ASN -> prefix",
    "cert_san": "domain/IP -> name found in a certificate SAN",
    "redirects_to": "URL -> URL",
    "url_host": "URL -> domain/IP",
    "links_to": "page -> external URL/domain",
    "archived_url": "domain -> historical URL",
    "same_analytics": "site -> tracking id / sites sharing it",
    "favicon": "site -> favicon hash",
    "has_account": "username/email -> profile URL or platform handle",
    "same_person": "identity link between person/username/email",
    "uses_username": "email/person -> username",
    "uses_email": "username/person -> email",
    "commit_email": "username -> email seen in public commits",
    "phone_of": "org/person -> phone",
    "partner": "company -> partner/officer (person/company)",
    "company_of": "person/domain -> company",
    "located_at": "entity -> CEP/coordinates/address",
    "drops": "malware hash -> URL/domain/IP contacted or dropped",
    "communicates_with": "malware -> C2",
    "family": "hash -> malware family",
    "attributed_to": "malware/campaign -> threat actor",
    "uses_technique": "actor/malware -> ATT&CK technique",
    "targets": "actor -> sector/country/org",
    "exploits": "actor/malware -> CVE",
    "has_vuln": "host/IP/domain/software -> CVE that affects it",
    "affects": "CVE -> product/CPE",
    "transacted_with": "wallet -> wallet",
    "victim_of": "org/domain -> ransomware group",
    "mentions": "document/text -> entity",
    "extracted_from": "file/text -> IOC",
    "lookalike": "brand domain -> typosquat candidate",
    "related": "generic relationship (use only if nothing else fits)",
}


def is_known_attribute(key: str) -> bool:
    return key in ATTRIBUTES


def is_known_tag(tag: str) -> bool:
    return tag in TAGS


def is_known_relation(rel: str) -> bool:
    return rel in RELATIONS
