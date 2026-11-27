"""censys: Censys Platform API v3 host and certificate lookups and seed-only searches (keyed) (P044).

Batch p3-G02-1, proposal P044 (approved, P3). Final conditions implemented here:

* c1 - Platform API v3 only (``api.platform.censys.io``). The legacy Search API was decommissioned on
  2026-09-30: :func:`censys_url` never builds a ``search.censys.io`` URL, and the legacy 'decommissioned'
  403 body maps to ERROR with a clear message (provider marker ``censys_legacy_decommissioned``).
* c2 - Bearer personal access token plus the organization id. P044 asks for two registered keys,
  ``censys_pat`` and ``censys_org``. A provider extension cannot declare keys and the registry allows one
  key per provider, so the PAT is the registered key ``censys`` (config.KNOWN_KEYS, 'Censys Platform API
  token'; ``V3LUM_KEY_CENSYS`` / ``CENSYS_API_KEY``). The organization id is the module setting
  ``censys_organization_id``, sent as the ``organization_id`` query parameter (official SDK) and
  registered with the central redactor before every request, so it is masked like a key value in URLs,
  logs, cache rows and evidence. The core request is in docs/backlog/p3-G02-1.md.
* c3 - terms: the free tier is non-commercial research (source ``censys.censys_platform_free``,
  noncommercial). A commercial company plan is key-terms (source ``censys.censys_platform_commercial``,
  needs ``key_plans.censys='business'``). Under the corporate profile the gate therefore lets the module
  run only with a recorded commercial plan or a licence_allow entry, and the module names the source the
  gate allowed on every request.
* c4 - lookup and search endpoints only (:data:`ENDPOINTS`). Rescan, scans, live discovery, CensEye
  and investigation jobs, uploads and collection writes cannot be built (they make Censys probe the
  target or write to the account).
* c5 - certificate fingerprints are pivots with expand=False. The SANs follow the P001 shared-certificate
  rule (:func:`v3lum.modules.ip_network.scan_engines.cert_sharing`): a shared certificate gives the
  ``shared_cert`` attribute and no SAN pivot. Names outside the queried apex are expand=False, which for
  IP and certificate seeds means every name.
* c6 - budget: the provider has no quota block (the company plan's credits are not recorded yet).
  ``daily_quota`` is the fallback, and searches run only for analyst-typed seeds. The web UIs block
  automation, so ``platform.censys.io/hosts/{ip}`` is a manual link only.
* c7 - merge gate: the success fixtures are documentation-shaped from the official SDK models (no
  company-plan capture exists). The recorded 401 and legacy 403 fixtures are real.

Vulnerabilities: a CVE counts as verified (``vulns_verified``) only when Censys itself reports it with
evidence (``source == 'censys'``). Every other CVE is version-inferred (``vulns``): one finding, POSSIBLE,
capped at HIGH (P291).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from v3lum.config import SettingSpec
from v3lum.core import redact
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.scan_engines import (
    ABSENT,
    SHA256_RE,
    VERSION_INFERRED_CRITERION,
    EndpointRefused,
    apex_of,
    as_dict,
    as_list,
    cert_sharing,
    cn_from_dn,
    cve_id,
    fetch_json,
    in_apex,
    integer,
    json_cache_veto,
    normalize_domain,
    normalize_ip,
    number,
    org_from_dn,
    port,
    public_ip,
    str_list,
    text,
    vuln_severity,
    worst,
)

SOURCE_FREE = "censys.censys_platform_free"  # free tier: noncommercial (c3)
SOURCE_COMMERCIAL = "censys.censys_platform_commercial"  # company plan: key-terms (c3)
KEY = "censys"
ORG_SETTING = "censys_organization_id"
API = "https://api.platform.censys.io"
WEB_HOST = "https://platform.censys.io/hosts/{ip}"
#: c4: op -> (method, path, Accept). Nothing else is ever built.
ENDPOINTS: dict[str, tuple[str, str, str]] = {
    "host": ("GET", "/v3/global/asset/host/{value}", "application/vnd.censys.api.v3.host.v1+json"),
    "certificate": ("GET", "/v3/global/asset/certificate/{value}", "application/vnd.censys.api.v3.certificate.v1+json"),
    "search": ("POST", "/v3/global/search/query", "application/json"),
}
PAGE_SIZE = 25
SEARCH_CAP = 25
NAME_PIVOT_CAP = 20
SAN_PIVOT_CAP = 20
SERVICE_CAP = 50
KEYWORD_RE = re.compile(r"^[\w .:/@-]{3,100}$")


def censys_url(op: str, value: str = "") -> tuple[str, str, str]:
    """(method, url, accept) of one wired Platform v3 endpoint (c1/c4). Raises EndpointRefused for
    rescans, scans, live discovery, CensEye/investigations, uploads, collections and the legacy API."""
    name = str(op or "").strip()
    if name not in ENDPOINTS:
        raise EndpointRefused(f"Censys endpoint {name!r} is never wired: Platform v3 lookup and search only (P044 cond 1 and 4)")
    method, path, accept = ENDPOINTS[name]
    if "{value}" in path:
        if name == "host":
            target = normalize_ip(value)
        else:
            target = text(value, 64).lower()
            target = target if SHA256_RE.match(target) else None
        if not target:
            raise ValueError(f"invalid value for the Censys {name} lookup")
        path = path.format(value=quote(target, safe=":"))
    return method, API + path, accept


def search_query(entity: Entity) -> str:
    """CenQL query of a seed search (c4): the domain's DNS names, or the analyst's keyword."""
    if entity.type is T.DOMAIN:
        name = normalize_domain(entity.value)
        if not name:
            raise ValueError("invalid domain for a Censys search")
        return f'host.dns.names: "{name}"'
    if entity.type is T.KEYWORD:
        kw = " ".join(str(entity.value).split())
        if not KEYWORD_RE.match(kw) or '"' in kw:
            raise ValueError("Censys keyword searches take 3-100 plain characters")
        return f'"{kw}"'
    raise EndpointRefused(f"no Censys search for {entity.type.value}")


# --------------------------------------------------------------------------------------
# parsers (untrusted data)
# --------------------------------------------------------------------------------------


def _resource(data: Any) -> dict[str, Any] | None:
    res = as_dict(as_dict(data).get("result")).get("resource")
    return res if isinstance(res, dict) else None


def parse_cert(cert: Any) -> dict[str, Any] | None:
    cert = as_dict(cert)
    sha = text(cert.get("fingerprint_sha256"), 64).lower()
    if not SHA256_RE.match(sha):
        return None
    parsed = as_dict(cert.get("parsed"))
    validity = as_dict(parsed.get("validity_period"))
    names = [n for n in (normalize_domain(x) for x in as_list(cert.get("names"))) if n]
    subject_cn = cn_from_dn(parsed.get("subject_dn"))
    return {"sha256": sha, "names": names[:500], "subject": subject_cn,
            "issuer": org_from_dn(parsed.get("issuer_dn")) or cn_from_dn(parsed.get("issuer_dn")),
            "not_before": text(validity.get("not_before"), 40), "not_after": text(validity.get("not_after"), 40),
            "sharing": cert_sharing(as_list(cert.get("names")), subject_cn)}


def _vuln(v: Any, svc_port: int | None, product: str) -> dict[str, Any] | None:
    v = as_dict(v)
    cid = cve_id(v.get("id"))
    if not cid:
        return None
    verified = text(v.get("source"), 30).lower() == "censys" and bool(as_list(v.get("evidence")))
    return {"cve": cid, "port": svc_port, "product": product, "severity_label": text(v.get("severity"), 12).lower(),
            "source": text(v.get("source"), 30).lower(), "kev": bool(as_list(v.get("kev"))), "verified": verified,
            "confidence": number(v.get("confidence"))}


def parse_host(data: Any) -> dict[str, Any] | None:
    """GET /v3/global/asset/host/{ip} -> facts; None when the body is not a host asset."""
    res = _resource(data)
    if res is None:
        return None
    out: dict[str, Any] = {"ip": normalize_ip(res.get("ip")) or ""}
    asys = as_dict(res.get("autonomous_system"))
    asn = integer(asys.get("asn"))
    out["asn"] = f"AS{asn}" if asn and asn > 0 else ""
    out["as_org"] = text(asys.get("description"), 160) or text(asys.get("name"), 160)
    out["prefix"] = text(asys.get("bgp_prefix"), 50)
    loc = as_dict(res.get("location"))
    out["country"] = text(loc.get("country_code"), 2).upper()
    out["city"] = text(loc.get("city"), 80)
    whois = as_dict(res.get("whois"))
    network = as_dict(whois.get("network"))
    out["whois_network"] = {k: v for k, v in {"name": text(network.get("name"), 120), "cidrs": str_list(network.get("cidrs"), 10, 50),
                                              "organization": text(as_dict(whois.get("organization")).get("name"), 160)}.items() if v}
    dns = as_dict(res.get("dns"))
    out["names"] = [n for n in (normalize_domain(x) for x in as_list(dns.get("names"))) if n][:100]
    out["rdns"] = [n for n in (normalize_domain(x) for x in as_list(as_dict(dns.get("reverse_dns")).get("names"))) if n][:20]
    out["labels"] = sorted({text(as_dict(lab).get("value"), 60).lower() for lab in as_list(res.get("labels"))} - {""})[:30]
    out["hosting"] = any(as_dict(n).get("hosting") is True for n in as_list(res.get("network")))
    services, ports, products, cpes, vulns, threats, certs, stamps = [], set(), [], [], {}, [], {}, []
    for svc in as_list(res.get("services"))[:SERVICE_CAP]:
        svc = as_dict(svc)
        p = port(svc.get("port"))
        if p is not None:
            ports.add(p)
        proto = text(svc.get("protocol"), 30)
        stamp = text(svc.get("scan_time"), 40)
        if stamp:
            stamps.append(stamp)
        names = []
        for sw in as_list(svc.get("software"))[:10]:
            sw = as_dict(sw)
            label = " ".join(x for x in (text(sw.get("product"), 60), text(sw.get("version"), 40)) if x)
            if label:
                names.append(label)
                if label not in products:
                    products.append(label)
            cpe = text(sw.get("cpe"), 200)
            if cpe.startswith("cpe:") and cpe not in cpes:
                cpes.append(cpe)
        services.append(f"{p or '?'}/{text(svc.get('transport_protocol'), 8) or 'tcp'} {proto or '?'}"
                        + (f" {names[0]}" if names else ""))
        for raw in as_list(svc.get("vulns")):
            v = _vuln(raw, p, names[0] if names else "")
            if v is not None:
                prev = vulns.get(v["cve"])
                if prev is None or (v["verified"] and not prev["verified"]):
                    vulns[v["cve"]] = v
        for raw in as_list(svc.get("threats")):
            raw = as_dict(raw)
            name = text(raw.get("name"), 80) or text(raw.get("id"), 80)
            if name:
                threats.append({"name": name, "port": p, "type": str_list(raw.get("type"), 5, 30), "source": text(raw.get("source"), 30),
                                "confidence": number(raw.get("confidence"))})
        cert = parse_cert(svc.get("cert"))
        if cert is not None:
            cert["port"] = p
            certs.setdefault(cert["sha256"], cert)
    out.update(services=services, ports=sorted(ports), products=products[:50], cpes=cpes[:50], vulns=list(vulns.values()),
               threats=threats[:20], certs=list(certs.values())[:20], last_seen=max(stamps) if stamps else "")
    out["empty"] = not any((services, out["names"], out["rdns"], out["asn"], out["whois_network"], out["labels"]))
    return out


def parse_search(data: Any) -> dict[str, Any] | None:
    """POST /v3/global/search/query -> {total, hosts, certs, web}; None when not a search answer."""
    result = as_dict(data).get("result")
    if not isinstance(result, dict) or not isinstance(result.get("hits"), list):
        return None
    hosts, certs, web = [], [], []
    for hit in result["hits"][:SEARCH_CAP]:
        hit = as_dict(hit)
        host = as_dict(as_dict(hit.get("host_v1")).get("resource"))
        if host:
            ip = normalize_ip(host.get("ip"))
            if ip:
                names = [n for n in (normalize_domain(x) for x in as_list(as_dict(host.get("dns")).get("names"))) if n][:20]
                hosts.append({"ip": ip, "names": names})
        cert = parse_cert(as_dict(hit.get("certificate_v1")).get("resource"))
        if cert is not None:
            certs.append(cert)
        prop = as_dict(as_dict(hit.get("webproperty_v1")).get("resource"))
        hostname = normalize_domain(prop.get("hostname"))
        if hostname:
            web.append({"hostname": hostname, "port": port(prop.get("port"))})
    total = number(result.get("total_hits"))
    return {"total": int(total) if total is not None else len(result["hits"]), "hosts": hosts, "certs": certs, "web": web}


@register
class Censys(Module):
    name = "censys"
    title = "Censys Platform host/certificate lookup"
    description = (
        "Services, software, certificates, DNS names, ASN and Censys-detected threats and vulnerabilities of an IP or a "
        "certificate, and seed-only searches for a domain or a keyword, from the Censys Platform API v3 (keyed)."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.DOMAIN, T.CERT_FP, T.KEYWORD}
    produces = {T.DOMAIN, T.CERT_FP, T.IPV4, T.IPV6}
    reference = "https://docs.censys.com/reference/get-started"
    notice = (
        "Censys free tier is non-commercial research: off under the corporate profile until legal records a commercial "
        "Censys plan (licence_allow or key_plans.censys='business'). Platform API v3 only; rescans and on-demand scans "
        "are never wired. Web UIs are manual links only."
    )
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "censys"
    sources = (SOURCE_FREE, SOURCE_COMMERCIAL)
    hosts = ("api.platform.censys.io",)
    access_model = "free_auth_limited"
    requires_keys = (KEY,)
    absent_statuses = frozenset({404})  # host/certificate lookups: 'no record' (SDK ErrorModel 404)
    max_requests = 2
    expected_latency = 2.0
    timeout = 30.0
    min_interval = 1.0
    daily_quota = 50  # fallback until the company plan's credits are recorded as a quota block (P334)
    cache_ttl = 86400
    max_pivots = 60
    manual_link = WEB_HOST
    default_enabled = True
    settings = {
        ORG_SETTING: SettingSpec("", "Censys organization id of the company plan, sent as organization_id so requests use the company wallet (P044 cond 2); masked like a key"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.IPV4:
            return public_ip(entity.value) is not None
        if entity.type is T.CERT_FP:
            return bool(SHA256_RE.match(str(entity.value).lower()))
        if entity.type in (T.DOMAIN, T.KEYWORD):
            return bool(getattr(ctx, "is_seed", False))  # c6: searches spend credits: analyst-typed seeds only
        return False

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        pat = str(ctx.key(KEY) or "").strip()
        if not pat:
            return res.mark(Status.NEEDS_KEY, "Censys needs the key 'censys' (Platform personal access token)", reason_code="needs_key")
        allowed = set(getattr(ctx, "allowed_sources", ()) or self.sources)
        if SOURCE_COMMERCIAL in allowed and (ctx.key_plan(KEY) == "business" or SOURCE_FREE not in allowed):
            source = SOURCE_COMMERCIAL
        elif SOURCE_FREE in allowed:
            source = SOURCE_FREE
        else:
            return res.mark(Status.SKIPPED, "Censys: no licensed access mode for this run (free tier is noncommercial; a "
                            "commercial plan needs key_plans.censys='business')", reason_code="licence")
        params: dict[str, str] = {}
        org = str(ctx.setting(ORG_SETTING, "") or "").strip()
        if org:
            redact.register_secret(org, label="censys organization id")  # c2: masked like a key value
            params["organization_id"] = org
        headers = {"Authorization": f"Bearer {pat}"}
        if entity.type is T.IPV4:
            return self._host(res, entity, ctx, source, headers, params)
        if entity.type is T.CERT_FP:
            return self._certificate(res, entity, ctx, source, headers, params)
        return self._search(res, entity, ctx, source, headers, params)

    # ---- host ---------------------------------------------------------------------------

    def _host(self, res: ModuleResult, entity: Entity, ctx: Any, source: str, headers: dict[str, str], params: dict[str, str]) -> ModuleResult:
        method, url, accept = censys_url("host", entity.value)
        data = fetch_json(ctx, method, url, source=source, headers={**headers, "Accept": accept}, params=params,
                          absent=self.absent_statuses, ttl=self.cache_ttl,
                          cache_if=json_cache_veto(lambda d: parse_host(d) is not None), provider_label="Censys")
        res.link("Censys host page (manual: the web UI blocks automation)", WEB_HOST.format(ip=entity.value))
        if data is ABSENT:
            return res.mark(Status.EMPTY, f"Censys holds no host record for {entity.value}")
        parsed = parse_host(data)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected Censys host answer: could not verify", reason_code="error")
        res.raw = {"source": source, "host": parsed}
        res.attr("scan_engine_summary", {"provider": "censys", "endpoint": "host", "totals": {"services": len(parsed["services"])}})
        if parsed["empty"]:
            return res.mark(Status.EMPTY, f"Censys holds no service or name for {entity.value}")
        res.attr("asn", parsed["asn"])
        res.attr("as_org", parsed["as_org"])
        res.attr("prefix", parsed["prefix"])
        res.attr("country", parsed["country"])
        res.attr("city", parsed["city"])
        if parsed["whois_network"]:
            res.attr("whois_network", {**parsed["whois_network"], "source": "censys"})
        res.attr("open_ports", parsed["ports"])
        res.attr("services", parsed["services"])
        res.attr("technologies", parsed["products"])
        res.attr("cpes", parsed["cpes"])
        res.attr("tags", parsed["labels"])
        res.attr("rdns", parsed["rdns"])
        res.attr("hostnames", parsed["names"][:50])
        if parsed["hosting"]:
            res.attr("is_hosting", True)
        self._vulns(res, entity, parsed, source)
        self._threats(res, parsed, source)
        for name in parsed["rdns"]:
            res.pivot(T.DOMAIN, name, "reverse_dns", confidence="probable", expand=False,
                      note="PTR name from Censys: listed, not expanded (P044 cond 5: no queried apex for an IP)")
        for name in [n for n in parsed["names"] if n not in parsed["rdns"]][:NAME_PIVOT_CAP]:
            res.pivot(T.DOMAIN, name, "hosted_domain", confidence="possible", expand=False,
                      note="name Censys associates with the address: listed, not expanded (P044 cond 5)")
        shared = []
        for cert in parsed["certs"]:
            res.pivot(T.CERT_FP, cert["sha256"], "serves_certificate", confidence="probable", expand=False,
                      note="certificate served on the host per Censys: listed, not expanded (P044 cond 5)")
            if cert["sharing"]["shared"]:
                shared.append(self._shared_entry(cert))
            else:
                for san in cert["names"][:SAN_PIVOT_CAP]:
                    res.pivot(T.DOMAIN, san, "cert_san", confidence="possible", expand=False)
        res.attr("shared_cert", shared)
        if parsed["certs"]:
            first = parsed["certs"][0]
            res.attr("cert_sha256", first["sha256"])
            res.attr("cert_issuer", first["issuer"])
            res.attr("cert_subject", first["subject"])
            res.attr("cert_not_after", first["not_after"])
        return res

    def _vulns(self, res: ModuleResult, entity: Entity, parsed: dict[str, Any], source: str) -> None:
        verified = [v for v in parsed["vulns"] if v["verified"]]
        inferred = [v for v in parsed["vulns"] if not v["verified"]]
        observed = parsed["last_seen"] or None
        if inferred:
            res.attr("vulns", [v["cve"] for v in inferred][:100])
            severity = worst(vuln_severity(None, v["severity_label"]) for v in inferred)
            products = sorted({v["product"] for v in inferred if v["product"]})
            res.finding(
                "CVE(s) associated with exposed software (version-inferred)",
                severity,
                f"Censys lists {len(inferred)} CVE(s) matched from software versions on {entity.value}"
                f"{' (' + ', '.join(products[:5]) + ')' if products else ''}. Distro backports are not considered: confirm on the host.",
                confidence="possible",
                criterion=VERSION_INFERRED_CRITERION,
                data={"vulns": [{k: v[k] for k in ("cve", "port", "product", "severity_label", "kev", "verified")} for v in inferred[:50]]},
                tags=["vulnerable", "version_inferred"] + (["kev"] if any(v["kev"] for v in inferred) else []),
                source=source,
                observed_last=observed,
            )
        if verified:
            res.attr("vulns_verified", [v["cve"] for v in verified][:50])
            labels = [v["severity_label"] for v in verified]
            severity = "critical" if "critical" in labels else worst(vuln_severity(None, lab) for lab in labels)
            res.finding(
                "Vulnerabilities verified by Censys on the host",
                severity,
                f"Censys reports {len(verified)} vulnerability(ies) with evidence of its own check on {entity.value}: "
                f"{', '.join(v['cve'] for v in verified[:10])}.",
                confidence="probable",
                criterion="vulnerability reported by Censys with evidence (vuln source 'censys'), not a version match: confirm and patch",
                data={"vulns": [{k: v[k] for k in ("cve", "port", "product", "severity_label", "kev", "verified")} for v in verified[:50]]},
                tags=["vulnerable"] + (["kev"] if any(v["kev"] for v in verified) else []),
                source=source,
                observed_last=observed,
                key="verified",
            )

    def _threats(self, res: ModuleResult, parsed: dict[str, Any], source: str) -> None:
        threats = parsed["threats"]
        if not threats:
            return
        res.attr("scan_threats", threats)
        types = {t for th in threats for t in th["type"]}
        res.finding(
            "Threat detected by Censys on a service",
            "high",
            "Censys fingerprints on exposed services: " + ", ".join(f"{t['name']} (port {t['port']})" for t in threats[:5])
            + ". One provider's detection: confirm before acting.",
            confidence="possible",
            criterion="Censys threat fingerprint on a scanned service (one vote, never ground truth)",
            data={"threats": threats},
            tags=(["c2"] if "c2" in types else ["suspicious"]) + ["third_party_verdict"],
            source=source,
            observed_last=parsed["last_seen"] or None,
        )

    @staticmethod
    def _shared_entry(cert: dict[str, Any]) -> dict[str, Any]:
        sharing = cert["sharing"]
        return {"sha256": cert["sha256"], "issuer": cert["issuer"], "not_before": cert["not_before"],
                "san_count": sharing["san_count"], "registrable_domains": sharing["registrable_domains"][:10],
                "reason": sharing["reason"]}

    # ---- certificate ----------------------------------------------------------------------

    def _certificate(self, res: ModuleResult, entity: Entity, ctx: Any, source: str, headers: dict[str, str], params: dict[str, str]) -> ModuleResult:
        method, url, accept = censys_url("certificate", entity.value)
        data = fetch_json(ctx, method, url, source=source, headers={**headers, "Accept": accept}, params=params,
                          absent=self.absent_statuses, ttl=604800,
                          cache_if=json_cache_veto(lambda d: parse_cert(_resource(d)) is not None), provider_label="Censys")
        if data is ABSENT:
            return res.mark(Status.EMPTY, f"Censys holds no certificate {entity.value}")
        cert = parse_cert(_resource(data))
        if cert is None:
            return res.mark(Status.ERROR, "unexpected Censys certificate answer: could not verify", reason_code="error")
        res.raw = {"source": source, "certificate": cert}
        res.attr("cert_issuer", cert["issuer"])
        res.attr("cert_subject", cert["subject"])
        res.attr("cert_not_after", cert["not_after"])
        res.attr("cert_sans", cert["names"][:100])
        if cert["sharing"]["shared"]:
            res.attr("shared_cert", [self._shared_entry(cert)])
            res.finding("Shared (multi-tenant) certificate", "info",
                        f"{cert['sharing']['reason']}: its names are not affiliate evidence and are not pivoted (P001).",
                        confidence="probable", data={"san_count": cert["sharing"]["san_count"]}, source=source)
            return res
        for san in cert["names"][:SAN_PIVOT_CAP]:
            res.pivot(T.DOMAIN, san, "cert_san", confidence="probable", expand=False,
                      note="SAN of the certificate: listed, not expanded (P044 cond 5: no queried apex for a certificate seed)")
        return res

    # ---- seed searches ----------------------------------------------------------------------

    def _search(self, res: ModuleResult, entity: Entity, ctx: Any, source: str, headers: dict[str, str], params: dict[str, str]) -> ModuleResult:
        method, url, accept = censys_url("search")
        query = search_query(entity)
        body = {"query": query, "page_size": PAGE_SIZE}
        data = fetch_json(ctx, method, url, source=source, headers={**headers, "Accept": accept}, params=params, json_body=body,
                          ttl=self.cache_ttl, cache_if=json_cache_veto(lambda d: parse_search(d) is not None), provider_label="Censys")
        parsed = parse_search(data)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected Censys search answer: could not verify", reason_code="error")
        res.raw = {"source": source, "query": query, "search": parsed}
        res.attr("scan_engine_summary", {"provider": "censys", "endpoint": "search", "totals": {"hits": parsed["total"]}})
        if not (parsed["hosts"] or parsed["certs"] or parsed["web"]):
            return res.mark(Status.EMPTY, f"Censys search {query} matched nothing")
        apex = apex_of(entity)
        for host in parsed["hosts"]:
            etype = T.IPV6 if ":" in host["ip"] else T.IPV4
            relation = "resolves_to" if entity.type is T.DOMAIN else "scanner_match"
            res.pivot(etype, host["ip"], relation, confidence="possible", expand=False,
                      note="host matched by a Censys search: a candidate, listed for the analyst (P044 cond 5)")
        for cert in parsed["certs"]:
            res.pivot(T.CERT_FP, cert["sha256"], "has_certificate" if entity.type is T.DOMAIN else "scanner_match",
                      confidence="possible", expand=False, note="certificate matched by a Censys search: listed, not expanded")
            if cert["sharing"]["shared"]:
                continue
            for san in cert["names"][:SAN_PIVOT_CAP]:
                inside = in_apex(san, apex)
                res.pivot(T.DOMAIN, san, "subdomain" if inside else "cert_san", confidence="possible", expand=inside,
                          note="" if inside else "name outside the queried apex: listed, not expanded (P044 cond 5)")
        res.attr("censys_web_properties", parsed["web"][:SEARCH_CAP])
        res.finding("Censys search matches", "info", f"{parsed['total']} hit(s) for {query}; at most {SEARCH_CAP} are listed.",
                    confidence="possible", data={"total": parsed["total"], "hosts": len(parsed["hosts"]), "certificates": len(parsed["certs"])},
                    source=source)
        return res


__all__ = ["Censys", "censys_url", "parse_cert", "parse_host", "parse_search", "search_query"]
