"""Microsoft 365 / Entra ID tenant discovery for a domain, from Microsoft's own domain-level endpoints (P011).

Batch p2-G01-2, proposal P011 ``m365_tenant``. Final conditions implemented here (the azmap.dev
adapter of cond 6-7 is the separate module ``m365_tenant_azmap``):

* c1 - first-party, domain-level endpoints only: the OpenID configuration
  (login.microsoftonline.com/{domain}/.well-known/openid-configuration: tenant GUID,
  tenant_region_scope), GetUserRealm with one hard-coded, documented non-existent local part
  (:data:`PROBE_LOCAL_PART`) and the Office ODC federation provider (tenant id).
* c2 - e-mail inputs are reduced to their domain before any request; the only local part ever sent is
  the constant (tests assert both on every request URL).
* c3 - rule 2: no template exists for GetCredentialType, Autodiscover user checks or OneDrive/Teams/login
  oracles; :func:`build_url` builds only the three allow-listed shapes and :func:`url_allowed` refuses
  any URL carrying a user-oracle marker (test-asserted).
* c4 - one OpenID call per registrable seed domain (the registrable domain of the input; repeated
  inputs are HTTP-cache hits), GetUserRealm/ODC only when a tenant exists; HTTP 400 AADSTS90002 and
  NameSpaceType 'Unknown' mean no Entra ID tenant (EMPTY); an unexpected ODC schema is ERROR 'schema
  changed' for that source, never EMPTY.
* c5 - federation AuthURL hosts (ADFS, Okta, Ping, Cloudflare Access...) become the attribute
  ``m365_identity_provider`` and an ``identity_provider`` pivot: pivots never get LIGHT/ACTIVE modules
  (A7: LIGHT runs on analyst-typed seeds only, ACTIVE only inside a scope), and this module never
  contacts them; Microsoft's own STS hosts are recorded, never pivoted.
* c8/c9 - the tenant id feeds the company correlation ``m365_shared_tenant``
  (v3lum/correlations/p2_g01_2.py: 'N domains share Microsoft 365 tenant <name>', PROBABLE, never
  proof of ownership); tenant domains are candidate own assets for ``v3lum org seed`` (analyst
  confirms) and never join an ACTIVE scope. The technique is re-implemented from Microsoft's public
  endpoints (AADInternals/o365chk read as documentation; bbot is AGPL: nothing copied, A6).
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.http import Cancelled, DeadlineExceeded, RequestCapReached
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

PROVIDER = "microsoft_entra"
OPENID_SOURCE = "microsoft_entra.openid"
REALM_SOURCE = "microsoft_entra.getuserrealm"
ODC_SOURCE = "microsoft_entra.odc"

#: P011 c1/c2: the ONLY local part ever sent to GetUserRealm. Documented, fixed, not a mailbox of any
#: organisation, naming neither the analyst's organisation nor V3LUM. Microsoft echoes it in 'Login'
#: and in a federated AuthURL query (dropped).
PROBE_LOCAL_PART = "nonexistent.realm.probe"

OPENID_URL = "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
REALM_URL = "https://login.microsoftonline.com/getuserrealm.srf?login={login}&json=1"  # v3lum-lint: allow LINT-03 -- P011 c1-c2: domain-level realm discovery with the fixed probe local part, never a user oracle
ODC_URL = "https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain={domain}"
#: The three allow-listed endpoint shapes (P011 c1, c3): nothing else can be built.
TEMPLATES = {"openid": OPENID_URL, "getuserrealm": REALM_URL, "odc": ODC_URL}
_ALLOWED = (
    re.compile(r"^https://login\.microsoftonline\.com/(?P<d>[a-z0-9.-]+)/\.well-known/openid-configuration$"),
    re.compile(r"^https://login\.microsoftonline\.com/getuserrealm\.srf\?login=" + re.escape(PROBE_LOCAL_PART) + r"@(?P<d>[a-z0-9.-]+)&json=1$"),
    re.compile(r"^https://odc\.officeapps\.live\.com/odc/v2\.1/federationprovider\?domain=(?P<d>[a-z0-9.-]+)$"),
)
#: Rule 2 (P011 c3): markers of user-level oracles. No template exists for them; a URL carrying one is
#: refused even if someone assembles it by hand. Checked on the endpoint part (the domain is cut out
#: first, so a domain such as myonedrive.example is not refused by mistake).
USER_ORACLE_MARKERS = (
    "getcredentialtype", "autodiscover", "getfederationinformation", "-my.sharepoint.com", "/personal/", "onedrive",
    "teams.microsoft.com", "teams.live.com", "/api/mt/", "oauth2/token", "oauth2/v2.0/token", "oauth2/authorize",
    "oauth2/v2.0/authorize", "/common/login", "login.srf", "outlook.office365.com", "outlook.office.com", "/ews/",
    "activesync", "/rst2.srf", "usernamemixed",
)
#: Microsoft's own STS/identity hosts: a federation AuthURL there is recorded, never an IdP pivot.
MICROSOFT_STS_SUFFIXES = (
    "microsoftonline.com", "microsoftonline-p.com", "microsoftonline.us", "windows.net", "live.com", "microsoft.com",
    "msauth.net", "msftauth.net", "chinacloudapi.cn", "partner.microsoftonline.cn",
)
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
UNMANAGED_NOTE = "federated to a Microsoft STS host: an unmanaged (self-service) or test tenant, no proof that the domain owner set it up"
ODC_SCHEMA_CHANGED = "ODC federationprovider: schema changed"


# ======================================================================================
# URL builders and allow-list (P011 c1-c3)
# ======================================================================================


def seed_domain(entity: Entity) -> str | None:
    """Registrable domain to query for a domain or e-mail input; the e-mail local part is dropped
    first (P011 c2) and a host that is itself a public suffix has no tenant to look up."""
    value = str(entity.value or "").strip().lower()
    if entity.type is T.EMAIL:
        if "@" not in value:
            return None
        value = value.rsplit("@", 1)[1]
    value = value.rstrip(".")
    if not _DOMAIN.match(value):
        return None
    return psl.registrable_domain(value)


def url_allowed(url: Any) -> bool:
    """True only for the three domain-level URL shapes; never a user-level oracle (P011 c1-c3)."""
    if not isinstance(url, str):
        return False
    for pattern in _ALLOWED:
        m = pattern.match(url)
        if m:
            endpoint = (url[: m.start("d")] + url[m.end("d") :]).lower()
            return not any(marker in endpoint for marker in USER_ORACLE_MARKERS)
    return False


def build_url(kind: str, domain: str) -> str:
    """One of the three allowed URLs for a registrable domain; ValueError for anything else."""
    if kind not in TEMPLATES:
        raise ValueError(f"m365_tenant: endpoint {kind!r} is not allowed (domain-level endpoints only)")
    d = str(domain or "").strip().lower()
    if not _DOMAIN.match(d):
        raise ValueError("m365_tenant: a domain name is required")
    url = TEMPLATES[kind].format(domain=d, login=f"{PROBE_LOCAL_PART}@{d}")
    if not url_allowed(url):
        raise ValueError("m365_tenant: the built URL failed the allow-list check")
    return url


# ======================================================================================
# parsers (untrusted answers: never raise, never read an odd answer as 'no tenant')
# ======================================================================================


def _json(content: Any) -> Any:
    if isinstance(content, (dict, list)):
        return content
    try:
        text = content.decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else str(content or "")
        text = text.lstrip("﻿").strip()
        return json.loads(text) if text[:1] in "{[" else None
    except (ValueError, RecursionError):
        return None


def _guid_in(text: Any) -> str | None:
    if not isinstance(text, str):
        return None
    for part in re.split(r"[/?#&=]", text.lower()):
        if _GUID.match(part):
            return part
    return None


def _text(data: dict[str, Any], key: str, limit: int = 200) -> str | None:
    value = data.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()[:limit]
    return None


def parse_openid(status: int, content: Any) -> dict[str, Any]:
    """state 'tenant' (GUID in issuer/endpoints) | 'no_tenant' (HTTP 400 invalid_tenant, AADSTS90002) |
    'error' (HTML, other errors, a document without a tenant id)."""
    out: dict[str, Any] = {"state": "error", "tenant_id": None, "reason": ""}
    data = _json(content)
    if not isinstance(data, dict):
        out["reason"] = "the OpenID configuration is not a JSON object (HTML or error page?)"
        return out
    codes = [c for c in data.get("error_codes", []) if isinstance(c, int) and not isinstance(c, bool)] if isinstance(data.get("error_codes"), list) else []
    if data.get("error") is not None or codes:
        if data.get("error") == "invalid_tenant" or 90002 in codes:
            out.update({"state": "no_tenant", "reason": "AADSTS90002: no Entra ID tenant for the domain", "error_codes": codes})
        else:
            out["reason"] = f"OpenID configuration error {str(data.get('error'))[:60]!r} (codes {codes[:5]})"
        return out
    if status != 200:
        out["reason"] = f"unexpected HTTP {status} with an OpenID document"
        return out
    tid = None
    for key in ("issuer", "token_endpoint", "authorization_endpoint", "device_authorization_endpoint"):
        tid = _guid_in(data.get(key))
        if tid:
            break
    if not tid:
        out["reason"] = "no tenant id in the OpenID configuration (schema changed?)"
        return out
    out.update({
        "state": "tenant",
        "tenant_id": tid,
        "tenant_region_scope": _text(data, "tenant_region_scope", 16),
        "tenant_region_sub_scope": _text(data, "tenant_region_sub_scope", 16),
        "cloud_instance_name": _text(data, "cloud_instance_name", 64),
        "issuer": _text(data, "issuer"),
    })
    return out


def classify_idp(auth_url: Any) -> dict[str, Any] | None:
    """Federation AuthURL -> {host, url, kind, pivot}: the query (it echoes the probe login) is dropped;
    Microsoft STS hosts are recorded with pivot False (P011 c5). Never contacted."""
    if not isinstance(auth_url, str) or not auth_url.strip():
        return None
    try:
        parts = urlsplit(auth_url.strip())
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if parts.scheme not in ("https", "http") or not _DOMAIN.match(host):
        return None
    path = parts.path or "/"
    low = path.lower()
    if any(host == s or host.endswith("." + s) for s in MICROSOFT_STS_SUFFIXES):
        kind = "microsoft_sts"
    elif "/adfs/" in low:
        kind = "adfs"
    elif host.endswith((".okta.com", ".oktapreview.com", ".okta-emea.com", ".okta-gov.com")):
        kind = "okta"
    elif host.endswith((".pingidentity.com", ".pingone.com", ".pingone.eu", ".pingone.asia", ".pingone.ca")) or "/idp/sso.saml2" in low or "/idp/prp.wsf" in low:
        kind = "ping"
    elif host.endswith(".cloudflareaccess.com"):
        kind = "cloudflare_access"
    elif host == "accounts.google.com":
        kind = "google"
    elif "/idp/profile/" in low or "shibboleth" in low:
        kind = "shibboleth"
    else:
        kind = "other"
    return {"host": host, "url": f"{parts.scheme}://{host}{path}"[:300], "kind": kind, "pivot": kind != "microsoft_sts"}


def parse_realm(content: Any, domain: str) -> dict[str, Any]:
    """GetUserRealm answer: state 'managed' | 'federated' | 'no_tenant' (NameSpaceType 'Unknown') | 'error'."""
    out: dict[str, Any] = {"state": "error", "reason": ""}
    data = _json(content)
    if not isinstance(data, dict) or not isinstance(data.get("NameSpaceType"), str):
        out["reason"] = "GetUserRealm answer without NameSpaceType (schema changed?)"
        return out
    ns = data["NameSpaceType"].strip()
    login = data.get("Login")
    out.update({
        "namespace_type": ns[:32],
        "brand": _text(data, "FederationBrandName", 120),
        "domain_name": (_text(data, "DomainName", 253) or "").lower() or None,
        "cloud_instance_name": _text(data, "CloudInstanceName", 64),
        "auth_nforward_type": data["AuthNForwardType"] if isinstance(data.get("AuthNForwardType"), int) and not isinstance(data.get("AuthNForwardType"), bool) else None,
        "login_is_probe": (login.rsplit("@", 1)[0].lower() == PROBE_LOCAL_PART) if isinstance(login, str) and "@" in login else None,
    })
    if ns == "Managed":
        out["state"] = "managed"
    elif ns == "Federated":
        out["state"] = "federated"
        out["idp"] = classify_idp(data.get("AuthURL"))
    elif ns == "Unknown":
        out.update({"state": "no_tenant", "reason": "NameSpaceType Unknown: no Entra ID tenant"})
    else:
        out["reason"] = f"unexpected NameSpaceType {ns[:32]!r}"
    if out.get("domain_name") and out["domain_name"] != domain and out["state"] in ("managed", "federated"):
        out["other_domain"] = out["domain_name"]
    return out


def parse_odc(content: Any) -> dict[str, Any]:
    """ODC federationprovider: state 'tenant' | 'no_tenant' (usual keys, no tenantId) | 'schema_changed'."""
    out: dict[str, Any] = {"state": "schema_changed", "reason": ODC_SCHEMA_CHANGED}
    data = _json(content)
    if not isinstance(data, dict):
        return out
    if not (isinstance(data.get("environment"), str) and isinstance(data.get("endpoint"), list) and isinstance(data.get("authority_host"), str)):
        return out
    out.update({"environment": data["environment"][:32], "authority_host": data["authority_host"][:120], "reason": ""})
    tid = data.get("tenantId")
    if tid is None:
        out["state"] = "no_tenant"
    elif isinstance(tid, str) and _GUID.match(tid.strip().lower()):
        out.update({"state": "tenant", "tenant_id": tid.strip().lower()})
    else:
        out.update({"state": "schema_changed", "reason": f"{ODC_SCHEMA_CHANGED} (tenantId is not a GUID)"})
    return out


def failure(exc: BaseException) -> tuple[Status, str, str]:
    """(status, reason_code, reason) of a failed request: 'could not verify', never an absence (rule 5)."""
    text = str(exc)[:200]
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited", text
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota", text
    if isinstance(exc, Blocked):
        return Status.BLOCKED, getattr(exc, "reason_code", "challenge") or "challenge", text
    if isinstance(exc, AuthRequired):
        return Status.BLOCKED, "challenge", text  # keyless endpoints: a refusal, never 'no tenant'
    return Status.ERROR, "error", text


#: Exceptions that end the whole run (the engine keeps partial results or maps the deadline).
STOP_EXCEPTIONS = (Cancelled, DeadlineExceeded, RequestCapReached)
SOURCE_FAILURES = (HttpError, NetworkError)


@register
class M365Tenant(Module):
    name = "m365_tenant"
    title = "Microsoft 365 / Entra ID tenant"
    description = (
        "Entra ID (Microsoft 365) tenant id, region, managed or federated sign-in, brand name and identity provider of a "
        "domain from Microsoft's own domain-level endpoints (OpenID configuration, GetUserRealm, ODC); never a user check."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.EMAIL}
    produces = {T.DOMAIN, T.ORG}
    tags = {"free"}
    reference = "https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc"
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = PROVIDER
    sources = (OPENID_SOURCE, REALM_SOURCE, ODC_SOURCE)
    hosts = ("login.microsoftonline.com", "odc.officeapps.live.com")
    access_model = "free_noauth_unlimited"
    max_requests = 3
    expected_latency = 1.2
    timeout = 20.0
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = 5
    default_enabled = True
    notice = (
        "Domain-level discovery only: e-mail inputs are reduced to their domain and GetUserRealm is called with the fixed "
        f"non-existent local part '{PROBE_LOCAL_PART}'. User checks (GetCredentialType, Autodiscover, OneDrive/Teams/login "
        "oracles) are never built (rule 2). Identity-provider hosts are recorded and pivoted for passive modules only, never "
        "contacted. A tenant answer is not proof of ownership: unmanaged or test tenants can claim a domain."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return seed_domain(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        domain = seed_domain(entity)
        if domain is None:
            return res.mark("skipped", "no registrable domain to look up", reason_code="not_applicable")
        raw: dict[str, Any] = {"domain": domain}
        res.raw = raw
        # 1. OpenID configuration: one call per registrable domain (P011 c4)
        resp = ctx.http.get(build_url("openid", domain), source=OPENID_SOURCE)
        if resp.status == 400:
            openid = parse_openid(400, resp.content)
            if openid["state"] != "no_tenant":
                ctx.http.check(resp)  # any other 400 is 'could not verify'
                return res.mark("error", f"OpenID configuration: {openid['reason']}: could not verify")
        else:
            ctx.http.check(resp)  # 429, 403, challenges, 5xx raise (rule 5)
            openid = parse_openid(resp.status, resp.content)
        raw["openid"] = {k: v for k, v in openid.items() if k != "issuer"}
        if openid["state"] == "no_tenant":
            res.source_status(OPENID_SOURCE, Status.EMPTY, reason="no Entra ID tenant (AADSTS90002)")
            return res.mark("empty", f"no Microsoft Entra ID tenant for {domain} (AADSTS90002)")
        if openid["state"] != "tenant":
            return res.mark("error", f"{openid['reason']}: could not verify")
        tenant_id = openid["tenant_id"]
        anomalies: list[str] = []
        # 2. GetUserRealm with the fixed probe (only after a tenant was found, P011 c4)
        realm = self._fetch(ctx, res, "getuserrealm", REALM_SOURCE, domain, lambda r: parse_realm(r.content, domain))
        if realm is not None:
            raw["realm"] = dict(realm)
            if realm["state"] == "no_tenant":
                anomalies.append("the OpenID configuration found a tenant but GetUserRealm says NameSpaceType Unknown")
                res.source_status(REALM_SOURCE, Status.EMPTY, reason="NameSpaceType Unknown")
            elif realm["state"] == "error":
                res.source_status(REALM_SOURCE, Status.ERROR, reason=f"{realm['reason']}: could not verify")
            if realm.get("login_is_probe") is False:
                anomalies.append("GetUserRealm echoed a login other than the probe constant")
            if realm.get("other_domain"):
                anomalies.append(f"GetUserRealm answered for {realm['other_domain']}, not {domain}")
        # 3. ODC federation provider (only after a tenant was found, P011 c4)
        odc = self._fetch(ctx, res, "odc", ODC_SOURCE, domain, lambda r: parse_odc(r.content))
        if odc is not None:
            raw["odc"] = odc
            if odc["state"] == "tenant" and odc["tenant_id"] != tenant_id:
                anomalies.append(f"the ODC tenant id {odc['tenant_id']} differs from the OpenID tenant id")
            elif odc["state"] == "no_tenant":
                anomalies.append("ODC returned no tenantId although the OpenID configuration found a tenant")
            elif odc["state"] == "schema_changed":
                # P011 c4: an unexpected ODC schema is ERROR 'schema changed' for that source, never EMPTY
                res.source_status(ODC_SOURCE, Status.ERROR, reason=f"{odc['reason']}: could not verify")
                anomalies.append(odc["reason"])
        self._report(res, domain, openid, realm, odc, anomalies)
        return res

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _fetch(ctx: Any, res: ModuleResult, kind: str, source: str, domain: str, parse: Any) -> dict[str, Any] | None:
        try:
            resp = ctx.http.get(build_url(kind, domain), source=source)
            ctx.http.check(resp)
        except STOP_EXCEPTIONS:
            raise
        except SOURCE_FAILURES as exc:
            status, code, reason = failure(exc)
            res.source_status(source, status, reason_code=code, reason=reason)
            return None
        return parse(resp)

    @staticmethod
    def _report(res: ModuleResult, domain: str, openid: dict[str, Any], realm: dict[str, Any] | None, odc: dict[str, Any] | None,
                anomalies: list[str]) -> None:
        tenant_id = openid["tenant_id"]
        region = openid.get("tenant_region_scope")
        res.attr("m365_tenant_id", tenant_id)
        res.attr("m365_tenant_region", region)
        res.attr("m365_cloud_instance", openid.get("cloud_instance_name"))
        namespace = brand = None
        idp = None
        unmanaged = False
        if realm is not None and realm["state"] in ("managed", "federated"):
            namespace = realm.get("namespace_type")
            brand = realm.get("brand")
            idp = realm.get("idp")
            res.attr("m365_namespace_type", namespace)
            res.attr("m365_brand_name", brand)
            if idp:
                res.attr("m365_identity_provider", {k: idp[k] for k in ("host", "kind", "url")})
                if not idp["pivot"]:
                    unmanaged = True
                    anomalies.append(f"{UNMANAGED_NOTE} (AuthNForwardType {realm.get('auth_nforward_type')})")
        if odc is not None and odc.get("environment"):
            res.attr("m365_odc_environment", odc["environment"])
        res.attr("m365_anomalies", list(dict.fromkeys(anomalies)))
        parts = [f"region {region}" if region else "", namespace or "", f"brand '{brand}'" if brand else ""]
        summary = ", ".join(p for p in parts if p)
        res.finding(
            "Microsoft 365 / Entra ID tenant",
            "info",
            f"{domain} is registered in Entra ID tenant {tenant_id}" + (f" ({summary})" if summary else "") + ". "
            "Domain-level discovery from Microsoft's public endpoints; a tenant is not proof of ownership (unmanaged or test tenants can claim a domain): "
            "the same tenant on several domains is a PROBABLE same-organisation link. Tenant domains are candidate own assets for `v3lum org seed` "
            "(analyst confirms), never an ACTIVE scope.",
            confidence="probable" if not unmanaged else "possible",
            data={"tenant_id": tenant_id, "region": region, "namespace_type": namespace, "brand": brand, "unmanaged": unmanaged},
            source=OPENID_SOURCE,
        )
        if unmanaged:
            res.finding(
                "Unmanaged or test Microsoft 365 tenant claims the domain",
                "info",
                f"GetUserRealm federates {domain} to a Microsoft STS host: the tenant was probably created by self-service sign-up or for tests, "
                "so its brand name and tenant id say nothing about who owns the domain.",
                confidence="possible",
                tags=["weak_signal"],
                source=REALM_SOURCE,
            )
        if brand and not unmanaged:
            res.pivot(T.ORG, brand, "company_of", confidence="possible", expand=False,
                      note="Microsoft 365 FederationBrandName (self-declared by the tenant admin, unverified)")
        if idp and idp["pivot"]:
            res.pivot(T.DOMAIN, idp["host"], "identity_provider", confidence="probable",
                      note=f"federated sign-in identity provider ({idp['kind']}): passive modules only, never contacted by m365_tenant")


__all__ = [
    "M365Tenant",
    "PROBE_LOCAL_PART",
    "TEMPLATES",
    "USER_ORACLE_MARKERS",
    "build_url",
    "classify_idp",
    "failure",
    "parse_odc",
    "parse_openid",
    "parse_realm",
    "seed_domain",
    "url_allowed",
]
