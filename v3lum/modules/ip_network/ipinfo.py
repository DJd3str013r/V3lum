"""ipinfo: country and ASN of an IP from the IPinfo Lite API (keyed) (P036).

Batch p2-G02-1, proposal P036 (approved, P2). Final conditions implemented here:

* c1 - requires key ``ipinfo`` (alias ``V3LUM_IPINFO_TOKEN``), sent only in the ``Authorization:
  Bearer`` header, never as ``?token=`` (the cache stores URLs). Keyless calls are never made (the
  shared egress gets 429 'Rate limit hit'): without the key the engine reports NEEDS_KEY before the run.
* c2 - key-terms: the policy gate runs it under the corporate profile only with ``key_plans.ipinfo =
  'business'`` (a company/team account whose plan and terms URL legal records; IPinfo Lite data is
  CC BY-SA 4.0 with commercial use allowed).
* c3 - Lite endpoint ``api.ipinfo.io/lite/{ip}``: ASN (pivot, ``belongs_to_asn``), AS name, country and
  continent; ``as_domain`` becomes a company-domain pivot with ``expand=False`` (relation
  ``operator_domain``: the AS operator is not the user of the address). The web views
  ``ipinfo.io/{ip}`` and ``ipinfo.io/AS{asn}`` are manual links only.
* c4 - 403 'Unknown token' -> NEEDS_KEY ('invalid key'); 429 -> RATE_LIMITED; a challenge page ->
  BLOCKED; an error object inside a 200 answer -> ERROR ('could not verify'), never EMPTY.
* c5 - attribution 'IP address data powered by IPinfo' (CC BY-SA 4.0) on every result (attribute
  ``data_attribution`` for the report footer), in the notice (``v3lum info``) and in
  ``v3lum/data/notices/ipinfo_lite.json`` (THIRD_PARTY_NOTICES). The data is case data only: never
  bundled, never redistributed outside the team unless under the same licence.

Private, reserved and documentation addresses are never sent (SKIPPED not_applicable); a 'bogon'
answer is EMPTY.
"""

from __future__ import annotations

import json
import re
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.noise import is_public_ip

SOURCE = "ipinfo.api"
KEY = "ipinfo"
LITE_URL = "https://api.ipinfo.io/lite/{ip}"
WEB_IP = "https://ipinfo.io/{ip}"
WEB_ASN = "https://ipinfo.io/AS{asn}"
ATTRIBUTION = "IP address data powered by IPinfo (https://ipinfo.io). IPinfo Lite data is licensed CC BY-SA 4.0."
_ASN_RE = re.compile(r"^(?:AS)?\s*(\d{1,10})$", re.I)
_CC_RE = re.compile(r"^[A-Za-z]{2}$")


def lite_request(ip: str, token: str) -> tuple[str, dict[str, str]]:
    """(url, headers) of the Lite lookup (c1/c3): the token travels only in the Authorization header."""
    return LITE_URL.format(ip=ip), {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _text(value: Any, limit: int = 200) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _asn(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value < 4294967296 else None
    m = _ASN_RE.match(_text(value, 20))
    if not m:
        return None
    n = int(m.group(1))
    return n if 0 < n < 4294967296 else None


def error_title(body: Any) -> str:
    """The title of an IPinfo error object ({status, error: {title, message}}), '' when none."""
    data = body
    if isinstance(body, (bytes, str)):
        try:
            data = json.loads(body)
        except (ValueError, RecursionError, TypeError):
            return ""
    if not isinstance(data, dict):
        return ""
    err = data.get("error")
    if isinstance(err, dict):
        return _text(err.get("title"), 120) or _text(err.get("message"), 120) or "error"
    return _text(err, 120)


def parse_lite(data: dict[str, Any]) -> dict[str, Any]:
    """IPinfo Lite answer (or the core-API shape 'org': 'AS15169 Google LLC') -> normalised fields."""
    asn = _asn(data.get("asn"))
    as_name = _text(data.get("as_name"))
    org = _text(data.get("org"), 300)
    if asn is None and org:
        m = re.match(r"^AS(\d{1,10})\s+(.*)$", org)
        if m:
            asn, as_name = _asn(m.group(1)), as_name or m.group(2).strip()[:200]
    as_domain = _text(data.get("as_domain"), 253).lower().rstrip(".")
    cc = _text(data.get("country_code"), 2)
    if not cc and _CC_RE.match(_text(data.get("country"), 3)):
        cc = _text(data.get("country"), 2)  # core-API shape: 'country' holds the code
    return {
        "asn": asn,
        "as_name": as_name,
        "as_domain": as_domain,
        "country_code": cc.upper() if _CC_RE.match(cc) else "",
        "country_name": _text(data.get("country"), 100) if data.get("country_code") else "",
        "continent_code": _text(data.get("continent_code"), 2).upper(),
        "continent": _text(data.get("continent"), 100),
    }


@register
class IpInfo(Module):
    name = "ipinfo"
    title = "IPinfo Lite (country and ASN)"
    description = "Country, continent and announcing ASN of an IP from the IPinfo Lite API (free token, header-only)."
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6}
    produces = {T.ASN, T.DOMAIN}
    tags = {"free"}
    reference = "https://ipinfo.io/developers/lite-api"
    notice = (
        "IP address data powered by IPinfo (IPinfo Lite data, CC BY-SA 4.0). Needs a company/team IPinfo token "
        "(key 'ipinfo', recorded with --plan business once legal records the plan and terms URL); the token is "
        "sent only in the Authorization header. IPinfo data is case data only: never bundled, never redistributed "
        "outside the team unless under the same licence."
    )
    # ---- contract v2 declarations --------------------------------------------------------
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ipinfo"
    sources = (SOURCE,)
    hosts = ("api.ipinfo.io",)
    access_model = "free_auth_unlimited"
    requires_keys = (KEY,)
    max_requests = 1
    expected_latency = 0.5
    min_interval = 0.5
    timeout = 30.0
    cache_ttl = 86400
    manual_link = "https://ipinfo.io/{ip}"
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return is_public_ip(entity.value)  # private/reserved/documentation space: never sent

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        token = ctx.key(KEY)
        if not token:  # the engine reports NEEDS_KEY before the run; keyless calls are never made (c1)
            return res.mark(Status.NEEDS_KEY, "IPinfo key 'ipinfo' (V3LUM_IPINFO_TOKEN) is not configured: keyless calls are disabled",
                            reason_code="needs_key")
        ip = entity.value
        url, headers = lite_request(ip, token)
        try:
            data = ctx.http.get_json(url, headers=headers, source=SOURCE)
        except AuthRequired as exc:  # c4: 403 'Unknown token' (the Lite 403 without a token is the same body)
            title = error_title(getattr(exc, "body", "")) or f"HTTP {getattr(exc, 'status', 403)}"
            return res.mark(Status.NEEDS_KEY, f"IPinfo rejected the token ({title}): invalid key - check `v3lum keys`",
                            reason_code="needs_key")
        if not isinstance(data, dict):
            return res.mark(Status.ERROR, f"unexpected IPinfo answer ({type(data).__name__}, not a JSON object): could not verify")
        if data.get("error") is not None or (isinstance(data.get("status"), int) and data.get("status") >= 300):
            return res.mark(Status.ERROR, f"IPinfo error in a 200 answer ({error_title(data) or data.get('status')}): could not verify")
        res.raw = {k: data.get(k) for k in ("ip", "asn", "as_name", "as_domain", "country_code", "country", "continent_code",
                                             "continent", "org", "bogon") if k in data}
        if data.get("bogon") is True:
            return res.mark(Status.EMPTY, "IPinfo: bogon address (no data)")
        fields = parse_lite(data)
        if fields["asn"] is None and not fields["country_code"]:
            return res.mark(Status.EMPTY, "IPinfo answered without an ASN or a country")
        res.link("IPinfo IP page", WEB_IP.format(ip=ip))  # manual web views (c3): never fetched
        asn = fields["asn"]
        if asn is not None:
            res.attr("asn", f"AS{asn}")
            res.attr("as_org", fields["as_name"])
            res.pivot(T.ASN, f"AS{asn}", "belongs_to_asn", confidence="probable",
                      note=f"IPinfo Lite IP-to-ASN{': ' + fields['as_name'][:80] if fields['as_name'] else ''}")
            res.link("IPinfo AS page", WEB_ASN.format(asn=asn))
        if fields["as_domain"]:
            res.attr("as_domain", fields["as_domain"])
            res.pivot(T.DOMAIN, fields["as_domain"], "operator_domain", confidence="possible", expand=False,
                      note="IPinfo as_domain of the announcing AS: the network operator, not necessarily the user of the address")
        res.attr("country", fields["country_code"])
        res.attr("continent", fields["continent_code"] or fields["continent"])
        res.attr("data_attribution", ATTRIBUTION)
        return res
