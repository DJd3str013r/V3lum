"""Gated module links of the G14 pivot packs of batch p2-G14-1 (P026, P057, P083, P170, P180, P194).

The six packs ship in ``v3lum/data/pivot_links/<pack>.json`` in the frozen schema ``v3lum.pivot_pack/1``
(domain_dns, ip_network, url_web, threat_intel_ioc, malware_hash, vulnerability). Their ``links`` are loaded,
linted and rendered by the core (:mod:`v3lum.core.links`), the engine and ``v3lum links``. A few entries need a
gate the frozen core link model does not carry; they live in the same file under the pack-level extension key
``x_module_links`` (``x_`` keys are ignored by the core loader) and are rendered by the pack's module through this
file:

* a **TLP ceiling** (``x_max_tlp``): FOFA and Criminal IP (foreign providers, P057 cond 10) and the
  scan-trigger links (ScamAdviser, securityheaders.com, URLVoid: P083 cond 11, P170 cond 9) are hidden at
  TLP:AMBER and above;
* **analyst-typed values only** (``x_seed_only``): the touches_target links of P083/P170 render only for seeds
  the analyst typed and confirmed (``ctx.is_seed``, not in ``options.unconfirmed_seeds``) and never for an entity
  flagged hostile (``policy.hostile_reasons``, best effort at run time);
* a **value rule** (``x_value_re``): the crt.sh certificate lookup only for 64-hex SHA-256 fingerprints (P026
  cond 9);
* a **vetted encoder** the core lacks: ``{b64q}`` (P057 cond 11: links.b64 applied to a fixed FOFA expression
  declared in the entry, ``ip="{q}"`` / ``icon_hash="{q}"`` / ``cert="{q}"``; values with a quote, a backslash
  or a control character never render), ``{cidrp}`` (bgp.he.net prefix pages need a literal '/': the address
  percent-encoded, '/', the prefix length) and ``{urlhp}`` (CyberCrime-Tracker stores C2 URLs without a
  scheme: host[:port] and path, percent-encoded as one query value);
* a **public-value filter** (P057 cond 9, applied to every module link): no link for private, loopback,
  link-local, CGNAT, ULA, multicast, documentation, benchmarking or reserved addresses (CIDRs overlapping
  them), private/reserved/documentation ASNs, single-label or internal host names (.local, .internal, .corp,
  .lan, .home.arpa, .test, .example, .invalid, .arpa, .onion...). :func:`public_value_problem` is the test.

Lint (fail closed): every module link is linted like a pack link - the core lint (:func:`links.lint_pack`) runs
on a copy whose vetted placeholders are replaced by ``{q}`` (https, declared host, no userinfo/port, forbidden
probe tables, publishing hosts, A8 tiers, CPF) - plus the batch rules of :func:`batch_rule_problems` (no MDN
Observatory, no CompleteDNS AJAX endpoint, no DNSViz /analyze/, Triage search pages only, securityheaders.com
with hide=on, foreign providers with ``x_max_tlp`` green, scan-trigger module links with ``x_seed_only`` and
``x_max_tlp`` green, the Sploitus caution label, the crt.sh SHA-256 rule, no ``{raw}``). Entries with problems
are dropped and listed by :func:`module_link_errors`.

Rendering re-checks the URL (https, the declared host, no userinfo/port, no whitespace or control
characters) and reads the host tier from the provider registry at render time. At TLP:RED nothing is emitted;
at AMBER and above the renderers show module links as non-clickable text with 'opening sends <value> to
<host>'. V3LUM never fetches any of these URLs.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.core import links as _links
from v3lum.core import tlp as _tlp
from v3lum.core.entities import IOC_TYPES, Entity, EntityType, url_host
from v3lum.core.models import ModuleResult, Status

BATCH = "p2-G14-1"
EXT_KEY = "x_module_links"
PACKS: tuple[str, ...] = ("domain_dns", "ip_network", "url_web", "threat_intel_ioc", "malware_hash", "vulnerability")
RECHECK_MAX_AGE_DAYS = 180  # cond 7 of every proposal of the batch
TERMINAL_MAX_LINKS = 8  # cond 6: the terminal shows at most 8 links per seed (ui.render.MAX_LINKS_PER_SEED)
ANTIBOT_BADGE = "anti-bot/CAPTCHA: open it manually in a browser"
TOUCHES_WARNING = "opening makes {host} contact the target live"
SPLOITUS_CAUTION = "view only, never download or run code"
SHA256_RE = "^[0-9a-f]{64}$"

#: Placeholders a module link may use (each one is its own encoder; whitelist substitution with re.sub).
MODULE_PLACEHOLDERS: dict[str, str] = {
    "q": "the value, percent-encoded (RFC 3986, nothing kept), like the core {q}",
    "b64q": "base64 of the entry's fixed x_b64q_expr with the value in place of {q}, percent-encoded (FOFA, P057 cond 11)",
    "cidrp": "CIDR network: address percent-encoded, a literal '/', the prefix length (bgp.he.net prefix pages)",
    "urlhp": "URL host[:port] and path without scheme, query or fragment, percent-encoded (CyberCrime-Tracker)",
}
PLACEHOLDER_TYPES: dict[str, frozenset[EntityType]] = {
    "b64q": frozenset({EntityType.IPV4, EntityType.IPV6, EntityType.FAVICON_HASH, EntityType.CERT_FP}),
    "cidrp": frozenset({EntityType.CIDR}),
    "urlhp": frozenset({EntityType.URL}),
}
#: The vetted FOFA query expressions and the entity types each one takes (P057 cond 11).
B64Q_EXPRESSIONS: dict[str, frozenset[EntityType]] = {
    'ip="{q}"': frozenset({EntityType.IPV4, EntityType.IPV6}),
    'icon_hash="{q}"': frozenset({EntityType.FAVICON_HASH}),
    'cert="{q}"': frozenset({EntityType.CERT_FP}),
}
_EXT_FIELDS = frozenset({
    "x_max_tlp", "x_seed_only", "x_badge", "x_value_re", "x_value_rule", "x_b64q_expr", "x_group", "x_public_only",
})
_RE_PH = re.compile(r"\{([a-z0-9_]+)\}")
_RE_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_RE_URL_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")

# ------------------------------------------------------------------------------------------------------
# Public-value filter (P057 cond 9)
# ------------------------------------------------------------------------------------------------------

_V4_RANGES: tuple[tuple[str, str], ...] = (
    ("0.0.0.0/8", "'this network' address"),
    ("10.0.0.0/8", "private address"),
    ("100.64.0.0/10", "CGNAT (shared address space)"),
    ("127.0.0.0/8", "loopback address"),
    ("169.254.0.0/16", "link-local address"),
    ("172.16.0.0/12", "private address"),
    ("192.0.0.0/24", "IETF protocol assignment"),
    ("192.0.2.0/24", "documentation address"),
    ("192.88.99.0/24", "6to4 relay anycast (deprecated)"),
    ("192.168.0.0/16", "private address"),
    ("198.18.0.0/15", "benchmarking address"),
    ("198.51.100.0/24", "documentation address"),
    ("203.0.113.0/24", "documentation address"),
    ("224.0.0.0/4", "multicast address"),
    ("240.0.0.0/4", "reserved address"),
)
_V6_RANGES: tuple[tuple[str, str], ...] = (
    ("::/128", "unspecified address"),
    ("::1/128", "loopback address"),
    ("::ffff:0:0/96", "IPv4-mapped address"),
    ("64:ff9b::/96", "NAT64 address"),
    ("64:ff9b:1::/48", "local NAT64 address"),
    ("100::/64", "discard-only address"),
    ("2001::/23", "IETF protocol assignment (Teredo, benchmarking, ORCHID)"),
    ("2001:db8::/32", "documentation address"),
    ("2002::/16", "6to4 address"),
    ("3fff::/20", "documentation address"),
    ("fc00::/7", "unique local address (ULA)"),
    ("fe80::/10", "link-local address"),
    ("fec0::/10", "site-local address"),
    ("ff00::/8", "multicast address"),
)
_V4_NETS = tuple((ipaddress.ip_network(n), label) for n, label in _V4_RANGES)
_V6_NETS = tuple((ipaddress.ip_network(n), label) for n, label in _V6_RANGES)
_V6_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")
_ASN_RANGES: tuple[tuple[int, int, str], ...] = (
    (0, 0, "reserved AS number"),
    (23456, 23456, "AS_TRANS (reserved)"),
    (64496, 64511, "documentation AS number"),
    (64512, 65534, "private AS number"),
    (65535, 65535, "reserved AS number"),
    (65536, 65551, "documentation AS number"),
    (65552, 131071, "reserved AS number"),
    (4200000000, 4294967294, "private AS number"),
    (4294967295, 4294967295, "reserved AS number"),
)
#: Internal, special-use and non-public name suffixes (RFC 6761/6762/8375/9476, de-facto internal TLDs).
INTERNAL_SUFFIXES: tuple[str, ...] = (
    "local", "localhost", "localdomain", "internal", "intranet", "corp", "lan", "home", "home.arpa", "private",
    "test", "example", "invalid", "arpa", "onion", "alt",
)


def _ip_problem(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.version == 4:
        for net, label in _V4_NETS:
            if ip in net:
                return f"{label} ({net})"
        return ""
    for net, label in _V6_NETS:
        if ip in net:
            return f"{label} ({net})"
    if ip not in _V6_GLOBAL_UNICAST:
        return "IPv6 address outside global unicast (2000::/3)"
    return ""


def _cidr_problem(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    ranges = _V4_NETS if net.version == 4 else _V6_NETS
    for other, label in ranges:
        if net.overlaps(other):  # type: ignore[arg-type]
            return f"network overlapping {label} ({other})"
    if net.version == 6 and not net.subnet_of(_V6_GLOBAL_UNICAST):  # type: ignore[arg-type]
        return "IPv6 network outside global unicast (2000::/3)"
    return ""


def _name_problem(name: str) -> str:
    host = name.strip().rstrip(".").lower()
    if not host:
        return "empty host name"
    if "." not in host:
        return "single-label host name"
    for suffix in INTERNAL_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return f"internal or special-use name (.{suffix})"
    return ""


def public_value_problem(entity: Entity) -> str:
    """Why a value must never be sent to a third-party page ('' = public): private, loopback, link-local,
    CGNAT, ULA, multicast, documentation, benchmarking and reserved addresses (and CIDRs overlapping them),
    private/reserved/documentation ASNs, single-label and internal host names (P057 cond 9). Unparseable
    values count as problems (fail closed)."""
    t, v = entity.type, str(entity.value or "")
    try:
        if t in (EntityType.IPV4, EntityType.IPV6):
            return _ip_problem(ipaddress.ip_address(v))
        if t is EntityType.CIDR:
            return _cidr_problem(ipaddress.ip_network(v, strict=False))
        if t is EntityType.ASN:
            digits = v[2:] if v[:2].upper() == "AS" else v
            if not digits.isdigit():
                return "unparseable AS number"
            n = int(digits)
            for low, high, label in _ASN_RANGES:
                if low <= n <= high:
                    return label
            return "AS number out of range" if n > 4294967295 else ""
        if t in (EntityType.DOMAIN, EntityType.ONION):
            return _name_problem(v)
        if t is EntityType.URL:
            host = (url_host(v) or "").strip("[]")
            try:
                return _ip_problem(ipaddress.ip_address(host))
            except ValueError:
                return _name_problem(host)
    except ValueError:
        return f"unparseable {t.value} value"
    return ""


# ------------------------------------------------------------------------------------------------------
# Encoders (whitelist substitution; never str.format)
# ------------------------------------------------------------------------------------------------------


def b64q(expr: str, value: str) -> str:
    """The FOFA ``qbase64`` value: base64 of the vetted expression with the value in place of ``{q}``,
    percent-encoded. Raises ValueError for an expression outside :data:`B64Q_EXPRESSIONS` or a value that could
    break out of the quoted FOFA term (a quote, a backslash or a control character)."""
    if expr not in B64Q_EXPRESSIONS:
        raise ValueError(f"FOFA expression {expr!r} is not vetted")
    value = str(value)
    if not value or '"' in value or "\\" in value or _RE_CTRL.search(value) or len(value) > 256:
        raise ValueError("value cannot go into a quoted FOFA term")
    return quote(_links.b64(expr.replace("{q}", value)), safe="")


def cidrp(value: str) -> str:
    """bgp.he.net prefix path: the network address percent-encoded, a literal '/', the prefix length."""
    net = ipaddress.ip_network(str(value), strict=False)
    return f"{quote(str(net.network_address), safe='')}/{net.prefixlen}"


def urlhp(value: str) -> str:
    """CyberCrime-Tracker search value: host[:port] and path of an http(s) URL, no scheme, userinfo, query or
    fragment, percent-encoded as one query value."""
    parts = urlsplit(str(value))
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("not an http(s) URL")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port  # raises ValueError for a bad port
    hostport = f"{host}:{port}" if port else host
    path = parts.path if parts.path not in ("", "/") else ""
    return quote(hostport + path, safe="")


def _encode(name: str, entity: Entity, gl: GatedLink) -> str:
    allowed = PLACEHOLDER_TYPES.get(name)
    if allowed is not None and entity.type not in allowed:
        raise ValueError(f"{{{name}}} does not apply to {entity.type.value}")
    if name == "q":
        return quote(str(entity.value), safe="")
    if name == "b64q":
        if entity.type not in B64Q_EXPRESSIONS.get(gl.b64q_expr, frozenset()):
            raise ValueError("the FOFA expression does not take this type")
        return b64q(gl.b64q_expr, entity.value)
    if name == "cidrp":
        return cidrp(entity.value)
    if name == "urlhp":
        return urlhp(entity.value)
    raise ValueError(f"unknown placeholder {{{name}}}")


# ------------------------------------------------------------------------------------------------------
# Lint
# ------------------------------------------------------------------------------------------------------


def batch_rule_problems(pack: str, entry: Mapping[str, Any], *, module_link: bool = False) -> list[str]:
    """Rules of the batch's final conditions on top of the core P311 lint (links and module links)."""
    template = str(entry.get("template") or "")
    host = str(entry.get("host") or "")
    label = str(entry.get("label") or "")
    try:
        parts = urlsplit(_RE_PH.sub("x", template))
    except ValueError:
        return ["template is not a URL"]
    path, query = parts.path, parts.query
    errs: list[str] = []
    if "{raw}" in template:
        errs.append("never {raw}: values go through the declared encoder (cond 3)")
    if host == "developer.mozilla.org" or "observatory" in path.lower():
        errs.append("no MDN Observatory link: opening it starts a scan published in a public per-host history (P083 cond 9)")
    if host == "completedns.com" and "/ajax" in path.lower():
        errs.append("CompleteDNS: the history page only, never its /dns-history/ajax/ endpoint (P026 cond 8)")
    if host == "dnsviz.net" and "/analyze" in path.lower():
        errs.append("DNSViz /analyze/ runs and publishes a fresh analysis (P026 cond 10)")
    if host == "tria.ge" and path not in ("/s", "/reports"):
        errs.append("Triage: search pages only (/s, /reports), never submission or download (P180 cond 9)")
    if host == "securityheaders.com" and "hide=on" not in query.split("&"):
        errs.append("securityheaders.com only with hide=on (P083 cond 9)")
    if host == "urlscan.io" and path.startswith("/api/"):
        errs.append("urlscan.io search/result pages only, never the API or a scan submission (rule 7)")
    if host == "sploitus.com" and SPLOITUS_CAUTION not in label:
        errs.append(f"the Sploitus label reads 'exploit listings - {SPLOITUS_CAUTION}' (P194 cond 9)")
    badge = str(entry.get("x_badge") or "")
    if "foreign provider" in badge and str(entry.get("x_max_tlp") or "").lower() != "green":
        errs.append("foreign providers carry x_max_tlp green (P057 cond 10, P170 cond 10)")
    types = {str(t) for t in entry.get("entity_types") or ()}
    if EntityType.CERT_FP.value in types and host == "crt.sh" and entry.get("x_value_re") != SHA256_RE:
        errs.append(f"crt.sh certificate lookups only for 64-hex SHA-256 values (x_value_re {SHA256_RE!r}, P026 cond 9)")
    if host == "en.fofa.info":
        if "{b64q}" not in template or entry.get("x_b64q_expr") not in B64Q_EXPRESSIONS:
            errs.append("FOFA templates use the vetted {b64q} placeholder with an x_b64q_expr from B64Q_EXPRESSIONS (P057 cond 11)")
        if not module_link:
            errs.append("FOFA links need the module renderer ({b64q}, x_max_tlp)")
    if "{b64q}" in template and entry.get("x_b64q_expr") not in B64Q_EXPRESSIONS:
        errs.append("{b64q} needs an x_b64q_expr from B64Q_EXPRESSIONS")
    if module_link and entry.get("touches_target") is True and (
            entry.get("x_seed_only") is not True or str(entry.get("x_max_tlp") or "").lower() != "green"):
        errs.append("scan-trigger module links carry x_seed_only and x_max_tlp green (P083 cond 11, P170 cond 9)")
    if not module_link:
        stray = sorted(k for k in ("x_max_tlp", "x_seed_only", "x_value_re", "x_b64q_expr") if k in entry)
        if stray:
            errs.append(f"{stray} need the module renderer: move the entry to {EXT_KEY}")
    return errs


@dataclass(frozen=True)
class GatedLink:
    """A linted ``x_module_links`` entry. ``link`` is its core view (vetted placeholders replaced by ``{q}``),
    which carries the frozen fields; ``template`` is the real one."""

    link: _links.PivotLink
    template: str
    placeholders: tuple[str, ...]
    max_tlp: _tlp.TLP | None = None
    seed_only: bool = False
    public_only: bool = True
    value_re: re.Pattern[str] | None = None
    value_rule: str = ""
    b64q_expr: str = ""
    badge: str = ""
    group: str = ""

    @property
    def id(self) -> str:
        return self.link.id

    @property
    def ref(self) -> str:
        return self.link.ref

    @property
    def host(self) -> str:
        return self.link.host


def _core_view(entry: Mapping[str, Any]) -> dict[str, Any]:
    template = _RE_PH.sub(lambda m: "{q}" if m.group(1) in MODULE_PLACEHOLDERS else m.group(0), str(entry.get("template") or ""))
    out = {k: v for k, v in entry.items() if k not in _EXT_FIELDS}
    out["template"] = template
    return out


def _parse_entry(pack: str, entry: Any) -> tuple[GatedLink | None, list[str]]:
    if not isinstance(entry, Mapping):
        return None, [f"{pack}:{EXT_KEY}: entries must be objects"]
    ident = str(entry.get("id") or "?")
    where = f"{pack}:{ident} ({EXT_KEY})"
    template = entry.get("template")
    if not isinstance(template, str) or not template:
        return None, [f"{where}: missing template"]
    names = tuple(_RE_PH.findall(template))
    errs: list[str] = []
    unknown = sorted({n for n in names if n not in MODULE_PLACEHOLDERS})
    if unknown:
        errs.append(f"unknown placeholders {unknown} (module links take {sorted(MODULE_PLACEHOLDERS)})")
    if len(names) != 1:
        errs.append("exactly one placeholder per module link")
    types: list[EntityType] = []
    for raw in entry.get("entity_types") or ():
        try:
            types.append(EntityType(str(raw)))
        except ValueError:
            errs.append(f"unknown entity type {raw!r}")
    for name in names:
        allowed = PLACEHOLDER_TYPES.get(name)
        if allowed is not None and any(t not in allowed for t in types):
            errs.append(f"{{{name}}} is valid only for {sorted(t.value for t in allowed)}")
    expr = entry.get("x_b64q_expr") or ""
    if "b64q" in names and any(t not in B64Q_EXPRESSIONS.get(str(expr), frozenset()) for t in types):
        errs.append(f"x_b64q_expr {expr!r} does not take {[t.value for t in types]}")
    max_tlp: _tlp.TLP | None = None
    if entry.get("x_max_tlp") not in (None, ""):
        try:
            max_tlp = _tlp.parse(entry.get("x_max_tlp"))
        except ValueError:
            errs.append(f"x_max_tlp {entry.get('x_max_tlp')!r} is not a TLP value")
    value_re: re.Pattern[str] | None = None
    if entry.get("x_value_re") not in (None, ""):
        raw_re = str(entry.get("x_value_re"))
        if not (raw_re.startswith("^") and raw_re.endswith("$")):
            errs.append("x_value_re must be anchored (^...$)")
        try:
            value_re = re.compile(raw_re)
        except re.error as exc:
            errs.append(f"x_value_re does not compile ({exc})")
    for key in ("x_badge", "x_value_rule", "x_group"):
        value = entry.get(key)
        if value is not None and (not isinstance(value, str) or _RE_CTRL.search(value) or len(value) > 200):
            errs.append(f"{key} must be a single-line string")
    for key in ("x_seed_only", "x_public_only"):
        if key in entry and not isinstance(entry[key], bool):
            errs.append(f"{key} must be true or false")
    if entry.get("x_public_only") is False:
        errs.append("module links always apply the public-value filter (P057 cond 9): x_public_only cannot be false")
    errs += batch_rule_problems(pack, entry, module_link=True)
    view = _core_view(entry)
    errs += [e.split(": ", 2)[-1] for e in _links.lint_pack(
        {"schema": _links.SCHEMA, "pack": pack, "title": pack, "links": [view]}, source=f"{pack}.json")]
    if errs:
        return None, [f"{where}: {e}" for e in errs]
    link = _links.PivotLink(
        pack=pack,
        id=ident,
        label=str(entry.get("label") or ""),
        template=str(view["template"]),
        entity_types=tuple(types),
        category=str(entry.get("category") or "other"),
        host=str(entry.get("host") or ""),
        verified=bool(entry.get("verified", False)),
        checked_at=str(entry.get("checked_at") or ""),
        privacy=False,
        publishes=False,
        touches_target=bool(entry.get("touches_target", False)),
        login_required=False,
        antibot=bool(entry.get("antibot", False)),
        tier=_links.host_tier(str(entry.get("host") or "")),
        notes=str(entry.get("notes") or ""),
    )
    return GatedLink(
        link=link,
        template=template,
        placeholders=names,
        max_tlp=max_tlp,
        seed_only=entry.get("x_seed_only") is True,
        value_re=value_re,
        value_rule=str(entry.get("x_value_rule") or ""),
        b64q_expr=str(expr),
        badge=str(entry.get("x_badge") or ""),
        group=str(entry.get("x_group") or ""),
    ), []


def parse_module_links(pack: str, data: Mapping[str, Any]) -> tuple[dict[str, GatedLink], list[str]]:
    """The valid ``x_module_links`` of a parsed pack (by id, file order) and the problems of the others."""
    items = data.get(EXT_KEY) or []
    if not isinstance(items, list):
        return {}, [f"{pack}: {EXT_KEY} must be a list"]
    out: dict[str, GatedLink] = {}
    errs: list[str] = []
    core_ids = {str(i.get("id")) for i in data.get("links") or [] if isinstance(i, Mapping)}
    for entry in items:
        gl, problems = _parse_entry(pack, entry)
        errs.extend(problems)
        if gl is None:
            continue
        if gl.id in out or gl.id in core_ids:
            errs.append(f"{pack}:{gl.id} ({EXT_KEY}): duplicate link id")
            continue
        out[gl.id] = gl
    return out, errs


def lint_pack_data(data: Any, *, pack: str) -> list[str]:
    """Every problem of a batch pack: the core lint of ``links``, the batch rules on every link, the full lint
    of ``x_module_links`` and the ``x_served_by`` references (they must resolve to loaded links)."""
    if not isinstance(data, Mapping):
        return [f"{pack}: a pack is an object"]
    errs = list(_links.lint_pack(data, source=f"{pack}.json"))
    for item in data.get("links") or []:
        if isinstance(item, Mapping):
            errs.extend(f"{pack}:{item.get('id')}: {e}" for e in batch_rule_problems(pack, item))
    errs += parse_module_links(pack, data)[1]
    for ref in data.get("x_served_by") or []:
        target = ref.get("ref") if isinstance(ref, Mapping) else None
        if not isinstance(target, str) or _links.get_link(target) is None:
            errs.append(f"{pack}: x_served_by {target!r} does not resolve to a loaded pivot link")
    return errs


# ------------------------------------------------------------------------------------------------------
# Loading
# ------------------------------------------------------------------------------------------------------

_LOCK = threading.Lock()
_CACHE: dict[str, tuple[Any, dict[str, Any], dict[str, GatedLink], list[str]]] = {}


def _registry_token() -> Any:
    try:
        from v3lum.core import providers

        return providers.registry()
    except Exception:  # noqa: BLE001 - a broken registry leaves every host unknown (fail closed)
        return None


def _load(pack: str) -> tuple[Any, dict[str, Any], dict[str, GatedLink], list[str]]:
    token = _registry_token()
    with _LOCK:
        cached = _CACHE.get(pack)
        if cached is not None and cached[0] is token:
            return cached
        path = _links.PACKS_DIR / f"{pack}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            state: tuple[Any, dict[str, Any], dict[str, GatedLink], list[str]] = (
                token, {}, {}, [f"{pack}: unreadable pack ({type(exc).__name__})"])
        else:
            if isinstance(data, dict):
                found, errs = parse_module_links(pack, data)
                state = (token, data, found, errs)
            else:
                state = (token, {}, {}, [f"{pack}: a pack is an object"])
        _CACHE[pack] = state
        return state


def reset_cache() -> None:
    with _LOCK:
        _CACHE.clear()


def pack_data(pack: str) -> dict[str, Any]:
    """The parsed pack file (``{}`` when missing or unreadable)."""
    return dict(_load(pack)[1])


def module_links(pack: str) -> dict[str, GatedLink]:
    """The valid ``x_module_links`` of a pack, by id (file order)."""
    return dict(_load(pack)[2])


def module_link_errors(pack: str | None = None) -> list[str]:
    """Problems of the ``x_module_links`` of one batch pack (or of all of them)."""
    return [e for p in ((pack,) if pack else PACKS) for e in _load(p)[3]]


# ------------------------------------------------------------------------------------------------------
# Rendering
# ------------------------------------------------------------------------------------------------------


def url_ok(url: str, host: str) -> bool:
    """https, exactly the declared host, no userinfo or port, no whitespace or control characters, only URL
    characters (non-ASCII and quotes are percent-encoded), at most links.MAX_URL characters."""
    if not isinstance(url, str) or len(url) > _links.MAX_URL or not _RE_URL_CHARS.match(url):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (parts.scheme == "https" and (parts.hostname or "") == host and parts.username is None
            and parts.password is None and port is None and "@" not in parts.netloc)


def _badge(link: _links.PivotLink, tier: str) -> str:
    badges = []
    if tier == "unknown":
        badges.append(_links.BADGE_UNKNOWN_OPERATOR)
    if not link.verified:
        badges.append(_links.BADGE_UNVERIFIED)
    return ", ".join(badges)


def value_problem(gl: GatedLink, entity: Entity) -> str:
    """Why the value of ``entity`` never goes into this link ('' = it may): the public-value filter
    (P057 cond 9) and the entry's value rule (e.g. crt.sh SHA-256 only, P026 cond 9)."""
    if gl.public_only:
        problem = public_value_problem(entity)
        if problem:
            return f"no third-party link for a {problem} (P057 cond 9)"
    if gl.value_re is not None and not gl.value_re.match(str(entity.value)):
        return gl.value_rule or "value does not match the entry's value rule"
    return ""


def render(gl: GatedLink, entity: Entity) -> _links.RenderedLink | None:
    """Render a module link for ``entity``; None when it does not apply (type, tier, value rule, encoder) -
    never a guessed URL. TLP and seed gates are :func:`gate`'s job."""
    if not isinstance(gl, GatedLink) or not isinstance(entity, Entity):
        return None
    link = gl.link
    if entity.type in _links.NO_LINK_TYPES or entity.type not in link.entity_types:
        return None
    if entity.type in _links.PRIVACY_TYPES:
        return None  # IOC packs: personal and company values never go into a module link
    tier = _links.host_tier(link.host)  # the registry tier now, never the one recorded at load
    if tier not in _links.TRUSTED_TIERS and entity.type not in IOC_TYPES:
        return None
    if value_problem(gl, entity):
        return None

    def repl(m: re.Match[str]) -> str:
        if m.group(1) not in gl.placeholders:
            raise ValueError(m.group(1))
        return _encode(m.group(1), entity, gl)

    try:
        url = _RE_PH.sub(repl, gl.template)
    except ValueError:
        return None
    if "{" in url or "}" in url or not url_ok(url, link.host):
        return None
    return _links.RenderedLink(
        ref=link.ref, label=link.label, url=url, host=link.host, category=link.category, verified=link.verified,
        privacy=False, touches_target=link.touches_target, antibot=link.antibot, tier=tier, badge=_badge(link, tier),
    )


def tlp_level(ctx: Any) -> _tlp.TLP:
    """The entity TLP of the run; an unreadable value fails closed to RED."""
    try:
        return _tlp.parse(getattr(ctx, "tlp", "") or "amber")
    except ValueError:
        return _tlp.TLP.RED


def typed_seed(ctx: Any, entity: Entity) -> bool:
    """True when the analyst typed (and confirmed) the value: ``ctx.is_seed`` and not an unconfirmed seed."""
    if not bool(getattr(ctx, "is_seed", False)):
        return False
    options = getattr(ctx, "options", None)
    unconfirmed = getattr(options, "unconfirmed_seeds", None) or ()
    return entity.key not in set(unconfirmed)


def hostile_reasons(ctx: Any, entity: Entity) -> list[str]:
    """GUARD-01 signals for the entity (case-DB sightings with a hostile verdict, hostile-shaped names, org-brand
    lookalikes) through ``policy.hostile_reasons``; best effort (``[]`` when the check cannot run)."""
    try:
        from v3lum.core import policy

        pctx = policy.make_context(ctx.runtime, ctx.options, path="scan")  # v3lum-lint: allow LINT-01 -- core policy.make_context only reads the runtime's case/org/health state to build the GUARD-01 context; no client or scope is built
        return [str(r) for r in policy.hostile_reasons(entity, pctx, run=getattr(ctx, "run", None))]
    except Exception:  # noqa: BLE001 - the check is advisory: the renderers re-apply it from the case graph
        return []


def gate(gl: GatedLink, entity: Entity, ctx: Any, level: _tlp.TLP) -> tuple[str, str]:
    """(reason_code, reason) when the link must not be emitted for this run, else ('', '')."""
    if level >= _tlp.TLP.RED:
        return "tlp", "TLP:RED: third-party links are hidden from reports"
    if gl.max_tlp is not None and level > gl.max_tlp:
        return "tlp", f"hidden at {level.label}: listed only up to {gl.max_tlp.label}"
    if gl.seed_only and not typed_seed(ctx, entity):
        return "not_applicable", "scan-trigger link: rendered only for values the analyst typed"
    problem = value_problem(gl, entity)
    if problem:
        return "not_applicable", problem
    if gl.link.touches_target:
        reasons = hostile_reasons(ctx, entity)
        if reasons:
            return "policy", f"scan-trigger link hidden for a hostile entity ({reasons[0]})"
    return "", ""


def label_for(rendered: _links.RenderedLink, gl: GatedLink) -> str:
    """The label shown with a module link: badges (unknown operator, unverified, anti-bot, the entry's own) and,
    for touches_target links, the live-contact warning."""
    badges = [b for b in (rendered.badge, ANTIBOT_BADGE if rendered.antibot else "", gl.badge) if b]
    label = rendered.label
    if badges:
        label += " [" + "; ".join(dict.fromkeys(badges)) + "]"
    if rendered.touches_target:
        label += " - WARNING: " + TOUCHES_WARNING.format(host=rendered.host)
    return label


def emit(res: ModuleResult, entity: Entity, level: _tlp.TLP, rendered: _links.RenderedLink, gl: GatedLink) -> dict[str, Any]:
    """Add the link to ``res`` and return its raw record."""
    label = label_for(rendered, gl)
    res.link(label, rendered.url)
    return {
        "ref": rendered.ref, "url": rendered.url, "host": rendered.host, "tier": rendered.tier,
        "category": rendered.category, "verified": rendered.verified, "antibot": rendered.antibot,
        "touches_target": rendered.touches_target, "badge": rendered.badge,
        "clickable": level < _tlp.TLP.AMBER and not rendered.touches_target,
        "disclosure": _links.disclosure_note(entity, rendered), "label": label,
    }


def run_links(module: Any, entity: Entity, ctx: Any, pack: str) -> ModuleResult:
    """The shared run of the batch's link modules: emit the module links of ``pack`` that apply to the entity
    and pass every gate; OK with the links, EMPTY when the only applicable links are already listed by a core
    pack link, SKIPPED ('tlp', 'policy' or 'not_applicable') when every one is gated."""
    res = module.result(entity)
    level = tlp_level(ctx)
    found = module_links(pack)
    applicable = [gl for gl in found.values() if entity.type in gl.link.entity_types]
    if level >= _tlp.TLP.RED:
        res.raw = {"pack": pack, "tlp": level.value_str, "links": [], "hidden": [
            {"id": gl.id, "code": "tlp", "reason": "TLP:RED"} for gl in applicable]}
        return res.mark(Status.SKIPPED, "TLP:RED: third-party links are hidden from reports (`v3lum links` lists the "
                                        "pack links with the disclosure warning)", reason_code="tlp")
    if not applicable:
        res.raw = {"pack": pack, "tlp": level.value_str, "links": [], "hidden": []}
        return res.mark(Status.SKIPPED, f"no module link of pack {pack} takes {entity.type.value}", reason_code="not_applicable")
    try:
        core_urls = {r.url: r.ref for r in _links.pivot_links_for(entity)}
    except Exception:  # noqa: BLE001 - pack problems are reported by links.errors()
        core_urls = {}
    shown: list[dict[str, Any]] = []
    hidden: list[dict[str, str]] = []
    for gl in applicable:
        code, why = gate(gl, entity, ctx, level)
        if code:
            hidden.append({"id": gl.id, "code": code, "reason": why})
            continue
        rendered = render(gl, entity)
        if rendered is None:
            hidden.append({"id": gl.id, "code": "not_applicable", "reason": "did not render (type, tier or encoder)"})
            continue
        if rendered.url in core_urls:
            hidden.append({"id": gl.id, "code": "duplicate", "reason": f"already listed by {core_urls[rendered.url]}"})
            continue
        shown.append(emit(res, entity, level, rendered, gl))
    res.raw = {"pack": pack, "tlp": level.value_str, "links": shown, "hidden": hidden}
    if shown:
        return res
    codes = [h["code"] for h in hidden]
    if all(c == "duplicate" for c in codes):
        return res.mark(Status.EMPTY)
    code = "tlp" if "tlp" in codes else ("policy" if "policy" in codes else "not_applicable")
    reason = "; ".join(f"{h['id']}: {h['reason']}" for h in hidden if h["code"] == code)
    return res.mark(Status.SKIPPED, reason[:500], reason_code=code)


# ------------------------------------------------------------------------------------------------------
# Re-check report (cond 7: the offline data of `v3lum doctor --links`)
# ------------------------------------------------------------------------------------------------------


def recheck_report(today: _dt.date, *, max_age_days: int = RECHECK_MAX_AGE_DAYS,
                   packs: Iterable[str] = PACKS) -> list[dict[str, Any]]:
    """Links of the batch packs (core links and x_module_links) that are unverified or were last checked more
    than ``max_age_days`` ago, plus the pending entries: ``[{ref, host, reason, checked_at}]``. Offline: reads
    the pack files only."""
    out: list[dict[str, Any]] = []
    for pack in packs:
        data = _load(pack)[1]
        entries = [(i, "") for i in data.get("links") or []] + [(i, " (module link)") for i in data.get(EXT_KEY) or []]
        for item, kind in entries:
            if not isinstance(item, Mapping):
                continue
            ref = f"{pack}:{item.get('id')}{kind}"
            checked = str(item.get("checked_at") or "")
            if not item.get("verified"):
                out.append({"ref": ref, "host": item.get("host"), "reason": "unverified", "checked_at": checked})
                continue
            try:
                age = (today - _dt.date.fromisoformat(checked)).days
            except ValueError:
                out.append({"ref": ref, "host": item.get("host"), "reason": "checked_at missing or invalid", "checked_at": checked})
                continue
            if age > max_age_days:
                out.append({"ref": ref, "host": item.get("host"), "reason": f"last checked {age} days ago", "checked_at": checked})
            elif age < 0:
                out.append({"ref": ref, "host": item.get("host"), "reason": "checked_at in the future", "checked_at": checked})
        for item in data.get("x_pending") or []:
            if isinstance(item, Mapping):
                out.append({"ref": f"{pack}:{item.get('id')} (pending)", "host": item.get("host"),
                            "reason": f"pending: {item.get('requires')}", "checked_at": ""})
    return out


def terminal_order(rendered: Iterable[_links.RenderedLink]) -> list[_links.RenderedLink]:
    """The cond 6 order: grouped by analyst question (links.LINK_CATEGORIES, first appearance), verified first
    inside a group, then the pack's file order (the curated analyst-value order); the terminal shows the first
    :data:`TERMINAL_MAX_LINKS`."""
    order = {c: i for i, c in enumerate(_links.LINK_CATEGORIES)}
    ranked = sorted(enumerate(rendered), key=lambda p: (order.get(p[1].category, len(order)), not p[1].verified, p[0]))
    return [r for _i, r in ranked]
