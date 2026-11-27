"""ransomware.live (P197): ransomware victim claims - PRO API with the team key, keyless v2 for research.

Final conditions (P197):

* cond 1 - corporate code path: the PRO API (api-pro.ransomware.live, header ``X-API-KEY``) with ONE
  key ``ransomwarelive`` (env ``V3LUM_RANSOMWARELIVE_KEY``; ``V3LUM_RANSOMWARELIVE_PRO_KEY`` is an
  alias of the same key, never a second one). The keyless v2 API (api.ransomware.live) runs only in
  the research profile.
* cond 2 - licence floor: T&C s.5.2 forbids commercial use without the owner's prior written approval
  and v2 is 'not intended for corporate or business use'. Registry classes: v2 ``noncommercial``, PRO
  ``license`` (module terms = noncommercial). Under the corporate profile the policy gate skips the
  module (reason_code 'licence') until legal records that approval in licence_allow: off under the
  corporate profile until licence-cleared.
* cond 3 - until then RansomLook (P196) and ransomfeed (P356) are the corporate defaults; without a
  key or licence the run is one coverage line plus the manual ransomware.live victim-search link
  (``manual_link``, emitted by the engine; the module adds it too when it stops itself).
* cond 4 - ``searchvictims``/``victims/search`` by normalised company name or by domain through the
  shared normaliser of ransomlook (P196); the same victim matching, grouping and 'not listed'
  wording; dedupe through the shared rule ``g09_ransomware_corroborated``. The recent-victims feed
  for watch needs licence-gated, keyed datasets (backlog p1-G09-1).
* cond 5 - cache >= 30 min (provider ttl 6 h; never poll faster than it), <= 60 requests/minute
  (min_interval 1 s; keyless v2: one request per minute per endpoint, so v2 calls wait 61 s after
  the previous one); raw records are never re-served or re-published; 'Source: Ransomware.live'
  with a link on every result.
* cond 6 - claim_url onions and screenshot URLs are never fetched or embedded: the claim link appears
  defanged, the screenshot as a link with a warning. Ransom-note contacts (onions, e-mail) and group
  IOCs (PRO) become hostile pivots with ``expand=False``; the PRO key is redacted everywhere (AR01:
  it travels only in a header and is registered with the central redactor).
* cond 7 - PRO success fixtures are captured with the team key (backlog p1-G09-1): the PRO shapes
  are tested from the swagger description until then. Registry provider ``ransomware_live``: tier
  community.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from v3lum.core import sanitize
from v3lum.core.entities import Entity, defang
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.darkweb_ransomware.ransomfeed import could_not_verify
from v3lum.modules.darkweb_ransomware.ransomlook import (
    _as_of,
    _loads,
    actor_profile,
    excerpt,
    extract_onions,
    make_claim,
    normalize_group_alias,
    not_listed_wording,
    onion_host,
    report_claims,
    search_term,
)

SOURCE_V2 = "ransomware_live.v2"
SOURCE_PRO = "ransomware_live.pro"
SOURCE_IOCS = "ransomware_live.pro_iocs"
SOURCE_NOTES = "ransomware_live.pro_notes"
KEY = "ransomwarelive"
V2_SEARCH_URL = "https://api.ransomware.live/v2/searchvictims/{term}"
V2_GROUP_URL = "https://api.ransomware.live/v2/group/{group}"
PRO_SEARCH_URL = "https://api-pro.ransomware.live/victims/search"
PRO_GROUP_URL = "https://api-pro.ransomware.live/group/{group}"
PRO_IOCS_URL = "https://api-pro.ransomware.live/iocs/{group}"
PRO_NOTES_URL = "https://api-pro.ransomware.live/ransomnotes/{group}"
PRO_NOTE_URL = "https://api-pro.ransomware.live/ransomnotes/{group}/{note}"
HOME = "https://www.ransomware.live/"
MANUAL_SEARCH = "https://www.ransomware.live/search?q={q}"
ATTRIBUTION = "Source: Ransomware.live (https://www.ransomware.live/)"
SCREENSHOT_PREFIX = "https://images.ransomware.live/"
SCREENSHOT_WARNING = "screenshot may show leaked documents - never fetched or embedded by V3LUM"
#: keyless v2: one request per minute PER ENDPOINT (research C0457)
V2_MIN_INTERVAL = 61.0
MAX_IOC_PIVOTS = 50
#: IOC type names of the PRO API (swagger: md5, sha256, ip, domain, email, btc, url) -> entity types
IOC_TYPES: dict[str, T] = {
    "md5": T.MD5, "sha1": T.SHA1, "sha256": T.SHA256, "sha512": T.SHA512, "ip": T.IPV4, "ipv4": T.IPV4, "ipv6": T.IPV6,
    "domain": T.DOMAIN, "url": T.URL, "email": T.EMAIL, "btc": T.BTC, "bitcoin": T.BTC, "eth": T.ETH, "xmr": T.XMR,
    "monero": T.XMR, "onion": T.ONION,
}
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")
_QTOX_RE = re.compile(r"\b[0-9A-F]{76}\b", re.I)
_V2_NOT_FOUND = "no victims found"


def _infostealer_counts(value: Any) -> dict[str, int] | None:
    """Only the aggregate HudsonRock counts of a PRO victim (A4 'kept': corporate/user service counts)."""
    if not isinstance(value, dict):
        return None
    out = {k: value[k] for k in ("employees", "users", "thirdparties") if isinstance(value.get(k), int) and not isinstance(value.get(k), bool)}
    return out or None


def normalize_victim(rec: Any) -> dict[str, Any] | None:
    """A v2 victim (victim/domain/group/url), an older v2 row (post_title/group_name/website/post_url) or a
    PRO victim (victim, website, group, id, permalink, infostealer) -> claim record. The screenshot URL
    is kept only when it is an https://images.ransomware.live/ link (shown with a warning, never
    fetched); anything else (embedded image data) is dropped."""
    if not isinstance(rec, dict):
        return None
    shot = rec.get("screenshot")
    screenshot = shot if isinstance(shot, str) and shot.startswith(SCREENSHOT_PREFIX) and len(shot) < 300 else None
    src = rec.get("permalink") or rec.get("url")
    return make_claim(
        "ransomware_live",
        victim=rec.get("victim") or rec.get("post_title"),
        group=rec.get("group") or rec.get("group_name"),
        claimed_at=rec.get("discovered") or rec.get("published"),
        attack_date=rec.get("attackdate") or rec.get("published"),
        website=rec.get("domain") or rec.get("website"),
        description=rec.get("description"),
        country=rec.get("country"),
        sector=rec.get("activity") if rec.get("activity") not in ("Not Found", "Unknown") else None,
        claim_url=rec.get("claim_url") or rec.get("post_url"),
        source_url=src if isinstance(src, str) and src.startswith("https://www.ransomware.live/") else None,
        record_id=rec.get("id"),
        extra={k: v for k, v in (("screenshot_url", screenshot), ("infostealer_counts", _infostealer_counts(rec.get("infostealer")))) if v},
    )


def parse_victims(doc: Any) -> list[dict[str, Any]] | None:
    """Victim lists of v2 (/searchvictims, /recentvictims) and PRO (/victims/search, a list or
    {'victims': [...]}) -> claim records; None when the answer is not a victim list."""
    if isinstance(doc, dict):
        for key in ("victims", "data", "results"):
            if isinstance(doc.get(key), list):
                doc = doc[key]
                break
    if not isinstance(doc, list):
        return None
    return [c for c in (normalize_victim(r) for r in doc[:5000]) if c]


def parse_group(doc: Any) -> dict[str, Any] | None:
    """A group card (v2 /group/{name}, PRO /group/{name}) -> {name, altname, about, onions, url}; None
    when the answer is not a card."""
    if isinstance(doc, list) and len(doc) == 1:
        doc = doc[0]
    if not isinstance(doc, dict):
        return None
    name = doc.get("name") or doc.get("group")
    if not isinstance(name, str) or not name.strip():
        return None
    onions = []
    for loc in doc.get("locations") if isinstance(doc.get("locations"), list) else []:
        host = onion_host(loc.get("fqdn") or loc.get("slug")) if isinstance(loc, dict) else None
        if host and host not in onions:
            onions.append(host)
    url = doc.get("url")
    return {
        "name": name.strip()[:100],
        "altname": doc.get("altname") if isinstance(doc.get("altname"), str) else None,
        "about": excerpt(doc.get("description")),
        "onions": onions[:50],
        "url": url if isinstance(url, str) and url.startswith("https://www.ransomware.live/") else None,
    }


def parse_iocs(doc: Any) -> list[tuple[T, str]]:
    """PRO /iocs/{group}: 'organized by type' - accepts {type: [values]}, {'iocs': {type: [...]}},
    {type: [{'value'|'ioc': v}]} and [{'type', 'value'}] until the team-key capture fixes the shape (cond 7).
    Unknown types and invalid values are skipped (the entity layer validates each value)."""
    items: list[tuple[Any, Any]] = []
    container = doc.get("iocs", doc) if isinstance(doc, dict) else doc
    if isinstance(container, dict):
        for typ, values in container.items():
            for val in values if isinstance(values, list) else []:
                items.append((typ, val.get("value") or val.get("ioc") if isinstance(val, dict) else val))
    elif isinstance(container, list):
        for val in container:
            if isinstance(val, dict):
                items.append((val.get("type"), val.get("value") or val.get("ioc")))
    out: list[tuple[T, str]] = []
    for typ, value in items:
        etype = IOC_TYPES.get(str(typ or "").strip().lower())
        if etype is None or not isinstance(value, str) or not value.strip():
            continue
        if etype is T.IPV4 and ":" in value:
            etype = T.IPV6
        if (etype, value.strip()) not in out:
            out.append((etype, value.strip()))
    return out


def note_names(doc: Any) -> list[str]:
    """PRO /ransomnotes/{group}: the note identifiers (a list of names, or {'notes'|'names': [...]})."""
    if isinstance(doc, dict):
        doc = doc.get("notes") or doc.get("names") or []
    names = []
    for item in doc if isinstance(doc, list) else []:
        name = item.get("name") if isinstance(item, dict) else item
        if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9 ._()+-]{1,120}", name.strip()):
            names.append(name.strip())
    return names


def note_contacts(doc: Any) -> dict[str, list[str]]:
    """Contacts printed in a ransom note (cond 6): onion hosts, e-mail addresses and qTox ids. The note
    text itself is never kept."""
    text = doc.get("content") if isinstance(doc, dict) else doc
    text = text[:200_000] if isinstance(text, str) else ""
    return {
        "onions": extract_onions(text),
        "emails": sorted({m.group(0).lower() for m in _EMAIL_RE.finditer(text)})[:20],
        "qtox": sorted({m.group(0).upper() for m in _QTOX_RE.finditer(text)})[:20],
    }


def _licence_profile(ctx: Any) -> str:
    options = getattr(ctx, "options", None)
    requested = str(getattr(options, "licence_profile", "") or "").strip().lower()
    if requested:
        return requested
    try:
        return str(ctx.setting("licence_profile", "corporate") or "corporate").strip().lower()
    except Exception:  # noqa: BLE001 - an unreadable setting is the corporate default (fail closed)
        return "corporate"


@register
class RansomwareLive(Module):
    name = "ransomware_live"
    title = "Ransomware.live victim claims (PRO API; keyless v2 for research)"
    description = (
        "Ransomware leak-site victims tracked by ransomware.live: victim search by normalised company name or domain, "
        "group cards with leak-site onions, group IOCs and ransom-note contacts (PRO). Off under the corporate "
        "profile until licence-cleared (manual search link instead)."
    )
    category = "darkweb_ransomware"
    accepts = {T.ORG, T.DOMAIN, T.KEYWORD, T.THREAT_ACTOR}
    produces = {T.THREAT_ACTOR, T.ONION, T.DOMAIN, T.EMAIL, T.MD5, T.SHA1, T.SHA256, T.URL, T.BTC}
    reference = "https://www.ransomware.live/api"
    notice = (
        "ransomware.live terms (T&C s.5.2) forbid commercial use without the owner's prior written approval; keyless v2 is "
        "'not intended for corporate or business use': off under the corporate profile until legal records that "
        "approval in licence_allow (PRO key 'ransomwarelive', one team token). RansomLook and ransomfeed are the "
        "corporate defaults; the manual ransomware.live victim search is offered instead. Raw records are never "
        f"re-served or re-published (STIX/MISP export to internal platforms only). {ATTRIBUTION}."
    )
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ransomware_live"
    sources = (SOURCE_V2, SOURCE_PRO, SOURCE_IOCS, SOURCE_NOTES)
    hosts = ("api.ransomware.live", "api-pro.ransomware.live")
    access_model = "free_auth_limited"
    optional_keys = (KEY,)
    max_requests = 4
    expected_latency = 0.8
    timeout = 90.0
    min_interval = 1.0
    cache_ttl = 21600
    max_pivots = 80
    manual_link = MANUAL_SEARCH
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return search_term(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        term = search_term(entity)
        if term is None:
            return res.mark("skipped", "nothing searchable left after normalisation", reason_code="not_applicable")
        allowed = ctx.allowed_sources
        key = ctx.key(KEY)
        research = _licence_profile(ctx) == "research"
        pro = SOURCE_PRO in allowed and bool(key)
        v2 = not pro and SOURCE_V2 in allowed and research
        if not pro and not v2:
            return self._not_run(res, term, pro_allowed=SOURCE_PRO in allowed, key=bool(key), research=research)
        if entity.type is T.THREAT_ACTOR:
            return self._actor_pro(entity, ctx, res, term, key, allowed) if pro else self._actor_v2(entity, ctx, res, term)
        if pro:
            resp = ctx.http.get(PRO_SEARCH_URL, params={"q": term}, source=SOURCE_PRO, headers={"X-API-KEY": key, "Accept": "application/json"})
            ctx.http.check(resp)  # 401 (key) -> NEEDS_KEY, 429 -> RATE_LIMITED/QUOTA, 5xx -> ERROR
            claims = parse_victims(_loads(resp.content))
            source = SOURCE_PRO
        else:
            resp = ctx.http.get(V2_SEARCH_URL.format(term=quote(term, safe="")), source=SOURCE_V2,
                                headers={"Accept": "application/json"}, min_interval=V2_MIN_INTERVAL)
            doc = _loads(resp.content)
            if resp.status == 404 and isinstance(doc, dict) and _V2_NOT_FOUND in str(doc.get("error", "")).lower():
                claims = []  # documented 'No victims found for keyword ...': the source answered
            else:
                ctx.http.check(resp)
                claims = parse_victims(doc)
            source = SOURCE_V2
        if claims is None:
            return res.mark("error", "unexpected ransomware.live answer (not a victim list): could not verify")
        as_of = _as_of(ctx, resp)
        _attribute(res)
        summary = report_claims(res, entity, claims, ctx, tracker="ransomware_live", source=source, as_of=as_of,
                                attribution=ATTRIBUTION, produces=frozenset({"threat_actor", "onion", "domain"}))
        for claim in summary["claims"]:
            if claim.get("screenshot_url"):
                res.link(f"{claim['victim'][:60]}: leak-site screenshot ({SCREENSHOT_WARNING})", claim["screenshot_url"])
        res.raw = {source.split(".", 1)[1]: [_raw_victim(c) for c in summary["claims"][:50]]}
        if not summary["matched"]:
            return res.mark("empty")  # 'not listed by Ransomware.live (data as of ...)', never 'not breached'
        return res

    # ------------------------------------------------------------------ cond 3: no key / no licence
    @staticmethod
    def _not_run(res: ModuleResult, term: str, *, pro_allowed: bool, key: bool, research: bool) -> ModuleResult:
        res.link("ransomware.live victim search (manual lookup)", MANUAL_SEARCH.format(q=quote(term, safe="")))
        if pro_allowed and not key:
            return res.mark(
                "needs_key",
                "ransomware.live PRO key 'ransomwarelive' (V3LUM_RANSOMWARELIVE_KEY) not configured; the keyless v2 API runs "
                "only in the research profile - manual ransomware.live search link instead",
                reason_code="needs_key",
            )
        why = "noncommercial (v2) / licence (PRO) terms" if not research else "no research basis covering ransomware.live"
        return res.mark(
            "skipped",
            f"skipped: ransomware.live {why} (licence profile {'research' if research else 'corporate'}) - manual "
            "ransomware.live search link instead",
            reason_code="licence",
        )

    # ------------------------------------------------------------------ threat actors
    def _actor_v2(self, entity: Entity, ctx: Any, res: ModuleResult, term: str) -> ModuleResult:
        group = normalize_group_alias(term)
        resp = ctx.http.get(V2_GROUP_URL.format(group=quote(group, safe="")), source=SOURCE_V2,
                            headers={"Accept": "application/json"}, min_interval=V2_MIN_INTERVAL)
        return self._actor_card(entity, ctx, res, term, resp, SOURCE_V2)

    def _actor_pro(self, entity: Entity, ctx: Any, res: ModuleResult, term: str, key: str, allowed: frozenset[str]) -> ModuleResult:
        group = normalize_group_alias(term)
        headers = {"X-API-KEY": key, "Accept": "application/json"}
        resp = ctx.http.get(PRO_GROUP_URL.format(group=quote(group, safe="")), source=SOURCE_PRO, headers=headers)
        out = self._actor_card(entity, ctx, res, term, resp, SOURCE_PRO)
        if out.status is not Status.OK:
            return out
        name = quote(group, safe="")
        if SOURCE_IOCS in allowed:
            self._feed(res, SOURCE_IOCS, lambda: self._iocs(ctx, res, name, headers))
        if SOURCE_NOTES in allowed:
            if self.sensitive and sanitize.is_second_net_field("content"):
                # A4: the core sanitizer drops 'content' fields of a sensitive provider before the module
                # reads them, so the note text (and its contacts) never arrives: no request is spent on it
                res.source_status(SOURCE_NOTES, Status.SKIPPED, reason_code="policy",
                                  reason="ransom-note text is dropped by the A4 sanitizer of this sensitive provider before it "
                                         "can be read: contacts unavailable (backlog p1-G09-1)")
            else:
                self._feed(res, SOURCE_NOTES, lambda: self._notes(ctx, res, name, headers))
        return res

    @staticmethod
    def _feed(res: ModuleResult, source: str, call: Any) -> None:
        """One optional PRO feed of an actor run: a refusal is recorded per feed (the card stands)."""
        try:
            call()
        except (RateLimited, Blocked, QuotaExceeded, AuthRequired, HttpError, NetworkError) as exc:
            status, code = could_not_verify(exc)
            if isinstance(exc, AuthRequired):
                status, code = Status.NEEDS_KEY, "needs_key"
            res.source_status(source, status, reason_code=code, reason=f"ransomware.live {source.split('.', 1)[1]}: {str(exc)[:160]}")

    def _actor_card(self, entity: Entity, ctx: Any, res: ModuleResult, term: str, resp: Any, source: str) -> ModuleResult:
        doc = _loads(resp.content)
        as_of = _as_of(ctx, resp)
        if resp.status == 404 and isinstance(doc, dict) and (doc.get("error") or doc.get("message")):
            _attribute(res)
            res.attr("ransomware_listing", f"group not tracked by Ransomware.live (data as of {as_of})")
            return res.mark("empty")
        ctx.http.check(resp)
        card = parse_group(doc)
        if card is None:
            return res.mark("error", "unexpected ransomware.live group answer (not a group card): could not verify")
        _attribute(res)
        actor_profile(res, entity, [], ctx, tracker="ransomware_live", source=source, as_of=as_of, attribution=ATTRIBUTION,
                      window_days=None, known=True, canonical=card["name"], extra_onions=card["onions"])
        profile = dict(res.attributes.get("ransomware_group_profile") or {})
        for field in ("altname", "about"):
            if card.get(field):
                profile[field] = card[field]
        res.attr("ransomware_group_profile", profile)
        if card.get("url"):
            res.link(f"Ransomware.live group page: {card['name']}", card["url"])
        res.raw = {source.split(".", 1)[1]: {"name": card["name"], "altname": card.get("altname"),
                                             "locations": [{"fqdn": o} for o in card["onions"][:20]]}}
        return res

    @staticmethod
    def _iocs(ctx: Any, res: ModuleResult, group: str, headers: dict[str, str]) -> None:
        resp = ctx.http.get(PRO_IOCS_URL.format(group=group), source=SOURCE_IOCS, headers=headers)
        ctx.http.check(resp)
        iocs = parse_iocs(_loads(resp.content))
        added = 0
        for etype, value in iocs:
            if added >= MAX_IOC_PIVOTS:
                break
            if res.pivot(etype, value, "group_ioc", confidence="probable", expand=False,
                         note="hostile: IOC published for the group by Ransomware.live (never contact from the corporate egress)") is not None:
                added += 1
        profile = dict(res.attributes.get("ransomware_group_profile") or {})
        profile["iocs"] = {"published": len(iocs), "pivots": added}
        res.attr("ransomware_group_profile", profile)

    @staticmethod
    def _notes(ctx: Any, res: ModuleResult, group: str, headers: dict[str, str]) -> None:
        resp = ctx.http.get(PRO_NOTES_URL.format(group=group), source=SOURCE_NOTES, headers=headers)
        ctx.http.check(resp)
        names = note_names(_loads(resp.content))
        if not names:
            return
        resp = ctx.http.get(PRO_NOTE_URL.format(group=group, note=quote(names[0], safe="")), source=SOURCE_NOTES, headers=headers)
        ctx.http.check(resp)
        contacts = note_contacts(_loads(resp.content) or resp.text)
        for host in contacts["onions"]:
            res.pivot(T.ONION, host, "ransom_contact", confidence="probable", expand=False,
                      note="hostile: contact onion printed in the group's ransom note (never visited automatically)")
        for email in contacts["emails"]:
            res.pivot(T.EMAIL, email, "ransom_contact", confidence="probable", expand=False,
                      note="hostile: contact address printed in the group's ransom note (never contacted)")
        profile = dict(res.attributes.get("ransomware_group_profile") or {})
        profile["ransom_notes"] = {"notes": len(names), "read": names[0], "contact_onions": [defang(o) for o in contacts["onions"]],
                                   "contact_emails": len(contacts["emails"]), "qtox_ids": len(contacts["qtox"])}
        res.attr("ransomware_group_profile", profile)


def _attribute(res: ModuleResult) -> None:
    """'Source: Ransomware.live' with a link on every answered result (cond 5); added only after the
    source answered, so a refusal is never read as partial data."""
    res.attr("data_attribution", ATTRIBUTION)
    res.link("Source: Ransomware.live", HOME)


def _raw_victim(claim: dict[str, Any]) -> dict[str, Any]:
    """Evidence form of a reported claim (metadata only, in the provider's own field names)."""
    out = {
        "victim": claim.get("victim"),
        "group": claim.get("group"),
        "discovered": claim.get("claimed_at"),
        "attackdate": claim.get("attack_date"),
        "domain": claim.get("website"),
        "country": claim.get("country"),
        "activity": claim.get("sector"),
        "url": claim.get("source_url"),
        "screenshot": claim.get("screenshot_url"),
    }
    return {k: v for k, v in out.items() if v is not None}


__all__ = [
    "ATTRIBUTION",
    "RansomwareLive",
    "normalize_victim",
    "not_listed_wording",
    "note_contacts",
    "note_names",
    "parse_group",
    "parse_iocs",
    "parse_victims",
]
