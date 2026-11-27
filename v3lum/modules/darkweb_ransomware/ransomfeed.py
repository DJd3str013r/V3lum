"""Ransomfeed (P356): ransomware leak-site claims from ransomfeed.it (RSS + REST API, CC BY 4.0).

Final conditions (P356):

* cond 1 - the RSS ``rss-complete.php`` (~520 KB, ~600 items) is a registered dataset refreshed at
  most hourly (TTL 3600 s) and parsed with a safe XML parser (expat with every DTD/entity handler
  refusing, no entity expansion; the stand-in for a core safe-XML helper, manifest core request).
  The bytes are parsed as bytes: the HTTP header says iso-8859-1 while the prolog and the bytes are
  UTF-8. HTML is stripped from descriptions (the matomo tracking image is never fetched). Every
  entity is matched offline against it (watch and supplier screening: :func:`match_feed_claims`).
  The per-entity API (``api.ransomfeed.it/search/{name}``, ``/ganginfo/{gang}`` for actor cards -
  ``/gang/{gang}`` returns claims, the card is ``/ganginfo``) is called only for analyst-typed seeds
  and org_profile names (own domains, brands, the organisation's name, suppliers).
* cond 2 - the shared victim-name normaliser and matching of ransomlook (P196): an exact
  domain/website or CNPJ decides severity (CRITICAL for org_profile entities or listed suppliers);
  name-only is POSSIBLE, MEDIUM at most; dedupe through the shared rule ``g09_ransomware_corroborated``.
* cond 3 - claims are actor statements ('claimed by'); descriptions are excerpts of at most 300
  characters; victims who may be natural persons get no description text; claim and onion links are
  never visited (P356 produces threat_actor and domain: leak-site onions of an actor card stay in the
  ``ransomware_group_profile`` attribute, defanged).
* cond 4 - CC BY 4.0: 'Source: Ransomfeed (CC BY 4.0, Dario Fadda)' on every result
  (``data_attribution``), the dataset registration and the notice; registry provider ``ransomfeed``
  (tier community, terms open). Fixtures were cut from the live answers in the gap-sample format.

Politeness: 5 requests per 60 s per IP (api.ransomfeed.it/docs): min_interval 13 s and a token bucket
in the provider fragment; 429 is RATE_LIMITED (could not verify).
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import quote
from xml.parsers import expat

from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity, defang
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.orgprofile import fold
from v3lum.modules.darkweb_ransomware.ransomlook import (
    _as_of,
    _dataset_as_of,
    _loads,
    actor_profile,
    excerpt,
    make_claim,
    match_claim,
    match_claims,
    normalize_group_alias,
    not_listed_wording,
    onion_host,
    report_claims,
    search_term,
    strip_html,
)

SOURCE_RSS = "ransomfeed.rss"
SOURCE_API = "ransomfeed.api"
RSS_URL = "https://ransomfeed.it/rss-complete.php"
RSS_DATASET = "ransomfeed_rss"
SEARCH_URL = "https://api.ransomfeed.it/search/{term}"
GANGINFO_URL = "https://api.ransomfeed.it/ganginfo/{gang}"
ATTRIBUTION = "Source: Ransomfeed (CC BY 4.0, Dario Fadda)"
#: the RSS is ~520 KB; a refusal above 5 MB keeps it a small dataset (downloaded during scans when stale)
RSS_MAX_BYTES = 5_000_000
_XML_MAX_ELEMENTS = 200_000
_XML_MAX_DEPTH = 32
_ITEM_FIELDS = frozenset({"title", "link", "guid", "id", "pubdate", "category", "description"})


class UnsafeXML(ValueError):
    """The RSS was refused: a DTD or entity declaration, too large or too deep, or not well formed."""


def parse_rss(data: bytes | str) -> dict[str, Any]:
    """rss-complete.php -> ``{'title', 'items': [{title, link, guid, id, pubdate, category, description}]}``.

    expat parses the raw bytes (the XML prolog decides the encoding); a DOCTYPE or any entity
    declaration is refused the moment the parser meets it (no entity expansion, no external entity or
    DTD fetched); parameter-entity parsing is off; element count and depth are capped. Raises
    UnsafeXML.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data or b"")
    if len(raw) > RSS_MAX_BYTES:
        raise UnsafeXML(f"RSS larger than {RSS_MAX_BYTES} bytes")
    parser = expat.ParserCreate()
    try:
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    except AttributeError:  # pragma: no cover - present on every CPython build
        pass
    stack: list[str] = []
    items: list[dict[str, str]] = []
    current: dict[str, list[str]] | None = None
    channel_title: list[str] = []
    root: list[str] = []
    count = 0

    def refuse(*_args: Any) -> None:
        raise UnsafeXML("XML with a DOCTYPE or entity declarations is refused (no entity expansion)")

    def start(tag: str, _attrs: dict[str, str]) -> None:
        nonlocal count, current
        count += 1
        if count > _XML_MAX_ELEMENTS or len(stack) >= _XML_MAX_DEPTH:
            raise UnsafeXML("RSS too large or too deep")
        local = tag.rsplit(":", 1)[-1].lower()
        if not stack:
            root.append(local)
        if local == "item" and current is None:
            current = {}
        stack.append(local)

    def end(_tag: str) -> None:
        nonlocal current
        local = stack.pop()
        if local == "item" and current is not None:
            items.append({k: "".join(v).strip() for k, v in current.items()})
            current = None

    def chars(text: str) -> None:
        if not stack:
            return
        local = stack[-1]
        if current is not None and local in _ITEM_FIELDS and len(stack) >= 2 and stack[-2] == "item":
            current.setdefault(local, []).append(text)
        elif current is None and local == "title" and len(stack) >= 2 and stack[-2] == "channel":
            channel_title.append(text)

    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    parser.UnparsedEntityDeclHandler = refuse
    parser.ExternalEntityRefHandler = refuse
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    try:
        parser.Parse(raw, True)
    except expat.ExpatError as exc:
        raise UnsafeXML(f"invalid XML ({expat.ErrorString(exc.code)})") from None
    if root[:1] != ["rss"]:
        raise UnsafeXML("not an RSS 2.0 document")
    return {"title": "".join(channel_title).strip() or None, "items": items}


def rss_claims(data: bytes | str) -> list[dict[str, Any]]:
    """The RSS items -> claim records. 'Target victim website: N/D' means no website; the feed carries
    no description text (a template), so no excerpt is kept."""
    out = []
    for item in parse_rss(data)["items"]:
        desc = strip_html(item.get("description", ""))
        site = re.search(r"Target victim website\s{0,3}:\s{0,3}(\S{1,253})", desc)
        country = re.search(r"The target comes from (.{1,60}?)\s*\.", desc)
        post_id = item.get("id", "")
        claim = make_claim(
            "ransomfeed",
            victim=item.get("title"),
            group=item.get("category"),
            claimed_at=item.get("pubdate"),
            website=site.group(1) if site else None,
            country=country.group(1) if country else None,
            source_url=item.get("link") if (item.get("link") or "").startswith("https://ransomfeed.it/") else None,
            record_id=post_id if post_id.isdigit() else (item.get("guid") or None),
        )
        if claim:
            out.append(claim)
    return out


def api_claim(row: Any) -> dict[str, Any] | None:
    """One api.ransomfeed.it row -> claim record (API dates are Italian local time)."""
    if not isinstance(row, dict):
        return None
    post_id = row.get("id")
    return make_claim(
        "ransomfeed",
        victim=row.get("victim"),
        group=row.get("gang"),
        claimed_at=row.get("date"),
        website=row.get("website"),
        description=row.get("description"),
        country=row.get("country"),
        sector=row.get("work_sector"),
        source_url=f"https://ransomfeed.it/index.php?page=post_details&id_post={post_id}" if isinstance(post_id, int) and not isinstance(post_id, bool) else None,
        record_id=post_id,
        local_tz="Europe/Rome",
    )


def parse_api_claims(doc: Any) -> list[dict[str, Any]] | None:
    """/search/{text} (and /gang/{gang}) answers -> claim records; None when not a list ([] = no results)."""
    if isinstance(doc, dict) and isinstance(doc.get("data"), list):
        doc = doc["data"]
    if not isinstance(doc, list):
        return None
    return [c for c in (api_claim(r) for r in doc[:5000]) if c]


_MD_LINK_RE = re.compile(r"\[([^\]]{1,200})\]\((https?://[^)\s]{1,500})\)")


def parse_ganginfo(doc: Any) -> dict[str, Any] | None:
    """/ganginfo/{gang} -> actor card {name, about, onions, profile_links}; None when not a card."""
    if not isinstance(doc, dict) or not isinstance(doc.get("name"), str) or not doc["name"].strip():
        return None
    onions = []
    for loc in doc.get("locations") if isinstance(doc.get("locations"), list) else []:
        host = onion_host(loc.get("fqdn")) if isinstance(loc, dict) else None
        if host and host not in onions:
            onions.append(host)
    links = []
    for entry in doc.get("profile") if isinstance(doc.get("profile"), list) else []:
        for match in _MD_LINK_RE.finditer(entry if isinstance(entry, str) else ""):
            if match.group(2).startswith("https://"):
                links.append({"text": match.group(1), "url": match.group(2)})
    return {"name": doc["name"].strip()[:100], "about": excerpt(doc.get("description")), "onions": onions[:50], "profile_links": links[:20]}


def match_feed_claims(rss: bytes | str, *, names: Iterable[str] = (), domains: Iterable[str] = (), cnpj_roots: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Offline matching on the hourly RSS (P356 cond 1) for watch and supplier screening; nothing is sent."""
    return match_claims(rss_claims(rss), names=names, domains=domains, cnpj_roots=cnpj_roots)


def _validate_rss(path: Path) -> bool:
    """register_dataset(validate=): an RSS 2.0 document with at least one item."""
    try:
        items = parse_rss(Path(path).read_bytes())["items"]
    except (OSError, UnsafeXML) as exc:
        raise ValueError(f"ransomfeed RSS refused: {exc}") from exc
    if not items:
        raise ValueError("ransomfeed RSS without items")
    return True


register_dataset(
    RSS_DATASET,
    RSS_URL,
    ttl=3600,
    description="Ransomfeed RSS of recent ransomware claims (~600 items; refreshed at most hourly, matched offline, P356 cond 1)",
    licence="CC-BY-4.0",
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="ransomfeed",
    source=SOURCE_RSS,
    validate=_validate_rss,
    min_bytes=200,
    expect="bytes",
    max_bytes=RSS_MAX_BYTES,
    large=False,
)

_MEMO: dict[str, Any] = {"stamp": None, "claims": None}
_LOCK = threading.Lock()


def _load_rss(path: Path) -> list[dict[str, Any]]:
    """The parsed local RSS copy, parsed once per file version."""
    st = Path(path).stat()
    stamp = (str(path), st.st_mtime_ns, st.st_size)
    with _LOCK:
        if _MEMO["stamp"] != stamp:
            _MEMO["claims"] = rss_claims(Path(path).read_bytes())
            _MEMO["stamp"] = stamp
        return list(_MEMO["claims"] or [])


def _org_related(entity: Entity, ctx: Any) -> bool:
    """An org_profile name (P356 cond 1): an own or supplier domain, the organisation's name or brands,
    or a supplier's name or brand."""
    org = getattr(ctx, "org", None)
    if org is None:
        return False
    if entity.type is T.DOMAIN:
        try:
            own = org.owns(entity)
        except Exception:  # noqa: BLE001 - a broken profile never widens the API use
            return False
        return bool(getattr(own, "own", False) or getattr(own, "kind", "") == "supplier")
    value = fold(entity.value)
    names = {fold(getattr(org, "name", ""))} | set(org.brand_terms())
    for supplier in getattr(org, "suppliers", []) or []:
        names.add(fold(getattr(supplier, "name", "")))
        names |= {fold(b) for b in getattr(supplier, "brands", ()) or ()}
    names.discard("")
    return value in names


@register
class Ransomfeed(Module):
    name = "ransomfeed"
    title = "Ransomfeed ransomware leak-site claims"
    description = (
        "Ransomware leak-site claims from ransomfeed.it (CC BY 4.0): every entity is matched offline against the "
        "hourly RSS; analyst-typed seeds and org-profile names are also searched through the API (actor cards for "
        "groups). Claims are actor statements; claim and onion links are never visited."
    )
    category = "darkweb_ransomware"
    accepts = {T.ORG, T.DOMAIN, T.KEYWORD, T.THREAT_ACTOR}
    produces = {T.THREAT_ACTOR, T.DOMAIN}
    tags = {"free"}
    reference = "https://api.ransomfeed.it/docs"
    notice = (
        f"{ATTRIBUTION}. Claims are actor statements (unverified): an exact domain/CNPJ match is high (critical for "
        "org-profile assets and suppliers), a name-only match is 'possible match - verify victim identity'. The API is "
        "searched only for analyst-typed or org-profile names; everything else is matched offline against the hourly RSS. "
        "A miss reads 'not listed by Ransomfeed (data as of <date>)', never 'not breached'."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ransomfeed"
    sources = (SOURCE_RSS, SOURCE_API)
    hosts = ("ransomfeed.it", "api.ransomfeed.it")
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 1.2
    timeout = 60.0
    min_interval = 13.0
    daily_quota = 300
    cache_ttl = 21600
    max_pivots = 60
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return search_term(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        term = search_term(entity)
        if term is None:
            return res.mark("skipped", "nothing searchable left after normalisation", reason_code="not_applicable")
        allowed = ctx.allowed_sources
        rss: list[dict[str, Any]] | None = None
        rss_as_of = ""
        rss_error: Exception | None = None
        if SOURCE_RSS in allowed:
            try:
                rss = _load_rss(ctx.data.fetch(RSS_DATASET))
                rss_as_of = _dataset_as_of(ctx, RSS_DATASET)
            except (DatasetError, DatasetUnavailable, OSError, UnsafeXML) as exc:
                rss_error = exc
                ctx.log(f"Ransomfeed RSS unavailable ({str(exc)[:120]})", "warning")
                res.source_status(SOURCE_RSS, Status.UNAVAILABLE if isinstance(exc, DatasetUnavailable) else Status.ERROR,
                                  reason_code="dataset" if isinstance(exc, DatasetUnavailable) else "error",
                                  reason=f"Ransomfeed RSS could not be read: {str(exc)[:160]}")
        use_api = SOURCE_API in allowed and (self._typed_seed(entity, ctx) or _org_related(entity, ctx))
        api_claims: list[dict[str, Any]] = []
        card: dict[str, Any] | None = None
        api_as_of = ""
        api_error: Exception | None = None
        if use_api:
            try:
                if entity.type is T.THREAT_ACTOR:
                    card, api_as_of = self._ganginfo(entity, ctx, term, rss or [])
                else:
                    api_claims, api_as_of = self._search(ctx, term)
            except (RateLimited, Blocked, QuotaExceeded, AuthRequired, HttpError, NetworkError) as exc:
                api_error = exc
                status, code = could_not_verify(exc)
                res.source_status(SOURCE_API, status, reason_code=code, reason=f"Ransomfeed API could not verify: {str(exc)[:160]}")
        if rss is None and (not use_api or api_error is not None):
            # neither the feed nor the API answered: could not verify (rule 5)
            if api_error is not None:
                return _fail(res, api_error)
            if isinstance(rss_error, DatasetUnavailable):
                raise rss_error
            return res.mark("error", f"Ransomfeed RSS could not be read and the API is used for analyst-typed or org-profile names only: could not verify ({str(rss_error)[:120]})")
        as_of = api_as_of or rss_as_of or ctx.now().date().isoformat()
        # the feed is matched offline: only its claims that match the entity join the API hits (the
        # unrelated rest of the feed is neither a match nor a mention)
        relevant = [c for c in rss or [] if match_claim(c, entity, ctx) is not None or (
            entity.type is T.THREAT_ACTOR and c.get("group_key") == normalize_group_alias(term))]
        claims = _merge(api_claims, relevant)
        coverage = "API search + hourly RSS" if use_api and api_error is None else "hourly RSS (offline match)"
        if entity.type is T.THREAT_ACTOR:
            return self._actor(entity, ctx, res, term, claims, card, as_of, coverage, api_error)
        summary = report_claims(res, entity, claims, ctx, tracker="ransomfeed", source=SOURCE_API if use_api and api_error is None else SOURCE_RSS,
                                as_of=as_of, attribution=ATTRIBUTION, produces=frozenset({"threat_actor", "domain"}))
        key = "api" if use_api and api_error is None else "rss"
        res.raw = {key: {"query": term, "data_as_of": as_of, "counts": {"api_rows": len(api_claims), "rss_items": len(rss or []),
                                                                         "matched": summary["matched"], "mentions": summary["mentions"]},
                         "claims": summary["raw"][:50]}}
        if not summary["matched"]:
            if api_error is not None:
                return _fail(res, api_error)  # the API search could not verify: the feed alone never reads 'not listed'
            res.attr("ransomware_listing", not_listed_wording(["ransomfeed"], as_of) + ("" if key == "api" else " - hourly RSS of recent claims only"))
            return res.mark("empty")
        return res

    # ------------------------------------------------------------------ API calls
    @staticmethod
    def _typed_seed(entity: Entity, ctx: Any) -> bool:
        unconfirmed = getattr(getattr(ctx, "options", None), "unconfirmed_seeds", None) or set()
        return bool(getattr(ctx, "is_seed", False)) and entity.key not in unconfirmed

    @staticmethod
    def _search(ctx: Any, term: str) -> tuple[list[dict[str, Any]], str]:
        resp = ctx.http.get(SEARCH_URL.format(term=quote(term, safe="")), source=SOURCE_API, headers={"Accept": "application/json"})
        ctx.http.check(resp)
        claims = parse_api_claims(_loads(resp.content))
        if claims is None:
            raise HttpError("unexpected Ransomfeed search answer (not a list): could not verify", resp.status, resp.url, b"")
        return claims, _as_of(ctx, resp)

    @staticmethod
    def _ganginfo(entity: Entity, ctx: Any, term: str, rss: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str]:
        gkey = normalize_group_alias(term)
        gang = next((c["group"] for c in rss if c.get("group_key") == gkey and c.get("group")), "") or re.sub(r"\s+", "", term)
        resp = ctx.http.get(GANGINFO_URL.format(gang=quote(gang.lower(), safe="")), source=SOURCE_API, headers={"Accept": "application/json"})
        ctx.http.check(resp)
        doc = _loads(resp.content)
        if doc is None or not isinstance(doc, (dict, list)):
            raise HttpError("unexpected Ransomfeed ganginfo answer (not JSON): could not verify", resp.status, resp.url, b"")
        return parse_ganginfo(doc), _as_of(ctx, resp)

    def _actor(self, entity: Entity, ctx: Any, res: ModuleResult, term: str, claims: list[dict[str, Any]], card: dict[str, Any] | None,
               as_of: str, coverage: str, api_error: Exception | None) -> ModuleResult:
        canonical = card["name"] if card else next((c["group"] for c in claims if c.get("group_key") == normalize_group_alias(term)), "")
        count = actor_profile(res, entity, claims, ctx, tracker="ransomfeed", source=SOURCE_API if card else SOURCE_RSS, as_of=as_of,
                              attribution=ATTRIBUTION, window_days=None, known=bool(card) or None, canonical=canonical,
                              extra_onions=(card or {}).get("onions") or (), pivot_onions=False)
        if card:
            profile = dict(res.attributes.get("ransomware_group_profile") or {})
            if card.get("about"):
                profile["about"] = card["about"]
            if card.get("profile_links"):
                profile["references"] = [link["url"] for link in card["profile_links"]]
                for link in card["profile_links"][:10]:
                    res.link(f"{card['name']}: {link['text']}"[:120], link["url"])
            res.attr("ransomware_group_profile", profile)
        res.raw = {"api" if card else "rss": {"query": term, "data_as_of": as_of, "counts": {"group_claims": count},
                                               "card": {"name": card["name"], "onions": [defang(o) for o in card["onions"][:20]],
                                                        "profile_links": [link["url"] for link in card["profile_links"]]} if card else None}}
        if not card and not count:
            if api_error is not None:
                return _fail(res, api_error)
            res.attr("ransomware_listing", not_listed_wording(["ransomfeed"], as_of) + f" - {coverage}")
            return res.mark("empty")
        return res


def _merge(api: list[dict[str, Any]], rss: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """API rows first, then RSS items not already seen (same record id, or same victim + group + date)."""
    seen_ids = {c["record_id"] for c in api if c.get("record_id")}
    seen_keys = {(c.get("victim_key"), c.get("group_key"), c.get("claimed_date")) for c in api}
    out = list(api)
    for claim in rss:
        if claim.get("record_id") in seen_ids or (claim.get("victim_key"), claim.get("group_key"), claim.get("claimed_date")) in seen_keys:
            continue
        out.append(claim)
    return out


def could_not_verify(exc: Exception) -> tuple[Status, str]:
    """(status, canonical reason code) of a refused or failed request (rule 5: never an absence)."""
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited"
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota"
    if isinstance(exc, Blocked):
        code = str(getattr(exc, "reason_code", "") or "")
        return Status.BLOCKED, code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
    if isinstance(exc, AuthRequired):
        return Status.BLOCKED, "challenge"  # keyless source: a 401/403 is a refusal, never 'no data'
    if "timeout" in str(getattr(exc, "reason_code", "") or "") or "timed out" in str(exc).lower():
        return Status.ERROR, "timeout"
    return Status.ERROR, "error"


def _fail(res: ModuleResult, exc: Exception) -> ModuleResult:
    """End the run 'could not verify' after a partial build: the listing wording is withdrawn."""
    res.attributes.pop("ransomware_listing", None)
    status, code = could_not_verify(exc)
    return res.mark(status, f"Ransomfeed could not verify: {str(exc)[:200]}", reason_code=code)


__all__ = [
    "ATTRIBUTION",
    "could_not_verify",
    "RSS_DATASET",
    "Ransomfeed",
    "UnsafeXML",
    "api_claim",
    "match_feed_claims",
    "parse_api_claims",
    "parse_ganginfo",
    "parse_rss",
    "rss_claims",
]
