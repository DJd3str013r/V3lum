"""RansomLook (P196): ransomware leak-site claims, plus the shared ransomware-claim helpers.

RansomLook (ransomlook.io) tracks ransomware and extortion leak sites; its data is CC BY 4.0 with
commercial use allowed (attribution 'Source: RansomLook (CC BY 4.0)'); the service code is AGPL and
nothing of it is copied here (behaviour re-implemented from the public API documentation).

Final conditions (P196):

* cond 1 - per-entity lookups through ``/api/search?q=<normalised name or domain>`` (bounded:
  ``max_bytes`` 2 MB; an answer cut by the cap is 'could not verify', never a partial list), plus a
  local index synced daily through the dataset manager: ``ransomlook_recent_posts``
  (``/api/last/30``: every post discovered in the last 30 days, the static-URL form of
  ``/api/posts/period/{today-30}/{today}`` - the dataset manager only fetches registered URLs) and
  ``ransomlook_groups`` (``/api/groups``). Matching on the index is offline: threat-actor inputs
  are answered from it (group recognised, recent claims, leak-site onions) and
  :func:`match_recent_claims` serves watch and supplier screening without sending any value.
* cond 2 - ``/api/group/{name}``, ``/api/posts`` and ``/api/export`` (3-163 MB, screenshots inline)
  are never called; there is no code path that builds those URLs.
* cond 3 - the victim-name normaliser (accents folded; LTDA, S.A., S/A, EIRELI, ME, EPP, Inc and
  'Grupo' stripped) and the group-alias normaliser are shared helpers of this file, used by
  ransomware_live (P197), ransomfeed (P356) and the one cross-tracker dedupe rule
  ``g09_ransomware_corroborated`` (v3lum/correlations/g09_ransomware.py: victim + group alias +
  date +/- 3 days, 'corroborated by N trackers'). They move to the core when it offers a home for
  them (P357 needs them too; manifest core request).
* cond 4 - matching (:func:`match_claim`): an exact domain/website or CNPJ match is HIGH, CRITICAL
  when the victim is an org_profile entity or a listed supplier, worded 'claimed by <group> on
  <date> (actor claim, unverified)'; name-only matches are POSSIBLE, MEDIUM at most, 'possible
  match - verify victim identity'. A full-text hit in the description only is a mention, not a
  victim match.
* cond 5 - one finding per victim claim (claims re-posted within 3 days collapse into one);
  cross-tracker grouping is the correlation rule above (scoring the group once is P335/P302). A
  miss reads 'not listed by RansomLook (data as of <date>)', never 'not breached'.
* cond 6 - claims are metadata plus an excerpt of at most 300 characters; victims who may be natural
  persons get no description text; onion and claim URLs are never fetched (they appear defanged,
  as text) and screenshots/images are never downloaded (the ``screen``/``source``/``magnet``
  fields are dropped unread, before the HTTP cache: provider flag ``sensitive``); leak-site onions
  are hostile pivots with ``expand=False``.
* cond 7 - registry provider ``ransomlook`` (seeded: tier community, terms open); every result
  carries ``data_attribution`` 'Source: RansomLook (CC BY 4.0)', as do the dataset registrations.
"""

from __future__ import annotations

import datetime as _dt
import email.utils
import html
import html.parser
import json
import re
import unicodedata
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import psl, sanitize
from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity, defang, normalize_domain
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.core.validators import cnpj_valid, onion_valid

# --------------------------------------------------------------------------------------
# shared ransomware-claim helpers (P196 cond 3; used by ransomware_live, ransomfeed and the
# g09_ransomware correlation pack)
# --------------------------------------------------------------------------------------

TRACKER_LABELS: dict[str, str] = {
    "ransomlook": "RansomLook",
    "ransomware_live": "Ransomware.live",
    "ransomfeed": "Ransomfeed",
}
#: Excerpt limit of claim descriptions (P196 cond 6, P356 cond 3).
CLAIM_EXCERPT_MAX = 300
#: Wording of name-only matches (P196 cond 4).
POSSIBLE_MATCH_TEXT = "possible match - verify victim identity"
#: The cross-tracker dedupe window (P196 cond 3: victim + group alias + date +/- 3 days).
CORROBORATION_DAYS = 3
#: Finding titles (stable: counts and names go to the description and data).
TITLE_CLAIM = "Claimed on a ransomware leak site (actor claim, unverified)"
TITLE_POSSIBLE = "Possible ransomware leak-site claim (name match only)"
HOSTILE_ONION_NOTE = "hostile: ransomware leak site (actor-controlled; never visited automatically)"
MAX_CLAIM_FINDINGS = 25
MAX_ONION_PIVOTS = 10

#: legal-form tokens stripped from the end of a victim name (P196 cond 3 + common foreign forms)
_LEGAL_TOKENS = frozenset({
    "ltda", "eireli", "me", "epp", "inc", "incorporated", "ltd", "limited", "llc", "llp", "plc", "corp",
    "corporation", "gmbh", "ag", "srl", "sro", "lda", "pvt", "pty", "bv", "nv", "sas", "sarl", "spa", "co", "cia",
    "sa", "mei",
})
#: dotted legal forms that tokenise into letters ('S.A.' -> s a, 's.r.o.' -> s r o)
_LEGAL_SEQS: tuple[tuple[str, ...], ...] = (
    ("s", "a"), ("s", "r", "o"), ("s", "r", "l"), ("s", "p", "a"), ("s", "a", "s"), ("b", "v"), ("n", "v"),
)
_GENERIC_TERMS = _LEGAL_TOKENS | {"grupo", "group", "the", "empresa", "company"}
#: a few well-known renames/aliases of leak-site names; the P295 alias index replaces this table
_GROUP_ALIASES: dict[str, str] = {
    "alphv": "blackcat", "alphvblackcat": "blackcat", "cl0p": "clop", "lockbit30": "lockbit3", "lockbitblack": "lockbit3",
    "gentlemen": "thegentlemen", "inc": "incransom", "huntersinternational": "hunters",
}
#: website values trackers use as placeholders (ransomfeed and ransomware.live put example.com on
#: killsec rows; the ransomfeed RSS prints N/D)
PLACEHOLDER_DOMAINS = frozenset({
    "example.com", "example.net", "example.org", "n/d", "nd", "n/a", "na", "-", "--", "none", "null", "unknown",
    "undefined", "not found", "notfound", "?",
})
_HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")
_CNPJ_RE = re.compile(r"(?<!\d)(\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2})(?!\d)")
_ONION_RE = re.compile(r"(?<![a-z2-7])([a-z2-7]{56}\.onion)\b", re.I)
_TZ_ABBREV = {"CET": "+0100", "CEST": "+0200", "UTC": "+0000", "GMT": "+0000"}
#: organisation words: their presence proves an organisation (the natural-person test fails safe)
_ORG_WORDS = frozenset({
    "ltda", "eireli", "epp", "sa", "inc", "ltd", "llc", "llp", "plc", "corp", "corporation", "company", "co", "gmbh", "ag",
    "srl", "sro", "lda", "pvt", "pty", "limited", "group", "grupo", "holding", "holdings", "hospital", "clinic",
    "clinica", "school", "escola", "college", "university", "universidade", "faculdade", "bank", "banco", "prefeitura",
    "municipality", "municipio", "county", "city", "government", "governo", "ministerio", "ministry", "secretaria",
    "associacao", "association", "cooperativa", "cooperative", "foundation", "fundacao", "institute", "instituto",
    "services", "servicos", "solutions", "solucoes", "systems", "sistemas", "technologies", "technology", "tecnologia",
    "comercio", "industria", "industries", "industrial", "partners", "law", "advogados", "advocacia", "contabilidade",
    "consultoria", "engenharia", "engineering", "construcoes", "construction", "logistics", "logistica", "transportes",
    "transport", "alimentos", "foods", "motors", "energy", "energia", "pharma", "farmacia", "labs", "laboratorio",
    "studio", "agency", "agencia", "store", "loja", "shop", "hotel", "resort", "church", "igreja", "club", "clube", "org",
    "seguros", "insurance", "capital", "trust", "finance", "financial", "media", "network", "telecom", "software",
    "medical", "health", "saude", "dental", "odontologia",
})
_NAME_PARTICLES = frozenset({"da", "de", "do", "das", "dos", "e", "van", "von", "der", "di", "del", "la", "le"})


def _text(value: Any, limit: int = 0) -> str:
    """str for str values ('' for anything else), stripped, optionally cut."""
    if not isinstance(value, str):
        return ""
    out = value.strip()
    return out[:limit] if limit else out


def fold_accents(text: Any) -> str:
    """'SOLUÇÕES CONTÁBEIS' -> 'SOLUCOES CONTABEIS' (NFKD, combining marks dropped)."""
    norm = unicodedata.normalize("NFKD", text if isinstance(text, str) else "")
    return "".join(ch for ch in norm if not unicodedata.combining(ch))


class _TextExtractor(html.parser.HTMLParser):
    _SKIP = frozenset({"script", "style", "noscript", "template"})
    _BREAK = frozenset({"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:  # images and links are dropped
        if tag in self._SKIP:
            self._skip += 1
        elif tag in self._BREAK:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip:
            self._skip -= 1
        elif tag in self._BREAK:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def strip_html(text: Any) -> str:
    """HTML -> plain text: tags, tracking images, scripts and styles removed, entities decoded,
    whitespace collapsed (P356 cond 1)."""
    raw = text if isinstance(text, str) else ""
    if "<" not in raw and "&" not in raw:
        return re.sub(r"\s+", " ", raw).strip()
    parser = _TextExtractor()
    try:
        parser.feed(raw)
        parser.close()
        out = "".join(parser.parts)
    except Exception:  # noqa: BLE001 - malformed markup: fall back to a tag strip
        out = html.unescape(re.sub(r"<[^>]{0,2000}>", " ", raw))
    return re.sub(r"\s+", " ", out).strip()


def excerpt(text: Any, limit: int = CLAIM_EXCERPT_MAX) -> str | None:
    """Plain-text excerpt of at most ``limit`` characters (ellipsis included); markdown headings,
    quotes and emphasis markers and HTML are removed first. None for empty text."""
    raw = text if isinstance(text, str) else ""
    raw = re.sub(r"(?m)^[ \t]{0,3}(?:#{1,6}|>+)[ \t]+", "", raw[:20000])
    raw = re.sub(r"\*\*|__|`+", "", raw)
    plain = strip_html(raw)
    if not plain:
        return None
    if len(plain) <= limit:
        return plain
    cut = plain[: limit - 1]
    space = cut.rfind(" ")
    if space > limit * 0.6:
        cut = cut[:space]
    return cut.rstrip(" ,.;:-") + "…"


def _last_sunday(year: int, month: int) -> _dt.date:
    nxt = _dt.date(year + (month == 12), month % 12 + 1, 1)
    day = nxt - _dt.timedelta(days=1)
    return day - _dt.timedelta(days=(day.weekday() - 6) % 7)


def rome_offset(naive: _dt.datetime) -> _dt.timezone:
    """Europe/Rome offset of a naive local time (CEST from the last Sunday of March 02:00 to the last
    Sunday of October 03:00): the ransomfeed API prints Italian local time."""
    start = _dt.datetime.combine(_last_sunday(naive.year, 3), _dt.time(2, 0))
    end = _dt.datetime.combine(_last_sunday(naive.year, 10), _dt.time(3, 0))
    return _dt.timezone(_dt.timedelta(hours=2 if start <= naive < end else 1))


def parse_datetime(value: Any, local_tz: str = "UTC") -> _dt.datetime | None:
    """The timestamp shapes of the trackers -> aware datetime, or None.

    '2026-11-25 22:18:40.220849' (RansomLook, UTC), '2026-11-19T15:49:10+00:00' (ransomware.live),
    '2026-11-25 02:36:30' (ransomfeed API, ``local_tz='Europe/Rome'``), 'Wed, 25 Nov 2026 02:36:32 CET'
    (ransomfeed RSS), epoch seconds or milliseconds. Naive values get ``local_tz`` ('UTC' or
    'Europe/Rome').
    """
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000.0 if value > 10_000_000_000 else float(value)
        try:
            return _dt.datetime.fromtimestamp(seconds, tz=_dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()[:64]
    if re.match(r"^[A-Za-z]{3}, ", text):
        for abbrev, offset in _TZ_ABBREV.items():
            if text.endswith(" " + abbrev):
                text = text[: -len(abbrev)] + offset
                break
        try:
            parsed = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.timezone.utc)
    try:
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = _dt.datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=rome_offset(parsed) if local_tz == "Europe/Rome" else _dt.timezone.utc)
    return parsed


def iso_or_none(value: Any, local_tz: str = "UTC") -> str | None:
    parsed = parse_datetime(value, local_tz)
    return parsed.isoformat() if parsed else None


def date_or_none(value: Any, local_tz: str = "UTC") -> str | None:
    parsed = parse_datetime(value, local_tz)
    return parsed.date().isoformat() if parsed else None


def normalize_victim_name(name: Any) -> str:
    """Shared victim-name normaliser (P196 cond 3; P197 cond 4; P356 cond 2).

    Accents folded, case folded, punctuation removed, a leading 'the' and every 'grupo' token dropped,
    trailing legal forms stripped (LTDA, S.A., S/A, EIRELI, ME, EPP, Inc, Ltd, LLC, GmbH, s.r.o.,
    Pvt...). Falls back to the unstripped tokens when stripping would leave nothing.
    """
    tokens = re.findall(r"[a-z0-9]+", fold_accents(name).casefold()[:400])
    if not tokens:
        return ""
    original = list(tokens)
    if tokens[0] == "the":
        tokens = tokens[1:]
    tokens = [t for t in tokens if t != "grupo"]
    changed = True
    while tokens and changed:
        changed = False
        for seq in _LEGAL_SEQS:
            if len(tokens) > len(seq) and tuple(tokens[-len(seq):]) == seq:
                tokens = tokens[: -len(seq)]
                changed = True
        if len(tokens) > 1 and tokens[-1] in _LEGAL_TOKENS:
            tokens = tokens[:-1]
            changed = True
    return " ".join(tokens or original)


def normalize_group_alias(name: Any) -> str:
    """Shared group-alias normaliser (P196 cond 3): 'The Gentlemen' == 'thegentlemen', 'Inc Ransom' ==
    'incransom', 'LockBit 3.0' == 'lockbit3', 'ALPHV' == 'BlackCat'; a trailing 'ransomware'/'team'
    word is dropped ('Vexy Ransomware' -> 'vexy')."""
    text = fold_accents(name).casefold()[:200].replace("3.0", "3")
    key = re.sub(r"[^a-z0-9]+", "", text)
    stripped = re.sub(r"(ransomware|team)$", "", key)
    key = stripped or key
    return _GROUP_ALIASES.get(key, key)


def victim_domain(value: Any) -> str | None:
    """A tracker's website/domain value -> lower-case host without scheme, path, port, 'www.' or
    trailing dot (IDN as punycode); None for placeholders (example.com, N/D...), IP literals, onions
    and anything that is not a host name."""
    text = _text(value, 500).strip("<>\"'").lower()
    if not text or text in PLACEHOLDER_DOMAINS:
        return None
    if "://" in text:
        try:
            text = urlsplit(text).hostname or ""
        except ValueError:
            return None
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    text = text.rsplit("@", 1)[-1].split(":", 1)[0].rstrip(".")
    if any(ord(ch) > 127 for ch in text):
        try:
            text = normalize_domain(text)
        except (ValueError, UnicodeError):
            return None
    if text.startswith("www."):
        text = text[4:]
    if text in PLACEHOLDER_DOMAINS or not _HOST_RE.match(text) or text.endswith(".onion"):
        return None
    return text


def looks_like_domain(text: Any) -> bool:
    """A bare host name (no spaces): a victim title that is a domain is domain evidence (cond 4)."""
    return isinstance(text, str) and " " not in text.strip() and victim_domain(text) is not None


def victim_domains(website: Any = None, title: Any = None, description: Any = None) -> list[dict[str, str]]:
    """Domain evidence of one claim, strongest first: the tracker's website field, a title that is a
    domain, a description whose first token is a domain ('initech.example Initech Inc. is ...'), and
    'Website:'/'Domain:'/'Target victim website:' labels. Other domains in the text (third parties) are
    ignored."""
    found: list[dict[str, str]] = []

    def add(value: Any, evidence: str) -> None:
        dom = victim_domain(value)
        if dom and dom not in [d["domain"] for d in found]:
            found.append({"domain": dom, "evidence": evidence})

    if website:
        add(website, "website")
    if looks_like_domain(title):
        add(title, "title")
    desc = strip_html(description)[:5000] if isinstance(description, str) else ""
    if desc:
        lead = desc.split(None, 1)[0].rstrip(".,;:") if desc.split() else ""
        if lead and looks_like_domain(lead):
            add(lead, "description_lead")
        for match in re.finditer(r"(?:target victim website|website|domain)\s{0,3}:\s{0,3}([^\s<>,;]{1,253})", desc, re.I):
            add(match.group(1).rstrip("."), "description_label")
    return found


def extract_cnpjs(text: Any) -> list[str]:
    """Valid CNPJs (check digits verified by the core validator) found in claim text: 14 digits each."""
    out: list[str] = []
    for match in _CNPJ_RE.finditer(strip_html(text)[:20000] if isinstance(text, str) else ""):
        digits = re.sub(r"\D", "", match.group(1))
        if len(digits) == 14 and digits != digits[0] * 14 and cnpj_valid(digits) and digits not in out:
            out.append(digits)
    return out


def is_probably_organisation(name: Any, domains: Iterable[str] = ()) -> bool:
    """Fail-safe natural-person test for the 'no description text for natural persons' rule (P196 cond
    6, P356 cond 3): True only with positive evidence of an organisation (an organisation word or
    legal form, a name that is a domain, digits, an acronym, a single-token brand, or domain evidence
    on a name that does not look like 'Given Family'). Anything else counts as a possible natural
    person, whose description text is never kept."""
    raw = _text(name, 300)
    if not raw:
        return False
    if looks_like_domain(raw):
        return True
    tokens = re.findall(r"[a-z0-9]+", fold_accents(raw).casefold())
    if any(t in _ORG_WORDS for t in tokens):
        return True
    if re.search(r"\d", raw) or re.search(r"\b[A-Z]{3,}\b", raw):
        return True
    words = re.findall(r"[^\W\d_]+(?:['-][^\W\d_]+)?", raw)
    person_like = (
        2 <= len(words) <= 5
        and all(w[:1].isupper() or w.casefold() in _NAME_PARTICLES for w in words)
        and sum(1 for w in words if w.casefold() not in _NAME_PARTICLES) >= 2
    )
    if person_like:
        return False
    if len(tokens) == 1:
        return True
    return bool(list(domains))


def onion_host(value: Any) -> str | None:
    """The v3 onion host of a URL or host string (checksum verified by the core validator), else None."""
    text = _text(value, 600).lower()
    if not text:
        return None
    host = text
    if "://" in text:
        try:
            host = urlsplit(text).hostname or ""
        except ValueError:
            return None
    host = host.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    return host if host.endswith(".onion") and onion_valid(host) else None


def extract_onions(*texts: Any) -> list[str]:
    """Valid v3 onion hosts found in the strings (deduplicated, in order)."""
    out: list[str] = []
    for text in texts:
        for match in _ONION_RE.finditer(text[:20000] if isinstance(text, str) else ""):
            host = match.group(1).lower()
            if onion_valid(host) and host not in out:
                out.append(host)
    return out


def make_claim(
    tracker: str,
    *,
    victim: Any,
    group: Any,
    claimed_at: Any,
    website: Any = None,
    description: Any = None,
    attack_date: Any = None,
    country: Any = None,
    sector: Any = None,
    claim_url: Any = None,
    source_url: Any = None,
    record_id: Any = None,
    local_tz: str = "UTC",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """The common normalised claim record of the three tracker modules (None without a victim).

    Claims are actor statements (P196 cond 4/6, P356 cond 3): the record keeps metadata, an excerpt
    of at most 300 characters (None for a possible natural person), the claim URL only as defanged
    text (never fetched) and the leak-site onion hosts.
    """
    victim_s = re.sub(r"\s+", " ", _text(victim, 200))
    if not victim_s:
        return None
    group_s = re.sub(r"\s+", " ", _text(group, 100))
    desc = description if isinstance(description, str) else ""
    domains = victim_domains(website, victim_s, desc)
    is_org = is_probably_organisation(victim_s, [d["domain"] for d in domains])
    claim_s = _text(claim_url, 500)
    onions = extract_onions(claim_s)
    src = _text(source_url, 500)
    rid = record_id if isinstance(record_id, (str, int)) and not isinstance(record_id, bool) else None
    return {
        "tracker": tracker,
        "victim": victim_s,
        "victim_key": normalize_victim_name(victim_s),
        "group": group_s,
        "group_key": normalize_group_alias(group_s),
        "claimed_at": iso_or_none(claimed_at, local_tz),
        "claimed_date": date_or_none(claimed_at, local_tz),
        "attack_date": date_or_none(attack_date, local_tz) if attack_date else None,
        "website": domains[0]["domain"] if domains and domains[0]["evidence"] == "website" else None,
        "domains": domains,
        "cnpjs": extract_cnpjs(desc) if desc else [],
        "country": _text(country, 60) or None,
        "sector": _text(sector, 120) or None,
        "is_organisation": is_org,
        "excerpt": excerpt(desc) if (desc and is_org) else None,
        "claim_url_display": defang(claim_s) if claim_s else None,
        "onions": onions,
        "source_url": src if src.startswith("https://") else None,
        "record_id": str(rid) if rid is not None else None,
        **(extra or {}),
    }


def claim_compact_key(claim: dict[str, Any]) -> str:
    """Spacing-insensitive victim key: a domain-shaped victim gives its first label ('grupo' dropped)."""
    victim = claim.get("victim") or ""
    if looks_like_domain(victim):
        label = re.sub(r"[^a-z0-9]", "", (victim_domain(victim) or "").split(".", 1)[0])
        return re.sub(r"^(?:grupo|group)", "", label) or label
    return str(claim.get("victim_key") or "").replace(" ", "")


def claim_key(claim: dict[str, Any]) -> str:
    """Deterministic key of one claim: '<victim key>|<group alias>|<claimed date>'."""
    return f"{claim.get('victim_key') or claim_compact_key(claim)}|{claim.get('group_key') or ''}|{claim.get('claimed_date') or ''}"


def _date(value: Any) -> _dt.date | None:
    try:
        return _dt.date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def claims_corroborate(a: dict[str, Any], b: dict[str, Any], days: int = CORROBORATION_DAYS) -> bool:
    """The shared dedupe test (P196 cond 3): same group alias AND the same victim (normalised name,
    compact name or a shared victim domain) AND claim dates within +/- ``days`` days."""
    if not a.get("group_key") or a.get("group_key") != b.get("group_key"):
        return False
    da, db = _date(a.get("claimed_date")), _date(b.get("claimed_date"))
    if da is None or db is None or abs((da - db).days) > days:
        return False
    if a.get("victim_key") and a.get("victim_key") == b.get("victim_key"):
        return True
    ca, cb = claim_compact_key(a), claim_compact_key(b)
    if ca and ca == cb:
        return True
    doms_a = {d.get("domain") for d in a.get("domains") or [] if isinstance(d, dict)}
    doms_b = {d.get("domain") for d in b.get("domains") or [] if isinstance(d, dict)}
    return bool((doms_a & doms_b) - {None})


def corroboration_groups(records: list[dict[str, Any]], days: int = CORROBORATION_DAYS) -> list[list[int]]:
    """Union-find over claims: one list of record indices per victim claim."""
    parent = list(range(len(records)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(records)):
        for j in range(i + 1, len(records)):
            if claims_corroborate(records[i], records[j], days):
                parent[find(j)] = find(i)
    groups: dict[int, list[int]] = {}
    for i in range(len(records)):
        groups.setdefault(find(i), []).append(i)
    return sorted(groups.values())


def tracker_label(tracker: str) -> str:
    return TRACKER_LABELS.get(tracker, tracker)


def corroboration_text(trackers: Iterable[str]) -> str:
    """'corroborated by N trackers: A, B' (P196 cond 3)."""
    names = sorted({tracker_label(t) for t in trackers})
    return f"corroborated by {len(names)} trackers: {', '.join(names)}"


def claim_wording(claim: dict[str, Any]) -> str:
    """'claimed by <group> on <date> (actor claim, unverified)' (P196 cond 4)."""
    return f"claimed by {claim.get('group') or 'an unknown group'} on {claim.get('claimed_date') or 'an unknown date'} (actor claim, unverified)"


def not_listed_wording(trackers: Iterable[str], as_of: str) -> str:
    """The miss wording (P196 cond 5): never 'not breached'."""
    return f"not listed by {', '.join(tracker_label(t) for t in trackers)} (data as of {as_of})"


def search_term(entity: Entity) -> str | None:
    """The per-entity lookup term (P196 cond 1, P197 cond 4, P356 cond 1): the domain for domains, the
    normalised victim name for company names and keywords, the folded name for actors, the host for
    onions. None when nothing searchable is left (fewer than 3 characters, or only legal forms and
    generic words such as 'S/A', 'LTDA', 'Grupo')."""
    value = str(entity.value or "")
    if entity.type is T.DOMAIN:
        dom = value.lower().rstrip(".")
        return dom[4:] if dom.startswith("www.") else dom
    if entity.type is T.ONION:
        return onion_host(value)
    if entity.type is T.THREAT_ACTOR:
        term = re.sub(r"\s+", " ", fold_accents(value).casefold()).strip()
        return term if len(term.replace(" ", "")) >= 3 else None
    if entity.type in (T.ORG, T.KEYWORD):
        if looks_like_domain(value):
            return victim_domain(value)
        term = normalize_victim_name(value)
        tokens = term.split()
        if not tokens or all(t in _GENERIC_TERMS or len(t) == 1 for t in tokens):
            return None
        return term if len(term.replace(" ", "")) >= 3 else None
    return None


def domains_match(claim_domain: str, domain: str) -> bool:
    """Exact domain/website match on a label boundary: equal hosts, or one a subdomain of the other
    when the shorter one is the registrable domain ('www.acme.com.br' and 'portal.acme.com.br' match
    'acme.com.br'; 'acme.com.br' never matches 'evilacme.com.br')."""
    a, b = claim_domain.lower().rstrip("."), domain.lower().rstrip(".")
    a, b = (a[4:] if a.startswith("www.") else a), (b[4:] if b.startswith("www.") else b)
    if a == b:
        return True
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return long_.endswith("." + short) and psl.registrable_domain(long_) == short


def _org_relation(ctx: Any, domain: str) -> str:
    """'own' / 'supplier' / '' for a victim domain, through the org profile (PSL + label match)."""
    org = getattr(ctx, "org", None)
    owns = getattr(org, "owns", None)
    if not callable(owns) or not domain:
        return ""
    try:
        own = owns(Entity.make(T.DOMAIN, domain))
    except (ValueError, TypeError):
        return ""
    if getattr(own, "own", False):
        return "own"
    return "supplier" if getattr(own, "kind", "") == "supplier" else ""


def _org_cnpj_roots(ctx: Any) -> set[str]:
    roots = getattr(getattr(ctx, "org", None), "cnpj_roots", None) or []
    return {re.sub(r"\D", "", str(r))[:8] for r in roots if re.sub(r"\D", "", str(r))}


def match_claim(claim: dict[str, Any], entity: Entity, ctx: Any = None) -> dict[str, Any] | None:
    """Victim matching and severity of one claim for the investigated entity (P196 cond 4, P356 cond 2).

    * exact domain/website (website field, a domain-shaped title, the description's lead token or a
      'Website:' label) or a CNPJ whose root is the organisation's -> HIGH, CRITICAL for org_profile
      entities and listed suppliers, PROBABLE (the identity matches; the claim stays unverified);
    * a claim on an org_profile or supplier domain is CRITICAL whatever was searched;
    * name-only (normalised victim name equal to the searched name) -> MEDIUM, POSSIBLE,
      'possible match - verify victim identity'; never for threat-actor or onion inputs.
    Returns None for a mention (the term appears elsewhere in the post) or an unrelated claim.
    """
    strong = [d["domain"] for d in claim.get("domains") or [] if isinstance(d, dict) and d.get("domain")]
    wording = claim_wording(claim)
    if entity.type is T.DOMAIN:
        for dom in strong:
            if domains_match(dom, str(entity.value)):
                rel = _org_relation(ctx, str(entity.value))
                return {"match_type": "domain", "matched": dom, "org_relation": rel,
                        "severity": "critical" if rel else "high", "confidence": "probable", "text": wording}
    for dom in strong:
        rel = _org_relation(ctx, dom)
        if rel:
            return {"match_type": "domain", "matched": dom, "org_relation": rel, "severity": "critical",
                    "confidence": "probable", "text": wording}
    roots = _org_cnpj_roots(ctx)
    for cnpj in claim.get("cnpjs") or []:
        if str(cnpj)[:8] in roots:
            return {"match_type": "cnpj", "matched": str(cnpj), "org_relation": "own", "severity": "critical",
                    "confidence": "probable", "text": wording}
    if entity.type in (T.ORG, T.KEYWORD):
        nkey = normalize_victim_name(entity.value)
        vkey = str(claim.get("victim_key") or "")
        if nkey and vkey and (nkey == vkey or claim_compact_key(claim) == nkey.replace(" ", "")):
            return {"match_type": "name", "matched": claim.get("victim"), "org_relation": "", "severity": "medium",
                    "confidence": "possible", "text": f"{POSSIBLE_MATCH_TEXT}: {wording}"}
    if entity.type is T.DOMAIN:
        label = (psl.registrable_domain(str(entity.value)) or str(entity.value)).split(".", 1)[0]
        compact = re.sub(r"[^a-z0-9]", "", label.lower())
        if len(compact) >= 4 and compact == claim_compact_key(claim):
            return {"match_type": "name", "matched": claim.get("victim"), "org_relation": "", "severity": "medium",
                    "confidence": "possible", "text": f"{POSSIBLE_MATCH_TEXT}: {wording}"}
    return None


def match_claims(
    claims: Iterable[dict[str, Any]], *, names: Iterable[str] = (), domains: Iterable[str] = (), cnpj_roots: Iterable[str] = ()
) -> list[dict[str, Any]]:
    """Offline claim matching for watch and supplier screening (P196 cond 1, P356 cond 1): the claims
    whose victim website/domain equals one of ``domains`` (label boundary), whose CNPJ has one of
    ``cnpj_roots`` or whose normalised victim name equals one of ``names``; each hit gets
    'match_type' domain | cnpj | name (the same severity rules as :func:`match_claim` apply when it is
    reported). Nothing is sent anywhere."""
    keys = {normalize_victim_name(n) for n in names if normalize_victim_name(n)}
    compact = {k.replace(" ", "") for k in keys}
    doms = [d for d in (victim_domain(x) for x in domains) if d]
    roots = {re.sub(r"\D", "", str(r))[:8] for r in cnpj_roots if re.sub(r"\D", "", str(r))}
    out = []
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        kind = ""
        if any(domains_match(d["domain"], dom) for d in claim.get("domains") or [] for dom in doms):
            kind = "domain"
        elif any(str(c)[:8] in roots for c in claim.get("cnpjs") or []):
            kind = "cnpj"
        elif claim.get("victim_key") in keys or claim_compact_key(claim) in compact:
            kind = "name"
        if kind:
            out.append({**claim, "match_type": kind})
    return out


def _merge_claims(claims: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Collapse re-posts of one tracker (same victim + group alias within +/- 3 days)."""
    return [[claims[i] for i in grp] for grp in corroboration_groups(claims)]


def _summary(claim: dict[str, Any], match: dict[str, Any] | None = None) -> dict[str, Any]:
    out = {
        "tracker": claim.get("tracker"),
        "victim": claim.get("victim"),
        "group": claim.get("group"),
        "claimed_date": claim.get("claimed_date"),
    }
    if match is not None:
        out["match_type"] = match["match_type"]
        out["severity"] = match["severity"]
    return out


def raw_claim(claim: dict[str, Any], match: dict[str, Any] | None = None, query_match: str | None = None) -> dict[str, Any]:
    """The compact evidence form of a claim (``res.raw``; no description text)."""
    out = {
        "victim": claim.get("victim"),
        "group": claim.get("group"),
        "claimed_at": claim.get("claimed_at"),
        "attack_date": claim.get("attack_date"),
        "website": claim.get("website"),
        "country": claim.get("country"),
        "sector": claim.get("sector"),
        "record_id": claim.get("record_id"),
        "source_url": claim.get("source_url"),
        "match_type": match["match_type"] if match else None,
        "query_match": query_match,
    }
    return {k: v for k, v in out.items() if v is not None}


def report_claims(
    res: ModuleResult,
    entity: Entity,
    claims: list[dict[str, Any]],
    ctx: Any,
    *,
    tracker: str,
    source: str,
    as_of: str,
    attribution: str,
    produces: frozenset[str],
) -> dict[str, Any]:
    """Turn the matched claims of one tracker into findings, pivots and attributes (shared by the three
    tracker modules: the same matching, grouping and 'not listed' wording, P197 cond 4).

    Returns ``{'matched': n, 'mentions': m, 'raw': [...], 'claims': [the reported claims]}``. Pivots: the claiming group
    (``victim_of``), leak-site onions (hostile, ``expand=False``) when the tracker produces onions,
    victim websites (``victim_website``, ``expand=False``) when it produces domains.
    """
    matched: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    mentions = 0
    raw: list[dict[str, Any]] = []
    for group in _merge_claims(claims):
        best = None
        for claim in group:
            match = match_claim(claim, entity, ctx)
            if match is not None and (best is None or _rank(match) > _rank(best[0])):
                best = (match, claim)
        if best is None:
            mentions += 1  # the term appears in the post text only: counted, never kept or matched
            continue
        match, claim = best
        matched.append((match, sorted(group, key=lambda c: c.get("claimed_at") or "")))
        raw.append(raw_claim(claim, match, "victim"))
    # most severe first, then the latest claim first
    matched.sort(key=lambda item: item[1][-1].get("claimed_at") or "", reverse=True)
    matched.sort(key=lambda item: -_rank(item[0]))
    summaries = []
    onions_done = 0
    for match, group in matched[:MAX_CLAIM_FINDINGS]:
        claim = group[-1]  # the latest post of the group carries the freshest metadata
        first, last = group[0].get("claimed_at"), group[-1].get("claimed_at")
        summaries.append(_summary(claim, match))
        title = TITLE_POSSIBLE if match["match_type"] == "name" else TITLE_CLAIM
        org_note = {"own": " The victim is an organisation asset (org profile).", "supplier": " The victim is a listed supplier (org profile)."}.get(match.get("org_relation", ""), "")
        desc = f"{claim['victim']}: {match['text']}.{org_note}"
        if claim.get("excerpt"):
            desc += f" Post excerpt: {claim['excerpt']}"
        if claim.get("claim_url_display"):
            desc += f" Leak-site link (never opened automatically): {claim['claim_url_display']}."
        desc += f" {attribution} (data as of {as_of})."
        criterion = _criterion(match)
        data = {
            "tracker": tracker,
            "victim": claim["victim"],
            "victim_key": claim.get("victim_key"),
            "group": claim.get("group"),
            "group_key": claim.get("group_key"),
            "claimed_at": claim.get("claimed_at"),
            "claimed_date": claim.get("claimed_date"),
            "attack_date": claim.get("attack_date"),
            "country": claim.get("country"),
            "sector": claim.get("sector"),
            "domains": claim.get("domains") or [],
            "match_type": match["match_type"],
            "matched": match["matched"],
            "org_relation": match.get("org_relation") or None,
            "posts": len(group),
            "excerpt": claim.get("excerpt"),
            "claim_url_display": claim.get("claim_url_display"),
            "source_url": claim.get("source_url"),
            "record_id": claim.get("record_id"),
            "data_as_of": as_of,
            "attribution": attribution,
        }
        for key in ("screenshot_url", "infostealer_counts"):
            if claim.get(key):
                data[key] = claim[key]
        res.finding(
            title,
            match["severity"],
            desc,
            confidence=match["confidence"],
            criterion=criterion,
            data={k: v for k, v in data.items() if v not in (None, "", [])},
            tags=["ransomware", "ransomware_claim"],
            references=[claim["source_url"]] if claim.get("source_url") else [],
            source=source,
            observed_first=first,
            observed_last=last,
            key=claim_key(claim),
        )
        conf = match["confidence"]
        if claim.get("group") and "threat_actor" in produces:
            res.pivot(T.THREAT_ACTOR, claim["group"], "victim_of", confidence=conf,
                      note=f"{tracker_label(tracker)}: {claim_wording(claim)}")
        if "onion" in produces:
            for host in claim.get("onions") or []:
                if onions_done < MAX_ONION_PIVOTS and res.pivot(
                    T.ONION, host, "leak_site", confidence=conf, expand=False, note=HOSTILE_ONION_NOTE
                ) is not None:
                    onions_done += 1
        if "domain" in produces and entity.type is not T.DOMAIN:
            for dom in claim.get("domains") or []:
                res.pivot(T.DOMAIN, dom["domain"], "victim_website", confidence=conf, expand=False,
                          note=f"victim website on a {tracker_label(tracker)} claim ({dom['evidence']}): actor claim, unverified")
    label = tracker_label(tracker)
    if matched:
        latest = max((g[-1].get("claimed_date") or "" for _m, g in matched), default="")
        res.attr("ransomware_listing", f"listed by {label}: {len(matched)} claim(s)" + (f", latest {latest}" if latest else "") + f" (data as of {as_of})")
        res.attr("ransomware_claims", summaries)
    else:
        res.attr("ransomware_listing", not_listed_wording([tracker], as_of))
    if mentions:
        res.attr("ransomware_mentions", mentions)
    res.attr("data_attribution", attribution)
    return {"matched": len(matched), "mentions": mentions, "raw": raw, "claims": [group[-1] for _match, group in matched]}


def _rank(match: dict[str, Any]) -> int:
    return {"critical": 3, "high": 2, "medium": 1}.get(match.get("severity", ""), 0)


def _criterion(match: dict[str, Any]) -> str:
    kind = match["match_type"]
    if kind == "domain":
        base = f"victim website/domain on the claim ({match['matched']}) matches exactly (label boundary)"
    elif kind == "cnpj":
        base = "a CNPJ printed on the claim has the organisation's CNPJ root (check digits verified)"
    else:
        return ("victim name equal after normalisation (accents folded, legal forms stripped) - "
                f"{POSSIBLE_MATCH_TEXT}: homonyms are common (one name can cover many separate companies)")
    rel = {"own": "; the victim is an org_profile asset", "supplier": "; the victim is a listed supplier"}.get(match.get("org_relation", ""), "")
    return base + rel + "; the claim itself is an actor statement (unverified)"


def actor_profile(
    res: ModuleResult,
    entity: Entity,
    claims: list[dict[str, Any]],
    ctx: Any,
    *,
    tracker: str,
    source: str,
    as_of: str,
    attribution: str,
    window_days: int | None,
    known: bool | None,
    canonical: str = "",
    extra_onions: Iterable[str] = (),
    pivot_onions: bool = True,
) -> int:
    """Threat-actor view of one tracker: the group's claims (offline), leak-site onions as hostile
    pivots and org_profile/supplier victims among them (CRITICAL, through :func:`match_claim`).
    Returns the number of claims of the group."""
    gkey = normalize_group_alias(canonical or entity.value)
    own = [c for c in claims if c.get("group_key") == gkey]
    own.sort(key=lambda c: c.get("claimed_at") or "")
    onions: list[str] = []
    for claim in own:
        for host in claim.get("onions") or []:
            if host not in onions:
                onions.append(host)
    for host in extra_onions:
        if host not in onions:
            onions.append(host)
    profile = {
        "tracker": tracker,
        "name": canonical or str(entity.value),
        "known": known,
        "claims_seen": len(own),
        "latest_claim": own[-1].get("claimed_date") if own else None,
        "window_days": window_days,
        "leak_sites": [defang(o) for o in onions[:MAX_ONION_PIVOTS]],
    }
    res.attr("ransomware_group_profile", {k: v for k, v in profile.items() if v is not None})
    if canonical:
        res.attr("ransomware_group", canonical)
    res.attr("data_attribution", attribution)
    for host in onions[:MAX_ONION_PIVOTS] if pivot_onions else []:
        res.pivot(T.ONION, host, "leak_site", confidence="probable", expand=False, note=HOSTILE_ONION_NOTE)
    if known or own:
        window = f" in the last {window_days} days" if window_days else ""
        res.finding(
            f"Ransomware group tracked by {tracker_label(tracker)}",
            "info",
            f"{profile['name']}: {len(own)} leak-site claim(s){window}"
            + (f", latest {profile['latest_claim']}" if profile["latest_claim"] else "")
            + f". Claims are actor statements (unverified). {attribution} (data as of {as_of}).",
            confidence="probable",
            data={k: v for k, v in profile.items() if v is not None},
            tags=["ransomware"],
            source=source,
            observed_last=own[-1].get("claimed_at") if own else None,
        )
    # the actor's claims on org_profile assets or listed suppliers are CRITICAL whatever was searched
    victims = [c for c in own if match_claim(c, entity, ctx) is not None]
    if victims:
        report_claims(res, entity, victims, ctx, tracker=tracker, source=source, as_of=as_of, attribution=attribution,
                      produces=frozenset({"onion"}) if pivot_onions else frozenset())
    return len(own)


def _loads(content: bytes | str) -> Any:
    try:
        text = content.decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else str(content)
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


# --------------------------------------------------------------------------------------
# RansomLook
# --------------------------------------------------------------------------------------

SOURCE_API = "ransomlook.api"
SOURCE_GROUPS = "ransomlook.ransomlook_groups_index"
SEARCH_URL = "https://www.ransomlook.io/api/search"
RECENT_WINDOW_DAYS = 30
RECENT_POSTS_URL = f"https://www.ransomlook.io/api/last/{RECENT_WINDOW_DAYS}"
GROUPS_URL = "https://www.ransomlook.io/api/groups"
RECENT_DATASET = "ransomlook_recent_posts"
GROUPS_DATASET = "ransomlook_groups"
ATTRIBUTION = "Source: RansomLook (CC BY 4.0)"
#: P196 cond 1: per-entity lookups are bounded
SEARCH_MAX_BYTES = 2 * 1024 * 1024
#: post fields read by the module; 'screen' (base64 screenshots or paths), 'source' (base64 HTML) and
#: 'magnet' are never kept (cond 6)
_POST_FIELDS = ("post_title", "discovered", "description", "link", "group_name", "misp_uuid", "private", "website")

sanitize.register_schema(
    SOURCE_API,
    keep=[
        *(f"posts[].{f}" for f in _POST_FIELDS),
        *(f"[].{f}" for f in _POST_FIELDS),
        "groups[].name",
        "groups[].meta",
        "query",
        "data_as_of",
        "counts.*",
        "claims[].victim",
        "claims[].group",
        "claims[].claimed_at",
        "claims[].attack_date",
        "claims[].website",
        "claims[].country",
        "claims[].sector",
        "claims[].record_id",
        "claims[].source_url",
        "claims[].match_type",
        "claims[].query_match",
    ],
    notes=(
        "P196 cond 6 / A4: posts keep title, dates, group, link and description (read for the <= 300-char excerpt "
        "and the domain/CNPJ evidence; the module's evidence keeps metadata only); screenshots (screen), base64 page "
        "sources and magnets are dropped before the HTTP cache and never read. Ransom-note text (notes) is not kept."
    ),
)


def _validate_posts(path: Path) -> bool:
    """register_dataset(validate=): a JSON list of post objects (an empty window is valid)."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise ValueError(f"not valid JSON ({str(exc)[:80]})") from exc
    if not isinstance(doc, list):
        raise ValueError("RansomLook recent posts: expected a JSON list")
    if doc and not any(isinstance(p, dict) and isinstance(p.get("post_title"), str) for p in doc):
        raise ValueError("RansomLook recent posts: no post object with a post_title")
    return True


def _validate_groups(path: Path) -> bool:
    """register_dataset(validate=): a JSON list of group-name strings (RansomLook tracks hundreds)."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise ValueError(f"not valid JSON ({str(exc)[:80]})") from exc
    if not isinstance(doc, list) or sum(1 for n in doc if isinstance(n, str) and n.strip()) < 5:
        raise ValueError("RansomLook groups: expected a JSON list of group names")
    return True


register_dataset(
    RECENT_DATASET,
    RECENT_POSTS_URL,
    ttl=86400,
    description=f"RansomLook posts discovered in the last {RECENT_WINDOW_DAYS} days (daily local index for offline matching, P196 cond 1)",
    licence="CC-BY-4.0",
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="ransomlook",
    source=SOURCE_API,
    validate=_validate_posts,
    min_bytes=2,
    expect="json",
    max_bytes=5_000_000,
    large=False,
)
register_dataset(
    GROUPS_DATASET,
    GROUPS_URL,
    ttl=86400,
    description="RansomLook tracked group names (daily local index, P196 cond 1)",
    licence="CC-BY-4.0",
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="ransomlook",
    source=SOURCE_GROUPS,
    validate=_validate_groups,
    min_bytes=20,
    expect="json",
    max_bytes=1_000_000,
    large=False,
)


def normalize_post(post: Any) -> dict[str, Any] | None:
    """One RansomLook post -> claim record ('screen', 'source' and 'magnet' are never read)."""
    if not isinstance(post, dict):
        return None
    return make_claim(
        "ransomlook",
        victim=post.get("post_title"),
        group=post.get("group_name"),
        claimed_at=post.get("discovered"),
        website=post.get("website"),
        description=post.get("description"),
        claim_url=post.get("link"),
        record_id=post.get("misp_uuid"),
    )


def parse_posts(doc: Any) -> list[dict[str, Any]] | None:
    """A posts list (/api/last/{n}, the period index) -> claim records; None when not a list."""
    if not isinstance(doc, list):
        return None
    return [c for c in (normalize_post(p) for p in doc[:20000]) if c]


def parse_search(doc: Any) -> dict[str, Any] | None:
    """/api/search -> {'claims', 'groups'}; None when the answer is not a search object."""
    if not isinstance(doc, dict) or not any(k in doc for k in ("posts", "groups", "markets", "leaks", "notes")):
        return None
    posts = doc.get("posts") if isinstance(doc.get("posts"), list) else []
    groups = []
    for grp in doc.get("groups") if isinstance(doc.get("groups"), list) else []:
        if isinstance(grp, dict) and isinstance(grp.get("name"), str) and grp["name"].strip():
            groups.append({"name": grp["name"].strip()[:100], "alias_key": normalize_group_alias(grp["name"]),
                           "about": excerpt(grp.get("meta"))})
    return {"claims": [c for c in (normalize_post(p) for p in posts[:5000]) if c], "groups": groups}


def parse_groups(doc: Any) -> list[str] | None:
    """/api/groups -> sorted group names; None when not a list."""
    if not isinstance(doc, list):
        return None
    return sorted({n.strip()[:100] for n in doc if isinstance(n, str) and n.strip()})


def match_recent_claims(posts_doc: Any, *, names: Iterable[str] = (), domains: Iterable[str] = (), cnpj_roots: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Offline matching on the daily index (P196 cond 1) for watch and supplier screening: the claims
    of ``posts_doc`` (the ``ransomlook_recent_posts`` dataset) matched with :func:`match_claims`.
    Nothing is sent anywhere."""
    return match_claims(parse_posts(posts_doc) or [], names=names, domains=domains, cnpj_roots=cnpj_roots)


def _as_of(ctx: Any, resp: Any = None) -> str:
    fetched = getattr(resp, "fetched_at", None) if resp is not None else None
    if isinstance(fetched, _dt.datetime):
        return fetched.date().isoformat()
    if isinstance(fetched, str) and len(fetched) >= 10:
        return fetched[:10]
    return ctx.now().date().isoformat()


def _dataset_as_of(ctx: Any, name: str) -> str:
    try:
        info = ctx.data.info(name)
    except (ValueError, OSError):
        return ctx.now().date().isoformat()
    fetched = str(getattr(info, "fetched_at", "") or "")
    return fetched[:10] or ctx.now().date().isoformat()


@register
class RansomLook(Module):
    name = "ransomlook"
    title = "RansomLook ransomware leak-site claims"
    description = (
        "Ransomware leak-site claims tracked by RansomLook (CC BY 4.0): bounded per-entity search by normalised "
        "company name or domain, group recognition and recent claims from a daily local index. Claims are actor "
        "statements; leak-site links are never visited."
    )
    category = "darkweb_ransomware"
    accepts = {T.ORG, T.KEYWORD, T.DOMAIN, T.THREAT_ACTOR, T.ONION}
    produces = {T.THREAT_ACTOR, T.ONION}
    tags = {"free"}
    reference = "https://www.ransomlook.io/doc/"
    notice = (
        f"{ATTRIBUTION}. Leak-site posts are actor claims (unverified): an exact domain/CNPJ match is high (critical "
        "for org-profile assets and suppliers), a name-only match is 'possible match - verify victim identity'. A miss "
        "reads 'not listed by RansomLook (data as of <date>)', never 'not breached'. Onion/claim links and screenshots "
        "are never fetched."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ransomlook"
    sources = (SOURCE_API, SOURCE_GROUPS)
    hosts = ("www.ransomlook.io", "ransomlook.io")
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 1.5
    timeout = 45.0
    min_interval = 2.0
    daily_quota = 300
    cache_ttl = 21600
    max_pivots = 60
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return search_term(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        term = search_term(entity)
        if term is None:  # applies() refused it already; defensive
            return res.mark("skipped", "nothing searchable left after normalisation", reason_code="not_applicable")
        if entity.type is T.THREAT_ACTOR:
            done = self._actor_offline(entity, ctx, res, term)
            if done is not None:
                return done
        resp = ctx.http.get(SEARCH_URL, params={"q": term}, max_bytes=SEARCH_MAX_BYTES, source=SOURCE_API,
                            headers={"Accept": "application/json"})
        ctx.http.check(resp)  # 403/429/5xx/challenge pages/HTML 404 raise: could not verify (rule 5)
        if getattr(resp, "truncated", False):
            return res.mark("error", "RansomLook answer larger than 2 MB (query too broad): could not verify")
        parsed = parse_search(_loads(resp.content))
        if parsed is None:
            return res.mark("error", "unexpected RansomLook search answer (not a search object): could not verify")
        as_of = _as_of(ctx, resp)
        if entity.type is T.THREAT_ACTOR:
            gkey = normalize_group_alias(term)
            known = next((g for g in parsed["groups"] if g["alias_key"] == gkey), None)
            count = actor_profile(res, entity, parsed["claims"], ctx, tracker="ransomlook", source=SOURCE_API, as_of=as_of,
                                  attribution=ATTRIBUTION, window_days=None, known=known is not None,
                                  canonical=known["name"] if known else "")
            res.raw = {"api": {"query": term, "data_as_of": as_of, "counts": {"group_claims": count}}}
            if known is None and not count:
                res.attr("ransomware_listing", not_listed_wording(["ransomlook"], as_of))
                return res.mark("empty")
            return res
        if entity.type is T.ONION:
            return self._onion(entity, parsed["claims"], res, term, as_of)
        summary = report_claims(res, entity, parsed["claims"], ctx, tracker="ransomlook",
                                source=SOURCE_API, as_of=as_of, attribution=ATTRIBUTION, produces=frozenset({"threat_actor", "onion"}))
        res.raw = {"api": {"query": term, "data_as_of": as_of, "counts": {"posts": len(parsed["claims"]), "matched": summary["matched"],
                                                                          "mentions": summary["mentions"]},
                           "claims": summary["raw"][:50]}}
        if not summary["matched"]:
            return res.mark("empty")  # 'not listed by RansomLook (data as of ...)' - never 'not breached'
        return res

    # ------------------------------------------------------------------ threat actors: offline index first
    def _actor_offline(self, entity: Entity, ctx: Any, res: ModuleResult, term: str) -> ModuleResult | None:
        """Answer a threat-actor input from the daily index (no value sent); None = index unavailable,
        fall back to the API search."""
        try:
            groups = parse_groups(ctx.data.fetch_json(GROUPS_DATASET))
            posts = parse_posts(ctx.data.fetch_json(RECENT_DATASET))
        except (DatasetError, DatasetUnavailable, OSError, ValueError) as exc:
            ctx.log(f"RansomLook local index unavailable ({str(exc)[:120]}): searching the API instead", "warning")
            return None
        if groups is None or posts is None:
            return None
        gkey = normalize_group_alias(term)
        canonical = next((g for g in groups if normalize_group_alias(g) == gkey), "")
        as_of = _dataset_as_of(ctx, RECENT_DATASET)
        count = actor_profile(res, entity, posts, ctx, tracker="ransomlook", source=SOURCE_GROUPS, as_of=as_of, attribution=ATTRIBUTION,
                              window_days=RECENT_WINDOW_DAYS, known=bool(canonical), canonical=canonical)
        res.raw = {"ransomlook_groups_index": {"group": canonical or term, "known": bool(canonical), "canonical": canonical or None}}
        if not canonical and not count:
            res.attr("ransomware_listing", f"group not tracked by RansomLook (data as of {_dataset_as_of(ctx, GROUPS_DATASET)})")
            return res.mark("empty")
        return res

    def _onion(self, entity: Entity, claims: list[dict[str, Any]], res: ModuleResult, term: str, as_of: str) -> ModuleResult:
        """An onion host: the groups whose posts link to it (the host is never visited)."""
        groups = sorted({c["group"] for c in claims if term in (c.get("onions") or []) and c.get("group")})
        res.raw = {"api": {"query": term, "data_as_of": as_of, "counts": {"posts": len(claims), "linked_groups": len(groups)}}}
        res.attr("data_attribution", ATTRIBUTION)
        if not groups:
            res.attr("ransomware_listing", not_listed_wording(["ransomlook"], as_of))
            return res.mark("empty")
        for group in groups:
            res.pivot(T.THREAT_ACTOR, group, "leak_site_of", confidence="probable",
                      note="RansomLook posts of this group link to the onion (leak site; never visited automatically)")
        res.attr("ransomware_group", groups[0] if len(groups) == 1 else groups)
        res.finding(
            "Onion host is a ransomware leak site (RansomLook)",
            "high",
            f"RansomLook posts of {', '.join(groups)} link to {defang(term)}: actor-controlled leak-site infrastructure. "
            f"Never visit it from the corporate egress. {ATTRIBUTION} (data as of {as_of}).",
            confidence="probable",
            criterion="the onion host appears as the claim link of posts of the named group(s) on RansomLook",
            data={"groups": groups, "onion": defang(term), "data_as_of": as_of, "attribution": ATTRIBUTION},
            tags=["ransomware", "malicious"],
            source=SOURCE_API,
        )
        return res
