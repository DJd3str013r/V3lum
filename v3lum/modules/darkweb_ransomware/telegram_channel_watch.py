"""Telegram public-channel watch (P357) and its news-feed companion - ``v3lum watch`` only (A14).

Two modules (tags ``watch_only`` + ``watch_source``: the policy gate never selects them outside ``v3lum watch``):

* ``telegram_channel_watch`` - one bounded cycle over public ``https://t.me/s/{channel}`` previews of a
  curated channel list, matched locally against org-profile rules; disclosure ``third_party`` (t.me receives
  channel handles only: the run's entity and the org-profile rules never leave the machine).
* ``telegram_watch_rss`` - the Dark Web Informer RSS companion feed (headline + link only, matched locally).
  Its registry terms are 'unknown' until legal records them (A1: unknown never runs; the dataset is not even
  registered for download until then), so it ships disabled.

Final conditions (council #1, P357) and where they live:

1. Only inside ``v3lum watch`` (tags ``watch_only``/``watch_source``; POL-01 refuses every other path). The
   ``--once``/``--max-runtime``/``--max-alerts`` bounds belong to the watch command (WP26); a cycle here honours
   the kill switch and the run deadline between requests (``ctx.cancelled()``, ``ctx.remaining()``), caps the
   alerts it reports (setting ``telegram_channel_watch_max_alerts``) and runs at most once per
   ``telegram_channel_watch_cycle_minutes``. Pages are read with the shared t.me parser of P112
   (``parse_tme_channel_posts``); no account, session, joining or bot token.
2. Channel list = the team-curated list (``v3lum/data/telegram_channel_watch/telegram_watch.json``, or the file
   of setting ``telegram_channel_watch_list_path``; every entry needs a public handle, a justification, an
   owner, a review date not in the past and ``reviewed_by.cti_lead`` + ``reviewed_by.legal``:
   :func:`validate_team_watch_list`) plus deepdarkCTI Telegram entries marked ONLINE/VALID (GPL-3.0 lists
   downloaded at runtime by the dataset manager, never bundled; :func:`parse_deepdarkcti_telegram`; VALID marks
   invite links only, which are never previewed or joined). At most :data:`WATCH_MAX_CHANNELS` per cycle, team
   list first, the rest rotated over cycles (:func:`plan_watch_cycle`); a channel unreachable for 30 days is
   auto-paused (:func:`should_autopause`).
3. Politeness: ``min_interval`` 10 s (module) between t.me requests, at most 3 pages per channel per cycle
   (``?before=``; a first run reads the newest page only), exponential back-off after a 429 (the cycle stops
   for t.me); the last-seen post id per channel is persisted (``ctx.state``) so only new posts are read; the
   generic 'Contact @name' page or a 302 to the profile = could not read (never 'absent').
4. Rules only over org-profile brands, domains, CNPJ roots, the organisation's own card BINs and the supplier
   list (:func:`build_watch_rules`; executives and any person are never rules). Matching is local, in memory,
   on the raw post text after IDNA->Unicode and accent folding (:func:`match_post`); a BIN prefix matches only
   inside a Luhn-valid PAN-like string or next to a 'BIN' keyword; CNPJs only with valid check digits.
5. P145 scrubbing before alerts or anything kept (:func:`scrub_for_alert`): secrets -> ``[redacted <kind>
   #<sha256 12>]`` (core P145 detectors), combos dropped (core ``drop_combos``), then the shared P112 scrubber (PAN -> BIN6 + last 4, CPF masked,
   credential/combo lines and leaked records dropped, e-mail local parts and phones masked). Alerts keep post
   id, date, URL and an excerpt of at most 200 characters only (:func:`make_alert`).
6. Text only: the parser keeps text and in-text hrefs; media, files, og:image and link previews are never
   fetched and links are never visited. URLs, domains and BTC/ETH wallets of matching posts become pivots noted
   'hostile' (``mentioned_in_post``); only :data:`ENRICH_MAX_PER_HOUR` per hour get ``expand=True`` (capped
   passive enrichment, A14), the rest are listed with ``expand=False``.
7. Alerts: a deduplicated digest (:func:`digest_lines`: one line per new match with date, channel/post, rule
   and list provenance), first_seen by ``channel:post_id:rule_id``, mutes per channel and per rule (settings);
   retention and the case TLP (default AMBER) are the core's (A10/A2).
8. Companion feed: Dark Web Informer RSS (``telegram_watch_rss``; headline + link only; the shared safe XML
   helper refuses DTD/entity declarations); DarkFeed is login-gated and not used.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum.config import SettingSpec
from v3lum.core import providers as _providers
from v3lum.core.datasets import DATASETS, DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.sanitize import drop_combos, find_secrets
from v3lum.core.validators import cnpj_valid, pan_valid
from v3lum.modules.file_analysis.file_type_sniff import UnsafeXML, safe_xml_parse
from v3lum.modules.username_social.telegram_public import (
    GENERIC_MARKER_ID,
    TME_HEADERS,
    TME_PAGE_CAP,
    TME_RESERVED,
    ioc_warninglisted,
    parse_tme_channel_posts,
    post_indicators,
    scrub_post_text,
    tme_fetch_allowed,
    tme_preview_url,
)

SOURCE_TME = "telegram.web_preview"
SOURCE_DDC = "github.telegram_channel_watch_deepdarkcti"
SOURCE_DWI = "darkwebinformer.rss"
TEAM_LIST = "telegram_channel_watch/telegram_watch.json"
DDC_DATASETS = {
    "telegram_channel_watch_ddc_threat_actors": "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/telegram_threat_actors.md",
    "telegram_channel_watch_ddc_infostealer": "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/telegram_infostealer.md",
}
DWI_DATASET = "telegram_watch_rss_darkwebinformer"
DWI_URL = "https://darkwebinformer.com/rss/"

TME_MIN_INTERVAL_S = 10.0  # cond 3
TME_MAX_PAGES = 3  # cond 3
WATCH_MAX_CHANNELS = 50  # cond 2
AUTOPAUSE_DAYS = 30  # cond 2
ENRICH_MAX_PER_HOUR = 30  # cond 6 / A14
EXCERPT_CHARS = 200  # cond 5
BACKOFF_BASE_S = 900.0
BACKOFF_MAX_S = 24 * 3600.0
SEEN_KEYS_MAX = 5000
RSS_MAX_BYTES = 5_000_000
REMOVED_MATCH = "[match in removed content]"
HANDLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,31}$")
PIVOT_TYPES = frozenset({T.URL, T.DOMAIN, T.BTC, T.ETH})
PIVOT_CAP = 60
HOSTILE_NOTE = "hostile: from a watched public Telegram post (never visited; passive enrichment only)"


# ======================================================================================
# small helpers
# ======================================================================================


def fold(text: Any) -> str:
    """Accent folding + casefold (NFKD, combining marks dropped)."""
    if not isinstance(text, str):
        return ""
    nfkd = unicodedata.normalize("NFKD", text.replace("\xa0", " "))
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch)).casefold()


def fold_with_map(text: str) -> tuple[str, list[int]]:
    """(folded, index_map): index_map[j] is the index in ``text`` of folded character j."""
    out: list[str] = []
    idx: list[int] = []
    for i, ch in enumerate(text or ""):
        f = fold(ch)
        out.append(f)
        idx.extend([i] * len(f))
    return "".join(out), idx


def idna_to_unicode(host: str) -> str:
    """Decode xn-- labels so lookalikes are matched in Unicode (cond 4)."""
    labels = []
    for label in str(host).split("."):
        if label.lower().startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


_HOST_RE = re.compile(r"(?<![\w.-])((?:[\w-]+\.)+[\w-]{2,})(?![\w-])", re.U)


def decode_hosts(text: str) -> str:
    """Replace punycode host names in free text with their Unicode form."""
    return _HOST_RE.sub(lambda m: idna_to_unicode(m.group(1)) if "xn--" in m.group(1).lower() else m.group(1), text or "")


def rule_id(kind: str, key: str) -> str:
    """Opaque, stable rule id: the org-profile value never appears in alerts or state."""
    return f"{kind}:{hashlib.sha256(f'{kind}:{key}'.encode()).hexdigest()[:8]}"


def _iso(dt: _dt.datetime) -> str:
    return dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: Any) -> _dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        d = _dt.datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=_dt.timezone.utc)


# ======================================================================================
# channel lists (cond 2)
# ======================================================================================


def tme_handle_from_link(link: Any) -> tuple[str | None, str]:
    """(handle | None, kind) of a t.me link or handle: public | invite | private_post | reserved | not_telegram | invalid."""
    if not isinstance(link, str) or not link.strip():
        return None, "invalid"
    s = link.strip()
    m = re.search(r"\]\((https?://[^)\s]+|t\.me/[^)\s]+)\)", s)  # markdown [text](url)
    if m:
        s = m.group(1)
    if "/" not in s:
        h = s.lstrip("@")
        return (h.lower(), "public") if HANDLE_RE.match(h) and h.lower() not in TME_RESERVED else (None, "invalid")
    m = re.match(r"^(?:https?://)?(?:www\.)?(?:t\.me|telegram\.me|telegram\.dog)/(.*)$", s, re.I)
    if not m:
        return None, "not_telegram"
    path = m.group(1).split("?")[0].split("#")[0].strip("/")
    if not path:
        return None, "invalid"
    parts = path.split("/")
    first = parts[0]
    if first.startswith("+") or first.lower() == "joinchat":
        return None, "invite"
    if first.lower() == "c":
        return None, "private_post"
    if first.lower() == "s" and len(parts) > 1:
        first = parts[1]
    if first.lower() in TME_RESERVED:
        return None, "reserved"
    if not HANDLE_RE.match(first):
        return None, "invalid"
    return first.lower(), "public"


def parse_deepdarkcti_telegram(md_text: Any) -> dict[str, Any] | None:
    """deepdarkCTI ``telegram_*.md`` table -> entries (tolerant: 2-4 cells per row, markdown links).

    Parser equivalent to P198's table reader (batch p2-G09-1): reconcile into one helper when both land."""
    if isinstance(md_text, (bytes, bytearray)):
        md_text = bytes(md_text).decode("utf-8", "replace")
    if not isinstance(md_text, str):
        return None
    entries, skipped, header, total = [], 0, None, 0
    for line in md_text.splitlines()[:20000]:
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if header is None:
            low = [c.lower() for c in cells]
            if any("telegram" in c for c in low) and any("status" in c for c in low):
                header = low
            continue
        if all(re.fullmatch(r":?-{2,}:?", c or "--") for c in cells):
            continue
        total += 1
        if len(cells) < 2 or not cells[0] or not cells[1]:
            skipped += 1
            continue
        handle, kind = tme_handle_from_link(cells[0])
        status = cells[1].upper()
        if kind == "not_telegram" or not re.fullmatch(r"[A-Z_ ]{3,20}", status):
            skipped += 1
            continue
        entries.append({"handle": handle, "link_kind": kind, "status": status,
                        "name": (cells[2][:120] if len(cells) > 2 and cells[2] else None)})
    return {"entries": entries, "rows_total": total, "rows_skipped": skipped, "header": header}


def select_deepdarkcti_channels(parsed: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Public handles with ONLINE/VALID status, deduplicated (invite links are never previewed or joined)."""
    out, seen = [], set()
    for e in (parsed or {}).get("entries", []):
        if e["link_kind"] != "public" or e["status"] not in ("ONLINE", "VALID") or e["handle"] in seen:
            continue
        seen.add(e["handle"])
        out.append({"handle": e["handle"], "provenance": "deepdarkcti"})
    return out


def validate_team_watch_list(obj: Any, today: str) -> tuple[list[dict[str, Any]], list[str]]:
    """The team list -> (usable entries, problems): public handle, justification, owner, review date not in
    the past, ``reviewed_by.cti_lead`` and ``reviewed_by.legal`` (cond 2). Problems name the entry index only."""
    entries: list[dict[str, Any]] = []
    problems: list[str] = []
    chans = obj.get("channels") if isinstance(obj, dict) else None
    if not isinstance(chans, list):
        return [], ["team list has no 'channels' list"]
    seen = set()
    for i, c in enumerate(chans):
        if not isinstance(c, dict):
            problems.append(f"entry {i}: not an object")
            continue
        handle, kind = tme_handle_from_link(str(c.get("handle") or ""))
        if kind != "public" or handle is None:
            problems.append(f"entry {i}: not a public channel handle ({kind})")
            continue
        missing = [k for k in ("justification", "owner", "review_date") if not c.get(k)]
        rb = c.get("reviewed_by") if isinstance(c.get("reviewed_by"), dict) else {}
        missing += [f"reviewed_by.{k}" for k in ("cti_lead", "legal") if not rb.get(k)]
        if missing:
            problems.append(f"entry {i} (@{handle}): missing {', '.join(missing)}")
            continue
        if str(c["review_date"])[:10] < today:
            problems.append(f"entry {i} (@{handle}): review date {str(c['review_date'])[:10]} passed")
            continue
        if handle in seen:
            continue
        seen.add(handle)
        entries.append({"handle": handle, "provenance": "team_list"})
    return entries, problems


def plan_watch_cycle(team: list[dict[str, Any]], ddc: list[dict[str, Any]], paused: Any = (),
                     max_channels: int = WATCH_MAX_CHANNELS, cycle: int = 0) -> list[dict[str, Any]]:
    """Channels for one cycle: team list first, then deepdarkCTI rotated by cycle, deduplicated, paused ones
    dropped, capped at ``max_channels`` (<= 50)."""
    max_channels = max(0, min(int(max_channels), WATCH_MAX_CHANNELS))
    paused = {str(p).lower() for p in paused or ()}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for e in team or []:
        if e["handle"] not in seen and e["handle"] not in paused:
            seen.add(e["handle"])
            out.append(e)
    rest = [e for e in ddc or [] if e["handle"] not in seen and e["handle"] not in paused]
    if rest:
        k = (cycle * max(1, max_channels - len(out))) % len(rest)
        rest = rest[k:] + rest[:k]
    for e in rest:
        if len(out) >= max_channels:
            break
        if e["handle"] not in seen:
            seen.add(e["handle"])
            out.append(e)
    return out[:max_channels]


def should_autopause(unreachable_since: Any, now: _dt.datetime, days: int = AUTOPAUSE_DAYS) -> bool:
    """True when a channel has been unreachable for at least ``days`` days."""
    since = _parse_iso(unreachable_since)
    return since is not None and (now - since).days >= days


def next_page_before(posts: list[dict[str, Any]], next_before: Any, last_seen_id: int | None, pages_done: int,
                     max_pages: int = TME_MAX_PAGES, first_run_pages: int = 1) -> int | None:
    """``?before=`` for the next older page, or None (cond 3: <= 3 pages, only new posts; a first run reads
    the newest page only)."""
    ids = [p["post_id"] for p in posts or [] if isinstance(p.get("post_id"), int)]
    if not ids:
        return None
    limit = max_pages if last_seen_id is not None else min(first_run_pages, max_pages)
    if pages_done >= limit:
        return None
    oldest = min(ids)
    if last_seen_id is not None and oldest <= last_seen_id + 1:
        return None
    nb = next_before if isinstance(next_before, int) and next_before > 0 else oldest
    return nb if nb > 1 else None


# ======================================================================================
# rules and matching (cond 4)
# ======================================================================================


def build_watch_rules(org: Any) -> list[dict[str, Any]]:
    """Rules only from org-profile brands, domains, CNPJ roots, own card BINs and suppliers (cond 4, A14).

    One rule per brand/supplier (all its keywords) so mutes per rule work; executives and any person entry
    are never rules. Accepts the core ``OrgProfile`` or the same keys as a mapping (tests)."""
    def items(name: str) -> list[Any]:
        value = getattr(org, name, None) if not isinstance(org, dict) else org.get(name)
        return list(value or [])

    def field(obj: Any, name: str, default: Any = None) -> Any:
        return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)

    rules: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(kind: str, key: str, values: list[str], domains: tuple[str, ...] = ()) -> None:
        vals = [v for v in dict.fromkeys(values) if v]
        if not key or not (vals or domains):
            return
        rid = rule_id(kind, key)
        if rid not in seen:
            seen.add(rid)
            rules.append({"id": rid, "kind": kind, "values": vals, "domains": list(domains)})

    for b in items("brands"):
        names = [b] if isinstance(b, str) else [field(b, "keyword") or field(b, "name"), *(field(b, "variants") or field(b, "keywords") or ())]
        folded = [" ".join(fold(str(n or "")).split()) for n in names]
        folded = [f for f in folded if len(f) >= 3]
        if folded:
            add("brand", folded[0], folded)
    for d in items("domains"):
        name = field(d, "name") if not isinstance(d, str) else d
        if isinstance(name, str) and "." in name:
            v = fold(idna_to_unicode(name.strip().lower().rstrip(".")))
            add("domain", v, [v])
    for r in items("cnpj_roots"):
        digits = re.sub(r"\D", "", str(r))
        if len(digits) == 8:
            add("cnpj_root", digits, [digits])
    for b in items("card_bins"):
        digits = re.sub(r"\D", "", str(b))
        if 6 <= len(digits) <= 8:
            add("bin", digits, [digits])
    for sup in items("suppliers"):
        name = sup if isinstance(sup, str) else field(sup, "name", "")
        v = " ".join(fold(str(name or "")).split())
        doms = tuple(fold(idna_to_unicode(str(x).strip().lower())) for x in (field(sup, "domains") or () if not isinstance(sup, str) else ())
                     if isinstance(x, str) and "." in x)
        brands = [" ".join(fold(str(x)).split()) for x in (field(sup, "brands") or () if not isinstance(sup, str) else ())]
        vals = [x for x in [v, *brands] if len(x) >= 3]
        if vals or doms:
            add("supplier", v or doms[0], vals, doms)
    return rules


_PAN_RE = re.compile(r"(?<![\d*])(?:\d[ -]?){12,18}\d(?![\d*])")
_CNPJ_RE = re.compile(r"(?<!\d)\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}(?!\d)")
_BIN_KW_RE = re.compile(r"\bbins?\b\s*[:#=-]?\s*(\d{6,8})(?!\d)|(?<!\d)(\d{6,8})\s*bins?\b", re.I)


def match_post(text: Any, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Local matching over the RAW post text, in memory only (cond 4). One hit per rule:
    ``[{rule_id, kind, needle}]`` (``needle`` locates the excerpt in the scrubbed text)."""
    raw = text if isinstance(text, str) else ""
    folded = fold(decode_hosts(raw))
    hosts = [h.lower() for h in _HOST_RE.findall(folded)]
    pans = [re.sub(r"\D", "", m.group(0)) for m in _PAN_RE.finditer(raw)]
    pans = [x for x in pans if 13 <= len(x) <= 19 and pan_valid(x) and not (len(x) == 14 and cnpj_valid(x))]
    bin_kw = [m.group(1) or m.group(2) for m in _BIN_KW_RE.finditer(raw)]
    cnpjs = [re.sub(r"\D", "", m.group(0)) for m in _CNPJ_RE.finditer(raw)]

    def host_hit(domains: list[str] | tuple[str, ...]) -> str | None:
        for h in hosts:
            for d in domains:
                if h == d or h.endswith("." + d):
                    return h
        return None

    hits = []
    for r in rules or []:
        k, needle = r["kind"], None
        if k in ("brand", "supplier"):
            for v in r.get("values") or []:
                if re.search(r"(?<![0-9a-z])" + re.escape(v) + r"(?![0-9a-z])", folded):
                    needle = v
                    break
            if needle is None and r.get("domains"):
                needle = host_hit(r["domains"])
        elif k == "domain":
            needle = host_hit(r["values"])
        elif k == "cnpj_root":
            for c in cnpjs:
                if cnpj_valid(c) and c[:8] == r["values"][0]:
                    needle = c[:8]
                    break
        elif k == "bin":
            v = r["values"][0]
            if any(x.startswith(v) for x in pans) or any(b.startswith(v) or v.startswith(b) for b in bin_kw):
                needle = v[:6]
        if needle:
            hits.append({"rule_id": r["id"], "kind": k, "needle": needle})
    return hits


# ======================================================================================
# scrubbing, alerts, digest (cond 5, 7)
# ======================================================================================


def scrub_for_alert(text: Any) -> dict[str, Any]:
    """P145 scrubbing before alerts or anything kept (cond 5): secrets become type + SHA-256 prefix, combos are
    dropped (core ``drop_combos``), then the shared P112 scrubber (PAN -> BIN6 + last 4, CPF masked, credential/combo/leaked-record lines dropped,
    e-mail local parts and phones masked). Returns ``{text, secrets, dropped, redactions}``."""
    raw = text if isinstance(text, str) else ""
    secrets = 0
    out, pos = [], 0
    for hit in find_secrets(raw):
        out.append(raw[pos:hit.start])
        secrets += 1
        if hit.action == "drop":
            out.append("[removed credential]")
        else:
            out.append(f"[redacted {hit.kind} #{hashlib.sha256(hit.value.encode('utf-8', 'replace')).hexdigest()[:12]}]")
        pos = hit.end
    out.append(raw[pos:])
    sc = scrub_post_text(drop_combos("".join(out)))
    return {"text": sc["text"], "secrets": secrets + len(sc["exposures"]), "dropped": sc["dropped"],
            "drop_reasons": sc["drop_reasons"], "redactions": sc["redactions"]}


def excerpt_for(scrubbed_text: str, needle: str | None, width: int = EXCERPT_CHARS) -> str:
    """<= ``width`` characters of scrubbed text around the (folded) needle; a placeholder when the match sat in
    content removed by scrubbing (credentials, leaked records)."""
    if not scrubbed_text or not needle:
        return REMOVED_MATCH
    text = decode_hosts(scrubbed_text).replace("\n", " / ")
    folded, idx = fold_with_map(text)
    nf = fold(needle)
    pos = folded.find(nf)
    if pos < 0 or not idx:
        return REMOVED_MATCH
    start, end = idx[pos], idx[min(pos + len(nf) - 1, len(idx) - 1)] + 1
    room = max(0, width - 6 - (end - start))
    a = max(0, start - room // 2)
    b = min(len(text), end + (room - (start - a)))
    a = max(0, min(a, b - (width - 6)))
    out = ("..." if a > 0 else "") + text[a:b] + ("..." if b < len(text) else "")
    return out[:width]


def make_alert(channel: str, post: dict[str, Any], hit: dict[str, Any], provenance: str, scrubbed_text: str) -> dict[str, Any]:
    """Alert record: post id, date, URL, rule, provenance and a short scrubbed excerpt only (cond 5/7)."""
    return {"key": f"{channel}:{post['post_id']}:{hit['rule_id']}", "channel": channel, "post_id": post["post_id"],
            "date": post.get("date"), "url": post.get("url") or f"https://t.me/{channel}/{post['post_id']}",
            "rule_id": hit["rule_id"], "rule_kind": hit["kind"], "provenance": provenance,
            "excerpt": excerpt_for(scrubbed_text, hit.get("needle"))}


def digest_lines(alerts: list[dict[str, Any]], seen_keys: Any = (), muted_channels: Any = (), muted_rules: Any = ()) -> tuple[list[str], list[str]]:
    """Deduplicated digest: one line per NEW alert with date, channel/post, provenance and rule (cond 7).
    Returns (lines, new keys)."""
    seen = set(seen_keys or ())
    mch = {str(m).lower().lstrip("@") for m in muted_channels or ()}
    mru = {str(m) for m in muted_rules or ()}
    lines, new = [], []
    for al in sorted(alerts or [], key=lambda x: (x.get("date") or "", x["channel"], x["post_id"], x["rule_id"])):
        if al["key"] in seen or al["channel"].lower() in mch or al["rule_id"] in mru:
            continue
        seen.add(al["key"])
        new.append(al["key"])
        lines.append(f"{al.get('date') or '?'} t.me/{al['channel']}/{al['post_id']} [{al['provenance']}] rule={al['rule_id']} :: {al['excerpt']}")
    return lines, new


# ======================================================================================
# RSS companion (cond 8)
# ======================================================================================


def parse_rss_headlines(raw: Any) -> dict[str, Any]:
    """RSS 2.0 -> ``{items: [{title, link, published, guid}], error}``; headline + link only (descriptions,
    content:encoded, media and authors are never kept). The shared safe XML helper refuses DTDs/entities."""
    data = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw or b"")
    try:
        root = safe_xml_parse(data, max_bytes=RSS_MAX_BYTES)
    except UnsafeXML as exc:
        return {"items": [], "error": f"RSS refused ({exc.args[0] if exc.args else 'unsafe'})"}
    except ValueError as exc:
        return {"items": [], "error": f"malformed RSS ({str(exc)[:80]})"}
    channel = root.find("channel")
    if root.tag != "rss" or channel is None:
        return {"items": [], "error": "not an RSS 2.0 document"}
    from email.utils import parsedate_to_datetime

    items = []
    for it in channel.findall("item"):
        title = " ".join(str(it.findtext("title") or "").split())[:300]
        link = (it.findtext("link") or "").strip()
        if not link.lower().startswith(("https://", "http://")):
            link = ""
        published = None
        pub = it.findtext("pubDate")
        if pub:
            try:
                published = _iso(parsedate_to_datetime(pub.strip()))
            except (TypeError, ValueError):
                published = None
        if title and link:
            items.append({"title": title, "link": link[:2048], "published": published,
                          "guid": " ".join(str(it.findtext("guid") or "").split())[:200] or None})
    return {"items": items, "error": None}


def match_headlines(items: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Headline-only matching (brands, domains, suppliers, CNPJ roots; BIN rules never apply to headlines)."""
    out = []
    for it in items or []:
        for m in match_post(it.get("title") or "", [r for r in rules or [] if r["kind"] != "bin"]):
            out.append({"title": it["title"], "link": it["link"], "published": it.get("published"), "rule_id": m["rule_id"],
                        "source": SOURCE_DWI})
    return out


# ======================================================================================
# datasets
# ======================================================================================


def _validate_ddc(path: Path) -> bool:
    parsed = parse_deepdarkcti_telegram(Path(path).read_bytes()[:3_000_000])
    if not parsed or parsed["header"] is None:
        raise ValueError("deepdarkCTI list without a '|Telegram|Status|' table")
    return True


for _name, _url in DDC_DATASETS.items():
    register_dataset(
        _name,
        _url,
        ttl=7 * 86400,
        description="deepdarkCTI Telegram channel list (GPL-3.0, runtime download only; telegram_channel_watch, P357)",
        licence="GPL-3.0 (runtime download, never bundled)",
        terms_class="open",
        attribution="deepdarkCTI by fastfire (https://github.com/fastfire/deepdarkCTI), GPL-3.0",
        provider="github",
        source=SOURCE_DDC,
        validate=_validate_ddc,
        min_bytes=64,
        expect="text",
        max_bytes=3_000_000,
    )


def _dwi_terms_class() -> str:
    try:
        src = _providers.registry().source(SOURCE_DWI)
        return str(getattr(getattr(src, "terms", None), "class_", "") or "unknown") if src is not None else "unknown"
    except Exception:  # noqa: BLE001 - a registry problem: fail closed
        return "unknown"


def dwi_registration_allowed() -> bool:
    """cond 8 + A1: the Dark Web Informer feed is registered (and so downloaded by ``v3lum data update``) only
    once legal recorded a terms class other than 'unknown' for ``darkwebinformer.rss``."""
    return _dwi_terms_class() != "unknown"


def _register_dwi() -> None:
    register_dataset(DWI_DATASET, DWI_URL, ttl=3600, description="Dark Web Informer RSS (headline + link only; telegram_watch_rss, P357 cond 8)",
                     licence="publisher content: headline + link use only", terms_class=_dwi_terms_class(),
                     attribution="Dark Web Informer (darkwebinformer.com)", provider="darkwebinformer", source=SOURCE_DWI,
                     min_bytes=64, expect="text", max_bytes=RSS_MAX_BYTES)


if dwi_registration_allowed():
    _register_dwi()


# ======================================================================================
# the cycle (cond 1-7)
# ======================================================================================


def _setting_list(ctx: Any, name: str) -> list[str]:
    value = ctx.setting(name, [])
    if isinstance(value, str):
        value = [v for v in re.split(r"[,\s]+", value) if v]
    return [str(v) for v in value or [] if str(v).strip()]


def _setting_int(ctx: Any, name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(ctx.setting(name, default))
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


def load_team_list(ctx: Any) -> tuple[Any, str]:
    """The team list document and where it came from (setting path, else the bundled file)."""
    path = str(ctx.setting("telegram_channel_watch_list_path", "") or "").strip()
    if path:
        p = Path(path).expanduser()
        try:
            if p.stat().st_size > 2_000_000:
                return None, f"team list {p.name} larger than 2 MB"
            return json.loads(p.read_text(encoding="utf-8")), f"setting telegram_channel_watch_list_path ({p.name})"
        except (OSError, ValueError) as exc:
            return None, f"team list unreadable ({type(exc).__name__})"
    try:
        return ctx.data.bundled_json(TEAM_LIST), "bundled v3lum/data/" + TEAM_LIST
    except (OSError, ValueError) as exc:
        return None, f"bundled team list unreadable ({type(exc).__name__})"


def load_deepdarkcti(ctx: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """deepdarkCTI channels (ONLINE/VALID public handles) and a status summary; failures never stop the cycle."""
    status: dict[str, Any] = {}
    channels: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in DDC_DATASETS:
        try:
            parsed = parse_deepdarkcti_telegram(ctx.data.fetch_text(name))
        except (DatasetUnavailable, DatasetError, OSError, ValueError) as exc:
            status[name] = f"unavailable ({str(exc)[:80]})"
            continue
        picked = [c for c in select_deepdarkcti_channels(parsed) if c["handle"] not in seen]
        seen.update(c["handle"] for c in picked)
        channels.extend(picked)
        status[name] = f"{len(picked)} public ONLINE/VALID channels of {parsed['rows_total'] if parsed else 0} rows"
    return channels, status


class TmeFetch:
    """One t.me/s page: ``state`` ok | could_not_read | rate_limited | blocked | error."""

    def __init__(self, state: str, reason: str = "", parsed: dict[str, Any] | None = None) -> None:
        self.state, self.reason, self.parsed = state, reason, parsed or {}


def fetch_channel_page(ctx: Any, handle: str, before: int | None = None) -> TmeFetch:
    """GET one public preview page (no cache: raw HTML is never stored; 2 MB cap; redirects not followed).

    A 302 to the profile or the generic 'Contact @name' page = could not read (private, missing or no
    preview: never 'absent'). Rate limits and blocks are returned, not raised, so the cycle can stop."""
    url = tme_preview_url(handle, before)
    if url is None or not tme_fetch_allowed(url):
        return TmeFetch("error", "not a public channel handle")
    try:
        resp = ctx.http.get(url, ttl=0, max_bytes=TME_PAGE_CAP, headers=dict(TME_HEADERS), source=SOURCE_TME, allow_redirects=False)
    except RateLimited as exc:
        return TmeFetch("rate_limited", str(exc)[:160])
    except (Blocked, AuthRequired) as exc:
        return TmeFetch("blocked", str(exc)[:160])
    except QuotaExceeded as exc:
        return TmeFetch("rate_limited", str(exc)[:160])
    except (HttpError, NetworkError) as exc:
        return TmeFetch("error", str(exc)[:160])
    status = int(getattr(resp, "status", 0) or 0)
    if 300 <= status < 400:
        location = str((getattr(resp, "headers", {}) or {}).get("location", ""))
        path = urlsplit(location).path if location else ""
        if path.startswith("/s/"):
            return TmeFetch("error", "unexpected redirect inside the preview")
        return TmeFetch("could_not_read", "no public preview (redirected to the t.me profile): private, missing or not a channel")
    try:
        ctx.http.check(resp)
    except RateLimited as exc:
        return TmeFetch("rate_limited", str(exc)[:160])
    except (Blocked, AuthRequired) as exc:
        return TmeFetch("blocked", str(exc)[:160])
    except HttpError as exc:
        found = getattr(resp, "classification", None)
        if found is None or getattr(found, "marker_id", "") != GENERIC_MARKER_ID:
            return TmeFetch("error", str(exc)[:160])
        return TmeFetch("could_not_read", "generic 'Contact @name' page: private or missing channel (could not read)")
    parsed = parse_tme_channel_posts(resp.content, handle)
    if parsed.get("state") != "FOUND":
        return TmeFetch("could_not_read", str(parsed.get("reason") or "no public channel preview")[:160])
    return TmeFetch("ok", str(parsed.get("reason") or ""), parsed)


def run_cycle(module: Module, entity: Entity, ctx: Any) -> ModuleResult:
    res = module.result(entity)
    now = ctx.now()
    rules = build_watch_rules(ctx.org)
    if not rules:
        return res.mark("skipped", "no org-profile watch rules (brands, domains, CNPJ roots, card BINs, suppliers): set up v3lum org",
                        reason_code="config")
    state = ctx.state
    cycle = state.get("cycle", {}) or {}
    backoff = state.get("backoff", {}) or {}
    until = _parse_iso(backoff.get("until"))
    if until is not None and until > now:
        return res.mark("rate_limited", f"t.me rate limited earlier: backing off until {_iso(until)} (could not verify)",
                        reason_code="rate_limited")
    interval = _setting_int(ctx, "telegram_channel_watch_cycle_minutes", 60, 60, 7 * 24 * 60)
    last_at = _parse_iso(cycle.get("last_at"))
    if last_at is not None and (now - last_at).total_seconds() < interval * 60:
        nxt = _iso(last_at + _dt.timedelta(minutes=interval))
        return res.mark("skipped", f"cycle not due: the last cycle ran at {_iso(last_at)} (next at {nxt})", reason_code="not_applicable")
    today = now.date().isoformat()
    doc, origin = load_team_list(ctx)
    team, problems = validate_team_watch_list(doc, today) if doc is not None else ([], [origin])
    ddc: list[dict[str, Any]] = []
    ddc_status: dict[str, Any] = {}
    if bool(ctx.setting("telegram_channel_watch_use_deepdarkcti", True)) and SOURCE_DDC in ctx.allowed_sources:
        ddc, ddc_status = load_deepdarkcti(ctx)
        if ddc_status and all(str(v).startswith("unavailable") for v in ddc_status.values()):
            res.source_status(SOURCE_DDC, Status.UNAVAILABLE, reason_code="dataset", reason="deepdarkCTI lists unavailable: team list only")
    channels_state: dict[str, Any] = state.get("channels", {}) or {}
    paused = [h for h, c in channels_state.items() if isinstance(c, dict) and c.get("paused")]
    cycle_no = int(cycle.get("count") or 0)
    plan = plan_watch_cycle(team, ddc, paused, _setting_int(ctx, "telegram_channel_watch_max_channels", WATCH_MAX_CHANNELS, 1, WATCH_MAX_CHANNELS), cycle_no)
    book: dict[str, Any] = {"cycle": cycle_no + 1, "channels_planned": len(plan), "channels_read": 0, "pages_read": 0, "posts_new": 0,
                            "could_not_read": [], "paused": sorted(paused), "rate_limited": False, "backoff_until": None,
                            "team_list": origin, "team_list_problems": problems[:20], "deepdarkcti": ddc_status}
    if not plan:
        res.attr("telegram_watch_cycle", book)
        return res.mark("skipped", "no channel to watch: the team list has no valid reviewed entry and deepdarkCTI gave none",
                        reason_code="config")
    alerts: list[dict[str, Any]] = []
    pivot_texts: list[tuple[str, str]] = []
    errors: list[str] = []
    stop_reason = ""
    for chan in plan:
        if ctx.cancelled():
            stop_reason = "cancelled"
            break
        rem = ctx.remaining()
        if rem is not None and rem < TME_MIN_INTERVAL_S + 2:
            stop_reason = "deadline"
            break
        handle = chan["handle"]
        cst = dict(channels_state.get(handle) or {})
        last_seen = cst.get("last_seen") if isinstance(cst.get("last_seen"), int) else None
        before: int | None = None
        pages = 0
        newest = last_seen
        outcome = "ok"
        while True:
            page = fetch_channel_page(ctx, handle, before)
            if page.state != "ok":
                outcome = page.state
                if page.state == "could_not_read":
                    book["could_not_read"].append(handle)
                elif page.state in ("rate_limited", "blocked"):
                    stop_reason = page.state
                else:
                    errors.append(f"@{handle}: {page.reason}")
                break
            pages += 1
            book["pages_read"] += 1
            posts = [p for p in page.parsed.get("posts") or [] if isinstance(p, dict) and isinstance(p.get("post_id"), int)]
            fresh = [p for p in posts if last_seen is None or p["post_id"] > last_seen]
            for post in sorted(fresh, key=lambda p: p["post_id"]):
                newest = max(newest or 0, post["post_id"])
                book["posts_new"] += 1
                raw_text = post.get("text") if isinstance(post.get("text"), str) else ""
                hits = match_post(raw_text, rules)  # raw text: in memory only, never stored
                if not hits:
                    continue
                scrubbed = scrub_for_alert(raw_text)["text"]
                for hit in hits:
                    alerts.append(make_alert(handle, post, hit, chan.get("provenance", "team_list"), scrubbed))
                pivot_texts.append((handle, scrubbed))
            before = next_page_before(posts, page.parsed.get("next_before"), last_seen, pages)
            if before is None or ctx.cancelled():
                break
        if outcome == "ok":
            book["channels_read"] += 1
            cst.update(last_seen=newest, last_ok=_iso(now), unreachable_since=None, paused=False)
        elif outcome == "could_not_read":
            cst.setdefault("unreachable_since", None)
            cst["unreachable_since"] = cst.get("unreachable_since") or _iso(now)
            if should_autopause(cst["unreachable_since"], now):
                cst["paused"] = True
                book["paused"].append(handle)
        channels_state[handle] = cst
        if stop_reason in ("rate_limited", "blocked"):
            break
    if stop_reason == "rate_limited":
        level = int(backoff.get("level") or 0) + 1
        wait = min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2 ** (level - 1)))
        book["rate_limited"] = True
        book["backoff_until"] = _iso(now + _dt.timedelta(seconds=wait))
        state.set("backoff", {"until": book["backoff_until"], "level": level})
    elif book["channels_read"]:
        state.delete("backoff")
    state.set("channels", _bounded_channels(channels_state))
    if stop_reason != "rate_limited":  # a rate-limited cycle is retried once the back-off is over
        state.set("cycle", {"last_at": _iso(now), "count": cycle_no + 1})
    return _report(module, res, ctx, now, alerts, pivot_texts, book, errors, stop_reason)


def _bounded_channels(channels: dict[str, Any], limit: int = 2000) -> dict[str, Any]:
    if len(channels) <= limit:
        return channels
    ordered = sorted(channels.items(), key=lambda kv: str((kv[1] or {}).get("last_ok") or ""), reverse=True)
    return dict(ordered[:limit])


def _report(module: Module, res: ModuleResult, ctx: Any, now: _dt.datetime, alerts: list[dict[str, Any]],
            pivot_texts: list[tuple[str, str]], book: dict[str, Any], errors: list[str], stop_reason: str) -> ModuleResult:
    state = ctx.state
    seen = list(state.get("seen_keys", []) or [])
    lines, new_keys = digest_lines(alerts, seen, _setting_list(ctx, "telegram_channel_watch_muted_channels"),
                                   _setting_list(ctx, "telegram_channel_watch_muted_rules"))
    max_alerts = _setting_int(ctx, "telegram_channel_watch_max_alerts", 200, 1, 10000)
    new = [a for a in alerts if a["key"] in set(new_keys)]
    suppressed = max(0, len(new) - max_alerts)
    new, lines = new[:max_alerts], lines[:max_alerts]
    if suppressed:
        lines.append(f"... {suppressed} more new matches this cycle (max_alerts {max_alerts}): see the next cycles")
    state.set("seen_keys", (seen + new_keys)[-SEEN_KEYS_MAX:])
    res.attr("telegram_watch_cycle", book)
    res.attr("posts_read", book["posts_new"])
    if new:
        res.attr("telegram_watch_alerts", new)
        res.attr("telegram_watch_digest", lines)
        res.attr("watch_hits", [{"name": a["url"], "registrable_domain": None, "serial": None, "cert_sha256": None, "issuer": None,
                                 "not_before": a["date"], "source": SOURCE_TME, "rule_id": a["rule_id"]} for a in new])
        alerted = {(a["channel"]) for a in new}
        _pivots(res, ctx, now, [t for t in pivot_texts if t[0] in alerted])
        res.finding(
            "Org-profile match in a public Telegram channel",
            "medium",
            f"{len(new)} new match(es) of org-profile watch rules in {len(alerted)} public channel(s) this cycle: " + "; ".join(lines[:5]),
            confidence="possible",
            criterion="local org-profile rule match (brand/domain/CNPJ root/own BIN/supplier) in new public t.me/s post text; "
                      "a mention is a lead, not a compromise",
            tags=["suspicious"],
            source=SOURCE_TME,
            data={"alerts": len(new), "channels": sorted(alerted)},
            key="cycle",
        )
    if stop_reason in ("deadline", "cancelled"):
        res.stop(stop_reason)
    if errors:
        res.source_status(SOURCE_TME, Status.ERROR, reason_code="error", reason=("; ".join(errors))[:240])
    if new:
        return res
    if book["rate_limited"] and not book["channels_read"]:
        return res.mark("rate_limited", f"t.me answered 429: backing off until {book['backoff_until']} (could not verify)", reason_code="rate_limited")
    if stop_reason == "blocked" and not book["channels_read"]:
        return res.mark("blocked", "t.me refused the preview (challenge or block): could not verify", reason_code="challenge")
    if not book["channels_read"]:
        detail = (f"{len(book['could_not_read'])} channel(s) could not be read" + (f"; {len(errors)} error(s)" if errors else ""))
        return res.mark("error", f"no channel preview could be read: could not verify ({detail})")
    return res.mark("empty")


def _pivots(res: ModuleResult, ctx: Any, now: _dt.datetime, texts: list[tuple[str, str]]) -> None:
    """IOCs of matching posts (scrubbed text) as hostile pivots: <= ENRICH_MAX_PER_HOUR expandable per hour."""
    hour = now.strftime("%Y-%m-%dT%H")
    enrich = ctx.state.get("enrich", {}) or {}
    used = int(enrich.get("count") or 0) if enrich.get("hour") == hour else 0
    added = 0
    for channel, text in texts:
        ents, _mentions = post_indicators(text, own_handle=channel)
        for ent in ents:
            if ent.type not in PIVOT_TYPES or ioc_warninglisted(ent) or added >= PIVOT_CAP:
                continue
            expand = used < ENRICH_MAX_PER_HOUR
            note = f"{HOSTILE_NOTE}; channel @{channel}" + ("" if expand else f"; enrichment cap {ENRICH_MAX_PER_HOUR}/h reached: listed only")
            if res.pivot(ent.type, ent.value, "mentioned_in_post", confidence="possible", expand=expand, note=note) is not None:
                added += 1
                if expand:
                    used += 1
    ctx.state.set("enrich", {"hour": hour, "count": used})


# ======================================================================================
# the modules
# ======================================================================================

_ACCEPTS = {T.KEYWORD, T.DOMAIN, T.ORG, T.CARD_BIN, T.CNPJ}


@register
class TelegramChannelWatch(Module):
    name = "telegram_channel_watch"
    title = "Telegram public-channel watch (v3lum watch only)"
    description = (
        "One bounded watch cycle over public t.me/s previews of a curated channel list (team list reviewed by the CTI lead "
        "and legal, plus deepdarkCTI ONLINE/VALID public channels): new posts are matched locally against org-profile "
        "brands, domains, CNPJ roots, own card BINs and suppliers, scrubbed, and reported as a deduplicated digest."
    )
    category = "darkweb_ransomware"
    accepts = _ACCEPTS
    produces = {T.URL, T.DOMAIN, T.BTC, T.ETH}
    tags = {"watch_only", "watch_source"}
    reference = "https://telegram.org/tos"
    notice = (
        "Only inside `v3lum watch`: public t.me/s previews only, text only (media, files and links in posts are never "
        "fetched), no account, session, joining or bot token. Org-profile keywords never leave the machine: t.me receives "
        "channel handles only. Channels come from the team list (justification, owner, review date, CTI lead and legal "
        "review) and deepdarkCTI ONLINE/VALID public entries. Post text is scrubbed before alerts (PAN -> BIN6+last4, CPF "
        "masked, credentials and leaked records dropped, secrets as type + hash). Natural persons are never watched."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "telegram"
    sources = (SOURCE_TME, SOURCE_DDC)
    hosts = ("t.me",)
    access_model = "free_noauth_limited"
    max_requests = WATCH_MAX_CHANNELS * TME_MAX_PAGES
    expected_latency = 600.0
    timeout = 1800.0
    min_interval = TME_MIN_INTERVAL_S
    max_pivots = PIVOT_CAP
    default_enabled = False
    settings = {
        "telegram_channel_watch_list_path": SettingSpec("", "Team-maintained channel list (JSON, schema of v3lum/data/telegram_channel_watch/"
                                                            "telegram_watch.json); empty = the bundled reviewed list"),
        "telegram_channel_watch_use_deepdarkcti": SettingSpec(True, "Also watch deepdarkCTI ONLINE/VALID public Telegram channels"),
        "telegram_channel_watch_max_channels": SettingSpec(WATCH_MAX_CHANNELS, "Channels per cycle (at most 50)"),
        "telegram_channel_watch_cycle_minutes": SettingSpec(60, "Minimum minutes between two watch cycles (at least 60)"),
        "telegram_channel_watch_max_alerts": SettingSpec(200, "New alerts reported per cycle; the rest is summarised in one line"),
        "telegram_channel_watch_muted_channels": SettingSpec([], "Channel handles whose matches are muted"),
        "telegram_channel_watch_muted_rules": SettingSpec([], "Rule ids (e.g. brand:1a2b3c4d) whose matches are muted"),
    }

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        return run_cycle(self, entity, ctx)


@register
class TelegramWatchRss(Module):
    name = "telegram_watch_rss"
    title = "Dark Web Informer RSS companion feed (v3lum watch only)"
    description = (
        "Headline-only matching of org-profile watch rules in the Dark Web Informer RSS feed (headline + link only), the "
        "companion feed of telegram_channel_watch. Off until legal records the feed's terms (registry class 'unknown')."
    )
    category = "darkweb_ransomware"
    accepts = _ACCEPTS
    produces = frozenset()
    tags = {"watch_only", "watch_source", "offline"}
    reference = "https://darkwebinformer.com/terms-of-service/"
    notice = (
        "Registry terms 'unknown' and tier 'unknown' (pseudonymous operator): never runs until legal records the feed's terms "
        "(A1) - the feed is not even downloaded before that. Headline + link + date only; DarkFeed is login-gated and not used."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    sources = (SOURCE_DWI,)
    hosts = ()
    default_enabled = False

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if SOURCE_DWI not in ctx.allowed_sources or DWI_DATASET not in DATASETS:
            return res.mark("skipped", "Dark Web Informer RSS terms are 'unknown' until legal reviews them (A1): not downloaded, not used",
                            reason_code="licence")
        rules = build_watch_rules(ctx.org)
        if not rules:
            return res.mark("skipped", "no org-profile watch rules", reason_code="config")
        try:
            raw = ctx.data.fetch(DWI_DATASET).read_bytes()
        except (DatasetUnavailable, DatasetError, OSError) as exc:
            return res.mark("unavailable", f"feed not downloaded ({str(exc)[:120]})", reason_code="dataset")
        parsed = parse_rss_headlines(raw)
        if parsed["error"]:
            return res.mark("error", f"{parsed['error']}: could not verify")
        seen = list(ctx.state.get("seen", []) or [])
        hits = [h for h in match_headlines(parsed["items"], rules) if f"{h['link']}|{h['rule_id']}" not in set(seen)]
        ctx.state.set("seen", (seen + [f"{h['link']}|{h['rule_id']}" for h in hits])[-SEEN_KEYS_MAX:])
        if not hits:
            return res.mark("empty")
        res.attr("news_watch_hits", hits[:200])
        return res


__all__ = [
    "AUTOPAUSE_DAYS",
    "ENRICH_MAX_PER_HOUR",
    "TME_MAX_PAGES",
    "TME_MIN_INTERVAL_S",
    "WATCH_MAX_CHANNELS",
    "TelegramChannelWatch",
    "TelegramWatchRss",
    "build_watch_rules",
    "digest_lines",
    "dwi_registration_allowed",
    "excerpt_for",
    "fetch_channel_page",
    "make_alert",
    "match_headlines",
    "match_post",
    "next_page_before",
    "parse_deepdarkcti_telegram",
    "parse_rss_headlines",
    "plan_watch_cycle",
    "rule_id",
    "scrub_for_alert",
    "select_deepdarkcti_channels",
    "should_autopause",
    "tme_handle_from_link",
    "validate_team_watch_list",
]
