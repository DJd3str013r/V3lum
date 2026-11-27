"""cisa_advisories: CISA cybersecurity advisories and #StopRansomware IOC files, matched locally (P374, batch p2-G11-1).

Final conditions (FC) of P374 and where they are met:

* **FC1 merge gate.** Real fixtures must come from a network CISA serves. On 2026-11-26 the advisories feed
  ``all.xml`` answered 200 to the dataset manager (neutral provider profile, no header games) while curl's
  default client and every advisory page (e.g. ``aa24-109a``) got Akamai 'Access Denied' 403: the real feed
  is captured (``tests/fixtures/cisa_advisories/feed_real_trimmed.xml``) together with the real 403 page;
  an advisory page and a STIX 2.1 IOC file still need the team network (batch backlog), so the STIX path
  is exercised with a synthetic bundle of the documented shape. A block is BLOCKED with the manual
  advisory search link (A9).
* **FC2 rule 1 / rule 5.** A 403 or challenge is BLOCKED 'could not verify' (never 'no advisory'); the
  request carries the neutral provider profile only - no browser UA, header games or other evasion.
* **FC3 ingestion.** The feed ``all.xml`` is the dataset ``cisa_advisories.feed`` polled daily by the
  dataset manager and parsed with the shared safe XML feed parser of ``cti_news_rss`` (DOCTYPE/entities
  refused). IOC files are datasets ``cisa_advisories.ioc.<advisory>`` listed in the team-curated
  ``v3lum/data/cisa_advisories/ioc_files.json`` (empty until captured: attachment URLs are not
  discoverable behind the block and are never guessed); each is checked by :func:`stix_check` (bundle,
  ids, spec_version 2.1, STIX indicator patterns, object cap) before its indicator patterns go through the
  shared IOC extraction engine (``v3lum.core.ioc.extract``) - no STIX pattern parser here; attachments are
  untrusted data, never executed.
* **FC4 local matching.** Indicators are matched locally (disclosure 'none') and carry the advisory id and
  publication date; IP/domain/URL indicators older than 90 days are 'historical' context, hashes keep
  their weight.
* **FC5 benign values.** Legitimate tools named by an indicator (PsExec, AnyDesk, Rclone... in
  :data:`DUAL_USE_TOOLS`) are tagged ``dual_use``; public resolvers, cloud ranges and known-good hashes
  are tagged through the P169 warninglists and are never matched as malicious (an unusable warninglist
  index fails closed: 'warninglist unavailable', never malicious).
* **FC6 indexing and cards.** Advisories are indexed by family/actor through the P295 alias index
  (unresolved names listed), by ATT&CK ids (P292: from STIX attack-patterns and descriptions) and by CVEs;
  actor, family, keyword and CVE cards show advisory id, title, date, link and 'IOC file available'; matched
  IOCs are tagged ``cisa_advisory``; the dataset date is shown (``dataset_age``). US Government work
  (public domain), noted in every card.
"""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DataStore, DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.cti_framework.cti_news_rss import clean_text, fold_text, parse_date, parse_feed
from v3lum.modules.file_analysis.file_type_sniff import UnsafeXML, safe_xml_parse

FEED_SOURCE = "cisa.advisories"
IOC_SOURCE = "cisa.advisories_ioc"
FEED_DATASET = "cisa_advisories.feed"
FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
IOC_FILES = "cisa_advisories/ioc_files.json"
IOC_PREFIX = "cisa_advisories.ioc."
DAILY = 86400  # FC3
IOC_TTL = 30 * 86400  # attachments do not change once published
HORIZON_DAYS = 90  # FC4
FEED_MAX_BYTES = 4 * 1024 * 1024
IOC_MAX_BYTES = 5 * 1024 * 1024
STIX_MAX_OBJECTS = 20_000
MAX_CARDS = 10
TERMINAL_LINKS = 5
MANUAL_LINK = "https://www.cisa.gov/news-events/cybersecurity-advisories?search_api_fulltext={q}"
ATTRIBUTION = "CISA cybersecurity advisories: U.S. Government work (public domain), https://www.cisa.gov/news-events/cybersecurity-advisories"
NETWORK_TYPES = frozenset({T.IPV4, T.IPV6, T.CIDR, T.DOMAIN, T.URL})
IOC_ENTITY_TYPES = frozenset({T.IPV4, T.IPV6, T.DOMAIN, T.URL, T.MD5, T.SHA1, T.SHA256})
#: FC5: legitimate tools advisories list (folded): dual_use, never malicious.
DUAL_USE_TOOLS = ("psexec", "paexec", "anydesk", "atera", "screenconnect", "connectwise control", "teamviewer", "splashtop", "logmein",
                  "rclone", "megasync", "mega", "winscp", "filezilla", "putty", "advanced ip scanner", "angry ip scanner", "softperfect",
                  "netscan", "adfind", "ngrok", "cloudflared", "7-zip", "winrar", "procdump", "process explorer", "process hacker",
                  "level.io", "simplehelp", "meshagent", "syncro", "pdq deploy", "remote utilities", "rsync", "bitsadmin", "certutil")
_CISA_ID = re.compile(r"(?<![a-z0-9])(aa\d{2}-\d{3}[a-z]|icsm?a-\d{2}-\d{3}-\d{2}[a-z]?)(?![a-z0-9])", re.I)
_TECH = re.compile(r"(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![0-9])")


# ------------------------------------------------------------------------------------------ feed (FC2/FC3/FC6)


def advisory_id(text: Any) -> str | None:
    """'.../cybersecurity-advisories/aa24-131a' or 'AA24-131A' -> 'AA24-131A'; ICS ids 'icsa-26-328-01' -> 'ICSA-26-328-01'."""
    m = _CISA_ID.search(str(text or ""))
    return m.group(1).upper() if m else None


def family_from_title(title: Any) -> str | None:
    """'#StopRansomware: Akira Ransomware' -> 'Akira' (None for other advisories)."""
    m = re.match(r"(?i)^#?stop\s*ransomware\s*[:\-]\s*(.+)$", clean_text(title, 200))
    if not m:
        return None
    family = re.sub(r"(?i)\s+ransomware(\s+variant)?\s*$", "", m.group(1)).strip()
    return family or None


def _item_techniques(raw: bytes) -> dict[str, list[str]]:
    """ATT&CK ids read in memory from item descriptions (facts), keyed by item link."""
    out: dict[str, list[str]] = {}
    try:
        root = safe_xml_parse(raw.lstrip(b"\xef\xbb\xbf").lstrip(), max_bytes=FEED_MAX_BYTES)
    except (UnsafeXML, ValueError):
        return out
    channel = root.find("channel")
    for item in channel.findall("item") if channel is not None else []:
        link = (item.findtext("link") or "").strip()
        text = "".join(item.find("description").itertext()) if item.find("description") is not None else ""
        ids = sorted({m.upper() for m in _TECH.findall(text[:50_000])})
        if link and ids:
            out[link] = ids
    return out


def parse_advisories(raw: Any) -> dict[str, Any]:
    """FC3/FC6: the advisories feed -> parse_feed result whose items also carry advisory_id, stop_ransomware,
    family, cves and techniques."""
    data = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw or b"")
    res = parse_feed(data, "cisa_advisories", max_bytes=FEED_MAX_BYTES)
    if res["status"] != "ok":
        return res
    techniques = _item_techniques(data)
    for item in res["items"]:
        item["advisory_id"] = advisory_id(item.get("link")) or advisory_id(item.get("title"))
        item["stop_ransomware"] = "stopransomware" in fold_text(item.get("title")).replace(" ", "")
        item["family"] = family_from_title(item.get("title"))
        item["techniques"] = techniques.get(item["link"], [])
    return res


def _validate_feed(path: Path) -> bool:
    parsed = parse_advisories(Path(path).read_bytes())
    if parsed["status"] == "error":
        raise ValueError(parsed["reason"])
    return True


# ------------------------------------------------------------------------------------------ STIX IOC files (FC3/FC4/FC5)


def stix_check(doc: Any, max_objects: int = STIX_MAX_OBJECTS) -> str | None:
    """FC3 schema check before the shared IOC ingestion: None for a plausible STIX 2.1 bundle, else why."""
    if not isinstance(doc, dict):
        return "STIX document is not an object"
    if doc.get("type") != "bundle":
        return f"not a STIX bundle (type={clean_text(doc.get('type'), 30)})"
    if not re.fullmatch(r"bundle--[0-9a-fA-F-]{36}", str(doc.get("id") or "")):
        return "bad bundle id"
    if "spec_version" in doc and str(doc.get("spec_version")) != "2.1":
        return f"STIX bundle spec_version {clean_text(doc.get('spec_version'), 10)} (2.1 required)"
    objects = doc.get("objects")
    if not isinstance(objects, list) or not objects:
        return "STIX bundle without objects"
    if len(objects) > max_objects:
        return f"STIX bundle has {len(objects)} objects (cap {max_objects})"
    for k, obj in enumerate(objects):
        if not isinstance(obj, dict):
            return f"STIX object {k} is not a mapping"
        otype = obj.get("type")
        if not isinstance(otype, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,249}", otype):
            return f"STIX object {k} has an invalid type"
        if not isinstance(obj.get("id"), str) or not obj["id"].startswith(otype + "--"):
            return f"STIX object {k} id does not match its type"
        if "spec_version" in obj and str(obj.get("spec_version")) != "2.1":
            return f"STIX object {k} spec_version {clean_text(obj.get('spec_version'), 10)} (2.1 required)"
        if otype == "indicator" and (not str(obj.get("pattern") or "").strip() or str(obj.get("pattern_type") or "stix") != "stix"):
            return f"STIX indicator {k} without a STIX pattern"
    return None


def stix_summary(doc: dict[str, Any]) -> dict[str, Any]:
    """FC6 facts from structured STIX fields: report name/date/id, ATT&CK ids, CVEs, malware, tools, and the
    indicators (pattern values extracted by the shared IOC engine, never a STIX pattern parser here)."""
    from v3lum.core.ioc import extract  # shared IOC extraction engine (WP17)

    out: dict[str, Any] = {"report_name": None, "published": None, "advisory_id": None, "attack_ids": [], "cves": [], "malware": [],
                           "tools": [], "indicators": []}
    for obj in doc["objects"]:
        otype = obj["type"]
        if otype == "report":
            out["report_name"] = clean_text(obj.get("name"), 200) or None
            out["published"] = obj.get("published")
            out["advisory_id"] = advisory_id(obj.get("name")) or out["advisory_id"]
        elif otype == "attack-pattern":
            for ref in obj.get("external_references") if isinstance(obj.get("external_references"), list) else []:
                if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack" and re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(ref.get("external_id"))):
                    out["attack_ids"].append(ref["external_id"])
        elif otype == "vulnerability":
            name = str(obj.get("name") or "").upper()
            if re.fullmatch(r"CVE-\d{4}-\d{4,7}", name):
                out["cves"].append(name)
        elif otype in ("malware", "tool"):
            name = clean_text(obj.get("name"), 120)
            if name:
                out["malware" if otype == "malware" else "tools"].append(name)
        elif otype == "indicator":
            label = clean_text(obj.get("name"), 200)
            description = clean_text(obj.get("description"), 300)
            for item in extract(str(obj.get("pattern"))[:4000], limit=50, source_type="text").entities:
                if item.entity.type in IOC_ENTITY_TYPES:
                    out["indicators"].append({"type": item.entity.type.value, "value": item.entity.value, "name": label,
                                              "description": description, "valid_from": obj.get("valid_from")})
    for key in ("attack_ids", "cves", "malware", "tools"):
        out[key] = sorted(set(out[key]))
    return out


def dual_use_names(text: Any) -> list[str]:
    """FC5: legitimate tools named in an indicator name or description (folded)."""
    blob = fold_text(text)
    return [t for t in DUAL_USE_TOOLS if re.search(r"(?<![0-9a-z])" + re.escape(t) + r"(?![0-9a-z])", blob)]


def ioc_tags(etype: T, value: str, indicator: dict[str, Any], published: Any, now: datetime) -> dict[str, Any]:
    """FC4/FC5/FC6 tags of one matched indicator: cisa_advisory always; historical for network IOCs older than
    90 days (or undated); dual_use; warninglist / known_good from P169 (fail closed: never malicious)."""
    tags = ["cisa_advisory"]
    dt = parse_date(published) or parse_date(indicator.get("valid_from"))
    age = (now - dt).days if dt else None
    historical = etype in NETWORK_TYPES and (age is None or age > HORIZON_DAYS)
    if historical:
        tags.append("historical")
    dual = dual_use_names(f"{indicator.get('name') or ''} {indicator.get('description') or ''}")
    if dual:
        tags.append("dual_use")
    warn: list[str] = []
    try:
        from v3lum.modules.threat_intel_ioc.warninglists import local_classification
        cls = local_classification(Entity.make(etype, value))
    except Exception:  # noqa: BLE001 - fail closed below
        cls = None
    if cls is None:
        warn.append("warninglist unavailable")
    elif cls.get("outcome") in ("suppress", "tag") or cls.get("categories"):
        tags.append("warninglist")
        warn = sorted({str(m.get("list")) for m in (cls.get("suppress_matches") or []) + (cls.get("tag_matches") or [])})[:5]
        if "empty_file_hash" in {m.get("category") for m in cls.get("suppress_matches") or []} or "known_fp" in (cls.get("categories") or []):
            tags.append("known_good")
    return {"tags": tags, "historical": historical, "age_days": age, "dual_use_tools": dual, "warninglists": warn,
            "matchable_as_malicious": not (dual or warn or "known_good" in tags)}


def _validate_ioc(path: Path) -> bool:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, RecursionError) as exc:
        raise ValueError(f"IOC file is not JSON ({str(exc)[:60]})") from exc
    problem = stix_check(doc)
    if problem:
        raise ValueError(problem)
    return True


# ------------------------------------------------------------------------------------------ datasets

register_dataset(FEED_DATASET, FEED_URL, ttl=DAILY, description="CISA cybersecurity advisories feed all.xml (P374, daily)",
                 licence="U.S. Government work (public domain)", terms_class="open", attribution=ATTRIBUTION, source=FEED_SOURCE,
                 validate=_validate_feed, min_bytes=128, expect="bytes", max_bytes=FEED_MAX_BYTES, large=False)


def load_ioc_files() -> list[dict[str, Any]]:
    """The team-curated IOC attachment list ({advisory_id, url, published}); empty until captured (FC1)."""
    try:
        doc = DataStore.bundled_json(IOC_FILES)
    except (OSError, ValueError):  # pragma: no cover - the file ships with the module
        return []
    out = []
    for entry in doc.get("files") if isinstance(doc, dict) and isinstance(doc.get("files"), list) else []:
        aid = advisory_id((entry or {}).get("advisory_id")) if isinstance(entry, dict) else None
        url = str(entry.get("url") or "") if isinstance(entry, dict) else ""
        if aid and url.startswith("https://www.cisa.gov/"):
            out.append({"advisory_id": aid, "url": url, "published": entry.get("published")})
    return out


def register_ioc_file(entry: dict[str, Any]) -> str:
    """Register the dataset of one curated IOC attachment (import time; tests call it directly)."""
    name = IOC_PREFIX + entry["advisory_id"].lower()
    register_dataset(name, entry["url"], ttl=IOC_TTL, description=f"CISA advisory {entry['advisory_id']} IOC file (STIX 2.1, P374)",
                     licence="U.S. Government work (public domain)", terms_class="open", attribution=ATTRIBUTION, source=IOC_SOURCE,
                     validate=_validate_ioc, min_bytes=64, expect="json", max_bytes=IOC_MAX_BYTES, large=False)
    return name


IOC_FILE_ENTRIES: list[dict[str, Any]] = load_ioc_files()
for _entry in IOC_FILE_ENTRIES:
    register_ioc_file(_entry)

_MEMO: dict[str, Any] = {}
_MEMO_LOCK = threading.Lock()


def _memo(key: str, sha: str, build: Any) -> Any:
    with _MEMO_LOCK:
        hit = _MEMO.get(key)
        if hit and hit[0] == sha:
            return hit[1]
    value = build()
    with _MEMO_LOCK:
        _MEMO[key] = (sha, value)
    return value


def canonical_name(name: str) -> str | None:
    from v3lum.modules.cti_framework.ransomware_matrices import canonical_group  # P295 join, shared helper

    return canonical_group([name])


def index_advisories(items: list[dict[str, Any]], ioc_ids: set[str]) -> dict[str, Any]:
    """FC6: {by_family {canonical or raw: [card]}, by_cve, by_technique, cards, unresolved}."""
    by_family: dict[str, list[dict[str, Any]]] = {}
    by_cve: dict[str, list[dict[str, Any]]] = {}
    by_technique: dict[str, list[dict[str, Any]]] = {}
    unresolved: list[str] = []
    cards = []
    for item in items:
        card = {"advisory_id": item.get("advisory_id"), "title": item["title"], "published": item.get("published"), "link": item["link"],
                "family": item.get("family"), "stop_ransomware": item.get("stop_ransomware"), "cves": item.get("cves") or [],
                "techniques": item.get("techniques") or [], "ioc_file": bool(item.get("advisory_id") in ioc_ids)}
        cards.append(card)
        if card["family"]:
            canon = canonical_name(card["family"])
            if not canon and card["family"] not in unresolved:
                unresolved.append(card["family"])
            by_family.setdefault(fold_text(canon or card["family"]), []).append(card)
        for cve in card["cves"]:
            by_cve.setdefault(cve, []).append(card)
        for tid in card["techniques"]:
            by_technique.setdefault(tid, []).append(card)
    return {"by_family": by_family, "by_cve": by_cve, "by_technique": by_technique, "cards": cards, "unresolved": unresolved}


# ------------------------------------------------------------------------------------------ module


@register
class CisaAdvisories(Module):
    name = "cisa_advisories"
    title = "CISA cybersecurity advisories (#StopRansomware, IOC files)"
    description = (
        "Offline lookup of an actor, ransomware family, CVE or keyword in the local copy of the CISA cybersecurity advisories feed "
        "(advisory id, title, date, link, IOC file available), and of an IOC in the curated CISA advisory IOC files."
    )
    category = "cti_framework"
    accepts = {T.THREAT_ACTOR, T.MALWARE, T.CVE, T.KEYWORD} | IOC_ENTITY_TYPES
    produces = {T.CVE, T.MITRE}
    tags = {"offline", "free"}
    reference = "https://www.cisa.gov/news-events/cybersecurity-advisories"
    notice = (
        "U.S. Government work (public domain). www.cisa.gov sits behind Akamai bot management: when the advisories feed is refused "
        "(403 'Access Denied') the module reports BLOCKED 'could not verify', never 'no advisory', with the manual search link (A9)."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    provider = ""
    sources = (FEED_SOURCE, IOC_SOURCE)
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.05
    timeout = 60.0
    max_pivots = 30
    manual_link = MANUAL_LINK
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in IOC_ENTITY_TYPES:
            return bool(IOC_FILE_ENTRIES)  # no curated IOC file yet: nothing local to match an IOC against
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        res.attr("data_attribution", ATTRIBUTION)
        if entity.type in IOC_ENTITY_TYPES:
            return self._ioc(entity, ctx, res)
        return self._advisories(entity, ctx, res)

    # ---- helpers ------------------------------------------------------------------------------------
    @staticmethod
    def _fetch(ctx: Any, name: str) -> tuple[Path | None, Any, tuple[str, str, str] | None]:
        try:
            path = ctx.data.fetch(name)
            return path, ctx.data.info(name), None
        except DatasetUnavailable as exc:
            return None, None, ("unavailable", "dataset", str(exc)[:200])
        except DatasetError as exc:
            code = str(getattr(exc, "reason_code", "") or "error")
            if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
                return None, None, ("blocked", code, str(exc)[:200])
            if code == "rate_limited":
                return None, None, ("rate_limited", "rate_limited", str(exc)[:200])
            return None, None, ("error", "timeout" if code == "timeout" else "error", str(exc)[:200])

    @staticmethod
    def _age(res: ModuleResult, info: Any, name: str) -> None:
        if info is not None and info.fetched_at:
            age = f"{info.age_hours / 24:.1f} days" if info.age_hours is not None else "age unknown"
            res.attr("dataset_age", [f"{name}, fetched {str(info.fetched_at)[:10]} ({age}{', stale' if info.stale else ''})"])

    # ---- advisories (FC6) ---------------------------------------------------------------------------
    def _advisories(self, entity: Entity, ctx: Any, res: ModuleResult) -> ModuleResult:
        path, info, problem = self._fetch(ctx, FEED_DATASET)
        if problem:
            status, code, reason = problem
            text = f"CISA advisories feed could not be read ({reason}): could not verify, never 'no advisory'"
            return res.mark(status, text, reason_code=code)
        self._age(res, info, FEED_DATASET)
        try:
            parsed = _memo(FEED_DATASET, info.sha256, lambda: parse_advisories(Path(path).read_bytes()))
        except OSError as exc:
            return res.mark("error", f"local advisories feed unreadable ({str(exc)[:80]}): could not verify")
        if parsed["status"] == "error":
            return res.mark("error", f"advisories feed unusable ({parsed['reason']}): could not verify")
        index = _memo(f"{FEED_DATASET}:index", info.sha256, lambda: index_advisories(parsed["items"], {e["advisory_id"] for e in IOC_FILE_ENTRIES}))
        value = clean_text(entity.value, 200)
        cards: list[dict[str, Any]] = []
        if entity.type is T.CVE:
            cards = list(index["by_cve"].get(value.upper(), []))
        else:
            canon = canonical_name(value) if entity.type in (T.THREAT_ACTOR, T.MALWARE) else None
            cards = list(index["by_family"].get(fold_text(canon or value), []))
            rx = re.compile(r"(?<![0-9a-z])" + re.escape(fold_text(value)) + r"(?![0-9a-z])") if len(fold_text(value)) >= 3 else None
            if rx:
                cards += [c for c in index["cards"] if rx.search(fold_text(c["title"])) and c not in cards]
        if index["unresolved"] and entity.type in (T.THREAT_ACTOR, T.MALWARE):
            res.attr("cisa_families_unresolved", index["unresolved"])
        res.raw = {"query": value, "advisories": [c["advisory_id"] or c["link"] for c in cards], "feed_items": len(index["cards"])}
        if not cards:
            return res.mark("empty", f"no advisory of the local CISA feed copy ({len(index['cards'])} items) names {value}")
        cards.sort(key=lambda c: (c.get("published") or "", c["title"]), reverse=True)
        res.attr("cisa_advisories", [{k: v for k, v in c.items() if v not in (None, [], "", False) and k not in ("cves", "techniques")}
                                     for c in cards[:MAX_CARDS]])
        for card in cards[:TERMINAL_LINKS]:
            res.link(f"CISA {card.get('advisory_id') or 'advisory'} ({(card.get('published') or '')[:10]}): {clean_text(card['title'], 100)}", card["link"])
        if entity.type is not T.CVE:
            for card in cards[:MAX_CARDS]:
                for cve in card["cves"]:
                    res.pivot(T.CVE, cve, "exploits", confidence="probable", expand=False, note=f"named in CISA advisory {card.get('advisory_id') or card['link']}")
                for tid in card["techniques"]:
                    res.pivot(T.MITRE, tid, "uses_technique", confidence="probable", expand=False,
                              note=f"ATT&CK id in CISA advisory {card.get('advisory_id') or card['link']}")
        res.finding(
            "Named in CISA cybersecurity advisories",
            "info",
            f"{len(cards)} CISA advisory(ies) name {value}: " + "; ".join(
                f"{c.get('advisory_id') or 'advisory'} {(c.get('published') or '')[:10]} {clean_text(c['title'], 80)}"
                + (" (IOC file available)" if c["ioc_file"] else "") for c in cards[:TERMINAL_LINKS]) + f". {ATTRIBUTION}",
            confidence="confirmed",
            tags=["cisa_advisory", "info"] + (["ransomware"] if any(c["stop_ransomware"] for c in cards) else []),
            references=[c["link"] for c in cards[:MAX_CARDS]],
            source=FEED_SOURCE,
            observed_last=cards[0].get("published"),
        )
        return res

    # ---- IOC files (FC3/FC4/FC5) ----------------------------------------------------------------------
    def _ioc(self, entity: Entity, ctx: Any, res: ModuleResult) -> ModuleResult:
        now = ctx.now()
        matches = []
        failures = []
        read = 0
        for entry in IOC_FILE_ENTRIES:
            name = IOC_PREFIX + entry["advisory_id"].lower()
            path, info, problem = self._fetch(ctx, name)
            if problem:
                failures.append(problem)
                continue
            try:
                summary = _memo(name, info.sha256, lambda p=path: stix_summary(json.loads(Path(p).read_text(encoding="utf-8-sig"))))
            except (OSError, ValueError, RecursionError) as exc:
                failures.append(("error", "error", f"{name} unreadable ({str(exc)[:60]})"))
                continue
            read += 1
            for indicator in summary["indicators"]:
                if indicator["type"] != entity.type.value or indicator["value"].lower() != entity.value.lower():
                    continue
                published = summary.get("published") or entry.get("published")
                tags = ioc_tags(entity.type, entity.value, indicator, published, now)
                matches.append({"advisory_id": summary.get("advisory_id") or entry["advisory_id"], "published": str(published or "")[:10] or None,
                                "indicator": indicator.get("name"), **tags, "report": summary.get("report_name")})
        for status, code, reason in failures:
            res.source_status(IOC_SOURCE, status, reason_code=code, reason=reason)
        if not read:
            status, code, reason = failures[0] if failures else ("unavailable", "dataset", "no CISA IOC file is available locally")
            return res.mark(status, f"{reason}: could not verify", reason_code=code)
        res.raw = {"files_read": read, "matches": len(matches)}
        if not matches:
            return res.mark("empty", f"not in the {read} local CISA advisory IOC file(s)")
        res.attr("cisa_ioc_matches", [{k: v for k, v in m.items() if v not in (None, [], "")} for m in matches])
        for match in matches:
            if match["matchable_as_malicious"] and not match["historical"]:
                severity = "high" if entity.type not in NETWORK_TYPES else "medium"
                tags = list(match["tags"])
            else:
                severity = "info"
                tags = list(match["tags"]) + ["context_only"]
            reason = ("historical (> 90 days: infrastructure rotates)" if match["historical"] else "") or (
                "dual-use tool, never malicious" if match["dual_use_tools"] else "") or (
                f"warninglisted ({', '.join(match['warninglists'])})" if match["warninglists"] else "")
            res.finding(
                "Indicator listed in a CISA advisory IOC file",
                severity,
                f"{entity.value} is an indicator of CISA advisory {match['advisory_id']} ({match['published'] or 'undated'}): "
                f"{match.get('indicator') or 'indicator'}." + (f" Context only: {reason}." if severity == "info" else "") + f" {ATTRIBUTION}",
                confidence="probable" if severity != "info" else "possible",
                criterion=(f"listed by CISA advisory {match['advisory_id']} (STIX 2.1 IOC file), local match; "
                           + ("file hash keeps its weight" if entity.type not in NETWORK_TYPES else "network indicator within 90 days")) if severity != "info" else "",
                tags=tags,
                source=IOC_SOURCE,
                observed_last=match["published"],
                key=match["advisory_id"],
                data={"advisory_id": match["advisory_id"], "historical": match["historical"], "matchable_as_malicious": match["matchable_as_malicious"]},
            )
        return res
