"""User-agent parsing and bad-crawler/scanner matching, offline (P317, batch p3-G12-1).

Final conditions, as implemented here:

1. **Offline matching** (disclosure ``none``: the analysed user agent never leaves the machine) of user agents
   from the team's own logs and alerts: an own, V3LUM-authored regex table (browser, OS, device, good bots,
   research scanners, attack tools, HTTP libraries) plus the teler-resources ``bad-crawlers.txt`` list (CC BY 4.0,
   patterns from Crawler-Detect, MIT), downloaded at runtime by the dataset manager (registered dataset
   ``teler_bad_crawlers.txt``, never bundled) with attribution in the notice fragment and in every result that
   used it (``res.datasets`` citation + ``ua_parsed.bad_crawler_attribution``). When the list cannot be fetched
   the own table still answers and the dataset source is reported UNAVAILABLE ``dataset`` (could not verify).
2. The PHPIDS-derived web-attack filters (teler ``common-web-attacks.json``, LGPL-3.0 payload PCREs) are never
   used for UA matching and never bundled: :func:`is_phpids_filter_set` refuses them as a UA list.
3. **ReDoS safety**: every user agent is truncated to 1 KB (UTF-8 safe) before matching; every regex of the own
   table is bounded by construction and every downloaded pattern passes a static screen (:func:`redos_static_flags`:
   nested quantifiers, quantified alternations, backreferences, length) before compilation, and the redundant
   leading ``[...]*`` of Crawler-Detect's generic pattern is dropped (:func:`normalise_crawler_pattern`, same
   matches with ``re.search``, linear instead of quadratic). The tests fuzz every own-table regex and the
   compiled list with adversarial 1 KB inputs under a per-UA time budget.
4. **Results**: scanner and attack-tool user agents (sqlmap, nuclei, masscan, ...) are tagged ``scanner`` - known
   research scanners ``benign_scanner`` - never malicious; a user agent is trivially spoofed, so a UA alone never
   gives more than LOW (``ua_risk_ceiling`` 'LOW'; scanner findings are LOW, everything else INFO). A bare
   Crawler-Detect hit means 'non-human agent' (link previews, Office), never 'bad': category ``automation``.
5. Fixtures: the teler captures plus synthetic user agents (browsers, bots, scanners, a ReDoS candidate).
"""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "github.user_agent_analysis_teler_bad_crawlers"
DATASET = "teler_bad_crawlers.txt"
TELER_BAD_CRAWLERS_URL = "https://raw.githubusercontent.com/kitabisa/teler-resources/master/db/bad-crawlers.txt"
TELER_ATTRIBUTION = ("teler-resources bad-crawlers.txt by kitabisa, CC BY 4.0 (https://github.com/kitabisa/teler-resources); "
                     "patterns derived from JayBizzle/Crawler-Detect (MIT)")
UA_MAX_BYTES = 1024
UA_RISK_CEILING = "LOW"
MIN_PATTERNS = 1000  # the real list holds ~1,741 patterns (2026-11-26); fewer means a broken download
MAX_TEXT_LINES = 5000
MAX_DISTINCT_UAS = 200


# ======================================================================================================
# ReDoS screen and the teler list (P317 cond 2-3)
# ======================================================================================================

_NESTED_Q_RE = re.compile(r"\((?:[^()\\]|\\.)*(?:[+*]|\{\d+,\})(?:[^()\\]|\\.)*\)(?:[+*]|\{\d+,?\d*\})")
_QUANT_ALT_RE = re.compile(r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)(?:[+*]|\{\d+,\d*\})")
_BACKREF_RE = re.compile(r"\\[1-9]|\(\?P=")
_LEAD_STAR_CLASS_RE = re.compile(r"^\[(?:[^\]\\]|\\.)+\]\*(?=.)")
REDOS_REJECT = ("nested_quantifier", "quantified_alternation", "backreference", "too_long", "not_a_string")


def truncate_ua(ua: Any, limit: int = UA_MAX_BYTES) -> tuple[str, bool]:
    """(text, truncated) with at most ``limit`` UTF-8 bytes; non-str input -> ('', False)."""
    if not isinstance(ua, str):
        return "", False
    raw = ua.encode("utf-8", "replace")
    if len(raw) <= limit:
        return ua, False
    return raw[:limit].decode("utf-8", "ignore"), True


def redos_static_flags(pattern: Any) -> list[str]:
    """Static ReDoS screen for one regex: 'nested_quantifier', 'quantified_alternation', 'backreference',
    'too_long', 'multiple_dotstar' (the last one only informs the timing test)."""
    if not isinstance(pattern, str):
        return ["not_a_string"]
    flags = []
    if len(pattern) > 512:
        flags.append("too_long")
    if _NESTED_Q_RE.search(pattern):
        flags.append("nested_quantifier")
    if _QUANT_ALT_RE.search(pattern):
        flags.append("quantified_alternation")
    if _BACKREF_RE.search(pattern):
        flags.append("backreference")
    if len(re.findall(r"(?<!\\)\.\*", pattern)) >= 2:
        flags.append("multiple_dotstar")
    return flags


def normalise_crawler_pattern(pattern: str) -> str:
    """Drop a redundant unanchored leading '[...]*' (it may match empty, so re.search finds the same UAs)."""
    return _LEAD_STAR_CLASS_RE.sub("", pattern, count=1) if isinstance(pattern, str) else pattern


def _looks_like_html(text: str) -> bool:
    head = text[:2048].lstrip().lower()
    return head.startswith(("<!doctype html", "<html", "<?xml")) or "<html" in head[:512] or "<body" in head[:512]


def parse_bad_crawlers(text: Any) -> dict[str, Any]:
    """Parse the teler bad-crawlers list: {'patterns', 'normalised', 'rejected', 'errors'} (lines kept verbatim)."""
    res: dict[str, Any] = {"patterns": [], "normalised": [], "rejected": [], "errors": []}
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    if not isinstance(text, str):
        res["errors"].append("not text")
        return res
    if _looks_like_html(text):
        res["errors"].append("HTML instead of the bad-crawlers list")
        return res
    if text.strip() in ("404: Not Found", "400: Invalid request"):
        res["errors"].append(f"dataset body is an error page: {text.strip()}")
        return res
    if is_phpids_filter_set(text):
        res["errors"].append("PHPIDS-derived web-attack filters (LGPL-3.0) are not UA patterns")
        return res
    for line in text.replace("\r\n", "\n").split("\n"):
        line = line.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        flags = [f for f in redos_static_flags(line) if f in REDOS_REJECT]
        if flags:
            res["rejected"].append((line, flags[0]))
            continue
        norm = normalise_crawler_pattern(line)
        try:
            re.compile(norm, re.I)
        except re.error as exc:
            res["rejected"].append((line, f"compile_error: {exc}"))
            continue
        if norm != line:
            res["normalised"].append((line, norm))
        res["patterns"].append(norm)
    return res


def bad_crawlers_problem(parsed: dict[str, Any]) -> str:
    """Why a parsed list must not be used ('' = usable)."""
    if parsed.get("errors"):
        return "; ".join(parsed["errors"])
    n = len(parsed.get("patterns", []))
    if n < MIN_PATTERNS:
        return f"bad-crawlers list too short ({n} patterns < {MIN_PATTERNS})"
    if len(parsed.get("rejected", [])) > max(5, n // 100):
        return f"too many rejected patterns ({len(parsed['rejected'])})"
    return ""


def validate_bad_crawlers_file(path: Path) -> bool:
    """Dataset-manager validator: a download replaces the previous copy only when it parses as a real list."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bad_crawlers_problem(parse_bad_crawlers(text)) == ""


def is_phpids_filter_set(obj: Any) -> str | None:
    """P317 cond 2 guard: a reason when ``obj`` looks like the PHPIDS filter set ({'filters': [{'rule','tags','impact'}]})."""
    if isinstance(obj, (bytes, bytearray)):
        obj = bytes(obj).decode("utf-8", "replace")
    if isinstance(obj, str):
        import json

        s = obj.strip()
        if not s.startswith("{"):
            return None
        try:
            obj = json.loads(s)
        except ValueError:
            return None
    if isinstance(obj, dict) and isinstance(obj.get("filters"), list) and obj["filters"]:
        first = obj["filters"][0]
        if isinstance(first, dict) and {"rule", "tags", "impact"} <= set(first):
            return "PHPIDS-derived web-attack filters (LGPL-3.0) are not UA patterns (P317 cond 2)"
    return None


def compile_crawler_matcher(patterns: Any) -> re.Pattern[str] | None:
    pats = [p for p in (patterns or []) if isinstance(p, str) and p]
    if not pats:
        return None
    return re.compile("|".join(f"(?:{p})" for p in pats), re.I)


# ======================================================================================================
# own UA table (V3LUM-authored; every repetition bounded, first match wins per group)
# ======================================================================================================

UA_BROWSERS = [
    ("Edge", r"\bEdg(?:e|A|iOS)?/(\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Opera", r"\b(?:OPR|Opera)[/ ](\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Samsung Internet", r"\bSamsungBrowser/(\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Yandex Browser", r"\bYaBrowser/(\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Chrome", r"\b(?:Chrome|CriOS)/(\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Firefox", r"\b(?:Firefox|FxiOS)/(\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Safari", r"\bVersion/(\d{1,10}(?:\.\d{1,10}){0,3})(?: Mobile/\w{1,20})? Safari/"),
    ("Internet Explorer", r"\bMSIE (\d{1,4}(?:\.\d{1,4})?)|\bTrident/\d{1,4}(?:\.\d{1,4})?;[^)]{0,100}?\brv:(\d{1,4}(?:\.\d{1,4})?)"),
]
UA_OS = [
    ("iOS", r"\((?:iPhone|iPad|iPod)[^)]{0,80}? OS (\d{1,10}(?:_\d{1,10}){0,3})"),
    ("Android", r"\bAndroid (\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Windows", r"\bWindows NT (\d{1,3}\.\d{1,3})"),
    ("macOS", r"\bMac OS X (\d{1,10}(?:[_.]\d{1,10}){0,3})"),
    ("ChromeOS", r"\bCrOS\b"),
    ("Linux", r"\bLinux\b|\bX11\b"),
]
WINDOWS_NT = {"10.0": "10/11", "6.3": "8.1", "6.2": "8", "6.1": "7", "6.0": "Vista", "5.1": "XP", "5.0": "2000"}
UA_GOOD_BOTS = [
    ("Googlebot", r"\bGooglebot\b|\bGoogle-InspectionTool\b|\bAdsBot-Google\b"),
    ("Bingbot", r"\bbingbot\b|\bBingPreview\b"),
    ("Applebot", r"\bApplebot\b"),
    ("YandexBot", r"\bYandex(?:Bot|Images)\b"),
    ("DuckDuckBot", r"\bDuckDuckBot\b"),
    ("Baiduspider", r"\bBaiduspider\b"),
    ("facebookexternalhit", r"\bfacebookexternalhit\b|\bmeta-externalagent\b"),
    ("Twitterbot", r"\bTwitterbot\b"),
    ("LinkedInBot", r"\bLinkedInBot\b"),
    ("Slackbot", r"\bSlackbot\b"),
    ("GPTBot", r"\bGPTBot\b|\bChatGPT-User\b|\bOAI-SearchBot\b"),
    ("ClaudeBot", r"\bClaudeBot\b|\banthropic-ai\b|\bClaude-User\b"),
    ("PerplexityBot", r"\bPerplexityBot\b"),
    ("AhrefsBot", r"\bAhrefsBot\b"),
    ("SemrushBot", r"\bSemrushBot\b"),
    ("CCBot", r"\bCCBot\b"),
    ("Bytespider", r"\bBytespider\b"),
    ("PetalBot", r"\bPetalBot\b"),
    ("WhatsApp link preview", r"^WhatsApp/"),
    ("TelegramBot", r"\bTelegramBot\b"),
    ("Discordbot", r"\bDiscordbot\b"),
    ("SkypeUriPreview", r"\bSkypeUriPreview\b"),
]
UA_RESEARCH_SCANNERS = [  # benign_scanner: identified research / attack-surface scanners
    ("Censys", r"\bCensysInspect\b|\bcensys\.io\b"),
    ("Palo Alto Cortex Xpanse", r"^Expanse\b|Palo Alto Networks"),
    ("InternetMeasurement", r"\bInternetMeasurement\b|internet-measurement\.com"),
    ("LeakIX", r"\bl9explore\b|\bl9tcpid\b|\bleakix\.net\b"),
    ("Netcraft", r"\bNETCRAFT\b|\bNetcraftSurveyAgent\b"),
    ("Shadowserver", r"\bshadowserver\b"),
    ("ONYPHE", r"\bonyphe\b"),
    ("BinaryEdge", r"\bbinaryedge\b"),
    ("Modat", r"\bModatScanner\b"),
]
UA_ATTACK_TOOLS = [  # scanner: offensive / vulnerability scanning tools (never 'malicious')
    ("sqlmap", r"\bsqlmap/"),
    ("Nuclei", r"\bnuclei\b"),
    ("masscan", r"\bmasscan\b"),
    ("Nikto", r"\bNikto\b"),
    ("Nmap NSE", r"Nmap Scripting Engine|\bnmap\.org\b"),
    ("ZGrab", r"\bzgrab\b"),
    ("WPScan", r"\bWPScan\b"),
    ("DirBuster", r"\bDirBuster\b"),
    ("gobuster", r"\bgobuster\b"),
    ("ffuf", r"\bFuzz Faster U Fool\b|\bffuf\b"),
    ("feroxbuster", r"\bferoxbuster\b"),
    ("Hydra", r"\(Hydra\)"),
    ("Acunetix", r"\bAcunetix\b"),
    ("Nessus", r"\bNessus\b"),
    ("OpenVAS", r"\bOpenVAS\b"),
    ("w3af", r"\bw3af\b"),
    ("Wfuzz", r"\bWfuzz\b"),
    ("commix", r"\bcommix\b"),
    ("Arachni", r"\bArachni\b"),
    ("Netsparker/Invicti", r"\bNetsparker\b|\bInvicti\b"),
    ("Jaeles", r"\bJaeles\b"),
    ("ZmEu", r"\bZmEu\b"),
    ("Log4Shell probe", r"\$\{jndi:"),
]
UA_HTTP_LIBS = [  # automation clients (tag 'automation')
    ("curl", r"^curl/"), ("Wget", r"^Wget/"), ("python-requests", r"\bpython-requests/"),
    ("python-httpx", r"\bpython-httpx/"), ("aiohttp", r"\baiohttp/"), ("Python-urllib", r"\bPython-urllib/"),
    ("Go-http-client", r"\bGo-http-client/"), ("okhttp", r"\bokhttp/"), ("axios", r"\baxios/"),
    ("Java", r"^Java/|\bJava-http-client/"), ("libwww-perl", r"\blibwww-perl/"),
    ("node-fetch", r"\bnode-fetch\b|^undici\b"), ("PowerShell", r"\bWindowsPowerShell/"),
]
UA_TABLE_GROUPS = (("browser", UA_BROWSERS), ("os", UA_OS), ("good_bot", UA_GOOD_BOTS),
                   ("research_scanner", UA_RESEARCH_SCANNERS), ("attack_tool", UA_ATTACK_TOOLS),
                   ("http_lib", UA_HTTP_LIBS))
_COMPILED = {g: [(n, re.compile(p, re.I)) for n, p in rules] for g, rules in UA_TABLE_GROUPS}
_MOBILE_RE = re.compile(r"\bMobile\b|\biPhone\b|\biPod\b|\bWindows Phone\b", re.I)
_TABLET_RE = re.compile(r"\biPad\b|\bTablet\b", re.I)


def ua_table_patterns() -> list[str]:
    """All own-table regexes (the ReDoS fuzz test runs each one)."""
    return [p for _, rules in UA_TABLE_GROUPS for _, p in rules]


def _first(group: str, ua: str) -> tuple[str | None, str | None]:
    for name, rx in _COMPILED[group]:
        m = rx.search(ua)
        if m:
            ver = next((g for g in m.groups() if g), None) if m.groups() else None
            return name, ver
    return None, None


def classify_user_agent(ua: Any, crawler_matcher: re.Pattern[str] | None = None) -> dict[str, Any]:
    """Offline UA analysis: category browser|bot|automation|scanner|benign_scanner|empty|unknown, browser/OS/device,
    tool, bad_crawler_match, exploit_probe, severity (info, low for scanners), risk_ceiling 'LOW'."""
    text, truncated = truncate_ua(ua)
    res: dict[str, Any] = {"truncated": truncated, "category": "unknown", "tags": [], "browser": None,
                           "browser_version": None, "os": None, "os_version": None, "device": None, "tool": None,
                           "bad_crawler_match": False, "exploit_probe": None, "severity": "info",
                           "risk_ceiling": UA_RISK_CEILING}
    if not text.strip():
        res["category"] = "empty"
        return res
    res["browser"], res["browser_version"] = _first("browser", text)
    os_name, os_ver = _first("os", text)
    if os_name == "Windows" and os_ver:
        os_ver = WINDOWS_NT.get(os_ver, os_ver)
    elif os_name in ("iOS", "macOS") and os_ver:
        os_ver = os_ver.replace("_", ".")
    res["os"], res["os_version"] = os_name, os_ver
    if _TABLET_RE.search(text) or (os_name == "Android" and not _MOBILE_RE.search(text)):
        res["device"] = "tablet"
    elif _MOBILE_RE.search(text):
        res["device"] = "mobile"
    elif res["browser"]:
        res["device"] = "desktop"
    if crawler_matcher is not None:
        res["bad_crawler_match"] = bool(crawler_matcher.search(text))
    research, _ = _first("research_scanner", text)
    tool, _ = _first("attack_tool", text)
    goodbot, _ = _first("good_bot", text)
    lib, _ = _first("http_lib", text)
    if research:
        res["category"], res["tool"], res["tags"] = "benign_scanner", research, ["benign_scanner"]
    elif tool:
        res["category"], res["tool"], res["tags"] = "scanner", tool, ["scanner"]
        res["severity"] = "low"
        if tool == "Log4Shell probe":
            res["exploit_probe"] = "log4shell_jndi"
    elif goodbot:
        res["category"], res["tool"], res["tags"], res["device"] = "bot", goodbot, ["bot"], "bot"
    elif lib:
        res["category"], res["tool"], res["tags"], res["device"] = "automation", lib, ["automation"], "bot"
    elif res["bad_crawler_match"]:
        res["category"], res["tags"], res["device"] = "automation", ["automation"], "bot"
    elif res["browser"]:
        res["category"] = "browser"
    return res


# combined log format: the user agent is the last quoted field
_COMBINED_UA_RE = re.compile(r'"([^"\n]{0,2048})"\s*$')
_HEADER_UA_RE = re.compile(r"^\s*User-Agent\s*:\s*(.{1,2048})$", re.I)


def user_agents_from_text(text: str) -> list[str]:
    """User agents found in log text: the last quoted field of combined-format lines and 'User-Agent:' lines
    (bounded: at most MAX_TEXT_LINES lines and MAX_DISTINCT_UAS distinct values)."""
    out: dict[str, None] = {}
    for line in text.splitlines()[:MAX_TEXT_LINES]:
        m = _HEADER_UA_RE.match(line)
        ua = m.group(1).strip() if m else None
        if ua is None and line.count('"') >= 4:
            m2 = _COMBINED_UA_RE.search(line)
            ua = m2.group(1).strip() if m2 else None
        if ua and ua != "-":
            out.setdefault(truncate_ua(ua)[0], None)
            if len(out) >= MAX_DISTINCT_UAS:
                break
    return list(out)


register_dataset(
    DATASET, TELER_BAD_CRAWLERS_URL, ttl=7 * 86400,
    description="teler-resources bad-crawlers.txt: Crawler-Detect user-agent patterns (one regex per line), runtime "
                "download only (P317 cond 1)",
    licence="CC-BY-4.0", terms_class="open", attribution=TELER_ATTRIBUTION, provider="github", source=SOURCE,
    validate=validate_bad_crawlers_file, min_bytes=10_000, max_bytes=1_000_000, expect="lines",
)

_MATCHER_LOCK = threading.Lock()
_MATCHERS: dict[str, tuple[re.Pattern[str] | None, int, str]] = {}


def _crawler_matcher(ctx: Any) -> tuple[re.Pattern[str] | None, str]:
    """(compiled matcher, problem) of the local teler list; compiled once per dataset sha256."""
    text = ctx.data.fetch_text(DATASET)
    info = ctx.data.info(DATASET)
    key = str(getattr(info, "sha256", "") or "") or str(hash(text))
    with _MATCHER_LOCK:
        hit = _MATCHERS.get(key)
        if hit is None:
            parsed = parse_bad_crawlers(text)
            problem = bad_crawlers_problem(parsed)
            matcher = None if problem else compile_crawler_matcher(parsed["patterns"])
            hit = (matcher, len(parsed["patterns"]), problem)
            if len(_MATCHERS) > 8:
                _MATCHERS.clear()
            _MATCHERS[key] = hit
    return hit[0], hit[2]


@register
class UserAgentAnalysis(Module):
    name = "user_agent_analysis"
    title = "User-agent analysis (own table + teler bad-crawlers)"
    description = ("Offline parsing of user agents from the team's own logs: browser/OS/device, bots, HTTP libraries, "
                   "research scanners and attack tools (tagged scanner, never malicious), plus the teler bad-crawlers list.")
    category = "utility"
    accepts = {T.USER_AGENT, T.TEXT}
    produces = frozenset()
    tags = {"offline"}
    reference = "https://github.com/kitabisa/teler-resources"
    notice = ("User agents are trivially spoofed: a UA alone never raises an IP's risk above LOW. Bad-crawler patterns: "
              + TELER_ATTRIBUTION + ".")
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SOURCE,)
    access_model = "offline"
    max_pivots = 0
    timeout = 30.0
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.TEXT:
            return bool(user_agents_from_text(entity.value))
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        matcher = None
        try:
            matcher, problem = _crawler_matcher(ctx)
            if problem:
                res.source_status(SOURCE, Status.ERROR, reason_code="error",
                                  reason=f"teler bad-crawlers list unusable ({problem}): own table only")
        except (DatasetUnavailable, DatasetError, OSError) as exc:
            res.source_status(SOURCE, Status.UNAVAILABLE, reason_code="dataset",
                              reason=f"teler bad-crawlers list not available ({str(exc)[:120]}): own table only - run "
                                     f"v3lum data update {DATASET}")
        if entity.type is T.USER_AGENT:
            info = classify_user_agent(entity.value, matcher)
            self._emit_one(res, info, matcher is not None)
            return res
        uas = user_agents_from_text(entity.value)
        results = [(ua, classify_user_agent(ua, matcher)) for ua in uas]
        counts: dict[str, int] = {}
        for _, info in results:
            counts[info["category"]] = counts.get(info["category"], 0) + 1
        res.attr("ua_category", max(counts, key=lambda k: counts[k]) if counts else "unknown")
        res.attr("ua_risk_ceiling", UA_RISK_CEILING)
        res.attr("ua_parsed", {"distinct_user_agents": len(uas), "by_category": counts,
                               "tools": sorted({i["tool"] for _, i in results if i.get("tool")}),
                               "bad_crawler_list_used": matcher is not None,
                               "bad_crawler_attribution": TELER_ATTRIBUTION if matcher is not None else None})
        for ua, info in results:
            if info["category"] in ("scanner", "benign_scanner"):
                self._finding(res, info, ua_text=truncate_ua(ua)[0][:200], key=info.get("tool") or "")
        return res

    # ------------------------------------------------------------------ helpers
    def _emit_one(self, res: ModuleResult, info: dict[str, Any], list_used: bool) -> None:
        res.attr("ua_category", info["category"])
        res.attr("ua_risk_ceiling", UA_RISK_CEILING)
        parsed = {k: info[k] for k in ("browser", "browser_version", "os", "os_version", "device", "tool",
                                       "bad_crawler_match", "exploit_probe", "truncated") if info.get(k) not in (None, "")}
        parsed["bad_crawler_list_used"] = list_used
        if list_used:
            parsed["bad_crawler_attribution"] = TELER_ATTRIBUTION
        res.attr("ua_parsed", parsed)
        res.raw = {"classification": info}
        if info["category"] in ("scanner", "benign_scanner"):
            self._finding(res, info)
        elif info["category"] in ("bot", "automation"):
            what = info.get("tool") or ("listed by the teler bad-crawlers list" if info.get("bad_crawler_match") else "non-human client")
            res.finding("Non-human user agent", "info", f"{what}: a crawler, link preview or HTTP library (not a verdict).",
                        confidence="possible", criterion="own UA table / Crawler-Detect pattern match (user agents are spoofable)",
                        tags=["info", "context_only", *info["tags"]])

    def _finding(self, res: ModuleResult, info: dict[str, Any], *, ua_text: str = "", key: str = "") -> None:
        tool = info.get("tool") or "scanner"
        if info["category"] == "benign_scanner":
            res.finding("Research scanner user agent", "info",
                        f"{tool}: an identified internet-measurement / attack-surface scanner (benign scanner, not an attack)."
                        + (f" UA: {ua_text}" if ua_text else ""),
                        confidence="probable", criterion="own UA table: identified research scanner (spoofable)",
                        tags=["info", "benign_scanner", "context_only"], key=key)
            return
        probe = " The UA carries a Log4Shell (CVE-2021-44228) JNDI lookup string: an exploitation probe, not proof of compromise." \
            if info.get("exploit_probe") else ""
        res.finding("Scanner or attack-tool user agent", "low",
                    f"{tool}: user agent of a scanning or attack tool (tagged scanner, never malicious: user agents are "
                    f"trivially spoofed, so a UA alone never raises an IP's risk above LOW).{probe}"
                    + (f" UA: {ua_text}" if ua_text else ""),
                    confidence="possible", criterion="own UA table: offensive / vulnerability scanning tool name in the UA (spoofable)",
                    tags=["scanner"], key=key)
