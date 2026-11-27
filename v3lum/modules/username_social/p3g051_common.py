"""Shared, network-free helpers of batch p3-G05-1 (keybase, mastodon, memory_lol, reddit_archive, hackernews,
youtube). No Module class lives here: only pure parsing helpers ported from the batch prep parsers (standard
library only) plus the per-source problem bookkeeping of the modules' secondary calls.

* Untrusted data: every helper accepts any type and never raises on bad input (None, wrong types, HTML where
  JSON or XML was expected, truncated bodies); callers turn a parse failure into ERROR 'could not verify'.
* ``json_body`` distinguishes the literal JSON ``null`` (Hacker News' documented absence, P109 cond 1) from an
  unreadable body.
* ``quote_if_mentioned`` cuts a <= 200-character window around the first organisation brand/domain mention
  (accent- and case-insensitive): P108 cond 3 and P109 cond 3 quote only items that mention the org profile.
* ``safe_xml_root`` refuses DTD/entity declarations and oversized documents before ElementTree parses
  anything (P110 cond 2; the core has no shared safe-XML helper yet: core request).
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import unicodedata
import xml.etree.ElementTree as ET  # noqa: S405 - DTD/ENTITY declarations are refused before parsing (safe_xml_root)
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

from v3lum.core.http import AuthRequired, Blocked, DeadlineExceeded, HttpError, NetworkError, OfflineError, QuotaExceeded, RateLimited
from v3lum.core.models import Status

JSON_CAP = 4 * 1024 * 1024
XML_CAP = 2 * 1024 * 1024
QUOTE_CAP = 200
_HTML_START_RE = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<title\b|<!--)", re.I)
_URL_RE = re.compile(r"https?://[^\s<>\"'\]\[)(]{1,2000}", re.I)
_EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24})\b")
_OBF_EMAIL_RE = re.compile(
    r"\b([A-Za-z0-9._%+-]{1,64})\s{0,3}[\[(]\s{0,3}at\s{0,3}[\])]\s{0,3}"
    r"([A-Za-z0-9-]{1,63}(?:\s{0,3}[\[(]\s{0,3}dot\s{0,3}[\])]\s{0,3}[A-Za-z0-9-]{1,63}){1,8})",
    re.I,
)
_HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")


# ---------------------------------------------------------------------------------------------- text / JSON
def to_text(raw: Any, cap: int | None = None) -> tuple[str, bool]:
    """``(text, truncated)`` for str/bytes input; any other type gives ``('', False)``."""
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        truncated = cap is not None and len(data) > cap
        return (data[:cap] if truncated else data).decode("utf-8", errors="replace"), truncated
    if isinstance(raw, str):
        if cap is not None and len(raw) > cap:
            return raw[:cap], True
        return raw, False
    return "", False


def looks_like_html(raw: Any) -> bool:
    """True when the body is an HTML document (an error, consent or challenge page instead of data)."""
    if raw is None or isinstance(raw, (dict, list)):
        return False
    head = to_text(raw, 4096)[0].lstrip("﻿")
    return bool(_HTML_START_RE.match(head)) and bool(re.search(r"<html\b|<!doctype\s+html|<title\b|<body\b|<h1\b", head, re.I))


def json_body(raw: Any, cap: int = JSON_CAP) -> tuple[Any, str | None]:
    """``(value, error)``: parsed JSON (``None`` for a literal ``null``) or a short error reason."""
    if isinstance(raw, (dict, list)):
        return raw, None
    if raw is None:
        return None, "no body"
    text, truncated = to_text(raw, cap)
    if truncated:
        return None, "answer larger than the parse cap"
    text = text.lstrip("﻿").strip()
    if not text:
        return None, "empty body"
    if looks_like_html(text):
        return None, "HTML page instead of JSON"
    try:
        return json.loads(text), None
    except (ValueError, RecursionError):
        return None, "malformed JSON"


def to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == value and abs(value) < 1e18:
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"\s*[+-]?\d{1,20}\s*", value):
        return int(value)
    return None


def to_str(value: Any, cap: int | None = None) -> str | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if cap:
        s = s[:cap]
    return s or None


def to_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


# ---------------------------------------------------------------------------------------------- dates
def parse_dt(value: Any) -> _dt.datetime | None:
    """Epoch seconds/milliseconds, ISO 8601 (Z, offsets, fractions) or YYYY-MM-DD -> aware UTC datetime."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
    if isinstance(value, (int, float)):
        v = float(value)
        if v != v:
            return None
        if v > 1e12:
            v /= 1000.0
        try:
            return _dt.datetime.fromtimestamp(v, _dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip() or len(value) > 64:
        return None
    s = value.strip()
    if re.fullmatch(r"\d{9,13}", s):
        return parse_dt(int(s))
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\.(\d+)(.*)", s)
    if m:  # Python 3.10 fromisoformat accepts 3 or 6 fraction digits only
        s = f"{m.group(1)}.{(m.group(2) + '000000')[:6]}{m.group(3)}"
    try:
        d = _dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.astimezone(_dt.timezone.utc)


def iso(value: Any) -> str | None:
    """Any accepted date -> 'YYYY-MM-DDTHH:MM:SSZ' or None."""
    d = parse_dt(value)
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def day(value: Any) -> str | None:
    d = parse_dt(value)
    return d.strftime("%Y-%m-%d") if d else None


def age_days(value: Any, now: Any) -> int | None:
    d = parse_dt(value)
    n = parse_dt(now)
    if d is None or n is None:
        return None
    return max(0, (n - d).days)


# ---------------------------------------------------------------------------------------------- HTML text
def collapse_ws(text: Any) -> str:
    return re.sub(r"\s+", " ", text if isinstance(text, str) else "").strip()


def excerpt(text: Any, cap: int) -> str | None:
    """Whitespace-collapsed text cut to ``cap`` characters (the ellipsis counts)."""
    t = collapse_ws(text)
    if not t:
        return None
    if len(t) <= cap:
        return t
    return t[: max(0, cap - 1)].rstrip() + "…"


class _TextLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in ("p", "br", "div", "li", "pre"):
            self.parts.append("\n")
        if tag == "a":
            for key, val in attrs:
                if key == "href" and val and len(self.links) < 200:
                    self.links.append(val.strip())

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_text_and_links(html: Any, cap: int = 200_000) -> tuple[str, list[str]]:
    """HTML fragment -> (plain text with entities unescaped, [href, ...]). Never raises."""
    if not isinstance(html, str) or not html:
        return "", []
    html = html[:cap]
    parser = _TextLinks()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed markup must never abort a module
        return collapse_ws(re.sub(r"<[^>]{0,2000}>", " ", html)), []
    text = "".join(parser.parts)
    text = "\n".join(collapse_ws(line) for line in text.split("\n"))
    return text.strip(), parser.links


# ---------------------------------------------------------------------------------------------- URLs, hosts, e-mails
def safe_url(value: Any, cap: int = 2000) -> str | None:
    """http(s) URL with a host, or None (AR13 safe-href rule)."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or len(v) > cap or any(c in v for c in "\r\n\t "):
        return None
    try:
        parts = urlsplit(v)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    return v


def host_of(url: Any) -> str | None:
    try:
        h = urlsplit(url).hostname if isinstance(url, str) else None
    except ValueError:
        return None
    return h.lower().rstrip(".") if h else None


def extract_urls(text: Any, limit: int = 50) -> list[str]:
    out: list[str] = []
    for m in _URL_RE.finditer(text if isinstance(text, str) else ""):
        u = safe_url(m.group(0).rstrip(".,;:!?'\""))
        if u and u not in out:
            out.append(u)
            if len(out) >= limit:
                break
    return out


def extract_emails(text: Any, limit: int = 20) -> list[str]:
    """Plain and bracket-obfuscated ('x [at] example [dot] com') e-mails, lower-cased, de-duplicated."""
    src = text if isinstance(text, str) else ""
    out: list[str] = []
    for m in _EMAIL_RE.finditer(src):
        e = m.group(1).lower().rstrip(".")
        if e not in out:
            out.append(e)
    for m in _OBF_EMAIL_RE.finditer(src):
        domain = re.sub(r"\s*[\[(]\s*dot\s*[\])]\s*", ".", m.group(2), flags=re.I)
        e = (m.group(1) + "@" + domain).lower()
        if e not in out:
            out.append(e)
    return out[:limit]


def normalise_host(value: Any) -> str | None:
    """Public DNS host name (lower-case, IDNA) or None: no IP literal, port, userinfo or single label."""
    if not isinstance(value, str):
        return None
    v = value.strip().rstrip(".").lower()
    if not v or len(v) > 253 or any(c in v for c in "/:@ \t[]\\?#"):
        return None
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if re.fullmatch(r"[0-9.]+", v):
        return None
    return v if _HOST_RE.match(v) else None


def registrable_like(host: str) -> str:
    """'www.example.com' -> 'example.com' (only the www. label is stripped: never a PSL guess)."""
    return host[4:] if host.startswith("www.") else host


# ---------------------------------------------------------------------------------------------- org mentions
def fold(text: Any) -> str:
    """Accent-folded, case-folded text (A11 brand matching)."""
    if not isinstance(text, str):
        return ""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c)).casefold()


def _folded_with_index(text: str) -> tuple[str, list[int]]:
    chars: list[str] = []
    index: list[int] = []
    for i, ch in enumerate(text):
        for f in fold(ch):
            chars.append(f)
            index.append(i)
    return "".join(chars), index


def quote_if_mentioned(text: Any, terms: Any, cap: int = QUOTE_CAP) -> str | None:
    """A <= ``cap``-character window around the first mention of an org brand/domain term, else None."""
    if not isinstance(text, str) or not text.strip():
        return None
    text = text[:20000]
    folded, index = _folded_with_index(text)
    best: tuple[int, int] | None = None
    for term in terms or ():
        t = fold(term).strip()
        if len(t) < 3:
            continue
        pos = folded.find(t)
        if pos >= 0 and (best is None or pos < best[0]):
            best = (pos, len(t))
    if best is None:
        return None
    start = index[best[0]]
    end = index[min(len(index) - 1, best[0] + best[1] - 1)] + 1
    width = max(10, cap - 2)  # room for the two ellipses
    if end - start >= width:
        lo, hi = start, start + width
    else:
        lo = max(0, start - (width - (end - start)) // 2)
        hi = min(len(text), lo + width)
        lo = max(0, hi - width)
    snippet = collapse_ws(text[lo:hi])
    if lo > 0:
        snippet = "…" + snippet
    if hi < len(text):
        snippet = snippet + "…"
    return snippet[:cap]


def org_terms(ctx: Any) -> list[str]:
    """Folded brand keywords, organisation domains and name of the org profile (empty without one). Never
    copied into results: only used to decide which items may be quoted."""
    org = getattr(ctx, "org", None)
    if org is None or getattr(org, "is_empty", True):
        return []
    terms: list[str] = []
    try:
        terms.extend(org.brand_terms())
    except Exception:  # noqa: BLE001 - a broken profile only means no quotes
        pass
    for entry in getattr(org, "domains", None) or ():
        name = getattr(entry, "name", "")
        if isinstance(name, str) and name:
            terms.append(fold(name))
    name = getattr(org, "name", "")
    if isinstance(name, str) and len(name.strip()) >= 3:
        terms.append(fold(name.strip()))
    out: list[str] = []
    for t in terms:
        if len(t) >= 3 and t not in out:
            out.append(t)
    return out


def org_domains(ctx: Any) -> list[str]:
    org = getattr(ctx, "org", None)
    if org is None or getattr(org, "is_empty", True):
        return []
    return [str(e.name).lower() for e in getattr(org, "domains", None) or () if isinstance(getattr(e, "name", None), str)]


# ---------------------------------------------------------------------------------------------- XML
def safe_xml_root(raw: Any, cap: int = XML_CAP) -> tuple[ET.Element | None, str | None]:
    """Parse a small XML document with DTD/entity declarations refused (no external or expanding entities)."""
    text, truncated = to_text(raw, cap)
    if truncated:
        return None, f"XML larger than {cap} bytes"
    head = text.lstrip("﻿").lstrip()
    if not head.startswith("<"):
        return None, "not XML"
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        return None, "DTD/entity declarations refused"
    try:
        return ET.fromstring(head.encode("utf-8")), None  # noqa: S314 - DTD/ENTITY refused above, size capped
    except (ET.ParseError, ValueError):
        return None, "malformed XML"


# ---------------------------------------------------------------------------------------------- per-source problems
Problems = dict[str, list[tuple[Status, str, str]]]


def attempt(problems: Problems, source: str, label: str, fn: Any) -> Any:
    """Run one secondary call: a refusal or failure is recorded per source and the run goes on. Rate limits,
    quotas, deadlines, cancellation and the request cap propagate (the engine keeps the data already built
    and marks the run partial)."""
    try:
        return fn()
    except (RateLimited, QuotaExceeded, DeadlineExceeded):
        raise
    except Blocked as exc:
        problems.setdefault(source, []).append((Status.BLOCKED, exc.reason_code or "challenge", f"{label}: {exc}"))
    except AuthRequired as exc:
        problems.setdefault(source, []).append((Status.BLOCKED, "challenge", f"{label}: {exc}"))
    except OfflineError as exc:
        problems.setdefault(source, []).append((Status.UNAVAILABLE, "offline", f"{label}: {exc}"))
    except (HttpError, NetworkError) as exc:
        code = "timeout" if getattr(exc, "reason_code", "") == "timeout" else "error"
        problems.setdefault(source, []).append((Status.ERROR, code, f"{label}: could not verify ({exc})"))
    except ValueError as exc:
        problems.setdefault(source, []).append((Status.ERROR, "error", f"{label}: unexpected answer ({exc})"))
    return None


def report_problems(res: Any, problems: Problems) -> None:
    """One per-source status line for the secondary calls that could not be verified."""
    for source, items in problems.items():
        status, code, _ = items[0]
        res.source_status(source, status, reason_code=code, reason="; ".join(text for _s, _c, text in items)[:500])
