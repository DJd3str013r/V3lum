"""P242 ``dou_search`` - Diario Oficial da Uniao (Imprensa Nacional) mentions, matched locally on the official
DOU open-data XML dumps.

Council P242 final conditions, as implemented here:

1. www.in.gov.br/robots.txt disallows all robots: the public search page is never fetched. Automation uses
   only the official DOU open-data XML dumps, installed into a local index outside any scan and matched
   locally (disclosure 'none'; this module has no network at all).
2. INLABS (daily XML behind a login) is not built (backlog). The manual pivot link is the public search URL
   (``dou_search_links:dou_search``, Module.manual_link) and every run lists it with ``res.link``.
3. Without the local index the module is UNAVAILABLE reason_code 'dataset' ('run v3lum data update dou'),
   with the manual link. Every answer says 'DOU dump as of <date>' (recent acts may be missing). The index
   keeps a configurable window (setting ``dou_search_window_months``, default 24) and prunes older months.
4. The official dump URL could not be recorded from the build egress (www.in.gov.br drops the connection;
   provider ``imprensa_nacional`` notes). Until the team network records it, official dump ZIPs downloaded
   by hand from the official open-data page are installed with :func:`install_dumps` (no network):
   ``python -m v3lum.modules.brazil_public_data.dou_search install <S01112026.zip> ...``. The
   ``v3lum data update dou`` wiring is a core request (backlog).
5. XML through a hardened expat parser (DTD/entity declarations refused by the parser handlers, size,
   depth and element caps); zip members are name/size/ratio checked before decompression. A dump that does
   not match the expected article schema is ERROR 'format changed', never 'no mentions'.
6. Matching: the formatted CNPJ and its digits, plus the exact razao social of a CNPJ seed when the local RFB
   index (rfb_cnpj_bulk) is installed (never an MEI/EI name, which is a person's name), and analyst-typed
   company names. Person names only for a typed person seed with a recorded purpose; never QSA names.
   Keywords only on explicit request (an analyst-typed keyword with ``-M dou_search``).
7. Output: hit count plus the 5 most relevant excerpts (date, section, organ/act type, link), penalty-term
   excerpts (penalidade, inidoneidade, rescisao, multa, sancao, suspensao) ranked first. Routine mentions are
   INFO and context only (never scored); a penalty term next to the exact CNPJ is LOW 'review the act'.
8. Case data per hit: title, date, section, organ, URL and an excerpt of at most 300 characters; no full act
   text. Person names in excerpts are never pivoted; CNJ process numbers in excerpts become KEYWORD pivots
   with expand=False (P241; until the core cnj_process type exists).
9. Tests: tests/modules/test_dou_search.py (derived excerpt dump, no-match dump, broken dump, DTD dump,
   traversal dump).
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sqlite3
import sys
import unicodedata
import xml.parsers.expat
import zipfile
import zlib
from collections.abc import Iterable, Iterator
from datetime import date, datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
from xml.etree import ElementTree as ET

from v3lum import paths
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.brazil_public_data.cnj_process import cnj_pivot_args, extract_cnj_numbers

SOURCE = "imprensa_nacional.dou_open_data"
MANUAL_SEARCH = "https://www.in.gov.br/consulta/-/buscar/dou"
OPEN_DATA_PAGE = "https://www.in.gov.br/acesso-a-informacao/dados-abertos/base-de-dados"
INDEX_SCHEMA = "v3lum.dou_index/1"
INDEX_DIR = "dou_search"
INDEX_FILE = "dou_index.sqlite"
STATE_FILE = "install_state.json"
UNAVAILABLE_TEXT = "DOU index not installed: run v3lum data update dou (official DOU XML dumps, matched locally)"
EXCERPT_MAX = 300
TOP = 5
WINDOW_MONTHS = 24
#: candidate acts verified per seed pattern (newest first); the count says '>= N' beyond it
MAX_CANDIDATES = 2000
XML_MAX_BYTES = 8 * 1024 * 1024
XML_MAX_DEPTH = 64
XML_MAX_ELEMENTS = 200_000
MAX_MEMBERS = 200_000
MAX_TOTAL_BYTES = 6 * 1024**3
MAX_RATIO = 100
REQUIRED_ATTRS = ("pubName", "pubDate", "artType")
PENALTY_RE = re.compile(r"\b(PENALIDADES?|INIDONE\w*|RESCIS\w*|MULTAS?|SANC(?:AO|OES)|SUSPENS(?:AO|OES))\b")
_PENALTY_CANON = (("PENALIDADE", "penalidade"), ("INIDONE", "inidoneidade"), ("RESCIS", "rescisao"), ("MULTA", "multa"),
                  ("SANC", "sancao"), ("SUSPENS", "suspensao"))
DUMP_NAME_RE = re.compile(r"^S(0[1-3])(0[1-9]|1[0-2])(\d{4})([A-Za-z0-9_-]*)\.zip$", re.IGNORECASE)
MONTH_RE = re.compile(r"^(\d{4})-(0[1-9]|1[0-2])$")
EI_NATUREZAS = frozenset({"2135"})  # Empresario (Individual), MEI included: the name is a person's name
_UNSAFE_MEMBER = re.compile(r"(^[/\\])|(^|[/\\])\.\.([/\\]|$)|^[A-Za-z]:|\x00")
_DROP_CHARS = frozenset(".'´`’")
LICENCE = "Diario Oficial da Uniao open data (Imprensa Nacional) - official public gazette"


class FormatChanged(ValueError):
    """The dump no longer matches the expected schema: ERROR 'format changed', never 'no mentions'."""


class XmlRefused(ValueError):
    """The hardened XML parser refused the document (DTD/entity, caps, not well-formed)."""


# --------------------------------------------------------------------------------------
# safe XML (P242 cond 5; a core safe-XML helper is a core request)
# --------------------------------------------------------------------------------------


def safe_xml_root(data: Any, *, max_bytes: int = XML_MAX_BYTES, max_depth: int = XML_MAX_DEPTH,
                  max_elements: int = XML_MAX_ELEMENTS) -> ET.Element:
    """Parse untrusted XML with expat: any DOCTYPE/ENTITY/NOTATION declaration is refused by the parser
    handlers (CDATA text that merely contains '<!DOCTYPE' is data, not markup), external entities are never
    resolved, and size, depth and element counts are capped. Raises XmlRefused."""
    if isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
    else:
        raise XmlRefused("XML payload is not bytes")
    if len(raw) > max_bytes:
        raise XmlRefused(f"XML larger than {max_bytes} bytes")
    parser = xml.parsers.expat.ParserCreate()
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
    builder = ET.TreeBuilder()
    state = {"depth": 0, "count": 0}

    def _start(tag: str, attrs: dict[str, str]) -> None:
        state["depth"] += 1
        state["count"] += 1
        if state["depth"] > max_depth or state["count"] > max_elements:
            raise XmlRefused("XML nesting or element count above the cap")
        builder.start(tag, attrs)

    def _end(tag: str) -> None:
        state["depth"] -= 1
        builder.end(tag)

    def _refuse(*_args: Any) -> None:
        raise XmlRefused("DTD/entity declarations are refused")

    parser.StartElementHandler = _start
    parser.EndElementHandler = _end
    parser.CharacterDataHandler = builder.data
    parser.StartDoctypeDeclHandler = _refuse
    parser.EntityDeclHandler = _refuse
    parser.UnparsedEntityDeclHandler = _refuse
    parser.NotationDeclHandler = _refuse
    parser.ExternalEntityRefHandler = _refuse
    parser.buffer_text = True
    try:
        parser.Parse(raw, True)
    except xml.parsers.expat.ExpatError as exc:
        raise XmlRefused(f"not well-formed XML: {exc}") from None
    return builder.close()


# --------------------------------------------------------------------------------------
# text helpers
# --------------------------------------------------------------------------------------


def fold(text: Any) -> str:
    """Accent-fold, uppercase and collapse whitespace."""
    if not isinstance(text, str):
        return ""
    t = unicodedata.normalize("NFKD", text)
    t = "".join(c for c in t if not unicodedata.combining(c))
    return " ".join(t.upper().split())


def norm_with_map(text: Any) -> tuple[str, list[int]]:
    """Matching form plus index map: accents folded, uppercase, '.' and apostrophes dropped, any other
    non-alphanumeric run -> one space. ``index_map[i]`` is the position in ``text`` of normalised char i."""
    out: list[str] = []
    idx: list[int] = []
    space = True
    for i, ch in enumerate(text if isinstance(text, str) else ""):
        base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c)).upper()
        for c in base:
            if c in _DROP_CHARS:
                continue
            if c.isalnum():
                out.append(c)
                idx.append(i)
                space = False
            elif not space:
                out.append(" ")
                idx.append(i)
                space = True
    if out and out[-1] == " ":
        out.pop()
        idx.pop()
    return "".join(out), idx


def match_key(text: Any) -> str:
    """Normalised key for exact name matching: 'Banco do Brasil S.A.' == 'BANCO DO BRASIL SA'."""
    return norm_with_map(text)[0]


def cnpj_clean(value: Any) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", value if isinstance(value, str) else "").upper()


def cnpj_format(value: Any) -> str | None:
    c = cnpj_clean(value)
    return f"{c[:2]}.{c[2:5]}.{c[5:8]}/{c[8:12]}-{c[12:]}" if len(c) == 14 else None


class _Text(HTMLParser):
    BLOCK = frozenset({"p", "br", "div", "tr", "td", "li", "h1", "h2", "h3", "h4", "h5", "table", "ul", "ol"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(fragment: Any) -> str:
    """HTML fragment (the act text, CDATA) -> plain text; nothing is ever evaluated."""
    p = _Text()
    p.feed(fragment if isinstance(fragment, str) else "")
    p.close()
    lines = (" ".join(line.split()) for line in "".join(p.parts).split("\n"))
    return "\n".join(line for line in lines if line)


# --------------------------------------------------------------------------------------
# dump parsing (P242 cond 5)
# --------------------------------------------------------------------------------------


def _dmy_to_iso(value: Any) -> str | None:
    m = re.fullmatch(r"\s*(\d{2})/(\d{2})/(\d{4})\s*", value or "")
    if not m:
        return None
    try:
        return date(int(m.group(3)), int(m.group(2)), int(m.group(1))).isoformat()
    except ValueError:
        return None


def _dou_url(value: Any) -> str | None:
    v = (value or "").strip()
    try:
        parts = urlsplit(v)
    except ValueError:
        return None
    if parts.scheme in ("http", "https") and parts.hostname in ("pesquisa.in.gov.br", "www.in.gov.br", "in.gov.br"):
        return v
    return None


def parse_dou_xml(data: Any) -> list[dict[str, Any]]:
    """One article file of the official DOU XML dump -> article dicts.

    Expected: <xml><article pubName pubDate artType artCategory numberPage editionNumber pdfPage idMateria ...>
    <body><Identifica/><Ementa/><Texto>(HTML in CDATA)</Texto></body></article></xml>. Any other shape raises
    FormatChanged; the XML guard raises XmlRefused.
    """
    root = safe_xml_root(data)
    arts = [root] if root.tag == "article" else root.findall("article")
    if root.tag not in ("xml", "article") or not arts:
        raise FormatChanged(f"unexpected DOU XML root {root.tag!r}")
    out = []
    for a in arts:
        missing = [k for k in REQUIRED_ATTRS if not (a.get(k) or "").strip()]
        body = a.find("body")
        if missing or body is None:
            raise FormatChanged("DOU article without " + ", ".join(missing or ["body"]))
        pub = (a.get("pubName") or "").strip().upper()
        sec = re.match(r"^DO([123])", pub)
        date_iso = _dmy_to_iso(a.get("pubDate"))
        if not sec or not date_iso:
            raise FormatChanged(f"unexpected pubName/pubDate {pub!r}/{a.get('pubDate')!r}")
        organ = " ".join((a.get("artCategory") or "").split()) or None
        title = " ".join((body.findtext("Identifica") or "").split()) or (a.get("name") or "").strip() or a.get("artType")
        out.append({
            "id": (a.get("idMateria") or a.get("id") or "").strip() or None, "pub_name": pub, "section": int(sec.group(1)),
            "art_type": " ".join((a.get("artType") or "").split()), "date": date_iso,
            "edition": (a.get("editionNumber") or "").strip() or None, "page": (a.get("numberPage") or "").strip() or None,
            "organ": organ, "title": title, "ementa": " ".join((body.findtext("Ementa") or "").split()) or None,
            "text": html_to_text(body.findtext("Texto") or ""), "url": _dou_url(a.get("pdfPage")),
        })
    return out


def iter_dou_zip(source: Any, stats: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
    """The articles of one dump zip (a local file; never fetched during a scan).

    Members are name/size/ratio checked first; non-XML members (images) are skipped. FormatChanged when the
    zip is not a zip, has no XML, has an unsafe member, breaks a cap, or its first XML members all fail the
    article schema (a broken dump is ERROR 'format changed', never 'no mentions').
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(source) if isinstance(source, (bytes, bytearray)) else source)
    except (zipfile.BadZipFile, OSError):
        raise FormatChanged("DOU dump is not a zip file") from None
    st = stats if stats is not None else {}
    st.update({"xml_members": 0, "other_members": 0, "articles": 0, "bad_members": 0})
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_MEMBERS:
            raise FormatChanged("too many members in the DOU dump")
        total = 0
        xml_infos = []
        for info in infos:
            if _UNSAFE_MEMBER.search(info.filename):
                raise FormatChanged(f"unsafe member name {info.filename[:80]!r}")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise FormatChanged("DOU dump larger than the cap")
            if not info.filename.lower().endswith(".xml"):
                st["other_members"] += 1
                continue
            if info.file_size > XML_MAX_BYTES or (info.compress_size and info.file_size / info.compress_size > MAX_RATIO):
                raise FormatChanged(f"member {info.filename[:80]!r} above the size/ratio cap")
            xml_infos.append(info)
        if not xml_infos:
            raise FormatChanged("no XML article in the DOU dump")
        st["xml_members"] = len(xml_infos)
        good = 0
        for info in xml_infos:
            try:
                articles = parse_dou_xml(zf.read(info))
            except (FormatChanged, XmlRefused):
                st["bad_members"] += 1
                if good == 0 and st["bad_members"] >= min(3, len(xml_infos)):
                    raise FormatChanged("DOU dump does not match the expected article schema") from None
                continue
            good += 1
            for art in articles:
                st["articles"] += 1
                yield art


def parse_dump_name(name: Any) -> dict[str, Any] | None:
    """'S01112026.zip' -> {'section': 1, 'month': '2026-11', 'variant': None} (official naming: section, month)."""
    m = DUMP_NAME_RE.match(name or "")
    if not m:
        return None
    return {"section": int(m.group(1)), "month": f"{m.group(3)}-{m.group(2)}", "variant": m.group(4) or None}


# --------------------------------------------------------------------------------------
# matching (P242 cond 6-8)
# --------------------------------------------------------------------------------------


def build_seeds(etype: Any, value: Any, *, razao_social: str | None = None, natureza: str | None = None,
                allow_person: bool = False, explicit_keyword: bool = False) -> list[dict[str, str]]:
    """What may be matched for one entity (cond 6). MEI/EI names are persons' names: only with allow_person."""
    kind = getattr(etype, "value", etype)
    seeds: list[dict[str, str]] = []
    if kind == "cnpj":
        c = cnpj_clean(value)
        if len(c) != 14:
            return []
        seeds.append({"kind": "cnpj", "value": c})
        person_like = (natureza or "").strip() in EI_NATUREZAS
        if razao_social and match_key(razao_social) and (not person_like or allow_person):
            seeds.append({"kind": "company_name", "value": razao_social})
    elif kind == "company_name":
        if match_key(value):
            seeds.append({"kind": "company_name", "value": str(value)})
    elif kind == "person_name" and allow_person and match_key(value):
        seeds.append({"kind": "person_name", "value": str(value)})
    elif kind == "keyword" and explicit_keyword and match_key(value):
        seeds.append({"kind": "keyword", "value": str(value)})
    return seeds


def seed_patterns(seed: dict[str, str]) -> list[str]:
    """Normalised phrases of a seed: the formatted CNPJ (dots dropped, '/' and '-' as spaces) and its digits."""
    if seed["kind"] == "cnpj":
        c = cnpj_clean(seed["value"])
        return [p for p in (match_key(cnpj_format(c)), c) if p]
    key = match_key(seed["value"])
    return [key] if key else []


def find_matches(article: dict[str, Any], seeds: list[dict[str, str]]) -> tuple[list[dict[str, Any]], str]:
    """First whole-word occurrence of each seed in title + ementa + text -> (matches, full text)."""
    full = "\n".join(x for x in (article.get("title"), article.get("ementa"), article.get("text")) if x)
    norm, idx = norm_with_map(full)
    padded = f" {norm} "
    out = []
    for seed in seeds:
        for pat in seed_patterns(seed):
            pos = padded.find(f" {pat} ")
            if pos >= 0:
                out.append({"kind": seed["kind"], "start": idx[pos], "end": idx[pos + len(pat) - 1] + 1})
                break
    return out, full


def excerpt(text: str, start: int, end: int, max_chars: int = EXCERPT_MAX) -> str:
    """Excerpt around [start, end): whitespace collapsed, '…' at cuts, at most ``max_chars`` characters."""
    text = text or ""
    budget = max_chars - 2
    if end - start >= budget:
        return " ".join(text[start : start + budget].split())[:max_chars]
    room = budget - (end - start)
    a = max(0, start - room // 2)
    b = min(len(text), end + (room - (start - a)))
    a = max(0, min(a, start - (room - (b - end))))
    snippet = " ".join(text[a:b].split())
    return (("…" if a > 0 else "") + snippet + ("…" if b < len(text) else ""))[:max_chars]


def penalty_terms(text: Any) -> list[str]:
    """Penalty terms of cond 7 in a text (penalidade, inidoneidade, rescisao, multa, sancao, suspensao)."""
    found = set()
    for m in PENALTY_RE.finditer(fold(text)):
        word = m.group(1)
        for prefix, canon in _PENALTY_CANON:
            if word.startswith(prefix):
                found.add(canon)
                break
    return sorted(found)


def make_hit(article: dict[str, Any], seeds: list[dict[str, str]]) -> dict[str, Any] | None:
    """Article + seeds -> hit or None. ``record`` is all the case keeps (cond 8)."""
    matches, full = find_matches(article, seeds)
    if not matches:
        return None
    first = min(matches, key=lambda m: m["start"])
    exc = excerpt(full, first["start"], first["end"])
    terms = penalty_terms(exc)
    return {
        "record": {"title": article.get("title"), "date": article.get("date"), "section": article.get("section"),
                   "organ": article.get("organ"), "url": article.get("url"), "excerpt": exc},
        "art_type": article.get("art_type"), "match_kinds": sorted({m["kind"] for m in matches}),
        "penalty_terms": terms, "kind": "penalty" if terms else "routine",
        "cnj_numbers": [n["formatted"] for n in extract_cnj_numbers(exc)["numbers"]],
        "id": article.get("id"),
    }


def rank(hits: list[dict[str, Any]], limit: int = TOP) -> dict[str, Any]:
    """Hit count plus the ``limit`` most relevant: penalty excerpts first, then the most recent."""
    ordered = sorted(hits, key=lambda h: (h["record"]["date"] or "", h["record"]["title"] or ""), reverse=True)
    ordered = sorted(ordered, key=lambda h: not h["penalty_terms"])
    return {"count": len(hits), "top": ordered[:limit]}


def as_of_banner(as_of: Any) -> str:
    return f"DOU dump as of {as_of}"


def window(months: Iterable[str], newest: str, size: int = WINDOW_MONTHS) -> dict[str, list[str]]:
    """Months to keep (``newest`` and the ``size``-1 before it) and months to prune (cond 3)."""

    def ordinal(m: str) -> int:
        y, mm = m.split("-")
        return int(y) * 12 + int(mm) - 1

    top = ordinal(newest)
    keep: list[str] = []
    prune: list[str] = []
    for m in sorted({m for m in months if MONTH_RE.match(m)}):
        (keep if top - size < ordinal(m) <= top else prune).append(m)
    return {"keep": keep, "prune": prune}


def manual_link(term: Any) -> str | None:
    """The public search page (never fetched by V3LUM: robots.txt Disallow: /), quoted exact-phrase search."""
    t = " ".join(str(term or "").replace('"', " ").split())
    if not t:
        return None
    return f"{MANUAL_SEARCH}?q={quote(chr(34) + t + chr(34), safe='')}&s=todos&exactDate=all"


# --------------------------------------------------------------------------------------
# the local index (installed outside any scan)
# --------------------------------------------------------------------------------------

_SCHEMA_SQL = (
    "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)",
    "CREATE TABLE IF NOT EXISTS months (month TEXT, section INTEGER, file TEXT, sha256 TEXT, articles INTEGER, installed_at TEXT, "
    "PRIMARY KEY (month, section))",
    "CREATE TABLE IF NOT EXISTS acts (id INTEGER PRIMARY KEY, month TEXT, section INTEGER, date TEXT, materia TEXT, title TEXT, "
    "organ TEXT, art_type TEXT, url TEXT, body BLOB)",
    "CREATE INDEX IF NOT EXISTS acts_month ON acts (month, section)",
    "CREATE INDEX IF NOT EXISTS acts_date ON acts (date)",
)


def index_dir(home: Path | None = None) -> Path:
    base = Path(home) if home is not None else paths.datasets_dir()
    return paths.private_dir(base / INDEX_DIR)


def _fts_available(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS temp._fts_probe USING fts5(x)")
        conn.execute("DROP TABLE IF EXISTS temp._fts_probe")
        return True
    except sqlite3.Error:
        return False


def _open_rw(path: Path) -> sqlite3.Connection:
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    conn = sqlite3.connect(str(path), isolation_level=None)  # explicit BEGIN/COMMIT per dump
    for sql in _SCHEMA_SQL:
        conn.execute(sql)
    fts = _fts_available(conn)
    if fts:
        conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS acts_fts USING fts5(norm, content='', tokenize='unicode61')")
    else:  # pragma: no cover - sqlite builds without FTS5: a plain normalised column (LIKE scan)
        conn.execute("CREATE TABLE IF NOT EXISTS acts_norm (id INTEGER PRIMARY KEY, norm TEXT)")
    conn.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('schema', ?)", (INDEX_SCHEMA,))
    conn.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('fts', ?)", ("1" if fts else "0",))
    return conn


def _sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_state(directory: Path, state: dict[str, Any]) -> None:
    paths.secure_write_text(directory / STATE_FILE, json.dumps(state, ensure_ascii=False, indent=1))


def read_state(directory: Path | None = None) -> dict[str, Any]:
    target = (directory or (paths.datasets_dir() / INDEX_DIR)) / STATE_FILE
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def install_dumps(files: Iterable[str | os.PathLike[str]], *, home: Path | None = None, window_months: int = WINDOW_MONTHS,
                  now: datetime | None = None) -> list[dict[str, Any]]:
    """Install official DOU dump ZIPs (downloaded from the official open-data page) into the local index.

    Each zip is parsed and indexed in its own transaction: a zip that fails the schema (FormatChanged,
    XmlRefused) is rolled back and reported 'format_changed', and the months already installed stay. Months
    outside the window (counted from the newest installed month) are pruned. No network is used. Returns one
    ``{file, status: installed | format_changed | error, month, section, articles, reason}`` per input.
    """
    directory = index_dir(home)
    db = directory / INDEX_FILE
    when = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    results: list[dict[str, Any]] = []
    conn = _open_rw(db)
    fts = conn.execute("SELECT v FROM meta WHERE k = 'fts'").fetchone()[0] == "1"
    try:
        for f in files:
            path = Path(f)
            item: dict[str, Any] = {"file": path.name, "status": "error", "month": None, "section": None, "articles": 0, "reason": ""}
            results.append(item)
            try:
                stats: dict[str, Any] = {}
                named = parse_dump_name(path.name)
                rows = []
                months_seen: set[tuple[str, int]] = set()
                with open(path, "rb") as fh:
                    for art in iter_dou_zip(fh, stats):
                        month = art["date"][:7]
                        months_seen.add((month, art["section"]))
                        rows.append(art)
                if named:
                    item.update(month=named["month"], section=named["section"])
                conn.execute("BEGIN")
                for month, section in months_seen:  # a re-installed month replaces its previous copy
                    _delete_acts(conn, [r[0] for r in conn.execute("SELECT id FROM acts WHERE month = ? AND section = ?", (month, section))], fts)
                count = 0
                for art in rows:
                    materia = art.get("id") or ""
                    full = "\n".join(x for x in (art.get("title"), art.get("ementa"), art.get("text")) if x)
                    cur = conn.execute(
                        "INSERT INTO acts (month, section, date, materia, title, organ, art_type, url, body) VALUES (?,?,?,?,?,?,?,?,?)",
                        (art["date"][:7], art["section"], art["date"], materia, art.get("title"), art.get("organ"), art.get("art_type"),
                         art.get("url"), zlib.compress(json.dumps({"title": art.get("title"), "ementa": art.get("ementa"),
                                                                   "text": art.get("text")}, ensure_ascii=False).encode("utf-8"))),
                    )
                    norm = match_key(full)
                    if fts:
                        conn.execute("INSERT INTO acts_fts (rowid, norm) VALUES (?, ?)", (cur.lastrowid, norm))
                    else:  # pragma: no cover
                        conn.execute("INSERT INTO acts_norm (id, norm) VALUES (?, ?)", (cur.lastrowid, f" {norm} "))
                    count += 1
                digest = _sha256(path)
                for month, section in months_seen:
                    conn.execute("INSERT OR REPLACE INTO months (month, section, file, sha256, articles, installed_at) VALUES (?,?,?,?,?,?)",
                                 (month, section, path.name, digest, count, when))
                conn.execute("COMMIT")
                item.update(status="installed", articles=count, reason=f"{stats.get('xml_members', 0)} XML members, "
                            f"{stats.get('bad_members', 0)} skipped")
            except (FormatChanged, XmlRefused) as exc:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                item.update(status="format_changed", reason=f"format changed: {exc}"[:300])
            except (OSError, sqlite3.Error, zipfile.BadZipFile, EOFError) as exc:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                item.update(status="error", reason=f"{type(exc).__name__}: {str(exc)[:200]}")
        conn.execute("BEGIN")
        _prune(conn, window_months, fts)
        newest = conn.execute("SELECT MAX(date) FROM acts").fetchone()[0]
        conn.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('as_of', ?)", (newest or "",))
        conn.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('updated_at', ?)", (when,))
        conn.execute("COMMIT")
    finally:
        conn.close()
    paths.restrict_file(db)
    state = read_state(directory)
    state["last_install"] = {"at": when, "files": results}
    _write_state(directory, state)
    return results


def _delete_acts(conn: sqlite3.Connection, ids: list[int], fts: bool) -> None:
    """Delete acts and their full-text rows (contentless FTS5 needs the indexed text to delete a row)."""
    for act_id in ids:
        if fts:
            row = conn.execute("SELECT title, body FROM acts WHERE id = ?", (act_id,)).fetchone()
            if row is not None:
                try:
                    body = json.loads(zlib.decompress(row[1]).decode("utf-8"))
                except (zlib.error, ValueError, UnicodeDecodeError, TypeError):
                    body = {}
                full = "\n".join(x for x in (body.get("title") or row[0], body.get("ementa"), body.get("text")) if x)
                conn.execute("INSERT INTO acts_fts (acts_fts, rowid, norm) VALUES ('delete', ?, ?)", (act_id, match_key(full)))
        else:  # pragma: no cover
            conn.execute("DELETE FROM acts_norm WHERE id = ?", (act_id,))
        conn.execute("DELETE FROM acts WHERE id = ?", (act_id,))


def _prune(conn: sqlite3.Connection, window_months: int, fts: bool) -> None:
    months = [r[0] for r in conn.execute("SELECT DISTINCT month FROM acts")]
    if not months:
        return
    newest = max(months)
    for month in window(months, newest, max(1, int(window_months or WINDOW_MONTHS)))["prune"]:
        _delete_acts(conn, [r[0] for r in conn.execute("SELECT id FROM acts WHERE month = ?", (month,))], fts)
        conn.execute("DELETE FROM months WHERE month = ?", (month,))


class DouIndex:
    """Read-only view of the installed local DOU index."""

    def __init__(self, path: Path) -> None:
        self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
        self.meta = dict(self.conn.execute("SELECT k, v FROM meta").fetchall())
        self.fts = self.meta.get("fts") == "1"

    def close(self) -> None:
        self.conn.close()

    def candidates(self, pattern: str, limit: int = MAX_CANDIDATES) -> tuple[list[int], bool]:
        """Act ids whose normalised text contains ``pattern`` as a phrase, newest first; (ids, capped)."""
        if not pattern:
            return [], False
        if self.fts:
            phrase = '"' + pattern.replace('"', " ") + '"'
            rows = self.conn.execute(
                "SELECT a.id FROM acts_fts f JOIN acts a ON a.id = f.rowid WHERE acts_fts MATCH ? ORDER BY a.date DESC LIMIT ?",
                (phrase, limit + 1),
            ).fetchall()
        else:  # pragma: no cover
            rows = self.conn.execute(
                "SELECT a.id FROM acts_norm n JOIN acts a ON a.id = n.id WHERE n.norm LIKE ? ORDER BY a.date DESC LIMIT ?",
                (f"% {pattern} %", limit + 1),
            ).fetchall()
        ids = [r[0] for r in rows]
        return ids[:limit], len(ids) > limit

    def article(self, act_id: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT id, section, date, materia, title, organ, art_type, url, body FROM acts WHERE id = ?", (act_id,)
        ).fetchone()
        if row is None:
            return None
        try:
            body = json.loads(zlib.decompress(row[8]).decode("utf-8"))
        except (zlib.error, ValueError, UnicodeDecodeError):
            body = {}
        return {"id": row[3] or str(row[0]), "section": row[1], "date": row[2], "title": body.get("title") or row[4],
                "organ": row[5], "art_type": row[6], "url": row[7], "ementa": body.get("ementa"), "text": body.get("text") or ""}

    def months(self) -> list[str]:
        return sorted({r[0] for r in self.conn.execute("SELECT month FROM months")})


def open_index(home: Path | None = None) -> tuple[DouIndex | None, str]:
    """The installed index (never downloads) or (None, why it is unusable)."""
    base = Path(home) if home is not None else paths.datasets_dir()
    path = base / INDEX_DIR / INDEX_FILE
    if not path.is_file():
        return None, "missing"
    try:
        idx = DouIndex(path)
    except sqlite3.Error:
        return None, "unreadable"
    if idx.meta.get("schema") != INDEX_SCHEMA:
        idx.close()
        return None, "format"
    return idx, ""


def search(idx: DouIndex, seeds: list[dict[str, str]]) -> tuple[list[dict[str, Any]], bool]:
    """Every act matching a seed (verified as whole words), newest first; (hits, capped)."""
    seen: set[int] = set()
    hits: list[dict[str, Any]] = []
    capped = False
    for seed in seeds:
        for pat in seed_patterns(seed):
            ids, cut = idx.candidates(pat)
            capped = capped or cut
            for act_id in ids:
                if act_id in seen:
                    continue
                art = idx.article(act_id)
                if art is None:
                    continue
                hit = make_hit(art, seeds)
                if hit is not None:
                    seen.add(act_id)
                    hits.append(hit)
    return hits, capped


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


def _rfb_company(cnpj: str) -> tuple[str | None, str | None]:
    """Razao social and natureza of a CNPJ from the local RFB index (rfb_cnpj_bulk), when installed."""
    try:
        from v3lum.modules.brazil_public_data.rfb_cnpj_bulk import company_name_for
    except ImportError:  # pragma: no cover - sibling module missing
        return None, None
    try:
        return company_name_for(cnpj)
    except Exception:  # noqa: BLE001 - the RFB index is optional here: CNPJ-only matching then
        return None, None


@register
class DouSearch(Module):
    name = "dou_search"
    title = "Diario Oficial da Uniao mentions (local DOU dump)"
    description = (
        "Mentions of a CNPJ (formatted and digits), its razao social or an analyst-typed company name in the official "
        "Diario Oficial da Uniao XML open-data dumps, matched locally: hit count plus the 5 most relevant excerpts "
        "(penalty terms first)."
    )
    category = "brazil_public_data"
    accepts = {T.CNPJ, T.ORG, T.PERSON, T.KEYWORD}
    produces = {T.KEYWORD}
    tags = {"brazil", "offline"}
    reference = OPEN_DATA_PAGE
    notice = (
        "Local matching on the official DOU open-data dumps (nothing is sent; the robots.txt of www.in.gov.br forbids "
        "automated access to the search page, which is only a manual link). Results say 'DOU dump as of <date>': recent "
        "acts may be missing. Person names only for a typed person seed with a recorded purpose; keywords only with -M "
        "dou_search; excerpts of at most 300 characters, never the full act."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SOURCE,)
    access_model = "offline"
    expected_latency = 0.5
    timeout = 30.0
    max_pivots = 25
    manual_link = "dou_search_links:dou_search"
    default_enabled = True  # A3: official Brazilian open data matched offline (P242)
    settings = {"dou_search_window_months": WINDOW_MONTHS}

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        etype = entity.type
        value = str(entity.value)
        # ---- who may be matched (cond 6) -------------------------------------------------
        razao: str | None = None
        natureza: str | None = None
        allow_person = False
        if etype is T.PERSON:
            refusal = self._person_refusal(ctx)
            if refusal:
                return res.mark(Status.SKIPPED, refusal, reason_code="privacy")
            allow_person = True
        elif etype is T.KEYWORD:
            if not (getattr(ctx, "is_seed", False) and self.name in set(getattr(ctx.options, "include", ()) or ())):
                return res.mark(Status.SKIPPED, "keywords are matched only on explicit request (-M dou_search on a typed keyword)",
                                reason_code="not_applicable")
        elif etype is T.ORG and not getattr(ctx, "is_seed", False):
            return res.mark(Status.SKIPPED, "company names are matched only when analyst-typed (CNPJ seeds bring their razao social)",
                            reason_code="not_applicable")
        term = cnpj_format(value) if etype is T.CNPJ else value
        link = manual_link(term)
        if link:
            res.link("DOU search page (manual, exact phrase)", link)
        idx, problem = open_index()
        if idx is not None and not idx.months():  # created by an install whose every dump failed
            idx.close()
            idx, problem = None, "missing"
        if idx is None:
            state = read_state()
            broken = [f for f in (state.get("last_install") or {}).get("files", []) if f.get("status") == "format_changed"]
            if problem == "format" or (problem == "missing" and broken):
                why = broken[-1]["reason"] if broken else "local DOU index has an unknown schema"
                return res.mark(Status.ERROR, f"DOU dump format changed ({why[:200]}): could not verify, never 'no mentions'", reason_code="error")
            return res.mark(Status.UNAVAILABLE, UNAVAILABLE_TEXT, reason_code="dataset")
        try:
            as_of = idx.meta.get("as_of") or "unknown date"
            if etype is T.CNPJ:
                razao, natureza = _rfb_company(value)
            seeds = build_seeds(etype, value, razao_social=razao, natureza=natureza, allow_person=allow_person,
                                explicit_keyword=etype is T.KEYWORD)
            if not seeds:
                return res.mark(Status.SKIPPED, "nothing matchable in this input", reason_code="not_applicable")
            hits, capped = search(idx, seeds)
            months = idx.months()
        except sqlite3.Error as exc:
            return res.mark(Status.ERROR, f"local DOU index unreadable ({type(exc).__name__}): could not verify", reason_code="error")
        finally:
            idx.close()
        self._cite(ctx, as_of, months)
        banner = as_of_banner(as_of)
        broken = [f for f in (read_state().get("last_install") or {}).get("files", []) if f.get("status") == "format_changed"]
        note = f" (newer dump rejected: {broken[-1]['reason'][:120]})" if broken else ""
        win = {"from": months[0] if months else None, "to": months[-1] if months else None, "months": len(months)}
        if etype is T.CNPJ and not razao:
            note += " (razao social not matched: local RFB index not installed or CNPJ absent)"
        if not hits:
            res.attr("dou_status", f"not found in the local DOU dump as of {as_of}{note}")
            res.attr("dou_mentions", {"count": 0, "as_of": as_of, "window": win, "top": []})
            return res.mark(Status.EMPTY, f"not found in the local {banner} (recent acts may be missing){note}")
        ranked = rank(hits)
        count = f">= {ranked['count']}" if capped else str(ranked["count"])
        res.attr("dou_status", f"{banner}: {count} mention(s){note}")
        top = []
        for h in ranked["top"]:
            rec = h["record"]
            top.append({**rec, "art_type": h["art_type"], "penalty_terms": h["penalty_terms"], "match": h["match_kinds"]})
            self._finding(res, h, banner, etype)
            for number in h["cnj_numbers"]:
                parsed = {"formatted": number}
                res.pivot(T.KEYWORD, **cnj_pivot_args(parsed))
            if rec.get("url"):
                res.link(f"DOU act {rec.get('date')} (DO{rec.get('section')})", rec["url"])
        res.attr("dou_mentions", {"count": ranked["count"], "capped": capped, "as_of": as_of, "window": win, "top": top})
        res.raw = {"as_of": as_of, "count": ranked["count"], "capped": capped, "window": win, "top": top}
        return res

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _person_refusal(ctx: Any) -> str:
        """Cond 6: a typed person seed in a case with a recorded purpose; never QSA names or other pivots."""
        if not getattr(ctx, "is_seed", False):
            return "person names are matched only for analyst-typed person seeds (never QSA names or pivots)"
        if not str(getattr(ctx, "purpose", "") or "").strip():
            return "person-name matching needs a due-diligence case with a recorded purpose (--purpose)"
        return ""

    def _cite(self, ctx: Any, as_of: str, months: list[str]) -> None:
        used = getattr(getattr(ctx, "data", None), "used", None)
        if isinstance(used, list) and not any(isinstance(c, dict) and c.get("name") == "dou_search.index" for c in used):
            used.append({"name": "dou_search.index", "sha256": "", "fetched_at": as_of, "licence": LICENCE,
                         "months": f"{months[0]}..{months[-1]}" if months else ""})

    @staticmethod
    def _finding(res: ModuleResult, hit: dict[str, Any], banner: str, etype: Any) -> None:
        rec = hit["record"]
        where = f"{rec.get('date')} DO{rec.get('section')} - {rec.get('organ') or '?'} - {hit.get('art_type') or '?'}"
        desc = f"{where}: {rec.get('excerpt')} ({banner})"
        data = {**rec, "art_type": hit.get("art_type"), "penalty_terms": hit["penalty_terms"], "match": hit["match_kinds"]}
        key = f"{rec.get('date')}|{hit.get('id') or rec.get('url') or rec.get('title')}"
        refs = [rec["url"]] if rec.get("url") else []
        if hit["penalty_terms"] and "cnpj" in hit["match_kinds"] and etype is T.CNPJ:
            res.finding(
                "DOU act with a penalty term mentions this CNPJ", "low", desc, confidence="possible", source=SOURCE,
                criterion=f"exact CNPJ in a DOU act excerpt that carries penalty terms ({', '.join(hit['penalty_terms'])}): review the act",
                tags=["penalty_term"], data=data, references=refs, observed_first=rec.get("date"), key=key,
            )
        elif hit["penalty_terms"]:
            res.finding("DOU act with a penalty term mentions this name", "info", desc, confidence="possible", source=SOURCE,
                        tags=["penalty_term", "context_only", "name_only_match"] if "cnpj" not in hit["match_kinds"] else ["penalty_term", "context_only"],
                        data=data, references=refs, observed_first=rec.get("date"), key=key)
        else:
            res.finding("DOU mention (routine act)", "info", desc, confidence="probable" if "cnpj" in hit["match_kinds"] else "possible",
                        source=SOURCE, tags=["info", "context_only"], data=data, references=refs, observed_first=rec.get("date"), key=key)


# --------------------------------------------------------------------------------------
# installer entry point (outside any scan): python -m v3lum.modules.brazil_public_data.dou_search install ...
# --------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m v3lum.modules.brazil_public_data.dou_search",
                                     description="Install official DOU open-data dump ZIPs into the local dou_search index (no network).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    inst = sub.add_parser("install", help="index dump ZIPs downloaded by hand from " + OPEN_DATA_PAGE)
    inst.add_argument("zips", nargs="+")
    inst.add_argument("--window-months", type=int, default=None, help="months kept (default: setting dou_search_window_months, 24)")
    sub.add_parser("status", help="installed months and the dump date")
    args = parser.parse_args(argv)
    if args.cmd == "install":
        months = args.window_months
        if months is None:
            from v3lum.config import Config

            try:
                months = int(Config.load().get("dou_search_window_months", WINDOW_MONTHS) or WINDOW_MONTHS)
            except (TypeError, ValueError, OSError):
                months = WINDOW_MONTHS
        results = install_dumps(args.zips, window_months=months)
        for r in results:
            sys.stdout.write(f"{r['file']}: {r['status']} ({r['articles']} acts) {r['reason']}\n")
        return 0 if all(r["status"] == "installed" for r in results) else 1
    idx, problem = open_index()
    if idx is None:
        sys.stdout.write(f"no usable DOU index ({problem})\n")
        return 1
    try:
        sys.stdout.write(f"{as_of_banner(idx.meta.get('as_of'))}; months: {', '.join(idx.months())}\n")
    finally:
        idx.close()
    return 0


if __name__ == "__main__":  # pragma: no cover - manual installer
    raise SystemExit(main())

__all__ = [
    "DouIndex", "DouSearch", "FormatChanged", "XmlRefused", "build_seeds", "excerpt", "install_dumps", "iter_dou_zip", "make_hit",
    "manual_link", "open_index", "parse_dou_xml", "parse_dump_name", "penalty_terms", "rank", "safe_xml_root", "search", "window",
]
