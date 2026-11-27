"""retirejs_check: vulnerable front-end library detection with the RetireJS repository (P344, batch p2-G03-1).

Detection semantics adapted from Retire.js ``node/lib/retire.js`` 6.1.1 (https://github.com/RetireJS/retire.js,
Apache-2.0; re-implemented in Python, notice in v3lum/data/notices/retirejs.json): the version placeholder,
filename extractors anchored on the last path segment, ``.min``/``-min`` stripped, hash-like versions dropped
for uri/filename, content order filecontent -> filecontentreplace -> SHA-1 of the CRLF-normalised content,
and the piecewise ``isAtOrAbove`` comparison.

Final conditions implemented (P344):

* c1 - a library over bodies already in hand (:func:`scan_javascript` / :func:`retire_scan` for
  web_fingerprint P072 and js_endpoints P068) plus the module ``retirejs_check`` for URL, file and text
  inputs. It never fetches the target (disclosure ``none``): a URL contributes its uri/filename only (the
  cache-only read of a body fetched by another module is a core request, see the backlog).
* c2 - ``jsrepository-v4.json`` (Apache-2.0) is the weekly dataset ``retirejs.jsrepository`` with a bundled
  snapshot fallback; uri, filename, filecontent(+replace) and hashes extractors are used, ``func``/``ast``
  extractors need a JS runtime and are skipped (counted). Version regexes go through the same kind of
  adversarial harness as secret_scanner (tests); at run time a literal prefilter, literal-anchored windows
  and input caps bound the six repository patterns that backtrack quadratically.
* c3 - OSV npm confirmation (library name and version only, never the target) lives in the sibling module
  ``retirejs_osv`` (disclosure third_party): at most 10 queries per entity and 20 per run.
* c4 - ONE finding per library+version listing its advisories (CVE/GHSA); severity = the highest advisory
  severity capped at MEDIUM unless a CVE is in the local CISA KEV copy (P291), and only for org-profile own
  assets or in-scope targets - third-party and hostile sites (and texts/files of unknown origin) get info.
* c5 - uri/filename detections are labelled 'version inferred from file name' (<= 0.5, POSSIBLE); content
  and hash detections rank higher (0.75-0.9).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import urllib.parse
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

DATASET = "retirejs.jsrepository"
DATASET_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json"
DATASET_SOURCE = "github.retirejs_check_jsrepository"
BUNDLED = "retirejs/jsrepository-v4.json"
ATTRIBUTION = "Retire.js vulnerability repository (https://github.com/RetireJS/retire.js), Apache-2.0"
RETIRE_VERSION_PLACEHOLDER = "\u00a7\u00a7version\u00a7\u00a7"
RETIRE_VERSION_RE = r"[0-9][0-9.a-z_\-]+"
RETIRE_EXTRACTOR_CONFIDENCE = {"hash": 0.9, "filecontent": 0.8, "filecontentreplace": 0.75, "uri": 0.5, "filename": 0.5}
SEVERITY_ORDER = {"info": 0, "none": 0, "low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}
SEVERITY_NAMES = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
RETIRE_WINDOW_PRE = 1024  # chars scanned before a literal occurrence (the version may precede it)
RETIRE_WINDOW_POST = 1024
RETIRE_MAX_OCCURRENCES = 20  # literal occurrences examined per pattern
RETIRE_NO_LITERAL_PREFIX = 65536  # patterns without a usable literal only see the head of the file (banners)
RETIRE_URI_MAX = 2048  # uri/filename extractors only ever see URL-sized input
MAX_INPUT_BYTES = 5_000_000
TEXT_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".map", ".html", ".htm", ".txt", ".json", ""}
CVE_PIVOT_CAP = 20
KEV_DATASET = "cisa_kev"


def _validate_repository(path: Path) -> bool:
    """register_dataset(validate=): a JSON object with at least 20 library entries carrying extractors."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(doc, dict):
        return False
    libs = [v for k, v in doc.items() if not str(k).startswith("_") and isinstance(v, dict) and isinstance(v.get("extractors"), dict)]
    return len(libs) >= 20


register_dataset(
    DATASET,
    DATASET_URL,
    ttl=7 * 86400,
    description="RetireJS vulnerability repository jsrepository-v4.json: extractors and vulnerable ranges of front-end JS libraries (P344)",
    licence="Apache-2.0",
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="github",
    source=DATASET_SOURCE,
    validate=_validate_repository,
    min_bytes=100_000,
    expect="json",
    max_bytes=5 * 1024 * 1024,
    large=False,
)


def _text(raw: Any, limit: int | None = None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", "replace")
    elif not isinstance(raw, str):
        raw = str(raw)
    return raw[:limit] if limit is not None else raw


# ============================================================================================ pattern compiling
def _strip_lookbehind(pattern: str) -> tuple[str, str] | None:
    """Python ``re`` rejects variable-width look-behind. When one directly follows a group, remove it and
    return its body so the caller re-checks it on the text that ends at the group end (same semantics)."""
    i = pattern.find("(?<=")
    if i <= 0 or pattern[i - 1] != ")":
        return None
    depth, j, esc, in_class = 0, i, False, False
    while j < len(pattern):
        ch = pattern[j]
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif in_class:
            if ch == "]":
                in_class = False
        elif ch == "[":
            in_class = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return pattern[:i] + pattern[j + 1:], pattern[i + 4:j]
        j += 1
    return None


def required_literal(src: str) -> str:
    """Longest literal run every match of a regex source must contain, outside groups, classes and optional
    atoms ('' when none is reliable: top-level alternation, too short). Used for prefiltering and windowing,
    the stdlib defence against the quadratic repository patterns."""
    cur: list[str] = []
    runs: list[str] = []
    i, n = 0, len(src)

    def flush() -> None:
        if cur:
            runs.append("".join(cur))
            cur.clear()

    def skip_quant(j: int) -> int:
        if j < n and src[j] in "*+?":
            j += 1
        elif j < n and src[j] == "{":
            k = src.find("}", j)
            j = k + 1 if k > 0 else j + 1
        if j < n and src[j] in "?+":
            j += 1
        return j

    while i < n:
        ch = src[i]
        lit: str | None
        if ch == "|":
            return ""
        if ch == "\\":
            nxt = src[i + 1] if i + 1 < n else ""
            lit = {"n": "\n", "t": "\t"}.get(nxt) or (nxt if nxt and not nxt.isalnum() else None)
            j = i + 2
        elif ch == "[":
            j = i + 1
            if j < n and src[j] == "^":
                j += 1
            if j < n and src[j] == "]":
                j += 1
            while j < n and src[j] != "]":
                j += 2 if src[j] == "\\" else 1
            lit, j = None, j + 1
        elif ch == "(":
            depth, j = 0, i
            while j < n:
                c = src[j]
                if c == "\\":
                    j += 2
                    continue
                if c == "[":
                    j += 1
                    while j < n and src[j] != "]":
                        j += 2 if src[j] == "\\" else 1
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            lit, j = None, j + 1
        elif ch in ".^$":
            lit, j = None, i + 1
        else:
            lit, j = ch, i + 1
        q = src[j] if j < n else ""
        if lit is None:
            flush()
            i = skip_quant(j)
            continue
        if q in ("*", "?", "{"):
            flush()
            i = skip_quant(j)
            continue
        cur.append(lit)
        if q == "+":
            flush()
            i = skip_quant(j)
            continue
        i = j
    flush()
    best = max(runs, key=len, default="")
    return best if len(best) >= 3 else ""


def _windowed_finditer(rx: re.Pattern[str], text: str, literal: str) -> Any:
    """finditer restricted to windows around the first RETIRE_MAX_OCCURRENCES occurrences of the literal."""
    if not literal:
        yield from rx.finditer(text, 0, min(len(text), RETIRE_NO_LITERAL_PREFIX))
        return
    start, seen, count = 0, set(), 0
    while count < RETIRE_MAX_OCCURRENCES:
        k = text.find(literal, start)
        if k < 0:
            return
        count += 1
        lo, hi = max(0, k - RETIRE_WINDOW_PRE), min(len(text), k + len(literal) + RETIRE_WINDOW_POST)
        for m in rx.finditer(text, lo, hi):
            if m.span() not in seen:
                seen.add(m.span())
                yield m
        start = k + max(1, len(literal))


def _compile_retire(pattern: str, anchored: bool = False) -> tuple[re.Pattern[str] | None, re.Pattern[str] | None, str | None]:
    """One RetireJS (JavaScript) regex for Python -> (compiled, post_check | None, error | None)."""
    src = pattern.replace(RETIRE_VERSION_PLACEHOLDER, RETIRE_VERSION_RE)
    src = re.sub(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>", r"(?P<\1>", src)  # JS named groups
    if anchored:
        src = "^" + src + "$"
    try:
        return re.compile(src), None, None
    except re.error as exc:
        stripped = _strip_lookbehind(src)
        if stripped:
            try:
                return re.compile(stripped[0]), re.compile("(?:" + stripped[1] + r")\Z"), None
            except re.error as exc2:
                return None, None, str(exc2)
        return None, None, str(exc)


def retire_load_repo(raw: Any) -> dict[str, Any]:
    """c2: jsrepository-v4.json -> compiled extractors. uri, filename, filecontent(+replace) and hashes are
    used; 'func'/'ast' need a JS runtime and are skipped (counted). Patterns that do not compile are
    listed, never silently dropped. Returns ``{"libraries", "skipped_func", "pattern_errors", "error"}``."""
    if isinstance(raw, dict):
        obj: Any = raw
    else:
        try:
            obj = json.loads(_text(raw))
        except ValueError as exc:
            return {"libraries": {}, "skipped_func": 0, "pattern_errors": [], "error": f"invalid json: {str(exc)[:80]}"}
    if not isinstance(obj, dict):
        return {"libraries": {}, "skipped_func": 0, "pattern_errors": [], "error": "not a repository object"}
    libs: dict[str, Any] = {}
    errors: list[dict[str, Any]] = []
    skipped = 0
    for name, ent in obj.items():
        if not isinstance(ent, dict) or str(name).startswith("_"):
            continue
        ex = ent.get("extractors") if isinstance(ent.get("extractors"), dict) else {}
        lib: dict[str, Any] = {"npmname": ent.get("npmname") if isinstance(ent.get("npmname"), str) else None,
                               "vulnerabilities": [v for v in ent.get("vulnerabilities") or [] if isinstance(v, dict)],
                               "uri": [], "filename": [], "filecontent": [], "filecontentreplace": [], "hashes": {}}
        for kind in ("uri", "filename", "filecontent"):
            for pat in ex.get(kind) or []:
                if not isinstance(pat, str):
                    continue
                rx, post, err = _compile_retire(pat, anchored=(kind == "filename"))
                if rx is None:
                    errors.append({"library": name, "extractor": kind, "pattern": pat[:120], "error": err})
                else:
                    lib[kind].append((rx, post, pat, required_literal(rx.pattern) if kind == "filecontent" else ""))
        for pat in ex.get("filecontentreplace") or []:
            m = re.match(r"^/(.*[^\\])/([^/]+)/$", pat or "", re.S) if isinstance(pat, str) else None
            if not m:
                errors.append({"library": name, "extractor": "filecontentreplace", "pattern": str(pat)[:120], "error": "not /regex/replacement/"})
                continue
            rx, post, err = _compile_retire(m.group(1))
            if rx is None:
                errors.append({"library": name, "extractor": "filecontentreplace", "pattern": pat[:120], "error": err})
                continue
            lib["filecontentreplace"].append((rx, post, re.sub(r"\$(\d)", r"\\g<\1>", m.group(2)), required_literal(rx.pattern)))
        if isinstance(ex.get("hashes"), dict):
            lib["hashes"] = {str(k).lower(): str(v) for k, v in ex["hashes"].items()}
        skipped += len(ex.get("func") or []) + len(ex.get("ast") or [])
        libs[str(name)] = lib
    return {"libraries": libs, "skipped_func": skipped, "pattern_errors": errors, "error": None}


def retire_repo_patterns(raw: Any) -> list[str]:
    """Every Python-ready regex source of a repository (for the ReDoS harness), placeholder replaced."""
    try:
        obj = raw if isinstance(raw, dict) else json.loads(_text(raw))
    except ValueError:
        return []
    pats: list[str] = []
    for _name, ent in obj.items() if isinstance(obj, dict) else []:
        ex = ent.get("extractors") if isinstance(ent, dict) and isinstance(ent.get("extractors"), dict) else {}
        for kind in ("uri", "filename", "filecontent"):
            for p in ex.get(kind) or []:
                if isinstance(p, str):
                    src = p.replace(RETIRE_VERSION_PLACEHOLDER, RETIRE_VERSION_RE)
                    stripped = _strip_lookbehind(src)
                    pats.append(stripped[0] if stripped and "(?<=" in src else src)
    return pats


# ============================================================================================ scanning
def _looks_like_hash(version: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{7,}", re.sub(r"(\.|-)min$", "", version)))


def _clean_version(v: str) -> str:
    return re.sub(r"(\.|-)min$", "", v)


def retire_normalise_content(content: Any) -> str:
    return _text(content).replace("\r\n", "\n").replace("\r", "\n")


def retire_sha1(content: Any) -> str:
    """SHA-1 of the CRLF-normalised content, as retire.js scanFileContent computes it for the hashes extractor."""
    return hashlib.sha1(retire_normalise_content(content).encode("utf-8")).hexdigest()  # noqa: S324 - RetireJS file identity, not security


def retire_scan(repo: dict[str, Any], content: Any = None, uri: Any = None, filename: Any = None, max_bytes: int = MAX_INPUT_BYTES) -> list[dict[str, Any]]:
    """c2/c5: detections from JS content (filecontent -> filecontentreplace -> SHA-1 hash, retire.js order),
    a URI and a file name; one entry per library+version keeps the strongest extractor.
    Returns ``[{"component", "version", "detection", "npmname", "confidence", "version_inferred"}]``."""
    libs = (repo or {}).get("libraries", {})
    found: dict[tuple[str, str], dict[str, Any]] = {}

    def add(component: str, version: Any, detection: str) -> None:
        if not isinstance(version, str) or not version:
            return
        version = _clean_version(version)[:64]
        conf = RETIRE_EXTRACTOR_CONFIDENCE.get(detection, 0.5)
        key = (component, version)
        if key not in found or conf > found[key]["confidence"]:
            found[key] = {"component": component, "version": version, "detection": detection, "npmname": libs.get(component, {}).get("npmname"),
                          "confidence": conf, "version_inferred": detection in ("uri", "filename")}

    if content is not None:
        text = retire_normalise_content(content)[:max_bytes]
        hits: list[tuple[str, str]] = []
        for name, lib in libs.items():
            for rx, post, _p, lit in lib["filecontent"]:
                if lit and lit not in text:
                    continue
                for m in _windowed_finditer(rx, text, lit):
                    if m.groups() and m.group(1) and (post is None or post.search(text, 0, m.end(1))):
                        hits.append((name, m.group(1)))
        if hits:
            for name, v in hits:
                add(name, v, "filecontent")
        else:
            for name, lib in libs.items():
                for rx, _post, repl, lit in lib["filecontentreplace"]:
                    if lit and lit not in text:
                        continue
                    for m in _windowed_finditer(rx, text, lit):
                        try:
                            hits.append((name, m.expand(repl)))
                        except (re.error, IndexError):
                            continue
            for name, v in hits:
                add(name, v, "filecontentreplace")
        if not hits:
            digest = retire_sha1(text)
            for name, lib in libs.items():
                if digest in lib["hashes"]:
                    add(name, lib["hashes"][digest], "hash")
                    break
    if isinstance(uri, str) and uri:
        uri = uri[:RETIRE_URI_MAX]
        for name, lib in libs.items():
            for rx, post, _p, _lit in lib["uri"]:
                for m in rx.finditer(uri):
                    if m.groups() and m.group(1) and not _looks_like_hash(m.group(1)) and (post is None or post.search(uri, 0, m.end(1))):
                        add(name, m.group(1), "uri")
        if not filename:
            try:  # retire.js scanFileName(includeUri): file-name extractors also see the URL's last path segment
                filename = urllib.parse.urlsplit(uri).path
            except ValueError:
                filename = None
    if isinstance(filename, str) and filename:
        last = re.split(r"[/\\]", filename[:RETIRE_URI_MAX])[-1]
        for name, lib in libs.items():
            for rx, _post, _p, _lit in lib["filename"]:
                m = rx.match(last)
                if m and m.groups() and m.group(1) and not _looks_like_hash(m.group(1)):
                    add(name, m.group(1), "filename")
    return sorted(found.values(), key=lambda d: (d["component"], d["version"]))


def _comparable(part: str | None) -> int | str:
    if part is None:
        return 0
    return int(part) if re.fullmatch(r"[0-9]+", part) else part


def retire_is_at_or_above(v1: Any, v2: Any) -> bool:
    """Port of retire.js isAtOrAbove: split on . - +, numbers compare numerically, a number beats a string at
    the same position, missing parts count as 0."""
    a = re.split(r"[.\-+]", str(v1))
    b = re.split(r"[.\-+]", str(v2))
    for i in range(max(len(a), len(b))):
        x = _comparable(a[i] if i < len(a) else None)
        y = _comparable(b[i] if i < len(b) else None)
        if type(x) is not type(y):
            return isinstance(x, int)
        if x > y:  # type: ignore[operator]
            return True
        if x < y:  # type: ignore[operator]
            return False
    return True


def retire_check(repo: dict[str, Any], component: str, version: str) -> list[dict[str, Any]]:
    """c4: vulnerability entries matching component+version (retire.js check(): below / atOrAbove / excludes).
    Returns ``[{"ids", "cves", "ghsa", "summary", "severity", "below", "atOrAbove", "info"}]``."""
    lib = (repo or {}).get("libraries", {}).get(component)
    if not lib:
        return []
    out = []
    for v in lib["vulnerabilities"]:
        below, above = v.get("below"), v.get("atOrAbove")
        if below is not None and retire_is_at_or_above(version, below):
            continue
        if above is not None and not retire_is_at_or_above(version, above):
            continue
        if version in (v.get("excludes") or []):
            continue
        ids = v.get("identifiers") if isinstance(v.get("identifiers"), dict) else {}
        cves = [c for c in (ids.get("CVE") or []) if isinstance(c, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", c)]
        ghsa = ids.get("githubID") if isinstance(ids.get("githubID"), str) and re.fullmatch(r"GHSA(-[0-9a-z]{4}){3}", ids.get("githubID")) else None
        info = [u for u in (v.get("info") or []) if isinstance(u, str) and u.startswith("https://")][:3]
        out.append({"ids": cves + ([ghsa] if ghsa else []), "cves": cves, "ghsa": ghsa,
                    "summary": str(ids.get("summary"))[:200] if ids.get("summary") else None,
                    "severity": str(v.get("severity") or "").lower() or None, "below": below, "atOrAbove": above, "info": info})
    return out


def retire_finding(detection: dict[str, Any], advisories: list[dict[str, Any]], owned_or_in_scope: bool = False,
                   kev_cves: Any = (), exploited_cves: Any = ()) -> dict[str, Any] | None:
    """c4/c5: ONE finding per library+version listing its advisories. Severity = highest advisory severity,
    capped at MEDIUM unless a CVE is in KEV / known exploited (P291), and only for own assets or in-scope
    targets (info otherwise). uri/filename detections: 'version inferred from file name', <= 0.5."""
    if not advisories:
        return None
    with_ids = [a for a in advisories if a["ids"]]
    notes = [a for a in advisories if not a["ids"]]
    top = max((SEVERITY_ORDER.get(a.get("severity") or "", 0) for a in advisories), default=0)
    cves = sorted({c for a in advisories for c in a["cves"]})
    kev = sorted(set(cves) & (set(kev_cves or ()) | set(exploited_cves or ())))
    severity = SEVERITY_NAMES.get(top if kev else min(top, SEVERITY_ORDER["medium"]), "info") if owned_or_in_scope else "info"
    inferred = bool(detection.get("version_inferred"))
    conf = min(float(detection.get("confidence", 0.5)), 0.5) if inferred else float(detection.get("confidence", 0.8))
    label = "possible" if conf < 0.55 else ("probable" if conf < 0.85 else "confirmed")
    crit = (f"version inferred from file name/URL ({detection['detection']}): backported fixes not considered" if inferred
            else f"version read from the file ({detection['detection']} extractor)")
    return {"title": f"{detection['component']} {detection['version']}: {len(with_ids)} known advisor{'y' if len(with_ids) == 1 else 'ies'}",
            "library": detection["component"], "version": detection["version"], "npmname": detection.get("npmname"), "advisories": with_ids,
            "other_notes": notes, "cves": cves, "kev_or_exploited": kev, "severity": severity, "confidence": conf, "confidence_label": label,
            "criterion": crit}


# ============================================================================================ repository access
_REPO_LOCK = threading.Lock()
_REPO_MEMO: dict[str, Any] = {"sha": None, "repo": None}


def _compiled(raw: bytes) -> tuple[dict[str, Any], str]:
    sha = hashlib.sha256(raw).hexdigest()
    with _REPO_LOCK:
        if _REPO_MEMO["sha"] != sha:
            _REPO_MEMO["repo"] = retire_load_repo(raw)
            _REPO_MEMO["sha"] = sha
        return _REPO_MEMO["repo"], sha


def load_repository(data: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """The compiled repository from ``ctx.data``: the weekly dataset copy when present (cited, never
    downloaded here), else the bundled snapshot. Returns ``(repo, info)``; raises DatasetError when neither
    is usable."""
    source, raw, fetched_at = "bundled", None, "bundled"
    try:
        info = data.info(DATASET)
        if info.present:
            path = data.fetch(DATASET, ttl=10 ** 12)  # the local copy: a citation, never a download
            raw = Path(path).read_bytes()
            source, fetched_at = "dataset", info.fetched_at
    except (DatasetError, OSError, ValueError):
        raw = None
    if raw is None:
        try:
            raw = Path(data.bundled_path(BUNDLED)).read_bytes()
        except (OSError, ValueError) as exc:
            raise DatasetError(f"RetireJS repository unavailable ({type(exc).__name__}): run v3lum data update {DATASET}", name=DATASET) from exc
    repo, sha = _compiled(raw)
    if repo.get("error") or not repo.get("libraries"):
        raise DatasetError(f"RetireJS repository unusable ({repo.get('error') or 'no libraries'}): run v3lum data update {DATASET}", name=DATASET)
    return repo, {"source": source, "sha256": sha, "libraries": len(repo["libraries"]), "skipped_func": repo["skipped_func"],
                  "pattern_errors": len(repo["pattern_errors"]), "fetched_at": fetched_at}


def kev_cves(data: Any) -> set[str]:
    """CVE ids of the local CISA KEV copy (P291 dataset of cisa_kev) when present; never downloaded here."""
    try:
        info = data.info(KEV_DATASET)
        if not info.present:
            return set()
        from v3lum.modules.vulnerability_cve.cisa_kev import load_kev_catalog

        catalog = load_kev_catalog(Path(data.fetch(KEV_DATASET, ttl=10 ** 12)))
        entries = catalog.get("entries") if isinstance(catalog, dict) and isinstance(catalog.get("entries"), dict) else catalog
        return {str(k) for k in (entries or {}) if str(k).startswith("CVE-")}
    except Exception:  # noqa: BLE001 - KEV is an optional severity input
        return set()


def scan_javascript(data: Any, content: Any = None, uri: Any = None, filename: Any = None) -> dict[str, Any]:
    """c1 library entry point for modules that already hold a JavaScript body (web_fingerprint P072,
    js_endpoints P068): ``{"repository": info, "libraries": [detection + advisories]}``. No request."""
    repo, info = load_repository(data)
    libraries = []
    for det in retire_scan(repo, content=content, uri=uri, filename=filename):
        libraries.append(dict(det, advisories=retire_check(repo, det["component"], det["version"])))
    return {"repository": info, "libraries": libraries}


def _owned_or_in_scope(entity: Entity, ctx: Any) -> bool:
    if entity.type is not T.URL:
        return False
    try:
        if ctx.org.owns(entity).own:
            return True
    except Exception:  # noqa: BLE001
        pass
    scope = getattr(getattr(ctx, "options", None), "scope", None)
    try:
        return bool(scope is not None and getattr(ctx, "authorized", False) and scope.matches_url(entity.value))
    except Exception:  # noqa: BLE001
        return False


def read_input(entity: Entity) -> tuple[Any, Any, Any]:
    """(content, uri, filename) of an entity: URLs give uri/filename only (never fetched)."""
    if entity.type is T.URL:
        return None, entity.value, None
    if entity.type is T.FILE:
        with open(entity.value, encoding="utf-8", errors="replace") as fh:
            return fh.read(MAX_INPUT_BYTES), None, os.path.basename(entity.value)
    return entity.value, None, None


def _file_applies(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in TEXT_EXT and os.path.isfile(path) and os.path.getsize(path) <= MAX_INPUT_BYTES


@register
class RetireJsCheck(Module):
    name = "retirejs_check"
    title = "Vulnerable front-end libraries (RetireJS, offline)"
    description = (
        "Recognises front-end JavaScript libraries and versions with the RetireJS repository (uri, file name, content and hash "
        "extractors) in URLs, files and text already in hand and lists their advisories (CVE/GHSA); never fetches the target."
    )
    category = "url_web"
    accepts = {T.URL, T.FILE, T.TEXT}
    produces = {T.CVE}
    tags = {"offline"}
    reference = "https://github.com/RetireJS/retire.js"
    notice = "RetireJS repository and detection logic: Apache-2.0 (v3lum/data/notices/retirejs.json)."
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # bodies already in hand; the dataset download carries no case value
    hosts = ()
    sources = (DATASET_SOURCE,)
    access_model = "offline"
    default_enabled = True
    max_pivots = CVE_PIVOT_CAP

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.FILE:
            return _file_applies(entity.value)
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            content, uri, filename = read_input(entity)
        except OSError as exc:
            return res.mark(Status.ERROR, f"cannot read the file: {exc.strerror or type(exc).__name__}")
        scanned = scan_javascript(ctx.data, content=content, uri=uri, filename=filename)
        res.attr("retirejs_repository", scanned["repository"])
        libraries = scanned["libraries"]
        res.raw = {"repository": scanned["repository"], "libraries": [{k: d[k] for k in ("component", "version", "detection", "confidence")} for d in libraries]}
        if not libraries:
            return res.mark(Status.EMPTY, "no library of the RetireJS repository recognised" + (" (URL: file name/path only, the body is never fetched)" if uri else ""))
        res.attr("js_libraries", [{"library": d["component"], "version": d["version"], "detection": d["detection"], "confidence": d["confidence"],
                                   "version_inferred": d["version_inferred"], "npm": d.get("npmname"), "advisories": len([a for a in d["advisories"] if a["ids"]])}
                                  for d in libraries])
        own = _owned_or_in_scope(entity, ctx)
        kev = kev_cves(ctx.data) if any(a["cves"] for d in libraries for a in d["advisories"]) else set()
        pivots = 0
        for det in libraries:
            card = retire_finding(det, det["advisories"], owned_or_in_scope=own, kev_cves=kev)
            if card is None:
                continue
            tags = ["vulnerable"] + (["version_inferred"] if det["version_inferred"] else []) + (["kev"] if card["kev_or_exploited"] else [])
            ids = [i for a in card["advisories"] for i in a["ids"]]
            res.finding(
                "Known-vulnerable JavaScript library",
                card["severity"],
                f"{card['title']}" + (f" ({', '.join(ids[:12])}{' ...' if len(ids) > 12 else ''})" if ids else "")
                + (f"; {len(card['other_notes'])} note(s) without an identifier (e.g. end of life)" if card["other_notes"] else "")
                + ("" if own else "; not an org-profile own asset or in-scope target: informational (P344 cond 4)."),
                confidence=card["confidence"],
                criterion=card["criterion"] + f"; RetireJS ranges, severity capped at MEDIUM unless in CISA KEV ({'KEV: ' + ', '.join(card['kev_or_exploited']) if card['kev_or_exploited'] else 'none in KEV'})",
                tags=tags,
                data={"library": card["library"], "version": card["version"], "npm": card["npmname"], "detection": det["detection"],
                      "advisories": [{k: a[k] for k in ("ids", "summary", "severity", "below", "atOrAbove")} for a in card["advisories"]],
                      "other_notes": [{k: a[k] for k in ("summary", "severity", "below")} for a in card["other_notes"]],
                      "kev": card["kev_or_exploited"]},
                references=[u for a in card["advisories"] for u in a["info"]][:10],
                source=DATASET_SOURCE,
                key=f"{card['library']}@{card['version']}",
            )
            for cve in card["cves"]:
                if pivots >= CVE_PIVOT_CAP:
                    break
                pivots += 1
                res.pivot(T.CVE, cve, "has_vuln", confidence="possible" if det["version_inferred"] else "probable", expand=False,
                          note=f"{card['library']} {card['version']} ({det['detection']} extractor, RetireJS ranges)")
        return res


# ============================================================================================ OSV confirmation (c3)
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_SOURCE = "osv.retirejs_check_query"
OSV_PER_ENTITY_CAP = 10
OSV_PER_RUN_CAP = 20


def osv_query_body(name: str, version: str, ecosystem: str = "npm") -> dict[str, Any]:
    """c3: library name and version only, never the target."""
    return {"package": {"name": name, "ecosystem": ecosystem}, "version": version}


def osv_budget(planned: list[tuple[str, str, str]], per_entity: int = OSV_PER_ENTITY_CAP, per_run: int = OSV_PER_RUN_CAP, used_in_run: int = 0) -> dict[str, Any]:
    """c3: at most 10 OSV queries per entity and 20 per run. planned = [(entity, name, version)]."""
    allowed: list[tuple[str, str, str]] = []
    deferred: list[tuple[str, str, str, str]] = []
    per: dict[str, int] = {}
    seen: set[tuple[str, str]] = set()
    for entity, name, version in planned or ():
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        if used_in_run + len(allowed) >= per_run:
            deferred.append((entity, name, version, "per-run cap"))
        elif per.get(entity, 0) >= per_entity:
            deferred.append((entity, name, version, "per-entity cap"))
        else:
            per[entity] = per.get(entity, 0) + 1
            allowed.append((entity, name, version))
    return {"allowed": allowed, "deferred": deferred}


def parse_osv_query(status: int, body: Any) -> dict[str, Any]:
    """c3: OSV /v1/query -> {"status", "advisories": [{"id", "aliases", "cves", "severity", "summary", "fixed"}]};
    {} = no known vulnerability (empty); 400 {"code", "message"} -> error."""
    try:
        obj = body if isinstance(body, (dict, list)) else json.loads(_text(body))
    except ValueError:
        return {"status": "error", "reason": "OSV answer is not JSON: could not verify", "advisories": []}
    if int(status or 200) >= 400 or (isinstance(obj, dict) and "code" in obj and "message" in obj and "vulns" not in obj):
        msg = obj.get("message") if isinstance(obj, dict) else ""
        return {"status": "error", "reason": f"OSV HTTP {status}: {str(msg or '')[:120]}", "advisories": []}
    if not isinstance(obj, dict):
        return {"status": "error", "reason": "unexpected OSV answer shape: could not verify", "advisories": []}
    advs = []
    for v in (obj.get("vulns") or [])[:100] if isinstance(obj.get("vulns"), list) else []:
        if not isinstance(v, dict):
            continue
        aliases = [a for a in v.get("aliases") or [] if isinstance(a, str)][:20]
        fixed = []
        for aff in v.get("affected") or []:
            for rng in (aff.get("ranges") or []) if isinstance(aff, dict) else []:
                for ev in (rng.get("events") or []) if isinstance(rng, dict) else []:
                    if isinstance(ev, dict) and isinstance(ev.get("fixed"), str):
                        fixed.append(ev["fixed"])
        ds = v.get("database_specific") if isinstance(v.get("database_specific"), dict) else {}
        vid = v.get("id") if isinstance(v.get("id"), str) else None
        advs.append({"id": vid, "aliases": aliases, "cves": sorted({a for a in aliases + [vid or ""] if a.startswith("CVE-")}),
                     "severity": str(ds.get("severity") or "").lower() or None, "summary": str(v.get("summary") or "")[:200] or None,
                     "fixed": sorted(set(fixed))[:10]})
    return {"status": "ok" if advs else "empty", "reason": None, "advisories": advs}


def osv_confirms(advisories: list[dict[str, Any]], osv_parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """Which RetireJS advisories OSV confirms (a CVE or GHSA id among the OSV ids/aliases)."""
    osv_ids: set[str] = set()
    for a in (osv_parsed or {}).get("advisories", []):
        if a.get("id"):
            osv_ids.add(a["id"])
        osv_ids.update(a.get("aliases") or [])
    return [dict(a, osv_confirmed=bool(set(a.get("ids") or []) & osv_ids)) for a in advisories or ()]


class _OsvRunBudget:
    """c3: 20 OSV queries per run (scan or single run), shared by every entity of the run."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._used: dict[str, int] = {}

    def used(self, key: str) -> int:
        with self._lock:
            return self._used.get(key, 0)

    def add(self, key: str, n: int) -> None:
        with self._lock:
            if len(self._used) > 1000:
                self._used.clear()
            self._used[key] = self._used.get(key, 0) + n

    def reset(self) -> None:
        with self._lock:
            self._used.clear()


OSV_BUDGET = _OsvRunBudget()


def _run_key(ctx: Any) -> str:
    case_id = str(getattr(ctx, "case_id", "") or "")
    return f"case:{case_id}" if case_id else f"runtime:{id(getattr(ctx, 'runtime', ctx))}"


@register
class RetireJsOsv(Module):
    name = "retirejs_osv"
    title = "RetireJS detections confirmed by OSV (npm)"
    description = (
        "Confirms the libraries recognised by retirejs_check against OSV.dev npm advisories, sending only the library name and "
        "version (never the URL, file or text); at most 10 queries per entity and 20 per run."
    )
    category = "url_web"
    accepts = {T.URL, T.FILE, T.TEXT}
    produces = {T.CVE}
    reference = "https://google.github.io/osv.dev/post-v1-query/"
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # OSV receives 'jquery' + '1.12.4', never the target
    provider = "osv"
    sources = (OSV_SOURCE, DATASET_SOURCE)
    hosts = ("api.osv.dev",)
    access_model = "free_noauth_unlimited"
    max_requests = OSV_PER_ENTITY_CAP
    expected_latency = 1.0
    timeout = 60.0
    min_interval = 0.5
    cache_ttl = 86400
    default_enabled = True
    max_pivots = CVE_PIVOT_CAP

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.FILE:
            return _file_applies(entity.value)
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            content, uri, filename = read_input(entity)
        except OSError as exc:
            return res.mark(Status.ERROR, f"cannot read the file: {exc.strerror or type(exc).__name__}")
        scanned = scan_javascript(ctx.data, content=content, uri=uri, filename=filename)
        npm = [d for d in scanned["libraries"] if d.get("npmname")]
        if not npm:
            return res.mark(Status.EMPTY, "no npm library of the RetireJS repository recognised: nothing to confirm with OSV")
        key = _run_key(ctx)
        plan = osv_budget([(entity.key, d["npmname"], d["version"]) for d in npm], used_in_run=OSV_BUDGET.used(key))
        results: list[dict[str, Any]] = []
        errors: list[str] = []
        for _e, name, version in plan["allowed"]:
            OSV_BUDGET.add(key, 1)
            resp = ctx.http.post(OSV_QUERY_URL, json_body=osv_query_body(name, version), source=OSV_SOURCE, ttl=86400)
            if resp.status >= 500 or resp.status in (401, 403, 429) or (resp.status >= 400 and resp.status != 400):
                ctx.http.check(resp)  # rule 5: could not verify
            parsed = parse_osv_query(resp.status, resp.content)
            if parsed["status"] == "error":
                errors.append(f"{name}@{version}: {parsed['reason']}")
                continue
            det = next(d for d in npm if d["npmname"] == name and d["version"] == version)
            confirmed = osv_confirms([a for a in det["advisories"] if a["ids"]], parsed)
            osv_cves = sorted({c for a in parsed["advisories"] for c in a["cves"]})
            results.append({"library": det["component"], "npm": name, "version": version, "osv_ids": [a["id"] for a in parsed["advisories"] if a["id"]][:30],
                            "osv_cves": osv_cves, "confirmed": [i for a in confirmed if a["osv_confirmed"] for i in a["ids"]],
                            "not_in_osv": [i for a in confirmed if not a["osv_confirmed"] for i in a["ids"]],
                            "fixed": sorted({f for a in parsed["advisories"] for f in a["fixed"]})[:10]})
            for cve in osv_cves[:CVE_PIVOT_CAP]:
                res.pivot(T.CVE, cve, "has_vuln", confidence="possible" if det["version_inferred"] else "probable", expand=False,
                          note=f"OSV npm advisory for {name} {version} ({det['detection']} detection)")
        res.raw = {"queries": len(plan["allowed"]), "deferred": [{"library": n, "version": v, "why": w} for _e, n, v, w in plan["deferred"]],
                   "results": results, "errors": errors}
        if plan["deferred"]:
            res.attr("js_libraries", [{"library": n, "version": v, "osv": f"not queried ({w})"} for _e, n, v, w in plan["deferred"]] + results)
        elif results:
            res.attr("js_libraries", results)
        if errors and not results:
            return res.mark(Status.ERROR, "; ".join(errors)[:400])
        if errors:
            res.source_status(OSV_SOURCE, Status.ERROR, reason_code="error", reason="; ".join(errors)[:400])
        if plan["deferred"] and not results:
            return res.mark(Status.SKIPPED, f"OSV query cap reached ({OSV_PER_RUN_CAP} per run, {OSV_PER_ENTITY_CAP} per entity; P344 cond 3)", reason_code="policy")
        if not any(r["osv_ids"] for r in results):
            return res.mark(Status.EMPTY, "OSV lists no npm advisory for the recognised library versions") if not res.attributes else res
        return res
