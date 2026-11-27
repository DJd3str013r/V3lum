"""technique_detections_tests: technique -> Sigma detections and Atomic Red Team tests (P373, batch p2-G11-1).

Final conditions (FC) of P373 and where they are met:

* **FC1 Sigma download.** ``sigma_core.zip`` (DRL 1.1) is the registered dataset
  ``technique_detections_tests.sigma_core`` (github.com/SigmaHQ/sigma/releases/latest/download, redirected
  to release-assets.githubusercontent.com; weekly check, conditional GET by the dataset manager). The zip
  is read in memory only (:func:`safe_zip_members`: member count, per-member and total size, compression
  ratio, path, symlink and encryption checks; nothing is extracted to disk). Rule YAML is parsed only with
  ``yaml.safe_load`` from the optional PyYAML extra (``v3lum/data/extras/yaml.json``); without it the Sigma
  index is UNAVAILABLE ``package`` (per source, the Atomic part still answers).
* **FC2 licence.** No Sigma-derived index is bundled (DRL 1.1 is not on the A6 list): the index is built
  locally from the runtime download. Only metadata is kept (title, id, status, level, tags, logsource, path;
  the author only for DRL attribution) keyed by ``attack.tXXXX`` and ``cve.*`` tags; rule bodies are never
  reproduced (if one ever is, :func:`sigma_attribution` gives the DRL 1.1 credit line).
* **FC3 Atomic Red Team.** ``Indexes-CSV/index.csv`` (MIT) is read with the stdlib csv module (header
  checked): per technique the test number, name, GUID and executor, as links only. Nothing is ever
  executed or written outside the dataset store; tests assert that no process is spawned.
* **FC4 ordering and data.** Stable and test Sigma rules first, experimental/deprecated marked; tactic names
  are read from the data (ATT&CK v18+ 'stealth', 'defense-impairment'...), never hard-coded; the Sigma
  release (``version.txt``: release date, label, commit) and the dataset dates are recorded.
* **FC5 providers and output.** SigmaHQ (community) and Red Canary (trusted), both registry sources of the
  ``github`` provider extension; downloads only, no value is ever sent (disclosure 'none'). Technique, CVE
  and malware/actor cards show 'N Sigma rules / N atomic tests' with links; names are matched through the
  ATT&CK group/software ids of the P295 alias index and rule titles.
"""

from __future__ import annotations

import csv
import html
import io
import re
import stat
import threading
import unicodedata
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SIGMA_SOURCE = "github.technique_detections_sigma"
ATOMIC_SOURCE = "github.technique_detections_atomic"
SIGMA_DATASET = "technique_detections_tests.sigma_core"
ATOMIC_DATASET = "technique_detections_tests.atomic_index"
SIGMA_URL = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip"
ATOMIC_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/Indexes-CSV/index.csv"
WEEKLY = 7 * 86400
SIGMA_ZIP_CAPS = {"max_members": 5000, "max_total_bytes": 32 * 1024 * 1024, "max_member_bytes": 1024 * 1024, "max_ratio": 50}
SIGMA_LICENCE_URL = "https://github.com/SigmaHQ/Detection-Rule-License"
SIGMA_ATTRIBUTION = ("Sigma rule metadata from SigmaHQ (https://github.com/SigmaHQ/sigma), Detection Rule License 1.1 "
                     f"({SIGMA_LICENCE_URL}): rule bodies are not reproduced; each link credits the rule authors upstream.")
ATOMIC_ATTRIBUTION = "Atomic Red Team by Red Canary (https://github.com/redcanaryco/atomic-red-team), MIT licence: links only, never executed."
SIGMA_STATUS_RANK = {"stable": 0, "test": 1, "experimental": 2, "deprecated": 3, "unsupported": 4}
SIGMA_LEVEL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
SIGMA_MARKED = frozenset({"experimental", "deprecated", "unsupported"})
ATOMIC_HEADER = ("Tactic", "Technique #", "Technique Name", "Test #", "Test Name", "Test GUID", "Executor Name")
MAX_LISTED = 25
TERMINAL_LINKS = 5

_WS = re.compile(r"\s+")
_TAG = re.compile(r"<[^<>]{0,2000}>")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_T_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
_S_TAG = re.compile(r"^attack\.(s\d{4})$")
_G_TAG = re.compile(r"^attack\.(g\d{4})$")
_CVE_TAG = re.compile(r"^cve\.(\d{4})[-.](\d{4,7})$")
_TECH = re.compile(r"T\d{4}(?:\.\d{3})?")


def _s(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def clean_text(value: Any, max_len: int = 300) -> str:
    text = html.unescape(_s(value))
    text = _TAG.sub(" ", text)
    text = _CTRL.sub(" ", text)
    text = _WS.sub(" ", text).strip()
    if max_len and len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def fold_text(value: Any) -> str:
    text = unicodedata.normalize("NFKD", _s(value))
    return "".join(ch for ch in text if not unicodedata.combining(ch)).casefold()


def yaml_safe_load() -> Any:
    """``yaml.safe_load`` from the optional PyYAML extra, or None when it is not installed (FC1)."""
    try:
        import yaml
    except ImportError:
        return None
    return yaml.safe_load


# ------------------------------------------------------------------------------------------ Sigma (FC1/FC2/FC4)


def safe_zip_members(data: Any, caps: dict[str, int] | None = None) -> tuple[tuple[zipfile.ZipFile, list[zipfile.ZipInfo]] | None, str | None]:
    """In-memory archive check (never extracts): ((ZipFile, infos), None) or (None, reason). Refuses a
    non-zip, too many members, absolute/'..'/backslash/drive paths, symlinks, encrypted members, members or
    totals above the caps and compression ratios above max_ratio (zip bombs)."""
    lim = dict(SIGMA_ZIP_CAPS, **(caps or {}))
    if not isinstance(data, (bytes, bytearray)):
        return None, "archive is not bytes"
    try:
        zf = zipfile.ZipFile(io.BytesIO(bytes(data)))
        infos = zf.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError, EOFError) as exc:
        return None, f"not a valid zip archive ({type(exc).__name__})"
    if len(infos) > lim["max_members"]:
        return None, f"archive has {len(infos)} members (cap {lim['max_members']})"
    total = 0
    for info in infos:
        name = info.filename
        parts = name.split("/")
        if name.startswith(("/", "\\")) or "\\" in name or re.match(r"^[A-Za-z]:", name) or ".." in parts or "\x00" in name:
            return None, f"unsafe member path {name[:80]!r}"
        if ((info.external_attr >> 16) & 0o170000) == stat.S_IFLNK:
            return None, f"symlink member {name[:80]!r}"
        if info.flag_bits & 0x1:
            return None, f"encrypted member {name[:80]!r}"
        if info.file_size > lim["max_member_bytes"]:
            return None, f"member {name[:80]!r} is {info.file_size} bytes (cap {lim['max_member_bytes']})"
        if info.file_size and (info.compress_size == 0 or info.file_size / info.compress_size > lim["max_ratio"]):
            return None, f"member {name[:80]!r} compression ratio above {lim['max_ratio']}"
        total += info.file_size
        if total > lim["max_total_bytes"]:
            return None, f"archive expands beyond {lim['max_total_bytes']} bytes (cap)"
    return (zf, infos), None


def sigma_version_txt(text: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"release_date": None, "label": None, "commit": None}
    for line in _s(text).splitlines()[:20]:
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), clean_text(value, 80)
        if key == "release date":
            out["release_date"] = value or None
        elif key == "label":
            out["label"] = value or None
        elif key in ("commit-hash", "commit hash", "commit"):
            out["commit"] = value if re.fullmatch(r"[0-9a-f]{7,40}", value or "") else None
    return out


def sigma_rule_metadata(doc: Any, path: str = "") -> dict[str, Any] | None:
    """One parsed rule mapping -> metadata only (FC2), or None when it is not a rule."""
    if not isinstance(doc, dict):
        return None
    rid, title = clean_text(doc.get("id"), 64), clean_text(doc.get("title"), 256)
    if not rid or not title:
        return None
    tags: list[str] = []
    for tag in _list(doc.get("tags"))[:200]:
        tag = clean_text(tag, 80).lower()
        if tag and tag not in tags:
            tags.append(tag)
    techniques, tactics, software, groups, cves = [], [], [], [], []
    for tag in tags:
        if m := _T_TAG.match(tag):
            techniques.append(m.group(1).upper())
        elif m := _S_TAG.match(tag):
            software.append(m.group(1).upper())
        elif m := _G_TAG.match(tag):
            groups.append(m.group(1).upper())
        elif m := _CVE_TAG.match(tag):
            cves.append(f"CVE-{m.group(1)}-{m.group(2)}")
        elif re.fullmatch(r"attack\.[a-z][a-z-]{2,40}", tag):
            tactics.append(tag.split(".", 1)[1])  # FC4: read from the data, never hard-coded
    source = doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {}
    logsource = {k: clean_text(source.get(k), 80) for k in ("product", "category", "service") if clean_text(source.get(k), 80)}
    status = clean_text(doc.get("status"), 20).lower() or "unknown"
    return {"id": rid, "title": title, "status": status, "level": clean_text(doc.get("level"), 20).lower() or "unknown", "tags": tags,
            "attack_techniques": techniques, "attack_tactics": tactics, "attack_software": software, "attack_groups": groups, "cves": cves,
            "logsource": logsource, "path": _s(path)[:300], "author": clean_text(doc.get("author"), 300) or None,
            "date": clean_text(doc.get("date"), 10) or None, "modified": clean_text(doc.get("modified"), 10) or None,
            "marked": status in SIGMA_MARKED}


def sigma_sort_key(rule: dict[str, Any]) -> tuple[int, int, str]:
    """FC4: stable, test, then experimental/deprecated; critical first; title."""
    return (SIGMA_STATUS_RANK.get(rule.get("status"), 9), SIGMA_LEVEL_RANK.get(rule.get("level"), 9), _s(rule.get("title")).lower())


def sigma_index_zip(data: Any, safe_load: Any, caps: dict[str, int] | None = None) -> dict[str, Any]:
    """FC1/FC2/FC4: index sigma_core.zip in memory -> {status ok|error|unavailable, reason, version, count, rules,
    by_technique, by_cve, by_group, by_software, tactics, errors}. ``safe_load`` None -> unavailable (package)."""
    base: dict[str, Any] = {"version": None, "count": 0, "rules": {}, "by_technique": {}, "by_cve": {}, "by_group": {}, "by_software": {},
                            "tactics": [], "errors": []}
    if safe_load is None or not callable(safe_load):
        return dict(base, status="unavailable", reason="PyYAML (optional extra 'yaml') is not installed: Sigma index unavailable")
    opened, reason = safe_zip_members(data, caps)
    if reason:
        return dict(base, status="error", reason=reason)
    zf, infos = opened
    cap = dict(SIGMA_ZIP_CAPS, **(caps or {}))["max_member_bytes"]
    rules: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, str]] = []
    version = None
    for info in infos:
        if info.is_dir():
            continue
        name = info.filename
        try:
            with zf.open(info) as fh:
                raw = fh.read(cap + 1)
        except (zipfile.BadZipFile, OSError, ValueError, EOFError, RuntimeError) as exc:
            errors.append({"path": name, "error": type(exc).__name__})
            continue
        if len(raw) > cap:
            errors.append({"path": name, "error": "member larger than declared"})
            continue
        if name.rsplit("/", 1)[-1] == "version.txt":
            version = sigma_version_txt(raw.decode("utf-8", "replace"))
            continue
        if not name.endswith((".yml", ".yaml")):
            continue
        try:
            doc = safe_load(raw)
        except Exception as exc:  # noqa: BLE001 - yaml errors are not importable without the extra
            errors.append({"path": name, "error": type(exc).__name__})
            continue
        meta = sigma_rule_metadata(doc, name)
        if meta is None:
            errors.append({"path": name, "error": "not a rule mapping"})
            continue
        if meta["id"] in rules:
            errors.append({"path": name, "error": "duplicate rule id"})
            continue
        rules[meta["id"]] = meta
    keyed: dict[str, dict[str, list[str]]] = {"by_technique": {}, "by_cve": {}, "by_group": {}, "by_software": {}}
    tactics: set[str] = set()
    for rid, meta in rules.items():
        for key, field in (("by_technique", "attack_techniques"), ("by_cve", "cves"), ("by_group", "attack_groups"), ("by_software", "attack_software")):
            for value in meta[field]:
                keyed[key].setdefault(value, []).append(rid)
        tactics.update(meta["attack_tactics"])
    for table in keyed.values():
        for ids in table.values():
            ids.sort(key=lambda r: sigma_sort_key(rules[r]))
    if not rules:
        return dict(base, status="error", reason="no Sigma rules indexed", errors=errors, version=version)
    return dict(base, status="ok", reason=None, version=version, count=len(rules), rules=rules, tactics=sorted(tactics), errors=errors, **keyed)


def sigma_rules_for(index: dict[str, Any], *, technique: str = "", cve: str = "", groups: tuple[str, ...] = (), software: tuple[str, ...] = (),
                    title_terms: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Rules for a technique (a parent includes its sub-techniques), a CVE, ATT&CK group/software ids or
    title words (word boundaries, accent-folded), ordered by :func:`sigma_sort_key`."""
    if not isinstance(index, dict) or index.get("status") != "ok":
        return []
    rules = index["rules"]
    ids: list[str] = []
    if technique:
        t = technique.strip().upper()
        for key, values in index["by_technique"].items():
            if key == t or ("." not in t and key.startswith(t + ".")):
                ids.extend(values)
    if cve:
        ids.extend(index["by_cve"].get(cve.strip().upper(), []))
    for gid in groups:
        ids.extend(index["by_group"].get(gid, []))
    for sid in software:
        ids.extend(index["by_software"].get(sid, []))
    for term in title_terms:
        ft = fold_text(term)
        if len(ft) < 4:
            continue
        rx = re.compile(r"(?<![0-9a-z])" + re.escape(ft) + r"(?![0-9a-z])")
        ids.extend(rid for rid, meta in rules.items() if rx.search(fold_text(meta["title"])))
    seen: set[str] = set()
    out = []
    for rid in ids:
        if rid in rules and rid not in seen:
            seen.add(rid)
            out.append(rules[rid])
    out.sort(key=sigma_sort_key)
    return out


def sigma_rule_link(rule: dict[str, Any], ref: str = "master") -> str | None:
    return f"https://github.com/SigmaHQ/sigma/blob/{quote(ref or 'master', safe='')}/{quote(rule['path'])}" if rule.get("path") else None


def sigma_attribution(rule: dict[str, Any], ref: str = "master") -> str:
    """FC2: the DRL 1.1 credit line that must accompany any reproduced rule body."""
    return (f"Sigma rule '{rule.get('title') or 'untitled'}' by {rule.get('author') or 'the SigmaHQ contributors'}, licensed under the "
            f"Detection Rule License (DRL) 1.1 ({SIGMA_LICENCE_URL}); source: {sigma_rule_link(rule, ref) or 'https://github.com/SigmaHQ/sigma'}")


# ------------------------------------------------------------------------------------------ Atomic Red Team (FC3)


def atomic_parse_index(text: Any, max_rows: int = 50_000) -> dict[str, Any]:
    """index.csv (MIT) with the stdlib csv module -> {status, reason, by_technique {T: {technique, name, tests}},
    tactics, rows, bad_rows}; a test listed under several tactics is one test (GUID), tactics merged."""
    try:
        reader = csv.reader(io.StringIO(_s(text).lstrip("﻿")))
        header = next(reader)
    except (StopIteration, csv.Error):
        return {"status": "error", "reason": "empty or unreadable CSV", "by_technique": {}, "tactics": [], "rows": 0, "bad_rows": 0}
    if tuple(h.strip() for h in header) != ATOMIC_HEADER:
        return {"status": "error", "reason": "format changed: unexpected index.csv header " + ",".join(header)[:160], "by_technique": {},
                "tactics": [], "rows": 0, "bad_rows": 0}
    by_t: dict[str, dict[str, Any]] = {}
    tactics: set[str] = set()
    rows = bad = 0
    try:
        for row in reader:
            rows += 1
            if rows > max_rows:
                break
            if len(row) != 7:
                bad += 1
                continue
            tactic, tech, tname, num, name, guid, executor = (c.strip() for c in row)
            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tech) or not _GUID.fullmatch(guid) or not tactic:
                bad += 1
                continue
            tactics.add(tactic)
            entry = by_t.setdefault(tech, {"technique": tech, "name": clean_text(tname, 200), "tests": {}})
            test = entry["tests"].setdefault(guid.lower(), {"guid": guid.lower(), "number": num, "name": clean_text(name, 200),
                                                            "executor": clean_text(executor, 40), "tactics": []})
            if tactic not in test["tactics"]:
                test["tactics"].append(tactic)
    except csv.Error:
        bad += 1
    for entry in by_t.values():
        tests = list(entry["tests"].values())
        tests.sort(key=lambda x: (int(x["number"]) if x["number"].isdigit() else 10 ** 6, x["name"]))
        entry["tests"] = tests
    if not by_t:
        return {"status": "error", "reason": "no atomic tests parsed", "by_technique": {}, "tactics": sorted(tactics), "rows": rows, "bad_rows": bad}
    return {"status": "ok", "reason": None, "by_technique": by_t, "tactics": sorted(tactics), "rows": rows, "bad_rows": bad}


def atomic_test_link(technique: str) -> str:
    t = technique.strip().upper()
    return f"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{quote(t)}/{quote(t)}.md"


def atomic_tests_for(index: dict[str, Any], technique: str) -> list[dict[str, Any]]:
    """Atomic tests of a technique (a parent includes its sub-techniques); links only, never executed."""
    if not isinstance(index, dict) or index.get("status") != "ok":
        return []
    t = technique.strip().upper()
    out = []
    for key, entry in sorted(index["by_technique"].items()):
        if key == t or ("." not in t and key.startswith(t + ".")):
            out.extend(dict(test, technique=key, link=atomic_test_link(key)) for test in entry["tests"])
    return out


# ------------------------------------------------------------------------------------------ datasets


def _validate_sigma(path: Path) -> bool:
    _opened, reason = safe_zip_members(Path(path).read_bytes())
    if reason:
        raise ValueError(f"sigma_core.zip refused: {reason}")
    return True


def _validate_atomic(path: Path) -> bool:
    parsed = atomic_parse_index(Path(path).read_text(encoding="utf-8-sig", errors="replace"))
    if parsed["status"] != "ok":
        raise ValueError(parsed["reason"])
    return True


register_dataset(SIGMA_DATASET, SIGMA_URL, ttl=WEEKLY, description="SigmaHQ sigma_core.zip release asset (P373: metadata indexed locally, DRL 1.1)",
                 licence="DRL-1.1", terms_class="open", attribution=SIGMA_ATTRIBUTION, source=SIGMA_SOURCE, validate=_validate_sigma,
                 min_bytes=100, expect="bytes", max_bytes=4 * 1024 * 1024, large=False)
register_dataset(ATOMIC_DATASET, ATOMIC_URL, ttl=WEEKLY, description="Atomic Red Team Indexes-CSV/index.csv (P373: links only, never executed)",
                 licence="MIT", terms_class="open", attribution=ATOMIC_ATTRIBUTION, source=ATOMIC_SOURCE, validate=_validate_atomic,
                 min_bytes=256, expect="text", max_bytes=4 * 1024 * 1024, large=False)

_MEMO: dict[str, Any] = {}
_MEMO_LOCK = threading.Lock()


def _memo(name: str, sha: str, build: Any) -> Any:
    with _MEMO_LOCK:
        hit = _MEMO.get(name)
        if hit and hit[0] == sha:
            return hit[1]
    value = build()
    with _MEMO_LOCK:
        _MEMO[name] = (sha, value)
    return value


def name_ids(name: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """ATT&CK group (G) and software (S) ids of an actor/malware name through the P295 alias index."""
    try:
        from v3lum.modules.cti_framework.actor_alias_index import mitre_ids_for
        ids = mitre_ids_for(name)
    except Exception:  # noqa: BLE001 - the alias join is optional context
        return (), ()
    return tuple(i for i in ids if i.startswith("G")), tuple(i for i in ids if i.startswith("S"))


# ------------------------------------------------------------------------------------------ module


@register
class TechniqueDetectionsTests(Module):
    name = "technique_detections_tests"
    title = "Technique detections and tests (SigmaHQ, Atomic Red Team)"
    description = (
        "Offline detection and validation coverage of an ATT&CK technique, CVE, malware family or threat actor: SigmaHQ rule "
        "metadata (DRL 1.1, indexed locally from sigma_core.zip) and Atomic Red Team tests (MIT index), as counts and links."
    )
    category = "cti_framework"
    accepts = {T.MITRE, T.CVE, T.MALWARE, T.THREAT_ACTOR, T.KEYWORD}
    produces = frozenset()
    tags = {"offline", "free"}
    reference = "https://github.com/SigmaHQ/sigma"
    notice = (
        "Sigma rules: Detection Rule License 1.1 (metadata only, built locally, never bundled; optional PyYAML extra). Atomic Red "
        "Team: MIT, links only - V3LUM never executes a test."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    provider = ""
    sources = (SIGMA_SOURCE, ATOMIC_SOURCE)
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.1
    timeout = 90.0
    max_pivots = 0
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        value = clean_text(entity.value, 200)
        technique = value.upper() if entity.type is T.MITRE else ""
        if entity.type is T.KEYWORD and _TECH.fullmatch(value.upper()):
            technique = value.upper()
        sigma, sigma_problem = self._sigma(ctx)
        atomic, atomic_problem = self._atomic(ctx) if technique else (None, None)
        if sigma_problem:
            status, code, reason = sigma_problem
            res.source_status(SIGMA_SOURCE, status, reason_code=code, reason=reason)
        if atomic_problem:
            status, code, reason = atomic_problem
            res.source_status(ATOMIC_SOURCE, status, reason_code=code, reason=reason)
        if sigma is None and atomic is None:
            problem = sigma_problem or atomic_problem
            if technique and atomic_problem and sigma_problem and atomic_problem[0] is not Status.UNAVAILABLE:
                problem = atomic_problem
            status, code, reason = problem or (Status.ERROR, "error", "no index could be read")
            return res.mark(status.value, f"{reason}: could not verify", reason_code=code)
        groups, software = ((), ()) if technique or entity.type is T.CVE else name_ids(value)
        rules = sigma_rules_for(sigma, technique=technique, cve=value.upper() if entity.type is T.CVE else "", groups=groups, software=software,
                                title_terms=(value,) if entity.type in (T.MALWARE, T.THREAT_ACTOR, T.KEYWORD) and not technique else ())
        tests = atomic_tests_for(atomic, technique) if technique and atomic else []
        label = f"{len(rules)} Sigma rules / {len(tests)} atomic tests"
        if sigma is None:
            label = f"Sigma index unavailable / {len(tests)} atomic tests"
        if sigma is not None and sigma.get("version"):
            version = sigma["version"]
            res.attr("sigma_release", {k: v for k, v in {"release_date": version.get("release_date"), "label": version.get("label"),
                                                         "commit": version.get("commit"), "rules": sigma.get("count")}.items() if v})
        res.attr("detection_coverage", label)
        res.raw = {"query": value, "technique": technique or None, "sigma_rules": [r["id"] for r in rules[:MAX_LISTED]],
                   "atomic_tests": [t["guid"] for t in tests[:MAX_LISTED]], "attack_ids": list(groups + software)}
        if not rules and not tests:
            return res.mark("empty", f"{label} for {value}")
        if rules:
            res.attr("sigma_rules", [{k: v for k, v in {
                "id": r["id"], "title": r["title"], "status": r["status"], "level": r["level"], "logsource": r["logsource"],
                "link": sigma_rule_link(r), "marked": True if r["marked"] else None, "tactics": r["attack_tactics"]}.items() if v}
                for r in rules[:MAX_LISTED]])
            for rule in rules[:TERMINAL_LINKS]:
                link = sigma_rule_link(rule)
                if link:
                    res.link(f"Sigma ({rule['status']}/{rule['level']}): {clean_text(rule['title'], 100)}", link)
        if tests:
            res.attr("atomic_tests", [{k: v for k, v in t.items() if v} for t in tests[:MAX_LISTED]])
            res.link(f"Atomic Red Team tests for {technique} (links only, never executed)", atomic_test_link(technique))
        res.attr("data_attribution", " ".join(x for x in (SIGMA_ATTRIBUTION if rules else "", ATOMIC_ATTRIBUTION if tests else "") if x))
        return res

    # ---- indexes --------------------------------------------------------------------------------------
    @staticmethod
    def _fetch(ctx: Any, name: str) -> tuple[Path | None, Any, tuple[Status, str, str] | None]:
        try:
            path = ctx.data.fetch(name)
            return path, ctx.data.info(name), None
        except DatasetUnavailable as exc:
            return None, None, (Status.UNAVAILABLE, "dataset", str(exc)[:200])
        except DatasetError as exc:
            code = str(getattr(exc, "reason_code", "") or "error")
            if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
                return None, None, (Status.BLOCKED, code, str(exc)[:200])
            if code == "rate_limited":
                return None, None, (Status.RATE_LIMITED, "rate_limited", str(exc)[:200])
            return None, None, (Status.ERROR, "timeout" if code == "timeout" else "error", str(exc)[:200])

    def _sigma(self, ctx: Any) -> tuple[dict[str, Any] | None, tuple[Status, str, str] | None]:
        safe_load = yaml_safe_load()
        if safe_load is None:  # FC1: never parse YAML without yaml.safe_load
            return None, (Status.UNAVAILABLE, "package", "PyYAML (optional extra 'yaml') is not installed: Sigma index unavailable")
        path, info, problem = self._fetch(ctx, SIGMA_DATASET)
        if problem:
            return None, problem
        try:
            index = _memo(SIGMA_DATASET, info.sha256, lambda: sigma_index_zip(Path(path).read_bytes(), safe_load))
        except OSError as exc:
            return None, (Status.ERROR, "error", f"local sigma_core.zip unreadable ({str(exc)[:80]})")
        if index["status"] != "ok":
            return None, (Status.ERROR, "error", f"Sigma index: {index['reason']}")
        return index, None

    def _atomic(self, ctx: Any) -> tuple[dict[str, Any] | None, tuple[Status, str, str] | None]:
        path, info, problem = self._fetch(ctx, ATOMIC_DATASET)
        if problem:
            return None, problem
        try:
            index = _memo(ATOMIC_DATASET, info.sha256, lambda: atomic_parse_index(Path(path).read_text(encoding="utf-8-sig", errors="replace")))
        except OSError as exc:
            return None, (Status.ERROR, "error", f"local index.csv unreadable ({str(exc)[:80]})")
        if index["status"] != "ok":
            return None, (Status.ERROR, "error", f"Atomic index: {index['reason']}")
        return index, None
