"""ransomware_matrices: ransomware group -> tools and exploited CVEs (P372, batch p2-G11-1).

BushidoUK Ransomware Tool Matrix and Ransomware Vulnerability Matrix (CC BY 4.0), matched offline.
Final conditions (FC) of P372 and where they are met:

* **FC1 datasets.** Every matrix file is a registered dataset on raw.githubusercontent.com
  (``ransomware_matrices.rtm.*`` / ``ransomware_matrices.rvm.*``), refreshed weekly by the dataset manager
  with conditional GET; raw.githubusercontent.com answers a weak ETag that is the SHA-256 of the content and
  no commit or Last-Modified header, so copies are pinned by content hash and fetch time
  (``matrix_versions``; the commit date needs github.com: backlog). Matching is offline (disclosure 'none').
* **FC2 parsing.** The Tool Matrix group links live only in its ``Tools/*.md`` tables (``| Tool Name |
  Threat Group Usage |``); ``Tools/AllTools.csv`` gives the tool categories. Vulnerability tables must read
  ``| Product | CVE(s) | Ransomware Group(s) | Source(s) |``. Every table header is checked: an unexpected
  layout, no table or more skipped than parsed rows is 'format changed'. The dataset validator rejects such
  a download, so the dataset manager keeps serving the last good copy; the run reports the source ERROR
  'format changed ... last good index kept' (``res.source_status``) and, without any good copy, ends ERROR.
  Never a silently empty result.
* **FC3 alias join.** Group names (affiliate ``X*``, broker ``*X`` and state ``X+`` markers stripped,
  ``A (B)`` and ``A/B`` split into candidates) are joined through the P295 actor alias index
  (``actor_alias_index.resolve``); unresolved names are listed (``ransomware_groups_unresolved`` and the
  doctor self-test), never guessed.
* **FC4 dual use.** Tools are hunting leads tagged ``dual_use`` (INFO, never a malicious verdict): AnyDesk,
  Atera, ScreenConnect, Rclone are legitimate too. Optional exact-name join to LOLRMM (local copy of the
  ``lol_datasets`` dataset, never fetched here); the ATT&CK software join is in the batch backlog.
* **FC5 CVE cards.** 'reported exploited by ransomware groups X, Y' with the per-row source links,
  combined with CISA KEV knownRansomwareCampaignUse (the shared ``cisa_kev`` dataset and parser) into
  ``patch_priority`` highest / raised; a row without a group stays 'reported ... (no group named)'.
* **FC6 tier and attribution.** Content tier community (individual researcher, reviewer confirms; recorded
  in the source notes). Every card carries the CC BY 4.0 attribution (``data_attribution``). Fixtures:
  trimmed real Markdown/CSV files plus changed-layout files.
"""

from __future__ import annotations

import csv
import html
import io
import re
import threading
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, HealthResult, Module, register

RTM_SOURCE = "github.ransomware_matrices_rtm"
RVM_SOURCE = "github.ransomware_matrices_rvm"
KEV_SOURCE = "cisa.kev"
LOLRMM_SOURCE = "lolrmm.dataset"
RTM_BASE = "https://raw.githubusercontent.com/BushidoUK/Ransomware-Tool-Matrix/main/"
RVM_BASE = "https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/"
RTM_TOOL_FILES = ("RMM-Tools", "Exfiltration", "CredentialTheft", "DefenseEvasion", "Networking", "DiscoveryEnum", "Offsec", "LOLBAS")
RVM_FILES = ("NetworkEdge", "Microsoft", "Linux", "Applications", "Virtualization", "FileTransferServers", "RMM_Tools", "Drivers")
WEEKLY = 7 * 86400  # FC1
MAX_FILE_BYTES = 1024 * 1024
RVM_HEADER = ("Product", "CVE(s)", "Ransomware Group(s)", "Source(s)")
RTM_HEADER = ("Tool Name", "Threat Group Usage")
RTM_ALLTOOLS_COLUMNS = ("Discovery", "RMM Tools", "Defense Evasion", "Credential Theft", "OffSec", "Networking", "LOLBAS", "Exfiltration")
MATRIX_ATTRIBUTION = (
    "Ransomware Tool Matrix and Ransomware Vulnerability Matrix by BushidoUK, licensed CC BY 4.0 "
    "(https://creativecommons.org/licenses/by/4.0/); https://github.com/BushidoUK/Ransomware-Tool-Matrix ; "
    "https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix"
)
DUAL_USE_NOTE = "hunting lead: dual-use tool also used legitimately by IT; not a malicious verdict"
MAX_CVE_PIVOTS = 25
MAX_TOOL_LEADS = 60

_WS = re.compile(r"\s+")
_TAG = re.compile(r"<[^<>]{0,2000}>")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_RE_CVE = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,7}(?!\d)", re.I)
_SEP_ROW = re.compile(r"^\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)*\|?\s*$")
_MDLINK = re.compile(r"\[([^\]]{0,300})\]\((https?://[^)\s]{1,2000})\)")
_NO_GROUP = frozenset({"", "-", "n/a", "na", "none", "unknown", "?", "tbd"})
_REFANG = re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\[dot\]", re.I)


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


def refang(value: Any) -> str:
    return _REFANG.sub(".", _s(value))


def safe_http_url(value: Any) -> str | None:
    text = _s(value).strip().replace(" ", "%20")
    if not text or len(text) > 2048 or any(ch in text for ch in "\r\n\t\x00"):
        return None
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return None
    return text if parts.scheme.lower() in ("http", "https") and host else None


def _dedupe(seq: Any) -> list[Any]:
    seen: set[str] = set()
    out = []
    for item in seq:
        key = fold_text(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


# ------------------------------------------------------------------------------------------ parsing (FC2)


def _format_changed(where: str, detail: str) -> str:
    return f"format changed: {detail} ({where})"


def _md_cells(line: str) -> list[str]:
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]
    return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", text)]


def md_tables(text: Any) -> list[dict[str, Any]]:
    """Markdown pipe tables -> [{h2, section, header, rows: [(line_no, cells)], line}] ('h2' is the last
    '#'/'##' heading, 'section' the last '###'+ heading, backticks stripped; rows without a trailing pipe
    are accepted)."""
    lines = _s(text).splitlines()
    tables: list[dict[str, Any]] = []
    h2 = section = None
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        m = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if m:
            title = m.group(2).strip().strip("`").strip()
            if len(m.group(1)) <= 2:
                h2, section = title, None
            else:
                section = title
            i += 1
            continue
        if line.startswith("|") and i + 1 < len(lines) and _SEP_ROW.match(lines[i + 1].strip()):
            header = _md_cells(line)
            rows = []
            j = i + 2
            while j < len(lines) and lines[j].strip().startswith("|"):
                rows.append((j + 1, _md_cells(lines[j])))
                j += 1
            tables.append({"h2": h2, "section": section, "header": header, "rows": rows, "line": i + 1})
            i = j
            continue
        i += 1
    return tables


def parse_group_cell(cell: Any) -> list[dict[str, Any]]:
    """Group cell -> [{raw, name, role, candidates}]: 'X*' affiliate, '*X' initial access broker, 'X+'
    state-sponsored; 'A (B)' and 'A/B' give extra candidates for the alias join (FC3)."""
    out: dict[str, dict[str, Any]] = {}
    for raw in re.split(r"[,;]", _s(cell)):
        raw = clean_text(raw, 120)
        if fold_text(raw) in _NO_GROUP:
            continue
        name, role = raw, "ransomware"
        if name.startswith("*"):
            role, name = "initial_access_broker", name[1:].strip()
        if name.endswith("*"):
            role, name = "affiliate", name[:-1].strip()
        if name.endswith("+"):
            role, name = "state_sponsored", name[:-1].strip()
        m = re.match(r"^(.*?)\s*\(([^()]+)\)\s*$", name)
        if m and m.group(1).strip():
            primary, candidates = m.group(1).strip(), [m.group(1).strip(), m.group(2).strip()]
        else:
            primary, candidates = name, [name]
        if "/" in primary:
            candidates += [p.strip() for p in primary.split("/") if p.strip()]
        if primary and fold_text(primary) not in out:
            out[fold_text(primary)] = {"raw": raw, "name": primary, "role": role, "candidates": _dedupe(candidates)}
    return list(out.values())


def parse_sources_cell(cell: Any) -> list[dict[str, str]]:
    out = []
    for label, url in _MDLINK.findall(_s(cell)):
        link = safe_http_url(url)
        if link:
            out.append({"label": clean_text(label, 100), "url": link})
    return out


def parse_vuln_matrix(text: Any, source_file: str = "") -> dict[str, Any]:
    """One Vulnerability Matrix file -> {status ok|error, reason, rows, skipped}; any other header, no
    table, or more skipped than parsed rows is 'format changed'."""
    tables = md_tables(text)
    if not tables:
        return {"status": "error", "reason": _format_changed(source_file, "no Markdown table"), "rows": [], "skipped": []}
    rows: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for table in tables:
        header = tuple(c.strip() for c in table["header"])
        if header != RVM_HEADER:
            return {"status": "error", "rows": [], "skipped": [], "reason": _format_changed(
                f"{source_file} line {table['line']}", "unexpected table header " + "|".join(header)[:120])}
        for lineno, cells in table["rows"]:
            if len(cells) != 4:
                skipped.append({"line": lineno, "why": f"expected 4 cells, got {len(cells)}"})
                continue
            product, cve_cell, group_cell, src_cell = cells
            cves = _dedupe(m.upper() for m in _RE_CVE.findall(cve_cell))
            if not cves:
                skipped.append({"line": lineno, "why": "no CVE id"})
                continue
            nick = re.findall(r"\(\s*\"([^\"]{1,60})\"\s*\)", cve_cell)
            rows.append({"file": source_file, "category": table["h2"], "vendor": table["section"], "product": clean_text(product, 200),
                         "cves": cves, "nickname": nick[0] if nick else None, "groups": parse_group_cell(group_cell),
                         "sources": parse_sources_cell(src_cell), "line": lineno})
    if not rows or len(skipped) > len(rows):
        return {"status": "error", "rows": [], "skipped": skipped,
                "reason": _format_changed(source_file, f"{len(rows)} rows parsed, {len(skipped)} skipped")}
    return {"status": "ok", "reason": None, "rows": rows, "skipped": skipped}


def parse_tool_matrix_md(text: Any, source_file: str = "") -> dict[str, Any]:
    """Tool Matrix ``Tools/<Category>.md`` -> {status, reason, category, tools, skipped} (header checked)."""
    tables = md_tables(text)
    if not tables:
        return {"status": "error", "reason": _format_changed(source_file, "no Markdown table"), "category": None, "tools": [], "skipped": []}
    tools: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for table in tables:
        header = tuple(c.strip() for c in table["header"])
        if header != RTM_HEADER:
            return {"status": "error", "category": table["h2"], "tools": [], "skipped": [], "reason": _format_changed(
                f"{source_file} line {table['line']}", "unexpected table header " + "|".join(header)[:120])}
        for lineno, cells in table["rows"]:
            tool = clean_text(cells[0], 120) if cells else ""
            if len(cells) != 2 or not tool:
                skipped.append({"line": lineno, "why": "expected 2 cells"})
                continue
            tools.append({"tool": tool, "tool_key": fold_text(refang(tool)), "category": table["h2"],
                          "groups": parse_group_cell(cells[1]), "file": source_file, "line": lineno})
    if not tools or len(skipped) > len(tools):
        return {"status": "error", "category": tables[0]["h2"], "tools": [], "skipped": skipped,
                "reason": _format_changed(source_file, f"{len(tools)} tools parsed, {len(skipped)} skipped")}
    return {"status": "ok", "reason": None, "category": tables[0]["h2"], "tools": tools, "skipped": skipped}


def parse_alltools_csv(text: Any) -> dict[str, Any]:
    """``Tools/AllTools.csv`` (one column per tool category, ragged) -> {status, reason, tools {key: {tool,
    categories}}}; the header must equal RTM_ALLTOOLS_COLUMNS."""
    try:
        rows = list(csv.reader(io.StringIO(_s(text).lstrip("﻿"))))
    except csv.Error as exc:
        return {"status": "error", "reason": _format_changed("AllTools.csv", f"CSV error {str(exc)[:60]}"), "tools": {}}
    if not rows:
        return {"status": "error", "reason": _format_changed("AllTools.csv", "empty file"), "tools": {}}
    header = tuple(c.strip() for c in rows[0])
    if header != RTM_ALLTOOLS_COLUMNS:
        return {"status": "error", "reason": _format_changed("AllTools.csv", "unexpected header " + ",".join(header)[:120]), "tools": {}}
    tools: dict[str, dict[str, Any]] = {}
    for row in rows[1:]:
        for column, value in zip(header, row, strict=False):  # ragged columns of unequal length
            value = clean_text(value, 120)
            if value:
                rec = tools.setdefault(fold_text(refang(value)), {"tool": value, "categories": []})
                if column not in rec["categories"]:
                    rec["categories"].append(column)
    if not tools:
        return {"status": "error", "reason": _format_changed("AllTools.csv", "no tool rows"), "tools": {}}
    return {"status": "ok", "reason": None, "tools": tools}


def build_cve_index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """FC5: CVE -> {cve, groups, roles, products, vendors, nicknames, sources, status 'reported', label}."""
    idx: dict[str, dict[str, Any]] = {}
    for row in rows:
        for cve in row.get("cves") or []:
            rec = idx.setdefault(cve, {"cve": cve, "groups": [], "roles": {}, "products": [], "vendors": [], "nicknames": [], "sources": [],
                                       "status": "reported"})
            for group in row.get("groups") or []:
                if group["name"] not in rec["groups"]:
                    rec["groups"].append(group["name"])
                    rec["roles"][group["name"]] = group["role"]
            for key, val in (("products", row.get("product")), ("vendors", row.get("vendor")), ("nicknames", row.get("nickname"))):
                if val and val not in rec[key]:
                    rec[key].append(val)
            for src in row.get("sources") or []:
                if src["url"] not in [x["url"] for x in rec["sources"]]:
                    rec["sources"].append(src)
    for rec in idx.values():
        rec["label"] = ("reported exploited by ransomware groups " + ", ".join(rec["groups"]) if rec["groups"]
                        else "reported exploited by ransomware (no group named in the source row)")
    return idx


def build_group_index(vuln_rows: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Folded raw group name -> {name, roles, candidates, cves [{cve, product, sources}], tools [{tool, category}]}."""
    idx: dict[str, dict[str, Any]] = {}

    def rec(group: dict[str, Any]) -> dict[str, Any]:
        entry = idx.setdefault(fold_text(group["name"]), {"name": group["name"], "roles": [], "candidates": list(group["candidates"]),
                                                          "cves": [], "tools": []})
        if group["role"] not in entry["roles"]:
            entry["roles"].append(group["role"])
        return entry

    for row in vuln_rows:
        for group in row.get("groups") or []:
            entry = rec(group)
            for cve in row["cves"]:
                if cve not in [c["cve"] for c in entry["cves"]]:
                    entry["cves"].append({"cve": cve, "product": row.get("product"), "sources": row.get("sources") or []})
    for tool in tools:
        for group in tool.get("groups") or []:
            entry = rec(group)
            if tool["tool"] not in [t["tool"] for t in entry["tools"]]:
                entry["tools"].append({"tool": tool["tool"], "category": tool.get("category")})
    return idx


def build_tool_index(tools: list[dict[str, Any]], alltools: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Folded refanged tool name -> {tool, categories, groups}."""
    idx: dict[str, dict[str, Any]] = {}
    for tool in tools:
        rec = idx.setdefault(tool["tool_key"], {"tool": tool["tool"], "categories": [], "groups": []})
        if tool.get("category") and tool["category"] not in rec["categories"]:
            rec["categories"].append(tool["category"])
        for group in tool.get("groups") or []:
            if group["name"] not in rec["groups"]:
                rec["groups"].append(group["name"])
    for key, entry in ((alltools or {}).get("tools") or {}).items():
        rec = idx.setdefault(key, {"tool": entry["tool"], "categories": [], "groups": []})
        for cat in entry.get("categories") or []:
            if cat not in rec["categories"]:
                rec["categories"].append(cat)
    return idx


def ransomware_cve_card(cve: str, cve_index: dict[str, Any], kev_entry: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """FC5 card: matrix label + per-row sources + KEV knownRansomwareCampaignUse -> patch_priority
    'highest' (groups named and KEV Known), 'raised' (either), 'normal' (a row naming no group, KEV not
    Known). None when the matrix does not list the CVE and KEV does not say Known."""
    row = cve_index.get(cve)
    kev_use = (kev_entry or {}).get("ransomware_use")
    kev_known = bool((kev_entry or {}).get("ransomware_known"))
    if row is None and not kev_known:
        return None
    signals = int(bool(row and row["groups"])) + int(kev_known)
    priority = "highest" if signals == 2 else ("raised" if signals == 1 else "normal")
    return {"cve": cve, "label": row["label"] if row else "CISA KEV: known ransomware campaign use (not in the ransomware matrix)",
            "status": "reported" if row else None, "groups": list(row["groups"]) if row else [], "sources": list(row["sources"]) if row else [],
            "products": list(row["products"]) if row else [], "kev_known_ransomware_use": kev_use, "patch_priority": priority,
            "attribution": MATRIX_ATTRIBUTION if row else None}


# ------------------------------------------------------------------------------------------ alias join (FC3)


def canonical_group(names: list[str]) -> str | None:
    """P295 canonical name of a group (first candidate that resolves unambiguously, actor namespace first);
    None when the alias index cannot resolve it (listed, never guessed)."""
    try:
        from v3lum.modules.cti_framework.actor_alias_index import namespace_cards, resolve
    except ImportError:  # pragma: no cover - P295 ships with the tree
        return None
    for name in names:
        res = resolve(name)
        if not res:
            continue
        for ns in ("actor", "malware"):
            cards = namespace_cards(res, ns)
            if len(cards) == 1:
                return str(cards[0]["canonical"])
    return None


# ------------------------------------------------------------------------------------------ datasets (FC1)

_REJECTED: dict[str, str] = {}
_REJECT_LOCK = threading.Lock()


def _validator(name: str, kind: str, label: str) -> Any:
    def check(path: Path) -> bool:
        text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
        if kind == "rvm":
            parsed = parse_vuln_matrix(text, label)
        elif kind == "rtm":
            parsed = parse_tool_matrix_md(text, label)
        else:
            parsed = parse_alltools_csv(text)
        if parsed["status"] != "ok":
            with _REJECT_LOCK:
                _REJECTED[name] = parsed["reason"]
            raise ValueError(parsed["reason"])
        with _REJECT_LOCK:
            _REJECTED.pop(name, None)
        return True
    return check


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


DATASETS_RTM: dict[str, str] = {}
DATASETS_RVM: dict[str, str] = {}
DATASET_ALLTOOLS = "ransomware_matrices.rtm.alltools"
for _f in RTM_TOOL_FILES:
    _name = f"ransomware_matrices.rtm.{_slug(_f)}"
    DATASETS_RTM[_name] = f"Tools/{_f}.md"
    register_dataset(_name, f"{RTM_BASE}Tools/{_f}.md", ttl=WEEKLY, description=f"BushidoUK Ransomware Tool Matrix Tools/{_f}.md (P372)",
                     licence="CC-BY-4.0", terms_class="open", attribution=MATRIX_ATTRIBUTION, source=RTM_SOURCE,
                     validate=_validator(_name, "rtm", f"Tools/{_f}.md"), min_bytes=64, expect="text", max_bytes=MAX_FILE_BYTES, large=False)
register_dataset(DATASET_ALLTOOLS, f"{RTM_BASE}Tools/AllTools.csv", ttl=WEEKLY, description="BushidoUK Ransomware Tool Matrix Tools/AllTools.csv (P372)",
                 licence="CC-BY-4.0", terms_class="open", attribution=MATRIX_ATTRIBUTION, source=RTM_SOURCE,
                 validate=_validator(DATASET_ALLTOOLS, "csv", "Tools/AllTools.csv"), min_bytes=64, expect="text", max_bytes=MAX_FILE_BYTES, large=False)
for _f in RVM_FILES:
    _name = f"ransomware_matrices.rvm.{_slug(_f)}"
    DATASETS_RVM[_name] = f"Vulnerabilities/{_f}.md"
    register_dataset(_name, f"{RVM_BASE}Vulnerabilities/{_f}.md", ttl=WEEKLY,
                     description=f"BushidoUK Ransomware Vulnerability Matrix Vulnerabilities/{_f}.md (P372)",
                     licence="CC-BY-4.0", terms_class="open", attribution=MATRIX_ATTRIBUTION, source=RVM_SOURCE,
                     validate=_validator(_name, "rvm", f"Vulnerabilities/{_f}.md"), min_bytes=64, expect="text", max_bytes=MAX_FILE_BYTES, large=False)

_MEMO: dict[str, Any] = {"key": None, "index": None}
_MEMO_LOCK = threading.Lock()


def build_index(files: dict[str, tuple[str, str]]) -> dict[str, Any]:
    """{dataset name: (kind, text)} -> {vuln_rows, tools, alltools, cve_index, group_index, tool_index, problems}."""
    vuln_rows: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    alltools: dict[str, Any] | None = None
    problems: dict[str, str] = {}
    for name, (kind, text) in sorted(files.items()):
        label = DATASETS_RTM.get(name) or DATASETS_RVM.get(name) or "Tools/AllTools.csv"
        if kind == "rvm":
            parsed = parse_vuln_matrix(text, label)
            vuln_rows += parsed["rows"]
        elif kind == "rtm":
            parsed = parse_tool_matrix_md(text, label)
            tools += parsed["tools"]
        else:
            parsed = parse_alltools_csv(text)
            alltools = parsed if parsed["status"] == "ok" else None
        if parsed["status"] != "ok":
            problems[name] = parsed["reason"]
    groups = build_group_index(vuln_rows, tools)
    for entry in groups.values():
        entry["canonical"] = canonical_group(entry["candidates"])
    return {"vuln_rows": vuln_rows, "tools": tools, "cve_index": build_cve_index(vuln_rows), "group_index": groups,
            "tool_index": build_tool_index(tools, alltools), "problems": problems}


def unresolved_groups(index: dict[str, Any]) -> list[str]:
    """FC3 doctor list: matrix group names the alias index could not resolve."""
    return sorted(e["name"] for e in index["group_index"].values() if not e.get("canonical"))


def _matching_groups(index: dict[str, Any], value: str) -> list[dict[str, Any]]:
    fv = fold_text(value)
    canon = canonical_group([value])
    hits = []
    for key, entry in index["group_index"].items():
        names = {key} | {fold_text(c) for c in entry["candidates"]}
        if fv in names or (canon and entry.get("canonical") and fold_text(entry["canonical"]) == fold_text(canon)):
            hits.append(entry)
    return hits


def _lolrmm_names(ctx: Any) -> dict[str, dict[str, Any]]:
    """Optional FC4 join: LOLRMM tool names from the local lol_datasets copy (never fetched here)."""
    try:
        from v3lum.modules.malware_hash.lol_datasets import DS_LOLRMM, load_index, local_copy
        path, _info = local_copy(ctx, DS_LOLRMM)
        if path is None:
            return {}
        index = load_index(DS_LOLRMM, path)
    except Exception:  # noqa: BLE001 - an optional join never breaks the run
        return {}
    out = {}
    for name, numbers in (index.get("tool_names") or {}).items():
        if numbers:
            out[fold_text(name)] = index["tools"][numbers[0]]
    return out


def _matrix_selftest(ctx: Any) -> HealthResult:
    """doctor: local copies present; unresolved group names counted (FC3)."""
    files, missing = {}, []
    for name, kind in [(n, "rtm") for n in DATASETS_RTM] + [(DATASET_ALLTOOLS, "csv")] + [(n, "rvm") for n in DATASETS_RVM]:
        info = ctx.data.info(name)
        if not info.present:
            missing.append(name)
            continue
        files[name] = (kind, ctx.data.store.path(name).read_text(encoding="utf-8-sig", errors="replace"))
    if not files:
        return HealthResult("dead", "ransomware matrices not downloaded: run v3lum data update")
    index = build_index(files)
    unresolved = unresolved_groups(index)
    detail = f"{len(index['cve_index'])} CVEs, {len(index['group_index'])} groups ({len(unresolved)} unresolved by the alias index)"
    if missing:
        detail += f"; {len(missing)} file(s) not downloaded"
    return HealthResult("ok", detail)


# ------------------------------------------------------------------------------------------ module


@register
class RansomwareMatrices(Module):
    name = "ransomware_matrices"
    title = "Ransomware group tools and exploited CVEs (BushidoUK matrices)"
    description = (
        "Offline lookup in the BushidoUK Ransomware Tool Matrix and Vulnerability Matrix (CC BY 4.0): tools a ransomware "
        "group was reported to use (dual-use hunting leads), CVEs it was reported to exploit, and for a CVE the groups that "
        "exploited it combined with CISA KEV known ransomware use into a patch priority."
    )
    category = "cti_framework"
    accepts = {T.THREAT_ACTOR, T.MALWARE, T.CVE, T.KEYWORD}
    produces = {T.CVE}
    tags = {"offline", "free"}
    reference = "https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix"
    notice = (
        "BushidoUK matrices, CC BY 4.0 (attribution on every card). Tools such as AnyDesk, Atera, ScreenConnect or Rclone "
        "are legitimate software too: hunting leads, never malicious verdicts. 'Reported exploited' comes from OSINT reports."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    provider = ""
    sources = (RTM_SOURCE, RVM_SOURCE, KEV_SOURCE, LOLRMM_SOURCE)
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.05
    timeout = 90.0
    max_pivots = MAX_CVE_PIVOTS
    default_enabled = True

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_matrix_selftest)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        index, versions, failures = self._load(ctx, res)
        if index is None:
            blocked = [f for f in failures if f[1] in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host")]
            if failures and len(blocked) == len(failures):
                return res.mark("blocked", "ransomware matrices could not be downloaded (blocked): could not verify", reason_code=blocked[0][1])
            if failures and all(f[1] == "dataset" for f in failures):
                return res.mark("unavailable", "ransomware matrices not downloaded: run v3lum data update", reason_code="dataset")
            detail = "; ".join(f[2] for f in failures[:3]) or "no matrix file could be read"
            return res.mark("error", f"ransomware matrices unusable ({detail[:300]}): could not verify")
        res.attr("matrix_versions", versions)
        res.attr("data_attribution", MATRIX_ATTRIBUTION)
        if entity.type is T.CVE:
            return self._cve(entity, ctx, res, index)
        return self._group_or_tool(entity, ctx, res, index)

    # ---- data -----------------------------------------------------------------------------------------
    def _load(self, ctx: Any, res: ModuleResult) -> tuple[dict[str, Any] | None, dict[str, Any], list[tuple[str, str, str]]]:
        files: dict[str, tuple[str, str]] = {}
        versions: dict[str, Any] = {}
        failures: list[tuple[str, str, str]] = []
        changed: dict[str, list[str]] = {RTM_SOURCE: [], RVM_SOURCE: []}
        plan = [(n, "rtm", RTM_SOURCE) for n in DATASETS_RTM] + [(DATASET_ALLTOOLS, "csv", RTM_SOURCE)] + [(n, "rvm", RVM_SOURCE) for n in DATASETS_RVM]
        for name, kind, source in plan:
            try:
                path = ctx.data.fetch(name)
                info = ctx.data.info(name)
                files[name] = (kind, Path(path).read_text(encoding="utf-8-sig", errors="replace"))
            except DatasetUnavailable as exc:
                failures.append((name, "dataset", str(exc)[:200]))
                continue
            except DatasetError as exc:
                failures.append((name, str(getattr(exc, "reason_code", "") or "error"), str(exc)[:200]))
                changed[source].append(f"{name}: {str(exc)[:160]}")
                continue
            except OSError as exc:
                failures.append((name, "error", f"{name} unreadable: {str(exc)[:80]}"))
                continue
            versions[name.split(".", 1)[1]] = {"sha256": info.sha256[:16], "fetched_at": info.fetched_at, "stale": bool(info.stale)}
            with _REJECT_LOCK:
                rejected = _REJECTED.get(name)
            if rejected and info.stale:
                changed[source].append(f"{name}: {rejected} - last good index kept")
        for source, notes in changed.items():
            if notes:
                res.source_status(source, Status.ERROR, reason_code="error", reason="; ".join(notes)[:500])
        if not files:
            return None, versions, failures
        key = tuple(sorted((n, len(t), hash(t)) for n, (_k, t) in files.items()))
        with _MEMO_LOCK:
            if _MEMO["key"] == key:
                return _MEMO["index"], versions, failures
        index = build_index(files)
        with _MEMO_LOCK:
            _MEMO["key"], _MEMO["index"] = key, index
        return index, versions, failures

    def _kev_entry(self, ctx: Any, cve: str) -> tuple[dict[str, Any] | None, str | None]:
        """KEV fact for the CVE from the shared cisa_kev dataset and parser (no second parser)."""
        try:
            from v3lum.modules.vulnerability_cve.cisa_kev import KEV_DATASET, load_kev_catalog
            path = ctx.data.fetch(KEV_DATASET)
            catalog = load_kev_catalog(path)
        except (DatasetError, OSError, ValueError, ImportError) as exc:
            return None, f"CISA KEV unavailable ({str(exc)[:100]})"
        return catalog["entries"].get(cve), None

    # ---- CVE cards (FC5) -------------------------------------------------------------------------------
    def _cve(self, entity: Entity, ctx: Any, res: ModuleResult, index: dict[str, Any]) -> ModuleResult:
        cve = entity.value.upper()
        kev, kev_problem = self._kev_entry(ctx, cve)
        if kev_problem:
            res.source_status(KEV_SOURCE, Status.UNAVAILABLE, reason_code="dataset", reason=kev_problem)
        card = ransomware_cve_card(cve, index["cve_index"], kev)
        if card is None:
            return res.mark("empty", f"{cve} is not listed in the ransomware vulnerability matrix (a reported-exploitation list, not exhaustive)")
        groups = card["groups"]
        resolved = {g: index["group_index"].get(fold_text(g), {}).get("canonical") for g in groups}
        card["unresolved_groups"] = sorted(g for g, c in resolved.items() if not c)
        res.attr("ransomware_cve_card", {k: v for k, v in card.items() if v not in (None, [], "")})
        res.attr("patch_priority", card["patch_priority"])
        if card["unresolved_groups"]:
            res.attr("ransomware_groups_unresolved", card["unresolved_groups"])
        severity = {"highest": "medium", "raised": "low"}.get(card["patch_priority"], "info")
        res.finding(
            "Reported exploited by ransomware",
            severity,
            f"{card['label']}. Patch priority {card['patch_priority']} (KEV knownRansomwareCampaignUse: "
            f"{card['kev_known_ransomware_use'] or 'not in KEV'}). {MATRIX_ATTRIBUTION}",
            confidence="probable" if groups else "possible",
            criterion=("BushidoUK Ransomware Vulnerability Matrix row naming ransomware groups (OSINT reports) combined with CISA KEV "
                       "knownRansomwareCampaignUse: raises patch priority, not proof of compromise") if severity != "info" else "",
            tags=["ransomware", "kev"] if card["kev_known_ransomware_use"] == "Known" else ["ransomware"],
            references=[s["url"] for s in card["sources"][:10]],
            source=RVM_SOURCE if card["status"] else KEV_SOURCE,
            data={"groups": groups, "patch_priority": card["patch_priority"], "status": card["status"]},
        )
        for src in card["sources"][:5]:
            res.link(f"Ransomware exploitation source: {src['label']}", src["url"])
        res.raw = {"cve": cve, "card": card}
        return res

    # ---- actor / family / tool cards (FC3/FC4) ----------------------------------------------------------
    def _group_or_tool(self, entity: Entity, ctx: Any, res: ModuleResult, index: dict[str, Any]) -> ModuleResult:
        value = clean_text(entity.value, 200)
        groups = _matching_groups(index, value)
        tool = index["tool_index"].get(fold_text(refang(value))) if entity.type is T.KEYWORD else None
        if not groups and not tool:
            return res.mark("empty", f"'{value}' is not a group or tool of the ransomware matrices (names joined through the actor alias index)")
        lolrmm = _lolrmm_names(ctx)
        if groups:
            leads: list[dict[str, Any]] = []
            cves: list[dict[str, Any]] = []
            for group in groups:
                for item in group["tools"]:
                    if item["tool"] not in [lead["tool"] for lead in leads]:
                        lead = {"tool": item["tool"], "category": item.get("category"), "note": DUAL_USE_NOTE}
                        match = lolrmm.get(fold_text(refang(item["tool"])))
                        if match:
                            lead["lolrmm"] = match.get("name")
                        leads.append(lead)
                for item in group["cves"]:
                    if item["cve"] not in [c["cve"] for c in cves]:
                        cves.append(item)
            names = sorted({g["name"] for g in groups})
            unresolved = sorted(g["name"] for g in groups if not g.get("canonical"))
            if unresolved:
                res.attr("ransomware_groups_unresolved", unresolved)
            res.attr("ransomware_group", names[0] if len(names) == 1 else names)
            res.attr("ransomware_tool_leads", leads[:MAX_TOOL_LEADS])
            res.attr("ransomware_exploited_cves", [{"cve": c["cve"], "product": c.get("product"), "sources": c.get("sources")[:5]} for c in cves])
            for item in cves[:MAX_CVE_PIVOTS]:
                res.pivot(T.CVE, item["cve"], "exploits", confidence="possible", expand=False,
                          note="reported exploited by this ransomware group (BushidoUK Vulnerability Matrix, OSINT reports)")
            if leads:
                res.finding(
                    "Tools reported in this ransomware group's intrusions (hunting leads)",
                    "info",
                    f"{len(leads)} tool(s) seen in intrusions attributed to {', '.join(names)}: "
                    f"{', '.join(lead['tool'] for lead in leads[:15])}. {DUAL_USE_NOTE}. {MATRIX_ATTRIBUTION}",
                    confidence="possible",
                    tags=["dual_use", "ransomware", "context_only"],
                    source=RTM_SOURCE,
                    data={"groups": names, "tools": len(leads)},
                )
            res.raw = {"groups": names, "tools": len(leads), "cves": [c["cve"] for c in cves]}
        if tool:
            lead = {"tool": tool["tool"], "categories": tool["categories"], "groups": tool["groups"], "note": DUAL_USE_NOTE}
            match = lolrmm.get(fold_text(refang(tool["tool"])))
            if match:
                lead["lolrmm"] = match.get("name")
                if match.get("link"):
                    res.link(f"LOLRMM: {match.get('name')}", match["link"])
            res.attr("ransomware_tool_leads", [lead])
            res.finding(
                "Dual-use tool reported in ransomware intrusions (hunting lead)",
                "info",
                f"{tool['tool']} ({', '.join(tool['categories']) or 'uncategorised'}) was reported in intrusions by "
                f"{len(tool['groups'])} ransomware group(s): {', '.join(tool['groups'][:15])}. {DUAL_USE_NOTE}. {MATRIX_ATTRIBUTION}",
                confidence="possible",
                tags=["dual_use", "ransomware", "context_only"],
                source=RTM_SOURCE,
                key="tool",
                data={"tool": tool["tool"], "groups": len(tool["groups"])},
            )
            res.raw = dict(res.raw or {}, tool=tool["tool"])
        return res
