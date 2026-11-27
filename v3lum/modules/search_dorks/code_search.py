"""code_search: mentions of a seed in public code - Sourcegraph stream API, GitHub and GitLab code search (P305, batch p2-G14-3).

Sources (cond 1, all trusted tier):

* ``sourcegraph.public_stream_search`` - ``sourcegraph.com/.api/search/stream`` (text/event-stream), keyless with an
  optional token ('Authorization: token <t>'). Terms 'open': ToS s.3.1 grants internal business use (evidence in
  the provider registry, cond 2); bounded use only (AUP: no bulk activity).
* ``github.code_search`` - ``api.github.com/search/code`` with the team token (no scopes, public data, 10 requests a
  minute, <= 1000 results a query); ``gitlab.blob_search`` - ``gitlab.com/api/v4/search?scope=blobs`` with a token
  (global blob search needs GitLab Premium/Ultimate with advanced or exact code search: a refusal is reported, never
  read as 'no mentions'). Both 'key-terms' (cond 2: business plans recorded in key_plans). API only: github.com/search
  is never scraped. **Merge gate (cond 10)**: these two parts run only with setting ``code_search_keyed_sources``
  until trimmed real fixtures captured with the team tokens are added; their parsers are tested on doc-shaped
  fixtures (docs/backlog/p2-G14-3.md).

Scope (cond 3-5): analyst-typed seeds and org_profile assets only (never every pivot); one exact quoted query per
provider by default (Sourcegraph keyless, GitHub/GitLab when enabled and keyed), <= 3 queries per entity inside a 20 s
budget. The full dork pack (ideas from github-dorks, Apache-2.0, re-implemented with attribution) runs only with
``code_search_full_pack`` or for org_profile own domains (<= 10 queries, 45 s). Secret-pattern dorks ('password',
'apikey', private-key headers) are combined only with verified org-owned identifiers or inside an --authorized
engagement; other entities get plain mention searches. Usernames and e-mail addresses are searched only on explicit
selection (-M code_search / v3lum run) for org_profile addresses/accounts or in a case with a recorded purpose.

Secrets (cond 6, rule 1, A7): matched fragments pass the P312 scanner (``v3lum.core.sanitize.find_secrets``) in memory;
only the rule id, repo, path, line, commit and a keyed hash for dedup (installation HMAC) are kept - never the
fragment or the secret. Raw search bodies are never cached (ttl 0) or written to evidence; repositories are never
cloned or walked; secrets are never validated, tested or reused.

Provenance (cond 7): hits in public IOC/blocklist repositories are tagged 'listed in public IOC repo' (context only,
never a malicious vote, P171); repositories of the org's own accounts (setting ``code_search_org_accounts``) are
'own repo'; anything else reads 'third-party repo mentions our asset' without showing the secret.

Limits (cond 8): tokens from ``v3lum keys`` in headers only (AR01); GitHub budgeted as a minute window of 8 (80% of 10)
in module state until the P334 quota block gains a minute window; GitHub 403 secondary limits and 429 are RATE_LIMITED
(could not verify); the Sourcegraph stream is read with max_bytes 2 MB and a 30 s deadline. Output (cond 9):
deduplicated per repository, top 10 as repo/path/line links; severity INFO unless a P312 rule matches (then HIGH with
the secret masked).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote, quote_plus

from v3lum.config import SettingSpec
from v3lum.core import hmacid
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.sanitize import find_secrets

SOURCE_SG = "sourcegraph.public_stream_search"
SOURCE_GH = "github.code_search"
SOURCE_GL = "gitlab.blob_search"
SG_STREAM = "https://sourcegraph.com/.api/search/stream"
GH_SEARCH = "https://api.github.com/search/code"
GL_SEARCH = "https://gitlab.com/api/v4/search"
GH_ACCEPT = "application/vnd.github.text-match+json"
SSE_MAX_BYTES = 2_000_000  # cond 8
SSE_DEADLINE_S = 30.0  # cond 8
DEFAULT_BUDGET_S = 20.0  # cond 3
FULL_PACK_BUDGET_S = 45.0
DEFAULT_QUERY_CAP = 3  # cond 3
FULL_PACK_QUERY_CAP = 10  # cond 3 + one GitHub minute window
GITHUB_MINUTE_BUDGET = 8  # 80% of the 10 code-search requests a minute (cond 8)
TOP_REPOS = 10  # cond 9
MAX_HOSTNAMES = 50
#: Documented example credentials (AWS docs...) that are never reported as secrets.
EXAMPLE_VALUES = frozenset({"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
#: Distinctive P312 kinds (a format, not a label): a match is 'probable'; label-classified assignments are 'possible'.
LABEL_KINDS = frozenset({"password", "secret", "assignment"})
#: V3LUM-owned code dorks (ideas from github-dorks by techgaun, Apache-2.0, re-implemented; notice
#: v3lum/data/notices/github_dorks_ideas.json). ``sensitive`` rows run only with verified org-owned identifiers or
#: inside an --authorized engagement (cond 4).
CODE_DORKS: tuple[dict[str, Any], ...] = (
    {"id": "env_file", "sensitive": False, "sourcegraph": r"file:\.env$", "github": "filename:.env", "gitlab": "filename:*.env"},
    {"id": "config_yaml", "sensitive": False, "sourcegraph": r"file:\.ya?ml$", "github": "extension:yml", "gitlab": "extension:yml"},
    {"id": "config_json", "sensitive": False, "sourcegraph": r"file:config.*\.json$", "github": "filename:config.json", "gitlab": "filename:config.json"},
    {"id": "password_word", "sensitive": True, "sourcegraph": "password", "github": "password", "gitlab": "password"},
    {"id": "apikey_word", "sensitive": True, "sourcegraph": "apikey", "github": "apikey", "gitlab": "apikey"},
    {"id": "private_key_header", "sensitive": True, "sourcegraph": '"PRIVATE KEY-----"', "github": '"PRIVATE KEY"', "gitlab": '"PRIVATE KEY"'},
)
IOC_REPO_WORDS = frozenset({
    "ioc", "iocs", "indicators", "threatintel", "threat-intel", "blocklist", "blocklists", "blacklist", "blacklists",
    "denylist", "malware", "phishing", "phish", "maltrail", "ipsets", "adblock", "adguard", "ublock", "spam", "scam",
    "feeds", "abuse", "hosts", "filters", "filterlists",
})
LIST_EXTENSIONS = (".txt", ".csv", ".list", ".lst", ".rules", ".hosts", ".netset", ".ipset")
PROVENANCE_TEXT = {
    "own_repo": "organisation repository",
    "third_party_repo": "third-party repo mentions our asset",
    "public_ioc_repo": "listed in public IOC repo",
}
_RE_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")
_RE_OWNER = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_RE_NAME = re.compile(r"^[A-Za-z0-9_./-]{1,300}$")
_RE_REF = re.compile(r"^[0-9A-Za-z_.-]{1,100}$")
_RE_BLOB_COMMIT = re.compile(r"^https://github\.com/[^/]+/[^/]+/blob/([0-9a-f]{7,40})/")


# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------


def _s(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def safe_term(value: Any) -> str:
    """A search term safe inside one quoted phrase: quotes, backslashes and control characters removed, spaces folded."""
    v = _RE_CTRL.sub(" ", _s(value)).replace('"', " ").replace("\\", " ")
    return re.sub(r"\s+", " ", v).strip()[:200]


def sourcegraph_query(term: str, dork: str = "") -> str:
    """cond 3 exact quoted query: '"<term>" [dork] type:file count:100 timeout:10s patternType:keyword'."""
    parts = [f'"{term}"', dork, "type:file", "count:100", "timeout:10s", "patternType:keyword"]
    return " ".join(p for p in parts if p)


def sourcegraph_url(term: str, dork: str = "") -> str:
    """``/.api/search/stream?q=...&v=V3&cm=t`` (cm=t asks for chunkMatches, cond 8); the token goes in a header."""
    return f"{SG_STREAM}?q={quote(sourcegraph_query(term, dork), safe='')}&v=V3&cm=t"


def github_url(term: str, dork: str = "") -> str:
    q = f'"{term}" {dork}'.strip()
    return f"{GH_SEARCH}?q={quote_plus(q)}&per_page=100"


def gitlab_url(term: str, dork: str = "") -> str:
    q = f'"{term}" {dork}'.strip()
    return f"{GL_SEARCH}?scope=blobs&search={quote(q, safe='')}&per_page=100"


# --------------------------------------------------------------------------------------
# Parsers (pure; untrusted data: never raise)
# --------------------------------------------------------------------------------------


def iter_sse(raw: Any, *, max_bytes: int = SSE_MAX_BYTES) -> dict[str, Any]:
    """text/event-stream framing: {'events': [(name, data)], 'truncated', 'tail_incomplete'} (at most max_bytes)."""
    data = bytes(raw) if isinstance(raw, (bytes, bytearray, memoryview)) else _s(raw).encode("utf-8", "replace")
    truncated = len(data) > max_bytes
    text = data[:max_bytes].decode("utf-8", "replace").replace("\r\n", "\n")
    events: list[tuple[str, str]] = []
    name: str | None = None
    lines: list[str] = []
    for line in text.split("\n"):
        if line == "":
            if name is not None or lines:
                events.append((name or "message", "\n".join(lines)))
            name, lines = None, []
            continue
        if line.startswith(":"):
            continue
        field, _, val = line.partition(":")
        val = val[1:] if val.startswith(" ") else val
        if field == "event":
            name = val
        elif field == "data":
            lines.append(val)
    tail = name is not None or bool(lines)
    if tail:
        events.append((name or "message", "\n".join(lines)))
    return {"events": events, "truncated": truncated, "tail_incomplete": tail}


def split_repo(repo: str) -> tuple[str, str, str]:
    """'github.com/owner/name' -> ('github.com', 'owner', 'name'); nested GitLab groups keep the rest in name."""
    parts = [p for p in _s(repo).split("/") if p]
    if len(parts) < 3:
        return (parts[0].lower() if parts else "", parts[1] if len(parts) > 1 else "", "")
    return (parts[0].lower(), parts[1], "/".join(parts[2:]))


def _sg_match(m: Any) -> dict[str, Any] | None:
    if not isinstance(m, Mapping) or m.get("type") not in ("content", "path"):
        return None
    repo = _s(m.get("repository"))
    host, owner, name = split_repo(repo)
    if not (host and owner and name):
        return None
    out: dict[str, Any] = {"source": SOURCE_SG, "repo": repo, "repo_host": host, "owner": owner, "name": name,
                           "owner_type": "", "path": _s(m.get("path")), "commit": _s(m.get("commit")), "url": "",
                           "first_line": None, "fragments": []}
    lines: list[int] = []
    for lm in m.get("lineMatches") or []:
        if isinstance(lm, Mapping):
            n = _int(lm.get("lineNumber"))
            if n is not None and n >= 0:
                lines.append(n + 1)  # 0-based in the API
            out["fragments"].append(_s(lm.get("line")))
    for cm in m.get("chunkMatches") or []:
        if not isinstance(cm, Mapping):
            continue
        start = cm.get("contentStart") if isinstance(cm.get("contentStart"), Mapping) else {}
        base = _int(start.get("line"))
        hits = sorted({_int((r.get("start") or {}).get("line")) for r in cm.get("ranges") or []
                       if isinstance(r, Mapping) and isinstance(r.get("start"), Mapping)} - {None})
        lines += [h + 1 for h in hits if h is not None and h >= 0] or ([base + 1] if base is not None and base >= 0 else [])
        out["fragments"].append(_s(cm.get("content")))
    out["first_line"] = min(lines) if lines else None
    return out


def parse_sourcegraph_stream(raw: Any, *, max_bytes: int = SSE_MAX_BYTES) -> dict[str, Any]:
    """Sourcegraph ``/.api/search/stream``: 'matches' events -> hits (lineMatches or chunkMatches[].content, 1-based
    lines); the last 'progress' -> matchCount and skipped reasons; 'alert'/'error' events kept; 'done' observed."""
    out: dict[str, Any] = {"hits": [], "match_count": 0, "done": False, "alerts": [], "errors": [], "warnings": [],
                           "truncated": False, "bad_events": 0, "html": False}
    head = _s(raw[:4096].decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else _s(raw)[:4096])
    if "event:" not in head and head.lstrip().lower().startswith(("<!doctype", "<html", "<head", "<body")):
        out["html"] = True
        return out
    sse = iter_sse(raw, max_bytes=max_bytes)
    out["truncated"] = sse["truncated"] or sse["tail_incomplete"]
    for name, data in sse["events"]:
        try:
            obj = json.loads(data) if data.strip() else None
        except ValueError:
            out["bad_events"] += 1
            continue
        if name == "matches":
            for m in obj if isinstance(obj, list) else []:
                hit = _sg_match(m)
                if hit:
                    out["hits"].append(hit)
        elif name == "progress" and isinstance(obj, Mapping):
            out["match_count"] = _int(obj.get("matchCount")) or 0
            skipped = [s for s in obj.get("skipped") or [] if isinstance(s, Mapping)]
            out["warnings"] = [_s(s.get("title")) or _s(s.get("reason")) for s in skipped
                               if _s(s.get("severity")).lower() in ("warn", "warning", "error")]
        elif name == "alert" and isinstance(obj, Mapping):
            out["alerts"].append((_s(obj.get("title")) + (" - " + _s(obj.get("description")) if obj.get("description") else ""))[:300])
        elif name == "error":
            out["errors"].append((_s(obj.get("message")) if isinstance(obj, Mapping) else _s(obj))[:300])
        elif name == "done":
            out["done"] = True
    return out


def sourcegraph_outcome(parsed: Mapping[str, Any]) -> tuple[str, str]:
    """(outcome, reason) of a parsed stream: 'ok' / 'empty' only for a clean done stream; 'partial' (hits, but the
    stream was cut or backends were missing); 'error' (alert/error event, an HTML page, or zero hits on a cut or
    degraded stream: could not verify, never 'no mentions', rule 5)."""
    n = len(parsed.get("hits") or [])
    if parsed.get("html"):
        return "error", "not an event stream (HTML page): could not verify"
    if parsed.get("errors"):
        return "error", "Sourcegraph error: " + "; ".join(parsed["errors"])[:200]
    if parsed.get("alerts"):
        return "error", "Sourcegraph alert: " + parsed["alerts"][0]
    problems = []
    if parsed.get("truncated") or not parsed.get("done"):
        problems.append("stream ended before the done event (max_bytes or deadline)")
    if parsed.get("bad_events"):
        problems.append(f"{parsed['bad_events']} undecodable event(s)")
    if parsed.get("warnings"):
        problems.append("partial index: " + "; ".join(parsed["warnings"])[:200])
    if problems:
        return ("partial" if n else "error"), "; ".join(problems) + ("" if n else ": could not verify")
    return ("ok" if n else "empty"), ""


def _commit_from_blob(url: str) -> str:
    m = _RE_BLOB_COMMIT.match(url)
    return m.group(1) if m else ""


def parse_github(payload: Any) -> dict[str, Any] | None:
    """GitHub ``search/code`` (text-match) -> {'total', 'incomplete', 'hits'}; None when the body is not the expected
    object (could not verify). Line numbers are absent in the REST API; repositories are never walked to find them."""
    if not isinstance(payload, Mapping) or not isinstance(payload.get("items"), list):
        return None
    hits = []
    for it in payload["items"]:
        if not isinstance(it, Mapping):
            continue
        repo = it.get("repository") if isinstance(it.get("repository"), Mapping) else {}
        owner = repo.get("owner") if isinstance(repo.get("owner"), Mapping) else {}
        full = _s(repo.get("full_name"))
        if "/" not in full:
            continue
        html_url = _s(it.get("html_url"))
        frags = [_s(tm.get("fragment")) for tm in it.get("text_matches") or []
                 if isinstance(tm, Mapping) and _s(tm.get("property") or "content") == "content"]
        hits.append({"source": SOURCE_GH, "repo": "github.com/" + full, "repo_host": "github.com",
                     "owner": _s(owner.get("login")) or full.split("/", 1)[0], "owner_type": _s(owner.get("type")),
                     "name": full.split("/", 1)[1], "path": _s(it.get("path")),
                     "commit": _commit_from_blob(html_url), "url": html_url if html_url.startswith("https://github.com/") else "",
                     "first_line": None, "fragments": frags, "fork": repo.get("fork") is True})
    return {"total": _int(payload.get("total_count")) or 0, "incomplete": payload.get("incomplete_results") is True,
            "hits": hits}


def parse_gitlab(payload: Any) -> dict[str, Any] | None:
    """GitLab ``search?scope=blobs`` -> {'hits'}; None when the body is not a JSON list (could not verify). Hits carry
    the project id only: no link is guessed (the project path would need one more request)."""
    if not isinstance(payload, list):
        return None
    hits = []
    for it in payload:
        if not isinstance(it, Mapping):
            continue
        pid = _int(it.get("project_id"))
        if pid is None:
            continue
        hits.append({"source": SOURCE_GL, "repo": f"gitlab.com/projects/{pid}", "repo_host": "gitlab.com", "owner": "",
                     "owner_type": "", "name": "", "path": _s(it.get("path") or it.get("filename")),
                     "commit": _s(it.get("ref")), "url": "", "first_line": _int(it.get("startline")),
                     "fragments": [_s(it.get("data"))]})
    return {"hits": hits}


# --------------------------------------------------------------------------------------
# Secrets, provenance and summary (cond 6, 7, 9)
# --------------------------------------------------------------------------------------


def scan_fragment(text: str) -> tuple[list[dict[str, str]], str]:
    """P312 scanner over one fragment (in memory): ([{rule, dedup}], masked text). The raw value never leaves this
    function: the dedup id is a keyed HMAC of the installation (cond 6)."""
    if not isinstance(text, str) or not text:
        return [], ""
    found = []
    out, last = [], 0
    for hit in find_secrets(text):
        if hit.value in EXAMPLE_VALUES or "${" in hit.value or "{{" in hit.value:
            continue
        found.append({"rule": hit.kind, "dedup": hmacid.hmac_hex("secret", f"{hit.kind}:{hit.value}")[:32]})
        out.append(text[last:hit.start])
        out.append(f"[REDACTED:{hit.kind}]")
        last = hit.end
    out.append(text[last:])
    return found, "".join(out)


def classify_repo(repo: str, path: str = "", *, org_accounts: Iterable[str] = (), ioc_repos: Iterable[str] = ()) -> str:
    """cond 7 provenance: 'own_repo' (an owner among the org's code-host accounts), 'public_ioc_repo' (team-curated list
    or IOC/blocklist name and path heuristics; context only) or 'third_party_repo'."""
    host, owner, name = split_repo(repo)
    owners = {_s(o).strip().lower() for o in org_accounts if _s(o).strip()}
    if owner and owner.lower() in owners:
        return "own_repo"
    curated = {_s(r).strip().lower() for r in ioc_repos if _s(r).strip()}
    words = set(re.split(r"[-_.\s]+", name.lower())) | set(re.split(r"[-_.\s]+", owner.lower()))
    p = path.lower()
    dirs = set(re.split(r"[/_.-]+", p.rsplit("/", 1)[0])) if "/" in p else set()
    if repo.lower() in curated or words & IOC_REPO_WORDS or any(w in name.lower() for w in ("blocklist", "blacklist", "phishing", "malware")) \
            or (dirs & IOC_REPO_WORDS and p.endswith(LIST_EXTENSIONS)):
        return "public_ioc_repo"
    return "third_party_repo"


def hit_link(hit: Mapping[str, Any]) -> str | None:
    """repo/path/line link of a hit (cond 9): the GitHub blob URL, a GitHub/GitLab blob URL built from a Sourcegraph
    match, or the Sourcegraph permalink; None when the parts are not safe tokens (never a guessed URL)."""
    line = hit.get("first_line")
    anchor = f"#L{line}" if isinstance(line, int) and line > 0 else ""
    url = _s(hit.get("url"))
    if hit.get("source") == SOURCE_GH and url.startswith("https://github.com/"):
        return url.split("#", 1)[0] + anchor
    host, owner, name = _s(hit.get("repo_host")), _s(hit.get("owner")), _s(hit.get("name"))
    path = quote(_s(hit.get("path")), safe="/")
    ref = _s(hit.get("commit")) or "HEAD"
    if not (owner and name and path) or not _RE_OWNER.match(owner) or not _RE_NAME.match(name) or ".." in name \
            or not _RE_REF.match(ref) or ".." in path.split("/"):
        return None
    if host == "github.com":
        return f"https://github.com/{owner}/{name}/blob/{ref}/{path}{anchor}"
    if host == "gitlab.com":
        return f"https://gitlab.com/{owner}/{name}/-/blob/{ref}/{path}{anchor}"
    if hit.get("source") == SOURCE_SG and re.fullmatch(r"[a-z0-9.-]{3,100}", host):
        return f"https://sourcegraph.com/{host}/{owner}/{name}@{ref}/-/blob/{path}" + (f"?L{line}" if anchor else "")
    return None


def extract_hostnames(text: str, apex: str) -> set[str]:
    """Hostnames strictly under ``apex`` in a (masked) fragment: 'login-example.com' and 'a.example.com.evil.net' are
    not under example.com."""
    if not apex or not text:
        return set()
    rx = re.compile(r"(?<![A-Za-z0-9.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+" + re.escape(apex)
                    + r")(?![A-Za-z0-9-]|\.[A-Za-z0-9])", re.I)
    return {m.group(1).lower() for m in rx.finditer(text)}


def summarise(hits: list[dict[str, Any]], *, org_accounts: Iterable[str] = (), ioc_repos: Iterable[str] = (),
              apex: str = "", limit: int = TOP_REPOS) -> dict[str, Any]:
    """cond 6/7/9: dedupe per repository, scan and mask, tag provenance, keep the top ``limit`` repositories (secret
    matches first, then own, third-party and IOC repos). Fragments never leave this function."""
    repos: dict[str, dict[str, Any]] = {}
    hostnames: set[str] = set()
    org_accounts = tuple(org_accounts)
    ioc_repos = tuple(ioc_repos)
    for h in hits:
        repo = _s(h.get("repo"))
        if not repo:
            continue
        g = repos.setdefault(repo, {"repo": repo, "hits": [], "dedup": {}, "first_path": _s(h.get("path")),
                                    "owner": _s(h.get("owner")), "owner_type": _s(h.get("owner_type")),
                                    "repo_host": _s(h.get("repo_host")), "kinds": set()})
        rules: set[str] = set()
        for frag in h.get("fragments") or []:
            found, masked = scan_fragment(_s(frag))
            for f in found:
                g["dedup"].setdefault(f["dedup"], f["rule"])
                rules.add(f["rule"])
            if apex:
                hostnames |= extract_hostnames(masked, apex)
        g["kinds"] |= rules
        key = (h.get("source"), _s(h.get("path")), h.get("first_line"))
        if key not in {(x["source"], x["path"], x["line"]) for x in g["hits"]}:
            g["hits"].append({"source": h.get("source"), "path": _s(h.get("path")), "line": h.get("first_line"),
                              "commit": _s(h.get("commit")), "link": hit_link(h), "rules": sorted(rules)})
    rows = []
    for repo, g in repos.items():
        prov = classify_repo(repo, g["first_path"], org_accounts=org_accounts, ioc_repos=ioc_repos)
        rows.append({"repo": repo, "provenance": prov, "wording": PROVENANCE_TEXT[prov],
                     "severity": "high" if g["dedup"] else "info", "hit_count": len(g["hits"]),
                     "rules": sorted(set(g["dedup"].values())), "dedup": sorted(g["dedup"]), "owner": g["owner"],
                     "owner_type": g["owner_type"], "repo_host": g["repo_host"], "hits": g["hits"][:5]})
    order = {"own_repo": 0, "third_party_repo": 1, "public_ioc_repo": 2}
    rows.sort(key=lambda r: (r["severity"] != "high", order.get(r["provenance"], 3), -r["hit_count"], r["repo"]))
    return {"repos": rows[:limit], "overflow": max(0, len(rows) - limit), "total_repos": len(rows),
            "total_hits": sum(r["hit_count"] for r in rows), "hostnames": sorted(hostnames)[:MAX_HOSTNAMES]}


# --------------------------------------------------------------------------------------
# Query plan (cond 3-5)
# --------------------------------------------------------------------------------------


def plan_queries(term: str, providers: list[str], *, full_pack: bool, sensitive_ok: bool) -> list[dict[str, Any]]:
    """One exact quoted query per provider; with ``full_pack`` the code dorks too (sensitive ones only when
    ``sensitive_ok``), capped at 3 (default) or 10 (full pack) queries."""
    plan = [{"provider": p, "dork_id": "", "dork": "", "sensitive": False} for p in providers]
    if full_pack:
        for d in CODE_DORKS:
            if d["sensitive"] and not sensitive_ok:
                continue
            plan += [{"provider": p, "dork_id": d["id"], "dork": d[p], "sensitive": d["sensitive"]} for p in providers]
    cap = FULL_PACK_QUERY_CAP if full_pack else DEFAULT_QUERY_CAP
    return plan[:cap]


_STATUS_OF = {
    RateLimited: (Status.RATE_LIMITED, "rate_limited"),
    QuotaExceeded: (Status.QUOTA, "quota"),
    DeadlineExceeded: (Status.ERROR, "timeout"),
    OfflineError: (Status.UNAVAILABLE, "offline"),
}


def failure_of(exc: BaseException, source: str) -> tuple[Status, str, str]:
    """(status, reason_code, reason) of a per-source failure (``source`` = provider name): always 'could not verify',
    never an absence (rule 5)."""
    for cls, (status, code) in _STATUS_OF.items():
        if isinstance(exc, cls):
            return status, code, f"{source}: {exc} (could not verify)"
    if isinstance(exc, Blocked):
        return Status.BLOCKED, getattr(exc, "reason_code", "") or "challenge", f"{source}: {exc} (could not verify)"
    if isinstance(exc, AuthRequired):
        body = _s(getattr(exc, "body", "")).lower()
        if source == "gitlab" and re.search(r"advanced search|exact code search|not available|scope", body):
            return (Status.SKIPPED, "config", "gitlab: global blob search needs GitLab Premium/Ultimate with advanced or "
                    "exact code search for the token's namespace (could not verify)")
        status_code = getattr(exc, "status", 0)
        return Status.NEEDS_KEY, "needs_key", f"{source}: HTTP {status_code}: the token was refused (could not verify)"
    if isinstance(exc, PolicyError):
        return Status.SKIPPED, getattr(exc, "reason_code", "") or "policy", f"{source}: {exc}"
    if isinstance(exc, (HttpError, NetworkError)):
        return Status.ERROR, "error", f"{source}: {exc} (could not verify)"
    return Status.ERROR, "error", f"{source}: {type(exc).__name__} (could not verify)"


@register
class CodeSearch(Module):
    name = "code_search"
    title = "Public code search (Sourcegraph, GitHub, GitLab)"
    description = (
        "Mentions of a seed domain, brand or keyword in public code: Sourcegraph public stream search (keyless), GitHub "
        "code search and GitLab blob search with team tokens. Repo/path/line locations only; secrets are masked, never "
        "shown, tested or reused."
    )
    category = "search_dorks"
    accepts = {T.DOMAIN, T.ORG, T.KEYWORD, T.USERNAME, T.EMAIL}
    produces = {T.URL, T.USERNAME}
    reference = "https://sourcegraph.com/docs/api/stream_api"
    notice = (
        "Searches public code for analyst-typed seeds and org_profile assets only. Matches are reported as repository, "
        "path and line with masked pattern ids; secrets are never shown, validated, tested or reused and repositories "
        "are never cloned. GitHub and GitLab need team tokens on business plans (key_plans) and stay off until setting "
        "code_search_keyed_sources is enabled (merge gate: real fixtures). Usernames and e-mail addresses are searched "
        "only on explicit selection with an org_profile asset or a recorded purpose."
    )
    terms = "key-terms"  # sourcegraph open + github/gitlab key-terms
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "sourcegraph"
    sources = (SOURCE_SG, SOURCE_GH, SOURCE_GL)
    hosts = ("sourcegraph.com", "api.github.com", "gitlab.com")
    access_model = "free_noauth_limited"
    optional_keys = ("sourcegraph", "github", "gitlab")
    max_requests = 10
    expected_latency = 7.0
    timeout = 50.0
    min_interval = 2.0
    cache_ttl = 0  # cond 6: raw search bodies are never cached
    max_pivots = 20
    default_enabled = True
    error_markers = (
        {"id": "code_search_github_secondary_limit", "statuses": [403, 429], "regex": "(?i)secondary rate limit|abuse detection",
         "maps_to": "rate_limited", "reason": "GitHub code search: secondary rate limit (could not verify)"},
        {"id": "code_search_github_primary_limit", "statuses": [403, 429], "regex": "(?i)API rate limit exceeded",
         "maps_to": "rate_limited", "reason": "GitHub code search: rate limit exhausted (could not verify)"},
    )
    settings = {
        "code_search_full_pack": SettingSpec(False, "run the full code-dork pack (<= 10 queries) for every seed, not only "
                                                    "for org_profile own domains (P305 cond 3)"),
        "code_search_keyed_sources": SettingSpec(False, "enable the GitHub and GitLab parts (needs team tokens on business "
                                                        "plans; merge gate P305 cond 10: real fixtures)"),
        "code_search_org_accounts": SettingSpec([], "the organisation's own code-host accounts (owners of own repositories)"),
        "code_search_ioc_repos": SettingSpec([], "team-curated public IOC/blocklist repositories ('github.com/owner/name'): "
                                                 "hits there are context only"),
    }

    # ---- scope (cond 3-5) ---------------------------------------------------------------
    @staticmethod
    def _explicit(ctx: Any) -> bool:
        name = CodeSearch.name
        opts = getattr(ctx, "options", None)
        if name in set(getattr(opts, "include", ()) or ()):
            return True
        pctx = getattr(getattr(ctx, "runtime", None), "policy_context", None)
        return name in set(getattr(pctx, "explicit", ()) or ())

    @staticmethod
    def _ownership(entity: Entity, ctx: Any) -> tuple[bool, bool]:
        """(org-owned, verified org-owned) for the entity (domain/e-mail via the org_profile, brand by name)."""
        org = getattr(ctx, "org", None)
        if org is None:
            return False, False
        try:
            if entity.type in (T.DOMAIN, T.EMAIL):
                domain = entity.value.rsplit("@", 1)[-1]
                own = org.owns(Entity.make(T.DOMAIN, domain))
                return bool(own.own), bool(own.own and org.is_verified_domain(domain))
            if entity.type in (T.ORG, T.KEYWORD):
                terms = {t.lower() for t in org.brand_terms()}
                name = str(getattr(org, "name", "") or "").strip().lower()
                v = entity.value.strip().lower()
                return (bool(v) and (v in terms or v == name)), False
            if entity.type is T.USERNAME:
                accounts = {str(a).lower() for a in ctx.setting("code_search_org_accounts", []) or []}
                return entity.value.lower() in accounts, False
        except Exception:  # noqa: BLE001 - an unusable profile never grants anything
            return False, False
        return False, False

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """cond 3: analyst-typed seeds and org_profile assets only, never every pivot."""
        return bool(getattr(ctx, "is_seed", False)) or self._ownership(entity, ctx)[0]

    # ---- per-source calls --------------------------------------------------------------
    def _sourcegraph(self, ctx: Any, term: str, dork: str, timeout: float) -> dict[str, Any]:
        headers = {"Accept": "text/event-stream"}
        token = ctx.key("sourcegraph")
        if token:
            headers["Authorization"] = f"token {token}"
        resp = ctx.http.get(sourcegraph_url(term, dork), headers=headers, source=SOURCE_SG, ttl=0,
                            timeout=timeout, max_bytes=SSE_MAX_BYTES)
        ctx.http.check(resp)  # challenge pages, 429/403/5xx and error markers raise (rule 5)
        parsed = parse_sourcegraph_stream(resp.content, max_bytes=SSE_MAX_BYTES)
        if resp.truncated:
            parsed["truncated"] = True
        outcome, reason = sourcegraph_outcome(parsed)
        return {"hits": parsed["hits"], "outcome": outcome, "reason": reason}

    def _github(self, ctx: Any, term: str, dork: str, timeout: float) -> dict[str, Any]:
        if not self._github_slot(ctx):
            raise RateLimited("GitHub code-search minute window full (8 of 10 a minute): could not verify now")
        headers = {"Accept": GH_ACCEPT, "Authorization": f"Bearer {ctx.key('github')}"}
        data = ctx.http.get_json(github_url(term, dork), headers=headers, source=SOURCE_GH, ttl=0, timeout=timeout)
        parsed = parse_github(data)
        if parsed is None:
            return {"hits": [], "outcome": "error", "reason": "unexpected GitHub answer: could not verify"}
        if parsed["incomplete"]:
            return {"hits": parsed["hits"], "outcome": "partial" if parsed["hits"] else "error",
                    "reason": "incomplete_results (GitHub search timed out)" + ("" if parsed["hits"] else ": could not verify")}
        return {"hits": parsed["hits"], "outcome": "ok" if parsed["hits"] else "empty", "reason": ""}

    def _gitlab(self, ctx: Any, term: str, dork: str, timeout: float) -> dict[str, Any]:
        headers = {"PRIVATE-TOKEN": ctx.key("gitlab")}
        data = ctx.http.get_json(gitlab_url(term, dork), headers=headers, source=SOURCE_GL, ttl=0, timeout=timeout)
        parsed = parse_gitlab(data)
        if parsed is None:
            return {"hits": [], "outcome": "error", "reason": "unexpected GitLab answer: could not verify"}
        return {"hits": parsed["hits"], "outcome": "ok" if parsed["hits"] else "empty", "reason": ""}

    @staticmethod
    def _github_slot(ctx: Any) -> bool:
        """cond 8 minute window (P334 has no minute window yet): at most 8 GitHub code searches in 60 s."""
        now = ctx.now().timestamp()
        try:
            stamps = [float(t) for t in ctx.state.get("github_minute", []) or [] if now - float(t) < 60.0]
        except (TypeError, ValueError):
            stamps = []
        if len(stamps) >= GITHUB_MINUTE_BUDGET:
            return False
        stamps.append(now)
        try:
            ctx.state.set("github_minute", stamps[-GITHUB_MINUTE_BUDGET:])
        except Exception:  # noqa: BLE001 - state is best effort; the run budget still caps requests
            pass
        return True

    # ---- run ------------------------------------------------------------------------------
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        own, verified_own = self._ownership(entity, ctx)
        if entity.type in (T.USERNAME, T.EMAIL):
            if not self._explicit(ctx):
                return res.mark(Status.SKIPPED, "usernames and e-mail addresses are searched only on explicit selection "
                                "(-M code_search or v3lum run) (P305 cond 5)", reason_code="privacy")
            if not (own or str(getattr(ctx, "purpose", "") or "").strip()):
                return res.mark(Status.SKIPPED, "only org_profile addresses/accounts or a case with a recorded purpose "
                                "(--purpose) (P305 cond 5)", reason_code="privacy")
        term = safe_term(entity.value)
        if not term:
            return res.mark(Status.SKIPPED, "empty search term", reason_code="not_applicable")
        allowed = set(getattr(ctx, "allowed_sources", ()) or ())
        keyed = bool(ctx.setting("code_search_keyed_sources", False))
        providers = []
        if SOURCE_SG in allowed:
            providers.append("sourcegraph")
        if keyed and SOURCE_GH in allowed and ctx.has_key("github"):
            providers.append("github")
        if keyed and SOURCE_GL in allowed and ctx.has_key("gitlab"):
            providers.append("gitlab")
        if not providers:
            return res.mark(Status.SKIPPED, "no code-search source is available (licence profile, keys or setting "
                            "code_search_keyed_sources)", reason_code="config")
        full_pack = bool(ctx.setting("code_search_full_pack", False)) or (entity.type is T.DOMAIN and own)
        sensitive_ok = verified_own or bool(getattr(ctx, "authorized", False) and getattr(getattr(ctx, "options", None), "authorization_ref", ""))
        plan = plan_queries(term, providers, full_pack=full_pack, sensitive_ok=sensitive_ok)
        budget = FULL_PACK_BUDGET_S if full_pack else DEFAULT_BUDGET_S
        started = ctx.now()
        source_of = {"sourcegraph": SOURCE_SG, "github": SOURCE_GH, "gitlab": SOURCE_GL}
        call = {"sourcegraph": self._sourcegraph, "github": self._github, "gitlab": self._gitlab}
        hits: list[dict[str, Any]] = []
        queries: list[dict[str, Any]] = []
        failures: dict[str, tuple[Status, str, str]] = {}
        answered: set[str] = set()
        degraded: dict[str, str] = {}
        for q in plan:
            source = source_of[q["provider"]]
            if source in failures and failures[source][0] in (Status.RATE_LIMITED, Status.QUOTA, Status.NEEDS_KEY, Status.BLOCKED, Status.SKIPPED):
                queries.append({"source": source, "dork": q["dork_id"], "outcome": "not sent (source failed earlier)"})
                continue
            left = budget - (ctx.now() - started).total_seconds()
            if left <= 1.0:
                queries.append({"source": source, "dork": q["dork_id"], "outcome": "not sent (entity budget spent)"})
                continue
            timeout = min(SSE_DEADLINE_S, left)
            try:
                out = call[q["provider"]](ctx, term, q["dork"], timeout)
            except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, PolicyError) as exc:
                failures.setdefault(source, failure_of(exc, q["provider"]))
                queries.append({"source": source, "dork": q["dork_id"], "outcome": failures[source][0].value})
                continue
            queries.append({"source": source, "dork": q["dork_id"], "outcome": out["outcome"], "hits": len(out["hits"])})
            hits += out["hits"]
            if out["outcome"] in ("ok", "empty"):
                answered.add(source)
            elif out["outcome"] == "partial":
                answered.add(source)
                degraded[source] = out["reason"]
            else:
                failures.setdefault(source, (Status.ERROR, "error", f"{q['provider']}: {out['reason']}"))
        for source, (status, code, reason) in failures.items():
            if source not in answered:
                res.source_status(source, status, reason_code=code, reason=reason)
        apex = entity.value if entity.type is T.DOMAIN else (entity.value.rsplit("@", 1)[1] if entity.type is T.EMAIL else "")
        summary = summarise(hits, org_accounts=ctx.setting("code_search_org_accounts", []) or [],
                            ioc_repos=ctx.setting("code_search_ioc_repos", []) or [], apex=apex)
        res.raw = {"queries": queries, "full_pack": full_pack, "sensitive_dorks": sensitive_ok,
                   "degraded": degraded, "summary": {k: v for k, v in summary.items() if k != "repos"},
                   "repos": [{k: v for k, v in r.items() if k != "owner_type"} for r in summary["repos"]]}
        res.attr("code_search_summary", {"providers": {s: ("partial: " + degraded[s]) if s in degraded else "answered"
                                                       for s in sorted(answered)}
                                         | {s: f"{failures[s][0].value} ({failures[s][1]})" for s in failures if s not in answered},
                                         "queries": len(queries), "total_repos": summary["total_repos"],
                                         "total_hits": summary["total_hits"], "overflow": summary["overflow"]})
        if summary["repos"]:
            self._report(res, entity, summary, own=own)
            return res
        if answered:
            note = "no mention in the indexed public code of the sources that answered"
            if degraded:
                note += " (partial index: " + "; ".join(degraded.values())[:200] + ")"
            return res.mark(Status.EMPTY, note)
        status, code, reason = next(iter(failures.values())) if failures else (Status.ERROR, "error", "no source answered")
        return res.mark(status, reason, reason_code=code)

    def _report(self, res: ModuleResult, entity: Entity, summary: dict[str, Any], *, own: bool) -> None:
        rows = summary["repos"]
        res.attr("code_search_hits", [{k: v for k, v in r.items() if k not in ("owner", "owner_type", "repo_host")} for r in rows])
        if summary["hostnames"]:
            res.attr("code_search_hostnames", summary["hostnames"])
        owners: set[str] = set()
        for r in rows:
            first = next((h for h in r["hits"] if h.get("link")), None)
            if first:
                res.pivot(T.URL, first["link"], "mentioned_in_code", confidence="probable", expand=False,
                          note=f"{r['wording']}: {r['repo']} {first['path']}")
            if r["owner"] and r["repo_host"] in ("github.com", "gitlab.com") and r["owner"].lower() not in owners:
                owners.add(r["owner"].lower())
                res.pivot(T.USERNAME, r["owner"], "code_repo_owner", confidence="possible", expand=False,
                          note="owner of a public repository whose code mentions the value: a lead, not an identity")
            for h in r["hits"][:3]:
                if h.get("link"):
                    res.link(f"code: {r['repo']} {h['path']}" + (f" line {h['line']}" if h.get("line") else ""), h["link"])
        secret_rows = [r for r in rows if r["severity"] == "high"]
        for r in secret_rows:
            where = ", ".join(f"{h['path']}" + (f":{h['line']}" if h.get("line") else "") for h in r["hits"][:5])
            distinctive = any(rule not in LABEL_KINDS for rule in r["rules"])
            res.finding(
                "Secret pattern in public code that mentions the value", "high",
                f"{r['repo']} ({r['wording']}): {where}. Pattern ids: {', '.join(r['rules'])}. The matched value is "
                "masked and was never validated, tested or reused; rotate it if it is real.",
                confidence="probable" if distinctive else "possible",
                criterion="P312 secret pattern in a public code fragment that mentions the value (P305 cond 6, 9); "
                          "location only, secret masked",
                data={"repo": r["repo"], "provenance": r["provenance"], "rules": r["rules"], "dedup": r["dedup"],
                      "locations": [{"path": h["path"], "line": h.get("line"), "commit": h.get("commit")} for h in r["hits"][:5]]},
                tags=["credential_exposure", r["provenance"]], source=self._source_of(r), key=r["repo"],
                references=[h["link"] for h in r["hits"][:3] if h.get("link")],
            )
        plain = [r for r in rows if r["severity"] != "high" and r["provenance"] != "public_ioc_repo"]
        if plain:
            wording = "Mentioned in public code" if not own else "Third-party repo mentions our asset"
            if own and all(r["provenance"] == "own_repo" for r in plain):
                wording = "Mentioned in the organisation's own public code"
            res.finding(
                wording, "info",
                f"{len(plain)} repositor{'y' if len(plain) == 1 else 'ies'} mention the value: "
                + "; ".join(f"{r['repo']} ({r['wording']})" for r in plain[:10])
                + (f" (+{summary['overflow']} more)" if summary["overflow"] else ""),
                confidence="probable", criterion="exact quoted match in public code search results (P305 cond 9)",
                data={"repos": [r["repo"] for r in plain]}, tags=sorted({r["provenance"] for r in plain}),
                source=self._source_of(plain[0]),
            )
        listed = [r for r in rows if r["severity"] != "high" and r["provenance"] == "public_ioc_repo"]
        if listed:
            res.finding(
                "Listed in public IOC repo", "info",
                "The value appears in public IOC/blocklist repositories: "
                + "; ".join(r["repo"] for r in listed[:10]) + ". Context only, never an independent malicious vote.",
                confidence="possible", criterion="match in a public IOC/blocklist repository (P305 cond 7, P171)",
                data={"repos": [r["repo"] for r in listed]}, tags=["context_only", "public_ioc_repo"],
                source=self._source_of(listed[0]),
            )

    @staticmethod
    def _source_of(row: Mapping[str, Any]) -> str:
        sources = [h.get("source") for h in row.get("hits") or [] if h.get("source")]
        return str(sources[0]) if sources else SOURCE_SG
