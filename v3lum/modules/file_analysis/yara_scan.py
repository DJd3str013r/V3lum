"""Optional local YARA scanning with the YARA Forge rule packages (P272, batch p2-G12-1).

Opt-in (default_enabled=False), terms 'noncommercial' (A1 aggregator rule: some rules are non-commercial),
council provider tier 'community' (YARA Forge), opsec passive, disclosure 'none' (local files only; the rule
package is a registered dataset). Final conditions:

* c1 yara-python (Apache-2.0) is the optional extra ``v3lum[yara]`` (``requires_packages``): without it, or on
  Python versions without wheels (3.14+), the module is UNAVAILABLE 'package' ('pip install v3lum[yara]').
* c2 rules come only as SOURCE from the YARA Forge release zip on GitHub through the dataset manager
  (``yara_scan.forge_core``; the manager records the sha256), are split per rule set and compiled locally per set
  inside the sandbox (``includes`` disabled, a failing set retried rule by rule so only broken rules drop;
  failures counted). Compiled rules are never loaded from the network. Rule packs are runtime downloads, never
  bundled or redistributed (A6). The compiled-rules cache (``yara.Rules.save``) waits for an allow-listed sandbox
  output file and a derived-artifact cache in the core (docs/backlog/p2-G12-1.md): until then each scan compiles
  in its sandbox child.
* c3/c4 per-rule licence from meta (``license``, ``malpedia_license``, ``license_url`` resolved through the
  repository LICENSE text Forge embeds): permissive (MIT, BSD, Apache-2.0, ISC, CC0, CC BY) and DRL 1.1 rules are
  class open (source ``github.yara_scan_forge_core``, author attribution kept); non-commercial rules (Malpedia,
  CC BY-NC) are ``github.yara_scan_rules_noncommercial``; GPL/CC BY-SA rules, which c3 does not name, are
  ``github.yara_scan_rules_license`` (licence_allow needed). The policy gate passes the allowed sources in
  ``ctx.allowed_sources`` (corporate: open only). Rules with an unknown or missing licence are never loaded in any
  profile. Exclusions are counted in the coverage table ('N rules excluded: licence').
* c5 the core package by default; extended/full only by flag (setting ``yara_scan_package``).
* c6 matching runs in the shared file-analysis sandbox ``core/sandbox.py`` (:func:`yara_scan_child`), local files
  only, with a 30 s match timeout per file; matched bytes are never returned (offsets and counts only). This
  build has no core sandbox yet: the module reports UNAVAILABLE 'package' with that reason (libyara is native
  code; it is never run in process).
* c7 results: rule name, author, reference, score and package version per hit. Generic or heuristic rules
  (SUSP_, HKTL_, PUA_ after the Forge source prefix, or score < 70) give 'suspicious' low-severity context only; a
  malware_family pivot (low confidence, expand=False) only from a family-specific rule with a family meta; never a
  'malicious' verdict.
* c8 fixtures: a tiny local rule set in the Forge layout (family rule, SUSP_ rule, rules without licence meta, NC
  rule) and the EICAR string stored as two halves (tests/fixtures/yara_scan/).
"""

from __future__ import annotations

import bisect
import re
import urllib.parse
from collections.abc import Iterable, Iterator
from typing import Any

from v3lum.core.datasets import register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.geo_image_meta.image_metadata import (
    InputRefused,
    SandboxUnavailable,
    as_int,
    as_str,
    core_sandbox,
    read_regular_file,
    sandbox_failure,
    sandbox_run,
)

FORGE_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-{package}.zip"
PACKAGES = ("core", "extended", "full")
SRC_OPEN = "github.yara_scan_forge_core"
SRC_LICENSE = "github.yara_scan_rules_license"
SRC_NC = "github.yara_scan_rules_noncommercial"
CLASS_BY_SOURCE = {SRC_OPEN: "open", SRC_LICENSE: "license", SRC_NC: "noncommercial"}
DATASET_SOURCES = {"core": SRC_OPEN, "extended": "github.yara_scan_forge_extended", "full": "github.yara_scan_forge_full"}


def _validate_package(path: Any) -> bool:
    """A downloaded package must be YARA Forge rule source (never a compiled blob or an HTML page)."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    return b"YARA-Forge" in head and b"rule " in head or b"YARA Rule Package" in head


for _pkg in PACKAGES:
    register_dataset(
        f"yara_scan.forge_{_pkg}", FORGE_URL.format(package=_pkg), ttl=7 * 86400,
        description=f"YARA Forge {_pkg} rule package (rule SOURCE; weekly builds)", licence="per-rule licences in meta "
        "(MIT, BSD, Apache-2.0, ISC, CC0, CC BY, DRL 1.1, GPL-3.0, CC BY-SA, CC BY-NC; some none); filtered per rule",
        terms_class="open", attribution="YARA Forge (YARAHQ) and the authors of each rule (author/reference kept, DRL 1.1)",
        provider="github", source=DATASET_SOURCES[_pkg], expect="bytes", archive="zip",
        member=f"packages/{_pkg}/yara-rules-{_pkg}.yar", large=True, validate=_validate_package,
    )


# ======================================================================================================
# [P272 yara_scan] (prep parsers.py, stdlib only)
# ======================================================================================================

YARA_GENERIC_PREFIXES = ('SUSP', 'HKTL', 'PUA')          # P272 c7 (after the Forge source prefix is removed)
YARA_GENERIC_SCORE_BELOW = 70                             # P272 c7
YARA_FAMILY_META_KEYS = ('malware_family', 'malpedia_family', 'family', 'malware')  # P272 c7 'family meta'
YARA_MAX_SOURCE_CHARS = 64 * 1024 * 1024
YARA_MAX_RULES = 50_000
YARA_MATCH_TIMEOUT_S = 30                                 # P272 c6


class YaraSplitError(ValueError):
    """Raised by yara_split() for sources it cannot tokenise safely (unterminated string/regex/comment,
    unbalanced braces, size caps).  The caller counts the whole source file as failed (P272 c2)."""


_YARA_TOKEN = re.compile(
    r'(?P<ws>[ \t\r\n\f\v]+)'
    r'|(?P<lcomment>//[^\n]*)'
    r'|(?P<bcomment>/\*.*?\*/)'
    r'|(?P<bad_bcomment>/\*)'
    r'|(?P<string>"(?:[^"\\\n]|\\.)*")'
    r'|(?P<bad_string>")'
    r'|(?P<regex>/(?:[^/\\\n]|\\.)+/[is]*)'
    r'|(?P<bad_regex>/)'
    r'|(?P<open>\{)|(?P<close>\})'
    r'|(?P<ident>[A-Za-z_][A-Za-z0-9_]*)'
    r'|(?P<number>0x[0-9A-Fa-f]+|\d+(?:\.\d+)?(?:KB|MB)?)'
    r'|(?P<punct>.)',
    re.S,
)
_YARA_ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\'}


def _yara_unquote(raw: str) -> str:
    body = raw[1:-1]
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        if ch == '\\' and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == 'x' and re.fullmatch(r'[0-9A-Fa-f]{2}', body[i + 2:i + 4] or ''):
                out.append(chr(int(body[i + 2:i + 4], 16)))
                i += 4
                continue
            out.append(_YARA_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def yara_tokens(text: str) -> Iterator[tuple[str, str, int, int, int]]:
    """Yield (kind, value, start, end, depth) for YARA source text; whitespace is dropped.

    depth is the brace depth *inside* which the token sits ('{' reports the depth it opens).  Comments,
    text strings and regex literals are single tokens, so braces inside them never count (hex strings
    ``{ 4D 5A }`` are balanced and do count).  YARA has no '/' operator (division is '\\'), so every '/'
    outside a comment starts a regex.  Serves P272 c2 (split per rule before compiling)."""
    depth = 0
    for m in _YARA_TOKEN.finditer(text):
        kind = m.lastgroup
        if kind == 'ws':
            continue
        start, end = m.span()
        if kind in ('bad_bcomment', 'bad_string', 'bad_regex'):
            line = text.count('\n', 0, start) + 1
            raise YaraSplitError(f'unterminated {kind[4:]} at line {line}')
        if kind == 'open':
            depth += 1
            yield ('open', '{', start, end, depth)
            continue
        if kind == 'close':
            yield ('close', '}', start, end, depth)
            depth -= 1
            if depth < 0:
                raise YaraSplitError(f'unbalanced "}}" at line {text.count(chr(10), 0, start) + 1}')
            continue
        yield (kind, m.group(), start, end, depth)
    if depth != 0:
        raise YaraSplitError('unbalanced braces at end of source')


def yara_split(text: str) -> dict:
    """Split YARA source into imports, includes, top-level block comments and rules (P272 c2, c3, c4).

    Each rule: name, modifiers (private/global), tags, meta (first value per key), meta_all (ordered
    pairs), refs (other rule names its condition uses), start/end offsets, line, text.  Never compiles or
    evaluates anything.  Raises YaraSplitError on malformed input or when the caps are exceeded."""
    if not isinstance(text, str):
        raise YaraSplitError('source must be text')
    if len(text) > YARA_MAX_SOURCE_CHARS:
        raise YaraSplitError(f'source larger than {YARA_MAX_SOURCE_CHARS} characters')
    imports: list[str] = []
    includes: list[str] = []
    comments: list[tuple[int, int, str]] = []
    rules: list[dict] = []
    toks = yara_tokens(text)
    pending: list[tuple[str, int]] = []
    expect: str | None = None
    cur: dict | None = None
    section: str | None = None
    meta_state: list = []
    prev: tuple | None = None
    for tok in toks:
        kind, val, start, end, depth = tok
        if cur is None:
            if kind == 'bcomment' and depth == 0:
                comments.append((start, end, val))
            elif kind in ('lcomment', 'bcomment'):
                pass
            elif expect in ('import', 'include'):
                if kind != 'string':
                    raise YaraSplitError(f'{expect} without a quoted name')
                (imports if expect == 'import' else includes).append(_yara_unquote(val))
                expect = None
            elif kind == 'ident' and val in ('import', 'include') and depth == 0 and not pending:
                expect = val
            elif kind == 'ident' and val in ('private', 'global') and depth == 0:
                pending.append((val, start))
            elif kind == 'ident' and val == 'rule' and depth == 0:
                cur = {'name': None, 'modifiers': [p[0] for p in pending], 'tags': [], 'meta': {},
                       'meta_all': [], 'refs': set(), 'start': pending[0][1] if pending else start,
                       'header_state': 'name'}
                pending = []
            elif kind == 'number' or kind == 'ident' or kind == 'punct' or kind == 'string':
                raise YaraSplitError(f'unexpected {val!r} at top level (line {text.count(chr(10), 0, start) + 1})')
            prev = tok
            continue
        # inside a rule header or body
        hs = cur.get('header_state')
        if hs == 'name':
            if kind != 'ident':
                raise YaraSplitError('rule without a name')
            cur['name'] = val
            cur['header_state'] = 'after_name'
        elif hs == 'after_name':
            if kind == 'punct' and val == ':':
                cur['header_state'] = 'tags'
            elif kind == 'open':
                cur['header_state'] = None
            else:
                raise YaraSplitError(f'bad rule header for {cur["name"]}')
        elif hs == 'tags':
            if kind == 'ident':
                cur['tags'].append(val)
            elif kind == 'open':
                cur['header_state'] = None
            else:
                raise YaraSplitError(f'bad tag list for {cur["name"]}')
        else:
            if kind == 'close' and depth == 1:
                cur['end'] = end
                cur.pop('header_state', None)
                cur['line'] = None
                rules.append(cur)
                if len(rules) > YARA_MAX_RULES:
                    raise YaraSplitError(f'more than {YARA_MAX_RULES} rules')
                cur, section, meta_state = None, None, []
                prev = tok
                continue
            if kind in ('lcomment', 'bcomment'):
                prev = tok
                continue
            if kind == 'punct' and val == ':' and prev is not None and prev[0] == 'ident' \
                    and prev[1] in ('meta', 'strings', 'condition') and prev[4] == 1:
                section = prev[1]
                meta_state = []
            elif section == 'meta' and depth == 1:
                meta_state.append(tok)
                _yara_meta_feed(cur, meta_state)
            elif section == 'condition' and kind == 'ident':
                glued = prev is not None and prev[0] == 'punct' and prev[1] in '$#@!' and prev[3] == start
                if not glued:
                    cur['refs'].add(val)
        prev = tok
    if cur is not None:
        raise YaraSplitError(f'rule {cur.get("name")} is not closed')
    nl = [m.start() for m in re.finditer('\n', text)]
    names = {r['name'] for r in rules}
    for r in rules:
        r['line'] = bisect.bisect_right(nl, r['start'] - 1) + 1
        r['text'] = text[r['start']:r['end']]
        r['refs'] = sorted((r['refs'] & names) - {r['name']})
    return {'imports': imports, 'includes': includes, 'comments': comments, 'rules': rules}


def _yara_meta_feed(cur: dict, st: list) -> None:
    """Consume `ident = value` triples (value may be '-' number) from the meta token buffer."""
    while True:
        if len(st) >= 3 and st[0][0] == 'ident' and st[1][0] == 'punct' and st[1][1] == '=':
            vtok = st[2]
            if vtok[0] == 'punct' and vtok[1] == '-':
                if len(st) < 4:
                    return
                if st[3][0] != 'number':
                    raise YaraSplitError(f'bad meta value in {cur["name"]}')
                value: Any = -_yara_number(st[3][1])
                used = 4
            elif vtok[0] == 'string':
                value, used = _yara_unquote(vtok[1]), 3
            elif vtok[0] == 'number':
                value, used = _yara_number(vtok[1]), 3
            elif vtok[0] == 'ident' and vtok[1] in ('true', 'false'):
                value, used = vtok[1] == 'true', 3
            else:
                raise YaraSplitError(f'bad meta value in {cur["name"]}')
            key = st[0][1]
            cur['meta_all'].append((key, value))
            cur['meta'].setdefault(key, value)
            del st[:used]
            continue
        if len(st) >= 2 and not (st[0][0] == 'ident' and st[1][0] == 'punct' and st[1][1] == '='):
            raise YaraSplitError(f'bad meta entry in {cur["name"]}')
        return


def _yara_number(text: str) -> int | float:
    if text.lower().startswith('0x'):
        return int(text, 16)
    mult = 1
    if text.endswith('KB'):
        mult, text = 1024, text[:-2]
    elif text.endswith('MB'):
        mult, text = 1024 * 1024, text[:-2]
    return float(text) * mult if '.' in text else int(text) * mult


_FORGE_FIELD = re.compile(r'^\s*\*\s*([A-Za-z][A-Za-z \-()]*?):\s*(.*?)\s*$', re.M)


def _comment_fields(comment: str) -> dict:
    head = comment.split('LICENSE', 1)[0]
    return {k.strip(): v.strip() for k, v in _FORGE_FIELD.findall(head)}


def _comment_licence_text(comment: str) -> str:
    if 'LICENSE' not in comment:
        return ''
    body = comment.split('LICENSE', 1)[1]
    lines = [ln.strip().lstrip('*').strip() for ln in body.splitlines()]
    return '\n'.join(ln for ln in lines if ln and ln != '/').strip()


def forge_source_prefix(repo_name: str | None) -> str | None:
    """Rule-name prefix YARA Forge adds for a repository ('Signature Base' -> 'SIGNATURE_BASE').  P272 c7
    must test SUSP_/HKTL_/PUA_ after this prefix (observed in package 20261122)."""
    if not repo_name:
        return None
    return re.sub(r'[^A-Za-z0-9]+', '_', repo_name).strip('_').upper() or None


def forge_split_package(text: str) -> dict:
    """Split a YARA Forge package (.yar) into package header, imports and rule sets (P272 c2, c3, c5, c7).

    package: name, description, forge_version, qa_commit, minimum_quality, minimum_score, creation_date,
    number_of_rules, skipped.  rule_sets: name, repository, retrieval_date, commit, number_of_rules, skipped,
    licence_text (the repository LICENSE Forge embeds), licence (detected SPDX-like id or None), prefix,
    rules (from yara_split).  Rules before the first set header go to rule set None."""
    sp = yara_split(text)
    pkg: dict = {}
    sets: list[dict] = []
    for start, _end, comment in sp['comments']:
        if 'YARA-Forge YARA Rule Package' in comment and not pkg:
            f = _comment_fields(comment)
            pkg = {
                'name': f.get('Name'), 'description': f.get('Description'),
                'forge_version': f.get('YARA-Forge Version'), 'qa_commit': f.get('YARA-QA Commit'),
                'minimum_quality': as_int(f.get('Minimum Quality')), 'minimum_score': as_int(f.get('Minimum Score')),
                'creation_date': f.get('Creation Date'), 'number_of_rules': as_int(f.get('Number of Rules')),
                'skipped': f.get('Skipped'),
            }
        elif 'YARA Rule Set' in comment:
            f = _comment_fields(comment)
            lic_text = _comment_licence_text(comment)
            sets.append({
                'start': start, 'name': f.get('Repository Name'), 'repository': f.get('Repository'),
                'retrieval_date': f.get('Retrieval Date'), 'commit': f.get('Git Commit'),
                'number_of_rules': as_int(f.get('Number of Rules')), 'skipped': f.get('Skipped'),
                'licence_text': lic_text[:4000], 'licence': detect_licence_text(lic_text),
                'prefix': forge_source_prefix(f.get('Repository Name')), 'rules': [],
            })
    starts = [s['start'] for s in sets]
    orphan: list[dict] = []
    for rule in sp['rules']:
        idx = bisect.bisect_right(starts, rule['start']) - 1
        if idx < 0:
            orphan.append(rule)
        else:
            rule['rule_set'] = sets[idx]['name']
            sets[idx]['rules'].append(rule)
    for s in sets:
        s.pop('start', None)
    return {'package': pkg, 'imports': sp['imports'], 'includes': sp['includes'], 'rule_sets': sets,
            'rules_outside_sets': orphan, 'repo_licences': forge_repo_licences(sets)}


def yara_source_for_rules(imports: Iterable[str], rule_texts: Iterable[str]) -> str:
    """Rebuild a compilable source: the package imports first, then the selected rules (P272 c2)."""
    head = ''.join(f'import "{i}"\n' for i in dict.fromkeys(imports) if re.fullmatch(r'[a-z0-9_]{1,32}', i))
    return head + '\n' + '\n\n'.join(rule_texts) + '\n'


_LICENCE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r'no licen[cs]e set', 'NONE'),
    (r'\bnon[- ]?commercial\b|\bcc[- ]by[- ]nc\b|by-nc', 'CC-BY-NC'),
    (r'detection rule licen[cs]e|\bdrl[- ]?1\.1\b', 'DRL-1.1'),
    (r'\bcc[- ]by[- ]sa\b|creativecommons\.org/licenses/by-sa', 'CC-BY-SA-4.0'),
    (r'\bcc0\b|creativecommons\.org/publicdomain/zero', 'CC0-1.0'),
    (r'\bcc[- ]by(?: 4\.0)?\b|creativecommons\.org/licenses/by/', 'CC-BY-4.0'),
    (r'gnu lesser general public licen[cs]e|\blgpl', 'LGPL'),
    (r'gnu affero|\bagpl', 'AGPL-3.0'),
    (r'gnu general public licen[cs]e(?:.|\n){0,200}?version 3|\bgpl-?3|\bgplv3', 'GPL-3.0'),
    (r'gnu general public licen[cs]e(?:.|\n){0,200}?version 2|\bgpl-?2|\bgplv2', 'GPL-2.0'),
    (r'gnu general public licen[cs]e|\bgpl\b', 'GPL'),
    (r'elastic licen[cs]e', 'Elastic-2.0'),
    (r'apache licen[cs]e(?:.|\n){0,80}?2\.0|apache-2\.0|apache 2\.0', 'Apache-2.0'),
    (r'\bmit licen[cs]e\b|^\s*mit\s*$|permission is hereby granted, free of charge, to any person obtaining a copy\s+of this software', 'MIT'),
    (r'bsd 3-clause|3-clause bsd|neither the name of', 'BSD-3-Clause'),
    (r'bsd 2-clause|2-clause bsd|redistribution and use in source and binary forms', 'BSD-2-Clause'),
    (r'\bisc licen[cs]e\b', 'ISC'),
)
LICENCE_CLASS = {
    # P272 c3: permissive + DRL 1.1 = 'open'; NC = 'noncommercial'; c4: unknown/missing never loaded.
    'MIT': 'open', 'BSD-2-Clause': 'open', 'BSD-3-Clause': 'open', 'Apache-2.0': 'open', 'ISC': 'open',
    'CC0-1.0': 'open', 'CC-BY-4.0': 'open', 'DRL-1.1': 'open',
    'CC-BY-NC': 'noncommercial',
    # Not named by P272 c3: copyleft/source-available rules wait for a legal decision -> 'license' (A1:
    # runs only with a licence_allow entry).  Malpedia is 'noncommercial' by A1's binding initial classes.
    'CC-BY-SA-4.0': 'license', 'GPL-3.0': 'license', 'GPL-2.0': 'license', 'GPL': 'license',
    'AGPL-3.0': 'license', 'LGPL': 'license', 'Elastic-2.0': 'license',
}


def detect_licence_text(text: str | None) -> str | None:
    """SPDX-like id for a licence string or LICENSE text; None when absent ('NO LICENSE SET', empty, 'N/A')
    or unrecognised.  The heading (first 1000 chars) decides first, because full GPL-3.0 texts mention the
    LGPL and AGPL near the end; DRL is tested before MIT (DRL reuses the MIT grant) and NC before CC BY.
    P272 c3, c4."""
    t = (as_str(text, 200000) or '').lower()
    if not t or t in ('n/a', 'na', 'none', '-', 'unknown'):
        return None
    for chunk in (t[:1000], t[:60000]):
        for pat, spdx in _LICENCE_PATTERNS:
            if re.search(pat, chunk, re.M):
                return None if spdx == 'NONE' else spdx
    return None


def repo_key(url: str | None) -> str:
    """'https://github.com/Owner/Repo//blob/<sha>/LICENSE' -> 'github.com/owner/repo' ('' if not a repo URL)."""
    u = as_str(url, 2000) or ''
    p = urllib.parse.urlsplit(u.lower())
    parts = [x for x in p.path.split('/') if x]
    return f'{p.netloc}/{parts[0]}/{parts[1]}' if p.netloc and len(parts) >= 2 else ''


def forge_repo_licences(rule_sets: Iterable[dict]) -> dict:
    """Map repo_key -> detected licence for every rule set of a package (P272 c3: a rule's license_url or
    'See license at <url>' meta is resolved through the LICENSE text Forge embeds for that repository)."""
    out = {}
    for rs in rule_sets:
        key = repo_key(rs.get('repository'))
        if key:
            out[key] = rs.get('licence')
    return out


def yara_rule_licence(meta: dict | None, rule_set: dict | None = None,
                      repo_licences: dict | None = None) -> dict:
    """Per-rule licence decision from meta (P272 c3, c4; A1 initial classes for Malpedia).

    Order: meta 'license' naming a licence -> meta 'malpedia_license' -> a URL in meta 'license' ('See
    license at <url>') or meta 'license_url', resolved through repo_licences (the LICENSE texts Forge embeds,
    keyed by repo_key) -> unknown.  'N/A' and unresolvable URLs give class 'unknown' = never loaded in any
    profile.  Malpedia rules are 'noncommercial' (A1 binding class) whatever their CC BY-SA meta says.
    Returns {'spdx', 'class', 'evidence', 'attribution_required'}."""
    meta = meta if isinstance(meta, dict) else {}
    repo_licences = dict(repo_licences or {})
    own = repo_key(rule_set.get('repository')) if rule_set else ''
    if own and own not in repo_licences:
        repo_licences[own] = rule_set.get('licence')
    lic = as_str(meta.get('license'), 2000)
    mal = as_str(meta.get('malpedia_license'), 200)
    url = as_str(meta.get('license_url'), 2000)
    spdx, evidence = None, 'missing'
    if lic:
        spdx = detect_licence_text(lic)
        evidence = 'meta:license'
        if spdx is None:
            m = re.search(r'https?://\S+', lic)
            if m and repo_licences.get(repo_key(m.group())):
                spdx, evidence = repo_licences[repo_key(m.group())], 'meta:license url->repository LICENSE'
    if spdx is None and mal:
        spdx, evidence = detect_licence_text(mal), 'meta:malpedia_license'
    if spdx is None and url and url.upper() != 'N/A' and repo_licences.get(repo_key(url)):
        spdx, evidence = repo_licences[repo_key(url)], 'meta:license_url->repository LICENSE'
    cls = LICENCE_CLASS.get(spdx or '', 'unknown')
    is_malpedia = bool(mal) or (rule_set is not None and (rule_set.get('name') or '').lower() == 'malpedia')
    if is_malpedia and cls != 'unknown':
        cls = 'noncommercial'
    credit = bool(lic and re.search(r'credit|attribution', lic, re.I))
    return {'spdx': spdx, 'class': cls, 'evidence': evidence if spdx else 'missing',
            'attribution_required': credit or spdx in ('DRL-1.1', 'CC-BY-4.0', 'CC-BY-SA-4.0')}


def yara_rule_kind(name: str, meta: dict | None, rule_set_name: str | None = None) -> dict:
    """Classify a rule for result wording (P272 c7).

    generic: SUSP_/HKTL_/PUA_ prefix after removing the Forge source prefix, score < 70, or meta
    category 'hunting' -> 'suspicious' low-severity context only.  family: a family meta key with a value
    -> malware_family pivot (low confidence).  specific: anything else -> context, no pivot.  Never
    'malicious'."""
    meta = meta if isinstance(meta, dict) else {}
    nm = as_str(name, 256) or ''
    prefix = forge_source_prefix(rule_set_name)
    core = nm[len(prefix) + 1:] if prefix and nm.upper().startswith(prefix + '_') else nm
    first = re.split(r'[_\W]', core, maxsplit=1)[0].upper() if core else ''
    score = as_int(meta.get('score'))
    reasons = []
    if first in YARA_GENERIC_PREFIXES:
        reasons.append(f'prefix {first}_')
    if score is not None and score < YARA_GENERIC_SCORE_BELOW:
        reasons.append(f'score {score} < {YARA_GENERIC_SCORE_BELOW}')
    if (as_str(meta.get('category')) or '').lower() == 'hunting':
        reasons.append('category hunting')
    family_raw = None
    for key in YARA_FAMILY_META_KEYS:
        v = as_str(meta.get(key), 200)
        if v:
            family_raw = v
            break
    if reasons:
        return {'kind': 'generic', 'label': 'suspicious', 'severity': 'low', 'reasons': reasons,
                'original_name': core, 'family': None, 'family_raw': family_raw}
    if family_raw:
        return {'kind': 'family', 'label': 'family match (low confidence)', 'severity': 'medium',
                'reasons': ['family meta'], 'original_name': core, 'family': normalize_family(family_raw),
                'family_raw': family_raw}
    return {'kind': 'specific', 'label': 'rule match (context)', 'severity': 'low', 'reasons': [],
            'original_name': core, 'family': None, 'family_raw': None}


def normalize_family(raw: str | None) -> str | None:
    """'Backdoor:W32/Pwnlnx' -> 'Pwnlnx', 'Ransom/XINOF' -> 'XINOF', 'win.lockbit' -> 'lockbit',
    'SUNSPOT' -> 'SUNSPOT' (values observed in Forge core 20261122).  P272 c7."""
    v = as_str(raw, 200)
    if not v:
        return None
    if re.fullmatch(r'(win|elf|osx|apk|js|jar|ps1|vbs|py|php|asp|aspx)\.[a-z0-9_\-]+', v, re.I):
        v = v.split('.', 1)[1]
    if '/' in v:
        v = v.rsplit('/', 1)[1]
    elif ':' in v:
        v = v.rsplit(':', 1)[1]
    v = v.strip(' ._-')
    return v or None


def select_yara_rules(rule_sets: list[dict], profile: str = 'corporate', allowed_classes: Iterable[str] = (),
                      package: str = 'core') -> dict:
    """Licence gate per rule (P272 c3, c4, c5; A1).

    corporate loads class 'open' plus classes listed in allowed_classes (a licence_allow decision);
    research loads 'open', 'noncommercial' and 'license'; 'unknown' never loads.  Rules that reference an
    excluded rule are excluded too (reason 'dependency').  Returns loaded rules grouped per rule set,
    exclusion counts per reason and the coverage line 'N rules excluded: licence'."""
    allowed = {'open'} | set(allowed_classes)
    if profile == 'research':
        allowed |= {'noncommercial', 'license'}
    allowed.discard('unknown')
    decisions: dict[str, dict] = {}
    by_name: dict[str, dict] = {}
    repo_map = forge_repo_licences(rule_sets)
    for rs in rule_sets:
        for r in rs.get('rules', []):
            lic = yara_rule_licence(r.get('meta'), rs, repo_map)
            decisions[r['name']] = {'rule': r, 'set': rs.get('name'), 'licence': lic,
                                    'excluded': None if lic['class'] in allowed else 'licence'}
            by_name[r['name']] = r
    changed = True
    while changed:
        changed = False
        for d in decisions.values():
            if d['excluded']:
                continue
            for ref in d['rule'].get('refs', []):
                if ref in decisions and decisions[ref]['excluded']:
                    d['excluded'] = 'dependency'
                    changed = True
                    break
    loaded: dict[str, list[dict]] = {}
    counts = {'loaded': 0, 'licence': 0, 'dependency': 0}
    by_class: dict[str, int] = {}
    for d in decisions.values():
        cls = d['licence']['class']
        by_class[cls] = by_class.get(cls, 0) + 1
        if d['excluded']:
            counts[d['excluded']] += 1
        else:
            counts['loaded'] += 1
            loaded.setdefault(d['set'] or '-', []).append(d['rule'])
    excluded = counts['licence'] + counts['dependency']
    line = f'{excluded} rules excluded: licence' if excluded else None
    return {'package': package, 'profile': profile, 'loaded': loaded, 'counts': counts, 'by_class': by_class,
            'coverage_line': line}


def normalize_yara_matches(dump: Any, package_version: str | None = None,
                           rules_index: dict | None = None) -> dict:
    """Normalise the yara_child() dump into hits (P272 c7; DRL attribution kept, P272 c3).

    dump: {'matches': [{'rule','namespace','tags','meta','strings':[{'identifier','count','offsets'}]}],
    'error': None|'timeout'|..., 'elapsed_s'}.  rules_index maps rule name -> {'rule_set', ...} when known.
    Each hit: rule, original_name, rule_set, author, reference, source_url, score, package_version, kind,
    label, severity, family (pivot only for kind 'family', confidence 'low'), licence, strings summary.
    status: 'match' | 'no_match' | 'error' (reason_code 'timeout' or 'error')."""
    if not isinstance(dump, dict):
        return {'status': 'error', 'reason_code': 'error', 'reason': 'child output is not an object', 'hits': [],
                'pivots': []}
    err = as_str(dump.get('error'), 300)
    if err:
        code = 'timeout' if 'timeout' in err.lower() else 'error'
        reason = (f'YARA match timed out after {YARA_MATCH_TIMEOUT_S} s' if code == 'timeout'
                  else f'YARA error: {err}')
        return {'status': 'error', 'reason_code': code, 'reason': reason, 'hits': [], 'pivots': []}
    hits, pivots = [], []
    matches = dump.get('matches')
    for m in matches if isinstance(matches, list) else []:
        if not isinstance(m, dict):
            continue
        name = as_str(m.get('rule'), 256)
        if not name:
            continue
        meta = m.get('meta') if isinstance(m.get('meta'), dict) else {}
        info = (rules_index or {}).get(name, {})
        ns = as_str(m.get('namespace'), 128)
        rs_name = info.get('rule_set') or (ns if ns and ns != 'default' else None)
        kind = yara_rule_kind(name, meta, rs_name)
        strings = []
        for s in m.get('strings') or []:
            if isinstance(s, dict) and as_str(s.get('identifier'), 64):
                offs = [o for o in (s.get('offsets') or []) if isinstance(o, int) and o >= 0][:10]
                strings.append({'identifier': as_str(s.get('identifier'), 64),
                                'count': as_int(s.get('count')) or len(offs), 'offsets': offs})
        hit = {
            'rule': name, 'original_name': kind['original_name'], 'rule_set': rs_name,
            'namespace': as_str(m.get('namespace'), 64),
            'tags': [t for t in (as_str(x, 64) for x in m.get('tags') or []) if t],
            'author': as_str(meta.get('author'), 300), 'reference': as_str(meta.get('reference'), 500),
            'source_url': as_str(meta.get('source_url'), 500), 'score': as_int(meta.get('score')),
            'description': as_str(meta.get('description'), 500),
            'package_version': package_version, 'kind': kind['kind'], 'label': kind['label'],
            'severity': kind['severity'], 'reasons': kind['reasons'], 'family': kind['family'],
            'licence': info.get('licence') or yara_rule_licence(meta, None).get('spdx'),
            'strings': strings, 'verdict': None,
        }
        hits.append(hit)
        if kind['kind'] == 'family' and kind['family']:
            pivots.append({'type': 'malware_family', 'value': kind['family'], 'confidence': 'low',
                           'relation': 'yara_family_rule', 'source_rule': name, 'expand': False})
    hits.sort(key=lambda h: ({'family': 0, 'specific': 1, 'generic': 2}[h['kind']], -(h['score'] or 0), h['rule']))
    dedup = {}
    for p in pivots:
        dedup.setdefault(p['value'].lower(), p)
    return {'status': 'match' if hits else 'no_match', 'reason_code': None,
            'reason': None if hits else 'no YARA rule matched (not a verdict: rules cover known families only)',
            'hits': hits, 'pivots': list(dedup.values())}


def yara_coverage_table(selection: dict, compile_report: dict | None = None) -> list[dict]:
    """Rows for the coverage appendix (P272 c2, c4): loaded / excluded (licence, dependency) / failed to
    compile, per package."""
    c = selection.get('counts', {})
    rows = [{'item': 'rules loaded', 'count': c.get('loaded', 0)},
            {'item': 'rules excluded: licence', 'count': c.get('licence', 0)},
            {'item': 'rules excluded: dependency on an excluded rule', 'count': c.get('dependency', 0)}]
    if compile_report:
        rows.append({'item': 'rules failed to compile', 'count': int(compile_report.get('failed_rules', 0))})
        rows.append({'item': 'source groups failed', 'count': int(compile_report.get('failed_groups', 0))})
    return rows


# ======================================================================================================
# Sandbox child (runs ONLY inside core/sandbox.py; yara imported inside the function)
# ======================================================================================================

MAX_HITS = 256
MAX_OFFSETS = 10


def compile_rule_sets(yara: Any, imports: list[str], sets: list[dict[str, Any]]) -> tuple[dict[str, str], dict[str, Any]]:
    """c2: compile one namespace per rule set from SOURCE (includes disabled); a failing set is retried rule by
    rule so only the broken rules drop; failures are counted. Returns (namespace -> source, report)."""
    sources: dict[str, str] = {}
    report: dict[str, Any] = {"groups": 0, "failed_groups": 0, "failed_rules": 0, "errors": []}
    for st in sets:
        report["groups"] += 1
        texts = [r["text"] for r in st.get("rules") or []]
        try:
            yara.compile(source=yara_source_for_rules(imports, texts), includes=False)
            sources[st["namespace"]] = yara_source_for_rules(imports, texts)
            continue
        except yara.SyntaxError as exc:
            report["failed_groups"] += 1
            report["errors"].append({"namespace": st["namespace"], "error": str(exc)[:300]})
        keep: list[str] = []
        for r in st.get("rules") or []:
            try:
                yara.compile(source=yara_source_for_rules(imports, [*keep, r["text"]]), includes=False)
                keep.append(r["text"])
            except yara.SyntaxError as exc:
                report["failed_rules"] += 1
                report["errors"].append({"namespace": st["namespace"], "rule": r.get("name"), "error": str(exc)[:300]})
        if keep:
            sources[st["namespace"]] = yara_source_for_rules(imports, keep)
    report["errors"] = report["errors"][:20]
    return sources, report


def yara_scan_child(data: bytes, rules_path: str, allowed_classes: list[str], package: str = "core",
                    timeout: int = YARA_MATCH_TIMEOUT_S) -> dict[str, Any]:
    """c2-c7 sandbox child: split the Forge package SOURCE, select rules by licence class, compile per rule set
    and match ``data`` with the 30 s timeout. Returns offsets and counts only, never the matched bytes."""
    import yara

    with open(rules_path, encoding="utf-8", errors="replace") as fh:
        text = fh.read(YARA_MAX_SOURCE_CHARS + 1)
    try:
        split = forge_split_package(text)
    except YaraSplitError as exc:
        return {"error": f"rule package unreadable: {exc}"}
    selection = select_yara_rules(split["rule_sets"], "corporate", allowed_classes, package)
    sets = [{"namespace": ns, "rules": rules} for ns, rules in selection["loaded"].items()]
    sources, report = compile_rule_sets(yara, split["imports"], sets)
    out: dict[str, Any] = {"package": split["package"], "includes_ignored": split["includes"][:20],
                           "selection": {k: selection[k] for k in ("counts", "by_class", "coverage_line")}, "compile": report}
    if not sources:
        return {**out, "error": "no rule compiled"}
    rules = yara.compile(sources=sources, includes=False)
    try:
        matches = rules.match(data=data, timeout=int(timeout))
    except yara.TimeoutError:
        return {**out, "error": "timeout"}
    except yara.Error as exc:
        return {**out, "error": str(exc)[:300]}
    hits = []
    for m in matches[:MAX_HITS]:
        strings = []
        for s in m.strings[:64]:
            inst = list(s.instances)
            strings.append({"identifier": s.identifier, "count": len(inst), "offsets": [i.offset for i in inst[:MAX_OFFSETS]]})
        hits.append({"rule": m.rule, "namespace": m.namespace, "tags": list(m.tags), "meta": dict(m.meta), "strings": strings})
    return {**out, "matches": hits}


# ======================================================================================================
# The module
# ======================================================================================================

SCAN_LIMITS = {"wall_timeout": 120.0, "cpu_seconds": 90}
_FAMILY = ["yara_match"]


def allowed_classes(ctx: Any) -> list[str]:
    """Licence classes the policy gate lets this run load (c3/c4): open with the core source, plus license /
    noncommercial with their sources (licence_allow or research). 'unknown' is never a class to load."""
    allowed = set(getattr(ctx, "allowed_sources", None) or ())
    return sorted(cls for src, cls in CLASS_BY_SOURCE.items() if src in allowed)


@register
class YaraScan(Module):
    name = "yara_scan"
    title = "YARA scan (YARA Forge rules, local)"
    description = (
        "Scans a local file with the YARA Forge rule package (core by default) compiled locally from source, rules "
        "filtered per licence; generic hits are context, family rules give a low-confidence malware family."
    )
    category = "file_analysis"
    accepts = {T.FILE}
    produces = {T.MALWARE}
    reference = "https://github.com/YARAHQ/yara-forge"
    tags = {"offline"}
    notice = (
        "Rule licences vary per rule: non-commercial rules (e.g. Malpedia) are off under the corporate profile until "
        "licence-cleared, rules without a licence never load. A YARA hit is context, never a 'malicious' verdict on its own."
    )
    terms = "noncommercial"  # A1 aggregator rule: the most restrictive class of its rule sources
    opsec = Opsec.PASSIVE
    disclosure = "none"  # local files only; the rule package is a dataset
    hosts = ()
    sources = (SRC_OPEN, SRC_LICENSE, SRC_NC)
    access_model = "offline"
    requires_packages = ("yara",)
    max_requests = 0
    expected_latency = 3.0
    timeout = 180.0
    max_pivots = 10
    default_enabled = False  # opt-in (c1)
    settings = {"yara_scan_package": "core"}

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        package = str(ctx.setting("yara_scan_package", "core") or "core").lower()
        if package not in PACKAGES:
            return res.mark("skipped", f"setting yara_scan_package must be one of {', '.join(PACKAGES)}", reason_code="config")
        classes = allowed_classes(ctx)
        if "open" not in classes and not classes:
            return res.mark("skipped", "no rule licence class is allowed for this run", reason_code="licence")
        try:
            read_regular_file(entity.value)  # local regular files of at most 100 MB only
            if core_sandbox() is None:
                raise SandboxUnavailable("YARA runs only inside the file-analysis sandbox (core/sandbox.py), which this build does not have")
            rules_path = str(ctx.data.fetch(f"yara_scan.forge_{package}"))
            info = ctx.data.info(f"yara_scan.forge_{package}")
            out = sandbox_run(f"{__name__}:yara_scan_child", entity.value,
                              args={"rules_path": rules_path, "allowed_classes": classes, "package": package,
                                    "timeout": YARA_MATCH_TIMEOUT_S}, **SCAN_LIMITS)
        except InputRefused as exc:
            return res.mark(exc.status, str(exc), reason_code=exc.code)
        except SandboxUnavailable as exc:
            return res.mark("unavailable", str(exc), reason_code="package")
        if not out.get("ok"):
            code, reason = sandbox_failure(out)
            return res.mark("error", reason, reason_code=code)
        return self.emit(res, out.get("result"), package, getattr(info, "sha256", "") or "", classes)

    def emit(self, res: ModuleResult, dump: Any, package: str, sha256: str, classes: list[str]) -> ModuleResult:
        """Attributes, findings and pivots of one child result (c4, c7)."""
        if not isinstance(dump, dict):
            return res.mark("error", "YARA child returned no result object")
        pkg = dump.get("package") if isinstance(dump.get("package"), dict) else {}
        version = " ".join(x for x in (as_str(pkg.get("name"), 80), as_str(pkg.get("forge_version"), 20), as_str(pkg.get("creation_date"), 20)) if x) or package
        selection = dump.get("selection") if isinstance(dump.get("selection"), dict) else {}
        compile_report = dump.get("compile") if isinstance(dump.get("compile"), dict) else {}
        coverage = {"package": package, "package_version": version, "dataset_sha256": sha256, "classes_loaded": classes,
                    "rows": yara_coverage_table(selection, compile_report), "coverage_line": selection.get("coverage_line"),
                    "includes_ignored": dump.get("includes_ignored") or []}
        norm = normalize_yara_matches(dump, version)
        res.raw = {"coverage": coverage, "hits": norm["hits"][:50], "error": norm.get("reason") if norm["status"] == "error" else None}
        if norm["status"] == "error":
            return res.mark("error", str(norm["reason"]), reason_code=str(norm.get("reason_code") or "error"))
        res.attr("yara_coverage", coverage)
        if norm["status"] == "no_match":
            return res.mark("empty", str(norm["reason"]))
        res.attr("yara_rules", [h["rule"] for h in norm["hits"]])
        res.attr("yara_hits", norm["hits"][:50])
        for i, hit in enumerate(norm["hits"][:50]):
            credit = f"rule {hit['original_name']} ({hit.get('rule_set') or 'unknown set'}) by {hit.get('author') or 'unknown author'}"
            if hit.get("reference"):
                credit += f", reference {hit['reference']}"
            data = {k: hit.get(k) for k in ("rule", "rule_set", "author", "reference", "source_url", "score", "package_version", "licence", "reasons")}
            if hit["kind"] == "generic":
                res.finding("YARA generic rule matched (suspicious, context only)", "low",
                            f"{credit}. Generic/heuristic rule ({', '.join(hit['reasons'])}): context, not a verdict.",
                            confidence="possible", criterion="YARA Forge generic or heuristic rule (SUSP_/HKTL_/PUA_ or score < 70, P272 c7)",
                            tags=["suspicious", "context_only", "yara_match"], data=data, key=hit["rule"] or str(i))
            elif hit["kind"] == "family":
                res.finding("YARA family rule matched", "medium",
                            f"{credit}: family {hit['family']} (low confidence; a YARA hit alone is not a verdict).",
                            confidence="possible", criterion="family-specific YARA Forge rule with a family meta matched the file (P272 c7)",
                            tags=_FAMILY, data=data, key=hit["rule"] or str(i))
            else:
                res.finding("YARA rule matched", "low", f"{credit}. Context, not a verdict.", confidence="possible",
                            criterion="YARA Forge rule matched the file (no family meta: no attribution, P272 c7)",
                            tags=_FAMILY, data=data, key=hit["rule"] or str(i))
        for p in norm["pivots"]:
            res.pivot(T.MALWARE, p["value"], "yara_family_rule", confidence="possible", expand=False,
                      note=f"family meta of YARA rule {p['source_rule']} (low confidence, not a verdict)")
        return res

