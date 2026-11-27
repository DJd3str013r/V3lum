"""Secret detection with the gitleaks ruleset (P312, batch p1-G03-1): a shared offline engine plus a
module for text blobs, local files and JWTs.

The engine is a library: ``scan_text(text, path=...)`` returns findings that carry only masked values,
and other modules (js_endpoints, public_api_exposure, archive_mining, email_header_analyzer, the
P172 text extraction) call it on content they already hold. It never fetches anything (c1).

Rules: ``v3lum/data/secret_scanner/gitleaks.toml`` is the unmodified gitleaks configuration
(https://github.com/gitleaks/gitleaks, config/gitleaks.toml, MIT, Copyright (c) 2019 Zachary Rice;
notice fragment ``gitleaks``). Its 222 rules (221 regex + 1 path-only) use Go RE2 syntax: 26 are
rewritten for Python ``re`` at load time (mid-pattern ``(?i)`` scoped per alternative, ``\\z`` ->
``\\Z``, POSIX classes such as ``[[:alnum:]]`` expanded - Python accepts that one silently with
another meaning) and compiled with ``re.ASCII`` like RE2; five doubled lazy prefixes are collapsed
to keep Python's backtracking linear-ish. ``google-re2`` (optional extra, ``re2``) runs the original
patterns when installed. Six V3LUM-authored rules cover phishing-kit exfiltration channels gitleaks
misses (Telegram bot tokens in ``api.telegram.org/bot<token>`` URLs and bare, Discord webhooks, SMTP
URLs, SMTP/mail password assignments, PHPMailer ``->Password``) (c8). trufflehog (AGPL) was read as
architecture reference only: no code or detector was copied (A6).

Pipeline (c2): input cap 5 MB, lines truncated at 10k characters -> lower-case keyword prefilter ->
regex (prefix-heavy rules only inside windows around keyword hits) -> secret group (secretGroup, else
the first non-empty group, else the match) -> Shannon entropy above the rule threshold (generic rules
also need a digit) -> gitleaks allowlists (global and per rule) -> the V3LUM allowlist of documented
examples and placeholders (c3). The ReDoS harness (``redos_probe_inputs``) runs every compiled
pattern on adversarial strings in the test suite (per-pattern time budget).

Masking (c4, c5): tokens/keys of 20+ characters are kept as rule + first 4/last 4 + SHA-256; shorter
secrets as rule + SHA-256 only; password-type values (config passwords, SMTP credentials, generic
matches on password-like keys) show no character and keep no digest at all (a hash of a password is a
password hash: rule 3) - their findings are keyed by location. The raw secret exists only in memory
during the scan and never reaches findings, attributes, ``res.raw``, evidence, events or reports.

Use (c6): secrets are SECRET_TYPES - never validated against a provider (no login, no API call: that
would be using someone else's credential), never pivoted, never sent anywhere as a search value. The
local SHA-256 is the only handle (dedupe and sightings). Severity comes from context only (c7): the
organisation's own credentials HIGH/CRITICAL with a notify recommendation, third-party credentials
MEDIUM with an owner-notification recommendation, phishing-kit channels MEDIUM with an abuse-report
recommendation, provider-specific rules with no owner context MEDIUM/HIGH, generic/entropy-only
matches an info count; one finding per secret with N locations.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import datetime as _dt
import functools
import hashlib
import json
import math
import os
import re
import threading
from collections.abc import Iterable
from typing import Any

from v3lum.core.datasets import DataStore
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    try:
        import tomli as _toml  # type: ignore[no-redef]
    except ModuleNotFoundError:
        _toml = None  # type: ignore[assignment]

try:  # optional extra 're2' (google-re2): linear-time matching of the original RE2 patterns
    import re2 as _re2  # type: ignore[import-not-found]
except ImportError:
    _re2 = None

__all__ = [
    "CRITICAL_RULES",
    "GENERIC_RULES",
    "MAX_INPUT_BYTES",
    "MAX_LINE",
    "RULESET",
    "V3LUM_EXTRA_RULES",
    "SecretScanner",
    "compile_rules",
    "convert_re2_to_python",
    "decode_jwt_unverified",
    "default_engine",
    "mask_secret",
    "optimise_backtracking",
    "parse_gitleaks_toml",
    "redos_probe_inputs",
    "scan_text",
    "secret_kind",
    "secret_severity",
    "shannon_entropy",
    "v3lum_allowlisted",
]

#: bundled ruleset (v3lum/data/<RULESET>): the unmodified gitleaks config/gitleaks.toml (MIT)
RULESET = "secret_scanner/gitleaks.toml"
#: c2: input cap per scan and per-line truncation
MAX_INPUT_BYTES = 5 * 1024 * 1024
MAX_LINE = 10_000
#: files larger than this are not read at all (the first MAX_INPUT_BYTES of smaller files are)
MAX_FILE_BYTES = 200 * 1024 * 1024
#: findings shown per run (the counts stay exact)
MAX_FINDINGS = 200


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character (gitleaks semantics)."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# =============================================================================================
# RE2 -> Python conversion (c2)
# =============================================================================================
_POSIX = {"alnum": "0-9A-Za-z", "alpha": "A-Za-z", "ascii": "\\x00-\\x7f", "blank": " \\t", "cntrl": "\\x00-\\x1f\\x7f",
          "digit": "0-9", "graph": "!-~", "lower": "a-z", "print": " -~", "punct": "!-/:-@\\[-`{-~",
          "space": "\\t\\n\\x0b\\x0c\\r ", "upper": "A-Z", "word": "0-9A-Za-z_", "xdigit": "0-9A-Fa-f"}
_INLINE_FLAG = re.compile(r"\(\?([a-zA-Z]*(?:-[a-zA-Z]+)?)\)")


def _posix_and_z(rx: str) -> str:
    out: list[str] = []
    i, in_cls = 0, False
    while i < len(rx):
        c = rx[i]
        if c == "\\" and i + 1 < len(rx):
            pair = rx[i:i + 2]
            out.append("\\Z" if (pair == "\\z" and not in_cls) else pair)
            i += 2
            continue
        if in_cls:
            if rx.startswith("[:", i):
                j = rx.find(":]", i + 2)
                name = rx[i + 2:j] if j > 0 else ""
                if name.startswith("^"):
                    raise ValueError(f"negated POSIX class [:{name}:] not supported")
                if name in _POSIX:
                    out.append(_POSIX[name])
                    i = j + 2
                    continue
            if c == "]" and not (out and out[-1] in ("[", "[^")):
                in_cls = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_cls = True
            if rx.startswith("[^", i):
                out.append("[^")
                i += 2
                if i < len(rx) and rx[i] == "]":
                    out.append("]")
                    i += 1
                continue
            out.append("[")
            i += 1
            if i < len(rx) and rx[i] == "]":
                out.append("]")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _scan_structure(rx: str) -> Iterable[tuple[int, str, int, bool, bool]]:
    """Yield (index, char, depth, in_class, escaped) for structural parsing."""
    depth, i, in_cls = 0, 0, False
    while i < len(rx):
        c = rx[i]
        if c == "\\":
            yield i, c, depth, in_cls, True
            i += 2
            continue
        if in_cls:
            if c == "]":
                in_cls = False
            yield i, c, depth, True, False
            i += 1
            continue
        if c == "[":
            in_cls = True
            yield i, c, depth, False, False
            i += 1
            if i < len(rx) and rx[i] == "^":
                i += 1
            if i < len(rx) and rx[i] == "]":
                i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        yield i, c, depth, False, False
        i += 1


def convert_re2_to_python(pattern: str) -> str:
    """Convert a Go RE2 pattern to Python ``re`` syntax (compile with ``re.ASCII``): ``\\z`` -> ``\\Z``,
    POSIX classes inside brackets expanded, and a mid-pattern global flag ``(?i)`` rewritten into
    scoped ``(?i:...)`` groups over each remaining alternative of the enclosing group (RE2 keeps the
    flag across ``|`` until the group closes). Raises ValueError on unsupported syntax."""
    if not isinstance(pattern, str):
        raise ValueError("pattern must be a string")
    if re.search(r"\(\?[a-zA-Z]*U", pattern):
        raise ValueError("RE2 ungreedy flag (?U) not supported")
    if "\\Q" in pattern or "\\p{" in pattern or "\\pL" in pattern:
        raise ValueError("RE2 \\Q..\\E / \\p classes not supported")
    rx = _posix_and_z(pattern)
    for _guard in range(64):
        target = None
        for idx, ch, _depth, in_cls, esc in _scan_structure(rx):
            if esc or in_cls or ch != "(":
                continue
            m = _INLINE_FLAG.match(rx, idx)
            if m and idx != 0 and m.group(1):
                target = m
                break
        if target is None:
            return rx
        flags = target.group(1)
        start, end_flag = target.start(), target.end()
        depth0, bars, close = 0, [], len(rx)
        for idx, ch, _depth, in_cls, esc in _scan_structure(rx[end_flag:]):
            if esc or in_cls:
                continue
            if ch == "(":
                depth0 += 1
            elif ch == ")":
                if depth0 == 0:
                    close = end_flag + idx
                    break
                depth0 -= 1
            elif ch == "|" and depth0 == 0:
                bars.append(end_flag + idx)
        segs, prev = [], end_flag
        for b in bars:
            segs.append(rx[prev:b])
            prev = b + 1
        segs.append(rx[prev:close])
        rx = rx[:start] + "|".join(f"(?{flags}:{s})" for s in segs) + rx[close:]
    raise ValueError("too many inline flags")


_DOUBLE_PREFIX = "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?"
_PREFIX_FAMILY = re.compile(r"^(?:\(\?i\))?(?:\(\?i:)?\[\\w\.-\]\{0,(?:50|100)\}\?")


def optimise_backtracking(py: str) -> str:
    """ReDoS mitigation for Python's backtracking engine: the doubled lazy prefix
    ``[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?`` (cisco-meraki, cohere, okta, privateai, sumologic rules) becomes
    ``(?i:[\\w.-]{0,100}?`` - same language and the same leftmost-lazy matches."""
    if py.startswith(_DOUBLE_PREFIX):
        return "(?i:[\\w.-]{0,100}?" + py[len(_DOUBLE_PREFIX):]
    return py


# =============================================================================================
# ruleset loading (c2, c3, c8)
# =============================================================================================
_PASSWORD_RULE_HINT = re.compile(r"(?i)passw(?:or)?d|pwd|senha|curl-auth-user|basic-auth")
GENERIC_RULES = frozenset({"generic-api-key"})
CRITICAL_RULES = frozenset({
    "private-key", "aws-access-token", "github-pat", "github-fine-grained-pat", "github-app-token", "github-oauth",
    "gitlab-pat", "azure-ad-client-secret", "gcp-service-account", "gcp-api-key", "vault-service-token",
    "hashicorp-tf-api-token", "stripe-access-token", "slack-bot-token", "slack-user-token",
})

#: V3LUM-authored rules (phishing-kit exfiltration, c8): gitleaks has no Discord-webhook or SMTP rule
#: and its Telegram rule needs a 'telegram...=' assignment.
V3LUM_EXTRA_RULES: tuple[dict[str, Any], ...] = (
    {"id": "v3lum-telegram-bot-token-url", "description": "Telegram Bot API token inside api.telegram.org/bot<token> (kit exfiltration)",
     "regex": r"(?i:api\.telegram\.org/bot)(\d{5,16}:A[A-Za-z0-9_-]{34})(?![A-Za-z0-9_-])", "keywords": ["api.telegram.org"],
     "entropy": 3.0, "secret_group": 1, "kind": "token", "tags": ["phishing_kit_exfil"]},
    {"id": "v3lum-telegram-bot-token-bare", "description": "Bare Telegram bot token '<id>:AA<33>' (kit configuration)",
     "regex": r"(?<![\w:])(\d{8,10}:AA[A-Za-z0-9_-]{33})(?![A-Za-z0-9_-])", "keywords": [":aa"],
     "entropy": 3.0, "secret_group": 1, "kind": "token", "tags": ["phishing_kit_exfil"]},
    {"id": "v3lum-discord-webhook-url", "description": "Discord webhook URL (kit exfiltration)",
     "regex": r"(?i:https?://(?:(?:canary|ptb)\.)?discord(?:app)?\.com/api/(?:v\d{1,2}/)?webhooks/)(\d{17,20})/([A-Za-z0-9_-]{60,100})",
     "keywords": ["discord"], "entropy": 3.0, "secret_group": 2, "kind": "token", "tags": ["phishing_kit_exfil"]},
    {"id": "v3lum-smtp-url-credentials", "description": "SMTP URL with embedded credentials",
     "regex": r"(?i:\bsmtps?://)([^:\s/@]{1,64}):([^@\s/]{3,128})@([A-Za-z0-9.-]{1,253})", "keywords": ["smtp://", "smtps://"],
     "entropy": None, "secret_group": 2, "kind": "password", "tags": ["phishing_kit_exfil"]},
    {"id": "v3lum-smtp-password-assignment", "description": "SMTP/mail password in a configuration assignment",
     "regex": r"""(?i:\b(?:smtp|mail)[_.-]?(?:pass(?:word)?|pwd|senha)\b)['"]?\s*(?:=>|=|:)\s*['"]([^'"\s]{3,128})['"]""",
     "keywords": ["smtp", "mail"], "entropy": None, "secret_group": 1, "kind": "password", "tags": ["phishing_kit_exfil"]},
    {"id": "v3lum-phpmailer-password", "description": "PHPMailer ->Password assignment",
     "regex": r"""->\s*Password\s*=\s*['"]([^'"]{3,128})['"]""", "keywords": ["->password"],
     "entropy": None, "secret_group": 1, "kind": "password", "tags": ["phishing_kit_exfil"]},
)

#: c3: documented example/test credentials and placeholders
V3LUM_ALLOW_EXACT = frozenset({
    "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw",
    # built by concatenation so the documented placeholder never appears as one literal in the source
    "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X" * 24,
})
V3LUM_ALLOW_PREFIXES = ("sk_test_", "pk_test_", "rk_test_", "whsec_test")
V3LUM_ALLOW_PATTERNS = tuple(re.compile(p, re.I | re.ASCII) for p in (
    r"^(?:x{4,}|\*{4,}|0{8,}|\.{4,}|#{4,})$",
    r"^(?:changeme|change_me|changeit|password|passw0rd|secret|example|dummy|placeholder|sample|test|testing|todo|none|null|undefined|redacted)$",
    r"^<[^>]{1,60}>$", r"^\$\{[^}]{1,60}\}$", r"^\{\{[^}]{1,60}\}\}$", r"^%[A-Z_]{1,40}%$",
    r"(?:your|my)[_-]?(?:api[_-]?)?(?:key|token|secret|password)", r"^replace[_-]?me$", r"EXAMPLE(?:KEY)?$",
))


def secret_kind(rule_id: str, context: str = "") -> str:
    """'password' for password-type rules or generic matches on password-like keys (no character is
    ever shown, no digest kept, c4), else 'token'."""
    rid = rule_id or ""
    if rid.startswith("v3lum-smtp") or rid == "v3lum-phpmailer-password" or _PASSWORD_RULE_HINT.search(rid):
        return "password"
    if rid in GENERIC_RULES and context and re.search(r"(?i)passw(?:or)?d|\bpwd\b|senha|\bpass\b", context):
        return "password"
    return "token"


def v3lum_allowlisted(secret: str) -> str | None:
    """c3: the reason when ``secret`` is a documented example/test credential or a placeholder."""
    s = (secret or "").strip().strip("'\"")
    if s in V3LUM_ALLOW_EXACT:
        return "documented example"
    if s.startswith(V3LUM_ALLOW_PREFIXES):
        return "test-mode key prefix"
    if any(rx.search(s) for rx in V3LUM_ALLOW_PATTERNS):
        return "placeholder"
    return None


def _conv_list(items: Any, errors: list[str], where: str) -> list[str]:
    out = []
    for item in items or []:
        if not isinstance(item, str):
            continue
        try:
            out.append(convert_re2_to_python(item))
        except ValueError as exc:
            errors.append(f"{where}: {exc}")
    return out


def _norm_allowlist(data: Any, errors: list[str], where: str) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    cond = str(data.get("condition") or "OR").upper()
    return {"description": data.get("description"), "condition": "AND" if cond == "AND" else "OR",
            "regex_target": str(data.get("regexTarget") or "secret").lower(), "regexes": _conv_list(data.get("regexes"), errors, where),
            "stopwords": [str(s).lower() for s in data.get("stopwords") or [] if isinstance(s, str)],
            "paths": _conv_list(data.get("paths"), errors, where)}


def parse_gitleaks_toml(raw: Any) -> dict[str, Any]:
    """gitleaks.toml -> ``{ok, error, title, min_version, rules[], allowlists[], stats}``. Each rule: id,
    description, regex (Python syntax), regex_source (RE2), converted, optimised, keywords (lower),
    entropy, secret_group, path, allowlists, compile_error, kind. Never raises."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw or "")
    out: dict[str, Any] = {"ok": False, "error": None, "title": None, "min_version": None, "rules": [], "allowlists": [], "stats": {}}
    if re.match(r"^\s*<", text):
        out["error"] = "html instead of toml"
        return out
    if _toml is None:
        out["error"] = "no TOML parser (Python 3.11+ tomllib or the tomli package is needed)"
        return out
    try:
        cfg = _toml.loads(text)
    except Exception as exc:  # noqa: BLE001 - tomllib.TOMLDecodeError or tomli's
        out["error"] = f"malformed toml: {exc}"
        return out
    errs: list[str] = []
    out["title"], out["min_version"] = cfg.get("title"), cfg.get("minVersion")
    glob: list[Any] = []
    if isinstance(cfg.get("allowlist"), dict):
        glob.append(cfg["allowlist"])
    if isinstance(cfg.get("allowlists"), list):
        glob.extend(a for a in cfg["allowlists"] if isinstance(a, dict))
    out["allowlists"] = [x for x in (_norm_allowlist(a, errs, "global allowlist") for a in glob) if x]
    n_conv = n_err = 0
    for r in cfg.get("rules") or []:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        rule: dict[str, Any] = {
            "id": str(r["id"]), "description": str(r.get("description") or ""), "regex": None, "regex_source": r.get("regex"),
            "converted": False, "optimised": False, "keywords": [str(k).lower() for k in r.get("keywords") or [] if isinstance(k, str)],
            "entropy": float(r["entropy"]) if isinstance(r.get("entropy"), (int, float)) and not isinstance(r.get("entropy"), bool) else None,
            "secret_group": int(r["secretGroup"]) if isinstance(r.get("secretGroup"), int) and not isinstance(r.get("secretGroup"), bool) else None,
            "path": None, "allowlists": [], "compile_error": None, "kind": None, "tags": [],
        }
        if isinstance(r.get("regex"), str):
            try:
                py = convert_re2_to_python(r["regex"])
                rule["converted"] = py != r["regex"]
                fast = optimise_backtracking(py)
                rule["optimised"] = fast != py
                re.compile(fast, re.ASCII)
                rule["regex"] = fast
                n_conv += rule["converted"]
            except (ValueError, re.error) as exc:
                rule["compile_error"] = str(exc)[:120]
                n_err += 1
        if isinstance(r.get("path"), str):
            try:
                rule["path"] = convert_re2_to_python(r["path"])
                re.compile(rule["path"], re.ASCII)
            except (ValueError, re.error) as exc:
                rule["compile_error"] = f"path: {exc}"[:120]
                rule["path"] = None
                n_err += 1
        rule["allowlists"] = [x for x in (_norm_allowlist(a, errs, rule["id"]) for a in r.get("allowlists") or []) if x]
        rule["kind"] = secret_kind(rule["id"])
        out["rules"].append(rule)
    out["ok"] = True
    out["error"] = "; ".join(errs[:5]) if errs else None
    rules = out["rules"]
    out["stats"] = {"rules": len(rules), "regex_rules": sum(1 for x in rules if x["regex_source"]),
                    "path_only": sum(1 for x in rules if x["path"] and not x["regex_source"]), "converted": n_conv,
                    "compile_errors": n_err, "with_entropy": sum(1 for x in rules if x["entropy"] is not None),
                    "with_keywords": sum(1 for x in rules if x["keywords"]),
                    "rule_allowlists": sum(len(x["allowlists"]) for x in rules), "optimised": sum(1 for x in rules if x["optimised"])}
    return out


def _compile(rule: dict[str, Any], use_re2: bool) -> tuple[Any, str]:
    """(compiled pattern, engine): google-re2 on the original RE2 pattern when available, else Python re."""
    if use_re2 and _re2 is not None and rule.get("regex_source") and not rule.get("v3lum"):
        try:
            return _re2.compile(rule["regex_source"]), "re2"
        except Exception:  # noqa: BLE001 - fall back to the converted pattern
            pass
    return re.compile(rule["regex"], re.ASCII), "re"


def compile_rules(parsed: dict[str, Any] | None, extra: Iterable[dict[str, Any]] = V3LUM_EXTRA_RULES, *, use_re2: bool = True) -> dict[str, Any]:
    """Compile the parsed gitleaks rules plus the V3LUM extra rules. Path-only rules and rules that do not
    compile are listed in ``skipped``."""
    rules, skipped = [], []
    base = list((parsed or {}).get("rules", []))
    extras = [dict(x, allowlists=[], regex_source=x["regex"], v3lum=True, description=x.get("description", "")) for x in extra or ()]
    for r in base + extras:
        if not r.get("regex"):
            skipped.append(r.get("id"))
            continue
        try:
            rx, engine = _compile(r, use_re2)
        except re.error:
            skipped.append(r.get("id"))
            continue
        rules.append({**r, "rx": rx, "engine": engine, "kind": r.get("kind") or secret_kind(r["id"]), "tags": list(r.get("tags") or [])})
    return {"rules": rules, "allowlists": (parsed or {}).get("allowlists", []), "skipped": skipped,
            "stats": (parsed or {}).get("stats", {}), "title": (parsed or {}).get("title"), "error": (parsed or {}).get("error")}


_ENGINE_LOCK = threading.Lock()


@functools.lru_cache(maxsize=1)
def _bundled_engine() -> dict[str, Any]:
    raw = DataStore.bundled_text(RULESET)
    parsed = parse_gitleaks_toml(raw)
    if not parsed["ok"]:
        return {"rules": [], "allowlists": [], "skipped": [], "stats": {}, "error": parsed["error"], "sha256": ""}
    engine = compile_rules(parsed)
    engine["sha256"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return engine


def default_engine() -> dict[str, Any]:
    """The compiled bundled ruleset (gitleaks + V3LUM extras), built once per process. ``error`` is set
    when the ruleset cannot be loaded (no TOML parser): callers report UNAVAILABLE."""
    with _ENGINE_LOCK:
        return _bundled_engine()


# =============================================================================================
# scanning (c2-c7)
# =============================================================================================
_DOMAIN_IN_LINE = re.compile(r"(?i)(?<![a-z0-9@._-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![a-z0-9-])")


def _keyword_windows(low: str, keywords: Iterable[str], before: int = 160, after: int = 2048, cap: int = 200_000) -> list[tuple[int, int]]:
    """Merged [start, end) windows around keyword hits; each window ends at a line break."""
    spans: list[tuple[int, int]] = []
    for kw in keywords:
        i = low.find(kw)
        while i >= 0 and len(spans) < cap:
            end = low.find("\n", i + len(kw) + after)
            spans.append((max(0, i - before), len(low) if end < 0 else end))
            i = low.find(kw, i + 1)
    spans.sort()
    merged: list[tuple[int, int]] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def _allow_match(al: dict[str, Any], secret: str, match: str, line: str, path: str | None) -> bool:
    target = {"secret": secret, "match": match, "line": line}.get(al["regex_target"], secret)
    checks = []
    if al["regexes"]:
        checks.append(any(re.search(rx, target or "", re.ASCII) for rx in al["regexes"]))
    if al["stopwords"]:
        low = (secret or "").lower()
        checks.append(any(w in low for w in al["stopwords"]))
    if al["paths"]:
        checks.append(bool(path) and any(re.search(rx, path, re.ASCII) for rx in al["paths"]))
    if not checks:
        return False
    return all(checks) if al["condition"] == "AND" else any(checks)


def mask_secret(secret: str, rule_id: str, kind: str = "token") -> dict[str, Any]:
    """c4: ``{rule, kind, display, sha256, length}``. Tokens of 20+ characters show first 4 / last 4 and
    keep their SHA-256; shorter tokens keep the SHA-256 only; passwords show nothing and keep no digest."""
    s = secret or ""
    if kind == "password":
        return {"rule": rule_id, "kind": "password", "display": "[password redacted]", "sha256": None, "length": None}
    digest = hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()
    display = f"{s[:4]}…{s[-4:]}" if len(s) >= 20 else "[redacted]"
    return {"rule": rule_id, "kind": "token", "display": display, "sha256": digest, "length": len(s)}


def _path_allowlisted(compiled: dict[str, Any], path: str | None) -> bool:
    """True when a global allowlist covers the whole file: a path match alone allowlists every match
    (an OR allowlist, or an AND allowlist with paths only)."""
    if not path:
        return False
    for al in compiled.get("allowlists") or []:
        if not al["paths"] or not any(re.search(rx, path, re.ASCII) for rx in al["paths"]):
            continue
        if al["condition"] != "AND" or (not al["regexes"] and not al["stopwords"]):
            return True
    return False


def scan_text(text: Any, compiled: dict[str, Any] | None = None, *, path: str | None = None, max_bytes: int = MAX_INPUT_BYTES,
              max_line: int = MAX_LINE, windowed: bool = True) -> dict[str, Any]:
    """Scan ``text`` with the compiled ruleset (default: the bundled one) and return
    ``{findings, truncated, allowlisted, rules_run, path_allowlisted}``.

    Each finding is one distinct secret: ``{rule_id, rule_ids, description, kind, masked, generic, tags,
    locations[{path, line}], count, context_domains}`` - only masked values (``mask_secret``) leave this
    function; the raw secret is never returned. ``context_domains`` are host names seen on the lines of
    the secret (for ownership, c7)."""
    compiled = compiled if compiled is not None else default_engine()
    if isinstance(text, (bytes, bytearray)):
        raw = bytes(text).decode("utf-8", errors="replace")
    else:
        raw = str(text or "")
    truncated = False
    enc = raw.encode("utf-8", errors="replace")
    if len(enc) > max_bytes:
        raw = enc[:max_bytes].decode("utf-8", errors="ignore")
        truncated = True
    if _path_allowlisted(compiled, path):
        return {"findings": [], "truncated": truncated, "allowlisted": 0, "rules_run": 0, "path_allowlisted": True}
    lines = raw.split("\n")
    if any(len(ln) > max_line for ln in lines):
        lines = [ln[:max_line] for ln in lines]
        truncated = True
    body = "\n".join(lines)
    starts = [0]
    for ln in lines[:-1]:
        starts.append(starts[-1] + len(ln) + 1)
    low = body.lower()
    if len(low) != len(body):  # Unicode lower-casing changed the length: window offsets would drift
        windowed = False
    found: dict[str, dict[str, Any]] = {}
    allowed = 0
    for r in compiled.get("rules", []):
        if r.get("keywords") and not any(k in low for k in r["keywords"]):
            continue
        if windowed and r.get("engine") == "re" and r.get("keywords") and _PREFIX_FAMILY.match(r["regex"]):
            matches: Iterable[Any] = (m for a, b in _keyword_windows(low, r["keywords"]) for m in r["rx"].finditer(body, a, b))
        else:
            matches = r["rx"].finditer(body)
        for m in matches:
            sg = r.get("secret_group")
            groups = m.groups()
            if sg and len(groups) >= sg:
                secret = m.group(sg)
            else:
                secret = next((g for g in groups if g), None) or m.group(0)
            if not secret:
                continue
            ent = r.get("entropy")
            if ent is not None:
                if shannon_entropy(secret) <= ent:
                    continue
                if r["id"].startswith("generic") and not re.search(r"\d", secret):
                    continue
            ln_no = bisect.bisect_right(starts, m.start())
            line = lines[ln_no - 1] if 0 < ln_no <= len(lines) else ""
            if any(_allow_match(a, secret, m.group(0), line, path) for a in (compiled.get("allowlists") or []) + (r.get("allowlists") or [])):
                allowed += 1
                continue
            if v3lum_allowlisted(secret):
                allowed += 1
                continue
            kind = "password" if r.get("kind") == "password" else secret_kind(r["id"], m.group(0))
            digest = hashlib.sha256(secret.encode("utf-8", "surrogatepass")).hexdigest()  # in-memory dedupe key
            entry = found.get(digest)
            if entry is None:
                entry = {"rule_ids": [], "descriptions": {}, "kind": kind, "locations": [], "tags": set(), "domains": set(), "_secret": secret}
                found[digest] = entry
            if r["id"] not in entry["rule_ids"]:
                entry["rule_ids"].append(r["id"])
                entry["descriptions"][r["id"]] = r.get("description") or ""
            if kind == "password":
                entry["kind"] = "password"
            entry["tags"].update(r.get("tags") or [])
            loc = {"path": path, "line": ln_no}
            if loc not in entry["locations"]:
                entry["locations"].append(loc)
            for dm in _DOMAIN_IN_LINE.finditer(line.replace(secret, " ")):
                entry["domains"].add(dm.group(0).lower())
    findings = []
    for entry in found.values():
        rule_ids = sorted(entry["rule_ids"], key=lambda x: (x in GENERIC_RULES, x.startswith("v3lum-") is False, x))
        rule_id = rule_ids[0]
        masked = mask_secret(entry.pop("_secret"), rule_id, entry["kind"])
        findings.append({
            "rule_id": rule_id, "rule_ids": rule_ids, "description": entry["descriptions"].get(rule_id, ""), "kind": entry["kind"],
            "masked": masked, "generic": all(x in GENERIC_RULES for x in rule_ids), "tags": sorted(entry["tags"]),
            "locations": sorted(entry["locations"], key=lambda x: (str(x["path"]), x["line"])), "count": len(entry["locations"]),
            "context_domains": sorted(entry["domains"])[:20],
        })
    findings.sort(key=lambda x: (x["generic"], x["rule_id"], x["locations"][0]["line"]))
    return {"findings": findings, "truncated": truncated, "allowlisted": allowed, "rules_run": len(compiled.get("rules", [])),
            "path_allowlisted": False}


def secret_severity(rule_id: str, owner: str = "unknown", generic: bool | None = None) -> dict[str, Any]:
    """c7 (never any validity test): own -> HIGH/CRITICAL + notify; third_party -> MEDIUM + owner
    notification; attacker_infra (kit exfiltration channel) -> MEDIUM + abuse report; unknown owner ->
    provider-specific HIGH (critical rules) or MEDIUM; generic/entropy-only -> INFO count."""
    gen = (rule_id in GENERIC_RULES) if generic is None else generic
    if gen:
        return {"severity": "info", "count_only": True, "recommendation": ""}
    if owner == "own":
        return {"severity": "critical" if rule_id in CRITICAL_RULES else "high", "count_only": False,
                "recommendation": "notify the owning team to revoke and rotate the credential (never validate or use it)"}
    if owner == "third_party":
        return {"severity": "medium", "count_only": False,
                "recommendation": "notify the credential owner so they can revoke it (never validate or use it)"}
    if owner == "attacker_infra":
        return {"severity": "medium", "count_only": False,
                "recommendation": "report the exfiltration channel to the platform's abuse team; never use the token"}
    return {"severity": "high" if rule_id in CRITICAL_RULES else "medium", "count_only": False,
            "recommendation": "establish the owner before notifying (never validate or use the credential)"}


def decode_jwt_unverified(token: Any) -> dict[str, Any]:
    """Decode a JWT header and claims offline WITHOUT verifying it. Only non-personal claims (iss, aud,
    exp, iat, nbf) and header fields (alg, kid, typ) are returned, plus presence flags for sub/email/name."""
    out: dict[str, Any] = {"ok": False, "error": None, "header": {}, "claims": {}, "has_sub": False, "has_email": False, "has_name": False}
    parts = str(token or "").strip().split(".")
    if len(parts) < 2:
        out["error"] = "not a jwt"
        return out
    try:
        hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, binascii.Error, UnicodeDecodeError, RecursionError):
        out["error"] = "undecodable jwt"
        return out
    if not isinstance(hdr, dict) or not isinstance(payload, dict):
        out["error"] = "unexpected jwt structure"
        return out
    out["header"] = {k: str(hdr.get(k))[:100] for k in ("alg", "kid", "typ") if k in hdr and hdr.get(k) is not None}
    claims: dict[str, Any] = {}
    for k in ("iss", "aud"):
        value = payload.get(k)
        if isinstance(value, str):
            claims[k] = value[:200]
        elif isinstance(value, list):
            claims[k] = [str(v)[:200] for v in value[:5] if isinstance(v, str)]
    for k in ("exp", "iat", "nbf"):
        value = payload.get(k)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value < 32503680000:
            claims[k] = _epoch_iso(int(value))
    out["claims"] = claims
    out["has_sub"], out["has_email"], out["has_name"] = "sub" in payload, "email" in payload, "name" in payload
    out["ok"] = True
    return out


def _epoch_iso(seconds: int) -> str:
    return _dt.datetime.fromtimestamp(seconds, tz=_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def redos_probe_inputs(rule: dict[str, Any], n: int = 10_000) -> list[str]:
    """ReDoS harness inputs (c2): adversarial strings per rule - keywords followed by long runs of the
    characters the patterns quantify over, unterminated PEM blocks. The test suite times every
    compiled pattern on them with a per-pattern budget."""
    kws = list(rule.get("keywords") or ["x"])[:2]
    out: list[str] = []
    for kw in kws:
        out += [kw + " " * n, kw + "a" * n, kw + "=" * n + "!", kw + "_-." * (n // 3), kw + ("a1" * (n // 2)) + "\x00",
                kw + "\t'" + "\"" * n]
    out.append("-----BEGIN PRIVATE KEY-----" + "A" * n)
    out.append(("-----BEGIN RSA PRIVATE KEY-----\n" + "B" * 64 + "\n") * 50)
    return out


# =============================================================================================
# the module
# =============================================================================================
_BINARY_SNIFF = 8192


def _owner(finding: dict[str, Any], org: Any) -> str:
    """'own' | 'third_party' | 'attacker_infra' | 'unknown' from the lines of the secret and the org profile."""
    domains = finding.get("context_domains") or []
    if org is not None and not getattr(org, "is_empty", True):
        own = False
        for dom in domains:
            ent = Entity.try_make(T.DOMAIN, dom)
            if ent is None:
                continue
            try:
                own = bool(getattr(org.owns(ent), "own", False))
            except Exception:  # noqa: BLE001 - a broken profile never breaks the scan
                own = False
            if own:
                return "own"
        if "phishing_kit_exfil" in finding.get("tags", []):
            return "attacker_infra"
        if domains:
            return "third_party"
        return "unknown"
    return "attacker_infra" if "phishing_kit_exfil" in finding.get("tags", []) else "unknown"


@register
class SecretScanner(Module):
    name = "secret_scanner"
    title = "Secret scanner (gitleaks rules)"
    description = (
        "Offline detection of exposed credentials in text, local files and JWTs with the bundled gitleaks ruleset (MIT) plus "
        "phishing-kit exfiltration rules; secrets are masked, never validated, never pivoted and never sent anywhere."
    )
    category = "utility"
    accepts = {T.TEXT, T.FILE, T.JWT}
    produces = set()
    terms = "open"  # bundled MIT ruleset, no registry source (P312: tier n/a, terms open)
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    tags = {"offline"}
    default_enabled = True
    timeout = 120.0
    reference = "https://github.com/gitleaks/gitleaks"
    notice = (
        "Detected secrets are masked (20+ chars: first/last 4 + SHA-256; shorter: SHA-256 only; passwords: nothing) and are "
        "never validated against the provider, pivoted or sent anywhere. Rules: gitleaks (MIT, Copyright (c) 2019 Zachary Rice)."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is not T.FILE:
            return True
        path = entity.value
        try:
            if not os.path.isfile(path) or os.path.getsize(path) > MAX_FILE_BYTES:
                return False
            with open(path, "rb") as fh:
                head = fh.read(_BINARY_SNIFF)
        except OSError:
            return True  # unreadable: run() reports the error (never 'nothing found')
        return head.count(b"\x00") <= len(head) // 100  # binary files are not text secrets sources

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if entity.type is T.JWT:
            return self._run_jwt(res, entity.value, ctx)
        engine = default_engine()
        if engine.get("error") and not engine.get("rules"):
            return res.mark("unavailable", f"secret ruleset not loaded: {engine['error']}", reason_code="package")
        path: str | None = None
        if entity.type is T.FILE:
            path = entity.value
            try:
                with open(path, "rb") as fh:
                    data = fh.read(MAX_INPUT_BYTES + 1)
            except OSError as exc:
                return res.mark("error", f"cannot read the file: {exc.strerror or type(exc).__name__}")
            text: Any = data
        else:
            text = entity.value
        out = scan_text(text, engine, path=path)
        return self._report(res, out, ctx, engine)

    # ------------------------------------------------------------------ reporting
    def _report(self, res: ModuleResult, out: dict[str, Any], ctx: Any, engine: dict[str, Any]) -> ModuleResult:
        findings = out["findings"]
        counts: dict[str, int] = {}
        for f in findings:
            counts[f["rule_id"]] = counts.get(f["rule_id"], 0) + 1
        res.attr("secret_counts", counts)
        specific = [f for f in findings if not f["generic"]]
        generic = [f for f in findings if f["generic"]]
        org = getattr(ctx, "org", None)
        for f in specific[:MAX_FINDINGS]:
            owner = _owner(f, org)
            sev = secret_severity(f["rule_id"], owner, generic=False)
            masked = f["masked"]
            where = ", ".join(f"{loc['path'] or 'text'}:{loc['line']}" for loc in f["locations"][:5])
            more = f" (+{f['count'] - 5} more)" if f["count"] > 5 else ""
            desc = (f"{f['description'] or f['rule_id']}: {masked['display']} at {where}{more}. "
                    f"{sev['recommendation'][:1].upper()}{sev['recommendation'][1:]}.")
            tags = ["credential_exposure"] + (["phishing_kit_exfil"] if "phishing_kit_exfil" in f["tags"] else [])
            res.finding(
                f"Secret exposed: {f['rule_id']}",
                sev["severity"],
                desc,
                confidence="probable",
                criterion=(f"pattern match of rule '{f['rule_id']}' ({'V3LUM kit rule' if f['rule_id'].startswith('v3lum-') else 'gitleaks, MIT'})"
                           " with its entropy threshold and allowlists; format only - never validated against the provider (P312 c6)"),
                data={"rule": f["rule_id"], "rules": f["rule_ids"], "kind": f["kind"], "masked": masked, "locations": f["locations"],
                      "count": f["count"], "owner": owner, "recommendation": sev["recommendation"]},
                tags=tags,
                key=masked["sha256"][:16] if masked.get("sha256") else f"{f['rule_id']}@{f['locations'][0]['path'] or 'text'}:{f['locations'][0]['line']}",
            )
        if generic:
            res.finding(
                "Generic high-entropy secrets (count only)",
                "info",
                f"{len(generic)} generic/entropy-only match(es) (rule generic-api-key): counted, not scored.",
                data={"count": len(generic), "items": [{"masked": g["masked"], "locations": g["locations"][:3]} for g in generic[:20]]},
                tags=["credential_exposure", "weak_signal"],
            )
        if out["truncated"]:
            res.finding(
                "Input truncated for secret scanning",
                "info",
                f"Only the first {MAX_INPUT_BYTES // (1024 * 1024)} MB were scanned and lines were cut at {MAX_LINE} characters (P312 c2): "
                "secrets beyond those limits were not checked.",
                tags=["info"],
            )
        res.raw = {
            "ruleset": {"source": RULESET, "sha256": engine.get("sha256", ""), "rules_run": out["rules_run"], "re2": _re2 is not None},
            "truncated": out["truncated"], "allowlisted": out["allowlisted"], "path_allowlisted": out["path_allowlisted"],
            "findings": [{k: f[k] for k in ("rule_id", "rule_ids", "kind", "masked", "locations", "count", "tags")} for f in findings[:MAX_FINDINGS]],
        }
        if not findings and not out["truncated"]:
            return res.mark("empty")
        return res

    def _run_jwt(self, res: ModuleResult, token: str, ctx: Any) -> ModuleResult:
        decoded = decode_jwt_unverified(token)
        masked = mask_secret(token, "jwt", "token")
        if not decoded["ok"]:
            return res.mark("error", f"JWT could not be decoded ({decoded['error']})")
        res.attr("jwt_header", decoded["header"])
        claims = dict(decoded["claims"])
        claims.update({"has_sub": decoded["has_sub"], "has_email": decoded["has_email"], "has_name": decoded["has_name"]})
        res.attr("jwt_claims", claims)
        alg = str(decoded["header"].get("alg") or "")
        res.finding(
            "JWT decoded offline (signature not verified)",
            "info",
            f"Token {masked['display']}: alg {alg or '?'}, issuer {claims.get('iss', '?')}. Personal claims are reported as presence "
            "flags only; the token is never used or validated.",
            data={"masked": masked, "header": decoded["header"], "claims": claims},
            tags=["info"],
        )
        if alg.lower() == "none":
            res.finding(
                "Unsigned JWT (alg 'none')",
                "low",
                "The token header declares alg 'none': any party can forge such tokens if a service accepts them.",
                confidence="probable",
                criterion="JWT header field alg == 'none' (decoded offline; no service was contacted)",
                tags=["misconfiguration"],
            )
        res.raw = {"masked": masked, "header": decoded["header"], "claims": claims}
        return res
