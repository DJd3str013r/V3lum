"""E-mail header / .eml / .msg analyzer (P085): static, offline triage of a reported e-mail.

Inputs: an ``.eml`` FILE, a pasted ``text_blob`` that looks like an e-mail, or the ``email_headers``
type (P333). Outlook ``.msg`` files go to ``email_header_analyzer_msg`` (optional ``olefile``).

Binding rules (P085 final conditions):

* C1 stdlib ``email`` parser on bytes (policy compat32) with caps of 25 MB per file, 2,000 headers
  and 64 KB per header; malformed input ends ERROR with the reason, never a crash (a line scanner
  survives broken header lines, MHA's fallback idea).
* C2 a reported e-mail is attacker-controlled: nothing is fetched, resolved, opened, rendered,
  executed, uploaded or written (remote images, tracking pixels, CSS, fonts, links, UNC/file paths and
  attachments are only listed). Disclosure 'none': allowed at TLP:RED.
* C3 the Received chain is reversed to chronological order, each header split on its LAST ';' for
  the date, hop delays via ``total_seconds()`` (day-aware, negatives flagged), 'IPv6:' tags blanked
  before scanning addresses; tokenization ported from mail-parser (Apache-2.0, NOTICE below).
* C4 trust boundary: only Received headers added by the organisation's own MTAs/gateways (setting
  ``email_header_analyzer_trusted_mta`` / ``..._trusted_networks``) are trusted; the first external
  hop they record is the originating IP. Lower hops are attacker-controllable (unverified);
  private/internal hops are skipped and never pivoted.
* C5 Authentication-Results are trusted only from the configured authserv-id
  (``email_header_analyzer_authserv_ids``); others read 'claimed by <host>'. Received-SPF is the SPF
  fallback.
* C6 From vs Return-Path/Reply-To mismatch, display-name brand spoofing (an org_profile brand in the
  display name with an unrelated domain) and X-Mailer-style sender-tool hints.
* C7 bodies are decoded (quoted-printable/base64); URLs are unwrapped through THE single P064 helper
  ``v3lum.modules.url_web.url_unwrap.unwrap_url`` (no second implementation: when it cannot be
  imported, wrapped URLs stay unwrapped and are never pivoted), defanged and never followed. URLs
  carrying a recipient's address (plain, URL-encoded or base64) are flagged 'recipient token'.
  Extracted IPs, domains and URLs are passive-only pivots.
* C8 attachments: name, size, declared type and locally computed SHA-256/MD5 only, as hash pivots
  with expand=False; never sent anywhere.
* C10 recipients and reporter addresses (setting ``email_header_analyzer_reporter_addresses``) are
  redacted from every attribute, finding and pivot (shared reports, STIX/MISP) and kept only in the
  local case evidence (``res.raw['local_only']``); recipients are never pivoted; no body text is stored.
* C11 the verdict block (attribute ``email_verdict`` and the 'E-mail analysis verdict' finding): From
  vs Return-Path/Reply-To, SPF/DKIM/DMARC and who asserted them, originating IP, sending
  infrastructure (enriched by the passive IP/ASN modules), total delay, unwrapped URLs.

Ideas only (GPL, nothing copied, A6): EmailAnalyzer (keraattin), MHA (lnxg33k), extract-msg.
"""

from __future__ import annotations

import base64
import datetime as _dt
import email
import email.policy
import email.utils
import hashlib
import html as _html
import ipaddress
import os
import re
import stat
import unicodedata
import urllib.parse
from collections.abc import Callable, Iterable
from email.header import decode_header, make_header
from typing import Any

from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, package_available, register

_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
#: URL rewriters (SafeLinks, Proofpoint, Mimecast): noise, never IOCs or pivots (P064 cond 4).
WRAPPER_HOSTS = (
    "*.safelinks.protection.outlook.com", "safelinks.protection.outlook.com", "urldefense.com", "*.urldefense.com",
    "urldefense.proofpoint.com", "*.mimecastprotect.com",
)


def clean_text(value: Any, limit: int = 2000) -> str:
    """Strip C0/C1 control characters (tab/newline kept) and cut to ``limit`` characters."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="replace")
    s = value if isinstance(value, str) else ("" if value is None else str(value))
    return _CTRL_RE.sub("", s)[:limit]



MAX_EMAIL_BYTES = 25 * 1024 * 1024        # P085 C1
MAX_HEADER_COUNT = 2000                   # P085 C1
MAX_HEADER_BYTES = 64 * 1024              # P085 C1 (per unfolded header field)
MAX_HOPS = 100                            # Received headers analysed (rest counted, not parsed)
MAX_BODY_TEXT = 5 * 1024 * 1024           # decoded text scanned for URLs
MAX_URLS = 500
#: MAPI stream with the transport headers (UTF-16LE) inside an Outlook .msg (P085 C9).
MSG_TRANSPORT_HEADERS_STREAM = "__substg1.0_007D001F"
MSG_SUBJECT_STREAM = "__substg1.0_0037001F"
MAX_MSG_STREAM_BYTES = 1024 * 1024        # size cap for the transport-headers stream
CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_HEADER_FIELD_RE = re.compile(rb"^([!-9;-~]+)[ \t]*:")   # RFC 5322 ftext = %d33-57 / %d59-126


def _unfold(value: str) -> str:
    return re.sub(r"\r?\n[ \t]+", " ", value).replace("\r", " ").replace("\n", " ").strip()


def _collapse_ws(value: str) -> str:
    return " ".join(value.split())


def scan_header_block(data: bytes) -> dict:
    """Line scanner for the header block, independent of the email package (P085 C1).

    Returns {'fields': [(name, value)], 'malformed_lines': [(line_no, preview)], 'header_bytes',
    'body_offset', 'too_many_headers', 'oversized': [names]}. Field values keep their folding
    (CRLF + WSP); malformed lines (no colon, not a continuation) are reported, skipped and never
    stop the scan, so headers placed after a broken line are still seen (MHA fallback idea).
    """
    out = {"fields": [], "malformed_lines": [], "header_bytes": 0, "body_offset": None,
           "too_many_headers": False, "oversized": []}
    if not isinstance(data, (bytes, bytearray)):
        return out
    data = bytes(data)
    ends = [i for i in (data.find(b"\r\n\r\n"), data.find(b"\n\n")) if i >= 0]
    if ends:
        end = min(ends)
        sep = 4 if data[end:end + 4] == b"\r\n\r\n" else 2
        block, out["body_offset"] = data[:end], end + sep
    else:
        block = data
    out["header_bytes"] = len(block)
    lines = block.split(b"\n")
    if lines and lines[0].startswith(b"From ") and b":" not in lines[0].split(b" ", 2)[1][:1]:
        lines[0] = b""                                    # mbox separator line
    cur_name: str | None = None
    cur_val: list[bytes] = []

    def flush() -> None:
        if cur_name is None:
            return
        raw = b"\n".join(cur_val)
        if len(raw) > MAX_HEADER_BYTES:
            out["oversized"].append(cur_name)
        out["fields"].append((cur_name, raw.decode("utf-8", errors="replace")))

    for n, line in enumerate(lines, 1):
        line = line.rstrip(b"\r")
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            if cur_name is None:
                out["malformed_lines"].append((n, _preview(line)))
            else:
                cur_val.append(line)
            continue
        m = _HEADER_FIELD_RE.match(line)
        if m:
            flush()
            if len(out["fields"]) >= MAX_HEADER_COUNT:
                out["too_many_headers"] = True
                cur_name = None
                break
            cur_name = m.group(1).decode("ascii", errors="replace")
            cur_val = [line[m.end():].lstrip(b" \t")]
        else:
            flush()
            cur_name, cur_val = None, []
            out["malformed_lines"].append((n, _preview(line)))
    flush()
    return out


def _preview(line: bytes, n: int = 60) -> str:
    return clean_text(line.decode("utf-8", errors="replace"), n)


def check_email_caps(data: Any) -> str | None:
    """P085 C1 input caps: 25 MB per file, 2,000 headers, 64 KB per header; not-an-e-mail -> ERROR.
    Returns None when the input may be parsed, else an 'error: ...' reason (Status.ERROR)."""
    if not isinstance(data, (bytes, bytearray)):
        return "error: input is not bytes"
    if not data:
        return "error: empty input"
    if len(data) > MAX_EMAIL_BYTES:
        return "error: input exceeds the 25 MB cap"
    if bytes(data[:8]) == CFB_MAGIC:
        return "error: Outlook .msg (OLE/CFB) file - use the .msg path (olefile)"
    scan = scan_header_block(bytes(data))
    if scan["too_many_headers"]:
        return "error: more than 2000 header fields"
    if scan["oversized"]:
        return "error: header field larger than 64 KB ({})".format(clean_text(scan["oversized"][0], 60))
    if not scan["fields"]:
        return "error: no RFC 5322 header block found (not an e-mail)"
    return None


def decode_header_value(value: Any, limit: int = MAX_HEADER_BYTES) -> str:
    """[P085 C1/C6] Unfold and decode RFC 2047 encoded words; never raises (bad charsets keep the raw text)."""
    if value is None:
        return ""
    v = _unfold(str(value))[:limit]
    if "=?" not in v:
        return v
    try:
        return str(make_header(decode_header(v)))[:limit]
    except Exception:          # HeaderParseError, LookupError (unknown charset), UnicodeError...
        return v


# ---------------------------------------------------------------------------------------------
# Adapted from SpamScope/mail-parser - https://github.com/SpamScope/mail-parser
# Apache License 2.0. Copyright 2016-2018 Fedele Mantuano. Source commit
# 2e5ec17ee986e2fb53ab83e76e9d4d3bbf9a2dcc (2026-11-25): src/mailparser/const.py (REGXIP, REGXIP6,
# _IPV6_TAG_RE, _SENDGRID_DATE_RE), src/mailparser/received.py (split_received lexical scanner,
# helo_argument_spans) and src/mailparser/core.py (_sender_ip_candidates).
# V3LUM modifications: the stamp date is split on the LAST top-level ';' (P085 C3); lexical problems
# are returned instead of raised (malformed input never crashes); IPv4 matches get digit boundaries;
# every candidate is validated with ipaddress. NOTICE.txt of mail-parser must be reproduced in
# THIRD_PARTY_NOTICES.md (A6 BR6).
# ---------------------------------------------------------------------------------------------
REGXIP = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)"
)
# Alternation order matters: the "trailing ::" branch must come after every branch that continues
# past '::' (else 2a00:1450:4864:20::32 matches only as 2a00:1450:4864:20::).
REGXIP6 = re.compile(
    r"(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|::)"
)
# RFC 5321 tags IPv6 literals as [IPv6:2a00:...]; blank the tag (same width) before scanning, else
# REGXIP6 starts at the '6' of the tag and yields a different, valid, routable address.
_IPV6_TAG_RE = re.compile(r"IPv6:", re.I)
_SENDGRID_DATE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{9}\s+\+0000\s+UTC)\s+m=\+\d+\.\d+", re.I)
_RCV_KEYWORD = re.compile(r"(from|by|via|with|id|for|envelope-from|envelope-sender)(?=[ \t\r\n])",
                          re.I)
_FWS = " \t\r\n"


def _received_lex(value: str) -> tuple[list, list, list, list]:
    """Comment/quote/literal/angle-aware scan: (keyword boundaries, top-level ';' positions,
    ( and [ group spans, lexical problems). Port of mail-parser split_received's scanner."""
    boundaries: list[tuple[int, int, str]] = []
    separators: list[int] = []
    groups: list[tuple[int, int]] = []
    problems: list[str] = []
    comment = 0
    quote = literal = angle = escaped = False
    group_start = 0
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if comment:
            if char == "\\":
                escaped = True
            elif char == "(":
                comment += 1
            elif char == ")":
                comment -= 1
                if not comment:
                    groups.append((group_start, index))
            continue
        if quote or literal:
            if char == "\\":
                escaped = True
            elif quote and char == '"':
                quote = False
            elif literal and char == "]":
                literal = False
                groups.append((group_start, index))
            continue
        if char == "(":
            comment = 1
            group_start = index + 1
        elif char == ")":
            problems.append("unexpected-comment-close")
        elif char == '"':
            quote = True
        elif char == "[":
            literal = True
            group_start = index + 1
        elif char == "<":
            if angle:
                problems.append("nested-angle-address")
            angle = True
        elif char == ">":
            angle = False
        elif not angle:
            if char == ";":
                separators.append(index)
            elif index == 0 or value[index - 1] in _FWS + ")":
                m = _RCV_KEYWORD.match(value, index)
                if m:
                    keyword = m.group(1).lower()
                    end = m.end()
                    while end < len(value) and value[end] in _FWS:
                        end += 1
                    if keyword != "with" or not value[end:end + 6].lower().startswith("cipher"):
                        boundaries.append((index, m.end(), keyword))
    if comment or literal:
        groups.append((group_start, len(value)))
    for flag, reason in ((comment, "unclosed-comment"), (quote, "unclosed-quoted-string"),
                         (literal, "unclosed-domain-literal"), (angle, "unclosed-angle-address")):
        if flag:
            problems.append(reason)
    return boundaries, separators, groups, problems


def _helo_argument_spans(value: str, groups: list) -> list[tuple[int, int]]:
    """Sender-controlled HELO arguments inside comments ('(helo=x)', '(HELO x)', CommuniGate
    '(account a@b HELO x)'): spans excluded from sender-IP candidates (mail-parser port)."""
    spans = []
    for start, end in groups:
        if start == 0 or value[start - 1] != "(":
            continue
        initial = True
        escaped = False
        for index in range(start, end):
            char = value[index]
            if escaped:
                escaped = False
                initial = False
                continue
            if char == "\\":
                escaped = True
                initial = False
                continue
            if char == "(":
                initial = True
                continue
            if char in _FWS:
                continue
            first_token = initial
            initial = False
            if index > start and value[index - 1] not in _FWS + "(":
                continue
            width = 5 if value[index:index + 5].lower() == "ehelo" else 4
            if value[index:index + width].lower() not in ("helo", "ehelo"):
                continue
            argument = index + width
            if argument >= end or value[argument] not in _FWS + "=":
                continue
            while argument < end and value[argument] in _FWS:
                argument += 1
            explicit = argument < end and value[argument] == "="
            if explicit:
                argument += 1
                while argument < end and value[argument] in _FWS:
                    argument += 1
            if not explicit and (argument == end or (first_token and value[argument] in "([")):
                continue
            spans.append((index, end))
            break
    return spans


def _in_spans(position: int, spans: list) -> bool:
    return any(start <= position < end for start, end in spans)


def _valid_ips(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        try:
            ip = str(ipaddress.ip_address(v))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


def sender_ip_candidates(from_clause: str) -> tuple[list[str], list[str]]:
    """(MTA-recorded IPs, sender-written HELO IPs) of a Received 'from' clause (P085 C3/C4).

    Port of mail-parser _sender_ip_candidates: the first token (HELO name, possibly an address
    literal) and explicit HELO arguments are sender-written and never candidates; a candidate must sit
    inside a '(' or '[' group written by the receiving MTA; the Exim layout 'from [ip] (helo=x)'
    accepts the first-token address only when nothing else exists. 'IPv6:' tags are blanked first.
    """
    if not from_clause:
        return [], []
    part = _IPV6_TAG_RE.sub("_____", from_clause)
    _, _, groups, _ = _received_lex(part)
    helo_spans = _helo_argument_spans(part, groups)
    first_token_end = len(part.split(" ", 1)[0])
    v6 = [m for m in REGXIP6.finditer(part) if not (m.end() < len(part) and part[m.end()] == ".")]
    matches = sorted(list(REGXIP.finditer(part)) + v6, key=lambda m: m.start())
    helo_written = [m.group() for m in matches if m.start() < first_token_end
                    or _in_spans(m.start(), helo_spans)]
    matches = [m for m in matches if not _in_spans(m.start(), helo_spans)]
    cands = [m.group() for m in matches if m.start() >= first_token_end
             and _in_spans(m.start(), groups)]
    if not cands and helo_spans:
        cands = [m.group() for m in matches if m.start() < first_token_end]
        helo_written = [h for h in helo_written if h not in cands]
    return _valid_ips(cands), _valid_ips(helo_written)

# ----------------------------- end of mail-parser adaptation ---------------------------------


def parse_email_date(value: Any) -> _dt.datetime | None:
    """[P085 C3] RFC 5322 date (trailing comments such as '(-03)' or '(UTC)' allowed), ISO-like dates and
    SendGrid's 'YYYY-MM-DD HH:MM:SS.nnnnnnnnn +0000 UTC' -> aware UTC datetime, or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    v = _collapse_ws(value)
    for _ in range(2):
        v = re.sub(r"\s*\([^()]*\)\s*$", "", v)
    d = None
    try:
        d = email.utils.parsedate_to_datetime(v)
    except Exception:              # TypeError/ValueError/IndexError/OverflowError on hostile input
        d = None
    if d is None:
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s*"
                      r"([+-]\d{2}:?\d{2}|Z|UTC)?", v)
        if m:
            try:
                tz = _dt.timezone.utc
                off = m.group(7)
                if off and off not in ("Z", "UTC"):
                    sign = 1 if off[0] == "+" else -1
                    hh, mm = int(off[1:3]), int(off[-2:])
                    tz = _dt.timezone(sign * _dt.timedelta(hours=hh, minutes=mm))
                d = _dt.datetime(*(int(m.group(i)) for i in range(1, 7)), tzinfo=tz)
            except (ValueError, OverflowError):
                d = None
    if d is None:
        return None
    if d.tzinfo is None:           # '-0000' = unknown local zone: read as UTC
        d = d.replace(tzinfo=_dt.timezone.utc)
    try:
        return d.astimezone(_dt.timezone.utc)
    except (OverflowError, ValueError):
        return None


_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}\.)+[A-Za-z0-9-]{1,63}\.?$")


def _first_token(clause: str | None) -> str | None:
    if not clause:
        return None
    tok = clause.split(" ", 1)[0].strip()
    return tok or None


def _host_or_none(token: str | None) -> str | None:
    if not token:
        return None
    t = token.strip().strip("[]()").rstrip(".").lower()
    return t or None


def parse_received(value: Any) -> dict:
    """One Received field -> clauses, hosts, MTA-recorded IPs and UTC date (P085 C3).

    The stamp date is the text after the LAST top-level ';' (comment/quote aware; raw last ';' when
    the delimiters are unbalanced). Only the first 'from' clause counts (IBM 'for <a> from <b>').
    Returns a JSON-safe dict; '_dt' is an internal datetime popped by received_chain().
    """
    raw = _unfold(str(value or ""))[:MAX_HEADER_BYTES]
    boundaries, seps, groups, problems = _received_lex(raw)
    cut: int | None = None
    if seps:
        cut = seps[-1]
    elif problems and ";" in raw:
        cut = raw.rfind(";")
    date_str = raw[cut + 1:].strip() if cut is not None else None
    end = cut if cut is not None else len(raw)
    if cut is None:
        sg = _SENDGRID_DATE_RE.search(raw)
        if sg:
            date_str, end = sg.group(1), sg.start()
    clauses: dict[str, str] = {}
    bnds = [b for b in boundaries if b[0] < end]
    for pos, (_, kw_end, kw) in enumerate(bnds):
        stop = bnds[pos + 1][0] if pos + 1 < len(bnds) else end
        key = kw.replace("-", "_")
        if key in clauses:          # RFC 5321: one clause of each kind; the first 'from' wins
            continue
        clauses[key] = _collapse_ws(raw[kw_end:stop])
    if not bnds and problems:       # fallback tokenisation (no nesting awareness) on broken input
        for m in re.finditer(r"(?i)\b(from|by|via|with|id|for)\s+(.+?)(?=\s+(?:from|by|via|with|id|"
                             r"for)\s+|$)", raw[:end]):
            clauses.setdefault(m.group(1).lower(), _collapse_ws(m.group(2)))
    env = re.search(r"(?i)envelope-(?:from|sender)\s+<([^<>\s]*)>", raw)
    from_clause = clauses.get("from", "")
    ips, helo_ips = sender_ip_candidates(from_clause)
    rdns = None
    if from_clause:
        _, _, fgroups, _ = _received_lex(from_clause)
        for s, e in fgroups:
            if s and from_clause[s - 1] == "(":
                tok = _first_token(from_clause[s:e].strip())
                if tok and tok.lower() not in ("helo", "ehlo", "unknown", "account") \
                        and "=" not in tok and _HOSTNAME_RE.match(tok.strip("[]")):
                    rdns = tok.rstrip(".").lower()
                break
    by_host = _host_or_none(_first_token(clauses.get("by")))
    if "by" in clauses and not by_host:
        problems.append("empty-by-clause")
    d = parse_email_date(date_str) if date_str else None
    if date_str and d is None:
        problems.append("unparseable-date")
    return {
        "raw": raw[:2048],
        "from": from_clause or None,
        "by": clauses.get("by") or None,
        "with": clauses.get("with") or None,
        "id": clauses.get("id") or None,
        "for": clauses.get("for") or None,
        "via": clauses.get("via") or None,
        "envelope_from": (env.group(1).lower() or None) if env else None,
        "from_host": _host_or_none(_first_token(from_clause)),
        "from_rdns": rdns,
        "by_host": by_host,
        "ips": ips,
        "helo_ips": helo_ips,
        "date_raw": clean_text(date_str, 120) if date_str else None,
        "date_utc": d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None,
        "problems": problems,
        "_dt": d,
    }


def received_chain(received_values: list[str]) -> list[dict]:
    """Received fields in header order (newest first) -> hops in chronological order (oldest first)
    with per-hop delay_s = total_seconds() (day-aware; negatives kept and flagged), P085 C3."""
    vals = [v for v in (received_values or []) if isinstance(v, str)]
    parsed = [parse_received(v) for v in vals[:MAX_HOPS]]
    for i, p in enumerate(parsed):
        p["header_index"] = i                         # 0 = top-most (newest) Received
    hops = list(reversed(parsed))
    prev = None
    for n, hop in enumerate(hops, 1):
        hop["hop"] = n
        d = hop.pop("_dt", None)
        hop["delay_s"] = None
        hop["negative_delay"] = False
        if d is not None and prev is not None:
            delay = (d - prev).total_seconds()
            hop["delay_s"] = delay
            hop["negative_delay"] = delay < 0
        prev = d if d is not None else None
        hop["_epoch"] = d.timestamp() if d else None
    return hops


_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8"))
_DOC_NETS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def is_internal_ip(ip: Any) -> bool:
    """Private/internal/non-routable hop addresses that are skipped (P085 C4). Documentation ranges
    (RFC 5737/3849) are NOT internal, so scrubbed fixtures exercise the external-hop logic."""
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return any(a in n for n in _INTERNAL_NETS if n.version == a.version)


def is_documentation_ip(ip: Any) -> bool:
    """[P085 C4] True for RFC 5737/3849 documentation ranges (flag only; they count as external)."""
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(a in n for n in _DOC_NETS if n.version == a.version)


def host_matches(host: Any, patterns: Iterable[str]) -> bool:
    """[P085 C4] Exact hostname or '*.suffix' (subdomains only) match, case-insensitive, no string suffix
    tricks (label boundary enforced)."""
    h = str(host or "").strip().rstrip(".").lower()
    if not h:
        return False
    for p in patterns or ():
        p = str(p or "").strip().rstrip(".").lower()
        if not p:
            continue
        if p.startswith("*."):
            if h.endswith("." + p[2:]):
                return True
        elif h == p:
            return True
    return False


def ip_in_networks(ip: Any, networks: Iterable[str]) -> bool:
    """ipaddress containment (never string matching): org CIDR checks for hudson_rock search-by-ip
    (P134 C7, A11) and trusted_networks of the e-mail trust boundary (P085 C4)."""
    return _ip_in_networks(ip, networks)


def _ip_in_networks(ip: Any, networks: Iterable[str]) -> bool:
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    for n in networks or ():
        try:
            net = ipaddress.ip_network(str(n), strict=False)
        except ValueError:
            continue
        if net.version == a.version and a in net:
            return True
    return False


def trust_boundary(hops: list[dict], trusted_mta: Iterable[str] = (),
                   trusted_networks: Iterable[str] = ()) -> dict:
    """Trust boundary walk (P085 C4). Mutates each hop's 'trust' label and returns the verdict.

    Walk the Received headers from the newest: a header is trusted only when its 'by' host is one of
    the organisation's MTAs (trusted_mta: exact names or '*.suffix'; an IP 'by' may match
    trusted_networks). Comment-only/no-'from' trusted hops (local delivery, qmail stamps) are
    transparent. A trusted hop whose MTA-recorded peer IP is internal or in trusted_networks is an
    internal relay; the first trusted hop recording an external peer gives the originating IP. Peer
    NAMES never extend trust (HELO and PTR are attacker-controlled). Ambiguous delimiters or a trusted
    hop naming no sender IP stop the walk (fail closed, CWE-345). Everything older is 'unverified'.
    Labels: trusted | local | internal | boundary | unverified.
    """
    trusted_mta = [p for p in (trusted_mta or ()) if p]
    trusted_networks = [n for n in (trusted_networks or ()) if n]
    for h in hops:
        h["trust"] = "unverified"
        h["internal_peer"] = bool(h.get("ips")) and all(is_internal_ip(i) for i in h["ips"])
    res: dict = {"configured": bool(trusted_mta or trusted_networks), "status": None,
                 "originating_ip": None, "boundary_hop": None, "reason": None,
                 "originating_ip_unverified": None}
    cand = None
    for h in hops:                                   # oldest first: first external MTA-recorded IP
        ext = [i for i in h.get("ips") or [] if not is_internal_ip(i)]
        if ext:
            cand = ext[-1]
            break
    res["originating_ip_unverified"] = cand
    if not res["configured"]:
        res.update(status="not_configured",
                   reason="trust boundary not configured (org_profile MTAs/authserv-id): every hop "
                          "is unverified")
        return res

    def by_trusted(h: dict) -> bool:
        b = h.get("by_host")
        return host_matches(b, trusted_mta) or (b is not None and _ip_in_networks(b, trusted_networks))

    seen_trusted = False
    for h in reversed(hops):                        # newest first
        no_clauses = not h.get("from") and not h.get("by")
        if no_clauses and not seen_trusted:
            h["trust"] = "local"
            continue
        if not by_trusted(h):
            res["status"] = res["status"] or ("top_hop_untrusted" if not seen_trusted
                                               else "no_external_peer")
            res["reason"] = res["reason"] or (
                "the newest Received header was not added by a configured org MTA" if not seen_trusted
                else "trusted chain ended without an external peer")
            break
        seen_trusted = True
        if not h.get("from"):
            h["trust"] = "local"
            continue
        if [p for p in h.get("problems") or [] if p not in ("unparseable-date",)]:
            h["trust"] = "trusted"
            res.update(status="ambiguous_trusted_hop",
                       reason="a trusted hop has unbalanced delimiters: walk stopped (fail closed)")
            break
        ips = h.get("ips") or []
        if not ips:
            h["trust"] = "trusted"
            res.update(status="trusted_hop_without_ip",
                       reason="a trusted hop names no sender IP: walk stopped (fail closed)")
            break
        peer = ips[-1]
        if is_internal_ip(peer) or _ip_in_networks(peer, trusted_networks):
            h["trust"] = "internal"
            continue
        h["trust"] = "boundary"
        res.update(status="ok", originating_ip=peer, boundary_hop=h.get("hop"),
                   reason="first external peer recorded by an org MTA")
        break
    if res["status"] is None:
        res.update(status="no_external_peer", reason="no external peer recorded by the org MTAs")
    return res


_AR_METHOD_RE = re.compile(r"^\s*([a-z][a-z0-9_-]*)(?:/\d+)?\s*=\s*([a-z][a-z0-9_-]*)", re.I)
_AR_PROP_RE = re.compile(r"\b([a-z][a-z0-9_-]*\.[a-z][a-z0-9_.-]*)\s*=\s*(\"[^\"]*\"|[^\s;()]+)", re.I)
_AR_KV_RE = re.compile(r"\b(reason|action|policy|dis)\s*=\s*(\"[^\"]*\"|[^\s;()]+)", re.I)


def _split_top_level(value: str, sep: str = ";") -> list[str]:
    parts, buf, depth, quote, esc = [], [], 0, False, False
    for ch in value:
        if esc:
            esc = False
            buf.append(ch)
            continue
        if ch == "\\":
            esc = True
        elif quote:
            if ch == '"':
                quote = False
        elif ch == '"':
            quote = True
        elif ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif ch == sep and not depth:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return parts


def _strip_comments(value: str) -> str:
    out, depth, quote = [], 0, False
    for ch in value:
        if quote:
            out.append(ch)
            if ch == '"':
                quote = False
            continue
        if ch == '"' and not depth:
            quote = True
            out.append(ch)
        elif ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif not depth:
            out.append(ch)
    return "".join(out)


def parse_authentication_results(value: Any, *, arc: bool = False) -> dict:
    """RFC 8601 Authentication-Results (or ARC-Authentication-Results with arc=True) ->
    {'authserv_id', 'instance', 'results': [{'method','result','props','reason'}]} (P085 C5).
    Microsoft 365 omits the authserv-id: then authserv_id is None and the first segment is a result."""
    v = _unfold(str(value or ""))[:MAX_HEADER_BYTES]
    segs = [s.strip() for s in _split_top_level(v)]
    instance = None
    if arc and segs and re.match(r"(?i)^i\s*=\s*\d+$", segs[0]):
        instance = int(re.sub(r"\D", "", segs[0]))
        segs = segs[1:]
    authserv = None
    if segs and not _AR_METHOD_RE.match(_strip_comments(segs[0])):
        head = _strip_comments(segs[0]).split()
        authserv = head[0].lower().rstrip(".") if head else None
        segs = segs[1:]
    results = []
    for seg in segs:
        nc = _strip_comments(seg)
        m = _AR_METHOD_RE.match(nc)
        if not m:
            continue
        props = {k.lower(): val.strip('"') for k, val in _AR_PROP_RE.findall(nc)}
        extra = {k.lower(): val.strip('"') for k, val in _AR_KV_RE.findall(nc)}
        results.append({"method": m.group(1).lower(), "result": m.group(2).lower(),
                        "props": props, "reason": extra.get("reason"),
                        "action": extra.get("action")})
    return {"authserv_id": authserv, "instance": instance, "results": results}


_RSPF_RESULT_RE = re.compile(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.I)


def parse_received_spf(value: Any) -> dict:
    """Received-SPF (RFC 7208 9.1) -> {'result', 'asserted_by', 'client_ip', 'envelope_from',
    'helo'}; used only as SPF fallback when no trusted Authentication-Results has spf (P085 C5)."""
    v = _unfold(str(value or ""))[:MAX_HEADER_BYTES]
    m = _RSPF_RESULT_RE.match(v)
    kv = {k.lower(): val.strip('"<>') for k, val in
          re.findall(r"\b([a-z][a-z-]*)\s*=\s*(\"[^\"]*\"|<[^>]*>|[^\s;]+)", _strip_comments(v), re.I)}
    asserted = kv.get("receiver")
    cm = re.search(r"\(([^():\s]+):", v)
    if not asserted and cm:
        asserted = cm.group(1)
    return {"result": m.group(1).lower() if m else None,
            "asserted_by": asserted.lower().rstrip(".") if asserted else None,
            "client_ip": kv.get("client-ip"), "envelope_from": kv.get("envelope-from"),
            "helo": kv.get("helo")}


def parse_dkim_signature(value: Any) -> dict:
    """[P085 C5/C11] DKIM-Signature tags d= (signing domain), s= (selector), a=, i= - informative only: signatures
    are never verified (offline, no DNS)."""
    v = _unfold(str(value or ""))
    tags = {}
    for part in v.split(";"):
        k, _, val = part.partition("=")
        k = k.strip().lower()
        if k in ("d", "s", "a", "i") and val.strip():
            tags[k] = val.strip().lower() if k in ("d", "s", "a") else val.strip()
    return tags


def summarize_auth(ar_fields: list[str], arc_fields: list[str], rspf_fields: list[str], *,
                   authserv_ids: Iterable[str] = (), trusted_mta: Iterable[str] = ()) -> dict:
    """SPF/DKIM/DMARC verdicts with who asserted them (P085 C5, C11).

    Trusted only when the A-R authserv-id is a configured one (RFC 8601 s5 requires the org's border
    MTA to delete incoming A-R headers that claim its authserv-id); others read 'claimed by <host>'.
    The top-most trusted A-R wins; conflicting trusted A-R values are reported. SPF falls back to a
    Received-SPF asserted by an org MTA, then to any claimed one.
    """
    ids = {str(i).strip().lower().rstrip(".") for i in (authserv_ids or ()) if i}
    parsed = [parse_authentication_results(f) for f in ar_fields or []]
    arcs = [parse_authentication_results(f, arc=True) for f in arc_fields or []]
    out: dict = {"spf": None, "dkim": None, "dmarc": None, "conflicts": [], "claims": [],
                 "arc": [{"instance": a["instance"], "authserv_id": a["authserv_id"],
                          "results": [(r["method"], r["result"]) for r in a["results"]]}
                         for a in arcs]}
    for method in ("spf", "dkim", "dmarc"):
        trusted_vals = []
        for p in parsed:
            for r in p["results"]:
                if r["method"] != method:
                    continue
                entry = {"result": r["result"], "props": r["props"], "asserted_by": p["authserv_id"],
                         "trusted": bool(p["authserv_id"]) and p["authserv_id"] in ids}
                if entry["trusted"]:
                    trusted_vals.append(entry)
                else:
                    out["claims"].append({"method": method, **entry})
        if trusted_vals:
            out[method] = {**trusted_vals[0], "source": "authentication-results"}
            if len({t["result"] for t in trusted_vals}) > 1:
                out["conflicts"].append(method)
    for a in arcs:                    # ARC results are what an intermediary claims: never verified
        for r in a["results"]:
            if r["method"] in ("spf", "dkim", "dmarc"):
                out["claims"].append({"method": r["method"], "result": r["result"], "props": r["props"],
                                      "asserted_by": a["authserv_id"], "trusted": False,
                                      "arc_instance": a["instance"]})
    if out["spf"] is None:
        rs = [parse_received_spf(f) for f in rspf_fields or []]
        rs = [r for r in rs if r["result"]]
        trusted = [r for r in rs if r["asserted_by"] and (r["asserted_by"] in ids
                                                          or host_matches(r["asserted_by"], trusted_mta))]
        pick = trusted[0] if trusted else None
        if pick:
            out["spf"] = {"result": pick["result"], "props": {"client-ip": pick["client_ip"]},
                          "asserted_by": pick["asserted_by"], "trusted": True,
                          "source": "received-spf"}
        for r in rs:
            if r is not pick:
                out["claims"].append({"method": "spf", "result": r["result"], "props": {},
                                      "asserted_by": r["asserted_by"], "trusted": False})
    for method in ("spf", "dkim", "dmarc"):
        if out[method] is None:
            claimed = [c for c in out["claims"] if c["method"] == method]
            if claimed:
                c = claimed[0]
                out[method] = {**c, "source": "claimed"}
    return out


def auth_label(entry: dict | None) -> str:
    """[P085 C5/C11] 'pass (asserted by mx1.example.com, trusted)' / 'fail (claimed by x, not verified)' / 'absent'."""
    if not entry:
        return "absent"
    who = entry.get("asserted_by") or "unnamed host"
    if entry.get("trusted"):
        return f"{entry.get('result')} (asserted by {who}, trusted)"
    return f"{entry.get('result')} (claimed by {who}, not verified)"


def raw_addresses(value: Any) -> list[tuple[str, str]]:
    """[P085 C6] (raw name, lowercased address) pairs parsed on the RAW header (before RFC 2047 decoding), so
    an encoded display name that embeds '<spoof@bank>' can never become the address."""
    raw = _unfold(str(value or ""))[:MAX_HEADER_BYTES]
    try:
        pairs = email.utils.getaddresses([raw])
    except Exception:
        pairs = []
    out = [(n, a.strip().lower()) for n, a in pairs if a and "@" in a]
    if out:
        return out
    angle = list(re.finditer(r"<\s*([^<>\s@]+@[^<>\s@]+)\s*>", raw))
    if angle:                                  # unparseable 'Name <x@y> <a@b>': last addr-spec wins
        m = angle[-1]
        return [(raw[:m.start()].strip().strip('"').strip(), m.group(1).strip().lower())]
    m = re.search(r"([^\s<>\"@,;]+@[^\s<>\"@,;]+)", raw)
    return [("", m.group(1).strip().lower())] if m else []


def parse_address(value: Any) -> tuple[str, str]:
    """[P085 C6] (decoded display name, lowercased address or '') of the first mailbox of an address header.
    Tolerant of quoted names embedding another address ('"Bank <a@bank>" <x@evil>')."""
    pairs = raw_addresses(value)
    if not pairs:
        return clean_text(decode_header_value(value), 300), ""
    name, addr = pairs[0]
    return clean_text(decode_header_value(name), 300), addr


def domain_of(address: Any) -> str | None:
    """[P085 C6] Lowercased domain part of an address, or None."""
    a = str(address or "")
    if "@" not in a:
        return None
    d = a.rsplit("@", 1)[1].strip().strip(">").rstrip(".").lower()
    return d or None


def fold_text(value: Any) -> str:
    """[P085 C6] Accent-fold, lowercase, non-alphanumerics -> single spaces (brand matching)."""
    s = unicodedata.normalize("NFKD", str(value or ""))
    s = "".join(c for c in s if not unicodedata.combining(c)).lower()
    return " ".join(re.sub(r"[^a-z0-9]+", " ", s).split())


_TOOL_HEADERS = ("x-mailer", "user-agent", "x-php-originating-script", "x-php-script",
                 "x-source", "x-source-args", "x-source-dir", "x-gophish-contact",
                 "x-gophish-signature", "x-originating-script", "x-mailer-version", "x-generator")
_TOOL_FAMILIES = (("phpmailer", "PHPMailer"), ("gophish", "Gophish"), ("swiftmailer", "SwiftMailer"),
                  ("swift mailer", "SwiftMailer"), ("python", "Python script"), ("php/", "PHP mail()"),
                  ("king-phisher", "King Phisher"), ("sendinblue", "Brevo/Sendinblue"),
                  ("mailchimp", "Mailchimp"), ("outlook", "Microsoft Outlook"),
                  ("thunderbird", "Thunderbird"), ("zimbra", "Zimbra"))


def sender_tool_hints(fields: list[tuple[str, str]]) -> list[dict]:
    """X-Mailer and similar sender-tool hints (P085 C6)."""
    out = []
    for name, val in fields:
        n = name.lower()
        if n in _TOOL_HEADERS:
            v = clean_text(decode_header_value(val), 300)
            low = (n + " " + v).lower()
            fam = next((label for key, label in _TOOL_FAMILIES if key in low), None)
            out.append({"header": name, "value": v, "family": fam})
    return out


def sender_findings(fields: list[tuple[str, str]], *, org_domains: Iterable[str] = (),
                    brands: Iterable[str] = (), registrable: Callable[[str], str | None] | None = None
                    ) -> list[dict]:
    """From vs Return-Path / Reply-To mismatch, display-name brand spoofing (an org_profile brand in
    the display name with an unrelated domain), display names embedding another address, multiple
    From addresses (P085 C6). Domains are compared by registrable domain when `registrable` (PSL) is
    given, else exactly."""
    def get(n: str) -> list[str]:
        return [v for k, v in fields if k.lower() == n]

    def reg(d: str | None) -> str | None:
        if not d:
            return None
        if registrable:
            try:
                return registrable(d) or d
            except Exception:
                return d
        return d

    findings: list[dict] = []
    froms = get("from")
    if not froms:
        findings.append({"type": "missing_from", "detail": "no From header"})
        return findings
    if len(froms) > 1:
        findings.append({"type": "multiple_from_headers", "detail": f"{len(froms)} From headers"})
    all_from = raw_addresses(froms[0])
    if len(all_from) > 1:
        findings.append({"type": "multiple_from_addresses", "detail": f"{len(all_from)} addresses"})
    name, addr = parse_address(froms[0])
    fdom = reg(domain_of(addr))
    for hdr, ftype in (("return-path", "return_path_mismatch"), ("reply-to", "reply_to_mismatch")):
        vals = get(hdr)
        if not vals:
            continue
        _, other = parse_address(vals[0])
        odom = reg(domain_of(other))
        if other and odom and fdom and odom != fdom:
            findings.append({"type": ftype, "detail": f"{hdr} domain {odom} != from domain {fdom}",
                             "from_domain": fdom, "other_domain": odom})
    orgs = {reg(str(d).lower().rstrip(".")) for d in (org_domains or ()) if d}
    fname = fold_text(name)
    if fname and fdom and fdom not in orgs:
        for b in brands or ():
            fb = fold_text(b)
            if fb and re.search(r"(?:^| )" + re.escape(fb) + r"(?: |$)", fname):
                findings.append({"type": "display_name_brand_spoofing",
                                 "detail": f"brand '{b}' in display name, sender domain {fdom}",
                                 "brand": b, "from_domain": fdom})
                break
    emb = re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", name or "")
    emb += [d for d in re.findall(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", (name or "").lower())
            if "@" not in d]
    emb_regs = sorted({reg(e.lower()) for e in emb} - {fdom, None})
    if emb_regs:
        findings.append({"type": "display_name_embeds_other_domain",
                         "detail": f"display name names {', '.join(emb_regs)} but sender domain is {fdom}",
                         "domains": emb_regs})
    return findings


_URL_TEXT_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`]+")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_KIND_PRIORITY = ("form_action", "script", "iframe", "object", "stylesheet", "font", "image", "media",
                  "base", "link_tag", "link", "text", "other")
_TAG_RE = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>", re.S)
_ATTR_RE = re.compile(r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""", re.S)
_CSS_URL_RE = re.compile(r"""url\(\s*['"]?([^'")\s]+)['"]?\s*\)""", re.I)
_UNC_RE = re.compile(r"(?<![\w/])\\\\[A-Za-z0-9._$-]+\\[^\s<>\"']+")
_URL_ATTRS = {"href", "src", "action", "background", "poster", "data", "formaction", "srcset"}
_TAG_KIND = {"a": "link", "area": "link", "img": "image", "link": "link_tag", "script": "script",
             "iframe": "iframe", "frame": "iframe", "form": "form_action", "base": "base",
             "source": "media", "video": "media", "audio": "media", "object": "object",
             "embed": "object", "input": "image", "button": "form_action", "body": "image",
             "table": "image", "td": "image"}


def _trim_url(u: str) -> str:
    u = u.strip().strip("\"'")
    while u and u[-1] in ".,;:!?)]}>'\"":
        if u[-1] == ")" and u.count("(") >= u.count(")"):
            break
        u = u[:-1]
    return u


def extract_urls_from_text(text: str) -> list[str]:
    """[P085 C7] http/https/ftp URLs in decoded body text (trailing punctuation trimmed)."""
    return [_trim_url(m.group()) for m in _URL_TEXT_RE.finditer(text[:MAX_BODY_TEXT])]


def extract_html_resources(html_text: str) -> list[dict]:
    """URLs referenced by an HTML body with their kind (link, image, stylesheet, font, form_action...)
    and a tracking_pixel flag. Extraction only: nothing is ever fetched or rendered (P085 C2)."""
    out: list[dict] = []
    h = html_text[:MAX_BODY_TEXT]
    for tm in _TAG_RE.finditer(h):
        tag = tm.group(1).lower()
        attrs = {}
        for am in _ATTR_RE.finditer(tm.group(2)):
            val = am.group(3) if am.group(3) is not None else (am.group(4) if am.group(4) is not None
                                                               else am.group(5))
            attrs[am.group(1).lower()] = _html.unescape(val or "")
        kind = _TAG_KIND.get(tag, "other")
        if tag == "link":
            kind = "stylesheet" if "stylesheet" in attrs.get("rel", "").lower() else "link_tag"
        pixel = tag == "img" and (attrs.get("width", "").strip() in ("0", "1")
                                  or attrs.get("height", "").strip() in ("0", "1")
                                  or "display:none" in attrs.get("style", "").replace(" ", "").lower())
        for an, av in attrs.items():
            if an in _URL_ATTRS and av.strip():
                vals = [p.strip().split(" ")[0] for p in av.split(",")] if an == "srcset" else [av.strip()]
                for v in vals:
                    out.append({"url": v, "kind": "form_action" if an == "formaction" else kind,
                                "tracking_pixel": pixel})
        if "style" in attrs:
            for cm in _CSS_URL_RE.finditer(attrs["style"]):
                out.append({"url": cm.group(1), "kind": "image", "tracking_pixel": False})
    for sm in re.finditer(r"(?is)<style[^>]*>(.*?)</style>", h):
        for cm in _CSS_URL_RE.finditer(sm.group(1)):
            kind = "font" if re.search(r"\.(?:woff2?|ttf|otf|eot)\b", cm.group(1), re.I) else "image"
            out.append({"url": cm.group(1), "kind": kind, "tracking_pixel": False})
    return out


def defang_url(url: Any) -> str:
    """'https://evil.example/x' -> 'hxxps://evil[.]example/x' (AR13 style); never followed."""
    u = str(url or "")
    try:
        p = urllib.parse.urlsplit(u)
    except ValueError:
        return u.replace(".", "[.]")
    scheme = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}.get(p.scheme.lower(), p.scheme)
    if not p.netloc:
        return u.replace(".", "[.]")
    rest = u.split(p.netloc, 1)[1] if p.netloc in u else ""
    return f"{scheme}://{p.netloc.replace('.', '[.]')}{rest}"


def recipient_token_forms(address: str) -> list[tuple[str, bool]]:
    """[P085 C7/C10] Encoded forms of an address searched for in URLs: (form, case_sensitive)."""
    a = (address or "").strip()
    if "@" not in a:
        return []
    forms = {(a.lower(), False), (urllib.parse.quote(a, safe="").lower(), False),
             (urllib.parse.quote_plus(a).lower(), False), (a.lower().replace("@", "%40"), False)}
    for v in {a, a.lower()}:
        raw = v.encode("utf-8")
        for enc in (base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()):
            forms.add((enc, True))
            forms.add((enc.rstrip("="), True))
    return sorted(forms)


def url_has_recipient_token(url: str, addresses: Iterable[str]) -> bool:
    """True when the URL carries a recipient/reporter address in plain, URL-encoded or base64 form
    (P085 C7; such URLs are flagged 'recipient token' and never fetched automatically, A7 BR14)."""
    if not url:
        return False
    low = url.lower()
    try:
        unq = urllib.parse.unquote(url)
    except Exception:
        unq = url
    for a in addresses or ():
        for form, cs in recipient_token_forms(a):
            if not form:
                continue
            if cs:
                if form in url or form in unq:
                    return True
            elif form in low or form in unq.lower():
                return True
    return False


def _unwrap(url: str, unwrap: Callable[[str], Any] | None) -> dict:
    """Unwrap a URL through THE single P064 helper (``url_unwrap.unwrap_url``; no second
    implementation here). Returns storage-safe forms (``input_safe``, ``final``: the helper's redacted
    URLs) and the in-memory final URL used only for local recipient-token matching. Without the helper,
    a URL on a known rewriter host is marked wrapped with no final URL (never pivoted)."""
    host = _url_host(url)
    out: dict = {"wrapped": False, "final": url, "final_in_memory": url, "input_safe": url, "host": host,
                 "chain": [], "recipient_token": False, "wrapper_hosts": [], "error": None}
    if unwrap is None:
        if host_matches(host, WRAPPER_HOSTS):
            out.update(wrapped=True, final=None, host=None,
                       error="url_unwrap helper (P064) unavailable: wrapped URL not unwrapped")
        return out
    try:
        r = unwrap(url)
    except Exception as exc:                       # the helper must never break the analysis
        out["error"] = f"url_unwrap failed: {type(exc).__name__}"
        return out
    if isinstance(r, str):
        if r and r != url:
            out.update(wrapped=True, final=r, final_in_memory=r, host=_url_host(r), chain=[r])
        return out
    if not isinstance(r, dict):
        return out
    wrapped = bool(r.get("wrapped"))
    final = r.get("final_url") if isinstance(r.get("final_url"), str) and r.get("final_url") else None
    in_memory = r.get("final_url_unredacted") if isinstance(r.get("final_url_unredacted"), str) else None
    out["wrapped"] = wrapped
    out["input_safe"] = r.get("input_redacted") if isinstance(r.get("input_redacted"), str) else url
    out["final"] = final if final else (None if wrapped else url)
    out["final_in_memory"] = in_memory or final or (None if wrapped else url)
    fh = r.get("final_host") or r.get("final_domain_only")
    out["host"] = str(fh).lower() if isinstance(fh, str) and fh else (_url_host(out["final"]) if out["final"] else None)
    out["chain"] = [c.get("unwrapped_redacted") for c in r.get("chain") or []
                    if isinstance(c, dict) and isinstance(c.get("unwrapped_redacted"), str)][:5]
    out["recipient_token"] = bool(r.get("recipient_token_flag"))
    out["wrapper_hosts"] = [h for h in r.get("wrapper_hosts") or [] if isinstance(h, str)]
    errs = [e for e in r.get("errors") or [] if isinstance(e, str)]
    out["error"] = "; ".join(errs)[:200] or None
    return out


def _url_host(url: str) -> str | None:
    try:
        h = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return None
    return h.rstrip(".").lower() if h else None


def _is_attachment(part: Any) -> bool:
    try:
        disp = part.get_content_disposition()
        fn = part.get_filename()
    except Exception:
        disp, fn = None, None
    ctype = part.get_content_type()
    if disp == "attachment" or fn:
        return True
    return ctype not in ("text/plain", "text/html") and not ctype.startswith("multipart/")


def _fallback_parts(body: bytes) -> list[Any]:
    """MIME fallback when the declared boundary never appears (StartBoundaryNotFoundDefect, a known
    gateway-evasion trick): split on '--token' delimiter lines and parse each chunk on its own."""
    parts = []
    chunks = re.split(rb"(?m)^--[^\s]{2,200}?(?:--)?[ \t]*\r?$", body[:MAX_EMAIL_BYTES])
    for ch in chunks:
        ch = ch.lstrip(b"\r\n")
        if not re.match(rb"(?i)content-", ch):
            continue
        try:
            parts.append(email.message_from_bytes(ch, policy=email.policy.compat32))
        except Exception:
            continue
    return parts


def _part_text(part: Any) -> str:
    try:
        payload = part.get_payload(decode=True) or b""
    except Exception:
        payload = b""
    if not isinstance(payload, (bytes, bytearray)):
        return ""
    cs = None
    try:
        cs = part.get_content_charset()
    except Exception:
        cs = None
    try:
        return bytes(payload[:MAX_BODY_TEXT]).decode(cs or "utf-8", errors="replace")
    except LookupError:
        return bytes(payload[:MAX_BODY_TEXT]).decode("utf-8", errors="replace")


def attachment_meta(part: Any) -> dict | None:
    """Name, size, declared type, locally computed SHA-256/MD5 only (P085 C8). Nothing is opened,
    rendered, executed, uploaded or written; hash pivots carry expand=False."""
    try:
        fn = part.get_filename()
    except Exception:
        fn = None
    ctype = part.get_content_type()
    payload: Any = None
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if payload is None and ctype == "message/rfc822":
        try:
            inner = part.get_payload()
            inner = inner[0] if isinstance(inner, list) and inner else inner
            payload = inner.as_bytes() if hasattr(inner, "as_bytes") else None
        except Exception:
            payload = None
    if not isinstance(payload, (bytes, bytearray)):
        payload = b""
    payload = bytes(payload)
    sha256 = hashlib.sha256(payload).hexdigest()
    md5 = hashlib.md5(payload, usedforsecurity=False).hexdigest()
    try:
        disp = part.get_content_disposition()
    except Exception:
        disp = None
    return {"filename": clean_text(decode_header_value(fn), 255) if fn else None,
            "declared_type": ctype, "disposition": disp, "size": len(payload),
            "sha256": sha256, "md5": md5, "embedded_message": ctype == "message/rfc822",
            "pivots": [{"type": "sha256", "value": sha256, "expand": False},
                       {"type": "md5", "value": md5, "expand": False}]}


def _ip_type(ip: str) -> str:
    return "ipv6" if ":" in ip else "ipv4"


def analyze_email(data: bytes, *, trusted_mta: Iterable[str] = (), trusted_networks: Iterable[str] = (),
                  authserv_ids: Iterable[str] = (), org_domains: Iterable[str] = (),
                  brands: Iterable[str] = (), reporter_addresses: Iterable[str] = (),
                  unwrap: Callable[[str], Any] | None = None,
                  registrable: Callable[[str], str | None] | None = None,
                  noise_hosts: Iterable[str] = WRAPPER_HOSTS) -> dict:
    """Full static analysis of an .eml / pasted header block (P085 C1-C11).

    Returns {'status': 'ok'|'error', 'reason'?, 'summary', 'hops', 'trust', 'auth', 'findings',
    'tool_hints', 'urls', 'resources', 'attachments', 'defects', 'pivots', 'verdict', 'local_only'}.
    `local_only` holds recipients/reporters: keep it in the local case only (C10) and render shared
    outputs through shareable_view(). Nothing is fetched, resolved, opened or written.
    """
    reason = check_email_caps(data)
    if reason:
        return {"status": "error", "reason": reason}
    data = bytes(data)
    scan = scan_header_block(data)
    fields = scan["fields"]
    defects: list[str] = []
    if scan["malformed_lines"]:
        defects.append("malformed header line(s) {} (fallback scanner kept the later headers)".format(", ".join(str(n) for n, _ in scan["malformed_lines"][:10])))

    def get_all(n: str) -> list[str]:
        return [v for k, v in fields if k.lower() == n]

    # MIME/body via the stdlib parser on bytes; a header block with broken lines is repaired first so
    # the parser does not treat the rest of the headers as body.
    to_parse = data
    if scan["malformed_lines"] and scan["body_offset"] is not None:
        hdr = b"\r\n".join(f"{k}: {v}".encode("utf-8", errors="replace") for k, v in fields)
        to_parse = hdr + b"\r\n\r\n" + data[scan["body_offset"]:]
    msg = None
    try:
        msg = email.message_from_bytes(to_parse, policy=email.policy.compat32)
    except Exception as exc:                         # never crash on hostile input
        defects.append(f"MIME parser failure: {type(exc).__name__}")
    parts: list[Any] = []
    if msg is not None:
        try:
            for p in msg.walk():
                for d in getattr(p, "defects", []) or []:
                    name = type(d).__name__
                    if name not in defects:
                        defects.append(name)
                if not p.is_multipart():
                    parts.append(p)
        except Exception as exc:
            defects.append(f"MIME walk failure: {type(exc).__name__}")
    if "StartBoundaryNotFoundDefect" in defects and scan["body_offset"] is not None:
        fb = _fallback_parts(data[scan["body_offset"]:])
        if fb:
            parts = fb
            defects.append("declared MIME boundary not found: parts recovered by the fallback "
                           "splitter (gateway-evasion indicator)")

    hops = received_chain(get_all("received"))
    if len(get_all("received")) > MAX_HOPS:
        defects.append(f"more than {MAX_HOPS} Received headers (rest not parsed)")
    trust = trust_boundary(hops, trusted_mta, trusted_networks)
    auth = summarize_auth(get_all("authentication-results"), get_all("arc-authentication-results"),
                          get_all("received-spf"), authserv_ids=authserv_ids, trusted_mta=trusted_mta)
    findings = sender_findings(fields, org_domains=org_domains, brands=brands, registrable=registrable)
    if auth["conflicts"]:
        findings.append({"type": "conflicting_trusted_auth_results", "methods": list(auth["conflicts"]),
                         "detail": "Authentication-Results carrying the org authserv-id disagree on "
                                   f"{', '.join(auth['conflicts'])} (forged copy; the top-most is used)"})
    for method in ("spf", "dkim", "dmarc"):
        e = auth.get(method)
        if e and e.get("result") in ("fail", "softfail", "permerror", "temperror", "none", "neutral"):
            findings.append({"type": f"{method}_not_passing", "detail": auth_label(e),
                             "trusted": bool(e.get("trusted"))})
    for h in hops:
        if h.get("negative_delay"):
            findings.append({"type": "clock_skew", "detail": f"hop {h['hop']} is {h['delay_s']:.0f} s "
                             "before the previous hop (forged or skewed date)"})
    tool_hints = sender_tool_hints(fields)

    from_name, from_addr = parse_address((get_all("from") or [""])[0])
    _, reply_to = parse_address((get_all("reply-to") or [""])[0])
    _, return_path = parse_address((get_all("return-path") or [""])[0])
    msgid = (get_all("message-id") or [""])[0]
    mid_dom = None
    mm = re.search(r"@([^>\s]+)>?\s*$", msgid.strip())
    if mm:
        mid_dom = mm.group(1).rstrip(".").lower()
    xoip_raw = (get_all("x-originating-ip") or get_all("x-sender-ip") or [""])[0]
    xoip = _valid_ips([xoip_raw.strip().strip("[]")]) if xoip_raw else []

    recipients: list[str] = []
    for hname in ("to", "cc", "delivered-to", "x-original-to", "envelope-to", "x-envelope-to",
                  "bcc"):
        for v in get_all(hname):
            for _, a in raw_addresses(v):
                if a not in recipients:
                    recipients.append(a)
    for h in hops:
        for a in re.findall(r"<?([^\s<>;]+@[^\s<>;]+)>?", h.get("for") or ""):
            if a.lower() not in recipients:
                recipients.append(a.lower())
    reporters = [str(a).lower() for a in (reporter_addresses or ()) if a]
    private_addrs = recipients + [r for r in reporters if r not in recipients]

    texts: list[tuple[str, str]] = []
    attachments: list[dict] = []
    for p in parts:
        try:
            if _is_attachment(p):
                meta = attachment_meta(p)
                if meta:
                    attachments.append(meta)
            elif p.get_content_type() in ("text/plain", "text/html"):
                texts.append((p.get_content_type(), _part_text(p)))
        except Exception as exc:
            defects.append(f"part decode failure: {type(exc).__name__}")
    if not texts and not attachments and scan["body_offset"] is not None \
            and data[scan["body_offset"]:].strip():
        # broken MIME with nothing recovered: never let an undecodable structure hide the body
        texts.append(("text/plain", data[scan["body_offset"]:scan["body_offset"] + MAX_BODY_TEXT]
                      .decode("utf-8", errors="replace")))
        defects.append("no decodable MIME part: raw body scanned as text")

    raw_urls: list[tuple[str, str, bool]] = []
    unc_paths: list[str] = []
    for ctype, txt in texts:
        scan_text = txt
        if ctype == "text/html":
            for r in extract_html_resources(txt):
                u = r["url"]
                if u.lower().startswith(("file:", "\\\\")):
                    unc_paths.append(u)
                    continue
                if u.lower().startswith(("http://", "https://", "ftp://")):
                    raw_urls.append((u, r["kind"], r["tracking_pixel"]))
            # attribute URLs are taken above; scan only the entity-decoded text nodes here
            scan_text = _html.unescape(_HTML_TAG_RE.sub(" ", txt[:MAX_BODY_TEXT]))
        for u in extract_urls_from_text(scan_text):
            raw_urls.append((u, "text", False))
        unc_paths.extend(m.group() for m in _UNC_RE.finditer(scan_text[:MAX_BODY_TEXT]))
    urls: list[dict] = []
    by_url: dict[str, dict] = {}
    for u, kind, pixel in raw_urls:
        u = clean_text(u, 4096)
        if not u:
            continue
        if u in by_url:                              # same URL in text/plain and HTML: merge kinds
            e = by_url[u]
            if kind not in e["kinds"]:
                e["kinds"].append(kind)
            e["tracking_pixel"] = e["tracking_pixel"] or pixel
            continue
        if len(urls) >= MAX_URLS:
            continue
        un = _unwrap(u, unwrap)
        final = un["final"]
        token = url_has_recipient_token(u, private_addrs) or bool(
            un["final_in_memory"] and url_has_recipient_token(un["final_in_memory"], private_addrs)) or un["recipient_token"]
        e = {"url": un["input_safe"], "kind": kind, "kinds": [kind], "tracking_pixel": pixel,
             "wrapped": un["wrapped"], "unwrapped": un["chain"] if un["wrapped"] and final else [],
             "final": final, "final_defanged": defang_url(final) if final else None, "host": un["host"],
             "wrapper_host": bool(un["wrapped"]) or host_matches(_url_host(u), noise_hosts),
             "recipient_token": token, "unwrap_note": un["error"], "fetched": False}
        by_url[u] = e
        urls.append(e)
    resources: list[dict] = []
    for e in urls:
        e["kind"] = min(e["kinds"], key=lambda k: _KIND_PRIORITY.index(k) if k in _KIND_PRIORITY
                        else len(_KIND_PRIORITY))
        if e["kind"] not in ("link", "text"):
            resources.append({"url": e["final_defanged"] or defang_url(e["url"]), "kind": e["kind"],
                              "tracking_pixel": e["tracking_pixel"]})
    if unc_paths:
        findings.append({"type": "unc_or_file_path", "detail": f"{len(set(unc_paths))} UNC/file path(s) - never resolved"})
    if any(r["tracking_pixel"] for r in resources):
        findings.append({"type": "tracking_pixel", "detail": "remote tracking pixel present (never fetched)"})
    if any(u["kind"] == "form_action" for u in urls):
        findings.append({"type": "html_form", "detail": "HTML form posting to a remote URL "
                         "(credential-harvesting indicator)"})
    if any(u["recipient_token"] for u in urls):
        findings.append({"type": "recipient_token", "detail": "URL(s) carry the recipient's address "
                         "(never fetched automatically)"})

    pivots: list[dict] = []

    def add_pivot(ptype: str, value: Any, label: str, expand: bool = True) -> None:
        if not value:
            return
        key = (ptype, str(value).lower())
        if any((p["type"], str(p["value"]).lower()) == key for p in pivots):
            return
        pivots.append({"type": ptype, "value": value, "label": label, "expand": expand,
                       "passive_only": True})

    if trust["originating_ip"]:
        add_pivot(_ip_type(trust["originating_ip"]), trust["originating_ip"],
                  "originating IP (recorded by an org MTA)")
    for h in hops:
        if h.get("trust") in ("unverified",):
            for ip in h.get("ips") or []:
                if not is_internal_ip(ip):
                    add_pivot(_ip_type(ip), ip, "unverified hop (attacker-controllable)")
    for h in hops:
        for ip in h.get("helo_ips") or []:
            if not is_internal_ip(ip):
                add_pivot(_ip_type(ip), ip, "sender-written HELO address (unverified)", expand=False)
    for ip in xoip:
        if not is_internal_ip(ip):
            add_pivot(_ip_type(ip), ip, "X-Originating-IP (sender-written, unverified)")
    for a, label in ((from_addr, "From"), (reply_to, "Reply-To"), (return_path, "Return-Path")):
        if a and a not in private_addrs:
            add_pivot("email", a, f"{label} address", expand=False)
            add_pivot("domain", domain_of(a), f"{label} domain")
    if mid_dom:
        add_pivot("domain", mid_dom, "Message-ID domain")
    dkim_domains = []
    for f in get_all("dkim-signature"):
        d = parse_dkim_signature(f).get("d")
        if d and d not in dkim_domains:
            dkim_domains.append(d)
            add_pivot("domain", d, "DKIM signing domain (signature not verified)")
    for u in urls:
        if u["final"] and u["host"] and not host_matches(u["host"], noise_hosts):
            add_pivot("url", u["final"], "URL from body (never fetched)" +
                      (", recipient token" if u["recipient_token"] else ""),
                      expand=not u["recipient_token"])
            add_pivot("domain", u["host"], "URL host")
    for att in attachments:
        for pv in att["pivots"]:
            add_pivot(pv["type"], pv["value"], "attachment hash (" + (att["filename"] or "unnamed") + ")",
                      expand=False)

    epochs = [h["_epoch"] for h in hops if h.get("_epoch") is not None]
    total_delay = (epochs[-1] - epochs[0]) if len(epochs) >= 2 else None
    b_hop = trust.get("boundary_hop")
    tr_epochs = [h["_epoch"] for h in hops if h.get("_epoch") is not None and b_hop
                 and h["hop"] >= b_hop]
    trusted_delay = (tr_epochs[-1] - tr_epochs[0]) if len(tr_epochs) >= 2 else None
    for h in hops:
        h.pop("_epoch", None)
    summary = {
        "from": from_addr or None, "from_display_name": from_name or None,
        "reply_to": reply_to or None, "return_path": return_path or None,
        "subject": clean_text(decode_header_value((get_all("subject") or [""])[0]), 500) or None,
        "date": clean_text((get_all("date") or [""])[0], 120) or None,
        "message_id": clean_text(msgid, 300) or None, "message_id_domain": mid_dom,
        "x_originating_ip": xoip[0] if xoip else None, "dkim_signing_domains": dkim_domains,
        "header_count": len(fields), "received_count": len(get_all("received")),
    }
    result = {"status": "ok", "summary": summary, "hops": hops, "trust": trust, "auth": auth,
              "findings": findings, "tool_hints": tool_hints, "urls": urls, "resources": resources,
              "attachments": attachments, "defects": defects, "pivots": pivots,
              "total_delay_s": total_delay, "trusted_delay_s": trusted_delay,
              "local_only": {"recipients": recipients, "reporters": reporters}}
    result["verdict"] = verdict_block(result)
    return result


def verdict_block(result: dict) -> dict:
    """The report's opening verdict block (P085 C11). Sending infrastructure (ASN/provider) is left
    for the passive IP modules: the parser only names the IP to enrich."""
    s = result.get("summary") or {}
    f_types = {f.get("type") for f in result.get("findings") or []}
    t = result.get("trust") or {}
    auth = result.get("auth") or {}
    if t.get("originating_ip"):
        oip, otrust = t["originating_ip"], "recorded by an org MTA (trust boundary)"
    elif t.get("originating_ip_unverified"):
        oip, otrust = t["originating_ip_unverified"], "unverified candidate (" + str(t.get("status")) + ")"
    else:
        oip, otrust = None, "not determined"

    def cmp(other: str | None, ftype: str) -> str:
        if not other:
            return "absent"
        return "mismatch" if ftype in f_types else "match"

    return {
        "from": s.get("from"), "return_path": s.get("return_path"), "reply_to": s.get("reply_to"),
        "from_vs_return_path": cmp(s.get("return_path"), "return_path_mismatch"),
        "from_vs_reply_to": cmp(s.get("reply_to"), "reply_to_mismatch"),
        "display_name_spoofing": "display_name_brand_spoofing" in f_types,
        "spf": auth_label(auth.get("spf")), "dkim": auth_label(auth.get("dkim")),
        "dmarc": auth_label(auth.get("dmarc")),
        "originating_ip": oip, "originating_ip_trust": otrust,
        "sending_infrastructure": {"ip": oip, "asn": None, "provider": None,
                                   "note": "enrich via the passive IP/ASN modules"},
        "total_delay_s": result.get("total_delay_s"),
        "trusted_delay_s": result.get("trusted_delay_s"),
        "unwrapped_urls": list(dict.fromkeys(u["final_defanged"] for u in result.get("urls") or []
                                             if u.get("unwrapped") and u.get("final_defanged"))),
        "recipient_token_urls": sum(1 for u in result.get("urls") or [] if u.get("recipient_token")),
    }


def redact_addresses(obj: Any, addresses: Iterable[str], token: str = "[recipient redacted]") -> Any:
    """[P085 C10] Deep-copy obj replacing every listed address (plain, URL-encoded and base64 forms, any case)."""
    forms: list[tuple[str, bool]] = []
    for a in addresses or ():
        forms.extend(recipient_token_forms(a))
    forms.sort(key=lambda f: -len(f[0]))

    def red(s: str) -> str:
        for form, cs in forms:
            if not form:
                continue
            s = s.replace(form, token) if cs else re.sub(re.escape(form), token, s, flags=re.I)
        return s

    def walk(o: Any) -> Any:
        if isinstance(o, str):
            return red(o)
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [walk(v) for v in o]
        return o

    return walk(obj)


def shareable_view(result: dict) -> dict:
    """Shared reports (HTML/MD) and STIX/MISP exports: drop local_only and redact recipient and
    reporter addresses everywhere (Received 'for' clauses, URLs, summaries), P085 C10."""
    if not isinstance(result, dict):
        return {}
    lo = result.get("local_only") or {}
    addrs = list(lo.get("recipients") or []) + list(lo.get("reporters") or [])
    view = {k: v for k, v in result.items() if k != "local_only"}
    return redact_addresses(view, addrs)


def decode_msg_transport_headers(stream: Any) -> str | None:
    """Bytes of the .msg stream __substg1.0_007D001F (PidTagTransportMessageHeaders, UTF-16LE) ->
    header text, capped at MAX_MSG_STREAM_BYTES (P085 C9). Reading the stream (olefile) is the
    module's job; this only decodes it."""
    if not isinstance(stream, (bytes, bytearray)) or not stream:
        return None
    b = bytes(stream[:MAX_MSG_STREAM_BYTES])
    if b.startswith(b"\xff\xfe"):
        b = b[2:]
    if len(b) % 2:
        b = b[:-1]
    text = b.decode("utf-16-le", errors="replace").rstrip("\x00")
    return text or None


def analyze_msg_transport_headers(stream: Any, **kwargs: Any) -> dict:
    """[P085 C9] Decode the .msg transport headers and run the header analysis on them (no body/attachments:
    the .msg body and attachment storages are not read by this helper)."""
    text = decode_msg_transport_headers(stream)
    if not text:
        return {"status": "error", "reason": "error: .msg has no transport headers stream"}
    return analyze_header_text(text, **kwargs)


def analyze_header_text(text: Any, **kwargs: Any) -> dict:
    """email_headers / text_blob entry point (P085 C11, P333): a pasted header block (str) is
    normalised to CRLF, terminated with a blank line and analysed like an .eml."""
    if not isinstance(text, str) or not text.strip():
        return {"status": "error", "reason": "error: empty header text"}
    data = text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
    if not data.endswith(b"\r\n\r\n"):
        data += b"\r\n" if data.endswith(b"\r\n") else b"\r\n\r\n"
    return analyze_email(data, **kwargs)


_KEY_HEADERS = {"received", "from", "to", "subject", "date", "message-id", "return-path",
                "authentication-results", "delivered-to", "mime-version", "content-type", "dkim-signature"}


def looks_like_email_headers(text: Any) -> bool:
    """Unambiguous-structure detector for the email_headers type (P333 C4): >= 3 header fields in
    the first block, >= 2 of them well-known e-mail headers, and >= 60% of its lines parse as header
    fields or folded continuations. Offline and cheap; never guesses from a single line."""
    raw = text.encode("utf-8", errors="replace") if isinstance(text, str) else (
        bytes(text) if isinstance(text, (bytes, bytearray)) else b"")
    if not raw or raw[:8] == CFB_MAGIC:
        return False
    scan = scan_header_block(raw[:MAX_HEADER_BYTES * 4])
    names = [n.lower() for n, _ in scan["fields"]]
    if len(names) < 3 or len({n for n in names if n in _KEY_HEADERS}) < 2:
        return False
    bad = len(scan["malformed_lines"])
    return bad <= 0.4 * (len(names) + bad)




# =============================================================================================
# V3LUM module (contract v2)
# =============================================================================================

#: The single URL-unwrapping helper (P064): ``url_unwrap.unwrap_url``; imported lazily.
UNWRAP_HELPER = "v3lum.modules.url_web.url_unwrap"
#: Readable head of a FILE input used to decide applicability.
_HEAD_BYTES = 64 * 1024
_EMAIL_EXT = {".eml", ".mbox", ".txt", ".msg", ".mht", ""}
_SUSPICIOUS_TOOLS = {"PHPMailer", "Gophish", "Python script", "PHP mail()", "King Phisher", "SwiftMailer"}
_RECIPIENT_NOTE = "[recipient redacted]"

#: analysis finding type -> (title, severity, confidence, tags, criterion)
_FINDINGS: dict[str, tuple[str, str, str, tuple[str, ...], str]] = {
    "missing_from": ("No From header", "low", "probable", ("suspicious",), "RFC 5322 requires a From header"),
    "multiple_from_headers": ("Several From headers", "medium", "probable", ("suspicious",), "more than one From header field (RFC 5322 allows one)"),
    "multiple_from_addresses": ("Several From addresses", "low", "possible", ("suspicious",), "the From header names more than one mailbox"),
    "return_path_mismatch": ("Return-Path domain differs from From", "low", "possible", ("weak_signal",), "registrable domain of Return-Path differs from From (common for bulk senders: weak signal)"),
    "reply_to_mismatch": ("Reply-To domain differs from From", "medium", "probable", ("phishing", "suspicious"), "registrable domain of Reply-To differs from From: replies go elsewhere (BEC/phishing pattern)"),
    "display_name_brand_spoofing": ("Display name impersonates an organisation brand", "high", "probable", ("phishing",), "an org_profile brand in the From display name with a sender domain outside the organisation's domains"),
    "display_name_embeds_other_domain": ("Display name names another domain", "medium", "probable", ("phishing", "suspicious"), "the From display name embeds a domain or address other than the sender domain"),
    "conflicting_trusted_auth_results": ("Conflicting Authentication-Results for the org authserv-id", "medium", "probable", ("suspicious",), "two Authentication-Results claiming the configured authserv-id disagree: one is forged (the top-most is used)"),
    "clock_skew": ("Received dates out of order", "low", "possible", ("suspicious",), "a hop is dated before the previous hop: forged or skewed Received header"),
    "unc_or_file_path": ("UNC or file path in the body (never resolved)", "medium", "probable", ("phishing",), "file:// or \\\\host\\share reference in the body: an NTLM credential-leak lure"),
    "tracking_pixel": ("Remote tracking pixel (never fetched)", "info", "probable", ("info",), "1x1 or hidden remote image in the HTML body"),
    "html_form": ("HTML form posting to a remote URL", "medium", "probable", ("phishing",), "a <form> or formaction pointing to a remote URL: credential-harvesting indicator"),
    "recipient_token": ("URLs carry the recipient's address", "low", "probable", ("recipient_token",), "recipient address in plain, URL-encoded or base64 form inside a URL: never fetched automatically (A7)"),
}


def _p064_unwrap() -> Callable[[str], Any] | None:
    """THE single unwrapping helper (P064) or None when it cannot be imported."""
    try:
        import importlib

        helper = importlib.import_module(UNWRAP_HELPER)
    except Exception:  # noqa: BLE001 - a missing or broken helper only disables unwrapping
        return None
    fn = getattr(helper, "unwrap_url", None)
    return fn if callable(fn) else None


def _str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [v for v in re.split(r"[,\s]+", value) if v]
    return [str(v).strip() for v in value if isinstance(v, str) and v.strip()] if isinstance(value, (list, tuple)) else []


def _regular_file(path: str) -> os.stat_result | None:
    try:
        st = os.stat(path)
    except (OSError, ValueError):
        return None
    return st if stat.S_ISREG(st.st_mode) else None


def _read_head(path: str, size: int = _HEAD_BYTES) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def _ip_type(ip: str) -> T:
    return T.IPV6 if ":" in ip else T.IPV4


@register
class EmailHeaderAnalyzer(Module):
    name = "email_header_analyzer"
    title = "E-mail header / .eml analyzer"
    description = (
        "Static, offline analysis of a reported e-mail (.eml file, pasted message or email_headers block): Received chain "
        "and trust boundary, SPF/DKIM/DMARC and who asserted them, sender mismatches and brand spoofing, URLs (unwrapped, "
        "never followed) and attachment hashes."
    )
    category = "email"
    accepts = {T.FILE, T.TEXT, T.EMAIL_HEADERS}
    produces = {T.IPV4, T.IPV6, T.DOMAIN, T.EMAIL, T.URL, T.SHA256, T.MD5}
    tags = {"offline"}
    reference = "https://www.rfc-editor.org/rfc/rfc8601"
    notice = (
        "Static parsing only: nothing in the message is fetched, resolved, opened or written. Recipients and reporters are "
        "redacted from shared outputs and never pivoted. Configure the trust boundary with the settings "
        "email_header_analyzer_trusted_mta / _trusted_networks / _authserv_ids (until then every hop is unverified)."
    )
    terms = "open"  # own code + adapted Apache-2.0 code, no registry source
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    default_enabled = True
    max_pivots = 200
    settings = {
        "email_header_analyzer_trusted_mta": [],
        "email_header_analyzer_trusted_networks": [],
        "email_header_analyzer_authserv_ids": [],
        "email_header_analyzer_reporter_addresses": [],
    }

    # ------------------------------------------------------------------ applicability
    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.EMAIL_HEADERS:
            return True
        if entity.type is T.TEXT:
            return looks_like_email_headers(entity.value)
        st = _regular_file(entity.value)
        if st is None:
            return False  # a vanished file, a FIFO or a device is not applicable
        head = _read_head(entity.value)
        if head[:8] == CFB_MAGIC:
            return False  # Outlook .msg: email_header_analyzer_msg (olefile)
        ext = os.path.splitext(entity.value)[1].lower()
        return ext in (".eml", ".mbox", ".mht") or looks_like_email_headers(head)

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        kwargs = self._analysis_kwargs(ctx)
        if entity.type is T.FILE:
            st = _regular_file(entity.value)
            if st is None:
                return res.mark("error", "cannot read the file (not a regular file)")
            if st.st_size > MAX_EMAIL_BYTES:
                return res.mark("error", "input exceeds the 25 MB cap")
            try:
                with open(entity.value, "rb") as fh:
                    data = fh.read(MAX_EMAIL_BYTES + 1)
            except OSError as exc:
                return res.mark("error", f"cannot read the file: {exc.strerror or type(exc).__name__}")
            result = analyze_email(data, **kwargs)
        else:
            result = analyze_header_text(entity.value, **kwargs)
        return self._report(res, result)

    def _analysis_kwargs(self, ctx: Any) -> dict[str, Any]:
        org = getattr(ctx, "org", None)
        org_domains: list[str] = []
        brands: list[str] = []
        if org is not None:
            try:
                org_domains = [d.name for d in getattr(org, "domains", []) or []]
                brands = list(org.brand_terms())
            except Exception:  # noqa: BLE001 - an unreadable profile only disables brand checks
                org_domains, brands = [], []
        return {
            "trusted_mta": _str_list(ctx.setting("email_header_analyzer_trusted_mta", [])),
            "trusted_networks": _str_list(ctx.setting("email_header_analyzer_trusted_networks", [])),
            "authserv_ids": _str_list(ctx.setting("email_header_analyzer_authserv_ids", [])),
            "reporter_addresses": [a.lower() for a in _str_list(ctx.setting("email_header_analyzer_reporter_addresses", [])) if "@" in a],
            "org_domains": org_domains,
            "brands": brands,
            "unwrap": _p064_unwrap(),
            "registrable": psl.registrable_domain,
        }

    # ------------------------------------------------------------------ mapping
    def _report(self, res: ModuleResult, result: dict[str, Any]) -> ModuleResult:
        if not isinstance(result, dict) or result.get("status") != "ok":
            reason = str((result or {}).get("reason") or "error: unreadable e-mail") if isinstance(result, dict) else "error: unreadable e-mail"
            return res.mark("error", reason.split(": ", 1)[-1])
        # C10: the local case keeps the full analysis (recipients in local_only); everything shown or
        # exported is built from the shareable view (recipient and reporter addresses redacted)
        res.raw = result
        view = shareable_view(result)
        verdict = view.get("verdict") or {}
        summary = view.get("summary") or {}
        res.attr("email_verdict", verdict)
        res.attr("email_summary", {k: v for k, v in summary.items() if v not in (None, "", [])})
        res.attr("received_hops", [
            {k: h.get(k) for k in ("hop", "from_host", "from_rdns", "by_host", "with", "ips", "helo_ips", "date_utc", "delay_s", "negative_delay", "trust", "problems") if h.get(k) not in (None, [], "")}
            for h in view.get("hops") or []
        ])
        auth = view.get("auth") or {}
        res.attr("email_auth", {
            m: {"label": auth_label(auth.get(m)), **({k: auth[m].get(k) for k in ("result", "asserted_by", "trusted", "source")} if auth.get(m) else {})}
            for m in ("spf", "dkim", "dmarc")
        })
        trust = view.get("trust") or {}
        if verdict.get("originating_ip"):
            res.attr("originating_ip", {"ip": verdict["originating_ip"], "trust": verdict.get("originating_ip_trust"), "boundary": trust.get("status")})
        res.attr("sender_tools", view.get("tool_hints") or [])
        res.attr("email_attachments", [
            {k: a.get(k) for k in ("filename", "declared_type", "size", "sha256", "md5", "embedded_message")} for a in view.get("attachments") or []
        ])
        res.attr("email_urls", [
            {"url": u.get("final_defanged") or defang_url(u.get("url")), "kind": u.get("kind"), "wrapped": bool(u.get("wrapped")),
             "unwrapped": bool(u.get("unwrapped")), "recipient_token": bool(u.get("recipient_token")), "tracking_pixel": bool(u.get("tracking_pixel")),
             **({"note": u["unwrap_note"]} if u.get("unwrap_note") else {})}
            for u in (view.get("urls") or [])[:100]
        ])
        res.attr("mime_defects", list(view.get("defects") or []))
        self._verdict_finding(res, verdict, trust)
        self._findings(res, view)
        self._pivots(res, view)
        return res

    @staticmethod
    def _verdict_finding(res: ModuleResult, verdict: dict[str, Any], trust: dict[str, Any]) -> None:
        delay = verdict.get("total_delay_s")
        parts = [
            f"From {verdict.get('from') or 'absent'} - Return-Path {verdict.get('from_vs_return_path')}, Reply-To {verdict.get('from_vs_reply_to')}",
            f"SPF {verdict.get('spf')}; DKIM {verdict.get('dkim')}; DMARC {verdict.get('dmarc')}",
            f"originating IP {verdict.get('originating_ip') or 'not determined'} ({verdict.get('originating_ip_trust')})",
            "sending infrastructure: enrich the originating IP with the passive IP/ASN modules",
            f"total delay {delay:.0f} s" if isinstance(delay, (int, float)) else "total delay unknown",
        ]
        if verdict.get("unwrapped_urls"):
            parts.append("unwrapped URLs: " + ", ".join(verdict["unwrapped_urls"][:5]))
        if trust.get("status") == "not_configured":
            parts.append("trust boundary not configured: every Received hop is unverified")
        res.finding(
            "E-mail analysis verdict",
            "info",
            ". ".join(parts) + ".",
            confidence="probable",
            criterion="static header analysis (P085 verdict block)",
            data=verdict,
            tags=["info"],
        )

    @staticmethod
    def _findings(res: ModuleResult, view: dict[str, Any]) -> None:
        for f in view.get("findings") or []:
            ftype = str(f.get("type") or "")
            detail = clean_text(f.get("detail"), 500)
            if ftype.endswith("_not_passing"):
                method = ftype.split("_", 1)[0].upper()
                trusted = bool(f.get("trusted"))
                severity = ("medium" if method == "DMARC" else "low") if trusted else "info"
                res.finding(
                    f"{method} did not pass",
                    severity,
                    detail + ("" if trusted else " - claimed by an untrusted host: not verified"),
                    confidence="probable" if trusted else "possible",
                    criterion=f"{method} result from {'the configured authserv-id (trusted)' if trusted else 'a header not added by the organisation (claimed, not verified)'}",
                    data={"label": detail, "trusted": trusted},
                    tags=["suspicious"] if trusted else ["info"],
                    key=method.lower(),
                )
                continue
            spec = _FINDINGS.get(ftype)
            if spec is None:
                continue
            title, severity, confidence, tags, criterion = spec
            res.finding(title, severity, detail, confidence=confidence, criterion=criterion, data={k: v for k, v in f.items() if k != "type"}, tags=list(tags))
        families = {}
        for hint in view.get("tool_hints") or []:
            fam = hint.get("family")
            if fam in _SUSPICIOUS_TOOLS and fam not in families:
                families[fam] = hint
        for fam, hint in families.items():
            res.finding(
                "Mass-mailing or phishing tool in the headers",
                "low",
                f"{hint.get('header')}: {clean_text(hint.get('value'), 200)} ({fam}): typical of scripted or phishing-kit mail, a weak signal on its own.",
                confidence="possible",
                criterion="sender-tool header (X-Mailer, User-Agent, X-PHP-Originating-Script, Gophish headers...) names a scripting or phishing tool",
                data={"family": fam, "header": hint.get("header")},
                tags=["weak_signal"],
                key=fam,
            )
        defects = list(view.get("defects") or [])
        if any("boundary not found" in d for d in defects):
            res.finding(
                "Declared MIME boundary not found",
                "low",
                "The declared multipart boundary never appears: parts were recovered by a fallback splitter. A known trick to hide payloads from mail gateways.",
                confidence="possible",
                criterion="StartBoundaryNotFoundDefect (stdlib e-mail parser) with parts recovered by the fallback splitter",
                data={"defects": defects[:20]},
                tags=["suspicious"],
            )
        elif defects:
            res.finding("MIME or header defects", "info", "; ".join(defects[:10]), confidence="probable", criterion="stdlib e-mail parser defects and malformed header lines", data={"defects": defects[:20]}, tags=["info"])
        attachments = view.get("attachments") or []
        if attachments:
            names = ", ".join(clean_text(a.get("filename") or "unnamed", 80) for a in attachments[:10])
            res.finding(
                "Attachments hashed locally",
                "info",
                f"{len(attachments)} attachment(s): {names}. Hashes computed locally: never opened, written, uploaded or sent to a sandbox.",
                confidence="confirmed",
                criterion="MIME parts with a filename or a non-text content type",
                data={"attachments": [{k: a.get(k) for k in ("filename", "declared_type", "size", "sha256")} for a in attachments[:20]]},
                tags=["info"],
            )

    @staticmethod
    def _pivots(res: ModuleResult, view: dict[str, Any]) -> None:
        trust = view.get("trust") or {}
        candidate = trust.get("originating_ip_unverified") if not trust.get("originating_ip") else None
        for p in view.get("pivots") or []:
            label = str(p.get("label") or "")
            value = str(p.get("value") or "")
            ptype = str(p.get("type") or "")
            if not value or _RECIPIENT_NOTE in value:
                continue  # a value that carried a recipient's address is never pivoted (C10)
            expand = bool(p.get("expand", True))
            if ptype in ("ipv4", "ipv6"):
                if label.startswith("originating IP"):
                    res.pivot(_ip_type(value), value, "sent_from", confidence="probable", note=label)
                elif label.startswith("X-Originating-IP"):
                    res.pivot(_ip_type(value), value, "sent_from", confidence="possible", note=label)
                else:
                    res.pivot(_ip_type(value), value, "relayed_by", confidence="possible", expand=expand, note=label)
            elif ptype == "email":
                res.pivot(T.EMAIL, value, "sender_address", confidence="probable", expand=False, note=f"{label} (attacker-chosen header value): analyst selection required")
            elif ptype == "domain":
                relation = "mentions" if label == "URL host" else "sender_domain"
                res.pivot(T.DOMAIN, value, relation, confidence="probable", note=label)
            elif ptype == "url":
                res.pivot(T.URL, value, "mentions", confidence="probable", expand=expand, note=label)
            elif ptype in ("sha256", "md5"):
                res.pivot(T.SHA256 if ptype == "sha256" else T.MD5, value, "attachment", confidence="confirmed", expand=False, note=label)
        if candidate and not is_internal_ip(candidate):
            res.pivot(_ip_type(candidate), candidate, "sent_from", confidence="possible", note=f"unverified originating-IP candidate ({trust.get('status')})")


@register
class EmailHeaderAnalyzerMsg(EmailHeaderAnalyzer):
    name = "email_header_analyzer_msg"
    title = "Outlook .msg header analyzer"
    description = (
        "Reads the transport headers of an Outlook .msg file (MAPI stream __substg1.0_007D001F, UTF-16LE) with the "
        "optional olefile package and runs the offline e-mail header analysis on them."
    )
    accepts = {T.FILE}
    requires_packages = ("olefile",)
    notice = (
        "Needs the optional olefile package (BSD). Only the transport-headers stream is read (size caps 25 MB per file, "
        "1 MB per stream): the .msg body and attachment storages are never opened. extract-msg (GPL) is not used."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return _regular_file(entity.value) is not None and _read_head(entity.value, 8) == CFB_MAGIC

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        st = _regular_file(entity.value)
        if st is None:
            return res.mark("error", "cannot read the file (not a regular file)")
        if st.st_size > MAX_EMAIL_BYTES:
            return res.mark("error", "input exceeds the 25 MB cap")
        if not package_available("olefile"):  # every path, not only the engine's readiness check
            return res.mark("unavailable", "needs python package: olefile (pip install 'v3lum[full]')", reason_code="package")
        stream = read_msg_transport_headers(entity.value)
        if isinstance(stream, str):
            return res.mark("error", stream)
        return self._report(res, analyze_msg_transport_headers(stream, **self._analysis_kwargs(ctx)))


def read_msg_transport_headers(path: str) -> bytes | str:
    """Bytes of the .msg transport-headers stream, or an error text (malformed file, no stream, too big)."""
    import olefile  # optional extra (requires_packages); BSD-2-Clause

    try:
        if not olefile.isOleFile(path):
            return "not an OLE/CFB file"
        ole = olefile.OleFileIO(path)
    except Exception as exc:  # noqa: BLE001 - malformed CFB: ERROR with the reason, never a crash
        return f"malformed .msg file ({type(exc).__name__})"
    try:
        if not ole.exists(MSG_TRANSPORT_HEADERS_STREAM):
            return ".msg has no transport headers stream (__substg1.0_007D001F)"
        with ole.openstream(MSG_TRANSPORT_HEADERS_STREAM) as fh:
            data = fh.read(MAX_MSG_STREAM_BYTES + 1)
    except Exception as exc:  # noqa: BLE001
        return f"malformed .msg stream ({type(exc).__name__})"
    finally:
        try:
            ole.close()
        except Exception:  # noqa: BLE001
            pass
    if len(data) > MAX_MSG_STREAM_BYTES:
        return "transport headers stream larger than 1 MB"
    return bytes(data)
