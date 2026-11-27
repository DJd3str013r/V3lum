"""Shared RFB CNPJ open-data importer (P238 rfb_cnpj_bulk, shared with P361 cnpj_name_resolver).

Behaviour re-implemented from minha-receita (https://github.com/cuducos/minha-receita, MIT licence, the
WebDAV listing body and the table layout; see v3lum/data/notices/minha_receita_rfb_import.json). Nothing is
copied verbatim.

What it does (P238 final conditions 1-5, 9), never during a scan:

1. ``plan()`` reads the RFB WebDAV share (PROPFIND, Depth 1, parsed with a hardened XML parser), picks the
   newest YYYY-MM month and shows the download size and the free disk space required: the import is refused
   when the free space is below 3x the download. ``import_rfb()`` downloads with resumable HTTP Range
   requests (``Range`` + ``If-Range`` ETag) into unique ``.part`` files, checks size and ETag, streams every
   zip member as latin-1 ';' CSV row by row into SQLite with batched inserts, builds the indexes after the
   load, installs the index atomically and deletes superseded monthly dumps. Table selection is shared with
   P361: presets ``full``, ``qsa`` (default) and ``names`` (Empresas + Estabelecimentos only, P361 light).
2. Only the WebDAV share token RFB itself publishes is used: setting ``rfb_cnpj_bulk_share_link`` must be an
   ``https://arquivos.receitafederal.gov.br/(index.php/)s/<token>`` link and ``rfb_cnpj_bulk_share_source``
   the official RFB / gov.br page it was read from (recorded with ``rfb_cnpj_bulk_share_checked_at``). A
   missing, rotated or rejected token, or a share path that is gone, is UNAVAILABLE with a doctor hint, never
   'no companies'; a login page stops the import.
3. Minimisation at import (rule 4): CPF digits in MEI/EI razao social and nome fantasia are stripped;
   natural-person partners keep only RFB's masked CPF (never completed, never indexed, never a join key);
   faixa etaria and legal representatives are not stored.
4. Storage: ``~/.v3lum/datasets/rfb_cnpj_bulk/`` (0700) with ``rfb_cnpj.sqlite`` (0600), schema version and
   source month in its meta table; never exported.

The command ``v3lum data import-rfb`` belongs to the core ``data`` command (core request); until it is wired
the importer runs as ``python -m v3lum.modules.brazil_public_data.rfb_import [--tables full|qsa|names]``.
"""

from __future__ import annotations

import base64
import contextlib
import csv
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import unicodedata
import xml.parsers.expat
import zipfile
from collections.abc import Callable, Iterable, Iterator
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree as ET

from v3lum import paths
from v3lum.core import redact

WEBDAV_URL = "https://arquivos.receitafederal.gov.br/public.php/webdav/"
SHARE_HOST = "arquivos.receitafederal.gov.br"
SOURCE = "rfb.cnpj_open_data"
PROVIDER = "rfb"
MODULE = "rfb_cnpj_bulk"
INDEX_SCHEMA = "v3lum.rfb_cnpj_index/1"
INDEX_DIR = "rfb_cnpj_bulk"
INDEX_FILE = "rfb_cnpj.sqlite"
STATE_FILE = "import_state.json"
DOWNLOADS = "downloads"
IMPORT_HINT = "run v3lum data import-rfb (until it is wired: python -m v3lum.modules.brazil_public_data.rfb_import)"
DOCTOR_HINT = ("re-check the share link on RFB's official CNPJ open-data page and set rfb_cnpj_bulk_share_link, "
               "rfb_cnpj_bulk_share_source and rfb_cnpj_bulk_share_checked_at (v3lum config set ...)")
#: official pages where RFB publishes the share link (P238 cond 2); the link itself must be on SHARE_HOST
OFFICIAL_SOURCE_PREFIXES = (
    "https://www.gov.br/receitafederal/",
    "https://dados.gov.br/dados/conjuntos-dados/cadastro-nacional-da-pessoa-juridica",
    "https://arquivos.receitafederal.gov.br/",
)
PROPFIND_BODY = (
    b'<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:getcontentlength/>'
    b"<d:getlastmodified/><d:resourcetype/><d:getetag/><d:quota-used-bytes/></d:prop></d:propfind>"
)
MONTH_RE = re.compile(r"^(\d{4})-(0[1-9]|1[0-2])$")
_D = "{DAV:}"
_STATUS_RE = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})")
_SAFE_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_UNSAFE_MEMBER = re.compile(r"(^[/\\])|(^|[/\\])\.\.([/\\]|$)|^[A-Za-z]:|\x00")
SPACE_FACTOR = 3
DEFAULT_CHUNK = 16 * 1024 * 1024
REQUEST_TIMEOUT = 120.0
MAX_MEMBER_BYTES = 40 * 1024**3
MAX_RATIO = 60
MAX_BAD_ROWS = 1000
BATCH = 5000
XML_MAX_BYTES = 4 * 1024 * 1024
SHARED_CONTACT_THRESHOLD = 20
SHARED_CONTACT_LABEL = "possible accountant/virtual office"

# table -> (zip-name regex, member-name marker, column count). QUALSCSV verified live ('F.K03200$Z.D61114.QUALSCSV',
# 2026-11); the other markers follow the same RFB naming. The table is chosen by the zip name, the marker only
# cross-checks it.
TABLES: dict[str, tuple[re.Pattern[str], str, int]] = {
    "empresas": (re.compile(r"^Empresas(\d+)\.zip$"), "EMPRECSV", 7),
    "estabelecimentos": (re.compile(r"^Estabelecimentos(\d+)\.zip$"), "ESTABELE", 30),
    "socios": (re.compile(r"^Socios(\d+)\.zip$"), "SOCIOCSV", 11),
    "simples": (re.compile(r"^Simples\.zip$"), "SIMPLES.CSV", 7),
    "cnaes": (re.compile(r"^Cnaes\.zip$"), "CNAECSV", 2),
    "motivos": (re.compile(r"^Motivos\.zip$"), "MOTICSV", 2),
    "municipios": (re.compile(r"^Municipios\.zip$"), "MUNICCSV", 2),
    "naturezas": (re.compile(r"^Naturezas\.zip$"), "NATJUCSV", 2),
    "paises": (re.compile(r"^Paises\.zip$"), "PAISCSV", 2),
    "qualificacoes": (re.compile(r"^Qualificacoes\.zip$"), "QUALSCSV", 2),
}
LOOKUP_TABLES = ("cnaes", "motivos", "municipios", "naturezas", "paises", "qualificacoes")
#: table selection shared with P361: --tables full | qsa | names
PRESETS: dict[str, tuple[str, ...]] = {
    "full": tuple(TABLES),
    "qsa": ("empresas", "estabelecimentos", "socios", "simples", "naturezas", "qualificacoes", "municipios"),
    "names": ("empresas", "estabelecimentos", "naturezas", "municipios"),
}
DEFAULT_PRESET = "qsa"
PORTE = {"00": "NAO INFORMADO", "01": "MICRO EMPRESA", "03": "EMPRESA DE PEQUENO PORTE", "05": "DEMAIS"}
SITUACAO = {"01": "NULA", "1": "NULA", "02": "ATIVA", "2": "ATIVA", "03": "SUSPENSA", "3": "SUSPENSA", "04": "INAPTA",
            "4": "INAPTA", "08": "BAIXADA", "8": "BAIXADA"}
SOCIO_TIPO = {"1": "pj", "2": "pf", "3": "estrangeiro"}
EI_NATUREZAS = frozenset({"2135"})  # Empresario (Individual), MEI included: the name is a person's name
MASKED_CPF_RE = re.compile(r"^\*{3}\d{6}\*{2}$")
CPF_TOKEN_RE = re.compile(r"(?<![0-9])(\d{3}\.?\d{3}\.?\d{3}-?\d{2})(?![0-9])")


class ImportError_(Exception):  # noqa: N801 - not the builtin ImportError
    """Base of importer failures; ``state`` is 'unavailable' (token/share/space), 'stopped' (login) or 'error'."""

    state = "error"

    def __init__(self, message: str, *, hint: str = "") -> None:
        super().__init__(message)
        self.hint = hint


class ImportUnavailable(ImportError_):
    state = "unavailable"


class ImportStopped(ImportError_):
    state = "stopped"


class FormatChanged(ImportError_):
    """The share or a dump no longer matches the expected layout (never 'no companies')."""

    state = "format_changed"


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------


def fold(text: Any) -> str:
    if not isinstance(text, str):
        return ""
    t = unicodedata.normalize("NFKD", text)
    t = "".join(c for c in t if not unicodedata.combining(c))
    return " ".join(t.upper().split())


def match_key(text: Any) -> str:
    """Normalised name key: accents folded, upper case, '.' and apostrophes dropped, other punctuation -> space."""
    t = fold(text)
    t = re.sub(r"[.'´`’]", "", t)
    return " ".join(re.sub(r"[^0-9A-Z]+", " ", t).split())


def only_digits(value: Any) -> str:
    return re.sub(r"\D", "", value if isinstance(value, str) else "")


def cnpj_clean(value: Any) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", value if isinstance(value, str) else "").upper()


def cnpj_dv(base12: str) -> str:
    """Check digits of a numeric or alphanumeric CNPJ base (value = ord(char) - 48)."""
    out = ""
    for weights in ((5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2), (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)):
        total = sum((ord(c) - 48) * w for c, w in zip(base12 + out, weights, strict=True))
        r = total % 11
        out += "0" if r < 2 else str(11 - r)
    return out


def cpf_valid(value: Any) -> bool:
    d = only_digits(value)
    if len(d) != 11 or d == d[0] * 11:
        return False
    for n in (9, 10):
        s = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        if (s * 10) % 11 % 10 != int(d[n]):
            return False
    return True


def http_date_iso(value: Any) -> str | None:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def snapshot_label(month: str) -> str:
    """The citation every finding carries: 'RFB snapshot YYYY-MM' (P238 cond 8)."""
    if not MONTH_RE.match(month or ""):
        raise ValueError(f"not a YYYY-MM month: {month!r}")
    return f"RFB snapshot {month}"


def share_token_from_link(link: Any) -> str | None:
    """Token of an official share link 'https://arquivos.receitafederal.gov.br/(index.php/)s/<token>' or None."""
    try:
        parts = urlsplit(str(link or "").strip())
    except ValueError:
        return None
    if parts.scheme != "https" or parts.hostname != SHARE_HOST:
        return None
    m = re.fullmatch(r"/(?:index\.php/)?s/([A-Za-z0-9]{10,32})/?", parts.path)
    return m.group(1) if m else None


def official_source(url: Any) -> bool:
    text = str(url or "").strip()
    return any(text.startswith(p) for p in OFFICIAL_SOURCE_PREFIXES)


# --------------------------------------------------------------------------------------
# WebDAV listing (P238 cond 1-3)
# --------------------------------------------------------------------------------------


def safe_xml_root(data: Any, *, max_bytes: int = XML_MAX_BYTES) -> ET.Element:
    """Hardened expat parse: DTD/entity declarations refused by the handlers, size cap. FormatChanged on refusal."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data or b"")
    if len(raw) > max_bytes:
        raise FormatChanged("WebDAV answer larger than the cap")
    parser = xml.parsers.expat.ParserCreate(namespace_separator="}")
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
    builder = ET.TreeBuilder()

    def _tag(name: str) -> str:
        return "{" + name if "}" in name else name

    def _refuse(*_args: Any) -> None:
        raise FormatChanged("DTD/entity declarations are refused in the WebDAV answer")

    parser.StartElementHandler = lambda tag, attrs: builder.start(_tag(tag), {})
    parser.EndElementHandler = lambda tag: builder.end(_tag(tag))
    parser.CharacterDataHandler = builder.data
    parser.StartDoctypeDeclHandler = _refuse
    parser.EntityDeclHandler = _refuse
    parser.UnparsedEntityDeclHandler = _refuse
    parser.ExternalEntityRefHandler = _refuse
    parser.buffer_text = True
    try:
        parser.Parse(raw, True)
    except xml.parsers.expat.ExpatError as exc:
        raise FormatChanged(f"WebDAV answer is not well-formed XML: {exc}") from None
    return builder.close()


def _int_text(el: ET.Element | None) -> int | None:
    if el is None or el.text is None:
        return None
    t = el.text.strip()
    return int(t) if t.isdigit() else None


def parse_multistatus(data: Any) -> list[dict[str, Any]]:
    """PROPFIND multistatus -> entries {href, path, name, is_dir, bytes, quota_used_bytes, etag, last_modified}.

    Only the ``200`` propstat is read (Nextcloud adds a ``404`` one); ``name`` falls back to the decoded last
    path segment (the allprop answer has no displayname). FormatChanged when it is not a DAV multistatus.
    """
    root = safe_xml_root(data)
    if root.tag != _D + "multistatus":
        raise FormatChanged(f"expected a DAV multistatus, got {root.tag[:60]!r}")
    entries = []
    for resp in root.findall(_D + "response"):
        href = (resp.findtext(_D + "href") or "").strip()
        props: dict[str, ET.Element] = {}
        for ps in resp.findall(_D + "propstat"):
            sm = _STATUS_RE.search(ps.findtext(_D + "status") or "")
            if not sm or sm.group(1) != "200":
                continue
            prop = ps.find(_D + "prop")
            if prop is not None:
                for child in prop:
                    props[child.tag] = child
        path = unquote(urlsplit(href).path)
        rtype = props.get(_D + "resourcetype")
        is_dir = (rtype is not None and rtype.find(_D + "collection") is not None) or path.endswith("/")
        dn = props.get(_D + "displayname")
        name = dn.text.strip() if dn is not None and dn.text and dn.text.strip() else path.rstrip("/").rsplit("/", 1)[-1]
        etag_el = props.get(_D + "getetag")
        etag = etag_el.text.strip().strip('"') if etag_el is not None and etag_el.text else None
        lm_el = props.get(_D + "getlastmodified")
        entries.append({
            "href": href, "path": path, "name": name, "is_dir": is_dir, "bytes": _int_text(props.get(_D + "getcontentlength")),
            "quota_used_bytes": _int_text(props.get(_D + "quota-used-bytes")), "etag": etag or None,
            "last_modified": http_date_iso(lm_el.text) if lm_el is not None and lm_el.text else None,
        })
    if not entries:
        raise FormatChanged("DAV multistatus without responses")
    return entries


def months_of(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """YYYY-MM collections of the share root, oldest first, with their size (quota-used-bytes)."""
    out = [{"month": e["name"], "bytes": e.get("quota_used_bytes"), "etag": e.get("etag")}
           for e in entries if e.get("is_dir") and MONTH_RE.match(e.get("name") or "")]
    return sorted(out, key=lambda m: m["month"])


def classify_file(name: str) -> tuple[str | None, int | None]:
    for table, (rx, _marker, _cols) in TABLES.items():
        m = rx.match(name or "")
        if m:
            return table, (int(m.group(1)) if m.groups() else None)
    return None, None


def month_files(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Files of one month, classified by table; unknown or unsafe names are listed and never downloaded."""
    files, unknown = [], []
    for e in entries:
        if e.get("is_dir"):
            continue
        name = e.get("name") or ""
        table, part = classify_file(name)
        if table is None or not _SAFE_FILE_NAME.fullmatch(name):
            unknown.append(name)
            continue
        files.append({"name": name, "table": table, "part": part, "bytes": e.get("bytes"), "etag": e.get("etag")})
    files.sort(key=lambda f: (f["table"], -1 if f["part"] is None else f["part"]))
    present = {f["table"] for f in files}
    return {"files": files, "unknown": unknown, "missing_tables": sorted(t for t in TABLES if t not in present),
            "total_bytes": sum(f["bytes"] or 0 for f in files)}


def download_plan(month_summary: dict[str, Any], free_bytes: int | None, tables: Iterable[str]) -> dict[str, Any]:
    """What will be downloaded, its size, the free space required (3x) and the refusal reason (P238 cond 1)."""
    selected = set(tables)
    unknown_tables = selected - set(TABLES)
    if unknown_tables:
        raise ValueError(f"unknown RFB tables: {sorted(unknown_tables)}")
    sel = [f for f in month_summary["files"] if f["table"] in selected]
    missing = sorted(t for t in selected if t in set(month_summary.get("missing_tables") or ()))
    no_size = [f["name"] for f in sel if not isinstance(f["bytes"], int)]
    download = sum(f["bytes"] for f in sel if isinstance(f["bytes"], int))
    need = download * SPACE_FACTOR
    reasons = []
    if missing:
        reasons.append("tables missing on the share (layout change): " + ", ".join(missing))
    if no_size:
        reasons.append("size unknown for: " + ", ".join(no_size))
    if not sel:
        reasons.append("nothing to download")
    if free_bytes is None:
        reasons.append("free space unknown")
    elif free_bytes < need:
        reasons.append(f"free space {free_bytes} B < {SPACE_FACTOR}x the download ({need} B)")
    return {"files": sel, "download_bytes": download, "required_free_bytes": need, "free_bytes": free_bytes,
            "ok": not reasons, "refusal": "; ".join(reasons) or None, "missing": missing}


def webdav_problem(status: int, headers: dict[str, str] | None, body: bytes | str | None) -> str | None:
    """Classify one WebDAV answer; None when usable (207 multistatus, 200/206 file)."""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else (body or "")
    if status in (301, 302, 303, 307, 308):
        loc = h.get("location", "")
        return "login_required" if ("/login" in loc or "require_login" in loc) else "redirected"
    if status == 401:
        return "token_missing" if "No 'Authorization: Basic' header" in text else "token_rejected"
    if status == 403:
        return "token_rejected"
    if status == 404:
        return "share_or_path_not_found"
    if status == 429:
        return "rate_limited"
    if status >= 500:
        return "server_error"
    if status not in (200, 206, 207):
        return "unexpected_status"
    head = text.lstrip()[:200].lower()
    if "text/html" in h.get("content-type", "") or head.startswith(("<!doctype html", "<html")):
        if "body-login" in text or 'name="password"' in text or "/login" in text:
            return "login_required"
        return "html_instead_of_dav"
    return None


def _raise_for(problem: str, what: str) -> None:
    if problem in ("token_missing", "token_rejected"):
        raise ImportUnavailable(f"RFB share token {problem.split('_')[1]} ({what}): could not import", hint=DOCTOR_HINT)
    if problem == "share_or_path_not_found":
        raise ImportUnavailable(f"RFB share or path not found ({what}): the share may have moved", hint=DOCTOR_HINT)
    if problem == "login_required":
        raise ImportStopped(f"RFB now requires a login ({what}): import stopped (P238 cond 2: never log in)", hint=DOCTOR_HINT)
    if problem == "rate_limited":
        raise ImportUnavailable(f"RFB rate-limited the import ({what}): retry later (could not import)")
    raise ImportError_(f"RFB answered {problem.replace('_', ' ')} ({what}): could not import")


# --------------------------------------------------------------------------------------
# row parsing (P238 cond 3-4: minimisation at import)
# --------------------------------------------------------------------------------------


def rfb_date(value: Any) -> str | None:
    v = (value or "").strip()
    if not re.fullmatch(r"\d{8}", v) or v == "00000000":
        return None
    try:
        return date(int(v[:4]), int(v[4:6]), int(v[6:])).isoformat()
    except ValueError:
        return None


def _brl(value: Any) -> float | None:
    v = (value or "").strip().replace(".", "").replace(",", ".")
    try:
        return float(v) if v else None
    except ValueError:
        return None


def _sn(value: Any) -> int | None:
    return {"S": 1, "N": 0}.get((value or "").strip().upper())


def strip_cpf_from_name(name: Any, natureza: Any = None) -> tuple[str, bool]:
    """Remove CPF digits embedded in MEI/EI names: any CPF-shaped token for natureza 2135, DV-valid tokens
    anywhere else. Returns (clean_name, stripped); the original value is never kept."""
    if not isinstance(name, str):
        return "", False
    ei = (natureza or "").strip() in EI_NATUREZAS
    stripped = False

    def repl(m: re.Match[str]) -> str:
        nonlocal stripped
        if ei or cpf_valid(m.group(1)):
            stripped = True
            return " "
        return m.group(0)

    out = CPF_TOKEN_RE.sub(repl, name)
    return " ".join(out.split()).strip(" -"), stripped


def masked_doc(value: Any) -> str | None:
    """RFB's published mask ('***456789**') as is; a full CPF (never expected) is masked the same way."""
    v = (value or "").strip()
    if MASKED_CPF_RE.match(v):
        return v
    d = only_digits(v)
    return f"***{d[3:9]}**" if len(d) == 11 else None


def phone_key(ddd: Any, number: Any) -> str | None:
    d, n = only_digits(ddd).lstrip("0"), only_digits(number)
    if not n or len(n) < 8 or len(n) > 9:
        return None
    return f"{d}{n}"


def parse_empresa(f: list[str]) -> tuple[Any, ...]:
    basico, razao, natureza, _qual, capital, porte, _ente = (x.strip() for x in f)
    clean, stripped = strip_cpf_from_name(razao, natureza)
    return (basico.upper(), clean, natureza or None, PORTE.get(porte), _brl(capital), int(stripped))


def parse_estabelecimento(f: list[str]) -> tuple[Any, ...]:
    (basico, ordem, dv, matriz, fantasia, situacao, data_sit, motivo, _cid_ext, pais, inicio, cnae, cnae_sec, tipo_log,
     logradouro, numero, complemento, bairro, cep, uf, municipio, ddd1, tel1, ddd2, tel2, _ddd_fax, _fax, email, sit_esp,
     data_sit_esp) = (x.strip() for x in f)
    cnpj = f"{basico}{ordem}{dv}".upper()
    mail = email.lower() if "@" in email else None
    return (cnpj, basico.upper(), int(matriz == "1"), strip_cpf_from_name(fantasia)[0] or None, SITUACAO.get(situacao),
            rfb_date(data_sit), motivo or None, pais or None, rfb_date(inicio), cnae or None,
            ",".join(c for c in cnae_sec.split(",") if c.strip()) or None, tipo_log or None, logradouro or None, numero or None,
            complemento or None, bairro or None, only_digits(cep) or None, uf or None, municipio or None, mail,
            phone_key(ddd1, tel1), phone_key(ddd2, tel2), sit_esp or None, rfb_date(data_sit_esp))


def parse_socio(f: list[str]) -> tuple[Any, ...]:
    """Partners: masked CPF as published (never a key), faixa etaria and legal representatives dropped."""
    basico, ident, nome, doc, qual, entrada, pais, _rep_doc, _rep_nome, _rep_qual, _faixa = (x.strip() for x in f)
    tipo = SOCIO_TIPO.get(ident)
    nome = " ".join(nome.split())
    socio_cnpj = None
    name_key = None
    masked = None
    if tipo == "pj":
        c = cnpj_clean(doc)
        socio_cnpj = c if len(c) == 14 else None
    else:
        name_key = match_key(nome) or None
        if tipo == "pf":
            masked = masked_doc(doc)
    return (basico.upper(), tipo, nome, name_key, qual or None, rfb_date(entrada), pais or None, socio_cnpj, masked)


def parse_simples(f: list[str]) -> tuple[Any, ...]:
    basico, op_s, d_op_s, d_exc_s, op_mei, d_op_mei, d_exc_mei = (x.strip() for x in f)
    return (basico.upper(), _sn(op_s), rfb_date(d_op_s), rfb_date(d_exc_s), _sn(op_mei), rfb_date(d_op_mei), rfb_date(d_exc_mei))


def parse_lookup(f: list[str]) -> tuple[Any, ...]:
    return (f[0].strip(), " ".join(f[1].split()))


ROW_SPEC: dict[str, tuple[int, Callable[[list[str]], tuple[Any, ...]]]] = {
    "empresas": (7, parse_empresa),
    "estabelecimentos": (30, parse_estabelecimento),
    "socios": (11, parse_socio),
    "simples": (7, parse_simples),
    **{t: (2, parse_lookup) for t in LOOKUP_TABLES},
}


def zip_member(zf: zipfile.ZipFile, expected_table: str | None = None) -> zipfile.ZipInfo:
    """The single CSV member of an RFB zip, checked before decompression (count, name, size, ratio, table)."""
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) != 1:
        raise FormatChanged(f"expected exactly one member in the RFB zip, found {len(infos)}")
    info = infos[0]
    if _UNSAFE_MEMBER.search(info.filename):
        raise FormatChanged(f"unsafe member name {info.filename[:80]!r}")
    if info.file_size > MAX_MEMBER_BYTES:
        raise FormatChanged("member larger than the cap")
    if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
        raise FormatChanged("compression ratio above the cap")
    up = info.filename.upper()
    found = next((t for t, (_rx, marker, _c) in TABLES.items() if marker in up), None)
    if expected_table and found and found != expected_table:
        raise FormatChanged(f"member {info.filename[:80]!r} is a {found} file, expected {expected_table}")
    return info


def iter_rows(source: Any, table: str, stats: dict[str, Any] | None = None, *, max_bad_rows: int = MAX_BAD_ROWS) -> Iterator[tuple[Any, ...]]:
    """Stream one RFB zip row by row (latin-1, ';', quoted, no header) -> parsed tuples. Memory stays flat.

    A wrong column count on the first record, or more than ``max_bad_rows`` bad records, raises FormatChanged;
    other bad records are counted in ``stats`` (rows, bad_rows).
    """
    n_cols, row_fn = ROW_SPEC[table]
    st = stats if stats is not None else {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(source) if isinstance(source, (bytes, bytearray)) else source)
    except (zipfile.BadZipFile, OSError):
        raise FormatChanged(f"{table}: the RFB download is not a zip file") from None
    with zf:
        info = zip_member(zf, expected_table=table)
        st.update({"member": info.filename, "rows": 0, "bad_rows": 0})
        with zf.open(info) as raw:
            text = io.TextIOWrapper(raw, encoding="latin-1", newline="")
            reader = csv.reader((line.replace("\x00", "") for line in text), delimiter=";", quotechar='"')
            for recno, fields in enumerate(reader, 1):
                if not fields or fields == [""]:
                    continue
                if len(fields) != n_cols:
                    st["bad_rows"] += 1
                    if recno == 1 or st["bad_rows"] > max_bad_rows:
                        raise FormatChanged(f"{table}: {len(fields)} columns at record {recno}, expected {n_cols}")
                    continue
                st["rows"] += 1
                yield row_fn(fields)


# --------------------------------------------------------------------------------------
# index build (P238 cond 3-5, 8)
# --------------------------------------------------------------------------------------

_TABLE_SQL = {
    "empresas": "CREATE TABLE empresas (cnpj_basico TEXT, razao_social TEXT, natureza TEXT, porte TEXT, capital REAL, cpf_stripped INTEGER)",
    "estabelecimentos": (
        "CREATE TABLE estabelecimentos (cnpj TEXT, cnpj_basico TEXT, matriz INTEGER, nome_fantasia TEXT, situacao TEXT, "
        "data_situacao TEXT, motivo TEXT, pais TEXT, data_inicio TEXT, cnae TEXT, cnaes_sec TEXT, tipo_logradouro TEXT, "
        "logradouro TEXT, numero TEXT, complemento TEXT, bairro TEXT, cep TEXT, uf TEXT, municipio TEXT, email TEXT, "
        "phone1 TEXT, phone2 TEXT, situacao_especial TEXT, data_situacao_especial TEXT)"
    ),
    "socios": (
        "CREATE TABLE socios (cnpj_basico TEXT, tipo TEXT, nome TEXT, name_key TEXT, qualificacao TEXT, data_entrada TEXT, "
        "pais TEXT, socio_cnpj TEXT, cpf_mascarado TEXT)"
    ),
    "simples": ("CREATE TABLE simples (cnpj_basico TEXT, simples INTEGER, simples_desde TEXT, simples_excluido TEXT, mei INTEGER, "
                "mei_desde TEXT, mei_excluido TEXT)"),
}
_INDEX_SQL = {
    "empresas": ("CREATE INDEX emp_root ON empresas (cnpj_basico)", "CREATE INDEX emp_name ON empresas (razao_social)"),
    "estabelecimentos": ("CREATE INDEX est_cnpj ON estabelecimentos (cnpj)", "CREATE INDEX est_root ON estabelecimentos (cnpj_basico)"),
    # no index on cpf_mascarado: never a join or lookup key (P238 cond 4)
    "socios": ("CREATE INDEX soc_root ON socios (cnpj_basico)", "CREATE INDEX soc_name ON socios (name_key)",
               "CREATE INDEX soc_pj ON socios (socio_cnpj)"),
    "simples": ("CREATE INDEX sim_root ON simples (cnpj_basico)",),
}


def building_key(tipo: Any, logradouro: Any, numero: Any, cep: Any) -> str | None:
    """Address key per building (street|number|CEP, accent-folded): rooms of one building share it."""
    street = fold(f"{tipo or ''} {logradouro or ''}")
    c = only_digits(cep or "")
    if not street or not c:
        return None
    return f"{street}|{fold(numero or '')}|{c}"


def _contacts(conn: sqlite3.Connection) -> None:
    """contact_keys (kind, key, cnpj, cnpj_basico) and shared_contacts (kind, key, roots >= 20) after the load."""
    conn.execute("CREATE TABLE contact_keys (kind TEXT, key TEXT, cnpj TEXT, cnpj_basico TEXT)")
    batch: list[tuple[str, str, str, str]] = []
    for row in conn.execute("SELECT cnpj, cnpj_basico, email, phone1, phone2, tipo_logradouro, logradouro, numero, cep FROM estabelecimentos"):
        cnpj, root, email, p1, p2, tipo, logr, num, cep = row
        if email:
            batch.append(("email", email, cnpj, root))
        for p in {p1, p2} - {None}:
            batch.append(("phone", p, cnpj, root))
        b = building_key(tipo, logr, num, cep)
        if b:
            batch.append(("address", b, cnpj, root))
        if cep:
            batch.append(("cep", cep, cnpj, root))
        if len(batch) >= BATCH:
            _flush(conn, batch)
    _flush(conn, batch)
    conn.execute("CREATE INDEX ck_key ON contact_keys (kind, key)")
    conn.execute("CREATE INDEX ck_cnpj ON contact_keys (cnpj)")
    conn.execute("CREATE TABLE shared_contacts (kind TEXT, key TEXT, roots INTEGER, PRIMARY KEY (kind, key))")
    conn.execute(
        "INSERT INTO shared_contacts (kind, key, roots) SELECT kind, key, COUNT(DISTINCT cnpj_basico) AS n FROM contact_keys "
        "WHERE kind IN ('email', 'phone', 'address') GROUP BY kind, key HAVING n >= ?",
        (SHARED_CONTACT_THRESHOLD,),
    )


def _flush(conn: sqlite3.Connection, batch: list[tuple[str, str, str, str]]) -> None:
    if batch:
        conn.executemany("INSERT INTO contact_keys (kind, key, cnpj, cnpj_basico) VALUES (?,?,?,?)", batch)
        batch.clear()


def build_index(files: dict[str, list[Path]], out_path: Path, *, month: str, progress: Callable[[dict[str, Any]], None] | None = None,
                now: datetime | None = None) -> dict[str, Any]:
    """Build the SQLite index from local zips ``{table: [paths]}`` into a unique temp file, then install it at
    ``out_path`` atomically (0600). Raises FormatChanged on a layout change (the previous index stays)."""
    out_path = Path(out_path)
    tmp = out_path.with_name(f".{out_path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    counts: dict[str, int] = {}
    try:
        conn = sqlite3.connect(str(tmp), isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=OFF")
            conn.execute("PRAGMA synchronous=OFF")
            conn.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT)")
            conn.execute("CREATE TABLE lookups (tbl TEXT, codigo TEXT, descricao TEXT, PRIMARY KEY (tbl, codigo))")
            for table, sql in _TABLE_SQL.items():
                if table in files:
                    conn.execute(sql)
            for table in TABLES:
                if table not in files:
                    continue
                n_cols = ROW_SPEC[table][0]
                for path in files[table]:
                    stats: dict[str, Any] = {}
                    conn.execute("BEGIN")
                    batch: list[tuple[Any, ...]] = []
                    with open(path, "rb") as fh:
                        for row in iter_rows(fh, table, stats):
                            batch.append(row if table not in LOOKUP_TABLES else (table, *row))
                            if len(batch) >= BATCH:
                                _insert(conn, table, n_cols, batch)
                    _insert(conn, table, n_cols, batch)
                    conn.execute("COMMIT")
                    counts[table] = counts.get(table, 0) + int(stats.get("rows", 0))
                    if progress:
                        progress({"event": "loaded", "table": table, "file": path.name, "rows": stats.get("rows", 0),
                                  "bad_rows": stats.get("bad_rows", 0)})
            for table, sqls in _INDEX_SQL.items():  # indexes after the load (P238 cond 3)
                if table in files:
                    for sql in sqls:
                        conn.execute(sql)
            if "estabelecimentos" in files:
                conn.execute("BEGIN")
                _contacts(conn)
                conn.execute("COMMIT")
            meta = {
                "schema": INDEX_SCHEMA, "snapshot": month, "tables": ",".join(t for t in TABLES if t in files),
                "rows": json.dumps(counts, sort_keys=True), "imported_at": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "shared_contact_threshold": str(SHARED_CONTACT_THRESHOLD),
            }
            conn.executemany("INSERT INTO meta (k, v) VALUES (?, ?)", list(meta.items()))
        finally:
            conn.close()
        os.replace(tmp, out_path)
        paths.restrict_file(out_path)
        return {"snapshot": month, "rows": counts, "tables": [t for t in TABLES if t in files]}
    except (csv.Error, UnicodeError, zipfile.BadZipFile, EOFError) as exc:
        raise FormatChanged(f"RFB dump unreadable ({type(exc).__name__}: {str(exc)[:160]})") from None
    finally:
        if tmp.exists():
            tmp.unlink()


def _insert(conn: sqlite3.Connection, table: str, n_cols: int, batch: list[tuple[Any, ...]]) -> None:
    if not batch:
        return
    if table in LOOKUP_TABLES:
        conn.executemany("INSERT OR REPLACE INTO lookups (tbl, codigo, descricao) VALUES (?,?,?)", batch)
    else:
        width = len(batch[0])
        conn.executemany(f"INSERT INTO {table} VALUES ({','.join('?' * width)})", batch)  # noqa: S608 - fixed table names
    batch.clear()


# --------------------------------------------------------------------------------------
# WebDAV client and resumable downloads (P238 cond 1-3)
# --------------------------------------------------------------------------------------


def dataset_dir(home: Path | None = None) -> Path:
    base = Path(home) if home is not None else paths.datasets_dir()
    return paths.private_dir(base / INDEX_DIR)


def read_state(directory: Path | None = None) -> dict[str, Any]:
    target = (directory or (paths.datasets_dir() / INDEX_DIR)) / STATE_FILE
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_state(directory: Path, state: dict[str, Any]) -> None:
    paths.secure_write_text(directory / STATE_FILE, json.dumps(state, ensure_ascii=False, indent=1))


class RfbShare:
    """The RFB WebDAV share through a passive HTTP scope (``http``: a ScopedHttp limited to the RFB host)."""

    def __init__(self, http: Any, token: str, *, chunk: int = DEFAULT_CHUNK) -> None:
        self.http = http
        self.chunk = max(64 * 1024, int(chunk))
        redact.register_secret(token, "RFB share token")
        auth = base64.b64encode(f"{token}:".encode()).decode()
        self._auth = {"Authorization": f"Basic {auth}"}

    def _propfind(self, url: str, what: str) -> list[dict[str, Any]]:
        resp = self.http.request(
            "PROPFIND", url, data=PROPFIND_BODY, headers={**self._auth, "Depth": "1", "Content-Type": "text/xml"},
            ttl=0, allow_redirects=False, timeout=60.0, source=SOURCE,
        )
        problem = webdav_problem(int(resp.status), dict(resp.headers or {}), resp.content)
        if problem:
            _raise_for(problem, what)
        if int(resp.status) != 207:
            raise FormatChanged(f"PROPFIND {what}: HTTP {resp.status} instead of 207 multistatus")
        return parse_multistatus(resp.content)

    def months(self) -> list[dict[str, Any]]:
        return months_of(self._propfind(WEBDAV_URL, "share root"))

    def month(self, month: str) -> dict[str, Any]:
        if not MONTH_RE.match(month):
            raise ValueError(f"not a YYYY-MM month: {month!r}")
        summary = month_files(self._propfind(f"{WEBDAV_URL}{month}/", f"month {month}"))
        if not summary["files"]:
            raise FormatChanged(f"month {month} lists no RFB file: layout change (never 'no companies')")
        return summary

    def download(self, month: str, entry: dict[str, Any], dest_dir: Path, progress: Callable[[dict[str, Any]], None] | None = None) -> Path:
        """Resumable Range download of one file into ``dest_dir`` (``.part`` + sidecar ETag; size/ETag checked)."""
        name = entry["name"]
        size = int(entry["bytes"])
        etag = entry.get("etag") or ""
        final = dest_dir / name
        if final.exists() and final.stat().st_size == size and _sidecar(final).get("etag") == etag:
            return final  # already complete (resumed import)
        part = dest_dir / f"{name}.part"
        side = _sidecar(part)
        have = part.stat().st_size if part.exists() and side.get("etag") == etag and side.get("size") == size else 0
        if have == 0 or not part.exists():
            fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.close(fd)
            _write_sidecar(part, {"etag": etag, "size": size})
        url = f"{WEBDAV_URL}{month}/{name}"
        while have < size:
            end = min(have + self.chunk, size) - 1
            headers = {**self._auth, "Range": f"bytes={have}-{end}"}
            if etag:
                headers["If-Range"] = f'"{etag}"'
            resp = self.http.request("GET", url, headers=headers, ttl=0, allow_redirects=False, max_bytes=self.chunk + 1,
                                     timeout=REQUEST_TIMEOUT, source=SOURCE)
            status = int(resp.status)
            problem = webdav_problem(status, dict(resp.headers or {}), (resp.content or b"")[:4096] if status not in (200, 206) else b"")
            if problem:
                _raise_for(problem, name)
            got_etag = str((resp.headers or {}).get("etag") or (resp.headers or {}).get("oc-etag") or "").strip('"')
            if etag and got_etag and got_etag != etag:
                part.unlink(missing_ok=True)
                raise ImportError_(f"{name} changed on the share during the download (ETag): run the import again")
            body = bytes(resp.content or b"")
            if status == 206:
                m = re.match(r"bytes (\d+)-(\d+)/(\d+|\*)", str((resp.headers or {}).get("content-range") or ""))
                if not m or int(m.group(1)) != have or len(body) != int(m.group(2)) - int(m.group(1)) + 1:
                    raise ImportError_(f"{name}: unexpected Content-Range in a resumed download")
            elif status == 200:
                if have != 0 or len(body) != size or getattr(resp, "truncated", False):
                    part.unlink(missing_ok=True)
                    raise ImportError_(f"{name}: the server ignored the Range request: run the import again")
            else:
                raise ImportError_(f"{name}: HTTP {status}")
            with open(part, "ab") as fh:
                fh.write(body)
            have += len(body)
            if progress:
                progress({"event": "download", "file": name, "done": have, "total": size})
        if part.stat().st_size != size:
            part.unlink(missing_ok=True)
            raise ImportError_(f"{name}: size mismatch after the download")
        os.replace(part, final)
        paths.restrict_file(final)
        _write_sidecar(final, {"etag": etag, "size": size})
        _sidecar_path(part).unlink(missing_ok=True)
        return final


def _sidecar_path(path: Path) -> Path:
    return path.with_name(path.name + ".json")


def _sidecar(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(_sidecar_path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_sidecar(path: Path, data: dict[str, Any]) -> None:
    paths.secure_write_text(_sidecar_path(path), json.dumps(data))


def share_token(config: Any) -> str:
    """The configured official share token (P238 cond 2) or ImportUnavailable with the doctor hint."""
    link = str(config.get("rfb_cnpj_bulk_share_link", "") or "").strip()
    source = str(config.get("rfb_cnpj_bulk_share_source", "") or "").strip()
    checked = str(config.get("rfb_cnpj_bulk_share_checked_at", "") or "").strip()
    token = share_token_from_link(link)
    if not token:
        raise ImportUnavailable("no RFB share link configured (only the link RFB publishes on its official page)", hint=DOCTOR_HINT)
    if not official_source(source):
        raise ImportUnavailable("the RFB share link has no official RFB/gov.br source page recorded (never a token from "
                                "third-party code)", hint=DOCTOR_HINT)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", checked):
        raise ImportUnavailable("record when the share link was read from the official page (rfb_cnpj_bulk_share_checked_at)",
                                hint=DOCTOR_HINT)
    return token


def scoped_http(runtime: Any) -> Any:
    """A passive HTTP scope over the runtime client, limited to the RFB share host (never during a scan)."""
    from v3lum.core.http import ScopedHttp

    return ScopedHttp(  # v3lum-lint: allow LINT-01 -- out-of-band RFB bulk importer (v3lum data import-rfb, never during a scan), restricted to the official RFB share host
        runtime.http, module=MODULE, provider=PROVIDER, sources=(SOURCE,), allowed_hosts=(SHARE_HOST,), disclosure="third_party",
        opsec="passive", max_requests=None, cancel_event=getattr(runtime, "cancel_event", None), clock=getattr(runtime, "clock", None),
    )


def plan(runtime: Any, *, tables: Iterable[str] | None = None, month: str | None = None, home: Path | None = None) -> dict[str, Any]:
    """Read the share and return the download plan (size, required free space, refusal) without downloading."""
    token = share_token(runtime.config)
    share = RfbShare(scoped_http(runtime), token)
    months = share.months()
    if not months:
        raise FormatChanged("no YYYY-MM collection in the RFB share root (never 'no companies')")
    chosen = month or months[-1]["month"]
    summary = share.month(chosen)
    directory = dataset_dir(home)
    free = shutil.disk_usage(directory).free
    p = download_plan(summary, free, tuple(tables or PRESETS[DEFAULT_PRESET]))
    p.update(month=chosen, month_bytes=next((m["bytes"] for m in months if m["month"] == chosen), None),
             months=[m["month"] for m in months])
    return p


def import_rfb(runtime: Any, *, tables: Iterable[str] | None = None, month: str | None = None, home: Path | None = None,
               keep_downloads: bool = False, progress: Callable[[dict[str, Any]], None] | None = None,
               confirm: Callable[[dict[str, Any]], bool] | None = None, now: datetime | None = None) -> dict[str, Any]:
    """The whole import: plan (size + 3x free space), resumable downloads, ETL, atomic install, cleanup.

    Returns ``{status: imported | refused | unavailable | stopped | format_changed | error, reason, hint, ...}``
    and records it in the state file the module reads (a failed import never reads as 'no companies').
    """
    directory = dataset_dir(home)
    when = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    selected = tuple(tables or PRESETS[DEFAULT_PRESET])
    result: dict[str, Any] = {"status": "error", "reason": "", "hint": "", "month": month, "tables": list(selected), "at": when}
    try:
        token = share_token(runtime.config)
        share = RfbShare(scoped_http(runtime), token, chunk=_chunk(runtime.config))
        months = share.months()
        if not months:
            raise FormatChanged("no YYYY-MM collection in the RFB share root (never 'no companies')")
        chosen = month or months[-1]["month"]
        result["month"] = chosen
        summary = share.month(chosen)
        p = download_plan(summary, shutil.disk_usage(directory).free, selected)
        result.update(download_bytes=p["download_bytes"], required_free_bytes=p["required_free_bytes"], free_bytes=p["free_bytes"])
        if progress:
            progress({"event": "plan", **{k: v for k, v in p.items() if k != "files"}, "month": chosen, "files": len(p["files"])})
        if not p["ok"]:
            state = "format_changed" if p["missing"] else "refused"
            result.update(status=state, reason=p["refusal"])
            return _finish(directory, result)
        if confirm is not None and not confirm({**p, "month": chosen}):
            result.update(status="refused", reason="not confirmed by the analyst")
            return _finish(directory, result)
        dl_dir = paths.private_dir(directory / DOWNLOADS / chosen)
        files: dict[str, list[Path]] = {}
        for entry in p["files"]:
            files.setdefault(entry["table"], []).append(share.download(chosen, entry, dl_dir, progress))
        info = build_index(files, directory / INDEX_FILE, month=chosen, progress=progress, now=now)
        removed = _cleanup(directory, chosen, keep_current=keep_downloads)
        result.update(status="imported", reason=f"{snapshot_label(chosen)} imported", rows=info["rows"], removed=removed)
    except ImportError_ as exc:
        result.update(status=exc.state, reason=str(exc), hint=exc.hint)
    except (OSError, sqlite3.Error) as exc:
        result.update(status="error", reason=f"{type(exc).__name__}: {str(exc)[:200]}")
    return _finish(directory, result)


def _chunk(config: Any) -> int:
    try:
        mb = float(config.get("rfb_cnpj_bulk_chunk_mb", DEFAULT_CHUNK // (1024 * 1024)) or 16)
    except (TypeError, ValueError):
        mb = 16
    return int(max(0.0625, min(mb, 256)) * 1024 * 1024)


def _cleanup(directory: Path, imported: str, *, keep_current: bool) -> list[str]:
    """Delete superseded monthly dumps (storage limitation, P238 cond 5); the current one unless kept."""
    removed = []
    base = directory / DOWNLOADS
    if not base.is_dir():
        return removed
    for child in sorted(base.iterdir()):
        if not MONTH_RE.match(child.name):
            continue
        if child.name < imported or (child.name == imported and not keep_current):
            shutil.rmtree(child, ignore_errors=True)
            removed.append(child.name)
    return removed


def _finish(directory: Path, result: dict[str, Any]) -> dict[str, Any]:
    state = read_state(directory)
    state["last_import"] = {k: v for k, v in result.items() if k in ("status", "reason", "hint", "month", "tables", "at")}
    if result.get("status") == "imported":
        state["imported"] = state["last_import"]
    _write_state(directory, state)
    return result


# --------------------------------------------------------------------------------------
# entry point (outside any scan)
# --------------------------------------------------------------------------------------


def _human(n: Any) -> str:
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} TB"  # pragma: no cover


class ImportRfbCommand:
    """``v3lum data import-rfb``: CommandSpec-compatible (add_arguments / run) for the core data command."""

    @staticmethod
    def add_arguments(parser: Any) -> None:
        parser.add_argument("--tables", choices=sorted(PRESETS), default=DEFAULT_PRESET,
                            help="full | qsa (default: companies, establishments, partners, Simples) | names (P361 light index)")
        parser.add_argument("--names", dest="tables", action="store_const", const="names",
                            help="the light name index only (Empresas + Estabelecimentos, P361): same as --tables names")
        parser.add_argument("--month", default=None, help="YYYY-MM (default: the newest month on the share)")
        parser.add_argument("--plan", action="store_true", help="show the download size and the required free space, download nothing")
        parser.add_argument("--keep-downloads", action="store_true", help="keep this month's zips after the import")
        parser.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation after the plan")

    @staticmethod
    def run(args: Any, app: Any, console: Any = None) -> int:
        out = (lambda s: console.print(s, markup=False, highlight=False)) if console is not None else (lambda s: sys.stdout.write(s + "\n"))
        rt = app.runtime()
        tables = PRESETS[getattr(args, "tables", DEFAULT_PRESET) or DEFAULT_PRESET]
        if getattr(args, "plan", False):
            try:
                p = plan(rt, tables=tables, month=getattr(args, "month", None))
            except ImportError_ as exc:
                out(f"RFB import unavailable: {exc}" + (f"\n  hint: {exc.hint}" if exc.hint else ""))
                return 1
            out(f"month {p['month']}: {len(p['files'])} files, download {_human(p['download_bytes'])}, needs {_human(p['required_free_bytes'])} "
                f"free ({SPACE_FACTOR}x), free {_human(p['free_bytes'])}" + (f"; REFUSED: {p['refusal']}" if not p["ok"] else ""))
            return 0 if p["ok"] else 1

        last: dict[str, float] = {}

        def progress(ev: dict[str, Any]) -> None:
            if ev.get("event") == "plan":
                out(f"month {ev.get('month')}: {ev.get('files')} files, download {_human(ev.get('download_bytes'))}, "
                    f"needs {_human(ev.get('required_free_bytes'))} free, free {_human(ev.get('free_bytes'))}")
            elif ev.get("event") == "download":
                pct = 100.0 * ev["done"] / max(1, ev["total"])
                if pct - last.get(ev["file"], -100) >= 10 or ev["done"] == ev["total"]:
                    last[ev["file"]] = pct
                    out(f"  {ev['file']}: {pct:5.1f}% of {_human(ev['total'])}")
            elif ev.get("event") == "loaded":
                out(f"  loaded {ev['table']} from {ev['file']}: {ev['rows']} rows ({ev['bad_rows']} skipped)")

        def confirm(p: dict[str, Any]) -> bool:
            if getattr(args, "yes", False):
                return True
            if not sys.stdin.isatty():
                out("non-interactive: re-run with --yes after reviewing the plan (--plan)")
                return False
            return input(f"download {_human(p['download_bytes'])} from RFB now? [y/N] ").strip().lower() in ("y", "yes")

        try:
            res = import_rfb(rt, tables=tables, month=getattr(args, "month", None), keep_downloads=getattr(args, "keep_downloads", False),
                             progress=progress, confirm=confirm)
        except KeyboardInterrupt:
            out("interrupted: partial downloads are kept and resumed by the next run")
            return 130
        out(f"{res['status']}: {res['reason']}" + (f"\n  hint: {res['hint']}" if res.get("hint") else ""))
        return 0 if res["status"] == "imported" else 1


def main(argv: list[str] | None = None) -> int:
    import argparse

    from v3lum.app import App
    from v3lum.modules.brazil_public_data import rfb_cnpj_bulk  # noqa: F401 - registers the rfb_cnpj_bulk_* settings

    parser = argparse.ArgumentParser(prog="python -m v3lum.modules.brazil_public_data.rfb_import",
                                     description="Import the RFB CNPJ open-data dump into the local rfb_cnpj_bulk index (outside any scan).")
    ImportRfbCommand.add_arguments(parser)
    args = parser.parse_args(argv)
    with contextlib.suppress(AttributeError):
        os.umask(0o077)
    return ImportRfbCommand.run(args, App(), None)


if __name__ == "__main__":  # pragma: no cover - manual entry point
    raise SystemExit(main())


__all__ = [
    "DEFAULT_PRESET", "ImportRfbCommand", "ImportStopped", "ImportUnavailable", "PRESETS", "RfbShare", "SHARED_CONTACT_LABEL",
    "SHARED_CONTACT_THRESHOLD", "TABLES", "build_index", "building_key", "download_plan", "import_rfb", "iter_rows", "match_key",
    "month_files", "months_of", "parse_multistatus", "plan", "read_state", "share_token", "share_token_from_link", "snapshot_label",
    "strip_cpf_from_name", "webdav_problem",
]
