"""Report writers. All work from the case dict (``CaseResult.to_dict()`` or a stored case).

:func:`write_reports` (reports v2, WP20):

* **File names carry the case id and the TLP label** (A2): ``<case_id>.TLP-<LABEL>.html`` /
  ``.md`` / ``.json`` / ``.stix.json`` / ``.misp.json`` / ``.pivots.html`` (e.g.
  ``20261126-101500-ab12.TLP-AMBER.html``). A case id that is not a plain name (path separators,
  '..') is refused, so a damaged or crafted case can never write outside ``out_dir``; the purge
  removes recorded report files only when their name contains the case id (WP10).
* **Owner-only files** (AR03/A10): every report and sidecar is written 0600 through
  :func:`v3lum.paths.secure_write_text` (``os.open(..., 0o600)`` + atomic replace) whatever the
  umask and wherever ``out_dir`` is; a missing ``out_dir`` is created 0700.
* **Sidecar hashes** (P336 cond 4, P324 cond 6): ``<report>.sha256`` next to every report, in the
  ``sha256sum`` format (``<hex>  <file name>``), because a file cannot contain its own hash.
* **Recording** (``record=True``): the report and sidecar paths (``Store.record_report_paths``: the
  purge removes them, ``-o`` copies included) and their SHA-256 (``Store.record_report_hashes``:
  ``v3lum cases verify`` recomputes them) go to the default case DB (``Store()``) whenever the case id is known,
  so App.scan and ``cases report`` need no change. A recording failure never fails the write: it is
  returned under the key ``'_errors'`` (a list of strings, present only on failure).
* **TLP rules** (A2, P375 cond 3): at TLP:CLEAR/GREEN every format is written from a copy without
  cross-case or internal-platform references (``report.summary.shareable_view``); the JSON report
  carries the top-level ``tlp`` field and masks CPF, VIN, personal-form EU VAT, PIX, payment-card and
  secret entity values unless the view is unmasked (``show_personal``, recorded in the case
  options/audit: AR24).
* Every format is rendered before the first file is written (a renderer failure leaves nothing
  behind), and whatever was written is recorded even when a later write fails.
* Formats: ``html`` (self-contained, CSP-hashed), ``md``, ``json``, ``stix`` (``report.stix.bundle``),
  ``misp`` (``report.misp.event``, WP21) and ``pivots`` (the standalone manual-pivot page,
  ``report.pivot_page``, P311 cond 11).
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from v3lum import paths

__all__ = ["FORMATS", "report_name", "write_reports"]

log = logging.getLogger(__name__)

#: Report formats ('markdown' is accepted for 'md').
FORMATS = ("html", "md", "json", "stix", "misp", "pivots")
#: File-name suffix per format (after '<case_id>.TLP-<LABEL>').
SUFFIXES = {"html": ".html", "md": ".md", "json": ".json", "stix": ".stix.json", "misp": ".misp.json", "pivots": ".pivots.html"}
#: Suffix of the hash sidecar written next to every report.
SIDECAR_SUFFIX = ".sha256"

#: Case ids name files and directories: no separators, no '..' (the rule of paths.case_dir).
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


def _tlp_tag(case: dict[str, Any]) -> str:
    from v3lum.core import tlp as _tlp
    from v3lum.report.summary import tlp_value

    return _tlp.parse(tlp_value(case)).file_tag


def report_name(case: dict[str, Any], fmt: str) -> str:
    """The file name of one report: ``<case_id>.TLP-<LABEL><suffix>`` (A2). ValueError for an
    invalid case id or an unknown format."""
    case_id = str(case.get("case_id") or "")
    if not _CASE_ID_RE.match(case_id):
        raise ValueError(f"invalid case id {case_id[:80]!r}: reports are named after it (letters, digits, '-' and '_' only)")
    fmt = _format(fmt)
    return f"{case_id}.{_tlp_tag(case)}{SUFFIXES[fmt]}"


def _format(fmt: Any) -> str:
    text = str(fmt or "").strip().lower()
    if text == "markdown":
        text = "md"
    if text not in SUFFIXES:
        raise ValueError(f"unknown report format {fmt!r} (choose from {', '.join(FORMATS)})")
    return text


#: Entity types whose raw value never leaves the case store in a JSON report (AR24): CPF, VIN, the
#: personal form of EU VAT numbers, PIX keys/BR Codes, payment cards and secrets are replaced by their
#: masked display (``ui.safe.entity_display``) unless the view is unmasked (``show_personal``).
_JSON_MASKED_TYPES = frozenset({"cpf", "vin", "eu_vat", "pix_key", "pix_brcode", "payment_card"})
#: Shortest raw value replaced by substring (shorter ones would hit unrelated text).
_MIN_MASKED_LEN = 6


def _masked_types() -> frozenset[str]:
    try:
        from v3lum.core.entities import SECRET_TYPES

        return _JSON_MASKED_TYPES | frozenset(t.value for t in SECRET_TYPES)
    except Exception:  # noqa: BLE001
        return _JSON_MASKED_TYPES


def _cpf_values(case: dict[str, Any]) -> dict[str, str]:
    """Raw values of the case's masked-type entities and seeds (CPF in every punctuation form, VIN,
    personal-form EU VAT, PIX, payment cards, secrets) -> their masked display (AR24)."""
    from v3lum.core.entities import mask_cpf
    from v3lum.ui.safe import entity_display

    masked_types = _masked_types()
    raw: set[tuple[str, str]] = set()
    for node in case.get("entities") or ():
        if isinstance(node, dict) and str(node.get("type") or "") in masked_types and node.get("value"):
            raw.add((str(node["type"]), str(node["value"])))
    for key in list(case.get("seeds") or ()) + [f"{i.get('type')}:{i.get('value')}" for i in case.get("inputs") or () if isinstance(i, dict)]:
        etype, _, value = str(key).partition(":")
        if etype in masked_types and value:
            raw.add((etype, value))
    out: dict[str, str] = {}
    for etype, value in raw:
        if etype == "cpf":
            digits = re.sub(r"\D", "", value)
            try:
                masked = mask_cpf(digits)
            except Exception:  # noqa: BLE001 - an unreadable CPF is fully hidden
                masked = "***.***.***-**"
            for form in {value, digits, f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}" if len(digits) == 11 else value}:
                if form and len(form) >= 11:
                    out[form] = masked
            continue
        try:
            masked = entity_display(etype, value, show_personal=False, no_defang=True, defang_urls=False)
        except Exception:  # noqa: BLE001 - a display problem hides the value entirely
            masked = f"*** ({etype})"
        if masked != value and len(value) >= _MIN_MASKED_LEN:
            out[value] = masked
    return out


def _mask_json(value: Any, mapping: dict[str, str]) -> Any:
    if not mapping:
        return value
    if isinstance(value, str):
        for raw in sorted(mapping, key=len, reverse=True):
            if raw in value:
                value = value.replace(raw, mapping[raw])
        return value
    if isinstance(value, dict):
        return {_mask_json(k, mapping) if isinstance(k, str) else k: _mask_json(v, mapping) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mask_json(v, mapping) for v in value]
    return value


def _json_text(case: dict[str, Any], *, show_personal: bool) -> str:
    from v3lum.report.summary import tlp_value

    data = {"tlp": tlp_value(case), **{k: v for k, v in case.items() if k != "tlp"}}
    if not show_personal:
        data = _mask_json(copy.deepcopy(data), _cpf_values(case))
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


def _render(fmt: str, view: dict[str, Any], *, show_personal: bool, no_defang: bool) -> str:
    if fmt == "html":
        from v3lum.report import html as html_r

        return html_r.render(view, show_personal=show_personal, no_defang=no_defang)
    if fmt == "md":
        from v3lum.report import markdown as md_r

        return md_r.render(view, show_personal=show_personal, no_defang=no_defang)
    if fmt == "pivots":
        from v3lum.report import pivot_page

        return pivot_page.render(view, show_personal=show_personal, no_defang=no_defang)
    if fmt == "json":
        return _json_text(view, show_personal=show_personal)
    if fmt == "stix":
        from v3lum.report import stix as stix_r

        return json.dumps(stix_r.bundle(view), ensure_ascii=False, indent=2)
    if fmt == "misp":
        misp_r = importlib.import_module("v3lum.report.misp")  # WP21
        return json.dumps(misp_r.event(view), ensure_ascii=False, indent=2)
    raise ValueError(f"unknown report format {fmt!r} (choose from {', '.join(FORMATS)})")


def _record(case_id: str, written: list[str], hashes: dict[str, str]) -> list[str]:
    """Record report paths and hashes in the default case DB; returns the problems (never raises)."""
    try:
        from v3lum.core.store import Store

        store = Store()
    except Exception as exc:  # noqa: BLE001 - a recording failure never fails the write
        return [f"report paths/hashes not recorded: case DB unavailable ({type(exc).__name__})"]
    errors: list[str] = []
    try:
        store.record_report_paths(case_id, written)
        store.record_report_hashes(case_id, hashes)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"report paths/hashes not recorded: {type(exc).__name__}: {str(exc)[:200]}")
    finally:
        try:
            store.close()
        except Exception:  # noqa: BLE001
            pass
    return errors


def write_reports(
    case: dict[str, Any],
    formats: list[str] | tuple[str, ...],
    out_dir: str | Path,
    *,
    record: bool = True,
    show_personal: bool | None = None,
    no_defang: bool | None = None,
) -> dict[str, Any]:
    """Write the requested formats into ``out_dir`` and return ``{format: path}``.

    Files are named ``<case_id>.TLP-<LABEL><suffix>`` (:func:`report_name`), written 0600, each with
    a ``<path>.sha256`` sidecar. With ``record`` (default) the paths and SHA-256 values are recorded
    in the default case DB (purge and ``cases verify``); a recording failure is returned under
    ``'_errors'`` instead of raising. ``show_personal`` / ``no_defang`` default to the flags recorded
    in ``case['options']``. Unknown formats raise ValueError before anything is written."""
    case = case if isinstance(case, dict) else {}
    case_id = str(case.get("case_id") or "")
    if not _CASE_ID_RE.match(case_id):
        raise ValueError(f"invalid case id {case_id[:80]!r}: reports are named after it (letters, digits, '-' and '_' only)")
    wanted: list[str] = []
    for fmt in formats:
        name = _format(fmt)
        if name not in wanted:
            wanted.append(name)
    opts = case.get("options") if isinstance(case.get("options"), dict) else {}
    show = bool(opts.get("show_personal", False)) if show_personal is None else bool(show_personal)
    raw = bool(opts.get("no_defang", False)) if no_defang is None else bool(no_defang)
    from v3lum.report.summary import shareable_view

    view = shareable_view(case)  # A2: cross-case references never leave a CLEAR/GREEN report
    # Every format is rendered before anything is written: a renderer failure leaves no file behind
    # (an unrecorded report would escape the purge and `cases verify`).
    rendered = [(fmt, report_name(case, fmt), _render(fmt, view, show_personal=show, no_defang=raw).encode("utf-8")) for fmt in wanted]
    out = paths.private_dir(out_dir)
    written: dict[str, Any] = {}
    hashes: dict[str, str] = {}
    try:
        for fmt, name, data in rendered:
            target = out / name
            paths.secure_write_bytes(target, data)
            digest = hashlib.sha256(data).hexdigest()
            written[fmt] = str(target)
            hashes[os.path.abspath(str(target))] = digest
            sidecar = Path(str(target) + SIDECAR_SUFFIX)
            side = f"{digest}  {target.name}\n".encode()
            paths.secure_write_bytes(sidecar, side)
            hashes[os.path.abspath(str(sidecar))] = hashlib.sha256(side).hexdigest()  # the sidecar is recorded too
    finally:
        # Recorded even when a later write failed (disk full...): every file on disk stays known to
        # the purge and to `cases verify`.
        if record and hashes:
            errors = _record(case_id, list(hashes), hashes)
            if errors:
                for err in errors:
                    log.warning("%s", err)
                written["_errors"] = errors
    return written
