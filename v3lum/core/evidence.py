"""Evidence store (case evidence files, P324 groundwork).

``EvidenceStore(case_dir).save(res, *, requests=()) -> (path, sha256)`` writes the sanitized raw
payload of one module run to ``<case_dir>/evidence/<module>__<type>__<pseudonym12>__<sha10>.json``:

* the payload is ``{module, entity, collected_at, redacted_fields, data}`` plus ``requests`` (the
  redacted request records of the run - ``ctx.http.request_log`` - when given); it passes the
  central redactor (AR01) before it is hashed, so no configured key value reaches a file;
* the file name never holds the investigated value (A4/AR24): the entity part is the keyed HMAC of
  the installation (``hmacid.hmac12``; random hex while the secret is unavailable, never a plain
  hash of the value) and the last part is the content SHA-256 (content addressing: a re-collection
  with other bytes is a new file, the same bytes the same file);
* files are 0600 from creation in 0700 directories (A10/AR03), whatever the process umask, and a
  symbolic link planted at the file name is never followed;
* SECRET_TYPES values are written redacted (``entities.redacted_value``): the entity key, and every
  raw secret value of the run's entity or pivots wherever it appears in the payload (raw secrets
  exist only in memory during the run, defence in depth behind the sanitizer).

The engine moves its evidence writer here in wave 2 (WP08); the evidence record with the request
context, re-collection versions, the audit trail and ``cases verify`` arrive with WP15 (wave 3).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import secrets
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from v3lum.core import entities as _entities

__all__ = ["EVIDENCE_DIR", "EvidenceStore", "evidence_name"]

#: Sub-directory of a case directory holding the evidence files.
EVIDENCE_DIR = "evidence"
_DIR_MODE = 0o700
_FILE_MODE = 0o600
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _redact(text: str) -> str:
    try:
        from v3lum.core import redact
    except ImportError:  # pragma: no cover - redactor not installed
        return text
    return str(redact.redact_text(text))


def _pseudonym(entity: Any) -> str:
    """Keyed HMAC (12 hex) of the entity value (A4 BR7). When the installation secret is unavailable
    the name part is random: a plain hash of the value could be tested against guessed values (an
    e-mail address, a phone number), which is what the keyed HMAC prevents."""
    try:
        from v3lum.core import hmacid

        return str(hmacid.hmac12(entity.type, entity.value))
    except Exception:  # noqa: BLE001 - the name only needs to be value-free; never fail the evidence
        return secrets.token_hex(6)


def _entity_key(entity: Any) -> str:
    etype = getattr(entity, "type", None)
    value = str(getattr(entity, "value", ""))
    if etype in _entities.SECRET_TYPES:
        try:
            value = _entities.redacted_value(etype, value)
        except Exception:  # noqa: BLE001 - never write a raw secret
            value = "[redacted]"
    return f"{getattr(etype, 'value', etype)}:{value}"


def _without_raw_secrets(payload: dict[str, Any], res: Any) -> Any:
    """``payload`` with every raw SECRET_TYPES value of the run (its entity and its pivots) replaced
    by the persisted form - wherever a module echoed it (a decoded token, a request URL...)."""
    try:
        from v3lum.core.graph import redact_secret_values, secret_value_map
    except ImportError:  # pragma: no cover - the graph is part of the core
        return payload
    entities = [getattr(res, "entity", None)] + [getattr(p, "entity", None) for p in (getattr(res, "pivots", None) or ())]
    return redact_secret_values(payload, secret_value_map(entities))


def evidence_name(module: str, entity: Any, digest: str) -> str:
    """``<module>__<type>__<pseudonym12>__<sha10>.json`` (no investigated value in the name)."""
    mod = _SAFE.sub("_", str(module or ""))[:64] or "module"
    etype = _SAFE.sub("_", str(getattr(getattr(entity, "type", None), "value", "") or "entity"))[:32]
    return f"{mod}__{etype}__{_pseudonym(entity)}__{digest[:10]}.json"


def _request_record(info: Any) -> dict[str, Any] | None:
    """A JSON-safe, redacted summary of one RequestInfo (or a dict with the same keys)."""
    data = info.to_dict() if hasattr(info, "to_dict") else (dict(info) if isinstance(info, dict) else None)
    if not isinstance(data, dict):
        return None
    keep = ("ts", "method", "url", "host", "status", "bytes", "elapsed", "cached", "error", "source", "opsec", "egress_profile", "resolved_ip", "port")
    out = {k: data.get(k) for k in keep if k in data}
    classification = data.get("classification")
    if isinstance(classification, dict):
        out["classification"] = {k: classification.get(k) for k in ("status", "reason_code", "marker_id") if k in classification}
    return out


class EvidenceStore:
    """Writes evidence files of one case (see the module docstring)."""

    def __init__(self, case_dir: str | Path, *, now: Callable[[], _dt.datetime] | None = None) -> None:
        self.case_dir = Path(case_dir)
        self._now = now

    @property
    def directory(self) -> Path:
        return self.case_dir / EVIDENCE_DIR

    def _now_iso(self) -> str:
        now = self._now() if self._now is not None else _dt.datetime.now(_dt.timezone.utc)
        return now.isoformat(timespec="seconds")

    def ensure_dirs(self) -> Path:
        """Create the case and evidence directories owner-only (0700)."""
        for directory in (self.case_dir, self.directory):
            directory.mkdir(parents=True, exist_ok=True)
            try:
                if directory.stat().st_mode & 0o077:
                    os.chmod(directory, _DIR_MODE)
            except OSError:  # pragma: no cover - a foreign-owned directory: the 0600 files still protect it
                pass
        return self.directory

    def save(self, res: Any, *, requests: Iterable[Any] = ()) -> tuple[str, str]:
        """Write the evidence of ``res`` (a ModuleResult); returns ``(path, sha256)``.

        Raises OSError/TypeError/ValueError when the file cannot be written (the caller keeps the
        result and notes the failure).
        """
        payload: dict[str, Any] = {
            "module": res.module,
            "entity": _entity_key(res.entity),
            "collected_at": self._now_iso(),
            "redacted_fields": list(getattr(res, "redacted_fields", []) or []),
            "data": res.raw,
        }
        records = [r for r in (_request_record(info) for info in requests or ()) if r]
        if records:
            payload["requests"] = records
        payload = _without_raw_secrets(payload, res)
        # AR01: configured key values and key-like URL parameters never reach an evidence file
        blob = _redact(json.dumps(payload, ensure_ascii=False, indent=1, default=str)).encode("utf-8")
        digest = hashlib.sha256(blob).hexdigest()
        path = self.ensure_dirs() / evidence_name(res.module, res.entity, digest)
        # evidence can hold provider data about people: owner-only from creation (A10/AR03); never
        # through a link planted at the name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), _FILE_MODE)
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        os.chmod(path, _FILE_MODE)  # an older copy of the same evidence file keeps no looser mode
        return str(path), digest
