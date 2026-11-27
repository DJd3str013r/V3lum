"""``v3lum export``: STIX 2.1 / MISP files and the gated push to the team's own MISP/OpenCTI (P303;
A1, A2, A7, A12).

* ``export <case> [--format stix|misp] [-o FILE] [--include-personal] [--include-weak]`` writes the
  stored case (analyst overrides applied, so confirmed findings count) as a STIX 2.1 bundle
  (``v3lum.report.stix.bundle``) or a MISP event (``v3lum.report.misp.event``) to a 0600 file whose
  name carries the TLP (``v3lum-<case>.TLP-AMBER.stix.json``; a ``-o`` name without the label gets
  it inserted before the extension). Default directory: setting ``report_dir``, else the case
  directory. The file is recorded for the purge and ``cases verify`` (``record_reports``) and the
  export is written to the case audit trail (kind 'export': format, file name, SHA-256, flags), so
  ``--include-personal`` - personal data in the file, CPF still masked - is always on record.
* ``export <case> --push misp|opencti [--dry-run] [--allow-engagement] [--include-weak] [-y]``
  sends the case only to the configured **internal** instance of the organisation: setting
  ``misp_url`` / ``opencti_url`` (a plain https base URL: no credentials, query or fragment),
  provider ``internal_misp`` / ``internal_opencti`` (``internal: true``, never flagged as publishing
  or reusing what it receives, ``trusted`` tier for AMBER+STRICT; a URL whose host another provider
  owns - a community or another organisation's instance - is refused), key ``misp`` / ``opencti``
  (``v3lum keys``), TLS verification always on (setting ``ca_bundle``; no option turns it off). It first prints the
  dry-run summary ('1 event, 23 attributes, 4 to_ids'); ``--dry-run`` stops there with no request.
  Otherwise an interactive confirmation naming the host is required (a non-TTY session refuses
  unless ``--yes``). MISP: ``POST /events/add`` (``/events/edit/<uuid>`` when the event already
  exists) of an unpublished event with distribution 0 (your organisation only) at every TLP, no
  sharing group, so nothing auto-syncs. OpenCTI: the bundle is uploaded to the import area
  (GraphQL ``uploadImport``) where an analyst validates it - a draft, never a direct write.
  Never pushed: TLP:RED cases, research-profile cases (A1), LIGHT/ACTIVE engagement cases unless
  ``--allow-engagement`` (recorded in the case audit), and personal data (``--include-personal``
  is refused with ``--push``). AMBER+STRICT goes only to these own instances. Every push attempt
  (sent, refused by the platform, failed, interrupted) is written to the case audit trail (kind
  'export_push'). A failure - 403/429/5xx, timeout, transport or client error - is 'could not
  verify', with the platform's error - errors inside an HTTP 200 body included; requests are never
  retried or redirected.
* File names always carry the case's own TLP label: a ``-o`` name with another label has it
  replaced (``x.TLP-CLEAR.json`` -> ``x.TLP-AMBER.json`` for an AMBER case).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import os
import re
import sys
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from rich.prompt import Confirm
from rich.text import Text

from v3lum import paths
from v3lum.commands import command

log = logging.getLogger("v3lum.commands.export")

__all__ = ["Export", "PUSH_TARGETS", "export_path", "push_refusal"]

#: --push target -> (URL setting, key name, provider id, source id).
PUSH_TARGETS: dict[str, tuple[str, str, str, str]] = {
    "misp": ("misp_url", "misp", "internal_misp", "internal_misp.events"),
    "opencti": ("opencti_url", "opencti", "internal_opencti", "internal_opencti.graphql"),
}
#: Push request timeout (an event with many attributes takes longer than a 5 s lookup).
PUSH_TIMEOUT = 60.0
EXPORT_AUDIT_KIND = "export"
PUSH_AUDIT_KIND = "export_push"
_OPENCTI_QUERY = "mutation V3lumImport($file: Upload!) { uploadImport(file: $file) { id name } }"
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
#: Any TLP label in a file name ('.TLP-AMBER+STRICT', '_tlp-clear', '.TLP:RED', legacy WHITE).
_TLP_LABEL_RE = re.compile(r"[._ -]?TLP[-_:]?(?:AMBER\+STRICT|AMBER|CLEAR|GREEN|RED|WHITE)(?![A-Za-z])", re.I)


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _user_error(message: str) -> Exception:
    from v3lum.app import UserError

    return UserError(message)


def _clean(value: Any) -> str:
    try:
        from v3lum.ui.safe import clean_text

        return clean_text(value)
    except Exception:  # noqa: BLE001 - WP14 helper unavailable: drop control characters here
        return "".join(ch for ch in str(value or "") if ch in "\n\t" or (ord(ch) >= 32 and not 0x7F <= ord(ch) <= 0x9F))


def _tty() -> bool:
    try:
        return bool(sys.stdin.isatty())
    except (AttributeError, ValueError):
        return False


def _analyst(app: Any) -> str:
    fn = getattr(app, "analyst", None)
    if callable(fn):
        try:
            return str(fn() or "")
        except Exception:  # noqa: BLE001
            pass
    return str(app.config.get("analyst") or "") or "unknown"


def _tlp_label(case: Mapping[str, Any]) -> tuple[str, str]:
    """(TLP value, 'TLP-AMBER' file tag) of a case (stix._tlp_value: missing -> amber, unreadable -> red)."""
    from v3lum.core import tlp as _tlp
    from v3lum.report.stix import _tlp_value

    value = _tlp_value(case)
    return value, _tlp.parse(value).file_tag


def _stored_case(app: Any, case_id: str) -> dict[str, Any]:
    data = app.store.get_case(case_id)
    if data is None:
        raise _user_error(f"case {_clean(case_id)[:80]!r} not found (see `v3lum cases list`)")
    return data


def _apply_overrides(app: Any, case: dict[str, Any]) -> dict[str, Any]:
    """The analyst's decisions win (P322 cond 3): confirmed findings are what the indicator gating
    reads. Override notes stay in the store (the exporters never copy them)."""
    from v3lum.commands.cases import apply_overrides

    ids = [str(i.get("id")) for group in ("findings", "correlations") for i in case.get(group) or () if isinstance(i, Mapping) and i.get("id")]
    if not ids:
        return case
    fn = getattr(app.store, "overrides_for", None)
    rows: Any = {}
    if callable(fn):
        try:
            rows = fn(ids) or {}
        except Exception as exc:  # noqa: BLE001 - no overrides table: nothing to apply
            log.debug("overrides_for failed: %s", type(exc).__name__)
            rows = {}
    apply_overrides(case, {str(k): (v if isinstance(v, list) else [v]) for k, v in dict(rows).items() if v})
    return case


def _audit(app: Any, case_id: str, kind: str, payload: Mapping[str, Any]) -> None:
    from v3lum.commands.cases import audit_append

    try:
        case_dir = str(paths.case_dir(case_id))
    except ValueError:
        case_dir = ""
    audit_append(app.store, case_id, case_dir, kind, dict(payload))


def _engagement(case: Mapping[str, Any]) -> bool:
    try:
        from v3lum.core.store import case_columns

        return bool(case_columns(case)["engagement"])
    except Exception:  # noqa: BLE001 - fall back to the mode
        options = case.get("options") if isinstance(case.get("options"), Mapping) else {}
        return str(options.get("mode") or "").lower() in ("light", "active") or bool(case.get("engagement"))


def push_refusal(case: Mapping[str, Any], *, allow_engagement: bool = False) -> str:
    """Why a case may never be pushed ('' when it may): TLP:RED (an unreadable TLP counts as RED),
    research licence profile (A1, P303 cond 10), LIGHT/ACTIVE engagement without
    ``allow_engagement`` (A7)."""
    from v3lum.report.stix import is_research

    tlp_value, _tag = _tlp_label(case)
    if tlp_value == "red":
        return "TLP:RED cases are never pushed to a platform (P303): export a file instead"
    if is_research(case):
        return "research-profile cases are never pushed (A1, P303): their sources' licences do not allow it"
    if _engagement(case) and not allow_engagement:
        return (
            "this case comes from a LIGHT/ACTIVE engagement: it is pushed only with --allow-engagement "
            "(the decision is recorded in the case audit)"
        )
    return ""


def export_path(case: Mapping[str, Any], fmt: str, out: str | None, default_dir: str | os.PathLike[str]) -> Path:
    """The export file: ``<default_dir>/v3lum-<case>.<TLP tag>.<fmt>.json``; ``out`` names a file or an
    existing directory (or ends with a separator). The file name always carries the case's own TLP
    label (A2): a ``-o`` name gets it inserted before its extension, and any other TLP label in that
    name (``x.TLP-CLEAR.json`` for an AMBER case) is replaced, never kept beside it. ValueError for a
    case id that is not a plain name."""
    case_id = str(case.get("case_id") or "")
    if not _CASE_ID_RE.match(case_id):
        raise ValueError(f"invalid case id {case_id[:80]!r}: exports are named after it")
    _value, tag = _tlp_label(case)
    name = f"v3lum-{case_id}.{tag}.{fmt}.json"
    if not out:
        return Path(default_dir) / name
    target = Path(os.path.expanduser(out))
    if str(out).endswith((os.sep, "/")) or target.is_dir():
        return target / name
    bare = _TLP_LABEL_RE.sub("", target.name).strip(".") or f"v3lum-{case_id}"
    stem, dot, ext = bare.rpartition(".")
    return target.with_name(f"{stem}.{tag}.{ext}" if dot and stem else f"{bare}.{tag}")


def _payload(fmt: str, case: Mapping[str, Any], *, include_personal: bool, include_weak: bool) -> tuple[dict[str, Any], dict[str, int]]:
    if fmt == "misp":
        from v3lum.report.misp import counts, event

        ev = event(case, include_personal=include_personal, include_weak=include_weak)
        return ev, counts(ev)
    from v3lum.report.stix import bundle

    b = bundle(case, include_personal=include_personal, include_weak=include_weak)
    objs = b.get("objects") or []
    return b, {"objects": len(objs), "indicators": sum(1 for o in objs if o.get("type") == "indicator")}


def _summary(fmt: str, numbers: Mapping[str, int]) -> str:
    if fmt == "misp":
        return f"1 event, {numbers.get('attributes', 0)} attributes, {numbers.get('to_ids', 0)} to_ids"
    return f"1 bundle, {numbers.get('objects', 0)} objects, {numbers.get('indicators', 0)} indicators"


# --------------------------------------------------------------------------------------
# file export
# --------------------------------------------------------------------------------------


def _export_file(app: Any, console: Any, args: Any, case: dict[str, Any]) -> int:
    from v3lum.commands.cases import record_reports

    fmt = args.format or "stix"
    case_id = str(case.get("case_id") or "")
    try:
        default_dir = str(app.config.get("report_dir") or "") or paths.case_dir(case_id)
        target = export_path(case, fmt, args.out, default_dir)
    except ValueError as exc:
        raise _user_error(f"cannot export: {_clean(exc)[:200]}") from None
    payload, numbers = _payload(fmt, case, include_personal=args.include_personal, include_weak=args.include_weak)
    paths.private_dir(target.parent)
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    paths.secure_write_text(target, text)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    record_reports(app.store, case_id, {f"export-{fmt}": str(target)})
    tlp_value, _tag = _tlp_label(case)
    _audit(app, case_id, EXPORT_AUDIT_KIND, {
        "format": fmt, "file": target.name, "sha256": digest, "tlp": tlp_value,
        "include_personal": bool(args.include_personal), "include_weak": bool(args.include_weak),
        "counts": dict(numbers), "analyst": _analyst(app),
    })
    if args.json:
        console.print_json(json.dumps({"case_id": case_id, "format": fmt, "path": str(target), "sha256": digest, "tlp": tlp_value, **numbers}))
        return 0
    console.print(Text(f"wrote {target} ({_summary(fmt, numbers)}, TLP:{tlp_value.upper()}, 0600)", style="v.ok"), soft_wrap=True)
    if args.include_personal:
        console.print(Text("contains personal data (LGPD): --include-personal recorded in the case audit; CPF stays masked", style="v.warn"))
    return 0


# --------------------------------------------------------------------------------------
# push
# --------------------------------------------------------------------------------------


def _target(app: Any, name: str, tlp_value: str = "amber") -> tuple[str, str, str, str, str]:
    """(base URL, host, key, provider id, source id) of an internal push target, or UserError."""
    from v3lum.core import providers

    setting, key_name, pid, sid = PUSH_TARGETS[name]
    url = str(app.config.get(setting) or "").strip()
    if not url:
        raise _user_error(f"--push {name} needs the setting {setting} (the organisation's own instance, https): v3lum config set {setting} https://...")
    try:
        parts = urlsplit(url)
        _port = parts.port  # a malformed port raises ValueError here
    except ValueError:
        raise _user_error(f"{setting} is not a valid URL") from None
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host:
        raise _user_error(f"{setting} must be an https URL: pushes use verified TLS only (A12)")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise _user_error(f"{setting} must be a plain base URL (no credentials, query or fragment): the key goes through `v3lum keys`")
    reg = providers.registry()
    prov = reg.get(pid)
    if prov is None or not bool(getattr(prov, "internal", False)):
        raise _user_error(f"provider {pid} is not registered as an internal platform: refused (pushes go only to the organisation's own instances)")
    flags = getattr(prov, "flags", None)
    if bool(getattr(flags, "publishes_queries", False)) or bool(getattr(flags, "reuses_queries", False)):
        raise _user_error(f"provider {pid} is flagged as publishing or reusing what it receives: never pushed to (rule 7)")
    if tlp_value == "amber+strict" and str(getattr(prov, "tier", "") or "") != "trusted":
        raise _user_error(f"TLP:AMBER+STRICT goes only to a trusted-tier instance of the organisation; {pid} is not trusted")
    if host not in {str(h).lower() for h in reg.hosts_for(pid, app.config)}:
        owner = reg.provider_for_host(host)
        who = f" (it belongs to provider {owner.id})" if owner is not None else ""
        raise _user_error(f"{host} is not the organisation's own {name} instance{who}: pushes never go to external communities or other organisations")
    key = ""
    getter = getattr(app.config, "key", None)
    if callable(getter):
        key = str(getter(key_name) or "")
    if not key:
        raise _user_error(f"--push {name} needs the API key {key_name!r} (v3lum keys set {key_name})")
    return url.rstrip("/"), host, key, pid, sid


def _body_json(resp: Any) -> Any:
    try:
        return resp.json()
    except Exception:  # noqa: BLE001 - not JSON
        return None


def _misp_error(body: Any, resp: Any) -> str:
    if isinstance(body, Mapping):
        for key in ("errors", "message", "name"):
            if body.get(key):
                return _clean(json.dumps(body[key], ensure_ascii=False) if not isinstance(body[key], str) else body[key])[:300]
    try:
        return _clean(resp.text)[:300]
    except Exception:  # noqa: BLE001
        return ""


def _send(rt: Any, method: str, url: str, **kw: Any) -> tuple[Any, str]:
    """(response, '') or (None, error text): transport, policy, quota, cancellation and any other
    client failure is 'could not verify' (403/429/5xx/timeouts never read as success or absence)."""
    from v3lum.core.http import Cancelled, ConfigError, HttpError, NetworkError, PolicyError, RequestCapReached

    try:
        return rt.http.request(method, url, timeout=PUSH_TIMEOUT, retries=0, allow_redirects=False, **kw), ""
    except HttpError as exc:
        detail = f"HTTP {exc.status}: {exc.message}" if exc.status else exc.message
        body = getattr(exc, "body", "") or ""
        return None, _clean(f"{detail} {body}".strip())[:300]
    except (NetworkError, PolicyError, Cancelled, RequestCapReached, ConfigError) as exc:
        return None, _clean(f"{type(exc).__name__}: {exc}")[:300]
    except Exception as exc:  # noqa: BLE001 - an unexpected client failure is still 'could not verify' (and audited)
        log.debug("push request failed: %s", type(exc).__name__)
        return None, _clean(f"{type(exc).__name__}: request failed")[:300]


def _push_misp(rt: Any, base: str, key: str, pid: str, sid: str, payload: Mapping[str, Any]) -> tuple[bool, dict[str, Any]]:
    headers = {"Authorization": key, "Accept": "application/json"}
    ev_uuid = str((payload.get("Event") or {}).get("uuid") or "")
    resp, err = _send(rt, "POST", f"{base}/events/add", json_body=payload, headers=headers, provider=pid, source=sid)
    body = _body_json(resp) if resp is not None else None
    failed = resp is None or not 200 <= resp.status < 300
    haystack = ""
    if failed:
        haystack = err if resp is None else (json.dumps(body, ensure_ascii=False) if body is not None else _misp_error(body, resp))
    if failed and "already exist" in haystack.lower() and ev_uuid:
        resp, err = _send(rt, "POST", f"{base}/events/edit/{ev_uuid}", json_body=payload, headers=headers, provider=pid, source=sid)
        body = _body_json(resp) if resp is not None else None
    if resp is None:
        return False, {"error": f"could not verify: {err}"}
    event = body.get("Event") if isinstance(body, Mapping) else None
    if 200 <= resp.status < 300 and isinstance(event, Mapping) and (event.get("id") or event.get("uuid")) and not body.get("errors"):
        if str(event.get("published") or "").lower() in ("true", "1"):
            log.warning("MISP reports the pushed event as published")
        return True, {"event_id": str(event.get("id") or ""), "event_uuid": str(event.get("uuid") or ev_uuid)}
    return False, {"error": f"could not verify: HTTP {resp.status}: {_misp_error(body, resp) or 'unexpected answer (no Event)'}"}


def _push_opencti(rt: Any, base: str, key: str, pid: str, sid: str, payload: Mapping[str, Any], filename: str) -> tuple[bool, dict[str, Any]]:
    boundary = "v3lum-" + uuid.uuid4().hex
    operations = json.dumps({"query": _OPENCTI_QUERY, "variables": {"file": None}})
    content = json.dumps(payload, ensure_ascii=False, indent=2)
    parts = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="operations"\r\n\r\n{operations}\r\n',
        f'--{boundary}\r\nContent-Disposition: form-data; name="map"\r\n\r\n{{"0": ["variables.file"]}}\r\n',
        f'--{boundary}\r\nContent-Disposition: form-data; name="0"; filename="{filename}"\r\nContent-Type: application/json\r\n\r\n{content}\r\n',
        f"--{boundary}--\r\n",
    ]
    headers = {
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "apollo-require-preflight": "true",
    }
    resp, err = _send(rt, "POST", f"{base}/graphql", data="".join(parts).encode("utf-8"), headers=headers, provider=pid, source=sid)
    if resp is None:
        return False, {"error": f"could not verify: {err}"}
    body = _body_json(resp)
    if isinstance(body, Mapping) and body.get("errors"):
        msgs = [str(e.get("message") or e) if isinstance(e, Mapping) else str(e) for e in body["errors"]][:3]
        return False, {"error": "could not verify: OpenCTI error: " + _clean("; ".join(msgs))[:300]}
    data = body.get("data") if isinstance(body, Mapping) else None
    upload = data.get("uploadImport") if isinstance(data, Mapping) else None
    if 200 <= resp.status < 300 and isinstance(upload, Mapping) and upload.get("id"):
        return True, {"import_id": _clean(upload.get("id"))[:200], "file": _clean(upload.get("name") or filename)[:200]}
    return False, {"error": f"could not verify: HTTP {resp.status}: unexpected OpenCTI answer (no uploadImport id)"}


def _push(app: Any, console: Any, args: Any, case: dict[str, Any]) -> int:
    target = args.push
    case_id = str(case.get("case_id") or "")
    if not _CASE_ID_RE.match(case_id):  # it names the uploaded file (multipart header): plain names only
        raise _user_error(f"cannot push: invalid case id {_clean(case_id)[:80]!r}")
    if args.include_personal:
        raise _user_error("--push never carries personal data (data minimisation): write a file with --include-personal instead")
    if args.out:
        raise _user_error("-o applies to file exports, not to --push")
    refusal = push_refusal(case, allow_engagement=args.allow_engagement)
    if refusal:
        raise _user_error(f"push refused: {refusal}")
    base, host, key, pid, sid = _target(app, target, _tlp_label(case)[0])
    fmt = "misp" if target == "misp" else "stix"
    payload, numbers = _payload(fmt, case, include_personal=False, include_weak=args.include_weak)
    if target == "misp":
        ev = payload["Event"]
        ev["distribution"] = "0"  # every TLP: your organisation only, never a sharing group
        ev["published"] = False
        ev.pop("sharing_group_id", None)
        ev.pop("SharingGroup", None)
    tlp_value, tag = _tlp_label(case)
    summary = _summary(fmt, numbers)
    engagement = _engagement(case)
    lines = [
        f"push {target} → {host} (internal {pid}): {summary}",
        f"TLP:{tlp_value.upper()} · distribution 0 (your organisation only) · unpublished · no sharing group · TLS verified"
        if target == "misp" else
        f"TLP:{tlp_value.upper()} · uploaded to the OpenCTI import area for analyst validation (draft) · TLS verified",
    ]
    if tlp_value == "amber+strict":
        lines.append("AMBER+STRICT: allowed only because the target is the organisation's own instance")
    if engagement:
        lines.append("LIGHT/ACTIVE engagement case pushed with --allow-engagement (recorded in the case audit)")
    if args.json and args.dry_run:
        console.print_json(json.dumps({"case_id": case_id, "target": target, "host": host, "dry_run": True, "summary": summary, **numbers}))
        return 0
    for line in lines:
        console.print(Text(line, style="v.dim" if not line.startswith("push") else "v.ok"), soft_wrap=True)
    if args.dry_run:
        console.print(Text("dry run: nothing was sent", style="v.dim"))
        return 0
    if not args.yes:
        if not _tty():
            raise _user_error(f"--push needs an interactive confirmation naming the host ({host}): refused in a non-interactive session (add --yes)")
        if not Confirm.ask(f"[v.warn]push {summary} to {host}?[/]", default=False, console=console):
            console.print(Text("not pushed", style="v.dim"))
            return 0
    ok, result = False, {"error": "could not verify: push interrupted before an answer"}
    try:
        rt = app.runtime()
        try:
            if target == "misp":
                ok, result = _push_misp(rt, base, key, pid, sid, payload)
            else:
                ok, result = _push_opencti(rt, base, key, pid, sid, payload, f"v3lum-{case_id}.{tag}.stix.json")
        finally:
            close = getattr(rt, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: BLE001
                    pass
    finally:  # every attempt is on record, an interrupted or crashed one included (it may have reached the platform)
        _audit(app, case_id, PUSH_AUDIT_KIND, {
            "target": target, "host": host, "provider": pid, "format": fmt, "tlp": tlp_value,
            "counts": dict(numbers), "include_weak": bool(args.include_weak), "engagement": engagement,
            "allow_engagement": bool(args.allow_engagement), "ok": ok, "result": dict(result),
            "at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"), "analyst": _analyst(app),
        })
    if args.json:
        console.print_json(json.dumps({"case_id": case_id, "target": target, "host": host, "ok": ok, "summary": summary, **result}))
        return 0 if ok else 1
    if ok:
        ref = result.get("event_id") or result.get("import_id") or ""
        console.print(Text(f"pushed to {host}{f' ({ref})' if ref else ''}: {summary}", style="v.ok"), soft_wrap=True)
        return 0
    console.print(Text(f"push to {host} failed: {result.get('error')}", style="v.warn"), soft_wrap=True)
    return 1


# --------------------------------------------------------------------------------------
# command
# --------------------------------------------------------------------------------------


@command("export", "export a stored case as STIX 2.1 or a MISP event (0600 file), or push it to the team's own MISP/OpenCTI")
class Export:
    """Write a stored case as a STIX 2.1 bundle or a MISP event (TLP in the file name, personal data
    stripped by default), or push it - after a dry-run summary and a confirmation - to the
    organisation's own MISP (unpublished, distribution 0) or OpenCTI (import area)."""

    @staticmethod
    def add_arguments(parser: Any) -> None:
        parser.add_argument("case_id", help="case id ('last' and unique prefixes work)")
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--format", choices=("stix", "misp"), help="write a file in this format (default: stix)")
        mode.add_argument("--push", choices=tuple(PUSH_TARGETS), help="push to the configured internal instance (misp_url / opencti_url)")
        parser.add_argument("-o", "--out", metavar="FILE", help="output file or directory (default: report_dir, else the case directory)")
        parser.add_argument("--include-personal", action="store_true", help="file exports only: include personal data (recorded in the case audit; CPF stays masked)")
        parser.add_argument("--include-weak", action="store_true", help="POSSIBLE and warninglisted IOCs become indicators / to_ids too")
        parser.add_argument("--dry-run", action="store_true", help="--push: print the summary and send nothing")
        parser.add_argument("--allow-engagement", action="store_true", help="--push: allow a LIGHT/ACTIVE engagement case (recorded in the case audit)")
        parser.add_argument("-y", "--yes", action="store_true", help="--push: confirm without a prompt (needed in non-interactive sessions)")
        parser.add_argument("--json", action="store_true", help="machine-readable summary")

    @staticmethod
    def run(args: Any, app: Any, console: Any) -> int:
        if not args.push and (args.dry_run or args.allow_engagement or args.yes):
            raise _user_error("--dry-run, --allow-engagement and --yes apply to --push only")
        case = _apply_overrides(app, _stored_case(app, args.case_id))
        if args.push:
            return _push(app, console, args, case)
        return _export_file(app, console, args, case)
