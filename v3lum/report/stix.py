"""STIX 2.1 bundle export v2 (P303, AR09, AR17, AR24; A1, A2, A7, A12). Hand-rolled: no ``stix2``
runtime dependency (``stix2`` is only an optional dev test oracle).

``bundle(case, *, include_personal=False, include_weak=False)`` turns a case dict
(``CaseResult.to_dict()`` or a stored case, analyst overrides applied by the caller) into a bundle:

* **Markings (A2).** The case TLP (FIRST TLP 2.0, AMBER+STRICT included) becomes one TLP 2.0
  ``marking-definition`` (:data:`MARKINGS`, the published OASIS ids) placed first in the bundle,
  and every SDO, SCO and SRO carries ``object_marking_refs`` to it. A case without a TLP is AMBER
  (the A2 default); an unreadable TLP fails closed to RED.
* **Deterministic ids (AR09).** SCO ids are ``uuid5(00abedb4-aa42-466c-9c01-fed23315a9b7, JCS of
  the id-contributing properties)`` (:func:`sco_id`; RFC 8785 canonical JSON; for ``file`` one hash
  is kept in the order MD5 > SHA-1 > SHA-256 > SHA-512). Global SDOs never get case-scoped ids:
  ``vulnerability`` = uuid5 of the CVE id, ``attack-pattern`` = the official ATT&CK STIX id
  (``attack.stix_id``; uuid5 of the technique id when the index does not know it),
  ``threat-actor`` / ``malware`` = the MISP galaxy cluster uuid (``galaxy.lookup``; uuid5 of the
  canonical name otherwise). Indicators are keyed by their pattern, notes by the deterministic
  finding/correlation id, relationships by (source, type, target): the same object gets the same id
  in every run and every case. Only the report and the bundle are case-scoped.
* **Indicator gating (P303 cond 5).** An entity gets an ``indicator`` only for a CR27
  ``multi_source_malicious`` consensus (>= 2 independent upstream families) or an analyst-confirmed
  hostile finding/correlation (override label 'confirmed' on an item tagged hostile, or a hostile
  override verdict - malicious, c2, phishing, compromised -; never a rejecting verdict). Confidence is
  90/70/40 from the label (``models.CONFIDENCE_TABLE``), ``valid_until`` = valid_from + the P302
  decay tau of the indicator class (``scoring.TAU_DAYS``; hashes never expire), ATT&CK techniques
  of the evidence become ``indicates`` relationships to their attack-pattern (kill-chain phases
  when the index knows the tactics; revoked techniques resolve to their replacement). POSSIBLE,
  warninglisted and other noise-listed IOCs (CDN, resolver, sinkhole, private...) stay observables
  unless ``include_weak``; ``context_only`` items are always observables only. A single-module
  finding is an observable, never an indicator. CIDR patterns use ``ISSUBSET``.
* **Personal data (A4/A8, AR24).** By default no PERSONAL_TYPES object is exported (email-addr,
  user-account, person identities...), personal entities' relationships and notes are dropped,
  free-form values carrying personal data (a URL or user agent with an e-mail, phone or personal
  value of the case; any CPF, in every export) are withheld, findings/correlations tagged
  ``privacy`` (P258) are excluded, and free text is scrubbed (personal values of the case, e-mail
  addresses, phone numbers). ``include_personal`` exports them (person names as ``identity``
  individuals); CPF is never an object and is masked (``***.456.789-**``) in every text, even then.
  Scores of personal subjects are never exported: the report carries the case score without
  personal-data entities (``risk['automation']``, :func:`export_risk`), none when a seed is personal.
  The report description lists only exported IOC seeds (never personal ones, local files, text
  blobs or keywords). SECRET_TYPES are never exported. Analyst notes (override notes, feedback),
  local evidence paths and local file names never appear.
* **Cross-case references (A2 BR10, P375 cond 3).** CLEAR/GREEN exports go through
  ``store.omit_cross_case(case)``; AMBER and above through ``omit_cross_case(case,
  keep_count=True)`` reduced further to the *visible* count (never the restricted count, other
  cases' ids, dates or verdicts; an item resting only on restricted cases is dropped). Findings of
  results marked above the case TLP (A12 platform markings) and ``internal_sighting`` findings
  (other platforms' event/case ids) are dropped at every TLP without even a count.
* **Licence banner (A1).** Research-profile cases carry the licence banner in the report
  description.
* **Escaping (P303 cond 7).** STIX pattern string literals escape backslashes and quotes for every
  type (:func:`pattern_literal`).

:func:`prepare` returns the filtered :class:`ExportView` shared with ``v3lum.report.misp``.
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import re
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "BAD_TAGS",
    "CONSENSUS_RULES",
    "ExportView",
    "HASH_PREFERENCE",
    "HOSTILE_VERDICTS",
    "ID_CONTRIBUTING",
    "MARKINGS",
    "STIX_NS",
    "TLP_EXTENSION",
    "V3LUM_NS",
    "bundle",
    "export_risk",
    "is_research",
    "jcs",
    "marking_for",
    "pattern_literal",
    "prepare",
    "sco_id",
]

#: STIX 2.1 namespace of deterministic SCO ids.
STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
#: V3LUM namespace of the other deterministic ids (identity, global SDOs, indicators, notes...).
V3LUM_NS = uuid.UUID("6f3f8a2e-2d1e-4b8b-9f3c-5a1d0c3e7b21")

#: The OASIS TLP 2.0 marking extension (extension-definition of the published TLP 2.0 markings).
TLP_EXTENSION = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"
_TLP2_IDS = {
    "clear": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "green": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "amber": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "amber+strict": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
    "red": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}
#: TLP value ('clear' | 'green' | 'amber' | 'amber+strict' | 'red') -> the TLP 2.0 marking-definition.
MARKINGS: dict[str, dict[str, Any]] = {
    value: {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": mid,
        "created": "2022-10-01T00:00:00.000Z",
        "name": "TLP:" + value.upper(),
        "extensions": {TLP_EXTENSION: {"extension_type": "property-extension", "tlp_2_0": value}},
    }
    for value, mid in _TLP2_IDS.items()
}

#: Hash kept for a file SCO id when several are known (stix2 ``_choose_one_hash``).
HASH_PREFERENCE: tuple[str, ...] = ("MD5", "SHA-1", "SHA-256", "SHA-512")
#: SCO type -> its id-contributing properties (STIX 2.1 section 6).
ID_CONTRIBUTING: dict[str, tuple[str, ...]] = {
    "artifact": ("hashes", "payload_bin"),
    "autonomous-system": ("number",),
    "directory": ("path",),
    "domain-name": ("value",),
    "email-addr": ("value",),
    "email-message": ("from_ref", "subject", "body"),
    "file": ("hashes", "name", "extensions", "parent_directory_ref"),
    "ipv4-addr": ("value",),
    "ipv6-addr": ("value",),
    "mac-addr": ("value",),
    "mutex": ("name",),
    "network-traffic": ("start", "end", "src_ref", "dst_ref", "src_port", "dst_port", "protocols", "extensions"),
    "process": (),
    "software": ("name", "cpe", "swid", "vendor", "version"),
    "url": ("value",),
    "user-account": ("account_type", "user_id", "account_login"),
    "windows-registry-key": ("key", "values"),
    "x509-certificate": ("hashes", "serial_number"),
}
#: Entity hash types -> STIX hash algorithm names exported on ``file`` objects.
HASH_KEYS: dict[str, str] = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512", "ssdeep": "SSDEEP", "tlsh": "TLSH"}
_HEX_HASHES = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
#: Finding/correlation tags that make an analyst-confirmed item an indicator.
BAD_TAGS: frozenset[str] = frozenset({"malicious", "phishing", "malware", "c2", "botnet", "compromised"})
#: Correlation rules whose consensus (>= 2 independent upstream families) makes an indicator (CR27).
CONSENSUS_RULES: frozenset[str] = frozenset({"multi_source_malicious"})
#: Fallback decay taus in days (P302; ``v3lum.core.scoring.TAU_DAYS`` wins when it exists).
_TAU_FALLBACK: dict[str, int | None] = {"ip": 30, "url": 30, "domain": 90, "typosquat": 180, "breach": 1095, "infostealer": 365, "hash": None}
#: Fixed timestamp of the V3LUM identity and of global SDOs (same object, same version everywhere).
GLOBAL_TS = "2026-01-01T00:00:00.000Z"
IDENTITY_ID = f"identity--{uuid.uuid5(V3LUM_NS, 'v3lum-tool')}"
_REJECT = frozenset({"false_positive", "false positive", "fp", "benign", "wrong", "negative", "not_malicious"})
#: Analyst override verdicts that confirm an item as hostile (the hostile ``store.TAG_VERDICTS``).
HOSTILE_VERDICTS: frozenset[str] = frozenset({"malicious", "c2", "phishing", "compromised"})
#: Entity types whose value is free-form text that can carry personal data (e-mail in a URL query,
#: a contact in a user agent, a CPF in an MEI company name): checked before the value is exported.
_TEXT_VALUE_TYPES = frozenset({"url", "user_agent", "company_name"})
_TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_ACCOUNT_KINDS = {
    "username": "",
    "social_account": "",
    "telegram_handle": "telegram",
    "fediverse_handle": "fediverse",
    "bsky_handle": "bluesky",
    "steam_profile": "steam",
}
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<![\w+])\+\d[\d ().-]{7,18}\d(?!\w)")
_CPF_RE = re.compile(r"(?<!\d)(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})(?!\d)")
_FAMILIES_RE = re.compile(r"\b(\d+)\s+independent\b", re.I)
PERSONAL_PLACEHOLDER = "[personal data removed]"


# ======================================================================================
# primitives
# ======================================================================================


def jcs(obj: Any) -> str:
    """RFC 8785 canonical JSON of the id-contributing values (strings, integers, lists, objects):
    sorted keys, no whitespace, UTF-8 kept."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _one_hash(hashes: Mapping[str, Any]) -> dict[str, Any]:
    for name in HASH_PREFERENCE:
        if hashes.get(name):
            return {name: hashes[name]}
    for name in sorted(hashes):
        if hashes[name]:
            return {name: hashes[name]}
    return {}


def sco_id(sco_type: str, props: Mapping[str, Any]) -> str:
    """Deterministic STIX 2.1 SCO id: ``<type>--uuid5(STIX_NS, JCS(id-contributing properties))``.

    ``props`` may be the whole SCO: only :data:`ID_CONTRIBUTING` properties count (all properties
    but ``type``/``id``/``spec_version``/markings for an unknown type); ``hashes`` is reduced to
    one hash (:data:`HASH_PREFERENCE`). Matches the ids ``stix2`` generates, e.g.
    ``sco_id('ipv4-addr', {'value': '8.8.8.8'}) == 'ipv4-addr--2f689bf9-0ff2-545f-aa61-e495eb8cecc7'``."""
    names = ID_CONTRIBUTING.get(sco_type)
    skip = {"type", "id", "spec_version", "object_marking_refs", "granular_markings", "defanged", "extensions"}
    contributing: dict[str, Any] = {}
    for name, value in props.items():
        if value in (None, "", [], {}):
            continue
        if (names is not None and name in names) or (names is None and name not in skip):
            contributing[name] = _one_hash(value) if name == "hashes" and isinstance(value, Mapping) else value
    return f"{sco_type}--{uuid.uuid5(STIX_NS, jcs(contributing))}"


def pattern_literal(value: Any) -> str:
    """A STIX pattern string literal: backslashes and single quotes escaped, quoted."""
    text = str(value)
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _uid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(V3LUM_NS, f'{kind}|{key}')}"


def _parse_time(value: Any) -> _dt.datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, _dt.datetime):
        dt = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            dt = _dt.datetime.fromtimestamp(float(value), _dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = _dt.datetime.fromisoformat(text)
        except ValueError:
            try:
                dt = _dt.datetime.combine(_dt.date.fromisoformat(text[:10]), _dt.time())
            except ValueError:
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc)


def _stamp(dt: _dt.datetime) -> str:
    """RFC 3339 with milliseconds and Z (STIX timestamp)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _tlp_value(case: Mapping[str, Any]) -> str:
    from v3lum.core import tlp as _tlp

    options = case.get("options") if isinstance(case.get("options"), Mapping) else {}
    raw = case.get("tlp") or options.get("tlp")
    if raw in (None, ""):
        return "amber"  # A2 default
    try:
        return _tlp.parse(raw).value_str
    except ValueError:
        return "red"  # unreadable: fail closed


def marking_for(tlp: Any) -> dict[str, Any]:
    """The TLP 2.0 marking-definition of a TLP value (parsed with ``tlp.parse``)."""
    from v3lum.core import tlp as _tlp

    return dict(MARKINGS[_tlp.parse(tlp).value_str])


def _clean(text: Any) -> str:
    return _CTRL.sub(" ", str(text or ""))


# ======================================================================================
# the export view (shared with the MISP exporter)
# ======================================================================================


@dataclass
class Indicator:
    """Why an entity is exported as an indicator: the deciding item and its facts."""

    key: str
    basis: str  # 'consensus' | 'confirmed'
    item_id: str
    label: str  # confirmed | probable | possible
    criterion: str
    tags: tuple[str, ...]
    attack: tuple[str, ...]
    observed_last: _dt.datetime | None
    weak: str = ""  # '' or why it stays an observable (possible, warninglisted, context_only)


@dataclass
class ExportView:
    """A case filtered for export (see the module docstring): ``nodes`` exportable entity nodes by
    key; ``withheld`` reason -> count; ``indicators`` entity key -> :class:`Indicator` (only those
    that passed the gating, ``weak`` ones included - check ``weak`` before emitting);
    ``findings``/``correlations`` the exportable items; ``scrub(text)`` the free-text filter."""

    case: dict[str, Any]
    tlp: str
    created: _dt.datetime
    include_personal: bool
    include_weak: bool
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    excluded: set[str] = field(default_factory=set)
    withheld: Counter = field(default_factory=Counter)
    indicators: dict[str, Indicator] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    no_export: set[str] = field(default_factory=set)
    personal_seeds: int = 0
    other_seeds: int = 0
    seeds: list[str] = field(default_factory=list)
    banner: str = ""
    _personal_re: re.Pattern[str] | None = None

    @property
    def marking_id(self) -> str:
        return MARKINGS[self.tlp]["id"]

    @property
    def case_id(self) -> str:
        return str(self.case.get("case_id") or "")

    def scrub(self, text: Any) -> str:
        """Free text fit for this export: control characters dropped, the case's excluded personal
        values replaced, e-mail addresses and phone numbers removed (default exports) and CPFs
        masked (always)."""
        out = _clean(text)
        if self._personal_re is not None:
            out = self._personal_re.sub(PERSONAL_PLACEHOLDER, out)
        if not self.include_personal:
            out = _EMAIL_RE.sub("[e-mail removed]", out)
            out = _PHONE_RE.sub("[phone removed]", out)
        return _CPF_RE.sub(_mask_cpf_match, out)

    def is_indicator(self, key: str) -> bool:
        """True when ``key`` is exported as an indicator (MISP ``to_ids``)."""
        ind = self.indicators.get(key)
        return ind is not None and (not ind.weak or (self.include_weak and ind.weak != "context_only"))


def _mask_cpf_match(m: re.Match[str]) -> str:
    digits = "".join(m.groups())
    try:
        from v3lum.core.validators import cpf_valid

        valid = cpf_valid(digits)
    except Exception:  # noqa: BLE001 - no validator: mask every CPF-shaped number
        valid = True
    if not valid and m.group(0).isdigit():
        return m.group(0)
    return f"***.{digits[3:6]}.{digits[6:9]}-**"


def _etype(name: str) -> Any:
    from v3lum.core.entities import EntityType

    try:
        return EntityType(name)
    except ValueError:
        try:
            return EntityType.parse(name)
        except ValueError:
            return None


def _node_parts(node: Mapping[str, Any]) -> tuple[str, str, str]:
    key = str(node.get("key") or "")
    etype, _, value = key.partition(":")
    etype = str(node.get("type") or etype)
    value = str(node.get("value") if node.get("value") is not None else value)
    return key or f"{etype}:{value}", etype, value


def _tags(item: Mapping[str, Any]) -> set[str]:
    return {str(t).lower() for t in item.get("tags") or () if t}


def _override(item: Mapping[str, Any]) -> dict[str, Any]:
    ov = item.get("override")
    return ov if isinstance(ov, dict) else {}


def _reject_verdicts() -> frozenset[str]:
    try:
        from v3lum.core.store import REJECT_VERDICTS

        return frozenset(REJECT_VERDICTS)
    except Exception:  # noqa: BLE001 - the documented words
        return _REJECT


def _verdict(item: Mapping[str, Any]) -> str:
    return str(_override(item).get("verdict") or "").strip().lower()


def _rejected(item: Mapping[str, Any]) -> bool:
    return _verdict(item) in _reject_verdicts()


def _confirmed(item: Mapping[str, Any]) -> bool:
    """An analyst decision confirms the item: override label 'confirmed', or a hostile verdict
    (malicious, c2, phishing, compromised) - never when the verdict rejects it."""
    ov = _override(item)
    if _rejected(item):
        return False
    return str(ov.get("label") or "").lower() == "confirmed" or _verdict(item) in HOSTILE_VERDICTS


def _hostile(item: Mapping[str, Any]) -> bool:
    """Tagged hostile by its rule/module, or given a hostile verdict by the analyst."""
    return bool(_tags(item) & BAD_TAGS) or _verdict(item) in HOSTILE_VERDICTS


def _families(item: Mapping[str, Any]) -> int:
    for text in (item.get("criterion"), item.get("title"), item.get("why")):
        m = _FAMILIES_RE.search(str(text or ""))
        if m:
            return int(m.group(1))
    return 2 if "malicious" in _tags(item) else 1


def _consensus_min() -> int:
    try:
        from v3lum.correlations.threat_intel import CONSENSUS_FAMILIES

        return int(CONSENSUS_FAMILIES)
    except Exception:  # noqa: BLE001 - the P171 value
        return 2


def _label(item: Mapping[str, Any]) -> str:
    label = str(item.get("confidence_label") or "").lower()
    if label in ("confirmed", "probable", "possible"):
        return label
    try:
        from v3lum.core.models import Confidence

        return Confidence.from_value(float(item.get("confidence", 0.0) or 0.0)).value
    except Exception:  # noqa: BLE001
        return "possible"


def _stix_confidence(label: str) -> int:
    try:
        from v3lum.core.models import Confidence

        return Confidence(label).stix
    except Exception:  # noqa: BLE001 - the documented table
        return {"confirmed": 90, "probable": 70}.get(label, 40)


def _suppressed_rules(item: Mapping[str, Any]) -> set[str]:
    return {str(s.get("rule") or "") for s in item.get("suppressed_by") or () if isinstance(s, Mapping)}


def _warninglisted(node: Mapping[str, Any], items: Iterable[Mapping[str, Any]]) -> str:
    """Why an entity is weak although an item backs it: 'warninglisted' (warninglist noise kind,
    tag or attribute, or a SUP-warninglist suppression), 'noise' (any other noise list: CDN,
    resolver, sinkhole, parked, private...), or ''."""
    if str(node.get("noise_kind") or "") == "warninglist":
        return "warninglisted"
    if {"warninglist", "warninglisted"} & {str(t).lower() for t in node.get("tags") or ()}:
        return "warninglisted"
    attrs = node.get("attributes") if isinstance(node.get("attributes"), Mapping) else {}
    if attrs.get("warninglists") or attrs.get("warninglist"):
        return "warninglisted"
    if any(any(r.lower().startswith("sup-warninglist") for r in _suppressed_rules(i)) for i in items):
        return "warninglisted"
    if node.get("noise") is True or str(node.get("noise_kind") or ""):
        return "noise"
    return ""


def _personal_strings(etype: Any, value: str, display: str) -> list[str]:
    out = [value, display]
    if getattr(etype, "value", "") == "cpf":
        digits = re.sub(r"\D", "", value)
        if len(digits) == 11:
            out += [digits, f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}"]
    if getattr(etype, "value", "") == "social_account" and ":" in value:
        out.append(value.split(":", 1)[1])
    return [s for s in out if s and len(s.strip()) >= 3]


def _result_tlp_excluded(case: Mapping[str, Any], tlp_value: str) -> set[str]:
    """Finding ids of module results marked above the case TLP (A12: never in a lower-TLP export)."""
    from v3lum.core import tlp as _tlp

    level = _tlp.parse(tlp_value)
    out: set[str] = set()
    for res in case.get("modules") or ():
        if not isinstance(res, Mapping) or not res.get("tlp"):
            continue
        try:
            marked = _tlp.parse(res["tlp"])
        except ValueError:
            marked = _tlp.TLP.RED
        if marked > level:
            out.update(str(f) for f in res.get("findings") or () if f)
    return out


def _tau_days() -> dict[str, Any]:
    try:
        from v3lum.core.scoring import TAU_DAYS

        if isinstance(TAU_DAYS, Mapping):
            return dict(TAU_DAYS)
    except Exception:  # noqa: BLE001 - WP19 not installed yet: the P302 table
        pass
    return dict(_TAU_FALLBACK)


def _tau_class(etype: str, tags: Iterable[str]) -> str:
    tagset = {str(t).lower() for t in tags}
    for cls in ("typosquat", "infostealer", "breach"):
        if cls in tagset:
            return cls
    if etype in ("ipv4", "ipv6", "cidr"):
        return "ip"
    if etype == "url":
        return "url"
    if etype in ("domain", "onion"):
        return "domain"
    if etype in HASH_KEYS:
        return "hash"
    return ""


def _licence_banner(case: Mapping[str, Any]) -> str:
    options = case.get("options") if isinstance(case.get("options"), Mapping) else {}
    profile = str(case.get("licence_profile") or options.get("licence_profile") or "corporate").strip().lower()
    used = case.get("licence_used") if isinstance(case.get("licence_used"), Mapping) else {}
    licensed = {
        str(sid): info for sid, info in used.items()
        if isinstance(info, Mapping) and str(info.get("class") or "") in ("noncommercial", "license")
    }
    if profile != "research" and not licensed:
        return ""
    head = "LICENCE: research profile (recorded legal basis)" if profile == "research" else f"LICENCE: licence profile {profile}"
    if licensed:
        items = [f"{sid} ({info.get('class')}, {info.get('basis') or 'basis not recorded'})" for sid, info in sorted(licensed.items())]
        return _clean(head + " - noncommercial/license sources used: " + ", ".join(items))
    return head + " - no noncommercial/license source was used in this run"


def is_research(case: Mapping[str, Any]) -> bool:
    """True for a research-profile case (A1: never pushed, banner in every export)."""
    options = case.get("options") if isinstance(case.get("options"), Mapping) else {}
    return str(case.get("licence_profile") or options.get("licence_profile") or "").strip().lower() == "research"


def _visible_count(entry: Any) -> int:
    value = entry.get("value") if isinstance(entry, Mapping) and "value" in entry else entry
    if not isinstance(value, Mapping):
        return 0
    try:
        return max(0, int(value.get("count") or 0))
    except (TypeError, ValueError):
        return 0


def _visible_cross_case(work: dict[str, Any]) -> None:
    """AMBER+ exports carry at most the visible count of earlier cases (A2 BR10, P375 cond 3):
    ``store.omit_cross_case(keep_count=True)`` keeps ``{count, restricted}``; the restricted count
    (cases above this one's TLP) and items that only rest on restricted cases are dropped here, and
    the recurrence correlations are recounted from the visible counts. Changes ``work`` in place."""
    from v3lum.core import store as _store

    counts: dict[str, int] = {}
    for node in work.get("entities") or ():
        if not isinstance(node, dict) or not isinstance(node.get("attributes"), dict):
            continue
        attrs = node["attributes"]
        for name in _store.CROSS_CASE_ATTRIBUTES & set(attrs):
            entries = attrs[name] if isinstance(attrs[name], list) else [attrs[name]]
            visible = max((_visible_count(e) for e in entries), default=0)
            counts[_node_parts(node)[0]] = visible
            if visible:
                attrs[name] = [{"value": {"count": visible}, "source": next(iter(_store.CROSS_CASE_MODULES))}]
            else:
                del attrs[name]
    findings: list[Any] = []
    for item in work.get("findings") or ():
        if isinstance(item, dict) and str(item.get("module") or "") in _store.CROSS_CASE_MODULES:
            visible = counts.get(str(item.get("entity") or ""), _visible_count(item.get("data")))
            if not visible:
                continue  # rests on restricted cases only: not even their existence is exported
            item["title"] = f"seen in {visible} previous case{'s' if visible != 1 else ''}"
            item["description"] = "Earlier V3LUM cases contain the same indicator (count only: no ids, dates or verdicts)."
            item["data"] = {"count": visible}
        findings.append(item)
    if "findings" in work:
        work["findings"] = findings
    correlations: list[Any] = []
    for item in work.get("correlations") or ():
        if isinstance(item, dict) and str(item.get("rule") or "") in _store.CROSS_CASE_RULES:
            total = sum(counts.get(str(k), 0) for k in item.get("entities") or ())
            if not total:
                continue
            plural = "s" if total != 1 else ""
            item["description"] = f"The same indicator appears in {total} earlier V3LUM case{plural} (count only)."
            item["evidence"] = [f"seen in {total} earlier case{plural}"]
            item["why"] = f"same indicator in this case and {total} earlier case{plural}"
        correlations.append(item)
    if "correlations" in work:
        work["correlations"] = correlations


def _value_leaks(etype_name: str, value: str, view: ExportView) -> str:
    """Why an exportable entity value must be withheld ('' when it may go out): free-form values
    (:data:`_TEXT_VALUE_TYPES`) carrying a CPF (every export) or - default exports - a personal value
    of the case, an e-mail address or a phone number. The IOC cannot be masked without changing it."""
    if etype_name not in _TEXT_VALUE_TYPES:
        return ""
    if any(_mask_cpf_match(m) != m.group(0) for m in _CPF_RE.finditer(value)):
        return "value with personal data"
    if view.include_personal:
        return ""
    if (view._personal_re is not None and view._personal_re.search(value)) or _EMAIL_RE.search(value) or _PHONE_RE.search(value):
        return "value with personal data"
    return ""


def prepare(case: Mapping[str, Any], *, include_personal: bool = False, include_weak: bool = False) -> ExportView:
    """Filter a case dict for export (cross-case omission, personal data, secrets, markings,
    indicator gating). The stored case is never changed."""
    from v3lum.core import entities as ents
    from v3lum.core import store as _store

    tlp_value = _tlp_value(case)
    if _store.cross_case_allowed(tlp_value):
        work = _store.omit_cross_case(case, keep_count=True)
        _visible_cross_case(work)
    else:
        work = _store.omit_cross_case(case)
    created = _parse_time(work.get("created")) or _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
    view = ExportView(case=work, tlp=tlp_value, created=created, include_personal=bool(include_personal), include_weak=bool(include_weak))
    view.banner = _licence_banner(work)

    risk = work.get("risk") if isinstance(work.get("risk"), Mapping) else {}
    view.no_export = {str(k) for k in risk.get("no_export") or ()}

    personal: list[str] = []
    nodes = {}
    for node in work.get("entities") or ():
        if isinstance(node, Mapping):
            key, _etype_name, _value = _node_parts(node)
            nodes[key] = node
    for key in sorted(nodes):
        node = nodes[key]
        _key, etype_name, value = _node_parts(node)
        etype = _etype(etype_name)
        if etype is None:
            view.excluded.add(key)
            continue
        if etype in ents.SECRET_TYPES:
            view.excluded.add(key)
            view.withheld["secret"] += 1
            continue
        if etype in ents.PERSONAL_TYPES:
            view.no_export.add(key)
            personal += _personal_strings(etype, value, str(node.get("display") or ""))
            if not include_personal or etype is ents.EntityType.CPF:
                view.excluded.add(key)
                view.withheld["personal"] += 1
                continue
        if etype is ents.EntityType.FILE:  # a local path: never exported (hash pivots are)
            view.excluded.add(key)
            continue
        view.nodes[key] = dict(node)
    listed_seeds: list[str] = []
    for seed in work.get("seeds") or ():
        etype_name, _, value = str(seed).partition(":")
        etype = _etype(etype_name)
        if etype is not None and (etype in ents.PERSONAL_TYPES or etype in ents.SECRET_TYPES):
            view.personal_seeds += 1
            view.no_export.add(str(seed))
            if etype in ents.PERSONAL_TYPES:
                personal += _personal_strings(etype, value, "")
        elif etype is not None and etype in ents.IOC_TYPES:
            listed_seeds.append(str(seed))  # listed below only when the entity itself is exported
        else:
            view.other_seeds += 1  # local files, text blobs, keywords, boletos...: never listed
    if personal and not include_personal:
        uniq = sorted({p for p in personal}, key=lambda s: (-len(s), s))
        view._personal_re = re.compile(
            "(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(p) for p in uniq) + ")(?![A-Za-z0-9_])", re.I
        )
    elif personal:  # include_personal: only CPFs stay masked (handled by scrub's CPF rule)
        cpfs = sorted({p for p in personal if re.sub(r"\D", "", p) == p and len(p) == 11}, key=lambda s: (-len(s), s))
        if cpfs:
            view._personal_re = re.compile("(?<!\\d)(?:" + "|".join(re.escape(p) for p in cpfs) + ")(?!\\d)")

    # free-form values carrying personal data (or any CPF) are withheld: the IOC cannot be masked
    # without changing it (a URL with the victim's e-mail in its query, an MEI name with its CPF...)
    for key in list(view.nodes):
        _k, etype_name, value = _node_parts(view.nodes[key])
        why = _value_leaks(etype_name, value, view)
        if why:
            del view.nodes[key]
            view.excluded.add(key)
            view.withheld["url with personal data" if etype_name == "url" else why] += 1
    for seed in listed_seeds:
        if seed in view.nodes:
            view.seeds.append(seed)
        else:
            view.other_seeds += 1

    # results marked above the case TLP and internal platforms' sightings are dropped silently: even
    # a count of them would tell the reader that a restricted source knows something (A2, A12)
    above = _result_tlp_excluded(work, tlp_value)
    for f in work.get("findings") or ():
        if not isinstance(f, Mapping):
            continue
        tags = _tags(f)
        fid = str(f.get("id") or "")
        if fid in above:
            continue
        if "internal_sighting" in tags:  # another platform's event/case ids: a cross-case reference at every TLP
            continue
        if "privacy" in tags and not include_personal:
            view.withheld["privacy-tagged finding"] += 1
            continue
        if str(f.get("entity") or "") not in view.nodes:
            continue
        view.findings.append(dict(f))
    for c in work.get("correlations") or ():
        if not isinstance(c, Mapping):
            continue
        tags = _tags(c)
        if "privacy" in tags and not include_personal:
            view.withheld["privacy-tagged correlation"] += 1
            continue
        keys = [str(k) for k in c.get("entities") or ()]
        if any(k in view.excluded for k in keys):
            view.withheld["correlation about withheld entities"] += 1
            continue
        if not any(k in view.nodes for k in keys):
            continue
        view.correlations.append(dict(c))

    _gate(view)
    return view


def _gate(view: ExportView) -> None:
    """Indicator gating (P303 cond 5): CR27 consensus or analyst-confirmed hostile items."""
    by_entity: dict[str, list[dict[str, Any]]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    for f in view.findings:
        by_entity.setdefault(str(f.get("entity") or ""), []).append(f)
        by_id[str(f.get("id") or "")] = f
    need = _consensus_min()
    candidates: dict[str, list[Indicator]] = {}

    def add(key: str, basis: str, item: Mapping[str, Any], evidence: list[Mapping[str, Any]]) -> None:
        label = "confirmed" if basis == "confirmed" else _label(item)
        times = [t for t in (_parse_time(e.get("observed_last")) for e in [item, *evidence]) if t is not None]
        attack = tuple(dict.fromkeys(str(a) for e in [item, *evidence] for a in e.get("attack") or () if a))
        tags = tuple(sorted(_tags(item) | {t for e in evidence for t in _tags(e)}))
        candidates.setdefault(key, []).append(
            Indicator(key, basis, str(item.get("id") or ""), label, str(item.get("criterion") or ""), tags, attack, max(times) if times else None)
        )

    for c in view.correlations:
        keys = [str(k) for k in c.get("entities") or () if str(k) in view.nodes]
        hostile = bool(_tags(c) & BAD_TAGS)
        evidence = [by_id[e[len("finding:"):]] for e in (str(x) for x in c.get("evidence") or ()) if e.startswith("finding:") and e[len("finding:"):] in by_id]
        if str(c.get("rule") or "") in CONSENSUS_RULES and not _rejected(c) and _families(c) >= need:
            for key in keys:
                add(key, "consensus", c, evidence)
        elif _confirmed(c) and (hostile or _hostile(c)):
            for key in keys:
                add(key, "confirmed", c, evidence)
    for key, items in by_entity.items():
        for f in items:
            if _confirmed(f) and _hostile(f):
                add(key, "confirmed", f, [])

    for key, options in candidates.items():
        node = view.nodes[key]
        _k, etype_name, _v = _node_parts(node)
        if _pattern(etype_name, node) is None:
            continue
        rank = {"confirmed": 2, "probable": 1, "possible": 0}
        best = max(options, key=lambda i: (rank.get(i.label, 0), i.basis == "confirmed", i.item_id))
        items = by_entity.get(key, [])
        if "context_only" in best.tags:
            best.weak = "context_only"
        elif best.label == "possible":
            best.weak = "possible"
        else:
            best.weak = _warninglisted(node, [*items, *[c for c in view.correlations if key in (c.get("entities") or ())]])
        view.indicators[key] = best


# ======================================================================================
# STIX objects
# ======================================================================================


def _hashes_of(node: Mapping[str, Any], etype_name: str, value: str) -> dict[str, str]:
    hashes = {HASH_KEYS[etype_name]: value} if etype_name in HASH_KEYS else {}
    attrs = node.get("attributes") if isinstance(node.get("attributes"), Mapping) else {}
    for name, algo in (("md5", "MD5"), ("sha1", "SHA-1"), ("sha256", "SHA-256"), ("sha512", "SHA-512")):
        for entry in attrs.get(name) or ():
            val = entry.get("value") if isinstance(entry, Mapping) else entry
            text = str(val or "").strip().lower()
            if re.fullmatch(r"[0-9a-f]+", text) and _HEX_HASHES.get(len(text)) == algo:
                hashes.setdefault(algo, text)
                break
    return hashes


def _sco(etype_name: str, value: str, node: Mapping[str, Any]) -> dict[str, Any] | None:
    """The SCO for one entity (without markings), or None when the type has no STIX observable."""
    if etype_name in ("domain", "onion"):
        props: dict[str, Any] = {"type": "domain-name", "value": value}
    elif etype_name == "url":
        props = {"type": "url", "value": value}
    elif etype_name in ("ipv4", "ipv6", "cidr"):
        kind = "ipv6-addr" if ":" in value else "ipv4-addr"
        props = {"type": kind, "value": value}
    elif etype_name == "email":
        props = {"type": "email-addr", "value": value}
    elif etype_name == "asn":
        digits = re.sub(r"\D", "", value)
        if not digits:
            return None
        props = {"type": "autonomous-system", "number": int(digits)}
    elif etype_name == "mac_address":
        props = {"type": "mac-addr", "value": value.lower()}
    elif etype_name in HASH_KEYS:
        props = {"type": "file", "hashes": _hashes_of(node, etype_name, value)}
    elif etype_name in ("cert_fingerprint", "code_signing_cert"):
        text = re.sub(r"[^0-9a-f]", "", value.lower())
        algo = _HEX_HASHES.get(len(text))
        if not algo:
            return None
        props = {"type": "x509-certificate", "hashes": {algo: text}}
    elif etype_name in _ACCOUNT_KINDS:
        kind = _ACCOUNT_KINDS[etype_name]
        login = value
        if etype_name == "social_account" and ":" in value:
            kind, login = value.split(":", 1)
        props = {"type": "user-account", "account_login": login}
        if kind:
            props["account_type"] = kind
    else:
        return None
    obj = {"type": props["type"], "spec_version": "2.1", "id": sco_id(props["type"], props)}
    obj.update({k: v for k, v in props.items() if k != "type"})
    return obj


def _pattern(etype_name: str, node: Mapping[str, Any]) -> str | None:
    """The STIX pattern of an entity (every literal escaped), or None."""
    _k, _t, value = _node_parts(node)
    if etype_name in ("domain", "onion"):
        return f"[domain-name:value = {pattern_literal(value)}]"
    if etype_name == "url":
        return f"[url:value = {pattern_literal(value)}]"
    if etype_name in ("ipv4", "ipv6", "cidr"):
        kind = "ipv6-addr" if ":" in value else "ipv4-addr"
        op = "ISSUBSET" if etype_name == "cidr" or "/" in value else "="  # a network matches its addresses
        return f"[{kind}:value {op} {pattern_literal(value)}]"
    if etype_name == "email":
        return f"[email-addr:value = {pattern_literal(value)}]"
    if etype_name in HASH_KEYS:
        return f"[file:hashes.{pattern_literal(HASH_KEYS[etype_name])} = {pattern_literal(value)}]"
    if etype_name in ("cert_fingerprint", "code_signing_cert"):
        text = re.sub(r"[^0-9a-f]", "", value.lower())
        algo = _HEX_HASHES.get(len(text))
        return f"[x509-certificate:hashes.{pattern_literal(algo)} = {pattern_literal(text)}]" if algo else None
    if etype_name in _ACCOUNT_KINDS:
        login = value.split(":", 1)[1] if etype_name == "social_account" and ":" in value else value
        return f"[user-account:account_login = {pattern_literal(login)}]"
    return None


def _sdo(etype_name: str, value: str, marking: str, view: ExportView | None = None) -> dict[str, Any] | None:
    """Global SDOs (stable ids, never case-scoped): CVE, ATT&CK technique, actor, malware, company."""
    base = {"spec_version": "2.1", "created": GLOBAL_TS, "modified": GLOBAL_TS, "object_marking_refs": [marking]}
    if etype_name == "cve":
        cve = value.upper()
        return {
            "type": "vulnerability", "id": _uid("vulnerability", cve), "name": cve,
            "external_references": [{"source_name": "cve", "external_id": cve}], **base,
        }
    if etype_name == "mitre_technique":
        from v3lum.core import attack

        tid = attack.canonical(value)  # revoked/deprecated ids resolve to their replacement
        if not _TECH_RE.match(tid):
            return None
        official = attack.stix_id(tid)
        name = attack.name(tid) or tid
        return {
            "type": "attack-pattern", "id": official or _uid("attack-pattern", tid), "name": name,
            "external_references": [{
                "source_name": "mitre-attack", "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            }], **base,
        }
    if etype_name in ("threat_actor", "malware_family"):
        from v3lum.core import galaxy

        cluster = galaxy.lookup(etype_name, value)
        if cluster is None:
            return None
        obj: dict[str, Any] = {"type": cluster.stix_type, "id": cluster.stix_id, "name": cluster.name, **base}
        if cluster.stix_type == "malware":
            obj["is_family"] = True
        if cluster.synonyms:
            obj["aliases"] = list(cluster.synonyms)
        return obj
    if etype_name == "company_name":
        masked = _CPF_RE.sub(_mask_cpf_match, _clean(value))  # an MEI name carries its owner's CPF
        return {
            "type": "identity", "id": _uid("identity", "organization|" + masked.casefold()),
            "name": view.scrub(value) if view is not None else masked, "identity_class": "organization", **base,
        }
    if etype_name == "person_name":
        return {
            "type": "identity", "id": _uid("identity", "individual|" + value.casefold()), "name": value,
            "identity_class": "individual", **base,
        }
    return None


def _object_for(node: Mapping[str, Any], view: ExportView) -> dict[str, Any] | None:
    _k, etype_name, value = _node_parts(node)
    obj = _sco(etype_name, value, node)
    if obj is not None:
        obj["object_marking_refs"] = [view.marking_id]
        return obj
    return _sdo(etype_name, value, view.marking_id, view)


def _versioned(view: ExportView) -> dict[str, str]:
    """``created``/``modified`` of objects whose id is the same in every case (indicators, notes,
    relationships): STIX versioning keeps ``created`` fixed for an id, so it is :data:`GLOBAL_TS`,
    and ``modified`` is the case time (never earlier than ``created``) - a later case is a newer
    version of the same object."""
    created = _parse_time(GLOBAL_TS) or view.created
    return {"created": GLOBAL_TS, "modified": _stamp(max(view.created, created))}


def _relationship(view: ExportView, src: str, rtype: str, dst: str, desc: str = "") -> dict[str, Any]:
    rel = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _uid("relationship", f"{src}|{rtype}|{dst}"),
        **_versioned(view),
        "created_by_ref": IDENTITY_ID,
        "relationship_type": rtype,
        "source_ref": src,
        "target_ref": dst,
        "object_marking_refs": [view.marking_id],
    }
    if desc:
        rel["description"] = view.scrub(desc)
    return rel


def _rtype(relation: Any) -> str:
    text = re.sub(r"[^a-z0-9-]+", "-", str(relation or "related-to").lower().replace("_", "-")).strip("-")
    return text or "related-to"


def _indicator(view: ExportView, ind: Indicator, node: Mapping[str, Any], target: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    from v3lum.core import attack
    from v3lum.core.entities import EntityType

    _k, etype_name, value = _node_parts(node)
    pattern = _pattern(etype_name, node) or ""
    valid_from = ind.observed_last or view.created
    try:
        label = EntityType(etype_name).label
    except ValueError:
        label = etype_name
    obj: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _uid("indicator", pattern),
        **_versioned(view),
        "created_by_ref": IDENTITY_ID,
        "name": _clean(f"{label}: {value}"),
        "description": view.scrub(
            ("Analyst-confirmed: " if ind.basis == "confirmed" else "Independent-source consensus (CR27): ")
            + (ind.criterion or "see the V3LUM case")
        ),
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": _stamp(valid_from),
        "confidence": _stix_confidence(ind.label),
        "labels": sorted(t for t in ind.tags if t in BAD_TAGS) or ["malicious-activity"],
        "external_references": [{"source_name": "v3lum", "external_id": ind.item_id, "description": f"V3LUM {'finding' if ind.basis == 'confirmed' else 'correlation'} id"}],
        "object_marking_refs": [view.marking_id],
    }
    if not ind.item_id:
        del obj["external_references"]
    tau = _tau_days().get(_tau_class(etype_name, ind.tags))
    if tau:
        obj["valid_until"] = _stamp(valid_from + _dt.timedelta(days=float(tau)))
    phases = []
    extra: list[dict[str, Any]] = []
    for tid in dict.fromkeys(attack.canonical(t) for t in ind.attack):
        if not attack.is_valid(tid):  # canonical first: a revoked id counts as its replacement
            continue
        sdo = _sdo("mitre_technique", tid, view.marking_id)
        if sdo is None:
            continue
        extra.append(sdo)
        tech = attack.lookup(tid)
        for tactic in getattr(tech, "tactics", ()) or ():
            phases.append({"kill_chain_name": "mitre-attack", "phase_name": str(tactic)})
    if phases:
        obj["kill_chain_phases"] = [dict(p) for p in {(p["kill_chain_name"], p["phase_name"]): p for p in phases}.values()]
    rels = [_relationship(view, obj["id"], "based-on", target)]
    rels += [_relationship(view, obj["id"], "indicates", sdo["id"]) for sdo in extra]
    return obj, extra + rels


def _note(view: ExportView, item: Mapping[str, Any], refs: list[str], *, kind: str) -> dict[str, Any]:
    label = _label(item)
    severity = str(item.get("severity") or "info").upper()
    content = str(item.get("description") or "").strip()
    if item.get("criterion"):
        content += ("\n" if content else "") + f"Criterion: {item.get('criterion')}"
    if kind == "correlation" and item.get("recommendation"):
        content += ("\n" if content else "") + f"Recommendation: {item.get('recommendation')}"
    note = {
        "type": "note",
        "spec_version": "2.1",
        "id": _uid("note", f"{kind}|{item.get('id') or item.get('title')}"),
        **_versioned(view),
        "created_by_ref": IDENTITY_ID,
        "abstract": view.scrub(f"[{severity}/{label}] {item.get('title') or ''}".strip()),
        "content": view.scrub(content or str(item.get("title") or "")),
        "confidence": _stix_confidence(label),
        "object_refs": sorted(set(refs)),
        "object_marking_refs": [view.marking_id],
    }
    refs_ext = [
        {"source_name": "reference", "url": str(u)}
        for u in item.get("references") or ()
        if isinstance(u, str) and u.lower().startswith(("https://", "http://")) and view.scrub(u) == u
    ]
    if refs_ext:
        note["external_references"] = refs_ext[:10]
    return note


def export_risk(view: ExportView) -> tuple[Any, str] | None:
    """(score, level) of the case fit for export, or None when it is withheld (P302 cond 10, LGPD
    art. 20): a case whose seeds are personal exports no score; otherwise the score without
    personal-data entities (``risk['automation']``) is used, and a stored case without that view
    whose score rests on personal entities (``risk['no_export']``) exports none."""
    case = view.case
    if view.personal_seeds or (view.no_export & {str(s) for s in case.get("seeds") or ()}):
        return None
    risk = case.get("risk") if isinstance(case.get("risk"), Mapping) else {}
    auto = risk.get("automation") if isinstance(risk.get("automation"), Mapping) else None
    if auto is not None and auto.get("score") is not None:
        return auto.get("score"), str(auto.get("level") or "no findings")
    if risk.get("no_export"):
        return None
    summary = case.get("summary") if isinstance(case.get("summary"), Mapping) else {}
    return summary.get("risk_score", 0), str(summary.get("risk_level") or "no findings")


def _report_description(view: ExportView) -> str:
    from v3lum.core import tlp as _tlp

    parts = [f"V3LUM case {view.case_id} ({_tlp.parse(view.tlp).label})."]
    risk = export_risk(view)
    if risk is None:
        parts.append("Risk score withheld (personal-data subject: scores of people are never exported).")
    else:
        parts.append(f"Risk {risk[1]} ({risk[0]}/100, without personal-data entities): a triage aid, not a conclusion.")
    seeds = ", ".join(view.seeds)
    if seeds:
        parts.append(f"Seeds: {seeds}.")
    if view.personal_seeds:
        parts.append(f"{view.personal_seeds} personal seed(s) not listed.")
    if view.other_seeds:
        parts.append(f"{view.other_seeds} other seed(s) not listed.")
    if view.withheld:
        parts.append("Withheld from this export: " + ", ".join(f"{n} {why}" for why, n in sorted(view.withheld.items())) + ".")
    if view.banner:
        parts.append(view.banner)
    return view.scrub(" ".join(parts))


def bundle(case: Mapping[str, Any], *, include_personal: bool = False, include_weak: bool = False) -> dict[str, Any]:
    """The STIX 2.1 bundle of a case (see the module docstring)."""
    view = prepare(case, include_personal=include_personal, include_weak=include_weak)
    return _bundle(view)


def _bundle(view: ExportView) -> dict[str, Any]:
    marking = copy.deepcopy(MARKINGS[view.tlp])
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": IDENTITY_ID,
        "created": GLOBAL_TS,
        "modified": GLOBAL_TS,
        "name": "V3LUM",
        "identity_class": "system",
        "object_marking_refs": [view.marking_id],
    }
    objs: dict[str, dict[str, Any]] = {}
    ids: dict[str, str] = {}
    for key, node in view.nodes.items():
        obj = _object_for(node, view)
        if obj is None:
            continue
        objs.setdefault(obj["id"], obj)
        ids[key] = obj["id"]

    extra: dict[str, dict[str, Any]] = {}
    for key, ind in sorted(view.indicators.items()):
        if key not in ids or not view.is_indicator(key):
            continue
        obj, more = _indicator(view, ind, view.nodes[key], ids[key])
        extra.setdefault(obj["id"], obj)
        for other in more:
            extra.setdefault(other["id"], other)
        # the indicator also indicates the actors/malware the entity is tied to in the graph
        for edge in view.case.get("edges") or ():
            if isinstance(edge, Mapping) and str(edge.get("src")) == key:
                dst = ids.get(str(edge.get("dst") or ""))
                if dst and dst.split("--", 1)[0] in ("malware", "threat-actor"):
                    rel = _relationship(view, obj["id"], "indicates", dst)
                    extra.setdefault(rel["id"], rel)

    for edge in view.case.get("edges") or ():
        if not isinstance(edge, Mapping):
            continue
        src, dst = ids.get(str(edge.get("src") or "")), ids.get(str(edge.get("dst") or ""))
        if src and dst and src != dst:
            rel = _relationship(view, src, _rtype(edge.get("relation")), dst, f"via {edge.get('module') or 'V3LUM'}")
            extra.setdefault(rel["id"], rel)

    for corr in view.correlations:
        refs = [ids[k] for k in (str(x) for x in corr.get("entities") or ()) if k in ids]
        if refs:
            note = _note(view, corr, refs, kind="correlation")
            extra.setdefault(note["id"], note)
    for f in view.findings:
        if str(f.get("severity") or "info").lower() == "info":
            continue
        ref = ids.get(str(f.get("entity") or ""))
        if ref:
            note = _note(view, f, [ref], kind="finding")
            extra.setdefault(note["id"], note)

    order = {"vulnerability": 0, "attack-pattern": 0, "threat-actor": 0, "malware": 0, "identity": 0, "indicator": 2, "note": 3, "relationship": 4}
    body = sorted([*objs.values(), *(o for k, o in extra.items() if k not in objs)], key=lambda o: (order.get(o["type"], 1), o["id"]))
    refs = [o["id"] for o in body] or [IDENTITY_ID]
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": _uid("report", view.case_id),
        "created": _stamp(view.created),
        "modified": _stamp(view.created),
        "created_by_ref": IDENTITY_ID,
        "name": f"V3LUM case {view.case_id}",
        "description": _report_description(view),
        "published": _stamp(view.created),
        "report_types": ["threat-report"],
        "object_refs": refs,
        "object_marking_refs": [view.marking_id],
    }
    flags = f"{int(view.include_personal)}{int(view.include_weak)}"
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(V3LUM_NS, f'bundle|{view.case_id}|{view.tlp}|{flags}')}",
        "objects": [marking, identity, *body, report],
    }
