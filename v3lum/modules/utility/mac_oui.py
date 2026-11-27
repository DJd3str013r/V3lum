"""MAC OUI vendor lookup from the IEEE registries, fully offline (P315, batch p2-G12-2).

c1: offline (disclosure 'none', allowed at TLP:RED): the IEEE Registration Authority listings MA-L (oui.csv),
MA-M (mam.csv), MA-S (oui36.csv) and IAB (iab.csv; IAB blocks are not repeated in oui36.csv) - plus CID
(cid.csv, registered for completeness, never used for lookups: CIDs live in the locally administered
space) - are whole public files fetched by the dataset manager (monthly; the provider profile sends the
neutral V3LUM UA, because the IEEE may block generic library UAs). They are parsed into a compact in-memory
prefix index with longest-prefix match: MA-S/IAB 36 bits > MA-M 28 > MA-L 24. No MAC address or prefix ever
leaves the machine.

c2: locally administered (0x02 bit of the first octet), multicast and null MACs are flagged 'random/private
MAC: vendor lookup not meaningful' and are never looked up (not even locally) or sent anywhere.

c3-c4: the online relays (api.maclookup.app, api.macvendors.com) live in the separate opt-in module
``mac_oui_online``; it runs only for prefixes missing from this index and sends only ``mac_oui.fallback_prefix``
(the 6, 7 or 9 hex digits of the registry prefix, never the full MAC). The shared helpers below
(``normalize_mac``, ``mac_flags``, ``lookup_vendor``, ``registry_prefix``, ``load_index``) are its source of
truth.
"""

from __future__ import annotations

import csv
import io
import re
import threading
import unicodedata
from pathlib import Path
from collections.abc import Iterable
from typing import Any

from v3lum.core.datasets import DATASETS, DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "ieee.oui_registries"
MONTH = 30 * 86400
IEEE_RA_NAME = "IEEE Registration Authority"
IEEE_REGISTRY_HEX_LEN = {"MA-L": 6, "MA-M": 7, "MA-S": 9, "IAB": 9, "CID": 6}
#: c1 dataset entries; min_rows/min_bytes from the 2026-11-26 live download (40,565 / 6,704 / 7,306 / 4,575 / 228 rows)
IEEE_DATASETS: dict[str, dict[str, Any]] = {
    "ieee_oui_ma_l": {"url": "https://standards-oui.ieee.org/oui/oui.csv", "registry": "MA-L", "min_rows": 30000,
                      "min_bytes": 3_000_000, "essential": True},
    "ieee_oui_ma_m": {"url": "https://standards-oui.ieee.org/oui28/mam.csv", "registry": "MA-M", "min_rows": 5000,
                      "min_bytes": 500_000, "essential": True},
    "ieee_oui_ma_s": {"url": "https://standards-oui.ieee.org/oui36/oui36.csv", "registry": "MA-S", "min_rows": 5000,
                      "min_bytes": 500_000, "essential": True},
    "ieee_oui_iab": {"url": "https://standards-oui.ieee.org/iab/iab.csv", "registry": "IAB", "min_rows": 4000,
                     "min_bytes": 300_000, "essential": True},
    "ieee_oui_cid": {"url": "https://standards-oui.ieee.org/cid/cid.csv", "registry": "CID", "min_rows": 100,
                     "min_bytes": 10_000, "essential": False},
}
#: the registries the lookup index is built from (CID is never used for lookups, c2)
LOOKUP_DATASETS = ("ieee_oui_ma_l", "ieee_oui_ma_m", "ieee_oui_ma_s", "ieee_oui_iab")
MAC_RANDOM_REASON = "random/private MAC: vendor lookup not meaningful"  # c2 (verbatim)
_SLAP_QUADRANT = {0x2: "AAI", 0x6: "reserved", 0xA: "ELI", 0xE: "SAI"}  # IEEE 802c quadrants of local addresses
_ISO_ALPHA2_TEXT = (
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW "
    "BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI "
    "FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN "
    "IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME "
    "MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF "
    "PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV "
    "SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK "
    "YE YT ZA ZM ZW"
)
_ISO_ALPHA2 = frozenset(_ISO_ALPHA2_TEXT.split())
_HEX_RE = re.compile(r"[0-9A-Fa-f]+")
_MAC_GROUPS_RE = re.compile(r"[0-9A-Fa-f]{1,2}(?:[:\-][0-9A-Fa-f]{1,2}){5}(?:[:\-][0-9A-Fa-f]{1,2}){0,2}")
_MAC_DOTTED_RE = re.compile(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4})?")
_HTML_HEAD_RE = re.compile(r"\s{0,200}(?:<!doctype\s{1,20}html|<html|<head|<body|<title|<meta\s)", re.I)


# ---------------------------------------------------------------------------------- MAC helpers
def normalize_mac(value: Any) -> str | None:
    """EUI-48/EUI-64 in any common notation -> 12 (or 16) upper-case hex digits; None when not a MAC."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or len(v) > 40:
        return None
    if _MAC_GROUPS_RE.fullmatch(v):
        groups = re.split(r"[:\-]", v)
        if len(groups) not in (6, 8):
            return None
        h = "".join(g.zfill(2) for g in groups)
    elif _MAC_DOTTED_RE.fullmatch(v):
        h = v.replace(".", "")
    elif _HEX_RE.fullmatch(v) and len(v) in (12, 16):
        h = v
    else:
        return None
    return h.upper()


def mac_flags(mac: Any) -> dict[str, Any]:
    """c2: multicast / locally administered (0x02 of the first octet) / null flags. lookup_allowed=False means
    the MAC is never looked up or sent anywhere; 'reason' then carries the verbatim c2 text."""
    h = normalize_mac(mac)
    if h is None:
        return {"valid": False, "lookup_allowed": False, "reason": "not a MAC address"}
    first = int(h[:2], 16)
    multicast = bool(first & 0x01)
    local = bool(first & 0x02)
    null = set(h) == {"0"}
    out: dict[str, Any] = {
        "valid": True, "mac": h, "eui": 64 if len(h) == 16 else 48, "multicast": multicast,
        "broadcast": h == "F" * len(h), "locally_administered": local,
        "slap_quadrant": _SLAP_QUADRANT.get(first & 0x0E) if local else None, "null": null,
        "lookup_allowed": not (multicast or local or null), "reason": None,
    }
    if multicast or local:
        out["reason"] = MAC_RANDOM_REASON
    elif null:
        out["reason"] = "null MAC (00:00:00:00:00:00): vendor lookup not meaningful"
    return out


def public_flags(flags: dict[str, Any]) -> dict[str, Any]:
    """The ``mac_flags`` attribute (the MAC itself is the entity: not repeated)."""
    return {k: flags.get(k) for k in ("eui", "locally_administered", "multicast", "broadcast", "null", "slap_quadrant",
                                      "lookup_allowed", "reason") if k in flags}


def registry_prefix(mac: str, kind: str | None) -> str | None:
    """c4: the registry prefix that may leave the machine: 6, 7 or 9 hex digits, never the full MAC."""
    h = normalize_mac(mac)
    n = {"MA-L": 6, "CID": 6, "MA-M": 7, "MA-S": 9, "IAB": 9}.get(kind or "")
    if not h or n is None or len(h) < 12:
        return None
    return h[:n]


# ---------------------------------------------------------------------------------- IEEE CSVs
def _clean_org(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s or "").split())


def ieee_country_hint(address: Any) -> str | None:
    """Best-effort ISO alpha-2 country from an IEEE 'Organization Address' ('... San Jose CA US 94568')."""
    if not isinstance(address, str):
        return None
    toks = _clean_org(address).replace(",", " ").split()
    for tok in reversed(toks[-4:]):
        if len(tok) == 2 and tok.isalpha() and tok.isupper() and tok in _ISO_ALPHA2:
            return tok
        if any(c.isdigit() for c in tok) or tok == "-":
            continue  # postal-code tokens after the country
        break
    return None


def _as_text(raw: Any) -> str | None:
    if isinstance(raw, (bytes, bytearray, memoryview)):
        b = bytes(raw)
        return (b[3:] if b.startswith(b"\xef\xbb\xbf") else b).decode("utf-8", errors="replace")
    if isinstance(raw, str):
        return raw[1:] if raw.startswith("﻿") else raw
    return None


def parse_ieee_csv(raw: Any) -> dict[str, Any]:
    """c1/c5: parse one IEEE registry CSV -> {'rows': [{'registry', 'assignment', 'org', 'country_hint',
    'private'}], 'skipped': n, 'error': None|reason}. Handles CRLF, quoted commas, NBSP/full-width punctuation
    (NFKC), padded names, 'Private' registrants and HTML block pages ('html_instead_of_csv')."""
    t = _as_text(raw)
    if t is None or not t.strip():
        return {"rows": [], "skipped": 0, "error": "empty"}
    if _HTML_HEAD_RE.match(t[:4096]):
        return {"rows": [], "skipped": 0, "error": "html_instead_of_csv"}
    reader = csv.reader(io.StringIO(t))
    try:
        header = next(reader)
    except (StopIteration, csv.Error):
        return {"rows": [], "skipped": 0, "error": "bad_header"}
    if [h.strip().lower() for h in header[:2]] != ["registry", "assignment"]:
        return {"rows": [], "skipped": 0, "error": "bad_header"}
    rows, skipped = [], 0
    try:
        for rec in reader:
            if not rec or not any(x.strip() for x in rec):
                continue
            rec = (rec + ["", "", "", ""])[:4] if len(rec) <= 4 else rec[:3] + [",".join(rec[3:])]
            reg, assign = rec[0].strip().upper(), rec[1].strip().upper()
            want = IEEE_REGISTRY_HEX_LEN.get(reg)
            if want is None or len(assign) != want or not _HEX_RE.fullmatch(assign):
                skipped += 1
                continue
            org = _clean_org(rec[2])
            rows.append({"registry": reg, "assignment": assign, "org": org, "private": org.lower() == "private",
                         "country_hint": ieee_country_hint(rec[3])})
    except csv.Error:
        return {"rows": rows, "skipped": skipped, "error": "csv_error"}
    return {"rows": rows, "skipped": skipped, "error": None}


def validate_ieee_csv(raw: Any, registry: str, min_rows: int | None = None) -> str | None:
    """AR10 ``validate=`` logic: a short reason when the download is unusable (HTML block page, bad header, a
    truncated file with too few rows, the wrong registry), else None."""
    parsed = parse_ieee_csv(raw)
    if parsed["error"]:
        return parsed["error"]
    regs = {r["registry"] for r in parsed["rows"]}
    if regs and regs != {registry}:
        return f"wrong_registry {sorted(regs)}"
    if min_rows is not None and len(parsed["rows"]) < min_rows:
        return f"too_few_rows {len(parsed['rows'])} < {min_rows}"
    return None


def build_oui_index(*row_lists: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """c1: compact longest-prefix index {'36': {...}, '28': {...}, '24': {...}, 'cid': {...}, 'parent_kind': {...},
    'counts': {...}} with values (registry, org, country_hint, alternatives). MA-S and IAB share the 36-bit
    table; duplicate assignments (080030 is listed three times) keep the first organisation and list the others."""
    idx: dict[str, Any] = {"36": {}, "28": {}, "24": {}, "cid": {}, "parent_kind": {}, "counts": {}}
    table_for = {"MA-L": "24", "MA-M": "28", "MA-S": "36", "IAB": "36", "CID": "cid"}
    for rows in row_lists:
        for r in rows or ():
            if not isinstance(r, dict):
                continue
            reg, a = r.get("registry"), r.get("assignment")
            tab = table_for.get(str(reg))
            if tab is None or not isinstance(a, str) or len(a) != IEEE_REGISTRY_HEX_LEN[str(reg)]:
                continue
            org = r.get("org") or ""
            cur = idx[tab].get(a)
            if cur is None:
                idx[tab][a] = (reg, org, r.get("country_hint"), ())
            elif org and org != cur[1] and org not in cur[3]:
                idx[tab][a] = (cur[0], cur[1], cur[2], cur[3] + (org,))
            idx["counts"][reg] = idx["counts"].get(reg, 0) + 1
            if reg in ("MA-M", "MA-S", "IAB"):
                kind = "MA-M" if reg == "MA-M" else "MA-S"
                prev = idx["parent_kind"].get(a[:6])
                idx["parent_kind"][a[:6]] = kind if prev in (None, kind) else "mixed"
    return idx


def lookup_vendor(index: dict[str, Any], mac: Any) -> dict[str, Any]:
    """c1-c2: offline longest-prefix match MA-S/IAB (36) > MA-M (28) > MA-L (24).

    status: 'found' | 'sub_block_unknown' (only the 'IEEE Registration Authority' parent matched) | 'unknown' |
    'flagged' (local/multicast/null: never looked up, c2) | 'invalid'. 'fallback_prefix' is the ONLY value
    the opt-in online module may send (c3-c4), or None.
    """
    flags = mac_flags(mac)
    if not flags.get("valid"):
        return {"status": "invalid", "reason": flags.get("reason"), "fallback_prefix": None}
    if not flags["lookup_allowed"]:
        return {"status": "flagged", "reason": flags["reason"], "flags": flags, "fallback_prefix": None}
    h = flags["mac"]
    for bits, n in (("36", 9), ("28", 7), ("24", 6)):
        hit = (index or {}).get(bits, {}).get(h[:n])
        if hit:
            reg, org, country, alts = hit
            res: dict[str, Any] = {
                "status": "found", "prefix": h[:n], "bits": int(bits), "registry": reg, "org": org, "country_hint": country,
                "alternatives": list(alts), "private_registrant": org.lower() == "private", "flags": flags, "fallback_prefix": None,
            }
            if bits == "24" and org == IEEE_RA_NAME:
                kind = (index or {}).get("parent_kind", {}).get(h[:6])
                res["status"] = "sub_block_unknown"
                # an RA parent whose sub-block size is unknown gets no fallback: 9 hex of an MA-M block would leak device bits
                res["fallback_prefix"] = registry_prefix(h, kind) if kind in ("MA-M", "MA-S") else None
                res["reason"] = ("assigned by IEEE as an MA-M/MA-S parent block; sub-block missing from the local index"
                                 + ("" if kind in ("MA-M", "MA-S") else " and block size unknown (no online fallback)"))
            return res
    return {"status": "unknown", "prefix": h[:6], "flags": flags, "fallback_prefix": registry_prefix(h, "MA-L")}


def _validator(registry: str, min_rows: int):
    def check(path: Path) -> bool:
        why = validate_ieee_csv(Path(path).read_bytes(), registry, min_rows)
        if why:
            raise ValueError(f"IEEE {registry} listing rejected: {why}")
        return True

    return check


def register_datasets() -> list[str]:
    names = []
    for name, spec in IEEE_DATASETS.items():
        if name not in DATASETS:
            register_dataset(
                name, spec["url"], ttl=MONTH,
                description=f"IEEE Registration Authority public {spec['registry']} listing (whole CSV; matched offline by mac_oui)",
                licence="IEEE RA public registry listing (public data)", terms_class="open",
                attribution="IEEE Registration Authority, standards-oui.ieee.org", provider="ieee", source=SOURCE,
                validate=_validator(spec["registry"], spec["min_rows"]), min_bytes=spec["min_bytes"], expect="text",
                max_bytes=10 * 1024 * 1024, essential=spec["essential"],
            )
        names.append(name)
    return names


DATASET_NAMES = register_datasets()

_LOCK = threading.Lock()
_CACHE: dict[str, Any] = {"key": None, "index": None}


def load_index(ctx: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """The lookup index from the local IEEE copies (downloaded by the dataset manager when missing or older
    than a month). Raises DatasetUnavailable/DatasetError when MA-L, the base registry, has no usable copy;
    the other registries missing only make the index partial (reported in the returned info)."""
    paths: dict[str, Path] = {}
    missing: dict[str, str] = {}
    for name in LOOKUP_DATASETS:
        try:
            paths[name] = Path(ctx.data.fetch(name))
        except (DatasetUnavailable, DatasetError) as exc:
            if name == "ieee_oui_ma_l":
                raise
            missing[name] = str(exc)[:200]
    key_parts = []
    for name, path in paths.items():
        try:
            info = ctx.data.info(name)
            key_parts.append((name, info.sha256 or "", int(path.stat().st_mtime_ns)))
        except (OSError, ValueError, DatasetError):
            key_parts.append((name, "", 0))
    key = tuple(sorted(key_parts))
    with _LOCK:
        if _CACHE["key"] == key and _CACHE["index"] is not None:
            return _CACHE["index"], {"missing": missing, "datasets": sorted(paths)}
    rows: list[list[dict[str, Any]]] = []
    problems: dict[str, str] = {}
    for name, path in paths.items():
        parsed = parse_ieee_csv(path.read_bytes())
        if parsed["error"] and not parsed["rows"]:
            problems[name] = parsed["error"]
            continue
        rows.append(parsed["rows"])
    if "ieee_oui_ma_l" in problems:
        raise DatasetError(f"IEEE MA-L local copy unusable ({problems['ieee_oui_ma_l']}): run v3lum data update ieee_oui_ma_l",
                           name="ieee_oui_ma_l")
    index = build_oui_index(*rows)
    with _LOCK:
        _CACHE["key"], _CACHE["index"] = key, index
    missing.update(problems)
    return index, {"missing": missing, "datasets": sorted(paths)}


def oui_attr(hit: dict[str, Any]) -> dict[str, Any]:
    keys = ("status", "prefix", "bits", "registry", "country_hint", "private_registrant", "alternatives", "fallback_prefix", "reason")
    return {k: hit.get(k) for k in keys if hit.get(k) not in (None, [], "")}


def _fmt_prefix(prefix: str) -> str:
    pairs = [prefix[i:i + 2] for i in range(0, len(prefix), 2)]
    return ":".join(pairs)


@register
class MacOui(Module):
    name = "mac_oui"
    title = "MAC vendor (IEEE OUI registries, offline)"
    description = (
        "Vendor of a MAC address from the IEEE MA-L/MA-M/MA-S/IAB listings, matched offline by longest prefix; "
        "random/locally administered and multicast MACs are flagged and never looked up."
    )
    category = "utility"
    accepts = {T.MAC}
    produces = frozenset()
    tags = {"offline", "free"}
    reference = "https://standards.ieee.org/products-programs/regauth/"
    notice = "IEEE RA public registry listings, fetched whole by `v3lum data update` (monthly); no MAC or prefix is ever sent anywhere."
    # ---- contract v2 declarations ---------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # c1: the dataset manager alone downloads the listings
    hosts = ()
    sources = (SOURCE,)
    access_model = "offline"
    expected_latency = 0.05
    max_pivots = 0
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        flags = mac_flags(entity.value)
        if not flags.get("valid"):
            return res.mark(Status.ERROR, "not a MAC address (EUI-48/EUI-64): not analysed")
        res.attr("mac_flags", public_flags(flags))
        if not flags["lookup_allowed"]:
            res.finding(
                "Random/private MAC: vendor lookup not meaningful",
                "info",
                f"{flags['reason']}. "
                + ("Locally administered address (0x02 bit of the first octet"
                   + (f", IEEE 802c quadrant {flags['slap_quadrant']}" if flags.get("slap_quadrant") else "")
                   + "): phones and laptops randomise it per network. " if flags["locally_administered"] else "")
                + ("Multicast/group address (0x01 bit). " if flags["multicast"] else "")
                + "It is never looked up locally or sent to any service (P315 c2).",
                confidence="confirmed",
                data={"flags": public_flags(flags)},
                tags=["info", "random_mac"],
            )
            return res
        index, info = load_index(ctx)
        hit = lookup_vendor(index, flags["mac"])
        res.attr("mac_oui", oui_attr(hit))
        partial = sorted(info["missing"])
        res.raw = {"lookup": oui_attr(hit), "datasets": info["datasets"], "missing_datasets": info["missing"]}
        if hit["status"] == "found":
            org = hit["org"]
            res.attr("mac_vendor", org)
            alts = f" Also listed for this prefix: {', '.join(hit['alternatives'])}." if hit["alternatives"] else ""
            private = " The registrant asked the IEEE to hide its name ('Private')." if hit["private_registrant"] else ""
            res.finding(
                "MAC vendor (IEEE registry)",
                "info",
                f"{_fmt_prefix(hit['prefix'])} ({hit['registry']}, {hit['bits']}-bit prefix) is assigned to {org}"
                + (f" ({hit['country_hint']})" if hit.get("country_hint") else "") + "." + alts + private
                + (f" Partial index: {', '.join(partial)} unavailable." if partial else ""),
                confidence="confirmed",
                data={"prefix": hit["prefix"], "registry": hit["registry"], "bits": hit["bits"], "org": org},
                tags=["info"],
                source=SOURCE,
            )
            return res
        if hit["status"] == "sub_block_unknown":
            res.finding(
                "MAC block assigned through the IEEE RA (sub-block not in the local index)",
                "info",
                f"{_fmt_prefix(hit['prefix'])} is an IEEE Registration Authority parent block: {hit['reason']}."
                + (f" Missing local listings: {', '.join(partial)} (run v3lum data update)." if partial else ""),
                confidence="confirmed",
                data={"prefix": hit["prefix"], "fallback_prefix": hit.get("fallback_prefix")},
                tags=["info"],
                source=SOURCE,
            )
            return res
        if partial:  # the prefix may sit in a registry we could not read: could not verify, never 'unknown vendor'
            return res.mark(Status.UNAVAILABLE, f"IEEE listings {', '.join(partial)} unavailable: run v3lum data update "
                                                f"{' '.join(partial)} (could not verify)", reason_code="dataset")
        res.error = (f"prefix {_fmt_prefix(hit['prefix'])} is not in the IEEE registries (local copies); the opt-in "
                     "mac_oui_online module may query the registry prefix only")
        return res.mark(Status.EMPTY)
