"""Offline IP -> country and ASN from the DB-IP Lite databases (CC BY 4.0), read locally (P047).

Batch p1-G02-2, proposal P047 ``ip_offline_db`` (the mmdb part; IPtoASN and bgp.tools live in
``ip_offline_db``). Final conditions implemented here:

* c1 - DB-IP Lite country + ASN mmdb (monthly; never the 86 MB city file) fetched only by
  ``v3lum data update`` (``large=True``); the gzip goes through the core ``safe_extract`` with its
  size caps and is streamed to disk.
* c2 - scans never wait for a download: a missing dataset is UNAVAILABLE reason_code 'dataset'
  ('run v3lum data update ...'), never EMPTY; the dataset name, release and age are shown
  (attribute ``dataset_age``: 'DB-IP Lite 2026-11, 25 days').
* c3 - lookups are local (disclosure 'none', allowed at TLP:RED).
* c4 - the .mmdb files are read through the optional pure-Python ``maxminddb`` package
  (``requires_packages``, Apache-2.0; UNAVAILABLE 'package' without it).
* c7/c8 - attribution 'IP Geolocation by DB-IP (https://db-ip.com)'; country/continent/ASN context
  only: city, coordinates, postal code and subdivisions are never read or kept.

MaxMind GeoLite2 (optional, terms 'license', two registered keys with HTTP Basic auth) waits for
keyed dataset downloads in the core dataset manager: see docs/backlog/p1-G02-2.md. The request
builder and the EULA 30-day rule are provided here (:func:`geolite2_request`,
:func:`geolite2_must_refresh`) for that module.
"""

from __future__ import annotations

import base64
import threading
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, package_available, register
from v3lum.modules.ip_network.ip_offline_db import age_text, local_dataset, mark_dataset_failure, parse_ts, special_purpose

SOURCE = "dbip.lite"
ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"
DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{release}.mmdb.gz"
MMDB_MARKER = b"\xab\xcd\xefMaxMind.com"
GEOLITE2_EDITIONS = ("GeoLite2-Country", "GeoLite2-ASN")
GEOLITE2_MAX_AGE_DAYS = 30


def dbip_release(today: date) -> str:
    """Release to fetch: the current month from the 2nd (DB-IP publishes on the 1st), else the
    previous month ('2026-12' answered 404 on 2026-11-26)."""
    if today.day >= 2:
        return f"{today.year:04d}-{today.month:02d}"
    year, month = (today.year - 1, 12) if today.month == 1 else (today.year, today.month - 1)
    return f"{year:04d}-{month:02d}"


def dbip_url(kind: str, release: str) -> str:
    """DB-IP Lite country or ASN mmdb URL; the city file is refused (P047 c1/c8)."""
    if kind not in ("country", "asn"):
        raise ValueError("DB-IP Lite kind must be 'country' or 'asn' (the city file is excluded, P047 c1/c8)")
    return DBIP_URL.format(kind=kind, release=release)


def _validate_mmdb(path: Path) -> bool:
    size = path.stat().st_size
    with open(path, "rb") as fh:
        fh.seek(max(0, size - 128 * 1024))
        tail = fh.read()
    if MMDB_MARKER not in tail:
        raise ValueError("not a MaxMind DB file (no metadata marker)")
    return True


RELEASE = dbip_release(datetime.now(timezone.utc).date())
COUNTRY = register_dataset(
    "ip_offline_geo.dbip_country_lite.mmdb",
    dbip_url("country", RELEASE),
    ttl=30 * 86400,
    description=f"DB-IP Lite country database (mmdb, release {RELEASE}); fetched by `v3lum data update` only",
    licence="CC-BY-4.0",
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="dbip",
    source=SOURCE,
    validate=_validate_mmdb,
    min_bytes=100_000,
    expect="bytes",
    max_bytes=96 * 1024 * 1024,
    large=True,
    archive="gz",
    member="dbip-country-lite.mmdb",
    essential=True,
)
ASN = register_dataset(
    "ip_offline_geo.dbip_asn_lite.mmdb",
    dbip_url("asn", RELEASE),
    ttl=30 * 86400,
    description=f"DB-IP Lite ASN database (mmdb, release {RELEASE}); fetched by `v3lum data update` only",
    licence="CC-BY-4.0",
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="dbip",
    source=SOURCE,
    validate=_validate_mmdb,
    min_bytes=100_000,
    expect="bytes",
    max_bytes=96 * 1024 * 1024,
    large=True,
    archive="gz",
    member="dbip-asn-lite.mmdb",
    essential=True,
)

_READERS: dict[str, tuple[str, Any]] = {}
_LOCK = threading.Lock()


def _reader(name: str, path: Path, sha256: str) -> Any:
    """An open maxminddb Reader per dataset version (memory-mapped, read only)."""
    import maxminddb  # optional dependency (requires_packages): imported only when used

    with _LOCK:
        hit = _READERS.get(name)
        if hit and hit[0] == sha256 and sha256:
            return hit[1]
    reader = maxminddb.open_database(str(path))
    with _LOCK:
        old = _READERS.get(name)
        _READERS[name] = (sha256, reader)
    if old is not None and old[1] is not reader:
        try:
            old[1].close()
        except Exception:  # noqa: BLE001 - closing an old reader is best effort
            pass
    return reader


def _get(reader: Any, ip: str) -> tuple[Any, int]:
    getter = getattr(reader, "get_with_prefix_len", None)
    if callable(getter):
        record, prefix = getter(ip)
        return record, int(prefix or 0)
    return reader.get(ip), 0


def normalise_geo(record: Any) -> dict[str, Any]:
    """Country/continent context only: city, location, postal code and subdivisions are never
    copied (P047 c8: geodata never locates a person or household)."""
    if not isinstance(record, dict):
        return {}
    country = record.get("country") if isinstance(record.get("country"), dict) else {}
    continent = record.get("continent") if isinstance(record.get("continent"), dict) else {}
    code = country.get("iso_code") if isinstance(country.get("iso_code"), str) else ""
    out: dict[str, Any] = {
        "country": code.upper() if len(code) == 2 and code.isalpha() else "",
        "continent": continent.get("code") if isinstance(continent.get("code"), str) and len(continent.get("code")) == 2 else "",
    }
    eu = country.get("is_in_european_union")
    if out["country"]:
        out["in_eu"] = eu if isinstance(eu, bool) else False
    return out


def normalise_asn(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    asn = record.get("autonomous_system_number")
    if not isinstance(asn, int) or isinstance(asn, bool) or asn <= 0:
        return {}
    org = record.get("autonomous_system_organization")
    return {"asn": asn, "as_org": org[:120] if isinstance(org, str) else ""}


def _build_date(reader: Any) -> datetime | None:
    meta = getattr(reader, "metadata", None)
    meta = meta() if callable(meta) else meta
    epoch = getattr(meta, "build_epoch", None)
    if isinstance(epoch, int) and not isinstance(epoch, bool) and epoch > 0:
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    return None


def geolite2_request(edition: str, account_id: str, licence_key: str) -> dict[str, Any] | None:
    """GeoLite2 permalink with HTTP Basic auth (account id + licence key, two registered keys);
    never ``?license_key=`` (P047 c6). None when a key is missing (NEEDS_KEY)."""
    if edition not in GEOLITE2_EDITIONS:
        raise ValueError(f"GeoLite2 edition must be one of {', '.join(GEOLITE2_EDITIONS)}")
    if not account_id or not licence_key:
        return None
    token = base64.b64encode(f"{account_id}:{licence_key}".encode()).decode("ascii")
    return {"url": f"https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz", "headers": {"Authorization": f"Basic {token}"}}


def geolite2_must_refresh(fetched_at: datetime | None, now: datetime) -> bool:
    """GeoLite2 EULA: a copy older than 30 days must be updated or deleted (never used)."""
    return fetched_at is None or (now - fetched_at).total_seconds() > GEOLITE2_MAX_AGE_DAYS * 86400


@register
class IpOfflineGeo(Module):
    name = "ip_offline_geo"
    title = "Offline IP -> country/ASN (DB-IP Lite)"
    description = (
        "Country, continent and AS number/organisation of an IP from the local DB-IP Lite databases (CC BY 4.0, "
        "monthly, fetched by `v3lum data update`); nothing is sent."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6}
    produces = {T.ASN}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SOURCE,)
    requires_packages = ("maxminddb",)
    reference = "https://db-ip.com/db/lite.php"
    notice = (
        f"{ATTRIBUTION}. Country/ASN context only: never used to locate a person or household. Run `v3lum data update` "
        "to fetch the monthly databases."
    )
    tags = {"offline", "free"}
    max_pivots = 2

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return special_purpose(entity.value) is None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        ip = entity.value
        if not package_available("maxminddb"):  # the policy gate (POL-13) normally stops the run first
            return res.mark("unavailable", "needs python package maxminddb (pip install 'v3lum[full]')", reason_code="package")
        now = ctx.now()
        ages: list[str] = []
        raw: dict[str, Any] = {}
        found = False
        for name, label in ((COUNTRY, "country"), (ASN, "asn")):
            try:
                path, info = local_dataset(ctx, name)
                reader = _reader(name, path, info.sha256)
                record, prefix = _get(reader, ip)
            except DatasetError as exc:
                return mark_dataset_failure(res, exc, f"DB-IP Lite {label}")
            except (OSError, ValueError, TypeError) as exc:
                return res.mark("error", f"DB-IP Lite {label}: unreadable local copy ({type(exc).__name__}: {exc}): could not verify")
            built = _build_date(reader)
            release = built.strftime("%Y-%m") if built else RELEASE
            ref = built or parse_ts(info.fetched_at)
            ages.append(f"DB-IP Lite {label} {release}, {age_text((now - ref).total_seconds()) if ref else 'age unknown'}")
            raw[label] = {"sha256": info.sha256, "release": release, "prefix_len": prefix}
            if label == "country":
                geo = normalise_geo(record)
                if geo.get("country"):
                    found = True
                    res.attr("country", geo["country"])
                    res.attr("continent", geo.get("continent"))
                    if "in_eu" in geo:
                        res.attr("in_eu", geo["in_eu"])
                    raw[label]["record"] = geo
            else:
                asn = normalise_asn(record)
                if asn:
                    found = True
                    res.attr("asn", f"AS{asn['asn']}")
                    res.attr("as_org", asn["as_org"])
                    res.pivot(T.ASN, f"AS{asn['asn']}", "belongs_to_asn", confidence=0.8)
                    raw[label]["record"] = asn
        res.raw = raw
        if not found:
            return res.mark("empty")
        res.attr("dataset_age", ages)
        return res
