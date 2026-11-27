"""Geocoding and reverse geocoding over OpenStreetMap data: Nominatim (OSMF) with Photon as the only fallback
(P262, batch p3-G12-1).

Final conditions, as implemented here:

1. **Nominatim** (``nominatim.openstreetmap.org``, provider ``osmf_nominatim``, tier trusted) per the OSMF usage
   policy: the provider ``http_profile`` asks for the identifying User-Agent with the ``contact_email`` role
   mailbox (P326; the core builds it and only for this provider's host). Without the mailbox the core raises
   ConfigError before anything is sent: the Nominatim source is reported SKIPPED ``config`` and Photon answers.
   A provider bucket of 1 req/s per installation (provider quota block, P334), no bulk geocoding (at most 3
   structured attempts per entity, ``max_requests`` 4), cache 30 days (negative answers included). The origin's
   403 'Access blocked'/'Access denied' page is BLOCKED (provider error marker, rule 5); 'Bandwidth limit
   exceeded' (429/503/509) and the CDN edge refusal HTTP 629 seen live are RATE_LIMITED - never 'no place'.
2. **Photon** (``photon.komoot.io``, provider ``komoot``, tier community) is the only fallback; its geometry is
   ``[lon, lat]`` and is swapped by :func:`parse_photon`. It runs when Nominatim is skipped, blocked, rate
   limited or failed, or when every structured attempt found nothing. Overpass and geocode.xyz are dropped.
3. **Inputs**: ``coordinates`` (reverse) and ``cep`` (forward, postal code); a ``keyword`` only as an explicit
   address-style TYPE:value (``address:``/``endereco:``/``endereço:``/``addr:``); ``text_blob`` is never accepted
   (geocoding pasted text would disclose it). Address search falls back street -> postal code -> city.
4. **Legal floor**: ``run_on='seeds'`` - only analyst-typed seeds run. Coordinates from photos (EXIF), devices,
   pivots or text never run automatically: the analyst confirms one entity by running it as a typed seed
   (``v3lum run geocoding coordinates:<lat,lon>``); otherwise SKIPPED ``privacy``. Company addresses (CNPJ/CEP
   records) are geocoded only when typed or run explicitly (pivot CEPs never run).
5. **Coordinates are PERSONAL_TYPES** (A8): both providers have no ``personal_data_review`` yet, so the policy gate
   keeps the module out of the effective default set for coordinates and runs it only when selected in a case
   with a recorded purpose (reason ``privacy``). Coordinates are never auto-expanded: every pivot is
   ``expand=False``.
6. **Wording**: every place is labelled 'approximate place (OSM)' with its precision (street/postcode/city/
   region) and 'an address is not proof of residence'; the attribution '(c) OpenStreetMap contributors (ODbL
   1.0)' is an attribute of every result and a notice fragment. Map links come from P260 (pivots_geo_image).
   Places from reverse geocoding (coordinates may locate a person) and from typed addresses carry
   ``geo_export_allowed: False`` and the ``privacy`` tag; :func:`export_view` strips them from STIX/MISP exports
   unless the analyst opts in (core request: the exporters call it, as P259 GPS).
7. Merge gate: offline tests over trimmed real fixtures (tests/fixtures/geocoding/), a provider entry for both
   hosts, the registry contract test and the P327 lint.
"""

from __future__ import annotations

import math
import re
import unicodedata
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    ConfigError,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

NOMINATIM_HOST = "nominatim.openstreetmap.org"
PHOTON_HOST = "photon.komoot.io"
NOMINATIM_SOURCE = "osmf_nominatim.geocoding"
PHOTON_SOURCE = "komoot.geocoding"
NOMINATIM_SEARCH = f"https://{NOMINATIM_HOST}/search"
NOMINATIM_REVERSE = f"https://{NOMINATIM_HOST}/reverse"
PHOTON_SEARCH = f"https://{PHOTON_HOST}/api/"
PHOTON_REVERSE = f"https://{PHOTON_HOST}/reverse"

OSM_ATTRIBUTION = "(c) OpenStreetMap contributors (ODbL 1.0)"
GEO_LABEL = "approximate place (OSM)"
GEO_DISCLAIMER = "an address is not proof of residence"
PRECISION_LEVELS = ("street", "postcode", "city", "region")
CACHE_TTL = 30 * 86400  # FC1: 30 days, negative answers included
PIVOT_NOTE = "approximate place (OSM), never auto-investigated: an address is not proof of residence"
#: attributes a STIX/MISP export drops for places that may locate a person (FC6)
PRIVACY_ATTRIBUTES = ("geo_place", "geo_display_name", "geo_address", "geo_osm_url", "city")

UF_NAMES = {
    "AC": "Acre", "AL": "Alagoas", "AP": "Amapá", "AM": "Amazonas", "BA": "Bahia",
    "CE": "Ceará", "DF": "Distrito Federal", "ES": "Espírito Santo", "GO": "Goiás",
    "MA": "Maranhão", "MT": "Mato Grosso", "MS": "Mato Grosso do Sul", "MG": "Minas Gerais",
    "PA": "Pará", "PB": "Paraíba", "PR": "Paraná", "PE": "Pernambuco", "PI": "Piauí",
    "RJ": "Rio de Janeiro", "RN": "Rio Grande do Norte", "RS": "Rio Grande do Sul",
    "RO": "Rondônia", "RR": "Roraima", "SC": "Santa Catarina", "SP": "São Paulo",
    "SE": "Sergipe", "TO": "Tocantins",
}
_OSM_TYPES = {"N": "node", "W": "way", "R": "relation", "node": "node", "way": "way", "relation": "relation"}


# ======================================================================================================
# helpers (ported from the batch prep parsers, stdlib only)
# ======================================================================================================

def fold(text: Any) -> str:
    """Accent-fold and casefold keeping one output character per input character."""
    if not isinstance(text, str):
        return ""
    out = []
    for ch in text:
        if ch.isascii():
            out.append(ch.lower())
            continue
        base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c)).casefold()
        out.append(base[:1] if base else " ")
    return "".join(out)


_UF_BY_FOLDED_NAME = {fold(v): k for k, v in UF_NAMES.items()}


def _digits(value: Any) -> str:
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        value = str(value)
    return "".join(ch for ch in value if "0" <= ch <= "9") if isinstance(value, str) else ""


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = float(value)
    elif isinstance(value, str) and value.strip():
        try:
            v = float(value.strip().replace(",", "."))
        except ValueError:
            return None
    else:
        return None
    return v if math.isfinite(v) else None


def coord_result(lat: float | None, lon: float | None) -> dict[str, Any] | None:
    """``{'lat', 'lon', 'key', 'null_island'}`` rounded to 6 decimals, or None when out of range."""
    if lat is None or lon is None or not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
        return None
    lat, lon = round(lat, 6), round(lon, 6)
    return {"lat": lat, "lon": lon, "key": f"{lat:.6f},{lon:.6f}", "null_island": abs(lat) < 1e-6 and abs(lon) < 1e-6}


_DEC_PAIR_RE = re.compile(r"^\s*([+-]?\d{1,3}(?:\.\d{1,15})?)\s*[,;\s]\s*([+-]?\d{1,3}(?:\.\d{1,15})?)\s*$")


def normalize_coordinates(value: Any) -> dict[str, Any] | None:
    """A 'lat,lon' value (the core coordinates entity form) as :func:`coord_result`, or None."""
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return coord_result(_num(value[0]), _num(value[1]))
    if not isinstance(value, str) or len(value) > 200:
        return None
    m = _DEC_PAIR_RE.match(value)
    return coord_result(_num(m.group(1)), _num(m.group(2))) if m else None


def normalize_cep(value: Any) -> str | None:
    """A CEP as 'NNNNN-NNN' (8 digits; '00000-000' refused) or None."""
    d = _digits(value)
    if len(d) != 8 or d == "00000000":
        return None
    return f"{d[:5]}-{d[5:]}"


ADDRESS_KEYWORD_PREFIXES = ("address:", "endereco:", "endereço:", "addr:")
_STREET_WORDS = ("rua", "r.", "avenida", "av.", "av", "alameda", "al.", "travessa", "tv.", "praca",
                 "pca", "rodovia", "rod.", "estrada", "estr.", "largo", "viela", "quadra", "saun",
                 "sain", "sbs", "scs", "shn", "shs", "sqn", "sqs", "setor", "via", "beco", "ladeira",
                 "parque", "vila", "conjunto", "passagem", "servidao")
_CEP_IN_TEXT_RE = re.compile(r"(?<!\d)(\d{5})-?(\d{3})(?!\d)")
_UF_TAIL_RE = re.compile(r"^(?P<city>.*?)\s*(?:[-–/,]\s*|\s+)(?P<uf>[A-Za-z]{2})\s*\.?$")
_LEADING_NUM_RE = re.compile(r"^\s*(?:n[º°o.]?\s*)?(\d{1,6}[A-Za-z]?)\b")
_TRAILING_NUM_RE = re.compile(r"^(?P<street>.*?\D)[\s,]+(?:n[º°o.]?\s*)?(?P<num>\d{1,6}[A-Za-z]?)$")


def address_from_keyword(value: Any) -> str | None:
    """Address text of an explicit address-style keyword ('address: ...'), else None (FC3)."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    low = s.lower()
    for prefix in ADDRESS_KEYWORD_PREFIXES:
        if low.startswith(prefix):
            rest = s[len(prefix):].strip()
            return rest[:300] or None
    return None


def _part_is_street(part: str) -> bool:
    low = fold(part).strip()
    return any(low == w.rstrip(".") or low.startswith(w + " ") or low.startswith(w.rstrip(".") + " ")
               for w in _STREET_WORDS)


def _clean_city(city: str) -> str | None:
    c = city.split(" - ")[-1].strip(" -–/") if " - " in city else city.strip(" -–/")
    return c or None


def parse_br_address(text: Any) -> dict[str, Any] | None:
    """Split a Brazilian address into ``{street, number, city, uf, cep, raw}`` (heuristic; never raises)."""
    if not isinstance(text, str):
        return None
    raw = " ".join(text.split())[:300]
    if not raw:
        return None
    out: dict[str, Any] = {"street": None, "number": None, "city": None, "uf": None, "cep": None, "raw": raw}
    s = raw
    m = _CEP_IN_TEXT_RE.search(s)
    if m:
        out["cep"] = normalize_cep(m.group(1) + m.group(2))
        s = s[:m.start()] + s[m.end():]
    s = re.sub(r"\bCEP\b[:.]?", " ", s, flags=re.I)
    parts = [p.strip(" .;") for p in s.split(",")]
    parts = [p for p in parts if p]
    for idx in range(len(parts) - 1, -1, -1):
        part = parts[idx]
        if part.upper() in UF_NAMES:
            out["uf"] = part.upper()
            if idx > 0 and not _part_is_street(parts[idx - 1]):
                out["city"] = _clean_city(parts[idx - 1])
            parts = parts[:idx]
            break
        mt = _UF_TAIL_RE.match(part)
        if mt and mt.group("uf").upper() in UF_NAMES and mt.group("city").strip():
            out["uf"] = mt.group("uf").upper()
            city = mt.group("city").strip(" -–/")
            if _part_is_street(city) and idx == 0:
                break
            out["city"] = _clean_city(city)
            parts = parts[:idx]
            break
    if parts:
        first = parts[0]
        if " - " in first:
            first = first.split(" - ", 1)[0].strip()
        if _part_is_street(first) or _TRAILING_NUM_RE.match(first):
            mt = _TRAILING_NUM_RE.match(first)
            if mt and _part_is_street(mt.group("street").strip()):
                out["street"], out["number"] = mt.group("street").strip(" ,"), mt.group("num")
            else:
                out["street"] = first
            if out["number"] is None and len(parts) > 1:
                mn = _LEADING_NUM_RE.match(parts[1])
                if mn:
                    out["number"] = mn.group(1)
        elif out["city"] is None and len(parts) == 1:
            out["city"] = _clean_city(first)
    return out


def build_nominatim_search_attempts(addr: Any, limit: int = 1) -> list[dict[str, Any]]:
    """Ordered structured attempts street -> postal code -> city (FC3), Brazil only, jsonv2, small limit."""
    if not isinstance(addr, dict):
        return []
    base = {"countrycodes": "br", "format": "jsonv2", "addressdetails": "1", "limit": str(max(1, min(int(limit), 5)))}
    out: list[dict[str, Any]] = []
    street, number = addr.get("street"), addr.get("number")
    city, uf, cep = addr.get("city"), addr.get("uf"), normalize_cep(addr.get("cep"))
    if street:
        p = dict(base, street=f"{number} {street}" if number else street)
        if city:
            p["city"] = city
        if uf:
            p["state"] = uf
        if cep:
            p["postalcode"] = cep
        out.append({"precision": "street", "params": p})
    if cep:
        out.append({"precision": "postcode", "params": dict(base, postalcode=cep)})
    if city:
        p = dict(base, city=city)
        if uf:
            p["state"] = uf
        out.append({"precision": "city", "params": p})
    return out


def build_nominatim_reverse_params(coords: Any, zoom: int = 18) -> dict[str, str]:
    """Params for /reverse; raises ValueError for invalid or 0,0 coordinates (never sent)."""
    c = normalize_coordinates(coords) if not isinstance(coords, dict) else coords
    if not c or c.get("null_island"):
        raise ValueError("invalid or null-island coordinates are never sent")
    return {"lat": f"{c['lat']:.6f}", "lon": f"{c['lon']:.6f}", "format": "jsonv2", "zoom": str(int(zoom)),
            "addressdetails": "1"}


def build_photon_search_params(query: str, limit: int = 5, lang: str = "en") -> dict[str, str]:
    if not isinstance(query, str) or not query.strip():
        raise ValueError("empty query")
    return {"q": " ".join(query.split())[:300], "limit": str(max(1, min(int(limit), 10))), "lang": lang}


def build_photon_reverse_params(coords: Any, lang: str = "en") -> dict[str, str]:
    c = normalize_coordinates(coords) if not isinstance(coords, dict) else coords
    if not c or c.get("null_island"):
        raise ValueError("invalid or null-island coordinates are never sent")
    return {"lat": f"{c['lat']:.6f}", "lon": f"{c['lon']:.6f}", "limit": "1", "lang": lang}


def photon_query_from_address(addr: Any) -> str | None:
    """'street number, city UF' when a street is known, else the CEP, else 'city UF' (FC2/FC3)."""
    if not isinstance(addr, dict):
        return None
    street, number, city, uf = addr.get("street"), addr.get("number"), addr.get("city"), addr.get("uf")
    cep = normalize_cep(addr.get("cep"))
    tail = " ".join(x for x in (city, uf) if isinstance(x, str) and x)
    if isinstance(street, str) and street:
        head = f"{street} {number}" if number else street
        return ", ".join(x for x in (head, tail) if x)[:300]
    if cep:
        return cep
    return tail[:300] or None


def keep_country(places: Any, country_code: str = "BR") -> list[dict[str, Any]]:
    """Photon search is global: a Brazilian seed must not resolve to a homonymous street abroad."""
    cc = country_code.upper()
    return [p for p in (places or []) if isinstance(p, dict) and (p.get("address") or {}).get("country_code") == cc]


def _osm_url(osm_type: Any, osm_id: Any) -> str | None:
    t = _OSM_TYPES.get(osm_type) if isinstance(osm_type, str) else None
    if t is None or isinstance(osm_id, bool) or not isinstance(osm_id, int) or osm_id <= 0:
        return None
    return f"https://www.openstreetmap.org/{t}/{osm_id}"


def _state_code(state: Any = None, iso_lvl4: Any = None) -> str | None:
    if isinstance(iso_lvl4, str) and iso_lvl4.upper().startswith("BR-") and iso_lvl4[3:].upper() in UF_NAMES:
        return iso_lvl4[3:].upper()
    if isinstance(state, str):
        return _UF_BY_FOLDED_NAME.get(fold(state).strip())
    return None


def precision_from_rank(place_rank: Any, addresstype: Any = None, osm_type_value: Any = None) -> str:
    """postcode objects -> 'postcode'; rank >= 26 -> 'street'; 13..25 -> 'city'; lower -> 'region'."""
    if addresstype == "postcode" or osm_type_value == "postcode":
        return "postcode"
    if isinstance(place_rank, bool) or not isinstance(place_rank, int):
        return "region"
    if place_rank >= 26:
        return "street"
    if place_rank >= 13:
        return "city"
    return "region"


def _first_str(d: dict[str, Any], *keys: str) -> str | None:
    return next((d[k] for k in keys if isinstance(d.get(k), str) and d.get(k)), None)


def _address_from_nominatim(addr: Any) -> dict[str, Any]:
    if not isinstance(addr, dict):
        return {}
    cc = addr.get("country_code")
    out = {
        "road": _first_str(addr, "road", "pedestrian", "footway", "street"),
        "house_number": _first_str(addr, "house_number"),
        "suburb": _first_str(addr, "suburb", "neighbourhood", "quarter", "city_district"),
        "city": _first_str(addr, "city", "town", "village", "municipality", "hamlet"),
        "state": _first_str(addr, "state"),
        "state_code": _state_code(addr.get("state"), addr.get("ISO3166-2-lvl4")),
        "postcode": normalize_cep(addr.get("postcode")) or _first_str(addr, "postcode"),
        "country": _first_str(addr, "country"),
        "country_code": cc.upper() if isinstance(cc, str) and cc else None,
    }
    return {k: v for k, v in out.items() if v}


def parse_nominatim_place(obj: Any) -> dict[str, Any] | None:
    """Normalise one Nominatim jsonv2 place (a search item or a reverse answer), or None."""
    if not isinstance(obj, dict):
        return None
    c = coord_result(_num(obj.get("lat")), _num(obj.get("lon")))
    if c is None:
        return None
    osm_type = _OSM_TYPES.get(obj.get("osm_type")) if isinstance(obj.get("osm_type"), str) else None
    osm_id = obj.get("osm_id") if isinstance(obj.get("osm_id"), int) and not isinstance(obj.get("osm_id"), bool) else None
    rank = obj.get("place_rank") if isinstance(obj.get("place_rank"), int) and not isinstance(obj.get("place_rank"), bool) else None
    return {
        "provider": "nominatim", "lat": c["lat"], "lon": c["lon"],
        "display_name": _first_str(obj, "display_name"), "name": _first_str(obj, "name"),
        "category": _first_str(obj, "category", "class"), "type": _first_str(obj, "type"),
        "osm_type": osm_type, "osm_id": osm_id, "osm_url": _osm_url(osm_type, osm_id),
        "address": _address_from_nominatim(obj.get("address")),
        "precision": precision_from_rank(rank, obj.get("addresstype"), obj.get("type")),
    }


def parse_nominatim_search(obj: Any) -> list[dict[str, Any]]:
    if not isinstance(obj, list):
        return []
    return [p for p in (parse_nominatim_place(o) for o in obj[:50]) if p]


def precision_from_photon(props: Any) -> str:
    if not isinstance(props, dict):
        return "region"
    if props.get("osm_key") == "place" and props.get("osm_value") == "postcode":
        return "postcode"
    t = props.get("type")
    if t in ("house", "street"):
        return "street"
    if t in ("locality", "district", "city"):
        return "city"
    if t == "other" and props.get("postcode"):
        return "postcode"
    return "region"


def parse_photon(obj: Any) -> list[dict[str, Any]]:
    """Places of a Photon FeatureCollection ([lon, lat] swapped; one entry per OSM object)."""
    if not isinstance(obj, dict) or not isinstance(obj.get("features"), list):
        return []
    out: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for feat in obj["features"][:50]:
        if not isinstance(feat, dict):
            continue
        geom = feat.get("geometry") if isinstance(feat.get("geometry"), dict) else {}
        coords = geom.get("coordinates")
        if not (isinstance(coords, list) and len(coords) >= 2):
            continue
        c = coord_result(_num(coords[1]), _num(coords[0]))  # Photon: [lon, lat]
        if c is None:
            continue
        props = feat.get("properties") if isinstance(feat.get("properties"), dict) else {}
        osm_type = _OSM_TYPES.get(props.get("osm_type")) if isinstance(props.get("osm_type"), str) else None
        osm_id = props.get("osm_id") if isinstance(props.get("osm_id"), int) and not isinstance(props.get("osm_id"), bool) else None
        key = (osm_type, osm_id) if osm_id is not None else (c["key"], props.get("name"))
        if key in seen:
            continue
        seen.add(key)

        def s(k: str, props: dict[str, Any] = props) -> str | None:
            v = props.get(k)
            return v if isinstance(v, str) and v else None

        cc = s("countrycode")
        address = {
            "road": s("street") or (s("name") if props.get("type") == "street" else None),
            "house_number": s("housenumber"),
            "suburb": s("locality") or s("district"),
            "city": s("city"), "state": s("state"), "state_code": _state_code(props.get("state")),
            "postcode": normalize_cep(props.get("postcode")) or s("postcode"),
            "country": s("country"), "country_code": cc.upper() if cc else None,
        }
        if props.get("osm_key") == "place" and props.get("osm_value") == "postcode" and not address["postcode"]:
            address["postcode"] = normalize_cep(props.get("name"))
        out.append({
            "provider": "photon", "lat": c["lat"], "lon": c["lon"],
            "display_name": ", ".join(x for x in (s("name"), s("street"), s("housenumber"), s("district"), s("city"),
                                                  s("state"), s("postcode"), s("country")) if x) or None,
            "name": s("name"), "category": s("osm_key"), "type": s("osm_value"),
            "osm_type": osm_type, "osm_id": osm_id, "osm_url": _osm_url(osm_type, osm_id),
            "address": {k: v for k, v in address.items() if v},
            "precision": precision_from_photon(props),
        })
    return out


def geocode_record(place: dict[str, Any], direction: str, attempt_precision: str | None = None) -> dict[str, Any]:
    """The labelled record of FC6: label, precision, disclaimer, attribution and the place itself."""
    precision = attempt_precision if (direction == "forward" and attempt_precision in PRECISION_LEVELS) \
        else str(place.get("precision") or "region")
    return {
        "label": GEO_LABEL, "precision": precision, "disclaimer": GEO_DISCLAIMER, "attribution": OSM_ATTRIBUTION,
        "direction": direction, "provider": place.get("provider"), "lat": place.get("lat"), "lon": place.get("lon"),
        "display_name": place.get("display_name"), "osm_url": place.get("osm_url"),
        "address": dict(place.get("address") or {}),
    }


def export_view(attributes: dict[str, Any], case_opt_in: bool = False) -> dict[str, Any]:
    """FC6: the attributes a STIX/MISP export may carry. A place whose ``geo_export_allowed`` is False (reverse
    geocoding of coordinates, typed addresses) keeps only the precision, label and attribution unless the analyst
    opted in for the case (the exporters call it; core request)."""
    if case_opt_in or attributes.get("geo_export_allowed") is not False:
        return dict(attributes)
    return {k: v for k, v in attributes.items() if k not in PRIVACY_ATTRIBUTES}


# ======================================================================================================
# source calls: every failure is kept per source (rule 5); Photon is the only fallback (FC2)
# ======================================================================================================

class _Failure:
    """A source that could not answer: status + canonical reason code + readable reason."""

    def __init__(self, source: str, status: Status, reason_code: str, reason: str) -> None:
        self.source, self.status, self.reason_code, self.reason = source, status, reason_code, reason[:300]


def _failure_from(source: str, label: str, exc: BaseException) -> _Failure:
    if isinstance(exc, ConfigError):
        return _Failure(source, Status.SKIPPED, "config",
                        f"{label} needs the contact_email role mailbox for its identifying User-Agent (OSMF usage "
                        "policy): v3lum config set contact_email <role mailbox>")
    if isinstance(exc, Blocked):
        code = str(getattr(exc, "reason_code", "") or "challenge")
        return _Failure(source, Status.BLOCKED, code, f"{label}: {exc} - could not verify")
    if isinstance(exc, AuthRequired):
        return _Failure(source, Status.BLOCKED, "challenge", f"{label}: access refused (HTTP 401/403) - could not verify")
    if isinstance(exc, RateLimited):
        return _Failure(source, Status.RATE_LIMITED, "rate_limited", f"{label}: rate limited - could not verify")
    if isinstance(exc, QuotaExceeded):
        return _Failure(source, Status.QUOTA, "quota", f"{label}: quota exhausted - could not verify")
    if isinstance(exc, OfflineError):
        return _Failure(source, Status.UNAVAILABLE, "offline", f"{label}: offline mode - could not verify")
    if isinstance(exc, DeadlineExceeded):
        return _Failure(source, Status.ERROR, "timeout", f"{label}: deadline reached - could not verify")
    return _Failure(source, Status.ERROR, "error", f"{label}: {str(exc)[:160] or type(exc).__name__} - could not verify")


_HANDLED = (ConfigError, Blocked, AuthRequired, RateLimited, QuotaExceeded, OfflineError, DeadlineExceeded,
            HttpError, NetworkError)


def _call(ctx: Any, url: str, params: dict[str, str], source: str, label: str) -> tuple[Any, _Failure | None]:
    """GET + JSON with the core's classification; returns (parsed JSON, None) or (None, failure).

    RequestCapReached, Cancelled and PolicyError propagate (partial result / policy refusal, engine-mapped)."""
    try:
        resp = ctx.http.get(url, params=params, source=source, ttl=CACHE_TTL)
        if resp.status == 629 or (resp.status >= 400 and "varnish" in (resp.text or "")[:4096].lower()):
            # CDN edge refusal seen live (HTTP 629, Varnish synthetic page, Retry-After: 0): not retried
            return None, _Failure(source, Status.RATE_LIMITED, "rate_limited",
                                  f"{label}: CDN edge refusal (HTTP {resp.status}) - could not verify, not retried this run")
        ctx.http.check(resp)
        try:
            return resp.json(), None
        except ValueError:
            ctx.http.evict(resp)
            kind = "HTML" if (resp.text or "").lstrip()[:1] == "<" else "malformed JSON"
            return None, _Failure(source, Status.ERROR, "error", f"{label} answered {kind} instead of JSON - could not verify")
    except _HANDLED as exc:
        return None, _failure_from(source, label, exc)


def _nominatim_answer(obj: Any) -> tuple[list[dict[str, Any]], str | None]:
    """(places, problem) of a Nominatim body: problem 'absent' for [] / 'Unable to geocode', else an error text."""
    if isinstance(obj, list):
        places = parse_nominatim_search(obj)
        if not obj:
            return [], "absent"
        return (places, None) if places else ([], "unexpected Nominatim answer (no usable place)")
    if isinstance(obj, dict):
        err = obj.get("error")
        if isinstance(err, str) and "unable to geocode" in err.lower():
            return [], "absent"
        if err is not None:
            msg = err.get("message") if isinstance(err, dict) else err
            return [], f"Nominatim error: {str(msg)[:160]}"
        place = parse_nominatim_place(obj)
        return ([place], None) if place else ([], "unexpected Nominatim answer")
    return [], "unexpected Nominatim answer"


def _photon_answer(obj: Any, country: str | None) -> tuple[list[dict[str, Any]], str | None]:
    if not isinstance(obj, dict) or not isinstance(obj.get("features"), list):
        return [], "unexpected Photon answer"
    if not obj["features"]:
        return [], "absent"
    places = parse_photon(obj)
    if country:
        places = keep_country(places, country)
    return (places, None) if places else ([], "absent")


# ======================================================================================================
# the module
# ======================================================================================================

@register
class Geocoding(Module):
    name = "geocoding"
    title = "Geocoding (Nominatim, Photon fallback)"
    description = ("Approximate place (OSM) of typed coordinates, CEPs and 'address:' keywords through Nominatim (OSMF) "
                   "with Photon (komoot) as the only fallback; precision street/postcode/city, never proof of residence.")
    category = "geo_image_meta"
    accepts = {T.COORDINATES, T.CEP, T.KEYWORD}
    produces = {T.COORDINATES, T.CEP}
    tags = {"brazil"}
    reference = "https://operations.osmfoundation.org/policies/nominatim/"
    notice = ("OSM data (c) OpenStreetMap contributors, ODbL 1.0: every place is an approximate place, never proof of "
              "residence. Coordinates are personal data: only analyst-typed seeds are geocoded, with a recorded purpose.")
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = (NOMINATIM_HOST, PHOTON_HOST)
    provider = "osmf_nominatim"
    sources = (NOMINATIM_SOURCE, PHOTON_SOURCE)
    access_model = "free_noauth_limited"
    run_on = "seeds"
    max_requests = 4  # 3 structured Nominatim attempts + 1 Photon fallback
    expected_latency = 1.5
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = CACHE_TTL
    max_pivots = 10
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.KEYWORD:
            return address_from_keyword(entity.value) is not None  # FC3: explicit address TYPE:value only
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not bool(getattr(ctx, "is_seed", True)):
            # FC4: pivots (EXIF GPS, devices, text, company records) need a per-entity analyst confirmation
            return res.mark(Status.SKIPPED, "only analyst-typed seeds are geocoded; confirm this entity by running it "
                            "as a typed seed (v3lum run geocoding <type>:<value>)", reason_code="privacy")
        if entity.type is T.COORDINATES:
            return self._reverse(entity, ctx, res)
        if entity.type is T.CEP:
            cep = normalize_cep(entity.value)
            if cep is None:
                return res.mark(Status.SKIPPED, "not a usable CEP", reason_code="not_applicable")
            addr = {"street": None, "number": None, "city": None, "uf": None, "cep": cep, "raw": cep}
            return self._forward(entity, ctx, res, addr, origin="seed_cep")
        text = address_from_keyword(entity.value)
        addr = parse_br_address(text)
        if not addr or not (addr.get("street") or addr.get("cep") or addr.get("city")):
            return res.mark(Status.SKIPPED, "address keyword without a street, CEP or city: nothing to geocode",
                            reason_code="not_applicable")
        return self._forward(entity, ctx, res, addr, origin="seed_address")

    # ------------------------------------------------------------------ forward (address / CEP -> place)
    def _forward(self, entity: Entity, ctx: Any, res: ModuleResult, addr: dict[str, Any], origin: str) -> ModuleResult:
        failures: list[_Failure] = []
        tried: list[dict[str, Any]] = []
        nominatim_absent = False
        for attempt in build_nominatim_search_attempts(addr):
            obj, fail = _call(ctx, NOMINATIM_SEARCH, attempt["params"], NOMINATIM_SOURCE, "Nominatim")
            tried.append({"provider": "nominatim", "precision": attempt["precision"],
                          "outcome": fail.status.value if fail else "answered"})
            if fail is not None:
                failures.append(fail)
                break  # stop the chain on any failure (FC1: no retries with other parameters)
            places, problem = _nominatim_answer(obj)
            if problem == "absent":
                tried[-1]["outcome"] = "no match"
                nominatim_absent = True
                continue
            if problem:
                failures.append(_Failure(NOMINATIM_SOURCE, Status.ERROR, "error", f"{problem} - could not verify"))
                break
            return self._emit(entity, res, places[0], "forward", attempt["precision"], origin, tried, failures)
        # FC2: Photon is the only fallback
        query = photon_query_from_address(addr)
        if query:
            obj, fail = _call(ctx, PHOTON_SEARCH, build_photon_search_params(query), PHOTON_SOURCE, "Photon")
            tried.append({"provider": "photon", "precision": "best", "outcome": fail.status.value if fail else "answered"})
            if fail is not None:
                failures.append(fail)
            else:
                places, problem = _photon_answer(obj, "BR")
                if problem == "absent":
                    tried[-1]["outcome"] = "no match"
                    return self._absent(res, tried, failures, nominatim_absent=nominatim_absent, photon_absent=True)
                if problem:
                    failures.append(_Failure(PHOTON_SOURCE, Status.ERROR, "error", f"{problem} - could not verify"))
                else:
                    best = places[0]
                    precision = best.get("precision")
                    return self._emit(entity, res, best, "forward", precision, origin, tried, failures)
        return self._absent(res, tried, failures, nominatim_absent=nominatim_absent, photon_absent=False)

    # ------------------------------------------------------------------ reverse (coordinates -> place)
    def _reverse(self, entity: Entity, ctx: Any, res: ModuleResult) -> ModuleResult:
        coords = normalize_coordinates(entity.value)
        if coords is None:
            return res.mark(Status.SKIPPED, "not usable coordinates", reason_code="not_applicable")
        if coords["null_island"]:
            # 0,0 is a common EXIF/device default: never worth a provider request
            return res.mark(Status.SKIPPED, "0,0 ('null island') is a default value, not a place: not sent",
                            reason_code="not_applicable")
        failures: list[_Failure] = []
        tried: list[dict[str, Any]] = []
        obj, fail = _call(ctx, NOMINATIM_REVERSE, build_nominatim_reverse_params(coords), NOMINATIM_SOURCE, "Nominatim")
        nominatim_absent = False
        if fail is not None:
            failures.append(fail)
            tried.append({"provider": "nominatim", "outcome": fail.status.value})
        else:
            places, problem = _nominatim_answer(obj)
            tried.append({"provider": "nominatim", "outcome": "no match" if problem == "absent" else "answered"})
            if problem is None:
                return self._emit(entity, res, places[0], "reverse", None, "seed", tried, failures)
            if problem == "absent":
                nominatim_absent = True
            else:
                failures.append(_Failure(NOMINATIM_SOURCE, Status.ERROR, "error", f"{problem} - could not verify"))
        obj, fail = _call(ctx, PHOTON_REVERSE, build_photon_reverse_params(coords), PHOTON_SOURCE, "Photon")
        if fail is not None:
            failures.append(fail)
            tried.append({"provider": "photon", "outcome": fail.status.value})
            return self._absent(res, tried, failures, nominatim_absent=nominatim_absent, photon_absent=False)
        places, problem = _photon_answer(obj, None)
        tried.append({"provider": "photon", "outcome": "no match" if problem == "absent" else "answered"})
        if problem is None:
            return self._emit(entity, res, places[0], "reverse", None, "seed", tried, failures)
        if problem != "absent":
            failures.append(_Failure(PHOTON_SOURCE, Status.ERROR, "error", f"{problem} - could not verify"))
        return self._absent(res, tried, failures, nominatim_absent=nominatim_absent, photon_absent=problem == "absent")

    # ------------------------------------------------------------------ results
    def _report_failures(self, res: ModuleResult, failures: list[_Failure]) -> None:
        for f in failures:
            res.source_status(f.source, f.status, reason_code=f.reason_code, reason=f.reason)

    def _emit(self, entity: Entity, res: ModuleResult, place: dict[str, Any], direction: str, precision: Any,
              origin: str, tried: list[dict[str, Any]], failures: list[_Failure]) -> ModuleResult:
        self._report_failures(res, failures)
        rec = geocode_record(place, direction, precision if isinstance(precision, str) else None)
        export_allowed = False  # FC6: reverse places and typed addresses may locate a person
        source = NOMINATIM_SOURCE if rec["provider"] == "nominatim" else PHOTON_SOURCE
        res.raw = {"direction": direction, "origin": origin, "attempts": tried, "place": rec}
        res.attr("geo_place", rec)
        res.attr("geo_label", GEO_LABEL)
        res.attr("geo_precision", rec["precision"])
        res.attr("geo_disclaimer", GEO_DISCLAIMER)
        res.attr("geo_attribution", OSM_ATTRIBUTION)
        res.attr("geo_provider", rec["provider"])
        res.attr("geo_direction", direction)
        res.attr("geo_display_name", rec.get("display_name"))
        res.attr("geo_osm_url", rec.get("osm_url"))
        res.attr("geo_address", rec.get("address"))
        res.attr("geo_export_allowed", export_allowed)
        address = rec.get("address") or {}
        res.attr("city", address.get("city"))
        if isinstance(address.get("country_code"), str) and len(address["country_code"]) == 2:
            res.attr("country", address["country_code"])
        where = rec.get("display_name") or f"{rec['lat']:.6f},{rec['lon']:.6f}"
        via = "Nominatim (OSMF)" if rec["provider"] == "nominatim" else "Photon (komoot, fallback)"
        res.finding(
            f"Approximate place (OSM), precision {rec['precision']}",
            "info",
            f"{where} - {GEO_LABEL}, precision {rec['precision']}, via {via}; {GEO_DISCLAIMER}. {OSM_ATTRIBUTION}.",
            confidence="possible",
            criterion=f"{direction} geocoding over OpenStreetMap data, {rec['precision']} precision ({GEO_DISCLAIMER})",
            data={"precision": rec["precision"], "provider": rec["provider"], "direction": direction},
            tags=["info", "privacy"],
            source=source,
        )
        if direction == "forward":
            res.pivot(T.COORDINATES, f"{rec['lat']:.6f},{rec['lon']:.6f}", "located_at", confidence="possible",
                      expand=False, note=PIVOT_NOTE)
        cep = normalize_cep(address.get("postcode")) if address.get("country_code") in (None, "BR") else None
        if cep and _digits(cep) != _digits(entity.value):
            res.pivot(T.CEP, cep, "located_at", confidence="possible", expand=False, note=PIVOT_NOTE)
        return res

    def _absent(self, res: ModuleResult, tried: list[dict[str, Any]], failures: list[_Failure], *,
                nominatim_absent: bool, photon_absent: bool) -> ModuleResult:
        self._report_failures(res, failures)
        res.raw = {"attempts": tried}
        answered_absent = nominatim_absent or photon_absent
        if answered_absent:
            # a source answered 'no match': EMPTY, with the sources that could not verify listed per source
            note = "no OSM match (not proof that the address or place does not exist)"
            if failures:
                note += "; " + "; ".join(f.reason for f in failures)
            return res.mark(Status.EMPTY, note[:500])
        real = [f for f in failures if f.status is not Status.SKIPPED] or failures
        if not real:
            return res.mark(Status.ERROR, "no geocoder could be queried - could not verify")
        first = real[0]
        reason = "; ".join(f.reason for f in failures)[:500]
        return res.mark(first.status, reason, reason_code=first.reason_code)
