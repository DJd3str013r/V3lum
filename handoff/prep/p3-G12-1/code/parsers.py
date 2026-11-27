"""Pure parsers, builders, gates and marker helpers for batch p3-G12-1 (group G12 files_geo_media).

Modules served: geocoding (P262), image_ela (P264), document_identity_signals (P273),
user_agent_analysis (P317), card_bin (P318), imei_check (P319).

Rules for this file:
- Standard library only, no V3LUM imports, no network, no file writes, no clock reads
  (the ReDoS timing helper is the one exception: it measures elapsed time with perf_counter).
- Parsers accept raw bodies as ``bytes``/``str``/parsed JSON and never raise on missing fields,
  wrong types or HTML instead of JSON: they return None/empty values and the ``*_marker``
  helpers say why. Request builders are the exception: they raise ValueError for a request that
  must never be built (a key in a URL, more than the BIN or the TAC leaving the host, an
  out-of-range coordinate).
- Docstrings name the final condition served as ``P<id>-FC<n>`` (council final conditions in
  specs/p3-G12-1.md) or the common rule (A1-A16, AR01, AR24, P321, P326, P334).

Marker convention (same as the other prep batches): helpers return ``None`` (normal answer) or
``'<kind>: <reason>'``; ``marker_kind()`` extracts the kind and ``marker_status()`` maps it to
the V3LUM Status and canonical reason_code (A3 BR16-17). ``absent`` is a declared meaningful
absence (Status.EMPTY with the module's own wording), never an error. ``skipped: <code>: ...``
carries a canonical SKIPPED reason_code (not_applicable, privacy, config, policy).
"""
from __future__ import annotations

import base64
import binascii
import bisect
import json
import math
import re
import statistics
import time
import unicodedata

# ---------------------------------------------------------------------------------------
# 0. Generic helpers (bodies, markers, folding, Luhn)
# ---------------------------------------------------------------------------------------

MARKER_KINDS = {
    # kind: (Status name, canonical reason_code or None = core default / taken from the reason)
    "absent": ("EMPTY", None),
    "error": ("ERROR", "error"),
    "rate_limited": ("RATE_LIMITED", "rate_limited"),
    "quota": ("QUOTA", "quota"),
    "blocked": ("BLOCKED", None),
    "needs_key": ("NEEDS_KEY", "needs_key"),
    "skipped": ("SKIPPED", None),
}

BLOCKED_REASON_CODES = ("challenge", "login_wall", "geo_block", "circuit", "hostile_host")
SKIPPED_REASON_CODES = ("not_applicable", "privacy", "config", "policy", "own_asset", "not_default")


def marker_kind(marker):
    """Return the kind of a ``'<kind>: <reason>'`` marker string, or None (A3 BR16-17)."""
    if not isinstance(marker, str) or ":" not in marker:
        return None
    kind = marker.split(":", 1)[0].strip()
    return kind if kind in MARKER_KINDS else None


def marker_status(marker):
    """Map a marker to ``(status, reason_code)`` with the canonical A3 codes.

    BLOCKED markers whose reason starts with a canonical BLOCKED code (challenge, login_wall,
    geo_block, circuit, hostile_host) get that code; other BLOCKED markers (plain 403 policy
    pages) keep the core default (P321 FC7). SKIPPED markers must start with a canonical
    SKIPPED code. Returns ``(None, None)`` for None or an unknown kind.
    """
    kind = marker_kind(marker)
    if kind is None:
        return (None, None)
    status, code = MARKER_KINDS[kind]
    reason = marker.split(":", 1)[1].strip().lower()
    if kind == "blocked":
        for candidate in BLOCKED_REASON_CODES:
            if reason.startswith(candidate):
                return (status, candidate)
    if kind == "skipped":
        for candidate in SKIPPED_REASON_CODES:
            if reason.startswith(candidate):
                return (status, candidate)
        return (status, "not_applicable")
    return (status, code)


def as_text(body, limit=None):
    """Return ``body`` as text (bytes decoded UTF-8 with replacement, JSON objects dumped)."""
    if body is None:
        text = ""
    elif isinstance(body, (bytes, bytearray, memoryview)):
        text = bytes(body).decode("utf-8", "replace")
    elif isinstance(body, str):
        text = body
    else:
        try:
            text = json.dumps(body, ensure_ascii=False)
        except (TypeError, ValueError):
            text = str(body)
    return text[:limit] if limit else text


def looks_like_html(body):
    """True when the start of ``body`` looks like an HTML/XHTML page (P321: HTML instead of JSON)."""
    head = as_text(body, 2048).lstrip().lower()
    if head.startswith("<?xml") and "<html" in head:
        return True
    return head.startswith("<!doctype html") or head.startswith("<html") or "<html" in head[:512] \
        or "<head>" in head[:512] or "<body" in head[:512]


_TITLE_RE = re.compile(r"<title[^>]{0,200}>([^<]{0,300})</title>", re.I)


def html_title(body):
    """Return the stripped <title> text of an HTML body, or ''."""
    m = _TITLE_RE.search(as_text(body, 65536))
    return " ".join(m.group(1).split()) if m else ""


def load_json(body):
    """Parse ``body`` defensively. Returns ``(obj, problem)``; problem is None or one of
    'empty', 'html', 'malformed'. Already-parsed dict/list values are returned as they are."""
    if isinstance(body, (dict, list)):
        return body, None
    text = as_text(body).strip()
    if not text:
        return None, "empty"
    if looks_like_html(text):
        return None, "html"
    try:
        return json.loads(text), None
    except ValueError:
        return None, "malformed"


def header(headers, name):
    """Case-insensitive header lookup over a dict (or list of pairs); returns str or None."""
    if not headers:
        return None
    items = headers.items() if isinstance(headers, dict) else headers
    lname = name.lower()
    for key, value in items:
        if isinstance(key, str) and key.lower() == lname:
            return value if isinstance(value, str) else str(value)
    return None


def fold(text):
    """Accent-fold and casefold ``text`` keeping its length (one output char per input char),
    so match offsets in the folded text are offsets in the original (P273-FC3)."""
    if not isinstance(text, str):
        return ""
    out = []
    for ch in text:
        if ch.isascii():
            out.append(ch.lower())
            continue
        dec = unicodedata.normalize("NFKD", ch)
        base = "".join(c for c in dec if not unicodedata.combining(c)).casefold()
        out.append(base[:1] if base else " ")
    return "".join(out)


def digits_only(value):
    """Return the ASCII digits of ``value`` (str/int), or '' for other types."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, str):
        return ""
    return "".join(ch for ch in value if "0" <= ch <= "9")


def luhn_valid(number):
    """Luhn check over a digit string (P318-FC1 card numbers, P319-FC1/FC3 IMEIs)."""
    d = digits_only(number)
    if len(d) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def luhn_check_digit(partial):
    """Return the Luhn check digit (str) that completes ``partial`` (digits only)."""
    d = digits_only(partial)
    if not d:
        raise ValueError("no digits")
    for c in "0123456789":
        if luhn_valid(d + c):
            return c
    raise ValueError("unreachable")


# ---------------------------------------------------------------------------------------
# 1. P262 geocoding - Nominatim (OSMF) + Photon (komoot) fallback
# ---------------------------------------------------------------------------------------

NOMINATIM_HOST = "nominatim.openstreetmap.org"
PHOTON_HOST = "photon.komoot.io"
OSM_ATTRIBUTION = "(c) OpenStreetMap contributors (ODbL 1.0)"
GEO_LABEL = "approximate place (OSM)"
GEO_DISCLAIMER = "an address is not proof of residence"
PRECISION_LEVELS = ("street", "postcode", "city", "region")

UF_NAMES = {
    "AC": "Acre", "AL": "Alagoas", "AP": "Amapá", "AM": "Amazonas", "BA": "Bahia",
    "CE": "Ceará", "DF": "Distrito Federal", "ES": "Espírito Santo", "GO": "Goiás",
    "MA": "Maranhão", "MT": "Mato Grosso", "MS": "Mato Grosso do Sul", "MG": "Minas Gerais",
    "PA": "Pará", "PB": "Paraíba", "PR": "Paraná", "PE": "Pernambuco", "PI": "Piauí",
    "RJ": "Rio de Janeiro", "RN": "Rio Grande do Norte", "RS": "Rio Grande do Sul",
    "RO": "Rondônia", "RR": "Roraima", "SC": "Santa Catarina", "SP": "São Paulo",
    "SE": "Sergipe", "TO": "Tocantins",
}
_UF_BY_FOLDED_NAME = {fold(v): k for k, v in UF_NAMES.items()}
_OSM_TYPES = {"N": "node", "W": "way", "R": "relation",
              "node": "node", "way": "way", "relation": "relation"}

_DEC_PAIR_RE = re.compile(r"^\s*([+-]?\d{1,3}(?:\.\d{1,15})?)\s*[,;\s]\s*([+-]?\d{1,3}(?:\.\d{1,15})?)\s*$")
_DMS_RE = re.compile(
    r"(\d{1,3}(?:[.,]\d{1,10})?)\s*[°º]\s*"
    r"(?:(\d{1,2}(?:[.,]\d{1,10})?)\s*['′’]\s*)?"
    r"(?:(\d{1,2}(?:[.,]\d{1,10})?)\s*(?:[\"″”]|'')\s*)?"
    r"([NSEWLOnsewlo])\b")


def _num(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = float(value)
    elif isinstance(value, str):
        try:
            v = float(value.strip().replace(",", ".")) if value.strip() else None
        except ValueError:
            return None
        if v is None:
            return None
    else:
        return None
    return v if math.isfinite(v) else None


def _coord_result(lat, lon):
    if lat is None or lon is None or not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
        return None
    lat, lon = round(lat, 6), round(lon, 6)
    return {"lat": lat, "lon": lon, "key": "%.6f,%.6f" % (lat, lon),
            "null_island": abs(lat) < 1e-6 and abs(lon) < 1e-6}


def normalize_coordinates(value):
    """Normalise a coordinates value to ``{'lat','lon','key','null_island'}`` or None.

    Accepts 'lat,lon' / 'lat lon' decimal strings, DMS strings (23°33'01"S 46°38'02"W, with
    O/L for oeste/leste), (lat, lon) pairs and dicts with lat/lon or latitude/longitude keys.
    Rounds to 6 decimals (~0.1 m) for the query and cache key (P262-FC1 cache 30 days);
    ``null_island`` flags 0,0 (a common EXIF default, never worth a provider request).
    P262-FC3 (coordinates input).
    """
    if isinstance(value, dict):
        lat = _num(value.get("lat", value.get("latitude")))
        lon = _num(value.get("lon", value.get("lng", value.get("longitude"))))
        return _coord_result(lat, lon)
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return _coord_result(_num(value[0]), _num(value[1]))
    if not isinstance(value, str) or len(value) > 200:
        return None
    m = _DEC_PAIR_RE.match(value)
    if m:
        return _coord_result(_num(m.group(1)), _num(m.group(2)))
    parts = _DMS_RE.findall(value)
    if len(parts) == 2:
        vals = {}
        for deg, mins, secs, hemi in parts:
            v = (_num(deg) or 0.0) + (_num(mins) or 0.0) / 60.0 + (_num(secs) or 0.0) / 3600.0
            h = hemi.upper()
            if h in "SWO":
                v = -v
            vals["lat" if h in "NS" else "lon"] = v
        if set(vals) == {"lat", "lon"}:
            return _coord_result(vals["lat"], vals["lon"])
    return None


def normalize_cep(value):
    """Return a CEP as 'NNNNN-NNN' (8 digits) or None; '00000-000' is rejected (P262-FC3)."""
    d = digits_only(value)
    if len(d) != 8 or d == "00000000":
        return None
    return "%s-%s" % (d[:5], d[5:])


ADDRESS_KEYWORD_PREFIXES = ("address:", "endereco:", "endereço:", "addr:")
_STREET_WORDS = ("rua", "r.", "avenida", "av.", "av", "alameda", "al.", "travessa", "tv.", "praca",
                 "pca", "rodovia", "rod.", "estrada", "estr.", "largo", "viela", "quadra", "saun",
                 "sain", "sbs", "scs", "shn", "shs", "sqn", "sqs", "setor", "via", "beco", "ladeira",
                 "parque", "vila", "conjunto", "passagem", "servidao")
_CEP_IN_TEXT_RE = re.compile(r"(?<!\d)(\d{5})-?(\d{3})(?!\d)")
_UF_TAIL_RE = re.compile(r"^(?P<city>.*?)\s*(?:[-–/,]\s*|\s+)(?P<uf>[A-Za-z]{2})\s*\.?$")
_LEADING_NUM_RE = re.compile(r"^\s*(?:n[º°o.]?\s*)?(\d{1,6}[A-Za-z]?)\b")
_TRAILING_NUM_RE = re.compile(r"^(?P<street>.*?\D)[\s,]+(?:n[º°o.]?\s*)?(?P<num>\d{1,6}[A-Za-z]?)$")


def address_from_keyword(value):
    """Return the address text of an explicit address-style TYPE:value keyword, else None.

    P262-FC3: keyword input is accepted only as an explicit 'address:'/'endereco:' value; bare
    keywords and pasted text (text_blob) are never geocoded.
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    low = s.lower()
    for p in ADDRESS_KEYWORD_PREFIXES:
        if low.startswith(p):
            rest = s[len(p):].strip()
            return rest[:300] or None
    return None


def parse_br_address(text):
    """Split a Brazilian address into ``{street, number, city, uf, cep, raw}`` (heuristic).

    Used to build the structured Nominatim attempts street -> postal code -> city (P262-FC3).
    Unknown parts are None; never raises.
    """
    if not isinstance(text, str):
        return None
    raw = " ".join(text.split())[:300]
    if not raw:
        return None
    out = {"street": None, "number": None, "city": None, "uf": None, "cep": None, "raw": raw}
    s = raw
    m = _CEP_IN_TEXT_RE.search(s)
    if m:
        out["cep"] = normalize_cep(m.group(1) + m.group(2))
        s = s[:m.start()] + s[m.end():]
    s = re.sub(r"\bCEP\b[:.]?", " ", s, flags=re.I)
    parts = [p.strip(" .;") for p in s.split(",")]
    parts = [p for p in parts if p]
    # UF + city: scan from the end for 'City - UF', 'City/UF' or a bare 'UF' part
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


def _part_is_street(part):
    low = fold(part).strip()
    return any(low == w.rstrip(".") or low.startswith(w + " ") or low.startswith(w.rstrip(".") + " ")
               for w in _STREET_WORDS)


def _clean_city(city):
    c = city.split(" - ")[-1].strip(" -–/") if " - " in city else city.strip(" -–/")
    return c or None


def build_nominatim_search_attempts(addr, limit=1):
    """Ordered structured-search attempts street -> postal code -> city (P262-FC3, FC1).

    Each item is ``{'precision': 'street'|'postcode'|'city', 'params': {...}}`` for
    GET https://nominatim.openstreetmap.org/search. Brazil only (countrycodes=br), jsonv2,
    addressdetails=1, small limit (no bulk geocoding, P262-FC1). The caller stops at the first
    attempt that returns a place, and stops the chain on any marker other than 'absent'.
    """
    if not isinstance(addr, dict):
        return []
    base = {"countrycodes": "br", "format": "jsonv2", "addressdetails": "1",
            "limit": str(max(1, min(int(limit), 5)))}
    out = []
    street, number = addr.get("street"), addr.get("number")
    city, uf, cep = addr.get("city"), addr.get("uf"), normalize_cep(addr.get("cep"))
    if street:
        p = dict(base, street=("%s %s" % (number, street)) if number else street)
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


def build_nominatim_reverse_params(coords, zoom=18):
    """Params for GET https://nominatim.openstreetmap.org/reverse (P262-FC1/FC4).

    Raises ValueError for invalid coordinates or 0,0 (never sent to a provider).
    """
    c = normalize_coordinates(coords)
    if c is None or c["null_island"]:
        raise ValueError("invalid or null-island coordinates are never sent")
    return {"lat": "%.6f" % c["lat"], "lon": "%.6f" % c["lon"], "format": "jsonv2",
            "zoom": str(int(zoom)), "addressdetails": "1"}


def build_photon_search_params(query, limit=5, lang="en"):
    """Params for GET https://photon.komoot.io/api/ (P262-FC2 fallback)."""
    if not isinstance(query, str) or not query.strip():
        raise ValueError("empty query")
    return {"q": " ".join(query.split())[:300], "limit": str(max(1, min(int(limit), 10))), "lang": lang}


def build_photon_reverse_params(coords, lang="en"):
    """Params for GET https://photon.komoot.io/reverse (P262-FC2 fallback)."""
    c = normalize_coordinates(coords)
    if c is None or c["null_island"]:
        raise ValueError("invalid or null-island coordinates are never sent")
    return {"lat": "%.6f" % c["lat"], "lon": "%.6f" % c["lon"], "limit": "1", "lang": lang}


def nominatim_user_agent(base_ua, contact_email):
    """Identifying UA for OSM hosts only: '<base_ua> (contact: <role mailbox>)' (P262-FC1, P326 FC3/FC4).

    Returns None when contact_email is empty or not a mailbox -> the caller reports SKIPPED
    reason_code 'config' for Nominatim (Photon still runs as the fallback).
    """
    if not isinstance(contact_email, str) or not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z]{2,24}",
                                                              contact_email.strip()):
        return None
    base = base_ua.strip() if isinstance(base_ua, str) and base_ua.strip() else "V3LUM"
    return "%s (contact: %s)" % (base, contact_email.strip())


def nominatim_config_marker(contact_email):
    """P262-FC1: without the contact_email role mailbox Nominatim is SKIPPED reason_code
    'config' (Photon, the FC2 fallback, still runs). Returns None when configured."""
    if nominatim_user_agent("V3LUM", contact_email) is None:
        return ("skipped: config: Nominatim needs the contact_email role mailbox for its identifying "
                "User-Agent (OSMF usage policy); set contact_email - Photon used instead")
    return None


def photon_query_from_address(addr):
    """Free-text Photon query for a parsed address (P262-FC2/FC3): 'street number, city UF'
    when a street is known, else the CEP, else 'city UF'. None when nothing is usable."""
    if not isinstance(addr, dict):
        return None
    street, number, city, uf = addr.get("street"), addr.get("number"), addr.get("city"), addr.get("uf")
    cep = normalize_cep(addr.get("cep"))
    tail = " ".join(x for x in (city, uf) if isinstance(x, str) and x)
    if isinstance(street, str) and street:
        head = "%s %s" % (street, number) if number else street
        return ", ".join(x for x in (head, tail) if x)[:300]
    if cep:
        return cep
    return tail[:300] or None


def keep_country(places, country_code="BR"):
    """Keep only places in ``country_code`` (Photon search is global; a Brazilian seed must not
    resolve to a homonymous street abroad) (P262-FC3/FC6)."""
    cc = country_code.upper() if isinstance(country_code, str) else None
    return [p for p in (places or []) if isinstance(p, dict)
            and (p.get("address") or {}).get("country_code") == cc]


def nominatim_marker(status, body, headers=None):
    """Classify a Nominatim answer (P262-FC1 rule 5; P321 FC1/FC7/FC8).

    - 403/418 or the 'Access blocked' page -> 'blocked: ...' (usage-policy block; never EMPTY)
    - 429/503/509 or 'Bandwidth limit exceeded' -> 'rate_limited: ...' (temporary block, the
      origin sends Retry-After: 3600)
    - 629 or a Varnish 'Unknown Error' synthetic page (CDN edge refusal seen live 2026-11-26,
      Retry-After: 0) -> 'rate_limited: ...' (do not retry; open the circuit; Photon fallback)
    - [] -> 'absent: ...'; reverse {'error': 'Unable to geocode'} -> 'absent: ...'
    - {'error': {...}} / other 4xx/5xx / HTML / malformed JSON -> 'error: ...'
    Returns None for a usable JSON answer.
    """
    text = as_text(body, 65536)
    low = text.lower()
    title = html_title(text).lower()
    if status in (403, 418) or "access blocked" in title or ("access denied" in low and status != 200):
        return ("blocked: Nominatim usage-policy block (HTTP %s 'Access blocked') - send the "
                "identifying User-Agent with contact_email, no bulk requests" % status)
    if status in (429, 503, 509) or "bandwidth limit exceeded" in title:
        ra = header(headers, "retry-after")
        return "rate_limited: Nominatim temporary block (HTTP %s%s)" % (
            status, ", Retry-After %s s" % ra if ra else "")
    if status == 629 or ("varnish" in low and "unknown error" in low):
        return ("rate_limited: Nominatim CDN edge refusal (HTTP %s Varnish synthetic error; "
                "do not retry this run)" % status)
    if isinstance(status, int) and status >= 500:
        return "error: Nominatim HTTP %s" % status
    obj, problem = load_json(body)
    if problem == "html":
        return "error: Nominatim answered HTML instead of JSON (HTTP %s)" % status
    if problem:
        return "error: Nominatim body %s (HTTP %s)" % (problem, status)
    if isinstance(obj, dict) and "error" in obj:
        err = obj.get("error")
        if isinstance(err, str) and "unable to geocode" in err.lower():
            return "absent: no OSM object at this point (Nominatim 'Unable to geocode')"
        if isinstance(err, dict):
            return "error: Nominatim error %s: %s" % (err.get("code"), str(err.get("message"))[:200])
        return "error: Nominatim error: %s" % str(err)[:200]
    if isinstance(status, int) and status >= 400:
        return "error: Nominatim HTTP %s" % status
    if isinstance(obj, list):
        if not obj:
            return "absent: no OSM match (not proof that the address does not exist)"
        return None
    if isinstance(obj, dict) and ("lat" in obj and "lon" in obj):
        return None
    return "error: unexpected Nominatim JSON shape"


def _float_or_none(v):
    f = _num(v)
    return f


def _osm_url(osm_type, osm_id):
    t = _OSM_TYPES.get(osm_type) if isinstance(osm_type, str) else None
    if t is None or isinstance(osm_id, bool) or not isinstance(osm_id, int) or osm_id <= 0:
        return None
    return "https://www.openstreetmap.org/%s/%d" % (t, osm_id)


def _state_code(state=None, iso_lvl4=None):
    if isinstance(iso_lvl4, str) and iso_lvl4.upper().startswith("BR-") and iso_lvl4[3:].upper() in UF_NAMES:
        return iso_lvl4[3:].upper()
    if isinstance(state, str):
        return _UF_BY_FOLDED_NAME.get(fold(state).strip())
    return None


def precision_from_rank(place_rank, addresstype=None, osm_type_value=None):
    """Precision level from a Nominatim place_rank/addresstype (P262-FC6 street/postcode/city).

    postcode objects -> 'postcode'; rank >= 26 (streets, houses, POIs) -> 'street';
    13..25 (cities, suburbs, neighbourhoods) -> 'city'; lower -> 'region'.
    """
    if (isinstance(addresstype, str) and addresstype == "postcode") or osm_type_value == "postcode":
        return "postcode"
    if isinstance(place_rank, bool) or not isinstance(place_rank, int):
        return "region"
    if place_rank >= 26:
        return "street"
    if place_rank >= 13:
        return "city"
    return "region"


def _address_from_nominatim(addr):
    if not isinstance(addr, dict):
        return {}
    g = lambda *keys: next((addr[k] for k in keys if isinstance(addr.get(k), str) and addr.get(k)), None)  # noqa: E731
    out = {
        "road": g("road", "pedestrian", "footway", "street"),
        "house_number": g("house_number"),
        "suburb": g("suburb", "neighbourhood", "quarter", "city_district"),
        "city": g("city", "town", "village", "municipality", "hamlet"),
        "state": g("state"),
        "state_code": _state_code(addr.get("state"), addr.get("ISO3166-2-lvl4")),
        "postcode": normalize_cep(addr.get("postcode")) or g("postcode"),
        "country": g("country"),
        "country_code": (addr.get("country_code") or "").upper() or None
        if isinstance(addr.get("country_code"), str) else None,
    }
    return {k: v for k, v in out.items() if v}


def parse_nominatim_place(obj):
    """Normalise one Nominatim jsonv2 place (search item or reverse answer) or return None.

    Output: provider, lat, lon (floats), display_name, name, category, type, addresstype,
    place_rank, osm_type, osm_id, osm_url, address{road, house_number, suburb, city, state,
    state_code, postcode (CEP), country, country_code}, boundingbox [s, n, w, e], precision,
    licence. P262-FC1/FC6.
    """
    if not isinstance(obj, dict):
        return None
    lat, lon = _float_or_none(obj.get("lat")), _float_or_none(obj.get("lon"))
    c = _coord_result(lat, lon)
    if c is None:
        return None
    osm_type = _OSM_TYPES.get(obj.get("osm_type")) if isinstance(obj.get("osm_type"), str) else None
    osm_id = obj.get("osm_id") if isinstance(obj.get("osm_id"), int) and not isinstance(obj.get("osm_id"), bool) else None
    rank = obj.get("place_rank") if isinstance(obj.get("place_rank"), int) else None
    bbox = obj.get("boundingbox")
    bb = None
    if isinstance(bbox, list) and len(bbox) == 4:
        vals = [_float_or_none(v) for v in bbox]
        bb = vals if all(v is not None for v in vals) else None
    s = lambda k: obj.get(k) if isinstance(obj.get(k), str) and obj.get(k) else None  # noqa: E731
    return {
        "provider": "nominatim",
        "lat": c["lat"], "lon": c["lon"],
        "display_name": s("display_name"),
        "name": s("name"),
        "category": s("category") or s("class"),
        "type": s("type"),
        "addresstype": s("addresstype"),
        "place_rank": rank,
        "osm_type": osm_type, "osm_id": osm_id, "osm_url": _osm_url(osm_type, osm_id),
        "address": _address_from_nominatim(obj.get("address")),
        "boundingbox": bb,
        "precision": precision_from_rank(rank, s("addresstype"), s("type")),
        "licence": s("licence"),
    }


def parse_nominatim_search(body):
    """List of normalised places from a Nominatim /search jsonv2 body ([] on anything else)."""
    obj, problem = load_json(body)
    if problem or not isinstance(obj, list):
        return []
    return [p for p in (parse_nominatim_place(o) for o in obj[:50]) if p]


def parse_nominatim_reverse(body):
    """Normalised place from a Nominatim /reverse jsonv2 body, or None (error/absent/HTML)."""
    obj, problem = load_json(body)
    if problem or not isinstance(obj, dict) or "error" in obj:
        return None
    return parse_nominatim_place(obj)


def photon_marker(status, body, headers=None):
    """Classify a Photon answer (P262-FC2; rule 5).

    400 validation errors (e.g. {'lat': [{'message': "Invalid value for 'lat' parameter."}]})
    -> 'error: ...'; 429 -> rate_limited; 403 -> blocked; empty FeatureCollection -> absent.
    """
    if status == 429:
        return "rate_limited: Photon HTTP 429"
    if status == 403:
        return "blocked: Photon HTTP 403"
    obj, problem = load_json(body)
    if isinstance(status, int) and status >= 400:
        msg = ""
        if isinstance(obj, dict):
            if isinstance(obj.get("message"), str):
                msg = obj["message"]
            else:
                for v in obj.values():
                    if isinstance(v, list) and v and isinstance(v[0], dict) and isinstance(v[0].get("message"), str):
                        msg = v[0]["message"]
                        break
        return "error: Photon HTTP %s%s" % (status, (": " + msg[:200]) if msg else "")
    if problem == "html":
        return "error: Photon answered HTML instead of JSON"
    if problem:
        return "error: Photon body %s" % problem
    if not isinstance(obj, dict) or not isinstance(obj.get("features"), list):
        return "error: unexpected Photon JSON shape"
    if not obj["features"]:
        return "absent: no Photon match (not proof that the address does not exist)"
    return None


def precision_from_photon(props):
    """Precision level from Photon properties (type / osm_key / osm_value) (P262-FC6)."""
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


def parse_photon(body):
    """Normalised places from a Photon FeatureCollection (search or reverse) (P262-FC2).

    Photon geometry is [lon, lat]: this function swaps it. Features are de-duplicated by
    (osm_type, osm_id) (the same OSM node is returned once per tag, e.g. office + shop).
    """
    obj, problem = load_json(body)
    if problem or not isinstance(obj, dict) or not isinstance(obj.get("features"), list):
        return []
    out, seen = [], set()
    for feat in obj["features"][:50]:
        if not isinstance(feat, dict):
            continue
        geom = feat.get("geometry") if isinstance(feat.get("geometry"), dict) else {}
        coords = geom.get("coordinates")
        if not (isinstance(coords, list) and len(coords) >= 2):
            continue
        c = _coord_result(_float_or_none(coords[1]), _float_or_none(coords[0]))  # [lon, lat]
        if c is None:
            continue
        props = feat.get("properties") if isinstance(feat.get("properties"), dict) else {}
        osm_type = _OSM_TYPES.get(props.get("osm_type")) if isinstance(props.get("osm_type"), str) else None
        osm_id = props.get("osm_id") if isinstance(props.get("osm_id"), int) and not isinstance(props.get("osm_id"), bool) else None
        key = (osm_type, osm_id) if osm_id is not None else (c["key"], props.get("name"))
        if key in seen:
            continue
        seen.add(key)
        def s(k, props=props):
            v = props.get(k)
            return v if isinstance(v, str) and v else None
        address = {
            "road": s("street") or (s("name") if props.get("type") == "street" else None),
            "house_number": s("housenumber"),
            "suburb": s("locality") or s("district"),
            "city": s("city"),
            "state": s("state"),
            "state_code": _state_code(props.get("state")),
            "postcode": normalize_cep(props.get("postcode")) or s("postcode"),
            "country": s("country"),
            "country_code": (s("countrycode") or "").upper() or None,
        }
        if props.get("osm_key") == "place" and props.get("osm_value") == "postcode" and not address["postcode"]:
            address["postcode"] = normalize_cep(props.get("name"))
        out.append({
            "provider": "photon",
            "lat": c["lat"], "lon": c["lon"],
            "display_name": ", ".join(x for x in (s("name"), s("street"), s("housenumber"), s("district"),
                                                    s("city"), s("state"), s("postcode"), s("country")) if x) or None,
            "name": s("name"),
            "category": s("osm_key"), "type": s("osm_value"), "addresstype": s("type"),
            "place_rank": None,
            "osm_type": osm_type, "osm_id": osm_id, "osm_url": _osm_url(osm_type, osm_id),
            "address": {k: v for k, v in address.items() if v},
            "boundingbox": None,
            "precision": precision_from_photon(props),
            "licence": "Data (c) OpenStreetMap contributors, ODbL 1.0 (via Photon)",
        })
    return out


def geocode_record(place, direction, attempt_precision=None):
    """Final normalised record for a place (P262-FC6): label, precision, disclaimer, attribution.

    ``direction`` is 'forward' (address/CEP -> coordinates) or 'reverse' (coordinates -> place).
    Forward precision is the fallback step that answered (street/postcode/city); reverse
    precision comes from the place itself. Adds the pivots the module may emit: 'coordinates'
    (forward; expand=False, P262-FC5) and 'cep' (from the place postcode).
    """
    if not isinstance(place, dict) or direction not in ("forward", "reverse"):
        return None
    precision = attempt_precision if (direction == "forward" and attempt_precision in PRECISION_LEVELS) \
        else place.get("precision", "region")
    rec = {
        "label": GEO_LABEL,
        "precision": precision,
        "disclaimer": GEO_DISCLAIMER,
        "attribution": OSM_ATTRIBUTION,
        "direction": direction,
        "provider": place.get("provider"),
        "lat": place.get("lat"), "lon": place.get("lon"),
        "display_name": place.get("display_name"),
        "osm_url": place.get("osm_url"),
        "address": dict(place.get("address") or {}),
        "pivots": [],
    }
    if direction == "forward":
        rec["pivots"].append({"type": "coordinates", "value": "%.6f,%.6f" % (place["lat"], place["lon"]),
                              "expand": False})
    cep = normalize_cep((place.get("address") or {}).get("postcode"))
    if cep:
        rec["pivots"].append({"type": "cep", "value": cep, "expand": False})
    return rec


COORD_ORIGINS_DEFAULT_OK = ("seed",)
COORD_ORIGINS_CONFIRM = ("exif", "device", "pivot", "text", "file", "other")


def reverse_geocode_gate(origin, analyst_confirmed=False):
    """P262-FC4 legal floor: reverse geocoding runs by default only for coordinates the analyst
    typed as seeds; coordinates from photos (EXIF), devices or other sources that may locate a
    natural person need a per-entity analyst confirmation. Returns None (allowed) or a
    'skipped: privacy: ...' marker. (The A8/P262-FC5 personal_data_review gate is policy's.)
    """
    if origin in COORD_ORIGINS_DEFAULT_OK:
        return None
    if analyst_confirmed:
        return None
    return ("skipped: privacy: coordinates from %s may locate a natural person; reverse geocoding "
            "needs a per-entity analyst confirmation" % (origin if isinstance(origin, str) else "an unknown source"))


def forward_geocode_gate(origin, explicit_request=False):
    """P262-FC3/FC4: forward geocoding runs for explicit address-style TYPE:value seeds and CEP
    seeds; addresses from company records (CNPJ/CEP) run only on explicit request; pasted text
    is never geocoded. Returns None or a 'skipped: ...' marker."""
    if origin in ("seed_address", "seed_cep"):
        return None
    if origin in ("company_record", "cep_record") and explicit_request:
        return None
    if origin in ("company_record", "cep_record"):
        return "skipped: not_default: company addresses are geocoded only on explicit request"
    return "skipped: privacy: only typed address/CEP seeds are geocoded (no text_blob, no pivots)"


def place_export_allowed(direction, origin, analyst_opt_in=False):
    """P262-FC6: places derived from coordinates that may locate a person stay in the case and
    are left out of STIX/MISP unless the analyst opts in (as P259 GPS). Reverse results and
    forward results of typed addresses are opt-in; forward results of company records export."""
    if analyst_opt_in:
        return True
    return direction == "forward" and origin in ("company_record", "cep_record")


# ---------------------------------------------------------------------------------------
# 2. P264 image_ela - Error Level Analysis (offline; Pillow runs in the sandbox child)
# ---------------------------------------------------------------------------------------

ELA_RESAVE_QUALITY = 90
ELA_WORDING = "Error level analysis: heuristic, not proof of tampering"
ELA_TERMINAL_LINE = "ELA map in the HTML report (heuristic, not proof)"
ELA_LOSSLESS_REASON = "ELA not meaningful for lossless images"
ELA_MAX_INPUT_BYTES = 100 * 1024 * 1024
ELA_MAX_PIXELS = 40_000_000
ELA_MAX_PNG_BYTES = 700_000

# IJG/Annex K standard luminance table in natural (row-major) order
_STD_LUMA = [16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
             14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
             18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
             49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99]
_ZIGZAG = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34,
           27, 20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37,
           44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63]
_STD_LUMA_ZZ = [_STD_LUMA[i] for i in _ZIGZAG]


def sniff_image_format(head):
    """Image format from magic bytes: jpeg, png, gif, bmp, tiff, webp_lossy, webp_lossless,
    webp_extended, heic, avif, or None (P264-FC3)."""
    if not isinstance(head, (bytes, bytearray)):
        return None
    h = bytes(head[:64])
    if h[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if h[:2] == b"BM" and len(h) >= 14:
        return "bmp"
    if h[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        chunk = h[12:16]
        return {b"VP8 ": "webp_lossy", b"VP8L": "webp_lossless", b"VP8X": "webp_extended"}.get(chunk, "webp_extended")
    if h[4:8] == b"ftyp":
        brand = h[8:12]
        if brand in (b"avif", b"avis"):
            return "avif"
        if brand in (b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1"):
            return "heic"
    return None


def ela_applicability(fmt):
    """P264-FC3: JPEG only. Returns None for JPEG, else a 'skipped: not_applicable: ...' marker
    ('ELA not meaningful for lossless images' for PNG/GIF/BMP/TIFF/lossless WebP)."""
    if fmt == "jpeg":
        return None
    if fmt in ("png", "gif", "bmp", "tiff", "webp_lossless"):
        return "skipped: not_applicable: " + ELA_LOSSLESS_REASON
    if fmt in ("webp_lossy", "webp_extended", "heic", "avif"):
        return "skipped: not_applicable: ELA is implemented for JPEG only"
    return "skipped: not_applicable: not a recognised image"


def ela_input_check(size_bytes, width=None, height=None):
    """P264-FC2 caps before any decoding: input <= 100 MB, decoded pixels <= 40 MP (memory
    rlimit 1 GiB holds three RGB copies). Returns None or a 'skipped: policy: ...' marker."""
    if not isinstance(size_bytes, int) or size_bytes < 0:
        return "error: unknown input size"
    if size_bytes > ELA_MAX_INPUT_BYTES:
        return "skipped: policy: file larger than the 100 MB sandbox input cap"
    if isinstance(width, int) and isinstance(height, int) and width * height > ELA_MAX_PIXELS:
        return "skipped: policy: image larger than %d MP (ELA on a resampled copy is meaningless)" % (
            ELA_MAX_PIXELS // 1_000_000)
    return None


def jpeg_info(data, max_segments=512):
    """Walk JPEG marker segments up to SOS (stdlib only, defensive) (P264-FC3/FC4).

    Returns {width, height, components, progressive, sof, dqt{table_id: [64 zigzag values]},
    exif, jfif, adobe, errors[]} or None when ``data`` is not a JPEG.
    """
    if not isinstance(data, (bytes, bytearray)) or bytes(data[:3]) != b"\xff\xd8\xff":
        return None
    info = {"width": None, "height": None, "components": None, "progressive": None, "sof": None,
            "dqt": {}, "exif": False, "jfif": False, "adobe": False, "errors": []}
    i, n, count = 2, len(data), 0
    while i + 4 <= n and count < max_segments:
        if data[i] != 0xFF:
            info["errors"].append("bad marker at %d" % i)
            break
        marker = data[i + 1]
        if marker == 0xFF:
            i += 1
            continue
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xD9:
            break
        seglen = int.from_bytes(data[i + 2:i + 4], "big")
        if seglen < 2 or i + 2 + seglen > n:
            info["errors"].append("truncated segment 0x%02X at %d" % (marker, i))
            break
        seg = bytes(data[i + 4:i + 2 + seglen])
        if marker == 0xDB:
            j = 0
            while j < len(seg):
                pq, tq = seg[j] >> 4, seg[j] & 0x0F
                size = 128 if pq else 64
                vals = seg[j + 1:j + 1 + size]
                if len(vals) < size or tq > 3:
                    info["errors"].append("bad DQT")
                    break
                info["dqt"][tq] = list(vals) if pq == 0 else [int.from_bytes(vals[k:k + 2], "big")
                                                             for k in range(0, 128, 2)]
                j += 1 + size
        elif 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            if len(seg) >= 6:
                info["height"] = int.from_bytes(seg[1:3], "big")
                info["width"] = int.from_bytes(seg[3:5], "big")
                info["components"] = seg[5]
                info["progressive"] = marker in (0xC2, 0xC6, 0xCA, 0xCE)
                info["sof"] = "0x%02X" % marker
        elif marker == 0xE1 and seg[:6] == b"Exif\x00\x00":
            info["exif"] = True
        elif marker == 0xE0 and seg[:5] == b"JFIF\x00":
            info["jfif"] = True
        elif marker == 0xEE and seg[:5] == b"Adobe":
            info["adobe"] = True
        elif marker == 0xDA:
            break
        i += 2 + seglen
        count += 1
    else:
        if i + 4 > n:
            info["errors"].append("ended before start of scan")
    return info


def _ijg_table(quality):
    q = max(1, min(100, int(quality)))
    scale = 5000 // q if q < 50 else 200 - 2 * q
    return [max(1, min(255, (v * scale + 50) // 100)) for v in _STD_LUMA_ZZ]


def jpeg_estimate_quality(dqt):
    """Estimate the IJG quality (1..100) from the luminance quantisation table (P264-FC4 context:
    ELA re-saves at q90; an already low-quality JPEG gives a flat, uninformative map).

    Returns {'quality': int, 'exact': bool, 'mean_abs_error': float} or None.
    """
    if not isinstance(dqt, dict):
        return None
    table = dqt.get(0)
    if not (isinstance(table, list) and len(table) == 64 and all(isinstance(v, int) for v in table)):
        return None
    best = None
    for q in range(1, 101):
        ref = _ijg_table(q)
        err = sum(abs(a - b) for a, b in zip(table, ref, strict=True))
        if best is None or err < best[1]:
            best = (q, err)
    return {"quality": best[0], "exact": best[1] == 0, "mean_abs_error": round(best[1] / 64.0, 3)}


def ela_aggregate_bytes(width, height, err, grid=8):
    """Aggregate a per-pixel error band (one byte per pixel, 0..255) into the histogram and
    grid tile means that ``ela_summary`` consumes (pure Python; small images and tests). The
    sandbox child computes the same aggregates with Pillow (histogram(), ImageStat on crops).
    P264-FC4."""
    if isinstance(width, bool) or isinstance(height, bool) or not isinstance(width, int) \
            or not isinstance(height, int) or width <= 0 or height <= 0:
        return None
    if not isinstance(err, (bytes, bytearray)) or len(err) != width * height:
        return None
    grid = max(1, min(int(grid), width, height))
    hist = [0] * 256
    for v in err:
        hist[v] += 1
    xs = [width * k // grid for k in range(grid + 1)]
    ys = [height * k // grid for k in range(grid + 1)]
    means = []
    for ty in range(grid):
        sums = [0] * grid
        for y in range(ys[ty], ys[ty + 1]):
            row = err[y * width:(y + 1) * width]
            for tx in range(grid):
                sums[tx] += sum(row[xs[tx]:xs[tx + 1]])
        means.append([round(sums[tx] / max(1, (xs[tx + 1] - xs[tx]) * (ys[ty + 1] - ys[ty])), 4)
                      for tx in range(grid)])
    return {"width": width, "height": height, "grid": grid, "histogram": hist, "tile_means": means}


def ela_summary(agg):
    """Numeric ELA metrics from aggregates (P264-FC4): mean/max/std/p50/p95/p99 error level,
    share of pixels >= 16 and >= 32, grid tile statistics (max, median, region_ratio =
    max/median) and the 3 hottest regions as image fractions. Returns None on bad input.
    Never produces a 'tamper' verdict or score (P264-FC5)."""
    if not isinstance(agg, dict):
        return None
    hist, tiles = agg.get("histogram"), agg.get("tile_means")
    w, h, grid = agg.get("width"), agg.get("height"), agg.get("grid")
    if not (isinstance(hist, list) and len(hist) == 256 and all(isinstance(c, int) and c >= 0 for c in hist)):
        return None
    if not all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in (w, h, grid)):
        return None
    if not (isinstance(tiles, list) and len(tiles) == grid and all(
            isinstance(r, list) and len(r) == grid and all(isinstance(x, (int, float)) and 0 <= x <= 255 for x in r)
            for r in tiles)):
        return None
    n = sum(hist)
    if n <= 0:
        return None
    mean = sum(i * c for i, c in enumerate(hist)) / n
    var = sum(c * (i - mean) ** 2 for i, c in enumerate(hist)) / n
    mx = max(i for i, c in enumerate(hist) if c)

    def pct(p):
        target, cum = p * n, 0
        for i, c in enumerate(hist):
            cum += c
            if cum >= target:
                return i
        return 255

    flat = [(tiles[r][c], r, c) for r in range(grid) for c in range(grid)]
    vals = [v for v, _, _ in flat]
    tmax, tmed = max(vals), statistics.median(vals)
    hot = sorted(flat, key=lambda t: (-t[0], t[1], t[2]))[:3]
    regions = [{"row": r, "col": c, "mean": round(v, 3),
                "box": [round(c / grid, 3), round(r / grid, 3), round((c + 1) / grid, 3), round((r + 1) / grid, 3)]}
               for v, r, c in hot]
    return {
        "mean": round(mean, 3), "max": mx, "std": round(math.sqrt(var), 3),
        "p50": pct(0.50), "p95": pct(0.95), "p99": pct(0.99),
        "frac_ge_16": round(sum(hist[16:]) / n, 5), "frac_ge_32": round(sum(hist[32:]) / n, 5),
        "tile_max": round(tmax, 3), "tile_median": round(tmed, 3),
        "region_ratio": round(tmax / max(tmed, 0.5), 3),
        "hot_regions": regions, "grid": grid, "width": w, "height": h,
    }


def png_data_uri(png, max_bytes=ELA_MAX_PNG_BYTES):
    """'data:image/png;base64,...' for an ELA PNG embedded in HTML reports (P264-FC4), or None
    when ``png`` is not a PNG or is larger than ``max_bytes``."""
    if isinstance(png, str):
        try:
            png = base64.b64decode(png, validate=True)
        except (binascii.Error, ValueError):
            return None
    if not isinstance(png, (bytes, bytearray)) or bytes(png[:8]) != b"\x89PNG\r\n\x1a\n" or len(png) > max_bytes:
        return None
    return "data:image/png;base64," + base64.b64encode(bytes(png)).decode("ascii")


def normalize_ela_child_output(obj):
    """Validate the sandbox child's JSON and turn it into module output (P264-FC2/FC4/FC5).

    Returns {'ok', 'errors', 'skip' (marker or None), 'attributes', 'png_data_uri', 'severity',
    'wording', 'terminal_line', 'score_delta'}. Attributes are numeric metrics only; severity is
    always 'info' and score_delta 0 (ELA never raises severity or score on its own).
    """
    res = {"ok": False, "errors": [], "skip": None, "attributes": {}, "png_data_uri": None,
           "severity": "info", "wording": ELA_WORDING, "terminal_line": ELA_TERMINAL_LINE, "score_delta": 0}
    if not isinstance(obj, dict):
        obj, problem = load_json(obj)
        if problem or not isinstance(obj, dict):
            res["errors"].append("child output is not a JSON object")
            return res
    if obj.get("skipped"):
        fmt = obj.get("format_sniffed") if isinstance(obj.get("format_sniffed"), str) else None
        res["skip"] = ela_applicability(fmt) if fmt else "skipped: not_applicable: %s" % str(obj.get("skipped"))[:120]
        return res
    if obj.get("error"):
        res["errors"].append("child error: %s" % str(obj.get("error"))[:200])
        return res
    summary = ela_summary(obj)
    if summary is None:
        res["errors"].append("aggregates missing or malformed")
        return res
    q = obj.get("jpeg_quality_estimate")
    attrs = {
        "ela_resave_quality": obj.get("quality_resave") if isinstance(obj.get("quality_resave"), int) else ELA_RESAVE_QUALITY,
        "ela_mean": summary["mean"], "ela_max": summary["max"], "ela_std": summary["std"],
        "ela_p99": summary["p99"], "ela_frac_ge_16": summary["frac_ge_16"],
        "ela_region_ratio": summary["region_ratio"], "ela_hot_regions": summary["hot_regions"],
        "image_width": summary["width"], "image_height": summary["height"],
        "jpeg_quality_estimate": q if isinstance(q, int) and 1 <= q <= 100 else None,
        "ela_heuristic": True,
    }
    res["attributes"] = attrs
    uri = png_data_uri(obj.get("ela_png_b64")) if obj.get("ela_png_b64") else None
    if obj.get("ela_png_b64") and uri is None:
        res["errors"].append("ELA PNG missing, invalid or over the size cap (not embedded)")
    res["png_data_uri"] = uri
    res["ok"] = True
    return res


# ---------------------------------------------------------------------------------------
# 3. P273 document_identity_signals - name windows + nearest CPF (Ceos port, offline)
# ---------------------------------------------------------------------------------------

MAX_WINDOW = 200
_CPF_RE = re.compile(r"(?<![\d*])(\d{3})\.?(\d{3})\.?(\d{3})\s?-?\s?(\d{2})(?!\d)")
_MASKED_CPF_RE = re.compile(r"(?<![\w*])(?:\*{3}|[xX]{3})\.?(\d{3})\.?(\d{3})-?(?:\*{2}|[xX]{2})(?![\w*])")
_STRONG_SEP_RE = re.compile(r";|\||\u2022|\n[ \t\r\f\v]*\n")
_CPF_LABEL_RE = re.compile(r"\bcpf\b")


def cpf_valid(cpf):
    """CPF check digits (offline only, never sent anywhere; the core P232 validator is the
    reference) (P273-FC3/FC4)."""
    d = digits_only(cpf)
    if len(d) != 11 or d == d[0] * 11:
        return False
    for n in (9, 10):
        s = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        if (s * 10) % 11 % 10 != int(d[n]):
            return False
    return True


def mask_cpf(cpf):
    """Government masking pattern '***.456.789-**' (AR24, P273-FC4). None if not 11 digits."""
    d = digits_only(cpf)
    if len(d) != 11:
        return None
    return "***.%s.%s-**" % (d[3:6], d[6:9])


def mask_cpfs_in_text(text):
    """Mask every CPF-shaped number (valid or not) in ``text`` (excerpts/evidence, P273-FC4)."""
    if not isinstance(text, str):
        return ""
    return _CPF_RE.sub(lambda m: "***.%s.%s-**" % (m.group(2), m.group(3)), text)


def find_cpfs(text):
    """CPF occurrences: [{'start','end','kind': 'full'|'masked','valid','masked'}] - the full
    digits are only used locally for an exact comparison with a typed seed and never returned
    (P273-FC4)."""
    out = []
    if not isinstance(text, str):
        return out
    for m in _CPF_RE.finditer(text):
        d = "".join(m.groups())
        out.append({"start": m.start(), "end": m.end(), "kind": "full", "valid": cpf_valid(d),
                    "masked": mask_cpf(d), "_digits": d})
    for m in _MASKED_CPF_RE.finditer(text):
        out.append({"start": m.start(), "end": m.end(), "kind": "masked", "valid": None,
                    "masked": "***.%s.%s-**" % (m.group(1), m.group(2)), "_digits": None})
    out.sort(key=lambda c: c["start"])
    return out


def name_regex(name):
    """Accent/case-insensitive regex for a full name with any punctuation/spacing (<= 10 chars)
    between parts, over ``fold(text)`` (P273-FC3). None for names with fewer than 2 parts."""
    parts = [p for p in re.split(r"[^0-9a-z]+", fold(name)) if p] if isinstance(name, str) else []
    if len(parts) < 2 or sum(len(p) for p in parts) < 5:
        return None
    sep = r"[^0-9a-z]{1,10}"
    return re.compile(r"(?<![0-9a-z])" + sep.join(re.escape(p) for p in parts) + r"(?![0-9a-z])")


def _gap(text, a_end, b_start):
    return text[a_end:b_start] if a_end <= b_start else ""


_LABEL_WORDS = frozenset(("cpf", "n", "no", "nr", "num", "numero", "mf", "rg"))


def document_layout(text, cands=None):
    """'lines' when the document lists one record per line, else 'prose' (P273-FC3).

    'lines': >= 3 lines carry exactly one CPF plus at least two words besides labels such as
    'CPF'/'nº' (a record: name and CPF on the same line, CSV/';'/'|' tables and PDF table
    text included), and those lines are >= 60 % of the CPF-bearing lines. In 'lines' layout a
    CPF on another line never attaches to a name, even when the name's own line has none, so
    a neighbour's CPF cannot attach to the subject. In 'prose' layout (gazette paragraphs,
    contracts, forms with 'CPF:' on its own line) records end at ';', '|', a bullet or a blank
    line and a line break only lowers the preference.
    """
    if not isinstance(text, str):
        return "prose"
    if cands is None:
        cands = find_cpfs(text)
    if len(cands) < 3:
        return "prose"
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    per_line, record_lines = {}, 0
    for c in cands:
        per_line.setdefault(bisect.bisect_right(starts, c["start"]) - 1, []).append(c)
    for ln, cs in per_line.items():
        if len(cs) != 1:
            continue
        ls = starts[ln]
        le = starts[ln + 1] - 1 if ln + 1 < len(starts) else len(text)
        rest = text[ls:cs[0]["start"]] + " " + text[cs[0]["end"]:le]
        words = [w for w in re.findall(r"[a-z]{2,}", fold(rest)) if w not in _LABEL_WORDS]
        if len(words) >= 2:
            record_lines += 1
    return "lines" if record_lines >= 3 and record_lines >= 0.6 * len(per_line) else "prose"


def _choose_cpf(text, folded, s, e, cands, layout="prose"):
    """Pick the CPF that belongs to the name at [s, e) (P273-FC3): same record only - in
    'lines' layout the same line; in 'prose' layout a neighbour's CPF behind a ';', '|',
    bullet or blank line never counts - then a 'CPF' label in the gap, then no line break in
    the gap, then the smallest distance, then 'after'."""
    scored = []
    for c in cands:
        if c["start"] >= e:
            side, gap_s, gap_e = "after", e, c["start"]
        elif c["end"] <= s:
            side, gap_s, gap_e = "before", c["end"], s
        else:
            continue
        gap = text[gap_s:gap_e]
        if layout == "lines":
            if "\n" in gap:
                continue
        elif _STRONG_SEP_RE.search(gap):
            continue
        labelled = bool(_CPF_LABEL_RE.search(folded[gap_s:gap_e])) and side == "after"
        key = (0 if labelled else 1, 1 if "\n" in gap else 0, len(gap), 0 if side == "after" else 1)
        scored.append((key, side, len(gap), c))
    if not scored:
        return None, False
    scored.sort(key=lambda t: t[0])
    best = scored[0]
    ambiguous = len(scored) > 1 and scored[1][0][:2] == best[0][:2] and abs(scored[1][2] - best[2]) <= 3 \
        and scored[1][3]["masked"] != best[3]["masked"]
    return {"cpf": best[3], "side": best[1], "distance": best[2]}, ambiguous


def identity_signals(text, person_name, cpf=None, city=None, uf=None, max_window=MAX_WINDOW):
    """Identity signals for a typed person seed inside one case document (P273-FC2..FC5).

    Name windows are bounded (<= ``max_window`` chars, FC3); only the CPF nearest to the name
    in the same record counts (FC3); a city near the name is a strong signal, a UF only weak
    (FC3). A typed ``cpf`` is only searched inside this text, exactly (FC2): fragments of masked
    CPFs are never compared (FC4, P236 floor) - the analyst reads the pair. Output carries masked
    CPFs only and the privacy tag (FC4/FC5); it is never indexed across cases.
    """
    res = {"name_found": False, "occurrences": 0, "windows": [], "nearest_cpf_masked": None,
           "typed_cpf": None, "signals": [], "confidence": "none", "criterion": None, "alert": None,
           "layout": None, "privacy": True, "cross_case_index": False, "export": False, "errors": []}
    rx = name_regex(person_name)
    if rx is None:
        res["errors"].append("name needs at least two parts")
        res["criterion"] = "name too short to search"
        return res
    if not isinstance(text, str) or not text:
        res["criterion"] = "empty document"
        return res
    folded = fold(text)
    cands = find_cpfs(text)
    layout = document_layout(text, cands)
    res["layout"] = layout
    typed = digits_only(cpf) if cpf is not None else None
    if typed is not None and not cpf_valid(typed):
        res["errors"].append("typed CPF is not valid (check digits)")
        typed = None
    city_rx = None
    if isinstance(city, str) and city.strip():
        cparts = [p for p in re.split(r"[^0-9a-z]+", fold(city)) if p]
        if cparts:
            city_rx = re.compile(r"(?<![0-9a-z])" + r"[^0-9a-z]{1,3}".join(map(re.escape, cparts)) + r"(?![0-9a-z])")
    uf_code = uf.strip().upper() if isinstance(uf, str) and uf.strip().upper() in UF_NAMES else None
    uf_rx = re.compile(r"(?<![0-9A-Za-z])%s(?![0-9A-Za-z])" % uf_code) if uf_code else None
    best_overall = None
    for m in rx.finditer(folded):
        s, e = m.start(), m.end()
        name_len = e - s
        radius = max(0, (max_window - name_len) // 2)
        ws, we = max(0, s - radius), min(len(text), e + radius)
        in_window = [c for c in cands if c["start"] >= ws and c["end"] <= we]
        choice, ambiguous = _choose_cpf(text, folded, s, e, in_window, layout)
        wtext = text[ws:we]
        win = {"start": ws, "end": we, "excerpt": mask_cpfs_in_text(wtext),
               "nearest_cpf_masked": choice["cpf"]["masked"] if choice else None,
               "cpf_kind": choice["cpf"]["kind"] if choice else None,
               "cpf_side": choice["side"] if choice else None,
               "cpf_distance": choice["distance"] if choice else None,
               "ambiguous": ambiguous,
               "city_near": bool(city_rx.search(folded[ws:we])) if city_rx else False,
               "uf_near": bool(uf_rx.search(wtext)) if uf_rx else False,
               "_choice": choice}
        res["windows"].append(win)
        if choice and (best_overall is None or choice["distance"] < best_overall["distance"]):
            best_overall = choice
    res["occurrences"] = len(res["windows"])
    res["name_found"] = res["occurrences"] > 0
    if not res["name_found"]:
        res["criterion"] = "name not found in this document"
        if typed is not None:
            res["typed_cpf"] = {"masked": mask_cpf(typed), "found_in_document": any(c["_digits"] == typed for c in cands),
                                "next_to_name": False}
        for w in res["windows"]:
            w.pop("_choice", None)
        return res
    signals = []
    score = 0
    if best_overall:
        res["nearest_cpf_masked"] = best_overall["cpf"]["masked"]
    if any(w["city_near"] for w in res["windows"]):
        signals.append("city_near_name")
        score += 2
    elif any(w["uf_near"] for w in res["windows"]):
        signals.append("uf_near_name")
        score += 1
    elif uf_rx is not None and uf_rx.search(text):
        signals.append("uf_in_document")
    attached = [w["_choice"]["cpf"] for w in res["windows"] if w["_choice"]]
    if typed is not None:
        next_to = any(c["_digits"] == typed for c in attached)
        res["typed_cpf"] = {"masked": mask_cpf(typed),
                            "found_in_document": any(c["_digits"] == typed for c in cands),
                            "next_to_name": next_to}
        if next_to:
            signals.append("typed_cpf_next_to_name")
            score += 4
        elif any(c["kind"] == "full" for c in attached):
            signals.append("different_cpf_next_to_name")
            res["alert"] = "a different CPF is next to this name (possible homonym)"
        elif any(c["kind"] == "masked" for c in attached):
            signals.append("masked_cpf_next_to_name")
            score += 1
    elif attached:
        signals.append("cpf_next_to_name")
        score += 1
    if any(w["ambiguous"] for w in res["windows"]):
        signals.append("ambiguous_cpf")
    res["signals"] = signals
    if res["alert"]:
        res["confidence"] = "weak"
    elif score >= 4:
        res["confidence"] = "strong"
    elif score >= 2:
        res["confidence"] = "medium"
    else:
        res["confidence"] = "weak"
    if "typed_cpf_next_to_name" in signals:
        res["criterion"] = "typed CPF next to the name"
    elif res["alert"]:
        res["criterion"] = "name found; another CPF is next to it"
    elif "masked_cpf_next_to_name" in signals:
        res["criterion"] = "name found next to a masked CPF - the analyst compares (no fragment join)"
    elif "cpf_next_to_name" in signals:
        res["criterion"] = "name found next to a CPF"
    else:
        res["criterion"] = "name found without a CPF nearby (homonyms possible)"
    for w in res["windows"]:
        w.pop("_choice", None)
    return res


# ---------------------------------------------------------------------------------------
# 4. P317 user_agent_analysis - own UA table + teler bad-crawlers (offline matching)
# ---------------------------------------------------------------------------------------

UA_MAX_BYTES = 1024
UA_RISK_CEILING = "LOW"
TELER_BAD_CRAWLERS_URL = "https://raw.githubusercontent.com/kitabisa/teler-resources/master/db/bad-crawlers.txt"
TELER_ATTRIBUTION = ("teler-resources bad-crawlers.txt by kitabisa, CC BY 4.0 "
                     "(https://github.com/kitabisa/teler-resources); patterns derived from "
                     "JayBizzle/Crawler-Detect (MIT)")


def truncate_ua(ua, limit=UA_MAX_BYTES):
    """Truncate a UA to ``limit`` UTF-8 bytes before any matching (P317-FC3). Returns
    (text, truncated: bool); non-str input -> ('', False)."""
    if not isinstance(ua, str):
        return "", False
    raw = ua.encode("utf-8", "replace")
    if len(raw) <= limit:
        return ua, False
    return raw[:limit].decode("utf-8", "ignore"), True


_NESTED_Q_RE = re.compile(r"\((?:[^()\\]|\\.)*(?:[+*]|\{\d+,\})(?:[^()\\]|\\.)*\)(?:[+*]|\{\d+,?\d*\})")
_QUANT_ALT_RE = re.compile(r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)(?:[+*]|\{\d+,\d*\})")
_BACKREF_RE = re.compile(r"\\[1-9]|\(\?P=")
_LEAD_STAR_CLASS_RE = re.compile(r"^\[(?:[^\]\\]|\\.)+\]\*(?=.)")


def redos_static_flags(pattern):
    """Static ReDoS screen for one regex (P317-FC3, P340 FC2): returns a list of reasons
    ('nested_quantifier', 'quantified_alternation', 'backreference', 'too_long',
    'multiple_dotstar'); an empty list means the timing screen decides."""
    if not isinstance(pattern, str):
        return ["not_a_string"]
    flags = []
    if len(pattern) > 512:
        flags.append("too_long")
    if _NESTED_Q_RE.search(pattern):
        flags.append("nested_quantifier")
    if _QUANT_ALT_RE.search(pattern):
        flags.append("quantified_alternation")
    if _BACKREF_RE.search(pattern):
        flags.append("backreference")
    if len(re.findall(r"(?<!\\)\.\*", pattern)) >= 2:
        flags.append("multiple_dotstar")
    return flags


REDOS_REJECT = ("nested_quantifier", "quantified_alternation", "backreference", "too_long", "not_a_string")


def normalise_crawler_pattern(pattern):
    """Drop a redundant unanchored leading '[...]*' (it can match empty, so re.search finds the
    same UAs): Crawler-Detect's generic '[a-z0-9\\-_]*(bot|crawl|...)' goes from quadratic
    (~95-150 ms on 1 KB) to linear (P317-FC3)."""
    return _LEAD_STAR_CLASS_RE.sub("", pattern, count=1) if isinstance(pattern, str) else pattern


def parse_bad_crawlers(text):
    """Parse the teler bad-crawlers list (one regex per line, Crawler-Detect style, matched
    case-insensitively) (P317-FC1/FC3).

    Lines are kept verbatim (leading/trailing spaces are significant, e.g. ' YLT', '^FDM ');
    blank and '#' lines are skipped. Each pattern is statically screened, normalised and
    compiled. Returns {'patterns', 'normalised', 'rejected': [(pattern, reason)], 'errors'}.
    HTML or a '404: Not Found' body yields errors and no patterns.
    """
    res = {"patterns": [], "normalised": [], "rejected": [], "errors": []}
    t = as_text(text)
    if looks_like_html(t):
        res["errors"].append("HTML instead of the bad-crawlers list")
        return res
    if t.strip() in ("404: Not Found", "400: Invalid request"):
        res["errors"].append("dataset body is an error page: %s" % t.strip())
        return res
    for line in t.replace("\r\n", "\n").split("\n"):
        line = line.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        flags = [f for f in redos_static_flags(line) if f in REDOS_REJECT]
        if flags:
            res["rejected"].append((line, flags[0]))
            continue
        norm = normalise_crawler_pattern(line)
        try:
            re.compile(norm, re.I)
        except re.error as exc:
            res["rejected"].append((line, "compile_error: %s" % exc))
            continue
        if norm != line:
            res["normalised"].append((line, norm))
        res["patterns"].append(norm)
    return res


def validate_bad_crawlers(parsed, min_patterns=1000):
    """Dataset-manager validator (AR10 validate=): a real list has ~1,741 patterns (2026-11-26);
    fewer than ``min_patterns`` or a high reject rate means a broken download. Returns None or
    an 'error: ...' marker."""
    if not isinstance(parsed, dict) or parsed.get("errors"):
        return "error: bad-crawlers list unusable: %s" % ("; ".join(parsed.get("errors", [])) if isinstance(parsed, dict) else "not parsed")
    n = len(parsed.get("patterns", []))
    if n < min_patterns:
        return "error: bad-crawlers list too short (%d patterns < %d)" % (n, min_patterns)
    if len(parsed.get("rejected", [])) > max(5, n // 100):
        return "error: too many rejected patterns (%d)" % len(parsed["rejected"])
    return None


def teler_dataset_marker(status, body):
    """Marker for the bad-crawlers download (AR10, P321): 404 '404: Not Found' / HTML / 429."""
    if status == 429:
        return "rate_limited: raw.githubusercontent.com HTTP 429"
    if status == 404:
        return "error: teler bad-crawlers dataset not found (HTTP 404)"
    if isinstance(status, int) and status >= 400:
        return "error: teler dataset HTTP %s" % status
    if looks_like_html(body):
        return "error: HTML instead of the teler dataset"
    return None


def compile_crawler_matcher(patterns):
    """One case-insensitive alternation over the screened patterns (compiled once; measured
    2026-11-26 on the full 1,741-line list: ~0.8 ms per typical UA and ~18-21 ms on 1 KB
    adversarial input after ``normalise_crawler_pattern``, vs ~80-135 ms without it)."""
    pats = [p for p in (patterns or []) if isinstance(p, str) and p]
    if not pats:
        return None
    return re.compile("|".join("(?:%s)" % p for p in pats), re.I)


def is_phpids_filter_set(obj):
    """P317-FC2 guard: PHPIDS-derived web-attack filters (teler common-web-attacks.json, LGPL-3.0
    payload PCREs) are never used for UA matching. Returns a reason string when ``obj`` looks
    like that filter set ({'filters': [{'id','rule','tags','impact'}...]}), else None."""
    if isinstance(obj, (bytes, str)):
        obj, problem = load_json(obj)
        if problem:
            return None
    if isinstance(obj, dict) and isinstance(obj.get("filters"), list) and obj["filters"]:
        first = obj["filters"][0]
        if isinstance(first, dict) and {"rule", "tags", "impact"} <= set(first):
            return "PHPIDS-derived web-attack filters (LGPL-3.0) are not UA patterns (P317-FC2)"
    return None


# Own UA table (V3LUM-authored). Order matters within each group: first match wins. Every
# repetition is bounded ({1,10}, {0,3}, {0,80}) so the table passes the static ReDoS screen by
# construction and the timing fuzz in the tests (P317-FC3).
UA_BROWSERS = [
    ("Edge", r"\bEdg(?:e|A|iOS)?/(\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Opera", r"\b(?:OPR|Opera)[/ ](\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Samsung Internet", r"\bSamsungBrowser/(\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Yandex Browser", r"\bYaBrowser/(\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Chrome", r"\b(?:Chrome|CriOS)/(\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Firefox", r"\b(?:Firefox|FxiOS)/(\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Safari", r"\bVersion/(\d{1,10}(?:\.\d{1,10}){0,3})(?: Mobile/\w{1,20})? Safari/"),
    ("Internet Explorer", r"\bMSIE (\d+(?:\.\d+)?)|\bTrident/\d+(?:\.\d+)?;[^)]{0,100}?\brv:(\d+(?:\.\d+)?)"),
]
UA_OS = [
    ("iOS", r"\((?:iPhone|iPad|iPod)[^)]{0,80}? OS (\d{1,10}(?:_\d{1,10}){0,3})"),
    ("Android", r"\bAndroid (\d{1,10}(?:\.\d{1,10}){0,3})"),
    ("Windows", r"\bWindows NT (\d+\.\d+)"),
    ("macOS", r"\bMac OS X (\d{1,10}(?:[_.]\d{1,10}){0,3})"),
    ("ChromeOS", r"\bCrOS\b"),
    ("Linux", r"\bLinux\b|\bX11\b"),
]
WINDOWS_NT = {"10.0": "10/11", "6.3": "8.1", "6.2": "8", "6.1": "7", "6.0": "Vista", "5.1": "XP", "5.0": "2000"}
UA_GOOD_BOTS = [
    ("Googlebot", r"\bGooglebot\b|\bGoogle-InspectionTool\b|\bAdsBot-Google\b"),
    ("Bingbot", r"\bbingbot\b|\bBingPreview\b"),
    ("Applebot", r"\bApplebot\b"),
    ("YandexBot", r"\bYandex(?:Bot|Images)\b"),
    ("DuckDuckBot", r"\bDuckDuckBot\b"),
    ("Baiduspider", r"\bBaiduspider\b"),
    ("facebookexternalhit", r"\bfacebookexternalhit\b|\bmeta-externalagent\b"),
    ("Twitterbot", r"\bTwitterbot\b"),
    ("LinkedInBot", r"\bLinkedInBot\b"),
    ("Slackbot", r"\bSlackbot\b"),
    ("GPTBot", r"\bGPTBot\b|\bChatGPT-User\b|\bOAI-SearchBot\b"),
    ("ClaudeBot", r"\bClaudeBot\b|\banthropic-ai\b|\bClaude-User\b"),
    ("PerplexityBot", r"\bPerplexityBot\b"),
    ("AhrefsBot", r"\bAhrefsBot\b"),
    ("SemrushBot", r"\bSemrushBot\b"),
    ("CCBot", r"\bCCBot\b"),
    ("Bytespider", r"\bBytespider\b"),
    ("PetalBot", r"\bPetalBot\b"),
    # link-preview agents (Crawler-Detect lists them too, e.g. 'WhatsApp'): bots, never scanners
    ("WhatsApp link preview", r"^WhatsApp/"),
    ("TelegramBot", r"\bTelegramBot\b"),
    ("Discordbot", r"\bDiscordbot\b"),
    ("SkypeUriPreview", r"\bSkypeUriPreview\b"),
]
UA_RESEARCH_SCANNERS = [  # benign_scanner: identified research/attack-surface scanners
    ("Censys", r"\bCensysInspect\b|\bcensys\.io\b"),
    ("Palo Alto Cortex Xpanse", r"^Expanse\b|Palo Alto Networks"),
    ("InternetMeasurement", r"\bInternetMeasurement\b|internet-measurement\.com"),
    ("LeakIX", r"\bl9explore\b|\bl9tcpid\b|\bleakix\.net\b"),
    ("Netcraft", r"\bNETCRAFT\b|\bNetcraftSurveyAgent\b"),
    ("Shadowserver", r"\bshadowserver\b"),
    ("ONYPHE", r"\bonyphe\b"),
    ("BinaryEdge", r"\bbinaryedge\b"),
    ("Modat", r"\bModatScanner\b"),
]
UA_ATTACK_TOOLS = [  # scanner: offensive / vulnerability scanning tools (never 'malicious')
    ("sqlmap", r"\bsqlmap/"),
    ("Nuclei", r"\bnuclei\b"),
    ("masscan", r"\bmasscan\b"),
    ("Nikto", r"\bNikto\b"),
    ("Nmap NSE", r"Nmap Scripting Engine|\bnmap\.org\b"),
    ("ZGrab", r"\bzgrab\b"),
    ("WPScan", r"\bWPScan\b"),
    ("DirBuster", r"\bDirBuster\b"),
    ("gobuster", r"\bgobuster\b"),
    ("ffuf", r"\bFuzz Faster U Fool\b|\bffuf\b"),
    ("feroxbuster", r"\bferoxbuster\b"),
    ("Hydra", r"\(Hydra\)"),
    ("Acunetix", r"\bAcunetix\b"),
    ("Nessus", r"\bNessus\b"),
    ("OpenVAS", r"\bOpenVAS\b"),
    ("w3af", r"\bw3af\b"),
    ("Wfuzz", r"\bWfuzz\b"),
    ("commix", r"\bcommix\b"),
    ("Arachni", r"\bArachni\b"),
    ("Netsparker/Invicti", r"\bNetsparker\b|\bInvicti\b"),
    ("Jaeles", r"\bJaeles\b"),
    ("ZmEu", r"\bZmEu\b"),
    ("Log4Shell probe", r"\$\{jndi:"),
]
UA_HTTP_LIBS = [  # automation clients (tag 'bot', category 'automation')
    ("curl", r"^curl/"), ("Wget", r"^Wget/"), ("python-requests", r"\bpython-requests/"),
    ("python-httpx", r"\bpython-httpx/"), ("aiohttp", r"\baiohttp/"), ("Python-urllib", r"\bPython-urllib/"),
    ("Go-http-client", r"\bGo-http-client/"), ("okhttp", r"\bokhttp/"), ("axios", r"\baxios/"),
    ("Java", r"^Java/|\bJava-http-client/"), ("libwww-perl", r"\blibwww-perl/"),
    ("node-fetch", r"\bnode-fetch\b|^undici\b"), ("PowerShell", r"\bWindowsPowerShell/"),
]
UA_TABLE_GROUPS = (("browser", UA_BROWSERS), ("os", UA_OS), ("good_bot", UA_GOOD_BOTS),
                   ("research_scanner", UA_RESEARCH_SCANNERS), ("attack_tool", UA_ATTACK_TOOLS),
                   ("http_lib", UA_HTTP_LIBS))
_COMPILED = {g: [(n, re.compile(p, re.I)) for n, p in rules] for g, rules in UA_TABLE_GROUPS}
_MOBILE_RE = re.compile(r"\bMobile\b|\biPhone\b|\biPod\b|\bWindows Phone\b", re.I)
_TABLET_RE = re.compile(r"\biPad\b|\bTablet\b", re.I)


def ua_table_patterns():
    """All own-table regexes (for the ReDoS fuzz test, P317-FC3)."""
    return [p for _, rules in UA_TABLE_GROUPS for _, p in rules]


def _first(group, ua):
    for name, rx in _COMPILED[group]:
        m = rx.search(ua)
        if m:
            ver = next((g for g in m.groups() if g), None) if m.groups() else None
            return name, ver
    return None, None


def classify_user_agent(ua, crawler_matcher=None):
    """Offline UA analysis (P317-FC1/FC3/FC4).

    Returns {'ua' (truncated), 'truncated', 'category': browser|bot|automation|scanner|
    benign_scanner|empty|unknown, 'tags', 'browser', 'browser_version', 'os', 'os_version',
    'device': desktop|mobile|tablet|bot|None, 'tool', 'bad_crawler_match', 'exploit_probe',
    'severity', 'risk_ceiling': 'LOW', 'never_malicious': True}. Scanner and attack-tool UAs
    are tagged 'scanner' (known research scanners 'benign_scanner'), never 'malicious'; a UA
    alone never raises an IP's risk above LOW.
    """
    text, truncated = truncate_ua(ua)
    res = {"ua": text, "truncated": truncated, "category": "unknown", "tags": [], "browser": None,
           "browser_version": None, "os": None, "os_version": None, "device": None, "tool": None,
           "bad_crawler_match": False, "exploit_probe": None, "severity": "info",
           "risk_ceiling": UA_RISK_CEILING, "never_malicious": True}
    if not text.strip():
        res["category"] = "empty"
        return res
    res["browser"], res["browser_version"] = _first("browser", text)
    os_name, os_ver = _first("os", text)
    if os_name == "Windows" and os_ver:
        os_ver = WINDOWS_NT.get(os_ver, os_ver)
    elif os_name in ("iOS", "macOS") and os_ver:
        os_ver = os_ver.replace("_", ".")
    res["os"], res["os_version"] = os_name, os_ver
    if _TABLET_RE.search(text) or (os_name == "Android" and not _MOBILE_RE.search(text)):
        res["device"] = "tablet"
    elif _MOBILE_RE.search(text):
        res["device"] = "mobile"
    elif res["browser"]:
        res["device"] = "desktop"
    if crawler_matcher is not None:
        try:
            res["bad_crawler_match"] = bool(crawler_matcher.search(text))
        except (TypeError, AttributeError):
            res["bad_crawler_match"] = False
    research, _ = _first("research_scanner", text)
    tool, _ = _first("attack_tool", text)
    goodbot, _ = _first("good_bot", text)
    lib, _ = _first("http_lib", text)
    if research:
        res["category"], res["tool"], res["tags"] = "benign_scanner", research, ["benign_scanner"]
    elif tool:
        res["category"], res["tool"], res["tags"] = "scanner", tool, ["scanner"]
        res["severity"] = "low"
        if tool == "Log4Shell probe":
            res["exploit_probe"] = "log4shell_jndi"
    elif goodbot:
        res["category"], res["tool"], res["tags"] = "bot", goodbot, ["bot"]
        res["device"] = "bot"
    elif lib:
        res["category"], res["tool"], res["tags"] = "automation", lib, ["bot"]
        res["device"] = "bot"
    elif res["bad_crawler_match"]:
        res["category"], res["tags"] = "automation", ["bot"]
        res["device"] = "bot"
    elif res["browser"]:
        res["category"] = "browser"
    return res


def regex_time_ms(pattern, inputs, flags=re.I):
    """Worst-case search time in ms of ``pattern`` over ``inputs`` (ReDoS timing screen,
    P317-FC3). Call only after ``redos_static_flags`` found nothing in REDOS_REJECT: Python's
    re cannot be interrupted, so a catastrophic pattern must never reach this function."""
    rx = re.compile(pattern, flags) if isinstance(pattern, str) else pattern
    worst = 0.0
    for s in inputs:
        t0 = time.perf_counter()
        rx.search(s)
        worst = max(worst, (time.perf_counter() - t0) * 1000.0)
    return worst


def adversarial_uas(limit=UA_MAX_BYTES):
    """Adversarial 1 KB UA strings for the ReDoS fuzz test (P317-FC3)."""
    base = ["a" * limit, "A/" * (limit // 2), ("Mozilla/5.0 " * 100)[:limit], "-" * limit,
            "1" * limit, ("x" * 50 + " ") * (limit // 51), "(" * limit, ";" * limit,
            ("Mozilla/5.0 (Windows NT 10.0; " * 40)[:limit], ("bot" * 400)[:limit]]
    return [s[:limit] for s in base]


# ---------------------------------------------------------------------------------------
# 5. P318 card_bin - PAN minimisation (AR24) + binlist.net lookup
# ---------------------------------------------------------------------------------------

BINLIST_HOST = "lookup.binlist.net"
BINLIST_HEADERS = {"Accept-Version": "3"}
_PAN_RE = re.compile(r"(?<![\d.,/-])(?:\d[ -]?){12,18}\d(?![\d,/]|\.\d)")
_SCHEMES = [  # offline scheme guess from the IIN (informational only)
    ("elo", r"^(?:4011(?:78|79)|43(?:1274|8935)|45(?:1416|7393|763[12])|50(?:4175|6699|67[0-7]\d|9\d{3})"
            r"|627780|636(?:297|368)|650(?:0(?:3[1-3]|[4-9]\d)|4(?:0[5-9]|[1-3]\d)|48[5-9]|49\d|5[0-2]\d|538)"
            r"|6516(?:5[2-9]|6\d|7[0-9])|6550(?:[01]\d|2[0-5]))"),
    ("hipercard", r"^(?:606282|3841(?:[046]0))"),
    ("amex", r"^3[47]"),
    ("diners", r"^3(?:0[0-5]|[68])"),
    ("jcb", r"^35(?:2[89]|[3-8]\d)"),
    ("discover", r"^(?:6011|65|64[4-9])"),
    ("mastercard", r"^(?:5[1-5]|2(?:2[2-9][1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720))"),
    ("visa", r"^4"),
]
_SCHEMES_C = [(n, re.compile(p)) for n, p in _SCHEMES]


def scheme_guess(digits):
    """Offline card scheme guess from the leading digits (informational, P318-FC5)."""
    d = digits_only(digits)
    for name, rx in _SCHEMES_C:
        if rx.match(d):
            return name
    return None


def truncate_pan(pan):
    """Truncate a full card number at parse time (P318-FC1, AR24): returns {'bin6', 'bin8'
    (16+ digit PANs only), 'last4', 'display' (BIN6 + last 4), 'length', 'luhn_valid',
    'scheme_guess'} - never the PAN itself. None for anything that is not 13-19 digits."""
    d = digits_only(pan)
    if not 13 <= len(d) <= 19:
        return None
    return {"bin6": d[:6], "bin8": d[:8] if len(d) >= 16 else None, "last4": d[-4:],
            "display": d[:6] + "*" * (len(d) - 10) + d[-4:], "length": len(d),
            "luhn_valid": luhn_valid(d), "scheme_guess": scheme_guess(d)}


def find_pans(text):
    """Find card numbers in free text and return only their truncated forms (P318-FC1).

    13-19 digits with optional single spaces/dashes, Luhn-valid, with a known scheme prefix
    (drops CNPJ/phone/order numbers). The full PAN never leaves this function.
    """
    out = []
    if not isinstance(text, str):
        return out
    for m in _PAN_RE.finditer(text[:2_000_000]):
        d = digits_only(m.group(0))
        if not 13 <= len(d) <= 19 or not luhn_valid(d) or scheme_guess(d) is None:
            continue
        t = truncate_pan(d)
        t["span"] = [m.start(), m.end()]
        out.append(t)
    return out


def mask_pans_in_text(text):
    """Replace every detected PAN in ``text`` by its BIN6 + last-4 display (P318-FC1, AR24)."""
    if not isinstance(text, str):
        return ""

    def _sub(m):
        d = digits_only(m.group(0))
        if 13 <= len(d) <= 19 and luhn_valid(d) and scheme_guess(d):
            return truncate_pan(d)["display"]
        return m.group(0)
    return _PAN_RE.sub(_sub, text)


def normalize_card_bin(value):
    """Normalise a card_bin input (P318-FC1/FC2). Returns {'bin', 'bin6', 'truncated_from'} or
    None. 6-8 digits are a BIN; 13-19 Luhn-valid digits are a PAN -> truncated to its BIN (the
    PAN is dropped); 9-12 digits are cut to 8 and flagged. Never more than 8 digits survive."""
    d = digits_only(value)
    if 6 <= len(d) <= 8:
        return {"bin": d, "bin6": d[:6], "truncated_from": None}
    if 9 <= len(d) <= 12:
        return {"bin": d[:8], "bin6": d[:6], "truncated_from": "partial_number"}
    if 13 <= len(d) <= 19:
        t = truncate_pan(d)
        b = t["bin8"] or t["bin6"]
        return {"bin": b, "bin6": t["bin6"], "truncated_from": "pan", "display": t["display"]}
    return None


def binlist_request(card_bin, digits=6):
    """(url, headers) for GET https://lookup.binlist.net/<BIN> with Accept-Version: 3 (P318-FC2).

    Sends 6 digits by default (binlist's free tier: 8-digit BINs are a paid feature, and 6 is
    the minimum disclosure); raises ValueError for anything that is not a 6-8 digit BIN.
    """
    d = digits_only(card_bin)
    if not 6 <= len(d) <= 8 or digits not in (6, 8):
        raise ValueError("only a 6-8 digit BIN may leave the host")
    return "https://%s/%s" % (BINLIST_HOST, d[:digits]), dict(BINLIST_HEADERS)


def binlist_marker(status, body, headers=None):
    """Classify a binlist answer (P318-FC3; P321): 404 -> absent (documented 'no matching
    cards'), HTTP 200 with every field empty -> absent (observed live for '100000'), 400 ->
    error (invalid BIN input; observed live for '000000' with an empty body), 429 ->
    rate_limited (5/hour per IP; never 'unknown BIN'), 403 / Cloudflare challenge -> blocked,
    5xx / HTML / malformed -> error. Only 'absent' may be worded as 'no data at binlist'."""
    text = as_text(body, 65536)
    title = html_title(text).lower()
    if status == 429:
        return "rate_limited: binlist 5 requests/hour per IP exhausted (HTTP 429)"
    if status == 403 or "just a moment" in title or "attention required" in title or "cf-chl" in text[:65536]:
        return "blocked: challenge: Cloudflare challenge or 403 at lookup.binlist.net"
    if status == 404:
        return "absent: BIN not found at binlist (not proof that the BIN is invalid)"
    if status == 400:
        return "error: binlist rejected the BIN as invalid input (HTTP 400)"
    if isinstance(status, int) and status >= 400:
        return "error: binlist HTTP %s" % status
    obj, problem = load_json(body)
    if problem == "html":
        return "error: binlist answered HTML instead of JSON"
    if problem:
        return "error: binlist body %s" % problem
    if not isinstance(obj, dict) or not ({"scheme", "type", "brand", "country", "bank"} & set(obj)):
        return "error: unexpected binlist JSON shape"
    parsed = parse_binlist(obj)
    if not parsed or not any(parsed.get(k) for k in ("scheme", "type", "brand", "country_alpha2", "bank_name")):
        # observed live 2026-11-26 for BIN 100000: HTTP 200 {"number":null,"country":{},"bank":{}}
        return "absent: binlist has no issuer data for this BIN (HTTP 200 with empty fields; not proof that the BIN is invalid)"
    return None


def parse_binlist(body):
    """Issuer context of a BIN (P318-FC5, INFO): scheme, type, brand, prepaid, country (alpha2,
    name, numeric, currency), bank (name, url, phone, city), number length/luhn. The country
    centroid lat/long and the flag emoji are dropped. None for unusable bodies."""
    obj, problem = load_json(body)
    if problem or not isinstance(obj, dict):
        return None
    s = lambda d, k: d.get(k) if isinstance(d, dict) and isinstance(d.get(k), str) and d.get(k) else None  # noqa: E731
    country = obj.get("country") if isinstance(obj.get("country"), dict) else {}
    bank = obj.get("bank") if isinstance(obj.get("bank"), dict) else {}
    number = obj.get("number") if isinstance(obj.get("number"), dict) else {}
    prepaid = obj.get("prepaid") if isinstance(obj.get("prepaid"), bool) else None
    out = {
        "scheme": s(obj, "scheme"), "type": s(obj, "type"), "brand": s(obj, "brand"), "prepaid": prepaid,
        "country_alpha2": s(country, "alpha2"), "country_name": s(country, "name"),
        "country_numeric": s(country, "numeric"), "currency": s(country, "currency"),
        "bank_name": s(bank, "name"), "bank_url": s(bank, "url"), "bank_phone": s(bank, "phone"),
        "bank_city": s(bank, "city"),
        "number_length": number.get("length") if isinstance(number.get("length"), int) else None,
        "number_luhn": number.get("luhn") if isinstance(number.get("luhn"), bool) else None,
    }
    return out if any(v is not None for v in out.values()) else None


def own_bin_match(card_bin, org_card_bins):
    """P318-FC5: 'own' when the BIN falls inside an org_profile card_bins prefix, 'possible_own'
    when a 6-digit BIN only covers a longer org prefix, else None."""
    d = digits_only(card_bin)
    if not 6 <= len(d) <= 8 or not org_card_bins:
        return None
    result = None
    for raw in org_card_bins:
        p = digits_only(raw)
        if not 6 <= len(p) <= 8:
            continue
        if d.startswith(p):
            return "own"
        if p.startswith(d):
            result = "possible_own"
    return result


def pan_leak_offenders(blob, pans):
    """Grep helper for the PCI test (P318-FC1): which of ``pans`` (full numbers known only to the
    test) appear in ``blob`` (cache rows, evidence, logs, case DB dump) contiguous, spaced in
    groups of four or dashed. Returns the list of offending last-4 displays (never the PAN)."""
    text = as_text(blob)
    hits = []
    for pan in pans:
        d = digits_only(pan)
        if not d:
            continue
        forms = {d, " ".join(d[i:i + 4] for i in range(0, len(d), 4)), "-".join(d[i:i + 4] for i in range(0, len(d), 4))}
        if any(f in text for f in forms):
            hits.append("****" + d[-4:])
    return hits


# ---------------------------------------------------------------------------------------
# 6. P319 imei_check - TAC -> model lookup at imeidb.xyz (keyed, opt-in)
# ---------------------------------------------------------------------------------------

IMEIDB_HOST = "imeidb.xyz"
IMEIDB_KEY_ENV = "V3LUM_IMEIDB_TOKEN"
REPORTING_BODIES = {  # informational; the core validators own the offline IMEI facts (P319-FC1)
    "00": "test IMEI", "01": "PTCRB (US)", "30": "Iridium", "33": "DGPT (FR)", "35": "BABT (UK)",
    "44": "BABT (UK)", "45": "NTA (DK)", "49": "BZT/BAPT (DE)", "50": "BZT ETS (DE)",
    "51": "Cetecom ICT (DE)", "52": "Cetecom (DE)", "53": "TUV (DE)", "54": "Phoenix Test Lab (DE)",
    "86": "TAF (CN)", "91": "MSAI (IN)", "98": "BABT (UK)", "99": "GHA (3GPP2)",
}


def imei_parse(value):
    """Offline IMEI facts (P319-FC1; the core validator is the reference): {'digits_len',
    'kind': imei|imei14|imeisv, 'luhn_valid', 'tac', 'reporting_body', 'masked'}. None for
    non-IMEI input. The serial is never returned."""
    d = digits_only(value)
    if len(d) == 15:
        kind, valid = "imei", luhn_valid(d)
    elif len(d) == 14:
        kind, valid = "imei14", None
    elif len(d) == 16:
        kind, valid = "imeisv", None
    else:
        return None
    return {"digits_len": len(d), "kind": kind, "luhn_valid": valid, "tac": d[:8],
            "reporting_body": REPORTING_BODIES.get(d[:2]), "masked": mask_imei(d)}


def mask_imei(value):
    """Mask an IMEI for reports: TAC (device model) kept, serial and check digit masked:
    '35389310*******' (P319-FC1)."""
    d = digits_only(value)
    if len(d) not in (14, 15, 16):
        return None
    return d[:8] + "*" * (len(d) - 8)


def imei_tac_probe(value):
    """The only IMEI form that may leave the machine (P319-FC3): TAC + '000000' + recomputed
    Luhn digit. Raises ValueError when no 8-digit TAC can be taken from ``value``."""
    d = digits_only(value)
    if len(d) < 8 or len(d) > 16:
        raise ValueError("no TAC")
    first14 = d[:8] + "000000"
    return first14 + luhn_check_digit(first14)


def imeidb_request(probe, token):
    """(url, headers) for the imeidb.xyz lookup (P319-FC2/FC3): the token goes in X-Api-Key,
    never in the URL (AR01); only a TAC probe (serial 000000 + valid Luhn digit) is accepted.
    Raises ValueError otherwise (no token -> the module reports NEEDS_KEY before building)."""
    d = digits_only(probe)
    if len(d) != 15 or d[8:14] != "000000" or not luhn_valid(d):
        raise ValueError("only the TAC probe (TAC + 000000 + Luhn) may be sent")
    if not isinstance(token, str) or not token.strip():
        raise ValueError("missing token")
    return "https://%s/api/imei/%s?format=json" % (IMEIDB_HOST, d), {"X-Api-Key": token.strip(),
                                                                     "Accept": "application/json"}


def imeidb_marker(status, body):
    """Classify an imeidb.xyz answer from its documented error codes (P319-FC2): 401 ->
    needs_key, 402 -> quota (balance exhausted), 429 -> rate_limited, 460 -> error (invalid
    IMEI), success:false with a not-found message -> absent, HTML/malformed -> error."""
    obj, problem = load_json(body)
    code = obj.get("code") if isinstance(obj, dict) and isinstance(obj.get("code"), int) else None
    eff = code if code is not None else status
    msg = str(obj.get("message"))[:200] if isinstance(obj, dict) and obj.get("message") else ""
    if eff == 401 or status == 401:
        return "needs_key: imeidb.xyz rejected the token (401%s)" % (": " + msg if msg else "")
    if eff == 402 or status == 402:
        return "quota: imeidb.xyz balance exhausted (402%s)" % (": " + msg if msg else "")
    if eff == 429 or status == 429:
        return "rate_limited: imeidb.xyz rate limit exceeded (429)"
    if eff == 460 or status == 460:
        return "error: imeidb.xyz rejected the IMEI (460 Invalid IMEI)"
    if problem == "html":
        return "error: imeidb.xyz answered HTML instead of JSON"
    if problem:
        return "error: imeidb.xyz body %s" % problem
    if isinstance(status, int) and status >= 400:
        return "error: imeidb.xyz HTTP %s" % status
    if not isinstance(obj, dict):
        return "error: unexpected imeidb.xyz JSON shape"
    if obj.get("success") is False:
        if re.search(r"not (?:be )?found|does not exist|no data|unknown", msg, re.I):
            return "absent: TAC not in imeidb.xyz"
        return "error: imeidb.xyz error%s" % (": " + msg if msg else "")
    if not isinstance(obj.get("data"), dict):
        return "error: imeidb.xyz answer without data"
    return None


def parse_imeidb(body):
    """Device model facts for the TAC (P319-FC2/FC3): tac, name, brand, model, models,
    manufacturer, device_type, os, os_family, sim_slots, nettech, aliases. Probe-specific
    fields (query, serial, controlNumber, valid, blacklist) and the device image URL are
    dropped: they describe the synthetic probe, not the investigated device."""
    obj, problem = load_json(body)
    if problem or not isinstance(obj, dict) or obj.get("success") is False:
        return None
    data = obj.get("data") if isinstance(obj.get("data"), dict) else None
    if data is None:
        return None
    spec = data.get("device_spec") if isinstance(data.get("device_spec"), dict) else {}
    s = lambda d, k: d.get(k) if isinstance(d.get(k), str) and d.get(k) else None  # noqa: E731
    strs = lambda v: [x for x in v if isinstance(x, str)][:20] if isinstance(v, list) else []  # noqa: E731
    tac = data.get("tac")
    tac = str(tac) if isinstance(tac, (int, str)) and not isinstance(tac, bool) and len(digits_only(tac)) == 8 else None
    out = {
        "tac": tac, "name": s(data, "name"), "brand": s(data, "brand"), "model": s(data, "model"),
        "models": strs(data.get("models")), "manufacturer": s(data, "manufacturer"),
        "device_type": s(data, "type"), "os": s(spec, "os"), "os_family": s(spec, "os_family"),
        "sim_slots": spec.get("sim_slots") if isinstance(spec.get("sim_slots"), int) else None,
        "nettech": strs(spec.get("nettech")), "aliases": strs(spec.get("aliases")),
    }
    return out if (out["brand"] or out["model"] or out["name"]) else None
