"""Card BIN lookup at binlist.net: scheme, type, brand, issuer and country of a BIN (P318, batch p3-G12-1).

Final conditions, as implemented here:

1. **PCI minimisation** - the core guarantees it at parse time: card numbers in any input become
   ``payment_card`` entities holding only BIN6...last4 (AR24, ``v3lum.core.entities``; the extraction engine and
   detection never keep the PAN) and a ``card_bin`` entity holds 6-8 digits only (a longer value is refused by
   the core normalizer). Luhn is checked offline (``v3lum.core.validators.luhn_valid``). This module accepts
   only ``card_bin``; :func:`truncate_pan`/:func:`mask_pans_in_text` are offline helpers for parsers, and the
   test suite greps the cache, evidence, logs and the case DB of a scan of a text holding PANs.
2. **Only the BIN leaves the host**: 6 digits by default (8-digit BINs are a paid binlist feature and 6 is the
   minimum disclosure), to ``lookup.binlist.net`` with ``Accept-Version: 3``. binlist.net publishes no terms
   of service: the registry records the home-page evidence with class ``unknown``, so the module stays off
   (``default_enabled=False``, A3) and the corporate licence profile never runs it until legal records
   business-compatible terms or a paid plan.
3. **Rate**: provider bucket of 5 requests per hour per IP (hour-window quota, P334; quota status in coverage);
   429 -> RATE_LIMITED, never 'unknown BIN'; cache 30 days (absences included).
4. The binlist/data ranges.csv seed (class unknown) and FreeBINChecker (Cloudflare Turnstile) are not used; a
   miss is never 'unknown BIN'.
5. Output: scheme, type, brand, prepaid, issuer and country as card-fraud triage context (INFO). BINs of the
   organisation's own ``card_bins`` (org profile) are tagged ``own_asset``.
6. Merge gate: offline tests over trimmed real binlist captures plus a 429 sample (tests/fixtures/card_bin/).
"""

from __future__ import annotations

import re
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.validators import luhn_valid

SOURCE = "binlist.lookup"
HOST = "lookup.binlist.net"
API = "https://lookup.binlist.net/{bin}"
HEADERS = {"Accept-Version": "3"}
CACHE_TTL = 30 * 86400

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


def _digits(value: Any) -> str:
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        value = str(value)
    return "".join(ch for ch in value if "0" <= ch <= "9") if isinstance(value, str) else ""


def scheme_guess(digits: Any) -> str | None:
    """Offline card scheme guess from the leading digits (informational)."""
    d = _digits(digits)
    for name, rx in _SCHEMES_C:
        if rx.match(d):
            return name
    return None


def truncate_pan(pan: Any) -> dict[str, Any] | None:
    """BIN6 / BIN8 / last 4 / display (BIN6 + last 4) of a 13-19 digit card number - never the PAN itself."""
    d = _digits(pan)
    if not 13 <= len(d) <= 19:
        return None
    return {"bin6": d[:6], "bin8": d[:8] if len(d) >= 16 else None, "last4": d[-4:],
            "display": d[:6] + "*" * (len(d) - 10) + d[-4:], "length": len(d), "luhn_valid": luhn_valid(d),
            "scheme_guess": scheme_guess(d)}


def find_pans(text: Any) -> list[dict[str, Any]]:
    """Card numbers in free text, returned only in truncated form (Luhn-valid, known scheme prefix)."""
    out: list[dict[str, Any]] = []
    if not isinstance(text, str):
        return out
    for m in _PAN_RE.finditer(text[:2_000_000]):
        d = _digits(m.group(0))
        if not 13 <= len(d) <= 19 or not luhn_valid(d) or scheme_guess(d) is None:
            continue
        t = truncate_pan(d)
        if t is not None:
            t["span"] = [m.start(), m.end()]
            out.append(t)
    return out


def mask_pans_in_text(text: Any) -> str:
    """Replace every detected card number by its BIN6 + last-4 display (AR24)."""
    if not isinstance(text, str):
        return ""

    def _sub(m: re.Match[str]) -> str:
        d = _digits(m.group(0))
        if 13 <= len(d) <= 19 and luhn_valid(d) and scheme_guess(d):
            t = truncate_pan(d)
            return t["display"] if t else m.group(0)
        return m.group(0)
    return _PAN_RE.sub(_sub, text)


def binlist_url(card_bin: Any, digits: int = 6) -> str:
    """The lookup URL; raises ValueError for anything that is not a 6-8 digit BIN (FC2)."""
    d = _digits(card_bin)
    if not 6 <= len(d) <= 8 or digits not in (6, 8) or len(d) < digits:
        raise ValueError("only a 6-8 digit BIN may leave the host")
    return API.format(bin=d[:digits])


def parse_binlist(obj: Any) -> dict[str, Any] | None:
    """Issuer context of a BIN: scheme, type, brand, prepaid, country, bank, number; centroid/emoji dropped."""
    if not isinstance(obj, dict):
        return None

    def s(d: Any, k: str) -> str | None:
        v = d.get(k) if isinstance(d, dict) else None
        return v.strip()[:200] if isinstance(v, str) and v.strip() else None

    country = obj.get("country") if isinstance(obj.get("country"), dict) else {}
    bank = obj.get("bank") if isinstance(obj.get("bank"), dict) else {}
    number = obj.get("number") if isinstance(obj.get("number"), dict) else {}
    length = number.get("length")
    info = {
        "scheme": s(obj, "scheme"), "type": s(obj, "type"), "brand": s(obj, "brand"),
        "prepaid": obj.get("prepaid") if isinstance(obj.get("prepaid"), bool) else None,
        "country": {k: v for k, v in {"alpha2": s(country, "alpha2"), "name": s(country, "name"),
                                      "numeric": s(country, "numeric"), "currency": s(country, "currency")}.items() if v},
        "bank": {k: v for k, v in {"name": s(bank, "name"), "url": s(bank, "url"), "phone": s(bank, "phone"),
                                   "city": s(bank, "city")}.items() if v},
        "number": {k: v for k, v in {"length": length if isinstance(length, int) and not isinstance(length, bool) else None,
                                     "luhn": number.get("luhn") if isinstance(number.get("luhn"), bool) else None}.items()
                   if v is not None},
    }
    return info


def has_issuer_data(info: dict[str, Any] | None) -> bool:
    return bool(info) and any((info.get("scheme"), info.get("type"), info.get("brand"),
                               (info.get("country") or {}).get("alpha2"), (info.get("bank") or {}).get("name")))


def own_bin_match(card_bin: Any, org_card_bins: Any) -> str | None:
    """'own' when the BIN falls inside an org card_bins prefix, 'possible_own' when it only covers one."""
    d = _digits(card_bin)
    if not 6 <= len(d) <= 8 or not org_card_bins:
        return None
    result = None
    for raw in org_card_bins:
        p = _digits(raw)
        if not 6 <= len(p) <= 8:
            continue
        if d.startswith(p):
            return "own"
        if p.startswith(d):
            result = "possible_own"
    return result


@register
class CardBin(Module):
    name = "card_bin"
    title = "Card BIN lookup (binlist.net)"
    description = ("Scheme, type, brand, issuer and country of a card BIN (first 6 digits only) from binlist.net, as "
                   "card-fraud triage context; full card numbers never leave the machine.")
    category = "utility"
    accepts = {T.CARD_BIN}
    produces = frozenset()
    reference = "https://binlist.net/"
    notice = ("binlist.net publishes no terms of service: terms class 'unknown', off under every profile until legal "
              "records business-compatible terms or a paid plan. Only the 6-digit BIN is sent; 5 requests/hour per IP.")
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = (HOST,)
    provider = "binlist"
    sources = (SOURCE,)
    access_model = "free_noauth_limited"
    absent_statuses = frozenset({404})  # documented: 'If no matching cards are found an HTTP 404 response is returned'
    max_requests = 1
    expected_latency = 0.8
    timeout = 20.0
    cache_ttl = CACHE_TTL
    max_pivots = 0
    default_enabled = False  # council: True; FC2 + A3: unknown terms keep it off

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        digits = _digits(entity.value)
        if not 6 <= len(digits) <= 8:  # defence in depth: the core card_bin normalizer refuses longer values
            return res.mark(Status.SKIPPED, "not a 6-8 digit BIN: nothing is sent", reason_code="not_applicable")
        url = binlist_url(digits, 6)
        data = ctx.http.get_json(url, headers=dict(HEADERS), source=SOURCE, ttl=CACHE_TTL)
        if data is None:  # 404: documented 'no matching cards'
            return res.mark(Status.EMPTY, "binlist has no data for this BIN (not proof that the BIN is invalid)")
        if not isinstance(data, dict):
            return res.mark(Status.ERROR, "unexpected binlist answer: could not verify")
        info = parse_binlist(data)
        if not has_issuer_data(info):
            # seen live for BIN 100000: HTTP 200 {"number": null, "country": {}, "bank": {}}
            return res.mark(Status.EMPTY, "binlist has no issuer data for this BIN (HTTP 200 with empty fields; not proof that the BIN is invalid)")
        assert info is not None
        res.raw = {"bin": digits[:6], "info": info}
        res.attr("card_bin_info", info)
        res.attr("card_scheme", info.get("scheme"))
        res.attr("card_type", info.get("type"))
        res.attr("card_issuer", (info.get("bank") or {}).get("name"))
        res.attr("country", (info.get("country") or {}).get("alpha2"))
        tags = ["info"]
        own = own_bin_match(digits, getattr(getattr(ctx, "org", None), "card_bins", None))
        if own == "own":
            tags.append("own_asset")
        parts = [p for p in (info.get("scheme"), info.get("type"), info.get("brand")) if p]
        country = (info.get("country") or {}).get("name") or (info.get("country") or {}).get("alpha2")
        issuer = (info.get("bank") or {}).get("name")
        desc = (f"BIN {digits[:6]}: {' / '.join(parts) or 'scheme unknown'}"
                + (f", issued in {country}" if country else "") + (f" by {issuer}" if issuer else "")
                + ". Triage context only (binlist.net community data).")
        if own == "possible_own":
            desc += " The 6-digit BIN covers one of the organisation's own longer BIN prefixes (possible own card)."
        res.finding("Card BIN issuer context", "info", desc, confidence="probable",
                    criterion="binlist.net IIN data for the 6-digit BIN (community data; bank fields often empty)",
                    data={"scheme": info.get("scheme"), "type": info.get("type"), "country": country,
                          "own": own}, tags=tags, source=SOURCE)
        return res
