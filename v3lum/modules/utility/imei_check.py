"""IMEI TAC -> device model lookup at imeidb.xyz (P319, batch p3-G12-1).

Final conditions, as implemented here:

1. Offline IMEI validation stays in the core: the ``imei`` entity normalizer accepts only 15 digits with a valid
   Luhn digit (``v3lum.core.validators.luhn_valid``) and runs always, with no module. IMEIs are PERSONAL_TYPES:
   this module never prints the serial (``imei_masked`` = TAC + '*******'), tags its finding ``privacy`` and
   keeps the full IMEI out of attributes, evidence, URLs and cache keys (masking in reports and exports is a
   core request: ``entities.display_value`` does not mask IMEIs yet).
2. The module is only the online TAC lookup: opt-in (``default_enabled=False``), ``requires_keys=('imeidb',)`` -
   the team-account token goes in the ``X-Api-Key`` header (documented by imeidb.xyz), never in URLs, logs or
   cache keys (AR01); 401 -> NEEDS_KEY; 402 -> QUOTA; 429 -> RATE_LIMITED; 460 / HTML / malformed -> ERROR.
3. Legal floor: only the 8-digit TAC leaves the machine. The API needs 15 digits, so it receives TAC + 000000 +
   the recomputed Luhn digit (:func:`tac_probe`), never the real serial; :func:`imeidb_url` refuses anything
   else. Probe-specific fields of the answer (query, serial, check digit, blacklist, image) are dropped: they
   describe the synthetic probe, not the device. Whether imeidb.xyz answers the model from the zero-serial
   probe is unverified until the team captures a success with its token (FC5); if it cannot, the online part
   is dropped (docs/backlog/p3-G12-1.md).
4. A8 gate: imeidb.xyz is recorded as tier ``unknown`` in the provider registry until a reviewer records the
   community tier (operator, terms, track record); the policy gate never sends an unknown-tier provider a
   PERSONAL_TYPES value, so the module receives nothing until then. The full IMEI is never sent anywhere.
5. Merge gate: a real success fixture captured with the team's token is still missing (only the live 401
   exists); the success fixture of the tests is the API documentation example re-keyed to the probe.
"""

from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.core.validators import luhn_valid

SOURCE = "imeidb.tac"
HOST = "imeidb.xyz"
API = "https://imeidb.xyz/api/imei/{probe}"
KEY = "imeidb"
CACHE_TTL = 30 * 86400
REPORTING_BODIES = {  # informational (first two TAC digits)
    "00": "test IMEI", "01": "PTCRB (US)", "30": "Iridium", "33": "DGPT (FR)", "35": "BABT (UK)",
    "44": "BABT (UK)", "45": "NTA (DK)", "49": "BZT/BAPT (DE)", "50": "BZT ETS (DE)",
    "51": "Cetecom ICT (DE)", "52": "Cetecom (DE)", "53": "TUV (DE)", "54": "Phoenix Test Lab (DE)",
    "86": "TAF (CN)", "91": "MSAI (IN)", "98": "BABT (UK)", "99": "GHA (3GPP2)",
}


def _digits(value: Any) -> str:
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        value = str(value)
    return "".join(ch for ch in value if "0" <= ch <= "9") if isinstance(value, str) else ""


def luhn_check_digit(partial: str) -> str:
    """The Luhn check digit completing ``partial`` (digits only)."""
    d = _digits(partial)
    if not d:
        raise ValueError("no digits")
    for c in "0123456789":
        if luhn_valid(d + c):
            return c
    raise ValueError("unreachable")  # pragma: no cover


def mask_imei(value: Any) -> str | None:
    """TAC kept, serial and check digit masked: '35389310*******'."""
    d = _digits(value)
    if len(d) not in (14, 15, 16):
        return None
    return d[:8] + "*" * (len(d) - 8)


def tac_probe(value: Any) -> str:
    """The only IMEI form that may leave the machine (FC3): TAC + '000000' + recomputed Luhn digit."""
    d = _digits(value)
    if len(d) < 8 or len(d) > 16:
        raise ValueError("no TAC")
    first14 = d[:8] + "000000"
    return first14 + luhn_check_digit(first14)


def imeidb_url(probe: str) -> str:
    """The lookup URL for a TAC probe; refuses anything but TAC + 000000 + a valid Luhn digit (FC3). The token
    is never part of it (it travels in the X-Api-Key header)."""
    d = _digits(probe)
    if len(d) != 15 or d[8:14] != "000000" or not luhn_valid(d):
        raise ValueError("only the TAC probe (TAC + 000000 + Luhn) may be sent")
    return API.format(probe=d)


def parse_imeidb(obj: Any) -> dict[str, Any] | None:
    """Device model facts of the TAC; probe-specific fields are dropped. None when nothing usable."""
    if not isinstance(obj, dict) or obj.get("success") is False:
        return None
    data = obj.get("data") if isinstance(obj.get("data"), dict) else None
    if data is None:
        return None
    spec = data.get("device_spec") if isinstance(data.get("device_spec"), dict) else {}

    def s(d: dict[str, Any], k: str) -> str | None:
        v = d.get(k)
        return v.strip()[:200] if isinstance(v, str) and v.strip() else None

    def strs(v: Any) -> list[str]:
        return [x[:100] for x in v if isinstance(x, str)][:20] if isinstance(v, list) else []

    tac = data.get("tac")
    tac_s = str(tac) if isinstance(tac, (int, str)) and not isinstance(tac, bool) and len(_digits(tac)) == 8 else None
    sim = spec.get("sim_slots")
    out = {
        "tac": tac_s, "name": s(data, "name"), "brand": s(data, "brand"), "model": s(data, "model"),
        "models": strs(data.get("models")), "manufacturer": s(data, "manufacturer"), "device_type": s(data, "type"),
        "os": s(spec, "os"), "os_family": s(spec, "os_family"),
        "sim_slots": sim if isinstance(sim, int) and not isinstance(sim, bool) else None,
        "nettech": strs(spec.get("nettech")), "aliases": strs(spec.get("aliases")),
    }
    return out if (out["brand"] or out["model"] or out["name"]) else None


@register
class ImeiCheck(Module):
    name = "imei_check"
    title = "IMEI TAC device lookup (imeidb.xyz)"
    description = ("Device model of an IMEI's 8-digit TAC from imeidb.xyz (team token); only TAC + 000000 + a recomputed "
                   "check digit is sent, never the serial.")
    category = "utility"
    accepts = {T.IMEI}
    produces = frozenset()
    reference = "https://imeidb.xyz/api"
    notice = ("IMEIs are personal data. imeidb.xyz is unknown tier until reviewed: the policy gate sends it nothing; "
              "only the TAC leaves the machine once it is reviewed. Opt-in, team token in the X-Api-Key header.")
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = (HOST,)
    provider = "imeidb"
    sources = (SOURCE,)
    access_model = "free_auth_limited"
    requires_keys = (KEY,)
    max_requests = 1
    expected_latency = 1.5
    timeout = 20.0
    cache_ttl = CACHE_TTL
    max_pivots = 0
    default_enabled = False

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        digits = _digits(entity.value)
        if len(digits) != 15 or not luhn_valid(digits):  # the core normalizer already guarantees it
            return res.mark(Status.SKIPPED, "not a valid IMEI (Luhn): nothing is sent", reason_code="not_applicable")
        tac = digits[:8]
        token = ctx.key(KEY)
        if not token:
            return res.mark(Status.NEEDS_KEY, "imeidb token not configured (v3lum keys set imeidb)", reason_code="needs_key")
        url = imeidb_url(tac_probe(digits))
        resp = ctx.http.get(url, params={"format": "json"}, headers={"X-Api-Key": token, "Accept": "application/json"},
                            source=SOURCE, ttl=CACHE_TTL)
        ctx.http.check(resp)  # 401 -> NEEDS_KEY, 402 -> QUOTA, 429 -> RATE_LIMITED, 460/5xx -> ERROR
        try:
            obj = resp.json()
        except ValueError:
            ctx.http.evict(resp)
            return res.mark(Status.ERROR, "imeidb.xyz answered HTML or malformed JSON instead of the device record: could not verify")
        if not isinstance(obj, dict):
            return res.mark(Status.ERROR, "unexpected imeidb.xyz answer: could not verify")
        if obj.get("success") is False:
            msg = str(obj.get("message") or "")[:160]
            low = msg.lower()
            if any(w in low for w in ("not found", "no data", "does not exist", "unknown")):
                return res.mark(Status.EMPTY, "TAC not in imeidb.xyz (not proof that the IMEI is invalid)")
            return res.mark(Status.ERROR, f"imeidb.xyz error{': ' + msg if msg else ''}: could not verify")
        info = parse_imeidb(obj)
        if info is None:
            return res.mark(Status.ERROR, "imeidb.xyz answer without device data: could not verify")
        info["tac"] = tac
        res.raw = {"tac": tac, "reporting_body": REPORTING_BODIES.get(tac[:2]), "device": info}
        res.attr("imei_tac", tac)
        res.attr("imei_masked", mask_imei(digits))
        res.attr("device_info", info)
        model = info.get("name") or " ".join(x for x in (info.get("brand"), info.get("model")) if x)
        res.finding(
            "Device model of the IMEI's TAC", "info",
            f"TAC {tac} ({REPORTING_BODIES.get(tac[:2]) or 'reporting body unknown'}): {model}"
            + (f", {info['device_type']}" if info.get("device_type") else "")
            + ". A TAC names the model, not the individual device; the serial was never sent.",
            confidence="possible",
            criterion="imeidb.xyz TAC record queried with the TAC probe (TAC + 000000 + Luhn digit)",
            data={"brand": info.get("brand"), "model": info.get("model"), "device_type": info.get("device_type")},
            tags=["info", "privacy"], source=SOURCE,
        )
        return res
