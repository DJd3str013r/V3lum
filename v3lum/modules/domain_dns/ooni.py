"""OONI censorship measurements per domain (P023 ooni): network-interference context from api.ooni.io.

Explains reachability differences (a site blocked in Brazil by court or ANATEL order, DNS tampering, TCP/IP
blocking seen by volunteer probes). Context only: nothing here is a verdict about the domain.

Final conditions (council #1, P023) and where they live:

1. Keyless OONI API (``api.ooni.io``): ``/api/v1/aggregation?domain=&probe_cc=&since=&until=`` gives the counts per
   country and ``/api/v1/measurements?domain=&probe_cc=&limit=50`` the evidence when anomalies or confirmed blocks
   exist; ``metadata.next_url`` is followed to at most :data:`MAX_PAGES` = 2 pages and only to the same API path
   and host (:func:`next_page`). Countries: BR by default plus the case country (setting ``ooni_case_country``);
   only ISO 3166-1 alpha-2 codes are ever sent, because the API answers an invalid ``probe_cc`` with HTTP 200
   and an empty list (verified live). ``domain=`` matches the exact host: for a host without ``www.`` and no
   measurements, ``www.<host>`` is tried once (:func:`domain_variants`). The window is the API default made
   explicit (last 30 days, day-stable cache keys).
   Measurement pages are fetched only as evidence for a 'confirmed' or 'possible blocking' summary.
2. Context only: every finding is ``info``, tagged ``context_only`` and ``censorship`` (never scored). 'Blocking
   confirmed' only for OONI ``confirmed`` measurements; 'possible blocking' needs >= 3 anomalies and >= 50% of the
   tests that ran (live data shows sporadic anomalies where nothing is blocked); no measurements is 'no evidence
   either way', never 'not blocked' (:func:`country_summary`).
3. Attribution: :data:`OONI_ATTRIBUTION` in attribute ``data_attribution`` (report footer) and the notice
   fragment ``v3lum/data/notices/ooni_data.json`` (THIRD_PARTY_NOTICES). The data licence is CC BY-NC-SA 4.0
   (verified: github.com/ooni/license data/LICENSE.md), so the source is classed ``noncommercial`` and is off
   under the corporate profile until licence-cleared (licence_allow entry), as cond 3 requires.
4. Opt-in: ``default_enabled = False`` (``-M ooni`` or ``--preset deep``). Errors, 403/429, challenge pages,
   timeouts and malformed or error-in-200 answers are 'could not verify' (BLOCKED / RATE_LIMITED / ERROR), never
   EMPTY; a low ``x-ratelimit-remaining`` stops the run before the API starts refusing.
5. Tests with the recorded measurements and aggregation fixtures (tests/fixtures/ooni/).

Explorer pages (explorer.ooni.org) sit behind a Vercel checkpoint for datacenter egress: they are manual links
only, never fetched. ``measurement_url`` (raw measurement on api.ooni.io) is kept as evidence and never fetched.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    Blocked,
    Cancelled,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "ooni.api"
HOST = "api.ooni.io"
API = "https://api.ooni.io/api/v1"
MEASUREMENTS_URL = API + "/measurements"
AGGREGATION_URL = API + "/aggregation"
EXPLORER_M = "https://explorer.ooni.org/m/"
EXPLORER_DOMAIN = "https://explorer.ooni.org/domain/"
DEFAULT_COUNTRY = "BR"
MAX_PAGES = 2  # P023 cond 1
MEASUREMENT_LIMIT = 50
WINDOW_DAYS = 30
ANOMALY_MIN_COUNT = 3
ANOMALY_CONSISTENT_RATE = 0.5
#: stop before the API starts refusing (x-ratelimit-remaining, an undocumented refilling budget of ~4000 units)
RATELIMIT_FLOOR = 50
MAX_EVIDENCE = 5
OONI_ATTRIBUTION = (
    "Censorship measurements: OONI - Open Observatory of Network Interference (https://ooni.org/data/), "
    "data licensed CC BY-NC-SA 4.0 (https://github.com/ooni/license/tree/master/data)."
)
_ISO_TEXT = """
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO
JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR
MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO
RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV
TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK
"""
#: ISO 3166-1 alpha-2 codes (+ XK, as OONI reports Kosovo); every probe_cc seen in the live 150-row answer is here.
ISO_3166_ALPHA2 = frozenset(_ISO_TEXT.split())
BLOCKING_TYPES = {
    "dns": "DNS tampering",
    "tcp_ip": "TCP/IP blocking",
    "http-diff": "HTTP response differs (possible block page)",
    "http-failure": "HTTP failure",
    "tls": "TLS interference",
}
_COUNT_KEYS = ("measurement_count", "anomaly_count", "confirmed_count", "failure_count", "ok_count")
_LABEL_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_UID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_ASN_RE = re.compile(r"^AS\d{1,10}$")
_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
STOP_EXCEPTIONS = (Cancelled, DeadlineExceeded, RequestCapReached, OfflineError)
_FAILURE_RANK = {Status.RATE_LIMITED: 4, Status.QUOTA: 3, Status.BLOCKED: 2, Status.ERROR: 1}
_BLOCKED_CODES = frozenset({"hostile_host", "circuit", "challenge", "geo_block", "login_wall"})


class _Unusable(Exception):
    """An answer that is not the documented format: could not verify."""


# ======================================================================================
# parsing (pure, defensive)
# ======================================================================================


def valid_cc(cc: Any) -> bool:
    """ISO 3166-1 alpha-2 (+ XK). An invalid probe_cc is answered 200 with an empty list: never send one."""
    return isinstance(cc, str) and cc.strip().upper() in ISO_3166_ALPHA2


def probe_countries(case_country: Any = None) -> list[str]:
    out = [DEFAULT_COUNTRY]
    if valid_cc(case_country) and case_country.strip().upper() not in out:
        out.append(case_country.strip().upper())
    return out


def query_host(entity: Entity) -> str | None:
    """The exact host sent as ``domain=``: the domain itself, or the host of a URL (IDNA, lower case)."""
    value = str(entity.value)
    if entity.type is T.URL:
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return None
    host = value.strip().lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii") if any(ord(c) > 127 for c in host) else host
    except UnicodeError:
        return None
    return host if _LABEL_RE.match(host) and not re.match(r"^[\d.]+$", host) else None


def domain_variants(host: str) -> list[str]:
    """[host, 'www.' + host]: the second is queried only when the exact host has no measurements (live:
    google.com 0 vs www.google.com 1318 BR measurements in 30 days)."""
    return [host] if host.startswith("www.") else [host, "www." + host]


def _int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return 0


def _counts(row: Mapping[str, Any]) -> dict[str, int]:
    return {k: _int(row.get(k)) for k in _COUNT_KEYS}


def parse_aggregation(doc: Any) -> dict[str, int] | None:
    """/api/v1/aggregation without axis -> the counts, or None when the body is not an aggregation answer."""
    if not isinstance(doc, Mapping) or "result" not in doc:
        return None
    res = doc.get("result")
    if isinstance(res, Mapping):
        return _counts(res)
    if isinstance(res, list):  # an axis answer: sum the rows
        total = dict.fromkeys(_COUNT_KEYS, 0)
        for row in res:
            if isinstance(row, Mapping):
                for k, v in _counts(row).items():
                    total[k] += v
        return total
    return None


def parse_aggregation_by_country(doc: Any) -> dict[str, dict[str, int]]:
    """axis_x=probe_cc answer -> {cc: counts} (invalid codes dropped)."""
    out: dict[str, dict[str, int]] = {}
    res = doc.get("result") if isinstance(doc, Mapping) else None
    for row in res if isinstance(res, list) else []:
        cc = row.get("probe_cc").upper() if isinstance(row, Mapping) and isinstance(row.get("probe_cc"), str) else None
        if cc in ISO_3166_ALPHA2:
            out[cc] = _counts(row)
    return out


def _bool(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


def parse_measurement(r: Mapping[str, Any]) -> dict[str, Any]:
    uid = r.get("measurement_uid") if isinstance(r.get("measurement_uid"), str) and _UID_RE.match(r["measurement_uid"]) else None
    scores = r.get("scores") if isinstance(r.get("scores"), Mapping) else {}
    analysis = scores.get("analysis") if isinstance(scores.get("analysis"), Mapping) else {}
    btype = analysis.get("blocking_type") if isinstance(analysis.get("blocking_type"), str) else None
    murl = r.get("measurement_url") if isinstance(r.get("measurement_url"), str) and r["measurement_url"].startswith("https://api.ooni.io/") else None
    cc = r.get("probe_cc").upper() if isinstance(r.get("probe_cc"), str) else None
    asn = r.get("probe_asn") if isinstance(r.get("probe_asn"), str) and _ASN_RE.match(r["probe_asn"]) else None
    anomaly, confirmed, failure = _bool(r.get("anomaly")), _bool(r.get("confirmed")), _bool(r.get("failure"))
    start = r.get("measurement_start_time") if isinstance(r.get("measurement_start_time"), str) else ""
    m = _DATE_RE.match(start)
    return {
        "measurement_uid": uid,
        "test_name": r.get("test_name") if isinstance(r.get("test_name"), str) else None,
        "probe_cc": cc if cc in ISO_3166_ALPHA2 else None,
        "probe_asn": asn,
        "date": m.group(1) if m else None,
        "anomaly": anomaly,
        "confirmed": confirmed,
        "failure": failure,
        "blocking_type": btype[:40] if btype else None,
        "measurement_url": murl,
        "explorer_url": EXPLORER_M + uid if uid else None,
    }


def parse_measurements(doc: Any) -> dict[str, Any] | None:
    """/api/v1/measurements page -> {results, next_url} or None when the body is not a measurements page."""
    if not isinstance(doc, Mapping) or not isinstance(doc.get("results"), list):
        return None
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
    nxt = meta.get("next_url") if isinstance(meta.get("next_url"), str) and meta.get("next_url") else None
    return {"results": [parse_measurement(r) for r in doc["results"] if isinstance(r, Mapping)], "next_url": nxt}


def next_page(next_url: str | None, pages_fetched: int, host: str) -> tuple[str | None, str]:
    """(url to follow, '') or (None, reason): last_page | page_cap | foreign_url. The URL comes from the
    answer, so it is followed only to the measurements path of api.ooni.io for the same host (cond 1)."""
    if not next_url:
        return None, "last_page"
    if pages_fetched >= MAX_PAGES:
        return None, "page_cap"
    try:
        parts = urlsplit(next_url)
    except ValueError:
        return None, "foreign_url"
    if parts.scheme != "https" or (parts.hostname or "").lower() != HOST or not parts.path.startswith("/api/v1/measurements"):
        return None, "foreign_url"
    if parse_qs(parts.query).get("domain", [""])[0].lower() != host:
        return None, "foreign_url"
    return next_url, ""


def counts_from_measurements(results: list[dict[str, Any]], cc: str) -> dict[str, int]:
    c = dict.fromkeys(_COUNT_KEYS, 0)
    for m in results:
        if m.get("probe_cc") != cc:
            continue
        c["measurement_count"] += 1
        c["confirmed_count"] += int(bool(m.get("confirmed")))
        c["anomaly_count"] += int(bool(m.get("anomaly")))
        c["failure_count"] += int(bool(m.get("failure")))
        c["ok_count"] += int(not (m.get("anomaly") or m.get("confirmed") or m.get("failure")))
    return c


def country_summary(cc: str, counts: Mapping[str, int], *, host: str, since: str, until: str,
                    measurements: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Per-country context (cond 2): states no_measurements | confirmed_blocking | anomalies_consistent |
    anomalies_sporadic | failures_only | no_anomaly, with a ready text. Only 'confirmed_blocking' says blocked."""
    c = {k: _int(counts.get(k)) for k in _COUNT_KEYS}
    n, a, conf, f = c["measurement_count"], c["anomaly_count"], c["confirmed_count"], c["failure_count"]
    tested = max(0, n - f)
    rate = (a / tested) if tested else 0.0
    if n == 0:
        state = "no_measurements"
    elif conf > 0:
        state = "confirmed_blocking"
    elif a >= ANOMALY_MIN_COUNT and rate >= ANOMALY_CONSISTENT_RATE:
        state = "anomalies_consistent"
    elif a > 0:
        state = "anomalies_sporadic"
    elif tested == 0:
        state = "failures_only"
    else:
        state = "no_anomaly"
    btypes: dict[str, int] = {}
    evidence: list[str] = []
    links: list[str] = []
    for m in measurements or []:
        if m.get("probe_cc") != cc or not (m.get("anomaly") or m.get("confirmed")):
            continue
        if m.get("blocking_type"):
            btypes[m["blocking_type"]] = btypes.get(m["blocking_type"], 0) + 1
        if m.get("measurement_url") and len(evidence) < MAX_EVIDENCE:
            evidence.append(m["measurement_url"])
        if m.get("explorer_url") and len(links) < MAX_EVIDENCE:
            links.append(m["explorer_url"])
    window = f" between {since} and {until}"
    pct = f"{100 * rate:.1f}%"
    texts = {
        "no_measurements": f"OONI: no measurements of {host} from {cc} probes{window} (no evidence either way)",
        "confirmed_blocking": f"OONI: blocking of {host} confirmed in {cc} ({conf} of {n} measurements confirmed{window})",
        "anomalies_consistent": f"OONI: anomalies in {a} of {tested} tests of {host} from {cc} ({pct}){window} - possible blocking, not confirmed",
        "anomalies_sporadic": f"OONI: {a} sporadic anomalies in {tested} tests of {host} from {cc} ({pct}){window} - usual network noise, not evidence of blocking",
        "failures_only": f"OONI: {n} measurements of {host} from {cc} all failed{window} (could not test)",
        "no_anomaly": f"OONI: {n} measurements of {host} from {cc}, no anomaly{window}",
    }
    text = texts[state]
    if btypes and state in ("confirmed_blocking", "anomalies_consistent"):
        text += "; blocking type: " + ", ".join(f"{BLOCKING_TYPES.get(k, k)} ({v})" for k, v in sorted(btypes.items()))
    return {"probe_cc": cc, "domain": host, "state": state, **c, "tested_count": tested, "anomaly_rate": round(rate, 4),
            "blocking_types": btypes, "since": since, "until": until, "evidence": evidence, "manual_links": links, "text": text}


def ratelimit_remaining(resp: Any) -> int | None:
    value = (getattr(resp, "headers", None) or {}).get("x-ratelimit-remaining")
    try:
        return int(float(value)) if value is not None else None
    except (TypeError, ValueError):
        return None


# ======================================================================================
# module
# ======================================================================================

_TITLES = {
    "confirmed_blocking": "Blocking confirmed by OONI probes",
    "anomalies_consistent": "Possible blocking seen by OONI probes (not confirmed)",
    "anomalies_sporadic": "OONI measurements: sporadic anomalies only",
    "failures_only": "OONI measurements: probes could not test",
    "no_anomaly": "OONI measurements: no anomaly",
}
_CONFIDENCE = {"confirmed_blocking": "probable", "anomalies_consistent": "possible"}


def _budget_ok(budget: dict[str, int | None]) -> bool:
    remaining = budget.get("remaining")
    return remaining is None or remaining >= RATELIMIT_FLOOR


def _budget_reason(budget: dict[str, int | None]) -> str:
    return f"OONI API rate budget almost spent (x-ratelimit-remaining {budget.get('remaining')}): stopped before it refuses"


@register
class Ooni(Module):
    name = "ooni"
    title = "OONI censorship measurements"
    description = (
        "Network-interference context from the OONI API: measurements and aggregated counts of a domain from probes "
        "in Brazil (and the case country) - DNS tampering, TCP/IP or HTTP blocking, court- or ANATEL-ordered blocks. "
        "Context only, never scored."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.URL}
    produces = frozenset()
    tags = {"free"}
    reference = "https://api.ooni.io/apidocs/"
    notice = (
        "OONI data is licensed CC BY-NC-SA 4.0 (noncommercial): off under the corporate profile until legal records a "
        "licence_allow entry (e.g. a grant from OONI); reports carry the OONI attribution. Context only, never scored."
    )
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ooni"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_noauth_limited"
    max_requests = 8  # 2 countries x (aggregation + www variant + 2 measurement pages)
    expected_latency = 1.2
    timeout = 60.0
    min_interval = 1.0
    daily_quota = 200
    cache_ttl = 86400
    max_pivots = 0
    manual_link = "https://explorer.ooni.org/domain/{domain}"
    default_enabled = False
    settings = {
        "ooni_case_country": SettingSpec("", "ooni: ISO 3166-1 alpha-2 country of the case, queried together with BR (P023 cond 1); '' = BR only"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return query_host(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        host = query_host(entity)
        if host is None:
            return res.mark("skipped", "no host name to look up", reason_code="not_applicable")
        case_country = ctx.setting("ooni_case_country", "")
        countries = probe_countries(case_country)
        notes: list[str] = []
        if isinstance(case_country, str) and case_country.strip() and not valid_cc(case_country):
            notes.append(f"setting ooni_case_country {case_country.strip()[:8]!r} is not an ISO 3166-1 alpha-2 code: ignored")
        today = ctx.now().date()
        since, until = (today - timedelta(days=WINDOW_DAYS)).isoformat(), (today + timedelta(days=1)).isoformat()
        summaries: list[dict[str, Any]] = []
        failures: list[tuple[str, Status, str, str]] = []
        stop = ""
        budget: dict[str, int | None] = {"remaining": None}
        for cc in countries:
            if ctx.cancelled():
                break
            if not _budget_ok(budget):
                failures.append((cc, Status.RATE_LIMITED, "rate_limited", _budget_reason(budget)))
                stop = "rate_limited"
                break
            try:
                summaries.append(self._country(ctx, host, cc, since, until, budget))
            except STOP_EXCEPTIONS:
                raise
            except (HttpError, NetworkError, _Unusable) as exc:
                status, code = _failure(exc)
                failures.append((cc, status, code, f"OONI API ({cc}): {str(exc)[:160]}"))
                if status in (Status.RATE_LIMITED, Status.QUOTA, Status.BLOCKED):
                    stop = "rate_limited" if status is Status.RATE_LIMITED else ("quota" if status is Status.QUOTA else "")
                    break  # never insist on a refusing API
        res.raw = {"host": host, "countries": countries, "since": since, "until": until,
                   "summaries": summaries, "failures": [{"probe_cc": cc, "status": st.value, "reason": why} for cc, st, _c, why in failures],
                   "notes": notes}
        measured = [s for s in summaries if s["measurement_count"]]
        if not measured:
            if failures:
                cc, status, code, why = max(failures, key=lambda f: _FAILURE_RANK.get(f[1], 0))
                return res.mark(status, f"{why}: could not verify", reason_code=code)
            return res.mark("empty", f"OONI has no measurements of {host} from {', '.join(countries)} probes between {since} and {until} "
                                     "(no evidence either way)")
        self._report(res, host, summaries, failures)
        if failures:
            res.error = "; ".join(f"{cc}: {why} (could not verify)" for cc, _st, _c, why in failures)[:400]
        if not stop and not _budget_ok(budget):
            stop = "rate_limited"  # evidence pages skipped to keep the API's rate budget
        if stop in ("rate_limited", "quota"):
            res.stop(stop)
        return res

    # ------------------------------------------------------------------ requests
    def _get(self, ctx: Any, url: str, params: dict[str, Any] | None, budget: dict[str, int | None]) -> Any:
        resp = ctx.http.get(url, params=params, source=SOURCE)
        ctx.http.check(resp)  # error-in-200 marker, challenge pages, 403/429, 5xx
        remaining = ratelimit_remaining(resp)
        if remaining is not None:
            budget["remaining"] = remaining
        if resp.truncated:
            raise _Unusable("answer truncated at the size cap")
        try:
            return resp.json()
        except (ValueError, HttpError):
            raise _Unusable("answer is not JSON (HTML or text)") from None

    def _aggregation(self, ctx: Any, host: str, cc: str, since: str, until: str, budget: dict[str, int | None]) -> dict[str, int]:
        doc = self._get(ctx, AGGREGATION_URL, {"domain": host, "probe_cc": cc, "since": since, "until": until}, budget)
        counts = parse_aggregation(doc)
        if counts is None:
            raise _Unusable("aggregation answer without a result: could not verify")
        return counts

    def _country(self, ctx: Any, host: str, cc: str, since: str, until: str, budget: dict[str, int | None]) -> dict[str, Any]:
        queried = host
        counts = self._aggregation(ctx, host, cc, since, until, budget)
        if not counts["measurement_count"]:
            for variant in domain_variants(host)[1:]:
                if not _budget_ok(budget):
                    break
                v_counts = self._aggregation(ctx, variant, cc, since, until, budget)
                if v_counts["measurement_count"]:
                    queried, counts = variant, v_counts
        measurements: list[dict[str, Any]] = []
        truncated = ""
        # evidence only for what the summary will claim (confirmed or consistent anomalies), not for noise
        if country_summary(cc, counts, host=queried, since=since, until=until)["state"] in ("confirmed_blocking", "anomalies_consistent"):
            url: str | None = MEASUREMENTS_URL
            params: dict[str, Any] | None = {"domain": queried, "probe_cc": cc, "limit": MEASUREMENT_LIMIT, "since": since, "until": until}
            pages = 0
            while url:
                if not _budget_ok(budget):
                    truncated = _budget_reason(budget)
                    break
                page = parse_measurements(self._get(ctx, url, params, budget))
                if page is None:
                    raise _Unusable("measurements answer without results: could not verify")
                measurements.extend(m for m in page["results"] if m.get("probe_cc") == cc)
                pages += 1
                url, _why = next_page(page["next_url"], pages, queried)
                params = None  # next_url carries the cursor and every parameter
        summary = country_summary(cc, counts, host=queried, since=since, until=until, measurements=measurements)
        if queried != host:
            summary["text"] += f" (queried {queried}: no measurements of {host} itself)"
        if truncated:
            summary["text"] += f" (evidence not collected: {truncated})"
        return summary

    # ------------------------------------------------------------------ output
    def _report(self, res: ModuleResult, host: str, summaries: list[dict[str, Any]], failures: list[tuple[str, Status, str, str]]) -> None:
        attribute = [dict(s) for s in summaries]
        for cc, status, _code, why in failures:
            attribute.append({"probe_cc": cc, "domain": host, "state": "could_not_verify", "status": status.value, "text": why})
        res.attr("ooni_censorship", attribute)
        res.attr("data_attribution", OONI_ATTRIBUTION)
        res.link(f"OONI Explorer: {host} (manual, browser only)", EXPLORER_DOMAIN + quote(host, safe=""))
        for s in summaries:
            if not s["measurement_count"]:
                continue
            for link in s["manual_links"]:
                res.link(f"OONI measurement {s['probe_cc']} (manual, browser only)", link)
            state = s["state"]
            res.finding(
                _TITLES[state],
                "info",
                s["text"] + ". Context only: explains reachability differences, never a verdict about the domain. " + OONI_ATTRIBUTION,
                confidence=_CONFIDENCE.get(state, "probable"),
                criterion=(f"OONI probe measurements from {s['probe_cc']} {s['since']}..{s['until']}: 'confirmed' = known block-page "
                           f"fingerprint; anomalies count as possible blocking only at >= {ANOMALY_MIN_COUNT} and >= "
                           f"{int(ANOMALY_CONSISTENT_RATE * 100)}% of the tests that ran (P023 cond 2)"),
                data={k: s[k] for k in ("probe_cc", "domain", "state", *_COUNT_KEYS, "tested_count", "anomaly_rate", "blocking_types",
                                        "since", "until", "evidence")},
                tags=["context_only", "censorship"],
                references=s["evidence"],
                source=SOURCE,
                key=s["probe_cc"],
                observed_first=s["since"],
                observed_last=s["until"],
            )


def _failure(exc: BaseException) -> tuple[Status, str]:
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited"
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota"
    if isinstance(exc, Blocked):
        code = getattr(exc, "reason_code", "") or "challenge"
        return Status.BLOCKED, code if code in _BLOCKED_CODES else "challenge"
    if isinstance(exc, HttpError):
        if getattr(exc, "status", 0) == 403:
            return Status.BLOCKED, "challenge"
        return Status.ERROR, "timeout" if getattr(exc, "status", 0) in (408, 504) else "error"
    if isinstance(exc, NetworkError):
        text = str(exc).lower()
        return Status.ERROR, "timeout" if "timeout" in text or "timed out" in text else "error"
    return Status.ERROR, "error"
