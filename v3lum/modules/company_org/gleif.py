"""P220 ``gleif`` - GLEIF LEI API: CNPJ <-> LEI and the corporate group around a company.

Council P220 final conditions, as implemented here (the GLEIF client itself is the shared helper
:mod:`v3lum.modules.company_org.gleif_client`, cond 1):

1. One GLEIF client (``gleif_client.GleifClient``) shared with P361; host api.gleif.org, keyless, CC0
   (courtesy line in attribute ``data_attribution``), 60 req/min: provider ``gleif`` carries min_interval
   1 s and the quota block; the module repeats min_interval 1 s.
2. ``filter[entity.registeredAs]`` always gets the formatted CNPJ (``00.000.000/0001-91``), never digits.
3. Page size 10; at most 4 requests per entity (``max_requests = 4``: the search/record, the direct parent,
   the ultimate parent and the first page of children; a parent slot reads the reporting exception
   when GLEIF links no parent); children capped at 10. When the direct parent has no parent itself the
   ultimate parent is the same record and is not requested again.
4. Default scans use CNPJ and exact company_name inputs only. A keyword runs fuzzycompletions only when
   the module is selected explicitly (``-M gleif`` or ``v3lum run gleif``); its hits are hypotheses
   (relation ``lei_candidate``, expand=False, confidence 0.5). Ambiguous exact-name hits are hypotheses too.
5. Exact CNPJ matches pivot with ``partner`` (parents) and ``company_of`` (children). Only the direct
   parent and the direct children of an analyst seed expand (one level); the ultimate parent, relations
   found from a pivot and every name match are expand=False, so a conglomerate cannot flood the graph.
   Sole proprietors (natural persons) never become name pivots and keep no address. Results are
   ownership hints, never scope: nothing here writes the org profile or an ACTIVE scope.
6. Attributes ``lei``, ``lei_summary`` (one line: LEI, legal name, ISSUED/LAPSED/RETIRED, last update,
   direct and ultimate parent), ``lei_record``, ``lei_parents``, ``lei_children``. No record is the INFO
   finding 'No LEI registered (GLEIF)' (tag context_only): most Brazilian SMEs have none, never a risk.
7. 401/403/429, timeouts, 5xx and error-in-200 bodies are could-not-verify (BLOCKED, RATE_LIMITED, QUOTA,
   ERROR), never EMPTY, and are never cached; 404 with GLEIF's own body is the declared absence
   (``absent_statuses = {404}``). A failed relation request keeps the record and says 'could not verify'
   for that relation (never 'none reported').
"""

from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register
from v3lum.modules.company_org import gleif_client as gc

SOURCE = gc.SOURCE
RECORD_PAGE = "https://search.gleif.org/#/record/{lei}"
NOTICE = (
    "GLEIF LEI data is CC0 (attribution given as a courtesy). Parent/child relationships are ownership hints, "
    "never scope: they may be proposed for analyst confirmation but never extend the org profile or an ACTIVE "
    "scope. 'No LEI' is not a risk signal (most Brazilian SMEs have none). Keyword (fuzzy) search runs only when "
    "the module is selected explicitly (-M gleif)."
)
_STATE_STATUS = {"blocked": Status.BLOCKED, "rate_limited": Status.RATE_LIMITED, "quota": Status.QUOTA, "error": Status.ERROR}


def explicitly_selected(module_name: str, ctx: Any) -> bool:
    """cond 4: -M <module> in a scan, or a single run (``v3lum run``) outside a scan."""
    options = getattr(ctx, "options", None)
    if module_name in set(getattr(options, "include", ()) or ()):
        return True
    runtime = getattr(ctx, "runtime", None)
    return not bool(getattr(runtime, "in_scan", False))


@register
class Gleif(Module):
    name = "gleif"
    title = "GLEIF LEI records and corporate group"
    description = (
        "Looks up the Legal Entity Identifier of a CNPJ (formatted registeredAs filter) or an exact legal name at "
        "GLEIF and lists the direct/ultimate parents and first-level subsidiaries as ownership hints."
    )
    category = "company_org"
    accepts = {T.CNPJ, T.ORG, T.KEYWORD}
    produces = {T.ORG}
    tags = {"brazil", "free"}
    reference = "https://www.gleif.org/en/lei-data/gleif-api"
    notice = NOTICE
    # ---- declarations --------------------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = (gc.HOST,)
    provider = "gleif"
    sources = (SOURCE,)
    access_model = "free_noauth_limited"
    absent_statuses = frozenset({404})  # cond 7: only with GLEIF's own JSON:API body (checked by the client)
    max_requests = gc.MAX_REQUESTS  # cond 3
    expected_latency = 3.5  # 1 request ~0.7 s; the 4-request path is paced at 1 s per request (measured 0.5-0.9 s each)
    timeout = 30.0
    min_interval = 1.0  # cond 1: documented 60 req/min
    cache_ttl = gc.CACHE_TTL
    max_pivots = 15  # 2 parents + 10 children (cond 3) + slack for candidate lists
    default_enabled = True  # A3: council P220 (CC0 legal-entity data, trusted provider)

    @classmethod
    def health_check(cls) -> HealthCheck:
        # Banco do Brasil: the golden-path CNPJ of the acceptance tests (LEI QE0Q0253K88YAGNPE356)
        return HealthCheck(etype=T.CNPJ, value="00000000000191")

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.ORG:
            prov = tuple(getattr(ctx, "provenance", ()) or ())
            last = prov[-1] if prov else ()
            # the legal name of a CNPJ record: the CNPJ itself goes through the exact registeredAs route
            return not (len(last) >= 2 and last[1] == "legal_name")
        return True

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        client = gc.GleifClient(ctx)
        if entity.type is T.CNPJ:
            return self._by_cnpj(res, ctx, client, str(entity.value))
        if entity.type is T.ORG:
            return self._by_name(res, ctx, client, str(entity.value))
        if not explicitly_selected(self.name, ctx):
            return res.mark(Status.SKIPPED, "keyword (fuzzy) search runs only when gleif is selected explicitly (-M gleif)",
                            reason_code="not_default")
        return self._by_keyword(res, client, str(entity.value))

    # ------------------------------------------------------------------ inputs
    def _by_cnpj(self, res: ModuleResult, ctx: Any, client: gc.GleifClient, cnpj: str) -> ModuleResult:
        formatted = gc.format_cnpj(cnpj)
        if not formatted:
            return res.mark(Status.SKIPPED, "not a valid CNPJ (check digits)", reason_code="not_applicable")
        ans = client.fetch(gc.cnpj_url(cnpj), what=f"LEI record for CNPJ {formatted}")
        if ans.could_not_verify:
            return self._fail(res, ans)
        res.attr("data_attribution", gc.GLEIF_ATTRIBUTION)
        if ans.state == "empty":
            return self._no_lei(res, f"CNPJ {formatted}")
        parsed = gc.parse_lei_records(ans.doc)
        matches = gc.cnpj_matches(parsed["records"], cnpj)
        if not matches:
            res.raw = {"search": _raw_view(parsed)}
            return res.mark(Status.ERROR, f"GLEIF answered records that do not carry {formatted} as registeredAs (filter ignored): "
                            "could not verify", reason_code="error")
        record = matches[0]
        if len(matches) > 1:
            res.attr("lei_candidates", [dict(gc.entity_view(r) or {}, match="same registeredAs") for r in matches[1:]])
        expand = int(getattr(ctx, "depth", 0) or 0) == 0
        return self._record(res, ctx, client, record, parsed, match="cnpj", expand_level1=expand, relations=True)

    def _by_name(self, res: ModuleResult, ctx: Any, client: gc.GleifClient, name: str) -> ModuleResult:
        try:
            url = gc.name_url(name)
        except ValueError:
            return res.mark(Status.SKIPPED, "company name too short for an exact GLEIF legal-name search", reason_code="not_applicable")
        ans = client.fetch(url, what="LEI record with this exact legal name")
        if ans.could_not_verify:
            return self._fail(res, ans)
        res.attr("data_attribution", gc.GLEIF_ATTRIBUTION)
        if ans.state == "empty":
            return self._no_lei(res, f"the legal name '{name}'")
        parsed = gc.parse_lei_records(ans.doc)
        hits = gc.classify_name_hits(name, parsed["records"])
        if hits["match"] == "exact_name":
            # an exact unique legal name is still a name match: relations only for analyst seeds, never expanded
            return self._record(res, ctx, client, hits["record"], parsed, match="name", expand_level1=False,
                                relations=bool(getattr(ctx, "is_seed", False)))
        cands = hits["candidates"]
        res.raw = {"search": _raw_view(parsed)}
        self._candidates(res, cands, match="legal name search (ambiguous)")
        res.attr("lei_summary", f"{len(cands)} GLEIF legal entities match the name '{name}' (no unique exact legal name): "
                                "hypotheses only")
        return res

    def _by_keyword(self, res: ModuleResult, client: gc.GleifClient, query: str) -> ModuleResult:
        try:
            url = gc.fuzzy_url(query)
        except ValueError:
            return res.mark(Status.SKIPPED, "keyword too short for a GLEIF search", reason_code="not_applicable")
        ans = client.fetch(url, what="legal-name completion")
        if ans.could_not_verify:
            return self._fail(res, ans)
        res.attr("data_attribution", gc.GLEIF_ATTRIBUTION)
        hits = gc.parse_fuzzycompletions(ans.doc) if ans.ok else []
        if not hits:
            res.attr("lei_summary", f"no GLEIF legal name completes '{query}'")
            return res.mark(Status.EMPTY)
        res.raw = {"fuzzycompletions": hits}
        self._candidates(res, hits, match="fuzzy completion (hypothesis)")
        res.attr("lei_summary", f"{len(hits)} GLEIF legal names complete '{query}': hypotheses only (expand=False)")
        return res

    # ------------------------------------------------------------------ a matched record
    def _record(self, res: ModuleResult, ctx: Any, client: gc.GleifClient, record: dict[str, Any], parsed: dict[str, Any], *,
                match: str, expand_level1: bool, relations: bool) -> ModuleResult:
        parents: dict[str, Any] = {"direct": None, "direct_exception": None, "ultimate": None, "ultimate_exception": None,
                                   "direct_state": "", "ultimate_state": ""}
        children: dict[str, Any] | None = None
        failures: list[gc.GleifAnswer] = []
        if relations and record.get("lei_valid"):
            children = self._relations(client, record, parents, failures)
        res.attr("lei", record["lei"])
        view = {k: v for k, v in record.items() if k not in ("relations", "lei_valid", "natural_person") and v not in (None, [], "")}
        if parsed.get("golden_copy"):
            view["golden_copy"] = parsed["golden_copy"]
        res.attr("lei_record", view)
        res.attr("lei_summary", gc.summary_line(record, parents))
        res.attr("lei_parents", {k: (gc.entity_view(v) if k in ("direct", "ultimate") else v) for k, v in parents.items()
                                 if v not in (None, "")})
        if children is not None:
            res.attr("lei_children", {
                "count": children["total"], "shown": len(children["children"]), "truncated": children["truncated"],
                "children": [gc.entity_view(c) for c in children["children"]],
            })
        res.link("GLEIF LEI record", RECORD_PAGE.format(lei=record["lei"]))
        self._pivots(res, record, parents, children, match=match, expand_level1=expand_level1)
        res.raw = {"match": match, "record": view, "parents": {k: gc.entity_view(v) if isinstance(v, dict) and "lei" in v else v
                                                                 for k, v in parents.items()},
                   "children": [gc.entity_view(c) for c in (children or {}).get("children", [])]}
        if failures:
            res.error = "; ".join(a.reason for a in failures)[:500]
            states = {a.state for a in failures}
            if "rate_limited" in states:
                res.stop("rate_limited")
            elif "quota" in states:
                res.stop("quota")
        return res

    def _relations(self, client: gc.GleifClient, record: dict[str, Any], parents: dict[str, Any],
                   failures: list[gc.GleifAnswer]) -> dict[str, Any] | None:
        """cond 3: at most 3 relation requests after the record (search) request."""
        lei = record["lei"]
        children: dict[str, Any] | None = None
        for step in gc.relation_plan(record, used=1):
            slot = "direct" if step.startswith("direct-parent") else "ultimate" if step.startswith("ultimate-parent") else "children"
            if slot == "ultimate" and parents.get("ultimate_state") == "same_as_direct":
                continue
            ans = client.fetch(gc.relation_url(lei, step), what=step.replace("-", " "))
            if ans.could_not_verify:
                failures.append(ans)
                if slot == "children":
                    children = None
                else:
                    parents[f"{slot}_state"] = "unverified"
                continue
            if slot == "children":
                children = gc.parse_children(ans.doc) if ans.ok else {"children": [], "total": 0, "truncated": False}
                continue
            if step.endswith("reporting-exception"):
                exc = gc.parse_reporting_exception(ans.doc) if ans.ok else None
                parents[f"{slot}_exception"] = exc
                parents[f"{slot}_state"] = "exception" if exc else "none"
                continue
            recs = gc.parse_lei_records(ans.doc)["records"] if ans.ok else []
            parent = recs[0] if recs else None
            parents[slot] = parent
            parents[f"{slot}_state"] = "present" if parent else "none"
            if slot == "direct" and parent and (parent.get("relations") or {}).get("direct-parent") == "exception":
                # the direct parent has no parent itself: it is the ultimate parent (no second request)
                parents["ultimate"] = parent
                parents["ultimate_state"] = "same_as_direct"
        return children

    def _pivots(self, res: ModuleResult, record: dict[str, Any], parents: dict[str, Any], children: dict[str, Any] | None, *,
                match: str, expand_level1: bool) -> None:
        exact = match == "cnpj"
        conf = gc.RELATION_CONFIDENCE if exact else gc.HYPOTHESIS_CONFIDENCE
        hint = "ownership hint from GLEIF, never scope"
        direct = parents.get("direct")
        if _pivotable(direct):
            res.pivot(T.ORG, direct["legal_name"], "partner", confidence=conf, expand=exact and expand_level1,
                      note=f"GLEIF direct parent {_ident(direct)}: {hint}")
        ultimate = parents.get("ultimate")
        if _pivotable(ultimate) and (not direct or ultimate.get("lei") != direct.get("lei")):
            res.pivot(T.ORG, ultimate["legal_name"], "partner", confidence=conf, expand=False,
                      note=f"GLEIF ultimate parent {_ident(ultimate)} (beyond one level, not expanded): {hint}")
        for child in (children or {}).get("children", [])[: gc.CHILDREN_CAP]:
            if _pivotable(child) and child.get("lei") != record.get("lei"):
                res.pivot(T.ORG, child["legal_name"], "company_of", confidence=conf, expand=exact and expand_level1,
                          note=f"GLEIF direct child {_ident(child)}: {hint}")

    def _candidates(self, res: ModuleResult, cands: list[dict[str, Any]], *, match: str) -> None:
        rows = []
        for c in cands[: gc.PAGE_SIZE]:
            rows.append(dict(gc.entity_view(c) or {"legal_name": c.get("legal_name"), "lei": c.get("lei")}, match=match))
            if c.get("legal_name") and not c.get("natural_person") and c.get("category") not in gc.NATURAL_PERSON_CATEGORIES:
                lei = f" (LEI {c['lei']})" if c.get("lei") else ""
                res.pivot(T.ORG, c["legal_name"], "lei_candidate", confidence=gc.HYPOTHESIS_CONFIDENCE, expand=False,
                          note=f"GLEIF {match}{lei}: a hypothesis, never a confirmed link")
        res.attr("lei_candidates", [{k: v for k, v in r.items() if v} for r in rows])

    # ------------------------------------------------------------------ outcomes
    @staticmethod
    def _no_lei(res: ModuleResult, what: str) -> ModuleResult:
        """cond 6: INFO 'no LEI', never a risk signal."""
        res.attr("lei_summary", f"no LEI for {what} (most Brazilian SMEs have none)")
        res.finding(
            "No LEI registered (GLEIF)", "info",
            f"GLEIF has no LEI record for {what}. Most Brazilian SMEs have no LEI: this is context, not a risk signal.",
            confidence="confirmed", tags=["context_only"], source=SOURCE,
        )
        return res.mark(Status.EMPTY)

    @staticmethod
    def _fail(res: ModuleResult, ans: gc.GleifAnswer) -> ModuleResult:
        """cond 7 / rule 5: could not verify, never EMPTY."""
        status = _STATE_STATUS.get(ans.state, Status.ERROR)
        return res.mark(status, ans.reason, reason_code=ans.reason_code or "")


def _pivotable(rec: dict[str, Any] | None) -> bool:
    return bool(rec and rec.get("legal_name") and rec.get("category") not in gc.NATURAL_PERSON_CATEGORIES)


def _ident(rec: dict[str, Any]) -> str:
    parts = [f"LEI {rec.get('lei')}"]
    if rec.get("jurisdiction"):
        parts.append(str(rec["jurisdiction"]))
    if rec.get("cnpj"):
        parts.append(f"CNPJ {gc.format_cnpj(rec['cnpj'])}")
    return "(" + ", ".join(parts) + ")"


def _raw_view(parsed: dict[str, Any]) -> dict[str, Any]:
    return {"total": parsed.get("total"), "golden_copy": parsed.get("golden_copy"),
            "records": [gc.entity_view(r) for r in parsed.get("records", [])[: gc.PAGE_SIZE]]}


__all__ = ["Gleif", "explicitly_selected"]
