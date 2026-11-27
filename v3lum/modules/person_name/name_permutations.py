"""Name -> username / corporate e-mail candidates, accent and particle aware (P251).

Offline (disclosure 'none'): every candidate comes from the shared helper
``v3lum.modules.person_name.permute`` (cond 1; the core ``core/permute.py`` stand-in, reused by the e-mail
pattern modules). The module runs only when the analyst selects it on an analyst-typed person_name seed
(cond 5, A3 BR2: ``run_on='seeds'``, default_enabled False).

* cond 1 - NFKD accent stripping, particles {de, da, do, das, dos, e, di, du, del, van, von} dropped,
  suffixes {junior, jr, filho, neto, sobrinho} recognised and never used as a surname, the last surname
  primary; Ceos priority patterns then maigret Permute 'strict' (MIT) in deterministic order.
* cond 2 - at most 15 candidates per person and kind. Corporate e-mail candidates only for domains of the
  case (domain, e-mail and URL seeds of the scan, domains on the entity's provenance path, company_name
  seeds matched to the org_profile) or of the org_profile; free-mail domains are refused. They are ranked
  by the domain's format inferred from observed addresses (the e-mail seeds of the case at that domain) and
  each shows the number of samples behind its pattern.
* cond 3 - candidates are hypotheses: attributes ``username_candidates`` / ``email_candidates`` (the
  collapsible 'candidates (unverified guesses)' list), never findings and never scored; every candidate is
  a pivot with expand=False, confidence POSSIBLE and the note 'generated'; the top 3 are offered first.
* cond 4 - generated e-mails are never sent automatically anywhere (expand=False) and the helper's
  ``generated_sink_reason`` refuses breach, stealer, reputation and validation sinks for them and SMTP,
  login, sign-up and reset flows for everything generated.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.person_name.permute import (
    CANDIDATE_CAP,
    OFFERED_FIRST,
    email_candidates,
    name_parts,
    normalise_domain,
    username_candidates,
)

MAX_DOMAINS = 5
GENERATED_NOTE = "generated (unverified guess)"


def _key_parts(key: Any) -> tuple[str, str] | None:
    if not isinstance(key, str) or ":" not in key:
        return None
    etype, _, value = key.partition(":")
    return etype, value


def case_context(ctx: Any) -> dict[str, Any]:
    """cond 2: domains and observed addresses of the case available to an offline module: the scan's seeds
    (``options.seed_tlp`` lists every seed key), the entity's provenance path and the org_profile.
    -> {case_domains, org_domains, samples}."""
    keys: list[str] = []
    options = getattr(ctx, "options", None)
    seeds = getattr(options, "seed_tlp", None) or {}
    keys.extend(k for k in seeds if isinstance(k, str))
    for step in getattr(ctx, "provenance", ()) or ():
        if isinstance(step, (tuple, list)) and step:
            keys.append(str(step[0]))
    org = getattr(ctx, "org", None)
    org_domains: list[str] = []
    org_names: list[str] = []
    if org is not None and not getattr(org, "is_empty", True):
        for entry in getattr(org, "domains", ()) or ():
            dom = normalise_domain(getattr(entry, "name", entry))
            if dom and dom not in org_domains:
                org_domains.append(dom)
        if getattr(org, "name", ""):
            org_names.append(str(org.name))
        org_names.extend(org.brand_terms())
    case_domains: list[str] = []
    samples: list[dict[str, Any]] = []
    for key in keys:
        parts = _key_parts(key)
        if not parts:
            continue
        etype, value = parts
        dom = None
        if etype == "domain":
            dom = normalise_domain(value)
        elif etype == "email" and "@" in value:
            dom = normalise_domain(value.rsplit("@", 1)[-1])
            samples.append({"address": value, "source": "e-mail seed of the case"})
        elif etype == "url":
            try:
                dom = normalise_domain(urlsplit(value).hostname)
            except ValueError:
                dom = None
            if dom and dom.startswith("www."):
                dom = dom[4:]
        elif etype == "company_name" and org_domains:
            folded = value.strip().lower()
            if folded and any(folded in n.lower() or n.lower() in folded for n in org_names if len(n) >= 3):
                case_domains.extend(d for d in org_domains if d not in case_domains)
        if dom and dom not in case_domains:
            case_domains.append(dom)
    return {"case_domains": case_domains, "org_domains": org_domains, "samples": samples}


@register
class NamePermutations(Module):
    name = "name_permutations"
    title = "Name -> username / e-mail candidates (unverified guesses)"
    description = (
        "Offline username and corporate e-mail hypotheses for an analyst-typed person name: accent-stripped, Brazilian "
        "particle and suffix aware, Ceos priority patterns then maigret 'strict' permutations, at most 15 per kind; e-mails "
        "only for case or org_profile domains, ranked by the observed address format."
    )
    category = "person_name"
    accepts = frozenset({T.PERSON})
    produces = frozenset({T.USERNAME, T.EMAIL})
    run_on = "seeds"  # cond 5: analyst-typed person_name seeds only
    tags = frozenset({"offline"})
    reference = "https://github.com/soxoj/maigret"
    notice = (
        "Candidates are unverified guesses: never findings, never scored, never expanded automatically. Generated e-mails are "
        "never sent to breach, stealer, reputation or validation services and nothing generated is validated by SMTP, login, "
        "sign-up or reset flows; generated handles reach username_check only after the analyst selects them."
    )
    terms = "open"  # offline, no registry source (A1 BR20)
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    max_pivots = CANDIDATE_CAP * 2
    default_enabled = False  # cond 5 / A3 BR2: person_name modules are never default

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        parts = name_parts(entity.value)
        if not parts["first"]:
            return res.mark("empty", "no usable name token after accent folding and particle removal")
        res.attr("name_parts", {k: parts[k] for k in ("tokens", "first", "middles", "last", "suffix", "particles_dropped")})
        users = username_candidates(entity.value)
        res.attr("username_candidates", [_public(c) for c in users])
        for c in users:
            res.pivot(T.USERNAME, c["value"], "generated_candidate", confidence="possible", expand=False,
                      note=_note(c, "handle reaches username_check only after the analyst selects it"))
        context = case_context(ctx)
        allowed = context["case_domains"] + [d for d in context["org_domains"] if d not in context["case_domains"]]
        mails = email_candidates(entity.value, allowed[:MAX_DOMAINS], allowed, samples=context["samples"]) if allowed else None
        if mails and mails["candidates"]:
            res.attr("email_candidates", [_public(c) for c in mails["candidates"]])
            res.attr("email_formats", mails["formats"])
            for c in mails["candidates"]:
                res.pivot(T.EMAIL, c["value"], "generated_candidate", confidence="possible", expand=False,
                          note=_note(c, "never sent to breach, stealer, reputation or validation services; never validated by "
                                        "SMTP, login, sign-up or reset flows"))
        res.raw = {"name_parts": parts, "case_domains": context["case_domains"], "org_domains": context["org_domains"][:MAX_DOMAINS],
                   "format_samples": len(context["samples"]), "email_state": mails["state"] if mails else "no case or org_profile domain",
                   "refused_domains": (mails or {}).get("refused", [])}
        if not users and not (mails and mails["candidates"]):
            return res.mark("empty", "no candidate could be generated from this name")
        return res


def _public(c: dict[str, Any]) -> dict[str, Any]:
    keys = ("value", "rank", "pattern", "origin", "label", "offered_first", "format_samples")
    return {k: c[k] for k in keys if k in c}


def _note(c: dict[str, Any], tail: str) -> str:
    first = f"; offered first (top {OFFERED_FIRST})" if c.get("offered_first") else ""
    samples = f"; format seen in {c['format_samples']} observed address(es)" if "format_samples" in c else ""
    return f"{GENERATED_NOTE}: rank {c['rank']}, pattern {c['pattern']}{samples}{first}; {tail}"
