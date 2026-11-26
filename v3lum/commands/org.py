"""``v3lum org``: the organisation profile (P378, A11). Nothing here sends the profile anywhere.

* ``org show [--full]`` - summary of the local profile (entries per kind, verification states,
  criticality, third-party-hosted flags); executive names are never printed (count only).
* ``org check [FILE]`` - strict schema validation (``orgprofile.validate``): every problem with its
  file line and field path; exit 1 when the profile is invalid.
* ``org verify <domain>`` - DNS proof of control: the TXT record ``v3lum-verify=<token>`` (token =
  ``hmacid.hmac12('domain', domain)``, keyed with this installation's secret) is read through the
  core resolver; when present the entry becomes ``txt_verified`` (added when missing). When it is
  absent the record to publish is printed; when DNS cannot answer nothing changes ('could not
  verify', never 'absent'). ``org verify <domain> --attest --by NAME [--date YYYY-MM-DD]`` records
  an analyst attestation instead.
* ``org seed [inputs...]`` - proposes entries (domains, CNPJ roots, ASNs, networks, favicon hashes,
  M365 tenant ids) from a normal PASSIVE scan through the policy gate (registro.br RDAP publicIds,
  NIC.br ASN list, RIPEstat announced prefixes, M365 tenant domains, CT SAN affiliates, BCB/gov.br
  lists - whichever modules provide them) seeded with the inputs or the profile's own domains and
  ASNs. Every proposal needs the analyst's confirmation in a terminal; a non-interactive session
  writes nothing; nothing is auto-trusted (accepted entries are 'seeded').

Every change is saved 0600 (``orgprofile.save`` through ``paths.secure_write_text``) and written to
the audit trail (``audit.CaseAudit`` with case id ``'org-profile'``, kind ``'profile_change'``). A
profile that does not validate strictly, or a read-only (team-maintained) file, is never rewritten.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich import box
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from v3lum.commands import command
from v3lum.core import orgprofile

__all__ = ["AUDIT_CASE_ID", "AUDIT_KIND", "SEED_RELATIONS", "Org", "Proposal", "audit_profile_change", "seed_proposals"]

#: Case id of the org-profile audit trail and the kind of its rows.
AUDIT_CASE_ID = "org-profile"
AUDIT_KIND = "profile_change"
#: Relations that suggest the same owner (core vocabulary and module fragments). ``org seed
#: --any-relation`` proposes every pivot of the seed types instead.
SEED_RELATIONS: frozenset[str] = frozenset({
    "registrant", "company_of", "announces", "cert_san", "same_m365_tenant", "same_tenant", "parent_domain", "favicon",
    "owns_network", "spf_authorized", "headquarters", "bcb_verified_domain", "bcb_verified_domain_of", "declared_website",
})
#: Entity type -> profile list of a proposal.
SEED_KINDS: dict[str, str] = {"domain": "domains", "cidr": "cidrs", "asn": "asns", "cnpj": "cnpj_roots", "favicon_hash": "favicon_hashes"}
#: Inputs ``org seed`` accepts as scan seeds.
SEED_INPUT_TYPES = frozenset({"domain", "cnpj", "asn", "cidr", "company_name", "keyword", "ipv4", "ipv6"})


def _clean(value: Any) -> str:
    try:
        from v3lum.ui.safe import clean_text

        return clean_text(value)
    except Exception:  # noqa: BLE001 - WP14 helper unavailable: drop control characters here
        return "".join(ch for ch in str(value or "") if ch in "\n\t" or (ord(ch) >= 32 and not 0x7F <= ord(ch) <= 0x9F))


def _user_error(message: str) -> Exception:
    from v3lum.app import UserError

    return UserError(message)


def _tty() -> bool:
    try:
        return bool(sys.stdin.isatty())
    except (AttributeError, ValueError):
        return False


def _analyst(app: Any) -> str:
    fn = getattr(app, "analyst", None)
    if callable(fn):
        try:
            return str(fn() or "")
        except Exception:  # noqa: BLE001
            pass
    configured = str(app.config.get("analyst") or "").strip()
    if configured:
        return configured
    try:
        import getpass

        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"


def audit_profile_change(store: Any, payload: Mapping[str, Any]) -> None:
    """One audit row of kind 'profile_change' in the org-profile trail (``audit.CaseAudit`` with case
    id 'org-profile' and no case directory; the store's own hash chain - the same format - when the
    audit module is unavailable). Payloads name entries of the organisation, never executives."""
    try:
        from v3lum.core.audit import CaseAudit
    except Exception:  # noqa: BLE001 - WP15 not installed: the store's chain records it
        store.append_audit(AUDIT_CASE_ID, AUDIT_KIND, dict(payload))
        return
    CaseAudit(store, AUDIT_CASE_ID, None).append(AUDIT_KIND, dict(payload))  # no case directory: no mirror


# --------------------------------------------------------------------------------------
# profile access
# --------------------------------------------------------------------------------------


def _load(app: Any) -> tuple[Any, Path]:
    path = orgprofile.default_path(app.config)
    prof = orgprofile.OrgProfile.load(path)
    if not prof.path:
        prof.path = str(path)
    return prof, path


def _writable(path: Path) -> None:
    """Refuse to rewrite a profile v3lum could damage: invalid (data would be dropped), read-only
    (team-maintained) or unreadable."""
    if path.is_file():
        problems = orgprofile.validate(path)
        if problems:
            raise _user_error(
                f"the org profile has {len(problems)} problem(s) (v3lum org check {path}): fix them before v3lum changes the file "
                "(rewriting it could drop entries)"
            )
        if not os.access(path, os.W_OK):
            raise _user_error(f"the org profile {path} is read-only (team-maintained?): ask its maintainer to record the change")
    elif path.suffix.lower() == ".toml" and orgprofile._toml is None:  # pragma: no cover - Python 3.10
        raise _user_error("TOML profiles need Python 3.11+: set org_profile_path to an org_profile.json")


def _save(app: Any, prof: Any, path: Path, changes: list[dict[str, Any]], action: str) -> Path:
    before = prof.sha256
    try:
        written = orgprofile.save(prof, path)
    except (ValueError, OSError) as exc:
        raise _user_error(f"org profile not written: {exc}") from exc
    for change in changes:
        audit_profile_change(app.store, {
            "action": action, **change, "analyst": _analyst(app), "path": str(written),
            "profile_sha256_before": before, "profile_sha256_after": prof.sha256,
        })
    return written


# --------------------------------------------------------------------------------------
# show / check
# --------------------------------------------------------------------------------------


def _show(app: Any, console: Any, full: bool) -> int:
    prof, path = _load(app)
    if prof.is_empty and not prof.errors:
        console.print(Text(f"no org profile at {path}: v3lum org seed <domain|CNPJ|ASN> or v3lum org verify <domain>", style="v.dim"))
        return 0
    head = Text.assemble(("◈ org profile ", "v.accent"), (_clean(prof.name or "(no name)"), "v.title"), (f"  {path}", "v.dim"))
    if prof.sha256:
        head.append(f"  sha256 {prof.sha256[:16]}", style="v.ghost")
    console.print(head)
    states: dict[str, int] = {}
    for d in prof.domains:
        states[d.verification] = states.get(d.verification, 0) + 1
    hosted = sum(1 for d in prof.domains if d.third_party_hosted) + sum(1 for n in [*prof.cidrs, *prof.asns] if n.third_party_hosted)
    t = Table(box=box.SIMPLE, header_style="v.dim", title="[v.accent]domains[/]", title_justify="left")
    t.add_column("domain", style="v.entity", overflow="fold")
    t.add_column("verification", no_wrap=True)
    t.add_column("criticality", no_wrap=True)
    t.add_column("hosted by a third party", no_wrap=True)
    for d in prof.domains if full else prof.domains[:50]:
        state = d.verification + (f" ({d.attested_by}, {d.attested_date})" if d.verification == "attested" else "")
        t.add_row(Text(_clean(d.name)), Text(_clean(state), style="v.ok" if d.verified else "v.dim"), d.criticality, "yes" if d.third_party_hosted else "")
    if prof.domains:
        console.print(t)
    lines = [
        f"domains {len(prof.domains)} ({', '.join(f'{k} {v}' for k, v in sorted(states.items())) or '-'})",
        f"brands {len(prof.brands)}" + (f": {', '.join(prof.brand_terms()[:12])}" if prof.brands else ""),
        f"CNPJ roots {len(prof.cnpj_roots)}" + (f": {', '.join(prof.cnpj_roots[:12])}" if full and prof.cnpj_roots else ""),
        f"ASNs {len(prof.asns)}" + (f": {', '.join(n.value for n in prof.asns[:12])}" if prof.asns else ""),
        f"networks {len(prof.cidrs)}" + (f": {', '.join(n.value for n in prof.cidrs[:12])}" if prof.cidrs else ""),
        f"card BIN prefixes {len(prof.card_bins)} · favicon hashes {len(prof.favicon_hashes)} · app ids {len(prof.app_ids)} · suppliers {len(prof.suppliers)}",
        f"executives {len(prof.executives)} (explicit opt-in only; names are not shown)",
        f"third-party hosted entries {hosted} (never ACTIVE targets unless a scope lists them)",
    ]
    for line in lines:
        console.print(Text(f"  {_clean(line)}", style="v.text"), soft_wrap=True)
    if prof.errors:
        console.print(Text(f"[!] {len(prof.errors)} problem(s) while loading: v3lum org check", style="v.warn"))
    verified = sum(1 for d in prof.domains if d.verified)
    if prof.domains and not verified:
        console.print(Text("[i] no verified domain: own-asset-only modules stay off (v3lum org verify <domain>)", style="v.dim"))
    console.print(Text("  local file: never exported or sent; reports carry only own_asset/third_party tags and its SHA-256", style="v.ghost"))
    return 0


def _check(app: Any, console: Any, file: str | None) -> int:
    path = Path(file).expanduser() if file else orgprofile.default_path(app.config)
    if not path.exists():
        raise _user_error(f"no org profile at {path}")
    problems = sorted(orgprofile.validate(path), key=lambda p: (p.line or 10**9, p.field))
    if not problems:
        prof = orgprofile.OrgProfile.load(path)
        counts = ", ".join(f"{k} {v}" for k, v in prof.counts().items() if v) or "empty"
        console.print(Text(f"[✓] {path}: valid ({counts})", style="status.ok"), soft_wrap=True)
        return 0
    console.print(Text(f"[x] {path}: {len(problems)} problem(s)", style="status.error"), soft_wrap=True)
    for problem in problems:
        where = f"{path}:{problem.line}" if problem.line else str(path)
        field = f" {problem.field}:" if problem.field else ""
        console.print(Text(f"  {where}:{_clean(field)} {_clean(problem.message)}", style="status.error"), soft_wrap=True)
    return 1


# --------------------------------------------------------------------------------------
# verify / attest
# --------------------------------------------------------------------------------------


def _resolver(app: Any) -> Any:
    """The core DoH resolver (setting doh_providers / doh_internal / dns_mode) over the runtime."""
    from v3lum.core.dns import Resolver

    rt = app.runtime()
    cfg = app.config
    return Resolver(
        rt.doh_scope(module="org_verify"),
        mode=str(cfg.get("dns_mode") or "doh"),
        provider=str(cfg.get("doh_provider") or "google"),
        clock=rt.clock,
        settings=cfg,
    )


def _verify(app: Any, console: Any, args: Any) -> int:
    try:
        name = orgprofile._require_domain(args.domain)
    except ValueError as exc:
        raise _user_error(str(exc)) from exc
    prof, path = _load(app)
    _writable(path)
    current = next((d for d in prof.domains if d.name == name), None)
    if args.attest:
        by = str(args.by or "").strip()
        if not by:
            raise _user_error("--attest needs --by NAME (the analyst who attests the ownership)")
        try:
            entry = prof.mark_attested(name, by, args.date)
        except ValueError as exc:
            raise _user_error(str(exc)) from exc
        written = _save(app, prof, path, [{
            "field": "domains", "domain": name, "verification": "attested", "attested_by": entry.attested_by,
            "attested_date": entry.attested_date, "previous": current.verification if current else "",
        }], "attest")
        console.print(Text(f"[✓] {name} attested by {entry.attested_by} on {entry.attested_date}: saved to {written} (0600, audited)", style="v.ok"), soft_wrap=True)
        return 0
    if args.by or args.date:
        raise _user_error("--by/--date belong to --attest (without --attest the DNS TXT record is checked)")
    record = orgprofile.txt_record(name)
    result = orgprofile.verify_txt(_resolver(app), name)
    if result is None:
        console.print(Text(f"[~] could not verify {name}: the DNS lookup did not answer (nothing changed; try again later)", style="v.warn"), soft_wrap=True)
        return 1
    if result is False:
        console.print(Text(f"[x] {name}: no TXT record {record!r} found (nothing changed)", style="status.error"), soft_wrap=True)
        console.print(Text(f'    publish at {name}:  TXT "{record}"   then run: v3lum org verify {name}', style="v.text"), soft_wrap=True)
        return 1
    if current is not None and current.verification == "txt_verified":
        console.print(Text(f"[✓] {name} is txt_verified already (TXT record present)", style="v.ok"))
        return 0
    prof.mark_txt_verified(name)
    written = _save(app, prof, path, [{
        "field": "domains", "domain": name, "verification": "txt_verified", "previous": current.verification if current else "",
    }], "verify_txt")
    console.print(Text(f"[✓] {name} txt_verified (TXT {record}): saved to {written} (0600, audited)", style="v.ok"), soft_wrap=True)
    return 0


# --------------------------------------------------------------------------------------
# seed
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Proposal:
    """One seeding proposal: profile list ``kind``, normalised ``value``, the pivot that suggested
    it (``parent`` entity key, ``relation``, ``module``) and a third-party-hosting hint."""

    kind: str
    value: str
    parent: str
    relation: str
    module: str
    third_party_hosted: bool = False

    @property
    def label(self) -> str:
        return {"domains": "domain", "cidrs": "network", "asns": "ASN", "cnpj_roots": "CNPJ root", "favicon_hashes": "favicon hash", "app_ids": "M365 tenant"}.get(self.kind, self.kind)


def _proposal_value(kind: str, entity: Any) -> str:
    if kind == "cnpj_roots":
        import re

        return re.sub(r"[^0-9A-Za-z]", "", str(entity.value)).upper()[:8]
    return str(entity.value)


def _already(prof: Any, kind: str, value: str, entity: Any) -> bool:
    if kind == "cnpj_roots":
        return value in prof.cnpj_roots
    if kind == "favicon_hashes":
        return value in prof.favicon_hashes
    if kind == "cidrs":
        return any(n.value == value for n in prof.cidrs) or prof.owns(entity).own
    if kind == "asns":
        return any(n.value == value for n in prof.asns)
    return prof.owns(entity).own or prof.owns(entity).kind == "supplier"


def _hosted_hint(graph: Any, key: str) -> bool:
    """A domain that resolves (or is a CNAME) to CDN/cloud/hosting/SaaS infrastructure: proposed with
    the third_party_hosted flag (never an ACTIVE target unless a scope lists it, A11 BR7)."""
    from v3lum.core.noise import CDN_KINDS

    for edge in getattr(graph, "edges", None) or []:
        if edge.src != key or edge.relation not in ("resolves_to", "cname_to"):
            continue
        target = graph.nodes.get(edge.dst)
        if target is not None and str(getattr(target, "noise_kind", "") or "") in CDN_KINDS:
            return True
    return False


def seed_proposals(graph: Any, seeds: Iterable[Any], prof: Any, *, any_relation: bool = False) -> list[Proposal]:
    """Proposals from a seed scan graph: entities of :data:`SEED_KINDS` reached from the seeds (or
    from earlier proposals) through :data:`SEED_RELATIONS` edges (every relation with
    ``any_relation``), minus noise and what the profile already holds; plus M365 tenant ids
    (attribute ``m365_tenant_id``) of seed or proposed domains."""
    frontier = {getattr(s, "key", str(s)) for s in seeds}
    proposals: dict[tuple[str, str], Proposal] = {}
    reached = set(frontier)
    changed = True
    edges = list(getattr(graph, "edges", None) or [])
    while changed:
        changed = False
        for edge in edges:
            if edge.src not in reached or edge.dst in reached:
                continue
            if not any_relation and edge.relation not in SEED_RELATIONS:
                continue
            node = graph.nodes.get(edge.dst)
            if node is None or getattr(node, "noise", False):
                continue
            kind = SEED_KINDS.get(node.entity.type.value)
            if kind is None:
                continue
            value = _proposal_value(kind, node.entity)
            if len(value) == 0:
                continue
            if kind == "domains" and prof.owns(node.entity).kind == "supplier":
                continue  # a supplier's domain is never ours, nor a path to our assets
            # an entry the profile already holds is not proposed again, but it still leads on:
            # a known CNPJ root -> its NIC.br ASN -> the ASN's announced prefixes
            reached.add(edge.dst)
            changed = True
            if _already(prof, kind, value, node.entity):
                continue
            hosted = kind == "domains" and _hosted_hint(graph, edge.dst)
            proposals.setdefault((kind, value), Proposal(kind, value, edge.src, edge.relation, edge.module, hosted))
    for key in sorted(reached):
        node = graph.nodes.get(key)
        if node is None or node.entity.type.value != "domain":
            continue
        for tenant, _source in node.attributes.get("m365_tenant_id", []) or []:
            value = str(tenant or "").strip()
            if value and not any(a.kind == "m365_tenant" and a.value == value for a in prof.app_ids):
                proposals.setdefault(("app_ids", value), Proposal("app_ids", value, key, "m365_tenant_id", str(_source or ""), False))
    order = list(SEED_KINDS.values()) + ["app_ids"]
    return sorted(proposals.values(), key=lambda p: (order.index(p.kind), p.value))


def _seed_inputs(app: Any, prof: Any, inputs: list[str]) -> list[Any]:
    from v3lum.core import detect as det

    raw = list(inputs)
    if not raw:
        raw = [d.name for d in prof.domains if d.verification != "seeded" and not d.third_party_hosted]
        raw += [f"asn:{n.value}" for n in prof.asns if not n.third_party_hosted]
    seeds: list[Any] = []
    scrub = getattr(app, "scrub_input", None)
    for item in raw:
        value = scrub(item, None) if callable(scrub) else item
        found = det.detect(value)
        picks = [d.entity for d in det.primary(found) if d.entity.type.value in SEED_INPUT_TYPES] if found else []
        if not picks:
            raise _user_error(f"org seed takes domains, CNPJs, ASNs, networks, company names or keywords: {_clean(item)[:80]!r} is not one")
        for ent in picks:
            if ent not in seeds:
                seeds.append(ent)
    return seeds


def _apply(prof: Any, proposal: Proposal, note: str) -> dict[str, Any]:
    if proposal.kind == "domains":
        prof.add_domain(proposal.value, verification="seeded", third_party_hosted=proposal.third_party_hosted, note=note)
    elif proposal.kind in ("cidrs", "asns"):
        prof.add_network(proposal.kind, proposal.value, third_party_hosted=proposal.third_party_hosted, note=note)
    elif proposal.kind == "cnpj_roots":
        prof.add_cnpj_root(proposal.value)
    elif proposal.kind == "favicon_hashes":
        if proposal.value not in prof.favicon_hashes:
            prof.favicon_hashes.append(proposal.value)
    elif proposal.kind == "app_ids":
        prof.add_app_id("m365_tenant", proposal.value, note=note)
    return {"field": proposal.kind, "value": proposal.value, "via": f"{proposal.module}:{proposal.relation}", "third_party_hosted": proposal.third_party_hosted}


def _seed(app: Any, console: Any, args: Any) -> int:
    from v3lum.core import tlp as _tlp
    from v3lum.core.context import ScanOptions
    from v3lum.core.engine import Engine
    from v3lum.core.models import Opsec

    prof, path = _load(app)
    _writable(path)
    seeds = _seed_inputs(app, prof, list(args.inputs or []))
    if not seeds:
        raise _user_error("nothing to seed from: give domains, CNPJs or ASNs (v3lum org seed acme.com.br 12.345.678/0001-90 AS64500)")
    try:
        level = _tlp.parse(args.tlp or app.config.get("tlp") or "amber")
    except ValueError as exc:
        raise _user_error(str(exc)) from exc
    include = {m.strip() for m in str(args.modules or "").split(",") if m.strip()}
    options = ScanOptions(
        mode=Opsec.PASSIVE,  # seeding is passive, never LIGHT/ACTIVE (P378 cond 8)
        depth=max(0, int(args.depth)),
        max_entities=int(app.config.get("max_entities") or 150),
        threads=int(app.config.get("threads") or 12),
        include=include,
        offline=bool(getattr(app, "offline", False)),
        no_cache=bool(getattr(app, "no_cache", False)),
        save_evidence=False,
        tlp=level.value_str,
        seed_tlp={s.key: level.value_str for s in seeds},
        purpose="org profile seeding (own assets)",
    )
    feed: Any = None
    try:
        from v3lum.ui.live import LiveFeed

        feed = LiveFeed(console, verbosity=getattr(app, "verbosity", 1))
    except Exception:  # noqa: BLE001
        feed = None
    rt = app.runtime(listener=feed) if feed is not None else app.runtime()
    engine = Engine(rt, options)  # a normal passive scan: every module goes through the policy gate
    if feed is not None:
        with feed:
            case = engine.investigate(seeds)
    else:
        case = engine.investigate(seeds)
    proposals = seed_proposals(case.graph, seeds, prof, any_relation=bool(args.any_relation))
    if not proposals:
        console.print(Text("no new entries proposed (the passive sources found nothing the profile does not hold)", style="v.dim"))
        return 0
    t = Table(box=box.SIMPLE, header_style="v.dim", title="[v.accent]proposals (nothing is trusted until you confirm it)[/]", title_justify="left")
    t.add_column("#", justify="right", style="v.dim")
    t.add_column("kind", no_wrap=True)
    t.add_column("value", style="v.entity", overflow="fold")
    t.add_column("found by", style="v.dim", overflow="fold")
    for n, p in enumerate(proposals, 1):
        via = f"{p.module}: {p.relation} of {p.parent}" + (" (third-party hosted?)" if p.third_party_hosted else "")
        t.add_row(str(n), p.label, Text(_clean(p.value)), Text(_clean(via)))
    console.print(t)
    if not _tty():
        console.print(Text("non-interactive session: nothing written. Run `v3lum org seed` in a terminal to confirm each proposal.", style="v.warn"), soft_wrap=True)
        return 0
    accepted: list[dict[str, Any]] = []
    note = f"org seed {case.created[:10]}"
    for n, p in enumerate(proposals, 1):
        answer = Prompt.ask(
            f"[v.accent][{n}/{len(proposals)}][/] add {p.label} [v.entity]{_clean(p.value)}[/]? [v.dim](y/n/q)[/]",
            choices=["y", "n", "q"], default="n", console=console, show_choices=False,
        )
        if answer == "q":
            break
        if answer != "y":
            continue
        try:
            accepted.append(_apply(prof, p, f"{note}: {p.module} {p.relation}"))
        except ValueError as exc:
            console.print(Text(f"    skipped: {_clean(exc)}", style="v.warn"))
    if not accepted:
        console.print(Text("nothing added", style="v.dim"))
        return 0
    written = _save(app, prof, path, accepted, "seed")
    console.print(Text(f"[✓] {len(accepted)} entr{'y' if len(accepted) == 1 else 'ies'} added as 'seeded' to {written} (0600, audited). "
                       "Verified states come only from v3lum org verify.", style="v.ok"), soft_wrap=True)
    return 0


# --------------------------------------------------------------------------------------
# the command
# --------------------------------------------------------------------------------------


@command("org", "organisation profile: show, check, verify (DNS TXT or attestation), seed (never sent anywhere)")
class Org:
    """The local organisation profile (P378): never exported, every change audited."""

    @staticmethod
    def add_arguments(parser: Any) -> None:
        sub = parser.add_subparsers(dest="org_cmd", metavar="<action>")
        sh = sub.add_parser("show", help="summary of the profile (local only)")
        sh.add_argument("--full", action="store_true", help="every entry")
        ck = sub.add_parser("check", help="strict schema validation with line/field errors")
        ck.add_argument("file", nargs="?", help="profile file (default: setting org_profile_path or ~/.v3lum/org_profile.toml)")
        vf = sub.add_parser("verify", help="DNS TXT proof of control (or --attest --by NAME)")
        vf.add_argument("domain")
        vf.add_argument("--attest", action="store_true", help="record an analyst attestation instead of the DNS check")
        vf.add_argument("--by", metavar="NAME", help="with --attest: the analyst who attests the ownership")
        vf.add_argument("--date", metavar="YYYY-MM-DD", help="with --attest: the attestation date (default today)")
        sd = sub.add_parser("seed", help="propose entries from passive sources; each needs your confirmation")
        sd.add_argument("inputs", nargs="*", help="domains, CNPJs, ASNs, networks (default: the profile's own domains and ASNs)")
        sd.add_argument("-d", "--depth", type=int, default=2, help="pivot depth of the seed scan (default 2)")
        sd.add_argument("-M", "--modules", help="only these modules (comma separated)")
        sd.add_argument("--tlp", choices=["clear", "green", "amber", "amber+strict", "red"], help="TLP of the seed scan (default: setting tlp)")
        sd.add_argument("--any-relation", action="store_true", help="propose pivots of every relation (default: ownership relations only)")

    @staticmethod
    def run(args: Any, app: Any, console: Any) -> int:
        action = getattr(args, "org_cmd", None) or "show"
        if action == "show":
            return _show(app, console, bool(getattr(args, "full", False)))
        if action == "check":
            return _check(app, console, getattr(args, "file", None))
        if action == "verify":
            return _verify(app, console, args)
        if action == "seed":
            return _seed(app, console, args)
        raise _user_error(f"unknown org action {action!r}")
