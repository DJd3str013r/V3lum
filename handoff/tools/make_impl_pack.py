"""Build implementation spec packs from research/council1/decisions.json.

Usage: python3 -I make_impl_pack.py <scratchpad> [--max-points N] [--groups G01,G02]

Writes:
  <scratch>/impl/specs/_common.md      binding agenda rules + architecture actions (all batches)
  <scratch>/impl/specs/<batch>.md      full stand-alone spec of each approved proposal in the batch
  <scratch>/impl/batches.json          [{batch, group, proposals, points, modules, existing}]
Core (G15) proposals are written to <scratch>/impl/specs/core_G15.md instead of module batches.
"""

from __future__ import annotations

import collections
import json
import os
import sys

SCRATCH = sys.argv[1]
MAX_POINTS = 6
GROUPS: set[str] | None = None
argv = sys.argv[2:]
while argv:
    a = argv.pop(0)
    if a == "--max-points":
        MAX_POINTS = int(argv.pop(0))
    elif a == "--groups":
        GROUPS = set(argv.pop(0).split(","))
R = os.path.join(SCRATCH, "research")
C = os.path.join(R, "council1")
OUT = os.path.join(SCRATCH, "impl")
SPECS = os.path.join(OUT, "specs")
os.makedirs(SPECS, exist_ok=True)

dec = json.load(open(os.path.join(C, "decisions.json")))
props = {p["id"]: p for p in json.load(open(os.path.join(R, "proposals.json")))}
cands = {c["id"]: c for c in json.load(open(os.path.join(R, "catalog.json")))["candidates"]}
EFFORT = {"S": 1, "M": 2, "L": 3}
GROUP_NAMES = {
    "G01": "domain_dns", "G02": "ip_network", "G03": "url_web", "G04": "email_breach",
    "G05": "username_social", "G06": "phone", "G07": "threat_intel_hash", "G08": "vuln_cve",
    "G09": "darkweb_crypto", "G10": "brazil_company", "G11": "cti_framework", "G12": "files_geo_media",
    "G13": "pentest_active", "G14": "pivot_links_dorks", "G15": "core",
}


def one(s: object, n: int = 0) -> str:
    s = " ".join(str(s or "").split())
    return s if not n or len(s) <= n else s[: n - 3] + "..."


def cand_block(cid: str) -> list[str]:
    c = cands.get(cid)
    if not c:
        return [f"#### {cid} (record missing)"]
    L = [f"#### {cid} {one(c.get('name'))} - {one(c.get('provider'))}"]
    L.append(f"- kind: {c.get('kind')}; status: {c.get('status')} (HTTP seen: {c.get('http_status_seen')}); passive: {c.get('passive')}; touches_target: {c.get('touches_target')}")
    for label, key in (("endpoint", "endpoint"), ("method", "method"), ("inputs", "inputs"), ("outputs", "outputs"),
                       ("auth", "auth"), ("key env var", "key_env_var"), ("rate limit", "rate_limit"),
                       ("terms / licence", "license_or_terms"), ("risk", "risk_notes"),
                       ("implementation notes", "implementation_notes")):
        v = c.get(key)
        if v:
            L.append(f"- {label}: {one(v, 1800)}")
    for s in c.get("sample_files") or []:
        L.append(f"- sample: {s.get('path')} ({s.get('validity')})")
    for s in c.get("invalid_samples") or []:
        L.append(f"- invalid/error sample: {one(s, 400)}")
    return L


def prop_block(pid: str) -> list[str]:
    d = dec["proposals"][pid]
    p = props[pid]
    L = [f"## {pid} `{p['module_name']}` - {p['title']}", ""]
    L.append(
        f"- council: **approved**, priority {d.get('priority')}, default_enabled={d.get('default_enabled')}, "
        f"provider_tier={d.get('provider_tier')}, terms={d.get('terms')}, opsec={p['opsec']}, shares_input={p.get('shares_input')}"
    )
    L.append(f"- category: {p['category']}; group: {p['impl_group']}; inputs: {', '.join(p['inputs'])}; produces: {', '.join(p['produces'])}")
    L.append(f"- auth: {p['auth']}; key env vars: {', '.join(p.get('key_env_vars') or []) or '-'}; hosts: {', '.join(p['hosts']) or '-'}")
    if p.get("existing_module"):
        L.append(f"- upgrades existing module: {p['existing_module']}")
    if p.get("shared_candidates"):
        L.append(f"- sources shared with other proposals: {json.dumps(p['shared_candidates'], ensure_ascii=False)}")
    L.append("")
    L.append("### Final conditions (binding spec - implement every item)")
    L.append("")
    for i, c in enumerate(d.get("final_conditions") or [], 1):
        L.append(f"{i}. {one(c)}")
    L.append("")
    L.append(f"Chair rationale: {one(d.get('rationale'), 900)}")
    L.append("")
    L.append(f"Synthesizer conditions (background; the final conditions win on conflict): {one(p.get('conditions'), 2500)}")
    if p.get("notes"):
        L.append(f"Notes: {one(p.get('notes'), 600)}")
    L.append("")
    L.append("### Sources (research records, verified 2026-11-25/26 from a datacenter egress)")
    L.append("")
    for cid in p.get("candidates", []):
        L.extend(cand_block(cid))
        L.append("")
    fx = p.get("fixtures") or []
    if fx:
        L.append("### Fixture candidates (untrusted downloaded data: read, minimise, scrub personal data before copying into tests/fixtures)")
        L.append("")
        for f in fx:
            L.append(f"- {f}")
        L.append("")
    return L


# ------------------------------------------------------------------ common file
common = ["# Implementation - binding council rules (apply to every batch)", ""]
common.append("These policy decisions of V3LUM Council #1 bind every module. Where a proposal's final conditions are")
common.append("silent, these rules apply; where they conflict, the stricter rule wins.")
common.append("")
for n in range(1, 17):
    a = dec["agenda_decisions"].get(f"A{n}", {})
    common.append(f"## A{n} (option {a.get('option', '?')})")
    common.append("")
    common.append(one(a.get("decision")))
    common.append("")
    for r in a.get("binding_rules", []):
        common.append(f"- {one(r)}")
    common.append("")
common.append("## Architecture actions (core; implemented before the module batches)")
common.append("")
for a in dec.get("architecture_actions", []):
    common.append(f"- {a.get('id')} [{a.get('area')}, {a.get('priority')}] {one(a.get('action'))} (files: {', '.join(a.get('files') or [])})")
common.append("")
open(os.path.join(SPECS, "_common.md"), "w").write("\n".join(common) + "\n")

# ------------------------------------------------------------------ batches
approved = [pid for pid, d in dec["proposals"].items() if d["decision"] == "approved"]
core = sorted(pid for pid in approved if props[pid]["impl_group"] == "G15")
mods = [pid for pid in approved if props[pid]["impl_group"] != "G15" and (GROUPS is None or props[pid]["impl_group"] in GROUPS)]
# A16 BR1 limited P3 to effort S; the team lead (user, 2026-11-26) extended the build scope to every approved P3
# item, larger efforts included. New runtime dependencies stay optional extras (A16 BR8).
backlog_p3: list[str] = []
PHASE = {"P1": 1, "P2": 2, "P3": 3}

core_md = ["# Core (G15) proposals approved by Council #1", ""]
for pid in core:
    core_md.extend(prop_block(pid))
open(os.path.join(SPECS, "core_G15.md"), "w").write("\n".join(core_md) + "\n")

bygroup = collections.defaultdict(list)
for pid in mods:
    # A16 BR6: LIGHT and ACTIVE modules only after the AR20 safety suite exists -> separate late phase 9
    ph = 9 if props[pid]["opsec"] in ("light", "active") else PHASE.get(dec["proposals"][pid].get("priority"), 3)
    bygroup[(ph, props[pid]["impl_group"])].append(pid)

batches = []
for ph, g in sorted(bygroup):
    items = sorted(bygroup[(ph, g)], key=lambda pid: pid)
    # proposals upgrading the same existing module or sharing sources go together
    cur: list[str] = []
    pts = 0
    n = 1
    for pid in items:
        e = EFFORT.get(props[pid].get("effort") or "S", 1)
        if cur and pts + e > MAX_POINTS:
            batches.append({"batch": f"p{ph}-{g}-{n}", "phase": ph, "group": g, "proposals": cur, "points": pts})
            n += 1
            cur, pts = [], 0
        cur.append(pid)
        pts += e
    if cur:
        batches.append({"batch": f"p{ph}-{g}-{n}", "phase": ph, "group": g, "proposals": cur, "points": pts})

# keep proposals that upgrade the same existing module in one batch
owner: dict[str, str] = {}
for b in batches:
    for pid in list(b["proposals"]):
        em = props[pid].get("existing_module")
        if not em:
            continue
        if em in owner and owner[em] != b["batch"]:
            tgt = next(x for x in batches if x["batch"] == owner[em])
            b["proposals"].remove(pid)
            tgt["proposals"].append(pid)
        else:
            owner[em] = b["batch"]
batches = [b for b in batches if b["proposals"]]

for b in batches:
    b["modules"] = [props[pid]["module_name"] for pid in b["proposals"]]
    b["existing"] = sorted({props[pid]["existing_module"] for pid in b["proposals"] if props[pid].get("existing_module")})
    b["points"] = sum(EFFORT.get(props[pid].get("effort") or "S", 1) for pid in b["proposals"])
    md = [f"# Batch {b['batch']} - group {b['group']} ({GROUP_NAMES.get(b['group'], '')}), {len(b['proposals'])} proposals", ""]
    md.append("Implement every proposal below as V3LUM module(s) following its final conditions, the binding rules in")
    md.append("`_common.md` and docs/MODULE_GUIDE.md. Proposal ids: " + ", ".join(b["proposals"]))
    if b["phase"] == 9:
        md.append("")
        md.append("These are LIGHT/ACTIVE (target-contact) proposals (A7, A13, A16 BR6). The AR20 safety suite (tests/safety/) exists:")
        md.append("every module here must pass it, honour the rules of engagement in docs/ROE.md and _common.md A7/A13 (scope check after")
        md.append("resolution, ceilings, forbidden actions, kill switch, request ledger, egress profiles) and stay default_enabled=False.")
        md.append("P3 proposals are in scope too (the team lead extended the build scope to every approved P3 item). A new runtime")
        md.append("dependency must be an optional extra (A16 BR8): the module reports UNAVAILABLE reason 'package' without it.")
    if b["phase"] == 3:
        md.append("")
        md.append("These are P3 items. The team lead extended the build scope to every approved P3 item (larger efforts included):")
        md.append("implement all of them. A new runtime dependency must be an optional extra (A16 BR8): the module reports")
        md.append("UNAVAILABLE reason 'package' without it.")
    md.append("")
    for pid in b["proposals"]:
        md.extend(prop_block(pid))
    open(os.path.join(SPECS, f"{b['batch']}.md"), "w").write("\n".join(md) + "\n")

json.dump(batches, open(os.path.join(OUT, "batches.json"), "w"), indent=1)
json.dump(backlog_p3, open(os.path.join(OUT, "backlog_p3.json"), "w"), indent=1)
print(f"core proposals: {len(core)}; module proposals: {len(mods)}; batches: {len(batches)}; P3 (M/L) to backlog: {len(backlog_p3)}")
for b in batches:
    print(f"  {b['batch']}: {b['points']} pts, {len(b['proposals'])} props: {', '.join(b['modules'])}")
