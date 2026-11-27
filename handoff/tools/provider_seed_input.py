"""Build the input for the provider-seed step that runs before the module batches.

Every host an approved module proposal contacts must belong to exactly one provider fragment
(v3lum/data/providers/). Batches run in parallel, so hosts used by more than one batch are seeded
once, centrally, before the batches start; the batches then only extend those providers.

Writes impl/providers_seed/:
  hosts.json      every host -> {batches, proposals, modules, core_owner}
  shared.json     hosts used by >= 2 batches and not owned by a core seed fragment
  dossier.md      per shared registrable domain: all hosts of that domain used by any batch, the
                  proposals (auth, keys, terms, tier, opsec) and the research records (terms, limits)
Usage: python3 -I provider_seed_input.py <scratchpad> <repo>
"""

from __future__ import annotations

import collections
import glob
import json
import os
import sys

S, REPO = sys.argv[1], sys.argv[2]
OUT = os.path.join(S, "impl", "providers_seed")
os.makedirs(OUT, exist_ok=True)
dec = json.load(open(os.path.join(S, "research", "council1", "decisions.json")))["proposals"]
batches = json.load(open(os.path.join(S, "impl", "batches.json")))
cands = {c["id"]: c for c in json.load(open(os.path.join(S, "research", "catalog.json")))["candidates"]}

# public suffix list from the repo (bundled data), for registrable domains
psl_rules: set[str] = set()
psl_wild: set[str] = set()
psl_exc: set[str] = set()
for line in open(os.path.join(REPO, "v3lum", "data", "public_suffix_list.dat"), encoding="utf-8"):
    line = line.strip()
    if not line or line.startswith("//"):
        continue
    line = line.split()[0]
    if line.startswith("!"):
        psl_exc.add(line[1:])
    elif line.startswith("*."):
        psl_wild.add(line[2:])
    else:
        psl_rules.add(line)


def registrable(host: str) -> str:
    labels = host.split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in psl_exc:
            return cand
        parent = ".".join(labels[i + 1:])
        if cand in psl_rules or (parent and parent in psl_wild):
            if i == 0:
                return host
            return ".".join(labels[i - 1:])
    return ".".join(labels[-2:])


core_owner: dict[str, str] = {}
for f in sorted(glob.glob(os.path.join(REPO, "v3lum", "data", "providers", "*.json"))):
    try:
        doc = json.load(open(f))
    except ValueError:
        continue
    stem = os.path.basename(f)[:-5]
    for h in doc.get("hosts", []) or []:
        core_owner[h] = doc.get("extends") or doc.get("id") or stem
    for p in doc.get("providers", []) or []:
        for h in p.get("hosts", []) or []:
            core_owner[h] = p.get("id", stem)

hosts: dict[str, dict] = collections.defaultdict(lambda: {"batches": set(), "proposals": set(), "modules": set()})
for b in batches:
    for pid in b["proposals"]:
        d = dec[pid]
        for h in d.get("hosts") or []:
            h = (h or "").strip().lower().rstrip(".")
            if not h or " " in h or "/" in h or ":" in h:
                continue
            e = hosts[h]
            e["batches"].add(b["batch"])
            e["proposals"].add(pid)
            e["modules"].add(d["module_name"])

out_hosts = {
    h: {"batches": sorted(e["batches"]), "proposals": sorted(e["proposals"]), "modules": sorted(e["modules"]),
        "registrable": registrable(h), "core_owner": core_owner.get(h)}
    for h, e in sorted(hosts.items())
}
json.dump(out_hosts, open(os.path.join(OUT, "hosts.json"), "w"), indent=1)
shared = {h: v for h, v in out_hosts.items() if len(v["batches"]) > 1 and not v["core_owner"]}
json.dump(shared, open(os.path.join(OUT, "shared.json"), "w"), indent=1)

by_dom: dict[str, list[str]] = collections.defaultdict(list)
for h, v in out_hosts.items():
    by_dom[v["registrable"]].append(h)
shared_doms = sorted({v["registrable"] for v in shared.values()})

L = ["# Provider seed dossier", "",
     f"{len(out_hosts)} hosts used by approved module proposals; {len(shared)} are used by >= 2 batches and have no core owner. "
     f"They fall under {len(shared_doms)} registrable domains, listed below with EVERY host of that domain any batch uses "
     "(seed all of them, so batches never need to add a host to a shared provider).", ""]
for dom in shared_doms:
    L.append(f"## {dom}")
    L.append("")
    for h in sorted(by_dom[dom]):
        v = out_hosts[h]
        L.append(f"- host `{h}`{' (core owner: ' + v['core_owner'] + ')' if v['core_owner'] else ''} - batches {', '.join(v['batches'])}")
    pids = sorted({p for h in by_dom[dom] for p in out_hosts[h]["proposals"]})
    L.append("")
    for pid in pids:
        d = dec[pid]
        L.append(
            f"- {pid} `{d['module_name']}` ({d['decision']}, {d.get('priority')}, opsec {d['opsec']}, auth {d.get('auth')}, "
            f"terms {d.get('terms')}, tier {d.get('provider_tier')}, default_enabled {d.get('default_enabled')}, "
            f"keys {', '.join(d.get('key_env_vars') or []) or '-'}; hosts {', '.join(d.get('hosts') or [])})"
        )
        for c in d.get("final_conditions", []):
            low = c.lower()
            if any(w in low for w in ("terms", "licen", "quota", "rate", "per day", "per minute", "key", "user-agent", "user agent", "tier", "429", "captcha", "block")):
                L.append(f"    - condition: {' '.join(c.split())}")
        for cid in d.get("candidates", []):
            c = cands.get(cid)
            if not c:
                continue
            ch = [x for x in (c.get("hosts") or []) if registrable(str(x).lower()) == dom]
            if not ch and dom not in str(c.get("endpoint", "")):
                continue
            L.append(
                f"    - research {cid} {c.get('name')}: endpoint {c.get('endpoint')}; auth {c.get('auth')}; key {c.get('key_env_var')}; "
                f"rate limit {' '.join(str(c.get('rate_limit') or '').split())}; terms {' '.join(str(c.get('license_or_terms') or '').split())}; "
                f"status {c.get('status')} {c.get('http_status_seen') or ''}"
            )
    L.append("")
open(os.path.join(OUT, "dossier.md"), "w").write("\n".join(L) + "\n")
print("hosts", len(out_hosts), "shared", len(shared), "shared registrable domains", len(shared_doms))
print(", ".join(shared_doms))
