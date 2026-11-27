"""Collect items earlier waves left for later core packages.

Reads impl/core/wave<N>_reports.json (implementer + reviewer reports) and impl/core/wave<N>_integration.json
(integrator + auditor results) for every finished wave and writes:
  impl/core/carry/<WP>.md      every open issue / remaining problem / open defect that names <WP>
  impl/core/contract_notes.md  the integrators' and auditors' contract notes, wave by wave
Usage: python3 -I carry_forward.py <scratchpad>
"""

from __future__ import annotations

import collections
import glob
import json
import os
import re
import sys

S = sys.argv[1]
CORE = os.path.join(S, "impl", "core")
plan = json.load(open(os.path.join(CORE, "plan.json")))
wave_of = {}
for w in plan["waves"]:
    for p in w["packages"]:
        wave_of[p["id"]] = w["wave"] if "wave" in w else w.get("id")

WP_RE = re.compile(r"\bWP(\d{2})\b")
items: dict[str, list[str]] = collections.defaultdict(list)
notes: list[str] = []


def add(text: str, origin: str) -> None:
    text = " ".join(str(text).split())
    for num in sorted(set(WP_RE.findall(text))):
        wp = f"WP{num}"
        line = f"- ({origin}) {text}"
        if line not in items[wp]:
            items[wp].append(line)


for path in sorted(glob.glob(os.path.join(CORE, "wave*_reports.json"))):
    wave = re.search(r"wave(\d+)_reports", path).group(1)
    for pkg in json.load(open(path)).get("packages", []):
        if not pkg:
            continue
        pid = pkg.get("id")
        for x in (pkg.get("impl") or {}).get("open_issues", []) or []:
            add(x, f"wave {wave} {pid} implementer")
        for x in (pkg.get("review") or {}).get("remaining", []) or []:
            add(x, f"wave {wave} {pid} reviewer")

for path in sorted(glob.glob(os.path.join(CORE, "wave*_integration.json"))):
    wave = re.search(r"wave(\d+)_integration", path).group(1)
    doc = json.load(open(path))
    for role in ("integ", "audit"):
        r = doc.get(role) or {}
        for x in r.get("open_defects", []) or []:
            add(x, f"wave {wave} {role}")
        if r.get("contract_notes"):
            notes.append(f"## Wave {wave} ({'integrator' if role == 'integ' else 'auditor'})\n\n{r['contract_notes'].strip()}\n")

os.makedirs(os.path.join(CORE, "carry"), exist_ok=True)
for wp, lines in sorted(items.items()):
    hdr = (
        f"# Items earlier waves left for {wp}\n\n"
        "Each item was written by an implementer, reviewer, integrator or auditor of an earlier wave. Resolve the ones "
        f"that fall inside {wp}'s scope (its owns list); if an item is wrong or already done, say so in your report.\n\n"
    )
    with open(os.path.join(CORE, "carry", f"{wp}.md"), "w") as fh:
        fh.write(hdr + "\n".join(lines) + "\n")
with open(os.path.join(CORE, "contract_notes.md"), "w") as fh:
    fh.write("# Contract notes from finished waves\n\n" + ("\n".join(notes) if notes else "(none yet)\n"))
for wp, lines in sorted(items.items()):
    print(wp, "wave", wave_of.get(wp), len(lines), "items")
print("contract notes sections:", len(notes))
