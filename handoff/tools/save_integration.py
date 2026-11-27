"""Save a core integration workflow result as impl/core/wave<N>_integration.json and print a summary.

Usage: python3 -I save_integration.py <scratchpad> <wave> <task.output>
"""

from __future__ import annotations

import json
import os
import sys

S, wave, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
raw = open(path).read()
try:
    doc = json.loads(raw)
except ValueError:
    doc = json.loads(raw[raw.find("{"):])
res = doc.get("result", doc)
if isinstance(res, str):
    res = json.loads(res)
out = os.path.join(S, "impl", "core", f"wave{wave}_integration.json")
json.dump(res, open(out, "w"), indent=1, ensure_ascii=False)
for role in ("integ", "audit"):
    r = res.get(role) or {}
    print(f"== {role}: suite={r.get('suite')!r} ruff={r.get('ruff')!r}")
    print(f"   fixes: {len(r.get('fixes') or [])}")
    for d in r.get("open_defects") or []:
        print("   OPEN:", " ".join(str(d).split())[:500])
    print("   contract_notes:", " ".join(str(r.get("contract_notes") or "").split())[:1500])
print("saved", out)
