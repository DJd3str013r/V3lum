"""Build a core-wave style output ({"result": {"results": [{id, impl, review}]}}) from a running
workflow's journal, so finished packages can feed wave_reports.py before the workflow ends.

Usage: python3 -I journal_to_output.py <journal.jsonl> <out.json>
"""

from __future__ import annotations

import json
import sys

src, out = sys.argv[1], sys.argv[2]
label_of: dict[str, str] = {}
res: dict[str, dict] = {}
order: list[str] = []
for line in open(src):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if e.get("type") == "started":
        label_of[e["key"]] = e.get("label", "")
    elif e.get("type") == "result":
        lab = label_of.get(e["key"], "")
        if ":" not in lab:
            continue
        kind, pid = lab.split(":", 1)
        val = e.get("result")
        if isinstance(val, str):
            try:
                val = json.loads(val)
            except ValueError:
                pass
        if pid not in res:
            res[pid] = {"id": pid, "impl": None, "review": None}
            order.append(pid)
        res[pid][kind] = val
json.dump({"result": {"results": [res[p] for p in order]}}, open(out, "w"), indent=1, ensure_ascii=False)
for p in order:
    print(p, "impl" if res[p]["impl"] else "-", "review" if res[p]["review"] else "(review pending)")
