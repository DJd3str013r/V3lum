"""Merge core wave workflow outputs into one reports file for the wave integrator.

Usage: python3 -I wave_reports.py <out.json> <task.output> [<task.output> ...]
"""

from __future__ import annotations

import json
import sys

out, files = sys.argv[1], sys.argv[2:]
merged: list = []
for f in files:
    raw = open(f).read()
    try:
        doc = json.loads(raw)
    except ValueError:
        # some outputs wrap the JSON result after a text prefix
        start = raw.find("{")
        doc = json.loads(raw[start:])
    res = doc.get("result", doc)
    if isinstance(res, str):
        res = json.loads(res)
    for item in res.get("results", []) or []:
        merged.append(item)
json.dump({"packages": merged}, open(out, "w"), indent=1, ensure_ascii=False)
for item in merged:
    if not item:
        print("null result")
        continue
    impl, rev = item.get("impl") or {}, item.get("review") or {}
    print(item.get("id"), "| impl done:", impl.get("done"), "| tests:", impl.get("test_result"), "| open:", len(impl.get("open_issues") or []),
          "| review:", rev.get("verdict"), "| remaining:", len(rev.get("remaining") or []))
