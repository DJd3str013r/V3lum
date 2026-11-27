"""Print text after the last anchor of an item's HTML field (untrusted data; python3 -I)."""
import json
import re
import sys

with open(sys.argv[1], "rb") as fh:
    page = json.loads(fh.read().decode("utf-8"))
for it in page.get("items") or []:
    if it.get("path") == sys.argv[2]:
        s = it.get(sys.argv[3]) or ""
        idx = s.rfind("</a>")
        print("anchors:", len(re.findall(r"<a\b", s)), "len:", len(s))
        print(s[idx:idx + 1500])
