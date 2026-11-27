"""Check that no real poster title, alias or name-like anchor text from the raw FBI pages appears in fixtures/.

Usage: python3 -I scan_fixtures_pii.py <raw_dir> <fixtures_dir>   (names are read at runtime, never stored here)
"""
import html
import json
import re
import sys
import unicodedata
from pathlib import Path


def fold(s):
    s = unicodedata.normalize("NFKD", s or "")
    s = "".join(c for c in s if not unicodedata.combining(c)).casefold()
    return " ".join(re.sub(r"[^0-9a-z]+", " ", s).split())


def main():
    raw, fx = Path(sys.argv[1]), Path(sys.argv[2])
    names = set()
    for f in raw.glob("fbi_*.json"):
        try:
            obj = json.loads(f.read_bytes().decode("utf-8", "replace"))
        except ValueError:
            continue
        for it in obj.get("items") or [] if isinstance(obj, dict) else []:
            t = fold(it.get("title"))
            if t and not re.search(r"\b(group|hackers|workers|arson|robbery|shooting|unknown|john doe|jane doe)\b", t):
                names.add(t)
            for a in it.get("aliases") or []:
                if len(fold(a)) >= 5:
                    names.add(fold(a))
            for fld in ("caution", "remarks", "details"):
                for label in re.findall(r"<a\b[^>]*>(.*?)</a>", it.get(fld) or "", re.S):
                    lab = fold(html.unescape(re.sub(r"<[^>]+>", " ", label)))
                    if len(lab.split()) >= 2 and "apt" not in lab:
                        names.add(lab)
    hits = 0
    texts = {f.name: " " + fold(f.read_bytes().decode("utf-8", "replace")) + " " for f in fx.iterdir()}
    for n in sorted(names):
        for fname, t in texts.items():
            if " " + n + " " in t:
                hits += 1
                print("HIT", fname, "<name of length", len(n), ">")
    print(f"checked {len(names)} real names/aliases against {len(texts)} fixtures: {hits} hits")
    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
