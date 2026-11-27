"""Summarise an untrusted FBI wanted list page: total, page, item count, subjects/path/classification per item. Run with python3 -I."""
import collections
import json
import sys


def main():
    with open(sys.argv[1], "rb") as fh:
        obj = json.loads(fh.read().decode("utf-8", "replace"))
    items = obj.get("items") or []
    print("total", obj.get("total"), "page", obj.get("page"), "items", len(items))
    subj = collections.Counter()
    cyber = 0
    for it in items:
        s = it.get("subjects") or []
        subj.update(s)
        is_cyber = any("cyber" in str(x).lower() for x in s)
        cyber += is_cyber
        print(f"{'C' if is_cyber else '-'} {str(it.get('path'))[:60]:60} pc={it.get('poster_classification')} perc={it.get('person_classification')} status={it.get('status')} subj={s}")
    print("cyber items:", cyber)
    print(subj.most_common(20))


if __name__ == "__main__":
    main()
