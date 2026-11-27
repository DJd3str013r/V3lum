"""Profile the D3FEND full-mappings CSV (python3 -I analyse_d3fend.py CSV). Read-only, stdlib."""
import collections
import csv
import io
import statistics
import sys

F = "http://d3fend.mitre.org/ontologies/d3fend.owl#"


def frag(iri):
    return iri[len(F):] if iri.startswith(F) else iri


def main(path):
    rows = list(csv.DictReader(io.open(path, encoding="utf-8", newline="")))
    print("rows", len(rows))
    fw = collections.Counter(frag(r["framework_root_iri"]) for r in rows)
    print("frameworks", fw.most_common())
    att = [r for r in rows if frag(r["framework_root_iri"]).startswith("ATTACK")]
    ids = sorted({r["off_tech_id"] for r in att})
    print("attack ids", len(ids), "subtech", sum(1 for i in ids if "." in i), ids[:5], ids[-5:])
    for fwk in fw:
        sub = {r["off_tech_id"] for r in rows if frag(r["framework_root_iri"]) == fwk}
        print("  ", fwk, len(sub), sorted(sub)[:4])
    per = collections.defaultdict(set)
    per_top = collections.defaultdict(set)
    for r in att:
        per[r["off_tech_id"]].add(frag(r["def_tech"]))
        per_top[r["off_tech_id"]].add(r["query_def_tech_label"])
    n = [len(v) for v in per.values()]
    q = [len(v) for v in per_top.values()]
    print("def_tech per id: min %d median %s max %d; <=5: %d of %d" % (min(n), statistics.median(n), max(n), sum(1 for x in n if x <= 5), len(n)))
    print("query_def_tech per id: min %d median %s max %d" % (min(q), statistics.median(q), max(q)))
    rel = collections.Counter()
    for r in rows:
        a, b, c = r["query_def_tech_label"], r["top_def_tech_label"], r["def_tech_label"]
        rel[("q==d" if a == c else "q!=d") + "," + ("t==d" if b == c else "t!=d") + "," + ("q==t" if a == b else "q!=t")] += 1
    print("label relations", rel.most_common())
    print("def_tactic", collections.Counter(r["def_tactic_label"] for r in att).most_common())
    print("off_tactic top", collections.Counter(r["off_tactic_label"] for r in att).most_common(5))
    print("toplevel flag", collections.Counter(r["off_tech_parent_is_toplevel"] for r in att).most_common())
    print("art rel def", collections.Counter(r["def_artifact_rel_label"] for r in att).most_common(8))
    print("art match", collections.Counter("same" if r["def_artifact"] == r["off_artifact"] else "diff" for r in att).most_common())
    for tid in ("T1059", "T1059.001", "T1566", "T1566.001", "T1486", "T1190", "T1003", "T1078"):
        s = [r for r in att if r["off_tech_id"] == tid]
        print(tid, "rows", len(s), "def_tech", len({r["def_tech"] for r in s}), "query", len({r["query_def_tech_label"] for r in s}),
              "parent", {r["off_tech_parent_label"] for r in s} if s else None, "tactics", sorted({r["off_tactic_label"] for r in s}))
    dup = collections.Counter(tuple(r.values()) for r in rows)
    print("exact duplicate rows", sum(c - 1 for c in dup.values() if c > 1))
    empt = collections.Counter(k for r in rows for k, v in r.items() if v == "")
    print("empty cells by column", empt.most_common(10))


if __name__ == "__main__":
    main(sys.argv[1])
