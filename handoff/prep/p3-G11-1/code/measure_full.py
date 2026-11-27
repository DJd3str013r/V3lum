"""Full-data measurements for batch p3-G11-1 (run: python3 -I measure_full.py).

Reads only local files (raw/ downloads and the research clone of misp-galaxy), never the network.
Writes raw/measure_d3fend.json and raw/measure_malpedia.json and prints a short summary.
"""
import gzip
import hashlib
import json
import sys
import time
import tracemalloc
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # -I drops the script dir; this dir holds only our own code

import parsers as P  # noqa: E402

RAW = HERE.parent / "raw"
GALAXY = Path("<scratch>/repos/MISP__misp-galaxy/clusters/malpedia.json")
PROBE = ["T1059", "T1059.001", "T1003", "T1003.001", "T1566", "T1566.001", "T1486", "T1190",
         "T1078", "T1110", "T1027", "T1055", "T0855", "T1611", "T9999"]


def d3fend():
    path = RAW / "d3fend_full_mappings_1_6_0_csv.body"
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    t0 = time.perf_counter()
    marker = P.validate_d3fend_mappings_csv(data[:200000])
    t_val = time.perf_counter() - t0
    tracemalloc.start()
    t0 = time.perf_counter()
    with open(path, encoding="utf-8", newline="") as fh:
        idx = P.build_d3fend_index(P.iter_d3fend_mapping_rows(fh), version="1.6.0", source_sha256=sha)
    t_build = time.perf_counter() - t0
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    blob = json.dumps(idx, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    gz = gzip.compress(blob, 9)
    t0 = time.perf_counter()
    loaded = json.loads(gzip.decompress(gz).decode("utf-8"))
    t_load = time.perf_counter() - t0
    t0 = time.perf_counter()
    for _ in range(1000):
        P.d3fend_recommendations(loaded, "T1059")
    t_lookup = (time.perf_counter() - t0) / 1000
    totals = sorted(v["total"] for v in idx["techniques"].values())
    recs = {}
    for tid in PROBE:
        r = P.d3fend_recommendations(loaded, tid)
        recs[tid] = {"basis": r["basis"], "basis_ids": r["basis_ids"][:6], "total": r["total"],
                     "controls": ["%s (%s)" % (c["label"], c["tactic"]) for c in r["controls"]],
                     "reason": r["reason"]}
    api = P.parse_d3fend_api((RAW / "d3fend_api_T1059.body").read_bytes(), technique="T1059")
    spec = {c["d3f"]: c["specificity"] for c in idx["techniques"]["T1059"]["controls"]}
    api_ranked = P.parse_d3fend_api((RAW / "d3fend_api_T1059.body").read_bytes(), technique="T1059", specificity=spec)
    out = {
        "source_sha256": sha, "source_bytes": len(data), "validator_marker": marker,
        "validator_s": round(t_val, 4), "build_s": round(t_build, 3), "build_peak_mb": round(peak / 1e6, 1),
        "rows": idx["rows"], "frameworks": idx["frameworks"], "techniques": len(idx["techniques"]),
        "enterprise_ids": sum(1 for v in idx["techniques"].values() if v["framework"] == "enterprise"),
        "ics_ids": sum(1 for v in idx["techniques"].values() if v["framework"] == "ics"),
        "parents_with_children_only": sorted(p for p in idx["children"] if p not in idx["techniques"]),
        "controls_per_technique": {"min": totals[0], "median": totals[len(totals) // 2], "max": totals[-1],
                                   "le5": sum(1 for t in totals if t <= 5)},
        "index_json_bytes": len(blob), "index_gzip_bytes": len(gz), "index_load_s": round(t_load, 4),
        "lookup_ms": round(t_lookup * 1000, 4),
        "api_T1059_total": api["total"], "api_vs_index_same_set":
            sorted(c["d3f"] for c in api["controls"]) == sorted(c["d3f"] for c in idx["techniques"]["T1059"]["controls"]),
        "api_T1059_top5_plain": [c["label"] for c in api["controls"][:5]],
        "api_T1059_top5_with_index_specificity": [c["label"] for c in api_ranked["controls"][:5]],
        "recommendations": recs,
    }
    (RAW / "measure_d3fend.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    return out


def malpedia():
    fam = P.parse_malpedia_families_list((RAW / "malpedia_list_families.body").read_bytes())
    emo = P.parse_malpedia_family((RAW / "malpedia_get_family_win_emotet.body").read_bytes(), "win.emotet", max_urls=5)
    act = P.parse_malpedia_actor((RAW / "malpedia_get_actor_apt28.body").read_bytes(), "apt28", max_refs=5)
    nf = P.parse_malpedia_family((RAW / "malpedia_get_family_not_found.body").read_bytes(), "win.zz_no_such_family_0000", status=404)
    empty = P.parse_malpedia_find_actor((RAW / "malpedia_find_actor_no_match.body").read_bytes())
    out = {"families": {"count": fam["count"], "platforms": fam["platforms"], "invalid": fam["invalid"][:5]},
           "emotet": {k: emo[k] for k in ("common_name", "alt_names", "attribution", "updated", "url_count", "urls")},
           "apt28": {"name": act["name"], "country": act["country"], "mitre": act["mitre_group_ids"],
                     "families": len(act["families"]), "refs": act["ref_count"], "top_refs": act["refs"],
                     "related": len(act["related"]), "first_families": [f["family_id"] for f in act["families"][:5]]},
           "not_found": {"not_found": nf["not_found"], "marker": nf["marker"]},
           "find_no_match": {"empty": empty["empty"], "marker": empty["marker"]}}
    if GALAXY.exists():
        t0 = time.perf_counter()
        gal = P.parse_galaxy_malpedia_cluster(GALAXY.read_bytes())
        t_gal = time.perf_counter() - t0
        ids = set(fam["ids"])
        out["galaxy"] = {
            "version": gal["version"], "families": gal["count"], "parse_s": round(t_gal, 3),
            "ids_not_in_live_list": sorted(set(gal["families"]) - ids)[:10],
            "live_ids_not_in_galaxy": len(ids - set(gal["families"])),
            "emotet_refs": len(gal["families"].get("win.emotet", {}).get("refs", [])),
            "resolve": {n: P.resolve_malpedia_family_ids(n, fam["ids"], gal) for n in
                        ("Emotet", "Geodo", "Casbaneiro", "Grandoreiro", "win.mekotio", "xagent", "Guildma")},
        }
    (RAW / "measure_malpedia.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    return out


if __name__ == "__main__":
    d = d3fend()
    print(json.dumps({k: v for k, v in d.items() if k != "recommendations"}, indent=1, ensure_ascii=False))
    for tid, r in d["recommendations"].items():
        print(tid, r["basis"], r["basis_ids"], r["total"], r["controls"], r["reason"] or "")
    m = malpedia()
    print(json.dumps(m, indent=1, ensure_ascii=False)[:4000])
