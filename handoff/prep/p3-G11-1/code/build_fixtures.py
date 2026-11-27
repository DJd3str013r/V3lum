"""Rebuild fixtures/ for batch p3-G11-1 from raw/ captures, research samples and the MISP galaxy clone.

Run: python3 -I build_fixtures.py   (deterministic: a rebuild reproduces MANIFEST.json byte for byte)

Reads only local files (never the network) and treats every input as untrusted data: JSON/CSV are
parsed with the standard library, nothing is executed, and only fields the parsers use are kept.
Personal data: Malpedia ``library_entries`` (author surnames), galaxy ``authors`` and blog URLs of
individual researchers are dropped; reference URLs are kept only from organisation domains.
"""
import csv
import hashlib
import io
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # -I drops the script dir; this dir holds only our own code

import parsers as P  # noqa: E402

ROOT = HERE.parent
RAW = ROOT / "raw"
FIX = ROOT / "fixtures"
SCRATCH = ROOT.parent.parent.parent  # .../scratchpad
SAMPLES = SCRATCH / "research" / "samples"
GALAXY = SCRATCH / "repos" / "MISP__misp-galaxy" / "clusters" / "malpedia.json"

D3FEND_LIC = "MITRE D3FEND ToU (royalty-free, copyright + licence notice required); ATT&CK content under the ATT&CK ToU"
SPARTA_LIC = "; SPARTA rows: (c)2023 The Aerospace Corporation, royalty-free licence, notice required"
MALPEDIA_LIC = "CC BY-NC-SA 3.0 (Malpedia, Fraunhofer FKIE) - excerpt, attribution required"
GALAXY_LIC = "CC0 1.0 / BSD-2-Clause (MISP galaxy)"

#: Organisation domains whose report URLs may appear in fixtures (no individual researchers' blogs).
ORG_DOMAINS = (
    "attack.mitre.org", "www.microsoft.com", "www.volexity.com", "www.welivesecurity.com",
    "www.secureworks.com", "research.checkpoint.com", "blog.checkpoint.com", "blogs.blackberry.com",
    "go.recordedfuture.com", "www.recordedfuture.com", "blog.fortinet.com", "www.fortinet.com",
    "blog.trendmicro.com", "www.trendmicro.com", "unit42.paloaltonetworks.com",
    "researchcenter.paloaltonetworks.com", "www.mandiant.com", "cloud.google.com", "www.cisa.gov",
    "securelist.com", "www.proofpoint.com", "blog.talosintelligence.com", "www.crowdstrike.com",
    "asec.ahnlab.com", "blog.malwarebytes.com", "www.malwarebytes.com", "www.accenture.com",
    "quointelligence.eu", "www.eset.com", "cert.gov.ua", "www.ncsc.gov.uk", "media.defense.gov",
    "www.bleepingcomputer.com", "www.justice.gov", "www.europol.europa.eu", "blog.lumen.com",
    "www.sentinelone.com", "symantec-enterprise-blogs.security.com", "www.zscaler.com",
    "www.netscout.com", "blog.cyble.com", "www.fortiguard.com", "www.kaspersky.com",
)

manifest = {}


def _host(url):
    m = re.match(r"^https?://([^/]+)/", url)
    return m.group(1).lower() if m else ""


def org_urls(urls, n):
    return [u for u in urls if isinstance(u, str) and _host(u) in ORG_DOMAINS][:n]


def write(name, data, origin, upstream, licence="", note=""):
    path = FIX / name
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.write_bytes(data)
    manifest[name] = {
        "bytes": len(data), "licence": licence, "note": note, "origin": origin,
        "sha256": hashlib.sha256(data).hexdigest(), "upstream": upstream,
    }


def jdump(obj):
    return json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=False) + "\n"


def http_json(status, headers, body):
    return jdump({"status": status, "headers": headers, "body": body})


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------------------ D3FEND

def gh_pages_404_body():
    s = (RAW / "d3fend_full_mappings_csv.body").read_text(encoding="utf-8")
    s = re.sub(r"<style.*?</style>", "<style>/* trimmed */</style>", s, flags=re.S)
    s = re.sub(r'src="data:[^"]*"', 'src="data:,"', s)
    return s


def d3fend():
    csv_path = RAW / "d3fend_full_mappings_1_6_0_csv.body"
    data = csv_path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    text = data.decode("utf-8")
    header_line = text.split("\r\n", 1)[0]
    reader = csv.reader(io.StringIO(text, newline=""))
    header = next(reader)
    col = {c: i for i, c in enumerate(header)}
    rows = list(reader)

    def pick(tid, n=None, distinct=None):
        out, seen = [], set()
        for r in rows:
            if r[col["off_tech_id"]] != tid:
                continue
            if distinct is not None:
                k = r[col[distinct]]
                if k in seen:
                    continue
                seen.add(k)
            out.append(r)
            if n is not None and len(out) >= n:
                break
        return out

    chosen = (pick("T1059")                                   # complete: cross-check with the API answer
              + pick("T1003.001", 3) + pick("T1003.002", 2)    # parent T1003 has only sub-technique rows
              + pick("T1078", distinct="off_tactic_label")     # one row per offensive tactic (4)
              + pick("T0855")                                  # ICS framework (6 rows, complete)
              + pick("DE-0006", 2))                            # SPARTA: must never match an ATT&CK id
    buf = io.StringIO(newline="")
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(header)
    for r in chosen:
        w.writerow(r)
    out = buf.getvalue()
    assert out.split("\r\n", 1)[0] == header_line, "header re-serialisation differs"
    write("d3fend__mappings_ok.csv", out, "live 2026-11-26 (raw/d3fend_full_mappings_1_6_0_csv)",
          P.d3fend_dataset_url("1.6.0"), D3FEND_LIC + SPARTA_LIC,
          "rows selected from the 16,249-row 1.6.0 export, all 27 columns and CRLF kept; T1059 and T0855 "
          "complete, T1003.001/.002, T1078 and SPARTA DE-0006 partial. Full-file sha256 %s" % sha)

    hdr_changed = out.replace("def_tech,", "defensive_technique,", 1).split("\r\n")
    write("d3fend__mappings_header_changed.csv", "\r\n".join(hdr_changed[:4]) + "\r\n",
          "derived from d3fend__mappings_ok.csv", P.d3fend_dataset_url("1.6.0"), D3FEND_LIC,
          "header column def_tech renamed: format-drift case for validate_d3fend_mappings_csv")
    sparta = [header] + pick("DE-0006", 2)
    buf = io.StringIO(newline="")
    csv.writer(buf, lineterminator="\r\n").writerows(sparta)
    write("d3fend__mappings_no_attack_rows.csv", buf.getvalue(), "derived from d3fend__mappings_ok.csv",
          P.d3fend_dataset_url("1.6.0"), D3FEND_LIC + SPARTA_LIC,
          "header plus SPARTA rows only: an export without any ATT&CK row must fail validation")

    write("d3fend__mappings_latest_404.http.json",
          http_json(404, {"content-type": "text/html; charset=utf-8", "server": "GitHub.com"}, gh_pages_404_body()),
          "live 2026-11-26 (raw/d3fend_full_mappings_csv)", P.D3FEND_LATEST_URL_BROKEN, "",
          "the unversioned 'latest' link on /resources/ontology/ answers the GitHub Pages 404 page; "
          "<style> and data: images trimmed")

    # index slice built from the FULL export (real specificity values)
    with open(csv_path, encoding="utf-8", newline="") as fh:
        idx = P.build_d3fend_index(P.iter_d3fend_mapping_rows(fh), version="1.6.0", source_sha256=sha)
    keep = ["T1059", "T1078", "T1486", "T0855", "T1566.001", "T1003.001", "T1003.002"]
    keep = sorted(t for t in set(keep) if t in idx["techniques"])
    sl = {
        "version": idx["version"], "source_sha256": idx["source_sha256"], "rows": idx["rows"],
        "frameworks": idx["frameworks"],
        "techniques": {t: idx["techniques"][t] for t in keep},
        "children": {p: [c for c in v if c in keep] for p, v in idx["children"].items() if p in ("T1003", "T1566")},
        "labels": {k: v for k, v in idx["labels"].items() if k in keep or k in ("T1003", "T1566", "T1059.001", "T1003.001")},
    }
    write("d3fend__index_slice.json", json.dumps(sl, separators=(",", ":"), ensure_ascii=False) + "\n",
          "derived: build_d3fend_index() over the full 1.6.0 export, then sliced", P.d3fend_dataset_url("1.6.0"),
          D3FEND_LIC, "the compact offline index the module would build on 'data update'; techniques %s" % ", ".join(keep))

    # API answer T1059, trimmed to the keys the parser reads
    api = load(RAW / "d3fend_api_T1059.body")
    used = {"off_tech_id", "off_tech_label", "framework_root_iri", "def_tech", "def_tech_id", "def_tech_label",
            "def_tactic_label", "def_artifact", "def_artifact_label", "def_artifact_rel_label", "off_artifact",
            "off_artifact_label", "off_artifact_rel_label", "off_tactic_label"}
    bindings = [{k: v for k, v in b.items() if k in used} for b in api["off_to_def"]["results"]["bindings"]]
    desc = [{k: n[k] for k in ("@id", "d3f:attack-id", "d3f:definition", "rdfs:label") if k in n}
            for n in api["description"]["@graph"]]
    subs = [{k: n[k] for k in ("@id", "d3f:attack-id", "rdfs:label") if k in n}
            for n in api["subtechniques"]["@graph"]]
    trimmed = {"off_to_def": {"head": {"vars": sorted(used)}, "results": {"bindings": bindings}},
               "description": {"@graph": desc}, "subtechniques": {"@graph": subs}, "framework": api["framework"]}
    write("d3fend__api_ok.json", jdump(trimmed), "live 2026-11-26 (raw/d3fend_api_T1059)", P.d3fend_api_url("T1059"),
          D3FEND_LIC, "16 bindings kept (15 with a countermeasure, 1 offensive-only); unused keys dropped")
    empty = json.loads(json.dumps(trimmed))
    empty["off_to_def"]["results"]["bindings"] = [b for b in bindings if "def_tech" not in b]
    write("d3fend__api_empty_bindings.json", jdump(empty), "derived from d3fend__api_ok.json", P.d3fend_api_url("T1059"),
          D3FEND_LIC, "only the offensive-only binding left: a 200 without countermeasures = no mapping")
    write("d3fend__api_no_mapping_404.http.json",
          http_json(404, {"content-type": "text/html; charset=utf-8", "server": "GitHub.com"}, gh_pages_404_body()),
          "live 2026-11-26 (raw/d3fend_full_mappings_csv: same host, same GitHub Pages 404)",
          P.d3fend_api_url("T1611"), "",
          "a missing per-technique JSON is served as this static GitHub Pages 404 (the per-technique 404 itself "
          "was not requested: request cap). FC2: 404 = no mapping, never an error")
    trunc = (SAMPLES / "caipora_infra__d3fend_attack_mapping.json").read_bytes()[:1500]
    write("d3fend__api_truncated_malformed.json", trunc,
          "research sample 2026-11-25 (caipora_infra__d3fend_attack_mapping.json, itself cut at 30,720 B)",
          P.d3fend_api_url("T1059"), D3FEND_LIC, "first 1,500 bytes of a truncated capture: malformed JSON")
    docs = (RAW / "d3fend_api_docs.body").read_text(encoding="utf-8")
    head = docs[: docs.find("<link href=")] + "</head>\n<body></body>\n</html>\n"
    write("d3fend__api_html_200.http.json",
          http_json(200, {"content-type": "text/html; charset=utf-8", "server": "GitHub.com"}, head),
          "live 2026-11-26 (raw/d3fend_api_docs, head only)", "https://d3fend.mitre.org/api-docs/", "",
          "a 200 HTML page where JSON was expected (moved route, captive portal): error marker")
    page = (RAW / "d3fend_resources_ontology.body").read_text(encoding="utf-8")
    m = re.search(r'data-url="/api/version\.json">(.*?)</script>', page, flags=re.S)
    ver = json.loads(json.loads(m.group(1))["body"])
    write("d3fend__version_ok.json", jdump(ver),
          "live 2026-11-26 (prerendered /api/version.json inside raw/d3fend_resources_ontology)",
          P.D3FEND_VERSION_URL, "", "drives the versioned dataset URL (FC1 'version recorded')")


# ---------------------------------------------------------------------------------------- Malpedia

def malpedia():
    lst = load(RAW / "malpedia_list_families.body")
    named = {"win.emotet", "win.xagent", "elf.xagent", "ios.xagent", "osx.xagent", "win.grandoreiro",
             "win.mekotio", "win.metamorfo", "win.astaroth", "win.mispadu", "win.carbanak", "js.spypress",
             "win.xtunnel", "apk.popr-d30", "osx.komplex"}
    first_per_platform, seen = set(), set()
    for fid in lst:
        p = fid.split(".", 1)[0]
        if p not in seen:
            seen.add(p)
            first_per_platform.add(fid)
    sub = [f for f in lst if f in named or f in first_per_platform]
    write("malpedia__list_families_ok.json", jdump(sub), "live 2026-11-26 (raw/malpedia_list_families)",
          P.build_malpedia_url("list_families"), MALPEDIA_LIC,
          "%d of %d ids: the first id of each of the %d platforms plus named ids, original order" % (len(sub), len(lst), len(seen)))

    write("malpedia__find_actor_ok.json", jdump(load(SAMPLES / "malpedia_find_actor.json")),
          "research sample 2026-11-25 (malpedia_find_actor.json)", P.build_malpedia_url("find_actor", "apt28"),
          MALPEDIA_LIC, "actor synonyms are group/vendor names, no personal data")
    write("malpedia__find_actor_lazarus_ok.json", jdump(load(SAMPLES / "live_cti__malpedia_find_actor.json")),
          "research sample 2026-11-25 (live_cti__malpedia_find_actor.json)",
          P.build_malpedia_url("find_actor", "lazarus"), MALPEDIA_LIC,
          "synonym normalisation case (Hidden Cobra -> lazarus_group; two ATT&CK group ids G0032/G0082)")
    write("malpedia__find_actor_empty.json", (RAW / "malpedia_find_actor_no_match.body").read_text(encoding="utf-8") + "\n",
          "live 2026-11-26 (raw/malpedia_find_actor_no_match)",
          P.build_malpedia_url("find_actor", "zz_no_such_actor_0000"), "", "no match = 200 with an empty list")

    act = load(RAW / "malpedia_get_actor_apt28.body")
    meta = act["meta"]
    syn = meta["synonyms"][:13]
    assert "G0007" in syn
    refs = org_urls(meta["refs"], 7)
    assert any("attack.mitre.org/groups/" in u for u in refs), refs
    fam_keep = ["win.xagent", "win.xtunnel", "apk.popr-d30", "osx.komplex"]
    fams = {}
    for fid in fam_keep:
        f = act["families"][fid]
        fams[fid] = {"urls": org_urls(f["urls"], 3), "uuid": f["uuid"], "updated": f["updated"],
                     "alt_names": f["alt_names"][:5], "attribution": f["attribution"], "common_name": f["common_name"],
                     "description": P._first_sentence(f.get("description") or "", 240)}
    actor = {
        "families": fams,
        "description": act["description"],
        "meta": {
            "attribution-confidence": meta["attribution-confidence"],
            "cfr-suspected-state-sponsor": meta["cfr-suspected-state-sponsor"],
            "cfr-suspected-victims": meta["cfr-suspected-victims"][:5],
            "cfr-target-category": meta["cfr-target-category"],
            "cfr-type-of-incident": meta["cfr-type-of-incident"],
            "country": meta["country"],
            "refs": refs,
            "synonyms": syn,
        },
        "related": act["related"],
        "uuid": act["uuid"],
        "value": act["value"],
    }
    write("malpedia__get_actor_ok.json", jdump(actor), "live 2026-11-26 (raw/malpedia_get_actor_apt28)",
          P.build_malpedia_url("get_actor", "apt28"), MALPEDIA_LIC,
          "4 of 41 families, 7 of 56 refs (organisation domains only), 13 of 38 synonyms; library_entries "
          "(author names), notes, sources, name-attribution and other meta keys dropped")

    fam = load(RAW / "malpedia_get_family_win_emotet.body")
    urls = org_urls(fam["urls"], 10)
    desc = fam["description"]
    family = {"urls": urls, "uuid": fam["uuid"], "updated": fam["updated"], "alt_names": fam["alt_names"],
              "attribution": fam["attribution"], "common_name": fam["common_name"],
              "description": desc[: desc.find(".", 200) + 1] if desc.find(".", 200) > 0 else desc[:400]}
    write("malpedia__get_family_ok.json", jdump(family), "live 2026-11-26 (raw/malpedia_get_family_win_emotet)",
          P.build_malpedia_url("get_family", "win.emotet"), MALPEDIA_LIC,
          "10 of 325 urls (organisation domains only), description cut after two sentences; library_entries "
          "(author names), notes and sources dropped. The body carries no family id")
    nf = (RAW / "malpedia_get_family_not_found.body").read_text(encoding="utf-8")
    write("malpedia__get_family_not_found.http.json",
          http_json(404, {"content-type": "application/json", "server": "nginx"}, nf),
          "live 2026-11-26 (raw/malpedia_get_family_not_found)",
          P.build_malpedia_url("get_family", "win.zz_no_such_family_0000"), "",
          "DRF 404 detail 'No Family matches the given query.' = not found, never an error")
    t = (SAMPLES / "malpedia_get_family.txt").read_text(encoding="utf-8")
    cut = t.find('"http://ropgadget')
    assert cut > 0
    write("malpedia__get_family_truncated_malformed.json", t[: cut + len('"http://')],
          "research sample 2026-11-25 (malpedia_get_family.txt, itself cut at 30,000 B)",
          P.build_malpedia_url("get_family", "win.emotet"), MALPEDIA_LIC,
          "first two urls of a truncated capture, cut inside a string: malformed JSON")

    gal = load(GALAXY)
    want = {"Emotet", "X-Agent", "Metamorfo", "Astaroth", "Grandoreiro", "Mekotio", "Carbanak"}
    vals = []
    for v in gal["values"]:
        if v.get("value") not in want:
            continue
        m = v.get("meta") or {}
        r = [x for x in m.get("refs", []) if "malpedia.caad.fkie.fraunhofer.de/details/" in x]
        r += org_urls(m.get("refs", []), 3)
        vals.append({"value": v["value"], "uuid": v["uuid"],
                     "meta": {"synonyms": m.get("synonyms", []), "refs": r}})
    vals.sort(key=lambda x: (x["value"], x["meta"]["refs"][0] if x["meta"]["refs"] else ""))
    cluster = {k: gal[k] for k in ("category", "description", "name", "source", "type", "uuid", "version")}
    cluster["values"] = vals
    write("malpedia__galaxy_cluster_slice.json", jdump(cluster),
          "MISP galaxy clone 2026-11-25 (clusters/malpedia.json, version %s)" % gal["version"],
          "https://github.com/MISP/misp-galaxy/blob/main/clusters/malpedia.json", GALAXY_LIC,
          "%d of %d values; 'authors' (real names) dropped; refs = Malpedia details links + up to 3 "
          "organisation report links" % (len(vals), len(gal["values"])))


def main():
    FIX.mkdir(exist_ok=True)
    for old in FIX.iterdir():
        if old.is_file():
            old.unlink()
    d3fend()
    malpedia()
    (FIX / "MANIFEST.json").write_text(json.dumps(dict(sorted(manifest.items())), indent=1, sort_keys=True,
                                                  ensure_ascii=False) + "\n", encoding="utf-8")
    for k, v in sorted(manifest.items()):
        print("%-52s %7d  %s" % (k, v["bytes"], v["origin"]))


if __name__ == "__main__":
    main()
