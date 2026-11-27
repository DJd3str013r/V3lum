"""Build minimised, scrubbed FBI Wanted fixtures from the raw live capture (untrusted data; run with python3 -I).

Usage: python3 -I build_fbi_fixtures.py <raw_page.json> <fixtures_dir>

Real names never appear in this script: the names to scrub are taken at runtime from the selected items
(titles, aliases, anchor texts and /wanted/cyber/<slug> URLs) and replaced by documentation placeholders.
A final scan asserts that none of those original tokens survive in the written fixtures.
"""
import html
import json
import re
import sys
from pathlib import Path

KEEP = ("uid", "title", "aliases", "description", "caution", "remarks", "details", "additional_information",
        "subjects", "status", "url", "path", "files", "images", "field_offices", "publication", "modified",
        "poster_classification", "person_classification", "reward_text", "warning_message")
GROUP_PATHS = ("/wanted/cyber/apt-41-group", "/wanted/cyber/dprk-it-workers")
ANCHOR = re.compile(r'<a\b[^>]*href="(https://www\.fbi\.gov/wanted/cyber/[^"]+)"[^>]*>(.*?)</a>', re.S | re.I)
WORDS = ["ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX", "SEVEN", "EIGHT", "NINE", "TEN", "ELEVEN", "TWELVE"]


def load(path):
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


class Scrubber:
    def __init__(self):
        self.slug_map = {}   # real slug -> example slug
        self.name_tokens = set()

    def placeholder_for_slug(self, slug):
        if slug not in self.slug_map:
            n = len(self.slug_map)
            self.slug_map[slug] = f"example-member-{WORDS[n].lower()}"
        return self.slug_map[slug]

    def register_name(self, text):
        for tok in re.findall(r"[A-Za-z][A-Za-z'\-]+", html.unescape(text or "")):
            if len(tok) >= 2:
                self.name_tokens.add(tok.lower())


def main():
    raw, out = sys.argv[1], Path(sys.argv[2])
    page = load(raw)
    items = {it.get("path"): it for it in page.get("items") or []}
    scr = Scrubber()
    group_items = [items[p] for p in GROUP_PATHS]
    # members: first two linked from APT 41 group, first linked from DPRK group; plus the persons present in this page
    selected_members = []
    for g in group_items:
        links = ANCHOR.findall(g.get("caution") or "")
        for url, text in links:
            slug = url.rstrip("/").rsplit("/", 1)[-1]
            scr.register_name(re.sub(r"<[^>]+>", " ", text))
            scr.register_name(slug.replace("-", " "))
    # pick one member poster present in the page for each group
    member_paths = []
    for g in group_items:
        for url, _ in ANCHOR.findall(g.get("caution") or ""):
            p = url.replace("https://www.fbi.gov", "")
            if p in items and p not in member_paths:
                member_paths.append(p)
                break
    for p, it in items.items():
        if it is not None and p.startswith("/wanted/cyber/") and p not in GROUP_PATHS and p not in member_paths:
            if "dprk-it-workers" in (it.get("caution") or "") and len(member_paths) < 2:
                member_paths.append(p)
    for p in member_paths:
        it = items[p]
        scr.register_name(it.get("title"))
        for a in it.get("aliases") or []:
            scr.register_name(a)
        scr.register_name(p.rsplit("/", 1)[-1].replace("-", " "))
    # generic words that are not names must stay
    for keep in ("apt", "group", "dprk", "it", "workers", "the", "and", "of", "to", "in", "is", "a", "barium",
                 "chinese", "china", "north", "korean", "wanted", "cyber", "www", "fbi", "gov", "https", "http",
                 "download", "pdf", "file", "images", "image", "large", "thumb", "view", "external", "member",
                 "example"):
        scr.name_tokens.discard(keep)

    def scrub_text(s, own_label=None):
        if not isinstance(s, str):
            return s

        def anchor_sub(m):
            url, _text = m.group(1), m.group(2)
            slug = url.rstrip("/").rsplit("/", 1)[-1]
            if "/wanted/cyber/" + slug in GROUP_PATHS:
                return m.group(0)
            ex = scr.placeholder_for_slug(slug)
            label = "EXAMPLE " + ex.split("-", 1)[1].replace("-", " ").title()
            return m.group(0).replace(url, "https://www.fbi.gov/wanted/cyber/" + ex).replace(_text, label)

        s = ANCHOR.sub(anchor_sub, s)
        # slugs in remaining URLs
        def url_sub(m):
            slug = m.group(1)
            if "/wanted/cyber/" + slug in GROUP_PATHS or slug.startswith("example-"):
                return m.group(0)
            return "/wanted/cyber/" + scr.placeholder_for_slug(slug)
        s = re.sub(r"/wanted/cyber/([a-z0-9\-]+)", url_sub, s)
        # remaining name tokens
        def tok_sub(m):
            return "EXAMPLE" if m.group(0).lower() in scr.name_tokens else m.group(0)
        s = re.sub(r"[A-Za-z][A-Za-z'\-]+", tok_sub, s)
        s = re.sub(r"(EXAMPLE\s+){2,}", "EXAMPLE ", s)
        s = re.sub(r"has ties to [^<.]+", "has ties to an example city", s)
        s = re.sub(r"(the )?District of [A-Z][a-z]+|Eastern District of [A-Za-z]+[^<]*?(?=, in)", "an example district", s)
        return s

    out_items = []
    uid_n = 0

    def minimise(it, title=None, aliases=None):
        nonlocal uid_n
        uid_n += 1
        o = {k: it.get(k) for k in KEEP}
        o["uid"] = f"{uid_n:032x}"
        if title:
            o["title"] = title
        if aliases is not None:
            o["aliases"] = aliases
        for f in ("caution", "remarks", "details", "additional_information", "description", "url", "path"):
            o[f] = scrub_text(o.get(f))
        o["files"] = [{"url": scrub_text(f.get("url")), "name": f.get("name")} for f in (it.get("files") or [])[:1]]
        o["images"] = [{k: scrub_text(v) for k, v in img.items()} for img in (it.get("images") or [])[:1]]
        o["dates_of_birth_used"] = ["January 1, 1970"] if it.get("dates_of_birth_used") else None
        o["pathId"] = "https://api.fbi.gov/@wanted-person/" + o["uid"]
        return o

    for g in group_items:
        g = dict(g)
        c = g.get("caution") or ""
        anchors = list(ANCHOR.finditer(c))
        if len(anchors) > 2:
            tail = c[anchors[-1].end():]
            g["caution"] = "<p>" + anchors[0].group(0) + ", " + anchors[1].group(0) + " and others" + tail
        out_items.append(minimise(g))
    for idx, p in enumerate(member_paths):
        it = items[p]
        ex = scr.placeholder_for_slug(p.rsplit("/", 1)[-1])
        label = "EXAMPLE " + ex.split("-", 1)[1].replace("-", " ").upper()
        aliases = [f"example-handle-{idx + 1}{c}" for c in "ab"][: len(it.get("aliases") or [])] or None
        out_items.append(minimise(it, title=label, aliases=aliases))
    # one non-cyber poster (seeking information), fully neutralised text
    nc = items.get("/wanted/seeking-info/arson---flora-indiana")
    o = minimise(nc, title="EXAMPLE INCIDENT - EXAMPLE CITY")
    o["description"] = "Unknown Suspect(s)\r\nNovember 21, 2016\r\nExample City"
    o["details"] = "<p>The FBI is seeking information from the public regarding an example incident.</p>"
    for f in ("url", "path"):
        o[f] = o[f].replace("arson---flora-indiana", "example-incident---example-city")
    o["files"] = [{"url": "https://www.fbi.gov/wanted/seeking-info/example-incident---example-city/download.pdf", "name": "English"}]
    o["images"] = []
    out_items.append(o)

    doc = {"total": page.get("total"), "items": out_items, "page": page.get("page")}
    text = json.dumps(doc, ensure_ascii=False, indent=1)
    # final PII scan: no original name token may survive
    low = text.lower()
    leaks = sorted(t for t in scr.name_tokens if re.search(r"(?<![a-z])" + re.escape(t) + r"(?![a-z])", low))
    if leaks:
        print("LEAKS:", len(leaks), "tokens survive; refusing to write")
        for t in leaks:
            for m in re.finditer(r"(?<![a-z])" + re.escape(t) + r"(?![a-z])", low):
                print("   ...", text[max(0, m.start() - 40): m.end() + 40].replace("\n", " "))
                break
        sys.exit(1)
    (out / "wanted_notices__fbi_list_ok.json").write_text(text + "\n", encoding="utf-8")
    print("wrote", len(out_items), "items;", len(scr.name_tokens), "name tokens scrubbed;", len(text), "bytes")


if __name__ == "__main__":
    main()
