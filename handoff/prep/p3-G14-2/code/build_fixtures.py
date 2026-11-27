"""Rebuild the minimised, scrubbed page fixtures of batch p3-G14-2 from raw/live (prep tooling only).

Run: python3 -I code/build_fixtures.py   (from the batch prep folder; reads raw/live, writes fixtures/)

The raw pages are untrusted third-party HTML. This script only reads them as text with regular expressions
and copies a few facts (result count, timing, the echoed query, result types, per-release totals, dates).
The page skeleton below reproduces the real markup the parsers key on (class names, attribute order,
whitespace style). Every result text, title and link is replaced by documentation values:
  - Lyzem: Telegram channel/message titles, descriptions and t.me handles are third-party content that may
    hold personal data -> 'Example ...' text, t.me/example_channel, telegra.ph/Example-Article.
  - WikiLeaks: document titles and excerpts are leaked material (rule 3: nothing ingested) -> 'FIXTURE
    DOCUMENT n' text and wikileaks.org/plusd/cables/EXAMPLE<n>_a.html links. Release names and totals
    (Plusd, Cablegate...) are WikiLeaks' own publication labels and are kept.
Nothing here is ever executed or rendered.
"""
import html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
RAW = os.path.join(BASE, "raw", "live")
FIX = os.path.join(BASE, "fixtures")
MODULE = "pivots_search"


def raw_text(label):
    with open(os.path.join(RAW, label + ".body"), "rb") as fh:
        return fh.read().decode("utf-8", "replace")


def log_records():
    out = {}
    with open(os.path.join(RAW, "_log.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            out[rec["label"]] = rec
    return out


def write(name, content):
    path = os.path.join(FIX, f"{MODULE}__{name}")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    return os.path.basename(path)


# ---------------------------------------------------------------------------------------------------------
# Lyzem
# ---------------------------------------------------------------------------------------------------------

LYZEM_HEAD = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf8" />
    <title>Search results</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="apple-mobile-web-app-title" content="Lyzem" />
  </head>
<body>
  <div class="page-search">
    <form method="GET" action="/search">
      <header class="search-header">
        <div class="searchbar-filters-wrapper">
  <div class="searchbar">
    <input aria-label="Search"
           autofocus="autofocus"
           name="q"
           placeholder=" "
           minlength="2"
           type="search"
           value="{echo}"
           class="searchbar-input"
    />
  </div>
        </div>
      </header>
  <div class="info-line">
    <div id="search-rollover">
      <div>
        <p class="is-size-6">
          {count} results
          –
          {ms}ms
        </p>
      </div>
    </div>
  </div>
    </form>
    <div class="l-screenful container-gapped-nocenter">
      <div class="columns results-wrapper l-dont-overflow-h">
        <div class="column is-two-thirds">
  <ul class="search-results">
"""

LYZEM_ITEM = """  <li class="search-result">
    <div class="search-result-type-wrapper {wrapper_extra}"
         {profile_attr}
         title="{title_attr}">
      <div class="search-result-type "></div>
      <div class="search-result-circle"></div>
      <div class="search-result-type-img">
        <div class="search-{sprite}">
          <span>{rtype}</span>
        </div>
      </div>
    </div>
    <div class="search-result-info">
      <p class="search-result-title">
        <a href="{href}">
          {title}
        </a>
      </p>
      <p class="search-result-descr">
        <a href="{href}"
           target="_blank">
          {descr}
        </a>
      </p>
    </div>
  </li>
"""

LYZEM_TAIL = """  </ul>
        </div>
        <div class="column is-one-third">
        </div>
      </div>
        <div class="pager">
          <ul>
                <li class="pager-current">1</li>
{pager}          </ul>
        </div>
    </div>
  <footer class="main-footer">
    <div class="container">
      <nav class="footer-nav-container">
        <ul class="footer-nav-col">
          <li class="footer-nav-title">Lyzem</li>
          <li><a href="https://www.lyzem.com">Lyzem Search</a></li>
        </ul>
      </nav>
    </div>
  </footer>
  </div>
</body>
</html>
"""

SPRITES = {"post": "post", "article": "article", "group": "group", "channel": "channel", "bot": "bot"}
FAKE_HREF = {
    "post": "https://t.me/example_channel/{n}",
    "article": "https://telegra.ph/Example-Article-0{n}-01",
    "group": "https://t.me/example_group_{n}",
    "channel": "https://t.me/example_channel_{n}",
    "bot": "https://t.me/example_{n}_bot",
}


def lyzem_facts(label):
    t = raw_text(label)
    echo = re.search(r'(?s)<input aria-label="Search".*?value="([^"]*)"', t).group(1)
    m = re.search(r"(?s)<p class=\"is-size-6\">\s*(\d+) results\s*\S\s*(\d+)ms", t)
    # two wrapper variants seen live: plain ('title="article"') and with a channel profile
    # ('search-result-with-profile" data-profile-link="https://t.me/<handle>" title="channel - with profile"')
    types = [tt.split(" - ")[0] + (" - with profile" if "with-profile" in cls else "")
             for cls, tt in re.findall(r'(?s)class="search-result-type-wrapper([^"]*)"[^>]*?title="([^"]+)"', t)]
    pager = re.search(r'<li><a href="(/search\?q=[^"]*?&amp;p=2[^"]*)">2</a></li>', t)
    return {"echo": echo, "count": int(m.group(1)), "ms": int(m.group(2)), "types": types,
            "pager2": pager.group(1) if pager else None}


def lyzem_page(facts, items, *, truncate_at=None):
    body = LYZEM_HEAD.format(echo=facts["echo"], count=facts["count"], ms=facts["ms"])
    for n, (rtype, title, descr) in enumerate(items, start=1):
        base = rtype.split(" - ")[0]
        href = FAKE_HREF[base].format(n=n)
        profile = rtype.endswith("with profile")
        body += LYZEM_ITEM.format(
            rtype=base, sprite=SPRITES.get(base, base), href=href, title=title, descr=descr,
            title_attr=rtype, wrapper_extra="search-result-with-profile" if profile else "",
            profile_attr=f'data-profile-link="{href}"' if profile else "")
    pager = ""
    if facts.get("pager2"):
        pager = f'                <li><a href="{facts["pager2"]}">2</a></li>\n'
    body += LYZEM_TAIL.format(pager=pager)
    if truncate_at is not None:
        body = body[:truncate_at]
    return body


def build_lyzem(files):
    dom = lyzem_facts("lyzem_search_domain_example_com")
    first3 = dom["types"][:3]
    items = []
    for n, rtype in enumerate(first3, start=1):
        items.append((rtype, f"Example {rtype} title {n}",
                      f"Fixture text mentioning <em>example.com</em> (scrubbed result {n})"))
    files["lyzem_ok.html"] = write("lyzem_ok.html", lyzem_page(dom, items))

    empty = lyzem_facts("lyzem_search_nonsense_token")
    files["lyzem_empty.html"] = write("lyzem_empty.html", lyzem_page(empty, []))

    cve = lyzem_facts("lyzem_search_keyword_cve_space")
    items = [(t, f"Example {t.split(' - ')[0]} title {n}",
              "Fixture text: <em>Log4j</em> <em>CVE</em>-<em>2021</em>-<em>44228</em> (scrubbed)")
             for n, t in enumerate(cve["types"][:2], start=1)]
    files["lyzem_space_encoding_ok.html"] = write("lyzem_space_encoding_ok.html", lyzem_page(cve, items))

    url = lyzem_facts("lyzem_search_url_example")
    picks = [url["types"][0], url["types"][-1]]  # one 'channel - with profile', one plain 'article'
    items = [(t, f"Example {t.split(' - ')[0]} title {n}",
              "Fixture text: a link <em>https</em>:&#x2F;&#x2F;example.org (scrubbed)")
             for n, t in enumerate(picks, start=1)]
    files["lyzem_url_tokenised_noise.html"] = write("lyzem_url_tokenised_noise.html", lyzem_page(url, items))

    # malformed: the OK page cut inside the result list (connection drop / partial body); derived
    full = lyzem_page(dom, [(t, f"Example {t} title {n}", "Fixture text <em>example.com</em>")
                            for n, t in enumerate(first3, start=1)])
    cut = full.find('<p class="search-result-descr">', full.find('<li class="search-result">'))
    files["lyzem_malformed_truncated.html"] = write("lyzem_malformed_truncated.html", full[:cut])
    # malformed: count line cut off (header only)
    files["lyzem_malformed_no_count.html"] = write("lyzem_malformed_no_count.html",
                                                    full[:full.find('<div class="info-line">')])
    return {"domain": dom, "empty": empty, "cve": cve, "url": url}


# ---------------------------------------------------------------------------------------------------------
# WikiLeaks
# ---------------------------------------------------------------------------------------------------------

WL_HEAD = """<!DOCTYPE HTML>
<html dir="ltr">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Search WikiLeaks</title>
<link href="/static/search.xml" title="wikileaks.org" type="application/opensearchdescription+xml" rel="search" />
</head>
<body class="wlsearch">
<form class="global-search" method="get" action="https://search.wikileaks.org/">
<input type="text" name="q" placeholder="Search">
</form>
<div class="wlsearch">
<form class="search-form" id="search-form" action="/#results" method="get">
<div class="search-content">
<h1>Advanced search</h1>
<div class="search-fields">
<div class="search-section">
<h2>Words</h2>
<div class="search-operator">
<label for="query">
<strong>All</strong> these words
</label>
<div class="input-section">
<input type="text" name="query" value="{echo}" id="query"/>
</div>
</div>
</div>
</div>
<div class="advanced-submit">
<button class="button-face green" type="submit" name="new_search" value="True">Search</button>
</div>
</div>
<div class="results-section" id="results">
  <div class="search-content">
    <div class="meta-section">
      <div class="meta-info">
        Searching for <i>{echo}</i>
      </div>
    </div>
    <div class="publication-totals">
{totals}    </div>
    <div class="results">
      <div class="publications">
      </div>
      <div class="order-by">
        <div class="total-count">
          <span>{count} results </span>
        </div>
      </div>
"""

WL_TOTAL = """      <div class="publication-total">
        <input
            type="checkbox"
            id="{lid}"
            name="publication_type[]"
            value="{val}"
            />
        <label for="{lid}" class="label">{label}</label>
        <div class="total">{total}</div>
      </div>
"""

WL_RESULT = """      <div class="result">
        <div class="info">
          <h4><a href="https://wikileaks.org/plusd/cables/EXAMPLE{n}_a.html"> FIXTURE DOCUMENT {n} </a></h4>
          <div class="excerpt"> ... {excerpt} ... </div>
        </div>
        <div class="other-info">
          <div class="leak-label">
            <div><b>{leak}</b></div>
          </div>
          <div class="dates">
            <div class="date">
              Created<br/>
              <span>{created}</span>
            </div>
            <div class="date">
              Released<br/>
              <span>{released}</span>
            </div>
          </div>
        </div>
      </div>
"""

WL_TAIL = """{pagination}    </div>
  </div>
</div>
</form>
</div>
<footer id="page-footer" class="footer-recommendations">
<a href="https://our.wikileaks.org" target="_blank">WL Research Community</a>
</footer>
</body>
</html>
"""


def wl_facts(label):
    t = raw_text(label)
    echo = re.search(r'<input type="text" name="query" value="([^"]*)" id="query"/>', t).group(1)
    count = re.search(r'(?s)class="total-count">\s*<span>([\d,]+) results', t).group(1)
    totals = re.findall(r'(?s)<div class="publication-total">\s*<input\s+type="checkbox"\s+id="([^"]+)"\s+'
                        r'name="publication_type\[\]"\s+value="(\d+)"\s*/>\s*<label for="[^"]+" class="label">'
                        r'([^<]+)</label>\s*<div class="total">([\d,]+)</div>', t)
    results = re.findall(r'(?s)<div class="result">.*?<div class="leak-label">\s*<div><b>([^<]+)</b></div>.*?'
                         r'Created<br/>\s*<span>([\d-]+)</span>.*?Released<br/>\s*<span>([\d-]+)</span>', t)
    pag = re.search(r'<ul class="pagination">.*?</ul>', t, re.S)
    return {"echo": echo, "count": count, "totals": totals, "results": results,
            "pagination": pag.group(0) if pag else ""}


def wl_page(facts, *, n_results, excerpt, keep_totals=3):
    totals = facts["totals"][:keep_totals]
    if totals:
        tot = "      <strong>Filter results by leak</strong>\n" + "".join(
            WL_TOTAL.format(lid=lid, val=val, label=label, total=total) for lid, val, label, total in totals)
    else:
        tot = "      No filters available\n"
    body = WL_HEAD.format(echo=facts["echo"], count=facts["count"], totals=tot)
    for n, (leak, created, released) in enumerate(facts["results"][:n_results], start=1):
        body += WL_RESULT.format(n=n, excerpt=excerpt, leak=leak, created=created, released=released)
    pagination = ""
    if facts["pagination"]:
        # keep the real pagination shape, first two pages only (the query echo in it is the probe value)
        links = re.findall(r'<li[^>]*>.*?</li>', facts["pagination"])
        pagination = '      <ul class="pagination">' + "".join(links[:3]) + "</ul>\n"
    body += WL_TAIL.format(pagination=pagination)
    return body


def build_wikileaks(files):
    bb = wl_facts("wikileaks_search_company_banco_do_brasil")
    page = wl_page(bb, n_results=2, excerpt="<b>Banco</b> <b>do</b> <b>Brasil</b> (scrubbed fixture excerpt)")
    files["wikileaks_ok.html"] = write("wikileaks_ok.html", page)

    cve = wl_facts("wikileaks_search_keyword_cve")
    files["wikileaks_empty.html"] = write("wikileaks_empty.html", wl_page(cve, n_results=0, excerpt=""))

    hq = wl_facts("wikileaks_search_hostile_quotes_unicode")
    files["wikileaks_hostile_quotes_unicode_ok.html"] = write(
        "wikileaks_hostile_quotes_unicode_ok.html",
        wl_page(hq, n_results=1, excerpt="&quot;<b>Ação</b>&quot; <b>example</b> (scrubbed fixture excerpt)"))

    # malformed: page cut after the query echo, before the results section (partial body); derived
    cut = page.find('<div class="publication-totals">')
    files["wikileaks_malformed_truncated.html"] = write("wikileaks_malformed_truncated.html", page[:cut])
    return {"ok": bb, "empty": cve, "hostile": hq}


# ---------------------------------------------------------------------------------------------------------
# Non-200 envelopes, live meta, provenance
# ---------------------------------------------------------------------------------------------------------

def envelope(label, rec, case_doc):
    body = raw_text(label)
    keep = {k: v for k, v in rec["headers"].items() if k in ("content-type", "server", "cache-control", "via")}
    return json.dumps({"_provenance": case_doc, "url": rec["url"], "status": int(rec["http_code"]),
                       "headers": keep, "body": body}, indent=1, ensure_ascii=False) + "\n"


def main():
    os.makedirs(FIX, exist_ok=True)
    files = {}
    logs = log_records()
    lyz = build_lyzem(files)
    wl = build_wikileaks(files)
    files["lyzem_not_found_404.http.json"] = write(
        "lyzem_not_found_404.http.json",
        envelope("lyzem_robots", logs["lyzem_robots"],
                 "live 2026-11-26: GET https://lyzem.com/robots.txt (no robots file; Caddy plain-text 404)"))
    files["wikileaks_not_found_404.http.json"] = write(
        "wikileaks_not_found_404.http.json",
        envelope("wikileaks_robots", logs["wikileaks_robots"],
                 "live 2026-11-26: GET https://search.wikileaks.org/robots.txt (no robots file; nginx/Varnish 404)"))

    meta = []
    for label, rec in logs.items():
        meta.append({
            "label": label, "url": rec["url"], "at_utc": rec["at_utc"], "status": int(rec["http_code"]),
            "time_total_s": float(rec["time_total_s"]), "ttfb_s": float(rec["ttfb_s"]),
            "bytes": int(rec["size_download"] or 0), "headers": rec["headers"],
            "redirect": rec["redirect_url"] or None,
        })
    with open(os.path.join(FIX, f"{MODULE}__live_checks.meta.json"), "w", encoding="utf-8") as fh:
        json.dump({"_doc": "every request made from the datacenter egress on 2026-11-26 (curl default UA, GET, "
                           "no cookies, redirects not followed, >= 1.2 s apart, <= 5 per host)",
                   "requests": meta}, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    files["live_checks.meta.json"] = f"{MODULE}__live_checks.meta.json"

    facts = {
        "lyzem": {k: {"echo": html.unescape(v["echo"]), "count": v["count"], "ms": v["ms"],
                      "types_first_page": v["types"]} for k, v in lyz.items()},
        "wikileaks": {k: {"echo": html.unescape(v["echo"]), "count": v["count"],
                          "totals_first3": [(lab, tot) for _, _, lab, tot in v["totals"][:3]],
                          "n_results_first_page": len(v["results"])} for k, v in wl.items()},
    }
    prov = {
        "_doc": "origin of every fixture: live = real response (minimised), derived = cut from a live page, "
                "skeleton = real markup with scrubbed result text (third-party/leaked content replaced)",
        "facts_from_raw": facts,
        "files": {
            "pivots_search__lyzem_ok.html": "skeleton of live lyzem.com/search?q=example.com (38 results, 3 kept)",
            "pivots_search__lyzem_empty.html": "skeleton of live lyzem.com/search?q=zqxvkjw9183pt (0 results)",
            "pivots_search__lyzem_space_encoding_ok.html":
                "skeleton of live lyzem.com/search?q=CVE-2021-44228%20log4j (echo shows a decoded space)",
            "pivots_search__lyzem_url_tokenised_noise.html":
                "skeleton of live lyzem.com/search?q=https%3A%2F%2Fexample.com%2F (1,835,042 OR-matches)",
            "pivots_search__lyzem_malformed_truncated.html": "derived: lyzem_ok cut inside the first result",
            "pivots_search__lyzem_malformed_no_count.html": "derived: lyzem_ok cut before the results count",
            "pivots_search__lyzem_not_found_404.http.json": "live 404 envelope",
            "pivots_search__wikileaks_ok.html":
                "skeleton of live search.wikileaks.org/?query=Banco%20do%20Brasil (9,196 results, 2 kept)",
            "pivots_search__wikileaks_empty.html": "skeleton of live search.wikileaks.org/?query=CVE-2021-44228",
            "pivots_search__wikileaks_hostile_quotes_unicode_ok.html":
                "skeleton of live search.wikileaks.org/?query=%22A%C3%A7%C3%A3o%22%20example (52 results)",
            "pivots_search__wikileaks_malformed_truncated.html": "derived: wikileaks_ok cut before the results",
            "pivots_search__wikileaks_not_found_404.http.json": "live 404 envelope",
            "pivots_search__live_checks.meta.json": "request log summary (no bodies)",
            "pivots_search__pack_draft.json": "hand-written draft of data/pivot_links/search.json",
            "pivots_search__pending_after_tier_review.json": "hand-written Lyzem entries gated on the A8 review",
            "pivots_search__registry_draft.json": "hand-written provider fragments (v3lum.provider/1)",
            "pivots_search__lint_bad_entries.json": "hand-written entries the lint must reject",
            "pivots_search__render_golden.json": "hand-checked expected URLs (sample + hostile values)",
            "pivots_search__hostile_values.json": "hand-written FC3 hostile value list",
        },
    }
    with open(os.path.join(FIX, "_provenance.json"), "w", encoding="utf-8") as fh:
        json.dump(prov, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    for k in sorted(files):
        print(files[k])


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(__doc__)
    main()
