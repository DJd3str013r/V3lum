"""Build the minimised, scrubbed fixtures of batch p3-G14-1 from raw/ (run with python3 -I).

Usage: python3 -I code/build_fixtures.py

raw/ holds untrusted downloads: they are read as text only, never executed or imported. Personal data is not
copied: email-format.com sample addresses (Cloudflare data-cfemail payloads) are dropped, people named in
DuckDuckGo infoboxes are replaced with documentation placeholders, the Webmii App Store seller (a natural person)
is recorded only as 'individual'. Synthetic fixtures carry _provenance.synthetic = true and are never merge-gate
evidence (P307 FC10).
"""
import html
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LIVE = os.path.join(ROOT, "raw", "live")
RESEARCH = os.path.join(ROOT, "raw", "research")
OUT = os.path.join(ROOT, "fixtures")
CHECKED_AT = "2026-11-26"
KEEP_HEADERS = ("content-type", "location", "server", "cache-control", "cf-cache-status", "x-cache", "retry-after",
                "www-authenticate", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
                "access-control-allow-origin", "x-robots-tag", "age")


def read_text(path):
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8", "replace")


def live_log():
    out = {}
    with open(os.path.join(LIVE, "_log.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            out[rec["id"]] = rec
    return out


LOG = live_log()


def final_headers(rid):
    """Headers of the last HTTP response block (after the proxy's CONNECT answer), selected keys only."""
    raw = read_text(os.path.join(LIVE, rid + ".headers"))
    blocks = re.split(r"(?m)^(?=HTTP/\S+ \d{3})", raw)
    last = [b for b in blocks if b.strip()][-1]
    out = {}
    for line in last.splitlines()[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        if k in KEEP_HEADERS:
            v = v.strip()
            out[k] = v if k != "www-authenticate" else v[:40] + "...(truncated)"
    return out


def provenance(rid, note, synthetic=False):
    rec = LOG.get(rid, {})
    return {"source": f"live {rec.get('at')} GET {rec.get('url')}" if rec else "n/a",
            "status_seen": rec.get("status"), "time_total_s": rec.get("time_total"),
            "minimised": note, "synthetic": synthetic}


def envelope(rid, body, note, status=None, headers=None):
    rec = LOG[rid]
    return {"_provenance": provenance(rid, note), "url": rec["url"],
            "status": int(status if status is not None else rec["status"]),
            "headers": headers if headers is not None else final_headers(rid), "body": body}


def write(name, obj):
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    return name


def title_of(text):
    m = re.search(r"<title[^>]*>(.*?)</title>", re.sub(r"<!--.*?-->", "", text, flags=re.S), re.I | re.S)
    return re.sub(r"\s+", " ", html.unescape(m.group(1))).strip() if m else None


def metas(text, keys):
    """Original <meta> tags (outside comments) for the given property/name keys, in page order."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    out = []
    for m in re.finditer(r"<meta\b[^>]*>", text, re.I | re.S):
        k = re.search(r"\b(?:property|name)\s*=\s*[\"']([^\"']+)[\"']", m.group(0), re.I)
        if k and k.group(1).lower() in keys:
            out.append(re.sub(r"\s+", " ", m.group(0)))
    return out


def html_doc(head_parts, body_parts):
    return ("<!DOCTYPE html><html><head><meta charset=\"utf-8\">" + "".join(head_parts) + "</head><body>"
            + "".join(body_parts) + "</body></html>")


written = []

# ------------------------------------------------------------------------------------------- P098 pivots_email
src = read_text(os.path.join(LIVE, "emailformat_www_example.body"))
formats = re.findall(r"<div class='format fl'>([^<]*)</div>.*?<div class='confidence_value fl'>([^<]*)</div>", src,
                     re.S)
canonical = re.search(r'<link rel="canonical" href="([^"]+)"', src).group(1)
commented = None
for _c in re.findall(r"<!--(.*?)-->", src, re.S):
    commented = commented or re.search(r'(<meta property="og:site_name" content="[^"]*"\s*/>)', _c)
blocks = "".join(
    "<div class=\"format_score_container\"> <div class='format fl'>%s</div> <div class='confidence_value fl'>%s</div>"
    " <div class='format_example fl'>e.g. <a href=\"/cdn-cgi/l/email-protection\" class=\"__cf_email__\">"
    "[email&#160;protected]</a></div></div>" % (f, p) for f, p in formats[:3])
ok_html = html_doc(
    ["<title>%s</title>" % html.escape(title_of(src)), '<link rel="canonical" href="%s">' % canonical,
     '<meta property="og:url" content="%s"/>' % canonical,
     "<!-- %s -->" % (commented.group(1) if commented else ""),
     "<script src='https://www.google.com/recaptcha/api.js'></script>"],
    ["<div id=\"format_scores_container\"><div class='confidence_container'>low confidence</div>", blocks, "</div>",
     '<div id="domain_removal_recaptcha" class="g-recaptcha"></div>'])
written.append(write("pivots_email__ok.http.json", envelope(
    "emailformat_www_example", ok_html,
    "title, canonical, the commented-out RocketReach og block (not live metadata), the reCAPTCHA domain-removal "
    "form marker and 3 of 10 format rows; every sample address (data-cfemail payload) dropped")))
src = read_text(os.path.join(LIVE, "emailformat_www_nic_br.body"))
written.append(write("pivots_email__ok_br.http.json", envelope(
    "emailformat_www_nic_br", html_doc(["<title>%s</title>" % html.escape(title_of(src))], []),
    "title only; sample addresses dropped")))
written.append(write("pivots_email__not_found.http.json", envelope(
    "emailformat_www_invalid_example", "", "302 to /i/main/ for a domain email-format does not know; body (a "
                                           "truncated head) dropped")))
written.append(write("pivots_email__redirect_apex.http.json", envelope(
    "emailformat_apex_example", "", "apex host answers 301 to the www host; body dropped")))

# --------------------------------------------------------------------------------- P125 pivots_username_social
src = read_text(os.path.join(LIVE, "bsky_profile_bsky_app.body"))
written.append(write("pivots_username_social__bsky_ok.http.json", envelope(
    "bsky_profile_bsky_app", html_doc(
        ["<title>%s</title>" % html.escape(title_of(src))] + metas(
            src, {"og:site_name", "og:type", "og:url", "og:title", "twitter:label1", "twitter:value1"}),
        ["<noscript>This is a heavily interactive web application, and JavaScript is required.</noscript>"]),
    "title and og/twitter profile tags of the official @bsky.app account; app config and description dropped")))
src = read_text(os.path.join(LIVE, "bsky_profile_example_com.body"))
written.append(write("pivots_username_social__bsky_not_found.http.json", envelope(
    "bsky_profile_example_com", html_doc(
        ["<title>%s</title>" % html.escape(title_of(src))] + metas(src, {"og:site_name", "og:type"}), []),
    "soft 404: HTTP 200 app shell titled 'Bluesky' with no og:title/og:url (handle example.com not resolvable)")))
src = read_text(os.path.join(LIVE, "mastodon_profile_mastodon.body"))
alt = re.findall(r'<link href="https://mastodon\.social/users/Mastodon" rel="alternate" type="application/activity'
                 r'\+json">', src)
written.append(write("pivots_username_social__mastodon_ok.http.json", envelope(
    "mastodon_profile_mastodon", html_doc(
        ["<title>%s</title>" % html.escape(title_of(src))]
        + metas(src, {"og:site_name", "og:type", "og:url", "og:title"}) + alt[:1], []),
    "title, og tags and the ActivityPub alternate link of the official @Mastodon account")))
for rid, case, note in (("mastodon_profile_random_control", "mastodon_not_found",
                         "404 for a random 20-char control handle (never a person's handle)"),
                        ("mastodon_profile_github", "mastodon_gone",
                         "410 for an organisation handle that does not exist (deleted/suspended/reserved) "
                         "on mastodon.social; @microsoft gave the same 410")):
    src = read_text(os.path.join(LIVE, rid + ".body"))
    written.append(write(f"pivots_username_social__{case}.http.json", envelope(
        rid, html_doc(["<title>%s</title>" % html.escape(title_of(src))], []), note + "; title only")))

# ------------------------------------------------------------------------------------- P144 pivots_breach_leak
src = read_text(os.path.join(LIVE, "hibp_breach_lower_adobe.body"))
precursor = ("<script>(function(){var u='/cdn-cgi/challenge-platform/scripts/precursor/main.js?ray=RAYID',"
             "s=document.createElement('script');s.src=u;document.head.appendChild(s);})();</script>")
written.append(write("pivots_breach_leak__page_ok.http.json", envelope(
    "hibp_breach_lower_adobe", html_doc(
        ["<title>%s</title>" % html.escape(title_of(src))] + metas(src, {"og:site_name", "og:title", "og:url"}),
        [precursor]),
    "title and og tags; Cloudflare's precursor beacon (present on normal 200 pages) kept with a placeholder ray id "
    "to test that it is not read as a challenge")))
src = read_text(os.path.join(LIVE, "hibp_breach_lower_example.body"))
written.append(write("pivots_breach_leak__page_not_found.http.json", envelope(
    "hibp_breach_lower_example", html_doc(
        ["<title>%s</title>" % html.escape(title_of(src))] + metas(src, {"og:title", "og:url"}), [precursor]),
    "404 page for an unknown breach name; title and og tags")))
api = json.loads(read_text(os.path.join(LIVE, "hibp_api_breach_adobe.body")))
keep = ("Name", "Title", "Domain", "BreachDate", "AddedDate", "PwnCount", "DataClasses", "IsVerified",
        "IsFabricated", "IsSensitive", "IsRetired", "IsSpamList", "IsMalware", "IsStealerLog")
written.append(write("pivots_breach_leak__api_breach_ok.http.json", envelope(
    "hibp_api_breach_adobe", {k: api[k] for k in keep if k in api},
    "keyless /api/v3/breach/Adobe; Description (HTML), LogoPath and secondary flags dropped")))
written.append(write("pivots_breach_leak__api_breach_not_found.http.json", envelope(
    "hibp_api_breach_example", read_text(os.path.join(LIVE, "hibp_api_breach_example.body")),
    "404 text/plain 'Not found' for an unknown breach name")))
cat = json.loads(read_text(os.path.join(RESEARCH, "live_osint__hibp_breaches_catalog",
                                        "live_osint__hibp_breaches_catalog.json")))
pick = [b for b in cat if b.get("Name") in ("000webhost", "17Media", "2844Breaches", "7-Eleven", "Abandonia2022")]
written.append(write("pivots_breach_leak__catalog_ok.json", {
    "_provenance": {"source": "research sample live_osint__hibp_breaches_catalog.json (keyless /api/v3/breaches, "
                              "2026-11-25)", "minimised": "5 of 20 records; Description, LogoPath dropped",
                    "synthetic": False},
    "body": [{k: b[k] for k in keep if k in b} for b in pick]}))

# ------------------------------------------------------------------------------------------ P257 pivots_person
src = read_text(os.path.join(LIVE, "webmii_unquoted_bancodobrasil.body"))
scripts = [s for s in re.findall(r'<script[^>]*src="([^"]+)"', src) if s.startswith("https://")]
written.append(write("pivots_person__ok.http.json", envelope(
    "webmii_unquoted_bancodobrasil", html_doc(
        ["<title>%s</title>" % html.escape(title_of(src))] + metas(src, {"og:url", "og:title"})
        + ['<script async src="%s"></script>' % html.escape(s) for s in scripts],
        ['<div id="score" class="score"> --- </div>',
         "<div>Searching for all public information available on the web...</div>",
         "<div>No public result found on the web.</div>"]),
    "benign company name used instead of a person (rules); title/og tags, the third-party script hosts the page "
    "loads (Google Tag Manager, Facebook SDK, Google CSE) and the client-side placeholders")))
about = read_text(os.path.join(LIVE, "webmii_about.body"))
priv = read_text(os.path.join(LIVE, "webmii_privacy.body"))


def text_of(t):
    t = re.sub(r"(?s)<script.*?</script>|<style.*?</style>", "", t)
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t))).strip()


written.append(write("pivots_person__operator_evidence.json", {
    "_provenance": {"source": "live 2026-11-26 webmii.com/, /about, /privacy, apps.apple.com listing",
                    "minimised": "page text excerpts; the App Store seller (a natural person) is recorded only "
                                 "as 'individual'", "synthetic": False},
    "about_text": text_of(about)[:700],
    "privacy_text": text_of(priv)[:400],
    "links_on_site": {"terms": False, "privacy_policy_linked": False, "legal_entity_named": False},
    "app_store": {"seller_kind": "individual", "copyright_year": 2021, "privacy_url": "https://webmii.com/privacy"},
    "a8_assessment": "unknown (individual operator, no terms, no named legal entity): P257 FC4 drops the link "
                     "unless the registry reviewer records community"}))

# -------------------------------------------------------------------------------------- P307 web_search_api
def ddg_min(obj, n_related=2, scrub=()):
    out = {k: obj.get(k) for k in ("Heading", "Abstract", "AbstractText", "AbstractSource", "AbstractURL", "Answer",
                                   "AnswerType", "Definition", "Entity", "OfficialDomain", "OfficialWebsite",
                                   "Redirect", "Type") if k in obj}
    for k in ("Abstract", "AbstractText"):
        if isinstance(out.get(k), str) and len(out[k]) > 160:
            out[k] = out[k][:160].rsplit(" ", 1)[0] + " ..."
    ib = obj.get("Infobox")
    if isinstance(ib, dict):
        rows = []
        for row in ib.get("content", []):
            row = {k: row.get(k) for k in ("label", "value", "data_type", "wiki_order")}
            if row["label"] in scrub:
                row["value"] = scrub[row["label"]]
            rows.append(row)
        out["Infobox"] = {"content": rows[:14], "meta": ib.get("meta", [])[:2]}
    else:
        out["Infobox"] = ib
    out["RelatedTopics"] = [{k: t.get(k) for k in ("FirstURL", "Text")} for t in obj.get("RelatedTopics", [])][
        :n_related]
    out["Results"] = [{k: t.get(k) for k in ("FirstURL", "Text")} for t in obj.get("Results", [])]
    out["meta"] = {"id": (obj.get("meta") or {}).get("id")}
    return out


for rid, case, scrub, note in (
        ("ddg_ia_example_com", "ddg_ok", {}, "example.com: abstract cut, 2 related topics, infobox rows 0-13"),
        ("ddg_ia_cloudflare_com", "ddg_ok_company",
         {"Founders": "Person Example A, Person Example B", "Key people": "Person Example C (CEO)"},
         "cloudflare.com company infobox; the people named in Founders/Key people replaced with documentation "
         "placeholders (the parser must drop these rows anyway)"),
        ("ddg_ia_9_9_9_9", "ddg_empty", {}, "9.9.9.9: every field empty (meta.id just_another_test)")):
    obj = json.loads(read_text(os.path.join(LIVE, rid + ".body")))
    written.append(write(f"web_search_api__{case}.http.json", envelope(rid, ddg_min(obj, scrub=scrub), note)))

gaps = json.loads(read_text(os.path.join(RESEARCH, "gaps__web_search_api", "gaps__web_search_api.json")))
by_label = {r["label"]: r for r in gaps["requests"]}


def research_env(label, body, note):
    r = by_label[label]
    hdr = {k: (v if k != "www-authenticate" else v[:40] + "...(truncated)") for k, v in r["headers"].items()
           if k in KEEP_HEADERS}
    return {"_provenance": {"source": f"research sample gaps__web_search_api.json {gaps['collected_at']} "
                                      f"{r['method']} {r['url']} (no key)", "status_seen": r["http_status"],
                            "minimised": note, "synthetic": False},
            "url": r["url"], "status": r["http_status"], "headers": hdr, "body": body}


written.append(write("web_search_api__brave_needs_key.http.json", research_env(
    "brave_web_search_notoken", by_label["brave_web_search_notoken"]["body"], "complete 422 body")))
written.append(write("web_search_api__tavily_needs_key.http.json", research_env(
    "tavily_search_nokey", by_label["tavily_search_nokey"]["body"], "complete 401 body")))
exa = by_label["exa_search_nokey"]["body"]
a0 = exa["accepts"][0]
written.append(write("web_search_api__exa_x402.http.json", research_env("exa_search_nokey", {
    "requestId": "00000000000000000000000000000000", "error": exa["error"], "tag": exa["tag"],
    "x402Version": exa["x402Version"], "resource": exa["resource"],
    "accepts": [{"scheme": a0["scheme"], "network": a0["network"], "amount": a0["amount"],
                 "payTo": "0x0000000000000000000000000000000000000000", "asset": a0["asset"],
                 "maxTimeoutSeconds": a0["maxTimeoutSeconds"]}]},
    "1 of 7 payment offers kept; payTo and requestId zeroed; WWW-Authenticate truncated")))
mg = read_text(os.path.join(RESEARCH, "lists_global__marginalia_search_public", "lists_global__marginalia_search_public.json"))
written.append(write("web_search_api__marginalia_quota.http.json", {
    "_provenance": {"source": "research sample lists_global__marginalia_search_public.json (shared 'public' key, "
                              "2026-11-25)", "status_seen": 429, "minimised": "complete body", "synthetic": False},
    "url": "https://api2.marginalia-search.com/search?query=example&count=5", "status": 429,
    "headers": {"content-type": "text/plain"}, "body": mg}))
serp = json.loads(read_text(os.path.join(RESEARCH, "caipora_apis_cti__serpapi_nokey",
                                         "caipora_apis_cti__serpapi_nokey.json")))
written.append(write("web_search_api__serpapi_never_requested.json", {
    "_provenance": {"source": "research sample caipora_apis_cti__serpapi_nokey.json (keyless call returned a CACHED "
                              "search of q=test)", "minimised": "status, parameters and 1 organic result",
                    "synthetic": False,
                    "use": "canned FakeHttp answer for serpapi.com: the P307 test asserts it is never requested"},
    "body": {"search_metadata": {"status": serp["search_metadata"]["status"],
                                 "created_at": serp["search_metadata"]["created_at"]},
             "search_parameters": serp["search_parameters"],
             "organic_results": [{k: serp["organic_results"][0][k] for k in ("position", "title", "link")}]}}))

SYN = {"synthetic": True, "note": "shape from the provider's public API documentation; NOT captured (no key). "
                                  "Replace with a real capture before enabling the provider (P307 FC10)."}


def syn(source, status, body, headers=None):
    return {"_provenance": dict(SYN, source=source), "status": status,
            "headers": headers or {"content-type": "application/json"}, "body": body}


written.append(write("web_search_api__brave_ok_synthetic.http.json", syn(
    "Brave /res/v1/web/search?q=example.com&count=20", 200, {
        "type": "search",
        "query": {"original": "example.com", "more_results_available": True},
        "web": {"type": "search", "family_friendly": True, "results": [
            {"type": "search_result", "title": "Example Domain", "url": "https://example.com/",
             "description": "This domain is for use in <strong>documentation</strong> examples.",
             "extra_snippets": ["snippet that must never be stored"], "page_age": "2026-01-01T00:00:00",
             "profile": {"name": "Example", "url": "https://example.com/"},
             "meta_url": {"scheme": "https", "netloc": "example.com", "hostname": "example.com"}},
            {"type": "search_result", "title": "Example &amp; <strong>Docs</strong>",
             "url": "https://docs.example.org/page?ref=1", "description": "Another documentation page."},
            {"type": "search_result", "title": "Duplicate", "url": "https://example.com/"},
            {"type": "search_result", "title": "Not a web URL", "url": "javascript:alert(1)"}]}},
    {"content-type": "application/json", "x-ratelimit-limit": "1, 15000", "x-ratelimit-remaining": "0, 14990",
     "x-ratelimit-reset": "1, 1419704"})))
written.append(write("web_search_api__brave_rate_limited_synthetic.http.json", syn(
    "Brave 429 RATE_LIMITED", 429, {"type": "ErrorResponse", "error": {
        "id": "00000000-0000-0000-0000-000000000000", "status": 429, "code": "RATE_LIMITED",
        "detail": "Request rate limit exceeded for plan.", "meta": {"plan": "Free", "rate_limit": 1,
                                                                    "rate_current": 2}}})))
written.append(write("web_search_api__brave_quota_synthetic.http.json", syn(
    "Brave 429 QUOTA_LIMITED", 429, {"type": "ErrorResponse", "error": {
        "id": "00000000-0000-0000-0000-000000000000", "status": 429, "code": "QUOTA_LIMITED",
        "detail": "Request quota limit exceeded for plan."}})))
written.append(write("web_search_api__marginalia_ok_synthetic.http.json", syn(
    "Marginalia api2 /search?query=example&count=2", 200, {
        "license": "CC-BY-NC-SA 4.0", "query": "example", "results": [
            {"url": "https://blog.example.net/post", "title": "A small-web post", "description": "dropped",
             "quality": -3.2, "format": "html5", "details": ""}]})))
written.append(write("web_search_api__tavily_ok_synthetic.http.json", syn(
    "Tavily POST /search", 200, {"query": "example.com", "answer": None, "images": [], "results": [
        {"title": "Example Domain", "url": "https://example.com/", "content": "page copy that must be dropped",
         "score": 0.98, "raw_content": None}], "response_time": 0.9})))
written.append(write("web_search_api__exa_ok_synthetic.http.json", syn(
    "Exa POST /search", 200, {"requestId": "00000000000000000000000000000000", "resolvedSearchType": "neural",
                              "results": [{"id": "https://example.com/", "title": "Example Domain",
                                           "url": "https://example.com/", "publishedDate": None, "author": None,
                                           "text": "dropped"}]})))
written.append(write("web_search_api__ddg_malformed_synthetic.http.json", syn(
    "DuckDuckGo IA answering an HTML page (not observed)", 200,
    "<html><head><title>DuckDuckGo</title></head><body>unexpected</body></html>", {"content-type": "text/html"})))

# ------------------------------------------------------------------------------------------ P289 employee_xray
people = [("Alice Example", "Analista de Segurança da Informação"), ("Bruno Exemplo", "Diretor Financeiro"),
          ("Carla Example", "Software Engineer"), ("Diego Exemplo", "Analista de RH"),
          ("Elisa Example", "Executivo de Contas"), ("Fabio Exemplo", "Coordenador de TI")]
results = [{"type": "search_result", "title": f"{n} - {r} - Example Corp | LinkedIn",
            "url": f"https://br.linkedin.com/in/{n.lower().replace(' ', '-')}-0000{i}",
            "description": "snippet text that must never be read"} for i, (n, r) in enumerate(people)]
results += [
    {"type": "search_result", "title": "Gabriela Example – Example Corp | LinkedIn",
     "url": "https://www.linkedin.com/in/gabriela-example-00007/", "description": "x"},
    {"type": "search_result", "title": "Alice Example - Analista de Segurança da Informação - Example Corp | LinkedIn",
     "url": "https://br.linkedin.com/in/alice-example-00000", "description": "duplicate profile"},
    {"type": "search_result", "title": "Henrique Exemplo - Gerente - Other Company | LinkedIn",
     "url": "https://br.linkedin.com/in/henrique-exemplo-00009", "description": "other employer"},
    {"type": "search_result", "title": "Example Corp | LinkedIn",
     "url": "https://br.linkedin.com/company/example-corp", "description": "company page, not a profile"},
    {"type": "search_result", "title": "Example Corp - Careers", "url": "https://example.com/careers",
     "description": "not LinkedIn"},
]
written.append(write("employee_xray__brave_ok_synthetic.http.json", {
    "_provenance": dict(SYN, source='Brave /res/v1/web/search?q=site:linkedin.com/in "Example Corp" (P289 FC6: '
                                    'synthetic Brave responses; fictional names)'),
    "status": 200, "headers": {"content-type": "application/json"},
    "body": {"type": "search", "query": {"original": 'site:linkedin.com/in "Example Corp"',
                                         "more_results_available": False},
             "web": {"type": "search", "results": results}}}))
written.append(write("employee_xray__brave_empty_synthetic.http.json", syn(
    'Brave web search with no web block', 200, {"type": "search", "query": {"original": 'site:linkedin.com/in '
                                                                                       '"Nobody Ltda"'}})))
written.append(write("employee_xray__gate_cases.json", {
    "_provenance": {"synthetic": True, "note": "P289 FC1 gate scenarios; org_profile is a normalised view of the "
                                               "core P378 profile; scope adds the proposed social_engineering flag"},
    "org_profile": {"names": ["Example Corp"], "domains": {"example.com": "txt_verified",
                                                           "example.net": "unverified"}},
    "cases": [
        {"name": "own verified domain", "company": None, "domain": "example.com", "scope": None,
         "expect": {"run": True, "basis": "own_org", "reason_code": None}},
        {"name": "own org name", "company": "Example Corp", "domain": None, "scope": None,
         "expect": {"run": True, "basis": "own_org", "reason_code": None}},
        {"name": "unverified own domain", "company": None, "domain": "example.net", "scope": None,
         "expect": {"run": False, "basis": None, "reason_code": "own_asset"}},
        {"name": "third-party company", "company": "Other Company", "domain": "example.org", "scope": None,
         "expect": {"run": False, "basis": None, "reason_code": "own_asset"}},
        {"name": "engagement without SE flag", "company": "Client SA", "domain": "client.example.org",
         "scope": {"authorization_ref": "ENG-2026-001", "window_start": "2026-11-01T00:00:00Z",
                   "window_end": "2026-12-31T23:59:59Z", "targets": {"domains": ["client.example.org"]}},
         "expect": {"run": False, "basis": None, "reason_code": "scope"}},
        {"name": "engagement with SE flag", "company": "Client SA", "domain": "client.example.org",
         "scope": {"authorization_ref": "ENG-2026-001", "social_engineering": True,
                   "window_start": "2026-11-01T00:00:00Z", "window_end": "2026-12-31T23:59:59Z",
                   "targets": {"domains": ["client.example.org"]}},
         "expect": {"run": True, "basis": "engagement", "reason_code": None}},
        {"name": "SE flag as a string is not explicit", "company": "Client SA", "domain": "client.example.org",
         "scope": {"authorization_ref": "ENG-2026-001", "social_engineering": "true",
                   "targets": {"domains": ["client.example.org"]}},
         "expect": {"run": False, "basis": None, "reason_code": "scope"}},
        {"name": "engagement target not listed", "company": "Client SA", "domain": "other.example.org",
         "scope": {"authorization_ref": "ENG-2026-001", "social_engineering": True,
                   "targets": {"domains": ["client.example.org"]}},
         "expect": {"run": False, "basis": None, "reason_code": "scope"}},
        {"name": "outside the window", "company": "Client SA", "domain": "client.example.org",
         "scope": {"authorization_ref": "ENG-2026-001", "social_engineering": True,
                   "window_start": "2026-01-01T00:00:00Z", "window_end": "2026-01-31T23:59:59Z",
                   "targets": {"domains": ["client.example.org"]}},
         "expect": {"run": False, "basis": None, "reason_code": "scope"}}],
    "now": "2026-11-26T12:00:00Z"}))

# ------------------------------------------------------------------------- per-module live check summaries
MODULE_OF = (("emailformat_", "pivots_email"), ("bsky_", "pivots_username_social"),
             ("mastodon_", "pivots_username_social"), ("hibp_", "pivots_breach_leak"),
             ("webmii_", "pivots_person"), ("ddg_", "web_search_api"))
summ = {}
for rid, rec in LOG.items():
    mod = next((m for p, m in MODULE_OF if rid.startswith(p)), None)
    if not mod:
        continue
    summ.setdefault(mod, []).append({k: rec.get(k) for k in ("id", "url", "at", "status", "time_total", "bytes",
                                                            "redirect_url")} | {"headers": {
        k: v for k, v in rec.get("headers", {}).items() if k in KEEP_HEADERS}})
summ.setdefault("web_search_api", []).extend(
    {"id": r["label"], "url": r["url"], "at": gaps["collected_at"], "status": r["http_status"],
     "time_total": r["elapsed_s"], "source": "research sample (not re-requested: keyed source)"}
    for r in gaps["requests"] if r["label"] in ("brave_web_search_notoken", "tavily_search_nokey",
                                                 "exa_search_nokey"))
summ.setdefault("employee_xray", []).append({"id": "none", "note": "keyed (Brave via P307): no live request; "
                                                                   "synthetic fixtures per FC6"})
for mod, rows in summ.items():
    written.append(write(f"{mod}__live_checks.meta.json", {"egress": "research datacenter (outside Brazil), curl "
                                                                     "default UA, no cookies, redirects not followed",
                                                           "checks": rows}))

print("\n".join(sorted(written)))
