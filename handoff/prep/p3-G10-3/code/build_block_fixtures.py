"""Write the derived/synthetic block, empty-page and malformed fixtures for wanted_notices (python3 -I).

Usage: python3 -I build_block_fixtures.py <fixtures_dir> [<raw_dir>]
"""
import json
import re
import sys
from pathlib import Path


def akamai_encode(url):
    out = []
    for ch in url:
        if ch.isalnum():
            out.append(ch)
        else:
            out.append(f"&#{ord(ch)};")
    return "".join(out)


def main():
    out = Path(sys.argv[1])
    url = "http://ws-public.interpol.int/notices/v1/red"  # Akamai shows the path without the query string
    body = ("<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD><BODY>\n<H1>Access Denied</H1>\n \n"
            f"You don't have permission to access \"{akamai_encode(url)}\" on this server.<P>\n"
            "Reference&#32;&#35;18&#46;00000000&#46;0000000000&#46;00000000\n"
            "<P>https&#58;&#47;&#47;errors&#46;edgesuite&#46;net&#47;18&#46;00000000&#46;0000000000&#46;00000000</P>\n"
            "</BODY>\n</HTML>\n")
    rec = {
        "request": {"method": "GET", "url": "https://ws-public.interpol.int/notices/v1/red?nationality=BR&resultPerPage=1"},
        "response": {"status": 403, "headers": {"content-type": "text/html", "server": "AkamaiGHost"}, "body": body},
        "origin": "derived",
        "note": ("derived: research probe 2026-11-25 (tmp_caipora_people/results.jsonl slug interpol_red_notices) saw HTTP 403 "
                 "text/html, 407 bytes, <title>Access Denied</title> from ws-public.interpol.int; the body is the Akamai "
                 "'Access Denied' template observed verbatim from www.cisa.gov (p1-G08-1 fixture) with this URL and a zeroed "
                 "reference. Not re-requested here: INTERPOL is Akamai bot-protected and not automated (P254 FC3). "
                 f"Body length {len(body.encode())} bytes."),
    }
    (out / "wanted_notices__interpol_blocked_403_akamai_derived.http.json").write_text(json.dumps(rec, indent=1) + "\n")

    cf = ("<!DOCTYPE html><html lang=\"en-US\"><head><title>Just a moment...</title>"
          "<meta http-equiv=\"refresh\" content=\"390\"></head><body><noscript>Enable JavaScript and cookies to continue"
          "</noscript><script src=\"/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1\"></script></body></html>")
    rec = {
        "request": {"method": "GET", "url": "https://api.fbi.gov/wanted/v1/list?poster_classification=default&pageSize=50&page=1"},
        "response": {"status": 403, "headers": {"content-type": "text/html; charset=UTF-8", "server": "cloudflare",
                                                 "cf-mitigated": "challenge"}, "body": cf},
        "origin": "synthetic",
        "note": ("synthetic: Cloudflare managed-challenge page. api.fbi.gov sits behind Cloudflare (server: cloudflare, "
                 "cf-ray, cf-cache-status; its /docs page loads the /cdn-cgi/challenge-platform jsd script) but answered "
                 "200 to every request from this datacenter egress on 2026-11-26. Template as in p1-G10-2 cnpj_lookup "
                 "challenge fixture."),
    }
    (out / "wanted_notices__fbi_blocked_403_cloudflare_synthetic.http.json").write_text(json.dumps(rec, indent=1) + "\n")

    # page past the end: the API keeps 'total' and returns no items (derived, not observed)
    (out / "wanted_notices__fbi_list_empty_page_derived.json").write_text(
        json.dumps({"total": 730, "items": [], "page": 16}, indent=1) + "\n")

    if len(sys.argv) > 2:
        raw = Path(sys.argv[2])
        # real 200 HTML (Swagger UI) of api.fbi.gov/docs with Cloudflare's passive jsd script: must NOT be read as a challenge
        docs = (raw / "fbi_docs.html").read_text(encoding="utf-8", errors="replace")
        docs = re.sub(r"r:'[0-9a-f]+'", "r:'0000000000000000'", docs)
        docs = re.sub(r"t:'[A-Za-z0-9=]+'", "t:'MDAwMDAwMDAwMA=='", docs)
        docs = re.sub(r"ray=[0-9a-f]+", "ray=0000000000000000", docs)
        (out / "wanted_notices__fbi_docs_html_200_not_challenge.html").write_text(docs)
        # malformed: the live list page cut in the middle (derived from the scrubbed ok fixture)
        ok = (out / "wanted_notices__fbi_list_ok.json").read_text(encoding="utf-8")
        (out / "wanted_notices__fbi_list_malformed_truncated_derived.json").write_text(ok[:1500])


if __name__ == "__main__":
    main()
