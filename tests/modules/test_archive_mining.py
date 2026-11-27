"""archive_mining (P060, opt-in): waymore-filtered archived URLs, historical robots.txt (Robofinder) and
archived favicons / analytics ids (chronos), offline.

Fixtures in tests/fixtures/archive_mining/ (batch p2-G01-3 prep, 2026-11-25/26): Wayback CDX slices in the
web_archives shapes (a robots.txt digest listing derived from the live Arquivo.pt answer, the synthetic URL
listing, the P059 cut listing), live Arquivo.pt NDJSON (registro.br robots.txt, google.com favicon, the P059
userinfo slice), the archived registro.br robots.txt (2019-11-15) and Google robots.txt (research), the
archived Google favicon of 2009-09-14 (Shodan hash -1184133586), a synthetic soft-404 favicon page, the P059
homepage with analytics ids, the live Wayback reset and an archive.org 429. The URL listing is rewritten
to the seed's host where a run needs it (derived). Every archive request is answered here; a request to the
live target fails the test (FakeHttp has no route for it).
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import string

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum.core.datasets import DataStore
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Opsec, Status
from v3lum.modules.url_web import archive_mining as A
from v3lum.modules.utility import secret_scanner as _scanner
from v3lum.modules.url_web.archive_mining import ArchiveMining
from v3lum.modules.url_web.web_archives import SRC_ARQUIVO, SRC_CDX

FX = FIXTURES / "archive_mining"
CDX = "https://web.archive.org/cdx/search/cdx"
ARQ = "https://arquivo.pt/wayback/cdx"
FL = "timestamp,original,digest,statuscode,mimetype"
HOST = "registro.br"
HEADER = ["timestamp", "original", "digest", "statuscode", "mimetype"]


def raw(name):
    return (FX / name).read_bytes()


def listing_url(query=HOST, match="domain", limit=5000):
    return f"{CDX}?url={query}&matchType={match}&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit={limit}&showResumeKey=true"


def versions_url(kind, host=HOST):
    if kind == "robots":
        return f"{CDX}?url={host}/robots.txt&output=json&fl={FL}&filter=statuscode:200&collapse=digest&limit=500"
    if kind == "favicon":
        return f"{CDX}?url={host}/favicon.ico&output=json&fl={FL}&filter=statuscode:200&filter=!mimetype:warc/revisit&collapse=digest&limit=500"
    return f"{CDX}?url={host}/&output=json&fl={FL}&filter=statuscode:200&filter=mimetype:text/html&collapse=timestamp:4&limit=500"


def arquivo_url(path, host=HOST):
    return f"{ARQ}?url={host}{path}&output=json&limit=500"


def snapshot(archive, host=HOST, path=r"robots\.txt"):
    base = r"https://web\.archive\.org/web/" if archive == "wayback" else r"https://arquivo\.pt/wayback/"
    return re.compile("^" + base + r"\d{14}id_/https?://(www\.)?" + re.escape(host) + "/" + path + "$")


def synthetic_listing(host=HOST):
    return (FX / "wayback_cdx_urls_synthetic.json").read_text(encoding="utf-8").replace("example.com", host)


def robots_rows(n=None):
    rows = json.loads((FX / "wayback_cdx_robots_digest_derived.json").read_text(encoding="utf-8"))
    if n is None:
        return rows
    return [HEADER] + [[f"20{10 + i // 12:02d}{1 + i % 12:02d}01000000", f"https://{HOST}/robots.txt", f"DIGEST{i:04d}", "200", "text/plain"]
                       for i in range(n)]


def full_http(host=HOST, listing=None):
    """A complete Wayback answer set for ``host``: URL listing, versions of robots/favicon/homepage, bodies."""
    http = FakeHttp()
    http.add("GET", listing_url(host), text=listing if listing is not None else synthetic_listing(host),
             headers={"content-type": "application/json"})
    http.add("GET", versions_url("robots", host), json=robots_rows())
    http.add("GET", versions_url("favicon", host), json=[HEADER, ["20090914010645", f"http://{host}/favicon.ico", "FAV2009", "200", "image/x-icon"]])
    http.add("GET", versions_url("homepage", host), json=[HEADER, ["20150101000000", f"https://{host}/", "HOME2015", "200", "text/html"]])
    http.add("GET", snapshot("wayback", host), body=raw("robots_registrobr_20191115.txt"), headers={"content-type": "text/plain"})
    http.add("GET", f"https://web.archive.org/web/20090914010645id_/http://{host}/favicon.ico", body=raw("favicon_google_20090914.ico"),
             headers={"content-type": "image/x-icon"})
    http.add("GET", f"https://web.archive.org/web/20150101000000id_/https://{host}/", body=raw("homepage_indicators_p059.html"),
             headers={"content-type": "text/html"})
    return http


def fake_github_token(seed):
    """A generated, never-issued token in the GitHub PAT format (no real key in the repository)."""
    rng = random.Random(seed)
    return "ghp_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))


def dumped(res):
    return json.dumps({"attributes": res.attributes, "raw": res.raw, "findings": [f.to_dict() for f in res.findings],
                       "pivots": [p.entity.value for p in res.pivots], "error": res.error}, default=str)


# ------------------------------------------------------------------ metadata (cond 1, 2, 8)
def test_contract_metadata():
    cls = ArchiveMining
    assert cls.default_enabled is False and cls.terms == "open" and cls.opsec is Opsec.PASSIVE and cls.run_on == "seeds"
    assert cls.hosts == ("web.archive.org", "arquivo.pt")  # never OTX/urlscan/ghostarchive/Intelligence X, never the target
    assert cls.produces == {T.URL, T.FAVICON_HASH, T.ANALYTICS_ID}
    assert cls.max_requests == 1 + 3 + 3 + A.MAX_BODIES == 27
    assert set(cls.settings) == {"archive_mining_budget", "archive_mining_max_bodies", "archive_mining_noise_favicons"}
    assert cls.settings["archive_mining_max_bodies"].default == 10


# ------------------------------------------------------------------ MurmurHash3 and the Shodan favicon form (cond 5)
@pytest.mark.parametrize(("hexdata", "seed", "expected"), [
    ("", 0, 0), ("", 1, 1364076727), ("", 0xFFFFFFFF, -2114883783), ("00000000", 0, 593689054), ("61", 0, 1009084850),
    ("6162", 0, -1681926305), ("616263", 0, -1277324294), ("61626364", 0, 1139631978), ("666f6f", 0, -156908512),
    ("666f6f", 42, -1322301282), ("48656c6c6f2c20776f726c6421", 0x9747B28C, 612912314),
    (b"The quick brown fox jumps over the lazy dog".hex(), 0x9747B28C, 799549133), ("61c3a7c3a36f", 0, -206526165),
])
def test_mmh3_32_reference_vectors(hexdata, seed, expected):
    assert A.mmh3_32(bytes.fromhex(hexdata), seed) == expected


def test_mmh3_32_long_input_unsigned_and_str():
    assert A.mmh3_32(bytes(range(256))) == -469103018
    assert A.mmh3_32(b"foo", signed=False) == 4138058784 == A.mmh3_32(b"foo") + 2**32
    assert A.mmh3_32("ação") == A.mmh3_32("ação".encode())


def test_shodan_favicon_hash_of_the_archived_google_favicon():
    ico = raw("favicon_google_20090914.ico")
    assert hashlib.md5(ico).hexdigest() == "09b565a51e14b721a323f0ba44b2982a"  # noqa: S324 - fixture identity
    assert A.shodan_favicon_hash(ico) == -1184133586
    assert A.mmh3_32(base64.encodebytes(ico).rstrip(b"\n")) == -1790163806  # chronos form: no trailing newline, matches nothing
    rec = A.favicon_record(ico, "20090914010645", "http://www.google.com/favicon.ico")
    assert rec["ok"] and rec["favicon_hash"] == "-1184133586" and rec["format"] == "ico" and rec["snapshot"] == "2009-09-14"
    soft = A.favicon_record(raw("favicon_soft404_synthetic.html"), "20150101000000")
    assert soft == {"ok": False, "reason": "HTML instead of an image (soft 404)", "snapshot": "2015-01-01"}


# ------------------------------------------------------------------ CDX rows, versions, body plan (cond 2, 4)
def test_parse_cdx_rows_shapes():
    wb = A.parse_cdx_rows(json.dumps(robots_rows()))
    assert wb["state"] == "ok" and len(wb["rows"]) == 5 and wb["rows"][0]["digest"] == "APCJ7TZOJXXBQIC62YIPKVO75HJGZOIA"
    arq = A.parse_cdx_rows(raw("arquivo_cdx_robots.ndjson"))
    assert arq["state"] == "ok" and len(arq["rows"]) == 12 and arq["rows"][4]["statuscode"] == "302"
    assert A.parse_cdx_rows(b"")["state"] == "empty" and A.parse_cdx_rows("[]")["state"] == "empty"
    html = A.parse_cdx_rows("<html><head><title>Wayback Machine</title></head></html>")
    assert html["state"] == "error" and "HTML" in html["error"]  # an error page is never 'no captures'
    cut = A.parse_cdx_rows(raw("wayback_cdx_truncated_p059.json"))
    assert cut["state"] == "error" and cut["partial"]
    capped = A.parse_cdx_rows(json.dumps(robots_rows(30)), row_cap=10)
    assert len(capped["rows"]) == 10 and capped["partial"]
    ndjson_cut = A.parse_cdx_rows(raw("arquivo_cdx_favicon.ndjson")[:-40])
    assert ndjson_cut["partial"] and len(ndjson_cut["rows"]) == 4


def test_distinct_versions_collapse_locally():
    rows = A.parse_cdx_rows(raw("arquivo_cdx_robots.ndjson"))["rows"]  # Arquivo.pt ignores collapse=digest
    versions = A.distinct_versions(rows)
    assert [v["key"][:4] for v in versions] == ["APCJ", "6EHE", "Y3XX", "QSJV", "T5YT"]  # 301/302 captures dropped
    assert versions[0] == {"key": "APCJ7TZOJXXBQIC62YIPKVO75HJGZOIA", "first_ts": "20090926115905", "last_ts": "20100530163745",
                           "url": "http://www.registro.br/robots.txt", "captures": 2}
    years = A.distinct_versions(A.parse_cdx_rows(raw("arquivo_cdx_userinfo_p059.ndjson"))["rows"], by="year")
    assert [(v["key"], v["captures"]) for v in years] == [("2009", 3), ("2010", 2)]
    revisit = [{"url": "https://a.example/favicon.ico", "timestamp": "20200101000000", "statuscode": "200", "mimetype": "warc/revisit", "digest": "X"}]
    assert A.distinct_versions(revisit) == []


def test_plan_bodies_caps_interleaves_and_never_plans_credentials():
    robots = A.distinct_versions(A.parse_cdx_rows(json.dumps(robots_rows(30)))["rows"])
    favicons = A.distinct_versions(A.parse_cdx_rows(raw("arquivo_cdx_favicon.ndjson"))["rows"])
    plan = A.plan_bodies({"robots": ("wayback", robots), "favicon": ("arquivo", favicons)}, 50)
    assert len(plan) == A.MAX_BODIES == 20  # the setting can never lift the hard cap
    assert [p["kind"] for p in plan[:6]] == ["robots", "favicon"] * 3
    assert plan[0]["timestamp"] == robots[-1]["first_ts"] and plan[2]["timestamp"] == robots[0]["first_ts"]  # newest, then oldest
    assert plan[1]["url"].startswith("https://arquivo.pt/wayback/") and "id_/" in plan[1]["url"]
    assert A.plan_bodies({"robots": ("wayback", robots)}, 0) == []
    homepage = A.distinct_versions(A.parse_cdx_rows(raw("arquivo_cdx_userinfo_p059.ndjson"))["rows"], by="year")
    only = A.plan_bodies({"homepage": ("arquivo", homepage)}, 10)
    assert [p["timestamp"] for p in only] == ["20100323155533"]  # the 2009 era starts with a user:pass original: never fetched
    assert all("@" not in p["url"] for p in only)


def test_check_body_rules():
    assert A.check_body(raw("favicon_google_20090914.ico"), "favicon")["format"] == "ico"
    assert A.check_body(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, "favicon")["format"] == "png"
    assert A.check_body(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>", "favicon")["format"] == "svg"
    assert not A.check_body(raw("favicon_soft404_synthetic.html"), "favicon")["ok"]
    assert A.check_body(b"\x00\x00\x01\x00" + b"x" * 64, "favicon", max_bytes=16)["reason"] == "larger than 16 bytes"
    assert A.check_body(b"", "robots")["reason"] == "empty body"
    assert A.check_body(b"User-agent: *\x00\x01", "robots")["reason"] == "binary body"
    assert A.check_body(b"<!DOCTYPE html><html><title>404</title></html>", "robots")["format"] == "html"
    assert A.check_body(raw("robots_registrobr_20191115.txt"), "robots")["ok"]


# ------------------------------------------------------------------ robots.txt (cond 4)
def test_parse_robots_archived_versions():
    rb = A.parse_robots(raw("robots_registrobr_20191115.txt"))
    assert rb["user_agents"] == ["*"] and rb["allow"] == ["/cgi-bin/whois/$", "/2/whois$"] and len(rb["disallow"]) == 20
    assert "/painel/" in rb["disallow"] and rb["invalid"] == 0 and not rb["truncated"]
    google = A.parse_robots(raw("robots_google_live_research.txt"))
    assert google["sitemap"] == ["https://www.google.com/sitemap.xml"] and "/m/finance" in google["allow"]
    assert google["user_agents"] == ["*", "Google-Extended", "Yandex"] and "/books?*dq=" in google["disallow"]
    odd = A.parse_robots("# comment\nDISALLOW: /x # trailing\nDisallow:\nDisallow: relative\nnot a directive\nSitemap: ftp://x/\n")
    assert odd["disallow"] == ["/x"] and odd["invalid"] == 2 and odd["sitemap"] == []
    big = A.parse_robots(b"Disallow: /a\n" * 50_000)
    assert big["truncated"] and big["disallow"] == ["/a"]


def test_robots_union_dates_patterns_and_masked_urls():
    versions = [
        {"timestamp": "20090926115905", "url": "http://www.registro.br/robots.txt", "parsed": A.parse_robots("Disallow: /old/\nDisallow: /2/\n")},
        {"timestamp": "20191115155400", "url": "https://registro.br/robots.txt", "parsed": A.parse_robots(raw("robots_registrobr_20191115.txt"))},
        {"timestamp": "20170803073929", "url": "https://registro.br/robots.txt",
         "parsed": A.parse_robots("Disallow: /*.php$\nDisallow: /\nDisallow: /reset?token=0123456789abcdef0123456789abcdef\n")},
    ]
    union = A.robots_union(versions)
    assert union["disallow"]["/2/"] == {"first_seen": "2009-09-26", "last_seen": "2019-11-15", "versions": 2, "origin": "https://registro.br"}
    assert union["disallow"]["/old/"]["origin"] == "http://www.registro.br"
    rows, patterns = A.robots_disallow_urls(union)
    assert {p["path"] for p in patterns} == {"/*.php$", "/", "/reset?token=***"}  # a masked path is no url entity
    by_path = {r["path"]: r["url"] for r in rows}
    assert by_path["/painel/"] == "https://registro.br/painel/" and by_path["/old/"] == "http://www.registro.br/old/"
    assert "0123456789abcdef0123456789abcdef" not in json.dumps([union, rows, patterns])  # tokens in robots lines are masked


# ------------------------------------------------------------------ analytics ids (cond 6)
def test_extract_analytics_ids_from_an_archived_homepage():
    ids = A.extract_analytics_ids(raw("homepage_indicators_p059.html"))
    assert ids == [{"id": "UA-1234567-1", "kind": "ga_universal"}, {"id": "G-ABC123XYZ9", "kind": "ga4"},
                   {"id": "GTM-W2XYZ9K", "kind": "gtm"}, {"id": "pub-1234567890123456", "kind": "adsense"}]
    assert A.extract_analytics_ids("xG-ABCDEF12 UA-12-1 GTM-AB pub-123 BG-ABCDEFGH") == []
    capped = A.extract_analytics_ids("G-ABC123 " * 10 + " ".join(f"UA-1234567-{i}" for i in range(80)), max_ids=5)
    assert [i["id"] for i in capped] == [f"UA-1234567-{i}" for i in range(5)]  # bounded; duplicates counted once
    assert [i["id"] for i in A.extract_analytics_ids("G-ABC123 G-ABC123 UA-1234567-1")] == ["UA-1234567-1", "G-ABC123"]


# ------------------------------------------------------------------ waymore filters and masking (cond 3, 8)
def test_bundled_waymore_lists_and_notice():
    data = DataStore.bundled_json(A.WAYMORE_FILE)
    assert data["schema"] == "v3lum.waymore_filters/1" and "MIT" in json.dumps(data)
    lists = A.load_waymore()
    assert lists["filter_code"] == ("404", "301", "302")
    assert "text/css" in lists["filter_mime"] and "admin" in lists["filter_keywords"] and lists["filter_url"]
    notice = DataStore.bundled_json("notices/waymore_filters.json")
    assert notice["schema"] == "v3lum.notice/1" and "v3lum/modules/url_web/archive_mining.py" in notice["files"]


def test_waymore_keep_and_categories_on_the_synthetic_listing():
    lists = A.load_waymore()
    keep = lambda url, status="200", mime="text/html": A.waymore_keep(url, status, mime, lists)  # noqa: E731
    assert keep("https://example.com/old-page", "404") == (False, "status 404")
    assert keep("https://example.com/logo.png", mime="image/png") == (False, "mime image/png")
    assert keep("https://example.com/config.php.bak", mime="application/octet-stream")[0]  # backups whatever the MIME
    assert keep("https://example.com/") == (False, "no keyword")
    assert keep("https://example.com/admin/login.php")[0]
    assert [A.categorise_url(u) for u in ("https://example.com/.env", "https://example.com/web.config", "https://example.com/config.php.bak",
                                          "https://example.com/backup/site-2018.zip", "https://dev.example.com/jenkins/",
                                          "https://api.example.com/v1/users?id=1", "https://example.com/service?wsdl",
                                          "https://example.com/blog/2019/hello-world")] == [
        "config", "config", "backup", "backup", "admin", "api", "api", "other"]


def test_mask_harvested_url():
    token = fake_github_token("p060-mask")
    masked, changed = A.mask_harvested_url(f"https://example.com/hooks/{token}/run")
    assert changed and token not in masked and A.MASK in masked
    assert A.mask_harvested_url("https://user:pass@example.com/admin/") == ("https://***@example.com/admin/", True)
    assert A.mask_harvested_url("https://example.com/api/v2/export?access_token=0123456789abcdef0123456789abcdef&format=csv")[0] == \
        "https://example.com/api/v2/export?access_token=***&format=csv"
    assert A.mask_harvested_url("https://example.com/graphql") == ("https://example.com/graphql", False)


# ------------------------------------------------------------------ the run
def test_full_run_mines_robots_favicons_analytics_and_urls():
    http = full_http()
    res = run_module(ArchiveMining, f"domain:{HOST}", http)
    assert res.status is Status.OK and not res.partial
    grouped = res.attributes["interesting_archived_urls"]
    assert grouped["counts"] == {"config": 2, "backup": 2, "admin": 3, "api": 4, "robots_disallow": 20}
    assert not grouped["truncated"] and grouped["shown"] == grouped["total"] == 31
    admin = {e["url"]: e for e in grouped["categories"]["admin"]}
    assert admin["https://registro.br/admin/login.php"]["captures"] == 2
    assert admin["https://registro.br/admin/login.php"]["first_seen"] == "2019-05-05"
    assert "https://***@registro.br/admin/" in admin  # userinfo masked before storage
    robots = res.attributes["archived_robots"]
    assert [v["timestamp"] for v in robots["versions"]] == ["20090926115905", "20140906131000", "20170803073929", "20171211140358",
                                                            "20191115155400"]
    assert robots["disallow"]["/painel/"]["versions"] == 5 and set(robots["allow"]) == {"/cgi-bin/whois/$", "/2/whois$"}
    [favicon] = res.attributes["archived_favicons"]
    assert favicon["favicon_hash"] == "-1184133586" and favicon["first_seen"] == "2009-09-14" and favicon["noise"] is False
    assert [a["id"] for a in res.attributes["archived_analytics_ids"]] == ["G-ABC123XYZ9", "GTM-W2XYZ9K", "UA-1234567-1", "pub-1234567890123456"]
    assert all(a["first_seen"] == "2015-01-01" for a in res.attributes["archived_analytics_ids"])
    # pivots: historical, never expanded, never fetched (cond 6, 7)
    assert res.pivots and all(p.expand is False for p in res.pivots)
    relations = {p.relation for p in res.pivots}
    assert relations == {"robots_disallow", "historical_favicon", "historical_analytics_id"}
    # historical ids never link sites across eras (cond 6): dedicated relations, weak edges (< 0.6, seeds_linked skips them)
    assert all(p.confidence < 0.6 for p in res.pivots if p.relation != "robots_disallow")
    assert {p.entity.value for p in res.pivots if p.entity.type is T.FAVICON_HASH} == {"-1184133586"}
    assert len([p for p in res.pivots if p.relation == "robots_disallow"]) == 20
    [info] = res.findings
    assert info.title == "Archive mining" and info.severity.name == "INFO" and "historical" in info.tags
    # archive hosts only: the live site is never contacted, snapshots are raw id_ captures
    http.assert_hosts_within(ArchiveMining)
    assert http.hosts() == {"web.archive.org"}
    bodies = [u for u in http.urls() if "/web/" in u]
    assert len(bodies) == 7 and all(re.search(r"/web/\d{14}id_/", u) for u in bodies)
    assert "user:pass" not in dumped(res)


def test_archived_bodies_are_never_cached_but_cdx_answers_are():
    http = full_http()
    runtime = make_runtime(http, cache=True)
    run_module(ArchiveMining, f"domain:{HOST}", http, runtime=runtime)
    first = http.urls()
    run_module(ArchiveMining, f"domain:{HOST}", http, runtime=runtime)
    second = http.urls()[len(first):]
    assert second and all("/web/" in u for u in second)  # bodies fetched again (ttl 0), CDX served from the cache
    assert len(second) == len([u for u in first if "/web/" in u])


def test_wayback_unreachable_falls_back_to_arquivo_and_stops_asking_wayback():
    http = FakeHttp()
    reset = json.loads((FX / "wayback_cdx_reset.http.json").read_text(encoding="utf-8"))["transport_error"]  # live 2026-11-26
    http.add("GET", listing_url(), error=NetworkError(reset, kind="ConnectionError"))
    http.add("GET", arquivo_url("/robots.txt"), body=raw("arquivo_cdx_robots.ndjson"), headers={"content-type": "text/plain"})
    http.add("GET", arquivo_url("/favicon.ico"), text="")
    http.add("GET", arquivo_url("/"), text="")
    http.add("GET", snapshot("arquivo"), body=raw("robots_registrobr_20191115.txt"), headers={"content-type": "text/plain"})
    res = run_module(ArchiveMining, f"domain:{HOST}", http)
    assert {u for u in http.urls() if u.startswith(CDX)} == {http.urls()[0]}  # the listing reset: no Wayback version query follows
    assert res.status is Status.OK and res.partial and "archive unreachable" in res.error
    row = res.source_statuses[SRC_CDX]
    assert row["status"] == "error" and row["reason_code"] == "error"
    assert res.attributes["archive_sources"]["wayback_robots_versions"].startswith("not_run: ")
    robots = res.attributes["archived_robots"]
    assert len(robots["versions"]) == 5 and robots["disallow"]["/painel/"]["versions"] == 5
    assert all(u.startswith("https://arquivo.pt/") for u in http.urls() if not u.startswith(CDX))


def test_rate_limited_everywhere_is_could_not_verify_never_empty():
    recorded = json.loads((FX / "ia_available_429.http.json").read_text(encoding="utf-8"))["response"]
    http = FakeHttp()
    http.add("GET", re.compile(r"^https://(web\.archive\.org|arquivo\.pt)/"), status=429, text=recorded["body"],
             headers={"content-type": recorded["headers"]["content-type"], "retry-after": "60"})
    res = run_module(ArchiveMining, f"domain:{HOST}", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited" and "could not verify" in res.error
    assert len([u for u in http.urls() if u.startswith(CDX)]) == 1 and len([u for u in http.urls() if u.startswith(ARQ)]) == 1
    assert res.findings == [] and res.pivots == []


def test_error_page_in_200_is_could_not_verify():
    http = FakeHttp()
    http.add("GET", re.compile(r"^https://web\.archive\.org/cdx/"), text="<html><head><title>Wayback Machine</title></head><body>Maintenance</body></html>")
    http.add("GET", re.compile(r"^https://arquivo\.pt/wayback/cdx\?"), text="")  # the fallback answers: nothing archived there
    res = run_module(ArchiveMining, "domain:example.org", http)
    assert res.status is Status.ERROR and "could not verify" in res.error and "HTML" in res.error
    assert res.source_statuses[SRC_CDX]["status"] == "error"


def test_archives_without_history_are_empty():
    http = FakeHttp()
    http.add("GET", listing_url("example.org"), json=[])
    for kind in ("robots", "favicon", "homepage"):
        http.add("GET", versions_url(kind, "example.org"), json=[])
    res = run_module(ArchiveMining, "domain:example.org", http)
    assert res.status is Status.EMPTY and not any(u.startswith(ARQ) for u in http.urls())  # Arquivo only for .br/.pt or a dead Wayback


def test_soft_404_favicon_is_rejected_and_noise_favicons_are_never_pivoted():
    http = FakeHttp()
    http.add("GET", listing_url("example.org"), json=[])
    http.add("GET", versions_url("robots", "example.org"), json=[])
    http.add("GET", versions_url("homepage", "example.org"), json=[])
    http.add("GET", versions_url("favicon", "example.org"), json=[
        HEADER, ["20090914010645", "http://example.org/favicon.ico", "FAV2009", "200", "image/x-icon"],
        ["20150101000000", "https://example.org/favicon.ico", "SOFT404", "200", "image/x-icon"]])
    http.add("GET", "https://web.archive.org/web/20090914010645id_/http://example.org/favicon.ico", body=raw("favicon_google_20090914.ico"))
    http.add("GET", "https://web.archive.org/web/20150101000000id_/https://example.org/favicon.ico", body=raw("favicon_soft404_synthetic.html"))
    res = run_module(ArchiveMining, "domain:example.org", http, settings={"archive_mining_noise_favicons": [-1184133586]})
    [favicon] = res.attributes["archived_favicons"]
    assert favicon["favicon_hash"] == "-1184133586" and favicon["noise"] is True
    assert not [p for p in res.pivots if p.entity.type is T.FAVICON_HASH]  # recorded, never pivoted (P062 rule)
    reasons = {b["timestamp"]: b["reason"] for b in res.raw["bodies"]}
    assert reasons == {"20090914010645": None, "20150101000000": "HTML instead of an image (soft 404)"}


@pytest.mark.parametrize(("setting", "expected"), [(None, 10), (50, 20), (3, 3)])
def test_body_cap(setting, expected):
    http = FakeHttp()
    http.add("GET", listing_url(), json=[])
    http.add("GET", versions_url("robots"), json=robots_rows(30))
    http.add("GET", versions_url("favicon"), json=[])
    http.add("GET", versions_url("homepage"), json=[])
    http.add("GET", arquivo_url("/favicon.ico"), text="")  # .br: Arquivo.pt is asked for the paths Wayback holds nothing of
    http.add("GET", arquivo_url("/"), text="")
    http.add("GET", snapshot("wayback"), body=raw("robots_registrobr_20191115.txt"))
    settings = {} if setting is None else {"archive_mining_max_bodies": setting, "archive_mining_budget": 115}
    res = run_module(ArchiveMining, f"domain:{HOST}", http, settings=settings)
    assert len([u for u in http.urls() if "/web/" in u]) == expected
    assert len(res.attributes["archived_robots"]["versions"]) == expected


def test_report_cap_50_keeps_the_full_lists_in_the_evidence():
    rows = [["original", "timestamp", "statuscode", "mimetype"]]
    rows += [[f"https://{HOST}/admin/panel{i}", f"2020{1 + i % 12:02d}01000000", "200", "text/html"] for i in range(60)]
    rows += [[f"https://{HOST}/api/v1/item{i}", f"2021{1 + i % 12:02d}01000000", "200", "application/json"] for i in range(60)]
    http = FakeHttp()
    http.add("GET", listing_url(), json=rows)
    for kind, path in (("robots", "/robots.txt"), ("favicon", "/favicon.ico"), ("homepage", "/")):
        http.add("GET", versions_url(kind), json=[])
        http.add("GET", arquivo_url(path), text="")
    res = run_module(ArchiveMining, f"domain:{HOST}", http)
    grouped = res.attributes["interesting_archived_urls"]
    assert grouped["total"] == 120 and grouped["shown"] == 50 and grouped["truncated"]
    assert len(grouped["categories"]["admin"]) == 25 and len(grouped["categories"]["api"]) == 25  # round-robin
    assert len(res.raw["interesting_urls"]["admin"]) == 60 and len(res.raw["interesting_urls"]["api"]) == 60
    assert not [f for f in res.findings if f.title != "Archive mining"]  # no per-URL findings (cond 8)


@pytest.mark.skipif(getattr(_scanner, "_toml", None) is None, reason="secret_scanner rules need a TOML parser (tomllib or tomli)")
def test_secret_in_an_archived_url_is_one_masked_finding():
    token = fake_github_token("p060-secret")
    rows = [["original", "timestamp", "statuscode", "mimetype"], [f"https://{HOST}/deploy/hook?gh={token}", "20210303000000", "200", "text/html"],
            [f"https://{HOST}/admin/", "20210303000001", "200", "text/html"]]
    http = FakeHttp()
    http.add("GET", listing_url(), json=rows)
    for kind, path in (("robots", "/robots.txt"), ("favicon", "/favicon.ico"), ("homepage", "/")):
        http.add("GET", versions_url(kind), json=[])
        http.add("GET", arquivo_url(path), text="")
    res = run_module(ArchiveMining, f"domain:{HOST}", http)
    [finding] = [f for f in res.findings if f.title.startswith("Secret exposed in an archived URL")]
    assert finding.title == "Secret exposed in an archived URL: github-pat" and "credential_exposure" in finding.tags
    assert finding.data["masked"]["display"].startswith("ghp_") and finding.data["owner"] == "third_party"
    assert token not in dumped(res)


def test_url_seed_mines_its_host_and_never_fetches_it():
    http = FakeHttp()
    http.add("GET", listing_url(f"https://{HOST}/painel/", match="prefix"), json=[])
    for kind, path in (("robots", "/robots.txt"), ("favicon", "/favicon.ico"), ("homepage", "/")):
        http.add("GET", versions_url(kind), json=[])
        http.add("GET", arquivo_url(path), text="")
    res = run_module(ArchiveMining, f"url:https://{HOST}/painel/", http)
    assert res.status is Status.EMPTY and http.hosts() == {"web.archive.org", "arquivo.pt"}
    skipped = run_module(ArchiveMining, "url:ftp://example.org/x", FakeHttp())
    assert skipped.status is Status.SKIPPED and skipped.reason_code == "not_applicable"


def test_userinfo_originals_are_masked_and_never_fetched():
    http = FakeHttp()
    http.add("GET", listing_url("example.com"), error=NetworkError("Recv failure: Connection reset by peer", kind="ConnectionError"))
    http.add("GET", arquivo_url("/robots.txt", "example.com"), text="")
    http.add("GET", arquivo_url("/favicon.ico", "example.com"), text="")
    http.add("GET", arquivo_url("/", "example.com"), body=raw("arquivo_cdx_userinfo_p059.ndjson"))
    http.add("GET", "https://arquivo.pt/wayback/20100323155533id_/http://www.example.com/", body=raw("homepage_indicators_p059.html"))
    res = run_module(ArchiveMining, "domain:example.com", http)
    assert not any("@" in u for u in http.urls())
    assert [a["first_seen"] for a in res.attributes["archived_analytics_ids"]] == ["2010-03-23"] * 4
    assert "user:pass" not in dumped(res)
    assert res.source_statuses[SRC_CDX]["status"] == "error" and SRC_ARQUIVO not in res.source_statuses
