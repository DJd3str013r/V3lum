"""Offline tests for batch p3-G10-3 parsers (P253 adverse_media_rss, P254 wanted_notices)."""
import json
import re
import sys
import urllib.parse
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import parsers as p  # noqa: E402

FIX = Path(__file__).parent.parent / "fixtures"


def raw(name):
    return (FIX / name).read_bytes()


def http(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------- P253 GDELT

@pytest.fixture(scope="module")
def articles():
    return p.parse_gdelt_artlist(raw("adverse_media_rss__gdelt_artlist_ok_synthetic.json"))


def test_gdelt_artlist_parse_keeps_headline_fields_only(articles):
    assert len(articles) == 8  # record without title and the non-object are skipped
    a = articles[0]
    assert set(a) == {"title", "url", "domain", "date", "language", "sourcecountry"}
    assert a["date"] == "2026-11-20T10:15:00Z"
    assert a["domain"] == "noticias.example.com"
    assert all("socialimage" not in x for x in articles)


def test_mentions_org_exact_name_and_risk_term_clustered(articles):
    r = p.adverse_media_mentions(articles, "Exemplo Comercial Ltda", kind="org")
    assert r["name_phrase"] == "exemplo comercial"
    assert r["articles_total"] == 8 and r["articles_matched"] == 5
    titles = [m["title"] for m in r["mentions"]]
    assert len(titles) == 3
    first = r["mentions"][0]
    assert first["articles"] == 3
    assert first["outlets"] == ["jornal.example.org", "noticias.example.com", "portal.example.net"]
    assert first["matched_terms"] == ["fraude", "operacao"]
    assert r["mentions"][1]["matched_terms"] == ["vazamento"]
    assert r["mentions"][2]["matched_terms"] == ["condenado", "corrupcao"]
    joined = " | ".join(titles)
    assert "centro de distribui" not in joined          # name but no risk term
    assert "Exemplo Comércio" not in joined             # risk term but not the exact name
    assert "Comercializadora" not in joined             # name is only a prefix of another word
    for m in r["mentions"]:
        assert m["severity"] == "info" and m["label"] == p.MENTION_LABEL
        assert set(m) == {"title", "url", "domain", "date", "outlets", "urls", "articles", "matched_terms",
                          "label", "severity"}
    assert r["summary_severity"] == "low" and r["risk_scored"] is False
    assert r["citation"].startswith("Source: The GDELT Project")
    assert r["homonym"] is None


def test_mentions_person_no_org_terms_and_homonym_phrase(articles):
    r = p.adverse_media_mentions(articles, "Exemplo Comercial", kind="person")
    assert [m["matched_terms"] for m in r["mentions"]] == [["fraude", "operacao"], ["condenado", "corrupcao"]]
    assert r["homonym"] == p.HOMONYM_DEFAULT_PHRASE
    r2 = p.adverse_media_mentions(articles, "Exemplo Comercial", kind="person", homonym_phrase="very common name")
    assert r2["homonym"] == "very common name"


def test_mentions_capped_at_ten_story_clusters():
    arts = [{"title": f"Operação {w} investiga fraude na Exemplo Comercial", "url": f"https://n.example.com/{i}",
             "domain": "n.example.com", "date": f"2026-11-{10 + i:02d}T00:00:00Z"}
            for i, w in enumerate(["alfa", "bravo", "charlie", "delta", "eco", "foxtrote", "golfe", "hotel",
                                   "india", "juliete", "kilo", "lima", "mike", "novembro", "oscar"])]
    # titles differ in one token out of 7 -> Jaccard 6/8 = 0.75 < 0.8 -> 15 separate stories
    r = p.adverse_media_mentions(arts, "Exemplo Comercial")
    assert r["clusters_total"] == 15 and len(r["mentions"]) == p.MAX_HEADLINES == 10 and r["truncated"] is True
    assert r["mentions"][0]["date"] == "2026-11-24T00:00:00Z"   # newest first


def test_similarity_threshold_is_named_constant():
    assert p.TITLE_SIMILARITY_THRESHOLD == 0.8
    a = p.title_tokens("PF deflagra operação contra fraude na Exemplo Comercial")
    b = p.title_tokens("PF deflagra operação contra fraude na Exemplo Comercial, diz jornal")
    assert p.jaccard(a, b) == pytest.approx(0.8)
    assert len(p.cluster_headlines([{"title": "a b c d e", "url": "u1"}, {"title": "a b c d x", "url": "u2"}])) == 2


def test_gdelt_empty_answer_is_empty_not_error():
    body = raw("adverse_media_rss__gdelt_empty.json")
    assert p.gdelt_marker(200, body) is None
    assert p.parse_gdelt_artlist(body) == []
    r = p.adverse_media_mentions([], "Exemplo Comercial")
    assert r["mentions"] == [] and r["summary_severity"] is None


def test_gdelt_429_is_rate_limited_never_no_news():
    rec = http("adverse_media_rss__gdelt_rate_limited_429.http.json")
    body, status = rec["response"]["body"], rec["response"]["status"]
    assert p.gdelt_marker(status, body, rec["response"]["headers"]) == "rate_limited"
    assert p.gdelt_marker(200, body) == "rate_limited"          # same text with a 200 status
    with pytest.raises(p.ParseError) as exc:
        p.parse_gdelt_artlist(body)
    assert exc.value.reason == "rate_limited"
    assert "@example.com" in body


def test_gdelt_error_in_200():
    body = raw("adverse_media_rss__gdelt_error_in_200_synthetic.txt")
    m = p.gdelt_marker(200, body)
    assert m == "error_in_200:The specified phrase is too short."
    with pytest.raises(p.ParseError) as exc:
        p.parse_gdelt_artlist(body)
    assert exc.value.reason == "error_in_200"


def test_gdelt_malformed_and_html():
    body = raw("adverse_media_rss__gdelt_malformed_truncated_derived.json")
    assert p.gdelt_marker(200, body) == "malformed_json"
    with pytest.raises(p.ParseError):
        p.parse_gdelt_artlist(body)
    docs = raw("wanted_notices__fbi_docs_html_200_not_challenge.html")
    assert p.gdelt_marker(200, docs) == "html_not_json"
    cf = http("wanted_notices__fbi_blocked_403_cloudflare_synthetic.http.json")["response"]
    assert p.gdelt_marker(403, cf["body"], cf["headers"]) == "challenge:cloudflare"
    assert p.gdelt_marker(503, "") == "http_503"
    assert p.gdelt_marker(200, b"") == "empty_body"
    with pytest.raises(p.ParseError):
        p.parse_gdelt_artlist({"articles": "nope"})
    assert p.parse_gdelt_artlist({"other": 1}) == []


def test_gdelt_connection_reset_maps_to_error_with_cool_down():
    rec = http("adverse_media_rss__gdelt_connection_reset.http.json")
    assert rec["response"] is None
    r = p.transport_reason(rec["transport_error"])
    assert r == {"reason_code": "error", "text": "connection reset by provider (throttling suspected)",
                 "cool_down": True}
    assert p.transport_reason("Read timed out")["reason_code"] == "timeout"


def test_gdelt_rss_through_safe_xml_gate():
    items = p.parse_gdelt_rss(raw("adverse_media_rss__gdelt_rss_ok_synthetic.xml"))
    assert [i["date"] for i in items] == ["2026-11-20T10:15:00Z", "2026-11-18T09:00:00Z"]
    assert items[0]["domain"] == "noticias.example.com"
    assert p.gdelt_marker(200, raw("adverse_media_rss__gdelt_rss_ok_synthetic.xml")) is None
    with pytest.raises(p.ParseError) as exc:
        p.parse_gdelt_rss(raw("adverse_media_rss__gdelt_rss_dtd_entities_malicious_synthetic.xml"))
    assert exc.value.reason == "xml_dtd_refused"
    with pytest.raises(p.ParseError):
        p.parse_gdelt_rss("<rss><channel><item>")


def test_one_combined_query_per_entity():
    q = p.build_gdelt_query("BANCO DO BRASIL S.A.", kind="org")
    assert q.startswith('"banco do brasil" (fraude OR corrupcao OR ')
    assert q.endswith(") sourcelang:portuguese")
    assert '"ataque hacker"' in q and '"dados expostos"' in q and "invasao" in q
    qp = p.build_gdelt_query("Dra. Maria Exemplo", kind="person", source_filter="sourcecountry:brazil")
    assert qp.startswith('"maria exemplo" (') and "vazamento" not in qp and qp.endswith("sourcecountry:brazil")
    params = p.gdelt_request_params(q)
    assert params["format"] == "json" and params["mode"] == "artlist" and params["maxrecords"] == "50"
    url = p.gdelt_request_url(q)
    assert url.startswith("https://api.gdeltproject.org/api/v2/doc/doc?query=%22banco%20do%20brasil%22")
    assert p.gdelt_query_problem(p.name_phrase("BB S.A.")) is not None
    assert p.gdelt_query_problem("exemplo comercial") is None
    assert p.RISK_TERMS_VERSION == "pt-risk-v1" and len(p.RISK_TERMS_PT) == 13 and len(p.RISK_TERMS_PT_ORG) == 6
    assert set(p.risk_terms("org", include_en=True)) >= {"fraud", "data breach"}
    assert p.GDELT_MIN_INTERVAL_S == 5.0


def test_google_news_is_a_manual_link_only():
    link = p.google_news_manual_link("Exemplo Comercial Ltda")
    parts = urllib.parse.urlsplit(link)
    assert parts.netloc == "news.google.com" and parts.path == "/search"
    q = urllib.parse.parse_qs(parts.query)
    assert q["q"][0].startswith('"exemplo comercial" (fraude OR ') and q["hl"] == ["pt-BR"]
    assert "/rss/" not in link


def test_person_query_gate():
    assert p.adverse_media_query_allowed("org", False, None) is None
    assert p.adverse_media_query_allowed("person", True, "due diligence fornecedor X") is None
    assert p.adverse_media_query_allowed("person", False, "due diligence") is not None
    assert p.adverse_media_query_allowed("person", True, "due diligence", source="qsa") is not None
    assert p.adverse_media_query_allowed("person", True, "") is not None
    assert "employment" in p.adverse_media_query_allowed("person", True, "triagem de candidato para contratação")


def test_url_pivots_never_expand(articles):
    r = p.adverse_media_mentions(articles, "Exemplo Comercial")
    piv = p.url_pivots(r["mentions"])
    assert len(piv) == 5 and all(x["type"] == "url" and x["expand"] is False for x in piv)


# ---------------------------------------------------------------- P254 FBI / INTERPOL

@pytest.fixture(scope="module")
def records():
    return p.parse_fbi_list(raw("wanted_notices__fbi_list_ok.json"))


def test_fbi_page_meta_and_page_plan():
    meta = p.fbi_page_meta(raw("wanted_notices__fbi_list_ok.json"))
    assert meta == {"total": 1283, "page": 1, "count": 5}
    assert p.fbi_pages_needed(1283) == {"pages": 25, "capped": True, "missing_items": 33}
    assert p.fbi_pages_needed(730) == {"pages": 15, "capped": False, "missing_items": 0}
    assert p.fbi_pages_needed(None)["pages"] == 1
    assert p.fbi_list_params(3) == {"pageSize": "50", "page": "3", "poster_classification": "default"}
    assert "poster_classification" not in p.fbi_list_params(1, poster_classification=None)


def test_fbi_cyber_filter_is_local(records):
    assert [r["path"] for r in records] == ["/wanted/cyber/apt-41-group", "/wanted/cyber/dprk-it-workers",
                                            "/wanted/cyber/example-member-two", "/wanted/cyber/example-member-five"]
    allrecs = p.parse_fbi_list(raw("wanted_notices__fbi_list_ok.json"), cyber_only=False)
    assert len(allrecs) == 5
    assert p.fbi_is_cyber({"subjects": ["Cyber’s Most Wanted"]})
    assert not p.fbi_is_cyber({"subjects": ["Seeking Information"], "path": "/wanted/seeking-info/x"})


def test_fbi_record_minimal_no_biometrics(records):
    r = records[2]
    assert r["title"] == "EXAMPLE MEMBER TWO" and r["aliases"] == ["example-handle-1a", "example-handle-1b"]
    assert r["charges"].startswith("Conspiracy to Cause Damage")
    assert r["poster_urls"] == ["https://www.fbi.gov/wanted/cyber/example-member-two/download.pdf"]
    for forbidden in ("images", "dates_of_birth_used", "sex", "race", "hair", "eyes", "height_min", "remarks",
                      "place_of_birth"):
        assert forbidden not in r
    assert "@@images" not in json.dumps(records)
    assert [x["is_group"] for x in records] == [True, True, False, False]
    assert records[0]["links"] == {"/wanted/cyber/example-member-one": "EXAMPLE Member One",
                                   "/wanted/cyber/example-member-two": "EXAMPLE Member Two"}
    assert set(p.fbi_public_view(r)) == {"title", "aliases", "charges", "url", "poster_urls", "status"}


def test_match_actor_apt41_counts_indicted_individuals(records):
    m = p.match_actor(records, "APT41", ["APT 41", "BARIUM", "Winnti", "Wicked Panda", "Brass Typhoon"])
    assert m["count"] == 2
    assert m["summary"] == "2 indicted individuals linked to APT41 - FBI"
    assert [(i["path"], i["via"]) for i in m["individuals"]] == [
        ("/wanted/cyber/example-member-two", "direct"), ("/wanted/cyber/example-member-one", "group_poster")]
    assert m["individuals"][1]["title"] == "EXAMPLE Member One"
    assert [g["path"] for g in m["groups"]] == ["/wanted/cyber/apt-41-group"]
    assert m["label"] == "possible match - not identity proof"
    assert (m["severity"], m["confidence"]) == ("info", "medium")


def test_match_actor_group_backlinks(records):
    m = p.match_actor(records, "DPRK IT Workers", ["Famous Chollima", "Jasper Sleet", "UNC5267"])
    assert m["count"] == 3
    assert {(i["path"], i["via"]) for i in m["individuals"]} == {
        ("/wanted/cyber/example-member-three", "group_poster"), ("/wanted/cyber/example-member-four", "group_poster"),
        ("/wanted/cyber/example-member-five", "links_to_group")}


def test_match_actor_no_match_and_generic_aliases(records):
    m = p.match_actor(records, "Lazarus Group", ["Lazarus", "Hidden Cobra", "APT38", "Diamond Sleet"])
    assert m["count"] == 0 and m["summary"] is None and m["matched"] == []
    assert p.actor_alias_forms("Lazarus Group") == ["lazarus group", "lazarus"]
    assert p.actor_alias_forms("APT", ["Group", "Panda", "TA5", "Bear"]) == []
    assert p.match_actor(records, "APT", ["Group", "Chinese"])["count"] == 0


def test_match_person_local_possible_match(records):
    hit = p.match_person(records, "Two Example Member")
    assert [(h["path"], h["match_type"]) for h in hit] == [("/wanted/cyber/example-member-two", "name_exact")]
    assert hit[0]["label"] == p.POSSIBLE_MATCH_LABEL and hit[0]["homonym"] == p.HOMONYM_DEFAULT_PHRASE
    assert p.match_person(records, "example handle 1a")[0]["match_type"] == "alias_exact"
    sub = p.match_person(records, "Member Five", homonym_phrase="common name")
    assert sub[0]["match_type"] == "name_subset" and sub[0]["homonym"] == "common name"
    assert p.match_person(records, "Example") == []                 # single token: too ambiguous
    assert p.match_person(records, "APT 41 Group") == []            # group posters are not persons
    assert p.match_person(records, "Fulano Exemplo da Silva") == []


def test_fbi_empty_page():
    body = raw("wanted_notices__fbi_list_empty_page_derived.json")
    assert p.fbi_marker(200, body) is None
    assert p.parse_fbi_list(body) == []
    assert p.merge_fbi_pages([[], []]) == []


def test_fbi_merge_dedupes(records):
    merged = p.merge_fbi_pages([records, records[1:]])
    assert len(merged) == 4


def test_fbi_blocked_cloudflare_is_challenge():
    rec = http("wanted_notices__fbi_blocked_403_cloudflare_synthetic.http.json")["response"]
    assert p.fbi_marker(rec["status"], rec["body"], rec["headers"]) == "challenge:cloudflare"
    assert p.detect_block(rec["status"], {}, rec["body"]) == "challenge:cloudflare"
    with pytest.raises(p.ParseError) as exc:
        p.parse_fbi_list(rec["body"])
    assert exc.value.reason == "challenge"


def test_interpol_akamai_403_is_challenge():
    rec = http("wanted_notices__interpol_blocked_403_akamai_derived.http.json")["response"]
    assert p.detect_block(rec["status"], rec["headers"], rec["body"]) == "challenge:akamai"
    assert p.fbi_marker(rec["status"], rec["body"]) == "challenge:akamai"


def test_cloudflare_passive_script_on_200_html_is_not_a_challenge():
    docs = raw("wanted_notices__fbi_docs_html_200_not_challenge.html")
    assert b"/cdn-cgi/challenge-platform/scripts/jsd/" in docs
    assert p.detect_block(200, {"server": "cloudflare"}, docs) is None
    assert p.fbi_marker(200, docs) == "html_not_json"
    with pytest.raises(p.ParseError) as exc:
        p.parse_fbi_list(docs)
    assert exc.value.reason == "html_not_json"


def test_fbi_malformed_and_wrong_shapes():
    body = raw("wanted_notices__fbi_list_malformed_truncated_derived.json")
    assert p.fbi_marker(200, body) == "malformed_json"
    with pytest.raises(p.ParseError):
        p.parse_fbi_list(body)
    assert p.fbi_marker(200, b"[]") == "unexpected_json"
    assert p.fbi_marker(429, b"") == "rate_limited"
    with pytest.raises(p.ParseError):
        p.parse_fbi_list({"total": 1})
    assert p.parse_fbi_list({"items": [None, 5, {"subjects": ["Cyber's Most Wanted"]}]}) == []
    assert p.normalise_fbi_item("x") is None


def test_manual_links():
    link = p.interpol_manual_link()
    assert link.startswith("https://www.interpol.int/") and "?" not in link and "yellow" not in link.lower()
    assert p.fbi_manual_link() == "https://www.fbi.gov/wanted/cyber"


# ---------------------------------------------------------------- fixture hygiene

def test_fixtures_have_no_personal_contact_data():
    email = re.compile(rb"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
    cpf = re.compile(rb"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
    phone = re.compile(rb"\+?55\s?\(?\d{2}\)?\s?9?\d{4}-?\d{4}")
    names = sorted(x.name for x in FIX.iterdir())
    assert len(names) >= 14
    for f in FIX.iterdir():
        data = f.read_bytes()
        for m in email.finditer(data):
            assert m.group(0).split(b"@", 1)[1].endswith((b"example.com", b"example.org", b"example.net")), f.name
        assert not cpf.search(data), f.name
        assert not phone.search(data), f.name
        assert b"apikey" not in data.lower() and b"set-cookie" not in data.lower(), f.name
