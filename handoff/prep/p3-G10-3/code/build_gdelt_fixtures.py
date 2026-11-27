"""Build adverse_media_rss fixtures (python3 -I).

Usage: python3 -I build_gdelt_fixtures.py <raw_dir> <fixtures_dir>

Observed (live, 2026-11-26, datacenter egress): HTTP 429 text body (twice) and TLS connection resets (three times).
Positive/RSS/error-in-200 bodies are SYNTHETIC in the documented GDELT DOC 2.0 shapes, about a fictional company
('Exemplo Comercial'), because no 200 answer could be obtained from this egress (P253 FC8 still needs a real
positive capture from the team network before merge).
"""
import json
import re
import sys
from pathlib import Path

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def main():
    raw, out = Path(sys.argv[1]), Path(sys.argv[2])
    body = (raw / "gdelt_pos_b.body").read_bytes().decode("utf-8", "replace")
    body = EMAIL.sub("operator@example.com", body)
    rec = {
        "request": {"method": "GET", "url": "https://api.gdeltproject.org/api/v2/doc/doc?query=%22banco+do+brasil%22+%28fraude+OR+corrupcao+OR+preso+OR+investigado+OR+condenado+OR+denuncia+OR+golpe+OR+lavagem+OR+estelionato+OR+improbidade+OR+operacao+OR+desvio+OR+propina+OR+vazamento+OR+ransomware+OR+%22ataque+hacker%22+OR+incidente+OR+%22dados+expostos%22+OR+invasao%29+sourcecountry%3Abrazil&mode=artlist&format=json&maxrecords=50&timespan=3months&sort=datedesc"},
        "response": {"status": 429, "headers": {"server": "GDELT Server", "content-length": "444"}, "body": body},
        "elapsed_s": 11.66,
        "origin": "live",
        "observed_at": "2026-11-26T10:49:52Z",
        "note": "live capture; no Content-Type and no Retry-After header; operator e-mail address in the body replaced by operator@example.com",
    }
    (out / "adverse_media_rss__gdelt_rate_limited_429.http.json").write_text(json.dumps(rec, indent=1, ensure_ascii=False) + "\n")

    rec = {
        "request": {"method": "GET", "url": "https://api.gdeltproject.org/api/v2/doc/doc?query=...&mode=artlist&format=json"},
        "response": None,
        "transport_error": "curl: (35) Recv failure: Connection reset by peer",
        "elapsed_s": 12.05,
        "origin": "live",
        "observed_at": ["2026-11-26T10:45:45Z", "2026-11-26T10:46:58Z", "2026-11-26T10:48:10Z"],
        "note": "three of five calls (60-90 s apart) ended in a TLS reset after ~12 s; the research egress saw the same after its 429s",
    }
    (out / "adverse_media_rss__gdelt_connection_reset.http.json").write_text(json.dumps(rec, indent=1) + "\n")

    # empty answer: GDELT answers HTTP 200 '{}' when nothing matches (research egress, 2026-11-26)
    (out / "adverse_media_rss__gdelt_empty.json").write_text("{}")

    arts = [
        ("https://noticias.example.com/2026/11/20/pf-operacao-fraude-exemplo", "PF deflagra operação contra fraude na Exemplo Comercial", "20261120T101500Z", "noticias.example.com"),
        ("https://jornal.example.org/economia/pf-operacao-fraude-exemplo-comercial", "PF deflagra operação contra fraude na Exemplo Comercial", "20261120T113000Z", "jornal.example.org"),
        ("https://portal.example.net/n/123456", "PF deflagra operação contra fraude na Exemplo Comercial, diz jornal", "20261120T120000Z", "portal.example.net"),
        ("https://noticias.example.com/2026/11/18/exemplo-novo-centro", "Exemplo Comercial anuncia novo centro de distribuição", "20261118T090000Z", "noticias.example.com"),
        ("https://jornal.example.org/tecnologia/vazamento-exemplo", "Vazamento de dados expõe clientes da Exemplo Comercial", "20261115T080000Z", "jornal.example.org"),
        ("https://portal.example.net/n/123457", "Golpe usa nome da Exemplo Comércio para enganar clientes", "20261114T070000Z", "portal.example.net"),
        ("https://noticias.example.com/2026/11/10/ex-diretor-condenado", "Ex-diretor da Exemplo Comercial é condenado por corrupção", "20261110T150000Z", "noticias.example.com"),
        ("https://jornal.example.org/policia/comercializadora", "Exemplo Comercializadora é investigada por lavagem de dinheiro", "20261109T140000Z", "jornal.example.org"),
    ]
    articles = [{"url": u, "url_mobile": "", "title": t, "seendate": d, "socialimage": "https://img.example.com/" + str(i) + ".jpg",
                 "domain": dom, "language": "Portuguese", "sourcecountry": "Brazil"} for i, (u, t, d, dom) in enumerate(arts)]
    articles.append({"url": "https://portal.example.net/n/999", "title": None, "seendate": "bad-date", "domain": None})
    articles.append("not-an-object")
    (out / "adverse_media_rss__gdelt_artlist_ok_synthetic.json").write_text(json.dumps({"articles": articles}, ensure_ascii=False, indent=1) + "\n")

    # error-in-200: GDELT answers query errors with HTTP 200 and a short plain-text message (shape per research
    # notes/GDELT docs; exact wording not observed from this egress)
    (out / "adverse_media_rss__gdelt_error_in_200_synthetic.txt").write_text("The specified phrase is too short.\n")

    full = json.dumps({"articles": articles[:3]}, ensure_ascii=False)
    (out / "adverse_media_rss__gdelt_malformed_truncated_derived.json").write_text(full[: len(full) // 2])

    rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>GDELT DOC API</title>
<item><title>PF deflagra operação contra fraude na Exemplo Comercial</title><link>https://noticias.example.com/2026/11/20/pf-operacao-fraude-exemplo</link><pubDate>Fri, 20 Nov 2026 10:15:00 +0000</pubDate><guid>https://noticias.example.com/2026/11/20/pf-operacao-fraude-exemplo</guid></item>
<item><title>Exemplo Comercial anuncia novo centro de distribuição</title><link>https://noticias.example.com/2026/11/18/exemplo-novo-centro</link><pubDate>Wed, 18 Nov 2026 09:00:00 +0000</pubDate></item>
<item><title></title><link></link></item>
</channel></rss>
"""
    (out / "adverse_media_rss__gdelt_rss_ok_synthetic.xml").write_text(rss)
    evil = """<?xml version="1.0"?>
<!DOCTYPE rss [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<rss version="2.0"><channel><item><title>&b;</title><link>https://example.com/</link></item></channel></rss>
"""
    (out / "adverse_media_rss__gdelt_rss_dtd_entities_malicious_synthetic.xml").write_text(evil)
    print("ok")


if __name__ == "__main__":
    main()
