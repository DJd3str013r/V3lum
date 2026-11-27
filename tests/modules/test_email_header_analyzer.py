"""email_header_analyzer (P085): static, offline analysis of a reported e-mail.

Fixtures in tests/fixtures/email_header_analyzer/ (no real reported e-mail can be committed with its
personal data, so the main one is synthetic in real header grammar):

* ``ok.eml`` - six hops (org Exchange + Postfix boundary, forged lower hops, an IPv6-tagged HELO), a
  genuine and a forged Authentication-Results, a SafeLinks URL wrapping a base64 recipient token in a
  QP text part and a base64 HTML part, a tracking pixel, CSS, a form, a file:// link and an HTML
  attachment; RFC 2047 From and Subject;
* ``malformed_header.eml`` - trimmed, scrubbed derivative of mail-parser's real spam sample
  ``tests/mails/mail_malformed_3`` (Apache-2.0): qmail stamp, private HELO literal, empty 'by', a MIME
  boundary that never appears and an inserted colon-less header line;
* ``headers_only.txt`` - Gmail-style header block with IPv6 hops and a SendGrid date;
* ``not_email.bin`` - PNG bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import shutil

import pytest

from tests.fakes import FIXTURES, DeadHttp, FakeHttp, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.email import email_header_analyzer as eha
from v3lum.modules.email.email_header_analyzer import EmailHeaderAnalyzer

MOD = EmailHeaderAnalyzer
FX = FIXTURES / "email_header_analyzer"
RECIPIENT = "recipient@example.com"
REPORTER = "phishing-report@example.com"
INNER_URL = "https://payout.example.org/login?u=" + base64.b64encode(RECIPIENT.encode()).decode()
ATTACHMENT = b"<html><body><p>Fatura de exemplo (fixture V3LUM, sem conteudo ativo)</p></body></html>\n"
ORG = dict(trusted_mta=["mx1.example.com", "*.corp.example.com"], authserv_ids=["mx1.example.com"],
           org_domains=["example.com"], brands=["Exemplo Bank", "Banco Exemplo"], reporter_addresses=[REPORTER])
SETTINGS = {
    "email_header_analyzer_trusted_mta": ["mx1.example.com", "*.corp.example.com"],
    "email_header_analyzer_authserv_ids": ["mx1.example.com"],
    "email_header_analyzer_reporter_addresses": [REPORTER],
}


def fb(name: str) -> bytes:
    return (FX / name).read_bytes()


def unwrap_stub(url):
    """Stands in for the single P064 helper in the pure-parser tests (a lookup, no decoding logic)."""
    return INNER_URL if url.startswith("https://nam12.safelinks.protection.outlook.com/") else url


@pytest.fixture(scope="module")
def ok_result():
    return eha.analyze_email(fb("ok.eml"), unwrap=unwrap_stub, registrable=eha.psl.registrable_domain, **ORG)


def org_profile():
    return OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "txt_verified"}], "brands": [{"keyword": "Exemplo Bank"}]})


def outputs(res):
    """Everything a shared report or export can show: attributes, findings, pivots, links, error."""
    return json.dumps([res.attributes, [f.to_dict() for f in res.findings], [p.to_dict() for p in res.pivots], res.links, res.error], default=str)


# ------------------------------------------------------------------ C1: caps, malformed input, never a crash
def test_caps_and_not_an_email():
    assert eha.analyze_email(b"")["reason"] == "error: empty input"
    assert eha.analyze_email("text")["reason"] == "error: input is not bytes"
    assert eha.analyze_email(b"A" * (eha.MAX_EMAIL_BYTES + 1))["reason"] == "error: input exceeds the 25 MB cap"
    many = b"".join(b"X-H%d: v\r\n" % i for i in range(eha.MAX_HEADER_COUNT + 1)) + b"\r\n"
    assert eha.analyze_email(many)["reason"] == "error: more than 2000 header fields"
    big = b"Subject: " + b"a" * (eha.MAX_HEADER_BYTES + 10) + b"\r\n\r\nbody"
    assert eha.analyze_email(big)["reason"] == "error: header field larger than 64 KB (Subject)"
    assert eha.analyze_email(fb("not_email.bin")) == {"status": "error", "reason": "error: no RFC 5322 header block found (not an e-mail)"}


def test_module_errors_with_the_reason(tmp_path):
    fake_eml = tmp_path / "not_mail.eml"
    shutil.copy(FX / "not_email.bin", fake_eml)
    res = run_module(MOD, f"file:{fake_eml}", FakeHttp())
    assert res.status is Status.ERROR and "not an e-mail" in res.error
    huge = tmp_path / "huge.eml"
    with open(huge, "wb") as fh:
        fh.truncate(eha.MAX_EMAIL_BYTES + 1)  # sparse file: the cap is checked before reading
    res2 = run_module(MOD, f"file:{huge}", FakeHttp())
    assert res2.status is Status.ERROR and "25 MB" in res2.error


def test_non_email_files_are_not_applicable(tmp_path):
    png = tmp_path / "image.png"
    shutil.copy(FX / "not_email.bin", png)
    assert run_module(MOD, f"file:{png}", FakeHttp()).reason_code == "not_applicable"
    text = run_module(MOD, "text_blob:just some notes\nwith lines\nand no headers", FakeHttp())
    assert text.status is Status.SKIPPED and text.reason_code == "not_applicable"


def test_hostile_inputs_never_crash():
    for data in (b"\x00\xff" * 500, b"Received: (((((\r\n\r\n", b"From: <<<@@@>>>\r\n\r\n",
                 b"Received: from x (y [1.2.3.4]\r\nSubject: =?bogus?Q?=ZZ?=\r\n\r\n",
                 b"Content-Type: multipart/mixed; boundary=\"\"\r\n\r\n--\r\n--\r\n"):
        assert eha.analyze_email(data)["status"] in ("ok", "error")


def test_mutation_fuzz_never_crashes():
    rnd = random.Random(20261126)
    seeds = [fb("ok.eml"), fb("malformed_header.eml"), fb("headers_only.txt")]
    junk = [b";", b"(", b")", b"[", b"]", b"<", b">", b"\"", b"\\", b"\r\n", b"\r\n ", b"=?utf-8?b?", b"::",
            b"IPv6:", b"--", b"\x00", b"\xff", b"Received: ", b"boundary=", b"%40", b"from ", b" by "]
    for i in range(150):
        data = bytearray(seeds[i % 3])
        for _ in range(rnd.randint(1, 12)):
            pos = rnd.randrange(len(data))
            op = rnd.random()
            if op < 0.4:
                data[pos:pos] = rnd.choice(junk)
            elif op < 0.7:
                del data[pos:pos + rnd.randint(1, 40)]
            else:
                data[pos] = rnd.randrange(256)
        r = eha.analyze_email(bytes(data), trusted_mta=["mx1.example.com", "mx.google.com"], authserv_ids=["mx1.example.com"], unwrap=unwrap_stub)
        assert r["status"] in ("ok", "error")
        if r["status"] == "ok":
            json.dumps(r)  # JSON-safe evidence


# ------------------------------------------------------------------ C3: the Received chain
def test_received_chain_chronological_last_semicolon_total_seconds(ok_result):
    hops = ok_result["hops"]
    assert [h["by_host"] for h in hops] == ["mail.innocent.example.org", "relay.mailer.example.net", "relay.mailer.example.net",
                                            "mx1.example.com", "mbx01.corp.example.com", "mbx02.corp.example.com"]
    assert [h["delay_s"] for h in hops] == [None, 86404.0, -2.0, 4.0, 2.0, 1.0]  # day-aware total_seconds()
    assert [h["negative_delay"] for h in hops] == [False, False, True, False, False, False]
    assert hops[3]["date_utc"] == "2026-11-24T13:00:06Z"  # '-0300 (-03)' after the LAST ';'
    assert any(f["type"] == "clock_skew" for f in ok_result["findings"])
    assert ok_result["total_delay_s"] == 86409.0 and ok_result["trusted_delay_s"] == 3.0


def test_ipv6_tag_blanked_and_trailing_double_colon_branch_last(ok_result):
    hop = ok_result["hops"][2]
    assert hop["ips"] == ["203.0.113.99"] and hop["helo_ips"] == ["2001:db8:4864:20::32"]
    assert eha.REGXIP6.search("x 2a00:1450:4864:20::32 y").group() == "2a00:1450:4864:20::32"
    ips, helo = eha.sender_ip_candidates("[IPv6:2001:db8::5] (unknown [IPv6:2001:db8::7])")
    assert ips == ["2001:db8::7"] and helo == ["2001:db8::5"]


def test_parse_received_variants():
    r = eha.parse_received("from a.example.net (a.example.net [198.51.100.1]; note) by mx.example.com id X1; for <r@example.com>; Tue, 24 Nov 2026 13:00:00 +0000")
    assert r["date_utc"] == "2026-11-24T13:00:00Z" and r["ips"] == ["198.51.100.1"]
    ibm = eha.parse_received("from first.example.net ([198.51.100.2]) by mx.example.com for <r@example.com> from second.example.org; 24 Nov 2026 13:00:00 -0000")
    assert ibm["from"].startswith("first.example.net")  # only the first 'from' clause counts
    sendgrid = eha.parse_received("by filterdrecv-1 with SMTP id f-1 2026-11-24 13:00:00.480137614 +0000 UTC m=+1.523017659")
    assert sendgrid["date_utc"] == "2026-11-24T13:00:00Z" and sendgrid["by_host"] == "filterdrecv-1"
    exim = eha.parse_received("from [198.51.100.9] (helo=mail.example.net) by mx.example.com with esmtp (Exim 4.96) id 1abc; Tue, 24 Nov 2026 13:00:00 +0000")
    assert exim["ips"] == ["198.51.100.9"]
    assert eha.parse_email_date("Tue, 99 Zzz 2026 99:99:99 +9999") is None


# ------------------------------------------------------------------ C4: trust boundary
def test_trust_boundary(ok_result):
    trust = ok_result["trust"]
    assert (trust["status"], trust["originating_ip"], trust["boundary_hop"]) == ("ok", "198.51.100.25", 4)
    assert [h["trust"] for h in ok_result["hops"]] == ["unverified", "unverified", "unverified", "boundary", "internal", "internal"]


def test_trust_not_configured_and_fail_closed():
    r = eha.analyze_email(fb("ok.eml"))
    assert r["trust"]["status"] == "not_configured" and r["trust"]["originating_ip"] is None
    assert r["trust"]["originating_ip_unverified"] == "192.0.2.200" and {h["trust"] for h in r["hops"]} == {"unverified"}
    noip = (b"Received: from mx.evil.example by mx1.example.com with SMTP; Tue, 24 Nov 2026 13:00:00 +0000"
            b"\r\nReceived: from x (x [198.51.100.66]) by mx.evil.example; Tue, 24 Nov 2026 12:00:00 +0000"
            b"\r\nFrom: a@example.net\r\n\r\n")
    assert eha.analyze_email(noip, trusted_mta=["mx1.example.com"])["trust"]["status"] == "trusted_hop_without_ip"
    assert eha.analyze_email(noip, trusted_mta=["other.example.com"])["trust"]["status"] == "top_hop_untrusted"


def test_peer_names_never_extend_trust():
    data = (b"Received: from mx2.example.com (mx2.example.com [198.51.100.77]) by mx1.example.com; Tue, 24 Nov 2026 13:00:01 +0000\r\n"
            b"Received: from x ([192.0.2.9]) by mx2.example.com; Tue, 24 Nov 2026 13:00:00 +0000\r\nFrom: a@example.net\r\n\r\n")
    assert eha.analyze_email(data, trusted_mta=["mx1.example.com", "mx2.example.com"])["trust"]["originating_ip"] == "198.51.100.77"
    relay = eha.analyze_email(data, trusted_mta=["mx1.example.com", "mx2.example.com"], trusted_networks=["198.51.100.0/24"])
    assert relay["trust"]["originating_ip"] == "192.0.2.9"


# ------------------------------------------------------------------ C5: authentication results
def test_authentication_results_trusted_only_from_the_authserv_id(ok_result):
    auth = ok_result["auth"]
    assert (auth["spf"]["result"], auth["spf"]["asserted_by"], auth["spf"]["trusted"]) == ("softfail", "mx1.example.com", True)
    assert auth["dmarc"]["result"] == "fail" and auth["conflicts"] == ["spf", "dkim", "dmarc"]
    assert any(c["asserted_by"] == "relay.mailer.example.net" and not c["trusted"] for c in auth["claims"])
    claimed = eha.analyze_email(fb("ok.eml"))["verdict"]
    assert claimed["dmarc"] == "fail (claimed by mx1.example.com, not verified)"


def test_received_spf_fallback():
    data = (b"Received-SPF: Fail (mx1.example.com: domain of a@example.net does not designate 192.0.2.3)"
            b" receiver=mx1.example.com; client-ip=192.0.2.3;\r\nFrom: a@example.net\r\n\r\n")
    spf = eha.analyze_email(data, trusted_mta=["mx1.example.com"])["auth"]["spf"]
    assert spf["source"] == "received-spf" and spf["trusted"] and spf["result"] == "fail"


# ------------------------------------------------------------------ C6: sender findings
def test_sender_findings_and_tool_hints(ok_result):
    summary = ok_result["summary"]
    assert summary["from"] == "alerts@mailer.example.net"  # an RFC 2047 display name cannot hijack the sender
    assert summary["subject"] == "Ação necessária: verifique sua conta"
    types = [f["type"] for f in ok_result["findings"]]
    for t in ("reply_to_mismatch", "display_name_brand_spoofing", "display_name_embeds_other_domain", "spf_not_passing", "dkim_not_passing", "dmarc_not_passing"):
        assert t in types
    assert "return_path_mismatch" not in types  # same registrable domain (PSL)
    assert ok_result["tool_hints"][0]["family"] == "PHPMailer"


def test_brand_on_own_domain_is_not_spoofing():
    data = b"From: =?utf-8?q?Exemplo_Bank_Seguran=C3=A7a?= <alerts@example.com>\r\n\r\n"
    r = eha.analyze_email(data, org_domains=["example.com"], brands=["Exemplo Bank"])
    assert "display_name_brand_spoofing" not in [f["type"] for f in r["findings"]]


# ------------------------------------------------------------------ C7/C8: URLs and attachments
def test_body_urls_unwrapped_defanged_never_fetched(ok_result):
    urls = {u["kind"]: u for u in ok_result["urls"]}
    link = urls["link"]
    assert link["kinds"] == ["text", "link"]  # QP text/plain + base64 HTML merged
    assert link["unwrapped"] == [INNER_URL] and link["wrapper_host"] is True and link["recipient_token"] is True
    assert link["final_defanged"].startswith("hxxps://payout[.]example[.]org/")
    assert urls["image"]["tracking_pixel"] is True and all(u["fetched"] is False for u in ok_result["urls"])
    assert {"unc_or_file_path", "tracking_pixel", "html_form", "recipient_token"} <= {f["type"] for f in ok_result["findings"]}


def test_without_the_p064_helper_wrapped_urls_are_never_pivoted():
    r = eha.analyze_email(fb("ok.eml"), **ORG)  # unwrap=None: no second unwrapping implementation
    link = next(u for u in r["urls"] if "safelinks" in u["url"])
    assert link["final"] is None and link["unwrapped"] == [] and link["recipient_token"] is True
    assert "P064" in link["unwrap_note"]
    assert not any("safelinks" in str(p["value"]) for p in r["pivots"])


def test_attachments_hashed_in_memory_only(ok_result):
    (att,) = ok_result["attachments"]
    assert att["filename"] == "fatura.html" and att["size"] == len(ATTACHMENT)
    assert att["sha256"] == hashlib.sha256(ATTACHMENT).hexdigest() and att["md5"] == hashlib.md5(ATTACHMENT).hexdigest()


def test_broken_mime_body_still_scanned():
    hdr = fb("ok.eml").split(b"\r\n\r\n", 1)[0]
    r = eha.analyze_email(hdr + b"\r\n\r\nno boundary here, visit https://hidden.example.org/pay now\r\n")
    assert [u["url"] for u in r["urls"]] == ["https://hidden.example.org/pay"]
    assert "no decodable MIME part: raw body scanned as text" in r["defects"]


def test_malformed_header_fixture():
    r = eha.analyze_email(fb("malformed_header.eml"), trusted_mta=["smtp.example.com"])
    assert r["status"] == "ok" and r["defects"][0].startswith("malformed header line(s) 14")
    assert "StartBoundaryNotFoundDefect" in r["defects"] and any("fallback splitter" in d for d in r["defects"])
    assert [u["url"] for u in r["urls"]] == ["http://promo.example.org/?v=1fda4fa5605d"]  # hidden in base64
    assert [h["trust"] for h in r["hops"]] == ["unverified", "boundary", "local"]  # qmail stamp is local
    assert r["trust"]["originating_ip"] == "198.51.100.29"  # HELO 192.168.15.15 ignored


# ------------------------------------------------------------------ C10: privacy
def test_shareable_view_redacts_recipients(ok_result):
    shared = eha.shareable_view(ok_result)
    dump = json.dumps(shared)
    assert "local_only" not in shared
    for form in (RECIPIENT, "recipient%40example.com", base64.b64encode(RECIPIENT.encode()).decode()):
        assert form.lower() not in dump.lower()
    assert RECIPIENT in json.dumps(ok_result["local_only"])  # kept only in the local case


# ------------------------------------------------------------------ the module
def test_module_maps_the_analysis_to_contract_outputs():
    http = FakeHttp()
    res = run_module(MOD, f"file:{FX / 'ok.eml'}", http, settings=SETTINGS, org_profile=org_profile())
    assert res.status is Status.OK and http.calls == []  # nothing fetched, resolved or downloaded (C2)
    verdict = res.attributes["email_verdict"]
    assert verdict["from_vs_reply_to"] == "mismatch" and verdict["originating_ip"] == "198.51.100.25"
    assert verdict["spf"] == "softfail (asserted by mx1.example.com, trusted)"
    assert res.attributes["originating_ip"]["ip"] == "198.51.100.25"
    assert res.attributes["email_auth"]["dmarc"]["trusted"] is True
    assert [h["trust"] for h in res.attributes["received_hops"]] == ["unverified", "unverified", "unverified", "boundary", "internal", "internal"]
    titles = {f.title: f for f in res.findings}
    assert titles["Display name impersonates an organisation brand"].severity.label == "high"
    assert titles["Reply-To domain differs from From"].severity.label == "medium"
    assert titles["DMARC did not pass"].severity.label == "medium"
    assert titles["E-mail analysis verdict"].data["originating_ip"] == "198.51.100.25"
    assert all(f.criterion for f in res.findings)
    sent_from = [p for p in res.pivots if p.relation == "sent_from"]
    assert [p.entity.value for p in sent_from] == ["198.51.100.25"] and sent_from[0].confidence_label.value == "probable"
    relayed = {p.entity.value for p in res.pivots if p.relation == "relayed_by"}
    assert {"192.0.2.200", "203.0.113.99"} <= relayed and "10.20.30.5" not in relayed  # internal hops skipped
    senders = [p for p in res.pivots if p.relation == "sender_address"]
    assert {p.entity.value for p in senders} == {"alerts@mailer.example.net", "collect@payout.example.org", "bounce@mailer.example.net"}
    assert all(not p.expand for p in senders)
    hashes = [p for p in res.pivots if p.relation == "attachment"]
    assert {p.entity.type for p in hashes} == {T.SHA256, T.MD5} and all(not p.expand for p in hashes)
    assert not any("safelinks" in p.entity.value for p in res.pivots)  # wrapper hosts are noise


def test_recipients_and_reporters_never_leave_the_local_case():
    res = run_module(MOD, f"file:{FX / 'ok.eml'}", FakeHttp(), settings=SETTINGS, org_profile=org_profile())
    text = outputs(res).lower()
    for form in (RECIPIENT, "recipient%40example.com", base64.b64encode(RECIPIENT.encode()).decode().lower(), REPORTER):
        assert form.lower() not in text, form
    assert not any(p.entity.value == RECIPIENT for p in res.pivots)  # recipients are never pivoted
    assert RECIPIENT in res.raw["local_only"]["recipients"]  # local case evidence only (C10)
    assert "body" not in json.dumps(res.raw).lower() or "Prezado cliente" not in json.dumps(res.raw)  # no body text stored


def test_real_p064_helper_unwraps_the_safelinks_url():
    helper = eha._p064_unwrap()
    if helper is None:
        pytest.skip("the P064 url_unwrap helper is not importable in this tree")
    res = run_module(MOD, f"file:{FX / 'ok.eml'}", FakeHttp(), settings=SETTINGS)
    url = next(u for u in res.attributes["email_urls"] if u["wrapped"])
    assert url["unwrapped"] is True and url["recipient_token"] is True and url["url"].startswith("hxxps://payout[.]example[.]org/login")
    login = next(p for p in res.pivots if p.entity.type is T.URL and "payout.example.org/login" in p.entity.value)
    assert login.expand is False and RECIPIENT not in login.entity.value


def test_trust_boundary_not_configured_offers_an_unverified_candidate():
    res = run_module(MOD, f"file:{FX / 'ok.eml'}", FakeHttp())
    assert res.attributes["email_verdict"]["originating_ip_trust"].startswith("unverified candidate")
    candidate = next(p for p in res.pivots if p.relation == "sent_from")
    assert candidate.entity.value == "192.0.2.200" and candidate.confidence_label.value == "possible"
    assert "not configured" in next(f for f in res.findings if f.title == "E-mail analysis verdict").description


def test_text_blob_and_email_headers_inputs():
    text = fb("headers_only.txt").decode("utf-8")
    settings = {"email_header_analyzer_trusted_mta": ["mx.google.com"], "email_header_analyzer_trusted_networks": ["2001:db8:a05::/48"], "email_header_analyzer_authserv_ids": ["mx.google.com"]}
    blob = run_module(MOD, ("text_blob:" + text), FakeHttp(), settings=settings)
    assert blob.status is Status.OK and blob.attributes["originating_ip"]["ip"] == "2001:db8:4864:20::32"
    headers = run_module(MOD, ("email_headers:" + text), FakeHttp(), settings=settings)
    assert headers.status is Status.OK and headers.attributes["email_auth"]["dmarc"]["label"] == "pass (asserted by mx.google.com, trusted)"


def test_malformed_fixture_through_the_module():
    res = run_module(MOD, f"file:{FX / 'malformed_header.eml'}", FakeHttp(), settings={"email_header_analyzer_trusted_mta": ["smtp.example.com"]})
    assert res.status is Status.OK
    assert "Declared MIME boundary not found" in {f.title for f in res.findings}
    assert res.attributes["mime_defects"][0].startswith("malformed header line(s)")


def test_tlp_red_and_dead_network():
    res = run_module(MOD, f"file:{FX / 'ok.eml'}", DeadHttp(), tlp="red", settings=SETTINGS)
    assert res.status is Status.OK and res.hosts == {}


def test_metadata_matches_the_council_decision():
    assert MOD.disclosure == "none" and MOD.terms == "open" and MOD.default_enabled is True
    assert MOD.trust_tier == "n/a" and MOD.hosts == () and MOD.requires_packages == ()
