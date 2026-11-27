# IOC extraction corpus (P172 cond 12)

Trimmed, sanitised excerpts used by `tests/test_ioc_corpus.py` to measure the precision and recall
of `v3lum.core.ioc.extract` against hand-written expected entity lists (`expected.json`).

* `cti_report_excerpt.txt` - CTI report prose in the style of public vendor write-ups (Log4Shell,
  Citrix Bleed, a loader campaign): defanged URLs, documentation IPs, EICAR test hashes, CVE and
  ATT&CK ids, public example wallets and the DuckDuckGo onion; version numbers, file names and
  dates that must NOT be extracted.
* `phishing_email.eml` - a phishing e-mail: header block (recipients must not be listed), a
  safelinks-wrapped link, a base64-encoded link, a tracking pixel and an HTML-entity link.
* `ptbr_sms_whatsapp.txt` - a PT-BR SMS/WhatsApp scam text with personal data replaced: national
  phone formats, wa.me / t.me / discord / instagram links, a test card number, a CPF (masked, never
  an entity) and a CNPJ with a valid check digit.
* `analyst_notes.txt` - analyst notes mixing code (`self.name`, `os.path`), versions, times, a MAC,
  IPv6/CIDR and a pasted token that must come out as a fingerprint only.

Every value is synthetic, a documentation value (RFC 5737/3849 addresses, `example.*` names) or a
public test value (EICAR, the Visa test PAN, the example CPF 111.444.777-35). Nothing here is
ever resolved or fetched.
