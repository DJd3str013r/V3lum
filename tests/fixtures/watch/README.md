# Watch-mode fixtures (WP26, P030)

`certstream_messages.jsonl`: one replayed CertStream message per line, `{"note", "raw"}` where `raw` is the
exact text the WebSocket delivers. The certificate messages keep the shape of the public
`certstream.calidog.io/example.json` sample (research C0009: message_type, data.leaf_cert.all_domains,
serial_number, issuer, not_before, source) trimmed to the fields watch reads (the SCT and key extensions
were removed). The names are fictional (`acmebank`), except the first certificate's public CT name
copied from the research sample; no personal data. Used by `tests/test_watch.py` through an injectable
replay transport and a fake clock (no network).
