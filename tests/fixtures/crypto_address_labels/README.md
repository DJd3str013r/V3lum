# Fixtures of crypto_address_labels (P358, batch p2-G09-3)

Minimised from the prep material of the batch (recorded 2026-11-26), no personal data:

| file | origin |
|---|---|
| `tagpack_*.yaml`, `actorpack.yaml` | graphsense/graphsense-tagpacks @ 507756d2a8ad0a60d148ee2fe56bf559a747f250 (MIT): header verbatim + selected tag blocks verbatim (exchange-wallets-binance, exchange-wallets-okx (live raw GET), ofac, aidecisions_ofac (organisations only), ransomware, etherscamdb_tagpack, hacks, usdt_blacklist, etherscan-wordcloud-exchange, defi_updated/defi-protocols_1inch, plustoken (its checksum-failing tags), demo (no tags)); `tagpack_truncated.yaml` is derived (a cut transfer) |
| `parsed/*.json` | `yaml.safe_load` result of each YAML file (PyYAML 6.0.3; dates as ISO strings; `{"ok": false, "error"}` when PyYAML refuses the text) |
| `archive_ok.zip` | derived: the YAML files above packed like a codeload/git-archive zip (top folder `graphsense-tagpacks-master/`, commit id as zip comment, commit time as member mtime, LICENSE/README/workflow members ignored by the module) |
| `archive_blocked_egress_403.json` | live 2026-11-26: the egress proxy's 403 JSON answer to the archive URL |
| `por_okx.csv` | OKX's documented PoR file format (github.com/okx/proof-of-reserves example), minimised; the staking row's validator key is synthetic |
| `por_generic.csv` | derived from Binance's 2022 published reserve wallets (public exchange addresses) |
| `por_okx_page.html` | live 2026-11-26: OKX PoR page (server-side rendered, no address data), minimised |
| `por_binance_blocked_202.json` | research 2026-11-25: Binance PoR page answering 202 with an empty body (bot interstitial) |
| `team_labels.json`, `team_labels_invalid.json` | synthetic team label files: fictional institutions, documentation addresses (BIP-173 example, private-key-1/2 test vectors), example.com/example.org contacts, example CNPJ 11.222.333/0001-81, placeholder CPF/name/e-mail that the parser must drop |
