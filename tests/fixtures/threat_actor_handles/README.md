# threat_actor_handles fixtures (P195)

* `forum_users_examplehub.txt`, `dead_forum_users_oldboard.txt`, `dnm_users_examplemarket.txt`: format-faithful
  SYNTHETIC lists (one handle per LF line, no header, sorted, lines starting with `#`, inner spaces, Cyrillic,
  digits-only and over-long lines as observed in the real lists on 2026-11-26). No real handle is stored: real list
  lines are handles of pseudonymous people (P195 cond 6).
* `crlf_bom.txt`, `malformed.bin`: line-format edge cases (BOM, CRLF, padding, invalid UTF-8, NUL).
* `readme_ok.md`: the real dataset README (MIT) trimmed to headings, file links, date ranges and amounts.
* `file_not_found.http.json`: the real 404 answer for a README-linked file (dead_forum_users_nohide_io.txt).
