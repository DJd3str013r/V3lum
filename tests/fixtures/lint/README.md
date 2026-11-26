# Lint fixtures (WP09, P327)

Inputs of `tests/test_lint.py`: one positive (`*_bad`) and one negative (`*_good`) snippet per
forbidden-capability rule (`LINT-01` ... `LINT-10`, see `v3lum.core.lint.LINT_RULES`), the pragma
example and data-file samples.

* `lintNN_bad.py.txt` / `lintNN_good.py.txt` - Python sources stored with a `.txt` suffix so the
  repository's own ruff run and pytest collection never pick them up; the test lints them with
  `lint.lint_module_source(path)` (and copies some into temporary trees as `.py` files).
* `pragma.py.txt` - an allowed issue (`# v3lum-lint: allow LINT-01 -- <justification>`) and a pragma
  without a justification (ignored).
* `sites_wmn_*.json`, `sites_maigret_bad.json` - username site lists in the WhatsMyName and Maigret
  formats (A5 rule 2: sign-up/availability/verification probes and submissions are rejected).
* `spec_*.json` - declarative specs ('v3lum.spec/1'): POST, people-search hosts, cookies and
  extracted password fields are rejected.
* `pack_*.json` - pivot packs ('v3lum.pivot_pack/1') linted through `links.lint_pack`.

Every host, handle and value is synthetic (`*.example`, documentation names).
