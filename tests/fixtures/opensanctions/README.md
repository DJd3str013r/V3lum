# opensanctions fixtures (batch p3-G10-1, P222)

* `bulk_index.json` - research capture of `data.opensanctions.org/datasets/latest/default/index.json`
  (2026-11-25, version 20261125185440-ckr), trimmed: children/datasets lists cut to five, resources kept.
  Metadata only (titles, sizes, SHA-1 checksums), no screening data.
* `bulk_index_redirect.http.json` - live 2026-11-26 HEAD answer: 307 to the versioned artifact.
* `targets_simple_sample.csv` - the real `targets.simple.csv` header (research range request) with
  **synthetic rows only** (documentation values): the real rows are CC BY-NC 4.0 data and are never committed
  (A6); a capture made with the company's bulk data licence replaces this file before enabling (P222 cond 9).
