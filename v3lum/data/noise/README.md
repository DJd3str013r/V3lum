# Noise and warning lists (`v3lum.noise/1`)

Benign, ubiquitous infrastructure is recorded in the graph but never pivoted on (AR06). The core
lists are built into `v3lum/core/noise.py`; every other list is a data fragment in this directory.
`core.json` (schema `v3lum.noise_kinds/1`) documents the kinds and is not a list.

## Fragment format

```json
{
  "schema": "v3lum.noise/1",
  "kind": "sinkhole",
  "name": "example_sinkholes",
  "source": "https://example.org/sinkhole-list (commit or date)",
  "licence": "CC0-1.0",
  "description": "optional one-liner",
  "domains": ["sinkhole.example.org"],
  "ips": ["192.0.2.10"],
  "cidrs": ["198.51.100.0/24"]
}
```

* `kind`: `cdn | cloud | resolver | webmail | hosting | saas | sinkhole | parked | benign_scanner | warninglist`.
* `name`: optional (defaults to the file stem) except for `warninglist` fragments, which must name
  their list (the name appears in findings: `POSSIBLE - on warninglist <name>`).
* `source` and `licence` are required. Only permissive data is bundled and the licence is checked
  against an allow-list (A6): MIT, BSD, Apache-2.0, CC0, CC BY 4.0, public domain / public data (a
  trailing parenthesised note such as `CC0-1.0 (MISP warninglists)` is fine). Anything else -
  GPL/LGPL/AGPL, CC BY-SA or any share-alike, ND, NC, ODbL, MPL, unknown or proprietary terms - is
  rejected: ship such lists as runtime datasets instead.
* Domains match the host and its parent domains down to the PSL registrable domain (never above:
  `evil.github.io` is not noise because of `github.io`). A leading `*.` is accepted and ignored.
* Malformed fragments, unknown keys and invalid entries are reported by `noise.errors()` (the registry
  contract test requires none); they never raise.

## Semantics

* `is_noise(entity)`: domains, IPs and **bare-host** URLs only. A URL with a path other than `/` or
  with a query is never noise, so phishing on Google Forms, SharePoint, GitHub Pages... is
  investigated; `noise.legit_platform(url)` names the platform (`PLATFORM_HOSTS`) and the engine tags
  the URL `hosted_on_legit_platform`.
* `noise_kind(entity)` returns the most informative kind (`sinkhole` > `parked` > `benign_scanner` >
  `resolver` > `webmail` > `cdn` > `cloud` > `hosting` > `saas` > `private`); `is_sinkhole`,
  `is_parked` and `is_cdn` (cdn/cloud/hosting/saas) test single kinds.
* `warninglist` lists are not noise: `noise.warninglists(entity)` returns the names of the matching
  lists; the engine lists those values without auto-pivoting and downgrades their malicious findings.

## Runtime lists (dataset-backed)

Large or non-permissive lists (e.g. the MISP warninglists of the P169 batch) are downloaded at
runtime. The module file that registers the dataset also registers the list at import time:

```python
from v3lum.core.datasets import register_dataset
from v3lum.core import noise

register_dataset("misp_wl_public_dns_v4.json", "https://raw.githubusercontent.com/MISP/misp-warninglists/<commit>/lists/public-dns-v4/list.json",
                 licence="CC0-1.0", terms_class="open", source="misp_warninglists.public_dns", expect="json")
noise.register_list("public_dns_v4", dataset="misp_wl_public_dns_v4.json", fmt="misp_warninglist",
                    description="MISP: public DNS resolvers (IPv4)")
```

`fmt`: `misp_warninglist` (types `cidr`, `hostname`, `string`, `substring`), `lines` (one value per
line) or `cidrs` (one network per line); `kind` defaults to `warninglist` (another kind makes the list
count for `is_noise`). Lists load lazily from the local copy and are never downloaded by the noise
module: while the dataset is missing the list is not applied and `noise.errors()` says
`run v3lum data update <dataset>`.
