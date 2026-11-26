# Pivot-link packs (`v3lum.pivot_pack/1`, frozen in wave 1)

Manual pivot links are web tools without an API, pre-filled with an entity value. V3LUM **never fetches
them**; it renders them for the analyst (terminal, reports, `v3lum links`) and as the fallback when a
module is skipped or blocked (`Module.manual_link`). One file per pack:
`v3lum/data/pivot_links/<pack>.json`, loaded by `v3lum/core/links.py`.

```json
{
  "schema": "v3lum.pivot_pack/1",
  "pack": "core_reference",
  "title": "Core reference pivots",
  "links": [
    {
      "id": "shodan_host",
      "label": "Shodan host",
      "template": "https://www.shodan.io/host/{ip}",
      "entity_types": ["ipv4", "ipv6"],
      "category": "reputation",
      "host": "www.shodan.io",
      "verified": true,
      "checked_at": "2026-11-25",
      "privacy": false,
      "publishes": false,
      "touches_target": false,
      "login_required": false,
      "antibot": false,
      "notes": "..."
    }
  ]
}
```

| field | rule |
|---|---|
| `pack` | equals the file stem, `^[a-z][a-z0-9_]{1,63}$`; links are referenced as `'<pack>:<id>'` |
| `id` | `^[a-z][a-z0-9_]{1,63}$`, unique in the pack |
| `label` | single line, at most 120 characters |
| `template` | `https://<host>/...` with whitelisted placeholders in the path, query or fragment only |
| `entity_types` | entity type values (`EntityType`), never `cpf`, secrets, `text_blob`, `file` or `email_headers` |
| `category` | `reputation` `history` `passive_dns` `code_paste` `social` `company` `crypto` `geo` `search` `other` (the analyst questions links are grouped by) |
| `host` | the exact lower-case host of the template (who receives the value, the disclosure target) |
| `verified` / `checked_at` | verified links record the check date `YYYY-MM-DD`; unverified links get the badge `unverified` |
| `privacy` | `true` for templates carrying personal values (person, phone, e-mail, handles...) or CNPJ / EU VAT |
| `publishes` | must be `false` (team rule 7) |
| `touches_target` | `true` when opening the link contacts the target or makes a third party fetch it live (rendered defanged and non-clickable) |
| `login_required` | must be `false` (team rule 1) |
| `antibot` | the page has an anti-bot/CAPTCHA wall: manual opening only, never automated |
| `notes` | free text; extra keys must start with `x_` |

## Placeholders (whitelist; substituted with `re.sub`, never `str.format`)

| placeholder | value | types |
|---|---|---|
| `{q}` `{qp}` `{raw}` | value percent-encoded / form-encoded / as is (unsafe characters encoded; `{raw}` only once, at the very end of the path, in a template without query or fragment, so a value can never inject query parameters) | any |
| `{b64}` `{b64url}` | base64 (percent-encoded) / URL-safe base64 without padding | any |
| `{domain}` | domain itself, e-mail domain, URL host | domain, url, email, onion |
| `{idn}` `{punycode}` | Unicode / ASCII form of that domain | domain, url, email |
| `{user}` | e-mail local part, username, social/telegram/fediverse/bsky/steam handle | those types |
| `{e164}` `{e164_plus}` `{wa}` | `5511987654321` / `%2B5511987654321` / wa.me digits | phone |
| `{br_national}` `{br_national_no9}` | DDD + number with / without the mobile 9 | phone (+55) |
| `{cnpj_fmt}` `{cnpj_digits}` `{cnpj_root}` | `00.000.000/0001-91` (encoded) / 14 characters / 8-character root | cnpj |
| `{ip}` | the IP address | ipv4, ipv6 |
| `{asn_num}` | AS number without `AS` | asn |

## Lint (CI: `links.errors() == []`, `links.lint_pack(data, source=...)`)

* https only; template host == declared host; no userinfo, no explicit port; known placeholders and
  types; type-restricted placeholders only for their types; at least one placeholder;
* no CPF template ever (team rule 4, AR24); `publishes` and `login_required` false; no `scan_trigger`;
* no submission/scan/publish endpoints (urlscan scan API, VirusTotal upload/scan, web.archive.org/save,
  archive.today submit, public recent-searches boards) and no people-search, 'painel', CPF-lookup or
  leaked-database hosts: `v3lum.core.lint.forbidden_probe()` (LINT-03/04/05) runs on every template;
* hosts whose provider is flagged `publishes_queries` are rejected (rule 7);
* PERSONAL_TYPES, CNPJ and EU VAT templates need `privacy: true` and a host owned by a **trusted or
  community** provider in the provider registry (`v3lum/data/providers/`); an unregistered host is
  `unknown` and rejected (A8 BR4);
* unknown-tier hosts receive **IOC_TYPES values only** (A8): a template to an unregistered/unknown host
  that accepts any other type (`company_name`, `keyword`, `malware_family`, `card_bin`...) is rejected.
  IOC-only links to unknown-tier hosts are allowed and carry the badge `unknown operator`;
* `checked_at` is a real calendar date; `notes` is a string.

Links with problems are dropped (fail closed) and listed by `links.errors()`; a pack whose `schema` is
missing (and that is not a legacy pack) is not loaded at all. Legacy items
`{name, types, url, category, description, source}` (a list, or `{"links": [...]}` without `schema` whose
items all use `url`) are migrated on load: name -> label, types -> entity_types, url -> template, host
from the URL, verified false.

## Rendering rules (`links.render`, `pivot_links_for`, `links_for`, `render_manual`)

* CPF, secrets, blobs and files are never rendered; personal/company values render only through privacy
  links to trusted/community hosts, and `privacy` links appear only with `include_privacy=True` (callers
  pass it for analyst-typed seeds of a case that opted in, never for auto-discovered entities);
  `render_manual(manual_link, entity, *, include_privacy=False)` follows the same opt-in;
* unknown-tier hosts only ever receive IOC_TYPES values;
* a `PivotLink` built by a caller (not loaded from a pack) is validated and linted like a pack link
  before it renders, and its tier is read from the provider registry (a claimed tier is ignored);
* an inline `Module.manual_link` template may have no placeholder (a search form behind an anti-bot
  wall, where the analyst types the value); pack templates always carry one;
* every rendered URL is re-checked (https, declared host, no userinfo/port);
* `pivot_links_for` returns verified links first; `links_for` is the legacy `(label, url)` view without
  privacy links;
* TLP rendering (non-clickable text with "opening sends <value> to <host>" at AMBER and above, hidden
  third-party links at RED), ranking and the case page are done by the renderers (waves 3-4).
