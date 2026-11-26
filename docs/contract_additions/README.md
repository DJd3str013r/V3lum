# Module-contract additions after the freeze

`docs/MODULE_GUIDE.md` (module contract v2) was frozen at the end of wave 1 (A16). After the freeze
the contract only **grows**: later packages may add names, never rename them or change their
behaviour. Each package that adds module-facing names documents them here, in its own file:

```
docs/contract_additions/<package>.md      e.g. WP09.md, WP11.md, WP17.md
```

## Content of a file

```markdown
# Contract additions - <package> (wave <n>)

| name | kind | since | summary |
|---|---|---|---|
| `v3lum.core.sanitize.scrub_text` | function | wave 2 | removes combo lines and masked hints from free text |

## Details
<one short section per name: signature, semantics, an example, the test that covers it>
```

Rules:

* additions only: a file never redefines a name of the frozen guide or of another package's file;
  a behaviour change needs an architect-approved migration recorded in the guide itself;
* every name is importable (`v3lum.<module>.<name>`) in the change that adds its file, and is
  covered by that package's tests;
* names announced in the guide's "Arriving later" table move here when they land (expected:
  `sanitize.scrub_text` and the lint API (WP09), `ctx.net.run_tool` with `core/tools.py` ToolSpec
  (WP11), `ioc.extract` and the aliases index (WP17), data rules `v3lum.rule/1` (WP22),
  `tls.check_interception` (WP25), the watch-source invocation (WP26)).
