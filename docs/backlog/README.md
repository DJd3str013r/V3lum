# Backlog fragments

Module contract v2, section 19 and rule A16: every rejected, deferred, P3 or unimplemented item is
recorded with its reason and the condition that would unblock it (legal preconditions included).
Packages and module batches do not edit a shared backlog file: each writes its own fragment here and
the backlog tool (wave 5, WP29: `python -m v3lum.tools.backlog`) assembles `BACKLOG.md` from them.

## File

`docs/backlog/<package_or_batch>.md` - one file per package (`WP06.md`, `core.md`...) or module batch
(`G03-light.md`...). A package that has nothing deferred writes no file.

```markdown
# Backlog - <package or batch id>

| item | reason | unblock condition |
|---|---|---|
| P332 multi-seat keys | one key per provider (P332 veto_lift 1-2) | a provider whose terms grant seats + a legal_dpo decision |
| <proposal id / module / feature> | <why it is not implemented now> | <what must happen first: licence, dataset, council decision...> |
```

Rules:

* exactly the three columns `item`, `reason`, `unblock condition`, one row per item;
* cite the decision (proposal id, A-rule, council reference) in `reason`;
* legal preconditions (licence, provider grant, `personal_data_review`) go in the unblock condition;
* rows are added or closed by the owning package only; a closed row is deleted in the change that
  implements the item.
