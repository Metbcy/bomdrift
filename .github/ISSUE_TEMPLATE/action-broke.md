---
name: The action broke
about: bomdrift the GitHub Action failed in a non-obvious way.
labels: action-bug
---

## What happened

<!-- What were you trying to do? What did the action do instead? -->

## Workflow snippet

```yaml
<!-- paste the relevant `steps:` from your workflow file -->
```

## Failed run logs

<!-- Either paste the failed step's "Run bomdrift" group, or link to
the workflow run if the repo is public. The action emits all of its
internal output under `::group::` / `::endgroup::` markers; the
failure is usually obvious if you expand all groups. -->

```
<!-- paste output here -->
```

## What you've ruled out

<!-- Optional but speeds triage. Examples:
- [ ] `permissions: pull-requests: write` is set on the workflow
- [ ] The base ref + head ref both exist and have valid `Cargo.toml`
- [ ] `verify-signatures: false` doesn't change the outcome
- [ ] The workflow's YAML parses (e.g. `actionlint` clean)
-->

## Environment

- **bomdrift version pin**: `@v1` / `@v0.9.0` / `@<sha>`
- **Runner**: <ubuntu-latest / self-hosted / etc.>
- **Trigger event**: <pull_request / push / workflow_dispatch / etc.>
