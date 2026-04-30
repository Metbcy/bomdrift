# `banned-packages` — worked plugin example

A reference [bomdrift plugin](../../../docs/src/plugins.md) that flags
any Added or VersionChanged dependency whose purl matches a
prefix in a maintained denylist file.

## What it does

For each component bomdrift sees as **added** or **version-changed**
during a diff, the plugin:

1. Reads bomdrift's JSON envelope on stdin.
2. Extracts `component.purl`.
3. Checks each non-comment line of `banned.txt` as a **purl prefix**.
4. For every match, emits a `banned-package` finding with severity
   `error`.

A versionless prefix like `pkg:npm/event-stream` flags every version
of the package; a versioned prefix like `pkg:npm/coa@2.0.3` only
flags that exact release.

## Files

| File              | Purpose                                              |
|-------------------|------------------------------------------------------|
| `plugin.toml`     | Manifest bomdrift loads with `--plugin`.             |
| `check-banned.sh` | The plugin executable. Bash + `jq`.                  |
| `banned.txt`      | Sample denylist with `#` comments. **Replace this.** |

## Adapting for your org

1. Replace the contents of `banned.txt` with your curated list. One
   purl prefix per line; `#` comments and blank lines ignored.
2. (Optional) Modify `check-banned.sh` to source the list from a URL
   (`curl ... | sponge banned.txt` in CI) or to honor a different
   `severity` per-entry.
3. Vendor or copy the directory into your repo and reference it from
   your bomdrift workflow.

## Wiring into a bomdrift run

```bash
bomdrift diff before.cdx.json after.cdx.json \
  --plugin path/to/banned-packages/plugin.toml
```

A matching ban shows up in every output format: terminal, markdown
PR comment, JSON, and SARIF (under the `bomdrift.plugin` rule, with
`partialFingerprints` set from the finding's `rule_id`).

### GitHub Actions example

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    extra-args: --plugin examples/plugins/banned-packages/plugin.toml
```

## Performance

The plugin is invoked **once per Added or VersionChanged component**.
With N changed components and M lines in `banned.txt`, the cost is
O(N×M) prefix comparisons. Bash + jq is fine for `M < 1000` and
`N < 500`; for larger denylists, rewrite the executable in a faster
language (Go, Rust, Python) — the plugin protocol is identical.

If your denylist is fetched from a network source, raise
`timeout_ms` in `plugin.toml` accordingly.

## Security

bomdrift does **not** sandbox plugins. `check-banned.sh` runs as
your CI user with whatever filesystem and network credentials that
user has. Vet plugin source (including this example) the same way
you'd vet any external script: read it, pin a commit, mirror it
internally if you need supply-chain isolation.

## Smoke test

```bash
echo '{"component":{"purl":"pkg:npm/event-stream@4.0.0","name":"event-stream","version":"4.0.0"},"event":"added","before":null}' \
  | ./check-banned.sh
# → {"findings":[{"kind":"banned-package", ... "rule_id":"banned-packages.pkg.npm.event.stream"}]}
```

A purl that matches no prefix returns `{"findings":[]}`.
