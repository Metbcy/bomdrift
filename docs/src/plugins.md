# Plugins

bomdrift's enricher set is intentionally curated — typosquats,
maintainer age, registry metadata, OSV/EPSS/KEV. Org-specific signals
(banned packages, license-tier policies, internal package allowlists)
don't belong in the binary, but they need a first-class extension
point. v0.9.6 ships that extension point as **external-process
plugins**.

## Overview

A plugin is an executable on the filesystem (any language, any shape
of dependencies) that reads a JSON envelope from stdin and writes a
JSON envelope to stdout. bomdrift invokes it once per matching
component during a diff. Findings the plugin emits are merged into
bomdrift's output across every render path: terminal, markdown, JSON,
SARIF.

Plugins are **not** a sandbox. They run as your CI user with the
same filesystem and network access bomdrift itself has. Treat plugin
source the same way you'd treat any external CI script.

## Why external-process and not WASM

The original v0.4 sketch on the roadmap floated WASM. v0.9.6
deliberately picks shell-out instead:

- **Smaller dep tree.** No wasmtime / wasmer pulled into the
  bomdrift binary. The dep-tree audit is a real OSS-first
  constraint.
- **Any language.** Plugins write Bash, Python, Go, Rust, whatever.
  WASM would force a per-language toolchain.
- **Sandboxing is the user's environment.** CI runners already
  isolate per-job. Adding WASM-level sandboxing inside an already
  isolated container is duplicate effort for marginal value.
- **Failure isolation is cheap.** A child-process crash can't take
  bomdrift down; we already get that for free from the OS.

WASM may revisit in v1.0+ if a clear need materializes (in-browser
diffing, multi-tenant CI without per-job isolation). For now, the
shell-out model wins on simplicity and dep cost.

## Manifest format

A plugin manifest is a TOML file pointed at by `--plugin <path>`.
The flag is **repeatable** — bomdrift loads each manifest in
declaration order and runs all matching plugins per component.

```toml
[plugin]
name        = "my-plugin"
description = "What this plugin checks for"
exec        = "./run.sh"
timeout_ms  = 5000
invoke_on   = ["added", "version-changed"]
```

### Fields

| Field         | Type        | Required | Default | Notes |
|---------------|-------------|----------|---------|-------|
| `name`        | string      | yes      | —       | Unique within a single bomdrift run. Used in error messages and SARIF rule IDs. |
| `description` | string      | no       | —       | Free-form. Surfaced when bomdrift logs plugin failures. |
| `exec`        | string      | yes      | —       | Path to the executable, **resolved relative to the manifest directory**. Use `./` prefix to make this explicit. Absolute paths are accepted. |
| `timeout_ms`  | integer     | no       | `5000`  | Wall-clock timeout per invocation. After expiry the process is killed and the invocation's findings are dropped. |
| `invoke_on`   | string list | yes      | —       | Subset of `["added", "version-changed"]`. Future versions may add `removed`, `license-changed`, `maintainer-changed`. Unknown values are rejected at load time. |

`exec` must be marked executable on disk. bomdrift does **not**
auto-`chmod +x`; this would mask permission bugs.

## Protocol — stdin/stdout JSON shape

bomdrift writes one JSON object on the plugin's stdin, closes
stdin, and reads exactly one JSON object from stdout (parsing the
**last** complete JSON object on stdout — earlier output is treated
as plugin log noise and discarded silently, but plugins shouldn't
rely on this). The plugin should write its findings JSON and exit
promptly.

### Stdin

```json
{
  "component": {
    "purl":     "pkg:npm/foo@1.2.3",
    "name":     "foo",
    "version":  "1.2.3",
    "licenses": ["MIT"]
  },
  "event":  "added",
  "before": null
}
```

- `component` — the **after** component. Always present.
- `event` — `"added"` or `"version-changed"`. Matches the manifest's
  `invoke_on` filter.
- `before` — `null` for `added`, the **before** component (same
  shape as `component`) for `version-changed`.

Unknown fields may appear in future bomdrift versions. Plugins
**must ignore unknown fields** on stdin and not assume the input
shape is closed.

### Stdout

Exactly one JSON object on a single line (newline-terminated is
fine; multi-line pretty-printed JSON is also accepted as long as
it's a single value):

```json
{
  "findings": [
    {
      "kind":     "your-finding-tag",
      "message":  "human-readable description",
      "severity": "info",
      "rule_id":  "stable.id.for.this.kind"
    }
  ]
}
```

| Field       | Type   | Required | Notes |
|-------------|--------|----------|-------|
| `kind`      | string | yes      | Free-text tag. Surfaced in the markdown/terminal renderers as the finding category. Keep it short and stable. |
| `message`   | string | yes      | One-line human-readable description. |
| `severity`  | string | yes      | One of `"info"`, `"warning"`, `"error"`. Maps to SARIF `level` as `note` / `warning` / `error`. |
| `rule_id`   | string | yes      | Stable identifier for this **class** of finding. Used in SARIF `partialFingerprints`; should be the same across runs for the same logical finding so dedup works. |

An empty findings array is the no-match path:

```json
{"findings": []}
```

### SARIF mapping

All plugin findings render under a single SARIF rule:
`bomdrift.plugin`. The plugin's `rule_id` is threaded into the
SARIF result's `partialFingerprints` so that GitHub Code Scanning
and similar consumers can dedup runs of the same finding.

## Failure semantics

Plugins are **best-effort**. Their failures never fail the bomdrift
diff:

| Failure mode                         | bomdrift response                                          |
|--------------------------------------|------------------------------------------------------------|
| Plugin exits non-zero                | Drop findings from this invocation. Log warning if `BOMDRIFT_DEBUG=1`. |
| Wall-clock timeout (`timeout_ms`)    | Kill the process. Drop findings. Log warning if `BOMDRIFT_DEBUG=1`. |
| Stdout is not parseable JSON         | Drop findings. Log warning if `BOMDRIFT_DEBUG=1`.          |
| Stdout JSON is missing `findings`    | Drop findings. Log warning if `BOMDRIFT_DEBUG=1`.          |
| `findings[i].severity` is unknown    | Drop that finding. Other findings in the same invocation pass through. |
| Plugin exec is missing on disk       | Manifest load fails fast (before any diff work). Exit 1.   |

The contract: the rest of the bomdrift report still renders. A bad
plugin is a noisy plugin, not a broken pipeline. Run with
`BOMDRIFT_DEBUG=1` while authoring a plugin to see why findings are
being dropped.

### Windows note

On Windows, `Command::kill()` has known quirks where killed
processes may leave orphan grandchildren. bomdrift kills the direct
child cleanly; if your plugin spawns sub-processes, ensure it
forwards the timeout signal itself. Plugin timeouts on Windows are
**best-effort** in v0.9.6.

## Worked example: `banned-packages`

The reference implementation lives in
[`examples/plugins/banned-packages/`](https://github.com/Metbcy/bomdrift/tree/main/examples/plugins/banned-packages):

```
examples/plugins/banned-packages/
├── README.md          # how to adapt for your org
├── plugin.toml        # the manifest below
├── check-banned.sh    # bash + jq implementation
└── banned.txt         # purl prefixes to flag
```

`plugin.toml`:

```toml
[plugin]
name        = "banned-packages"
description = "Flag dependencies on the org-maintained banned-packages list"
exec        = "./check-banned.sh"
timeout_ms  = 5000
invoke_on   = ["added", "version-changed"]
```

Invocation:

```bash
bomdrift diff before.cdx.json after.cdx.json \
  --plugin examples/plugins/banned-packages/plugin.toml
```

See the example's [README](https://github.com/Metbcy/bomdrift/blob/main/examples/plugins/banned-packages/README.md)
for adaptation guidance, performance characteristics, and security
notes.

## Performance

bomdrift invokes plugins **sequentially**, once per matching
component. With `N` Added/VersionChanged components and `P`
plugins, you'll see `N × P` invocations. Implications:

- **Process-startup cost matters.** A bash plugin that forks `jq`
  ten times costs ~30 ms of fork + interpreter warmup per call.
  At `N = 200, P = 3` that's ~18 s of pure startup overhead.
  Compile to a static Go/Rust binary if hot-path performance
  matters.
- **Tune `timeout_ms`.** The default (`5000`) is generous for
  pure-CPU plugins; a plugin that hits a network endpoint per
  component might need `30000`. A plugin that's intermittently
  slow ruins your CI cycle time — consider sampling inside the
  plugin (return early for components that don't match its
  scope).
- **No parallelism in v0.9.6.** Concurrent plugin execution is on
  the table for v1.0 if a meaningful workload demands it. File an
  issue with timing data if you hit this.

## Security

bomdrift does **not** sandbox plugins:

- Plugins run as the bomdrift parent's user.
- Plugins inherit the parent's environment (including secret-bearing
  env vars like `GITHUB_TOKEN`, `NPM_TOKEN`, etc.).
- Plugins inherit the parent's filesystem and network access.
- Plugins can spawn arbitrary sub-processes.

Treat plugin source like any external CI script:

- **Vet what you ship.** Read the plugin source, including any
  binary dependencies it pulls in.
- **Pin to a commit / tag.** Don't `curl ... | bash` an
  always-latest plugin executable.
- **Minimize the env.** If a plugin doesn't need a secret, don't
  let it inherit one. `env -i bomdrift diff ...` strips the
  environment; manually re-export only what bomdrift itself needs.
- **Mirror internally.** For high-trust pipelines, vendor the
  plugin into your own repo or internal artifact store rather
  than pulling from a public registry on every CI run.

## Stability promise

The plugin protocol's stdin/stdout JSON shape is **best-effort
stable in v0.9.6**:

- We may **add** fields to the stdin envelope in a future minor
  release. Plugins must ignore unknown fields.
- We will **not remove or rename** documented stdin or stdout
  fields without a major version bump.
- The stdout `findings` schema is the public contract; treat
  `kind`, `message`, `severity`, `rule_id` as semver-stable.
- The TOML manifest schema may grow new optional fields; existing
  fields stay.

If the protocol needs a breaking change for v1.0, every plugin
invocation already carries `protocol_version: 1` on the stdin
envelope, so a future bomdrift release can detect old plugins and
keep them working through a deprecation window.

## CI integration

A typical GitHub Actions job that wires in a plugin:

```yaml
jobs:
  bomdrift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Make sure jq is available if your plugin needs it.
      - run: sudo apt-get install -y jq

      - uses: Metbcy/bomdrift@v1
        with:
          before-sbom: before.cdx.json
          after-sbom:  after.cdx.json
          extra-args:  --plugin examples/plugins/banned-packages/plugin.toml
```

For multiple plugins, repeat `--plugin` in `extra-args`:

```yaml
extra-args: >-
  --plugin .bomdrift/plugins/banned-packages/plugin.toml
  --plugin .bomdrift/plugins/license-tier/plugin.toml
```

## Related

- [`examples/plugins/banned-packages/`](https://github.com/Metbcy/bomdrift/tree/main/examples/plugins/banned-packages) — worked reference.
- [SARIF + Code Scanning](./sarif.md) — how `bomdrift.plugin`
  findings appear in Code Scanning.
- [Roadmap](./roadmap.md) — design rationale for shipping plugins
  in v0.9.6.
