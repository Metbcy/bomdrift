# Quickstart

## In a GitHub workflow (recommended)

The most common way to run bomdrift is the composite Action — drop it into
a `pull_request` workflow alongside an SBOM-generation step:

```yaml
# .github/workflows/sbom-diff.yml
name: SBOM diff
on: pull_request
permissions:
  contents: read
  pull-requests: write       # to upsert the diff comment
jobs:
  diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anchore/sbom-action@v0
        with: { path: ., output-file: after.json }
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.base.ref }}, path: base }
      - uses: anchore/sbom-action@v0
        with: { path: base, output-file: before.json }
      - uses: Metbcy/bomdrift@v1
        with:
          before-sbom: before.json
          after-sbom:  after.json
          fail-on:     critical-cve   # optional: exit 2 on HIGH/CRITICAL
```

The `@v1` mutable tag tracks the latest v0.x release. Pin to a specific
version (`@v0.3.0`) if you prefer reproducible builds. See
[GitHub Action](./github-action.md) for every input.

## Locally with the binary

Pre-built binaries cover Linux x86_64 + aarch64, macOS aarch64, and
Windows x86_64. Each archive is cosign-signed via Sigstore + GitHub OIDC.

```bash
VERSION=v0.3.0
TARGET=x86_64-unknown-linux-gnu
curl -sSL -o bomdrift.tar.gz \
  "https://github.com/Metbcy/bomdrift/releases/download/${VERSION}/bomdrift-${VERSION}-${TARGET}.tar.gz"
tar -xzf bomdrift.tar.gz
./bomdrift-${VERSION}-${TARGET}/bomdrift --version

# Diff two SBOMs
./bomdrift-${VERSION}-${TARGET}/bomdrift diff before.json after.json
```

To verify the archive's signature before you trust the binary, see
[Release signing](./release-signing.md).

## From source

```bash
cargo install --locked --git https://github.com/Metbcy/bomdrift --tag v0.3.0 bomdrift
```

Requires Rust 1.85+ (the project uses edition 2024).

## First diff

The repository ships four runnable example scenarios under `examples/`.
After cloning + `cargo build --release`:

```bash
./target/release/bomdrift diff \
  examples/axios-incident/before.json \
  examples/axios-incident/after.json \
  --no-osv --no-maintainer-age
```

The output is GitHub-Flavored Markdown ready for PR-comment posting.

## Next steps

- [GitHub Action](./github-action.md) — every input, common patterns.
- [CLI reference](./cli-reference.md) — every flag.
- [Output formats](./output-formats.md) — markdown / terminal / JSON / SARIF.
- [Baseline & suppression](./baseline.md) — adopt bomdrift on a project
  with pre-existing findings without drowning the first PR.
