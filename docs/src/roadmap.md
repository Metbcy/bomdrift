# Roadmap

What's planned, what's deliberately out of scope, and what the
acceptance criteria for new contributions look like.

## Planned

The list below is intentionally short — bomdrift is small on purpose.
Items are grouped by likely v0.4+ landing and rough sizing.

### v0.5 candidates (not committed)

- **GraphQL maintainer-age** — was investigated for v0.4 and deferred.
  The current REST implementation already uses `?per_page=1` + Link-header
  parsing for top contributor and contributor count. The remaining
  round-trip cost is the per-author commit-history pagination, and
  GitHub's GraphQL `history()` connection doesn't expose ASC ordering —
  finding the oldest commit still requires cursor pagination. v0.5 may
  approach this via `User.contributionsCollection` or accept that REST
  is the right tool here.
- **Custom rules / plugin system** — let consumers add
  organization-specific enrichers (e.g. "flag any dep from
  internal-mirror.example.com without a SHA-256 attestation").
  Probably WASM-based for sandboxing.
- **GitLab CI integration** — same `bomdrift diff` invocation, but
  with a wrapper that posts to GitLab merge-request notes instead of
  PR comments. The CLI is already CI-agnostic; this is glue + docs.
- **OCI artifact attestation** — verify SBOMs are themselves signed
  by the build system before diffing. Pairs with cosign attest.
- **Diff-stat threshold flags** — `--fail-on-added <N>`,
  `--fail-on-removed-from-allowlist <file>`. Useful for governance
  workflows.

### Calibration backlog

These are tunable thresholds where the v0.3 default may not be the
right answer at scale. Adjusting requires real-world signal data, so
they're tracked as "watch the false-positive rate":

- Typosquat `SIMILARITY_THRESHOLD` (currently 0.92).
- Maintainer-age `YOUNG_MAINTAINER_DAYS` (currently 90).
- OSV severity cache TTL (currently 24h).

## Non-goals

These are **explicit non-goals**. Don't open a PR for them — it'll be
declined.

### SBOM generation

bomdrift only **consumes** SBOMs. Use [Syft](https://github.com/anchore/syft)
to generate them — it's already excellent and bomdrift's contribution
would be net-negative.

### Replacing your SCA scanner

OSV-scanner, Grype, Trivy all have richer vulnerability databases and
broader package metadata than bomdrift. **bomdrift's CVE enrichment is
change-focused**: only on what's *new* in this diff. If you want
"what's in my SBOM right now?", run an SCA scanner. If you want "what
changed in this PR's deps that I should worry about?", that's
bomdrift's question.

### Dependency-tree visualization

[`cargo tree`](https://doc.rust-lang.org/cargo/commands/cargo-tree.html),
[`pnpm why`](https://pnpm.io/cli/why), and ecosystem-specific
equivalents handle this well. bomdrift's diff core could in principle
walk the `dependencies` / `relationships` arrays from the source
SBOM, but it's outside the "what's risky" scope.

### Per-language deep parsing

bomdrift treats SBOMs as the source of truth for what's installed.
Walking `package-lock.json` / `Pipfile.lock` / `Cargo.lock` directly
would let us catch things SBOMs miss (lockfile drift), but doubles
the parser surface for marginal signal — and the SBOM-generation
ecosystem is converging fast enough that this won't matter in 18
months.

### Web UI / dashboard

bomdrift is intentionally a CI tool. Long-running stateful
dashboards (org-wide vuln tracking, exception management UI) are
better served by tools designed for that — Anchore Enterprise,
Snyk, etc. The PR comment is the UX.

## Contribution acceptance criteria

A new enricher / output format / parser PR should:

1. **Pass `cargo clippy --all-targets --all-features -- -D warnings`**
   on its own. The codebase is clippy-clean and we keep it that way.
2. **Add unit tests** in `src/<your-module>/tests` covering the
   happy path + at least one edge case. Best-effort enrichers should
   test the network-failure path (via fake fetcher injection).
3. **Add an end-to-end test** in `tests/cli.rs` if it's CLI-visible,
   or `tests/integration.rs` if it's library-internal.
4. **Document its rationale in a module doc comment** at the top of
   the file. The "why" is more interesting than the "what" — future
   contributors lift the rationale, not just the implementation.
5. **Stay best-effort**. Network or filesystem failures must not
   block the diff from rendering. The contract is "render whatever
   we got", not "all-or-nothing".
6. **Not pull in tokio / chrono / semver / octocrab** without strong
   justification. The dep-tree audit is real — see
   [Architecture](./architecture.md#why-no-async--tokio).

See [Contributing](./contributing.md) for the development loop.
