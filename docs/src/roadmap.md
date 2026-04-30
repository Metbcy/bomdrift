# Roadmap

What's planned, what's deliberately out of scope, and what the
acceptance criteria for new contributions look like.

## Shipped (v0.9.6 — finish the roadmap)

- **OCI artifact attestation verification** — `--before-attestation`,
  `--after-attestation`, `--cosign-identity`, `--cosign-issuer`, and
  `--require-attestation`. bomdrift shells out to
  `cosign verify-attestation --type=cyclonedx` and consumes the
  verified CycloneDX SBOM payload. See
  [Attestation](./attestation.md).
- **Custom rules / plugin system** — external-process plugins via
  repeatable `--plugin <manifest.toml>`. JSON over stdin/stdout,
  best-effort failures, new `bomdrift.plugin` SARIF rule. See
  [Plugins](./plugins.md).
- **Calibration knobs** — `--typosquat-similarity-threshold`,
  `--young-maintainer-days`, `--cache-ttl-hours` flags plus matching
  `[diff]` config keys. Every previously hardcoded threshold is now
  configurable.
- **Cache-TTL unification** — internal refactor consolidating the
  four duplicated `CACHE_TTL_SECS` constants behind a single
  `cache::ttl()` helper. No user-visible change.

## Shipped (v0.9.5 — polish + multi-SCM parity)

- **Per-exception SPDX allow/deny** via `[license] allow_exceptions` /
  `deny_exceptions` and `--allow-exception` / `--deny-exception` CLI
  flags. `Apache-2.0 WITH LLVM-exception` etc. now evaluated at the
  exception level, not just the base license.
- **Bitbucket + Azure DevOps comment-driven suppression bridges** —
  Cloudflare Worker references with the same five guards as the GitLab
  bridge. bomdrift now has comment-driven suppression parity across
  all four major SCMs.
- **`bomdrift::vex::parse_synthetic_id` public helper** — round-trips
  bomdrift's synthetic finding IDs back to a structured kind. Lets
  external VEX tooling identify which finding a statement targets.
- `spdx` crate exact-pinned (`=0.10.9`) so license-list updates can't
  silently change policy semantics.
- `BaselineEntry` / `ExpiredEntry` unified internally; public alias
  preserved.
- CI Rust toolchain pinned to MSRV 1.88; bumps are deliberate.
- Single source of truth for the suppress-comment grammar
  (`scripts/parse-suppress-comment.sh` + CI sync guard).
- GitLab note upsert + threading semantics documented.

## Shipped (v0.9 — interoperability + breadth)

- **VEX consume** — `--vex <path>` accepts OpenVEX 0.2.0 + CycloneDX
  VEX 1.6 statements; `not_affected` / `fixed` suppress findings,
  `under_investigation` annotates.
- **VEX emit** — `--emit-vex <path>` emits an OpenVEX 0.2.0 document
  with explicit per-entry `vex_status` (default
  `under_investigation`, never auto-promoted).
- **Full SPDX expression evaluator** via the `spdx` crate. Deprecates
  `allow_ambiguous`.
- **Bitbucket Pipelines + Azure DevOps Pipelines** templates with
  auto-detection (`BITBUCKET_BUILD_NUMBER`, `TF_BUILD`) and
  per-platform footer shapes.
- **Registry-metadata enrichers** — npm/PyPI/crates.io. New kinds:
  recently-published, deprecated, maintainer-set-changed (npm only).
- **GitLab comment-driven suppression** via a security-reviewed
  Cloudflare Worker reference bridge (five guards).
- **Explicit non-goals + pair-with recommendations** in README and
  STATUS.

## Shipped (v0.8 — supply-chain hardening)

- SARIF + GitHub Code Scanning with stable per-result fingerprints
  and one-line action opt-in (`upload-to-code-scanning: true`).
- EPSS scoring on every CVE-aliased advisory; `--fail-on-epss`.
- CISA KEV flagging of known-exploited advisories; `--fail-on kev`.
- License allow/deny policy with `*`-suffix glob matching and
  fail-closed compound-expression handling. New
  `bomdrift.license-violation` SARIF rule.
- Baseline `expires` + `reason` with stderr warnings on expiry.
- `time` crate + `clock` module honoring `SOURCE_DATE_EPOCH`.
- OSV CVE aliases threaded through `VulnRef`.
- `--debug-calibration-format jsonl` and `--output-file <PATH>`.

## Investigated and decided

- **GraphQL maintainer-age** — investigated again for v0.9.6 and
  rejected. GitHub's GraphQL `history()` connection doesn't expose
  ascending-date ordering, so finding the oldest contributor commit
  still requires walking the cursor backward from the most recent
  commit. REST's
  `GET /repos/{o}/{r}/commits?author=X&per_page=1` plus `Link`-header
  parsing for the last page lets bomdrift fetch a single author's
  oldest commit in two requests. **Decided: REST stays.** Closing
  this one off the roadmap permanently — re-open only if GitHub adds
  ASC ordering to the GraphQL history connection.

## Calibration

All calibration thresholds are configurable via `.bomdrift.toml` and
CLI flags. Tune `[diff] typosquat_similarity_threshold`,
`young_maintainer_days`, `recently_published_days`, `cache_ttl_hours`.
See [CLI reference](./cli-reference.md) for flag forms.

## Blocked on upstream

- **PyPI / crates.io maintainer-set-changed.** The npm enricher
  (shipped v0.9) compares maintainer sets for VersionChanged
  components by reading `registry.npmjs.org`'s per-version
  `maintainers[]` array. PyPI's
  `https://pypi.org/pypi/<pkg>/json` returns repository-level
  maintainers but no per-version history. Crates.io's
  `https://crates.io/api/v1/crates/<name>` returns repository-level
  `crate.owners` but no per-version `published_by` history. If
  either ecosystem ships a per-version maintainer endpoint, bomdrift
  adds the enricher in a future minor release.

## Future candidates (not committed)

_Empty as of v0.9.6._ The previously listed candidates have all been
shipped, marked non-goal, decided against, or moved to "Blocked on
upstream" above. New post-v0.9.6 ideas land here as they emerge.

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

### Reachability / call-graph analysis

Determining whether the vulnerable function in a flagged advisory is
actually invoked from your application's entry points is a
fundamentally different analysis than diff-level supply-chain risk.
It requires whole-program call-graph construction, language-specific
runtime modeling (dynamic dispatch, reflection, eval), and an
ever-growing per-CVE vulnerable-symbol database. The vendors who do
this well — Endor Labs, Snyk Reachability — invest at a scale OSS
bomdrift can't match, and the per-CVE symbol curation is the moat,
not the call-graph engine itself. **Pair bomdrift with Endor or Snyk
for reachability**; bomdrift answers "what changed", they answer
"does the change reach prod code".

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
