# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Repository policy config (`.bomdrift.toml`).** `bomdrift diff`
  auto-loads `.bomdrift.toml` from the current working directory when
  present, or an explicit file via `--config`. Config can set defaults
  for output format, fail thresholds, baseline path, markdown focus
  mode, and dependency-churn budgets while leaving CLI flags as the
  one-off override path.

- **`bomdrift init` scaffolding.** `bomdrift init` writes a starter
  `.bomdrift.toml`, SBOM-diff workflow, and comment-suppression workflow.
  `--config-only` writes just the policy file; `--force` overwrites
  existing generated files.

- **Diff-budget gates.** `--max-added`, `--max-removed`, and
  `--max-version-changed` exit 2 after rendering when a PR changes more
  dependencies than the configured budget allows.

- **Focused markdown comments.** `--findings-only` keeps the summary and
  risk-bearing sections but omits raw Added / Removed / Version changed
  detail rows for high-churn PRs.

- **License-change threshold.** `--fail-on license-change` exits 2 on
  same-version license drift without also requiring `--fail-on any`.

- **GitHub Action inputs for policy controls.** The action now accepts
  `config`, `findings-only`, `max-added`, `max-removed`, and
  `max-version-changed` and passes them through to the CLI.

## [0.5.0] - 2026-04-29

The adoption milestone: bomdrift now works as a copy-paste GitHub Action,
posts a much more scannable PR comment, supports comment-driven suppression,
and has the repo surfaces first-time OSS users expect.

### Changed

- **`Ecosystem::Other("file")` pseudo-components are now dropped from
  diffs by default.** Syft's `directory` cataloger emits each YAML /
  lockfile / source file in the scanned directory as a synthetic
  component whose ecosystem string is `"file"`. Path differs between
  the PR-head and base-ref checkouts, so each file shows up as both
  Added and Removed in the same diff, drowning real package changes
  in noise. The filter is applied at the CLI layer, after parse —
  the `bomdrift::parse` library API still returns whatever the SBOM
  format declares.

  This is a visible default-output change but not a breaking one:
  pre-v0.5 baselines that captured `file:` entries continue to load
  (the baseline parser is forgiving) and the entries simply become
  inert, matching against findings that no longer surface.

### Added

- **Zero-config GitHub Action invocation.** `Metbcy/bomdrift@v1` can now
  run on a `pull_request` workflow with no explicit checkout, Syft step,
  or SBOM path wiring. The action checks out the PR base and head refs,
  installs Syft via `anchore/sbom-action/download-syft@v0`, generates
  CycloneDX JSON SBOMs for both sides, runs `bomdrift diff`, and upserts
  the markdown result as a PR comment. Existing `before-sbom` /
  `after-sbom` inputs remain supported as the bring-your-own-SBOM escape
  hatch, but are no longer required.

- **`bomdrift baseline add <id>` CLI subcommand** for adding wildcard
  advisory suppressions to `.bomdrift/baseline.json`. The command creates
  the file and parent directory when missing, writes atomically, and is
  idempotent when the advisory is already suppressed.

- **Companion `Metbcy/bomdrift/comment-suppress@v1` action** for
  in-comment suppression. A reviewer can comment `/bomdrift suppress
  <ID>` on a PR; the sub-action validates the command, runs
  `bomdrift baseline add <ID>`, commits the baseline update to the PR
  branch, and reacts to the trigger comment.

- **`--include-file-components` flag** on `bomdrift diff` for users
  who want the raw cataloger output (debugging, auditing). Off by
  default; enabling it restores the pre-v0.5 behavior.

- **Markdown comment is now collapsible.** Each per-category section
  (Added / Removed / Version changed / Vulnerabilities / Possible
  typosquats / Multi-major version jumps / Young maintainers /
  License changed) is wrapped in a `<details><summary>` block. The
  `### Section (count)` header stays visible above the wrapper so
  the table of contents still works; the body is hidden by default
  for skim-readability on big diffs. Reviewers expand the sections
  they care about.

- **Severity-sorted vulnerability rows.** Within the Vulnerabilities
  section, components are ordered by their highest-severity
  advisory (Critical first, then High / Medium / Low / None), with
  alphabetical tie-breaking on ecosystem+name. Per-component
  advisories continue to be severity-then-id sorted as before.
  Critical / High findings now cluster at the top of the table —
  the load-bearing rows that justify a reviewer's attention.

- **`<summary>` teasers** on the Vulnerabilities and Possible
  typosquats sections surface the most-actionable item without
  expanding (e.g. `top severity: CRITICAL (CVE-2025-foo)` or
  `top similarity: 0.95 (axiosx → axios)`).

- **Per-section "Why this matters" links** in the markdown output,
  reusing the SARIF rule helpUris that v0.4.2 introduced. Reviewers
  click through to the docs chapter explaining what the enricher is
  detecting and why.

- **`--repo-url` flag** (also reads `BOMDRIFT_REPO_URL` env var) on
  `bomdrift diff`. When set, the markdown comment renders an
  action-affordance footer with three links: a pre-filled "Report
  this finding" issue URL, the `/bomdrift suppress <id>`
  suppress-comment hint, and the docs site. The action sets this
  automatically from the consuming repository, while standalone CLI
  runs can pass the flag or env var explicitly. When unset, the footer
  is omitted entirely so forks / standalone CLI use don't render dead
  links to bomdrift's own issue tracker.

- **OSS adoption surfaces.** The README now leads with the one-step
  workflow, a comparison table, suppression setup, and v0.5 examples.
  The repo also has issue templates, a pull-request template,
  root-level CONTRIBUTING.md, CODE_OF_CONDUCT.md, STATUS.md, and a
  pinned feedback issue for early users.

## [0.4.4] - 2026-04-28

The "make the action actually produce output" patch release. Sister
fix to v0.4.3, which fixed the action manifest's location but left
two upstream bugs that prevented bomdrift from running at all once
the manifest was found.

### Fixed

- **`log()` and `endlog()` now write workflow-command directives to
  stderr instead of stdout.** The functions are called from inside
  `download_bomdrift()` whose stdout is captured by the caller
  (`bin="$(download_bomdrift ...)"`) and from inside `run_diff()`
  whose stdout is tee'd into the PR comment body. Writing
  `::group::...` directives to stdout meant:

  1. `$bin` became a concatenation of `::group::bomdrift:
     Downloading...` + cosign's "Verified OK" + `::endgroup::` +
     the actual binary path. Bash then tried to exec a "command"
     called `::group::bomdrift: Downloading...` and reported
     `File name too long`, so bomdrift never actually ran.
  2. The PR comment body ended up as
     `<!-- bomdrift:diff -->\n::group::bomdrift: Running ...\n::endgroup::`
     — just the action's own log markers wrapped around an empty
     body, since the binary never produced output.

  GitHub Actions parses workflow commands from BOTH stdout and
  stderr, so the UI grouping is preserved while the captured
  streams stay clean for the data they're carrying.

- **`download_bomdrift()` now redirects its entire work region to
  stderr via `exec 3>&1 1>&2`, restoring stdout only for the final
  `printf '%s' "$bin"`.** Catches every other stdout-leaking
  command in the function — cosign's "Verified OK", any future
  curl progress modes that route to stdout, tar's verbose output if
  someone adds `-v`, etc. The captured-bin-path value is now
  guaranteed to be the binary path and nothing else.

This bug has been latent since the action shipped in v0.1.0; v0.4.3
was the first release where someone actually invoked the action and
hit it (bomdrift's own dogfood workflow on PR #1).

## [0.4.3] - 2026-04-28

The "make the action actually invokable" patch release. No new
features; fixes a layout bug that has silently broken every consumer
trying to use `Metbcy/bomdrift@v1` since v0.1.0 was tagged.

### Fixed

- **`action.yml` moved from `action/action.yml` to the repo root.**
  GitHub Actions resolves a composite action's manifest at the repo
  root by default; subdirectory actions require consumers to type
  `Metbcy/bomdrift/action@v1` instead of `Metbcy/bomdrift@v1`. Every
  example in the README and docs site used the latter form, so any
  consumer copying those snippets hit:

  ```
  Can't find 'action.yml', 'action.yaml' or 'Dockerfile' for action
  'Metbcy/bomdrift@v1'.
  ```

  The bug surfaced when bomdrift's own dogfood workflow (introduced
  in `60e772d`) tried to self-invoke `Metbcy/bomdrift@v1` and
  failed for the same reason. With the manifest at the repo root,
  `Metbcy/bomdrift@v1` (the form the docs always advertised) now
  works. `entrypoint.sh` moved alongside it; the
  `${{ github.action_path }}/entrypoint.sh` reference continues
  to resolve correctly because that variable points at whatever
  directory contains the loaded `action.yml`.

  Note: this is a v0.x patch release, so the layout change is fine
  for existing consumers who pinned to a prior tag (those tags still
  work as they always did — broken). v1.0 will keep `action.yml` at
  the root permanently.

## [0.4.2] - 2026-04-28

The "fix the broken help links" patch release. No new features, no
behavior change beyond the URLs that finding consumers click through.

### Fixed

- **SARIF `helpUri` fields point to real docs pages.** Every rule's
  `helpUri` previously pointed to a README anchor like
  `https://github.com/Metbcy/bomdrift#cve-enrichment` that didn't
  exist — the README never had those exact heading texts, so the
  link silently scrolled nowhere when a user clicked through GitHub
  Code Scanning's UI for a `bomdrift.cve` finding (or any other
  bomdrift rule). Now point at the corresponding chapter on the
  mdBook docs site:
  - `bomdrift.cve` → `enrichers/osv-cve.html`
  - `bomdrift.typosquat` → `enrichers/typosquat.html`
  - `bomdrift.version-jump` → `enrichers/version-jump.html`
  - `bomdrift.young-maintainer` → `enrichers/maintainer-age.html`
  - `bomdrift.license-change` → `output-formats.html#sarif-v210`
    (no dedicated chapter; the SARIF rule listing is the
    closest user-facing reference for this rule's semantics).
- **SARIF `tool.driver.informationUri`** changed from the GitHub
  repo root to the docs site. SARIF spec defines this as "the
  absolute URI of the tool's website" — the docs site is the
  user-friendly destination from a Code Scanning UI click.
- **Broken anchor in `docs/src/output-formats.md`**: a CHANGELOG
  cross-reference used `#breaking-output-shape` but the actual
  GitHub heading-slug for that section is
  `#changed-breaking-output-shape`. Now matches reality.

## [0.4.1] - 2026-04-28

The "harden the foundations" patch release. No user-visible behavior
change, no new features — pure quality / regression-coverage
improvements that catch entire classes of bugs in advance.

### Added

- **Criterion benchmarks** for the four hot paths: parse, diff,
  typosquat, render. Run with `cargo bench`. Not gated in CI (shared
  GitHub runner variance is ±20%, which buries any real signal); the
  HTML report at `target/criterion/report/index.html` is the workflow
  for validating perf-relevant changes locally. Documented in the
  new [Benchmarks](https://metbcy.github.io/bomdrift/development/benchmarks.html)
  chapter.
- **Property-based tests** via `proptest`, running as part of
  `cargo test --release`. 14 new property tests cover:
  - Parser layer: arbitrary bytes / arbitrary JSON / arbitrary JSON
    with each format hint forced — must NEVER panic. Errors are fine;
    panics are bugs.
  - Typosquat canonicalization: `pep503_normalize` on arbitrary
    unicode (output invariants asserted: lowercase, no leading/
    trailing dashes); `last_path_segment` always returns a substring
    with no `/` in it; `enrich()` never panics on arbitrary added-
    component sets.
  - Diff core: `diff(a, a)` is always empty (identity);
    `diff(a, b)` swaps `added`/`removed` cardinalities from
    `diff(b, a)` (symmetry); two `diff()` calls on the same input
    are byte-equal (determinism — the upsert contract for PR-comment
    renderers).
  - Version-jump extractor: never panics on arbitrary strings;
    round-trips well-formed numerics (`1..10000` with `v`-prefix
    and pre-release suffix variants); handles arbitrary unicode
    prefixes without panic.
- **Real-world SBOM regression corpus** at
  `tests/fixtures/real-world/` containing 4 CycloneDX SBOMs (cern,
  dropwizard, keycloak, laravel) and 1 SPDX SBOM (example10),
  sourced from the official `CycloneDX/sbom-examples` and
  `spdx/spdx-examples` repos. Tests in `tests/real_world.rs` exercise:
  - Every fixture parses without error and to ≥ 1 component.
  - Format auto-detection routes to the correct parser.
  - Components with known purl types resolve to the canonical
    `Ecosystem` variant (catches `ecosystem_from_purl` regressions).
  - Diff of two unrelated real SBOMs doesn't panic.
  - Self-diff of any real SBOM produces an empty ChangeSet
    (parser non-determinism guard).
  - All four renderers produce non-empty output on a real diff.

### Changed

- **Test count**: 236 → 256 passing (226 unit + 15 cli + 9 integration
  + 6 real-world).
- New `[dev-dependencies]`: `criterion = "0.5"` and `proptest = "1"`.
  No effect on the production binary; release-profile size stays at
  ~3.5 MB.

## [0.4.0] - 2026-04-28

The "more ecosystems, more action surface" release. Adds four typosquat
ecosystems (Go, RubyGems, NuGet, Composer), plumbs `--baseline` into the
GitHub Action input surface, and refreshes the docs site to match.

### Added

- **`baseline:` action input** — passes straight through to
  `bomdrift diff --baseline <path>`. Previously consumers wanting baseline
  suppression had to bypass the action and call the binary directly via a
  custom step; the action now handles it. The file's existence is
  validated up front (a typo'd path no-op'ing would defeat the point).
- **Typosquat detection for Go, RubyGems, NuGet, and Composer.** The
  v0.2 multi-ecosystem expansion shipped npm + PyPI + Cargo + Maven; v0.4
  rounds out the JVM-adjacent and dynamic-language pillars. Per-ecosystem
  rules:
  - **Go** matches on the **last path segment** of `host/owner/repo`
    (`github.com/attacker/cobra` flagged against `github.com/spf13/cobra`).
    Same-segment-different-org is treated as a legitimate fork and not
    flagged.
  - **Gem** uses standard JW + suffix-containment with `-` and `_`
    separators (`railz` flagged against `rails`; `rspec-rails` extension
    pattern not flagged).
  - **NuGet** canonicalizes IDs to lowercase per the package-spec's
    case-insensitivity (`Newtonsoft.Json` ≡ `newtonsoft.json`); `.` is
    the separator (`Microsoft.Extensions.Logging` shape).
  - **Composer** matches on the **package portion** of `vendor/package`
    (symmetric to the Maven artifactId-only rule) — `attacker/consolee`
    flagged against `symfony/console`; `myorg/console` is a legit fork.
- **`Ecosystem::Gem`, `Ecosystem::NuGet`, `Ecosystem::Composer`** model
  variants. Components whose purl now resolves to one of these will
  serialize their `ecosystem` field as the canonical name (`gem`,
  `nuget`, `composer`) rather than falling back to the
  `Other("gem")`-as-string representation. JSON / SARIF / markdown
  output all reflect this shape change.
- **`bomdrift refresh-typosquat --ecosystem`** now accepts `nuget`
  (real fetcher; uses the v3 search API
  `?orderby=totalDownloads&take=200`), `go`, `gem`, and `composer`.
  The latter three are no-ops with informational notices: pkg.go.dev,
  rubygems.org, and packagist.org all lack stable public popularity
  feeds, so the curated `data/{go,gem,composer}-top200.txt` snapshots
  shipped in the binary remain the source of truth. Adding a name
  to those lists is an explicit editorial decision; PRs welcome.
- **Embedded data files**: `data/go-top200.txt` (~140 module paths
  curated from pkg.go.dev and well-known imports — cobra, gin, grpc,
  k8s, prometheus, opentelemetry), `data/gem-top200.txt` (~185 well-
  known gems — rails, rspec, devise, sidekiq), `data/nuget-top200.txt`
  (200 IDs auto-fetched from the v3 search API), and
  `data/composer-top200.txt` (~140 `vendor/package` coords — symfony,
  laravel, doctrine).

### Changed

- **`--ecosystem all`** for `refresh-typosquat` now expands to **eight**
  ecosystems (npm, PyPI, Cargo, Maven, Go, Gem, NuGet, Composer)
  instead of four. Network egress increases proportionally; pin to a
  specific `--ecosystem <name>` if you need the v0.3 behavior.

### Deferred to v0.5

- **GraphQL maintainer-age** was investigated for v0.4 and deferred. The
  current REST implementation already uses `?per_page=1` + `Link: rel=
  "last"` parsing for both top contributor and contributor count, so
  the only remaining round-trip cost is the per-author commit-history
  pagination — and GitHub's GraphQL `history()` connection doesn't
  expose an ASC ordering, so the GraphQL replacement would still need
  cursor-based pagination to find the oldest commit (same shape as
  REST). Will revisit if a v0.5 contributor finds a clean approach,
  e.g. via `User.contributionsCollection`.

### Migration notes

- The serialized `ecosystem` field for components with
  `pkg:gem/...`, `pkg:nuget/...`, or `pkg:composer/...` purls
  changes from the v0.3 fallback (`"library"` or `"gem"` as the
  `Other(...)` string) to the v0.4 canonical name. Consumers that
  pinned on the v0.3 string need to migrate.

## [0.3.0] - 2026-04-28

The "severity, baselines, and big-PR survival" release. Closes the v0.2
deferral on real OSV severity, adds an on-disk severity cache, surfaces
baseline-suppression for adoption-mid-stream teams, and stops big PR
diffs from blowing past GitHub's comment-body cap.

### Added

- **Per-advisory OSV severity** via `/v1/vulns/{id}` follow-up. Severity
  is sourced from GHSA's `database_specific.severity` text label
  (`LOW|MODERATE|HIGH|CRITICAL`); advisories without that field surface
  as `NONE` and don't trip `--fail-on critical-cve`. The label is
  rendered alongside each advisory ID in markdown / terminal / JSON /
  SARIF output. SARIF results map Critical/High to `level: "error"`,
  everything else to `level: "warning"`. Markdown / term sort
  highest-severity-first within a component, ties broken by ID, so the
  rendered output stays byte-deterministic for the PR-comment upsert.
- **`--fail-on critical-cve` is now real.** Previously aliased to `cve`
  with a v0.2 stub warning; now filters on `severity >= High` per the
  OSV-fetched severity. The `critical-cve` name covers the
  HIGH-or-CRITICAL bucket (CRITICAL is rare in GHSA tagging; many
  actively-exploited advisories ship as HIGH, and treating them as the
  actionable bucket matches what the option name communicates).
- **On-disk OSV severity cache** at `<XDG_CACHE_HOME>/bomdrift/osv/`
  with a 24h TTL. New `--no-osv-cache` flag opts out. Hits are reported
  via a single end-of-run "osv: N/M severities served from cache"
  stderr line. Atomic temp-file + rename writes mirror the existing
  `src/refresh.rs` pattern.
- **`--baseline <path.json>`** suppresses findings already present in a
  previously captured `bomdrift diff --output json` snapshot. Match
  keys are conservative — drift surfaces — so adopting bomdrift on a
  project with pre-existing findings doesn't drown the first PR
  comment. See `src/baseline.rs` module doc for per-finding-type key
  semantics.
- **`--summary-only`** flag emits only the summary table + a footer
  pointing reviewers at the full output. Markdown-only.
- **Action input `comment-size-limit`** (default 60000 bytes; just
  under GitHub's 65536-char comment cap so a marker + footer fit).
  When the rendered diff exceeds the limit, `entrypoint.sh`
  re-renders with `--summary-only` for the PR comment while keeping
  the full body in the workflow step summary. Set to 0 to disable.

### Changed (breaking output shape)

- **`Enrichment.vulns` JSON shape** is now
  `{"<purl>": [{"id": "...", "severity": "..."}, ...]}` instead of
  `{"<purl>": ["GHSA-..."]}`. Consumers parsing the v0.2 string-list
  shape need to migrate. The CLI wrapper for downstream tooling can
  pin `--baseline` files to v0.3 — the baseline parser is forgiving
  about missing fields, so old baselines still load (with reduced
  suppression precision for the severity-aware fields).

### Fixed

- The action's `entrypoint.sh` now uses `tee` + `PIPESTATUS` so PR
  comments still post when bomdrift exits 2 from `--fail-on`. (This
  was already true in v0.2; the v0.3 size-fallback path follows the
  same pattern when re-running with `--summary-only`.)

## [0.2.0] - 2026-04-28

The "ship the deferred gaps" release. Every "Known gaps (deferred to v0.2)"
bullet from v0.1.0 is now closed, plus several quality-of-life fixes that
surfaced during the v0.1.0 code review.

### Added

- **SARIF v2.1.0 renderer** (`--output sarif`). Emits one result per finding
  with five stable rule IDs (`bomdrift.cve`, `bomdrift.typosquat`,
  `bomdrift.version-jump`, `bomdrift.young-maintainer`,
  `bomdrift.license-change`) suitable for ingestion by GitHub Code Scanning,
  GitLab Vulnerability Reports, etc. All results are `level: warning` in
  v0.2 (severity data isn't yet returned by OSV's `/v1/querybatch`).
  Output is byte-deterministic (HashMap keys are sorted before emission)
  so PR-comment upserts stay stable.
- **`--fail-on` enforcement** (`none|cve|critical-cve|typosquat|any`).
  Exits with code 2 when the configured threshold trips. The PR comment is
  still posted on a tripped run — the action's `entrypoint.sh` now uses a
  `tee` + `PIPESTATUS` capture instead of `out="$(...)"` so reviewers see
  the findings even when the workflow step fails. `critical-cve` is
  currently aliased to `cve` with a one-shot stderr warning; v0.3 will
  populate per-advisory severity from `/v1/vulns/{id}` and narrow it.
- **Linux aarch64 release artifact**. Built via `cross-rs/cross` so the
  `ring` (transitive `ureq → rustls`) cross-compile from ubuntu-x86_64
  Just Works without per-target CC/AR env-var surgery. Released as
  `bomdrift-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz` alongside the
  existing three targets, with cosign signature + SHA-256 attached.
- **Multi-ecosystem typosquat detection**. The npm-only enricher now
  covers npm, PyPI, Cargo, and Maven, with rules tuned per-ecosystem:
  - **PyPI**: PEP 503 normalization (`-`/`_`/`.` collapse) on candidate
    and legit-list entries so `scikit_learn` ≡ `scikit-learn`. Embedded
    top-200 list from hugovk/top-pypi-packages.
  - **Cargo**: separator `-` only. Embedded top-200 list from the
    crates.io API (`?sort=downloads`).
  - **Maven**: Levenshtein ≤ 2 on the `artifactId` portion of
    `groupId:artifactId` only — the shared `groupId` prefix would
    inflate Jaro-Winkler past anything useful. ~100 hand-curated
    coordinates from mvnrepository.com Most Popular categories.
- **`bomdrift refresh-typosquat`** now supports `--ecosystem pypi|cargo`
  in addition to `npm`, fetching from each ecosystem's canonical upstream
  with a polite User-Agent and (for Cargo) a 1-second pagination delay.
  `--ecosystem maven` is accepted but emits a notice — Maven Central has
  no canonical "top N" feed. `--ecosystem all` now expands to all four
  (previously expanded to npm only).
- **`verify-signatures` action input** (default `true`). Lets consumers
  on trusted mirrors / cached runners skip the cosign-installer step and
  the .sig/.pem download round-trips (~15s saved). When `true` and cosign
  is missing, the action now fails loudly instead of silently degrading.

### Fixed

- **Wired up `--format`**. v0.1.0 parsed the flag through clap and
  plumbed it through the action via `INPUT_FORMAT`, but `run_diff` never
  read it — every invocation auto-detected via `parse::parse()`. Now
  forces dispatch to the chosen parser when `--format cdx|spdx|syft`
  is supplied; `auto` still auto-detects.
- **Multi-version components no longer silently dropped from diffs**.
  v0.1.0's `BTreeMap<ComponentKey, &Component>` collector kept only the
  last-inserted entry when an SBOM contained the same component at
  multiple versions (legitimate in non-flat dep trees, e.g. npm). The
  diff core now collects `BTreeMap<ComponentKey, Vec<&Component>>` and
  computes pair-by-version per key, surfacing every transition through
  added/removed/license_changed (version_changed remains the
  single-version-per-key fast path for backward-compatible rendering).

### Migration notes

- **`--fail-on`** was a no-op stub in v0.1.0; consumers that set
  `fail-on: cve` and were silently no-op'd will start exiting 2 on CVE
  findings. This is the intended behavior they thought they had — but
  worth checking your workflows before pinning to `@v0.2.0`.
- **Multi-version diff output shape**. Diffs of SBOMs with duplicate
  components at different versions previously emitted one
  `version_changed` pair (silently dropping the others); they now emit
  multiple `added` / `removed` entries. JSON / SARIF / markdown all
  reflect this faithfully.
- **`--ecosystem all`** for `refresh-typosquat` now refreshes four
  ecosystems (npm, PyPI, Cargo, Maven) instead of just npm. Network
  egress increases proportionally; pin to `--ecosystem npm` if you
  need the v0.1.0 behavior.

### Distribution

- Linux aarch64 added to the release matrix. Cosign keyless signatures
  attached to every archive (no change from v0.1.0).
- Release binary still stripped + LTO; ~3.2 MB on Linux x86_64.

## [0.1.0] - 2026-04-28

First public release. The wedge: a single `bomdrift diff before.json after.json`
invocation parses CycloneDX 1.5/1.6, SPDX 2.3, or Syft JSON SBOMs (auto-detected),
diffs them deterministically, and surfaces supply-chain risk signals on every
changed dependency in a format ready to drop into a PR comment.

### Parsers
- CycloneDX 1.5/1.6 JSON
- SPDX 2.3 JSON
- Syft JSON
- Unified component model with cross-format diff keying via purl-without-version
  (falling back to ecosystem+name when no purl is provided)

### Diff
- Categorizes per-component changes into added, removed, version-changed, and
  license-changed (same-version-different-license is the suspicious bucket)
- Byte-deterministic output for stable PR-comment upserts via
  `peter-evans/create-or-update-comment`

### Risk-signal enrichers
- **OSV.dev CVE lookup** via `/v1/querybatch` for added and version-bumped
  components. Best-effort: network failures warn and continue rendering.
- **Typosquat detection** flagging newly added npm components whose name is
  suspiciously close to a top-1000 package, via Jaro-Winkler plus a
  suffix-containment boost rule. Catches the `plain-crypto-js` → `crypto-js`
  pattern that pure JW alone misses. Embedded snapshot of 1000 names sourced
  from anvaka/npmrank; refreshable via `bomdrift refresh-typosquat`.
- **Multi-major version-jump heuristic** flagging dependencies that crossed
  two or more major versions in a single diff (the "takeover swap" / xz
  pattern at SemVer scale). Pure-compute, no I/O, no semver crate.
- **Maintainer-age signal** flagging newly added GitHub-hosted dependencies
  whose top contributor's first commit is younger than 90 days (the xz/Jia
  Tan pattern). Hand-rolled GitHub REST calls via `ureq`; honors
  `GITHUB_TOKEN`; rate-limit-aware. Skipped when the repo has > 50
  contributors. Toggle with `--no-maintainer-age` for offline runs.

### Renderers
- **GitHub-Flavored Markdown** (default for non-TTY / piped output / explicit
  `--output markdown`): summary table plus per-category sections with osv.dev
  hyperlinks, designed for direct posting as a PR comment.
- **Terminal with ANSI color** (default for TTY): tree-style output with
  bracketed `[ADD]`/`[REM]`/`[VER]`/`[LIC]`/`[CVE]`/`[SQT]` prefixes;
  respects `NO_COLOR` and `CLICOLOR_FORCE`.
- **JSON** (`--output json`): pretty-printed `{changes, enrichment}` graph
  for downstream tooling.

### CLI
- `bomdrift diff <before> <after> [--output ...] [--no-osv]
  [--no-maintainer-age] [--format ...]`
- `bomdrift refresh-typosquat [--ecosystem npm|all]` writes refreshed
  popular-package lists to `<XDG_CACHE_HOME>/bomdrift/typosquat/`; the
  enricher prefers cache files over the embedded snapshot when present.

### Distribution

- Pre-built binaries for **Linux x86_64**, **macOS aarch64**, and **Windows
  x86_64**, attached to each GitHub release as `tar.gz` / `zip` archives plus
  SHA-256 checksums. (Linux aarch64 is planned for v0.1.1.)
- **Cosign keyless signatures** (Sigstore via GitHub OIDC) for every released
  archive. Verify with:
  ```bash
  cosign verify-blob \
    --certificate-identity 'https://github.com/Metbcy/bomdrift/.github/workflows/release.yml@refs/tags/v0.1.0' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate <archive>.pem \
    --signature  <archive>.sig \
    <archive>
  ```
- Release binary stripped + LTO; ~3.2 MB on Linux x86_64.

### GitHub Action

- `Metbcy/bomdrift@v1` (composite, no Docker) downloads the matching release
  archive for the runner's OS+arch, cosign-verifies it (when cosign is
  available), runs `bomdrift diff`, writes the rendered output to the job
  step summary, and upserts the diff as a single PR comment marked
  `<!-- bomdrift:diff -->` so subsequent pushes update the same comment
  instead of accumulating.

### Known gaps (deferred to v0.2)

- `--output sarif` is not implemented (the CLI value is reserved).
- `fail-on=cve|critical-cve|typosquat|any` Action input is accepted for
  forward compatibility but treated as `none` in v0.1.0; the action never
  fails on findings.
- Linux aarch64 binary.
- PyPI / Cargo / Maven typosquat reference lists (only npm in v0.1.0).

[Unreleased]: https://github.com/Metbcy/bomdrift/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Metbcy/bomdrift/compare/v0.4.4...v0.5.0
[0.4.4]: https://github.com/Metbcy/bomdrift/releases/tag/v0.4.4
[0.4.3]: https://github.com/Metbcy/bomdrift/releases/tag/v0.4.3
[0.4.2]: https://github.com/Metbcy/bomdrift/releases/tag/v0.4.2
[0.4.1]: https://github.com/Metbcy/bomdrift/releases/tag/v0.4.1
[0.4.0]: https://github.com/Metbcy/bomdrift/releases/tag/v0.4.0
[0.3.0]: https://github.com/Metbcy/bomdrift/releases/tag/v0.3.0
[0.2.0]: https://github.com/Metbcy/bomdrift/releases/tag/v0.2.0
[0.1.0]: https://github.com/Metbcy/bomdrift/releases/tag/v0.1.0
