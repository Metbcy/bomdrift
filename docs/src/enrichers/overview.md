# Enrichers overview

An **enricher** runs over the `ChangeSet` produced by the diff core and
adds risk-signal metadata to the rendered output without modifying the
ChangeSet itself. Each is independent, has its own opt-out flag, and
follows a best-effort contract: any failure (network, rate-limit,
upstream API change) is logged once to stderr and the diff renders
without that enricher's findings.

## Shipping enrichers

| Enricher | Source | Network? | Default | Opt-out flag |
|---|---|---|---|---|
| [OSV.dev CVE lookup](./osv-cve.md) | OSV.dev `/v1/querybatch` + `/v1/vulns/{id}` | yes | on | `--no-osv` |
| [Typosquat](./typosquat.md) | Embedded top-N lists, optional XDG cache | no | on | (none — pure compute) |
| [Multi-major version jump](./version-jump.md) | The diff itself | no | on | (none — pure compute) |
| [Maintainer age](./maintainer-age.md) | GitHub REST `/repos/.../contributors` + `/commits` | yes | on | `--no-maintainer-age` |

## Best-effort contract

Every enricher that touches the network honors the same contract:

1. **Per-request timeout** (15s for OSV, 15s for GitHub) so a
   misbehaving upstream can't hang a CI job.
2. **Errors warn, never block.** A failed enricher logs one line to
   stderr (the warning is the same key every time, so it dedupes
   reasonably) and the diff renders without that enricher's
   contributions.
3. **Rate-limit awareness.** OSV's `/v1/querybatch` is unauthenticated;
   the GitHub REST API honors `GITHUB_TOKEN` for the 5000/hr cap. On a
   `403 + X-RateLimit-Remaining: 0`, the maintainer-age enricher
   returns whatever was already collected and warns once.
4. **Per-component caching within a single run.** Repeated `cs.added`
   entries from the same project (e.g. monorepo subpackages sharing a
   GitHub repo) don't multiply HTTP requests.

## Determinism

Each enricher's output is structured into the `Enrichment` graph
(`vulns: HashMap<...>`, `typosquats: Vec<...>`, `version_jumps: Vec<...>`,
`maintainer_age: Vec<...>`). Renderers iterate these in deterministic
order — `Vec`s in their natural BTreeMap-derived order from the
ChangeSet, the `vulns` HashMap with its keys sorted before emission.

This is the contract that lets `peter-evans/create-or-update-comment`
upsert PR comments in place: identical inputs render to byte-identical
output, so the comment body is patched only when the diff genuinely
changes.

## Why these four signals?

The four enrichers were chosen because each maps to a real, recent,
high-impact incident class:

- **OSV.dev CVE lookup**: published advisories.
- **Typosquat**: malicious packages mimicking popular ones (the
  `plain-crypto-js` axios dropper, the PyPI campaigns 2024–2026).
- **Multi-major version jump**: takeover swaps, namespace reuse.
- **Maintainer age**: long-game social-engineering campaigns (xz / Jia
  Tan).

Future enrichers will live alongside these in the same module structure;
see [Roadmap](../roadmap.md) for what's planned.
