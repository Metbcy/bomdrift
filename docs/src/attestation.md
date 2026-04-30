# OCI artifact attestation

bomdrift can verify that the SBOMs it diffs were signed by your
build system before any drift signal is computed. This closes the
"who produced this SBOM?" gap: you already trust the binary you
shipped through SLSA-style signing — the SBOM that describes that
binary's supply chain deserves the same scrutiny.

Shipped in v0.9.6. The verification path is **opt-in** per flag;
existing file-based diffs (`bomdrift diff before.json after.json`)
are unaffected unless you explicitly pass attestation flags.

## Overview

An OCI attestation is a signed in-toto envelope, stored next to a
container image in an OCI registry, that asserts a claim about that
image. bomdrift consumes attestations whose **predicate type** is
`cyclonedx`: the predicate body is a CycloneDX SBOM, which bomdrift
then diffs against another (also-attested) SBOM.

bomdrift does **not** ship a Sigstore client. It shells out to
[`cosign`](https://github.com/sigstore/cosign), which handles:

- in-toto envelope signature verification,
- certificate-chain validation against Fulcio,
- transparency-log inclusion proof (Rekor),
- certificate-identity matching against your supplied regex/issuer.

bomdrift trusts cosign's verdict. If cosign exits 0, bomdrift parses
the verified predicate and feeds it to the diff core. If cosign
exits non-zero, bomdrift surfaces the cosign stderr verbatim and
exits 1.

### Threat model gap NOT addressed

bomdrift does not implement Sigstore protocol verification itself.
You are trusting cosign's implementation, the cosign binary on
`PATH`, and whichever Sigstore instance cosign is configured against
(public-good by default; see [Self-managed Sigstore](#self-managed-sigstore-instances)).

## Prerequisites

1. **Install cosign.** Follow
   <https://docs.sigstore.dev/system_config/installation/>. v0.9.6
   was developed and tested against `cosign 2.x`. Pin to a specific
   cosign version in your CI image so signature-verification
   semantics don't drift across runs.
2. **Push your SBOMs as cyclonedx attestations** on the same OCI
   reference as the binary they describe (see next section).

## Generating attestations

The canonical guide is [the sigstore docs](https://docs.sigstore.dev/cosign/signing/other_types/);
this section is a sketch.

```bash
# Produce the SBOM however you do today (Syft, etc.).
syft <oci-ref> -o cyclonedx-json > sbom.cdx.json

# Sign it as an attestation against the same digest.
cosign attest \
  --predicate sbom.cdx.json \
  --type     cyclonedx \
  ghcr.io/myorg/myapp@sha256:abc...
```

The `--type cyclonedx` flag is the predicate-type matcher bomdrift
filters on. Other predicate types (SPDX, SLSA provenance, custom)
are ignored — see [What's NOT in v0.9.6](#whats-not-in-v096).

## Verifying with bomdrift

Pass an OCI reference instead of a local file path via the
attestation flags:

```bash
bomdrift diff \
  --before-attestation oci://ghcr.io/myorg/myapp@sha256:abc... \
  --after-attestation  oci://ghcr.io/myorg/myapp@sha256:def... \
  --cosign-identity '^https://github.com/myorg/.+@refs/tags/v.+$' \
  --cosign-issuer    https://token.actions.githubusercontent.com
```

### `--before-attestation <OCI-REF>`

OCI reference (with `oci://` scheme) of the "before" image whose
attached cyclonedx attestation is the "before" SBOM. Mutually
exclusive with the positional `<BEFORE>` argument; pass one or the
other.

### `--after-attestation <OCI-REF>`

Same as above, for the "after" SBOM.

### `--cosign-identity <REGEX>`

Required when any `--*-attestation` flag is set. RE2-syntax regex
that the certificate's `subject` Subject Alternative Name must
match. For GitHub Actions OIDC, this is typically the workflow URL
plus a refs constraint, e.g.
`^https://github.com/myorg/myapp/.github/workflows/release\.yml@refs/tags/v.+$`.

bomdrift passes this to cosign as `--certificate-identity-regexp`.

### `--cosign-issuer <URL>`

Required when any `--*-attestation` flag is set. The OIDC issuer
that minted the signing certificate. For GitHub Actions, this is
`https://token.actions.githubusercontent.com`.

bomdrift passes this to cosign as `--certificate-oidc-issuer`.

## `--require-attestation`

Hard-mode flag. When set:

- Both `--before-attestation` and `--after-attestation` must be
  provided.
- Positional `<BEFORE>` and `<AFTER>` file arguments are **rejected**
  (clap conflict).
- Any cosign verification failure exits 1; there is no fallback to
  unverified file inputs.

Use this on the production-CI gate that blocks releases. In dev
loops where you sometimes diff a local file against a published
attestation, leave `--require-attestation` off and let the operator
mix file inputs with attestation inputs.

## What bomdrift trusts

The trust boundaries, made explicit:

- bomdrift trusts **cosign** to verify the in-toto envelope's
  signature, certificate chain, and Rekor inclusion proof.
- bomdrift trusts **cosign** to enforce the certificate identity
  regex and OIDC issuer match.
- bomdrift does **not** independently re-verify the Sigstore
  transparency log. That is `cosign verify-attestation`'s job.
- bomdrift assumes the predicate-type filter (`--type=cyclonedx`)
  is honored by cosign. It is, but the assumption is documented
  here so future cosign behavior changes are visible to auditors.
- bomdrift parses the verified predicate as **CycloneDX JSON**.
  Anything cosign hands back that doesn't parse as CycloneDX exits
  bomdrift with a parse error.

## Self-managed Sigstore instances

If you run your own Sigstore stack (private Fulcio + Rekor), cosign
honors the standard Sigstore env vars:

| Variable | Purpose |
|---|---|
| `COSIGN_REKOR_URL` / `SIGSTORE_REKOR_URL` | Override the public-good Rekor instance. |
| `COSIGN_FULCIO_URL` / `SIGSTORE_FULCIO_URL` | Override Fulcio. |
| `COSIGN_OIDC_ISSUER` | Override the default OIDC issuer probed during signing. |
| `SIGSTORE_ROOT_FILE` | Pin a custom Sigstore TUF root for verification. |

bomdrift inherits the parent process environment when shelling out
to cosign, so exporting these before invoking `bomdrift diff` is
sufficient. No bomdrift-side flags are needed.

```bash
export SIGSTORE_REKOR_URL=https://rekor.internal.example.com
bomdrift diff --before-attestation ... --after-attestation ... ...
```

## Air-gapped / self-hosted Sigstore

Regulated environments — finance, defense, healthcare on-prem, government
cloud — frequently can't reach the public-good Sigstore instance
(`rekor.sigstore.dev`, `fulcio.sigstore.dev`, `tuf-repo-cdn.sigstore.dev`).
The org runs its own Sigstore stack inside the trust boundary, with its
own TUF root, Fulcio CA, and Rekor transparency log. bomdrift supports
this without any bomdrift-side configuration: the attestation module
shells out to cosign and **does not scrub or modify** the calling
environment, so every Sigstore env var cosign respects flows through
unchanged.

### Environment variables

| Variable | Purpose |
|---|---|
| `SIGSTORE_REKOR_URL` / `COSIGN_REKOR_URL` | Transparency-log endpoint (your private Rekor). |
| `SIGSTORE_FULCIO_URL` / `COSIGN_FULCIO_URL` | Short-lived cert issuer (your private Fulcio). |
| `SIGSTORE_OIDC_ISSUER` / `COSIGN_OIDC_ISSUER` | OIDC issuer used by the keyless flow. In a true air-gap you'll likely use key-based attestations instead — see below. |
| `SIGSTORE_ROOT_FILE` | Path to a custom Sigstore TUF root JSON (`root.json`). |
| `TUF_ROOT` | Directory containing TUF metadata (root + targets). |
| `COSIGN_REPOSITORY` | Alternate cosign-data registry, when attestations are stored separately from the artifact's registry. |

bomdrift forwards the unchanged process environment to every cosign
invocation, so exporting the variables on the workflow / shell that
invokes bomdrift is enough — no bomdrift flag is needed.

### Worked example: GitHub Actions against a private Sigstore

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    before-attestation: oci://registry.internal.example/myapp@sha256:abc...
    after-attestation:  oci://registry.internal.example/myapp@sha256:def...
    cosign-identity:    '^https://github.example.internal/.+$'
    cosign-issuer:      https://oidc.internal.example
    require-attestation: 'true'
  env:
    SIGSTORE_REKOR_URL:  https://internal-rekor.example
    COSIGN_FULCIO_URL:   https://internal-fulcio.example
    SIGSTORE_OIDC_ISSUER: https://oidc.internal.example
    TUF_ROOT:            ${{ github.workspace }}/.sigstore/tuf
    SIGSTORE_ROOT_FILE:  ${{ github.workspace }}/.sigstore/tuf/root.json
```

The action's composite step inherits this `env:` block, propagates it to
the bomdrift binary, and bomdrift propagates it again to cosign. No
input on the action surface is needed for any of these — they are
cosign's own contract.

### Key-based (non-keyless) attestations

In a true air-gap, the OIDC keyless flow may not be reachable: there's
no public-good Fulcio CA to mint short-lived certificates, and your
internal OIDC issuer may not be wired up to your internal Fulcio yet.
cosign's fallback is **key-based** attestation:

```bash
cosign attest --key cosign.key --predicate sbom.cdx.json \
  --type cyclonedx registry.internal.example/myapp@sha256:abc...
```

For verification, cosign auto-detects a `cosign.pub` in the working
directory or honors the `COSIGN_PUBLIC_KEY` env var. bomdrift's current
`--cosign-identity` / `--cosign-issuer` flags target the keyless flow;
for the key-based flow, leave them empty (or pass identity values that
match how cosign records key-based attestations) and rely on env-var
passthrough:

```bash
export COSIGN_PUBLIC_KEY=$PWD/cosign.pub
bomdrift diff \
  --before-attestation oci://registry.internal.example/myapp@sha256:abc... \
  --after-attestation  oci://registry.internal.example/myapp@sha256:def...
```

cosign reads `COSIGN_PUBLIC_KEY` directly when no certificate-identity
flags are present. bomdrift forwards the env unchanged, so no
bomdrift-side configuration is required.

### Troubleshooting checklist

When verification fails in an air-gapped setup, walk this list:

1. **`Error: updating local metadata and targets`** — TUF can't reach
   the configured TUF repo. Verify `TUF_ROOT` points at a directory
   pre-populated with your org's TUF metadata, and that
   `SIGSTORE_ROOT_FILE` references a valid `root.json`.
2. **`Error: getting Rekor public keys`** — Rekor URL is unreachable
   from the runner. `curl -v "$SIGSTORE_REKOR_URL/api/v1/log/publicKey"`
   from the same runner identity to confirm network reachability.
3. **`x509: certificate signed by unknown authority`** — your private
   Fulcio's intermediate CA isn't in the system trust store. Either
   install it on the runner image, or set `SSL_CERT_FILE` to a bundle
   that includes it.
4. **`Error: no matching signatures`** with key-based attestations —
   cosign found the attestation but the public key didn't match. Confirm
   `COSIGN_PUBLIC_KEY` resolves to the same key that signed the
   attestation, and that no `--cosign-identity` / `--cosign-issuer`
   values are present (those force the keyless code path).
5. **`Error: dial tcp: lookup rekor.sigstore.dev`** — cosign fell back
   to the public-good defaults because one of the SIGSTORE\_\* env vars
   wasn't actually exported into bomdrift's process. On GitHub Actions,
   double-check the `env:` block lives on the same step as the action
   (or a parent `jobs.<id>.env:` block), not on a different step.
6. **Verification works locally but not in CI** — the runner image lacks
   cosign, or cosign was installed but `PATH` isn't propagated to the
   composite-action subshell. The `verify-signatures: true` codepath
   already installs cosign for release signature verification; reuse
   that install or pin a known cosign version explicitly.

The air-gapped path uses cosign's own contract, so any deeper diagnosis
is a cosign problem, not a bomdrift problem. Reproduce with `cosign
verify-attestation --type cyclonedx ...` directly, with the same env
vars exported, before opening a bomdrift issue.

## Troubleshooting

### `executable file not found in $PATH: cosign`

bomdrift couldn't find cosign on `PATH`. Install per
[Prerequisites](#prerequisites), or set `PATH` so the cosign binary
is reachable from the bomdrift process.

### `Error: no matching signatures`

The cosign verification rejected every attached signature. Most
common cause: `--cosign-identity` regex doesn't match the actual
certificate SAN. Debug with cosign directly first:

```bash
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp '<your-regex>' \
  --certificate-oidc-issuer    '<your-issuer>' \
  ghcr.io/myorg/myapp@sha256:abc...
```

If cosign's own output is more revealing, you've isolated the
problem outside bomdrift.

### `predicate type mismatch` / `no attestations of the requested type`

The OCI reference has attestations, but none of type `cyclonedx`.
bomdrift only consumes CycloneDX SBOM attestations in v0.9.6 — see
the next section.

### `Error: parsing CycloneDX: ...`

cosign verified the envelope but bomdrift couldn't parse the
predicate body as CycloneDX. Inspect the raw predicate by running
the cosign command above with `-o json` and look at
`payload.predicate`.

## What's NOT in v0.9.6

- **SPDX SBOM attestations.** Only CycloneDX. SPDX-attestation
  support is a future ask; file an issue if you need it. The
  predicate parser is the only piece that needs to grow.
- **Direct Rekor verification.** Deferred to cosign. bomdrift will
  not grow a Sigstore client implementation.
- **Air-gapped Sigstore.** Documented as a first-class flow via
  cosign-respected env-var passthrough; see
  [Air-gapped / self-hosted Sigstore](#air-gapped--self-hosted-sigstore).
- **In-process attestation (no shell-out).** Pulling in a
  full-fat Sigstore Rust SDK contradicts the OSS-first /
  small-dep-tree design constraint. Revisit once a minimal,
  audited Rust Sigstore client exists.

## Related

- [Plugins](./plugins.md) — for verifying additional org-specific
  signals on attested SBOMs.
- [Output formats](./output-formats.md) — verified diffs render
  identically to file-based diffs.
- [Roadmap](./roadmap.md) — for the broader v0.9.6 dispositions.
