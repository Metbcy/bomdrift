# Release signing

Every bomdrift release archive is signed with [cosign keyless](https://docs.sigstore.dev/)
via Sigstore + GitHub OIDC. This means:

- The signing key is **not** stored in the repo or in any GitHub Secret.
- Each signature is bound to the GitHub Actions workflow run that
  produced it, with the OIDC issuer
  (`token.actions.githubusercontent.com`) acting as the identity
  provider.
- The signing transparency log is the public Sigstore Rekor instance.

## Verifying a release manually

```bash
VERSION=v0.3.0
TARGET=x86_64-unknown-linux-gnu
ARCHIVE=bomdrift-${VERSION}-${TARGET}.tar.gz

# Download the archive + signature + certificate
BASE="https://github.com/Metbcy/bomdrift/releases/download/${VERSION}"
curl -fsSL -O "${BASE}/${ARCHIVE}"
curl -fsSL -O "${BASE}/${ARCHIVE}.sig"
curl -fsSL -O "${BASE}/${ARCHIVE}.pem"

# Verify
cosign verify-blob \
  --certificate-identity "https://github.com/Metbcy/bomdrift/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate "${ARCHIVE}.pem" \
  --signature  "${ARCHIVE}.sig" \
  "${ARCHIVE}"
```

A successful verification prints `Verified OK`. Anything else means the
archive has been tampered with (or the certificate's identity doesn't
match the expected workflow run — same outcome, do not trust).

## What the certificate identity proves

The `--certificate-identity` argument pins the verification to the
**exact workflow file** that produced the signature, including the tag
ref. As long as `release.yml` is the only workflow that ever signs
bomdrift archives (it is, and the file is reviewed in PRs), an
attacker who can't push to the bomdrift repo can't produce a verifiable
signature.

The `--certificate-oidc-issuer` pins to GitHub's OIDC issuer.
Substituting a different IDP-backed signature wouldn't pass.

## Action-side verification (default)

The `Metbcy/bomdrift` action calls `cosign verify-blob` automatically
on every download (when `verify-signatures: true`, the default). When
verification fails, the action exits non-zero **before** running
bomdrift, so a tampered binary never executes.

To skip verification (saves ~15s by also skipping the cosign-installer
step), set:

```yaml
- uses: Metbcy/bomdrift@v1
  with:
    before-sbom: before.json
    after-sbom:  after.json
    verify-signatures: false
```

This is appropriate when:

- You're running on self-hosted runners with a hardened image you
  control.
- You've pre-pinned the bomdrift archive in your Nexus/Artifactory
  mirror and verified its signature once at mirror time.
- You're running in a network-restricted environment where the
  public Sigstore endpoints aren't reachable.

When `verify-signatures: true` and cosign isn't installed (or the
`.sig` / `.pem` aren't on the release), the action fails loudly
rather than silently degrading — that's the whole point of the
explicit opt-out.

## Why keyless?

The traditional alternative is a long-lived signing key stored as a
GitHub Secret. That's:

- A **single credential** that, if leaked, lets an attacker sign
  forever.
- A **rotation problem** — every key rotation breaks all consumers
  who pinned the verifying public key.
- An **audit gap** — there's no public record of who signed what
  when.

Keyless cosign moves the trust to the GitHub OIDC issuer + the
Sigstore Rekor transparency log: every signature has a public,
queryable record of the exact GitHub Actions workflow run that
produced it, and the signing certificate is short-lived (10 minutes).

## SHA-256 checksums

In addition to cosign, every archive ships with a `.sha256` file for
old-school checksum verification:

```bash
curl -fsSL -O "${BASE}/${ARCHIVE}.sha256"
sha256sum -c "${ARCHIVE}.sha256"   # GNU
shasum -a 256 -c "${ARCHIVE}.sha256"  # macOS
```

Checksums alone don't authenticate the archive (an attacker who can
modify the `.tar.gz` can also modify the `.sha256`); cosign is the
authoritative verification path. The checksums exist for older toolchains
and for quick local-rerun checks.
