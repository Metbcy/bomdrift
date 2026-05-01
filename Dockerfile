# syntax=docker/dockerfile:1.7

# bomdrift container image — distroless cc, multi-arch (linux/amd64, linux/arm64).
#
# Two-stage by design: the first stage runs on $BUILDPLATFORM (the
# host runner's native arch) and picks the right pre-built bomdrift
# binary based on $TARGETARCH; the second stage is the actual
# distroless runtime image.
#
# Why two stages? `COPY dist/linux-${TARGETARCH}/bomdrift /bomdrift`
# in a single-stage Dockerfile is fragile across buildx versions —
# the variable doesn't always expand reliably inside COPY paths, and
# v0.9.9's first release attempt hit exactly that bug (TARGETARCH
# expanded to empty, producing `dist/linux-/bomdrift: not found`).
# The workaround: COPY both arches in unconditionally during a
# BUILDPLATFORM-only stage, then use TARGETARCH inside a RUN command
# (which always expands correctly) to choose the right one. The
# final stage just COPY --from=pick.
#
# This Dockerfile consumes pre-built per-arch binaries that the release
# pipeline (.github/workflows/release.yml) stages under
# dist/linux-${arch}/bomdrift. There is no `cargo build` in the image;
# the bytes baked into ghcr.io are exactly the cosign-signed artifacts
# attached to the corresponding GitHub Release.
#
# Image base is gcr.io/distroless/cc-debian12 (supports glibc; ~22 MB
# base + ~6 MB stripped binary). Runs as the distroless `nonroot` user.
#
# Local development:
#
#   cargo build --release
#   mkdir -p dist/linux-amd64 dist/linux-arm64
#   cp target/release/bomdrift dist/linux-amd64/
#   cp target/release/bomdrift dist/linux-arm64/   # if you only have one arch
#   docker buildx build --platform linux/amd64 -t bomdrift:local --load .
#   docker run --rm bomdrift:local --version

FROM --platform=$BUILDPLATFORM busybox:stable AS pick
ARG TARGETARCH
COPY dist/linux-amd64/bomdrift /bins/linux-amd64/bomdrift
COPY dist/linux-arm64/bomdrift /bins/linux-arm64/bomdrift
RUN cp "/bins/linux-${TARGETARCH}/bomdrift" /bomdrift && chmod +x /bomdrift

# Debian 13 (Trixie, GLIBC 2.41) — matches the GLIBC 2.39 the
# bomdrift binaries pick up from the GitHub Actions ubuntu-latest
# runner. Don't downgrade to debian12 (GLIBC 2.36) without first
# moving the release matrix to ubuntu-22.04, or the binary will fail
# to load with `version 'GLIBC_2.39' not found`.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=pick /bomdrift /bomdrift
USER nonroot
ENTRYPOINT ["/bomdrift"]

