# syntax=docker/dockerfile:1.7

# bomdrift container image — distroless cc, multi-arch (linux/amd64, linux/arm64).
#
# Single-stage by design: this Dockerfile consumes pre-built per-arch
# binaries that the release pipeline (.github/workflows/release.yml)
# stages under dist/linux-${TARGETARCH}/bomdrift. There is no `cargo
# build` in the image; the binaries baked into ghcr.io are exactly the
# cosign-signed artifacts attached to the corresponding GitHub Release.
#
# Image base is gcr.io/distroless/cc-debian12 (supports glibc; ~22 MB
# base + ~6 MB stripped bomdrift binary). Runs as the distroless
# `nonroot` user — every production read of an SBOM in this image is
# intentional and uncovered by privileged-process side effects.
#
# Local development:
#
#   cargo build --release
#   mkdir -p dist/linux-amd64
#   cp target/release/bomdrift dist/linux-amd64/
#   docker buildx build --platform linux/amd64 -t bomdrift:local --load .
#   docker run --rm bomdrift:local --version

ARG TARGETARCH

FROM gcr.io/distroless/cc-debian12:nonroot
ARG TARGETARCH
COPY dist/linux-${TARGETARCH}/bomdrift /bomdrift
USER nonroot
ENTRYPOINT ["/bomdrift"]
