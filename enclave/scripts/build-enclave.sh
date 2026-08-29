#!/usr/bin/env bash
#
# Build the enclave image file and report its measurements.
#
# The point of this script is that anyone can run it and get the same PCR0 that
# @cavos/kit pins. A measurement nobody can reproduce proves nothing: it would
# just be a number Cavos asserts. This makes it checkable.
#
#   ./scripts/build-enclave.sh                     # build and print measurements
#   ./scripts/build-enclave.sh --expect <pcr0>     # ...and fail if it differs
#
# Reproducibility rests on four things, all verified rather than assumed:
#
#   1. base images pinned by digest in the Dockerfile;
#   2. SOURCE_DATE_EPOCH plus BuildKit's `rewrite-timestamp`, without which the
#      image config carries a wall-clock timestamp and PCR0 changes every build;
#   3. `cargo build --locked` against a committed Cargo.lock;
#   4. a pinned nitro-cli version — the tool itself is an input to the EIF, so
#      two versions of it measure the same image differently.
#
# The target platform is an input too. Cavos runs Graviton, so this builds
# linux/arm64; the same source built for amd64 has a different, equally valid
# measurement.

set -euo pipefail

# A fixed epoch, not `now`. The value is arbitrary but must never change, or
# every previously published measurement becomes unreproducible.
SOURCE_DATE_EPOCH=1700000000
export SOURCE_DATE_EPOCH
readonly PLATFORM=linux/arm64
readonly NITRO_CLI_VERSION=1.4.4
readonly IMAGE=cavos-enclave:reproducible
readonly OUTPUT_DIR=${OUTPUT_DIR:-./build}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here"

expected=""
if [[ ${1:-} == "--expect" ]]; then
  expected=${2:?"--expect needs a PCR0 value"}
fi

echo "==> Building the container image (reproducibly)"
# `--no-cache` so a stale layer cannot hide a source change.
#
# `unpack=false` is required, not incidental: with the containerd image store
# buildx unpacks by default, and unpacking is incompatible with rewriting
# timestamps. Without it the build fails outright.
#
# buildx also attaches provenance/SBOM manifests whose contents vary per run.
# They are deliberately left on: they change the local image ID but not the
# image config or its layers, and nitro-cli measures the image itself — which
# was confirmed by building twice and comparing PCR0, not assumed.
docker buildx build \
  --platform "$PLATFORM" \
  --no-cache \
  --build-arg SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
  --output "type=image,name=$IMAGE,rewrite-timestamp=true,unpack=false" \
  .

mkdir -p "$OUTPUT_DIR"

echo "==> Building the enclave image file"
# nitro-cli runs in a container so the result does not depend on what happens to
# be installed on the machine. It needs the Docker socket to read the image
# built above; building an EIF does not need the /dev/nitro_enclaves device,
# only running one does.
# `-devel` is required, not optional: it ships the kernel and init blobs under
# /usr/share/nitro_enclaves/blobs that the EIF is assembled from. Without it the
# build fails with a bare file-not-found on `cmdline`.
# The version is pinned in the install, not just asserted afterwards. Amazon
# Linux moves this package — it shipped 1.4.5 while this recipe pinned 1.4.4 —
# and an unpinned `dnf install` silently measures the same source differently
# the day the repo rolls forward.
docker build -q --platform "$PLATFORM" -t "cavos-nitro-cli:$NITRO_CLI_VERSION" \
  --build-arg NITRO_CLI_VERSION="$NITRO_CLI_VERSION" - <<'EOF' >/dev/null
FROM amazonlinux:2023
ARG NITRO_CLI_VERSION
RUN dnf install -y \
      "aws-nitro-enclaves-cli-${NITRO_CLI_VERSION}" \
      "aws-nitro-enclaves-cli-devel-${NITRO_CLI_VERSION}"
EOF

# The tool is an input to the measurement, so a version drift must fail loudly
# rather than silently produce a PCR0 nobody else can reproduce.
actual_cli=$(docker run --rm --platform "$PLATFORM" "cavos-nitro-cli:$NITRO_CLI_VERSION" \
  nitro-cli --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
if [[ $actual_cli != "$NITRO_CLI_VERSION" ]]; then
  echo "nitro-cli is $actual_cli but this recipe pins $NITRO_CLI_VERSION." >&2
  echo "Update NITRO_CLI_VERSION and re-publish the measurement." >&2
  exit 1
fi

measurements=$(docker run --rm --platform "$PLATFORM" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(cd "$OUTPUT_DIR" && pwd)":/out \
  "cavos-nitro-cli:$NITRO_CLI_VERSION" \
  nitro-cli build-enclave --docker-uri "$IMAGE" --output-file /out/enclave.eif)

pcr0=$(printf '%s' "$measurements" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Measurements"]["PCR0"])')
pcr1=$(printf '%s' "$measurements" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Measurements"]["PCR1"])')
pcr2=$(printf '%s' "$measurements" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Measurements"]["PCR2"])')

cat <<EOF

==> Measurements

  PCR0 (enclave image)  $pcr0
  PCR1 (kernel + init)  $pcr1
  PCR2 (application)    $pcr2

  EIF: $OUTPUT_DIR/enclave.eif

PCR0 is the value to pin. It goes in two places, and they must agree:
  - kit/src/recovery/attestationDefaults.ts   (what browsers will accept)
  - the KMS key policy's kms:RecipientAttestation:PCR0 condition

Keep the previous value alongside the new one in the SDK for one release, so
apps on either version keep working while the deploy rolls out.
EOF

if [[ -n $expected ]]; then
  if [[ $pcr0 == "$expected" ]]; then
    echo
    echo "==> PCR0 matches the expected measurement"
  else
    echo
    echo "==> PCR0 DOES NOT MATCH"
    echo "    expected $expected"
    echo "    built    $pcr0"
    exit 1
  fi
fi
