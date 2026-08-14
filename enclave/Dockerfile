# The enclave image. Its measurement (PCR0) is what every Cavos browser checks
# before encrypting a user's credential, so this file is part of the security
# boundary: anything that changes the built bytes changes PCR0 and breaks every
# installed copy of @cavos/kit until the new measurement is published.
#
# Build it with `scripts/build-enclave.sh`, never with a bare `docker build`.
# That script sets SOURCE_DATE_EPOCH and BuildKit's timestamp rewriting, which
# is what makes two independent builds of the same source produce the same
# PCR0. Without them the image config carries a wall-clock `created` timestamp
# and the measurement changes on every build — verified, not assumed.
#
# Base images are pinned by digest rather than tag. A tag is a moving pointer;
# if `rust:1.93-bookworm` were re-published the measurement would change with no
# change to this repository, and a published PCR0 nobody can reproduce is worse
# than no PCR0 at all.

FROM rust:1.93-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# `--locked` refuses to update Cargo.lock: dependency resolution must be a
# property of the committed source, not of when the build happened.
RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:adcd20c7b4c988b73cbfbddb26d2eee574571e6d7c9ffea29b3821e0690efb77
COPY --from=build /src/target/release/cavos-confidential-recovery /workload
USER nonroot:nonroot
ENTRYPOINT ["/workload"]
