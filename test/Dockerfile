# Conformance test image for smb-server-rs: builds the workspace and runs the
# Rust integration suite against a locally-started rustsmb, recording results.
#
# Build:
#   docker build -f test/Dockerfile -t smb-server-rs-test .
#
# Run (io_uring needs a permissive seccomp profile inside containers):
#   docker run --rm --security-opt seccomp=unconfined \
#     -v "$PWD/test/data:/work/test/data" smb-server-rs-test
#
# Results are written to the mounted test/data/ so history persists on the host.

# ---- build stage ----
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY src ./src
RUN cargo build --release -p smb-server -p smb-server-testsuite

# ---- runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip git ca-certificates \
    && pip3 install --no-cache-dir --break-system-packages smbprotocol \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY --from=build /src/target/release/rustsmb /usr/local/bin/rustsmb
COPY --from=build /src/target/release/smb-testrunner /usr/local/bin/smb-testrunner
COPY test/driver /work/test/driver
COPY test/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV SMB_TEST_PYTHON=python3 \
    SMB_TEST_DRIVER=/work/test/driver/smb_driver.py \
    PORT=4450 \
    DATA_DIR=/work/test/data
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
