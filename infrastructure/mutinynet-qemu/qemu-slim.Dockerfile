# The QEMU image the enclave harness runs, without the toolchain that built it.
#
# enclave-runtime's deploy/qemu-nitro/Dockerfile compiles QEMU with the nitro-enclave machine and
# keeps the compilers: 3.7 GB. Running needs the binaries and their shared libraries: ~100 MB
# compressed, which is what makes shipping it to the host cheap. Build the full image first.
FROM s3fs-qemu-nitro:latest AS built

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0t64 libpixman-1-0 libslirp0 libcbor0.10 libgnutls30t64 \
        libfdt1 libzstd1 zlib1g libaio1t64 liburing2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=built /usr/local /usr/local
COPY --from=built /qemu-version /qemu-version
# Fails the build, not the boot, if a library is missing.
RUN ! ldd /usr/local/bin/qemu-system-x86_64 | grep -q "not found" \
 && qemu-system-x86_64 -M help | grep -qi nitro
WORKDIR /work
