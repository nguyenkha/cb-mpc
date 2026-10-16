#!/usr/bin/env bash
# Build cb-mpc-ts/prebuilds/linux-<arch>/libcbmpc.so for the host architecture
# inside a manylinux_2_28 container (AlmaLinux 8, glibc 2.28), so the result
# loads on any distro with glibc >= 2.28 (Debian 10+, Ubuntu 18.10+, RHEL/Alma 8+,
# Amazon Linux 2023). Building on a current distro instead ties the library to
# that distro's glibc (e.g. ubuntu-24.04 -> glibc 2.38+, which Debian 12 lacks).
# The C++ runtime is linked statically (see native/CMakeLists.txt).
#
# CBMPC_LINUX_LIBC=musl builds the Alpine (musl) variant instead, installed as
# prebuilds/linux-<arch>-musl/.
#
# Usage (from the repo root, needs docker): cb-mpc-ts/scripts/build-linux-prebuild.sh
set -euo pipefail
LIBC=${CBMPC_LINUX_LIBC:-glibc}
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac
if [ "$LIBC" = musl ]; then
  IMAGE=${CBMPC_LINUX_BUILD_IMAGE:-alpine:3.22}
  docker run --rm -v "$PWD":/src -w /src "$IMAGE" sh -euc '
    apk add -q --no-cache bash build-base cmake perl linux-headers curl binutils >/dev/null
    CBMPC_OPENSSL_ROOT=/opt/openssl bash scripts/openssl/build-static-openssl-linux.sh >/tmp/openssl.log 2>&1 \
      || { tail -40 /tmp/openssl.log; exit 1; }
    rm -rf build/native-linux-musl
    cmake -B build/native-linux-musl -S cb-mpc-ts/native -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCBMPC_OPENSSL_ROOT=/opt/openssl \
      -DCBMPC_PREBUILD_SUFFIX=-musl >/dev/null
    cmake --build build/native-linux-musl -- -j"$(nproc)"
    CBMPC_LIBC=musl bash cb-mpc-ts/scripts/check-linux-prebuild.sh cb-mpc-ts/prebuilds/linux-*-musl/libcbmpc.so
  '
  exit 0
fi
IMAGE=${CBMPC_LINUX_BUILD_IMAGE:-quay.io/pypa/manylinux_2_28_${arch}}
docker run --rm -v "$PWD":/src -w /src "$IMAGE" bash -euo pipefail -c '
  dnf install -y -q perl >/dev/null  # full perl: OpenSSL 3 needs IPC::Cmd, Time::Piece, ...
  CBMPC_OPENSSL_ROOT=/opt/openssl bash scripts/openssl/build-static-openssl-linux.sh >/tmp/openssl.log 2>&1 \
    || { tail -40 /tmp/openssl.log; exit 1; }
  rm -rf build/native-linux
  cmake -B build/native-linux -S cb-mpc-ts/native -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCBMPC_OPENSSL_ROOT=/opt/openssl >/dev/null
  cmake --build build/native-linux -- -j"$(nproc)"
  MAX_GLIBC=2.28 bash cb-mpc-ts/scripts/check-linux-prebuild.sh cb-mpc-ts/prebuilds/linux-*/libcbmpc.so
'
