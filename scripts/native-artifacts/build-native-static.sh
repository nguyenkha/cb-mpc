#!/usr/bin/env bash
# Build static cb-mpc + the cb-mpc-ts C ABI and static OpenSSL 3.6.4 for this host, then package
# them (package.sh). Linux: run inside quay.io/pypa/manylinux_2_28_x86_64 so the archives need only
# glibc >= 2.28 (native-release.yml does). macOS: deployment target 11.0.
# Usage (repo root): scripts/native-artifacts/build-native-static.sh <linux-x64|darwin-arm64> <outdir>
set -euo pipefail
PLATFORM=$1
OUT=$2
W="${CBMPC_ARTIFACT_WORK:-$PWD/build/native-artifact-$PLATFORM}"
OSSL="$W/openssl"
mkdir -p "$W"
case "$PLATFORM" in
  linux-x64)
    OSSL_SCRIPT=scripts/openssl/build-static-openssl-linux.sh
    CMAKE_EXTRA=(-DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++)
    JOBS=$(nproc)
    ;;
  darwin-arm64)
    export MACOSX_DEPLOYMENT_TARGET=11.0
    OSSL_SCRIPT=scripts/openssl/build-static-openssl-macos-m1.sh
    CMAKE_EXTRA=(-DCMAKE_CXX_COMPILER=clang++ -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0)
    JOBS=$(sysctl -n hw.ncpu)
    ;;
  *) echo "unsupported platform $PLATFORM" >&2; exit 1 ;;
esac

if [ ! -f "$OSSL/lib64/libcrypto.a" ] && [ ! -f "$OSSL/lib/libcrypto.a" ]; then
  CBMPC_OPENSSL_ROOT="$OSSL" bash "$OSSL_SCRIPT" > "$W/openssl.log" 2>&1 || { tail -40 "$W/openssl.log"; exit 1; }
fi
CRYPTO_A="$OSSL/lib64/libcrypto.a"
[ -f "$CRYPTO_A" ] || CRYPTO_A="$OSSL/lib/libcrypto.a"

cmake -B "$W/cmake" -S cb-mpc-ts/native -DCMAKE_BUILD_TYPE=Release -DCBMPC_NATIVE_STATIC=ON \
  -DCBMPC_OPENSSL_ROOT="$OSSL" "${CMAKE_EXTRA[@]}" > "$W/cmake.log"
cmake --build "$W/cmake" --target cbmpc -- -j"$JOBS"
bash scripts/native-artifacts/package.sh "$PLATFORM" "$W/cmake/libcbmpc.a" "$CRYPTO_A" "$OUT"
