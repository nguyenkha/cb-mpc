#!/usr/bin/env bash
# Package one platform's native artifact (what rust/cbmpc-sys downloads):
#   cbmpc-native-<platform>/
#     lib/libcbmpc.a   cb-mpc + cb-mpc-ts C ABI (cb-mpc-ts/native, CBMPC_NATIVE_STATIC=ON)
#     lib/libcrypto.a  static OpenSSL 3.6.4 (scripts/openssl)
#     include/cbmpc_ts.h, include/cbmpc/c_api/cmem.h
#     LICENSE.md, BUILDINFO
#   -> <outdir>/cbmpc-native-<platform>.tar.gz
# Usage (repo root): package.sh <platform> <libcbmpc.a> <libcrypto.a> <outdir>
set -euo pipefail
PLATFORM=$1
CBMPC_A=$2
CRYPTO_A=$3
OUT=$4
NAME="cbmpc-native-$PLATFORM"
STAGE="$(mktemp -d)/$NAME"
mkdir -p "$STAGE/lib" "$STAGE/include/cbmpc/c_api" "$OUT"
cp "$CBMPC_A" "$STAGE/lib/libcbmpc.a"
cp "$CRYPTO_A" "$STAGE/lib/libcrypto.a"
cp cb-mpc-ts/capi/cbmpc_ts.h "$STAGE/include/"
cp include/cbmpc/c_api/cmem.h "$STAGE/include/cbmpc/c_api/"
cp LICENSE.md "$STAGE/"
{
  echo "platform=$PLATFORM"
  echo "commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "ref=${GITHUB_REF_NAME:-local}"
  echo "openssl=3.6.4"
  echo "compiler=$(${CXX:-c++} --version 2>/dev/null | head -1)"
} > "$STAGE/BUILDINFO"
tar -C "$(dirname "$STAGE")" -czf "$OUT/$NAME.tar.gz" "$NAME"
echo "packaged $OUT/$NAME.tar.gz"
