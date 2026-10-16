#!/usr/bin/env bash
# Build CbMpc.xcframework for iOS (device arm64 + simulator arm64): per slice one static
# libcbmpc.a = cb-mpc (core/crypto/zk/protocol, the public C++ API and the upstream C API except its
# PVE files, i.e. what the kexify iOS app compiles today) + the cb-mpc-ts C ABI (capi/cbmpc_ts.cpp)
# + static OpenSSL 3.6.4. Headers: cbmpc_ts.h, cbmpc/c_api/*.h and openssl/*.h (the app's bridge
# uses OpenSSL directly; it must use these, not a second libcrypto).
# App-specific glue (e.g. a Swift bridge) is compiled by the app and links against it.
# No CMake: upstream cmake/arch.cmake rejects iPhone SDKs. Flags mirror cb-mpc-ts/native/CMakeLists.txt.
# OpenSSL: built per slice like scripts/openssl/build-static-openssl-macos-m1.sh (same tarball hash,
# patch and no-* options) with an iOS target; reuse a build with CBMPC_IOS_OPENSSL_<SIM|DEVICE>=<prefix>.
# Usage (repo root, macOS + Xcode): scripts/native-artifacts/build-ios-xcframework.sh <outdir>
#   -> <outdir>/cbmpc-native-ios.xcframework.zip
set -euo pipefail
OUT=$1
IOS_MIN=${IOS_MIN:-15.0}
W="${CBMPC_ARTIFACT_WORK:-$PWD/build/native-artifact-ios}"
ROOT=$PWD
V=3.6.4
HASH=9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef
mkdir -p "$W/dl" "$OUT"

openssl_ios() { # <sim|device> -> prints the install prefix
  local kind=$1 target sdk min prefix src tb
  local reuse_var="CBMPC_IOS_OPENSSL_$(echo "$kind" | tr a-z A-Z)"
  if [ -n "${!reuse_var:-}" ]; then echo "${!reuse_var}"; return; fi
  prefix="$W/openssl-$kind"
  if [ -f "$prefix/lib/libcrypto.a" ]; then echo "$prefix"; return; fi
  tb="$W/dl/openssl-$V.tar.gz"
  [ -f "$tb" ] || curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-$V/openssl-$V.tar.gz" -o "$tb"
  [ "$(shasum -a 256 "$tb" | cut -d' ' -f1)" = "$HASH" ] || { echo "OpenSSL SHA256 mismatch" >&2; exit 1; }
  src="$W/openssl-src-$kind"; rm -rf "$src"; mkdir -p "$src"
  tar -xzf "$tb" -C "$src" --strip-components=1
  sed -i '' -e 's/^static//' "$src/crypto/ec/curve25519.c" # same patch as scripts/openssl
  if [ "$kind" = sim ]; then target=iossimulator-arm64-xcrun; sdk=iphonesimulator; min="-mios-simulator-version-min=$IOS_MIN"
  else target=ios64-xcrun; sdk=iphoneos; min="-miphoneos-version-min=$IOS_MIN"; fi
  (
    cd "$src"
    export CROSS_TOP; CROSS_TOP="$(xcrun --sdk $sdk --show-sdk-platform-path)/Developer"
    export CROSS_SDK; CROSS_SDK="$(basename "$(xcrun --sdk $sdk --show-sdk-path)")"
    ./Configure $target -static -DOPENSSL_THREADS no-shared $min \
      no-afalgeng no-apps no-aria no-autoload-config no-bf no-camellia no-cast no-chacha no-cmac no-cms no-crypto-mdebug \
      no-comp no-cmp no-ct no-des no-dh no-dgram no-dsa no-dso no-dtls no-dynamic-engine no-ec2m no-egd no-engine no-external-tests \
      no-gost no-http no-idea no-mdc2 no-md2 no-md4 no-module no-nextprotoneg no-ocb no-ocsp no-psk no-padlockeng no-poly1305 \
      no-quic no-rc2 no-rc4 no-rc5 no-rfc3779 no-scrypt no-sctp no-seed no-siphash no-sm2 no-sm3 no-sm4 no-sock no-srtp no-srp \
      no-ssl-trace no-ssl3 no-stdio no-tests no-tls no-ts no-unit-test no-uplink no-whirlpool no-zlib --prefix="$prefix" >"$W/openssl-$kind.log" 2>&1
    make -j"$(sysctl -n hw.ncpu)" build_libs >>"$W/openssl-$kind.log" 2>&1
    make install_dev >>"$W/openssl-$kind.log" 2>&1
  ) || { tail -40 "$W/openssl-$kind.log" >&2; exit 1; }
  echo "$prefix"
}

slice() { # <sim|device> -> <W>/slice-<kind>/libcbmpc.a
  local kind=$1 sdk tgt sysroot ossl obj lib
  if [ "$kind" = sim ]; then sdk=iphonesimulator; tgt="arm64-apple-ios$IOS_MIN-simulator"; else sdk=iphoneos; tgt="arm64-apple-ios$IOS_MIN"; fi
  sysroot=$(xcrun --sdk $sdk --show-sdk-path)
  ossl=$(openssl_ios "$kind")
  obj="$W/slice-$kind/obj"; lib="$W/slice-$kind/libcbmpc.a"
  rm -rf "$obj"; mkdir -p "$obj"
  # Arrays are declared before assignment: bash 3.2 (macOS) does not expand globs in `local a=(...)`.
  local flags sources n
  flags=(-target "$tgt" -isysroot "$sysroot" -std=c++17 -fPIC -O3 -DNDEBUG -fno-operator-names
    -DNO_DEPRECATED_OPENSSL -fexceptions -Wno-everything
    -I"$ROOT/include" -I"$ROOT/include-internal" -I"$ROOT/src" -I"$ROOT/cb-mpc-ts/capi" -I"$ROOT/vendors" -I"$ossl/include")
  sources=("$ROOT"/src/cbmpc/{core,crypto,zk,protocol,api}/*.cpp "$ROOT/cb-mpc-ts/capi/cbmpc_ts.cpp")
  local f
  for f in "$ROOT"/src/cbmpc/c_api/*.cpp; do
    case "$f" in */c_api/pve_*) ;; *) sources+=("$f") ;; esac # C-API PVE needs extra error headers
  done
  printf '%s\n' "${sources[@]}" | xargs -P"$(sysctl -n hw.ncpu)" -I{} sh -c \
    'xcrun clang++ "$@" -c "$0" -o "'"$obj"'/$(echo "$0" | shasum | cut -c1-16).o"' {} "${flags[@]}" >&2 \
    || { echo "compile failed ($kind)" >&2; return 1; }
  n=$(ls "$obj" | wc -l | tr -d ' ')
  [ "$n" -eq "${#sources[@]}" ] || { echo "expected ${#sources[@]} objects, got $n ($kind)" >&2; return 1; }
  # One archive per slice with OpenSSL folded in, so the app links a single library.
  rm -f "$lib"
  xcrun libtool -static -o "$lib" "$obj"/*.o "$ossl/lib/libcrypto.a" >&2
  echo "$lib"
}

HEADERS="$W/headers"
rm -rf "$HEADERS"; mkdir -p "$HEADERS/cbmpc/c_api"
cp cb-mpc-ts/capi/cbmpc_ts.h "$HEADERS/"
for h in include/cbmpc/c_api/*.h; do
  case "$h" in */pve_*) ;; *) cp "$h" "$HEADERS/cbmpc/c_api/" ;; esac # C-API PVE is not compiled in
done
cp -R "$(openssl_ios device)/include/openssl" "$HEADERS/" # same headers for both slices

DEVICE_LIB=$(slice device) || exit 1
SIM_LIB=$(slice sim) || exit 1
XCF="$W/CbMpc.xcframework"
rm -rf "$XCF"
xcodebuild -create-xcframework -library "$DEVICE_LIB" -headers "$HEADERS" -library "$SIM_LIB" -headers "$HEADERS" -output "$XCF" >/dev/null
cp LICENSE.md "$XCF/"
(cd "$W" && rm -f cbmpc-native-ios.xcframework.zip && ditto -c -k --keepParent CbMpc.xcframework cbmpc-native-ios.xcframework.zip)
mv "$W/cbmpc-native-ios.xcframework.zip" "$OUT/"
echo "packaged $OUT/cbmpc-native-ios.xcframework.zip"
