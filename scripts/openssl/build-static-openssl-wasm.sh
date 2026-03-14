#!/usr/bin/env bash
#
# Build a static OpenSSL 3.2.0 for WebAssembly using Emscripten.
#
# Prerequisites:
#   - Emscripten SDK (emsdk) installed and activated
#   - EMSDK environment variable set (e.g., source emsdk_env.sh)
#
# The output is installed to ${CBMPC_OPENSSL_ROOT:-/usr/local/opt/openssl@3.2.0-wasm}.

set -euo pipefail

OPENSSL_VERSION="3.2.0"
OPENSSL_SHA256="14c826f07c7e433706fb5c69fa9e25dab95684844b4c962a2cf1bf183eb4690e"
INSTALL_PREFIX="${CBMPC_OPENSSL_ROOT:-/usr/local/opt/openssl@3.2.0-wasm}"

# Verify Emscripten is available
if ! command -v emcc &>/dev/null; then
  echo "ERROR: emcc not found. Please install and activate Emscripten SDK first."
  echo "  git clone https://github.com/emscripten-core/emsdk.git"
  echo "  cd emsdk && ./emsdk install latest && ./emsdk activate latest"
  echo "  source emsdk_env.sh"
  exit 1
fi

echo "=== Building OpenSSL ${OPENSSL_VERSION} for WebAssembly ==="
echo "Install prefix: ${INSTALL_PREFIX}"

cd /tmp

# Download if not already present
if [ ! -f "openssl-${OPENSSL_VERSION}.tar.gz" ]; then
  curl -L "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    --output "openssl-${OPENSSL_VERSION}.tar.gz"
fi

# Verify checksum
if command -v sha256sum &>/dev/null; then
  fileHash=$(sha256sum "openssl-${OPENSSL_VERSION}.tar.gz" | cut -d " " -f 1)
elif command -v shasum &>/dev/null; then
  fileHash=$(shasum -a 256 "openssl-${OPENSSL_VERSION}.tar.gz" | cut -d " " -f 1)
else
  echo "WARNING: No sha256 tool found, skipping checksum verification"
  fileHash="${OPENSSL_SHA256}"
fi

if [ "${OPENSSL_SHA256}" != "${fileHash}" ]; then
  echo "ERROR: SHA256 DOES NOT MATCH!"
  echo "expected: ${OPENSSL_SHA256}"
  echo "file:     ${fileHash}"
  exit 1
fi

# Clean previous build and extract fresh copy
rm -rf "openssl-${OPENSSL_VERSION}-wasm"
tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz"
mv "openssl-${OPENSSL_VERSION}" "openssl-${OPENSSL_VERSION}-wasm"
cd "openssl-${OPENSSL_VERSION}-wasm"

# Apply the same patch as the native build (expose curve25519 symbols)
sed -i.bak -e 's/^static//' crypto/ec/curve25519.c

# Configure for WASM.
# Set CC/AR/RANLIB explicitly — emconfigure can corrupt the compiler path
# when used with OpenSSL's Configure script.
CC=emcc AR=emar RANLIB=emranlib ./Configure linux-generic32 \
  --prefix="${INSTALL_PREFIX}" \
  --libdir=lib \
  -static \
  -no-asm \
  -no-shared \
  -no-async \
  -no-dso \
  -no-engine \
  -DOPENSSL_NO_SECURE_MEMORY \
  -DOPENSSL_THREADS \
  no-afalgeng no-apps no-aria no-autoload-config no-bf no-camellia no-cast \
  no-chacha no-cmac no-cms no-crypto-mdebug no-comp no-cmp no-ct no-des \
  no-dh no-dgram no-dsa no-dtls no-dynamic-engine no-ec2m no-egd \
  no-external-tests no-gost no-http no-idea no-mdc2 no-md2 no-md4 \
  no-module no-nextprotoneg no-ocb no-ocsp no-psk no-padlockeng \
  no-poly1305 no-quic no-rc2 no-rc4 no-rc5 no-rfc3779 no-scrypt no-sctp \
  no-seed no-siphash no-sm2 no-sm3 no-sm4 no-sock no-srtp no-srp \
  no-ssl-trace no-ssl3 no-stdio no-tests no-tls no-ts no-unit-test \
  no-uplink no-whirlpool no-zlib \
  -fPIC

# Ensure the Makefile uses emcc (not the host cc)
sed -i.bak 's|^CC=.*|CC=emcc|' Makefile
sed -i.bak 's|^AR=.*|AR=emar|' Makefile
sed -i.bak 's|^RANLIB=.*|RANLIB=emranlib|' Makefile
sed -i.bak 's|^CNF_CFLAGS=.*|CNF_CFLAGS=-DOPENSSL_NO_SECURE_MEMORY|' Makefile

make build_generated -j4
make libcrypto.a -j4

# Install headers and library
mkdir -p "${INSTALL_PREFIX}/lib" "${INSTALL_PREFIX}/include"
cp libcrypto.a "${INSTALL_PREFIX}/lib/"
cp -r include/openssl "${INSTALL_PREFIX}/include/"

echo "=== OpenSSL ${OPENSSL_VERSION} WASM build complete ==="
echo "Installed to: ${INSTALL_PREFIX}"
