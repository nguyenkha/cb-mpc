# Rust bindings (cbmpc-sys, cbmpc)

Safe Rust API for cb-mpc's 2-party ECDSA and EdDSA (Schnorr-2P) over the cb-mpc-ts C ABI
(`cb-mpc-ts/capi/cbmpc_ts.h`). Keys and protocol messages are byte-compatible with the cb-mpc-ts
npm package (WASM and native) and with shares it stored.

## Native library: where it comes from

`cbmpc-sys` links `libcbmpc.a` (cb-mpc + the C ABI) and a static OpenSSL 3.6.4 `libcrypto.a`.
First match wins:

| Setting | Source |
|---|---|
| `CBMPC_NATIVE_DIR=<dir>` | an unpacked `cbmpc-native-<platform>` artifact; nothing is downloaded or compiled |
| `CBMPC_FROM_SOURCE=1` or `CBMPC_SRC=<checkout>` | CMake build of `cb-mpc-ts/native` (`CBMPC_NATIVE_STATIC=ON`), OpenSSL from `CBMPC_OPENSSL_ROOT` |
| default | download the release artifact pinned in `cbmpc-sys/prebuilt.rs` and check its sha256 |

Targets or crate versions without a pinned artifact fall back to the source build with a warning.
Release artifacts come from `.github/workflows/native-release.yml` on a `v*` tag:
`cbmpc-native-linux-x64.tar.gz` (glibc >= 2.28), `cbmpc-native-darwin-arm64.tar.gz` and
`cbmpc-native-ios.xcframework.zip`, with `SHA256SUMS` and GitHub build provenance
(`gh attestation verify <file> --repo nguyenkha/cb-mpc`). After a release, a PR copies its
SHA256SUMS into `prebuilt.rs`.

Do not link `openssl-sys` into the same binary (use rustls): two libcrypto copies would mix symbols.

## Tests

```bash
cd rust/interop && bun install && cd ..
CBMPC_OPENSSL_ROOT=/usr/local/opt/openssl@3.6.4 CBMPC_FROM_SOURCE=1 cargo test
```

`tests/interop_ts.rs` runs the npm cb-mpc-ts client against the Rust server party
(`CBMPC_REQUIRE_INTEROP=1` makes a missing setup fail). `tests/mdwe.rs` (Linux) runs the protocols
with `PR_SET_MDWE` enforced (`CBMPC_REQUIRE_MDWE=1`).
