# About this fork

`nguyenkha/cb-mpc` is a fork of [coinbase/cb-mpc](https://github.com/coinbase/cb-mpc)
that ships the library to JavaScript/TypeScript as the npm package
[`cb-mpc`](https://www.npmjs.com/package/cb-mpc) (WebAssembly + native prebuilds),
and adds a few protocol features on top.

- **Upstream base:** coinbase/cb-mpc `v0.2.2` + coinbase/cb-mpc#137 (`0b71670`).
- **npm package:** see the version table in [cb-mpc-ts/README.md](cb-mpc-ts/README.md).
- Everything that is not listed below is upstream code, unchanged.

## 1. Fork-only additions (no upstream equivalent)

These live in files upstream does not have, so upstream merges do not touch them.

| Path | What |
|---|---|
| `cb-mpc-ts/` | The TypeScript package: WASM backend (Emscripten), native backends (`bun:ffi`, koffi), examples, tests. |
| `cb-mpc-ts/capi/` | C ABI used by the package. Replaces the Go cgobinding that upstream removed in v0.2.0; keeps the 0.1.x symbols and key serialization so old keys still load. |
| `cb-mpc-ts/capi/hd_keyset.{h,inc}` | HD keysets for 2-party ECDSA/EdDSA on top of upstream's internal HD code: derive, account node / xpub, upgrade an existing key. Upstream only exposes HD in its C++ API (no chain code / xpub). |
| `cb-mpc-ts/scripts/` | Test suites: `hd.ts`, `error-paths.ts`, `native-mp/` (one worker per party, bun:ffi + koffi), `c-interop/` (JS parties vs upstream's C API), `compat-npm.ts` (vs published releases), `compat-reshare.ts` (2-of-2 shares from 0.1.x reshared to 2-of-3); portable Linux build + checks. |
| `scripts/openssl/build-static-openssl-wasm.sh` | OpenSSL 3.6.4 for wasm32. |
| `.github/workflows/build-prebuilds.yml` | Builds WASM and native prebuilds (Linux glibc/musl x64/arm64 in old-glibc / Alpine containers, macOS arm64), smoke-tests them on Debian 11/12 and Alpine, publishes to npm on `v*` tags. |
| `Makefile` (`wasm`, `native` targets) | Local WASM / native builds of the package. |

## 2. Changes to upstream files

These are the places an upstream merge can conflict. Each one is small and listed
with its reason.

### WebAssembly portability (wasm32: 32-bit `BN_ULONG`, 32-bit `unsigned long`)

| File | Change |
|---|---|
| `include/cbmpc/core/precompiled.h` | Skip Linux/Unix-only headers under `__EMSCRIPTEN__`. |
| `include-internal/cbmpc/internal/crypto/base_bn256.h`, `src/cbmpc/crypto/base_bn256.cpp`, `src/cbmpc/crypto/drbg.cpp` | `addx`/`subx` use `__builtin_addcll`; modulus, Barrett mu and Montgomery RR are read through `bn_words_t` (zero-copy with 64-bit limbs) and a 64-bit Montgomery `n0` is derived when OpenSSL only has a 32-bit one. **Native 64-bit code paths are unchanged.** |
| `src/cbmpc/crypto/base_ec_core.cpp` | `booth_wnaf_t` bounds the limb copy by bytes instead of asserting 64-bit limbs. |
| `src/cbmpc/crypto/base_mod.cpp` | WASM only: variable-time modular arithmetic by default (see section 3). |
| `cmake/openssl.cmake`, `cmake/compilation_flags.cmake` | WASM OpenSSL location and arch. |

### Protocol additions

| File | Change |
|---|---|
| `src/cbmpc/protocol/ec_dkg_reshare.cpp` (new), `include-internal/.../ec_dkg.h`, `src/cbmpc/protocol/ec_dkg.cpp` | `reshare_from_additive`: move a key from an additive sharing to a new access structure (e.g. 2-of-3, lost-device replacement) keeping the public key; `ac_key_to_additive_share`. |
| `src/cbmpc/protocol/ec_dkg.cpp` | **Security fix:** `refresh_ac` binds `Q` and all `Qis` in its consistency check. Upstream lets parties holding blobs of different generations or different keys "succeed" and silently corrupt their shares (a stale blob could bring a revoked device back). |
| `include/cbmpc/api/{ecdsa,eddsa}_mp.h`, `src/cbmpc/api/{ecdsa,eddsa}_mp.cpp`, `src/cbmpc/api/reshare_util.h` | Public C++ API for the above. |
| `include/cbmpc/c_api/{ecdsa,eddsa}_mp.h`, `src/cbmpc/c_api/{ecdsa,eddsa}_mp.cpp` | C API: `cbmpc_{ecdsa,eddsa}_mp_reshare_from_additive`, `cbmpc_{ecdsa,eddsa}_mp_ac_key_to_additive_share`. |
| `tests/unit/...` | Tests for the above (upstream's `ctest` suite still passes). |

### CI

| File | Change |
|---|---|
| `Dockerfile` | Base image pulled from `mirror.gcr.io`, pinned by digest (public.ecr.aws rate-limits GitHub runners). |
| `.github/workflows/codeql.yml` | Drop gtest-registration false positives before upload. |

## 3. Security-relevant differences

- **WebAssembly is outside upstream's support.** Upstream supports 64-bit macOS and
  Linux only. In the WASM build the modular arithmetic is variable-time (upstream's
  constant-time Barrett code needs 64-bit limbs). This is the same as cb-mpc-ts 0.1.x.
  Prefer the native backends for long-running servers.
- **Stricter than upstream:** `refresh_ac` key binding (above); cb-mpc-ts validates
  every key share when it is deserialized (same checks as upstream's public-API
  blobs), and C++ exceptions never cross the C ABI.
- **HD account node:** the hardened step is re-implemented in `capi/hd_keyset.inc`
  (upstream keeps the chain code internal). `cb-mpc-ts/scripts/hd.ts` checks it
  against upstream's `derive_keys` and a standard BIP32 library, and runs in CI
  before every publish.

## 4. Compatibility

| | |
|---|---|
| Key shares from cb-mpc-ts 0.1.x | Load and sign in 0.3+ (and back). |
| Protocol messages 0.1.x vs 0.3+ | **Not compatible** (upstream changed its ZK proofs); upgrade all parties together. |
| Upstream C API (`include/cbmpc/c_api`) | Interoperates: a JS party and a C party run DKG/sign together (`scripts/c-interop`). |
| Platforms (native) | Linux glibc >= 2.28 and musl (x64, arm64), macOS 11+ arm64; everything else uses WASM. |

## 5. Updating from upstream

1. `git fetch origin && git merge origin/master` on a branch.
2. Conflicts can only be in the files of section 2; keep upstream's change and
   re-apply the fork's intent.
3. Run upstream's unit tests (`ctest`) and the cb-mpc-ts suites: `scripts/hd.ts`,
   `error-paths.ts`, `native-mp/run.ts`, `c-interop/run.ts`, `compat-npm.ts`,
   and the examples, on WASM and native.
4. The HD drift guard (`npm run test:hd`) must pass; it fails if upstream changed
   its hardened derivation.
