# cb-mpc

TypeScript wrapper for the [cb-mpc](https://github.com/coinbase/cb-mpc) cryptographic MPC library.

| cb-mpc (npm) | Based on coinbase/cb-mpc |
|---|---|
| 0.3.x – 0.5.x | [v0.2.2](https://github.com/coinbase/cb-mpc/releases/tag/v0.2.2) + [coinbase/cb-mpc#137](https://github.com/coinbase/cb-mpc/pull/137) |
| 0.1.x | v0.1.0 + 42 commits (before v0.1.1) |

Supports three backends:

- **WASM** (Emscripten) — browsers and Node.js
- **bun:ffi** — Bun runtime (native performance)
- **koffi** — Node.js runtime (native performance)

## Upgrading from 0.1.x

0.3.0 is built on upstream cb-mpc after v0.2.2 (security fixes, including the
ECDSA-2P signing fix in coinbase/cb-mpc#124). The TypeScript API is unchanged.

- **Keys are compatible**: keys serialized by 0.1.x load and sign in 0.3.0, and
  keys serialized by 0.3.0 load in 0.1.x.
- **Protocol messages are not**: upstream changed its zero-knowledge proofs, so a
  0.1.x party and a 0.3.0 party cannot run DKG, sign or refresh together.
  Upgrade every party before the next session.
- 0.3.0 interoperates with upstream's own C API (see `scripts/c-interop`).

## Installation

```bash
npm install cb-mpc
```

For native performance on Node.js, also install koffi:

```bash
npm install koffi
```

## Quick Start

```typescript
import { initCbMpcAuto } from "cb-mpc";

const mpc = await initCbMpcAuto();
```

`initCbMpcAuto` selects the best backend automatically:

1. `bun:ffi` if running in Bun with a prebuilt native library
2. `koffi` if installed with a prebuilt native library
3. WASM fallback (works everywhere)

You can also initialize a specific backend:

```typescript
import { initCbMpc, initCbMpcBunFfi, initCbMpcKoffi } from "cb-mpc";

// WASM (browser / Node.js)
const mpc = await initCbMpc();

// bun:ffi (Bun only)
const mpc = await initCbMpcBunFfi();

// koffi (Node.js)
const mpc = await initCbMpcKoffi();
```

## Supported Protocols

### ECDSA 2-Party

```typescript
// Distributed key generation
const key = await mpc.ecdsa2pDkg(transport, partyIndex, names, NID_secp256k1);

// Signing
const sigs = await mpc.ecdsa2pSign(transport, partyIndex, names, key, sessionId, [msgHash]);

// Key refresh
const newKey = await mpc.ecdsa2pRefresh(transport, partyIndex, names, key);
```

### ECDSA Multi-Party

```typescript
// DKG (returns an EC key share)
const curve = mpc.createCurve(NID_secp256k1);
const key = await mpc.ecKeyMpDkg(transport, partyCount, partyIndex, names, curve);

// Signing
const sig = await mpc.ecdsaMpSign(transport, partyCount, partyIndex, names, key, msgHash, sigReceiver);
```

### EdDSA 2-Party (Schnorr)

```typescript
// DKG
const key = await mpc.ecKey2pDkg(transport, partyIndex, names, NID_ED25519);

// Signing
const sig = await mpc.schnorr2pEddsaSign(transport, partyIndex, names, key, message);
```

### EdDSA Multi-Party

```typescript
// DKG
const curve = mpc.createCurve(NID_ED25519);
const key = await mpc.ecKeyMpDkg(transport, partyCount, partyIndex, names, curve);

// Signing
const sig = await mpc.eddsaMpSign(transport, partyCount, partyIndex, names, key, message, sigReceiver);
```

## Key Serialization

All key types support serialization for persistence (database, Redis, etc.):

```typescript
// Serialize key share to store
const parts: Uint8Array[] = mpc.serializeEcdsa2p(key);

// Restore later
const restored = mpc.deserializeEcdsa2p(parts);
```

| Key Type | Serialize | Deserialize |
|----------|-----------|-------------|
| ECDSA 2P | `serializeEcdsa2p(key)` | `deserializeEcdsa2p(parts)` |
| EC Key 2P (EdDSA) | `serializeEcKey2p(key)` | `deserializeEcKey2p(parts)` |
| EC Key MP | `serializeEcKeyMp(key)` | `deserializeEcKeyMp(parts)` |

ECDSA-MP and EdDSA-MP share the same key type as EC Key MP.

## Publicly Verifiable Encryption (PVE)

Back up key-share scalars to a recipient key so that anyone holding the public
share points can check the backup without decrypting it (cbmpc's built-in
ECIES P-256 base PKE, batch, single recipient):

```typescript
const { ek, dk } = mpc.pveGenerateKeypair();           // dk stays with the recipient
const { xShare } = mpc.ecdsa2pKeyInfo(key);
const label = new TextEncoder().encode("my-app:backup:<key id>"); // non-empty, domain-separated
const ct = mpc.pveBatchEncrypt(NID_secp256k1, ek, label, [xShare]);

const curve = mpc.createCurve(NID_secp256k1);
const Q = mpc.pointToBytes(mpc.mulGenerator(curve, xShare)); // or any trusted copy of x*G
mpc.pveBatchVerify(NID_secp256k1, ek, ct, [Q], label);  // true, no decryption needed

const [x] = mpc.pveBatchDecrypt(NID_secp256k1, dk, ek, ct, label);
```

Notes:
- `label` must be non-empty; use a domain-separated value tied to the key.
- Scalars are big-endian and must be below the curve order (larger values
  are reduced mod order and round-trip as `x mod order`).
- `pveBatchVerify` returns `false` both for a bad proof and for malformed input.
- `pveBatchDecrypt` does not verify first. A restore flow should call
  `pveBatchVerify` before decrypting, or check `x*G` afterwards.
- `dk` and decrypted scalars are secrets: overwrite the returned arrays
  (`.fill(0)`) once they are no longer needed.
- For ECDSA-2P party 0 (P1) a scalar backup is not enough to restore the key;
  see [SECURE_USAGE.md](../SECURE_USAGE.md#ecdsa-2p-p1-backup-limitations).

## Access-Structure Keys and Resharing

Threshold keys (for example 2-of-3) over the library's own access-structure (AC) key blobs: the same bytes the
upstream C API (`cbmpc_ecdsa_mp_*_ac`, `cbmpc_eddsa_mp_*_ac`) reads and writes, so a share made in the browser can
be used from a native app and the other way round. ECDSA-MP on secp256k1 / P-256, EdDSA-MP on Ed25519.

```ts
const names = ["iphone", "mac", "server"];
const ac = thresholdOf(2, names);

// All parties online. Returns this party's key blob (secret).
const blob = await mpc.dkgAc(transport, myIndex, names, NID_secp256k1, ac, names);
const { publicKey } = mpc.acKeyInfo(blob); // compressed

// Any qualifying set signs; only the signers are in the job.
const sig = await mpc.signAc(transport, idx, ["iphone", "server"], blob, ac, hash, 0);

// Re-randomize all shares (same key). All parties online.
const fresh = await mpc.refreshAc(transport, myIndex, names, blob, ac, names);
```

`reshareFromAdditive` moves an existing key to a new access structure and keeps the public key. The dealers hold an
additive sharing of the key:

- a 2-of-2 key: both parties' `xShare` from `ecdsa2pKeyInfo` / `ecKey2pInfo` (pass the 2P `publicKey` as is);
- an AC key: `acToAdditiveShare(blob, ac, dealers)` on each dealer, for exactly that dealer set.

```ts
// iphone lost: mac + server deal a new generation for {new iphone, mac, server}.
const dealers = ["mac", "server"];
const x = dealers.includes(me) ? mpc.acToAdditiveShare(blob, ac, dealers) : null;
const newBlob = await mpc.reshareFromAdditive(transport, myIndex, names, NID_secp256k1, publicKey, dealers, x, ac);
```

Each dealer commits to its sharing and proves knowledge of it; every receiver checks its share against the
commitments and that the dealt shares add up to `publicKey`, so a wrong share or a wrong key aborts the protocol.
Notes:

- Every party in the job must be online; each is a dealer, a member of the new structure, or both. A dealer outside
  the new structure gets an empty array.
- **Take `publicKey` from your own record** (your 2P key or AC blob, or the wallet's known key), never from a peer
  or relay message: a dealer that knows the other public shares could otherwise steer the reshare to another key.
- `acToAdditiveShare` needs a minimal qualifying set (2 of a 2-of-3); a zero-weight member is rejected.
- **Resharing does not revoke old shares.** Any old qualifying set still holds the same key. A malicious dealer can
  make one party abort while others succeed: treat the new generation as live only after every party reported
  success, then delete old blobs and 2P keys and run `refreshAc`.
- **Take the new structure, the dealer list and which device/person holds each name from your own record** too. The
  protocol only checks that all parties agree; a coordinator that gives everyone a structure where it holds a
  qualifying set of names gets the key.
- The transport must be authenticated and encrypted end to end: dealers send each party its share in the clear inside
  the protocol messages. A relay run by another party (e.g. the server relaying device <-> backup traffic) must not be
  able to read them: with threshold 2, one intercepted share plus its own gives it the dealer's additive share. The
  same holds for `dkgAc` and `refreshAc`.
- Leave `sid` empty so a fresh one is derived; a caller-supplied sid is not checked for freshness.
- Run one protocol at a time per `CbMpc` instance (Asyncify); a second concurrent call is rejected. Use one instance
  per session. A protocol whose transport never settles keeps its instance busy; make `receive` reject on abort or
  timeout.
- `refreshAc` now binds the key being refreshed (public key and public shares): every party must run this version
  or later, otherwise refresh aborts with `h_consistency mismatch`.

Measured over a real relay: `scripts/relay-bench/` (see the comments there for setup).

## Curve Codes

```typescript
import { NID_secp256k1, NID_X9_62_prime256v1, NID_ED25519 } from "cb-mpc";
```

| Curve | Constant | Value |
|-------|----------|-------|
| secp256k1 | `NID_secp256k1` | 714 |
| P-256 (secp256r1) | `NID_X9_62_prime256v1` | 415 |
| Ed25519 | `NID_ED25519` | 1087 |

## Transport

MPC protocols require a transport layer for parties to exchange messages. Implement the `DataTransport` interface:

```typescript
import type { DataTransport } from "cb-mpc";

const transport: DataTransport = {
  send: async (receiver: number, message: Uint8Array) => { /* ... */ return 0; },
  receive: async (sender: number): Promise<Uint8Array> => { /* ... */ },
  receiveAll: async (senders: number[]): Promise<Uint8Array[]> => { /* ... */ },
};
```

With the native backends (bun:ffi, koffi) the library calls the transport
synchronously, so a transport must also implement `sendSync`, `receiveSync` and
`receiveAllSync`, and parties that talk to each other must run on different
threads (e.g. one worker per party). See `scripts/native-mp` for an example
using `SharedArrayBuffer` and `Atomics`.

## Server Architecture

For production servers handling concurrent requests:

- **WASM for protocols** (DKG, signing) — async, doesn't block the event loop
- **bun:ffi for fast ops** (verify, curve math) — synchronous, microseconds

```typescript
const mpcWasm = await initCbMpc();        // for protocols
const mpcFfi = await initCbMpcBunFfi();   // for quick ops

// Fast path — FFI
app.post("/verify", (req) => {
  const valid = mpcFfi.verifyDer(curve, pubkey, hash, sig);
  return Response.json({ valid });
});

// Protocol path — WASM, async
app.post("/dkg", async (req) => {
  const key = await mpcWasm.ecdsa2pDkg(transport, ...);
  return Response.json({ publicKey: "..." });
});
```

## Browser Usage

Works in any modern browser via WASM — no bundler required:

```html
<script type="module">
  import { initCbMpc, NID_secp256k1 } from "./dist/index.js";

  const mpc = await initCbMpc();
  const curve = mpc.createCurve(NID_secp256k1);
  const scalar = mpc.randomScalar(curve);
  console.log("Random scalar:", scalar);
</script>
```

See [examples/browser.html](examples/browser.html) for a full demo.

## Examples

| Example | Description |
|---------|-------------|
| [curve-ops.ts](examples/curve-ops.ts) | Elliptic curve and point operations |
| [ecdsa-2pc.ts](examples/ecdsa-2pc.ts) | ECDSA two-party DKG, sign, refresh |
| [ecdsa-mpc.ts](examples/ecdsa-mpc.ts) | ECDSA multi-party (3-of-3) |
| [eddsa-2pc.ts](examples/eddsa-2pc.ts) | EdDSA two-party DKG and sign |
| [eddsa-mpc.ts](examples/eddsa-mpc.ts) | EdDSA multi-party (3-of-3) |
| [agree-random.ts](examples/agree-random.ts) | Two-party random agreement |
| [key-serialization.ts](examples/key-serialization.ts) | Serialize/deserialize all key types |
| [pve-backup.ts](examples/pve-backup.ts) | PVE backup of key shares: encrypt, verify, decrypt |
| [ac-reshare.ts](examples/ac-reshare.ts) | 2-of-3 keys: reshare a 2P key, lost-device replacement, sign with any pair |
| [browser.html](examples/browser.html) | Browser WASM demo |

Run examples with:

```bash
# Bun
bun run examples/curve-ops.ts

# Node.js
npx tsx examples/curve-ops.ts
```

## Building from Source

```bash
# Build WASM (requires Emscripten)
make wasm

# Build native shared library (macOS ARM64)
make build-native

# Build TypeScript
cd cb-mpc-ts && npm run build
```

## License

[MIT](LICENSE)
