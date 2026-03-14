# cb-mpc

TypeScript wrapper for the [cb-mpc](https://github.com/coinbase/cb-mpc) cryptographic MPC library.

Supports three backends:

- **WASM** (Emscripten) — browsers and Node.js
- **bun:ffi** — Bun runtime (native performance)
- **koffi** — Node.js runtime (native performance)

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
