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
const key = await mpc.ecdsa2pDkg(job, curveCode);

// Signing
const sig = await mpc.ecdsa2pSign(job, key, sessionId, msgHash);

// Key refresh
const newKey = await mpc.ecdsa2pRefresh(job, key);
```

### ECDSA Multi-Party

```typescript
// DKG (returns an EC key)
const key = await mpc.ecKeyMpDkg(job, curve);

// Signing
const sig = await mpc.ecdsaMpSign(job, key, msgHash, sigReceiver);
```

### EdDSA 2-Party

```typescript
// DKG
const key = await mpc.ecKey2pDkg(job, curveCode);

// Signing
const sig = await mpc.schnorr2pEddsaSign(job, key, message);
```

### EdDSA Multi-Party

```typescript
// DKG
const key = await mpc.ecKeyMpDkg(job, curve);

// Signing
const sig = await mpc.eddsaMpSign(job, key, message, sigReceiver);
```

## Curve Codes

| Curve | Code |
|-------|------|
| secp256k1 | `0x0301` |
| P-256 (secp256r1) | `0x0303` |
| Ed25519 | `0x0309` |
| Stark curve | `0x030a` |

## Transport

MPC protocols require a transport layer for parties to exchange messages. Implement the `DataTransport` interface:

```typescript
import type { DataTransport } from "cb-mpc";

const transport: DataTransport = {
  send: async (receiver: number, message: Uint8Array) => { /* ... */ },
  receive: async (sender: number) => { /* ... */ },
  receiveAll: async (senders: number[]) => { /* ... */ },
};
```

For native backends, transport callbacks must be synchronous. Use `SyncDataTransport` with worker threads and SharedArrayBuffer for concurrent parties.

## Building from Source

```bash
# WASM
make wasm

# Native (macOS ARM64)
make native

# Native (Linux x64, via Docker)
make build-native-linux-x64
```

## License

[MIT](LICENSE)
