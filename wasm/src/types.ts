/**
 * cb-mpc WebAssembly TypeScript type definitions.
 *
 * These types model the WASM module's exported C API at a high level,
 * suitable for direct consumption by TypeScript applications.
 */

// ---------------------------------------------------------------------------
// Opaque handle types (WASM pointers represented as numbers)
// ---------------------------------------------------------------------------

/** Opaque pointer to an elliptic curve instance. */
export type CurveHandle = number & { readonly __brand: "CurveHandle" };

/** Opaque pointer to an elliptic curve point. */
export type PointHandle = number & { readonly __brand: "PointHandle" };

/** Opaque pointer to a two-party job. */
export type Job2pHandle = number & { readonly __brand: "Job2pHandle" };

/** Opaque pointer to a multi-party job. */
export type JobMpHandle = number & { readonly __brand: "JobMpHandle" };

/** Opaque pointer to a two-party ECDSA key. */
export type Ecdsa2pKeyHandle = number & { readonly __brand: "Ecdsa2pKeyHandle" };

/** Opaque pointer to a multi-party EC key. */
export type EcKeyMpHandle = number & { readonly __brand: "EcKeyMpHandle" };

/** Opaque pointer to a party set. */
export type PartySetHandle = number & { readonly __brand: "PartySetHandle" };

/** Opaque pointer to an access-structure. */
export type AccessStructureHandle = number & { readonly __brand: "AccessStructureHandle" };

/** Opaque pointer to a secret-sharing node. */
export type SsNodeHandle = number & { readonly __brand: "SsNodeHandle" };

// ---------------------------------------------------------------------------
// Struct-like types mapped to WASM linear memory
// ---------------------------------------------------------------------------

/** Corresponds to cmem_t { uint8_t* data; int size; } — 8 bytes on wasm32. */
export const CMEM_SIZE = 8;

/** Corresponds to cmems_t { int count; uint8_t* data; int* sizes; } — 12 bytes. */
export const CMEMS_SIZE = 12;

/** Corresponds to opaque ref structs { void* opaque; } — 4 bytes on wasm32. */
export const REF_SIZE = 4;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

export const CBMPC_SUCCESS = 0;

// Network error codes (from network.h)
export const NETWORK_SUCCESS = 0;
export const NETWORK_ERROR = -1;
export const NETWORK_PARAM_ERROR = -2;
export const NETWORK_MEMORY_ERROR = -3;
export const NETWORK_INVALID_STATE = -4;

// ---------------------------------------------------------------------------
// Well-known curve codes (OpenSSL NIDs)
// ---------------------------------------------------------------------------

/** secp256k1 (Bitcoin, Ethereum) */
export const NID_secp256k1 = 714;
/** prime256v1 / P-256 */
export const NID_X9_62_prime256v1 = 415;
/** Ed25519 */
export const NID_ED25519 = 1087;

// ---------------------------------------------------------------------------
// Transport interface (user-provided network layer)
// ---------------------------------------------------------------------------

/**
 * Data transport callbacks for MPC protocol message passing.
 *
 * Implementations must handle the actual network communication between
 * MPC parties (e.g., via WebSocket, WebRTC, HTTP, or in-memory channels).
 */
export interface DataTransport {
  /**
   * Send a message to a specific party.
   * @param receiver - Party index of the receiver.
   * @param message  - Raw message bytes.
   * @returns 0 on success, non-zero error code on failure.
   */
  send(receiver: number, message: Uint8Array): Promise<number>;

  /**
   * Receive a message from a specific party.
   * @param sender - Party index of the sender.
   * @returns The received message bytes.
   */
  receive(sender: number): Promise<Uint8Array>;

  /**
   * Receive messages from multiple senders at once.
   * @param senders - Array of party indices to receive from.
   * @returns Array of received messages, one per sender (same order).
   */
  receiveAll(senders: number[]): Promise<Uint8Array[]>;
}

// ---------------------------------------------------------------------------
// High-level result types
// ---------------------------------------------------------------------------

/** Two-party ECDSA key information. */
export interface Ecdsa2pKeyInfo {
  /** Party role index (0 or 1). */
  roleIndex: number;
  /** OpenSSL NID for the curve. */
  curveCode: number;
  /** Serialized public key point Q. */
  publicKey: Uint8Array;
  /** Secret share x_i (big-endian bytes). */
  xShare: Uint8Array;
}

/** Multi-party EC key information. */
export interface EcKeyMpInfo {
  /** Party name. */
  partyName: string;
  /** Serialized public key point Q. */
  publicKey: Uint8Array;
  /** Secret share x_i (big-endian bytes). */
  xShare: Uint8Array;
}

/** Elliptic curve point in serialized form. */
export interface EcPoint {
  /** X coordinate (big-endian bytes). */
  x: Uint8Array;
  /** Y coordinate (big-endian bytes). */
  y: Uint8Array;
}

// ---------------------------------------------------------------------------
// Emscripten module interface
// ---------------------------------------------------------------------------

/**
 * The raw Emscripten module interface.
 * This is the low-level WASM module before our TypeScript wrapper.
 */
export interface CbMpcWasmModule {
  // Emscripten runtime
  HEAPU8: Uint8Array;

  _malloc(size: number): number;
  _free(ptr: number): void;

  ccall(
    ident: string,
    returnType: string | null,
    argTypes: string[],
    args: unknown[],
    opts?: { async?: boolean },
  ): unknown;

  cwrap(
    ident: string,
    returnType: string | null,
    argTypes: string[],
    opts?: { async?: boolean },
  ): (...args: unknown[]) => unknown;

  addFunction(func: Function, sig: string): number;
  removeFunction(funcPtr: number): void;
  getValue(ptr: number, type: string): number;
  setValue(ptr: number, value: number, type: string): void;
  UTF8ToString(ptr: number): string;
  stringToUTF8(str: string, outPtr: number, maxBytesToWrite: number): void;
  lengthBytesUTF8(str: string): number;

  // Entropy seeding
  _wasm_seed_random(ptr: number, size: number): number;

  // Transport callback registry (set up by our wrapper)
  _transportCallbacks: Record<number, DataTransport>;
}
