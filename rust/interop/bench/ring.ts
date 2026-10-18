// Single-producer / single-consumer message ring on a SharedArrayBuffer, for the bun:ffi bench
// (native cb-mpc calls its transport synchronously, so the receiving worker blocks with
// Atomics.wait). Same layout as the kexify MPC server's mpc/src/ffi-sync-ring.ts.
// Layout: Int32 header [writeSeq, readSeq], then SLOTS slots of [len:int32][bytes].
const HEADER = 8;
const SLOTS = 8;
const SLOT = 1 << 20;

export function createRing(): SharedArrayBuffer {
  return new SharedArrayBuffer(HEADER + SLOTS * SLOT);
}

export function ringWrite(sab: SharedArrayBuffer, msg: Uint8Array): void {
  const h = new Int32Array(sab, 0, 2);
  const w = Atomics.load(h, 0);
  if (msg.length > SLOT - 4) throw new Error("message too large");
  while (w - Atomics.load(h, 1) >= SLOTS) Atomics.wait(h, 1, Atomics.load(h, 1), 10);
  const off = HEADER + (w % SLOTS) * SLOT;
  new DataView(sab).setInt32(off, msg.length, true);
  new Uint8Array(sab, off + 4, msg.length).set(msg);
  Atomics.store(h, 0, w + 1);
  Atomics.notify(h, 0);
}

export function ringRead(sab: SharedArrayBuffer, timeoutMs = 60_000): Uint8Array {
  const h = new Int32Array(sab, 0, 2);
  const r = Atomics.load(h, 1);
  const deadline = Date.now() + timeoutMs;
  while (Atomics.load(h, 0) === r) {
    if (Date.now() > deadline) throw new Error("ring read timeout");
    Atomics.wait(h, 0, r, 100);
  }
  const off = HEADER + (r % SLOTS) * SLOT;
  const len = new DataView(sab).getInt32(off, true);
  const msg = new Uint8Array(sab, off + 4, len).slice();
  Atomics.store(h, 1, r + 1);
  Atomics.notify(h, 1);
  return msg;
}
