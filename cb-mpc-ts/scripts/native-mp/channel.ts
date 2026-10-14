// Synchronous in-process transport for the native backends.
//
// Native FFI callbacks are synchronous, so each MPC party runs in its own
// worker and blocks on Atomics.wait until a peer's message arrives. One
// append-only SharedArrayBuffer mailbox per (sender -> receiver) pair.

const HEADER_INTS = 2; // [writeOffset, unused]
const HEADER_BYTES = HEADER_INTS * 4;

export type Mailboxes = SharedArrayBuffer[][]; // [sender][receiver]

export function createMailboxes(n: number, bytesPerPair = 16 << 20): Mailboxes {
  return Array.from({ length: n }, () =>
    Array.from({ length: n }, () => new SharedArrayBuffer(HEADER_BYTES + bytesPerPair)),
  );
}

export class SyncChannel {
  private readOffsets: number[];

  constructor(
    private readonly self: number,
    private readonly boxes: Mailboxes,
    private readonly timeoutMs = 60000,
  ) {
    this.readOffsets = boxes.map(() => 0);
  }

  sendSync(receiver: number, msg: Uint8Array): number {
    const sab = this.boxes[this.self][receiver];
    const hdr = new Int32Array(sab, 0, HEADER_INTS);
    const off = Atomics.load(hdr, 0);
    if (HEADER_BYTES + off + 4 + msg.length > sab.byteLength) return -1;
    const view = new DataView(sab, HEADER_BYTES);
    view.setUint32(off, msg.length, true);
    new Uint8Array(sab, HEADER_BYTES + off + 4, msg.length).set(msg);
    Atomics.store(hdr, 0, off + 4 + msg.length);
    Atomics.notify(hdr, 0);
    return 0;
  }

  receiveSync(sender: number): Uint8Array {
    const sab = this.boxes[sender][this.self];
    const hdr = new Int32Array(sab, 0, HEADER_INTS);
    const off = this.readOffsets[sender];
    while (Atomics.load(hdr, 0) <= off) {
      if (Atomics.wait(hdr, 0, off, this.timeoutMs) === "timed-out" && Atomics.load(hdr, 0) <= off) {
        throw new Error(`party ${this.self}: timed out waiting for party ${sender}`);
      }
    }
    const len = new DataView(sab, HEADER_BYTES).getUint32(off, true);
    const msg = new Uint8Array(sab, HEADER_BYTES + off + 4, len).slice();
    this.readOffsets[sender] = off + 4 + len;
    return msg;
  }

  receiveAllSync(senders: number[]): Uint8Array[] {
    return senders.map((s) => this.receiveSync(s));
  }

  // Async DataTransport methods (unused by the native backends, kept for the interface).
  async send(receiver: number, msg: Uint8Array): Promise<number> {
    return this.sendSync(receiver, msg);
  }
  async receive(sender: number): Promise<Uint8Array> {
    return this.receiveSync(sender);
  }
  async receiveAll(senders: number[]): Promise<Uint8Array[]> {
    return this.receiveAllSync(senders);
  }
}
