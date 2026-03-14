/**
 * In-memory mock transport for testing MPC protocols.
 *
 * Creates a network of N parties that exchange messages through
 * in-memory queues — no real networking required. This mirrors
 * the Go mocknet implementation in demos-go.
 */

import type { DataTransport } from "cb-mpc";

/** A message in the mock network. */
interface Message {
  data: Uint8Array;
  resolve: () => void;
}

/**
 * Per-party messenger backed by in-memory queues.
 *
 * Each party has one queue per possible sender. Messages are
 * delivered immediately and resolved via Promises.
 */
class MockMessenger implements DataTransport {
  /** Incoming message queues indexed by sender party index. */
  private queues: Map<number, Message[]> = new Map();
  /** Pending receive waiters indexed by sender party index. */
  private waiters: Map<number, ((msg: Uint8Array) => void)[]> = new Map();
  /** Reference to the full network for send routing. */
  private network: MockMessenger[];
  /** This party's index. */
  readonly partyIndex: number;

  constructor(partyIndex: number, network: MockMessenger[]) {
    this.partyIndex = partyIndex;
    this.network = network;
  }

  /** Enqueue a message destined for this party from a given sender. */
  private enqueue(sender: number, data: Uint8Array): void {
    const waiters = this.waiters.get(sender);
    if (waiters && waiters.length > 0) {
      // A receive is already waiting — resolve it immediately.
      const resolve = waiters.shift()!;
      resolve(data);
      return;
    }
    // No waiter yet — buffer the message.
    if (!this.queues.has(sender)) this.queues.set(sender, []);
    this.queues.get(sender)!.push({ data, resolve: () => {} });
  }

  async send(receiver: number, message: Uint8Array): Promise<number> {
    // Route message to the receiver party's incoming queue.
    this.network[receiver].enqueue(this.partyIndex, message);
    return 0;
  }

  sendSync(receiver: number, message: Uint8Array): number {
    this.network[receiver].enqueue(this.partyIndex, message);
    return 0;
  }

  async receive(sender: number): Promise<Uint8Array> {
    // Check if a message is already buffered.
    const queue = this.queues.get(sender);
    if (queue && queue.length > 0) {
      return queue.shift()!.data;
    }
    // Wait for a message.
    return new Promise<Uint8Array>((resolve) => {
      if (!this.waiters.has(sender)) this.waiters.set(sender, []);
      this.waiters.get(sender)!.push(resolve);
    });
  }

  receiveSync(sender: number): Uint8Array {
    const queue = this.queues.get(sender);
    if (queue && queue.length > 0) {
      return queue.shift()!.data;
    }
    throw new Error(`No message buffered from sender ${sender}`);
  }

  async receiveAll(senders: number[]): Promise<Uint8Array[]> {
    return Promise.all(senders.map((s) => this.receive(s)));
  }

  receiveAllSync(senders: number[]): Uint8Array[] {
    return senders.map((s) => this.receiveSync(s));
  }
}

/**
 * Create an in-memory mock network of N parties.
 *
 * @param n - Number of parties.
 * @returns Array of DataTransport instances, one per party.
 *
 * @example
 * ```ts
 * const transports = createMockNetwork(2);
 * // transports[0] is party 0's transport
 * // transports[1] is party 1's transport
 * ```
 */
export function createMockNetwork(n: number): DataTransport[] {
  const messengers: MockMessenger[] = [];
  for (let i = 0; i < n; i++) {
    messengers.push(new MockMessenger(i, messengers));
  }
  return messengers;
}
