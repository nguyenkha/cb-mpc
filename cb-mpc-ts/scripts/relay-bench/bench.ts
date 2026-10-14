// Latency benchmark over a real relay (relay.mjs), WASM parties in this process, one TCP connection each.
// Every protocol message goes party -> relay -> party, so each flight costs one relay round trip.
//
// Usage (from cb-mpc-ts/), relay on a remote host reached through an SSH tunnel:
//   scp scripts/relay-bench/relay.mjs host:/tmp/ && ssh -L 47812:127.0.0.1:47811 host 'node /tmp/relay.mjs 47811'
//   bun run scripts/relay-bench/bench.ts 127.0.0.1:47812 [iterations]
// Add RELAY_DELAY_MS=<n> on the relay side to add n ms of one-way delay per forwarded message.
import net from "node:net";
import { createHash } from "node:crypto";
import { initCbMpc, CbMpc, NID_secp256k1, NID_ED25519, thresholdOf } from "../../dist/index";

const [host, port] = (process.argv[2] || "127.0.0.1:47811").split(":");
const iters = Number(process.argv[3] || 5);
const hash = new Uint8Array(createHash("sha256").update("relay-bench").digest());

type Stats = { msgs: number; bytes: number; flights: number; maxMsg: number };

/** DataTransport over one relay connection; `ids` maps job party index -> relay client id. */
class RelayTransport {
  private q = new Map<number, Uint8Array[]>();
  private w = new Map<number, (m: Uint8Array) => void>();
  private buf = Buffer.alloc(0);
  private lastWasReceive = true;
  stats: Stats = { msgs: 0, bytes: 0, flights: 0, maxMsg: 0 };
  ids: number[] = [];
  constructor(private sock: net.Socket, readonly relayId: number) {
    sock.on("data", (d) => {
      this.buf = Buffer.concat([this.buf, d]);
      while (this.buf.length >= 8) {
        const from = this.buf.readUInt32BE(0), len = this.buf.readUInt32BE(4);
        if (this.buf.length < 8 + len) break;
        const m = new Uint8Array(this.buf.subarray(8, 8 + len));
        this.buf = this.buf.subarray(8 + len);
        const waiter = this.w.get(from);
        if (waiter) { this.w.delete(from); waiter(m); } else { if (!this.q.has(from)) this.q.set(from, []); this.q.get(from)!.push(m); }
      }
    });
  }
  static connect(relayId: number): Promise<RelayTransport> {
    return new Promise((res, rej) => {
      const s = net.connect(Number(port), host, () => {
        s.setNoDelay(true);
        const hdr = Buffer.alloc(4); hdr.writeUInt32BE(relayId, 0); s.write(hdr);
        res(new RelayTransport(s, relayId));
      });
      s.on("error", rej);
    });
  }
  resetStats() { this.stats = { msgs: 0, bytes: 0, flights: 0, maxMsg: 0 }; this.lastWasReceive = true; }
  async send(receiver: number, m: Uint8Array) {
    if (this.lastWasReceive) this.stats.flights++;
    this.lastWasReceive = false;
    this.stats.msgs++; this.stats.bytes += m.length; this.stats.maxMsg = Math.max(this.stats.maxMsg, m.length);
    const hdr = Buffer.alloc(8); hdr.writeUInt32BE(this.ids[receiver], 0); hdr.writeUInt32BE(m.length, 4);
    this.sock.write(Buffer.concat([hdr, m]));
    return 0;
  }
  receive(sender: number): Promise<Uint8Array> {
    this.lastWasReceive = true;
    const from = this.ids[sender];
    const q = this.q.get(from);
    if (q?.length) return Promise.resolve(q.shift()!);
    return new Promise((r) => this.w.set(from, r));
  }
  async receiveAll(senders: number[]) { return Promise.all(senders.map((s) => this.receive(s))); }
  close() { this.sock.destroy(); }
}

const NAMES = ["iphone", "mac", "server"];
const inst: Record<string, CbMpc> = {};
const tr: Record<string, RelayTransport> = {};
for (const [i, n] of NAMES.entries()) { inst[n] = await initCbMpc(); tr[n] = await RelayTransport.connect(i + 1); }

async function run<T>(names: string[], fn: (m: CbMpc, t: RelayTransport, i: number) => Promise<T>): Promise<T[]> {
  for (const n of names) { tr[n].ids = names.map((x) => NAMES.indexOf(x) + 1); tr[n].resetStats(); }
  return Promise.all(names.map((n, i) => fn(inst[n], tr[n], i)));
}

async function bench(label: string, names: string[], fn: (m: CbMpc, t: RelayTransport, i: number) => Promise<unknown>) {
  const times: number[] = [];
  let stats: Stats[] = [];
  for (let k = 0; k < iters; k++) {
    const t0 = performance.now();
    await run(names, fn);
    times.push(performance.now() - t0);
    stats = names.map((n) => ({ ...tr[n].stats }));
  }
  times.sort((a, b) => a - b);
  const kb = (b: number) => (b / 1024).toFixed(1);
  console.log(
    `| ${label} | ${stats.map((s) => s.msgs).join(" / ")} | ${stats.map((s) => s.flights).join(" / ")} | ` +
      `${stats.map((s) => kb(s.bytes)).join(" / ")} KB | ${kb(Math.max(...stats.map((s) => s.maxMsg)))} KB | ` +
      `${times[Math.floor(times.length / 2)].toFixed(0)} ms | ${times[0].toFixed(0)}–${times[times.length - 1].toFixed(0)} ms |`,
  );
}

const pair = ["iphone", "server"];
const ac = thresholdOf(2, NAMES);
console.log(`relay ${host}:${port}, ${iters} iterations each`);
console.log("| protocol | msgs sent (per party) | send flights | bytes sent | largest msg | median | range |");
console.log("|---|---|---|---|---|---|---|");

for (const [cname, curve] of [["ECDSA", NID_secp256k1], ["EdDSA", NID_ED25519]] as const) {
  // Today's 2P baseline.
  if (curve === NID_secp256k1) {
    const k = await run(pair, (m, t, i) => m.ecdsa2pDkg(t, i, pair, curve));
    await bench("ECDSA-2P sign (today)", pair, (m, t, i) => m.ecdsa2pSign(t, i, pair, k[i], new Uint8Array(0), [hash]));
  } else {
    const k = await run(pair, (m, t, i) => m.ecKey2pDkg(t, i, pair, curve));
    await bench("EdDSA-2P sign (today)", pair, (m, t, i) => m.schnorr2pEddsaSign(t, i, pair, k[i], hash));
  }
  const g0 = await run(NAMES, (m, t, i) => m.dkgAc(t, i, NAMES, curve, ac, NAMES));
  const keys = Object.fromEntries(NAMES.map((n, i) => [n, g0[i]]));
  const pub = inst.iphone.acKeyInfo(keys.iphone).publicKey;
  for (const p of [["iphone", "server"], ["iphone", "mac"]])
    await bench(`${cname}-MP signAc ${p.join("+")}`, p, (m, t, i) => m.signAc(t, i, p, keys[p[i]], ac, hash, 0));
  const dealers = ["mac", "server"];
  await bench(`${cname} reshare (mac+server deal, 3 parties)`, NAMES, (m, t, i) => {
    const x = i === 0 ? null : m.acToAdditiveShare(keys[NAMES[i]], ac, dealers);
    return m.reshareFromAdditive(t, i, NAMES, curve, pub, dealers, x, ac);
  });
  await bench(`${cname} refreshAc (3 parties)`, NAMES, (m, t, i) => m.refreshAc(t, i, NAMES, keys[NAMES[i]], ac, NAMES));
}
for (const n of NAMES) tr[n].close();
process.exit(0);
