// Minimal message relay for latency benchmarks (node, no dependencies).
// Each client connects and sends a 4-byte id; afterwards frames are [to u32][len u32][payload] and are forwarded to
// client `to` as [from u32][len u32][payload]. Optional extra one-way delay per forwarded frame: RELAY_DELAY_MS.
//
// Usage: node relay.mjs [port]
import net from "node:net";

const port = Number(process.argv[2] || 47811);
const delay = Number(process.env.RELAY_DELAY_MS || 0);
const clients = new Map();

net
  .createServer((sock) => {
    sock.setNoDelay(true);
    let id = -1;
    let buf = Buffer.alloc(0);
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (id < 0) {
        if (buf.length < 4) return;
        id = buf.readUInt32BE(0);
        buf = buf.subarray(4);
        clients.set(id, sock);
      }
      while (buf.length >= 8) {
        const to = buf.readUInt32BE(0), len = buf.readUInt32BE(4);
        if (buf.length < 8 + len) break;
        const out = Buffer.concat([Buffer.alloc(8), buf.subarray(8, 8 + len)]);
        out.writeUInt32BE(id, 0);
        out.writeUInt32BE(len, 4);
        buf = buf.subarray(8 + len);
        const send = () => clients.get(to)?.write(out);
        delay ? setTimeout(send, delay) : send();
      }
    });
    sock.on("close", () => clients.get(id) === sock && clients.delete(id));
    sock.on("error", () => {});
  })
  .listen(port, "127.0.0.1", () => console.log(`relay listening on ${port}, extra delay ${delay} ms`));
