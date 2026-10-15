// Worker: one MPC party on a native backend. Receives a scenario, runs it and
// posts back public results (public keys, signatures, serialized keys).

import { SyncChannel } from "./channel.ts";

declare const self: Worker;

self.onmessage = async (ev: MessageEvent) => {
  const { idx, n, boxes, backend, libPath, distPath, scenario } = ev.data;
  try {
    const M: any = await import(distPath);
    const mpc = backend === "koffi" ? await M.initCbMpcKoffi(libPath) : await M.initCbMpcBunFfi(libPath);
    const t = new SyncChannel(idx, boxes);
    const names = Array.from({ length: n }, (_, i) => `p${i}`);
    const out: Record<string, any> = {};
    const msg = scenario.msg as Uint8Array;

    switch (scenario.kind) {
      case "ecdsa2p": {
        let key = await mpc.ecdsa2pDkg(t, idx, names, scenario.curve);
        out.pub = mpc.ecdsa2pKeyInfo(key).publicKey;
        out.sig = (await mpc.ecdsa2pSign(t, idx, names, key, new Uint8Array(0), [msg]))[0];
        key = await mpc.ecdsa2pRefresh(t, idx, names, key);
        out.sig2 = (await mpc.ecdsa2pSign(t, idx, names, key, new Uint8Array(0), [msg]))[0];
        out.ser = mpc.serializeEcdsa2p(key);
        break;
      }
      case "eddsa2p": {
        const key = await mpc.ecKey2pDkg(t, idx, names, M.NID_ED25519);
        out.pub = mpc.ecKey2pInfo(key).publicKey;
        out.sig = await mpc.schnorr2pEddsaSign(t, idx, names, key, msg);
        out.ser = mpc.serializeEcKey2p(key);
        break;
      }
      case "mp": {
        const curve = mpc.createCurve(scenario.curve);
        let key = await mpc.ecKeyMpDkg(t, n, idx, names, curve);
        mpc.freeCurve(curve);
        key = await mpc.ecKeyMpRefresh(t, n, idx, names, key, new Uint8Array(0));
        out.pub = mpc.ecKeyMpInfo(key).publicKey;
        out.sig =
          scenario.curve === M.NID_ED25519
            ? await mpc.eddsaMpSign(t, n, idx, names, key, msg, 0)
            : await mpc.ecdsaMpSign(t, n, idx, names, key, msg, 0);
        out.ser = mpc.serializeEcKeyMp(key);
        break;
      }
      case "agree": {
        out.rand = await mpc.agreeRandom(t, idx, names, 256);
        break;
      }
      case "ac": {
        // Access-structure op over scenario.names (this worker is names[idx]); blobs passed in by name.
        const sc = scenario;
        const me = sc.names[idx];
        if (sc.op === "dkg") out.blob = await mpc.dkgAc(t, idx, sc.names, sc.curve, sc.ac, sc.names);
        else if (sc.op === "refresh") out.blob = await mpc.refreshAc(t, idx, sc.names, sc.blobs[me], sc.ac, sc.names);
        else if (sc.op === "sign") out.sig = await mpc.signAc(t, idx, sc.names, sc.blobs[me], sc.ac, msg, 0);
        else if (sc.op === "reshare") {
          const x = sc.dealers.includes(me)
            ? sc.xs?.[me] ?? mpc.acToAdditiveShare(sc.blobs[me], sc.oldAc, sc.dealers)
            : null;
          out.blob = await mpc.reshareFromAdditive(t, idx, sc.names, sc.curve, sc.pub, sc.dealers, x, sc.ac);
        }
        if (out.blob?.length) out.pub = mpc.acKeyInfo(out.blob).publicKey;
        break;
      }
      case "hdsign": {
        // Load an ECDSA HD keyset (made on WASM), derive on native, sign, and
        // return the account node so the caller can compare with WASM.
        const ks = mpc.deserializeHdEcdsa2p(scenario.keysets[idx]);
        const [key] = await mpc.hdEcdsa2pDerive(t, idx, names, ks, scenario.hardened, [scenario.path]);
        out.pub = mpc.ecdsa2pKeyInfo(key).publicKey;
        out.sig = (await mpc.ecdsa2pSign(t, idx, names, key, new Uint8Array(0), [msg]))[0];
        out.node = await mpc.hdEcdsa2pAccountNode(t, idx, names, ks, scenario.hardened);
        break;
      }
      case "loadsign": {
        // Load a serialized ECDSA-2P key (e.g. made by another version) and sign.
        const key = mpc.deserializeEcdsa2p(scenario.keys[idx]);
        out.pub = mpc.ecdsa2pKeyInfo(key).publicKey;
        out.sig = (await mpc.ecdsa2pSign(t, idx, names, key, new Uint8Array(0), [msg]))[0];
        break;
      }
    }
    self.postMessage({ ok: true, out });
  } catch (e) {
    self.postMessage({ ok: false, error: (e as Error).stack || String(e) });
  }
};
