/**
 * Access structures for access-structure (AC) keys: which party sets can sign.
 *
 *   thresholdOf(2, ["iphone", "mac", "server"])   // any 2 of 3
 *   { and: [{ leaf: "server" }, thresholdOf(1, ["iphone", "mac"])] }
 *
 * Every party must pass the same structure to dkgAc / refreshAc / signAc / reshareFromAdditive.
 */
export type AccessStructure =
  | { leaf: string }
  | { and: AccessStructure[] }
  | { or: AccessStructure[] }
  | { threshold: number; of: AccessStructure[] };

/** k-of-n over plain party names. */
export function thresholdOf(k: number, partyNames: string[]): AccessStructure {
  return { threshold: k, of: partyNames.map((leaf) => ({ leaf })) };
}

/** Binary encoding read by capi/access_structure_codec.h. */
export function encodeAccessStructure(ac: AccessStructure): Uint8Array {
  const out: number[] = [];
  const u32 = (v: number) => {
    if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) throw new RangeError("access structure: bad integer");
    out.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  };
  const children = (list: AccessStructure[]) => {
    u32(list.length);
    for (const c of list) node(c);
  };
  const node = (n: AccessStructure) => {
    if ("leaf" in n) {
      const name = new TextEncoder().encode(n.leaf);
      out.push(1);
      u32(name.length);
      for (const b of name) out.push(b);
    } else if ("and" in n) {
      out.push(2);
      children(n.and);
    } else if ("or" in n) {
      out.push(3);
      children(n.or);
    } else {
      out.push(4);
      u32(n.threshold);
      children(n.of);
    }
  };
  node(ac);
  return new Uint8Array(out);
}
