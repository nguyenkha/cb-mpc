#!/usr/bin/env bash
# Run the three backends (Rust crates, cb-mpc-ts bun:ffi, cb-mpc-ts WASM) with the same ops and
# runs, one process each (so peak RSS is per backend), and print a markdown table plus sizes.
# Usage (repo root): rust/interop/bench/run-bench.sh [runs_dkg] [runs_sign] [cpu-list]
#   cpu-list (Linux only, e.g. 0): pin every process to those CPUs with taskset (dev3 has 1 vCPU).
# Needs: cargo (CBMPC_OPENSSL_ROOT or CBMPC_NATIVE_DIR for cbmpc-sys), bun, rust/interop deps.
set -euo pipefail
N_DKG=${1:-10}
N_SIGN=${2:-30}
CPUS=${3:-}
ROOT=$PWD
OUT=$(mktemp -d)
pin=() # expanded as ${pin[@]+...}: bash 3.2 + set -u rejects an empty "${pin[@]}"
[ -n "$CPUS" ] && pin=(taskset -c "$CPUS")

(cd rust && cargo build --release --example bench --quiet)
BIN=$(cd rust && cargo build --release --example bench --message-format=json --quiet \
  | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -1)

${pin[@]+"${pin[@]}"} "$BIN" "$N_DKG" "$N_SIGN" > "$OUT/rust.jsonl"
(cd rust/interop && ${pin[@]+"${pin[@]}"} bun bench/ts-bench.ts ffi "$N_DKG" "$N_SIGN") > "$OUT/ffi.jsonl"
(cd rust/interop && ${pin[@]+"${pin[@]}"} bun bench/ts-bench.ts wasm "$N_DKG" "$N_SIGN") > "$OUT/wasm.jsonl"

# Sizes: the bench binary is a minimal Rust signer (2P ECDSA + EdDSA DKG/sign), stripped copy.
cp "$BIN" "$OUT/signer"
strip "$OUT/signer" 2>/dev/null || true
size() { if [ -e "$1" ]; then du -k "$1" | cut -f1; else echo "-"; fi; }
TS=rust/interop/node_modules/cb-mpc
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) PREBUILD=$TS/prebuilds/linux-x64/libcbmpc.so ;;
  Darwin-arm64) PREBUILD=$TS/prebuilds/darwin-arm64/libcbmpc.dylib ;;
  *) PREBUILD=missing ;;
esac

python3 - "$OUT" "$N_DKG" "$N_SIGN" "${CPUS:-all}" <<'PY'
import json, os, sys
out, n_dkg, n_sign, cpus = sys.argv[1:]
rows, meta = {}, {}
for b in ("rust", "ffi", "wasm"):
    for line in open(os.path.join(out, f"{b}.jsonl")):
        if not line.startswith("{"):
            continue
        d = json.loads(line)
        if "op" in d:
            rows.setdefault(d["op"], {})[b] = d
        else:
            meta[b] = d
names = {"rust": "Rust (cbmpc)", "ffi": "TS bun:ffi", "wasm": "TS WASM"}
print(f"runs: DKG {n_dkg}, sign {n_sign}; CPUs pinned: {cpus}; host CPUs: {meta['rust']['cpus']}")
print()
print("| op | " + " | ".join(f"{names[b]} median / p95 ms" for b in names) + " |")
print("|---|" + "---|" * len(names))
for op, by in rows.items():
    print(f"| {op} | " + " | ".join(f"{by[b]['median_ms']} / {by[b]['p95_ms']}" for b in names) + " |")
print("| peak RSS MB | " + " | ".join(str(meta[b]["peak_rss_mb"]) for b in names) + " |")
PY
echo
echo "| size (KiB) | value |"
echo "|---|---|"
echo "| stripped Rust signer (bench binary, cb-mpc + OpenSSL static) | $(size "$OUT/signer") |"
[ -n "${CBMPC_NATIVE_DIR:-}" ] && {
  echo "| libcbmpc.a | $(size "$CBMPC_NATIVE_DIR/lib/libcbmpc.a") |"
  echo "| libcrypto.a (OpenSSL 3.6.4) | $(size "$CBMPC_NATIVE_DIR/lib/libcrypto.a") |"
}
echo "| cb-mpc-ts native prebuild ($(basename "$PREBUILD")) | $(size "$PREBUILD") |"
echo "| cb-mpc-ts cbmpc.wasm | $(size "$TS/cbmpc.wasm") |"
echo "| cb-mpc-ts cbmpc.js (glue) | $(size "$TS/cbmpc.js") |"
cd "$ROOT"
