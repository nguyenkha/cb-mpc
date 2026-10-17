#!/usr/bin/env bash
# Link check for cbmpc-native-ios.xcframework.zip: for the device and the simulator slice, link a
# small C program against libcbmpc.a with -force_load (every object in the archive must resolve,
# not only the ones the program references) and check the slice's architecture.
# Usage (macOS + Xcode): check-ios-xcframework.sh <cbmpc-native-ios.xcframework.zip>
set -euo pipefail
ZIP=$1
W=$(mktemp -d)
ditto -x -k "$ZIP" "$W"
XCF="$W/CbMpc.xcframework"
cat > "$W/check.c" <<'EOF'
#include "cbmpc_ts.h"
int main(void) {
  ecurve_ref c = new_ecurve(714); /* secp256k1 */
  cmem_t order = ecurve_order(&c);
  free_ecurve(c);
  return (order.size == 32 && cbmpc_ts_take_last_error() == 0) ? 0 : 1;
}
EOF
for slice in ios-arm64:iphoneos:arm64-apple-ios15.0 ios-arm64-simulator:iphonesimulator:arm64-apple-ios15.0-simulator; do
  IFS=: read -r dir sdk target <<< "$slice"
  lib="$XCF/$dir/libcbmpc.a"
  [ -f "$lib" ] || { echo "missing $dir/libcbmpc.a" >&2; exit 1; }
  xcrun lipo -info "$lib" | grep -q "arm64" || { echo "$dir is not arm64" >&2; exit 1; }
  xcrun --sdk "$sdk" clang -target "$target" -I"$XCF/$dir/Headers" "$W/check.c" \
    -Wl,-force_load,"$lib" -lc++ -o "$W/check-$dir"
  echo "linked $dir"
done
