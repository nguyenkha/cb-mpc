#!/usr/bin/env bash
# For the release pinned in rust/cbmpc-sys/prebuilt.rs (if any): download every pinned
# cbmpc-native-<platform>.tar.gz, compare its sha256 with the pin, and verify its GitHub build
# provenance (gh attestation verify, this repo's workflows). Sets the step output pinned=true|false.
# Usage: check-pinned-prebuilt.sh <prebuilt.rs>   (needs gh with GH_TOKEN)
set -euo pipefail
FILE=$1
REPO=${GITHUB_REPOSITORY:-nguyenkha/cb-mpc}
TAG=$(sed -n 's/^const PREBUILT_TAG: &str = "\(.*\)";$/\1/p' "$FILE")
out() { [ -n "${GITHUB_OUTPUT:-}" ] && echo "pinned=$1" >> "$GITHUB_OUTPUT"; return 0; }
if [ -z "$TAG" ]; then
  echo "no release pinned in $FILE"
  out false
  exit 0
fi
W=$(mktemp -d)
pins=$(sed -n 's/^ *("\([a-z0-9-]*\)", "\([0-9a-f]\{64\}\)"),*$/\1 \2/p' "$FILE")
[ -n "$pins" ] || { echo "PREBUILT_TAG=$TAG but no (platform, sha256) pins parsed from $FILE" >&2; exit 1; }
while read -r platform sha; do
  name="cbmpc-native-$platform.tar.gz"
  gh release download "$TAG" --repo "$REPO" --pattern "$name" --dir "$W"
  got=$( (sha256sum "$W/$name" 2>/dev/null || shasum -a 256 "$W/$name") | cut -d' ' -f1)
  [ "$got" = "$sha" ] || { echo "$name: sha256 $got does not match the pin $sha" >&2; exit 1; }
  gh attestation verify "$W/$name" --repo "$REPO"
  echo "ok $name ($TAG)"
done <<< "$pins"
out true
