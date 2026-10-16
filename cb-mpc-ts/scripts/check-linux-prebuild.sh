#!/usr/bin/env bash
# Fail if a Linux prebuild needs more than the supported baseline:
#   - glibc symbol versions above $MAX_GLIBC (default 2.28: Debian 10+, Ubuntu 18.10+, RHEL/Alma 8+, AL2023)
#   - any dynamic C++ runtime (libstdc++ / GLIBCXX / CXXABI); it must be linked statically
# Usage: check-linux-prebuild.sh <libcbmpc.so>...
set -euo pipefail
MAX_GLIBC=${MAX_GLIBC:-2.28}
status=0
LIBC=${CBMPC_LIBC:-glibc}
for so in "$@"; do
  echo "== $so"
  needed=$(objdump -p "$so" | awk '/NEEDED/ {print $2}' | tr '\n' ' ')
  echo "   NEEDED: $needed"
  if grep -qE 'libstdc\+\+|libc\+\+' <<<"$needed"; then
    echo "   FAIL: dynamic C++ runtime"; status=1
  fi
  if objdump -T "$so" | grep -qE 'GLIBCXX_|CXXABI_'; then
    echo "   FAIL: GLIBCXX/CXXABI symbol versions present"; status=1
  fi
  if [ "$LIBC" = musl ]; then
    # musl has no symbol versioning; just require the musl loader and no glibc.
    if grep -q 'libc.so.6' <<<"$needed"; then echo "   FAIL: links glibc"; status=1; fi
    continue
  fi
  max=$(objdump -T "$so" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)*' | sed 's/GLIBC_//' | sort -V | tail -1)
  echo "   max GLIBC: ${max:-none} (allowed <= $MAX_GLIBC)"
  if [ -n "$max" ] && [ "$(printf '%s\n%s\n' "$max" "$MAX_GLIBC" | sort -V | tail -1)" != "$MAX_GLIBC" ]; then
    echo "   FAIL: needs glibc $max"; objdump -T "$so" | grep "GLIBC_$max" | awk '{print "     " $NF}' | head; status=1
  fi
done
exit $status
