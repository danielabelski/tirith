#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
CHECK_SCRIPT="$SCRIPT_DIR/check-threatdb-manifest-transition.py"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/tirith-threatdb-manifest-test.XXXXXX")
trap 'rm -rf -- "$TEST_ROOT"' EXIT

SIGNATURE="/3t78yjtLW37AZ1lmptI8PXo/yWm/3QzJ9REkgDVLT3PLqGYEbR1yFkP5OpsBcloaP8uzKVLuVKrCpvhF+QZAw=="

cat > "$TEST_ROOT/base.json" <<EOF
{"version":100,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1000,"url":"https://github.com/sheeki03/tirith/releases/download/threatdb-latest/tirith-threatdb-100-1.dat","signature":"$SIGNATURE"}
EOF
cat > "$TEST_ROOT/forward.json" <<EOF
{"version":101,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":1001,"url":"https://github.com/sheeki03/tirith/releases/download/threatdb-latest/tirith-threatdb-101-1.dat","signature":"$SIGNATURE"}
EOF
cat > "$TEST_ROOT/regression.json" <<EOF
{"version":99,"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":999,"url":"https://github.com/sheeki03/tirith/releases/download/threatdb-latest/tirith-threatdb-99-1.dat","signature":"$SIGNATURE"}
EOF
cat > "$TEST_ROOT/equivocation.json" <<EOF
{"version":100,"sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","size":1000,"url":"https://github.com/sheeki03/tirith/releases/download/threatdb-latest/tirith-threatdb-100-1.dat","signature":"$SIGNATURE"}
EOF
cat > "$TEST_ROOT/duplicate.json" <<EOF
{"version":101,"version":102,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":1001,"url":"https://github.com/sheeki03/tirith/releases/download/threatdb-latest/tirith-threatdb-101-1.dat","signature":"$SIGNATURE"}
EOF

python3 "$CHECK_SCRIPT" "$TEST_ROOT/base.json"
python3 "$CHECK_SCRIPT" "$TEST_ROOT/base.json" "$TEST_ROOT/forward.json"

if python3 "$CHECK_SCRIPT" "$TEST_ROOT/base.json" "$TEST_ROOT/regression.json" \
    > "$TEST_ROOT/regression.log" 2>&1; then
  echo "expected a manifest version rollback to fail" >&2
  exit 1
fi
grep -Fq 'manifest version regressed from 100 to 99' "$TEST_ROOT/regression.log"

if python3 "$CHECK_SCRIPT" "$TEST_ROOT/base.json" "$TEST_ROOT/equivocation.json" \
    > "$TEST_ROOT/equivocation.log" 2>&1; then
  echo "expected same-version manifest equivocation to fail" >&2
  exit 1
fi
grep -Fq 'manifest equivocates at version 100' "$TEST_ROOT/equivocation.log"

if python3 "$CHECK_SCRIPT" "$TEST_ROOT/duplicate.json" \
    > "$TEST_ROOT/duplicate.log" 2>&1; then
  echo "expected duplicate manifest keys to fail" >&2
  exit 1
fi
grep -Fq 'duplicate JSON key: version' "$TEST_ROOT/duplicate.log"

echo "threatdb manifest transition regression passed"
