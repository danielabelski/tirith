#!/usr/bin/env bash

# Deterministic regression for the workflow fetch transaction. One background
# fetch writes partial bytes and fails while all siblings succeed; the wrapper
# must return nonzero, leave no compiler-visible source directory, and prevent
# the simulated compile/publication continuation from running.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
FETCH_SCRIPT="$SCRIPT_DIR/fetch-threatdb-sources.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/tirith-threatdb-fetch-test.XXXXXX")
trap 'rm -rf -- "$TEST_ROOT"' EXIT

FAKE_BIN="$TEST_ROOT/bin"
OUTPUT_ROOT="$TEST_ROOT/output"
mkdir -p -- "$FAKE_BIN" "$OUTPUT_ROOT"

cat > "$FAKE_BIN/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
destination=${!#}
mkdir -p -- "$destination/.git"
printf 'fixture\n' > "$destination/feed.json"
if [[ "$*" == *"${FAKE_FETCH_FAILURE:-never-match}"* ]]; then
  exit 41
fi
if [[ "$*" == *"${FAKE_FETCH_HANG:-never-match}"* ]]; then
  while :; do read -r -t 1 _ || :; done
fi
EOF

cat > "$FAKE_BIN/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=
url=
while (( $# > 0 )); do
  case "$1" in
    -o)
      output=$2
      shift 2
      ;;
    http://*|https://*)
      url=$1
      shift
      ;;
    *)
      shift
      ;;
  esac
done
if [ -z "$output" ] || [ -z "$url" ]; then
  exit 64
fi
printf 'fixture for %s\n' "$url" > "$output"
if [[ "$url" == *"${FAKE_FETCH_FAILURE:-never-match}"* ]]; then
  exit 42
fi
if [[ "$url" == *"${FAKE_FETCH_HANG:-never-match}"* ]]; then
  while :; do read -r -t 1 _ || :; done
fi
EOF

cat > "$FAKE_BIN/timeout" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
while (( $# > 0 )); do
  case "$1" in
    --signal=*|--kill-after=*) shift ;;
    *) break ;;
  esac
done
duration=${1%s}
shift
case "$duration" in
  ''|*[!0-9]*) exit 64 ;;
esac
"$@" &
child=$!
(
  sleep "$duration"
  kill -TERM "$child" 2>/dev/null || exit 0
  sleep 0.2
  kill -KILL "$child" 2>/dev/null || true
) &
watchdog=$!
wait "$child"
status=$?
kill "$watchdog" 2>/dev/null || true
wait "$watchdog" 2>/dev/null || true
case "$status" in
  137|143) exit 124 ;;
  *) exit "$status" ;;
esac
EOF

chmod +x "$FAKE_BIN/git" "$FAKE_BIN/curl" "$FAKE_BIN/timeout"

compile_reached="$TEST_ROOT/compile-reached"

# Preflight validation happens after private staging is created. Invalid
# configuration must still leave neither staging nor a compiler-visible output.
status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
   THREATDB_FETCH_TIMEOUT_SECONDS=invalid \
   bash "$FETCH_SCRIPT"; then
  touch "$compile_reached"
else
  status=$?
fi
if (( status == 0 )); then
  echo "expected an invalid fetch timeout to fail preflight" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "invalid fetch timeout reached compile/publication" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "invalid fetch timeout left private staging state" >&2
  exit 1
fi

status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_FETCH_TIMEOUT_BIN="$TEST_ROOT/missing-timeout" \
   bash "$FETCH_SCRIPT"; then
  touch "$compile_reached"
else
  status=$?
fi
if (( status == 0 )); then
  echo "expected a missing timeout binary to fail preflight" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "missing timeout binary reached compile/publication" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "missing timeout binary left private staging state" >&2
  exit 1
fi

for failed_source in \
  ossf/malicious-packages \
  DataDog/malicious-software-packages-dataset \
  ipblocklist \
  known_exploited_vulnerabilities
do
  status=0
  if PATH="$FAKE_BIN:$PATH" \
     THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
     THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
     FAKE_FETCH_FAILURE="$failed_source" \
     bash "$FETCH_SCRIPT"; then
    touch "$compile_reached"
  else
    status=$?
  fi

  if (( status == 0 )); then
    echo "expected failed required fetch $failed_source to fail the transaction" >&2
    exit 1
  fi
  if [ -e "$compile_reached" ]; then
    echo "compile/publication continuation ran after $failed_source failed" >&2
    exit 1
  fi
  if [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
    echo "a partial source set became visible after $failed_source failed" >&2
    exit 1
  fi
  if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
    echo "failed source-fetch staging state was not cleaned after $failed_source" >&2
    exit 1
  fi
done

# A required source that never returns must be terminated by the wrapper's
# deadline, cleaned from private staging, and block the compile continuation.
status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
   THREATDB_FETCH_TIMEOUT_SECONDS=1 \
   FAKE_FETCH_HANG=ipblocklist \
   bash "$FETCH_SCRIPT"; then
  touch "$compile_reached"
else
  status=$?
fi
if (( status == 0 )); then
  echo "expected a hung required fetch to time out" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "hung fetch reached compile/publication" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "hung source-fetch staging state was not cleaned" >&2
  exit 1
fi

PATH="$FAKE_BIN:$PATH" \
THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
bash "$FETCH_SCRIPT"

published="$OUTPUT_ROOT/tirith-threatdb-sources"
test -d "$published/ossf-mp/.git"
test -d "$published/dd-mp/.git"
test -s "$published/feodo.txt"
test -s "$published/cisa-kev.json"

echo "threatdb source-fetch orchestration regression passed"
