#!/usr/bin/env bash

# Fetch every required threat-database source as one fail-closed transaction.
# Jobs write only below a private staging directory. The complete source set is
# exposed to the compiler with one same-filesystem rename after every PID has
# been waited successfully and every expected output has been validated.

set -euo pipefail

OUTPUT_ROOT=${THREATDB_FETCH_OUTPUT_DIR:-/tmp}
FINAL_DIR="$OUTPUT_ROOT/tirith-threatdb-sources"

mkdir -p -- "$OUTPUT_ROOT"
if [ -e "$FINAL_DIR" ]; then
  echo "::error::threatdb source destination already exists: $FINAL_DIR" >&2
  exit 1
fi

pids=()
labels=()

cleanup() {
  local pid
  # `${array[@]}` is an error for an empty array under Bash 3.2 + `set -u`;
  # the `${array+...}` guard keeps the cleanup portable to macOS as well as CI.
  for pid in ${pids+"${pids[@]}"}; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  for pid in ${pids+"${pids[@]}"}; do
    wait "$pid" 2>/dev/null || true
  done
  rm -rf -- "$STAGING_DIR"
}

STAGING_DIR=$(mktemp -d "$OUTPUT_ROOT/.tirith-threatdb-fetch.XXXXXX")
trap cleanup EXIT
STAGED_SOURCES="$STAGING_DIR/sources"
mkdir -p -- "$STAGED_SOURCES"

FETCH_TIMEOUT_SECONDS=${THREATDB_FETCH_TIMEOUT_SECONDS:-180}
case "$FETCH_TIMEOUT_SECONDS" in
  ''|*[!0-9]*|0)
    echo "::error::THREATDB_FETCH_TIMEOUT_SECONDS must be a positive integer" >&2
    exit 1
    ;;
esac

TIMEOUT_BIN=${THREATDB_FETCH_TIMEOUT_BIN:-}
if [ -z "$TIMEOUT_BIN" ]; then
  TIMEOUT_BIN=$(command -v timeout 2>/dev/null || command -v gtimeout 2>/dev/null || true)
fi
if [ -z "$TIMEOUT_BIN" ] || [ ! -x "$TIMEOUT_BIN" ]; then
  echo "::error::GNU timeout is required for bounded threatdb source fetches" >&2
  exit 1
fi

run_fetch() {
  "$TIMEOUT_BIN" --signal=TERM --kill-after=10s "${FETCH_TIMEOUT_SECONDS}s" "$@"
}

run_fetch git clone --depth 1 \
  https://github.com/ossf/malicious-packages.git \
  "$STAGED_SOURCES/ossf-mp" &
pids+=("$!")
labels+=("OpenSSF malicious-packages")

run_fetch git clone --depth 1 \
  https://github.com/DataDog/malicious-software-packages-dataset.git \
  "$STAGED_SOURCES/dd-mp" &
pids+=("$!")
labels+=("DataDog malicious-software-packages-dataset")

run_fetch curl -sSfL \
  https://feodotracker.abuse.ch/downloads/ipblocklist.txt \
  -o "$STAGED_SOURCES/feodo.txt" &
pids+=("$!")
labels+=("Feodo Tracker")

run_fetch curl -sSfL \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  -o "$STAGED_SOURCES/cisa-kev.json" &
pids+=("$!")
labels+=("CISA KEV")

failed=0
for index in "${!pids[@]}"; do
  if wait "${pids[$index]}"; then
    echo "Fetched ${labels[$index]}"
  else
    status=$?
    echo "::error::failed to fetch ${labels[$index]} (exit $status)" >&2
    failed=1
  fi
done
pids=()
if (( failed != 0 )); then
  exit 1
fi

if [ ! -d "$STAGED_SOURCES/ossf-mp/.git" ] ||
   [ ! -d "$STAGED_SOURCES/dd-mp/.git" ] ||
   [ ! -s "$STAGED_SOURCES/feodo.txt" ] ||
   [ ! -s "$STAGED_SOURCES/cisa-kev.json" ]; then
  echo "::error::one or more required threatdb sources is empty or incomplete" >&2
  exit 1
fi

# STAGING_DIR was created inside OUTPUT_ROOT, so this publishes the complete set
# atomically on the same filesystem. No compiler-visible path exists beforehand.
mv -- "$STAGED_SOURCES" "$FINAL_DIR"
echo "Sources fetched successfully into $FINAL_DIR"
