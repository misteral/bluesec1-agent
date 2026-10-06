#!/usr/bin/env bash
# Wait until a local time, then retry launching until the keychain is unlocked.
# Usage: scripts/launch_when_ready.sh HH:MM exp-NNN-name [ENV=VALUE ...]
set -uo pipefail
cd "$(dirname "$0")/.."
not_before="$1"; shift
until [[ "$(date +%H:%M)" > "$not_before" || "$(date +%H:%M)" == "$not_before" ]]; do sleep 60; done
until kc get BLUE_SEC --silent >/dev/null 2>&1; do
  echo "$(date +%T) keychain locked; retrying in 5 min"; sleep 300
done
scripts/launch.sh "$@"
