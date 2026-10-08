#!/usr/bin/env bash
# Launch the final configuration plus extra ENV=VALUE overrides (one experiment variable).
# Usage: scripts/launch_variant.sh exp-NNN-name EXTRA=VALUE [...]
set -euo pipefail
cd "$(dirname "$0")/.."
name="$1"; shift
final=()
while IFS= read -r pair; do final+=("$pair"); done < <(
  grep -E '^  [A-Z_]+=' scripts/launch_final.sh | sed -E 's/^  ([A-Z_]+=[^ ]+).*/\1/'
)
exec scripts/launch.sh "$name" "${final[@]}" "$@"
