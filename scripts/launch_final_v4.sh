#!/usr/bin/env bash
# Candidate final configuration v4 = final-v3 + soc-expert consultation 4 (H-A root resolution,
# H-B cleanup, H-C cap 8, H-E local relations). exp-055: 17.25 at 30/30, 0 wrong verdicts;
# replicate exp-057 decides adoption. Usage: scripts/launch_final_v4.sh exp-NNN-name
set -euo pipefail
cd "$(dirname "$0")/.."
exec scripts/launch_variant.sh "$1" \
  AGENT_RESOLVE_ROOTS=true AGENT_LOCAL_RELATIONS=true AGENT_CLEAN_ROWS=true AGENT_MAX_ROWS=8
