#!/usr/bin/env bash
# Launch one experiment run in the background with secrets from the macOS keychain.
# Usage: scripts/launch.sh exp-NNN-name [ENV=VALUE ...]
# Extra ENV=VALUE pairs override .env for this run (e.g. AGENT_PROMPT=reference).
set -euo pipefail
cd "$(dirname "$0")/.."
experiment="$1"; shift
for pair in "$@"; do
  # Guard against a whole "A=1 B=2" string arriving as one argument (zsh does not word-split
  # unquoted variables; exp-021/022 first died with LLM_DEFAULT_MODEL="... AGENT_...=true").
  if [[ "$pair" != *=* || "$pair" == *" "* ]]; then
    echo "bad ENV=VALUE argument: '$pair'" >&2; exit 2
  fi
done
token="$(kc get BLUE_SEC)"; llm_key="$(kc get OPENROUTER_API_KEY)"
if [[ -z "$token" || -z "$llm_key" ]]; then
  echo "keychain returned an empty secret; not launching" >&2; exit 1
fi
mkdir -p runs
env "$@" SCENARIO_RUNTIME_TOKEN="$token" LLM_API_KEY="$llm_key" \
  nohup caffeinate -i uv run --env-file .env bluesec1-agent --experiment "$experiment" \
  > "runs/$experiment-$(date +%Y%m%d-%H%M%S).log" 2>&1 &
echo "launched $experiment pid $! log runs/$experiment-*.log"
