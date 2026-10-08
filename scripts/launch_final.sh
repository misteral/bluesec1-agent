#!/usr/bin/env bash
# Frozen final configuration v2 (exp-036: score~ 16.55 at 30/30, 0 wrong verdicts, 2026-10-09):
# mimo LLM agent + expand_entity + finish review (precision checklist) + payload policy
# (benign cap, no tier rows, no telemetry rows) + empty benign evidence + retry/idle guards
# + SGR conclude step with code-verified checks K1–K3 (H-44).
# Usage: scripts/launch_final.sh exp-NNN-name   (credit day: run several in parallel, keep the best)
set -euo pipefail
cd "$(dirname "$0")/.."
# A run whose CreateRun fails (exp-032 hit a transient server error at 17:34) is relaunched
# up to 3 times; once a task has started, the agent's own retries take over.
for attempt in 1 2 3; do
  scripts/launch.sh "$1" \
  LLM_DEFAULT_MODEL=xiaomi/mimo-v2.6-flash \
  AGENT_EXPAND_ENTITY=true \
  AGENT_FINISH_REVIEW=true \
  AGENT_REVIEW_PRECISION=true \
  AGENT_PAYLOAD_POLICY=true \
  AGENT_PAYLOAD_TIERS=false \
  PAYLOAD_NO_TELEMETRY=true \
  AGENT_BENIGN_EMPTY=true \
  AGENT_CONCLUDE_FLAGS=host_window,inbound_source,effects \
  LLM_RUN_BUDGET_USD=1.0
  sleep 90
  log=$(ls -t runs/"$1"-*.log | head -1)
  if grep -q "Starting structured investigation" "$log"; then exit 0; fi
  if ! grep -qE "RemoteServerError|RemoteUnavailableError|Cannot reach the runtime" "$log"; then exit 0; fi
  echo "attempt $attempt: run did not start ($log); retrying in 60 s" >&2
  sleep 60
done
exit 1
