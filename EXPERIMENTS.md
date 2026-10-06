# Experiment ledger

Single source of truth for what we tried and what it did to the score.
Raw artifacts live in `runs/` (gitignored, contains platform data); this file is committed.

## Protocol

1. **Hypothesis first.** Before launching, add a row below with `Hypothesis` and `Change`
   filled in and results empty. Write the expected direction ("err% ↓ from 0.57 to <0.2,
   reward ↑"), not just the idea.
2. **One variable per experiment.** Model, prompt, loop logic, context policy — change one.
   If two changes are coupled, say so in `Change`.
3. **Commit before the run.** The ledger cites a commit; a `*` after it means the tree was dirty
   and the result is not reproducible. Run with an id:
   ```bash
   SCENARIO_RUNTIME_TOKEN="$(kc get BLUE_SEC)" LLM_API_KEY="$(kc get OPENROUTER_API_KEY)" \
     uv run --env-file .env bluesec1-agent --experiment exp-NNN-short-name
   ```
   On the platform the run is labelled `<experiment>@<commit>` (`-dirty` if uncommitted) under
   the stable `AGENT_NAME`; experiment, commit and prompt hash also go into run metadata.
4. **Record.** `uv run python scripts/summarize_runs.py` prints the metrics row;
   `--scenarios` compares the same scenarios across runs (keyed by alert fingerprint,
   because task ids change on every lease). Fill in results and a one-line conclusion.
5. **Noise floor.** The LLM is stochastic and the queue is small. A delta smaller than the
   spread between two runs of the same config (see `Baselines`) is not an improvement.
6. **Generalise.** The final round uses unseen, mutated scenarios. A change that only helps a
   specific practice scenario (hard-coded ids, names, hashes) is rejected even if it scores.

## Metrics

| Metric | Source | Meaning |
|---|---|---|
| reward | server `total_reward`, mean per task | the competition score — primary |
| quality | server `quality_score` | verdict + artifact completeness |
| effic. | server `efficiency_score` | tool-call economy |
| calls | server `tool_calls` | tool calls per task |
| err% | agent `error_calls / tool_calls` | calls that returned a non-ok status (pure waste) |
| tokens, $ | provider usage | cost of the run |

Per run (`runs/<timestamp>-<experiment>/`): `config.json` (model, prompt hash, commit),
`observations.jsonl`, `steps.jsonl` (arguments, status, error text, usage per step),
`tasks.jsonl` (server result + agent counters, verdict, artifacts), `summary.json`.

## Baselines

| Config | Runs | reward mean | spread |
|---|---|---|---|
| reference agent, deepseek-v4-pro | exp-001 (stopped) | scores only on platform UI | not repeated — too expensive |

## Log

| ID | Date | Commit | Model | Hypothesis | Change | reward | quality | effic. | calls | err% | $ | Conclusion |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| exp-000 | 2026-10-06 | 97ac821 | apodex/apodex-1.1-mini:free | reference agent runs on a free model | none | — | — | — | — | — | 0 | **Failed:** provider rejects `json_schema` → all 6 tasks aborted. Added `LLM_RESPONSE_FORMAT`, LLM preflight, stop after 2 consecutive failures. Free tier also hit upstream 429 — seen in a manual LLM-only preflight probe at ~22:01 after the run (not in the run log). |
| exp-001 | 2026-10-06 | 97ac821* | deepseek/deepseek-v4-pro | establish the reference-agent baseline | none (format/preflight fixes only) | n/a | | | | 49/113 ≈ 0.43 | ≈1.17 | **Stopped manually at 22:49 on budget** (7th task in progress; CloseRun sent at 22:49:51, response not confirmed — process interrupted). 6 tasks finished via finish_investigation; server scores not captured (pre-tracking code prints them only at run end — check the platform UI). ~14.5M tokens over 113 LLM steps (+5 invalid attempts); up to 306,107 tokens/step; two 230–250 s gaps ending in an invalid structured reply (cause not established; per-request timeout is 120 s). $ = OpenRouter key usage_daily on 2026-10-06 (includes exp-000 and probes). **Lesson:** the reference loop's full-history context is the cost driver; cap tokens/steps per task before any further run. |
