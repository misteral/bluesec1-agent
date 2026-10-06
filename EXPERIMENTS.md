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
4. **Record.** `scripts/compare_completed.py exp-A exp-B` compares completed tasks and lists shared scenarios.
    `uv run python scripts/summarize_runs.py` prints the metrics row;
   `--scenarios` compares the same scenarios across runs (keyed by alert fingerprint,
   because task ids change on every lease). Fill in results and a one-line conclusion.
5. **Only complete runs compare.** A run is the full queue of **30 tasks** (organisers, 2026-10-06). Every run gets the same 30
   scenarios, **mutated** (new hostnames, IPs, PIDs, ids) and in a different order, so `scenario_fp` (hash of the raw alert) does not
   match across runs and partial runs are biased by which tasks came first. Compare 30/30 runs; treat partial runs as indicative.
6. **Noise floor.** The LLM is stochastic and the queue is small. A delta smaller than the
   spread between two runs of the same config (see `Baselines`) is not an improvement.
7. **Generalise.** The final round uses unseen, mutated scenarios. A change that only helps a
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
| reference agent, dots-3-note-preview:free | exp-002 | _pending_ | second run needed for noise floor |

## Log

| ID | Date | Commit | Model | Hypothesis | Change | reward | quality | effic. | calls | err% | $ | Conclusion |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| exp-000 | 2026-10-06 | 97ac821 | apodex/apodex-1.1-mini:free | reference agent runs on a free model | none | — | — | — | — | — | 0 | **Failed:** provider rejects `json_schema` → all 6 tasks aborted. Added `LLM_RESPONSE_FORMAT`, LLM preflight, stop after 2 consecutive failures. Free tier also hit upstream 429 — seen in a manual LLM-only preflight probe at ~22:01 after the run (not in the run log). |
| exp-001 | 2026-10-06 | 97ac821* | deepseek/deepseek-v4-pro | establish the reference-agent baseline | none (format/preflight fixes only) | n/a | | | | 49/113 ≈ 0.43 | ≈1.17 | **Stopped manually at 22:49 on budget** (7th task in progress; CloseRun sent at 22:49:51, response not confirmed — process interrupted). 6 tasks finished via finish_investigation; server scores not captured (pre-tracking code prints them only at run end — check the platform UI). ~14.5M tokens over 113 LLM steps (+5 invalid attempts); up to 306,107 tokens/step; two 230–250 s gaps ending in an invalid structured reply (cause not established; per-request timeout is 120 s). $ = OpenRouter key usage_daily on 2026-10-06 (includes exp-000 and probes). **Lesson:** the reference loop's full-history context is the cost driver; cap tokens/steps per task before any further run. |
| exp-002 | 2026-10-06 | _see run label_ | dots-studio/dots-3-note-preview:free | free-model baseline of the reference loop; expect err% ≈ 0.4–0.5 like exp-001, ~15–20 calls/task, $0 | none (reference loop; tracking on) | _pending_ | | | | | 0 | |
| exp-003 | 2026-10-06 | 0a67b1d | dots-studio/dots-3-note-preview:free | context hygiene + local call guard (H-01, H-02a): expect tokens/step ↓ ≥5×, err% <0.1, quality ≈ exp-002 | coupled harness change: tool feedback = last_tool_result only (catalog sent once); current_state kept in history; guard answers wrong-id-kind and duplicate calls locally; raw tool results recorded | 63.6 | 0.525 | 0.975 | 15.3 | 0.000 | 0 | **Partial: 6 completed of 8** — 2 tasks aborted by OpenRouter free-tier 429 (20 req/min per key) after I started a 3rd parallel run; stop-after-2-failures fired as designed. Completed-task means vs exp-002 (12 tasks): reward 1.9→63.6, quality 0.25→0.53, err% 0.30→0.00, tokens/task 2.0M→0.42M (≈4.8×). Scenario sets do not overlap (0/20 shared — but the fingerprint is mutation-sensitive, see protocol 5) → reward delta partly sample mix; err% and tokens are sample-independent. Fix: wait out the 429 window (llm._create). |
| exp-004 | 2026-10-06 | _see run label_ | dots-studio/dots-3-note-preview:free | investigation-strategy prompt on top of exp-003: fewer premature benign verdicts (exp-002: 5/7 benign, two at Q=0 → rewards −28.5/−74), more artifacts per malicious task; expect quality ↑ (>0.4), reward ↑, calls/task ≈ or ↓ via search-based neighbourhood | system prompt only: judge behaviour not binary (LOLBins), expansion plan, red flags, benign criteria, RESPOND/FORENSIC artifact kinds, search for typed neighbours (H-05, H-13 prompt part) | _pending_ | | | | | 0 | |
| exp-003b | 2026-10-07 | _see run label_ | dots-studio/dots-3-note-preview:free | full 30-task rerun of exp-003 (harness only, `AGENT_PROMPT=reference`) to separate harness from prompt effects; expect err% ≈ 0, tokens/task ≈ 0.4M | same as exp-003 + 429 wait fix + loop breaker (forced finish after 3 guarded calls in a row / 95 platform calls) | _pending_ | | | | | 0 | |
| exp-005 | 2026-10-07 | _see run label_ | dots-studio/dots-3-note-preview:free | H-13: an agent-side `expand_entity` (one platform search by entity id, typed neighbours) replaces one-get_relation-per-edge; expect calls/task ↓ (exp-004: 120 get_relation vs 4 search in 3 tasks), quality ≥ exp-004; also verifies whether search matches relation endpoint ids | `AGENT_EXPAND_ENTITY=true` + prompt addon, on top of exp-004 (+ 429 wait and loop breaker) | _pending_ | | | | | 0 | |
