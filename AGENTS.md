# AGENTS.md

## Purpose
Our entry for **BlueSec** — Positive Technologies' open competition for AI agents that
investigate security incidents (article: https://habr.com/ru/companies/pt/articles/1085878/,
platform: https://bluesec.team/). The repo started as the organisers' reference ReAct/SGR agent;
we evolve it into a stronger investigator.

Online stage: 2026-09-25 → 2026-10-10. The closed evaluation uses **unseen, mutated scenarios** —
never overfit to specific practice tasks (no hard-coded ids, hostnames, hashes, scenario names).

## The task
The agent receives an alert (JSON: initial entities such as hosts/processes plus relations with
properties — IPs, accounts, command lines, timestamps). It walks an evidence graph over gRPC
(processes, files, network connections, registry writes, AD objects, relations) and submits via
`finish_investigation`:
- **malicious** verdict → response artifacts (compromised hosts, accounts, processes, …), or
- **benign** verdict → graph evidence (entities/relations) proving the activity is legitimate.

Scenarios cover the full kill chain, include legitimate noise and false leads.

Scoring:
1. verdict correctness;
2. investigation completeness (artifacts found);
3. tool efficiency — **every extra tool call lowers the score**. Fewer, targeted calls beat brute force.

## Layout
| Path | What | Edit? |
|---|---|---|
| `src/bluesec1_agent/agent.py` | `SYSTEM_PROMPT`, `SimpleSGRAgent` loop (`run`, `_investigate`, tool feedback) | yes — main work area |
| `src/bluesec1_agent/llm.py` | OpenAI-compatible structured-output step client, JSON extraction | yes |
| `src/bluesec1_agent/models.py` | pydantic `NextStep` schema, tool request models, finish submission models, strict JSON schema builder | yes, carefully — must match runtime tool schemas |
| `src/bluesec1_agent/settings.py` | env-based settings (`pydantic-settings`, reads `.env`) | yes |
| `src/bluesec1_agent/cli.py` | entry point `bluesec1-agent` | yes |
| `src/bluesec1_client/` | runtime client: retries, deadlines, idempotency, validation | **no** — organisers say keep as is |
| `src/bluesec1_client/proto/`, `proto/` | generated gRPC code / schema | no (regenerate via `scripts/generate_remote_proto.py` only if proto changes) |
| `tests/` | pytest suite | keep green, extend for new logic |

The runtime is the source of truth for tools: each task observation carries `available_tools`
with the exact argument schemas. Build calls from that catalog, don't hard-code a contract.

## Secrets
Stored in macOS Keychain via `kc` (see the `env-keychain` skill). Never print or commit them.
- `BLUE_SEC` → `SCENARIO_RUNTIME_TOKEN` (competition platform key)
- `OPENROUTER_API_KEY` → `LLM_API_KEY` (with `LLM_BASE_URL=https://openrouter.ai/api/v1`)

Target model: `xiaomi/mimo-v2.6-flash` (strong on security, cheap; works with both
`LLM_RESPONSE_FORMAT=json_schema` and `json_object`). Free OpenRouter models proved unreliable
(no `json_schema`, upstream 429s).

`.env` is gitignored; `.env.example` is the template. Preferred: keep tokens out of `.env` and
inject them at launch:

```bash
SCENARIO_RUNTIME_TOKEN="$(kc get BLUE_SEC)" LLM_API_KEY="$(kc get OPENROUTER_API_KEY)" \
  uv run --env-file .env bluesec1-agent
```

## Commands
```bash
uv sync                      # install
uv run pytest                # tests
uv run ruff check .          # lint (line length 100, py311)
uv run --env-file .env bluesec1-agent   # real run against the platform
```

Platform constraints:
- Only **one run in flight** per key; a second start is refused until the first finishes.
- A real run consumes the whole task queue and counts toward the leaderboard — ask the user
  before launching one. Use `SCENARIO_RUNTIME_ARENA=practice` for experiments when available.
- `BLUESEC_AGENT_MAX_STEPS` is capped at 100; the LLM must support tool calling / structured output.

## Experiments
Every change to the agent is an experiment, tracked in `EXPERIMENTS.md` (protocol, metrics, log).
- Write the hypothesis and expected metric change in the ledger **before** launching.
- One variable per experiment; commit before the run; launch with `--experiment exp-NNN-name`.
- Each run writes `runs/<timestamp>-<experiment>/` (`config.json`, `steps.jsonl` with error
  texts, `tasks.jsonl` with server scores, `summary.json`). `runs/` is gitignored.
- `uv run python scripts/summarize_runs.py [--scenarios]` produces the ledger row and the
  per-scenario comparison (scenarios keyed by alert fingerprint; task ids change per lease).
- Deltas within the noise floor (spread of repeated baseline runs) do not count.

Remotes: `origin` = private `misteral/bluesec1-agent` (ours, push here); `upstream` = the
organisers' public reference repo (pull updates only, never push).
Commit and push after every significant result (finished experiment, working feature),
with the ledger row updated in the same commit.

## Working rules
- Make changes in `src/bluesec1_agent/`; treat `src/bluesec1_client/` as a vendored dependency.
- Optimise for: correct verdict > complete artifacts > minimal tool calls. Every prompt or loop
  change should be judged against all three.
- Generalise from investigation logic (kill-chain reasoning, relation traversal, benign-evidence
  patterns), not from memorised practice scenarios.
- Log per-task results (verdict, score, tool calls) so changes can be compared run to run.
- Before finishing a change: `uv run pytest` and `uv run ruff check .` must pass.
