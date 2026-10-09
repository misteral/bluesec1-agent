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

Platform limits (organisers' announcement, received 2026-10-06; overrides README's "one run"):
- ≤ **10 active runs** per participant at once; within a run, **one task at a time**.
  → independent experiments can run in parallel as separate processes.
- ≤ **10 run creations per 30 min** per competition stage.
- ≤ **100 tool calls per task**; at the limit the task is closed automatically.
- A run auto-closes after **15 min without client requests** (checked every minute, so 15–16 min).
  It is an idle timeout, not a time limit — a slow LLM step longer than 15 min would lose the run.
- Close runs explicitly on normal completion to free the slot (client or web UI).
- Each run takes the whole task queue and is shown on the leaderboard.
  The user delegated experiment decisions (2026-10-06): launch without asking, prefer free models.
- The LLM must support tool calling / structured output.

## Dev vs prod — no overfitting
Current runs are the **dev** stage (practice queue of 30 tasks). A **prod** stage follows with
unseen, mutated scenarios; the agent must work there, not just score on dev.
- Every change must be justified by general SOC reasoning or a platform contract
  (tool schemas, artifact kinds), never by "this fixes dev task N".
- No scenario-specific values in code or prompts: hostnames, accounts, IPs, hashes, ids,
  non-system file names, alert texts. `uv run python scripts/overfit_check.py` scans recorded
  runs and fails if any such value appears in `src/` — run it before every commit.
- Prompt examples use generic, well-known techniques (LOLBins, persistence types), not wording
  copied from dev alerts.
- Prefer changes that reduce error modes (guards, gates, budgets) over changes that encode
  verdict rules; verdict heuristics must be stated as general detection logic.
- Do not tune thresholds to dev scores alone; check the per-task breakdown for *why*.

## Experiments
Every change to the agent is an experiment, tracked in `EXPERIMENTS.md` (protocol, metrics, log).
Ideas waiting to be tested live in `HYPOTHESES.md` (backlog H-NN with priority and sources);
pick from there, then open an `exp-NNN` row.
- Write the hypothesis and expected metric change in the ledger **before** launching.
- One variable per experiment; commit before the run; launch with `--experiment exp-NNN-name`.
- Each run writes `runs/<timestamp>-<experiment>/` (`config.json`, `steps.jsonl` with error
  texts, `tasks.jsonl` with server scores, `summary.json`). `runs/` is gitignored.
- `uv run python scripts/summarize_runs.py [--scenarios]` produces the ledger row and the
  per-scenario comparison (scenarios keyed by alert fingerprint; task ids change per lease).
- Deltas within the noise floor (spread of repeated baseline runs) do not count.

Budgets (2026-10-09): OpenRouter key ≈$7.6 for mimo/deepseek runs (≈$0.43 per mimo run); owner's Anthropic
key via OpenRouter BYOK — Anthropic budget $150 (Sonnet ≈$27/run, Haiku ≈$1/run); always pin `LLM_PROVIDER_ONLY=anthropic`.

Remotes: `origin` = private `misteral/bluesec1-agent` (ours, push here); `upstream` = the
organisers' public reference repo (pull updates only, never push).
Commit and push after every significant result (finished experiment, working feature),
with the ledger row updated in the same commit.

## SOC expert subagent
`.claude/agents/soc-expert.md` defines **soc-expert** — a senior SOC/IR lead consulted on
investigation logic (complete IR responses, benign evidence, verdict reasoning). Read-only;
returns general principles from real recorded tasks, never scenario-specific rules. Its advice
is a hypothesis: test it (Jev bench or mimo run) before adopting.

## Working rules
- Make changes in `src/bluesec1_agent/`; treat `src/bluesec1_client/` as a vendored dependency.
- Optimise for: correct verdict > complete artifacts > minimal tool calls. Every prompt or loop
  change should be judged against all three.
- Generalise from investigation logic (kill-chain reasoning, relation traversal, benign-evidence
  patterns), not from memorised practice scenarios.
- Log per-task results (verdict, score, tool calls) so changes can be compared run to run.
- Before finishing a change: `uv run pytest` and `uv run ruff check .` must pass.
