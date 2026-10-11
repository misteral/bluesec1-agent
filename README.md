# BlueSec1 agent

An LLM agent for [BlueSec](https://bluesec.team/) — Positive Technologies' open competition for
AI agents that investigate security incidents
([announcement](https://habr.com/ru/companies/pt/articles/1085878/)). The agent receives a
security alert, walks an evidence graph through the competition runtime (processes, files,
network connections, registry writes, AD objects and the relations between them) and submits a
verdict: a real attack with the artifacts that need a response, or a false positive with the
evidence that proves the activity is legitimate.

Built on the organisers' reference agent
([False-Positive-Community/bluesec1-agent](https://github.com/False-Positive-Community/bluesec1-agent)).
The runtime client `src/bluesec1_client/` and the proto are theirs and kept unchanged; the
investigation harness in `src/bluesec1_agent/` is reworked.

## Result

Graded credit stage (2026-10-10, 40 unseen tasks): **19.87 points, 25th place**.

| | |
|---|---|
| Model | `xiaomi/mimo-v2.6-flash` via OpenRouter |
| Verdicts | 28/28 attacks right; 8/12 benign right (4 missed attacks) |
| Tool calls | 16.1 per task, 0.3% erroneous calls |
| Cost | $0.40 for the whole run (≈$0.01 per task), 56 min |

Task score on the platform is `Q · (0.6 + 0.4 · efficiency)`, where `Q` is verdict plus
payload quality and efficiency drops with every tool call. The run score is the sum over tasks.

On the practice queue the agent went from 6.1 (reference loop, free model) to ≈17 out of 30
over about 60 tracked experiments. The full log is in [`EXPERIMENTS.md`](EXPERIMENTS.md), and
the hypotheses, with the reasons rejected ones were dropped, are in [`HYPOTHESES.md`](HYPOTHESES.md).

## How it works

Since every platform tool call lowers the score, most of the harness exists to stop the model
from wasting calls, and to check its conclusion with code before anything is submitted.

- **Context hygiene** (`agent.py`): the tool catalog is sent once, and after that the model
  sees only the last tool result and its own running state. This cut tokens per task about 5×
  and removed most malformed calls.
- **Local call guard** (`guard.py`): repeated calls are answered from a cache, and ids passed
  to the wrong getter are rejected locally. Neither reaches the scored runtime.
- **Harness-side lookups** (`agent.py`): code fetches the account and origin entities behind
  the alerted process and resolves relations it already knows, so the model does not spend
  calls on them.
- **SGR `conclude` step** (`conclude.py`): before finishing, the model states a structured
  conclusion. For a benign verdict, code checks the task's own call log for the evidence an
  analyst would require (host activity window, inbound source, process effects) and returns a
  specific instruction if anything is missing. The check demands evidence and never pushes the
  verdict either way.
- **Finish gates and review** (`review.py`): deterministic checks compare the payload with the
  entities the agent actually observed. Artifact kinds are fixed per entity type, rows are
  cleaned and capped at 8, and the account running attacker code must be marked for rotation.
  The model then gets one review turn with a precision checklist. None of this costs a
  platform call.
- **Experiment tracking** (`tracking.py`): every run writes `runs/<timestamp>-<experiment>/`
  with its config, every step, per-task server scores and a summary. `runs/` is gitignored
  because it holds platform data.

An alternative agent, in which a small decision model (Jev) navigates the graph and code builds
all the arguments, lives in `jev_agent.py` / `jev_evidence.py` (`AGENT_KIND=jev_llm|jev_only`).
It made zero malformed calls but produced weaker payloads, so the final configuration uses the
LLM agent.

What did not help, briefly:
- bigger models: Opus was ≈+0.04 per task at ≈180× the cost, and Sonnet/Haiku leaned towards
  false positives;
- free OpenRouter models: no `json_schema` support and upstream 429s;
- any rule tied to specific practice scenarios, since the graded stage used mutated, unseen
  ones. `scripts/overfit_check.py` fails if values from recorded runs appear in `src/`.

## Quick start

You need Python 3.11+, [uv](https://docs.astral.sh/uv/), a BlueSec runtime key and an
OpenAI-compatible LLM provider.

```bash
uv sync
cp .env.example .env   # fill in the runtime endpoint/key and the LLM provider
```

Run the final configuration (final-v4). Every feature is an env flag, off by default, so with
no flags you get the reference loop.

```bash
SCENARIO_RUNTIME_TOKEN=... LLM_API_KEY=... \
LLM_DEFAULT_MODEL=xiaomi/mimo-v2.6-flash \
AGENT_EXPAND_ENTITY=true AGENT_FINISH_REVIEW=true AGENT_REVIEW_PRECISION=true \
AGENT_PAYLOAD_POLICY=true AGENT_PAYLOAD_TIERS=false PAYLOAD_NO_TELEMETRY=true \
AGENT_BENIGN_EMPTY=true AGENT_CONCLUDE_FLAGS=host_window,inbound_source,effects \
AGENT_ROTATE_IDENTITY=true AGENT_RESOLVE_ROOTS=true AGENT_LOCAL_RELATIONS=true \
AGENT_CLEAN_ROWS=true AGENT_MAX_ROWS=8 LLM_RUN_BUDGET_USD=10 \
  uv run --env-file .env bluesec1-agent --experiment exp-001-my-run
```

`scripts/launch_final.sh` runs the same configuration in the background. It reads secrets from
the macOS Keychain through [`kc`](scripts/launch.sh), so adapt it if you keep secrets elsewhere.
All settings are listed in `src/bluesec1_agent/settings.py`.

Useful scripts:

```bash
uv run python scripts/summarize_runs.py [--scenarios]   # metrics row per run, per-scenario comparison
uv run python scripts/compare_completed.py exp-A exp-B  # compare two runs on shared scenarios
uv run python scripts/overfit_check.py                  # no scenario-specific values in src/
```

## Development

```bash
uv run pytest
uv run ruff check .
```

`AGENTS.md` contains the working rules used while developing with coding agents: the experiment
protocol, platform limits and the no-overfitting policy.

## License

No license file. The runtime client and proto (`src/bluesec1_client/`, `proto/`) and the
original reference agent belong to the competition organisers; ask them before reusing that
part. The rest is published for reference.
