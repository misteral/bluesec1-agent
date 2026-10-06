"""Compare runs on completed (non-aborted) tasks only, plus per-scenario overlap.

Usage: uv run python scripts/compare_completed.py exp-002 exp-003 exp-004
"""

import json
import sys
from pathlib import Path

RUNS = Path(__file__).resolve().parents[1] / "runs"


def load(experiment: str) -> list[dict]:
    """Return task records of the latest run directory matching an experiment id."""
    directory = sorted(RUNS.glob(f"*-{experiment}*/"))[-1]
    return [json.loads(line) for line in (directory / "tasks.jsonl").open()]


def main() -> None:
    """Print completed-task means and the scenarios shared between runs."""
    by_run = {name: load(name) for name in sys.argv[1:]}
    print("| run | done/all | reward | quality | effic. | calls | err% | benign | tokens/task |")
    print("|---|---|---|---|---|---|---|---|---|")
    for name, tasks in by_run.items():
        done = [t for t in tasks if t["completion_reason"] == "terminated"]
        n = len(done) or 1
        calls = sum(t["tool_calls"] for t in done) or 1
        print(
            f"| {name} | {len(done)}/{len(tasks)} "
            f"| {sum(t['total_reward'] for t in done) / n:.1f} "
            f"| {sum(t['quality_score'] for t in done) / n:.3f} "
            f"| {sum(t['efficiency_score'] for t in done) / n:.3f} "
            f"| {sum(t['tool_calls'] for t in done) / n:.1f} "
            f"| {sum(t.get('error_calls', 0) for t in done) / calls:.3f} "
            f"| {sum(t.get('verdict') == 'benign' for t in done)}/{len(done)} "
            f"| {sum(t.get('total_tokens', 0) for t in done) / n / 1000:.0f}k |"
        )
    scenarios: dict[str, dict[str, float]] = {}
    for name, tasks in by_run.items():
        for t in tasks:
            if t["completion_reason"] == "terminated":
                scenarios.setdefault(t["scenario_fp"], {})[name] = t["total_reward"]
    shared = {fp: s for fp, s in scenarios.items() if len(s) > 1}
    print(f"\nScenarios seen in more than one run: {len(shared)} of {len(scenarios)}")
    for fp, scores in sorted(shared.items()):
        print(fp, {k: round(v, 1) for k, v in scores.items()})


if __name__ == "__main__":
    main()
