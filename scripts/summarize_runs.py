"""Summarize recorded runs for the experiment ledger.

Usage:
    uv run python scripts/summarize_runs.py                 # table of all runs
    uv run python scripts/summarize_runs.py --scenarios     # per-scenario scores across runs
    uv run python scripts/summarize_runs.py --import-log runs/x.log --experiment exp-001 \
        --model deepseek/deepseek-v4-pro                    # import a pre-tracking log
"""

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from bluesec1_agent.tracking import RUNS_DIR, RunRecorder, summarize_tasks  # noqa: E402

COLUMNS = [
    ("run", "run"),
    ("model", "model"),
    ("commit", "commit"),
    ("tasks", "tasks"),
    ("done", "completed"),
    ("reward", "mean_total_reward"),
    ("quality", "mean_quality_score"),
    ("effic.", "mean_efficiency_score"),
    ("calls", "mean_tool_calls"),
    ("err%", "error_call_rate"),
    ("tokens", "total_tokens"),
    ("$", "total_cost_usd"),
]


def load_runs() -> list[tuple[Path, dict, list[dict]]]:
    """Load every run directory that has a summary."""
    runs = []
    for directory in sorted(RUNS_DIR.glob("*/")):
        summary_path = directory / "summary.json"
        if not summary_path.exists():
            continue
        tasks_path = directory / "tasks.jsonl"
        tasks = (
            [json.loads(line) for line in tasks_path.open(encoding="utf-8")]
            if tasks_path.exists()
            else []
        )
        runs.append((directory, json.loads(summary_path.read_text()), tasks))
    return runs


def print_runs_table() -> None:
    """Print one markdown row per recorded run."""
    print("| " + " | ".join(title for title, _ in COLUMNS) + " |")
    print("|" + "---|" * len(COLUMNS))
    for directory, summary, _ in load_runs():
        values = {**summary, "run": directory.name}
        if values.get("dirty"):
            values["commit"] = f"{values.get('commit')}*"
        print("| " + " | ".join(str(values.get(key, "")) for _, key in COLUMNS) + " |")


def print_scenarios_table() -> None:
    """Print total_reward per scenario fingerprint across runs."""
    runs = load_runs()
    scenarios: dict[str, dict[str, float]] = {}
    for directory, _, tasks in runs:
        for task in tasks:
            fingerprint = task.get("scenario_fp") or task["task_id"]
            scenarios.setdefault(fingerprint, {})[directory.name] = task.get("total_reward", 0.0)
    names = [directory.name for directory, _, _ in runs]
    print("| scenario | " + " | ".join(names) + " |")
    print("|" + "---|" * (len(names) + 1))
    for fingerprint, scores in sorted(scenarios.items()):
        cells = [str(scores.get(name, "")) for name in names]
        print(f"| {fingerprint} | " + " | ".join(cells) + " |")


def import_log(log_path: Path, experiment: str, model: str) -> None:
    """Create a run directory from a pre-tracking log that ends with the result JSON."""
    text = log_path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r'^\{\n  "failed_tasks".*?^\}$', text, flags=re.MULTILINE | re.DOTALL)
    if match is None:
        raise SystemExit(f"No final result JSON found in {log_path}")
    result = json.loads(match.group(0))
    recorder = RunRecorder(
        experiment,
        {
            "experiment": experiment,
            "model": model,
            "imported_from": str(log_path),
            "imported_at": datetime.now(UTC).isoformat(),
            "run_id": result["run_id"],
        },
    )
    errors = len(re.findall(r"returned status error", text))
    for task in result["task_results"]:
        recorder.record_task(task)
    summary = summarize_tasks(recorder.tasks, recorder.config)
    calls = sum(task.get("tool_calls", 0) for task in recorder.tasks)
    summary["error_call_rate"] = round(errors / calls, 4) if calls else 0.0
    (recorder.directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Imported {len(recorder.tasks)} tasks into {recorder.directory}")


def main() -> None:
    """Parse arguments and print the requested view."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenarios", action="store_true", help="Per-scenario reward table.")
    parser.add_argument("--import-log", type=Path, help="Import a pre-tracking run log.")
    parser.add_argument("--experiment", default="imported", help="Experiment id for --import-log.")
    parser.add_argument("--model", default="unknown", help="Model name for --import-log.")
    args = parser.parse_args()
    if args.import_log:
        import_log(args.import_log, args.experiment, args.model)
    elif args.scenarios:
        print_scenarios_table()
    else:
        print_runs_table()


if __name__ == "__main__":
    main()
