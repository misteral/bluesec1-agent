"""Experiment tracking: one directory per run with config, steps, tasks and summary."""

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RUNS_DIR = Path(__file__).resolve().parents[2] / "runs"
RUN_TASKS = 30  # tasks per competition run (organisers, 2026-10-06)
# Platform run score ≈ PLATFORM_SCALE × Σ quality·(0.5 + 0.5·efficiency) / 30 (failed = 0).
# Fitted on 8 runs on 2026-10-07 (exp-008…015): ratio spread 1.5 %; quality alone fails on the
# low-efficiency run (exp-015). The efficiency weight (≈0.2–0.5) is an estimate, not a spec.
PLATFORM_SCALE = 30.2


def estimated_platform_score(tasks: list[dict[str, Any]]) -> float:
    """Estimate the platform's run score from per-task quality and efficiency."""
    total = sum(
        float(t.get("quality_score") or 0.0) * (0.5 + 0.5 * float(t.get("efficiency_score") or 0.0))
        for t in tasks
        if t.get("completion_reason") == "terminated"
    )
    return round(PLATFORM_SCALE * total / RUN_TASKS, 3)


def sha256_text(text: str) -> str:
    """Return a short stable hash of a text value."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def scenario_fingerprint(observation: dict[str, Any]) -> str:
    """Hash the alert content so the same scenario is recognisable across runs.

    Task ids change on every lease, so comparisons between runs key on this value.
    The tool catalog is excluded because it does not identify the scenario.
    """
    alert = {key: value for key, value in observation.items() if key != "available_tools"}
    return sha256_text(json.dumps(alert, sort_keys=True, ensure_ascii=False, default=str))


def git_state() -> dict[str, Any]:
    """Return the current commit and whether the working tree has local changes."""

    def _git(*args: str) -> str:
        try:
            return subprocess.run(
                ["git", *args],
                capture_output=True,
                text=True,
                check=True,
                cwd=RUNS_DIR.parent,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return ""

    return {"commit": _git("rev-parse", "--short", "HEAD"), "dirty": bool(_git("status", "-s"))}


class RunRecorder:
    """Append-only JSONL recorder for one agent run.

    Files inside the run directory:
        config.json: settings, git state and prompt hash, written before the run starts.
        observations.jsonl: the initial observation of every task.
        steps.jsonl: every LLM step with tool arguments, status, error text and usage.
        tasks.jsonl: the authoritative server result of every task plus agent-side stats.
        summary.json: aggregate metrics, rewritten after every task.
    """

    def __init__(self, label: str, config: dict[str, Any], root: Path = RUNS_DIR) -> None:
        """Create the run directory and write its configuration.

        Args:
            label: Short experiment label used in the directory name.
            config: Run configuration to persist; git state and timestamp are added.
            root: Parent directory for run directories.
        """
        started_at = datetime.now(UTC)
        self.directory = root / f"{started_at:%Y%m%d-%H%M%S}-{label}"
        self.directory.mkdir(parents=True, exist_ok=False)
        self.config = {**config, **git_state(), "started_at": started_at.isoformat()}
        self.tasks: list[dict[str, Any]] = []
        self._write_json("config.json", self.config)

    def set_run_id(self, run_id: str) -> None:
        """Store the server run id once the remote run exists."""
        self.config["run_id"] = run_id
        self._write_json("config.json", self.config)

    def record_observation(self, task_id: str, observation: dict[str, Any]) -> None:
        """Persist the initial observation of one task."""
        self._append(
            "observations.jsonl",
            {
                "task_id": task_id,
                "scenario_fp": scenario_fingerprint(observation),
                "observation": observation,
            },
        )

    def record_step(self, record: dict[str, Any]) -> None:
        """Persist one investigation step."""
        self._append("steps.jsonl", record)

    def record_task(self, record: dict[str, Any]) -> None:
        """Persist one task result and refresh the run summary."""
        self.tasks.append(record)
        self._append("tasks.jsonl", record)
        self._write_json("summary.json", summarize_tasks(self.tasks, self.config))

    def _append(self, name: str, record: dict[str, Any]) -> None:
        with (self.directory / name).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    def _write_json(self, name: str, value: dict[str, Any]) -> None:
        (self.directory / name).write_text(
            json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n",
            encoding="utf-8",
        )


def summarize_tasks(tasks: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    """Aggregate per-task records into run-level metrics.

    Args:
        tasks: Records written by `RunRecorder.record_task`.
        config: Run configuration.

    Returns:
        Summary with means of server scores and totals of agent-side counters.
    """
    count = len(tasks)

    def _sum(key: str) -> float:
        return round(sum(float(task.get(key) or 0.0) for task in tasks), 4)

    def _mean(key: str) -> float:
        return round(_sum(key) / count, 4) if count else 0.0

    tool_calls = _sum("tool_calls")
    error_calls = _sum("error_calls")
    completed_quality = sum(
        float(task.get("quality_score") or 0.0)
        for task in tasks
        if task.get("completion_reason") == "terminated"
    )
    return {
        # Primary metric: the platform score tracks Σ quality / 30 with failed tasks as 0
        # (ratio ≈ 0.29 across 5 runs on 2026-10-07), not the per-task total_reward.
        "q30": round(completed_quality / RUN_TASKS, 4),
        "score_est": estimated_platform_score(tasks),
        "run_id": config.get("run_id"),
        "model": config.get("model"),
        "commit": config.get("commit"),
        "dirty": config.get("dirty"),
        "tasks": count,
        "completed": sum(task.get("completion_reason") == "terminated" for task in tasks),
        "mean_total_reward": _mean("total_reward"),
        "mean_quality_score": _mean("quality_score"),
        "mean_efficiency_score": _mean("efficiency_score"),
        "mean_tool_calls": _mean("tool_calls"),
        "error_call_rate": round(error_calls / tool_calls, 4) if tool_calls else 0.0,
        "total_tokens": int(_sum("total_tokens")),
        "total_cost_usd": _sum("cost_usd"),
        "wall_time_seconds": _sum("wall_time_seconds"),
    }
