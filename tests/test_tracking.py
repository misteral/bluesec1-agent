from bluesec1_agent.tracking import estimated_platform_score, task_score


def test_task_score_matches_platform_page() -> None:
    # Values as shown on the platform's per-task run page.
    assert round(task_score({"quality_score": 0.5, "efficiency_score": 0.4615}), 4) == 0.3923
    assert round(task_score({"quality_score": 0.5, "efficiency_score": 0.9}), 4) == 0.48


def test_run_score_sums_terminated_tasks_only() -> None:
    tasks = [
        {"completion_reason": "terminated", "quality_score": 0.6, "efficiency_score": 1.0},
        {"completion_reason": "terminated", "quality_score": 0.5, "efficiency_score": 0.5},
        {"completion_reason": "aborted", "quality_score": 0.9, "efficiency_score": 1.0},
    ]
    assert estimated_platform_score(tasks) == 0.6 + 0.4
