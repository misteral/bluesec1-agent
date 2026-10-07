import asyncio
import json
from types import SimpleNamespace
from typing import Any, cast

from bluesec1_agent.jev_agent import JevNavigatorAgent
from bluesec1_agent.jev_client import JevClient
from bluesec1_client import PublicTask, RemoteBenchmarkClient, TaskResult, ToolCallResult

ALERT = {
    "alert_description": "Process powershell.exe started on host H1",
    "trigger_entities": [
        {"id": "h1", "type": "host", "properties": {"hostname": "H1"}},
        {"id": "p1", "type": "windows_process", "properties": {"image_path": "powershell.exe"}},
    ],
    "trigger_relations": [{"id": "r1", "type": "hosts", "source_id": "h1", "target_id": "p1"}],
}
CHILD = {
    "kind": "entity",
    "id": "p2",
    "type": "windows_process",
    "properties": {"image_path": "C:\\Temp\\x.exe", "cmdline": "x.exe", "signed": None},
}
CHILD_EDGE = {
    "kind": "relation",
    "id": "r2",
    "type": "win_process_create",
    "source_id": "p1",
    "target_id": "p2",
    "timestamp": "t",
    "properties": None,
}


class FakeJev:
    """Expands the alerted process once, then finishes; answers final questions."""

    def __init__(self, p_attack: float) -> None:
        self.p_attack = p_attack
        self.cost_usd = 0.0
        self.questions: list[dict[str, Any]] = []

    async def decide(self, state: dict[str, Any], questions: dict[str, Any]) -> dict[str, Any]:
        self.questions.append(questions)
        if "next" in questions:
            options = questions["next"]["criteria"]
            pick = next(
                (
                    k
                    for k, label in options.items()
                    if "expand relations of windows_process powershell" in label
                ),
                "finish",
            )
            if len(self.questions) > 1:
                pick = "finish"
            return {"next": {"type": "choice", "choice": pick, "confidence": 0.9}}
        if "attack" in questions:
            return {"attack": {"type": "noul", "noul": self.p_attack}}
        answers = {}
        for key, question in questions.items():
            first = next(iter(question["criteria"]))
            answers[key] = {
                "type": "choice",
                "choice": "attacker" if key.startswith("r") else first,
            }
        return answers


class FakeSession:
    """Platform stand-in: one search result, then finish."""

    def __init__(self) -> None:
        self.task = PublicTask(
            task_id="t1",
            observation={
                "alert_text": json.dumps(ALERT),
                "available_tools": json.dumps(
                    [{"name": "search"}, {"name": "finish_investigation"}]
                ),
                "last_tool_result": "",
            },
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @property
    def task_id(self) -> str:
        return "t1"

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        self.calls.append((tool_name, arguments))
        if tool_name == "finish_investigation":
            return ToolCallResult(
                task_id="t1",
                tool_name=tool_name,
                terminated=True,
                info={"tool_status": "ok"},
                task_result=TaskResult(task_id="t1", completion_reason="terminated"),
            )
        result = {"current_page_id": 1, "next_page_id": None, "results": [CHILD_EDGE, CHILD]}
        return ToolCallResult(
            task_id="t1",
            tool_name=tool_name,
            observation={"last_tool_result": json.dumps(result)},
            info={"tool_status": "ok"},
        )

    async def abort_task(self, *, error_message: str | None = None) -> TaskResult:
        raise AssertionError(error_message)


class FakeClient:
    def __init__(self, session: FakeSession) -> None:
        self.run = SimpleNamespace(run_id="run-1")
        self.session: FakeSession | None = session

    async def start_task(self) -> Any:
        session, self.session = self.session, None
        return session


def run_jev_only(p_attack: float) -> tuple[FakeSession, FakeJev]:
    session, jev = FakeSession(), FakeJev(p_attack)
    agent = JevNavigatorAgent(cast(JevClient, jev), final_mode="jev_only")
    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))
    assert result.successful_tasks == 1
    return session, jev


def test_jev_navigation_expands_with_code_built_arguments_then_finishes() -> None:
    """Jev picks among labelled candidates; the platform call is built by code."""
    session, jev = run_jev_only(0.9)

    assert session.calls[0] == (
        "search",
        {"query": "p1", "page_id": 1, "reasoning": "Jev-selected expansion"},
    )
    assert session.calls[-1][0] == "finish_investigation"
    assert "finish" in jev.questions[0]["next"]["criteria"]


def test_jev_only_malicious_reports_attacker_entities_with_fitting_kinds() -> None:
    """Above the threshold, attacker entities become artifacts; process → process_observed."""
    session, _ = run_jev_only(0.9)
    submission = session.calls[-1][1]["submission"]

    assert submission["verdict"] == "malicious"
    kinds = {a["entity_id"]: a["kind"] for a in submission["ir_artifacts"]}
    assert kinds["p1"] == "process_observed"
    assert kinds["p2"] == "process_observed"
    assert "h1" in kinds


def test_jev_only_benign_cites_set_fields_only() -> None:
    """Below the threshold, benign evidence cites only properties that are actually set."""
    session, _ = run_jev_only(0.1)
    submission = session.calls[-1][1]["submission"]

    assert submission["verdict"] == "benign"
    for evidence in submission["legitimacy_evidence"]:
        assert "signed" not in evidence["property_fields"]
