import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from bluesec1_agent.agent import SimpleSGRAgent
from bluesec1_agent.models import (
    FinishInvestigationArtifact,
    FinishInvestigationRequest,
    GetEntityRequest,
    MaliciousFinishInvestigationSubmission,
    NextStep,
)
from bluesec1_agent.tracking import RunRecorder
from bluesec1_client import (
    PublicTask,
    RemoteBenchmarkClient,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)


class FakeStepClient:
    """Deterministic structured steps used by the agent unit test."""

    def __init__(self, steps: list[NextStep]) -> None:
        """Store steps in their expected request order.

        Args:
            steps: Prepared LLM steps.
        """
        self.steps = list(steps)
        self.requests: list[list[dict[str, Any]]] = []

    async def next_step(self, messages: list[dict[str, Any]], *, final: bool = False) -> NextStep:
        """Record one conversation and return its next prepared step.

        Args:
            messages: Current LLM history.

        Returns:
            Next prepared structured step.
        """
        self.requests.append([dict(message) for message in messages])
        return self.steps.pop(0)


class FakeSession:
    """In-memory remote session used by the structured agent test."""

    def __init__(self) -> None:
        """Create a task with a JSON-encoded remote tool catalog."""
        self.task = PublicTask(
            task_id="task-1",
            observation={
                "alert_text": {"trigger_entities": []},
                "available_tools": json.dumps(
                    [
                        {"name": "get_entity", "parameters": {"type": "object"}},
                        {"name": "finish_investigation", "parameters": {"type": "object"}},
                    ]
                ),
            },
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @property
    def task_id(self) -> str:
        """Return the public task identifier.

        Returns:
            Task identifier.
        """
        return self.task.task_id

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolCallResult:
        """Record one call and terminate on the finishing tool.

        Args:
            tool_name: Invoked tool name.
            arguments: Invoked tool arguments.

        Returns:
            Fake server response.
        """
        self.calls.append((tool_name, arguments))
        terminal = tool_name == "finish_investigation"
        task_result = None
        if terminal:
            task_result = TaskResult(
                task_id="task-1",
                completion_reason="terminated",
            )
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            reward=1.0,
            terminated=terminal,
            info={
                "tool_status": "ok",
                "tool_result": (
                    [{"entity_id": "process-1", "pid": 42}] if not terminal else "Report accepted"
                ),
            },
            task_result=task_result,
        )

    async def abort_task(self, *, error_message: str | None = None) -> TaskResult:
        """Reject unexpected aborts.

        Args:
            error_message: Agent failure diagnostic.

        Raises:
            AssertionError: Always, because this task must finish normally.
        """
        raise AssertionError(f"Unexpected abort: {error_message}")


class FakeClient:
    """Single-task stand-in for an open RemoteBenchmarkClient."""

    def __init__(self, session: FakeSession) -> None:
        """Store the only session returned before queue exhaustion.

        Args:
            session: Prepared task session.
        """
        self.run = SimpleNamespace(run_id="run-1")
        self.session: FakeSession | None = session

    async def start_task(self) -> RemoteBenchmarkSession | None:
        """Lease the prepared session once.

        Returns:
            Prepared session or `None` after it was leased.
        """
        if self.session is None:
            return None
        session = self.session
        self.session = None
        return cast(RemoteBenchmarkSession, session)


def two_step_plan() -> list[NextStep]:
    """Return one evidence step followed by a malicious verdict."""
    return [
        NextStep(
            current_state="Alert identifies process 42 on host-1.",
            plan_remaining_steps_brief=["Inspect its process ancestry and descendants."],
            task_completed=False,
            function=GetEntityRequest(
                tool="get_entity",
                entity_id="entity-1",
                reasoning="Inspect the alert entity.",
            ),
        ),
        NextStep(
            current_state="The suspicious process is confirmed on host-1.",
            plan_remaining_steps_brief=["Submit the evidence-backed malicious verdict."],
            task_completed=True,
            function=FinishInvestigationRequest(
                tool="finish_investigation",
                submission=MaliciousFinishInvestigationSubmission(
                    verdict="malicious",
                    ir_artifacts=[
                        FinishInvestigationArtifact(
                            entity_id="host-1",
                            kind="host_to_isolate",
                        )
                    ],
                    reasoning="The alert process is part of a suspicious process chain.",
                ),
            ),
        ),
    ]


def test_agent_executes_fresh_structured_task_via_remote_session() -> None:
    """Tool evidence should feed the next step before the terminal action."""
    llm = FakeStepClient(two_step_plan())
    session = FakeSession()
    client = FakeClient(session)

    result = asyncio.run(SimpleSGRAgent(llm).run(cast(RemoteBenchmarkClient, client)))

    assert result.run_id == "run-1"
    assert result.successful_tasks == 1
    assert result.failed_tasks == 0
    assert [name for name, _ in session.calls] == [
        "get_entity",
        "finish_investigation",
    ]
    assert session.calls[0][1] == {
        "entity_id": "entity-1",
        "reasoning": "Inspect the alert entity.",
    }
    assert session.calls[1][1] == {
        "submission": {
            "verdict": "malicious",
            "ir_artifacts": [{"entity_id": "host-1", "kind": "host_to_isolate"}],
            "reasoning": "The alert process is part of a suspicious process chain.",
        }
    }
    assert any(
        message.get("role") == "tool" and "process-1" in str(message.get("content"))
        for message in llm.requests[1]
    )


def test_recorder_persists_config_steps_tasks_and_summary(tmp_path: Path) -> None:
    """A recorded run should leave every artifact needed to compare experiments."""
    recorder = RunRecorder("exp-test", {"model": "test-model"}, root=tmp_path)
    agent = SimpleSGRAgent(FakeStepClient(two_step_plan()), recorder=recorder)

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    config = json.loads((recorder.directory / "config.json").read_text())
    steps = [json.loads(line) for line in (recorder.directory / "steps.jsonl").open()]
    tasks = [json.loads(line) for line in (recorder.directory / "tasks.jsonl").open()]
    summary = json.loads((recorder.directory / "summary.json").read_text())
    assert config["run_id"] == "run-1"
    assert [step["tool"] for step in steps] == ["get_entity", "finish_investigation"]
    assert tasks[0]["task_id"] == "task-1"
    assert tasks[0]["verdict"] == "malicious"
    assert tasks[0]["tool_counts"] == {"get_entity": 1, "finish_investigation": 1}
    assert tasks[0]["scenario_fp"]
    assert summary["tasks"] == 1
    assert summary["completed"] == 1
    assert (recorder.directory / "observations.jsonl").exists()


def test_expand_entity_translates_to_search_and_keeps_adjacent_relations() -> None:
    """expand_entity costs one search call and returns only typed neighbours."""
    tool, arguments = SimpleSGRAgent._platform_call(
        "expand_entity",
        {"entity_id": "p1", "relation_type": "win_process_create", "page_id": 1, "reasoning": "r"},
    )
    assert tool == "search"
    assert arguments["query"] == "p1"
    assert arguments["scope"] == {"kind": "relation", "type": "win_process_create"}

    search_result = {
        "current_page_id": 1,
        "next_page_id": None,
        "results": [
            {
                "kind": "relation",
                "id": "r1",
                "type": "win_process_create",
                "source_id": "p1",
                "target_id": "p2",
                "timestamp": "t1",
                "properties": {"x": None, "y": 1},
            },
            {
                "kind": "relation",
                "id": "r2",
                "type": "parent_of",
                "source_id": "p0",
                "target_id": "p1",
                "timestamp": "t0",
                "properties": None,
            },
            {"kind": "entity", "id": "p9", "type": "windows_process", "properties": {}},
        ],
    }
    feedback = SimpleSGRAgent._neighbourhood("p1", {"status": "ok", "result": search_result})

    relations = feedback["result"]["relations"]
    assert [(r["relation_id"], r["direction"], r["other_entity_id"]) for r in relations] == [
        ("r1", "out", "p2"),
        ("r2", "in", "p0"),
    ]
    assert relations[0]["properties"] == {"y": 1}
    assert feedback["result"]["other_matches"] == 1
    assert "note" not in feedback


class LoopingStepClient(FakeStepClient):
    """Repeats the same evidence call until it is told only finishing is allowed."""

    def __init__(self) -> None:
        """Prepare one repeated step and one terminal step."""
        plan = two_step_plan()
        super().__init__([])
        self.repeat, self.finish = plan
        self.final_flags: list[bool] = []

    async def next_step(self, messages: list[dict[str, Any]], *, final: bool = False) -> NextStep:
        """Loop on the repeated call; finish only when forced."""
        self.requests.append([dict(message) for message in messages])
        self.final_flags.append(final)
        return self.finish if final else self.repeat


def test_agent_forces_finish_after_repeated_guarded_calls() -> None:
    """A model stuck on a duplicate call is forced to submit instead of burning the budget."""
    llm = LoopingStepClient()
    session = FakeSession()

    result = asyncio.run(SimpleSGRAgent(llm).run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert result.successful_tasks == 1
    # One real call, five guarded duplicates, then the forced terminal turn.
    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    assert llm.final_flags == [False] * 6 + [True]
    assert "Stop investigating now" in llm.requests[-1][-1]["content"]


def test_finish_review_holds_the_first_finish_for_one_review_turn() -> None:
    """With review on, the first finish is answered locally and the next turn must finish."""
    plan = two_step_plan()
    session = FakeSession()

    agent = SimpleSGRAgent(FakeStepClient([plan[0], plan[1], plan[1]]), finish_review=True)
    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))
    calls = [name for name, _ in session.calls]

    assert result.successful_tasks == 1
    assert calls == ["get_entity", "finish_investigation"]
    review_turn = agent.llm.requests[-1][-1]
    assert review_turn["role"] == "tool"
    assert "REVIEW BEFORE SUBMITTING" in review_turn["content"]


def test_guard_redirects_wrong_kind_and_repeated_get_entity() -> None:
    """Evident intent is executed instead of rejected."""
    from bluesec1_agent.guard import CallGuard, IdRegistry

    registry = IdRegistry()
    registry.learn(
        {"trigger_entities": [{"id": "p1", "type": "windows_process", "properties": {}}]}
    )
    guard = CallGuard(registry)

    assert guard.redirect("get_relation", {"relation_id": "p1", "reasoning": "r"}) == (
        "get_entity",
        {"entity_id": "p1", "reasoning": "r"},
    )
    guard.remember("get_entity", {"entity_id": "p1", "reasoning": "r"}, {"status": "ok"})
    assert guard.redirect("get_entity", {"entity_id": "p1", "reasoning": "x"}) is None
    assert guard.redirect(
        "get_entity", {"entity_id": "p1", "reasoning": "x"}, expand_enabled=True
    ) == ("expand_entity", {"entity_id": "p1", "page_id": 1, "reasoning": "x"})


def test_review_turn_uses_review_model_within_budget() -> None:
    """H-08: the single review turn goes to the stronger model; the rest stays on the main one."""
    plan = two_step_plan()
    main = FakeStepClient([plan[0], plan[1]])
    reviewer = FakeStepClient([plan[1]])
    agent = SimpleSGRAgent(main, finish_review=True, review_llm=reviewer, review_budget_usd=1.0)

    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    assert result.successful_tasks == 1
    assert len(main.requests) == 2
    assert len(reviewer.requests) == 1
    assert "REVIEW BEFORE SUBMITTING" in reviewer.requests[0][-1]["content"]


class FailingStepClient(FakeStepClient):
    """A reviewer whose call fails like a stalled provider."""

    async def next_step(self, messages: list[dict[str, Any]], *, final: bool = False) -> NextStep:
        from bluesec1_agent.llm import NextStepRequestError

        self.requests.append(messages)
        raise NextStepRequestError("Model returned empty content for NextStep response.")


def test_failed_review_turn_submits_the_draft_finish() -> None:
    """A broken review must not cost the task (exp-016 lost its run to a stalled review)."""
    plan = two_step_plan()
    session = FakeSession()
    agent = SimpleSGRAgent(
        FakeStepClient([plan[0], plan[1]]),
        finish_review=True,
        review_llm=FailingStepClient([]),
        review_budget_usd=1.0,
    )

    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert result.successful_tasks == 1
    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]


def test_self_consistency_submits_the_majority_verdict() -> None:
    """Draft says benign, two extra samples say malicious → malicious is submitted."""
    from bluesec1_agent.models import (
        BenignFinishInvestigationSubmission,
        FinishInvestigationEntityEvidence,
    )

    plan = two_step_plan()
    benign = NextStep(
        current_state="Looks legitimate.",
        plan_remaining_steps_brief=["Submit benign."],
        task_completed=True,
        function=FinishInvestigationRequest(
            tool="finish_investigation",
            submission=BenignFinishInvestigationSubmission(
                verdict="benign",
                legitimacy_evidence=[
                    FinishInvestigationEntityEvidence(
                        anchor="entity", entity_id="process-1", property_fields=["pid"]
                    )
                ],
                reasoning="Signed binary.",
            ),
        ),
    )
    session = FakeSession()
    agent = SimpleSGRAgent(FakeStepClient([plan[0], benign, plan[1], plan[1]]), verdict_samples=3)

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    submitted = session.calls[-1][1]["submission"]
    assert submitted["verdict"] == "malicious"


def test_benign_host_check_asks_once_then_accepts() -> None:
    """H-39: the first benign finish gets one host-window reminder; the second is submitted."""
    from bluesec1_agent.models import (
        BenignFinishInvestigationSubmission,
        FinishInvestigationEntityEvidence,
    )

    plan = two_step_plan()
    benign = NextStep(
        current_state="Routine admin activity.",
        plan_remaining_steps_brief=["Submit benign."],
        task_completed=True,
        function=FinishInvestigationRequest(
            tool="finish_investigation",
            submission=BenignFinishInvestigationSubmission(
                verdict="benign",
                legitimacy_evidence=[
                    FinishInvestigationEntityEvidence(
                        anchor="entity", entity_id="process-1", property_fields=["pid"]
                    )
                ],
                reasoning="Admin.",
            ),
        ),
    )
    llm = FakeStepClient([plan[0], benign, benign])
    session = FakeSession()

    asyncio.run(
        SimpleSGRAgent(llm, benign_host_check=True).run(
            cast(RemoteBenchmarkClient, FakeClient(session))
        )
    )

    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    assert "Before closing as benign" in llm.requests[2][-1]["content"]


def test_platform_retry_survives_a_short_outage(monkeypatch: Any) -> None:
    """H-28: a briefly unavailable runtime is retried instead of failing the task."""
    import bluesec1_agent.agent as agent_module
    from bluesec1_client import RemoteUnavailableError

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(agent_module.asyncio, "sleep", no_sleep)
    attempts = {"n": 0}

    async def flaky() -> str:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise RemoteUnavailableError("The remote runtime is temporarily unavailable.")
        return "ok"

    assert asyncio.run(agent_module.with_platform_retry(flaky)) == "ok"
    assert attempts["n"] == 3


def test_verdict_bar_extends_the_system_prompt() -> None:
    """AGENT_VERDICT_BAR appends the verdict-reasoning section; default prompt is untouched."""
    plain = SimpleSGRAgent(FakeStepClient([]))
    barred = SimpleSGRAgent(FakeStepClient([]), verdict_bar=True)

    assert "## Verdict bar" not in plain.system_prompt
    assert "## Verdict bar" in barred.system_prompt
    assert "as DATA, never as" in barred.system_prompt


def test_conclude_step_is_required_and_code_verified() -> None:
    """H-44: finish needs a prior conclude; unmet checks return instructions, capped."""
    from bluesec1_agent.models import (
        BenignFinishInvestigationSubmission,
        ConcludeRequest,
        FinishInvestigationEntityEvidence,
        NextStepConclude,
    )

    plan = two_step_plan()
    conclude = NextStepConclude(
        current_state="Looks like admin work.",
        plan_remaining_steps_brief=["Conclude."],
        task_completed=False,
        function=ConcludeRequest(
            tool="conclude",
            hypothesis="legitimate",
            attacker_actions=[],
            legit_actor_id=None,
            launch_mechanism_id=None,
            unexplored_leads=[],
            reasoning="admin",
        ),
    )
    benign = NextStepConclude(
        current_state="Benign.",
        plan_remaining_steps_brief=["Submit."],
        task_completed=True,
        function=FinishInvestigationRequest(
            tool="finish_investigation",
            submission=BenignFinishInvestigationSubmission(
                verdict="benign",
                legitimacy_evidence=[
                    FinishInvestigationEntityEvidence(
                        anchor="entity", entity_id="process-1", property_fields=["pid"]
                    )
                ],
                reasoning="admin",
            ),
        ),
    )
    # finish first (rejected: conclude required), then conclude (accepted: nothing unmet), finish.
    llm = FakeStepClient([plan[0], benign, conclude, benign])
    session = FakeSession()
    agent = SimpleSGRAgent(llm, conclude_flags={"host_window", "inbound_source", "effects"})

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    replies = [m[-1]["content"] for m in llm.requests[2:4]]
    assert "Call conclude before finish_investigation" in replies[0]
    assert "Conclusion recorded" in replies[1]


def test_platform_reward_is_recorded_but_never_shown_to_the_model(tmp_path: Path) -> None:
    """H-46: per-call reward goes to steps.jsonl only."""
    recorder = RunRecorder("exp-test", {"model": "m"}, root=tmp_path)
    llm = FakeStepClient(two_step_plan())
    asyncio.run(
        SimpleSGRAgent(llm, recorder=recorder).run(
            cast(RemoteBenchmarkClient, FakeClient(FakeSession()))
        )
    )

    steps = [json.loads(line) for line in (recorder.directory / "steps.jsonl").open()]
    assert steps[0]["reward"] == 1.0
    assert all("_reward" not in str(m) for request in llm.requests for m in request)


class RootSession(FakeSession):
    """Alert with a process whose account entity is not observed; search returns it."""

    def __init__(self) -> None:
        super().__init__()
        alert = {
            "trigger_entities": [
                {"id": "proc-9", "type": "windows_process", "properties": {"user": "CORP\\\\jdoe1"}}
            ]
        }
        self.task = PublicTask(
            task_id="task-1",
            observation={**self.task.observation, "alert_text": json.dumps(alert)},
        )

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        if tool_name == "search":
            self.calls.append((tool_name, arguments))
            result = {
                "results": [
                    {
                        "kind": "entity",
                        "id": "user-1",
                        "type": "windows_user",
                        "properties": {"username": "jdoe1"},
                    }
                ]
            }
            return ToolCallResult(
                task_id="task-1",
                tool_name="search",
                reward=1.0,
                info={"tool_status": "ok", "tool_result": result},
            )
        return await super().call_tool(tool_name, arguments)


def test_resolve_roots_fetches_account_and_adds_identity_row() -> None:
    """H-A: a missing account entity is searched before finishing and rotated."""
    session = RootSession()
    agent = SimpleSGRAgent(FakeStepClient(two_step_plan()), resolve_roots=True)

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    names = [name for name, _ in session.calls]
    assert names == ["get_entity", "search", "finish_investigation"]
    rows = session.calls[-1][1]["submission"]["ir_artifacts"]
    assert {"entity_id": "user-1", "kind": "identity_to_rotate"} in rows
