import json
from typing import Any

from loguru import logger
from pydantic import BaseModel, ConfigDict, Field

from bluesec1_agent.guard import CallGuard, IdRegistry, parse_jsonish
from bluesec1_agent.llm import StructuredStepClient, render_json
from bluesec1_agent.models import NextStep
from bluesec1_agent.review import EntityBook, gate_issues, review_message, sanitize_submission
from bluesec1_agent.tracking import RunRecorder, scenario_fingerprint
from bluesec1_client import (
    RemoteBenchmarkClient,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)

STRATEGY_SYSTEM_PROMPT = """
You are a senior SOC analyst investigating one security alert in an evidence graph.

Return exactly one JSON object matching the supplied NextStep schema on every turn.
Do not emit prose, markdown, XML tags, or extra keys outside that object.
The first user message holds the alert and `available_tools`, the authoritative tool catalog.

## Scoring you are optimising
1. Correct verdict (malicious / benign) — by far the largest part of the score.
2. Completeness of the response: every attacker-related entity reported with the right kind.
3. Few tool calls: every platform call costs score. Think more, call less.

## Judge behaviour, not the binary
Alerts are often raised on legitimate, signed system binaries (explorer.exe, powershell.exe,
wsmprovhost.exe, cmd.exe, rundll32.exe, wmiprvse.exe, net.exe, ...). Attackers live off the land:
a Microsoft signature, a normal parent or a service account proves NOTHING by itself.
Decide only after you have seen what the alerted activity actually did and who caused it.

## How to investigate
- Start from the alert's trigger entities and relations; they are already in the first message.
- Expand around the alerted process/user/host:
  - upward: parent chain, the user and logon session, remote source (WinRM/WMI/RDP/SMB/PsExec);
  - downward: child processes and their command lines, scripts, cmdlets;
  - effects: files written/executed, registry/service/scheduled-task/WMI persistence, network
    connections, credential access (lsass access, ticket requests), account/AD changes,
    shadow-copy deletion, encryption-like file writes, archive/exfiltration.
- `get_entity` returns only bare relation ids. To learn neighbours with their types in ONE call,
  prefer `search` with the entity id as `query`, optionally narrowed by `scope`
  ({"kind": "relation", "type": ...}) and a `time_window` around the alert. Use `get_relation`
  for a specific relation id you need, `get_entity` for an entity id. Entity ids go to
  `get_entity`, relation ids to `get_relation` — never mix them.
- Never repeat a call. A call answered with `local_guard` was not sent; change your approach.
- Hosts and users can have hundreds of relations: do not walk them one by one — search with a
  relation-type scope and a tight time window instead.

## Red flags (any one warrants deeper checks; several together → malicious)
Encoded/obfuscated command lines, download cradles, LOLBins proxying execution, Office/browser/
explorer spawning shells, execution from user-writable or temp paths, unsigned or renamed binaries,
new services/tasks/run keys/WMI subscriptions, lsass access or credential-dumping tools,
`vssadmin`/`wbadmin`/`bcdedit` recovery tampering, mass file renames/writes, remote execution from
another host followed by discovery or credential access, admin accounts used at odd hosts/times,
connections to rare external IPs, defence evasion (log clearing, AV tampering).

## Verdict
- malicious: an attack chain or clear attacker action is evidenced.
- benign: ONLY when you have checked what the activity did (children, effects, origin) and all of
  it is explained by legitimate administration or business behaviour.

## Submitting
- malicious → `ir_artifacts`: report every entity of the attack chain you saw, each with a kind.
  RESPOND kinds (actions): host_to_isolate (compromised hosts), identity_to_rotate (compromised or
  attacker-created accounts), persistence_to_remove (services, tasks, run keys, WMI objects),
  file_to_delete (malicious files/tools/scripts on disk), network_block (attacker infrastructure
  entities), mailbox_action (malicious email), cleanup_to_verify (attacker changes to verify),
  other.
  FORENSIC kinds (observed attacker artifacts): process_observed (attacker processes),
  file_observed, registry_observed, mount_observed, lnk_observed, ticket_observed,
  identity_observed, artifact_observed. Network connections are not artifacts.
  Include the alerted host and accounts when they are part of the chain. Use only entity ids you
  actually saw in the alert or in tool results.
- benign → `legitimacy_evidence`: cite the entities/relations that prove legitimacy with the exact
  property field names you saw (e.g. signer, cmdline, parent_image, user).
- Keep current_state as a compact running summary of evidence and suspicions; set
  task_completed=true exactly when calling finish_investigation.
- Typical investigations need 8–25 calls; finish as soon as the chain is understood.
""".strip()


# Organisers' reference prompt, kept for A/B runs (AGENT_PROMPT=reference).
REFERENCE_SYSTEM_PROMPT = """
You are a pragmatic senior SOC analyst investigating one security alert.

Return exactly one JSON object matching the supplied NextStep schema on every turn.
Do not emit prose, markdown, XML tags, or extra keys outside that object.

The task observation contains `available_tools`, the authoritative catalog of
enabled tool calls and their argument schemas. Follow that catalog exactly.

Investigation rules:
- Treat the alert as an initial hypothesis, not proof that the activity is malicious.
- Use only tools advertised in the current task observation.
- Execute exactly one tool per step and use its evidence before choosing the next step.
- Start from the entity ids named in the alert, then expand through their relations.
- Prefer following relations over searching again: an entity you already hold tells
  you where to go next.
- Search when you have a concrete string worth looking for and no edge leading to it.
- Do not repeat an identical unhelpful or failed call.
- Use only entity_id values actually returned by the alert or by a tool.
- Submit only response artifacts supported by evidence. Do not invent entity ids.
- Keep current_state evidence-focused and the remaining plan short.
- Set task_completed=true exactly when selecting finish_investigation.
- Finish before the investigation step budget is exhausted.
""".strip()

SYSTEM_PROMPTS = {"reference": REFERENCE_SYSTEM_PROMPT, "strategy": STRATEGY_SYSTEM_PROMPT}
SYSTEM_PROMPT = STRATEGY_SYSTEM_PROMPT

EXPAND_ENTITY_SPEC: dict[str, Any] = {
    "name": "expand_entity",
    "description": (
        "Agent-side helper (costs one platform `search` call): list relations touching an entity "
        "with their type, direction, the entity on the other end and the timestamp, 10 per page. "
        "Optionally restrict to one relation_type. Use it instead of fetching relation ids one by "
        "one with get_relation."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "entity_id": {"type": "string"},
            "relation_type": {"type": ["string", "null"], "description": "RelationType or null"},
            "page_id": {"type": "integer", "minimum": 1, "default": 1},
            "reasoning": {"type": "string"},
        },
        "required": ["entity_id", "reasoning"],
    },
}

EXPAND_PROMPT_ADDON = """
## Neighbourhood expansion
Use `expand_entity(entity_id, relation_type?)` to see an entity's relations with types and the
other ends in ONE call (10 per page; follow `next_page_id` only if needed). Prefer it over
`get_relation` on bare ids. For busy hosts/users pass a relation_type (e.g. win_process_create,
connected_to, logged_on_to, wrote_file, set_registry_value, created_service,
created_scheduled_task, accessed_process) to get only what matters.
""".strip()

MAX_CONSECUTIVE_TASK_FAILURES = 2
# A small model can loop on a guarded call forever (exp-004: 82 identical repeats). After this
# many locally answered calls in a row, the next turn may only finish the investigation.
MAX_CONSECUTIVE_GUARDED = 3
# The runtime closes a task after 100 tool calls; finish before that with what we know.
PLATFORM_CALL_BUDGET = 95
FORCE_FINISH_MESSAGE = (
    "Stop investigating now: {reason}. Submit finish_investigation with your best verdict "
    "and the artifacts or evidence already gathered. Use only ids you have seen."
)


class ConsecutiveTaskFailuresError(RuntimeError):
    """Raised to stop a run before a systemic agent failure drains the task queue."""


class AgentRunResult(BaseModel):
    """Aggregate results returned by one remote benchmark run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    successful_tasks: int
    failed_tasks: int
    task_results: list[TaskResult] = Field(default_factory=list)


class SimpleSGRAgent:
    """Run a typed one-action-per-turn LLM investigation loop."""

    def __init__(
        self,
        llm: StructuredStepClient,
        *,
        max_steps: int = 100,
        recorder: RunRecorder | None = None,
        system_prompt: str = SYSTEM_PROMPT,
        expand_entity: bool = False,
        finish_review: bool = False,
    ) -> None:
        """Store the LLM dependency and per-task step limit.

        Args:
            llm: Structured step generator used for every investigation turn.
            max_steps: Maximum total tool calls allowed for one task.
            recorder: Optional experiment recorder for steps and task results.
            system_prompt: System prompt used for every task.
            expand_entity: Advertise the agent-side `expand_entity` helper (H-13).
            finish_review: Gate and review finish_investigation once before sending (H-03/04).

        Raises:
            ValueError: If the configured limit is not positive.
        """
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.llm = llm
        self.max_steps = max_steps
        self.recorder = recorder
        self.expand_entity = expand_entity
        self.finish_review = finish_review
        self.system_prompt = (
            f"{system_prompt}\n\n{EXPAND_PROMPT_ADDON}" if expand_entity else system_prompt
        )
        self._task_stats: dict[str, Any] = {}

    async def run(self, client: RemoteBenchmarkClient) -> AgentRunResult:
        """Consume the remote queue and aggregate authoritative task results.

        Args:
            client: Open remote benchmark client that owns the current run.

        Returns:
            Aggregate result for the newly created remote run.

        Raises:
            RuntimeError: If the client is not open.
            ConsecutiveTaskFailuresError: If several tasks in a row fail in the agent.
        """
        remote_run = client.run
        if remote_run is None:
            raise RuntimeError("RemoteBenchmarkClient must be open before running the agent.")

        if self.recorder is not None:
            self.recorder.set_run_id(remote_run.run_id)
        task_results: list[TaskResult] = []
        consecutive_failures = 0
        while (session := await client.start_task()) is not None:
            logger.info("Starting structured investigation for task {}.", session.task_id)
            self._task_stats = self._new_task_stats(session.task.observation)
            try:
                task_result = await self._investigate(session)
            except Exception as exc:
                logger.error("Task {} failed in the agent: {}", session.task_id, exc)
                error_message = f"{type(exc).__name__}: {exc}"[:2_000]
                aborted_result = await session.abort_task(error_message=error_message)
                task_result = TaskResult.model_validate(aborted_result)
                self._task_stats["agent_error"] = error_message
                self._record_task(task_result)
                consecutive_failures += 1
                if consecutive_failures >= MAX_CONSECUTIVE_TASK_FAILURES:
                    raise ConsecutiveTaskFailuresError(
                        f"{consecutive_failures} consecutive tasks failed in the agent; "
                        "stopping to preserve the task queue."
                    ) from exc
            else:
                consecutive_failures = 0
                self._record_task(task_result)
            task_results.append(task_result)

        successful_tasks = sum(
            result.completion_reason in {"terminated", "truncated"} for result in task_results
        )
        return AgentRunResult(
            run_id=remote_run.run_id,
            successful_tasks=successful_tasks,
            failed_tasks=len(task_results) - successful_tasks,
            task_results=task_results,
        )

    async def _investigate(self, session: RemoteBenchmarkSession) -> TaskResult:
        """Drive one leased task until its terminal investigation tool succeeds.

        Args:
            session: Active remote task session.

        Returns:
            Authoritative terminal task result returned by the server.

        Raises:
            ValueError: If the task observation has an invalid tool catalog.
            RuntimeError: If the agent exhausts its step budget.
        """
        observation = session.task.observation
        tool_specs = self._tool_specs(observation)
        available_tools = {
            specification["name"]
            for specification in tool_specs
            if isinstance(specification.get("name"), str)
        }
        if "finish_investigation" not in available_tools:
            raise ValueError("The runtime did not advertise finish_investigation.")
        if self.expand_entity and "search" in available_tools:
            tool_specs = [*tool_specs, EXPAND_ENTITY_SPEC]
            available_tools = {*available_tools, "expand_entity"}
        if self.recorder is not None:
            self.recorder.record_observation(session.task_id, observation)
        alert = parse_jsonish(observation.get("alert_text"))
        registry = IdRegistry()
        registry.learn(alert)
        guard = CallGuard(registry)
        book = EntityBook()
        book.learn(alert)
        reviewed = False
        review_pending = False

        # The tool catalog is sent once here; tool feedback carries only per-call data.
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            {
                "role": "user",
                "content": render_json(
                    {
                        "instruction": "Investigate this alert and submit the correct response.",
                        "alert": alert,
                        "available_tools": tool_specs,
                    }
                ),
            },
        ]

        consecutive_guarded = 0
        platform_calls = 0
        for step_index in range(1, self.max_steps + 1):
            reason = None
            if consecutive_guarded >= MAX_CONSECUTIVE_GUARDED:
                reason = f"{consecutive_guarded} calls in a row were repeats or invalid"
            elif platform_calls >= PLATFORM_CALL_BUDGET:
                reason = f"tool-call budget reached ({platform_calls} calls)"
            elif step_index >= self.max_steps:
                reason = "step budget exhausted"
            if reason is not None:
                logger.warning("Forcing finish_investigation: {}.", reason)
                messages.append(
                    {"role": "user", "content": FORCE_FINISH_MESSAGE.format(reason=reason)}
                )
                self._task_stats["forced_finish"] = reason
            step = await self.llm.next_step(messages, final=reason is not None or review_pending)
            review_pending = False
            llm_stats = dict(getattr(self.llm, "last_step_stats", None) or {})
            tool_name = step.function.tool
            arguments = step.function.model_dump(
                mode="json",
                by_alias=True,
                exclude={"tool"},
                exclude_none=True,
            )
            tool_call_id = f"step_{step_index}"
            messages.append(
                {
                    "role": "assistant",
                    "content": render_json(
                        {
                            "current_state": step.current_state,
                            "plan": step.plan_remaining_steps_brief,
                        }
                    ),
                    "tool_calls": [
                        {
                            "type": "function",
                            "id": tool_call_id,
                            "function": {
                                "name": tool_name,
                                "arguments": render_json(arguments),
                            },
                        }
                    ],
                }
            )

            server_result: TaskResult | None = None
            if tool_name == "finish_investigation" and self.finish_review:
                submission = arguments.get("submission", {})
                seen_ids = set(registry.kinds) | set(book.entities)
                if not reviewed:
                    reviewed = True
                    review_pending = True
                    issues = gate_issues(submission, book, seen_ids)
                    self._task_stats["review_issues"] = issues
                    self._task_stats["draft_verdict"] = submission.get("verdict")
                    feedback = {
                        "status": "review",
                        "local_guard": "finish_review",
                        "message": review_message(submission, book, issues),
                    }
                    logger.info("Finish review requested ({} gate issues).", len(issues))
                    self._record_step(
                        session.task_id, step_index, step, arguments, feedback, llm_stats
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "content": render_json(feedback),
                            "tool_call_id": tool_call_id,
                        }
                    )
                    continue
                arguments["submission"] = sanitize_submission(submission, book, seen_ids)
            local_feedback = guard.check(tool_name, arguments)
            consecutive_guarded = consecutive_guarded + 1 if local_feedback is not None else 0
            if local_feedback is not None:
                feedback = local_feedback
                logger.info("Guard answered {} locally ({}).", tool_name, feedback["local_guard"])
            elif tool_name not in available_tools:
                feedback: dict[str, Any] = {
                    "status": "error",
                    "message": (
                        f"Tool {tool_name!r} is not advertised for this task. "
                        f"Available tools: {sorted(available_tools)}"
                    ),
                }
                logger.warning("Rejected unavailable tool {} locally.", tool_name)
            else:
                platform_calls += 1
                platform_tool, platform_arguments = self._platform_call(tool_name, arguments)
                response = await session.call_tool(platform_tool, platform_arguments)
                feedback = self._tool_feedback(response)
                if tool_name == "expand_entity":
                    feedback = self._neighbourhood(arguments["entity_id"], feedback)
                guard.remember(tool_name, arguments, feedback)
                book.learn(feedback.get("result"))
                book.learn(feedback.get("raw_result"))
                server_result = response.task_result
                logger.info(
                    "Tool {} returned status {}.{}",
                    tool_name,
                    feedback.get("status", "unknown"),
                    f" Error: {feedback['error']}" if feedback.get("error") else "",
                )
            self._record_step(session.task_id, step_index, step, arguments, feedback, llm_stats)
            if server_result is not None:
                return TaskResult.model_validate(server_result)

            messages.append(
                {
                    "role": "tool",
                    "content": render_json(
                        {key: value for key, value in feedback.items() if key != "raw_result"}
                    ),
                    "tool_call_id": tool_call_id,
                }
            )

        raise RuntimeError(
            f"Agent hit the {self.max_steps}-step limit without finish_investigation."
        )

    @staticmethod
    def _platform_call(tool_name: str, arguments: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Translate agent-side tools into the platform call they cost."""
        if tool_name != "expand_entity":
            return tool_name, arguments
        search: dict[str, Any] = {
            "query": arguments["entity_id"],
            "page_id": arguments.get("page_id", 1),
            "reasoning": arguments["reasoning"],
        }
        if arguments.get("relation_type"):
            search["scope"] = {"kind": "relation", "type": arguments["relation_type"]}
        return "search", search

    @staticmethod
    def _neighbourhood(entity_id: str, feedback: dict[str, Any]) -> dict[str, Any]:
        """Reduce a search result to the relations touching one entity."""
        result = feedback.get("result")
        if feedback.get("status") != "ok" or not isinstance(result, dict):
            return feedback
        neighbours = []
        for item in result.get("results") or []:
            if not isinstance(item, dict) or "source_id" not in item:
                continue
            outgoing = item.get("source_id") == entity_id
            if not outgoing and item.get("target_id") != entity_id:
                continue
            properties = {
                key: value
                for key, value in (item.get("properties") or {}).items()
                if value not in (None, "", [], {})
            }
            neighbours.append(
                {
                    "relation_id": item.get("id"),
                    "type": item.get("type"),
                    "direction": "out" if outgoing else "in",
                    "other_entity_id": item.get("target_id" if outgoing else "source_id"),
                    "timestamp": item.get("timestamp"),
                    **({"properties": properties} if properties else {}),
                }
            )
        compact: dict[str, Any] = {
            "status": "ok",
            "result": {
                "entity_id": entity_id,
                "relations": neighbours,
                "next_page_id": result.get("next_page_id"),
                "other_matches": len(result.get("results") or []) - len(neighbours),
            },
            "raw_result": result,
        }
        if not neighbours:
            compact["note"] = (
                "Search found no relations touching this entity id on this page; fall back to "
                "get_entity relation ids and get_relation."
            )
        return compact

    @staticmethod
    def _new_task_stats(observation: dict[str, Any]) -> dict[str, Any]:
        """Return empty agent-side counters for one task."""
        return {
            "scenario_fp": scenario_fingerprint(observation),
            "llm_steps": 0,
            "error_calls": 0,
            "guarded_calls": 0,
            "tool_counts": {},
            "total_tokens": 0,
            "cost_usd": 0.0,
            "llm_latency_ms": 0,
            "forced_finish": None,
            "verdict": None,
            "ir_artifacts": None,
            "legitimacy_evidence": None,
        }

    def _record_step(
        self,
        task_id: str,
        step_index: int,
        step: NextStep,
        arguments: dict[str, Any],
        feedback: dict[str, Any],
        llm_stats: dict[str, Any],
    ) -> None:
        """Update per-task counters and persist one step when a recorder is set."""
        stats = self._task_stats
        tool_name = step.function.tool
        status = feedback.get("status")
        stats["llm_steps"] += 1
        if feedback.get("local_guard"):
            stats["guarded_calls"] += 1
        else:
            stats["tool_counts"][tool_name] = stats["tool_counts"].get(tool_name, 0) + 1
            stats["error_calls"] += status != "ok"
        stats["total_tokens"] += llm_stats.get("total_tokens", 0)
        stats["cost_usd"] += llm_stats.get("cost_usd", 0.0)
        stats["llm_latency_ms"] += llm_stats.get("latency_ms", 0)
        if tool_name == "finish_investigation":
            submission = arguments.get("submission", {})
            stats["verdict"] = submission.get("verdict")
            stats["ir_artifacts"] = submission.get("ir_artifacts")
            stats["legitimacy_evidence"] = submission.get("legitimacy_evidence")
        if self.recorder is None:
            return
        error = feedback.get("error") or feedback.get("message")
        self.recorder.record_step(
            {
                "task_id": task_id,
                "step": step_index,
                "tool": tool_name,
                "arguments": arguments,
                "status": status,
                "error": error,
                "result_chars": len(render_json(feedback.get("result"))),
                "local_guard": feedback.get("local_guard"),
                # Raw per-call evidence for analysis and offline replay (runs/ is gitignored).
                "result": feedback.get("result"),
                "extra": {
                    key: feedback[key]
                    for key in ("observation_extra", "info_extra", "raw_result")
                    if key in feedback
                },
                "current_state": step.current_state,
                "plan": step.plan_remaining_steps_brief,
                "llm": llm_stats,
            }
        )

    def _record_task(self, task_result: TaskResult) -> None:
        """Persist the server task result merged with agent-side counters."""
        if self.recorder is None:
            return
        self.recorder.record_task({**task_result.model_dump(mode="json"), **self._task_stats})

    @staticmethod
    def _tool_specs(observation: dict[str, Any]) -> list[dict[str, Any]]:
        """Decode the runtime tool catalog from the current observation.

        Args:
            observation: Current public task observation.

        Returns:
            Advertised tool specifications.

        Raises:
            ValueError: If `available_tools` is absent or malformed.
        """
        raw_tool_specs = observation.get("available_tools")
        if not isinstance(raw_tool_specs, str):
            raise ValueError("Observation has no JSON-encoded available_tools field.")
        try:
            tool_specs = json.loads(raw_tool_specs)
        except json.JSONDecodeError as exc:
            raise ValueError("available_tools is not valid JSON.") from exc
        if not isinstance(tool_specs, list) or not all(
            isinstance(specification, dict) for specification in tool_specs
        ):
            raise ValueError("available_tools must encode a list of tool specifications.")
        return [dict(specification) for specification in tool_specs]

    @staticmethod
    def _tool_feedback(response: ToolCallResult) -> dict[str, Any]:
        """Reduce a remote tool response to evidence needed by the LLM.

        Args:
            response: Server tool-call response.

        Returns:
            Compact evidence and lifecycle flags.
        """
        # The runtime returns the whole observation (alert + ~48k-char tool catalog) on every
        # call; only `last_tool_result` and unknown extra keys are per-call evidence.
        static_keys = {"available_tools", "alert_text", "last_tool_result"}
        info_keys = {"tool_status", "tool_result", "error"}
        result = response.info.get("tool_result")
        if result is None:
            result = response.observation.get("last_tool_result")
        feedback: dict[str, Any] = {
            "status": response.info.get("tool_status", "unknown"),
            "result": parse_jsonish(result),
        }
        if response.info.get("error"):
            feedback["error"] = response.info["error"]
        extra_observation = {
            key: value for key, value in response.observation.items() if key not in static_keys
        }
        if extra_observation:
            feedback["observation_extra"] = extra_observation
        extra_info = {key: value for key, value in response.info.items() if key not in info_keys}
        if extra_info:
            feedback["info_extra"] = extra_info
        if response.terminated or response.truncated:
            feedback["terminated"] = response.terminated
            feedback["truncated"] = response.truncated
        return feedback
