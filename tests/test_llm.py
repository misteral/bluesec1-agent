import asyncio
from types import SimpleNamespace
from typing import Any, cast

import pytest
from openai import AsyncOpenAI

from bluesec1_agent.llm import (
    OpenAIStructuredStepClient,
    parse_next_step_payload,
)
from bluesec1_agent.models import (
    NEXT_STEP_RESPONSE_FORMAT,
    BenignFinishInvestigationSubmission,
    FinishInvestigationEntityEvidence,
    FinishInvestigationRequest,
    GetADObjectInfoRequest,
    GetEntityRequest,
    NextStep,
    SearchRequest,
)


class FakeCompletions:
    """Queue-backed fake for the OpenAI chat completion endpoint."""

    def __init__(self, contents: list[str]) -> None:
        """Store response content and request audit state."""
        self.contents = list(contents)
        self.requests: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        """Return the next queued assistant message."""
        self.requests.append(kwargs)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=self.contents.pop(0),
                        refusal=None,
                    )
                )
            ],
            usage=SimpleNamespace(total_tokens=17),
        )


class FakeOpenAI:
    """Minimal object graph required by `OpenAIStructuredStepClient`."""

    def __init__(self, contents: list[str]) -> None:
        """Expose fake chat completions."""
        self.completions = FakeCompletions(contents)
        self.chat = SimpleNamespace(completions=self.completions)


def valid_process_step() -> NextStep:
    """Build one valid non-terminal graph navigation step."""
    return NextStep(
        current_state="The trigger entity needs its relations.",
        plan_remaining_steps_brief=["Read the trigger entity."],
        task_completed=False,
        function=GetEntityRequest(
            tool="get_entity",
            entity_id="entity-1",
            reasoning="Inspect the alert entity.",
        ),
    )


def test_structured_client_repairs_malformed_response() -> None:
    """Malformed provider output should be retried outside the main history."""
    fake_openai = FakeOpenAI(["not-json", valid_process_step().model_dump_json()])
    client = OpenAIStructuredStepClient(
        base_url="https://llm.example/v1",
        api_key="secret",
        model="test-model",
        timeout_seconds=10.0,
        max_completion_tokens=1000,
        max_retries=3,
        client=cast(AsyncOpenAI, fake_openai),
    )
    original_messages = [{"role": "system", "content": "Investigate."}]

    step = asyncio.run(client.next_step(original_messages))

    assert step.function.tool == "get_entity"
    assert len(fake_openai.completions.requests) == 2
    first_messages = fake_openai.completions.requests[0]["messages"]
    assert "Never use top-level `action`" in first_messages[0]["content"]
    assert "advertised_tool" in first_messages[0]["content"]
    repaired_messages = fake_openai.completions.requests[1]["messages"]
    assert repaired_messages[-1]["role"] == "user"
    assert original_messages == [{"role": "system", "content": "Investigate."}]


def test_parser_corrects_inconsistent_completion_flag() -> None:
    """The redundant task_completed flag follows the chosen function instead of failing."""
    payload = valid_process_step().model_copy(update={"task_completed": True}).model_dump_json()

    assert parse_next_step_payload(payload).task_completed is False


def test_response_schema_requires_nullable_tool_fields() -> None:
    """Strict provider schema should require optional fields as nullable values."""
    schema = NEXT_STEP_RESPONSE_FORMAT["json_schema"]["schema"]
    process_schema = schema["$defs"]["GetEntityRequest"]

    assert set(process_schema["required"]) == set(process_schema["properties"])
    assert "default" not in str(schema)
    assert "discriminator" not in str(schema)
    assert "oneOf" not in str(schema)
    assert set(schema["$defs"]["SearchRequest"]["required"]) == set(
        schema["$defs"]["SearchRequest"]["properties"]
    )
    assert set(schema["$defs"]["FinishInvestigationRequest"]["properties"]) == {
        "tool",
        "submission",
    }


def test_competition_search_serializes_extended_arguments() -> None:
    """Search should retain every argument supported by the competition tool."""
    request = SearchRequest.model_validate(
        {
            "tool": "search",
            "query": "powershell",
            "reasoning": "Find the related process.",
            "page_id": 2,
            "scope": {"kind": "entity", "type": "windows_process"},
            "time_window": {"from": "2026-09-01", "to": "2026-09-02"},
            "sort_order": "descending",
        }
    )

    arguments = request.model_dump(mode="json", by_alias=True, exclude={"tool"}, exclude_none=True)

    assert arguments["page_id"] == 2
    assert arguments["scope"] == {"kind": "entity", "type": "windows_process"}
    assert arguments["time_window"] == {
        "from": "2026-09-01T00:00:00Z",
        "to": "2026-09-02T23:59:59.999999Z",
    }
    assert arguments["sort_order"] == "descending"
    with pytest.raises(ValueError):
        SearchRequest.model_validate(
            {"tool": "search", "query": "process", "reasoning": "Inspect.", "page_id": 0}
        )
    with pytest.raises(ValueError):
        SearchRequest.model_validate(
            {
                "tool": "search",
                "query": "process",
                "reasoning": "Inspect.",
                "scope": {"kind": "entity", "type": "nonexistent"},
            }
        )
    with pytest.raises(ValueError):
        SearchRequest.model_validate(
            {
                "tool": "search",
                "query": "process",
                "reasoning": "Inspect.",
                "time_window": {"from": "2026-09-02", "to": "2026-09-01"},
            }
        )


def test_navigation_requires_reasoning_and_supports_ad_lookup() -> None:
    """Competition navigation tools should require a bounded rationale."""
    with pytest.raises(ValueError):
        GetEntityRequest.model_validate({"tool": "get_entity", "entity_id": "entity-1"})
    with pytest.raises(ValueError):
        GetADObjectInfoRequest.model_validate(
            {"tool": "get_ad_object_info", "ad_object_id": "ad-1", "reasoning": "x" * 4097}
        )

    request = GetADObjectInfoRequest(
        tool="get_ad_object_info", ad_object_id="ad-1", reasoning="Inspect the account."
    )
    assert request.model_dump(exclude={"tool"}) == {
        "ad_object_id": "ad-1",
        "reasoning": "Inspect the account.",
    }


def test_benign_finish_uses_submission_envelope() -> None:
    """Benign conclusions should contain only legitimacy evidence."""
    request = FinishInvestigationRequest(
        tool="finish_investigation",
        submission=BenignFinishInvestigationSubmission(
            verdict="benign",
            legitimacy_evidence=[
                FinishInvestigationEntityEvidence(
                    anchor="entity", entity_id="entity-1", property_fields=["command_line"]
                )
            ],
            reasoning="The process matches authorized activity.",
        ),
    )

    assert request.model_dump(exclude={"tool"}) == {
        "submission": {
            "verdict": "benign",
            "legitimacy_evidence": [
                {"anchor": "entity", "entity_id": "entity-1", "property_fields": ["command_line"]}
            ],
            "reasoning": "The process matches authorized activity.",
        }
    }
    step = NextStep(
        current_state="The alert is explained by authorized activity.",
        plan_remaining_steps_brief=["Submit benign evidence."],
        task_completed=True,
        function=request,
    )
    assert isinstance(
        parse_next_step_payload(step.model_dump_json()).function, FinishInvestigationRequest
    )
    with pytest.raises(ValueError):
        FinishInvestigationRequest.model_validate(
            {
                "tool": "finish_investigation",
                "submission": {"verdict": "benign", "ir_artifacts": [], "reasoning": "Safe."},
            }
        )


def test_rate_limit_wait_uses_openrouter_reset_header() -> None:
    """A per-minute 429 should wait until the reported window reset, bounded."""
    import httpx
    from openai import RateLimitError

    from bluesec1_agent.llm import rate_limit_wait_seconds

    request = httpx.Request("POST", "https://llm.example/v1/chat/completions")
    body = {"error": {"code": 429, "metadata": {"headers": {"X-RateLimit-Reset": "61000"}}}}
    error = RateLimitError("limited", response=httpx.Response(429, request=request), body=body)

    assert rate_limit_wait_seconds(error, now_ms=1000) == 61.0
    assert rate_limit_wait_seconds(error, now_ms=0) == 62.0
    no_header = RateLimitError("limited", response=httpx.Response(429, request=request), body={})
    assert rate_limit_wait_seconds(no_header, now_ms=0) == 30.0


def test_create_retries_responses_without_choices(monkeypatch: pytest.MonkeyPatch) -> None:
    """An upstream error returned as 200 without choices is retried, not fatal."""
    import bluesec1_agent.llm as llm_module

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(llm_module.asyncio, "sleep", no_sleep)
    good = valid_process_step().model_dump_json()
    fake_openai = FakeOpenAI([good])
    real_create = fake_openai.completions.create
    calls = {"n": 0}

    async def flaky_create(**kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            return SimpleNamespace(choices=[], usage=None, model_extra={"error": "upstream"})
        return await real_create(**kwargs)

    fake_openai.completions.create = flaky_create
    client = OpenAIStructuredStepClient(
        base_url="https://llm.example/v1",
        api_key="secret",
        model="test-model",
        timeout_seconds=10.0,
        max_completion_tokens=1000,
        max_retries=1,
        client=cast(AsyncOpenAI, fake_openai),
    )

    step = asyncio.run(client.next_step([{"role": "system", "content": "Investigate."}]))

    assert step.function.tool == "get_entity"
    assert calls["n"] == 2
