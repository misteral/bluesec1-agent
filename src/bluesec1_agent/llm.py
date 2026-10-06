import asyncio
import json
import re
import time
from types import TracebackType
from typing import Any, Literal, Protocol, Self, cast

from loguru import logger
from openai import AsyncOpenAI, RateLimitError
from openai.types.chat import ChatCompletionMessageParam
from openai.types.shared_params import ResponseFormatJSONSchema
from pydantic import ValidationError

from bluesec1_agent.models import (
    FINAL_STEP_RESPONSE_FORMAT,
    NEXT_STEP_RESPONSE_FORMAT,
    FinishInvestigationRequest,
    NextStep,
)

STRUCTURED_OUTPUT_INSTRUCTION = """
Every assistant reply must be exactly one JSON object with these top-level fields:
{
  "current_state": "short evidence-focused string",
  "plan_remaining_steps_brief": ["one to five short step strings"],
  "task_completed": false,
  "function": {
    "tool": "one advertised tool name",
    "...": "that tool's arguments placed directly in this function object"
  }
}

Never use top-level `action`, `parameters`, `tool_name`, or `arguments` fields.
Never wrap tool arguments in a nested `parameters` or `arguments` object.
For example, a call with one advertised argument is:
{"tool":"advertised_tool","argument_name":"value"}
Set task_completed=true only for a function whose tool is finish_investigation.
Return no prose, markdown, XML, comments, or keys outside the required object.
""".strip()

JSON_OBJECT_SCHEMA_INSTRUCTION = "The reply must validate against this JSON schema:\n" + json.dumps(
    NEXT_STEP_RESPONSE_FORMAT["json_schema"]["schema"], separators=(",", ":")
)

ResponseFormatMode = Literal["json_schema", "json_object"]

# Free-tier limits are per minute; the SDK's sub-second backoff cannot outlast the window.
RATE_LIMIT_MAX_WAITS = 8
RATE_LIMIT_DEFAULT_WAIT_SECONDS = 30.0
RATE_LIMIT_MAX_WAIT_SECONDS = 75.0


def rate_limit_wait_seconds(error: RateLimitError, now_ms: float | None = None) -> float:
    """Return how long to wait before retrying, from the provider's reset header if present.

    Args:
        error: Provider 429 error; OpenRouter puts `X-RateLimit-Reset` (epoch ms) in metadata.
        now_ms: Current epoch time in milliseconds, injectable for tests.

    Returns:
        Seconds to sleep, bounded to a sane range.
    """
    now_ms = time.time() * 1000 if now_ms is None else now_ms
    body = error.body if isinstance(error.body, dict) else {}
    body = body.get("error", body) if isinstance(body.get("error", body), dict) else body
    headers = (body.get("metadata") or {}).get("headers") or {}
    reset = headers.get("X-RateLimit-Reset")
    try:
        wait = (float(reset) - now_ms) / 1000 + 1.0
    except (TypeError, ValueError):
        wait = RATE_LIMIT_DEFAULT_WAIT_SECONDS
    return min(max(wait, 2.0), RATE_LIMIT_MAX_WAIT_SECONDS)


REPAIR_INSTRUCTION = (
    "Your previous reply violated the required NextStep contract. " + STRUCTURED_OUTPUT_INSTRUCTION
)


class NextStepRequestError(RuntimeError):
    """Raised when an LLM cannot produce a valid structured step."""


class StructuredStepClient(Protocol):
    """Narrow async contract consumed by the investigation loop."""

    async def next_step(self, messages: list[dict[str, Any]], *, final: bool = False) -> NextStep:
        """Generate and validate one investigation step (only finishing when `final`)."""
        ...


class OpenAIStructuredStepClient:
    """Portable structured-output client for OpenAI-compatible providers."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_completion_tokens: int,
        max_retries: int,
        response_format: ResponseFormatMode = "json_schema",
        client: AsyncOpenAI | None = None,
    ) -> None:
        """Initialize an OpenAI-compatible structured step generator.

        Args:
            base_url: OpenAI-compatible API root.
            api_key: Provider credential.
            model: Provider model identifier.
            timeout_seconds: Timeout applied to each provider request.
            max_completion_tokens: Maximum generated tokens per attempt.
            max_retries: Maximum schema-generation attempts per step.
            response_format: `json_schema` for strict provider-side schemas, or
                `json_object` for providers that only support JSON mode; the
                schema is then embedded in the system prompt.
            client: Optional injected SDK client used by tests.
        """
        self.model = model
        self.max_completion_tokens = max_completion_tokens
        self.max_retries = max_retries
        self.response_format = response_format
        self.last_step_stats: dict[str, Any] = {}
        self._instruction = STRUCTURED_OUTPUT_INSTRUCTION
        self._response_format: dict[str, Any] = NEXT_STEP_RESPONSE_FORMAT
        if response_format == "json_object":
            self._instruction = (
                f"{STRUCTURED_OUTPUT_INSTRUCTION}\n\n{JSON_OBJECT_SCHEMA_INSTRUCTION}"
            )
            self._response_format = {"type": "json_object"}
        self._owns_client = client is None
        self._client = client or AsyncOpenAI(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout_seconds,
            # SDK backoff covers transient 429/5xx; schema repair stays in next_step.
            max_retries=3,
        )

    async def __aenter__(self) -> Self:
        """Enter the async LLM client context."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close an internally owned provider client."""
        await self.aclose()

    async def aclose(self) -> None:
        """Close the provider transport created by this wrapper."""
        if self._owns_client:
            await self._client.close()

    async def _create(self, **kwargs: Any) -> Any:
        """Create a chat completion, waiting out per-minute rate-limit windows.

        Raises:
            RateLimitError: If the provider is still rate-limiting after all waits.
        """
        for wait_index in range(RATE_LIMIT_MAX_WAITS + 1):
            try:
                response = await self._client.chat.completions.create(model=self.model, **kwargs)
            except RateLimitError as error:
                if wait_index == RATE_LIMIT_MAX_WAITS:
                    raise
                wait = rate_limit_wait_seconds(error)
                logger.warning("LLM rate-limited; waiting {:.0f} s before retrying.", wait)
                await asyncio.sleep(wait)
                continue
            # OpenRouter can answer 200 with an upstream error and no choices; that is transient.
            if getattr(response, "choices", None) or wait_index == RATE_LIMIT_MAX_WAITS:
                return response
            wait = min(5.0 * (wait_index + 1), RATE_LIMIT_MAX_WAIT_SECONDS)
            logger.warning(
                "LLM response had no choices ({}); retrying in {:.0f} s.",
                str(getattr(response, "model_extra", None) or "")[:300],
                wait,
            )
            await asyncio.sleep(wait)
        raise AssertionError("unreachable")

    async def preflight(self) -> None:
        """Send one tiny request with the configured response format.

        Provider-side rejections (unsupported model, response format, credentials)
        surface here, before a remote run is created and tasks are leased.

        Raises:
            openai.APIError: If the provider rejects the request.
        """
        await self._create(
            messages=[
                {"role": "system", "content": 'Reply with the JSON object {"ok": true}.'},
                {"role": "user", "content": "ping"},
            ],
            response_format=cast(ResponseFormatJSONSchema, self._response_format),
            max_completion_tokens=self.max_completion_tokens,
        )

    async def next_step(self, messages: list[dict[str, Any]], *, final: bool = False) -> NextStep:
        """Return one valid `NextStep`, repairing malformed replies when possible.

        Args:
            messages: Current investigation conversation.

        Returns:
            A locally validated structured investigation step.

        Raises:
            NextStepRequestError: If every provider reply violates the schema.
        """
        request_messages = list(messages)
        if request_messages and request_messages[0].get("role") == "system":
            first_message = dict(request_messages[0])
            first_message["content"] = f"{first_message.get('content', '')}\n\n{self._instruction}"
            request_messages[0] = first_message
        else:
            request_messages.insert(
                0,
                {"role": "system", "content": self._instruction},
            )
        last_error: Exception | None = None
        stats = {
            "attempts": 0,
            "latency_ms": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cost_usd": 0.0,
        }
        self.last_step_stats = stats

        for attempt in range(1, self.max_retries + 1):
            started_at = time.perf_counter()
            response = await self._create(
                messages=cast(list[ChatCompletionMessageParam], request_messages),
                response_format=cast(
                    ResponseFormatJSONSchema,
                    FINAL_STEP_RESPONSE_FORMAT
                    if final and self.response_format == "json_schema"
                    else self._response_format,
                ),
                max_completion_tokens=self.max_completion_tokens,
            )
            latency_ms = int((time.perf_counter() - started_at) * 1000)
            raw_content = extract_raw_content(response)
            total_tokens = response_total_tokens(response)
            usage = getattr(response, "usage", None)
            stats["attempts"] = attempt
            stats["latency_ms"] += latency_ms
            stats["prompt_tokens"] += int(getattr(usage, "prompt_tokens", 0) or 0)
            stats["completion_tokens"] += int(getattr(usage, "completion_tokens", 0) or 0)
            stats["total_tokens"] += total_tokens
            stats["cost_usd"] += float(getattr(usage, "cost", 0.0) or 0.0)

            try:
                step = parse_next_step_payload(raw_content)
                if final and not isinstance(step.function, FinishInvestigationRequest):
                    raise ValueError("Only finish_investigation is allowed on this turn.")
            except ValueError as exc:
                last_error = exc
                logger.warning(
                    "Invalid structured LLM response on attempt {}/{}: {}",
                    attempt,
                    self.max_retries,
                    raw_content[:2000] or str(exc),
                )
                if attempt == self.max_retries:
                    break
                request_messages.extend(
                    [
                        {"role": "assistant", "content": raw_content or "<empty>"},
                        {"role": "user", "content": REPAIR_INSTRUCTION},
                    ]
                )
                continue

            logger.info(
                "LLM selected {} in {} ms using {} tokens.",
                step.function.tool,
                latency_ms,
                total_tokens,
            )
            return step

        message = str(last_error or ValueError("Unable to parse model response."))
        raise NextStepRequestError(message) from last_error


def extract_message_text(message: Any) -> str:
    """Normalize string and multipart assistant content into plain text.

    Args:
        message: Provider-specific chat completion message.

    Returns:
        Concatenated textual message content.
    """
    content = getattr(message, "content", None)
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""

    text_parts: list[str] = []
    for part in content:
        if isinstance(part, dict) and part.get("type") == "text":
            text_parts.append(str(part.get("text", "")))
        elif getattr(part, "type", None) == "text":
            text_parts.append(str(getattr(part, "text", "")))
    return "".join(text_parts)


def extract_raw_content(response: Any) -> str:
    """Extract the first assistant message from a completion response.

    Args:
        response: OpenAI-compatible chat completion response.

    Returns:
        Raw assistant text.

    Raises:
        ValueError: If the provider response is missing a usable message.
    """
    choices = getattr(response, "choices", None)
    if not choices:
        raise ValueError("Model response is missing choices.")

    message = getattr(choices[0], "message", None)
    if message is None:
        raise ValueError("Model response is missing a message.")

    refusal = getattr(message, "refusal", None)
    if refusal:
        raise ValueError(f"Model refused structured output: {refusal}")
    return extract_message_text(message)


def extract_json_object(raw_content: str) -> str:
    """Remove common provider wrappers around a JSON object.

    Args:
        raw_content: Untrusted assistant response text.

    Returns:
        Candidate JSON object text for local validation.
    """
    stripped = raw_content.strip()
    if not stripped:
        return ""
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped).strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped

    match = re.search(r"\{.*\}", stripped, re.DOTALL)
    return match.group(0) if match is not None else stripped


def parse_next_step_payload(raw_content: str) -> NextStep:
    """Validate one raw provider reply as a consistent `NextStep`.

    Args:
        raw_content: Assistant response containing a structured step.

    Returns:
        Parsed and validated step.

    Raises:
        ValueError: If JSON, schema, or completion semantics are invalid.
    """
    if not raw_content:
        raise ValueError("Model returned empty content for NextStep response.")

    normalized_content = extract_json_object(raw_content)
    try:
        step = NextStep.model_validate_json(normalized_content)
    except ValidationError as exc:
        raise ValueError("Model returned invalid NextStep JSON.") from exc

    is_finish = isinstance(step.function, FinishInvestigationRequest)
    if step.task_completed != is_finish:
        raise ValueError(
            "task_completed must be true exactly when finish_investigation is selected."
        )
    return step


def response_total_tokens(response: Any) -> int:
    """Read total token usage when the provider supplies it.

    Args:
        response: OpenAI-compatible chat completion response.

    Returns:
        Non-negative total token count, or zero when unavailable.
    """
    usage = getattr(response, "usage", None)
    total_tokens = getattr(usage, "total_tokens", 0)
    return total_tokens if isinstance(total_tokens, int) and total_tokens >= 0 else 0


def render_json(value: Any) -> str:
    """Serialize participant-visible context for an LLM message.

    Args:
        value: Public JSON-compatible value.

    Returns:
        Stable readable JSON text.
    """
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str)
