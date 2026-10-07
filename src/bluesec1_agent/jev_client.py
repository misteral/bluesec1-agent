"""Client for TypeSafe Jev typed decisions on OpenRouter (`POST /api/alpha/decisions`).

Jev is a decision model: it takes a state object plus typed questions (`noul`, `choice`,
`score`) and returns typed answers with probabilities. It writes no free text.
Docs: https://openrouter.ai/docs/guides/community/jev-tutorial
"""

import asyncio
import json
from typing import Any

import httpx
from loguru import logger

DECISIONS_URL = "https://openrouter.ai/api/alpha/decisions"
# Jev's context covers state + questions; keep a margin under its 32k-token window.
MAX_STATE_CHARS = 90_000


class JevError(RuntimeError):
    """Raised when Jev cannot return a decision."""


class JevClient:
    """Minimal async Jev client with retries and cost accounting."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str = "typesafe/jev-1.13",
        timeout_seconds: float = 60.0,
        max_attempts: int = 4,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Configure the client.

        Args:
            api_key: OpenRouter API key.
            model: Jev model id.
            timeout_seconds: Per-request timeout.
            max_attempts: Attempts for transient failures (429, 5xx, network).
            client: Optional injected HTTP client for tests.
        """
        self.model = model
        self.max_attempts = max_attempts
        self.cost_usd = 0.0
        self.calls = 0
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=timeout_seconds, headers={"Authorization": f"Bearer {api_key}"}
        )

    async def aclose(self) -> None:
        """Close an internally owned HTTP client."""
        if self._owns_client:
            await self._client.aclose()

    async def decide(
        self, state: dict[str, Any], questions: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        """Ask typed questions about a state; return the `answers` object.

        Raises:
            JevError: If every attempt fails or the state is too large.
        """
        body = {"model": self.model, "state": state, "questions": questions}
        if len(json.dumps(state, default=str)) > MAX_STATE_CHARS:
            raise JevError("Jev state exceeds the context budget; compact it first.")
        last_error: str = ""
        for attempt in range(1, self.max_attempts + 1):
            try:
                response = await self._client.post(DECISIONS_URL, json=body)
            except httpx.HTTPError as error:
                last_error = f"{type(error).__name__}: {error}"
            else:
                if response.status_code == 200:
                    data = response.json()
                    self.calls += 1
                    self.cost_usd += float((data.get("usage") or {}).get("cost") or 0.0)
                    answers = data.get("answers")
                    if isinstance(answers, dict) and set(questions) <= set(answers):
                        return answers
                    last_error = f"incomplete answers: {str(data)[:300]}"
                elif response.status_code in (429, 500, 502, 503, 504):
                    last_error = f"HTTP {response.status_code}: {response.text[:300]}"
                else:
                    raise JevError(f"HTTP {response.status_code}: {response.text[:500]}")
            wait = min(2.0 * attempt, 20.0)
            logger.warning(
                "Jev attempt {} failed ({}); retrying in {:.0f} s.", attempt, last_error, wait
            )
            await asyncio.sleep(wait)
        raise JevError(last_error or "Jev returned no decision.")
