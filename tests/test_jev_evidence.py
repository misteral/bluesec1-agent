import asyncio
from typing import Any, cast

from bluesec1_agent.jev_client import JevClient
from bluesec1_agent.jev_evidence import jev_root_cause_evidence
from bluesec1_agent.review import EntityBook


class PickFirstJev:
    """Picks the first candidate for every role with a given confidence."""

    def __init__(self, confidence: float) -> None:
        self.confidence = confidence
        self.cost_usd = 0.0
        self.questions: dict[str, Any] = {}

    async def decide(self, state: dict[str, Any], questions: dict[str, Any]) -> dict[str, Any]:
        self.questions = questions
        return {
            role: {"type": "choice", "choice": "e00", "confidence": self.confidence}
            for role in questions
        }


def book() -> EntityBook:
    b = EntityBook()
    b.learn(
        [
            {
                "id": "alerted",
                "type": "windows_process",
                "properties": {"cmdline": "a", "user": "u"},
            },
            {
                "id": "parent",
                "type": "windows_process",
                "properties": {"cmdline": "svc", "image_path": "p"},
            },
            {
                "id": "acct",
                "type": "windows_user",
                "properties": {"username": "u", "domain": "d", "sid": "s"},
            },
            {
                "id": "script",
                "type": "powershell_script",
                "properties": {"path": "x.ps1", "script_text": "t"},
            },
        ]
    )
    return b


def test_root_cause_cites_actor_launcher_action_not_the_alerted_process() -> None:
    jev = PickFirstJev(0.9)
    alert = {"trigger_entities": [{"id": "alerted"}]}

    evidence = asyncio.run(jev_root_cause_evidence(cast(JevClient, jev), book(), alert, "admin"))

    assert evidence is not None
    cited = {e["entity_id"]: e["property_fields"] for e in evidence}
    assert "alerted" not in cited
    assert cited["acct"] == ["username", "domain"]
    assert set(cited) == {"acct", "parent", "script"}
    assert all(len(fields) <= 2 for fields in cited.values())
    assert all(e["anchor"] == "entity" for e in evidence)


def test_low_confidence_keeps_the_llm_evidence() -> None:
    evidence = asyncio.run(
        jev_root_cause_evidence(cast(JevClient, PickFirstJev(0.2)), book(), {}, "admin")
    )
    assert evidence is None
