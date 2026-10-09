"""H-34: the reasoning LLM decides the verdict; Jev selects the benign root-cause evidence.

Jev's typed `choice` answers pick, from the entities the agent observed, who legitimately
performed the alerted activity, what legitimately launched it, and one item showing it stayed in
role (H-29: benign evidence = the root cause, not the alerted process). Code builds the payload:
1–3 entity citations, ≤2 identifying fields each, no relation anchors.
"""

from typing import Any

from loguru import logger

from bluesec1_agent.jev_client import JevClient, JevError
from bluesec1_agent.review import EntityBook

ACCOUNT_TYPES = {"windows_user", "linux_user", "ad_object"}
LAUNCHER_TYPES = {
    "windows_process",
    "linux_process",
    "scheduled_task",
    "windows_service",
    "systemd_unit",
    "wmi_event_consumer",
    "app_object",
}
ACTION_TYPES = {
    # Processes belong to the launcher role; the action is what the activity worked with.
    "powershell_script",
    "windows_file",
    "linux_file",
    "powershell_cmdlet_invocation",
    "registry_key",
}
# Identifying fields per role, most telling first; only fields actually set are cited.
FIELDS_BY_ROLE = {
    "actor": ("account_type", "username", "domain", "group_memberships", "is_privileged", "name"),
    "launcher": (
        "cmdline",
        "image_path",
        "task_name",
        "action_target",
        "run_as_account",
        "service_name",
        "binary_path",
        "service_account",
        "parent_image",
        "user",
    ),
    "action": ("script_text", "path", "command_name", "cmdline", "image_path", "key_path"),
}
NONE = "none"
MIN_CONFIDENCE = 0.4
MAX_CANDIDATES = 25

QUESTIONS = {
    "actor": (
        ACCOUNT_TYPES,
        "Which account legitimately performed the alerted activity (the responsible actor)?",
    ),
    "launcher": (
        LAUNCHER_TYPES,
        "Which entity legitimately launched, scheduled or hosted the alerted activity "
        "(its parent, task, service, installer or session root)? Not the alerted process itself.",
    ),
    "action": (
        ACTION_TYPES,
        "Which single item best shows the activity stayed within its legitimate role "
        "(the script, command or file it worked with)?",
    ),
}


async def jev_root_cause_evidence(
    jev: JevClient,
    book: EntityBook,
    alert: dict[str, Any],
    verdict_reasoning: str,
    max_items: int = 3,
) -> list[dict[str, Any]] | None:
    """Return 1–3 root-cause entity citations chosen by Jev, or None to keep the LLM's own.

    Args:
        jev: Jev decisions client.
        book: Entities observed in the task (type, label, set fields).
        alert: Parsed alert (trigger entities are excluded from launcher/action choices).
        verdict_reasoning: The LLM's benign reasoning, given to Jev as context.
    """
    alerted = {
        e["id"] for e in alert.get("trigger_entities") or [] if isinstance(e, dict) and "id" in e
    }
    questions: dict[str, dict[str, Any]] = {}
    options_by_role: dict[str, dict[str, str]] = {}
    for role, (types, instruction) in QUESTIONS.items():
        candidates = [
            entity_id
            for entity_id, entity in book.entities.items()
            if entity["type"] in types and (role == "actor" or entity_id not in alerted)
        ][:MAX_CANDIDATES]
        if not candidates:
            continue
        options = {f"e{i:02d}": entity_id for i, entity_id in enumerate(candidates)}
        options_by_role[role] = options
        criteria = {
            key: f"{book.entities[entity_id]['type']}: {book.entities[entity_id]['label']}"[:200]
            for key, entity_id in options.items()
        }
        criteria[NONE] = "No observed entity fits this role."
        questions[role] = {"type": "choice", "instructions": instruction, "criteria": criteria}
    if not questions:
        return None
    state = {
        "alert": alert.get("alert_description") or "",
        "analyst_conclusion": verdict_reasoning[:1500],
        "observed_entities": [
            f"{e['type']}: {e['label']}"[:160] for e in list(book.entities.values())[:80]
        ],
    }
    try:
        answers = await jev.decide(state, questions)
    except JevError as error:
        logger.warning("Jev root-cause selection failed: {}", error)
        return None
    evidence: list[dict[str, Any]] = []
    # Most telling first when only a few citations are kept: what launched it, then who.
    for role in sorted(options_by_role, key=["launcher", "actor", "action"].index):
        options = options_by_role[role]
        answer = answers.get(role) or {}
        choice = answer.get("choice")
        confidence = float(answer.get("confidence") or 0.0)
        if choice in (None, NONE) or choice not in options or confidence < MIN_CONFIDENCE:
            continue
        entity_id = options[choice]
        fields = [f for f in FIELDS_BY_ROLE[role] if f in book.entities[entity_id]["fields"]][:2]
        if fields and all(e["entity_id"] != entity_id for e in evidence):
            evidence.append({"anchor": "entity", "entity_id": entity_id, "property_fields": fields})
    return evidence[:max_items] or None
