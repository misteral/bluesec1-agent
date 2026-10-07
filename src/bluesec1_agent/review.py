"""Finish gates and pre-submission review (H-03, H-04).

Before `finish_investigation` reaches the scored runtime, deterministic gates check the payload
against what the agent actually saw, and the model gets one review turn with the full list of
entities it observed. Neither costs a platform tool call.
"""

from typing import Any

from bluesec1_agent.guard import parse_jsonish

# IR artifact kinds that fit each entity type. Types not listed are not gated on kind.
KINDS_BY_ENTITY_TYPE: dict[str, set[str]] = {
    "host": {"host_to_isolate", "cleanup_to_verify", "artifact_observed", "other"},
    "windows_user": {"identity_to_rotate", "identity_observed", "other"},
    "linux_user": {"identity_to_rotate", "identity_observed", "other"},
    "ad_object": {"identity_to_rotate", "identity_observed", "persistence_to_remove", "other"},
    "windows_process": {"process_observed", "other"},
    "linux_process": {"process_observed", "other"},
    "windows_file": {"file_to_delete", "file_observed", "persistence_to_remove", "other"},
    "linux_file": {"file_to_delete", "file_observed", "persistence_to_remove", "other"},
    "archive_file": {"file_to_delete", "file_observed", "other"},
    "powershell_script": {"file_to_delete", "file_observed", "artifact_observed", "other"},
    "registry_key": {"registry_observed", "persistence_to_remove", "cleanup_to_verify", "other"},
    "windows_service": {"persistence_to_remove", "artifact_observed", "other"},
    "scheduled_task": {"persistence_to_remove", "artifact_observed", "other"},
    "wmi_event_filter": {"persistence_to_remove", "artifact_observed", "other"},
    "wmi_event_consumer": {"persistence_to_remove", "artifact_observed", "other"},
    "wmi_binding": {"persistence_to_remove", "artifact_observed", "other"},
    "systemd_unit": {"persistence_to_remove", "artifact_observed", "other"},
    "network_connection": {"network_block", "other"},
    "email": {"mailbox_action", "artifact_observed", "other"},
    "email_url": {"network_block", "mailbox_action", "artifact_observed", "other"},
    "email_attachment": {"file_to_delete", "mailbox_action", "file_observed", "other"},
    "mounted_volume": {"mount_observed", "cleanup_to_verify", "other"},
    "lnk_shortcut": {"lnk_observed", "file_to_delete", "persistence_to_remove", "other"},
    "kerberos_ticket": {"ticket_observed", "identity_to_rotate", "other"},
}

# The artifact contract has two tiers (IRArtifactKind docstring in the tool catalog): RESPOND
# actions and FORENSIC observed records, with a validator enforcing tier/kind pairing. These
# tables give one kind per tier for each entity type, from the contract — not from dev tasks.
RESPOND_KIND_BY_TYPE: dict[str, str] = {
    "host": "host_to_isolate",
    "windows_user": "identity_to_rotate",
    "linux_user": "identity_to_rotate",
    "ad_object": "identity_to_rotate",
    "kerberos_ticket": "identity_to_rotate",
    "windows_file": "file_to_delete",
    "linux_file": "file_to_delete",
    "archive_file": "file_to_delete",
    "powershell_script": "file_to_delete",
    "email_attachment": "file_to_delete",
    "windows_service": "persistence_to_remove",
    "scheduled_task": "persistence_to_remove",
    "wmi_event_filter": "persistence_to_remove",
    "wmi_event_consumer": "persistence_to_remove",
    "wmi_binding": "persistence_to_remove",
    "systemd_unit": "persistence_to_remove",
    "registry_key": "persistence_to_remove",
    "network_connection": "network_block",
    "email_url": "network_block",
    "email": "mailbox_action",
}
FORENSIC_KIND_BY_TYPE: dict[str, str] = {
    "windows_process": "process_observed",
    "linux_process": "process_observed",
    "windows_file": "file_observed",
    "linux_file": "file_observed",
    "archive_file": "file_observed",
    "email_attachment": "file_observed",
    "registry_key": "registry_observed",
    "windows_user": "identity_observed",
    "linux_user": "identity_observed",
    "ad_object": "identity_observed",
    "mounted_volume": "mount_observed",
    "lnk_shortcut": "lnk_observed",
    "kerberos_ticket": "ticket_observed",
}


# H-37: telemetry records are not IR artifacts (contract: connection telemetry lives on relations;
# soc-expert: cmdlet rows r −0.53, connection rows r −0.35 with Q within template, 5 families).
TELEMETRY_TYPES = {"powershell_cmdlet_invocation", "network_connection"}


def drop_telemetry(rows: list[dict[str, str]], book: "EntityBook") -> list[dict[str, str]]:
    """Remove artifact rows whose entity is a telemetry record; never empties the list."""
    kept = [
        r
        for r in rows
        if (book.entities.get(r.get("entity_id", "")) or {}).get("type") not in TELEMETRY_TYPES
    ]
    return kept or rows


def dual_tier_artifacts(
    entity_ids: list[str], book: "EntityBook", *, allow_fallback: bool = True
) -> list[dict[str, str]]:
    """One RESPOND and one FORENSIC row per attacker entity, where the type has each tier.

    With `allow_fallback=False`, entities whose type has no tier row are skipped instead of
    being reported as `artifact_observed` (that escape-hatch kind lowered quality in both agent
    families across exp-008…015 — likely a marker of reporting a non-attacker entity).
    """
    artifacts: list[dict[str, str]] = []
    for entity_id in entity_ids:
        entity_type = book.entities[entity_id]["type"]
        kinds = [
            kind
            for kind in (
                RESPOND_KIND_BY_TYPE.get(entity_type),
                FORENSIC_KIND_BY_TYPE.get(entity_type),
            )
            if kind
        ] or (["artifact_observed"] if allow_fallback else [])
        artifacts.extend({"entity_id": entity_id, "kind": kind} for kind in kinds)
    return artifacts


LABEL_KEYS = (
    "hostname",
    "image_path",
    "path",
    "name",
    "user",
    "account_name",
    "sam_account_name",
    "key_path",
    "service_name",
    "task_name",
    "remote_ip",
    "dest_ip",
    "url",
    "subject",
)


class EntityBook:
    """Every entity observed in the task: type, short label and property names."""

    def __init__(self) -> None:
        """Start empty."""
        self.entities: dict[str, dict[str, Any]] = {}

    def learn(self, value: Any) -> None:
        """Record entities (dicts with id, type and properties) found anywhere in a value."""
        value = parse_jsonish(value)
        if isinstance(value, list):
            for item in value:
                self.learn(item)
            return
        if not isinstance(value, dict):
            return
        properties = value.get("properties")
        if (
            isinstance(value.get("id"), str)
            and isinstance(value.get("type"), str)
            and isinstance(properties, dict)
            and "source_id" not in value
        ):
            self.entities[value["id"]] = {
                "type": value["type"],
                "label": self._label(properties),
                "fields": sorted(key for key, item in properties.items() if item is not None),
            }
        for item in value.values():
            if isinstance(item, dict | list | str):
                self.learn(item)

    @staticmethod
    def _label(properties: dict[str, Any]) -> str:
        parts = [str(properties[key]) for key in LABEL_KEYS if properties.get(key)]
        cmdline = properties.get("cmdline")
        if cmdline and str(cmdline) not in parts:
            parts.append(str(cmdline)[:160])
        return " | ".join(parts[:3])[:240]

    def catalogue(self) -> list[dict[str, Any]]:
        """Compact list of observed entities for the review turn."""
        return [
            {"entity_id": entity_id, "type": data["type"], "label": data["label"]}
            for entity_id, data in self.entities.items()
        ]


def gate_issues(
    submission: dict[str, Any],
    book: EntityBook,
    seen_ids: set[str],
    endpoint_entities: set[str] | None = None,
) -> list[str]:
    """Return deterministic problems with a finish payload; empty when it passes.

    Args:
        submission: The `submission` object of a finish_investigation call.
        book: Entities observed in the task.
        seen_ids: Every id seen in the alert or tool results (entities and relations).
        endpoint_entities: Entity ids known only as relation endpoints (never read). They are
            valid artifacts; their type is unknown, so the kind is not checked. Before this,
            12–17 real artifacts per mimo run were rejected as "relation ids" (exp-013/018/020).

    Returns:
        Human-readable issues the model must fix before submitting.
    """
    issues: list[str] = []
    if submission.get("verdict") == "malicious":
        artifacts = submission.get("ir_artifacts") or []
        if not artifacts:
            issues.append("A malicious verdict needs ir_artifacts.")
        pairs: set[tuple[str, str]] = set()
        for artifact in artifacts:
            entity_id, kind = artifact.get("entity_id"), artifact.get("kind")
            if (entity_id, kind) in pairs:
                issues.append(f"Duplicate artifact {entity_id} / {kind}.")
            pairs.add((entity_id, kind))
            if entity_id in (endpoint_entities or set()) and entity_id not in book.entities:
                continue
            if entity_id not in book.entities:
                where = "a relation id" if entity_id in seen_ids else "never observed"
                issues.append(f"Artifact {entity_id!r} is {where}; artifacts must be entity ids.")
                continue
            entity_type = book.entities[entity_id]["type"]
            allowed = KINDS_BY_ENTITY_TYPE.get(entity_type)
            if allowed is not None and kind not in allowed:
                issues.append(
                    f"Kind {kind!r} does not fit {entity_type} {entity_id}; "
                    f"use one of {sorted(allowed)}."
                )
    else:
        for evidence in submission.get("legitimacy_evidence") or []:
            if evidence.get("anchor") == "entity":
                entity = book.entities.get(evidence.get("entity_id"))
                if entity is None:
                    issues.append(f"Evidence entity {evidence.get('entity_id')!r} never observed.")
                    continue
                missing = set(evidence.get("property_fields") or []) - set(entity["fields"])
                if missing:
                    issues.append(
                        f"Evidence fields {sorted(missing)} are not set on "
                        f"{evidence.get('entity_id')}; available: {entity['fields']}."
                    )
            elif evidence.get("relation_id") not in seen_ids:
                issues.append(f"Evidence relation {evidence.get('relation_id')!r} never observed.")
    return issues


def review_message(submission: dict[str, Any], book: EntityBook, issues: list[str]) -> str:
    """Build the single pre-submission review prompt."""
    lines = [
        "REVIEW BEFORE SUBMITTING (no tool call is spent on this turn).",
        f"Your draft verdict: {submission.get('verdict')}.",
    ]
    if issues:
        lines.append("Problems that must be fixed:")
        lines.extend(f"- {issue}" for issue in issues)
    lines += [
        "Entities you observed in this task (id, type, label):",
        *(f"- {e['entity_id']} | {e['type']} | {e['label']}" for e in book.catalogue()),
        "Re-check: (1) is the verdict right — a signed or system binary alone proves nothing; "
        "(2) for malicious, is EVERY attacker-related entity above reported with a fitting kind "
        "(hosts, accounts, processes, files, persistence, registry, tickets), and nothing "
        "unrelated; (3) for benign, does the evidence cite real fields. "
        "Then call finish_investigation with the final payload.",
    ]
    return "\n".join(lines)


def sanitize_submission(
    submission: dict[str, Any],
    book: EntityBook,
    seen_ids: set[str],
    endpoint_entities: set[str] | None = None,
) -> dict[str, Any]:
    """Drop parts of a final payload that cannot be right, keeping the rest.

    Removes artifacts that are not observed entity ids and duplicates, and evidence fields that
    are not set on the cited entity. Never empties a non-empty list: if nothing survives, the
    original is kept so the runtime still receives the model's answer.
    """
    cleaned = dict(submission)
    if submission.get("verdict") == "malicious":
        artifacts, pairs = [], set()
        for artifact in submission.get("ir_artifacts") or []:
            pair = (artifact.get("entity_id"), artifact.get("kind"))
            known = pair[0] in book.entities or pair[0] in (endpoint_entities or set())
            if known and pair not in pairs:
                artifacts.append(artifact)
                pairs.add(pair)
        if artifacts:
            cleaned["ir_artifacts"] = artifacts
    else:
        evidence_list = []
        for evidence in submission.get("legitimacy_evidence") or []:
            if evidence.get("anchor") == "entity":
                entity = book.entities.get(evidence.get("entity_id"))
                if entity is None:
                    continue
                fields = [f for f in evidence.get("property_fields") or [] if f in entity["fields"]]
                if fields:
                    evidence_list.append({**evidence, "property_fields": fields})
            elif evidence.get("relation_id") in seen_ids:
                evidence_list.append(evidence)
        if evidence_list:
            cleaned["legitimacy_evidence"] = evidence_list
    return cleaned


def apply_payload_policy(
    submission: dict[str, Any],
    book: EntityBook,
    *,
    benign_max_entities: int = 3,
    tiers: bool = True,
    v2: bool = False,
    no_telemetry: bool = False,
    alert_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Contract-derived payload shaping (exp-014 showed +0.06 quality in both verdict groups).

    Malicious: every reported entity also gets its missing RESPOND/FORENSIC tier rows.
    Benign: at most `benign_max_entities` entity citations with at most 4 fields each, because
    extra citations lowered quality.

    v2 (brainstorm 2026-10-07, devil's-advocate-checked): malicious drops `artifact_observed`
    rows; benign cites alert entities first and keeps at most one relation anchor (relation
    anchors lowered quality within both agent families; a case may still rest on one link).
    """
    shaped = dict(submission)
    if no_telemetry and submission.get("verdict") == "malicious":
        submission = {
            **submission,
            "ir_artifacts": drop_telemetry(list(submission.get("ir_artifacts") or []), book),
        }
        shaped = dict(submission)
    if v2 and submission.get("verdict") == "malicious":
        kept = [
            r for r in submission.get("ir_artifacts") or [] if r.get("kind") != "artifact_observed"
        ]
        if kept:
            submission = {**submission, "ir_artifacts": kept}
    if submission.get("verdict") == "malicious" and not tiers:
        return shaped
    if submission.get("verdict") == "malicious":
        rows = list(submission.get("ir_artifacts") or [])
        present = {(r.get("entity_id"), r.get("kind")) for r in rows}
        reported = [r.get("entity_id") for r in rows if r.get("entity_id") in book.entities]
        for row in dual_tier_artifacts(list(dict.fromkeys(reported)), book):
            if (
                row["kind"] != "artifact_observed"
                and (row["entity_id"], row["kind"]) not in present
            ):
                rows.append(row)
                present.add((row["entity_id"], row["kind"]))
        shaped["ir_artifacts"] = rows
    else:
        evidence = []
        entities = 0
        items = list(submission.get("legitimacy_evidence") or [])
        if v2:
            alert = set(alert_ids or [])
            items.sort(key=lambda i: 0 if i.get("entity_id") in alert else 1)
            relations = [i for i in items if i.get("anchor") == "relation"][:1]
            items = [i for i in items if i.get("anchor") != "relation"] + relations
        for item in items:
            if item.get("anchor") == "entity":
                if entities >= benign_max_entities:
                    continue
                entities += 1
                item = {**item, "property_fields": list(item.get("property_fields") or [])[:4]}
            evidence.append(item)
        if evidence:
            shaped["legitimacy_evidence"] = evidence
    return shaped
