"""SGR `conclude` step: a structured conclusion verified by code before finish (H-44).

The model must call the agent-side tool `conclude` before `finish_investigation`. For a
legitimate (benign) conclusion the harness checks, from the task's own call log and observed
graph — never from the model's self-report — that the evidence-gathering steps a SOC analyst
would require were done. A failed check returns a specific instruction; no platform call is
spent. The check forces evidence, never a verdict direction.
"""

from dataclasses import dataclass, field
from typing import Any

from bluesec1_agent.guard import parse_jsonish

# Relation types whose source side is "who/what reached in" — the other end must be examined
# before calling activity legitimate (soc-expert consultation 2: "misread inbound").
INBOUND_TYPES = {
    "accepted_connection_from",
    "logged_on_to",
    "received_data_from",
    "opened_share_session",
    "served_request_for",
    "connected_to_pipe",
}
HOST_TYPES = {"host"}
CHILD_TYPES = {"win_process_create", "parent_of", "wrote_file", "executed_file", "executed_script"}
MAX_FAILED_CONCLUDES = 2


@dataclass
class TaskLog:
    """What the agent did and saw in one task, for verifying a conclusion."""

    alert_ids: set[str]
    alert_hosts: set[str]
    relations: dict[str, dict[str, Any]] = field(default_factory=dict)
    expanded: set[str] = field(default_factory=set)
    searched_queries: list[dict[str, Any]] = field(default_factory=list)
    read_entities: set[str] = field(default_factory=set)

    @classmethod
    def from_alert(cls, alert: dict[str, Any]) -> "TaskLog":
        entities = [e for e in alert.get("trigger_entities") or [] if isinstance(e, dict)]
        log = cls(
            alert_ids={e["id"] for e in entities if "id" in e},
            alert_hosts={e["id"] for e in entities if e.get("type") in HOST_TYPES},
        )
        log.learn(alert)
        return log

    def record_call(self, tool: str, arguments: dict[str, Any], result: Any) -> None:
        if tool == "expand_entity":
            self.expanded.add(arguments.get("entity_id", ""))
        elif tool == "search":
            self.searched_queries.append(arguments)
        elif tool == "get_entity":
            self.read_entities.add(arguments.get("entity_id", ""))
        self.learn(result)

    def learn(self, value: Any) -> None:
        value = parse_jsonish(value)
        stack = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, dict):
                if isinstance(item.get("id"), str) and "source_id" in item and "target_id" in item:
                    self.relations[item["id"]] = {
                        "type": item.get("type"),
                        "source": item.get("source_id"),
                        "target": item.get("target_id"),
                    }
                if isinstance(item.get("id"), str) and isinstance(item.get("properties"), dict):
                    self.read_entities.add(item["id"])
                stack.extend(v for v in item.values() if isinstance(v, dict | list))


def unmet_checks(log: TaskLog, conclusion: dict[str, Any], flags: set[str]) -> list[str]:
    """Return instructions for every enabled check a legitimate conclusion has not met."""
    if conclusion.get("hypothesis") != "legitimate":
        return []
    issues: list[str] = []
    if "host_window" in flags and log.alert_hosts:
        host_looked = bool(log.alert_hosts & log.expanded) or any(
            q.get("query") in log.alert_hosts or q.get("time_window") for q in log.searched_queries
        )
        if not host_looked:
            issues.append(
                "You have not looked at what else happened on the alerted host around the alert "
                "time. Search the host id with a tight time_window (or expand it with a relevant "
                "relation_type) before concluding legitimate."
            )
    if "inbound_sources" in flags:
        unread = sorted(
            {
                rel["source"]
                for rel in log.relations.values()
                if rel["type"] in INBOUND_TYPES
                and rel["target"] in log.alert_ids | log.alert_hosts
                and rel["source"] not in log.read_entities
            }
        )
        if unread:
            issues.append(
                "Inbound activity reached the alerted entity from sources you have not examined: "
                + ", ".join(unread[:5])
                + ". Read or expand them (who is on the other end; repeated or periodic attempts?) "
                "before concluding legitimate."
            )
    if "children" in flags:
        alerted_processes = log.alert_ids - log.alert_hosts
        if alerted_processes and not (alerted_processes & log.expanded):
            issues.append(
                "You have not expanded the alerted process itself (its children, written and "
                "executed files). Do that before concluding legitimate."
            )
    if "actor_mechanism" in flags:
        for key, role in (
            ("legit_actor_id", "legitimate actor"),
            ("launch_mechanism_id", "launch mechanism"),
        ):
            entity_id = conclusion.get(key)
            if not entity_id or entity_id not in log.read_entities:
                issues.append(
                    f"Name the {role} with an entity id you have actually observed "
                    f"(`{key}`), or investigate until you can."
                )
    return issues
