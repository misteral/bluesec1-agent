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
# Relation types that are network telemetry, not effects (soc-expert consultation 3, K1).
NETWORK_TYPES = {"connected_to", "accepted_connection_from", "sent_data_to", "received_data_from"}
EFFECT_TYPES = {"win_process_create", "wrote_file", "executed_script", "executed_file"}
MAX_FAILED_CONCLUDES = 2


@dataclass
class TaskLog:
    """What the agent did and saw in one task, for verifying a conclusion."""

    alert_ids: set[str]
    alert_hosts: set[str]
    host_terms: set[str] = field(default_factory=set)
    entity_ips: dict[str, set[str]] = field(default_factory=dict)
    more_pages: set[str] = field(default_factory=set)
    types: dict[str, str] = field(default_factory=dict)
    ad_lookups: int = 0
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
        for e in entities:
            if e.get("type") in HOST_TYPES:
                props = e.get("properties") or {}
                log.host_terms |= {e["id"]} | {
                    str(props[k]) for k in ("hostname", "ip") if props.get(k)
                }
        log.learn(alert)
        return log

    def record_call(self, tool: str, arguments: dict[str, Any], result: Any) -> None:
        if tool == "expand_entity":
            entity_id = arguments.get("entity_id", "")
            self.expanded.add(entity_id)
            page = result[0] if isinstance(result, list) and result else result
            if isinstance(page, dict) and page.get("next_page_id"):
                self.more_pages.add(entity_id)
            else:
                self.more_pages.discard(entity_id)
        elif tool == "search":
            self.searched_queries.append(arguments)
        elif tool == "get_entity":
            self.read_entities.add(arguments.get("entity_id", ""))
        elif tool == "get_ad_object_info":
            self.ad_lookups += 1
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
                    if isinstance(item.get("type"), str):
                        self.types[item["id"]] = item["type"]
                    ips = {
                        str(v)
                        for k, v in item["properties"].items()
                        if v and isinstance(v, str) and "ip" in k.lower()
                    }
                    if ips:
                        self.entity_ips[item["id"]] = ips
                stack.extend(v for v in item.values() if isinstance(v, dict | list))


def unmet_checks(log: TaskLog, conclusion: dict[str, Any], flags: set[str]) -> list[str]:
    """Return instructions for every enabled check a legitimate conclusion has not met.

    Flags from soc-expert consultation 3 (23 wrong-benign vs 127 correct-benign tasks):
    K1 `host_window` — alerted process changed nothing but network → survey the host in the
    alert window (caught 16/23, fired on 15/127); K2 `inbound_source` — inbound connections
    whose source IP was never searched (7/23, 8/127); K3 `effects` — the alerted process'
    effects not fully read (7/23, 16/127). Together 19/23 vs 29/127.
    """
    if conclusion.get("hypothesis") == "attack":
        return attack_checks(log, flags)
    if conclusion.get("hypothesis") != "legitimate":
        return []
    issues: list[str] = []
    processes = log.alert_ids - log.alert_hosts
    out_effects = [
        r
        for r in log.relations.values()
        if r["source"] in processes and r["type"] not in NETWORK_TYPES | {"hosts", "runs_process"}
    ]
    if "host_window" in flags and log.host_terms and (not processes or not out_effects):
        surveyed = any(
            q.get("query") in log.host_terms
            and q.get("time_window")
            and (q.get("scope") or {}).get("kind") != "relation"
            for q in log.searched_queries
        )
        if not surveyed:
            host = sorted(log.alert_hosts)[0] if log.alert_hosts else sorted(log.host_terms)[0]
            issues.append(
                "The alerted process itself changed nothing, so the alert points at the host and "
                "the time, not at this process. Before benign, call search with query = "
                f"{host!r}, a time_window of about ±30 min around the alert, sort_order = "
                "ascending; read 2 pages. Report any Office/browser/script → shell chain, "
                "downloaded or executed files, archiving, service or network changes on this "
                "host. Treat the same user's activity as related only if time and session match."
            )
    if "inbound_source" in flags:
        inbound_sources = {
            r["source"] if r["target"] in log.alert_ids | log.alert_hosts else r["target"]
            for r in log.relations.values()
            if r["type"] == "accepted_connection_from"
            and (
                r["target"] in log.alert_ids | log.alert_hosts
                or r["source"] in log.alert_ids | log.alert_hosts
            )
        }
        source_ips = (
            set().union(*(log.entity_ips.get(e, set()) for e in inbound_sources)) - log.host_terms
        )
        searched = {str(q.get("query")) for q in log.searched_queries}
        if inbound_sources and not (source_ips & searched):
            ips = ", ".join(sorted(source_ips)[:5]) or "the source IPs of those connections"
            issues.append(
                f"The alerted entity accepted inbound connections ({ips}). Identify the source: "
                "search the source IP without scope, then with scope "
                '{"kind": "relation", "type": "logged_on_to"} and a time_window around the alert. '
                "Look at logon outcomes (success/failure, error codes, accounts). A regular "
                "interval is not proof of monitoring: repeated failures from one source mean "
                "password guessing."
            )
    if "effects" in flags and processes:
        unexpanded = processes - log.expanded
        unread = sorted(
            {
                r["target"]
                for r in log.relations.values()
                if r["source"] in processes
                and r["type"] in EFFECT_TYPES
                and r["target"] not in log.read_entities
            }
        )
        paged = processes & log.more_pages
        if unexpanded or unread or paged:
            listed = ", ".join(unread[:8]) or ", ".join(sorted(unexpanded | paged))
            issues.append(
                f"You have not read all effects of the alerted process ({listed}). Read them "
                "(for more than 10 relations, search the process id with a relation-type "
                "scope). For every written or changed file decide: attacker tool, modified "
                "business data, or a normal work artefact? Benign only if every effect is "
                "explained."
            )
    return issues


ACCOUNT_TYPES = {"windows_user", "linux_user", "ad_object"}


def attack_checks(log: TaskLog, flags: set[str]) -> list[str]:
    """Checks for an attack conclusion (H-49, Claude profile).

    Claude models flagged powerful but authorised admin activity as attacks (exp-043/050 false
    positives: directory admin consoles, management-agent tasks, installers, IR collection
    tools) without checking who acted. `attack_actor`: before concluding attack, the acting
    account must have been examined (account entity or its directory object).
    """
    issues: list[str] = []
    if "attack_actor" in flags:
        account_read = any(t in ACCOUNT_TYPES for t in log.types.values()) or log.ad_lookups > 0
        if not account_read:
            issues.append(
                "Before concluding attack, examine the account that performed the activity: read "
                "its user entity or directory object (groups, description, role). Powerful admin "
                "actions by the expected admin or service account through the expected tooling "
                "are authorised activity, not an attack."
            )
    return issues
