"""Local call guard: catch wasted tool calls before they reach the scored runtime.

Every platform tool call lowers the efficiency score, so calls that cannot succeed or that
repeat an earlier call are answered locally:
- an id whose kind is known (entity / relation / AD object) passed to the wrong getter;
- an exact repeat of an earlier call (served from cache).
"""

import json
from typing import Any, Literal

IdKind = Literal["entity", "relation", "ad_object"]

# Getter tool -> (argument name, id kind it expects).
GETTERS: dict[str, tuple[str, IdKind]] = {
    "get_entity": ("entity_id", "entity"),
    "get_relation": ("relation_id", "relation"),
    "get_ad_object_info": ("ad_object_id", "ad_object"),
}
TOOL_FOR_KIND: dict[IdKind, str] = {kind: tool for tool, (_, kind) in GETTERS.items()}
# Agent-side tools that take an id are checked like getters but never suggested as the fix.
GETTERS["expand_entity"] = ("entity_id", "entity")


def parse_jsonish(value: Any) -> Any:
    """Decode JSON strings, leaving other values unchanged."""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in ("{", "["):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                return value
    return value


class IdRegistry:
    """Remember the kind of every id seen in the alert and in tool results."""

    def __init__(self) -> None:
        """Start with no known ids."""
        self.kinds: dict[str, IdKind] = {}

    def kind_of(self, identifier: str) -> IdKind | None:
        """Return the known kind of an id, if any."""
        return self.kinds.get(identifier)

    def learn(self, value: Any) -> None:
        """Walk a decoded JSON value and record ids by their structural role.

        Relations carry `source_id`/`target_id`; entities carry `type` + `properties`;
        keys naming entity/relation/AD ids classify the values they hold.
        """
        value = parse_jsonish(value)
        if isinstance(value, list):
            for item in value:
                self.learn(item)
            return
        if not isinstance(value, dict):
            return
        identifier = value.get("id")
        if isinstance(identifier, str):
            if "source_id" in value and "target_id" in value:
                self._set(identifier, "relation")
            elif "properties" in value and "type" in value:
                self._set(identifier, "entity")
        for key, item in value.items():
            kind = self._kind_for_key(key)
            if kind is not None:
                for text in item if isinstance(item, list) else [item]:
                    if isinstance(text, str) and text:
                        self._set(text, kind)
            if isinstance(item, dict | list | str):
                self.learn(item)

    @staticmethod
    def _kind_for_key(key: str) -> IdKind | None:
        lowered = key.lower()
        if "ad_object_id" in lowered:
            return "ad_object"
        if lowered in ("source_id", "target_id", "host_id", "entity_id", "entity_ids"):
            return "entity"
        if lowered.endswith(("relation_id", "relation_ids")):
            return "relation"
        return None

    def _set(self, identifier: str, kind: IdKind) -> None:
        # First classification wins: a later, weaker key-based guess must not flip it.
        self.kinds.setdefault(identifier, kind)


class CallGuard:
    """Decide whether a tool call should be answered locally instead of sent."""

    def __init__(self, registry: IdRegistry) -> None:
        """Use a shared id registry and an empty call cache."""
        self.registry = registry
        self.cache: dict[str, dict[str, Any]] = {}

    @staticmethod
    def call_key(tool_name: str, arguments: dict[str, Any]) -> str:
        """Canonical cache key; free-text reasoning does not make a call different."""
        relevant = {key: value for key, value in arguments.items() if key != "reasoning"}
        return f"{tool_name}:{json.dumps(relevant, sort_keys=True, default=str)}"

    def check(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
        """Return local feedback for a call that must not reach the runtime, else None."""
        if tool_name == "finish_investigation":
            return None
        cached = self.cache.get(self.call_key(tool_name, arguments))
        if cached is not None:
            return {
                **cached,
                "local_guard": "duplicate_call",
                "note": "Identical call already made; this is the earlier result, served "
                "locally. Do not repeat calls — choose a different next step.",
            }
        getter = GETTERS.get(tool_name)
        if getter is None:
            return None
        argument, expected = getter
        identifier = arguments.get(argument)
        actual = self.registry.kind_of(identifier) if isinstance(identifier, str) else None
        if actual is None or actual == expected:
            return None
        right_tool = TOOL_FOR_KIND[actual]
        right_argument = GETTERS[right_tool][0]
        return {
            "status": "error",
            "local_guard": "wrong_id_kind",
            "error": (
                f"{identifier!r} is a {actual} id, not a {expected} id. "
                f"Use {right_tool}({right_argument}={identifier!r}) instead."
            ),
        }

    def remember(self, tool_name: str, arguments: dict[str, Any], feedback: dict[str, Any]) -> None:
        """Cache a runtime result and learn ids from it."""
        self.cache[self.call_key(tool_name, arguments)] = feedback
        self.registry.learn(feedback.get("result"))
        self.registry.learn(feedback.get("raw_result"))
        if feedback.get("status") == "ok":
            getter = GETTERS.get(tool_name)
            identifier = arguments.get(getter[0]) if getter else None
            if getter and isinstance(identifier, str):
                self.registry.kinds[identifier] = getter[1]
