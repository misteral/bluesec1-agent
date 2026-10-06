import json

from bluesec1_agent.guard import CallGuard, IdRegistry

ALERT = {
    "alert_description": "Process started",
    "trigger_entities": [
        {"id": "ent-host", "type": "host", "properties": {"hostname": "H1"}, "host_id": None},
        {"id": "ent-proc", "type": "windows_process", "properties": {"pid": 1}},
    ],
    "trigger_relations": [
        {"id": "rel-1", "type": "hosts", "source_id": "ent-host", "target_id": "ent-proc"}
    ],
}


def make_guard() -> CallGuard:
    """Guard primed with the alert, as the agent does at task start."""
    registry = IdRegistry()
    registry.learn(json.dumps(ALERT))
    return CallGuard(registry)


def test_registry_classifies_alert_ids_by_structure() -> None:
    """Entities, relations and relation endpoints get their kinds from the alert."""
    guard = make_guard()

    assert guard.registry.kind_of("ent-proc") == "entity"
    assert guard.registry.kind_of("ent-host") == "entity"
    assert guard.registry.kind_of("rel-1") == "relation"
    assert guard.registry.kind_of("unknown") is None


def test_guard_redirects_entity_id_passed_to_get_relation() -> None:
    """The exp-002 failure mode is answered locally with the correct call."""
    feedback = make_guard().check("get_relation", {"relation_id": "ent-proc", "reasoning": "x"})

    assert feedback is not None
    assert feedback["local_guard"] == "wrong_id_kind"
    assert "get_entity(entity_id='ent-proc')" in feedback["error"]


def test_guard_lets_unknown_and_matching_ids_through() -> None:
    """Only ids with a known, mismatching kind are blocked."""
    guard = make_guard()

    assert guard.check("get_entity", {"entity_id": "ent-proc", "reasoning": "x"}) is None
    assert guard.check("get_relation", {"relation_id": "rel-1", "reasoning": "x"}) is None
    assert guard.check("get_relation", {"relation_id": "unknown", "reasoning": "x"}) is None
    assert guard.check("finish_investigation", {"submission": {}}) is None


def test_guard_serves_repeats_from_cache_ignoring_reasoning() -> None:
    """A repeated call differs only by reasoning text and must not hit the runtime."""
    guard = make_guard()
    result = {"id": "ent-proc", "incoming_relation_ids": ["rel-2"], "outgoing_relation_ids": []}
    guard.remember(
        "get_entity",
        {"entity_id": "ent-proc", "reasoning": "first"},
        {"status": "ok", "result": result},
    )

    repeat = guard.check("get_entity", {"entity_id": "ent-proc", "reasoning": "second"})

    assert repeat is not None
    assert repeat["local_guard"] == "duplicate_call"
    assert repeat["result"] == result
    assert guard.registry.kind_of("rel-2") == "relation"
