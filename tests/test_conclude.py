from bluesec1_agent.conclude import TaskLog, unmet_checks

ALERT = {
    "trigger_entities": [
        {"id": "h1", "type": "host", "properties": {"hostname": "H1", "ip": "10.0.0.5"}},
        {"id": "p1", "type": "windows_process", "properties": {"image_path": "x.exe"}},
    ],
    "trigger_relations": [{"id": "r0", "type": "hosts", "source_id": "h1", "target_id": "p1"}],
}
LEGIT = {"hypothesis": "legitimate"}
FLAGS = {"host_window", "inbound_source", "effects"}


def test_quiet_process_requires_a_host_window_survey() -> None:
    log = TaskLog.from_alert(ALERT)
    log.record_call("expand_entity", {"entity_id": "p1"}, {"next_page_id": None})
    issues = unmet_checks(log, LEGIT, {"host_window"})
    assert len(issues) == 1 and "query = 'h1'" in issues[0]

    log.record_call("search", {"query": "h1", "time_window": {"from": "a", "to": "b"}}, {})
    assert unmet_checks(log, LEGIT, {"host_window"}) == []


def test_unread_effects_and_inbound_sources_are_flagged() -> None:
    log = TaskLog.from_alert(ALERT)
    log.record_call(
        "expand_entity",
        {"entity_id": "p1"},
        [
            {"next_page_id": None},
            {
                "results": [
                    {"id": "r1", "type": "wrote_file", "source_id": "p1", "target_id": "f1"},
                    {
                        "id": "r2",
                        "type": "accepted_connection_from",
                        "source_id": "c1",
                        "target_id": "p1",
                    },
                    {
                        "id": "c1",
                        "type": "network_connection",
                        "properties": {"src_ip": "10.9.9.9"},
                    },
                ]
            },
        ],
    )
    issues = unmet_checks(log, LEGIT, FLAGS)
    assert any("f1" in i for i in issues)
    assert any("10.9.9.9" in i for i in issues)

    log.record_call(
        "get_entity",
        {"entity_id": "f1"},
        {"id": "f1", "type": "windows_file", "properties": {"path": "p"}},
    )
    log.record_call("search", {"query": "10.9.9.9"}, {})
    assert unmet_checks(log, LEGIT, {"inbound_source", "effects"}) == []


def test_attack_conclusions_are_not_gated() -> None:
    log = TaskLog.from_alert(ALERT)
    assert unmet_checks(log, {"hypothesis": "attack"}, FLAGS) == []


def test_attack_conclusion_requires_examining_the_actor() -> None:
    """H-49: an attack conclusion without reading the acting account is sent back."""
    log = TaskLog.from_alert(ALERT)
    issues = unmet_checks(log, {"hypothesis": "attack"}, {"attack_actor"})
    assert len(issues) == 1 and "account" in issues[0]

    log.record_call(
        "get_entity",
        {"entity_id": "u1"},
        {"id": "u1", "type": "windows_user", "properties": {"username": "x"}},
    )
    assert unmet_checks(log, {"hypothesis": "attack"}, {"attack_actor"}) == []
    assert unmet_checks(TaskLog.from_alert(ALERT), {"hypothesis": "attack"}, FLAGS) == []
