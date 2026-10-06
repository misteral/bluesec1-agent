from bluesec1_agent.review import EntityBook, gate_issues, sanitize_submission

RESULT = {
    "id": "proc-1",
    "type": "windows_process",
    "properties": {"image_path": "C:\\x.exe", "cmdline": "x.exe -enc AAA", "signer": None},
    "relation_ids": {"incoming": ["rel-1"], "outgoing": []},
}


def make_book() -> EntityBook:
    """Book with one observed process and the alert host."""
    book = EntityBook()
    book.learn(
        {"trigger_entities": [{"id": "host-1", "type": "host", "properties": {"hostname": "H"}}]}
    )
    book.learn(RESULT)
    return book


def test_book_records_type_label_and_set_fields() -> None:
    """Entities are catalogued with a readable label and only non-null fields."""
    book = make_book()

    assert book.entities["proc-1"]["type"] == "windows_process"
    assert "C:\\x.exe" in book.entities["proc-1"]["label"]
    assert book.entities["proc-1"]["fields"] == ["cmdline", "image_path"]
    assert {e["entity_id"] for e in book.catalogue()} == {"host-1", "proc-1"}


def test_gates_flag_kind_mismatch_unknown_ids_and_duplicates() -> None:
    """Malicious payload problems are reported before the runtime sees them."""
    submission = {
        "verdict": "malicious",
        "ir_artifacts": [
            {"entity_id": "proc-1", "kind": "host_to_isolate"},
            {"entity_id": "host-1", "kind": "host_to_isolate"},
            {"entity_id": "host-1", "kind": "host_to_isolate"},
            {"entity_id": "rel-1", "kind": "other"},
            {"entity_id": "ghost", "kind": "other"},
        ],
    }
    issues = gate_issues(submission, make_book(), {"rel-1", "proc-1", "host-1"})

    assert any("does not fit windows_process" in issue for issue in issues)
    assert any("Duplicate artifact host-1" in issue for issue in issues)
    assert any("'rel-1' is a relation id" in issue for issue in issues)
    assert any("'ghost' is never observed" in issue for issue in issues)


def test_sanitize_drops_unobserved_and_unset_fields_but_never_empties() -> None:
    """Only provably wrong parts are removed."""
    book = make_book()
    malicious = {
        "verdict": "malicious",
        "ir_artifacts": [
            {"entity_id": "proc-1", "kind": "process_observed"},
            {"entity_id": "proc-1", "kind": "process_observed"},
            {"entity_id": "ghost", "kind": "other"},
        ],
    }
    benign = {
        "verdict": "benign",
        "legitimacy_evidence": [
            {"anchor": "entity", "entity_id": "proc-1", "property_fields": ["cmdline", "signer"]}
        ],
    }
    only_ghost = {"verdict": "malicious", "ir_artifacts": [{"entity_id": "ghost", "kind": "other"}]}

    assert sanitize_submission(malicious, book, set())["ir_artifacts"] == [
        {"entity_id": "proc-1", "kind": "process_observed"}
    ]
    assert sanitize_submission(benign, book, set())["legitimacy_evidence"][0][
        "property_fields"
    ] == ["cmdline"]
    assert sanitize_submission(only_ghost, book, set()) == only_ghost
