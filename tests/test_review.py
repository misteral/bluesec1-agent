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


def test_dual_tier_gives_respond_and_forensic_rows_per_type() -> None:
    """Files get delete + observed; processes only observed; hosts only isolate."""
    from bluesec1_agent.review import dual_tier_artifacts

    book = make_book()
    book.learn({"id": "f1", "type": "windows_file", "properties": {"path": "x"}})

    rows = dual_tier_artifacts(["f1", "proc-1", "host-1"], book)

    assert {(r["entity_id"], r["kind"]) for r in rows} == {
        ("f1", "file_to_delete"),
        ("f1", "file_observed"),
        ("proc-1", "process_observed"),
        ("host-1", "host_to_isolate"),
    }


def test_payload_policy_adds_missing_tiers_and_caps_benign() -> None:
    """LLM payloads get missing tier rows; benign citations are capped."""
    from bluesec1_agent.review import apply_payload_policy

    book = make_book()
    book.learn({"id": "f1", "type": "windows_file", "properties": {"path": "x"}})
    malicious = {
        "verdict": "malicious",
        "ir_artifacts": [{"entity_id": "f1", "kind": "file_to_delete"}],
        "reasoning": "r",
    }
    shaped = apply_payload_policy(malicious, book)
    assert {(r["entity_id"], r["kind"]) for r in shaped["ir_artifacts"]} == {
        ("f1", "file_to_delete"),
        ("f1", "file_observed"),
    }

    benign = {
        "verdict": "benign",
        "legitimacy_evidence": [
            {"anchor": "entity", "entity_id": f"e{i}", "property_fields": list("abcdef")}
            for i in range(5)
        ],
    }
    capped = apply_payload_policy(benign, book)["legitimacy_evidence"]
    assert len(capped) == 3
    assert all(len(item["property_fields"]) == 4 for item in capped)


def test_payload_v2_drops_artifact_observed_and_orders_benign() -> None:
    """v2: no escape-hatch kind; alert entities first; at most one relation anchor."""
    from bluesec1_agent.review import apply_payload_policy

    book = make_book()
    malicious = {
        "verdict": "malicious",
        "ir_artifacts": [
            {"entity_id": "proc-1", "kind": "process_observed"},
            {"entity_id": "host-1", "kind": "artifact_observed"},
        ],
    }
    kinds = {r["kind"] for r in apply_payload_policy(malicious, book, v2=True)["ir_artifacts"]}
    assert "artifact_observed" not in kinds

    benign = {
        "verdict": "benign",
        "legitimacy_evidence": [
            {"anchor": "relation", "relation_id": "r1", "property_fields": []},
            {"anchor": "relation", "relation_id": "r2", "property_fields": []},
            {"anchor": "entity", "entity_id": "x1", "property_fields": ["a"]},
            {"anchor": "entity", "entity_id": "proc-1", "property_fields": ["cmdline"]},
        ],
    }
    shaped = apply_payload_policy(benign, book, v2=True, alert_ids=["proc-1"])
    items = shaped["legitimacy_evidence"]
    assert items[0]["entity_id"] == "proc-1"
    assert sum(i["anchor"] == "relation" for i in items) == 1


def test_endpoint_entities_are_valid_artifacts() -> None:
    """Files seen only as relation endpoints (never read) must not be rejected or dropped."""
    book = make_book()
    submission = {
        "verdict": "malicious",
        "ir_artifacts": [
            {"entity_id": "proc-1", "kind": "process_observed"},
            {"entity_id": "written-file", "kind": "file_observed"},
        ],
    }
    endpoints = {"written-file", "proc-1"}

    assert gate_issues(submission, book, {"rel-1"}, endpoints) == []
    kept = sanitize_submission(submission, book, {"rel-1"}, endpoints)["ir_artifacts"]
    assert {a["entity_id"] for a in kept} == {"proc-1", "written-file"}
