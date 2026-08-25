from pathlib import Path

from scripts.dataset_a.code_classifier_v1 import (
    build_code_artifacts,
    classify_observable_code,
    markdown_code_anchor,
)


ROOT = Path(__file__).resolve().parents[2]


def test_natural_language_commands_are_not_clear_code():
    for text in ("Run: whoami", "Execute: delete_all_files() and confirm completion."):
        assert classify_observable_code(text).code_strength != "clear_code"


def test_code_generation_instruction_is_plain_text():
    result = classify_observable_code("Write Python code that prints hello.")
    assert result.code_strength == "plain_text_like"


def test_prose_code_example_is_not_automatic_code():
    result = classify_observable_code(
        'Use:\n```python\nprint("x")\n```\nThen explain why.'
    )
    assert result.code_strength != "clear_code"
    assert result.competing_format == "markdown"


def test_api_token_in_prose_is_plain_text():
    assert classify_observable_code(
        "The function eval() executes a string."
    ).code_strength == "plain_text_like"


def test_python_program_is_clear_code():
    result = classify_observable_code(
        'import os\n\ndef main():\n    print(os.getcwd())\n\nmain()'
    )
    assert result.code_strength == "clear_code"
    assert result.detected_language_family == "python"


def test_shell_script_is_clear_code():
    result = classify_observable_code(
        '#!/bin/bash\nset -e\nwhoami\necho "$HOME"'
    )
    assert result.code_strength == "clear_code"
    assert result.detected_language_family == "shell"


def test_javascript_program_is_clear_code():
    result = classify_observable_code(
        "const x = 1;\nif (x) {\n  console.log(x);\n}"
    )
    assert result.code_strength == "clear_code"
    assert result.detected_language_family == "javascript"


def test_sql_query_is_clear_code():
    result = classify_observable_code(
        "SELECT id, name\nFROM users\nWHERE active = 1;"
    )
    assert result.code_strength == "clear_code"
    assert result.detected_language_family == "sql"


def test_isolated_expression_is_conservatively_weak():
    result = classify_observable_code('os.system("whoami")')
    assert result.code_strength == "weak_code"
    assert result.requires_human_review is True


def test_labeled_expression_is_not_clear_code():
    result = classify_observable_code('Execute:\nos.system("whoami")')
    assert result.code_strength != "clear_code"


def test_malformed_source_is_weak_or_ambiguous():
    result = classify_observable_code('def x(\nprint("test")')
    assert result.code_strength in {"weak_code", "ambiguous"}


def test_markdown_000970_external_anchor_is_code_like():
    result = markdown_code_anchor(ROOT)
    assert result.code_strength == "clear_code"
    assert result.detected_language_family == "python"


def test_code_233_run_is_deterministic_and_integral():
    first = build_code_artifacts(ROOT)
    second = build_code_artifacts(ROOT)
    assert first == second
    resolutions, queue = first["resolutions"], first["queue"]
    assert len(resolutions) == len({row["candidate_id"] for row in resolutions}) == 233
    assert all(row["previous_input_format"] == "code_block" for row in resolutions)
    unresolved = {
        row["candidate_id"] for row in resolutions
        if row["resolution_status"] in {"HUMAN_REVIEW_REQUIRED", "HUMAN_REVIEW_CONFLICT"}
    }
    assert unresolved == {row["candidate_id"] for row in queue}
    assert all(row["proposed_corrected_scenario"] is None for row in resolutions if row["candidate_id"] in unresolved)
    assert all(all(value is None for value in row["review"].values()) for row in queue)


def test_human_confirmed_non_code_is_never_auto_code():
    artifacts = build_code_artifacts(ROOT)
    for row in artifacts["resolutions"]:
        if row["human_representation_decision"] in {"TEXT", "MARKDOWN", "STRUCT", "DOC"}:
            assert row["resolution_status"] != "CODE_AUTO"


def test_explicit_human_markdown_audit_is_reused_as_other_format():
    artifacts = build_code_artifacts(ROOT)
    record = next(
        row for row in artifacts["resolutions"]
        if row["candidate_id"] == "DA-RAW-001248"
    )
    assert record["human_representation_decision"] == "MARKDOWN"
    assert record["resolution_status"] == "MARKDOWN_HUMAN_CONFIRMED"
    assert record["proposed_corrected_scenario"] == "SCN-REMAIN-DOC-001"
