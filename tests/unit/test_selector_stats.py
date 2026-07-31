from __future__ import annotations

import json

from src.core.selector_stats import OperatorStatsByBucket, OperatorStatsByScope


def test_scope_stats_update_counts_scores_and_isolate_scopes() -> None:
    stats = OperatorStatsByScope()
    stats.report_result("plain_text:instruction_override", "op_x", "PASS", 1.5)
    stats.report_result("plain_text:instruction_override", "op_x", "FAIL", -0.5)
    stats.report_result("json:tool_manipulation", "op_x", "UNKNOWN", None)

    primary = stats.get("plain_text:instruction_override", "op_x")
    other = stats.get("json:tool_manipulation", "op_x")
    assert primary is not None and other is not None
    assert (primary.n, primary.n_pass, primary.n_fail, primary.n_unknown) == (2, 1, 1, 0)
    assert primary.pass_rate == 0.5
    assert primary.n_score == 2
    assert primary.avg_oracle_score == 0.5
    assert (other.n, other.n_unknown) == (1, 1)


def test_scope_stats_normalize_bad_inputs_and_dump_scope_schema(tmp_path) -> None:
    stats = OperatorStatsByScope()
    stats.report_result("scope-a", "op_y", {"unexpected": True}, "not-a-number")
    output = tmp_path / "stats.json"
    stats.dump_json(str(output))

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "operator_stats_by_scope.v1"
    row = payload["stats"]["scope-a"]["op_y"]
    assert row["n"] == 1
    assert row["n_unknown"] == 1
    assert row["n_score"] == 0


def test_bucket_name_remains_a_compatibility_alias() -> None:
    assert OperatorStatsByBucket is OperatorStatsByScope
