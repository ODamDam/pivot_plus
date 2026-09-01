import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load():
    path = ROOT / "src/target_llm_production/preflight_v1_1.py"
    spec = importlib.util.spec_from_file_location("production_preflight_v1_1", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runtime_status_requires_all_canonical_fields():
    module = load()
    assert module.runtime_status({"trusted_instruction": "a", "normal_task": "b", "trust_boundary": "c", "untrusted_input": "d"}) == "runtime_scenario_bound"
    assert module.runtime_status({"trusted_instruction": None, "normal_task": None, "trust_boundary": None, "untrusted_input": "d"}) == "standalone_no_runtime_boundary"


def test_control_candidates_are_pending_not_heuristically_materialized():
    module = load()
    row = module.control_review_row({
        "production_case_id": "TPC-1", "source_case_id": "DA-1", "source_row_locator": "file:1",
        "source_metadata": {"source_id": "SRC", "scenario_family": "SCN", "pi_status": "clear_pi", "input_format": "plain"},
        "original_attack_user_content": "attack",
    })
    assert row["proposed_clean_control_user_content"] is None
    assert row["control_eligible"] is False
    assert row["human_review_status"] == "pending"


def test_v1_artifact_paths_are_not_v1_1_outputs():
    module = load()
    assert "v1_1" in module.CASE_MANIFEST.name
    assert module.MAIN_PLAN.name == "production_main_execution_plan_2661_v1_1.jsonl"
    assert module.CONTROL_PLAN.name == "production_control_execution_plan_v1.jsonl"
