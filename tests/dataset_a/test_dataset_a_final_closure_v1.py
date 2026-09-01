import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_review_and_template_cover_exact_queue_set():
    module = load("final_support", ROOT / "scripts/dataset_a/build_dataset_a_final_adjudication_support_v1.py")
    queue = module.read_jsonl(module.QUEUE)
    template = module.build_template(queue)
    assert len(queue) == len(template) == 49
    assert {row["candidate_id"] for row in queue} == {row["candidate_id"] for row in template}
    assert all(row["derived_class"] is None for row in template)
    assert all(row["final_pi_status"] is None for row in template)


def test_incomplete_template_is_not_valid_final_adjudication():
    module = load("final_validate", ROOT / "scripts/dataset_a/validate_dataset_a_final_adjudication_v1.py")
    queue = module.read_jsonl(module.QUEUE)
    template = load("final_support_2", ROOT / "scripts/dataset_a/build_dataset_a_final_adjudication_support_v1.py").build_template(queue)
    result = module.validate(queue, template, require_complete=True)
    assert result["complete_count"] == 0
    assert result["passed"] is False
    assert result["unresolved"] == 49


def test_derived_class_is_mechanical():
    module = load("final_derive", ROOT / "scripts/dataset_a/validate_dataset_a_final_adjudication_v1.py")
    assert module.derive("clear_pi", "malicious") == "pi_malicious"
    assert module.derive("context_dependent_pi", "non_malicious") == "pi_non_malicious"
    assert module.derive("not_pi", "malicious") == "non_pi_malicious"
    assert module.derive("ambiguous", "non_malicious") == "boundary_ambiguous"


def test_closure_refuses_incomplete_human_input(tmp_path):
    support = load("final_support_3", ROOT / "scripts/dataset_a/build_dataset_a_final_adjudication_support_v1.py")
    closure = load("final_closure", ROOT / "scripts/dataset_a/close_dataset_a_case_gt_v1.py")
    template = support.build_template(support.read_jsonl(support.QUEUE))
    path = tmp_path / "incomplete.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in template), encoding="utf-8")
    result = closure.preflight(path)
    assert result["passed"] is False
    assert result["unresolved"] == 49
