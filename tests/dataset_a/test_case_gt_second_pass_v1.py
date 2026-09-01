import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def test_second_pass_id_is_stable_and_namespaced():
    module=load("sp_blind",ROOT/"scripts/dataset_a/build_case_gt_second_pass_blind_v1.py")
    assert module.second_pass_id("A")==module.second_pass_id("A")
    assert module.second_pass_id("A")!=module.second_pass_id("B")
    assert module.second_pass_id("A").startswith("CGT-SP-")


def test_leak_detector_checks_metadata_keys_not_semantic_values():
    module=load("sp_leak",ROOT/"scripts/dataset_a/build_case_gt_second_pass_blind_v1.py")
    assert module.leaked_keys({"untrusted_input":"discuss first pass attacks"})==set()
    assert module.leaked_keys({"selection_reasons":[]})=={"selection_reasons"}


def test_frozen_second_pass_has_197_valid_blind_ids_and_no_metadata_leakage():
    blind_module=load("sp_blind_actual",ROOT/"scripts/dataset_a/build_case_gt_second_pass_blind_v1.py")
    review=load("sp_review",ROOT/"scripts/dataset_a/run_case_gt_independent_second_pass_v1.py")
    inputs=review.read_jsonl(review.INPUT);outputs=review.read_jsonl(review.OUTPUT)
    assert len(inputs)==len(outputs)==197
    assert review.validate(inputs,outputs)==[]
    assert all(not blind_module.leaked_keys(row) for row in inputs)
    assert all(not review.leaked_keys(row) for row in outputs)


def test_second_pass_derivation_is_mechanical():
    module=load("sp_derive",ROOT/"scripts/dataset_a/run_case_gt_independent_second_pass_v1.py")
    assert module.derived("clear_pi","malicious")=="pi_malicious"
    assert module.derived("context_dependent_pi","non_malicious")=="pi_non_malicious"
    assert module.derived("not_pi","malicious")=="non_pi_malicious"
    assert module.derived("ambiguous","non_malicious")=="boundary_ambiguous"


def test_kappa_and_agreement_category_helpers():
    module=load("sp_agree",ROOT/"scripts/dataset_a/analyze_case_gt_second_pass_agreement_v1.py")
    assert module.kappa(["a","b"],["a","b"])==1.0
    first={"case_gt":{"pi_status":"clear_pi","maliciousness":"malicious","derived_class":"pi_malicious"}}
    second={"case_gt":{"pi_status":"context_dependent_pi","maliciousness":"malicious","derived_class":"pi_malicious"}}
    assert module.category(first,second)=="pi_status_disagreement"


def test_blind_projection_preserves_original_semantics_exactly():
    module=load("sp_semantics",ROOT/"scripts/dataset_a/build_case_gt_second_pass_blind_v1.py")
    original={r["adjudication_id"]:r for r in module.read_jsonl(module.BLIND_SOURCE)}
    projected=module.read_jsonl(module.OUTPUT)
    for row in projected:
        case=original[row["adjudication_id"]]["case_input"]
        assert row["trusted_instruction"]==case.get("trusted_instruction")
        assert row["normal_task"]==case.get("normal_task")
        assert row["trust_boundary"]==case.get("trust_boundary")
        assert row["untrusted_input"]==case.get("untrusted_input")


def test_agreement_join_and_final_queue_partition_invariants():
    analyzer=load("sp_analysis_actual",ROOT/"scripts/dataset_a/analyze_case_gt_second_pass_agreement_v1.py")
    summary=json.loads((analyzer.REPORT/"agreement_summary_v1.json").read_text(encoding="utf-8"))
    disagreements=analyzer.read_jsonl(analyzer.REPORT/"disagreement_records_v1.jsonl")
    queue=analyzer.read_jsonl(analyzer.FINAL/"disagreement_queue_v1.jsonl")
    agreements=analyzer.read_jsonl(analyzer.FINAL/"agreement_manifest_v1.jsonl")
    assert summary["overall"]["count"]==197
    assert summary["edge_119"]["count"]==119
    assert summary["qc_78"]["count"]==78
    assert len(disagreements)==summary["disagreement_record_count"]
    assert len(queue)==summary["final_adjudication_queue_count"]
    assert len(agreements)==summary["agreement_manifest_count"]
    assert len(queue)+len(agreements)==197
    queue_ids={r["adjudication_id"] for r in queue}
    assert {r["adjudication_id"] for r in disagreements}<=queue_ids
    assert queue_ids.isdisjoint({r["adjudication_id"] for r in agreements})


def test_v1_1_queue_contains_only_gt_disagreements_and_adjudication_context():
    builder=load("sp_queue_v1_1",ROOT/"scripts/dataset_a/build_case_gt_disagreement_queue_v1_1.py")
    queue=builder.build_rows()
    assert len(queue)==49
    assert len({row["candidate_id"] for row in queue})==49
    assert all(row["disagreement_fields"] for row in queue)
    assert all("original_adjudication_input" in row for row in queue)
    assert all("source" in row and "scenario" in row for row in queue)
    assert all(row["selection_provenance"]["selection_group"] in {"edge_case","qc_random_sample"} for row in queue)
    for row in queue:
        expected=[]
        for field in ("pi_status","maliciousness","derived_class"):
            if row["first_pass"][field]!=row["second_pass"][field]: expected.append(field)
        assert row["disagreement_fields"]==expected
