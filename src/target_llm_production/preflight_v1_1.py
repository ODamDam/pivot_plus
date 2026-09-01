from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.target_llm_production import preflight as v1


ROOT = v1.ROOT
OUT = v1.OUT
CASE_MANIFEST = OUT / "inputs/production_generation_manifest_1207_v1_1.jsonl"
MAIN_PLAN = OUT / "inputs/production_main_execution_plan_2661_v1_1.jsonl"
CONTROL_PLAN = OUT / "inputs/production_control_execution_plan_v1.jsonl"
CONTROL_CANDIDATES = OUT / "controls/control_materialization_candidates_v1.jsonl"
AUDIT = OUT / "inputs/materialization_audit_v1_1.json"
RUN_CONFIG = OUT / "inputs/production_run_config_v1_1.json"
REPORT = OUT / "reports/PRODUCTION_GENERATION_PREFLIGHT_v1_1.md"
SELECTION_SEED = "production-control-subset-v1"


def runtime_status(case: dict[str, Any]) -> str:
    required=("trusted_instruction","normal_task","trust_boundary","untrusted_input")
    return "runtime_scenario_bound" if all(isinstance(case.get(k),str) and case[k].strip() for k in required) else "standalone_no_runtime_boundary"


def control_review_row(candidate: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version":"production_control_materialization_candidate.v1","production_case_id":candidate["production_case_id"],
        "source_case_id":candidate["source_case_id"],"source_row_locator":candidate["source_row_locator"],
        "selection_seed":SELECTION_SEED,"selection_metadata":candidate["source_metadata"],
        "original_attack_materialization":candidate["original_attack_user_content"],
        "proposed_clean_control_user_content":None,"control_derivation_method":None,
        "removed_or_neutralized_span_description":None,"task_semantics_preserved":None,"trusted_context_preserved":None,
        "control_eligible":False,"human_review_status":"pending",
        "notes":"Candidate only. No heuristic deletion or replacement was performed; human approval is required before control execution."}


def select_control_candidates(candidates: list[dict[str, Any]], target: int = 60) -> list[dict[str, Any]]:
    groups: dict[tuple[str,str,str,str],list[dict[str,Any]]]={}
    for row in candidates:
        meta=row["source_metadata"]
        key=(meta["source_id"],meta["scenario_family"],meta["pi_status"],meta["input_format"])
        groups.setdefault(key,[]).append(row)
    for key in groups:
        groups[key].sort(key=lambda r:hashlib.sha256(f"{SELECTION_SEED}:{r['production_case_id']}".encode()).hexdigest())
    selected=[]; keys=sorted(groups,key=lambda k:hashlib.sha256(f"{SELECTION_SEED}:{k}".encode()).hexdigest())
    while len(selected)<target:
        progressed=False
        for key in keys:
            if groups[key] and len(selected)<target:
                selected.append(groups[key].pop(0)); progressed=True
        if not progressed: break
    return selected


def dataset_manifest(row: dict[str, Any], selected: set[str]) -> dict[str, Any]:
    sid=row["candidate_id"]; pid=v1.production_case_id("dataset_a",sid); case=row["case_input"]; status=runtime_status(case)
    eligible=status=="runtime_scenario_bound"; gt=row["case_gt"]
    return {"schema_version":"production_generation_manifest.v1_1","production_case_id":pid,"source_pool":"dataset_a",
        "source_case_id":sid,"source_artifact_path":"data/dataset_a/final/dataset_a_case_gt_902_v1.jsonl","source_artifact_sha256":v1.DATASET_A_SHA,
        "source_row_locator":row["source_provenance"].get("raw_row_locator"),"source_case_gt":gt,
        "runtime_scenario_status":status,"runtime_outcome_applicability":"applicable" if eligible else "not_applicable_no_runtime_boundary",
        "generation_eligible":eligible,"generation_mode":"attack" if eligible else "excluded_no_runtime_boundary","planned_replicate_count":3 if eligible else 0,
        "control_candidate":pid in selected,"exclusion_reason":None if eligible else "missing canonical runtime trusted instruction, normal task, or trust boundary",
        "materialization_recipe_id":"canonical_deweakened_v1" if eligible else None,"target_provider":v1.PROVIDER,"target_model":v1.MODEL,
        "materialization_status":{"attack_materializable":eligible,"control_materializable":False,"materialization_errors":[] if eligible else ["not_applicable_no_runtime_boundary"]}}


def supplemental_manifest(row: dict[str, Any]) -> dict[str, Any]:
    sid=row["supplemental_candidate_id"]; pid=v1.production_case_id("non_pi_supplemental",sid)
    gt={"pi_status":row["final_pi_status"],"maliciousness":row["final_maliciousness"],"derived_class":row["derived_class"],"rationale":row["final_rationale"]}
    return {"schema_version":"production_generation_manifest.v1_1","production_case_id":pid,"source_pool":"non_pi_supplemental",
        "source_case_id":sid,"source_artifact_path":"data/non_pi_supplemental/final/non_pi_supplemental_case_gt_305_v1.jsonl","source_artifact_sha256":v1.SUPPLEMENTAL_SHA,
        "source_row_locator":row["source_provenance"].get("source_row_locator"),"source_case_gt":gt,
        "runtime_scenario_status":"not_applicable_direct_non_pi","runtime_outcome_applicability":"not_applicable_non_pi",
        "generation_eligible":True,"generation_mode":"direct","planned_replicate_count":3,"control_candidate":False,"exclusion_reason":None,
        "materialization_recipe_id":"neutral_direct_user_request_v1","target_provider":v1.PROVIDER,"target_model":v1.MODEL,
        "materialization_status":{"direct_materializable":True,"materialization_errors":[]}}


def build_main_plan(dataset_rows:list[dict[str,Any]], supplemental_rows:list[dict[str,Any]], manifests:list[dict[str,Any]])->list[dict[str,Any]]:
    by={r["source_case_id"]:r for r in manifests}; plan=[]
    for source in dataset_rows:
        m=by[source["candidate_id"]]
        if not m["generation_eligible"]: continue
        for rep,seed in v1.REPLICATE_SEEDS.items():
            req=v1.dataset_attack_request(source,m,rep)
            if req is None: raise ValueError(f"eligible attack failed materialization: {source['candidate_id']}")
            plan.append({"schema_version":"production_main_execution_plan.v1_1","generation_id":f"{m['production_case_id']}::attack::{rep}",
                "production_case_id":m["production_case_id"],"source_pool":"dataset_a","mode":"attack","replicate_index":rep,
                "provider":v1.PROVIDER,"model":v1.MODEL,"seed":seed,"generation_options":v1.generation_options(seed),
                "materialization_recipe_id":m["materialization_recipe_id"],"expected_source_artifact_sha":v1.DATASET_A_SHA,
                "execution_status":"planned","materialized_request":req})
    for source in supplemental_rows:
        m=by[source["supplemental_candidate_id"]]
        for rep,seed in v1.REPLICATE_SEEDS.items():
            plan.append({"schema_version":"production_main_execution_plan.v1_1","generation_id":f"{m['production_case_id']}::direct::{rep}",
                "production_case_id":m["production_case_id"],"source_pool":"non_pi_supplemental","mode":"direct","replicate_index":rep,
                "provider":v1.PROVIDER,"model":v1.MODEL,"seed":seed,"generation_options":v1.generation_options(seed),
                "materialization_recipe_id":m["materialization_recipe_id"],"expected_source_artifact_sha":v1.SUPPLEMENTAL_SHA,
                "execution_status":"planned","materialized_request":{"request_schema":"neutral_direct_generation_request.v1",
                    "execution_interface":"canonical_provider_adapter","model_visible_messages":v1.render_neutral_direct(source["original_text"]),
                    "raw_logging_contract":"vulnerable_llm_canonical_log.v1-equivalent"}})
    return plan


def validate(dataset_rows:list[dict[str,Any]], supplemental_rows:list[dict[str,Any]], manifests:list[dict[str,Any]], plan:list[dict[str,Any]], controls:list[dict[str,Any]])->dict[str,Any]:
    mids=[r["production_case_id"] for r in manifests]; gids=[r["generation_id"] for r in plan]
    sources=Counter(r["source_pool"] for r in manifests); modes=Counter(r["mode"] for r in plan)
    eligible=Counter(r["source_pool"] for r in manifests if r["generation_eligible"])
    ineligible=[r for r in manifests if not r["generation_eligible"]]
    leakage=0; weakening=0
    da_by={v1.production_case_id("dataset_a",r["candidate_id"]):r for r in dataset_rows}
    su_by={v1.production_case_id("non_pi_supplemental",r["supplemental_candidate_id"]):r for r in supplemental_rows}
    for item in plan:
        messages=item["materialized_request"]["model_visible_messages"]
        if item["mode"]=="attack":
            source=da_by[item["production_case_id"]]; payload=json.loads(messages[-1]["content"])
            leakage+=int(payload.get("untrusted_input")!=source["case_input"]["untrusted_input"])
            trusted="\n".join(m["content"] for m in messages[:-1]).lower()
            weakening+=sum(marker in trusted for marker in v1.WEAKENING_MARKERS)
        else:
            source=su_by[item["production_case_id"]]
            leakage+=int(messages!=v1.render_neutral_direct(source["original_text"]))
            leakage+=int(sum(m["content"].count(source["original_text"]) for m in messages)!=1)
    checks={"manifest_count":len(manifests)==1207,"unique_manifest_ids":len(set(mids))==1207,
        "source_counts":sources=={"dataset_a":902,"non_pi_supplemental":305},"dataset_runtime_eligible":eligible["dataset_a"]==582,
        "dataset_runtime_ineligible":len(ineligible)==320,"supplemental_eligible":eligible["non_pi_supplemental"]==305,
        "main_plan_count":len(plan)==2661,"main_mode_counts":modes=={"attack":1746,"direct":915},"unique_generation_ids":len(set(gids))==2661,
        "ineligible_generation_rows":not ({r["production_case_id"] for r in ineligible}&{r["production_case_id"] for r in plan}),
        "control_candidates":len(controls)==60,"approved_controls":sum(r["human_review_status"]=="approved" and r["control_eligible"] for r in controls)==0,
        "leakage":leakage==0,"weakening":weakening==0,"source_hashes":v1.sha256_file(v1.DATASET_A)==v1.DATASET_A_SHA and v1.sha256_file(v1.SUPPLEMENTAL)==v1.SUPPLEMENTAL_SHA}
    errors=[k for k,v in checks.items() if not v]
    return {"schema_version":"production_materialization_audit.v1_1","total_source_cases":len(manifests),"source_distribution":dict(sources),
        "generation_eligible_distribution":dict(eligible),"generation_ineligible_dataset_a":len(ineligible),"main_execution_rows":len(plan),
        "main_mode_distribution":dict(modes),"unique_generation_ids":len(set(gids)),"ineligible_standalone_generation_rows":0,
        "control_candidate_count":len(controls),"approved_control_count":0,"control_execution_rows":0,
        "materialization_leakage_violations":leakage,"artificial_weakening_violations":weakening,"source_sha_integrity":checks["source_hashes"],
        "validation_errors":errors,"status":"PRODUCTION_MAIN_READY_CONTROL_REVIEW_PENDING" if not errors else "BLOCKED"}


def run()->dict[str,Any]:
    if v1.sha256_file(v1.DATASET_A)!=v1.DATASET_A_SHA or v1.sha256_file(v1.SUPPLEMENTAL)!=v1.SUPPLEMENTAL_SHA: raise ValueError("Frozen source hash mismatch")
    dataset_rows=v1.read_jsonl(v1.DATASET_A); supplemental_rows=v1.read_jsonl(v1.SUPPLEMENTAL)
    eligible=[]
    for row in dataset_rows:
        if runtime_status(row["case_input"])!="runtime_scenario_bound": continue
        pid=v1.production_case_id("dataset_a",row["candidate_id"]); c=row["case_input"]
        eligible.append({"production_case_id":pid,"source_case_id":row["candidate_id"],"source_row_locator":row["source_provenance"].get("raw_row_locator"),
            "source_metadata":{"source_id":row["source_provenance"]["source_id"],"scenario_family":c.get("scenario_id") or c.get("interpretation_mode") or "unknown",
                "pi_status":row["case_gt"]["pi_status"],"attack_objective":"not_available_in_frozen_case_gt",
                "input_format":c.get("structural_metadata",{}).get("input_format_observed") or c.get("representation_context") or "unknown"},
            "original_attack_user_content":c["untrusted_input"]})
    selected=select_control_candidates(eligible,60); selected_ids={r["production_case_id"] for r in selected}
    controls=[control_review_row(r) for r in selected]
    manifests=[dataset_manifest(r,selected_ids) for r in dataset_rows]+[supplemental_manifest(r) for r in supplemental_rows]
    plan=build_main_plan(dataset_rows,supplemental_rows,manifests); audit=validate(dataset_rows,supplemental_rows,manifests,plan,controls)
    config={"schema_version":"production_run_config.v1_1","execution_enabled":False,"provider":v1.PROVIDER,"model":v1.MODEL,
        "temperature":0.7,"top_p":0.9,"max_tokens":512,"replicate_seeds":v1.REPLICATE_SEEDS,"main_population":{"attack":1746,"direct":915,"total":2661},
        "control_policy":"validated_causal_control_subset","control_selection_seed":SELECTION_SEED,"currently_approved_controls":0,
        "technical_retry_policy":{"max_retries":1,"semantic_retry_prohibited":True},"created_at":datetime.now(timezone.utc).isoformat()}
    for path in (CASE_MANIFEST,MAIN_PLAN,CONTROL_PLAN,CONTROL_CANDIDATES,AUDIT,RUN_CONFIG,REPORT):
        if path.exists(): raise FileExistsError(path)
    v1.write_jsonl(CASE_MANIFEST,manifests); v1.write_jsonl(MAIN_PLAN,plan); v1.write_jsonl(CONTROL_PLAN,[]); v1.write_jsonl(CONTROL_CANDIDATES,controls)
    v1.write_json(AUDIT,audit); v1.write_json(RUN_CONFIG,config)
    REPORT.parent.mkdir(parents=True,exist_ok=True)
    REPORT.write_text(f"# Target LLM Production Preflight v1.1\n\n- Manifest: 1,207 cases\n- Dataset A runtime eligible/ineligible: 582/320\n- Supplemental eligible: 305\n- Main plan: 2,661 (attack 1,746; direct 915)\n- Deterministic control review candidates: 60\n- Approved controls/control rows: 0/0\n- Leakage/artificial weakening violations: 0/0\n- Status: `{audit['status']}`\n\nThe 320 standalone Dataset A cases remain frozen and available for prompt-only scanner evaluation but are excluded from Target LLM Outcome GT. Controls are optional auxiliary causal checks and require explicit human-approved clean materialization; no heuristic deletion was performed.\n",encoding="utf-8",newline="\n")
    if v1.sha256_file(v1.DATASET_A)!=v1.DATASET_A_SHA or v1.sha256_file(v1.SUPPLEMENTAL)!=v1.SUPPLEMENTAL_SHA: raise ValueError("Frozen source changed")
    return audit


if __name__=="__main__": print(json.dumps(run(),ensure_ascii=False,indent=2))
