#!/usr/bin/env python3
"""Materialize, validate, and freeze Non-PI Supplemental Pool v1."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POOL = ROOT / "data/non_pi_supplemental/candidate_pool/non_pi_supplemental_candidates_v1_1.jsonl"
FIRST = ROOT / "data/non_pi_supplemental/adjudication/first_pass/non_pi_supplemental_first_pass_305_v1.jsonl"
SECOND = ROOT / "data/non_pi_supplemental/adjudication/second_pass/blind_second_pass_results_34_v1.jsonl"
FROZEN_A = ROOT / "data/dataset_a/final/dataset_a_case_gt_902_v1.jsonl"
FINAL = ROOT / "data/non_pi_supplemental/final/non_pi_supplemental_case_gt_305_v1.jsonl"
SNAPSHOT = ROOT / "data/non_pi_supplemental/freeze/non_pi_supplemental_freeze_v1.json"
REPORT_DIR = ROOT / "reports/non_pi_supplemental/final_closure_v1"
REPORT = REPORT_DIR / "NON_PI_SUPPLEMENTAL_CLOSURE_REPORT_v1.md"
VALIDATION = REPORT_DIR / "non_pi_supplemental_validation_v1.json"
POOL_SHA = "8123cc5f88cc043a1b58814307644369fd6f4f6a1ad7d794905f151afaf3f050"
FIRST_SHA = "51191e9fbc982c60b5a606dc062ff65481aebcde548892c8de716ee12f71f822"
SECOND_SHA = "df136f0a91568959d5b542f7542f836778ea5609cf272f9b1cdc4cfc628a658a"
FROZEN_A_SHA = "6cf89b6746491fadc404982f85118fbcc99bcefbc0219a5406c1d800967bcf9b"
ALLOWED_SOURCE_IDS = {"NPS-SRC-XSTEST", "NPS-SRC-JBB-ORIGINAL"}


def sha(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path: Path) -> list[dict[str, Any]]: return [json.loads(x) for x in path.open(encoding="utf-8") if x.strip()]


def derive(pi: str, mal: str) -> str:
    if pi == "out_of_scope": return "out_of_scope"
    if pi == "ambiguous" or mal in {"ambiguous", "not_applicable"}: return "boundary_ambiguous"
    if pi in {"clear_pi", "context_dependent_pi"}: return "pi_malicious" if mal == "malicious" else "pi_non_malicious"
    if pi == "not_pi": return "non_pi_malicious" if mal == "malicious" else "non_pi_non_malicious"
    raise ValueError((pi, mal))


def materialize(candidate: dict[str, Any], first: dict[str, Any], second: dict[str, Any] | None) -> dict[str, Any]:
    decision = second or first
    if second and any(first[field] != second[field] for field in ("pi_status", "maliciousness", "derived_class")):
        raise ValueError(f"Unresolved disagreement: {candidate['supplemental_candidate_id']}")
    return {
        "schema_version": "non_pi_supplemental_case_gt_final.v1",
        "supplemental_candidate_id": candidate["supplemental_candidate_id"],
        "original_text": candidate["original_text"],
        "final_pi_status": decision["pi_status"], "final_maliciousness": decision["maliciousness"],
        "derived_class": derive(decision["pi_status"], decision["maliciousness"]),
        "final_rationale": decision["rationale"], "confidence": decision["confidence"],
        "source_provenance": {key: candidate.get(key) for key in (
            "source_id", "source_name", "source_repo", "pinned_revision", "source_file",
            "source_row_locator", "source_record_id", "raw_file_sha256", "upstream_source")},
        "source_metadata": candidate.get("original_source_label_category"),
        "license": {"license_id": candidate["license_id"], "license_evidence": candidate["license_evidence"],
                    "redistribution_status": candidate["redistribution_status"]},
        "adjudication_provenance": {"contract_version": "GT Adjudication Contract v2",
            "resolution": "first_second_agreement" if second else "validated_high_confidence_first_pass",
            "first_pass_adjudicator": first["adjudicator"],
            "second_pass_adjudicator": second["adjudicator"] if second else None},
    }


def run() -> dict[str, Any]:
    expected=((POOL,POOL_SHA),(FIRST,FIRST_SHA),(SECOND,SECOND_SHA),(FROZEN_A,FROZEN_A_SHA))
    if any(sha(path)!=digest for path,digest in expected): raise ValueError("Canonical parent hash mismatch")
    if any(path.exists() for path in (FINAL,SNAPSHOT,REPORT,VALIDATION)): raise FileExistsError("Refusing to overwrite freeze artifacts")
    pool,first,second=read(POOL),read(FIRST),read(SECOND)
    pids=[r["supplemental_candidate_id"] for r in pool]
    f={r["supplemental_candidate_id"]:r for r in first}; s={r["supplemental_candidate_id"]:r for r in second}
    if len(pool)!=305 or len(set(pids))!=305 or set(pids)!=set(f) or len(s)!=34 or not set(s)<=set(pids): raise ValueError("Parent ID invariant failed")
    rows=[materialize(candidate,f[candidate["supplemental_candidate_id"]],s.get(candidate["supplemental_candidate_id"])) for candidate in pool]
    ids=[r["supplemental_candidate_id"] for r in rows]
    pi=Counter(r["final_pi_status"] for r in rows); mal=Counter(r["final_maliciousness"] for r in rows); derived=Counter(r["derived_class"] for r in rows)
    sources=Counter(r["source_provenance"]["source_id"] for r in rows); licenses=Counter(r["license"]["license_id"] for r in rows)
    errors=[]
    if len(rows)!=305 or len(set(ids))!=305: errors.append("row_or_id_count")
    if set(ids)!=set(pids): errors.append("id_set")
    if pi!={"not_pi":305}: errors.append(f"pi_distribution:{pi}")
    if mal!={"non_malicious":254,"malicious":51}: errors.append(f"mal_distribution:{mal}")
    if derived!={"non_pi_non_malicious":254,"non_pi_malicious":51}: errors.append(f"derived_distribution:{derived}")
    for index,row in enumerate(rows):
        if row["final_pi_status"] not in {"clear_pi","context_dependent_pi","not_pi","ambiguous","out_of_scope"}: errors.append(f"{index}:pi_enum")
        if row["final_maliciousness"] not in {"malicious","non_malicious","ambiguous","not_applicable"}: errors.append(f"{index}:mal_enum")
        if row["derived_class"]!=derive(row["final_pi_status"],row["final_maliciousness"]): errors.append(f"{index}:derived")
        if not all(row["source_provenance"].get(k) is not None for k in ("source_id","source_repo","pinned_revision","source_file","source_row_locator","raw_file_sha256")): errors.append(f"{index}:provenance")
        if row["license"]["redistribution_status"]!="redistribution_approved_with_attribution": errors.append(f"{index}:license")
        if row["source_provenance"]["source_id"] not in ALLOWED_SOURCE_IDS: errors.append(f"{index}:blocked_source")
    validation={"schema_version":"non_pi_supplemental_freeze_validation.v1","rows":len(rows),"unique_ids":len(set(ids)),
                "unresolved":sum(r["final_pi_status"] in {"ambiguous","out_of_scope"} or r["final_maliciousness"] in {"ambiguous","not_applicable"} for r in rows),
                "pi_status_distribution":dict(sorted(pi.items())),"maliciousness_distribution":dict(sorted(mal.items())),
                "derived_class_distribution":dict(sorted(derived.items())),"source_distribution":dict(sorted(sources.items())),
                "license_distribution":dict(sorted(licenses.items())),"provenance_coverage":sum(bool(r["source_provenance"]["source_row_locator"]) for r in rows),
                "license_approved_coverage":sum(r["license"]["redistribution_status"]=="redistribution_approved_with_attribution" for r in rows),
                "blocked_source_contamination":sum(r["source_provenance"]["source_id"] not in ALLOWED_SOURCE_IDS for r in rows),
                "enum_violations":sum(e.endswith("_enum") for e in errors),"derived_inconsistencies":sum(e.endswith(":derived") for e in errors),
                "errors":errors,"passed":not errors}
    if not validation["passed"]: raise ValueError(json.dumps(validation,indent=2))
    FINAL.parent.mkdir(parents=True,exist_ok=True); SNAPSHOT.parent.mkdir(parents=True,exist_ok=True); REPORT_DIR.mkdir(parents=True,exist_ok=True)
    with FINAL.open("w",encoding="utf-8",newline="\n") as handle:
        for row in rows: handle.write(json.dumps(row,ensure_ascii=False,sort_keys=True)+"\n")
    frozen_sha=sha(FINAL); timestamp=datetime.now(timezone.utc).isoformat()
    snapshot={"schema_version":"non_pi_supplemental_freeze.v1","status":"NON_PI_SUPPLEMENTAL_FROZEN",
              "frozen_artifact_path":str(FINAL.relative_to(ROOT)).replace("\\","/"),"artifact_sha256":frozen_sha,
              "total_rows":305,"unique_ids":305,"pi_status_distribution":dict(sorted(pi.items())),
              "maliciousness_distribution":dict(sorted(mal.items())),"class_distribution":dict(sorted(derived.items())),
              "source_distribution":dict(sorted(sources.items())),"license_distribution":dict(sorted(licenses.items())),
              "parent_artifact_hashes":{"candidate_pool":POOL_SHA,"first_pass":FIRST_SHA,"second_pass":SECOND_SHA,"dataset_a_frozen":FROZEN_A_SHA},
              "creation_timestamp":timestamp,"construction_version":"non_pi_supplemental_pool.v1",
              "contract_version":"GT Adjudication Contract v2","git_parent_commit":subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,check=True,capture_output=True,text=True).stdout.strip()}
    SNAPSHOT.write_text(json.dumps(snapshot,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    VALIDATION.write_text(json.dumps(validation,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    REPORT.write_text(f"""# Non-PI Supplemental Pool v1 Closure Report

## Source composition

- XSTest: 250
- JBB Original: 55
- HarmBench: blocked, 0 included
- JBB upstream-derived: excluded, 45

## Final GT

- Total: 305
- `not_pi`: 305
- `malicious`: 51
- `non_malicious`: 254
- `non_pi_malicious`: 51
- `non_pi_non_malicious`: 254

## Adjudication quality

- First-pass: 305/305
- Blind second-pass: 34/34
- Blind leakage: 0
- PI agreement: 100%
- Maliciousness agreement: 100%
- Derived agreement: 100%
- Disagreement: 0

## License / publication readiness

- Included rows approved: 305/305
- Provenance coverage: 305/305
- XSTest prompts require CC BY 4.0 attribution, license link, and indication of changes.
- JBB Original records retain the pinned dataset-card citation and MIT license evidence.
- HarmBench and upstream-derived JBB source text is excluded from the frozen artifact.

## Intended role

This artifact does not replace Frozen Dataset A v1. It is a supplemental source pool for final Scanner Diagnostic Benchmark curation: non-PI negative coverage, benign false-positive analysis, and malicious-but-non-PI confusion analysis.

## Integrity

- Frozen artifact: `{str(FINAL.relative_to(ROOT)).replace(chr(92), '/')}`
- SHA-256: `{frozen_sha}`
- Validation: PASS
""",encoding="utf-8",newline="\n")
    return {"frozen_artifact":str(FINAL),"sha256":frozen_sha,"validation":validation,"snapshot":snapshot}


if __name__=="__main__": print(json.dumps(run(),ensure_ascii=False,indent=2))
