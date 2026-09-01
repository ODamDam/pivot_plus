#!/usr/bin/env python3
"""Analyze supplemental first/second agreement and materialize GT disagreements only."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POOL = ROOT / "data/non_pi_supplemental/candidate_pool/non_pi_supplemental_candidates_v1_1.jsonl"
FIRST = ROOT / "data/non_pi_supplemental/adjudication/first_pass/non_pi_supplemental_first_pass_305_v1.jsonl"
MANIFEST = ROOT / "data/non_pi_supplemental/adjudication/second_pass/second_pass_candidate_manifest_v1.jsonl"
SECOND = ROOT / "data/non_pi_supplemental/adjudication/second_pass/blind_second_pass_results_34_v1.jsonl"
QUEUE = ROOT / "data/non_pi_supplemental/adjudication/final_adjudication/disagreement_queue_v1.jsonl"
ANALYSIS = ROOT / "reports/non_pi_supplemental/second_pass/agreement_analysis_v1.json"
REPORT = ROOT / "reports/non_pi_supplemental/second_pass/NON_PI_SUPPLEMENTAL_SECOND_PASS_v1.md"
POOL_SHA = "8123cc5f88cc043a1b58814307644369fd6f4f6a1ad7d794905f151afaf3f050"
FIRST_SHA = "51191e9fbc982c60b5a606dc062ff65481aebcde548892c8de716ee12f71f822"
MANIFEST_SHA = "61360b75aaef3f1931c03b90ffae2b837c757e394b8302f6aa25ff3779ada876"
SECOND_SHA = "df136f0a91568959d5b542f7542f836778ea5609cf272f9b1cdc4cfc628a658a"


def sha(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path: Path) -> list[dict[str, Any]]: return [json.loads(x) for x in path.open(encoding="utf-8") if x.strip()]


def metrics(pairs: list[tuple[dict[str, Any], dict[str, Any]]]) -> dict[str, Any]:
    total = len(pairs)
    agreement = lambda field: sum(a[field] == b[field] for a,b in pairs)
    pi, mal, derived = agreement("pi_status"), agreement("maliciousness"), agreement("derived_class")
    full = sum(all(a[f] == b[f] for f in ("pi_status", "maliciousness", "derived_class")) for a,b in pairs)
    return {"count": total, "pi_status": {"agree": pi, "rate": pi/total if total else 1.0},
            "maliciousness": {"agree": mal, "rate": mal/total if total else 1.0},
            "derived_class": {"agree": derived, "rate": derived/total if total else 1.0},
            "full_primary": {"agree": full, "rate": full/total if total else 1.0}}


def run() -> dict[str, Any]:
    expected = ((POOL,POOL_SHA),(FIRST,FIRST_SHA),(MANIFEST,MANIFEST_SHA),(SECOND,SECOND_SHA))
    if any(sha(path)!=digest for path,digest in expected): raise ValueError("Canonical artifact hash mismatch")
    pool, first, manifest, second = read(POOL),read(FIRST),read(MANIFEST),read(SECOND)
    ids=[r["supplemental_candidate_id"] for r in manifest]
    if len(ids)!=34 or len(set(ids))!=34: raise ValueError("Manifest ID invariant")
    f={r["supplemental_candidate_id"]:r for r in first}; s={r["supplemental_candidate_id"]:r for r in second}; p={r["supplemental_candidate_id"]:r for r in pool}; m={r["supplemental_candidate_id"]:r for r in manifest}
    if set(ids)!=set(s) or not set(ids)<=set(f): raise ValueError("First/second ID mismatch")
    pairs=[(f[i],s[i]) for i in ids]
    edge_pairs=[(f[i],s[i]) for i in ids if m[i]["selection_group"]=="edge_case"]
    qc_pairs=[(f[i],s[i]) for i in ids if m[i]["selection_group"]=="deterministic_qc"]
    queue=[]
    for identifier in ids:
        a,b=f[identifier],s[identifier]
        fields=[field for field in ("pi_status","maliciousness","derived_class") if a[field]!=b[field]]
        if fields:
            source=p[identifier]
            queue.append({"supplemental_candidate_id":identifier,"original_text":source["original_text"],
                          "provenance_ref":source["source_row_locator"],"license_id":source["license_id"],
                          "first_pass":{k:a[k] for k in ("pi_status","maliciousness","derived_class","rationale","confidence")},
                          "second_pass":{k:b[k] for k in ("pi_status","maliciousness","derived_class","rationale","confidence")},
                          "disagreement_fields":fields,"selection_provenance":m[identifier]})
    review_cases=[{"supplemental_candidate_id":i,"first":{k:f[i][k] for k in ("pi_status","maliciousness","derived_class")},
                   "second":{k:s[i][k] for k in ("pi_status","maliciousness","derived_class")},
                   "agreement":all(f[i][k]==s[i][k] for k in ("pi_status","maliciousness","derived_class"))}
                  for i in ids if m[i]["selection_group"]=="edge_case"]
    result={"schema_version":"supplemental_second_pass_agreement.v1","overall":metrics(pairs),"review_trigger":metrics(edge_pairs),
            "review_trigger_cases":review_cases,"qc":metrics(qc_pairs),"gt_disagreement_count":len(queue),
            "disagreement_unique_id_count":len({r['supplemental_candidate_id'] for r in queue}),
            "policy_schema_blocker":False,"status":"SUPPLEMENTAL_READY_TO_FREEZE" if not queue else "SUPPLEMENTAL_READY_FOR_FINAL_ADJUDICATION"}
    QUEUE.parent.mkdir(parents=True,exist_ok=True); ANALYSIS.parent.mkdir(parents=True,exist_ok=True)
    if any(path.exists() for path in (QUEUE,ANALYSIS,REPORT)): raise FileExistsError("Refusing to overwrite agreement artifacts")
    with QUEUE.open("w",encoding="utf-8",newline="\n") as handle:
        for row in queue: handle.write(json.dumps(row,ensure_ascii=False,sort_keys=True)+"\n")
    ANALYSIS.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    REPORT.write_text(f"# Non-PI Supplemental Second-Pass v1\n\n- Completed: 34/34\n- Overall: `{result['overall']}`\n- Review-trigger: `{result['review_trigger']}`\n- QC: `{result['qc']}`\n- GT disagreements: {len(queue)}\n- Policy/schema blocker: false\n- Status: `{result['status']}`\n",encoding="utf-8",newline="\n")
    return result


if __name__ == "__main__": print(json.dumps(run(),ensure_ascii=False,indent=2))
