# Non-PI Supplemental Pool v1 — Source/License/Raw Intake Preflight

This checkpoint does not assign Case GT and does not modify or merge Frozen Dataset A.

## XSTest

- Revision: `d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d`
- Prompt file SHA-256: `073e0b0fcc056dc053e4bd473bcf25c02e50f7771ffb261a1b047901d7de286e`
- Prompt license: `CC-BY-4.0`
- Prompt redistribution: `redistribution_approved_with_attribution`
- Total prompt rows: 450
- Provisional safe candidates: 250
- Unsafe contrast rows excluded: 200
- Model completions ingested: 0

The upstream `safe` label is retained only as provisional source intent and is not Case GT.

## HarmBench

- Revision: `8e1604d1171fe8a48d8febecd22f600e462bdcdd`
- Raw behavior file SHA-256: `8d81accedd38eaaf8b760618622bb888417d1fd0c86eba65c427a16f1cbb4afc`
- Repository license: MIT
- Raw behavior rows: 400
- Redistribution approved: 0
- Blocked pending upstream license: 400
- Non-copyright harmful semantic potential: 300
- Copyright rows outside the requested semantic intake: 100
- Attack-generated test cases ingested: 0
- Internal exact/normalized duplicate groups: 5/5 (blocked inventory only)

The CSV exposes behavior/category/tag/context/ID fields but no row-level or source-family provenance field. The repository README acknowledges several red-team method repositories but does not map behavior text to upstream copyright or license. Repository-level MIT was therefore not treated as automatic redistribution approval for behavior text.

## Candidate pool

- Materialized candidates: 250
- `non_pi_non_malicious_candidate`: 250
- `non_pi_malicious_candidate`: 0
- Exact duplicate groups: 0
- Normalized duplicate groups: 0
- XSTest/HarmBench exact or normalized overlaps: 0
- Frozen Dataset A exact or normalized overlaps: 0

Status: `LICENSE_REVIEW_REQUIRED` for HarmBench; the XSTest-only candidate materialization passed validation.
