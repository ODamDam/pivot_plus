# Inventory Validation v1

## Validation contract

The inventory must satisfy all of the following before external verification:

1. Both CSVs parse with Python's `csv` module and every row has the header width.
2. `source_id` and `edge_id` values are unique in their respective files.
3. Every edge endpoint exists in the source inventory.
4. Every semicolon-delimited internal evidence path exists in the checkout.
5. Counts are explicitly tied to internal CSV evidence or the build contract.
6. The mutation 500 count appears as inherited, never as observed source rows.
7. SCOUT's MIT string remains `internal_claim_only`, not verified.
8. SRC-02 and SRC-08 remain present despite having no current data records.
9. Git LFS pointers are not classified as materialized contents.
10. An internal license claim must have an internal evidence path.
11. `docs/archive/**`, `docs/legacy/**`, source data, review data, and LFS pointers
    remain unchanged.
12. Mutation edges use child-to-parent `derived_from` direction.
13. Derived collections are not independent external-verification targets; their
    eligibility remains parent-license and derivative-use dependent.

## Latest validation result

Validation date: 2026-07-31 (Asia/Seoul)

| check | result |
| --- | --- |
| CSV parsing and row widths | PASS |
| unique source IDs | PASS — 29/29 |
| unique edge IDs | PASS — 24/24 |
| edge endpoint closure | PASS |
| internal evidence paths exist | PASS |
| count basis present for non-zero counts | PASS |
| observed GT sum | PASS — 500 |
| inherited mutation GT sum | PASS — 500 |
| total GT sum | PASS — 1,000 |
| mutation inheritance not observed | PASS |
| mutation edge direction (`derived_from`) | PASS |
| derived collections external verification flag | PASS - false for 2/2 |
| independent/parent-dependent split | PASS - 27/2 |
| SCOUT MIT not verified | PASS |
| SRC-02 and SRC-08 present | PASS |
| LFS pointer classification | PASS |
| internal license claim evidence | PASS |
| protected paths unchanged | PASS |
| `git diff --check` | PASS |

No external network or API was used. This validation checks internal consistency,
not license correctness.
