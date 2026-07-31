# Source License Audit

This directory contains the internal evidence phase of the source-license audit.
It does not make an allow, conditional, or exclude decision and does not treat an
internal license string as externally verified evidence.

## Audit flow

1. **Internal inventory** — enumerate primary, upstream, reference, and derived
   source nodes using repository evidence.
2. **Source-edge reconstruction** — record normalization, wrapping, generation,
   embedded-source, and child-to-parent mutation derivation separately from nodes.
3. **Official URL identification** — identify canonical owner-controlled source
   pages without inferring URLs from names.
4. **External license evidence collection** — collect official LICENSE, NOTICE,
   dataset-card, terms-of-use, paper-appendix, version, and revision evidence.
5. **Record-level upstream dependency review** — determine which records depend
   on embedded or reused upstream material.
6. **Decision** — assign allow, conditional, exclude, or unresolved only after
   the external evidence review.
7. **Ground Truth eligibility filter** — apply the decision at source and record
   level, preserving parent provenance for mutations.
8. **Attribution manifest** — produce release-facing attribution and notice data.
9. **Audit freeze** — freeze the inventory, evidence hashes, decisions, and
   eligible Ground Truth revision.

## Files

- `source_inventory_v1.csv`: machine-readable source nodes.
- `source_provenance_edges_v1.csv`: machine-readable relationships between nodes.
- `source_inventory_v1.md`: inventory summary and counting methodology.
- `unresolved_sources_v1.md`: external evidence work queue.
- `inventory_validation_v1.md`: validation rules and the latest results.

## Interpretation rules

- Empty URL, owner, version, revision, and retrieval fields mean that the value
  is not established by internal evidence.
- `license_claim_internal` is a repository claim, not a verified license.
- `observed_ground_truth_count` counts direct source-bearing GT rows.
- `inherited_ground_truth_count` counts the 500 mutation rows whose provenance is
  inferred through their parent seeds; it is never an observed source count.
- Git LFS pointer files are not treated as materialized dataset contents.
- The 27 primary/upstream/reference nodes are independent external-evidence
  targets; the two derived collections are parent-dependent and are not
  independent official source-page search targets.
