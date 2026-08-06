# Contract Documents

This directory contains implementation-facing schemas and interface contracts.

## Current Contracts

| document | purpose |
| --- | --- |
| `dataset_schema_v1.md` | Final diagnostic benchmark schema |
| `dataset_schema_v1.json` | JSON Schema for validating final benchmark samples |
| `mutation_input_contract_v1.md` | Engine-compatible mutation input contract |
| `operator_contract_v0.1.md` | Mutation operator apply interface and trace contract |

## Rule

Only documents that define required fields, interfaces, input/output structures, or validation rules should live here.

Research decisions and selection policies belong in `docs/policies/`.
Execution instructions belong in `docs/howto/`.
Superseded documents belong in `docs/archive/`.
