# Pipelines

This directory contains runnable pipeline scripts used to support the bucket-free Prompt Injection Diagnostic Benchmark workflow.

## Design decision

The original pilot used OWASP LLM category buckets such as `LLM01_PROMPT_INJECTION`, `LLM05_INPUT_ROBUSTNESS`, and `LLM08_TOOL_MISUSE`.

The current research scope is narrower and more diagnostic:

```text
Prompt Injection Diagnostic Benchmark v1
→ operator_family
→ attack_type_compat
→ surface_compat
→ output_format
→ semantic_preservation_risk
→ label_change_risk
```

Therefore, pipeline scripts no longer use OWASP bucket membership as the primary operator selection criterion.

`bucket_tags` may still exist in older operator metadata as a legacy compatibility field, but it should not determine the final benchmark composition.

---

## Files

### `inspect_registry.py`

Inspects the operator registry from a bucket-free diagnostic perspective.

It reports:

- all importable operators
- diagnostic_v1 enabled operators
- grouping by `operator_family`
- grouping by `attack_type_compat`
- grouping by `surface_compat`

Run:

```bash
python -m src.pipelines.inspect_registry
```

### `run_operator_smoke_test.py`

Runs a lightweight sanity check over all `use_in_diagnostic_v1=True` operators.

Run:

```bash
python -m src.pipelines.run_operator_smoke_test
```

### `run_llm01_batch.py`

Runs the diagnostic v1 batch mutation workflow.

The file name is kept for backward compatibility, but the output is now bucket-free:

```text
data/outputs/runs/run_diagnostic_v1_batch.jsonl
data/outputs/runs/run_diagnostic_v1_batch_attempts.jsonl
data/outputs/runs/run_diagnostic_v1_batch_unresolved.jsonl
```

Run:

```bash
python -m src.pipelines.run_llm01_batch
```

### `report_llm01_batch.py`

Builds a batch-level diagnostic report.

Output:

```text
data/outputs/reports/run_diagnostic_v1_batch_report.json
```

Run:

```bash
python -m src.pipelines.report_llm01_batch
```

### `report_llm01_diversity.py`

Builds a diagnostic diversity report over child prompts.

Output:

```text
data/outputs/reports/run_diagnostic_v1_diversity.json
```

Run:

```bash
python -m src.pipelines.report_llm01_diversity
```

### `export_execution_input_jsonl.py`

Exports execution-ready JSONL records for downstream scanner evaluation.

Output:

```text
data/outputs/final/execution_input_diagnostic_v1.jsonl
```

Run:

```bash
python -m src.pipelines.export_execution_input_jsonl
```

---

## Recommended workflow

```text
inspect registry
→ run operator smoke test
→ run diagnostic batch
→ generate batch report
→ generate diversity report
→ export execution input JSONL
```

Commands:

```bash
python -m src.pipelines.inspect_registry
python -m src.pipelines.run_operator_smoke_test
python -m src.pipelines.run_llm01_batch
python -m src.pipelines.report_llm01_batch
python -m src.pipelines.report_llm01_diversity
python -m src.pipelines.export_execution_input_jsonl
```

---

## Compatibility note

The script names still contain `llm01` because the project is historically centered on LLM01 Prompt Injection.

However, the selection logic is now bucket-free and diagnostic-v1 oriented.
