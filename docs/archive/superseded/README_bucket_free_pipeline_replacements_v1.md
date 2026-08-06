# Bucket-free pipeline replacements v1

This archive replaces `src/pipelines` scripts with bucket-free diagnostic-v1 versions.

## Replace target files

Copy these files into the repository root:

```text
src/pipelines/export_execution_input_jsonl.py
src/pipelines/inspect_registry.py
src/pipelines/README.md
src/pipelines/report_llm01_batch.py
src/pipelines/report_llm01_diversity.py
src/pipelines/run_llm01_batch.py
src/pipelines/run_operator_smoke_test.py
```

## Test commands

From repository root:

```powershell
$env:PYTHONPATH = (Get-Location).Path

python -m compileall .\src\pipelines -q
python -m src.pipelines.inspect_registry
python -m src.pipelines.run_operator_smoke_test
```

The batch and report commands require local input/output data:

```powershell
python -m src.pipelines.run_llm01_batch
python -m src.pipelines.report_llm01_batch
python -m src.pipelines.report_llm01_diversity
python -m src.pipelines.export_execution_input_jsonl
```

## Main change

Old selection criterion:

```text
bucket_id / bucket_tags / ENABLED_BUCKETS
```

New selection criterion:

```text
use_in_diagnostic_v1
operator_family
attack_type_compat
surface_compat
output_format
risk_level
```
