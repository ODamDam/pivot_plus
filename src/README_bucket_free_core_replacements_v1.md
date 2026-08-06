# Bucket-free core replacements v1

This package contains replacement files for `src/core/` to deprecate the old OWASP bucket-based operator selection.

## Replace target files

Copy these files into:

```text
C:\Users\2271086\Desktop\PIVOT\llm-prompt-injection-diagnostic-benchmark\src\core\
```

Files included:

- `types.py`
- `registry.py`
- `selector.py`
- `selector_weights.py`
- `mutator.py`
- `novelty_tracker.py`
- `selector_stats.py`
- `selection_hook.py`

Files not changed:

- `rng.py`
- `trace.py`
- `validity_guard.py`

## Main design changes

- `bucket_tags` is now legacy metadata only.
- `operator_family`, `attack_type_compat`, `output_format`, and `use_in_diagnostic_v1` are the main selection fields.
- `registry.filter()` now supports:
  - `surface`
  - `risk_max`
  - `use_in_diagnostic_v1`
  - `operator_family`
  - `attack_type`
  - `output_format`
  - `op_ids`
- Backward-compatible parameters such as `bucket_id` are accepted but ignored or stored only as legacy metadata.
- Existing old operators can still load because `registry.py` infers bucket-free defaults by `op_id`.

## Suggested test commands

```powershell
cd C:\Users\2271086\Desktop\PIVOT\llm-prompt-injection-diagnostic-benchmark
$env:PYTHONPATH = (Get-Location).Path

python -m compileall .\src\core -q
python -m compileall .\src\operators -q
python -m src.pipelines.inspect_registry
python -m src.pipelines.run_operator_smoke_test
```

The pipeline scripts may still print old bucket wording until they are refactored separately.
