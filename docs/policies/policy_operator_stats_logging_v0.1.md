# Operator Stats Logging Policy v1

This policy defines the bucket-free selector statistics output used for
post-run analysis.

## Update API

Call `OperatorStatsByScope.report_result(selection_scope, op_id, verdict,
oracle_score)` from the execution loop.

- `selection_scope` is the selector's bucket-free scope, such as
  `plain_text:instruction_override`.
- `op_id` is the active operator ID.
- `verdict` is normalized to `PASS`, `FAIL`, or `UNKNOWN`.
- `oracle_score`, when numeric, is clamped to the range 0..1.

Scopes are opaque selector keys. They must not be treated as renamed OWASP
buckets.

## JSON schema

`OperatorStatsByScope.dump_json(path)` writes this shape:

```json
{
  "schema_version": "operator_stats_by_scope.v1",
  "generated_at": 1730000000.0,
  "stats": {
    "<selection_scope>": {
      "<op_id>": {
        "n": 0,
        "n_pass": 0,
        "n_fail": 0,
        "n_unknown": 0,
        "pass_rate": 0.0,
        "n_score": 0,
        "avg_oracle_score": 0.0,
        "last_updated_ts": 0.0
      }
    }
  }
}
```

`pass_rate` excludes `UNKNOWN` verdicts. `avg_oracle_score` includes only
numeric scores. A recommended generated-output path is
`out/stats/operator_stats_by_scope.v1.json`; generated outputs remain
untracked.

## Compatibility

`OperatorStatsByBucket` remains an import alias for external compatibility.
New code and current policy must use `OperatorStatsByScope`; the alias does
not restore bucket-based selection semantics.
