# Target LLM Production Generation Preflight v1

- Source cases: 1,207 (Dataset A 902; supplemental 305)
- Planned generations: 4,523 (attack 2,706; control 902; direct 915)
- Dataset A attack materializable: 582/902
- Dataset A control materializable: 0/902
- Supplemental direct materializable: 305/305
- Blocked execution rows: 1862
- Leakage violations: 0
- Artificial weakening violations: 0
- Control/attack scenario consistency: not evaluable for 902/902 controls because no approved control request could be materialized
- Adapter options: SUPPORTED_AS_IS
- Status: `BLOCKED`

Execution is blocked because 320 standalone Dataset A cases lack canonical trusted fields and no frozen Dataset A case contains the approved clean control input or injection-span locator required by the diagnostic same-carrier deletion recipe. No substitute control semantics were invented.
