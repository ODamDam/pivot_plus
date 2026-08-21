# Target LLM Diagnostic Input v2 Provenance

- Status: diagnostic-only; no live inference performed
- Source input: `experiments/target_llm_diagnostic_v1/inputs/target_llm_diagnostic_10pair_v1.jsonl`
- source_v1_git_blob_sha256: `f2331033411fc135bb74aeaa97a27066dfcccdc028d9543da559391ae801aea6`
- source_v1_gpu_worktree_sha256: `9616a696ac42d45e5fb026faf79fe4b4ecd1a4e038dbf5269946406f11f47974`
- source_v1_git_blob_oid: `4222ec652199372d470187f05c8c3cb274c4e26b`
- line_ending_difference_only: `true`
- input_content_drift: `false`
- Materialized input: `experiments/target_llm_diagnostic_v1/inputs/target_llm_diagnostic_10pair_v2_qwen2.5-7b.jsonl`
- v2 input SHA-256: `ad33587f5c53550f593fbd4527275239a7ae98508b2bfa31df8fdc740afa2caf`
- Git HEAD: `5b368ab281c1977b9e7ce66c99caf833a33e2071`
- Provider: `ollama`
- Model: `qwen2.5:7b`
- Full model digest: `845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e`
- Model identity source: GPU preflight / Ollama model inventory and `/api/show`
- Model identity verified: `true`
- Ollama version: `0.32.15`
- Ollama base URL: `http://127.0.0.1:11434`
- GPU: `NVIDIA GeForce RTX 3070 Ti Laptop GPU`
- Architecture: `qwen2`
- Parameter size: `7.6B`
- Quantization: `Q4_K_M`
- Context length: `32768`
- Neutral SYSTEM assessment: standard Qwen helpful-assistant identity
- Vulnerable Modelfile/SYSTEM contamination: not detected
- Legacy isolation: legacy Docker containers stopped; restart disabled; legacy volumes preserved but disconnected
- Planned dry-run ID: `target-llm-diag-10pair-v2-qwen25-gpu-dryrun`
- Expected plan: 20 generations, comprising 10 control and 10 attack requests
- v1 preservation: v1 was retained unchanged to preserve the approved diagnostic source and audit trail
- Digest persistence method: sidecar provenance, because `DiagnosticInputRecord` uses `extra="forbid"` and the current manifest schema has no model-digest field

## Dry-run execution-plan binding

- Run ID: `target-llm-diag-10pair-v2-qwen25-gpu-dryrun`
- v2 input SHA-256: `ad33587f5c53550f593fbd4527275239a7ae98508b2bfa31df8fdc740afa2caf`
- Manifest SHA-256: `8942c5ed848e2db1ce9cf8963f8a1713cb902e9cadcecc6dacbbce8e3c0ff7c5`
- Execution plan SHA-256: `9c23189b686d2565246a9339d658be4ae146b2eecfd0996158a6fe7c0b299ac7`
- Bound verified model digest: `845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e`
- Manifest input hash matches v2: `true`
- Planned generations: `20`
- Control requests: `10`
- Attack requests: `10`
- Live generation calls: `0`
- Result/failure/checkpoint artifacts: absent


## First live-smoke input binding

- Smoke input: `experiments/target_llm_diagnostic_v1/inputs/target_llm_diagnostic_smoke_1pair_v1_qwen2.5-7b.jsonl`
- Smoke input SHA-256: `973f0c63cbcfce11a012d302000bb4e9a34ccf15ba5b85abc9cdd91b2d75f361`
- Selected diagnostic case: `TLD-10P-V1-006`
- Selected source candidate: `DA-RAW-001123`
- Dry-run ID: `target-llm-diag-smoke-001123-qwen25-dryrun`
- Live-run ID: `target-llm-diag-smoke-001123-qwen25-live-v1`
- Provider: `ollama`
- Model: `qwen2.5:7b`
- Verified model digest: `845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e`
- Planned live generations: `2`
- Planned order: `control`, then `attack`
