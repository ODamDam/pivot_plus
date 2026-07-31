# Project Objective

This repository implements a diagnostic benchmark for evaluating prompt-injection
scanners, vulnerable LLM behavior, and evaluator reliability.

# Research Principles

- Mutation is used to evaluate detection robustness, not to maximize attack success.
- Preserve the original semantic intent and label of each sample.
- Do not automatically change dataset labels.
- Do not classify ordinary instruction following as a vulnerability by itself.
- Distinguish input maliciousness, model behavior, and evaluator decisions.
- Distinguish acceptable model behavior from actual security-boundary violations.
- Ambiguous cases must be marked for human review rather than force-classified.

# Data Rules

- Never modify or overwrite source datasets.
- Preserve sample_id through every pipeline stage.
- Preserve raw prompts, constructed requests, raw model responses, parsed responses,
  and evaluator decisions separately.
- Do not overwrite previous experiment outputs.
- Store generated results only in designated output or report directories.
- Do not commit generated experiment outputs unless explicitly requested.

# Implementation Rules

- Keep the new Vuln LLM implementation independent from the legacy implementation.
- Do not modify legacy Vuln LLM code unless explicitly requested.
- Write or update tests before changing core pipeline behavior.
- Prefer small, reviewable changes.
- Do not weaken, skip, or delete tests merely to make them pass.
- Do not install or add dependencies without first reporting the reason and impact.
- Preserve compatibility with Windows and PowerShell where applicable.

# Execution Rules

- Do not call external APIs unless explicitly requested.
- Use deterministic mock clients and dry-run execution before real API calls.
- Never read, display, log, or commit API keys, credentials, authorization headers,
  or the contents of .env files.
- Record run_id, Git commit, dataset hash, model configuration, schema version,
  and random seed for every experiment.
- Support checkpoint and resume for experiments where applicable.
- Treat authentication and configuration errors as non-retryable.
- Retry only explicitly approved transient failures.

# Validation Rules

- Run the relevant unit and integration tests before reporting completion.
- Run a fixture-based smoke test when pipeline behavior changes.
- Validate schemas and sample_id integrity.
- Confirm that dry-run mode performs no external network requests.
- Report tests that were not run or could not be completed.

# Completion Report

For every completed task, report:

- Files created, modified, or deleted
- Commands executed
- Tests executed and their results
- Any behavior that was not verified
- Remaining risks, assumptions, or technical debt
- Whether external APIs or network access were used

Do not create Git commits unless explicitly requested.
