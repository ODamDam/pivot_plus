# Pre-Monorepo Execution Pipeline Freeze

- Freeze date: 2026-07-30
- Repository: pivot_plus
- Branch: generation-pipeline-v1
- Repository role: target-LLM generation, scanner execution, annotation, input revalidation, and evaluator analysis
- Status: pre-integration execution-pipeline checkpoint
- Input Ground Truth status: provisional and not independently validated

## Important interpretation

The current execution and evaluation pipeline was developed using a provisional
1,000-record dataset whose upstream labels cannot be treated as final human
Ground Truth.

The existing outputs and workflows remain useful as pilot artifacts, pipeline
validation evidence, and error-analysis material. They must not be interpreted
as final benchmark results until the input Ground Truth is reconstructed.

## Repository cleanup included in this freeze

- Removed tracked Visual Studio workspace and cache files.
- Removed the duplicated P0.1 patch archive and extracted patch directory.
- Verified that the canonical repository files contain all patch functions,
  classes, and API routes.
- Preserved the expanded chat-generation implementation in the canonical paths.
- Converted requirements.txt from UTF-16 LE to UTF-8 with BOM.
- Changed greenlet from 3.2.5 to 3.2.4 for the current Python environment.

## Next step

Integrate the data-construction pipeline from
llm-prompt-injection-diagnostic-benchmark into this repository, then reconstruct
the human-adjudicated input Ground Truth before rerunning the main generation,
scanner, and evaluator experiments.
