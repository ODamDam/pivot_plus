# JBB Supplemental Intake v1

## Source pin

- Repository: `https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors`
- Revision: `886acc352a31533ffbcf4ef22c744658688086fc`
- Harmful CSV SHA-256: `f985615b17b7659a7598f751a3c1fe0704e80d4f966d6ba36b6777d53ad18150`
- LICENSE SHA-256: `90646877cb6bda11eff59af1ea1bc09776dda552e1cf4685ed9dbac4753bb189`
- Dataset license: MIT
- Paper: Chao et al., *JailbreakBench: An Open Robustness Benchmark for Jailbreaking Large Language Models*, NeurIPS Datasets and Benchmarks Track (2024), arXiv:2404.01318.
- DOI: none stated in the pinned dataset card.

## Intake decision

The 55 records with `Source=Original` are approved with attribution. Only each record's `Goal` is candidate text. `Target` is excluded from candidate text and retained only in the Original-only provenance projection. The 27 TDC/HarmBench and 18 AdvBench rows are excluded because of upstream provenance; their Goal and Target text is not materialized.

The deterministic PI prefilter found no explicit hierarchy/trust-boundary takeover and no ambiguous PI case among the 55 Original goals. This is an intake decision, not final Case GT adjudication.

## Results

- Original candidates: 55
- Needs PI review: 0
- Semantic exclusions: 0
- Internal exact/normalized duplicate groups: 0 / 0
- XSTest overlaps: 0
- Frozen Dataset A overlaps: 0
- Combined supplemental pool: 305 (250 provisional benign, 55 provisional malicious)
- Validation: PASS

HarmBench raw-text comparison was not performed because its blocked inventory intentionally withholds behavior text.
