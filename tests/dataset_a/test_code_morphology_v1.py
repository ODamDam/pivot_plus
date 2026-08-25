from pathlib import Path

from scripts.dataset_a.code_morphology_v1 import (
    analyze_code_morphology,
    build_morphology_artifact,
    calibration_anchors,
)


ROOT = Path(__file__).resolve().parents[2]


def test_whole_record_fenced_python():
    row = analyze_code_morphology('```python\nimport os\nprint(os.getcwd())\n```')
    assert row["fence_topology"] == "WHOLE_RECORD_FENCE"
    assert row["fenced_block_count"] == 1
    assert row["outside_nonblank_lines"] == 0
    assert row["fenced_char_ratio"] > 0.9


def test_short_wrapper_large_fenced_source():
    text = "Answer:\n```python\nimport os\ndef main():\n    print(os.getcwd())\nmain()\n```"
    row = analyze_code_morphology(text)
    assert row["fence_topology"] == "CODE_WITH_SHORT_WRAPPER"
    assert row["outside_nonblank_lines"] == 1


def test_long_prose_small_code_example():
    text = (
        "This document explains an example in detail.\n"
        "Read the surrounding discussion before considering the sample.\n"
        "The sample is illustrative.\n```python\nprint('x')\n```\n"
        "The explanation continues after the sample."
    )
    row = analyze_code_morphology(text)
    assert row["fence_topology"] == "PROSE_WITH_CODE_EXAMPLE"
    assert row["fenced_char_ratio"] < 0.5
    assert row["provisional_dominance_class"] == "TEXT_DOMINANT_HIGH"


def test_multi_section_markdown_with_fenced_examples():
    text = "# Guide\n\n## One\n```python\nprint(1)\n```\n\n## Two\n```python\nprint(2)\n```"
    row = analyze_code_morphology(text)
    assert row["fence_topology"] == "MULTI_BLOCK_DOCUMENT"
    assert row["fenced_block_count"] == 2
    assert row["outside_markdown_heading_lines"] == 3


def test_unbalanced_fence():
    row = analyze_code_morphology("Introduction\n```python\nprint('x')")
    assert row["fence_topology"] == "UNBALANCED_OR_MALFORMED"
    assert row["unbalanced_fence_count"] == 1


def test_no_fence():
    row = analyze_code_morphology("Run: whoami")
    assert row["fence_topology"] == "NO_VALID_FENCE"
    assert row["fence_count"] == 0


def test_multiple_fenced_blocks():
    row = analyze_code_morphology("```\na\n```\ntext\n```\nb\n```")
    assert row["fenced_block_count"] == 2
    assert row["fence_count"] == 4


def test_external_markdown_anchor_000970_remains_code_dominant():
    anchors = calibration_anchors(ROOT)
    assert anchors["DA-RAW-000970"]["provisional_dominance_class"] == "CODE_DOMINANT_HIGH"


def test_reusable_code_anchors_are_code_dominant():
    anchors = calibration_anchors(ROOT)
    code = [row for cid, row in anchors.items() if row["anchor_type"] == "REUSABLE_CODE"]
    assert len(code) == 6
    assert all(row["provisional_dominance_class"] == "CODE_DOMINANT_HIGH" for row in code)


def test_reusable_markdown_anchor_is_markdown_or_mixed():
    anchors = calibration_anchors(ROOT)
    markdown = [row for row in anchors.values() if row["anchor_type"] == "REUSABLE_MARKDOWN"]
    assert len(markdown) == 1
    assert markdown[0]["provisional_dominance_class"] in {"MARKDOWN_DOMINANT_HIGH", "MIXED"}


def test_224_run_is_deterministic_and_integral():
    first = build_morphology_artifact(ROOT)
    second = build_morphology_artifact(ROOT)
    assert first == second
    assert len(first) == len({row["candidate_id"] for row in first}) == 224
    assert all(row["existing_resolution_status"] == "HUMAN_REVIEW_REQUIRED" for row in first)
    assert not any("review" in row for row in first)
