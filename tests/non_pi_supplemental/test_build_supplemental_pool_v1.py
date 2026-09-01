import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load():
    path = ROOT / "scripts/non_pi_supplemental/build_supplemental_pool_v1.py"
    spec = importlib.util.spec_from_file_location("supplemental", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_deterministic_candidate_id():
    module = load()
    assert module.candidate_id("XSTEST", "1") == module.candidate_id("XSTEST", "1")
    assert module.candidate_id("XSTEST", "1") != module.candidate_id("XSTEST", "2")
    assert module.candidate_id("XSTEST", "1").startswith("NPS-V1-")


def test_normalization_is_case_and_whitespace_stable():
    module = load()
    assert module.normalize("  Hello,   WORLD!  ") == module.normalize("hello, world!")


def test_derived_gt_fields_are_not_part_of_candidate_schema():
    module = load()
    assert not ({"pi_status", "maliciousness", "derived_class", "case_gt"} & module.CANDIDATE_FIELDS)
