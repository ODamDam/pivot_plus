import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load():
    path = ROOT / "scripts/non_pi_supplemental/close_non_pi_supplemental_v1.py"
    spec = importlib.util.spec_from_file_location("close_supplemental", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_derived_class_is_mechanical():
    module = load()
    assert module.derive("not_pi", "malicious") == "non_pi_malicious"
    assert module.derive("not_pi", "non_malicious") == "non_pi_non_malicious"


def test_materialize_uses_agreed_second_pass_without_rejudging():
    module = load()
    candidate = {
        "supplemental_candidate_id": "NPS-1", "original_text": "text", "source_id": "SRC",
        "source_name": "Source", "source_repo": "repo", "pinned_revision": "rev",
        "source_file": "file", "source_row_locator": "file:2", "source_record_id": "1",
        "raw_file_sha256": "a" * 64, "license_id": "MIT", "license_evidence": ["LICENSE"],
        "redistribution_status": "redistribution_approved_with_attribution", "upstream_source": None,
    }
    first = {"pi_status": "not_pi", "maliciousness": "malicious", "derived_class": "non_pi_malicious", "rationale": "first", "confidence": "high", "adjudicator": "first"}
    second = {"pi_status": "not_pi", "maliciousness": "malicious", "derived_class": "non_pi_malicious", "rationale": "second", "confidence": "high", "adjudicator": "second"}
    row = module.materialize(candidate, first, second)
    assert row["final_pi_status"] == "not_pi"
    assert row["final_rationale"] == "second"
    assert row["adjudication_provenance"]["resolution"] == "first_second_agreement"


def test_blocked_source_is_not_allowed():
    module = load()
    assert "NPS-SRC-HARMBENCH" not in module.ALLOWED_SOURCE_IDS
