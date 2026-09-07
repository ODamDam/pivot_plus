"""Synthetic Garak 0.16 detector boundary tests; never import the scanner."""
from __future__ import annotations

import copy
import socket
import subprocess
import sys

import pytest

from test_replay_contract import artifacts
from src.scanner_adapter_v2 import load_replay_cases
from src.scanner_adapter_v2.results import (ScannerRawEvaluatorResult, canonical_hash,
                                          validate_normalized_result, verify_raw_lineage)
from src.scanner_adapter_v2.adapters.garak import GarakAdapterConfig, GarakDetectorAdapter
from src.scanner_adapter_v2.adapters.garak_backend import BackendFailure, Garak016Backend


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network forbidden in synthetic adapter tests")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def replay(artifacts):
    return load_replay_cases(**artifacts[0])[0]


def mapping():
    return {"schema_version": "scanner_mapping_policy.v1", "policy_id": "fixture-threshold",
            "version": "1", "scanner": {"name": "garak", "version": "0.16.0"},
            "evaluator": {"name": "garak.detectors.synthetic.Fixture", "version": "fixture-1"},
            "kind": "numeric_threshold", "value_path": ["values", 0],
            "basis": "Synthetic detector contract only: threshold 0.75, not a Garak default",
            "native_direction": "higher_is_more_suspicious",
            "threshold": {"source": "evaluator_contract", "identifier": "fixture-contract-v1",
                          "value": 0.75, "path": None}, "comparator": "gte", "values": []}


def config(policy=None):
    return GarakAdapterConfig.from_dict({
        "scanner_version": "0.16.0", "detector_id": "garak.detectors.synthetic.Fixture",
        "detector_version": "fixture-1", "adapter_version": "garak_adapter.v1",
        "observation_surface": "response_only",
        "response_only_basis": "Synthetic detector reads only Attempt.outputs",
        "native_direction": "higher_is_more_suspicious",
        "detector_config": {"identity": "fixture-empty", "options": {}},
        "mapping_policy": policy})


class FakeBackend:
    identifier = "synthetic-garak-016"
    synthetic = True

    def __init__(self, values):
        self.values = values
        self.calls = 0
        self.received = None

    def detect(self, prepared, configuration):
        self.calls += 1
        self.received = copy.deepcopy(prepared)
        if isinstance(self.values, BaseException):
            raise self.values
        return self.values


def run(replay, values, policy=None):
    backend = FakeBackend(values)
    adapter = GarakDetectorAdapter(config(policy), backend=backend)
    prepared = adapter.prepare_input(replay, observation_surface="response_only")
    raw = adapter.execute(prepared, replay_case=replay,
                          run_context={"scanner_run_id": "synthetic-run", "git_commit": "b" * 40,
                                       "execution_id": "fixture-attempt-1", "random_seed": 7})
    return adapter, prepared, raw, backend


@pytest.mark.parametrize("value,verdict", [(0.0, "not_flagged"), (1.0, "flagged"),
                                          (0.37, "not_flagged"), (0.75, "flagged")])
def test_native_threshold_mapping(replay, value, verdict):
    policy = mapping()
    adapter, prepared, raw, backend = run(replay, [value], policy)
    data = raw.to_dict()
    norm = adapter.normalize(raw, policy).to_dict()
    assert data["native_output"]["values"] == [value]
    assert type(data["native_output"]["values"][0]) is float
    assert data["native_output"]["output_indices"] == [0]
    assert norm["normalized_verdict"] == verdict
    assert norm["native_score"] == value
    assert norm["native_threshold"] == 0.75
    assert norm["threshold_source"] == "evaluator_contract"
    assert norm["native_direction"] == "higher_is_more_suspicious"
    assert backend.calls == 1
    verify_raw_lineage(raw, replay, prepared)
    validate_normalized_result(norm, raw_result=raw)


@pytest.mark.parametrize("value", [0.0, 1.0, 0.42])
def test_unknown_threshold_abstains(replay, value):
    adapter, _, raw, _ = run(replay, [value])
    norm = adapter.normalize(raw, None).to_dict()
    assert norm["normalized_verdict"] == "indeterminate"
    assert norm["native_score"] == value
    assert norm["native_threshold"] is None and norm["threshold_source"] is None
    validate_normalized_result(norm, raw_result=raw)


@pytest.mark.parametrize("value,status,error", [
    ([], "error", "invalid_native_result"),
    ([0.0, 1.0], "error", "invalid_native_result"),
    ([None], "unsupported", "unsupported_result"),
    (["unexpected"], "error", "invalid_native_result"),
    ([True], "error", "invalid_native_result"),
    ([float("nan")], "error", "invalid_native_result"),
    ([float("inf")], "error", "invalid_native_result"),
    ([float("-inf")], "error", "invalid_native_result"),
    (0.5, "error", "invalid_native_result"),
    ({"outcome_gt": "forbidden"}, "error", "invalid_native_result"),
    ([{"scanner_results": []}], "error", "invalid_native_result"),
    (RuntimeError("do not expose exception content"), "error", "evaluator_error"),
    (TimeoutError(), "timeout", "timeout"),
    (BackendFailure("dependency_error", "dependency_error"), "dependency_error", "dependency_error"),
    (BackendFailure("configuration_error", "configuration_error"), "configuration_error", "configuration_error"),
])
def test_failure_never_safe(replay, value, status, error):
    adapter, _, raw, _ = run(replay, value, mapping())
    data = raw.to_dict()
    assert (data["execution_status"], data["error_type"]) == (status, error)
    assert adapter.normalize(raw, mapping()).to_dict()["normalized_verdict"] == "no_result"
    assert "do not expose" not in str(data)
    if value == [None]:
        assert data["native_output"]["values"] == [None]


def test_immutability_identity_and_provenance(replay):
    before = replay.to_dict()
    adapter, prepared, raw, backend = run(replay, [0.12])
    snapshot = raw.to_dict()
    assert snapshot["evaluation_id"] == adapter.evaluation_id(replay)
    assert snapshot["generation_id"] == before["generation_id"]
    assert snapshot["provenance"]["runtime"]["identifier"] == "synthetic-garak-016"
    assert snapshot["provenance"]["runtime"]["dependencies"] == []
    assert prepared["backend"]["synthetic"] is True
    assert prepared["outputs"] == [before["response_text"]]
    assert prepared["prompt"] == {"text": ""}
    assert "untrusted_input" not in prepared and "model_visible_messages" not in prepared
    adapter.normalize(raw, None)
    prepared["outputs"][0] = "changed"
    assert raw.to_dict() == snapshot and replay.to_dict() == before
    assert backend.received["outputs"] == [before["response_text"]]
    assert run(replay, [0.99])[2].to_dict()["evaluation_id"] == snapshot["evaluation_id"]
    other = config().to_dict()
    other["detector_config"]["identity"] = "another"
    assert GarakDetectorAdapter(GarakAdapterConfig.from_dict(other), backend=backend).evaluation_id(replay) != snapshot["evaluation_id"]


@pytest.mark.parametrize("surface", ["request_and_response", "trusted_context_untrusted_input_and_response"])
def test_unsupported_surface(replay, surface):
    backend = FakeBackend([0.0])
    adapter = GarakDetectorAdapter(config(), backend=backend)
    with pytest.raises(ValueError, match="surface"):
        adapter.prepare_input(replay, observation_surface=surface)
    assert backend.calls == 0


@pytest.mark.parametrize("mutation", ["response_hash", "outcome_gt", "judge_decision", "pi_status"])
def test_replay_revalidated_at_entry(replay, mutation):
    class TamperedReplay:
        def to_dict(self):
            data = replay.to_dict()
            if mutation == "response_hash":
                data["response_sha256"] = "0" * 64
            else:
                data[mutation] = "forbidden"
            return data
    adapter = GarakDetectorAdapter(config(), backend=FakeBackend([0.0]))
    with pytest.raises(ValueError):
        adapter.prepare_input(TamperedReplay(), observation_surface="response_only")


@pytest.mark.parametrize("mutation", ["outcome_gt", "outputs", "backend"])
def test_prepared_input_tampering_prevents_execution(replay, mutation):
    adapter = GarakDetectorAdapter(config(), backend=FakeBackend([0.0]))
    prepared = adapter.prepare_input(replay, observation_surface="response_only")
    prepared[mutation] = {"outcome_gt": "forbidden"} if mutation == "outcome_gt" else None
    with pytest.raises(ValueError):
        adapter.execute(prepared, replay_case=replay, run_context={})
    assert adapter.backend.calls == 0


def test_policy_substitution_rejected(replay):
    adapter, _, raw, _ = run(replay, [0.8], mapping())
    changed = mapping()
    changed["threshold"]["value"] = 0.1
    with pytest.raises(ValueError):
        adapter.normalize(raw, changed)
    with pytest.raises(ValueError):
        adapter.normalize(raw, None)


def test_iterator_exception_is_failure_and_partial_values_preserved(replay):
    def values():
        yield 0.2
        raise RuntimeError()
    adapter, _, raw, _ = run(replay, values())
    assert raw.to_dict()["native_output"]["values"] == [0.2]
    assert adapter.normalize(raw, None).to_dict()["normalized_verdict"] == "no_result"


def test_module_import_does_not_load_garak():
    script = """import builtins
original = builtins.__import__
def guarded(name, *args, **kwargs):
    assert not (name == 'garak' or name.startswith('garak.'))
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
import src.scanner_adapter_v2.adapters.garak
"""
    subprocess.run([sys.executable, "-c", script], check=True, capture_output=True)


def test_real_hook_dependency_detection_without_scanner_import(monkeypatch):
    from importlib.metadata import PackageNotFoundError
    import src.scanner_adapter_v2.adapters.garak_backend as module
    def absent(name):
        raise PackageNotFoundError(name)
    monkeypatch.setattr(module.metadata, "version", absent)
    with pytest.raises(module.BackendFailure) as exc:
        Garak016Backend().detect({}, {})
    assert exc.value.status == "dependency_error"


@pytest.mark.parametrize("field", ["outcome_gt", "judge_decision", "pi_status", "scanner_results"])
def test_detector_options_reject_leakage(field):
    data = config().to_dict()
    data["detector_config"]["options"] = {"nested": [{field: "not allowed"}]}
    with pytest.raises(ValueError):
        GarakAdapterConfig.from_dict(data)


@pytest.mark.parametrize("values", [[], [None], [0.0, 1.0], ["unknown"]])
def test_normalize_rejects_forged_success_shape(replay, values):
    adapter, _, raw, _ = run(replay, [0.2])
    data = raw.to_dict()
    data["native_output"]["values"] = values
    data["native_output_sha256"] = canonical_hash(data["native_output"])
    forged = ScannerRawEvaluatorResult.from_dict(data)
    with pytest.raises(ValueError):
        adapter.normalize(forged, None)


def test_rejected_values_do_not_shift_output_indices(replay):
    _, _, raw, _ = run(replay, [float("nan"), 0.4])
    payload = raw.to_dict()["native_output"]
    assert payload["values"] == [0.4]
    assert payload["output_indices"] == [1]
    assert payload["rejected_indices"] == [0]


def test_version_mismatch_and_unapproved_detector_no_import(monkeypatch):
    import src.scanner_adapter_v2.adapters.garak_backend as module
    def forbidden(*args, **kwargs):
        raise AssertionError("scanner import forbidden")
    monkeypatch.setattr(module.importlib, "import_module", forbidden)
    for version, status in [("0.15.0", "configuration_error"), ("0.16.0", "unsupported")]:
        monkeypatch.setattr(module.metadata, "version", lambda name: version)
        with pytest.raises(BackendFailure) as exc:
            Garak016Backend().detect({}, config().to_dict())
        assert exc.value.status == status


def test_invalid_run_context_prevents_backend_call(replay):
    backend = FakeBackend([0.0])
    adapter = GarakDetectorAdapter(config(), backend=backend)
    prepared = adapter.prepare_input(replay, observation_surface="response_only")
    with pytest.raises(ValueError):
        adapter.execute(prepared, replay_case=replay,
                        run_context={"scanner_run_id": "r", "git_commit": "invalid",
                                     "execution_id": "e", "random_seed": 1})
    assert backend.calls == 0


def test_native_hook_with_official_shape_doubles_only(replay, monkeypatch):
    from types import SimpleNamespace
    import src.scanner_adapter_v2.adapters.garak_backend as module
    seen = {}
    class Message:
        def __init__(self, *, text):
            self.text = text
    class Attempt:
        def __init__(self, *, prompt):
            assert isinstance(prompt, Message)
            self.prompt = prompt
    class Detector:
        def __init__(self, *, config_root):
            seen["config_root"] = config_root
        def detect(self, attempt):
            seen["attempt"] = attempt
            return iter([0.25])
    modules = {"garak.attempt": SimpleNamespace(Attempt=Attempt, Message=Message),
               "garak.detectors.base": SimpleNamespace(Detector=Detector),
               "garak.detectors.synthetic": SimpleNamespace(Fixture=Detector)}
    monkeypatch.setattr(module.metadata, "version", lambda name: "0.16.0")
    monkeypatch.setattr(module.importlib, "import_module", lambda name: modules[name])
    # This subclass identifies the hook's fake native modules truthfully.
    class SyntheticHook(Garak016Backend):
        identifier = "synthetic-native-hook"
        synthetic = True
    backend = SyntheticHook(approved_detector_ids=("garak.detectors.synthetic.Fixture",))
    adapter = GarakDetectorAdapter(config(), backend=backend)
    prepared = adapter.prepare_input(replay, observation_surface="response_only")
    assert list(backend.detect(prepared, config().to_dict())) == [0.25]
    assert seen["attempt"].outputs == [replay.to_dict()["response_text"]]
    assert seen["config_root"] == {"detectors": {"synthetic": {"Fixture": {}}}}


def test_backend_mutation_cannot_change_prepared_input(replay):
    class MutatingBackend(FakeBackend):
        def detect(self, prepared, configuration):
            prepared["outputs"][0] = "backend changed its private copy"
            configuration["detector_config"]["options"]["local"] = True
            return [0.3]
    adapter = GarakDetectorAdapter(config(), backend=MutatingBackend([]))
    prepared = adapter.prepare_input(replay, observation_surface="response_only")
    before = copy.deepcopy(prepared)
    adapter.execute(prepared, replay_case=replay,
                    run_context={"scanner_run_id": "synthetic", "git_commit": "c" * 40,
                                 "execution_id": "1", "random_seed": None})
    assert prepared == before
    assert adapter.configuration.to_dict()["detector_config"]["options"] == {}
