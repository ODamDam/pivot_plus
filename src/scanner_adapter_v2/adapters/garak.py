"""Response-only frozen replay boundary. No generators, probes or aggregation."""
from __future__ import annotations

import copy
import json
import platform
import re
from dataclasses import dataclass

from ..contract import ScannerReplayCase, validate_replay_case
from ..leakage_validator import validate_no_leakage
from ..normalization import normalize_raw_result
from ..results import (
    LINEAGE_FIELDS, ScannerNormalizedResult, build_raw_result, canonical_hash,
    canonical_json, validate_document, validate_normalized_result, validate_result_leakage,
)
from .garak_backend import BackendFailure, Garak016Backend, GarakDetectorBackend

CONFIG_KEYS = {"scanner_version", "detector_id", "detector_version", "adapter_version",
               "observation_surface", "response_only_basis", "native_direction",
               "detector_config", "mapping_policy"}
ABSTENTION_POLICY = {
    "identity": "garak-no-threshold-abstention", "version": "1",
    "basis": "No registered threshold: retain native numeric value without a verdict decision.",
}
MAX_NATIVE_VALUES = 1024


def _text(value):
    return type(value) is str and bool(value.strip())


@dataclass(frozen=True)
class GarakAdapterConfig:
    _serialized: str

    def __post_init__(self):
        data = json.loads(self._serialized)
        canonical_json(data)
        validate_result_leakage(data)
        if type(data) is not dict or set(data) != CONFIG_KEYS:
            raise ValueError("configuration: unexpected/missing fields")
        for key in ("detector_id", "detector_version", "adapter_version", "response_only_basis"):
            if not _text(data[key]):
                raise ValueError("configuration: missing identity or response-only evidence")
        if data["scanner_version"] != "0.16.0":
            raise ValueError("configuration: only Garak 0.16.0 audited")
        if not re.fullmatch(r"garak\.detectors\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*",
                            data["detector_id"]):
            raise ValueError("configuration: invalid detector identifier")
        if data["observation_surface"] != "response_only":
            raise ValueError("configuration: unsupported surface")
        if data["native_direction"] not in ("higher_is_more_suspicious", "lower_is_more_suspicious"):
            raise ValueError("configuration: explicit native direction required")
        detector = data["detector_config"]
        if (type(detector) is not dict or set(detector) != {"identity", "options"}
                or not _text(detector["identity"]) or type(detector["options"]) is not dict):
            raise ValueError("configuration: invalid detector config")
        validate_no_leakage(detector["options"], "$.detector_config.options")
        policy = data["mapping_policy"]
        if policy is not None:
            validate_document(policy, "scanner_mapping_policy_v1.schema.json")
            if (policy["scanner"] != {"name": "garak", "version": "0.16.0"}
                    or policy["evaluator"] != {"name": data["detector_id"], "version": data["detector_version"]}
                    or policy["kind"] != "numeric_threshold"
                    or policy["value_path"] != ["values", 0]
                    or policy["native_direction"] != data["native_direction"]):
                raise ValueError("configuration: mapping scope mismatch")
            # Garak detect supplies scores, not a threshold object. A registered
            # evaluator contract must explicitly own the threshold for this hook.
            if policy["threshold"]["source"] != "evaluator_contract":
                raise ValueError("configuration: native threshold not supplied by this backend")

    @classmethod
    def from_dict(cls, data):
        return cls(canonical_json(data))

    def to_dict(self):
        return json.loads(self._serialized)


class GarakDetectorAdapter:
    def __init__(self, configuration: GarakAdapterConfig, *, backend: GarakDetectorBackend = None):
        self.configuration = configuration
        self.backend = backend if backend is not None else Garak016Backend()
        if not _text(self.backend.identifier) or type(self.backend.synthetic) is not bool:
            raise ValueError("backend: explicit identity and synthetic marker required")

    def _configuration(self):
        return self.configuration.to_dict()

    def prepare_input(self, replay_case: ScannerReplayCase, *, observation_surface: str) -> dict:
        if observation_surface != "response_only":
            raise ValueError("unsupported observation surface")
        case = replay_case.to_dict()
        validate_replay_case(case)  # Recompute SHA, including on forged caller objects.
        config = self._configuration()
        return {
            "schema_version": "garak_frozen_input.v1",
            "generation_id": case["generation_id"],
            "production_case_id": case["production_case_id"],
            "observation_surface": "response_only",
            "prompt": {"text": ""},  # Structural Message, never a fabricated request.
            "outputs": [case["response_text"]],
            "response_sha256": case["response_sha256"],
            "configuration": config,
            "configuration_sha256": canonical_hash(config),
            "backend": {"identifier": self.backend.identifier, "synthetic": self.backend.synthetic},
        }

    def evaluation_id(self, replay_case):
        prepared = self.prepare_input(replay_case, observation_surface="response_only")
        # Bind the full replay lineage and input/config; never include scores or GT.
        identity = {"scanner": "garak", "replay_sha256": canonical_hash(replay_case.to_dict()),
                    "input_sha256": canonical_hash(prepared)}
        return "garak-eval-v1-" + canonical_hash(identity)

    def execute(self, prepared_input, *, replay_case, run_context):
        config = self._configuration()
        expected = self.prepare_input(replay_case, observation_surface="response_only")
        validate_result_leakage(prepared_input)
        if canonical_json(prepared_input) != canonical_json(expected):
            raise ValueError("prepared input does not match replay/configuration")
        if type(run_context) is not dict or set(run_context) != {
                "scanner_run_id", "git_commit", "execution_id", "random_seed"}:
            raise ValueError("run_context: explicit closed run metadata required")
        validate_result_leakage(run_context)
        runtime = {"identifier": self.backend.identifier, "python_version": platform.python_version(),
                   "dependencies": []}
        provenance = {
            "adapter_version": config["adapter_version"], "git_commit": run_context["git_commit"],
            "execution_id": run_context["execution_id"], "random_seed": run_context["random_seed"],
            "configuration": {"identity": "garak-config-" + canonical_hash(config),
                              "sha256": canonical_hash(config)},
            "runtime": runtime, "llm_judge": None,
        }
        arguments = dict(
            scanner_run_id=run_context["scanner_run_id"], evaluation_id=self.evaluation_id(replay_case),
            scanner={"name": "garak", "version": config["scanner_version"]},
            evaluator={"name": config["detector_id"], "version": config["detector_version"],
                       "kind": "deterministic"},
            observation_surface="response_only", evaluator_input=expected, provenance=provenance)
        # Validate metadata BEFORE a backend can run.
        build_raw_result(replay_case, **arguments, execution_status="skipped",
                         error_type=None, native_output=None)
        status, error, values, complete, rejected = "success", None, [], False, []
        indices = []
        try:
            output = self.backend.detect(copy.deepcopy(expected), copy.deepcopy(config))
            if isinstance(output, (str, bytes, dict)) or output is None:
                raise BackendFailure("error", "invalid_native_result")
            try:
                iterator = iter(output)
            except TypeError:
                raise BackendFailure("error", "invalid_native_result") from None
            for index, value in enumerate(iterator):
                if index >= MAX_NATIVE_VALUES:
                    raise BackendFailure("error", "invalid_native_result")
                try:
                    canonical_json(value)
                    validate_result_leakage(value)
                except ValueError:
                    # Non-JSON/non-finite/leaking output cannot cross the contract.
                    # Record a rejection location, never repr()/coerce/drop silently.
                    rejected.append(index)
                    status, error = "error", "invalid_native_result"
                    continue
                values.append(value)
                indices.append(index)
                if value is not None and type(value) not in (int, float):
                    status, error = "error", "invalid_native_result"
            complete = True
            if rejected or len(values) != len(expected["outputs"]):
                status, error = "error", "invalid_native_result"
            elif values[0] is None and error is None:
                status, error = "unsupported", "unsupported_result"
        except BackendFailure as exc:
            status, error = exc.status, exc.error_type
        except TimeoutError:
            status, error = "timeout", "timeout"
        except Exception:
            status, error = "error", "evaluator_error"
        payload = {
            "values": values, "output_indices": indices,
            "expected_output_count": 1, "iteration_complete": complete,
            "rejected_indices": rejected,
            "detector": {"identifier": config["detector_id"], "version": config["detector_version"]},
            "detector_config": {"identity": config["detector_config"]["identity"],
                                "sha256": canonical_hash(config["detector_config"]["options"])},
            "mapping_policy": self._policy_identity(),
            "backend": expected["backend"],
        }
        if status == "success" and not self.backend.synthetic:
            runtime["dependencies"] = [{"name": "garak", "version": config["scanner_version"]}]
        return build_raw_result(replay_case, **arguments, execution_status=status,
                                error_type=error, native_output=payload)

    def _policy_identity(self):
        policy = self._configuration()["mapping_policy"]
        if policy is None:
            return dict(ABSTENTION_POLICY, sha256=canonical_hash(ABSTENTION_POLICY))
        return {"identity": policy["policy_id"], "version": policy["version"],
                "basis": policy["basis"], "sha256": canonical_hash(policy)}

    def normalize(self, raw_result, mapping_policy=None):
        config = self._configuration()
        if canonical_json(mapping_policy) != canonical_json(config["mapping_policy"]):
            raise ValueError("mapping policy differs from configuration")
        raw = raw_result.to_dict()
        if (raw["scanner"] != {"name": "garak", "version": config["scanner_version"]}
                or raw["evaluator"] != {"name": config["detector_id"], "version": config["detector_version"],
                                        "kind": "deterministic"}
                or raw["provenance"]["configuration"]["sha256"] != canonical_hash(config)
                or raw["provenance"]["runtime"]["identifier"] != self.backend.identifier):
            raise ValueError("raw result belongs to another adapter configuration")
        identity = {"scanner": "garak", "replay_sha256": raw["replay_case"]["sha256"],
                    "input_sha256": raw["evaluator_input"]["sha256"]}
        if raw["evaluation_id"] != "garak-eval-v1-" + canonical_hash(identity):
            raise ValueError("raw evaluation identity mismatch")
        payload = raw["native_output"]
        if (type(payload) is not dict or payload.get("mapping_policy") != self._policy_identity()
                or payload.get("backend") != {"identifier": self.backend.identifier,
                                              "synthetic": self.backend.synthetic}):
            raise ValueError("raw adapter payload mismatch")
        if raw["execution_status"] == "success":
            values = payload.get("values")
            if (type(values) is not list or len(values) != 1 or type(values[0]) not in (int, float)
                    or payload.get("output_indices") != [0] or payload.get("rejected_indices") != []
                    or payload.get("iteration_complete") is not True
                    or payload.get("expected_output_count") != 1):
                raise ValueError("invalid native success payload")
        if mapping_policy is not None:
            return normalize_raw_result(raw_result, mapping_policy)
        # Generic v1 requires a threshold for numeric mapping. A local abstention
        # path preserves the numeric score without extending that policy/schema.
        result = {key: raw[key] for key in LINEAGE_FIELDS}
        success = raw["execution_status"] == "success"
        value = raw["native_output"]["values"][0] if success else None
        result.update(
            schema_version="scanner_normalized_result.v1",
            raw_result={"identity": raw["evaluation_id"], "sha256": canonical_hash(raw)},
            normalized_verdict="indeterminate" if success else "no_result",
            normalization_error="unsupported_result" if success else None,
            native_value=value, native_score=value,
            native_score_type="numeric" if success else "unavailable",
            native_threshold=None, threshold_source=None,
            native_direction=config["native_direction"] if success else None,
            mapping_policy=self._policy_identity())
        validate_normalized_result(result, raw_result=raw_result)
        return ScannerNormalizedResult.from_dict(result)
