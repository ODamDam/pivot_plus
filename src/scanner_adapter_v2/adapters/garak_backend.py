"""Lazy, opt-in Garak 0.16 hooks. No scanner import during module loading."""
from __future__ import annotations

import importlib
from importlib import metadata
from typing import Protocol


class BackendFailure(Exception):
    """Typed operational failure without exception payloads or credentials."""

    def __init__(self, status, error_type):
        super().__init__(error_type)
        self.status = status
        self.error_type = error_type


class GarakDetectorBackend(Protocol):
    identifier: str
    synthetic: bool

    def detect(self, prepared: dict, configuration: dict):
        """Return the native per-output iterable; do not normalize scores."""
        ...


class Garak016Backend:
    """Real smoke hook, disabled unless a detector is explicitly allowlisted.

    Allowlisting is a later operator decision after reviewing constructor, config,
    response-only consumption and offline behavior. This is not process isolation.
    Run only inside a separately approved isolated worker/environment.
    """

    identifier = "garak-0.16.0-lazy-hook"
    synthetic = False

    def __init__(self, *, approved_detector_ids=()):
        self.approved_detector_ids = frozenset(approved_detector_ids)

    def detect(self, prepared, configuration):
        try:
            installed = metadata.version("garak")  # SMOKE: distribution/version
        except metadata.PackageNotFoundError:
            raise BackendFailure("dependency_error", "dependency_error") from None
        if installed != "0.16.0":
            raise BackendFailure("configuration_error", "configuration_error")
        identifier = configuration["detector_id"]
        if identifier not in self.approved_detector_ids:
            raise BackendFailure("unsupported", "unsupported_result")
        module_name, class_name = identifier.rsplit(".", 1)
        try:
            module = importlib.import_module(module_name)  # SMOKE: detector resolver
            detector_class = getattr(module, class_name)
            native = importlib.import_module("garak.attempt")
            base = importlib.import_module("garak.detectors.base")
        except ModuleNotFoundError as exc:
            status = "configuration_error" if exc.name == module_name else "dependency_error"
            raise BackendFailure(status, status) from None
        except (ImportError, AttributeError):
            raise BackendFailure("configuration_error", "configuration_error") from None
        if not isinstance(detector_class, type) or not issubclass(detector_class, base.Detector):
            raise BackendFailure("configuration_error", "configuration_error")
        namespace = module_name.rsplit(".", 1)[1]
        options = configuration["detector_config"]["options"]
        config_root = {"detectors": {namespace: {class_name: options}}}
        try:
            detector = detector_class(config_root=config_root)  # SMOKE: isolated config
            attempt = native.Attempt(prompt=native.Message(text=prepared["prompt"]["text"]))
            attempt.outputs = list(prepared["outputs"])  # SMOKE: one unchanged response
        except ModuleNotFoundError:
            raise BackendFailure("dependency_error", "dependency_error") from None
        except Exception:
            raise BackendFailure("configuration_error", "configuration_error") from None
        return detector.detect(attempt)  # SMOKE: detector-only, iterator may raise later
