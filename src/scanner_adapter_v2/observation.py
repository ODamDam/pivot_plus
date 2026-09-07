"""Pure, scanner-independent evaluator content projections."""
from __future__ import annotations

from .contract import CONTEXT_FIELDS, SURFACES, ScannerReplayCase
from .leakage_validator import validate_no_leakage


def project_observation(replay_case: ScannerReplayCase, surface: str) -> dict:
    if surface not in SURFACES:
        raise ValueError("unsupported observation surface")
    case = replay_case.to_dict()
    content = {"response_text": case["response_text"]}
    if surface == "request_and_response":
        content["model_visible_messages"] = case["model_visible_messages"]
    elif surface == "trusted_context_untrusted_input_and_response":
        for key in CONTEXT_FIELDS:
            content[key] = case[key]
    observation = {"observation_surface": surface, "content": content}
    validate_no_leakage(observation)
    return observation
