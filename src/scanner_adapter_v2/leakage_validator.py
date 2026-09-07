"""Key-semantic leakage checks. Text values are opaque, never classified."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping


class LeakageError(ValueError):
    """Forbidden field found; includes its exact JSON path, never its value."""


FORBIDDEN_CATEGORIES = (
    "Dataset A labels/classes/GT rationale", "Outcome GT and Outcome Rule verdicts",
    "Judge A/B decisions/evidence/rationale/disagreement", "scanner GT/correctness/results",
    "legacy passed/PASS/FAIL", "response-derived objectives/rules",
)
FORBIDDEN_KEYS = frozenset({
    "pistatus", "pilabel", "maliciousness", "derivedclass", "finalclass", "boundaryclass",
    "casegt", "sourcecasegt", "gtrationale", "groundtruth", "outcomegt", "outcomelabel",
    "finallabel", "finaldecision", "verdict", "decision", "rationale", "evidence", "evidencespans",
    "disagreement", "passed", "pass", "fail", "passfail", "expectedcorrectness",
    "attackergoalachieved", "boundaryviolated", "normaltaskcompleted", "original_label",
})


def normalized_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", key).casefold())


def forbidden_key(key: str) -> bool:
    name = normalized_key(key)
    if name in FORBIDDEN_KEYS or name == "originallabel" or name.endswith(("passed", "passfail")):
        return True
    if any(part in name for part in ("pistatus", "pilabel", "maliciousness", "derivedclass",
                                     "finalclass", "boundaryclass", "outcomegt", "casegt", "groundtruth", "gtrationale")):
        return True
    if "judge" in name or "scanner" in name:
        return True
    if "outcomerule" in name:
        return True
    return ("objective" in name or "rule" in name) and any(
        part in name for part in ("response", "posthoc", "observed", "inferred", "derived"))


def validate_no_leakage(value, path: str = "$") -> None:
    """Recursively reject key variants in mappings/lists without changing content.

    Use on the explicitly selected source projection and on the completed case.
    This is defense in depth; a closed schema also rejects unknown aliases.
    It intentionally does not parse JSON-looking strings in prompt/response text.
    """
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise LeakageError(f"{path}: non-string key")
            child_path = f"{path}.{key}"
            if forbidden_key(key):
                raise LeakageError(f"{child_path}: forbidden field")
            name = normalized_key(key)
            # These are contract metadata fields, not free-form content strings.
            # No objective source has been verified for this version.
            if (name == "attackobjective" and child is not None
                    or name == "objectivestatus" and child != "unavailable"
                    or name == "objectiveprovenance" and child != "no_verified_response_independent_source"):
                raise LeakageError(f"{child_path}: unverified objective metadata")
            validate_no_leakage(child, child_path)
    elif isinstance(value, (list, tuple)):
        for i, child in enumerate(value):
            validate_no_leakage(child, f"{path}[{i}]")
