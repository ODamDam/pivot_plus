from garak.attempt import Attempt

from scanner_input.core.data_models import VulnRecord
from scanner_input.config import PROBE_CLASSNAME_DEFAULT, SEQ_DEFAULT


def build_attempt(record: VulnRecord) -> Attempt:
    attempt = Attempt()

    attempt.prompt = record.mutated_prompt
    attempt.outputs = [record.model_output]

    attempt.goal = record.bucket_id

    attempt.status = 1

    attempt.probe_classname = PROBE_CLASSNAME_DEFAULT
    attempt.seq = SEQ_DEFAULT

    notes = {"seed_id": record.seed_id}

    if record.triggers:
        notes["triggers"] = record.triggers

    attempt.notes = notes

    return attempt