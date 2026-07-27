from scanner_input.core.data_models import VulnRecord


def build_input(record: VulnRecord) -> dict:
    return {
        "seed_id": record.seed_id,
        "prompt": record.mutated_prompt,
        "response": record.model_output,
        "goal": record.bucket_id, 
    }