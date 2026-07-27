from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class VulnRecord:
    seed_id: str
    mutated_prompt: str
    model_output: str
    bucket_id: str
    triggers: Optional[List[str]] = field(default=None)