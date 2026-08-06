from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from src.dataset.loader import load_dataset_records
from src.generation.message_builder import MessageBuilder
from src.generation.models import ExcludedGenerationInput


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--input-view",
        choices=["prompt_only", "context_prompt"],
        required=True,
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    records = load_dataset_records(args.dataset)
    builder = MessageBuilder()

    included = []
    excluded = []

    for record in records:
        result = builder.build(
            record,
            args.input_view,
        )

        if isinstance(result, ExcludedGenerationInput):
            excluded.append(result)
        else:
            included.append(result)

    print(
        json.dumps(
            {
                "dataset_rows": len(records),
                "included_rows": len(included),
                "excluded_rows": len(excluded),
                "included_subset_counts": dict(
                    Counter(
                        item.dataset_subset
                        for item in included
                    )
                ),
                "excluded_reason_counts": dict(
                    Counter(
                        item.reason
                        for item in excluded
                    )
                ),
                "context_type_counts": dict(
                    Counter(
                        item.context_type
                        for item in included
                    )
                ),
            },
            ensure_ascii=False,
            indent=2,
        )
    )

    if included:
        print("\nFirst included record:")
        print(
            json.dumps(
                included[0].to_dict(),
                ensure_ascii=False,
                indent=2,
            )
        )

    if excluded:
        print("\nFirst excluded record:")
        print(
            json.dumps(
                excluded[0].to_dict(),
                ensure_ascii=False,
                indent=2,
            )
        )


if __name__ == "__main__":
    main()