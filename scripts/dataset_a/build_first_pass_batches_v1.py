import json
from pathlib import Path

INPUT = Path(
    "data/dataset_a/adjudication/first_pass_v1/"
    "dataset_a_first_pass_1500_v1.jsonl"
)

OUTPUT_DIR = Path(
    "data/dataset_a/adjudication/first_pass_v1/batches"
)

BATCH_SIZE = 50


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    records = []

    with INPUT.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                raise RuntimeError(
                    f"Invalid JSON at line {line_no}: {e}"
                ) from e

            records.append(record)

    if len(records) != 1500:
        raise RuntimeError(
            f"Expected 1500 records, got {len(records)}"
        )

    batch_count = 0

    for start in range(0, len(records), BATCH_SIZE):
        batch = records[start:start + BATCH_SIZE]
        batch_count += 1

        output = OUTPUT_DIR / (
            f"dataset_a_first_pass_batch_{batch_count:02d}_v1.jsonl"
        )

        with output.open("w", encoding="utf-8") as f:
            for record in batch:
                f.write(
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                )

        print(
            f"{output.name}: "
            f"{len(batch)} records "
            f"({batch[0]['candidate_id']} "
            f"~ {batch[-1]['candidate_id']})"
        )

    print()
    print(f"total records = {len(records)}")
    print(f"batch size    = {BATCH_SIZE}")
    print(f"batch count   = {batch_count}")


if __name__ == "__main__":
    main()