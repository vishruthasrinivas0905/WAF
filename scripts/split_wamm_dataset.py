#!/usr/bin/env python3
"""Stream and deduplicate the prepared WAMM CSV into reproducible splits.

Split assignment is a seeded SHA-256 bucket of each host-aware canonical
request fingerprint. This is a request-level split, not a cross-site split.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

csv.field_size_limit(2**31 - 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    train_path = args.output_dir / "transformer_train.csv"
    val_path = args.output_dir / "transformer_val.csv"
    test_path = args.output_dir / "transformer_test.csv"
    assignments_path = args.output_dir / "split_assignments.csv"
    outputs = {
        "train": train_path.open("w", newline="", encoding="utf-8"),
        "validation": val_path.open("w", newline="", encoding="utf-8"),
        "test": test_path.open("w", newline="", encoding="utf-8"),
    }
    assignment_stream = assignments_path.open("w", newline="", encoding="utf-8")
    fields = ["request", "is_attack", "group", "request_sha256", "category"]
    writers = {split: csv.DictWriter(stream, fieldnames=fields) for split, stream in outputs.items()}
    assignment_writer = csv.DictWriter(assignment_stream, fieldnames=["request_sha256", "group", "split"])
    for writer in writers.values():
        writer.writeheader()
    assignment_writer.writeheader()

    seen: set[str] = set()
    row_counts: dict[str, Counter[str]] = {name: Counter() for name in outputs}
    duplicate_count = 0
    try:
        with args.csv.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            required = {"request", "is_attack", "group", "request_sha256", "category"}
            missing = required - set(reader.fieldnames or [])
            if missing:
                raise ValueError(f"CSV missing columns: {', '.join(sorted(missing))}")
            for row_number, row in enumerate(reader, start=2):
                fingerprint = (row.get("request_sha256") or "").strip().lower()
                if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
                    raise ValueError(f"Invalid request SHA-256 on row {row_number}")
                if fingerprint in seen:
                    duplicate_count += 1
                    continue
                seen.add(fingerprint)
                bucket = int(hashlib.sha256(f"{args.seed}:{fingerprint}".encode()).hexdigest()[:8], 16) % 100
                split = "train" if bucket < 70 else "validation" if bucket < 80 else "test"
                label = (row.get("is_attack") or "").strip()
                if label not in {"0", "1"}:
                    raise ValueError(f"Invalid binary label on row {row_number}: {label!r}")
                writers[split].writerow(row)
                assignment_writer.writerow({"request_sha256": fingerprint, "group": row["group"], "split": split})
                row_counts[split][label] += 1
    finally:
        for stream in outputs.values():
            stream.close()
        assignment_stream.close()

    with args.csv.open("rb") as source_stream:
        dataset_digest = hashlib.file_digest(source_stream, "sha256").hexdigest()
    manifest = {
        "dataset_file": args.csv.name,
        "dataset_sha256": dataset_digest,
        "split_method": "seeded SHA-256 request-level buckets after host-aware canonical deduplication",
        "seed": args.seed,
        "requested_bucket_percentages": {"train": 70, "validation": 10, "test": 20},
        "unique_fingerprints": len(seen),
        "duplicate_rows_removed": duplicate_count,
        "rows_by_split_and_label": {split: dict(counts) for split, counts in row_counts.items()},
        "limitations": [
            "The source does not provide a reliable application-family grouping column; this is not a cross-site generalization test.",
            "Split percentages are hash-bucket approximations and are not forced to exact per-class counts.",
        ],
    }
    (args.output_dir / "split_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
