#!/usr/bin/env python3
"""Create deduplicated, group-held-out train/validation/test CSVs.

Outputs the filenames expected by train_transformer.py and a hash-based split
manifest. Keep the licensed source and generated splits outside Git unless the
license explicitly permits redistribution.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.evaluate_dataset import grouped_split, load_examples


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--group-column", required=True)
    parser.add_argument("--request-column", default="request")
    parser.add_argument("--label-column", default="is_attack")
    parser.add_argument("--category-column", default="category")
    parser.add_argument("--fingerprint-column", default=None, help="Optional canonical SHA-256 column to avoid reparsing requests")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--validation-size", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.test_size <= 0 or args.validation_size <= 0 or args.test_size + args.validation_size >= 0.8:
        parser.error("test and validation sizes must be positive and sum to less than 0.8")

    loader_args = argparse.Namespace(
        csv=args.csv,
        request_column=args.request_column,
        label_column=args.label_column,
        group_column=args.group_column,
        category_column=args.category_column,
        fingerprint_column=args.fingerprint_column,
        model_score_column=None,
    )
    examples, source_hash, duplicates = load_examples(loader_args)
    train_rows, validation_rows, test_rows, validation_groups, test_groups = grouped_split(
        examples, args.test_size, args.validation_size, args.seed
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)

    split_data = {
        "transformer_train.csv": train_rows,
        "transformer_val.csv": validation_rows,
        "transformer_test.csv": test_rows,
    }
    assignments = []
    for split_name, rows in split_data.items():
        split_label = {"transformer_train.csv": "train", "transformer_val.csv": "validation", "transformer_test.csv": "test"}[split_name]
        out_path = args.output_dir / split_name
        with out_path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=["request", "is_attack", "group", "request_sha256", "category"])
            writer.writeheader()
            for row in rows:
                writer.writerow({"request": row["raw_request"], "is_attack": row["label"], "group": row["group"], "request_sha256": row["fingerprint"], "category": row["category"]})
                assignments.append({"request_sha256": row["fingerprint"], "group": row["group"], "split": split_label})

    with (args.output_dir / "split_assignments.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["request_sha256", "group", "split"])
        writer.writeheader()
        writer.writerows(assignments)

    manifest = {
        "source_file": args.csv.name,
        "source_sha256": source_hash,
        "canonical_duplicates_removed": duplicates,
        "unique_rows": len(examples),
        "group_column": args.group_column,
        "seed": args.seed,
        "test_size": args.test_size,
        "validation_size": args.validation_size,
        "validation_groups": validation_groups,
        "test_groups": test_groups,
        "rows": {name: len(rows) for name, rows in split_data.items()},
        "warning": "This script does not verify dataset licensing, label quality, or application-family semantics.",
    }
    (args.output_dir / "split_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
