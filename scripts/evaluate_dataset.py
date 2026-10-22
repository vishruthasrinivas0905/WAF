#!/usr/bin/env python3
"""Group-held-out evaluation for a licensed, labeled HTTP request CSV.

Required columns: raw request, binary label, and a grouping key such as
application or source. Optional columns: category and externally generated
model score in [0, 1]. The bundled prototype heuristic is not a Transformer.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from waf.application_profile.profile_engine import ApplicationProfileEngine
from waf.normalization.canonicalizer import Canonicalizer
from waf.pipeline import WafPipeline
from waf.rules.deterministic_engine import DeterministicRuleEngine
from waf.risk.policy_engine import PolicyEngine
from waf.inference.model_engine import create_default_scorer


def parse_label(value: str) -> int:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "attack", "malicious", "anomaly"}:
        return 1
    if normalized in {"0", "false", "benign", "valid", "normal"}:
        return 0
    raise ValueError(f"Unsupported label value {value!r}; expected 0/1 or benign/attack.")


def load_examples(args: argparse.Namespace) -> tuple[list[dict[str, Any]], str, int]:
    source_bytes = args.csv.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    canonicalizer = Canonicalizer()
    examples: dict[str, dict[str, Any]] = {}
    duplicate_count = 0

    with args.csv.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {args.request_column, args.label_column, args.group_column}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV missing required columns: {', '.join(sorted(missing))}")
        if args.model_score_column and args.model_score_column not in (reader.fieldnames or []):
            raise ValueError(f"Model score column not found: {args.model_score_column}")
        if args.category_column and args.category_column not in (reader.fieldnames or []):
            raise ValueError(f"Category column not found: {args.category_column}")

        for row_number, row in enumerate(reader, start=2):
            raw_request = (row.get(args.request_column) or "").strip()
            group = (row.get(args.group_column) or "").strip()
            if not raw_request or not group:
                raise ValueError(f"CSV row {row_number} has an empty request or group value.")

            label = parse_label(row.get(args.label_column) or "")
            parsed = canonicalizer.parse_raw_http_request(raw_request)
            canonical_text = parsed["canonical_text"]
            fingerprint = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
            model_score = None
            if args.model_score_column:
                raw_model_score = (row.get(args.model_score_column) or "").strip()
                if raw_model_score:
                    try:
                        model_score = float(raw_model_score)
                    except ValueError as exc:
                        raise ValueError(f"Invalid model score on CSV row {row_number}.") from exc
                    if not math.isfinite(model_score) or not 0 <= model_score <= 1:
                        raise ValueError(f"Model score on CSV row {row_number} must be within [0, 1].")

            example = {
                "fingerprint": fingerprint,
                "raw_request": raw_request,
                "label": label,
                "group": group,
                "category": (row.get(args.category_column) or "UNCATEGORIZED").strip() if args.category_column else "ALL",
                "model_score": model_score,
            }
            existing = examples.get(fingerprint)
            if existing:
                if existing["label"] != label:
                    raise ValueError(f"Conflicting labels for duplicate canonical request at row {row_number}.")
                duplicate_count += 1
                continue
            examples[fingerprint] = example

    return list(examples.values()), source_hash, duplicate_count


def grouped_split(examples: list[dict[str, Any]], test_size: float, validation_size: float, seed: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str], list[str]]:
    groups = sorted({example["group"] for example in examples})
    if len(groups) < 3:
        raise ValueError("Train/validation/test group splits require at least three distinct groups.")
    test_group_count = min(len(groups) - 2, max(1, math.ceil(len(groups) * test_size)))
    validation_group_count = min(len(groups) - test_group_count - 1, max(1, math.ceil(len(groups) * validation_size)))
    rng = random.Random(seed)
    single_class_test_candidate = None

    # Requests from a group remain together. Prefer a test fold with both classes;
    # allow a one-class fold for grouped attack-family generalization studies.
    for _ in range(10000):
        shuffled = groups[:]
        rng.shuffle(shuffled)
        test_groups = set(shuffled[:test_group_count])
        validation_groups = set(shuffled[test_group_count:test_group_count + validation_group_count])
        train = [item for item in examples if item["group"] not in test_groups | validation_groups]
        validation = [item for item in examples if item["group"] in validation_groups]
        test = [item for item in examples if item["group"] in test_groups]
        if {item["label"] for item in train} == {0, 1} and {item["label"] for item in validation} == {0, 1} and test:
            if {item["label"] for item in test} == {0, 1}:
                return train, validation, test, sorted(validation_groups), sorted(test_groups)
            if single_class_test_candidate is None:
                single_class_test_candidate = (train, validation, test, sorted(validation_groups), sorted(test_groups))
    if single_class_test_candidate:
        return single_class_test_candidate
    raise ValueError("Could not form group-held-out train/validation/test splits with both labels in train and validation. Choose a different grouping column or split sizes.")


def metric_values(rows: list[dict[str, Any]], predicted: list[int]) -> dict[str, float | int | None]:
    labels = [row["label"] for row in rows]
    tp = sum(y == 1 and p == 1 for y, p in zip(labels, predicted))
    tn = sum(y == 0 and p == 0 for y, p in zip(labels, predicted))
    fp = sum(y == 0 and p == 1 for y, p in zip(labels, predicted))
    fn = sum(y == 1 and p == 0 for y, p in zip(labels, predicted))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    fnr = fn / (fn + tp) if fn + tp else None
    f1 = (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and precision + recall else (0.0 if precision is not None and recall is not None else None)
    return {
        "n": len(rows), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": (tp + tn) / len(rows) if rows else None,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr, "fnr": fnr,
    }


def cluster_bootstrap_ci(rows: list[dict[str, Any]], predicted: list[int], seed: int, iterations: int) -> dict[str, list[float] | None]:
    groups: dict[str, list[tuple[dict[str, Any], int]]] = defaultdict(list)
    for row, prediction in zip(rows, predicted):
        groups[row["group"]].append((row, prediction))
    group_names = sorted(groups)
    metrics = ("accuracy", "precision", "recall", "f1", "fpr", "fnr")
    if len(group_names) < 2:
        return {name: None for name in metrics}

    rng = random.Random(seed)
    samples: dict[str, list[float]] = {name: [] for name in metrics}
    for _ in range(iterations):
        selected = [rng.choice(group_names) for _ in group_names]
        resampled_rows: list[dict[str, Any]] = []
        resampled_predictions: list[int] = []
        for group in selected:
            for row, prediction in groups[group]:
                resampled_rows.append(row)
                resampled_predictions.append(prediction)
        values = metric_values(resampled_rows, resampled_predictions)
        for name in metrics:
            value = values[name]
            if value is not None:
                samples[name].append(float(value))
    intervals = {}
    for name, values in samples.items():
        if len(values) < 100:
            intervals[name] = None
            continue
        ordered = sorted(values)
        low = ordered[int((len(ordered) - 1) * 0.025)]
        high = ordered[math.ceil((len(ordered) - 1) * 0.975)]
        intervals[name] = [round(low, 6), round(high, 6)]
    return intervals


def run(args: argparse.Namespace) -> dict[str, Any]:
    examples, dataset_hash, duplicate_count = load_examples(args)
    if args.model_scores_csv:
        score_map: dict[str, float] = {}
        with args.model_scores_csv.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not {"request_sha256", "model_score"}.issubset(set(reader.fieldnames or [])):
                raise ValueError("Score sidecar must contain request_sha256 and model_score columns.")
            for row_number, row in enumerate(reader, start=2):
                fingerprint = row["request_sha256"].strip()
                try:
                    score = float(row["model_score"])
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"Invalid model score in sidecar row {row_number}.") from exc
                if not fingerprint or not math.isfinite(score) or not 0 <= score <= 1:
                    raise ValueError(f"Invalid request hash or score in sidecar row {row_number}.")
                if fingerprint in score_map:
                    raise ValueError(f"Duplicate request hash in sidecar row {row_number}.")
                score_map[fingerprint] = score
        for example in examples:
            example["model_score"] = score_map.get(example["fingerprint"])
    train_rows, validation_rows, test_rows, validation_groups, test_groups = grouped_split(examples, args.test_size, args.validation_size, args.seed)
    has_model_scores = bool(args.model_score_column or args.model_scores_csv)
    if has_model_scores and any(row["model_score"] is None for row in test_rows):
        raise ValueError("Every held-out test row needs a finite external model score when --model-score-column is set.")
    scorer = create_default_scorer()
    rule_engine = DeterministicRuleEngine()
    profile_engine = ApplicationProfileEngine(app_id="group-held-out-evaluation")
    policy = PolicyEngine(mode="ENFORCING")
    hybrid_pipeline = WafPipeline(mode="ENFORCING", model_inference_fn=scorer.predict, app_id="group-held-out-evaluation")

    lanes: dict[str, list[int]] = {"rules_only": [], "heuristic_only": [], "hybrid_rules_heuristic": []}
    if has_model_scores:
        lanes["external_model_only"] = []
        lanes["hybrid_rules_external_model"] = []
    prediction_rows: list[dict[str, Any]] = []

    for row in test_rows:
        parsed = hybrid_pipeline.canonicalizer.parse_raw_http_request(row["raw_request"])
        det_score, matches = rule_engine.inspect(parsed)
        heuristic_score = scorer.predict(parsed["canonical_text"])
        profile_eval = profile_engine.evaluate(parsed)
        app_score = profile_eval.get("profile_score", 0.0)
        rule_decision = policy.evaluate(det_score, 0.0, app_score, matches, parsed["anomaly_flags"]).action
        heuristic_prediction = int(heuristic_score >= args.heuristic_threshold)
        hybrid_event = hybrid_pipeline.inspect_request(row["raw_request"])

        predictions = {
            "rules_only": int(rule_decision == "BLOCK"),
            "heuristic_only": heuristic_prediction,
            "hybrid_rules_heuristic": int(hybrid_event["decision"] == "BLOCK"),
        }
        if has_model_scores:
            model_score = float(row["model_score"])
            predictions["external_model_only"] = int(model_score >= args.model_threshold)
            model_pipeline = WafPipeline(
                mode="ENFORCING",
                model_inference_fn=lambda _text, value=model_score: value,
                app_id="group-held-out-evaluation",
            )
            model_event = model_pipeline.inspect_request(row["raw_request"])
            predictions["hybrid_rules_external_model"] = int(model_event["decision"] == "BLOCK")

        for lane, prediction in predictions.items():
            lanes[lane].append(prediction)
        prediction_rows.append({
            "request_sha256": row["fingerprint"],
            "group": row["group"],
            "category": row["category"],
            "actual": row["label"],
            "deterministic_score": round(det_score, 6),
            "heuristic_score": round(heuristic_score, 6),
            "external_model_score": row["model_score"],
            **{f"predicted_{name}": value for name, value in predictions.items()},
        })

    metrics: dict[str, Any] = {}
    for lane, predicted in lanes.items():
        metrics[lane] = {
            **metric_values(test_rows, predicted),
            "cluster_bootstrap_95pct_ci": cluster_bootstrap_ci(test_rows, predicted, args.seed + 1, args.bootstrap_iterations),
        }

    category_report: dict[str, Any] = {}
    categories = sorted({row["category"] for row in test_rows})
    for category in categories:
        indexes = [i for i, row in enumerate(test_rows) if row["category"] == category]
        cat_rows = [test_rows[i] for i in indexes]
        category_report[category] = {
            lane: {
                **metric_values(cat_rows, [predicted[i] for i in indexes]),
                "cluster_bootstrap_95pct_ci": cluster_bootstrap_ci(cat_rows, [predicted[i] for i in indexes], args.seed + 1, args.bootstrap_iterations),
            }
            for lane, predicted in lanes.items()
        }

    report = {
        "schema_version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_file": args.csv.name,
        "dataset_sha256": dataset_hash,
        "deduplication": {"method": "SHA-256 of canonical request text", "duplicates_removed": duplicate_count, "unique_rows": len(examples)},
        "split": {
            "method": "group-held-out train/validation/test", "group_column": args.group_column,
            "test_size_requested": args.test_size, "validation_size_requested": args.validation_size, "random_seed": args.seed,
            "train_rows": len(train_rows), "validation_rows": len(validation_rows), "test_rows": len(test_rows),
            "train_groups": len({row["group"] for row in train_rows}), "validation_groups": len(validation_groups), "test_groups": len(test_groups),
            "validation_group_values": validation_groups,
            "test_group_values": test_groups,
            "test_label_classes": sorted({row["label"] for row in test_rows}),
        },
        "score_method": {
            "heuristic": "bundled lexical/entropy heuristic; not a trained model",
            "external_model": args.model_score_column or (args.model_scores_csv.name if args.model_scores_csv else None),
            "heuristic_threshold": args.heuristic_threshold,
            "model_threshold": args.model_threshold if has_model_scores else None,
            "policy": "bundled deterministic/risk policy; thresholds fixed before evaluation",
        },
        "confidence_intervals": {
            "method": "percentile cluster bootstrap over test groups",
            "iterations": args.bootstrap_iterations,
            "note": "Intervals are unavailable with fewer than two held-out groups; single-class test partitions leave class-specific rates undefined.",
        },
        "results": metrics,
        "per_category_test_results": category_report,
        "limitations": [
            "This script evaluates existing scores and rules; it does not train a Transformer.",
            "Train external models on train groups, select thresholds on validation groups, and generate test scores without test-label access.",
            "Group split quality depends on the supplied grouping key and dataset provenance.",
        ],
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.output_dir / "evaluation_report.json"
    predictions_path = args.output_dir / "test_predictions.csv"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    split_by_fingerprint = {row["fingerprint"]: "train" for row in train_rows}
    split_by_fingerprint.update({row["fingerprint"]: "validation" for row in validation_rows})
    split_by_fingerprint.update({row["fingerprint"]: "test" for row in test_rows})
    with (args.output_dir / "split_assignments.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["request_sha256", "group", "split"])
        writer.writeheader()
        for row in examples:
            writer.writerow({"request_sha256": row["fingerprint"], "group": row["group"], "split": split_by_fingerprint[row["fingerprint"]]})
    if prediction_rows:
        with predictions_path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(prediction_rows[0]))
            writer.writeheader()
            writer.writerows(prediction_rows)
    print(json.dumps({"report": str(report_path), "predictions": str(predictions_path), "unique_rows": len(examples), "test_rows": len(test_rows), "metrics": metrics}, indent=2))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path, help="Licensed dataset CSV with one request per row")
    parser.add_argument("--request-column", default="request")
    parser.add_argument("--label-column", default="is_attack")
    parser.add_argument("--group-column", required=True, help="Application/source/family grouping key; all rows in a group stay in one split")
    parser.add_argument("--category-column", default="category", help="Per-category analysis; optional if column is absent")
    parser.add_argument("--model-score-column", help="Optional precomputed external model probability column")
    parser.add_argument("--model-scores-csv", type=Path, help="Optional sidecar with request_sha256,model_score columns (for train_transformer.py output)")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--validation-size", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--heuristic-threshold", type=float, default=0.7)
    parser.add_argument("--model-threshold", type=float, default=0.5)
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "evaluation_results")
    args = parser.parse_args()
    if not 0.05 <= args.test_size <= 0.5 or not 0.05 <= args.validation_size <= 0.3 or args.test_size + args.validation_size >= 0.8:
        parser.error("test size must be 0.05-0.5, validation size 0.05-0.3, and their sum less than 0.8")
    if not 0 <= args.heuristic_threshold <= 1 or not 0 <= args.model_threshold <= 1:
        parser.error("score thresholds must be between 0 and 1")
    if args.model_score_column and args.model_scores_csv:
        parser.error("use either --model-score-column or --model-scores-csv, not both")
    if args.bootstrap_iterations < 100:
        parser.error("--bootstrap-iterations must be at least 100")
    if args.category_column and args.csv.exists():
        with args.csv.open("r", encoding="utf-8-sig", newline="") as stream:
            headers = next(csv.reader(stream), [])
        if args.category_column not in headers:
            args.category_column = None
    run(args)


if __name__ == "__main__":
    main()
