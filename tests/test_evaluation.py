import csv
import argparse
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.evaluate_dataset import grouped_split, load_baseline_sidecar, metric_values, run
from scripts.score_http_baseline import local_origin, request_parts
from waf.normalization.canonicalizer import Canonicalizer


class TestEvaluationHelpers(unittest.TestCase):
    def test_grouped_split_keeps_groups_disjoint(self):
        rows = [
            {"group": f"app-{group}", "label": label}
            for group in range(20)
            for label in (0, 1)
        ]
        train, validation, test, _, _ = grouped_split(rows, 0.2, 0.1, 42)
        train_groups = {row["group"] for row in train}
        validation_groups = {row["group"] for row in validation}
        test_groups = {row["group"] for row in test}
        self.assertFalse(train_groups & validation_groups)
        self.assertFalse(train_groups & test_groups)
        self.assertFalse(validation_groups & test_groups)
        self.assertEqual({row["label"] for row in train}, {0, 1})
        self.assertEqual({row["label"] for row in validation}, {0, 1})

    def test_metric_nulls_when_class_missing(self):
        values = metric_values([{"label": 1}], [1])
        self.assertIsNone(values["fpr"])
        self.assertEqual(values["recall"], 1.0)

    def test_baseline_sidecar_requires_hashed_binary_predictions(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            sidecar = Path(temp_dir) / "baseline.csv"
            with sidecar.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["request_sha256", "prediction"])
                writer.writeheader()
                writer.writerow({"request_sha256": "a" * 64, "prediction": "1"})
            name, path, predictions, digest, metadata = load_baseline_sidecar(f"crs={sidecar}")
            self.assertEqual(name, "crs")
            self.assertEqual(path, sidecar)
            self.assertEqual(predictions["a" * 64], 1)
            self.assertEqual(len(digest), 64)
            self.assertEqual(metadata, {})

    def test_evaluator_reports_external_baseline_lane(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            work = Path(temp_dir)
            dataset = work / "requests.csv"
            requests = []
            with dataset.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["request", "is_attack", "application", "category"])
                writer.writeheader()
                for group in range(20):
                    for request, label, category in (
                        (f"GET /shop/{group}/products?page=1 HTTP/1.1\r\nHost: site.test\r\n\r\n", 0, "BENIGN"),
                        (f"GET /shop/{group}/search?q=union%20select%20password%20from%20users-- HTTP/1.1\r\nHost: site.test\r\n\r\n", 1, "SQLI"),
                    ):
                        writer.writerow({"request": request, "is_attack": label, "application": f"app-{group}", "category": category})
                        requests.append((request, label))

            canonicalizer = Canonicalizer()
            scores = work / "crs.csv"
            with scores.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["request_sha256", "prediction"])
                writer.writeheader()
                for request, label in requests:
                    canonical = canonicalizer.parse_raw_http_request(request)["canonical_text"]
                    writer.writerow({"request_sha256": hashlib.sha256(canonical.encode()).hexdigest(), "prediction": label})

            report = run(argparse.Namespace(
                csv=dataset, request_column="request", label_column="is_attack", group_column="application",
                category_column="category", model_score_column=None, model_scores_csv=None,
                baseline_scores=[f"crs={scores}"], test_size=0.2, validation_size=0.1, seed=42,
                heuristic_threshold=0.7, model_threshold=0.5, bootstrap_iterations=100, output_dir=work / "out",
            ))
            self.assertEqual(report["results"]["baseline_crs"]["n"], report["split"]["test_rows"])
            self.assertIn("baseline_crs", report["per_category_test_results"]["SQLI"])
            saved = json.loads((work / "out" / "evaluation_report.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["score_method"]["baseline_sidecars"]["crs"]["sha256"], report["score_method"]["baseline_sidecars"]["crs"]["sha256"])

    def test_request_replay_strips_proxy_and_hop_headers(self):
        method, target, headers, body = request_parts(
            "POST /search?q=a%20b HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 203.0.113.7\r\nContent-Type: application/json\r\n\r\n{\"q\":\"test\"}"
        )
        self.assertEqual((method, target), ("POST", "/search?q=a%20b"))
        self.assertEqual(headers, {"Content-Type": "application/json"})
        self.assertEqual(body, b'{"q":"test"}')

    def test_baseline_target_defaults_to_loopback_only(self):
        self.assertEqual(local_origin("http://127.0.0.1:8081", False), "http://127.0.0.1:8081")
        with self.assertRaises(ValueError):
            local_origin("https://example.com", False)


if __name__ == "__main__":
    unittest.main()
