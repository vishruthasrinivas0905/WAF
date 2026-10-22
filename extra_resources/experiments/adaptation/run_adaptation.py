#!/usr/bin/env python3
"""
FEW-SHOT ADAPTATION EXPERIMENTAL BENCHMARK
Experiment: experiments/adaptation/run_adaptation.py

Investigates Research Question 1:
"Can application-aware adaptation of a Transformer-based WAF reduce false positives
on previously unseen web applications using limited benign application-specific traffic,
while preserving malicious-request detection?"

Evaluates sample budgets:
- 0 samples (Unadapted baseline)
- 100 samples
- 500 samples
- 1,000 samples

Measures:
- False Positive Rate (FPR)
- False Negative Rate (FNR)
- Precision, Recall, F1
- P50 & P95 Evaluation Latency
"""

import os
import sys
import csv
import json
import time
import random
from collections import defaultdict
from typing import List, Dict, Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from waf.pipeline import WafPipeline
from waf.normalization.canonicalizer import Canonicalizer

def load_data(filepath: str, limit: int = 5000):
    samples = []
    canonicalizer = Canonicalizer()
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if limit and i >= limit:
                break
            raw_req = row.get("request", "")
            raw_lbl = row.get("is_attack", "").strip()
            if not raw_lbl:
                raw_lbl = "0" if row.get("label", "").strip().upper() == "BENIGN" else "1"
            lbl = int(raw_lbl) if raw_lbl in ("0", "1") else 1
            
            parsed = canonicalizer.parse_raw_http_request(raw_req)
            samples.append({
                "raw_request": raw_req,
                "parsed": parsed,
                "is_attack": lbl
            })
    return samples

def run_experiment(test_samples: List[Dict[str, Any]], benign_pool: List[Dict[str, Any]], budgets=[0, 100, 500, 1000]):
    results = {}
    print("=" * 70)
    print("FEW-SHOT APPLICATION-AWARE ADAPTATION BENCHMARK")
    print(f"Total test evaluation samples: {len(test_samples):,}")
    print(f"Available benign adaptation pool: {len(benign_pool):,}")
    print("=" * 70)

    for budget in budgets:
        print(f"\n[Evaluating Budget: {budget} Benign Samples]")
        pipeline = WafPipeline(mode="ENFORCING", app_id=f"adapted_app_{budget}")
        
        # Adaptation Phase (0, 100, 500, 1000 benign requests)
        if budget > 0:
            adaptation_samples = [s["parsed"] for s in benign_pool[:budget]]
            pipeline.profile_engine.adapt_from_benign_samples(adaptation_samples)

        # Evaluation Phase
        tp, fp, tn, fn = 0, 0, 0, 0
        latencies = []

        start_time = time.perf_counter()
        for s in test_samples:
            t0 = time.perf_counter()
            event = pipeline.inspect_request(s["raw_request"])
            lat = (time.perf_counter() - t0) * 1000.0
            latencies.append(lat)

            decision = event["decision"]
            is_malicious = (s["is_attack"] == 1)

            # WAF Decision Mapping: BLOCK is positive prediction (attack), ALLOW/MONITOR is negative (pass)
            predicted_attack = (decision == "BLOCK")

            if predicted_attack and is_malicious:
                tp += 1
            elif predicted_attack and not is_malicious:
                fp += 1
            elif not predicted_attack and not is_malicious:
                tn += 1
            elif not predicted_attack and is_malicious:
                fn += 1

        total_eval_time = time.perf_counter() - start_time
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        latencies.sort()
        p50 = latencies[int(0.50 * len(latencies))] if latencies else 0.0
        p95 = latencies[int(0.95 * len(latencies))] if latencies else 0.0

        res = {
            "budget": budget,
            "f1": round(f1, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "latency_p50_ms": round(p50, 3),
            "latency_p95_ms": round(p95, 3),
            "total_eval_time_sec": round(total_eval_time, 2)
        }
        results[budget] = res

        print(f"  F1: {f1:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} | FPR: {fpr*100:.2f}% | P50 Latency: {p50:.2f}ms")

    os.makedirs(os.path.join("experiments", "adaptation"), exist_ok=True)
    out_file = os.path.join("experiments", "adaptation", "few_shot_results.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nBenchmark completed. Results exported to: {out_file}")
    return results

if __name__ == "__main__":
    test_path = os.path.join("DATASETS", "FINAL_DATASET", "transformer_test.csv")
    if not os.path.exists(test_path):
        print(f"[ERROR] Test split not found: {test_path}")
        sys.exit(1)

    print("Loading test samples...")
    test_data = load_data(test_path, limit=3000)
    benign_pool = [d for d in test_data if d["is_attack"] == 0]
    eval_set = test_data

    run_experiment(eval_set, benign_pool)
