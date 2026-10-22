#!/usr/bin/env python3
"""
DATASET INSPECTION & INTEGRITY AUDIT UTILITY
Phase 1: Verification of Existing Dataset Splits & Contamination Check

Checks:
1. File existence and row counts for train, val, and test splits.
2. Exact column schema and data types.
3. Label distribution (Benign=0 vs Malicious=1).
4. Attack family categorization and frequency.
5. Source dataset provenance distribution.
6. Data leakage / exact duplicate contamination between train and test.
7. Request sample inspection for encoding format (URI, Body, Headers).
"""

import os
import sys
import hashlib
from collections import Counter

def find_dataset_dir():
    candidates = [
        os.path.join(".", "DATASETS", "FINAL_DATASET"),
        os.path.join("..", "DATASETS", "FINAL_DATASET"),
        os.path.expanduser(r"C:\Users\SAHANA KS\OneDrive\Desktop\MAJOR WAF 7\DATASETS\FINAL_DATASET"),
        os.path.join(os.getcwd(), "DATASETS", "FINAL_DATASET"),
    ]
    for path in candidates:
        if os.path.isdir(path):
            return os.path.abspath(path)
    return None

def inspect_csv_file(filepath):
    import csv
    print(f"\n{'='*70}")
    print(f"Inspecting file: {filepath}")
    print(f"Size: {os.path.getsize(filepath) / (1024 * 1024):.2f} MB")
    
    label_counter = Counter()
    attack_counter = Counter()
    source_counter = Counter()
    hashes = set()
    total_rows = 0
    headers = []
    sample_rows = []

    with open(filepath, mode="r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        for row in reader:
            total_rows += 1
            lbl = row.get("label", "UNKNOWN").strip()
            atk = row.get("attack_type", "unspecified").strip()
            src = row.get("source_dataset", "unknown").strip()
            req = row.get("request", "")
            
            label_counter[lbl] += 1
            attack_counter[atk] += 1
            source_counter[src] += 1
            
            # Hash normalized request for leak detection
            norm_req = req.strip()
            req_hash = hashlib.sha256(norm_req.encode("utf-8", errors="ignore")).hexdigest()
            hashes.add(req_hash)
            
            if total_rows <= 3:
                sample_rows.append(row)

    print(f"Columns: {headers}")
    print(f"Total rows: {total_rows:,}")
    print(f"Unique requests: {len(hashes):,} (Duplicate rate: {100.0 * (1 - len(hashes)/max(1, total_rows)):.2f}%)")
    print("\nClass distribution (label):")
    for k, v in label_counter.most_common():
        pct = (v / total_rows) * 100 if total_rows else 0
        print(f"  [{k}]: {v:,} ({pct:.2f}%)")
        
    print("\nTop 8 Attack types:")
    for k, v in attack_counter.most_common(8):
        print(f"  {k}: {v:,}")
        
    print("\nSource dataset distribution:")
    for k, v in source_counter.most_common():
        print(f"  {k}: {v:,}")
        
    print("\nFirst sample row preview:")
    if sample_rows:
        first = sample_rows[0]
        preview_req = first.get("request", "")[:180]
        print(f"  Sample label: {first.get('label')}")
        print(f"  Sample attack_type: {first.get('attack_type')}")
        print(f"  Sample request (truncated): {preview_req}...")

    return {
        "headers": headers,
        "total_rows": total_rows,
        "hashes": hashes,
        "labels": dict(label_counter),
        "attacks": dict(attack_counter),
        "sources": dict(source_counter)
    }

def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else find_dataset_dir()
    
    if not target_dir or not os.path.exists(target_dir):
        print(f"Dataset directory not found at candidate locations.")
        print("Usage: python inspect_dataset.py [path_to_FINAL_DATASET]")
        print("Example Windows PowerShell command:")
        print(r'  python scripts\inspect_dataset.py "C:\Users\SAHANA KS\OneDrive\Desktop\MAJOR WAF 7\DATASETS\FINAL_DATASET"')
        sys.exit(1)

    print(f"Target dataset directory: {target_dir}")
    splits = {
        "train": os.path.join(target_dir, "transformer_train.csv"),
        "val": os.path.join(target_dir, "transformer_val.csv"),
        "test": os.path.join(target_dir, "transformer_test.csv")
    }

    results = {}
    for name, path in splits.items():
        if os.path.isfile(path):
            results[name] = inspect_csv_file(path)
        else:
            print(f"\n[WARNING] Split file not found: {path}")

    # Check for Train-Test contamination / overlap
    if "train" in results and "test" in results:
        train_hashes = results["train"]["hashes"]
        test_hashes = results["test"]["hashes"]
        overlap = train_hashes.intersection(test_hashes)
        overlap_pct = (len(overlap) / len(test_hashes) * 100) if test_hashes else 0
        print(f"\n{'='*70}")
        print("CONTAMINATION AUDIT (Train vs Test Overlap):")
        print(f"  Train unique requests: {len(train_hashes):,}")
        print(f"  Test unique requests:  {len(test_hashes):,}")
        print(f"  Identical requests in both Train and Test: {len(overlap):,} ({overlap_pct:.2f}% of test set)")
        if len(overlap) > 0:
            print("  [ALERT] Data leakage detected between train and test splits!")
            print("  Recommendation: Apply template deduplication or strict source/application holdout split.")
        else:
            print("  [CLEAN] Zero identical string overlap detected between train and test splits.")

if __name__ == "__main__":
    main()
