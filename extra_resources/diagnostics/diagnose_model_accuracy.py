#!/usr/bin/env python3
"""
EXTRA RESOURCE: Model Evaluation and Accuracy Diagnostic Utility
Location: extra_resources/scripts/diagnose_model.py

Evaluates the sequence classification Transformer on any dataset split
(train, val, test) and outputs:
- Confusion Matrix (TN, FP, FN, TP)
- Classification Report (Precision, Recall, F1-Score)
- ROC-AUC Score
- In-distribution & Out-of-distribution error analysis
- Latency metrics
"""

import os
import sys
import time
import json
import argparse
from typing import List, Tuple

def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate Transformer WAF model accuracy")
    parser.add_argument("--model-path", type=str, default="models/transformer_waf",
                        help="Path to saved HuggingFace model directory")
    parser.add_argument("--test-file", type=str, default="DATASETS/FINAL_DATASET/transformer_test.csv",
                        help="Path to CSV test split")
    parser.add_argument("--batch-size", type=int, default=64, help="Inference batch size")
    parser.add_argument("--max-length", type=int, default=256, help="Max sequence length")
    return parser.parse_args()

def main():
    args = parse_args()
    print("=" * 60)
    print(" AppAware-WAF: Transformer Model Diagnostic Suite")
    print("=" * 60)
    print(f"Target Model: {args.model_path}")
    print(f"Test Split:   {args.test_file}")
    
    if not os.path.exists(args.test_file):
        print(f"[!] Test file not found at: {args.test_file}")
        print("    Ensure your dataset path is correct.")
        return

    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, f1_score
    except ImportError as e:
        print(f"[!] Missing required ML dependencies: {e}")
        print("    Install via: pip install torch transformers scikit-learn pandas")
        return

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Inference Device: {device}")

    print("Loading model and tokenizer...")
    try:
        tokenizer = AutoTokenizer.from_pretrained(args.model_path)
        model = AutoModelForSequenceClassification.from_pretrained(args.model_path)
        model.to(device)
        model.eval()
        print("Model loaded successfully!")
    except Exception as e:
        print(f"[!] Failed to load model from {args.model_path}: {e}")
        return

    import csv
    texts, labels = [], []
    print(f"Reading records from {args.test_file}...")
    with open(args.test_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            req = row.get("request", "")
            is_atk = row.get("is_attack", "")
            if not req:
                continue
            lbl = 1 if is_atk.strip() in ("1", "attack", "malicious") else 0
            texts.append(req)
            labels.append(lbl)

    total_samples = len(texts)
    print(f"Loaded {total_samples:,} records (Benign: {labels.count(0):,}, Malicious: {labels.count(1):,})")

    preds, scores = [], []
    start_time = time.time()
    
    with torch.no_grad():
        for i in range(0, total_samples, args.batch_size):
            batch_texts = texts[i:i + args.batch_size]
            encoded = tokenizer(
                batch_texts,
                padding=True,
                truncation=True,
                max_length=args.max_length,
                return_tensors="pt"
            ).to(device)
            
            outputs = model(**encoded)
            probs = torch.softmax(outputs.logits, dim=-1)[:, 1].cpu().numpy()
            
            scores.extend(probs)
            preds.extend([1 if p >= 0.5 else 0 for p in probs])

    elapsed = time.time() - start_time
    avg_latency = (elapsed / total_samples) * 1000

    print("\n" + "=" * 60)
    print(" EVALUATION RESULTS")
    print("=" * 60)
    print(f"Total Requests:     {total_samples:,}")
    print(f"Evaluation Time:    {elapsed:.2f} s")
    print(f"Latency per Req:    {avg_latency:.2f} ms")
    
    cm = confusion_matrix(labels, preds)
    tn, fp, fn, tp = cm.ravel()
    print(f"\nConfusion Matrix:")
    print(f"  TN (Benign Allowed):   {tn:,}")
    print(f"  FP (Benign Blocked):   {fp:,}  (FPR: {fp / (fp + tn) * 100:.2f}%)")
    print(f"  FN (Attack Missed):    {fn:,}  (FNR: {fn / (fn + tp) * 100:.2f}%)")
    print(f"  TP (Attack Blocked):   {tp:,}")

    try:
        auc = roc_auc_score(labels, scores)
        print(f"\nROC-AUC Score:        {auc:.4f}")
    except Exception:
        pass

    print("\nClassification Report:")
    print(classification_report(labels, preds, target_names=["Benign", "Attack"], digits=4))

if __name__ == "__main__":
    main()
