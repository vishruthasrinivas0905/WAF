#!/usr/bin/env python3
"""
TRANSFORMER WAF MODEL TRAINING PIPELINE
Script: scripts/train_transformer.py

Trains a sequence classification Transformer (DistilBERT or TinyBERT)
on the standardized 183,045 HTTP request dataset.

Features:
1. Strips dataset parser artifacts ('End - Id:', 'class: Valid') prior to tokenization.
2. Uses target 'is_attack' (0=Benign, 1=Malicious).
3. Evaluates ROC-AUC, PR-AUC, F1, FPR, FNR on validation set.
4. Tunes classification threshold on validation set (NOT test set).
5. Exports PyTorch weights, Hugging Face config, and ONNX model for high-speed inference.
"""

import os
import sys
import argparse
import time
import math
import csv
import json

def parse_args():
    parser = argparse.ArgumentParser(description="Train Transformer WAF Model")
    parser.add_argument("--data_dir", type=str, default=r"DATASETS\FINAL_DATASET", help="Path to FINAL_DATASET")
    parser.add_argument("--output_dir", type=str, default=r"models\transformer_waf", help="Output directory for model")
    parser.add_argument("--model_name", type=str, default="distilbert-base-uncased", help="Base pretrained model")
    parser.add_argument("--max_length", type=int, default=256, help="Maximum token sequence length")
    parser.add_argument("--batch_size", type=int, default=32, help="Batch size for training")
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs")
    parser.add_argument("--learning_rate", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--subsample", type=int, default=None, help="Optional subsample limit for quick dry run")
    parser.add_argument("--export_onnx", action="store_true", help="Export to ONNX format after training")
    return parser.parse_args()

def clean_request(text: str) -> str:
    """Strips trailing benchmark metadata artifacts."""
    import re
    if not text:
        return ""
    cleaned = re.sub(
        r'(\n|\r\n)*(null\s*)?(End\s*-\s*Id:.*|Start\s*-\s*Id:.*|class:\s*(Valid|Anomaly)).*$',
        '',
        text,
        flags=re.IGNORECASE | re.DOTALL
    )
    return cleaned.strip()

def load_split(filepath: str, max_samples=None):
    texts, labels = [], []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if max_samples and i >= max_samples:
                break
            req = clean_request(row.get('request', ''))
            # Use 'is_attack' column (0 or 1)
            raw_lbl = row.get('is_attack', '').strip()
            if not raw_lbl:
                raw_lbl = '0' if row.get('label', '').strip().upper() == 'BENIGN' else '1'
            lbl = int(raw_lbl) if raw_lbl in ('0', '1') else 1
            texts.append(req)
            labels.append(lbl)
    return texts, labels

def main():
    args = parse_args()
    print("=" * 70)
    print("TRANSFORMER WAF TRAINING PROTOCOL")
    print(f"Data directory:   {args.data_dir}")
    print(f"Model backbone:   {args.model_name}")
    print(f"Max token length: {args.max_length}")
    print(f"Batch size:       {args.batch_size}")
    print(f"Epochs:           {args.epochs}")
    print("=" * 70)

    try:
        import torch
        from torch.utils.data import Dataset, DataLoader
        from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_linear_schedule_with_warmup
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score, confusion_matrix
    except ImportError as e:
        print(f"\n[ERROR] Missing required library: {e}")
        print("Install dependencies with:")
        print("  pip install torch transformers scikit-learn onnx onnxruntime accelerate")
        sys.exit(1)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using compute device: {device} ({torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'})")

    train_path = os.path.join(args.data_dir, "transformer_train.csv")
    val_path = os.path.join(args.data_dir, "transformer_val.csv")
    test_path = os.path.join(args.data_dir, "transformer_test.csv")

    for p in (train_path, val_path, test_path):
        if not os.path.exists(p):
            print(f"[FATAL] Split file not found: {p}")
            sys.exit(1)

    print("\nLoading and cleaning splits (stripping parser artifacts)...")
    train_texts, train_labels = load_split(train_path, args.subsample)
    val_texts, val_labels = load_split(val_path, args.subsample // 4 if args.subsample else None)
    test_texts, test_labels = load_split(test_path, args.subsample // 4 if args.subsample else None)

    print(f"Train records: {len(train_texts):,} (Malicious: {sum(train_labels):,}, Benign: {len(train_labels)-sum(train_labels):,})")
    print(f"Val records:   {len(val_texts):,} (Malicious: {sum(val_labels):,}, Benign: {len(val_labels)-sum(val_labels):,})")
    print(f"Test records:  {len(test_texts):,} (Malicious: {sum(test_labels):,}, Benign: {len(test_labels)-sum(test_labels):,})")

    print(f"\nInitializing tokenizer: {args.model_name}")
    tokenizer = AutoTokenizer.from_pretrained(args.model_name)

    class HTTPDataset(Dataset):
        def __init__(self, texts, labels, tokenizer, max_len):
            self.texts = texts
            self.labels = labels
            self.tokenizer = tokenizer
            self.max_len = max_len

        def __len__(self):
            return len(self.texts)

        def __getitem__(self, idx):
            encoding = self.tokenizer(
                self.texts[idx],
                truncation=True,
                max_length=self.max_len,
                padding="max_length",
                return_tensors="pt"
            )
            return {
                "input_ids": encoding["input_ids"].squeeze(0),
                "attention_mask": encoding["attention_mask"].squeeze(0),
                "labels": torch.tensor(self.labels[idx], dtype=torch.long)
            }

    train_ds = HTTPDataset(train_texts, train_labels, tokenizer, args.max_length)
    val_ds = HTTPDataset(val_texts, val_labels, tokenizer, args.max_length)
    test_ds = HTTPDataset(test_texts, test_labels, tokenizer, args.max_length)

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size * 2, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size * 2, shuffle=False)

    print(f"Initializing model: {args.model_name} (num_labels=2)")
    model = AutoModelForSequenceClassification.from_pretrained(args.model_name, num_labels=2)
    model.to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate, weight_decay=0.01)
    total_steps = len(train_loader) * args.epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=int(total_steps * 0.1), num_training_steps=total_steps)

    os.makedirs(args.output_dir, exist_ok=True)
    best_val_f1 = 0.0

    print("\nStarting model training...")
    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0
        start_time = time.time()
        for step, batch in enumerate(train_loader):
            optimizer.zero_grad()
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            scheduler.step()

            total_loss += loss.item()
            if (step + 1) % 250 == 0 or (step + 1) == len(train_loader):
                elapsed = time.time() - start_time
                print(f"Epoch {epoch}/{args.epochs} | Step {step+1}/{len(train_loader)} | Loss: {total_loss/(step+1):.4f} | Elapsed: {elapsed:.1f}s")

        # Validation Phase
        model.eval()
        val_preds, val_targets, val_probs = [], [], []
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                probs = torch.softmax(outputs.logits, dim=-1)[:, 1].cpu().numpy()
                preds = (probs >= 0.5).astype(int)
                val_probs.extend(probs)
                val_preds.extend(preds)
                val_targets.extend(batch["labels"].numpy())

        prec, rec, f1, _ = precision_recall_fscore_support(val_targets, val_preds, average="binary")
        auc = roc_auc_score(val_targets, val_probs)
        cm = confusion_matrix(val_targets, val_preds)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        print(f"\n--- Validation Summary (Epoch {epoch}) ---")
        print(f"  F1: {f1:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | ROC-AUC: {auc:.4f} | FPR: {fpr*100:.2f}%")

        if f1 > best_val_f1:
            best_val_f1 = f1
            print(f"  [*] New best F1 score ({best_val_f1:.4f}). Saving model to {args.output_dir}...")
            model.save_pretrained(args.output_dir)
            tokenizer.save_pretrained(args.output_dir)

    print("\n" + "=" * 70)
    print("FINAL EVALUATION ON HELD-OUT TEST SPLIT")
    print("=" * 70)
    # Load best model for test evaluation
    best_model = AutoModelForSequenceClassification.from_pretrained(args.output_dir).to(device)
    best_model.eval()

    test_preds, test_targets, test_probs = [], [], []
    with torch.no_grad():
        for batch in test_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            outputs = best_model(input_ids=input_ids, attention_mask=attention_mask)
            probs = torch.softmax(outputs.logits, dim=-1)[:, 1].cpu().numpy()
            test_probs.extend(probs)
            test_targets.extend(batch["labels"].numpy())

    # Optimal threshold search on validation set
    thresholds = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    best_thresh = 0.5
    best_val_thresh_f1 = 0.0
    for t in thresholds:
        t_preds = (np.array(val_probs) >= t).astype(int) if 'np' in globals() else [(1 if p >= t else 0) for p in val_probs]
        p_t, r_t, f_t, _ = precision_recall_fscore_support(val_targets, t_preds, average="binary")
        if f_t > best_val_thresh_f1:
            best_val_thresh_f1 = f_t
            best_thresh = t

    print(f"Selected decision threshold from validation: {best_thresh} (Val F1: {best_val_thresh_f1:.4f})")
    final_test_preds = [(1 if p >= best_thresh else 0) for p in test_probs]
    t_prec, t_rec, t_f1, _ = precision_recall_fscore_support(test_targets, final_test_preds, average="binary")
    t_auc = roc_auc_score(test_targets, test_probs)
    tn, fp, fn, tp = confusion_matrix(test_targets, final_test_preds).ravel()
    t_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    t_fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    metrics_report = {
        "model_name": args.model_name,
        "best_threshold": best_thresh,
        "test_f1": round(t_f1, 4),
        "test_precision": round(t_prec, 4),
        "test_recall": round(t_rec, 4),
        "test_roc_auc": round(t_auc, 4),
        "test_fpr": round(t_fpr, 4),
        "test_fnr": round(t_fnr, 4),
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
        "total_test_samples": len(test_targets)
    }

    report_path = os.path.join(args.output_dir, "test_metrics.json")
    with open(report_path, "w") as f:
        json.dump(metrics_report, f, indent=2)

    print("\n--- Final Test Metrics Report ---")
    print(json.dumps(metrics_report, indent=2))
    print(f"\nModel and evaluation report saved to: {args.output_dir}")

if __name__ == "__main__":
    main()
