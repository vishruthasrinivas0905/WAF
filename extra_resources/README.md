# Extra Resources & Supplementary Research Assets

This directory contains legacy exploratory scripts and result artifacts. The raw datasets and trained checkpoint referenced by some scripts are not included. Treat historical metrics as unverified until reproduced with licensed data and a recorded run manifest. The standalone robustness script uses a small handcrafted payload list and is a regression demonstration, not evidence of real-world detection performance.

---

## Directory Organization

```
extra_resources/
├── README.md                      # This directory guide
├── experiments/                   # Academic empirical experiments
│   ├── adaptation/                # Experiment D: Few-Shot Application Adaptation
│   │   └── run_adaptation.py      # Legacy exploratory demo; not validated evidence
│   └── robustness/                # Experiment E: Canonicalization & Evasion Benchmark
│       ├── run_robustness.py      # Small handcrafted canonicalization regression suite
│       └── robustness_results.json# Historical output; rerun before citing
└── scripts/                       # Dataset & Model Diagnostic Utilities
    ├── inspect_dataset.py         # Audit tool for a user-supplied dataset directory
    └── diagnose_model.py          # PyTorch / HuggingFace model evaluation on test splits
```

---

## Evidence limits

The earlier numeric claims in these files are not a substitute for a reproducible study package. This repository does not include the underlying split CSVs or model checkpoint. Use `scripts/create_group_splits.py` and `scripts/evaluate_dataset.py` for new measurements, and complete `research/dataset_manifest.example.json` with data provenance first.

## 1. Exploratory scripts

### `experiments/adaptation/run_adaptation.py`
Evaluates the core thesis question:
> *"Can application-aware adaptation of a Transformer-based WAF reduce false positive rates on unseen endpoints without retraining the base deep learning model?"*

**Execution:**
```bash
python extra_resources/experiments/adaptation/run_adaptation.py
```

This script requires an external dataset directory and currently uses the prototype profile engine with synthetic adaptation samples. Its output is not a validated application-adaptation result.

### `experiments/robustness/run_robustness.py`
Tests defensive resilience against evasion transformations, including:
1. Standard URL percent-encoding
2. Double URL encoding (`%2527`, `%253C`)
3. Mixed-case obfuscation (`sElEcT`, `<sCrIpT>`)
4. Hexadecimal encoding (`\x27`, `0x27`)
5. Overlong UTF-8 representations
6. HTML decimal and hex entities (`&#39;`, `&#x27;`)
7. Directory traversal path folding (`/a/b/../../etc/passwd`)

**Execution:**
```bash
python extra_resources/experiments/robustness/run_robustness.py
```

Rerunning provides a deterministic smoke comparison on its handcrafted payload list. Report the sample count and scope; do not generalize it to all evasions or production traffic.

---

## 2. Diagnostic & Audit Scripts

### `scripts/inspect_dataset.py`
Runs legacy checks against a user-supplied dataset directory:
* Row count verification (`transformer_train.csv`, `transformer_val.csv`, `transformer_test.csv`)
* Label schema consistency check (`0` / `1` vs `BENIGN` / `1`)
* Train-test exact-string overlap check (not a group-disjoint leakage audit)
* Parser artifact delimiter detection (`End - Id:`, `Start - Id:`, `class: Valid`)

**Execution:**
```bash
python extra_resources/scripts/inspect_dataset.py --dataset-dir "DATASETS/FINAL_DATASET"
```

### `scripts/diagnose_model.py`
Can load user-supplied fine-tuned weights (`models/transformer_waf`) for batch inference; no such checkpoint is included:
* Produces confusion matrix ($TN$, $FP$, $FN$, $TP$)
* Generates precision, recall, F1, and ROC-AUC
* Measures average inference latency per request

**Execution:**
```bash
python extra_resources/scripts/diagnose_model.py --model-path "models/transformer_waf" --test-file "DATASETS/FINAL_DATASET/transformer_test.csv"
```
