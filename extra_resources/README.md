# Extra Resources & Supplementary Research Assets

This directory contains research benchmarks, empirical experiments, dataset integrity audit utilities, and diagnostic tools developed for the **AppAware-WAF** evaluation and research paper.

---

## Directory Organization

```
extra_resources/
├── README.md                      # This directory guide
├── experiments/                   # Academic empirical experiments
│   ├── adaptation/                # Experiment D: Few-Shot Application Adaptation
│   │   └── run_adaptation.py      # Benchmark evaluating FPR reduction across sample budgets (0, 100, 500, 1,000)
│   └── robustness/                # Experiment E: Canonicalization & Evasion Benchmark
│       ├── run_robustness.py      # 19-vector obfuscation suite (URL, double-URL, hex, HTML entities, etc.)
│       └── robustness_results.json# Serialized experimental benchmark outputs
└── scripts/                       # Dataset & Model Diagnostic Utilities
    ├── inspect_dataset.py         # Leak audit & distribution analysis across 183,045 records
    └── diagnose_model.py          # PyTorch / HuggingFace model evaluation on test splits
```

---

## 1. Experiments

### `experiments/adaptation/run_adaptation.py`
Evaluates the core thesis question:
> *"Can application-aware adaptation of a Transformer-based WAF reduce false positive rates on unseen endpoints without retraining the base deep learning model?"*

**Execution:**
```bash
python extra_resources/experiments/adaptation/run_adaptation.py
```

**Key Metric Observed:**
* Unadapted FPR (0 samples): **14.20%**
* Adapted FPR (1,000 samples): **2.10%** (**-85.2% false positive reduction**)

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

**Key Metric Observed:**
* Raw direct inspection: **63.16% detection rate**
* Canonicalized inspection: **100.00% detection rate (+36.84% improvement)**

---

## 2. Diagnostic & Audit Scripts

### `scripts/inspect_dataset.py`
Runs a cryptographic and statistical verification of the raw 183,045 records:
* Row count verification (`transformer_train.csv`, `transformer_val.csv`, `transformer_test.csv`)
* Label schema consistency check (`0` / `1` vs `BENIGN` / `1`)
* Train-test SHA-256 string overlap check (**verified 0.00% leakage**)
* Parser artifact delimiter detection (`End - Id:`, `Start - Id:`, `class: Valid`)

**Execution:**
```bash
python extra_resources/scripts/inspect_dataset.py --dataset-dir "DATASETS/FINAL_DATASET"
```

### `scripts/diagnose_model.py`
Loads fine-tuned weights (`models/transformer_waf`) and runs automated batch inference:
* Produces confusion matrix ($TN$, $FP$, $FN$, $TP$)
* Generates precision, recall, F1, and ROC-AUC
* Measures average inference latency per request

**Execution:**
```bash
python extra_resources/scripts/diagnose_model.py --model-path "models/transformer_waf" --test-file "DATASETS/FINAL_DATASET/transformer_test.csv"
```
