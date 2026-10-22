# WAMM BERT-Tiny benchmark

## Setup

This is a reproducible research-prototype evaluation on WAMM DS-Augmented-v2. Dataset provenance and preparation are documented in [DATASET_PROVENANCE.md](DATASET_PROVENANCE.md). The source release and resulting request files are not checked into this repository; the fine-tuned checkpoint is in `models/wamm-bert-tiny/`.

- Unique host-aware canonical requests after preparation: **164,602**.
- Split: seeded request-level SHA-256 buckets, seed **42**; train **115,380**, validation **16,382**, test **32,840**.
- Train subset: **4,000** requests (2,000 benign and 2,000 attacks), sampled with a seeded class-stratified reservoir from the training partition.
- Model: `google/bert_uncased_L-2_H-128_A-2`, [Apache-2.0](https://huggingface.co/google/bert_uncased_L-2_H-128_A-2), one fine-tuning epoch, max length 128 tokens, batch size 32, learning rate `2e-5`, seed 42, CPU.
- Decision threshold: **0.5**, selected on validation data (validation F1 0.8711). Test labels were not used for threshold selection.
- Bootstrap: 500 percentile resamples over test requests. These intervals do not capture application/site-to-site variance.
- The full evaluation report and hash-keyed predictions are in `research/wamm_v2_evaluation/`.

## Aggregate held-out results

| Lane | Accuracy | Precision | Recall | F1 (95% interval) | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|
| Project deterministic rules | 92.32% | 98.46% | 89.28% | 93.65% (93.41–93.88%) | 2.42% | 10.72% |
| Fine-tuned BERT-Tiny | 85.32% | 94.18% | 81.89% | 87.61% (87.24–87.96%) | 8.76% | 18.11% |
| Bundled heuristic | 56.66% | 64.80% | 69.24% | 66.94% (66.42–67.46%) | 65.10% | 30.76% |

The external-model-plus-rules lane produced the same decisions as rules-only at the existing policy settings. The deterministic rule overrides dominated, so this experiment does **not** show that the trained model improves the live WAF policy. The BERT-Tiny score is evaluated as a separate model lane; the current website gateway still uses the handcrafted heuristic.

## Attack-category recall

| Test category | Requests | BERT-Tiny recall | Rules recall |
|---|---:|---:|---:|
| SQL Injection | 18,451 | 83.29% | 89.88% |
| Path Traversal | 1,422 | 83.33% | 91.28% |
| OS Command Injection | 636 | 62.89% | 74.69% |
| Code Injection | 96 | 38.54% | 73.96% |
| SSRF | 84 | 41.67% | 50.00% |
| Cross-Site Scripting | 59 | 10.17% | 88.14% |
| Command Injection | 34 | 0.00% | 97.06% |
| SSTI | 32 | 46.88% | 87.50% |

Several categories have very small test counts, so their recall estimates are unstable. The full JSON report contains per-category counts and confidence intervals.

## Interpretation limits

These are measured results on a public benchmark’s request-level random holdout. The source combines captured benign requests with generated/scanner attack traffic, and the request split does not hold out entire applications, hosts, attack campaigns, or time periods. The training subset is modest and the one-epoch model is a baseline. The source has 129 deduplicated fingerprints with more than one attack-category label; the first category is retained for those rows, so per-category figures have this additional label ambiguity. The results do not establish deployment effectiveness, production false-positive rates, or superiority over OWASP CRS. CRS was not run in this evaluation. The live Node gateway still uses the handcrafted heuristic; checkpoint serving and policy integration remain separate work.

## Reproduce training and evaluation

```powershell
$env:HF_HOME = (Resolve-Path private-model).Path + '\hf-cache'
python scripts/train_transformer.py `
  --data_dir private-data/splits `
  --output_dir private-model/transformer-waf `
  --model_name google/bert_uncased_L-2_H-128_A-2 `
  --model_revision 30b0a37ccaaa32f332884b96992754e246e48c5f `
  --max_length 128 --batch_size 32 --epochs 1 `
  --learning_rate 2e-5 --seed 42 --train_per_class 2000

python scripts/evaluate_dataset.py private-data/splits/transformer_test.csv `
  --request-column request --label-column is_attack --group-column group `
  --category-column category --fingerprint-column request_sha256 `
  --fixed-test-split `
  --split-manifest private-data/splits/split_manifest.json `
  --model-scores-csv private-model/transformer-waf/test_model_scores.csv `
  --model-threshold 0.5 --bootstrap-iterations 500 --seed 42 `
  --output-dir research/wamm_v2_evaluation
```
