# Publication Readiness and Reproducibility

## What this checkout can substantiate

The repository contains a canonicalizer, handwritten deterministic signatures, a handcrafted lexical/entropy score, an in-memory synthetic profile demonstration, a local smoke corpus, and a configurable single-origin proxy. It does not include a trained Transformer checkpoint, the cited dataset files, or evidence artifacts supporting the old headline scores. The UI, README, and defense guide now describe this state directly.

The local smoke benchmark is a regression tool only. It counts each unique canonical request once for classification metrics and uses repetitions only for latency. Its small handcrafted corpus cannot establish generalization, a production false-positive rate, or an SLA.

## Dataset and artifact package

Copy `dataset_manifest.example.json` into your study record and fill every field before reporting measurements. Record source URLs, license terms, retrieval date, checksums, label definitions, preprocessing versions, group definition, split seed, model checkpoint/tokenizer hashes, dependency lock hash, and hardware/runtime details. Keep restricted source data outside Git and document how reviewers can obtain it.

## Evaluation protocol

The runner is:

```powershell
python scripts/evaluate_dataset.py .\private-data\requests.csv --group-column application --category-column category
```

Required columns default to `request`, `is_attack`, and the explicitly named group column. Labels may be `0/1` or benign/attack variants. Optional category and external model-score columns are supported. The evaluation process:

1. Canonicalizes requests, hashes the canonical text, removes exact canonical duplicates, and stops on contradictory labels.
2. Creates a seeded group-held-out train/validation/test split; no group value crosses splits. Both labels must appear in train and validation; the test fold prefers both labels but can be single-class for attack-family generalization. Undefined class-specific rates remain null. `scripts/create_group_splits.py` exports the CSVs expected by the optional training script and writes hash-based split assignments.
3. Compares rules-only, heuristic-only, and hybrid decisions. If external model scores are supplied as a column or hash-keyed sidecar, it also reports model-only and model-plus-rules lanes.
4. Writes an aggregate report and test prediction CSV with request hashes rather than payload text.
5. Computes 95% percentile cluster-bootstrap intervals over held-out groups. Intervals are unavailable with fewer than two test groups; confidence improves with more independent groups.

Choose score thresholds using validation data before running a final held-out test. `create_group_splits.py` and `evaluate_dataset.py` use the same split function, group column, split sizes, and seed; keep those arguments fixed. Prefer separate tests by application/source and attack family, since one grouping column cannot answer both generalization questions. Publish per-category confusion counts and analyze false positives and false negatives.

## Model comparison

No model is bundled by default. The runtime fallback is explicitly a heuristic. To evaluate a trained model, create the group splits, train only on training groups, select thresholds on validation groups, and generate test scores without using test labels. `train_transformer.py` writes a `test_model_scores.csv` sidecar keyed by canonical request SHA-256; pass it with `--model-scores-csv` and the validation-selected `--model-threshold`. Save the checkpoint, tokenizer, preprocessing code, and hashes. The evaluation runner does not train models and must not be cited as a Transformer result.

## Deployment safeguards

- Set `UPSTREAM_URL` to one trusted `http(s)` origin. The proxy rejects invalid target forms, does not follow redirects, enforces a request timeout, and caps upstream response bodies at 10 MiB.
- Set `WAF_ADMIN_TOKEN` to a random secret of at least 32 characters in production. Management APIs use bearer authentication; the browser UI keeps the key in page memory only.
- Set `WAF_TRUST_PROXY` only to explicit IP/CIDR ranges for proxy servers you control. Do not use `true`. With no trusted proxy configured, forwarded client-IP headers are ignored.
- The compose stack uses a local demo vulnerable target. Isolate it; do not expose it as a public service.
- Pin the vulnerable upstream image to a reviewed version or digest before a reproducible deployment.

## Publication claims to hold until evidence exists

Do not claim that a trained Transformer is included, that the referenced 183,045-record dataset is in this repository, that few-shot adaptation achieves a particular FPR, that 19 evasion tests achieve 100% detection, or that the gateway meets a latency SLA. Replace any such statement only after the corresponding artifacts and evaluation report are available and independently rerunnable.
