# Publication Readiness and Reproducibility

## What this checkout can substantiate

The repository contains the live Node gateway, deterministic signatures, its handcrafted heuristic, an in-memory synthetic profile demonstration, a smoke corpus, and a configurable single-origin proxy. It now also includes a BERT-Tiny checkpoint trained for a separate WAMM benchmark and aggregate evaluation artifacts. The live gateway does not load that checkpoint. The raw WAMM dataset remains outside Git.

The local smoke benchmark is a regression tool only. It counts each unique canonical request once for classification metrics and uses repetitions only for latency. Its small handcrafted corpus cannot establish generalization, a production false-positive rate, or an SLA.

## Dataset and artifact package

See [DATASET_PROVENANCE.md](DATASET_PROVENANCE.md) for the pinned WAMM DS-Augmented-v2 source, CC BY 4.0 attribution, download hash, label processing, contradictory-label exclusions, and request-level split. See [WAMM_BERT_TINY_RESULTS.md](WAMM_BERT_TINY_RESULTS.md) and the checkpoint's `training_manifest.json` for training/runtime details. The WAMM README describes captured benign requests and generated/scanner attack requests; do not characterize all attack records as naturally observed production traffic.

## Evaluation protocol

For arbitrary datasets with trustworthy application/source IDs, the general runner remains:

```powershell
python scripts/evaluate_dataset.py .\private-data\requests.csv --group-column application --category-column category
```

Required columns default to `request`, `is_attack`, and the explicitly named group column. Labels may be `0/1` or benign/attack variants. Optional category and external model-score columns are supported. For WAMM, use the dedicated preparation and split scripts in [DATASET_PROVENANCE.md](DATASET_PROVENANCE.md); the fixed test partition is evaluated using commands in [WAMM_BERT_TINY_RESULTS.md](WAMM_BERT_TINY_RESULTS.md). That study:

1. Converts the pinned SQLite release, maps normal/attack labels, and excludes host-aware fingerprints with contradictory binary labels.
2. Deduplicates by host-aware canonical request fingerprint and assigns seeded SHA-256 request-level buckets (70/10/20). No fingerprint crosses partitions. This is **not** a group-held-out or cross-site split because the source lacks reliable application/source group IDs.
3. Trains BERT-Tiny using a balanced 4,000-request reservoir sample from the training partition; selects the threshold on the complete validation partition.
4. Compares rules-only, heuristic-only, trained-model-only, and hybrid decisions on all 32,840 unique held-out requests. The hybrid lane is unchanged from rules-only under current policy.
   External WAF baselines can be replayed with `scripts/score_http_baseline.py`; its hash-keyed binary sidecar is accepted through repeated `--baseline-scores NAME=CSV` options. The scorer ignores labels and defaults to loopback-only targets.
5. Writes an aggregate report and test prediction CSV with request hashes rather than payload text.
6. Computes 95% percentile bootstrap intervals over held-out request fingerprints. These intervals quantify request-sampling variation, not application/site variation.

Choose score thresholds using validation data before running a final held-out test. For the general group-held-out protocol, `create_group_splits.py` and `evaluate_dataset.py` use the same split function, group column, split sizes, and seed. WAMM uses its dedicated hash-bucket request-level splitter. Prefer separate tests by application/source and attack family, since one grouping column cannot answer both generalization questions. Publish per-category confusion counts and analyze false positives and false negatives.

## Model comparison

The BERT-Tiny checkpoint and tokenizer are included under `models/wamm-bert-tiny/`, with Apache-2.0 base-model terms and a training manifest. The runtime fallback remains the heuristic; the live Node gateway does not load the checkpoint. `train_transformer.py` writes a test-only score sidecar; `evaluate_dataset.py` accepts it with `--model-scores-csv`. The trained-model-only lane is a benchmark result, not a claim about the current live gateway.

## Deployment safeguards

- Set `UPSTREAM_URL` to one trusted `http(s)` origin. The proxy rejects invalid target forms, does not follow redirects, enforces a request timeout, and caps upstream response bodies at 10 MiB.
- Set `WAF_ADMIN_TOKEN` to a random secret of at least 32 characters in production. Management APIs use bearer authentication; the browser UI keeps the key in page memory only.
- Set `WAF_TRUST_PROXY` only to explicit IP/CIDR ranges for proxy servers you control. Do not use `true`. With no trusted proxy configured, forwarded client-IP headers are ignored.
- The compose stack uses a local demo vulnerable target. Isolate it; do not expose it as a public service.
- Pin the vulnerable upstream image to a reviewed version or digest before a reproducible deployment.
- For comparative evaluation, run the optional official OWASP CRS Compose profile on loopback, record the exact image tag and paranoia settings, and keep its hash-keyed decision sidecar plus metadata with the evaluation report.

## Publication claims to hold until evidence exists

Do not claim cross-application generalization, production effectiveness, OWASP CRS superiority, measured few-shot improvement, comprehensive evasion resistance, or a latency SLA from the current study. The checkpoint is trained on a small sample for one epoch, the WAMM split is request-level, and CRS was not evaluated. An independent application-held-out dataset and deployment integration are still needed before publication claims go beyond this benchmark.
