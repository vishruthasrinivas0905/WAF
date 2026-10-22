# AppAware-WAF BERT-Tiny checkpoint

This is a fine-tuned, binary request classifier created for the WAMM DS-Augmented-v2 research evaluation. It is a benchmark artifact, not the scorer currently used by the live Node gateway.

- Base model: [`google/bert_uncased_L-2_H-128_A-2`](https://huggingface.co/google/bert_uncased_L-2_H-128_A-2), pinned revision `30b0a37ccaaa32f332884b96992754e246e48c5f`.
- Base model license: Apache-2.0; see [LICENSE](LICENSE).
- Training data: WAMM DS-Augmented-v2, licensed by its publisher under CC BY 4.0; see [dataset provenance](../../research/DATASET_PROVENANCE.md) for attribution and preparation details.
- Task: binary classification (`0` normal, `1` attack).
- Training: 4,000 requests (2,000 per class) sampled from the training partition; one epoch; seed 42; max sequence length 128; batch size 32; learning rate `2e-5`; CPU.
- Threshold: 0.5, selected on the validation partition.
- Held-out test: 32,840 unique host-aware canonical request fingerprints; F1 0.8761, precision 0.9418, recall 0.8189, ROC-AUC 0.9323.
- Artifact checksums and runtime details: [training_manifest.json](training_manifest.json).

The test data and model-score sidecar are not included. The aggregate report, confidence intervals, and per-category analysis are in [`research/wamm_v2_evaluation/`](../../research/wamm_v2_evaluation/) and summarized in [`research/WAMM_BERT_TINY_RESULTS.md`](../../research/WAMM_BERT_TINY_RESULTS.md).

The model has not been validated for production traffic. Evaluation uses a request-level random holdout and does not establish cross-application generalization. The current live gateway continues to use the bundled handcrafted heuristic.
