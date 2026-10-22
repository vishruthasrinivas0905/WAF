# AppAware-WAF: Project Defense Guide

## Accurate project summary

AppAware-WAF is a prototype that parses and canonicalizes HTTP-like requests, applies handwritten deterministic signatures, calculates a lexical/entropy heuristic score, and combines those signals with an in-memory route profile. Its Express gateway can return a mock response or proxy to one explicitly configured upstream origin.

This repository does not include a trained Transformer checkpoint or the research datasets described in earlier drafts. The heuristic score is not a calibrated probability. The few-shot UI uses synthetic samples. The smoke benchmark is a small handcrafted regression corpus, not evidence of performance on real-world traffic.

## Explain the request path

1. Parse the request line, headers, query, and body.
2. Apply bounded URL decoding and path normalization.
3. Match handwritten patterns for common SQL injection, XSS, command injection, path traversal, and scanner indicators.
4. Compute lexical/entropy and profile scores.
5. Apply a threshold policy to allow, monitor, or block.
6. When allowed, return a labeled mock response if no upstream is configured, or proxy to the configured origin.

The current signatures are inspired by OWASP CRS categories. They are not the OWASP Core Rule Set itself.

## Likely questions

### Is a Transformer being used?

No trained Transformer is loaded by this checkout. The current secondary score is a handcrafted heuristic. `scripts/train_transformer.py` is an experimental training utility and requires a compatible dataset and dependencies; its existence does not mean a checkpoint is included or used by the gateway.

### How were accuracy and false-positive claims calculated?

The old dataset-scale figures were not reproducible from the published archive and have been removed from the live UI and current project summary. The built-in smoke benchmark only checks a small handcrafted example set. For research, the project now includes a group-held-out evaluation runner; it requires licensed data, a defined group column, and completed provenance manifest.

### How do you prevent train/test leakage?

The evaluator canonicalizes requests, hashes canonical text, removes duplicate requests before splitting, and holds out entire values from a user-selected application/source/family grouping column. The result is only as meaningful as the supplied grouping key and dataset labels. The runner refuses contradictory labels for duplicate canonical requests.

### What confidence intervals are reported?

The grouped evaluator uses percentile cluster-bootstrap intervals over held-out groups. It requires at least two test groups for intervals; more independent groups are preferable. Do not present request-level smoke-test accuracy as a population estimate.

### Is the gateway a real reverse proxy?

It proxies only when `UPSTREAM_URL` is configured. The destination is constrained to one configured origin, redirects are not followed, upstream calls have a timeout, and response bodies have a size limit. Without that setting, responses are explicitly labeled mock and are not forwarded.

### How is client IP determined?

Direct socket peer by default. Forwarded headers are trusted only when `WAF_TRUST_PROXY` lists explicit proxy IPs or CIDRs. The setting must never be `true`.

### How are management endpoints protected?

In production, startup requires `WAF_ADMIN_TOKEN` of at least 32 characters. `/api/waf/*` requires a matching bearer token. The dashboard accepts the key in a password field and keeps it in memory rather than persistent browser storage.

## Demonstration commands

```powershell
python -m unittest discover tests -v
python scripts/live_attack_tester.py --pipeline
python scripts/benchmark_waf.py
```

For a publication-style evaluation with a licensed dataset:

```powershell
python scripts/evaluate_dataset.py .\private-data\requests.csv --group-column application --category-column category
```

The smoke benchmark is a regression check. The dataset evaluator is the research harness; neither trains a Transformer. See [research/PUBLICATION_READINESS.md](research/PUBLICATION_READINESS.md) for required artifacts, methodology, and reporting limits.
