# Dataset provenance and preparation

## Source

- Dataset: **WAMM DS-Augmented-v2**, `DS_Augmented_v2.db.xz`.
- Upstream: [CyShield-Security-R-D/WAMM-Dataset-Repository](https://github.com/CyShield-Security-R-D/WAMM-Dataset-Repository), pinned to commit `2783eab560c4355f5976a57fc2e97a2e6c5c79a1`.
- License stated by the dataset repository: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).
- Retrieval date: 2026-10-22.
- Downloaded compressed size: 10,845,336 bytes.
- Compressed artifact SHA-256: `2631c31b8f4bdc389365274e6f22d9753534ef1e2eab52f3d1fd20c4f6bc65c9`.
- Upstream release count: 704,665 labeled full HTTP requests across eight attack categories and normal traffic.

The upstream README describes the release as derived from SR-BH 2020, with deduplication/relabeling, scanner and Burp-generated malicious requests, and benign requests captured from public services. Therefore “real dataset” here means a real published request corpus with captured benign traffic; the malicious portion is a mixture that includes generated/scanner traffic. The upstream label-quality statements have not been independently audited by this project. Do not describe this as a naturally sampled production-attack corpus.

### Attribution

When reusing or redistributing the dataset or results derived from it, credit the WAMM dataset repository and cite its associated paper:

Heba Osama, Omar Elebiary, Youssef Qassim, Mohamed Amgad, Ahmed Maghawry, Ahmed Saafan, and Haitham Ghalwash. “Enhanced Web Payload Classification Using WAMM: An AI-Based Framework for Dataset Refinement and Model Evaluation.” *IEEE Access*, 2026. [doi:10.1109/ACCESS.2026.3685450](https://doi.org/10.1109/ACCESS.2026.3685450).

The project keeps the raw and normalized dataset files out of Git. The pinned source release is downloadable under its stated license.

## Preparation and exclusions

`scripts/prepare_wamm_dataset.py` converts the SQLite release to the project’s CSV schema. It maps label `000 - Normal` to `0` and attack categories to `1`. The deduplication fingerprint is SHA-256 of the lowercased `Host` value plus the project canonicalizer’s canonical request text. This includes the host because the canonicalizer intentionally omits request headers and a canonical-text-only fingerprint produced many contradictory labels across hosts.

The preparation pass excluded all records for **1,113 host-aware fingerprints** whose source rows disagree on the binary benign/attack label. The remaining CSV contained 354,216 rows. `scripts/split_wamm_dataset.py` then removed 189,614 repeated fingerprints and retained **164,602 unique requests**. These choices are recorded in `private-data/splits/split_manifest.json` when the pipeline is run locally.

An audit found 129 of the retained fingerprints assigned to more than one attack-category label (while agreeing on the binary attack label). The current deduplicator retains the first source category for those requests. Overall binary metrics are unaffected by this category ambiguity, but per-category scores may be affected slightly; the low-count categories are especially uncertain.

The dataset does not provide a reliable application-family group column. Requests were assigned to train, validation, or test by seeded SHA-256 buckets (seed 42; approximately 70/10/20). This prevents a repeated host-aware canonical fingerprint from crossing partitions, but it is a random request-level holdout, **not** an application-held-out or cross-site evaluation. The source contains host diversity, but the split does not isolate hosts or attack campaigns. A future publication should add an independent source/application-held-out test.

## Reproduce data preparation

From the repository root in PowerShell:

```powershell
New-Item -ItemType Directory -Force private-data | Out-Null
Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/CyShield-Security-R-D/WAMM-Dataset-Repository/2783eab560c4355f5976a57fc2e97a2e6c5c79a1/DS_Augmented_v2.db.xz" `
  -OutFile "private-data/DS_Augmented_v2.db.xz"
Get-FileHash private-data/DS_Augmented_v2.db.xz -Algorithm SHA256
python scripts/prepare_wamm_dataset.py private-data/DS_Augmented_v2.db.xz private-data/wamm.csv
python scripts/split_wamm_dataset.py private-data/wamm.csv --output-dir private-data/splits --seed 42
```

Compare the downloaded hash with the value above before using the data.
