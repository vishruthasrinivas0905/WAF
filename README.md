# AppAware-WAF: Application-Aware Web Application Firewall Prototype

An academic prototype for request canonicalization, handwritten attack signatures, heuristic risk scoring, application-profile demonstrations, and a configurable HTTP gateway. It is not a production-validated WAF. The live gateway still uses the lexical/entropy heuristic; a separately trained BERT-Tiny benchmark checkpoint and evaluation report are included. The licensed WAMM source dataset is not bundled.

The `/proxy/*` route returns a clearly labeled mock response when `UPSTREAM_URL` is unset. Set `UPSTREAM_URL` to an explicitly trusted HTTP(S) origin to enable proxying. Management APIs require `WAF_ADMIN_TOKEN` in production. See [DEPLOYMENT.md](DEPLOYMENT.md) and [research/PUBLICATION_READINESS.md](research/PUBLICATION_READINESS.md).

---

## 1. Implemented Components

| Component | Current behavior |
| :--- | :--- |
| Canonicalization | Bounded URL decoding, path normalization, request parsing |
| Deterministic inspection | Handwritten regex signatures for common SQLi, XSS, RCE, traversal, and scanner patterns |
| Additional score | Lexical/entropy heuristic; not a trained neural model or calibrated probability |
| Application profile | In-memory synthetic sample adaptation for UI demonstration |
| Gateway | WAF-enforced mock mode by default; configured single-origin proxy when `UPSTREAM_URL` is set |
| Evaluation | Handcrafted smoke corpus plus WAMM DS-Augmented-v2 request-level holdout report |

The WAMM results are reproducible at the request-level using the pinned, licensed source corpus and preparation scripts. They do not establish cross-application generalization or production performance; see [the results and limitations](research/WAMM_BERT_TINY_RESULTS.md).

---

## 2. System Architecture

```
                                [ CLIENT TRAFFIC ]
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │        HTTP REVERSE PROXY GATEWAY       │
                   │      (Header Validation & Rate Limit)   │
                   └────────────────────┬────────────────────┘
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │    REQUEST NORMALIZER & CANONICALIZER   │
                   │ (URL decode, UTF-8 clean, path normal.) │
                   └────────────────────┬────────────────────┘
                                        │
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │       DETERMINISTIC SECURITY ENGINE     │
                   │  (Handwritten signatures inspired by CRS)
                   └────────────────────┬────────────────────┘
                                        │ (Score: S_det)
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │       HEURISTIC SCORER ENGINE           │
                   │   (Handwritten lexical/entropy rules)   │
                   └────────────────────┬────────────────────┘
                                        │ (Heuristic score)
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │      APPLICATION PROFILE EVALUATOR      │
                   │   (Route match, Param structure, Stats) │
                   └────────────────────┬────────────────────┘
                                        │ (Score: S_profile)
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │          RISK & POLICY ENGINE           │
                   │    Fusion: Risk = f(S_det, S_heur, S_app)│
                   └────────────────────┬────────────────────┘
                                        │
                 ┌──────────────────────┼──────────────────────┐
                 ▼                      ▼                      ▼
           [ ALLOW: 200 ]        [ MONITOR: 200 ]       [ BLOCK: 403 ]
                 │                      │                      │
                 ▼                      ▼                      ▼
        (Forward to Upstream)   (Forward + Sec Log)     (Terminate + Alert)
```

---

## 3. Reproducible Dataset Evaluation

The BERT-Tiny checkpoint is included at `models/wamm-bert-tiny/`; source and training details are in its model card. The raw dataset stays outside Git. Reproduce the current WAMM benchmark from the pinned CC BY 4.0 source:

```powershell
New-Item -ItemType Directory -Force private-data | Out-Null
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/CyShield-Security-R-D/WAMM-Dataset-Repository/2783eab560c4355f5976a57fc2e97a2e6c5c79a1/DS_Augmented_v2.db.xz" -OutFile "private-data/DS_Augmented_v2.db.xz"
Get-FileHash private-data/DS_Augmented_v2.db.xz -Algorithm SHA256
python scripts/prepare_wamm_dataset.py private-data/DS_Augmented_v2.db.xz private-data/wamm.csv
python scripts/split_wamm_dataset.py private-data/wamm.csv --output-dir private-data/splits --seed 42
```

Train and run the fixed held-out comparison:

```powershell
python -m pip install torch transformers scikit-learn accelerate
New-Item -ItemType Directory -Force private-model | Out-Null
$env:HF_HOME = (Resolve-Path private-model).Path + '\hf-cache'
python scripts/train_transformer.py --data_dir private-data/splits --output_dir private-model/transformer-waf --model_name google/bert_uncased_L-2_H-128_A-2 --model_revision 30b0a37ccaaa32f332884b96992754e246e48c5f --max_length 128 --batch_size 32 --epochs 1 --learning_rate 2e-5 --seed 42 --train_per_class 2000
python scripts/evaluate_dataset.py private-data/splits/transformer_test.csv --request-column request --label-column is_attack --group-column group --category-column category --fingerprint-column request_sha256 --fixed-test-split --split-manifest private-data/splits/split_manifest.json --model-scores-csv private-model/transformer-waf/test_model_scores.csv --model-threshold 0.5 --bootstrap-iterations 500 --seed 42 --output-dir research/wamm_v2_evaluation
```

The saved results include rules-only, heuristic-only, trained-model-only, and hybrid lanes with per-category results and 95% request-level bootstrap intervals. This dataset has no reliable application-family field, so its random request-level split is not a cross-site holdout. The live Node gateway still uses the heuristic; the included model is benchmark-only. See [dataset provenance](research/DATASET_PROVENANCE.md), [benchmark results](research/WAMM_BERT_TINY_RESULTS.md), and [publication readiness](research/PUBLICATION_READINESS.md) for exact limits.

### Compare an OWASP CRS baseline

The optional `baseline` Compose profile runs the official OWASP ModSecurity CRS image alongside the isolated Juice Shop target. It binds only to loopback. Compose pins Juice Shop to a versioned tag and CRS to a dated tag plus image-index digest. The CRS project documents its [official container images and tag formats](https://github.com/coreruleset/modsecurity-crs-docker).

Start the reference baseline and its backend:

```powershell
docker compose --profile baseline up -d upstream-vulnerable-app crs-baseline
```

Replay a licensed corpus only against this local baseline, writing hash keyed decisions without reading labels:

```powershell
python scripts/score_http_baseline.py .\private-data\requests.csv --base-url http://127.0.0.1:8081 --engine-id owasp/modsecurity-crs:4.30.0-nginx-202610180210@sha256:7698c48a41a43138ae317feeec964d1515b861cc1d9e50617bc1cdfe9f314e1d --block-statuses 403 --output .\private-data\crs_predictions.csv
```

Add the baseline lane to the same group-held-out evaluation:

```powershell
python scripts/evaluate_dataset.py .\private-data\requests.csv --group-column application --category-column category --baseline-scores crs=.\private-data\crs_predictions.csv
```

The scorer sends requests to the local WAF and counts the configured HTTP status codes as blocks; verify those statuses against the selected engine and backend. Preserve the emitted metadata JSON with the report. Results depend on CRS version, paranoia level, and deployment settings, so record those alongside metrics.

---

## 4. Local Execution & Testing (Windows PowerShell)

Navigate to the cloned project directory:
```powershell
cd "C:\path\to\appaware-waf_-transformer-web-application-firewall"
```

### 1. Interactive Manual Attack Testing (CLI Prompt)
```powershell
python scripts/interactive_cli.py
```
Select **Option 2** to type any HTTP Method (`GET`, `POST`, `PUT`, `DELETE`), Path, and Body to see the live 5-stage trace and decision (**ALLOW** vs **BLOCK**).

### 2. Run the 20-Vector Test Matrix
```powershell
python scripts/live_attack_tester.py
```
Evaluates all combinations of GET, POST, PUT, DELETE for SQLi, XSS, RCE, Path Traversal, and Benign traffic.

### 3. Run Automated Unit & Regression Tests
```powershell
python -m unittest tests/test_waf_pipeline.py
```

### 4. Run the Full-Stack Console
```powershell
npm run dev
```
Access the dashboard at `http://localhost:3000`:
* **Gateway Console:** Manual request inspection and proxy/mock response.
* **Evidence tabs:** State which results/artifacts are absent and link to the reproducible evaluation workflow.
* **Management API key:** Enter the configured key in the browser UI when `WAF_ADMIN_TOKEN` is set.

---

## 5. Project Folder Structure

```
MAJOR WAF 7/
│
├── README.md                      # Comprehensive Architecture, Results & Setup Documentation
├── package.json                   # Web application manifest and dev dependencies
├── tsconfig.json                  # TypeScript compiler configuration
├── vite.config.ts                 # Vite frontend build pipeline
├── index.html                     # Web application entry point
├── server.ts                      # Express API, authenticated management, and configured-origin gateway
│
├── src/                           # Frontend Web Console & Client Inspection
│   ├── App.tsx                    # Transparent prototype console with API-key input
│   ├── index.css                  # Tailwind styles
│   ├── main.tsx                   # React client bootstrap
│   └── waf/                       # TypeScript WAF engine implementation
│       ├── types.ts               # Core telemetry & decision data types
│       ├── canonicalizer.ts       # Defensive request normalizer
│       ├── rules.ts               # Handwritten CRS-inspired regex signatures
│       ├── profile.ts             # Application behavior profile engine
│       ├── policy.ts              # Risk fusion & decision engine
│       └── pipeline.ts            # Complete end-to-end WAF pipeline
│
├── waf/                           # Python inspection pipeline
│   ├── __init__.py                # Package initialization
│   ├── pipeline.py                # Canonicalization, rules, heuristic, policy pipeline
│   ├── normalization/             # Stage 1: Request Canonicalization
│   │   ├── __init__.py
│   │   └── canonicalizer.py
│   ├── rules/                     # Stage 2: OWASP CRS Deterministic Matching
│   │   ├── __init__.py
│   │   └── deterministic_engine.py
│   ├── application_profile/       # Stage 4: Profile & Anomaly Scoring
│   │   ├── __init__.py
│   │   └── profile_engine.py
│   └── risk/                      # Stage 5: Multi-Signal Decision Fusion
│       ├── __init__.py
│       └── policy_engine.py
│
├── scripts/                       # Demo, split, training, and evaluation scripts
│   ├── create_group_splits.py      # Deduplicate and create group-held-out train/val/test splits
│   ├── evaluate_dataset.py         # Baseline comparison and cluster-bootstrap CIs
│   ├── interactive_cli.py         # Live interactive attack testing CLI
│   ├── live_attack_tester.py      # 20-vector test matrix (GET/POST/PUT/DELETE)
│   ├── train_transformer.py       # Sequence-classification Transformer training script
│   └── organize_project.py        # Automated project cleanup & folder reorganization tool
│
├── tests/                         # Production Automated Test Suite
│   ├── __init__.py
│   └── test_waf_pipeline.py       # Unit and regression test suite
│
└── extra_resources/               # Supplementary Research & Experimental Assets
    ├── README.md                  # Detailed guide to extra research resources
    ├── experiments/               # Empirical Academic Experiments
    │   ├── adaptation/            # Experiment D: Few-Shot Application Adaptation
    │   │   └── run_adaptation.py
    │   └── robustness/            # Experiment E: Evasion & Canonicalization Benchmark
    │       ├── run_robustness.py
    │       └── robustness_results.json
    ├── scripts/                   # Dataset Audit Tools
    │   └── inspect_dataset.py     # Audit tool for user-supplied data
    └── diagnostics/               # Offline Diagnostic & Diagnostic Artifacts
```
