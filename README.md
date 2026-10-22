# AppAware-WAF: Application-Aware Web Application Firewall Prototype

An academic prototype for request canonicalization, handwritten attack signatures, heuristic risk scoring, application-profile demonstrations, and a configurable HTTP gateway. It is not a production-validated WAF. The bundled score engine is a lexical/entropy heuristic; this repository does not contain trained Transformer weights or source dataset files.

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
| Evaluation | Small handcrafted smoke corpus plus a group-held-out CSV evaluation runner |

Earlier drafts contained dataset-scale scores that cannot be reproduced from this repository because the cited datasets and model checkpoint are absent. Those figures have been removed from the live interface and should not be cited as results.

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

No licensed research dataset or trained checkpoint is included. Start with [the dataset manifest template](research/dataset_manifest.example.json), fill in the source, license, retrieval date, source hash, label method, group field, and model provenance, then evaluate a local CSV without committing licensed data:

```powershell
python scripts/evaluate_dataset.py .\private-data\requests.csv --group-column application --category-column category
```

Create canonical-deduplicated train/validation/test CSVs with groups kept intact:

```powershell
python scripts/create_group_splits.py .\private-data\requests.csv --group-column application --output-dir .\private-data\splits
```

The split command writes `transformer_train.csv`, `transformer_val.csv`, `transformer_test.csv`, a hash-based `split_assignments.csv`, and a provenance summary. Train using the existing optional training script and supplied dependencies/data:

```powershell
python scripts/train_transformer.py --data_dir .\private-data\splits --output_dir .\private-model
```

For group-held-out evaluation, rerun with the same source CSV, group column, sizes, and seed:

```powershell
python scripts/evaluate_dataset.py .\private-data\requests.csv --group-column application --category-column category --model-scores-csv .\private-model\test_model_scores.csv --model-threshold 0.50
```

The evaluator uses the same deterministic split procedure, compares rules-only, heuristic-only, and hybrid decisions, reports per-category results, and calculates cluster-bootstrap confidence intervals over test groups. Replace `0.50` with the threshold selected on validation data. `train_transformer.py` writes a test-only model-score sidecar keyed by canonical request SHA-256. The evaluator does not train a Transformer, and its heuristic lane is not a model result. See [PUBLICATION_READINESS.md](research/PUBLICATION_READINESS.md) for requirements and limits.

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
