# AppAware-WAF: Application-Aware Transformer Web Application Firewall

A production-oriented, research-grade Web Application Firewall combining bounded request canonicalization, OWASP Core Rule Set (CRS) deterministic validation, a sequence-classification Transformer (DistilBERT), an application-specific profile engine, and a live reverse-proxy gateway.

---

## 1. Executive Summary & Key Results

| Metric / Experiment | Baseline / Unadapted | AppAware Hybrid WAF | Impact / Evidence |
| :--- | :---: | :---: | :--- |
| **In-Distribution Test Accuracy** | — | **94.57%** | Evaluated on 27,457 test requests |
| **Test F1-Score (Experiment A)** | — | **0.9532** | Precision: 99.95%, Recall: 91.09%, ROC-AUC: 0.9904 |
| **False Negative Rate (FNR)** | 8.91% (1,484 missed by standalone ML) | **0.00%** | Parallel OWASP CRS rule layer intercepts missed vectors |
| **Out-of-Distribution FPR (Experiment D)** | 14.20% (0 benign samples) | **2.10%** (1,000 samples) | **-85% False Positive Reduction** via few-shot profile adaptation |
| **Evasion Robustness (Experiment E)** | 63.16% (Direct inspection) | **100.00%** (Canonicalized) | **+36.84% Evasion Resistance** across 19 obfuscated attack vectors |
| **Train-Test String Contamination** | — | **0.00% (0 / 27,457)** | Rigorously verified zero train-test string leakage |
| **Median P50 Processing Latency** | 144.71 ms (CPU DistilBERT) | **0.95 ms** | Sub-1ms gateway decision via hybrid multi-signal gating |
| **Gateway Enforcement Accuracy** | — | **100.0% (20/20 Passed)** | GET, POST, PUT, DELETE across SQLi, XSS, RCE, Traversal, Benign |

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
                   │  (Known CRS signatures, injection patterns)
                   └────────────────────┬────────────────────┘
                                        │ (Score: S_det)
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │       TRANSFORMER DETECTOR ENGINE       │
                   │   (DistilBERT / MiniLM Tokenizer + Clf) │
                   └────────────────────┬────────────────────┘
                                        │ (Score: P_ml)
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │      APPLICATION PROFILE EVALUATOR      │
                   │   (Route match, Param structure, Stats) │
                   └────────────────────┬────────────────────┘
                                        │ (Score: S_profile)
                                        ▼
                   ┌─────────────────────────────────────────┐
                   │          RISK & POLICY ENGINE           │
                   │    Fusion: Risk = f(S_det, P_ml, S_app) │
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

## 3. Dataset Accounting & Provenance

The standardized corpus comprises **183,045 HTTP-request records** collected from five sources:
* CSIC 2010
* ECML/PKDD 2007
* HttpParamsDataset
* PayloadsAllTheThings
* Web-Application-Attack-Datasets

### Split Distribution
* **Train Split (`transformer_train.csv`):** 128,131 rows (77,731 Malicious / 50,400 Benign, 70.0%)
* **Validation Split (`transformer_val.csv`):** 27,457 rows (16,657 Malicious / 10,800 Benign, 15.0%)
* **Test Split (`transformer_test.csv`):** 27,457 rows (16,657 Malicious / 10,800 Benign, 15.0%)
* **Total Class Balance:** 72,000 Benign (39.33%), 111,045 Malicious (60.67%)
* **Ground Truth Column:** `is_attack` (0 = Benign, 1 = Malicious).

### Benchmark Delimiter Shortcut Learning Discovery
Sample row inspection of raw dataset records revealed trailing parser metadata stamped by benchmark tools:
```text
\n\nnull\n\nEnd - Id: 28966\nStart - Id: 2877\nclass: Valid
```
To prevent self-attention shortcut learning, `waf/normalization/canonicalizer.py` strictly strips these non-HTTP annotations before tokenization.

---

## 4. Local Execution & Testing (Windows PowerShell)

Navigate to your project directory:
```powershell
cd "C:\Users\SAHANA KS\OneDrive\Desktop\MAJOR WAF 7"
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

### 4. Run the Full-Stack Web Console & Reverse Proxy Gateway
```powershell
npm run dev
```
Access the dashboard at `http://localhost:3000`:
* **Live Gateway Console:** Manual request interceptor with real-time telemetry.
* **Few-Shot Adaptation Tab:** Interactive budget curves (0, 100, 500, 1,000 samples).
* **Robustness Suite Tab:** Breakdown of the +36.84% evasion resilience improvement.
* **Dataset & Model Provenance Tab:** Empirical confusion matrix and audit metrics.
* **Research Manuscript Tab:** Formatted academic manuscript ready for project defense and publication.

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
├── server.ts                      # Express API backend & Live WAF Reverse Proxy Gateway
│
├── src/                           # Frontend Web Console & Client Inspection
│   ├── App.tsx                    # Interactive dashboard & research defense console
│   ├── index.css                  # Tailwind styles
│   ├── main.tsx                   # React client bootstrap
│   └── waf/                       # TypeScript WAF engine implementation
│       ├── types.ts               # Core telemetry & decision data types
│       ├── canonicalizer.ts       # Defensive request normalizer
│       ├── rules.ts               # OWASP CRS regex rules
│       ├── profile.ts             # Application behavior profile engine
│       ├── policy.ts              # Risk fusion & decision engine
│       └── pipeline.ts            # Complete end-to-end WAF pipeline
│
├── waf/                           # Production Python Core WAF Package
│   ├── __init__.py                # Package initialization
│   ├── pipeline.py                # 5-stage WAF inspection pipeline
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
├── scripts/                       # Core Production Scripts
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
    │   └── inspect_dataset.py     # Leak audit across 183,045 records
    └── diagnostics/               # Offline Diagnostic & Diagnostic Artifacts
```
#   W A F  
 