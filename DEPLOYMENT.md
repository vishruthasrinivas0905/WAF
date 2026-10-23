# Local Deployment and Gateway Demo

This repository is an academic prototype. The score engine is a handcrafted heuristic and the default /proxy/* behavior is a clearly labeled mock response. Set a single trusted UPSTREAM_URL to enable real HTTP proxying. Production dashboard access uses a signed-in session; direct management API clients use WAF_ADMIN_TOKEN.

## Local dashboard

```powershell
npm ci
npm run dev
```

Open `http://localhost:3000`. Without `UPSTREAM_URL`, proxy responses explicitly say the request was not forwarded. For a local target, set `UPSTREAM_URL=http://127.0.0.1:3001` in the environment before starting the server.

## Protected production mode

Set these environment values through a secret manager or an untracked `.env` file:

```text
NODE_ENV=production
PORT=3000
WAF_MODE=ENFORCING
AUTH_USERNAME=admin
AUTH_PASSWORD_HASH=<bcrypt hash of the dashboard password>
SESSION_SECRET=<random secret, at least 32 characters>
SESSION_COOKIE_SECURE=true
UPSTREAM_URL=https://your-approved-upstream.example
WAF_ADMIN_TOKEN=<random secret, at least 32 characters>
WAF_TRUST_PROXY=<optional trusted proxy IPs/CIDRs, comma-separated>
```

Dashboard sign-in uses AUTH_USERNAME and a bcrypt password hash in AUTH_PASSWORD_HASH; set SESSION_SECRET to a long random value. A signed-in browser session authorizes dashboard management actions. WAF_ADMIN_TOKEN is for direct management API clients and is kept server-side by the dashboard. Do not put these values in frontend code.

`WAF_TRUST_PROXY` must name only proxy addresses you control, for example `loopback,10.0.0.0/8`. Leave it unset when direct clients connect. Express ignores `X-Forwarded-For` unless the connecting proxy matches a configured trusted range. Never set this value to `true`.

## Docker Compose demo

1. Create an untracked .env file with AUTH_USERNAME, a bcrypt AUTH_PASSWORD_HASH, a random SESSION_SECRET of at least 32 characters, and a random WAF_ADMIN_TOKEN of at least 32 characters.
2. Compose pins the demo target to a versioned Juice Shop image tag. Record the image digest as well when archiving a publication run.
3. Start the isolated demo:

```powershell
docker compose up --build
```

The dashboard/gateway is available on http://localhost:8080 and the port is bound to loopback. The local Compose demo uses a non-secure session cookie because it runs over HTTP; production defaults to secure cookies.

## Reproducible evaluation

The UI smoke benchmark uses handcrafted examples and is not publication evidence. For a licensed dataset, fill out `research/dataset_manifest.example.json`, then run:

```powershell
python scripts/evaluate_dataset.py .\private-data\requests.csv --group-column application --category-column category
```

The evaluator writes `evaluation_results/evaluation_report.json`, `test_predictions.csv`, and `split_assignments.csv`. It removes canonical duplicates before a group-held-out train/validation/test split and compares rules-only, heuristic-only, and hybrid lanes. Supply optional trained-model results using `--model-scores-csv` and a validation-selected `--model-threshold`. This runner does not train a Transformer. Read [research/PUBLICATION_READINESS.md](research/PUBLICATION_READINESS.md) before interpreting metrics.

To add the isolated OWASP CRS reference baseline, start the optional Compose profile and replay your licensed corpus through its loopback listener:

```powershell
docker compose --profile baseline up -d upstream-vulnerable-app crs-baseline
python scripts/score_http_baseline.py .\private-data\requests.csv --base-url http://127.0.0.1:8081 --engine-id owasp/modsecurity-crs:4.30.0-nginx-202610180210@sha256:7698c48a41a43138ae317feeec964d1515b861cc1d9e50617bc1cdfe9f314e1d --output .\private-data\crs_predictions.csv
python scripts/evaluate_dataset.py .\private-data\requests.csv --group-column application --baseline-scores crs=.\private-data\crs_predictions.csv
```

The reference image and Juice Shop tag are version-pinned in Compose. Record image digests, CRS paranoia level, and block status mapping with any published report. Only use the replay tool with a local WAF or infrastructure you control.

## Limits

This is a prototype, not a production-supported WAF. It has handwritten signatures and a heuristic score, uses in-memory event metrics, and includes no training dataset or trained model checkpoint. The local smoke corpus cannot establish real-world detection quality or an SLA. Review and harden the deployment for your own traffic and threat model before exposing it to users.
