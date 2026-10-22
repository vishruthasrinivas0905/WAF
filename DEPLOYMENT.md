# Local Deployment and Gateway Demo

This repository is an academic prototype. The score engine is a handcrafted heuristic and the default `/proxy/*` behavior is a clearly labeled mock response. Set a single trusted `UPSTREAM_URL` to enable real HTTP proxying. Production management endpoints require an admin bearer token.

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
UPSTREAM_URL=https://your-approved-upstream.example
WAF_ADMIN_TOKEN=<random secret, at least 32 characters>
WAF_TRUST_PROXY=<optional trusted proxy IPs/CIDRs, comma-separated>
```

`UPSTREAM_URL` must be an origin without credentials, path, query, or fragment. The gateway keeps requests on that origin, does not follow redirects, has a 10-second upstream timeout, and limits upstream response bodies to 10 MiB. Management APIs under `/api/waf` require `Authorization: Bearer <WAF_ADMIN_TOKEN>`. The UI's password field holds the key in page memory and sends it only to those APIs.

`WAF_TRUST_PROXY` must name only proxy addresses you control, for example `loopback,10.0.0.0/8`. Leave it unset when direct clients connect. Express ignores `X-Forwarded-For` unless the connecting proxy matches a configured trusted range. Never set this value to `true`.

## Docker Compose demo

1. Create an untracked `.env` file with a random `WAF_ADMIN_TOKEN` at least 32 characters long.
2. Compose pins the demo target to a versioned Juice Shop image tag. Record the image digest as well when archiving a publication run.
3. Start the isolated demo:

```powershell
docker compose up --build
```

The dashboard/gateway is exposed on `http://localhost:8080`. The WAF proxies to the Juice Shop service configured in Compose. The admin key must be entered in the dashboard for telemetry and management controls. Keep this intentionally vulnerable target isolated and do not expose it publicly.

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
