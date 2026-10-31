# Explainable BGP Origin and Subprefix Anomaly Monitor

This project detects suspicious BGP announcements using operator inventory,
RPKI ROAs, routing state, and explainable rule findings. It includes a
batch-oriented engine, MRT replay support, incremental processing, FastAPI,
SQLite persistence, and an optional XGBoost second-stage detector.

## Canonical event format

Announcements and withdrawals use `announcement` and `withdrawal`. The parser
also accepts `A` and `W`, Unix timestamps or ISO 8601 timestamps, and ASN
strings such as `AS64500`. Prefixes must be strict networks; host bits are
rejected.

```json
{
  "timestamp": 1793260800,
  "event_type": "announcement",
  "prefix": "203.0.113.0/24",
  "as_path": [64510, 64520, 64500],
  "origin_as": 64500
}
```

The supplied origin must agree with the final AS_PATH ASN. RPKI state is
calculated from ROAs and is never trusted from the incoming event.

## Inventory and ROA formats

Inventory records support multiple legitimate origins:

```json
[
  {"prefix": "203.0.113.0/24", "origin_as": [64500, 64501]}
]
```

ROAs include validity windows:

```json
[
  {
    "prefix": "203.0.113.0/24",
    "origin_as": 64500,
    "max_length": 24,
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z"
  }
]
```

## Current modules

- `src/ingestion`: strict event, inventory, and ROA parsing plus JSONL replay.
- `src/routing`: origin extraction, prefix utilities, and active route state.
- `src/detection`: origin, RPKI, subprefix, and hybrid rule evaluation.
- `src/features`, `src/ml`, and `src/storage`: follow-up integration phases.

## API

Start the service with:

```bash
uvicorn src.api.main:app --reload
```

Available endpoints include:

- `GET /health`
- `POST /detect`
- `POST /detect/batch`
- `GET /routes`
- `GET /history`
- `POST /roas`
- `POST /inventory`
- `GET /model/status`

Interactive API documentation is available at `/docs`.

## Real data setup

The repository includes a setup script for RIPE RIS MRT data, Routinator VRPs,
and a demo inventory:

```bash
chmod +x scripts/setup_data.sh
MRT_RRC=rrc00 ./scripts/setup_data.sh
```

Set `MRT_URL` when a specific archive is required. The script resolves the
latest bview archive from the RIPE RIS collector index when it is not set.
Routinator must be installed and initialized before generating VRP JSON.
Generated data is ignored by Git. Configure the application with:

```bash
export BGP_INVENTORY_PATH=data/inventory/prefix_inventory.json
export BGP_ROA_PATH=data/roa/sample_vrps.json
export BGP_DATABASE_PATH=data/bgp_sentinel.db
```

## Development

Python 3.11+ is required. Install dependencies with:

```bash
pip install -r requirements.txt
```

Run the test suite with:

```bash
pytest
```

The rule engine remains usable when optional ML dependencies or a trained model
are unavailable. Configure database, inventory, ROA, model, and CORS settings
through environment variables; see `.env.example`.

For announcements, when `models/bgp_sentinel_xgboost.json` is available, the
API uses the model's anomaly probability as `confidence_score` and returns the
same value as `ml_score`, together with `ml_prediction`. If the model is
unavailable, the API keeps the rule-based confidence and returns
`ml_score: null`. Train or place the model artifact before relying on ML
confidence:

```bash
python src/ml/train_xgboost.py
```

## Supabase deployment

The local API uses SQLite by default so development and tests do not require
cloud credentials. The production PostgreSQL schema is in
`supabase/migrations/001_initial_schema.sql`. Open the Supabase SQL Editor,
paste that migration, and run it once for a new project.

The API persistence layer uses the same production tables:
`bgp_events`, `roa_records`, `prefix_inventory`, `routing_state`,
`anomaly_alerts`, `detection_evidence`, `ml_predictions`, and `system_logs`.
Route history is read from `bgp_events`, because the final Supabase schema does
not define a separate route-history table. Synthetic CSV data is kept in the
separate `dataset_rows` table created by the optional seed migration.

For the demo inventory and local CSV datasets, run
`supabase/migrations/002_seed_demo_inventory.sql` after the schema migration.
This inserts four inventory rows and loads the CSV files under `data/` into a
separate `dataset_rows` table (9,000 rows across six CSV files) for training
and replay. It intentionally does not convert synthetic rows into live BGP
events, routing state, alerts, or ML predictions. Load real ROA/VRP records
from Routinator instead.

Set `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, and `DATABASE_URL` only in the
server environment (local `.env` or Vercel project settings). Never use the
secret key in a `VITE_*` variable or frontend source. The migration enables
Row Level Security; privileged writes must remain server-side.

When `DATABASE_URL` is present, the API selects its PostgreSQL adapter
automatically. When it is absent, the API uses the local SQLite database.
For local development, create an ignored `.env` file in the repository root:

```dotenv
DATABASE_URL=postgresql://...
```

The value is never logged or sent to the frontend. The PostgreSQL adapter uses
the repository-compatible operational tables (`events`, `active_routes`,
`route_history`, `roas`, `inventory`, and `detection_results`); run the
application initialization once after applying the Supabase migration.

## Vercel deployment

`api/index.py` is the ASGI entrypoint and `vercel.json` routes `/api/*` to the
FastAPI application. The frontend uses `/api` automatically in production and
uses `http://127.0.0.1:8000` during local Vite development. Set
`VITE_API_BASE_URL` if the backend is hosted elsewhere.

From the repository root:

```bash
npx vercel
```

Configure the server-side environment variables in the Vercel dashboard before
deploying. A Vercel function supports bounded JSON ingestion, replay, and
dashboard queries; it cannot provide a permanently running BGP collector or
long-lived streaming connection. Run continuous collectors in a separate
worker environment and send normalized events to `/api/ingest`.

The API also exposes the deployment-oriented aliases `/api/analyze`,
`/api/ingest`, `/api/replay`, `/api/upload-roa`, `/api/upload-inventory`, and
`/api/ml/status` (the unprefixed local-development routes remain available).

## Team Introduction Video
Youtube Link - https://youtu.be/EGsV7reaN_A?si=DqGCYhcMbKtF8-A0
