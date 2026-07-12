# NIDS-XAI — Backend & Detection Engine

The Python side of the Network Intrusion Detection System with Explainable AI:
the FastAPI backend, the Random Forest detection engine, the SHAP/LIME explainer,
and a menu-driven CLI.

For the overall project (architecture, datasets, web dashboard) see the
[root README](../README.md). For the React frontend see [web/README.md](../web/README.md).

## What's here

```
nids_xai/
├── api/            FastAPI backend (REST + WebSocket)
│   ├── main.py     app factory, CORS, router registration, model load on startup
│   ├── routers/    HTTP endpoints: status, model, monitor, alerts, explain, train, evaluate, classify
│   ├── services/   logic + state singletons:
│   │               model_service, monitor_service, explainer_service,
│   │               type_classifier_service, alert_store, training_service
│   └── ws/         WebSocket channels (/ws/alerts, /ws/stats, /ws/training) + manager
├── src/            detection engine
│   ├── data_loader.py     chunked CSV loading (CIC-IDS2017/2018)
│   ├── preprocessor.py    clean -> top-25 feature selection (ANOVA F-test) -> scale -> 80/20 split
│   ├── model_trainer.py   Random Forest training + persistence
│   ├── type_trainer.py    attack-type classifier
│   ├── evaluator.py       metrics + plots
│   ├── explainer.py       SHAP + LIME with plain-English summaries
│   ├── classifier.py      classify a new CSV (CLI)
│   ├── monitor.py         live / replay flow monitor
│   └── pcap_converter.py  PCAP -> flow CSV
├── config/config.py       all configuration constants
├── tools/kali_replay.py   feed dataset flows to the backend over the network (demo)
├── examples/              sample CSVs / PCAPs
├── tests/ and api/tests/  test suites
└── main.py                CLI entry point
```

## Setup

```bash
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
```

## Run the API

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Key endpoints:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET  | `/api/status` | health check |
| GET  | `/api/model`, `/api/model/list` | current / available models |
| POST | `/api/model/load` | switch model |
| POST | `/api/monitor/start`, `/replay`, `/ingest`, `/stop` | drive live detection |
| GET  | `/api/alerts` | recent alerts |
| GET  | `/api/explain/{alert_id}`, `/lime`, `/type` | on-demand explanations |
| POST | `/api/train`, `/api/evaluate`, `/api/classify` | train / evaluate / classify |
| WS   | `/ws/alerts`, `/ws/stats`, `/ws/training` | live streams |

## Run the CLI

```bash
python main.py
```

```
[1] Load & Preprocess Data
[2] Load Saved Data (Quick)
[3] Train Model
[4] Evaluate Model
[5] Test & Explain Predictions
[6] Classify New CSV File
[7] View Status
[8] Exit
```

## Configuration

All settings live in `config/config.py`:

```python
ACTIVE_DATASET   = "2017"     # "2017", "2018", or "both"
TOP_K_FEATURES   = 25         # features kept by SelectKBest (ANOVA F-test)
RF_PARAMS        = {...}       # n_estimators=100, max_depth=15, class_weight="balanced", ...
TEST_SIZE        = 0.2        # 80/20 stratified split
CHUNK_SIZE       = 200000     # rows per chunk when loading
MAX_TRAINING_SAMPLES = 300000 # training set cap
SHAP_SAMPLE_SIZE = 100        # background samples for SHAP
```

## Tests

```bash
pytest
```

Datasets, the processed cache, trained `.joblib` models and `outputs/` are
gitignored. Train once to regenerate them locally.
