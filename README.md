# Network Intrusion Detection System with Explainable AI (NIDS-XAI)

A machine learning Network Intrusion Detection System that classifies network
traffic as benign or malicious using a Random Forest model, and explains every
decision in plain English using SHAP and LIME. A second model names the attack
type (Port Scan, DoS, Brute Force, and so on), and a live web dashboard streams
alerts with their explanations in real time.

This is a Final Year Project. It is built for detection and explanation in a lab
setting, not for blocking traffic or production deployment.

---

## Key features

- **Binary detection** — Random Forest classifies each network flow as Benign or Attack
- **Dual explainability** — SHAP and LIME explain every prediction, with a plain-English narrative
- **Attack-type classifier** — a second Random Forest names the attack type for flagged flows
- **Live web dashboard** — React frontend over a FastAPI backend, streaming alerts and stats over WebSockets
- **Two datasets** — CIC-IDS2017 and CIC-IDS2018, with cross-dataset validation
- **Faithful explanations** — SHAP contributions reconstruct the model output and agree with the model's own feature importances

---

## Architecture

The project has three tiers:

```
React Frontend  ──HTTP / WebSocket──►  FastAPI Backend  ──►  AI Detection Engine
   (web/)                                 (nids_xai/api/)        (nids_xai/src/)
 dashboard, alerts,                    REST + WebSocket        Random Forest,
 charts, SHAP panel                    routers + services      SHAP + LIME, monitor
```

- **Frontend** (`web/`) — React 19 + Vite, react-router, recharts, axios. The dashboard, alert table, KPI cards and SHAP panel.
- **Backend** (`nids_xai/api/`) — FastAPI app exposing REST endpoints and three WebSocket channels (`/ws/alerts`, `/ws/stats`, `/ws/training`). Thin routers delegate to singleton services.
- **Detection engine** (`nids_xai/src/`) — the preprocessing, Random Forest training, SHAP/LIME explainer, and flow monitor.

There is also a menu-driven **CLI** (`nids_xai/main.py`) for training, evaluation and explanation without the web stack.

---

## Project structure

```
nids_xai_projectv2/
├── README.md                     # This file
├── docs/                         # Architecture and testing notes
├── nids_xai/
│   ├── api/                      # FastAPI backend
│   │   ├── main.py               #   app factory, CORS, router registration
│   │   ├── routers/              #   HTTP endpoints (model, monitor, alerts, explain, train, evaluate, classify)
│   │   ├── services/             #   logic + state (model, monitor, explainer, alert store, type classifier)
│   │   └── ws/                   #   WebSocket endpoints + connection manager
│   ├── src/
│   │   ├── data_loader.py        #   chunked CSV loading
│   │   ├── preprocessor.py       #   cleaning, feature selection, scaling, split
│   │   ├── model_trainer.py      #   Random Forest training + persistence
│   │   ├── type_trainer.py       #   attack-type classifier training
│   │   ├── evaluator.py          #   metrics + plots
│   │   ├── explainer.py          #   SHAP + LIME with English summaries
│   │   ├── classifier.py         #   CSV classification (CLI)
│   │   ├── monitor.py            #   live / replay flow monitor
│   │   └── pcap_converter.py     #   PCAP -> flow CSV
│   ├── config/config.py          # all configuration constants
│   ├── data/raw/                 # CIC-IDS2017 / 2018 CSVs (not committed)
│   ├── data/processed/           # preprocessed cache (not committed)
│   ├── models/                   # trained models (not committed)
│   ├── examples/                 # sample CSVs/PCAPs for the demo
│   ├── tools/kali_replay.py      # feeds dataset flows to the backend over the network
│   ├── tests/                    # CLI + integration tests
│   ├── main.py                   # CLI entry point
│   └── requirements.txt
└── web/                          # React dashboard (see web/README.md)
```

---

## Requirements

- Python 3.10+
- Node.js 18+ (for the web dashboard)
- 16 GB RAM recommended for training on the full datasets
- Npcap (Windows) only if you want live packet capture with Scapy

---

## Installation

### Backend

```bash
cd nids_xai
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
```

### Frontend

```bash
cd web
npm install
```

---

## Datasets

Place the CIC-IDS CSV files under:

```
nids_xai/data/raw/CIC-IDS-2017/
nids_xai/data/raw/CIC-IDS-2018/
```

- CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- CIC-IDS2018: https://www.unb.ca/cic/datasets/ids-2018.html

Datasets and trained models are gitignored (too large to commit). Train a model
once and the processed cache and `.joblib` files are created locally.

---

## Running

### Web dashboard (backend + frontend)

```bash
# Terminal 1 — backend (from nids_xai/)
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Terminal 2 — frontend (from web/)
npm run dev
```

Open the dashboard at the Vite URL (default http://localhost:5173). The backend
serves the API on http://localhost:8000.

### CLI

```bash
cd nids_xai
python main.py
```

Menu: Load & Preprocess → Train → Evaluate → Test & Explain → Classify CSV.

---

## How it works

1. **Preprocessing** (`src/preprocessor.py`) — loads the CSVs in chunks, cleans and
   converts to numeric, selects the top 25 features with an ANOVA F-test
   (`SelectKBest(f_classif)`), scales with `StandardScaler`, and makes an 80/20
   stratified train/test split.
2. **Detection** (`src/model_trainer.py`) — a Random Forest (100 trees, max depth 15,
   balanced class weights) classifies each flow as Benign or Attack.
3. **Explanation** (`src/explainer.py`) — SHAP (TreeExplainer) gives per-feature
   contributions toward the decision; LIME gives local rules. Both are turned into
   a plain-English narrative. SHAP contributions sum back to the model output, and
   agree closely with the model's own feature importances.
4. **Attack type** (`src/type_trainer.py`) — a second Random Forest names the attack
   type for flows already flagged as attacks.
5. **Dashboard** — every classified flow is pushed to the React UI over WebSockets,
   with KPI metrics, a live alert table, and an on-demand SHAP/LIME explanation panel.

---

## Evaluation metrics

- **Detection (binary):** Accuracy, Precision, Recall (detection rate), F1, ROC-AUC, confusion matrix, and per-attack-type accuracy.
- **Explanation (faithfulness):** SHAP additivity (contributions reconstruct the prediction), agreement with the model's feature importances, and SHAP–LIME agreement.

Typical results: ~98% accuracy on both datasets; attack-type accuracy 96–99.7%.

---

## Testing

```bash
cd nids_xai
pytest
```

See `docs/TESTING.md` for details.

---

## References

- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.* ICISSP, 108–116.
- Lundberg, S. M., & Lee, S. I. (2017). *A Unified Approach to Interpreting Model Predictions.* NeurIPS 30.
- Ribeiro, M. T., Singh, S., & Guestrin, C. (2016). *"Why Should I Trust You?" Explaining the Predictions of Any Classifier.* KDD, 1135–1144.
- Breiman, L. (2001). *Random Forests.* Machine Learning, 45(1), 5–32.

---

## Acknowledgments

- Canadian Institute for Cybersecurity for the CIC-IDS datasets
- The SHAP, LIME, scikit-learn, FastAPI and React projects

Developed as a Final Year Project for academic purposes.
