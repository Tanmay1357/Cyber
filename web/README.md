# NIDS-XAI Dashboard (Frontend)

The React web dashboard for the Network Intrusion Detection System with
Explainable AI. It talks to the FastAPI backend over REST and three WebSocket
channels, showing live alerts, KPI metrics, traffic charts, and on-demand
SHAP/LIME explanations.

For the overall project see the [root README](../README.md); for the backend see
[nids_xai/README.md](../nids_xai/README.md).

## Stack

- **React 19** + **Vite** — UI and build tooling
- **react-router-dom** — page navigation
- **recharts** — live traffic and donut charts
- **axios** — REST calls to the backend
- **Vitest** + Testing Library — component/hook tests

## Structure

```
web/src/
├── main.jsx              app entry (loads styles/globals.css + components.css)
├── App.jsx               routes + layout
├── pages/               Dashboard, Alerts, Explain, Classify, Train, Evaluate, Settings
├── components/          KpiCards, AlertTable, ShapPanel, TrafficChart, DonutChart,
│                        TopBar, ModeToggle, StatusBar, FilterButtons, WelcomeBanner, ui
├── hooks/               useAlerts (WS), useStats (WS), useModel, useTheme
├── api/                 http.js (axios), ws.js (WebSocket helper)
└── styles/              globals.css, components.css
```

## Setup

```bash
npm install
```

## Run

The backend must be running first (from `nids_xai/`):

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Then start the dev server:

```bash
npm run dev      # Vite dev server with hot reload
```

Open the printed URL (default http://localhost:5173).

## Build

```bash
npm run build    # outputs to web/dist/
npm run preview  # preview the production build
```

When `web/dist/` exists, the FastAPI backend serves it directly, so the whole
app (API + UI) can run from `http://localhost:8000`.

## How it connects

- **`/ws/alerts`** — each classified flow is pushed live into the alert table (`useAlerts`).
- **`/ws/stats`** — KPI cards and traffic chart update in real time (`useStats`).
- **`/ws/training`** — training progress streams to the Train page.
- **REST `/api/...`** — model selection, on-demand explanations, classify/evaluate/train.

## Tests

```bash
npm run test     # Vitest
```
