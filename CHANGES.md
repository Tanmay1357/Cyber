# CHANGES

## Feature additions (2026-11-11)

### New files
- `nids_xai/rules/__init__.py` — package init
- `nids_xai/rules/rules.yaml` — rule definitions
- `nids_xai/rules/engine.py` — rule evaluator
- `nids_xai/rules/risk_score.py` — risk score computation
- `nids_xai/api/services/prevention_service.py` — iptables enforcement service
- `nids_xai/api/routers/prevention.py` — /api/blocked and /api/unblock endpoints
- `nids_xai/api/routers/feedback.py` — /api/feedback endpoint
- `nids_xai/scripts/retrain.py` — versioned model retraining script
- `nids_xai/tests/test_rules.py` — rule engine tests
- `nids_xai/tests/test_prevention_feedback.py` — prevention service and feedback router tests
- `web/src/components/SuspiciousIPs.jsx` — suspicious IPs panel
- `web/src/components/BlockedIPs.jsx` — blocked IPs panel with unblock
- `web/src/components/LiveTrafficChart.jsx` — live traffic line chart
- `web/src/components/AlertExplanation.jsx` — explanation list + feedback buttons

### Modified files
- `nids_xai/config/config.py` — added RISK_WEIGHT_ML, RISK_WEIGHT_RULE, RISK_LEVELS, enforcement config
- `nids_xai/api/main.py` — registered prevention and feedback routers
- `nids_xai/api/services/monitor_service.py` — wired rule engine + risk score + explanation into alerts
- `web/src/components/AlertTable.jsx` — added risk score column, attack type column
- `web/src/components/ShapPanel.jsx` — added AlertExplanation with feedback buttons
- `web/src/pages/Dashboard.jsx` — added SuspiciousIPs and BlockedIPs panels
- `README.md` — updated with run instructions and enforce mode warning
