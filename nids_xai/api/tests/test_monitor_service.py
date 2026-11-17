import pytest
from api.services.monitor_service import MonitorService, _normalise_event
from api.services.alert_store import AlertStore


def test_normalise_flow_event():
    raw = {
        "type": "monitor_event",
        "src_ip": "1.2.3.4", "src_port": 100,
        "dst_ip": "5.6.7.8", "dst_port": 80,
        "is_alert": True,
        "prediction": "Attack",
        "confidence": 0.97,
        "timestamp": "14:32:01",
        "shap_factors": [
            {"feature": "Flow Duration", "shap_value": 0.42, "direction": "attack"},
        ],
    }
    result = _normalise_event(raw)
    assert result["kind"] == "flow"
    assert result["is_attack"] is True
    assert result["attack_prob"] == 0.97
    assert result["shap_top3"][0]["feature"] == "Flow Duration"
    assert result["shap_top3"][0]["value"] == 0.42
    assert "direction" in result["shap_top3"][0]


def test_normalise_benign_event_has_null_shap():
    raw = {
        "type": "monitor_event",
        "src_ip": "1.2.3.4", "src_port": 100,
        "dst_ip": "5.6.7.8", "dst_port": 80,
        "is_alert": False,
        "prediction": "Benign",
        "confidence": 0.05,
        "timestamp": "14:32:02",
        "shap_factors": [],
    }
    result = _normalise_event(raw)
    assert result["kind"] == "flow"
    assert result["is_attack"] is False
    assert result["shap_top3"] is None


def test_normalise_replay_done():
    raw = {"type": "monitor_replay_done", "total_flows": 100, "elapsed": 5.2}
    result = _normalise_event(raw)
    assert result["kind"] == "replay_done"
    assert result["total_flows"] == 100


def test_normalise_error():
    raw = {"type": "monitor_error", "message": "File not found"}
    result = _normalise_event(raw)
    assert result["kind"] == "error"
    assert result["message"] == "File not found"


def test_normalise_event_risk_and_rules():
    raw = {
        "type": "monitor_event",
        "src_ip": "1.2.3.4", "src_port": 100,
        "dst_ip": "5.6.7.8", "dst_port": 80,
        "is_alert": True,
        "prediction": "Attack",
        "confidence": 0.90,
        "timestamp": "14:32:01",
        "distinct_dst_ports": 100,  # triggers PORTSCAN_01
        "shap_factors": [
            {"feature": "Flow Duration", "shap_value": 0.42, "direction": "attack"},
        ],
    }
    result = _normalise_event(raw)
    assert "risk_score" in result
    assert "risk_level" in result
    assert "matched_rules" in result
    assert "explanation" in result
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert any(r["rule_id"] == "PORTSCAN_01" for r in result["matched_rules"])
    assert any("Flow Duration" in exp for exp in result["explanation"])
    assert any("port scan" in exp.lower() for exp in result["explanation"])
