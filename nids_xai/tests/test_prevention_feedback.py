import os
import json
import pytest
from starlette.testclient import TestClient

from api.main import app
from api.services.prevention_service import PreventionService
from config import config

client = TestClient(app)


def test_prevention_mode_endpoints():
    # GET mode
    res = client.get("/api/prevention/mode")
    assert res.status_code == 200
    assert "mode" in res.json()

    # POST mode valid
    res = client.post("/api/prevention/mode", json={"mode": "dry_run"})
    assert res.status_code == 200
    assert res.json()["mode"] == "dry_run"

    # POST mode invalid
    res = client.post("/api/prevention/mode", json={"mode": "invalid_mode"})
    assert res.status_code == 400


def test_prevention_service_block_unblock_lifecycle():
    svc = PreventionService()
    svc.set_mode("dry_run")

    # Whitelisted IP
    res = svc.block_ip("127.0.0.1", "test reason")
    assert res["action"] == "skipped"

    # Normal IP block
    res = svc.block_ip("10.0.0.99", "DoS detected", ttl=300)
    assert res["action"] == "dry_run_blocked"
    assert res["ip"] == "10.0.0.99"

    # List blocked
    blocked = svc.get_blocked()
    ips = [b["ip"] for b in blocked]
    assert "10.0.0.99" in ips

    # Unblock
    unblock = svc.unblock_ip("10.0.0.99")
    assert unblock["action"] == "dry_run_unblocked"

    # Unblock not found
    unblock2 = svc.unblock_ip("10.0.0.99")
    assert unblock2["action"] == "not_found"


def test_feedback_api(tmp_path, monkeypatch):
    test_feedback_file = str(tmp_path / "feedback.json")
    monkeypatch.setattr("api.routers.feedback.FEEDBACK_FILE", test_feedback_file)

    # Submit true positive
    res = client.post("/api/feedback", json={"alert_id": "alert-001", "label": "true_positive"})
    assert res.status_code == 200
    data = res.json()
    assert data["stored"] is True
    assert data["alert_id"] == "alert-001"
    assert data["label"] == "true_positive"

    # Submit false positive
    res = client.post("/api/feedback", json={"alert_id": "alert-002", "label": "false_positive"})
    assert res.status_code == 200

    # Retrieve feedback
    res = client.get("/api/feedback?limit=10")
    assert res.status_code == 200
    body = res.json()
    assert body["count"] == 2
    entries = body["feedback"]
    assert entries[0]["alert_id"] == "alert-001"
    assert entries[1]["alert_id"] == "alert-002"
