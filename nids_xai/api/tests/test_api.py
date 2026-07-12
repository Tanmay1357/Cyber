import pytest
from fastapi.testclient import TestClient
from api.main import create_app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_status_endpoint(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    data = r.json()
    assert "model_loaded" in data
    assert "monitor_running" in data


def test_model_list_endpoint(client):
    r = client.get("/api/model/list")
    assert r.status_code == 200
    assert isinstance(r.json(), dict)


def test_alerts_endpoint_empty(client):
    r = client.get("/api/alerts")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_explain_unknown_id_returns_404(client):
    r = client.get("/api/explain/nonexistent-id")
    assert r.status_code == 404
