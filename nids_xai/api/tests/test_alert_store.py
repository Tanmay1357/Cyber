import pytest
from api.services.alert_store import AlertStore

def test_push_assigns_uuid():
    store = AlertStore(maxlen=10)
    alert = store.push({"kind": "flow", "is_attack": True})
    assert "id" in alert
    assert len(alert["id"]) == 36  # UUID4 format

def test_get_all_returns_newest_first():
    store = AlertStore(maxlen=10)
    store.push({"kind": "flow", "is_attack": False, "seq": 1})
    store.push({"kind": "flow", "is_attack": True,  "seq": 2})
    results = store.get(limit=10, filter_type="all")
    assert results[0]["seq"] == 2

def test_filter_attack_only():
    store = AlertStore(maxlen=10)
    store.push({"kind": "flow", "is_attack": False})
    store.push({"kind": "flow", "is_attack": True})
    store.push({"kind": "flow", "is_attack": True})
    results = store.get(limit=10, filter_type="attack")
    assert all(r["is_attack"] for r in results)
    assert len(results) == 2

def test_filter_benign_only():
    store = AlertStore(maxlen=10)
    store.push({"kind": "flow", "is_attack": False})
    store.push({"kind": "flow", "is_attack": True})
    results = store.get(limit=10, filter_type="benign")
    assert len(results) == 1
    assert not results[0]["is_attack"]

def test_maxlen_evicts_oldest():
    store = AlertStore(maxlen=3)
    for i in range(5):
        store.push({"seq": i})
    results = store.get(limit=10, filter_type="all")
    seqs = [r["seq"] for r in results]
    assert 0 not in seqs and 1 not in seqs
    assert len(results) == 3

def test_get_by_id():
    store = AlertStore(maxlen=10)
    alert = store.push({"kind": "flow"})
    found = store.get_by_id(alert["id"])
    assert found is not None
    assert found["id"] == alert["id"]

def test_get_by_id_missing_returns_none():
    store = AlertStore(maxlen=10)
    assert store.get_by_id("nonexistent-id") is None
