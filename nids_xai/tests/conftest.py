"""
Shared pytest fixtures for NIDS-XAI smoke tests.

Tests run from the repo root with PYTHONPATH=nids_xai (mirrors how the API
runs in production via `python nids_xai/api/main.py`).
"""
import sys
from pathlib import Path

import pytest

# Make `from api.x import y` and `from src.x import y` resolve regardless
# of where pytest is invoked from.
_NIDS_DIR = Path(__file__).resolve().parent.parent
if str(_NIDS_DIR) not in sys.path:
    sys.path.insert(0, str(_NIDS_DIR))


@pytest.fixture(scope="session")
def api_client():
    """FastAPI TestClient against the live app. Triggers lifespan, so
    model_service.load_latest() runs once for the whole test session."""
    from fastapi.testclient import TestClient
    from api.main import app

    with TestClient(app) as client:
        yield client


@pytest.fixture
def fresh_alert_store():
    """A clean, isolated AlertStore (does not share state with the singleton)."""
    from api.services.alert_store import AlertStore
    return AlertStore(maxlen=10)
