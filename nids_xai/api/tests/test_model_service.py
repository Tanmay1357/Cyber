import pytest
from pathlib import Path
from api.services.model_service import ModelService

def test_list_models_returns_dict():
    svc = ModelService()
    models = svc.list_models()
    assert isinstance(models, dict)

def test_status_before_load():
    svc = ModelService()
    status = svc.status()
    assert status["loaded"] is False
    assert status["model_file"] is None

def test_load_nonexistent_raises():
    svc = ModelService()
    with pytest.raises(FileNotFoundError):
        svc.load("nonexistent_model.joblib")
