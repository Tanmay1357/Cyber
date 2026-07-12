import pytest
from api.services.explainer_service import _remap_direction, _sort_features, ExplainerService


def test_remap_attack_to_positive():
    assert _remap_direction("attack") == "positive"


def test_remap_benign_to_negative():
    assert _remap_direction("benign") == "negative"


def test_sort_features_by_abs_shap_desc():
    features = [
        {"feature": "A", "shap_value": 0.1,  "direction": "positive"},
        {"feature": "B", "shap_value": -0.5, "direction": "negative"},
        {"feature": "C", "shap_value": 0.3,  "direction": "positive"},
    ]
    result = _sort_features(features, max_features=8)
    assert result[0]["feature"] == "B"
    assert result[1]["feature"] == "C"
    assert result[2]["feature"] == "A"


def test_sort_features_respects_max():
    features = [{"feature": str(i), "shap_value": float(i), "direction": "positive"}
                for i in range(20)]
    result = _sort_features(features, max_features=8)
    assert len(result) == 8


def test_explain_formats_shap_top3():
    svc = ExplainerService()
    alert = {
        "id": "test-uuid",
        "prediction": "Attack",
        "attack_prob": 0.92,
        "shap_top3": [
            {"feature": "Flow Duration", "value": 0.42, "direction": "attack"},
            {"feature": "Packet Rate",   "value": 0.31, "direction": "attack"},
        ],
    }
    result = svc.explain(alert, model_service=None)
    assert result["alert_id"] == "test-uuid"
    assert result["prediction"] == "Attack"
    assert result["attack_prob"] == 0.92
    assert len(result["features"]) == 2
    assert result["features"][0]["direction"] == "positive"
    assert "summary" in result


def test_explain_raises_when_no_shap():
    svc = ExplainerService()
    alert = {"id": "abc", "prediction": "Benign", "attack_prob": 0.03, "shap_top3": None}
    with pytest.raises(RuntimeError):
        svc.explain(alert, model_service=None)
