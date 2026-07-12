from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from api.services.alert_store import alert_store
from api.services.explainer_service import explainer_service
from api.services.model_service import model_service

router = APIRouter()
_BASE = Path(__file__).parent.parent.parent


@router.get("/api/explain/sample")
def explain_sample(sample_type: str = Query("attack", alias="type"),
                   index: Optional[int] = Query(None, description="Explain this exact row instead of a random one"),
                   dataset: Optional[str] = Query(None, description="Which dataset to sample from ('2017' or '2018')")):
    """
    Generate a SHAP + LIME explanation for a dataset row. If `index` is given, that
    exact row is explained (useful for checking consistency); otherwise a random
    row of the requested type ('attack', 'benign', 'random') is chosen. `dataset`
    selects which dataset to sample from; the matching model is loaded so the
    explanation stays feature-aligned. This can take ~10 seconds while LIME runs.
    """
    if not model_service.is_loaded:
        raise HTTPException(status_code=400, detail="No model loaded.")

    # If a dataset is requested that differs from the loaded model, switch to the
    # matching model so the rows and the model share a feature space.
    if dataset:
        if dataset not in ("2017", "2018"):
            raise HTTPException(status_code=400, detail="dataset must be '2017' or '2018'.")
        if (model_service.dataset or "2017") != dataset:
            from api.routers.monitor import _pick_model_for_dataset
            filename = _pick_model_for_dataset(dataset)
            if not filename:
                raise HTTPException(status_code=404, detail=f"No model found for CIC-IDS{dataset}.")
            try:
                model_service.load(filename)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to load CIC-IDS{dataset} model: {e}")

    dataset = model_service.dataset or "2017"
    npz_path = _BASE / "data" / "processed" / f"processed_data_{dataset}.npz"
    if not npz_path.exists():
        npz_path = _BASE / "data" / "processed" / "processed_data.npz"
    if not npz_path.exists():
        raise HTTPException(status_code=404, detail="No processed data found.")

    import numpy as np
    from src.explainer import Explainer

    data = np.load(npz_path, allow_pickle=True)
    X = data["X"]
    y = data["y"]

    if index is not None:
        if index < 0 or index >= len(y):
            raise HTTPException(status_code=400, detail=f"Row index out of range (0 to {len(y) - 1}).")
        chosen = int(index)
    else:
        if sample_type == "attack":
            idx = np.where(y == 1)[0]
        elif sample_type == "benign":
            idx = np.where(y == 0)[0]
        else:
            idx = np.arange(len(y))
        if len(idx) == 0:
            raise HTTPException(status_code=404, detail="No samples of that type found.")
        chosen = int(np.random.choice(idx))
    X_sample = X[chosen : chosen + 1]
    y_true = int(y[chosen])

    explainer = Explainer(model=model_service.model, feature_names=model_service.feature_names)
    explainer.setup(X[:100])
    result = explainer.explain(X_sample, true_label=y_true, method="both")

    pred_code   = int(result["prediction_code"])
    prediction  = result["prediction"]
    attack_prob = round(float(result["probabilities"].get("Attack", 0)), 4)

    shap_exp = result.get("shap_explanation", {}) or {}
    lime_exp = result.get("lime_explanation",  {}) or {}
    # Use the full set so the explorer shows every feature, like the dashboard panel.
    shap_contribs = shap_exp.get("all_contributions") or shap_exp.get("contributions") or []
    lime_contribs = lime_exp.get("contributions") or []

    shap_features = [
        {
            "feature":       c["feature"],
            "shap_value":    round(float(c["shap_value"]), 4),
            "feature_value": round(float(c.get("feature_value", 0)), 4),
            "direction":     "positive" if c["direction"] == "attack" else "negative",
        }
        for c in shap_contribs
    ]

    lime_features = [
        {
            "feature":     c["feature"],
            "description": c.get("description", c["feature"]),
            "lime_weight": round(float(c["lime_weight"]), 4),
            "direction":   "positive" if c["direction"] == "attack" else "negative",
        }
        for c in lime_contribs
    ]

    # Drop negligible (≈0.00) features from the displayed lists to cut clutter.
    from api.services.explainer_service import trim_features
    shap_features = trim_features(shap_features, "shap_value")
    lime_features = trim_features(lime_features, "lime_weight")

    # --- English narratives (same rich engine as the dashboard and classify) ---
    from api.services.explainer_service import _build_shap_narrative

    shap_feats_n = [
        {"feature": c["feature"], "shap_value": float(c["shap_value"]),
         "direction": "positive" if c["direction"] == "attack" else "negative"}
        for c in shap_contribs
    ]
    shap_narrative = _build_shap_narrative(prediction, float(attack_prob), shap_feats_n)

    lime_feats_n = [
        {"feature": c["feature"], "shap_value": float(c["lime_weight"]),
         "direction": "positive" if c["direction"] == "attack" else "negative"}
        for c in lime_contribs
    ]
    lime_narrative = _build_shap_narrative(prediction, float(attack_prob), lime_feats_n)

    # If this is an attack, also predict and explain the attack TYPE.
    type_info = None
    if prediction.upper() == "ATTACK":
        try:
            from api.services.type_classifier_service import type_classifier_service
            type_info = type_classifier_service.explain_type(
                X_sample, dataset, model_service.feature_names, want_lime=True)
        except Exception:
            type_info = None

    return {
        "prediction":      prediction,
        "attack_prob":     attack_prob,
        "true_label":      "Attack" if y_true == 1 else "Benign",
        "dataset":         dataset,
        "row_index":       chosen,
        "dataset_size":    int(len(y)),
        "shap_features":   shap_features,
        "lime_features":   lime_features,
        "shap_narrative":  shap_narrative,
        "lime_narrative":  lime_narrative,
        "attack_type":     type_info,
    }


@router.get("/api/explain/global")
def explain_global(n_samples: int = Query(200, ge=20, le=2000)):
    """
    Global feature importance: mean(|SHAP|) across n_samples drawn from
    the model's training dataset. Tells you which features the model
    relies on overall, not per-prediction.
    """
    if not model_service.is_loaded:
        raise HTTPException(status_code=400, detail="No model loaded.")

    dataset  = model_service.dataset or "2017"
    npz_path = _BASE / "data" / "processed" / f"processed_data_{dataset}.npz"
    if not npz_path.exists():
        npz_path = _BASE / "data" / "processed" / "processed_data.npz"
    if not npz_path.exists():
        raise HTTPException(status_code=404, detail="No processed data found.")

    import numpy as np
    import shap

    data = np.load(npz_path, allow_pickle=True)
    X = data["X"]
    y = data["y"]

    n_samples = min(n_samples, len(X))
    rng = np.random.default_rng(42)
    sample_idx = rng.choice(len(X), size=n_samples, replace=False)
    X_sample = X[sample_idx]
    y_sample = y[sample_idx]

    feature_names = model_service.feature_names or [f"f{i}" for i in range(X.shape[1])]

    try:
        explainer = shap.TreeExplainer(model_service.model)
        # Tree explainers return list-of-arrays (one per class) for classifiers
        shap_values = explainer.shap_values(X_sample, check_additivity=False)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SHAP failed: {e}")

    # Normalise: pick attack-class SHAP if 3D/list-of-arrays, else use directly
    if isinstance(shap_values, list) and len(shap_values) >= 2:
        sv_attack = np.asarray(shap_values[1])
    elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
        sv_attack = shap_values[:, :, 1]
    else:
        sv_attack = np.asarray(shap_values)

    mean_abs = np.abs(sv_attack).mean(axis=0)
    # Mean signed value tells us the *direction* this feature usually pushes predictions
    mean_signed = sv_attack.mean(axis=0)

    # Per-class subset means
    benign_mask = y_sample == 0
    attack_mask = y_sample == 1
    benign_mean = np.abs(sv_attack[benign_mask]).mean(axis=0) if benign_mask.any() else np.zeros_like(mean_abs)
    attack_mean = np.abs(sv_attack[attack_mask]).mean(axis=0) if attack_mask.any() else np.zeros_like(mean_abs)

    rows = [
        {
            "feature":       feature_names[i],
            "mean_abs_shap": round(float(mean_abs[i]),    5),
            "mean_signed":   round(float(mean_signed[i]), 5),
            "benign_impact": round(float(benign_mean[i]), 5),
            "attack_impact": round(float(attack_mean[i]), 5),
            "direction":     "attack" if mean_signed[i] > 0 else "benign",
        }
        for i in range(len(feature_names))
    ]
    rows.sort(key=lambda r: r["mean_abs_shap"], reverse=True)

    return {
        "dataset":   dataset,
        "n_samples": int(n_samples),
        "n_attack":  int(attack_mask.sum()),
        "n_benign":  int(benign_mask.sum()),
        "features":  rows,
    }


@router.get("/api/explain/{alert_id}")
def get_explanation(alert_id: str):
    alert = alert_store.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    try:
        return explainer_service.explain(alert, model_service)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/api/explain/{alert_id}/type")
def explain_alert_type(alert_id: str):
    """Explain WHY the attack-type classifier assigned this type (SHAP + LIME). Slow (~5-10s)."""
    if not model_service.is_loaded:
        raise HTTPException(status_code=400, detail="No model loaded.")
    alert = alert_store.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    feats = alert.get("features")
    if not feats or str(alert.get("prediction", "")).upper() != "ATTACK":
        return {"available": False}
    import numpy as np
    from api.services.type_classifier_service import type_classifier_service
    ds = model_service.dataset or "2017"
    res = type_classifier_service.explain_type(
        np.array(feats, dtype=np.float32).reshape(1, -1), ds, model_service.feature_names)
    if not res:
        return {"available": False}
    return {"available": True, **res}


@router.get("/api/explain/{alert_id}/lime")
def get_lime_explanation(alert_id: str):
    """Run LIME on the stored feature vector for this alert. Slow (~5–10s)."""
    if not model_service.is_loaded:
        raise HTTPException(status_code=400, detail="No model loaded.")
    alert = alert_store.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    try:
        return explainer_service.explain_lime(alert, model_service)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
