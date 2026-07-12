import io
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Query
from api.services.model_service import model_service

router = APIRouter()
_BASE = Path(__file__).parent.parent.parent


def _build_explanations(X, y_pred, labels_raw, n_explain):
    """Pick a random mix of rows (favouring attacks) and explain them with SHAP.
    Shared by /classify and /classify/explanations so the explanation text and
    randomisation behave identically."""
    import numpy as np
    try:
        from src.explainer import Explainer
        from api.services.explainer_service import _build_shap_narrative

        dataset = model_service.dataset or "2017"
        npz_path = _BASE / "data" / "processed" / f"processed_data_{dataset}.npz"
        if not npz_path.exists():
            npz_path = _BASE / "data" / "processed" / "processed_data.npz"
        if not npz_path.exists():
            return []

        bg = np.load(npz_path, allow_pickle=True)["X"][:100]
        explainer = Explainer(model=model_service.model, feature_names=model_service.feature_names)
        explainer.setup(bg)

        attack_idx = np.where(y_pred == 1)[0]
        benign_idx = np.where(y_pred == 0)[0]
        picks = []
        if len(attack_idx):
            picks.extend(np.random.choice(attack_idx, min(2, len(attack_idx)), replace=False))
        if len(benign_idx) and len(picks) < n_explain:
            picks.extend(np.random.choice(benign_idx, min(n_explain - len(picks), len(benign_idx)), replace=False))
        # If we still need more (e.g. all-attack file), top up from whatever remains.
        if len(picks) < n_explain:
            remaining = [i for i in range(len(y_pred)) if i not in set(int(p) for p in picks)]
            if remaining:
                picks.extend(np.random.choice(remaining, min(n_explain - len(picks), len(remaining)), replace=False))
        picks = [int(p) for p in picks[:n_explain]]

        out = []
        for idx in picks:
            res = explainer.explain(X[idx:idx + 1], method="shap")
            sx = res.get("shap_explanation") or {}
            all_c = sx.get("all_contributions") or sx.get("contributions") or []
            pred = res["prediction"]
            ap = float(res["probabilities"].get("Attack", 0))
            narrative_feats = [
                {"feature": c["feature"], "shap_value": float(c["shap_value"]),
                 "direction": "positive" if c["direction"] == "attack" else "negative"}
                for c in all_c
            ]
            summary = _build_shap_narrative(pred, ap, narrative_feats)
            if labels_raw is not None:
                summary += f"\n\nThe dataset labels this flow as {labels_raw[idx]}."
            predicted_type = predicted_type_conf = None
            if pred.upper() == "ATTACK":
                try:
                    from api.services.type_classifier_service import type_classifier_service
                    te = type_classifier_service.explain_type(
                        X[idx:idx + 1], model_service.dataset or "2017",
                        model_service.feature_names, want_lime=False)
                    if te:
                        predicted_type = te["predicted_type"]
                        predicted_type_conf = round(float(te["confidence"]), 4)
                        reasons = [f["feature"].strip() for f in te.get("shap", []) if f["direction"] == "positive"][:3]
                        if reasons:
                            summary += (f"\n\nIdentified as {predicted_type} "
                                        f"({predicted_type_conf * 100:.0f}% type confidence); key signals: "
                                        + ", ".join(reasons) + ".")
                except Exception:
                    pass
            out.append({
                "row_index": idx,
                "prediction": pred,
                "attack_prob": round(ap, 4),
                "actual_type": labels_raw[idx] if labels_raw is not None else None,
                "predicted_type": predicted_type,
                "predicted_type_conf": predicted_type_conf,
                "summary": summary,
                "top_factors": [
                    {"feature": c["feature"], "shap_value": round(float(c["shap_value"]), 4),
                     "direction": "positive" if c["direction"] == "attack" else "negative"}
                    for c in all_c[:6]
                ],
            })
        return out
    except Exception as e:
        return [{"error": f"Explanation skipped: {e}"}]


async def _read_transform_predict(file: UploadFile):
    """Read an uploaded CSV, transform it, and predict. Returns (X, y_pred, labels_raw)."""
    import io
    import numpy as np
    import pandas as pd

    if not model_service.is_loaded:
        raise HTTPException(status_code=400, detail="No model loaded.")
    if model_service.preprocessor is None:
        raise HTTPException(status_code=400, detail="Preprocessor not available.")
    safe_name = Path(file.filename or "").name
    if not safe_name.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted.")
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    df = pd.read_csv(io.BytesIO(raw), low_memory=False)
    if len(df) == 0:
        raise HTTPException(status_code=400, detail="CSV contains no rows.")

    has_label = "label" in {str(c).strip().lower() for c in df.columns}
    if has_label:
        res = model_service.preprocessor.transform(df, include_labels=True)
        X = res[0] if isinstance(res, tuple) else res
    else:
        X = model_service.preprocessor.transform(df)
    y_pred = model_service.model.predict(X)

    labels_raw = None
    if has_label:
        lc = next((c for c in df.columns if str(c).strip().lower() == "label"), None)
        if lc is not None and len(df) == len(y_pred):
            labels_raw = df[lc].astype(str).str.strip().tolist()
    return X, y_pred, labels_raw


@router.post("/api/classify/explanations")
async def classify_explanations(
    file: UploadFile = File(...),
    n_explain: int = Query(3, ge=1, le=10),
):
    """Re-pick a random set of rows from the uploaded CSV and explain them.
    Used by the 'Randomise' button so the explanation cards can be re-rolled
    without re-running the full classification."""
    X, y_pred, labels_raw = await _read_transform_predict(file)
    return {"explanations": _build_explanations(X, y_pred, labels_raw, n_explain)}


@router.post("/api/classify")
async def classify_csv(
    file: UploadFile = File(...),
    explain: bool = Query(True, description="Run SHAP on a few sample predictions"),
    n_explain: int = Query(3, ge=0, le=10, description="How many sample explanations to generate"),
):
    """
    Classify rows in an uploaded CSV (CICFlowMeter-format) using the loaded model.
    Returns per-row predictions plus a summary, plus optional SHAP explanations
    on a few representative samples (mix of attacks and benign).
    """
    if not model_service.is_loaded:
        raise HTTPException(status_code=400, detail="No model loaded.")
    if model_service.preprocessor is None:
        raise HTTPException(status_code=400, detail="Preprocessor not available.")

    safe_name = Path(file.filename or "").name  # strip any path components
    if not safe_name.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted.")

    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        import pandas as pd
        import numpy as np
        df = pd.read_csv(io.BytesIO(raw), low_memory=False)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {e}")

    if len(df) == 0:
        raise HTTPException(status_code=400, detail="CSV contains no rows.")

    # If the CSV carries a ground-truth label column (as the CIC-IDS files do),
    # extract it so we can report measurable accuracy against the predictions.
    has_label = "label" in {str(c).strip().lower() for c in df.columns}

    y_true = None
    try:
        if has_label:
            result = model_service.preprocessor.transform(df, include_labels=True)
            # transform() returns (X, y_binary, y_types) only if it recognised
            # the label column; otherwise it returns X alone.
            if isinstance(result, tuple):
                X, y_true, _ = result
            else:
                X = result
        else:
            X = model_service.preprocessor.transform(df)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Preprocessing failed: {e}")

    model = model_service.model
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)

    # Measurable result against ground truth (only when labels were present).
    metrics = None
    if y_true is not None and len(y_true) == len(y_pred):
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, f1_score, confusion_matrix,
        )
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = (int(v) for v in cm.ravel())
        metrics = {
            "accuracy":  round(float(accuracy_score(y_true, y_pred)), 4),
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall":    round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1":        round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            "actual_attacks": int((y_true == 1).sum()),
            "actual_benign":  int((y_true == 0).sum()),
        }

    n = int(len(y_pred))
    n_attack = int((y_pred == 1).sum())
    n_benign = int((y_pred == 0).sum())
    avg_conf = float(y_proba.max(axis=1).mean())

    # If the CSV has a Label column, capture the original attack-type names
    # (e.g. "PortScan", "DoS Hulk", "BENIGN"). This is the true category from the
    # labelled file, shown alongside the model's Attack/Benign verdict.
    labels_raw = None
    if has_label:
        lc = next((c for c in df.columns if str(c).strip().lower() == "label"), None)
        if lc is not None and len(df) == len(y_pred):
            labels_raw = df[lc].astype(str).str.strip().tolist()

    # Per-type breakdown: how many of each attack type the model flagged as Attack.
    type_breakdown = None
    if labels_raw is not None:
        labels_arr = np.array(labels_raw)
        type_breakdown = []
        for t in sorted(set(labels_raw)):
            mask = labels_arr == t
            cnt = int(mask.sum())
            flagged = int((y_pred[mask] == 1).sum())
            is_benign = t.upper() == "BENIGN"
            type_breakdown.append({
                "type": t,
                "count": cnt,
                "flagged_attack": flagged,
                # For attacks this is recall (caught / total); for benign it is the
                # false-alarm rate, so we only report detection rate for attacks.
                "detection_rate": round(flagged / cnt, 4) if (cnt and not is_benign) else None,
                "is_benign": is_benign,
            })
        type_breakdown.sort(key=lambda x: x["count"], reverse=True)

    # Compact preview (first 100 rows)
    preview_rows = []
    for i in range(min(100, n)):
        row = {
            "index": i,
            "prediction": "Attack" if y_pred[i] == 1 else "Benign",
            "attack_prob": round(float(y_proba[i, 1]), 4),
        }
        if labels_raw is not None:
            row["actual_type"] = labels_raw[i]
        if y_true is not None:
            row["actual"] = "Attack" if y_true[i] == 1 else "Benign"
            row["correct"] = bool(y_true[i] == y_pred[i])
        preview_rows.append(row)

    sample_explanations: List[dict] = []
    if explain and n_explain > 0:
        sample_explanations = _build_explanations(X, y_pred, labels_raw, n_explain)

    return {
        "filename":      safe_name,
        "total":         n,
        "attacks":       n_attack,
        "benign":        n_benign,
        "attack_pct":    round(n_attack / n * 100, 2) if n else 0.0,
        "benign_pct":    round(n_benign / n * 100, 2) if n else 0.0,
        "avg_confidence": round(avg_conf, 4),
        "metrics":       metrics,
        "type_breakdown": type_breakdown,
        "preview":       preview_rows,
        "explanations":  sample_explanations,
    }
