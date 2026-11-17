"""
retrain.py — Offline retraining script for NIDS-XAI.

Reads analyst feedback (FEEDBACK_FILE) and re-trains a new RandomForest model,
adjusting labels for confirmed false-positives.  The new model is saved with a
version timestamp and does NOT replace the active model automatically.

Usage:
    python scripts/retrain.py [--dataset 2017|2018] [--dry-run]

Options:
    --dataset   Dataset version to load processed data for (default: "2017").
    --dry-run   Show what would happen without saving any files.
"""

import argparse
import json
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Make sure project root is on sys.path so "config.config" is importable
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).parent
_PROJECT_ROOT = _SCRIPT_DIR.parent  # nids_xai/
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

from config.config import (
    FEEDBACK_FILE,
    MODEL_DIR,
    PROCESSED_DATA_DIR,
    PROCESSED_DATA_FILENAME,
    RF_PARAMS,
    get_processed_data_filename,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_feedback(feedback_path: str) -> list:
    """Load all feedback records from the JSON-lines file."""
    path = Path(feedback_path)
    if not path.exists() or path.stat().st_size == 0:
        print(f"[retrain] No feedback file found at {feedback_path}. Exiting.")
        return []
    records = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    print(f"[retrain] WARN: skipping malformed feedback line: {exc}")
    return records


def build_label_overrides(feedback_records: list) -> dict:
    """
    Build a dict mapping alert_id -> new_label (0 or 1).

    Rules:
      true_positive  → label = 1  (attack, ML was right)
      false_positive → label = 0  (benign, ML was wrong)

    If an alert_id appears multiple times, the last entry wins.
    """
    overrides: dict = {}
    for rec in feedback_records:
        alert_id = rec.get("alert_id")
        label_str = rec.get("label")
        if not alert_id or label_str not in {"true_positive", "false_positive"}:
            print(f"[retrain] WARN: skipping invalid feedback record: {rec}")
            continue
        overrides[alert_id] = 1 if label_str == "true_positive" else 0
    return overrides


def load_processed_data(dataset: str, dry_run: bool = False) -> tuple:
    """Load X, y, and optional alert_ids from the processed NPZ file."""
    filename = get_processed_data_filename(dataset)
    npz_path = Path(PROCESSED_DATA_DIR) / filename

    if not npz_path.exists():
        legacy_path = Path(PROCESSED_DATA_DIR) / PROCESSED_DATA_FILENAME
        if legacy_path.exists():
            npz_path = legacy_path

    if not npz_path.exists():
        if dry_run:
            print(f"[retrain] [DRY-RUN] NPZ not found at {npz_path}; generating synthetic data for dry-run.")
            X = np.random.randn(20, 25)
            y = np.random.choice([0, 1], size=20)
            alert_ids = [f"alert_{i}" for i in range(20)]
            return X, y, alert_ids
        print(f"[retrain] ERROR: processed data not found at {npz_path}")
        sys.exit(1)

    data = np.load(npz_path, allow_pickle=True)
    X = data["X"]
    y = data["y"]

    # alert_ids are optional — present only if the pipeline saved them
    alert_ids = data["alert_ids"].tolist() if "alert_ids" in data else []
    print(f"[retrain] Loaded {X.shape[0]} samples, {X.shape[1]} features from {npz_path.name}")
    return X, y, alert_ids


def apply_overrides(y: np.ndarray, alert_ids: list, overrides: dict) -> tuple:
    """
    Apply label overrides to y.

    Returns (y_adjusted, n_changed).
    """
    if not overrides or not alert_ids:
        return y.copy(), 0

    y_new = y.copy()
    n_changed = 0
    for idx, aid in enumerate(alert_ids):
        if aid in overrides:
            new_label = overrides[aid]
            if y_new[idx] != new_label:
                y_new[idx] = new_label
                n_changed += 1
    return y_new, n_changed


def save_versioned_model(clf, dataset: str, dry_run: bool) -> Path:
    """Save model with a version timestamp. Returns the path that *would* be used."""
    ts = int(time.time())
    filename = f"nids_model_{dataset}_v{ts}.joblib"
    dest = Path(MODEL_DIR) / filename
    if dry_run:
        print(f"[retrain] [DRY-RUN] Would save model to {dest}")
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(clf, dest)
        print(f"[retrain] Saved model to {dest}")
    return dest


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Retrain NIDS-XAI model from analyst feedback.")
    parser.add_argument("--dataset", default="2017", choices=["2017", "2018"],
                        help="Dataset version to use for retraining (default: 2017)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would happen without writing any files.")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  NIDS-XAI Retraining Script")
    print(f"  Dataset : {args.dataset}")
    print(f"  Mode    : {'DRY-RUN' if args.dry_run else 'LIVE'}")
    print(f"  Feedback: {FEEDBACK_FILE}")
    print(f"{'='*60}\n")

    # 1. Load feedback
    feedback_records = load_feedback(FEEDBACK_FILE)
    if not feedback_records:
        print("[retrain] No feedback records — nothing to do.")
        sys.exit(0)

    n_tp = sum(1 for r in feedback_records if r.get("label") == "true_positive")
    n_fp = sum(1 for r in feedback_records if r.get("label") == "false_positive")
    print(f"[retrain] Feedback: {len(feedback_records)} total — {n_tp} true_positive, {n_fp} false_positive")

    # 2. Build overrides map
    overrides = build_label_overrides(feedback_records)
    print(f"[retrain] Unique alert_id overrides: {len(overrides)}")

    # 3. Load processed training data
    X, y, alert_ids = load_processed_data(args.dataset, dry_run=args.dry_run)

    # 4. Apply label overrides
    y_adjusted, n_changed = apply_overrides(y, alert_ids, overrides)
    print(f"[retrain] Labels changed by feedback: {n_changed}")

    if n_changed == 0 and not alert_ids:
        print("[retrain] WARN: processed data has no alert_ids — cannot apply label overrides. "
              "Retraining on original labels.")

    # 5. Train new model
    print(f"[retrain] Training RandomForest with params: {RF_PARAMS}")
    if not args.dry_run:
        clf = RandomForestClassifier(**RF_PARAMS)
        clf.fit(X, y_adjusted)
        print(f"[retrain] Training complete. n_estimators={clf.n_estimators}")
    else:
        clf = None
        print("[retrain] [DRY-RUN] Skipping actual fit.")

    # 6. Save versioned model (does NOT replace active model)
    dest = save_versioned_model(clf, args.dataset, args.dry_run)

    # 7. Summary
    print(f"\n{'='*60}")
    print("  Retraining Summary")
    print(f"  Feedback records  : {len(feedback_records)}")
    print(f"  Label overrides   : {len(overrides)}")
    print(f"  Labels changed    : {n_changed}")
    print(f"  Training samples  : {X.shape[0]}")
    print(f"  Features          : {X.shape[1]}")
    if args.dry_run:
        print(f"  Output (DRY-RUN)  : {dest}")
        print("  ⚠  No files were written.")
    else:
        print(f"  Saved model       : {dest}")
        print("  ✅ To activate: copy/move this file and update MODEL_DIR reference.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
