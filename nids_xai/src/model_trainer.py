"""
Model Trainer for NIDS with XAI.
Supports multiple training modes: Quick, Standard, Optimized, and Auto-Tuning.

Author: Final Year CS Project
Version: 2.0 - Enhanced with hyperparameter tuning
"""

import sys
from pathlib import Path
from typing import Optional, Dict, List, Callable
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV, cross_val_score

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import (
    RF_PARAMS, RF_PARAMS_OPTIMIZED, RF_PARAMS_QUICK, RF_PARAM_GRID,
    MODEL_DIR, MODEL_FILENAME, CV_FOLDS, TRAINING_DATASET,
    get_model_filename, USE_SMOTE,
)
from src.utils import (
    print_header, print_subheader, print_success,
    print_info, print_warning, print_metric, format_number, Timer, get_timestamp,
)


class ModelTrainer:
    """
    Train and manage the Random Forest model.

    Supports multiple training modes:
    - 'quick': Fast training with reduced parameters
    - 'standard': Default balanced parameters
    - 'optimized': Higher accuracy parameters (slower)
    - 'auto': Automatic hyperparameter tuning
    """

    def __init__(self, mode: str = "standard", use_smote: bool = None,
                 custom_params: Dict = None):
        """
        Initialize trainer.

        Args:
            mode: Training mode - 'quick', 'standard', 'optimized', or 'auto'
            use_smote: Override USE_SMOTE config setting (None = use config)
            custom_params: Custom RF hyperparameters to override defaults
        """
        self.mode = mode
        self.params = self._get_params_for_mode(mode)

        # Apply custom parameter overrides (from GUI settings)
        if custom_params:
            self.params.update(custom_params)

        self.model = RandomForestClassifier(**self.params)
        self.feature_names = []
        self.training_info = {}
        self.is_trained = False
        self.best_params = None
        self.cv_scores = None
        self.use_smote = use_smote if use_smote is not None else USE_SMOTE

    def _get_params_for_mode(self, mode: str) -> Dict:
        """Get parameters based on training mode."""
        if mode == "quick":
            return RF_PARAMS_QUICK.copy()
        elif mode == "optimized":
            return RF_PARAMS_OPTIMIZED.copy()
        else:  # standard or auto
            return RF_PARAMS.copy()

    def train(self, X: np.ndarray, y: np.ndarray, feature_names: List[str],
              progress_callback: Callable = None) -> 'ModelTrainer':
        """
        Train the model.

        Args:
            X: Training features
            y: Training labels
            feature_names: List of feature names
            progress_callback: Optional callback for progress updates (for GUI)

        Returns:
            self
        """
        print_header("Training Model")

        self.feature_names = feature_names

        # Info
        print_subheader("Configuration")
        print_info(f"Training Mode: {self.mode.upper()}")
        print_info(f"Samples: {format_number(len(X))}")
        print_info(f"Features: {len(feature_names)}")
        print_info(f"Trees: {self.params.get('n_estimators', 100)}")
        print_info(f"Max Depth: {self.params.get('max_depth', 'None')}")

        # Class distribution
        unique, counts = np.unique(y, return_counts=True)
        print_subheader("Class Distribution")
        for label, count in zip(unique, counts):
            name = "Attack" if label == 1 else "Benign"
            pct = count / len(y) * 100
            bar_len = int(pct / 5)
            bar = "|" + "#" * bar_len + " " * (20 - bar_len) + "|"
            print_info(f"  {name}: {format_number(count)} ({pct:.1f}%) {bar}")

        # Apply SMOTE oversampling if enabled (helps with minority classes)
        if self.use_smote:
            X, y = self._apply_smote(X, y)

        # Choose training method based on mode
        if self.mode == "auto":
            self._train_with_tuning(X, y, progress_callback)
        else:
            self._train_standard(X, y, progress_callback)

        self.is_trained = True

        # Store info
        self.training_info = {
            "timestamp": get_timestamp(),
            "mode": self.mode,
            "n_samples": len(X),
            "n_features": len(feature_names),
            "feature_names": feature_names,
            "params": self.params,
            "best_params": self.best_params,
        }

        # Feature importances
        self._show_importances()

        # Training accuracy
        acc = self.model.score(X, y)
        print_metric("Training Accuracy", acc)

        # Cross-validation score (optional)
        if self.cv_scores is not None:
            print_info(f"  CV Score (mean): {np.mean(self.cv_scores):.4f} (+/- {np.std(self.cv_scores):.4f})")

        # Auto save
        self.save()

        print_success("Model trained and saved!")
        return self

    def _train_standard(self, X: np.ndarray, y: np.ndarray,
                        progress_callback: Callable = None) -> None:
        """Standard training without hyperparameter tuning."""
        print_info("\nTraining Random Forest...")

        if progress_callback:
            progress_callback(0, "Starting training...")

        with Timer("Training time"):
            self.model.fit(X, y)

        if progress_callback:
            progress_callback(100, "Training complete!")

    def _train_with_tuning(self, X: np.ndarray, y: np.ndarray,
                           progress_callback: Callable = None) -> None:
        """Train with automatic hyperparameter tuning using GridSearchCV."""
        print_info("\nPerforming Hyperparameter Tuning...")
        print_info(f"  Grid: {RF_PARAM_GRID}")
        print_info(f"  CV Folds: {CV_FOLDS}")

        if progress_callback:
            progress_callback(0, "Starting hyperparameter search...")

        # Calculate total combinations
        total_combinations = 1
        for values in RF_PARAM_GRID.values():
            total_combinations *= len(values)
        total_fits = total_combinations * CV_FOLDS
        print_info(f"  Total fits: {total_fits}")

        with Timer("Hyperparameter tuning time"):
            # Use GridSearchCV for exhaustive search
            grid_search = GridSearchCV(
                estimator=RandomForestClassifier(
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1
                ),
                param_grid=RF_PARAM_GRID,
                cv=CV_FOLDS,
                scoring='accuracy',
                n_jobs=-1,
                verbose=1,
                return_train_score=True
            )

            grid_search.fit(X, y)

            # Get best model and params
            self.model = grid_search.best_estimator_
            self.best_params = grid_search.best_params_
            self.cv_scores = grid_search.cv_results_['mean_test_score']
            self.params.update(self.best_params)

        print_subheader("Best Parameters Found")
        for param, value in self.best_params.items():
            print_info(f"  {param}: {value}")
        print_info(f"  Best CV Score: {grid_search.best_score_:.4f}")

        if progress_callback:
            progress_callback(100, "Tuning complete!")

    def _apply_smote(self, X: np.ndarray, y: np.ndarray) -> tuple:
        """
        Apply SMOTE oversampling to balance minority classes.

        This is particularly important for web attack detection, where
        classes like SQL Injection and XSS may have very few samples
        compared to benign traffic or DoS attacks.

        Returns:
            Resampled (X, y) arrays.
        """
        try:
            from imblearn.over_sampling import SMOTE

            print_subheader("Applying SMOTE Oversampling")
            original_counts = dict(zip(*np.unique(y, return_counts=True)))
            print_info(f"Before SMOTE: {len(X):,} samples")
            for label, count in sorted(original_counts.items()):
                name = "Attack" if label == 1 else "Benign"
                print_info(f"  {name}: {count:,}")

            smote = SMOTE(random_state=42, k_neighbors=min(5, min(original_counts.values()) - 1))
            X_resampled, y_resampled = smote.fit_resample(X, y)

            new_counts = dict(zip(*np.unique(y_resampled, return_counts=True)))
            print_info(f"After SMOTE: {len(X_resampled):,} samples")
            for label, count in sorted(new_counts.items()):
                name = "Attack" if label == 1 else "Benign"
                print_info(f"  {name}: {count:,}")

            return X_resampled, y_resampled

        except ImportError:
            print_warning("SMOTE not available (pip install imbalanced-learn)")
            print_warning("Training without oversampling.")
            return X, y

    def cross_validate(self, X: np.ndarray, y: np.ndarray, cv: int = 5) -> Dict:
        """
        Perform cross-validation on the current model.

        Args:
            X: Features
            y: Labels
            cv: Number of folds

        Returns:
            Dictionary with CV results
        """
        print_subheader(f"{cv}-Fold Cross-Validation")

        with Timer("CV time"):
            scores = cross_val_score(self.model, X, y, cv=cv, scoring='accuracy', n_jobs=-1)

        self.cv_scores = scores

        print_info(f"  Accuracy: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})")
        print_info(f"  Scores: {', '.join([f'{s:.4f}' for s in scores])}")

        return {
            "mean": float(scores.mean()),
            "std": float(scores.std()),
            "scores": scores.tolist()
        }

    def _show_importances(self, n: int = 10) -> None:
        """Show top feature importances."""
        print_subheader(f"Top {n} Important Features")

        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1][:n]

        max_imp = importances[indices[0]]

        self.training_info["top_features"] = []

        for rank, idx in enumerate(indices, 1):
            name = self.feature_names[idx] if idx < len(self.feature_names) else f"Feature_{idx}"
            imp = importances[idx]
            bar_len = int((imp / max_imp) * 25)
            bar = "#" * bar_len + " " * (25 - bar_len)
            print(f"  {rank:2d}. {name[:30]:<30} {imp:.4f} |{bar}|")
            self.training_info["top_features"].append((name, float(imp)))

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions."""
        if not self.is_trained:
            raise ValueError("Model not trained")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get prediction probabilities."""
        if not self.is_trained:
            raise ValueError("Model not trained")
        return self.model.predict_proba(X)

    def save(self, filename: str = None, dataset: str = None) -> str:
        """
        Save model to file.

        Args:
            filename: Custom filename (optional)
            dataset: Dataset identifier for filename (optional)

        Returns:
            Path to saved model
        """
        MODEL_DIR.mkdir(parents=True, exist_ok=True)

        if filename:
            path = MODEL_DIR / filename
        elif dataset:
            path = MODEL_DIR / get_model_filename(dataset)
        else:
            path = MODEL_DIR / MODEL_FILENAME

        joblib.dump({
            'model': self.model,
            'feature_names': self.feature_names,
            'training_info': self.training_info,
            'mode': self.mode,
            'best_params': self.best_params,
        }, path)

        print_info(f"Model saved: {path}")
        return str(path)

    def load(self, filename: str = None, dataset: str = None) -> 'ModelTrainer':
        """
        Load model from file.

        Args:
            filename: Custom filename (optional)
            dataset: Dataset identifier for filename (optional)

        Returns:
            self
        """
        if filename:
            path = MODEL_DIR / filename
        elif dataset:
            path = MODEL_DIR / get_model_filename(dataset)
        else:
            path = MODEL_DIR / MODEL_FILENAME

        if not path.exists():
            raise FileNotFoundError(f"No model: {path}")

        data = joblib.load(path)
        self.model = data['model']
        self.feature_names = data['feature_names']
        self.training_info = data.get('training_info', {})
        self.mode = data.get('mode', 'standard')
        self.best_params = data.get('best_params', None)
        self.is_trained = True

        print_success(f"Model loaded: {path}")
        return self

    def get_info(self) -> Dict:
        """Get model info."""
        return {
            "trained": self.is_trained,
            "mode": self.mode,
            "n_estimators": self.model.n_estimators,
            "max_depth": self.model.max_depth,
            "n_features": len(self.feature_names),
            "best_params": self.best_params,
            "training_info": self.training_info,
        }

    def get_feature_importance(self) -> List[tuple]:
        """Get feature importance as sorted list of (name, importance) tuples."""
        if not self.is_trained:
            return []

        importances = self.model.feature_importances_
        result = list(zip(self.feature_names, importances))
        result.sort(key=lambda x: x[1], reverse=True)
        return result


def train_model(X: np.ndarray, y: np.ndarray, feature_names: List[str],
                mode: str = "standard") -> ModelTrainer:
    """
    Convenience function to train a model.

    Args:
        X: Training features
        y: Training labels
        feature_names: List of feature names
        mode: Training mode - 'quick', 'standard', 'optimized', or 'auto'

    Returns:
        Trained ModelTrainer instance
    """
    trainer = ModelTrainer(mode=mode)
    trainer.train(X, y, feature_names)
    return trainer
