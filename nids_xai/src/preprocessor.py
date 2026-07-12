"""
Preprocessor for NIDS with XAI.
Uses 80/20 train/test split for same-dataset mode.
Supports cross-dataset validation (fit on training dataset, transform testing dataset).
Tracks both binary labels and original attack types.

Author: Final Year CS Project
Version: 3.0 - Enhanced for cross-dataset validation
"""

import sys
import gc
from pathlib import Path
from typing import Optional, Tuple, List, Union
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.model_selection import train_test_split
import joblib

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import (
    LABEL_COLUMN, COLUMNS_TO_DROP,
    TEST_SIZE, RANDOM_STATE, MODEL_DIR,
    PREPROCESSOR_FILENAME, PROCESSED_DATA_FILENAME, PROCESSED_DATA_DIR,
    ENABLE_FEATURE_SELECTION, TOP_K_FEATURES,
    ENABLE_SAMPLING, MAX_TRAINING_SAMPLES,
    get_processed_data_filename, get_preprocessor_filename,
    COLUMN_RENAME_2018_TO_CANONICAL,
)
from src.utils import (
    print_header, print_subheader, print_success, print_error,
    print_info, print_warning, format_number,
)


class Preprocessor:
    """
    Data preprocessor for NIDS.

    Supports two modes:
    1. Same-dataset mode: fit_transform() then split_data() for 80/20 split
    2. Cross-dataset mode: fit_transform() on train, transform() on test

    Key features:
    - Tracks both binary labels (Benign/Attack) and original attack types
    - Feature selection to keep top K most important features
    - StandardScaler normalization
    - Handles feature alignment between different datasets
    """

    def __init__(self):
        self.scaler = None
        self.feature_selector = None
        self.feature_names = []
        self.original_feature_names = []  # Before feature selection
        self.classes_ = ["Benign", "Attack"]  # Binary
        self.attack_types = []  # Original attack type names
        self.is_fitted = False
        self.dataset_fitted_on = None  # Track which dataset was used for fitting

    def fit_transform(self, data: pd.DataFrame, dataset_name: str = None,
                      progress_callback=None) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str]]:
        """
        Preprocess the data - fit the scaler and selector, then transform.

        Args:
            data: Raw DataFrame with features and labels
            dataset_name: Optional name of dataset (for saving purposes)
            progress_callback: Optional callback(step_number, total_steps, step_name) for progress reporting

        Returns:
            X: Preprocessed feature matrix
            y_binary: Binary labels (0=Benign, 1=Attack)
            y_types: Original attack type indices
            feature_names: List of feature names
        """
        total_steps = 9
        def _report(step, name):
            print_subheader(f"Step {step}: {name}")
            if progress_callback:
                progress_callback(step, total_steps, name)

        print_header("Preprocessing Data")

        self.dataset_fitted_on = dataset_name
        initial_rows = len(data)

        # Normalize column names (strip whitespace, rename 2018 -> canonical)
        data.columns = data.columns.str.strip()
        rename_map = {k: v for k, v in COLUMN_RENAME_2018_TO_CANONICAL.items()
                      if k in data.columns}
        if rename_map:
            data = data.rename(columns=rename_map)

        # ── VERY EARLY SAMPLING ────────────────────────────────────────────
        # Must happen BEFORE any pandas operations (drop/copy/replace) that
        # would create full-size copies of a 16M-row DataFrame.
        # Memory budget for CIC-IDS2018 (16M rows × 76 cols float32 ≈ 4.9 GB):
        #   caller keeps raw_data reference  → 4.9 GB
        #   _to_numeric does data.copy()     → +4.9 GB   (peak ~15 GB → crash)
        #   f_classif float64 scratch        → +9.1 GB   (crash even if steps 1-6 survive)
        # Sampling here caps everything that follows to MAX_TRAINING_SAMPLES rows.
        if ENABLE_SAMPLING and MAX_TRAINING_SAMPLES and len(data) > MAX_TRAINING_SAMPLES:
            label_col_pre = self._find_label_column(data)
            if label_col_pre:
                # Stratified sample: preserve benign/attack ratio
                is_benign = data[label_col_pre].astype(str).str.strip().str.upper() == "BENIGN"
                n_total = MAX_TRAINING_SAMPLES
                n_benign = min(int(n_total * 0.8), int(is_benign.sum()))
                n_attack = min(n_total - n_benign, int((~is_benign).sum()))
                benign_idx = (data[is_benign]
                              .sample(n=n_benign, random_state=RANDOM_STATE)
                              .index)
                attack_idx = (data[~is_benign]
                              .sample(n=n_attack, random_state=RANDOM_STATE)
                              .index)
                data = data.loc[benign_idx.union(attack_idx)].reset_index(drop=True)
            else:
                data = data.sample(n=MAX_TRAINING_SAMPLES,
                                   random_state=RANDOM_STATE).reset_index(drop=True)
            print_info(
                f"Large dataset ({format_number(initial_rows)} rows) sampled to "
                f"{format_number(len(data))} before preprocessing."
            )
            gc.collect()
        # ──────────────────────────────────────────────────────────────────

        # Step 1: Extract labels
        _report(1, "Extracting Labels")
        label_col = self._find_label_column(data)
        y_raw = data[label_col].copy()
        data = data.drop(columns=[label_col])

        # Step 2: Drop identifier columns
        _report(2, "Removing Identifiers")
        data = self._drop_identifiers(data)

        # Step 3: Convert to numeric
        _report(3, "Converting to Numeric")
        data = self._to_numeric(data)
        gc.collect()

        # Step 4: Clean data
        _report(4, "Cleaning Data")
        data, y_raw = self._clean(data, y_raw)
        gc.collect()

        # Step 5: Remove constant columns
        _report(5, "Removing Constants")
        data = self._remove_constants(data)

        # Store original feature names (before selection)
        self.original_feature_names = list(data.columns)
        self.feature_names = list(data.columns)

        # Step 6: Encode labels (binary + keep original types)
        _report(6, "Encoding Labels")
        y_binary, y_types = self._encode_labels(y_raw)
        del y_raw
        gc.collect()

        # Step 7: Convert to numpy
        _report(7, "Converting to Arrays")
        X = data.values.astype(np.float32)
        del data
        gc.collect()

        # Step 8: Feature selection
        # X is already capped at MAX_TRAINING_SAMPLES by the early sampling above.
        if ENABLE_FEATURE_SELECTION and TOP_K_FEATURES < X.shape[1]:
            _report(8, "Feature Selection")
            X = self._select_features(X, y_binary)
            gc.collect()
        else:
            _report(8, "Feature Selection (skipped)")

        # Step 9: Scale
        _report(9, "Scaling Features")
        self.scaler = StandardScaler()
        X = self.scaler.fit_transform(X).astype(np.float32)

        self.is_fitted = True

        # Summary with visual
        self._print_summary(initial_rows, len(X), y_binary, y_types)

        return X, y_binary, y_types, self.feature_names

    def transform(self, data: pd.DataFrame, include_labels: bool = False) -> Union[np.ndarray, Tuple[np.ndarray, np.ndarray, np.ndarray]]:
        """
        Transform new data using fitted scaler and selector.
        Used for:
        - Cross-dataset validation (transform test dataset)
        - Classifying new CSV files

        Args:
            data: DataFrame to transform
            include_labels: If True, also extract and return labels

        Returns:
            If include_labels=False: X (feature matrix only)
            If include_labels=True: (X, y_binary, y_types)
        """
        if not self.is_fitted:
            raise ValueError("Preprocessor not fitted. Call fit_transform() first.")

        print_subheader("Transforming Data")
        initial_rows = len(data)

        # Normalize column names (strip whitespace, rename 2018 -> canonical)
        # This ensures data from any source (CIC-IDS2017, 2018, or new CSVs)
        # uses the same column names as the training data.
        data.columns = data.columns.str.strip()
        rename_map = {k: v for k, v in COLUMN_RENAME_2018_TO_CANONICAL.items()
                      if k in data.columns}
        if rename_map:
            data = data.rename(columns=rename_map)

        # Extract labels if requested
        y_raw = None
        if include_labels:
            label_col = self._find_label_column(data)
            if label_col:
                y_raw = data[label_col].copy()
                data = data.drop(columns=[label_col])

        # Drop label columns if present
        label_cols = ["Label", "label", " Label"]
        for col in label_cols:
            if col in data.columns:
                data = data.drop(columns=[col])

        # Drop identifiers
        data = self._drop_identifiers(data)

        # Convert to numeric
        data = self._to_numeric(data)

        # Clean (fill instead of drop for transform)
        data = data.replace([np.inf, -np.inf], np.nan).fillna(0)

        # Ensure all required features exist, track how many are missing
        missing_count = 0
        missing_names = []
        for col in self.feature_names:
            if col not in data.columns:
                data[col] = 0
                missing_count += 1
                missing_names.append(col)

        # Report missing features
        if missing_count > 0:
            total_features = len(self.feature_names)
            missing_pct = missing_count / total_features * 100
            print_warning(f"{missing_count}/{total_features} features missing ({missing_pct:.0f}%) - filled with 0")
            for name in missing_names[:5]:
                print_warning(f"  Missing: '{name}'")
            if len(missing_names) > 5:
                print_warning(f"  ... and {len(missing_names) - 5} more")

            # If more than 20% of features are missing, the schema mismatch is
            # too severe for reliable predictions. This typically means the
            # column name mapping between CIC-IDS2017 and 2018 is incomplete
            # or the input data uses a different feature schema entirely.
            if missing_pct > 20:
                raise ValueError(
                    f"Schema mismatch: {missing_count}/{total_features} required features "
                    f"({missing_pct:.0f}%) are missing from the input data. "
                    f"This usually means the input data uses different column names "
                    f"than the training data (e.g., CIC-IDS2018 vs CIC-IDS2017). "
                    f"Ensure column name normalization is applied before transform. "
                    f"First 5 missing: {missing_names[:5]}"
                )

        # Keep only the features we need, in the correct order
        data = data[self.feature_names]

        # Transform
        X = self.scaler.transform(data.values.astype(np.float32))

        print_info(f"Transformed {format_number(initial_rows)} rows -> {format_number(len(X))} samples")

        if include_labels and y_raw is not None:
            y_binary, y_types = self._encode_labels(y_raw)
            return X.astype(np.float32), y_binary, y_types

        return X.astype(np.float32)

    def transform_cross_dataset(self, data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Transform data from a different dataset for cross-dataset validation.
        Extracts labels and handles feature alignment.

        Args:
            data: DataFrame from the test dataset

        Returns:
            X: Transformed feature matrix
            y_binary: Binary labels
            y_types: Attack type indices
        """
        print_header("Cross-Dataset Transform")

        return self.transform(data, include_labels=True)

    def _find_label_column(self, data: pd.DataFrame) -> Optional[str]:
        """Find the label column."""
        for name in ["Label", "label", " Label", "LABEL"]:
            if name in data.columns:
                print_info(f"Found label column: '{name}'")
                return name
        return None

    def _drop_identifiers(self, data: pd.DataFrame) -> pd.DataFrame:
        """Drop identifier columns."""
        to_drop = []
        for col in data.columns:
            col_clean = col.strip().lower()
            for drop_name in COLUMNS_TO_DROP:
                if drop_name.lower() in col_clean:
                    to_drop.append(col)
                    break

        if to_drop:
            data = data.drop(columns=to_drop, errors='ignore')
            print_info(f"Dropped {len(to_drop)} identifier columns")

        return data

    def _to_numeric(self, data: pd.DataFrame) -> pd.DataFrame:
        """Convert to numeric types."""
        data = data.copy()
        for col in data.columns:
            if pd.api.types.is_numeric_dtype(data[col]):
                data[col] = data[col].astype(np.float32)
                continue

            numeric = pd.to_numeric(data[col], errors='coerce')
            if numeric.notna().sum() / len(numeric) > 0.5:
                data[col] = numeric.astype(np.float32)
            else:
                le = LabelEncoder()
                data[col] = le.fit_transform(data[col].astype(str)).astype(np.float32)

        return data

    def _clean(self, data: pd.DataFrame, y: pd.Series) -> Tuple[pd.DataFrame, pd.Series]:
        """Remove invalid rows."""
        initial = len(data)
        data = data.replace([np.inf, -np.inf], np.nan)
        valid = ~data.isna().any(axis=1)
        data = data[valid].reset_index(drop=True)
        y = y[valid].reset_index(drop=True)

        removed = initial - len(data)
        if removed > 0:
            print_info(f"Removed {format_number(removed)} invalid rows")

        return data, y

    def _remove_constants(self, data: pd.DataFrame) -> pd.DataFrame:
        """Remove constant columns."""
        constants = [col for col in data.columns if data[col].nunique() <= 1]
        if constants:
            data = data.drop(columns=constants)
            print_info(f"Removed {len(constants)} constant columns")
        return data

    def _encode_labels(self, y: pd.Series) -> Tuple[np.ndarray, np.ndarray]:
        """
        Encode labels.
        Returns: y_binary (0/1), y_types (original attack type indices)
        """
        # Clean labels
        y_clean = y.astype(str).str.strip()

        # Get unique attack types (only update if fitting)
        if not self.is_fitted or len(self.attack_types) == 0:
            self.attack_types = sorted(y_clean.unique().tolist())

        # Create type encoder
        type_to_idx = {t: i for i, t in enumerate(self.attack_types)}

        # Map to indices, use -1 for unknown types
        y_types = y_clean.map(lambda x: type_to_idx.get(x, -1)).values.astype(np.int32)

        # Count unknowns
        unknown_count = (y_types == -1).sum()
        if unknown_count > 0:
            print_warning(f"Found {format_number(unknown_count)} samples with unknown attack types")

        # Binary: Benign (0) vs Attack (1)
        y_binary = y_clean.apply(
            lambda x: 0 if x.upper() == "BENIGN" else 1
        ).values.astype(np.int32)

        # Print distribution
        benign = (y_binary == 0).sum()
        attack = (y_binary == 1).sum()
        print_info(f"Benign: {format_number(benign)} ({benign/len(y)*100:.1f}%)")
        print_info(f"Attack: {format_number(attack)} ({attack/len(y)*100:.1f}%)")
        print_info(f"Attack types found: {len(self.attack_types)}")

        return y_binary, y_types

    def _select_features(self, X: np.ndarray, y: np.ndarray) -> np.ndarray:
        """Select top K features."""
        k = min(TOP_K_FEATURES, X.shape[1])
        self.feature_selector = SelectKBest(score_func=f_classif, k=k)
        X_selected = self.feature_selector.fit_transform(X, y)

        mask = self.feature_selector.get_support()
        self.feature_names = [self.original_feature_names[i] for i, m in enumerate(mask) if m]
        print_info(f"Selected {k} best features")

        return X_selected.astype(np.float32)

    def _print_summary(self, initial: int, final: int, y_binary: np.ndarray, y_types: np.ndarray):
        """Print preprocessing summary with visual."""
        print()
        print("=" * 60)
        print_success("Preprocessing Complete")
        print()
        print(f"  Samples: {format_number(initial)} -> {format_number(final)}")
        print(f"  Features: {len(self.feature_names)}")
        print()

        # Binary distribution bar
        benign = (y_binary == 0).sum()
        attack = (y_binary == 1).sum()
        total = len(y_binary)

        benign_pct = benign / total * 100
        attack_pct = attack / total * 100

        bar_width = 40
        benign_bar = int(benign_pct / 100 * bar_width)
        attack_bar = bar_width - benign_bar

        print("  Class Distribution:")
        print(f"  +{'-' * bar_width}+")
        print(f"  |{'#' * benign_bar}{'.' * attack_bar}|")
        print(f"  +{'-' * bar_width}+")
        print(f"   Benign: {benign_pct:.1f}%    Attack: {attack_pct:.1f}%")
        print()

        # Attack type breakdown
        print("  Attack Types:")
        type_counts = {}
        for i, t in enumerate(self.attack_types):
            count = (y_types == i).sum()
            type_counts[t] = count

        # Sort by count
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        max_count = sorted_types[0][1] if sorted_types else 1

        for attack_type, count in sorted_types[:8]:
            pct = count / total * 100
            bar_len = int(count / max_count * 25)
            bar = "#" * bar_len
            print(f"    {attack_type[:25]:<25} {count:>8} ({pct:5.1f}%) {bar}")

        if len(sorted_types) > 8:
            print(f"    ... and {len(sorted_types) - 8} more types")

        print("=" * 60)

    def split_data(self, X: np.ndarray, y: np.ndarray, y_types: np.ndarray = None):
        """
        Split into 80% training and 20% testing.
        Only used for same-dataset mode, not cross-dataset.
        """
        print_subheader("Splitting Data (80/20)")

        if y_types is not None:
            X_train, X_test, y_train, y_test, yt_train, yt_test = train_test_split(
                X, y, y_types,
                test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
            )
        else:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
            )
            yt_train, yt_test = None, None

        # Sample if needed
        if ENABLE_SAMPLING and MAX_TRAINING_SAMPLES and len(X_train) > MAX_TRAINING_SAMPLES:
            print_info(f"Sampling: {format_number(len(X_train))} -> {format_number(MAX_TRAINING_SAMPLES)}")
            idx = self._stratified_sample_idx(y_train, MAX_TRAINING_SAMPLES)
            X_train, y_train = X_train[idx], y_train[idx]
            if yt_train is not None:
                yt_train = yt_train[idx]

        print_info(f"Training: {format_number(len(X_train))} (80%)")
        print_info(f"Testing:  {format_number(len(X_test))} (20%)")

        if y_types is not None:
            return X_train, X_test, y_train, y_test, yt_train, yt_test
        return X_train, X_test, y_train, y_test

    def _stratified_sample_idx(self, y: np.ndarray, n: int) -> np.ndarray:
        """Get stratified sample indices."""
        unique, counts = np.unique(y, return_counts=True)
        ratios = counts / counts.sum()

        indices = []
        for label, ratio in zip(unique, ratios):
            label_idx = np.where(y == label)[0]
            n_samples = min(int(n * ratio), len(label_idx))
            sampled = np.random.choice(label_idx, size=n_samples, replace=False)
            indices.extend(sampled)

        return np.array(indices)

    def get_attack_type_name(self, type_idx: int) -> str:
        """Get attack type name from index."""
        if 0 <= type_idx < len(self.attack_types):
            return self.attack_types[type_idx]
        return "Unknown"

    def save_data(self, X: np.ndarray, y: np.ndarray, y_types: np.ndarray = None,
                  dataset_name: str = None) -> str:
        """Save processed data."""
        if dataset_name:
            filename = get_processed_data_filename(dataset_name)
        else:
            filename = PROCESSED_DATA_FILENAME

        filepath = PROCESSED_DATA_DIR / filename
        save_dict = {
            'X': X, 'y': y,
            'feature_names': np.array(self.feature_names, dtype=object),
            'classes': np.array(self.classes_, dtype=object),
            'attack_types': np.array(self.attack_types, dtype=object),
        }
        if y_types is not None:
            save_dict['y_types'] = y_types

        np.savez_compressed(filepath, **save_dict)
        print_success(f"Data saved: {filepath}")
        return str(filepath)

    def load_data(self, dataset_name: str = None) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str]]:
        """Load saved data."""
        if dataset_name:
            filename = get_processed_data_filename(dataset_name)
        else:
            filename = PROCESSED_DATA_FILENAME

        filepath = PROCESSED_DATA_DIR / filename
        if not filepath.exists():
            raise FileNotFoundError(f"No saved data: {filepath}")

        data = np.load(filepath, allow_pickle=True)
        self.feature_names = list(data['feature_names'])
        self.classes_ = list(data['classes'])
        self.attack_types = list(data['attack_types'])
        self.is_fitted = True

        y_types = data['y_types'] if 'y_types' in data else None

        print_success(f"Loaded {format_number(len(data['X']))} samples")
        return data['X'], data['y'], y_types, self.feature_names

    def save(self, dataset_name: str = None) -> None:
        """Save preprocessor."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)

        if dataset_name:
            filename = get_preprocessor_filename(dataset_name)
        else:
            filename = PREPROCESSOR_FILENAME

        joblib.dump({
            'scaler': self.scaler,
            'feature_selector': self.feature_selector,
            'feature_names': self.feature_names,
            'original_feature_names': self.original_feature_names,
            'classes': self.classes_,
            'attack_types': self.attack_types,
            'dataset_fitted_on': self.dataset_fitted_on,
        }, MODEL_DIR / filename)
        print_info(f"Preprocessor saved: {filename}")

    def load(self, dataset_name: str = None) -> None:
        """Load preprocessor."""
        if dataset_name:
            filename = get_preprocessor_filename(dataset_name)
        else:
            filename = PREPROCESSOR_FILENAME

        filepath = MODEL_DIR / filename
        if not filepath.exists():
            # Try default filename
            filepath = MODEL_DIR / PREPROCESSOR_FILENAME
            if not filepath.exists():
                raise FileNotFoundError(f"No preprocessor found: {filepath}")

        data = joblib.load(filepath)
        self.scaler = data['scaler']
        self.feature_selector = data['feature_selector']
        self.feature_names = data['feature_names']
        self.original_feature_names = data.get('original_feature_names', data['feature_names'])
        self.classes_ = data['classes']
        self.attack_types = data.get('attack_types', [])
        self.dataset_fitted_on = data.get('dataset_fitted_on', None)
        self.is_fitted = True
        print_info(f"Preprocessor loaded: {filepath.name}")


class CrossDatasetPreprocessor:
    """
    Preprocessor specifically designed for cross-dataset validation.

    Fits on training dataset, then transforms testing dataset while
    maintaining feature alignment.
    """

    def __init__(self):
        self.preprocessor = Preprocessor()
        self.train_dataset = None
        self.test_dataset = None

    def fit_transform_train(self, train_data: pd.DataFrame, dataset_name: str = "2017") -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str]]:
        """
        Fit and transform the training data.

        Args:
            train_data: Training DataFrame
            dataset_name: Name of training dataset

        Returns:
            X_train, y_train, y_types_train, feature_names
        """
        self.train_dataset = dataset_name
        return self.preprocessor.fit_transform(train_data, dataset_name=dataset_name)

    def transform_test(self, test_data: pd.DataFrame, dataset_name: str = "2018") -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Transform the testing data using fitted preprocessor.

        Args:
            test_data: Testing DataFrame
            dataset_name: Name of testing dataset

        Returns:
            X_test, y_test, y_types_test
        """
        self.test_dataset = dataset_name
        print_header(f"Transforming Test Data (CIC-IDS{dataset_name})")
        return self.preprocessor.transform(test_data, include_labels=True)

    def save(self) -> None:
        """Save the preprocessor."""
        self.preprocessor.save(dataset_name=self.train_dataset)

    def load(self, dataset_name: str = None) -> None:
        """Load a saved preprocessor."""
        self.preprocessor.load(dataset_name=dataset_name)
        self.train_dataset = self.preprocessor.dataset_fitted_on

    @property
    def feature_names(self) -> List[str]:
        return self.preprocessor.feature_names

    @property
    def attack_types(self) -> List[str]:
        return self.preprocessor.attack_types

    def get_attack_type_name(self, idx: int) -> str:
        return self.preprocessor.get_attack_type_name(idx)
