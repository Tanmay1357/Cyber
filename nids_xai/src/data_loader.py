"""
Data Loader for NIDS with XAI.
Supports CIC-IDS2017 and CIC-IDS2018 datasets with separate folder structure.
"""

import sys
import gc
from pathlib import Path
from typing import Optional, List, Tuple, Dict
import pandas as pd
import numpy as np
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import (
    RAW_DATA_DIR_2017, RAW_DATA_DIR_2018, CHUNK_SIZE,
    DATASET_2017_FILES, DATASET_2017_SKIP,
    DATASET_2018_FILES, DATASET_2018_SKIP, LABEL_COLUMN,
    get_data_dir, TRAINING_DATASET,
    COLUMN_RENAME_2018_TO_CANONICAL,
)
from src.utils import (
    print_header, print_subheader, print_success, print_error,
    print_warning, print_info, format_number, Timer,
)


class DataLoader:
    """
    Load CIC-IDS2017 or CIC-IDS2018 datasets.

    Supports the folder structure:
    - data/raw/CIC-IDS-2017/ for CIC-IDS2017 files
    - data/raw/CIC-IDS-2018/ for CIC-IDS2018 files

    Also supports legacy structure (data/raw/) for backwards compatibility.

    Cross-Dataset Mode:
    - Can load training data from one dataset and test data from another
    - Use load_for_training() and load_for_testing() for cross-dataset validation
    """

    def __init__(self, dataset: str = None, data_dir: str = None):
        """
        Initialize loader.

        Args:
            dataset: "2017" or "2018" (defaults to TRAINING_DATASET from config)
            data_dir: Optional override path for the data directory.
                      If provided, uses this instead of the default path.
        """
        self.dataset = dataset or TRAINING_DATASET
        if data_dir:
            self.data_dir = Path(data_dir)
        else:
            self.data_dir = get_data_dir(self.dataset)
        self.loaded_files = []
        self.data = None
        self.attack_info = {}  # Track which attacks are in each file

    def get_available_files(self) -> Tuple[List[str], List[str]]:
        """
        Check which files are available.

        When using a custom data_dir, scans the directory for all CSV files
        instead of looking for specific expected filenames.

        Returns:
            Tuple of (available_files, missing_files)
        """
        available = []
        missing = []

        # Get expected files based on dataset choice
        if self.dataset == "2017":
            expected = list(DATASET_2017_FILES.keys())
            skip_list = DATASET_2017_SKIP
        else:  # 2018
            expected = list(DATASET_2018_FILES.keys())
            skip_list = DATASET_2018_SKIP

        # Check if we are using a custom directory (not the default dataset dirs)
        default_dirs = [get_data_dir("2017"), get_data_dir("2018")]
        is_custom_dir = self.data_dir not in default_dirs

        if is_custom_dir and self.data_dir.exists():
            # Custom directory: scan for all CSV files
            csv_files = sorted(self.data_dir.glob("*.csv"))
            available = [f.name for f in csv_files]
            return available, []

        # Standard mode: check expected files
        for filename in expected:
            if filename in skip_list:
                continue

            filepath = self.data_dir / filename

            # Check legacy location if not found
            legacy_path = Path(__file__).parent.parent / "data" / "raw" / filename

            if filepath.exists():
                available.append(filename)
            elif legacy_path.exists():
                available.append(filename)
            else:
                missing.append(filename)

        return available, missing

    def get_file_path(self, filename: str) -> Optional[Path]:
        """Get the actual path to a file (handles both new and legacy structure)."""
        # Try new structure first
        filepath = self.data_dir / filename
        if filepath.exists():
            return filepath

        # Try legacy structure
        legacy_path = Path(__file__).parent.parent / "data" / "raw" / filename
        if legacy_path.exists():
            return legacy_path

        # Try with/without .csv extension
        for path in [filepath, legacy_path]:
            if not filename.endswith('.csv'):
                csv_path = path.parent / (filename + ".csv")
                if csv_path.exists():
                    return csv_path
            else:
                no_csv_path = path.parent / filename.replace(".csv", "")
                if no_csv_path.exists():
                    return no_csv_path

        return None

    def load_file(self, filename: str, show_progress: bool = True) -> Optional[pd.DataFrame]:
        """
        Load a single CSV file.

        Args:
            filename: Name of the CSV file
            show_progress: Whether to show progress bar

        Returns:
            DataFrame or None if loading failed
        """
        filepath = self.get_file_path(filename)

        if filepath is None:
            print_error(f"File not found: {filename}")
            return None

        try:
            chunks = []
            chunk_iter = pd.read_csv(
                filepath,
                chunksize=CHUNK_SIZE,
                low_memory=False,
                encoding='utf-8',
                on_bad_lines='skip',
            )

            # Get column names from first chunk
            first_chunk = True
            column_names = None

            desc = f"  {filepath.name}" if show_progress else None
            iterator = tqdm(chunk_iter, desc=desc, unit="chunk") if show_progress else chunk_iter

            for chunk in iterator:
                # Normalize column names first (strip whitespace, rename 2018->canonical)
                chunk = self._normalize_columns(chunk)

                if first_chunk:
                    column_names = chunk.columns.tolist()
                    first_chunk = False

                # Remove repeated headers (common in CIC-IDS datasets)
                if column_names:
                    mask = ~chunk.apply(
                        lambda row: any(str(v).strip() in column_names for v in row.values[:5]),
                        axis=1
                    )
                    chunk = chunk[mask]

                # Convert to numeric
                chunk = self._convert_numeric(chunk)

                # Clean
                chunk = self._clean(chunk)

                if len(chunk) > 0:
                    chunks.append(chunk)

            if not chunks:
                return None

            df = pd.concat(chunks, ignore_index=True)
            del chunks
            gc.collect()

            return df

        except Exception as e:
            print_error(f"Error loading {filename}: {e}")
            return None

    def _normalize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize column names to canonical form.

        1. Strip leading/trailing whitespace from all column names
           (CIC-IDS2017 has leading spaces on many columns).
        2. Rename CIC-IDS2018-specific column names to canonical
           (CIC-IDS2017-stripped) equivalents using COLUMN_RENAME_2018_TO_CANONICAL.

        This ensures both datasets use identical column names so that
        cross-dataset validation works correctly.
        """
        # Step 1: strip whitespace
        df.columns = df.columns.str.strip()

        # Step 2: rename 2018 names to canonical equivalents
        # Only renames columns that actually exist in the DataFrame
        rename_map = {k: v for k, v in COLUMN_RENAME_2018_TO_CANONICAL.items()
                      if k in df.columns}
        if rename_map:
            df = df.rename(columns=rename_map)

        return df

    def _convert_numeric(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convert columns to numeric where possible."""
        df = df.copy()

        for col in df.columns:
            if col == LABEL_COLUMN:
                continue
            if pd.api.types.is_numeric_dtype(df[col]):
                continue

            try:
                numeric = pd.to_numeric(df[col], errors='coerce')
                if numeric.notna().sum() / len(numeric) > 0.5:
                    df[col] = numeric.astype(np.float32)
            except:
                pass

        return df

    def _clean(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean data - remove inf and NaN."""
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        if len(numeric_cols) > 0:
            df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        df = df.dropna()
        return df

    def load_all(self, show_progress: bool = True) -> Optional[pd.DataFrame]:
        """
        Load all available dataset files.

        Args:
            show_progress: Whether to show progress bars

        Returns:
            Combined DataFrame or None if no data loaded
        """
        print_header(f"Loading CIC-IDS{self.dataset} Dataset")

        available, missing = self.get_available_files()

        if not available:
            print_error(f"No files found in: {self.data_dir}")
            print_info(f"Please add your CSV files to: {self.data_dir}")
            print_info("")
            print_info("Expected files:")
            files_dict = DATASET_2017_FILES if self.dataset == "2017" else DATASET_2018_FILES
            for filename, info in files_dict.items():
                attacks = info.get("attacks", []) if isinstance(info, dict) else info
                print_info(f"  - {filename}")
                if isinstance(attacks, list):
                    print_info(f"    Contains: {', '.join(attacks)}")
            return None

        print_info(f"Found {len(available)} files")
        if missing:
            print_warning(f"Missing {len(missing)} files (skipped)")
            for m in missing[:3]:  # Show first 3 missing
                print_info(f"  - {m}")
            if len(missing) > 3:
                print_info(f"  ... and {len(missing) - 3} more")

        dataframes = []

        with Timer("Total loading time"):
            for filename in available:
                df = self.load_file(filename, show_progress=show_progress)
                if df is not None:
                    dataframes.append(df)
                    self.loaded_files.append(filename)

                    # Track attack types in this file
                    if LABEL_COLUMN in df.columns:
                        attacks = df[LABEL_COLUMN].unique().tolist()
                        self.attack_info[filename] = attacks

                    print_info(f"  Loaded {format_number(len(df))} rows")
                gc.collect()

        if not dataframes:
            print_error("No data loaded!")
            return None

        print_info("\nCombining files...")
        self.data = pd.concat(dataframes, ignore_index=True)
        del dataframes
        gc.collect()

        self._show_summary()
        return self.data

    def _show_summary(self) -> None:
        """Show data summary."""
        if self.data is None:
            return

        print()
        print("=" * 60)
        print_success("Data Loaded Successfully")
        print_info(f"  Dataset: CIC-IDS{self.dataset}")
        print_info(f"  Total rows: {format_number(len(self.data))}")
        print_info(f"  Columns: {len(self.data.columns)}")
        print_info(f"  Files: {len(self.loaded_files)}")

        if LABEL_COLUMN in self.data.columns:
            print_info("\n  Attack Distribution:")
            counts = self.data[LABEL_COLUMN].value_counts()
            for label, count in counts.head(10).items():
                pct = count / len(self.data) * 100
                # Visual bar
                bar_len = int(pct / 5)  # Max 20 chars
                bar = "|" + "#" * bar_len + " " * (20 - bar_len) + "|"
                print_info(f"    {label[:25]:<25} {format_number(count):>10} ({pct:5.1f}%) {bar}")
            if len(counts) > 10:
                print_info(f"    ... and {len(counts) - 10} more")

        print("=" * 60)

    def get_dataset_info(self) -> Dict:
        """Get information about the loaded dataset."""
        info = {
            "dataset": self.dataset,
            "data_dir": str(self.data_dir),
            "loaded_files": self.loaded_files,
            "attack_info": self.attack_info,
            "total_rows": len(self.data) if self.data is not None else 0,
        }

        if self.data is not None and LABEL_COLUMN in self.data.columns:
            counts = self.data[LABEL_COLUMN].value_counts()
            info["label_distribution"] = counts.to_dict()

        return info


class CrossDatasetLoader:
    """
    Load data for cross-dataset validation (train on one dataset, test on another).

    This class handles the complexity of ensuring feature alignment between
    different datasets (2017 and 2018) which may have slightly different features.
    """

    def __init__(self, train_dataset: str = "2017", test_dataset: str = "2018"):
        """
        Initialize cross-dataset loader.

        Args:
            train_dataset: Dataset for training ("2017" or "2018")
            test_dataset: Dataset for testing ("2017" or "2018")
        """
        self.train_dataset = train_dataset
        self.test_dataset = test_dataset
        self.train_data = None
        self.test_data = None
        self.common_features = []

    def load(self, show_progress: bool = True) -> Tuple[Optional[pd.DataFrame], Optional[pd.DataFrame]]:
        """
        Load both training and testing datasets.

        Returns:
            Tuple of (train_data, test_data) DataFrames
        """
        print_header("Cross-Dataset Loading")
        print_info(f"Training dataset: CIC-IDS{self.train_dataset}")
        print_info(f"Testing dataset: CIC-IDS{self.test_dataset}")
        print()

        # Load training data
        print_subheader("Loading Training Data")
        train_loader = DataLoader(dataset=self.train_dataset)
        self.train_data = train_loader.load_all(show_progress=show_progress)

        if self.train_data is None:
            print_error("Failed to load training data")
            return None, None

        # Load testing data
        print()
        print_subheader("Loading Testing Data")
        test_loader = DataLoader(dataset=self.test_dataset)
        self.test_data = test_loader.load_all(show_progress=show_progress)

        if self.test_data is None:
            print_error("Failed to load testing data")
            return None, None

        # Align features between datasets
        self._align_features()

        return self.train_data, self.test_data

    def _align_features(self) -> None:
        """Align features between training and testing datasets."""
        print_subheader("Aligning Features")

        train_cols = set(self.train_data.columns) - {LABEL_COLUMN}
        test_cols = set(self.test_data.columns) - {LABEL_COLUMN}

        # Find common features
        self.common_features = list(train_cols.intersection(test_cols))
        self.common_features.sort()

        train_only = train_cols - test_cols
        test_only = test_cols - train_cols

        print_info(f"Training features: {len(train_cols)}")
        print_info(f"Testing features: {len(test_cols)}")
        print_info(f"Common features: {len(self.common_features)}")

        if train_only:
            print_warning(f"Features only in training: {len(train_only)}")
        if test_only:
            print_warning(f"Features only in testing: {len(test_only)}")

        # Keep only common features plus label
        keep_cols = self.common_features + [LABEL_COLUMN] if LABEL_COLUMN in self.train_data.columns else self.common_features
        self.train_data = self.train_data[[c for c in keep_cols if c in self.train_data.columns]]
        self.test_data = self.test_data[[c for c in keep_cols if c in self.test_data.columns]]

        print_success(f"Aligned to {len(self.common_features)} common features")

    def get_info(self) -> Dict:
        """Get information about the cross-dataset loading."""
        return {
            "train_dataset": self.train_dataset,
            "test_dataset": self.test_dataset,
            "train_rows": len(self.train_data) if self.train_data is not None else 0,
            "test_rows": len(self.test_data) if self.test_data is not None else 0,
            "common_features": len(self.common_features),
            "features": self.common_features,
        }


def load_dataset(dataset: str = "2017", show_progress: bool = True) -> Optional[pd.DataFrame]:
    """
    Convenience function to load a dataset.

    Args:
        dataset: "2017" or "2018"
        show_progress: Whether to show progress bars

    Returns:
        DataFrame or None
    """
    loader = DataLoader(dataset=dataset)
    return loader.load_all(show_progress=show_progress)


def load_cross_dataset(
    train_dataset: str = "2017",
    test_dataset: str = "2018",
    show_progress: bool = True
) -> Tuple[Optional[pd.DataFrame], Optional[pd.DataFrame]]:
    """
    Convenience function to load cross-dataset data.

    Args:
        train_dataset: Dataset for training
        test_dataset: Dataset for testing
        show_progress: Whether to show progress bars

    Returns:
        Tuple of (train_data, test_data)
    """
    loader = CrossDatasetLoader(train_dataset, test_dataset)
    return loader.load(show_progress=show_progress)


def check_dataset_availability() -> Dict[str, Dict]:
    """
    Check which datasets and files are available.

    Returns:
        Dictionary with availability information for each dataset
    """
    result = {}

    for dataset in ["2017", "2018"]:
        loader = DataLoader(dataset=dataset)
        available, missing = loader.get_available_files()
        result[dataset] = {
            "available": available,
            "missing": missing,
            "available_count": len(available),
            "missing_count": len(missing),
            "data_dir": str(loader.data_dir),
            "ready": len(available) > 0,
        }

    return result
