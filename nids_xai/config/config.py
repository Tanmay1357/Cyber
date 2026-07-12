"""
Configuration for NIDS with XAI.
Supports CIC-IDS2017 and CIC-IDS2018 datasets with cross-dataset validation.
"""

from pathlib import Path

# =============================================================================
# Directory Paths
# =============================================================================
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"

# Separate folders for each dataset (makes switching easy)
# Place CIC-IDS2017 files in: data/raw/CIC-IDS-2017/
# Place CIC-IDS2018 files in: data/raw/CIC-IDS-2018/
RAW_DATA_DIR_2017 = DATA_DIR / "raw" / "CIC-IDS-2017"
RAW_DATA_DIR_2018 = DATA_DIR / "raw" / "CIC-IDS-2018"

# Legacy support - default raw data dir
RAW_DATA_DIR = RAW_DATA_DIR_2017

PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODEL_DIR = PROJECT_ROOT / "models"
OUTPUT_DIR = PROJECT_ROOT / "outputs"
LOG_DIR = PROJECT_ROOT / "logs"

# Create all necessary directories
for directory in [RAW_DATA_DIR_2017, RAW_DATA_DIR_2018, PROCESSED_DATA_DIR,
                  MODEL_DIR, OUTPUT_DIR, LOG_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# =============================================================================
# Dataset Configuration
# =============================================================================
# Training dataset: "2017" or "2018"
TRAINING_DATASET = "2017"

# Testing dataset: "2017", "2018", or "same" (use same as training)
# For cross-dataset validation, set different values for TRAINING and TESTING
TESTING_DATASET = "same"

# Cross-dataset mode: When True, train on one dataset, test on another
# This is automatically determined based on TRAINING_DATASET and TESTING_DATASET
CROSS_DATASET_MODE = False

# Legacy support
ACTIVE_DATASET = TRAINING_DATASET


def get_data_dir(dataset: str) -> Path:
    """Get the data directory for a specific dataset."""
    if dataset == "2017":
        return RAW_DATA_DIR_2017
    elif dataset == "2018":
        return RAW_DATA_DIR_2018
    else:
        return RAW_DATA_DIR_2017


def get_testing_dataset() -> str:
    """Get the actual testing dataset (resolves 'same' to actual dataset)."""
    if TESTING_DATASET == "same":
        return TRAINING_DATASET
    return TESTING_DATASET


def is_cross_dataset_mode() -> bool:
    """Check if we're in cross-dataset validation mode."""
    return TESTING_DATASET != "same" and TESTING_DATASET != TRAINING_DATASET


def set_dataset_mode(train_dataset: str, test_dataset: str = "same") -> None:
    """
    Set the dataset mode for training and testing.

    Args:
        train_dataset: Dataset to train on ("2017" or "2018")
        test_dataset: Dataset to test on ("2017", "2018", or "same")

    Examples:
        set_dataset_mode("2017", "same")  # Train and test on 2017
        set_dataset_mode("2017", "2018")  # Train on 2017, test on 2018 (cross-dataset)
        set_dataset_mode("2018", "2017")  # Train on 2018, test on 2017 (cross-dataset)
    """
    global TRAINING_DATASET, TESTING_DATASET, CROSS_DATASET_MODE, ACTIVE_DATASET
    TRAINING_DATASET = train_dataset
    TESTING_DATASET = test_dataset
    CROSS_DATASET_MODE = is_cross_dataset_mode()
    ACTIVE_DATASET = train_dataset


# =============================================================================
# CIC-IDS2017 Dataset Files
# =============================================================================
# Place these files in: data/raw/CIC-IDS-2017/
DATASET_2017_FILES = {
    "Tuesday-WorkingHours.pcap_ISCX.csv": {
        "attacks": ["FTP-Patator", "SSH-Patator"],
        "description": "Brute Force attacks on FTP and SSH"
    },
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": {
        "attacks": ["Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - Sql Injection"],
        "description": "Web application attacks"
    },
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": {
        "attacks": ["PortScan"],
        "description": "Network port scanning"
    },
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": {
        "attacks": ["Bot"],
        "description": "Botnet traffic patterns"
    },
    "Monday-WorkingHours.pcap_ISCX.csv": {
        "attacks": ["BENIGN"],
        "description": "Normal/benign traffic only"
    },
    "Wednesday-workingHours.pcap_ISCX.csv": {
        "attacks": ["DoS Slowloris", "DoS GoldenEye", "DoS Hulk", "Heartbleed"],
        "description": "Denial of Service attacks"
    },
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": {
        "attacks": ["DDoS"],
        "description": "Distributed Denial of Service attacks"
    },
}

# Files to SKIP (not useful for testing)
DATASET_2017_SKIP = [
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
]

# =============================================================================
# CIC-IDS2018 Dataset Files
# =============================================================================
# Place these files in: data/raw/CIC-IDS-2018/
# Note: 2018 uses different file naming convention
DATASET_2018_FILES = {
    "02-14-2018.csv": {
        "attacks": ["FTP-BruteForce", "SSH-Bruteforce"],
        "description": "Brute Force attacks"
    },
    "02-15-2018.csv": {
        "attacks": ["DoS attacks-Hulk", "DoS attacks-Slowloris"],
        "description": "DoS attacks - Day 1"
    },
    "02-16-2018.csv": {
        "attacks": ["DoS attacks-SlowHTTPTest", "DoS attacks-GoldenEye"],
        "description": "DoS attacks - Day 2"
    },
    "02-20-2018.csv": {
        "attacks": ["DDoS attacks-LOIC-HTTP", "DDoS attack-HOIC", "DDoS attack-LOIC-UDP"],
        "description": "DDoS attacks"
    },
    "02-21-2018.csv": {
        "attacks": ["DDOS attack-HOIC", "DDOS attack-LOIC-UDP"],
        "description": "DDoS attacks - Day 2"
    },
    "02-22-2018.csv": {
        "attacks": ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"],
        "description": "Web attacks - Day 1"
    },
    "02-23-2018.csv": {
        "attacks": ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"],
        "description": "Web attacks - Day 2"
    },
    "02-28-2018.csv": {
        "attacks": ["Infilteration"],
        "description": "Infiltration attacks - Day 1"
    },
    "03-01-2018.csv": {
        "attacks": ["Infilteration"],
        "description": "Infiltration attacks - Day 2"
    },
    "03-02-2018.csv": {
        "attacks": ["Bot"],
        "description": "Botnet attacks (Ares)"
    },
}

# Files to skip (too large or not needed)
DATASET_2018_SKIP = []

# =============================================================================
# Memory Optimization
# =============================================================================
CHUNK_SIZE = 200000  # Rows per chunk when loading CSV
MAX_SAMPLES = None   # None = no limit, or set a number to limit total samples

# =============================================================================
# Attack Categories (for reference and testing)
# =============================================================================
TESTABLE_ATTACKS = {
    # Brute Force
    "FTP-Patator": {"category": "Brute Force", "tool": "hydra -L users.txt -P pass.txt ftp://target", "difficulty": "Easy"},
    "SSH-Patator": {"category": "Brute Force", "tool": "hydra -L users.txt -P pass.txt ssh://target", "difficulty": "Easy"},

    # Reconnaissance
    "PortScan": {"category": "Reconnaissance", "tool": "nmap -sS -p- target", "difficulty": "Very Easy"},

    # Web Attacks
    "Web Attack - Brute Force": {"category": "Web Attack", "tool": "hydra/burpsuite", "difficulty": "Easy"},
    "Web Attack - XSS": {"category": "Web Attack", "tool": "manual/burpsuite", "difficulty": "Medium"},
    "Web Attack - Sql Injection": {"category": "Web Attack", "tool": "sqlmap -u URL", "difficulty": "Medium"},

    # DoS
    "DoS Slowloris": {"category": "DoS", "tool": "slowloris.py target", "difficulty": "Easy"},
    "DoS GoldenEye": {"category": "DoS", "tool": "goldeneye.py target", "difficulty": "Easy"},
    "DoS Hulk": {"category": "DoS", "tool": "hulk.py target", "difficulty": "Easy"},

    # Botnet
    "Bot": {"category": "Botnet", "tool": "custom script", "difficulty": "Medium"},
}

# =============================================================================
# Feature Configuration
# =============================================================================
LABEL_COLUMN = "Label"

# Columns to drop (identifiers, not useful for ML)
# Covers both CIC-IDS2017 and CIC-IDS2018 column name variants
COLUMNS_TO_DROP = [
    "Flow ID", "Source IP", "Src IP", "Source Port", "Src Port",
    "Destination IP", "Dst IP", "Destination Port", "Dst Port",
    "Timestamp", "Protocol", "SimillarHTTP",
]

# =============================================================================
# Column Name Mapping: CIC-IDS2018 -> Canonical (CIC-IDS2017 stripped)
# =============================================================================
# CIC-IDS2017 and CIC-IDS2018 use different column names for the same features.
# After stripping whitespace from 2017 names, this mapping converts the remaining
# 2018-specific names to the canonical (2017-stripped) equivalents.
# Columns that already match after stripping (e.g., "Flow Duration", "Active Mean")
# do not need entries here.
COLUMN_RENAME_2018_TO_CANONICAL = {
    # Packet counts
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    # Forward packet lengths
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    # Backward packet lengths
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    # Flow rates
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    # IAT totals
    "Fwd IAT Tot": "Fwd IAT Total",
    "Bwd IAT Tot": "Bwd IAT Total",
    # Header lengths
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    # Packet rates
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    # Packet length stats
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    # Flag counts
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    # Averages
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    # Bulk averages
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    # Subflow
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    # Init window bytes
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    # Misc
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
    # Destination port (2018 uses "Dst Port" which is in COLUMNS_TO_DROP)
    "Dst Port": "Destination Port",
    # NFStream-format exports (Wireshark/PCAP -> nfstream) use full but
    # differently-ordered names for the packet-length extremes.
    "Packet Length Min": "Min Packet Length",
    "Packet Length Max": "Max Packet Length",
}

# Feature selection settings
ENABLE_FEATURE_SELECTION = True
TOP_K_FEATURES = 25  # Number of best features to keep

# =============================================================================
# Sampling Configuration
# =============================================================================
ENABLE_SAMPLING = True
MAX_TRAINING_SAMPLES = 300000  # Cap training set size for memory efficiency

# =============================================================================
# Class Imbalance Handling
# =============================================================================
# SMOTE oversampling for minority attack classes (e.g., Web Attacks)
# Requires: pip install imbalanced-learn
USE_SMOTE = False

# =============================================================================
# Model Configuration - Random Forest
# =============================================================================
# Default parameters (balanced for accuracy and speed)
RF_PARAMS = {
    "n_estimators": 100,
    "max_depth": 15,
    "min_samples_split": 10,
    "min_samples_leaf": 4,
    "max_features": "sqrt",
    "class_weight": "balanced",
    "random_state": 42,
    "n_jobs": -1,
}

# Optimized parameters for higher accuracy (slower training)
RF_PARAMS_OPTIMIZED = {
    "n_estimators": 200,
    "max_depth": 20,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "max_features": "sqrt",
    "class_weight": "balanced",
    "random_state": 42,
    "n_jobs": -1,
}

# Quick training parameters (faster, slightly lower accuracy)
RF_PARAMS_QUICK = {
    "n_estimators": 50,
    "max_depth": 10,
    "min_samples_split": 20,
    "min_samples_leaf": 10,
    "max_features": "sqrt",
    "class_weight": "balanced",
    "random_state": 42,
    "n_jobs": -1,
}

# Hyperparameter grid for tuning (GridSearchCV)
RF_PARAM_GRID = {
    "n_estimators": [100, 150, 200],
    "max_depth": [15, 20, 25],
    "min_samples_split": [5, 10],
    "min_samples_leaf": [2, 4],
}

# Hyperparameter distributions for RandomizedSearchCV (faster than grid)
RF_PARAM_DISTRIBUTIONS = {
    "n_estimators": [50, 100, 150, 200, 250],
    "max_depth": [10, 15, 20, 25, 30, None],
    "min_samples_split": [2, 5, 10, 15, 20],
    "min_samples_leaf": [1, 2, 4, 6, 8],
    "max_features": ["sqrt", "log2", None],
}

# =============================================================================
# Training Configuration
# =============================================================================
TEST_SIZE = 0.2  # 20% for testing (only used in same-dataset mode)
RANDOM_STATE = 42

# Cross-validation settings
CV_FOLDS = 5
ENABLE_HYPERPARAMETER_TUNING = False  # Set True for auto-tuning (slower)
TUNING_METHOD = "grid"  # "grid" for exhaustive, "random" for faster

# =============================================================================
# XAI Configuration
# =============================================================================
SHAP_SAMPLE_SIZE = 100  # Background samples for SHAP
SHAP_MAX_DISPLAY = 10   # Top features to show in explanations
AUTO_EXPLAIN = True     # Auto-explain when classifying new data

# =============================================================================
# External Tools
# =============================================================================
# Path to CICFlowMeter executable or JAR (empty string = auto-detect)
CICFLOWMETER_PATH = ""

# =============================================================================
# File Names
# =============================================================================
MODEL_FILENAME = "nids_model.joblib"
PREPROCESSOR_FILENAME = "preprocessor.joblib"
PROCESSED_DATA_FILENAME = "processed_data.npz"


def get_model_filename(train_dataset: str, test_dataset: str = None) -> str:
    """Get model filename based on training and testing datasets."""
    if test_dataset and test_dataset != train_dataset and test_dataset != "same":
        return f"nids_model_{train_dataset}_cross_{test_dataset}.joblib"
    return f"nids_model_{train_dataset}.joblib"


def get_preprocessor_filename(train_dataset: str) -> str:
    """Get preprocessor filename based on training dataset."""
    return f"preprocessor_{train_dataset}.joblib"


def get_processed_data_filename(dataset: str) -> str:
    """Get processed data filename based on dataset."""
    return f"processed_data_{dataset}.npz"


# =============================================================================
# Terminal Display
# =============================================================================
COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "BOLD": "\033[1m",
    "END": "\033[0m",
}

TERMINAL_WIDTH = 80

# =============================================================================
# Logging Configuration
# =============================================================================
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# =============================================================================
# Real-Time Monitor Configuration
# =============================================================================
MONITOR_IDLE_TIMEOUT_LIVE   = 4.0    # seconds: live interface flow idle expiry
MONITOR_IDLE_TIMEOUT_REPLAY = 5.0    # seconds: PCAP replay flow idle expiry
MONITOR_DEFAULT_THRESHOLD   = 0.70   # default attack confidence threshold
MONITOR_MAX_TABLE_ROWS      = 200    # max rows held in alert feed before trimming
MONITOR_SWEEP_INTERVAL      = 2.0    # seconds between sweep-thread expiry checks
MONITOR_MIN_FLOW_PACKETS    = 1      # min packets before flow is classified
MONITOR_TOAST_DURATION_MS   = 5000   # ms before toast auto-dismisses
MONITOR_MAX_TOASTS          = 3      # max simultaneous toast overlays
MONITOR_LOG_FEATURES        = True   # log each flow's raw feature vector (live debug)
