# NIDS-XAI System Architecture

## Overview

This document describes the architecture of the Network Intrusion Detection System with Explainable AI (NIDS-XAI). The system is designed with a modular architecture that separates concerns and allows for easy testing, maintenance, and extension.

---

## System Architecture Diagram

```
+===========================================================================+
|                           NIDS-XAI SYSTEM                                  |
+===========================================================================+
|                                                                            |
|  +------------------+     +------------------+     +------------------+    |
|  |   DATA INPUT     |     |   PROCESSING     |     |     OUTPUT       |    |
|  +------------------+     +------------------+     +------------------+    |
|  |                  |     |                  |     |                  |    |
|  | - CIC-IDS2017    |---->| - Preprocessing  |---->| - Predictions    |    |
|  |   CSV Files      |     | - Feature Select |     | - Explanations   |    |
|  |                  |     | - Scaling        |     | - Reports        |    |
|  | - PCAP Files     |---->| - Model Training |---->| - Visualizations |    |
|  |   (converted)    |     | - Classification |     |                  |    |
|  +------------------+     +------------------+     +------------------+    |
|                                                                            |
+===========================================================================+
```

---

## Component Architecture

```
+===========================================================================+
|                          MAIN APPLICATION                                  |
|                            (main.py)                                       |
+===========================================================================+
           |              |              |              |
           v              v              v              v
+----------+   +----------+   +----------+   +----------+
|  Data    |   |  Model   |   |  Eval    |   |  XAI     |
|  Layer   |   |  Layer   |   |  Layer   |   |  Layer   |
+----------+   +----------+   +----------+   +----------+
|          |   |          |   |          |   |          |
| DataLoad |   | Trainer  |   | Evaluator|   | Explainer|
| Preproc  |   | Model    |   | Metrics  |   | SHAP     |
|          |   |          |   |          |   | LIME     |
+----------+   +----------+   +----------+   +----------+
      |              |              |              |
      v              v              v              v
+===========================================================================+
|                         UTILITIES & CONFIG                                 |
|                    (utils.py, config.py)                                   |
+===========================================================================+
```

---

## Module Responsibilities

### 1. Configuration (`config/config.py`)

**Purpose**: Centralized configuration management

**Responsibilities**:
- Define directory paths (data, models, outputs)
- Dataset file mappings
- Model hyperparameters
- Feature selection settings
- XAI configuration

```python
# Key configurations:
ACTIVE_DATASET = "2017"           # Which dataset to use
RF_PARAMS = {...}                 # Random Forest parameters
TEST_SIZE = 0.2                   # Train/test split ratio
SHAP_SAMPLE_SIZE = 100            # Background samples for SHAP
```

### 2. Data Loader (`src/data_loader.py`)

**Purpose**: Load and parse CSV dataset files

**Responsibilities**:
- Read CSV files in chunks (memory efficient)
- Handle different file encodings
- Remove duplicate headers
- Convert data types
- Clean invalid values

**Data Flow**:
```
CSV Files --> Chunk Reading --> Type Conversion --> Cleaning --> DataFrame
```

### 3. Preprocessor (`src/preprocessor.py`)

**Purpose**: Transform raw data for machine learning

**Responsibilities**:
- Extract and encode labels (binary + attack types)
- Drop identifier columns
- Handle missing values
- Feature selection (SelectKBest)
- Feature scaling (StandardScaler)
- Train/test splitting

**Data Flow**:
```
Raw DataFrame --> Label Extraction --> Feature Selection --> Scaling --> NumPy Arrays
```

### 4. Model Trainer (`src/model_trainer.py`)

**Purpose**: Train and manage the classification model

**Responsibilities**:
- Configure Random Forest classifier
- Train on preprocessed data
- Save/load model checkpoints
- Display feature importances

**Model Configuration**:
```python
RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    min_samples_split=10,
    class_weight='balanced',
    n_jobs=-1
)
```

### 5. Evaluator (`src/evaluator.py`)

**Purpose**: Comprehensive model evaluation

**Responsibilities**:
- Calculate metrics (accuracy, precision, recall, F1)
- Generate confusion matrix
- ROC curve and AUC
- Per-attack-type accuracy
- Save visualizations

**Metrics Tracked**:
- Overall accuracy
- True Positives / True Negatives
- False Positives (false alarms)
- False Negatives (missed attacks)
- Attack detection rate by type

### 6. Explainer (`src/explainer.py`)

**Purpose**: Generate XAI explanations

**Responsibilities**:
- Setup SHAP TreeExplainer
- Setup LIME TabularExplainer
- Generate per-sample explanations
- Create plain English summaries
- Compare SHAP vs LIME

**XAI Methods**:
```
SHAP (TreeExplainer)     - Feature contribution values
LIME (TabularExplainer)  - Local linear approximation rules
```

### 7. Classifier (`src/classifier.py`)

**Purpose**: Classify new data samples

**Responsibilities**:
- Load and preprocess new CSV files
- Generate predictions
- Auto-explain attack detections
- Save classification results

### 8. HTML Report Generator (`src/html_report.py`)

**Purpose**: Generate professional HTML reports

**Responsibilities**:
- Export XAI explanations as HTML
- Create visual representations
- Generate executive summaries
- Save to outputs/reports/

---

## Data Flow Diagram

```
+===========================================================================+
|                            DATA FLOW                                       |
+===========================================================================+

1. TRAINING PHASE:

   CIC-IDS2017 CSV Files
          |
          v
   +----------------+
   |  DataLoader    |  --> Chunk reading, cleaning
   +----------------+
          |
          v
   +----------------+
   |  Preprocessor  |  --> Feature selection, scaling
   +----------------+
          |
          v
   +----------------+
   |  ModelTrainer  |  --> Random Forest training
   +----------------+
          |
          v
   +----------------+
   |  Saved Model   |  --> models/nids_model.joblib
   +----------------+

2. CLASSIFICATION PHASE:

   New CSV File (or PCAP --> CSV)
          |
          v
   +----------------+
   |  Preprocessor  |  --> Transform with saved scaler
   +----------------+
          |
          v
   +----------------+
   |  Classifier    |  --> Predict (Benign/Attack)
   +----------------+
          |
          v
   +----------------+
   |  Explainer     |  --> SHAP + LIME explanations
   +----------------+
          |
          v
   +----------------+
   |  HTML Report   |  --> Professional report output
   +----------------+
```

---

## PCAP Processing Pipeline

```
+===========================================================================+
|                     PCAP TO CLASSIFICATION PIPELINE                        |
+===========================================================================+

   [Kali Linux VM]          [Target VM]           [Capture Point]
         |                       |                       |
         +-------ATTACK--------->|                       |
                                 |<----CAPTURE----------+
                                 |
                                 v
                        +----------------+
                        |   PCAP File    |
                        +----------------+
                                 |
                                 v
                        +----------------+
                        | pcap_to_csv.py |  --> Extract network flows
                        +----------------+      Calculate features
                                 |
                                 v
                        +----------------+
                        |   CSV File     |  --> CIC-IDS2017 format
                        +----------------+
                                 |
                                 v
                        +----------------+
                        |  NIDS-XAI      |  --> Classification
                        +----------------+
                                 |
                                 v
                        +----------------+
                        |  Detection +   |  --> Attack/Benign +
                        |  Explanation   |      XAI explanation
                        +----------------+
```

---

## Feature Extraction

The PCAP converter extracts 78 features matching CIC-IDS2017 format:

```
+-----------------------------+-----------------------------+
|     FORWARD FEATURES        |     BACKWARD FEATURES       |
+-----------------------------+-----------------------------+
| Total Fwd Packets           | Total Backward Packets      |
| Fwd Packet Length Max/Min   | Bwd Packet Length Max/Min   |
| Fwd Packet Length Mean/Std  | Bwd Packet Length Mean/Std  |
| Fwd IAT Total/Mean/Std      | Bwd IAT Total/Mean/Std      |
| Fwd PSH/URG Flags           | Bwd PSH/URG Flags           |
| Fwd Header Length           | Bwd Header Length           |
| Fwd Packets/s               | Bwd Packets/s               |
+-----------------------------+-----------------------------+
|                FLOW FEATURES                              |
+-----------------------------------------------------------+
| Flow Duration               | Flow Bytes/s                |
| Flow Packets/s              | Flow IAT Mean/Std/Max/Min   |
| SYN/ACK/FIN/RST/PSH Flag Counts                          |
| Init Window Bytes (Fwd/Bwd)                               |
| Active/Idle Mean/Std/Max/Min                              |
+-----------------------------------------------------------+
```

---

## XAI Explanation Architecture

```
+===========================================================================+
|                      XAI EXPLANATION FLOW                                  |
+===========================================================================+

                    +-------------------+
                    |   Sample Input    |
                    |   (1 network flow)|
                    +-------------------+
                            |
           +----------------+----------------+
           |                                 |
           v                                 v
   +----------------+               +----------------+
   |     SHAP       |               |     LIME       |
   | TreeExplainer  |               | TabularExplain |
   +----------------+               +----------------+
           |                                 |
           v                                 v
   +----------------+               +----------------+
   | SHAP Values    |               | Local Rules    |
   | (per feature)  |               | (if-then)      |
   +----------------+               +----------------+
           |                                 |
           +----------------+----------------+
                            |
                            v
                    +-------------------+
                    |  Combined Report  |
                    +-------------------+
                    | - Feature contrib |
                    | - Rule conditions |
                    | - Plain English   |
                    +-------------------+
```

---

## Directory Structure

```
nids_xai_projectv2/
|
+-- README.md                    # Project documentation
+-- ARCHITECTURE.md              # This file
+-- TESTING.md                   # Testing guide
|
+-- nids_xai/
    |
    +-- main.py                  # Main application entry
    +-- quick_start.py           # Setup verification script
    +-- requirements.txt         # Dependencies
    |
    +-- config/
    |   +-- config.py            # All configuration
    |
    +-- src/
    |   +-- data_loader.py       # CSV loading
    |   +-- preprocessor.py      # Data preprocessing
    |   +-- model_trainer.py     # Model training
    |   +-- evaluator.py         # Evaluation metrics
    |   +-- explainer.py         # SHAP + LIME
    |   +-- classifier.py        # New data classification
    |   +-- html_report.py       # Report generation
    |   +-- utils.py             # Utilities
    |
    +-- tools/
    |   +-- pcap_to_csv.py       # PCAP conversion
    |   +-- test_helpers.py      # Testing utilities
    |
    +-- data/
    |   +-- raw/                 # Original CSV files
    |   +-- processed/           # Preprocessed data
    |
    +-- models/                  # Saved models
    +-- outputs/                 # Results and plots
    |   +-- reports/             # HTML reports
    +-- logs/                    # Application logs
```

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Language | Python 3.8+ | Core development |
| ML Framework | scikit-learn | Random Forest, preprocessing |
| XAI - SHAP | shap | Shapley value explanations |
| XAI - LIME | lime | Local interpretable models |
| Data Processing | pandas, numpy | Data manipulation |
| Visualization | matplotlib, seaborn | Plots and charts |
| Packet Analysis | scapy | PCAP processing |
| Serialization | joblib | Model persistence |

---

## Security Considerations

1. **Data Privacy**: IP addresses and identifiers are removed during preprocessing
2. **Model Security**: Trained models are stored locally, not transmitted
3. **Input Validation**: CSV/PCAP inputs are validated before processing
4. **No Network Access**: The system operates entirely offline

---

## Performance Characteristics

| Operation | Typical Time | Memory Usage |
|-----------|--------------|--------------|
| Data Loading (all files) | 5-10 minutes | 4-8 GB |
| Preprocessing | 2-5 minutes | 2-4 GB |
| Training | 2-5 minutes | 1-2 GB |
| Single Classification | <1 second | <100 MB |
| SHAP Explanation | ~0.1 seconds | <200 MB |
| LIME Explanation | ~0.5 seconds | <200 MB |

---

## Extension Points

The architecture supports extension in several ways:

1. **New Classifiers**: Replace Random Forest in `model_trainer.py`
2. **Additional XAI Methods**: Add to `explainer.py`
3. **New Attack Types**: Update `config.py` mappings
4. **Different Datasets**: Modify `data_loader.py` for new formats
5. **Real-time Processing**: Add streaming support to `classifier.py`

---

*Document Version: 1.0*
*Last Updated: January 2026*
