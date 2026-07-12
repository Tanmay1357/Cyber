# NIDS-XAI Examples

This directory contains example files and scripts demonstrating how to use the NIDS-XAI system.

## Contents

### Sample Data Files

Since actual PCAP files containing attack traffic should not be distributed, this directory contains:

1. **sample_flows.csv** - A small CSV file with example network flow data
2. **generate_sample_data.py** - Script to generate synthetic test data

### Usage Examples

#### 1. Generate Sample Data

```bash
cd examples
python generate_sample_data.py
```

This creates `sample_flows.csv` with synthetic network flow data for testing.

#### 2. Test Classification

```bash
cd ..
python main.py
# Select option 6
# Enter path: examples/sample_flows.csv
```

#### 3. Generate HTML Report

```python
from src.html_report import HTMLReportGenerator

# After setting up explainer
generator = HTMLReportGenerator(explainer)
report_path = generator.generate_report(X_test, y_test, n_samples=5)
print(f"Report saved to: {report_path}")
```

## Creating Your Own Test Data

### Option 1: Capture Real Traffic

```bash
# On Linux/macOS
sudo tcpdump -i eth0 -w my_capture.pcap

# Convert to CSV
python -m tools.pcap_to_csv --input my_capture.pcap --output my_data.csv
```

### Option 2: Use CIC-IDS2017 Subsets

Extract specific attack types from the full dataset:

```python
import pandas as pd

# Load a day's data
df = pd.read_csv('data/raw/Tuesday-WorkingHours.pcap_ISCX.csv')

# Filter for specific attack
ssh_attacks = df[df['Label'] == 'SSH-Patator']
ssh_attacks.to_csv('examples/ssh_attacks_sample.csv', index=False)
```

### Option 3: Use Synthetic Data

The `generate_sample_data.py` script creates realistic-looking but synthetic data for testing.

## Notes

- Sample data is for testing the system workflow only
- For accurate evaluation, use the full CIC-IDS2017 dataset
- Real attack detection should be tested with actual captured traffic
