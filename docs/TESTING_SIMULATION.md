# Simulation-Based Testing Guide

## Overview

This guide explains how to test your NIDS using **simulated attack traffic** instead of real attacks. This approach is:
- ✅ Safer and ethical
- ✅ Fully reproducible
- ✅ Acceptable for academic FYP submissions
- ✅ Demonstrates all system capabilities

## Testing Strategy

Your NIDS will be tested using **three complementary approaches**:

### 1. Dataset-Based Testing (Primary Method)
Use the CIC-IDS2017 dataset which contains pre-recorded attack captures from a controlled lab environment.

### 2. Synthetic Traffic Generation (Secondary Method)
Generate realistic simulated attack patterns programmatically.

### 3. End-to-End Workflow Demonstration (Tertiary Method)
Show the complete PCAP → CSV → Detection → XAI pipeline using simulated data.

---

## Method 1: Dataset-Based Testing (Recommended)

### Why This Works
The CIC-IDS2017 dataset contains **real attacks captured in a lab environment** - this IS simulation-based testing because:
- Attacks were executed in an isolated network
- Traffic was pre-recorded for analysis
- You're replaying the captures, not running live attacks
- It's the industry-standard approach for NIDS research

### How to Use

**Step 1: Load the Dataset**
```bash
cd nids_xai
python main.py
# Select: 1. Load & Preprocess Data
```

**Step 2: Train Model**
```bash
# Select: 3. Train Model
```

**Step 3: Evaluate Performance**
```bash
# Select: 4. Evaluate Model
# This gives you overall metrics
```

**Step 4: Test Specific Attack Types**
```bash
# Select: 5. Test & Explain Predictions
# Choose: 2. Test attack samples only
```

This will show:
- Detection results for various attacks
- SHAP explanations (global + local)
- LIME explanations
- Prediction confidence

**Step 5: Document Results for Chapter 5**

For each attack type in the dataset, document:

| Attack Type | Samples Tested | Detected | Missed | Accuracy | Key Features (from SHAP) |
|------------|----------------|----------|--------|----------|--------------------------|
| Port Scan | 100 | 98 | 2 | 98% | Dst Port, SYN Flag Count |
| SSH Brute Force | 50 | 48 | 2 | 96% | Fwd Packets/s, Flow Duration |
| DoS Slowloris | 75 | 72 | 3 | 96% | Flow Duration, Bwd IAT |

---

## Method 2: Synthetic Traffic Generation

### Generate Simulated PCAPs

**Step 1: Install scapy (if needed)**
```bash
pip install scapy
```

**Step 2: Generate Attack Simulations**
```bash
cd nids_xai
python -m tools.generate_attack_pcaps
```

This creates simulated PCAP files for:
- Port Scan (500 ports scanned)
- SSH Brute Force (30 failed attempts)
- DoS Slowloris (50 slow connections)
- DoS Hulk (200 HTTP flood requests)
- Benign Traffic (30 normal connections)

**Output:** `examples/simulated_attacks/*.pcap`

### Convert to CSV

```bash
# Convert each PCAP
python -m tools.pcap_to_csv \
    --input examples/simulated_attacks/port_scan.pcap \
    --output examples/simulated_attacks/port_scan.csv

python -m tools.pcap_to_csv \
    --input examples/simulated_attacks/ssh_brute_force.pcap \
    --output examples/simulated_attacks/ssh_brute_force.csv

# ... repeat for other attack types
```

### Classify Simulated Attacks

```bash
python main.py
# Select: 6. Classify New CSV File
# Enter path: examples/simulated_attacks/port_scan.csv
```

The system will:
1. Load the CSV
2. Preprocess features
3. Make predictions
4. Generate XAI explanations
5. Save HTML report to `outputs/reports/`

---

## Method 3: Direct CSV Generation (Fastest)

If you don't want to deal with PCAPs, generate CSV directly:

```bash
cd nids_xai/examples
python generate_sample_data.py
```

This creates:
- `sample_flows.csv` - Mixed benign and attack traffic
- `sample_benign.csv` - Normal traffic only
- `sample_attacks.csv` - Attack traffic only

Then classify:
```bash
cd ..
python main.py
# Select: 6. Classify New CSV File
# Enter: examples/sample_attacks.csv
```

---

## Complete Testing Workflow for Chapter 5

### Test Scenario 1: Port Scan Detection

**Objective:** Demonstrate detection of network reconnaissance

**Simulation Method:** Use CIC-IDS2017 port scan samples OR generate synthetic

**Procedure:**
1. Load port scan traffic (from dataset or synthetic)
2. Run classification
3. Capture detection result
4. Analyze XAI explanation
5. Screenshot results

**Expected Results:**
- Detection Rate: 95-99%
- Key SHAP Features: Destination Port Variability, SYN Flag Count
- LIME Explanation: "High number of SYN packets to different ports"

**Documentation:**
```
Test 1: Port Scan Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Simulation: 500-port nmap scan (simulated)
Detection: ✓ ATTACK (Confidence: 97.3%)

SHAP Top Features:
1. Destination Port [+0.45] - Multiple ports targeted
2. SYN Flag Count [+0.38] - High SYN, low ACK
3. Flow Duration [-0.22] - Very short connections

LIME Explanation:
The system detected malicious activity because:
- 500 different destination ports were accessed
- 95% of packets had SYN flag without completion
- Average flow duration was 0.03 seconds

Conclusion: Successfully detected port scan with high confidence
```

### Test Scenario 2: Brute Force Detection

**Objective:** Demonstrate detection of authentication attacks

**Simulation Method:** SSH brute force samples

**Procedure:**
1. Load SSH brute force traffic
2. Run classification
3. Generate XAI report
4. Analyze feature importance

**Expected Results:**
- Detection Rate: 92-98%
- Key Features: Failed Login Attempts, Port 22 Activity
- Clear explanation of repeated connection pattern

### Test Scenario 3: DoS Detection

**Objective:** Demonstrate detection of denial-of-service

**Simulation Method:** Slowloris or Hulk samples

**Procedure:**
1. Load DoS traffic
2. Classify
3. Export HTML report
4. Compare SHAP vs LIME explanations

**Expected Results:**
- Slowloris: High flow duration, low packet rate
- Hulk: High packet rate, same destination

### Test Scenario 4: Benign Traffic Verification

**Objective:** Verify low false positive rate

**Procedure:**
1. Load normal traffic samples
2. Classify
3. Document any false alarms
4. Analyze reasons for misclassification

**Expected Results:**
- True Negative Rate: >95%
- False Positives: <5%

---

## Documenting Results for Your FYP Report

### Chapter 5 Structure

```
5.1 Dataset-Based Testing
    5.1.1 CIC-IDS2017 Performance
    5.1.2 Confusion Matrix Analysis
    5.1.3 ROC-AUC Curves

5.2 Simulated Attack Testing
    5.2.1 Port Scan Simulation
          - Methodology
          - Results
          - XAI Analysis
    5.2.2 Brute Force Simulation
          - Methodology
          - Results
          - XAI Analysis
    5.2.3 DoS Simulation
          - Methodology
          - Results
          - XAI Analysis
    5.2.4 Benign Traffic Verification

5.3 XAI Explanation Quality
    5.3.1 SHAP Feature Importance
    5.3.2 LIME Local Explanations
    5.3.3 Comparison and Validation

5.4 Performance Summary
    5.4.1 Detection Accuracy by Attack Type
    5.4.2 False Positive/Negative Analysis
    5.4.3 Computational Performance

5.5 Limitations and Observations
```

### Screenshots to Include

1. **System Training**
   - Progress during data loading
   - Model training output
   - Feature importance visualization

2. **Detection Results**
   - Classification output for each attack type
   - Confusion matrix
   - ROC curves

3. **XAI Explanations**
   - SHAP summary plot
   - SHAP force plot for specific detection
   - LIME explanation output
   - HTML report screenshots

4. **End-to-End Workflow**
   - PCAP → CSV conversion
   - CSV classification
   - Report generation

---

## Key Advantages of Simulation-Based Testing

1. **Reproducibility**
   - Same results every time
   - Easy to demonstrate in FYP presentation
   - Supervisor can verify

2. **Safety**
   - No real network attacks
   - No security risks
   - No ethical concerns

3. **Completeness**
   - Test all attack types systematically
   - Controlled conditions
   - Easier to document

4. **Academic Validity**
   - Standard approach in NIDS research
   - Uses established benchmark datasets
   - Demonstrates technical understanding

---

## Frequently Asked Questions

### Q: Is simulation-based testing acceptable for FYP?
**A:** Yes! Most academic NIDS projects use datasets and simulations. Real attacks would raise ethical concerns.

### Q: How do I explain this in my report?
**A:**
"Testing was conducted using simulation-based approaches including the CIC-IDS2017 benchmark dataset and synthetically generated attack patterns. This methodology aligns with industry-standard NIDS research practices and provides controlled, reproducible results while avoiding ethical concerns associated with live attack execution."

### Q: What's the difference between my approach and real attacks?
**A:** The detection mechanism is IDENTICAL. You're testing the same features, patterns, and ML model. The only difference is the traffic source (pre-recorded vs live).

### Q: Can I still use the PCAP conversion tool?
**A:** Yes! Use it to demonstrate the end-to-end workflow with simulated PCAPs.

### Q: How many tests should I run?
**A:** Aim for:
- 5-7 different attack types
- 50-100 samples per attack type
- 100+ benign samples for false positive testing

---

## Summary

Your NIDS testing strategy:

```
┌─────────────────────────────────────────────────────────┐
│  PRIMARY: CIC-IDS2017 Dataset Testing                   │
│  ✓ Real attack captures in controlled environment      │
│  ✓ Multiple attack types                               │
│  ✓ Thousands of samples                                │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│  SECONDARY: Synthetic Traffic Generation                │
│  ✓ Programmatically created attack patterns            │
│  ✓ Demonstrates technical understanding                │
│  ✓ Customizable scenarios                              │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│  VALIDATION: XAI Explanation Analysis                   │
│  ✓ SHAP global/local importance                        │
│  ✓ LIME instance explanations                          │
│  ✓ HTML reports for documentation                      │
└─────────────────────────────────────────────────────────┘
```

This comprehensive testing approach will satisfy your supervisor while demonstrating all system capabilities!
