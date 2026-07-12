# Test CSVs for the Classify page

Upload any of these on the **Classify** page to demonstrate flow classification
and the SHAP explanations.

## Recommended demo file (detects + measurable accuracy)

- **`cicids2017_portscan_mixed_3000.csv`** — 3,000 labelled CIC-IDS2017 flows
  (1,500 Port Scan attacks + 1,500 benign). Because it carries a `Label` column,
  the Classify page reports accuracy / precision / recall / F1 and a confusion
  matrix. Expected: ~99% accuracy, ~100% recall. **Use this to show detection
  working with a measurable result.**

## Real packet captures (`live_captures/`)

CSV flows extracted with **NFStream** from the Wireshark/PCAP DoS captures
(SYN flood, amplification, port scan, etc.). These now classify without error,
but most read **Benign**. Two reasons:

1. NFStream is a different feature extractor than the CICFlowMeter the model was
   trained on, and it does not compute the `Idle*` / `Fwd IAT Total` features
   (those are zero-filled).
2. The CIC-IDS2017 model does not generalise to traffic captured on different
   tooling — the documented dataset generalisation gap.

They are useful for *showing the pipeline accepts real captures* and for
discussing that gap, not for demonstrating detection. For a live detection
demo, use the Dashboard's **Demo replay** button or the labelled sample above.
