"""
PCAP to CSV Converter for NIDS-XAI.

Converts network packet captures (PCAP/PCAPNG) into CIC-IDS-compatible CSV
files that can be classified by the NIDS model.

Conversion methods (tried in order):
  1. CICFlowMeter - produces exact CIC-IDS feature names (requires Java)
  2. NFStream      - Python-based, similar features, easy to install
  3. Error         - clear instructions provided if neither is available

Author: Final Year CS Project
"""

import subprocess
import sys
import os
import shutil
from pathlib import Path
from typing import Optional, Callable, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.utils import print_info, print_error, print_success, print_warning

# Common locations to search for CICFlowMeter
_CFM_EXECUTABLES = [
    "cfm",
    "CICFlowMeter",
    "cicflowmeter",
]

_CFM_PATHS = [
    Path("tools/CICFlowMeter/bin/cfm"),
    Path("tools/cfm"),
    Path("tools/CICFlowMeter"),
    Path("C:/CICFlowMeter/bin/cfm"),
    Path("C:/CICFlowMeter/bin/CICFlowMeter"),
    Path("C:/Program Files/CICFlowMeter/bin/cfm"),
]

_CFM_JARS = [
    Path("tools/CICFlowMeter.jar"),
    Path("tools/CICFlowMeter-3.0-SNAPSHOT.jar"),
    Path("C:/CICFlowMeter/CICFlowMeter-3.0-SNAPSHOT.jar"),
]

# NFStream column -> CIC-IDS column mapping
_NFSTREAM_COLUMN_MAP = {
    "bidirectional_duration_ms":   "Flow Duration",
    "src2dst_packets":             "Total Fwd Packets",
    "dst2src_packets":             "Total Backward Packets",
    "src2dst_bytes":               "Total Length of Fwd Packets",
    "dst2src_bytes":               "Total Length of Bwd Packets",
    "src2dst_max_ps":              "Fwd Packet Length Max",
    "src2dst_min_ps":              "Fwd Packet Length Min",
    "src2dst_mean_ps":             "Fwd Packet Length Mean",
    "src2dst_stddev_ps":           "Fwd Packet Length Std",
    "dst2src_max_ps":              "Bwd Packet Length Max",
    "dst2src_min_ps":              "Bwd Packet Length Min",
    "dst2src_mean_ps":             "Bwd Packet Length Mean",
    "dst2src_stddev_ps":           "Bwd Packet Length Std",
    "bidirectional_max_ps":        "Packet Length Max",
    "bidirectional_min_ps":        "Packet Length Min",
    "bidirectional_mean_ps":       "Packet Length Mean",
    "bidirectional_stddev_ps":     "Packet Length Std",
    "src2dst_max_piat_ms":         "Fwd IAT Max",
    "src2dst_min_piat_ms":         "Fwd IAT Min",
    "src2dst_mean_piat_ms":        "Fwd IAT Mean",
    "src2dst_stddev_piat_ms":      "Fwd IAT Std",
    "src2dst_sum_piat_ms":         "Fwd IAT Total",
    "dst2src_max_piat_ms":         "Bwd IAT Max",
    "dst2src_min_piat_ms":         "Bwd IAT Min",
    "dst2src_mean_piat_ms":        "Bwd IAT Mean",
    "dst2src_stddev_piat_ms":      "Bwd IAT Std",
    "dst2src_sum_piat_ms":         "Bwd IAT Total",
    "bidirectional_max_piat_ms":   "Flow IAT Max",
    "bidirectional_min_piat_ms":   "Flow IAT Min",
    "bidirectional_mean_piat_ms":  "Flow IAT Mean",
    "bidirectional_stddev_piat_ms": "Flow IAT Std",
    "src2dst_syn_packets":         "SYN Flag Count",
    "src2dst_fin_packets":         "FIN Flag Count",
    "src2dst_rst_packets":         "RST Flag Count",
    "src2dst_psh_packets":         "PSH Flag Count",
    "src2dst_ack_packets":         "ACK Flag Count",
    "src2dst_urg_packets":         "URG Flag Count",
    "protocol":                    "Protocol",
    "src2dst_first_seen_ms":       "Flow Start",
    "src_port":                    "Src Port",
    "dst_port":                    "Dst Port",
}


def _find_cicflowmeter() -> Optional[str]:
    """Return path/command to CICFlowMeter, or None if not found."""
    # Check PATH
    for name in _CFM_EXECUTABLES:
        found = shutil.which(name)
        if found:
            return found

    # Check known filesystem paths
    for path in _CFM_PATHS:
        if path.exists():
            return str(path)

    # Check jar files (needs Java)
    for jar in _CFM_JARS:
        if jar.exists():
            java = shutil.which("java")
            if java:
                return f'"{java}" -jar "{jar}"'

    # Check config override
    try:
        from config.config import CICFLOWMETER_PATH
        if CICFLOWMETER_PATH:
            p = Path(CICFLOWMETER_PATH)
            if p.exists():
                return str(p)
    except (ImportError, AttributeError):
        pass

    return None


def _nfstream_available() -> bool:
    """Return True if nfstream is importable."""
    try:
        import nfstream  # noqa: F401
        return True
    except ImportError:
        return False


def check_available_tools() -> dict:
    """
    Check which PCAP conversion tools are available on this system.

    Returns:
        {
          "cicflowmeter": path_string or None,
          "nfstream": True/False,
        }
    """
    return {
        "cicflowmeter": _find_cicflowmeter(),
        "nfstream": _nfstream_available(),
    }


# ---------------------------------------------------------------------------
# CICFlowMeter conversion
# ---------------------------------------------------------------------------

def convert_with_cicflowmeter(
    pcap_path: str,
    output_dir: str,
    progress_callback: Optional[Callable] = None,
) -> str:
    """
    Convert a PCAP file to CSV using CICFlowMeter.

    CICFlowMeter produces the exact same feature names as CIC-IDS2017/2018.

    Args:
        pcap_path: Path to the input PCAP file.
        output_dir: Directory where the output CSV will be written.
        progress_callback: Optional callback(value: float, status: str).

    Returns:
        Path to the generated CSV file.
    """
    cfm = _find_cicflowmeter()
    if not cfm:
        raise RuntimeError("CICFlowMeter not found. See instructions below.")

    pcap_path = Path(pcap_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if progress_callback:
        progress_callback(0.05, "Running CICFlowMeter...")

    print_info(f"CICFlowMeter: processing {pcap_path.name}...")

    # Build command
    if cfm.startswith('"') or " -jar " in cfm:
        cmd_str = f"{cfm} {pcap_path} {output_dir}"
        use_shell = True
    else:
        cmd_str = None
        cmd_list = [cfm, str(pcap_path), str(output_dir)]
        use_shell = False

    try:
        if use_shell:
            result = subprocess.run(
                cmd_str, shell=True, capture_output=True, text=True, timeout=300
            )
        else:
            result = subprocess.run(
                cmd_list, capture_output=True, text=True, timeout=300
            )
    except subprocess.TimeoutExpired:
        raise RuntimeError("CICFlowMeter timed out after 300 seconds.")

    if result.returncode != 0:
        raise RuntimeError(
            f"CICFlowMeter exited with code {result.returncode}.\n"
            f"stderr: {result.stderr[:500]}"
        )

    if progress_callback:
        progress_callback(0.9, "Locating output CSV...")

    # Find the generated CSV (newest .csv in output_dir)
    csv_files = sorted(output_dir.glob("*.csv"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not csv_files:
        raise RuntimeError(f"CICFlowMeter produced no CSV files in {output_dir}")

    output_csv = csv_files[0]
    if progress_callback:
        progress_callback(1.0, "CICFlowMeter conversion complete")

    print_success(f"CICFlowMeter: {output_csv.name} created")
    return str(output_csv)


# ---------------------------------------------------------------------------
# NFStream conversion
# ---------------------------------------------------------------------------

def convert_with_nfstream(
    pcap_path: str,
    output_path: str,
    progress_callback: Optional[Callable] = None,
) -> str:
    """
    Convert a PCAP file to CSV using NFStream.

    NFStream generates flow-level statistics similar to CIC-IDS features.
    Feature names are mapped to CIC-IDS equivalents where possible.

    Args:
        pcap_path: Path to the input PCAP file.
        output_path: Full path for the output CSV file.
        progress_callback: Optional callback(value: float, status: str).

    Returns:
        Path to the generated CSV file.
    """
    try:
        from nfstream import NFStreamer
    except ImportError:
        raise RuntimeError(
            "NFStream is not installed. Install it with: pip install nfstream"
        )

    import pandas as pd
    import numpy as np

    pcap_path = Path(pcap_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if progress_callback:
        progress_callback(0.05, "Starting NFStream analysis...")

    print_info(f"NFStream: processing {pcap_path.name}...")

    streamer = NFStreamer(
        source=str(pcap_path),
        statistical_analysis=True,
        idle_timeout=120,
        active_timeout=1800,
    )

    if progress_callback:
        progress_callback(0.3, "Collecting flows...")

    df = streamer.to_pandas()

    if df.empty:
        raise RuntimeError("NFStream produced no flows from the PCAP file.")

    if progress_callback:
        progress_callback(0.7, f"Mapping {len(df)} flows to CIC-IDS features...")

    # Rename columns to CIC-IDS names
    rename = {k: v for k, v in _NFSTREAM_COLUMN_MAP.items() if k in df.columns}
    df = df.rename(columns=rename)

    # Derive additional CIC-IDS features
    eps = 1e-9  # avoid division by zero
    duration_s = df.get("Flow Duration", pd.Series(0.0, index=df.index)) / 1000.0
    duration_s = duration_s.clip(lower=eps)

    fwd_bytes = df.get("Total Length of Fwd Packets", pd.Series(0.0, index=df.index))
    bwd_bytes = df.get("Total Length of Bwd Packets", pd.Series(0.0, index=df.index))
    fwd_pkts  = df.get("Total Fwd Packets",  pd.Series(0.0, index=df.index))
    bwd_pkts  = df.get("Total Backward Packets", pd.Series(0.0, index=df.index))
    total_pkts  = fwd_pkts + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes

    df["Flow Bytes/s"]      = total_bytes / duration_s
    df["Flow Packets/s"]    = total_pkts  / duration_s
    df["Fwd Packets/s"]     = fwd_pkts    / duration_s
    df["Bwd Packets/s"]     = bwd_pkts    / duration_s
    df["Down/Up Ratio"]     = bwd_bytes   / (fwd_bytes + eps)
    df["Average Packet Size"] = total_bytes / (total_pkts + eps)

    if "Packet Length Std" in df.columns:
        df["Packet Length Variance"] = df["Packet Length Std"] ** 2

    if "Fwd Packet Length Mean" in df.columns:
        df["Avg Fwd Segment Size"] = df["Fwd Packet Length Mean"]
    if "Bwd Packet Length Mean" in df.columns:
        df["Avg Bwd Segment Size"] = df["Bwd Packet Length Mean"]

    # Add unknown label column (no ground truth for new traffic)
    df["Label"] = "UNKNOWN"

    df.to_csv(output_path, index=False)

    if progress_callback:
        progress_callback(1.0, "NFStream conversion complete")

    print_success(f"NFStream: {len(df)} flows written to {output_path.name}")
    return str(output_path)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def convert_pcap_to_csv(
    pcap_path: str,
    output_dir: Optional[str] = None,
    progress_callback: Optional[Callable] = None,
) -> Tuple[str, str]:
    """
    Convert a PCAP/PCAPNG file to a CIC-IDS-compatible CSV.

    Tries CICFlowMeter first, then NFStream. Raises a descriptive
    RuntimeError if neither tool is available.

    Args:
        pcap_path: Path to the PCAP or PCAPNG file.
        output_dir: Directory to write the CSV (defaults to <pcap_dir>/converted/).
        progress_callback: Optional callback(value: float, status: str).

    Returns:
        (csv_path, method_used) tuple.
            csv_path    - absolute path to the generated CSV
            method_used - "CICFlowMeter" or "NFStream"

    Raises:
        FileNotFoundError: If the PCAP does not exist.
        RuntimeError: If no conversion tool is available.
    """
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_dir is None:
        output_dir = pcap_path.parent / "converted"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    output_csv = output_dir / f"{pcap_path.stem}_flows.csv"

    tools = check_available_tools()

    # --- Try CICFlowMeter ---
    if tools["cicflowmeter"]:
        try:
            csv = convert_with_cicflowmeter(
                str(pcap_path), str(output_dir), progress_callback
            )
            return csv, "CICFlowMeter"
        except Exception as e:
            print_warning(f"CICFlowMeter failed ({e}). Trying NFStream...")

    # --- Try NFStream ---
    if tools["nfstream"]:
        try:
            csv = convert_with_nfstream(
                str(pcap_path), str(output_csv), progress_callback
            )
            return csv, "NFStream"
        except Exception as e:
            print_warning(f"NFStream failed: {e}")

    # --- Neither available ---
    raise RuntimeError(
        "No PCAP conversion tool is available on this system.\n\n"
        "OPTION 1 — CICFlowMeter (recommended, produces exact CIC-IDS features):\n"
        "  Download: https://github.com/CanadianInstituteForCybersecurity/CICFlowMeter\n"
        "  • Install Java 8+ first\n"
        "  • Place the cfm executable (or CICFlowMeter-3.0-SNAPSHOT.jar) in:\n"
        "      nids_xai/tools/   OR   anywhere on your system PATH\n\n"
        "OPTION 2 — NFStream (easy Python install, slightly different features):\n"
        "  pip install nfstream\n\n"
        "OPTION 3 — Pre-convert manually:\n"
        "  Run CICFlowMeter on your PCAP outside this tool, then use\n"
        "  'Classify CSV' to classify the resulting CSV file."
    )
