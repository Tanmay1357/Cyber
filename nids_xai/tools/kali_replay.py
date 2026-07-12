#!/usr/bin/env python3
"""
Run on the Kali VM. Sends a CIC-IDS CSV to the host NIDS over the host-only
network, so the host detects and explains the flows live on its dashboard.

This feeds the dataset's flows (in-distribution data the model detects), which is
why detection works - unlike replaying raw packets, which the host would read as
benign because of the feature-extraction gap.

Setup once on Kali:   pip3 install requests
On the host:          run the API with  uvicorn api.main:app --host 0.0.0.0 --port 8000
                      and allow port 8000 through the Windows firewall.

Usage:
    python3 kali_replay.py <host_ip> <csv_file> [rate] [model]

Example (host-only IP of the host is usually 192.168.179.1):
    python3 kali_replay.py 192.168.179.1 portscan.csv 0.6 2017
"""
import sys

try:
    import requests
except ImportError:
    sys.exit("Missing dependency. Run:  pip3 install requests")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    host = sys.argv[1]
    csv_path = sys.argv[2]
    rate = sys.argv[3] if len(sys.argv) > 3 else "0.6"
    model = sys.argv[4] if len(sys.argv) > 4 else ""

    url = f"http://{host}:8000/api/monitor/ingest"
    params = {"rate": rate}
    if model:
        params["model"] = model

    print(f"[*] Sending {csv_path} to {url} (rate={rate}s/flow"
          + (f", model={model}" if model else "") + ") ...")
    try:
        with open(csv_path, "rb") as f:
            resp = requests.post(url, files={"file": (csv_path, f, "text/csv")},
                                 params=params, timeout=600)
    except FileNotFoundError:
        sys.exit(f"[!] CSV not found: {csv_path}")
    except requests.exceptions.ConnectionError:
        sys.exit(f"[!] Could not reach the host at {host}:8000. "
                 "Check the host-only IP, that the API runs with --host 0.0.0.0, "
                 "and the Windows firewall allows port 8000.")

    if resp.status_code == 200:
        data = resp.json()
        print(f"[+] OK - {data.get('queued')} flows queued from {data.get('source')}. "
              "Watch the host dashboard: they stream in as live detections with explanations.")
    else:
        print(f"[!] Host returned {resp.status_code}: {resp.text}")


if __name__ == "__main__":
    main()
