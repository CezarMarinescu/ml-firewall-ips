"""Re-label an existing flows.csv using both attack and benign manifests."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from src.flow_features import label_flows_from_manifest

ROOT = Path(__file__).parent.parent
FLOWS_PATH    = ROOT / "data" / "flows.csv"
ATTACK_PATH   = ROOT / "data" / "attack_manifest.json"
BENIGN_PATH   = ROOT / "data" / "benign_manifest.json"
OUTPUT_PATH   = ROOT / "data" / "flows_labeled.csv"


def main():
    df = pd.read_csv(FLOWS_PATH)
    print(f"Loaded {len(df)} flows from {FLOWS_PATH.name}")

    df = label_flows_from_manifest(
        df,
        attack_manifest_path=ATTACK_PATH,
        benign_manifest_path=BENIGN_PATH,
    )

    print("\n=== Manifest-based label distribution ===")
    print(df["label"].value_counts())

    print("\n=== Attack/benign category distribution ===")
    print(df["attack_type"].value_counts())

    if (df["traffic_type"] != "").any():
        print("\n=== Benign-active traffic types ===")
        print(df[df["traffic_type"] != ""]["traffic_type"].value_counts())

    if (df["label"] == 1).any():
        print("\n=== Matched malicious flows ===")
        cols = ["src_ip", "window_start", "n_packets",
                "unique_dst_ports", "syn_only_ratio", "attack_type"]
        print(df[df["label"] == 1][cols].to_string(index=False))

    if (df["attack_type"] == "benign_active").any():
        print("\n=== Matched benign-active flows ===")
        cols = ["src_ip", "window_start", "n_packets",
                "tcp_ratio", "udp_ratio", "icmp_ratio", "traffic_type"]
        print(df[df["attack_type"] == "benign_active"][cols].to_string(index=False))

    df.to_csv(OUTPUT_PATH, index=False)
    print(f"\nSaved to {OUTPUT_PATH.name}")


if __name__ == "__main__":
    main()