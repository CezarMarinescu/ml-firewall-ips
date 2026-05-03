"""Re-label an existing flows.csv using the attack manifest.

Useful for testing the manifest labeler without re-collecting data.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from src.flow_features import label_flows_from_manifest

FLOWS_PATH    = Path(__file__).parent.parent / "data" / "flows.csv"
MANIFEST_PATH = Path(__file__).parent.parent / "data" / "attack_manifest.json"
OUTPUT_PATH   = Path(__file__).parent.parent / "data" / "flows_labeled.csv"


def main():
    df = pd.read_csv(FLOWS_PATH)
    print(f"Loaded {len(df)} flows from {FLOWS_PATH.name}")

    df = label_flows_from_manifest(df, MANIFEST_PATH)

    print("\n=== Manifest-based label distribution ===")
    print(df["label"].value_counts())
    print("\n=== Attack type distribution ===")
    print(df["attack_type"].value_counts())

    # Show the flows that matched the manifest
    if (df["label"] == 1).any():
        print("\n=== Matched malicious flows ===")
        cols = ["src_ip", "window_start", "n_packets",
                "unique_dst_ports", "syn_only_ratio", "attack_type"]
        print(df[df["label"] == 1][cols].to_string(index=False))
    else:
        print("\nWARNING: no flows matched the manifest!")
        print("Possible causes:")
        print("  - Attack happened but log collection ran before packets were written")
        print("  - Server clock vs flow timestamp drift")
        print("  - Attacker IP mismatch (Kali had different IP than expected)")

    df.to_csv(OUTPUT_PATH, index=False)
    print(f"\nSaved to {OUTPUT_PATH.name}")


if __name__ == "__main__":
    main()