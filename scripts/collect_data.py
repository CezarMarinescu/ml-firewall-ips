"""
Collect firewall logs from the server, aggregate into time-windowed flows,
label heuristically, and save a CSV ready for training.

Usage (from project root):
    python -m scripts.collect_data
"""
import sys
from pathlib import Path

# Add project root to path we can import from src/
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ssh_client import ssh_connection
from src.fw_parser import parse_fw_log
from src.flow_features import (
    packets_to_dataframe,
    build_flows,
    label_flows_heuristic,
)


WINDOW_SECONDS = 60
OUTPUT_PATH = Path(__file__).parent.parent / "data" / "flows.csv"


def fetch_raw_logs() -> list:
    """SSH to server and pull all FW_LOG lines from kern.log."""
    print("Connecting to server...")
    packets = []

    with ssh_connection() as ssh:
        cmd = "sudo grep -h 'FW_LOG' /var/log/kern.log /var/log/kern.log.1 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(cmd)

        for line in stdout:
            parsed = parse_fw_log(line)
            if parsed:
                packets.append(parsed)

    print(f"Parsed {len(packets)} FW_LOG packets from server.")
    return packets


def main():
    packet_records = fetch_raw_logs()
    if not packet_records:
        print("No FW_LOG entries found. Has the firewall LOG rule been active?")
        print("Run on the server: sudo iptables -A INPUT -j LOG --log-prefix 'FW_LOG: '")
        return

    raw_df = packets_to_dataframe(packet_records)
    print(f"DataFrame built: {len(raw_df)} rows after timestamp cleanup.")

    if raw_df.empty:
        print("\nERROR: All packets were dropped during timestamp parsing.")
        print("This usually means the kern.log timestamp format isn't recognized.")
        print("Check src/fw_parser.py:_extract_timestamp() and grab a sample line:")
        print("  ssh admin-ai@<server> \"sudo grep 'FW_LOG' /var/log/kern.log | head -1\"")
        return

    flows_df = build_flows(raw_df, window_seconds=WINDOW_SECONDS)
    print(f"Aggregated into {len(flows_df)} flows ({WINDOW_SECONDS}s windows).")

    if flows_df.empty:
        print("No flows produced — nothing to label or save.")
        return

    flows_df = label_flows_heuristic(flows_df)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    flows_df.to_csv(OUTPUT_PATH, index=False)

    print("\n=== Summary ===")
    print(f"Total flows:       {len(flows_df)}")
    print(f"Malicious (1):     {(flows_df['label'] == 1).sum()}")
    print(f"Benign    (0):     {(flows_df['label'] == 0).sum()}")
    print(f"Unique source IPs: {flows_df['src_ip'].nunique()}")
    print(f"Saved to:          {OUTPUT_PATH}")

    if (flows_df["label"] == 1).any():
        print("\n=== Malicious flows preview ===")
        cols = ["src_ip", "n_packets", "unique_dst_ports",
                "syn_only_ratio", "packets_per_sec"]
        print(flows_df[flows_df["label"] == 1][cols].to_string(index=False))

if __name__ == "__main__":
    main()