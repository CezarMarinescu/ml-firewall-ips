"""
Aggregate raw packet records into per-IP time-windowed flow features.

A 'flow' here = all packets from one source IP within one time window.
Default window = 60 seconds.
"""
import pandas as pd


# Map protocol names to IANA numbers (standard)
PROTOCOL_MAP = {"ICMP": 1, "TCP": 6, "UDP": 17}


def packets_to_dataframe(packet_records: list) -> pd.DataFrame:
    """Convert list of parsed packet dicts into a clean DataFrame."""
    if not packet_records:
        return pd.DataFrame()

    df = pd.DataFrame(packet_records)

    # Drop rows without a timestamp — we can't window them
    df = df.dropna(subset=["timestamp"])

    # Numeric protocol code for ML; keep original name for grouping/debugging
    df["protocol_num"] = df["protocol"].map(PROTOCOL_MAP).fillna(0).astype(int)

    return df


def build_flows(df: pd.DataFrame, window_seconds: int = 60) -> pd.DataFrame:
    """
    Group packets into (src_ip, time_window) flows and compute features.

    Returns one row per flow with behavioral features that describe
    HOW the IP behaved during that window — not what individual packets were.
    """
    if df.empty:
        return pd.DataFrame()

    df = df.copy()
    df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")

    flows = []
    for (src_ip, window), group in df.groupby(["src_ip", "window_start"]):
        flows.append(_compute_flow_features(src_ip, window, group, window_seconds))

    return pd.DataFrame(flows)


def _compute_flow_features(src_ip: str, window_start, packets: pd.DataFrame,
                           window_seconds: int) -> dict:
    """Compute behavioral features for one (src_ip, window) group of packets."""
    n_packets = len(packets)

    time_span = (packets["timestamp"].max() - packets["timestamp"].min()).total_seconds()
    time_span = max(time_span, 1.0)

    # --- Volume features ---
    packets_per_sec = n_packets / time_span
    total_bytes = packets["length"].sum()
    avg_packet_size = packets["length"].mean()
    std_packet_size = packets["length"].std() if n_packets > 1 else 0.0

    # --- Diversity features (the big tells for port scans) ---
    unique_dst_ports = packets["dst_port"].nunique()
    unique_src_ports = packets["src_port"].nunique()
    unique_protocols = packets["protocol"].nunique()
    unique_dst_ips   = packets["dst_ip"].nunique() if "dst_ip" in packets else 1

    # --- TCP flag features ---
    syn_count = packets.get("flag_syn", pd.Series([0])).sum()
    ack_count = packets.get("flag_ack", pd.Series([0])).sum()
    fin_count = packets.get("flag_fin", pd.Series([0])).sum()
    rst_count = packets.get("flag_rst", pd.Series([0])).sum()

    syn_ratio = syn_count / n_packets
    syn_only_count = ((packets.get("flag_syn", 0) == 1) &
                      (packets.get("flag_ack", 0) == 0)).sum()
    syn_only_ratio = syn_only_count / n_packets

    # --- Protocol mix ---
    proto_counts = packets["protocol"].value_counts()
    tcp_ratio  = proto_counts.get("TCP", 0)  / n_packets
    udp_ratio  = proto_counts.get("UDP", 0)  / n_packets
    icmp_ratio = proto_counts.get("ICMP", 0) / n_packets

    # --- Targeting features ---
    common_ports = {22, 80, 443, 21, 25, 53, 110, 143, 3306, 3389, 8080, 8443}
    common_port_hits = packets["dst_port"].isin(common_ports).sum()
    common_port_ratio = common_port_hits / n_packets

    dst_port_std = packets["dst_port"].std() if n_packets > 1 else 0.0

    return {
        "src_ip": src_ip,
        "window_start": window_start,
        "n_packets": n_packets,
        "packets_per_sec": packets_per_sec,
        "total_bytes": total_bytes,
        "avg_packet_size": avg_packet_size,
        "std_packet_size": std_packet_size,
        "unique_dst_ports": unique_dst_ports,
        "unique_src_ports": unique_src_ports,
        "unique_protocols": unique_protocols,
        "unique_dst_ips": unique_dst_ips,
        "syn_ratio": syn_ratio,
        "syn_only_ratio": syn_only_ratio,
        "ack_ratio": ack_count / n_packets,
        "fin_ratio": fin_count / n_packets,
        "rst_ratio": rst_count / n_packets,
        "tcp_ratio": tcp_ratio,
        "udp_ratio": udp_ratio,
        "icmp_ratio": icmp_ratio,
        "common_port_ratio": common_port_ratio,
        "dst_port_std": dst_port_std,
    }


def label_flows_heuristic(flows_df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply a *temporary* heuristic label so we have ground truth for Phase 1.

    Heuristic: a flow is malicious (1) if ANY of these are true:
      - Touched > 20 unique destination ports in the window (port scan)
      - SYN-only ratio > 0.8 with > 10 packets (SYN scan / SYN flood)
      - Packets/sec > 50 (flooding)

    In Phase 2 we'll generate labeled data by knowing exactly when we ran
    each attack from Kali, which gives much cleaner ground truth.
    """
    if flows_df.empty:
        return flows_df

    df = flows_df.copy()
    is_port_scan = df["unique_dst_ports"] > 20
    is_syn_scan  = (df["syn_only_ratio"] > 0.8) & (df["n_packets"] > 10)
    is_flood     = df["packets_per_sec"] > 50

    df["label"] = (is_port_scan | is_syn_scan | is_flood).astype(int)
    return df

def label_flows_from_manifest(flows_df: pd.DataFrame, manifest_path,
                              buffer_seconds: int = 5,
                              window_seconds: int = 60) -> pd.DataFrame:
    """
    Label flows using ground-truth attack manifest instead of heuristics.

    A flow is labeled malicious (1) if its (src_ip, time_window) overlaps
    with any attack in the manifest (with buffer_seconds of slack).

    When multiple attacks touch the same window, we pick the one with the
    GREATEST time-overlap as the primary attack_type, and record all
    matching attack types in `all_attack_types` (semicolon-separated).
    This prevents silently dropping attacks when cooldowns are too short
    to cleanly separate them.

    Adds three new columns:
      - label (0/1)
      - attack_type    : primary (most-overlap) attack type, or "benign"
      - all_attack_types : semicolon-separated list of every attack
                           that touched this window (for debugging)
    """
    import json
    from datetime import datetime, timedelta

    if flows_df.empty:
        return flows_df

    with open(manifest_path) as f:
        records = json.load(f)

    df = flows_df.copy()
    df["window_start"] = pd.to_datetime(df["window_start"])
    df["window_end"]   = df["window_start"] + pd.Timedelta(seconds=window_seconds)

    df["label"] = 0
    df["attack_type"] = "benign"
    df["all_attack_types"] = ""

    # Pre-parse manifest into datetimes once
    parsed_records = []
    for rec in records:
        parsed_records.append({
            "atype":     rec["attack_type"],
            "attacker":  rec["attacker_ip"],
            "atk_start": datetime.fromisoformat(rec["start_ts"]) - timedelta(seconds=buffer_seconds),
            "atk_end":   datetime.fromisoformat(rec["end_ts"])   + timedelta(seconds=buffer_seconds),
        })

    # For each row, find ALL matching attacks and pick the one with greatest overlap
    for idx, row in df.iterrows():
        win_start = row["window_start"]
        win_end   = row["window_end"]
        src_ip    = row["src_ip"]

        matches = []  # list of (attack_type, overlap_seconds)
        for rec in parsed_records:
            if rec["attacker"] != src_ip:
                continue
            # Compute time-overlap between flow window and attack window
            overlap_start = max(win_start, rec["atk_start"])
            overlap_end   = min(win_end,   rec["atk_end"])
            overlap = (overlap_end - overlap_start).total_seconds()
            if overlap > 0:
                matches.append((rec["atype"], overlap))

        if matches:
            # Sort by overlap descending; pick first as primary
            matches.sort(key=lambda x: x[1], reverse=True)
            df.at[idx, "label"] = 1
            df.at[idx, "attack_type"] = matches[0][0]
            df.at[idx, "all_attack_types"] = ";".join(m[0] for m in matches)

    df = df.drop(columns=["window_end"])
    return df