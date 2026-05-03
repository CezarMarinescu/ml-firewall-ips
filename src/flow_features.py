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

def label_flows_from_manifest(flows_df: pd.DataFrame,
                              attack_manifest_path,
                              benign_manifest_path=None,
                              buffer_seconds: int = 5,
                              window_seconds: int = 60) -> pd.DataFrame:
    """
    Label flows using ground-truth manifests instead of heuristics.

    A flow is labeled malicious (1) if it overlaps with an attack manifest
    entry whose attacker_ip matches.

    A flow is given an explicit benign label and traffic_type when it
    overlaps with a benign manifest entry — these are KNOWN-good active
    sessions (SSH, HTTP, file transfer, etc).

    Flows that match neither manifest stay as label=0 / attack_type='benign_idle'.

    When multiple entries touch the same window, the one with greatest
    time-overlap wins. All matches are recorded in `all_attack_types`
    (or `all_traffic_types` for benign) for debugging.

    Adds columns:
      - label             : 0 or 1
      - attack_type       : primary attack type, or 'benign_active' / 'benign_idle'
      - traffic_type      : for benign-active flows, the specific kind
                            (ssh_session, http_get, ping_burst, file_xfer, dns_query, mixed)
      - all_attack_types  : ;-separated list of overlapping attacks
      - all_traffic_types : ;-separated list of overlapping benign sessions
    """
    import json
    from datetime import datetime, timedelta

    if flows_df.empty:
        return flows_df

    # Load attack manifest (required)
    with open(attack_manifest_path) as f:
        attack_records = json.load(f)

    # Load benign manifest (optional — Phase 2D adds this)
    benign_records = []
    if benign_manifest_path is not None:
        try:
            with open(benign_manifest_path) as f:
                benign_records = json.load(f)
        except FileNotFoundError:
            pass  # benign manifest not yet generated — that's OK

    df = flows_df.copy()
    df["window_start"] = pd.to_datetime(df["window_start"])
    df["window_end"]   = df["window_start"] + pd.Timedelta(seconds=window_seconds)

    df["label"] = 0
    df["attack_type"] = "benign_idle"
    df["traffic_type"] = ""
    df["all_attack_types"] = ""
    df["all_traffic_types"] = ""

    def _parse_records(records, type_field):
        parsed = []
        for rec in records:
            parsed.append({
                "type":     rec[type_field],
                "src_ip":   rec.get("attacker_ip") or rec.get("source_ip"),
                "ts_start": datetime.fromisoformat(rec["start_ts"]) - timedelta(seconds=buffer_seconds),
                "ts_end":   datetime.fromisoformat(rec["end_ts"])   + timedelta(seconds=buffer_seconds),
            })
        return parsed

    parsed_attacks = _parse_records(attack_records, "attack_type")
    parsed_benign  = _parse_records(benign_records, "traffic_type")

    for idx, row in df.iterrows():
        win_start = row["window_start"]
        win_end   = row["window_end"]
        src_ip    = row["src_ip"]

        # Find all overlapping attacks
        attack_matches = []
        for rec in parsed_attacks:
            if rec["src_ip"] != src_ip:
                continue
            overlap = (min(win_end, rec["ts_end"]) - max(win_start, rec["ts_start"])).total_seconds()
            if overlap > 0:
                attack_matches.append((rec["type"], overlap))

        # Find all overlapping benign-active sessions
        benign_matches = []
        for rec in parsed_benign:
            if rec["src_ip"] != src_ip:
                continue
            overlap = (min(win_end, rec["ts_end"]) - max(win_start, rec["ts_start"])).total_seconds()
            if overlap > 0:
                benign_matches.append((rec["type"], overlap))

        if attack_matches:
            attack_matches.sort(key=lambda x: x[1], reverse=True)
            df.at[idx, "label"] = 1
            df.at[idx, "attack_type"] = attack_matches[0][0]
            df.at[idx, "all_attack_types"] = ";".join(m[0] for m in attack_matches)

        if benign_matches:
            benign_matches.sort(key=lambda x: x[1], reverse=True)
            df.at[idx, "traffic_type"] = benign_matches[0][0]
            df.at[idx, "all_traffic_types"] = ";".join(m[0] for m in benign_matches)
            # If not also flagged malicious, mark as benign_active
            if not attack_matches:
                df.at[idx, "attack_type"] = "benign_active"

    df = df.drop(columns=["window_end"])
    return df