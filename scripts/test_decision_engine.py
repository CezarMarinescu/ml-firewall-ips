"""
Smoke test for the decision engine — runs every labeled flow through both
models and prints a decision summary. No firewall side effects.

This is how we sanity-check the decision logic before letting it touch ipset.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from src.decision_engine import DecisionEngine, Verdict


ROOT = Path(__file__).parent.parent
RF_PATH       = ROOT / "data" / "models" / "rf_baseline"
IF_PATH       = ROOT / "data" / "models" / "iforest_baseline"
FLOWS_LABELED = ROOT / "data" / "flows_labeled.csv"

# CRITICAL: these IPs are NEVER blocked, no matter what the models say.
# Edit this list to match your lab — see the comments in main().
ALLOWLIST = [
    "127.0.0.1",       # loopback
    "192.168.56.1",    # Windows operator host (host-only adapter)
    "10.0.2.2",        # VirtualBox NAT host
    "10.0.2.3",        # VirtualBox NAT DNS
]


def main():
    print("=" * 60)
    print("Decision engine smoke test")
    print("=" * 60)

    df = pd.read_csv(FLOWS_LABELED)
    print(f"Loaded {len(df)} flows")

    engine = DecisionEngine.from_disk(
        rf_path=RF_PATH,
        if_path=IF_PATH,
        allowlist=ALLOWLIST,
        rf_confidence_threshold=0.85,
    )
    print(f"Allowlist: {sorted(ALLOWLIST)}")
    print(f"RF confidence threshold: {engine.rf_confidence_threshold}")
    print()

    # Run every flow through the engine
    decisions = [engine.decide(row) for row in df.to_dict("records")]

    # Aggregate stats
    verdict_counts = {v.value: 0 for v in Verdict}
    for d in decisions:
        verdict_counts[d.verdict.value] += 1

    print("=== Verdict distribution ===")
    for v, n in verdict_counts.items():
        print(f"  {v:>6}: {n}")

    # Cross-tab against ground truth
    print("\n=== Verdict × ground truth ===")
    by_label = {("benign", "ALLOW"): 0, ("benign", "WATCH"): 0, ("benign", "BLOCK"): 0,
                ("malicious", "ALLOW"): 0, ("malicious", "WATCH"): 0, ("malicious", "BLOCK"): 0}
    for d, row in zip(decisions, df.to_dict("records")):
        label = "malicious" if row["label"] == 1 else "benign"
        by_label[(label, d.verdict.value)] += 1

    print(f"  {'':<12} {'ALLOW':>6} {'WATCH':>6} {'BLOCK':>6}")
    for label in ("benign", "malicious"):
        print(f"  {label:<12} "
              f"{by_label[(label, 'ALLOW')]:>6} "
              f"{by_label[(label, 'WATCH')]:>6} "
              f"{by_label[(label, 'BLOCK')]:>6}")

    # Show a few example BLOCK decisions with full reasoning
    blocks = [d for d in decisions if d.verdict == Verdict.BLOCK]
    print(f"\n=== Sample BLOCK decisions ({len(blocks)} total) ===")
    for d in blocks[:5]:
        print(f"\n  {d.src_ip} @ {d.window_start}")
        print(f"    {d.reason}")
        print(f"    Top features: {d.top_features}")

    # Show any flows from the operator's IP (192.168.56.1) — should ALL be ALLOW
    print(f"\n=== Operator IP (192.168.56.1) flows — must all be ALLOW ===")
    operator_decisions = [d for d, row in zip(decisions, df.to_dict("records"))
                          if row["src_ip"] == "192.168.56.1"]
    operator_verdicts = {v.value: 0 for v in Verdict}
    for d in operator_decisions:
        operator_verdicts[d.verdict.value] += 1
    for v, n in operator_verdicts.items():
        print(f"  {v:>6}: {n}")

    if operator_verdicts["BLOCK"] > 0 or operator_verdicts["WATCH"] > 0:
        print("\n  WARNING: operator IP got non-ALLOW verdict. Allowlist may not be working!")
    else:
        print("\n  ✓ Allowlist working correctly — operator IP always ALLOW")


if __name__ == "__main__":
    main()