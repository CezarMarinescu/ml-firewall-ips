"""
Phase 5B — Interactive review CLI.

Reads data/review/review_queue.csv (produced by Phase 5A.1), walks through
the un-reviewed rows one at a time, prompts the operator for a label, and
saves the result back to the same CSV. Auto-saves after every keypress so
a crash mid-session loses at most one row of work.

Workflow per row:
  - Show src_ip, window_start, agent verdict, and the most-relevant features
    annotated with "(vs typical benign: ...)" so unusual values stand out
  - Prompt: [a]ttack / [b]enign / [s]kip / [u]nsure / [f]ull features / [q]uit
  - For [a], pick the attack_type from a numbered menu
  - For [b], pick benign_idle / benign_active
  - For [u], free-text notes
  - The CSV columns reviewed_label / reviewed_attack_type / reviewed_notes are
    filled in, and needs_review is changed from "yes" to "done"

Resume support: re-running picks up where you left off — rows with
needs_review != "yes" are skipped automatically.

Usage:
    python -m scripts.review_queue
    python -m scripts.review_queue --skip-allowlist     # skip allowlist ALLOWs
    python -m scripts.review_queue --queue path/to.csv  # custom queue
"""
from __future__ import annotations

import argparse
import csv
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Project root importability (consistent with sibling scripts).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


REVIEW_QUEUE_DEFAULT = Path("data/review/review_queue.csv")


# ---------------------------------------------------------------------------
# Console colors
# ---------------------------------------------------------------------------
RESET   = "\033[0m"
DIM     = "\033[2m"
BOLD    = "\033[1m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
RED     = "\033[31m"
CYAN    = "\033[36m"
MAGENTA = "\033[35m"


# ---------------------------------------------------------------------------
# Known attack & benign labels (mirrors simulate_attacks.py + generate_benign.py)
# ---------------------------------------------------------------------------
ATTACK_TYPES = [
    "syn_scan",
    "fin_scan",
    "udp_scan",
    "slow_scan",
    "syn_flood",
    "ssh_brute",
    "other",       # free-text follow-up
]

BENIGN_TYPES = [
    "benign_idle",       # uncontrolled background traffic
    "benign_active",     # operator-driven legitimate traffic
    "benign_allowlist",  # known-allowlisted IP (operator, NAT gateway, etc.)
]


# ---------------------------------------------------------------------------
# Feature display hints — for each notable feature, a rule-of-thumb range
# the reviewer can compare against. These are NOT model thresholds; they
# are visual aids based on observed benign baseline traffic.
# ---------------------------------------------------------------------------
FEATURE_HINTS = {
    "n_packets":         "typical benign 1–1500",
    "packets_per_sec":   "typical benign <30",
    "total_bytes":       "typical benign <100k",
    "avg_packet_size":   "typical benign 40–600 (40=SYN/ACK, 576=DNS)",
    "unique_dst_ports":  "typical benign 1–4 (>20 suggests scan)",
    "unique_src_ports":  "typical benign 1–4 (>100 suggests flood)",
    "syn_only_ratio":    "typical benign <0.05 (>0.5 suggests SYN scan)",
    "fin_ratio":         "typical benign <0.05 (>0.5 suggests FIN scan)",
    "rst_ratio":         "typical benign <0.05",
    "udp_ratio":         "typical benign 0 or 1, mixed=DNS+other",
    "icmp_ratio":        "typical benign <0.05",
    "common_port_ratio": "typical benign ~1.0 (legit traffic hits common ports)",
    "dst_port_std":      "typical benign 0 (only ports 22/80/443 etc.)",
}

# Which features to always show at the top of each row, in order. Others
# are available via the 'f' (full features) command.
HEADLINE_FEATURES = [
    "n_packets", "packets_per_sec", "total_bytes", "avg_packet_size",
    "unique_dst_ports", "unique_src_ports",
    "syn_only_ratio", "fin_ratio", "rst_ratio",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    "dst_port_std",
]


# ---------------------------------------------------------------------------
# CSV I/O
# ---------------------------------------------------------------------------
def load_queue(path: Path) -> tuple[list[dict], list[str]]:
    """Read the queue CSV. Returns (rows, fieldnames)."""
    if not path.exists():
        print(f"{RED}ERROR: queue not found at {path}.{RESET}")
        print("Run `python -m scripts.build_review_queue` first.")
        sys.exit(2)

    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])

    if not rows:
        print(f"{YELLOW}Queue is empty.{RESET}")
        sys.exit(0)

    return rows, fieldnames


def save_queue(path: Path, rows: list[dict], fieldnames: list[str]):
    """
    Atomic write: write to a tempfile, then replace. Avoids leaving a
    half-written CSV if Python is killed mid-write.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow(row)
    tmp.replace(path)


def backup_queue(path: Path) -> Optional[Path]:
    """Save a one-shot backup with a timestamp suffix before the session starts."""
    if not path.exists():
        return None
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_name(path.stem + f".backup_{stamp}" + path.suffix)
    shutil.copy2(path, backup)
    return backup


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------
def _safe_float(v) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _fmt_num(v) -> str:
    """Format a numeric cell compactly."""
    f = _safe_float(v)
    if f is None:
        return str(v)
    if f == int(f) and abs(f) < 1e9:
        return str(int(f))
    if abs(f) < 100:
        return f"{f:.4f}".rstrip("0").rstrip(".")
    return f"{f:.2f}"


def show_row(row: dict, idx: int, total: int, reviewed: int, skipped: int):
    """Print the dense per-row display."""
    remaining = total - reviewed - skipped
    print()
    print(BOLD + "=" * 76 + RESET)
    print(BOLD + f" Row {row.get('row_id', idx+1)} of {total} "
                f"| Reviewed: {reviewed} | Skipped: {skipped} | Remaining: {remaining}" + RESET)
    print(BOLD + "=" * 76 + RESET)

    src_ip   = row.get("src_ip", "?")
    wstart   = row.get("window_start", "?")
    verdict  = row.get("agent_verdict", "?")
    outcome  = row.get("executor_outcome", "?")
    reason   = row.get("reason", "")
    n_merged = row.get("n_flows_merged", "1")

    # Color the verdict for visual scanning.
    verdict_color = {
        "ALLOW": GREEN, "WATCH": YELLOW, "BLOCK": RED,
    }.get(verdict, RESET)

    print(f"  src_ip:        {CYAN}{src_ip}{RESET}")
    print(f"  window_start:  {wstart}")
    print(f"  agent verdict: {verdict_color}{verdict}{RESET}  ({outcome})")
    print(f"  agent reason:  {DIM}{reason}{RESET}")
    if str(n_merged) not in ("", "1"):
        print(f"  merged flows:  {MAGENTA}{n_merged}{RESET}  (this row represents {n_merged} consecutive flows)")

    print()
    print(f"  {BOLD}Headline features:{RESET}")
    for col in HEADLINE_FEATURES:
        if col not in row:
            continue
        val = _fmt_num(row[col])
        hint = FEATURE_HINTS.get(col, "")
        hint_str = f"  {DIM}({hint}){RESET}" if hint else ""
        print(f"    {col:<20} {val:<14}{hint_str}")

    print()
    print(f"  {DIM}Press 'f' to see ALL features (not just headline ones).{RESET}")
    print(BOLD + "-" * 76 + RESET)


def show_full_features(row: dict, fieldnames: list[str]):
    """Dump every feature column for the row."""
    print()
    print(BOLD + " Full feature vector " + RESET)
    print("-" * 76)
    # Feature columns are everything after the metadata block.
    # Use the row's keys instead of guessing — preserves the column union.
    meta = {
        "row_id", "logged_at", "src_ip", "window_start",
        "agent_verdict", "executor_outcome",
        "rf_prediction", "rf_probability", "if_anomalous", "if_score",
        "reason", "n_flows_merged", "needs_review",
        "reviewed_label", "reviewed_attack_type", "reviewed_notes",
    }
    feature_keys = [k for k in fieldnames if k not in meta]
    for k in feature_keys:
        print(f"    {k:<22} {_fmt_num(row.get(k, ''))}")
    print("-" * 76)


# ---------------------------------------------------------------------------
# Prompting
# ---------------------------------------------------------------------------
def prompt_action() -> str:
    """Return one-letter action: a / b / s / u / f / q."""
    while True:
        ans = input(f"{BOLD}[a]ttack  [b]enign  [s]kip  [u]nsure  [f]ull features  [q]uit  > {RESET}").strip().lower()
        if ans in ("a", "b", "s", "u", "f", "q"):
            return ans
        print(f"{YELLOW}Unrecognized — type one of a / b / s / u / f / q.{RESET}")


def prompt_attack_type() -> tuple[str, str]:
    """Prompt for attack_type from numbered menu. Returns (type, notes)."""
    print(f"\n  {BOLD}Select attack type:{RESET}")
    for i, t in enumerate(ATTACK_TYPES, 1):
        print(f"    {i}) {t}")
    while True:
        ans = input(f"  > ").strip()
        if ans.isdigit() and 1 <= int(ans) <= len(ATTACK_TYPES):
            chosen = ATTACK_TYPES[int(ans) - 1]
            break
        print(f"{YELLOW}Enter a number 1–{len(ATTACK_TYPES)}.{RESET}")

    notes = ""
    if chosen == "other":
        chosen = input(f"  Free-text attack type (or press Enter for 'other'): ").strip() or "other"
    extra_notes = input(f"  Notes (optional, press Enter to skip): ").strip()
    if extra_notes:
        notes = extra_notes
    return chosen, notes


def prompt_benign_type() -> tuple[str, str]:
    """Prompt for benign sub-type. Returns (type, notes)."""
    print(f"\n  {BOLD}Select benign type:{RESET}")
    for i, t in enumerate(BENIGN_TYPES, 1):
        print(f"    {i}) {t}")
    while True:
        ans = input(f"  > ").strip()
        if ans.isdigit() and 1 <= int(ans) <= len(BENIGN_TYPES):
            chosen = BENIGN_TYPES[int(ans) - 1]
            break
        print(f"{YELLOW}Enter a number 1–{len(BENIGN_TYPES)}.{RESET}")

    notes = input(f"  Notes (optional, press Enter to skip): ").strip()
    return chosen, notes


def prompt_unsure() -> str:
    """Prompt for free-text notes when the reviewer is unsure."""
    return input(f"  {BOLD}Notes (required for 'unsure'): {RESET}").strip()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Phase 5B — Interactive review CLI.")
    p.add_argument(
        "--queue", type=Path, default=REVIEW_QUEUE_DEFAULT,
        help=f"Queue CSV to review. Default: {REVIEW_QUEUE_DEFAULT}",
    )
    p.add_argument(
        "--skip-allowlist", action="store_true",
        help="Automatically mark allowlisted-ALLOW rows as benign_allowlist and skip them. "
             "Useful when you know your operator IP doesn't need manual review.",
    )
    p.add_argument(
        "--no-backup", action="store_true",
        help="Don't create a timestamped backup before the session.",
    )
    return p.parse_args()


def main():
    args = parse_args()
    queue_path = args.queue

    rows, fieldnames = load_queue(queue_path)

    if not args.no_backup:
        backup_path = backup_queue(queue_path)
        if backup_path:
            print(f"{DIM}Backup saved: {backup_path}{RESET}")

    # Required columns must be present (build_review_queue.py guarantees these).
    for col in ("needs_review", "reviewed_label", "reviewed_attack_type", "reviewed_notes"):
        if col not in fieldnames:
            print(f"{RED}ERROR: queue is missing required column '{col}'. "
                  f"Was it produced by build_review_queue.py?{RESET}")
            sys.exit(2)

    total      = len(rows)
    reviewed   = sum(1 for r in rows if r.get("needs_review") == "done")
    skipped    = sum(1 for r in rows if r.get("needs_review") == "skip")
    unreviewed = [r for r in rows if r.get("needs_review") == "yes"]

    print(BOLD + "=" * 76 + RESET)
    print(BOLD + " Review session" + RESET)
    print(BOLD + "=" * 76 + RESET)
    print(f"  Queue file:        {queue_path}")
    print(f"  Total rows:        {total}")
    print(f"  Already reviewed:  {reviewed}")
    print(f"  Previously skipped:{skipped}")
    print(f"  To review now:     {len(unreviewed)}")
    if args.skip_allowlist:
        autoskip = sum(1 for r in unreviewed
                       if r.get("agent_verdict") == "ALLOW"
                       and "Allowlisted" in (r.get("reason") or ""))
        print(f"  Auto-label allowlist ALLOWs: {autoskip}")
    print(BOLD + "=" * 76 + RESET)

    if not unreviewed:
        print(f"\n{GREEN}Nothing to review — every row is already done or skipped.{RESET}")
        return 0

    print(f"\n{DIM}Tip: type 'q' at any prompt to save and exit. Progress is "
          f"auto-saved after every label.{RESET}")

    # Walk through unreviewed rows.
    for row in unreviewed:
        # Auto-label allowlist ALLOWs if requested
        if (args.skip_allowlist
            and row.get("agent_verdict") == "ALLOW"
            and "Allowlisted" in (row.get("reason") or "")):
            row["reviewed_label"]        = "0"
            row["reviewed_attack_type"]  = "benign_allowlist"
            row["reviewed_notes"]        = "auto-labeled (--skip-allowlist)"
            row["needs_review"]          = "done"
            save_queue(queue_path, rows, fieldnames)
            reviewed += 1
            continue

        # Interactive flow for one row.
        while True:
            show_row(row, rows.index(row), total, reviewed, skipped)
            action = prompt_action()

            if action == "f":
                show_full_features(row, fieldnames)
                continue  # re-prompt without leaving this row

            if action == "q":
                print(f"\n{GREEN}Saved. Resume with the same command.{RESET}")
                print(f"  Reviewed this session: {reviewed}")
                print(f"  Skipped this session:  {skipped}")
                return 0

            if action == "s":
                row["needs_review"] = "skip"
                save_queue(queue_path, rows, fieldnames)
                skipped += 1
                break

            if action == "a":
                attack_type, notes = prompt_attack_type()
                row["reviewed_label"]        = "1"
                row["reviewed_attack_type"]  = attack_type
                row["reviewed_notes"]        = notes
                row["needs_review"]          = "done"
                save_queue(queue_path, rows, fieldnames)
                reviewed += 1
                print(f"  {GREEN}Labeled as malicious / {attack_type}.{RESET}")
                break

            if action == "b":
                benign_type, notes = prompt_benign_type()
                row["reviewed_label"]        = "0"
                row["reviewed_attack_type"]  = benign_type
                row["reviewed_notes"]        = notes
                row["needs_review"]          = "done"
                save_queue(queue_path, rows, fieldnames)
                reviewed += 1
                print(f"  {GREEN}Labeled as benign / {benign_type}.{RESET}")
                break

            if action == "u":
                notes = prompt_unsure()
                if not notes:
                    print(f"{YELLOW}'unsure' requires notes. Try again or skip.{RESET}")
                    continue
                row["reviewed_label"]        = ""
                row["reviewed_attack_type"]  = "unsure"
                row["reviewed_notes"]        = notes
                row["needs_review"]          = "unsure"
                save_queue(queue_path, rows, fieldnames)
                # Treat "unsure" like a kind of review for counter purposes —
                # the row is no longer pending. But it's NOT counted as labeled
                # for training purposes.
                reviewed += 1
                print(f"  {YELLOW}Marked as unsure: {notes}{RESET}")
                break

    # End of queue.
    print()
    print(BOLD + "=" * 76 + RESET)
    print(BOLD + " Session complete" + RESET)
    print(BOLD + "=" * 76 + RESET)
    print(f"  Total rows:            {total}")
    print(f"  Reviewed (this run):   {reviewed}")
    print(f"  Skipped (this run):    {skipped}")
    print(f"  Queue file:            {queue_path}")
    print()
    print(f"  Next step: Phase 5C will use the rows with needs_review='done' AND")
    print(f"  reviewed_label in ('0','1') to retrain the models.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted. Latest auto-save preserved.{RESET}")
        sys.exit(130)