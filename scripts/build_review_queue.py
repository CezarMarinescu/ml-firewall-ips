"""
Phase 5A.1 — Build the human review queue.

Reads data/agent/decisions.jsonl and produces data/review/review_queue.csv,
a candidate dataset waiting for human labeling. The reviewer (Phase 5B) walks
through this file row by row; after labeling, `finalize_reviews.py` moves
those labels into data/review/flows_reviewed.csv (the cumulative archive).
Phase 5C reads from the archive, not from review_queue.csv directly.

Already-finalized rows are skipped automatically when building a new queue —
matched by (src_ip, window_start) — so rerunning this script after another
agent session produces "rows I haven't labeled yet" rather than re-asking you
to label things you already did. Use --include-finalized to override.

What ends up in the queue
-------------------------
We include records where human judgment adds the most signal:

  - All REAL_BLOCK / DRY_RUN_BLOCK  -> confirm true positives
  - All WATCH_LOGGED                -> the most informative: model was uncertain
  - Sampled ALLOW_NOOP              -> ~5%, biased toward "near misses"

We skip outright:
  - REFUSED_ALLOWLIST   (label is structurally correct: it's an allowlist hit)
  - SKIPPED_DUPLICATE   (the first instance is what we'd review)
  - REFUSED_RATE_LIMIT  (operational state, not a classification)
  - FAILED_BLOCK        (operational state, not a classification)

Records without a "flow" key (logged before Phase 5A.0) are skipped entirely:
they can't contribute to retraining because the full feature vector wasn't
preserved.

Incident deduplication
----------------------
Consecutive BLOCK-class decisions from the same src_ip within a 5-minute
window are grouped into one "incident" row. The reviewer labels the incident
once; in Phase 5C each underlying flow inherits that label.

Usage
-----
    python -m scripts.build_review_queue
    python -m scripts.build_review_queue --since 2026-05-17
    python -m scripts.build_review_queue --allow-sample-rate 0.10
    python -m scripts.build_review_queue --dry-run
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Make `src` importable when run as a script from project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DECISIONS_PATH = Path("data/agent/decisions.jsonl")
REVIEW_DIR     = Path("data/review")
REVIEW_QUEUE   = REVIEW_DIR / "review_queue.csv"
REVIEW_META    = REVIEW_DIR / "review_queue.meta.json"
FLOWS_REVIEWED = REVIEW_DIR / "flows_reviewed.csv"  # cumulative archive of finalized labels

# Outcomes that always go into the queue.
ALWAYS_INCLUDE = {"REAL_BLOCK", "DRY_RUN_BLOCK", "WATCH_LOGGED"}

# Outcomes we sample from.
SAMPLE_INCLUDE = {"ALLOW_NOOP"}

# Outcomes we never include.
NEVER_INCLUDE  = {
    "REFUSED_ALLOWLIST", "SKIPPED_DUPLICATE",
    "REFUSED_RATE_LIMIT", "FAILED_BLOCK",
}

# Incident grouping: BLOCKs from same src_ip within this gap merge into one row.
INCIDENT_GAP_SECONDS = 300

# RFC: under-sample very confident ALLOWs, over-sample near-misses.
# Score for biased sampling — see _allow_sample_score().
ALLOW_NEAR_MISS_BOOST = 5.0


# ANSI for stats summary
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load_decisions(path: Path) -> list[dict]:
    """Read all JSONL lines. Skip malformed lines with a warning."""
    if not path.exists():
        print(f"{RED}ERROR: {path} not found.{RESET}")
        print("Run the agent at least once before building a review queue.")
        sys.exit(2)

    records = []
    skipped = 0
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"{YELLOW}WARN line {i}: bad JSON ({e}); skipping{RESET}")
                skipped += 1
    if skipped:
        print(f"{YELLOW}Skipped {skipped} malformed line(s).{RESET}")
    return records


def parse_dt(s: str) -> Optional[datetime]:
    """Parse an ISO timestamp into a tz-aware UTC datetime. None on failure."""
    if not s:
        return None
    try:
        # Handle both "2026-05-17T08:14:09.931226+00:00" and naive forms.
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Filtering & sampling
# ---------------------------------------------------------------------------
def in_date_range(rec: dict, since: Optional[datetime],
                  until: Optional[datetime]) -> bool:
    dt = parse_dt(rec.get("logged_at", ""))
    if dt is None:
        return True  # don't drop on missing timestamp; surface it elsewhere
    if since and dt < since:
        return False
    if until and dt > until:
        return False
    return True


def has_full_flow(rec: dict) -> bool:
    """A record can be used for retraining only if it has the full flow dict."""
    return isinstance(rec.get("flow"), dict) and len(rec["flow"]) > 0


def load_finalized_keys(path: Path) -> set[tuple[str, str]]:
    """
    Read flows_reviewed.csv and return the set of (src_ip, window_start) tuples
    that have already been finalized — i.e., the user has already labeled them
    and committed those labels to the archive.

    Rows matching these keys should be skipped when building the next queue,
    otherwise the user re-labels work they've already done.

    Returns an empty set if the archive doesn't exist yet.
    """
    if not path.exists():
        return set()
    keys: set[tuple[str, str]] = set()
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            ip = r.get("src_ip", "")
            ws = r.get("window_start", "")
            if ip and ws:
                keys.add((ip, ws))
    return keys


def _allow_sample_score(rec: dict) -> float:
    """
    Higher score = more "interesting" ALLOW worth reviewing.
    ALLOWs near the decision boundary (RF prob 0.3-0.5) are over-sampled.
    """
    rf_prob = rec.get("decision", {}).get("rf_probability", 0.0) or 0.0
    if 0.3 <= rf_prob <= 0.5:
        return ALLOW_NEAR_MISS_BOOST
    return 1.0


def filter_and_sample(records: list[dict],
                      allow_sample_rate: float,
                      since: Optional[datetime],
                      until: Optional[datetime],
                      rng: random.Random,
                      finalized_keys: Optional[set] = None) -> tuple[list[dict], dict]:
    """
    Apply category filters and ALLOW sampling. Returns (kept, stats).

    If `finalized_keys` is given, records whose (src_ip, window_start) is in
    that set are skipped — they've already been labeled and archived, so
    asking the user to label them again would just waste time.
    """
    stats = Counter()
    skipped_no_flow = 0
    skipped_finalized = 0
    kept = []

    for rec in records:
        stats["total_seen"] += 1
        if not in_date_range(rec, since, until):
            stats["filtered_date_range"] += 1
            continue

        outcome = rec.get("executor", {}).get("outcome")
        stats[f"outcome:{outcome}"] += 1

        if outcome in NEVER_INCLUDE:
            stats["skipped_never_include"] += 1
            continue
        if outcome not in ALWAYS_INCLUDE and outcome not in SAMPLE_INCLUDE:
            stats["skipped_unknown_outcome"] += 1
            continue
        if not has_full_flow(rec):
            skipped_no_flow += 1
            continue

        # Skip rows we've already finalized labels for.
        if finalized_keys:
            ip = rec.get("decision", {}).get("src_ip", "")
            ws = rec.get("decision", {}).get("window_start", "")
            if (ip, ws) in finalized_keys:
                skipped_finalized += 1
                continue

        if outcome in ALWAYS_INCLUDE:
            kept.append(rec)
            stats["kept_always"] += 1
        else:  # SAMPLE_INCLUDE
            score = _allow_sample_score(rec)
            # Per-record probability = base_rate * score, capped at 1.0
            p = min(1.0, allow_sample_rate * score)
            if rng.random() < p:
                kept.append(rec)
                stats["kept_sampled"] += 1
            else:
                stats["skipped_sampled_out"] += 1

    stats["skipped_no_flow"]   = skipped_no_flow
    stats["skipped_finalized"] = skipped_finalized
    return kept, stats


# ---------------------------------------------------------------------------
# Incident grouping
# ---------------------------------------------------------------------------
def group_incidents(records: list[dict]) -> list[dict]:
    """
    Merge consecutive BLOCK-class records from the same src_ip into one
    "incident" row. Non-block records pass through unchanged. The merged
    row carries the list of original flow records under `_merged_flows`
    so Phase 5C can expand them during retraining.
    """
    # Sort by (src_ip, logged_at) so consecutive BLOCKs from one IP cluster.
    def sort_key(r):
        return (r.get("decision", {}).get("src_ip", ""),
                parse_dt(r.get("logged_at", "")) or datetime.min.replace(tzinfo=timezone.utc))
    records = sorted(records, key=sort_key)

    out: list[dict] = []
    current: Optional[dict] = None  # the in-progress incident
    current_flows: list[dict] = []

    def flush():
        nonlocal current, current_flows
        if current is None:
            return
        # Attach the merged flows so Phase 5C can expand them.
        merged = dict(current)
        merged["_merged_flows"] = current_flows
        merged["_merge_count"]  = len(current_flows)
        out.append(merged)
        current = None
        current_flows = []

    BLOCK_OUTCOMES = {"REAL_BLOCK", "DRY_RUN_BLOCK"}

    for rec in records:
        outcome = rec.get("executor", {}).get("outcome")
        src_ip  = rec.get("decision", {}).get("src_ip", "")
        ts      = parse_dt(rec.get("logged_at", ""))

        # Non-block records pass through and break any in-progress incident.
        if outcome not in BLOCK_OUTCOMES:
            flush()
            single = dict(rec)
            single["_merged_flows"] = [rec]
            single["_merge_count"]  = 1
            out.append(single)
            continue

        # Block record: can we extend the current incident?
        if (current is not None
            and current.get("decision", {}).get("src_ip") == src_ip
            and ts is not None
            and (ts - (parse_dt(current["logged_at"]) or ts)).total_seconds() <= INCIDENT_GAP_SECONDS):
            current_flows.append(rec)
        else:
            flush()
            current = rec
            current_flows = [rec]

    flush()
    return out


# ---------------------------------------------------------------------------
# CSV emission
# ---------------------------------------------------------------------------
META_COLUMNS = [
    "row_id", "logged_at", "src_ip", "window_start",
    "agent_verdict", "executor_outcome",
    "rf_prediction", "rf_probability",
    "if_anomalous", "if_score",
    "reason",
    "n_flows_merged", "needs_review",
    "reviewed_label", "reviewed_attack_type", "reviewed_notes",
]


def collect_feature_columns(records: list[dict]) -> list[str]:
    """Union of all feature keys present across records, sorted."""
    keys: set[str] = set()
    for rec in records:
        flow = rec.get("flow")
        if isinstance(flow, dict):
            keys.update(flow.keys())
    return sorted(keys)


def write_review_queue(records: list[dict], out_path: Path,
                       feature_columns: list[str]):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    columns = META_COLUMNS + feature_columns

    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        w.writeheader()

        for i, rec in enumerate(records, 1):
            dec  = rec.get("decision", {})
            exe  = rec.get("executor", {})
            flow = rec.get("flow", {})

            row = {
                "row_id":              i,
                "logged_at":           rec.get("logged_at", ""),
                "src_ip":              dec.get("src_ip", ""),
                "window_start":        dec.get("window_start", ""),
                "agent_verdict":       dec.get("verdict", ""),
                "executor_outcome":    exe.get("outcome", ""),
                "rf_prediction":       dec.get("rf_prediction", ""),
                "rf_probability":      dec.get("rf_probability", ""),
                "if_anomalous":        dec.get("if_anomalous", ""),
                "if_score":            dec.get("if_score", ""),
                "reason":              dec.get("reason", ""),
                "n_flows_merged":      rec.get("_merge_count", 1),
                "needs_review":        "yes",
                "reviewed_label":      "",   # filled in by Phase 5B
                "reviewed_attack_type": "",  # filled in by Phase 5B
                "reviewed_notes":      "",   # filled in by Phase 5B
            }
            for fc in feature_columns:
                row[fc] = flow.get(fc, "")
            w.writerow(row)


def write_meta(stats: Counter, since, until, allow_sample_rate,
               n_rows, n_features, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "built_at":             datetime.now(timezone.utc).isoformat(),
        "since":                since.isoformat() if since else None,
        "until":                until.isoformat() if until else None,
        "allow_sample_rate":    allow_sample_rate,
        "queue_rows":           n_rows,
        "feature_columns":      n_features,
        "stats":                dict(stats),
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Pretty stats
# ---------------------------------------------------------------------------
def print_stats(stats: Counter, kept: list[dict], grouped: list[dict],
                feature_cols: list[str]):
    print(BOLD + "=" * 70 + RESET)
    print(BOLD + " Review queue stats" + RESET)
    print(BOLD + "=" * 70 + RESET)

    print(f"  Decisions seen:           {stats.get('total_seen', 0)}")
    print(f"  Filtered by date range:   {stats.get('filtered_date_range', 0)}")
    print(f"  Skipped (no flow data):   {stats.get('skipped_no_flow', 0)}")
    print(f"  Skipped (already labeled):{stats.get('skipped_finalized', 0)}")
    print(f"  Skipped (never-include):  {stats.get('skipped_never_include', 0)}")
    print(f"  Skipped by sampling:      {stats.get('skipped_sampled_out', 0)}")
    print()
    print(f"  Kept (always-include):    {stats.get('kept_always', 0)}")
    print(f"  Kept (sampled):           {stats.get('kept_sampled', 0)}")
    print(f"  Total kept (pre-merge):   {len(kept)}")
    print(f"  Total rows (post-merge):  {len(grouped)}")
    print(f"  Feature columns:          {len(feature_cols)}")
    print()
    print(BOLD + "  Outcome breakdown of all decisions:" + RESET)
    outcome_keys = [k for k in stats if k.startswith("outcome:")]
    for k in sorted(outcome_keys):
        print(f"    {k[len('outcome:'):]:.<24} {stats[k]}")
    print(BOLD + "=" * 70 + RESET)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Phase 5A.1 — Build the human review queue from decisions.jsonl.",
    )
    p.add_argument(
        "--since", type=str, default=None,
        help="Only include decisions logged on or after this date (YYYY-MM-DD).",
    )
    p.add_argument(
        "--until", type=str, default=None,
        help="Only include decisions logged on or before this date (YYYY-MM-DD).",
    )
    p.add_argument(
        "--allow-sample-rate", type=float, default=0.05,
        help="Base probability of including each ALLOW (default 0.05). "
             "ALLOWs near the decision boundary are over-sampled relative to this.",
    )
    p.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for ALLOW sampling. Default 42 for reproducible queues.",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print stats but do not write review_queue.csv.",
    )
    p.add_argument(
        "--out", type=Path, default=REVIEW_QUEUE,
        help=f"Output CSV path. Default: {REVIEW_QUEUE}",
    )
    p.add_argument(
        "--meta-out", type=Path, default=REVIEW_META,
        help=f"Output metadata JSON path. Default: {REVIEW_META}",
    )
    p.add_argument(
        "--archive", type=Path, default=FLOWS_REVIEWED,
        help=f"Path to flows_reviewed.csv (finalized labels archive). "
             f"Rows that exist there are skipped to avoid re-labeling. "
             f"Default: {FLOWS_REVIEWED}",
    )
    p.add_argument(
        "--include-finalized", action="store_true",
        help="Don't skip already-finalized rows. Useful for re-reviewing the "
             "whole queue, but you'll re-label things you've already labeled.",
    )
    return p.parse_args()


def main():
    args = parse_args()

    since = parse_dt(args.since + "T00:00:00+00:00") if args.since else None
    until = parse_dt(args.until + "T23:59:59+00:00") if args.until else None

    print(f"Reading {DECISIONS_PATH}...")
    records = load_decisions(DECISIONS_PATH)
    print(f"  {len(records)} decisions loaded.")

    # Load already-finalized labels so we can skip them.
    if args.include_finalized:
        finalized_keys: set = set()
    else:
        finalized_keys = load_finalized_keys(args.archive)
        if finalized_keys:
            print(f"  {len(finalized_keys)} previously-finalized row(s) loaded from {args.archive}; "
                  f"these will be skipped.")

    rng = random.Random(args.seed)
    kept, stats = filter_and_sample(records, args.allow_sample_rate,
                                    since, until, rng, finalized_keys)
    grouped = group_incidents(kept)
    feature_cols = collect_feature_columns(grouped)

    print_stats(stats, kept, grouped, feature_cols)

    if not grouped:
        print(f"{YELLOW}No rows to write — review queue is empty.{RESET}")
        if not has_any_flow_records(records):
            print(f"{YELLOW}HINT: no decisions have full 'flow' data. "
                  f"This is expected for entries logged before Phase 5A.0. "
                  f"Run the agent again to produce reviewable decisions.{RESET}")
        return 0

    if args.dry_run:
        print(f"{DIM}(--dry-run set; not writing files){RESET}")
        return 0

    write_review_queue(grouped, args.out, feature_cols)
    write_meta(stats, since, until, args.allow_sample_rate,
               len(grouped), len(feature_cols), args.meta_out)

    print(f"{GREEN}Wrote {len(grouped)} rows -> {args.out}{RESET}")
    print(f"{GREEN}Wrote stats         -> {args.meta_out}{RESET}")
    print(f"\nNext step: review the CSV by hand (Phase 5B will automate this).")
    print(f"For each row, fill in:")
    print(f"  reviewed_label        -> 0 (benign) or 1 (malicious)")
    print(f"  reviewed_attack_type  -> e.g. 'syn_scan', 'benign_active', 'benign_idle'")
    print(f"  reviewed_notes        -> optional free text")
    return 0


def has_any_flow_records(records: list[dict]) -> bool:
    return any(has_full_flow(r) for r in records)


if __name__ == "__main__":
    sys.exit(main())