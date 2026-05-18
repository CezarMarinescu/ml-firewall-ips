"""
Phase 5B.5 — Finalize reviews.

Takes the labeled rows from review_queue.csv (the volatile workspace) and
appends them to flows_reviewed.csv (the cumulative archive of human labels).

This separation matters because:
  - build_review_queue.py regenerates review_queue.csv from scratch on every
    run, which would otherwise destroy in-progress labels.
  - retrain.py reads from flows_reviewed.csv — the cumulative human knowledge
    of every label ever applied.

Idempotency: if you run this twice, the second run is a no-op (every row is
already finalized). Deduplication is by (src_ip, window_start) keeping the
MOST RECENT label, so re-labeling a row and re-finalizing corrects mistakes.

Usage:
    python -m scripts.finalize_reviews
    python -m scripts.finalize_reviews --dry-run
"""
from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make `src` importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


REVIEW_QUEUE_DEFAULT  = Path("data/review/review_queue.csv")
FLOWS_REVIEWED_DEFAULT = Path("data/review/flows_reviewed.csv")


# ANSI colors
RESET, BOLD, DIM      = "\033[0m", "\033[1m", "\033[2m"
GREEN, YELLOW, RED    = "\033[32m", "\033[33m", "\033[31m"


def read_csv_or_empty(path: Path) -> tuple[list[dict], list[str]]:
    """Read a CSV, returning (rows, fieldnames). Empty result if file missing."""
    if not path.exists():
        return [], []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])
    return rows, fieldnames


def select_finalizable(queue_rows: list[dict]) -> list[dict]:
    """
    A queue row is finalizable when:
      - needs_review == "done"
      - reviewed_label is "0" or "1" (so NOT "unsure" or empty)

    Skipped, unsure, and unreviewed rows are excluded.
    """
    out = []
    for r in queue_rows:
        if r.get("needs_review") != "done":
            continue
        if str(r.get("reviewed_label", "")).strip() not in ("0", "1"):
            continue
        out.append(r)
    return out


def add_finalization_metadata(rows: list[dict]) -> list[dict]:
    """Append a `finalized_at` timestamp so we can audit when labels landed."""
    stamp = datetime.now(timezone.utc).isoformat()
    out = []
    for r in rows:
        copy = dict(r)
        copy["finalized_at"] = stamp
        out.append(copy)
    return out


def dedup_keep_latest(old_rows: list[dict], new_rows: list[dict]) -> list[dict]:
    """
    Merge old and new, keyed by (src_ip, window_start). New rows win on conflict.

    Returns the combined list in (old non-conflicting + new) order.
    """
    new_keys = {(r.get("src_ip"), r.get("window_start")) for r in new_rows}
    kept_old = [r for r in old_rows
                if (r.get("src_ip"), r.get("window_start")) not in new_keys]
    return kept_old + new_rows


def union_fieldnames(*lists_of_dicts) -> list[str]:
    """
    Build the union of all keys across all rows, preserving first-seen order.

    We prefer this over hard-coding a schema because review_queue.csv may have
    different feature columns over time as the model evolves.
    """
    seen: list[str] = []
    seen_set: set[str] = set()
    for rows in lists_of_dicts:
        for r in rows:
            for k in r.keys():
                if k not in seen_set:
                    seen.append(k)
                    seen_set.add(k)
    return seen


def parse_args():
    p = argparse.ArgumentParser(
        description="Phase 5B.5 — Move labels from review queue to permanent archive.",
    )
    p.add_argument(
        "--queue", type=Path, default=REVIEW_QUEUE_DEFAULT,
        help=f"Source queue CSV. Default: {REVIEW_QUEUE_DEFAULT}",
    )
    p.add_argument(
        "--archive", type=Path, default=FLOWS_REVIEWED_DEFAULT,
        help=f"Destination archive CSV. Default: {FLOWS_REVIEWED_DEFAULT}",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print the summary but don't write anything.",
    )
    return p.parse_args()


def main():
    args = parse_args()

    queue_rows, queue_fields  = read_csv_or_empty(args.queue)
    if not queue_rows:
        print(f"{RED}ERROR: queue {args.queue} not found or empty.{RESET}")
        return 2

    finalizable = select_finalizable(queue_rows)
    print(BOLD + "=" * 72 + RESET)
    print(BOLD + " Finalize reviews" + RESET)
    print(BOLD + "=" * 72 + RESET)
    print(f"  Source queue:     {args.queue}")
    print(f"  Archive:          {args.archive}")
    print(f"  Queue rows total: {len(queue_rows)}")
    print(f"  Finalizable now:  {len(finalizable)}  "
          f"({sum(1 for r in finalizable if r['reviewed_label']=='1')} mal / "
          f"{sum(1 for r in finalizable if r['reviewed_label']=='0')} ben)")

    if not finalizable:
        print(f"\n{YELLOW}Nothing to finalize. "
              f"Are any rows fully labeled with a binary value?{RESET}")
        return 0

    existing_rows, _ = read_csv_or_empty(args.archive)
    print(f"  Existing archive: {len(existing_rows)} previously finalized rows")

    finalizable_stamped = add_finalization_metadata(finalizable)
    merged = dedup_keep_latest(existing_rows, finalizable_stamped)

    n_replaced = len(existing_rows) + len(finalizable_stamped) - len(merged)
    n_new      = len(finalizable_stamped) - n_replaced
    print(f"  Will add:         {n_new} new row(s)")
    print(f"  Will overwrite:   {n_replaced} existing row(s) (re-labeled)")
    print(f"  Archive total after: {len(merged)}")

    if args.dry_run:
        print(f"\n{DIM}--dry-run set; archive not modified.{RESET}")
        return 0

    fields = union_fieldnames(merged)
    args.archive.parent.mkdir(parents=True, exist_ok=True)

    # Atomic write
    tmp = args.archive.with_suffix(args.archive.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in merged:
            w.writerow(row)
    tmp.replace(args.archive)

    print(f"\n{GREEN}Wrote {len(merged)} rows -> {args.archive}{RESET}")
    print(f"  Next step: run `python -m scripts.retrain` — it reads the archive.")
    return 0


if __name__ == "__main__":
    sys.exit(main())