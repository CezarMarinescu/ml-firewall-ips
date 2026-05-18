"""
Phase 5C — Retraining pipeline.

Combines the original training data (flows_labeled.csv) with the human-reviewed
labels from Phase 5B (review_queue.csv), trains new RandomForest + IsolationForest
models with identical hyperparameters to the originals, evaluates BOTH old and
new models on the SAME held-out test set, and applies a strict gate to decide
whether the new models should replace production.

Design choices (decided in conversation, see PROJECT_CONTEXT.md):
  Q1 -> (b) Use the ORIGINAL test set as fixed evaluation set.
          Random state=42 was preserved in train_ai.py, so we can recreate
          the exact same split from flows_labeled.csv. Reviewed rows are NOT
          added to that test set — they go into training only. This keeps
          old/new comparison apples-to-apples.

  Q2 -> (a) Just append reviewed rows to training, trust class_weight='balanced'.

  Q3 -> (b) Manual commit. Default mode is "print verdict, don't touch
          production". --commit flag does the actual archive + swap.

What happens:
  1. Load flows_labeled.csv (172 rows)
  2. Recreate the EXACT same 80/20 stratified split as train_ai.py (random_state=42)
     -> test_set is now FROZEN; we will never train on it.
  3. Load review_queue.csv, expand merged rows, coerce features to floats,
     drop rows that aren't labeled "0" or "1".
  4. Build new training set = original_train + reviewed_rows
  5. Train new RF + IF on the new training set
  6. Evaluate OLD models (rf_baseline.pkl, iforest_baseline.pkl) on the frozen test set
  7. Evaluate NEW models on the same frozen test set
  8. Strict gate: new wins ONLY if precision AND recall both non-regress for the
     malicious class.
  9. With --commit: archive old to rf_v<N>.pkl, swap new in as rf_baseline.pkl.
     Without --commit: just print the verdict and leave production untouched.

Usage:
    python -m scripts.retrain                  # dry comparison, no swap
    python -m scripts.retrain --commit         # if gate passes, do the swap
    python -m scripts.retrain --review path/to/review_queue.csv
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

# Make `src` importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.model_io import ModelMetadata, load_model, save_model


# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
ROOT           = Path(__file__).resolve().parents[1]
FLOWS_LABELED  = ROOT / "data" / "flows_labeled.csv"
FLOWS_REVIEWED = ROOT / "data" / "review" / "flows_reviewed.csv"
MODELS_DIR     = ROOT / "data" / "models"

RF_BASE       = MODELS_DIR / "rf_baseline"
IF_BASE       = MODELS_DIR / "iforest_baseline"

# These MUST match train_ai.py exactly so the recreated split is identical.
RANDOM_STATE  = 42
TEST_SIZE     = 0.2

# Match train_ai.py's exclusions so feature columns line up.
NON_FEATURE_COLUMNS = [
    "src_ip", "window_start", "label", "attack_type", "traffic_type",
    "all_attack_types", "all_traffic_types",
]

# ANSI colors
RESET, BOLD, DIM       = "\033[0m", "\033[1m", "\033[2m"
GREEN, YELLOW, RED     = "\033[32m", "\033[33m", "\033[31m"
CYAN, MAGENTA          = "\033[36m", "\033[35m"


# ---------------------------------------------------------------------------
# Data loading & preparation
# ---------------------------------------------------------------------------
def load_original_data():
    """Read flows_labeled.csv and split off feature columns + labels."""
    if not FLOWS_LABELED.exists():
        print(f"{RED}ERROR: {FLOWS_LABELED} not found.{RESET}")
        sys.exit(2)
    df = pd.read_csv(FLOWS_LABELED).dropna(subset=["label"]).copy()
    df["label"] = df["label"].astype(int)
    return df


def feature_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if c not in NON_FEATURE_COLUMNS]


def recreate_original_split(df: pd.DataFrame):
    """
    Recreate the EXACT split train_ai.py produced, by passing the same
    parameters: random_state=42, test_size=0.2, stratify=y.

    Returns (train_df, test_df). These are pandas DataFrames so we preserve
    all columns (label, attack_type, etc.) — handy for downstream inspection.
    """
    feat_cols = feature_columns(df)
    X = df[feat_cols].values
    y = df["label"].values

    # train_test_split returns positional indices when we pass arange.
    idx = np.arange(len(df))
    train_idx, test_idx = train_test_split(
        idx,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    return df.iloc[train_idx].reset_index(drop=True), df.iloc[test_idx].reset_index(drop=True)


def load_reviewed_rows(archive_path: Path, feat_cols: list[str]):
    """
    Read flows_reviewed.csv (the cumulative archive of finalized labels),
    keep rows with a binary label (0 or 1), and coerce feature values to floats.

    Returns a DataFrame with the same feature columns as the original data,
    plus a `label` column (int), an `attack_type` column (string), and a
    `source` column ('reviewed') for traceability.
    """
    if not archive_path.exists():
        print(f"{YELLOW}No flows_reviewed.csv found at {archive_path}. "
              f"Training only on original data.{RESET}")
        print(f"{DIM}  Tip: after labeling in review_queue.py, run "
              f"`python -m scripts.finalize_reviews` to populate the archive.{RESET}")
        return pd.DataFrame(columns=feat_cols + ["label", "attack_type", "source"])

    raw = pd.read_csv(archive_path)

    # flows_reviewed.csv only contains finalized rows, so just filter by label.
    valid = raw[raw["reviewed_label"].astype(str).isin(["0", "1"])].copy()

    if valid.empty:
        print(f"{YELLOW}Archive has no usable labels yet.{RESET}")
        return pd.DataFrame(columns=feat_cols + ["label", "attack_type", "source"])

    # Coerce feature columns to floats. CSVs store everything as strings;
    # missing or non-numeric values become NaN, which we then drop.
    out = pd.DataFrame()
    for col in feat_cols:
        if col not in valid.columns:
            print(f"{YELLOW}  WARN: archive is missing feature '{col}'. "
                  f"Defaulting to 0.{RESET}")
            out[col] = 0.0
            continue
        out[col] = pd.to_numeric(valid[col], errors="coerce")

    out["label"]       = valid["reviewed_label"].astype(int).values
    out["attack_type"] = valid["reviewed_attack_type"].astype(str).values
    out["source"]      = "reviewed"

    # Drop rows where feature coercion produced any NaN — these can't train.
    pre = len(out)
    out = out.dropna(subset=feat_cols).reset_index(drop=True)
    if len(out) < pre:
        print(f"{YELLOW}Dropped {pre - len(out)} reviewed row(s) "
              f"due to non-numeric feature values.{RESET}")

    return out


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_rf(X, y):
    """Same hyperparameters as train_ai.py."""
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X, y)
    return model


def train_if(X_benign):
    """Same hyperparameters as train_anomaly.py."""
    model = IsolationForest(
        n_estimators=300,
        contamination="auto",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_benign)
    return model


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
def eval_rf(model, X_test, y_test):
    """Per-class precision/recall/F1 for the RF."""
    y_pred = model.predict(X_test)
    p, r, f, _ = precision_recall_fscore_support(
        y_test, y_pred, average=None, zero_division=0
    )
    # Index 0 = benign, 1 = malicious (matches train_ai.py)
    return {
        "benign":    {"precision": float(p[0]), "recall": float(r[0]), "f1": float(f[0])},
        "malicious": {"precision": float(p[1]), "recall": float(r[1]), "f1": float(f[1])},
    }


def eval_if(model, X_test, y_test):
    """Per-class precision/recall/F1 + ROC-AUC for the IF."""
    # IF.predict returns -1 for anomaly, 1 for normal -> map to (1, 0).
    y_pred = (model.predict(X_test) == -1).astype(int)
    # Anomaly score: higher = more anomalous (negate decision_function).
    scores = -model.decision_function(X_test)

    p, r, f, _ = precision_recall_fscore_support(
        y_test, y_pred, average=None, zero_division=0
    )
    out = {
        "benign":    {"precision": float(p[0]), "recall": float(r[0]), "f1": float(f[0])},
        "malicious": {"precision": float(p[1]), "recall": float(r[1]), "f1": float(f[1])},
    }
    try:
        out["roc_auc"] = float(roc_auc_score(y_test, scores))
    except ValueError:
        # Happens if test set has only one class — degenerate case.
        out["roc_auc"] = float("nan")
    return out


# ---------------------------------------------------------------------------
# Strict gate
# ---------------------------------------------------------------------------
def passes_strict_gate(old_metrics: dict, new_metrics: dict, label: str) -> tuple[bool, str]:
    """
    The strict gate (Q3=b from the design discussion):
        new wins iff precision_new >= precision_old AND recall_new >= recall_old
        for the malicious class.

    Equivalently: no regression on either metric.

    Returns (passed: bool, explanation: str).
    """
    old_mal = old_metrics["malicious"]
    new_mal = new_metrics["malicious"]

    dp = new_mal["precision"] - old_mal["precision"]
    dr = new_mal["recall"]    - old_mal["recall"]

    # Tiny floating-point slack so 0.799999 vs 0.8 doesn't fail.
    EPS = 1e-9
    precision_ok = dp >= -EPS
    recall_ok    = dr >= -EPS

    if precision_ok and recall_ok:
        return True, (
            f"{label}: PASS  "
            f"Δprecision={dp:+.4f}  Δrecall={dr:+.4f}"
        )
    fails = []
    if not precision_ok:
        fails.append(f"precision regressed by {-dp:.4f}")
    if not recall_ok:
        fails.append(f"recall regressed by {-dr:.4f}")
    return False, (
        f"{label}: FAIL  "
        f"Δprecision={dp:+.4f}  Δrecall={dr:+.4f}  ({', '.join(fails)})"
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_comparison(label: str, old: dict, new: dict, include_auc: bool = False):
    print(BOLD + f"\n  {label} metrics on frozen test set" + RESET)
    print("  " + "-" * 64)
    print(f"  {'':<14} {'OLD':>10} {'NEW':>10} {'Δ':>12}")
    for cls in ("benign", "malicious"):
        for metric in ("precision", "recall", "f1"):
            old_v = old[cls][metric]
            new_v = new[cls][metric]
            delta = new_v - old_v
            color = GREEN if delta > 1e-6 else (RED if delta < -1e-6 else "")
            print(f"  {cls:>6} {metric:<7} {old_v:>10.4f} {new_v:>10.4f} "
                  f"{color}{delta:>+12.4f}{RESET}")
    if include_auc and "roc_auc" in old and "roc_auc" in new:
        old_v, new_v = old["roc_auc"], new["roc_auc"]
        delta = new_v - old_v
        color = GREEN if delta > 1e-6 else (RED if delta < -1e-6 else "")
        print(f"  {'roc_auc':>14} {old_v:>10.4f} {new_v:>10.4f} "
              f"{color}{delta:>+12.4f}{RESET}")


# ---------------------------------------------------------------------------
# Commit (archive + swap)
# ---------------------------------------------------------------------------
def next_version_path(base: Path) -> Path:
    """
    Find the next available archive path: data/models/rf_v1, rf_v2, ...
    base is e.g. data/models/rf_baseline; we archive as rf_vN under the same dir.
    """
    stem_prefix = base.stem.split("_")[0] + "_v"  # "rf_v" or "iforest_v"
    n = 1
    while True:
        candidate = base.with_name(f"{stem_prefix}{n}")
        if not candidate.with_suffix(".pkl").exists():
            return candidate
        n += 1


def archive_existing(base: Path) -> Optional[Path]:
    """Copy base.{pkl,json} to base_vN.{pkl,json}. Returns new base path."""
    pkl = base.with_suffix(".pkl")
    js  = base.with_suffix(".json")
    if not pkl.exists():
        return None
    archive_base = next_version_path(base)
    shutil.copy2(pkl, archive_base.with_suffix(".pkl"))
    if js.exists():
        shutil.copy2(js, archive_base.with_suffix(".json"))
    return archive_base


def swap_in(new_model, new_meta: ModelMetadata, base: Path):
    """Overwrite base.{pkl,json} with the new model."""
    save_model(new_model, new_meta, base)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Phase 5C — Retrain models from original + reviewed data.",
    )
    p.add_argument(
        "--archive", type=Path, default=FLOWS_REVIEWED,
        help=f"Path to flows_reviewed.csv (cumulative label archive). "
             f"Default: {FLOWS_REVIEWED}",
    )
    p.add_argument(
        "--commit", action="store_true",
        help="If the strict gate passes, archive old models and swap in new ones. "
             "Default is dry-run: print verdict, no changes to production.",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_args()

    print(BOLD + "=" * 72 + RESET)
    print(BOLD + " Phase 5C — Retraining pipeline" + RESET)
    print(BOLD + "=" * 72 + RESET)
    print(f"  Mode:           {RED + 'COMMIT' + RESET if args.commit else GREEN + 'DRY-RUN (no swap)' + RESET}")
    print(f"  Original data:  {FLOWS_LABELED}")
    print(f"  Reviewed data:  {args.archive}")
    print(f"  Models dir:     {MODELS_DIR}")
    print(BOLD + "=" * 72 + RESET)

    # -----------------------------------------------------------------
    # 1. Original data + recreate the original 80/20 split
    # -----------------------------------------------------------------
    df = load_original_data()
    feat_cols = feature_columns(df)
    train_df, test_df = recreate_original_split(df)
    print(f"\n  Loaded {len(df)} flows from flows_labeled.csv")
    print(f"    Recreated train split: {len(train_df)} rows  "
          f"({(train_df['label']==1).sum()} mal / {(train_df['label']==0).sum()} ben)")
    print(f"    Recreated test split:  {len(test_df)} rows  (FROZEN — never trained on)")
    print(f"    Feature columns:       {len(feat_cols)}")

    # -----------------------------------------------------------------
    # 2. Reviewed rows
    # -----------------------------------------------------------------
    reviewed = load_reviewed_rows(args.archive, feat_cols)
    print(f"\n  Reviewed labels added: {len(reviewed)}  "
          f"({(reviewed['label']==1).sum() if len(reviewed) else 0} mal / "
          f"{(reviewed['label']==0).sum() if len(reviewed) else 0} ben)")

    # -----------------------------------------------------------------
    # 3. Build new training set
    # -----------------------------------------------------------------
    # Only keep the columns we care about, in a consistent order.
    train_subset = train_df[feat_cols + ["label"]].copy()
    train_subset["source"] = "original"
    if not reviewed.empty:
        reviewed_subset = reviewed[feat_cols + ["label", "source"]].copy()
        new_train = pd.concat([train_subset, reviewed_subset], ignore_index=True)
    else:
        new_train = train_subset

    X_new_train = new_train[feat_cols].values
    y_new_train = new_train["label"].values

    X_test = test_df[feat_cols].values
    y_test = test_df["label"].values

    print(f"\n  New training set:  {len(new_train)} rows  "
          f"({(new_train['label']==1).sum()} mal / {(new_train['label']==0).sum()} ben)")
    print(f"  Frozen test set:   {len(test_df)} rows  "
          f"({(test_df['label']==1).sum()} mal / {(test_df['label']==0).sum()} ben)")

    # -----------------------------------------------------------------
    # 4. Load old models (production)
    # -----------------------------------------------------------------
    print(BOLD + "\n  Loading old (production) models..." + RESET)
    try:
        old_rf, _ = load_model(RF_BASE)
        old_if, _ = load_model(IF_BASE)
    except Exception as e:
        print(f"{RED}ERROR loading old models: {e}{RESET}")
        sys.exit(2)
    print("    OK.")

    # -----------------------------------------------------------------
    # 5. Train new models
    # -----------------------------------------------------------------
    print(BOLD + "\n  Training new RandomForest..." + RESET)
    new_rf = train_rf(X_new_train, y_new_train)
    print("    OK.")

    print(BOLD + "  Training new IsolationForest (benign-only)..." + RESET)
    benign_mask = new_train["label"] == 0
    new_if = train_if(new_train.loc[benign_mask, feat_cols].values)
    print(f"    OK (trained on {benign_mask.sum()} benign rows).")

    # -----------------------------------------------------------------
    # 6. Evaluate BOTH on the SAME frozen test set
    # -----------------------------------------------------------------
    old_rf_metrics = eval_rf(old_rf, X_test, y_test)
    new_rf_metrics = eval_rf(new_rf, X_test, y_test)
    old_if_metrics = eval_if(old_if, X_test, y_test)
    new_if_metrics = eval_if(new_if, X_test, y_test)

    print_comparison("RandomForest", old_rf_metrics, new_rf_metrics)
    print_comparison("IsolationForest", old_if_metrics, new_if_metrics, include_auc=True)

    # -----------------------------------------------------------------
    # 7. Strict gate decision (per model)
    # -----------------------------------------------------------------
    print(BOLD + "\n  Strict gate (Δprecision >= 0 AND Δrecall >= 0 on malicious):" + RESET)
    rf_pass, rf_note = passes_strict_gate(old_rf_metrics, new_rf_metrics, "RF")
    if_pass, if_note = passes_strict_gate(old_if_metrics, new_if_metrics, "IF")
    print(f"    {GREEN if rf_pass else RED}{rf_note}{RESET}")
    print(f"    {GREEN if if_pass else RED}{if_note}{RESET}")

    # We're STRICT: either model fails => no swap. (One-fail-fails-all.)
    overall_pass = rf_pass and if_pass

    # -----------------------------------------------------------------
    # 8. Commit or report
    # -----------------------------------------------------------------
    print(BOLD + "\n" + "=" * 72 + RESET)
    if not overall_pass:
        print(f"  {RED + BOLD}VERDICT: REJECT new models.{RESET}")
        print(f"  At least one model regressed on the strict gate. "
              f"Production unchanged.")
        print(f"  {DIM}Tip: gather more reviewed data and re-run.{RESET}")
        return 1

    print(f"  {GREEN + BOLD}VERDICT: ACCEPT new models.{RESET}")

    if not args.commit:
        print(f"  {YELLOW}Dry-run mode — production NOT updated.{RESET}")
        print(f"  Re-run with {BOLD}--commit{RESET} to archive old models and swap in new.")
        return 0

    # Actually swap.
    print(BOLD + "\n  Committing..." + RESET)

    rf_archive = archive_existing(RF_BASE)
    if_archive = archive_existing(IF_BASE)
    if rf_archive: print(f"    Archived OLD RF -> {rf_archive.with_suffix('.pkl').name}")
    if if_archive: print(f"    Archived OLD IF -> {if_archive.with_suffix('.pkl').name}")

    rf_meta = ModelMetadata(
        model_type="RandomForestClassifier",
        feature_columns=feat_cols,
        label_classes=["benign", "malicious"],
        training_set_size=len(new_train),
        training_timestamp=datetime.now().isoformat(),
        metrics=new_rf_metrics,
    )
    if_meta = ModelMetadata(
        model_type="IsolationForest",
        feature_columns=feat_cols,
        label_classes=["benign", "malicious"],
        training_set_size=int(benign_mask.sum()),
        training_timestamp=datetime.now().isoformat(),
        metrics=new_if_metrics,
    )
    swap_in(new_rf, rf_meta, RF_BASE)
    swap_in(new_if, if_meta, IF_BASE)
    print(f"    New RF in production -> {RF_BASE.with_suffix('.pkl').name}")
    print(f"    New IF in production -> {IF_BASE.with_suffix('.pkl').name}")
    print(BOLD + "=" * 72 + RESET)
    return 0


if __name__ == "__main__":
    sys.exit(main())