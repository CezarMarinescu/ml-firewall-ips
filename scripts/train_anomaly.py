"""
Phase 3C — Train an Isolation Forest anomaly detector on benign flows only.

Unlike the supervised RandomForest, this model learns ONLY what normal
traffic looks like and flags deviations. This lets it catch attacks the
supervised model never saw during training (its main weakness).

Pipeline:
  1. Load flows_labeled.csv
  2. Split: benign flows for training, all flows for testing
  3. Train Isolation Forest on benign only
  4. Score every flow; convert to anomaly labels at a chosen threshold
  5. Evaluate against ground truth using precision/recall/F1 + ROC-AUC
  6. Save model with metadata

Usage (from project root):
    python -m scripts.train_anomaly
"""
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_fscore_support,
)

from src.model_io import save_model, ModelMetadata


ROOT = Path(__file__).parent.parent
FLOWS_LABELED = ROOT / "data" / "flows_labeled.csv"
MODEL_OUT     = ROOT / "data" / "models" / "iforest_baseline"

# Same exclusions as the RF script — identifiers, not behavioral features.
NON_FEATURE_COLUMNS = [
    "src_ip",
    "window_start",
    "label",
    "attack_type",
    "traffic_type",
    "all_attack_types",
    "all_traffic_types",
]


def prepare_features(df: pd.DataFrame):
    """Return (X, y, feature_columns). y is ground-truth label (0/1)."""
    df = df.dropna(subset=["label"]).copy()
    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLUMNS]
    X = df[feature_cols].values
    y = df["label"].astype(int).values
    return X, y, feature_cols


def evaluate(y_true, y_pred, scores, class_names=("benign", "malicious")):
    """Print classification report, confusion matrix, and ROC-AUC."""
    print("\n=== Classification report ===")
    print(classification_report(
        y_true, y_pred, target_names=class_names, digits=3, zero_division=0
    ))

    print("=== Confusion matrix ===")
    cm = confusion_matrix(y_true, y_pred)
    print(f"                  Predicted")
    print(f"                  {class_names[0]:>10} {class_names[1]:>10}")
    for i, name in enumerate(class_names):
        print(f"Actual {name:<10} {cm[i][0]:>10} {cm[i][1]:>10}")

    # ROC-AUC uses raw anomaly scores, not binary predictions.
    # Higher score = more anomalous, so we use scores directly.
    auc = roc_auc_score(y_true, scores)
    print(f"\n=== ROC-AUC: {auc:.3f} ===")
    print("  (1.0 = perfect, 0.5 = random, our target is > 0.85)")

    p, r, f, _ = precision_recall_fscore_support(
        y_true, y_pred, average=None, zero_division=0
    )
    return {
        class_names[0]: {"precision": float(p[0]), "recall": float(r[0]), "f1": float(f[0])},
        class_names[1]: {"precision": float(p[1]), "recall": float(r[1]), "f1": float(f[1])},
        "roc_auc": float(auc),
    }


def threshold_sweep(y_true, scores):
    """
    Print precision/recall at several thresholds so we can see the tradeoff.
    This helps pick a good operating point for the live agent in Phase 4.
    """
    print("\n=== Threshold sweep ===")
    print(f"  {'Threshold':>10} {'Precision':>10} {'Recall':>10} {'F1':>8} {'Flagged':>8}")
    # IsolationForest score: higher = more normal. We negate so higher = more anomalous.
    # Try percentile thresholds.
    for pct in [99, 95, 90, 85, 80, 70]:
        threshold = np.percentile(scores, pct)
        y_pred = (scores >= threshold).astype(int)
        p, r, f, _ = precision_recall_fscore_support(
            y_true, y_pred, average=None, zero_division=0
        )
        # Use class index 1 = malicious
        flagged = y_pred.sum()
        print(f"  {pct:>9}% {p[1]:>10.3f} {r[1]:>10.3f} {f[1]:>8.3f} {flagged:>8d}")


def main():
    print("=" * 60)
    print("Phase 3C — Isolation Forest anomaly detector training")
    print("=" * 60)

    # 1. Load
    if not FLOWS_LABELED.exists():
        print(f"ERROR: {FLOWS_LABELED} not found.")
        return

    df = pd.read_csv(FLOWS_LABELED)
    print(f"Loaded {len(df)} flows from {FLOWS_LABELED.name}")

    # 2. Split: train on benign only, test on everything
    benign_df = df[df["label"] == 0].copy()
    print(f"\nBenign flows (training):   {len(benign_df)}")
    print(f"Malicious flows (held out): {(df['label'] == 1).sum()}")
    print(f"Total flows (evaluation):   {len(df)}")

    if len(benign_df) < 20:
        print("\nWARNING: Very few benign flows. Model quality will be limited.")

    # Build feature matrices
    X_train, _, feature_cols = prepare_features(benign_df)
    X_all, y_all, _          = prepare_features(df)

    print(f"\nFeature matrix shape (train): {X_train.shape}")
    print(f"Feature matrix shape (eval):  {X_all.shape}")

    # 3. Train Isolation Forest
    # contamination=0.01 means "I expect about 1% of the benign training data
    # to actually be mislabeled anomalies." We set it small because our manifest
    # labels are mostly trustworthy.
    print("\nTraining IsolationForest on benign flows only...")
    model = IsolationForest(
        n_estimators=300,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)
    print("Training complete.")

    # 4. Score every flow in the dataset
    # decision_function: higher = more normal. Negate so higher = more anomalous.
    raw_scores = -model.decision_function(X_all)

    # IsolationForest.predict returns -1 for anomalies, 1 for normal.
    # Convert to our convention (1 = malicious, 0 = benign).
    y_pred = (model.predict(X_all) == -1).astype(int)

    # 5. Evaluate at the default threshold
    metrics = evaluate(y_all, y_pred, raw_scores)

    # 5b. Show threshold sweep so we can see precision/recall tradeoffs
    threshold_sweep(y_all, raw_scores)

    # 6. Save
    metadata = ModelMetadata(
        model_type="IsolationForest",
        feature_columns=feature_cols,
        label_classes=["benign", "malicious"],
        training_set_size=len(X_train),
        training_timestamp=datetime.now().isoformat(),
        metrics=metrics,
    )
    save_model(model, metadata, MODEL_OUT)

    print("\n" + "=" * 60)
    print("Done. Compare these metrics to the RandomForest baseline:")
    print("  RandomForest (3B): F1 ~0.80 malicious, requires labeled attacks")
    print("  IsolationForest (3C): can detect attacks it has never seen")
    print("  Together: stronger combined coverage")
    print("=" * 60)


if __name__ == "__main__":
    main()