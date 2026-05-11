"""
Phase 3B — Train a baseline Random Forest classifier on labeled flow data.

Pipeline:
  1. Load flows_labeled.csv
  2. Drop non-feature columns (src_ip, timestamps, etc.) — these are
     identifiers, not behavioral features. Keeping them would let the
     model memorize "192.168.56.103 = bad" instead of learning behavior.
  3. Stratified 80/20 train/test split (preserves class proportions).
  4. Train RandomForest with class_weight='balanced' to handle imbalance.
  5. Evaluate with per-class precision/recall/F1 and a confusion matrix.
  6. Save the model + metadata for reuse.

Usage (from project root):
    python -m scripts.train_ai
"""
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)

from src.model_io import save_model, ModelMetadata


ROOT = Path(__file__).parent.parent
FLOWS_LABELED = ROOT / "data" / "flows_labeled.csv"
MODEL_OUT     = ROOT / "data" / "models" / "rf_baseline"

# Columns to exclude from features: identifiers and labels themselves.
NON_FEATURE_COLUMNS = [
    "src_ip",
    "window_start",
    "label",
    "attack_type",
    "traffic_type",
    "all_attack_types",
    "all_traffic_types",
]


def prepare_features_and_labels(df: pd.DataFrame):
    """
    Split the DataFrame into feature matrix X and label vector y.

    Returns (X, y, feature_columns).
    """
    # Drop any rows with missing values in case of edge cases
    df = df.dropna(subset=["label"]).copy()

    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLUMNS]
    X = df[feature_cols].values
    y = df["label"].astype(int).values
    return X, y, feature_cols


def evaluate(y_true, y_pred, class_names=("benign", "malicious")):
    """Pretty-print evaluation metrics."""
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

    # Return metrics dict for metadata
    p, r, f, _ = precision_recall_fscore_support(
        y_true, y_pred, average=None, zero_division=0
    )
    return {
        class_names[0]: {"precision": float(p[0]), "recall": float(r[0]), "f1": float(f[0])},
        class_names[1]: {"precision": float(p[1]), "recall": float(r[1]), "f1": float(f[1])},
    }


def feature_importance_report(model, feature_cols, top_n=10):
    """Print the top-N most important features (Random Forest tells us this)."""
    importances = model.feature_importances_
    ranked = sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)
    print(f"\n=== Top {top_n} most important features ===")
    for name, importance in ranked[:top_n]:
        bar = "#" * int(importance * 100)
        print(f"  {name:25s} {importance:.4f}  {bar}")


def main():
    print("=" * 60)
    print("Phase 3B — Random Forest baseline training")
    print("=" * 60)

    # 1. Load
    if not FLOWS_LABELED.exists():
        print(f"ERROR: {FLOWS_LABELED} not found.")
        print("Run: python -m scripts.collect_data && "
              "python -m scripts.relabel_with_manifest")
        return

    df = pd.read_csv(FLOWS_LABELED)
    print(f"Loaded {len(df)} flows from {FLOWS_LABELED.name}")
    print(f"Label distribution:")
    print(df["label"].value_counts().to_string())

    # Sanity check: need both classes present
    if df["label"].nunique() < 2:
        print("\nERROR: Only one class present in dataset — cannot train.")
        print("Run more attacks/benign sessions to get a mixed dataset.")
        return

    # 2. Prepare features
    X, y, feature_cols = prepare_features_and_labels(df)
    print(f"\nFeature matrix shape: {X.shape}")
    print(f"Number of features:   {len(feature_cols)}")

    # 3. Stratified train/test split
    # stratify=y ensures both train and test have proportional class mix
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
    except ValueError as e:
        # Happens if a class has only 1 sample — can't stratify
        print(f"\nWARNING: stratified split failed ({e})")
        print("Falling back to random split. Results will be noisier.")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

    print(f"\nTrain set size: {len(X_train)}")
    print(f"Test set size:  {len(X_test)}")

    # 4. Train
    # class_weight='balanced' tells sklearn to penalize misclassification
    # of the minority (malicious) class more heavily, compensating for imbalance.
    print("\nTraining RandomForest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,              # cap depth to avoid overfitting tiny dataset
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,                  # use all CPU cores
    )
    model.fit(X_train, y_train)
    print("Training complete.")

    # 5. Evaluate
    y_pred = model.predict(X_test)
    metrics = evaluate(y_test, y_pred)
    feature_importance_report(model, feature_cols)

    # 6. Save model + metadata
    metadata = ModelMetadata(
        model_type="RandomForestClassifier",
        feature_columns=feature_cols,
        label_classes=["benign", "malicious"],
        training_set_size=len(X_train),
        training_timestamp=datetime.now().isoformat(),
        metrics=metrics,
    )
    save_model(model, metadata, MODEL_OUT)

    print("\n" + "=" * 60)
    print("Done. Next steps:")
    print("  - Inspect data/models/rf_baseline.json for the saved metrics")
    print("  - If metrics look weak, generate more attack/benign data and re-run")
    print("  - Phase 3C will add an Isolation Forest anomaly detector")
    print("=" * 60)


if __name__ == "__main__":
    main()