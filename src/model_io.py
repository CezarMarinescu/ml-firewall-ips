"""
Model serialization with versioning and schema checks.

Why this exists: a model trained on 20 features will silently produce garbage
predictions if you later feed it 19 or 21 features. By storing the feature
schema alongside the model, we can detect that mismatch at load time and
fail loudly instead of silently corrupting predictions.
"""
import json
import joblib
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class ModelMetadata:
    """Everything we need to know about a saved model."""
    model_type: str                 # e.g. "RandomForestClassifier"
    feature_columns: list           # ordered list of feature names
    label_classes: list             # e.g. ["benign", "malicious"] or attack types
    training_set_size: int          # how many rows it was trained on
    training_timestamp: str         # ISO 8601, when it was trained
    metrics: dict                   # final test metrics for documentation


def save_model(model: Any, metadata: ModelMetadata, base_path: Path):
    """
    Save model and metadata to base_path with .pkl and .json extensions.

    e.g. base_path = data/models/rf_v1  ->
      data/models/rf_v1.pkl  (the model)
      data/models/rf_v1.json (the metadata)
    """
    base_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, base_path.with_suffix(".pkl"))
    with open(base_path.with_suffix(".json"), "w") as f:
        json.dump(asdict(metadata), f, indent=2)
    print(f"Saved model     -> {base_path.with_suffix('.pkl')}")
    print(f"Saved metadata  -> {base_path.with_suffix('.json')}")


def load_model(base_path: Path, expected_features: list = None):
    """
    Load model + metadata. If expected_features is given, raises if the
    feature list doesn't match (prevents silent prediction corruption).

    Returns (model, metadata_dict).
    """
    model = joblib.load(base_path.with_suffix(".pkl"))
    with open(base_path.with_suffix(".json")) as f:
        meta = json.load(f)

    if expected_features is not None:
        if meta["feature_columns"] != expected_features:
            missing = set(meta["feature_columns"]) - set(expected_features)
            extra   = set(expected_features) - set(meta["feature_columns"])
            raise ValueError(
                f"Feature schema mismatch loading {base_path}.\n"
                f"  Missing from current data: {missing}\n"
                f"  Extra in current data:     {extra}"
            )

    return model, meta