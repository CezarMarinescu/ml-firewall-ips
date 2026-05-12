"""
Phase 4B — Decision engine for the live agent.

Takes a flow (DataFrame row or dict of features) and returns a structured
Decision indicating whether to ALLOW, WATCH, or BLOCK the source IP.

Combines verdicts from the supervised RandomForest classifier and the
unsupervised IsolationForest anomaly detector using a conservative policy:
block only when both models agree AND the RF is highly confident.

This module is pure logic — no firewall side effects, no SSH, no I/O.
That makes it safe to unit-test and reason about in isolation.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional
import json

import numpy as np


class Verdict(str, Enum):
    """Final decision categories. Inherits from str so JSON-serializable."""
    ALLOW = "ALLOW"   # benign, take no action
    WATCH = "WATCH"   # suspicious, log only — do not touch firewall
    BLOCK = "BLOCK"   # high-confidence malicious, issue ipset block


@dataclass
class Decision:
    """
    A structured verdict with all the evidence that led to it.
    Stored to disk for every flow the agent processes — full audit trail.
    """
    src_ip: str
    window_start: str           # ISO 8601
    verdict: Verdict
    rf_prediction: int          # 0 = benign, 1 = malicious
    rf_probability: float       # probability of malicious class
    if_anomalous: bool          # True if IsolationForest flagged as anomaly
    if_score: float             # raw anomaly score (higher = more anomalous)
    on_allowlist: bool          # was the source IP allowlisted?
    reason: str                 # human-readable explanation
    top_features: dict = field(default_factory=dict)  # name -> value, top contributors

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value  # ensure plain string in JSON
        return d


class DecisionEngine:
    """
    Loads both trained models once and provides a decide() method per flow.

    Allowlist semantics: IPs (or CIDR ranges later) on this list are NEVER
    blocked regardless of model output. This is the most important safety
    feature in the entire system.
    """

    def __init__(
        self,
        rf_model,
        if_model,
        feature_columns: list,
        allowlist: list = None,
        rf_confidence_threshold: float = 0.85,
    ):
        self.rf_model = rf_model
        self.if_model = if_model
        self.feature_columns = feature_columns
        self.allowlist = set(allowlist or [])
        self.rf_confidence_threshold = rf_confidence_threshold

    @classmethod
    def from_disk(
        cls,
        rf_path: Path,
        if_path: Path,
        allowlist: list = None,
        rf_confidence_threshold: float = 0.85,
    ):
        """Convenience constructor that loads both models from saved paths."""
        from src.model_io import load_model

        rf_model, rf_meta = load_model(rf_path)
        if_model, if_meta = load_model(if_path)

        # Sanity check: both models must have been trained on the same feature schema
        if rf_meta["feature_columns"] != if_meta["feature_columns"]:
            raise ValueError(
                "RF and IF models have different feature schemas. "
                "Retrain both on the same dataset."
            )

        return cls(
            rf_model=rf_model,
            if_model=if_model,
            feature_columns=rf_meta["feature_columns"],
            allowlist=allowlist,
            rf_confidence_threshold=rf_confidence_threshold,
        )

    def decide(self, flow: dict) -> Decision:
        """
        Run both models on one flow and return a verdict.

        `flow` must contain at minimum: src_ip, window_start, and all keys
        in self.feature_columns. Extra keys are ignored.
        """
        src_ip = flow["src_ip"]
        window_start = str(flow["window_start"])

        # Layer 1: allowlist short-circuit. Never blocks an allowlisted IP.
        if self._is_allowlisted(src_ip):
            return Decision(
                src_ip=src_ip,
                window_start=window_start,
                verdict=Verdict.ALLOW,
                rf_prediction=0,
                rf_probability=0.0,
                if_anomalous=False,
                if_score=0.0,
                on_allowlist=True,
                reason=f"Allowlisted: {src_ip}",
            )

        # Build feature vector in the exact order the models were trained on.
        X = np.array([[flow[col] for col in self.feature_columns]])

        # Random Forest: predict class + probability of malicious
        rf_pred = int(self.rf_model.predict(X)[0])
        # predict_proba returns [[p_benign, p_malicious]]
        rf_prob = float(self.rf_model.predict_proba(X)[0][1])

        # Isolation Forest: predict label (-1 anomaly, 1 normal) + raw score
        if_label = int(self.if_model.predict(X)[0])  # -1 or 1
        if_anomalous = (if_label == -1)
        # decision_function: higher = more normal. Negate so higher = more anomalous.
        if_score = float(-self.if_model.decision_function(X)[0])

        # Layer 2-6: combine the two opinions using the conservative policy.
        verdict, reason = self._combine_verdicts(rf_pred, rf_prob, if_anomalous)

        # Capture top contributing features (just for explainability in logs).
        # We use RF feature importances multiplied by the flow's feature magnitudes
        # — a crude but useful "what stood out in this specific flow" signal.
        top_features = self._top_contributing_features(X[0], top_n=5)

        return Decision(
            src_ip=src_ip,
            window_start=window_start,
            verdict=verdict,
            rf_prediction=rf_pred,
            rf_probability=rf_prob,
            if_anomalous=if_anomalous,
            if_score=if_score,
            on_allowlist=False,
            reason=reason,
            top_features=top_features,
        )

    # ------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------

    def _is_allowlisted(self, ip: str) -> bool:
        """
        Currently a simple exact-match check. Future versions can extend this
        to CIDR ranges using ipaddress.ip_network.
        """
        return ip in self.allowlist

    def _combine_verdicts(self, rf_pred: int, rf_prob: float,
                          if_anomalous: bool) -> tuple[Verdict, str]:
        """
        Conservative combining policy — see module docstring for the matrix.
        Returns (Verdict, human-readable reason).
        """
        rf_says_malicious = (rf_pred == 1)
        rf_confident = (rf_prob >= self.rf_confidence_threshold)

        if rf_says_malicious and rf_confident and if_anomalous:
            return Verdict.BLOCK, (
                f"BLOCK: RF malicious (prob={rf_prob:.3f} >= {self.rf_confidence_threshold}) "
                f"AND IF anomalous"
            )

        if rf_says_malicious and rf_confident:
            return Verdict.WATCH, (
                f"WATCH: RF malicious (prob={rf_prob:.3f}) but IF says normal"
            )

        if rf_says_malicious or if_anomalous:
            sources = []
            if rf_says_malicious:
                sources.append(f"RF flagged (prob={rf_prob:.3f}, below threshold)")
            if if_anomalous:
                sources.append("IF anomalous")
            return Verdict.WATCH, "WATCH: " + " AND ".join(sources)

        return Verdict.ALLOW, "ALLOW: RF benign, IF normal"

    def _top_contributing_features(self, x: np.ndarray, top_n: int = 5) -> dict:
        """
        Identify which features stood out most for this specific flow.
        Uses RF feature_importances_ as a global weight, multiplied by the
        absolute feature value. Not a true SHAP/LIME explanation, just a
        cheap-and-useful proxy for the audit log.
        """
        if not hasattr(self.rf_model, "feature_importances_"):
            return {}
        importances = self.rf_model.feature_importances_
        contributions = np.abs(x) * importances
        ranked = sorted(
            zip(self.feature_columns, x, contributions),
            key=lambda t: t[2], reverse=True,
        )
        return {name: float(value) for name, value, _ in ranked[:top_n]}