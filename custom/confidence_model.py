"""Pure-standard-library logistic regression for credential-confidence scoring.

This mirrors the shape of the hand-tuned ``calculate_confidence`` heuristic in
``credential_extractor`` — a linear score passed through a sigmoid — but with
*learned* weights. It deliberately avoids scikit-learn so the scanner keeps zero
new runtime dependencies and the model stays a transparent, inspectable list of
per-feature weights serialized as JSON.

Two roles:
  * ``LogisticRegression`` — train via gradient descent (used by the trainer).
  * ``ConfidenceModel`` — load a serialized model and score candidates, with a
    graceful "no model present" path so the heuristic remains the default.
"""
from __future__ import annotations

import json
import math
import os
import random
from typing import Any, Dict, List, Optional, Sequence

from custom.confidence_features import FEATURE_NAMES, candidate_to_vector

MODEL_VERSION = 1
# Default location the scanner looks for a trained model when asked to use one.
# Resolved relative to the current working directory so it matches where
# ``credx-train`` writes by default (``models/confidence_model.json``) and works
# the same whether credx is run from the repo or installed via pipx.
DEFAULT_MODEL_PATH = os.path.join('models', 'confidence_model.json')


def _sigmoid(z: float) -> float:
    """Numerically stable logistic sigmoid."""
    if z >= 0:
        ez = math.exp(-z)
        return 1.0 / (1.0 + ez)
    ez = math.exp(z)
    return ez / (1.0 + ez)


class LogisticRegression:
    """Minimal L2-regularized logistic regression trained with gradient descent.

    Feature standardization (zero mean, unit variance) is learned at ``fit`` time
    and stored alongside the weights so scoring is self-contained.
    """

    def __init__(
        self,
        feature_names: Sequence[str] = FEATURE_NAMES,
        learning_rate: float = 0.1,
        epochs: int = 400,
        l2: float = 0.001,
        seed: int = 13,
    ) -> None:
        self.feature_names = list(feature_names)
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.l2 = l2
        self.seed = seed
        self.weights: List[float] = [0.0] * len(self.feature_names)
        self.bias: float = 0.0
        self.mean: List[float] = [0.0] * len(self.feature_names)
        self.std: List[float] = [1.0] * len(self.feature_names)
        self.metrics: Dict[str, float] = {}

    # ── Standardization ──────────────────────────────────────────────────────
    def _fit_scaler(self, X: List[List[float]]) -> None:
        n = len(X)
        dim = len(self.feature_names)
        means = [0.0] * dim
        for row in X:
            for j in range(dim):
                means[j] += row[j]
        means = [m / n for m in means]

        variances = [0.0] * dim
        for row in X:
            for j in range(dim):
                diff = row[j] - means[j]
                variances[j] += diff * diff
        stds = [math.sqrt(v / n) if v > 0 else 1.0 for v in variances]

        self.mean = means
        self.std = stds

    def _standardize(self, row: Sequence[float]) -> List[float]:
        return [(row[j] - self.mean[j]) / self.std[j] for j in range(len(self.feature_names))]

    # ── Training ─────────────────────────────────────────────────────────────
    def fit(self, X: List[List[float]], y: List[int]) -> 'LogisticRegression':
        """Fit weights to feature matrix ``X`` and binary labels ``y``."""
        if not X:
            raise ValueError('cannot fit on an empty dataset')
        dim = len(self.feature_names)
        self._fit_scaler(X)
        Xs = [self._standardize(row) for row in X]

        rng = random.Random(self.seed)
        self.weights = [rng.uniform(-0.01, 0.01) for _ in range(dim)]
        self.bias = 0.0
        n = len(Xs)

        for _ in range(self.epochs):
            grad_w = [0.0] * dim
            grad_b = 0.0
            for row, label in zip(Xs, y):
                z = self.bias + sum(self.weights[j] * row[j] for j in range(dim))
                error = _sigmoid(z) - label
                for j in range(dim):
                    grad_w[j] += error * row[j]
                grad_b += error
            for j in range(dim):
                grad_w[j] = grad_w[j] / n + self.l2 * self.weights[j]
                self.weights[j] -= self.learning_rate * grad_w[j]
            self.bias -= self.learning_rate * (grad_b / n)
        return self

    # ── Inference ────────────────────────────────────────────────────────────
    def predict_proba_vector(self, vector: Sequence[float]) -> float:
        """Return P(real credential) for a raw (unstandardized) feature vector."""
        row = self._standardize(vector)
        z = self.bias + sum(self.weights[j] * row[j] for j in range(len(self.feature_names)))
        return _sigmoid(z)

    # ── Serialization ────────────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        return {
            'version': MODEL_VERSION,
            'feature_names': self.feature_names,
            'weights': self.weights,
            'bias': self.bias,
            'mean': self.mean,
            'std': self.std,
            'metrics': self.metrics,
        }

    def save(self, path: str) -> None:
        """Serialize the model to JSON, creating parent directories as needed."""
        directory = os.path.dirname(path) or '.'
        os.makedirs(directory, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogisticRegression':
        model = cls(feature_names=data['feature_names'])
        model.weights = list(data['weights'])
        model.bias = float(data['bias'])
        model.mean = list(data['mean'])
        model.std = list(data['std'])
        model.metrics = dict(data.get('metrics', {}))
        return model


class ConfidenceModel:
    """Loads a serialized model and scores candidate credentials.

    Use :meth:`load` to get an instance or ``None`` when no usable model file is
    present — callers then fall back to the heuristic confidence.
    """

    def __init__(self, regressor: LogisticRegression) -> None:
        self._regressor = regressor

    @classmethod
    def load(cls, path: Optional[str] = None) -> Optional['ConfidenceModel']:
        """Load a model from ``path`` (or the default). Returns ``None`` on any problem."""
        target = path or DEFAULT_MODEL_PATH
        if not os.path.exists(target):
            return None
        try:
            with open(target, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if data.get('feature_names') != FEATURE_NAMES:
                # Feature schema drift — refuse rather than score with a stale layout.
                return None
            dim = len(FEATURE_NAMES)
            # Validate array shapes and the scaler before trusting the model, so a
            # malformed file falls back to the heuristic instead of raising
            # (IndexError / ZeroDivisionError) mid-scan.
            if any(len(data.get(k, [])) != dim for k in ('weights', 'mean', 'std')):
                return None
            if any(float(s) == 0.0 for s in data['std']):
                return None
            float(data['bias'])  # must be numeric
            return cls(LogisticRegression.from_dict(data))
        except (json.JSONDecodeError, ValueError, KeyError, OSError, TypeError):
            return None

    def score(self, candidate: Dict[str, Any], raw_line: Optional[str] = None) -> float:
        """Return a calibrated probability in [0, 1] that ``candidate`` is a real credential."""
        vector = candidate_to_vector(candidate, raw_line)
        return round(self._regressor.predict_proba_vector(vector), 3)

    @property
    def metrics(self) -> Dict[str, float]:
        return dict(self._regressor.metrics)
