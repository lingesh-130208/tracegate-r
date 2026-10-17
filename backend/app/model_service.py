"""Load and run the trained TraceGate-R models."""
import json
import os
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np

ARTIFACT_DIR = Path(os.environ.get(
    "TRACEGATE_ARTIFACT_DIR",
    str(Path.home() / "tracegate-live" / "artifacts"),
))
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class ModelsUnavailableError(RuntimeError):
    pass


def _feature_schema_path():
    candidates = [
        ARTIFACT_DIR / "feature_names.json",
        PROJECT_ROOT / "data" / "model_feature_names.json",
    ]
    return next((p for p in candidates if p.is_file()), None)


def model_info():
    schema_path = _feature_schema_path()
    names = []
    if schema_path:
        try:
            names = json.loads(schema_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            names = []

    required = [
        ARTIFACT_DIR / "logistic_regression.joblib",
        ARTIFACT_DIR / "random_forest.joblib",
        ARTIFACT_DIR / "feature_names.json",
    ]
    missing = [p.name for p in required if not p.is_file()]

    metrics = {}
    metrics_path = ARTIFACT_DIR / "metrics.json"
    if metrics_path.is_file():
        try:
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            metrics = {}

    return {
        "models_available": not missing,
        "artifact_directory": str(ARTIFACT_DIR),
        "missing_artifacts": missing,
        "feature_count": len(names),
        "feature_names": names,
        "offline_benchmark": metrics.get("models", {}),
        "ensemble_benchmark": metrics.get("ensemble_average_probability"),
        "benchmark_split": metrics.get("split"),
    }


@lru_cache(maxsize=1)
def load_models():
    info = model_info()
    if not info["models_available"]:
        missing = ", ".join(info["missing_artifacts"])
        raise ModelsUnavailableError(
            f"Trained model artifacts are unavailable: {missing}. "
            "Deploy them to TRACEGATE_ARTIFACT_DIR."
        )

    names = json.loads(
        (ARTIFACT_DIR / "feature_names.json").read_text(encoding="utf-8")
    )
    if not names or len(names) != len(set(names)):
        raise ModelsUnavailableError("Feature schema is empty or duplicated.")

    try:
        logistic = joblib.load(ARTIFACT_DIR / "logistic_regression.joblib")
        forest = joblib.load(ARTIFACT_DIR / "random_forest.joblib")
    except Exception as exc:
        raise ModelsUnavailableError(
            f"Could not load trained model artifacts: {exc}"
        ) from exc

    for model in (logistic, forest):
        if not hasattr(model, "predict_proba"):
            raise ModelsUnavailableError("A model lacks predict_proba().")
        if 1 not in list(model.classes_):
            raise ModelsUnavailableError(
                "A model does not contain the malicious class (1)."
            )

    return names, logistic, forest


def predict_models(features):
    names, logistic, forest = load_models()

    unknown = sorted(set(features) - set(names))
    if unknown:
        raise ValueError(
            "Unknown feature names: " + ", ".join(unknown[:10])
        )

    values = []
    missing = []
    observed = 0

    for name in names:
        value = features.get(name)
        if value is None:
            values.append(np.nan)
            missing.append(name)
            continue

        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Feature {name!r} must be numeric or null.") from exc

        if not np.isfinite(number):
            raise ValueError(f"Feature {name!r} must be finite or null.")

        values.append(number)
        observed += 1

    if observed == 0:
        return {
            "prediction_available": False,
            "prediction_unavailable_reason": "NO_NUMERIC_FEATURES",
            "logistic_probability_malicious": None,
            "random_forest_probability_malicious": None,
            "ensemble_probability_malicious": None,
            "logistic_label": None,
            "random_forest_label": None,
            "probability_gap": None,
            "model_disagreement": False,
            "missing_features": missing,
            "feature_count": len(names),
            "provided_feature_count": observed,
        }

    row = np.asarray(values, dtype=float).reshape(1, -1)

    def malicious_probability(model):
        classes = list(model.classes_)
        return float(model.predict_proba(row)[0][classes.index(1)])

    try:
        p_logistic = malicious_probability(logistic)
        p_forest = malicious_probability(forest)
    except ValueError:
        # Never replace unknown measurements with zero or a guessed imputation.
        # Some trained pipelines can consume NaN and still score; preserve that
        # behavior, but fail closed when the trained estimators reject it.
        if not missing:
            raise
        return {
            "prediction_available": False,
            "prediction_unavailable_reason": "MODEL_DOES_NOT_SUPPORT_MISSING_FEATURES",
            "logistic_probability_malicious": None,
            "random_forest_probability_malicious": None,
            "ensemble_probability_malicious": None,
            "logistic_label": None,
            "random_forest_label": None,
            "probability_gap": None,
            "model_disagreement": False,
            "missing_features": missing,
            "feature_count": len(names),
            "provided_feature_count": observed,
        }
    threshold = 0.5
    label_logistic = int(p_logistic >= threshold)
    label_forest = int(p_forest >= threshold)
    gap = abs(p_logistic - p_forest)
    disagreement = label_logistic != label_forest or gap >= 0.25

    return {
        "prediction_available": True,
        "prediction_unavailable_reason": None,
        "logistic_probability_malicious": p_logistic,
        "random_forest_probability_malicious": p_forest,
        "ensemble_probability_malicious": (p_logistic + p_forest) / 2,
        "logistic_label": label_logistic,
        "random_forest_label": label_forest,
        "probability_gap": gap,
        "model_disagreement": disagreement,
        "missing_features": missing,
        "feature_count": len(names),
        "provided_feature_count": observed,
    }
