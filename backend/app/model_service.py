"""Load and run the trained TraceGate-R models."""
import hashlib
import json
import os
from functools import lru_cache
from numbers import Real
from pathlib import Path

import joblib
import numpy as np

ARTIFACT_DIR = Path(os.environ.get(
    "TRACEGATE_ARTIFACT_DIR",
    str(Path.home() / "tracegate-live" / "artifacts"),
))
PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_SCHEMA_PATH = PROJECT_ROOT / "data" / "model_feature_names.json"
EXPECTED_FEATURE_COUNT = 48


class ModelsUnavailableError(RuntimeError):
    pass


class ModelOutputInvalidError(RuntimeError):
    """A loaded estimator produced a malformed probability vector."""


class ModelPredictionFailedError(RuntimeError):
    """A loaded estimator failed during prediction for an unexpected reason."""


def _read_schema(path: Path):
    """Read a feature-name list and reject malformed or ambiguous schemas."""
    try:
        names = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "FEATURE_SCHEMA_UNREADABLE"
    if (
        not isinstance(names, list)
        or not names
        or any(not isinstance(name, str) or not name.strip() for name in names)
        or len(names) != len(set(names))
    ):
        return None, "FEATURE_SCHEMA_INVALID"
    return names, None


def release_feature_names():
    """Return the checked-in release schema independently of model availability."""
    names, error = _read_schema(EXPECTED_SCHEMA_PATH)
    if error or len(names) != EXPECTED_FEATURE_COUNT:
        raise ModelsUnavailableError("The checked-in release feature schema is invalid.")
    return names


def release_schema_sha256():
    try:
        return hashlib.sha256(EXPECTED_SCHEMA_PATH.read_bytes()).hexdigest()
    except OSError:
        return None


def _artifact_state():
    expected_names, expected_error = _read_schema(EXPECTED_SCHEMA_PATH)
    artifact_schema_path = ARTIFACT_DIR / "feature_names.json"
    if artifact_schema_path.is_file():
        artifact_names, artifact_error = _read_schema(artifact_schema_path)
    else:
        artifact_names, artifact_error = None, "ARTIFACT_FEATURE_SCHEMA_MISSING"
    required = (
        "logistic_regression.joblib",
        "random_forest.joblib",
        "feature_names.json",
    )
    missing = [name for name in required if not (ARTIFACT_DIR / name).is_file()]

    schema_error = expected_error or artifact_error
    if schema_error is None:
        if len(expected_names) != EXPECTED_FEATURE_COUNT:
            schema_error = "RELEASE_SCHEMA_FEATURE_COUNT_MISMATCH"
        elif artifact_names != expected_names:
            schema_error = "ARTIFACT_SCHEMA_MISMATCH"

    return {
        "expected_names": expected_names or [],
        "artifact_names": artifact_names,
        "missing_artifacts": missing,
        "schema_valid": schema_error is None,
        "schema_error": schema_error,
    }


def _validate_estimator(model, names):
    if not callable(getattr(model, "predict_proba", None)):
        raise ModelsUnavailableError("A trained model lacks predict_proba().")

    classes = getattr(model, "classes_", None)
    try:
        labels = list(classes)
        valid_labels = len(labels) == 2 and set(labels) == {0, 1}
    except (TypeError, ValueError):
        labels = []
        valid_labels = False
    if not valid_labels:
        raise ModelsUnavailableError(
            "A trained model must expose both expected classes, 0 and 1."
        )

    feature_count = getattr(model, "n_features_in_", None)
    if feature_count is not None:
        raw_feature_count = feature_count
        try:
            feature_count = int(feature_count)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ModelsUnavailableError(
                "A trained model exposes an invalid feature count."
            ) from exc
        if (
            isinstance(raw_feature_count, bool)
            or feature_count != len(names)
            or raw_feature_count != feature_count
        ):
            raise ModelsUnavailableError(
                "A trained model feature count differs from the release schema."
            )

    trained_names = getattr(model, "feature_names_in_", None)
    if trained_names is not None and list(trained_names) != names:
        raise ModelsUnavailableError(
            "A trained model feature order differs from the release schema."
        )


@lru_cache(maxsize=1)
def load_models():
    state = _artifact_state()
    if state["missing_artifacts"]:
        missing = ", ".join(state["missing_artifacts"])
        raise ModelsUnavailableError(
            f"Trained model artifacts are unavailable: {missing}. "
            "Deploy them to TRACEGATE_ARTIFACT_DIR."
        )
    if state["schema_error"]:
        raise ModelsUnavailableError(
            f"Trained model feature schema is invalid: {state['schema_error']}."
        )

    names = state["expected_names"]
    try:
        logistic = joblib.load(ARTIFACT_DIR / "logistic_regression.joblib")
        forest = joblib.load(ARTIFACT_DIR / "random_forest.joblib")
    except Exception as exc:
        # Do not expose paths or pickle loader details through the public API.
        raise ModelsUnavailableError(
            "Could not load the configured trained model artifacts."
        ) from exc

    _validate_estimator(logistic, names)
    _validate_estimator(forest, names)
    return names, logistic, forest


def model_info():
    state = _artifact_state()
    metrics = {}
    metrics_path = ARTIFACT_DIR / "metrics.json"
    if metrics_path.is_file():
        try:
            candidate = json.loads(metrics_path.read_text(encoding="utf-8"))
            if isinstance(candidate, dict):
                metrics = candidate
        except (OSError, json.JSONDecodeError):
            pass

    info = {
        "models_available": False,
        "missing_artifacts": state["missing_artifacts"],
        "feature_count": len(state["expected_names"]),
        "feature_names": state["expected_names"],
        "schema_valid": state["schema_valid"],
        "schema_error": state["schema_error"],
        "offline_benchmark": metrics.get("models", {}),
        "ensemble_benchmark": metrics.get("ensemble_average_probability"),
        "benchmark_split": metrics.get("split"),
    }
    if state["missing_artifacts"]:
        info["model_readiness_error"] = "Required model artifacts are missing."
    elif state["schema_error"]:
        info["model_readiness_error"] = (
            f"Configured model schema is invalid: {state['schema_error']}."
        )
    else:
        try:
            load_models()
        except ModelsUnavailableError as exc:
            info["model_readiness_error"] = str(exc)
        else:
            info["models_available"] = True
            info["model_readiness_error"] = None
    return info


def predict_models(features):
    names, logistic, forest = load_models()

    if not isinstance(features, dict):
        raise ValueError("features must be an object keyed by feature name.")
    if any(not isinstance(name, str) for name in features):
        raise ValueError("Feature names must be strings.")
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

        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError(f"Feature {name!r} must be a number or null.")
        try:
            number = float(value)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ValueError(f"Feature {name!r} must be a finite number or null.") from exc
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
        try:
            raw_probabilities = model.predict_proba(row)
        except ValueError as exc:
            if missing:
                raise ModelPredictionFailedError("Estimator rejected the incomplete feature row.") from exc
            raise ModelPredictionFailedError("Estimator failed during prediction.") from exc
        except Exception as exc:
            raise ModelPredictionFailedError("Estimator failed during prediction.") from exc
        try:
            probabilities = np.asarray(raw_probabilities, dtype=float)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ModelOutputInvalidError from exc
        if probabilities.shape != (1, len(classes)):
            raise ModelOutputInvalidError("Estimator returned an invalid probability shape.")
        values = probabilities[0]
        if (
            not np.isfinite(values).all()
            or (values < 0).any()
            or (values > 1).any()
            or not np.isclose(values.sum(), 1.0, rtol=1e-5, atol=1e-5)
        ):
            raise ModelOutputInvalidError("Estimator returned invalid probabilities.")
        return float(values[classes.index(1)])

    try:
        p_logistic = malicious_probability(logistic)
        p_forest = malicious_probability(forest)
    except ModelOutputInvalidError:
        return {
            "prediction_available": False,
            "prediction_unavailable_reason": "MODEL_OUTPUT_INVALID",
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
    except ModelPredictionFailedError:
        # Never replace unknown measurements with zero or a guessed imputation.
        # Keep expected model failures distinct from malformed output and input.
        reason = (
            "MODEL_DOES_NOT_SUPPORT_MISSING_FEATURES"
            if missing
            else "MODEL_PREDICTION_FAILED"
        )
        return {
            "prediction_available": False,
            "prediction_unavailable_reason": reason,
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
