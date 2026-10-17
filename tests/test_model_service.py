import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from backend.app import model_service
from backend.app.model_service import predict_models


class FakeModel:
    classes_ = [0, 1]

    def __init__(self, probability, supports_missing=True):
        self.probability = probability
        self.supports_missing = supports_missing

    def predict_proba(self, row):
        import numpy as np
        if np.isnan(row).any() and not self.supports_missing:
            raise ValueError("Input X contains NaN")
        return [[1 - self.probability, self.probability]]


class ModelServiceMissingFeatureTests(TestCase):
    def test_ensemble_is_arithmetic_mean_and_reports_model_disagreement(self):
        models = (["feature_a"], FakeModel(0.3), FakeModel(0.7))
        with patch("backend.app.model_service.load_models", return_value=models):
            result = predict_models({"feature_a": 1.0})
        self.assertTrue(result["prediction_available"])
        self.assertEqual(result["logistic_probability_malicious"], 0.3)
        self.assertEqual(result["random_forest_probability_malicious"], 0.7)
        self.assertEqual(result["ensemble_probability_malicious"], 0.5)
        self.assertEqual(result["logistic_label"], 0)
        self.assertEqual(result["random_forest_label"], 1)
        self.assertAlmostEqual(result["probability_gap"], 0.4)
        self.assertTrue(result["model_disagreement"])

    def test_same_labels_can_still_disagree_when_probability_gap_reaches_threshold(self):
        models = (["feature_a"], FakeModel(0.1), FakeModel(0.4))
        with patch("backend.app.model_service.load_models", return_value=models):
            result = predict_models({"feature_a": 1.0})
        self.assertEqual(result["logistic_label"], 0)
        self.assertEqual(result["random_forest_label"], 0)
        self.assertAlmostEqual(result["probability_gap"], 0.3)
        self.assertTrue(result["model_disagreement"])

    def test_trained_pipeline_that_accepts_missing_values_still_scores(self):
        models = (["feature_a", "feature_b"], FakeModel(0.2), FakeModel(0.4))
        with patch("backend.app.model_service.load_models", return_value=models):
            result = predict_models({"feature_a": 1.0, "feature_b": None})
        self.assertTrue(result["prediction_available"])
        self.assertAlmostEqual(result["ensemble_probability_malicious"], 0.3)
        self.assertEqual(result["missing_features"], ["feature_b"])

    def test_model_rejecting_missing_values_returns_no_fabricated_score(self):
        models = (["feature_a", "feature_b"], FakeModel(0.2, False), FakeModel(0.4))
        with patch("backend.app.model_service.load_models", return_value=models):
            result = predict_models({"feature_a": 1.0, "feature_b": None})
        self.assertFalse(result["prediction_available"])
        self.assertEqual(result["prediction_unavailable_reason"], "MODEL_DOES_NOT_SUPPORT_MISSING_FEATURES")
        self.assertIsNone(result["ensemble_probability_malicious"])

    def test_all_missing_features_are_unscorable(self):
        models = (["feature_a", "feature_b"], FakeModel(0.2), FakeModel(0.4))
        with patch("backend.app.model_service.load_models", return_value=models):
            result = predict_models({"feature_a": None, "feature_b": None})
        self.assertFalse(result["prediction_available"])
        self.assertEqual(result["provided_feature_count"], 0)
        self.assertIsNone(result["logistic_probability_malicious"])

    def test_string_boolean_and_non_finite_values_are_rejected(self):
        models = (["feature_a"], FakeModel(0.2), FakeModel(0.4))
        for value in ("1.0", True, float("nan"), float("inf")):
            with self.subTest(value=value):
                with patch.object(model_service, "load_models", return_value=models):
                    with self.assertRaises(ValueError):
                        predict_models({"feature_a": value})

    def test_invalid_estimator_probabilities_are_not_returned_as_a_score(self):
        class InvalidModel(FakeModel):
            def predict_proba(self, _row):
                return [[0.8, 0.8]]

        models = (["feature_a"], InvalidModel(0.2), FakeModel(0.4))
        with patch("backend.app.model_service.load_models", return_value=models):
            result = predict_models({"feature_a": 1.0})
        self.assertFalse(result["prediction_available"])
        self.assertEqual(result["prediction_unavailable_reason"], "MODEL_OUTPUT_INVALID")
        self.assertIsNone(result["ensemble_probability_malicious"])

    def test_unexpected_estimator_failure_returns_null_probabilities(self):
        class FailingModel(FakeModel):
            def predict_proba(self, _row):
                raise RuntimeError("private estimator detail")

        models = (["feature_a"], FailingModel(0.2), FakeModel(0.4))
        with patch("backend.app.model_service.load_models", return_value=models):
            result = predict_models({"feature_a": 1.0})
        self.assertFalse(result["prediction_available"])
        self.assertEqual(result["prediction_unavailable_reason"], "MODEL_PREDICTION_FAILED")
        self.assertIsNone(result["logistic_probability_malicious"])
        self.assertIsNone(result["random_forest_probability_malicious"])
        self.assertIsNone(result["ensemble_probability_malicious"])


class ReadyModel:
    classes_ = [0, 1]
    n_features_in_ = 48

    def predict_proba(self, _row):
        return [[0.7, 0.3]]


class ModelArtifactReadinessTests(TestCase):
    def setUp(self):
        self.schema = json.loads(
            model_service.EXPECTED_SCHEMA_PATH.read_text(encoding="utf-8")
        )

    def _bundle(self, directory, names=None):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "feature_names.json").write_text(
            json.dumps(self.schema if names is None else names), encoding="utf-8"
        )
        (directory / "logistic_regression.joblib").write_bytes(b"test fixture")
        (directory / "random_forest.joblib").write_bytes(b"test fixture")

    def _info_with_models(self, directory, models):
        with patch.object(model_service, "ARTIFACT_DIR", Path(directory)), patch.object(
            model_service.joblib, "load", side_effect=models
        ):
            model_service.load_models.cache_clear()
            try:
                return model_service.model_info()
            finally:
                model_service.load_models.cache_clear()

    def test_ready_requires_exact_release_schema_and_compatible_estimators(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._bundle(temp_dir)
            info = self._info_with_models(temp_dir, [ReadyModel(), ReadyModel()])
        self.assertTrue(info["schema_valid"])
        self.assertTrue(info["models_available"])
        self.assertEqual(info["feature_count"], 48)
        self.assertEqual(model_service.release_feature_names(), self.schema)

    def test_schema_order_mismatch_keeps_models_unavailable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._bundle(temp_dir, list(reversed(self.schema)))
            info = self._info_with_models(temp_dir, [ReadyModel(), ReadyModel()])
        self.assertFalse(info["schema_valid"])
        self.assertEqual(info["schema_error"], "ARTIFACT_SCHEMA_MISMATCH")
        self.assertFalse(info["models_available"])

    def test_model_feature_count_mismatch_keeps_models_unavailable(self):
        for width in (47, 48.5):
            class WrongWidthModel(ReadyModel):
                n_features_in_ = width

            with self.subTest(width=width), tempfile.TemporaryDirectory() as temp_dir:
                self._bundle(temp_dir)
                info = self._info_with_models(temp_dir, [WrongWidthModel(), ReadyModel()])
            self.assertFalse(info["models_available"])
            self.assertIn("feature count differs", info["model_readiness_error"])
