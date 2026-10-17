from unittest import TestCase
from unittest.mock import patch

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
