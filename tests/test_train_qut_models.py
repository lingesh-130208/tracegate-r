import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from scripts import train_qut_models as trainer

SCHEMA = trainer.names_from(Path(__file__).parents[1] / "data" / "model_feature_names.json")


def make_frames(count: int = 100) -> dict[str, pd.DataFrame]:
    rng = np.random.default_rng(19)
    packages = [f"pkg{i:03d}-1.0" for i in range(count)]
    labels = np.array([i % 2 for i in range(count)], dtype=int)
    tags = {name.split("__", 1)[0] for name in SCHEMA} | {"Pattern"}
    frames = {}
    for tag in tags:
        data = {"Package_Name": packages, "Level": labels}
        for index, name in enumerate(SCHEMA):
            feature_tag, column = name.split("__", 1)
            if feature_tag == tag:
                data[column] = labels * 2.0 + rng.normal(0.0, 0.4, size=count) + index / 100
        frames[tag] = pd.DataFrame(data)
    return frames


def test_feature_matrix_preserves_schema_order_and_labels():
    X, y, packages = trainer.matrix(make_frames(), SCHEMA)
    assert list(X.columns) == SCHEMA
    assert len(X) == len(y) == len(packages) == 100
    assert set(np.unique(y)) == {0, 1}
    assert np.isfinite(X.to_numpy(dtype=float)).all()


def test_feature_matrix_rejects_conflicting_labels():
    frames = make_frames()
    frames["TCP"].loc[0, "Level"] = 1 - int(frames["TCP"].loc[0, "Level"])
    with pytest.raises(ValueError, match="Conflicting labels"):
        trainer.matrix(frames, SCHEMA)


def test_feature_matrix_rejects_entirely_missing_feature():
    frames = make_frames()
    first = SCHEMA[0].split("__", 1)[1]
    frames["Filetop"][first] = np.nan
    with pytest.raises(ValueError, match="All-missing features"):
        trainer.matrix(frames, SCHEMA)


def test_grouped_holdout_has_no_package_family_leakage():
    X, y, packages = trainer.matrix(make_frames(), SCHEMA)
    groups = np.asarray([trainer.re.sub(r"-\d.*$", "", str(p)) for p in packages])
    train, holdout = next(
        trainer.StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=trainer.SEED)
        .split(X, y, groups)
    )
    assert not set(groups[train]) & set(groups[holdout])
    assert set(np.unique(y[train])) == {0, 1}
    assert set(np.unique(y[holdout])) == {0, 1}


def test_pipelines_fit_missing_features_and_emit_valid_probabilities():
    X, y, _ = trainer.matrix(make_frames(), SCHEMA)
    X = X.to_numpy(dtype=float)
    X[0, 0] = np.nan
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    models = (
        Pipeline([("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
                  ("scale", StandardScaler()),
                  ("classifier", LogisticRegression(max_iter=3000, class_weight="balanced", random_state=trainer.SEED))]),
        Pipeline([("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
                  ("classifier", RandomForestClassifier(n_estimators=20, min_samples_leaf=2,
                       class_weight="balanced_subsample", random_state=trainer.SEED, n_jobs=-1))]),
    )
    for model in models:
        model.fit(X, y)
        probabilities = model.predict_proba(X[:5])
        assert list(model.classes_) == [0, 1]
        assert model.n_features_in_ == 48
        assert probabilities.shape == (5, 2)
        assert np.isfinite(probabilities).all()
        assert np.allclose(probabilities.sum(axis=1), 1.0)


def test_metrics_reject_nonfinite_probabilities():
    with pytest.raises(ValueError, match="Invalid model probabilities"):
        trainer.metrics(np.array([0, 1]), np.array([0.2, np.nan]))


def test_schema_requires_48_unique_names(tmp_path):
    path = tmp_path / "schema.json"
    path.write_text(json.dumps(SCHEMA[:-1]), encoding="utf-8")
    with pytest.raises(ValueError, match="48 unique ordered"):
        trainer.names_from(path)


def test_training_packaging_roundtrip_uses_test_fixture_and_never_overwrites(tmp_path, monkeypatch):
    archive = tmp_path / "fixture.zip"
    archive.write_bytes(b"test fixture only")
    monkeypatch.setattr(trainer, "digest", lambda _path, alg="sha256": trainer.MD5 if alg == "md5" else "test-digest")
    monkeypatch.setattr(trainer, "read_frames", lambda *_: make_frames())
    output = tmp_path / "artifacts"
    trainer.train(archive, output, Path(__file__).parents[1] / "data" / "model_feature_names.json")
    for name in trainer.FILES:
        assert (output / name).is_file()
    manifest = json.loads((output / "training_manifest.json").read_text(encoding="utf-8"))
    assert manifest["models_smoke_tested_after_serialization"] is True
    assert manifest["training_data_is_live_telemetry"] is False
    assert manifest["evaluation"]["package_group_overlap"] == 0
    with pytest.raises(FileExistsError, match="must be new or empty"):
        trainer.train(archive, output, Path(__file__).parents[1] / "data" / "model_feature_names.json")
