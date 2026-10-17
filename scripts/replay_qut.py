import argparse
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from zipfile import ZipFile

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)
from sklearn.model_selection import StratifiedGroupKFold

ARCHIVE = Path.home() / "datasets/qut-dv25/QUT-DV25_Datasets.zip"
ARTIFACTS = Path.home() / "tracegate-live/artifacts"
API = "http://127.0.0.1:8001"
PREFIX = "QUT-DV25_Datasets/QUT-DV25_Processed_Datasets/"


def request_json(path, payload=None, timeout=20):
    body = None if payload is None else json.dumps(
        payload, allow_nan=False
    ).encode("utf-8")
    req = urllib.request.Request(
        API + path,
        data=body,
        headers={"Content-Type": "application/json"},
        method="GET" if body is None else "POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"API {path}: HTTP {exc.code}: {detail}") from exc


def main(limit):
    if not ARCHIVE.is_file():
        raise FileNotFoundError(f"Missing archive: {ARCHIVE}")

    feature_path = ARTIFACTS / "feature_names.json"
    names = json.loads(feature_path.read_text(encoding="utf-8"))
    if len(names) != 48:
        raise RuntimeError(f"Expected 48 model features, got {len(names)}")

    # Load only the six processed CSVs directly from the ZIP.
    frames = {}
    labels = {}
    with ZipFile(ARCHIVE) as z:
        csvs = sorted(
            n for n in z.namelist()
            if n.startswith(PREFIX) and n.lower().endswith(".csv")
        )
        if len(csvs) != 6:
            raise RuntimeError(f"Expected six processed CSVs; found {len(csvs)}")

        for filename in csvs:
            with z.open(filename) as source:
                frame = pd.read_csv(source, low_memory=False)

            frame.columns = [str(c).strip() for c in frame.columns]
            frame["Package_Name"] = frame["Package_Name"].astype(str).str.strip()
            frame["Level"] = pd.to_numeric(frame["Level"], errors="raise").astype(int)

            tag = (
                Path(filename).parent.name
                .replace("QUT-DV25_", "")
                .replace("_Traces", "")
            )
            if frame["Package_Name"].duplicated().any():
                raise RuntimeError(f"Duplicate package IDs in {tag}")

            frames[tag] = frame
            labels[tag] = frame.set_index("Package_Name")["Level"]

    common = sorted(set.intersection(
        *(set(series.index) for series in labels.values())
    ))
    if len(common) < 100:
        raise RuntimeError(f"Unexpectedly small cross-trace overlap: {len(common)}")

    y_series = labels["Filetop"].reindex(common)
    for tag, series in labels.items():
        aligned = series.reindex(common)
        if aligned.isna().any() or not aligned.equals(y_series):
            raise RuntimeError(f"Missing or conflicting labels in {tag}")

    # Construct features in the exact order stored beside the trained models.
    X = pd.DataFrame(index=common)
    for feature in names:
        tag, column = feature.split("__", 1)
        if tag not in frames:
            raise RuntimeError(f"Trained feature source missing: {tag}")

        # Match the same column-name normalization used during training.
        matches = [
            raw for raw in frames[tag].columns
            if str(raw).strip().replace(" ", "_") == column
        ]
        if len(matches) != 1:
            raise RuntimeError(
                f"Expected one source column for {feature}; found {matches}"
            )

        table = frames[tag].set_index("Package_Name").reindex(common)
        X[feature] = pd.to_numeric(
            table[matches[0]], errors="coerce"
        ).to_numpy()

    X = X.replace([np.inf, -np.inf], np.nan)
    y = y_series.to_numpy(dtype=int)
    if not set(np.unique(y)) <= {0, 1}:
        raise RuntimeError("Unexpected dataset labels")

    # Recreate the same deterministic grouped holdout used for training.
    groups = np.array([re.sub(r"-\d.*$", "", name) for name in common])
    splitter = StratifiedGroupKFold(
        n_splits=5, shuffle=True, random_state=42
    )
    train_idx, test_idx = next(splitter.split(X, y, groups))
    if set(groups[train_idx]) & set(groups[test_idx]):
        raise RuntimeError("Package-group leakage detected")

    # Pick a balanced sample from the held-out fold.
    rng = np.random.default_rng(42)
    half = limit // 2
    selected = []
    for label in (0, 1):
        candidates = test_idx[y[test_idx] == label]
        take = min(half, len(candidates))
        selected.extend(rng.choice(candidates, size=take, replace=False).tolist())

    if len(selected) < limit:
        remaining = np.array(sorted(set(test_idx) - set(selected)), dtype=int)
        need = min(limit - len(selected), len(remaining))
        selected.extend(rng.choice(remaining, size=need, replace=False).tolist())

    rng.shuffle(selected)
    if not selected:
        raise RuntimeError("No held-out records selected")

    print("COMMON_PACKAGES:", len(common))
    print("FEATURES:", len(names))
    print("HELD_OUT_FOLD:", len(test_idx), "records")
    print("REPLAY_SAMPLE:", len(selected), "records")
    print("NOTE: historical labeled traces replayed through the API; not live package execution.")

    health = request_json("/health")
    if health.get("model_ready") is not True:
        raise RuntimeError(f"Trained model artifacts not ready: {health}")

    true_labels, predictions, scores = [], [], []
    latencies, reviews, disagreements = [], 0, 0
    errors = []

    for count, idx in enumerate(selected, 1):
        feature_values = {}
        for name, value in X.iloc[idx].items():
            feature_values[name] = (
                None if pd.isna(value) else float(value)
            )

        package = str(common[idx])
        payload = {
            "event_id": f"qut-replay-{count:04d}-{idx}",
            "package_ref": "QUT-DV25:" + package[:180],
            "features": feature_values,
            "evidence": {
                "file_activity": "present",
                "process_execution": "present",
                "system_calls": "present",
                "network_behavior": "present",
            },
            "integrity_alerts": [],
        }

        start = time.perf_counter()
        try:
            result = request_json("/api/predict", payload)
        except Exception as exc:
            errors.append({"row": count, "error": str(exc)[:500]})
            if len(errors) >= 5:
                break
            continue
        latencies.append((time.perf_counter() - start) * 1000)

        probability = float(result["model_probabilities"]["ensemble"])
        score_label = int(probability >= 0.5)
        truth = int(y[idx])
        true_labels.append(truth)
        predictions.append(score_label)
        scores.append(probability)
        reviews += result["decision"] == "REVIEW_REQUIRED"
        disagreements += bool(result["model_disagreement"])

        if count % 25 == 0:
            print(f"Processed {count}/{len(selected)} held-out records")

    if len(true_labels) < max(20, int(len(selected) * 0.95)):
        raise RuntimeError(
            f"Too few successful API predictions ({len(true_labels)}); "
            f"first errors: {errors[:3]}"
        )

    report = {
        "dataset": "QUT-DV25 processed runtime traces",
        "evaluation_type": "API replay on the training script's held-out grouped fold",
        "source_is_live_telemetry": False,
        "label_mapping": {"0": "benign", "1": "malicious"},
        "successful_requests": len(true_labels),
        "request_errors": errors,
        "features": len(names),
        "metrics": {
            "accuracy": round(float(accuracy_score(true_labels, predictions)), 4),
            "precision_malicious": round(float(
                precision_score(true_labels, predictions, zero_division=0)
            ), 4),
            "recall_malicious": round(float(
                recall_score(true_labels, predictions, zero_division=0)
            ), 4),
            "f1_malicious": round(float(
                f1_score(true_labels, predictions, zero_division=0)
            ), 4),
            "roc_auc": round(float(roc_auc_score(true_labels, scores)), 4),
            "confusion_matrix_labels_0_1": confusion_matrix(
                true_labels, predictions, labels=[0, 1]
            ).tolist(),
        },
        "api_latency_ms": {
            "mean": round(float(np.mean(latencies)), 2),
            "p50": round(float(np.percentile(latencies, 50)), 2),
            "p95": round(float(np.percentile(latencies, 95)), 2),
            "max": round(float(np.max(latencies)), 2),
        },
        "review_rate": round(reviews / len(true_labels), 4),
        "model_disagreement_rate": round(disagreements / len(true_labels), 4),
        "limitations": [
            "This is recorded-trace API replay, not live untrusted-package execution.",
            "The grouped holdout is one fold; independent external validation remains necessary.",
            "Model scores do not establish that a package is safe.",
        ],
    }

    # Confirm that audit history contains our newly created events.
    audit = request_json("/api/audit?limit=200")
    submitted_ids = {
        f"qut-replay-{i:04d}-{idx}" for i, idx in enumerate(selected, 1)
        if i <= len(selected)
    }
    audit_ids = {row.get("event_id") for row in audit.get("events", [])}
    matched = len(submitted_ids & audit_ids)
    report["audit_events_found_in_latest_200"] = matched

    output = ARTIFACTS / "api_replay_metrics.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n===== API REPLAY RESULTS =====")
    print(json.dumps(report, indent=2))
    print("\nSAVED_REPORT:", output)

    if matched < min(10, len(true_labels)):
        raise RuntimeError(
            f"Audit verification failed: found {matched} replay events."
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=200)
    args = parser.parse_args()
    if args.limit < 20 or args.limit > 500:
        raise SystemExit("--limit must be between 20 and 500")
    main(args.limit)
