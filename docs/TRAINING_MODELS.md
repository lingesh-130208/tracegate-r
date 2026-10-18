# Reproducible QUT-DV25 model training

This utility trains TraceGate-R's two classifiers from the public QUT-DV25 processed trace dataset hosted by Harvard Dataverse (DOI: https://doi.org/10.7910/DVN/LBMXJY; CC0 1.0 Universal). The archive is approximately 2.14 GB.

## Install and run

From the repository root, install the normal requirements plus the optional training dependency:

    python -m pip install -r requirements-training.txt

Download the official archive if absent, verify its publisher checksum, train the models, evaluate a grouped holdout, and validate the serialized artifacts:

    python scripts/train_qut_models.py --download

Default archive: ~/datasets/qut-dv25/QUT-DV25_Datasets.zip.
Default artifact directory: TRACEGATE_ARTIFACT_DIR or ~/tracegate-live/artifacts.
Use --archive and --output-dir to select explicit paths.

The utility reads only needed columns from the six processed trace tables; validates the 48-feature schema and consistent labels; groups package families to keep related versions out of both train and holdout; trains Logistic Regression and Random Forest pipelines; reports accuracy, malicious-class precision/recall/F1, ROC AUC, and the confusion matrix; reloads serialized models and smoke-tests inference; then writes artifact hashes, dataset provenance, and dependency versions.

Generated artifacts are logistic_regression.joblib, random_forest.joblib, feature_names.json, metrics.json, and training_manifest.json. Output must be a new or empty directory. Existing files are not overwritten, and generated binaries or dataset archives must not be committed to Git.

## Interpretation limits

These metrics apply only to the held-out QUT-DV25 processed dataset. They do not prove live malware-detection performance or feature parity with LinuxONE telemetry. The collector's feature parity remains unvalidated. Missing-value imputation enables a model to calculate a result but does not make incomplete evidence reliable; the application's evidence gate must continue routing incomplete or integrity-alerted observations to REVIEW_REQUIRED.

## LinuxONE preflight

After independently verifying the candidate SSH host identity, run:

    python scripts/linuxone_preflight.py

The script emits read-only JSON diagnostics for system architecture, NNPA flag visibility, bpftrace availability and permission/tracepoint status, model artifact presence, and candidate loopback ports 8001/8002. It does not contact port 8000, attach a trace probe, deploy, restart services, write files, or change permissions. A successful tracepoint listing is not proof of real capture, and the NNPA flag is not proof of accelerator execution.
