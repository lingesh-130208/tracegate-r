# TraceGate-R runtime telemetry and offline explanations

## Implemented and tested locally

- The release schema contains 48 ordered features in `data/model_feature_names.json`.
- Procfs and bpftrace collectors preserve unmeasured values as `null`. Their tests cover malformed records, partial probe coverage, missing TCP observations, platform guards, and schema ordering.
- The LinuxONE collector has a telemetry-only mode that writes a local report without an API call, model score, verdict, or SQLite audit entry. Its actual kernel capture is **not** verified from this Windows workspace; see [BPFTRACE_RUNTIME_SENSOR.md](BPFTRACE_RUNTIME_SENSOR.md) for the owner-reported s390x run and demo checks.
- The evidence gate returns `REVIEW_REQUIRED` for missing/incomplete evidence, unknown verdicts, model disagreement alerts, or integrity alerts.
- The prediction API stores every schema-valid observation in SQLite, including partial vectors and hosts without trained model artifacts. Unscored events retain null probabilities and labels, record the unavailability reason and missing feature names, and receive an `unknown` verdict with `REVIEW_REQUIRED`.
- Offline explanations are generated deterministically from allow-listed audit fields, saved in a separate SQLite database, and do not change the formal decision or require an external provider.

## Model readiness in this checkout

No trained model artifacts were found in the repository or at the expected local artifact path. `TRACEGATE_ARTIFACT_DIR` is not set. The local `/api/model-info` therefore reports models unavailable; predictions cannot be scored here. Schema-valid requests are still recorded as unscored audit events. Do not infer current server readiness from old deployment notes. Verify `/health` and `/api/model-info` on the target host before enabling the scored collector path.

When valid models are loaded, the service currently maps each malicious-class probability at or above `0.5` to the model label `malicious`. This threshold has not been calibrated or reproduced against the missing training dataset; it is a label convention, not a validated malware-detection threshold. The evidence gate remains a separate decision layer.

## Runtime limitations

- The generic PID collector does not implement the complete QUT-DV25 feature-extraction pipeline or establish parity with its package-install windows and grouping rules.
- Runtime feature vectors can be partial. A numeric model score, if available from deployed estimators, remains provisional until parity and missing-feature behavior are validated.
- The LinuxONE telemetry-only flow reports observations locally; it does not send them to the API, populate the SQLite audit trail, or make a malware classification.
- The collector is not an isolation sandbox or production endpoint-detection-and-response agent.
- Offline replay metrics, if present in an artifact bundle, are not evidence of live detection accuracy.
