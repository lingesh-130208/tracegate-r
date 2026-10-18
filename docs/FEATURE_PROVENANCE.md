# Feature provenance and parity status

`data/feature_provenance.json` is the machine-readable mapping for the exact
ordered 48-feature release schema. Regenerate it with:

```bash
python scripts/build_feature_provenance.py
python scripts/build_feature_provenance.py --check
```

The manifest describes what the current collectors actually measure, their
units and capture windows, required process/probe context, and when each value
must remain `null`. It separates those implementation facts from training-time
definitions. Schema digests normalize CRLF and CR line endings to LF so Windows
archives and Linux checkouts report the same digest for the same ordered schema.

## Training-time definitions

This checkout contains the feature-name list and an API replay utility, but it
does not contain the QUT-DV25 archive or a model-training implementation. The
replay utility expects the archive at
`~/datasets/qut-dv25/QUT-DV25_Datasets.zip`; that configured local path was
absent during this audit. Consequently the training source columns,
transformations, measurement units, and aggregation windows cannot currently be
independently established from the repository. Each manifest record marks its
training definition as unavailable and its runtime parity as
`NOT_VALIDATED`.

Do not turn a similarly named runtime counter into a training feature by
assumption. In particular, `/proc/<pid>/io` `rchar`/`wchar` byte counts are not
substituted for the two transfer features, and an instantaneous descriptor
count is not reported as a count of open events. The procfs collector reports
only read/write syscall-count deltas; other model fields remain `null` there.

## Current runtime coverage

- **Implemented and unit tested:** bounded read/write syscall deltas, PID-scoped
  bpftrace syscall and path-event collection, path-category counts, selected
  syscall-group counts, and process-associated TCP table observations.
- **Unavailable by design:** package dependency/install features, transfer
  features without validated units, and `TCP__Unique_C-COMM` without a verified
  source definition.
- **Not validated:** parity between any runtime mapping and the QUT-DV25
  training pipeline. A real runtime probability remains provisional; the
  runtime collectors attach a parity alert so the evidence gate requires
  `REVIEW_REQUIRED`.
- **Missing-value semantics:** `null` represents unavailable, incomplete, or
  unsupported evidence. A measured zero is emitted only when the corresponding
  source was successfully observed for the complete interval.

The manifest is intentionally conservative. Updating a mapping requires the
source dataset/training pipeline, a documented comparison, and regression
tests. Until then, do not describe runtime output as a validated malware
prediction.
