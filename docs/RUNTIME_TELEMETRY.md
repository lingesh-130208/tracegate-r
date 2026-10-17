# TraceGate-R runtime telemetry and offline explanations

## Verified capabilities
- The FastAPI service loads the trained Logistic Regression and Random Forest artifacts from the LinuxONE artifacts directory.
- `/proc` collector snapshots process I/O counters and open-file-descriptor counts and checks that submitted event IDs are persisted in the audit endpoint.
- The evidence gate returns `REVIEW_REQUIRED` for incomplete observations or integrity alerts.
- Runtime events with missing features are never zero-filled. If both trained estimators can score the incomplete vector, their scores remain provisional and the evidence gate still applies. If the trained models reject missing values (or no numeric features were observed), the API stores the event with an `unknown` verdict, null probabilities, and `REVIEW_REQUIRED`; the dashboard labels the score unavailable.
- `/api/genai/status` and `/api/genai/explain` now run locally. Explanations are generated deterministically from allow-listed audit fields and saved in a separate SQLite table. This feature requires no external provider, API key, or outbound network request. It never changes the formal verdict.

## Important telemetry limitations
- The `/proc` collector does not instrument every system call.
- It does not attribute network flows to a process.
- It does not produce the full 48-feature model vector. Previous smoke tests had 41 missing features; those probabilities are provisional and are not validated live-malware detections.
- The collector is not an isolation sandbox or a production endpoint-detection-and-response agent.
- Recorded QUT-DV25 replay and grouped holdout metrics are offline benchmark results; they are not proof that live telemetry has the same accuracy.

## Explanation limitations
- The offline explanation engine summarizes recorded fields; it is not an LLM and does not independently classify malware.
- Audit score normalization supports known score fields and nested model result wrappers, with tests preventing invented probabilities.
- The explanation panel enforces UTF-8 rendering and responsive spacing.
- Missing/unavailable evidence is explicitly disclosed. Numeric model scores are not proof by themselves.
- Any old server-side Groq key file is unused by this version. No key is required for explanations.
