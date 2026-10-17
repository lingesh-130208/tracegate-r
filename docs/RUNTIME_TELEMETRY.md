# TraceGate-R runtime telemetry: measured scope and limitations

## Implemented and smoke-tested
- The LinuxONE FastAPI service loads the trained Logistic Regression and Random Forest artifacts and exposes prediction and audit endpoints.
- The `/proc` collector can sample a chosen Linux process's I/O counters and open-file-descriptor count, submit the partial feature vector, and verify that submitted event IDs appear in the persistent audit log.
- The evidence gate returns `REVIEW_REQUIRED` when observations are incomplete or integrity alerts are present.
- The GenAI endpoint explains an existing audited record using a server-side Groq credential. Explanations are stored separately in SQLite and cannot modify the formal verdict.

## Not implemented by `/proc` collector
- It does **not** instrument every system call.
- It does **not** attribute network flows to a process.
- It does **not** produce all 48 trained model features. The current smoke test had 41 missing features, so probabilities must be treated as provisional and are not validated live-malware detections.
- It is a process-level observation tool, not an isolation sandbox or a production endpoint-detection-and-response agent.

## Model evaluation caveat
The recorded QUT-DV25 replay and grouped holdout metrics are offline benchmark results. They are not evidence that live process telemetry has the same accuracy. Validate against a ground-truthed runtime dataset before making live-detection claims.

## Secret handling
`GROQ_API_KEY` is never stored in source code or committed to Git. Setup can install it at `~/.config/tracegate-r/groq_api_key` with owner-only permissions. The browser calls the local backend; it never receives the key.
