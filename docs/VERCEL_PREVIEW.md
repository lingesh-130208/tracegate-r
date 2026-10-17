# Vercel website preview

## Frontend and build

- Framework: static HTML ("Other"); the existing UI is frontend/index.html.
- Project root: frontend/.
- Install command: none.
- Build command: none.
- Output: static files from the project root (.); there is no generated bundle.
- Production branch: keep the existing Git default branch configuration. Pushes to tracegate-r-runtime-fixes are Preview candidates; do not merge PR #1 or change main to publish the website.

## API connection

The dashboard calls same-origin routes: /health, /api/model-info, /api/audit, /api/predict, and /api/genai/explain. This works when FastAPI serves the dashboard and those routes from one origin.

Vercel serves the static frontend only. No Vercel API proxy or API base URL is configured. The LinuxONE API is bound to loopback at 127.0.0.1:8001; there is no verified HTTPS ingress, and the API has no analyst authentication. A hosted page cannot reach that private service. The preview must show API, model, audit, and collector state as unavailable until an approved secure ingress and server-side authorization are implemented and verified.

Do not add the upstream URL to browser-visible configuration, expose port 8001, or proxy sensitive audit/prediction routes without real server-side authentication and authorization.

## Environment variables and access

No Vercel environment variables are required for the static preview. In particular, do not add API credentials, SSH credentials, or model artifacts to frontend variables.

Protect Preview deployments with Vercel Authentication. This is platform access control for the Preview URL; it does not add authentication to the FastAPI service. Keep production deployment disabled until secure backend access, analyst authorization, and the production environment have been reviewed.

## Verified boundaries

- The page does not launch bpftrace or claim collector health without an API field.
- The UI uses backend responses for model readiness, schema ordering, benchmark metadata, audit rows, and prediction output.
- Missing feature measurements remain null or absent; the page does not generate substitute values.
- Historical offline metrics, if returned, are labeled separately from live results.