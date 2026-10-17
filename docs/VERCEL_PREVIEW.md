# Vercel website preview

## Project settings

Configure the existing Vercel project with these static-site settings:

| Setting | Value |
|---|---|
| Framework preset | Vite |
| Root directory | `frontend` |
| Install command | `npm ci` |
| Build command | `npm run build` |
| Output directory | `dist` |
| Node.js version | 20.19+ or 22.12+ (verified locally with 24.22.0) |

The lockfile pins the frontend dependencies. The build imports the public
ordered feature list from `../data/model_feature_names.json`; Vite includes
that schema reference in the generated assets. There is no serverless function,
rewriting proxy, or API secret in the static deployment.

`dist/` is a generated directory and is ignored by Git. The Vercel build creates
it from the selected commit. For a FastAPI release, build the exact candidate
revision and include `frontend/dist/` in that immutable release bundle; the
API serves the built entry and `/assets/` files. Without it, the API returns a
clear build-required page.

## API connection and data boundaries

The dashboard calls same-origin routes: `/health`, `/api/model-info`,
`/api/audit`, `/api/predict`, and `/api/genai/explain`. This works when FastAPI
serves the dashboard and routes from one origin.

Vercel serves only the static frontend. No API proxy or API base URL is
configured. The LinuxONE API is bound to loopback at `127.0.0.1:8001`; there is
no verified HTTPS ingress, and the API has no analyst authentication. A hosted
page cannot reach that private service. On Vercel, live health, model, and audit
requests therefore remain unavailable unless an approved, authenticated
backend connection is designed and verified. Demo Mode remains explicitly
synthetic and never submits writes.

Do not add the upstream URL to browser-visible configuration, expose port 8001,
or proxy sensitive audit/prediction routes without real server-side
authentication and authorization. No Vercel environment variables are needed;
never add API credentials, SSH credentials, or model artifacts to frontend
variables. Preview protection controls page access only; it does not authorize
FastAPI requests.

## Verified boundaries

- The page does not launch bpftrace or claim collector health without an API field.
- Model readiness, schema ordering, benchmark metadata, audit rows, and predictions come from same-origin API responses.
- Missing feature measurements remain null or absent; the page does not generate substitute values.
- Historical offline metrics are labeled separately from live results.

## Current deployment status

The Vercel project `tracegate-r-public` currently has a `READY` production
deployment at `tracegate-r-public.vercel.app`, built from branch
`tracegate-r-runtime-fixes` at commit
`d497759942acc29996f42e647b1c3e6398979e3f`. The separate `tracegate-r`
project also has a `READY` production deployment at that commit and has SSO
protection enabled. The public project has no password, SSO, or trusted-IP
protection configured.

This React redesign is uncommitted and was not pushed or deployed. The public
alias therefore remains on its previous standalone deployment. An anonymous
GET to that public alias returned HTTP 200 with title `TraceGate-R | Evidence
Console` and no Vite `/assets/*.js` entry. No Vercel domains, aliases, access
rules, production settings, or deployments were changed during this work. The
Vercel state above was inspected read-only on 2026-10-17.
