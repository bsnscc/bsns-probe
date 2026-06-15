# Deployment

The hosted web app should deploy as the `tools` Vercel project.

## Domains

- Production: `tools.bsns.cc`
- Development: `dev-tools.bsns.cc`
- Preview/staging alias: `preview-tools.bsns.cc`

## Routes

- `/` is the bsns probe domain health checker.
- `/probe` permanently redirects to `/`.
- `/privacy` is the hosted privacy note.
- `/security` is the hosted security reporting policy.
- `/robots.txt`, `/sitemap.xml`, `/opengraph-image`, `/icon.svg`, and `/.well-known/security.txt` are public launch/discovery surfaces.
- `/api/probe/scan` is the scanner API route.
- `/api/scan` remains as a temporary compatibility alias during the scaffold phase.

## Vercel

Recommended settings:

- Project name: `tools`
- Framework: Next.js
- Root directory: `apps/web` when deploying from the `bsns-probe` workspace; repository root if split into a standalone repo and project settings are updated accordingly
- Source files outside root directory: enabled
- Install command: `cd ../.. && corepack pnpm install --frozen-lockfile`
- Build command: `cd ../.. && corepack pnpm --filter @bsns/tools-web build`
- Node.js version: 24.x on the current Vercel project; local/package engines support current Node LTS 22+

Keep the scanner in its own Vercel project rather than mounting it inside the apex/auth app. The probe API performs outbound DNS, HTTP, and TLS work, so it should have separate rate limits, logs, deployment settings, and incident blast radius.

The application enforces small JSON request bodies, per-IP best-effort rate limits, whole-scan timeouts, and per-runtime active scan backpressure. Treat those as defense in depth. For a public hosted deployment, keep Vercel Firewall or another edge control in front of `/api/probe/scan` and `/api/scan` before requests reach the serverless function.

Current production edge rule:

- Name: `Rate limit probe scan API`
- Match: `/api/probe/scan` or `/api/scan`
- Limit: 30 requests per 60 seconds per source IP
- Exceeded action: deny

See [operations](operations.md) for verification and rollback notes.

## Launch Checklist

- Point `tools.bsns.cc` at the production Vercel deployment.
- Keep reports ephemeral; do not add storage unless share links become explicit opt-in.
- Keep third-party analytics disabled unless the privacy policy is updated first.
- Confirm platform-level rate limiting for the scan API routes.
- Confirm `/api/probe/scan` returns sanitized errors and rate-limit headers.
- Run `corepack pnpm test`, `corepack pnpm typecheck`, `corepack pnpm lint`, and `corepack pnpm build` before promotion.
- After promotion, run `corepack pnpm smoke:production` and `corepack pnpm smoke:browser`.
