# Operations

## Production

- Hosted app: `https://tools.bsns.cc`
- Primary scan API: `POST /api/probe/scan`
- Compatibility scan API: `POST /api/scan`

Run the production smoke checks after each promotion:

```bash
corepack pnpm smoke:production
corepack pnpm smoke:browser
```

Refresh README screenshots when the public UI changes:

```bash
corepack pnpm screenshots:production
```

## Edge Rate Limiting

The Vercel Firewall rule `Rate limit probe scan API` is published on the `tools` project.

- Match: path equals `/api/probe/scan` OR `/api/scan`
- Action: rate limit
- Window: 30 requests per 60 seconds
- Key: source IP
- Exceeded action: deny

Verify it with:

```bash
vercel firewall rules ls
vercel firewall diff
```

Expected state:

- The rule is listed as enabled in the live configuration.
- `vercel firewall diff` reports no pending changes.

The app still keeps its own defense-in-depth controls: small JSON request bodies, per-IP
best-effort rate limits, whole-scan timeouts, and per-runtime active scan backpressure.

## Incident Notes

- For scan abuse, tighten the Vercel Firewall rule before changing application code.
- For scanner false positives or noisy findings, prefer lowering severity before removing evidence.
- For production deployment rollback, use the previous Vercel deployment or alias target, then rerun `corepack pnpm smoke:production`.
- For unpublished firewall drafts, use `vercel firewall diff` before `vercel firewall publish`; use `vercel firewall discard` only when the pending changes are known to be unwanted.
