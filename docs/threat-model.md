# Threat Model

bsns probe is a public scanner, so the scan endpoint must be treated as an SSRF target from day one.

## SSRF

The scanner accepts domain names only. It rejects IP addresses, localhost names, private DNS answers, reserved ranges, and arbitrary ports. HTTP redirects repeat hostname and IP validation before being followed.

## DNS Rebinding

HTTP, TLS, and MTA-STS policy fetches use controlled Node networking primitives instead of global `fetch`. Each HTTP fetch attempt validates the URL, resolves the hostname to public addresses, and passes that vetted address set into the Node request lookup callback so the connection can only use pinned public answers. TLS inspection resolves once and reuses the same vetted address set for strict and fallback certificate inspection. Redirect targets go through the same validation and pinned lookup path before any follow-up request.

## Redirect Abuse

Redirect chains are capped. Redirect targets are normalized and validated before follow-up requests. HTTPS-to-HTTP downgrades are findings and should not bypass SSRF controls.

## XSS

DNS records, HTTP headers, certificate fields, and provider metadata are attacker-controlled text. The web UI must render report data as text, never raw HTML.

## Denial of Service

The API should enforce rate limits, whole-scan timeouts, per-check timeouts, redirect limits, response body caps, and bounded concurrency.

## Dependency Supply Chain

Dependencies should stay small and well-maintained. Release builds should run tests, linting, dependency review, and lockfile verification.

## Log Privacy

Submitted domains can be sensitive operational data. Hosted deployments should redact request bodies where practical and document what remains in standard server logs.
