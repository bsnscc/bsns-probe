# Accessibility check (bsns accessibility)

A second tool under bsns tools, alongside bsns probe. Where probe checks a
*domain's* health (DNS/TLS/headers/email), the accessibility tool checks a
*website's pages* for machine-detectable accessibility problems and gives each
scan its own A–F score.

It exists because automated, "did you forget the obvious things" feedback is the
cheapest way for a small-business operator to reduce the risk behind web
accessibility complaints — without buying an overlay widget or a full audit.

## What it is — and is not

This is a **static (no-browser) scan**. It fetches each page's HTML and inspects
the markup. It deliberately does **not** render the page in a headless browser.

- It catches roughly the machine-detectable portion of WCAG 2.1 (commonly cited
  as ~30–40%): missing alt text, unlabeled form fields, nameless links/buttons,
  missing page title/language, blocked zoom, heading-order problems, data tables
  without headers, duplicate ids.
- It does **not** judge colour contrast against rendered styles, keyboard
  operability, focus order, or whether alt text is *meaningful*. Those need a
  rendered scan and human judgement.
- It is **not a compliance certification** and not a substitute for a manual
  audit or testing with real assistive technology. Every report carries this
  disclaimer (`A11Y_DISCLAIMER`), and the API/UI surface it prominently. Do not
  market it as "ADA compliant."

## How a scan works

1. The seed URL the user enters is fetched through probe-core's SSRF-guarded
   HTTP client (private/reserved hosts are rejected; redirects are re-validated
   per hop; only `text/html` is read, up to a byte cap).
2. Up to `maxPages - 1` additional same-host pages are discovered from the seed's
   links, ranked by operational importance (contact, booking, ordering,
   services, hours/location, about). The homepage is always considered.
3. Every fetched page is parsed with `node-html-parser` and run through the rule
   set in `rules.ts`.
4. Each page gets a 0–100 score; the site score is the **average of page
   scores**, and the lowest-scoring page is surfaced as `weakestPage` (one bad
   page is what drives legal exposure).

If the seed page can't be fetched the whole scan fails. If a *discovered* page
can't be fetched, it is recorded with an error and excluded from the score.

## Scoring

Separate from probe's domain-health score. Weights (sum to 100):

| Category  | Max | Covers                                             |
| --------- | --- | -------------------------------------------------- |
| images    | 20  | `<img>` / `input[type=image]` alt text             |
| forms     | 20  | label association for inputs, selects, textareas   |
| language  | 20  | `<html lang>`, `<title>`, viewport zoom            |
| structure | 20  | single `<h1>`, heading order, `main`, duplicate ids |
| links     | 15  | accessible name on links/buttons, vague link text  |
| tables    | 5   | data tables with header cells                      |

Deductions per finding follow probe's model (high −10, medium −5, low −2). A–F
bands are shared with probe via `gradeScore`.

## Surfaces

- **Library:** `@bsns/a11y-core` — `scanAccessibility(url, options)` returns an
  `A11yReport`. Reusable pieces: `runRules`, `discoverPages`,
  `createGuardedPageFetcher`, `scorePage`, and the renderers
  (`renderA11yText` / `renderA11yMarkdown` / `renderA11yJson`).
- **CLI:** `bsns-a11y <url>` (in `@bsns/probe-cli`). Flags: `--json`,
  `--markdown`, `--max-pages <n>`, `--timeout <ms>`.
- **Web:** `/accessibility` page + `POST /api/accessibility` (Node.js runtime,
  rate-limited, concurrency-capped, 4 KB request cap — mirrors the probe scan
  API).

## Tests

- `packages/a11y-core/src/*.test.ts` — rules, scoring, page discovery, and a
  full scan with an injected fetcher (no network).
- `apps/web/lib/a11y-api.test.ts` — the API handler (validation, error mapping,
  size limit, rate limiting) with `@bsns/a11y-core` mocked.

## Future work (Tier 2)

A rendered scan (headless browser + axe-core) would add contrast, focus, and
dynamic-DOM coverage. It breaks the no-browser/serverless model, so it belongs
behind a separate, opt-in "deep scan" rather than the default fast path.
