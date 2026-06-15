import { discoverPages } from "./crawl.js";
import { PageFetchError, createGuardedPageFetcher } from "./fetch-page.js";
import { runRules } from "./rules.js";
import {
  buildHeadline,
  buildReportScore,
  buildTopFixes,
  countFindings,
  scorePage
} from "./score.js";
import {
  A11Y_DISCLAIMER,
  type A11yPageResult,
  type A11yReport,
  type A11yScanOptions,
  type FetchedPage,
  type PageFetcher
} from "./types.js";

const DEFAULT_MAX_PAGES = 5;
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_HTML_BYTES = 2_000_000;

/**
 * Run a static accessibility scan: fetch the seed URL, discover a few key pages,
 * check each one, and aggregate into a report with its own A-F score.
 */
export async function scanAccessibility(
  input: string,
  options: A11yScanOptions = {}
): Promise<A11yReport> {
  const maxPages = Math.max(1, options.maxPages ?? DEFAULT_MAX_PAGES);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxHtmlBytes = options.maxHtmlBytes ?? DEFAULT_MAX_HTML_BYTES;
  const fetchPage: PageFetcher = options.fetchPage ?? createGuardedPageFetcher();
  const fetchOptions = { timeoutMs, maxHtmlBytes };
  const scannedAt = new Date().toISOString();

  // The seed page must load; everything else anchors off it.
  let seed: FetchedPage;
  try {
    seed = await fetchPage(input, fetchOptions);
  } catch (error) {
    throw normalizeSeedError(error);
  }

  const seedUrl = new URL(seed.finalUrl);
  const discovered = discoverPages(seed.html, seed.finalUrl, maxPages - 1);

  const pages: A11yPageResult[] = [scorePageResult(seed, seed.finalUrl, "seed")];

  const discoveredResults = await Promise.all(
    discovered.map(async (url) => {
      try {
        const page = await fetchPage(url, fetchOptions);
        return scorePageResult(page, url, "discovered");
      } catch (error) {
        return errorPageResult(url, error);
      }
    })
  );
  pages.push(...discoveredResults);

  const scoredPages = pages.filter((page) => !page.error);
  const allFindings = scoredPages.flatMap((page) => page.findings);
  const counts = countFindings(allFindings);

  return {
    schemaVersion: "1.0",
    target: {
      input,
      seedUrl: seed.finalUrl,
      hostname: seedUrl.hostname,
      scannedAt
    },
    score: buildReportScore(pages),
    summary: {
      headline: buildHeadline(counts, scoredPages.length),
      topFixes: buildTopFixes(allFindings),
      counts,
      disclaimer: A11Y_DISCLAIMER
    },
    pages
  };
}

function scorePageResult(
  page: FetchedPage,
  requestedUrl: string,
  discovery: A11yPageResult["discovery"]
): A11yPageResult {
  const findings = runRules(page.html);
  const { score, grade } = scorePage(findings);
  return {
    url: page.finalUrl,
    requestedUrl,
    discovery,
    status: page.status,
    score,
    grade,
    findings
  };
}

function errorPageResult(url: string, error: unknown): A11yPageResult {
  const normalized =
    error instanceof PageFetchError
      ? { code: error.code, message: error.message }
      : { code: "FETCH_FAILED", message: "The page could not be scanned." };
  return {
    url,
    requestedUrl: url,
    discovery: "discovered",
    status: null,
    score: 0,
    grade: "F",
    findings: [],
    error: normalized
  };
}

function normalizeSeedError(error: unknown): Error {
  if (error instanceof PageFetchError) {
    return error;
  }
  return new PageFetchError(
    "FETCH_FAILED",
    error instanceof Error ? error.message : "The page could not be scanned."
  );
}
