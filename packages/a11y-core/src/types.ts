import type { Finding, FindingStatus, ReportGrade } from "@bsns/probe-core";

export type { Finding, FindingStatus, ReportGrade } from "@bsns/probe-core";

/**
 * Accessibility findings reuse the probe `Finding` shape (status/severity/title/
 * summary/whyItMatters/fix) so reports render the same way, but they are grouped
 * into accessibility-specific categories that map onto the WCAG areas a static
 * (no-browser) scan can actually check.
 */
export type A11yCategory =
  | "images"
  | "forms"
  | "structure"
  | "links"
  | "language"
  | "tables"
  | "meta";

/**
 * An accessibility finding: structurally identical to a probe `Finding` (so the
 * same report renderer works) but tagged with an accessibility category.
 */
export type A11yFinding = Omit<Finding, "category"> & { category: A11yCategory };

/** WCAG-area weights for the accessibility score. Sums to 100. */
export interface A11yScoreCategory {
  score: number;
  max: number;
}

export interface A11yPageResult {
  /** The URL that was actually fetched (after redirects). */
  url: string;
  /** The URL we asked for, before redirects. */
  requestedUrl: string;
  /** Why this page was scanned: the seed the user entered or a discovered page. */
  discovery: "seed" | "discovered";
  /** Final HTTP status of the fetched page. */
  status: number | null;
  /** Per-page accessibility score (0-100) and grade. */
  score: number;
  grade: ReportGrade;
  /** Findings for this page only. */
  findings: A11yFinding[];
  /** Set when the page could not be fetched or parsed. */
  error?: { code: string; message: string };
}

export interface A11yReport {
  schemaVersion: "1.0";
  target: {
    /** The raw URL the user submitted. */
    input: string;
    /** The normalized seed URL that anchored the crawl. */
    seedUrl: string;
    hostname: string;
    scannedAt: string;
  };
  score: {
    /** Site-wide accessibility score: the average of per-page scores. */
    total: number;
    grade: ReportGrade;
    /** Aggregated category scores across all scanned pages. */
    categories: Record<A11yCategory, A11yScoreCategory>;
    /** The lowest-scoring page, surfaced because one bad page drives legal exposure. */
    weakestPage?: { url: string; score: number; grade: ReportGrade };
  };
  summary: {
    headline: string;
    topFixes: string[];
    counts: Record<FindingStatus, number>;
    /** Plain-English statement of what this scan can and cannot certify. */
    disclaimer: string;
  };
  pages: A11yPageResult[];
}

export interface A11yScanOptions {
  /** Max pages to scan (seed + discovered). Defaults to 5. */
  maxPages?: number;
  /** Per-request timeout in milliseconds. Defaults to 10000. */
  timeoutMs?: number;
  /** Max HTML bytes to read per page. Defaults to 2_000_000. */
  maxHtmlBytes?: number;
  /**
   * Inject a page fetcher (used in tests). When omitted, a probe-core
   * SSRF-guarded fetcher is used.
   */
  fetchPage?: PageFetcher;
}

export interface FetchedPage {
  requestedUrl: string;
  finalUrl: string;
  status: number;
  contentType: string | null;
  html: string;
}

export type PageFetcher = (
  url: string,
  options: { timeoutMs: number; maxHtmlBytes: number }
) => Promise<FetchedPage>;

export const A11Y_DISCLAIMER =
  "This is an automated scan that flags machine-detectable accessibility issues only. " +
  "It catches a portion of WCAG 2.1 problems and is not a compliance certification or a " +
  "substitute for a manual audit or testing with real assistive technology.";
