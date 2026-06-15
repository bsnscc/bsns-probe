import type { HttpFetchResult, HttpRawResult } from "./http.js";
import type { Finding } from "./types.js";

export interface PerformanceCheckResult {
  findings: Finding[];
  raw: PerformanceRawResult;
}

export interface PerformanceRawResult {
  checkedAt: string;
  source: "https" | "http" | null;
  finalUrl?: string;
  finalStatus?: number;
  responseTimeMs?: number;
  totalTimeMs?: number;
  contentType?: string;
  contentEncoding?: string;
  contentLength?: number;
  textLike: boolean;
}

const FAST_RESPONSE_MS = 800;
const SLOW_RESPONSE_MS = 2000;

export function checkPerformance(http: HttpRawResult): PerformanceCheckResult {
  const selected = selectFinalResponse(http);
  const raw: PerformanceRawResult = selected
    ? buildPerformanceRaw(selected.source, selected.result)
    : {
        checkedAt: new Date().toISOString(),
        source: null,
        textLike: false
      };

  return {
    findings: buildPerformanceFindings(raw),
    raw
  };
}

function selectFinalResponse(
  http: HttpRawResult
): { source: "https" | "http"; result: HttpFetchResult } | null {
  if (http.https.status === "ok") {
    return { source: "https", result: http.https };
  }

  if (http.http.status === "ok") {
    return { source: "http", result: http.http };
  }

  return null;
}

function buildPerformanceRaw(
  source: "https" | "http",
  result: HttpFetchResult
): PerformanceRawResult {
  const headers = result.finalHeaders ?? {};
  const contentType = getHeader(headers, "content-type");
  const contentEncoding = getHeader(headers, "content-encoding");
  const contentLength = parseContentLength(getHeader(headers, "content-length"));
  const finalAttempt = result.attempts.at(-1);
  const responseTimeMs = finalAttempt?.responseTimeMs ?? result.totalTimeMs;

  return {
    checkedAt: new Date().toISOString(),
    source,
    ...(result.finalUrl ? { finalUrl: result.finalUrl } : {}),
    ...(typeof result.finalStatus === "number" ? { finalStatus: result.finalStatus } : {}),
    responseTimeMs,
    totalTimeMs: result.totalTimeMs,
    ...(contentType ? { contentType } : {}),
    ...(contentEncoding ? { contentEncoding } : {}),
    ...(typeof contentLength === "number" ? { contentLength } : {}),
    textLike: isTextLikeContent(contentType)
  };
}

function buildPerformanceFindings(raw: PerformanceRawResult): Finding[] {
  const findings: Finding[] = [];

  if (!raw.source || typeof raw.responseTimeMs !== "number") {
    return [
      {
        id: "perf.response.unavailable",
        category: "performance",
        status: "skip",
        severity: "info",
        title: "Performance check skipped",
        summary: "No final web response was available for performance-lite checks.",
        whyItMatters: "Reachability and redirect findings should be fixed before measuring response speed."
      }
    ];
  }

  if (raw.responseTimeMs >= SLOW_RESPONSE_MS) {
    findings.push({
      id: "perf.response.slow",
      category: "performance",
      status: "warn",
      severity: "medium",
      title: "Initial response is slow",
      summary: `The final ${raw.source.toUpperCase()} response took about ${raw.responseTimeMs} ms.`,
      evidence: {
        finalUrl: raw.finalUrl,
        responseTimeMs: raw.responseTimeMs,
        totalTimeMs: raw.totalTimeMs
      },
      whyItMatters: "Slow first responses can make the site feel unavailable and hurt conversion.",
      fix: "Check hosting latency, server-side rendering work, redirects, and cache configuration."
    });
  } else {
    findings.push({
      id: "perf.response.fast",
      category: "performance",
      status: "pass",
      severity: "info",
      title: raw.responseTimeMs <= FAST_RESPONSE_MS ? "Initial response is fast" : "Initial response is acceptable",
      summary: `The final ${raw.source.toUpperCase()} response took about ${raw.responseTimeMs} ms.`,
      evidence: {
        finalUrl: raw.finalUrl,
        responseTimeMs: raw.responseTimeMs,
        totalTimeMs: raw.totalTimeMs
      }
    });
  }

  if (raw.textLike && !raw.contentEncoding) {
    findings.push({
      id: "perf.compression.missing",
      category: "performance",
      status: "warn",
      severity: "low",
      title: "Text response does not advertise compression",
      summary: "The final text response did not include a Content-Encoding header.",
      evidence: {
        finalUrl: raw.finalUrl,
        contentType: raw.contentType,
        contentLength: raw.contentLength
      },
      whyItMatters: "Compression can reduce transfer size for HTML, CSS, JavaScript, JSON, and SVG.",
      fix: "Enable gzip, Brotli, or zstd compression for text responses at the web server or CDN."
    });
  }

  return findings;
}

function getHeader(headers: Record<string, string>, name: string): string | undefined {
  return headers[name.toLowerCase()];
}

function parseContentLength(value: string | undefined): number | undefined {
  if (!value) {
    return undefined;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}

function isTextLikeContent(contentType: string | undefined): boolean {
  if (!contentType) {
    return false;
  }

  const normalized = contentType.toLowerCase();
  return (
    normalized.startsWith("text/") ||
    normalized.includes("json") ||
    normalized.includes("javascript") ||
    normalized.includes("xml") ||
    normalized.includes("svg")
  );
}
