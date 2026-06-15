import {
  type HttpClient,
  ProbeInputError,
  createGuardedHttpClient,
  normalizeDomainInput
} from "@bsns/probe-core";

import type { FetchedPage, PageFetcher } from "./types.js";

const MAX_REDIRECTS = 5;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export class PageFetchError extends Error {
  constructor(
    readonly code: string,
    message: string
  ) {
    super(message);
    this.name = "PageFetchError";
  }
}

/**
 * Build a page fetcher backed by probe-core's SSRF-guarded HTTP client.
 * Each request (and each redirect hop) re-resolves and re-validates the host
 * against private/reserved ranges, so the crawler cannot be pointed at internal
 * services. Only text/html responses are read, and only up to a byte cap.
 */
export function createGuardedPageFetcher(client: HttpClient = createGuardedHttpClient()): PageFetcher {
  return async (url, { timeoutMs, maxHtmlBytes }) => {
    const start = normalizeUrl(url);
    let current = start;
    const seen = new Set<string>();

    for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
      const key = current.toString();
      if (seen.has(key)) {
        throw new PageFetchError("REDIRECT_LOOP", "The page redirected in a loop.");
      }
      seen.add(key);

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await client.fetch(current, { signal: controller.signal });

        if (REDIRECT_STATUSES.has(response.status)) {
          const location = response.headers.get("location");
          await response.body?.cancel();
          const next = location ? safeResolve(location, current) : null;
          if (!next) {
            throw new PageFetchError("BAD_REDIRECT", "The page sent an unusable redirect.");
          }
          if (redirects === MAX_REDIRECTS) {
            throw new PageFetchError("TOO_MANY_REDIRECTS", "The page redirected too many times.");
          }
          current = next;
          continue;
        }

        const contentType = response.headers.get("content-type");
        if (response.status >= 400) {
          await response.body?.cancel();
          throw new PageFetchError("HTTP_ERROR", `The page returned HTTP ${response.status}.`);
        }
        if (!isHtml(contentType)) {
          await response.body?.cancel();
          throw new PageFetchError(
            "NOT_HTML",
            `The page is not HTML (content-type: ${contentType ?? "unknown"}).`
          );
        }
        if (!response.body?.text) {
          throw new PageFetchError("NO_BODY", "The page returned no readable body.");
        }

        const html = await response.body.text(maxHtmlBytes);
        return {
          requestedUrl: start.toString(),
          finalUrl: current.toString(),
          status: response.status,
          contentType,
          html
        } satisfies FetchedPage;
      } catch (error) {
        throw toFetchError(error);
      } finally {
        clearTimeout(timeout);
      }
    }

    throw new PageFetchError("TOO_MANY_REDIRECTS", "The page redirected too many times.");
  };
}

function normalizeUrl(input: string): URL {
  let url: URL;
  try {
    url = new URL(hasScheme(input) ? input : `https://${input}`);
  } catch {
    throw new PageFetchError("INVALID_URL", "That does not look like a valid URL.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new PageFetchError("INVALID_URL", "Only http and https URLs can be scanned.");
  }
  // Reuse probe-core's hostname validation (rejects private/reserved hosts up front).
  try {
    normalizeDomainInput(url.hostname);
  } catch (error) {
    if (error instanceof ProbeInputError) {
      throw new PageFetchError(error.code, error.message);
    }
    throw error;
  }
  return url;
}

function safeResolve(location: string, base: URL): URL | null {
  try {
    const next = new URL(location, base);
    if (next.protocol !== "http:" && next.protocol !== "https:") {
      return null;
    }
    return next;
  } catch {
    return null;
  }
}

function hasScheme(input: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//iu.test(input.trim());
}

function isHtml(contentType: string | null): boolean {
  if (!contentType) {
    // Be lenient: many servers omit content-type. Treat as HTML and let parsing decide.
    return true;
  }
  const lowered = contentType.toLowerCase();
  return lowered.includes("text/html") || lowered.includes("application/xhtml+xml");
}

function toFetchError(error: unknown): PageFetchError {
  if (error instanceof PageFetchError) {
    return error;
  }
  if (error instanceof ProbeInputError) {
    return new PageFetchError(error.code, error.message);
  }
  if (error instanceof Error && error.name === "AbortError") {
    return new PageFetchError("TIMEOUT", "The page took too long to respond.");
  }
  return new PageFetchError(
    "FETCH_FAILED",
    error instanceof Error ? error.message : "The page could not be fetched."
  );
}
