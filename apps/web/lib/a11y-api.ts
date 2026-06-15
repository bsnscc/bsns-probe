import { NextResponse } from "next/server";
import { z } from "zod";

import { PageFetchError, scanAccessibility } from "@bsns/a11y-core";
import type { A11yReport } from "@bsns/a11y-core";

const API_SCAN_TIMEOUT_MS = 25_000;
const API_REQUEST_TIMEOUT_MS = 10_000;
const API_MAX_PAGES = 5;
const MAX_ACTIVE_SCANS = 3;
const MAX_REQUEST_BODY_BYTES = 4096;
const RATE_LIMIT_MAX = 12;
const RATE_LIMIT_WINDOW_MS = 60_000;
const SCAN_BUSY_RETRY_SECONDS = 5;

const JsonA11yRequest = z.object({
  url: z.string().trim().min(1).max(2048)
});

interface RateLimitBucket {
  count: number;
  resetAt: number;
}

interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
}

const rateLimitBuckets = new Map<string, RateLimitBucket>();
let activeScans = 0;

export async function handleA11yRequest(request: Request) {
  const rateLimit = checkRateLimit(getClientIp(request));

  if (!rateLimit.allowed) {
    return errorResponse("RATE_LIMITED", "Too many scans. Try again shortly.", 429, {
      ...rateLimitHeaders(rateLimit),
      "retry-after": retryAfterSeconds(rateLimit).toString()
    });
  }

  try {
    const parsed = await parseRequest(request);

    if (!tryAcquireScanSlot()) {
      return errorResponse(
        "SCANNER_BUSY",
        "The scanner is handling other requests. Try again shortly.",
        503,
        { ...rateLimitHeaders(rateLimit), "retry-after": SCAN_BUSY_RETRY_SECONDS.toString() }
      );
    }

    let report: A11yReport;
    try {
      report = await withTimeout(
        scanAccessibility(parsed.url, {
          maxPages: API_MAX_PAGES,
          timeoutMs: API_REQUEST_TIMEOUT_MS
        }),
        API_SCAN_TIMEOUT_MS
      );
    } finally {
      releaseScanSlot();
    }

    return NextResponse.json({ ok: true, report }, { headers: rateLimitHeaders(rateLimit) });
  } catch (error) {
    return errorResponseFor(error, rateLimit);
  }
}

async function parseRequest(request: Request) {
  assertRequestContentLength(request);
  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return JsonA11yRequest.parse(parseJson(await readLimitedRequestText(request)));
  }
  const formData = await request.formData();
  const url = formData.get("url");
  return JsonA11yRequest.parse({ url: typeof url === "string" ? url : "" });
}

function assertRequestContentLength(request: Request): void {
  const contentLength = request.headers.get("content-length");
  if (!contentLength) {
    return;
  }
  const parsed = Number.parseInt(contentLength, 10);
  if (Number.isFinite(parsed) && parsed > MAX_REQUEST_BODY_BYTES) {
    throw new A11yApiError("REQUEST_TOO_LARGE", "Scan requests must be 4 KB or smaller.", 413);
  }
}

async function readLimitedRequestText(request: Request): Promise<string> {
  const reader = request.body?.getReader();
  if (!reader) {
    return "";
  }
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    bytes += value.byteLength;
    if (bytes > MAX_REQUEST_BODY_BYTES) {
      await reader.cancel();
      throw new A11yApiError("REQUEST_TOO_LARGE", "Scan requests must be 4 KB or smaller.", 413);
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new A11yApiError("INVALID_JSON", "Send a valid JSON scan request.", 400);
  }
}

function checkRateLimit(key: string, now = Date.now()): RateLimitResult {
  for (const [bucketKey, bucket] of rateLimitBuckets.entries()) {
    if (bucket.resetAt <= now) {
      rateLimitBuckets.delete(bucketKey);
    }
  }

  const bucket = rateLimitBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    rateLimitBuckets.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return {
      allowed: true,
      limit: RATE_LIMIT_MAX,
      remaining: RATE_LIMIT_MAX - 1,
      resetAt: now + RATE_LIMIT_WINDOW_MS
    };
  }

  bucket.count += 1;
  return {
    allowed: bucket.count <= RATE_LIMIT_MAX,
    limit: RATE_LIMIT_MAX,
    remaining: Math.max(0, RATE_LIMIT_MAX - bucket.count),
    resetAt: bucket.resetAt
  };
}

function tryAcquireScanSlot(): boolean {
  if (activeScans >= MAX_ACTIVE_SCANS) {
    return false;
  }
  activeScans += 1;
  return true;
}

function releaseScanSlot(): void {
  activeScans = Math.max(0, activeScans - 1);
}

function getClientIp(request: Request): string {
  const forwardedFor = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return (
    forwardedFor ||
    request.headers.get("x-real-ip")?.trim() ||
    request.headers.get("cf-connecting-ip")?.trim() ||
    "unknown"
  );
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timeout = setTimeout(() => {
          reject(new A11yApiError("SCAN_TIMEOUT", "The scan timed out. Try again shortly.", 504));
        }, timeoutMs);
      })
    ]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}

function errorResponseFor(error: unknown, rateLimit: RateLimitResult): NextResponse {
  if (error instanceof PageFetchError) {
    // The seed page could not be fetched — usually a bad URL or unreachable site.
    return errorResponse(error.code, error.message, 400, rateLimitHeaders(rateLimit));
  }
  if (error instanceof A11yApiError) {
    return errorResponse(error.code, error.message, error.status, rateLimitHeaders(rateLimit));
  }
  if (error instanceof z.ZodError) {
    return errorResponse(
      "INVALID_REQUEST",
      "Enter a public website URL, like https://example.com.",
      400,
      rateLimitHeaders(rateLimit)
    );
  }
  return errorResponse(
    "SCAN_FAILED",
    "The scan request failed. Try again in a moment.",
    500,
    rateLimitHeaders(rateLimit)
  );
}

function errorResponse(
  code: string,
  message: string,
  status: number,
  headers: HeadersInit = {}
): NextResponse {
  return NextResponse.json(
    { ok: false, error: { code, message } },
    { status, headers: { "cache-control": "no-store", ...headers } }
  );
}

function rateLimitHeaders(rateLimit: RateLimitResult): Record<string, string> {
  return {
    "cache-control": "no-store",
    "x-ratelimit-limit": rateLimit.limit.toString(),
    "x-ratelimit-remaining": rateLimit.remaining.toString(),
    "x-ratelimit-reset": Math.ceil(rateLimit.resetAt / 1000).toString()
  };
}

function retryAfterSeconds(rateLimit: RateLimitResult): number {
  return Math.max(1, Math.ceil((rateLimit.resetAt - Date.now()) / 1000));
}

class A11yApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number
  ) {
    super(message);
    this.name = "A11yApiError";
  }
}

export function resetA11yApiRateLimitForTest(): void {
  rateLimitBuckets.clear();
  activeScans = 0;
}
