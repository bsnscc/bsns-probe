import { NextResponse } from "next/server";
import { z } from "zod";

import { ProbeInputError, scanDomain } from "@bsns/probe-core";
import type { ProbeReport } from "@bsns/probe-core";

const API_SCAN_TIMEOUT_MS = 15000;
const API_SUBCHECK_TIMEOUT_MS = 8000;
const MAX_ACTIVE_SCANS = 4;
const MAX_REQUEST_BODY_BYTES = 4096;
const RATE_LIMIT_MAX = 20;
const RATE_LIMIT_WINDOW_MS = 60_000;
const SCAN_BUSY_RETRY_SECONDS = 5;
const SCAN_API_CACHE_CONTROL = "no-store";

const JsonScanRequest = z.object({
  domain: z.string().trim().min(1).max(253),
  dkimSelectors: z
    .array(z.string().trim().min(1).max(63).regex(/^[a-z0-9._-]+$/iu))
    .max(20)
    .optional(),
  includeRaw: z.boolean().optional()
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

export async function handleScanRequest(request: Request) {
  const rateLimit = checkRateLimit(getClientIp(request));

  if (!rateLimit.allowed) {
    return errorResponse(
      "RATE_LIMITED",
      "Too many scan requests. Try again shortly.",
      429,
      scanApiHeaders(rateLimit, {
        retryAfterSeconds: retryAfterSeconds(rateLimit)
      })
    );
  }

  try {
    const parsed = await parseScanRequest(request);

    if (!tryAcquireScanSlot()) {
      return errorResponse(
        "SCANNER_BUSY",
        "The scanner is handling other requests. Try again shortly.",
        503,
        scanApiHeaders(rateLimit, {
          retryAfterSeconds: SCAN_BUSY_RETRY_SECONDS
        })
      );
    }

    let report: ProbeReport;
    try {
      report = await withTimeout(
        scanDomain(parsed.domain, {
          dkimSelectors: parsed.dkimSelectors,
          includeRaw: parsed.includeRaw,
          timeoutMs: API_SUBCHECK_TIMEOUT_MS
        }),
        API_SCAN_TIMEOUT_MS
      );
    } finally {
      releaseScanSlot();
    }

    return NextResponse.json(
      { ok: true, report },
      {
        headers: scanApiHeaders(rateLimit)
      }
    );
  } catch (error) {
    return errorResponseFor(error, rateLimit);
  }
}

async function parseScanRequest(request: Request) {
  const contentType = request.headers.get("content-type") ?? "";
  assertRequestContentLength(request);

  if (contentType.includes("application/json")) {
    return JsonScanRequest.parse(parseJson(await readLimitedRequestText(request)));
  }

  return parseFormRequest(await request.formData());
}

function assertRequestContentLength(request: Request): void {
  const contentLength = request.headers.get("content-length");
  if (!contentLength) {
    return;
  }

  const parsed = Number.parseInt(contentLength, 10);
  if (Number.isFinite(parsed) && parsed > MAX_REQUEST_BODY_BYTES) {
    throw new ScanApiError(
      "REQUEST_TOO_LARGE",
      "Scan requests must be 4 KB or smaller.",
      413
    );
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
      throw new ScanApiError(
        "REQUEST_TOO_LARGE",
        "Scan requests must be 4 KB or smaller.",
        413
      );
    }

    text += decoder.decode(value, { stream: true });
  }

  return text + decoder.decode();
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new ScanApiError(
      "INVALID_JSON",
      "Send a valid JSON scan request.",
      400
    );
  }
}

function parseFormRequest(formData: FormData) {
  const domain = formData.get("domain");
  const dkimSelectors = formData.get("dkimSelectors");

  return JsonScanRequest.parse({
    domain: typeof domain === "string" ? domain : "",
    dkimSelectors:
      typeof dkimSelectors === "string" && dkimSelectors.trim()
        ? dkimSelectors.split(",").map((selector) => selector.trim())
        : undefined,
    includeRaw: true
  });
}

function checkRateLimit(key: string, now = Date.now()): RateLimitResult {
  pruneExpiredRateLimitBuckets(now);

  const bucket = rateLimitBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    rateLimitBuckets.set(key, {
      count: 1,
      resetAt: now + RATE_LIMIT_WINDOW_MS
    });

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

function pruneExpiredRateLimitBuckets(now: number): void {
  for (const [key, bucket] of rateLimitBuckets.entries()) {
    if (bucket.resetAt <= now) {
      rateLimitBuckets.delete(key);
    }
  }
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
          reject(new ScanApiError("SCAN_TIMEOUT", "The scan timed out. Try again shortly.", 504));
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
  if (error instanceof ProbeInputError) {
    return errorResponse(error.code, error.message, 400, scanApiHeaders(rateLimit));
  }

  if (error instanceof ScanApiError) {
    return errorResponse(error.code, error.message, error.status, scanApiHeaders(rateLimit));
  }

  if (error instanceof z.ZodError) {
    return errorResponse(
      "INVALID_REQUEST",
      "Enter a public domain name and optional DKIM selectors.",
      400,
      scanApiHeaders(rateLimit)
    );
  }

  return errorResponse(
    "SCAN_FAILED",
    "The scan request failed. Try again in a moment.",
    500,
    scanApiHeaders(rateLimit)
  );
}

function errorResponse(
  code: string,
  message: string,
  status: number,
  headers: HeadersInit = {}
): NextResponse {
  return NextResponse.json(
    {
      ok: false,
      error: {
        code,
        message
      }
    },
    {
      status,
      headers
    }
  );
}

function scanApiHeaders(
  rateLimit: RateLimitResult,
  options: { retryAfterSeconds?: number } = {}
): HeadersInit {
  return {
    "cache-control": SCAN_API_CACHE_CONTROL,
    ...rateLimitHeaders(rateLimit),
    ...(options.retryAfterSeconds === undefined
      ? {}
      : { "retry-after": options.retryAfterSeconds.toString() })
  };
}

function rateLimitHeaders(rateLimit: RateLimitResult): Record<string, string> {
  return {
    "x-ratelimit-limit": rateLimit.limit.toString(),
    "x-ratelimit-remaining": rateLimit.remaining.toString(),
    "x-ratelimit-reset": Math.ceil(rateLimit.resetAt / 1000).toString()
  };
}

function retryAfterSeconds(rateLimit: RateLimitResult): number {
  return Math.max(1, Math.ceil((rateLimit.resetAt - Date.now()) / 1000));
}

class ScanApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number
  ) {
    super(message);
    this.name = "ScanApiError";
  }
}

export function resetScanApiRateLimitForTest(): void {
  rateLimitBuckets.clear();
  activeScans = 0;
}
