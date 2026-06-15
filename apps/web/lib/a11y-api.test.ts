import { beforeEach, describe, expect, it, vi } from "vitest";
import type { A11yReport } from "@bsns/a11y-core";

const scanAccessibilityMock = vi.hoisted(() => vi.fn());

vi.mock("@bsns/a11y-core", () => {
  class PageFetchError extends Error {
    constructor(
      readonly code: string,
      message: string
    ) {
      super(message);
      this.name = "PageFetchError";
    }
  }

  return {
    PageFetchError,
    scanAccessibility: scanAccessibilityMock
  };
});

import { PageFetchError } from "@bsns/a11y-core";

import { handleA11yRequest, resetA11yApiRateLimitForTest } from "./a11y-api";

describe("handleA11yRequest", () => {
  beforeEach(() => {
    resetA11yApiRateLimitForTest();
    scanAccessibilityMock.mockReset();
    scanAccessibilityMock.mockResolvedValue(makeReport());
  });

  it("returns an accessibility report with rate-limit headers", async () => {
    const response = await handleA11yRequest(request("https://example.com"));
    const body = (await response.json()) as { ok: boolean; report?: A11yReport };

    expect(response.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.report?.target.hostname).toBe("example.com");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-ratelimit-limit")).toBe("12");
    expect(scanAccessibilityMock).toHaveBeenCalledWith("https://example.com", {
      maxPages: 5,
      timeoutMs: 10_000
    });
  });

  it("returns a sanitized validation error for an empty URL", async () => {
    const response = await handleA11yRequest(request(""));
    const body = (await response.json()) as ErrorBody;

    expect(response.status).toBe(400);
    expect(body.error.code).toBe("INVALID_REQUEST");
    expect(scanAccessibilityMock).not.toHaveBeenCalled();
  });

  it("maps an unreachable seed page to a 400 with the fetch error code", async () => {
    scanAccessibilityMock.mockRejectedValueOnce(
      new PageFetchError("BLOCKED_HOSTNAME", "That domain resolves to a private address.")
    );
    const response = await handleA11yRequest(request("http://127.0.0.1"));
    const body = (await response.json()) as ErrorBody;

    expect(response.status).toBe(400);
    expect(body.error.code).toBe("BLOCKED_HOSTNAME");
  });

  it("rejects oversized requests before scanning", async () => {
    const response = await handleA11yRequest(
      new Request("https://tools.bsns.cc/api/accessibility", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": "198.51.100.11" },
        body: JSON.stringify({ url: "https://example.com", padding: "x".repeat(5000) })
      })
    );
    const body = (await response.json()) as ErrorBody;

    expect(response.status).toBe(413);
    expect(body.error.code).toBe("REQUEST_TOO_LARGE");
    expect(scanAccessibilityMock).not.toHaveBeenCalled();
  });

  it("rate limits repeated requests from the same client", async () => {
    let response = await handleA11yRequest(request("https://example.com"));
    for (let index = 1; index < 13; index += 1) {
      response = await handleA11yRequest(request("https://example.com"));
    }
    const body = (await response.json()) as ErrorBody;

    expect(response.status).toBe(429);
    expect(body.error.code).toBe("RATE_LIMITED");
    expect(response.headers.get("retry-after")).toMatch(/^[1-9]\d*$/u);
  });
});

interface ErrorBody {
  ok: false;
  error: { code: string; message: string };
}

function request(url: string): Request {
  return new Request("https://tools.bsns.cc/api/accessibility", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": "198.51.100.11" },
    body: JSON.stringify({ url })
  });
}

function makeReport(): A11yReport {
  return {
    schemaVersion: "1.0",
    target: {
      input: "https://example.com",
      seedUrl: "https://example.com/",
      hostname: "example.com",
      scannedAt: "2026-06-15T00:00:00.000Z"
    },
    score: {
      total: 100,
      grade: "A",
      categories: {
        images: { score: 20, max: 20 },
        forms: { score: 20, max: 20 },
        language: { score: 20, max: 20 },
        structure: { score: 20, max: 20 },
        links: { score: 15, max: 15 },
        tables: { score: 5, max: 5 },
        meta: { score: 0, max: 0 }
      }
    },
    summary: {
      headline: "Scanned 1 page: no machine-detectable issues found.",
      topFixes: ["No machine-detectable fixes were needed."],
      counts: { pass: 6, warn: 0, fail: 0, info: 0, skip: 0 },
      disclaimer: "Automated scan disclaimer."
    },
    pages: []
  };
}
