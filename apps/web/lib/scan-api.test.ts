import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ProbeReport } from "@bsns/probe-core";

const scanDomainMock = vi.hoisted(() => vi.fn());

vi.mock("@bsns/probe-core", () => {
  class ProbeInputError extends Error {
    constructor(
      readonly code: string,
      message: string
    ) {
      super(message);
      this.name = "ProbeInputError";
    }
  }

  return {
    ProbeInputError,
    scanDomain: scanDomainMock
  };
});

import { ProbeInputError } from "@bsns/probe-core";

import { handleScanRequest, resetScanApiRateLimitForTest } from "./scan-api";

describe("handleScanRequest", () => {
  beforeEach(() => {
    resetScanApiRateLimitForTest();
    scanDomainMock.mockReset();
    scanDomainMock.mockResolvedValue(makeReport());
  });

  it("returns a scan report with rate-limit headers", async () => {
    const response = await handleScanRequest(scanRequest("example.com"));
    const body = (await response.json()) as { ok: boolean; report?: ProbeReport };

    expect(response.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.report?.target.hostname).toBe("example.com");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-ratelimit-limit")).toBe("20");
    expect(response.headers.get("x-ratelimit-remaining")).toBe("19");
    expect(response.headers.get("x-ratelimit-reset")).toMatch(/^\d+$/u);
    expect(scanDomainMock).toHaveBeenCalledWith("example.com", {
      dkimSelectors: undefined,
      includeRaw: true,
      timeoutMs: 8000
    });
  });

  it("returns sanitized validation errors", async () => {
    const response = await handleScanRequest(scanRequest(""));
    const body = (await response.json()) as ScanErrorBody;

    expect(response.status).toBe(400);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toEqual({
      ok: false,
      error: {
        code: "INVALID_REQUEST",
        message: "Enter a public domain name and optional DKIM selectors."
      }
    });
    expect(scanDomainMock).not.toHaveBeenCalled();
  });

  it("rejects oversized JSON scan requests before scanning", async () => {
    const response = await handleScanRequest(
      new Request("https://tools.bsns.cc/api/probe/scan", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-forwarded-for": "198.51.100.10"
        },
        body: JSON.stringify({
          domain: "example.com",
          includeRaw: true,
          padding: "x".repeat(5000)
        })
      })
    );
    const body = (await response.json()) as ScanErrorBody;

    expect(response.status).toBe(413);
    expect(body.error).toEqual({
      code: "REQUEST_TOO_LARGE",
      message: "Scan requests must be 4 KB or smaller."
    });
    expect(scanDomainMock).not.toHaveBeenCalled();
  });

  it("maps scanner input errors without exposing stack traces", async () => {
    scanDomainMock.mockRejectedValueOnce(
      new ProbeInputError("BLOCKED_HOSTNAME", "Enter a public domain name.")
    );

    const response = await handleScanRequest(scanRequest("localhost"));
    const body = (await response.json()) as ScanErrorBody;

    expect(response.status).toBe(400);
    expect(body.error).toEqual({
      code: "BLOCKED_HOSTNAME",
      message: "Enter a public domain name."
    });
  });

  it("rate limits repeated requests from the same client", async () => {
    let response = await handleScanRequest(scanRequest("example.com"));

    for (let index = 1; index < 21; index += 1) {
      response = await handleScanRequest(scanRequest("example.com"));
    }

    const body = (await response.json()) as ScanErrorBody;
    expect(response.status).toBe(429);
    expect(body.error.code).toBe("RATE_LIMITED");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-ratelimit-remaining")).toBe("0");
    expect(response.headers.get("retry-after")).toMatch(/^[1-9]\d*$/u);
  });

  it("returns a retryable busy response when active scan slots are full", async () => {
    const pendingScans = Array.from({ length: 4 }, () => deferred<ProbeReport>());
    let scanIndex = 0;
    scanDomainMock.mockImplementation(() => pendingScans[scanIndex++]?.promise ?? makeReport());

    const runningScans = pendingScans.map(() => handleScanRequest(scanRequest("example.com")));
    await waitFor(() => scanDomainMock.mock.calls.length === 4);

    const busyResponse = await handleScanRequest(scanRequest("example.com"));
    const busyBody = (await busyResponse.json()) as ScanErrorBody;

    expect(busyResponse.status).toBe(503);
    expect(busyBody.error).toEqual({
      code: "SCANNER_BUSY",
      message: "The scanner is handling other requests. Try again shortly."
    });
    expect(busyResponse.headers.get("retry-after")).toBe("5");
    expect(scanDomainMock).toHaveBeenCalledTimes(4);

    for (const pendingScan of pendingScans) {
      pendingScan.resolve(makeReport());
    }

    await Promise.all(runningScans);
  });
});

interface ScanErrorBody {
  ok: false;
  error: {
    code: string;
    message: string;
  };
}

function scanRequest(domain: string): Request {
  return new Request("https://tools.bsns.cc/api/probe/scan", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-forwarded-for": "198.51.100.10"
    },
    body: JSON.stringify({
      domain,
      includeRaw: true
    })
  });
}

function makeReport(): ProbeReport {
  return {
    schemaVersion: "1.0",
    target: {
      input: "example.com",
      hostname: "example.com",
      asciiHostname: "example.com",
      registrableDomain: "example.com",
      scannedAt: "2026-06-15T00:00:00.000Z"
    },
    score: {
      total: 100,
      grade: "A",
      categories: {
        dns: { score: 20, max: 20 },
        web: { score: 30, max: 30 },
        email: { score: 30, max: 30 },
        headers: { score: 15, max: 15 },
        performance: { score: 5, max: 5 }
      }
    },
    summary: {
      headline: "Scan complete with no urgent fixes found.",
      topFixes: ["No urgent fixes found in the checks that completed."],
      counts: {
        pass: 1,
        warn: 0,
        fail: 0,
        info: 0,
        skip: 0
      }
    },
    findings: [
      {
        id: "dns.resolve.ok",
        category: "dns",
        status: "pass",
        severity: "info",
        title: "Domain resolves",
        summary: "example.com has public address records."
      }
    ],
    raw: {}
  };
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((innerResolve) => {
    resolve = innerResolve;
  });

  return { promise, resolve };
}

async function waitFor(condition: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (condition()) {
      return;
    }

    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  throw new Error("Timed out waiting for condition.");
}
