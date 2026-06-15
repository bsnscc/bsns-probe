import { describe, expect, it } from "vitest";

import { checkPerformance } from "./performance.js";
import type { HttpFetchResult, HttpRawResult } from "./http.js";

describe("checkPerformance", () => {
  it("passes fast compressed text responses", () => {
    const result = checkPerformance(
      httpRaw({
        status: "ok",
        responseTimeMs: 120,
        finalHeaders: {
          "content-encoding": "br",
          "content-length": "4096",
          "content-type": "text/html; charset=utf-8"
        }
      })
    );

    expect(findingIds(result.findings)).toContain("perf.response.fast");
    expect(findingIds(result.findings)).not.toContain("perf.compression.missing");
    expect(result.raw).toMatchObject({
      source: "https",
      responseTimeMs: 120,
      contentEncoding: "br",
      contentLength: 4096,
      textLike: true
    });
  });

  it("warns on slow final responses", () => {
    const result = checkPerformance(
      httpRaw({
        status: "ok",
        responseTimeMs: 2200,
        finalHeaders: {
          "content-encoding": "gzip",
          "content-type": "text/html"
        }
      })
    );

    expect(result.findings.find((item) => item.id === "perf.response.slow")).toMatchObject({
      status: "warn",
      severity: "medium"
    });
  });

  it("warns when text responses do not advertise compression", () => {
    const result = checkPerformance(
      httpRaw({
        status: "ok",
        responseTimeMs: 250,
        finalHeaders: {
          "content-length": "12000",
          "content-type": "application/javascript"
        }
      })
    );

    expect(result.findings.find((item) => item.id === "perf.compression.missing"))
      .toMatchObject({
        status: "warn",
        severity: "low"
      });
  });

  it("skips when no final web response is available", () => {
    const result = checkPerformance(
      httpRaw({
        status: "error",
        responseTimeMs: 0,
        finalHeaders: {}
      })
    );

    expect(result.findings).toEqual([
      expect.objectContaining({
        id: "perf.response.unavailable",
        status: "skip"
      })
    ]);
  });
});

function findingIds(findings: Array<{ id: string }>): string[] {
  return findings.map((finding) => finding.id);
}

function httpRaw(result: {
  status: HttpFetchResult["status"];
  responseTimeMs: number;
  finalHeaders: Record<string, string>;
}): HttpRawResult {
  return {
    hostname: "example.com",
    checkedAt: "2026-06-15T00:00:00.000Z",
    https: fetchResult("https://example.com/", result),
    http: fetchResult("http://example.com/", {
      status: "error",
      responseTimeMs: 0,
      finalHeaders: {}
    })
  };
}

function fetchResult(
  url: string,
  result: {
    status: HttpFetchResult["status"];
    responseTimeMs: number;
    finalHeaders: Record<string, string>;
  }
): HttpFetchResult {
  const ok = result.status === "ok";

  return {
    startUrl: url,
    status: result.status,
    attempts: [
      {
        url,
        hostname: "example.com",
        ...(ok ? { status: 200 } : {}),
        responseTimeMs: result.responseTimeMs,
        ...(ok ? { headers: result.finalHeaders } : {})
      }
    ],
    ...(ok
      ? {
          finalUrl: url,
          finalStatus: 200,
          finalHeaders: result.finalHeaders,
          finalHostname: "example.com",
          finalProtocol: url.startsWith("https://") ? "https:" : "http:"
        }
      : {}),
    totalTimeMs: result.responseTimeMs
  };
}
