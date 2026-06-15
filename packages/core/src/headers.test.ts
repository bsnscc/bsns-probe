import { describe, expect, it } from "vitest";

import { checkHeaders } from "./headers.js";
import type { HttpRawResult } from "./http.js";

describe("checkHeaders", () => {
  it("skips header checks when HTTPS is unavailable", () => {
    const result = checkHeaders(httpRaw({}, "error"));

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      id: "headers.unavailable",
      status: "skip"
    });
  });

  it("passes a strong header fixture", () => {
    const result = checkHeaders(
      httpRaw({
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
        "set-cookie": "sid=abc; Secure; HttpOnly; SameSite=Lax"
      })
    );

    expect(findingIds(result.findings)).toContain("headers.hsts.present");
    expect(findingIds(result.findings)).toContain("headers.csp.present");
    expect(findingIds(result.findings)).toContain("headers.clickjacking.present");
    expect(findingIds(result.findings)).toContain("headers.nosniff.present");
    expect(findingIds(result.findings)).toContain("headers.referrer_policy.present");
    expect(findingIds(result.findings)).toContain("headers.permissions_policy.present");
    expect(findingIds(result.findings)).not.toContain("headers.cookie.missing_secure");
  });

  it("warns for missing common security headers", () => {
    const result = checkHeaders(httpRaw({}));

    expect(result.findings.find((item) => item.id === "headers.hsts.missing")).toMatchObject({
      status: "warn",
      severity: "medium"
    });
    expect(result.findings.find((item) => item.id === "headers.csp.missing")).toMatchObject({
      status: "warn",
      severity: "medium"
    });
    expect(result.findings.find((item) => item.id === "headers.clickjacking.missing")).toMatchObject({
      status: "warn",
      severity: "medium"
    });
    expect(result.findings.find((item) => item.id === "headers.nosniff.missing")).toMatchObject({
      status: "warn",
      severity: "low"
    });
  });

  it("warns for short HSTS max-age", () => {
    const result = checkHeaders(
      httpRaw({
        "strict-transport-security": "max-age=300"
      })
    );

    expect(result.findings.find((item) => item.id === "headers.hsts.short_max_age")).toMatchObject({
      status: "warn",
      severity: "low"
    });
  });

  it("warns for CSP unsafe-inline without treating it as an automatic failure", () => {
    const result = checkHeaders(
      httpRaw({
        "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"
      })
    );

    expect(result.findings.find((item) => item.id === "headers.csp.unsafe_inline")).toMatchObject({
      status: "warn",
      severity: "low"
    });
  });

  it("accepts X-Frame-Options as a clickjacking control", () => {
    const result = checkHeaders(
      httpRaw({
        "x-frame-options": "DENY"
      })
    );

    expect(findingIds(result.findings)).toContain("headers.clickjacking.present");
    expect(findingIds(result.findings)).not.toContain("headers.clickjacking.missing");
  });

  it("warns once per missing cookie attribute type", () => {
    const result = checkHeaders(
      httpRaw({
        "set-cookie": "sid=abc; Path=/, prefs=dark; Secure; Path=/"
      })
    );

    expect(findingIds(result.findings).filter((id) => id === "headers.cookie.missing_secure")).toHaveLength(1);
    expect(findingIds(result.findings).filter((id) => id === "headers.cookie.missing_httponly")).toHaveLength(1);
    expect(findingIds(result.findings).filter((id) => id === "headers.cookie.missing_samesite")).toHaveLength(1);
  });

  it("keeps disclosure headers low severity", () => {
    const result = checkHeaders(
      httpRaw({
        server: "nginx",
        "x-powered-by": "Express"
      })
    );

    expect(result.findings.find((item) => item.id === "headers.server.disclosed")).toMatchObject({
      status: "info",
      severity: "low"
    });
    expect(
      result.findings.find((item) => item.id === "headers.x_powered_by.disclosed")
    ).toMatchObject({
      status: "info",
      severity: "low"
    });
  });
});

function findingIds(findings: Array<{ id: string }>): string[] {
  return findings.map((finding) => finding.id);
}

function httpRaw(
  headers: Record<string, string>,
  status: HttpRawResult["https"]["status"] = "ok"
): HttpRawResult {
  return {
    hostname: "example.com",
    checkedAt: "2026-01-01T00:00:00.000Z",
    https: {
      startUrl: "https://example.com/",
      status,
      attempts: [],
      finalHeaders: status === "ok" ? headers : undefined,
      finalHostname: status === "ok" ? "example.com" : undefined,
      finalProtocol: status === "ok" ? "https:" : undefined,
      finalStatus: status === "ok" ? 200 : undefined,
      finalUrl: status === "ok" ? "https://example.com/" : undefined,
      totalTimeMs: 10
    },
    http: {
      startUrl: "http://example.com/",
      status: "ok",
      attempts: [],
      finalHostname: "example.com",
      finalProtocol: "https:",
      finalStatus: 200,
      finalUrl: "https://example.com/",
      totalTimeMs: 10
    }
  };
}
