import { describe, expect, it } from "vitest";

import {
  buildScanUiError,
  networkScanUiError,
  unreadableScanResponseError,
  type ScanApiErrorBody
} from "./scan-error";

describe("scan UI errors", () => {
  it("explains rate limits with retry-after seconds", () => {
    const error = buildScanUiError({
      body: errorBody("RATE_LIMITED", "Too many scan requests. Try again shortly."),
      headers: new Headers({ "retry-after": "42" }),
      status: 429
    });

    expect(error).toEqual({
      title: "Too many checks",
      message: "Too many scan requests. Try again shortly.",
      detail: "Try again in about 42 seconds."
    });
  });

  it("falls back to a short retry window when rate limit metadata is missing", () => {
    const error = buildScanUiError({
      body: errorBody("RATE_LIMITED", "Too many scan requests. Try again shortly."),
      headers: new Headers(),
      status: 429
    });

    expect(error.detail).toBe("Try again in about a minute.");
  });

  it("explains busy scanner backpressure with retry-after seconds", () => {
    const error = buildScanUiError({
      body: errorBody("SCANNER_BUSY", "The scanner is handling other requests. Try again shortly."),
      headers: new Headers({ "retry-after": "5" }),
      status: 503
    });

    expect(error).toEqual({
      title: "Scanner is busy",
      message: "The scanner is handling other requests. Try again shortly.",
      detail: "Try again in about 5 seconds."
    });
  });

  it("keeps SSRF block messages explicit", () => {
    const error = buildScanUiError({
      body: errorBody("BLOCKED_HOSTNAME", "Enter a public domain name."),
      headers: new Headers(),
      status: 400
    });

    expect(error.title).toBe("Use a public domain");
    expect(error.detail).toContain("local, private, reserved, or IP-address targets");
  });

  it("explains whole-scan timeouts", () => {
    const error = buildScanUiError({
      body: errorBody("SCAN_TIMEOUT", "The scan timed out. Try again shortly."),
      headers: new Headers(),
      status: 504
    });

    expect(error.title).toBe("The scan timed out");
    expect(error.detail).toContain("15 second limit");
  });

  it("returns a network failure message for fetch errors", () => {
    expect(networkScanUiError()).toEqual({
      title: "Could not reach the scanner",
      message: "Check your connection and try again."
    });
  });

  it("creates a safe fallback for unreadable responses", () => {
    expect(unreadableScanResponseError(502)).toEqual({
      ok: false,
      error: {
        code: "INVALID_RESPONSE",
        message: "The scanner returned HTTP 502. Try again in a moment."
      }
    });
  });

  it("treats unreadable edge 429s as rate limits", () => {
    expect(unreadableScanResponseError(429)).toEqual({
      ok: false,
      error: {
        code: "RATE_LIMITED",
        message: "Too many scan requests. Try again shortly."
      }
    });
  });
});

function errorBody(code: string, message: string): ScanApiErrorBody {
  return {
    ok: false,
    error: {
      code,
      message
    }
  };
}
