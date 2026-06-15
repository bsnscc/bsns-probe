import { describe, expect, it } from "vitest";

import { buildScore, buildSummary, gradeScore } from "./score.js";
import type { Finding } from "./types.js";

describe("buildScore", () => {
  it("scores findings by severity and maps TLS into the Web/TLS category", () => {
    const score = buildScore([
      finding("dns.a.missing", "dns", "warn", "medium"),
      finding("tls.expired", "tls", "fail", "critical"),
      finding("headers.hsts.missing", "headers", "warn", "low"),
      finding("email.spf.permissive_all", "email", "fail", "high")
    ]);

    expect(score.categories.dns).toEqual({ score: 15, max: 20 });
    expect(score.categories.web).toEqual({ score: 10, max: 30 });
    expect(score.categories.headers).toEqual({ score: 13, max: 15 });
    expect(score.categories.email).toEqual({ score: 20, max: 30 });
    expect(score.categories.performance).toEqual({ score: 5, max: 5 });
    expect(score.total).toBe(63);
    expect(score.grade).toBe("D");
  });

  it("does not subtract for pass, info, skip, or meta findings", () => {
    const score = buildScore([
      finding("dns.resolve.ok", "dns", "pass", "info"),
      finding("dns.aaaa.missing", "dns", "info", "low"),
      finding("meta.scan.note", "meta", "warn", "high"),
      finding("perf.not_run", "performance", "skip", "medium")
    ]);

    expect(score.total).toBe(100);
    expect(score.grade).toBe("A");
  });
});

describe("buildSummary", () => {
  it("orders top fixes by severity and stable priority", () => {
    const summary = buildSummary([
      finding(
        "headers.hsts.missing",
        "headers",
        "warn",
        "medium",
        "Add Strict-Transport-Security after HTTPS is stable."
      ),
      finding("email.dmarc.missing", "email", "warn", "medium", "Add a DMARC record."),
      finding("tls.expired", "tls", "fail", "critical", "Renew the TLS certificate."),
      finding("dns.resolve.ok", "dns", "pass", "info", "This fix should not appear.")
    ]);

    expect(summary.headline).toBe("Scan complete with 1 failed checks and 2 warnings.");
    expect(summary.topFixes).toEqual([
      "Renew the TLS certificate.",
      "Add a DMARC record.",
      "Add Strict-Transport-Security after HTTPS is stable."
    ]);
  });

  it("returns a calm fallback when no fixes are needed", () => {
    const summary = buildSummary([finding("dns.resolve.ok", "dns", "pass", "info")]);

    expect(summary.headline).toBe("Scan complete with no urgent fixes found.");
    expect(summary.topFixes).toEqual(["No urgent fixes found in the checks that completed."]);
  });

  it("does not promote low-severity warnings into top fixes", () => {
    const summary = buildSummary([
      finding(
        "headers.csp.unsafe_inline",
        "headers",
        "warn",
        "low",
        "Move inline scripts/styles to nonces, hashes, or external files where practical."
      ),
      finding(
        "perf.compression.missing",
        "performance",
        "warn",
        "low",
        "Enable gzip, Brotli, or zstd compression for text responses at the web server or CDN."
      )
    ]);

    expect(summary.headline).toBe("Scan complete with 2 warnings.");
    expect(summary.topFixes).toEqual(["No urgent fixes found in the checks that completed."]);
  });
});

describe("gradeScore", () => {
  it("uses the documented grade thresholds", () => {
    expect(gradeScore(90)).toBe("A");
    expect(gradeScore(80)).toBe("B");
    expect(gradeScore(65)).toBe("C");
    expect(gradeScore(50)).toBe("D");
    expect(gradeScore(49)).toBe("F");
  });
});

function finding(
  id: string,
  category: Finding["category"],
  status: Finding["status"],
  severity: Finding["severity"],
  fix?: string
): Finding {
  return {
    id,
    category,
    status,
    severity,
    title: id,
    summary: id,
    ...(fix ? { fix } : {})
  };
}
