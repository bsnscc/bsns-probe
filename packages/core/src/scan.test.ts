import { describe, expect, it } from "vitest";

import { scanDomain } from "./scan.js";
import type { DnsResolver } from "./dns.js";
import type { AddressResolver } from "./domain.js";
import type { HttpClient } from "./http.js";
import type { ScanOptions } from "./types.js";

describe("scanDomain", () => {
  it("returns a typed report with DNS, web, TLS, header, and email findings", async () => {
    const report = await scanDomain("https://Example.com/path", {
      ...scanOptions(),
      dkimSelectors: ["google"],
      timeoutMs: 8000
    });

    expect(report.schemaVersion).toBe("1.0");
    expect(report.target.hostname).toBe("example.com");
    expect(report.score.total).toBe(100);
    expect(report.summary.counts.info).toBeGreaterThanOrEqual(1);
    expect(report.findings.some((finding) => finding.id === "dns.resolve.ok")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "web.https.ok")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "tls.valid")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "email.spf.present")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "email.dmarc.enforcing_policy"))
      .toBe(true);
    expect(report.findings.some((finding) => finding.id === "perf.response.fast")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "meta.scan.stub")).toBe(false);
  });

  it("omits raw data when includeRaw is false", async () => {
    const report = await scanDomain("example.com", {
      ...scanOptions(),
      includeRaw: false
    });

    expect(report.raw).toEqual({});
  });

  it("rejects blocked hostnames before returning a report", async () => {
    await expect(scanDomain("localhost")).rejects.toMatchObject({
      code: "BLOCKED_HOSTNAME"
    });
  });

  it("includes DNS raw data when raw output is enabled", async () => {
    const report = await scanDomain("example.com", scanOptions());

    expect(report.raw.dns).toMatchObject({
      hostname: "example.com",
      registrableDomain: "example.com"
    });
    expect(report.raw.http).toMatchObject({
      hostname: "example.com"
    });
    expect(report.raw.tls).toMatchObject({
      hostname: "example.com",
      handshake: true
    });
    expect(report.raw.email).toMatchObject({
      domain: "example.com"
    });
    expect(report.raw.performance).toMatchObject({
      source: "https"
    });
  });

  it("returns a partial report when DNS validation times out", async () => {
    const report = await scanDomain("example.com", {
      ...scanOptions(),
      dnsResolver: {
        ...healthyResolver(),
        async resolve4() {
          return never();
        }
      },
      timeoutMs: 1
    });

    const ids = findingIds(report.findings);
    expect(ids).toContain("dns.check.timeout");
    expect(ids).toContain("web.check.skipped");
    expect(ids).toContain("tls.check.skipped");
    expect(ids).toContain("email.check.skipped");
    expect(ids).toContain("headers.unavailable");
    expect(ids).toContain("perf.response.unavailable");
    expect(report.raw.dns).toMatchObject({
      status: "timeout",
      timeoutMs: 1
    });
  });

  it("returns a partial report when TLS inspection times out", async () => {
    const report = await scanDomain("example.com", {
      ...scanOptions(),
      tlsInspector: {
        async inspect() {
          return never();
        }
      },
      timeoutMs: 1
    });

    const ids = findingIds(report.findings);
    expect(ids).toContain("web.https.ok");
    expect(ids).toContain("tls.check.timeout");
    expect(ids).toContain("email.spf.present");
    expect(report.raw.tls).toMatchObject({
      hostname: "example.com",
      error: {
        code: "CHECK_TIMEOUT"
      }
    });
  });
});

function findingIds(findings: Array<{ id: string }>): string[] {
  return findings.map((finding) => finding.id);
}

function never<T>(): Promise<T> {
  return new Promise<T>(() => undefined);
}

function scanOptions(): ScanOptions {
  return {
    addressResolver: publicAddressResolver(),
    dnsResolver: healthyResolver(),
    httpClient: healthyHttpClient(),
    tlsInspector: {
      async inspect() {
        return {
          handshake: true,
          chainTrusted: true,
          negotiatedProtocol: "TLSv1.3",
          certificate: {
            subject: { CN: "example.com" },
            issuer: { CN: "Test CA" },
            validFrom: "2026-01-01T00:00:00.000Z",
            validTo: "2026-12-31T00:00:00.000Z",
            subjectAltNames: ["example.com"]
          }
        };
      }
    }
  };
}

function healthyResolver(): DnsResolver {
  return {
    async resolve4() {
      return [{ address: "93.184.216.34", ttl: 300 }];
    },
    async resolve6() {
      return [{ address: "2606:2800:220:1:248:1893:25c8:1946", ttl: 300 }];
    },
    async resolveCname() {
      const error = new Error("No CNAME records");
      Object.assign(error, { code: "ENODATA" });
      throw error;
    },
    async resolveNs() {
      return ["ns1.example.com", "ns2.example.com"];
    },
    async resolveMx() {
      return [{ priority: 10, exchange: "mail.example.com" }];
    },
    async resolveTxt(hostname) {
      if (hostname === "_dmarc.example.com") {
        return [["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]];
      }

      if (hostname === "google._domainkey.example.com") {
        return [["v=DKIM1; k=rsa; p=abc123"]];
      }

      if (hostname === "_mta-sts.example.com") {
        return [["v=STSv1; id=2026061401"]];
      }

      if (hostname === "_smtp._tls.example.com") {
        return [["v=TLSRPTv1; rua=mailto:tls@example.com"]];
      }

      if (hostname.endsWith("._domainkey.example.com")) {
        const error = new Error("No TXT records");
        Object.assign(error, { code: "ENODATA" });
        throw error;
      }

      return [["v=spf1", " -all"]];
    },
    async resolveCaa() {
      return [{ critical: 0, issue: "letsencrypt.org" }];
    }
  };
}

function publicAddressResolver(): AddressResolver {
  return {
    async lookup() {
      return [{ address: "93.184.216.34", family: 4 }];
    }
  };
}

function healthyHttpClient(): HttpClient {
  return {
    async fetch(url) {
      if (url.protocol === "http:") {
        return {
          status: 301,
          headers: new Headers({ location: `https://${url.hostname}/` })
        };
      }

      if (url.hostname === "mta-sts.example.com") {
        return {
          status: 200,
          headers: new Headers({ "content-type": "text/plain" }),
          body: {
            cancel() {
              return undefined;
            },
            async text() {
              return "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n";
            }
          }
        };
      }

      return {
        status: 200,
        headers: new Headers({
          "content-encoding": "br",
          "content-length": "4096",
          "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
          "content-type": "text/html",
          "permissions-policy": "camera=(), microphone=()",
          "referrer-policy": "strict-origin-when-cross-origin",
          "strict-transport-security": "max-age=31536000",
          "x-content-type-options": "nosniff",
          "x-frame-options": "DENY"
        })
      };
    }
  };
}
