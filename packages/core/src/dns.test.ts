import { describe, expect, it } from "vitest";

import { checkDns } from "./dns.js";
import type { DnsResolver } from "./dns.js";
import type { NormalizedTarget } from "./domain.js";

const TARGET: NormalizedTarget = {
  input: "example.com",
  hostname: "example.com",
  asciiHostname: "example.com",
  registrableDomain: "example.com"
};

describe("checkDns", () => {
  it("returns pass findings and raw records for a healthy domain", async () => {
    const result = await checkDns(TARGET, healthyResolver());

    expect(findingIds(result.findings)).toContain("dns.resolve.ok");
    expect(findingIds(result.findings)).toContain("dns.ns.present");
    expect(findingIds(result.findings)).toContain("dns.caa.present");
    expect(findingIds(result.findings)).toContain("dns.www.present");
    expect(findingIds(result.findings)).not.toContain("dns.a.missing");
    expect(result.raw.records.target.a.records[0]?.address).toBe("93.184.216.34");
    expect(result.raw.records.registrableDomain?.mx.records[0]?.exchange).toBe(
      "mail.example.com"
    );
  });

  it("treats missing AAAA as low-severity info", async () => {
    const result = await checkDns(
      TARGET,
      healthyResolver({
        aaaa: dnsError("ENODATA")
      })
    );
    const finding = result.findings.find((item) => item.id === "dns.aaaa.missing");

    expect(finding).toMatchObject({
      status: "info",
      severity: "low"
    });
    expect(findingIds(result.findings)).toContain("dns.resolve.ok");
  });

  it("warns when A records are missing", async () => {
    const result = await checkDns(
      TARGET,
      healthyResolver({
        a: dnsError("ENODATA")
      })
    );

    expect(result.findings.find((item) => item.id === "dns.a.missing")).toMatchObject({
      status: "warn",
      severity: "medium"
    });
    expect(findingIds(result.findings)).toContain("dns.resolve.ok");
  });

  it("fails when the target does not resolve to A or AAAA records", async () => {
    const result = await checkDns(
      TARGET,
      healthyResolver({
        a: dnsError("ENODATA"),
        aaaa: dnsError("ENODATA")
      })
    );

    expect(result.findings.find((item) => item.id === "dns.resolve.error")).toMatchObject({
      status: "fail",
      severity: "high"
    });
  });

  it("fails when NS records are missing", async () => {
    const result = await checkDns(
      TARGET,
      healthyResolver({
        ns: dnsError("ENODATA")
      })
    );

    expect(result.findings.find((item) => item.id === "dns.ns.missing")).toMatchObject({
      status: "fail",
      severity: "high"
    });
  });

  it("reports missing MX records without failing the domain", async () => {
    const result = await checkDns(
      TARGET,
      healthyResolver({
        mx: dnsError("ENODATA")
      })
    );

    expect(result.findings.find((item) => item.id === "dns.mx.missing")).toMatchObject({
      status: "info",
      severity: "info"
    });
  });

  it("reports missing CAA records as optional", async () => {
    const result = await checkDns(
      TARGET,
      healthyResolver({
        caa: dnsError("ENODATA")
      })
    );

    expect(result.findings.find((item) => item.id === "dns.caa.missing")).toMatchObject({
      status: "info",
      severity: "low"
    });
  });

  it("detects CNAME loops", async () => {
    const result = await checkDns(
      TARGET,
      healthyResolver({
        cname: {
          "example.com": ["loop.example.com"],
          "loop.example.com": ["example.com"]
        }
      })
    );

    expect(result.findings.find((item) => item.id === "dns.cname.loop")).toMatchObject({
      status: "fail",
      severity: "high"
    });
    expect(result.raw.records.target.cnameChain).toMatchObject({
      status: "loop",
      chain: ["example.com", "loop.example.com", "example.com"]
    });
  });

  it("normalizes resolver errors in raw records", async () => {
    const result = await checkDns(
      TARGET,
      healthyResolver({
        a: dnsError("ESERVFAIL"),
        aaaa: dnsError("ENODATA")
      })
    );

    expect(result.raw.records.target.a).toMatchObject({
      status: "error",
      error: {
        code: "ESERVFAIL",
        kind: "servfail"
      }
    });
  });

  it("rejects target address records in blocked IP ranges", async () => {
    await expect(
      checkDns(
        TARGET,
        healthyResolver({
          targetARecords: [{ address: "10.0.0.1", ttl: 300 }]
        })
      )
    ).rejects.toMatchObject({
      code: "BLOCKED_DNS_ADDRESS"
    });
  });
});

function findingIds(findings: Array<{ id: string }>): string[] {
  return findings.map((finding) => finding.id);
}

interface ResolverOverrides {
  a?: Error;
  aaaa?: Error;
  ns?: Error;
  mx?: Error;
  txt?: Error;
  caa?: Error;
  cname?: Record<string, string[]>;
  targetARecords?: Array<{ address: string; ttl: number }>;
}

function healthyResolver(overrides: ResolverOverrides = {}): DnsResolver {
  return {
    async resolve4(hostname) {
      if (hostname === "example.com" && overrides.a) throw overrides.a;
      if (hostname === "example.com" && overrides.targetARecords) {
        return overrides.targetARecords;
      }

      return [
        {
          address: hostname === "www.example.com" ? "93.184.216.35" : "93.184.216.34",
          ttl: 300
        }
      ];
    },
    async resolve6() {
      if (overrides.aaaa) throw overrides.aaaa;
      return [{ address: "2606:2800:220:1:248:1893:25c8:1946", ttl: 300 }];
    },
    async resolveCname(hostname) {
      const records = overrides.cname?.[hostname];
      if (records) {
        return records;
      }

      throw dnsError("ENODATA");
    },
    async resolveNs() {
      if (overrides.ns) throw overrides.ns;
      return ["ns1.example.com", "ns2.example.com"];
    },
    async resolveMx() {
      if (overrides.mx) throw overrides.mx;
      return [{ priority: 10, exchange: "mail.example.com" }];
    },
    async resolveTxt() {
      if (overrides.txt) throw overrides.txt;
      return [["v=spf1", " -all"]];
    },
    async resolveCaa() {
      if (overrides.caa) throw overrides.caa;
      return [{ critical: 0, issue: "letsencrypt.org" }];
    }
  };
}

function dnsError(code: string): Error {
  const error = new Error(`mock DNS ${code}`);
  Object.assign(error, { code });
  return error;
}
