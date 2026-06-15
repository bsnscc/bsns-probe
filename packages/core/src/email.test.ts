import { describe, expect, it } from "vitest";

import { checkEmail, parseDmarcRecord, parseMtaStsPolicy, parseSpfRecord } from "./email.js";
import type { EmailDnsResolver } from "./email.js";
import type { NormalizedTarget } from "./domain.js";
import type { HttpClient } from "./http.js";

const TARGET: NormalizedTarget = {
  input: "example.com",
  hostname: "example.com",
  asciiHostname: "example.com",
  registrableDomain: "example.com"
};

describe("checkEmail", () => {
  it("detects SPF, enforcing DMARC, DKIM, MTA-STS, and TLS-RPT records", async () => {
    const result = await checkEmail(TARGET, {
      resolver: txtResolver({
        "example.com": ["v=spf1 include:_spf.example.com -all"],
        "_spf.example.com": ["v=spf1 ip4:192.0.2.10 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=abc123"],
        "_mta-sts.example.com": ["v=STSv1; id=2026061401"],
        "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"]
      }),
      httpClient: textHttpClient({
        "https://mta-sts.example.com/.well-known/mta-sts.txt": {
          status: 200,
          body: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n"
        }
      }),
      selectors: ["google"]
    });

    expect(findingIds(result.findings)).toContain("email.spf.present");
    expect(findingIds(result.findings)).toContain("email.dmarc.enforcing_policy");
    expect(findingIds(result.findings)).toContain("email.dkim.selector_found");
    expect(findingIds(result.findings)).toContain("email.mta_sts.present");
    expect(findingIds(result.findings)).toContain("email.mta_sts.policy_found");
    expect(findingIds(result.findings)).toContain("email.tls_rpt.present");
    expect(result.raw.spf.lookupCount?.count).toBe(1);
    expect(result.raw.dkim.checkedSelectors[0]).toBe("google");
    expect(result.raw.mtaSts.policy?.parsed).toMatchObject({
      version: "STSv1",
      mode: "enforce",
      maxAge: 604800,
      mx: ["mail.example.com"]
    });
  });

  it("warns about missing SPF and DMARC without claiming DKIM is missing", async () => {
    const result = await checkEmail(TARGET, {
      resolver: txtResolver({})
    });

    expect(result.findings.find((item) => item.id === "email.spf.missing")).toMatchObject({
      status: "warn",
      severity: "medium"
    });
    expect(result.findings.find((item) => item.id === "email.dmarc.missing")).toMatchObject({
      status: "warn",
      severity: "medium"
    });
    expect(result.findings.find((item) => item.id === "email.dkim.no_known_selector_found"))
      .toMatchObject({
        status: "info",
        severity: "info"
      });
  });

  it("fails multiple SPF records", async () => {
    const result = await checkEmail(TARGET, {
      resolver: txtResolver({
        "example.com": ["v=spf1 include:_spf.example.com -all", "v=spf1 ip4:192.0.2.20 -all"]
      })
    });

    expect(result.findings.find((item) => item.id === "email.spf.multiple_records"))
      .toMatchObject({
        status: "fail",
        severity: "high"
      });
  });

  it("fails permissive SPF +all", async () => {
    const result = await checkEmail(TARGET, {
      resolver: txtResolver({
        "example.com": ["v=spf1 +all"]
      })
    });

    expect(result.findings.find((item) => item.id === "email.spf.permissive_all"))
      .toMatchObject({
        status: "fail",
        severity: "high"
      });
  });

  it("fails SPF records that exceed the DNS lookup limit", async () => {
    const result = await checkEmail(TARGET, {
      resolver: txtResolver({
        "example.com": [
          [
            "v=spf1",
            "include:one.example.com",
            "include:two.example.com",
            "include:three.example.com",
            "include:four.example.com",
            "include:five.example.com",
            "include:six.example.com",
            "include:seven.example.com",
            "include:eight.example.com",
            "include:nine.example.com",
            "include:ten.example.com",
            "include:eleven.example.com",
            "-all"
          ].join(" ")
        ]
      })
    });

    expect(result.findings.find((item) => item.id === "email.spf.lookup_limit_exceeded"))
      .toMatchObject({
        status: "fail",
        severity: "high"
      });
    expect(result.raw.spf.lookupCount?.count).toBe(11);
  });

  it("reports DMARC p=none as monitoring mode and encourages aggregate reports", async () => {
    const result = await checkEmail(TARGET, {
      resolver: txtResolver({
        "example.com": ["v=spf1 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=none"]
      })
    });

    expect(result.findings.find((item) => item.id === "email.dmarc.none_policy"))
      .toMatchObject({
        status: "warn",
        severity: "low"
      });
    expect(result.findings.find((item) => item.id === "email.dmarc.missing_rua"))
      .toMatchObject({
        status: "warn",
        severity: "low"
      });
  });

  it("warns when an MTA-STS TXT record exists but the policy file is unreachable", async () => {
    const result = await checkEmail(TARGET, {
      resolver: txtResolver({
        "example.com": ["v=spf1 -all"],
        "_mta-sts.example.com": ["v=STSv1; id=2026061401"]
      }),
      httpClient: textHttpClient({
        "https://mta-sts.example.com/.well-known/mta-sts.txt": {
          status: 404,
          body: "not found"
        }
      })
    });

    expect(result.findings.find((item) => item.id === "email.mta_sts.policy_unreachable"))
      .toMatchObject({
        status: "warn",
        severity: "low"
      });
    expect(result.raw.mtaSts.policy).toMatchObject({
      status: "error",
      httpStatus: 404
    });
  });
});

describe("email parsers", () => {
  it("parses SPF mechanisms, modifiers, and terminal all", () => {
    const parsed = parseSpfRecord(
      "v=spf1 include:_spf.example.com a mx ip4:192.0.2.1 redirect=_spf2.example.com ~all"
    );

    expect(parsed.mechanisms.map((item) => item.name)).toEqual([
      "include",
      "a",
      "mx",
      "ip4",
      "all"
    ]);
    expect(parsed.modifiers[0]).toMatchObject({
      name: "redirect",
      value: "_spf2.example.com"
    });
    expect(parsed.terminalAll).toMatchObject({
      qualifier: "~",
      raw: "~all"
    });
  });

  it("parses DMARC tags", () => {
    expect(parseDmarcRecord("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com").tags)
      .toMatchObject({
        v: "DMARC1",
        p: "quarantine",
        rua: "mailto:dmarc@example.com"
      });
  });

  it("parses MTA-STS policy fields", () => {
    expect(
      parseMtaStsPolicy("version: STSv1\nmode: testing\nmx: *.example.com\nmax_age: 86400\n")
    ).toEqual({
      version: "STSv1",
      mode: "testing",
      mx: ["*.example.com"],
      maxAge: 86400
    });
  });
});

function findingIds(findings: Array<{ id: string }>): string[] {
  return findings.map((finding) => finding.id);
}

function txtResolver(records: Record<string, string[]>): EmailDnsResolver {
  return {
    async resolveTxt(hostname) {
      const values = records[hostname.toLowerCase()];

      if (!values) {
        throw dnsError("ENODATA");
      }

      return values.map((value) => [value]);
    }
  };
}

function dnsError(code: string): Error {
  const error = new Error(`mock DNS ${code}`);
  Object.assign(error, { code });
  return error;
}

function textHttpClient(
  routes: Record<string, { status: number; body: string } | Error>
): HttpClient {
  return {
    async fetch(url) {
      const route = routes[url.toString()];

      if (!route) {
        throw dnsError("ENOTFOUND");
      }

      if (route instanceof Error) {
        throw route;
      }

      return {
        status: route.status,
        headers: new Headers({ "content-type": "text/plain" }),
        body: {
          cancel() {
            return undefined;
          },
          async text() {
            return route.body;
          }
        }
      };
    }
  };
}
